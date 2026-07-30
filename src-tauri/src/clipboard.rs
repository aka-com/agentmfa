//! Core-side clipboard copy with hygiene.
//!
//! Copy is performed core-side so the raw value is written straight to the
//! pasteboard without passing back through the webview. Because the general
//! pasteboard is readable by every running app and by clipboard-history
//! managers, the copy: marks the item `org.nspasteboard.ConcealedType`
//! (asking history managers not to retain it), and auto-clears the
//! pasteboard after 30 s if the copied value is still present.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use sha2::{Digest as _, Sha256};
use tauri::AppHandle;
#[cfg(not(target_os = "macos"))]
use tauri_plugin_clipboard_manager::ClipboardExt as _;
use zeroize::Zeroizing;

const AUTO_CLEAR: Duration = Duration::from_secs(30);
type ClipboardDigest = [u8; 32];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PendingClipboard {
    digest: ClipboardDigest,
    generation: u64,
}

/// The last value AgentMFA placed on the clipboard, represented only by a
/// one-way digest. The credential itself is zeroized as soon as the platform
/// write returns; timeout and shutdown compare the current clipboard by hash.
static PENDING_CLEAR: Mutex<Option<PendingClipboard>> = Mutex::new(None);
static NEXT_GENERATION: AtomicU64 = AtomicU64::new(1);
static EXIT_CLEANUP: ExitCleanupState = ExitCleanupState::new();

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExitCleanupAction {
    Proceed,
    Start,
    Wait,
}

struct ExitCleanupState {
    started: AtomicBool,
    finished: AtomicBool,
}

impl ExitCleanupState {
    const fn new() -> Self {
        Self {
            started: AtomicBool::new(false),
            finished: AtomicBool::new(false),
        }
    }

    fn action(&self, has_pending: bool) -> ExitCleanupAction {
        if !has_pending || self.finished.load(Ordering::Acquire) {
            ExitCleanupAction::Proceed
        } else if self.started.swap(true, Ordering::AcqRel) {
            ExitCleanupAction::Wait
        } else {
            ExitCleanupAction::Start
        }
    }

    fn finish(&self) {
        self.finished.store(true, Ordering::Release);
    }
}

fn digest(value: &str) -> ClipboardDigest {
    Sha256::digest(value.as_bytes()).into()
}

/// Write `value` to the clipboard with hygiene, then schedule the auto-clear.
pub fn copy_with_hygiene(app: &AppHandle, value: Zeroizing<String>) -> Result<(), String> {
    let expected = PendingClipboard {
        digest: digest(&value),
        generation: NEXT_GENERATION.fetch_add(1, Ordering::Relaxed),
    };
    // Serialize our own writes with timeout/exit cleanup. Without this lock,
    // an old timer could verify value A, a new copy could write value B, and
    // the old timer could then clear B before the pending digest changed.
    let mut pending = PENDING_CLEAR.lock().unwrap();
    #[cfg(target_os = "macos")]
    {
        macos::write_concealed(&value)?;
    }
    #[cfg(not(target_os = "macos"))]
    {
        app.clipboard()
            .write_text(value.as_str())
            .map_err(|error| format!("could not write the system clipboard: {error}"))?;
    }
    *pending = Some(expected);
    drop(pending);

    let app = app.clone();
    std::thread::spawn(move || {
        std::thread::sleep(AUTO_CLEAR);
        if let Err(error) = clear_digest_if_unchanged(&app, expected) {
            tracing::warn!(%error, "could not auto-clear copied credential");
        }
    });
    Ok(())
}

/// Best-effort shutdown cleanup. This runs while the Tauri clipboard plugin
/// and macOS application context still exist; it never clears content copied
/// after AgentMFA's credential.
fn clear_pending(app: &AppHandle) {
    let expected = *PENDING_CLEAR.lock().unwrap();
    if let Some(expected) = expected {
        if let Err(error) = clear_digest_if_unchanged(app, expected) {
            tracing::warn!(%error, "could not clear copied credential on exit");
        }
    }
}

fn clear_digest_if_unchanged(app: &AppHandle, expected: PendingClipboard) -> Result<(), String> {
    let mut pending = PENDING_CLEAR.lock().unwrap();
    if pending.as_ref() != Some(&expected) {
        return Ok(());
    }

    #[cfg(target_os = "macos")]
    let _ = app;
    #[cfg(target_os = "macos")]
    let current = macos::read_plain_text();
    #[cfg(not(target_os = "macos"))]
    let current = app
        .clipboard()
        .read_text()
        .map(Some)
        .map_err(|error| format!("could not read the system clipboard: {error}"))?;

    let still_matches = current.as_deref().map(digest) == Some(expected.digest);
    if still_matches {
        #[cfg(target_os = "macos")]
        macos::clear();
        #[cfg(not(target_os = "macos"))]
        app.clipboard()
            .write_text("")
            .map_err(|error| format!("could not clear the system clipboard: {error}"))?;
    }
    *pending = None;
    Ok(())
}

/// Defer normal shutdown until clipboard cleanup has completed. Tauri plugin
/// exit hooks run before the application callback, so cleanup at `RunEvent::Exit`
/// is too late. Keeping the event loop alive also lets Linux clipboard reads
/// happen on this worker rather than deadlocking the main thread.
pub fn defer_exit_cleanup(
    app: &AppHandle,
    code: Option<i32>,
    api: &tauri::ExitRequestApi,
) {
    let has_pending = PENDING_CLEAR.lock().unwrap().is_some();
    match EXIT_CLEANUP.action(has_pending) {
        ExitCleanupAction::Proceed => {}
        ExitCleanupAction::Wait => api.prevent_exit(),
        ExitCleanupAction::Start => {
            api.prevent_exit();
            let app = app.clone();
            std::thread::spawn(move || {
                clear_pending(&app);
                EXIT_CLEANUP.finish();
                app.exit(code.unwrap_or(0));
            });
        }
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use objc2::rc::autoreleasepool;
    use objc2_app_kit::NSPasteboard;
    use objc2_foundation::NSString;

    const CONCEALED_TYPE: &str = "org.nspasteboard.ConcealedType";
    const UTF8: &str = "public.utf8-plain-text";

    pub fn write_concealed(value: &str) -> Result<(), String> {
        autoreleasepool(|_| {
            let pb = NSPasteboard::generalPasteboard();
            pb.clearContents();
            let s = NSString::from_str(value);
            // Set both the plain-text and the concealed type so history
            // managers that honor the hint skip it.
            let ok_text = pb.setString_forType(&s, &NSString::from_str(UTF8));
            let _ = pb.setString_forType(&s, &NSString::from_str(CONCEALED_TYPE));
            if !ok_text {
                return Err("failed to write pasteboard item".to_string());
            }
            Ok(())
        })
    }

    pub fn read_plain_text() -> Option<String> {
        autoreleasepool(|_| {
            NSPasteboard::generalPasteboard()
                .stringForType(&NSString::from_str(UTF8))
                .map(|value| value.to_string())
        })
    }

    pub fn clear() {
        autoreleasepool(|_| {
            NSPasteboard::generalPasteboard().clearContents();
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clipboard_tracking_retains_only_a_fixed_size_fingerprint() {
        let secret = "end_super-secret-capability";
        let fingerprint = digest(secret);
        assert_eq!(fingerprint.len(), 32);
        assert_ne!(fingerprint.as_slice(), secret.as_bytes());
        assert_eq!(fingerprint, digest(secret));
        assert_ne!(fingerprint, digest("another value"));
    }

    #[test]
    fn repeated_identical_copies_have_distinct_timer_tokens() {
        let first = PendingClipboard {
            digest: digest("same credential"),
            generation: 1,
        };
        let second = PendingClipboard {
            digest: digest("same credential"),
            generation: 2,
        };
        assert_eq!(first.digest, second.digest);
        assert_ne!(first, second);
    }

    #[test]
    fn exit_waits_for_one_cleanup_before_proceeding() {
        let lifecycle = ExitCleanupState::new();
        assert_eq!(lifecycle.action(false), ExitCleanupAction::Proceed);
        assert_eq!(lifecycle.action(true), ExitCleanupAction::Start);
        assert_eq!(lifecycle.action(true), ExitCleanupAction::Wait);
        lifecycle.finish();
        assert_eq!(lifecycle.action(true), ExitCleanupAction::Proceed);
    }
}
