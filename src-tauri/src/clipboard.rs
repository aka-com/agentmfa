//! Core-side clipboard copy with hygiene (DESIGN.md §9).
//!
//! Copy is performed core-side so the raw value is written straight to the
//! pasteboard without passing back through the webview. Because the general
//! pasteboard is readable by every running app and by clipboard-history
//! managers, the copy: marks the item `org.nspasteboard.ConcealedType`
//! (asking history managers not to retain it), and auto-clears the
//! pasteboard after 30 s if the copied value is still present.

use std::time::Duration;

use zeroize::Zeroizing;

const AUTO_CLEAR: Duration = Duration::from_secs(30);

/// Write `value` to the clipboard with hygiene, then schedule the auto-clear.
pub fn copy_with_hygiene(value: Zeroizing<String>) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        macos::write_concealed(&value)?;
        let snapshot = value.to_string();
        std::thread::spawn(move || {
            std::thread::sleep(AUTO_CLEAR);
            macos::clear_if_unchanged(&snapshot);
        });
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    {
        // Dev fallback: the concealed-type marking is a macOS pasteboard
        // feature. We still auto-clear via the OS clipboard through arboard
        // if available; here we just log, since the dev build has no
        // pasteboard integration wired.
        tracing::warn!(
            "clipboard copy on non-macOS dev build is a no-op \
             (concealed-type + auto-clear are macOS pasteboard features)"
        );
        let _ = value;
        let _ = AUTO_CLEAR;
        Ok(())
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

    /// Clear the pasteboard only if it still holds the copied value, so we
    /// never wipe something the user copied afterwards.
    pub fn clear_if_unchanged(expected: &str) {
        autoreleasepool(|_| {
            let pb = NSPasteboard::generalPasteboard();
            let current = pb.stringForType(&NSString::from_str(UTF8));
            if current.map(|s| s.to_string()).as_deref() == Some(expected) {
                pb.clearContents();
            }
        });
    }
}
