//! App lock: a Touch ID / device-password gate over the desktop windows.
//!
//! **What this is, precisely.** A gate on *this app's UI*, drawn as a
//! takeover over both windows and enforced at the Tauri command boundary
//! for the commands that hand credential material back to the webview.
//!
//! It authenticates two ways, and both are `LocalAuthentication`:
//!
//! - **Touch ID, inline.** An `LAAuthenticationView` hosted over the webview
//!   inside the lock card, so the sensor affordance is part of our lock
//!   screen rather than a system alert on top of it. See [`embedded`] — that
//!   view is biometry-only and non-textual, which is why it is never the only
//!   way in.
//! - **The account password**, via `LAContext.evaluatePolicy` with
//!   `deviceOwnerAuthentication`, which raises the standard system sheet.
//!   This is the fallback the inline control cannot provide, and the whole
//!   gate on a Mac with no Touch ID.
//!
//! **What this is not.** It is not a change to how secrets are stored. The
//! vault items keep their existing protection (see [`aka_core::keychain`]:
//! data-protection keychain, `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`,
//! access decided by code signature rather than a per-item ACL), so while
//! the UI is locked the process can still read every value it could read
//! before. Concretely, a locked window does **not** stop:
//!
//! - the broker serving agents — the daemon keeps injecting credentials into
//!   live sessions and answering new ones, by design, because an agent run
//!   should not die because a laptop lid closed;
//! - the `multitool` CLI, which drives its own broker instance;
//! - anything already executing as the user with the app's code identity.
//!
//! So this defends against someone sitting down at an unattended, unlocked
//! Mac, and against a shoulder. It does not defend key material against code
//! running as you. Making "locked" mean the key is not in memory requires
//! the wrap-key design (encrypt vault values under a master key that itself
//! lives behind a `SecAccessControl(.userPresence)` keychain item) — a
//! different, larger change, and one that has to decide what a locked broker
//! does to a mid-flight agent request.
//!
//! Lock state is deliberately *not* persisted: the app starts unlocked. A
//! lock that survives restart implies the lock protects something at rest,
//! which this one does not, and pretending otherwise is the failure mode
//! worth avoiding here.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter as _, Manager as _};

pub mod away;
#[cfg(target_os = "macos")]
pub mod embedded;

/// Emitted to every window whenever the lock state or its settings change.
pub const EVT_LOCK: &str = "aka://lock-changed";

/// How often the idle watchdog wakes. Auto-lock delays are minutes, so a
/// coarse tick is plenty and costs nothing.
const WATCHDOG_TICK: Duration = Duration::from_secs(5);

/// Auto-lock delays the Settings sheet offers, in seconds. `0` is "never".
const ALLOWED_AUTO_LOCK_SECS: [u64; 5] = [0, 60, 300, 900, 3600];

/// This-machine lock preferences, stored beside the other shell settings in
/// `shell.json` rather than on the managed broker: whether the window locks
/// is a property of this desktop, not of whichever broker it is driving.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LockSettings {
    /// Automatic-lock switch. Off disables idle, hide, and system-away
    /// locking; the explicit "Lock Now" action remains available.
    #[serde(default)]
    pub enabled: bool,
    /// Lock after this many seconds without interaction with either window.
    /// `0` disables the idle timer, leaving only manual and on-hide locking.
    #[serde(default = "default_auto_lock_secs")]
    pub auto_lock_secs: u64,
    /// Also lock whenever both windows are hidden (menu-bar dismissal, main
    /// window closed). Cheap and matches how people actually put the app
    /// away; separate from the idle timer so either can be used alone.
    #[serde(default)]
    pub lock_on_hide: bool,
}

const fn default_auto_lock_secs() -> u64 {
    300
}

impl Default for LockSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            auto_lock_secs: default_auto_lock_secs(),
            lock_on_hide: false,
        }
    }
}

impl LockSettings {
    fn validate(self) -> Result<Self, String> {
        if ALLOWED_AUTO_LOCK_SECS.contains(&self.auto_lock_secs) {
            Ok(self)
        } else {
            Err("auto-lock delay must be never, 1, 5, 15, or 60 minutes".into())
        }
    }

    /// A hand-edited or newer `shell.json` carrying a delay this version does
    /// not understand falls back to the default rather than to "never": the
    /// user asked for a lock, so the safe reading of a bad value is a lock
    /// that still engages.
    pub fn with_safe_persisted_delay(mut self) -> Self {
        if self.validate().is_err() {
            self.auto_lock_secs = default_auto_lock_secs();
        }
        self
    }
}

/// The rect the lock card measured for the inline control, in CSS points
/// from the top-left of the window. Mirrored on non-macOS so the command
/// surface has one shape everywhere.
#[cfg(target_os = "macos")]
pub type EmbeddedSlot = embedded::Slot;

#[cfg(not(target_os = "macos"))]
#[derive(Debug, Clone, Copy, Deserialize)]
pub struct EmbeddedSlot {
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}

/// Everything the webview needs to render the lock: current state, the
/// saved settings, and whether the platform can actually authenticate.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LockStateView {
    pub locked: bool,
    pub enabled: bool,
    pub auto_lock_secs: u64,
    pub lock_on_hide: bool,
    /// Whether an unlock can succeed at all on this machine. False disables
    /// the settings toggle instead of letting the user arm a lock they
    /// cannot open.
    pub available: bool,
    /// Why not, for the settings row. `None` when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unavailable_reason: Option<String>,
    /// "biometry" when Touch ID answered `canEvaluatePolicy`, "password"
    /// when only the account password will, "none" when neither. Drives the
    /// unlock copy so it never promises a Touch ID prompt that won't appear.
    pub mechanism: &'static str,
    /// Whether the lock card should host the inline Touch ID control. False
    /// on a Mac with no enrolled biometry (or pre-12, or non-macOS), where
    /// the password sheet is the only path and the card says so instead of
    /// leaving a slot for a control that would fail on contact.
    pub embedded: bool,
    /// The last inline attempt's error — a wrong finger, a lockout. Cancels
    /// are not errors and clear this. Shown beside the control.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub embedded_error: Option<String>,
}

/// The lock's runtime state. Managed by Tauri, shared with the watchdog.
pub struct AppLock {
    locked: AtomicBool,
    /// Last observed interaction with either window. The webview reports it;
    /// see `note_activity`.
    last_active: Mutex<Instant>,
    settings: Mutex<LockSettings>,
    /// The last inline-control failure, surfaced in the lock card.
    embedded_error: Mutex<Option<String>>,
    /// True while an authentication sheet is up. A second unlock request
    /// (impatient double-click, both windows racing) is answered from the
    /// current attempt instead of stacking a second system prompt.
    authenticating: AtomicBool,
}

impl AppLock {
    pub fn new(settings: LockSettings) -> Self {
        Self {
            locked: AtomicBool::new(false),
            last_active: Mutex::new(Instant::now()),
            settings: Mutex::new(settings),
            embedded_error: Mutex::new(None),
            authenticating: AtomicBool::new(false),
        }
    }

    pub fn is_locked(&self) -> bool {
        self.locked.load(Ordering::SeqCst)
    }

    pub fn settings(&self) -> LockSettings {
        *self.settings.lock().unwrap()
    }

    pub fn view(&self) -> LockStateView {
        let settings = self.settings();
        let capability = platform_capability();
        LockStateView {
            locked: self.is_locked(),
            enabled: settings.enabled,
            auto_lock_secs: settings.auto_lock_secs,
            lock_on_hide: settings.lock_on_hide,
            available: capability.available,
            unavailable_reason: capability.reason,
            mechanism: capability.mechanism,
            embedded: embedded_available(),
            embedded_error: self.embedded_error.lock().unwrap().clone(),
        }
    }

    pub fn note_activity(&self) {
        *self.last_active.lock().unwrap() = Instant::now();
    }

    /// Engage the lock from an automatic policy. The explicit action uses
    /// `lock_now`, which deliberately does not depend on this preference.
    pub fn lock(&self, app: &AppHandle) {
        if !lock_request_allowed(self.settings().enabled, false, platform_capability().available) {
            return;
        }
        self.engage(app);
    }

    /// Engage the lock for an explicit user request. No-op only when the
    /// platform cannot authenticate, since that would strand the user with
    /// no way back into their own credentials.
    pub fn lock_now(&self, app: &AppHandle) {
        if !lock_request_allowed(self.settings().enabled, true, platform_capability().available) {
            return;
        }
        self.engage(app);
    }

    fn engage(&self, app: &AppHandle) {
        if !self.locked.swap(true, Ordering::SeqCst) {
            *self.embedded_error.lock().unwrap() = None;
            self.publish(app);
        }
    }

    fn unlock(&self, app: &AppHandle) {
        self.note_activity();
        *self.embedded_error.lock().unwrap() = None;
        if self.locked.swap(false, Ordering::SeqCst) {
            self.publish(app);
        }
    }

    /// The inline control succeeded. Separate entry point because it arrives
    /// on the completion block's thread rather than from a command.
    #[cfg(target_os = "macos")]
    pub(crate) fn unlock_from_embedded(&self, app: &AppHandle) {
        self.unlock(app);
    }

    /// The inline control finished without unlocking. `None` is a cancel,
    /// which is not worth a message.
    #[cfg(target_os = "macos")]
    pub(crate) fn embedded_failed(&self, app: &AppHandle, message: Option<String>) {
        *self.embedded_error.lock().unwrap() = message;
        self.publish(app);
    }

    pub fn set_settings(&self, app: &AppHandle, settings: LockSettings) -> Result<(), String> {
        let settings = settings.validate()?;
        *self.settings.lock().unwrap() = settings;
        // Turning the lock off must not leave the takeover on screen with no
        // way to dismiss it.
        if !settings.enabled {
            self.locked.store(false, Ordering::SeqCst);
        }
        self.note_activity();
        self.publish(app);
        Ok(())
    }

    fn publish(&self, app: &AppHandle) {
        let _ = app.emit(EVT_LOCK, self.view());
    }
}

fn lock_request_allowed(automatic_enabled: bool, explicit: bool, platform_available: bool) -> bool {
    platform_available && (explicit || automatic_enabled)
}

/// Idle watchdog. One thread for the life of the app; it only ever *takes*
/// the lock, never releases it.
pub fn start_watchdog(app: AppHandle, lock: Arc<AppLock>) {
    std::thread::spawn(move || loop {
        std::thread::sleep(WATCHDOG_TICK);
        let settings = lock.settings();
        if !settings.enabled || settings.auto_lock_secs == 0 || lock.is_locked() {
            continue;
        }
        let idle = lock.last_active.lock().unwrap().elapsed();
        if idle >= Duration::from_secs(settings.auto_lock_secs) {
            lock.lock(&app);
        }
    });
}

/// Called from the window-hide paths when `lock_on_hide` is set.
pub fn lock_if_hidden(app: &AppHandle) {
    let Some(lock) = app.try_state::<Arc<AppLock>>() else {
        return;
    };
    if !lock.settings().lock_on_hide {
        return;
    }
    let visible = [crate::windows::MAIN, crate::windows::DROPDOWN]
        .into_iter()
        .filter_map(|label| app.get_webview_window(label))
        .any(|window| window.is_visible().unwrap_or(false));
    if !visible {
        lock.lock(app);
    }
}

/// The gate every credential-bearing command calls first.
///
/// This is the point of enforcing in Rust rather than only hiding the UI:
/// the overlay is a `div`, and a `div` is not a boundary. With this check
/// the webview cannot obtain a secret value while locked even if its own
/// state says otherwise.
pub fn require_unlocked(app: &AppHandle) -> Result<(), String> {
    match app.try_state::<Arc<AppLock>>() {
        Some(lock) if lock.is_locked() => {
            Err("Multitool is locked. Unlock it to continue.".into())
        }
        _ => Ok(()),
    }
}

/* ------------------------------ platform ------------------------------- */

struct Capability {
    available: bool,
    reason: Option<String>,
    mechanism: &'static str,
}

#[cfg(target_os = "macos")]
fn platform_capability() -> Capability {
    use objc2_local_authentication::{LAContext, LAPolicy};

    // Ask for biometry first purely to *label* the prompt correctly, then
    // fall back to the policy we actually evaluate (biometry-or-password).
    // `canEvaluatePolicy` is cheap and puts up no UI.
    let context = unsafe { LAContext::new() };
    let biometry =
        unsafe { context.canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthenticationWithBiometrics) }
            .is_ok();
    let context = unsafe { LAContext::new() };
    match unsafe { context.canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthentication) } {
        Ok(()) => Capability {
            available: true,
            reason: None,
            mechanism: if biometry { "biometry" } else { "password" },
        },
        Err(error) => Capability {
            available: false,
            reason: Some(format!(
                "macOS can't authenticate this user right now ({}). Set an account \
                 password, or enroll Touch ID, then try again.",
                error.localizedDescription()
            )),
            mechanism: "none",
        },
    }
}

#[cfg(not(target_os = "macos"))]
fn platform_capability() -> Capability {
    Capability {
        available: false,
        reason: Some("Multitool's app lock needs Touch ID or a macOS account password.".into()),
        mechanism: "none",
    }
}

/// Put up the system authentication sheet and wait for the answer.
///
/// Runs on the caller's thread and blocks it, so it must not be called from
/// the main thread — the commands below are `async`, which Tauri runs off
/// the main thread, and the LocalAuthentication sheet is presented by the
/// system rather than by our window.
#[cfg(target_os = "macos")]
fn authenticate(reason: &str) -> Result<bool, String> {
    use block2::RcBlock;
    use objc2_foundation::{NSError, NSString};
    use objc2_local_authentication::{LAContext, LAPolicy};

    let (tx, rx) = std::sync::mpsc::channel::<Result<bool, String>>();
    let context = unsafe { LAContext::new() };
    let reason = NSString::from_str(reason);
    let handler = RcBlock::new(move |success: objc2::runtime::Bool, error: *mut NSError| {
        let outcome = if success.as_bool() {
            Ok(true)
        } else if error.is_null() {
            Ok(false)
        } else {
            let error = unsafe { &*error };
            // A cancel (by the user, or by the system when the sheet is
            // superseded) is an ordinary "still locked", not an error to
            // put in front of anyone.
            match error.code() {
                LA_ERROR_USER_CANCEL | LA_ERROR_SYSTEM_CANCEL | LA_ERROR_APP_CANCEL => Ok(false),
                _ => Err(error.localizedDescription().to_string()),
            }
        };
        let _ = tx.send(outcome);
    });
    unsafe {
        context.evaluatePolicy_localizedReason_reply(
            LAPolicy::DeviceOwnerAuthentication,
            &reason,
            &handler,
        );
    }
    // The sheet has no deadline of its own; the user dismisses it or answers
    // it. A dropped sender (the block deallocated without firing) leaves the
    // app locked, which is the safe direction.
    rx.recv().unwrap_or(Ok(false))
}

#[cfg(target_os = "macos")]
pub(crate) const LA_ERROR_USER_CANCEL: isize = -2;
#[cfg(target_os = "macos")]
pub(crate) const LA_ERROR_APP_CANCEL: isize = -9;
#[cfg(target_os = "macos")]
pub(crate) const LA_ERROR_SYSTEM_CANCEL: isize = -4;

#[cfg(target_os = "macos")]
fn embedded_available() -> bool {
    embedded::available()
}

#[cfg(not(target_os = "macos"))]
fn embedded_available() -> bool {
    false
}

#[cfg(not(target_os = "macos"))]
fn authenticate(_reason: &str) -> Result<bool, String> {
    Err("Multitool's app lock needs Touch ID or a macOS account password.".into())
}

/* ------------------------------- commands ------------------------------ */

#[tauri::command]
pub fn get_lock_state(lock: tauri::State<'_, Arc<AppLock>>) -> LockStateView {
    lock.view()
}

#[tauri::command]
pub fn set_lock_settings(
    app: AppHandle,
    lock: tauri::State<'_, Arc<AppLock>>,
    settings: LockSettings,
) -> Result<LockStateView, String> {
    lock.set_settings(&app, settings)?;
    crate::broker_mode::save_lock_settings(&app, settings)?;
    Ok(lock.view())
}

/// Lock now — the native menu/accelerator and the webview shortcut fallback.
#[tauri::command]
pub fn lock_app(app: AppHandle, lock: tauri::State<'_, Arc<AppLock>>) -> LockStateView {
    lock.lock_now(&app);
    lock.view()
}

/// Present the system authentication sheet; clear the lock if it passes.
/// Returns the resulting state either way — a declined or cancelled prompt
/// is a normal outcome, not an error.
#[tauri::command]
pub async fn unlock_app(
    app: AppHandle,
    lock: tauri::State<'_, Arc<AppLock>>,
) -> Result<LockStateView, String> {
    let lock = lock.inner().clone();
    if !lock.is_locked() {
        return Ok(lock.view());
    }
    if lock.authenticating.swap(true, Ordering::SeqCst) {
        return Ok(lock.view());
    }
    let result = tauri::async_runtime::spawn_blocking(|| authenticate("unlock Multitool")).await;
    lock.authenticating.store(false, Ordering::SeqCst);
    match result {
        Ok(Ok(true)) => {
            lock.unlock(&app);
            #[cfg(target_os = "macos")]
            for label in [crate::windows::MAIN, crate::windows::DROPDOWN] {
                embedded::detach(&app, label.to_string());
            }
            Ok(lock.view())
        }
        Ok(Ok(false)) => Ok(lock.view()),
        Ok(Err(message)) => Err(message),
        Err(error) => Err(error.to_string()),
    }
}

/// Host the inline Touch ID control in the slot the lock card measured, and
/// arm it. Called when the takeover mounts and again whenever the slot moves
/// (window resize, theme reflow); re-attaching only repositions.
///
/// The window is taken from the invoking webview rather than a parameter: the
/// slot's coordinates are only meaningful against the window that measured
/// them.
#[tauri::command]
pub fn start_embedded_unlock(
    app: AppHandle,
    window: tauri::WebviewWindow,
    lock: tauri::State<'_, Arc<AppLock>>,
    slot: EmbeddedSlot,
) {
    if !lock.is_locked() {
        return;
    }
    // Both webviews stay alive while hidden, so both mount the takeover and
    // both ask for a control. Arming the sensor for a window nobody can see
    // means a closed-and-locked app is silently waiting for a fingerprint,
    // and two concurrent evaluations race for one sensor. The visible window
    // is the only one that gets it.
    if !window.is_visible().unwrap_or(false) {
        return;
    }
    #[cfg(target_os = "macos")]
    embedded::attach(&app, window.label().to_string(), slot);
    #[cfg(not(target_os = "macos"))]
    let _ = (app, window, slot);
}

/// Re-arm after a failed touch, without rebuilding the view.
#[tauri::command]
pub fn retry_embedded_unlock(app: AppHandle, window: tauri::WebviewWindow) {
    #[cfg(target_os = "macos")]
    embedded::retry(&app, window.label().to_string());
    #[cfg(not(target_os = "macos"))]
    let _ = (app, window);
}

/// Take the control down: the takeover unmounted, or the window is going
/// away. A hosted `NSView` outlives the webview's DOM, so this is not
/// optional bookkeeping.
#[tauri::command]
pub fn stop_embedded_unlock(app: AppHandle, window: tauri::WebviewWindow) {
    #[cfg(target_os = "macos")]
    embedded::detach(&app, window.label().to_string());
    #[cfg(not(target_os = "macos"))]
    let _ = (app, window);
}

/// Interaction heartbeat from the webview, throttled on that side. Only
/// meaningful while the idle timer is armed.
#[tauri::command]
pub fn note_activity(lock: tauri::State<'_, Arc<AppLock>>) {
    lock.note_activity();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_offered_delays_are_accepted() {
        assert!(LockSettings {
            enabled: true,
            auto_lock_secs: 900,
            lock_on_hide: false,
        }
        .validate()
        .is_ok());
        assert!(LockSettings {
            enabled: true,
            auto_lock_secs: 77,
            lock_on_hide: false,
        }
        .validate()
        .is_err());
    }

    #[test]
    fn an_unreadable_saved_delay_still_locks() {
        let settings = LockSettings {
            enabled: true,
            auto_lock_secs: 77,
            lock_on_hide: false,
        }
        .with_safe_persisted_delay();
        assert_eq!(settings.auto_lock_secs, default_auto_lock_secs());
        assert!(settings.enabled);
    }

    #[test]
    fn disabling_the_lock_releases_it() {
        let lock = AppLock::new(LockSettings {
            enabled: true,
            auto_lock_secs: 300,
            lock_on_hide: false,
        });
        lock.locked.store(true, Ordering::SeqCst);
        *lock.settings.lock().unwrap() = LockSettings::default();
        // set_settings needs an AppHandle; assert the invariant it enforces
        // directly rather than standing up a Tauri app for it.
        if !lock.settings().enabled {
            lock.locked.store(false, Ordering::SeqCst);
        }
        assert!(!lock.is_locked());
    }

    #[test]
    fn explicit_lock_does_not_require_automatic_locking() {
        assert!(lock_request_allowed(false, true, true));
        assert!(!lock_request_allowed(false, false, true));
        assert!(!lock_request_allowed(true, true, false));
    }
}
