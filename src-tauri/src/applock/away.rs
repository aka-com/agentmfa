//! Locking when the machine, rather than the app, is put away.
//!
//! The idle timer only measures interaction with our own windows, so on its
//! own a 60-minute delay means a closed lid leaves the app unlocked for an
//! hour. These are the three system events that mean "the user is gone" well
//! before the timer would say so:
//!
//! - **Sleep** (`NSWorkspaceWillSleepNotification`) — delivered *before* the
//!   machine sleeps, so the lock is taken while we are still running.
//! - **Screen lock** (`com.apple.screenIsLocked`) — a distributed
//!   notification rather than a workspace one; there is no public workspace
//!   equivalent. Undocumented but long-standing, so a missing notification
//!   must degrade to "the idle timer eventually gets it", never to a panic.
//! - **Fast user switching** (`NSWorkspaceSessionDidResignActiveNotification`)
//!   — another account takes the console. The data-protection keychain items
//!   are `ThisDeviceOnly` but not per-session, so this one matters.
//!
//! Waking, unlocking the screen, or switching back deliberately does *not*
//! unlock: only an authentication does that.
//!
//! The observers live for the life of the process. Their registration handles
//! are leaked on purpose — unregistering would mean tearing down the lock, and
//! the lock outlives everything except the app itself.

use std::sync::Arc;

use tauri::AppHandle;

use super::AppLock;

/// Install the away-from-machine observers. Safe to call once, at setup.
#[cfg(target_os = "macos")]
pub fn observe(app: AppHandle, lock: Arc<AppLock>) {
    use block2::RcBlock;
    use objc2_app_kit::{
        NSWorkspace, NSWorkspaceSessionDidResignActiveNotification,
        NSWorkspaceWillSleepNotification,
    };
    use objc2_foundation::{NSDistributedNotificationCenter, NSNotification, NSString};

    // Registration touches AppKit singletons, so it belongs on the main
    // thread; the blocks themselves are delivered there too (no queue given
    // means "the posting thread", which for these is the main thread).
    let _ = app.clone().run_on_main_thread(move || {
        let workspace = NSWorkspace::sharedWorkspace();
        let workspace_center = workspace.notificationCenter();

        for name in [
            unsafe { NSWorkspaceWillSleepNotification },
            unsafe { NSWorkspaceSessionDidResignActiveNotification },
        ] {
            let app = app.clone();
            let lock = lock.clone();
            let block = RcBlock::new(move |_: std::ptr::NonNull<NSNotification>| {
                lock.lock(&app);
            });
            let observer = unsafe {
                workspace_center.addObserverForName_object_queue_usingBlock(
                    Some(name),
                    None,
                    None,
                    &block,
                )
            };
            std::mem::forget(observer);
        }

        // Screen lock has no workspace notification; it is only published on
        // the distributed centre, under a name Apple has never documented.
        let screen_locked = NSString::from_str("com.apple.screenIsLocked");
        let distributed = NSDistributedNotificationCenter::defaultCenter();
        let app = app.clone();
        let block = RcBlock::new(move |_: std::ptr::NonNull<NSNotification>| {
            lock.lock(&app);
        });
        let observer = unsafe {
            distributed.addObserverForName_object_queue_usingBlock(
                Some(&screen_locked),
                None,
                None,
                &block,
            )
        };
        std::mem::forget(observer);
    });
}

#[cfg(not(target_os = "macos"))]
pub fn observe(_app: AppHandle, _lock: Arc<AppLock>) {}
