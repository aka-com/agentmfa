//! The inline Touch ID control, hosted over the webview.
//!
//! `LAAuthenticationView` (LocalAuthenticationEmbeddedUI, macOS 12+) draws the
//! authentication UI inside our own window instead of raising the system
//! alert. Two properties of it decide this module's whole shape, and both come
//! straight from the framework headers:
//!
//! 1. **It is non-textual.** The view is "a compact icon hinting users to use
//!    Touch ID or Watch"; the headers require that "the reason for the
//!    authentication must be apparent from the surrounding UI." The lock
//!    screen's title and explanation stay ours, in the webview — this view is
//!    only the sensor affordance that sits in the middle of it.
//!
//! 2. **It cannot do passwords.** The only policies it accepts are the
//!    biometrics/companion ones; `DeviceOwnerAuthentication` is accepted "just
//!    for convenience" and *fails outright* when neither biometry nor a Watch
//!    is available. So this is never the only way in: the lock screen keeps an
//!    "Enter password…" button on the system-sheet path in [`super`], which is
//!    what a Mac with no Touch ID, a failed enrollment, or a user who simply
//!    prefers typing gets.
//!
//! Hosting it means an `NSView` over the `WKWebView`. The webview reports the
//! rect of the slot it left in the lock card, in CSS points from the top-left
//! of the window's content view (Tauri gives the webview the whole content
//! view: `titleBarStyle: Overlay` with a hidden title, so the two are the same
//! surface and the only conversion needed is flipping the origin). Everything
//! here runs on the main thread, and the views are kept in a main-thread-only
//! registry because `Retained` is not `Send`.

use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::Arc;

use block2::RcBlock;
use objc2::rc::Retained;
use objc2::MainThreadMarker;
use objc2_app_kit::{NSView, NSWindow};
use objc2_foundation::{NSError, NSPoint, NSRect, NSSize, NSString};
use objc2_local_authentication::{LAContext, LAPolicy};
use objc2_local_authentication_embedded_ui::LAAuthenticationView;
use tauri::{AppHandle, Manager as _};

use super::{AppLock, LA_ERROR_APP_CANCEL, LA_ERROR_SYSTEM_CANCEL, LA_ERROR_USER_CANCEL};

/// A hosted control, kept alive for as long as it is on screen. The context is
/// retained alongside its view: the view is only a presentation surface for
/// that context's evaluation, and dropping the context would cancel it.
struct Hosted {
    context: Retained<LAContext>,
    view: Retained<LAAuthenticationView>,
}

thread_local! {
    /// Window label → its hosted control. Main thread only, by construction:
    /// every entry point below hops through `run_on_main_thread` first.
    static HOSTED: RefCell<HashMap<String, Hosted>> = RefCell::new(HashMap::new());
}

/// The slot the webview measured for the control, in CSS points from the
/// top-left of the window.
#[derive(Debug, Clone, Copy, serde::Deserialize)]
pub struct Slot {
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}

/// Whether the inline control can be used at all: biometry (or a paired
/// Watch) has to be enrolled, since this view cannot fall back to a password.
pub fn available() -> bool {
    let context = unsafe { LAContext::new() };
    unsafe { context.canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthenticationWithBiometrics) }
        .is_ok()
}

/// Place the control in `slot` and begin evaluating. Idempotent per window:
/// re-attaching (a resize, a re-render) moves the existing view rather than
/// stacking a second one and starting a second evaluation.
pub fn attach(app: &AppHandle, label: String, slot: Slot) {
    let app_for_main = app.clone();
    let _ = app.clone().run_on_main_thread(move || {
        let Some(mtm) = MainThreadMarker::new() else {
            return;
        };
        let Some(content) = content_view(&app_for_main, &label) else {
            return;
        };
        let frame = flip(&content, slot);

        // Already hosted: this is a move, not a new evaluation. Restarting the
        // evaluation on every resize would re-arm the sensor mid-touch.
        let moved = HOSTED.with_borrow(|hosted| {
            if let Some(existing) = hosted.get(&label) {
                existing.view.setFrame(frame);
                true
            } else {
                false
            }
        });
        if moved {
            return;
        }

        let context = unsafe { LAContext::new() };
        let view = unsafe {
            LAAuthenticationView::initWithContext(mtm.alloc::<LAAuthenticationView>(), &context)
        };
        view.setFrame(frame);
        content.addSubview(&view);
        HOSTED.with_borrow_mut(|hosted| {
            hosted.insert(
                label.clone(),
                Hosted {
                    context: context.clone(),
                    view,
                },
            );
        });
        evaluate(&app_for_main, &context, label);
    });
}

/// Take the control down — on unlock, on a window hiding, on a webview reload.
pub fn detach(app: &AppHandle, label: String) {
    let _ = app.clone().run_on_main_thread(move || {
        HOSTED.with_borrow_mut(|hosted| {
            if let Some(existing) = hosted.remove(&label) {
                // Invalidating first stops the in-flight evaluation; a context
                // whose view has gone away would otherwise keep the sensor
                // armed with nothing to draw into.
                unsafe { existing.context.invalidate() };
                existing.view.removeFromSuperview();
            }
        });
    });
}

/// Re-arm after a failed or cancelled touch, without rebuilding the view.
pub fn retry(app: &AppHandle, label: String) {
    let app_for_main = app.clone();
    let _ = app.clone().run_on_main_thread(move || {
        let context = HOSTED.with_borrow(|hosted| hosted.get(&label).map(|h| h.context.clone()));
        if let Some(context) = context {
            evaluate(&app_for_main, &context, label);
        }
    });
}

/// Start (or restart) the evaluation this view is presenting.
///
/// Unlike the system-sheet path this does not block: `evaluatePolicy` returns
/// immediately and the reply block lands on an arbitrary queue, so the outcome
/// reaches the UI as a lock-state event rather than as a command's return
/// value. That is also why the inline control can be armed the moment the lock
/// engages — there is no modal sheet to strand on an unattended screen.
fn evaluate(app: &AppHandle, context: &LAContext, label: String) {
    let app = app.clone();
    let reason = NSString::from_str("unlock your credentials");
    let handler = RcBlock::new(move |success: objc2::runtime::Bool, error: *mut NSError| {
        let Some(lock) = app.try_state::<Arc<AppLock>>() else {
            return;
        };
        if success.as_bool() {
            lock.unlock_from_embedded(&app);
            detach(&app, label.clone());
            return;
        }
        // A cancel is an ordinary "still locked" — the user reaching for the
        // password button, or the system taking the sensor away. Anything else
        // (a wrong finger, too many attempts, biometry locked out) is a
        // message the lock screen shows next to the control.
        let message = unsafe { error.as_ref() }.and_then(|error| match error.code() {
            LA_ERROR_USER_CANCEL | LA_ERROR_SYSTEM_CANCEL | LA_ERROR_APP_CANCEL => None,
            _ => Some(error.localizedDescription().to_string()),
        });
        lock.embedded_failed(&app, message);
    });
    unsafe {
        // Biometrics-only: this view cannot present a password, and asking for
        // `DeviceOwnerAuthentication` here would fail outright on a Mac with
        // no sensor rather than falling back to one.
        context.evaluatePolicy_localizedReason_reply(
            LAPolicy::DeviceOwnerAuthenticationWithBiometrics,
            &reason,
            &handler,
        );
    }
}

fn content_view(app: &AppHandle, label: &str) -> Option<Retained<NSView>> {
    let window = app.get_webview_window(label)?;
    let ns_window = window.ns_window().ok()?;
    let ns_window: &NSWindow = unsafe { &*ns_window.cast() };
    ns_window.contentView()
}

/// CSS points from the top-left → AppKit points from the bottom-left.
///
/// Split from the view so the arithmetic is testable without an `NSWindow`:
/// getting this wrong puts the control somewhere plausible-looking but wrong,
/// which is exactly the kind of thing a unit test should catch and a glance
/// at a screenshot will not.
fn flip_in(content_height: f64, slot: Slot) -> NSRect {
    NSRect::new(
        NSPoint::new(slot.x, content_height - slot.y - slot.height),
        NSSize::new(slot.width, slot.height),
    )
}

fn flip(content: &NSView, slot: Slot) -> NSRect {
    flip_in(content.frame().size.height, slot)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_slot_is_flipped_into_appkit_coordinates() {
        // A 64pt slot 100pt down from the top of a 600pt content view sits
        // 436pt up from the bottom: 600 - 100 - 64.
        let frame = flip_in(
            600.0,
            Slot {
                x: 120.0,
                y: 100.0,
                width: 64.0,
                height: 64.0,
            },
        );
        assert_eq!(frame.origin.x, 120.0);
        assert_eq!(frame.origin.y, 436.0);
        assert_eq!(frame.size.width, 64.0);
        assert_eq!(frame.size.height, 64.0);
    }

    #[test]
    fn a_slot_at_the_bottom_edge_lands_at_the_origin() {
        let frame = flip_in(
            600.0,
            Slot {
                x: 0.0,
                y: 536.0,
                width: 64.0,
                height: 64.0,
            },
        );
        assert_eq!(frame.origin.y, 0.0);
    }
}
