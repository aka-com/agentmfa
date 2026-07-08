//! Tray + window choreography (DESIGN.md §2).
//!
//! AgentMFA is a regular windowed app: the resizable **main window** is the
//! primary surface and is present in the Dock and the app switcher. The menu
//! bar is opt-in — the user minimizes to it (or closes the window, which
//! keeps the broker running), and the always-present tray icon brings the
//! window back. The **approval window** is its own small always-on-top
//! window so it can appear even when the main window is hidden.
//!
//! Only when the user enables "hide the Dock icon when minimized to the menu
//! bar" does retreating switch to the accessory activation policy; opening
//! the window always restores the regular policy.

use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager};

pub const MAIN: &str = "main";
pub const APPROVAL: &str = "approval";

/// Install the always-present tray icon (§2). Left-click brings the main
/// window forward (from hidden or the menu bar); when the window is already
/// up it stays the guaranteed entry point to pending approvals.
pub fn setup_tray(app: &AppHandle) -> tauri::Result<()> {
    let icon = app
        .default_window_icon()
        .cloned()
        .expect("bundled default icon");
    TrayIconBuilder::with_id("main")
        .icon(icon)
        .icon_as_template(true) // render as a menu-bar template image
        .tooltip("AgentMFA")
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                let app = tray.app_handle();
                if window_visible(app, MAIN) {
                    raise_pending_approval(app);
                } else {
                    open_main(app);
                }
            }
        })
        .build(app)?;
    Ok(())
}

fn window_visible(app: &AppHandle, label: &str) -> bool {
    app.get_webview_window(label)
        .and_then(|w| w.is_visible().ok())
        .unwrap_or(false)
}

fn raise_pending_approval(app: &AppHandle) {
    if let Some(win) = app.get_webview_window(APPROVAL) {
        // The core shows/hides this on queue changes; nudge it forward on
        // an explicit tray click too.
        if win.is_visible().unwrap_or(false) {
            let _ = win.show();
            let _ = win.set_focus();
        }
    }
}

/// Bring the always-on-top approval window forward — the pending banner's
/// "Review" button. The core populates and shows it whenever the queue is
/// non-empty; this makes the button an explicit path back to it (e.g. after
/// it lost focus behind another always-on-top window or on another Space).
#[tauri::command]
pub fn ui_show_approval(app: AppHandle) {
    if let Some(win) = app.get_webview_window(APPROVAL) {
        let _ = win.show();
        let _ = win.set_focus();
    }
}

/// Show and focus the main window under the regular (Dock-visible)
/// activation policy. Restores the Dock icon if a prior menu-bar retreat
/// had hidden it.
fn open_main(app: &AppHandle) {
    set_activation_policy(app, true);
    if let Some(win) = app.get_webview_window(MAIN) {
        let _ = win.show();
        let _ = win.set_focus();
    }
}

/// Hide the main window, leaving the broker running behind the tray icon. If
/// the user opted to hide the Dock icon in the menu bar, drop to accessory
/// activation; otherwise keep the Dock icon (the conventional default).
fn retreat_to_menu_bar(app: &AppHandle) {
    if let Some(win) = app.get_webview_window(MAIN) {
        let _ = win.hide();
    }
    if menu_bar_hides_dock(app) {
        set_activation_policy(app, false);
    }
}

/// Read the "hide Dock icon in the menu bar" preference. Defaults to `false`
/// (keep the Dock icon) if the broker state is not yet managed.
fn menu_bar_hides_dock(app: &AppHandle) -> bool {
    app.try_state::<crate::commands::AppState>()
        .map(|s| s.broker.settings().menu_bar_hides_dock)
        .unwrap_or(false)
}

#[cfg(target_os = "macos")]
fn set_activation_policy(app: &AppHandle, regular: bool) {
    let policy = if regular {
        tauri::ActivationPolicy::Regular
    } else {
        tauri::ActivationPolicy::Accessory
    };
    let _ = app.set_activation_policy(policy);
}

#[cfg(not(target_os = "macos"))]
fn set_activation_policy(_app: &AppHandle, _regular: bool) {}

/// Reopen the main window (Dock-icon reactivation via `RunEvent::Reopen`).
pub fn ui_open_main(app: AppHandle) {
    open_main(&app);
}

/// Switch chrome: "window" opens the main window; "tray" minimizes to the
/// menu bar.
#[tauri::command]
pub fn ui_set_mode(app: AppHandle, mode: String) -> Result<(), String> {
    match mode.as_str() {
        "window" => {
            open_main(&app);
            Ok(())
        }
        "tray" => {
            retreat_to_menu_bar(&app);
            Ok(())
        }
        other => Err(format!("unknown mode {other:?}")),
    }
}

/// Closing the main window hides it and keeps the broker running rather than
/// quitting (§2); honors the "hide Dock in the menu bar" preference.
#[tauri::command]
pub fn ui_hide_main(app: AppHandle) {
    retreat_to_menu_bar(&app);
}
