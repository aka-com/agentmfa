//! Tray + window
//!
//! Multitool has a resizable main window, an NSStatusItem-style tray
//! dropdown. The tray icon
//! is always present and toggles the compact dropdown beneath its status item.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use tauri::menu::{Menu, MenuItem, MenuItemKind, PredefinedMenuItem, WINDOW_SUBMENU_ID};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, PhysicalPosition, Rect};

#[cfg(target_os = "macos")]
use tauri_nspanel::{tauri_panel, ManagerExt as _, WebviewWindowExt as _};

#[cfg(test)]
use tauri::image::Image;

#[cfg(test)]
const TRAY_ICON_BYTES: &[u8] = include_bytes!("../icons/tray.png");
#[cfg(test)]
const APP_ICON_BYTES: &[u8] = include_bytes!("../icons/icon.png");

pub const MAIN: &str = "main";
pub const DROPDOWN: &str = "dropdown";
pub const EVT_DROPDOWN_HIDDEN: &str = "aka://dropdown-hidden";
pub const EVT_DROPDOWN_SHOWN: &str = "aka://dropdown-shown";
pub const EVT_OPEN_SETTINGS: &str = "aka://open-settings";
const APP_WINDOW_MENU_ID: &str = "app-window";
const NEW_WINDOW_MENU_ID: &str = "new-window";

const DROPDOWN_GAP: f64 = 6.0;
static LAST_TRAY_ANCHOR: Mutex<Option<TrayAnchor>> = Mutex::new(None);
/// A dropdown form may hold credentials that must survive native
/// authentication and any error returned afterwards. While it is open, focus
/// loss (including the Touch ID sheet becoming key) must not dismiss it.
static DROPDOWN_FORM_ACTIVE: AtomicBool = AtomicBool::new(false);

fn dropdown_hide_allowed() -> bool {
    !DROPDOWN_FORM_ACTIVE.load(Ordering::SeqCst)
}

#[cfg(target_os = "macos")]
tauri_panel! {
    panel!(AkaDropdownPanel {
        config: {
            can_become_key_window: true,
            can_become_main_window: false,
            becomes_key_only_if_needed: true,
            is_floating_panel: true,
            hides_on_deactivate: false
        }
    })
}

/// Convert the dropdown's ordinary Tauri NSWindow into a non-activating
/// NSPanel. A panel can accept keyboard input without activating Multitool and
/// raising the already-visible main window above the user's current app.
#[cfg(target_os = "macos")]
pub fn setup_dropdown_panel(app: &AppHandle) -> tauri::Result<()> {
    use tauri_nspanel::panel::NSWindowStyleMask;

    let window = app
        .get_webview_window(DROPDOWN)
        .ok_or_else(|| tauri::Error::AssetNotFound("configured dropdown window".into()))?;
    let panel = window.to_panel::<AkaDropdownPanel>()?;
    let style = panel.as_panel().styleMask() | NSWindowStyleMask::NonactivatingPanel;
    panel.set_style_mask(style);
    panel.set_floating_panel(true);
    panel.set_becomes_key_only_if_needed(true);
    panel.set_hides_on_deactivate(false);
    Ok(())
}

#[cfg(not(target_os = "macos"))]
pub fn setup_dropdown_panel(_app: &AppHandle) -> tauri::Result<()> {
    Ok(())
}

#[cfg(target_os = "macos")]
pub fn move_traffic_lights_down(window: &tauri::WebviewWindow, offset: f64) -> tauri::Result<()> {
    use objc2_app_kit::{NSWindow, NSWindowButton};

    let ns_window = window.ns_window()?;
    let ns_window: &NSWindow = unsafe { &*ns_window.cast() };
    for kind in [
        NSWindowButton::CloseButton,
        NSWindowButton::MiniaturizeButton,
        NSWindowButton::ZoomButton,
    ] {
        if let Some(button) = ns_window.standardWindowButton(kind) {
            let mut origin = button.frame().origin;
            origin.y -= offset;
            button.setFrameOrigin(origin);
        }
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
pub fn move_traffic_lights_down(_window: &tauri::WebviewWindow, _offset: f64) -> tauri::Result<()> {
    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct TrayAnchor {
    x: f64,
    y: f64,
    width: f64,
    height: f64,
}

#[derive(Clone, Copy, Debug)]
struct Bounds {
    x: f64,
    y: f64,
    width: f64,
    height: f64,
}

/// Extend Tauri's conventional macOS application menu with a reliable way
/// back to Multitool when its Dock and tray affordances are unavailable.
pub fn setup_app_menu(app: &AppHandle) -> tauri::Result<()> {
    let menu = Menu::default(app)?;
    let new_window = MenuItem::with_id(
        app,
        NEW_WINDOW_MENU_ID,
        "New Window",
        true,
        Some("CmdOrCtrl+N"),
    )?;
    for item in menu.items()? {
        if let MenuItemKind::Submenu(submenu) = item {
            if submenu.text()? == "File" {
                let separator = PredefinedMenuItem::separator(app)?;
                submenu.prepend_items(&[&new_window, &separator])?;
                break;
            }
        }
    }

    let app_window = MenuItem::with_id(app, APP_WINDOW_MENU_ID, "Multitool", true, None::<&str>)?;
    if let Some(MenuItemKind::Submenu(window_menu)) = menu.get(WINDOW_SUBMENU_ID) {
        let separator = PredefinedMenuItem::separator(app)?;
        window_menu.append_items(&[&separator, &app_window])?;
    }
    app.set_menu(menu)?;
    app.on_menu_event(|app, event| match event.id().as_ref() {
        NEW_WINDOW_MENU_ID => open_main(app),
        APP_WINDOW_MENU_ID => focus_existing_or_reopen(app),
        _ => {}
    });
    Ok(())
}

fn focus_existing_or_reopen(app: &AppHandle) {
    if !dropdown_hide_allowed() {
        show_dropdown(app);
        return;
    }
    for label in [MAIN, DROPDOWN] {
        let Some(window) = app.get_webview_window(label) else {
            continue;
        };
        if window.is_visible().unwrap_or(false) {
            let _ = window.unminimize();
            let _ = window.set_focus();
            return;
        }
    }
    open_main(app);
}

/// Install the always-present tray icon. Left-click toggles the compact
/// dropdown; right-click exposes the conventional app menu.
pub fn setup_tray(app: &AppHandle) -> tauri::Result<()> {
    let open = MenuItem::with_id(app, "tray-open", "Open Multitool", true, None::<&str>)?;
    let settings = MenuItem::with_id(app, "tray-settings", "Settings…", true, None::<&str>)?;
    let separator = PredefinedMenuItem::separator(app)?;
    let quit = MenuItem::with_id(app, "tray-quit", "Quit Multitool", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&open, &settings, &separator, &quit])?;

    let tray = app
        .tray_by_id("main")
        .ok_or_else(|| tauri::Error::AssetNotFound("configured tray icon".into()))?;
    tray.set_menu(Some(menu))?;
    tray.set_show_menu_on_left_click(false)?;
    tray.on_menu_event(|app, event| match event.id().as_ref() {
        "tray-open" => open_main(app),
        "tray-settings" => {
            if !dropdown_hide_allowed() {
                show_dropdown(app);
                return;
            }
            show_dropdown(app);
            let _ = app.emit_to(DROPDOWN, EVT_OPEN_SETTINGS, ());
        }
        "tray-quit" => app.exit(0),
        _ => {}
    });
    tray.on_tray_icon_event(|tray, event| match event {
        TrayIconEvent::Click {
            rect,
            button: MouseButton::Left,
            button_state: MouseButtonState::Up,
            ..
        } => {
            let app = tray.app_handle();
            remember_tray_anchor(app, rect);
            toggle_dropdown(app);
        }
        TrayIconEvent::Click { rect, .. } => {
            remember_tray_anchor(tray.app_handle(), rect);
        }
        _ => {}
    });
    Ok(())
}

fn remember_tray_anchor(app: &AppHandle, rect: Rect) {
    let scale = app
        .get_webview_window(DROPDOWN)
        .and_then(|window| window.scale_factor().ok())
        .unwrap_or(1.0);
    let position = rect.position.to_physical::<f64>(scale);
    let size = rect.size.to_physical::<f64>(scale);
    *LAST_TRAY_ANCHOR.lock().unwrap() = Some(TrayAnchor {
        x: position.x,
        y: position.y,
        width: size.width,
        height: size.height,
    });
}

fn toggle_dropdown(app: &AppHandle) {
    if window_visible(app, DROPDOWN) {
        let _ = hide_dropdown(app);
    } else {
        show_dropdown(app);
    }
}

fn show_dropdown(app: &AppHandle) {
    let Some(window) = app.get_webview_window(DROPDOWN) else {
        return;
    };
    if let Some(anchor) = *LAST_TRAY_ANCHOR.lock().unwrap() {
        if let Ok(size) = window.outer_size() {
            let monitor = app
                .monitor_from_point(
                    anchor.x + anchor.width / 2.0,
                    anchor.y + anchor.height / 2.0,
                )
                .ok()
                .flatten();
            let bounds = monitor.map(|monitor| {
                let work = monitor.work_area();
                Bounds {
                    x: work.position.x as f64,
                    y: work.position.y as f64,
                    width: work.size.width as f64,
                    height: work.size.height as f64,
                }
            });
            let (x, y) = dropdown_origin(anchor, size.width as f64, size.height as f64, bounds);
            let _ = window.set_position(PhysicalPosition::new(x, y));
        }
    }
    show_dropdown_window(app, &window);
    let _ = app.emit_to(DROPDOWN, EVT_DROPDOWN_SHOWN, ());
}

/// Show the macOS dropdown through NSPanel rather than Tauri's `show` and
/// `set_focus`: Tauri activates the whole application when focusing a native
/// window, which also raises the main Multitool window.
#[cfg(target_os = "macos")]
fn show_dropdown_window(app: &AppHandle, window: &tauri::WebviewWindow) {
    if let Ok(panel) = app.get_webview_panel(DROPDOWN) {
        panel.show_and_make_key();
    } else {
        // Startup normally makes this unreachable, but retaining a fallback
        // keeps the dropdown recoverable if panel registration ever changes.
        let _ = window.show();
        let _ = window.set_focus();
    }
}

#[cfg(not(target_os = "macos"))]
fn show_dropdown_window(_app: &AppHandle, window: &tauri::WebviewWindow) {
    let _ = window.show();
    let _ = window.set_focus();
}

fn dropdown_origin(
    anchor: TrayAnchor,
    window_width: f64,
    window_height: f64,
    bounds: Option<Bounds>,
) -> (i32, i32) {
    let mut x = anchor.x + anchor.width / 2.0 - window_width / 2.0;
    let mut y = anchor.y + anchor.height + DROPDOWN_GAP;

    if let Some(bounds) = bounds {
        let right = bounds.x + bounds.width;
        let bottom = bounds.y + bounds.height;
        if anchor.y + anchor.height / 2.0 > bounds.y + bounds.height / 2.0 {
            y = anchor.y - window_height - DROPDOWN_GAP;
        }
        x = x.clamp(bounds.x, (right - window_width).max(bounds.x));
        y = y.clamp(bounds.y, (bottom - window_height).max(bounds.y));
    }
    (x.round() as i32, y.round() as i32)
}

fn window_visible(app: &AppHandle, label: &str) -> bool {
    app.get_webview_window(label)
        .and_then(|w| w.is_visible().ok())
        .unwrap_or(false)
}

/// Hide the compact dropdown and ask its webview to clear transient secret
/// prefixes and unfinished modal state before the next open. An active form
/// blocks hiding so focus transfers to native authentication cannot destroy
/// the draft before a command reports its outcome.
pub fn hide_dropdown(app: &AppHandle) -> bool {
    if !dropdown_hide_allowed() {
        return false;
    }
    if let Some(window) = app.get_webview_window(DROPDOWN) {
        if window.is_visible().unwrap_or(false) {
            let _ = app.emit_to(DROPDOWN, EVT_DROPDOWN_HIDDEN, ());
            hide_dropdown_window(app, &window);
        }
    }
    true
}

#[cfg(target_os = "macos")]
fn hide_dropdown_window(app: &AppHandle, window: &tauri::WebviewWindow) {
    if let Ok(panel) = app.get_webview_panel(DROPDOWN) {
        panel.hide();
    } else {
        let _ = window.hide();
    }
}

#[cfg(not(target_os = "macos"))]
fn hide_dropdown_window(_app: &AppHandle, window: &tauri::WebviewWindow) {
    let _ = window.hide();
}

#[tauri::command]
pub fn ui_hide_dropdown(app: AppHandle) {
    let _ = hide_dropdown(&app);
}

/// Keep the menu-bar form visible across focus changes while it may contain
/// unfinished or sensitive input. Only the dropdown webview can hold this
/// lock; other windows must not be able to strand the dropdown open.
#[tauri::command]
pub fn ui_set_dropdown_form_active(
    window: tauri::WebviewWindow,
    active: bool,
) -> Result<(), String> {
    if window.label() != DROPDOWN {
        return Err("only the menu-bar dropdown can hold its form open".into());
    }
    DROPDOWN_FORM_ACTIVE.store(active, Ordering::SeqCst);
    Ok(())
}

/// Show and focus the main window under the regular (Dock-visible)
/// activation policy. Restores the Dock icon if a prior menu-bar retreat
/// had hidden it.
fn open_main(app: &AppHandle) {
    if !hide_dropdown(app) {
        return;
    }
    set_activation_policy(app, true);
    if let Some(win) = app.get_webview_window(MAIN) {
        let _ = win.unminimize();
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
/// (keep the Dock icon) if the broker state is not yet managed, and for a
/// remote broker: window chrome is a this-machine concern, and this sync
/// window-event path cannot await a network round trip.
fn menu_bar_hides_dock(app: &AppHandle) -> bool {
    app.try_state::<crate::commands::AppState>()
        .and_then(|s| s.brokers.local_broker())
        .map(|broker| broker.settings().menu_bar_hides_dock)
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

/// Reopen the main window (Dock-icon reactivation via `RunEvent::Reopen`,
/// which only macOS emits).
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
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
/// quitting; honors the "hide Dock in the menu bar" preference.
#[tauri::command]
pub fn ui_hide_main(app: AppHandle) {
    retreat_to_menu_bar(&app);
}

#[cfg(test)]
mod tests {
    use super::*;

    const WORK: Bounds = Bounds {
        x: 0.0,
        y: 24.0,
        width: 1440.0,
        height: 876.0,
    };

    #[test]
    fn active_form_blocks_dropdown_hiding() {
        DROPDOWN_FORM_ACTIVE.store(true, Ordering::SeqCst);
        assert!(!dropdown_hide_allowed());
        DROPDOWN_FORM_ACTIVE.store(false, Ordering::SeqCst);
        assert!(dropdown_hide_allowed());
    }

    #[test]
    fn dropdown_is_centered_below_a_top_tray_item() {
        let anchor = TrayAnchor {
            x: 1200.0,
            y: 0.0,
            width: 24.0,
            height: 24.0,
        };
        assert_eq!(dropdown_origin(anchor, 430.0, 520.0, Some(WORK)), (997, 30));
    }

    #[test]
    fn dropdown_flips_above_a_bottom_tray_item() {
        let anchor = TrayAnchor {
            x: 700.0,
            y: 900.0,
            width: 24.0,
            height: 24.0,
        };
        assert_eq!(
            dropdown_origin(anchor, 430.0, 520.0, Some(WORK)),
            (497, 374)
        );
    }

    #[test]
    fn dropdown_stays_inside_the_monitor_work_area() {
        let anchor = TrayAnchor {
            x: 1430.0,
            y: 0.0,
            width: 24.0,
            height: 24.0,
        };
        assert_eq!(
            dropdown_origin(anchor, 430.0, 520.0, Some(WORK)),
            (1010, 30)
        );
    }

    #[test]
    fn tray_icon_has_a_visible_shape_with_transparent_padding() {
        let icon = Image::from_bytes(TRAY_ICON_BYTES).expect("tray icon should be valid PNG");
        let alpha = icon.rgba().chunks_exact(4).map(|pixel| pixel[3]);
        let pixel_count = alpha.len();
        let (transparent, visible) = alpha.fold((0, 0), |(transparent, visible), value| {
            (
                transparent + usize::from(value == 0),
                visible + usize::from(value > 0),
            )
        });

        assert!(
            transparent > pixel_count / 10,
            "tray icon needs transparent padding"
        );
        assert!(
            visible > pixel_count / 10,
            "tray icon needs a substantial visible shape"
        );
    }

    #[test]
    fn bundled_app_icon_is_retina_sized_and_not_a_placeholder() {
        let icon = Image::from_bytes(APP_ICON_BYTES).expect("app icon should be valid PNG");
        assert_eq!((icon.width(), icon.height()), (1024, 1024));

        let mut pixels = icon.rgba().chunks_exact(4);
        let first = pixels.next().expect("app icon should contain pixels");
        assert!(
            pixels.any(|pixel| pixel != first),
            "app icon should contain real artwork"
        );
    }
}
