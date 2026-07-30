//! Tray + window
//!
//! AgentMFA has a resizable main window, an NSStatusItem-style tray
//! dropdown. The tray icon
//! is always present and toggles the compact dropdown beneath its status item.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

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
pub const EVT_OPEN_REQUESTS: &str = "aka://open-requests";
const APP_WINDOW_MENU_ID: &str = "app-window";
const NEW_WINDOW_MENU_ID: &str = "new-window";
const TRAY_OPEN_ID: &str = "tray-open";
const TRAY_REQUESTS_ID: &str = "tray-requests";
const TRAY_SETTINGS_ID: &str = "tray-settings";
const TRAY_QUIT_ID: &str = "tray-quit";

const DROPDOWN_GAP: f64 = 6.0;
static LAST_TRAY_ANCHOR: Mutex<Option<TrayAnchor>> = Mutex::new(None);
/// A dropdown form may hold credentials that must survive native
/// authentication and any error returned afterwards. While it is open, focus
/// loss (including the Touch ID sheet becoming key) must not dismiss it. The
/// webview renews this lease; a crashed/reloaded form cannot strand the panel.
static DROPDOWN_FORM_ACTIVE: Mutex<Option<Instant>> = Mutex::new(None);
const DROPDOWN_FORM_TTL: Duration = Duration::from_secs(2 * 60);
/// Tray navigation can happen before a webview installs its event listener.
/// Keep one pending bit per request surface so the destination can drain it
/// after boot instead of silently losing the user's click.
static MAIN_REQUESTS_PENDING: AtomicBool = AtomicBool::new(false);
static DROPDOWN_REQUESTS_PENDING: AtomicBool = AtomicBool::new(false);

fn dropdown_hide_allowed() -> bool {
    dropdown_hide_allowed_at(Instant::now())
}

fn dropdown_hide_allowed_at(now: Instant) -> bool {
    let mut active = DROPDOWN_FORM_ACTIVE.lock().unwrap();
    if active.is_some_and(|renewed| now.duration_since(renewed) < DROPDOWN_FORM_TTL) {
        return false;
    }
    *active = None;
    true
}

pub fn clear_dropdown_form_hold() {
    *DROPDOWN_FORM_ACTIVE.lock().unwrap() = None;
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
/// NSPanel. A panel can accept keyboard input without activating AgentMFA and
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
    // The panel frame is rectangular even though the web surface is rounded.
    // Its native shadow therefore sticks past the lower CSS corners; the
    // surface supplies its own radius-aware shadow instead.
    panel.set_has_shadow(false);
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
/// back to AgentMFA when its Dock and tray affordances are unavailable.
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

    let app_window = MenuItem::with_id(app, APP_WINDOW_MENU_ID, "AgentMFA", true, None::<&str>)?;
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
    let menu = tray_menu(app, 0)?;
    let tray = app
        .tray_by_id("main")
        .ok_or_else(|| tauri::Error::AssetNotFound("configured tray icon".into()))?;
    tray.set_menu(Some(menu))?;
    tray.set_show_menu_on_left_click(false)?;
    tray.on_menu_event(|app, event| match event.id().as_ref() {
        TRAY_OPEN_ID => open_main(app),
        TRAY_REQUESTS_ID => open_request_inbox(app),
        TRAY_SETTINGS_ID => {
            if !dropdown_hide_allowed() {
                show_dropdown(app);
                return;
            }
            show_dropdown(app);
            let _ = app.emit_to(DROPDOWN, EVT_OPEN_SETTINGS, ());
        }
        TRAY_QUIT_ID => app.exit(0),
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

fn tray_menu(app: &AppHandle, request_count: usize) -> tauri::Result<Menu<tauri::Wry>> {
    let open = MenuItem::with_id(app, TRAY_OPEN_ID, "Open AgentMFA", true, None::<&str>)?;
    let request_label = if request_count == 0 {
        "Request Inbox…".to_string()
    } else {
        format!(
            "Review {request_count} request{}…",
            if request_count == 1 { "" } else { "s" }
        )
    };
    let requests = MenuItem::with_id(app, TRAY_REQUESTS_ID, request_label, true, None::<&str>)?;
    let settings = MenuItem::with_id(app, TRAY_SETTINGS_ID, "Settings…", true, None::<&str>)?;
    let separator = PredefinedMenuItem::separator(app)?;
    let quit = MenuItem::with_id(app, TRAY_QUIT_ID, "Quit AgentMFA", true, None::<&str>)?;
    Menu::with_items(app, &[&open, &requests, &settings, &separator, &quit])
}

/// Keep the native tray affordance in sync with the authoritative active
/// queue. The count title is visible beside the icon on macOS and supported
/// Linux panels; Windows still gets the dynamic menu label.
pub fn update_request_count(app: &AppHandle, request_count: usize) {
    let app = app.clone();
    let _ = app.clone().run_on_main_thread(move || {
        // Main-thread work from different producers can be delivered out of
        // order. Re-read the coordinator here so a stale captured count can
        // never overwrite a newer tray state.
        let request_count = app
            .try_state::<crate::attention::RequestAttention>()
            .map(|attention| attention.count())
            .unwrap_or(request_count);
        let Some(tray) = app.tray_by_id("main") else {
            return;
        };
        match tray_menu(&app, request_count) {
            Ok(menu) => {
                let _ = tray.set_menu(Some(menu));
            }
            Err(error) => {
                tracing::warn!(%error, "could not update the tray request menu");
            }
        }
        let tooltip = if request_count == 0 {
            "AgentMFA".to_string()
        } else {
            format!(
                "AgentMFA — {request_count} request{} waiting",
                if request_count == 1 { "" } else { "s" }
            )
        };
        let _ = tray.set_tooltip(Some(tooltip));
        let title = (request_count > 0).then(|| request_count.to_string());
        let _ = tray.set_title(title.as_deref());
    });
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
/// window, which also raises the main AgentMFA window.
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

/// Bring a window forward because traffic is waiting on a decision.
///
/// Only when nothing is on screen: with the app already open, the queue
/// banner is enough, and stealing focus mid-typing would be worse than the
/// prompt it announces. Runs on the main thread — the broker calls this
/// from whichever task parked the traffic.
pub fn surface_for_approval(app: &AppHandle) {
    let app = app.clone();
    let _ = app.clone().run_on_main_thread(move || {
        if window_presented(&app, MAIN) || window_presented(&app, DROPDOWN) {
            return;
        }
        open_main(&app);
    });
}

/// Whether one of the trusted request surfaces is actually focused. A
/// visible main window can be covered by another application; in that case a
/// native notification is still useful.
pub fn request_surface_focused(app: &AppHandle) -> bool {
    [MAIN, DROPDOWN].into_iter().any(|label| {
        app.get_webview_window(label)
            .and_then(|window| window.is_focused().ok())
            .unwrap_or(false)
    })
}

/// Visible and not minimized. Window managers may report a minimized window
/// as visible; that is not enough for a 90-second approval prompt.
fn window_presented(app: &AppHandle, label: &str) -> bool {
    app.get_webview_window(label).is_some_and(|window| {
        window.is_visible().unwrap_or(false) && !window.is_minimized().unwrap_or(false)
    })
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
    *DROPDOWN_FORM_ACTIVE.lock().unwrap() = active.then(Instant::now);
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

pub(crate) fn open_request_inbox(app: &AppHandle) {
    let app = app.clone();
    let _ = app
        .clone()
        .run_on_main_thread(move || open_request_inbox_on_main(&app));
}

fn open_request_inbox_on_main(app: &AppHandle) {
    // A protected dropdown form may contain credentials. Keep it open and
    // queue the navigation until the form closes rather than destroying a
    // draft or losing the user's request.
    if !dropdown_hide_allowed() {
        show_dropdown(app);
        DROPDOWN_REQUESTS_PENDING.store(true, Ordering::SeqCst);
        let _ = app.emit_to(DROPDOWN, EVT_OPEN_REQUESTS, ());
        return;
    }
    open_main(app);
    MAIN_REQUESTS_PENDING.store(true, Ordering::SeqCst);
    let _ = app.emit_to(MAIN, EVT_OPEN_REQUESTS, ());
}

/// Consume a tray request-inbox route for the invoking webview. The pending
/// bit makes tray navigation reliable during webview boot and while a
/// protected form temporarily prevents navigation.
#[tauri::command]
pub fn ui_take_open_requests(window: tauri::WebviewWindow) -> bool {
    match window.label() {
        MAIN => MAIN_REQUESTS_PENDING.swap(false, Ordering::SeqCst),
        DROPDOWN => DROPDOWN_REQUESTS_PENDING.swap(false, Ordering::SeqCst),
        _ => false,
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
        let now = Instant::now();
        *DROPDOWN_FORM_ACTIVE.lock().unwrap() = Some(now);
        assert!(!dropdown_hide_allowed_at(now + Duration::from_secs(119)));
        assert!(dropdown_hide_allowed_at(now + Duration::from_secs(120)));
        assert!(DROPDOWN_FORM_ACTIVE.lock().unwrap().is_none());
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
