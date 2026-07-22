//! Multitool Tauri shell.
//!
//! The webview is the discovery/ergonomics surface; the Rust core
//! owns everything sensitive. This shell wires the two together: it
//! constructs the [`Broker`], starts the agent-facing daemon (control
//! plane over the Unix socket + WS/PG data planes), installs the tray
//! and windows, and exposes the minimal, OS-confirmation-gated
//! command surface.

mod auth;
mod clipboard;
mod commands;
mod dto;
mod events;
mod sidecar;
mod ssh_import;
mod windows;

use std::sync::Arc;

use aka_core::broker::Broker;
use aka_core::config::BrokerConfig;
use aka_core::daemon;
use aka_core::error::CoreError;
use aka_core::paths::Paths;
use aka_core::vault::platform_vault;
use tauri::{Manager, WindowEvent};
use tauri_plugin_dialog::{DialogExt as _, MessageDialogKind};

use commands::AppState;

enum IntegrityRecoveryDecision {
    Quit,
    ArchiveConfirmed,
    ArchiveUnconfirmed,
}

#[cfg(target_os = "macos")]
fn integrity_recovery_dialog(file: &str) -> IntegrityRecoveryDecision {
    use objc2::{msg_send, rc::autoreleasepool, rc::Retained, ClassType, MainThreadMarker};
    use objc2_app_kit::{NSAlert, NSAlertSecondButtonReturn, NSAlertStyle, NSControlStateValueOn};
    use objc2_foundation::NSString;

    autoreleasepool(|_| {
        let Some(_mtm) = MainThreadMarker::new() else {
            return IntegrityRecoveryDecision::Quit;
        };
        let alert: Retained<NSAlert> = unsafe { msg_send![NSAlert::class(), new] };
        alert.setAlertStyle(NSAlertStyle::Critical);
        alert.setMessageText(&NSString::from_str(
            "Saved state failed its integrity check",
        ));
        alert.setInformativeText(&NSString::from_str(&format!(
            "{file} failed its integrity check and won't be loaded.\n\n\
             This happens when the file was modified outside Multitool, or was \
             created under a different app identity. You can quit and restore \
             the file from backup, or archive Multitool's local data directory \
             so the next launch starts with fresh local state. Keychain secret \
             values are not deleted."
        )));
        alert.addButtonWithTitle(&NSString::from_str("Quit"));
        alert.addButtonWithTitle(&NSString::from_str("Archive Data and Quit"));
        alert.setShowsSuppressionButton(true);
        let Some(checkbox) = alert.suppressionButton() else {
            return IntegrityRecoveryDecision::Quit;
        };
        checkbox.setTitle(&NSString::from_str(
            "I understand Multitool will start with fresh local state on next launch.",
        ));

        let response = alert.runModal();
        if response != NSAlertSecondButtonReturn {
            return IntegrityRecoveryDecision::Quit;
        }
        if checkbox.state() == NSControlStateValueOn {
            IntegrityRecoveryDecision::ArchiveConfirmed
        } else {
            IntegrityRecoveryDecision::ArchiveUnconfirmed
        }
    })
}

#[cfg(not(target_os = "macos"))]
fn integrity_recovery_dialog(_file: &str) -> IntegrityRecoveryDecision {
    IntegrityRecoveryDecision::Quit
}

fn fatal_integrity_startup(app: &tauri::App, file: &str) -> ! {
    match integrity_recovery_dialog(file) {
        IntegrityRecoveryDecision::Quit => {
            #[cfg(not(target_os = "macos"))]
            app.dialog()
                .message(format!(
                    "{file} failed its integrity check and won't be loaded.\n\n\
                     Restore the file from a backup, or move Multitool's local \
                     data directory away to start fresh, then relaunch Multitool."
                ))
                .kind(MessageDialogKind::Error)
                .title("Saved state failed its integrity check")
                .blocking_show();
            std::process::exit(1);
        }
        IntegrityRecoveryDecision::ArchiveUnconfirmed => {
            app.dialog()
                .message(
                    "Multitool did not archive local data because the confirmation checkbox \
                     was not selected.",
                )
                .kind(MessageDialogKind::Warning)
                .title("Archive Not Confirmed")
                .blocking_show();
            std::process::exit(1);
        }
        IntegrityRecoveryDecision::ArchiveConfirmed => {
            let archived = Paths::default_locations().and_then(|paths| paths.archive_data_dir());
            match archived {
                Ok(path) => {
                    app.dialog()
                        .message(format!(
                            "Multitool archived its local data to:\n\n{}\n\n\
                             Relaunch Multitool to start with fresh local state. \
                             Keychain secret values were not deleted.",
                            path.display()
                        ))
                        .kind(MessageDialogKind::Info)
                        .title("Multitool Data Archived")
                        .blocking_show();
                    std::process::exit(0);
                }
                Err(e) => {
                    app.dialog()
                        .message(format!(
                            "Multitool could not archive its local data directory: {e}.\n\n\
                             Nothing was changed. Restore the failed state file from backup, \
                             or move the data directory away manually, then relaunch Multitool."
                        ))
                        .kind(MessageDialogKind::Error)
                        .title("Archive Failed")
                        .blocking_show();
                    std::process::exit(1);
                }
            }
        }
    }
}

/// A startup failure the user can act on is a dialog, not a crash. The
/// cases are tailored: which file failed, what likely caused it, what to do
/// next. `StateTampered` in particular is security-relevant *and* the
/// expected outcome of an app-identity change — the user should see it, not
/// find a crash report.
fn fatal_startup(app: &tauri::App, e: CoreError) -> ! {
    if let CoreError::StateTampered(file) = &e {
        fatal_integrity_startup(app, file);
    }

    let (title, kind, message) = match &e {
        // Single-instance only catches duplicate launches of this app; a
        // broker it cannot see (a headless dev broker, a differently-
        // identified build) can still hold the socket.
        CoreError::BrokerAlreadyRunning(_) => (
            "Multitool is already running",
            MessageDialogKind::Warning,
            format!("{e}.\n\nQuit the other broker, then relaunch Multitool."),
        ),
        CoreError::Vault(_) => (
            "Keychain access failed",
            MessageDialogKind::Error,
            format!(
                "{e}.\n\nMultitool cannot run without its Keychain items. \
                 Approve Keychain access for Multitool (or unlock the login \
                 keychain), then relaunch."
            ),
        ),
        _ => (
            "Multitool could not start",
            MessageDialogKind::Error,
            format!("{e}.\n\nFix the underlying problem, then relaunch Multitool."),
        ),
    };
    app.dialog()
        .message(message)
        .kind(kind)
        .title(title)
        .blocking_show();
    // Exit through the normal path either way — the dialog already told the
    // user what happened. 0 for the informational already-running case, 1
    // for real failures; neither raises a crash report.
    std::process::exit(if matches!(e, CoreError::BrokerAlreadyRunning(_)) {
        0
    } else {
        1
    });
}

pub fn run() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "aka_core=info,aka_desktop_app=info".into()),
        )
        .init();

    let builder = tauri::Builder::default()
        // Must be the first plugin registered: a duplicate launch hands off
        // here (in the running instance) and exits before its own broker
        // setup can race the daemon socket and panic inside the setup hook
        // (a nounwind context, so any Err there aborts the process).
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            app.dialog()
                .message("Multitool is already running in the menu bar.")
                .kind(MessageDialogKind::Info)
                .title("Multitool")
                .show(|_| {});
        }))
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_clipboard_manager::init());

    // The menu-bar dropdown is an NSPanel on macOS, while the main window
    // remains a conventional Dock-backed application window.
    #[cfg(target_os = "macos")]
    let builder = builder.plugin(tauri_nspanel::init());

    builder
        .invoke_handler(commands::handler())
        .setup(|app| {
            let handle = app.handle().clone();

            // Everything that can fail before the app is usable runs inside
            // this closure; a failure becomes a dialog via fatal_startup,
            // never an `Err` out of the hook (a nounwind context, so any Err
            // here aborts the process with a crash report whose guidance —
            // reinstall, report a bug — is wrong for every actionable case).
            let started = || -> Result<
                (Arc<Broker>, daemon::DaemonHandle, tokio::runtime::Runtime),
                CoreError,
            > {
                // The broker's tokio runtime hosts the daemon listeners and
                // the execution tasks. Broker::new must run inside it
                // (executions spawn tasks; the integrity key loads via the
                // async vault).
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()?;

                let paths = Paths::default_locations()?;
                let vault = platform_vault(&paths)?;
                let config = BrokerConfig::default();
                let events = events::observer(handle.clone());

                let broker: Arc<Broker> = runtime.block_on(Broker::new(
                    paths,
                    vault,
                    config,
                    events,
                ))?;

                // Start the agent-facing daemon (UDS control plane + WS/PG
                // data planes). Kept in state; dropping the handle stops it.
                let daemon = runtime.block_on(daemon::serve(broker.clone()))?;
                Ok((broker, daemon, runtime))
            };
            let (broker, daemon, runtime) = match started() {
                Ok(parts) => parts,
                Err(e) => fatal_startup(app, e),
            };
            tracing::info!(
                "Multitool daemon listening on {}",
                daemon.socket_path.display()
            );

            // Supervised on the broker's runtime, so it is torn down with
            // everything else it depends on. `block_on` is only for the
            // spawn context — starting the sidecar does not block.
            let sidecar = runtime.block_on(async {
                sidecar::start(&handle, daemon.socket_path.clone())
            });
            // Keep the broker told where the MCP endpoint is listening
            // (restarts move the port), so the discovery manifest can
            // advertise it to `aka mcp` and other bridges.
            if let Some(sidecar) = &sidecar {
                let watch = sidecar.watch();
                let broker = broker.clone();
                runtime.spawn(watch.follow(move |endpoint| {
                    broker.set_sidecar_mcp_port(endpoint.map(|e| e.port));
                }));
            }

            windows::setup_app_menu(&handle)?;
            windows::setup_dropdown_panel(&handle)?;
            windows::setup_tray(&handle)?;

            // The regular main window is shown at launch. The always-present
            // tray icon toggles a separate compact dropdown window.

            // Closing the main window hides it and keeps the broker running
            // rather than quitting; reopen from the Dock or the tray.
            if let Some(win) = app.get_webview_window(windows::MAIN) {
                windows::move_traffic_lights_down(&win, 3.0)?;
                let handle = handle.clone();
                win.on_window_event(move |event| {
                    if let WindowEvent::CloseRequested { api, .. } = event {
                        api.prevent_close();
                        windows::ui_hide_main(handle.clone());
                    }
                });
            }
            if let Some(win) = app.get_webview_window(windows::DROPDOWN) {
                let handle = handle.clone();
                win.on_window_event(move |event| match event {
                    WindowEvent::Focused(false) => {
                        let _ = windows::hide_dropdown(&handle);
                    }
                    WindowEvent::CloseRequested { api, .. } => {
                        api.prevent_close();
                        let _ = windows::hide_dropdown(&handle);
                    }
                    _ => {}
                });
            }

            app.manage(AppState {
                broker,
                ssh_imports: Default::default(),
                _sidecar: sidecar,
                _daemon: daemon,
                _runtime: runtime,
            });
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building Multitool")
        .run(|handle, event| {
            // Clicking the Dock icon (incl. when no window is visible) reopens
            // the main window — the standard regular-app reactivation path.
            #[cfg(target_os = "macos")]
            if let tauri::RunEvent::Reopen { .. } = &event {
                windows::ui_open_main(handle.clone());
            }
            let _ = (handle, &event);
        });
}
