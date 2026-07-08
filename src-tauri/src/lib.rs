//! AgentMFA Tauri shell.
//!
//! The webview is the discovery/ergonomics surface; the Rust core owns
//! everything sensitive (DESIGN.md §2). This shell wires the two together:
//! it constructs the [`Broker`], starts the agent-facing daemon (control
//! plane over the Unix socket + WS/PG data planes), installs the tray and
//! windows, and exposes the minimal, OS-confirmation-gated command surface.

mod auth;
mod clipboard;
mod commands;
mod dto;
mod events;
mod windows;

use std::sync::Arc;

use agentmfa_core::broker::Broker;
use agentmfa_core::config::BrokerConfig;
use agentmfa_core::daemon;
use agentmfa_core::error::CoreError;
use agentmfa_core::paths::Paths;
use agentmfa_core::vault::platform_vault;
use tauri::{Manager, WindowEvent};
use tauri_plugin_dialog::{DialogExt as _, MessageDialogKind};

use commands::AppState;

/// A startup failure the user can act on is a dialog, not a crash. The
/// cases are tailored: which file failed, what likely caused it, what to do
/// next. `StateTampered` in particular is security-relevant (DESIGN.md
/// §13.1) *and* the expected outcome of an app-identity change — the user
/// should see it, not find a crash report.
fn fatal_startup(app: &tauri::App, e: CoreError) -> ! {
    let (title, kind, message) = match &e {
        // Single-instance only catches duplicate launches of this app; a
        // broker it cannot see (a headless dev broker, a differently-
        // identified build) can still hold the socket.
        CoreError::BrokerAlreadyRunning(_) => (
            "AgentMFA is already running",
            MessageDialogKind::Warning,
            format!("{e}.\n\nQuit the other broker, then relaunch AgentMFA."),
        ),
        CoreError::StateTampered(file) => (
            "Saved state failed its integrity check",
            MessageDialogKind::Error,
            format!(
                "{file} failed its integrity check and won't be loaded.\n\n\
                 This happens when the file was modified outside AgentMFA, \
                 or was created under a different app identity (for example \
                 a build signed with a different certificate or bundle \
                 identifier). Restore the file from a backup, or move it \
                 away to start fresh, then relaunch AgentMFA."
            ),
        ),
        CoreError::Vault(_) => (
            "Keychain access failed",
            MessageDialogKind::Error,
            format!(
                "{e}.\n\nAgentMFA cannot run without its Keychain items. \
                 Approve Keychain access for AgentMFA (or unlock the login \
                 keychain), then relaunch."
            ),
        ),
        _ => (
            "AgentMFA could not start",
            MessageDialogKind::Error,
            format!("{e}.\n\nFix the underlying problem, then relaunch AgentMFA."),
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
                .unwrap_or_else(|_| "agentmfa_core=info,agentmfa_app=info".into()),
        )
        .init();

    tauri::Builder::default()
        // Must be the first plugin registered: a duplicate launch hands off
        // here (in the running instance) and exits before its own broker
        // setup can race the daemon socket and panic inside the setup hook
        // (a nounwind context, so any Err there aborts the process).
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            app.dialog()
                .message("AgentMFA is already running in the menu bar.")
                .kind(MessageDialogKind::Info)
                .title("AgentMFA")
                .show(|_| {});
        }))
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_clipboard_manager::init())
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
                // the approvals timers. Broker::new must run inside it
                // (approvals spawn tasks; the integrity key loads via the
                // async vault).
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()?;

                let paths = Paths::default_locations()?;
                let vault = platform_vault(&paths)?;
                let events = events::observer(handle.clone());

                let broker: Arc<Broker> = runtime.block_on(Broker::new(
                    paths,
                    vault,
                    BrokerConfig::default(),
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
                "AgentMFA daemon listening on {}",
                daemon.socket_path.display()
            );

            windows::setup_tray(&handle)?;

            // Regular windowed app: the main window is shown at launch
            // (tauri.conf.json `visible: true`) with the default Regular
            // activation policy, so it appears in the Dock and app switcher.
            // The menu bar is opt-in — the user minimizes to it, and only
            // then (and only if they enabled it) is the Dock icon hidden.

            // Closing the main window hides it and keeps the broker running
            // rather than quitting; reopen from the Dock or the tray.
            if let Some(win) = app.get_webview_window(windows::MAIN) {
                let handle = handle.clone();
                win.on_window_event(move |event| {
                    if let WindowEvent::CloseRequested { api, .. } = event {
                        api.prevent_close();
                        windows::ui_hide_main(handle.clone());
                    }
                });
            }

            app.manage(AppState {
                broker,
                _daemon: daemon,
                _runtime: runtime,
            });
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building AgentMFA")
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
