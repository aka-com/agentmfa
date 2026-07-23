//! Core → webview event bridge.
//!
//! The Rust core owns every state transition; this observer turns
//! them into Tauri events the webview re-renders from.

use std::sync::Arc;
use std::time::Duration;

use aka_core::audit::AuditEntry;
use aka_core::events::BrokerEvents;
use aka_core::manage::activity_dto;
use aka_core::types::{ConfirmationMethod, SecretMeta};
use tauri::{AppHandle, Emitter};

pub const EVT_SESSIONS: &str = "aka://sessions-changed";
pub const EVT_AGENTS: &str = "aka://agents-changed";
pub const EVT_WIRINGS: &str = "aka://wirings-changed";
pub const EVT_CONNECTIONS: &str = "aka://connections-changed";
pub const EVT_ACTIVITY: &str = "aka://activity-appended";
pub const EVT_ACTIVITY_CHANGED: &str = "aka://activity-changed";
pub const EVT_MCP_AUTH: &str = "aka://mcp-auth-changed";
pub const EVT_CONNECT_REQUESTED: &str = "aka://connect-requested";

fn copy_authorization_reason(duration: Duration) -> String {
    let seconds = duration.as_secs();
    let window = if seconds.is_multiple_of(60) {
        let minutes = seconds / 60;
        format!("{minutes} minute{}", if minutes == 1 { "" } else { "s" })
    } else {
        format!("{seconds} second{}", if seconds == 1 { "" } else { "s" })
    };
    format!("allow copying saved secrets for the next {window}")
}

pub struct TauriEvents {
    app: AppHandle,
}

impl TauriEvents {
    pub fn new(app: AppHandle) -> Self {
        Self { app }
    }
}

impl BrokerEvents for TauriEvents {
    fn sessions_changed(&self) {
        let _ = self.app.emit(EVT_SESSIONS, ());
    }

    fn agents_changed(&self) {
        let _ = self.app.emit(EVT_AGENTS, ());
    }

    fn wirings_changed(&self) {
        let _ = self.app.emit(EVT_WIRINGS, ());
    }

    fn connections_changed(&self) {
        let _ = self.app.emit(EVT_CONNECTIONS, ());
    }

    fn audit_appended(&self, entry: &AuditEntry) {
        let _ = self.app.emit(EVT_ACTIVITY, activity_dto(entry));
    }

    fn mcp_auth_changed(&self, state: &aka_core::mcp_auth::McpAuthState) {
        let _ = self.app.emit(EVT_MCP_AUTH, state);
    }

    fn connect_requested(&self, agent: &str, service: &str) {
        let _ = self.app.emit(
            EVT_CONNECT_REQUESTED,
            serde_json::json!({ "agent": agent, "service": service }),
        );
    }

    fn confirm_secret_read(&self, secret: &SecretMeta) -> bool {
        let reason = format!("read the secret \"{}\"", secret.name);
        crate::auth::confirm(&reason).is_ok()
    }

    fn confirm_secret_copy(&self, _secret: &SecretMeta, duration: Duration) -> bool {
        let reason = copy_authorization_reason(duration);
        crate::auth::confirm(&reason).is_ok()
    }

    /// The core-demanded gate on high-consequence configuration actions.
    fn confirm_action(&self, description: &str) -> Option<ConfirmationMethod> {
        crate::auth::confirm(description)
            .ok()
            .map(|_| ConfirmationMethod::OsAuthentication)
    }

    /// Open the OAuth authorize page in the user's default browser.
    fn open_external_url(&self, url: &str) -> bool {
        open_consent_url(url)
    }
}

/// Open an OAuth consent page in the default browser. Only web URLs, ever:
/// this exists for the consent page, local mode and relayed-remote alike.
pub fn open_consent_url(url: &str) -> bool {
    if !url.starts_with("https://") {
        return false;
    }
    #[cfg(target_os = "macos")]
    let launcher = "open";
    #[cfg(not(target_os = "macos"))]
    let launcher = "xdg-open";
    std::process::Command::new(launcher)
        .arg(url)
        .spawn()
        .is_ok()
}

/// Convenience for the shell to construct the observer as a trait object.
pub fn observer(app: AppHandle) -> Arc<dyn BrokerEvents> {
    Arc::new(TauriEvents::new(app))
}

/// Re-emit a remote broker's manage event as the Tauri event local mode
/// would have produced, so the webview never knows which mode it is in.
pub fn emit_manage_event(app: &AppHandle, event: aka_api::ManageEvent) {
    use aka_api::ManageEvent;
    match event {
        ManageEvent::SessionsChanged => {
            let _ = app.emit(EVT_SESSIONS, ());
        }
        ManageEvent::AgentsChanged => {
            let _ = app.emit(EVT_AGENTS, ());
        }
        ManageEvent::WiringsChanged => {
            let _ = app.emit(EVT_WIRINGS, ());
        }
        ManageEvent::ConnectionsChanged => {
            let _ = app.emit(EVT_CONNECTIONS, ());
        }
        ManageEvent::ActivityAppended { entry } => {
            let _ = app.emit(EVT_ACTIVITY, entry);
        }
        ManageEvent::ActivityCleared => {
            let _ = app.emit(EVT_ACTIVITY_CHANGED, ());
        }
        ManageEvent::McpAuthChanged { state } => {
            let _ = app.emit(EVT_MCP_AUTH, state);
        }
        ManageEvent::ConnectRequested { agent, service } => {
            let _ = app.emit(
                EVT_CONNECT_REQUESTED,
                serde_json::json!({ "agent": agent, "service": service }),
            );
        }
        // The stream (re)connected or dropped notifications: refetch
        // everything rather than trusting incremental state.
        ManageEvent::Resync => {
            for topic in [
                EVT_CONNECTIONS,
                EVT_SESSIONS,
                EVT_WIRINGS,
                EVT_AGENTS,
                EVT_ACTIVITY_CHANGED,
            ] {
                let _ = app.emit(topic, ());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copy_authorization_reason_describes_the_timed_window() {
        assert_eq!(
            copy_authorization_reason(Duration::from_secs(5 * 60)),
            "allow copying saved secrets for the next 5 minutes"
        );
    }
}
