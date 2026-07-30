//! Core → webview event bridge.
//!
//! The Rust core owns every state transition; this observer turns
//! them into Tauri events the webview re-renders from.

use std::sync::Arc;
use std::time::Duration;

use aka_core::audit::AuditEntry;
use aka_core::events::{ApprovalHandling, BrokerEvents};
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
pub const EVT_APPROVALS: &str = "aka://approvals-changed";
pub const EVT_ELICITATIONS: &str = "aka://elicitations-changed";

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

    /// Agent traffic is parked on the user. Unlike the gates above, this one
    /// does not block: the webview renders the queue and answers through
    /// `respond_approval`, which releases the call.
    fn approval_requested(
        &self,
        pending: &aka_core::approvals::PendingApproval,
    ) -> ApprovalHandling {
        crate::attention::approval_requested(&self.app, pending);
        let _ = self.app.emit(EVT_APPROVALS, ());
        // Native attention delivery is notification-first. It falls back to
        // the existing window surfacing when notifications are disabled or
        // the platform reports a delivery failure.
        ApprovalHandling::Taken
    }

    fn approval_updated(&self, pending: &aka_core::approvals::PendingApproval) {
        crate::attention::approval_updated(&self.app, pending);
        let _ = self.app.emit(EVT_APPROVALS, ());
    }

    fn approval_resolved(&self, id: &uuid::Uuid) {
        crate::attention::approval_resolved(&self.app, id);
        let _ = self.app.emit(EVT_APPROVALS, ());
    }

    /// An upstream MCP server asked the user for input. The webview renders
    /// the form and answers through `respond_elicitation`.
    fn elicitation_requested(
        &self,
        pending: &aka_core::elicitations::PendingElicitation,
    ) -> aka_core::events::ElicitationHandling {
        crate::attention::elicitation_requested(&self.app, pending);
        let _ = self.app.emit(EVT_ELICITATIONS, ());
        aka_core::events::ElicitationHandling::Taken
    }

    fn elicitation_resolved(&self, id: &uuid::Uuid) {
        crate::attention::elicitation_resolved(&self.app, id);
        let _ = self.app.emit(EVT_ELICITATIONS, ());
    }
}

/// Open an OAuth consent page in the default browser. Only web URLs, ever:
/// this exists for the consent page, local mode and relayed-remote alike.
pub fn open_consent_url(url: &str) -> bool {
    if !allowed_external_url(url) {
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

/// Browser launches may carry OAuth state or management context. Permit
/// cleartext HTTP only when it cannot leave this machine.
pub(crate) fn allowed_external_url(raw: &str) -> bool {
    let Ok(url) = url::Url::parse(raw.trim()) else {
        return false;
    };
    if !url.username().is_empty() || url.password().is_some() {
        return false;
    }
    match url.scheme() {
        "https" => true,
        "http" => url.host_str().is_some_and(|host| {
            let address_host = host.trim_start_matches('[').trim_end_matches(']');
            host.eq_ignore_ascii_case("localhost")
                || host.to_ascii_lowercase().ends_with(".localhost")
                || address_host
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|address| address.is_loopback())
        }),
        _ => false,
    }
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
        ManageEvent::ApprovalsChanged => {
            let _ = app.emit(EVT_APPROVALS, ());
        }
        ManageEvent::ElicitationsChanged => {
            let _ = app.emit(EVT_ELICITATIONS, ());
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
                EVT_APPROVALS,
                EVT_ELICITATIONS,
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

    #[test]
    fn browser_urls_require_https_off_machine() {
        assert!(allowed_external_url("https://broker.example/authorize"));
        assert!(allowed_external_url("http://127.0.0.1:4780/callback"));
        assert!(allowed_external_url("http://[::1]:4780/callback"));
        assert!(allowed_external_url("http://app.localhost/callback"));
        assert!(!allowed_external_url("http://broker.example/authorize"));
        assert!(!allowed_external_url("https://user:secret@broker.example/"));
        assert!(!allowed_external_url("file:///tmp/secret"));
    }
}
