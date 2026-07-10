//! Core → webview event bridge and window/tray choreography.
//!
//! The Rust core owns every state transition (DESIGN.md §2); this observer
//! turns them into Tauri events the webview re-renders from, updates the
//! tray pending-count, raises the always-on-top approval window on every
//! prompt, and rings the advisory notification doorbell (§6).

use std::sync::Arc;
use std::time::Duration;

use agentmfa_core::approvals::{ApprovalKind, ApprovalRequest};
use agentmfa_core::audit::AuditEntry;
use agentmfa_core::broker::UiDecision;
use agentmfa_core::events::BrokerEvents;
use agentmfa_core::types::{ConfirmationMethod, PgSslMode, SecretMeta};
use tauri::{AppHandle, Emitter, Manager};
use tauri_plugin_notification::NotificationExt;

use crate::dto::{ActivityDto, ApprovalDto};

pub const EVT_QUEUE: &str = "amfa://queue-changed";
pub const EVT_SESSIONS: &str = "amfa://sessions-changed";
pub const EVT_AGENTS: &str = "amfa://agents-changed";
pub const EVT_RULES: &str = "amfa://rules-changed";
pub const EVT_ACTIVITY: &str = "amfa://activity-appended";
pub const EVT_ACTIVITY_CHANGED: &str = "amfa://activity-changed";

pub const APPROVAL_WINDOW: &str = "approval";

fn copy_authorization_reason(duration: Duration) -> String {
    let seconds = duration.as_secs();
    let window = if seconds % 60 == 0 {
        let minutes = seconds / 60;
        format!("{minutes} minute{}", if minutes == 1 { "" } else { "s" })
    } else {
        format!("{seconds} second{}", if seconds == 1 { "" } else { "s" })
    };
    format!("allow copying saved secrets for the next {window}")
}

pub struct TauriEvents {
    app: AppHandle,
    access_duration_seconds: u64,
}

impl TauriEvents {
    pub fn new(app: AppHandle, access_duration_seconds: u64) -> Self {
        Self {
            app,
            access_duration_seconds,
        }
    }

    fn update_tray_badge(&self, count: usize) {
        // NSStatusItem has no badge API and an accessory app has no Dock
        // icon to badge, so the pending count is rendered into the
        // status-item title text (DESIGN.md §2).
        if let Some(tray) = self.app.tray_by_id("main") {
            let title = if count > 0 {
                Some(count.to_string())
            } else {
                None
            };
            let _ = tray.set_title(title.as_deref());
        }
    }

    fn set_approval_visible(&self, visible: bool) {
        if let Some(win) = self.app.get_webview_window(APPROVAL_WINDOW) {
            if visible {
                let _ = win.show();
                let _ = win.set_focus();
            } else {
                let _ = win.hide();
            }
        }
    }

    fn access_duration(&self) -> String {
        if self.access_duration_seconds % 60 == 0 {
            let minutes = self.access_duration_seconds / 60;
            format!("{minutes} minute{}", if minutes == 1 { "" } else { "s" })
        } else {
            format!("{} seconds", self.access_duration_seconds)
        }
    }

    fn connection_name<'a>(&self, request: &'a ApprovalRequest) -> &'a str {
        request
            .connection
            .as_ref()
            .map(|connection| connection.name.as_str())
            .unwrap_or("this connection")
    }

    fn request_summary(&self, request: &ApprovalRequest) -> String {
        let connection = self.connection_name(request);
        match request.kind {
            ApprovalKind::Pair => format!("{} wants to connect to AgentMFA", request.agent),
            ApprovalKind::Http if request.http.as_ref().is_some_and(|http| !http.mutating) => {
                format!("{} wants to fetch data from {connection}", request.agent)
            }
            ApprovalKind::Http => {
                format!(
                    "{} wants to make a request through {connection}",
                    request.agent
                )
            }
            ApprovalKind::Ssh => format!("{} wants to sign in through {connection}", request.agent),
            ApprovalKind::Pg | ApprovalKind::Ws => {
                format!("{} wants to connect to {connection}", request.agent)
            }
        }
    }
}

impl BrokerEvents for TauriEvents {
    fn queue_changed(&self, queue: &[ApprovalRequest]) {
        let dtos: Vec<ApprovalDto> = queue
            .iter()
            .cloned()
            .map(|request| ApprovalDto::new(request, self.access_duration_seconds))
            .collect();
        self.update_tray_badge(queue.len());
        self.set_approval_visible(!queue.is_empty());
        let _ = self.app.emit(EVT_QUEUE, &dtos);
    }

    fn prompt_raised(&self, request: &ApprovalRequest) {
        // Guaranteed path is the tray badge + auto-raised window; the
        // notification is a best-effort doorbell (§6).
        self.set_approval_visible(true);
        let _ = self
            .app
            .notification()
            .builder()
            .title("AgentMFA")
            .body(self.request_summary(request))
            .show();
    }

    fn sessions_changed(&self) {
        let _ = self.app.emit(EVT_SESSIONS, ());
    }

    fn agents_changed(&self) {
        let _ = self.app.emit(EVT_AGENTS, ());
    }

    fn rules_changed(&self) {
        let _ = self.app.emit(EVT_RULES, ());
    }

    fn audit_appended(&self, entry: &AuditEntry) {
        let _ = self.app.emit(EVT_ACTIVITY, ActivityDto::from(entry));
    }

    fn confirm_secret_read(&self, secret: &SecretMeta) -> bool {
        let reason = format!("read the secret \"{}\"", secret.name);
        crate::auth::confirm(&reason).is_ok()
    }

    fn confirm_secret_copy(&self, _secret: &SecretMeta, duration: Duration) -> bool {
        let reason = copy_authorization_reason(duration);
        crate::auth::confirm(&reason).is_ok()
    }

    /// The core-demanded gate on confirmation-required decisions (§8): the
    /// LocalAuthentication sheet, phrased for what is being decided.
    fn confirm_decision(
        &self,
        request: &ApprovalRequest,
        decision: UiDecision,
    ) -> Option<ConfirmationMethod> {
        let reason = match decision {
            UiDecision::AlwaysAllow => {
                let connection = self.connection_name(request);
                match request.kind {
                    ApprovalKind::Http => format!(
                        "Let {} make any request through {} without asking again",
                        request.agent, connection
                    ),
                    ApprovalKind::Pair => format!("Connect {} to AgentMFA", request.agent),
                    ApprovalKind::Pg | ApprovalKind::Ws | ApprovalKind::Ssh => format!(
                        "Let {} open and use {} without asking again",
                        request.agent, connection
                    ),
                }
            }
            UiDecision::AllowSession => {
                let connection = self.connection_name(request);
                let duration = self.access_duration();
                match request.kind {
                    ApprovalKind::Http
                        if request.http.as_ref().is_some_and(|http| !http.mutating) =>
                    {
                        format!(
                            "Let {} fetch data from {} for {}",
                            request.agent, connection, duration
                        )
                    }
                    ApprovalKind::Http => format!(
                        "Let {} make any request through {} for {}",
                        request.agent, connection, duration
                    ),
                    ApprovalKind::Pg | ApprovalKind::Ws | ApprovalKind::Ssh => format!(
                        "Let {} open and use {} for {}",
                        request.agent, connection, duration
                    ),
                    ApprovalKind::Pair => format!("Connect {} to AgentMFA", request.agent),
                }
            }
            _ => match request.kind {
                ApprovalKind::Pair => format!("Connect {} to AgentMFA", request.agent),
                _ => format!("Allow {}", request.action),
            },
        };
        crate::auth::confirm(&reason)
            .ok()
            .map(|_| ConfirmationMethod::OsAuthentication)
    }

    /// The core-demanded gate on high-consequence configuration actions (§8).
    fn confirm_action(&self, description: &str) -> Option<ConfirmationMethod> {
        crate::auth::confirm(description)
            .ok()
            .map(|_| ConfirmationMethod::OsAuthentication)
    }

    fn confirm_unverified_pg_tls(
        &self,
        host: &str,
        port: u16,
        sslmode: PgSslMode,
        error: &str,
    ) -> bool {
        let mode = match sslmode {
            PgSslMode::Disable => "disable",
            PgSslMode::Prefer => "prefer",
            PgSslMode::Require => "require",
            PgSslMode::VerifyCa => "verify-ca",
            PgSslMode::VerifyFull => "verify-full",
        };
        let reason = format!(
            "The Postgres TLS certificate for {host}:{port} could not be verified with sslmode={mode}.\n\n{error}\n\nContinue without certificate verification for this connection attempt?"
        );
        #[cfg(target_os = "macos")]
        {
            crate::auth::confirm(&reason).is_ok()
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = reason;
            false
        }
    }
}

/// Convenience for the shell to construct the observer as a trait object.
pub fn observer(app: AppHandle, access_duration_seconds: u64) -> Arc<dyn BrokerEvents> {
    Arc::new(TauriEvents::new(app, access_duration_seconds))
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
