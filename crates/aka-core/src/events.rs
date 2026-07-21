//! Core → UI notification bridge.
//!
//! The Rust core owns all state transitions; the shell (Tauri layer, tests,
//! or the headless dev harness) observes them through this trait to refresh
//! views and to run the native confirmation gates for user-initiated
//! actions.

use std::time::Duration;

use crate::types::{ConfirmationMethod, PgSslMode, SecretMeta};

pub trait BrokerEvents: Send + Sync {
    /// Live WS/PG session set changed.
    fn sessions_changed(&self) {}

    /// Registered agents changed (pair/revoke).
    fn agents_changed(&self) {}

    /// The wiring table changed.
    fn wirings_changed(&self) {}

    /// A connection's persisted configuration changed core-side (today: a
    /// trust-on-first-use host-key pin). UI-originated edits refresh through
    /// their command result instead.
    fn connections_changed(&self) {}

    /// A new audit entry was appended (drives the activity view).
    fn audit_appended(&self, _entry: &crate::audit::AuditEntry) {}

    /// An MCP sign-in session advanced (probing → … → succeeded/failed).
    /// The state carries no token material; shells forward it to the UI's
    /// live auth-progress view.
    fn mcp_auth_changed(&self, _state: &crate::mcp_auth::McpAuthState) {}

    /// A secret value is about to be read from the vault for a
    /// user-initiated action while the re-auth-on-read setting is enabled.
    /// Product shells should show their native authentication gate here.
    /// Agent-plane executions are pre-authorized by their wiring and never
    /// reach this. The default fails closed so new shell implementations do
    /// not silently bypass this setting.
    fn confirm_secret_read(&self, _secret: &SecretMeta) -> bool {
        false
    }

    /// A user-initiated clipboard copy is about to open a short authorization
    /// window for more copies. The default delegates to the ordinary secret
    /// read gate so existing shells remain fail-closed and compatible.
    fn confirm_secret_copy(&self, secret: &SecretMeta, _duration: Duration) -> bool {
        self.confirm_secret_read(secret)
    }

    /// An agent asked for a service that is not configured. Shells may
    /// surface the request, but it grants no authority by itself.
    fn connect_requested(&self, _agent: &str, _service: &str) {}

    /// A high-consequence configuration action — creating/deleting a
    /// connection, changing its capability, or deleting a secret — is about
    /// to take effect. The core demands it, `None` aborts, and the default
    /// fails closed.
    fn confirm_action(&self, _description: &str) -> Option<ConfirmationMethod> {
        None
    }

    /// A Postgres `verify-ca`/`verify-full` TLS handshake could not verify
    /// the upstream certificate. Returning true explicitly allows this one
    /// connection attempt to continue with encryption but without certificate
    /// verification. The default is fail-closed for tests and headless use.
    fn confirm_unverified_pg_tls(
        &self,
        _host: &str,
        _port: u16,
        _sslmode: PgSslMode,
        _error: &str,
    ) -> bool {
        false
    }
}

/// Default observer: nothing to notify. Confirmation gates are explicitly
/// waived — this observer is for tests and dev harnesses, not products.
pub struct NoopEvents;

impl BrokerEvents for NoopEvents {
    fn confirm_secret_read(&self, _secret: &SecretMeta) -> bool {
        true
    }

    fn confirm_action(&self, _description: &str) -> Option<ConfirmationMethod> {
        Some(ConfirmationMethod::Waived)
    }
}
