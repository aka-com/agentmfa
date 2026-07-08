//! Core → UI notification bridge.
//!
//! The Rust core owns all state transitions; the shell (Tauri layer, tests,
//! or the headless dev harness) observes them through this trait to update
//! the tray badge, raise the approval window, ring the notification
//! doorbell, and refresh views.

use crate::approvals::ApprovalRequest;
use crate::audit::AuditEntry;
use crate::broker::UiDecision;
use crate::types::{ConfirmationMethod, PgSslMode, SecretMeta};

pub trait BrokerEvents: Send + Sync {
    /// The pending queue changed (something parked, decided, timed out or
    /// was abandoned). Drives the tray badge and the approval window.
    fn queue_changed(&self, _queue: &[ApprovalRequest]) {}

    /// A new prompt was parked, the advisory notification doorbell (§6).
    fn prompt_raised(&self, _request: &ApprovalRequest) {}

    /// Live WS/PG session set changed.
    fn sessions_changed(&self) {}

    /// Paired agents changed (pair/revoke).
    fn agents_changed(&self) {}

    /// Standing rules changed.
    fn rules_changed(&self) {}

    /// A new audit entry was appended (drives the activity view).
    fn audit_appended(&self, _entry: &AuditEntry) {}

    /// A secret value is about to be read from the vault while the user's
    /// re-auth-on-read setting is enabled. Product shells should show their
    /// native authentication gate here. The default fails closed so new
    /// shell implementations do not silently bypass this setting.
    fn confirm_secret_read(&self, _secret: &SecretMeta) -> bool {
        false
    }

    /// A high-consequence decision — approving a pairing or a mutating
    /// request, or saving an "Always allow…" rule — is about to take
    /// effect. Product shells must run their native confirmation gate here
    /// (the LocalAuthentication sheet on macOS) and report how it was
    /// satisfied; `None` aborts the decision. The core calls this exactly
    /// once per decision, *before* any effect (rule save, execution)
    /// happens, so a shell cannot apply a gated decision without passing
    /// through it. The default fails closed so a new shell implementation
    /// does not silently skip the gate (§8).
    fn confirm_decision(
        &self,
        _request: &ApprovalRequest,
        _decision: UiDecision,
    ) -> Option<ConfirmationMethod> {
        None
    }

    /// A high-consequence configuration action — creating/editing/deleting
    /// a connection, deleting a secret, revoking a pairing, ending a live
    /// session — is about to take effect. Same contract as
    /// [`Self::confirm_decision`]: the core demands it, `None` aborts, and
    /// the default fails closed (§8).
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

    fn confirm_decision(
        &self,
        _request: &ApprovalRequest,
        _decision: UiDecision,
    ) -> Option<ConfirmationMethod> {
        Some(ConfirmationMethod::Waived)
    }

    fn confirm_action(&self, _description: &str) -> Option<ConfirmationMethod> {
        Some(ConfirmationMethod::Waived)
    }
}
