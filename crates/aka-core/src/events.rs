//! Core → UI notification bridge.
//!
//! The Rust core owns all state transitions; the shell (Tauri layer, tests,
//! or the headless dev harness) observes them through this trait to refresh
//! views and surface agent traffic that needs a human decision.

use std::time::Duration;

use crate::approvals::PendingApproval;
use crate::elicitations::PendingElicitation;
use crate::request_history::RequestResolution;
use crate::types::{ConfirmationMethod, SecretMeta};

/// What an observer did with a traffic-confirmation prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalHandling {
    /// A surface is showing it and will answer through
    /// [`Approvals::respond`](crate::approvals::Approvals::respond).
    Taken,
    /// Nothing here can ask the user. The call is refused.
    Unavailable,
    /// The observer stands in for the user and waives the prompt (tests and
    /// dev harnesses only — never a product shell).
    Waived,
}

/// What an observer did with an upstream elicitation. Unlike an approval it
/// cannot be waived — there is a real answer only a user can give.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElicitationHandling {
    /// A surface is showing the form and will answer through
    /// [`Elicitations::respond`](crate::elicitations::Elicitations::respond).
    Taken,
    /// Nothing here can ask the user. The upstream call is cancelled.
    Unavailable,
}

/// Compatibility classification for shells that still implement the retired
/// native-authentication hooks. The broker no longer consults it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresenceAuthority {
    Authenticated,
    Substituted,
}

impl PresenceAuthority {
    pub fn establishes_presence(self) -> bool {
        self == Self::Authenticated
    }
}

pub trait BrokerEvents: Send + Sync {
    /// Whether this shell can currently surface and answer traffic approval
    /// prompts. The default is deliberately false: shells must opt in rather
    /// than making confirmed traffic wait for a UI that is not there.
    fn has_approval_surface(&self) -> bool {
        false
    }

    /// Compatibility hook for older management clients. Native
    /// authentication is no longer part of broker policy.
    fn native_authentication_available(&self) -> bool {
        false
    }

    /// Live session set changed.
    fn sessions_changed(&self) {}

    /// Registered agents changed (pair/revoke).
    fn agents_changed(&self) {}

    /// The wiring table changed.
    fn wirings_changed(&self) {}

    /// A connection's persisted configuration changed core-side (today: a
    /// trust-on-first-use host-key pin). UI-originated edits refresh through
    /// their command result instead.
    fn connections_changed(&self) {}

    /// Saved-secret metadata changed (add, rename, replace, or delete).
    fn secrets_changed(&self) {}

    /// A new audit entry was appended (drives the activity view).
    fn audit_appended(&self, _entry: &crate::audit::AuditEntry) {}

    /// An MCP sign-in session advanced (probing → … → succeeded/failed).
    /// The state carries no token material; shells forward it to the UI's
    /// live auth-progress view.
    fn mcp_auth_changed(&self, _state: &crate::mcp_auth::McpAuthState) {}

    /// Retired compatibility hook. Secret reads no longer call it.
    fn confirm_secret_read(&self, _secret: &SecretMeta) -> bool {
        true
    }

    /// Retired compatibility hook.
    fn secret_read_authority(&self) -> PresenceAuthority {
        PresenceAuthority::Substituted
    }

    /// Retired compatibility hook. Secret copies no longer call it.
    fn confirm_secret_copy(&self, secret: &SecretMeta, _duration: Duration) -> bool {
        self.confirm_secret_read(secret)
    }

    /// Retired compatibility hook.
    fn secret_copy_authority(&self) -> PresenceAuthority {
        self.secret_read_authority()
    }

    /// An agent asked (via the sidecar's `agentmfa_connect` tool) for a
    /// service that is not configured. Purely advisory: shells surface it
    /// so the user can add the tool; nothing is granted by the request.
    fn connect_requested(&self, _agent: &str, _service: &str) {}

    /// Open a URL in the user's default browser (a BYO-app OAuth consent
    /// page; the MCP sign-in flow opens URLs from the UI instead). Returning
    /// false means the shell could not open it; the caller surfaces the URL
    /// so the user can open it by hand. The default is fail-closed for tests
    /// and headless use.
    fn open_external_url(&self, _url: &str) -> bool {
        false
    }

    /// Retired compatibility hook. Configuration actions no longer call it.
    fn confirm_action(&self, _description: &str) -> Option<ConfirmationMethod> {
        Some(ConfirmationMethod::Waived)
    }

    /// Retired compatibility hook.
    fn action_authority(&self, _method: ConfirmationMethod) -> PresenceAuthority {
        PresenceAuthority::Substituted
    }

    /// Agent traffic is parked on a connection whose confirmation switch is
    /// on, waiting for the user to approve or refuse it.
    ///
    /// Unlike the gates above this one never blocks: the shell shows the
    /// prompt and answers later through
    /// [`Approvals::respond`](crate::approvals::Approvals::respond), which
    /// releases the parked call. The default is fail-closed — a shell that
    /// has not implemented the prompt must refuse the traffic, not carry it.
    fn approval_requested(&self, _pending: &PendingApproval) -> ApprovalHandling {
        ApprovalHandling::Unavailable
    }

    /// More calls joined a prompt already on screen (its `waiting` count
    /// grew). Purely a refresh; the decision is unchanged.
    fn approval_updated(&self, _pending: &PendingApproval) {}

    /// A prompt left the queue — answered, revoked, or lapsed. Shells close
    /// whatever they raised for it.
    fn approval_resolved(&self, _id: &uuid::Uuid, _resolution: RequestResolution) {}

    /// An upstream MCP server asked the user for input mid tool call, and the
    /// call is parked until the user answers through
    /// [`Elicitations::respond`](crate::elicitations::Elicitations::respond).
    /// Like [`Self::approval_requested`] this never blocks and fails closed —
    /// a shell that cannot render the form must cancel, not carry the call.
    fn elicitation_requested(&self, _pending: &PendingElicitation) -> ElicitationHandling {
        ElicitationHandling::Unavailable
    }

    /// An elicitation left the queue — answered, revoked, or lapsed.
    fn elicitation_resolved(&self, _id: &uuid::Uuid) {}
}

/// Default observer: nothing to notify. This observer is for tests and dev
/// harnesses, not products.
#[cfg(any(test, feature = "test-harness"))]
pub struct NoopEvents;

#[cfg(any(test, feature = "test-harness"))]
impl BrokerEvents for NoopEvents {
    fn has_approval_surface(&self) -> bool {
        true
    }

    fn approval_requested(&self, _pending: &PendingApproval) -> ApprovalHandling {
        ApprovalHandling::Waived
    }
}
