//! The Agent Broker Protocol (ABP) wire vocabulary.
//!
//! This module is the in-code source of truth for the protocol surface the
//! manifest advertises and PROTOCOL.md specifies in prose: the protocol
//! version, the **closed registry** of machine-readable error reasons, the
//! approval lifecycle states, and the capability flags (auth schemes,
//! approval modes). Everything an agent can observe on the wire is named
//! here, so the vocabulary is reviewable and freezable as a unit.
//!
//! Compatibility rules: renaming or removing anything here is a breaking
//! protocol change; additions are backwards-compatible but bump
//! [`PROTOCOL_VERSION`] when a conforming agent must know about them to
//! behave correctly.

use std::fmt;

use serde::{Serialize, Serializer};

/// The Agent Broker Protocol version the daemon speaks, advertised as
/// `protocol_version` in the discovery manifest. Version 0 remains the
/// unpublished, pre-freeze draft of the surface this codebase implements.
pub const PROTOCOL_VERSION: u32 = 0;

/// Maximum UTF-8 byte length of an agent-minted idempotency key. The bound
/// keeps compact tombstones compact as well as limiting request parsing.
pub const REQUEST_ID_MAX_BYTES: usize = 256;

/// The closed registry of machine-readable `{"reason": …}` values (ABP
/// error registry). Every error body the broker sends names exactly one of
/// these; producers hold variants, never raw strings, so the registry
/// cannot drift from the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorReason {
    // Authentication and pairing.
    MissingToken,
    InvalidToken,
    TokenExpired,
    TokenSuperseded,
    PeerIdentityMismatch,
    InvalidAgentName,
    PairingAlreadyPending,
    PairingDeniedCooldown,
    PairingRateLimited,
    PairingFailed,
    // Request validation.
    UnknownConnection,
    WrongConnectionType,
    /// The request body never reached the endpoint's deserializer: wrong or
    /// missing Content-Type, malformed JSON, or a missing field.
    InvalidJson,
    InvalidMethod,
    InvalidPath,
    ReservedHeader,
    InvalidHeader,
    InvalidBody,
    RequestTooLarge,
    RequestIdMismatch,
    OutcomeNotReplayable,
    // Policy and approval outcomes.
    DeniedByUser,
    DeniedByPolicy,
    ApprovalTimeout,
    // Rate limits and budgets.
    RateLimited,
    IdempotencyCapacity,
    TicketSessionLimit,
    BrokerSessionLimit,
    // Tickets (data-plane redemption).
    UnknownTicket,
    TicketExpired,
    TicketAlreadyRedeemed,
    // Upstream execution.
    UpstreamTimeout,
    UpstreamError,
    UpstreamConnectFailed,
    ResponseTooLarge,
    CredentialRenderFailed,
    SshAgentOpenFailed,
    // Broker-side faults.
    BadConnectionConfig,
    BodyUnavailable,
    SpoolFailed,
    BridgeNotRunning,
    ProxyNotRunning,
    BrokerShutdown,
}

impl ErrorReason {
    /// Every registered reason, for exhaustiveness checks and docs.
    pub const ALL: [ErrorReason; 43] = [
        ErrorReason::MissingToken,
        ErrorReason::InvalidToken,
        ErrorReason::TokenExpired,
        ErrorReason::TokenSuperseded,
        ErrorReason::PeerIdentityMismatch,
        ErrorReason::InvalidAgentName,
        ErrorReason::PairingAlreadyPending,
        ErrorReason::PairingDeniedCooldown,
        ErrorReason::PairingRateLimited,
        ErrorReason::PairingFailed,
        ErrorReason::UnknownConnection,
        ErrorReason::WrongConnectionType,
        ErrorReason::InvalidJson,
        ErrorReason::InvalidMethod,
        ErrorReason::InvalidPath,
        ErrorReason::ReservedHeader,
        ErrorReason::InvalidHeader,
        ErrorReason::InvalidBody,
        ErrorReason::RequestTooLarge,
        ErrorReason::RequestIdMismatch,
        ErrorReason::OutcomeNotReplayable,
        ErrorReason::DeniedByUser,
        ErrorReason::DeniedByPolicy,
        ErrorReason::ApprovalTimeout,
        ErrorReason::RateLimited,
        ErrorReason::IdempotencyCapacity,
        ErrorReason::TicketSessionLimit,
        ErrorReason::BrokerSessionLimit,
        ErrorReason::UnknownTicket,
        ErrorReason::TicketExpired,
        ErrorReason::TicketAlreadyRedeemed,
        ErrorReason::UpstreamTimeout,
        ErrorReason::UpstreamError,
        ErrorReason::UpstreamConnectFailed,
        ErrorReason::ResponseTooLarge,
        ErrorReason::CredentialRenderFailed,
        ErrorReason::SshAgentOpenFailed,
        ErrorReason::BadConnectionConfig,
        ErrorReason::BodyUnavailable,
        ErrorReason::SpoolFailed,
        ErrorReason::BridgeNotRunning,
        ErrorReason::ProxyNotRunning,
        ErrorReason::BrokerShutdown,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            ErrorReason::MissingToken => "missing_token",
            ErrorReason::InvalidToken => "invalid_token",
            ErrorReason::TokenExpired => "token_expired",
            ErrorReason::TokenSuperseded => "token_superseded",
            ErrorReason::PeerIdentityMismatch => "peer_identity_mismatch",
            ErrorReason::InvalidAgentName => "invalid_agent_name",
            ErrorReason::PairingAlreadyPending => "pairing_already_pending",
            ErrorReason::PairingDeniedCooldown => "pairing_denied_cooldown",
            ErrorReason::PairingRateLimited => "pairing_rate_limited",
            ErrorReason::PairingFailed => "pairing_failed",
            ErrorReason::UnknownConnection => "unknown_connection",
            ErrorReason::WrongConnectionType => "wrong_connection_type",
            ErrorReason::InvalidJson => "invalid_json",
            ErrorReason::InvalidMethod => "invalid_method",
            ErrorReason::InvalidPath => "invalid_path",
            ErrorReason::ReservedHeader => "reserved_header",
            ErrorReason::InvalidHeader => "invalid_header",
            ErrorReason::InvalidBody => "invalid_body",
            ErrorReason::RequestTooLarge => "request_too_large",
            ErrorReason::RequestIdMismatch => "request_id_mismatch",
            ErrorReason::OutcomeNotReplayable => "outcome_not_replayable",
            ErrorReason::DeniedByUser => "denied_by_user",
            ErrorReason::DeniedByPolicy => "denied_by_policy",
            ErrorReason::ApprovalTimeout => "approval_timeout",
            ErrorReason::RateLimited => "rate_limited",
            ErrorReason::IdempotencyCapacity => "idempotency_capacity",
            ErrorReason::TicketSessionLimit => "ticket_session_limit",
            ErrorReason::BrokerSessionLimit => "broker_session_limit",
            ErrorReason::UnknownTicket => "unknown_ticket",
            ErrorReason::TicketExpired => "ticket_expired",
            ErrorReason::TicketAlreadyRedeemed => "ticket_already_redeemed",
            ErrorReason::UpstreamTimeout => "upstream_timeout",
            ErrorReason::UpstreamError => "upstream_error",
            ErrorReason::UpstreamConnectFailed => "upstream_connect_failed",
            ErrorReason::ResponseTooLarge => "response_too_large",
            ErrorReason::CredentialRenderFailed => "credential_render_failed",
            ErrorReason::SshAgentOpenFailed => "ssh_agent_open_failed",
            ErrorReason::BadConnectionConfig => "bad_connection_config",
            ErrorReason::BodyUnavailable => "body_unavailable",
            ErrorReason::SpoolFailed => "spool_failed",
            ErrorReason::BridgeNotRunning => "bridge_not_running",
            ErrorReason::ProxyNotRunning => "proxy_not_running",
            ErrorReason::BrokerShutdown => "broker_shutdown",
        }
    }
}

impl fmt::Display for ErrorReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for ErrorReason {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

/// How a client authenticates to the control plane. Advertised as
/// `auth_schemes` in the manifest so agents can negotiate before future
/// schemes (device-flow pairing, federated workload identity,
/// sender-constrained tokens) exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthScheme {
    /// A bearer pair token bound out-of-band to the OS-verified peer
    /// identity observed at pairing (§8): the only scheme in ABP/0.
    BearerPinned,
}

impl AuthScheme {
    pub const ALL: [AuthScheme; 1] = [AuthScheme::BearerPinned];
    pub const fn as_str(self) -> &'static str {
        match self {
            AuthScheme::BearerPinned => "bearer_pinned",
        }
    }
}

impl Serialize for AuthScheme {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

/// How approval decisions reach the agent. Advertised as `approval_modes`
/// in the manifest. ABP/0 defines only the blocking mode; an async mode
/// (submit, then poll or subscribe) would be a new flag, not a change to
/// this one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalMode {
    /// Held-open requests: the capability call does not respond until the
    /// request reaches a terminal [`ApprovalState`].
    Blocking,
}

impl ApprovalMode {
    pub const ALL: [ApprovalMode; 1] = [ApprovalMode::Blocking];
    pub const fn as_str(self) -> &'static str {
        match self {
            ApprovalMode::Blocking => "blocking",
        }
    }
}

impl Serialize for ApprovalMode {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

/// The approval lifecycle (ABP lifecycle registry). Every capability
/// request occupies exactly one state:
///
/// ```text
/// pending ──allow──▶ executing ──▶ executed   (exactly one execution)
///    │
///    ├──deny────────▶ denied     (user or policy; reason names which)
///    ├──timeout─────▶ expired    (approval window elapsed; auto-denied)
///    └──abandon─────▶ abandoned  (no waiter left; never executed)
/// ```
///
/// `executed`, `denied`, `expired`, and `abandoned` are terminal. On the
/// blocking binding, abandonment is defined by waiter liveness: a parked
/// request whose every attached client connection has closed is abandoned
/// and MUST NOT be executed. A future non-blocking binding must define its
/// own abandonment trigger (e.g. an explicit TTL) but keeps these states
/// and transitions unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalState {
    Pending,
    Executing,
    Executed,
    Denied,
    Expired,
    Abandoned,
}

impl ApprovalState {
    pub const ALL: [ApprovalState; 6] = [
        ApprovalState::Pending,
        ApprovalState::Executing,
        ApprovalState::Executed,
        ApprovalState::Denied,
        ApprovalState::Expired,
        ApprovalState::Abandoned,
    ];
    pub const fn as_str(self) -> &'static str {
        match self {
            ApprovalState::Pending => "pending",
            ApprovalState::Executing => "executing",
            ApprovalState::Executed => "executed",
            ApprovalState::Denied => "denied",
            ApprovalState::Expired => "expired",
            ApprovalState::Abandoned => "abandoned",
        }
    }
}

impl Serialize for ApprovalState {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn reason_strings_are_unique_snake_case_and_complete() {
        let mut seen = BTreeSet::new();
        for reason in ErrorReason::ALL {
            let s = reason.as_str();
            assert!(
                s.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "not snake_case: {s}"
            );
            assert!(seen.insert(s), "duplicate reason string: {s}");
        }
        assert_eq!(seen.len(), ErrorReason::ALL.len());
    }

    #[test]
    fn vocabulary_serializes_as_bare_strings() {
        assert_eq!(
            serde_json::to_string(&ErrorReason::DeniedByUser).unwrap(),
            "\"denied_by_user\""
        );
        assert_eq!(
            serde_json::to_string(&AuthScheme::BearerPinned).unwrap(),
            "\"bearer_pinned\""
        );
        assert_eq!(
            serde_json::to_string(&ApprovalMode::Blocking).unwrap(),
            "\"blocking\""
        );
        assert_eq!(
            serde_json::to_string(&ApprovalState::Abandoned).unwrap(),
            "\"abandoned\""
        );
    }
}
