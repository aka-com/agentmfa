//! The Agent Broker Protocol (ABP) wire vocabulary.
//!
//! This module is the in-code source of truth for the protocol surface the
//! manifest advertises and PROTOCOL.md specifies in prose: the protocol
//! version, the **closed registry** of machine-readable error reasons, and
//! the capability flags (auth schemes). Everything an agent can observe on
//! the wire is named here, so the vocabulary is reviewable and freezable as
//! a unit.
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

/// Why authentication arrived without a usable bearer credential. This is
/// deliberately phrased in terms of what the broker observed: without a
/// credential, the broker cannot attribute omission or rewriting to the
/// calling agent, its HTTP library, or another local forwarding application.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissingTokenCause {
    AuthorizationHeaderAbsent,
    AuthorizationHeaderInvalid,
    AuthorizationSchemeInvalid,
    BearerTokenEmpty,
}

impl MissingTokenCause {
    pub const fn detail(self) -> &'static str {
        match self {
            Self::AuthorizationHeaderAbsent => {
                "No Authorization header reached the broker. It may have been blocked by a local application."
            }
            Self::AuthorizationHeaderInvalid => {
                "An invalid Authorization header reached the broker. It may have been rewritten by a local application."
            }
            Self::AuthorizationSchemeInvalid => {
                "An Authorization header reached the broker but did not use the Bearer scheme. It may have been rewritten by a local application."
            }
            Self::BearerTokenEmpty => {
                "A Bearer Authorization header reached the broker without a token. It may have been rewritten by a local application."
            }
        }
    }
}

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
    InvalidAgentName,
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
    // Policy outcomes.
    DeniedByPolicy,
    /// The user was asked to confirm this call and refused it.
    ApprovalDenied,
    /// Nobody answered the confirmation before its deadline.
    ApprovalTimeout,
    /// The connection asks for confirmation, but no surface could ask the
    /// user (no app attached to this broker).
    ApprovalUnavailable,
    // Rate limits and budgets.
    RateLimited,
    IdempotencyCapacity,
    TicketSessionLimit,
    BrokerSessionLimit,
    // Tickets (data-plane redemption).
    UnknownTicket,
    TicketExpired,
    // Upstream execution.
    UpstreamTimeout,
    UpstreamError,
    UpstreamConnectFailed,
    ResponseTooLarge,
    CredentialRenderFailed,
    SshAgentOpenFailed,
    /// The endpoint exists on another transport but is not served on the
    /// one the request arrived on (pairing over TCP).
    NotServedRemotely,
    /// The MCP host is not running (no sidecar to proxy to).
    McpUnavailable,
    // Broker-side faults.
    BadConnectionConfig,
    BodyUnavailable,
    SpoolFailed,
    ProxyNotRunning,
    BrokerShutdown,
}

impl ErrorReason {
    /// Every registered reason, for exhaustiveness checks and docs.
    pub const ALL: [ErrorReason; 41] = [
        ErrorReason::MissingToken,
        ErrorReason::InvalidToken,
        ErrorReason::TokenExpired,
        ErrorReason::TokenSuperseded,
        ErrorReason::InvalidAgentName,
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
        ErrorReason::DeniedByPolicy,
        ErrorReason::ApprovalDenied,
        ErrorReason::ApprovalTimeout,
        ErrorReason::ApprovalUnavailable,
        ErrorReason::RateLimited,
        ErrorReason::IdempotencyCapacity,
        ErrorReason::TicketSessionLimit,
        ErrorReason::BrokerSessionLimit,
        ErrorReason::UnknownTicket,
        ErrorReason::TicketExpired,
        ErrorReason::UpstreamTimeout,
        ErrorReason::UpstreamError,
        ErrorReason::UpstreamConnectFailed,
        ErrorReason::ResponseTooLarge,
        ErrorReason::CredentialRenderFailed,
        ErrorReason::SshAgentOpenFailed,
        ErrorReason::NotServedRemotely,
        ErrorReason::McpUnavailable,
        ErrorReason::BadConnectionConfig,
        ErrorReason::BodyUnavailable,
        ErrorReason::SpoolFailed,
        ErrorReason::ProxyNotRunning,
        ErrorReason::BrokerShutdown,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            ErrorReason::MissingToken => "missing_token",
            ErrorReason::InvalidToken => "invalid_token",
            ErrorReason::TokenExpired => "token_expired",
            ErrorReason::TokenSuperseded => "token_superseded",
            ErrorReason::InvalidAgentName => "invalid_agent_name",
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
            ErrorReason::DeniedByPolicy => "denied_by_policy",
            ErrorReason::ApprovalDenied => "approval_denied",
            ErrorReason::ApprovalTimeout => "approval_timeout",
            ErrorReason::ApprovalUnavailable => "approval_unavailable",
            ErrorReason::RateLimited => "rate_limited",
            ErrorReason::IdempotencyCapacity => "idempotency_capacity",
            ErrorReason::TicketSessionLimit => "ticket_session_limit",
            ErrorReason::BrokerSessionLimit => "broker_session_limit",
            ErrorReason::UnknownTicket => "unknown_ticket",
            ErrorReason::TicketExpired => "ticket_expired",
            ErrorReason::UpstreamTimeout => "upstream_timeout",
            ErrorReason::UpstreamError => "upstream_error",
            ErrorReason::UpstreamConnectFailed => "upstream_connect_failed",
            ErrorReason::ResponseTooLarge => "response_too_large",
            ErrorReason::CredentialRenderFailed => "credential_render_failed",
            ErrorReason::SshAgentOpenFailed => "ssh_agent_open_failed",
            ErrorReason::NotServedRemotely => "not_served_remotely",
            ErrorReason::McpUnavailable => "mcp_unavailable",
            ErrorReason::BadConnectionConfig => "bad_connection_config",
            ErrorReason::BodyUnavailable => "body_unavailable",
            ErrorReason::SpoolFailed => "spool_failed",
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
    /// A plain bearer pair token minted at registration: the only scheme in
    /// ABP/0. The token identifies the agent; there is no peer identity
    /// verification.
    Bearer,
}

impl AuthScheme {
    pub const ALL: [AuthScheme; 1] = [AuthScheme::Bearer];
    pub const fn as_str(self) -> &'static str {
        match self {
            AuthScheme::Bearer => "bearer",
        }
    }
}

impl Serialize for AuthScheme {
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
            serde_json::to_string(&ErrorReason::DeniedByPolicy).unwrap(),
            "\"denied_by_policy\""
        );
        assert_eq!(
            serde_json::to_string(&AuthScheme::Bearer).unwrap(),
            "\"bearer\""
        );
        assert_eq!(
            serde_json::to_string(&MissingTokenCause::AuthorizationHeaderAbsent).unwrap(),
            "\"authorization_header_absent\""
        );
    }
}
