//! Broker tunables. Tests shrink the defaults.

use std::time::Duration;

#[derive(Debug, Clone)]
pub struct BrokerConfig {
    /// Broker version advertised in the discovery manifest.
    pub version: String,

    /// Advertised, machine-actionable client timeout: upstream timeout +
    /// margin.
    pub recommended_client_timeout: Duration,
    /// Completed idempotency keys are retained this long. Their outcomes are
    /// replayed when the byte-bounded response cache still has them. A
    /// zero duration fails closed for new retainable keyed requests.
    pub outcome_retention: Duration,
    /// Global cap on in-flight reservations plus completed idempotency-key
    /// tombstones. Request IDs have a separate wire-level length limit, so
    /// entry count also bounds retained tombstone metadata. New keyed
    /// executions fail closed when every slot is used.
    pub outcome_retention_max_entries: usize,
    /// Global cap on serialized replay-body bytes. An individual outcome
    /// larger than this keeps only its compact idempotency tombstone.
    pub outcome_retention_max_bytes: usize,

    /// Upstream HTTP call timeout.
    pub upstream_timeout: Duration,
    /// Response body cap (default 10 MB).
    pub response_cap: usize,
    /// Request body cap (default 150 MB).
    pub request_cap: usize,
    /// Request bodies past this are spooled to a temp file rather than held
    /// in memory while parked.
    pub spool_threshold: usize,
    /// Redirect loop bound.
    pub max_redirects: usize,

    /// Pair token TTL, refreshed on use.
    pub token_ttl: Duration,

    /// Per-token rate limit on capability calls: requests per minute.
    pub per_token_per_min: u32,
    /// Global discovery limit (unauthenticated endpoints).
    pub discovery_per_min: u32,
    /// Global pairing brake: max attempts per window.
    pub pairing_max_attempts: u32,
    pub pairing_window: Duration,

    /// Data-plane tickets die this long after issue.
    pub ticket_ttl: Duration,
    /// Bridged/proxied session max TTL.
    pub session_max_ttl: Duration,
    /// Idle teardown (no traffic either direction; WS ping/pong counts as
    /// activity).
    pub session_idle_timeout: Duration,
    /// Per-approval (per-ticket) concurrent session cap.
    pub per_ticket_sessions: usize,
    /// Global concurrent session backstop.
    pub global_sessions: usize,
}

impl Default for BrokerConfig {
    fn default() -> Self {
        Self {
            version: env!("CARGO_PKG_VERSION").to_string(),
            recommended_client_timeout: Duration::from_secs(2 * 60),
            outcome_retention: Duration::from_secs(600),
            outcome_retention_max_entries: 1024,
            outcome_retention_max_bytes: 64 * 1024 * 1024,
            upstream_timeout: Duration::from_secs(60),
            response_cap: 10 * 1024 * 1024,
            request_cap: 150 * 1024 * 1024,
            spool_threshold: 2 * 1024 * 1024,
            max_redirects: 10,
            token_ttl: Duration::from_secs(30 * 24 * 60 * 60),
            per_token_per_min: 60,
            discovery_per_min: 60,
            pairing_max_attempts: 3,
            pairing_window: Duration::from_secs(5),
            ticket_ttl: Duration::from_secs(60),
            session_max_ttl: Duration::from_secs(60 * 60),
            session_idle_timeout: Duration::from_secs(5 * 60),
            per_ticket_sessions: 60,
            global_sessions: 300,
        }
    }
}
