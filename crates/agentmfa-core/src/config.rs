//! Broker tunables. Defaults match DESIGN.md; tests shrink them.

use std::time::Duration;

#[derive(Debug, Clone)]
pub struct BrokerConfig {
    /// Broker version advertised in the discovery manifest.
    pub version: String,

    /// Hard per-request approval timeout (§6): auto-deny after this.
    pub approval_timeout: Duration,
    /// Advertised, machine-actionable client timeout: approval wait +
    /// upstream timeout + margin (§4/§5b).
    pub recommended_client_timeout: Duration,
    /// Completed idempotency keys are retained this long. Their outcomes are
    /// replayed when the byte-bounded response cache still has them (§4). A
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

    /// Upstream HTTP call timeout (§4.1).
    pub upstream_timeout: Duration,
    /// Response body cap (§4.1, default 10 MB).
    pub response_cap: usize,
    /// Request body cap (§4.1, default 150 MB).
    pub request_cap: usize,
    /// Request bodies past this are spooled to a temp file rather than held
    /// in memory while parked (§4.1).
    pub spool_threshold: usize,
    /// Redirect loop bound (§4.1).
    pub max_redirects: usize,
    /// How much request body the approval window's payload view shows (§6).
    pub approval_body_preview: usize,

    /// Fixed lifetime of an in-memory access session.
    pub access_grant_ttl: Duration,

    /// Pair token TTL, refreshed on use (§8).
    pub token_ttl: Duration,

    /// Per-token rate limit on capability calls (§8): requests per minute.
    pub per_token_per_min: u32,
    /// Global discovery limit (unauthenticated endpoints, §8).
    pub discovery_per_min: u32,
    /// Global pairing brake: max attempts per window (§8).
    pub pairing_max_attempts: u32,
    pub pairing_window: Duration,
    /// Cooldown after a user denies a pairing (§8).
    pub pairing_deny_cooldown: Duration,

    /// Data-plane tickets die this long after issue (§4.2/§4.3).
    pub ticket_ttl: Duration,
    /// Bridged/proxied session max TTL (§4.2).
    pub session_max_ttl: Duration,
    /// Idle teardown (no traffic either direction; WS ping/pong counts as
    /// activity, §4.2).
    pub session_idle_timeout: Duration,
    /// Per-approval (per-ticket) concurrent session cap (§8).
    pub per_ticket_sessions: usize,
    /// Global concurrent session backstop (§8).
    pub global_sessions: usize,
}

impl Default for BrokerConfig {
    fn default() -> Self {
        Self {
            version: env!("CARGO_PKG_VERSION").to_string(),
            approval_timeout: Duration::from_secs(120),
            recommended_client_timeout: Duration::from_secs(240),
            outcome_retention: Duration::from_secs(600),
            outcome_retention_max_entries: 1024,
            outcome_retention_max_bytes: 64 * 1024 * 1024,
            upstream_timeout: Duration::from_secs(60),
            response_cap: 10 * 1024 * 1024,
            request_cap: 150 * 1024 * 1024,
            spool_threshold: 2 * 1024 * 1024,
            max_redirects: 10,
            approval_body_preview: 4096,
            access_grant_ttl: Duration::from_secs(15 * 60),
            token_ttl: Duration::from_secs(30 * 24 * 60 * 60),
            per_token_per_min: 60,
            discovery_per_min: 60,
            pairing_max_attempts: 3,
            pairing_window: Duration::from_secs(5),
            pairing_deny_cooldown: Duration::from_secs(30),
            ticket_ttl: Duration::from_secs(60),
            session_max_ttl: Duration::from_secs(60 * 60),
            session_idle_timeout: Duration::from_secs(5 * 60),
            per_ticket_sessions: 60,
            global_sessions: 300,
        }
    }
}
