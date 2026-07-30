//! Broker tunables. Tests shrink the defaults.

use std::time::Duration;

#[derive(Debug, Clone)]
pub struct BrokerConfig {
    /// Broker version advertised in the discovery manifest.
    pub version: String,

    /// Advertised, machine-actionable client timeout: confirmation + direct
    /// upload + the complete upstream operation + transport margin.
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

    /// Deadline for one upstream HTTP hop (a single redirect leg's request
    /// and response).
    pub upstream_timeout: Duration,
    /// Deadline for the complete upstream operation — OAuth refresh, the
    /// full redirect chain, and response-body receipt together. Kept larger
    /// than a single hop so one slow leg (a sluggish token refresh, say)
    /// does not consume the entire budget the rest of the operation needs.
    pub upstream_operation_timeout: Duration,
    /// Response body cap (default 10 MB).
    pub response_cap: usize,
    /// Request body cap on the *direct endpoint* plane, which streams the body
    /// to a spool file (default 150 MB).
    pub request_cap: usize,
    /// Request body cap on `POST /v1/http` (default 8 MB).
    ///
    /// Deliberately far below `request_cap`: that plane takes the body inside a
    /// JSON envelope, so axum buffers the whole thing, `serde` materializes it
    /// again as a `Value`, and the decoded copy is a third — roughly three times
    /// the wire size resident before the spool threshold is even consulted, with
    /// no bound on how many calls do it at once. Large uploads belong on the
    /// direct endpoint, which streams.
    pub control_plane_request_cap: usize,
    /// Request bodies past this are spooled to a temp file rather than held
    /// in memory while parked.
    pub spool_threshold: usize,
    /// Concurrent direct-endpoint uploads across the broker.
    pub endpoint_global_uploads: usize,
    /// Concurrent uploads admitted by one direct HTTP endpoint.
    pub endpoint_uploads_per_listener: usize,
    /// Absolute deadline for receiving a direct-endpoint request body.
    pub endpoint_upload_timeout: Duration,
    /// Maximum gap between chunks while receiving a direct-endpoint body.
    pub endpoint_upload_idle_timeout: Duration,
    /// Redirect loop bound.
    pub max_redirects: usize,

    /// Pair token TTL, refreshed on use.
    pub token_ttl: Duration,

    /// Per-identity rate limit on capability calls: requests per minute,
    /// bucketed on the verified shared identity UUID. The self-reported
    /// activity label never affects authorization or throttling.
    pub per_identity_per_min: u32,
    /// Global discovery limit (unauthenticated endpoints).
    pub discovery_per_min: u32,
    /// Global pairing brake: max attempts per window.
    pub pairing_max_attempts: u32,
    pub pairing_window: Duration,

    /// Data-plane tickets die this long after issue.
    pub ticket_ttl: Duration,
    /// Bridged/proxied session max TTL.
    pub session_max_ttl: Duration,
    /// Idle teardown (no traffic either direction; protocol keepalives count as
    /// activity).
    pub session_idle_timeout: Duration,
    /// Deadline on the *unauthenticated* part of a Postgres downstream
    /// handshake: the pre-startup probes, the StartupMessage, and the
    /// PasswordMessage carrying the ticket. Without it a client that connects
    /// and sends nothing pins a task, an fd, and a read buffer indefinitely,
    /// which takes no ticket at all. Everything after authentication — notably
    /// a parked confirmation prompt — has its own, much longer budget.
    pub pg_handshake_timeout: Duration,
    /// Concurrent Postgres handshakes admitted before new connections wait.
    /// Bounds the unauthenticated pre-auth phase the same way the endpoint
    /// upload semaphores bound HTTP.
    pub max_pending_pg_handshakes: usize,
    /// Record the SQL of each statement seen on a brokered Postgres session in
    /// the activity log, not just how many there were.
    ///
    /// Off by default, and deliberately an operator decision: statement text
    /// can carry credentials (`ALTER USER … PASSWORD '…'`) and personal data
    /// into a durable log, which is a retention choice rather than something
    /// to switch on for someone.
    pub audit_pg_statements: bool,
    /// Per-approval (per-ticket) concurrent session cap.
    pub per_ticket_sessions: usize,
    /// Global concurrent session backstop.
    pub global_sessions: usize,

    /// Global cap on issued per-connection direct endpoints (each owns a
    /// persistent listener + socket, so the count is bounded).
    pub max_endpoints: usize,

    /// How long a traffic-confirmation prompt waits for an answer before
    /// the parked call is refused. Deliberately below
    /// `recommended_client_timeout`, so an unanswered prompt surfaces as a
    /// broker refusal the agent can read rather than as its own timeout.
    pub approval_timeout: Duration,
    /// How long one approval covers a connection's traffic ("Approve 15m").
    pub approval_window: Duration,
    /// How long a refusal keeps refusing without asking again, so a
    /// retrying agent cannot turn one denial into a prompt loop.
    pub approval_deny_cooldown: Duration,
    /// Backstop on prompts waiting at once. Coalescing already bounds these
    /// to one per connection; this bounds a broker with many connections.
    pub max_pending_approvals: usize,
    /// Backstop on all calls parked behind those prompts. Direct endpoints
    /// are gated before upload admission, so this separately bounds their
    /// sockets/tasks and the prompt's waiter channels.
    pub max_approval_waiters: usize,
}

impl BrokerConfig {
    /// Never advertise a recommendation shorter than the longest direct,
    /// confirmed, or user-eliciting call the same configuration permits.
    pub fn effective_client_timeout(&self) -> Duration {
        let minimum = self
            .approval_timeout
            .saturating_add(self.endpoint_upload_timeout)
            .saturating_add(self.upstream_operation_timeout)
            .saturating_add(crate::elicitations::ELICITATION_TIMEOUT)
            .saturating_add(Duration::from_secs(30));
        self.recommended_client_timeout.max(minimum)
    }

    pub fn approvals(&self) -> crate::approvals::ApprovalConfig {
        crate::approvals::ApprovalConfig {
            timeout: self.approval_timeout,
            window: self.approval_window,
            deny_cooldown: self.approval_deny_cooldown,
            max_pending: self.max_pending_approvals,
            max_waiters: self.max_approval_waiters,
        }
    }
}

impl Default for BrokerConfig {
    fn default() -> Self {
        Self {
            version: env!("CARGO_PKG_VERSION").to_string(),
            // An MCP call may spend the full approval, body-upload,
            // upstream-operation, and elicitation budgets; leave another 30
            // seconds for broker and transport overhead.
            recommended_client_timeout: Duration::from_secs(10 * 60),
            outcome_retention: Duration::from_secs(600),
            outcome_retention_max_entries: 1024,
            outcome_retention_max_bytes: 64 * 1024 * 1024,
            upstream_timeout: Duration::from_secs(60),
            // Two full hops' worth: an OAuth refresh or a redirect hop that
            // eats its whole per-hop budget still leaves the operation room
            // to finish instead of turning into a 504.
            upstream_operation_timeout: Duration::from_secs(120),
            response_cap: 10 * 1024 * 1024,
            request_cap: 150 * 1024 * 1024,
            control_plane_request_cap: 8 * 1024 * 1024,
            spool_threshold: 2 * 1024 * 1024,
            endpoint_global_uploads: 16,
            endpoint_uploads_per_listener: 4,
            endpoint_upload_timeout: Duration::from_secs(60),
            endpoint_upload_idle_timeout: Duration::from_secs(15),
            max_redirects: 10,
            token_ttl: Duration::from_secs(30 * 24 * 60 * 60),
            per_identity_per_min: 60,
            discovery_per_min: 60,
            pairing_max_attempts: 3,
            pairing_window: Duration::from_secs(5),
            ticket_ttl: Duration::from_secs(60),
            session_max_ttl: Duration::from_secs(60 * 60),
            session_idle_timeout: Duration::from_secs(5 * 60),
            pg_handshake_timeout: Duration::from_secs(10),
            max_pending_pg_handshakes: 64,
            audit_pg_statements: false,
            per_ticket_sessions: 60,
            global_sessions: 300,
            max_endpoints: 64,
            approval_timeout: Duration::from_secs(90),
            approval_window: Duration::from_secs(15 * 60),
            approval_deny_cooldown: Duration::from_secs(60),
            max_pending_approvals: 32,
            max_approval_waiters: 256,
        }
    }
}
