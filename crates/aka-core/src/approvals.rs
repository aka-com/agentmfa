//! Traffic confirmation: parking agent traffic on a human decision.
//!
//! A connection whose [`ConfirmMode`](crate::types::ConfirmMode) is on does
//! not carry traffic until the user says so. The call parks here, the shell
//! raises a prompt, and the answer resolves it: **approve for a window**,
//! **approve and stop asking**, or **deny**.
//!
//! This is the only gate in the broker that runs on *agent*-initiated work,
//! and that shapes it:
//!
//! - It is asynchronous. The user-plane gates
//!   ([`BrokerEvents::confirm_action`](crate::events::BrokerEvents::confirm_action))
//!   block a thread on a native sheet; a parked request instead awaits a
//!   channel, so a request body already spooled to disk stays parked
//!   without pinning a runtime thread.
//! - It **coalesces**. A connection pool opening ten Postgres sessions, or
//!   an agent firing concurrent requests, raises one prompt that every
//!   waiter rides. Otherwise the first honest use of the switch would bury
//!   the user.
//! - It **fails closed**. With no surface able to ask (a headless
//!   `mfa serve`, a shell that never implemented the hook), traffic on a
//!   confirm-on connection is refused rather than waved through: the user
//!   asked to be asked.
//! - A refusal **cools down**. An agent that retries in a loop would
//!   otherwise re-prompt in a loop, so a denial also refuses the calls that
//!   follow it for a short while, without asking again.
//!
//! Grants live in memory only. A broker restart, a key rotation, disabling
//! agent access, or repointing the connection all drop them — an approval
//! is permission for the traffic the user was shown, not a standing state
//! worth persisting. Only "approve all" outlives the process, and it does
//! so as the connection's own switch going off, through the same
//! confirmation every other gate-weakening change takes.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde::Serialize;
use tokio::sync::oneshot;
use uuid::Uuid;

use crate::audit::{AuditEntry, AuditKind, AuditLog};
use crate::events::{ApprovalHandling, BrokerEvents};
use crate::types::{Connection, ConnectionKind};
use crate::wire::ErrorReason;

/// The concrete thing the prompt authorizes, independent of the connection
/// that carries it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalUnit {
    Request,
    Tool,
    Session,
}

impl ApprovalUnit {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Tool => "tool",
            Self::Session => "session",
        }
    }
}

const APPROVAL_TEXT_CAP: usize = 400;

fn cap_approval_text(mut text: String) -> String {
    if let Some((cutoff, _)) = text.char_indices().nth(APPROVAL_TEXT_CAP) {
        text.truncate(cutoff);
        text.push('…');
    }
    text
}

/// Bound an untrusted field before cloning it into a prompt. Callers use
/// this for method, tool, and path strings that can otherwise be as large as
/// the whole request envelope.
pub(crate) fn capped_text(text: &str) -> String {
    if let Some((cutoff, _)) = text.char_indices().nth(APPROVAL_TEXT_CAP) {
        format!("{}…", &text[..cutoff])
    } else {
        text.to_string()
    }
}

/// What the user is being asked about: one unit of traffic, described in
/// the terms of its own plane.
#[derive(Debug, Clone)]
pub struct ApprovalRequest {
    pub connection: Connection,
    pub unit: ApprovalUnit,
    /// Self-reported agent label. Attribution for the prompt, never
    /// authorization — the decision is scoped to the connection.
    pub agent: String,
    /// The headline: `GET /user/repos`, `search_issues`, `psql session`.
    pub summary: String,
    /// The second line, when there is more worth showing: a body preview,
    /// the tool's arguments, the client's application name.
    pub detail: Option<String>,
}

impl ApprovalRequest {
    pub fn new(
        connection: &Connection,
        agent: impl Into<String>,
        summary: impl Into<String>,
    ) -> Self {
        let unit = match connection.kind() {
            ConnectionKind::Pg => ApprovalUnit::Session,
            _ => ApprovalUnit::Request,
        };
        Self {
            connection: connection.clone(),
            unit,
            agent: agent.into(),
            summary: cap_approval_text(summary.into()),
            detail: None,
        }
    }

    pub fn detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(cap_approval_text(detail.into()));
        self
    }

    pub fn tool(mut self) -> Self {
        self.unit = ApprovalUnit::Tool;
        self
    }

    /// Attach a detail only when there is one.
    pub fn maybe_detail(mut self, detail: Option<String>) -> Self {
        self.detail = detail.map(cap_approval_text);
        self
    }
}

/// One prompt waiting on the user, as the app renders it. Carries no
/// credential material and no request body — only what was summarized for
/// the decision.
#[derive(Debug, Clone, Serialize)]
pub struct PendingApproval {
    pub id: Uuid,
    pub connection_id: Uuid,
    pub connection: String,
    pub kind: ConnectionKind,
    pub unit: ApprovalUnit,
    /// The pinned destination (`https://api.github.com`, `app@db:5432/x`).
    pub target: String,
    pub agent: String,
    pub summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// How many calls are riding this one prompt, itself included.
    pub waiting: usize,
    pub requested_at: DateTime<Utc>,
    /// When the prompt gives up on its own and every waiter is refused.
    pub expires_at: DateTime<Utc>,
    /// How long "approve for now" lasts, so the button can name it.
    pub window_secs: u64,
}

/// The user's answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalDecision {
    /// Let this through, and everything else on the connection until the
    /// window lapses.
    ApproveWindow,
    /// Let this through and stop asking. The caller persists the switch
    /// going off; the registry only releases the waiters.
    ApproveAll,
    /// Refuse this, and whatever follows it during the cooldown.
    Deny,
}

/// How a gated call ended up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Proceed: approved just now, or riding an open window.
    Allowed,
    /// The user refused (or the refusal's cooldown is still running).
    Denied,
    /// The authority changed or disappeared while the call was parked.
    Revoked,
    /// Nobody answered before the deadline.
    TimedOut,
    /// No surface could ask: nothing is attached to this broker, or too
    /// many prompts are already waiting.
    Unavailable,
}

impl Verdict {
    pub fn is_allowed(self) -> bool {
        matches!(self, Verdict::Allowed)
    }

    /// The wire reason a refused call is answered with.
    pub fn reason(self) -> Option<ErrorReason> {
        match self {
            Verdict::Allowed => None,
            Verdict::Denied => Some(ErrorReason::ApprovalDenied),
            Verdict::Revoked => Some(ErrorReason::DeniedByPolicy),
            Verdict::TimedOut => Some(ErrorReason::ApprovalTimeout),
            Verdict::Unavailable => Some(ErrorReason::ApprovalUnavailable),
        }
    }

    /// Prose for planes that answer in their own protocol (Postgres error
    /// fields, MCP tool errors) rather than the JSON envelope.
    pub fn detail(self) -> &'static str {
        match self {
            Verdict::Allowed => "approved",
            Verdict::Denied => "the user refused this call in AgentMFA",
            Verdict::Revoked => {
                "the connection or its access policy changed while confirmation was waiting"
            }
            Verdict::TimedOut => "the confirmation request was not answered in time",
            Verdict::Unavailable => {
                "traffic confirmation is unavailable; attach AgentMFA or retry when capacity is available"
            }
        }
    }

    fn audit_outcome(self) -> &'static str {
        match self {
            Verdict::Allowed => "approved",
            Verdict::Denied => "denied",
            Verdict::Revoked => "denied_by_policy",
            Verdict::TimedOut => "timed_out",
            Verdict::Unavailable => "unavailable",
        }
    }
}

/// Tunables, mirrored from [`BrokerConfig`](crate::config::BrokerConfig) so
/// the registry can be built standalone in tests.
#[derive(Debug, Clone, Copy)]
pub struct ApprovalConfig {
    /// How long a prompt waits for an answer.
    pub timeout: Duration,
    /// How long "approve for now" covers the connection.
    pub window: Duration,
    /// How long a denial refuses what follows without asking again.
    pub deny_cooldown: Duration,
    /// Backstop on prompts waiting at once (coalescing already bounds this
    /// to one per connection).
    pub max_pending: usize,
    /// Backstop on all calls riding prompts, including direct-endpoint
    /// sockets that have not entered the upload semaphores yet.
    pub max_waiters: usize,
}

struct Pending {
    info: PendingApproval,
    waiters: Vec<oneshot::Sender<Verdict>>,
    deadline: Instant,
}

#[derive(Default)]
struct State {
    /// Prompt id → the prompt and everyone riding it.
    pending: HashMap<Uuid, Pending>,
    /// Connection id → its in-flight prompt, the coalescing index.
    inflight: HashMap<Uuid, Uuid>,
    /// Connection id → when its approval window lapses.
    grants: HashMap<Uuid, Instant>,
    /// Connection id → when its post-denial cooldown lifts.
    cooldowns: HashMap<Uuid, Instant>,
}

struct Inner {
    config: ApprovalConfig,
    audit: Arc<AuditLog>,
    events: Arc<dyn BrokerEvents>,
    state: Mutex<State>,
}

/// The broker's pending-approval registry.
#[derive(Clone)]
pub struct Approvals {
    inner: Arc<Inner>,
}

impl Approvals {
    pub fn new(
        config: ApprovalConfig,
        audit: Arc<AuditLog>,
        events: Arc<dyn BrokerEvents>,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                config,
                audit,
                events,
                state: Mutex::new(State::default()),
            }),
        }
    }

    /// Ask the user about one unit of traffic, and wait for the answer.
    ///
    /// Callers reach this only for connections whose switch is on; an open
    /// window or a running cooldown answers without raising anything.
    pub async fn gate(&self, request: ApprovalRequest) -> Verdict {
        let connection_id = request.connection.id;
        let now = Instant::now();

        // Retire whatever lapsed while nobody was looking, and tell the
        // shell before adding to the queue — a prompt swept here answers
        // its waiters through their channels, which emit nothing.
        let lapsed = {
            let mut state = self.inner.state.lock().unwrap();
            Self::sweep(&mut state, now)
        };
        self.announce_lapsed(&lapsed);

        // The prompt this call ends up riding, so its own deadline retires
        // exactly that one and never a later prompt on the same connection.
        let (receiver, prompt, deadline) = {
            let inner = &self.inner;
            let mut state = inner.state.lock().unwrap();

            if state.grants.contains_key(&connection_id) {
                return Verdict::Allowed;
            }
            if state.cooldowns.contains_key(&connection_id) {
                // The user just said no. Honour that for the calls chasing
                // it rather than asking again on every retry.
                drop(state);
                self.audit_decision(&request, Verdict::Denied, Some("cooldown"));
                return Verdict::Denied;
            }

            let waiter_count: usize = state
                .pending
                .values()
                .map(|pending| pending.waiters.len())
                .sum();
            if waiter_count >= inner.config.max_waiters {
                drop(state);
                self.audit_decision(&request, Verdict::Unavailable, Some("waiter_queue_full"));
                return Verdict::Unavailable;
            }

            let (tx, rx) = oneshot::channel();
            match state.inflight.get(&connection_id).copied() {
                // Someone is already being asked about this connection:
                // ride their answer instead of stacking a second prompt.
                Some(id) => {
                    let pending = state
                        .pending
                        .get_mut(&id)
                        .expect("inflight without pending");
                    pending.waiters.push(tx);
                    pending.info.waiting = pending.waiters.len();
                    let info = pending.info.clone();
                    let deadline = pending.deadline;
                    drop(state);
                    inner.events.approval_updated(&info);
                    (rx, id, deadline)
                }
                None => {
                    if state.pending.len() >= inner.config.max_pending {
                        drop(state);
                        self.audit_decision(&request, Verdict::Unavailable, Some("queue_full"));
                        return Verdict::Unavailable;
                    }
                    let id = Uuid::new_v4();
                    let requested_at = Utc::now();
                    let deadline = now + inner.config.timeout;
                    let info = PendingApproval {
                        id,
                        connection_id,
                        connection: request.connection.name.clone(),
                        kind: request.connection.kind(),
                        unit: request.unit,
                        target: request.connection.target(),
                        agent: request.agent.clone(),
                        summary: request.summary.clone(),
                        detail: request.detail.clone(),
                        waiting: 1,
                        requested_at,
                        expires_at: requested_at
                            + chrono::Duration::from_std(inner.config.timeout)
                                .unwrap_or_else(|_| chrono::Duration::seconds(90)),
                        window_secs: inner.config.window.as_secs(),
                    };
                    state.pending.insert(
                        id,
                        Pending {
                            info: info.clone(),
                            waiters: vec![tx],
                            deadline,
                        },
                    );
                    state.inflight.insert(connection_id, id);
                    // The hook runs outside the lock: a shell may answer
                    // re-entrantly (the dev harness does), and the oneshot
                    // holds the verdict either way.
                    drop(state);

                    self.inner.audit.append(
                        AuditEntry::new(
                            AuditKind::Requested,
                            format!(
                                "Confirmation requested: {} → {}",
                                request.agent, request.connection.name
                            ),
                        )
                        .agent(request.agent.clone())
                        .connection(request.connection.name.clone())
                        .detail(request.summary.clone())
                        .field("kind", request.connection.kind().as_str())
                        .field("approval_id", id.to_string()),
                    );

                    match inner.events.approval_requested(&info) {
                        ApprovalHandling::Taken => {
                            // The request future can disappear (a direct
                            // client disconnects) while the UI still holds
                            // this prompt. Keep deadline retirement owned by
                            // the registry, not solely by that future.
                            let approvals = self.clone();
                            tokio::spawn(async move {
                                tokio::time::sleep_until(tokio::time::Instant::from_std(deadline))
                                    .await;
                                approvals.resolve(&id, Verdict::TimedOut);
                            });
                            (rx, id, deadline)
                        }
                        ApprovalHandling::Unavailable => {
                            // Nothing can ask. Refuse now rather than leave
                            // the agent hanging until the deadline.
                            self.resolve(&id, Verdict::Unavailable);
                            self.audit_decision(&request, Verdict::Unavailable, Some("no_surface"));
                            return Verdict::Unavailable;
                        }
                        ApprovalHandling::Waived => {
                            // A harness that stands in for the user: let it
                            // through without opening a window.
                            self.resolve(&id, Verdict::Allowed);
                            self.audit_decision(&request, Verdict::Allowed, Some("waived"));
                            return Verdict::Allowed;
                        }
                    }
                }
            }
        };

        let verdict =
            match tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), receiver).await
            {
                Ok(Ok(verdict)) => verdict,
                // The prompt was dropped without an answer (broker teardown).
                Ok(Err(_)) => Verdict::Revoked,
                Err(_) => {
                    // Retire by id: by now the connection may be being asked
                    // about again, and that newer prompt is not ours to refuse.
                    self.resolve(&prompt, Verdict::TimedOut);
                    Verdict::TimedOut
                }
            };
        self.audit_decision(&request, verdict, None);
        verdict
    }

    /// Answer a prompt. Returns whether one was waiting under that id.
    ///
    /// [`ApprovalDecision::ApproveAll`] releases the waiters exactly like a
    /// windowed approval; persisting the connection's switch is the
    /// caller's job, and it takes its own confirmation.
    pub fn respond(&self, id: &Uuid, decision: ApprovalDecision) -> bool {
        let now = Instant::now();
        let (pending, lapsed) = {
            let mut state = self.inner.state.lock().unwrap();
            // A response that loses the deadline race must not manufacture a
            // fresh approval window after the prompt has already expired.
            let lapsed = Self::sweep(&mut state, now);
            let Some(pending) = state.pending.remove(id) else {
                drop(state);
                self.announce_lapsed(&lapsed);
                return false;
            };
            let connection_id = pending.info.connection_id;
            if state.inflight.get(&connection_id) == Some(id) {
                state.inflight.remove(&connection_id);
            }
            match decision {
                ApprovalDecision::ApproveWindow => {
                    state
                        .grants
                        .insert(connection_id, now + self.inner.config.window);
                }
                ApprovalDecision::ApproveAll => {
                    // The switch is going off; nothing to remember here.
                    state.grants.remove(&connection_id);
                }
                ApprovalDecision::Deny => {
                    state
                        .cooldowns
                        .insert(connection_id, now + self.inner.config.deny_cooldown);
                }
            }
            (pending, lapsed)
        };
        self.announce_lapsed(&lapsed);
        let verdict = match decision {
            ApprovalDecision::Deny => Verdict::Denied,
            _ => Verdict::Allowed,
        };
        for waiter in pending.waiters {
            let _ = waiter.send(verdict);
        }
        self.inner.events.approval_resolved(id);
        true
    }

    /// Every prompt waiting on the user, oldest first.
    pub fn pending(&self) -> Vec<PendingApproval> {
        let (mut pending, lapsed) = {
            let mut state = self.inner.state.lock().unwrap();
            let lapsed = Self::sweep(&mut state, Instant::now());
            let pending: Vec<PendingApproval> =
                state.pending.values().map(|p| p.info.clone()).collect();
            (pending, lapsed)
        };
        self.announce_lapsed(&lapsed);
        pending.sort_by_key(|p| p.requested_at);
        pending
    }

    /// Whether an open window currently covers this connection (the UI
    /// shows it, so the user knows why nothing is asking).
    pub fn window_remaining(&self, connection_id: &Uuid) -> Option<Duration> {
        let now = Instant::now();
        let (remaining, lapsed) = {
            let mut state = self.inner.state.lock().unwrap();
            let lapsed = Self::sweep(&mut state, now);
            let remaining = state
                .grants
                .get(connection_id)
                .map(|until| until.saturating_duration_since(now));
            (remaining, lapsed)
        };
        self.announce_lapsed(&lapsed);
        remaining
    }

    /// A prompt swept away by its deadline or by all callers disconnecting
    /// still left the queue, so the shell has to hear about it. Deadline
    /// waiters were answered inside the sweep, where there is no observer
    /// to call.
    fn announce_lapsed(&self, lapsed: &[Uuid]) {
        for id in lapsed {
            self.inner.events.approval_resolved(id);
        }
    }

    /// Drop everything remembered about a connection and refuse whatever is
    /// waiting on it. Called when its access is switched off, its target
    /// changes, or it is deleted — an approval covers the traffic the user
    /// was shown, and none of those are it any more.
    pub fn revoke(&self, connection_id: &Uuid) {
        let waiting: Vec<Uuid> = {
            let mut state = self.inner.state.lock().unwrap();
            state.grants.remove(connection_id);
            state.cooldowns.remove(connection_id);
            state
                .inflight
                .get(connection_id)
                .copied()
                .into_iter()
                .collect()
        };
        for id in waiting {
            self.resolve(&id, Verdict::Revoked);
        }
    }

    /// Stop gating this connection: whatever is parked on it goes through.
    ///
    /// This is the switch being turned off, which is the user saying "carry
    /// this traffic without asking" — refusing the very calls that raised
    /// the prompt would be a strange way to honour that. Contrast
    /// [`Self::revoke`], where the authority itself went away.
    pub fn release(&self, connection_id: &Uuid) {
        let waiting: Vec<Uuid> = {
            let mut state = self.inner.state.lock().unwrap();
            state.grants.remove(connection_id);
            state.cooldowns.remove(connection_id);
            state
                .inflight
                .get(connection_id)
                .copied()
                .into_iter()
                .collect()
        };
        for id in waiting {
            self.resolve(&id, Verdict::Allowed);
        }
    }

    /// Rotation-scale invalidation: every window closes and every prompt is
    /// refused, exactly as outstanding tickets are.
    pub fn revoke_all(&self) {
        let waiting: Vec<Uuid> = {
            let mut state = self.inner.state.lock().unwrap();
            state.grants.clear();
            state.cooldowns.clear();
            state.pending.keys().copied().collect()
        };
        for id in waiting {
            self.resolve(&id, Verdict::Revoked);
        }
    }

    /// Hand `verdict` to everyone riding the prompt and retire it.
    fn resolve(&self, id: &Uuid, verdict: Verdict) {
        let pending = {
            let mut state = self.inner.state.lock().unwrap();
            let Some(pending) = state.pending.remove(id) else {
                return;
            };
            state.inflight.remove(&pending.info.connection_id);
            pending
        };
        for waiter in pending.waiters {
            let _ = waiter.send(verdict);
        }
        self.inner.events.approval_resolved(id);
    }

    fn audit_decision(&self, request: &ApprovalRequest, verdict: Verdict, note: Option<&str>) {
        let (kind, text) = match verdict {
            Verdict::Allowed => (
                AuditKind::AllowedOnce,
                format!("Confirmed: {} → {}", request.agent, request.connection.name),
            ),
            Verdict::Denied => (
                AuditKind::Denied,
                format!(
                    "Refused by the user: {} → {}",
                    request.agent, request.connection.name
                ),
            ),
            Verdict::Revoked => (
                AuditKind::Denied,
                format!(
                    "Refused (policy changed): {} → {}",
                    request.agent, request.connection.name
                ),
            ),
            Verdict::TimedOut => (
                AuditKind::ApprovalTimeout,
                format!(
                    "Confirmation not answered: {} → {}",
                    request.agent, request.connection.name
                ),
            ),
            Verdict::Unavailable => (
                AuditKind::Denied,
                if matches!(note, Some("queue_full" | "waiter_queue_full")) {
                    format!(
                        "Refused (confirmation queue full): {} → {}",
                        request.agent, request.connection.name
                    )
                } else {
                    format!(
                        "Refused (nobody could confirm): {} → {}",
                        request.agent, request.connection.name
                    )
                },
            ),
        };
        let mut entry = AuditEntry::new(kind, text)
            .agent(request.agent.clone())
            .connection(request.connection.name.clone())
            .detail(request.summary.clone())
            .outcome(verdict.audit_outcome())
            .field("kind", request.connection.kind().as_str());
        if let Some(note) = note {
            entry = entry.field("via", note);
        }
        self.inner.audit.append(entry);
    }

    /// Drop lapsed windows and cooldowns, and refuse prompts whose deadline
    /// has passed. A prompt whose callers all disconnected is retired too:
    /// answering it must not open a window for traffic that no longer exists.
    /// Returns the prompts that left the queue, so the caller can tell the
    /// shell they are gone once the lock is released.
    #[must_use]
    fn sweep(state: &mut State, now: Instant) -> Vec<Uuid> {
        state.grants.retain(|_, until| *until > now);
        state.cooldowns.retain(|_, until| *until > now);
        for pending in state.pending.values_mut() {
            pending.waiters.retain(|waiter| !waiter.is_closed());
            pending.info.waiting = pending.waiters.len();
        }
        let retired: Vec<Uuid> = state
            .pending
            .iter()
            .filter(|(_, pending)| pending.deadline <= now || pending.waiters.is_empty())
            .map(|(id, _)| *id)
            .collect();
        for id in &retired {
            if let Some(pending) = state.pending.remove(id) {
                state.inflight.remove(&pending.info.connection_id);
                if pending.deadline <= now {
                    for waiter in pending.waiters {
                        let _ = waiter.send(Verdict::TimedOut);
                    }
                }
            }
        }
        retired
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ConnectionConfig;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A shell that answers every prompt the moment it is raised, the way a
    /// user with a very fast finger would.
    struct AutoAnswer {
        decision: ApprovalDecision,
        seen: AtomicUsize,
        approvals: Mutex<Option<Approvals>>,
    }

    impl BrokerEvents for AutoAnswer {
        fn approval_requested(&self, pending: &PendingApproval) -> ApprovalHandling {
            self.seen.fetch_add(1, Ordering::SeqCst);
            let approvals = self.approvals.lock().unwrap().clone();
            if let Some(approvals) = approvals {
                approvals.respond(&pending.id, self.decision);
            }
            ApprovalHandling::Taken
        }
    }

    /// A shell that takes the prompt and sits on it.
    struct NeverAnswers;
    impl BrokerEvents for NeverAnswers {
        fn approval_requested(&self, _pending: &PendingApproval) -> ApprovalHandling {
            ApprovalHandling::Taken
        }
    }

    /// A shell with no way to ask (the trait default).
    struct NoSurface;
    impl BrokerEvents for NoSurface {}

    fn connection() -> Connection {
        Connection {
            id: Uuid::new_v4(),
            name: "github".into(),
            config: ConnectionConfig::Api {
                host: "api.github.com".into(),
                scheme: "https".into(),
                port: None,
                template: "Authorization: Bearer {{T}}".into(),
                mcp_path: None,
                oauth: None,
            },
            secrets: vec![],
            account: None,
            oauth: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn config() -> ApprovalConfig {
        ApprovalConfig {
            timeout: Duration::from_millis(200),
            window: Duration::from_secs(900),
            deny_cooldown: Duration::from_secs(60),
            max_pending: 32,
            max_waiters: 256,
        }
    }

    fn registry(events: Arc<dyn BrokerEvents>) -> (Approvals, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let audit = Arc::new(AuditLog::open(dir.path().join("audit.jsonl")).unwrap());
        (Approvals::new(config(), audit, events), dir)
    }

    fn auto(decision: ApprovalDecision) -> (Approvals, Arc<AutoAnswer>, tempfile::TempDir) {
        let events = Arc::new(AutoAnswer {
            decision,
            seen: AtomicUsize::new(0),
            approvals: Mutex::new(None),
        });
        let (approvals, dir) = registry(events.clone());
        *events.approvals.lock().unwrap() = Some(approvals.clone());
        (approvals, events, dir)
    }

    fn request(connection: &Connection) -> ApprovalRequest {
        ApprovalRequest::new(connection, "claude-code", "GET /user/repos")
    }

    #[tokio::test]
    async fn an_approval_opens_a_window_the_next_calls_ride() {
        let (approvals, events, _dir) = auto(ApprovalDecision::ApproveWindow);
        let conn = connection();

        assert_eq!(approvals.gate(request(&conn)).await, Verdict::Allowed);
        assert_eq!(approvals.gate(request(&conn)).await, Verdict::Allowed);
        assert_eq!(
            events.seen.load(Ordering::SeqCst),
            1,
            "the window covers what follows without asking again"
        );
        assert!(approvals.window_remaining(&conn.id).is_some());

        // A different connection is a different decision.
        let other = connection();
        assert_eq!(approvals.gate(request(&other)).await, Verdict::Allowed);
        assert_eq!(events.seen.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn approve_all_lets_the_call_through_without_opening_a_window() {
        // "Stop asking" is persisted by the caller as the switch going off,
        // so the registry deliberately remembers nothing.
        let (approvals, _events, _dir) = auto(ApprovalDecision::ApproveAll);
        let conn = connection();
        assert_eq!(approvals.gate(request(&conn)).await, Verdict::Allowed);
        assert_eq!(approvals.window_remaining(&conn.id), None);
    }

    #[tokio::test]
    async fn a_refusal_cools_down_instead_of_reprompting_every_retry() {
        let (approvals, events, _dir) = auto(ApprovalDecision::Deny);
        let conn = connection();

        assert_eq!(approvals.gate(request(&conn)).await, Verdict::Denied);
        assert_eq!(approvals.gate(request(&conn)).await, Verdict::Denied);
        assert_eq!(approvals.gate(request(&conn)).await, Verdict::Denied);
        assert_eq!(
            events.seen.load(Ordering::SeqCst),
            1,
            "a retry loop must not become a prompt loop"
        );
    }

    #[tokio::test]
    async fn concurrent_calls_ride_one_prompt() {
        let events = Arc::new(AutoAnswer {
            decision: ApprovalDecision::ApproveWindow,
            seen: AtomicUsize::new(0),
            approvals: Mutex::new(None),
        });
        let (approvals, _dir) = registry(events.clone());
        let conn = connection();

        // Nothing answers until every caller has parked, so all ten are in
        // flight when the prompt is finally taken.
        let calls = (0..10).map(|_| {
            let approvals = approvals.clone();
            let conn = conn.clone();
            tokio::spawn(async move { approvals.gate(request(&conn)).await })
        });
        let calls: Vec<_> = calls.collect();
        let pending = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let pending = approvals.pending();
                if pending.first().is_some_and(|p| p.waiting == 10) {
                    return pending;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("ten calls should coalesce onto one prompt");
        assert_eq!(pending.len(), 1);

        approvals.respond(&pending[0].id, ApprovalDecision::ApproveWindow);
        for call in calls {
            assert_eq!(call.await.unwrap(), Verdict::Allowed);
        }
        assert_eq!(events.seen.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn an_unanswered_prompt_times_out_and_refuses() {
        let (approvals, _dir) = registry(Arc::new(NeverAnswers));
        let conn = connection();
        assert_eq!(approvals.gate(request(&conn)).await, Verdict::TimedOut);
        assert!(
            approvals.pending().is_empty(),
            "a lapsed prompt does not linger in the queue"
        );
        // Timing out is not a decision: nothing is remembered either way.
        assert_eq!(approvals.window_remaining(&conn.id), None);
    }

    #[tokio::test]
    async fn no_surface_fails_closed() {
        let (approvals, _dir) = registry(Arc::new(NoSurface));
        let conn = connection();
        assert_eq!(approvals.gate(request(&conn)).await, Verdict::Unavailable);
        assert!(approvals.pending().is_empty());
    }

    #[tokio::test]
    async fn revoking_a_connection_drops_its_window_and_refuses_its_prompt() {
        let (approvals, _events, _dir) = auto(ApprovalDecision::ApproveWindow);
        let conn = connection();
        approvals.gate(request(&conn)).await;
        assert!(approvals.window_remaining(&conn.id).is_some());

        approvals.revoke(&conn.id);
        assert_eq!(approvals.window_remaining(&conn.id), None);

        // A prompt in flight when the connection is revoked is refused.
        let (approvals, _dir) = registry(Arc::new(NeverAnswers));
        let waiting = {
            let approvals = approvals.clone();
            let conn = conn.clone();
            tokio::spawn(async move { approvals.gate(request(&conn)).await })
        };
        tokio::time::timeout(Duration::from_secs(1), async {
            while approvals.pending().is_empty() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the prompt should be raised");
        approvals.revoke(&conn.id);
        assert_eq!(waiting.await.unwrap(), Verdict::Revoked);
    }

    #[tokio::test]
    async fn rotation_closes_every_window_and_prompt() {
        let (approvals, _events, _dir) = auto(ApprovalDecision::ApproveWindow);
        let first = connection();
        let second = connection();
        approvals.gate(request(&first)).await;
        approvals.gate(request(&second)).await;

        approvals.revoke_all();
        assert_eq!(approvals.window_remaining(&first.id), None);
        assert_eq!(approvals.window_remaining(&second.id), None);
    }

    #[tokio::test]
    async fn a_lapsed_call_never_refuses_the_prompt_that_replaced_it() {
        // A call whose deadline passes retires *its* prompt by id, because
        // the connection may already be being asked about again — by a call
        // with every right to its own answer. The tight interleaving (the
        // lapsed call's timer firing after the replacement is queued) is a
        // scheduling race a test cannot force; this covers the sequence.
        let (approvals, _dir) = registry(Arc::new(NeverAnswers));
        let conn = connection();

        let first = {
            let approvals = approvals.clone();
            let conn = conn.clone();
            tokio::spawn(async move { approvals.gate(request(&conn)).await })
        };
        assert_eq!(first.await.unwrap(), Verdict::TimedOut);

        // The replacement prompt, raised after the first one lapsed.
        let second = {
            let approvals = approvals.clone();
            let conn = conn.clone();
            tokio::spawn(async move { approvals.gate(request(&conn)).await })
        };
        let pending = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let pending = approvals.pending();
                if let Some(pending) = pending.first() {
                    return pending.clone();
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the second call should raise its own prompt");

        approvals.respond(&pending.id, ApprovalDecision::ApproveWindow);
        assert_eq!(
            second.await.unwrap(),
            Verdict::Allowed,
            "the first call's deadline must not have refused this prompt"
        );
    }

    #[tokio::test]
    async fn answering_an_unknown_prompt_reports_it() {
        let (approvals, _dir) = registry(Arc::new(NeverAnswers));
        assert!(!approvals.respond(&Uuid::new_v4(), ApprovalDecision::ApproveWindow));
    }

    #[test]
    fn untrusted_prompt_text_is_bounded() {
        let conn = connection();
        let request =
            ApprovalRequest::new(&conn, "agent", "x".repeat(10_000)).detail("y".repeat(10_000));
        assert_eq!(request.summary.chars().count(), APPROVAL_TEXT_CAP + 1);
        assert!(request.summary.ends_with('…'));
        assert_eq!(
            request.detail.unwrap().chars().count(),
            APPROVAL_TEXT_CAP + 1
        );
    }

    #[tokio::test]
    async fn an_answer_after_the_deadline_cannot_open_a_window() {
        let (approvals, _dir) = registry(Arc::new(NeverAnswers));
        let conn = connection();
        let call = {
            let approvals = approvals.clone();
            let conn = conn.clone();
            tokio::spawn(async move { approvals.gate(request(&conn)).await })
        };
        let prompt = tokio::time::timeout(Duration::from_millis(100), async {
            loop {
                if let Some(prompt) = approvals.pending().first() {
                    return prompt.clone();
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the call should raise a prompt");

        // Simulate its request task being cancelled before its timer can
        // retire the prompt. The registry still has to enforce the deadline.
        call.abort();
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert!(
            approvals.inner.state.lock().unwrap().pending.is_empty(),
            "the registry-owned deadline must retire a cancelled caller's prompt"
        );
        assert!(!approvals.respond(&prompt.id, ApprovalDecision::ApproveWindow));
        assert!(approvals.pending().is_empty());
        assert_eq!(approvals.window_remaining(&conn.id), None);
    }

    #[tokio::test]
    async fn an_abandoned_prompt_cannot_open_a_window() {
        let (approvals, _dir) = registry(Arc::new(NeverAnswers));
        let conn = connection();
        let call = {
            let approvals = approvals.clone();
            let conn = conn.clone();
            tokio::spawn(async move { approvals.gate(request(&conn)).await })
        };
        let prompt = tokio::time::timeout(Duration::from_millis(100), async {
            loop {
                if let Some(prompt) = approvals.pending().first() {
                    return prompt.clone();
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the call should raise a prompt");

        call.abort();
        call.await.expect_err("the request task was cancelled");
        assert!(approvals.pending().is_empty());
        assert!(!approvals.respond(&prompt.id, ApprovalDecision::ApproveWindow));
        assert_eq!(approvals.window_remaining(&conn.id), None);
    }

    #[tokio::test]
    async fn parked_calls_are_bounded_even_when_they_share_one_prompt() {
        let dir = tempfile::tempdir().unwrap();
        let audit = Arc::new(AuditLog::open(dir.path().join("audit.jsonl")).unwrap());
        let approvals = Approvals::new(
            ApprovalConfig {
                max_waiters: 2,
                ..config()
            },
            audit,
            Arc::new(NeverAnswers),
        );
        let conn = connection();
        let first = {
            let approvals = approvals.clone();
            let conn = conn.clone();
            tokio::spawn(async move { approvals.gate(request(&conn)).await })
        };
        let second = {
            let approvals = approvals.clone();
            let conn = conn.clone();
            tokio::spawn(async move { approvals.gate(request(&conn)).await })
        };
        tokio::time::timeout(Duration::from_millis(100), async {
            loop {
                if approvals
                    .pending()
                    .first()
                    .is_some_and(|pending| pending.waiting == 2)
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("two calls should park");

        assert_eq!(
            approvals.gate(request(&conn)).await,
            Verdict::Unavailable,
            "the waiter backstop must reject more sockets/tasks"
        );
        first.abort();
        second.abort();
    }
}
