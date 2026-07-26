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
use crate::request_history::{RequestHistory, RequestRecord, RequestResolution};
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
    /// One SSH authentication. The narrowest unit the agent protocol offers:
    /// the broker signs a login and is then out of the connection entirely,
    /// so this authorizes a session it cannot afterwards see or stop.
    Login,
}

impl ApprovalUnit {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Tool => "tool",
            Self::Session => "session",
            Self::Login => "login",
        }
    }
}

const APPROVAL_TEXT_CAP: usize = 400;

/// How often a live prompt re-checks that someone is still waiting on it.
/// Retirement happens inside [`Approvals::sweep`], and sweeping takes a
/// caller — which a vanished caller by definition stops being. Without this
/// poll, a prompt every one of whose waiters disconnected would sit in the
/// queue (and the user's Inbox) until its deadline.
const WAITER_LIVENESS_PERIOD: Duration = Duration::from_secs(3);

/// Directional-override and isolate characters. In text an agent controls
/// they can visually reorder the very string the user is deciding on
/// (`DELETE /prod` dressed up as something harmless), so a prompt never
/// renders them.
const BIDI_CONTROLS: [char; 12] = [
    '\u{061C}', '\u{200E}', '\u{200F}', '\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}', '\u{202E}',
    '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}',
];

/// Whether a character may appear in prompt text. Newlines and tabs keep a
/// body preview readable; other controls (and the bidi set above) are
/// replaced so they cannot reorder, hide, or corrupt what the user is shown.
fn approval_text_char(c: char) -> char {
    if BIDI_CONTROLS.contains(&c) || (c.is_control() && c != '\n' && c != '\t') {
        '\u{FFFD}'
    } else {
        c
    }
}

/// Every string a prompt shows funnels through here: bounded, and stripped
/// of characters that could visually rewrite the question.
fn cap_approval_text(text: String) -> String {
    let mut capped: String = text
        .chars()
        .take(APPROVAL_TEXT_CAP)
        .map(approval_text_char)
        .collect();
    if text.chars().nth(APPROVAL_TEXT_CAP).is_some() {
        capped.push('…');
    }
    capped
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
    /// What approving actually hands over, in the broker's own words.
    ///
    /// Deliberately a separate field from `summary`/`detail`, which are
    /// derived from what the agent and its client sent: a warning that shared
    /// a field with attacker-influenced text could be crowded out or
    /// contradicted by it. Nothing outside this crate's capability modules
    /// sets it, and no agent input reaches it.
    pub consequence: Option<&'static str>,
}

impl ApprovalRequest {
    pub fn new(
        connection: &Connection,
        agent: impl Into<String>,
        summary: impl Into<String>,
    ) -> Self {
        let unit = match connection.kind() {
            ConnectionKind::Pg => ApprovalUnit::Session,
            ConnectionKind::Ssh => ApprovalUnit::Login,
            _ => ApprovalUnit::Request,
        };
        Self {
            connection: connection.clone(),
            unit,
            agent: agent.into(),
            summary: cap_approval_text(summary.into()),
            detail: None,
            consequence: None,
        }
    }

    pub fn detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(cap_approval_text(detail.into()));
        self
    }

    /// State what approving hands over. Takes a `&'static str` so the text
    /// can only come from the binary, never from a request.
    pub fn consequence(mut self, consequence: &'static str) -> Self {
        self.consequence = Some(consequence);
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
    /// What approving hands over, in the broker's words rather than the
    /// agent's — see [`ApprovalRequest::consequence`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consequence: Option<&'static str>,
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
                // An attached app that predates request surfaces is an
                // observer here, not a surface: name the update path or the
                // refusal reads as the app being ignored.
                "traffic confirmation is unavailable; attach AgentMFA (updating it if one is \
                 already attached), or retry when capacity is available"
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
    /// The coalescing/grant key this prompt was raised under, so retiring it
    /// clears exactly its own index entry and never another agent's.
    key: GrantKey,
    waiters: Vec<oneshot::Sender<Verdict>>,
    deadline: Instant,
}

struct Lapsed {
    info: PendingApproval,
    resolution: RequestResolution,
}

/// An open approval window, closed by whichever bound passes first. The
/// monotonic bound caps it at the window of *running* time and cannot be
/// stretched by setting the wall clock back; the wall bound keeps it from
/// outliving the end time the user was shown when a suspend pauses the
/// monotonic clock (`Instant` stops during sleep on macOS and Linux).
#[derive(Debug, Clone, Copy)]
struct Grant {
    until: Instant,
    wall_until: DateTime<Utc>,
}

/// What an approval covers: one connection, for one agent.
///
/// The agent label is self-reported, which is why it scopes a grant but never
/// grants one. Keying the window on it can only *narrow* what an approval
/// admits — a second agent that does not claim the first one's label gets
/// asked in its own name instead of riding an answer the user gave about
/// somebody else. An agent that does claim it is no better off than under a
/// connection-wide window, which is what this replaces.
type GrantKey = (Uuid, String);

#[derive(Default)]
struct State {
    /// Prompt id → the prompt and everyone riding it.
    pending: HashMap<Uuid, Pending>,
    /// (Connection, agent) → its in-flight prompt, the coalescing index.
    /// Scoped the same way as the grant it can produce: a pool opening ten
    /// sessions still raises one prompt, but two agents are two questions.
    inflight: HashMap<GrantKey, Uuid>,
    /// (Connection, agent) → its open approval window.
    grants: HashMap<GrantKey, Grant>,
    /// Connection id → when its post-denial cooldown lifts.
    ///
    /// Deliberately *not* per-agent, unlike the grant above. A cooldown is
    /// the refusal being honoured for what follows it, so it has to bind
    /// what the user was protecting — the connection — and a self-reported
    /// label would otherwise be a one-line way around it: rotate the name,
    /// get asked again. Narrow what an approval covers, keep broad what a
    /// denial covers; both directions fail closed.
    cooldowns: HashMap<Uuid, Instant>,
}

struct Inner {
    config: ApprovalConfig,
    audit: Arc<AuditLog>,
    events: Arc<dyn BrokerEvents>,
    history: Arc<RequestHistory>,
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
        Self::with_history(config, audit, events, Arc::new(RequestHistory::default()))
    }

    /// Build against the broker-owned request history so future request kinds
    /// can publish into the same lifecycle store.
    pub fn with_history(
        config: ApprovalConfig,
        audit: Arc<AuditLog>,
        events: Arc<dyn BrokerEvents>,
        history: Arc<RequestHistory>,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                config,
                audit,
                events,
                history,
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
        let key: GrantKey = (connection_id, request.agent.clone());
        let now = Instant::now();

        // Retire whatever lapsed while nobody was looking, and tell the
        // shell before adding to the queue — a prompt swept here answers
        // its waiters through their channels, which emit nothing.
        let lapsed = {
            let mut state = self.inner.state.lock().unwrap();
            Self::sweep(&mut state, now, Utc::now())
        };
        self.announce_lapsed(&lapsed);

        // The prompt this call ends up riding, so its own deadline retires
        // exactly that one and never a later prompt on the same connection.
        let (receiver, prompt, deadline) = {
            let inner = &self.inner;
            let mut state = inner.state.lock().unwrap();

            // An open window covers this agent on this connection — not the
            // connection at large, and not an agent the user never saw.
            if state.grants.contains_key(&key) {
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
            match state.inflight.get(&key).copied() {
                // This agent is already being asked about this connection:
                // ride that answer instead of stacking a second prompt.
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
                    inner.history.update_approval(&info);
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
                        consequence: request.consequence,
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
                            key: key.clone(),
                            waiters: vec![tx],
                            deadline,
                        },
                    );
                    state.inflight.insert(key.clone(), id);
                    // The hook runs outside the lock: a shell may answer
                    // re-entrantly (the dev harness does), and the oneshot
                    // holds the verdict either way.
                    drop(state);

                    inner.history.record_approval(&info);
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
                            // the registry, not solely by that future — and
                            // poll waiter liveness on the way, so a prompt
                            // nobody is waiting on anymore leaves the queue
                            // in seconds rather than at its deadline.
                            let approvals = self.clone();
                            tokio::spawn(async move {
                                let deadline = tokio::time::Instant::from_std(deadline);
                                loop {
                                    let now = tokio::time::Instant::now();
                                    if now >= deadline {
                                        approvals.resolve(
                                            &id,
                                            Verdict::TimedOut,
                                            RequestResolution::TimedOut,
                                        );
                                        return;
                                    }
                                    tokio::time::sleep_until(
                                        deadline.min(now + WAITER_LIVENESS_PERIOD),
                                    )
                                    .await;
                                    // `pending` sweeps: a passed deadline and
                                    // a fully disconnected waiter list both
                                    // retire the prompt inside it.
                                    if !approvals.pending().iter().any(|prompt| prompt.id == id) {
                                        return;
                                    }
                                }
                            });
                            (rx, id, deadline)
                        }
                        ApprovalHandling::Unavailable => {
                            // Nothing can ask. Refuse now rather than leave
                            // the agent hanging until the deadline.
                            self.resolve(&id, Verdict::Unavailable, RequestResolution::NoSurface);
                            self.audit_decision(&request, Verdict::Unavailable, Some("no_surface"));
                            return Verdict::Unavailable;
                        }
                        ApprovalHandling::Waived => {
                            // A harness that stands in for the user: let it
                            // through without opening a window.
                            self.resolve(&id, Verdict::Allowed, RequestResolution::Waived);
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
                    self.resolve(&prompt, Verdict::TimedOut, RequestResolution::TimedOut);
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
        let wall_now = Utc::now();
        let (pending, lapsed) = {
            let mut state = self.inner.state.lock().unwrap();
            // A response that loses the deadline race must not manufacture a
            // fresh approval window after the prompt has already expired.
            let lapsed = Self::sweep(&mut state, now, wall_now);
            let Some(pending) = state.pending.remove(id) else {
                drop(state);
                self.announce_lapsed(&lapsed);
                return false;
            };
            let connection_id = pending.info.connection_id;
            let key = pending.key.clone();
            if state.inflight.get(&key) == Some(id) {
                state.inflight.remove(&key);
            }
            match decision {
                ApprovalDecision::ApproveWindow => {
                    // Scoped to the agent the prompt named. Another agent on
                    // the same connection is a question the user has not been
                    // asked yet, and gets asked in its own name.
                    state.grants.insert(
                        key,
                        Grant {
                            until: now + self.inner.config.window,
                            wall_until: wall_now
                                + chrono::Duration::from_std(self.inner.config.window)
                                    .unwrap_or_else(|_| chrono::Duration::seconds(900)),
                        },
                    );
                }
                ApprovalDecision::ApproveAll => {
                    // The switch is going off; nothing to remember here.
                    state.grants.remove(&key);
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
        self.inner.history.update_approval(&pending.info);
        self.inner.history.resolve(
            id,
            match decision {
                ApprovalDecision::ApproveWindow => RequestResolution::ApprovedForWindow,
                ApprovalDecision::ApproveAll => RequestResolution::ApprovedAll,
                ApprovalDecision::Deny => RequestResolution::Denied,
            },
        );
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
            let lapsed = Self::sweep(&mut state, Instant::now(), Utc::now());
            let pending: Vec<PendingApproval> =
                state.pending.values().map(|p| p.info.clone()).collect();
            (pending, lapsed)
        };
        self.announce_lapsed(&lapsed);
        for info in &pending {
            self.inner.history.update_approval(info);
        }
        pending.sort_by_key(|p| p.requested_at);
        pending
    }

    /// Surfaced requests, newest state change first. Terminal entries are
    /// retained in memory for seven days, up to the bounded history cap.
    pub fn requests(&self) -> Vec<RequestRecord> {
        // `pending` also retires deadlines and refreshes coalesced waiter
        // counts before the history snapshot is taken.
        let _ = self.pending();
        self.inner.history.records()
    }

    /// How long the longest-running window on this connection has left (the
    /// UI shows it, so the user knows why nothing is asking).
    ///
    /// Windows are per agent, so this is the outer bound across them —
    /// enough for a countdown, but not the whole truth on its own. Pair it
    /// with [`Self::window_agents`] so the app can name who is covered
    /// rather than implying the connection is open to everyone.
    pub fn window_remaining(&self, connection_id: &Uuid) -> Option<Duration> {
        let now = Instant::now();
        let wall_now = Utc::now();
        let (remaining, lapsed) = {
            let mut state = self.inner.state.lock().unwrap();
            let lapsed = Self::sweep(&mut state, now, wall_now);
            let remaining = state
                .grants
                .iter()
                .filter(|((id, _), _)| id == connection_id)
                .map(|(_, grant)| {
                    grant
                        .until
                        .saturating_duration_since(now)
                        .min((grant.wall_until - wall_now).to_std().unwrap_or_default())
                })
                .max();
            (remaining, lapsed)
        };
        self.announce_lapsed(&lapsed);
        remaining
    }

    /// The agents an open window currently covers on this connection, sorted.
    /// Empty when nothing is open.
    pub fn window_agents(&self, connection_id: &Uuid) -> Vec<String> {
        let (mut agents, lapsed) = {
            let mut state = self.inner.state.lock().unwrap();
            let lapsed = Self::sweep(&mut state, Instant::now(), Utc::now());
            let agents: Vec<String> = state
                .grants
                .keys()
                .filter(|(id, _)| id == connection_id)
                .map(|(_, agent)| agent.clone())
                .collect();
            (agents, lapsed)
        };
        self.announce_lapsed(&lapsed);
        agents.sort();
        agents
    }

    /// Whether a denial's cooldown still covers this connection (the UI
    /// shows it, so the user knows retries are being refused unasked).
    pub fn cooldown_remaining(&self, connection_id: &Uuid) -> Option<Duration> {
        let now = Instant::now();
        let (remaining, lapsed) = {
            let mut state = self.inner.state.lock().unwrap();
            let lapsed = Self::sweep(&mut state, now, Utc::now());
            let remaining = state
                .cooldowns
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
    fn announce_lapsed(&self, lapsed: &[Lapsed]) {
        for item in lapsed {
            self.inner.history.update_approval(&item.info);
            self.inner.history.resolve(&item.info.id, item.resolution);
            self.inner.events.approval_resolved(&item.info.id);
        }
    }

    /// Drop everything remembered about a connection and refuse whatever is
    /// waiting on it. Called when its access is switched off, its target
    /// changes, or it is deleted — an approval covers the traffic the user
    /// was shown, and none of those are it any more.
    pub fn revoke(&self, connection_id: &Uuid) {
        let waiting = {
            let mut state = self.inner.state.lock().unwrap();
            Self::drop_connection(&mut state, connection_id)
        };
        for id in waiting {
            self.resolve(&id, Verdict::Revoked, RequestResolution::PolicyChanged);
        }
    }

    /// Forget every agent's window and prompt on one connection, returning
    /// the prompts left to answer. Grants and prompts are keyed per agent, so
    /// a connection-scoped change has to sweep all of them — leaving one
    /// behind would let a policy change that closed one agent's window quietly
    /// spare another's.
    fn drop_connection(state: &mut State, connection_id: &Uuid) -> Vec<Uuid> {
        state.grants.retain(|(id, _), _| id != connection_id);
        state.cooldowns.remove(connection_id);
        let waiting: Vec<Uuid> = state
            .inflight
            .iter()
            .filter(|((id, _), _)| id == connection_id)
            .map(|(_, prompt)| *prompt)
            .collect();
        state.inflight.retain(|(id, _), _| id != connection_id);
        waiting
    }

    /// Stop gating this connection: whatever is parked on it goes through.
    ///
    /// This is the switch being turned off, which is the user saying "carry
    /// this traffic without asking" — refusing the very calls that raised
    /// the prompt would be a strange way to honour that. Contrast
    /// [`Self::revoke`], where the authority itself went away.
    pub fn release(&self, connection_id: &Uuid) {
        self.release_as(connection_id, RequestResolution::ConfirmationDisabled);
    }

    /// Release a connection while preserving the user action that disabled
    /// confirmation (`Approve all` versus a separate settings change).
    pub(crate) fn release_as(&self, connection_id: &Uuid, resolution: RequestResolution) {
        let waiting = {
            let mut state = self.inner.state.lock().unwrap();
            Self::drop_connection(&mut state, connection_id)
        };
        for id in waiting {
            self.resolve(&id, Verdict::Allowed, resolution);
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
            self.resolve(&id, Verdict::Revoked, RequestResolution::PolicyChanged);
        }
    }

    /// Hand `verdict` to everyone riding the prompt and retire it.
    fn resolve(&self, id: &Uuid, verdict: Verdict, resolution: RequestResolution) {
        let pending = {
            let mut state = self.inner.state.lock().unwrap();
            let Some(pending) = state.pending.remove(id) else {
                return;
            };
            state.inflight.remove(&pending.key);
            pending
        };
        self.inner.history.update_approval(&pending.info);
        self.inner.history.resolve(id, resolution);
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
    ///
    /// Windows and prompts are checked against both clocks: `Instant` pauses
    /// during a system suspend, so on its own a 15-minute window approved
    /// before the lid closed would still be admitting traffic the next
    /// morning, long past the end time the user was shown.
    #[must_use]
    fn sweep(state: &mut State, now: Instant, wall_now: DateTime<Utc>) -> Vec<Lapsed> {
        state
            .grants
            .retain(|_, grant| grant.until > now && grant.wall_until > wall_now);
        state.cooldowns.retain(|_, until| *until > now);
        for pending in state.pending.values_mut() {
            pending.waiters.retain(|waiter| !waiter.is_closed());
            pending.info.waiting = pending.waiters.len();
        }
        let expired =
            |pending: &Pending| pending.deadline <= now || pending.info.expires_at <= wall_now;
        let retired: Vec<(Uuid, bool)> = state
            .pending
            .iter()
            .filter(|(_, pending)| expired(pending) || pending.waiters.is_empty())
            .map(|(id, pending)| (*id, expired(pending)))
            .collect();
        let mut lapsed = Vec::with_capacity(retired.len());
        for (id, timed_out) in retired {
            if let Some(pending) = state.pending.remove(&id) {
                state.inflight.remove(&pending.key);
                if timed_out {
                    for waiter in pending.waiters {
                        let _ = waiter.send(Verdict::TimedOut);
                    }
                }
                lapsed.push(Lapsed {
                    info: pending.info,
                    resolution: if timed_out {
                        RequestResolution::TimedOut
                    } else {
                        RequestResolution::CallerDisconnected
                    },
                });
            }
        }
        lapsed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request_history::RequestStatus;
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

    fn request_from(connection: &Connection, agent: &str) -> ApprovalRequest {
        ApprovalRequest::new(connection, agent, "GET /user/repos")
    }

    /* ------------------------- per-agent scoping -------------------------- */

    /// The prompt names one agent, so its answer covers that one. A second
    /// agent on the same connection is a question the user was never asked.
    #[tokio::test]
    async fn one_agents_window_does_not_cover_another() {
        let (approvals, events, _dir) = auto(ApprovalDecision::ApproveWindow);
        let conn = connection();

        assert_eq!(
            approvals.gate(request_from(&conn, "claude-code")).await,
            Verdict::Allowed
        );
        assert_eq!(
            approvals.gate(request_from(&conn, "claude-code")).await,
            Verdict::Allowed
        );
        assert_eq!(
            events.seen.load(Ordering::SeqCst),
            1,
            "the same agent rides its own window"
        );

        assert_eq!(
            approvals.gate(request_from(&conn, "some-other-agent")).await,
            Verdict::Allowed
        );
        assert_eq!(
            events.seen.load(Ordering::SeqCst),
            2,
            "a different agent is asked about in its own name"
        );
        assert_eq!(
            approvals.window_agents(&conn.id),
            vec!["claude-code".to_string(), "some-other-agent".to_string()],
        );
    }

    /// Coalescing collapses one agent's burst, not two agents' questions —
    /// otherwise approving a prompt that names A silently releases B's
    /// parked call in the same click.
    #[tokio::test]
    async fn two_agents_do_not_ride_one_prompt() {
        let (approvals, _dir) = registry(Arc::new(NeverAnswers));
        let conn = connection();

        let first = approvals.clone();
        let a = conn.clone();
        let one = tokio::spawn(async move { first.gate(request_from(&a, "agent-a")).await });
        let second = approvals.clone();
        let b = conn.clone();
        let two = tokio::spawn(async move { second.gate(request_from(&b, "agent-b")).await });

        // Let both park.
        for _ in 0..50 {
            if approvals.pending().len() >= 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        let pending = approvals.pending();
        assert_eq!(pending.len(), 2, "one prompt each, not one shared");
        assert!(pending.iter().all(|p| p.waiting == 1));

        // Answering one leaves the other still waiting on the user.
        let a_prompt = pending.iter().find(|p| p.agent == "agent-a").unwrap();
        approvals.respond(&a_prompt.id, ApprovalDecision::ApproveWindow);
        assert_eq!(one.await.unwrap(), Verdict::Allowed);
        assert_eq!(
            approvals.pending().len(),
            1,
            "agent-b is still being asked about"
        );
        assert_eq!(two.await.unwrap(), Verdict::TimedOut);
    }

    /// The asymmetry that keeps the label from becoming an authorization
    /// bypass: an approval narrows to the agent, a denial does not. A
    /// per-agent cooldown would be evadable by renaming.
    #[tokio::test]
    async fn a_denial_cools_down_the_connection_not_just_the_agent() {
        let (approvals, events, _dir) = auto(ApprovalDecision::Deny);
        let conn = connection();

        assert_eq!(
            approvals.gate(request_from(&conn, "agent-a")).await,
            Verdict::Denied
        );
        assert_eq!(
            approvals.gate(request_from(&conn, "agent-b")).await,
            Verdict::Denied
        );
        assert_eq!(
            events.seen.load(Ordering::SeqCst),
            1,
            "a rename does not buy a fresh prompt during the cooldown"
        );
    }

    #[tokio::test]
    async fn revoking_drops_every_agents_window() {
        let (approvals, _events, _dir) = auto(ApprovalDecision::ApproveWindow);
        let conn = connection();
        approvals.gate(request_from(&conn, "agent-a")).await;
        approvals.gate(request_from(&conn, "agent-b")).await;
        assert_eq!(approvals.window_agents(&conn.id).len(), 2);

        approvals.revoke(&conn.id);
        assert_eq!(approvals.window_remaining(&conn.id), None);
        assert!(approvals.window_agents(&conn.id).is_empty());
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
        // so the gate remembers no traffic grant. Lifecycle history still
        // records what answered this prompt.
        let (approvals, _events, _dir) = auto(ApprovalDecision::ApproveAll);
        let conn = connection();
        assert_eq!(approvals.gate(request(&conn)).await, Verdict::Allowed);
        assert_eq!(approvals.window_remaining(&conn.id), None);
        let history = approvals.requests();
        assert_eq!(history[0].status, RequestStatus::Approved);
        assert_eq!(history[0].resolution, Some(RequestResolution::ApprovedAll));
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
        let history = approvals.requests();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].id, pending[0].id);
        assert_eq!(history[0].waiting, 10);
        assert_eq!(history[0].status, RequestStatus::Approved);
        assert_eq!(
            history[0].resolution,
            Some(RequestResolution::ApprovedForWindow)
        );
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
        // Timing out opens no grant and starts no denial cooldown.
        assert_eq!(approvals.window_remaining(&conn.id), None);
        let history = approvals.requests();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].status, RequestStatus::Expired);
        assert_eq!(history[0].resolution, Some(RequestResolution::TimedOut));
    }

    #[tokio::test]
    async fn no_surface_fails_closed() {
        let (approvals, _dir) = registry(Arc::new(NoSurface));
        let conn = connection();
        assert_eq!(approvals.gate(request(&conn)).await, Verdict::Unavailable);
        assert!(approvals.pending().is_empty());
        let history = approvals.requests();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].status, RequestStatus::Unavailable);
        assert_eq!(history[0].resolution, Some(RequestResolution::NoSurface));
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

    #[test]
    fn untrusted_prompt_text_cannot_reorder_or_hide_what_the_user_reads() {
        // A right-to-left override in a path or tool argument would render
        // the decision string backwards; a bare control character can
        // corrupt whatever surface shows it. Both are replaced, while the
        // newlines and tabs of an ordinary body preview survive.
        let conn = connection();
        let request =
            ApprovalRequest::new(&conn, "agent", "GET /safe\u{202E}dorp/ ETELED".to_string())
                .detail("line one\n\tindented\u{0007}\u{200F}".to_string());
        assert_eq!(request.summary, "GET /safe\u{FFFD}dorp/ ETELED");
        assert_eq!(
            request.detail.as_deref(),
            Some("line one\n\tindented\u{FFFD}\u{FFFD}")
        );
    }

    #[tokio::test]
    async fn a_window_is_bounded_by_the_wall_clock_as_well_as_uptime() {
        // `Instant` pauses during a system suspend, so a window measured
        // only in running time could still be admitting traffic the morning
        // after the lid closed. The wall bound closes it on schedule.
        let (approvals, events, _dir) = auto(ApprovalDecision::ApproveWindow);
        let conn = connection();
        assert_eq!(approvals.gate(request(&conn)).await, Verdict::Allowed);
        assert!(approvals.window_remaining(&conn.id).is_some());

        // Wall time passed while the monotonic clock stood still.
        approvals
            .inner
            .state
            .lock()
            .unwrap()
            .grants
            .get_mut(&(conn.id, "claude-code".to_string()))
            .unwrap()
            .wall_until = Utc::now() - chrono::Duration::seconds(1);

        assert_eq!(approvals.window_remaining(&conn.id), None);
        assert_eq!(approvals.gate(request(&conn)).await, Verdict::Allowed);
        assert_eq!(
            events.seen.load(Ordering::SeqCst),
            2,
            "traffic after the advertised end must be asked about again"
        );
    }

    #[tokio::test]
    async fn a_prompt_past_its_advertised_expiry_cannot_be_answered() {
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

        // Wall-expire the prompt while its monotonic deadline is still
        // ahead, as a suspend across the deadline would.
        approvals
            .inner
            .state
            .lock()
            .unwrap()
            .pending
            .get_mut(&prompt.id)
            .unwrap()
            .info
            .expires_at = Utc::now() - chrono::Duration::seconds(1);

        assert!(!approvals.respond(&prompt.id, ApprovalDecision::ApproveWindow));
        assert_eq!(call.await.unwrap(), Verdict::TimedOut);
        assert_eq!(approvals.window_remaining(&conn.id), None);
    }

    #[tokio::test(start_paused = true)]
    async fn a_prompt_all_of_whose_callers_vanished_retires_before_its_deadline() {
        // Sweeping needs a caller, and a vanished caller stops calling. The
        // liveness poll is what retires the prompt then — well before the
        // deadline that would otherwise keep a dead question on the user.
        let dir = tempfile::tempdir().unwrap();
        let audit = Arc::new(AuditLog::open(dir.path().join("audit.jsonl")).unwrap());
        let approvals = Approvals::new(
            ApprovalConfig {
                timeout: Duration::from_secs(90),
                ..config()
            },
            audit,
            Arc::new(NeverAnswers),
        );
        let conn = connection();
        let call = {
            let approvals = approvals.clone();
            let conn = conn.clone();
            tokio::spawn(async move { approvals.gate(request(&conn)).await })
        };
        tokio::time::timeout(Duration::from_secs(1), async {
            while approvals.inner.state.lock().unwrap().pending.is_empty() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the call should raise a prompt");
        call.abort();
        let _ = call.await;

        // Watch the raw state so the assertion itself cannot run the sweep.
        tokio::time::timeout(WAITER_LIVENESS_PERIOD * 2, async {
            while !approvals.inner.state.lock().unwrap().pending.is_empty() {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("the abandoned prompt should retire within one liveness period");
        let history = approvals.inner.history.records();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].status, RequestStatus::Abandoned);
        assert_eq!(
            history[0].resolution,
            Some(RequestResolution::CallerDisconnected)
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
