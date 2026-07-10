//! The approval queue.
//!
//! Approval waits are held-open requests where a `Prompt` decision parks the
//! request and the daemon simply does not respond until the user decides or
//! the timeout (default 120s) auto-denies. No polling or callback channel.
//!
//! Retries are governed by an idempotency key. Mutating calls carry an
//! optional `request_id`, and a retry re-sending the same `(agent,
//! request_id)` joins the existing prompt, one approval, exactly one
//! upstream execution, the same response replayed to every waiter and to
//! late retries while its byte-bounded replay body remains cached. Every
//! completed key keeps a compact tombstone for 10 minutes, so evicting a
//! response can never turn a retry into a second execution. Equality under
//! the key is checked, not assumed: each key stores a hash of the full
//! normalized request, and reusing a `request_id` with a different payload
//! is rejected (409).
//!
//! A parked request whose every waiter has disconnected is **abandoned**,
//! dropped from the queue, its prompt withdrawn, audited, and **never
//! executed upstream**. Disconnection is detected eagerly: each waiter
//! holds a guard whose drop (the handler future being dropped when the
//! agent's connection closes) deregisters it. A disconnect *after* the
//! upstream call has begun does not cancel it; completion always leaves an
//! idempotency tombstone and retains the outcome for replay when it fits.
//!
//! The canonical lifecycle this machinery implements is
//! [`crate::wire::ApprovalState`] (pending → executing → executed, or
//! pending → denied/expired/abandoned); terminal transitions record their
//! state in the audit log's `approval_state` field.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::io::Write;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde::Serialize;
use tokio::sync::oneshot;
use uuid::Uuid;

use crate::audit::{AuditEntry, AuditKind, AuditLog};
use crate::events::BrokerEvents;
use crate::types::{ConnectionKind, PeerIdentity};
use crate::wire::ErrorReason;

/* ------------------------------ view types ------------------------------- */

/// What one queued approval looks like to the UI (the approval window).
#[derive(Debug, Clone, Serialize)]
pub struct ApprovalRequest {
    pub id: Uuid,
    pub agent: String,
    /// Stable paired-client authorization principal. Pairing requests carry
    /// the existing matching client's id when reconnecting the same program.
    #[serde(skip)]
    pub client_id: Option<Uuid>,
    /// Pair-token generation that originated a capability request. This is
    /// internal grant state and is never serialized to an approval surface.
    #[serde(skip)]
    #[doc(hidden)]
    pub agent_token_hash: Option<String>,
    pub kind: ApprovalKind,
    /// None for pairing requests.
    pub connection: Option<ConnectionSummary>,
    /// Display line: "GET api.github.com/user/repos",
    /// "Connect to Postgres → app@db…".
    pub action: String,
    /// Doorbell body: "claude-code wants to use github, GET /user/repos".
    pub notification: String,
    pub received_at: DateTime<Utc>,
    /// Auto-deny deadline; the UI renders the countdown.
    pub deadline: DateTime<Utc>,
    /// Pairing only: the peer's verified identity display string (§6/§8).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<String>,
    /// Pairing only: plain-language program identity for the human prompt.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pairing_identity: Option<PairingIdentitySummary>,
    /// Pairing only: this name already has an active pair token that the new
    /// token will replace.
    pub replaces_existing_agent: bool,
    /// Pairing only: connections the name's standing rules would grant the
    /// connecting process promptless access to, the loud disclosure (§6).
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub inherited: Vec<ConnectionSummary>,
    /// HTTP only: the request-payload view (§6).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http: Option<HttpPayloadView>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PairingIdentitySummary {
    pub program: String,
    pub verification: &'static str,
    pub technical: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<&'static str>,
}

impl PairingIdentitySummary {
    pub fn from_identity(identity: &PeerIdentity) -> Self {
        match identity {
            PeerIdentity::Signed { signing_id, .. } => Self {
                program: signing_id.clone(),
                verification: "Signed application",
                technical: identity.display(),
                warning: None,
            },
            PeerIdentity::Unsigned {
                executable_path, ..
            } => Self {
                program: executable_path
                    .as_deref()
                    .and_then(|path| std::path::Path::new(path).file_name())
                    .and_then(|name| name.to_str())
                    .unwrap_or("Unsigned local program")
                    .to_string(),
                verification: "Local executable",
                technical: identity.display(),
                warning: Some(
                    "This program is not signed. AgentMFA uses local file details, and scripts run by the same program may share this identity.",
                ),
            },
            PeerIdentity::DevUnverified { .. } => Self {
                program: "Development process".into(),
                verification: "Development identity",
                technical: identity.display(),
                warning: Some("This development build cannot verify the connecting program."),
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ApprovalKind {
    Pair,
    Http,
    Ws,
    Pg,
    Ssh,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConnectionSummary {
    pub id: Uuid,
    pub name: String,
    #[serde(rename = "type")]
    pub kind: ConnectionKind,
    pub target: String,
    /// Exact security-relevant connection revision presented by the prompt.
    /// It stays internal because approval surfaces do not need to render it.
    #[serde(skip)]
    #[doc(hidden)]
    pub connection_updated_at: DateTime<Utc>,
}

/// Agent-supplied headers plus a size-capped body preview, collapsed for
/// GET/HEAD, auto-expanded for mutating methods in the UI. The injected
/// credential is never part of this (§6).
#[derive(Debug, Clone, Serialize)]
pub struct HttpPayloadView {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    /// Lossy UTF-8 preview, capped at `approval_body_preview` bytes.
    pub body_preview: Option<String>,
    pub body_len: u64,
    pub body_truncated: bool,
    pub mutating: bool,
}

impl ApprovalRequest {
    /// Requests whose exact *Allow once* decision completes only behind the
    /// native OS confirmation: pairing and mutating HTTP requests (§6/§8).
    /// Starting an access session and saving "Always allow…" are gated for
    /// every request kind; the broker enforces those decisions separately.
    pub fn is_high_consequence(&self) -> bool {
        match self.kind {
            ApprovalKind::Pair => true,
            ApprovalKind::Http => self.http.as_ref().is_some_and(|h| h.mutating),
            _ => false,
        }
    }
}

/* ------------------------------ outcomes --------------------------------- */

/// What a decided request resolves to on the wire: a status plus a JSON
/// body. For approved requests this is the upstream execution's result (for
/// opens, the ticket response); for refusals it's `403 {"reason": …}`.
#[derive(Debug, Clone, Serialize)]
pub struct ExecOutcome {
    pub status: u16,
    pub body: serde_json::Value,
}

impl ExecOutcome {
    pub fn refusal(reason: ErrorReason) -> Self {
        Self {
            status: 403,
            body: serde_json::json!({ "reason": reason }),
        }
    }
}

/// The single upstream execution, run once per approval.
pub type Executor = Pin<Box<dyn Future<Output = ExecOutcome> + Send + 'static>>;

/* ------------------------------ internals -------------------------------- */

type Key = (String, String); // (agent, request_id)

enum PendingState {
    /// Parked, awaiting the human.
    Prompted { executor: Executor },
    /// Approved; the one execution is in flight. New retries still attach.
    Executing,
}

struct Pending {
    request: ApprovalRequest,
    state: PendingState,
    key: Option<Key>,
    payload_hash: Option<String>,
    /// A slot reserved before this keyed execution was accepted. On
    /// completion it becomes a tombstone; denial or abandonment releases it.
    retention_reserved: bool,
    waiters: Vec<(u64, oneshot::Sender<ExecOutcome>)>,
}

struct Retained {
    at: Instant,
    payload_hash: Option<String>,
    /// `None` is a compact tombstone: execution completed, but its response
    /// was too large to retain or was evicted from the byte-bounded cache.
    outcome: Option<ExecOutcome>,
    serialized_len: usize,
}

#[derive(Default)]
struct Inner {
    queue: Vec<Uuid>,
    pending: HashMap<Uuid, Pending>,
    by_key: HashMap<Key, Uuid>,
    outcomes: HashMap<Key, Retained>,
    /// Completion order for tombstone expiry. Entries stay here for their
    /// full TTL even after their replay body is evicted.
    outcome_order: VecDeque<Key>,
    /// Completion order for byte-budget eviction of replay bodies only.
    replay_order: VecDeque<Key>,
    outcome_bytes: usize,
    retention_reservations: usize,
    waiter_seq: u64,
}

struct Shared {
    approval_timeout: Duration,
    retention: Duration,
    retention_max_entries: usize,
    retention_max_bytes: usize,
    audit: Arc<AuditLog>,
    events: Arc<dyn BrokerEvents>,
    runtime: tokio::runtime::Handle,
    inner: Mutex<Inner>,
}

pub struct Approvals {
    shared: Arc<Shared>,
}

/// Prompted executions claimed by one access-session decision. Claiming is
/// separate from starting them so the broker can install the grant only
/// after the selected prompt is guaranteed not to have timed out or been
/// abandoned.
pub(crate) struct SessionClaim {
    primary: ApprovalRequest,
    absorbed: Vec<ApprovalRequest>,
    executions: Vec<(Uuid, Executor)>,
}

/* ------------------------------ public API ------------------------------- */

/// What `park` needs from a capability handler.
pub struct ParkRequest {
    pub request: ApprovalRequest,
    /// `(agent, request_id)` for mutating calls that sent a `request_id`;
    /// never set for GET/HEAD (§4).
    pub coalesce_key: Option<(String, String)>,
    /// Hash of the full normalized request; required with `coalesce_key`.
    pub payload_hash: Option<String>,
    /// Whether the completed outcome may be replayed to late retries under
    /// the key (§4). Capability calls retain; pairing must not — replaying
    /// a minted token to a *later* caller would skip its approval — so
    /// pairing coalesces only while the prompt is in flight.
    pub retain_outcome: bool,
    /// The one upstream execution, run on approval.
    pub executor: Executor,
}

pub enum Parked {
    /// Wait on the held-open decision.
    Wait(WaitHandle),
    /// A completed outcome for this `request_id` was replayed (§4).
    Replay(ExecOutcome),
}

#[derive(Debug, thiserror::Error)]
pub enum ParkError {
    /// `request_id` reused with a different payload, a client bug (§4).
    #[error("request_id reused with a different payload")]
    RequestIdMismatch,
    /// The bounded idempotency table has no slot for a new keyed execution.
    #[error("idempotency capacity exhausted")]
    IdempotencyCapacity,
    /// The keyed execution completed, but its response body is no longer
    /// available for a safe replay. The tombstone prevents re-execution.
    #[error("completed outcome is not replayable")]
    OutcomeNotReplayable,
}

pub struct WaitHandle {
    rx: oneshot::Receiver<ExecOutcome>,
    _guard: WaiterGuard,
}

impl WaitHandle {
    /// Resolve when the user decides, the timeout fires, or execution
    /// completes. `None` only if the broker is shutting down.
    pub async fn wait(self) -> Option<ExecOutcome> {
        self.rx.await.ok()
    }
}

/// Deregisters its waiter on drop; the last waiter leaving a *prompted*
/// entry abandons it (§4).
struct WaiterGuard {
    shared: Arc<Shared>,
    pending_id: Uuid,
    waiter_id: u64,
}

impl Drop for WaiterGuard {
    fn drop(&mut self) {
        let mut abandoned: Option<ApprovalRequest> = None;
        let mut snapshot: Option<Vec<ApprovalRequest>> = None;
        {
            let mut inner = self.shared.inner.lock().unwrap();
            if let Some(entry) = inner.pending.get_mut(&self.pending_id) {
                entry.waiters.retain(|(id, _)| *id != self.waiter_id);
                let prompted = matches!(entry.state, PendingState::Prompted { .. });
                if prompted && entry.waiters.is_empty() {
                    // Every waiter has disconnected before a decision:
                    // withdraw the prompt, never execute (§4).
                    let entry = inner.pending.remove(&self.pending_id).unwrap();
                    inner.queue.retain(|id| id != &self.pending_id);
                    if let Some(key) = &entry.key {
                        inner.by_key.remove(key);
                    }
                    release_retention_reservation(&mut inner, entry.retention_reserved);
                    abandoned = Some(entry.request);
                    snapshot = Some(queue_snapshot(&inner));
                }
            }
        }
        if let Some(request) = abandoned {
            self.shared.audit.append(
                AuditEntry::new(
                    AuditKind::Abandoned,
                    format!("Abandoned (agent disconnected): {}", request.agent),
                )
                .agent(request.agent.clone())
                .connection(
                    request
                        .connection
                        .as_ref()
                        .map(|c| c.name.clone())
                        .unwrap_or_default(),
                )
                .detail(request.action.clone())
                .outcome("abandoned")
                .field(
                    "approval_state",
                    crate::wire::ApprovalState::Abandoned.as_str(),
                ),
            );
            self.shared.events.queue_changed(&snapshot.unwrap());
        }
    }
}

fn queue_snapshot(inner: &Inner) -> Vec<ApprovalRequest> {
    inner
        .queue
        .iter()
        .filter_map(|id| inner.pending.get(id).map(|p| p.request.clone()))
        .collect()
}

impl Approvals {
    pub fn new(
        approval_timeout: Duration,
        retention: Duration,
        retention_max_entries: usize,
        retention_max_bytes: usize,
        audit: Arc<AuditLog>,
        events: Arc<dyn BrokerEvents>,
    ) -> Self {
        let shared = Arc::new(Shared {
            approval_timeout,
            retention,
            retention_max_entries,
            retention_max_bytes,
            audit,
            events,
            runtime: tokio::runtime::Handle::current(),
            inner: Mutex::new(Inner::default()),
        });
        if !retention.is_zero() {
            let weak = Arc::downgrade(&shared);
            let runtime = shared.runtime.clone();
            runtime.spawn(async move {
                let mut interval = tokio::time::interval(retention_sweep_interval(retention));
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                // `interval` ticks immediately once; consume that tick so
                // the first sweep happens after a useful delay.
                interval.tick().await;
                loop {
                    interval.tick().await;
                    let Some(shared) = weak.upgrade() else {
                        break;
                    };
                    prune_expired_outcomes(&mut shared.inner.lock().unwrap(), retention);
                }
            });
        }
        Self { shared }
    }

    /// The FIFO queue, oldest first (the approval window renders the front
    /// request and "N more pending").
    pub fn queue(&self) -> Vec<ApprovalRequest> {
        queue_snapshot(&self.shared.inner.lock().unwrap())
    }

    pub fn get(&self, id: &Uuid) -> Option<ApprovalRequest> {
        self.shared
            .inner
            .lock()
            .unwrap()
            .pending
            .get(id)
            .map(|p| p.request.clone())
    }

    /// Join or replay by idempotency key, if possible. Returns:
    /// - `Some(Ok(Parked))`, replayed or attached to an in-flight entry;
    /// - `Some(Err(_))`, key reuse with a different payload or a completed
    ///   key whose replay body is no longer available;
    /// - `None`, nothing under this key; the caller creates a new entry.
    fn try_join(
        &self,
        inner: &mut Inner,
        coalesce_key: &Option<Key>,
        payload_hash: &Option<String>,
    ) -> Option<Result<Parked, ParkError>> {
        prune_expired_outcomes(inner, self.shared.retention);
        let key = coalesce_key.as_ref()?;
        // Late retry after completion: replay the same response (§4).
        if let Some(retained) = inner.outcomes.get(key) {
            if &retained.payload_hash != payload_hash {
                return Some(Err(ParkError::RequestIdMismatch));
            }
            return Some(match &retained.outcome {
                Some(outcome) => Ok(Parked::Replay(outcome.clone())),
                None => Err(ParkError::OutcomeNotReplayable),
            });
        }
        // In-flight (prompted or executing): attach to it.
        if let Some(&pending_id) = inner.by_key.get(key) {
            let waiter_id = next_waiter(inner);
            let entry = inner.pending.get_mut(&pending_id).unwrap();
            if &entry.payload_hash != payload_hash {
                return Some(Err(ParkError::RequestIdMismatch));
            }
            let (tx, rx) = oneshot::channel();
            entry.waiters.push((waiter_id, tx));
            return Some(Ok(Parked::Wait(WaitHandle {
                rx,
                _guard: WaiterGuard {
                    shared: self.shared.clone(),
                    pending_id,
                    waiter_id,
                },
            })));
        }
        None
    }

    /// Reserve a tombstone slot before accepting a keyed execution. This is
    /// the fail-closed boundary: once execution can begin, capacity already
    /// exists to remember that it happened for the full retention TTL.
    fn reserve_retention_slot(
        &self,
        inner: &mut Inner,
        coalesce_key: &Option<Key>,
        retain_outcome: bool,
    ) -> Result<bool, ParkError> {
        if !retain_outcome || coalesce_key.is_none() {
            return Ok(false);
        }
        if self.shared.retention.is_zero()
            || inner
                .outcomes
                .len()
                .saturating_add(inner.retention_reservations)
                >= self.shared.retention_max_entries
        {
            return Err(ParkError::IdempotencyCapacity);
        }
        inner.retention_reservations += 1;
        Ok(true)
    }

    /// Park a request (policy said Prompt), or join / replay by idempotency
    /// key.
    pub fn park(&self, park: ParkRequest) -> Result<Parked, ParkError> {
        let ParkRequest {
            mut request,
            coalesce_key,
            payload_hash,
            retain_outcome,
            executor,
        } = park;
        let raised: Option<(ApprovalRequest, Vec<ApprovalRequest>)>;
        let result = {
            let mut inner = self.shared.inner.lock().unwrap();
            if let Some(joined) = self.try_join(&mut inner, &coalesce_key, &payload_hash) {
                return joined;
            }
            let retention_reserved =
                self.reserve_retention_slot(&mut inner, &coalesce_key, retain_outcome)?;

            // New prompt.
            let id = request.id;
            let now = Utc::now();
            request.received_at = now;
            request.deadline = now
                + chrono::Duration::from_std(self.shared.approval_timeout)
                    .unwrap_or_else(|_| chrono::Duration::seconds(120));
            let waiter_id = next_waiter(&mut inner);
            let (tx, rx) = oneshot::channel();
            inner.pending.insert(
                id,
                Pending {
                    request: request.clone(),
                    state: PendingState::Prompted { executor },
                    key: coalesce_key.clone(),
                    payload_hash,
                    retention_reserved,
                    waiters: vec![(waiter_id, tx)],
                },
            );
            inner.queue.push(id);
            if let Some(key) = coalesce_key {
                inner.by_key.insert(key, id);
            }
            raised = Some((request.clone(), queue_snapshot(&inner)));

            // Hard per-request timeout → auto-deny (§6).
            let shared = self.shared.clone();
            let timeout = self.shared.approval_timeout;
            self.shared.runtime.spawn(async move {
                tokio::time::sleep(timeout).await;
                Approvals { shared }.timeout_fire(id);
            });

            Ok(Parked::Wait(WaitHandle {
                rx,
                _guard: WaiterGuard {
                    shared: self.shared.clone(),
                    pending_id: id,
                    waiter_id,
                },
            }))
        };
        if let Some((request, snapshot)) = raised {
            self.shared.events.prompt_raised(&request);
            self.shared.events.queue_changed(&snapshot);
        }
        result
    }

    /// User approved: run the single execution and fan the outcome out to
    /// every attached waiter. Returns the request, or None if it no longer
    /// exists (already decided, timed out, or abandoned).
    pub(crate) fn approve(
        &self,
        id: &Uuid,
        decision_confirmed: bool,
        authorization: Option<crate::authorization::SecretReadAuthorization>,
    ) -> Option<ApprovalRequest> {
        let (request, snapshot, executor) = {
            let mut inner = self.shared.inner.lock().unwrap();
            let entry = inner.pending.get_mut(id)?;
            if !matches!(entry.state, PendingState::Prompted { .. }) {
                return None; // double-approve race
            }
            // Defensive: abandonment is eager, but never execute with no
            // waiter attached (§4).
            if entry.waiters.is_empty() {
                return None;
            }
            let executor = match std::mem::replace(&mut entry.state, PendingState::Executing) {
                PendingState::Prompted { executor } => executor,
                PendingState::Executing => unreachable!(),
            };
            let request = entry.request.clone();
            inner.queue.retain(|q| q != id);
            (request, queue_snapshot(&inner), executor)
        };
        // Pairing mints an agent token and never reads a user credential. Do
        // not let its confirmation authorize secret reads if that invariant
        // is ever accidentally violated by a future executor.
        let secret_read_confirmed = decision_confirmed && request.kind != ApprovalKind::Pair;
        self.spawn_completion(*id, executor, secret_read_confirmed, authorization);
        self.shared.events.queue_changed(&snapshot);
        Some(request)
    }

    /// Atomically claim the selected prompt and every other queued prompt
    /// covered by the access session it is about to create. Once this
    /// returns `Some`, timeout and waiter-abandonment paths see each claimed
    /// request as executing and cannot withdraw it.
    pub(crate) fn claim_session(
        &self,
        id: &Uuid,
        covers: impl Fn(&ApprovalRequest) -> bool,
    ) -> Option<SessionClaim> {
        let (claim, snapshot) = {
            let mut inner = self.shared.inner.lock().unwrap();
            let selected = inner.pending.get(id)?;
            if !matches!(selected.state, PendingState::Prompted { .. })
                || selected.waiters.is_empty()
            {
                return None;
            }

            let mut claimed_ids = vec![*id];
            claimed_ids.extend(inner.queue.iter().copied().filter(|queued_id| {
                queued_id != id
                    && inner.pending.get(queued_id).is_some_and(|entry| {
                        matches!(entry.state, PendingState::Prompted { .. })
                            && !entry.waiters.is_empty()
                            && covers(&entry.request)
                    })
            }));

            let mut primary = None;
            let mut absorbed = Vec::new();
            let mut executions = Vec::with_capacity(claimed_ids.len());
            for claimed_id in &claimed_ids {
                let entry = inner
                    .pending
                    .get_mut(claimed_id)
                    .expect("queued approval disappeared while locked");
                let executor = match std::mem::replace(&mut entry.state, PendingState::Executing) {
                    PendingState::Prompted { executor } => executor,
                    PendingState::Executing => unreachable!("claim filtered executing entries"),
                };
                let request = entry.request.clone();
                if claimed_id == id {
                    primary = Some(request);
                } else {
                    absorbed.push(request);
                }
                executions.push((*claimed_id, executor));
            }
            inner
                .queue
                .retain(|queued_id| !claimed_ids.contains(queued_id));
            (
                SessionClaim {
                    primary: primary.expect("selected approval was claimed"),
                    absorbed,
                    executions,
                },
                queue_snapshot(&inner),
            )
        };
        self.shared.events.queue_changed(&snapshot);
        Some(claim)
    }

    /// Start every execution claimed by `claim` under the same grant-backed
    /// secret-read authorization.
    pub(crate) fn execute_session(
        &self,
        claim: SessionClaim,
        authorization: crate::authorization::SecretReadAuthorization,
    ) -> (ApprovalRequest, Vec<ApprovalRequest>) {
        for (id, executor) in claim.executions {
            self.spawn_completion(id, executor, true, Some(authorization.clone()));
        }
        (claim.primary, claim.absorbed)
    }

    /// Run a rule-allowed request through the same machinery, no prompt,
    /// straight to Executing, so auto-allowed mutating retries coalesce
    /// and replay exactly like prompted ones (§4).
    pub(crate) fn run_preapproved(
        &self,
        park: ParkRequest,
        authorization: Option<crate::authorization::SecretReadAuthorization>,
    ) -> Result<Parked, ParkError> {
        let ParkRequest {
            mut request,
            coalesce_key,
            payload_hash,
            retain_outcome,
            executor,
        } = park;
        let (handle, id) = {
            let mut inner = self.shared.inner.lock().unwrap();
            if let Some(joined) = self.try_join(&mut inner, &coalesce_key, &payload_hash) {
                return joined;
            }
            let retention_reserved =
                self.reserve_retention_slot(&mut inner, &coalesce_key, retain_outcome)?;
            let id = request.id;
            let now = Utc::now();
            request.received_at = now;
            request.deadline = now;
            let waiter_id = next_waiter(&mut inner);
            let (tx, rx) = oneshot::channel();
            inner.pending.insert(
                id,
                Pending {
                    request,
                    state: PendingState::Executing,
                    key: coalesce_key.clone(),
                    payload_hash,
                    retention_reserved,
                    waiters: vec![(waiter_id, tx)],
                },
            );
            if let Some(key) = coalesce_key {
                inner.by_key.insert(key, id);
            }
            (
                WaitHandle {
                    rx,
                    _guard: WaiterGuard {
                        shared: self.shared.clone(),
                        pending_id: id,
                        waiter_id,
                    },
                },
                id,
            )
        };
        self.spawn_completion(id, executor, false, authorization);
        Ok(Parked::Wait(handle))
    }

    /// The execution task: not tied to any waiter, so a disconnect cannot
    /// cancel a side effect already in flight (§4). On completion the
    /// outcome is fanned out and the reserved idempotency slot becomes a
    /// tombstone, with a replay body when the byte budget permits.
    fn spawn_completion(
        &self,
        id: Uuid,
        executor: Executor,
        secret_read_confirmed: bool,
        authorization: Option<crate::authorization::SecretReadAuthorization>,
    ) {
        let shared = self.shared.clone();
        self.shared.runtime.spawn(async move {
            let outcome = match authorization {
                Some(authorization) => {
                    crate::authorization::scope_authorization(authorization, executor).await
                }
                None => crate::authorization::scope(secret_read_confirmed, executor).await,
            };
            let mut waiters;
            {
                let mut inner = shared.inner.lock().unwrap();
                let Some(entry) = inner.pending.remove(&id) else {
                    return;
                };
                if let Some(key) = &entry.key {
                    inner.by_key.remove(key);
                    if entry.retention_reserved {
                        release_retention_reservation(&mut inner, true);
                        retain_completed_outcome(
                            &mut inner,
                            key.clone(),
                            entry.payload_hash.clone(),
                            outcome.clone(),
                            shared.retention,
                            shared.retention_max_bytes,
                        );
                    }
                }
                waiters = entry.waiters;
            }
            for (_, tx) in waiters.drain(..) {
                let _ = tx.send(outcome.clone());
            }
        });
    }

    /// User denied (or the shell decided for them). Completes every waiter
    /// with `403 {"reason": reason}`; nothing is retained (§4 retains only
    /// executed outcomes, a denial's retry may re-prompt).
    pub fn deny(&self, id: &Uuid, reason: ErrorReason) -> Option<ApprovalRequest> {
        let (request, waiters, snapshot) = {
            let mut inner = self.shared.inner.lock().unwrap();
            // Deny applies to prompted entries only; an executing request
            // can no longer be stopped.
            match inner.pending.get(id) {
                Some(p) if matches!(p.state, PendingState::Prompted { .. }) => {}
                _ => return None,
            }
            let entry = inner.pending.remove(id).unwrap();
            inner.queue.retain(|q| q != id);
            if let Some(key) = &entry.key {
                inner.by_key.remove(key);
            }
            release_retention_reservation(&mut inner, entry.retention_reserved);
            (entry.request, entry.waiters, queue_snapshot(&inner))
        };
        let outcome = ExecOutcome::refusal(reason);
        for (_, tx) in waiters {
            let _ = tx.send(outcome.clone());
        }
        self.shared.events.queue_changed(&snapshot);
        Some(request)
    }

    /// Timeout task body: auto-deny if still prompted (§6).
    fn timeout_fire(&self, id: Uuid) {
        if let Some(request) = self.deny(&id, ErrorReason::ApprovalTimeout) {
            self.shared.audit.append(
                AuditEntry::new(
                    AuditKind::ApprovalTimeout,
                    format!("Auto-denied (approval timeout): {}", request.agent),
                )
                .agent(request.agent.clone())
                .connection(
                    request
                        .connection
                        .as_ref()
                        .map(|c| c.name.clone())
                        .unwrap_or_default(),
                )
                .detail(request.action.clone())
                .outcome("approval_timeout")
                .field(
                    "approval_state",
                    crate::wire::ApprovalState::Expired.as_str(),
                ),
            );
        }
    }
}

fn retention_sweep_interval(retention: Duration) -> Duration {
    // Frequent enough that expiry is prompt even for tests and short-lived
    // configurations, but capped so the default ten-minute retention does
    // not leave stale entries around for another full retention period.
    (retention / 2)
        .max(Duration::from_millis(1))
        .min(Duration::from_secs(30))
}

fn prune_expired_outcomes(inner: &mut Inner, retention: Duration) {
    while let Some(key) = inner.outcome_order.front().cloned() {
        let expired = inner
            .outcomes
            .get(&key)
            .is_none_or(|retained| retained.at.elapsed() > retention);
        if !expired {
            break;
        }
        inner.outcome_order.pop_front();
        if let Some(retained) = inner.outcomes.remove(&key) {
            inner.outcome_bytes = inner.outcome_bytes.saturating_sub(retained.serialized_len);
        }
        inner.replay_order.retain(|queued| queued != &key);
    }
}

fn evict_oldest_replay_body(inner: &mut Inner) -> bool {
    while let Some(key) = inner.replay_order.pop_front() {
        if let Some(retained) = inner.outcomes.get_mut(&key) {
            if retained.outcome.take().is_none() {
                continue;
            }
            inner.outcome_bytes = inner.outcome_bytes.saturating_sub(retained.serialized_len);
            retained.serialized_len = 0;
            return true;
        }
    }
    false
}

fn retain_completed_outcome(
    inner: &mut Inner,
    key: Key,
    payload_hash: Option<String>,
    outcome: ExecOutcome,
    retention: Duration,
    max_bytes: usize,
) {
    if retention.is_zero() {
        return;
    }
    debug_assert!(!inner.outcomes.contains_key(&key));

    let serialized_len = serialized_outcome_len(&outcome).filter(|len| *len <= max_bytes);
    let (outcome, serialized_len) = if let Some(serialized_len) = serialized_len {
        while serialized_len > max_bytes.saturating_sub(inner.outcome_bytes) {
            if !evict_oldest_replay_body(inner) {
                break;
            }
        }
        if serialized_len <= max_bytes.saturating_sub(inner.outcome_bytes) {
            inner.outcome_bytes += serialized_len;
            inner.replay_order.push_back(key.clone());
            (Some(outcome), serialized_len)
        } else {
            (None, 0)
        }
    } else {
        (None, 0)
    };

    inner.outcome_order.push_back(key.clone());
    inner.outcomes.insert(
        key,
        Retained {
            at: Instant::now(),
            payload_hash,
            outcome,
            serialized_len,
        },
    );
}

fn release_retention_reservation(inner: &mut Inner, reserved: bool) {
    if reserved {
        debug_assert!(inner.retention_reservations > 0);
        inner.retention_reservations = inner.retention_reservations.saturating_sub(1);
    }
}

fn serialized_outcome_len(outcome: &ExecOutcome) -> Option<usize> {
    #[derive(Default)]
    struct Counter(usize);

    impl Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self.0.saturating_add(bytes.len());
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let mut counter = Counter::default();
    serde_json::to_writer(&mut counter, outcome).ok()?;
    Some(counter.0)
}

fn next_waiter(inner: &mut Inner) -> u64 {
    inner.waiter_seq += 1;
    inner.waiter_seq
}

/* --------------------------------- tests --------------------------------- */

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::NoopEvents;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn approvals(timeout: Duration) -> (Approvals, tempfile::TempDir) {
        approvals_with_limits(timeout, Duration::from_secs(600), 1024, 64 * 1024 * 1024)
    }

    fn approvals_with_limits(
        timeout: Duration,
        retention: Duration,
        max_entries: usize,
        max_bytes: usize,
    ) -> (Approvals, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let audit = Arc::new(AuditLog::open(dir.path().join("audit.jsonl")).unwrap());
        (
            Approvals::new(
                timeout,
                retention,
                max_entries,
                max_bytes,
                audit,
                Arc::new(NoopEvents),
            ),
            dir,
        )
    }

    fn request(agent: &str, action: &str) -> ApprovalRequest {
        let now = Utc::now();
        ApprovalRequest {
            id: Uuid::new_v4(),
            agent: agent.into(),
            client_id: Some(Uuid::new_v4()),
            agent_token_hash: None,
            kind: ApprovalKind::Http,
            connection: Some(ConnectionSummary {
                id: Uuid::new_v4(),
                name: "github".into(),
                kind: ConnectionKind::Api,
                target: "api.github.com".into(),
                connection_updated_at: now,
            }),
            action: action.into(),
            notification: format!("{agent} wants to use GitHub: {action}"),
            received_at: now,
            deadline: now,
            identity: None,
            pairing_identity: None,
            replaces_existing_agent: false,
            inherited: vec![],
            http: None,
        }
    }

    fn ok_executor(counter: Arc<AtomicUsize>) -> Executor {
        Box::pin(async move {
            counter.fetch_add(1, Ordering::SeqCst);
            ExecOutcome {
                status: 200,
                body: serde_json::json!({"ok": true}),
            }
        })
    }

    fn outcome_executor(outcome: ExecOutcome) -> Executor {
        Box::pin(async move { outcome })
    }

    async fn complete_retained(approvals: &Approvals, key: Key, outcome: ExecOutcome) {
        let req = request("claude-code", "POST /dispatch");
        let id = req.id;
        let parked = approvals
            .park(ParkRequest {
                request: req,
                coalesce_key: Some(key),
                payload_hash: Some("payload".into()),
                retain_outcome: true,
                executor: outcome_executor(outcome),
            })
            .unwrap();
        approvals.approve(&id, false, None).unwrap();
        let Parked::Wait(handle) = parked else {
            panic!("new request unexpectedly replayed")
        };
        assert!(handle.wait().await.is_some());
    }

    #[test]
    fn pairing_identity_summary_separates_program_and_verification() {
        let signed = PairingIdentitySummary::from_identity(&PeerIdentity::Signed {
            signing_id: "com.example.agent".into(),
            team_id: Some("TEAM123".into()),
        });
        assert_eq!(signed.program, "com.example.agent");
        assert_eq!(signed.verification, "Signed application");
        assert!(signed.warning.is_none());

        let unsigned = PairingIdentitySummary::from_identity(&PeerIdentity::Unsigned {
            uid: Some(501),
            executable_path: Some("/usr/local/bin/node".into()),
            file_id: None,
            executable_sha256: Some("a".repeat(64)),
        });
        assert_eq!(unsigned.program, "node");
        assert_eq!(unsigned.verification, "Local executable");
        assert!(unsigned.warning.is_some());
    }

    #[tokio::test]
    async fn approve_runs_executor_once_and_resolves_waiter() {
        let (approvals, _dir) = approvals(Duration::from_secs(60));
        let count = Arc::new(AtomicUsize::new(0));
        let req = request("claude-code", "GET api.github.com/user/repos");
        let id = req.id;
        let parked = approvals
            .park(ParkRequest {
                request: req,
                coalesce_key: None,
                payload_hash: None,
                retain_outcome: true,
                executor: ok_executor(count.clone()),
            })
            .unwrap();
        assert_eq!(approvals.queue().len(), 1);
        approvals.approve(&id, false, None).expect("pending");
        let Parked::Wait(handle) = parked else {
            panic!()
        };
        let outcome = handle.wait().await.unwrap();
        assert_eq!(outcome.status, 200);
        assert_eq!(count.load(Ordering::SeqCst), 1);
        assert!(approvals.queue().is_empty());
    }

    #[tokio::test]
    async fn session_claim_absorbs_covered_prompts_atomically() {
        let (approvals, _dir) = approvals(Duration::from_secs(60));
        let counter = Arc::new(AtomicUsize::new(0));
        let mut covered_a = request("codex", "covered-a");
        covered_a.agent_token_hash = Some("token-a".into());
        let selected_id = covered_a.id;
        let mut covered_b = request("codex", "covered-b");
        covered_b.agent_token_hash = Some("token-a".into());
        let covered_b_id = covered_b.id;
        let uncovered = request("other", "uncovered");

        let Parked::Wait(first) = approvals
            .park(ParkRequest {
                request: covered_a,
                coalesce_key: None,
                payload_hash: None,
                retain_outcome: true,
                executor: ok_executor(counter.clone()),
            })
            .unwrap()
        else {
            panic!()
        };
        let Parked::Wait(second) = approvals
            .park(ParkRequest {
                request: covered_b,
                coalesce_key: None,
                payload_hash: None,
                retain_outcome: true,
                executor: ok_executor(counter.clone()),
            })
            .unwrap()
        else {
            panic!()
        };
        let _uncovered = approvals
            .park(ParkRequest {
                request: uncovered,
                coalesce_key: None,
                payload_hash: None,
                retain_outcome: true,
                executor: ok_executor(counter.clone()),
            })
            .unwrap();

        let claim = approvals
            .claim_session(&selected_id, |queued| queued.action.starts_with("covered"))
            .expect("selected prompt should be claimable");
        assert!(approvals.get(&covered_b_id).is_some());
        assert_eq!(approvals.queue().len(), 1);
        assert!(approvals.claim_session(&covered_b_id, |_| true).is_none());

        let authorization = crate::authorization::SecretReadAuthorization::for_grant(
            Uuid::new_v4(),
            Instant::now() + Duration::from_secs(60),
        );
        let (primary, absorbed) = approvals.execute_session(claim, authorization);
        assert_eq!(primary.id, selected_id);
        assert_eq!(absorbed.len(), 1);
        assert_eq!(first.wait().await.unwrap().status, 200);
        assert_eq!(second.wait().await.unwrap().status, 200);
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn deny_resolves_with_reason_and_never_executes() {
        let (approvals, _dir) = approvals(Duration::from_secs(60));
        let count = Arc::new(AtomicUsize::new(0));
        let req = request("claude-code", "GET /x");
        let id = req.id;
        let parked = approvals
            .park(ParkRequest {
                request: req,
                coalesce_key: None,
                payload_hash: None,
                retain_outcome: true,
                executor: ok_executor(count.clone()),
            })
            .unwrap();
        approvals.deny(&id, ErrorReason::DeniedByUser).unwrap();
        let Parked::Wait(handle) = parked else {
            panic!()
        };
        let outcome = handle.wait().await.unwrap();
        assert_eq!(outcome.status, 403);
        assert_eq!(outcome.body["reason"], "denied_by_user");
        assert_eq!(count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn coalesced_retry_joins_and_gets_one_execution() {
        let (approvals, _dir) = approvals(Duration::from_secs(60));
        let count = Arc::new(AtomicUsize::new(0));
        let key = ("claude-code".to_string(), "req_1".to_string());
        let hash = Some("h1".to_string());

        let first = request("claude-code", "POST /dispatch");
        let id = first.id;
        let p1 = approvals
            .park(ParkRequest {
                request: first,
                coalesce_key: Some(key.clone()),
                payload_hash: hash.clone(),
                retain_outcome: true,
                executor: ok_executor(count.clone()),
            })
            .unwrap();
        // Retry with the same key joins, no second queue entry.
        let p2 = approvals
            .park(ParkRequest {
                request: request("claude-code", "POST /dispatch"),
                coalesce_key: Some(key.clone()),
                payload_hash: hash.clone(),
                retain_outcome: true,
                executor: ok_executor(count.clone()),
            })
            .unwrap();
        assert_eq!(approvals.queue().len(), 1);
        // Mismatched payload under the same key → 409.
        assert!(matches!(
            approvals.park(ParkRequest {
                request: request("claude-code", "POST /dispatch"),
                coalesce_key: Some(key.clone()),
                payload_hash: Some("different".into()),
                retain_outcome: true,
                executor: ok_executor(count.clone()),
            }),
            Err(ParkError::RequestIdMismatch)
        ));

        approvals.approve(&id, false, None).unwrap();
        let (Parked::Wait(h1), Parked::Wait(h2)) = (p1, p2) else {
            panic!()
        };
        let (o1, o2) = tokio::join!(h1.wait(), h2.wait());
        assert_eq!(o1.unwrap().status, 200);
        assert_eq!(o2.unwrap().status, 200);
        assert_eq!(count.load(Ordering::SeqCst), 1, "exactly one execution");

        // A late retry replays the retained outcome without a new prompt.
        let replay = approvals
            .park(ParkRequest {
                request: request("claude-code", "POST /dispatch"),
                coalesce_key: Some(key.clone()),
                payload_hash: hash,
                retain_outcome: true,
                executor: ok_executor(count.clone()),
            })
            .unwrap();
        match replay {
            Parked::Replay(outcome) => assert_eq!(outcome.status, 200),
            _ => panic!("expected replay"),
        }
        assert_eq!(count.load(Ordering::SeqCst), 1);
        assert!(approvals.queue().is_empty());
    }

    #[tokio::test]
    async fn retention_capacity_rejects_before_prompt_or_preapproved_execution() {
        let (approvals, _dir) = approvals_with_limits(
            Duration::from_secs(60),
            Duration::from_secs(600),
            1,
            usize::MAX,
        );
        let executions = Arc::new(AtomicUsize::new(0));
        let first = request("claude-code", "POST /first");
        let parked = approvals
            .park(ParkRequest {
                request: first,
                coalesce_key: Some(("claude-code".into(), "req_first".into())),
                payload_hash: Some("payload".into()),
                retain_outcome: true,
                executor: ok_executor(executions.clone()),
            })
            .unwrap();

        let prompted_rejection = approvals.park(ParkRequest {
            request: request("claude-code", "POST /second"),
            coalesce_key: Some(("claude-code".into(), "req_second".into())),
            payload_hash: Some("payload".into()),
            retain_outcome: true,
            executor: ok_executor(executions.clone()),
        });
        assert!(matches!(
            prompted_rejection,
            Err(ParkError::IdempotencyCapacity)
        ));
        assert_eq!(approvals.queue().len(), 1, "no second prompt was raised");
        assert_eq!(executions.load(Ordering::SeqCst), 0);

        // Abandoning before execution releases the reservation.
        drop(parked);
        assert_eq!(
            approvals
                .shared
                .inner
                .lock()
                .unwrap()
                .retention_reservations,
            0
        );
        complete_retained(
            &approvals,
            ("claude-code".into(), "req_completed".into()),
            ExecOutcome {
                status: 200,
                body: serde_json::json!({"ok": true}),
            },
        )
        .await;

        let preapproved_rejection = approvals.run_preapproved(
            ParkRequest {
                request: request("claude-code", "POST /preapproved"),
                coalesce_key: Some(("claude-code".into(), "req_preapproved".into())),
                payload_hash: Some("payload".into()),
                retain_outcome: true,
                executor: ok_executor(executions.clone()),
            },
            None,
        );
        assert!(matches!(
            preapproved_rejection,
            Err(ParkError::IdempotencyCapacity)
        ));
        tokio::task::yield_now().await;
        assert_eq!(executions.load(Ordering::SeqCst), 0);
        let inner = approvals.shared.inner.lock().unwrap();
        assert_eq!(inner.outcomes.len(), 1);
        assert_eq!(inner.retention_reservations, 0);
    }

    #[tokio::test]
    async fn zero_retention_rejects_keyed_requests_before_execution() {
        let (approvals, _dir) =
            approvals_with_limits(Duration::from_secs(60), Duration::ZERO, 10, usize::MAX);
        let executions = Arc::new(AtomicUsize::new(0));

        let prompted = approvals.park(ParkRequest {
            request: request("claude-code", "POST /prompted"),
            coalesce_key: Some(("claude-code".into(), "req_prompted".into())),
            payload_hash: Some("payload".into()),
            retain_outcome: true,
            executor: ok_executor(executions.clone()),
        });
        assert!(matches!(prompted, Err(ParkError::IdempotencyCapacity)));
        assert!(approvals.queue().is_empty());

        let preapproved = approvals.run_preapproved(
            ParkRequest {
                request: request("claude-code", "POST /preapproved"),
                coalesce_key: Some(("claude-code".into(), "req_preapproved".into())),
                payload_hash: Some("payload".into()),
                retain_outcome: true,
                executor: ok_executor(executions.clone()),
            },
            None,
        );
        assert!(matches!(preapproved, Err(ParkError::IdempotencyCapacity)));
        tokio::task::yield_now().await;
        assert_eq!(executions.load(Ordering::SeqCst), 0);
        let inner = approvals.shared.inner.lock().unwrap();
        assert!(inner.outcomes.is_empty());
        assert_eq!(inner.retention_reservations, 0);
    }

    #[tokio::test]
    async fn retained_outcomes_obey_byte_bound_and_skip_oversized_results() {
        let first = ExecOutcome {
            status: 200,
            body: serde_json::json!({"result": "first"}),
        };
        let second = ExecOutcome {
            status: 200,
            body: serde_json::json!({"result": "second"}),
        };
        let byte_cap =
            serialized_outcome_len(&first).unwrap() + serialized_outcome_len(&second).unwrap() - 1;
        let (approvals, _dir) = approvals_with_limits(
            Duration::from_secs(60),
            Duration::from_secs(600),
            10,
            byte_cap,
        );
        let first_key = ("claude-code".into(), "req_first".into());
        let second_key = ("claude-code".into(), "req_second".into());
        let oversized_key = ("claude-code".into(), "req_oversized".into());

        complete_retained(&approvals, first_key.clone(), first).await;
        complete_retained(&approvals, second_key.clone(), second).await;
        {
            let inner = approvals.shared.inner.lock().unwrap();
            assert!(
                inner.outcomes[&first_key].outcome.is_none(),
                "oldest replay body was evicted but its tombstone remains"
            );
            assert!(inner.outcomes[&second_key].outcome.is_some());
            assert!(inner.outcome_bytes <= byte_cap);
        }

        let retry_count = Arc::new(AtomicUsize::new(0));
        let evicted_retry = approvals.park(ParkRequest {
            request: request("claude-code", "POST /dispatch"),
            coalesce_key: Some(first_key.clone()),
            payload_hash: Some("payload".into()),
            retain_outcome: true,
            executor: ok_executor(retry_count.clone()),
        });
        assert!(matches!(
            evicted_retry,
            Err(ParkError::OutcomeNotReplayable)
        ));
        let mismatched_retry = approvals.park(ParkRequest {
            request: request("claude-code", "POST /dispatch"),
            coalesce_key: Some(first_key.clone()),
            payload_hash: Some("different".into()),
            retain_outcome: true,
            executor: ok_executor(retry_count.clone()),
        });
        assert!(matches!(
            mismatched_retry,
            Err(ParkError::RequestIdMismatch)
        ));

        complete_retained(
            &approvals,
            oversized_key.clone(),
            ExecOutcome {
                status: 200,
                body: serde_json::json!({"result": "x".repeat(byte_cap)}),
            },
        )
        .await;
        {
            let inner = approvals.shared.inner.lock().unwrap();
            assert!(
                inner.outcomes[&second_key].outcome.is_some(),
                "an oversized result must not evict existing replay bodies"
            );
            assert!(inner.outcomes[&oversized_key].outcome.is_none());
            assert!(inner.outcome_bytes <= byte_cap);
        }
        let oversized_retry = approvals.run_preapproved(
            ParkRequest {
                request: request("claude-code", "POST /dispatch"),
                coalesce_key: Some(oversized_key),
                payload_hash: Some("payload".into()),
                retain_outcome: true,
                executor: ok_executor(retry_count.clone()),
            },
            None,
        );
        assert!(matches!(
            oversized_retry,
            Err(ParkError::OutcomeNotReplayable)
        ));
        tokio::task::yield_now().await;
        assert_eq!(retry_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn retained_outcomes_expire_without_a_later_request() {
        let retention = Duration::from_millis(40);
        let (approvals, _dir) =
            approvals_with_limits(Duration::from_secs(60), retention, 10, usize::MAX);
        complete_retained(
            &approvals,
            ("claude-code".into(), "req_expiring".into()),
            ExecOutcome {
                status: 200,
                body: serde_json::json!({"ok": true}),
            },
        )
        .await;
        assert_eq!(approvals.shared.inner.lock().unwrap().outcomes.len(), 1);

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if approvals.shared.inner.lock().unwrap().outcomes.is_empty() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("background expiry did not remove retained outcome");

        let inner = approvals.shared.inner.lock().unwrap();
        assert_eq!(inner.outcome_bytes, 0);
        assert!(inner.outcome_order.is_empty());
        assert!(inner.replay_order.is_empty());
    }

    #[tokio::test]
    async fn unretained_outcome_is_never_replayed() {
        let (approvals, _dir) = approvals(Duration::from_secs(60));
        let count = Arc::new(AtomicUsize::new(0));
        let key = ("pair\u{0}claude-code".to_string(), String::new());

        let first = request("claude-code", "pair");
        let id = first.id;
        let p1 = approvals
            .park(ParkRequest {
                request: first,
                coalesce_key: Some(key.clone()),
                payload_hash: Some("identity".into()),
                retain_outcome: false,
                executor: ok_executor(count.clone()),
            })
            .unwrap();
        // In-flight coalescing still works without retention.
        let p2 = approvals
            .park(ParkRequest {
                request: request("claude-code", "pair"),
                coalesce_key: Some(key.clone()),
                payload_hash: Some("identity".into()),
                retain_outcome: false,
                executor: ok_executor(count.clone()),
            })
            .unwrap();
        assert_eq!(approvals.queue().len(), 1);
        approvals.approve(&id, false, None).unwrap();
        let (Parked::Wait(h1), Parked::Wait(h2)) = (p1, p2) else {
            panic!()
        };
        let (o1, o2) = tokio::join!(h1.wait(), h2.wait());
        assert_eq!(o1.unwrap().status, 200);
        assert_eq!(o2.unwrap().status, 200);
        assert_eq!(count.load(Ordering::SeqCst), 1, "exactly one execution");

        // A later request under the same key must NOT get the old outcome:
        // it parks a fresh prompt of its own.
        let late = approvals
            .park(ParkRequest {
                request: request("claude-code", "pair"),
                coalesce_key: Some(key),
                payload_hash: Some("identity".into()),
                retain_outcome: false,
                executor: ok_executor(count.clone()),
            })
            .unwrap();
        assert!(
            matches!(late, Parked::Wait(_)),
            "no replay after completion"
        );
        assert_eq!(approvals.queue().len(), 1, "a fresh prompt was raised");
    }

    #[tokio::test]
    async fn timeout_auto_denies() {
        let (approvals, _dir) = approvals(Duration::from_millis(50));
        let count = Arc::new(AtomicUsize::new(0));
        let parked = approvals
            .park(ParkRequest {
                request: request("claude-code", "GET /x"),
                coalesce_key: None,
                payload_hash: None,
                retain_outcome: true,
                executor: ok_executor(count.clone()),
            })
            .unwrap();
        let Parked::Wait(handle) = parked else {
            panic!()
        };
        let outcome = handle.wait().await.unwrap();
        assert_eq!(outcome.status, 403);
        assert_eq!(outcome.body["reason"], "approval_timeout");
        assert_eq!(count.load(Ordering::SeqCst), 0);
        assert!(approvals.queue().is_empty());
    }

    #[tokio::test]
    async fn dropping_all_waiters_abandons_without_execution() {
        let (approvals, _dir) = approvals(Duration::from_secs(60));
        let count = Arc::new(AtomicUsize::new(0));
        let req = request("claude-code", "GET /x");
        let id = req.id;
        let parked = approvals
            .park(ParkRequest {
                request: req,
                coalesce_key: None,
                payload_hash: None,
                retain_outcome: true,
                executor: ok_executor(count.clone()),
            })
            .unwrap();
        assert_eq!(approvals.queue().len(), 1);
        drop(parked); // agent disconnected
        assert!(approvals.queue().is_empty(), "prompt withdrawn");
        // Approving after abandonment is a no-op, never executed.
        assert!(approvals.approve(&id, false, None).is_none());
        assert_eq!(count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn disconnect_after_execution_starts_retains_outcome() {
        let (approvals, _dir) = approvals(Duration::from_secs(60));
        let count = Arc::new(AtomicUsize::new(0));
        let key = ("claude-code".to_string(), "req_2".to_string());
        let req = request("claude-code", "POST /dispatch");
        let id = req.id;
        let c = count.clone();
        let (gate_tx, gate_rx) = oneshot::channel::<()>();
        let parked = approvals
            .park(ParkRequest {
                request: req,
                coalesce_key: Some(key.clone()),
                payload_hash: Some("h".into()),
                retain_outcome: true,
                executor: Box::pin(async move {
                    gate_rx.await.ok();
                    c.fetch_add(1, Ordering::SeqCst);
                    ExecOutcome {
                        status: 204,
                        body: serde_json::Value::Null,
                    }
                }),
            })
            .unwrap();
        approvals.approve(&id, false, None).unwrap();
        // Waiter disconnects mid-execution; the side effect still completes.
        drop(parked);
        gate_tx.send(()).unwrap();
        // Wait for the execution task to finish.
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if count.load(Ordering::SeqCst) == 1 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        // A retry with the same request_id replays the retained outcome.
        let replay = approvals
            .park(ParkRequest {
                request: request("claude-code", "POST /dispatch"),
                coalesce_key: Some(key),
                payload_hash: Some("h".into()),
                retain_outcome: true,
                executor: ok_executor(count.clone()),
            })
            .unwrap();
        match replay {
            Parked::Replay(outcome) => assert_eq!(outcome.status, 204),
            _ => panic!("expected replay"),
        }
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn queue_is_fifo() {
        let (approvals, _dir) = approvals(Duration::from_secs(60));
        let mut handles = Vec::new();
        for i in 0..3 {
            let parked = approvals
                .park(ParkRequest {
                    request: request("claude-code", &format!("GET /{i}")),
                    coalesce_key: None,
                    payload_hash: None,
                    retain_outcome: true,
                    executor: ok_executor(Arc::new(AtomicUsize::new(0))),
                })
                .unwrap();
            handles.push(parked);
        }
        let queue = approvals.queue();
        assert_eq!(queue.len(), 3);
        assert_eq!(queue[0].action, "GET /0");
        assert_eq!(queue[2].action, "GET /2");
    }
}
