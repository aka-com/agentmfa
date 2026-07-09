//! The approval queue (DESIGN.md §4, §6).
//!
//! Approval waits are **held-open requests**: a `Prompt` decision parks the
//! request and the daemon simply does not respond until the user decides or
//! the timeout (default 120 s) auto-denies. No polling, no callback channel.
//!
//! Retries are governed by an **idempotency key**: mutating calls carry an
//! optional `request_id`, and a retry re-sending the same `(agent,
//! request_id)` joins the existing prompt, one approval, exactly one
//! upstream execution, the same response replayed to every waiter and to
//! late retries for 10 minutes. Equality under the key is checked, not
//! assumed: each key stores a hash of the full normalized request, and
//! reusing a `request_id` with a different payload is rejected (409).
//!
//! A parked request whose every waiter has disconnected is **abandoned**,
//! dropped from the queue, its prompt withdrawn, audited, and **never
//! executed upstream**. Disconnection is detected eagerly: each waiter
//! holds a guard whose drop (the handler future being dropped when the
//! agent's connection closes) deregisters it. A disconnect *after* the
//! upstream call has begun does not cancel it; the outcome is retained and
//! replayed to a retry presenting the same `request_id`.
//!
//! The canonical lifecycle this machinery implements is
//! [`crate::wire::ApprovalState`] (pending → executing → executed, or
//! pending → denied/expired/abandoned); terminal transitions record their
//! state in the audit log's `approval_state` field.

use std::collections::HashMap;
use std::future::Future;
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
use crate::types::ConnectionKind;
use crate::wire::ErrorReason;

/* ------------------------------ view types ------------------------------- */

/// What one queued approval looks like to the UI (the approval window).
#[derive(Debug, Clone, Serialize)]
pub struct ApprovalRequest {
    pub id: Uuid,
    pub agent: String,
    /// Pair-token generation that originated a capability request. This is
    /// internal grant state and is never serialized to an approval surface.
    #[serde(skip)]
    #[doc(hidden)]
    pub agent_token_hash: Option<String>,
    pub kind: ApprovalKind,
    /// None for pairing requests.
    pub connection: Option<ConnectionSummary>,
    /// Display line: "GET api.github.com/user/repos",
    /// "Open Postgres session → app@db…".
    pub action: String,
    /// Doorbell body: "claude-code wants to use github, GET /user/repos".
    pub notification: String,
    pub received_at: DateTime<Utc>,
    /// Auto-deny deadline; the UI renders the countdown.
    pub deadline: DateTime<Utc>,
    /// Pairing only: the peer's verified identity display string (§6/§8).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<String>,
    /// Pairing only: connections the name's standing rules would grant the
    /// connecting process promptless access to, the loud disclosure (§6).
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub inherited: Vec<ConnectionSummary>,
    /// HTTP only: the request-payload view (§6).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http: Option<HttpPayloadView>,
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
    pub multi_connect: bool,
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
    /// Approvals that complete only behind the native OS confirmation:
    /// pairing, and mutating HTTP requests (§6/§8). ("Always allow…" is
    /// gated regardless of kind, the shell enforces that.)
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
    retain: bool,
    waiters: Vec<(u64, oneshot::Sender<ExecOutcome>)>,
}

struct Retained {
    at: Instant,
    payload_hash: Option<String>,
    outcome: ExecOutcome,
}

#[derive(Default)]
struct Inner {
    queue: Vec<Uuid>,
    pending: HashMap<Uuid, Pending>,
    by_key: HashMap<Key, Uuid>,
    outcomes: HashMap<Key, Retained>,
    waiter_seq: u64,
}

struct Shared {
    approval_timeout: Duration,
    retention: Duration,
    audit: Arc<AuditLog>,
    events: Arc<dyn BrokerEvents>,
    runtime: tokio::runtime::Handle,
    inner: Mutex<Inner>,
}

pub struct Approvals {
    shared: Arc<Shared>,
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
        audit: Arc<AuditLog>,
        events: Arc<dyn BrokerEvents>,
    ) -> Self {
        Self {
            shared: Arc::new(Shared {
                approval_timeout,
                retention,
                audit,
                events,
                runtime: tokio::runtime::Handle::current(),
                inner: Mutex::new(Inner::default()),
            }),
        }
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
    /// - `Some(Err(_))`, key reuse with a different payload;
    /// - `None`, nothing under this key; the caller creates a new entry.
    fn try_join(
        &self,
        inner: &mut Inner,
        coalesce_key: &Option<Key>,
        payload_hash: &Option<String>,
    ) -> Option<Result<Parked, ParkError>> {
        let retention = self.shared.retention;
        inner.outcomes.retain(|_, r| r.at.elapsed() <= retention);
        let key = coalesce_key.as_ref()?;
        // Late retry after completion: replay the same response (§4).
        if let Some(retained) = inner.outcomes.get(key) {
            if &retained.payload_hash != payload_hash {
                return Some(Err(ParkError::RequestIdMismatch));
            }
            return Some(Ok(Parked::Replay(retained.outcome.clone())));
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
                    retain: retain_outcome,
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
                    retain: retain_outcome,
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
    /// outcome is fanned out and retained under the idempotency key.
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
                    if entry.retain {
                        inner.outcomes.insert(
                            key.clone(),
                            Retained {
                                at: Instant::now(),
                                payload_hash: entry.payload_hash.clone(),
                                outcome: outcome.clone(),
                            },
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
        let dir = tempfile::tempdir().unwrap();
        let audit = Arc::new(AuditLog::open(dir.path().join("audit.jsonl")).unwrap());
        (
            Approvals::new(
                timeout,
                Duration::from_secs(600),
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
            agent_token_hash: None,
            kind: ApprovalKind::Http,
            connection: Some(ConnectionSummary {
                id: Uuid::new_v4(),
                name: "github".into(),
                kind: ConnectionKind::Api,
                target: "api.github.com".into(),
                multi_connect: false,
            }),
            action: action.into(),
            notification: format!("{agent} wants to use GitHub: {action}"),
            received_at: now,
            deadline: now,
            identity: None,
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
