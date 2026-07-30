//! Capability execution with idempotency.
//!
//! There is no approval step: an authorized (wired) call executes
//! immediately. What this module adds is retry safety, governed by an
//! idempotency key. Mutating calls carry an optional `request_id`, and a
//! retry re-sending the same `(identity, connection, request_id)` joins the
//! in-flight execution — exactly one upstream execution, the same response
//! fanned out to every waiter and replayed to late retries while its
//! byte-bounded replay body remains cached. Every completed key keeps a
//! compact tombstone for the retention window, except pre-execution refusals
//! (confirmation timeout/unavailability, policy) that never reached an
//! upstream and are therefore safe to retry.
//! Equality under the key is checked, not assumed: each key stores a hash of
//! the full normalized request (client label included), and reusing a
//! `request_id` with a different payload — or under a different label — is
//! rejected (409), never replayed across labels.
//!
//! A disconnect never cancels an execution already in flight; completion
//! normally leaves an idempotency tombstone and retains the outcome for
//! replay when it fits.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::io::Write;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::Serialize;
use tokio::sync::oneshot;
use uuid::Uuid;

use crate::wire::ErrorReason;

/* ------------------------------ outcomes --------------------------------- */

/// What an execution resolves to on the wire: a status plus a JSON body.
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

/// The single upstream execution, run exactly once per accepted request.
pub type Executor = Pin<Box<dyn Future<Output = ExecOutcome> + Send + 'static>>;

/* ------------------------------ internals -------------------------------- */

/// Idempotency namespace: authenticated client identity, target connection,
/// and the caller's request id. A self-reported display label is deliberately
/// absent; changing it cannot split an identity's namespace. The label rides
/// in the payload hash instead, so one label reusing another's request id is
/// refused with a mismatch rather than handed the other's cached outcome.
pub type CoalesceKey = (Uuid, Uuid, String);
type Key = CoalesceKey;

struct Pending {
    key: Option<Key>,
    payload_hash: Option<String>,
    /// A slot reserved before this keyed execution was accepted. On
    /// completion it becomes a tombstone.
    retention_reserved: bool,
    waiters: Vec<(u64, oneshot::Sender<ExecOutcome>)>,
    /// Fired when the last waiter deregisters. Only unkeyed executions set
    /// this: with no idempotency key, no retry can ever reattach or replay,
    /// so a still-parked execution may stop waiting for a caller that no
    /// longer exists. A keyed execution keeps running for the retry.
    abandon: Option<tokio::sync::watch::Sender<bool>>,
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
    retention: Duration,
    retention_max_entries: usize,
    retention_max_bytes: usize,
    runtime: tokio::runtime::Handle,
    inner: Mutex<Inner>,
}

pub struct Executions {
    shared: Arc<Shared>,
}

/* ------------------------------ public API ------------------------------- */

/// What `run` needs from a capability handler.
pub struct ExecRequest {
    /// `(authenticated client id, connection id, request_id)` for mutating
    /// calls that sent a `request_id`; never set for GET/HEAD.
    pub coalesce_key: Option<CoalesceKey>,
    /// Hash of the full normalized request; required with `coalesce_key`.
    pub payload_hash: Option<String>,
    /// The one upstream execution.
    pub executor: Executor,
    /// Set `true` when the last waiter deregisters from an *unkeyed*
    /// execution (ignored when `coalesce_key` is set — a keyed retry can
    /// reattach). The executor holds the matching receiver and may use it
    /// to stop pre-execution waits, such as a parked confirmation, whose
    /// answer nobody can ever observe.
    pub abandon: Option<tokio::sync::watch::Sender<bool>>,
}

pub enum Execution {
    /// Wait on the (possibly joined) execution.
    Wait(WaitHandle),
    /// A completed outcome for this `request_id` was replayed.
    Replay(ExecOutcome),
}

#[derive(Debug, thiserror::Error)]
pub enum ExecError {
    /// `request_id` reused with a different payload, a client bug.
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
    /// Resolve when the execution completes. `None` only if the broker is
    /// shutting down.
    pub async fn wait(self) -> Option<ExecOutcome> {
        self.rx.await.ok()
    }
}

/// Deregisters its waiter on drop. The execution itself is never cancelled:
/// a side effect already in flight completes, is retained, and can be
/// replayed to a retry.
struct WaiterGuard {
    shared: Arc<Shared>,
    pending_id: Uuid,
    waiter_id: u64,
}

impl Drop for WaiterGuard {
    fn drop(&mut self) {
        let mut inner = self.shared.inner.lock().unwrap();
        if let Some(entry) = inner.pending.get_mut(&self.pending_id) {
            entry.waiters.retain(|(id, _)| *id != self.waiter_id);
            if entry.waiters.is_empty() {
                if let Some(abandon) = &entry.abandon {
                    let _ = abandon.send(true);
                }
            }
        }
    }
}

impl Executions {
    pub fn new(
        retention: Duration,
        retention_max_entries: usize,
        retention_max_bytes: usize,
    ) -> Self {
        let shared = Arc::new(Shared {
            retention,
            retention_max_entries,
            retention_max_bytes,
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

    /// Join or replay by idempotency key, if possible. Returns:
    /// - `Some(Ok(Execution))`, replayed or attached to an in-flight entry;
    /// - `Some(Err(_))`, key reuse with a different payload or a completed
    ///   key whose replay body is no longer available;
    /// - `None`, nothing under this key; the caller starts a new execution.
    fn try_join(
        &self,
        inner: &mut Inner,
        coalesce_key: &Option<Key>,
        payload_hash: &Option<String>,
    ) -> Option<Result<Execution, ExecError>> {
        prune_expired_outcomes(inner, self.shared.retention);
        let key = coalesce_key.as_ref()?;
        // Late retry after completion: replay the same response.
        if let Some(retained) = inner.outcomes.get(key) {
            if &retained.payload_hash != payload_hash {
                return Some(Err(ExecError::RequestIdMismatch));
            }
            return Some(match &retained.outcome {
                Some(outcome) => Ok(Execution::Replay(outcome.clone())),
                None => Err(ExecError::OutcomeNotReplayable),
            });
        }
        // In-flight: attach to it.
        if let Some(&pending_id) = inner.by_key.get(key) {
            let waiter_id = next_waiter(inner);
            let entry = inner.pending.get_mut(&pending_id).unwrap();
            if &entry.payload_hash != payload_hash {
                return Some(Err(ExecError::RequestIdMismatch));
            }
            let (tx, rx) = oneshot::channel();
            entry.waiters.push((waiter_id, tx));
            return Some(Ok(Execution::Wait(WaitHandle {
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
    ) -> Result<bool, ExecError> {
        if coalesce_key.is_none() {
            return Ok(false);
        }
        if self.shared.retention.is_zero()
            || inner
                .outcomes
                .len()
                .saturating_add(inner.retention_reservations)
                >= self.shared.retention_max_entries
        {
            return Err(ExecError::IdempotencyCapacity);
        }
        inner.retention_reservations += 1;
        Ok(true)
    }

    /// Run an authorized request: join or replay by idempotency key, or
    /// start the one execution. Agent-plane secret reads inside the
    /// execution are pre-authorized — the wiring is the authorization.
    pub fn run(&self, request: ExecRequest) -> Result<Execution, ExecError> {
        let ExecRequest {
            coalesce_key,
            payload_hash,
            executor,
            abandon,
        } = request;
        let (handle, id) = {
            let mut inner = self.shared.inner.lock().unwrap();
            if let Some(joined) = self.try_join(&mut inner, &coalesce_key, &payload_hash) {
                return joined;
            }
            let retention_reserved = self.reserve_retention_slot(&mut inner, &coalesce_key)?;
            let id = Uuid::new_v4();
            let waiter_id = next_waiter(&mut inner);
            let (tx, rx) = oneshot::channel();
            inner.pending.insert(
                id,
                Pending {
                    key: coalesce_key.clone(),
                    payload_hash,
                    retention_reserved,
                    waiters: vec![(waiter_id, tx)],
                    // A keyed execution must keep running for the retry
                    // that can reattach to it; drop its sender so a waiter
                    // exodus never signals it.
                    abandon: coalesce_key.is_none().then_some(abandon).flatten(),
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
        self.spawn_completion(id, executor);
        Ok(Execution::Wait(handle))
    }

    /// The execution task is not tied to any waiter, so a disconnect cannot
    /// cancel a side effect already in flight. On completion, the outcome is
    /// fanned out and the reserved idempotency slot becomes a tombstone, with
    /// a replay body when the byte budget permits. A confirmation that could
    /// not be answered is a pre-execution result, so its key is released and
    /// the documented retry can raise a fresh prompt.
    fn spawn_completion(&self, id: Uuid, executor: Executor) {
        let shared = self.shared.clone();
        self.shared.runtime.spawn(async move {
            // The wiring authorized this execution; its vault reads never
            // demand a separate native confirmation.
            let outcome = crate::authorization::scope(true, executor).await;
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
                        if !is_retryable_preflight_outcome(&outcome) {
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
                }
                waiters = entry.waiters;
            }
            for (_, tx) in waiters.drain(..) {
                let _ = tx.send(outcome.clone());
            }
        });
    }
}

/// These outcomes happen before the executor can reach an upstream. Keeping
/// their idempotency tombstone would make "attach the app and retry" (or
/// "re-enable the tool and retry") replay the old refusal for the full
/// retention window. `denied_by_policy` qualifies because every executor
/// that produces it refuses before dispatch — a policy refusal after
/// upstream work would be an upstream response relayed inside a 200
/// envelope, never this shape. A user's explicit `approval_denied` is
/// deliberately retained: replaying it matches the denial cooldown.
fn is_retryable_preflight_outcome(outcome: &ExecOutcome) -> bool {
    let reason = outcome
        .body
        .get("reason")
        .and_then(serde_json::Value::as_str);
    matches!(
        (outcome.status, reason),
        (408, Some("approval_timeout"))
            | (403, Some("approval_unavailable"))
            | (403, Some("denied_by_policy"))
    )
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
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn executions() -> Executions {
        Executions::new(Duration::from_secs(60), 64, 1024 * 1024)
    }

    fn key(id: &str) -> Option<Key> {
        Some((Uuid::from_u128(1), Uuid::from_u128(2), id.into()))
    }

    fn expect_err(result: Result<Execution, ExecError>) -> ExecError {
        match result {
            Err(error) => error,
            Ok(_) => panic!("expected an execution error"),
        }
    }

    fn counting_executor(counter: Arc<AtomicUsize>, body: serde_json::Value) -> Executor {
        Box::pin(async move {
            counter.fetch_add(1, Ordering::SeqCst);
            ExecOutcome { status: 200, body }
        })
    }

    async fn run_to_completion(
        e: &Executions,
        coalesce_key: Option<Key>,
        payload_hash: Option<String>,
        executor: Executor,
    ) -> ExecOutcome {
        match e
            .run(ExecRequest {
                coalesce_key,
                payload_hash,
                executor,
                abandon: None,
            })
            .unwrap()
        {
            Execution::Wait(handle) => handle.wait().await.unwrap(),
            Execution::Replay(outcome) => outcome,
        }
    }

    #[tokio::test]
    async fn unkeyed_requests_execute_independently() {
        let e = executions();
        let count = Arc::new(AtomicUsize::new(0));
        for _ in 0..2 {
            let outcome = run_to_completion(
                &e,
                None,
                None,
                counting_executor(count.clone(), serde_json::json!({"ok": true})),
            )
            .await;
            assert_eq!(outcome.status, 200);
        }
        assert_eq!(count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn keyed_retry_replays_without_reexecuting() {
        let e = executions();
        let count = Arc::new(AtomicUsize::new(0));
        let first = run_to_completion(
            &e,
            key("req-1"),
            Some("payload".into()),
            counting_executor(count.clone(), serde_json::json!({"n": 1})),
        )
        .await;
        let replayed = run_to_completion(
            &e,
            key("req-1"),
            Some("payload".into()),
            counting_executor(count.clone(), serde_json::json!({"n": 2})),
        )
        .await;
        assert_eq!(count.load(Ordering::SeqCst), 1, "exactly one execution");
        assert_eq!(first.body, replayed.body);
    }

    #[tokio::test]
    async fn unanswered_confirmation_can_retry_with_the_same_key() {
        let e = executions();
        let first = run_to_completion(
            &e,
            key("req-confirm"),
            Some("payload".into()),
            Box::pin(async {
                ExecOutcome {
                    status: 408,
                    body: serde_json::json!({"reason": ErrorReason::ApprovalTimeout}),
                }
            }),
        )
        .await;
        assert_eq!(first.status, 408);

        let count = Arc::new(AtomicUsize::new(0));
        let second = run_to_completion(
            &e,
            key("req-confirm"),
            Some("payload".into()),
            counting_executor(count.clone(), serde_json::json!({"ok": true})),
        )
        .await;
        assert_eq!(second.status, 200);
        assert_eq!(count.load(Ordering::SeqCst), 1);

        assert!(is_retryable_preflight_outcome(&ExecOutcome::refusal(
            ErrorReason::ApprovalUnavailable
        )));
    }

    #[tokio::test]
    async fn a_policy_refusal_before_execution_can_retry_with_the_same_key() {
        // A call parked on confirmation can be refused by a disable or edit
        // that raced it (`denied_by_policy`, produced before any upstream
        // dispatch). Re-enabling the tool and retrying the same `request_id`
        // must re-evaluate, not replay the stale refusal for ten minutes.
        let e = executions();
        let first = run_to_completion(
            &e,
            key("req-policy"),
            Some("payload".into()),
            Box::pin(async { ExecOutcome::refusal(ErrorReason::DeniedByPolicy) }),
        )
        .await;
        assert_eq!(first.status, 403);

        let count = Arc::new(AtomicUsize::new(0));
        let second = run_to_completion(
            &e,
            key("req-policy"),
            Some("payload".into()),
            counting_executor(count.clone(), serde_json::json!({"ok": true})),
        )
        .await;
        assert_eq!(second.status, 200);
        assert_eq!(count.load(Ordering::SeqCst), 1);

        // The user's own refusal is different: it is retained, so a blind
        // retry replays the denial instead of re-executing behind it.
        assert!(!is_retryable_preflight_outcome(&ExecOutcome {
            status: 403,
            body: serde_json::json!({"reason": ErrorReason::ApprovalDenied}),
        }));
    }

    #[tokio::test]
    async fn key_reuse_with_a_different_payload_is_rejected() {
        let e = executions();
        let count = Arc::new(AtomicUsize::new(0));
        run_to_completion(
            &e,
            key("req-1"),
            Some("payload-a".into()),
            counting_executor(count.clone(), serde_json::json!({})),
        )
        .await;
        let err = expect_err(e.run(ExecRequest {
            coalesce_key: key("req-1"),
            payload_hash: Some("payload-b".into()),
            executor: counting_executor(count.clone(), serde_json::json!({})),
            abandon: None,
        }));
        assert!(matches!(err, ExecError::RequestIdMismatch));
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn concurrent_keyed_calls_share_one_execution() {
        let e = executions();
        let count = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(tokio::sync::Notify::new());
        let gate_exec = gate.clone();
        let counter = count.clone();
        let slow: Executor = Box::pin(async move {
            // notify_one below stores a permit, so this cannot miss a
            // notification sent before the task first polls.
            gate_exec.notified().await;
            counter.fetch_add(1, Ordering::SeqCst);
            ExecOutcome {
                status: 200,
                body: serde_json::json!({"shared": true}),
            }
        });
        let first = e
            .run(ExecRequest {
                coalesce_key: key("req-1"),
                payload_hash: Some("payload".into()),
                executor: slow,
                abandon: None,
            })
            .unwrap();
        let second = e
            .run(ExecRequest {
                coalesce_key: key("req-1"),
                payload_hash: Some("payload".into()),
                executor: counting_executor(count.clone(), serde_json::json!({"other": true})),
                abandon: None,
            })
            .unwrap();
        gate.notify_one();
        let (Execution::Wait(first), Execution::Wait(second)) = (first, second) else {
            panic!("both callers should wait on the shared execution");
        };
        let (a, b) = (first.wait().await.unwrap(), second.wait().await.unwrap());
        assert_eq!(a.body, b.body);
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn capacity_fails_closed_before_execution() {
        let e = Executions::new(Duration::from_secs(60), 1, 1024);
        let count = Arc::new(AtomicUsize::new(0));
        run_to_completion(
            &e,
            key("req-1"),
            Some("payload".into()),
            counting_executor(count.clone(), serde_json::json!({})),
        )
        .await;
        let err = expect_err(e.run(ExecRequest {
            coalesce_key: key("req-2"),
            payload_hash: Some("payload".into()),
            executor: counting_executor(count.clone(), serde_json::json!({})),
            abandon: None,
        }));
        assert!(matches!(err, ExecError::IdempotencyCapacity));
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn zero_retention_rejects_keyed_requests_but_runs_unkeyed() {
        let e = Executions::new(Duration::ZERO, 64, 1024);
        let count = Arc::new(AtomicUsize::new(0));
        assert!(matches!(
            expect_err(e.run(ExecRequest {
                coalesce_key: key("req-1"),
                payload_hash: Some("payload".into()),
                executor: counting_executor(count.clone(), serde_json::json!({})),
                abandon: None,
            })),
            ExecError::IdempotencyCapacity
        ));
        let outcome = run_to_completion(
            &e,
            None,
            None,
            counting_executor(count.clone(), serde_json::json!({})),
        )
        .await;
        assert_eq!(outcome.status, 200);
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn oversized_outcome_leaves_a_non_replayable_tombstone() {
        // Byte budget too small for the body: the tombstone survives, the
        // replay body does not, and a retry must not re-execute.
        let e = Executions::new(Duration::from_secs(60), 64, 8);
        let count = Arc::new(AtomicUsize::new(0));
        run_to_completion(
            &e,
            key("req-1"),
            Some("payload".into()),
            counting_executor(count.clone(), serde_json::json!({"large": "x".repeat(64)})),
        )
        .await;
        let err = expect_err(e.run(ExecRequest {
            coalesce_key: key("req-1"),
            payload_hash: Some("payload".into()),
            executor: counting_executor(count.clone(), serde_json::json!({})),
            abandon: None,
        }));
        assert!(matches!(err, ExecError::OutcomeNotReplayable));
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn dropping_the_last_unkeyed_waiter_signals_abandonment() {
        // No idempotency key means no retry can ever reattach: once the one
        // caller hangs up, the executor's abandon receiver must learn it so
        // a pre-execution wait (a parked confirmation) can stop.
        let e = executions();
        let (abandon_tx, mut abandon_rx) = tokio::sync::watch::channel(false);
        let gate = Arc::new(tokio::sync::Notify::new());
        let executor_gate = gate.clone();
        let handle = match e
            .run(ExecRequest {
                coalesce_key: None,
                payload_hash: None,
                executor: Box::pin(async move {
                    executor_gate.notified().await;
                    ExecOutcome {
                        status: 200,
                        body: serde_json::json!({}),
                    }
                }),
                abandon: Some(abandon_tx),
            })
            .unwrap()
        {
            Execution::Wait(handle) => handle,
            Execution::Replay(_) => panic!("nothing to replay"),
        };
        assert!(!*abandon_rx.borrow());
        drop(handle);
        tokio::time::timeout(Duration::from_secs(1), abandon_rx.wait_for(|gone| *gone))
            .await
            .expect("abandonment should be signalled")
            .expect("the pending entry outlives its waiters");
        gate.notify_one();
    }

    #[tokio::test]
    async fn a_keyed_execution_ignores_a_waiter_exodus() {
        // A keyed retry can reattach or replay, so losing every waiter must
        // not signal abandonment even when a sender was supplied.
        let e = executions();
        let (abandon_tx, abandon_rx) = tokio::sync::watch::channel(false);
        let gate = Arc::new(tokio::sync::Notify::new());
        let executor_gate = gate.clone();
        let handle = match e
            .run(ExecRequest {
                coalesce_key: key("req-abandon"),
                payload_hash: Some("payload".into()),
                executor: Box::pin(async move {
                    executor_gate.notified().await;
                    ExecOutcome {
                        status: 200,
                        body: serde_json::json!({}),
                    }
                }),
                abandon: Some(abandon_tx),
            })
            .unwrap()
        {
            Execution::Wait(handle) => handle,
            Execution::Replay(_) => panic!("nothing to replay"),
        };
        drop(handle);
        tokio::task::yield_now().await;
        assert!(
            !*abandon_rx.borrow(),
            "a keyed execution keeps running for the retry that can reattach"
        );
        gate.notify_one();
    }

    #[tokio::test]
    async fn expired_tombstones_free_capacity() {
        let e = Executions::new(Duration::from_millis(20), 1, 1024);
        let count = Arc::new(AtomicUsize::new(0));
        run_to_completion(
            &e,
            key("req-1"),
            Some("payload".into()),
            counting_executor(count.clone(), serde_json::json!({})),
        )
        .await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        // The expired tombstone no longer blocks a new key.
        run_to_completion(
            &e,
            key("req-2"),
            Some("payload".into()),
            counting_executor(count.clone(), serde_json::json!({})),
        )
        .await;
        assert_eq!(count.load(Ordering::SeqCst), 2);
    }
}
