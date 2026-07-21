//! Execution-scoped authorization for broker-side secret reads.
//!
//! Agent-plane executions run with secret reads pre-authorized: the wiring
//! is the authorization, so a wired call never raises a native prompt.
//! UI-initiated reads (reveal, copy) run outside any execution scope and
//! keep their own per-operation confirmation behavior. Data-plane tickets
//! carry the execution's authorization into deferred or repeated session
//! dials.

use std::future::Future;
use std::sync::Arc;

use tokio::sync::Mutex;

use crate::{CoreError, Result};

enum ConfirmationState {
    Pending,
    Confirmed,
    Refused,
}

#[derive(Clone)]
pub(crate) struct SecretReadAuthorization {
    state: Arc<Mutex<ConfirmationState>>,
}

impl SecretReadAuthorization {
    pub(crate) fn new(confirmed: bool) -> Self {
        Self {
            state: Arc::new(Mutex::new(if confirmed {
                ConfirmationState::Confirmed
            } else {
                ConfirmationState::Pending
            })),
        }
    }
}

tokio::task_local! {
    static CURRENT: SecretReadAuthorization;
}

/// Run one execution under a fresh authorization; `confirmed: true` marks
/// its secret reads pre-authorized.
pub(crate) async fn scope<F>(confirmed: bool, future: F) -> F::Output
where
    F: Future,
{
    CURRENT
        .scope(SecretReadAuthorization::new(confirmed), future)
        .await
}

/// Continue an execution authorization across a deferred data-plane dial.
pub(crate) async fn scope_existing<F>(
    authorization: Option<SecretReadAuthorization>,
    future: F,
) -> F::Output
where
    F: Future,
{
    match authorization {
        Some(authorization) => CURRENT.scope(authorization, future).await,
        None => future.await,
    }
}

/// Capture the current execution authorization for a session ticket.
pub(crate) fn current() -> Option<SecretReadAuthorization> {
    CURRENT.try_with(Clone::clone).ok()
}

/// Confirm at most once within the current execution authorization. With no
/// execution scope (for example, a user-initiated copy), preserve the normal
/// per-operation confirmation behavior.
pub(crate) async fn confirm_once<F, Fut>(confirm: F) -> Result<()>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<()>>,
{
    let Some(authorization) = current() else {
        return confirm().await;
    };
    let mut state = authorization.state.lock().await;
    match *state {
        ConfirmationState::Confirmed => return Ok(()),
        ConfirmationState::Refused => return Err(CoreError::SecretReadNotAuthenticated),
        ConfirmationState::Pending => {}
    }
    match confirm().await {
        Ok(()) => {
            *state = ConfirmationState::Confirmed;
            Ok(())
        }
        Err(error) => {
            // Fail the whole execution authorization closed. In particular,
            // concurrent redemptions must not queue a series of native auth
            // sheets after the user refuses the first one.
            *state = ConfirmationState::Refused;
            Err(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn refusal_is_terminal_within_one_execution() {
        let calls = AtomicUsize::new(0);
        scope(false, async {
            let first = confirm_once(|| async {
                calls.fetch_add(1, Ordering::SeqCst);
                Err(CoreError::SecretReadNotAuthenticated)
            })
            .await;
            assert!(matches!(first, Err(CoreError::SecretReadNotAuthenticated)));

            let second = confirm_once(|| async {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .await;
            assert!(matches!(second, Err(CoreError::SecretReadNotAuthenticated)));
        })
        .await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn preauthorized_scope_never_confirms() {
        let calls = AtomicUsize::new(0);
        scope(true, async {
            let result = confirm_once(|| async {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .await;
            assert!(result.is_ok());
        })
        .await;
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}
