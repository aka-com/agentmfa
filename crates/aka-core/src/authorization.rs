//! Execution-scoped authorization for broker-side secret reads.
//!
//! A user decision and the credential reads performed for that decision are
//! one interaction. The approval executor receives a fresh authorization;
//! a separately confirmed decision marks it satisfied up front, while an
//! ordinary approval lets the first vault read satisfy it. Data-plane tickets
//! carry the same authorization into deferred or repeated session dials.

use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use tokio::sync::Mutex;
use uuid::Uuid;

use crate::{CoreError, Result};

enum ConfirmationState {
    Pending,
    Confirmed,
    Refused,
}

#[derive(Clone)]
pub(crate) struct SecretReadAuthorization {
    state: Arc<Mutex<ConfirmationState>>,
    grant: Option<GrantAuthorization>,
}

#[derive(Clone)]
pub(crate) struct GrantAuthorization {
    pub(crate) id: Uuid,
    pub(crate) expires_at: Instant,
    revoked: Arc<AtomicBool>,
}

impl GrantAuthorization {
    pub(crate) fn is_active(&self) -> bool {
        !self.revoked.load(Ordering::Acquire) && Instant::now() < self.expires_at
    }

    fn revoke(&self) {
        self.revoked.store(true, Ordering::Release);
    }
}

impl SecretReadAuthorization {
    pub(crate) fn new(confirmed: bool) -> Self {
        Self {
            state: Arc::new(Mutex::new(if confirmed {
                ConfirmationState::Confirmed
            } else {
                ConfirmationState::Pending
            })),
            grant: None,
        }
    }

    pub(crate) fn for_grant(id: Uuid, expires_at: Instant) -> Self {
        Self {
            state: Arc::new(Mutex::new(ConfirmationState::Confirmed)),
            grant: Some(GrantAuthorization {
                id,
                expires_at,
                revoked: Arc::new(AtomicBool::new(false)),
            }),
        }
    }

    pub(crate) fn grant(&self) -> Option<GrantAuthorization> {
        self.grant.clone()
    }

    pub(crate) fn revoke_grant(&self) {
        if let Some(grant) = &self.grant {
            grant.revoke();
        }
    }
}

tokio::task_local! {
    static CURRENT: SecretReadAuthorization;
}

/// Run one approval execution under a fresh, narrowly-scoped authorization.
pub(crate) async fn scope<F>(confirmed: bool, future: F) -> F::Output
where
    F: Future,
{
    CURRENT
        .scope(SecretReadAuthorization::new(confirmed), future)
        .await
}

/// Run under a particular authorization, used by active access grants.
pub(crate) async fn scope_authorization<F>(
    authorization: SecretReadAuthorization,
    future: F,
) -> F::Output
where
    F: Future,
{
    CURRENT.scope(authorization, future).await
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

pub(crate) fn current_grant() -> Option<GrantAuthorization> {
    current().and_then(|authorization| authorization.grant())
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
    if authorization
        .grant()
        .is_some_and(|grant| !grant.is_active())
    {
        return Err(CoreError::SecretReadNotAuthenticated);
    }
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
    async fn revoked_grant_cannot_read_a_secret() {
        let calls = AtomicUsize::new(0);
        let authorization = SecretReadAuthorization::for_grant(
            Uuid::new_v4(),
            Instant::now() + std::time::Duration::from_secs(60),
        );
        authorization.revoke_grant();
        scope_authorization(authorization, async {
            let result = confirm_once(|| async {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .await;
            assert!(matches!(result, Err(CoreError::SecretReadNotAuthenticated)));
        })
        .await;
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}
