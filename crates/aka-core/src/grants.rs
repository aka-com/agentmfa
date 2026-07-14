//! In-memory, identity-bound access sessions.
//!
//! Grants deliberately never touch disk. They bind the current pair-token
//! generation to one stable connection and its exact configuration revision,
//! expire at a fixed deadline, and carry the native-authenticated secret-read
//! authorization reused by matching executions.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

use crate::authorization::SecretReadAuthorization;
use crate::types::{Connection, PermissionScope};

#[derive(Clone)]
struct AccessGrant {
    id: Uuid,
    agent: String,
    token_hash: String,
    connection_id: Uuid,
    connection_updated_at: DateTime<Utc>,
    scope: PermissionScope,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    deadline: Instant,
    authorization: SecretReadAuthorization,
}

#[derive(Debug, Clone, Serialize)]
pub struct AccessGrantSummary {
    pub id: Uuid,
    pub agent: String,
    pub connection_id: Uuid,
    pub scope: PermissionScope,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone)]
pub(crate) struct GrantMatch {
    pub(crate) summary: AccessGrantSummary,
    pub(crate) authorization: SecretReadAuthorization,
}

pub(crate) struct GrantCreated {
    pub(crate) grant: GrantMatch,
    pub(crate) replaced: Vec<Uuid>,
    pub(crate) deadline: Instant,
}

pub(crate) enum GrantRemoval {
    Revoked(AccessGrantSummary),
    Expired(AccessGrantSummary),
}

pub(crate) struct GrantsRemoved {
    pub(crate) revoked: Vec<Uuid>,
    pub(crate) expired: Vec<AccessGrantSummary>,
}

#[derive(Default)]
pub struct AccessGrants {
    grants: Mutex<Vec<AccessGrant>>,
}

impl AccessGrants {
    pub fn new() -> Self {
        Self::default()
    }

    pub(crate) fn create(
        &self,
        agent: &str,
        token_hash: &str,
        connection: &Connection,
        scope: PermissionScope,
        ttl: Duration,
    ) -> GrantCreated {
        let now = Utc::now();
        let deadline = Instant::now() + ttl;
        let id = Uuid::new_v4();
        let authorization = SecretReadAuthorization::for_grant(id, deadline);
        let mut grants = self.grants.lock().unwrap();
        let instant_now = Instant::now();
        let active = |grant: &&AccessGrant| instant_now < grant.deadline;
        let replaced = grants
            .iter()
            .filter(active)
            .filter(|grant| grant.token_hash == token_hash && grant.connection_id == connection.id)
            .map(|grant| grant.id)
            .collect();
        for grant in grants
            .iter()
            .filter(active)
            .filter(|grant| grant.token_hash == token_hash && grant.connection_id == connection.id)
        {
            grant.authorization.revoke_grant();
        }
        grants.retain(|grant| {
            instant_now >= grant.deadline
                || grant.token_hash != token_hash
                || grant.connection_id != connection.id
        });
        let grant = AccessGrant {
            id,
            agent: agent.to_string(),
            token_hash: token_hash.to_string(),
            connection_id: connection.id,
            connection_updated_at: connection.updated_at,
            scope,
            created_at: now,
            expires_at: now
                + chrono::Duration::from_std(ttl).unwrap_or_else(|_| chrono::Duration::minutes(15)),
            deadline,
            authorization,
        };
        let matched = GrantMatch {
            summary: grant.summary(),
            authorization: grant.authorization.clone(),
        };
        grants.push(grant);
        GrantCreated {
            grant: matched,
            replaced,
            deadline,
        }
    }

    pub(crate) fn matching(
        &self,
        token_hash: &str,
        connection: &Connection,
        required: PermissionScope,
    ) -> Option<GrantMatch> {
        let grants = self.grants.lock().unwrap();
        grants
            .iter()
            .find(|grant| {
                Instant::now() < grant.deadline
                    && grant.token_hash == token_hash
                    && grant.connection_id == connection.id
                    && grant.connection_updated_at == connection.updated_at
                    && grant.scope.allows(required)
            })
            .map(|grant| GrantMatch {
                summary: grant.summary(),
                authorization: grant.authorization.clone(),
            })
    }

    pub fn for_connection(&self, connection: &Connection) -> Vec<AccessGrantSummary> {
        let grants = self.grants.lock().unwrap();
        grants
            .iter()
            .filter(|grant| {
                Instant::now() < grant.deadline
                    && grant.connection_id == connection.id
                    && grant.connection_updated_at == connection.updated_at
            })
            .map(AccessGrant::summary)
            .collect()
    }

    pub fn count_for_agent(&self, agent: &str) -> usize {
        let grants = self.grants.lock().unwrap();
        grants
            .iter()
            .filter(|grant| Instant::now() < grant.deadline && grant.agent == agent)
            .count()
    }

    /// Remove a grant only once its fixed deadline has passed. The scheduled
    /// broker expiry task and any late observer can race safely: exactly one
    /// caller receives the summary and therefore emits the expiry event.
    pub(crate) fn expire(&self, id: &Uuid) -> Option<AccessGrantSummary> {
        let mut grants = self.grants.lock().unwrap();
        let position = grants
            .iter()
            .position(|grant| &grant.id == id && Instant::now() >= grant.deadline)?;
        let grant = grants.remove(position);
        grant.authorization.revoke_grant();
        Some(grant.summary())
    }

    pub(crate) fn remove(&self, id: &Uuid) -> Option<GrantRemoval> {
        let mut grants = self.grants.lock().unwrap();
        let position = grants.iter().position(|grant| &grant.id == id)?;
        let grant = grants.remove(position);
        grant.authorization.revoke_grant();
        let summary = grant.summary();
        Some(if Instant::now() >= grant.deadline {
            GrantRemoval::Expired(summary)
        } else {
            GrantRemoval::Revoked(summary)
        })
    }

    pub(crate) fn remove_for_agent(&self, agent: &str) -> GrantsRemoved {
        self.remove_where(|grant| grant.agent == agent)
    }

    pub(crate) fn remove_for_connection(&self, connection_id: &Uuid) -> GrantsRemoved {
        self.remove_where(|grant| &grant.connection_id == connection_id)
    }

    fn remove_where(&self, predicate: impl Fn(&AccessGrant) -> bool) -> GrantsRemoved {
        let mut grants = self.grants.lock().unwrap();
        let now = Instant::now();
        let mut revoked = Vec::new();
        let mut expired = Vec::new();
        for grant in grants.iter().filter(|grant| predicate(grant)) {
            grant.authorization.revoke_grant();
            if now >= grant.deadline {
                expired.push(grant.summary());
            } else {
                revoked.push(grant.id);
            }
        }
        grants.retain(|grant| !predicate(grant));
        GrantsRemoved { revoked, expired }
    }
}

impl AccessGrant {
    fn summary(&self) -> AccessGrantSummary {
        AccessGrantSummary {
            id: self.id,
            agent: self.agent.clone(),
            connection_id: self.connection_id,
            scope: self.scope,
            created_at: self.created_at,
            expires_at: self.expires_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ConnectionConfig;

    fn connection() -> Connection {
        Connection {
            id: Uuid::new_v4(),
            name: "github".into(),
            config: ConnectionConfig::Api {
                host: "api.github.com".into(),
                scheme: "https".into(),
                port: None,
                template: "Authorization: Bearer {{TOKEN}}".into(),
            },
            secrets: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn read_does_not_cover_full_and_replacement_upgrades() {
        let grants = AccessGrants::new();
        let conn = connection();
        grants.create(
            "codex",
            "token-a",
            &conn,
            PermissionScope::Read,
            Duration::from_secs(60),
        );
        assert!(grants
            .matching("token-a", &conn, PermissionScope::Read)
            .is_some());
        assert!(grants
            .matching("token-a", &conn, PermissionScope::Full)
            .is_none());

        let upgraded = grants.create(
            "codex",
            "token-a",
            &conn,
            PermissionScope::Full,
            Duration::from_secs(60),
        );
        assert_eq!(upgraded.replaced.len(), 1);
        assert!(grants
            .matching("token-a", &conn, PermissionScope::Full)
            .is_some());
    }

    #[test]
    fn grants_are_token_and_revision_bound() {
        let grants = AccessGrants::new();
        let conn = connection();
        grants.create(
            "codex",
            "token-a",
            &conn,
            PermissionScope::Full,
            Duration::from_secs(60),
        );
        assert!(grants
            .matching("token-b", &conn, PermissionScope::Read)
            .is_none());
        let mut changed = conn.clone();
        changed.updated_at += chrono::Duration::seconds(1);
        assert!(grants
            .matching("token-a", &changed, PermissionScope::Read)
            .is_none());
    }

    #[test]
    fn expired_grants_do_not_match_and_are_removed_once() {
        let grants = AccessGrants::new();
        let conn = connection();
        let created = grants.create(
            "codex",
            "token-a",
            &conn,
            PermissionScope::Full,
            Duration::ZERO,
        );
        assert!(grants
            .matching("token-a", &conn, PermissionScope::Read)
            .is_none());
        let expired = grants
            .expire(&created.grant.summary.id)
            .expect("expired grant should be removed");
        assert_eq!(expired.id, created.grant.summary.id);
        assert!(grants.expire(&expired.id).is_none());

        grants.create(
            "codex",
            "token-a",
            &conn,
            PermissionScope::Full,
            Duration::ZERO,
        );
        let removed = grants.remove_for_agent("codex");
        assert!(removed.revoked.is_empty());
        assert_eq!(removed.expired.len(), 1);
    }
}
