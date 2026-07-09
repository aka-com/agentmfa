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
use crate::types::Connection;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum GrantScope {
    Read,
    Full,
}

impl GrantScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Full => "full",
        }
    }

    pub fn allows(self, required: Self) -> bool {
        self == Self::Full || required == Self::Read
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Read => "read access",
            Self::Full => "full access",
        }
    }
}

#[derive(Clone)]
struct AccessGrant {
    id: Uuid,
    agent: String,
    token_hash: String,
    connection_id: Uuid,
    connection_updated_at: DateTime<Utc>,
    scope: GrantScope,
    expires_at: DateTime<Utc>,
    deadline: Instant,
    authorization: SecretReadAuthorization,
}

#[derive(Debug, Clone, Serialize)]
pub struct AccessGrantSummary {
    pub id: Uuid,
    pub agent: String,
    pub connection_id: Uuid,
    pub scope: GrantScope,
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
        scope: GrantScope,
        ttl: Duration,
    ) -> GrantCreated {
        let now = Utc::now();
        let deadline = Instant::now() + ttl;
        let id = Uuid::new_v4();
        let authorization = SecretReadAuthorization::for_grant(id, deadline);
        let mut grants = self.grants.lock().unwrap();
        Self::sweep(&mut grants);
        let replaced = grants
            .iter()
            .filter(|grant| grant.token_hash == token_hash && grant.connection_id == connection.id)
            .map(|grant| grant.id)
            .collect();
        for grant in grants
            .iter()
            .filter(|grant| grant.token_hash == token_hash && grant.connection_id == connection.id)
        {
            grant.authorization.revoke_grant();
        }
        grants
            .retain(|grant| grant.token_hash != token_hash || grant.connection_id != connection.id);
        let grant = AccessGrant {
            id,
            agent: agent.to_string(),
            token_hash: token_hash.to_string(),
            connection_id: connection.id,
            connection_updated_at: connection.updated_at,
            scope,
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
        }
    }

    pub(crate) fn matching(
        &self,
        token_hash: &str,
        connection: &Connection,
        required: GrantScope,
    ) -> Option<GrantMatch> {
        let mut grants = self.grants.lock().unwrap();
        Self::sweep(&mut grants);
        grants
            .iter()
            .find(|grant| {
                grant.token_hash == token_hash
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
        let mut grants = self.grants.lock().unwrap();
        Self::sweep(&mut grants);
        grants
            .iter()
            .filter(|grant| {
                grant.connection_id == connection.id
                    && grant.connection_updated_at == connection.updated_at
            })
            .map(AccessGrant::summary)
            .collect()
    }

    pub(crate) fn remove(&self, id: &Uuid) -> Option<AccessGrantSummary> {
        let mut grants = self.grants.lock().unwrap();
        let position = grants.iter().position(|grant| &grant.id == id)?;
        let grant = grants.remove(position);
        grant.authorization.revoke_grant();
        Some(grant.summary())
    }

    pub(crate) fn remove_for_agent(&self, agent: &str) -> Vec<Uuid> {
        self.remove_where(|grant| grant.agent == agent)
    }

    pub(crate) fn remove_for_connection(&self, connection_id: &Uuid) -> Vec<Uuid> {
        self.remove_where(|grant| &grant.connection_id == connection_id)
    }

    fn remove_where(&self, predicate: impl Fn(&AccessGrant) -> bool) -> Vec<Uuid> {
        let mut grants = self.grants.lock().unwrap();
        let removed = grants
            .iter()
            .filter(|grant| predicate(grant))
            .map(|grant| grant.id)
            .collect();
        for grant in grants.iter().filter(|grant| predicate(grant)) {
            grant.authorization.revoke_grant();
        }
        grants.retain(|grant| !predicate(grant));
        removed
    }

    fn sweep(grants: &mut Vec<AccessGrant>) {
        grants.retain(|grant| Instant::now() < grant.deadline);
    }
}

impl AccessGrant {
    fn summary(&self) -> AccessGrantSummary {
        AccessGrantSummary {
            id: self.id,
            agent: self.agent.clone(),
            connection_id: self.connection_id,
            scope: self.scope,
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
            multi_connect: false,
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
            GrantScope::Read,
            Duration::from_secs(60),
        );
        assert!(grants
            .matching("token-a", &conn, GrantScope::Read)
            .is_some());
        assert!(grants
            .matching("token-a", &conn, GrantScope::Full)
            .is_none());

        let upgraded = grants.create(
            "codex",
            "token-a",
            &conn,
            GrantScope::Full,
            Duration::from_secs(60),
        );
        assert_eq!(upgraded.replaced.len(), 1);
        assert!(grants
            .matching("token-a", &conn, GrantScope::Full)
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
            GrantScope::Full,
            Duration::from_secs(60),
        );
        assert!(grants
            .matching("token-b", &conn, GrantScope::Read)
            .is_none());
        let mut changed = conn.clone();
        changed.updated_at += chrono::Duration::seconds(1);
        assert!(grants
            .matching("token-a", &changed, GrantScope::Read)
            .is_none());
    }

    #[test]
    fn expired_grants_do_not_match() {
        let grants = AccessGrants::new();
        let conn = connection();
        grants.create("codex", "token-a", &conn, GrantScope::Full, Duration::ZERO);
        assert!(grants
            .matching("token-a", &conn, GrantScope::Read)
            .is_none());
    }
}
