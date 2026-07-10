//! The policy engine, deliberately a stub in v1 (DESIGN.md §7).
//!
//! The interface is real; the brains are not. Within this persistent policy
//! layer, decisions are Allow / Deny / Prompt and no matching rule prompts.
//! The broker checks scoped, in-memory access grants before this layer.
//! "Always allow…"
//! stores a rule keyed by exact `(client_id, connection_id)`, the client's
//! stable id and the connection's
//! **stable id**, never its renamable name, so a new connection recycling
//! an old name never inherits an old rule. There are no deny rules. The
//! real engine (scoping, precedence, TTLs) is a deferred design session,
//! quarantined behind this trait so the naive engine can be replaced
//! wholesale.

use std::path::PathBuf;
use std::sync::Arc;

use chrono::Utc;
use uuid::Uuid;

use crate::integrity::StateIntegrity;
use crate::types::{Decision, PairedAgent, PermissionScope, Rule};
use crate::Result;

pub trait PolicyEngine: Send + Sync {
    fn evaluate(
        &self,
        client_id: &Uuid,
        connection_id: &Uuid,
        required_scope: PermissionScope,
    ) -> Decision;
    /// From "Always allow…". Returns the stored rule.
    fn record_rule(
        &self,
        client_id: Uuid,
        agent: &str,
        connection_id: Uuid,
        scope: PermissionScope,
    ) -> Result<Rule>;
}

/// v1 behavior: no matching rule → Prompt; a `(agent, connection_id)` rule →
/// Allow. Rules persist in `rules.json`, sealed (§13.1).
pub struct NaivePolicyEngine {
    path: PathBuf,
    integrity: Arc<StateIntegrity>,
    rules: std::sync::Mutex<Vec<Rule>>,
}

impl NaivePolicyEngine {
    pub fn open(path: PathBuf, integrity: Arc<StateIntegrity>) -> Result<Self> {
        Self::open_with_clients(path, integrity, &[])
    }

    pub fn open_with_clients(
        path: PathBuf,
        integrity: Arc<StateIntegrity>,
        clients: &[PairedAgent],
    ) -> Result<Self> {
        let mut rules: Vec<Rule> = match integrity.read_verified(&path)? {
            Some(bytes) => serde_json::from_slice(&bytes)?,
            None => Vec::new(),
        };
        let before = rules.len();
        let mut migrated = false;
        rules.retain_mut(|rule| {
            if !rule.client_id.is_nil() {
                return true;
            }
            if let Some(client) = clients.iter().find(|client| client.name == rule.agent) {
                rule.client_id = client.id;
                migrated = true;
                true
            } else {
                false
            }
        });
        if migrated || rules.len() != before {
            integrity.write(&path, &serde_json::to_vec_pretty(&rules)?)?;
        }
        Ok(Self {
            path,
            integrity,
            rules: std::sync::Mutex::new(rules),
        })
    }

    fn persist(&self, rules: &[Rule]) -> Result<()> {
        self.integrity
            .write(&self.path, &serde_json::to_vec_pretty(rules)?)?;
        Ok(())
    }

    pub fn rules(&self) -> Vec<Rule> {
        self.rules.lock().unwrap().clone()
    }

    pub fn rules_for_client(&self, client_id: &Uuid) -> Vec<Rule> {
        self.rules
            .lock()
            .unwrap()
            .iter()
            .filter(|r| &r.client_id == client_id)
            .cloned()
            .collect()
    }

    pub fn rules_for_connection(&self, connection_id: &Uuid) -> Vec<Rule> {
        self.rules
            .lock()
            .unwrap()
            .iter()
            .filter(|r| &r.connection_id == connection_id)
            .cloned()
            .collect()
    }

    pub fn matching_rule(
        &self,
        client_id: &Uuid,
        connection_id: &Uuid,
        required_scope: PermissionScope,
    ) -> Option<Rule> {
        self.rules
            .lock()
            .unwrap()
            .iter()
            .find(|rule| {
                &rule.client_id == client_id
                    && &rule.connection_id == connection_id
                    && rule.scope.allows(required_scope)
            })
            .cloned()
    }

    /// Remove one rule (the removable auto-allow chip, §7).
    pub fn remove_rule(&self, id: &Uuid) -> Result<Option<Rule>> {
        let mut rules = self.rules.lock().unwrap();
        let mut next = rules.clone();
        let removed = next
            .iter()
            .position(|r| &r.id == id)
            .map(|pos| next.remove(pos));
        if removed.is_some() {
            self.persist(&next)?;
            *rules = next;
        }
        Ok(removed)
    }

    /// Rules die with their connection, also invoked when a connection's
    /// target changes (a rule granted for one destination must not silently
    /// cover another, §9). Returns how many were removed.
    pub fn remove_rules_for_connection(&self, connection_id: &Uuid) -> Result<usize> {
        let mut rules = self.rules.lock().unwrap();
        let mut next = rules.clone();
        let before = next.len();
        next.retain(|r| &r.connection_id != connection_id);
        let removed = before - next.len();
        if removed > 0 {
            self.persist(&next)?;
            *rules = next;
        }
        Ok(removed)
    }

    pub fn remove_rules_for_client(&self, client_id: &Uuid) -> Result<usize> {
        let mut rules = self.rules.lock().unwrap();
        let mut next = rules.clone();
        let before = next.len();
        next.retain(|r| &r.client_id != client_id);
        let removed = before - next.len();
        if removed > 0 {
            self.persist(&next)?;
            *rules = next;
        }
        Ok(removed)
    }
}

impl PolicyEngine for NaivePolicyEngine {
    fn evaluate(
        &self,
        client_id: &Uuid,
        connection_id: &Uuid,
        required_scope: PermissionScope,
    ) -> Decision {
        if self
            .matching_rule(client_id, connection_id, required_scope)
            .is_some()
        {
            Decision::Allow
        } else {
            Decision::Prompt
        }
    }

    fn record_rule(
        &self,
        client_id: Uuid,
        agent: &str,
        connection_id: Uuid,
        scope: PermissionScope,
    ) -> Result<Rule> {
        let mut rules = self.rules.lock().unwrap();
        if let Some(existing) = rules.iter().find(|rule| {
            rule.client_id == client_id
                && rule.connection_id == connection_id
                && rule.scope.allows(scope)
        }) {
            return Ok(existing.clone());
        }
        let rule = Rule {
            id: Uuid::new_v4(),
            client_id,
            agent: agent.to_string(),
            connection_id,
            scope,
            created_at: Utc::now(),
        };
        let mut next = rules.clone();
        next.retain(|existing| {
            existing.client_id != client_id || existing.connection_id != connection_id
        });
        next.push(rule.clone());
        self.persist(&next)?;
        *rules = next;
        Ok(rule)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn integrity() -> Arc<StateIntegrity> {
        Arc::new(
            futures::executor::block_on(StateIntegrity::open(&crate::vault::MemoryVault::new()))
                .unwrap(),
        )
    }

    fn engine() -> (NaivePolicyEngine, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let e = NaivePolicyEngine::open(dir.path().join("rules.json"), integrity()).unwrap();
        (e, dir)
    }

    #[test]
    fn no_rule_prompts_rule_allows() {
        let (e, _dir) = engine();
        let conn = Uuid::new_v4();
        let claude = Uuid::new_v4();
        let codex = Uuid::new_v4();
        assert_eq!(
            e.evaluate(&claude, &conn, PermissionScope::Full),
            Decision::Prompt
        );
        e.record_rule(claude, "claude-code", conn, PermissionScope::Full)
            .unwrap();
        assert_eq!(
            e.evaluate(&claude, &conn, PermissionScope::Full),
            Decision::Allow
        );
        // Keyed on both halves.
        assert_eq!(
            e.evaluate(&codex, &conn, PermissionScope::Full),
            Decision::Prompt
        );
        assert_eq!(
            e.evaluate(&claude, &Uuid::new_v4(), PermissionScope::Full),
            Decision::Prompt
        );
    }

    #[test]
    fn record_is_idempotent() {
        let (e, _dir) = engine();
        let conn = Uuid::new_v4();
        let client = Uuid::new_v4();
        let a = e
            .record_rule(client, "claude-code", conn, PermissionScope::Full)
            .unwrap();
        let b = e
            .record_rule(client, "claude-code", conn, PermissionScope::Full)
            .unwrap();
        assert_eq!(a.id, b.id);
        assert_eq!(e.rules().len(), 1);
    }

    #[test]
    fn rules_die_with_their_connection() {
        let (e, _dir) = engine();
        let conn = Uuid::new_v4();
        e.record_rule(Uuid::new_v4(), "claude-code", conn, PermissionScope::Full)
            .unwrap();
        e.record_rule(Uuid::new_v4(), "codex", conn, PermissionScope::Full)
            .unwrap();
        e.record_rule(
            Uuid::new_v4(),
            "codex",
            Uuid::new_v4(),
            PermissionScope::Full,
        )
        .unwrap();
        assert_eq!(e.remove_rules_for_connection(&conn).unwrap(), 2);
        assert_eq!(e.rules().len(), 1);
    }

    #[test]
    fn rules_can_be_revoked_by_client_id() {
        let (e, _dir) = engine();
        let claude = Uuid::new_v4();
        e.record_rule(claude, "claude-code", Uuid::new_v4(), PermissionScope::Full)
            .unwrap();
        e.record_rule(claude, "claude-code", Uuid::new_v4(), PermissionScope::Full)
            .unwrap();
        e.record_rule(
            Uuid::new_v4(),
            "codex",
            Uuid::new_v4(),
            PermissionScope::Full,
        )
        .unwrap();
        assert_eq!(e.remove_rules_for_client(&claude).unwrap(), 2);
        assert_eq!(e.rules().len(), 1);
        assert_eq!(e.rules()[0].agent, "codex");
    }

    #[test]
    fn rules_persist_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rules.json");
        let conn = Uuid::new_v4();
        let client = Uuid::new_v4();
        let integrity = integrity();
        {
            let e = NaivePolicyEngine::open(path.clone(), integrity.clone()).unwrap();
            e.record_rule(client, "claude-code", conn, PermissionScope::Full)
                .unwrap();
        }
        let e = NaivePolicyEngine::open(path, integrity).unwrap();
        assert_eq!(
            e.evaluate(&client, &conn, PermissionScope::Full),
            Decision::Allow
        );
    }

    #[test]
    fn failed_rule_writes_do_not_change_active_policy() {
        let (e, dir) = engine();
        let path = dir.path().join("rules.json");
        let existing_conn = Uuid::new_v4();
        let client = Uuid::new_v4();
        let existing = e
            .record_rule(client, "claude-code", existing_conn, PermissionScope::Full)
            .unwrap();
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();

        assert!(e
            .record_rule(
                Uuid::new_v4(),
                "codex",
                Uuid::new_v4(),
                PermissionScope::Full,
            )
            .is_err());
        assert_eq!(e.rules(), vec![existing.clone()]);
        assert_eq!(
            e.evaluate(&client, &existing_conn, PermissionScope::Full),
            Decision::Allow
        );

        assert!(e.remove_rule(&existing.id).is_err());
        assert_eq!(e.rules(), vec![existing]);
        assert_eq!(
            e.evaluate(&client, &existing_conn, PermissionScope::Full),
            Decision::Allow
        );
    }

    #[test]
    fn legacy_name_rules_migrate_only_for_current_clients() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rules.json");
        let integrity = integrity();
        let client = PairedAgent {
            id: Uuid::new_v4(),
            name: "claude-code".into(),
            token_hash: "hash".into(),
            token_preview: "amfa_legacy".into(),
            identity: crate::types::PeerIdentity::DevUnverified { uid: 501 },
            paired_at: Utc::now(),
            last_used: Utc::now(),
        };
        let connection_id = Uuid::new_v4();
        let legacy = serde_json::json!([
            {"id": Uuid::new_v4(), "agent": "claude-code", "connection_id": connection_id, "created_at": Utc::now()},
            {"id": Uuid::new_v4(), "agent": "orphan", "connection_id": Uuid::new_v4(), "created_at": Utc::now()}
        ]);
        integrity
            .write(&path, &serde_json::to_vec_pretty(&legacy).unwrap())
            .unwrap();

        let policy =
            NaivePolicyEngine::open_with_clients(path, integrity, std::slice::from_ref(&client))
                .unwrap();
        assert_eq!(policy.rules().len(), 1);
        assert_eq!(policy.rules()[0].client_id, client.id);
        assert_eq!(
            policy.evaluate(&client.id, &connection_id, PermissionScope::Full),
            Decision::Allow
        );
    }

    #[test]
    fn read_permission_does_not_allow_full_access() {
        let (policy, _dir) = engine();
        let client = Uuid::new_v4();
        let connection = Uuid::new_v4();
        policy
            .record_rule(client, "claude-code", connection, PermissionScope::Read)
            .unwrap();
        assert_eq!(
            policy.evaluate(&client, &connection, PermissionScope::Read),
            Decision::Allow
        );
        assert_eq!(
            policy.evaluate(&client, &connection, PermissionScope::Full),
            Decision::Prompt
        );
    }
}
