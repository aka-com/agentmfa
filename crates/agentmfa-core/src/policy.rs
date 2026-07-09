//! The policy engine, deliberately a stub in v1 (DESIGN.md §7).
//!
//! The interface is real; the brains are not. Decisions are Allow / Deny /
//! Prompt; with no matching rule, everything prompts. "Always allow…"
//! stores a rule keyed by exact `(agent, connection_id)`, the connection's
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
use crate::types::{Decision, Rule};
use crate::Result;

pub trait PolicyEngine: Send + Sync {
    fn evaluate(&self, agent: &str, connection_id: &Uuid) -> Decision;
    /// From "Always allow…". Returns the stored rule.
    fn record_rule(&self, agent: &str, connection_id: Uuid) -> Result<Rule>;
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
        let rules = match integrity.read_verified(&path)? {
            Some(bytes) => serde_json::from_slice(&bytes)?,
            None => Vec::new(),
        };
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

    pub fn rules_for_agent(&self, agent: &str) -> Vec<Rule> {
        self.rules
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.agent == agent)
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

    pub fn matching_rule(&self, agent: &str, connection_id: &Uuid) -> Option<Rule> {
        self.rules
            .lock()
            .unwrap()
            .iter()
            .find(|r| r.agent == agent && &r.connection_id == connection_id)
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

    pub fn remove_rules_for_agent(&self, agent: &str) -> Result<usize> {
        let mut rules = self.rules.lock().unwrap();
        let mut next = rules.clone();
        let before = next.len();
        next.retain(|r| r.agent != agent);
        let removed = before - next.len();
        if removed > 0 {
            self.persist(&next)?;
            *rules = next;
        }
        Ok(removed)
    }
}

impl PolicyEngine for NaivePolicyEngine {
    fn evaluate(&self, agent: &str, connection_id: &Uuid) -> Decision {
        if self.matching_rule(agent, connection_id).is_some() {
            Decision::Allow
        } else {
            Decision::Prompt
        }
    }

    fn record_rule(&self, agent: &str, connection_id: Uuid) -> Result<Rule> {
        let mut rules = self.rules.lock().unwrap();
        if let Some(existing) = rules
            .iter()
            .find(|r| r.agent == agent && r.connection_id == connection_id)
        {
            return Ok(existing.clone());
        }
        let rule = Rule {
            id: Uuid::new_v4(),
            agent: agent.to_string(),
            connection_id,
            created_at: Utc::now(),
        };
        let mut next = rules.clone();
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
        Arc::new(futures::executor::block_on(StateIntegrity::open(&crate::vault::MemoryVault::new())).unwrap())
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
        assert_eq!(e.evaluate("claude-code", &conn), Decision::Prompt);
        e.record_rule("claude-code", conn).unwrap();
        assert_eq!(e.evaluate("claude-code", &conn), Decision::Allow);
        // Keyed on both halves.
        assert_eq!(e.evaluate("codex", &conn), Decision::Prompt);
        assert_eq!(e.evaluate("claude-code", &Uuid::new_v4()), Decision::Prompt);
    }

    #[test]
    fn record_is_idempotent() {
        let (e, _dir) = engine();
        let conn = Uuid::new_v4();
        let a = e.record_rule("claude-code", conn).unwrap();
        let b = e.record_rule("claude-code", conn).unwrap();
        assert_eq!(a.id, b.id);
        assert_eq!(e.rules().len(), 1);
    }

    #[test]
    fn rules_die_with_their_connection() {
        let (e, _dir) = engine();
        let conn = Uuid::new_v4();
        e.record_rule("claude-code", conn).unwrap();
        e.record_rule("codex", conn).unwrap();
        e.record_rule("codex", Uuid::new_v4()).unwrap();
        assert_eq!(e.remove_rules_for_connection(&conn).unwrap(), 2);
        assert_eq!(e.rules().len(), 1);
    }

    #[test]
    fn rules_can_be_revoked_by_agent_name() {
        let (e, _dir) = engine();
        e.record_rule("claude-code", Uuid::new_v4()).unwrap();
        e.record_rule("claude-code", Uuid::new_v4()).unwrap();
        e.record_rule("codex", Uuid::new_v4()).unwrap();
        assert_eq!(e.remove_rules_for_agent("claude-code").unwrap(), 2);
        assert_eq!(e.rules().len(), 1);
        assert_eq!(e.rules()[0].agent, "codex");
    }

    #[test]
    fn rules_persist_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rules.json");
        let conn = Uuid::new_v4();
        let integrity = integrity();
        {
            let e = NaivePolicyEngine::open(path.clone(), integrity.clone()).unwrap();
            e.record_rule("claude-code", conn).unwrap();
        }
        let e = NaivePolicyEngine::open(path, integrity).unwrap();
        assert_eq!(e.evaluate("claude-code", &conn), Decision::Allow);
    }

    #[test]
    fn failed_rule_writes_do_not_change_active_policy() {
        let (e, dir) = engine();
        let path = dir.path().join("rules.json");
        let existing_conn = Uuid::new_v4();
        let existing = e.record_rule("claude-code", existing_conn).unwrap();
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();

        assert!(e.record_rule("codex", Uuid::new_v4()).is_err());
        assert_eq!(e.rules(), vec![existing.clone()]);
        assert_eq!(e.evaluate("claude-code", &existing_conn), Decision::Allow);

        assert!(e.remove_rule(&existing.id).is_err());
        assert_eq!(e.rules(), vec![existing]);
        assert_eq!(e.evaluate("claude-code", &existing_conn), Decision::Allow);
    }
}
