//! The wiring table: which agents may use which connections.
//!
//! Authorization is a plain persisted set of `(client_id, connection_id)`
//! pairs, edited only in the app. A wired agent uses the connection without
//! prompting; an unwired agent is refused (`403 denied_by_policy`). There
//! are no prompts or expiring grants. Each wiring additionally carries an
//! attenuation `mode` (`read-write` by default, or `read-only`); the
//! capability planes consult it and, where the upstream can enforce it
//! (Postgres), the broker makes read-only stick. Wirings persist in
//! `wirings.json`, sealed. Standing rules written by earlier versions
//! (`rules.json`) are migrated on first open.

use std::path::PathBuf;
use std::sync::Arc;

use chrono::Utc;
use uuid::Uuid;

use crate::integrity::StateIntegrity;
use crate::types::{Wiring, WiringMode};
use crate::Result;

pub struct Wirings {
    path: PathBuf,
    integrity: Arc<StateIntegrity>,
    wirings: std::sync::Mutex<Vec<Wiring>>,
}

impl Wirings {
    pub fn open(path: PathBuf, integrity: Arc<StateIntegrity>) -> Result<Self> {
        Self::open_with_legacy_rules(path, None, integrity)
    }

    /// Open `wirings.json`; when it does not exist yet and a legacy
    /// `rules.json` does, convert each standing rule into a wiring.
    pub fn open_with_legacy_rules(
        path: PathBuf,
        legacy_rules_path: Option<&std::path::Path>,
        integrity: Arc<StateIntegrity>,
    ) -> Result<Self> {
        let mut wirings: Option<Vec<Wiring>> = integrity
            .read_verified(&path)?
            .map(|bytes| serde_json::from_slice(&bytes))
            .transpose()?;
        if wirings.is_none() {
            if let Some(rules_path) = legacy_rules_path {
                if let Some(bytes) = integrity.read_verified(rules_path)? {
                    // Legacy rule shape: {id, client_id, agent, connection_id,
                    // scope, created_at}. Scope collapses away — a wiring is
                    // full access.
                    #[derive(serde::Deserialize)]
                    struct LegacyRule {
                        #[serde(default)]
                        client_id: Uuid,
                        agent: String,
                        connection_id: Uuid,
                    }
                    let rules: Vec<LegacyRule> = serde_json::from_slice(&bytes)?;
                    let mut migrated: Vec<Wiring> = Vec::new();
                    for rule in rules {
                        if rule.client_id.is_nil() {
                            continue;
                        }
                        if migrated.iter().any(|wiring: &Wiring| {
                            wiring.client_id == rule.client_id
                                && wiring.connection_id == rule.connection_id
                        }) {
                            continue;
                        }
                        migrated.push(Wiring {
                            id: Uuid::new_v4(),
                            client_id: rule.client_id,
                            agent: rule.agent,
                            connection_id: rule.connection_id,
                            allowed_tools: None,
                            // Legacy rules carried no attenuation; a wiring was
                            // full access, so migrate to read-write.
                            mode: WiringMode::default(),
                            created_at: Utc::now(),
                        });
                    }
                    integrity.write(&path, &serde_json::to_vec_pretty(&migrated)?)?;
                    wirings = Some(migrated);
                }
            }
        }
        Ok(Self {
            path,
            integrity,
            wirings: std::sync::Mutex::new(wirings.unwrap_or_default()),
        })
    }

    fn persist(&self, wirings: &[Wiring]) -> Result<()> {
        self.integrity
            .write(&self.path, &serde_json::to_vec_pretty(wirings)?)?;
        Ok(())
    }

    /// Whether the agent may use the connection.
    pub fn is_wired(&self, client_id: &Uuid, connection_id: &Uuid) -> bool {
        self.wirings
            .lock()
            .unwrap()
            .iter()
            .any(|w| &w.client_id == client_id && &w.connection_id == connection_id)
    }

    /// The attenuation mode of an agent↔connection wiring, or `None` when the
    /// pair is not wired at all. Capability opens consult this to decide
    /// whether to enforce read-only.
    pub fn mode(&self, client_id: &Uuid, connection_id: &Uuid) -> Option<WiringMode> {
        self.wirings
            .lock()
            .unwrap()
            .iter()
            .find(|w| &w.client_id == client_id && &w.connection_id == connection_id)
            .map(|w| w.mode)
    }

    pub fn wirings(&self) -> Vec<Wiring> {
        self.wirings.lock().unwrap().clone()
    }

    /// The wiring for one agent↔connection pair, when it exists.
    pub fn wiring_for(&self, client_id: &Uuid, connection_id: &Uuid) -> Option<Wiring> {
        self.wirings
            .lock()
            .unwrap()
            .iter()
            .find(|w| &w.client_id == client_id && &w.connection_id == connection_id)
            .cloned()
    }

    /// Set (or clear, with `None`) the wiring's allowed upstream MCP tools.
    /// Returns whether a wiring existed and was updated.
    pub fn set_allowed_tools(
        &self,
        client_id: &Uuid,
        connection_id: &Uuid,
        tools: Option<Vec<String>>,
    ) -> Result<bool> {
        let mut wirings = self.wirings.lock().unwrap();
        let mut next = wirings.clone();
        let Some(wiring) = next
            .iter_mut()
            .find(|w| &w.client_id == client_id && &w.connection_id == connection_id)
        else {
            return Ok(false);
        };
        if wiring.allowed_tools == tools {
            return Ok(false);
        }
        wiring.allowed_tools = tools;
        self.persist(&next)?;
        *wirings = next;
        Ok(true)
    }

    pub fn wirings_for_client(&self, client_id: &Uuid) -> Vec<Wiring> {
        self.wirings
            .lock()
            .unwrap()
            .iter()
            .filter(|w| &w.client_id == client_id)
            .cloned()
            .collect()
    }

    pub fn wirings_for_connection(&self, connection_id: &Uuid) -> Vec<Wiring> {
        self.wirings
            .lock()
            .unwrap()
            .iter()
            .filter(|w| &w.connection_id == connection_id)
            .cloned()
            .collect()
    }

    /// Wire an agent to a connection. Idempotent: an existing wiring is
    /// returned unchanged.
    pub fn wire(&self, client_id: Uuid, agent: &str, connection_id: Uuid) -> Result<Wiring> {
        let mut wirings = self.wirings.lock().unwrap();
        if let Some(existing) = wirings
            .iter()
            .find(|w| w.client_id == client_id && w.connection_id == connection_id)
        {
            return Ok(existing.clone());
        }
        let wiring = Wiring {
            id: Uuid::new_v4(),
            client_id,
            agent: agent.to_string(),
            connection_id,
            allowed_tools: None,
            mode: WiringMode::default(),
            created_at: Utc::now(),
        };
        let mut next = wirings.clone();
        next.push(wiring.clone());
        self.persist(&next)?;
        *wirings = next;
        Ok(wiring)
    }

    /// Set the attenuation mode of an existing wiring. Idempotent: an
    /// unchanged mode is a no-op returning the current wiring. Returns `None`
    /// when the pair is not wired (there is nothing to attenuate).
    pub fn set_mode(
        &self,
        client_id: &Uuid,
        connection_id: &Uuid,
        mode: WiringMode,
    ) -> Result<Option<Wiring>> {
        let mut wirings = self.wirings.lock().unwrap();
        let Some(pos) = wirings
            .iter()
            .position(|w| &w.client_id == client_id && &w.connection_id == connection_id)
        else {
            return Ok(None);
        };
        if wirings[pos].mode == mode {
            return Ok(Some(wirings[pos].clone()));
        }
        let mut next = wirings.clone();
        next[pos].mode = mode;
        let updated = next[pos].clone();
        self.persist(&next)?;
        *wirings = next;
        Ok(Some(updated))
    }

    /// Wire an agent to every listed connection in one persisted write
    /// (the first-agent bootstrap).
    pub fn wire_all(
        &self,
        client_id: Uuid,
        agent: &str,
        connection_ids: &[Uuid],
    ) -> Result<Vec<Wiring>> {
        let mut wirings = self.wirings.lock().unwrap();
        let mut next = wirings.clone();
        let mut added = Vec::new();
        for connection_id in connection_ids {
            if next
                .iter()
                .any(|w| w.client_id == client_id && &w.connection_id == connection_id)
            {
                continue;
            }
            let wiring = Wiring {
                id: Uuid::new_v4(),
                client_id,
                agent: agent.to_string(),
                connection_id: *connection_id,
                allowed_tools: None,
                mode: WiringMode::default(),
                created_at: Utc::now(),
            };
            next.push(wiring.clone());
            added.push(wiring);
        }
        if !added.is_empty() {
            self.persist(&next)?;
            *wirings = next;
        }
        Ok(added)
    }

    /// Remove one agent↔connection wiring. Returns it when it existed.
    pub fn unwire(&self, client_id: &Uuid, connection_id: &Uuid) -> Result<Option<Wiring>> {
        let mut wirings = self.wirings.lock().unwrap();
        let mut next = wirings.clone();
        let removed = next
            .iter()
            .position(|w| &w.client_id == client_id && &w.connection_id == connection_id)
            .map(|pos| next.remove(pos));
        if removed.is_some() {
            self.persist(&next)?;
            *wirings = next;
        }
        Ok(removed)
    }

    /// Wirings die with their connection. Returns how many were removed.
    pub fn remove_for_connection(&self, connection_id: &Uuid) -> Result<usize> {
        let mut wirings = self.wirings.lock().unwrap();
        let mut next = wirings.clone();
        let before = next.len();
        next.retain(|w| &w.connection_id != connection_id);
        let removed = before - next.len();
        if removed > 0 {
            self.persist(&next)?;
            *wirings = next;
        }
        Ok(removed)
    }

    /// Wirings die with their agent. Returns how many were removed.
    pub fn remove_for_client(&self, client_id: &Uuid) -> Result<usize> {
        let mut wirings = self.wirings.lock().unwrap();
        let mut next = wirings.clone();
        let before = next.len();
        next.retain(|w| &w.client_id != client_id);
        let removed = before - next.len();
        if removed > 0 {
            self.persist(&next)?;
            *wirings = next;
        }
        Ok(removed)
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

    fn table() -> (Wirings, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let w = Wirings::open(dir.path().join("wirings.json"), integrity()).unwrap();
        (w, dir)
    }

    #[test]
    fn unwired_refused_wired_allowed() {
        let (w, _dir) = table();
        let conn = Uuid::new_v4();
        let claude = Uuid::new_v4();
        let codex = Uuid::new_v4();
        assert!(!w.is_wired(&claude, &conn));
        w.wire(claude, "claude-code", conn).unwrap();
        assert!(w.is_wired(&claude, &conn));
        // Keyed on both halves.
        assert!(!w.is_wired(&codex, &conn));
        assert!(!w.is_wired(&claude, &Uuid::new_v4()));
    }

    #[test]
    fn wirings_default_to_read_write_and_mode_is_settable() {
        let (w, _dir) = table();
        let conn = Uuid::new_v4();
        let claude = Uuid::new_v4();
        // A fresh wiring is full access.
        w.wire(claude, "claude-code", conn).unwrap();
        assert_eq!(w.mode(&claude, &conn), Some(WiringMode::ReadWrite));
        // Attenuate it.
        let updated = w
            .set_mode(&claude, &conn, WiringMode::ReadOnly)
            .unwrap()
            .expect("wiring exists");
        assert_eq!(updated.mode, WiringMode::ReadOnly);
        assert_eq!(w.mode(&claude, &conn), Some(WiringMode::ReadOnly));
        // Unwired pairs have no mode, and setting one is a no-op.
        assert_eq!(w.mode(&claude, &Uuid::new_v4()), None);
        assert!(w
            .set_mode(&Uuid::new_v4(), &conn, WiringMode::ReadOnly)
            .unwrap()
            .is_none());
    }

    #[test]
    fn mode_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wirings.json");
        let conn = Uuid::new_v4();
        let client = Uuid::new_v4();
        let integrity = integrity();
        {
            let w = Wirings::open(path.clone(), integrity.clone()).unwrap();
            w.wire(client, "claude-code", conn).unwrap();
            w.set_mode(&client, &conn, WiringMode::ReadOnly).unwrap();
        }
        let w = Wirings::open(path, integrity).unwrap();
        assert_eq!(w.mode(&client, &conn), Some(WiringMode::ReadOnly));
    }

    #[test]
    fn wirings_without_a_mode_field_load_as_read_write() {
        // A wirings.json written before attenuation has no `mode` key.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wirings.json");
        let integrity = integrity();
        let client = Uuid::new_v4();
        let conn = Uuid::new_v4();
        let legacy = serde_json::json!([
            {"id": Uuid::new_v4(), "client_id": client, "agent": "claude-code",
             "connection_id": conn, "created_at": Utc::now()}
        ]);
        integrity
            .write(&path, &serde_json::to_vec_pretty(&legacy).unwrap())
            .unwrap();
        let w = Wirings::open(path, integrity).unwrap();
        assert_eq!(w.mode(&client, &conn), Some(WiringMode::ReadWrite));
    }

    #[test]
    fn wire_is_idempotent() {
        let (w, _dir) = table();
        let conn = Uuid::new_v4();
        let client = Uuid::new_v4();
        let a = w.wire(client, "claude-code", conn).unwrap();
        let b = w.wire(client, "claude-code", conn).unwrap();
        assert_eq!(a.id, b.id);
        assert_eq!(w.wirings().len(), 1);
    }

    #[test]
    fn unwire_removes_exactly_one_pair() {
        let (w, _dir) = table();
        let conn = Uuid::new_v4();
        let claude = Uuid::new_v4();
        let codex = Uuid::new_v4();
        w.wire(claude, "claude-code", conn).unwrap();
        w.wire(codex, "codex", conn).unwrap();
        assert!(w.unwire(&claude, &conn).unwrap().is_some());
        assert!(w.unwire(&claude, &conn).unwrap().is_none());
        assert!(w.is_wired(&codex, &conn));
    }

    #[test]
    fn wirings_die_with_their_connection() {
        let (w, _dir) = table();
        let conn = Uuid::new_v4();
        w.wire(Uuid::new_v4(), "claude-code", conn).unwrap();
        w.wire(Uuid::new_v4(), "codex", conn).unwrap();
        w.wire(Uuid::new_v4(), "codex", Uuid::new_v4()).unwrap();
        assert_eq!(w.remove_for_connection(&conn).unwrap(), 2);
        assert_eq!(w.wirings().len(), 1);
    }

    #[test]
    fn wirings_die_with_their_client() {
        let (w, _dir) = table();
        let claude = Uuid::new_v4();
        w.wire(claude, "claude-code", Uuid::new_v4()).unwrap();
        w.wire(claude, "claude-code", Uuid::new_v4()).unwrap();
        w.wire(Uuid::new_v4(), "codex", Uuid::new_v4()).unwrap();
        assert_eq!(w.remove_for_client(&claude).unwrap(), 2);
        assert_eq!(w.wirings().len(), 1);
        assert_eq!(w.wirings()[0].agent, "codex");
    }

    #[test]
    fn wire_all_persists_once_and_skips_existing() {
        let (w, _dir) = table();
        let client = Uuid::new_v4();
        let existing = Uuid::new_v4();
        w.wire(client, "claude-code", existing).unwrap();
        let added = w
            .wire_all(
                client,
                "claude-code",
                &[existing, Uuid::new_v4(), Uuid::new_v4()],
            )
            .unwrap();
        assert_eq!(added.len(), 2);
        assert_eq!(w.wirings().len(), 3);
    }

    #[test]
    fn wirings_persist_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wirings.json");
        let conn = Uuid::new_v4();
        let client = Uuid::new_v4();
        let integrity = integrity();
        {
            let w = Wirings::open(path.clone(), integrity.clone()).unwrap();
            w.wire(client, "claude-code", conn).unwrap();
        }
        let w = Wirings::open(path, integrity).unwrap();
        assert!(w.is_wired(&client, &conn));
    }

    #[test]
    fn failed_writes_do_not_change_active_wirings() {
        let (w, dir) = table();
        let path = dir.path().join("wirings.json");
        let conn = Uuid::new_v4();
        let client = Uuid::new_v4();
        let existing = w.wire(client, "claude-code", conn).unwrap();
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();

        assert!(w.wire(Uuid::new_v4(), "codex", Uuid::new_v4()).is_err());
        assert_eq!(w.wirings(), vec![existing.clone()]);
        assert!(w.is_wired(&client, &conn));

        assert!(w.unwire(&client, &conn).is_err());
        assert_eq!(w.wirings(), vec![existing]);
        assert!(w.is_wired(&client, &conn));
    }

    #[test]
    fn legacy_rules_migrate_into_wirings() {
        let dir = tempfile::tempdir().unwrap();
        let wirings_path = dir.path().join("wirings.json");
        let rules_path = dir.path().join("rules.json");
        let integrity = integrity();
        let client = Uuid::new_v4();
        let connection = Uuid::new_v4();
        let legacy = serde_json::json!([
            {"id": Uuid::new_v4(), "client_id": client, "agent": "claude-code",
             "connection_id": connection, "scope": "read", "created_at": Utc::now()},
            // Duplicate pair under a different scope collapses to one wiring.
            {"id": Uuid::new_v4(), "client_id": client, "agent": "claude-code",
             "connection_id": connection, "scope": "full", "created_at": Utc::now()},
            // Un-migrated legacy rows (nil client) are dropped.
            {"id": Uuid::new_v4(), "agent": "orphan",
             "connection_id": Uuid::new_v4(), "created_at": Utc::now()}
        ]);
        integrity
            .write(&rules_path, &serde_json::to_vec_pretty(&legacy).unwrap())
            .unwrap();

        let w = Wirings::open_with_legacy_rules(
            wirings_path.clone(),
            Some(&rules_path),
            integrity.clone(),
        )
        .unwrap();
        assert_eq!(w.wirings().len(), 1);
        assert!(w.is_wired(&client, &connection));

        // The converted table persisted: a reopen without the legacy file
        // sees the same wirings.
        let reopened = Wirings::open(wirings_path, integrity).unwrap();
        assert!(reopened.is_wired(&client, &connection));
    }
}
