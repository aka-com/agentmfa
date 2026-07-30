//! Per-connection agent access: the authorization table.
//!
//! There is one shared local identity, so authorization is a property of the
//! connection, not of an (agent, connection) pair: agents may use a
//! connection when it is **enabled** for them, and a disabled call is
//! refused (`403 denied_by_policy`). Connections are enabled by default —
//! adding a tool in the app is already a deliberate user action — so the
//! table records only the non-default states: agents switched off, or an
//! MCP tool subset curated. There are no prompts, scopes, or expiring
//! grants. Entries persist in `access.json`, sealed. Per-agent wirings
//! written by earlier versions (`wirings.json`) are collapsed on first open:
//! a connection any agent was wired to is enabled (tool subsets union), and
//! one no agent was wired to is disabled, preserving the install's aggregate
//! posture.

use std::path::PathBuf;
use std::sync::Arc;

use chrono::Utc;
use uuid::Uuid;

use crate::integrity::StateIntegrity;
use crate::types::{ConfirmMode, ToolAccess};
use crate::Result;

pub(crate) trait AccessGenerationStore: Send + Sync {
    fn access_generation(&self) -> u64;
    fn advance_access_generation(&self) -> Result<u64>;
}

#[derive(serde::Serialize, serde::Deserialize)]
struct AccessState {
    generation: u64,
    entries: Vec<ToolAccess>,
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum AccessStateRead {
    Current(AccessState),
    Legacy(Vec<ToolAccess>),
}

pub struct AccessTable {
    path: PathBuf,
    integrity: Arc<StateIntegrity>,
    entries: std::sync::Mutex<Vec<ToolAccess>>,
    generation: std::sync::atomic::AtomicU64,
    generation_store: Option<Arc<dyn AccessGenerationStore>>,
}

impl AccessTable {
    pub fn open(path: PathBuf, integrity: Arc<StateIntegrity>) -> Result<Self> {
        Self::open_with_legacy_wirings(path, None, &[], integrity)
    }

    /// Open `access.json`; when it does not exist yet and a legacy per-agent
    /// `wirings.json` does, collapse the wirings into per-connection access.
    /// `known_connections` names every connection in the store, so the ones
    /// no agent was wired to migrate as explicitly disabled (the old model's
    /// default) instead of inheriting the new enabled-by-default.
    pub fn open_with_legacy_wirings(
        path: PathBuf,
        legacy_wirings_path: Option<&std::path::Path>,
        known_connections: &[Uuid],
        integrity: Arc<StateIntegrity>,
    ) -> Result<Self> {
        Self::open_with_legacy_policy(
            path,
            legacy_wirings_path,
            None,
            known_connections,
            integrity,
        )
    }

    /// Open `access.json`, preferring the immediately preceding
    /// `wirings.json` representation but also accepting the older
    /// `rules.json` representation. Supporting both prevents a direct
    /// upgrade from losing its deny-by-default posture.
    pub fn open_with_legacy_policy(
        path: PathBuf,
        legacy_wirings_path: Option<&std::path::Path>,
        legacy_rules_path: Option<&std::path::Path>,
        known_connections: &[Uuid],
        integrity: Arc<StateIntegrity>,
    ) -> Result<Self> {
        Self::open_with_legacy_policy_and_generation(
            path,
            legacy_wirings_path,
            legacy_rules_path,
            known_connections,
            integrity,
            None,
        )
    }

    pub(crate) fn open_with_legacy_policy_and_generation(
        path: PathBuf,
        legacy_wirings_path: Option<&std::path::Path>,
        legacy_rules_path: Option<&std::path::Path>,
        known_connections: &[Uuid],
        integrity: Arc<StateIntegrity>,
        generation_store: Option<Arc<dyn AccessGenerationStore>>,
    ) -> Result<Self> {
        let expected_generation = generation_store
            .as_ref()
            .map_or(0, |store| store.access_generation());
        let loaded = integrity
            .read_verified(&path)?
            .map(|bytes| serde_json::from_slice::<AccessStateRead>(&bytes))
            .transpose()?;
        let (mut entries, generation, migrate_legacy_access) = match loaded {
            Some(AccessStateRead::Current(state)) => {
                match &generation_store {
                    Some(store) if state.generation.checked_sub(expected_generation) == Some(1) => {
                        // The sealed file is written before the index advances
                        // (see `persist`), so a file exactly one ahead is the
                        // interrupted-commit shape — never a rollback, which
                        // only ever leaves the file *behind*. Heal the index
                        // forward instead of refusing to start forever.
                        if store.advance_access_generation()? != state.generation {
                            return Err(crate::CoreError::StateTampered(
                                path.display().to_string(),
                            ));
                        }
                    }
                    Some(_) if state.generation != expected_generation => {
                        return Err(crate::CoreError::StateTampered(path.display().to_string()));
                    }
                    _ => {}
                }
                (Some(state.entries), state.generation, false)
            }
            Some(AccessStateRead::Legacy(entries)) => {
                if expected_generation != 0 {
                    return Err(crate::CoreError::StateTampered(path.display().to_string()));
                }
                (Some(entries), 0, true)
            }
            None => {
                if expected_generation != 0 {
                    return Err(crate::CoreError::StateTampered(path.display().to_string()));
                }
                (None, 0, false)
            }
        };
        let table = Self {
            path,
            integrity,
            entries: std::sync::Mutex::new(Vec::new()),
            generation: std::sync::atomic::AtomicU64::new(generation),
            generation_store,
        };
        let mut migrated_policy = false;
        if entries.is_none() {
            if let Some(wirings_path) = legacy_wirings_path {
                if let Some(bytes) = table.integrity.read_verified(wirings_path)? {
                    #[derive(serde::Deserialize)]
                    struct LegacyWiring {
                        connection_id: Uuid,
                        #[serde(default)]
                        allowed_tools: Option<Vec<String>>,
                    }
                    let wirings: Vec<LegacyWiring> = serde_json::from_slice(&bytes)?;
                    let mut migrated: Vec<ToolAccess> = Vec::new();
                    for connection_id in known_connections {
                        let wired: Vec<&LegacyWiring> = wirings
                            .iter()
                            .filter(|w| &w.connection_id == connection_id)
                            .collect();
                        if wired.is_empty() {
                            migrated.push(ToolAccess {
                                connection_id: *connection_id,
                                enabled: false,
                                allowed_tools: None,
                                confirm: ConfirmMode::Off,
                                expose_response_credentials: false,
                                audit_statements: None,
                                updated_at: Utc::now(),
                            });
                            continue;
                        }
                        // The union across agents was already the shared
                        // identity's effective power: any wiring with no
                        // subset means all tools; otherwise the subsets
                        // union.
                        let allowed_tools = if wired.iter().any(|w| w.allowed_tools.is_none()) {
                            None
                        } else {
                            let mut union: Vec<String> = wired
                                .iter()
                                .flat_map(|w| w.allowed_tools.iter().flatten().cloned())
                                .collect();
                            union.sort();
                            union.dedup();
                            Some(union)
                        };
                        migrated.push(ToolAccess {
                            connection_id: *connection_id,
                            enabled: true,
                            allowed_tools,
                            confirm: ConfirmMode::Off,
                            expose_response_credentials: false,
                            audit_statements: None,
                            updated_at: Utc::now(),
                        });
                    }
                    entries = Some(migrated);
                    migrated_policy = true;
                }
            }
        }
        if entries.is_none() {
            if let Some(rules_path) = legacy_rules_path {
                if let Some(bytes) = table.integrity.read_verified(rules_path)? {
                    #[derive(serde::Deserialize)]
                    struct LegacyRule {
                        #[serde(default)]
                        client_id: Uuid,
                        connection_id: Uuid,
                    }
                    let rules: Vec<LegacyRule> = serde_json::from_slice(&bytes)?;
                    let migrated: Vec<ToolAccess> = known_connections
                        .iter()
                        .map(|connection_id| ToolAccess {
                            connection_id: *connection_id,
                            enabled: rules.iter().any(|rule| {
                                !rule.client_id.is_nil() && &rule.connection_id == connection_id
                            }),
                            allowed_tools: None,
                            confirm: ConfirmMode::Off,
                            expose_response_credentials: false,
                            audit_statements: None,
                            updated_at: Utc::now(),
                        })
                        .collect();
                    entries = Some(migrated);
                    migrated_policy = true;
                }
            }
        }
        let entries = entries.unwrap_or_default();
        if migrate_legacy_access || migrated_policy {
            table.persist(&entries)?;
        }
        *table.entries.lock().unwrap() = entries;
        Ok(table)
    }

    fn persist(&self, entries: &[ToolAccess]) -> Result<()> {
        let generation = self
            .generation
            .load(std::sync::atomic::Ordering::SeqCst)
            .checked_add(1)
            .ok_or_else(|| crate::CoreError::InvalidSetting("access generation overflow".into()))?;
        let state = AccessState {
            generation,
            entries: entries.to_vec(),
        };
        // File first, index second: the two sealed writes cannot be atomic,
        // and a crash (or plain write failure) between them must leave a
        // shape `open` can tell apart from tampering. File-one-ahead is that
        // shape, and it heals. The reverse order left an index the file could
        // never catch up to — a permanent, false `StateTampered` wall on
        // every later start, with both files MAC-sealed beyond hand repair.
        self.integrity
            .write(&self.path, &serde_json::to_vec_pretty(&state)?)?;
        if let Some(store) = &self.generation_store {
            if store.advance_access_generation()? != generation {
                return Err(crate::CoreError::InvalidSetting(
                    "access generation skew".into(),
                ));
            }
        }
        self.generation
            .store(generation, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    /// Whether agents may use the connection. No entry means enabled.
    pub fn allows(&self, connection_id: &Uuid) -> bool {
        self.entries
            .lock()
            .unwrap()
            .iter()
            .find(|e| &e.connection_id == connection_id)
            .map(|e| e.enabled)
            .unwrap_or(true)
    }

    /// The curated MCP tool subset for a connection; `None` means every
    /// tool (including when no entry exists).
    pub fn allowed_tools(&self, connection_id: &Uuid) -> Option<Vec<String>> {
        self.entries
            .lock()
            .unwrap()
            .iter()
            .find(|e| &e.connection_id == connection_id)
            .and_then(|e| e.allowed_tools.clone())
    }

    /// Whether traffic on this connection is confirmed with the user. No
    /// entry means off, the behaviour every connection had before the
    /// switch existed.
    pub fn confirm_mode(&self, connection_id: &Uuid) -> ConfirmMode {
        self.entries
            .lock()
            .unwrap()
            .iter()
            .find(|e| &e.connection_id == connection_id)
            .map(|e| e.confirm)
            .unwrap_or_default()
    }

    /// Whether response headers that can create or negotiate credentials may
    /// cross the broker boundary. No entry and older entries both mean no.
    pub fn expose_response_credentials(&self, connection_id: &Uuid) -> bool {
        self.entries
            .lock()
            .unwrap()
            .iter()
            .find(|entry| &entry.connection_id == connection_id)
            .is_some_and(|entry| entry.expose_response_credentials)
    }

    /// The recorded entry for a connection, when one exists (i.e. the
    /// connection has left the default state at least once).
    pub fn entry(&self, connection_id: &Uuid) -> Option<ToolAccess> {
        self.entries
            .lock()
            .unwrap()
            .iter()
            .find(|e| &e.connection_id == connection_id)
            .cloned()
    }

    pub fn entries(&self) -> Vec<ToolAccess> {
        self.entries.lock().unwrap().clone()
    }

    /// Enable or disable agent access for a connection. Returns whether the
    /// effective state changed.
    pub fn set_enabled(&self, connection_id: Uuid, enabled: bool) -> Result<bool> {
        let mut entries = self.entries.lock().unwrap();
        let current = entries
            .iter()
            .find(|e| e.connection_id == connection_id)
            .map(|e| e.enabled)
            .unwrap_or(true);
        if current == enabled {
            return Ok(false);
        }
        let mut next = entries.clone();
        match next.iter_mut().find(|e| e.connection_id == connection_id) {
            Some(entry) => {
                entry.enabled = enabled;
                entry.updated_at = Utc::now();
            }
            None => next.push(ToolAccess {
                connection_id,
                enabled,
                allowed_tools: None,
                confirm: ConfirmMode::Off,
                expose_response_credentials: false,
                audit_statements: None,
                updated_at: Utc::now(),
            }),
        }
        self.persist(&next)?;
        *entries = next;
        Ok(true)
    }

    /// Set (or clear, with `None`) the connection's allowed upstream MCP
    /// tools. Returns whether anything changed.
    pub fn set_allowed_tools(
        &self,
        connection_id: Uuid,
        tools: Option<Vec<String>>,
    ) -> Result<bool> {
        let mut entries = self.entries.lock().unwrap();
        let current = entries
            .iter()
            .find(|e| e.connection_id == connection_id)
            .and_then(|e| e.allowed_tools.clone());
        if current == tools {
            return Ok(false);
        }
        let mut next = entries.clone();
        match next.iter_mut().find(|e| e.connection_id == connection_id) {
            Some(entry) => {
                entry.allowed_tools = tools;
                entry.updated_at = Utc::now();
            }
            None => next.push(ToolAccess {
                connection_id,
                enabled: true,
                allowed_tools: tools,
                confirm: ConfirmMode::Off,
                expose_response_credentials: false,
                audit_statements: None,
                updated_at: Utc::now(),
            }),
        }
        self.persist(&next)?;
        *entries = next;
        Ok(true)
    }

    /// Ask for (or stop asking for) confirmation on this connection's
    /// traffic. Returns whether the effective state changed.
    pub fn set_confirm_mode(&self, connection_id: Uuid, confirm: ConfirmMode) -> Result<bool> {
        let mut entries = self.entries.lock().unwrap();
        let current = entries
            .iter()
            .find(|e| e.connection_id == connection_id)
            .map(|e| e.confirm)
            .unwrap_or_default();
        if current == confirm {
            return Ok(false);
        }
        let mut next = entries.clone();
        match next.iter_mut().find(|e| e.connection_id == connection_id) {
            Some(entry) => {
                entry.confirm = confirm;
                entry.updated_at = Utc::now();
            }
            None => next.push(ToolAccess {
                connection_id,
                enabled: true,
                allowed_tools: None,
                confirm,
                expose_response_credentials: false,
                audit_statements: None,
                updated_at: Utc::now(),
            }),
        }
        self.persist(&next)?;
        *entries = next;
        Ok(true)
    }

    /// Allow or contain upstream response credentials for this connection.
    /// False is the default and the value older policy records imply.
    pub fn set_expose_response_credentials(
        &self,
        connection_id: Uuid,
        expose: bool,
    ) -> Result<bool> {
        let mut entries = self.entries.lock().unwrap();
        let current = entries
            .iter()
            .find(|entry| entry.connection_id == connection_id)
            .is_some_and(|entry| entry.expose_response_credentials);
        if current == expose {
            return Ok(false);
        }
        let mut next = entries.clone();
        match next
            .iter_mut()
            .find(|entry| entry.connection_id == connection_id)
        {
            Some(entry) => {
                entry.expose_response_credentials = expose;
                entry.updated_at = Utc::now();
            }
            None => next.push(ToolAccess {
                connection_id,
                enabled: true,
                allowed_tools: None,
                confirm: ConfirmMode::default(),
                expose_response_credentials: expose,
                audit_statements: None,
                updated_at: Utc::now(),
            }),
        }
        self.persist(&next)?;
        *entries = next;
        Ok(true)
    }

    /// Whether this connection records statement text, given the broker-wide
    /// default. An entry with no override inherits it.
    pub fn audit_statements(&self, connection_id: &Uuid, default: bool) -> bool {
        self.entries
            .lock()
            .unwrap()
            .iter()
            .find(|e| &e.connection_id == connection_id)
            .and_then(|e| e.audit_statements)
            .unwrap_or(default)
    }

    /// Override statement recording for one connection; `None` restores the
    /// broker-wide default. Returns whether the stored override changed.
    pub fn set_audit_statements(
        &self,
        connection_id: Uuid,
        audit_statements: Option<bool>,
    ) -> Result<bool> {
        let mut entries = self.entries.lock().unwrap();
        let current = entries
            .iter()
            .find(|e| e.connection_id == connection_id)
            .and_then(|e| e.audit_statements);
        if current == audit_statements {
            return Ok(false);
        }
        let mut next = entries.clone();
        match next.iter_mut().find(|e| e.connection_id == connection_id) {
            Some(entry) => {
                entry.audit_statements = audit_statements;
                entry.updated_at = Utc::now();
            }
            None => next.push(ToolAccess {
                connection_id,
                enabled: true,
                allowed_tools: None,
                confirm: ConfirmMode::default(),
                expose_response_credentials: false,
                audit_statements,
                updated_at: Utc::now(),
            }),
        }
        self.persist(&next)?;
        *entries = next;
        Ok(true)
    }

    /// Access records die with their connection. Returns whether one existed.
    pub fn remove_for_connection(&self, connection_id: &Uuid) -> Result<bool> {
        let mut entries = self.entries.lock().unwrap();
        let mut next = entries.clone();
        let before = next.len();
        next.retain(|e| &e.connection_id != connection_id);
        let removed = next.len() != before;
        if removed {
            self.persist(&next)?;
            *entries = next;
        }
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn integrity() -> Arc<StateIntegrity> {
        Arc::new(
            futures::executor::block_on(StateIntegrity::open(&crate::vault::MemoryVault::new()))
                .unwrap(),
        )
    }

    fn table() -> (AccessTable, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let t = AccessTable::open(dir.path().join("access.json"), integrity()).unwrap();
        (t, dir)
    }

    #[derive(Default)]
    struct TestGeneration(AtomicU64);

    impl AccessGenerationStore for TestGeneration {
        fn access_generation(&self) -> u64 {
            self.0.load(Ordering::SeqCst)
        }

        fn advance_access_generation(&self) -> Result<u64> {
            Ok(self.0.fetch_add(1, Ordering::SeqCst) + 1)
        }
    }

    #[test]
    fn connections_default_to_enabled() {
        let (t, _dir) = table();
        let conn = Uuid::new_v4();
        assert!(t.allows(&conn));
        assert_eq!(t.allowed_tools(&conn), None);
        assert!(t.entry(&conn).is_none());
    }

    /// P6. Statement recording is a per-destination retention choice layered
    /// over the operator's broker-wide default: no override follows the
    /// default whichever way it is set, and an override wins over it in both
    /// directions until explicitly dropped.
    #[test]
    fn statement_recording_overrides_the_broker_default_in_both_directions() {
        let (t, _dir) = table();
        let conn = Uuid::new_v4();

        // No entry at all: whatever the operator launched with.
        assert!(!t.audit_statements(&conn, false));
        assert!(t.audit_statements(&conn, true));

        // Opt one connection in while the broker default is off.
        assert!(t.set_audit_statements(conn, Some(true)).unwrap());
        assert!(t.audit_statements(&conn, false));
        assert!(!t.set_audit_statements(conn, Some(true)).unwrap());

        // And opt one out while the default is on — the direction that makes
        // this a retention control rather than a convenience.
        assert!(t.set_audit_statements(conn, Some(false)).unwrap());
        assert!(!t.audit_statements(&conn, true));

        // Dropping the override returns the connection to the default.
        assert!(t.set_audit_statements(conn, None).unwrap());
        assert!(t.audit_statements(&conn, true));
        assert!(!t.audit_statements(&conn, false));
        assert_eq!(t.entry(&conn).unwrap().audit_statements, None);
    }

    /// The override is orthogonal to access: setting it must not disturb the
    /// enabled flag or a curated tool subset sharing the same record.
    #[test]
    fn statement_recording_leaves_the_rest_of_the_entry_alone() {
        let (t, _dir) = table();
        let conn = Uuid::new_v4();
        t.set_enabled(conn, false).unwrap();
        t.set_allowed_tools(conn, Some(vec!["search".into()])).unwrap();

        t.set_audit_statements(conn, Some(true)).unwrap();
        assert!(!t.allows(&conn));
        assert_eq!(t.allowed_tools(&conn), Some(vec!["search".into()]));
        assert!(t.audit_statements(&conn, false));
    }

    #[test]
    fn disable_and_reenable_round_trip() {
        let (t, _dir) = table();
        let conn = Uuid::new_v4();
        assert!(t.set_enabled(conn, false).unwrap());
        assert!(!t.allows(&conn));
        // Idempotent: no change reported.
        assert!(!t.set_enabled(conn, false).unwrap());
        assert!(t.set_enabled(conn, true).unwrap());
        assert!(t.allows(&conn));
    }

    #[test]
    fn allowed_tools_survive_toggling() {
        let (t, _dir) = table();
        let conn = Uuid::new_v4();
        assert!(t
            .set_allowed_tools(conn, Some(vec!["search".into(), "fetch".into()]))
            .unwrap());
        assert!(t.set_enabled(conn, false).unwrap());
        assert!(t.set_enabled(conn, true).unwrap());
        assert_eq!(
            t.allowed_tools(&conn),
            Some(vec!["search".into(), "fetch".into()])
        );
        assert!(t.set_allowed_tools(conn, None).unwrap());
        assert_eq!(t.allowed_tools(&conn), None);
    }

    #[test]
    fn confirmation_defaults_off_and_survives_toggling_access() {
        let (t, _dir) = table();
        let conn = Uuid::new_v4();
        assert_eq!(t.confirm_mode(&conn), ConfirmMode::Off);
        assert!(t.set_confirm_mode(conn, ConfirmMode::On).unwrap());
        assert!(!t.set_confirm_mode(conn, ConfirmMode::On).unwrap());
        assert_eq!(t.confirm_mode(&conn), ConfirmMode::On);

        // Switching agents off and back on is about access, not about how
        // the traffic that access allows is confirmed.
        t.set_enabled(conn, false).unwrap();
        t.set_enabled(conn, true).unwrap();
        assert_eq!(t.confirm_mode(&conn), ConfirmMode::On);

        assert!(t.set_confirm_mode(conn, ConfirmMode::Off).unwrap());
        assert_eq!(t.confirm_mode(&conn), ConfirmMode::Off);
    }

    #[test]
    fn response_credentials_default_to_contained_and_persist_independently() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("access.json");
        let conn = Uuid::new_v4();
        let integrity = integrity();
        {
            let table = AccessTable::open(path.clone(), integrity.clone()).unwrap();
            assert!(!table.expose_response_credentials(&conn));
            assert!(table.set_expose_response_credentials(conn, true).unwrap());
            assert!(!table.set_expose_response_credentials(conn, true).unwrap());
            table.set_enabled(conn, false).unwrap();
        }
        let table = AccessTable::open(path, integrity).unwrap();
        assert!(table.expose_response_credentials(&conn));
        assert!(!table.allows(&conn));
        assert!(table.set_expose_response_credentials(conn, false).unwrap());
        assert!(!table.expose_response_credentials(&conn));
    }

    #[test]
    fn entries_persist_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("access.json");
        let conn = Uuid::new_v4();
        let integrity = integrity();
        {
            let t = AccessTable::open(path.clone(), integrity.clone()).unwrap();
            t.set_enabled(conn, false).unwrap();
        }
        let t = AccessTable::open(path, integrity).unwrap();
        assert!(!t.allows(&conn));
    }

    #[test]
    fn records_die_with_their_connection() {
        let (t, _dir) = table();
        let conn = Uuid::new_v4();
        t.set_enabled(conn, false).unwrap();
        assert!(t.remove_for_connection(&conn).unwrap());
        assert!(!t.remove_for_connection(&conn).unwrap());
        // Back to the default.
        assert!(t.allows(&conn));
    }

    #[test]
    fn failed_writes_do_not_change_active_entries() {
        let (t, dir) = table();
        let path = dir.path().join("access.json");
        let conn = Uuid::new_v4();
        t.set_enabled(conn, false).unwrap();
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();

        assert!(t.set_enabled(Uuid::new_v4(), false).is_err());
        assert!(!t.allows(&conn));
        assert!(t.set_enabled(conn, true).is_err());
        assert!(!t.allows(&conn));
    }

    #[test]
    fn a_missing_or_rolled_back_access_table_fails_closed_once_persisted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("access.json");
        let backup = dir.path().join("access-old.json");
        let integrity = integrity();
        let generation = Arc::new(TestGeneration::default());
        let conn = Uuid::new_v4();
        let table = AccessTable::open_with_legacy_policy_and_generation(
            path.clone(),
            None,
            None,
            &[conn],
            integrity.clone(),
            Some(generation.clone()),
        )
        .unwrap();
        table.set_enabled(conn, false).unwrap();
        std::fs::copy(&path, &backup).unwrap();
        table
            .set_allowed_tools(conn, Some(vec!["read".into()]))
            .unwrap();

        // A validly sealed older generation is still a rollback.
        std::fs::copy(&backup, &path).unwrap();
        assert!(matches!(
            AccessTable::open_with_legacy_policy_and_generation(
                path.clone(),
                None,
                None,
                &[conn],
                integrity.clone(),
                Some(generation.clone()),
            ),
            Err(crate::CoreError::StateTampered(_))
        ));

        std::fs::remove_file(&path).unwrap();
        assert!(matches!(
            AccessTable::open_with_legacy_policy_and_generation(
                path,
                None,
                None,
                &[conn],
                integrity,
                Some(generation),
            ),
            Err(crate::CoreError::StateTampered(_))
        ));
    }

    #[test]
    fn legacy_wirings_collapse_preserving_aggregate_posture() {
        let dir = tempfile::tempdir().unwrap();
        let access_path = dir.path().join("access.json");
        let wirings_path = dir.path().join("wirings.json");
        let integrity = integrity();
        let wired_all = Uuid::new_v4(); // one wiring with no subset
        let wired_curated = Uuid::new_v4(); // two wirings with subsets
        let unwired = Uuid::new_v4(); // no wirings at all
        let legacy = serde_json::json!([
            {"id": Uuid::new_v4(), "client_id": Uuid::new_v4(), "agent": "claude-code",
             "connection_id": wired_all, "created_at": Utc::now()},
            {"id": Uuid::new_v4(), "client_id": Uuid::new_v4(), "agent": "claude-code",
             "connection_id": wired_curated, "allowed_tools": ["search"],
             "created_at": Utc::now()},
            {"id": Uuid::new_v4(), "client_id": Uuid::new_v4(), "agent": "codex",
             "connection_id": wired_curated, "allowed_tools": ["fetch", "search"],
             "created_at": Utc::now()},
        ]);
        integrity
            .write(&wirings_path, &serde_json::to_vec_pretty(&legacy).unwrap())
            .unwrap();

        let t = AccessTable::open_with_legacy_wirings(
            access_path.clone(),
            Some(&wirings_path),
            &[wired_all, wired_curated, unwired],
            integrity.clone(),
        )
        .unwrap();
        assert!(t.allows(&wired_all));
        assert_eq!(t.allowed_tools(&wired_all), None);
        assert!(t.allows(&wired_curated));
        assert_eq!(
            t.allowed_tools(&wired_curated),
            Some(vec!["fetch".into(), "search".into()])
        );
        // Never wired → migrates as disabled, preserving the old default.
        assert!(!t.allows(&unwired));

        // The collapsed table persisted: a reopen without the legacy file
        // sees the same posture.
        let reopened = AccessTable::open(access_path, integrity).unwrap();
        assert!(!reopened.allows(&unwired));
        assert!(reopened.allows(&wired_all));
    }

    #[test]
    fn legacy_rules_collapse_preserving_deny_by_default() {
        let dir = tempfile::tempdir().unwrap();
        let access_path = dir.path().join("access.json");
        let rules_path = dir.path().join("rules.json");
        let integrity = integrity();
        let granted = Uuid::new_v4();
        let not_granted = Uuid::new_v4();
        let legacy = serde_json::json!([{
            "id": Uuid::new_v4(),
            "client_id": Uuid::new_v4(),
            "agent": "claude-code",
            "connection_id": granted,
            "scope": {"kind": "standing"},
            "created_at": Utc::now(),
        }]);
        integrity
            .write(&rules_path, &serde_json::to_vec_pretty(&legacy).unwrap())
            .unwrap();

        let table = AccessTable::open_with_legacy_policy(
            access_path.clone(),
            None,
            Some(&rules_path),
            &[granted, not_granted],
            integrity.clone(),
        )
        .unwrap();
        assert!(table.allows(&granted));
        assert!(!table.allows(&not_granted));

        let reopened = AccessTable::open(access_path, integrity).unwrap();
        assert!(reopened.allows(&granted));
        assert!(!reopened.allows(&not_granted));
    }

    #[test]
    fn malformed_legacy_rules_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let rules_path = dir.path().join("rules.json");
        let integrity = integrity();
        integrity.write(&rules_path, b"{}").unwrap();

        assert!(AccessTable::open_with_legacy_policy(
            dir.path().join("access.json"),
            None,
            Some(&rules_path),
            &[Uuid::new_v4()],
            integrity,
        )
        .is_err());
    }
}
