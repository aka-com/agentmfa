//! Last-known connection health.
//!
//! A small persisted map of connection id → the outcome of the most recent
//! check: an explicit UI-initiated test, or a brokered call that proved
//! (or disproved) the credential in passing. Advisory display state only —
//! it never participates in authorization — so it lives in its own
//! best-effort file rather than the integrity-sealed index.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use chrono::Utc;
use uuid::Uuid;

use crate::events::BrokerEvents;
use crate::types::{ConnectionHealth, HealthStatus};

pub struct HealthRegistry {
    path: PathBuf,
    map: Mutex<HashMap<Uuid, ConnectionHealth>>,
    events: Arc<dyn BrokerEvents>,
}

impl HealthRegistry {
    /// Load whatever the file holds; a missing or unreadable file is an
    /// empty registry (health is re-learnable, never worth failing startup).
    pub fn open(path: PathBuf, events: Arc<dyn BrokerEvents>) -> Self {
        let map = std::fs::read(&path)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default();
        Self {
            path,
            map: Mutex::new(map),
            events,
        }
    }

    pub fn get(&self, id: &Uuid) -> Option<ConnectionHealth> {
        self.map.lock().unwrap().get(id).cloned()
    }

    /// Record a check outcome and notify the UI. Persisting is best-effort;
    /// the in-memory state is authoritative for this process's lifetime.
    pub fn record(&self, id: &Uuid, status: HealthStatus, detail: impl Into<String>) {
        let entry = ConnectionHealth {
            status,
            detail: detail.into(),
            checked_at: Utc::now(),
        };
        {
            let mut map = self.map.lock().unwrap();
            map.insert(*id, entry);
            self.persist(&map);
        }
        self.events.connections_changed();
    }

    /// Upgrade to Ok only when the connection is not already Ok — brokered
    /// calls succeed constantly and must not rewrite the file per request.
    pub fn record_ok_if_changed(&self, id: &Uuid, detail: impl Into<String>) {
        let already_ok = self.get(id).is_some_and(|h| h.status == HealthStatus::Ok);
        if !already_ok {
            self.record(id, HealthStatus::Ok, detail);
        }
    }

    /// Drop a connection's entry (deleted, or repointed at a new target —
    /// a result for the old destination must not describe the new one).
    pub fn forget(&self, id: &Uuid) {
        let mut map = self.map.lock().unwrap();
        if map.remove(id).is_some() {
            self.persist(&map);
        }
    }

    fn persist(&self, map: &HashMap<Uuid, ConnectionHealth>) {
        match serde_json::to_vec_pretty(map) {
            Ok(bytes) => {
                if let Err(error) = std::fs::write(&self.path, bytes) {
                    tracing::warn!("could not persist connection health: {error}");
                }
            }
            Err(error) => tracing::warn!("could not serialize connection health: {error}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::NoopEvents;

    #[test]
    fn records_survive_reopen_and_forget_removes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("health.json");
        let id = Uuid::new_v4();
        {
            let registry = HealthRegistry::open(path.clone(), Arc::new(NoopEvents));
            registry.record(&id, HealthStatus::NeedsReconnect, "HTTP 401");
        }
        let registry = HealthRegistry::open(path.clone(), Arc::new(NoopEvents));
        let health = registry.get(&id).unwrap();
        assert_eq!(health.status, HealthStatus::NeedsReconnect);
        assert_eq!(health.detail, "HTTP 401");

        registry.forget(&id);
        let registry = HealthRegistry::open(path, Arc::new(NoopEvents));
        assert!(registry.get(&id).is_none());
    }

    #[test]
    fn ok_upgrade_only_writes_on_change() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("health.json");
        let registry = HealthRegistry::open(path, Arc::new(NoopEvents));
        let id = Uuid::new_v4();
        registry.record_ok_if_changed(&id, "answered");
        let first = registry.get(&id).unwrap();
        registry.record_ok_if_changed(&id, "answered again");
        let second = registry.get(&id).unwrap();
        assert_eq!(first, second, "an Ok entry is not rewritten");

        registry.record(&id, HealthStatus::Failed, "timeout");
        registry.record_ok_if_changed(&id, "recovered");
        assert_eq!(registry.get(&id).unwrap().status, HealthStatus::Ok);
    }
}
