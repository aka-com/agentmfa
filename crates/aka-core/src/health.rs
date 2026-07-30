//! Last-known connection health.
//!
//! A small persisted map of connection id → the outcome of the most recent
//! check: an explicit UI-initiated test, or a brokered call that proved
//! (or disproved) the credential in passing. Advisory display state: it never
//! participates in authorization, so it lives in its own file rather than in
//! the index.
//!
//! It is sealed all the same. A green badge is what the user reads to decide
//! a tool is fine, and a local process that could paint one — or hide a
//! `NeedsReconnect` behind it — would be lying to them in the one place they
//! look. Being advisory changes the *response*, not the protection: a file
//! that fails verification is discarded and reported rather than refusing to
//! start, because health is re-learnable and no authorization rests on it.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use chrono::Utc;
use uuid::Uuid;

use crate::events::BrokerEvents;
use crate::integrity::StateIntegrity;
use crate::types::{ConnectionHealth, HealthStatus};

/// Consecutive upstream credential rejections required before a connection's
/// badge turns amber. One is not evidence: an API key that is valid but
/// unscoped for a single path answers 401/403 there and 200 everywhere else,
/// and a connection whose credential *works* must not be labelled "reconnect"
/// because one call reached a route it may not use.
const CREDENTIAL_REJECTION_CORROBORATION: u32 = 2;

pub struct HealthRegistry {
    path: PathBuf,
    map: Mutex<HashMap<Uuid, ConnectionHealth>>,
    /// Consecutive credential rejections per connection, cleared by any
    /// relayed success. Runtime only: a restart re-learns it, and the stored
    /// badge is whatever the last corroborated verdict was.
    rejections: Mutex<HashMap<Uuid, u32>>,
    events: Arc<dyn BrokerEvents>,
    integrity: Arc<StateIntegrity>,
    /// Set when the stored file failed verification and was discarded, so
    /// the broker can say so in the activity log once it is constructed.
    discarded: bool,
}

impl HealthRegistry {
    /// Load whatever the file holds. A missing file is an empty registry, and
    /// so is one that fails its seal — health is re-learnable, and refusing to
    /// start would turn a tampered advisory file into an outage.
    pub fn open(
        path: PathBuf,
        events: Arc<dyn BrokerEvents>,
        integrity: Arc<StateIntegrity>,
    ) -> Self {
        let (map, discarded) = match integrity.read_verified(&path) {
            Ok(Some(bytes)) => (serde_json::from_slice(&bytes).unwrap_or_default(), false),
            Ok(None) => (HashMap::new(), false),
            Err(error) => {
                tracing::error!("connection health did not verify, discarding: {error}");
                (HashMap::new(), true)
            }
        };
        Self {
            path,
            map: Mutex::new(map),
            rejections: Mutex::new(HashMap::new()),
            events,
            integrity,
            discarded,
        }
    }

    /// Whether the stored health file was discarded as unverifiable on open.
    pub fn was_discarded(&self) -> bool {
        self.discarded
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
        // A served response is proof the credential works, so it also clears
        // any half-accumulated rejection streak.
        self.rejections.lock().unwrap().remove(id);
        let already_ok = self.get(id).is_some_and(|h| h.status == HealthStatus::Ok);
        if !already_ok {
            self.record(id, HealthStatus::Ok, detail);
        }
    }

    /// Record an upstream credential rejection observed in passing on a
    /// brokered call, downgrading the badge only once a second consecutive
    /// rejection corroborates it.
    ///
    /// A single 401/403 is ambiguous in a way the Test button's is not: the
    /// agent chose the path, and a token that is merely unscoped for that one
    /// route is not a token the user needs to reconnect. Requiring corroboration
    /// keeps the amber badge meaning "this credential stopped working" instead
    /// of "an agent probed something it may not read". Returns whether the badge
    /// was downgraded.
    pub fn record_credential_rejection(&self, id: &Uuid, detail: impl Into<String>) -> bool {
        let corroborated = {
            let mut rejections = self.rejections.lock().unwrap();
            let seen = rejections.entry(*id).or_insert(0);
            *seen = seen.saturating_add(1);
            *seen >= CREDENTIAL_REJECTION_CORROBORATION
        };
        if corroborated {
            self.record_if_changed(id, HealthStatus::NeedsReconnect, detail);
        }
        corroborated
    }

    /// Record a failure only when it says something new. An unreachable
    /// upstream fails on every retry with the same message, and each write
    /// costs a file rewrite and a UI refresh; the same restraint the success
    /// path already shows applies to the loud side too. Status and detail are
    /// both compared, so a connection that starts failing differently — auth
    /// rejected rather than unreachable — still surfaces.
    pub fn record_if_changed(&self, id: &Uuid, status: HealthStatus, detail: impl Into<String>) {
        let detail = detail.into();
        let unchanged = self
            .get(id)
            .is_some_and(|h| h.status == status && h.detail == detail);
        if !unchanged {
            self.record(id, status, detail);
        }
    }

    /// Forget the passive rejection streak without touching the badge.
    ///
    /// Called when an explicit, user-initiated check produces an authoritative
    /// verdict: whatever the agent plane had half-observed is superseded, and
    /// the next passive rejection starts counting from scratch.
    pub fn clear_rejection_streak(&self, id: &Uuid) {
        self.rejections.lock().unwrap().remove(id);
    }

    /// Drop a connection's entry (deleted, or repointed at a new target —
    /// a result for the old destination must not describe the new one).
    pub fn forget(&self, id: &Uuid) {
        self.rejections.lock().unwrap().remove(id);
        let mut map = self.map.lock().unwrap();
        if map.remove(id).is_some() {
            self.persist(&map);
        }
    }

    fn persist(&self, map: &HashMap<Uuid, ConnectionHealth>) {
        match serde_json::to_vec_pretty(map) {
            Ok(bytes) => {
                if let Err(error) = self.integrity.write(&self.path, &bytes) {
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
    use crate::vault::MemoryVault;

    async fn integrity() -> Arc<StateIntegrity> {
        Arc::new(StateIntegrity::open(&MemoryVault::new()).await.unwrap())
    }

    #[tokio::test]
    async fn records_survive_reopen_and_forget_removes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("health.json");
        let seal = integrity().await;
        let id = Uuid::new_v4();
        {
            let registry = HealthRegistry::open(path.clone(), Arc::new(NoopEvents), seal.clone());
            registry.record(&id, HealthStatus::NeedsReconnect, "HTTP 401");
        }
        let registry = HealthRegistry::open(path.clone(), Arc::new(NoopEvents), seal.clone());
        let health = registry.get(&id).unwrap();
        assert_eq!(health.status, HealthStatus::NeedsReconnect);
        assert_eq!(health.detail, "HTTP 401");

        registry.forget(&id);
        let registry = HealthRegistry::open(path, Arc::new(NoopEvents), seal);
        assert!(registry.get(&id).is_none());
    }

    #[tokio::test]
    async fn ok_upgrade_only_writes_on_change() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("health.json");
        let registry = HealthRegistry::open(path, Arc::new(NoopEvents), integrity().await);
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

    /// Painting a badge green is the whole point of rewriting this file, so
    /// an edited one must not load — and must not take the broker down with
    /// it either, since nothing is authorized on the strength of it.
    #[tokio::test]
    async fn a_rewritten_file_is_discarded_not_trusted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("health.json");
        let seal = integrity().await;
        let id = Uuid::new_v4();
        let registry = HealthRegistry::open(path.clone(), Arc::new(NoopEvents), seal.clone());
        registry.record(&id, HealthStatus::NeedsReconnect, "HTTP 401");

        let sealed = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, sealed.replace("needs_reconnect", "ok")).unwrap();

        let reopened = HealthRegistry::open(path, Arc::new(NoopEvents), seal);
        assert!(reopened.was_discarded(), "the edit was noticed");
        assert!(
            reopened.get(&id).is_none(),
            "and the forged status did not survive it"
        );
    }
}
