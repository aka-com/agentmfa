//! The direct-endpoint registry: per-wiring stable endpoints and their
//! secrets.
//!
//! A [`WiringEndpoint`] is an *artifact of a wiring* — one persistent
//! listener + secret an agent keeps in its own config so it can reach a tool
//! with an unmodified client (a DSN pasted into `psql`, a socket in
//! `~/.ssh/config`) instead of round-tripping the control plane for a
//! short-lived ticket on every session.
//!
//! Because a stable endpoint is standing access, the security model differs
//! from a ticket in exactly two ways, both enforced here plus at the listener:
//!
//! - **Attribution requires a secret.** On a single-user box neither a
//!   loopback port nor a socket path separates one same-user process from
//!   another, so the endpoint carries a per-wiring secret the caller presents
//!   (like the bearer token). It is persisted only as a SHA-256 hash;
//!   [`EndpointRegistry::resolve_secret`] is how a listener authenticates a
//!   presented secret back to its wiring.
//! - **Revocation must be prompt and total.** Endpoints die with their wiring:
//!   [`remove_for_connection`](EndpointRegistry::remove_for_connection),
//!   [`remove_for_client`](EndpointRegistry::remove_for_client), and
//!   [`remove_for_wiring`](EndpointRegistry::remove_for_wiring) return the
//!   removed records so the caller can tear down the live listener and close
//!   any established sessions.
//!
//! Persisted in `endpoints.json`, sealed by the same integrity key as the
//! wiring table and pairing registry.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use chrono::Utc;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::integrity::StateIntegrity;
use crate::types::{ConnectionKind, WiringEndpoint};
use crate::{CoreError, Result};

/// A minted endpoint plus the one-time plaintext secret. The secret is never
/// stored and never returned again; losing it means re-issuing (which rotates
/// it).
pub struct IssuedEndpoint {
    pub endpoint: WiringEndpoint,
    /// `end_` + 64 hex. Shown to the user once, embedded in the pasteable
    /// DSN/URL by the caller.
    pub secret: String,
}

pub struct EndpointRegistry {
    path: PathBuf,
    integrity: Arc<StateIntegrity>,
    max_total: usize,
    max_per_client: usize,
    endpoints: Mutex<Vec<WiringEndpoint>>,
}

fn hash_secret(secret: &str) -> String {
    let digest = Sha256::digest(secret.as_bytes());
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// 256-bit random endpoint secret: `end_` + 64 hex chars. Distinct prefix
/// from pair tokens (`aka_`) and tickets (`tkt_`) so the three credential
/// classes never confuse a log reader.
fn mint_secret() -> String {
    let mut buf = [0u8; 32];
    getrandom::fill(&mut buf).expect("os rng");
    let hex: String = buf.iter().map(|b| format!("{b:02x}")).collect();
    format!("end_{hex}")
}

impl EndpointRegistry {
    /// Open `endpoints.json`, enforcing the issuance bounds on every mint.
    pub fn open(
        path: PathBuf,
        max_total: usize,
        max_per_client: usize,
        integrity: Arc<StateIntegrity>,
    ) -> Result<Self> {
        let endpoints: Vec<WiringEndpoint> = match integrity.read_verified(&path)? {
            Some(bytes) => serde_json::from_slice(&bytes)?,
            None => Vec::new(),
        };
        Ok(Self {
            path,
            integrity,
            max_total,
            max_per_client,
            endpoints: Mutex::new(endpoints),
        })
    }

    fn persist(&self, endpoints: &[WiringEndpoint]) -> Result<()> {
        self.integrity
            .write(&self.path, &serde_json::to_vec_pretty(endpoints)?)?;
        Ok(())
    }

    /// Issue (or rotate) the endpoint for one wiring. If an endpoint already
    /// exists for `(client_id, connection_id)` its secret is rotated in place
    /// — the id and listener path are stable, but any previously pasted DSN
    /// stops working. This is the "issue / regenerate" action; the caller is
    /// responsible for the wiring actually existing.
    pub fn issue(
        &self,
        client_id: Uuid,
        agent: &str,
        connection_id: Uuid,
        kind: ConnectionKind,
    ) -> Result<IssuedEndpoint> {
        let secret = mint_secret();
        let secret_hash = hash_secret(&secret);
        let mut endpoints = self.endpoints.lock().unwrap();
        let mut next = endpoints.clone();

        if let Some(existing) = next
            .iter_mut()
            .find(|e| e.client_id == client_id && e.connection_id == connection_id)
        {
            existing.secret_hash = secret_hash;
            existing.kind = kind;
            existing.agent = agent.to_string();
            let endpoint = existing.clone();
            self.persist(&next)?;
            *endpoints = next;
            return Ok(IssuedEndpoint { endpoint, secret });
        }

        // A fresh mint: enforce the bounds.
        if next.len() >= self.max_total {
            return Err(CoreError::EndpointLimit(self.max_total));
        }
        if next.iter().filter(|e| e.client_id == client_id).count() >= self.max_per_client {
            return Err(CoreError::EndpointLimit(self.max_per_client));
        }
        let endpoint = WiringEndpoint {
            id: Uuid::new_v4(),
            client_id,
            agent: agent.to_string(),
            connection_id,
            kind,
            secret_hash,
            port: None,
            created_at: Utc::now(),
        };
        next.push(endpoint.clone());
        self.persist(&next)?;
        *endpoints = next;
        Ok(IssuedEndpoint { endpoint, secret })
    }

    /// Pin an endpoint's loopback port (HTTP reverse-proxy endpoints), so a
    /// pasted base URL survives a restart. Idempotent; a no-op if unchanged.
    pub fn set_port(&self, id: &Uuid, port: u16) -> Result<()> {
        let mut endpoints = self.endpoints.lock().unwrap();
        let Some(pos) = endpoints.iter().position(|e| &e.id == id) else {
            return Ok(());
        };
        if endpoints[pos].port == Some(port) {
            return Ok(());
        }
        let mut next = endpoints.clone();
        next[pos].port = Some(port);
        self.persist(&next)?;
        *endpoints = next;
        Ok(())
    }

    /// Revoke one endpoint by id. Returns it when it existed so the caller can
    /// tear down its listener.
    pub fn revoke(&self, id: &Uuid) -> Result<Option<WiringEndpoint>> {
        let mut endpoints = self.endpoints.lock().unwrap();
        let Some(pos) = endpoints.iter().position(|e| &e.id == id) else {
            return Ok(None);
        };
        let mut next = endpoints.clone();
        let removed = next.remove(pos);
        self.persist(&next)?;
        *endpoints = next;
        Ok(Some(removed))
    }

    pub fn list(&self) -> Vec<WiringEndpoint> {
        self.endpoints.lock().unwrap().clone()
    }

    pub fn get(&self, id: &Uuid) -> Option<WiringEndpoint> {
        self.endpoints
            .lock()
            .unwrap()
            .iter()
            .find(|e| &e.id == id)
            .cloned()
    }

    pub fn list_for_client(&self, client_id: &Uuid) -> Vec<WiringEndpoint> {
        self.endpoints
            .lock()
            .unwrap()
            .iter()
            .filter(|e| &e.client_id == client_id)
            .cloned()
            .collect()
    }

    pub fn get_for_wiring(&self, client_id: &Uuid, connection_id: &Uuid) -> Option<WiringEndpoint> {
        self.endpoints
            .lock()
            .unwrap()
            .iter()
            .find(|e| &e.client_id == client_id && &e.connection_id == connection_id)
            .cloned()
    }

    /// Authenticate a presented secret back to its endpoint. The comparison is
    /// over the stored hash; an unknown secret resolves to `None`. This is the
    /// listener's attribution + wiring re-check entry point (the caller still
    /// confirms the wiring is live before serving).
    pub fn resolve_secret(&self, presented: &str) -> Option<WiringEndpoint> {
        let hash = hash_secret(presented);
        self.endpoints
            .lock()
            .unwrap()
            .iter()
            .find(|e| e.secret_hash == hash)
            .cloned()
    }

    /// Endpoints die with their connection (deleted or retargeted). Returns
    /// the removed records so their listeners can be torn down.
    pub fn remove_for_connection(&self, connection_id: &Uuid) -> Result<Vec<WiringEndpoint>> {
        self.remove_where(|e| &e.connection_id == connection_id)
    }

    /// Endpoints die with their agent (disconnect). Returns the removed
    /// records so their listeners can be torn down.
    pub fn remove_for_client(&self, client_id: &Uuid) -> Result<Vec<WiringEndpoint>> {
        self.remove_where(|e| &e.client_id == client_id)
    }

    /// The single endpoint for one wiring dies when that wiring is removed.
    pub fn remove_for_wiring(
        &self,
        client_id: &Uuid,
        connection_id: &Uuid,
    ) -> Result<Option<WiringEndpoint>> {
        Ok(self
            .remove_where(|e| &e.client_id == client_id && &e.connection_id == connection_id)?
            .into_iter()
            .next())
    }

    fn remove_where(&self, pred: impl Fn(&WiringEndpoint) -> bool) -> Result<Vec<WiringEndpoint>> {
        let mut endpoints = self.endpoints.lock().unwrap();
        let (removed, kept): (Vec<_>, Vec<_>) = endpoints.iter().cloned().partition(|e| pred(e));
        if removed.is_empty() {
            return Ok(removed);
        }
        self.persist(&kept)?;
        *endpoints = kept;
        Ok(removed)
    }
}

/// A running per-wiring endpoint listener: its accept-loop task and a
/// shutdown signal. The broker holds one per live endpoint, keyed on the
/// endpoint id, and stops it when the wiring goes away.
pub struct EndpointListenerHandle {
    pub shutdown: Arc<tokio::sync::Notify>,
    pub task: tokio::task::JoinHandle<()>,
}

impl EndpointListenerHandle {
    /// Stop accepting new connections and abort the accept loop. Established
    /// sessions are closed separately via `DataPlane::close_endpoint_sessions`.
    pub fn stop(self) {
        self.shutdown.notify_waiters();
        self.task.abort();
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

    fn registry() -> (EndpointRegistry, tempfile::TempDir) {
        registry_bounded(64, 16)
    }

    fn registry_bounded(
        max_total: usize,
        max_per_client: usize,
    ) -> (EndpointRegistry, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let r = EndpointRegistry::open(
            dir.path().join("endpoints.json"),
            max_total,
            max_per_client,
            integrity(),
        )
        .unwrap();
        (r, dir)
    }

    #[test]
    fn issue_mints_a_prefixed_secret_stored_only_hashed() {
        let (r, dir) = registry();
        let client = Uuid::new_v4();
        let conn = Uuid::new_v4();
        let issued = r
            .issue(client, "claude-code", conn, ConnectionKind::Pg)
            .unwrap();
        assert!(issued.secret.starts_with("end_"));
        assert_eq!(issued.secret.len(), 4 + 64);
        assert_eq!(issued.endpoint.secret_hash, hash_secret(&issued.secret));

        // The plaintext never touches disk; only its hash does.
        let on_disk = std::fs::read_to_string(dir.path().join("endpoints.json")).unwrap();
        assert!(!on_disk.contains(&issued.secret));
        assert!(on_disk.contains(&issued.endpoint.secret_hash));
    }

    #[test]
    fn resolve_secret_authenticates_back_to_the_endpoint() {
        let (r, _dir) = registry();
        let client = Uuid::new_v4();
        let conn = Uuid::new_v4();
        let issued = r
            .issue(client, "claude-code", conn, ConnectionKind::Pg)
            .unwrap();
        let resolved = r.resolve_secret(&issued.secret).expect("known secret");
        assert_eq!(resolved.id, issued.endpoint.id);
        assert_eq!(resolved.client_id, client);
        assert_eq!(resolved.connection_id, conn);
        assert!(r.resolve_secret("end_bogus").is_none());
    }

    #[test]
    fn issue_rotates_in_place_for_an_existing_wiring() {
        let (r, _dir) = registry();
        let client = Uuid::new_v4();
        let conn = Uuid::new_v4();
        let first = r
            .issue(client, "claude-code", conn, ConnectionKind::Pg)
            .unwrap();
        let second = r
            .issue(client, "claude-code", conn, ConnectionKind::Pg)
            .unwrap();
        // Same endpoint id (stable listener path) …
        assert_eq!(first.endpoint.id, second.endpoint.id);
        assert_ne!(first.secret, second.secret);
        assert_eq!(r.list().len(), 1);
        // … but the old secret no longer resolves.
        assert!(r.resolve_secret(&first.secret).is_none());
        assert!(r.resolve_secret(&second.secret).is_some());
    }

    #[test]
    fn bounds_are_enforced_on_fresh_mints() {
        let (r, _dir) = registry_bounded(2, 1);
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        r.issue(a, "a", Uuid::new_v4(), ConnectionKind::Pg).unwrap();
        // Per-client cap of 1: a's second distinct connection is refused.
        assert!(matches!(
            r.issue(a, "a", Uuid::new_v4(), ConnectionKind::Pg),
            Err(CoreError::EndpointLimit(1))
        ));
        // A different client still fits until the global cap of 2.
        r.issue(b, "b", Uuid::new_v4(), ConnectionKind::Pg).unwrap();
        assert!(matches!(
            r.issue(Uuid::new_v4(), "c", Uuid::new_v4(), ConnectionKind::Pg),
            Err(CoreError::EndpointLimit(2))
        ));
        // Re-issuing an existing wiring rotates and never trips the bound.
        assert!(r
            .issue(a, "a", r.list()[0].connection_id, ConnectionKind::Pg)
            .is_ok());
    }

    #[test]
    fn endpoints_die_with_their_connection_and_client() {
        let (r, _dir) = registry();
        let claude = Uuid::new_v4();
        let codex = Uuid::new_v4();
        let shared_conn = Uuid::new_v4();
        r.issue(claude, "claude", shared_conn, ConnectionKind::Pg)
            .unwrap();
        r.issue(codex, "codex", shared_conn, ConnectionKind::Pg)
            .unwrap();
        r.issue(claude, "claude", Uuid::new_v4(), ConnectionKind::Ssh)
            .unwrap();

        let removed = r.remove_for_connection(&shared_conn).unwrap();
        assert_eq!(removed.len(), 2);
        assert_eq!(r.list().len(), 1);

        let removed = r.remove_for_client(&claude).unwrap();
        assert_eq!(removed.len(), 1);
        assert!(r.list().is_empty());
    }

    #[test]
    fn remove_for_wiring_removes_exactly_one() {
        let (r, _dir) = registry();
        let client = Uuid::new_v4();
        let conn = Uuid::new_v4();
        let issued = r.issue(client, "claude", conn, ConnectionKind::Pg).unwrap();
        let removed = r.remove_for_wiring(&client, &conn).unwrap();
        assert_eq!(removed.map(|e| e.id), Some(issued.endpoint.id));
        assert!(r.remove_for_wiring(&client, &conn).unwrap().is_none());
    }

    #[test]
    fn revoke_returns_the_endpoint_and_is_idempotent() {
        let (r, _dir) = registry();
        let issued = r
            .issue(Uuid::new_v4(), "claude", Uuid::new_v4(), ConnectionKind::Pg)
            .unwrap();
        assert_eq!(
            r.revoke(&issued.endpoint.id).unwrap().map(|e| e.id),
            Some(issued.endpoint.id)
        );
        assert!(r.revoke(&issued.endpoint.id).unwrap().is_none());
    }

    #[test]
    fn endpoints_persist_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("endpoints.json");
        let integrity = integrity();
        let client = Uuid::new_v4();
        let conn = Uuid::new_v4();
        let secret = {
            let r = EndpointRegistry::open(path.clone(), 64, 16, integrity.clone()).unwrap();
            r.issue(client, "claude", conn, ConnectionKind::Pg)
                .unwrap()
                .secret
        };
        let r = EndpointRegistry::open(path, 64, 16, integrity).unwrap();
        let resolved = r.resolve_secret(&secret).expect("secret survives reopen");
        assert_eq!(resolved.connection_id, conn);
    }

    #[test]
    fn failed_writes_do_not_change_active_endpoints() {
        let (r, dir) = registry();
        let path = dir.path().join("endpoints.json");
        let client = Uuid::new_v4();
        let conn = Uuid::new_v4();
        let issued = r.issue(client, "claude", conn, ConnectionKind::Pg).unwrap();
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();

        // A write that can't land leaves the in-memory table untouched.
        assert!(r
            .issue(Uuid::new_v4(), "codex", Uuid::new_v4(), ConnectionKind::Pg)
            .is_err());
        assert_eq!(r.list().len(), 1);
        assert!(r.resolve_secret(&issued.secret).is_some());
        assert!(r.revoke(&issued.endpoint.id).is_err());
        assert!(r.resolve_secret(&issued.secret).is_some());
    }
}
