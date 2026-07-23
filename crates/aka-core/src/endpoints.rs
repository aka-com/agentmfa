//! The direct-endpoint registry: per-connection stable endpoints and their
//! secrets.
//!
//! A [`DirectEndpoint`] is one persistent listener + secret an agent keeps in
//! its own config so it can reach a tool with an unmodified client (a DSN
//! pasted into `psql`, a socket in `~/.ssh/config`) instead of round-tripping
//! the control plane for a short-lived ticket on every session.
//!
//! Because a stable endpoint is standing access, the security model differs
//! from a ticket in exactly two ways, both enforced here plus at the listener:
//!
//! - **The secret is the capability.** A loopback port is reachable by any
//!   local process, so the endpoint carries its own secret the caller presents
//!   — deliberately not the shared broker key, so one pasted config can be
//!   revoked alone. It is persisted only as a SHA-256 hash;
//!   [`EndpointRegistry::resolve_secret`] is how a listener authenticates a
//!   presented secret back to its endpoint.
//! - **Revocation must be prompt and total.** Endpoints die with their
//!   connection:
//!   [`remove_for_connection`](EndpointRegistry::remove_for_connection)
//!   returns the removed records so the caller can tear down the live
//!   listener and close any established sessions.
//!
//! Persisted in `endpoints.json`, sealed by the same integrity key as the
//! access table and identity record. Records written by the per-agent era
//! carried a `client_id`/`agent` pair; they load fine (the fields are
//! ignored), and duplicates for one connection collapse to the newest.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use chrono::Utc;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::integrity::StateIntegrity;
use crate::types::{ConnectionKind, DirectEndpoint};
use crate::{CoreError, Result};

/// A minted endpoint plus the one-time plaintext secret. The secret is never
/// stored and never returned again; losing it means re-issuing (which rotates
/// it).
pub struct IssuedEndpoint {
    pub endpoint: DirectEndpoint,
    /// `end_` + 64 hex. Shown to the user once, embedded in the pasteable
    /// DSN/URL by the caller.
    pub secret: String,
}

pub struct EndpointRegistry {
    path: PathBuf,
    integrity: Arc<StateIntegrity>,
    max_total: usize,
    endpoints: Mutex<Vec<DirectEndpoint>>,
}

fn hash_secret(secret: &str) -> String {
    let digest = Sha256::digest(secret.as_bytes());
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// 256-bit random endpoint secret: `end_` + 64 hex chars. Distinct prefix
/// from the broker key (`aka_`) and tickets (`tkt_`) so the three credential
/// classes never confuse a log reader.
fn mint_secret() -> String {
    let mut buf = [0u8; 32];
    getrandom::fill(&mut buf).expect("os rng");
    let hex: String = buf.iter().map(|b| format!("{b:02x}")).collect();
    format!("end_{hex}")
}

impl EndpointRegistry {
    /// Open `endpoints.json`, enforcing the issuance bound on every mint.
    /// Per-agent-era duplicates for one connection collapse to the newest
    /// record (their other secrets stop resolving).
    pub fn open(path: PathBuf, max_total: usize, integrity: Arc<StateIntegrity>) -> Result<Self> {
        let mut endpoints: Vec<DirectEndpoint> = match integrity.read_verified(&path)? {
            Some(bytes) => serde_json::from_slice(&bytes)?,
            None => Vec::new(),
        };
        let before = endpoints.len();
        endpoints.sort_by_key(|e| std::cmp::Reverse(e.created_at));
        let mut seen: Vec<Uuid> = Vec::new();
        endpoints.retain(|e| {
            if seen.contains(&e.connection_id) {
                false
            } else {
                seen.push(e.connection_id);
                true
            }
        });
        if endpoints.len() != before {
            integrity.write(&path, &serde_json::to_vec_pretty(&endpoints)?)?;
        }
        Ok(Self {
            path,
            integrity,
            max_total,
            endpoints: Mutex::new(endpoints),
        })
    }

    fn persist(&self, endpoints: &[DirectEndpoint]) -> Result<()> {
        self.integrity
            .write(&self.path, &serde_json::to_vec_pretty(endpoints)?)?;
        Ok(())
    }

    /// Issue (or rotate) the endpoint for one connection. If an endpoint
    /// already exists its secret is rotated in place — the id and listener
    /// path are stable, but any previously pasted DSN stops working. This is
    /// the "issue / regenerate" action; the caller is responsible for the
    /// connection's agent access actually being enabled.
    pub fn issue(&self, connection_id: Uuid, kind: ConnectionKind) -> Result<IssuedEndpoint> {
        let secret = mint_secret();
        let secret_hash = hash_secret(&secret);
        let mut endpoints = self.endpoints.lock().unwrap();
        let mut next = endpoints.clone();

        if let Some(existing) = next.iter_mut().find(|e| e.connection_id == connection_id) {
            existing.secret_hash = secret_hash;
            existing.kind = kind;
            let endpoint = existing.clone();
            self.persist(&next)?;
            *endpoints = next;
            return Ok(IssuedEndpoint { endpoint, secret });
        }

        // A fresh mint: enforce the bound.
        if next.len() >= self.max_total {
            return Err(CoreError::EndpointLimit(self.max_total));
        }
        let endpoint = DirectEndpoint {
            id: Uuid::new_v4(),
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
    pub fn revoke(&self, id: &Uuid) -> Result<Option<DirectEndpoint>> {
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

    pub fn list(&self) -> Vec<DirectEndpoint> {
        self.endpoints.lock().unwrap().clone()
    }

    pub fn get(&self, id: &Uuid) -> Option<DirectEndpoint> {
        self.endpoints
            .lock()
            .unwrap()
            .iter()
            .find(|e| &e.id == id)
            .cloned()
    }

    pub fn get_for_connection(&self, connection_id: &Uuid) -> Option<DirectEndpoint> {
        self.endpoints
            .lock()
            .unwrap()
            .iter()
            .find(|e| &e.connection_id == connection_id)
            .cloned()
    }

    /// Authenticate a presented secret back to its endpoint. The comparison is
    /// over the stored hash; an unknown secret resolves to `None`. This is the
    /// listener's attribution entry point (the caller still confirms the
    /// connection's agent access is enabled before serving).
    pub fn resolve_secret(&self, presented: &str) -> Option<DirectEndpoint> {
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
    pub fn remove_for_connection(&self, connection_id: &Uuid) -> Result<Vec<DirectEndpoint>> {
        let mut endpoints = self.endpoints.lock().unwrap();
        let (removed, kept): (Vec<_>, Vec<_>) = endpoints
            .iter()
            .cloned()
            .partition(|e| &e.connection_id == connection_id);
        if removed.is_empty() {
            return Ok(removed);
        }
        self.persist(&kept)?;
        *endpoints = kept;
        Ok(removed)
    }
}

/// A running endpoint listener: its accept-loop task and a shutdown signal.
/// The broker holds one per live endpoint, keyed on the endpoint id, and
/// stops it when the endpoint goes away.
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
        registry_bounded(64)
    }

    fn registry_bounded(max_total: usize) -> (EndpointRegistry, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let r = EndpointRegistry::open(dir.path().join("endpoints.json"), max_total, integrity())
            .unwrap();
        (r, dir)
    }

    #[test]
    fn issue_mints_a_prefixed_secret_stored_only_hashed() {
        let (r, dir) = registry();
        let conn = Uuid::new_v4();
        let issued = r.issue(conn, ConnectionKind::Pg).unwrap();
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
        let conn = Uuid::new_v4();
        let issued = r.issue(conn, ConnectionKind::Pg).unwrap();
        let resolved = r.resolve_secret(&issued.secret).expect("known secret");
        assert_eq!(resolved.id, issued.endpoint.id);
        assert_eq!(resolved.connection_id, conn);
        assert!(r.resolve_secret("end_bogus").is_none());
    }

    #[test]
    fn issue_rotates_in_place_for_an_existing_connection() {
        let (r, _dir) = registry();
        let conn = Uuid::new_v4();
        let first = r.issue(conn, ConnectionKind::Pg).unwrap();
        let second = r.issue(conn, ConnectionKind::Pg).unwrap();
        // Same endpoint id (stable listener path) …
        assert_eq!(first.endpoint.id, second.endpoint.id);
        assert_ne!(first.secret, second.secret);
        assert_eq!(r.list().len(), 1);
        // … but the old secret no longer resolves.
        assert!(r.resolve_secret(&first.secret).is_none());
        assert!(r.resolve_secret(&second.secret).is_some());
    }

    #[test]
    fn bound_is_enforced_on_fresh_mints() {
        let (r, _dir) = registry_bounded(2);
        let a = Uuid::new_v4();
        r.issue(a, ConnectionKind::Pg).unwrap();
        r.issue(Uuid::new_v4(), ConnectionKind::Pg).unwrap();
        assert!(matches!(
            r.issue(Uuid::new_v4(), ConnectionKind::Pg),
            Err(CoreError::EndpointLimit(2))
        ));
        // Re-issuing an existing connection rotates and never trips the bound.
        assert!(r.issue(a, ConnectionKind::Pg).is_ok());
    }

    #[test]
    fn endpoints_die_with_their_connection() {
        let (r, _dir) = registry();
        let conn = Uuid::new_v4();
        r.issue(conn, ConnectionKind::Pg).unwrap();
        r.issue(Uuid::new_v4(), ConnectionKind::Ssh).unwrap();

        let removed = r.remove_for_connection(&conn).unwrap();
        assert_eq!(removed.len(), 1);
        assert_eq!(r.list().len(), 1);
        assert!(r.remove_for_connection(&conn).unwrap().is_empty());
    }

    #[test]
    fn revoke_returns_the_endpoint_and_is_idempotent() {
        let (r, _dir) = registry();
        let issued = r.issue(Uuid::new_v4(), ConnectionKind::Pg).unwrap();
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
        let conn = Uuid::new_v4();
        let secret = {
            let r = EndpointRegistry::open(path.clone(), 64, integrity.clone()).unwrap();
            r.issue(conn, ConnectionKind::Pg).unwrap().secret
        };
        let r = EndpointRegistry::open(path, 64, integrity).unwrap();
        let resolved = r.resolve_secret(&secret).expect("secret survives reopen");
        assert_eq!(resolved.connection_id, conn);
    }

    #[test]
    fn legacy_per_agent_duplicates_collapse_to_the_newest() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("endpoints.json");
        let integrity = integrity();
        let conn = Uuid::new_v4();
        let older = Uuid::new_v4();
        let newer = Uuid::new_v4();
        // Two per-agent-era records for one connection, extra fields intact.
        let legacy = serde_json::json!([
            {"id": older, "client_id": Uuid::new_v4(), "agent": "claude-code",
             "connection_id": conn, "kind": "pg", "secret_hash": "aaa",
             "created_at": "2026-01-01T00:00:00Z"},
            {"id": newer, "client_id": Uuid::new_v4(), "agent": "codex",
             "connection_id": conn, "kind": "pg", "secret_hash": "bbb",
             "created_at": "2026-02-01T00:00:00Z"},
        ]);
        integrity
            .write(&path, &serde_json::to_vec_pretty(&legacy).unwrap())
            .unwrap();

        let r = EndpointRegistry::open(path, 64, integrity).unwrap();
        assert_eq!(r.list().len(), 1);
        assert_eq!(r.list()[0].id, newer);
    }

    #[test]
    fn failed_writes_do_not_change_active_endpoints() {
        let (r, dir) = registry();
        let path = dir.path().join("endpoints.json");
        let conn = Uuid::new_v4();
        let issued = r.issue(conn, ConnectionKind::Pg).unwrap();
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();

        // A write that can't land leaves the in-memory table untouched.
        assert!(r.issue(Uuid::new_v4(), ConnectionKind::Pg).is_err());
        assert_eq!(r.list().len(), 1);
        assert!(r.resolve_secret(&issued.secret).is_some());
        assert!(r.revoke(&issued.endpoint.id).is_err());
        assert!(r.resolve_secret(&issued.secret).is_some());
    }
}
