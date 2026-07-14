//! Pairing and pair tokens.
//!
//! `POST /v1/pair {"agent_name": …}` triggers a user approval and returns a
//! random 256-bit bearer token, stored hashed. Tokens have a 30-day TTL
//! refreshed on use, are revocable from the UI, and are pinned to the
//! peer identity observed at pairing: any later call presenting the token
//! from a different peer identity is rejected and audited.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::Utc;
use sha2::{Digest, Sha256};

use crate::integrity::StateIntegrity;
use crate::types::{PairedAgent, PeerIdentity};
use crate::wire::ErrorReason;
use crate::Result;

/// Why a presented token was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenError {
    /// Unknown or revoked.
    Invalid,
    /// Known but past its TTL.
    Expired,
    /// Known, but presented by a peer whose identity doesn't match the pin.
    IdentityMismatch,
    /// Replaced by a later pairing under the same name. Distinct from
    /// `Invalid` so a stale instance re-reads the shared token file instead
    /// of re-pairing (which would break the newer instance in turn). Carries
    /// the name so the refusal can point at the exact token file.
    Superseded { name: String },
}

impl TokenError {
    pub fn reason(&self) -> ErrorReason {
        match self {
            TokenError::Invalid => ErrorReason::InvalidToken,
            TokenError::Expired => ErrorReason::TokenExpired,
            TokenError::IdentityMismatch => ErrorReason::PeerIdentityMismatch,
            TokenError::Superseded { .. } => ErrorReason::TokenSuperseded,
        }
    }
}

pub struct PairingRegistry {
    path: PathBuf,
    ttl: Duration,
    /// Minimum `last_used` advance before a refresh is written to disk. The
    /// TTL is measured in days, so persisting every authenticated request is
    /// a needless blocking write in the hot path; refreshes are coalesced to
    /// at most one write per interval.
    refresh_interval: chrono::Duration,
    integrity: Arc<StateIntegrity>,
    agents: Mutex<Vec<PairedAgent>>,
    /// Hashes of tokens replaced by a re-pairing, mapped to the replacing
    /// name, kept in memory (a best-effort hint, not state worth persisting)
    /// so `verify` can tell a superseded token apart from a bogus one and
    /// name the shared token file to re-read. Bounded: hint-only, so a
    /// wholesale clear on overflow is fine.
    superseded: Mutex<std::collections::HashMap<String, String>>,
}

fn hash_token(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    hex(&digest)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// 256-bit random bearer token: `aka_` + 64 hex chars.
fn mint_token() -> String {
    let mut buf = [0u8; 32];
    getrandom::fill(&mut buf).expect("os rng");
    format!("aka_{}", hex(&buf))
}

impl PairingRegistry {
    /// `agents.json` carries token hashes *and pinned identities*, so it is
    /// sealed: a rewrite of a pin must not go unnoticed.
    pub fn open(path: PathBuf, ttl: Duration, integrity: Arc<StateIntegrity>) -> Result<Self> {
        let mut agents: Vec<PairedAgent> = match integrity.read_verified(&path)? {
            Some(bytes) => serde_json::from_slice(&bytes)?,
            None => Vec::new(),
        };
        let migrated = agents.iter().any(|agent| agent.id.is_nil());
        for agent in &mut agents {
            if agent.id.is_nil() {
                agent.id = uuid::Uuid::new_v4();
            }
        }
        if migrated {
            integrity.write(&path, &serde_json::to_vec_pretty(&agents)?)?;
        }
        // Refresh at most once per tenth of the TTL, capped at an hour — far
        // inside the window, so an active token never expires, while a busy
        // agent does not trigger a disk write per call.
        let refresh = std::cmp::min(ttl / 10, Duration::from_secs(3600));
        let refresh_interval =
            chrono::Duration::from_std(refresh).unwrap_or_else(|_| chrono::Duration::seconds(3600));
        Ok(Self {
            path,
            ttl,
            refresh_interval,
            integrity,
            agents: Mutex::new(agents),
            superseded: Mutex::new(std::collections::HashMap::new()),
        })
    }

    fn persist(&self, agents: &[PairedAgent]) -> Result<()> {
        self.integrity
            .write(&self.path, &serde_json::to_vec_pretty(agents)?)?;
        Ok(())
    }

    /// Complete an approved pairing: mint a token pinned to `identity`.
    /// Re-pairing the same verified client preserves its stable id while a
    /// different program using the same display name receives a new id. One
    /// live token remains per name. The replaced token's hash is remembered
    /// so its holder gets `token_superseded`, not `invalid_token`.
    pub fn pair(&self, name: &str, identity: PeerIdentity) -> Result<(String, PairedAgent)> {
        let token = mint_token();
        let now = Utc::now();
        let existing_id = agents_for_identity(&self.agents, name, &identity);
        let agent = PairedAgent {
            id: existing_id.unwrap_or_else(uuid::Uuid::new_v4),
            name: name.to_string(),
            token_hash: hash_token(&token),
            token_preview: token[..11].to_string(),
            identity,
            paired_at: now,
            last_used: now,
        };
        let mut agents = self.agents.lock().unwrap();
        let replaced: Vec<String> = agents
            .iter()
            .filter(|a| a.name == name)
            .map(|a| a.token_hash.clone())
            .collect();
        let mut next = agents.clone();
        next.retain(|a| a.name != name);
        next.push(agent.clone());
        self.persist(&next)?;
        *agents = next;
        let mut superseded = self.superseded.lock().unwrap();
        if superseded.len() > 1024 {
            superseded.clear();
        }
        for hash in replaced {
            superseded.insert(hash, name.to_string());
        }
        Ok((token, agent))
    }

    /// Verify a presented bearer token against the given peer identity.
    /// Success refreshes `last_used` (the TTL is refreshed on use).
    pub fn verify(
        &self,
        token: &str,
        peer: &PeerIdentity,
    ) -> std::result::Result<PairedAgent, TokenError> {
        let hash = hash_token(token);
        let mut agents = self.agents.lock().unwrap();
        let Some(agent) = agents.iter_mut().find(|a| a.token_hash == hash) else {
            if let Some(name) = self.superseded.lock().unwrap().get(&hash) {
                return Err(TokenError::Superseded { name: name.clone() });
            }
            return Err(TokenError::Invalid);
        };
        let now = Utc::now();
        let age = now.signed_duration_since(agent.last_used);
        if age.num_seconds() > self.ttl.as_secs() as i64 {
            return Err(TokenError::Expired);
        }
        if &agent.identity != peer {
            return Err(TokenError::IdentityMismatch);
        }
        // Refresh the sliding TTL, but only rewrite agents.json when the
        // advance is material — a sub-interval refresh stays in memory, so the
        // common authenticated call costs no disk write.
        if age < self.refresh_interval {
            return Ok(agent.clone());
        }
        agent.last_used = now;
        let out = agent.clone();
        // last_used is best-effort persisted; failure to write must not fail
        // the call.
        if let Err(e) = self.persist(&agents) {
            tracing::warn!("could not persist token refresh: {e}");
        }
        Ok(out)
    }

    /// Invalidate a name's token immediately (the Revoke button). The
    /// broker removes permissions for the returned client as part of the
    /// same user action.
    pub fn revoke(&self, client_id: &uuid::Uuid) -> Result<bool> {
        let mut agents = self.agents.lock().unwrap();
        let mut next = agents.clone();
        let before = next.len();
        next.retain(|agent| &agent.id != client_id);
        let removed = next.len() != before;
        if removed {
            self.persist(&next)?;
            *agents = next;
        }
        Ok(removed)
    }

    pub fn list(&self) -> Vec<PairedAgent> {
        let mut agents = self.agents.lock().unwrap().clone();
        agents.sort_by(|a, b| a.name.cmp(&b.name));
        agents
    }

    pub fn get(&self, name: &str) -> Option<PairedAgent> {
        self.agents
            .lock()
            .unwrap()
            .iter()
            .find(|a| a.name == name)
            .cloned()
    }

    pub fn get_by_id(&self, client_id: &uuid::Uuid) -> Option<PairedAgent> {
        self.agents
            .lock()
            .unwrap()
            .iter()
            .find(|agent| &agent.id == client_id)
            .cloned()
    }

    pub fn get_matching(&self, name: &str, identity: &PeerIdentity) -> Option<PairedAgent> {
        self.agents
            .lock()
            .unwrap()
            .iter()
            .find(|agent| agent.name == name && &agent.identity == identity)
            .cloned()
    }
}

fn agents_for_identity(
    agents: &Mutex<Vec<PairedAgent>>,
    name: &str,
    identity: &PeerIdentity,
) -> Option<uuid::Uuid> {
    agents
        .lock()
        .unwrap()
        .iter()
        .find(|agent| agent.name == name && &agent.identity == identity)
        .map(|agent| agent.id)
}

/// Agent names are self-asserted labels; keep them printable and bounded so
/// they render safely in dialogs and logs.
pub fn validate_agent_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry(ttl: Duration) -> (PairingRegistry, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let integrity = Arc::new(
            futures::executor::block_on(StateIntegrity::open(&crate::vault::MemoryVault::new()))
                .unwrap(),
        );
        let r = PairingRegistry::open(dir.path().join("agents.json"), ttl, integrity).unwrap();
        (r, dir)
    }

    fn dev_identity() -> PeerIdentity {
        PeerIdentity::DevUnverified { uid: 501 }
    }

    #[test]
    fn pair_verify_roundtrip() {
        let (r, _dir) = registry(Duration::from_secs(3600));
        let (token, agent) = r.pair("claude-code", dev_identity()).unwrap();
        assert!(token.starts_with("aka_"));
        assert_eq!(token.len(), 4 + 64);
        assert_eq!(agent.token_preview, &token[..11]);
        let verified = r.verify(&token, &dev_identity()).unwrap();
        assert_eq!(verified.name, "claude-code");
        assert!(r.verify("aka_bogus", &dev_identity()).is_err());
    }

    #[test]
    fn identity_pin_is_enforced() {
        let (r, _dir) = registry(Duration::from_secs(3600));
        let (token, _) = r
            .pair(
                "claude-code",
                PeerIdentity::Signed {
                    signing_id: "com.anthropic.claude-code".into(),
                    team_id: Some("6XN7K9RPQ2".into()),
                },
            )
            .unwrap();
        // Same identity passes.
        assert!(r
            .verify(
                &token,
                &PeerIdentity::Signed {
                    signing_id: "com.anthropic.claude-code".into(),
                    team_id: Some("6XN7K9RPQ2".into()),
                }
            )
            .is_ok());
        // A different peer identity presenting a lifted token is rejected.
        assert_eq!(
            r.verify(
                &token,
                &PeerIdentity::Signed {
                    signing_id: "com.evil.tool".into(),
                    team_id: Some("EVIL000000".into()),
                }
            )
            .unwrap_err(),
            TokenError::IdentityMismatch
        );
        assert_eq!(
            r.verify(
                &token,
                &PeerIdentity::Unsigned {
                    uid: Some(501),
                    executable_path: Some("/tmp/unsigned-tool".into()),
                    file_id: Some("dev:1 ino:2".into()),
                    executable_sha256: Some("a".repeat(64)),
                }
            )
            .unwrap_err(),
            TokenError::IdentityMismatch
        );
    }

    #[test]
    fn expired_tokens_are_rejected() {
        let (r, _dir) = registry(Duration::from_secs(0));
        let (token, _) = r.pair("claude-code", dev_identity()).unwrap();
        std::thread::sleep(Duration::from_millis(1100));
        assert_eq!(
            r.verify(&token, &dev_identity()).unwrap_err(),
            TokenError::Expired
        );
    }

    #[test]
    fn revoke_invalidates_immediately() {
        let (r, _dir) = registry(Duration::from_secs(3600));
        let (token, client) = r.pair("claude-code", dev_identity()).unwrap();
        assert!(r.revoke(&client.id).unwrap());
        assert_eq!(
            r.verify(&token, &dev_identity()).unwrap_err(),
            TokenError::Invalid
        );
        assert!(!r.revoke(&client.id).unwrap());
    }

    #[test]
    fn repairing_replaces_the_token() {
        let (r, _dir) = registry(Duration::from_secs(3600));
        let (token1, first) = r.pair("claude-code", dev_identity()).unwrap();
        let (token2, repaired) = r.pair("claude-code", dev_identity()).unwrap();
        assert_eq!(first.id, repaired.id);
        // The replaced token is reported as superseded — naming whose token
        // file to re-read — not merely invalid, so its holder recovers
        // instead of re-pairing.
        assert_eq!(
            r.verify(&token1, &dev_identity()).unwrap_err(),
            TokenError::Superseded {
                name: "claude-code".into()
            }
        );
        assert!(r.verify(&token2, &dev_identity()).is_ok());
        assert_eq!(r.list().len(), 1);
        // A different name's pairing does not disturb the tombstone.
        let (token3, _) = r.pair("codex", dev_identity()).unwrap();
        assert_eq!(
            r.verify(&token1, &dev_identity()).unwrap_err(),
            TokenError::Superseded {
                name: "claude-code".into()
            }
        );
        assert!(r.verify(&token3, &dev_identity()).is_ok());
    }

    #[test]
    fn same_name_different_identity_gets_a_new_client_id() {
        let (r, _dir) = registry(Duration::from_secs(3600));
        let (_, first) = r.pair("claude-code", dev_identity()).unwrap();
        let (_, replacement) = r
            .pair(
                "claude-code",
                PeerIdentity::Signed {
                    signing_id: "com.example.other".into(),
                    team_id: Some("OTHERTEAM".into()),
                },
            )
            .unwrap();
        assert_ne!(first.id, replacement.id);
    }

    #[test]
    fn legacy_agents_receive_persisted_client_ids() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agents.json");
        let integrity = Arc::new(
            futures::executor::block_on(StateIntegrity::open(&crate::vault::MemoryVault::new()))
                .unwrap(),
        );
        let now = Utc::now();
        let legacy = serde_json::json!([{
            "name": "claude-code",
            "token_hash": "hash",
            "token_preview": "aka_legacy",
            "identity": {"kind": "dev_unverified", "uid": 501},
            "paired_at": now,
            "last_used": now
        }]);
        integrity
            .write(&path, &serde_json::to_vec_pretty(&legacy).unwrap())
            .unwrap();

        let registry =
            PairingRegistry::open(path.clone(), Duration::from_secs(3600), integrity).unwrap();
        let client = registry.get("claude-code").unwrap();
        assert!(!client.id.is_nil());

        let sealed: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        let persisted: Vec<PairedAgent> =
            serde_json::from_value(sealed["payload"].clone()).unwrap();
        assert_eq!(persisted[0].id, client.id);
    }

    #[test]
    fn verify_coalesces_the_ttl_refresh_write() {
        // ttl 2s → refresh interval ~200ms.
        let (r, dir) = registry(Duration::from_secs(2));
        let (token, _) = r.pair("claude-code", dev_identity()).unwrap();
        let path = dir.path().join("agents.json");
        // agents.json is sealed: the agent list is the envelope's
        // `payload`.
        let persisted_last_used = |p: &std::path::Path| {
            let sealed: serde_json::Value =
                serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap();
            let agents: Vec<PairedAgent> =
                serde_json::from_value(sealed["payload"].clone()).unwrap();
            agents[0].last_used
        };
        let at_pair = persisted_last_used(&path);

        // A refresh well inside the interval stays in memory — the file is
        // left untouched.
        r.verify(&token, &dev_identity()).unwrap();
        assert_eq!(
            persisted_last_used(&path),
            at_pair,
            "a sub-interval refresh must not rewrite agents.json"
        );

        // Past the interval (but inside the TTL), the refresh is persisted.
        std::thread::sleep(Duration::from_millis(350));
        r.verify(&token, &dev_identity()).unwrap();
        assert!(
            persisted_last_used(&path) > at_pair,
            "a refresh past the interval must be written"
        );
    }

    #[test]
    fn tokens_are_stored_hashed() {
        let (r, dir) = registry(Duration::from_secs(3600));
        let (token, _) = r.pair("claude-code", dev_identity()).unwrap();
        let on_disk = std::fs::read_to_string(dir.path().join("agents.json")).unwrap();
        assert!(!on_disk.contains(&token));
        assert!(on_disk.contains(&hash_token(&token)));
    }

    #[test]
    fn agent_names_validated() {
        assert!(validate_agent_name("claude-code"));
        assert!(validate_agent_name("codex_2.1"));
        assert!(!validate_agent_name(""));
        assert!(!validate_agent_name("has space"));
        assert!(!validate_agent_name("emoji🙂"));
    }

    #[test]
    fn failed_agent_writes_do_not_change_active_tokens() {
        let (r, dir) = registry(Duration::from_secs(3600));
        let path = dir.path().join("agents.json");
        let (token, original) = r.pair("claude-code", dev_identity()).unwrap();
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();

        assert!(r.pair("codex", dev_identity()).is_err());
        assert!(r.get("codex").is_none());

        assert!(r.pair("claude-code", dev_identity()).is_err());
        assert_eq!(
            r.get("claude-code").unwrap().token_hash,
            original.token_hash
        );
        assert!(r.verify(&token, &dev_identity()).is_ok());

        assert!(r.revoke(&original.id).is_err());
        assert!(r.verify(&token, &dev_identity()).is_ok());
    }
}
