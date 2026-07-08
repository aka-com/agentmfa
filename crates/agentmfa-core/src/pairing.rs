//! Pairing and pair tokens (DESIGN.md §8).
//!
//! `POST /v1/pair {"agent_name": …}` triggers a user approval and returns a
//! random 256-bit bearer token, stored hashed. Tokens have a 30-day TTL
//! refreshed on use, are revocable from the UI, and are pinned to the
//! code-signing identity observed at pairing: any later call presenting the
//! token from a differently-signed peer is rejected and audited.

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

/// 256-bit random bearer token: `amfa_` + 64 hex chars.
fn mint_token() -> String {
    let mut buf = [0u8; 32];
    getrandom::fill(&mut buf).expect("os rng");
    format!("amfa_{}", hex(&buf))
}

impl PairingRegistry {
    /// `agents.json` carries token hashes *and pinned identities*, so it is
    /// sealed (§13.1): a rewrite of a pin must not go unnoticed.
    pub fn open(path: PathBuf, ttl: Duration, integrity: Arc<StateIntegrity>) -> Result<Self> {
        let agents = match integrity.read_verified(&path)? {
            Some(bytes) => serde_json::from_slice(&bytes)?,
            None => Vec::new(),
        };
        // Refresh at most once per tenth of the TTL, capped at an hour — far
        // inside the window, so an active token never expires, while a busy
        // agent does not trigger a disk write per call.
        let refresh = std::cmp::min(ttl / 10, Duration::from_secs(3600));
        let refresh_interval = chrono::Duration::from_std(refresh)
            .unwrap_or_else(|_| chrono::Duration::seconds(3600));
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
    /// Re-pairing under an existing name replaces the prior record, one
    /// live token per name (the §13.2 lifecycle question, resolved to the
    /// simpler and safer semantics). The replaced token's hash is remembered
    /// so its holder gets `token_superseded`, not `invalid_token`.
    pub fn pair(&self, name: &str, identity: PeerIdentity) -> Result<(String, PairedAgent)> {
        let token = mint_token();
        let now = Utc::now();
        let agent = PairedAgent {
            name: name.to_string(),
            token_hash: hash_token(&token),
            token_preview: token[..11].to_string(),
            identity,
            paired_at: now,
            last_used: now,
        };
        let mut agents = self.agents.lock().unwrap();
        {
            let mut superseded = self.superseded.lock().unwrap();
            if superseded.len() > 1024 {
                superseded.clear();
            }
            for old in agents.iter().filter(|a| a.name == name) {
                superseded.insert(old.token_hash.clone(), name.to_string());
            }
        }
        agents.retain(|a| a.name != name);
        agents.push(agent.clone());
        self.persist(&agents)?;
        Ok((token, agent))
    }

    /// Verify a presented bearer token against the given peer identity.
    /// Success refreshes `last_used` (the TTL is refreshed on use, §8).
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

    /// Invalidate a name's token immediately (the Revoke button, §8).
    /// Standing rules are deliberately *not* touched here, they stay
    /// visible on the Connections tab and are re-disclosed if the name
    /// pairs again (DESIGN.md §9).
    pub fn revoke(&self, name: &str) -> Result<bool> {
        let mut agents = self.agents.lock().unwrap();
        let before = agents.len();
        agents.retain(|a| a.name != name);
        let removed = agents.len() != before;
        if removed {
            self.persist(&agents)?;
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
        assert!(token.starts_with("amfa_"));
        assert_eq!(token.len(), 5 + 64);
        assert_eq!(agent.token_preview, &token[..11]);
        let verified = r.verify(&token, &dev_identity()).unwrap();
        assert_eq!(verified.name, "claude-code");
        assert!(r.verify("amfa_bogus", &dev_identity()).is_err());
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
        // A differently-signed peer presenting a lifted token is rejected.
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
            r.verify(&token, &PeerIdentity::Unsigned).unwrap_err(),
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
        let (token, _) = r.pair("claude-code", dev_identity()).unwrap();
        assert!(r.revoke("claude-code").unwrap());
        assert_eq!(
            r.verify(&token, &dev_identity()).unwrap_err(),
            TokenError::Invalid
        );
        assert!(!r.revoke("claude-code").unwrap());
    }

    #[test]
    fn repairing_replaces_the_token() {
        let (r, _dir) = registry(Duration::from_secs(3600));
        let (token1, _) = r.pair("claude-code", dev_identity()).unwrap();
        let (token2, _) = r.pair("claude-code", dev_identity()).unwrap();
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
    fn verify_coalesces_the_ttl_refresh_write() {
        // ttl 2s → refresh interval ~200ms.
        let (r, dir) = registry(Duration::from_secs(2));
        let (token, _) = r.pair("claude-code", dev_identity()).unwrap();
        let path = dir.path().join("agents.json");
        // agents.json is sealed (§13.1): the agent list is the envelope's
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
}
