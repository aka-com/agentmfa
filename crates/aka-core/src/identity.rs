//! The shared broker identity and its key.
//!
//! One 256-bit bearer key covers every local agent — "this computer's key".
//! The plaintext lives in the broker's token file (`~/.aka/token`, 0600)
//! where agents read it themselves; `identity.json` (sealed) stores only the
//! SHA-256 hash. `POST /v1/pair` remains as a compat shim that hands the
//! same key back and records the caller's name as an activity label.
//!
//! Rotation replaces per-agent revocation: a rotated key answers
//! `401 token_superseded` naming the token file, the same recovery path
//! agents already follow. Token hashes from the per-agent era are carried as
//! aliases until the first rotation so running agents don't break mid-session.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};

use crate::integrity::StateIntegrity;
use crate::types::{BrokerIdentity, SupersededTokenHash};
use crate::wire::ErrorReason;
use crate::Result;

/// Why a presented token was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenError {
    /// Unknown.
    Invalid,
    /// Known but past its TTL.
    Expired,
    /// The key was rotated. Distinct from `Invalid` so the holder re-reads
    /// the token file instead of giving up (or looping through `/v1/pair`).
    Superseded,
}

impl TokenError {
    pub fn reason(&self) -> ErrorReason {
        match self {
            TokenError::Invalid => ErrorReason::InvalidToken,
            TokenError::Expired => ErrorReason::TokenExpired,
            TokenError::Superseded => ErrorReason::TokenSuperseded,
        }
    }
}

/// An online management-token mutation must distinguish stale authority from
/// a persistence failure. The daemon maps the former to 401 and the latter to
/// its ordinary structured internal error.
#[derive(Debug)]
pub enum ManageTokenMutationError {
    Unauthorized(TokenError),
    Persist(crate::error::CoreError),
}

/// A successful verification. `via_alias` marks a legacy per-agent token
/// still riding the migration grace period, so `/v1/whoami` can steer its
/// holder to the shared token file.
#[derive(Debug, Clone)]
pub struct VerifiedToken {
    pub client_id: uuid::Uuid,
    pub via_alias: bool,
}

struct State {
    identity: BrokerIdentity,
    /// The plaintext key. Held in memory so `/v1/pair` and the UI can hand
    /// it out; on disk it exists only in the 0600 token file.
    token: String,
}

const RECOVERY_ALIAS_TTL: Duration = Duration::from_secs(6 * 60 * 60);
const MAX_SUPERSEDED_TOKEN_HASHES: usize = 8;
const SUPERSEDED_TOKEN_TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);

pub struct IdentityStore {
    path: PathBuf,
    token_file: PathBuf,
    ttl: Duration,
    /// Minimum `last_used` advance before a refresh is written to disk;
    /// refreshes are coalesced so the hot path costs no write.
    refresh_interval: chrono::Duration,
    integrity: Arc<StateIntegrity>,
    state: Mutex<State>,
}

fn hash_token(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    hex(&digest)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// 256-bit random bearer key: `aka_` + 64 hex chars.
fn mint_token() -> String {
    let mut buf = [0u8; 32];
    getrandom::fill(&mut buf).expect("os rng");
    format!("aka_{}", hex(&buf))
}

/// The management token's distinguishing prefix. Distinct from the agent
/// key's `aka_` so the two can never be confused, pasted into the wrong
/// field silently, or accepted by the wrong plane.
pub const MANAGE_TOKEN_PREFIX: &str = "akamgr_";

/// 256-bit random management token: `akamgr_` + 64 hex chars.
fn mint_manage_token() -> String {
    let mut buf = [0u8; 32];
    getrandom::fill(&mut buf).expect("os rng");
    format!("{MANAGE_TOKEN_PREFIX}{}", hex(&buf))
}

fn verify_manage_identity(
    identity: &BrokerIdentity,
    token: &str,
) -> std::result::Result<(), TokenError> {
    if !token.starts_with(MANAGE_TOKEN_PREFIX) {
        return Err(TokenError::Invalid);
    }
    let hash = hash_token(token);
    match &identity.manage_token_hash {
        Some(stored) if *stored == hash => {
            if identity
                .manage_token_expires_at
                .is_some_and(|expires_at| Utc::now() >= expires_at)
            {
                return Err(TokenError::Expired);
            }
            Ok(())
        }
        _ => Err(TokenError::Invalid),
    }
}

/// The shape of the per-agent-era `agents.json`, read once to carry its
/// token hashes across as aliases.
#[derive(serde::Deserialize)]
struct LegacyAgent {
    token_hash: String,
    last_used: chrono::DateTime<Utc>,
}

impl IdentityStore {
    /// Open (or establish) the identity. `identity.json` is sealed: a
    /// rewrite must not go unnoticed. On first open after the per-agent era,
    /// hashes from a legacy `agents.json` become aliases of the fresh key.
    ///
    /// The plaintext is reconciled with the token file: a matching file
    /// yields the known key; a missing or foreign file forces a re-mint
    /// (demoting the old hash to an alias so in-flight holders keep working)
    /// because the broker itself only stores the hash.
    pub fn open(
        path: PathBuf,
        token_file: PathBuf,
        legacy_agents_path: Option<&std::path::Path>,
        ttl: Duration,
        integrity: Arc<StateIntegrity>,
    ) -> Result<Self> {
        let refresh = std::cmp::min(ttl / 10, Duration::from_secs(3600));
        let refresh_interval =
            chrono::Duration::from_std(refresh).unwrap_or_else(|_| chrono::Duration::seconds(3600));

        let existing: Option<BrokerIdentity> = integrity
            .read_verified(&path)?
            .map(|bytes| serde_json::from_slice(&bytes))
            .transpose()?;

        let store = Self {
            path,
            token_file,
            ttl,
            refresh_interval,
            integrity,
            state: Mutex::new(State {
                identity: BrokerIdentity {
                    id: uuid::Uuid::nil(),
                    token_hash: String::new(),
                    alias_hashes: Vec::new(),
                    alias_last_used: std::collections::HashMap::new(),
                    alias_expires_at: std::collections::HashMap::new(),
                    superseded_token_hashes: Vec::new(),
                    minted_at: Utc::now(),
                    last_used: Utc::now(),
                    manage_token_hash: None,
                    manage_token_expires_at: None,
                },
                token: String::new(),
            }),
        };

        match existing {
            Some(identity) => {
                let on_disk = std::fs::read_to_string(&store.token_file)
                    .ok()
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty());
                match on_disk {
                    Some(token) if hash_token(&token) == identity.token_hash => {
                        let mut state = store.state.lock().unwrap();
                        state.identity = identity;
                        state.token = token;
                    }
                    _ => {
                        // The plaintext is unrecoverable (file lost, replaced,
                        // or foreign): re-mint. The old hash rides along as an
                        // alias so agents holding the old key keep working
                        // until the user rotates deliberately.
                        tracing::warn!(
                            "token file {} missing or stale; minting a fresh key",
                            store.token_file.display()
                        );
                        let mut aliases = identity.alias_hashes.clone();
                        let mut alias_last_used = identity.alias_last_used.clone();
                        let mut alias_expires_at = identity.alias_expires_at.clone();
                        let now = Utc::now();
                        if !identity.token_hash.is_empty() {
                            aliases.push(identity.token_hash.clone());
                            alias_last_used.insert(identity.token_hash.clone(), now);
                            let recovery_ttl = RECOVERY_ALIAS_TTL.min(ttl);
                            alias_expires_at.insert(
                                identity.token_hash.clone(),
                                now + chrono::Duration::from_std(recovery_ttl)
                                    .unwrap_or_else(|_| chrono::Duration::hours(6)),
                            );
                        }
                        let token = mint_token();
                        let next = BrokerIdentity {
                            id: identity.id,
                            token_hash: hash_token(&token),
                            alias_hashes: aliases,
                            alias_last_used,
                            alias_expires_at,
                            superseded_token_hashes: identity.superseded_token_hashes.clone(),
                            minted_at: Utc::now(),
                            last_used: Utc::now(),
                            // The manage token is independent of the agent
                            // key; losing the token file must not revoke it.
                            manage_token_hash: identity.manage_token_hash.clone(),
                            manage_token_expires_at: identity.manage_token_expires_at,
                        };
                        store.persist_and_write_file(&next, &token)?;
                        let mut state = store.state.lock().unwrap();
                        state.identity = next;
                        state.token = token;
                    }
                }
            }
            None => {
                // First open. Absorb the per-agent era's token hashes as
                // aliases (grace period until the first rotation).
                let legacy_agents = match legacy_agents_path {
                    Some(path) => store
                        .integrity
                        .read_verified(path)?
                        .map(|bytes| serde_json::from_slice::<Vec<LegacyAgent>>(&bytes))
                        .transpose()?
                        .unwrap_or_default(),
                    None => Vec::new(),
                };
                let now = Utc::now();
                let mut alias_hashes = Vec::new();
                let mut alias_last_used = std::collections::HashMap::new();
                let mut alias_expires_at = std::collections::HashMap::new();
                for agent in legacy_agents {
                    let age = now.signed_duration_since(agent.last_used);
                    if age.num_seconds() > ttl.as_secs() as i64 {
                        continue;
                    }
                    alias_last_used.insert(agent.token_hash.clone(), agent.last_used);
                    alias_expires_at.insert(
                        agent.token_hash.clone(),
                        agent.last_used
                            + chrono::Duration::from_std(ttl)
                                .unwrap_or_else(|_| chrono::Duration::days(30)),
                    );
                    alias_hashes.push(agent.token_hash);
                }
                let token = mint_token();
                let identity = BrokerIdentity {
                    id: uuid::Uuid::new_v4(),
                    token_hash: hash_token(&token),
                    alias_hashes,
                    alias_last_used,
                    alias_expires_at,
                    superseded_token_hashes: Vec::new(),
                    minted_at: Utc::now(),
                    last_used: Utc::now(),
                    manage_token_hash: None,
                    manage_token_expires_at: None,
                };
                store.persist_and_write_file(&identity, &token)?;
                let mut state = store.state.lock().unwrap();
                state.identity = identity;
                state.token = token;
            }
        }
        Ok(store)
    }

    fn persist(&self, identity: &BrokerIdentity) -> Result<()> {
        self.integrity
            .write(&self.path, &serde_json::to_vec_pretty(identity)?)?;
        Ok(())
    }

    fn persist_and_write_file(&self, identity: &BrokerIdentity, token: &str) -> Result<()> {
        self.persist(identity)?;
        crate::paths::write_private_atomic(&self.token_file, token.as_bytes())?;
        Ok(())
    }

    /// The stable principal id (what pairing used to call the client id).
    pub fn client_id(&self) -> uuid::Uuid {
        self.state.lock().unwrap().identity.id
    }

    /// The plaintext key, for `/v1/pair` and the UI's copy affordance.
    pub fn token(&self) -> String {
        self.state.lock().unwrap().token.clone()
    }

    /// A snapshot of the persisted record (hash, timestamps, aliases).
    pub fn info(&self) -> BrokerIdentity {
        self.state.lock().unwrap().identity.clone()
    }

    /// Legacy aliases that would authenticate right now. The Connect page
    /// must not describe hashes with a missing independent clock, or aliases
    /// past that clock's TTL, as still accepted.
    pub fn active_alias_count(&self) -> usize {
        let state = self.state.lock().unwrap();
        let now = Utc::now();
        state
            .identity
            .alias_hashes
            .iter()
            .filter(|hash| {
                state
                    .identity
                    .alias_last_used
                    .get(*hash)
                    .is_some_and(|last_used| {
                        let within_sliding_ttl =
                            now.signed_duration_since(*last_used).num_seconds()
                                <= self.ttl.as_secs() as i64;
                        let before_absolute_deadline = state
                            .identity
                            .alias_expires_at
                            .get(*hash)
                            .is_none_or(|expires_at| now < *expires_at);
                        within_sliding_ttl && before_absolute_deadline
                    })
            })
            .count()
    }

    /// Verify a presented bearer token against the key (or a legacy alias).
    /// Success refreshes the sliding TTL, coalesced to at most one disk
    /// write per interval.
    pub fn verify(&self, token: &str) -> std::result::Result<VerifiedToken, TokenError> {
        let hash = hash_token(token);
        let mut state = self.state.lock().unwrap();
        let (via_alias, last_used) = if state.identity.token_hash == hash {
            (false, state.identity.last_used)
        } else if state.identity.alias_hashes.contains(&hash) {
            let Some(last_used) = state.identity.alias_last_used.get(&hash).copied() else {
                return Err(TokenError::Expired);
            };
            if state
                .identity
                .alias_expires_at
                .get(&hash)
                .is_some_and(|expires_at| Utc::now() >= *expires_at)
            {
                return Err(TokenError::Expired);
            }
            (true, last_used)
        } else if state.identity.superseded_token_hashes.iter().any(|entry| {
            entry.token_hash == hash
                && Utc::now()
                    .signed_duration_since(entry.superseded_at)
                    .num_seconds()
                    <= SUPERSEDED_TOKEN_TTL.as_secs() as i64
        }) {
            return Err(TokenError::Superseded);
        } else {
            return Err(TokenError::Invalid);
        };
        let now = Utc::now();
        let age = now.signed_duration_since(last_used);
        if age.num_seconds() > self.ttl.as_secs() as i64 {
            return Err(TokenError::Expired);
        }
        let verified = VerifiedToken {
            client_id: state.identity.id,
            via_alias,
        };
        if age < self.refresh_interval {
            return Ok(verified);
        }
        if via_alias {
            state.identity.alias_last_used.insert(hash, now);
        } else {
            state.identity.last_used = now;
        }
        // last_used is best-effort persisted; failure to write must not fail
        // the call.
        if let Err(e) = self.persist(&state.identity) {
            tracing::warn!("could not persist key refresh: {e}");
        }
        Ok(verified)
    }

    /// A compat `/v1/pair` counts as use: refresh the sliding TTL so an
    /// expired key recovers through the documented pair path instead of
    /// dead-ending (pair would otherwise return a key that still 401s).
    pub fn touch(&self) {
        let mut state = self.state.lock().unwrap();
        state.identity.last_used = Utc::now();
        if let Err(e) = self.persist(&state.identity) {
            tracing::warn!("could not persist key refresh: {e}");
        }
    }

    /// Whether a management token has been issued (the manage API is closed
    /// until one exists).
    pub fn manage_token_issued(&self) -> bool {
        self.state
            .lock()
            .unwrap()
            .identity
            .manage_token_hash
            .is_some()
    }

    /// Issue (or rotate) the management token with no expiry, returning its
    /// plaintext — shown exactly once; only the hash is persisted.
    pub fn issue_manage_token(&self) -> Result<String> {
        self.issue_manage_token_with_ttl(None)
    }

    /// Issue (or rotate) the management token. `ttl: Some` bakes a fixed
    /// expiry into the record (bounding a leaked token's blast radius);
    /// `None` never expires. A fresh issue always resets the clock.
    pub fn issue_manage_token_with_ttl(&self, ttl: Option<Duration>) -> Result<String> {
        let mut state = self.state.lock().unwrap();
        let token = mint_manage_token();
        let mut next = state.identity.clone();
        next.manage_token_hash = Some(hash_token(&token));
        next.manage_token_expires_at = ttl.map(|ttl| {
            Utc::now()
                + chrono::Duration::from_std(ttl).unwrap_or_else(|_| chrono::Duration::days(3650))
        });
        self.persist(&next)?;
        state.identity = next;
        Ok(token)
    }

    /// Rotate a live management token without a check/use race. Verification,
    /// minting, persistence, and the in-memory swap all happen under the same
    /// identity lock, so two concurrent callers cannot both receive a token
    /// that appeared current when returned.
    pub fn rotate_manage_token_with_ttl(
        &self,
        current: &str,
        ttl: Option<Duration>,
    ) -> std::result::Result<String, ManageTokenMutationError> {
        let mut state = self.state.lock().unwrap();
        verify_manage_identity(&state.identity, current)
            .map_err(ManageTokenMutationError::Unauthorized)?;
        let token = mint_manage_token();
        let mut next = state.identity.clone();
        next.manage_token_hash = Some(hash_token(&token));
        next.manage_token_expires_at = ttl.map(|ttl| {
            Utc::now()
                + chrono::Duration::from_std(ttl).unwrap_or_else(|_| chrono::Duration::days(3650))
        });
        self.persist(&next)
            .map_err(ManageTokenMutationError::Persist)?;
        state.identity = next;
        Ok(token)
    }

    /// When the management token expires, if it does.
    pub fn manage_token_expires_at(&self) -> Option<DateTime<Utc>> {
        self.state.lock().unwrap().identity.manage_token_expires_at
    }

    /// Revoke the management token (close the manage API). Returns whether
    /// one existed.
    pub fn revoke_manage_token(&self) -> Result<bool> {
        let mut state = self.state.lock().unwrap();
        let had = state.identity.manage_token_hash.is_some();
        if had {
            let mut next = state.identity.clone();
            next.manage_token_hash = None;
            next.manage_token_expires_at = None;
            self.persist(&next)?;
            state.identity = next;
        }
        Ok(had)
    }

    /// Revoke through the live manage API, atomically requiring that the
    /// credential authorizing this request is still the current one.
    pub fn revoke_manage_token_with_token(
        &self,
        current: &str,
    ) -> std::result::Result<(), ManageTokenMutationError> {
        let mut state = self.state.lock().unwrap();
        verify_manage_identity(&state.identity, current)
            .map_err(ManageTokenMutationError::Unauthorized)?;
        let mut next = state.identity.clone();
        next.manage_token_hash = None;
        next.manage_token_expires_at = None;
        self.persist(&next)
            .map_err(ManageTokenMutationError::Persist)?;
        state.identity = next;
        Ok(())
    }

    /// Verify a presented management token. Long-lived unless issued with a
    /// TTL: re-issue to rotate, revoke to close the plane. The agent key
    /// never verifies here, nor the manage token on the agent plane —
    /// separate hashes, separate prefixes. An expired token answers
    /// `Expired`, distinct from `Invalid`, so the client can tell "re-issue
    /// this" apart from "wrong token".
    pub fn verify_manage(&self, token: &str) -> std::result::Result<(), TokenError> {
        let state = self.state.lock().unwrap();
        verify_manage_identity(&state.identity, token)
    }

    /// Rotate the key: mint a fresh one, clear the migration aliases, and
    /// rewrite the token file. The old key answers `token_superseded` so
    /// holders re-read the file. The caller is responsible for closing live
    /// sessions — rotation is the "disconnect everything" action.
    pub fn rotate(&self) -> Result<String> {
        let mut state = self.state.lock().unwrap();
        let token = mint_token();
        let now = Utc::now();
        let mut superseded_token_hashes = state.identity.superseded_token_hashes.clone();
        superseded_token_hashes.retain(|entry| {
            now.signed_duration_since(entry.superseded_at).num_seconds()
                <= SUPERSEDED_TOKEN_TTL.as_secs() as i64
        });
        superseded_token_hashes.retain(|entry| entry.token_hash != state.identity.token_hash);
        superseded_token_hashes.push(SupersededTokenHash {
            token_hash: state.identity.token_hash.clone(),
            superseded_at: now,
        });
        if superseded_token_hashes.len() > MAX_SUPERSEDED_TOKEN_HASHES {
            let excess = superseded_token_hashes.len() - MAX_SUPERSEDED_TOKEN_HASHES;
            superseded_token_hashes.drain(..excess);
        }
        let next = BrokerIdentity {
            id: state.identity.id,
            token_hash: hash_token(&token),
            alias_hashes: Vec::new(),
            alias_last_used: std::collections::HashMap::new(),
            alias_expires_at: std::collections::HashMap::new(),
            superseded_token_hashes,
            minted_at: now,
            last_used: now,
            // Rotating the agent key deliberately leaves the management
            // token alone: they authorize different planes.
            manage_token_hash: state.identity.manage_token_hash.clone(),
            manage_token_expires_at: state.identity.manage_token_expires_at,
        };
        self.persist_and_write_file(&next, &token)?;
        state.identity = next;
        state.token = token.clone();
        Ok(token)
    }
}

/// Client labels are self-asserted; keep them printable and bounded so they
/// render safely in dialogs and logs. (Also the compat pair's name rule.)
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

    fn integrity() -> Arc<StateIntegrity> {
        Arc::new(
            futures::executor::block_on(StateIntegrity::open(&crate::vault::MemoryVault::new()))
                .unwrap(),
        )
    }

    fn store(ttl: Duration) -> (IdentityStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let s = IdentityStore::open(
            dir.path().join("identity.json"),
            dir.path().join("token"),
            None,
            ttl,
            integrity(),
        )
        .unwrap();
        (s, dir)
    }

    #[test]
    fn open_mints_and_writes_the_token_file() {
        let (s, dir) = store(Duration::from_secs(3600));
        let token = s.token();
        assert!(token.starts_with("aka_"));
        assert_eq!(token.len(), 4 + 64);
        let on_disk = std::fs::read_to_string(dir.path().join("token")).unwrap();
        assert_eq!(on_disk, token);
        // 0600 on the plaintext.
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(dir.path().join("token"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        // The sealed record holds only the hash.
        let sealed = std::fs::read_to_string(dir.path().join("identity.json")).unwrap();
        assert!(!sealed.contains(&token));
        assert!(sealed.contains(&hash_token(&token)));
    }

    #[test]
    fn verify_accepts_the_key_and_rejects_others() {
        let (s, _dir) = store(Duration::from_secs(3600));
        let token = s.token();
        let verified = s.verify(&token).unwrap();
        assert!(!verified.via_alias);
        assert_eq!(verified.client_id, s.client_id());
        assert_eq!(s.verify("aka_bogus").unwrap_err(), TokenError::Invalid);
    }

    #[test]
    fn reopen_reuses_the_token_file() {
        let dir = tempfile::tempdir().unwrap();
        let integrity = integrity();
        let token = {
            let s = IdentityStore::open(
                dir.path().join("identity.json"),
                dir.path().join("token"),
                None,
                Duration::from_secs(3600),
                integrity.clone(),
            )
            .unwrap();
            s.token()
        };
        let s = IdentityStore::open(
            dir.path().join("identity.json"),
            dir.path().join("token"),
            None,
            Duration::from_secs(3600),
            integrity,
        )
        .unwrap();
        assert_eq!(s.token(), token, "a matching file keeps the same key");
        assert!(s.verify(&token).is_ok());
    }

    #[test]
    fn lost_token_file_reminting_keeps_the_old_key_as_alias() {
        let dir = tempfile::tempdir().unwrap();
        let integrity = integrity();
        let old = {
            let s = IdentityStore::open(
                dir.path().join("identity.json"),
                dir.path().join("token"),
                None,
                Duration::from_secs(3600),
                integrity.clone(),
            )
            .unwrap();
            s.token()
        };
        std::fs::remove_file(dir.path().join("token")).unwrap();
        let s = IdentityStore::open(
            dir.path().join("identity.json"),
            dir.path().join("token"),
            None,
            Duration::from_secs(3600),
            integrity,
        )
        .unwrap();
        assert_ne!(s.token(), old);
        let verified = s.verify(&old).expect("old key stays valid as an alias");
        assert!(verified.via_alias);
        assert!(!s.verify(&s.token()).unwrap().via_alias);
        let info = s.info();
        let expiry = info
            .alias_expires_at
            .get(&hash_token(&old))
            .expect("recovery alias has an absolute deadline");
        assert!(*expiry <= Utc::now() + chrono::Duration::hours(6));
    }

    #[test]
    fn rotation_supersedes_and_clears_aliases() {
        let (s, dir) = store(Duration::from_secs(3600));
        let old = s.token();
        let new = s.rotate().unwrap();
        assert_ne!(old, new);
        assert_eq!(s.verify(&old).unwrap_err(), TokenError::Superseded);
        assert!(s.verify(&new).is_ok());
        assert_eq!(
            std::fs::read_to_string(dir.path().join("token")).unwrap(),
            new
        );
        assert!(s.info().alias_hashes.is_empty());
    }

    #[test]
    fn several_rotated_keys_remain_superseded_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let integrity = integrity();
        let mut old = Vec::new();
        {
            let store = IdentityStore::open(
                dir.path().join("identity.json"),
                dir.path().join("token"),
                None,
                Duration::from_secs(3600),
                integrity.clone(),
            )
            .unwrap();
            for _ in 0..3 {
                old.push(store.token());
                store.rotate().unwrap();
            }
            assert_eq!(store.info().superseded_token_hashes.len(), 3);
        }
        let reopened = IdentityStore::open(
            dir.path().join("identity.json"),
            dir.path().join("token"),
            None,
            Duration::from_secs(3600),
            integrity,
        )
        .unwrap();
        for token in old {
            assert_eq!(reopened.verify(&token).unwrap_err(), TokenError::Superseded);
        }
    }

    #[test]
    fn legacy_agent_hashes_become_aliases() {
        let dir = tempfile::tempdir().unwrap();
        let integrity = integrity();
        let legacy_token = "aka_legacy_token";
        let legacy = serde_json::json!([{
            "id": uuid::Uuid::new_v4(),
            "name": "claude-code",
            "token_hash": hash_token(legacy_token),
            "token_preview": "aka_legacy_",
            "paired_at": Utc::now(),
            "last_used": Utc::now(),
        }]);
        let agents_path = dir.path().join("agents.json");
        integrity
            .write(&agents_path, &serde_json::to_vec_pretty(&legacy).unwrap())
            .unwrap();

        let s = IdentityStore::open(
            dir.path().join("identity.json"),
            dir.path().join("token"),
            Some(&agents_path),
            Duration::from_secs(3600),
            integrity,
        )
        .unwrap();
        let verified = s.verify(legacy_token).expect("legacy token is an alias");
        assert!(verified.via_alias);
        // Rotation ends the grace period.
        s.rotate().unwrap();
        assert_eq!(s.verify(legacy_token).unwrap_err(), TokenError::Invalid);
    }

    #[test]
    fn shared_key_activity_does_not_revive_an_expired_legacy_alias() {
        let dir = tempfile::tempdir().unwrap();
        let integrity = integrity();
        let legacy_token = "aka_legacy_token";
        let legacy = serde_json::json!([{
            "id": uuid::Uuid::new_v4(),
            "name": "claude-code",
            "token_hash": hash_token(legacy_token),
            "token_preview": "aka_legacy_",
            "paired_at": Utc::now(),
            "last_used": Utc::now(),
        }]);
        let agents_path = dir.path().join("agents.json");
        integrity
            .write(&agents_path, &serde_json::to_vec_pretty(&legacy).unwrap())
            .unwrap();

        let s = IdentityStore::open(
            dir.path().join("identity.json"),
            dir.path().join("token"),
            Some(&agents_path),
            Duration::from_secs(1),
            integrity,
        )
        .unwrap();
        assert!(s.verify(legacy_token).is_ok());
        assert_eq!(s.active_alias_count(), 1);
        std::thread::sleep(Duration::from_millis(1100));
        s.touch();
        assert!(s.verify(&s.token()).is_ok());
        assert_eq!(s.verify(legacy_token).unwrap_err(), TokenError::Expired);
        assert_eq!(s.active_alias_count(), 0);
    }

    #[test]
    fn expired_legacy_aliases_are_not_imported() {
        let dir = tempfile::tempdir().unwrap();
        let integrity = integrity();
        let legacy_token = "aka_expired_legacy_token";
        let legacy = serde_json::json!([{
            "id": uuid::Uuid::new_v4(),
            "name": "old-agent",
            "token_hash": hash_token(legacy_token),
            "token_preview": "aka_expired_",
            "paired_at": Utc::now() - chrono::Duration::hours(2),
            "last_used": Utc::now() - chrono::Duration::hours(2),
        }]);
        let agents_path = dir.path().join("agents.json");
        integrity
            .write(&agents_path, &serde_json::to_vec_pretty(&legacy).unwrap())
            .unwrap();

        let s = IdentityStore::open(
            dir.path().join("identity.json"),
            dir.path().join("token"),
            Some(&agents_path),
            Duration::from_secs(3600),
            integrity,
        )
        .unwrap();
        assert_eq!(s.verify(legacy_token).unwrap_err(), TokenError::Invalid);
        assert!(s.info().alias_hashes.is_empty());
    }

    #[test]
    fn aliases_missing_an_independent_clock_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let integrity = integrity();
        let primary = "aka_primary_token";
        let legacy = "aka_alias_without_a_clock";
        let identity = serde_json::json!({
            "id": uuid::Uuid::new_v4(),
            "token_hash": hash_token(primary),
            "alias_hashes": [hash_token(legacy)],
            "minted_at": Utc::now(),
            "last_used": Utc::now(),
        });
        integrity
            .write(
                &dir.path().join("identity.json"),
                &serde_json::to_vec(&identity).unwrap(),
            )
            .unwrap();
        std::fs::write(dir.path().join("token"), primary).unwrap();

        let s = IdentityStore::open(
            dir.path().join("identity.json"),
            dir.path().join("token"),
            None,
            Duration::from_secs(3600),
            integrity,
        )
        .unwrap();
        assert!(s.verify(primary).is_ok());
        assert_eq!(s.verify(legacy).unwrap_err(), TokenError::Expired);
        assert_eq!(s.active_alias_count(), 0);
    }

    #[test]
    fn malformed_legacy_agents_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let integrity = integrity();
        let agents_path = dir.path().join("agents.json");
        integrity.write(&agents_path, b"{}").unwrap();

        assert!(IdentityStore::open(
            dir.path().join("identity.json"),
            dir.path().join("token"),
            Some(&agents_path),
            Duration::from_secs(3600),
            integrity,
        )
        .is_err());
    }

    #[test]
    fn tampered_legacy_agents_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let integrity = integrity();
        let agents_path = dir.path().join("agents.json");
        integrity.write(&agents_path, b"[]").unwrap();
        let sealed = std::fs::read_to_string(&agents_path).unwrap();
        std::fs::write(
            &agents_path,
            sealed.replace("\"payload\":[]", "\"payload\":[ ]"),
        )
        .unwrap();

        assert!(IdentityStore::open(
            dir.path().join("identity.json"),
            dir.path().join("token"),
            Some(&agents_path),
            Duration::from_secs(3600),
            integrity,
        )
        .is_err());
    }

    #[test]
    fn expired_key_recovers_via_touch() {
        let (s, _dir) = store(Duration::from_secs(0));
        let token = s.token();
        std::thread::sleep(Duration::from_millis(1100));
        assert_eq!(s.verify(&token).unwrap_err(), TokenError::Expired);
        s.touch();
        assert!(s.verify(&token).is_ok());
    }

    #[test]
    fn verify_coalesces_the_ttl_refresh_write() {
        // ttl 2s → refresh interval ~200ms.
        let (s, dir) = store(Duration::from_secs(2));
        let token = s.token();
        let path = dir.path().join("identity.json");
        let persisted_last_used = |p: &std::path::Path| {
            let sealed: serde_json::Value =
                serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap();
            let identity: BrokerIdentity =
                serde_json::from_value(sealed["payload"].clone()).unwrap();
            identity.last_used
        };
        let at_mint = persisted_last_used(&path);

        s.verify(&token).unwrap();
        assert_eq!(
            persisted_last_used(&path),
            at_mint,
            "a sub-interval refresh must not rewrite identity.json"
        );

        std::thread::sleep(Duration::from_millis(350));
        s.verify(&token).unwrap();
        assert!(
            persisted_last_used(&path) > at_mint,
            "a refresh past the interval must be written"
        );
    }

    #[test]
    fn manage_token_is_a_separate_credential() {
        let (s, _dir) = store(Duration::from_secs(3600));
        // Closed until issued; the agent key never opens the manage plane.
        assert!(!s.manage_token_issued());
        assert_eq!(
            s.verify_manage(&s.token()).unwrap_err(),
            TokenError::Invalid
        );

        let manage = s.issue_manage_token().unwrap();
        assert!(manage.starts_with("akamgr_"));
        assert_eq!(manage.len(), 7 + 64);
        assert!(s.manage_token_issued());
        s.verify_manage(&manage).unwrap();
        // The manage token never authenticates the agent plane.
        assert_eq!(s.verify(&manage).unwrap_err(), TokenError::Invalid);
        // The sealed record never holds the plaintext.
        let sealed = std::fs::read_to_string(_dir.path().join("identity.json")).unwrap();
        assert!(!sealed.contains(&manage));

        // Rotating the agent key leaves the manage token working.
        s.rotate().unwrap();
        s.verify_manage(&manage).unwrap();

        // Re-issuing supersedes; revoking closes the plane.
        let second = s.issue_manage_token().unwrap();
        assert_eq!(s.verify_manage(&manage).unwrap_err(), TokenError::Invalid);
        s.verify_manage(&second).unwrap();
        assert!(s.revoke_manage_token().unwrap());
        assert_eq!(s.verify_manage(&second).unwrap_err(), TokenError::Invalid);
        assert!(!s.revoke_manage_token().unwrap());
    }

    #[test]
    fn online_manage_token_mutations_require_the_still_current_token() {
        let (s, _dir) = store(Duration::from_secs(3600));
        let first = s
            .issue_manage_token_with_ttl(Some(Duration::from_secs(3600)))
            .unwrap();
        let second = s
            .rotate_manage_token_with_ttl(&first, Some(Duration::from_secs(7200)))
            .unwrap();

        assert_eq!(s.verify_manage(&first), Err(TokenError::Invalid));
        s.verify_manage(&second).unwrap();
        assert!(matches!(
            s.rotate_manage_token_with_ttl(&first, Some(Duration::from_secs(3600))),
            Err(ManageTokenMutationError::Unauthorized(TokenError::Invalid))
        ));
        assert!(matches!(
            s.revoke_manage_token_with_token(&first),
            Err(ManageTokenMutationError::Unauthorized(TokenError::Invalid))
        ));

        s.revoke_manage_token_with_token(&second).unwrap();
        assert!(!s.manage_token_issued());
        assert_eq!(s.verify_manage(&second), Err(TokenError::Invalid));
    }

    #[test]
    fn a_manage_token_ttl_expires_and_reissue_resets_it() {
        let (s, _dir) = store(Duration::from_secs(3600));
        // No TTL by default: never expires.
        let forever = s.issue_manage_token().unwrap();
        assert!(s.manage_token_expires_at().is_none());
        s.verify_manage(&forever).unwrap();

        // An immediate expiry rejects with Expired (distinct from Invalid),
        // and the recorded horizon is surfaced.
        let expired = s.issue_manage_token_with_ttl(Some(Duration::ZERO)).unwrap();
        assert!(s.manage_token_expires_at().is_some());
        assert_eq!(s.verify_manage(&expired).unwrap_err(), TokenError::Expired);
        // The old (no-TTL) token is superseded regardless.
        assert_eq!(s.verify_manage(&forever).unwrap_err(), TokenError::Invalid);

        // Re-issuing without a TTL clears the expiry.
        let fresh = s.issue_manage_token().unwrap();
        assert!(s.manage_token_expires_at().is_none());
        s.verify_manage(&fresh).unwrap();

        // A live TTL still verifies.
        let live = s
            .issue_manage_token_with_ttl(Some(Duration::from_secs(3600)))
            .unwrap();
        s.verify_manage(&live).unwrap();
        assert!(s.manage_token_expires_at().unwrap() > Utc::now());
    }

    #[test]
    fn a_ttl_manage_token_survives_reopen_with_its_horizon() {
        let dir = tempfile::tempdir().unwrap();
        let integrity = integrity();
        let token = {
            let s = IdentityStore::open(
                dir.path().join("identity.json"),
                dir.path().join("token"),
                None,
                Duration::from_secs(3600),
                integrity.clone(),
            )
            .unwrap();
            s.issue_manage_token_with_ttl(Some(Duration::from_secs(3600)))
                .unwrap()
        };
        let s = IdentityStore::open(
            dir.path().join("identity.json"),
            dir.path().join("token"),
            None,
            Duration::from_secs(3600),
            integrity,
        )
        .unwrap();
        s.verify_manage(&token)
            .expect("live TTL token survives reopen");
        assert!(s.manage_token_expires_at().unwrap() > Utc::now());
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
