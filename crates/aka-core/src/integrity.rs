//! On-disk state integrity.
//!
//! `index.json`, `rules.json`, and `agents.json` are non-secret but
//! *binding*: a local process that can rewrite them can repoint a pinned
//! target or a pinned identity and ride an existing standing rule with no
//! prompt. Each file is therefore sealed in a single-file envelope
//! `{"v", "alg", "mac", "payload"}` — one atomic rename, no companion file to
//! desynchronize — where `mac` is HMAC-SHA256 over
//! `basename \0 payload-bytes` (the basename binds the seal to its file,
//! so a whole envelope cannot be transplanted between state files), keyed
//! by a 256-bit key held in the vault (the Keychain on macOS): readable
//! by the broker, but not writable by an arbitrary user process without
//! an OS access decision. A file that fails verification **refuses to
//! load**.
//!
//! Migration is trust-on-first-use: a bare legacy file is accepted and
//! sealed only while the integrity key is being created for the first
//! time. Once the key exists, a bare file is a downgrade — exactly what a
//! tamperer who cannot forge the MAC would produce — and is refused.
//!
//! Two files do not fit that whole-file shape and take the variants below:
//! `audit.jsonl` is append-only and would pay an O(n) re-seal per entry, so
//! it chains a per-line MAC ([`StateIntegrity::chain`]) and seals only the
//! chain head; `health.json` is advisory, so a failed verification discards
//! it loudly rather than refusing to start.

use std::path::Path;

use hmac::{Hmac, Mac as _};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use uuid::Uuid;
use zeroize::{Zeroize as _, Zeroizing};

use crate::error::CoreError;
use crate::paths::{write_private_atomic, Paths};
use crate::vault::{SecretVault, VaultAttrs};
use crate::Result;

/// Reserved vault item holding the HMAC key. It is not in the secrets
/// index, so it is never listed in the UI or exposed to agents, and the
/// nil UUID cannot collide with the v4 ids user secrets get.
const KEY_ID: Uuid = Uuid::nil();
const KEY_NAME: &str = "AKA_STATE_INTEGRITY_KEY";
const ENVELOPE_VERSION: u32 = 1;
const STATE_SCHEMA_VERSION: u32 = 1;
const ALG: &str = "hmac-sha256";

#[derive(Serialize)]
struct SealWrite<'a> {
    v: u32,
    schema_version: u32,
    alg: &'a str,
    mac: String,
    payload: &'a serde_json::value::RawValue,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SealRead<'a> {
    v: u32,
    #[serde(default)]
    schema_version: Option<u32>,
    alg: String,
    mac: String,
    #[serde(borrow)]
    payload: &'a serde_json::value::RawValue,
}

pub struct StateIntegrity {
    key: Zeroizing<Vec<u8>>,
    /// Whether the key pre-existed this open. Once established, a bare
    /// (unsealed) state file is a downgrade, not a migration.
    established: bool,
}

impl StateIntegrity {
    /// Load the integrity key from the vault, creating it on first run.
    pub async fn open(vault: &dyn SecretVault) -> Result<Self> {
        Self::open_with_established_state(vault, false).await
    }

    /// Load the integrity key while accounting for already-sealed state.
    ///
    /// The vault item alone cannot distinguish a first run from deletion of
    /// the integrity key. A recognizable sealed envelope on disk proves that
    /// this store was established, so a missing key must not reopen the
    /// trust-on-first-use migration path.
    pub async fn open_for_paths(vault: &dyn SecretVault, paths: &Paths) -> Result<Self> {
        Self::open_with_established_state(vault, sealed_state_exists(paths)?).await
    }

    async fn open_with_established_state(
        vault: &dyn SecretVault,
        established_on_disk: bool,
    ) -> Result<Self> {
        match vault.get(&KEY_ID).await {
            Ok(stored) => {
                let key = decode_hex(&stored)
                    .ok_or_else(|| CoreError::Vault("integrity key is corrupt".into()))?;
                Ok(Self {
                    key: Zeroizing::new(key),
                    established: true,
                })
            }
            Err(CoreError::SecretNotFound) => {
                let mut bytes = [0u8; 32];
                getrandom::fill(&mut bytes).expect("os rng");
                let hex = encode_hex(&bytes);
                vault.set(
                    &KEY_ID,
                    &VaultAttrs {
                        name: KEY_NAME.into(),
                        created_at: chrono::Utc::now(),
                    },
                    &Zeroizing::new(hex),
                )?;
                let key = Zeroizing::new(bytes.to_vec());
                bytes.zeroize();
                Ok(Self {
                    key,
                    established: established_on_disk,
                })
            }
            Err(e) => Err(e),
        }
    }

    /// Read and verify a sealed state file.
    ///
    /// - Absent file → `Ok(None)` (fresh install).
    /// - Sealed and verified → the payload bytes.
    /// - Sealed but MAC/version mismatch → [`CoreError::StateTampered`].
    /// - Bare legacy file → accepted **and immediately resealed** while the
    ///   key is first being established; refused as a downgrade afterwards.
    pub fn read_verified(&self, path: &Path) -> Result<Option<Vec<u8>>> {
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        match serde_json::from_slice::<SealRead>(&bytes) {
            Ok(sealed) => {
                if sealed.v != ENVELOPE_VERSION || sealed.alg != ALG {
                    return Err(CoreError::StateTampered(display(path)));
                }
                let payload = sealed.payload.get().as_bytes();
                if !self.verify(&basename(path), sealed.schema_version, payload, &sealed.mac) {
                    return Err(CoreError::StateTampered(display(path)));
                }
                match sealed.schema_version {
                    Some(version) if version > STATE_SCHEMA_VERSION => {
                        return Err(CoreError::UnsupportedStateVersion {
                            path: display(path),
                            found: version,
                            supported: STATE_SCHEMA_VERSION,
                        });
                    }
                    Some(STATE_SCHEMA_VERSION) => {}
                    Some(_) => return Err(CoreError::StateTampered(display(path))),
                    None => {
                        // Version the already-authenticated legacy envelope
                        // immediately, without changing its payload format.
                        // Best-effort: the payload is already verified, so a
                        // read-only or otherwise unwritable store must still
                        // open — a failed re-seal only defers the version bump
                        // rather than bricking the read.
                        if let Err(error) = self.write(path, payload) {
                            tracing::warn!(
                                "could not re-version legacy state file {}: {error}",
                                path.display()
                            );
                        }
                    }
                }
                Ok(Some(payload.to_vec()))
            }
            Err(_) => {
                if self.established {
                    // A bare file after the key exists is exactly the
                    // rewrite defends against: refuse.
                    return Err(CoreError::StateTampered(display(path)));
                }
                // Trust-on-first-use: seal now so protection starts at once.
                self.write(path, &bytes)?;
                tracing::warn!(
                    "sealed legacy state file {} (trust-on-first-use migration)",
                    path.display()
                );
                Ok(Some(bytes))
            }
        }
    }

    /// Seal `payload` (which must be valid JSON) and write it atomically.
    pub fn write(&self, path: &Path, payload: &[u8]) -> Result<()> {
        let text = String::from_utf8(payload.to_vec())
            .map_err(|_| CoreError::Vault("state payload is not UTF-8".into()))?;
        let raw = serde_json::value::RawValue::from_string(text)?;
        let sealed = SealWrite {
            v: ENVELOPE_VERSION,
            schema_version: STATE_SCHEMA_VERSION,
            alg: ALG,
            // MAC the exact bytes that will be read back out of the
            // envelope (RawValue embeds and yields them verbatim).
            mac: self.mac_hex(
                &basename(path),
                Some(STATE_SCHEMA_VERSION),
                raw.get().as_bytes(),
            ),
            payload: &raw,
        };
        write_private_atomic(path, &serde_json::to_vec(&sealed)?)?;
        Ok(())
    }

    /// Chain one record onto a running MAC head, returning the new head.
    ///
    /// [`Self::write`] seals a file whole, which costs a re-MAC of everything
    /// on every change — fine for a settings file rewritten by hand, wrong for
    /// an append-only log written on every brokered call. Chaining instead
    /// MACs `basename \0 previous-head \0 record`, so each record costs one
    /// HMAC over itself while still depending on every record before it:
    /// editing or inserting one line invalidates that line and every line
    /// after it.
    ///
    /// A chain cannot see a *truncation* on its own — a shortened chain is
    /// still internally consistent — so the head belongs in a sealed file the
    /// tamperer cannot rewrite. [`crate::audit::AuditLog`] does exactly that.
    pub fn chain(&self, basename: &str, previous: &str, record: &[u8]) -> String {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&self.key).expect("hmac accepts any key length");
        mac.update(basename.as_bytes());
        mac.update(&[0]);
        mac.update(previous.as_bytes());
        mac.update(&[0]);
        mac.update(record);
        encode_hex(&mac.finalize().into_bytes())
    }

    /// Constant-time comparison of two hex MACs of the same length.
    pub fn chain_matches(&self, expected: &str, found: &str) -> bool {
        let (Some(expected), Some(found)) = (decode_hex(expected), decode_hex(found)) else {
            return false;
        };
        if expected.len() != found.len() {
            return false;
        }
        expected
            .iter()
            .zip(found.iter())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
    }

    fn mac(&self, basename: &str, schema_version: Option<u32>, payload: &[u8]) -> Hmac<Sha256> {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&self.key).expect("hmac accepts any key length");
        mac.update(basename.as_bytes());
        mac.update(&[0]);
        if let Some(schema_version) = schema_version {
            mac.update(&schema_version.to_be_bytes());
            mac.update(&[0]);
        }
        mac.update(payload);
        mac
    }

    fn mac_hex(&self, basename: &str, schema_version: Option<u32>, payload: &[u8]) -> String {
        encode_hex(
            &self
                .mac(basename, schema_version, payload)
                .finalize()
                .into_bytes(),
        )
    }

    fn verify(
        &self,
        basename: &str,
        schema_version: Option<u32>,
        payload: &[u8],
        mac_hex: &str,
    ) -> bool {
        let Some(expected) = decode_hex(mac_hex) else {
            return false;
        };
        // Constant-time comparison via the hmac crate.
        self.mac(basename, schema_version, payload)
            .verify_slice(&expected)
            .is_ok()
    }
}

fn sealed_state_exists(paths: &Paths) -> Result<bool> {
    let protected = [
        paths.index_file(),
        paths.access_file(),
        paths.identity_file(),
        paths.endpoints_file(),
        paths.audit_seal_file(),
        paths.health_file(),
    ];
    for path in protected {
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
            continue;
        };
        let Some(object) = value.as_object() else {
            continue;
        };
        if object.contains_key("mac") && object.contains_key("payload") {
            return Ok(true);
        }
    }
    Ok(false)
}

fn basename(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn display(path: &Path) -> String {
    path.display().to_string()
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn decode_hex(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::MemoryVault;

    async fn fresh() -> (StateIntegrity, MemoryVault) {
        let vault = MemoryVault::new();
        let integrity = StateIntegrity::open(&vault).await.unwrap();
        (integrity, vault)
    }

    #[tokio::test]
    async fn roundtrip_and_key_reuse_across_opens() {
        let (integrity, vault) = fresh().await;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rules.json");
        integrity.write(&path, br#"[{"rule": 1}]"#).unwrap();
        let read = integrity.read_verified(&path).unwrap().unwrap();
        assert_eq!(read, br#"[{"rule": 1}]"#);
        // A second open on the same vault shares the key.
        let again = StateIntegrity::open(&vault).await.unwrap();
        assert!(again.established);
        assert_eq!(again.read_verified(&path).unwrap().unwrap(), read);
    }

    #[tokio::test]
    async fn absent_file_is_fresh() {
        let (integrity, _vault) = fresh().await;
        let dir = tempfile::tempdir().unwrap();
        assert!(integrity
            .read_verified(&dir.path().join("index.json"))
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn tampered_payload_refuses_to_load() {
        let (integrity, _vault) = fresh().await;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("index.json");
        integrity
            .write(&path, br#"{"host": "api.github.com"}"#)
            .unwrap();
        let sealed = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, sealed.replace("api.github.com", "evil.example.com")).unwrap();
        assert!(matches!(
            integrity.read_verified(&path),
            Err(CoreError::StateTampered(_))
        ));
    }

    #[tokio::test]
    async fn envelope_cannot_be_transplanted_between_files() {
        let (integrity, _vault) = fresh().await;
        let dir = tempfile::tempdir().unwrap();
        let rules = dir.path().join("rules.json");
        integrity.write(&rules, br#"[]"#).unwrap();
        // Copy the (validly sealed) rules envelope over agents.json.
        let agents = dir.path().join("agents.json");
        std::fs::copy(&rules, &agents).unwrap();
        assert!(integrity.read_verified(&rules).is_ok());
        assert!(matches!(
            integrity.read_verified(&agents),
            Err(CoreError::StateTampered(_))
        ));
    }

    #[tokio::test]
    async fn legacy_file_is_sealed_on_first_open_only() {
        let vault = MemoryVault::new();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("index.json");
        std::fs::write(&path, br#"{"secrets": []}"#).unwrap();

        // Key being established: trust-on-first-use accepts and reseals.
        let integrity = StateIntegrity::open(&vault).await.unwrap();
        assert!(!integrity.established);
        let read = integrity.read_verified(&path).unwrap().unwrap();
        assert_eq!(read, br#"{"secrets": []}"#);
        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert!(on_disk.contains("\"mac\""), "file was resealed: {on_disk}");

        // Key established: a bare file is a downgrade and is refused.
        std::fs::write(&path, br#"{"secrets": []}"#).unwrap();
        let again = StateIntegrity::open(&vault).await.unwrap();
        assert!(matches!(
            again.read_verified(&path),
            Err(CoreError::StateTampered(_))
        ));
    }

    #[tokio::test]
    async fn sealed_state_keeps_tofu_closed_when_the_vault_key_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::under(dir.path());
        std::fs::create_dir_all(&paths.data_dir).unwrap();

        let original_vault = MemoryVault::new();
        let original = StateIntegrity::open(&original_vault).await.unwrap();
        original
            .write(&paths.index_file(), br#"{"secrets":[]}"#)
            .unwrap();

        // Model deletion of the integrity item by opening the established
        // state with an otherwise-empty vault.
        let replacement_vault = MemoryVault::new();
        let replacement = StateIntegrity::open_for_paths(&replacement_vault, &paths)
            .await
            .unwrap();
        assert!(replacement.established);

        std::fs::write(&paths.index_file(), br#"{"secrets":[]}"#).unwrap();
        assert!(matches!(
            replacement.read_verified(&paths.index_file()),
            Err(CoreError::StateTampered(_))
        ));
    }

    #[tokio::test]
    async fn a_future_state_schema_is_refused_without_truncating_it() {
        let (integrity, _vault) = fresh().await;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("index.json");
        let raw = serde_json::value::RawValue::from_string(r#"{"future_narrowing":true}"#.into())
            .unwrap();
        let future_version = STATE_SCHEMA_VERSION + 1;
        let sealed = SealWrite {
            v: ENVELOPE_VERSION,
            schema_version: future_version,
            alg: ALG,
            mac: integrity.mac_hex(&basename(&path), Some(future_version), raw.get().as_bytes()),
            payload: &raw,
        };
        std::fs::write(&path, serde_json::to_vec(&sealed).unwrap()).unwrap();

        assert!(matches!(
            integrity.read_verified(&path),
            Err(CoreError::UnsupportedStateVersion {
                found,
                supported,
                ..
            }) if found == future_version && supported == STATE_SCHEMA_VERSION
        ));
        assert!(
            std::fs::read_to_string(&path)
                .unwrap()
                .contains("future_narrowing"),
            "a refused future payload must remain untouched"
        );
    }
}
