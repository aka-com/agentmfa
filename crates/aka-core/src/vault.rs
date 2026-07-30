//! Secret value storage.
//!
//! Each secret's sensitive material is one Keychain item, keyed by the
//! secret's stable UUID (service `com.aka.desktop`). Everything that is
//! *not* a secret value lives in `index.json` (see `store`); the vault
//! stores values and nothing else.
//!
//! Backends:
//! - `MacKeychainVault` (macOS): the real thing, over Security.framework
//!   directly — see [`crate::keychain`] for which of the two macOS keychains
//!   it lands in and why.
//! - `EncryptedFileVault`: the production non-macOS backend (hosted Linux),
//!   a `0600` JSON file whose values are XChaCha20-Poly1305 sealed under a
//!   master key the host provides (`AKA_VAULT_KEY`/`AKA_VAULT_KEY_FILE`).
//! - `FileVault`: dev fallback for non-macOS builds with no key configured,
//!   a `0600` JSON file, *not encrypted*, loudly not for production.
//! - `MemoryVault`: tests.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use base64::Engine as _;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::CoreError;
use crate::types::SecretValue;

/// The secret's non-sensitive Keychain attributes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultAttrs {
    pub name: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// The read path (`get`) is `async`:
/// network-backed vaults (Vault, cloud secret managers, just-in-time
/// issuance) are read-bound, and the broker fetches values post-approval
/// from async context. Writes stay synchronous — they are UI-driven CRUD
/// against a local store today; revisit if a network backend needs them.
#[async_trait::async_trait]
pub trait SecretVault: Send + Sync {
    /// Create or replace the item for `id`.
    fn set(&self, id: &Uuid, attrs: &VaultAttrs, value: &SecretValue) -> Result<(), CoreError>;

    /// Fetch the value. Called as late as possible — after approval, or for
    /// the short prefix reveal — and dropped immediately.
    async fn get(&self, id: &Uuid) -> Result<SecretValue, CoreError>;

    fn delete(&self, id: &Uuid) -> Result<(), CoreError>;

    /// Update the non-sensitive attributes.
    fn set_attrs(&self, id: &Uuid, attrs: &VaultAttrs) -> Result<(), CoreError>;

    /// Whether this backend stores secret values in the clear.
    ///
    /// Only the dev fallback does. It exists so a non-macOS checkout runs
    /// without a master key, and it says so loudly in the log — but a log line
    /// is not a boundary, and a broker started with `--listen` would happily
    /// serve a network from a vault that is a readable JSON file. The serve
    /// path asks this and refuses.
    fn is_plaintext_development(&self) -> bool {
        false
    }
}

/// The durable backend that owns a store's secret values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PlatformVaultBackend {
    MacosKeychain,
    EncryptedFile,
    PlaintextDevFile,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VaultBackendRecord {
    version: u32,
    backend: PlatformVaultBackend,
}

const VAULT_BACKEND_RECORD_VERSION: u32 = 1;

/// The backend this process is configured to select.
pub fn selected_platform_vault_backend(_paths: &crate::paths::Paths) -> PlatformVaultBackend {
    #[cfg(target_os = "macos")]
    {
        PlatformVaultBackend::MacosKeychain
    }
    #[cfg(not(target_os = "macos"))]
    {
        if master_key_from_env().is_some() {
            PlatformVaultBackend::EncryptedFile
        } else {
            PlatformVaultBackend::PlaintextDevFile
        }
    }
}

/// The backend already recorded for the store, with a compatibility
/// inference for stores created before the advisory record existed.
pub fn recorded_platform_vault_backend(
    paths: &crate::paths::Paths,
) -> Option<PlatformVaultBackend> {
    if let Some(recorded) = read_vault_backend_record(paths) {
        return Some(recorded);
    }
    #[cfg(any(not(target_os = "macos"), test))]
    {
        infer_file_vault_backend(paths)
    }
    #[cfg(all(target_os = "macos", not(test)))]
    {
        None
    }
}

fn read_vault_backend_record(paths: &crate::paths::Paths) -> Option<PlatformVaultBackend> {
    let bytes = std::fs::read(paths.vault_backend_file()).ok()?;
    let record: VaultBackendRecord = serde_json::from_slice(&bytes).ok()?;
    (record.version == VAULT_BACKEND_RECORD_VERSION).then_some(record.backend)
}

#[cfg(any(not(target_os = "macos"), test))]
fn infer_file_vault_backend(paths: &crate::paths::Paths) -> Option<PlatformVaultBackend> {
    let (encrypted, plaintext) = file_vault_presence(paths);
    match (encrypted, plaintext) {
        (true, false) => Some(PlatformVaultBackend::EncryptedFile),
        (false, true) => Some(PlatformVaultBackend::PlaintextDevFile),
        _ => None,
    }
}

#[cfg(any(not(target_os = "macos"), test))]
fn file_vault_presence(paths: &crate::paths::Paths) -> (bool, bool) {
    (
        paths.encrypted_vault_file().try_exists().unwrap_or(false),
        paths.dev_vault_file().try_exists().unwrap_or(false),
    )
}

#[cfg(any(not(target_os = "macos"), test))]
fn record_vault_backend(
    paths: &crate::paths::Paths,
    backend: PlatformVaultBackend,
) -> Result<(), CoreError> {
    let bytes = serde_json::to_vec_pretty(&VaultBackendRecord {
        version: VAULT_BACKEND_RECORD_VERSION,
        backend,
    })?;
    crate::paths::write_private_atomic(&paths.vault_backend_file(), &bytes)?;
    Ok(())
}

#[cfg(any(not(target_os = "macos"), test))]
fn check_vault_backend(
    paths: &crate::paths::Paths,
    selected: PlatformVaultBackend,
) -> Result<(), CoreError> {
    if read_vault_backend_record(paths).is_none() && file_vault_presence(paths) == (true, true) {
        return Err(CoreError::Vault(
            "both encrypted and plaintext vault files exist, but no valid backend marker \
             selects one; refusing to guess"
                .into(),
        ));
    }
    let Some(recorded) = recorded_platform_vault_backend(paths) else {
        return Ok(());
    };
    if recorded == selected {
        return Ok(());
    }
    let message = match (recorded, selected) {
        (PlatformVaultBackend::EncryptedFile, PlatformVaultBackend::PlaintextDevFile) => {
            "this store's secrets are sealed by the encrypted vault — set \
             AKA_VAULT_KEY or AKA_VAULT_KEY_FILE and retry"
                .to_string()
        }
        (PlatformVaultBackend::PlaintextDevFile, PlatformVaultBackend::EncryptedFile) => {
            "this store uses the plaintext development vault — unset \
             AKA_VAULT_KEY/AKA_VAULT_KEY_FILE or migrate the vault before retrying"
                .to_string()
        }
        _ => format!(
            "this store uses the {recorded:?} vault, but this process selected {selected:?}"
        ),
    };
    Err(CoreError::Vault(message))
}

/* ------------------------------- macOS ---------------------------------- */

const MAC_KEYCHAIN_SERVICE: &str = "com.aka.desktop";

/// The macOS Keychain backend: one generic-password item per secret (service
/// `com.aka.desktop`, account = the secret's UUID), over Security.framework
/// directly. Dev roots use a root-scoped service so `mfa serve --root ...`
/// cannot create or rotate production vault state.
///
/// Which of the two macOS keychains those items live in — and therefore
/// whether reads put an OS dialog in front of the user — is decided at open
/// time by [`crate::keychain`].
#[cfg(target_os = "macos")]
pub type MacKeychainVault =
    crate::keychain::KeychainVault<crate::keychain::darwin::SecurityFramework>;

#[cfg(target_os = "macos")]
impl MacKeychainVault {
    pub const SERVICE: &'static str = MAC_KEYCHAIN_SERVICE;

    /// The production vault for `paths`.
    pub fn open_default(paths: &crate::paths::Paths) -> Result<Self, CoreError> {
        Self::open_for_store(
            crate::keychain::darwin::SecurityFramework,
            Self::SERVICE,
            &paths.keychain_file(),
            paths.index_file().try_exists()?,
        )
    }

    /// The vault for an explicit CLI/dev root: same keychain, a service name
    /// derived from the root so it can never touch production items.
    pub fn open_for_dev_root(paths: &crate::paths::Paths, root: &Path) -> Result<Self, CoreError> {
        Self::open_for_store(
            crate::keychain::darwin::SecurityFramework,
            dev_root_vault_service(root)?,
            &paths.keychain_file(),
            paths.index_file().try_exists()?,
        )
    }
}

/* ----------------------------- dev fallback ------------------------------ */

/// File-backed vault for non-macOS development builds.
///
/// **Not encrypted.** A `0600` JSON file standing in for the Keychain so the
/// daemon and UI can be developed and integration-tested on Linux. The real
/// product ships with [`MacKeychainVault`]; this backend logs a warning at
/// construction.
pub struct FileVault {
    path: PathBuf,
    state: Mutex<FileVaultState>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct FileVaultState {
    items: HashMap<Uuid, FileVaultItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FileVaultItem {
    attrs: VaultAttrs,
    value: String,
}

impl FileVault {
    pub fn open(path: PathBuf) -> Result<Self, CoreError> {
        tracing::warn!(
            "FileVault in use ({}): dev-only fallback, secret values are NOT encrypted at rest",
            path.display()
        );
        let state = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => FileVaultState::default(),
            Err(e) => return Err(e.into()),
        };
        Ok(Self {
            path,
            state: Mutex::new(state),
        })
    }

    fn persist(&self, state: &FileVaultState) -> Result<(), CoreError> {
        let bytes = serde_json::to_vec_pretty(state)?;
        crate::paths::write_private_atomic(&self.path, &bytes)?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl SecretVault for FileVault {
    fn set(&self, id: &Uuid, attrs: &VaultAttrs, value: &SecretValue) -> Result<(), CoreError> {
        let mut state = self.state.lock().unwrap();
        let mut next = state.clone();
        next.items.insert(
            *id,
            FileVaultItem {
                attrs: attrs.clone(),
                value: value.to_string(),
            },
        );
        self.persist(&next)?;
        *state = next;
        Ok(())
    }

    async fn get(&self, id: &Uuid) -> Result<SecretValue, CoreError> {
        let state = self.state.lock().unwrap();
        state
            .items
            .get(id)
            .map(|item| Zeroizing::new(item.value.clone()))
            .ok_or(CoreError::SecretNotFound)
    }

    fn delete(&self, id: &Uuid) -> Result<(), CoreError> {
        let mut state = self.state.lock().unwrap();
        let mut next = state.clone();
        next.items.remove(id).ok_or(CoreError::SecretNotFound)?;
        self.persist(&next)?;
        *state = next;
        Ok(())
    }

    fn set_attrs(&self, id: &Uuid, attrs: &VaultAttrs) -> Result<(), CoreError> {
        let mut state = self.state.lock().unwrap();
        let mut next = state.clone();
        let item = next.items.get_mut(id).ok_or(CoreError::SecretNotFound)?;
        item.attrs = attrs.clone();
        self.persist(&next)?;
        *state = next;
        Ok(())
    }

    /// This is the one backend whose "vault" is a file anyone able to read the
    /// data directory can read.
    fn is_plaintext_development(&self) -> bool {
        true
    }
}

/* ---------------------------- encrypted file ----------------------------- */

/// The master-key environment variables, in precedence order: the key value
/// directly, then a file to read it from.
pub const VAULT_KEY_ENV: &str = "AKA_VAULT_KEY";
pub const VAULT_KEY_FILE_ENV: &str = "AKA_VAULT_KEY_FILE";

/// Parse a 32-byte master key from text: 64 hex chars, or base64 (standard
/// or url-safe) of 32 bytes. Whitespace is trimmed.
fn parse_master_key(text: &str) -> Result<Zeroizing<[u8; 32]>, CoreError> {
    let text = text.trim();
    let bytes = if text.len() == 64 && text.bytes().all(|b| b.is_ascii_hexdigit()) {
        (0..32)
            .map(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16))
            .collect::<Result<Vec<u8>, _>>()
            .ok()
    } else {
        base64::engine::general_purpose::STANDARD
            .decode(text)
            .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(text))
            .ok()
    };
    match bytes {
        Some(bytes) if bytes.len() == 32 => {
            let mut key = Zeroizing::new([0u8; 32]);
            key.copy_from_slice(&bytes);
            Ok(key)
        }
        _ => Err(CoreError::Vault(
            "the vault master key must be 32 bytes as 64 hex chars or base64".into(),
        )),
    }
}

/// Load the configured master key, if any. `AKA_VAULT_KEY` wins over
/// `AKA_VAULT_KEY_FILE`; a file may hold the key as text (hex/base64) or as
/// 32 raw bytes. Returns `None` when neither is set.
pub fn master_key_from_env() -> Option<Result<Zeroizing<[u8; 32]>, CoreError>> {
    if let Ok(value) = std::env::var(VAULT_KEY_ENV) {
        if !value.trim().is_empty() {
            return Some(parse_master_key(&value));
        }
    }
    if let Ok(path) = std::env::var(VAULT_KEY_FILE_ENV) {
        if !path.trim().is_empty() {
            return Some(load_master_key_file(Path::new(path.trim())));
        }
    }
    None
}

fn load_master_key_file(path: &Path) -> Result<Zeroizing<[u8; 32]>, CoreError> {
    let raw = std::fs::read(path)
        .map_err(|e| CoreError::Vault(format!("could not read {} ({e})", path.display())))?;
    // 32 raw bytes are taken as the key directly; anything else is parsed as
    // text (a hex/base64 line, trailing newline tolerated).
    if raw.len() == 32 {
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&raw);
        return Ok(key);
    }
    let text = String::from_utf8(raw)
        .map_err(|_| CoreError::Vault("the vault key file is neither 32 bytes nor text".into()))?;
    parse_master_key(&text)
}

/// The production non-macOS vault: a `0600` JSON file whose secret values
/// are XChaCha20-Poly1305 sealed under a host-provided master key. The
/// secret's UUID is the AEAD associated data, binding each ciphertext to
/// its slot so a value cannot be moved between ids. Attribute metadata
/// (name, created-at) is non-secret and stored in the clear, exactly as the
/// index does.
pub struct EncryptedFileVault {
    path: PathBuf,
    cipher: XChaCha20Poly1305,
    state: Mutex<EncryptedVaultState>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct EncryptedVaultState {
    items: HashMap<Uuid, EncryptedVaultItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EncryptedVaultItem {
    attrs: VaultAttrs,
    /// base64 XNonce (24 bytes).
    nonce: String,
    /// base64 ciphertext (includes the Poly1305 tag).
    ciphertext: String,
}

impl EncryptedFileVault {
    pub fn open(path: PathBuf, key: &[u8; 32]) -> Result<Self, CoreError> {
        let cipher = XChaCha20Poly1305::new(key.into());
        let state = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => EncryptedVaultState::default(),
            Err(e) => return Err(e.into()),
        };
        let vault = Self {
            path,
            cipher,
            state: Mutex::new(state),
        };
        // A wrong key must fail loudly at open, not silently on the first
        // read: verify we can decrypt one existing item.
        if let Some((id, item)) = vault.state.lock().unwrap().items.iter().next() {
            vault.decrypt(id, item).map_err(|_| {
                CoreError::Vault(
                    "the encrypted vault would not open: wrong master key (AKA_VAULT_KEY) \
                     or the store was tampered with"
                        .into(),
                )
            })?;
        }
        Ok(vault)
    }

    fn encrypt(&self, id: &Uuid, value: &SecretValue) -> Result<EncryptedVaultItem, CoreError> {
        let mut nonce = [0u8; 24];
        getrandom::fill(&mut nonce).map_err(|e| CoreError::Vault(format!("nonce entropy: {e}")))?;
        let ciphertext = self
            .cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: value.as_bytes(),
                    aad: id.as_bytes(),
                },
            )
            .map_err(|_| CoreError::Vault("vault encryption failed".into()))?;
        Ok(EncryptedVaultItem {
            attrs: VaultAttrs {
                name: String::new(),
                created_at: chrono::Utc::now(),
            },
            nonce: base64::engine::general_purpose::STANDARD.encode(nonce),
            ciphertext: base64::engine::general_purpose::STANDARD.encode(ciphertext),
        })
    }

    fn decrypt(&self, id: &Uuid, item: &EncryptedVaultItem) -> Result<SecretValue, CoreError> {
        let nonce = base64::engine::general_purpose::STANDARD
            .decode(&item.nonce)
            .map_err(|_| CoreError::Vault("corrupt vault nonce".into()))?;
        let ciphertext = base64::engine::general_purpose::STANDARD
            .decode(&item.ciphertext)
            .map_err(|_| CoreError::Vault("corrupt vault ciphertext".into()))?;
        let plaintext = self
            .cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: id.as_bytes(),
                },
            )
            .map_err(|_| {
                CoreError::Vault("vault decryption failed (wrong key or tampered)".into())
            })?;
        String::from_utf8(plaintext)
            .map(Zeroizing::new)
            .map_err(|_| CoreError::Vault("decrypted vault value is not valid UTF-8".into()))
    }

    fn persist(&self, state: &EncryptedVaultState) -> Result<(), CoreError> {
        let bytes = serde_json::to_vec_pretty(state)?;
        crate::paths::write_private_atomic(&self.path, &bytes)?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl SecretVault for EncryptedFileVault {
    fn set(&self, id: &Uuid, attrs: &VaultAttrs, value: &SecretValue) -> Result<(), CoreError> {
        let mut item = self.encrypt(id, value)?;
        item.attrs = attrs.clone();
        let mut state = self.state.lock().unwrap();
        let mut next = state.clone();
        next.items.insert(*id, item);
        self.persist(&next)?;
        *state = next;
        Ok(())
    }

    async fn get(&self, id: &Uuid) -> Result<SecretValue, CoreError> {
        let item = {
            let state = self.state.lock().unwrap();
            state
                .items
                .get(id)
                .cloned()
                .ok_or(CoreError::SecretNotFound)?
        };
        self.decrypt(id, &item)
    }

    fn delete(&self, id: &Uuid) -> Result<(), CoreError> {
        let mut state = self.state.lock().unwrap();
        let mut next = state.clone();
        next.items.remove(id).ok_or(CoreError::SecretNotFound)?;
        self.persist(&next)?;
        *state = next;
        Ok(())
    }

    fn set_attrs(&self, id: &Uuid, attrs: &VaultAttrs) -> Result<(), CoreError> {
        let mut state = self.state.lock().unwrap();
        let mut next = state.clone();
        let item = next.items.get_mut(id).ok_or(CoreError::SecretNotFound)?;
        item.attrs = attrs.clone();
        self.persist(&next)?;
        *state = next;
        Ok(())
    }
}

/* -------------------------------- tests ---------------------------------- */

/// In-memory vault for unit tests.
#[derive(Default)]
pub struct MemoryVault {
    items: Mutex<HashMap<Uuid, (VaultAttrs, String)>>,
}

impl MemoryVault {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn len(&self) -> usize {
        self.items.lock().unwrap().len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[async_trait::async_trait]
impl SecretVault for MemoryVault {
    fn set(&self, id: &Uuid, attrs: &VaultAttrs, value: &SecretValue) -> Result<(), CoreError> {
        self.items
            .lock()
            .unwrap()
            .insert(*id, (attrs.clone(), value.to_string()));
        Ok(())
    }

    async fn get(&self, id: &Uuid) -> Result<SecretValue, CoreError> {
        self.items
            .lock()
            .unwrap()
            .get(id)
            .map(|(_, v)| Zeroizing::new(v.clone()))
            .ok_or(CoreError::SecretNotFound)
    }

    fn delete(&self, id: &Uuid) -> Result<(), CoreError> {
        self.items
            .lock()
            .unwrap()
            .remove(id)
            .ok_or(CoreError::SecretNotFound)?;
        Ok(())
    }

    fn set_attrs(&self, id: &Uuid, attrs: &VaultAttrs) -> Result<(), CoreError> {
        let mut items = self.items.lock().unwrap();
        let item = items.get_mut(id).ok_or(CoreError::SecretNotFound)?;
        item.0 = attrs.clone();
        Ok(())
    }
}

/// Stable macOS Keychain service for an existing CLI dev root. This is public
/// so callers and diagnostics can name the scope without constructing a
/// Keychain backend.
pub fn dev_root_vault_service(root: &Path) -> Result<String, CoreError> {
    let root = vault_scope_root(root)?;
    let digest = Sha256::digest(root.to_string_lossy().as_bytes());
    Ok(format!(
        "{MAC_KEYCHAIN_SERVICE}.dev.{}",
        encode_hex(&digest)
    ))
}

fn vault_scope_root(root: &Path) -> Result<PathBuf, CoreError> {
    let absolute = if root.is_absolute() {
        root.to_path_buf()
    } else {
        std::env::current_dir()?.join(root)
    };
    Ok(absolute.canonicalize()?)
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The platform-default vault: Keychain on macOS; on other platforms the
/// XChaCha20-Poly1305 [`EncryptedFileVault`] when a master key is configured
/// (`AKA_VAULT_KEY`/`AKA_VAULT_KEY_FILE` — the hosted path), else the
/// unencrypted dev [`FileVault`].
pub fn platform_vault(
    paths: &crate::paths::Paths,
) -> Result<std::sync::Arc<dyn SecretVault>, CoreError> {
    #[cfg(target_os = "macos")]
    {
        Ok(std::sync::Arc::new(MacKeychainVault::open_default(paths)?))
    }
    #[cfg(not(target_os = "macos"))]
    {
        non_macos_vault(paths)
    }
}

/// Choose the non-macOS backend from the environment: encrypted when a
/// master key is set (and it seals the state-integrity key too, so tamper
/// protection is not left in the clear), otherwise the loud dev fallback.
#[cfg(not(target_os = "macos"))]
fn non_macos_vault(
    paths: &crate::paths::Paths,
) -> Result<std::sync::Arc<dyn SecretVault>, CoreError> {
    paths.ensure()?;
    let selected = selected_platform_vault_backend(paths);
    check_vault_backend(paths, selected)?;
    let vault: std::sync::Arc<dyn SecretVault> = match master_key_from_env() {
        Some(key) => {
            let key = key?;
            std::sync::Arc::new(EncryptedFileVault::open(
                paths.encrypted_vault_file(),
                &key,
            )?)
        }
        None => std::sync::Arc::new(FileVault::open(paths.dev_vault_file())?),
    };
    if read_vault_backend_record(paths) != Some(selected) {
        record_vault_backend(paths, selected)?;
    }
    Ok(vault)
}

/// The platform vault for an explicit CLI/dev root. On macOS this scopes the
/// Keychain service to `root`, while non-macOS builds already scope through the
/// root-local `dev-vault.json` path. The scoped directories are created first
/// so the root has one canonical identity from its first use onward.
pub fn platform_vault_for_root(
    paths: &crate::paths::Paths,
    root: &Path,
) -> Result<std::sync::Arc<dyn SecretVault>, CoreError> {
    paths.ensure()?;
    #[cfg(target_os = "macos")]
    {
        Ok(std::sync::Arc::new(MacKeychainVault::open_for_dev_root(
            paths, root,
        )?))
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = root;
        non_macos_vault(paths)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn file_vault_rejects_unpersisted_memory_changes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.json");
        let vault = FileVault::open(path.clone()).unwrap();
        let id = Uuid::new_v4();
        let attrs = VaultAttrs {
            name: "API_KEY".into(),
            created_at: chrono::Utc::now(),
        };
        vault
            .set(&id, &attrs, &Zeroizing::new("secret".to_string()))
            .unwrap();
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();

        assert!(vault
            .set(&id, &attrs, &Zeroizing::new("replacement".to_string()))
            .is_err());
        assert_eq!(&*vault.get(&id).await.unwrap(), "secret");

        let mut renamed = attrs.clone();
        renamed.name = "RENAMED_KEY".into();
        assert!(vault.set_attrs(&id, &renamed).is_err());
        assert_eq!(vault.state.lock().unwrap().items[&id].attrs.name, "API_KEY");

        assert!(vault.delete(&id).is_err());
        assert_eq!(&*vault.get(&id).await.unwrap(), "secret");

        let rejected = Uuid::new_v4();
        assert!(vault
            .set(&rejected, &attrs, &Zeroizing::new("rejected".to_string()))
            .is_err());
        assert!(matches!(
            vault.get(&rejected).await,
            Err(CoreError::SecretNotFound)
        ));
    }

    fn test_key(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[tokio::test]
    async fn encrypted_vault_round_trips_and_seals_the_value() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.enc.json");
        let key = test_key(7);
        let vault = EncryptedFileVault::open(path.clone(), &key).unwrap();
        let id = Uuid::new_v4();
        let attrs = VaultAttrs {
            name: "API_KEY".into(),
            created_at: chrono::Utc::now(),
        };
        vault
            .set(&id, &attrs, &Zeroizing::new("s3cr3t-value".into()))
            .unwrap();
        assert_eq!(&*vault.get(&id).await.unwrap(), "s3cr3t-value");

        // The plaintext never touches the file; the name (non-secret) does.
        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert!(
            !on_disk.contains("s3cr3t-value"),
            "value is encrypted at rest"
        );
        assert!(on_disk.contains("API_KEY"), "attrs stay in the clear");

        // It survives reopen with the same key.
        let reopened = EncryptedFileVault::open(path.clone(), &key).unwrap();
        assert_eq!(&*reopened.get(&id).await.unwrap(), "s3cr3t-value");
    }

    #[tokio::test]
    async fn a_wrong_key_fails_at_open_not_silently() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.enc.json");
        {
            let vault = EncryptedFileVault::open(path.clone(), &test_key(1)).unwrap();
            vault
                .set(
                    &Uuid::new_v4(),
                    &VaultAttrs {
                        name: "K".into(),
                        created_at: chrono::Utc::now(),
                    },
                    &Zeroizing::new("v".into()),
                )
                .unwrap();
        }
        // Reopening with the wrong key is rejected up front.
        match EncryptedFileVault::open(path, &test_key(2)) {
            Err(CoreError::Vault(msg)) => assert!(msg.contains("AKA_VAULT_KEY"), "{msg}"),
            Ok(_) => panic!("a wrong key must be rejected at open"),
            Err(other) => panic!("unexpected error: {other}"),
        }
    }

    #[tokio::test]
    async fn tampering_with_the_ciphertext_is_detected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.enc.json");
        let key = test_key(9);
        let id = Uuid::new_v4();
        {
            let vault = EncryptedFileVault::open(path.clone(), &key).unwrap();
            vault
                .set(
                    &id,
                    &VaultAttrs {
                        name: "K".into(),
                        created_at: chrono::Utc::now(),
                    },
                    &Zeroizing::new("value".into()),
                )
                .unwrap();
        }
        // Flip a byte inside the base64 ciphertext. The AEAD tag catches it;
        // the open-time verify makes it fail fast rather than on first read.
        let _ = id;
        let text = std::fs::read_to_string(&path).unwrap();
        let mutated = text.replacen("\"ciphertext\": \"", "\"ciphertext\": \"AA", 1);
        std::fs::write(&path, mutated).unwrap();
        match EncryptedFileVault::open(path, &key) {
            Err(CoreError::Vault(_)) => {}
            Ok(_) => panic!("tampered ciphertext must be rejected"),
            Err(other) => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn master_key_parses_hex_and_base64_and_rejects_wrong_length() {
        let hex = "00".repeat(32);
        assert_eq!(parse_master_key(&hex).unwrap()[..], [0u8; 32]);
        let b64 = base64::engine::general_purpose::STANDARD.encode([5u8; 32]);
        assert_eq!(parse_master_key(&b64).unwrap()[..], [5u8; 32]);
        assert!(parse_master_key("tooshort").is_err());
        assert!(parse_master_key(&"00".repeat(16)).is_err());
    }

    #[test]
    fn backend_record_diagnoses_a_missing_encrypted_vault_key() {
        let dir = tempfile::tempdir().unwrap();
        let paths = crate::paths::Paths::under(dir.path());
        paths.ensure().unwrap();
        record_vault_backend(&paths, PlatformVaultBackend::EncryptedFile).unwrap();

        assert_eq!(
            recorded_platform_vault_backend(&paths),
            Some(PlatformVaultBackend::EncryptedFile)
        );
        let error =
            check_vault_backend(&paths, PlatformVaultBackend::PlaintextDevFile).unwrap_err();
        assert!(
            matches!(
                error,
                CoreError::Vault(ref message)
                    if message.contains("sealed by the encrypted vault")
                        && message.contains("AKA_VAULT_KEY")
            ),
            "{error}"
        );
    }

    #[test]
    fn pre_marker_file_vaults_are_inferred_without_guessing_when_both_exist() {
        let dir = tempfile::tempdir().unwrap();
        let paths = crate::paths::Paths::under(dir.path());
        paths.ensure().unwrap();

        std::fs::write(paths.encrypted_vault_file(), b"{}").unwrap();
        assert_eq!(
            recorded_platform_vault_backend(&paths),
            Some(PlatformVaultBackend::EncryptedFile)
        );
        std::fs::write(paths.dev_vault_file(), b"{}").unwrap();
        assert_eq!(recorded_platform_vault_backend(&paths), None);
        let error = check_vault_backend(&paths, PlatformVaultBackend::EncryptedFile).unwrap_err();
        assert!(
            matches!(error, CoreError::Vault(ref message) if message.contains("refusing to guess")),
            "{error}"
        );
    }

    #[test]
    fn dev_root_service_is_stable_and_not_production() {
        let dir = tempfile::tempdir().unwrap();
        let service = dev_root_vault_service(dir.path()).unwrap();

        assert_ne!(service, MAC_KEYCHAIN_SERVICE);
        assert!(service.starts_with("com.aka.desktop.dev."));
        assert_eq!(service, dev_root_vault_service(dir.path()).unwrap());
    }

    #[test]
    fn dev_root_service_separates_roots() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();

        assert_ne!(
            dev_root_vault_service(a.path()).unwrap(),
            dev_root_vault_service(b.path()).unwrap()
        );
    }

    #[test]
    fn dev_root_service_requires_an_existing_root() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing");

        assert!(matches!(
            dev_root_vault_service(&missing),
            Err(CoreError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound
        ));
    }

    #[test]
    fn explicit_vault_root_is_created_before_service_is_derived() {
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().join("parent");
        let intermediate = parent.join("intermediate");
        std::fs::create_dir_all(&intermediate).unwrap();
        let root = intermediate.join("..").join("vault-root");
        let canonical_root = parent.join("vault-root");
        let paths = crate::paths::Paths::under(&root);

        assert!(!canonical_root.exists());
        platform_vault_for_root(&paths, &root).unwrap();

        assert!(canonical_root.exists());
        assert_eq!(
            dev_root_vault_service(&root).unwrap(),
            dev_root_vault_service(&canonical_root).unwrap()
        );
    }
}
