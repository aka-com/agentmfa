//! Secret value storage (DESIGN.md §3).
//!
//! Each secret's sensitive material is one Keychain item, keyed by the
//! secret's stable UUID (service `com.aka.desktop`). Everything that is
//! *not* a secret value lives in `index.json` (see `store`); the vault
//! stores values and nothing else.
//!
//! Backends:
//! - `MacKeychainVault` (macOS): the real thing, via the `keyring` crate.
//! - `FileVault`: dev fallback for non-macOS builds, a `0600` JSON file,
//!   *not encrypted*, loudly not for production.
//! - `MemoryVault`: tests.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::CoreError;
use crate::types::SecretValue;

/// The secret's non-sensitive Keychain attributes. Each item carries the
/// secret's name and creation date so a fresh install on a second Mac can
/// rebuild an index from synced items ("import N synced secrets",
/// DESIGN.md §3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultAttrs {
    pub name: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Whether the item was created `kSecAttrSynchronizable` (rides iCloud
    /// Keychain). The synchronizable attribute is effectively fixed at
    /// creation, so toggling the setting migrates items (§3).
    pub sync: bool,
}

/// The read path (`get`, and `migrate_sync` which reads) is `async`:
/// network-backed vaults (Vault, cloud secret managers, just-in-time
/// issuance) are read-bound, and the broker fetches values post-approval
/// from async context. Writes stay synchronous — they are UI-driven CRUD
/// against a local store today; revisit if a network backend needs them.
#[async_trait::async_trait]
pub trait SecretVault: Send + Sync {
    /// Create or replace the item for `id`. `attrs.sync` selects the
    /// synchronizable attribute at (re)creation time.
    fn set(&self, id: &Uuid, attrs: &VaultAttrs, value: &SecretValue) -> Result<(), CoreError>;

    /// Fetch the value. Called as late as possible — after approval, or for
    /// the audited reveal-prefix read — and dropped immediately (§3).
    async fn get(&self, id: &Uuid) -> Result<SecretValue, CoreError>;

    fn delete(&self, id: &Uuid) -> Result<(), CoreError>;

    /// Update the non-sensitive attributes (rename keeps the Keychain label
    /// in sync so synced items are self-describing on another Mac).
    fn set_attrs(&self, id: &Uuid, attrs: &VaultAttrs) -> Result<(), CoreError>;

    /// Re-create the item with a different `sync` attribute (read → delete →
    /// re-create, §3). Default impl works for every backend.
    ///
    /// The synchronizable attribute is fixed at creation, so the delete is
    /// unavoidable — but a failure re-creating the item under the new
    /// attribute would otherwise lose the value outright. If the re-create
    /// fails we put the item back under its previous attribute (the sync flag
    /// inverted) so a transient Keychain error can't destroy a secret; the
    /// original error is still returned.
    async fn migrate_sync(&self, id: &Uuid, attrs: &VaultAttrs) -> Result<(), CoreError> {
        let value = self.get(id).await?;
        self.delete(id)?;
        if let Err(e) = self.set(id, attrs, &value) {
            let restore = VaultAttrs {
                sync: !attrs.sync,
                ..attrs.clone()
            };
            if let Err(re) = self.set(id, &restore, &value) {
                tracing::error!("vault migrate_sync restore failed for {id}: {re}");
            }
            return Err(e);
        }
        Ok(())
    }
}

/* ------------------------------- macOS ---------------------------------- */

const MAC_KEYCHAIN_SERVICE: &str = "com.aka.desktop";

/// The macOS Keychain backend (service `com.aka.desktop`, account = the
/// secret's UUID), via the `keyring` crate. Dev roots use a root-scoped service
/// so `agentmfa serve --root ...` cannot create or rotate production vault
/// state.
///
/// Documented divergence from DESIGN.md §3: the `keyring` crate's
/// apple-native backend targets the file-based login keychain and does not
/// expose `kSecUseDataProtectionKeychain`, `kSecAttrSynchronizable`, or
/// `SecAccessControl`. AgentMFA still gates broker-side reads with the
/// shell's native re-auth hook before calling `get`; moving iCloud sync and
/// per-item ACLs into the Data Protection keychain needs direct
/// Security.framework calls plus the `keychain-access-groups` entitlement.
#[cfg(target_os = "macos")]
pub struct MacKeychainVault {
    service: String,
    /// Attribute sidecar (name/created/sync) kept next to the index so the
    /// UI can enumerate without touching the Keychain.
    attrs: Mutex<HashMap<Uuid, VaultAttrs>>,
}

#[cfg(target_os = "macos")]
impl MacKeychainVault {
    pub const SERVICE: &'static str = MAC_KEYCHAIN_SERVICE;

    pub fn new() -> Self {
        Self::with_service(Self::SERVICE)
    }

    pub fn with_service(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
            attrs: Mutex::new(HashMap::new()),
        }
    }

    pub fn for_dev_root(root: &Path) -> Result<Self, CoreError> {
        Ok(Self::with_service(dev_root_vault_service(root)?))
    }

    fn entry(&self, id: &Uuid) -> Result<keyring::Entry, CoreError> {
        keyring::Entry::new(&self.service, &id.to_string())
            .map_err(|e| CoreError::Vault(e.to_string()))
    }
}

#[cfg(target_os = "macos")]
impl Default for MacKeychainVault {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "macos")]
#[async_trait::async_trait]
impl SecretVault for MacKeychainVault {
    fn set(&self, id: &Uuid, attrs: &VaultAttrs, value: &SecretValue) -> Result<(), CoreError> {
        self.entry(id)?
            .set_password(value)
            .map_err(|e| CoreError::Vault(e.to_string()))?;
        self.attrs.lock().unwrap().insert(*id, attrs.clone());
        Ok(())
    }

    async fn get(&self, id: &Uuid) -> Result<SecretValue, CoreError> {
        // Security.framework calls block; keep them off the async workers.
        let service = self.service.clone();
        let account = id.to_string();
        let looked_up = tokio::task::spawn_blocking(move || {
            keyring::Entry::new(&service, &account)
                .map_err(|e| CoreError::Vault(e.to_string()))?
                .get_password()
                .map_err(|e| match e {
                    // Distinguish "absent" from real Keychain errors, so
                    // callers (e.g. the integrity key's create-on-first-run)
                    // can branch.
                    keyring::Error::NoEntry => CoreError::SecretNotFound,
                    other => CoreError::Vault(other.to_string()),
                })
        })
        .await
        .map_err(|e| CoreError::Vault(format!("keychain task: {e}")))??;
        Ok(Zeroizing::new(looked_up))
    }

    fn delete(&self, id: &Uuid) -> Result<(), CoreError> {
        self.entry(id)?
            .delete_credential()
            .map_err(|e| CoreError::Vault(e.to_string()))?;
        self.attrs.lock().unwrap().remove(id);
        Ok(())
    }

    fn set_attrs(&self, id: &Uuid, attrs: &VaultAttrs) -> Result<(), CoreError> {
        self.attrs.lock().unwrap().insert(*id, attrs.clone());
        Ok(())
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
    /// Test helper: inspect an item's sync attribute.
    pub fn sync_flag(&self, id: &Uuid) -> Option<bool> {
        self.items.lock().unwrap().get(id).map(|(a, _)| a.sync)
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

/// The platform-default vault: Keychain on macOS, the dev file vault
/// elsewhere.
pub fn platform_vault(
    paths: &crate::paths::Paths,
) -> Result<std::sync::Arc<dyn SecretVault>, CoreError> {
    #[cfg(target_os = "macos")]
    {
        let _ = paths;
        Ok(std::sync::Arc::new(MacKeychainVault::new()))
    }
    #[cfg(not(target_os = "macos"))]
    {
        Ok(std::sync::Arc::new(FileVault::open(
            paths.dev_vault_file(),
        )?))
    }
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
        Ok(std::sync::Arc::new(MacKeychainVault::for_dev_root(root)?))
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = root;
        Ok(std::sync::Arc::new(FileVault::open(
            paths.dev_vault_file(),
        )?))
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
            sync: false,
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
        assert_eq!(
            vault.state.lock().unwrap().items[&id].attrs.name,
            "API_KEY"
        );

        assert!(vault.delete(&id).is_err());
        assert_eq!(&*vault.get(&id).await.unwrap(), "secret");

        let rejected = Uuid::new_v4();
        assert!(vault
            .set(
                &rejected,
                &attrs,
                &Zeroizing::new("rejected".to_string())
            )
            .is_err());
        assert!(matches!(
            vault.get(&rejected).await,
            Err(CoreError::SecretNotFound)
        ));
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
