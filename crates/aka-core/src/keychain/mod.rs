//! macOS Keychain access without per-item ACL prompts.
//!
//! macOS has two keychains behind one `SecItem` API:
//!
//! - The **file-based login keychain** (`~/Library/Keychains/login.keychain-db`)
//!   decides access with a per-item ACL. When the reading process is not on
//!   the item's trusted-application list — an unsigned build, a rebuilt binary
//!   whose signature changed, a different binary entirely — the OS puts up the
//!   "…wants to use your confidential information stored in…" dialog, once per
//!   item, per process, until someone clicks *Always Allow*. This is what the
//!   `keyring` crate's apple-native backend targets, and it is the entire
//!   source of Multitool's Keychain prompt fatigue.
//!
//! - The **data-protection keychain** (`kSecUseDataProtectionKeychain`) decides
//!   access with *code identity*: an item belongs to a keychain access group,
//!   and a process may open the group only if its code signature carries the
//!   matching `keychain-access-groups` entitlement. There is no per-item ACL,
//!   so there is no dialog and no "Always Allow" — a correctly signed
//!   Multitool reads its own items silently, forever, and a process without
//!   the entitlement is not prompted to approve anything; it simply sees a
//!   keychain with nothing in it.
//!
//! That last detail is load-bearing and easy to get wrong. An unentitled
//! process is not *refused* by the data-protection keychain, it is handed an
//! **empty** one: reads succeed and find nothing, and only writes fail
//! (`errSecMissingEntitlement`), because only a write has to name the group
//! it is storing into. Anything asking "can I use this keychain?" has to ask
//! with a write — see [`KeychainApi::data_protection_available`].
//!
//! Multitool uses the data-protection keychain wherever the running binary can
//! (see [`Keychain`] and [`resolve`]), and keeps the login keychain as the
//! fallback for builds that cannot carry the entitlement — `cargo run`, `tauri
//! dev`, ad-hoc-signed local builds, and the unsigned `aka` binaries published
//! to npm. Items written by the old `keyring` backend live in the login
//! keychain; [`KeychainVault`] migrates each one into the data-protection
//! keychain the first time it is read (see [`read_migrating`]).
//!
//! Everything here except [`darwin`] is platform-independent and unit-tested
//! on every platform through the [`KeychainApi`] seam; only the small
//! Security.framework binding is macOS-only.

#[cfg(target_os = "macos")]
pub mod darwin;

use std::path::Path;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::CoreError;
use crate::types::SecretValue;
use crate::vault::{SecretVault, VaultAttrs};

/// Environment override for the keychain choice: `auto` (default),
/// `data-protection`, or `login`.
pub const KEYCHAIN_ENV: &str = "AKA_KEYCHAIN";

/// The throwaway item [`KeychainApi::data_protection_available`] stores and
/// removes to find out whether this process may write to the data-protection
/// keychain at all. One fixed name, so a crash between the two leaves at most
/// one item, holding nothing.
const PROBE_SERVICE: &str = "com.aka.desktop.entitlement-probe";
const PROBE_ACCOUNT: &str = "probe";
const PROBE_LABEL: &str = "Multitool (keychain probe)";
const PROBE_VALUE: &[u8] = b"entitlement probe";

/// Which of the two macOS keychains an item lives in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Keychain {
    /// The entitlement-gated keychain. No per-item ACL, so no prompts.
    DataProtection,
    /// The file-based login keychain. Per-item ACL, so prompts.
    Login,
}

impl Keychain {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DataProtection => "data-protection",
            Self::Login => "login",
        }
    }
}

impl std::fmt::Display for Keychain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An `OSStatus` and, where the platform gave us one, its own words for it.
///
/// Security.framework can describe every status it returns
/// (`SecCopyErrorMessageString`), and the tail of statuses worth enumerating
/// here is long. Carrying the text means a report reads "User interaction is
/// not allowed. (OSStatus -25308)" instead of a bare integer to go look up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OsError {
    pub status: i32,
    pub message: Option<String>,
}

impl OsError {
    /// A status with no description — the platform had none, or the caller
    /// is not on a platform that offers them.
    pub fn new(status: i32) -> Self {
        Self {
            status,
            message: None,
        }
    }

    pub fn described(status: i32, message: Option<String>) -> Self {
        Self { status, message }
    }
}

impl std::fmt::Display for OsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.message {
            Some(message) => write!(f, "{message} (OSStatus {})", self.status),
            None => write!(f, "OSStatus {}", self.status),
        }
    }
}

/// What a Security.framework call can go wrong with, in the shapes callers
/// actually branch on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeychainError {
    /// `errSecItemNotFound`. Not an error for `get`: it is how "no such
    /// secret" arrives. Note that an unentitled process gets this from
    /// *every* data-protection read, so it does not distinguish "no such
    /// item" from "no keychain to look in".
    NotFound,
    /// `errSecMissingEntitlement`. The process is not signed with a
    /// `keychain-access-groups` (or application-identifier) entitlement, so
    /// it has no access group to store into. Reads do not report this —
    /// they report [`Self::NotFound`] — which is why the probe writes.
    MissingEntitlement,
    /// The user dismissed the login keychain's ACL dialog, or it could not be
    /// shown (`errSecUserCanceled`, `errSecAuthFailed`,
    /// `errSecInteractionNotAllowed`).
    NotAuthorized(OsError),
    /// Any other `OSStatus`.
    Os(OsError),
    /// A value the Keychain returned that we could not make sense of.
    Malformed(String),
}

impl std::fmt::Display for KeychainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => f.write_str("no such Keychain item"),
            Self::MissingEntitlement => f.write_str(
                "this build is not signed with the keychain-access-groups entitlement, \
                 so it cannot open the data-protection keychain (OSStatus -34018)",
            ),
            Self::NotAuthorized(error) => {
                write!(f, "Keychain access was not authorized: {error}")
            }
            Self::Os(error) => write!(f, "Keychain error: {error}"),
            Self::Malformed(what) => write!(f, "unusable Keychain item: {what}"),
        }
    }
}

impl std::error::Error for KeychainError {}

impl From<KeychainError> for CoreError {
    fn from(error: KeychainError) -> Self {
        match error {
            KeychainError::NotFound => CoreError::SecretNotFound,
            other => CoreError::Vault(other.to_string()),
        }
    }
}

/// The Security.framework surface Multitool needs, as a trait so the policy
/// above it — keychain selection, lazy migration, labelling — is exercised by
/// tests on every platform rather than only on a signed Mac.
///
/// Implementations are called from `spawn_blocking`: every one of these
/// blocks, and the login-keychain path can block for as long as a user takes
/// to answer a dialog.
pub trait KeychainApi: Send + Sync + 'static {
    /// The item's secret bytes.
    fn read(
        &self,
        keychain: Keychain,
        service: &str,
        account: &str,
    ) -> Result<Zeroizing<Vec<u8>>, KeychainError>;

    /// Create the item, or replace the value and label of an existing one.
    fn write(
        &self,
        keychain: Keychain,
        service: &str,
        account: &str,
        label: &str,
        value: &[u8],
    ) -> Result<(), KeychainError>;

    /// Retitle an existing item without touching its value.
    fn relabel(
        &self,
        keychain: Keychain,
        service: &str,
        account: &str,
        label: &str,
    ) -> Result<(), KeychainError>;

    fn remove(&self, keychain: Keychain, service: &str, account: &str)
        -> Result<(), KeychainError>;

    /// Whether this process may use the data-protection keychain, asked by
    /// storing a throwaway item and removing it again.
    ///
    /// It has to be a *write*. An unentitled process has no keychain access
    /// group, so a data-protection **read** searches an empty set of groups
    /// and comes back `errSecItemNotFound` — indistinguishable from an
    /// entitled process that simply has no such item. Only `SecItemAdd` has
    /// to name a group to put the item in, and that is where an unentitled
    /// process gets `errSecMissingEntitlement`. Probing with a read reports
    /// the keychain as available on builds that cannot write a single value
    /// to it.
    fn data_protection_available(&self) -> Result<(), KeychainError> {
        self.write(
            Keychain::DataProtection,
            PROBE_SERVICE,
            PROBE_ACCOUNT,
            PROBE_LABEL,
            PROBE_VALUE,
        )?;
        // Racing copies of the probe can delete each other's item; the
        // permission question was answered by the write.
        match self.remove(Keychain::DataProtection, PROBE_SERVICE, PROBE_ACCOUNT) {
            Ok(()) | Err(KeychainError::NotFound) => {}
            Err(error) => tracing::warn!("could not clean up the keychain probe item: {error}"),
        }
        Ok(())
    }
}

/* --------------------------- choosing a keychain -------------------------- */

/// The `AKA_KEYCHAIN` override. `None` (or `auto`) leaves the choice to
/// [`resolve`].
pub fn requested_from_env() -> Result<Option<Keychain>, CoreError> {
    let raw = match std::env::var(KEYCHAIN_ENV) {
        Ok(value) => value,
        Err(_) => return Ok(None),
    };
    parse_requested(&raw)
}

fn parse_requested(raw: &str) -> Result<Option<Keychain>, CoreError> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "" | "auto" => Ok(None),
        "data-protection" | "dataprotection" => Ok(Some(Keychain::DataProtection)),
        "login" | "file" => Ok(Some(Keychain::Login)),
        other => Err(CoreError::Vault(format!(
            "{KEYCHAIN_ENV}={other:?} is not one of: auto, data-protection, login"
        ))),
    }
}

/// Pick the keychain to use.
///
/// `requested` is the operator's `AKA_KEYCHAIN` override, `recorded` is the
/// keychain this store's items were last written to (see [`read_record`]), and
/// `available` is the entitlement probe's answer.
///
/// The one case that must not be quiet is a binary that cannot open the
/// data-protection keychain against a store whose items live there: it would
/// otherwise find an empty vault and report every secret as missing. That
/// fails with an actionable error instead.
pub fn resolve(
    requested: Option<Keychain>,
    recorded: Option<Keychain>,
    available: Result<(), KeychainError>,
) -> Result<Keychain, CoreError> {
    resolve_for_store(requested, recorded, false, available)
}

fn resolve_for_store(
    requested: Option<Keychain>,
    recorded: Option<Keychain>,
    store_exists: bool,
    available: Result<(), KeychainError>,
) -> Result<Keychain, CoreError> {
    match requested {
        // An explicit choice is honoured, including the choice to stay on the
        // prompting keychain — that is the escape hatch for a mixed setup
        // where an unsigned CLI has to see the same items as the app.
        Some(Keychain::Login) => Ok(Keychain::Login),
        // An explicit choice that cannot be served is an error, never a
        // silent downgrade to the keychain the operator just ruled out.
        Some(Keychain::DataProtection) => match available {
            Ok(()) => Ok(Keychain::DataProtection),
            Err(error) => Err(CoreError::Vault(format!(
                "{KEYCHAIN_ENV}=data-protection was requested but {error}"
            ))),
        },
        None => match available {
            Ok(()) => Ok(Keychain::DataProtection),
            Err(error) if recorded == Some(Keychain::DataProtection) => {
                Err(CoreError::Vault(format!(
                    "this store's secret values are in the macOS data-protection keychain, \
                     but {error}. Use the signed Multitool app for this store, or set \
                     {KEYCHAIN_ENV}=login to fall back to the login keychain (which will \
                     not see those values)."
                )))
            }
            Err(error) if store_exists && recorded.is_none() => Err(CoreError::Vault(format!(
                "this store already has state but its macOS keychain marker is missing or \
                 unreadable, so Multitool will not silently fall back to an empty login keychain \
                 ({error}). Restore keychain.json, use the signed Multitool app, or set \
                 {KEYCHAIN_ENV}=login explicitly if the fallback is intentional."
            ))),
            Err(error) => {
                tracing::warn!(
                    "falling back to the macOS login keychain, which prompts per item: {error}"
                );
                Ok(Keychain::Login)
            }
        },
    }
}

/// Pick a keychain for state that can simply be obtained again — the client's
/// stored management tokens, as opposed to the vault's secret values.
///
/// There is no store marker to consult and nothing to fail loudly over: a
/// binary that cannot reach the data-protection keychain falls back, finds
/// nothing there, and costs the user one `multitool manage login`. Losing a secret
/// value that way would be unrecoverable, which is why [`resolve`] refuses
/// instead.
pub fn best_effort<A: KeychainApi + ?Sized>(api: &A) -> Keychain {
    if matches!(requested_from_env(), Ok(Some(Keychain::Login))) {
        return Keychain::Login;
    }
    match api.data_protection_available() {
        Ok(()) => Keychain::DataProtection,
        Err(error) => {
            tracing::debug!("using the macOS login keychain for client tokens: {error}");
            Keychain::Login
        }
    }
}

/* ------------------------------ the marker -------------------------------- */

/// Marker generation. Version 1 was written by a build whose entitlement
/// probe was a read, which an unentitled process passes (see
/// [`KeychainApi::data_protection_available`]) — so a v1 file claiming
/// `data-protection` may well describe a store whose values never left the
/// login keychain. Acting on that claim is exactly the case that refuses to
/// open, so those files are read as absent rather than believed.
const MARKER_VERSION: u32 = 2;

/// Which keychain a store's secret values were last written to.
///
/// Deliberately *not* sealed by [`crate::integrity`]: the integrity key is
/// itself a vault item, so this file has to be readable before the vault is
/// open. It is an availability marker, not a security control — the worst a
/// tamperer achieves by editing it is turning a clear error into an empty
/// vault, which is what would have happened without the file at all.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct KeychainRecord {
    #[serde(default)]
    v: u32,
    keychain: Keychain,
    updated_at: chrono::DateTime<chrono::Utc>,
}

/// Read the marker. A missing, unreadable, or outdated file is `None` — this
/// is advisory state, and refusing to open the vault over it would be worse
/// than the ambiguity it resolves.
pub fn read_record(path: &Path) -> Option<Keychain> {
    let bytes = std::fs::read(path).ok()?;
    let record: KeychainRecord = serde_json::from_slice(&bytes).ok()?;
    (record.v == MARKER_VERSION).then_some(record.keychain)
}

/// Record the keychain in use, if it is not already what the file says.
/// Best-effort: a store that cannot write its marker still works, it just
/// loses the clear error a later unsigned binary would have got.
pub fn write_record(path: &Path, keychain: Keychain) {
    if read_record(path) == Some(keychain) {
        return;
    }
    let record = KeychainRecord {
        v: MARKER_VERSION,
        keychain,
        updated_at: chrono::Utc::now(),
    };
    let bytes = match serde_json::to_vec_pretty(&record) {
        Ok(bytes) => bytes,
        Err(error) => {
            tracing::warn!("could not encode the keychain marker: {error}");
            return;
        }
    };
    // The vault opens before the store does, so on a fresh install this is
    // the first thing to create the data directory — it must land 0700, not
    // whatever `create_dir_all` and the umask would have made it.
    if let Some(parent) = path.parent() {
        if let Err(error) = crate::paths::create_private_dir(parent) {
            tracing::warn!("could not create {}: {error}", parent.display());
            return;
        }
    }
    if let Err(error) = crate::paths::write_private_atomic(path, &bytes) {
        tracing::warn!("could not record the keychain in use: {error}");
    }
}

/* ------------------------------- the vault -------------------------------- */

/// The label migrated items get. Items the `keyring` backend wrote are all
/// labelled with the bare service name, so there is no per-secret title to
/// carry over; the next rename or value replacement writes the real one.
const MIGRATED_LABEL: &str = "Multitool";

fn label_for(name: &str) -> String {
    if name.is_empty() {
        MIGRATED_LABEL.to_string()
    } else {
        format!("Multitool ({name})")
    }
}

/// Read an item, migrating it out of the login keychain on the way.
///
/// On the data-protection keychain a miss is checked against the login
/// keychain before it is reported: that is where every item written before
/// this change lives. A hit is copied across and the original deleted, so the
/// item prompts at most once more, ever — and only if the running build was
/// not already on its ACL.
///
/// The whole migration is best-effort, and deliberately: once the value is in
/// hand, the caller's read has succeeded, and neither a failed copy nor a
/// failed cleanup is worth turning that into an error. A failed copy just
/// means the next read tries again; a failed cleanup leaves a duplicate that
/// `delete` will also go after.
pub fn read_migrating<A: KeychainApi + ?Sized>(
    api: &A,
    keychain: Keychain,
    service: &str,
    account: &str,
) -> Result<Zeroizing<Vec<u8>>, KeychainError> {
    match api.read(keychain, service, account) {
        Err(KeychainError::NotFound) if keychain == Keychain::DataProtection => {}
        other => return other,
    }
    let value = api.read(Keychain::Login, service, account)?;
    if let Err(error) = api.write(
        Keychain::DataProtection,
        service,
        account,
        MIGRATED_LABEL,
        &value,
    ) {
        tracing::warn!(
            "could not copy {service}/{account} into the data-protection keychain, \
             leaving it where it is: {error}"
        );
        return Ok(value);
    }
    match api.remove(Keychain::Login, service, account) {
        Ok(()) | Err(KeychainError::NotFound) => {}
        Err(error) => tracing::warn!(
            "migrated {service}/{account} into the data-protection keychain but could not \
             remove the login-keychain copy: {error}"
        ),
    }
    tracing::info!("migrated a secret value into the macOS data-protection keychain");
    Ok(value)
}

/// The macOS Keychain vault: one item per secret, keyed by the secret's stable
/// UUID under a fixed service. Dev roots use a root-scoped service so `aka
/// serve --root …` can never create or rotate production vault state.
pub struct KeychainVault<A: KeychainApi> {
    api: Arc<A>,
    service: Arc<str>,
    keychain: Keychain,
}

impl<A: KeychainApi> KeychainVault<A> {
    /// Build a vault over an already-decided keychain. Callers that want the
    /// decision made for them use [`KeychainVault::open`].
    pub fn with_keychain(api: A, service: impl Into<String>, keychain: Keychain) -> Self {
        Self {
            api: Arc::new(api),
            service: Arc::from(service.into()),
            keychain,
        }
    }

    /// Probe, consult the operator's override and the store's marker, and
    /// record the outcome.
    pub fn open(api: A, service: impl Into<String>, record_path: &Path) -> Result<Self, CoreError> {
        Self::open_for_store(api, service, record_path, false)
    }

    /// Open a vault whose associated store may already contain binding state.
    ///
    /// Existing state plus a missing marker makes an automatic login-keychain
    /// fallback ambiguous and therefore fail-closed.
    pub fn open_for_store(
        api: A,
        service: impl Into<String>,
        record_path: &Path,
        store_exists: bool,
    ) -> Result<Self, CoreError> {
        let service = service.into();
        let keychain = resolve_for_store(
            requested_from_env()?,
            read_record(record_path),
            store_exists,
            api.data_protection_available(),
        )?;
        tracing::info!("macOS keychain in use: {keychain} (service {service})");
        write_record(record_path, keychain);
        Ok(Self::with_keychain(api, service, keychain))
    }

    pub fn keychain(&self) -> Keychain {
        self.keychain
    }

    pub fn service(&self) -> &str {
        &self.service
    }

    fn account(id: &Uuid) -> String {
        id.to_string()
    }
}

#[async_trait::async_trait]
impl<A: KeychainApi> SecretVault for KeychainVault<A> {
    fn set(&self, id: &Uuid, attrs: &VaultAttrs, value: &SecretValue) -> Result<(), CoreError> {
        self.api
            .write(
                self.keychain,
                &self.service,
                &Self::account(id),
                &label_for(&attrs.name),
                value.as_bytes(),
            )
            .map_err(CoreError::from)
    }

    async fn get(&self, id: &Uuid) -> Result<SecretValue, CoreError> {
        // Security.framework calls block, and the login-keychain path can
        // block on a user; keep them off the async workers.
        let api = self.api.clone();
        let service = self.service.clone();
        let keychain = self.keychain;
        let account = Self::account(id);
        let bytes = tokio::task::spawn_blocking(move || {
            read_migrating(api.as_ref(), keychain, &service, &account)
        })
        .await
        .map_err(|e| CoreError::Vault(format!("keychain task: {e}")))??;
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| CoreError::Vault("the stored secret value is not valid UTF-8".into()))?;
        Ok(Zeroizing::new(text.to_string()))
    }

    fn delete(&self, id: &Uuid) -> Result<(), CoreError> {
        let account = Self::account(id);
        let removed = self.api.remove(self.keychain, &self.service, &account);
        // An un-migrated login-keychain copy must go too, or a "deleted"
        // secret would come back the next time it is read.
        let mut removed_legacy = false;
        if self.keychain == Keychain::DataProtection {
            match self.api.remove(Keychain::Login, &self.service, &account) {
                Ok(()) => removed_legacy = true,
                Err(KeychainError::NotFound) => {}
                Err(error) => {
                    tracing::warn!("could not remove the login-keychain copy: {error}")
                }
            }
        }
        match removed {
            Ok(()) => Ok(()),
            // Before its first read, a legacy item exists only in the login
            // keychain. Deleting that item is success even though the selected
            // data-protection keychain correctly reported no current copy.
            Err(KeychainError::NotFound) if removed_legacy => Ok(()),
            Err(error) => Err(CoreError::from(error)),
        }
    }

    fn set_attrs(&self, id: &Uuid, attrs: &VaultAttrs) -> Result<(), CoreError> {
        // Cosmetic: it retitles the item in Keychain Access so the list is
        // readable. The index owns the name, so an item that is not there
        // (or is still in the login keychain, awaiting its first read) must
        // not fail the rename that asked for this.
        match self.api.relabel(
            self.keychain,
            &self.service,
            &Self::account(id),
            &label_for(&attrs.name),
        ) {
            Ok(()) | Err(KeychainError::NotFound) => Ok(()),
            Err(error) => Err(CoreError::from(error)),
        }
    }
}

/* -------------------------------- tests ---------------------------------- */

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// Keychain + service + account, the triple that names one item.
    type ItemKey = (Keychain, String, String);
    /// Label + value, everything an item carries.
    type Item = (String, Vec<u8>);

    /// The macOS keychain, as observed rather than as assumed.
    ///
    /// The subtlety this exists to reproduce: an unentitled process is not
    /// refused by the data-protection keychain, it is given an *empty* one.
    /// Reads succeed and find nothing; only writes are refused, because only
    /// a write has to name an access group. A fake that refused reads too
    /// would let a read-based entitlement probe look correct.
    #[derive(Default)]
    pub(crate) struct FakeKeychain {
        items: Mutex<HashMap<ItemKey, Item>>,
        /// Set when this process holds no keychain access group.
        unentitled: bool,
        /// Makes every write fail, for the paths that have to survive one.
        write_error: Option<KeychainError>,
    }

    impl FakeKeychain {
        fn entitled() -> Self {
            Self::default()
        }

        fn unentitled() -> Self {
            Self {
                unentitled: true,
                ..Self::default()
            }
        }

        fn read_only() -> Self {
            Self {
                write_error: Some(KeychainError::Os(OsError::new(-25243))),
                ..Self::default()
            }
        }

        fn seed(&self, keychain: Keychain, service: &str, account: &str, value: &str) {
            self.items.lock().unwrap().insert(
                (keychain, service.into(), account.into()),
                ("Multitool".into(), value.as_bytes().to_vec()),
            );
        }

        fn peek(
            &self,
            keychain: Keychain,
            service: &str,
            account: &str,
        ) -> Option<(String, String)> {
            self.items
                .lock()
                .unwrap()
                .get(&(keychain, service.into(), account.into()))
                .map(|(label, value)| (label.clone(), String::from_utf8(value.clone()).unwrap()))
        }
    }

    impl KeychainApi for Arc<FakeKeychain> {
        fn read(
            &self,
            keychain: Keychain,
            service: &str,
            account: &str,
        ) -> Result<Zeroizing<Vec<u8>>, KeychainError> {
            // No access group means an empty search, not a refused one.
            if keychain == Keychain::DataProtection && self.unentitled {
                return Err(KeychainError::NotFound);
            }
            self.items
                .lock()
                .unwrap()
                .get(&(keychain, service.into(), account.into()))
                .map(|(_, value)| Zeroizing::new(value.clone()))
                .ok_or(KeychainError::NotFound)
        }

        fn write(
            &self,
            keychain: Keychain,
            service: &str,
            account: &str,
            label: &str,
            value: &[u8],
        ) -> Result<(), KeychainError> {
            // A write has to name a group to put the item in, and there is
            // none — this is the call that reports the missing entitlement.
            if keychain == Keychain::DataProtection && self.unentitled {
                return Err(KeychainError::MissingEntitlement);
            }
            if let Some(error) = &self.write_error {
                return Err(error.clone());
            }
            self.items.lock().unwrap().insert(
                (keychain, service.into(), account.into()),
                (label.into(), value.to_vec()),
            );
            Ok(())
        }

        fn relabel(
            &self,
            keychain: Keychain,
            service: &str,
            account: &str,
            label: &str,
        ) -> Result<(), KeychainError> {
            let mut items = self.items.lock().unwrap();
            let item = items
                .get_mut(&(keychain, service.into(), account.into()))
                .ok_or(KeychainError::NotFound)?;
            item.0 = label.into();
            Ok(())
        }

        fn remove(
            &self,
            keychain: Keychain,
            service: &str,
            account: &str,
        ) -> Result<(), KeychainError> {
            self.items
                .lock()
                .unwrap()
                .remove(&(keychain, service.into(), account.into()))
                .map(|_| ())
                .ok_or(KeychainError::NotFound)
        }
    }

    fn attrs(name: &str) -> VaultAttrs {
        VaultAttrs {
            name: name.into(),
            created_at: chrono::Utc::now(),
        }
    }

    const SERVICE: &str = "com.aka.desktop";

    #[test]
    fn the_probe_answers_the_question_writes_will_be_asked() {
        let entitled = Arc::new(FakeKeychain::entitled());
        assert_eq!(entitled.data_protection_available(), Ok(()));
        assert_eq!(
            entitled.peek(Keychain::DataProtection, PROBE_SERVICE, PROBE_ACCOUNT),
            None,
            "the probe item is cleaned up"
        );

        let unentitled = Arc::new(FakeKeychain::unentitled());
        assert_eq!(
            unentitled.data_protection_available(),
            Err(KeychainError::MissingEntitlement)
        );
    }

    #[test]
    fn a_read_probe_would_have_passed_a_build_that_cannot_write() {
        // The regression this module was shipped with: an unentitled process
        // is handed an *empty* data-protection keychain rather than being
        // refused, so a read comes back "no such item" — the same answer an
        // entitled process with no probe item gives. Every read below is
        // indistinguishable between the two; only the write tells them apart.
        let unentitled = Arc::new(FakeKeychain::unentitled());
        assert_eq!(
            unentitled.read(Keychain::DataProtection, PROBE_SERVICE, PROBE_ACCOUNT),
            Err(KeychainError::NotFound),
        );
        assert_eq!(
            unentitled.read(Keychain::DataProtection, SERVICE, "anything"),
            Err(KeychainError::NotFound),
        );

        // So the choice has to come out Login, or every write fails and every
        // read falls back to the login keychain with a warning per secret.
        assert_eq!(
            resolve(None, None, unentitled.data_protection_available()).unwrap(),
            Keychain::Login
        );
    }

    #[test]
    fn an_entitled_build_takes_the_data_protection_keychain() {
        assert_eq!(
            resolve(None, None, Ok(())).unwrap(),
            Keychain::DataProtection
        );
        assert_eq!(
            resolve(None, Some(Keychain::Login), Ok(())).unwrap(),
            Keychain::DataProtection,
            "a store recorded on the login keychain still upgrades: reads migrate"
        );
    }

    #[test]
    fn an_unentitled_build_falls_back_only_on_a_store_that_never_used_the_new_one() {
        assert_eq!(
            resolve(None, None, Err(KeychainError::MissingEntitlement)).unwrap(),
            Keychain::Login
        );
        assert_eq!(
            resolve(
                None,
                Some(Keychain::Login),
                Err(KeychainError::MissingEntitlement)
            )
            .unwrap(),
            Keychain::Login
        );

        // The case that must never be quiet: the values are somewhere this
        // binary cannot reach, so it says so instead of showing nothing.
        let error = resolve(
            None,
            Some(Keychain::DataProtection),
            Err(KeychainError::MissingEntitlement),
        )
        .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("data-protection keychain"), "{message}");
        assert!(message.contains(KEYCHAIN_ENV), "{message}");
    }

    #[test]
    fn an_explicit_request_is_honoured_or_refused_never_downgraded() {
        assert_eq!(
            resolve(
                Some(Keychain::Login),
                Some(Keychain::DataProtection),
                Ok(())
            )
            .unwrap(),
            Keychain::Login
        );
        assert!(resolve(
            Some(Keychain::DataProtection),
            None,
            Err(KeychainError::MissingEntitlement)
        )
        .is_err());
    }

    #[test]
    fn an_os_error_prefers_the_platforms_own_words() {
        // What `SecCopyErrorMessageString` gives us on macOS.
        let described = KeychainError::Os(OsError::described(
            -25308,
            Some("User interaction is not allowed.".into()),
        ));
        assert_eq!(
            described.to_string(),
            "Keychain error: User interaction is not allowed. (OSStatus -25308)"
        );

        // And what a status it cannot describe still has to say.
        let bare = KeychainError::NotAuthorized(OsError::new(-128));
        assert_eq!(
            bare.to_string(),
            "Keychain access was not authorized: OSStatus -128"
        );
    }

    #[test]
    fn the_override_parses_its_documented_spellings() {
        assert_eq!(parse_requested("auto").unwrap(), None);
        assert_eq!(parse_requested("").unwrap(), None);
        assert_eq!(
            parse_requested(" Data-Protection ").unwrap(),
            Some(Keychain::DataProtection)
        );
        assert_eq!(parse_requested("login").unwrap(), Some(Keychain::Login));
        assert!(parse_requested("keychain").is_err());
    }

    #[test]
    fn the_marker_round_trips_and_tolerates_a_missing_or_corrupt_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keychain.json");

        assert_eq!(read_record(&path), None);
        write_record(&path, Keychain::DataProtection);
        assert_eq!(read_record(&path), Some(Keychain::DataProtection));
        write_record(&path, Keychain::Login);
        assert_eq!(read_record(&path), Some(Keychain::Login));

        std::fs::write(&path, b"not json").unwrap();
        assert_eq!(read_record(&path), None);
    }

    #[test]
    fn a_marker_from_the_broken_probe_is_not_believed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keychain.json");
        // What the read-probe build wrote: it claims the data-protection
        // keychain on a store whose values never got there. Believing it
        // would refuse to open a vault that is in fact perfectly readable.
        std::fs::write(
            &path,
            br#"{"keychain":"data-protection","updated_at":"2026-07-24T23:40:31Z"}"#,
        )
        .unwrap();

        assert_eq!(read_record(&path), None);
        assert_eq!(
            resolve(
                None,
                read_record(&path),
                Err(KeychainError::MissingEntitlement)
            )
            .unwrap(),
            Keychain::Login
        );

        // A marker this build wrote is believed, and still refuses.
        write_record(&path, Keychain::DataProtection);
        assert_eq!(read_record(&path), Some(Keychain::DataProtection));
        assert!(resolve(
            None,
            read_record(&path),
            Err(KeychainError::MissingEntitlement)
        )
        .is_err());
    }

    #[test]
    fn an_existing_store_cannot_silently_fall_back_without_its_marker() {
        assert!(
            resolve_for_store(None, None, true, Err(KeychainError::MissingEntitlement)).is_err()
        );

        assert_eq!(
            resolve_for_store(
                Some(Keychain::Login),
                None,
                true,
                Err(KeychainError::MissingEntitlement)
            )
            .unwrap(),
            Keychain::Login
        );

        assert_eq!(
            resolve_for_store(None, None, false, Err(KeychainError::MissingEntitlement)).unwrap(),
            Keychain::Login
        );
    }

    #[test]
    fn the_marker_creates_its_data_directory_privately() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        // The vault opens before the store, so this can be the first write
        // into a fresh data directory.
        let data_dir = dir.path().join("data");
        let path = data_dir.join("keychain.json");

        write_record(&path, Keychain::DataProtection);

        let mode = std::fs::metadata(&data_dir).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[tokio::test]
    async fn values_written_now_never_touch_the_login_keychain() {
        let api = Arc::new(FakeKeychain::entitled());
        let vault = KeychainVault::with_keychain(api.clone(), SERVICE, Keychain::DataProtection);
        let id = Uuid::new_v4();

        vault
            .set(&id, &attrs("API_KEY"), &Zeroizing::new("s3cr3t".into()))
            .unwrap();

        let account = id.to_string();
        assert_eq!(
            api.peek(Keychain::DataProtection, SERVICE, &account),
            Some(("Multitool (API_KEY)".into(), "s3cr3t".into()))
        );
        assert_eq!(api.peek(Keychain::Login, SERVICE, &account), None);
        assert_eq!(&*vault.get(&id).await.unwrap(), "s3cr3t");
    }

    #[tokio::test]
    async fn a_legacy_item_migrates_on_its_first_read() {
        let api = Arc::new(FakeKeychain::entitled());
        let id = Uuid::new_v4();
        let account = id.to_string();
        api.seed(Keychain::Login, SERVICE, &account, "from-keyring");

        let vault = KeychainVault::with_keychain(api.clone(), SERVICE, Keychain::DataProtection);
        assert_eq!(&*vault.get(&id).await.unwrap(), "from-keyring");

        // Copied across and the prompting original removed, so the next read
        // — and every read after it — is silent.
        assert_eq!(
            api.peek(Keychain::DataProtection, SERVICE, &account)
                .map(|(_, value)| value),
            Some("from-keyring".into())
        );
        assert_eq!(api.peek(Keychain::Login, SERVICE, &account), None);
        assert_eq!(&*vault.get(&id).await.unwrap(), "from-keyring");
    }

    #[tokio::test]
    async fn a_failed_migration_still_hands_back_the_value() {
        let api = Arc::new(FakeKeychain::read_only());
        let id = Uuid::new_v4();
        let account = id.to_string();
        api.seed(Keychain::Login, SERVICE, &account, "from-keyring");

        // Migration is an optimization on top of a read that has already
        // succeeded; it must never turn that read into a failure.
        let vault = KeychainVault::with_keychain(api.clone(), SERVICE, Keychain::DataProtection);
        assert_eq!(&*vault.get(&id).await.unwrap(), "from-keyring");
        assert_eq!(
            api.peek(Keychain::Login, SERVICE, &account)
                .map(|(_, value)| value),
            Some("from-keyring".into()),
            "the original stays put, so the next read can try again"
        );
    }

    #[tokio::test]
    async fn a_missing_secret_is_still_reported_as_missing() {
        let api = Arc::new(FakeKeychain::entitled());
        let vault = KeychainVault::with_keychain(api, SERVICE, Keychain::DataProtection);

        assert!(matches!(
            vault.get(&Uuid::new_v4()).await,
            Err(CoreError::SecretNotFound)
        ));
    }

    #[tokio::test]
    async fn a_login_keychain_vault_does_not_migrate_anything() {
        let api = Arc::new(FakeKeychain::unentitled());
        let id = Uuid::new_v4();
        let account = id.to_string();
        api.seed(Keychain::Login, SERVICE, &account, "stays-put");

        let vault = KeychainVault::with_keychain(api.clone(), SERVICE, Keychain::Login);
        assert_eq!(&*vault.get(&id).await.unwrap(), "stays-put");
        assert_eq!(
            api.peek(Keychain::Login, SERVICE, &account)
                .map(|(_, value)| value),
            Some("stays-put".into())
        );
    }

    #[tokio::test]
    async fn delete_takes_the_un_migrated_copy_with_it() {
        let api = Arc::new(FakeKeychain::entitled());
        let id = Uuid::new_v4();
        let account = id.to_string();
        api.seed(Keychain::Login, SERVICE, &account, "legacy");

        let vault = KeychainVault::with_keychain(api.clone(), SERVICE, Keychain::DataProtection);
        vault
            .set(&id, &attrs("API_KEY"), &Zeroizing::new("current".into()))
            .unwrap();
        vault.delete(&id).unwrap();

        assert_eq!(api.peek(Keychain::DataProtection, SERVICE, &account), None);
        assert_eq!(
            api.peek(Keychain::Login, SERVICE, &account),
            None,
            "a deleted secret must not come back from the login keychain"
        );
        assert!(matches!(
            vault.get(&id).await,
            Err(CoreError::SecretNotFound)
        ));
    }

    #[tokio::test]
    async fn deleting_a_login_only_legacy_item_reports_success() {
        let api = Arc::new(FakeKeychain::entitled());
        let id = Uuid::new_v4();
        let account = id.to_string();
        api.seed(Keychain::Login, SERVICE, &account, "legacy-only");

        let vault = KeychainVault::with_keychain(api.clone(), SERVICE, Keychain::DataProtection);
        vault.delete(&id).unwrap();

        assert_eq!(api.peek(Keychain::Login, SERVICE, &account), None);
        assert!(matches!(
            vault.get(&id).await,
            Err(CoreError::SecretNotFound)
        ));
    }

    #[tokio::test]
    async fn renaming_retitles_the_item_and_never_fails_over_a_missing_one() {
        let api = Arc::new(FakeKeychain::entitled());
        let vault = KeychainVault::with_keychain(api.clone(), SERVICE, Keychain::DataProtection);
        let id = Uuid::new_v4();
        vault
            .set(&id, &attrs("API_KEY"), &Zeroizing::new("v".into()))
            .unwrap();

        vault.set_attrs(&id, &attrs("RENAMED")).unwrap();
        assert_eq!(
            api.peek(Keychain::DataProtection, SERVICE, &id.to_string())
                .map(|(label, _)| label),
            Some("Multitool (RENAMED)".into())
        );

        // The index owns the name; a vault item that is not there must not
        // block the rename.
        assert!(vault.set_attrs(&Uuid::new_v4(), &attrs("GHOST")).is_ok());
    }

    #[test]
    fn open_records_the_keychain_it_settled_on() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keychain.json");

        let vault =
            KeychainVault::open(Arc::new(FakeKeychain::entitled()), SERVICE, &path).unwrap();
        assert_eq!(vault.keychain(), Keychain::DataProtection);
        assert_eq!(read_record(&path), Some(Keychain::DataProtection));

        // A build that cannot reach those values refuses to open rather than
        // presenting an empty vault.
        assert!(KeychainVault::open(Arc::new(FakeKeychain::unentitled()), SERVICE, &path).is_err());
    }
}
