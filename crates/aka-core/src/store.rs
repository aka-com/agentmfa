//! Vault-backed store. Secrets live in the vault (e.g. macOS Keychain).
//! Everything else, including the secrets index and connection config
//! lives in `index.json`.
//!
//! Invariants enforced here:
//! - secret and connection names are unique (templates resolve secrets by
//!   name; agents and rules address connections by name);
//! - renaming a secret rewrites every injection template that references it,
//!   atomically with the rename;
//! - deleting a secret still referenced by a connection is refused;
//! - API connections' secret list is derived from their template's refs;
//!   pg/ssh connections bind at most one secret;
//! - a connection's type is fixed after creation.

use std::sync::Arc;
use std::sync::Mutex;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{ConnectionField, CoreError};
use crate::events::BrokerEvents;
#[cfg(any(test, feature = "test-harness"))]
use crate::events::NoopEvents;
use crate::integrity::StateIntegrity;
use crate::paths::Paths;
use crate::template::{is_valid_secret_name, Template};
use crate::types::{
    reveal_prefix, Connection, ConnectionConfig, ConnectionKind, SecretMeta, SecretValue, Settings,
};
use crate::vault::{SecretVault, VaultAttrs};
use crate::Result;

const PRESENCE_ABSOLUTE_MAX: std::time::Duration = std::time::Duration::from_secs(12 * 60 * 60);

#[derive(Debug, Clone, Copy)]
struct PresenceGrant {
    idle_until: std::time::Instant,
    absolute_until: std::time::Instant,
    idle_wall_until: chrono::DateTime<Utc>,
    absolute_wall_until: chrono::DateTime<Utc>,
}

impl PresenceGrant {
    fn new(
        now: std::time::Instant,
        wall_now: chrono::DateTime<Utc>,
        window: std::time::Duration,
    ) -> Self {
        let absolute_until = now + PRESENCE_ABSOLUTE_MAX;
        let absolute_wall_until = wall_now
            + chrono::Duration::from_std(PRESENCE_ABSOLUTE_MAX)
                .expect("the presence maximum fits chrono");
        Self {
            idle_until: std::cmp::min(now + window, absolute_until),
            absolute_until,
            idle_wall_until: std::cmp::min(
                wall_now
                    + chrono::Duration::from_std(window)
                        .expect("the configured presence window fits chrono"),
                absolute_wall_until,
            ),
            absolute_wall_until,
        }
    }

    fn ride(
        &mut self,
        now: std::time::Instant,
        wall_now: chrono::DateTime<Utc>,
        window: std::time::Duration,
    ) -> bool {
        if now >= self.idle_until
            || now >= self.absolute_until
            || wall_now >= self.idle_wall_until
            || wall_now >= self.absolute_wall_until
        {
            return false;
        }
        self.idle_until = std::cmp::min(now + window, self.absolute_until);
        self.idle_wall_until = std::cmp::min(
            wall_now
                + chrono::Duration::from_std(window)
                    .expect("the configured presence window fits chrono"),
            self.absolute_wall_until,
        );
        true
    }

    fn reanchor(
        &mut self,
        now: std::time::Instant,
        wall_now: chrono::DateTime<Utc>,
        window: std::time::Duration,
    ) {
        if now < self.idle_until
            && now < self.absolute_until
            && wall_now < self.idle_wall_until
            && wall_now < self.absolute_wall_until
        {
            self.idle_until = std::cmp::min(now + window, self.absolute_until);
            self.idle_wall_until = std::cmp::min(
                wall_now
                    + chrono::Duration::from_std(window)
                        .expect("the configured presence window fits chrono"),
                self.absolute_wall_until,
            );
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
struct PresenceState {
    secret_read: Option<PresenceGrant>,
    configuration: Option<PresenceGrant>,
}

#[derive(Debug, Default)]
struct PresenceCoordinator {
    state: Mutex<PresenceState>,
    /// One process-wide lane for the freshness re-check and any native
    /// prompt it triggers. The check must happen after acquiring this lock.
    confirmation: Mutex<()>,
}

/// Everything `index.json` holds.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct IndexState {
    #[serde(default)]
    secrets: Vec<SecretMeta>,
    #[serde(default, deserialize_with = "connections_dropping_retired_kinds")]
    connections: Vec<Connection>,
    #[serde(default)]
    settings: Option<Settings>,
    /// Monotonic generation of the separately sealed access table. A
    /// non-zero value makes a missing or rolled-back `access.json` a hard
    /// integrity failure instead of silently restoring default access.
    #[serde(default)]
    access_generation: u64,
}

/// Connection kinds this build still understands. A store written by an older
/// version may name one that has since been removed.
const SUPPORTED_CONNECTION_KINDS: [&str; 3] = ["api", "pg", "ssh"];

thread_local! {
    /// What the last load dropped, as `name (kind)` per row.
    ///
    /// A `deserialize_with` hook cannot reach a sibling field, and losing a
    /// user's configured tool is not a log-only event — it has to reach the
    /// audit trail and, through it, the user. `Store::open_with_events`
    /// deserializes and drains this on the same thread, in the same call.
    static RETIRED_CONNECTIONS_DROPPED: std::cell::RefCell<Vec<String>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// Load connections, dropping any whose kind this build no longer supports.
///
/// WebSocket support was removed, and an upgrading user's `index.json` may
/// still list `"kind": "ws"` rows. Failing the whole deserialization would
/// report the store as corrupt and refuse to open the vault — losing access to
/// every *other* connection and secret over a feature that is simply gone. So
/// a retired kind is dropped, while a record that is genuinely malformed still
/// fails loudly: the two are told apart by whether the kind itself is one this
/// build knows. What was dropped is left in [`RETIRED_CONNECTIONS_DROPPED`] for
/// the caller to audit.
fn connections_dropping_retired_kinds<'de, D>(deserializer: D) -> Result<Vec<Connection>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error as _;
    let rows = Vec::<serde_json::Value>::deserialize(deserializer)?;
    let mut connections = Vec::with_capacity(rows.len());
    for row in rows {
        let kind = row
            .get("config")
            .and_then(|config| config.get("kind"))
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);
        let name = row
            .get("name")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unnamed")
            .to_string();
        match serde_json::from_value::<Connection>(row) {
            Ok(connection) => connections.push(connection),
            Err(error) => {
                let retired = kind
                    .as_deref()
                    .is_some_and(|kind| !SUPPORTED_CONNECTION_KINDS.contains(&kind));
                if !retired {
                    return Err(D::Error::custom(error));
                }
                let kind = kind.as_deref().unwrap_or("unknown").to_string();
                tracing::warn!(
                    "dropping the {kind} connection {name:?}: that connection type is no \
                     longer supported"
                );
                RETIRED_CONNECTIONS_DROPPED
                    .with(|dropped| dropped.borrow_mut().push(format!("{name} ({kind})")));
            }
        }
    }
    Ok(connections)
}

impl IndexState {
    fn settings(&self) -> Settings {
        self.settings.clone().unwrap_or_default()
    }
}

/// Outcome of a trust-on-first-use SSH host-key pin attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinOutcome {
    /// The observed key was pinned by this call.
    Pinned(ssh_key::Fingerprint),
    /// The connection already pinned a key; nothing changed. Callers must
    /// compare it against the observed key and fail closed on a mismatch.
    AlreadyPinned(ssh_key::Fingerprint),
}

/// Input for creating or updating a connection. Serializable: it rides the
/// manage API when a remote shell submits an add or edit.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ConnectionSpec {
    pub name: String,
    pub config: ConnectionConfig,
    /// For pg/ssh: the optional single bound secret. Ignored for
    /// api connections, whose secret list is derived from the template's refs.
    pub secrets: Vec<Uuid>,
}

pub struct Store {
    paths: Paths,
    vault: Arc<dyn SecretVault>,
    events: Arc<dyn BrokerEvents>,
    integrity: Arc<StateIntegrity>,
    state: Mutex<IndexState>,
    /// Native-authentication grants. Any *native* prompt the user passes —
    /// configuration, full-authority, or the clipboard copy sheet — opens the
    /// whole user-plane window ("one OS authentication keeps AgentMFA
    /// unlocked"); only riding an existing read grant stays read-scoped. No
    /// grant can slide beyond its original 12-hour absolute lifetime. Never
    /// persisted.
    presence: Arc<PresenceCoordinator>,
    /// Tools this build could not load because their kind was retired, as
    /// `name (kind)`. Captured at open so the broker can audit the loss.
    retired_connections_dropped: Vec<String>,
}

impl Store {
    #[cfg(any(test, feature = "test-harness"))]
    pub async fn open(paths: Paths, vault: Arc<dyn SecretVault>) -> Result<Self> {
        let integrity = Arc::new(StateIntegrity::open_for_paths(&*vault, &paths).await?);
        Self::open_with_events(paths, vault, Arc::new(NoopEvents), integrity)
    }

    pub fn open_with_events(
        paths: Paths,
        vault: Arc<dyn SecretVault>,
        events: Arc<dyn BrokerEvents>,
        integrity: Arc<StateIntegrity>,
    ) -> Result<Self> {
        paths.ensure()?;
        RETIRED_CONNECTIONS_DROPPED.with(|dropped| dropped.borrow_mut().clear());
        // index.json is sealed: a file that fails verification
        // refuses to load rather than silently serving repointed bindings.
        let mut state: IndexState = match integrity.read_verified(&paths.index_file())? {
            Some(bytes) => serde_json::from_slice(&bytes)?,
            None => IndexState::default(),
        };
        let retired_connections_dropped =
            RETIRED_CONNECTIONS_DROPPED.with(|dropped| std::mem::take(&mut *dropped.borrow_mut()));
        // Rewrite once when a retired row was dropped, so the record on disk
        // matches what the broker is serving and the next open is a clean
        // load rather than a repeat of the same warning.
        let migrated_pg_ca = migrate_legacy_pg_ca_bundle(&mut state);
        let migrated_oauth_tokens = migrate_oauth_token_secret_ids(&mut state);
        if migrated_pg_ca || migrated_oauth_tokens || !retired_connections_dropped.is_empty() {
            integrity.write(&paths.index_file(), &serde_json::to_vec_pretty(&state)?)?;
        }
        Ok(Self {
            paths,
            vault,
            events,
            integrity,
            state: Mutex::new(state),
            presence: Arc::new(PresenceCoordinator::default()),
            retired_connections_dropped,
        })
    }

    /// Tools discarded at load because this build no longer supports their
    /// kind, as `name (kind)`. The broker audits these once at startup: a
    /// configured tool vanishing from the list is the user's business, and a
    /// `tracing` warning is not somewhere they will ever look.
    pub fn retired_connections_dropped(&self) -> &[String] {
        &self.retired_connections_dropped
    }

    /* ----------------------------- presence ------------------------------- */

    fn presence_window(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.settings().presence_window_secs)
    }

    /// Establish a configuration grant, which also covers reads. Used after
    /// any successful *native* authentication — a configuration action
    /// (preserving the save-then-test flow), a full-authority action-gate
    /// prompt (agent grants, key rotation), or the clipboard copy sheet. The
    /// prompts all present the same OS authentication, so one passed sheet
    /// opens the same window regardless of which gate collected it; riding
    /// an existing read grant establishes nothing new.
    fn note_configuration_presence(&self) {
        let now = std::time::Instant::now();
        let grant = PresenceGrant::new(now, Utc::now(), self.presence_window());
        let mut presence = self.presence.state.lock().unwrap();
        presence.configuration = Some(grant);
        presence.secret_read = Some(grant);
    }

    /// Ride a configuration grant. It may extend an existing read grant, but
    /// cannot create one unless a native configuration authentication did.
    fn use_configuration_presence(&self) -> bool {
        let now = std::time::Instant::now();
        let wall_now = Utc::now();
        let window = self.presence_window();
        let mut presence = self.presence.state.lock().unwrap();
        let fresh = presence
            .configuration
            .as_mut()
            .is_some_and(|grant| grant.ride(now, wall_now, window));
        if fresh {
            if let Some(grant) = presence.secret_read.as_mut() {
                grant.ride(now, wall_now, window);
            }
        }
        fresh
    }

    /// Re-anchor active grants after the configured idle window changes. The
    /// original absolute deadline is deliberately retained.
    pub fn reanchor_presence(&self) {
        let _confirmation = self.presence.confirmation.lock().unwrap();
        let now = std::time::Instant::now();
        let wall_now = Utc::now();
        let window = self.presence_window();
        let mut presence = self.presence.state.lock().unwrap();
        if let Some(grant) = presence.secret_read.as_mut() {
            grant.reanchor(now, wall_now, window);
        }
        if let Some(grant) = presence.configuration.as_mut() {
            grant.reanchor(now, wall_now, window);
        }
    }

    /// Drop all grants so the next gated action re-prompts (e.g. after the
    /// read-authentication setting changes).
    pub fn clear_user_presence(&self) {
        let _confirmation = self.presence.confirmation.lock().unwrap();
        *self.presence.state.lock().unwrap() = PresenceState::default();
    }

    /// Always invoke the native action gate, serialized with every other
    /// presence check and prompt. The action gate never *rides* the presence
    /// window — a full-authority action (agent grants, key rotation) always
    /// re-prompts — but a successful authentication here *opens* it, so an
    /// immediately following user-plane read or configuration change is not a
    /// surprise re-prompt. This keeps the documented "one OS authentication
    /// keeps AgentMFA unlocked" model: the strongest prompt there is also
    /// covers the weaker user-plane actions that follow it.
    pub fn confirm_action(&self, description: &str) -> Result<crate::types::ConfirmationMethod> {
        let _confirmation = self.presence.confirmation.lock().unwrap();
        let method = self
            .events
            .confirm_action(description)
            .ok_or(CoreError::NotConfirmed)?;
        if self.events.action_authority(method).establishes_presence() {
            self.note_configuration_presence();
        }
        Ok(method)
    }

    /// Check and ride the configuration grant, or establish purpose-scoped
    /// grants after one serialized native prompt.
    pub fn confirm_configuration_action(
        &self,
        description: &str,
    ) -> Result<crate::types::ConfirmationMethod> {
        let _confirmation = self.presence.confirmation.lock().unwrap();
        if self.use_configuration_presence() {
            return Ok(crate::types::ConfirmationMethod::RecentAuthentication);
        }
        let method = self
            .events
            .confirm_action(description)
            .ok_or(CoreError::NotConfirmed)?;
        if self.events.action_authority(method).establishes_presence() {
            self.note_configuration_presence();
        }
        Ok(method)
    }

    /// Check and ride the read grant, or establish grants after the
    /// clipboard's native authentication. The blocking prompt and check share
    /// the same global lane as config and ordinary read prompts. A *passed
    /// sheet* opens the full user-plane window (read + configuration): it is
    /// the same OS authentication a configuration prompt would collect, so
    /// acting near the copy (edit, reissue, delete) must not re-prompt
    /// back-to-back. Riding an existing read grant grants nothing new.
    pub async fn confirm_secret_copy(&self, meta: SecretMeta) -> Result<()> {
        let presence = self.presence.clone();
        let events = self.events.clone();
        let window = self.presence_window();
        tokio::task::spawn_blocking(move || {
            let _confirmation = presence.confirmation.lock().unwrap();
            let now = std::time::Instant::now();
            let wall_now = Utc::now();
            if presence
                .state
                .lock()
                .unwrap()
                .secret_read
                .as_mut()
                .is_some_and(|grant| grant.ride(now, wall_now, window))
            {
                return Ok(());
            }
            if !events.confirm_secret_copy(&meta, window) {
                return Err(CoreError::SecretReadNotAuthenticated);
            }
            if events.secret_copy_authority().establishes_presence() {
                let grant = PresenceGrant::new(std::time::Instant::now(), Utc::now(), window);
                let mut state = presence.state.lock().unwrap();
                state.secret_read = Some(grant);
                state.configuration = Some(grant);
            }
            Ok(())
        })
        .await
        .map_err(|e| CoreError::Vault(format!("confirmation task failed: {e}")))?
    }

    fn persist(&self, state: &IndexState) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(state)?;
        self.integrity.write(&self.paths.index_file(), &bytes)?;
        Ok(())
    }

    fn commit(&self, state: &mut IndexState, next: IndexState) -> Result<()> {
        self.persist(&next)?;
        *state = next;
        Ok(())
    }

    /* ------------------------------ secrets ------------------------------ */

    pub fn list_secrets(&self) -> Vec<SecretMeta> {
        let mut secrets = self.state.lock().unwrap().secrets.clone();
        secrets.sort_by(|a, b| a.name.cmp(&b.name));
        secrets
    }

    pub fn secret_by_id(&self, id: &Uuid) -> Result<SecretMeta> {
        self.state
            .lock()
            .unwrap()
            .secrets
            .iter()
            .find(|s| &s.id == id)
            .cloned()
            .ok_or(CoreError::SecretNotFound)
    }

    pub fn secret_by_name(&self, name: &str) -> Option<SecretMeta> {
        self.state
            .lock()
            .unwrap()
            .secrets
            .iter()
            .find(|s| s.name == name)
            .cloned()
    }

    pub fn add_secret(&self, name: &str, value: SecretValue) -> Result<SecretMeta> {
        if !is_valid_secret_name(name) {
            return Err(CoreError::InvalidSecretName(name.to_string()));
        }
        let mut state = self.state.lock().unwrap();
        if state.secrets.iter().any(|s| s.name == name) {
            return Err(CoreError::SecretNameTaken(name.to_string()));
        }
        let now = Utc::now();
        let meta = SecretMeta {
            id: Uuid::new_v4(),
            name: name.to_string(),
            created_at: now,
            updated_at: now,
        };
        self.vault.set(
            &meta.id,
            &VaultAttrs {
                name: meta.name.clone(),
                created_at: now,
            },
            &value,
        )?;
        drop(value); // late fetch, early drop, the plaintext came in exactly once
        let mut next = state.clone();
        next.secrets.push(meta.clone());
        if let Err(error) = self.persist(&next) {
            if let Err(rollback) = self.vault.delete(&meta.id) {
                tracing::error!("failed to roll back vault item {}: {rollback}", meta.id);
            }
            return Err(error);
        }
        *state = next;
        Ok(meta)
    }

    /// Rename a secret, rewriting every injection template that references
    /// it, inside `{{ … }}` placeholders and transform expressions alike,
    /// atomically with the rename.
    ///
    /// Returns the updated meta and how many templates were rewritten.
    pub fn rename_secret(&self, id: &Uuid, new_name: &str) -> Result<(SecretMeta, usize)> {
        if !is_valid_secret_name(new_name) {
            return Err(CoreError::InvalidSecretName(new_name.to_string()));
        }
        let mut state = self.state.lock().unwrap();
        let old_name = state
            .secrets
            .iter()
            .find(|s| &s.id == id)
            .ok_or(CoreError::SecretNotFound)?
            .name
            .clone();
        if new_name == old_name {
            let meta = state.secrets.iter().find(|s| &s.id == id).unwrap().clone();
            return Ok((meta, 0));
        }
        if state.secrets.iter().any(|s| s.name == new_name) {
            return Err(CoreError::SecretNameTaken(new_name.to_string()));
        }
        // Rewrite templates in a working copy first; nothing is committed
        // until every rewrite has parsed and applied cleanly.
        let mut next = state.clone();
        let mut rewritten = 0usize;
        for conn in next.connections.iter_mut() {
            let template = match &mut conn.config {
                ConnectionConfig::Api { template, .. } => Some(template),
                ConnectionConfig::Pg { .. } | ConnectionConfig::Ssh { .. } => None,
            };
            if let Some(template) = template {
                let parsed = Template::parse(template)?;
                if parsed.refs().contains(&old_name) {
                    *template = parsed.rename_ref(&old_name, new_name);
                    conn.updated_at = Utc::now();
                    rewritten += 1;
                }
            }
        }
        let now = Utc::now();
        let (meta, created_at) = {
            let secret = next.secrets.iter_mut().find(|s| &s.id == id).unwrap();
            secret.name = new_name.to_string();
            secret.updated_at = now;
            (secret.clone(), secret.created_at)
        };
        self.persist(&next)?;
        // Keep the Keychain label aligned with the index.
        if let Err(error) = self.vault.set_attrs(
            id,
            &VaultAttrs {
                name: new_name.to_string(),
                created_at,
            },
        ) {
            if let Err(rollback) = self.persist(&state) {
                tracing::error!("failed to roll back index after vault error: {rollback}");
            }
            return Err(error);
        }
        *state = next;
        Ok((meta, rewritten))
    }

    /// Replace a secret's value (the Edit sheet's write-only field).
    pub fn replace_secret_value(&self, id: &Uuid, value: SecretValue) -> Result<SecretMeta> {
        let mut state = self.state.lock().unwrap();
        let mut next = state.clone();
        let secret = next
            .secrets
            .iter_mut()
            .find(|s| &s.id == id)
            .ok_or(CoreError::SecretNotFound)?;
        secret.updated_at = Utc::now();
        let meta = secret.clone();
        self.persist(&next)?;
        if let Err(error) = self.vault.set(
            id,
            &VaultAttrs {
                name: meta.name.clone(),
                created_at: meta.created_at,
            },
            &value,
        ) {
            if let Err(rollback) = self.persist(&state) {
                tracing::error!("failed to roll back index after vault error: {rollback}");
            }
            return Err(error);
        }
        *state = next;
        Ok(meta)
    }

    /// Deleting a secret a connection still uses is refused.
    pub fn delete_secret(&self, id: &Uuid) -> Result<SecretMeta> {
        let mut state = self.state.lock().unwrap();
        let pos = state
            .secrets
            .iter()
            .position(|s| &s.id == id)
            .ok_or(CoreError::SecretNotFound)?;
        let users: Vec<String> = state
            .connections
            .iter()
            .filter(|c| c.secrets.contains(id))
            .map(|c| c.name.clone())
            .collect();
        if !users.is_empty() {
            return Err(CoreError::SecretInUse(users));
        }
        let mut next = state.clone();
        let meta = next.secrets.remove(pos);
        self.persist(&next)?;
        if let Err(error) = self.vault.delete(id) {
            if let Err(rollback) = self.persist(&state) {
                tracing::error!("failed to roll back index after vault error: {rollback}");
            }
            return Err(error);
        }
        *state = next;
        Ok(meta)
    }

    /// Core-side Keychain read returning only the short prefix
    /// (`min(6, ⌊len/2⌋)` chars). This is still secret disclosure, so it
    /// rides the ordinary read gate and presence window.
    pub async fn reveal_secret_prefix(&self, id: &Uuid) -> Result<String> {
        let value = self.secret_value(id).await?;
        Ok(reveal_prefix(&value))
    }

    /// Fetch a secret's full value from the vault. Core-side callers only:
    /// upstream credential injection and the clipboard-copy command. There
    /// is deliberately no Tauri command that returns this to the webview.
    pub async fn secret_value(&self, id: &Uuid) -> Result<SecretValue> {
        let (meta, reauth) = self.secret_read_target(id)?;
        self.confirm_secret_read(meta, reauth).await?;
        self.vault.get(id).await
    }

    pub async fn secret_value_by_name(&self, name: &str) -> Result<SecretValue> {
        let (meta, reauth) = self.secret_read_target_by_name(name)?;
        let id = meta.id;
        self.confirm_secret_read(meta, reauth).await?;
        self.vault.get(&id).await
    }

    /// Resolve every secret the template references, then render it. The
    /// late-fetch discipline holds: values are fetched here, per use, after
    /// approval — never cached (caching would foreclose just-in-time
    /// issuance backends).
    pub async fn render_template(&self, template: &Template) -> Result<SecretValue> {
        let mut values: std::collections::BTreeMap<String, SecretValue> =
            std::collections::BTreeMap::new();
        for name in template.refs() {
            let value = self.secret_value_by_name(&name).await?;
            values.insert(name, value);
        }
        template.render(|name| {
            values
                .get(name)
                .cloned()
                .ok_or_else(|| CoreError::UnknownTemplateRef(name.to_string()))
        })
    }

    fn secret_read_target(&self, id: &Uuid) -> Result<(SecretMeta, bool)> {
        let state = self.state.lock().unwrap();
        let meta = state
            .secrets
            .iter()
            .find(|s| &s.id == id)
            .cloned()
            .ok_or(CoreError::SecretNotFound)?;
        Ok((meta, state.settings().reauth_on_read))
    }

    fn secret_read_target_by_name(&self, name: &str) -> Result<(SecretMeta, bool)> {
        let state = self.state.lock().unwrap();
        let meta = state
            .secrets
            .iter()
            .find(|s| s.name == name)
            .cloned()
            .ok_or(CoreError::SecretNotFound)?;
        Ok((meta, state.settings().reauth_on_read))
    }

    /// The confirmation hook can block on a native re-auth prompt (Touch
    /// ID), so it runs on the blocking pool rather than tying up a runtime
    /// worker while the user decides.
    async fn confirm_secret_read(&self, meta: SecretMeta, reauth: bool) -> Result<()> {
        if !reauth {
            return Ok(());
        }
        let presence = self.presence.clone();
        let events = self.events.clone();
        let window = self.presence_window();
        crate::authorization::confirm_once(|| async move {
            tokio::task::spawn_blocking(move || {
                let _confirmation = presence.confirmation.lock().unwrap();
                // Re-check only after joining the global lane: another prompt
                // may have established a suitable grant while this read was
                // waiting. Pre-authorized agent executions never reach here.
                let now = std::time::Instant::now();
                let wall_now = Utc::now();
                if presence
                    .state
                    .lock()
                    .unwrap()
                    .secret_read
                    .as_mut()
                    .is_some_and(|grant| grant.ride(now, wall_now, window))
                {
                    return Ok(());
                }
                if !events.confirm_secret_read(&meta) {
                    return Err(CoreError::SecretReadNotAuthenticated);
                }
                if events.secret_read_authority().establishes_presence() {
                    presence.state.lock().unwrap().secret_read = Some(PresenceGrant::new(
                        std::time::Instant::now(),
                        Utc::now(),
                        window,
                    ));
                }
                Ok(())
            })
            .await
            .map_err(|e| CoreError::Vault(format!("confirmation task failed: {e}")))?
        })
        .await
    }

    /// Names of connections referencing this secret (for the "Used by N
    /// connections" line and the delete guard message).
    pub fn connections_using(&self, id: &Uuid) -> Vec<String> {
        self.state
            .lock()
            .unwrap()
            .connections
            .iter()
            .filter(|c| c.secrets.contains(id))
            .map(|c| c.name.clone())
            .collect()
    }

    /* ---------------------------- connections ---------------------------- */

    /// Connections in their persisted order. New tools append to the end
    /// (`add_connection`), deletes preserve the rest, and `reorder_connections`
    /// permutes the list — so this order is the user-chosen one the Tools tab
    /// renders and every consumer (MCP listing, CLI, manage API) mirrors.
    pub fn list_connections(&self) -> Vec<Connection> {
        self.state.lock().unwrap().connections.clone()
    }

    pub fn connection_by_id(&self, id: &Uuid) -> Result<Connection> {
        self.state
            .lock()
            .unwrap()
            .connections
            .iter()
            .find(|c| &c.id == id)
            .cloned()
            .ok_or(CoreError::ConnectionNotFound)
    }

    pub fn connection_by_name(&self, name: &str) -> Option<Connection> {
        self.state
            .lock()
            .unwrap()
            .connections
            .iter()
            .find(|c| c.name == name)
            .cloned()
    }

    /// Check whether a connection can be added against the current index
    /// without changing either the index or the vault. Callers that pause for
    /// user confirmation must still use `add_connection` afterward, which
    /// repeats these state-dependent checks to close the confirmation race.
    pub fn preflight_add_connection(&self, spec: &ConnectionSpec) -> Result<()> {
        let state = self.state.lock().unwrap();
        prepare_connection(&state, spec.clone()).map(|_| ())
    }

    pub fn add_connection(&self, spec: ConnectionSpec) -> Result<Connection> {
        let mut state = self.state.lock().unwrap();
        let conn = prepare_connection(&state, spec)?;
        let mut next = state.clone();
        next.connections.push(conn.clone());
        self.commit(&mut state, next)?;
        Ok(conn)
    }

    /// Atomically add one credential and the connection that first uses it.
    /// The index becomes visible only after both objects validate and persist;
    /// a failed index write removes the just-created vault item.
    pub fn preflight_add_connection_with_secret(
        &self,
        secret_name: &str,
        spec: &ConnectionSpec,
    ) -> Result<()> {
        let state = self.state.lock().unwrap();
        prepare_connection_with_secret(&state, secret_name, spec.clone()).map(|_| ())
    }

    pub fn add_connection_with_secret(
        &self,
        secret_name: &str,
        value: SecretValue,
        spec: ConnectionSpec,
    ) -> Result<(SecretMeta, Connection)> {
        let mut state = self.state.lock().unwrap();
        let (meta, conn) = prepare_connection_with_secret(&state, secret_name, spec)?;
        let mut next = state.clone();
        next.secrets.push(meta.clone());
        next.connections.push(conn.clone());

        self.vault.set(
            &meta.id,
            &VaultAttrs {
                name: meta.name.clone(),
                created_at: meta.created_at,
            },
            &value,
        )?;
        drop(value);
        if let Err(error) = self.persist(&next) {
            if let Err(rollback) = self.vault.delete(&meta.id) {
                tracing::error!("failed to roll back vault item {}: {rollback}", meta.id);
            }
            return Err(error);
        }
        *state = next;
        Ok((meta, conn))
    }

    /// Update a connection. The kind is fixed after creation. Returns the
    /// updated connection and whether its pinned target changed, the caller
    /// must revoke the connection's direct endpoints when it did (a pasted
    /// address granted for one destination must not silently cover another).
    pub fn update_connection(
        &self,
        id: &Uuid,
        mut spec: ConnectionSpec,
    ) -> Result<(Connection, bool)> {
        validate_connection_name(&spec.name)?;
        let mut state = self.state.lock().unwrap();
        if state
            .connections
            .iter()
            .any(|c| c.name == spec.name && &c.id != id)
        {
            return Err(CoreError::ConnectionNameTaken(spec.name));
        }
        let existing = state
            .connections
            .iter()
            .find(|c| &c.id == id)
            .ok_or(CoreError::ConnectionNotFound)?;
        if existing.kind() != spec.config.kind() {
            return Err(CoreError::KindChange);
        }
        inherit_oauth_token_secret_id(&existing.config, &mut spec.config);
        let broker_managed_oauth = existing.oauth.is_some()
            && matches!(
                &existing.config,
                ConnectionConfig::Api {
                    mcp_path: Some(_),
                    ..
                }
            );
        let byo_oauth = matches!(
            &existing.config,
            ConnectionConfig::Api { oauth: Some(_), .. }
        );
        if (broker_managed_oauth || byo_oauth) && existing.config != spec.config {
            let kind = if byo_oauth {
                "OAuth API"
            } else {
                "OAuth-managed MCP"
            };
            return Err(CoreError::InvalidConnectionConfig(format!(
                "{kind} tools can only be renamed; reconnect the tool to change \
                     its authentication, or add another tool to use a different destination"
            )));
        }
        let old_target = existing.target();
        let old_config = existing.config.clone();
        let secrets = validate_config_and_bind_secrets(&state, &spec)?;
        let mut next = state.clone();
        let conn = next
            .connections
            .iter_mut()
            .find(|c| &c.id == id)
            .expect("checked above");
        conn.name = spec.name;
        conn.config = spec.config;
        conn.secrets = secrets;
        conn.updated_at = Utc::now();
        let updated = conn.clone();
        let ssh_host_key_changed = matches!(
            (&old_config, &updated.config),
            (
                ConnectionConfig::Ssh {
                    host_key_fingerprint: old,
                    ..
                },
                ConnectionConfig::Ssh {
                    host_key_fingerprint: new,
                    ..
                }
            ) if old != new
        );
        let target_changed = updated.target() != old_target || ssh_host_key_changed;
        self.commit(&mut state, next)?;
        Ok((updated, target_changed))
    }

    /// Rename a connection without accepting or rewriting any capability
    /// fields. This is the metadata-only update path used when native
    /// authentication is intentionally skipped.
    pub fn rename_connection(&self, id: &Uuid, name: String) -> Result<Connection> {
        validate_connection_name(&name)?;
        let mut state = self.state.lock().unwrap();
        if state
            .connections
            .iter()
            .any(|connection| connection.name == name && &connection.id != id)
        {
            return Err(CoreError::ConnectionNameTaken(name));
        }
        let mut next = state.clone();
        let connection = next
            .connections
            .iter_mut()
            .find(|connection| &connection.id == id)
            .ok_or(CoreError::ConnectionNotFound)?;
        connection.name = name;
        connection.updated_at = Utc::now();
        let renamed = connection.clone();
        self.commit(&mut state, next)?;
        Ok(renamed)
    }

    /// Record which upstream account a connection's credential was last
    /// verified as (an MCP whoami answer). Display metadata only: it does
    /// not touch the capability config or `updated_at`, so it never trips
    /// the edit-conflict check or drops wirings.
    pub fn set_connection_account(&self, id: &Uuid, account: Option<String>) -> Result<Connection> {
        let mut state = self.state.lock().unwrap();
        let mut next = state.clone();
        let connection = next
            .connections
            .iter_mut()
            .find(|connection| &connection.id == id)
            .ok_or(CoreError::ConnectionNotFound)?;
        if connection.account == account {
            return Ok(connection.clone());
        }
        connection.account = account;
        let updated = connection.clone();
        self.commit(&mut state, next)?;
        Ok(updated)
    }

    /// Attach (or replace) a connection's OAuth refresh grant: the JSON
    /// payload lands in its own vault item — never listed as a user-visible
    /// secret — and the sealed index records the linkage plus the access
    /// token's expiry. Like `set_connection_account`, this is maintenance
    /// metadata: it does not touch the capability config or `updated_at`.
    pub fn set_connection_oauth(
        &self,
        id: &Uuid,
        payload: SecretValue,
        expires_at: Option<chrono::DateTime<Utc>>,
    ) -> Result<Connection> {
        let mut state = self.state.lock().unwrap();
        let mut next = state.clone();
        let connection = next
            .connections
            .iter_mut()
            .find(|connection| &connection.id == id)
            .ok_or(CoreError::ConnectionNotFound)?;
        let existing = connection.oauth.as_ref().map(|oauth| oauth.grant_id);
        let grant_id = existing.unwrap_or_else(Uuid::new_v4);
        connection.oauth = Some(crate::types::ConnectionOAuth {
            grant_id,
            expires_at,
        });
        let updated = connection.clone();
        let attrs = VaultAttrs {
            name: format!("{} OAuth grant", updated.name),
            created_at: Utc::now(),
        };
        self.vault.set(&grant_id, &attrs, &payload)?;
        drop(payload);
        if let Err(error) = self.persist(&next) {
            // A fresh grant item with no index linkage would be orphaned.
            if existing.is_none() {
                if let Err(rollback) = self.vault.delete(&grant_id) {
                    tracing::error!("failed to roll back vault item {grant_id}: {rollback}");
                }
            }
            return Err(error);
        }
        *state = next;
        Ok(updated)
    }

    /// Read a connection's OAuth refresh grant straight from the vault.
    ///
    /// This deliberately bypasses the re-auth-on-read confirmation gate:
    /// the grant is broker maintenance material, read only by the silent
    /// token refresh, and its contents leave the process solely toward the
    /// grant's own pinned https token endpoint — never to an agent, the
    /// webview, or the clipboard. There is no command that returns it.
    pub async fn connection_oauth_grant(&self, id: &Uuid) -> Result<SecretValue> {
        let grant_id = self
            .connection_by_id(id)?
            .oauth
            .ok_or(CoreError::SecretNotFound)?
            .grant_id;
        self.vault.get(&grant_id).await
    }

    /// Pin an SSH connection's host key, trust-on-first-use. Called by the
    /// SSH agent adapter after the user approves the first-connection trust
    /// prompt; the human factor is the approval decision itself, so there is
    /// deliberately no additional `confirm_action` gate here. Unlike
    /// `update_connection`, pinning does **not** drop the connection's
    /// standing rules: the fingerprint only moves empty → set, which narrows
    /// access rather than repointing it. The state lock plus commit make
    /// concurrent pins linearizable: exactly one caller observes `Pinned`.
    pub fn pin_ssh_host_key(
        &self,
        id: &Uuid,
        observed: &ssh_key::Fingerprint,
    ) -> Result<PinOutcome> {
        let mut state = self.state.lock().unwrap();
        let existing = state
            .connections
            .iter()
            .find(|c| &c.id == id)
            .ok_or(CoreError::ConnectionNotFound)?;
        let ConnectionConfig::Ssh {
            host_key_fingerprint,
            ..
        } = &existing.config
        else {
            return Err(CoreError::InvalidConnectionConfig(
                "not an ssh connection".into(),
            ));
        };
        if !host_key_fingerprint.is_empty() {
            let pinned = host_key_fingerprint
                .parse::<ssh_key::Fingerprint>()
                .map_err(|e| {
                    CoreError::InvalidConnectionConfig(format!(
                        "stored host key fingerprint is invalid: {e}"
                    ))
                })?;
            return Ok(PinOutcome::AlreadyPinned(pinned));
        }
        let mut next = state.clone();
        let conn = next
            .connections
            .iter_mut()
            .find(|c| &c.id == id)
            .expect("checked above");
        let ConnectionConfig::Ssh {
            host_key_fingerprint,
            ..
        } = &mut conn.config
        else {
            unreachable!("kind checked above");
        };
        *host_key_fingerprint = observed.to_string();
        // Deliberately *not* touching `updated_at`. That field is the
        // "was this connection retargeted?" version every execution re-checks
        // at its boundary, and bumping it here made a first-connection pin
        // look like a retarget: an open racing the pin was refused with
        // `denied_by_policy`, as though the user had repointed the tool.
        // Learning the host key is the connection converging on what it
        // already described, not a change of destination or credential.
        self.commit(&mut state, next)?;
        Ok(PinOutcome::Pinned(*observed))
    }

    /// Delete a connection. The caller (policy layer) deletes its rules,
    /// rules die with their connection.
    pub fn delete_connection(&self, id: &Uuid) -> Result<Connection> {
        let mut state = self.state.lock().unwrap();
        let pos = state
            .connections
            .iter()
            .position(|c| &c.id == id)
            .ok_or(CoreError::ConnectionNotFound)?;
        let mut next = state.clone();
        let conn = next.connections.remove(pos);
        self.commit(&mut state, next)?;
        // The OAuth refresh grant is not a listed secret; it dies with the
        // connection. Best-effort: a stale vault item cannot be reached
        // again once the index linkage is gone.
        if let Some(oauth) = &conn.oauth {
            if let Err(error) = self.vault.delete(&oauth.grant_id) {
                tracing::warn!(
                    "could not delete OAuth grant {} for removed connection {}: {error}",
                    oauth.grant_id,
                    conn.name
                );
            }
        }
        Ok(conn)
    }

    /// Persist a new order for the connection list. `ordered_ids` is the
    /// desired front-to-back order; connections it names move into that order,
    /// and any current connection it omits (a tool added or dropped in another
    /// window while the user was dragging) keeps its relative position at the
    /// end. Unknown ids are ignored. This is display order only — no
    /// capability, secret binding, or `updated_at` changes — so it never trips
    /// the edit-conflict guard. Returns the reordered list.
    pub fn reorder_connections(&self, ordered_ids: &[Uuid]) -> Result<Vec<Connection>> {
        let mut state = self.state.lock().unwrap();
        let mut next = state.clone();
        let mut remaining = std::mem::take(&mut next.connections);
        let mut ordered = Vec::with_capacity(remaining.len());
        for id in ordered_ids {
            if let Some(pos) = remaining.iter().position(|c| &c.id == id) {
                ordered.push(remaining.remove(pos));
            }
        }
        // Leftovers keep their prior relative order behind the named ones.
        ordered.append(&mut remaining);
        // A no-op reorder must not rewrite the index (nor wake listeners).
        if ordered == state.connections {
            return Ok(ordered);
        }
        next.connections = ordered;
        self.commit(&mut state, next)?;
        Ok(state.connections.clone())
    }

    /* ------------------------------ settings ------------------------------ */

    pub fn settings(&self) -> Settings {
        self.state.lock().unwrap().settings()
    }

    pub fn set_reauth_on_read(&self, on: bool) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        let mut settings = state.settings();
        settings.reauth_on_read = on;
        let mut next = state.clone();
        next.settings = Some(settings);
        self.commit(&mut state, next)
    }

    pub fn set_menu_bar_hides_dock(&self, on: bool) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        let mut settings = state.settings();
        settings.menu_bar_hides_dock = on;
        let mut next = state.clone();
        next.settings = Some(settings);
        self.commit(&mut state, next)
    }

    /// Unvalidated persistence; the broker's UI command restricts the value
    /// to the offered choices.
    pub fn set_presence_window_secs(&self, secs: u64) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        let mut settings = state.settings();
        settings.presence_window_secs = secs;
        let mut next = state.clone();
        next.settings = Some(settings);
        self.commit(&mut state, next)
    }
}

impl crate::policy::AccessGenerationStore for Store {
    fn access_generation(&self) -> u64 {
        self.state.lock().unwrap().access_generation
    }

    fn advance_access_generation(&self) -> Result<u64> {
        let mut state = self.state.lock().unwrap();
        let mut next = state.clone();
        next.access_generation = state
            .access_generation
            .checked_add(1)
            .ok_or_else(|| CoreError::InvalidSetting("access generation overflow".into()))?;
        let generation = next.access_generation;
        self.commit(&mut state, next)?;
        Ok(generation)
    }
}

fn migrate_legacy_pg_ca_bundle(state: &mut IndexState) -> bool {
    let Some(path) = state
        .settings
        .as_mut()
        .and_then(|settings| settings.legacy_pg_trusted_ca_bundle_path.take())
    else {
        return false;
    };
    for connection in &mut state.connections {
        if let ConnectionConfig::Pg {
            trusted_ca_bundle_path,
            ..
        } = &mut connection.config
        {
            if trusted_ca_bundle_path.is_none() {
                *trusted_ca_bundle_path = Some(path.clone());
            }
        }
    }
    true
}

fn migrate_oauth_token_secret_ids(state: &mut IndexState) -> bool {
    let mut changed = false;
    for connection in &mut state.connections {
        let ConnectionConfig::Api {
            oauth: Some(oauth), ..
        } = &mut connection.config
        else {
            continue;
        };
        if oauth.token_secret_id.is_none() && connection.secrets.len() == 1 {
            oauth.token_secret_id = Some(connection.secrets[0]);
            changed = true;
        }
    }
    changed
}

fn prepare_connection(state: &IndexState, mut spec: ConnectionSpec) -> Result<Connection> {
    validate_connection_name(&spec.name)?;
    if state.connections.iter().any(|conn| conn.name == spec.name) {
        return Err(CoreError::ConnectionNameTaken(spec.name));
    }
    let secrets = validate_config_and_bind_secrets(state, &spec)?;
    let preferred = (spec.secrets.len() == 1).then(|| spec.secrets[0]);
    pin_oauth_token_secret(&mut spec.config, &secrets, preferred)?;
    let now = Utc::now();
    Ok(Connection {
        id: Uuid::new_v4(),
        name: spec.name,
        config: spec.config,
        secrets,
        account: None,
        oauth: None,
        created_at: now,
        updated_at: now,
    })
}

fn prepare_connection_with_secret(
    state: &IndexState,
    secret_name: &str,
    mut spec: ConnectionSpec,
) -> Result<(SecretMeta, Connection)> {
    if !is_valid_secret_name(secret_name) {
        return Err(CoreError::InvalidSecretName(secret_name.to_string()));
    }
    validate_connection_name(&spec.name)?;
    if state
        .secrets
        .iter()
        .any(|secret| secret.name == secret_name)
    {
        return Err(CoreError::SecretNameTaken(secret_name.to_string()));
    }
    if state.connections.iter().any(|conn| conn.name == spec.name) {
        return Err(CoreError::ConnectionNameTaken(spec.name));
    }

    let now = Utc::now();
    let meta = SecretMeta {
        id: Uuid::new_v4(),
        name: secret_name.to_string(),
        created_at: now,
        updated_at: now,
    };
    let mut next = state.clone();
    next.secrets.push(meta.clone());
    if spec.config.kind() != ConnectionKind::Api {
        spec.secrets = vec![meta.id];
    }
    let secrets = validate_config_and_bind_secrets(&next, &spec)?;
    if !secrets.contains(&meta.id) {
        return Err(CoreError::InvalidConnectionConfig(
            "the new credential is not referenced by this connection".into(),
        ));
    }
    pin_oauth_token_secret(&mut spec.config, &secrets, Some(meta.id))?;
    let conn = Connection {
        id: Uuid::new_v4(),
        name: spec.name,
        config: spec.config,
        secrets,
        account: None,
        oauth: None,
        created_at: now,
        updated_at: now,
    };
    Ok((meta, conn))
}

fn validate_connection_name(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name.len() <= 64
        && name.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(c, ' ' | '-' | '_' | '(' | ')' | '@' | '.' | ':' | '[' | ']')
        })
        && name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric())
        && !name.ends_with(' ');
    if ok {
        Ok(())
    } else {
        Err(CoreError::InvalidConnectionName(name.to_string()))
    }
}

/// Validate the type-specific config and resolve the connection's bound
/// secrets: API secret lists are derived from the template's refs; pg/ssh
/// bind at most one secret.
fn validate_config_and_bind_secrets(
    state: &IndexState,
    spec: &ConnectionSpec,
) -> Result<Vec<Uuid>> {
    let find_by_name = |name: &str| -> Result<Uuid> {
        state
            .secrets
            .iter()
            .find(|s| s.name == name)
            .map(|s| s.id)
            .ok_or_else(|| CoreError::UnknownTemplateRef(name.to_string()))
    };
    match &spec.config {
        ConnectionConfig::Api {
            host,
            scheme,
            port: _,
            trusted_ca_bundle_path,
            template,
            mcp_path,
            oauth,
        } => {
            if host.is_empty() || host.contains('/') || host.contains('@') || host.contains(':') {
                return Err(CoreError::InvalidConnectionField {
                    field: ConnectionField::Host,
                    message: "Enter only the hostname, without a user, port, scheme, or path"
                        .into(),
                });
            }
            if scheme != "https" && scheme != "http" {
                return Err(CoreError::InvalidConnectionField {
                    field: ConnectionField::Scheme,
                    message: "Use http:// or https://".into(),
                });
            }
            if trusted_ca_bundle_path
                .as_deref()
                .is_some_and(|path| path.trim().is_empty())
            {
                return Err(CoreError::InvalidConnectionField {
                    field: ConnectionField::Url,
                    message: "The trusted CA bundle path cannot be blank".into(),
                });
            }
            if let Some(path) = mcp_path {
                if !path.starts_with('/') {
                    return Err(CoreError::InvalidConnectionField {
                        field: ConnectionField::Url,
                        message: "The MCP path must start with / (for example /mcp)".into(),
                    });
                }
            }
            if mcp_path.is_some() && oauth.is_some() {
                return Err(CoreError::InvalidConnectionField {
                    field: ConnectionField::Url,
                    message: "An MCP path cannot be combined with API OAuth; use the MCP sign-in flow instead"
                        .into(),
                });
            }
            if let Some(oauth) = oauth {
                // https, or plain http to a loopback host (dev/test
                // providers) — the same rule the OAuth module enforces.
                let https_url = |value: &str| {
                    url::Url::parse(value).is_ok_and(|url| {
                        url.scheme() == "https"
                            || (url.scheme() == "http"
                                && matches!(
                                    url.host_str(),
                                    Some("127.0.0.1") | Some("localhost") | Some("[::1]")
                                ))
                    })
                };
                if !https_url(&oauth.auth_url) || !https_url(&oauth.token_url) {
                    return Err(CoreError::InvalidConnectionField {
                        field: ConnectionField::Url,
                        message: "OAuth endpoints must be complete https:// URLs".into(),
                    });
                }
                if oauth.client_id.trim().is_empty() {
                    return Err(CoreError::InvalidConnectionField {
                        field: ConnectionField::Template,
                        message: "The OAuth client ID is required".into(),
                    });
                }
                if template.trim().is_empty() {
                    return Err(CoreError::InvalidConnectionField {
                        field: ConnectionField::Template,
                        message: "An OAuth connection must reference its token credential".into(),
                    });
                }
            }
            // An empty template is a credential-less connection (e.g. a public
            // MCP server): nothing is injected, so it binds no secrets.
            if template.trim().is_empty() {
                return Ok(Vec::new());
            }
            let parsed = Template::parse(template)?;
            let refs = parsed.refs();
            if refs.is_empty() {
                return Err(CoreError::InvalidConnectionField {
                    field: ConnectionField::Template,
                    message: "Add a saved credential reference such as {{API_KEY}}".into(),
                });
            }
            refs.iter().map(|name| find_by_name(name)).collect()
        }
        ConnectionConfig::Pg {
            host,
            port,
            dbname,
            user,
            ..
        } => {
            if host.is_empty() || dbname.is_empty() || user.is_empty() || *port == 0 {
                let (field, message) = if host.is_empty() {
                    (ConnectionField::Host, "Host is required")
                } else if *port == 0 {
                    (ConnectionField::Port, "Port must be 1–65535")
                } else if dbname.is_empty() {
                    (ConnectionField::Database, "Database is required")
                } else {
                    (ConnectionField::User, "User is required")
                };
                return Err(CoreError::InvalidConnectionField {
                    field,
                    message: message.into(),
                });
            }
            bind_optional_secret(state, spec)
        }
        ConnectionConfig::Ssh {
            destination,
            host,
            port,
            user,
            host_key_fingerprint,
        } => {
            if destination.as_ref().is_some_and(|value| {
                value.is_empty()
                    || value.contains('/')
                    || value.contains(':')
                    || value.chars().any(char::is_whitespace)
                    || value.matches('@').count() > 1
            }) {
                return Err(CoreError::InvalidConnectionConfig(
                    "invalid SSH destination alias".into(),
                ));
            }
            if host.is_empty() || host.contains('/') || host.contains('@') || host.contains(':') {
                return Err(CoreError::InvalidConnectionField {
                    field: ConnectionField::Host,
                    message: "Enter only the hostname, without a user, port, scheme, or path"
                        .into(),
                });
            }
            if user.is_empty() || *port == 0 {
                let (field, message) = if *port == 0 {
                    (ConnectionField::Port, "Port must be 1–65535")
                } else {
                    (ConnectionField::User, "User is required")
                };
                return Err(CoreError::InvalidConnectionField {
                    field,
                    message: message.into(),
                });
            }
            // Empty is a valid state: unpinned, trusted on first use via
            // `pin_ssh_host_key` at the first agent session-bind.
            if !host_key_fingerprint.is_empty() {
                host_key_fingerprint
                    .parse::<ssh_key::Fingerprint>()
                    .map_err(|_| CoreError::InvalidConnectionField {
                        field: ConnectionField::HostKeyFingerprint,
                        message: "Enter an OpenSSH SHA-256 or SHA-512 fingerprint".into(),
                    })?;
            }
            bind_optional_secret(state, spec)
        }
    }
}

fn inherit_oauth_token_secret_id(existing: &ConnectionConfig, incoming: &mut ConnectionConfig) {
    let (
        ConnectionConfig::Api {
            oauth: Some(existing),
            ..
        },
        ConnectionConfig::Api {
            oauth: Some(incoming),
            ..
        },
    ) = (existing, incoming)
    else {
        return;
    };
    if incoming.token_secret_id.is_none() {
        incoming.token_secret_id = existing.token_secret_id;
    }
}

fn pin_oauth_token_secret(
    config: &mut ConnectionConfig,
    bound_secrets: &[Uuid],
    preferred: Option<Uuid>,
) -> Result<()> {
    let ConnectionConfig::Api {
        oauth: Some(oauth), ..
    } = config
    else {
        return Ok(());
    };
    let token_secret_id = oauth
        .token_secret_id
        .or(preferred.filter(|id| bound_secrets.contains(id)))
        .or_else(|| (bound_secrets.len() == 1).then_some(bound_secrets[0]))
        .ok_or_else(|| {
            CoreError::InvalidConnectionConfig(
                "the OAuth token credential is ambiguous; reconnect this tool to bind it explicitly"
                    .into(),
            )
        })?;
    if !bound_secrets.contains(&token_secret_id) {
        return Err(CoreError::InvalidConnectionConfig(
            "the OAuth token credential is not referenced by this connection".into(),
        ));
    }
    oauth.token_secret_id = Some(token_secret_id);
    Ok(())
}

fn bind_optional_secret(state: &IndexState, spec: &ConnectionSpec) -> Result<Vec<Uuid>> {
    let kind = match spec.config.kind() {
        ConnectionKind::Pg => "postgres",
        ConnectionKind::Ssh => "ssh",
        ConnectionKind::Api => unreachable!(),
    };
    if spec.secrets.len() > 1 {
        return Err(CoreError::WrongSecretCount { kind });
    }
    if let Some(id) = spec.secrets.first() {
        if !state.secrets.iter().any(|s| &s.id == id) {
            return Err(CoreError::SecretNotFound);
        }
    }
    Ok(spec.secrets.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::PgSslMode;
    use crate::vault::MemoryVault;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use zeroize::Zeroizing;

    const SSH_HOST_FP: &str = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const SSH_HOST_FP_ALT: &str = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE";

    #[test]
    fn presence_grant_cannot_slide_past_twelve_hours() {
        let start = std::time::Instant::now();
        let wall_start = Utc::now();
        let window = std::time::Duration::from_secs(2 * 60 * 60);
        let mut grant = PresenceGrant::new(start, wall_start, window);

        for hour in 1..12 {
            assert!(grant.ride(
                start + std::time::Duration::from_secs(hour * 60 * 60),
                wall_start + chrono::Duration::hours(hour as i64),
                window,
            ));
        }
        assert_eq!(grant.absolute_until, start + PRESENCE_ABSOLUTE_MAX);
        assert_eq!(grant.idle_until, grant.absolute_until);
        assert!(!grant.ride(grant.absolute_until, grant.absolute_wall_until, window));
    }

    #[test]
    fn reanchoring_never_resets_the_absolute_deadline() {
        let start = std::time::Instant::now();
        let wall_start = Utc::now();
        let mut grant =
            PresenceGrant::new(start, wall_start, std::time::Duration::from_secs(60 * 60));
        let absolute = grant.absolute_until;
        let wall_absolute = grant.absolute_wall_until;
        grant.reanchor(
            start + std::time::Duration::from_secs(30 * 60),
            wall_start + chrono::Duration::minutes(30),
            std::time::Duration::from_secs(2 * 60 * 60),
        );
        assert_eq!(grant.absolute_until, absolute);
        assert_eq!(grant.absolute_wall_until, wall_absolute);
    }

    #[test]
    fn presence_grant_expires_when_wall_clock_advances_during_suspend() {
        let start = std::time::Instant::now();
        let wall_start = Utc::now();
        let window = std::time::Duration::from_secs(15 * 60);
        let mut grant = PresenceGrant::new(start, wall_start, window);

        assert!(!grant.ride(start, wall_start + chrono::Duration::days(1), window));
    }

    struct ReadGate {
        allow: AtomicBool,
        calls: AtomicUsize,
    }

    impl BrokerEvents for ReadGate {
        fn confirm_secret_read(&self, _secret: &SecretMeta) -> bool {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.allow.load(Ordering::SeqCst)
        }
    }

    async fn store() -> (Store, Arc<MemoryVault>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let vault = Arc::new(MemoryVault::new());
        let store = Store::open(Paths::under(dir.path()), vault.clone())
            .await
            .unwrap();
        (store, vault, dir)
    }

    fn val(s: &str) -> SecretValue {
        Zeroizing::new(s.to_string())
    }

    fn api_spec(name: &str, host: &str, template: &str) -> ConnectionSpec {
        ConnectionSpec {
            name: name.into(),
            config: ConnectionConfig::Api {
                host: host.into(),
                scheme: "https".into(),
                port: None,
                trusted_ca_bundle_path: None,
                template: template.into(),

                mcp_path: None,
                oauth: None,
            },
            secrets: vec![],
        }
    }

    #[tokio::test]
    async fn add_list_and_persist_secrets() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Arc::new(MemoryVault::new());
        {
            let store = Store::open(Paths::under(dir.path()), vault.clone())
                .await
                .unwrap();
            store
                .add_secret("GITHUB_API_KEY", val("ghp_secret"))
                .unwrap();
            store.add_secret("DATABASE_PASSWORD", val("pg-pw")).unwrap();
            assert_eq!(
                store
                    .add_secret("GITHUB_API_KEY", val("dupe"))
                    .unwrap_err()
                    .to_string(),
                CoreError::SecretNameTaken("GITHUB_API_KEY".into()).to_string()
            );
        }
        // Reopen: index survives; values stay in the vault.
        let store = Store::open(Paths::under(dir.path()), vault.clone())
            .await
            .unwrap();
        let names: Vec<_> = store.list_secrets().into_iter().map(|s| s.name).collect();
        assert_eq!(names, ["DATABASE_PASSWORD", "GITHUB_API_KEY"]);
        // Two user secrets plus the integrity key.
        assert_eq!(vault.len(), 3);
        let gh = store.secret_by_name("GITHUB_API_KEY").unwrap();
        assert_eq!(&*store.secret_value(&gh.id).await.unwrap(), "ghp_secret");
    }

    #[tokio::test]
    async fn add_connection_with_secret_is_atomic_and_binds_the_new_secret() {
        let (store, vault, _dir) = store().await;
        let initial_vault_len = vault.len();
        let (secret, connection) = store
            .add_connection_with_secret(
                "DATABASE_PASSWORD",
                val("pg-pw"),
                ConnectionSpec {
                    name: "prod-db".into(),
                    config: ConnectionConfig::Pg {
                        host: "db.example.com".into(),
                        port: 5432,
                        dbname: "app".into(),
                        user: "app".into(),
                        sslmode: PgSslMode::Require,
                        trusted_ca_bundle_path: None,
                    },
                    secrets: vec![],
                },
            )
            .unwrap();
        assert_eq!(connection.secrets, vec![secret.id]);
        assert_eq!(vault.len(), initial_vault_len + 1);
        assert_eq!(&*store.secret_value(&secret.id).await.unwrap(), "pg-pw");

        let (api_secret, api_connection) = store
            .add_connection_with_secret(
                "API_TOKEN",
                val("api-token"),
                api_spec(
                    "tool-api",
                    "api.example.com",
                    "Authorization: Bearer {{API_TOKEN}}",
                ),
            )
            .unwrap();
        assert_eq!(api_connection.secrets, vec![api_secret.id]);

        store.add_secret("OTHER", val("existing")).unwrap();
        let before_invalid = vault.len();
        let error = store
            .add_connection_with_secret(
                "ORPHAN_TOKEN",
                val("should-not-persist"),
                api_spec(
                    "broken",
                    "api.example.com",
                    "Authorization: Bearer {{OTHER}}",
                ),
            )
            .unwrap_err();
        assert!(matches!(error, CoreError::InvalidConnectionConfig(_)));
        assert!(store.secret_by_name("ORPHAN_TOKEN").is_none());
        assert_eq!(vault.len(), before_invalid);
    }

    #[tokio::test]
    async fn reveal_prefix_is_capped() {
        let (store, _, _dir) = store().await;
        let meta = store
            .add_secret("GITHUB_API_KEY", val("ghp_9aXf2Qe7LmNoP3demoToken41c"))
            .unwrap();
        assert_eq!(
            store.reveal_secret_prefix(&meta.id).await.unwrap(),
            "ghp_9a…"
        );
        let short = store.add_secret("SHORT", val("abcd")).unwrap();
        assert_eq!(store.reveal_secret_prefix(&short.id).await.unwrap(), "ab…");
    }

    #[tokio::test]
    async fn secret_reads_require_reauth_when_enabled() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Arc::new(MemoryVault::new());
        let gate = Arc::new(ReadGate {
            allow: AtomicBool::new(false),
            calls: AtomicUsize::new(0),
        });
        let integrity = Arc::new(StateIntegrity::open(&*vault).await.unwrap());
        let store =
            Store::open_with_events(Paths::under(dir.path()), vault, gate.clone(), integrity)
                .unwrap();
        let meta = store
            .add_secret("GITHUB_API_KEY", val("ghp_secret"))
            .unwrap();

        assert!(store.settings().reauth_on_read);
        assert!(matches!(
            store.secret_value(&meta.id).await.unwrap_err(),
            CoreError::SecretReadNotAuthenticated
        ));
        assert_eq!(gate.calls.load(Ordering::SeqCst), 1);

        gate.allow.store(true, Ordering::SeqCst);
        assert_eq!(
            &*store.secret_value_by_name("GITHUB_API_KEY").await.unwrap(),
            "ghp_secret"
        );
        assert_eq!(gate.calls.load(Ordering::SeqCst), 2);

        store.set_reauth_on_read(false).unwrap();
        gate.allow.store(false, Ordering::SeqCst);
        assert_eq!(&*store.secret_value(&meta.id).await.unwrap(), "ghp_secret");
        assert_eq!(gate.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn invalid_names_rejected() {
        let (store, _, _dir) = store().await;
        assert!(store.add_secret("9BAD", val("x")).is_err());
        assert!(store.add_secret("has space", val("x")).is_err());
        assert!(store.add_secret("", val("x")).is_err());
    }

    #[test]
    fn connection_names_allow_internal_spaces() {
        assert!(validate_connection_name("Internal API").is_ok());
        assert!(validate_connection_name("Production Database 2").is_ok());
        assert!(validate_connection_name("two  spaces").is_ok());
        assert!(validate_connection_name("SSH (root@localhost:7878)").is_ok());
        assert!(validate_connection_name("Postgres (app@db.example.com:5432)").is_ok());

        for invalid in [
            " leading",
            "trailing ",
            "has\ttab",
            "has\nnewline",
            "-starts-with-hyphen",
            "_starts_with_underscore",
        ] {
            assert!(
                validate_connection_name(invalid).is_err(),
                "accepted invalid service name {invalid:?}"
            );
        }
    }

    #[tokio::test]
    async fn connection_names_with_spaces_round_trip() {
        let (store, _, _dir) = store().await;
        let token = store.add_secret("STREAM_TOKEN", val("t")).unwrap();
        let connection = store
            .add_connection(ConnectionSpec {
                name: "Market Feed".into(),
                config: ConnectionConfig::Api {
                    host: "stream.example.com".into(),
                    scheme: "https".into(),
                    port: None,
                    trusted_ca_bundle_path: None,
                    template: "Authorization: Bearer {{STREAM_TOKEN}}".into(),
                    mcp_path: None,
                    oauth: None,
                },
                secrets: vec![token.id],
            })
            .unwrap();

        assert_eq!(
            store.connection_by_name("Market Feed").unwrap().id,
            connection.id
        );
        let renamed = store
            .rename_connection(&connection.id, "Production Market Feed".into())
            .unwrap();
        assert_eq!(renamed.name, "Production Market Feed");
        assert!(store.connection_by_name("Market Feed").is_none());
        assert_eq!(
            store
                .connection_by_name("Production Market Feed")
                .unwrap()
                .id,
            connection.id
        );
    }

    #[tokio::test]
    async fn rename_rewrites_templates_atomically() {
        let (store, _, _dir) = store().await;
        let user = store.add_secret("SERVICE_USER", val("svc")).unwrap();
        store.add_secret("SERVICE_PASSWORD", val("pw")).unwrap();
        store
            .add_connection(api_spec(
                "internal-api",
                "internal.aka.com",
                "Authorization: Basic {{base64(SERVICE_USER \":\" SERVICE_PASSWORD)}}",
            ))
            .unwrap();
        let (meta, rewritten) = store.rename_secret(&user.id, "SVC_USER").unwrap();
        assert_eq!(meta.name, "SVC_USER");
        assert_eq!(rewritten, 1);
        let conn = store.connection_by_name("internal-api").unwrap();
        match &conn.config {
            ConnectionConfig::Api { template, .. } => assert_eq!(
                template,
                "Authorization: Basic {{base64(SVC_USER \":\" SERVICE_PASSWORD)}}"
            ),
            _ => unreachable!(),
        }
        // Secrets binding still resolves.
        assert_eq!(conn.secrets.len(), 2);
    }

    #[tokio::test]
    async fn rename_collision_rejected() {
        let (store, _, _dir) = store().await;
        let a = store.add_secret("A_KEY", val("a")).unwrap();
        store.add_secret("B_KEY", val("b")).unwrap();
        assert!(matches!(
            store.rename_secret(&a.id, "B_KEY").unwrap_err(),
            CoreError::SecretNameTaken(_)
        ));
    }

    #[tokio::test]
    async fn delete_secret_in_use_is_blocked() {
        let (store, vault, _dir) = store().await;
        let key = store.add_secret("GITHUB_API_KEY", val("ghp")).unwrap();
        store
            .add_connection(api_spec(
                "github",
                "api.github.com",
                "Authorization: Bearer {{GITHUB_API_KEY}}",
            ))
            .unwrap();
        match store.delete_secret(&key.id).unwrap_err() {
            CoreError::SecretInUse(users) => assert_eq!(users, ["github"]),
            other => panic!("unexpected: {other}"),
        }
        // Deleting the connection unblocks the secret; only the
        // integrity key remains in the vault afterwards.
        let conn = store.connection_by_name("github").unwrap();
        store.delete_connection(&conn.id).unwrap();
        store.delete_secret(&key.id).unwrap();
        assert_eq!(vault.len(), 1);
    }

    #[tokio::test]
    async fn api_connection_derives_secrets_from_template() {
        let (store, _, _dir) = store().await;
        store.add_secret("SERVICE_USER", val("u")).unwrap();
        store.add_secret("SERVICE_PASSWORD", val("p")).unwrap();
        let conn = store
            .add_connection(api_spec(
                "internal-api",
                "internal.aka.com",
                "Authorization: Basic {{base64(SERVICE_USER \":\" SERVICE_PASSWORD)}}",
            ))
            .unwrap();
        assert_eq!(conn.secrets.len(), 2);

        // Unknown ref is rejected.
        assert!(matches!(
            store
                .add_connection(api_spec("x", "x.example.com", "Bearer {{NOPE}}"))
                .unwrap_err(),
            CoreError::UnknownTemplateRef(_)
        ));
    }

    #[tokio::test]
    async fn reorder_connections_permutes_persists_and_is_lenient() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Arc::new(MemoryVault::new());
        let (a, b, c);
        {
            let store = Store::open(Paths::under(dir.path()), vault.clone())
                .await
                .unwrap();
            a = store
                .add_connection(api_spec("alpha", "a.example.com", ""))
                .unwrap()
                .id;
            b = store
                .add_connection(api_spec("bravo", "b.example.com", ""))
                .unwrap()
                .id;
            c = store
                .add_connection(api_spec("charlie", "c.example.com", ""))
                .unwrap()
                .id;
            // Insertion order until reordered.
            let ids: Vec<_> = store
                .list_connections()
                .iter()
                .map(|conn| conn.id)
                .collect();
            assert_eq!(ids, vec![a, b, c]);

            // A full permutation is applied in the given order.
            store.reorder_connections(&[c, a, b]).unwrap();
            let ids: Vec<_> = store
                .list_connections()
                .iter()
                .map(|conn| conn.id)
                .collect();
            assert_eq!(ids, vec![c, a, b]);

            // A partial list moves the named ids to the front; omitted ones keep
            // their relative order behind them, and an unknown id is ignored.
            let ghost = Uuid::new_v4();
            store.reorder_connections(&[ghost, b]).unwrap();
            let ids: Vec<_> = store
                .list_connections()
                .iter()
                .map(|conn| conn.id)
                .collect();
            assert_eq!(ids, vec![b, c, a]);
        }

        // Order survives a reopen of the index.
        let store = Store::open(Paths::under(dir.path()), vault.clone())
            .await
            .unwrap();
        let ids: Vec<_> = store
            .list_connections()
            .iter()
            .map(|conn| conn.id)
            .collect();
        assert_eq!(ids, vec![b, c, a]);
    }

    #[tokio::test]
    async fn api_connection_may_have_no_credential() {
        let (store, _, _dir) = store().await;
        // An empty template is a credential-less connection (e.g. a public MCP
        // server): it saves and binds no secrets.
        let conn = store
            .add_connection(api_spec("public-mcp", "mcp.example.com", ""))
            .unwrap();
        assert!(conn.secrets.is_empty());

        // Whitespace-only is treated the same way.
        let blank = store
            .add_connection(api_spec("blank-tmpl", "blank.example.com", "  "))
            .unwrap();
        assert!(blank.secrets.is_empty());

        // A non-empty template with no credential reference is still rejected.
        assert!(matches!(
            store
                .add_connection(api_spec(
                    "x",
                    "x.example.com",
                    "Authorization: Bearer static"
                ))
                .unwrap_err(),
            CoreError::InvalidConnectionField {
                field: ConnectionField::Template,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn pg_allows_no_secret_but_rejects_multiple() {
        let (store, _, _dir) = store().await;
        let pw = store.add_secret("DATABASE_PASSWORD", val("pw")).unwrap();
        let conn = store
            .add_connection(ConnectionSpec {
                name: "prod-db".into(),
                config: ConnectionConfig::Pg {
                    host: "db.internal.aka.com".into(),
                    port: 5432,
                    dbname: "app_production".into(),
                    user: "app".into(),
                    sslmode: PgSslMode::Require,
                    trusted_ca_bundle_path: None,
                },
                secrets: vec![pw.id],
            })
            .unwrap();
        assert_eq!(conn.target(), "app@db.internal.aka.com:5432/app_production");

        let passwordless = store
            .add_connection(ConnectionSpec {
                name: "passwordless".into(),
                config: ConnectionConfig::Pg {
                    host: "h".into(),
                    port: 5432,
                    dbname: "d".into(),
                    user: "u".into(),
                    sslmode: PgSslMode::Prefer,
                    trusted_ca_bundle_path: None,
                },
                secrets: vec![],
            })
            .expect("postgres may use trust or certificate authentication");
        assert!(passwordless.secrets.is_empty());

        let other = store.add_secret("OTHER_PASSWORD", val("pw2")).unwrap();
        assert!(matches!(
            store
                .add_connection(ConnectionSpec {
                    name: "too-many".into(),
                    config: ConnectionConfig::Pg {
                        host: "h".into(),
                        port: 5432,
                        dbname: "d".into(),
                        user: "u".into(),
                        sslmode: PgSslMode::Prefer,
                        trusted_ca_bundle_path: None,
                    },
                    secrets: vec![pw.id, other.id],
                })
                .unwrap_err(),
            CoreError::WrongSecretCount { .. }
        ));
    }

    #[tokio::test]
    async fn ssh_allows_no_secret_and_validates_host() {
        let (store, _, _dir) = store().await;
        let key = store
            .add_secret(
                "DEPLOY_SSH_KEY",
                val("-----BEGIN OPENSSH PRIVATE KEY-----…"),
            )
            .unwrap();
        let conn = store
            .add_connection(ConnectionSpec {
                name: "prod-ssh".into(),
                config: ConnectionConfig::Ssh {
                    destination: None,
                    host: "prod.example.com".into(),
                    port: 22,
                    user: "deploy".into(),
                    host_key_fingerprint: SSH_HOST_FP.into(),
                },
                secrets: vec![key.id],
            })
            .unwrap();
        assert_eq!(conn.target(), "deploy@prod.example.com");

        let (_, changed) = store
            .update_connection(
                &conn.id,
                ConnectionSpec {
                    name: "prod-ssh".into(),
                    config: ConnectionConfig::Ssh {
                        destination: None,
                        host: "prod.example.com".into(),
                        port: 22,
                        user: "deploy".into(),
                        host_key_fingerprint: SSH_HOST_FP_ALT.into(),
                    },
                    secrets: vec![key.id],
                },
            )
            .unwrap();
        assert!(changed, "changing the pinned host key must reset rules");

        // Empty is a valid unpinned state (trusted on first use)…
        store
            .add_connection(ConnectionSpec {
                name: "unpinned-host-key".into(),
                config: ConnectionConfig::Ssh {
                    destination: None,
                    host: "h.example.com".into(),
                    port: 22,
                    user: "u".into(),
                    host_key_fingerprint: String::new(),
                },
                secrets: vec![key.id],
            })
            .expect("empty fingerprint saves as unpinned");
        // …but a malformed non-empty fingerprint is still rejected.
        assert!(matches!(
            store
                .add_connection(ConnectionSpec {
                    name: "bad-host-key".into(),
                    config: ConnectionConfig::Ssh {
                        destination: None,
                        host: "h.example.com".into(),
                        port: 22,
                        user: "u".into(),
                        host_key_fingerprint: "not-a-fingerprint".into(),
                    },
                    secrets: vec![key.id],
                })
                .unwrap_err(),
            CoreError::InvalidConnectionField {
                field: ConnectionField::HostKeyFingerprint,
                ..
            }
        ));

        let passwordless = store
            .add_connection(ConnectionSpec {
                name: "no-secret".into(),
                config: ConnectionConfig::Ssh {
                    destination: None,
                    host: "h.example.com".into(),
                    port: 22,
                    user: "u".into(),
                    host_key_fingerprint: SSH_HOST_FP.into(),
                },
                secrets: vec![],
            })
            .expect("SSH may authenticate without a brokered private key");
        assert!(passwordless.secrets.is_empty());
        // Host must be a bare hostname; user is required.
        for (host, user) in [
            ("prod.example.com:22", "deploy"),
            ("deploy@prod.example.com", "deploy"),
            ("", "deploy"),
            ("prod.example.com", ""),
        ] {
            assert!(matches!(
                store
                    .add_connection(ConnectionSpec {
                        name: "bad".into(),
                        config: ConnectionConfig::Ssh {
                            destination: None,
                            host: host.into(),
                            port: 22,
                            user: user.into(),
                            host_key_fingerprint: SSH_HOST_FP.into(),
                        },
                        secrets: vec![key.id],
                    })
                    .unwrap_err(),
                CoreError::InvalidConnectionField { .. }
            ));
        }
    }

    #[tokio::test]
    async fn oauth_specs_validate_endpoints_and_client_id() {
        let (store, _, _dir) = store().await;
        store.add_secret("SLACK_OAUTH_TOKEN", val("{}")).unwrap();
        let spec = |auth: &str, token: &str, client: &str| ConnectionSpec {
            name: "slack".into(),
            config: ConnectionConfig::Api {
                host: "slack.com".into(),
                scheme: "https".into(),
                port: None,
                trusted_ca_bundle_path: None,
                template: "Authorization: Bearer {{SLACK_OAUTH_TOKEN}}".into(),
                mcp_path: None,
                oauth: Some(crate::types::OAuthSpec {
                    auth_url: auth.into(),
                    token_url: token.into(),
                    client_id: client.into(),
                    scopes: vec!["chat:write".into()],
                    extra_auth_params: vec![],
                    token_secret_id: None,
                }),
            },
            secrets: vec![],
        };
        // Plain-http endpoints and a blank client id are refused…
        assert!(store
            .add_connection(spec(
                "http://slack.com/authorize",
                "https://slack.com/token",
                "id"
            ))
            .is_err());
        assert!(store
            .add_connection(spec("https://slack.com/authorize", "not a url", "id"))
            .is_err());
        assert!(store
            .add_connection(spec(
                "https://slack.com/authorize",
                "https://slack.com/token",
                "  "
            ))
            .is_err());
        // API OAuth and MCP OAuth are separate token lifecycles. Combining
        // them could render the JSON token set itself into the MCP request.
        let mut mixed = spec(
            "https://slack.com/authorize",
            "https://slack.com/token",
            "id",
        );
        let ConnectionConfig::Api { mcp_path, .. } = &mut mixed.config else {
            unreachable!()
        };
        *mcp_path = Some("/mcp".into());
        let error = store.add_connection(mixed).unwrap_err();
        assert!(error
            .to_string()
            .contains("MCP path cannot be combined with API OAuth"));
        // …while a complete spec saves and round-trips.
        let saved = store
            .add_connection(spec(
                "https://slack.com/oauth/v2/authorize",
                "https://slack.com/api/oauth.v2.access",
                "1234.5678",
            ))
            .unwrap();
        let ConnectionConfig::Api {
            oauth: Some(oauth), ..
        } = &saved.config
        else {
            panic!("oauth spec lost");
        };
        assert_eq!(oauth.client_id, "1234.5678");
        assert_eq!(
            oauth.token_secret_id,
            Some(store.secret_by_name("SLACK_OAUTH_TOKEN").unwrap().id)
        );

        let token_id = oauth.token_secret_id.unwrap();
        let mut legacy = IndexState {
            connections: vec![saved],
            ..IndexState::default()
        };
        let ConnectionConfig::Api {
            oauth: Some(oauth), ..
        } = &mut legacy.connections[0].config
        else {
            unreachable!()
        };
        oauth.token_secret_id = None;
        assert!(migrate_oauth_token_secret_ids(&mut legacy));
        let ConnectionConfig::Api {
            oauth: Some(oauth), ..
        } = &legacy.connections[0].config
        else {
            unreachable!()
        };
        assert_eq!(oauth.token_secret_id, Some(token_id));
    }

    #[tokio::test]
    async fn oauth_token_binding_is_explicit_not_secret_name_order() {
        let (store, _, _dir) = store().await;
        let auxiliary = store.add_secret("AUXILIARY", val("other")).unwrap();
        let tokens = store.add_secret("Z_OAUTH_TOKENS", val("{}")).unwrap();
        let saved = store
            .add_connection(ConnectionSpec {
                name: "slack".into(),
                config: ConnectionConfig::Api {
                    host: "slack.com".into(),
                    scheme: "https".into(),
                    port: None,
                    trusted_ca_bundle_path: None,
                    template: "Authorization: Bearer {{Z_OAUTH_TOKENS}}; auxiliary={{AUXILIARY}}"
                        .into(),
                    mcp_path: None,
                    oauth: Some(crate::types::OAuthSpec {
                        auth_url: "https://slack.com/oauth/v2/authorize".into(),
                        token_url: "https://slack.com/api/oauth.v2.access".into(),
                        client_id: "1234.5678".into(),
                        scopes: vec![],
                        extra_auth_params: vec![],
                        token_secret_id: None,
                    }),
                },
                // Explicit creation input identifies the token set even
                // though the derived secret list sorts AUXILIARY first.
                secrets: vec![tokens.id],
            })
            .unwrap();
        assert_eq!(saved.secrets, vec![auxiliary.id, tokens.id]);
        let ConnectionConfig::Api {
            oauth: Some(oauth), ..
        } = &saved.config
        else {
            panic!("oauth spec lost");
        };
        assert_eq!(oauth.token_secret_id, Some(tokens.id));

        let mut legacy = IndexState {
            connections: vec![saved],
            ..IndexState::default()
        };
        let ConnectionConfig::Api {
            oauth: Some(oauth), ..
        } = &mut legacy.connections[0].config
        else {
            unreachable!()
        };
        oauth.token_secret_id = None;
        assert!(
            !migrate_oauth_token_secret_ids(&mut legacy),
            "a multi-secret legacy connection is ambiguous and must fail closed"
        );
        let ConnectionConfig::Api {
            oauth: Some(oauth), ..
        } = &legacy.connections[0].config
        else {
            unreachable!()
        };
        assert_eq!(oauth.token_secret_id, None);
    }

    #[tokio::test]
    async fn oauth_grants_live_outside_the_secret_list_and_die_with_the_connection() {
        let (store, vault, _dir) = store().await;
        store.add_secret("GITHUB_MCP_TOKEN", val("at-1")).unwrap();
        let conn = store
            .add_connection(api_spec(
                "github",
                "api.githubcopilot.com",
                "Authorization: Bearer {{GITHUB_MCP_TOKEN}}",
            ))
            .unwrap();
        let secrets_before = store.list_secrets().len();
        let vault_before = vault.len();

        let expires = Utc::now() + chrono::Duration::hours(1);
        let updated = store
            .set_connection_oauth(&conn.id, val(r#"{"refresh_token":"rt-1"}"#), Some(expires))
            .unwrap();
        let oauth = updated.oauth.clone().expect("oauth linkage");
        assert_eq!(oauth.expires_at, Some(expires));
        // The grant is a vault item but never a listed secret.
        assert_eq!(vault.len(), vault_before + 1);
        assert_eq!(store.list_secrets().len(), secrets_before);
        assert_eq!(
            &*store.connection_oauth_grant(&conn.id).await.unwrap(),
            r#"{"refresh_token":"rt-1"}"#
        );

        // Replacing the grant reuses the same vault item.
        let replaced = store
            .set_connection_oauth(&conn.id, val(r#"{"refresh_token":"rt-2"}"#), None)
            .unwrap();
        assert_eq!(replaced.oauth.as_ref().unwrap().grant_id, oauth.grant_id);
        assert_eq!(replaced.oauth.as_ref().unwrap().expires_at, None);
        assert_eq!(vault.len(), vault_before + 1);
        assert_eq!(
            &*store.connection_oauth_grant(&conn.id).await.unwrap(),
            r#"{"refresh_token":"rt-2"}"#
        );

        // The linkage is maintenance metadata: it must not look like an
        // edit (that would trip conflict checks and drop wirings).
        assert_eq!(replaced.updated_at, conn.updated_at);

        store.delete_connection(&conn.id).unwrap();
        assert_eq!(vault.len(), vault_before);
    }

    #[tokio::test]
    async fn oauth_managed_mcp_connections_are_rename_only() {
        let (store, _, _dir) = store().await;
        store.add_secret("NOTION_MCP_TOKEN", val("at-1")).unwrap();
        store.add_secret("OTHER_TOKEN", val("other")).unwrap();
        let mut spec = api_spec(
            "Notion",
            "mcp.notion.com",
            "Authorization: Bearer {{NOTION_MCP_TOKEN}}",
        );
        let ConnectionConfig::Api { mcp_path, .. } = &mut spec.config else {
            unreachable!()
        };
        *mcp_path = Some("/mcp".into());
        let conn = store.add_connection(spec).unwrap();
        store
            .set_connection_oauth(
                &conn.id,
                val(r#"{"refresh_token":"rt-1"}"#),
                Some(Utc::now() + chrono::Duration::hours(1)),
            )
            .unwrap();

        let (renamed, target_changed) = store
            .update_connection(
                &conn.id,
                ConnectionSpec {
                    name: "Notion work".into(),
                    config: conn.config.clone(),
                    secrets: vec![],
                },
            )
            .unwrap();
        assert_eq!(renamed.name, "Notion work");
        assert!(!target_changed);

        let mut changed_config = renamed.config.clone();
        let ConnectionConfig::Api { template, .. } = &mut changed_config else {
            unreachable!()
        };
        *template = "Authorization: Bearer {{OTHER_TOKEN}}".into();
        let error = store
            .update_connection(
                &conn.id,
                ConnectionSpec {
                    name: renamed.name.clone(),
                    config: changed_config,
                    secrets: vec![],
                },
            )
            .unwrap_err();
        assert!(matches!(error, CoreError::InvalidConnectionConfig(_)));

        let unchanged = store.connection_by_id(&conn.id).unwrap();
        assert_eq!(unchanged.config, conn.config);
        assert!(unchanged.oauth.is_some());
        assert_eq!(unchanged.secrets, conn.secrets);
    }

    #[tokio::test]
    async fn byo_oauth_connections_are_rename_only() {
        let (store, _, _dir) = store().await;
        let token = store.add_secret("SLACK_OAUTH_TOKEN", val("{}")).unwrap();
        let conn = store
            .add_connection(ConnectionSpec {
                name: "Slack".into(),
                config: ConnectionConfig::Api {
                    host: "slack.com".into(),
                    scheme: "https".into(),
                    port: None,
                    trusted_ca_bundle_path: None,
                    template: "Authorization: Bearer {{SLACK_OAUTH_TOKEN}}".into(),
                    mcp_path: None,
                    oauth: Some(crate::types::OAuthSpec {
                        auth_url: "https://slack.com/oauth/v2/authorize".into(),
                        token_url: "https://slack.com/api/oauth.v2.access".into(),
                        client_id: "1234.5678".into(),
                        scopes: vec![],
                        extra_auth_params: vec![],
                        token_secret_id: None,
                    }),
                },
                secrets: vec![token.id],
            })
            .unwrap();

        // Manage clients do not receive the internal token-secret id. The
        // store restores it before comparing an otherwise-identical rename.
        let mut rename_config = conn.config.clone();
        let ConnectionConfig::Api {
            oauth: Some(oauth), ..
        } = &mut rename_config
        else {
            unreachable!()
        };
        oauth.token_secret_id = None;
        let (renamed, target_changed) = store
            .update_connection(
                &conn.id,
                ConnectionSpec {
                    name: "Slack work".into(),
                    config: rename_config,
                    secrets: vec![],
                },
            )
            .unwrap();
        assert!(!target_changed);

        let mut broken = renamed.config.clone();
        let ConnectionConfig::Api { template, .. } = &mut broken else {
            unreachable!()
        };
        template.clear();
        assert!(matches!(
            store.update_connection(
                &conn.id,
                ConnectionSpec {
                    name: renamed.name.clone(),
                    config: broken,
                    secrets: vec![],
                }
            ),
            Err(CoreError::InvalidConnectionConfig(_))
        ));
        assert_eq!(
            store.connection_by_id(&conn.id).unwrap().config,
            renamed.config
        );
    }

    #[tokio::test]
    async fn tofu_pin_sets_the_fingerprint_exactly_once() {
        let (store, _, _dir) = store().await;
        let key = store.add_secret("DEPLOY_SSH_KEY", val("k")).unwrap();
        let conn = store
            .add_connection(ConnectionSpec {
                name: "prod-ssh".into(),
                config: ConnectionConfig::Ssh {
                    destination: None,
                    host: "prod.example.com".into(),
                    port: 22,
                    user: "deploy".into(),
                    host_key_fingerprint: String::new(),
                },
                secrets: vec![key.id],
            })
            .unwrap();
        let observed: ssh_key::Fingerprint = SSH_HOST_FP.parse().unwrap();
        let racing: ssh_key::Fingerprint = SSH_HOST_FP_ALT.parse().unwrap();

        assert_eq!(
            store.pin_ssh_host_key(&conn.id, &observed).unwrap(),
            PinOutcome::Pinned(observed)
        );
        let pinned = store.connection_by_id(&conn.id).unwrap();
        // A host-key pin is the connection learning what it already described,
        // not a retarget. Bumping `updated_at` made it look like one to the
        // version check every execution runs at its boundary, so an open racing
        // a first-connection pin was refused as `denied_by_policy`.
        assert_eq!(
            pinned.updated_at, conn.updated_at,
            "pinning must not look like a retarget"
        );
        match &pinned.config {
            ConnectionConfig::Ssh {
                host_key_fingerprint,
                ..
            } => assert_eq!(host_key_fingerprint, SSH_HOST_FP),
            _ => unreachable!(),
        }
        // A second (racing) pin reports the existing key and changes nothing.
        assert_eq!(
            store.pin_ssh_host_key(&conn.id, &racing).unwrap(),
            PinOutcome::AlreadyPinned(observed)
        );
        assert_eq!(
            store.connection_by_id(&conn.id).unwrap().updated_at,
            pinned.updated_at
        );
        // Wrong kind and unknown connections are refused.
        store.add_secret("GITHUB_API_KEY", val("g")).unwrap();
        let api = store
            .add_connection(api_spec(
                "github",
                "api.github.com",
                "Authorization: Bearer {{GITHUB_API_KEY}}",
            ))
            .unwrap();
        assert!(store.pin_ssh_host_key(&api.id, &observed).is_err());
        assert!(matches!(
            store
                .pin_ssh_host_key(&Uuid::new_v4(), &observed)
                .unwrap_err(),
            CoreError::ConnectionNotFound
        ));
    }

    /// A store written before WebSocket support was removed still lists
    /// `"kind": "ws"` rows. Refusing to deserialize would report the whole
    /// store as corrupt and lock the user out of every other connection and
    /// secret, so the retired rows are dropped and the rest loads.
    #[test]
    fn a_store_with_retired_connection_kinds_still_loads() {
        let state: IndexState = serde_json::from_str(
            r#"{
              "secrets": [],
              "connections": [
                {"id":"00000000-0000-0000-0000-000000000001","name":"market-feed",
                 "config":{"kind":"ws","url":"wss://example.com/feed"},"secrets":[],
                 "created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"},
                {"id":"00000000-0000-0000-0000-000000000002","name":"analytics",
                 "config":{"kind":"pg","host":"db.internal","dbname":"app","user":"app"},
                 "secrets":[],
                 "created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"}
              ]
            }"#,
        )
        .expect("a retired kind must not fail the whole load");
        assert_eq!(state.connections.len(), 1);
        assert_eq!(state.connections[0].name, "analytics");
        // What was dropped is left for the caller, so the loss reaches the
        // audit trail instead of only a `tracing` warning nobody reads.
        let dropped =
            RETIRED_CONNECTIONS_DROPPED.with(|dropped| std::mem::take(&mut *dropped.borrow_mut()));
        assert_eq!(dropped, vec!["market-feed (ws)".to_string()]);
    }

    /// A record that is malformed for a kind this build *does* support is a
    /// real integrity problem and must still fail loudly.
    #[test]
    fn a_malformed_supported_connection_still_fails() {
        let parsed = serde_json::from_str::<IndexState>(
            r#"{"secrets": [], "connections": [
                {"id":"00000000-0000-0000-0000-000000000003","name":"broken",
                 "config":{"kind":"pg"},"secrets":[],
                 "created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"}
              ]}"#,
        );
        assert!(parsed.is_err());
    }

    #[tokio::test]
    async fn connection_names_unique_and_kind_fixed() {
        let (store, _, _dir) = store().await;
        let tok = store.add_secret("STREAM_TOKEN", val("t")).unwrap();
        let ws = store
            .add_connection(ConnectionSpec {
                name: "market-feed".into(),
                config: ConnectionConfig::Api {
                    host: "stream.example.com".into(),
                    scheme: "https".into(),
                    port: None,
                    trusted_ca_bundle_path: None,
                    template: "Authorization: Bearer {{STREAM_TOKEN}}".into(),
                    mcp_path: None,
                    oauth: None,
                },
                secrets: vec![tok.id],
            })
            .unwrap();
        assert!(matches!(
            store
                .add_connection(ConnectionSpec {
                    name: "market-feed".into(),
                    config: ConnectionConfig::Api {
                        host: "other.example.com".into(),
                        scheme: "https".into(),
                        port: None,
                        trusted_ca_bundle_path: None,
                        template: "Authorization: Bearer {{STREAM_TOKEN}}".into(),
                        mcp_path: None,
                        oauth: None,
                    },
                    secrets: vec![tok.id],
                })
                .unwrap_err(),
            CoreError::ConnectionNameTaken(_)
        ));
        // Kind is fixed after creation.
        assert!(matches!(
            store
                .update_connection(
                    &ws.id,
                    ConnectionSpec {
                        name: "market-feed".into(),
                        config: ConnectionConfig::Pg {
                            host: "db.internal".into(),
                            port: 5432,
                            dbname: "app".into(),
                            user: "app".into(),
                            sslmode: Default::default(),
                            trusted_ca_bundle_path: None,
                        },
                        secrets: vec![tok.id],
                    }
                )
                .unwrap_err(),
            CoreError::KindChange
        ));
    }

    #[tokio::test]
    async fn update_reports_target_change() {
        let (store, _, _dir) = store().await;
        store.add_secret("GITHUB_API_KEY", val("g")).unwrap();
        let conn = store
            .add_connection(api_spec(
                "github",
                "api.github.com",
                "Authorization: Bearer {{GITHUB_API_KEY}}",
            ))
            .unwrap();
        // Rename only → target unchanged.
        let (updated, changed) = store
            .update_connection(
                &conn.id,
                api_spec(
                    "github-main",
                    "api.github.com",
                    "Authorization: Bearer {{GITHUB_API_KEY}}",
                ),
            )
            .unwrap();
        assert_eq!(updated.name, "github-main");
        assert!(!changed);
        // Repoint host → target changed (caller drops rules).
        let (_, changed) = store
            .update_connection(
                &conn.id,
                api_spec(
                    "github-main",
                    "evil.example.com",
                    "Authorization: Bearer {{GITHUB_API_KEY}}",
                ),
            )
            .unwrap();
        assert!(changed);
    }

    #[tokio::test]
    async fn failed_index_writes_do_not_change_active_state() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::under(dir.path());
        let vault = Arc::new(MemoryVault::new());
        let store = Store::open(paths.clone(), vault.clone()).await.unwrap();
        store.add_secret("A_KEY", val("a")).unwrap();
        let spare = store.add_secret("B_KEY", val("b")).unwrap();
        let connection = store
            .add_connection(api_spec(
                "github",
                "api.github.com",
                "Authorization: Bearer {{A_KEY}}",
            ))
            .unwrap();
        let index = paths.index_file();
        std::fs::remove_file(&index).unwrap();
        std::fs::create_dir(&index).unwrap();

        let vault_items = vault.len();
        assert!(store.add_secret("C_KEY", val("c")).is_err());
        assert!(store.secret_by_name("C_KEY").is_none());
        assert_eq!(vault.len(), vault_items);

        assert!(store.rename_secret(&spare.id, "RENAMED_KEY").is_err());
        assert_eq!(store.secret_by_id(&spare.id).unwrap().name, "B_KEY");

        assert!(store.replace_secret_value(&spare.id, val("new")).is_err());
        assert_eq!(&*store.secret_value(&spare.id).await.unwrap(), "b");

        assert!(store
            .update_connection(
                &connection.id,
                api_spec(
                    "renamed",
                    "other.example.com",
                    "Authorization: Bearer {{A_KEY}}",
                ),
            )
            .is_err());
        assert_eq!(
            store.connection_by_id(&connection.id).unwrap().name,
            "github"
        );

        assert!(store.delete_connection(&connection.id).is_err());
        assert!(store.connection_by_id(&connection.id).is_ok());

        assert!(store.set_menu_bar_hides_dock(true).is_err());
        assert!(!store.settings().menu_bar_hides_dock);

        assert!(store.delete_secret(&spare.id).is_err());
        assert!(store.secret_by_id(&spare.id).is_ok());
        assert_eq!(&*store.secret_value(&spare.id).await.unwrap(), "b");
    }

    #[tokio::test]
    async fn legacy_global_pg_ca_bundle_migrates_to_connections() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Arc::new(MemoryVault::new());
        {
            let store = Store::open(Paths::under(dir.path()), vault.clone())
                .await
                .unwrap();
            let password = store.add_secret("PG_PASSWORD", val("pw")).unwrap();
            store
                .add_connection(ConnectionSpec {
                    name: "prod-db".into(),
                    config: ConnectionConfig::Pg {
                        host: "db.example.com".into(),
                        port: 5432,
                        dbname: "app".into(),
                        user: "app".into(),
                        sslmode: PgSslMode::VerifyFull,
                        trusted_ca_bundle_path: None,
                    },
                    secrets: vec![password.id],
                })
                .unwrap();
            let mut state = store.state.lock().unwrap();
            let mut settings = state.settings();
            settings.legacy_pg_trusted_ca_bundle_path = Some("/etc/ssl/private/pg-ca.pem".into());
            state.settings = Some(settings);
            store.persist(&state).unwrap();
        }
        let store = Store::open(Paths::under(dir.path()), vault).await.unwrap();
        let connection = store.connection_by_name("prod-db").unwrap();
        let ConnectionConfig::Pg {
            trusted_ca_bundle_path,
            ..
        } = connection.config
        else {
            panic!("expected postgres connection");
        };
        assert_eq!(
            trusted_ca_bundle_path.as_deref(),
            Some("/etc/ssl/private/pg-ca.pem")
        );
        assert_eq!(store.settings().legacy_pg_trusted_ca_bundle_path, None);
    }

    #[tokio::test]
    async fn tampered_index_refuses_to_load() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Arc::new(MemoryVault::new());
        {
            let store = Store::open(Paths::under(dir.path()), vault.clone())
                .await
                .unwrap();
            store.add_secret("GITHUB_API_KEY", val("ghp")).unwrap();
            store
                .add_connection(api_spec(
                    "github",
                    "api.github.com",
                    "Authorization: Bearer {{GITHUB_API_KEY}}",
                ))
                .unwrap();
        }
        // A local process repoints the pinned host inside the sealed file.
        let index = Paths::under(dir.path()).index_file();
        let sealed = std::fs::read_to_string(&index).unwrap();
        std::fs::write(&index, sealed.replace("api.github.com", "evil.example.com")).unwrap();
        match Store::open(Paths::under(dir.path()), vault).await {
            Err(CoreError::StateTampered(_)) => {}
            Err(other) => panic!("unexpected error: {other}"),
            Ok(_) => panic!("tampered index must refuse to load"),
        }
    }

    #[tokio::test]
    async fn legacy_index_is_sealed_on_first_open() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::under(dir.path());
        paths.ensure().unwrap();
        // A bare index.json from before any integrity key exists.
        std::fs::write(paths.index_file(), br#"{"secrets": [], "connections": []}"#).unwrap();
        let vault = Arc::new(MemoryVault::new());
        let store = Store::open(paths.clone(), vault).await.unwrap();
        assert!(store.list_secrets().is_empty());
        let on_disk = std::fs::read_to_string(paths.index_file()).unwrap();
        assert!(on_disk.contains("\"mac\""), "resealed: {on_disk}");
    }

    #[tokio::test]
    async fn index_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let (store, _, dir) = store().await;
        store.add_secret("A_KEY", val("a")).unwrap();
        let mode = std::fs::metadata(Paths::under(dir.path()).index_file())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
