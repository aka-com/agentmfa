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
//!   pg/ssh connections bind at most one secret; ws binds exactly one;
//! - a connection's type is fixed after creation.

use std::sync::Arc;
use std::sync::Mutex;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{ConnectionField, CoreError};
use crate::events::{BrokerEvents, NoopEvents};
use crate::integrity::StateIntegrity;
use crate::paths::Paths;
use crate::template::{is_valid_secret_name, Template};
use crate::types::{
    reveal_prefix, Connection, ConnectionConfig, ConnectionKind, SecretMeta, SecretValue, Settings,
};
use crate::vault::{SecretVault, VaultAttrs};
use crate::Result;

/// Everything `index.json` holds.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct IndexState {
    #[serde(default)]
    secrets: Vec<SecretMeta>,
    #[serde(default)]
    connections: Vec<Connection>,
    #[serde(default)]
    settings: Option<Settings>,
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

/// Input for creating or updating a connection.
#[derive(Debug, Clone)]
pub struct ConnectionSpec {
    pub name: String,
    pub config: ConnectionConfig,
    /// For pg/ssh: the optional single bound secret; ws binds one. Ignored for
    /// api connections, whose secret list is derived from the template's refs.
    pub secrets: Vec<Uuid>,
}

pub struct Store {
    paths: Paths,
    vault: Arc<dyn SecretVault>,
    events: Arc<dyn BrokerEvents>,
    integrity: Arc<StateIntegrity>,
    state: Mutex<IndexState>,
}

impl Store {
    pub async fn open(paths: Paths, vault: Arc<dyn SecretVault>) -> Result<Self> {
        let integrity = Arc::new(StateIntegrity::open(&*vault).await?);
        Self::open_with_events(paths, vault, Arc::new(NoopEvents), integrity)
    }

    pub fn open_with_events(
        paths: Paths,
        vault: Arc<dyn SecretVault>,
        events: Arc<dyn BrokerEvents>,
        integrity: Arc<StateIntegrity>,
    ) -> Result<Self> {
        paths.ensure()?;
        // index.json is sealed: a file that fails verification
        // refuses to load rather than silently serving repointed bindings.
        let mut state: IndexState = match integrity.read_verified(&paths.index_file())? {
            Some(bytes) => serde_json::from_slice(&bytes)?,
            None => IndexState::default(),
        };
        if migrate_legacy_pg_ca_bundle(&mut state) {
            integrity.write(&paths.index_file(), &serde_json::to_vec_pretty(&state)?)?;
        }
        Ok(Self {
            paths,
            vault,
            events,
            integrity,
            state: Mutex::new(state),
        })
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
                ConnectionConfig::Ws { template, .. } => template.as_mut(),
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
    /// (`min(6, ⌊len/2⌋)` chars).
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
        let events = self.events.clone();
        crate::authorization::confirm_once(|| async move {
            let confirmed = tokio::task::spawn_blocking(move || events.confirm_secret_read(&meta))
                .await
                .map_err(|e| CoreError::Vault(format!("confirmation task failed: {e}")))?;
            if !confirmed {
                return Err(CoreError::SecretReadNotAuthenticated);
            }
            Ok(())
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

    pub fn list_connections(&self) -> Vec<Connection> {
        let mut conns = self.state.lock().unwrap().connections.clone();
        conns.sort_by(|a, b| a.name.cmp(&b.name));
        conns
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
    /// must drop the connection's standing rules when it did (a rule granted
    /// for one destination must not silently cover another).
    pub fn update_connection(&self, id: &Uuid, spec: ConnectionSpec) -> Result<(Connection, bool)> {
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
        conn.updated_at = Utc::now();
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

    pub fn set_show_websockets(&self, on: bool) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        let mut settings = state.settings();
        settings.show_websockets = on;
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

fn prepare_connection(state: &IndexState, spec: ConnectionSpec) -> Result<Connection> {
    validate_connection_name(&spec.name)?;
    if state.connections.iter().any(|conn| conn.name == spec.name) {
        return Err(CoreError::ConnectionNameTaken(spec.name));
    }
    let secrets = validate_config_and_bind_secrets(state, &spec)?;
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
/// bind at most one secret, while ws binds exactly one.
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
            if let Some(path) = mcp_path {
                if !path.starts_with('/') {
                    return Err(CoreError::InvalidConnectionField {
                        field: ConnectionField::Url,
                        message: "The MCP path must start with / (for example /mcp)".into(),
                    });
                }
            }
            if let Some(oauth) = oauth {
                let https_url =
                    |value: &str| url::Url::parse(value).is_ok_and(|url| url.scheme() == "https");
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
        ConnectionConfig::Ws { url, template } => {
            let parsed_url =
                url::Url::parse(url).map_err(|_| CoreError::InvalidConnectionField {
                    field: ConnectionField::Url,
                    message: "Enter a complete ws:// or wss:// URL".into(),
                })?;
            match parsed_url.scheme() {
                "ws" | "wss" => {}
                other => {
                    return Err(CoreError::InvalidConnectionField {
                        field: ConnectionField::Url,
                        message: format!("Use ws:// or wss://, not {other}://"),
                    })
                }
            }
            if let Some(template) = template {
                let parsed = Template::parse(template)?;
                let refs = parsed.refs();
                if refs.len() != 1 {
                    return Err(CoreError::WrongSecretCount { kind: "websocket" });
                }
                return Ok(vec![find_by_name(refs.iter().next().unwrap())?]);
            }
            bind_single_secret(state, spec)
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

fn bind_optional_secret(state: &IndexState, spec: &ConnectionSpec) -> Result<Vec<Uuid>> {
    let kind = match spec.config.kind() {
        ConnectionKind::Pg => "postgres",
        ConnectionKind::Ws => "websocket",
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

fn bind_single_secret(state: &IndexState, spec: &ConnectionSpec) -> Result<Vec<Uuid>> {
    if spec.secrets.len() != 1 {
        let kind = match spec.config.kind() {
            ConnectionKind::Ws => "websocket",
            ConnectionKind::Pg => "postgres",
            ConnectionKind::Ssh => "ssh",
            ConnectionKind::Api => unreachable!(),
        };
        return Err(CoreError::WrongSecretCount { kind });
    }
    bind_optional_secret(state, spec)
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
                config: ConnectionConfig::Ws {
                    url: "wss://stream.example.com/feed".into(),
                    template: None,
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
                template: "Authorization: Bearer {{SLACK_OAUTH_TOKEN}}".into(),
                mcp_path: None,
                oauth: Some(crate::types::OAuthSpec {
                    auth_url: auth.into(),
                    token_url: token.into(),
                    client_id: client.into(),
                    scopes: vec!["chat:write".into()],
                    extra_auth_params: vec![],
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
        } = saved.config
        else {
            panic!("oauth spec lost");
        };
        assert_eq!(oauth.client_id, "1234.5678");
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
        assert!(pinned.updated_at > conn.updated_at);
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

    #[tokio::test]
    async fn connection_names_unique_and_kind_fixed() {
        let (store, _, _dir) = store().await;
        let tok = store.add_secret("STREAM_TOKEN", val("t")).unwrap();
        let ws = store
            .add_connection(ConnectionSpec {
                name: "market-feed".into(),
                config: ConnectionConfig::Ws {
                    url: "wss://stream.example.com/feed".into(),
                    template: None,
                },
                secrets: vec![tok.id],
            })
            .unwrap();
        assert!(matches!(
            store
                .add_connection(ConnectionSpec {
                    name: "market-feed".into(),
                    config: ConnectionConfig::Ws {
                        url: "wss://other.example.com".into(),
                        template: None,
                    },
                    secrets: vec![tok.id],
                })
                .unwrap_err(),
            CoreError::ConnectionNameTaken(_)
        ));
        // Kind is fixed after creation.
        store.add_secret("GITHUB_API_KEY", val("g")).unwrap();
        assert!(matches!(
            store
                .update_connection(
                    &ws.id,
                    api_spec("market-feed", "x.example.com", "Bearer {{GITHUB_API_KEY}}")
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
