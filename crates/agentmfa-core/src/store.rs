//! The vault-backed store (DESIGN.md §3, §9).
//!
//! Secret *values* live in the vault (Keychain on macOS); everything else,
//! the secrets index (id, name, timestamps; deliberately no value preview)
//! and all connection config, lives in `index.json`, written atomically.
//!
//! Invariants enforced here:
//! - secret and connection names are unique (templates resolve secrets by
//!   name; agents and rules address connections by name);
//! - renaming a secret rewrites every injection template that references it,
//!   atomically with the rename;
//! - deleting a secret still referenced by a connection is refused;
//! - API connections' secret list is derived from their template's refs;
//!   pg/ws/ssh connections bind exactly one secret;
//! - a connection's type is fixed after creation.

use std::sync::Arc;
use std::sync::Mutex;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::CoreError;
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
#[derive(Debug, Default, Serialize, Deserialize)]
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

/// Input for creating or updating a connection.
#[derive(Debug, Clone)]
pub struct ConnectionSpec {
    pub name: String,
    pub config: ConnectionConfig,
    /// For pg/ws/ssh: the single bound secret. Ignored for api connections,
    /// whose secret list is derived from the template's refs.
    pub secrets: Vec<Uuid>,
    /// pg/ws/ssh multi-connect checkbox (ignored for api).
    pub multi_connect: bool,
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
        // index.json is sealed (§13.1): a file that fails verification
        // refuses to load rather than silently serving repointed bindings.
        let state = match integrity.read_verified(&paths.index_file())? {
            Some(bytes) => serde_json::from_slice(&bytes)?,
            None => IndexState::default(),
        };
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
        let sync = state.settings().icloud_sync;
        self.vault.set(
            &meta.id,
            &VaultAttrs {
                name: meta.name.clone(),
                created_at: now,
                sync,
            },
            &value,
        )?;
        drop(value); // late fetch, early drop, the plaintext came in exactly once
        state.secrets.push(meta.clone());
        self.persist(&state)?;
        Ok(meta)
    }

    /// Rename a secret, rewriting every injection template that references
    /// it, inside `{{ … }}` placeholders and transform expressions alike,
    /// atomically with the rename (DESIGN.md §3).
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
        // Rewrite templates in a working copy first; nothing is persisted
        // until every rewrite has parsed and applied cleanly.
        let mut rewritten = 0usize;
        for conn in state.connections.iter_mut() {
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
            let secret = state.secrets.iter_mut().find(|s| &s.id == id).unwrap();
            secret.name = new_name.to_string();
            secret.updated_at = now;
            (secret.clone(), secret.created_at)
        };
        // Keep the Keychain label in sync so synced items stay
        // self-describing on another Mac (§3).
        let sync = state.settings().icloud_sync;
        self.vault.set_attrs(
            id,
            &VaultAttrs {
                name: new_name.to_string(),
                created_at,
                sync,
            },
        )?;
        self.persist(&state)?;
        Ok((meta, rewritten))
    }

    /// Replace a secret's value (the Edit sheet's write-only field, §9).
    pub fn replace_secret_value(&self, id: &Uuid, value: SecretValue) -> Result<SecretMeta> {
        let mut state = self.state.lock().unwrap();
        let sync = state.settings().icloud_sync;
        let secret = state
            .secrets
            .iter_mut()
            .find(|s| &s.id == id)
            .ok_or(CoreError::SecretNotFound)?;
        self.vault.set(
            id,
            &VaultAttrs {
                name: secret.name.clone(),
                created_at: secret.created_at,
                sync,
            },
            &value,
        )?;
        secret.updated_at = Utc::now();
        let meta = secret.clone();
        self.persist(&state)?;
        Ok(meta)
    }

    /// Deleting a secret a connection still uses is refused (DESIGN.md §3).
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
        self.vault.delete(id)?;
        let meta = state.secrets.remove(pos);
        self.persist(&state)?;
        Ok(meta)
    }

    /// Audited, core-side Keychain read returning only the short prefix
    /// (`min(6, ⌊len/2⌋)` chars — DESIGN.md §2). Callers audit.
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
    /// approval — never cached (§3; caching would foreclose just-in-time
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
    /// worker while the user decides (§3/§8).
    async fn confirm_secret_read(&self, meta: SecretMeta, reauth: bool) -> Result<()> {
        if !reauth {
            return Ok(());
        }
        let events = self.events.clone();
        let confirmed = tokio::task::spawn_blocking(move || events.confirm_secret_read(&meta))
            .await
            .map_err(|e| CoreError::Vault(format!("confirmation task failed: {e}")))?;
        if !confirmed {
            return Err(CoreError::SecretReadNotAuthenticated);
        }
        Ok(())
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

    pub fn add_connection(&self, spec: ConnectionSpec) -> Result<Connection> {
        validate_connection_name(&spec.name)?;
        let mut state = self.state.lock().unwrap();
        if state.connections.iter().any(|c| c.name == spec.name) {
            return Err(CoreError::ConnectionNameTaken(spec.name));
        }
        let secrets = validate_config_and_bind_secrets(&state, &spec)?;
        let now = Utc::now();
        let conn = Connection {
            id: Uuid::new_v4(),
            name: spec.name,
            multi_connect: spec.config.kind() != ConnectionKind::Api && spec.multi_connect,
            config: spec.config,
            secrets,
            created_at: now,
            updated_at: now,
        };
        state.connections.push(conn.clone());
        self.persist(&state)?;
        Ok(conn)
    }

    /// Update a connection. The kind is fixed after creation. Returns the
    /// updated connection and whether its pinned target changed, the caller
    /// must drop the connection's standing rules when it did (a rule granted
    /// for one destination must not silently cover another, DESIGN.md §9).
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
        let secrets = validate_config_and_bind_secrets(&state, &spec)?;
        let conn = state
            .connections
            .iter_mut()
            .find(|c| &c.id == id)
            .expect("checked above");
        conn.name = spec.name;
        conn.multi_connect = spec.config.kind() != ConnectionKind::Api && spec.multi_connect;
        conn.config = spec.config;
        conn.secrets = secrets;
        conn.updated_at = Utc::now();
        let updated = conn.clone();
        let target_changed = updated.target() != old_target;
        self.persist(&state)?;
        Ok((updated, target_changed))
    }

    /// Delete a connection. The caller (policy layer) deletes its rules,
    /// rules die with their connection (DESIGN.md §7).
    pub fn delete_connection(&self, id: &Uuid) -> Result<Connection> {
        let mut state = self.state.lock().unwrap();
        let pos = state
            .connections
            .iter()
            .position(|c| &c.id == id)
            .ok_or(CoreError::ConnectionNotFound)?;
        let conn = state.connections.remove(pos);
        self.persist(&state)?;
        Ok(conn)
    }

    /* ------------------------------ settings ------------------------------ */

    pub fn settings(&self) -> Settings {
        self.state.lock().unwrap().settings()
    }

    /// Toggle iCloud Keychain sync. Flipping it migrates every secret in the
    /// vault (read → delete → re-create with the new attribute, §3). Returns
    /// how many items were migrated.
    pub async fn set_icloud_sync(&self, on: bool) -> Result<usize> {
        // Snapshot under the lock, migrate without holding it (vault reads
        // may suspend), then commit the setting. A secret added mid-toggle
        // keeps its creation-time sync attribute — acceptable for a
        // single-user UI action.
        let metas = {
            let state = self.state.lock().unwrap();
            if state.settings().icloud_sync == on {
                return Ok(0);
            }
            state.secrets.clone()
        };
        // Migrate every secret to the new sync attribute. If any migration
        // fails partway, roll the already-migrated items back to the old
        // attribute so we never leave the vault half-flipped with `settings`
        // disagreeing about it — the toggle is all-or-nothing. The setting is
        // only committed once every item migrated.
        let mut migrated: Vec<&SecretMeta> = Vec::new();
        for meta in &metas {
            let attrs = VaultAttrs {
                name: meta.name.clone(),
                created_at: meta.created_at,
                sync: on,
            };
            match self.vault.migrate_sync(&meta.id, &attrs).await {
                Ok(()) => migrated.push(meta),
                Err(e) => {
                    for m in &migrated {
                        let old = VaultAttrs {
                            name: m.name.clone(),
                            created_at: m.created_at,
                            sync: !on,
                        };
                        if let Err(re) = self.vault.migrate_sync(&m.id, &old).await {
                            tracing::error!("icloud sync rollback failed for {}: {re}", m.id);
                        }
                    }
                    return Err(e);
                }
            }
        }
        let mut state = self.state.lock().unwrap();
        let mut settings = state.settings();
        settings.icloud_sync = on;
        state.settings = Some(settings);
        self.persist(&state)?;
        Ok(metas.len())
    }

    pub fn set_reauth_on_read(&self, on: bool) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        let mut settings = state.settings();
        settings.reauth_on_read = on;
        state.settings = Some(settings);
        self.persist(&state)?;
        Ok(())
    }

    pub fn set_hide_secret_prefixes(&self, on: bool) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        let mut settings = state.settings();
        settings.hide_secret_prefixes = on;
        state.settings = Some(settings);
        self.persist(&state)?;
        Ok(())
    }

    pub fn set_menu_bar_hides_dock(&self, on: bool) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        let mut settings = state.settings();
        settings.menu_bar_hides_dock = on;
        state.settings = Some(settings);
        self.persist(&state)?;
        Ok(())
    }

    pub fn set_pg_trusted_ca_bundle_path(&self, path: Option<String>) -> Result<()> {
        let path = path.and_then(|p| {
            let trimmed = p.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        });
        let mut state = self.state.lock().unwrap();
        let mut settings = state.settings();
        settings.pg_trusted_ca_bundle_path = path;
        state.settings = Some(settings);
        self.persist(&state)?;
        Ok(())
    }
}

fn validate_connection_name(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        && name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric());
    if ok {
        Ok(())
    } else {
        Err(CoreError::InvalidConnectionName(name.to_string()))
    }
}

/// Validate the type-specific config and resolve the connection's bound
/// secrets: API secret lists are derived from the template's refs; pg/ws
/// bind exactly one secret (DESIGN.md §9).
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
        } => {
            if host.is_empty() || host.contains('/') || host.contains('@') || host.contains(':') {
                return Err(CoreError::InvalidConnectionConfig(format!(
                    "invalid host {host:?} (bare hostname, no scheme/port/path)"
                )));
            }
            if scheme != "https" && scheme != "http" {
                return Err(CoreError::InvalidConnectionConfig(format!(
                    "invalid scheme {scheme:?}"
                )));
            }
            let parsed = Template::parse(template)?;
            let refs = parsed.refs();
            if refs.is_empty() {
                return Err(CoreError::InvalidConnectionConfig(
                    "template references no secret".into(),
                ));
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
                return Err(CoreError::InvalidConnectionConfig(
                    "host, port, database and user are required".into(),
                ));
            }
            bind_single_secret(state, spec)
        }
        ConnectionConfig::Ws { url, template } => {
            let parsed_url = url::Url::parse(url).map_err(|e| {
                CoreError::InvalidConnectionConfig(format!("invalid url {url:?}: {e}"))
            })?;
            match parsed_url.scheme() {
                "ws" | "wss" => {}
                other => {
                    return Err(CoreError::InvalidConnectionConfig(format!(
                        "url scheme must be ws or wss, got {other:?}"
                    )))
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
        ConnectionConfig::Ssh { host, port, user } => {
            if host.is_empty() || host.contains('/') || host.contains('@') || host.contains(':') {
                return Err(CoreError::InvalidConnectionConfig(format!(
                    "invalid host {host:?} (bare hostname, no scheme/port/path)"
                )));
            }
            if user.is_empty() || *port == 0 {
                return Err(CoreError::InvalidConnectionConfig(
                    "host, port and user are required".into(),
                ));
            }
            bind_single_secret(state, spec)
        }
    }
}

fn bind_single_secret(state: &IndexState, spec: &ConnectionSpec) -> Result<Vec<Uuid>> {
    let kind = match spec.config.kind() {
        ConnectionKind::Pg => "postgres",
        ConnectionKind::Ws => "websocket",
        ConnectionKind::Ssh => "ssh",
        ConnectionKind::Api => unreachable!(),
    };
    if spec.secrets.len() != 1 {
        return Err(CoreError::WrongSecretCount { kind });
    }
    let id = spec.secrets[0];
    if !state.secrets.iter().any(|s| s.id == id) {
        return Err(CoreError::SecretNotFound);
    }
    Ok(vec![id])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::PgSslMode;
    use crate::vault::MemoryVault;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use zeroize::Zeroizing;

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
        let store = Store::open(Paths::under(dir.path()), vault.clone()).await.unwrap();
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
            },
            secrets: vec![],
            multi_connect: true,
        }
    }

    #[tokio::test]
    async fn add_list_and_persist_secrets() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Arc::new(MemoryVault::new());
        {
            let store = Store::open(Paths::under(dir.path()), vault.clone()).await.unwrap();
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
        let store = Store::open(Paths::under(dir.path()), vault.clone()).await.unwrap();
        let names: Vec<_> = store.list_secrets().into_iter().map(|s| s.name).collect();
        assert_eq!(names, ["DATABASE_PASSWORD", "GITHUB_API_KEY"]);
        // Two user secrets plus the §13.1 integrity key.
        assert_eq!(vault.len(), 3);
        let gh = store.secret_by_name("GITHUB_API_KEY").unwrap();
        assert_eq!(&*store.secret_value(&gh.id).await.unwrap(), "ghp_secret");
    }

    #[tokio::test]
    async fn reveal_prefix_is_capped() {
        let (store, _, _dir) = store().await;
        let meta = store
            .add_secret("GITHUB_API_KEY", val("ghp_9aXf2Qe7LmNoP3demoToken41c"))
            .unwrap();
        assert_eq!(store.reveal_secret_prefix(&meta.id).await.unwrap(), "ghp_9a…");
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
        // Deleting the connection unblocks the secret; only the §13.1
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
        // api connections never carry multi_connect.
        assert!(!conn.multi_connect);

        // Unknown ref is rejected.
        assert!(matches!(
            store
                .add_connection(api_spec("x", "x.example.com", "Bearer {{NOPE}}"))
                .unwrap_err(),
            CoreError::UnknownTemplateRef(_)
        ));
    }

    #[tokio::test]
    async fn pg_and_ws_bind_exactly_one_secret() {
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
                },
                secrets: vec![pw.id],
                multi_connect: true,
            })
            .unwrap();
        assert!(conn.multi_connect);
        assert_eq!(conn.target(), "app@db.internal.aka.com:5432/app_production");

        assert!(matches!(
            store
                .add_connection(ConnectionSpec {
                    name: "bad".into(),
                    config: ConnectionConfig::Pg {
                        host: "h".into(),
                        port: 5432,
                        dbname: "d".into(),
                        user: "u".into(),
                        sslmode: PgSslMode::Prefer,
                    },
                    secrets: vec![],
                    multi_connect: false,
                })
                .unwrap_err(),
            CoreError::WrongSecretCount { .. }
        ));
    }

    #[tokio::test]
    async fn ssh_binds_exactly_one_secret_and_validates_host() {
        let (store, _, _dir) = store().await;
        let key = store
            .add_secret("DEPLOY_SSH_KEY", val("-----BEGIN OPENSSH PRIVATE KEY-----…"))
            .unwrap();
        let conn = store
            .add_connection(ConnectionSpec {
                name: "prod-ssh".into(),
                config: ConnectionConfig::Ssh {
                    host: "prod.example.com".into(),
                    port: 22,
                    user: "deploy".into(),
                },
                secrets: vec![key.id],
                multi_connect: true,
            })
            .unwrap();
        assert!(conn.multi_connect);
        assert_eq!(conn.target(), "deploy@prod.example.com");

        assert!(matches!(
            store
                .add_connection(ConnectionSpec {
                    name: "no-secret".into(),
                    config: ConnectionConfig::Ssh {
                        host: "h.example.com".into(),
                        port: 22,
                        user: "u".into(),
                    },
                    secrets: vec![],
                    multi_connect: true,
                })
                .unwrap_err(),
            CoreError::WrongSecretCount { kind: "ssh" }
        ));
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
                            host: host.into(),
                            port: 22,
                            user: user.into(),
                        },
                        secrets: vec![key.id],
                        multi_connect: true,
                    })
                    .unwrap_err(),
                CoreError::InvalidConnectionConfig(_)
            ));
        }
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
                multi_connect: true,
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
                    multi_connect: true,
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
    async fn sync_toggle_migrates_vault_items_and_keeps_reauth() {
        let (store, vault, _dir) = store().await;
        let a = store.add_secret("A_KEY", val("a")).unwrap();
        assert_eq!(vault.sync_flag(&a.id), Some(true)); // default on
        assert!(store.settings().reauth_on_read);
        assert_eq!(store.set_icloud_sync(false).await.unwrap(), 1);
        assert_eq!(vault.sync_flag(&a.id), Some(false));
        store.set_reauth_on_read(false).unwrap();
        assert!(!store.settings().reauth_on_read);
        store.set_reauth_on_read(true).unwrap();
        // Turning sync back on keeps read-time re-auth enabled.
        assert_eq!(store.set_icloud_sync(true).await.unwrap(), 1);
        let s = store.settings();
        assert!(s.icloud_sync && s.reauth_on_read);
        assert_eq!(vault.sync_flag(&a.id), Some(true));
        store.set_reauth_on_read(false).unwrap();
        assert!(!store.settings().reauth_on_read);
    }

    /// A vault that fails the `set` for one specific `(id, sync)` exactly
    /// once, delegating everything else to an inner `MemoryVault` — to
    /// simulate a Keychain op failing partway through a sync migration.
    struct FlakyVault {
        inner: MemoryVault,
        fail_once: Mutex<Option<(Uuid, bool)>>,
    }

    impl FlakyVault {
        fn new() -> Self {
            Self {
                inner: MemoryVault::new(),
                fail_once: Mutex::new(None),
            }
        }
        fn arm(&self, id: Uuid, sync: bool) {
            *self.fail_once.lock().unwrap() = Some((id, sync));
        }
        fn sync_flag(&self, id: &Uuid) -> Option<bool> {
            self.inner.sync_flag(id)
        }
    }

    #[async_trait::async_trait]
    impl SecretVault for FlakyVault {
        fn set(&self, id: &Uuid, attrs: &VaultAttrs, value: &SecretValue) -> Result<()> {
            {
                let mut fail = self.fail_once.lock().unwrap();
                if *fail == Some((*id, attrs.sync)) {
                    *fail = None;
                    return Err(CoreError::Vault("simulated keychain failure".into()));
                }
            }
            self.inner.set(id, attrs, value)
        }
        async fn get(&self, id: &Uuid) -> Result<SecretValue> {
            self.inner.get(id).await
        }
        fn delete(&self, id: &Uuid) -> Result<()> {
            self.inner.delete(id)
        }
        fn set_attrs(&self, id: &Uuid, attrs: &VaultAttrs) -> Result<()> {
            self.inner.set_attrs(id, attrs)
        }
    }

    #[tokio::test]
    async fn sync_migration_failure_rolls_back_and_loses_no_values() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Arc::new(FlakyVault::new());
        let store = Store::open(Paths::under(dir.path()), vault.clone())
            .await
            .unwrap();
        let a = store.add_secret("A_KEY", val("a")).unwrap();
        let b = store.add_secret("B_KEY", val("b")).unwrap();
        let c = store.add_secret("C_KEY", val("c")).unwrap();
        // Secrets default to sync=on; toggling off migrates each to sync=off.
        // Make B's re-create under sync=off fail once, midway through.
        vault.arm(b.id, false);

        let err = store.set_icloud_sync(false).await.unwrap_err();
        assert!(matches!(err, CoreError::Vault(_)));

        // The setting is not flipped (all-or-nothing).
        assert!(store.settings().icloud_sync);
        // Every item is back on the original attribute — A was migrated then
        // rolled back, B was restored by migrate_sync, C was never touched.
        assert_eq!(vault.sync_flag(&a.id), Some(true));
        assert_eq!(vault.sync_flag(&b.id), Some(true));
        assert_eq!(vault.sync_flag(&c.id), Some(true));
        // No value was lost anywhere.
        assert_eq!(&*store.secret_value(&a.id).await.unwrap(), "a");
        assert_eq!(&*store.secret_value(&b.id).await.unwrap(), "b");
        assert_eq!(&*store.secret_value(&c.id).await.unwrap(), "c");

        // With no armed failure the toggle now succeeds cleanly.
        assert_eq!(store.set_icloud_sync(false).await.unwrap(), 3);
        assert!(!store.settings().icloud_sync);
        assert_eq!(vault.sync_flag(&a.id), Some(false));
        assert_eq!(vault.sync_flag(&b.id), Some(false));
        assert_eq!(vault.sync_flag(&c.id), Some(false));
    }

    #[tokio::test]
    async fn pg_trusted_ca_bundle_path_persists_and_clears() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Arc::new(MemoryVault::new());
        {
            let store = Store::open(Paths::under(dir.path()), vault.clone()).await.unwrap();
            store
                .set_pg_trusted_ca_bundle_path(Some("  /etc/ssl/private/pg-ca.pem  ".into()))
                .unwrap();
            assert_eq!(
                store.settings().pg_trusted_ca_bundle_path.as_deref(),
                Some("/etc/ssl/private/pg-ca.pem")
            );
        }
        let store = Store::open(Paths::under(dir.path()), vault.clone()).await.unwrap();
        assert_eq!(
            store.settings().pg_trusted_ca_bundle_path.as_deref(),
            Some("/etc/ssl/private/pg-ca.pem")
        );
        store
            .set_pg_trusted_ca_bundle_path(Some(" ".into()))
            .unwrap();
        assert_eq!(store.settings().pg_trusted_ca_bundle_path, None);
    }

    #[tokio::test]
    async fn tampered_index_refuses_to_load() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Arc::new(MemoryVault::new());
        {
            let store = Store::open(Paths::under(dir.path()), vault.clone()).await.unwrap();
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
        // A pre-§13.1 bare index.json, before any integrity key exists.
        std::fs::write(
            paths.index_file(),
            br#"{"secrets": [], "connections": []}"#,
        )
        .unwrap();
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
