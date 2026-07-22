//! The broker facade: one struct owning the store, the shared identity,
//! the per-connection access table, execution machinery and audit log. The
//! daemon (agent-facing) and the shell (UI-facing Tauri commands, tests,
//! dev harness) both drive it.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use uuid::Uuid;

use crate::audit::{AuditEntry, AuditKind, AuditLog};
use crate::config::BrokerConfig;
use crate::error::CoreError;
use crate::events::BrokerEvents;
use crate::executions::Executions;
use crate::identity::IdentityStore;
use crate::paths::{BrokerInstanceLock, Paths};
use crate::policy::AccessTable;
use crate::ratelimit::{KeyedLimiter, WindowLimiter};
use crate::sessions::{DataPlane, SessionInfo};
use crate::store::{ConnectionSpec, Store};
use crate::types::{
    BrokerIdentity, Connection, ConnectionConfig, ConnectionKind, DirectEndpoint, SecretMeta,
    SecretValue, Settings, ToolAccess,
};
use crate::Result;

/// Presence-window lengths the Settings sheet offers: 15 minutes, 1 hour,
/// 2 hours.
pub const PRESENCE_WINDOW_CHOICES: &[u64] = &[15 * 60, 60 * 60, 2 * 60 * 60];

/// Outcome of a UI-initiated connection test: a pass/fail flag plus a short
/// human-readable summary (never credential material).
#[derive(Debug, Clone, serde::Serialize)]
pub struct ConnectionTestReport {
    pub ok: bool,
    pub detail: String,
}

/// The result of issuing a direct endpoint: the pasteable connection string
/// and the one-time secret. The secret is returned exactly once; it is not
/// recoverable afterward (re-issuing rotates it).
#[derive(Debug, Clone, serde::Serialize)]
pub struct IssuedEndpointInfo {
    pub endpoint_id: Uuid,
    pub kind: ConnectionKind,
    /// Pasteable connection string (a Postgres DSN today).
    pub dsn: String,
    /// The one-time secret to supply out-of-band (`PGPASSWORD`).
    pub secret: String,
    /// Ready-to-adapt invocation, e.g. `PGPASSWORD=… psql "…"`.
    pub example: String,
}

pub struct Broker {
    pub config: BrokerConfig,
    pub paths: Paths,
    pub store: Arc<Store>,
    /// Per-connection agent access: the whole authorization model.
    pub access: Arc<AccessTable>,
    /// Per-connection direct endpoints (stable DSN/URL issuance). Bounds and
    /// teardown ride alongside the access table.
    pub endpoints: Arc<crate::endpoints::EndpointRegistry>,
    /// Live endpoint listeners, keyed on endpoint id. Runtime only:
    /// re-established from `endpoints` at daemon start, stopped on teardown.
    endpoint_listeners: Mutex<HashMap<Uuid, crate::endpoints::EndpointListenerHandle>>,
    /// Serializes configuration mutations that read-then-write shared state
    /// (connection edits, access changes) so concurrent UI actions cannot
    /// interleave.
    pub(crate) config_gate: Mutex<()>,
    /// The shared local identity ("this computer's key").
    pub identity: Arc<IdentityStore>,
    pub executions: Executions,
    /// Runtime that owns broker background work. UI entry points can be
    /// called from threads without an entered Tokio context (notably
    /// synchronous Tauri commands), so they must not rely on
    /// `tokio::spawn` finding the caller's runtime.
    task_runtime: tokio::runtime::Handle,
    pub audit: Arc<AuditLog>,
    pub events: Arc<dyn BrokerEvents>,
    /// Last-known per-connection health (tests + brokered-call outcomes).
    pub health: Arc<crate::health::HealthRegistry>,
    /// Tickets + live WS/PG sessions.
    pub data_plane: DataPlane,
    /// The sidecar's loopback MCP port, reported by the shell that
    /// supervises it (restarts move it; `None` while it is not running).
    /// Advertised in the discovery manifest so `aka mcp` and other bridges
    /// can find the MCP endpoint without a config file.
    sidecar_mcp_port: Mutex<Option<u16>>,
    /// The WS bridge's ephemeral loopback port, set when the daemon starts;
    /// surfaced only in open responses.
    pub(crate) ws_bridge_port: std::sync::OnceLock<u16>,
    /// The PG proxy's ephemeral loopback port, set when the daemon starts;
    /// surfaced only in open responses' DSNs.
    pub(crate) pg_proxy_port: std::sync::OnceLock<u16>,
    pub(crate) http_client: reqwest::Client,
    /// Admission backstop acquired before direct HTTP request bodies are
    /// read. Each listener has a narrower semaphore as well.
    pub(crate) endpoint_uploads: Arc<tokio::sync::Semaphore>,
    /// Live and recently finished MCP sign-in sessions (`mcp_auth` module).
    pub mcp_auth: crate::mcp_auth::McpAuthSessions,
    /// Recent agent connect-requests, so a retrying agent cannot spam the
    /// activity log or the shell's attention. Keyed on the self-reported
    /// client label. Never leaves memory.
    connect_request_debounce: Mutex<std::collections::HashMap<(String, String), Instant>>,
    pub(crate) token_limiter: KeyedLimiter,
    pub(crate) discovery_limiter: WindowLimiter,
    pub(crate) pairing_limiter: WindowLimiter,
    /// Acquired before any persistent state is opened and declared last so it
    /// remains held while every state-owning field is dropped.
    _instance_lock: BrokerInstanceLock,
}

impl Broker {
    /// Must be constructed inside a tokio runtime (executions spawn tasks;
    /// the integrity key loads through the async vault read path).
    pub async fn new(
        paths: Paths,
        vault: Arc<dyn crate::vault::SecretVault>,
        config: BrokerConfig,
        events: Arc<dyn BrokerEvents>,
    ) -> Result<Arc<Self>> {
        paths.ensure()?;
        let instance_lock = paths
            .try_acquire_broker_lock()?
            .ok_or_else(|| CoreError::BrokerAlreadyRunning(paths.socket_display()))?;
        reject_legacy_live_socket(&paths).await?;
        let audit = Arc::new(AuditLog::open(paths.audit_file())?);
        {
            let events = events.clone();
            audit.subscribe(move |entry| events.audit_appended(entry));
        }
        // One integrity key seals every state file: index.json,
        // access.json, and identity.json refuse to load if tampered with.
        let integrity = Arc::new(crate::integrity::StateIntegrity::open(&*vault).await?);
        let store = Arc::new(Store::open_with_events(
            paths.clone(),
            vault,
            events.clone(),
            integrity.clone(),
        )?);
        let identity = Arc::new(IdentityStore::open(
            paths.identity_file(),
            paths.token_file(),
            Some(&paths.agents_file()),
            config.token_ttl,
            integrity.clone(),
        )?);
        let endpoints = Arc::new(crate::endpoints::EndpointRegistry::open(
            paths.endpoints_file(),
            config.max_endpoints,
            integrity.clone(),
        )?);
        // The per-agent wirings collapse needs the connection list so
        // never-wired connections migrate as disabled (the old default)
        // rather than inheriting the new enabled-by-default.
        let known_connections: Vec<Uuid> =
            store.list_connections().into_iter().map(|c| c.id).collect();
        let access = Arc::new(AccessTable::open_with_legacy_policy(
            paths.access_file(),
            Some(&paths.wirings_file()),
            Some(&paths.rules_file()),
            &known_connections,
            integrity,
        )?);
        let executions = Executions::new(
            config.outcome_retention,
            config.outcome_retention_max_entries,
            config.outcome_retention_max_bytes,
        );
        let task_runtime = tokio::runtime::Handle::current();
        let http_client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none()) // hand-rolled loop
            .build()
            .map_err(|e| CoreError::Vault(format!("http client: {e}")))?;
        let data_plane = DataPlane::new(
            config.ticket_ttl,
            config.per_ticket_sessions,
            config.global_sessions,
            audit.clone(),
            events.clone(),
        );
        let health = Arc::new(crate::health::HealthRegistry::open(
            paths.health_file(),
            events.clone(),
        ));
        let endpoint_uploads =
            Arc::new(tokio::sync::Semaphore::new(config.endpoint_global_uploads));
        let broker = Arc::new(Self {
            data_plane,
            mcp_auth: crate::mcp_auth::McpAuthSessions::default(),
            connect_request_debounce: Mutex::new(std::collections::HashMap::new()),
            sidecar_mcp_port: Mutex::new(None),
            ws_bridge_port: std::sync::OnceLock::new(),
            pg_proxy_port: std::sync::OnceLock::new(),
            token_limiter: KeyedLimiter::new(
                config.per_identity_per_min,
                std::time::Duration::from_secs(60),
            ),
            discovery_limiter: WindowLimiter::new(
                config.discovery_per_min,
                std::time::Duration::from_secs(60),
            ),
            pairing_limiter: WindowLimiter::new(config.pairing_max_attempts, config.pairing_window),
            config,
            paths,
            store,
            access,
            endpoints,
            endpoint_listeners: Mutex::new(HashMap::new()),
            endpoint_uploads,
            config_gate: Mutex::new(()),
            identity,
            executions,
            task_runtime,
            audit,
            events,
            health,
            http_client,
            _instance_lock: instance_lock,
        });
        // Keeps OAuth-minted MCP access tokens fresh in the background; the
        // task holds only a weak reference and exits when the broker drops.
        crate::mcp_refresh::spawn_refresh_sweeper(&broker);
        Ok(broker)
    }

    pub(crate) fn task_runtime(&self) -> tokio::runtime::Handle {
        self.task_runtime.clone()
    }

    /// Report where the sidecar's MCP endpoint is listening (`None` when it
    /// stopped). Called by the shell supervising the sidecar; the discovery
    /// manifest advertises it.
    pub fn set_sidecar_mcp_port(&self, port: Option<u16>) {
        *self.sidecar_mcp_port.lock().unwrap() = port;
    }

    /// The sidecar's MCP URL, when one is running.
    pub fn sidecar_mcp_url(&self) -> Option<String> {
        self.sidecar_mcp_port
            .lock()
            .unwrap()
            .map(|port| format!("http://127.0.0.1:{port}/mcp"))
    }

    /// Demand the shell's native confirmation, regardless of the presence
    /// window. Fails closed when the shell refuses or does not implement the
    /// gate. Every action that grants an agent new authority goes through
    /// here; async callers run this same serialized store gate off-runtime.
    /// A successful prompt opens the user-plane presence window (see
    /// `Store::confirm_action`), so a following read or config change rides it.
    fn confirm_action(&self, description: &str) -> Result<crate::types::ConfirmationMethod> {
        self.store.confirm_action(description)
    }

    /// Confirm a user-plane configuration action (tool and secret CRUD):
    /// rides the presence window when it is fresh, otherwise prompts and
    /// opens it. Never used for granting an agent authority.
    fn confirm_user_action(&self, description: &str) -> Result<crate::types::ConfirmationMethod> {
        self.store.confirm_configuration_action(description)
    }

    /* ----------------------- secrets (UI commands) ------------------------ */

    pub fn ui_add_secret(&self, name: &str, value: SecretValue) -> Result<SecretMeta> {
        let meta = self.store.add_secret(name, value)?;
        self.audit.append(AuditEntry::new(
            AuditKind::SecretAdded,
            format!("Secret added: {name}"),
        ));
        Ok(meta)
    }

    /// The Edit-secret sheet: rename and/or replace the value; blank value
    /// keeps the current one.
    pub fn ui_edit_secret(
        &self,
        id: &Uuid,
        new_name: Option<&str>,
        new_value: Option<SecretValue>,
    ) -> Result<SecretMeta> {
        let _gate = self.config_gate.lock().unwrap();
        let mut meta = self.store.secret_by_id(id)?;
        let mut changes = Vec::new();
        let mut rename: Option<(String, String, usize)> = None;
        if let Some(new_name) = new_name {
            if new_name != meta.name {
                let old = meta.name.clone();
                let (updated, rewritten) = self.store.rename_secret(id, new_name)?;
                meta = updated;
                changes.push(if rewritten > 0 {
                    format!(
                        "renamed {old} → {new_name} ({rewritten} template{} rewritten)",
                        if rewritten == 1 { "" } else { "s" }
                    )
                } else {
                    format!("renamed {old} → {new_name}")
                });
                rename = Some((old, new_name.to_string(), rewritten));
            }
        }
        let value_replaced = new_value.is_some();
        if let Some(value) = new_value {
            meta = self.store.replace_secret_value(id, value)?;
            changes.push("value replaced".into());
        }
        if !changes.is_empty() {
            let mut entry = AuditEntry::new(
                AuditKind::SecretUpdated,
                format!("Secret updated: {}", meta.name),
            )
            .detail(changes.join(" · "))
            .field("value_replaced", value_replaced);
            if let Some((from, to, rewritten)) = rename {
                entry = entry
                    .field("renamed_from", from)
                    .field("renamed_to", to)
                    .field("templates_rewritten", rewritten);
            }
            self.audit.append(entry);
        }
        Ok(meta)
    }

    pub fn ui_delete_secret(&self, id: &Uuid) -> Result<SecretMeta> {
        let meta = self.store.secret_by_id(id)?;
        // Refuse in-use deletion *before* the confirmation, so the user is
        // never asked to authenticate an action that cannot proceed.
        let users = self.store.connections_using(id);
        if !users.is_empty() {
            return Err(CoreError::SecretInUse(users));
        }
        let confirmation =
            self.confirm_user_action(&format!("Delete secret “{}” from the Keychain", meta.name))?;
        let meta = self.store.delete_secret(id)?;
        self.audit.append(
            AuditEntry::new(
                AuditKind::SecretDeleted,
                format!("Secret deleted: {}", meta.name),
            )
            .detail("Removed from Keychain")
            .confirmation(confirmation),
        );
        Ok(meta)
    }

    /// Core-side reveal: only the short prefix ever leaves.
    pub async fn ui_reveal_secret_prefix(&self, id: &Uuid) -> Result<String> {
        self.store.reveal_secret_prefix(id).await
    }

    /// Fetch a value for the shell's core-side clipboard copy. A successful
    /// OS authentication opens (or a fresh one extends) the presence window;
    /// agent executions keep their own authorization scopes.
    pub async fn ui_secret_value_for_copy(&self, id: &Uuid) -> Result<SecretValue> {
        if !self.store.settings().reauth_on_read {
            return self.store.secret_value(id).await;
        }
        let meta = self.store.secret_by_id(id)?;
        self.store.confirm_secret_copy(meta).await?;
        crate::authorization::scope(true, self.store.secret_value(id)).await
    }

    /// Audit trail for the core-side clipboard copy; the shell owns the
    /// actual pasteboard write and hygiene.
    pub fn ui_note_secret_copied(&self, id: &Uuid) -> Result<()> {
        let meta = self.store.secret_by_id(id)?;
        self.audit.append(AuditEntry::new(
            AuditKind::SecretCopied,
            format!("Secret copied: {}", meta.name),
        ));
        Ok(())
    }

    /* --------------------- connections (UI commands) ---------------------- */

    /// A connection binds a secret to a destination, so creating one is not
    /// completable without the native confirmation the core demands.
    pub fn ui_add_connection(&self, spec: ConnectionSpec) -> Result<Connection> {
        // Reject invalid or already-stale input before asking the user to
        // authenticate. `add_connection` repeats the state-dependent checks
        // after confirmation in case the index changed while the sheet was up.
        self.store.preflight_add_connection(&spec)?;
        let confirmation = self.confirm_user_action(&format!("Add tool “{}”", spec.name))?;
        let conn = self.store.add_connection(spec)?;
        self.audit.append(
            AuditEntry::new(
                AuditKind::ConnectionAdded,
                format!("Tool added: {}", conn.name),
            )
            .connection(conn.name.clone())
            .detail(format!("{} → {}", conn.kind().label(), conn.target()))
            .field("kind", conn.kind().as_str())
            .field("target", conn.target())
            .confirmation(confirmation),
        );
        Ok(conn)
    }

    /// One connection-first setup action: save a new credential and bind it
    /// without exposing an intermediate, partially configured state.
    pub fn ui_add_connection_with_secret(
        &self,
        secret_name: &str,
        value: SecretValue,
        spec: ConnectionSpec,
    ) -> Result<Connection> {
        self.store
            .preflight_add_connection_with_secret(secret_name, &spec)?;
        let confirmation = self.confirm_user_action(&format!("Add tool “{}”", spec.name))?;
        let (secret, conn) = self
            .store
            .add_connection_with_secret(secret_name, value, spec)?;
        self.audit.append(AuditEntry::new(
            AuditKind::SecretAdded,
            format!("Secret added: {}", secret.name),
        ));
        self.audit.append(
            AuditEntry::new(
                AuditKind::ConnectionAdded,
                format!("Tool added: {}", conn.name),
            )
            .connection(conn.name.clone())
            .detail(format!("{} → {}", conn.kind().label(), conn.target()))
            .field("kind", conn.kind().as_str())
            .field("target", conn.target())
            .confirmation(confirmation),
        );
        Ok(conn)
    }

    /// Update a connection. Name-only edits are metadata and do not require
    /// native authentication; changes to configuration, secret bindings, or
    /// authentication do. When the pinned target changes, its wirings are
    /// dropped: a wiring granted for one destination must not silently cover
    /// another.
    pub fn ui_update_connection(&self, id: &Uuid, spec: ConnectionSpec) -> Result<Connection> {
        let old = self.store.connection_by_id(id)?;
        let explicit_secrets_changed =
            old.kind() != ConnectionKind::Api && old.secrets != spec.secrets;
        let capability_changed = old.config != spec.config || explicit_secrets_changed;
        let confirmation = if capability_changed {
            Some(self.confirm_user_action(&format!(
                "Change security settings for tool “{}”",
                spec.name
            ))?)
        } else {
            None
        };
        let _gate = self.config_gate.lock().unwrap();
        if self.store.connection_by_id(id)?.updated_at != old.updated_at {
            return Err(CoreError::ApprovalConnectionChanged);
        }
        let (conn, target_changed) = if capability_changed {
            self.store.update_connection(id, spec)?
        } else {
            (self.store.rename_connection(id, spec.name)?, false)
        };
        let mut dropped = 0;
        if target_changed {
            // The enabled/disabled flag names the *tool* and survives a
            // retarget (a disabled tool must not silently re-enable), but a
            // curated MCP tool subset names the old upstream's tools and its
            // direct endpoints grant standing access to the old destination:
            // both die with the retarget.
            let tools_cleared = self.access.set_allowed_tools(*id, None)?;
            dropped = usize::from(tools_cleared);
            let endpoints = self.endpoints.remove_for_connection(id)?;
            self.teardown_endpoints(&endpoints);
            if tools_cleared || !endpoints.is_empty() {
                self.events.wirings_changed();
            }
            // A health result for the old destination says nothing about
            // the new one.
            self.health.forget(id);
        }
        let mut entry = AuditEntry::new(
            AuditKind::ConnectionUpdated,
            format!(
                "Tool updated: {}",
                if old.name != conn.name {
                    format!("{} → {}", old.name, conn.name)
                } else {
                    conn.name.clone()
                }
            ),
        )
        .connection(conn.name.clone())
        .detail(format!(
            "{}{}",
            conn.target(),
            if dropped > 0 {
                " · tool selection reset (target changed)".to_string()
            } else {
                String::new()
            }
        ))
        .field("target", conn.target())
        .field("target_changed", target_changed)
        .field("capability_changed", capability_changed)
        .field("tool_selection_reset", dropped > 0);
        if let Some(confirmation) = confirmation {
            entry = entry.confirmation(confirmation);
        }
        if old.name != conn.name {
            entry = entry
                .field("renamed_from", old.name.clone())
                .field("renamed_to", conn.name.clone());
        }
        self.audit.append(entry);
        Ok(conn)
    }

    /// Delete a connection; wirings die with it.
    pub fn ui_delete_connection(&self, id: &Uuid) -> Result<Connection> {
        let conn = self.store.connection_by_id(id)?;
        let confirmation = self.confirm_user_action(&format!("Delete tool “{}”", conn.name))?;
        let _gate = self.config_gate.lock().unwrap();
        if self.store.connection_by_id(id)?.updated_at != conn.updated_at {
            return Err(CoreError::ApprovalConnectionChanged);
        }
        let conn = self.store.delete_connection(id)?;
        self.health.forget(id);
        let dropped = self.access.remove_for_connection(id)?;
        let endpoints = self.endpoints.remove_for_connection(id)?;
        self.teardown_endpoints(&endpoints);
        if dropped || !endpoints.is_empty() {
            self.events.wirings_changed();
        }
        self.audit.append(
            AuditEntry::new(
                AuditKind::ConnectionDeleted,
                format!("Tool deleted: {}", conn.name),
            )
            .connection(conn.name.clone())
            .confirmation(confirmation),
        );
        Ok(conn)
    }

    /// UI-initiated connectivity/credential test against the connection's
    /// pinned destination. The credential travels only on the upstream leg,
    /// exactly as it would for a brokered agent request; only a pass/fail
    /// summary comes back.
    pub async fn ui_test_connection(&self, id: &Uuid) -> Result<ConnectionTestReport> {
        const TEST_TIMEOUT: Duration = Duration::from_secs(15);
        let mut connection = self.store.connection_by_id(id)?;
        // An OAuth token at expiry is renewed before the test, so the test
        // grades the connection, not a token the broker knew was stale.
        if crate::mcp_refresh::wants_refresh(&connection)
            && crate::mcp_refresh::refresh_connection_token(
                &self.refresh_context(),
                id,
                crate::mcp_refresh::RefreshMode::IfStale,
            )
            .await
            .is_ok()
        {
            connection = self.store.connection_by_id(id)?;
        }
        let connection = connection;
        let test = async {
            match connection.config.kind() {
                ConnectionKind::Api => {
                    crate::capability::http::test_upstream(
                        &self.store,
                        &self.http_client,
                        TEST_TIMEOUT,
                        &connection,
                    )
                    .await
                }
                ConnectionKind::Pg => {
                    crate::capability::pg::test_upstream(&self.store, &self.events, &connection)
                        .await
                }
                ConnectionKind::Ws => {
                    crate::capability::ws::test_upstream(&self.store, &connection).await
                }
                ConnectionKind::Ssh => {
                    crate::capability::ssh::test_reachability(&self.store, &connection).await
                }
            }
        };
        // One authorization scope per test: a template referencing several
        // secrets confirms once, not once per secret — and within the
        // presence window (which the save preceding an automatic post-save
        // test refreshed) not at all.
        let test = crate::authorization::scope(false, test);
        let outcome = match tokio::time::timeout(TEST_TIMEOUT, test).await {
            Ok(result) => result,
            Err(_) => Err(format!(
                "no answer within {} seconds",
                TEST_TIMEOUT.as_secs()
            )),
        };
        let (ok, detail) = match outcome {
            Ok(detail) => (true, detail),
            Err(detail) => (false, detail),
        };
        // The test result is the connection's new last-known health. A
        // credential rejection reads as "reconnect", not "retry".
        let status = if ok {
            crate::types::HealthStatus::Ok
        } else if detail.contains("rejected the credential")
            || detail.contains("password authentication failed")
        {
            crate::types::HealthStatus::NeedsReconnect
        } else {
            crate::types::HealthStatus::Failed
        };
        self.health.record(id, status, detail.clone());
        Ok(ConnectionTestReport { ok, detail })
    }

    /* ---------------------- OAuth (BYO app, REST rows) --------------------- */

    /// Connect a new OAuth tool: confirm, open the provider's consent page
    /// in the user's browser, catch the loopback redirect, exchange the
    /// code (PKCE), and store the token set + connection atomically. The
    /// token secret named `secret_name` is what the connection's template
    /// references; the tokens never leave the vault.
    pub async fn ui_oauth_connect(
        &self,
        secret_name: &str,
        client_secret: Option<SecretValue>,
        spec: ConnectionSpec,
    ) -> Result<Connection> {
        let crate::types::ConnectionConfig::Api {
            oauth: Some(oauth_spec),
            mcp_path: None,
            ..
        } = spec.config.clone()
        else {
            return Err(CoreError::InvalidConnectionConfig(
                "OAuth connect requires a plain api config with an oauth section                  (MCP servers use the sign-in flow instead)"
                    .into(),
            ));
        };
        self.store
            .preflight_add_connection_with_secret(secret_name, &spec)?;
        let confirmation =
            self.confirm_user_action(&format!("Connect “{}” with your browser", spec.name))?;
        let pending = crate::oauth::begin(&oauth_spec)
            .await
            .map_err(CoreError::OAuth)?;
        if !self.events.open_external_url(&pending.authorize_url) {
            return Err(CoreError::OAuth(format!(
                "could not open the browser; open this URL yourself: {}",
                pending.authorize_url
            )));
        }
        let tokens = crate::oauth::finish(pending, &oauth_spec, client_secret, &self.http_client)
            .await
            .map_err(CoreError::OAuth)?;
        let (_, conn) =
            self.store
                .add_connection_with_secret(secret_name, tokens.to_secret_value(), spec)?;
        self.health.record(
            &conn.id,
            crate::types::HealthStatus::Ok,
            "Connected via OAuth",
        );
        self.audit.append(
            AuditEntry::new(
                AuditKind::ConnectionAdded,
                format!("Tool connected via OAuth: {}", conn.name),
            )
            .connection(conn.name.clone())
            .detail(format!("{} → {}", conn.kind().label(), conn.target()))
            .field("kind", conn.kind().as_str())
            .field("target", conn.target())
            .field("oauth", true)
            .confirmation(confirmation),
        );
        self.events.connections_changed();
        Ok(conn)
    }

    /// Re-run the OAuth flow for an existing connection whose token was
    /// rejected or expired, replacing the stored token set in place.
    pub async fn ui_oauth_reconnect(&self, id: &Uuid) -> Result<Connection> {
        let conn = self.store.connection_by_id(id)?;
        let crate::types::ConnectionConfig::Api {
            oauth: Some(oauth_spec),
            ..
        } = conn.config.clone()
        else {
            return Err(CoreError::InvalidConnectionConfig(
                "this tool is not an OAuth connection".into(),
            ));
        };
        let secret_id = *conn.secrets.first().ok_or_else(|| {
            CoreError::InvalidConnectionConfig("the OAuth connection has no token secret".into())
        })?;
        let confirmation =
            self.confirm_user_action(&format!("Reconnect “{}” with your browser", conn.name))?;
        // Carry the client secret across (BYO apps that require one at the
        // token endpoint); the old tokens are replaced wholesale.
        let previous = self
            .store
            .secret_value(&secret_id)
            .await
            .ok()
            .and_then(|value| crate::oauth::TokenSet::from_secret_value(&value).ok());
        let client_secret = previous
            .and_then(|tokens| tokens.client_secret)
            .map(zeroize::Zeroizing::new);
        let pending = crate::oauth::begin(&oauth_spec)
            .await
            .map_err(CoreError::OAuth)?;
        if !self.events.open_external_url(&pending.authorize_url) {
            return Err(CoreError::OAuth(format!(
                "could not open the browser; open this URL yourself: {}",
                pending.authorize_url
            )));
        }
        let tokens = crate::oauth::finish(pending, &oauth_spec, client_secret, &self.http_client)
            .await
            .map_err(CoreError::OAuth)?;
        self.store
            .replace_secret_value(&secret_id, tokens.to_secret_value())?;
        self.health.record(
            &conn.id,
            crate::types::HealthStatus::Ok,
            "Reconnected via OAuth",
        );
        self.audit.append(
            AuditEntry::new(
                AuditKind::ConnectionUpdated,
                format!("Tool reconnected via OAuth: {}", conn.name),
            )
            .connection(conn.name.clone())
            .field("oauth", true)
            .confirmation(confirmation),
        );
        self.events.connections_changed();
        Ok(conn)
    }

    /// UI-initiated MCP status check: reach the connection's MCP endpoint
    /// with its own injected credential, acknowledge the account (via the
    /// template's whoami tool, when one is configured), list tools against
    /// the template's expectations, and enumerate resources. The account is
    /// persisted on the connection so several connections to the same
    /// service stay tellable apart; only the summary reaches the webview.
    pub async fn ui_mcp_check(
        &self,
        id: &Uuid,
        options: crate::mcp::McpCheckOptions,
    ) -> Result<crate::mcp::McpStatusReport> {
        const CHECK_TIMEOUT: Duration = Duration::from_secs(45);
        let mut connection = self.store.connection_by_id(id)?;
        // An access token at (or past) expiry is renewed silently before
        // the check, so an aged token reads as healthy rather than
        // "credential rejected".
        let mut refreshed = false;
        if crate::mcp_refresh::wants_refresh(&connection)
            && crate::mcp_refresh::refresh_connection_token(
                &self.refresh_context(),
                id,
                crate::mcp_refresh::RefreshMode::IfStale,
            )
            .await
            .is_ok()
        {
            connection = self.store.connection_by_id(id)?;
            refreshed = true;
        }
        let mut report = match tokio::time::timeout(
            CHECK_TIMEOUT,
            crate::mcp::check_connection(&self.store, &self.http_client, &connection, &options),
        )
        .await
        {
            Ok(report) => report,
            Err(_) => crate::mcp::McpStatusReport::timed_out(CHECK_TIMEOUT),
        };
        // Rescue: a rejected credential on an OAuth connection usually just
        // means the token aged out between sweeps — renew and retry once
        // instead of sending the user through the browser again.
        if !report.ok
            && report.credential_rejected
            && !refreshed
            && crate::mcp_refresh::refresh_connection_token(
                &self.refresh_context(),
                id,
                crate::mcp_refresh::RefreshMode::Force,
            )
            .await
            .is_ok()
        {
            connection = self.store.connection_by_id(id)?;
            report = match tokio::time::timeout(
                CHECK_TIMEOUT,
                crate::mcp::check_connection(&self.store, &self.http_client, &connection, &options),
            )
            .await
            {
                Ok(report) => report,
                Err(_) => crate::mcp::McpStatusReport::timed_out(CHECK_TIMEOUT),
            };
        }
        if report.ok && report.account.is_some() && report.account != connection.account {
            self.store
                .set_connection_account(id, report.account.clone())?;
            self.events.connections_changed();
        }
        // The check's verdict is the connection's new last-known health.
        let status = if report.ok {
            crate::types::HealthStatus::Ok
        } else if report.credential_rejected {
            crate::types::HealthStatus::NeedsReconnect
        } else {
            crate::types::HealthStatus::Failed
        };
        self.health.record(id, status, report.detail.clone());
        Ok(report)
    }

    /* ------------------------ agent connect requests ----------------------- */

    /// An agent asked for a service that is not configured (the sidecar's
    /// `multitool_connect` tool). This records the ask and pokes the shell
    /// so the user can add the tool — nothing is created or granted here,
    /// and the same client label asking for the same service within a minute
    /// is coalesced. Returns whether this call surfaced a fresh request.
    pub fn agent_connect_request(&self, client: &str, service: &str) -> Result<bool> {
        const DEBOUNCE: Duration = Duration::from_secs(60);
        let service = service.trim();
        if service.is_empty()
            || service.len() > 120
            || !service.chars().all(|c| c.is_ascii_graphic() || c == ' ')
        {
            return Err(CoreError::InvalidConnectionConfig(
                "the requested service name must be short printable text".into(),
            ));
        }
        {
            let mut recent = self.connect_request_debounce.lock().unwrap();
            let now = Instant::now();
            recent.retain(|_, at| now.duration_since(*at) < DEBOUNCE);
            let key = (client.to_string(), service.to_ascii_lowercase());
            if recent.contains_key(&key) {
                return Ok(false);
            }
            recent.insert(key, now);
        }
        self.audit.append(
            AuditEntry::new(
                AuditKind::ConnectRequested,
                format!("{client} asked to connect: {service}"),
            )
            .agent(client.to_string())
            .detail("A request only — add the tool in Multitool to grant it")
            .field("service", service),
        );
        self.events.connect_requested(client, service);
        Ok(true)
    }

    /* ------------------------- agent access (UI) --------------------------- */

    /// Every recorded access entry, for the app's tool rows. Connections
    /// with no entry are in the default state (enabled, all tools).
    pub fn tool_access(&self) -> Vec<ToolAccess> {
        self.access.entries()
    }

    /// Every issued direct endpoint, for the app's tool rows.
    pub fn endpoints(&self) -> Vec<DirectEndpoint> {
        self.endpoints.list()
    }

    /// Issue (or rotate) a direct endpoint for a connection: mint the
    /// endpoint secret, bind its listener, and hand back the pasteable DSN.
    /// The secret leaves the broker exactly once, here. Gated behind the
    /// native confirmation because it grants standing access; the
    /// connection's agent access must be enabled.
    pub async fn ui_issue_endpoint(
        self: &Arc<Self>,
        connection_id: &Uuid,
    ) -> Result<IssuedEndpointInfo> {
        let connection = self.store.connection_by_id(connection_id)?;
        // Direct endpoints exist for Postgres, SSH, and HTTP; WebSocket later.
        match connection.kind() {
            ConnectionKind::Pg | ConnectionKind::Ssh | ConnectionKind::Api => {}
            other => return Err(CoreError::EndpointUnsupportedKind(other.label())),
        }
        if !self.access.allows(connection_id) {
            return Err(CoreError::EndpointRequiresWiring);
        }

        // Confirm off the async runtime: the native sheet blocks its thread.
        let store = self.store.clone();
        let description = format!("Issue a direct endpoint for {}", connection.name);
        let confirmation = tokio::task::spawn_blocking(move || store.confirm_action(&description))
            .await
            .map_err(|e| CoreError::Vault(format!("confirmation task failed: {e}")))??;
        // Mint under the gate; re-check access didn't vanish while the
        // sheet was up. Rotating a live endpoint changes only its persisted
        // secret: the listener resolves the registry on every request, so
        // rebinding would collide with our own occupied port and destroy a
        // healthy endpoint.
        let (issued, listener_already_live) = {
            let _gate = self.config_gate.lock().unwrap();
            if !self.access.allows(connection_id) {
                return Err(CoreError::EndpointRequiresWiring);
            }
            let existing = self.endpoints.get_for_connection(connection_id);
            let listener_already_live = existing.as_ref().is_some_and(|endpoint| {
                self.endpoint_listeners
                    .lock()
                    .unwrap()
                    .contains_key(&endpoint.id)
            });
            (
                self.endpoints.issue(*connection_id, connection.kind())?,
                listener_already_live,
            )
        };

        if !listener_already_live {
            // Bind the listener outside the gate (it awaits). A bind failure
            // revokes the record so a port conflict can never leave a valid
            // credential pointing at another process.
            if let Err(error) = self
                .bind_endpoint_listener(&issued.endpoint, &connection)
                .await
            {
                let _ = self.endpoints.revoke(&issued.endpoint.id);
                return Err(CoreError::Io(error));
            }
        }

        let dir = self.paths.endpoint_dir(&issued.endpoint.id);
        let info = match &connection.config {
            ConnectionConfig::Pg { user, dbname, .. } => {
                let dsn = crate::capability::pg::endpoint_dsn(dir.as_path(), user, dbname);
                let example = format!("PGPASSWORD={} psql \"{dsn}\"", issued.secret);
                IssuedEndpointInfo {
                    endpoint_id: issued.endpoint.id,
                    kind: ConnectionKind::Pg,
                    dsn,
                    secret: issued.secret,
                    example,
                }
            }
            ConnectionConfig::Ssh {
                user,
                host,
                port,
                destination,
                ..
            } => {
                let sock = dir
                    .join(crate::capability::ssh::ENDPOINT_SOCK)
                    .display()
                    .to_string();
                let target = match destination {
                    Some(dest) => format!("ssh {dest}"),
                    None if *port == 22 => format!("ssh {user}@{host}"),
                    None => format!("ssh -p {port} {user}@{host}"),
                };
                // SSH has no presented secret: the ssh-agent protocol offers no
                // password, so the socket path is the whole capability. The
                // minted secret is not surfaced.
                IssuedEndpointInfo {
                    endpoint_id: issued.endpoint.id,
                    kind: ConnectionKind::Ssh,
                    dsn: sock.clone(),
                    secret: String::new(),
                    example: format!("SSH_AUTH_SOCK=\"{sock}\" {target}"),
                }
            }
            ConnectionConfig::Api { .. } => {
                // The loopback port was assigned (and persisted) during bind.
                let port = self
                    .endpoints
                    .get(&issued.endpoint.id)
                    .and_then(|e| e.port)
                    .ok_or_else(|| CoreError::Vault("http endpoint bound no port".to_string()))?;
                let base = format!("http://127.0.0.1:{port}");
                IssuedEndpointInfo {
                    endpoint_id: issued.endpoint.id,
                    kind: ConnectionKind::Api,
                    dsn: base.clone(),
                    secret: issued.secret.clone(),
                    // The secret rides an Authorization header, not the URL, so
                    // it stays out of argv and shell history; the proxy strips
                    // it and injects the real credential upstream.
                    example: format!(
                        "curl -H \"Authorization: Bearer {}\" {base}/<path>",
                        issued.secret
                    ),
                }
            }
            ConnectionConfig::Ws { .. } => unreachable!("kind checked above"),
        };
        self.audit.append(
            AuditEntry::new(
                AuditKind::Wired,
                format!("Direct endpoint issued: {}", connection.name),
            )
            .connection(connection.name.clone())
            .confirmation(confirmation)
            .field("endpoint_id", issued.endpoint.id.to_string())
            .field("kind", connection.kind().as_str()),
        );
        self.events.wirings_changed();
        Ok(info)
    }

    /// Revoke one direct endpoint: drop the record, stop its listener, and
    /// close any live sessions it was serving.
    pub fn ui_revoke_endpoint(&self, endpoint_id: &Uuid) -> Result<bool> {
        let _gate = self.config_gate.lock().unwrap();
        let Some(endpoint) = self.endpoints.revoke(endpoint_id)? else {
            return Ok(false);
        };
        self.teardown_endpoints(std::slice::from_ref(&endpoint));
        let connection = self
            .store
            .connection_by_id(&endpoint.connection_id)
            .map(|c| c.name)
            .unwrap_or_else(|_| "removed tool".to_string());
        self.audit.append(
            AuditEntry::new(
                AuditKind::Unwired,
                format!("Direct endpoint revoked: {connection}"),
            )
            .connection(connection.clone())
            .field("endpoint_id", endpoint.id.to_string()),
        );
        self.events.wirings_changed();
        Ok(true)
    }

    /// Re-establish every persisted endpoint's listener at daemon start.
    /// Endpoints whose connection has since disappeared or changed kind are
    /// stale and dropped rather than rebound.
    pub async fn rebind_endpoints(self: &Arc<Self>) {
        for endpoint in self.endpoints.list() {
            if self
                .endpoint_listeners
                .lock()
                .unwrap()
                .contains_key(&endpoint.id)
            {
                continue;
            }
            match self.store.connection_by_id(&endpoint.connection_id) {
                Ok(connection) if connection.kind() == endpoint.kind => {
                    if let Err(error) = self.bind_endpoint_listener(&endpoint, &connection).await {
                        // A persisted port owned by another process is not a
                        // harmless degraded state: clients would send their
                        // still-valid endpoint secret to that listener. Make
                        // the credential invalid before continuing startup.
                        tracing::error!(
                            "revoking endpoint {} after listener rebind failed: {error}",
                            endpoint.id
                        );
                        if let Ok(Some(removed)) = self.endpoints.revoke(&endpoint.id) {
                            self.teardown_endpoints(std::slice::from_ref(&removed));
                            self.audit.append(
                                AuditEntry::new(
                                    AuditKind::Unwired,
                                    format!(
                                        "Direct endpoint revoked after bind conflict: {}",
                                        connection.name
                                    ),
                                )
                                .connection(connection.name.clone())
                                .outcome("listener_bind_failed")
                                .field("endpoint_id", endpoint.id.to_string()),
                            );
                            self.events.wirings_changed();
                        }
                    }
                }
                _ => {
                    tracing::info!(
                        "dropping stale endpoint {} (connection missing or kind changed)",
                        endpoint.id
                    );
                    if let Ok(Some(removed)) = self.endpoints.revoke(&endpoint.id) {
                        self.teardown_endpoints(std::slice::from_ref(&removed));
                    }
                }
            }
        }
    }

    /// Bind (or rebind) the listener for one endpoint and record its handle,
    /// stopping any prior listener for the same endpoint id.
    async fn bind_endpoint_listener(
        self: &Arc<Self>,
        endpoint: &DirectEndpoint,
        connection: &Connection,
    ) -> std::io::Result<()> {
        let handle = match connection.kind() {
            ConnectionKind::Pg => {
                crate::capability::pg::bind_endpoint(self.clone(), endpoint).await?
            }
            ConnectionKind::Ssh => {
                crate::capability::ssh::bind_endpoint(self.clone(), endpoint).await?
            }
            ConnectionKind::Api => {
                let (handle, port) =
                    crate::capability::http::bind_endpoint(self.clone(), endpoint).await?;
                // Pin the assigned loopback port so a pasted base URL survives
                // a restart (rebind reuses it).
                if endpoint.port != Some(port) {
                    let _ = self.endpoints.set_port(&endpoint.id, port);
                }
                handle
            }
            other => {
                return Err(std::io::Error::other(format!(
                    "direct endpoints are not supported for {} tools",
                    other.as_str()
                )))
            }
        };
        if let Some(old) = self
            .endpoint_listeners
            .lock()
            .unwrap()
            .insert(endpoint.id, handle)
        {
            old.stop();
        }
        Ok(())
    }

    /// Tear down endpoints that just went away. Removing the persisted
    /// record already happened; this releases the runtime resources tied to it
    /// (the listener and its socket directory) and closes any live
    /// sessions it was serving, so a revoked endpoint stops working at once —
    /// unlike a ticket, its access is standing and cannot be left to expire.
    fn teardown_endpoints(&self, removed: &[DirectEndpoint]) {
        for endpoint in removed {
            if let Some(handle) = self.endpoint_listeners.lock().unwrap().remove(&endpoint.id) {
                handle.stop();
            }
            self.data_plane.close_endpoint_sessions(&endpoint.id);
            let dir = self.paths.endpoint_dir(&endpoint.id);
            if let Err(error) = std::fs::remove_dir_all(&dir) {
                if error.kind() != std::io::ErrorKind::NotFound {
                    tracing::warn!("could not remove endpoint dir {}: {error}", dir.display());
                }
            }
        }
    }

    /// Enable or disable agent access for a connection from the app.
    /// Disabling does not chase down live ticket transports — tickets are
    /// short-lived, and the next open is refused. Direct endpoints are
    /// standing authority, so their established sessions are closed at once;
    /// the issued endpoint itself remains available for later re-enabling.
    pub fn ui_set_tool_access(&self, connection_id: &Uuid, enabled: bool) -> Result<bool> {
        let _gate = self.config_gate.lock().unwrap();
        let connection = self.store.connection_by_id(connection_id)?;
        let changed = self.access.set_enabled(*connection_id, enabled)?;
        if changed {
            let closed_sessions = if enabled {
                0
            } else {
                self.endpoints
                    .get_for_connection(connection_id)
                    .map(|endpoint| self.data_plane.close_endpoint_sessions(&endpoint.id))
                    .unwrap_or(0)
            };
            self.audit.append(
                AuditEntry::new(
                    if enabled {
                        AuditKind::Wired
                    } else {
                        AuditKind::Unwired
                    },
                    format!(
                        "Agent access {} for {}",
                        if enabled { "enabled" } else { "disabled" },
                        connection.name
                    ),
                )
                .connection(connection.name.clone())
                .field("closed_endpoint_sessions", closed_sessions),
            );
            self.events.wirings_changed();
        }
        Ok(changed)
    }

    /// Curate which upstream MCP tools agents may call on a connection.
    /// `None` restores the default (all tools); `Some` is enforced by the
    /// broker on every `tools/call` and mirrored by the sidecar's tool
    /// listing.
    pub fn ui_set_allowed_tools(
        &self,
        connection_id: &Uuid,
        tools: Option<Vec<String>>,
    ) -> Result<bool> {
        let _gate = self.config_gate.lock().unwrap();
        let connection = self.store.connection_by_id(connection_id)?;
        let detail = match &tools {
            None => "all tools".to_string(),
            Some(list) => format!(
                "{} tool{} allowed",
                list.len(),
                if list.len() == 1 { "" } else { "s" }
            ),
        };
        let changed = self.access.set_allowed_tools(*connection_id, tools)?;
        if changed {
            self.audit.append(
                AuditEntry::new(
                    AuditKind::Wired,
                    format!("Tool selection for {}: {detail}", connection.name),
                )
                .connection(connection.name.clone()),
            );
            self.events.wirings_changed();
        }
        Ok(changed)
    }

    /// Ask an MCP connection's upstream server for its tool list (the
    /// per-wiring tool picker). Read-only against the upstream; the
    /// credential rides only the upstream leg, as everywhere.
    pub async fn ui_list_mcp_tools(&self, id: &Uuid) -> Result<Vec<crate::mcp::McpToolInfo>> {
        let connection = self.store.connection_by_id(id)?;
        if crate::mcp_refresh::wants_refresh(&connection) {
            let _ = crate::mcp_refresh::refresh_connection_token(
                &self.refresh_context(),
                id,
                crate::mcp_refresh::RefreshMode::IfStale,
            )
            .await;
        }
        let connection = self.store.connection_by_id(id)?;
        crate::mcp::list_tools(&self.store, &self.http_client, &connection)
            .await
            .map_err(CoreError::InvalidConnectionConfig)
    }

    /* ------------------------- shared identity (UI) ------------------------ */

    /// The persisted identity record (hash, timestamps, migration aliases —
    /// never the plaintext key).
    pub fn identity_info(&self) -> BrokerIdentity {
        self.identity.info()
    }

    /// Rotate this computer's key: mint a fresh one, rewrite the token
    /// file, clear the migration aliases, and close every outstanding
    /// data-plane capability. This is the "disconnect everything" action —
    /// agents that read the token file reconnect on their own; anything
    /// holding a pasted copy stops working. Gated behind the native
    /// confirmation because it is destructive and touches the credential.
    pub fn ui_rotate_key(&self) -> Result<()> {
        let confirmation =
            self.confirm_action("Rotate this computer's key and disconnect all agents")?;
        let _gate = self.config_gate.lock().unwrap();
        self.identity.rotate()?;
        let sessions_closed = self.data_plane.close_all();
        self.audit.append(
            AuditEntry::new(
                AuditKind::TokenRevoked,
                "Key rotated; all agents disconnected".to_string(),
            )
            .confirmation(confirmation)
            .field("sessions_closed", sessions_closed),
        );
        self.events.agents_changed();
        Ok(())
    }

    /* --------------------------- live sessions ---------------------------- */

    pub fn sessions(&self) -> Vec<SessionInfo> {
        self.data_plane.sessions()
    }

    /// Close a live session immediately. This is a remediation action: ending
    /// an agent's access must not be delayed by native authentication.
    pub fn ui_close_session(&self, id: u64) -> Result<bool> {
        Ok(self.data_plane.close_session(id))
    }

    /* ----------------------------- settings ------------------------------- */

    pub fn settings(&self) -> Settings {
        self.store.settings()
    }

    pub fn ui_change_reauth_on_read(&self, on: bool) -> Result<()> {
        if !on {
            // Weakening the read gate always re-prompts; the presence window
            // does not cover it.
            self.confirm_action("Disable OS authentication requirement for reading secrets")?;
        }
        self.store.set_reauth_on_read(on)?;
        self.store.clear_user_presence();
        Ok(())
    }

    /// Change the presence-window length. Restricted to the offered choices;
    /// the window restarts under the new length immediately.
    pub fn ui_set_presence_window(&self, secs: u64) -> Result<()> {
        if !PRESENCE_WINDOW_CHOICES.contains(&secs) {
            return Err(CoreError::InvalidSetting(format!(
                "presence window must be 900, 3600, or 7200 seconds, got {secs}"
            )));
        }
        self.confirm_user_action("Change how long Multitool stays unlocked")?;
        self.store.set_presence_window_secs(secs)?;
        // Re-anchor the just-confirmed window so a shortened length takes
        // effect now instead of at the old deadline.
        self.store.reanchor_presence();
        Ok(())
    }

    pub fn ui_set_show_websockets(&self, on: bool) -> Result<()> {
        self.store.set_show_websockets(on)
    }

    pub fn ui_set_menu_bar_hides_dock(&self, on: bool) -> Result<()> {
        self.store.set_menu_bar_hides_dock(on)
    }
}

/// A broker from before the advisory-lock protocol can still own the socket
/// without holding `broker.lock`. Probe conservatively after acquiring the new
/// lock but before opening any persistent state, so the first upgraded launch
/// cannot race the old process's in-memory store.
async fn reject_legacy_live_socket(paths: &Paths) -> Result<()> {
    use std::io;
    use std::os::unix::fs::FileTypeExt as _;

    let socket = paths.socket_file();
    let metadata = match std::fs::symlink_metadata(&socket) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(CoreError::Io(error)),
    };
    if !metadata.file_type().is_socket() {
        return Err(CoreError::Io(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "refusing to open broker state while {} is not a Unix socket",
                socket.display()
            ),
        )));
    }

    match tokio::time::timeout(
        Duration::from_secs(1),
        tokio::net::UnixStream::connect(&socket),
    )
    .await
    {
        Ok(Ok(_)) => Err(CoreError::BrokerAlreadyRunning(paths.socket_display())),
        Ok(Err(error))
            if matches!(
                error.kind(),
                io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound
            ) =>
        {
            Ok(())
        }
        Ok(Err(error)) => Err(CoreError::Io(io::Error::new(
            error.kind(),
            format!(
                "failed to probe existing control socket {}; refusing to open broker state: {error}",
                socket.display()
            ),
        ))),
        Err(_) => Err(CoreError::Io(io::Error::new(
            io::ErrorKind::TimedOut,
            format!(
                "existing control socket {} did not respond within 1 second; refusing to open broker state",
                socket.display()
            ),
        ))),
    }
}
