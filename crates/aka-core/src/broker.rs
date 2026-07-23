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
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ConnectionTestReport {
    pub ok: bool,
    pub detail: String,
}

/// The result of issuing a direct endpoint: the pasteable connection string
/// and its secret. The secret is retained on the endpoint record, so later
/// copies of the address carry it too; re-issuing rotates it.
#[derive(Debug, Clone, serde::Serialize)]
pub struct IssuedEndpointInfo {
    pub endpoint_id: Uuid,
    pub kind: ConnectionKind,
    /// Pasteable connection string (a Postgres DSN today).
    pub dsn: String,
    /// The endpoint secret, also embedded in the DSN's password slot.
    pub secret: String,
    /// Ready-to-adapt invocation, e.g. `psql "…"`.
    pub example: String,
}

/// A begun remotely-relayed OAuth flow: what the shell needs to open the
/// browser and match the callback.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ManageOAuthStart {
    pub flow_id: Uuid,
    pub authorize_url: String,
    pub state: String,
}

/// What happens when a relayed flow's code comes back.
enum ManageOAuthPlan {
    Connect {
        secret_name: String,
        client_secret: Option<crate::types::SecretValue>,
        spec: Box<ConnectionSpec>,
    },
    Reconnect {
        connection_id: Uuid,
        secret_id: Uuid,
        client_secret: Option<crate::types::SecretValue>,
    },
}

struct PendingManageOAuth {
    oauth_spec: crate::types::OAuthSpec,
    redirect_uri: String,
    state: String,
    verifier: zeroize::Zeroizing<String>,
    plan: ManageOAuthPlan,
    created_at: Instant,
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
    /// Manage-plane change bus: everything `events` reports also lands here
    /// (via [`crate::manage::FanoutEvents`]), numbered and buffered so a
    /// reconnecting SSE client resumes instead of refetching everything.
    manage_bus: Arc<crate::manage::ManageBus>,
    /// Last-known per-connection health (tests + brokered-call outcomes).
    pub health: Arc<crate::health::HealthRegistry>,
    /// Tickets + live WS/PG sessions.
    pub data_plane: DataPlane,
    /// The URL remote clients reach this broker at (`serve --public-url`),
    /// when one is configured. Drives remote-flavored agent-setup text.
    public_url: Mutex<Option<String>>,
    /// The address the WS/PG data-plane proxies and API direct endpoints
    /// bind to (`serve --data-plane-listen`); loopback by default. A
    /// non-loopback value exposes plaintext credential legs to the network.
    data_plane_bind: std::sync::OnceLock<std::net::IpAddr>,
    /// The host put into returned data-plane URLs/DSNs (`serve
    /// --advertise-host`); loopback by default. What a remote agent dials.
    advertise_host: std::sync::OnceLock<String>,
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
    /// Pending remotely-relayed OAuth flows (manage API): the shell on the
    /// user's machine holds the loopback catcher; the verifier and the
    /// completion plan wait here for the code to come back.
    manage_oauth: Mutex<HashMap<Uuid, PendingManageOAuth>>,
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
        // Every shell observer is wrapped in the manage-event fanout so the
        // SSE stream sees exactly what the shell sees.
        let manage_bus = Arc::new(crate::manage::ManageBus::new());
        let events: Arc<dyn BrokerEvents> =
            Arc::new(crate::manage::FanoutEvents::new(events, manage_bus.clone()));
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
            manage_oauth: Mutex::new(HashMap::new()),
            connect_request_debounce: Mutex::new(std::collections::HashMap::new()),
            public_url: Mutex::new(None),
            data_plane_bind: std::sync::OnceLock::new(),
            advertise_host: std::sync::OnceLock::new(),
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
            manage_bus,
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

    /// Record the URL remote clients reach this broker at.
    pub fn set_public_url(&self, url: Option<String>) {
        *self.public_url.lock().unwrap() = url;
    }

    /// The configured public URL, when serving one.
    pub fn public_url(&self) -> Option<String> {
        self.public_url.lock().unwrap().clone()
    }

    /// Configure the data-plane bind address and advertised host (once, at
    /// serve). Absent values keep the loopback defaults.
    pub fn set_data_plane_address(
        &self,
        bind: Option<std::net::IpAddr>,
        advertise_host: Option<String>,
    ) {
        if let Some(bind) = bind {
            let _ = self.data_plane_bind.set(bind);
        }
        if let Some(host) = advertise_host {
            let _ = self.advertise_host.set(host);
        }
    }

    /// The address WS/PG proxies and API endpoints bind to (loopback by
    /// default).
    pub fn data_plane_bind(&self) -> std::net::IpAddr {
        *self
            .data_plane_bind
            .get()
            .unwrap_or(&std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
    }

    /// The host put into returned data-plane URLs/DSNs (loopback by
    /// default).
    pub fn advertise_host(&self) -> String {
        self.advertise_host
            .get()
            .cloned()
            .unwrap_or_else(|| "127.0.0.1".to_string())
    }

    /// The manage-plane event bus (SSE subscription + reconnect replay).
    pub fn manage_bus(&self) -> &Arc<crate::manage::ManageBus> {
        &self.manage_bus
    }

    /// Publish a synthetic manage event with no `BrokerEvents` counterpart
    /// (e.g. the activity log was cleared through the manage API).
    pub fn publish_manage_event(&self, event: aka_api::ManageEvent) {
        self.manage_bus.emit(event);
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
        // Refuse in-use deletion first, so the user is never asked to
        // confirm an action that cannot proceed.
        let users = self.store.connections_using(id);
        if !users.is_empty() {
            return Err(CoreError::SecretInUse(users));
        }
        // The in-app confirm is the gate: an unused secret grants nothing,
        // so deleting it is destructive to the user's own material only.
        let meta = self.store.delete_secret(id)?;
        self.audit.append(
            AuditEntry::new(
                AuditKind::SecretDeleted,
                format!("Secret deleted: {}", meta.name),
            )
            .detail("Removed from Keychain"),
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

    /// Whether the spec attaches a stored secret to a destination that
    /// secret does not already cover. Attaching a stored credential to a
    /// *new* destination extends that credential's reach, which is the
    /// escalation the native gate exists for; reusing it at a destination
    /// an existing tool already binds it to extends nothing, so it adds
    /// without a prompt. A credential typed into the form alongside the
    /// tool is self-authorizing: the form is the intent. `exclude` names a
    /// secret being created atomically with the tool, so its own template
    /// ref does not count as reuse.
    fn spec_extends_stored_secret_reach(
        &self,
        spec: &ConnectionSpec,
        exclude: Option<&str>,
    ) -> bool {
        let secrets = self.store.list_secrets();
        // The stored secrets the spec attaches: explicit bindings plus
        // template refs that name a secret the vault already holds.
        let mut attached: Vec<Uuid> = spec.secrets.clone();
        let template = match &spec.config {
            crate::types::ConnectionConfig::Api { template, .. } => Some(template.as_str()),
            crate::types::ConnectionConfig::Ws { template, .. } => template.as_deref(),
            _ => None,
        };
        if let Some(template) = template {
            let Ok(parsed) = crate::template::Template::parse(template) else {
                // Unparseable templates are rejected later by validation;
                // treat the ambiguity as an escalation so the gate fails safe.
                return true;
            };
            for name in parsed.refs() {
                if Some(name.as_str()) == exclude {
                    continue;
                }
                if let Some(meta) = secrets.iter().find(|meta| meta.name == name) {
                    attached.push(meta.id);
                }
            }
        }
        if attached.is_empty() {
            return false;
        }
        // A secret already covers the spec's destination when some existing
        // tool binds it to an equivalent target (API connections derive
        // their secret list from template refs, so `secrets` is the full
        // binding set for every kind).
        let connections = self.store.list_connections();
        attached.iter().any(|secret_id| {
            !connections.iter().any(|conn| {
                conn.secrets.contains(secret_id) && conn.config.has_equivalent_target(&spec.config)
            })
        })
    }

    /// A connection pins a destination and may bind a secret to it. The
    /// native confirmation fires only when the spec attaches an
    /// already-stored secret to a destination it does not already cover;
    /// credential-less tools, tools whose secret arrives with the form, and
    /// same-destination reuse add without a prompt.
    pub fn ui_add_connection(&self, spec: ConnectionSpec) -> Result<Connection> {
        // Reject invalid or already-stale input before asking the user to
        // authenticate. `add_connection` repeats the state-dependent checks
        // after confirmation in case the index changed while the sheet was up.
        self.store.preflight_add_connection(&spec)?;
        let confirmation = if self.spec_extends_stored_secret_reach(&spec, None) {
            Some(self.confirm_user_action(&format!("Add tool “{}”", spec.name))?)
        } else {
            None
        };
        let conn = self.store.add_connection(spec)?;
        let mut entry = AuditEntry::new(
            AuditKind::ConnectionAdded,
            format!("Tool added: {}", conn.name),
        )
        .connection(conn.name.clone())
        .detail(format!("{} → {}", conn.kind().label(), conn.target()))
        .field("kind", conn.kind().as_str())
        .field("target", conn.target());
        if let Some(confirmation) = confirmation {
            entry = entry.confirmation(confirmation);
        }
        self.audit.append(entry);
        Ok(conn)
    }

    /// One connection-first setup action: save a new credential and bind it
    /// without exposing an intermediate, partially configured state. The
    /// credential arrives with the form (or was just minted by an OAuth
    /// sign-in the user drove), so no native confirmation fires unless the
    /// spec additionally extends some other stored secret's reach.
    pub fn ui_add_connection_with_secret(
        &self,
        secret_name: &str,
        value: SecretValue,
        spec: ConnectionSpec,
    ) -> Result<Connection> {
        self.store
            .preflight_add_connection_with_secret(secret_name, &spec)?;
        let confirmation = if self.spec_extends_stored_secret_reach(&spec, Some(secret_name)) {
            Some(self.confirm_user_action(&format!("Add tool “{}”", spec.name))?)
        } else {
            None
        };
        let (secret, conn) = self
            .store
            .add_connection_with_secret(secret_name, value, spec)?;
        self.audit.append(AuditEntry::new(
            AuditKind::SecretAdded,
            format!("Secret added: {}", secret.name),
        ));
        let mut entry = AuditEntry::new(
            AuditKind::ConnectionAdded,
            format!("Tool added: {}", conn.name),
        )
        .connection(conn.name.clone())
        .detail(format!("{} → {}", conn.kind().label(), conn.target()))
        .field("kind", conn.kind().as_str())
        .field("target", conn.target());
        if let Some(confirmation) = confirmation {
            entry = entry.confirmation(confirmation);
        }
        self.audit.append(entry);
        Ok(conn)
    }

    /// Update a connection. Name-only edits are metadata and do not require
    /// native authentication; changes to configuration, secret bindings, or
    /// authentication do. When the pinned target changes, its direct
    /// endpoints are revoked: a pasted address granted for one destination
    /// must not silently cover another.
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
        let mut endpoints_revoked = false;
        if target_changed {
            // Direct endpoints grant standing access to the old destination —
            // an already-pasted DSN must not silently point at the new one —
            // so they die with the retarget. The enabled/disabled flag and
            // any curated MCP tool subset name the *tool* and survive: stale
            // tool names simply stop matching, which only narrows access.
            let endpoints = self.endpoints.remove_for_connection(id)?;
            self.teardown_endpoints(&endpoints);
            endpoints_revoked = !endpoints.is_empty();
            if endpoints_revoked {
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
            if endpoints_revoked {
                " · direct endpoints revoked (target changed)".to_string()
            } else {
                String::new()
            }
        ))
        .field("target", conn.target())
        .field("target_changed", target_changed)
        .field("capability_changed", capability_changed)
        .field("endpoints_revoked", endpoints_revoked);
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

    /// Delete a connection; wirings die with it. Deletion only narrows
    /// access (its listed secrets stay in the Keychain), so the in-app
    /// confirmation is the gate — no native prompt.
    pub fn ui_delete_connection(&self, id: &Uuid) -> Result<Connection> {
        let conn = self.store.connection_by_id(id)?;
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
            .connection(conn.name.clone()),
        );
        Ok(conn)
    }

    /// Test a connection *draft* — an add-form's config before anything is
    /// persisted. The invariant that makes this safe without a gate: it
    /// never reads the secret store. A credential typed into the form is
    /// used for a full sign-in (it came from the same user gesture that is
    /// about to store it); a draft that references an already-stored secret
    /// gets a reachability + TLS dial only, with the credential exchange
    /// deferred to after the gated add. No health is recorded — there is no
    /// connection yet.
    pub async fn ui_test_connection_draft(
        &self,
        spec: crate::store::ConnectionSpec,
        typed_secret: Option<SecretValue>,
    ) -> Result<ConnectionTestReport> {
        const TEST_TIMEOUT: Duration = Duration::from_secs(15);
        let credential_deferred = !spec.secrets.is_empty();
        let now = chrono::Utc::now();
        let connection = Connection {
            id: Uuid::new_v4(),
            name: spec.name,
            config: spec.config,
            secrets: Vec::new(),
            account: None,
            oauth: None,
            created_at: now,
            updated_at: now,
        };
        let test = async {
            match connection.config.kind() {
                ConnectionKind::Pg => {
                    crate::capability::pg::test_draft_upstream(
                        &connection,
                        typed_secret.as_ref().map(|value| value.as_str()),
                        credential_deferred,
                    )
                    .await
                }
                // The reachability test performs no key exchange, so the
                // draft's key — stored or typed — is simply not consulted.
                ConnectionKind::Ssh => {
                    crate::capability::ssh::test_reachability(&self.store, &connection).await
                }
                _ => Err("draft tests cover Postgres and SSH connections".to_string()),
            }
        };
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
        Ok(ConnectionTestReport { ok, detail })
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
                    crate::capability::pg::test_upstream(&self.store, &connection).await
                }
                ConnectionKind::Ws => {
                    crate::capability::ws::test_upstream(&self.store, &connection).await
                }
                ConnectionKind::Ssh => {
                    crate::capability::ssh::test_reachability(&self.store, &connection).await
                }
            }
        };
        // Testing rides the same pre-authorization as the agent plane: any
        // enabled agent can already open this connection with no prompt, so
        // the user's own Test button reading the secret it is about to send
        // to the pinned destination must not re-authenticate either.
        let test = crate::authorization::scope(true, test);
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

    /// Begin a remotely-relayed OAuth connect: the shell (on the user's
    /// machine) bound a loopback catcher and sends its redirect URI; the
    /// broker validates the draft, builds the authorize URL, and parks the
    /// verifier + completion plan under a flow id until the code returns.
    pub fn manage_oauth_start(
        &self,
        secret_name: &str,
        client_secret: Option<SecretValue>,
        spec: ConnectionSpec,
        redirect_uri: &str,
    ) -> Result<ManageOAuthStart> {
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
        let authorization =
            crate::oauth::begin_external(&oauth_spec, redirect_uri).map_err(CoreError::OAuth)?;
        self.park_manage_oauth(
            authorization,
            oauth_spec,
            redirect_uri,
            ManageOAuthPlan::Connect {
                secret_name: secret_name.to_string(),
                client_secret,
                spec: Box::new(spec),
            },
        )
    }

    /// Begin a remotely-relayed OAuth reconnect for an existing connection.
    pub async fn manage_oauth_reconnect_start(
        &self,
        id: &Uuid,
        redirect_uri: &str,
    ) -> Result<ManageOAuthStart> {
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
        // Carry the client secret across, exactly like the local reconnect.
        let previous = self
            .store
            .secret_value(&secret_id)
            .await
            .ok()
            .and_then(|value| crate::oauth::TokenSet::from_secret_value(&value).ok());
        let client_secret = previous
            .and_then(|tokens| tokens.client_secret)
            .map(zeroize::Zeroizing::new);
        let authorization =
            crate::oauth::begin_external(&oauth_spec, redirect_uri).map_err(CoreError::OAuth)?;
        self.park_manage_oauth(
            authorization,
            oauth_spec,
            redirect_uri,
            ManageOAuthPlan::Reconnect {
                connection_id: conn.id,
                secret_id,
                client_secret,
            },
        )
    }

    fn park_manage_oauth(
        &self,
        authorization: crate::oauth::ExternalAuthorization,
        oauth_spec: crate::types::OAuthSpec,
        redirect_uri: &str,
        plan: ManageOAuthPlan,
    ) -> Result<ManageOAuthStart> {
        let flow_id = Uuid::new_v4();
        let mut flows = self.manage_oauth.lock().unwrap();
        // Abandoned flows expire; prune on the way in so the map is bounded.
        flows.retain(|_, flow| flow.created_at.elapsed() < crate::oauth::CONNECT_TIMEOUT);
        flows.insert(
            flow_id,
            PendingManageOAuth {
                oauth_spec,
                redirect_uri: redirect_uri.to_string(),
                state: authorization.state.clone(),
                verifier: authorization.verifier,
                plan,
                created_at: Instant::now(),
            },
        );
        Ok(ManageOAuthStart {
            flow_id,
            authorize_url: authorization.authorize_url,
            state: authorization.state,
        })
    }

    /// Complete a remotely-relayed flow: exchange the returned code and run
    /// the parked plan (add the connection + token secret, or replace the
    /// token in place). The flow is consumed either way.
    pub async fn manage_oauth_complete(
        &self,
        flow_id: &Uuid,
        code: &str,
        state: &str,
    ) -> Result<()> {
        let flow = {
            let mut flows = self.manage_oauth.lock().unwrap();
            flows.retain(|_, flow| flow.created_at.elapsed() < crate::oauth::CONNECT_TIMEOUT);
            flows.remove(flow_id).ok_or_else(|| {
                CoreError::OAuth("this sign-in expired or was already completed".into())
            })?
        };
        if flow.state != state {
            return Err(CoreError::OAuth(
                "authorization state mismatch; try connecting again".into(),
            ));
        }
        let client_secret = match &flow.plan {
            ManageOAuthPlan::Connect { client_secret, .. } => client_secret.clone(),
            ManageOAuthPlan::Reconnect { client_secret, .. } => client_secret.clone(),
        };
        let tokens = crate::oauth::exchange_code(
            code,
            &flow.redirect_uri,
            flow.verifier.as_str(),
            &flow.oauth_spec,
            client_secret,
            &self.http_client,
        )
        .await
        .map_err(CoreError::OAuth)?;
        match flow.plan {
            ManageOAuthPlan::Connect {
                secret_name, spec, ..
            } => {
                let (_, conn) = self.store.add_connection_with_secret(
                    &secret_name,
                    tokens.to_secret_value(),
                    *spec,
                )?;
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
                    .field("oauth", true),
                );
                self.events.connections_changed();
            }
            ManageOAuthPlan::Reconnect {
                connection_id,
                secret_id,
                ..
            } => {
                let conn = self.store.connection_by_id(&connection_id)?;
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
                    .connection(conn.name.clone()),
                );
                self.events.connections_changed();
            }
        }
        Ok(())
    }

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
        // No native gate: the token set is minted fresh by the sign-in the
        // user is about to drive in the browser — the same new-credential
        // rule as every other add. The provider's consent page is the
        // deliberate act.
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
            .field("oauth", true),
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
        // No native gate, matching connect: the browser consent page is the
        // deliberate act, and the replaced token targets the same pinned
        // destination.
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
            .field("oauth", true),
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
        // Same pre-authorization as tests: the check reads the connection's
        // own credential to talk to its own pinned upstream.
        let mut report = match tokio::time::timeout(
            CHECK_TIMEOUT,
            crate::authorization::scope(
                true,
                crate::mcp::check_connection(&self.store, &self.http_client, &connection, &options),
            ),
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
    /// The secret is retained on the record so later copies of the address
    /// carry it too. Gated behind the
    /// configuration gate: a fresh native authentication is reused (the
    /// presence window), otherwise the OS prompt appears — issuance grants
    /// standing access, so it is never silent for a user who has not
    /// authenticated recently. The connection's agent access must be enabled.
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

        // First issuance mints standing access, so it takes the native gate.
        // A *reissue* only rotates the secret of an endpoint the user already
        // authorized — the in-app confirm is its gate (revoking, which only
        // narrows, is likewise in-app only).
        let confirmation = if self.endpoints.get_for_connection(connection_id).is_none() {
            // Confirm off the async runtime: the native sheet blocks its thread.
            let store = self.store.clone();
            let description = format!("Issue a direct endpoint for {}", connection.name);
            Some(
                tokio::task::spawn_blocking(move || {
                    store.confirm_configuration_action(&description)
                })
                .await
                .map_err(|e| CoreError::Vault(format!("confirmation task failed: {e}")))??,
            )
        } else {
            None
        };
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
                let dsn = crate::capability::pg::endpoint_dsn(
                    dir.as_path(),
                    user,
                    dbname,
                    Some(&issued.secret),
                );
                let example = format!("psql \"{dsn}\"");
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
                let base = format!("http://{}:{port}", self.advertise_host());
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
        let mut entry = AuditEntry::new(
            AuditKind::Wired,
            format!("Direct endpoint issued: {}", connection.name),
        )
        .connection(connection.name.clone())
        .field("endpoint_id", issued.endpoint.id.to_string())
        .field("kind", connection.kind().as_str());
        if let Some(confirmation) = confirmation {
            entry = entry.confirmation(confirmation);
        }
        self.audit.append(entry);
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
        // Same pre-authorization as tests: this reads the connection's own
        // credential to talk to its own pinned upstream.
        crate::authorization::scope(
            true,
            crate::mcp::list_tools(&self.store, &self.http_client, &connection),
        )
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
    /// holding a pasted copy stops working. The single native sheet is both
    /// the warning and the gate: its reason text carries the consequences,
    /// so no separate dialog precedes it.
    pub fn ui_rotate_key(&self) -> Result<()> {
        let confirmation = self.confirm_action(
            "rotate this computer's key — every live agent session closes now, \
             and agents reconnect on their own from the key file",
        )?;
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
