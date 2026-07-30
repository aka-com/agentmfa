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
    BrokerIdentity, ConfirmMode, Connection, ConnectionConfig, ConnectionKind, DirectEndpoint,
    SecretMeta, SecretValue, Settings, ToolAccess,
};
use crate::Result;

/// Presence-window lengths the Settings sheet offers: 15 minutes, 1 hour,
/// 2 hours.
pub const PRESENCE_WINDOW_CHOICES: &[u64] = &[15 * 60, 60 * 60, 2 * 60 * 60];
const CONNECT_REQUEST_DEBOUNCE: Duration = Duration::from_secs(60);
const MAX_CONNECT_REQUEST_DEBOUNCE_KEYS: usize = 256;

/// Outcome of a UI-initiated connection test: a pass/fail flag, a short
/// human-readable summary (never credential material), and — on failure —
/// the machine-readable kind the UI keys fix affordances off. The detail
/// is presentation only; anything branching on a failure branches on
/// `kind`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ConnectionTestReport {
    pub ok: bool,
    pub detail: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<crate::capability::TestErrorKind>,
}

#[derive(Debug, Clone)]
struct CachedMcpTools {
    fetched_at: chrono::DateTime<chrono::Utc>,
    listing: crate::mcp::McpToolListing,
}

/// The result of issuing a direct endpoint: the pasteable connection string
/// and its secret. The secret is retained on the endpoint record, so later
/// copies of the address carry it too; re-issuing rotates it.
#[derive(Debug, Clone, serde::Serialize)]
pub struct IssuedEndpointInfo {
    pub endpoint_id: Uuid,
    pub kind: ConnectionKind,
    /// Pasteable connection string (a Postgres DSN today). For Postgres this
    /// is the Unix-socket form: the tighter surface, and libpq-only.
    pub dsn: String,
    /// The TCP form of the same endpoint, for drivers that cannot speak Unix
    /// sockets and for any client reaching a broker on another machine.
    /// `None` for kinds that have no second address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcp_dsn: Option<String>,
    /// The endpoint secret, also embedded in the DSN's password slot.
    pub secret: String,
    /// Ready-to-adapt usage line. For Postgres this is `.env`-shaped
    /// (`DATABASE_URL="…"`) rather than a shell command, so the embedded
    /// secret is not steered toward argv/shell history.
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
    /// The vault, retained beyond the store so endpoint secrets can live in it
    /// rather than in plaintext on disk. They are not `Secret` records: they
    /// have no index entry and never appear in the Secrets tab.
    vault: Arc<dyn crate::vault::SecretVault>,
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
    /// Tickets + live data-plane sessions.
    pub data_plane: DataPlane,
    /// Traffic parked on the user: prompts, approval windows, and the
    /// cooldown a refusal leaves behind.
    pub approvals: crate::approvals::Approvals,
    /// Upstream MCP tool calls parked on the user for interactive input.
    pub elicitations: crate::elicitations::Elicitations,
    /// Short-lived, single-use capabilities proving that an elicitation came
    /// from an upstream response the broker relayed.
    pub(crate) elicitation_permits: Arc<crate::elicitations::ElicitationPermits>,
    /// Unified lifecycle history for human-decision requests. Approvals and
    /// elicitations both write it, so both land in one Recent Inbox.
    pub request_history: Arc<crate::request_history::RequestHistory>,
    /// The URL remote clients reach this broker at (`serve --public-url`),
    /// when one is configured. Drives remote-flavored agent-setup text.
    public_url: Mutex<Option<String>>,
    /// The address the PG data-plane proxy and API direct endpoints
    /// bind to (`serve --data-plane-listen`); loopback by default. A
    /// non-loopback value exposes plaintext credential legs to the network.
    data_plane_bind: std::sync::OnceLock<std::net::IpAddr>,
    /// The host put into returned data-plane URLs/DSNs (`serve
    /// --advertise-host`); loopback by default. What a remote agent dials.
    advertise_host: std::sync::OnceLock<String>,
    /// The sidecar's loopback MCP port, reported by the shell that
    /// supervises it (restarts move it; `None` while it is not running).
    /// Advertised in the discovery manifest so `mfa mcp` and other bridges
    /// can find the MCP endpoint without a config file.
    sidecar_mcp_port: Mutex<Option<u16>>,
    /// The PG proxy's ephemeral loopback port, set when the daemon starts;
    /// surfaced only in open responses' DSNs.
    pub(crate) pg_proxy_port: std::sync::OnceLock<u16>,
    pub(crate) http_client: reqwest::Client,
    /// Last successfully-listed upstream MCP tools per connection. The
    /// per-wiring tool picker falls back to this when a live listing can't be
    /// fetched (an OAuth access token lapsed, the upstream is briefly
    /// unreachable), so curating and saving a tool subset never forces a
    /// reconnect. Runtime only; enforcement on `tools/call` is always by name.
    mcp_tools_cache: Mutex<HashMap<Uuid, CachedMcpTools>>,
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
    /// Capability retargets that still require a fresh, non-presence-window
    /// confirmation before a stored credential may be sent by the Test
    /// affordance. Runtime-only: restarting the broker cannot preserve an
    /// in-process presence grant either.
    recent_retargets: Mutex<HashMap<Uuid, Instant>>,
    /// Rejected credentials are security telemetry, but an automated stale
    /// client must not amplify the append-only activity log without bound.
    /// Keys include plane, transport, peer, and failure reason.
    auth_failure_debounce: Mutex<HashMap<String, Instant>>,
    pub(crate) token_limiter: KeyedLimiter,
    /// Failed manage authentication attempts, keyed by transport/peer.
    /// Successful callers never consume this budget.
    pub(crate) manage_auth_limiter: KeyedLimiter,
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
        Self::new_inner(paths, vault, config, events, true).await
    }

    /// Construct the broker state for a short-lived offline management
    /// command. This exposes the same `ui_*` management layer and holds the
    /// normal process lease, but does not start daemon-only background work
    /// such as proactive OAuth refreshes.
    pub async fn new_for_offline_management(
        paths: Paths,
        vault: Arc<dyn crate::vault::SecretVault>,
        config: BrokerConfig,
        events: Arc<dyn BrokerEvents>,
    ) -> Result<Arc<Self>> {
        Self::new_inner(paths, vault, config, events, false).await
    }

    async fn new_inner(
        paths: Paths,
        vault: Arc<dyn crate::vault::SecretVault>,
        config: BrokerConfig,
        events: Arc<dyn BrokerEvents>,
        start_background_tasks: bool,
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
        // One integrity key seals every state file: index.json,
        // access.json, and identity.json refuse to load if tampered with.
        // It is established before the activity log so the log's own entries
        // are chained from the first one this process writes.
        let integrity =
            Arc::new(crate::integrity::StateIntegrity::open_for_paths(&*vault, &paths).await?);
        let audit = Arc::new(AuditLog::open_sealed(
            paths.audit_file(),
            paths.audit_seal_file(),
            integrity.clone(),
        )?);
        {
            let events = events.clone();
            audit.subscribe(move |entry| events.audit_appended(entry));
        }
        let store = Arc::new(Store::open_with_events(
            paths.clone(),
            vault.clone(),
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
        let access = Arc::new(AccessTable::open_with_legacy_policy_and_generation(
            paths.access_file(),
            Some(&paths.wirings_file()),
            Some(&paths.rules_file()),
            &known_connections,
            integrity.clone(),
            Some(store.clone()),
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
        let request_history = Arc::new(crate::request_history::RequestHistory::default());
        let approvals = crate::approvals::Approvals::with_history(
            config.approvals(),
            audit.clone(),
            events.clone(),
            request_history.clone(),
        );
        let elicitations = crate::elicitations::Elicitations::with_history(
            audit.clone(),
            events.clone(),
            request_history.clone(),
        );
        let health = Arc::new(crate::health::HealthRegistry::open(
            paths.health_file(),
            events.clone(),
            integrity.clone(),
        ));
        let endpoint_uploads =
            Arc::new(tokio::sync::Semaphore::new(config.endpoint_global_uploads));
        let broker = Arc::new(Self {
            vault,
            data_plane,
            approvals,
            elicitations,
            elicitation_permits: Arc::new(crate::elicitations::ElicitationPermits::default()),
            request_history,
            mcp_auth: crate::mcp_auth::McpAuthSessions::default(),
            manage_oauth: Mutex::new(HashMap::new()),
            connect_request_debounce: Mutex::new(std::collections::HashMap::new()),
            recent_retargets: Mutex::new(HashMap::new()),
            auth_failure_debounce: Mutex::new(HashMap::new()),
            public_url: Mutex::new(None),
            data_plane_bind: std::sync::OnceLock::new(),
            advertise_host: std::sync::OnceLock::new(),
            sidecar_mcp_port: Mutex::new(None),
            pg_proxy_port: std::sync::OnceLock::new(),
            token_limiter: KeyedLimiter::new(
                config.per_identity_per_min,
                std::time::Duration::from_secs(60),
            ),
            manage_auth_limiter: KeyedLimiter::new(10, std::time::Duration::from_secs(60)),
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
            mcp_tools_cache: Mutex::new(HashMap::new()),
            _instance_lock: instance_lock,
        });
        // Check the state that carries its own tamper evidence, and record
        // what the check found. A log that was edited or shortened is exactly
        // what the user needs told, and telling them in the log is fine: the
        // alert is chained onto whatever survived, so hiding it means breaking
        // the chain again.
        let audit_integrity = broker.audit.verify();
        if !audit_integrity.is_verified() {
            tracing::error!("{}", audit_integrity.summary());
            broker.audit.append(
                AuditEntry::new(
                    AuditKind::IntegrityAlert,
                    "Activity log integrity check failed".to_string(),
                )
                .detail(audit_integrity.summary())
                .outcome("integrity_failed")
                .field("file", "audit.jsonl"),
            );
        }
        if broker.health.was_discarded() {
            broker.audit.append(
                AuditEntry::new(
                    AuditKind::IntegrityAlert,
                    "Connection health was rewritten on disk and has been discarded".to_string(),
                )
                .detail(
                    "Health badges are advisory and re-learn themselves on the next check, so \
                     the file was dropped rather than trusted."
                        .to_string(),
                )
                .outcome("integrity_failed")
                .field("file", "health.json"),
            );
        }
        // A tool disappearing from the list because its kind was retired is a
        // change to what the user configured, so it is recorded where they can
        // see it rather than left in the process log.
        for dropped in broker.store.retired_connections_dropped() {
            broker.audit.append(
                AuditEntry::new(
                    AuditKind::ConnectionDeleted,
                    format!("Tool removed on upgrade: {dropped}"),
                )
                .detail(
                    "This build no longer supports that connection type. Its secrets are \
                     untouched and still in the vault."
                        .to_string(),
                )
                .field("reason", "connection_kind_retired"),
            );
        }
        if start_background_tasks {
            // Keeps OAuth-minted MCP access tokens fresh in the background;
            // the task holds only a weak reference and exits when the broker
            // drops. Offline management commands must not contact providers
            // or mutate unrelated connections.
            crate::mcp_refresh::spawn_refresh_sweeper(&broker);
        }
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

    /// The address the PG proxy and API endpoints bind to (loopback by
    /// default).
    pub fn data_plane_bind(&self) -> std::net::IpAddr {
        *self
            .data_plane_bind
            .get()
            .unwrap_or(&std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
    }

    /// The host put into returned data-plane URLs/DSNs (loopback by
    /// default). A bare IPv6 literal is bracketed so `scheme://host:port`
    /// forms stay parseable.
    pub fn advertise_host(&self) -> String {
        let host = self
            .advertise_host
            .get()
            .cloned()
            .unwrap_or_else(|| "127.0.0.1".to_string());
        if host.contains(':') && !host.starts_with('[') {
            format!("[{host}]")
        } else {
            host
        }
    }

    /// The advertised data-plane host when it points beyond this machine —
    /// `None` while PG opens hand back loopback addresses.
    pub fn data_plane_advertised(&self) -> Option<String> {
        let host = self.advertise_host();
        match host.trim_start_matches('[').trim_end_matches(']') {
            "127.0.0.1" | "localhost" | "::1" => None,
            _ => Some(host),
        }
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

    /// Record one rejected control-plane credential, coalescing identical
    /// failures for 30 seconds. No token material is included in the key or
    /// entry.
    pub(crate) fn audit_auth_failure(
        &self,
        plane: &str,
        reason: &str,
        transport: &str,
        peer: Option<&str>,
    ) {
        const COALESCE: Duration = Duration::from_secs(30);
        const MAX_KEYS: usize = 1024;
        let key = format!(
            "{plane}\u{1f}{transport}\u{1f}{}\u{1f}{reason}",
            peer.unwrap_or("")
        );
        let now = Instant::now();
        {
            let mut recent = self.auth_failure_debounce.lock().unwrap();
            recent.retain(|_, at| now.duration_since(*at) < COALESCE);
            if recent.contains_key(&key) {
                return;
            }
            if recent.len() >= MAX_KEYS {
                if let Some(oldest) = recent
                    .iter()
                    .min_by_key(|(_, at)| *at)
                    .map(|(key, _)| key.clone())
                {
                    recent.remove(&oldest);
                }
            }
            recent.insert(key, now);
        }
        let kind = if plane == "manage" && reason == "token_expired" {
            AuditKind::ManagementTokenExpired
        } else {
            AuditKind::AuthenticationFailed
        };
        let mut entry = AuditEntry::new(
            kind,
            if kind == AuditKind::ManagementTokenExpired {
                "Management token expired".to_string()
            } else {
                format!("Rejected {plane} authentication")
            },
        )
        .outcome(reason)
        .field("plane", plane)
        .field("transport", transport);
        if let Some(peer) = peer {
            entry = entry.field("peer_addr", peer);
        }
        self.audit.append(entry);
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
        let confirmation = if new_value.is_some() {
            let meta = self.store.secret_by_id(id)?;
            Some(self.confirm_user_action(&format!(
                "Replace the stored value of secret “{}”",
                meta.name
            ))?)
        } else {
            None
        };
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
        let mut closed_sessions = 0;
        if let Some(value) = new_value {
            meta = self.store.replace_secret_value(id, value)?;
            changes.push("value replaced".into());
            // Rotating a credential has to reach the traffic already using it.
            // A live session authenticated with the old value keeps working
            // until it idles out, which is exactly the window a rotation is
            // meant to close — so drop the sessions of every tool bound to
            // this secret and make the next call redial with the new value.
            // A rename leaves the value alone and needs none of this.
            for connection in self.store.list_connections() {
                if connection.secrets.contains(id) {
                    self.approvals.revoke(&connection.id);
                    self.elicitations.revoke(&connection.id);
                    closed_sessions += self.data_plane.close_connection_sessions(&connection.id);
                }
            }
        }
        if !changes.is_empty() {
            let mut entry = AuditEntry::new(
                AuditKind::SecretUpdated,
                format!("Secret updated: {}", meta.name),
            )
            .detail(changes.join(" · "))
            .field("value_replaced", value_replaced)
            .field("closed_sessions", closed_sessions);
            if let Some((from, to, rewritten)) = rename {
                entry = entry
                    .field("renamed_from", from)
                    .field("renamed_to", to)
                    .field("templates_rewritten", rewritten);
            }
            if let Some(confirmation) = confirmation {
                entry = entry.confirmation(confirmation);
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
        let meta = self.store.secret_by_id(id)?;
        let prefix = self.store.reveal_secret_prefix(id).await?;
        self.audit.append(
            AuditEntry::new(
                AuditKind::SecretRevealed,
                format!("Secret prefix revealed: {}", meta.name),
            )
            .field("characters", prefix.chars().count().saturating_sub(1)),
        );
        Ok(prefix)
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

    /// Management backends are bearer-authorized and may be network
    /// reachable, so releasing plaintext through them requires a fresh
    /// step-up rather than merely riding the ordinary read-presence window.
    pub async fn ui_managed_secret_value_for_copy(&self, id: &Uuid) -> Result<SecretValue> {
        let meta = self.store.secret_by_id(id)?;
        let store = self.store.clone();
        let description = format!("Copy secret “{}” through management", meta.name);
        tokio::task::spawn_blocking(move || store.confirm_action(&description))
            .await
            .map_err(|e| CoreError::Vault(format!("confirmation task failed: {e}")))??;
        crate::authorization::scope(true, self.store.secret_value(id)).await
    }

    /// Release the shared agent key through a management backend only after
    /// a fresh step-up, and attribute that release in the audit trail.
    pub fn ui_agent_key_for_copy(&self) -> Result<String> {
        let confirmation = self.confirm_action("Copy the shared agent key through management")?;
        self.audit.append(
            AuditEntry::new(AuditKind::SecretCopied, "Shared key copied")
                .confirmation(confirmation)
                .field("credential", "agent_key")
                .field("surface", "management"),
        );
        Ok(self.identity.token())
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
    /// authentication do. Any capability change closes the tool's live
    /// sessions, so in-flight traffic cannot outlive the settings it was
    /// authorized under. When the pinned target changes, its direct endpoints
    /// are revoked as well: a pasted address granted for one destination must
    /// not silently cover another.
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
        // A live session was authenticated with the *old* configuration and
        // the *old* credential, and it keeps carrying traffic after the user
        // has changed both. Retargeting is only the loudest case: rebinding a
        // Postgres tool to a different secret leaves the target untouched, and
        // repinning an MCP path changes what the session may reach without
        // changing where it dials. Close on any capability change — the
        // agent's next call redials under the settings the user just chose.
        let mut closed_sessions = 0;
        if capability_changed {
            closed_sessions = self.data_plane.close_connection_sessions(id);
        }
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
            // An open approval window was permission for traffic to the old
            // destination; the new one has never been shown to the user.
            self.approvals.revoke(id);
            // A parked elicitation asked about the old destination; its answer
            // no longer maps to anything, so cancel it too.
            self.elicitations.revoke(id);
            // A health result for the old destination says nothing about
            // the new one.
            self.health.forget(id);
            // Nor do the old destination's advertised tools.
            self.forget_mcp_tools_cache(id);
            let mut recent = self.recent_retargets.lock().unwrap();
            let now = Instant::now();
            recent.retain(|_, at| now.duration_since(*at) < Duration::from_secs(60));
            recent.insert(*id, now);
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
        .field("endpoints_revoked", endpoints_revoked)
        .field("closed_sessions", closed_sessions);
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
        self.forget_mcp_tools_cache(id);
        self.approvals.revoke(id);
        self.elicitations.revoke(id);
        let dropped = self.access.remove_for_connection(id)?;
        let endpoints = self.endpoints.remove_for_connection(id)?;
        self.teardown_endpoints(&endpoints);
        // The connection is gone, so nothing it authorized may keep running:
        // invalidate its tickets and close its live sessions, ticket-served
        // ones included.
        let closed_sessions = self.data_plane.close_connection_sessions(id);
        if dropped || !endpoints.is_empty() {
            self.events.wirings_changed();
        }
        self.audit.append(
            AuditEntry::new(
                AuditKind::ConnectionDeleted,
                format!("Tool deleted: {}", conn.name),
            )
            .connection(conn.name.clone())
            .field("closed_sessions", closed_sessions),
        );
        Ok(conn)
    }

    /// Persist a user-chosen order for the Tools list (drag to reorder).
    /// `ordered_ids` is the full desired front-to-back order; the store is
    /// lenient about a list that raced an add/delete. This is display metadata
    /// only — it touches no capability, secret, or access state — so there is
    /// no native confirmation and no audit entry, but every observer refreshes
    /// so all windows (and a remote manager) converge on the new order.
    pub fn ui_reorder_connections(&self, ordered_ids: &[Uuid]) -> Result<()> {
        let _gate = self.config_gate.lock().unwrap();
        self.store.reorder_connections(ordered_ids)?;
        self.events.connections_changed();
        Ok(())
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
                _ => Err(crate::capability::TestError::from(
                    "Draft tests cover Postgres and SSH connections",
                )),
            }
        };
        let outcome = match tokio::time::timeout(TEST_TIMEOUT, test).await {
            Ok(result) => result,
            Err(_) => Err(crate::capability::TestError::new(
                crate::capability::TestErrorKind::Timeout,
                format!("No answer within {} seconds", TEST_TIMEOUT.as_secs()),
            )),
        };
        Ok(match outcome {
            Ok(detail) => ConnectionTestReport {
                ok: true,
                detail,
                kind: None,
            },
            Err(e) => ConnectionTestReport {
                ok: false,
                detail: e.detail,
                kind: Some(e.kind),
            },
        })
    }

    /// UI-initiated connectivity/credential test against the connection's
    /// pinned destination. The credential travels only on the upstream leg,
    /// exactly as it would for a brokered agent request; only a pass/fail
    /// summary comes back.
    pub async fn ui_test_connection(&self, id: &Uuid) -> Result<ConnectionTestReport> {
        const TEST_TIMEOUT: Duration = Duration::from_secs(15);
        const RETARGET_STEP_UP_WINDOW: Duration = Duration::from_secs(60);
        let mut connection = self.store.connection_by_id(id)?;
        let recently_retargeted = {
            let now = Instant::now();
            let mut recent = self.recent_retargets.lock().unwrap();
            recent.retain(|_, at| now.duration_since(*at) < RETARGET_STEP_UP_WINDOW);
            recent.contains_key(id)
        };
        let confirmation = if recently_retargeted {
            Some(self.confirm_action(&format!(
                "Test newly retargeted tool “{}” with its stored credential",
                connection.name
            ))?)
        } else {
            None
        };
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
                ConnectionKind::Ssh => crate::capability::ssh::test_login(self, &connection).await,
            }
        };
        // Testing rides the same pre-authorization as the agent plane: any
        // enabled agent can already open this connection with no prompt, so
        // the user's own Test button reading the secret it is about to send
        // to the pinned destination must not re-authenticate either.
        let test = crate::authorization::scope(true, test);
        let outcome = match tokio::time::timeout(TEST_TIMEOUT, test).await {
            Ok(result) => result,
            Err(_) => Err(crate::capability::TestError::new(
                crate::capability::TestErrorKind::Timeout,
                format!("No answer within {} seconds", TEST_TIMEOUT.as_secs()),
            )),
        };
        let report = match outcome {
            Ok(detail) => ConnectionTestReport {
                ok: true,
                detail,
                kind: None,
            },
            Err(e) => ConnectionTestReport {
                ok: false,
                detail: e.detail,
                kind: Some(e.kind),
            },
        };
        // The test result is the connection's new last-known health, graded by
        // the same mapping the data planes use.
        let status = match report.kind {
            None => crate::types::HealthStatus::Ok,
            Some(kind) => kind.health_status(),
        };
        self.health.record(id, status, report.detail.clone());
        let mut entry = AuditEntry::new(
            AuditKind::ConnectionTested,
            format!("Tool tested: {}", connection.name),
        )
        .connection(connection.name.clone())
        .outcome(if report.ok { "succeeded" } else { "failed" })
        .field("target", connection.target())
        .field("recently_retargeted", recently_retargeted)
        .field(
            "failure_kind",
            report
                .kind
                .map(|kind| format!("{kind:?}").to_ascii_lowercase()),
        );
        if let Some(confirmation) = confirmation {
            entry = entry.confirmation(confirmation);
        }
        self.audit.append(entry);
        Ok(report)
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
                "OAuth connect requires a plain api config with an oauth section \
                 (MCP servers use the sign-in flow instead)"
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
        let secret_id = crate::oauth::oauth_token_secret_id(&conn)
            .map_err(CoreError::InvalidConnectionConfig)?;
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
                    .connection(conn.name.clone())
                    .field("oauth", true),
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
                "OAuth connect requires a plain api config with an oauth section \
                 (MCP servers use the sign-in flow instead)"
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
        let secret_id = crate::oauth::oauth_token_secret_id(&conn)
            .map_err(CoreError::InvalidConnectionConfig)?;
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
        mut options: crate::mcp::McpCheckOptions,
    ) -> Result<crate::mcp::McpStatusReport> {
        const CHECK_TIMEOUT: Duration = Duration::from_secs(45);
        let mut connection = self.store.connection_by_id(id)?;
        if let (Some(whoami), Some(allowed)) =
            (options.whoami_tool.as_ref(), self.access.allowed_tools(id))
        {
            if !allowed.iter().any(|tool| tool == whoami) {
                options.whoami_tool = None;
            }
        }
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
        if let Some(tool) = report.status_tool_invoked.as_deref() {
            self.audit.append(
                AuditEntry::new(
                    AuditKind::ConnectionTested,
                    format!("MCP account status checked: {}", connection.name),
                )
                .connection(connection.name.clone())
                .outcome(if report.ok { "ok" } else { "failed" })
                .field("mcp_method", "tools/call")
                .field("mcp_name", tool),
            );
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
    /// `agentmfa_connect` tool). This records the ask and pokes the shell
    /// so the user can add the tool — nothing is created or granted here,
    /// and the same client label asking for the same service within a minute
    /// is coalesced. Returns whether this call surfaced a fresh request.
    pub fn agent_connect_request(&self, client: &str, service: &str) -> Result<bool> {
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
            let key = (client.to_string(), service.to_ascii_lowercase());
            if !remember_connect_request(&mut recent, key, Instant::now()) {
                return Ok(false);
            }
        }
        self.audit.append(
            AuditEntry::new(
                AuditKind::ConnectRequested,
                format!("{client} asked to connect: {service}"),
            )
            .agent(client.to_string())
            .detail("A request only — add the tool in AgentMFA to grant it")
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

        // Park the plaintext in the vault, keyed by the endpoint id. The state
        // file keeps only the hash, so a copy-back still works after a restart
        // without `endpoints.json` being a second credential store.
        self.store_endpoint_secret(&issued.endpoint.id, &issued.secret);

        // Read back the just-persisted record so the API loopback port
        // (assigned during bind) is present.
        let mut record = self
            .endpoints
            .get(&issued.endpoint.id)
            .unwrap_or_else(|| issued.endpoint.clone());
        record.secret = issued.secret.clone();
        let info = self.endpoint_info(&connection, &record).await?;
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

    /// Build the pasteable address (DSN / socket path / base URL), the
    /// retained secret, and a copy-ready example for an existing endpoint
    /// record. Shared by issuance and read-back so both present the identical
    /// address; performs no minting, gating, or listener work.
    async fn endpoint_info(
        &self,
        connection: &Connection,
        endpoint: &DirectEndpoint,
    ) -> Result<IssuedEndpointInfo> {
        let dir = self.paths.endpoint_dir(&endpoint.id);
        let recovered = self.endpoint_secret_for(endpoint).await;
        let secret = recovered.as_str();
        let info = match &connection.config {
            ConnectionConfig::Pg { user, dbname, .. } => {
                // A pre-retention record (empty secret) prints the
                // password-less DSN until it is reissued.
                let dsn = crate::capability::pg::endpoint_dsn(
                    dir.as_path(),
                    user,
                    dbname,
                    (!secret.is_empty()).then_some(secret),
                );
                // .env-shaped on purpose: the expected home for a brokered
                // DSN is a config file, not a shell command — argv would
                // leave the embedded secret in history and `ps` output.
                let example = format!("DATABASE_URL=\"{dsn}\"");
                // The TCP form for drivers with no Unix-socket support, and the
                // only form that works at all when the broker is not on the
                // caller's machine. `advertise_host` is what a remote client
                // should dial, which is not necessarily what we bound.
                let tcp_dsn = endpoint.port.map(|port| {
                    crate::capability::pg::endpoint_tcp_dsn(
                        &self.advertise_host(),
                        port,
                        user,
                        dbname,
                        (!secret.is_empty()).then_some(secret),
                    )
                });
                IssuedEndpointInfo {
                    endpoint_id: endpoint.id,
                    kind: ConnectionKind::Pg,
                    dsn,
                    tcp_dsn,
                    secret: recovered.clone(),
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
                let sock = crate::capability::ssh::endpoint_sock_path(dir.as_path(), secret)
                    .display()
                    .to_string();
                let target = ssh_endpoint_invocation(destination.as_deref(), user, host, *port);
                // SSH has no presented secret: the ssh-agent protocol offers no
                // password, so the socket path is the whole capability. The
                // minted secret is not surfaced.
                IssuedEndpointInfo {
                    endpoint_id: endpoint.id,
                    kind: ConnectionKind::Ssh,
                    dsn: sock.clone(),
                    // The socket path is the only address an ssh-agent has.
                    tcp_dsn: None,
                    secret: String::new(),
                    example: format!("SSH_AUTH_SOCK=\"{sock}\" {target}"),
                }
            }
            ConnectionConfig::Api { .. } => {
                // The loopback port was assigned (and persisted) during bind.
                let port = endpoint
                    .port
                    .ok_or_else(|| CoreError::Vault("http endpoint bound no port".to_string()))?;
                let base = format!("http://{}:{port}", self.advertise_host());
                IssuedEndpointInfo {
                    endpoint_id: endpoint.id,
                    kind: ConnectionKind::Api,
                    dsn: base.clone(),
                    // The HTTP endpoint is already TCP; `dsn` is that address.
                    tcp_dsn: None,
                    secret: recovered.clone(),
                    // The secret rides an Authorization header, not the URL, so
                    // it stays out of argv and shell history; the proxy strips
                    // it and injects the real credential upstream.
                    // Runnable as-is; the trailing slash is what marks where
                    // an upstream route goes, since the proxy forwards the
                    // path through and the bare root 404s on most APIs.
                    example: format!("curl -H \"Authorization: Bearer {secret}\" {base}/"),
                }
            }
        };
        Ok(info)
    }

    /// Read an existing direct endpoint's pasteable address and retained
    /// secret without minting or rotating; `None` when none is issued for the
    /// connection. The address contains a standing credential, so read-back
    /// takes a fresh gate and is audited just like copying a stored secret.
    pub async fn ui_get_endpoint(
        &self,
        connection_id: &Uuid,
    ) -> Result<Option<IssuedEndpointInfo>> {
        let connection = self.store.connection_by_id(connection_id)?;
        let Some(endpoint) = self.endpoints.get_for_connection(connection_id) else {
            return Ok(None);
        };
        let store = self.store.clone();
        let description = format!("Copy the direct endpoint for “{}”", connection.name);
        let confirmation = tokio::task::spawn_blocking(move || store.confirm_action(&description))
            .await
            .map_err(|e| CoreError::Vault(format!("confirmation task failed: {e}")))??;
        let info = self.endpoint_info(&connection, &endpoint).await?;
        self.audit.append(
            AuditEntry::new(
                AuditKind::SecretCopied,
                format!("Direct endpoint copied: {}", connection.name),
            )
            .connection(connection.name)
            .confirmation(confirmation)
            .field("endpoint_id", endpoint.id.to_string()),
        );
        Ok(Some(info))
    }

    /// The vault item holding one endpoint's plaintext secret.
    ///
    /// Keyed by the endpoint's own id: there is no `Secret` index entry, so it
    /// never appears in the Secrets tab, and revoking the endpoint removes it.
    fn store_endpoint_secret(&self, endpoint_id: &Uuid, secret: &str) {
        let attrs = crate::vault::VaultAttrs {
            name: format!("endpoint:{endpoint_id}"),
            created_at: chrono::Utc::now(),
        };
        if let Err(error) = self.vault.set(
            endpoint_id,
            &attrs,
            &zeroize::Zeroizing::new(secret.to_string()),
        ) {
            // Not fatal: the endpoint works (its hash is what authenticates),
            // only the copy-back affordance is lost.
            tracing::warn!("could not store the endpoint secret in the vault: {error}");
        }
    }

    /// The plaintext for an endpoint, for rebuilding a pasteable address.
    /// Empty when it cannot be recovered, which renders a password-less form.
    pub(crate) async fn endpoint_secret_for(&self, endpoint: &DirectEndpoint) -> String {
        // A legacy record still carrying its plaintext is used as-is and
        // migrated into the vault, so the next read comes from there.
        if !endpoint.secret.is_empty() {
            self.store_endpoint_secret(&endpoint.id, &endpoint.secret);
            return endpoint.secret.clone();
        }
        match self.vault.get(&endpoint.id).await {
            Ok(value) => value.to_string(),
            Err(_) => String::new(),
        }
    }

    /// Revoke one direct endpoint: drop the record, stop its listener, and
    /// close any live sessions it was serving.
    pub fn ui_revoke_endpoint(&self, endpoint_id: &Uuid) -> Result<bool> {
        let _gate = self.config_gate.lock().unwrap();
        let Some(endpoint) = self.endpoints.revoke(endpoint_id)? else {
            return Ok(false);
        };
        let _ = self.vault.delete(&endpoint.id);
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
                let (handle, port) =
                    crate::capability::pg::bind_endpoint(self.clone(), endpoint).await?;
                // Pin the TCP port so a pasted DSN survives a restart, exactly
                // as the HTTP endpoint's base URL does.
                if endpoint.port != Some(port) {
                    let _ = self.endpoints.set_port(&endpoint.id, port);
                }
                handle
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
    /// Disabling withdraws the connection from the data plane outright: every
    /// ticket issued against it is invalidated and every live session it
    /// serves is closed, whether a ticket or a direct endpoint opened it. A
    /// pg or ssh session runs to `session_max_ttl` once established, so
    /// refusing the next open would otherwise leave an authenticated upstream
    /// connection alive for an hour after the user revoked it. The issued
    /// endpoint itself remains available for later re-enabling.
    pub fn ui_set_tool_access(&self, connection_id: &Uuid, enabled: bool) -> Result<bool> {
        let connection = self.store.connection_by_id(connection_id)?;
        // Turning access **on** hands every agent on this machine standing use
        // of the credential — the same grant `ui_issue_endpoint` takes the
        // native gate for, and strictly more than it (an endpoint covers one
        // pasted address; this covers every agent). Turning it **off** only
        // narrows, so it stays free: revocation must never wait on
        // authentication.
        //
        // Only a real off→on transition prompts. A no-op call, or the
        // enabled-by-default state a new connection already has, is not a
        // change in authority and must not put a sheet in front of the user.
        let confirmation = if enabled && !self.access.allows(connection_id) {
            Some(self.confirm_action(&format!(
                "Let agents use “{}” — every agent on this computer can use its \
                 saved credential until you turn this off",
                connection.name
            ))?)
        } else {
            None
        };
        let _gate = self.config_gate.lock().unwrap();
        let changed = self.access.set_enabled(*connection_id, enabled)?;
        if changed {
            let closed_sessions = if enabled {
                0
            } else {
                self.data_plane.close_connection_sessions(connection_id)
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
                .field("closed_sessions", closed_sessions)
                .maybe_confirmation(confirmation),
            );
            self.events.wirings_changed();
        }
        if !enabled {
            // Nothing is authorized here any more, so an open window and a
            // prompt already on screen both have to go — along with any
            // upstream elicitation parked on this connection.
            self.approvals.revoke(connection_id);
            self.elicitations.revoke(connection_id);
        }
        Ok(changed)
    }

    /// Ask the user to confirm this connection's traffic — or stop asking.
    ///
    /// Turning it **on** only adds friction, so the in-app switch is the
    /// gate. Turning it **off** removes a gate the user deliberately put
    /// up, which is the same class of change as disabling the read gate:
    /// it takes a real authentication, and the presence window does not
    /// cover it. That is also what the prompt's "Approve all" button
    /// routes through, so "stop asking" can never be one stray click.
    pub fn ui_set_confirm_mode(&self, connection_id: &Uuid, confirm: ConfirmMode) -> Result<bool> {
        self.ui_set_confirm_mode_with_resolution(
            connection_id,
            confirm,
            crate::request_history::RequestResolution::ConfirmationDisabled,
        )
    }

    fn ui_set_confirm_mode_with_resolution(
        &self,
        connection_id: &Uuid,
        confirm: ConfirmMode,
        release_resolution: crate::request_history::RequestResolution,
    ) -> Result<bool> {
        let connection = self.store.connection_by_id(connection_id)?;
        let old_mode = self.access.confirm_mode(connection_id);
        let confirmation = if confirm.is_on() {
            None
        } else if old_mode.is_on() {
            Some(self.confirm_action(&format!(
                "stop confirming traffic on “{}” — agents will use it without asking",
                connection.name
            ))?)
        } else {
            None
        };
        let _gate = self.config_gate.lock().unwrap();
        let current = self.store.connection_by_id(connection_id)?;
        if current.updated_at != connection.updated_at {
            return Err(CoreError::ApprovalConnectionChanged);
        }
        let current_mode = self.access.confirm_mode(connection_id);
        if current_mode == confirm {
            return Ok(false);
        }
        // In particular, an unauthenticated "already off" request must not
        // turn off a mode another window enabled while this call was waiting.
        if current_mode != old_mode {
            return Err(CoreError::ApprovalConnectionChanged);
        }
        let changed = self.access.set_confirm_mode(*connection_id, confirm)?;
        if changed {
            if !confirm.is_on() {
                // The user just said this traffic needs no asking: release
                // whatever is parked on it instead of refusing it.
                self.approvals.release_as(connection_id, release_resolution);
            }
            let mut entry = AuditEntry::new(
                AuditKind::Wired,
                format!(
                    "Traffic confirmation {} for {}",
                    if confirm.is_on() {
                        "enabled"
                    } else {
                        "disabled"
                    },
                    connection.name
                ),
            )
            .connection(connection.name.clone())
            .field("confirm", confirm.is_on());
            if let Some(confirmation) = confirmation {
                entry = entry.confirmation(confirmation);
            }
            self.audit.append(entry);
            self.events.wirings_changed();
        }
        Ok(changed)
    }

    /* ------------------------- traffic confirmation ----------------------- */

    /// Prompts waiting on the user right now.
    pub fn pending_approvals(&self) -> Vec<crate::approvals::PendingApproval> {
        self.approvals.pending()
    }

    /// Request decision lifecycles for management clients' Recent Inbox.
    pub fn request_records(&self) -> Vec<crate::request_history::RequestRecord> {
        // Keep deadline retirement and waiter counts authoritative before
        // reading the shared lifecycle store.
        let _ = self.approvals.pending();
        self.request_history.records()
    }

    /// Answer a prompt. "Approve all" persists the switch going off first —
    /// through [`Self::ui_set_confirm_mode`] and its authentication — so a
    /// refused authentication leaves the traffic parked and the prompt up,
    /// rather than half-applying the decision.
    pub fn ui_respond_approval(
        &self,
        id: &Uuid,
        decision: crate::approvals::ApprovalDecision,
    ) -> Result<bool> {
        if decision == crate::approvals::ApprovalDecision::ApproveAll {
            let Some(pending) = self
                .approvals
                .pending()
                .into_iter()
                .find(|pending| &pending.id == id)
            else {
                return Ok(false);
            };
            // Turning the switch off releases everything parked on the
            // connection, this prompt included — so there is nothing left
            // to answer afterwards. A no-op change (the switch was already
            // off, raced by another window) still has to release it.
            if !self.ui_set_confirm_mode_with_resolution(
                &pending.connection_id,
                ConfirmMode::Off,
                crate::request_history::RequestResolution::ApprovedAll,
            )? {
                self.approvals.release_as(
                    &pending.connection_id,
                    crate::request_history::RequestResolution::ApprovedAll,
                );
            }
            return Ok(true);
        }
        Ok(self.approvals.respond(id, decision))
    }

    /* ---------------------------- elicitation ----------------------------- */

    /// Elicitations waiting on the user right now.
    pub fn pending_elicitations(&self) -> Vec<crate::elicitations::PendingElicitation> {
        self.elicitations.pending()
    }

    /// Answer one elicitation from the app: `approved` with the user's field
    /// values accepts, otherwise it declines. `false` means it was already
    /// answered, cancelled, or has lapsed.
    pub fn ui_respond_elicitation(
        &self,
        id: &Uuid,
        approved: bool,
        values: std::collections::HashMap<String, String>,
    ) -> Result<bool> {
        Ok(self.elicitations.respond(id, approved, values))
    }

    /// Park an upstream elicitation on the user and wait for the answer. The
    /// sidecar drives this on the agent's behalf mid tool call; the answer is
    /// shaped as an MCP `ElicitResult`.
    pub async fn elicit(
        &self,
        request: crate::elicitations::ElicitationRequest,
    ) -> crate::elicitations::ElicitationOutcome {
        self.elicitations.elicit(request).await
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
            // A pending prompt or open window was admitted under the old
            // tool subset. Narrowing must take effect before any parked call
            // can leave; widening should likewise require a fresh decision.
            self.approvals.revoke(connection_id);
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
    pub async fn ui_list_mcp_tools(&self, id: &Uuid) -> Result<crate::mcp::McpToolCatalog> {
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
        let live = crate::authorization::scope(
            true,
            crate::mcp::list_tools(&self.store, &self.http_client, &connection),
        )
        .await;
        match live {
            Ok(listing) => {
                // Remember the last good listing so a later open can still
                // curate the subset once the credential has lapsed.
                let fetched_at = chrono::Utc::now();
                self.mcp_tools_cache.lock().unwrap().insert(
                    *id,
                    CachedMcpTools {
                        fetched_at,
                        listing: listing.clone(),
                    },
                );
                Ok(crate::mcp::McpToolCatalog {
                    tools: listing.tools,
                    truncated: listing.truncated,
                    stale: false,
                    fetched_at,
                    cache_age_seconds: 0,
                })
            }
            Err(error) => {
                // A live listing needs a valid credential; when it can't be
                // had — a lapsed OAuth token, a brief upstream outage — fall
                // back to the last good listing rather than forcing a
                // reconnect just to change which tools agents may call.
                if let Some(cached) = self.mcp_tools_cache.lock().unwrap().get(id).cloned() {
                    let age = chrono::Utc::now()
                        .signed_duration_since(cached.fetched_at)
                        .num_seconds()
                        .max(0) as u64;
                    return Ok(crate::mcp::McpToolCatalog {
                        tools: cached.listing.tools,
                        truncated: cached.listing.truncated,
                        stale: true,
                        fetched_at: cached.fetched_at,
                        cache_age_seconds: age,
                    });
                }
                Err(CoreError::InvalidConnectionConfig(error))
            }
        }
    }

    /// Drop a connection's cached MCP tool listing. Called when the pinned
    /// destination changes (the old server's tools say nothing about the new
    /// one) or the connection is removed.
    fn forget_mcp_tools_cache(&self, id: &Uuid) {
        self.mcp_tools_cache.lock().unwrap().remove(id);
    }

    /* ------------------------- shared identity (UI) ------------------------ */

    /// The persisted identity record (hash, timestamps, migration aliases —
    /// never the plaintext key).
    pub fn identity_info(&self) -> BrokerIdentity {
        self.identity.info()
    }

    /// Rotate this computer's key: mint a fresh one, rewrite the token
    /// file, clear the migration aliases, and close every outstanding
    /// data-plane capability, including standing direct endpoints. This is
    /// the "disconnect everything" action — agents that read the token file
    /// reconnect on their own; pasted endpoint addresses must be reissued.
    /// The single native sheet is both the warning and the gate: its reason
    /// text carries the consequences, so no separate dialog precedes it.
    pub fn ui_rotate_key(&self) -> Result<()> {
        let confirmation = self.confirm_action(
            "rotate this computer's key — every live agent session closes now, \
             and agents reconnect on their own from the key file",
        )?;
        let _gate = self.config_gate.lock().unwrap();
        // Revoke standing capabilities before rotating the shared identity.
        // If a persistence error interrupts the operation, failing with fewer
        // live capabilities is safer than leaving an endpoint usable after a
        // successful identity rotation.
        let endpoints = self.endpoints.revoke_all()?;
        for endpoint in &endpoints {
            let _ = self.vault.delete(&endpoint.id);
        }
        self.teardown_endpoints(&endpoints);
        self.identity.rotate()?;
        let sessions_closed = self.data_plane.close_all();
        // An approval window is permission for traffic from the generation
        // being disconnected; it must not outlive it.
        self.approvals.revoke_all();
        self.audit.append(
            AuditEntry::new(
                AuditKind::TokenRevoked,
                "Key rotated; all agents disconnected".to_string(),
            )
            .confirmation(confirmation)
            .field("sessions_closed", sessions_closed)
            .field("endpoints_revoked", endpoints.len()),
        );
        self.events.agents_changed();
        Ok(())
    }

    /* --------------------------- live sessions ---------------------------- */

    pub fn sessions(&self) -> Vec<SessionInfo> {
        self.data_plane.sessions()
    }

    /// Stop standing endpoint listeners, invalidate outstanding tickets, and
    /// signal every established data-plane transport. The daemon stops its
    /// accept loops first; this covers the independently owned endpoint
    /// listeners and lets a process supervisor wait for clean audit/accounting
    /// teardown before the runtime disappears.
    pub fn begin_shutdown(&self) -> usize {
        let listeners = {
            let mut listeners = self.endpoint_listeners.lock().unwrap();
            std::mem::take(&mut *listeners)
        };
        for (_, listener) in listeners {
            listener.stop();
        }
        self.data_plane.close_all()
    }

    /// Wait for signalled session tasks to retire their accounting. Returns
    /// false at the deadline so shutdown remains bounded under a stuck
    /// upstream transport.
    pub async fn wait_for_session_drain(&self, timeout: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if self.data_plane.sessions().is_empty() {
                return true;
            }
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    /// Close a live session immediately. This is a remediation action: ending
    /// an agent's access must not be delayed by native authentication.
    pub fn ui_close_session(&self, id: u64) -> Result<bool> {
        Ok(self.data_plane.close_session(id))
    }

    /// Clear the audit log only after a fresh full-authority confirmation,
    /// then leave a tombstone as the first entry in the new chain.
    pub fn ui_clear_activity(&self) -> Result<()> {
        let confirmation =
            self.confirm_action("Clear AgentMFA activity history and restart its audit chain")?;
        let removed = self.audit.recent(usize::MAX).len();
        self.audit.clear()?;
        self.audit.append(
            AuditEntry::new(AuditKind::ActivityCleared, "Activity history cleared")
                .confirmation(confirmation)
                .field("entries_removed", removed)
                .field("surface", "management"),
        );
        Ok(())
    }

    /* ----------------------------- settings ------------------------------- */

    pub fn settings(&self) -> Settings {
        self.store.settings()
    }

    pub fn ui_change_reauth_on_read(&self, on: bool) -> Result<()> {
        let old = self.store.settings().reauth_on_read;
        if old == on {
            return Ok(());
        }
        let confirmation = if !on {
            // Weakening the read gate always re-prompts; the presence window
            // does not cover it.
            Some(self.confirm_action("Disable OS authentication requirement for reading secrets")?)
        } else {
            None
        };
        self.store.set_reauth_on_read(on)?;
        self.store.clear_user_presence();
        self.audit.append(
            AuditEntry::new(
                AuditKind::SettingsChanged,
                "Setting changed: require authentication to read secrets",
            )
            .field("setting", "reauth_on_read")
            .field("old", old)
            .field("new", on)
            .maybe_confirmation(confirmation),
        );
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
        let old = self.store.settings().presence_window_secs;
        if old == secs {
            return Ok(());
        }
        let confirmation = self.confirm_user_action("Change how long AgentMFA stays unlocked")?;
        self.store.set_presence_window_secs(secs)?;
        // Re-anchor the just-confirmed window so a shortened length takes
        // effect now instead of at the old deadline.
        self.store.reanchor_presence();
        self.audit.append(
            AuditEntry::new(
                AuditKind::SettingsChanged,
                "Setting changed: presence window",
            )
            .field("setting", "presence_window_secs")
            .field("old", old)
            .field("new", secs)
            .confirmation(confirmation),
        );
        Ok(())
    }

    pub fn ui_set_menu_bar_hides_dock(&self, on: bool) -> Result<()> {
        let old = self.store.settings().menu_bar_hides_dock;
        if old == on {
            return Ok(());
        }
        self.store.set_menu_bar_hides_dock(on)?;
        self.audit.append(
            AuditEntry::new(
                AuditKind::SettingsChanged,
                "Setting changed: hide Dock icon in menu-bar mode",
            )
            .field("setting", "menu_bar_hides_dock")
            .field("old", old)
            .field("new", on),
        );
        Ok(())
    }
}

fn remember_connect_request(
    recent: &mut HashMap<(String, String), Instant>,
    key: (String, String),
    now: Instant,
) -> bool {
    recent.retain(|_, at| now.duration_since(*at) < CONNECT_REQUEST_DEBOUNCE);
    if recent.contains_key(&key) {
        return false;
    }
    if recent.len() >= MAX_CONNECT_REQUEST_DEBOUNCE_KEYS {
        if let Some(oldest) = recent
            .iter()
            .min_by_key(|(_, at)| *at)
            .map(|(key, _)| key.clone())
        {
            recent.remove(&oldest);
        }
    }
    recent.insert(key, now);
    true
}

/// The `ssh` command an issued endpoint hands the user.
///
/// A non-default port is spelled out even behind an imported alias, so the
/// command reaches the port the tool was configured for rather than whatever
/// `~/.ssh/config` resolves the alias to today. That is a snapshot taken at
/// import: re-point the alias at a new port and the copied command keeps
/// overriding it with the old one until the tool is re-imported. Pinning the
/// tool's own port is the lesser surprise — the alternative silently sends
/// the endpoint somewhere the tool was never configured to reach.
fn ssh_endpoint_invocation(destination: Option<&str>, user: &str, host: &str, port: u16) -> String {
    let flags = crate::capability::ssh::SSH_BROKER_OPTIONS
        .iter()
        .map(|option| format!("-o {option}"))
        .collect::<Vec<_>>()
        .join(" ");
    let port = if port == 22 {
        String::new()
    } else {
        format!(" -p {port}")
    };
    let target = destination
        .map(str::to_string)
        .unwrap_or_else(|| format!("{user}@{host}"));
    format!("ssh{port} {flags} {target}")
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

#[cfg(test)]
mod tests {
    use super::{
        remember_connect_request, ssh_endpoint_invocation, MAX_CONNECT_REQUEST_DEBOUNCE_KEYS,
    };
    use std::collections::HashMap;
    use std::time::{Duration, Instant};

    #[test]
    fn connect_request_debounce_is_hard_bounded() {
        let mut recent = HashMap::new();
        let start = Instant::now();
        for index in 0..(MAX_CONNECT_REQUEST_DEBOUNCE_KEYS + 20) {
            assert!(remember_connect_request(
                &mut recent,
                ("agent".into(), format!("service-{index}")),
                start + Duration::from_millis(index as u64),
            ));
        }
        assert_eq!(recent.len(), MAX_CONNECT_REQUEST_DEBOUNCE_KEYS);
    }

    #[test]
    fn ssh_endpoint_invocation_preserves_imported_non_default_ports() {
        // Derived, not spelled out: the list is the core's, and a copy here
        // would just be a second thing to forget to update.
        let flags = crate::capability::ssh::SSH_BROKER_OPTIONS
            .iter()
            .map(|option| format!("-o {option}"))
            .collect::<Vec<_>>()
            .join(" ");
        assert_eq!(
            ssh_endpoint_invocation(Some("sandbox@127.0.0.1"), "sandbox", "127.0.0.1", 12222),
            format!("ssh -p 12222 {flags} sandbox@127.0.0.1")
        );
        assert_eq!(
            ssh_endpoint_invocation(Some("production"), "deploy", "prod.example.com", 2200),
            format!("ssh -p 2200 {flags} production")
        );
        assert_eq!(
            ssh_endpoint_invocation(Some("production"), "deploy", "prod.example.com", 22),
            format!("ssh {flags} production")
        );
        assert_eq!(
            ssh_endpoint_invocation(None, "deploy", "prod.example.com", 22),
            format!("ssh {flags} deploy@prod.example.com")
        );
    }

    /// SSH-14. `SSH_AUTH_SOCK` alone leaves the default `IdentityFile` list in
    /// place, so a user with a working `~/.ssh/id_ed25519` gets a successful
    /// login with no broker involvement and no audit entry. `IdentitiesOnly=yes`
    /// is the flag that looks right and is wrong: OpenSSH drops agent
    /// identities matching no configured `IdentityFile`, and the broker's key
    /// has no on-disk `.pub`.
    #[test]
    fn the_endpoint_example_suppresses_on_disk_keys_forwarding_and_muxing() {
        let example = ssh_endpoint_invocation(Some("production"), "deploy", "prod.example.com", 22);
        for option in crate::capability::ssh::SSH_BROKER_OPTIONS {
            assert!(example.contains(&format!("-o {option}")), "{example}");
        }
        assert!(!example.contains("IdentitiesOnly"), "{example}");
    }
}
