//! The broker facade: one struct owning the store, wiring table, pairing
//! registry, execution machinery and audit log. The daemon (agent-facing)
//! and the shell (UI-facing Tauri commands, tests, dev harness) both drive
//! it.

use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use uuid::Uuid;

use crate::audit::{AuditEntry, AuditKind, AuditLog};
use crate::config::BrokerConfig;
use crate::error::CoreError;
use crate::events::BrokerEvents;
use crate::executions::Executions;
use crate::pairing::PairingRegistry;
use crate::paths::{BrokerInstanceLock, Paths};
use crate::policy::Wirings;
use crate::ratelimit::{KeyedLimiter, WindowLimiter};
use crate::sessions::{DataPlane, SessionInfo};
use crate::store::{ConnectionSpec, Store};
use crate::types::{
    Connection, ConnectionKind, PairedAgent, SecretMeta, SecretValue, Settings, Wiring, WiringMode,
};
use crate::Result;

const COPY_AUTHORIZATION_TTL: Duration = Duration::from_secs(5 * 60);

/// Outcome of a UI-initiated connection test: a pass/fail flag plus a short
/// human-readable summary (never credential material).
#[derive(Debug, Clone, serde::Serialize)]
pub struct ConnectionTestReport {
    pub ok: bool,
    pub detail: String,
}

pub struct Broker {
    pub config: BrokerConfig,
    pub paths: Paths,
    pub store: Arc<Store>,
    pub wirings: Arc<Wirings>,
    /// Serializes configuration mutations that read-then-write shared state
    /// (connection edits, wiring changes) so concurrent UI actions cannot
    /// interleave.
    pub(crate) config_gate: Mutex<()>,
    /// A successful OS authentication for a user-initiated clipboard copy may
    /// authorize more clipboard copies briefly. This cache is deliberately
    /// separate from agent execution authorizations and never leaves memory.
    copy_authorization_until: Mutex<Option<Instant>>,
    copy_authorization_gate: tokio::sync::Mutex<()>,
    pub pairing: Arc<PairingRegistry>,
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
    /// The WS bridge's ephemeral loopback port, set when the daemon starts;
    /// surfaced only in open responses.
    pub(crate) ws_bridge_port: std::sync::OnceLock<u16>,
    /// The PG proxy's ephemeral loopback port, set when the daemon starts;
    /// surfaced only in open responses' DSNs.
    pub(crate) pg_proxy_port: std::sync::OnceLock<u16>,
    pub(crate) http_client: reqwest::Client,
    /// Live and recently finished MCP sign-in sessions (`mcp_auth` module).
    pub mcp_auth: crate::mcp_auth::McpAuthSessions,
    /// Recent agent connect-requests, so a retrying agent cannot spam the
    /// activity log or the shell's attention. Never leaves memory.
    connect_request_debounce: Mutex<std::collections::HashMap<(Uuid, String), Instant>>,
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
        // wirings.json, and agents.json refuse to load if tampered with.
        let integrity = Arc::new(crate::integrity::StateIntegrity::open(&*vault).await?);
        let store = Arc::new(Store::open_with_events(
            paths.clone(),
            vault,
            events.clone(),
            integrity.clone(),
        )?);
        let pairing = Arc::new(PairingRegistry::open(
            paths.agents_file(),
            config.token_ttl,
            integrity.clone(),
        )?);
        let wirings = Arc::new(Wirings::open_with_legacy_rules(
            paths.wirings_file(),
            Some(&paths.rules_file()),
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
        let broker = Arc::new(Self {
            data_plane,
            mcp_auth: crate::mcp_auth::McpAuthSessions::default(),
            connect_request_debounce: Mutex::new(std::collections::HashMap::new()),
            ws_bridge_port: std::sync::OnceLock::new(),
            pg_proxy_port: std::sync::OnceLock::new(),
            token_limiter: KeyedLimiter::new(
                config.per_token_per_min,
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
            wirings,
            config_gate: Mutex::new(()),
            copy_authorization_until: Mutex::new(None),
            copy_authorization_gate: tokio::sync::Mutex::new(()),
            pairing,
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

    /// Demand the shell's native confirmation for a high-consequence
    /// configuration action. Fails closed when the shell refuses or
    /// does not implement the gate.
    fn confirm_action(&self, description: &str) -> Result<crate::types::ConfirmationMethod> {
        self.events
            .confirm_action(description)
            .ok_or(CoreError::NotConfirmed)
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
            self.confirm_action(&format!("Delete secret “{}” from the Keychain", meta.name))?;
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
    /// OS authentication authorizes only subsequent user-initiated copies for
    /// five minutes; agent executions and every other protected action keep
    /// their own authorization scopes.
    pub async fn ui_secret_value_for_copy(&self, id: &Uuid) -> Result<SecretValue> {
        // Serialize copy authorization checks so simultaneous clicks cannot
        // open duplicate native prompts or race to establish the window.
        let _gate = self.copy_authorization_gate.lock().await;

        if !self.store.settings().reauth_on_read {
            *self.copy_authorization_until.lock().unwrap() = None;
            return self.store.secret_value(id).await;
        }

        let authorized = {
            let mut until = self.copy_authorization_until.lock().unwrap();
            match *until {
                Some(deadline) if Instant::now() < deadline => true,
                _ => {
                    *until = None;
                    false
                }
            }
        };
        if authorized {
            return crate::authorization::scope(true, self.store.secret_value(id)).await;
        }

        let meta = self.store.secret_by_id(id)?;
        let events = self.events.clone();
        let confirmed = tokio::task::spawn_blocking(move || {
            events.confirm_secret_copy(&meta, COPY_AUTHORIZATION_TTL)
        })
        .await
        .map_err(|e| CoreError::Vault(format!("confirmation task failed: {e}")))?;
        if !confirmed {
            return Err(CoreError::SecretReadNotAuthenticated);
        }
        let value = crate::authorization::scope(true, self.store.secret_value(id)).await?;
        *self.copy_authorization_until.lock().unwrap() =
            Some(Instant::now() + COPY_AUTHORIZATION_TTL);
        Ok(value)
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
        let confirmation = self.confirm_action(&format!("Add tool “{}”", spec.name))?;
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
        let confirmation = self.confirm_action(&format!("Add tool “{}”", spec.name))?;
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
            Some(self.confirm_action(&format!(
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
            dropped = self.wirings.remove_for_connection(id)?;
            if dropped > 0 {
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
                format!(
                    " · {dropped} wiring{} removed (target changed)",
                    if dropped == 1 { "" } else { "s" }
                )
            } else {
                String::new()
            }
        ))
        .field("target", conn.target())
        .field("target_changed", target_changed)
        .field("capability_changed", capability_changed)
        .field("wirings_removed", dropped);
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
        let confirmation = self.confirm_action(&format!("Delete tool “{}”", conn.name))?;
        let _gate = self.config_gate.lock().unwrap();
        if self.store.connection_by_id(id)?.updated_at != conn.updated_at {
            return Err(CoreError::ApprovalConnectionChanged);
        }
        let conn = self.store.delete_connection(id)?;
        self.health.forget(id);
        let dropped = self.wirings.remove_for_connection(id)?;
        if dropped > 0 {
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
            self.confirm_action(&format!("Connect “{}” with your browser", spec.name))?;
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
            self.confirm_action(&format!("Reconnect “{}” with your browser", conn.name))?;
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
    /// and the same agent asking for the same service within a minute is
    /// coalesced. Returns whether this call surfaced a fresh request.
    pub fn agent_connect_request(&self, agent: &PairedAgent, service: &str) -> Result<bool> {
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
            let key = (agent.id, service.to_ascii_lowercase());
            if recent.contains_key(&key) {
                return Ok(false);
            }
            recent.insert(key, now);
        }
        self.audit.append(
            AuditEntry::new(
                AuditKind::ConnectRequested,
                format!("{} asked to connect: {service}", agent.name),
            )
            .agent(agent.name.clone())
            .detail("A request only — add and wire the tool in Multitool to grant it")
            .field("service", service),
        );
        self.events.connect_requested(&agent.name, service);
        Ok(true)
    }

    /* ---------------------------- wirings (UI) ----------------------------- */

    pub fn wirings(&self) -> Vec<Wiring> {
        self.wirings.wirings()
    }

    /// Wire or unwire an agent from the app. Unwiring does not chase down
    /// live transports — tickets are short-lived, and the next open is
    /// refused.
    pub fn ui_set_wiring(
        &self,
        client_id: &Uuid,
        connection_id: &Uuid,
        wired: bool,
    ) -> Result<bool> {
        let _gate = self.config_gate.lock().unwrap();
        let Some(agent) = self.pairing.get_by_id(client_id) else {
            return Ok(false);
        };
        let connection = self.store.connection_by_id(connection_id)?;
        if wired {
            let existing = self.wirings.is_wired(client_id, connection_id);
            self.wirings.wire(*client_id, &agent.name, *connection_id)?;
            if !existing {
                self.audit.append(
                    AuditEntry::new(
                        AuditKind::Wired,
                        format!("{} wired to {}", agent.name, connection.name),
                    )
                    .agent(agent.name.clone())
                    .connection(connection.name.clone()),
                );
                self.events.wirings_changed();
            }
            Ok(true)
        } else {
            let removed = self.wirings.unwire(client_id, connection_id)?;
            if removed.is_some() {
                self.audit.append(
                    AuditEntry::new(
                        AuditKind::Unwired,
                        format!("{} unwired from {}", agent.name, connection.name),
                    )
                    .agent(agent.name.clone())
                    .connection(connection.name.clone()),
                );
                self.events.wirings_changed();
            }
            Ok(removed.is_some())
        }
    }

    /// Curate which upstream MCP tools a wiring may call. `None` restores
    /// the default (all tools); `Some` is enforced by the broker on every
    /// `tools/call` and mirrored by the sidecar's tool listing.
    pub fn ui_set_wiring_tools(
        &self,
        client_id: &Uuid,
        connection_id: &Uuid,
        tools: Option<Vec<String>>,
    ) -> Result<bool> {
        let _gate = self.config_gate.lock().unwrap();
        let Some(agent) = self.pairing.get_by_id(client_id) else {
            return Ok(false);
        };
        let connection = self.store.connection_by_id(connection_id)?;
        let detail = match &tools {
            None => "all tools".to_string(),
            Some(list) => format!(
                "{} tool{} allowed",
                list.len(),
                if list.len() == 1 { "" } else { "s" }
            ),
        };
        let changed = self
            .wirings
            .set_allowed_tools(client_id, connection_id, tools)?;
        if changed {
            self.audit.append(
                AuditEntry::new(
                    AuditKind::Wired,
                    format!(
                        "Tool selection for {} → {}: {detail}",
                        agent.name, connection.name
                    ),
                )
                .agent(agent.name.clone())
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

    /// Set a wiring's attenuation mode from the app. `read-only` narrows what
    /// the agent may do; for Postgres the broker enforces it structurally on
    /// the next open (upstream opened `default_transaction_read_only=on`).
    /// Returns whether a wiring existed to change.
    pub fn ui_set_wiring_mode(
        &self,
        client_id: &Uuid,
        connection_id: &Uuid,
        mode: WiringMode,
    ) -> Result<bool> {
        let _gate = self.config_gate.lock().unwrap();
        let Some(agent) = self.pairing.get_by_id(client_id) else {
            return Ok(false);
        };
        let connection = self.store.connection_by_id(connection_id)?;
        let changed = self.wirings.mode(client_id, connection_id) != Some(mode);
        if self.wirings.set_mode(client_id, connection_id, mode)?.is_none() {
            return Ok(false);
        }
        if changed {
            self.audit.append(
                AuditEntry::new(
                    AuditKind::Wired,
                    format!(
                        "{} → {} set to {}",
                        agent.name,
                        connection.name,
                        mode.as_str()
                    ),
                )
                .agent(agent.name.clone())
                .connection(connection.name.clone())
                .field("mode", mode.as_str()),
            );
            self.events.wirings_changed();
        }
        Ok(true)
    }

    /// The very first agent to register is wired to every existing
    /// connection, so a fresh install works end-to-end without a wiring
    /// trip through the app. Later agents start unwired.
    pub(crate) fn bootstrap_first_agent_wirings(&self, agent: &PairedAgent) {
        let _gate = self.config_gate.lock().unwrap();
        let connection_ids: Vec<Uuid> = self
            .store
            .list_connections()
            .into_iter()
            .map(|c| c.id)
            .collect();
        if connection_ids.is_empty() {
            return;
        }
        match self
            .wirings
            .wire_all(agent.id, &agent.name, &connection_ids)
        {
            Ok(added) if !added.is_empty() => {
                self.audit.append(
                    AuditEntry::new(
                        AuditKind::Wired,
                        format!(
                            "First agent {} wired to all {} tool{}",
                            agent.name,
                            added.len(),
                            if added.len() == 1 { "" } else { "s" }
                        ),
                    )
                    .agent(agent.name.clone())
                    .field("wirings_added", added.len()),
                );
                self.events.wirings_changed();
            }
            Ok(_) => {}
            Err(error) => {
                tracing::warn!("could not bootstrap first-agent wirings: {error}");
            }
        }
    }

    /* ------------------------- registered agents (UI) ---------------------- */

    pub fn paired_agents(&self) -> Vec<PairedAgent> {
        self.pairing.list()
    }

    /// Disconnect invalidates the token, the agent's wirings, and every
    /// issued data-plane capability immediately.
    pub fn ui_revoke_agent(&self, client_id: &Uuid) -> Result<bool> {
        let _gate = self.config_gate.lock().unwrap();
        let client = self.pairing.get_by_id(client_id);
        let Some(client) = client else {
            return Ok(false);
        };
        let name = client.name.clone();
        let removed = self.pairing.revoke(client_id)?;
        if removed {
            let dropped = self.wirings.remove_for_client(client_id)?;
            if dropped > 0 {
                self.events.wirings_changed();
            }
            let sessions_closed = self.data_plane.close_agent(&name);
            self.audit.append(
                AuditEntry::new(
                    AuditKind::TokenRevoked,
                    format!("Agent disconnected: {name}"),
                )
                .agent(name)
                .field("sessions_closed", sessions_closed)
                .field("wirings_removed", dropped),
            );
            self.events.agents_changed();
        }
        Ok(removed)
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
            self.confirm_action("Disable OS authentication requirement for reading secrets")?;
        }
        self.store.set_reauth_on_read(on)?;
        *self.copy_authorization_until.lock().unwrap() = None;
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
