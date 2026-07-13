//! The broker facade: one struct owning the store, policy engine, pairing
//! registry, approvals queue and audit log. The daemon (agent-facing) and
//! the shell (UI-facing Tauri commands, tests, dev harness) both drive it.

use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use uuid::Uuid;

use crate::approvals::{ApprovalKind, ApprovalRequest, Approvals, ConnectionSummary};
use crate::audit::{AuditEntry, AuditKind, AuditLog};
use crate::config::BrokerConfig;
use crate::error::CoreError;
use crate::events::BrokerEvents;
use crate::grants::{AccessGrantSummary, AccessGrants, GrantRemoval};
use crate::pairing::PairingRegistry;
use crate::paths::{BrokerInstanceLock, Paths};
use crate::policy::{NaivePolicyEngine, PolicyEngine as _};
use crate::ratelimit::{KeyedLimiter, PairingLimiter, WindowLimiter};
use crate::sessions::{DataPlane, SessionInfo};
use crate::store::{ConnectionSpec, Store};
use crate::types::{
    ConfirmationMethod, Connection, ConnectionKind, DecisionContext, PairedAgent, PermissionScope,
    Rule, SecretMeta, SecretValue, Settings,
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

/// What the user clicked in the approval window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UiDecision {
    Deny,
    AllowOnce,
    /// Create a fixed-lifetime, in-memory access session, then allow.
    AllowSession,
    /// Save the `(agent, connection)` standing rule, then allow.
    AlwaysAllow,
}

pub struct Broker {
    pub config: BrokerConfig,
    pub paths: Paths,
    pub store: Arc<Store>,
    pub policy: Arc<NaivePolicyEngine>,
    pub grants: Arc<AccessGrants>,
    /// Serializes the short "match-or-park" and "claim-and-create" sections
    /// so a request cannot become a stale prompt while a session grant is
    /// being installed.
    pub(crate) access_gate: Mutex<()>,
    /// A successful OS authentication for a user-initiated clipboard copy may
    /// authorize more clipboard copies briefly. This cache is deliberately
    /// separate from agent execution authorizations and never leaves memory.
    copy_authorization_until: Mutex<Option<Instant>>,
    copy_authorization_gate: tokio::sync::Mutex<()>,
    runtime: tokio::runtime::Handle,
    pub pairing: Arc<PairingRegistry>,
    pub approvals: Approvals,
    pub audit: Arc<AuditLog>,
    pub events: Arc<dyn BrokerEvents>,
    /// Tickets + live WS/PG sessions.
    pub data_plane: DataPlane,
    /// The WS bridge's ephemeral loopback port, set when the daemon starts;
    /// surfaced only in open responses.
    pub(crate) ws_bridge_port: std::sync::OnceLock<u16>,
    /// The PG proxy's ephemeral loopback port, set when the daemon starts;
    /// surfaced only in open responses' DSNs.
    pub(crate) pg_proxy_port: std::sync::OnceLock<u16>,
    pub(crate) http_client: reqwest::Client,
    pub(crate) token_limiter: KeyedLimiter,
    pub(crate) discovery_limiter: WindowLimiter,
    pub(crate) pairing_limiter: PairingLimiter,
    /// Acquired before any persistent state is opened and declared last so it
    /// remains held while every state-owning field is dropped.
    _instance_lock: BrokerInstanceLock,
}

impl Broker {
    /// Must be constructed inside a tokio runtime (approvals spawn tasks;
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
        let runtime = tokio::runtime::Handle::current();
        {
            let events = events.clone();
            audit.subscribe(move |entry| events.audit_appended(entry));
        }
        // One integrity key seals every state file: index.json,
        // rules.json, and agents.json refuse to load if tampered with.
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
        let policy = Arc::new(NaivePolicyEngine::open_with_clients(
            paths.rules_file(),
            integrity,
            &pairing.list(),
        )?);
        let grants = Arc::new(AccessGrants::new());
        let approvals = Approvals::new(
            config.approval_timeout,
            config.outcome_retention,
            config.outcome_retention_max_entries,
            config.outcome_retention_max_bytes,
            audit.clone(),
            events.clone(),
        );
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
        Ok(Arc::new(Self {
            data_plane,
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
            pairing_limiter: PairingLimiter::new(
                config.pairing_max_attempts,
                config.pairing_window,
                config.pairing_deny_cooldown,
            ),
            config,
            paths,
            store,
            policy,
            grants,
            access_gate: Mutex::new(()),
            copy_authorization_until: Mutex::new(None),
            copy_authorization_gate: tokio::sync::Mutex::new(()),
            runtime,
            pairing,
            approvals,
            audit,
            events,
            http_client,
            _instance_lock: instance_lock,
        }))
    }

    pub(crate) fn connection_summary(&self, conn: &Connection) -> ConnectionSummary {
        ConnectionSummary {
            id: conn.id,
            name: conn.name.clone(),
            kind: conn.kind(),
            target: conn.target(),
            connection_updated_at: conn.updated_at,
        }
    }

    /// Reload the connection named by a prompt and require that its exact
    /// revision still matches what the user reviewed.
    fn approval_connection(&self, summary: &ConnectionSummary) -> Result<Connection> {
        let conn = self
            .store
            .connection_by_id(&summary.id)
            .map_err(|_| CoreError::ApprovalConnectionChanged)?;
        if conn.updated_at != summary.connection_updated_at
            || conn.kind() != summary.kind
            || conn.target() != summary.target
        {
            return Err(CoreError::ApprovalConnectionChanged);
        }
        Ok(conn)
    }

    /// The connections a pairing under `agent` would inherit promptless
    /// access to, the loud disclosure list.
    pub fn inherited_for(&self, client_id: &Uuid) -> Vec<ConnectionSummary> {
        self.policy
            .rules_for_client(client_id)
            .into_iter()
            .filter_map(|rule| self.store.connection_by_id(&rule.connection_id).ok())
            .map(|conn| self.connection_summary(&conn))
            .collect()
    }

    /* --------------------------- approvals (UI) --------------------------- */

    pub fn approvals_queue(&self) -> Vec<ApprovalRequest> {
        self.approvals.queue()
    }

    /// Apply the user's decision to a queued request. Auditing and rule
    /// recording happen here, and so does the decision confirmation gate: the
    /// core demands the native confirmation through
    /// [`BrokerEvents::confirm_decision`] *before* the decision takes
    /// effect, so no shell can apply a gated decision without passing
    /// through it. `ctx` attributes the decision in the audit log.
    pub fn decide(
        &self,
        id: &Uuid,
        decision: UiDecision,
        ctx: &DecisionContext,
    ) -> Result<Option<ApprovalRequest>> {
        self.decide_with_pairing_options(id, decision, false, ctx)
    }

    /// Apply the user's decision, optionally removing inherited standing
    /// rules before an approved pairing can mint and return its token.
    pub fn decide_with_pairing_options(
        &self,
        id: &Uuid,
        decision: UiDecision,
        revoke_inherited_rules: bool,
        ctx: &DecisionContext,
    ) -> Result<Option<ApprovalRequest>> {
        let Some(request) = self.approvals.get(id) else {
            return Ok(None);
        };
        let confirmation = self.confirm_decision(&request, decision)?;
        if revoke_inherited_rules
            && request.kind == ApprovalKind::Pair
            && matches!(decision, UiDecision::AllowOnce | UiDecision::AlwaysAllow)
        {
            if let Some(client_id) = request.client_id {
                self.remove_rules_for_client_before_pairing(
                    &client_id,
                    &request.agent,
                    Some(ctx),
                    confirmation,
                )?;
            }
        }
        self.apply_decision(id, decision, ctx, confirmation)
    }

    /// Whether — and how — the decision was confirmed. Deny is always one
    /// click; *Allow once* on a pairing or mutating request, every access
    /// session, and *Always allow…* in every case complete only after the
    /// shell's native confirmation. Fails closed when the shell refuses.
    fn confirm_decision(
        &self,
        request: &ApprovalRequest,
        decision: UiDecision,
    ) -> Result<Option<ConfirmationMethod>> {
        let required = match decision {
            UiDecision::Deny => false,
            UiDecision::AllowOnce => request.is_high_consequence(),
            UiDecision::AllowSession => true,
            UiDecision::AlwaysAllow => true,
        };
        if !required {
            return Ok(None);
        }
        match self.events.confirm_decision(request, decision) {
            Some(method) => Ok(Some(method)),
            None => Err(CoreError::NotConfirmed),
        }
    }

    /// The decision body, run after the (single) confirmation. The
    /// AlwaysAllow → AllowOnce recursion stays inside this method so a
    /// decision is never confirmed twice.
    fn apply_decision(
        &self,
        id: &Uuid,
        decision: UiDecision,
        ctx: &DecisionContext,
        confirmation: Option<ConfirmationMethod>,
    ) -> Result<Option<ApprovalRequest>> {
        let attributed = |mut entry: AuditEntry| {
            entry = entry.context(ctx);
            if let Some(method) = confirmation {
                entry = entry.confirmation(method);
            }
            entry
        };
        match decision {
            UiDecision::Deny => {
                let request = self
                    .approvals
                    .deny(id, crate::wire::ErrorReason::DeniedByUser);
                if let Some(request) = &request {
                    if request.kind == ApprovalKind::Pair {
                        // Pairing-prompt spam brake.
                        self.pairing_limiter.on_user_denied();
                        self.audit.append(attributed(
                            AuditEntry::new(
                                AuditKind::PairDenied,
                                format!("Connection denied: {}", request.agent),
                            )
                            .agent(request.agent.clone())
                            .outcome("denied_by_user"),
                        ));
                    } else {
                        self.audit.append(attributed(
                            AuditEntry::new(
                                AuditKind::Denied,
                                format!("Denied: {}", request.agent),
                            )
                            .agent(request.agent.clone())
                            .connection(
                                request
                                    .connection
                                    .as_ref()
                                    .map(|c| c.name.clone())
                                    .unwrap_or_default(),
                            )
                            .detail(request.action.clone())
                            .outcome("denied_by_user")
                            .field(
                                "approval_state",
                                crate::wire::ApprovalState::Denied.as_str(),
                            ),
                        ));
                    }
                }
                Ok(request)
            }
            UiDecision::AllowOnce => {
                let request = self.approvals.approve(id, confirmation.is_some(), None);
                if let Some(request) = &request {
                    if request.kind != ApprovalKind::Pair {
                        self.audit.append(attributed(
                            AuditEntry::new(
                                AuditKind::AllowedOnce,
                                format!("Allowed this request: {}", request.agent),
                            )
                            .agent(request.agent.clone())
                            .connection(
                                request
                                    .connection
                                    .as_ref()
                                    .map(|c| c.name.clone())
                                    .unwrap_or_default(),
                            )
                            .detail(request.action.clone())
                            .outcome("allowed_once")
                            .field(
                                "approval_state",
                                crate::wire::ApprovalState::Executing.as_str(),
                            ),
                        ));
                    }
                }
                Ok(request)
            }
            UiDecision::AlwaysAllow => {
                // Save the standing rule first, then allow this request.
                let _access = self.access_gate.lock().unwrap();
                let Some(request) = self.approvals.get(id) else {
                    return Ok(None);
                };
                if request.kind == ApprovalKind::Pair {
                    // "Always allow" does not apply to pairing.
                    return self.apply_decision(id, UiDecision::AllowOnce, ctx, confirmation);
                }
                if request.ssh.is_some() {
                    // Trusting a host key must never create a standing rule;
                    // the only allow shape is the one-time pin.
                    return self.apply_decision(id, UiDecision::AllowOnce, ctx, confirmation);
                }
                if let Some(summary) = &request.connection {
                    let conn = self.approval_connection(summary)?;
                    let client_id = request.client_id.ok_or(CoreError::NotConfirmed)?;
                    let scope = match request.http.as_ref() {
                        Some(http) if !http.mutating => PermissionScope::Read,
                        _ => PermissionScope::Full,
                    };
                    let rule =
                        self.policy
                            .record_rule(client_id, &request.agent, conn.id, scope)?;
                    self.audit.append(attributed(
                        AuditEntry::new(
                            AuditKind::RuleSaved,
                            format!("{} can use {} without asking", request.agent, conn.name),
                        )
                        .agent(request.agent.clone())
                        .connection(conn.name.clone())
                        .rule(rule.id)
                        .field("scope", scope.as_str()),
                    ));
                    self.events.rules_changed();
                }
                self.apply_decision(id, UiDecision::AllowOnce, ctx, confirmation)
            }
            UiDecision::AllowSession => {
                let _access = self.access_gate.lock().unwrap();
                let Some(request) = self.approvals.get(id) else {
                    return Ok(None);
                };
                if request.kind == ApprovalKind::Pair {
                    return self.apply_decision(id, UiDecision::AllowOnce, ctx, confirmation);
                }
                if request.ssh.is_some() {
                    // A host-key trust decision must not start an access
                    // session; coerce to the one-time pin.
                    return self.apply_decision(id, UiDecision::AllowOnce, ctx, confirmation);
                }
                let token_hash = request
                    .agent_token_hash
                    .as_deref()
                    .ok_or(CoreError::NotConfirmed)?;
                let current_agent = self
                    .pairing
                    .get(&request.agent)
                    .filter(|agent| agent.token_hash == token_hash)
                    .ok_or(CoreError::NotConfirmed)?;
                let summary = request
                    .connection
                    .as_ref()
                    .ok_or(CoreError::ApprovalConnectionChanged)?;
                let conn = self.approval_connection(summary)?;
                let scope = match request.http.as_ref() {
                    Some(http) if !http.mutating => PermissionScope::Read,
                    _ => PermissionScope::Full,
                };
                let Some(claim) = self.approvals.claim_session(id, |queued| {
                    queued.kind != ApprovalKind::Pair
                        // A queued host-key trust prompt is never absorbed by
                        // an access session; the user must see the fingerprint.
                        && queued.ssh.is_none()
                        && queued.agent_token_hash.as_deref()
                            == Some(current_agent.token_hash.as_str())
                        && queued.connection.as_ref().is_some_and(|queued_connection| {
                            queued_connection.id == summary.id
                                && queued_connection.kind == summary.kind
                                && queued_connection.target == summary.target
                                && queued_connection.connection_updated_at
                                    == summary.connection_updated_at
                        })
                        && scope.allows(match queued.http.as_ref() {
                            Some(http) if !http.mutating => PermissionScope::Read,
                            _ => PermissionScope::Full,
                        })
                }) else {
                    return Ok(None);
                };
                let created = self.grants.create(
                    &current_agent.name,
                    &current_agent.token_hash,
                    &conn,
                    scope,
                    self.config.access_grant_ttl,
                );
                let grant_deadline = created.deadline;
                for replaced in &created.replaced {
                    self.data_plane.close_grant(replaced);
                }
                let grant = created.grant;
                let (approved, absorbed) = self
                    .approvals
                    .execute_session(claim, grant.authorization.clone());
                self.audit.append(attributed(
                    AuditEntry::new(
                        AuditKind::GrantStarted,
                        format!(
                            "Temporary access started: {} can {} {}",
                            request.agent,
                            if scope == PermissionScope::Read {
                                "fetch data from"
                            } else {
                                "use"
                            },
                            conn.name
                        ),
                    )
                    .agent(request.agent.clone())
                    .connection(conn.name.clone())
                    .outcome("access_session_started")
                    .field("grant_id", grant.summary.id.to_string())
                    .field("scope", format!("{:?}", scope).to_lowercase())
                    .field("expires_at", grant.summary.expires_at.to_rfc3339()),
                ));
                self.schedule_grant_expiry(
                    grant.summary.clone(),
                    grant_deadline,
                    conn.name.clone(),
                );
                for request in absorbed {
                    self.audit.append(attributed(
                        AuditEntry::new(
                            AuditKind::AutoAllowed,
                            format!("Temporary access used: {} → {}", request.agent, conn.name),
                        )
                        .agent(request.agent)
                        .connection(conn.name.clone())
                        .detail(request.action)
                        .outcome("access_session")
                        .field("grant_id", grant.summary.id.to_string())
                        .field("scope", format!("{:?}", scope).to_lowercase())
                        .field(
                            "approval_state",
                            crate::wire::ApprovalState::Executing.as_str(),
                        ),
                    ));
                }
                self.events.rules_changed();
                Ok(Some(approved))
            }
        }
    }

    /// Demand the shell's native confirmation for a high-consequence
    /// configuration action. Fails closed when the shell refuses or
    /// does not implement the gate.
    fn confirm_action(&self, description: &str) -> Result<ConfirmationMethod> {
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
        let _access = self.access_gate.lock().unwrap();
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
        let confirmation = self.confirm_action(&format!("Add service “{}”", spec.name))?;
        let conn = self.store.add_connection(spec)?;
        self.audit.append(
            AuditEntry::new(
                AuditKind::ConnectionAdded,
                format!("Service added: {}", conn.name),
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
        let confirmation = self.confirm_action(&format!("Add service “{}”", spec.name))?;
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
                format!("Service added: {}", conn.name),
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
    /// authentication do. When the pinned target changes, its standing rules
    /// are dropped, a rule granted for one destination must not silently cover
    /// another.
    pub fn ui_update_connection(&self, id: &Uuid, spec: ConnectionSpec) -> Result<Connection> {
        let old = self.store.connection_by_id(id)?;
        let explicit_secrets_changed =
            old.kind() != ConnectionKind::Api && old.secrets != spec.secrets;
        let capability_changed = old.config != spec.config || explicit_secrets_changed;
        let confirmation = if capability_changed {
            Some(self.confirm_action(&format!(
                "Change security settings for service “{}”",
                spec.name
            ))?)
        } else {
            None
        };
        let _access = self.access_gate.lock().unwrap();
        if self.store.connection_by_id(id)?.updated_at != old.updated_at {
            return Err(CoreError::ApprovalConnectionChanged);
        }
        let (conn, target_changed) = if capability_changed {
            self.store.update_connection(id, spec)?
        } else {
            (self.store.rename_connection(id, spec.name)?, false)
        };
        let removed_grants = self.grants.remove_for_connection(id);
        self.close_grants(&removed_grants.revoked);
        self.record_expired_grants(removed_grants.expired, Some(old.name.clone()));
        let mut dropped = 0;
        if target_changed {
            dropped = self.policy.remove_rules_for_connection(id)?;
            if dropped > 0 {
                self.events.rules_changed();
            }
        }
        let mut entry = AuditEntry::new(
            AuditKind::ConnectionUpdated,
            format!(
                "Service updated: {}",
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
                    " · {dropped} auto-allow rule{} removed (target changed)",
                    if dropped == 1 { "" } else { "s" }
                )
            } else {
                String::new()
            }
        ))
        .field("target", conn.target())
        .field("target_changed", target_changed)
        .field("capability_changed", capability_changed)
        .field("rules_removed", dropped);
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

    /// Delete a connection; rules die with it.
    pub fn ui_delete_connection(&self, id: &Uuid) -> Result<Connection> {
        let conn = self.store.connection_by_id(id)?;
        let confirmation = self.confirm_action(&format!("Delete service “{}”", conn.name))?;
        let _access = self.access_gate.lock().unwrap();
        if self.store.connection_by_id(id)?.updated_at != conn.updated_at {
            return Err(CoreError::ApprovalConnectionChanged);
        }
        let conn = self.store.delete_connection(id)?;
        let removed_grants = self.grants.remove_for_connection(id);
        self.close_grants(&removed_grants.revoked);
        self.record_expired_grants(removed_grants.expired, Some(conn.name.clone()));
        let dropped = self.policy.remove_rules_for_connection(id)?;
        if dropped > 0 {
            self.events.rules_changed();
        }
        self.audit.append(
            AuditEntry::new(
                AuditKind::ConnectionDeleted,
                format!("Service deleted: {}", conn.name),
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
        let connection = self.store.connection_by_id(id)?;
        let started = Instant::now();
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
        self.audit.append(
            AuditEntry::new(
                AuditKind::ConnectionTested,
                format!(
                    "Service test {}: {}",
                    if ok { "passed" } else { "failed" },
                    connection.name
                ),
            )
            .connection(connection.name.clone())
            .outcome(if ok { "ok" } else { "failed" })
            .detail(detail.clone())
            .duration_ms(started.elapsed().as_millis() as u64),
        );
        Ok(ConnectionTestReport { ok, detail })
    }

    /* ---------------------------- rules (UI) ------------------------------ */

    pub fn rules(&self) -> Vec<Rule> {
        self.policy.rules()
    }

    pub fn grants_for_connection(&self, connection: &Connection) -> Vec<AccessGrantSummary> {
        self.grants.for_connection(connection)
    }

    pub fn grant_count_for_agent(&self, agent: &str) -> usize {
        self.grants.count_for_agent(agent)
    }

    pub fn ui_remove_grant(&self, id: &Uuid) -> Result<bool> {
        let Some(removal) = self.grants.remove(id) else {
            return Ok(false);
        };
        let grant = match removal {
            GrantRemoval::Expired(grant) => {
                self.record_expired_grants(vec![grant], None);
                return Ok(true);
            }
            GrantRemoval::Revoked(grant) => grant,
        };
        self.data_plane.close_grant(id);
        let connection = self
            .store
            .connection_by_id(&grant.connection_id)
            .map(|connection| connection.name)
            .unwrap_or_else(|_| "(deleted connection)".into());
        self.audit.append(
            AuditEntry::new(
                AuditKind::GrantRevoked,
                format!("Temporary access ended: {} → {connection}", grant.agent),
            )
            .agent(grant.agent)
            .connection(connection)
            .field("grant_id", id.to_string())
            .field("scope", format!("{:?}", grant.scope).to_lowercase()),
        );
        self.events.rules_changed();
        Ok(true)
    }

    /// Revoke a permission without requiring the UI to know whether it is
    /// an expiring in-memory authorization or a standing one.
    pub fn ui_remove_permission(&self, id: &Uuid) -> Result<bool> {
        if self.ui_remove_grant(id)? {
            return Ok(true);
        }
        self.ui_remove_rule(id)
    }

    fn schedule_grant_expiry(
        &self,
        grant: AccessGrantSummary,
        deadline: std::time::Instant,
        connection_name: String,
    ) {
        let grants = self.grants.clone();
        let data_plane = self.data_plane.clone();
        let audit = self.audit.clone();
        let events = self.events.clone();
        self.runtime.spawn(async move {
            tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await;
            let Some(expired) = grants.expire(&grant.id) else {
                return;
            };
            record_grant_expiry(&data_plane, &audit, &*events, expired, connection_name);
        });
    }

    fn record_expired_grants(
        &self,
        grants: Vec<AccessGrantSummary>,
        known_connection_name: Option<String>,
    ) {
        for grant in grants {
            let connection_name = known_connection_name.clone().unwrap_or_else(|| {
                self.store
                    .connection_by_id(&grant.connection_id)
                    .map(|connection| connection.name)
                    .unwrap_or_else(|_| "(deleted connection)".into())
            });
            record_grant_expiry(
                &self.data_plane,
                &self.audit,
                &*self.events,
                grant,
                connection_name,
            );
        }
    }

    pub(crate) fn revoke_access_grants_for_agent(&self, agent: &str, reason: &str) {
        let removed = self.grants.remove_for_agent(agent);
        self.record_expired_grants(removed.expired, None);
        if removed.revoked.is_empty() {
            return;
        }
        self.close_grants(&removed.revoked);
        self.audit.append(
            AuditEntry::new(
                AuditKind::GrantRevoked,
                format!("Temporary access ended: {agent}"),
            )
            .agent(agent.to_string())
            .detail(reason)
            .field("grants_removed", removed.revoked.len()),
        );
        self.events.rules_changed();
    }

    fn close_grants(&self, ids: &[Uuid]) {
        for id in ids {
            self.data_plane.close_grant(id);
        }
        if !ids.is_empty() {
            self.events.rules_changed();
        }
    }

    pub fn ui_remove_rule(&self, id: &Uuid) -> Result<bool> {
        let removed = self.policy.remove_rule(id)?;
        if let Some(rule) = removed {
            let conn_name = self
                .store
                .connection_by_id(&rule.connection_id)
                .map(|c| c.name)
                .unwrap_or_else(|_| "(deleted connection)".into());
            self.audit.append(
                AuditEntry::new(
                    AuditKind::RuleRemoved,
                    format!("Approval required again: {} → {}", rule.agent, conn_name),
                )
                .agent(rule.agent.clone())
                .rule(rule.id),
            );
            self.events.rules_changed();
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn ui_remove_rules_for_agent(&self, agent: &str) -> Result<usize> {
        let Some(client) = self.pairing.get(agent) else {
            return Ok(0);
        };
        self.remove_rules_for_client_before_pairing(&client.id, agent, None, None)
    }

    pub(crate) fn remove_rules_for_client_before_pairing(
        &self,
        client_id: &Uuid,
        agent: &str,
        ctx: Option<&DecisionContext>,
        confirmation: Option<ConfirmationMethod>,
    ) -> Result<usize> {
        let removed = self.policy.remove_rules_for_client(client_id)?;
        if removed > 0 {
            let mut entry = AuditEntry::new(
                AuditKind::RuleRemoved,
                format!("Approval required again: {agent}"),
            )
            .agent(agent.to_string())
            .detail(format!(
                "{removed} standing rule{} removed before pairing",
                if removed == 1 { "" } else { "s" }
            ))
            .field("rules_removed", removed);
            if let Some(ctx) = ctx {
                entry = entry.context(ctx);
            }
            if let Some(confirmation) = confirmation {
                entry = entry.confirmation(confirmation);
            }
            self.audit.append(entry);
            self.events.rules_changed();
        }
        Ok(removed)
    }

    /* ------------------------- paired agents (UI) ------------------------- */

    pub fn paired_agents(&self) -> Vec<PairedAgent> {
        self.pairing.list()
    }

    /// Disconnect invalidates the token, standing permissions, and every
    /// issued data-plane capability immediately.
    pub fn ui_revoke_agent(&self, client_id: &Uuid) -> Result<bool> {
        let client = self.pairing.get_by_id(client_id);
        let Some(client) = client else {
            return Ok(false);
        };
        let name = client.name.clone();
        let removed = self.pairing.revoke(client_id)?;
        if removed {
            self.remove_rules_for_client_before_pairing(&client.id, &name, None, None)?;
            self.revoke_access_grants_for_agent(&name, "agent revoked");
            let sessions_closed = self.data_plane.close_agent(&name);
            self.audit.append(
                AuditEntry::new(
                    AuditKind::TokenRevoked,
                    format!("Agent disconnected: {name}"),
                )
                .agent(name)
                .field("sessions_closed", sessions_closed),
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

    pub fn ui_set_menu_bar_hides_dock(&self, on: bool) -> Result<()> {
        self.store.set_menu_bar_hides_dock(on)
    }

    pub fn ui_set_service_walkthrough_visible(&self, on: bool) -> Result<()> {
        self.store.set_service_walkthrough_visible(on)
    }

    pub fn ui_set_agent_walkthrough_visible(&self, on: bool) -> Result<()> {
        self.store.set_agent_walkthrough_visible(on)
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

fn record_grant_expiry(
    data_plane: &DataPlane,
    audit: &AuditLog,
    events: &dyn BrokerEvents,
    expired: AccessGrantSummary,
    connection_name: String,
) {
    let transports_closed = data_plane.close_grant(&expired.id);
    audit.append(
        AuditEntry::new(
            AuditKind::GrantExpired,
            format!(
                "Temporary access expired: {} → {connection_name}",
                expired.agent
            ),
        )
        .agent(expired.agent)
        .connection(connection_name)
        .outcome("access_session_expired")
        .field("reason", "expired")
        .field("grant_id", expired.id.to_string())
        .field("scope", expired.scope.as_str())
        .field("created_at", expired.created_at.to_rfc3339())
        .field("expires_at", expired.expires_at.to_rfc3339())
        .field("transports_closed", transports_closed),
    );
    events.rules_changed();
}
