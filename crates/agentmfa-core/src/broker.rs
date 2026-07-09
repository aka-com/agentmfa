//! The broker facade: one struct owning the store, policy engine, pairing
//! registry, approvals queue and audit log. The daemon (agent-facing) and
//! the shell (UI-facing Tauri commands, tests, dev harness) both drive it.

use std::sync::Arc;

use uuid::Uuid;

use crate::approvals::{ApprovalKind, ApprovalRequest, Approvals, ConnectionSummary};
use crate::audit::{AuditEntry, AuditKind, AuditLog};
use crate::config::BrokerConfig;
use crate::error::CoreError;
use crate::events::BrokerEvents;
use crate::grants::{AccessGrantSummary, AccessGrants, GrantScope};
use crate::pairing::PairingRegistry;
use crate::paths::Paths;
use crate::policy::{NaivePolicyEngine, PolicyEngine as _};
use crate::ratelimit::{KeyedLimiter, PairingLimiter, WindowLimiter};
use crate::sessions::{DataPlane, SessionInfo};
use crate::store::{ConnectionSpec, Store};
use crate::types::{
    ConfirmationMethod, Connection, ConnectionKind, DecisionContext, PairedAgent, Rule, SecretMeta,
    SecretValue, Settings,
};
use crate::Result;

/// What the user clicked in the approval window (§6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UiDecision {
    Deny,
    AllowOnce,
    /// Create a fixed-lifetime, in-memory access session, then allow.
    AllowSession,
    /// Save the `(agent, connection)` standing rule, then allow (§7).
    AlwaysAllow,
}

pub struct Broker {
    pub config: BrokerConfig,
    pub paths: Paths,
    pub store: Arc<Store>,
    pub policy: Arc<NaivePolicyEngine>,
    pub grants: Arc<AccessGrants>,
    pub pairing: Arc<PairingRegistry>,
    pub approvals: Approvals,
    pub audit: Arc<AuditLog>,
    pub events: Arc<dyn BrokerEvents>,
    /// Tickets + live WS/PG sessions (§4.2/§4.3).
    pub data_plane: DataPlane,
    /// The WS bridge's ephemeral loopback port, set when the daemon starts;
    /// surfaced only in open responses (§8).
    pub(crate) ws_bridge_port: std::sync::OnceLock<u16>,
    /// The PG proxy's ephemeral loopback port, set when the daemon starts;
    /// surfaced only in open responses' DSNs (§4.3/§8).
    pub(crate) pg_proxy_port: std::sync::OnceLock<u16>,
    pub(crate) http_client: reqwest::Client,
    pub(crate) token_limiter: KeyedLimiter,
    pub(crate) discovery_limiter: WindowLimiter,
    pub(crate) pairing_limiter: PairingLimiter,
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
        let audit = Arc::new(AuditLog::open(paths.audit_file())?);
        {
            let events = events.clone();
            audit.subscribe(move |entry| events.audit_appended(entry));
        }
        // One integrity key seals every state file (§13.1): index.json,
        // rules.json, and agents.json refuse to load if tampered with.
        let integrity = Arc::new(crate::integrity::StateIntegrity::open(&*vault).await?);
        let store = Arc::new(Store::open_with_events(
            paths.clone(),
            vault,
            events.clone(),
            integrity.clone(),
        )?);
        let policy = Arc::new(NaivePolicyEngine::open(
            paths.rules_file(),
            integrity.clone(),
        )?);
        let grants = Arc::new(AccessGrants::new());
        let pairing = Arc::new(PairingRegistry::open(
            paths.agents_file(),
            config.token_ttl,
            integrity,
        )?);
        let approvals = Approvals::new(
            config.approval_timeout,
            config.outcome_retention,
            audit.clone(),
            events.clone(),
        );
        let http_client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none()) // hand-rolled loop (§4.1)
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
            pairing,
            approvals,
            audit,
            events,
            http_client,
        }))
    }

    pub(crate) fn connection_summary(&self, conn: &Connection) -> ConnectionSummary {
        ConnectionSummary {
            id: conn.id,
            name: conn.name.clone(),
            kind: conn.kind(),
            target: conn.target(),
            multi_connect: conn.multi_connect,
        }
    }

    /// The connections a pairing under `agent` would inherit promptless
    /// access to, the loud disclosure list (§6).
    pub fn inherited_for(&self, agent: &str) -> Vec<ConnectionSummary> {
        self.policy
            .rules_for_agent(agent)
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
    /// through it (§8). `ctx` attributes the decision in the audit log.
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
            self.remove_rules_for_agent_before_pairing(&request.agent, Some(ctx), confirmation)?;
        }
        self.apply_decision(id, decision, ctx, confirmation)
    }

    /// Whether — and how — the decision was confirmed. Deny is always one
    /// click (§6); *Allow once* on a pairing or mutating request, every access
    /// session, and *Always allow…* in every case complete only after the
    /// shell's native confirmation. Fails closed when the shell refuses (§8).
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
                        // Pairing-prompt spam brake (§8).
                        self.pairing_limiter.on_user_denied();
                        self.audit.append(attributed(
                            AuditEntry::new(
                                AuditKind::PairDenied,
                                format!("Pairing denied: {}", request.agent),
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
                                format!("Allowed once: {}", request.agent),
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
                let Some(request) = self.approvals.get(id) else {
                    return Ok(None);
                };
                if request.kind == ApprovalKind::Pair {
                    // "Always allow" does not apply to pairing.
                    return self.apply_decision(id, UiDecision::AllowOnce, ctx, confirmation);
                }
                if let Some(summary) = &request.connection {
                    let conn = self.store.connection_by_id(&summary.id)?;
                    if conn.kind() != summary.kind
                        || conn.target() != summary.target
                        || conn.multi_connect != summary.multi_connect
                    {
                        return Err(CoreError::ApprovalConnectionChanged);
                    }
                    let rule = self.policy.record_rule(&request.agent, conn.id)?;
                    self.audit.append(attributed(
                        AuditEntry::new(
                            AuditKind::RuleSaved,
                            format!("Auto-allow saved: {} → {}", request.agent, conn.name),
                        )
                        .agent(request.agent.clone())
                        .connection(conn.name.clone())
                        .rule(rule.id),
                    ));
                    self.events.rules_changed();
                }
                self.apply_decision(id, UiDecision::AllowOnce, ctx, confirmation)
            }
            UiDecision::AllowSession => {
                let Some(request) = self.approvals.get(id) else {
                    return Ok(None);
                };
                if request.kind == ApprovalKind::Pair {
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
                let conn = self.store.connection_by_id(&summary.id)?;
                if conn.kind() != summary.kind
                    || conn.target() != summary.target
                    || conn.multi_connect != summary.multi_connect
                {
                    return Err(CoreError::ApprovalConnectionChanged);
                }
                let scope = match request.http.as_ref() {
                    Some(http) if !http.mutating => GrantScope::Read,
                    _ => GrantScope::Full,
                };
                let created = self.grants.create(
                    &current_agent.name,
                    &current_agent.token_hash,
                    &conn,
                    scope,
                    self.config.access_grant_ttl,
                );
                for replaced in &created.replaced {
                    self.data_plane.close_grant(replaced);
                }
                let grant = created.grant;
                let approved = self
                    .approvals
                    .approve(id, true, Some(grant.authorization.clone()));
                if approved.is_none() {
                    self.grants.remove(&grant.summary.id);
                    self.data_plane.close_grant(&grant.summary.id);
                    return Ok(None);
                }
                self.audit.append(attributed(
                    AuditEntry::new(
                        AuditKind::GrantStarted,
                        format!(
                            "{} started: {} → {}",
                            scope.label(),
                            request.agent,
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
                self.events.rules_changed();
                Ok(approved)
            }
        }
    }

    /// Demand the shell's native confirmation for a high-consequence
    /// configuration action (§8). Fails closed when the shell refuses or
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
    /// keeps the current one (§9).
    pub fn ui_edit_secret(
        &self,
        id: &Uuid,
        new_name: Option<&str>,
        new_value: Option<SecretValue>,
    ) -> Result<SecretMeta> {
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

    /// Audited core-side reveal: only the short prefix ever leaves (§2).
    pub async fn ui_reveal_secret_prefix(&self, id: &Uuid) -> Result<String> {
        let meta = self.store.secret_by_id(id)?;
        let prefix = self.store.reveal_secret_prefix(id).await?;
        self.audit.append(AuditEntry::new(
            AuditKind::SecretRevealed,
            format!("Secret prefix revealed: {}", meta.name),
        ));
        Ok(prefix)
    }

    /// Audit trail for the core-side clipboard copy (the shell owns the
    /// actual pasteboard write + hygiene, §9).
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
    /// completable without the native confirmation the core demands (§8).
    pub fn ui_add_connection(&self, spec: ConnectionSpec) -> Result<Connection> {
        let confirmation = self.confirm_action(&format!("Add connection “{}”", spec.name))?;
        let conn = self.store.add_connection(spec)?;
        self.audit.append(
            AuditEntry::new(
                AuditKind::ConnectionAdded,
                format!("Connection added: {}", conn.name),
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
    /// session scope do. When the pinned target changes, its standing rules
    /// are dropped, a rule granted for one destination must not silently cover
    /// another (§9).
    pub fn ui_update_connection(&self, id: &Uuid, spec: ConnectionSpec) -> Result<Connection> {
        let old = self.store.connection_by_id(id)?;
        let effective_multi_connect =
            spec.config.kind() != ConnectionKind::Api && spec.multi_connect;
        let explicit_secrets_changed =
            old.kind() != ConnectionKind::Api && old.secrets != spec.secrets;
        let capability_changed = old.config != spec.config
            || explicit_secrets_changed
            || old.multi_connect != effective_multi_connect;
        let (confirmation, conn, target_changed) = if capability_changed {
            let confirmation = self.confirm_action(&format!(
                "Change security settings for connection “{}”",
                spec.name
            ))?;
            let (conn, target_changed) = self.store.update_connection(id, spec)?;
            (Some(confirmation), conn, target_changed)
        } else {
            let conn = self.store.rename_connection(id, spec.name)?;
            (None, conn, false)
        };
        let revoked_grants = self.grants.remove_for_connection(id);
        self.close_grants(&revoked_grants);
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
                "Connection updated: {}",
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

    /// Delete a connection; rules die with it (§7).
    pub fn ui_delete_connection(&self, id: &Uuid) -> Result<Connection> {
        let conn = self.store.connection_by_id(id)?;
        let confirmation = self.confirm_action(&format!("Delete connection “{}”", conn.name))?;
        let conn = self.store.delete_connection(id)?;
        let revoked_grants = self.grants.remove_for_connection(id);
        self.close_grants(&revoked_grants);
        let dropped = self.policy.remove_rules_for_connection(id)?;
        if dropped > 0 {
            self.events.rules_changed();
        }
        self.audit.append(
            AuditEntry::new(
                AuditKind::ConnectionDeleted,
                format!("Connection deleted: {}", conn.name),
            )
            .connection(conn.name.clone())
            .confirmation(confirmation),
        );
        Ok(conn)
    }

    /* ---------------------------- rules (UI) ------------------------------ */

    pub fn rules(&self) -> Vec<Rule> {
        self.policy.rules()
    }

    pub fn grants_for_connection(&self, connection: &Connection) -> Vec<AccessGrantSummary> {
        self.grants.for_connection(connection)
    }

    pub fn ui_remove_grant(&self, id: &Uuid) -> Result<bool> {
        let Some(grant) = self.grants.remove(id) else {
            return Ok(false);
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
                format!("Access session revoked: {} → {connection}", grant.agent),
            )
            .agent(grant.agent)
            .connection(connection)
            .field("grant_id", id.to_string())
            .field("scope", format!("{:?}", grant.scope).to_lowercase()),
        );
        self.events.rules_changed();
        Ok(true)
    }

    pub(crate) fn revoke_access_grants_for_agent(&self, agent: &str, reason: &str) {
        let removed = self.grants.remove_for_agent(agent);
        if removed.is_empty() {
            return;
        }
        self.close_grants(&removed);
        self.audit.append(
            AuditEntry::new(
                AuditKind::GrantRevoked,
                format!("Access sessions revoked: {agent}"),
            )
            .agent(agent.to_string())
            .detail(reason)
            .field("grants_removed", removed.len()),
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
                    format!("Auto-allow removed: {} → {}", rule.agent, conn_name),
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
        self.remove_rules_for_agent_before_pairing(agent, None, None)
    }

    fn remove_rules_for_agent_before_pairing(
        &self,
        agent: &str,
        ctx: Option<&DecisionContext>,
        confirmation: Option<ConfirmationMethod>,
    ) -> Result<usize> {
        let removed = self.policy.remove_rules_for_agent(agent)?;
        if removed > 0 {
            let mut entry = AuditEntry::new(
                AuditKind::RuleRemoved,
                format!("Auto-allow permissions revoked: {agent}"),
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

    /// Revoke invalidates the token immediately; standing rules are kept
    /// (visible and removable on the Connections tab) and re-disclosed if
    /// the name pairs again (§9).
    pub fn ui_revoke_agent(&self, name: &str) -> Result<bool> {
        let removed = self.pairing.revoke(name)?;
        if removed {
            self.revoke_access_grants_for_agent(name, "agent revoked");
            self.audit.append(
                AuditEntry::new(
                    AuditKind::TokenRevoked,
                    format!("Pair token revoked: {name}"),
                )
                .agent(name.to_string()),
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
        let confirmation = if on {
            None
        } else {
            Some(self.confirm_action("Disable OS authentication requirement for reading secrets")?)
        };
        self.store.set_reauth_on_read(on)?;
        let mut entry = AuditEntry::new(
            AuditKind::SettingsChanged,
            format!(
                "OS authentication requirement {}",
                if on { "enabled" } else { "disabled" }
            ),
        );
        if let Some(confirmation) = confirmation {
            entry = entry.confirmation(confirmation);
        }
        self.audit.append(
            entry
                .field("setting", "reauth_on_read")
                .field("enabled", on),
        );
        Ok(())
    }

    pub fn ui_set_hide_secret_prefixes(&self, on: bool) -> Result<()> {
        self.store.set_hide_secret_prefixes(on)?;
        self.audit.append(AuditEntry::new(
            AuditKind::SettingsChanged,
            format!(
                "Secret prefixes {} in the secrets list",
                if on { "hidden" } else { "shown" }
            ),
        ));
        Ok(())
    }

    pub fn ui_set_menu_bar_hides_dock(&self, on: bool) -> Result<()> {
        self.store.set_menu_bar_hides_dock(on)?;
        self.audit.append(
            AuditEntry::new(
                AuditKind::SettingsChanged,
                format!(
                    "Dock icon {} when minimized to the menu bar",
                    if on { "hidden" } else { "kept" }
                ),
            )
            .field("setting", "menu_bar_hides_dock")
            .field("enabled", on),
        );
        Ok(())
    }

    pub fn ui_change_pg_trusted_ca_bundle_path(&self, path: Option<String>) -> Result<()> {
        let path = path.and_then(|p| {
            let trimmed = p.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        });
        let confirmation = self.confirm_action(match &path {
            Some(_) => "Change Postgres trusted CA bundle",
            None => "Clear Postgres trusted CA bundle",
        })?;
        self.store.set_pg_trusted_ca_bundle_path(path.clone())?;
        self.audit.append(
            AuditEntry::new(
                AuditKind::SettingsChanged,
                "Postgres trusted CA bundle updated",
            )
            .detail(path.clone().unwrap_or_else(|| "cleared".to_string()))
            .field("setting", "pg_trusted_ca_bundle_path")
            .field(
                "path",
                path.map(serde_json::Value::from)
                    .unwrap_or(serde_json::Value::Null),
            )
            .confirmation(confirmation),
        );
        Ok(())
    }
}
