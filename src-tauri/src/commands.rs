//! The Tauri command surface (DESIGN.md §2/§8).
//!
//! Locked to the minimal set the UI needs. Crucially:
//! - there is **no** command that returns a stored secret value; reveal
//!   returns only the short prefix, copy writes core-side to the clipboard;
//! - high-consequence commands (approving a pairing or a mutating request,
//!   saving an "Always allow…" rule, creating a connection, or changing a
//!   connection's capability) are
//!   gated by the **core itself**: the broker demands the native OS
//!   confirmation through the `BrokerEvents` hooks (implemented over
//!   [`crate::auth::confirm`] in this shell) before any effect happens —
//!   this command layer cannot apply a gated action without passing
//!   through it, so the webview cannot forge or skip the gate.

use agentmfa_core::broker::{Broker, UiDecision};
use agentmfa_core::store::ConnectionSpec;
use agentmfa_core::types::{ConnectionConfig, DecisionContext, DecisionSurface, PgSslMode};
use serde::Deserialize;
use tauri::State;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::dto::*;

pub struct AppState {
    pub broker: std::sync::Arc<Broker>,
    // Keeps the daemon (control plane + WS/PG data planes) alive; dropping
    // it aborts the listeners.
    pub _daemon: agentmfa_core::daemon::DaemonHandle,
    // Keeps the broker's tokio runtime (daemon + approvals) alive for the
    // life of the app. Dropped last (after `_daemon`).
    pub _runtime: tokio::runtime::Runtime,
}

type CmdResult<T> = Result<T, String>;
const ACTIVITY_VIEW_LIMIT: usize = 200;

fn activity_view_limit(requested: Option<usize>) -> usize {
    requested
        .unwrap_or(ACTIVITY_VIEW_LIMIT)
        .min(ACTIVITY_VIEW_LIMIT)
}

fn parse_id(id: &str) -> CmdResult<Uuid> {
    Uuid::parse_str(id).map_err(|_| "invalid id".to_string())
}

/* ------------------------------- reads ----------------------------------- */

#[tauri::command]
pub fn list_secrets(state: State<AppState>) -> Vec<SecretDto> {
    let broker = &state.broker;
    broker
        .store
        .list_secrets()
        .iter()
        .map(|m| SecretDto::from(m, broker))
        .collect()
}

#[tauri::command]
pub fn list_connections(state: State<AppState>) -> Vec<ConnectionDto> {
    let broker = &state.broker;
    let rules = broker.rules();
    broker
        .store
        .list_connections()
        .iter()
        .map(|c| ConnectionDto::from(c, &rules, broker))
        .collect()
}

#[tauri::command]
pub fn list_agents(state: State<AppState>) -> Vec<AgentDto> {
    let rules = state.broker.rules();
    state
        .broker
        .paired_agents()
        .iter()
        .map(|a| AgentDto::from(a, &rules))
        .collect()
}

#[tauri::command]
pub fn list_sessions(state: State<AppState>) -> Vec<SessionDto> {
    state
        .broker
        .sessions()
        .iter()
        .map(SessionDto::from)
        .collect()
}

#[tauri::command]
pub fn list_activity(state: State<AppState>, limit: Option<usize>) -> Vec<ActivityDto> {
    let limit = activity_view_limit(limit);
    state
        .broker
        .audit
        .recent(limit)
        .iter()
        .map(ActivityDto::from)
        .collect()
}

#[tauri::command]
pub fn get_queue(state: State<AppState>) -> Vec<ApprovalDto> {
    state
        .broker
        .approvals_queue()
        .into_iter()
        .map(ApprovalDto::from)
        .collect()
}

#[tauri::command]
pub fn get_settings(state: State<AppState>) -> SettingsDto {
    let s = state.broker.settings();
    SettingsDto {
        reauth_on_read: s.reauth_on_read,
        hide_secret_prefixes: s.hide_secret_prefixes,
        pg_trusted_ca_bundle_path: s.pg_trusted_ca_bundle_path,
        menu_bar_hides_dock: s.menu_bar_hides_dock,
    }
}

/* ------------------------------ secrets ---------------------------------- */

#[tauri::command]
pub fn add_secret(state: State<AppState>, name: String, value: String) -> CmdResult<()> {
    state
        .broker
        .ui_add_secret(&name, Zeroizing::new(value))
        .map(|_| ())
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn edit_secret(
    state: State<AppState>,
    id: String,
    new_name: Option<String>,
    new_value: Option<String>,
) -> CmdResult<()> {
    let id = parse_id(&id)?;
    let value = new_value.filter(|v| !v.is_empty()).map(Zeroizing::new);
    state
        .broker
        .ui_edit_secret(&id, new_name.as_deref(), value)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn delete_secret(state: State<AppState>, id: String) -> CmdResult<()> {
    let id = parse_id(&id)?;
    // The core refuses in-use deletion and demands the OS confirmation (§8).
    state
        .broker
        .ui_delete_secret(&id)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// Audited, core-side Keychain read returning only the short prefix (§2).
#[tauri::command]
pub async fn reveal_secret_prefix(state: State<'_, AppState>, id: String) -> CmdResult<String> {
    let id = parse_id(&id)?;
    state
        .broker
        .ui_reveal_secret_prefix(&id)
        .await
        .map_err(|e| e.to_string())
}

/// Core-side copy: reads the value in the core, writes it straight to the
/// clipboard with hygiene, audits *that* a copy happened, never the value.
/// The value never re-enters the webview (§9).
#[tauri::command]
pub async fn copy_secret(state: State<'_, AppState>, id: String) -> CmdResult<()> {
    let id = parse_id(&id)?;
    let value = state
        .broker
        .store
        .secret_value(&id)
        .await
        .map_err(|e| e.to_string())?;
    crate::clipboard::copy_with_hygiene(value)?;
    state
        .broker
        .ui_note_secret_copied(&id)
        .map_err(|e| e.to_string())
}

/* ----------------------------- connections ------------------------------- */

#[derive(Deserialize)]
pub struct ConnectionInput {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: String,
    // API
    pub host: Option<String>,
    pub scheme: Option<String>,
    pub port: Option<u16>,
    pub template: Option<String>,
    // PG
    pub dbname: Option<String>,
    pub user: Option<String>,
    pub host_key_fingerprint: Option<String>,
    pub sslmode: Option<String>,
    // WS
    pub url: Option<String>,
    // pg/ws/ssh single-secret binding (by id) + multi-connect
    pub secret_id: Option<String>,
    #[serde(default = "default_true")]
    pub multi_connect: bool,
}

fn default_true() -> bool {
    true
}

fn parse_pg_sslmode(value: Option<&str>) -> CmdResult<PgSslMode> {
    match value {
        None => Ok(PgSslMode::Require),
        Some("disable") => Ok(PgSslMode::Disable),
        Some("prefer") => Ok(PgSslMode::Prefer),
        Some("require") => Ok(PgSslMode::Require),
        Some("verify-ca") => Ok(PgSslMode::VerifyCa),
        Some("verify-full") => Ok(PgSslMode::VerifyFull),
        Some(other) => Err(format!(
            "invalid pg sslmode {other:?}: expected disable, prefer, require, verify-ca, or verify-full"
        )),
    }
}

impl ConnectionInput {
    fn into_spec(self) -> CmdResult<ConnectionSpec> {
        let config = match self.kind.as_str() {
            "api" => ConnectionConfig::Api {
                host: self.host.unwrap_or_default(),
                scheme: self.scheme.unwrap_or_else(|| "https".into()),
                port: self.port,
                template: self.template.unwrap_or_default(),
            },
            "pg" => ConnectionConfig::Pg {
                host: self.host.unwrap_or_default(),
                port: self.port.unwrap_or(5432),
                dbname: self.dbname.unwrap_or_default(),
                user: self.user.unwrap_or_default(),
                sslmode: parse_pg_sslmode(self.sslmode.as_deref())?,
            },
            "ws" => ConnectionConfig::Ws {
                url: self.url.unwrap_or_default(),
                template: self.template.filter(|t| !t.is_empty()),
            },
            "ssh" => ConnectionConfig::Ssh {
                host: self.host.unwrap_or_default(),
                port: self.port.unwrap_or(22),
                user: self.user.unwrap_or_default(),
                host_key_fingerprint: self.host_key_fingerprint.unwrap_or_default(),
            },
            other => return Err(format!("unknown connection type {other:?}")),
        };
        let secrets = match self.secret_id {
            Some(id) => vec![parse_id(&id)?],
            None => vec![],
        };
        Ok(ConnectionSpec {
            name: self.name,
            config,
            secrets,
            multi_connect: self.multi_connect,
        })
    }
}

/// Creating a connection binds a secret to a destination; the core demands
/// the native OS confirmation before it takes effect (§8).
#[tauri::command]
pub fn add_connection(state: State<AppState>, input: ConnectionInput) -> CmdResult<()> {
    let spec = input.into_spec()?;
    state
        .broker
        .ui_add_connection(spec)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// Security-relevant connection edits are core-gated (§8); metadata-only
/// edits are not. A target change drops the connection's standing rules (§9).
#[tauri::command]
pub fn edit_connection(
    state: State<AppState>,
    id: String,
    input: ConnectionInput,
) -> CmdResult<()> {
    let id = parse_id(&id)?;
    let spec = input.into_spec()?;
    state
        .broker
        .ui_update_connection(&id, spec)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn delete_connection(state: State<AppState>, id: String) -> CmdResult<()> {
    let id = parse_id(&id)?;
    state
        .broker
        .ui_delete_connection(&id)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/* -------------------------------- rules ---------------------------------- */

#[tauri::command]
pub fn remove_rule(state: State<AppState>, id: String) -> CmdResult<bool> {
    let id = parse_id(&id)?;
    state.broker.ui_remove_rule(&id).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn remove_grant(state: State<AppState>, id: String) -> CmdResult<bool> {
    let id = parse_id(&id)?;
    state
        .broker
        .ui_remove_grant(&id)
        .map_err(|e| e.to_string())
}

/* ----------------------------- paired agents ----------------------------- */

#[tauri::command]
pub fn revoke_agent(state: State<AppState>, name: String) -> CmdResult<bool> {
    state
        .broker
        .ui_revoke_agent(&name)
        .map_err(|e| e.to_string())
}

/* ------------------------------ sessions --------------------------------- */

#[tauri::command]
pub fn close_session(state: State<AppState>, id: u64) -> CmdResult<bool> {
    state.broker.ui_close_session(id).map_err(|e| e.to_string())
}

/* ------------------------------ settings --------------------------------- */

#[tauri::command]
pub fn set_reauth_on_read(state: State<AppState>, on: bool) -> CmdResult<()> {
    state
        .broker
        .ui_change_reauth_on_read(on)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn set_hide_secret_prefixes(state: State<AppState>, on: bool) -> CmdResult<()> {
    state
        .broker
        .ui_set_hide_secret_prefixes(on)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn set_menu_bar_hides_dock(state: State<AppState>, on: bool) -> CmdResult<()> {
    state
        .broker
        .ui_set_menu_bar_hides_dock(on)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn set_pg_trusted_ca_bundle_path(
    state: State<AppState>,
    path: Option<String>,
) -> CmdResult<()> {
    state
        .broker
        .ui_change_pg_trusted_ca_bundle_path(path)
        .map_err(|e| e.to_string())
}

/* ------------------------------ approvals -------------------------------- */

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionInput {
    Deny,
    AllowOnce,
    AllowSession,
    AlwaysAllow,
}

/// Apply a decision to a queued approval. Deny is always one click. Allow
/// on a pairing or a mutating request — and Always allow in every case —
/// complete only after the native OS confirmation, which the **core**
/// demands via `BrokerEvents::confirm_decision` before the decision takes
/// effect (§6/§8); this command only names the surface for attribution.
#[tauri::command]
pub fn decide(
    state: State<AppState>,
    id: String,
    decision: DecisionInput,
    revoke_inherited_rules: Option<bool>,
) -> CmdResult<()> {
    let broker = &state.broker;
    let id = parse_id(&id)?;
    let ui_decision = match decision {
        DecisionInput::Deny => UiDecision::Deny,
        DecisionInput::AllowOnce => UiDecision::AllowOnce,
        DecisionInput::AllowSession => UiDecision::AllowSession,
        DecisionInput::AlwaysAllow => UiDecision::AlwaysAllow,
    };
    let ctx = DecisionContext::local(DecisionSurface::AppWindow);
    broker
        .decide_with_pairing_options(
            &id,
            ui_decision,
            revoke_inherited_rules.unwrap_or(false),
            &ctx,
        )
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "no such pending request".to_string())?;
    Ok(())
}

/// Register every command with the Tauri builder.
pub fn handler() -> impl Fn(tauri::ipc::Invoke<tauri::Wry>) -> bool + Send + Sync + 'static {
    tauri::generate_handler![
        list_secrets,
        list_connections,
        list_agents,
        list_sessions,
        list_activity,
        get_queue,
        get_settings,
        add_secret,
        edit_secret,
        delete_secret,
        reveal_secret_prefix,
        copy_secret,
        add_connection,
        edit_connection,
        delete_connection,
        remove_rule,
        remove_grant,
        revoke_agent,
        close_session,
        set_reauth_on_read,
        set_hide_secret_prefixes,
        set_menu_bar_hides_dock,
        set_pg_trusted_ca_bundle_path,
        decide,
        crate::windows::ui_set_mode,
        crate::windows::ui_hide_main,
        crate::windows::ui_hide_dropdown,
        crate::windows::ui_show_approval,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pg_sslmode_rejects_unknown_values() {
        assert_eq!(parse_pg_sslmode(None).unwrap(), PgSslMode::Require);
        assert_eq!(
            parse_pg_sslmode(Some("verify-full")).unwrap(),
            PgSslMode::VerifyFull
        );
        let err = parse_pg_sslmode(Some("verify_none")).unwrap_err();
        assert!(err.contains("invalid pg sslmode"));
    }

    #[test]
    fn activity_view_limit_is_bounded() {
        assert_eq!(activity_view_limit(None), ACTIVITY_VIEW_LIMIT);
        assert_eq!(activity_view_limit(Some(50)), 50);
        assert_eq!(activity_view_limit(Some(usize::MAX)), ACTIVITY_VIEW_LIMIT);
        assert_eq!(activity_view_limit(Some(0)), 0);
    }
}
