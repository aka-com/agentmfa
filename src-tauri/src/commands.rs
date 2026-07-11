//! The Tauri command surface locked to the minimal set the UI needs:
//!
//! - there is **no** command that returns a stored secret value; reveal
//!   returns only the short prefix, copy writes core-side to the clipboard;
//! - confirmation-gated commands (approving a pairing or mutating request,
//!   starting an access session, saving an "Always allow…" rule, creating a
//!   connection, or changing a connection's capability) are
//!   gated by the **core itself**: the broker demands the native OS
//!   confirmation through the `BrokerEvents` hooks (implemented over
//!   [`crate::auth::confirm`] in this shell) before any effect happens —
//!   this command layer cannot apply a gated action without passing
//!   through it, so the webview cannot forge or skip the gate.

use agentmfa_core::broker::{Broker, UiDecision};
use agentmfa_core::error::{ConnectionField, CoreError};
use agentmfa_core::store::ConnectionSpec;
use agentmfa_core::types::{ConnectionConfig, DecisionContext, DecisionSurface, PgSslMode};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter as _, State};
use tauri_plugin_clipboard_manager::ClipboardExt as _;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::dto::*;

pub struct AppState {
    pub broker: std::sync::Arc<Broker>,
    pub ssh_imports: std::sync::Mutex<crate::ssh_import::ImportCache>,
    // Keeps the daemon (control plane + WS/PG data planes) alive; dropping
    // it aborts the listeners.
    pub _daemon: agentmfa_core::daemon::DaemonHandle,
    // Keeps the broker's tokio runtime (daemon + approvals) alive for the
    // life of the app. Dropped last (after `_daemon`).
    pub _runtime: tokio::runtime::Runtime,
}

type CmdResult<T> = Result<T, String>;
type FormResult<T> = Result<T, FormError>;
const ACTIVITY_VIEW_LIMIT: usize = 200;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FormError {
    kind: &'static str,
    code: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    field: Option<&'static str>,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
}

#[derive(Clone, Copy)]
enum FormContext<'a> {
    Secret,
    Connection {
        kind: &'a str,
        includes_new_secret: bool,
    },
}

impl FormError {
    fn validation(code: &'static str, field: &'static str, message: impl Into<String>) -> Self {
        Self {
            kind: "validation",
            code,
            field: Some(field),
            message: message.into(),
            detail: None,
        }
    }

    fn global(
        kind: &'static str,
        code: &'static str,
        message: impl Into<String>,
        detail: Option<String>,
    ) -> Self {
        Self {
            kind,
            code,
            field: None,
            message: message.into(),
            detail,
        }
    }

    fn from_core(error: CoreError, context: FormContext<'_>) -> Self {
        match error {
            CoreError::SecretNameTaken(_) => {
                let field = match context {
                    FormContext::Secret => "name",
                    FormContext::Connection { .. } => "newSecretName",
                };
                Self::validation(
                    "secret_name_taken",
                    field,
                    "That credential name is already in use",
                )
                .with_kind("conflict")
            }
            CoreError::ConnectionNameTaken(_) => Self::validation(
                "connection_name_taken",
                "name",
                "That service name is already in use",
            )
            .with_kind("conflict"),
            CoreError::InvalidSecretName(_) => {
                let field = match context {
                    FormContext::Secret => "name",
                    FormContext::Connection { .. } => "newSecretName",
                };
                Self::validation(
                    "invalid_secret_name",
                    field,
                    "Use letters, numbers, and underscores; start with a letter or underscore",
                )
            }
            CoreError::InvalidConnectionName(_) => Self::validation(
                "invalid_connection_name",
                "name",
                "Use 1–64 lowercase letters, numbers, hyphens, or underscores",
            ),
            CoreError::Template(error) => Self::validation(
                "invalid_template",
                "template",
                format!("Invalid template: {error}"),
            ),
            CoreError::UnknownTemplateRef(name) => Self::validation(
                "unknown_template_credential",
                "template",
                format!("{name} is not a saved credential"),
            ),
            CoreError::WrongSecretCount { kind } => {
                let field = if kind == "websocket" {
                    "template"
                } else {
                    "secret"
                };
                Self::validation(
                    "wrong_credential_count",
                    field,
                    format!("{kind} services require exactly one saved credential"),
                )
            }
            CoreError::SecretNotFound => match context {
                FormContext::Secret => Self::global(
                    "conflict",
                    "secret_not_found",
                    "This credential was removed elsewhere",
                    None,
                ),
                FormContext::Connection { .. } => Self::validation(
                    "secret_not_found",
                    "secret",
                    "This credential no longer exists; choose another",
                ),
            },
            CoreError::InvalidConnectionField { field, message } => {
                let connection_kind = match context {
                    FormContext::Connection { kind, .. } => kind,
                    FormContext::Secret => "",
                };
                let field = match field {
                    ConnectionField::Host | ConnectionField::Scheme if connection_kind == "api" => {
                        "origin"
                    }
                    ConnectionField::Host => "host",
                    ConnectionField::Scheme => "origin",
                    ConnectionField::Port => "port",
                    ConnectionField::Database => "dbname",
                    ConnectionField::User => "user",
                    ConnectionField::Url => "url",
                    ConnectionField::Template => "template",
                    ConnectionField::HostKeyFingerprint => "hostKeyFingerprint",
                };
                Self::validation("invalid_connection_field", field, message)
            }
            CoreError::InvalidConnectionConfig(message) => {
                let field = match context {
                    FormContext::Connection {
                        kind: "api",
                        includes_new_secret: true,
                    } => Some("template"),
                    FormContext::Connection {
                        includes_new_secret: true,
                        ..
                    } => Some("newSecretValue"),
                    _ => None,
                };
                match field {
                    Some(field) => Self::validation("invalid_connection", field, message),
                    None => Self::global("validation", "invalid_connection", message, None),
                }
            }
            CoreError::NotConfirmed => {
                Self::global("cancelled", "not_confirmed", "Nothing was saved", None)
            }
            CoreError::KindChange => Self::global(
                "validation",
                "connection_kind_fixed",
                "Service type cannot be changed after creation",
                None,
            ),
            CoreError::ConnectionNotFound => Self::global(
                "conflict",
                "connection_not_found",
                "This service was removed elsewhere",
                None,
            ),
            CoreError::ApprovalConnectionChanged => Self::global(
                "conflict",
                "connection_changed",
                "The service changed while you were confirming. Review it and save again.",
                None,
            ),
            CoreError::Vault(detail) => Self::global(
                "system",
                "keychain_unavailable",
                "Couldn’t save to macOS Keychain",
                Some(detail),
            ),
            CoreError::Io(error) => Self::global(
                "system",
                "state_write_failed",
                "Couldn’t save your changes",
                Some(error.to_string()),
            ),
            other => {
                let detail = other.to_string();
                Self::global(
                    "system",
                    "save_failed",
                    "Couldn’t save your changes",
                    Some(detail),
                )
            }
        }
    }

    fn with_kind(mut self, kind: &'static str) -> Self {
        self.kind = kind;
        self
    }
}

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
    let broker = &state.broker;
    let rules = broker.rules();
    broker
        .paired_agents()
        .iter()
        .map(|a| AgentDto::from(a, &rules, broker))
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
pub fn clear_activity(app: AppHandle, state: State<AppState>) -> CmdResult<()> {
    state.broker.audit.clear().map_err(|e| e.to_string())?;
    let _ = app.emit(crate::events::EVT_ACTIVITY_CHANGED, ());
    Ok(())
}

#[tauri::command]
pub fn get_queue(state: State<AppState>) -> Vec<ApprovalDto> {
    let duration = state.broker.config.access_grant_ttl.as_secs();
    state
        .broker
        .approvals_queue()
        .into_iter()
        .map(|request| ApprovalDto::new(request, duration))
        .collect()
}

#[tauri::command]
pub fn get_settings(state: State<AppState>) -> SettingsDto {
    let s = state.broker.settings();
    SettingsDto {
        reauth_on_read: s.reauth_on_read,
        menu_bar_hides_dock: s.menu_bar_hides_dock,
        show_service_walkthrough: s.show_service_walkthrough,
        show_agent_walkthrough: s.show_agent_walkthrough,
    }
}

fn agent_setup_instructions(socket: &str) -> String {
    format!(
        "Connect to the local AgentMFA broker. Read its current instructions with:\n\ncurl -fsS --unix-socket {socket} http://localhost/instructions"
    )
}

#[tauri::command]
pub fn get_agent_setup(state: State<AppState>) -> String {
    agent_setup_instructions(&state.broker.paths.socket_display())
}

/// The full agent-facing walkthrough the daemon serves at `GET /instructions`.
#[tauri::command]
pub fn get_broker_instructions(state: State<AppState>) -> String {
    agentmfa_core::daemon::wellknown::instructions(&state.broker.config, &state.broker.paths)
}

#[tauri::command]
pub fn copy_agent_setup(app: AppHandle, state: State<AppState>) -> CmdResult<()> {
    let instructions = agent_setup_instructions(&state.broker.paths.socket_display());
    app.clipboard()
        .write_text(instructions)
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn inspect_ssh_import(
    state: State<'_, AppState>,
    source: String,
) -> CmdResult<crate::ssh_import::SshImportPreview> {
    let resolved = tokio::task::spawn_blocking(move || crate::ssh_import::resolve(&source))
        .await
        .map_err(|error| format!("SSH configuration resolution stopped: {error}"))??;
    let mut imports = state.ssh_imports.lock().unwrap();
    Ok(imports.insert(resolved))
}

/// known_hosts provenance for the first-connection host-key trust prompt:
/// what the user's own known_hosts files say about `host:port`. Read-only
/// and fingerprints-only — never key material.
#[tauri::command]
pub async fn check_known_hosts(
    host: String,
    port: u16,
) -> CmdResult<Vec<crate::ssh_import::HostKeyCandidate>> {
    tokio::task::spawn_blocking(move || crate::ssh_import::known_hosts_candidates(&host, port))
        .await
        .map_err(|error| format!("known_hosts lookup stopped: {error}"))?
}

/* ------------------------------ secrets ---------------------------------- */

#[tauri::command]
pub fn add_secret(state: State<AppState>, name: String, value: String) -> FormResult<()> {
    state
        .broker
        .ui_add_secret(&name, Zeroizing::new(value))
        .map(|_| ())
        .map_err(|error| FormError::from_core(error, FormContext::Secret))
}

#[tauri::command]
pub fn edit_secret(
    state: State<AppState>,
    id: String,
    new_name: Option<String>,
    new_value: Option<String>,
) -> FormResult<()> {
    let id = parse_id(&id).map_err(|detail| {
        FormError::global(
            "system",
            "invalid_secret_id",
            "Couldn’t edit this credential",
            Some(detail),
        )
    })?;
    let value = new_value.filter(|v| !v.is_empty()).map(Zeroizing::new);
    state
        .broker
        .ui_edit_secret(&id, new_name.as_deref(), value)
        .map(|_| ())
        .map_err(|error| FormError::from_core(error, FormContext::Secret))
}

#[tauri::command]
pub fn delete_secret(state: State<AppState>, id: String) -> CmdResult<()> {
    let id = parse_id(&id)?;
    // The core refuses in-use deletion and demands the OS confirmation.
    state
        .broker
        .ui_delete_secret(&id)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// Audited, core-side Keychain read returning only the short prefix.
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
/// The value never re-enters the webview.
#[tauri::command]
pub async fn copy_secret(state: State<'_, AppState>, id: String) -> CmdResult<()> {
    let id = parse_id(&id)?;
    let value = state
        .broker
        .ui_secret_value_for_copy(&id)
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
    pub destination: Option<String>,
    pub sslmode: Option<String>,
    pub trusted_ca_bundle_path: Option<String>,
    // WS
    pub url: Option<String>,
    // pg/ws/ssh single-secret binding (by id)
    pub secret_id: Option<String>,
    // Add-only connection-first setup. Both fields must be present together;
    // the core writes the vault item and connection atomically.
    pub new_secret_name: Option<String>,
    pub new_secret_value: Option<String>,
    // SSH import-only: an opaque preview id and one identity path returned by
    // that preview. The backend verifies the binding before reading the file.
    pub ssh_import_id: Option<String>,
    pub identity_file: Option<String>,
}

fn parse_pg_sslmode(value: Option<&str>) -> CmdResult<PgSslMode> {
    match value {
        None => Ok(PgSslMode::VerifyFull),
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
    fn into_spec(self) -> FormResult<ConnectionSpec> {
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
                sslmode: parse_pg_sslmode(self.sslmode.as_deref()).map_err(|_| {
                    FormError::validation(
                        "invalid_sslmode",
                        "sslmode",
                        "Choose a supported TLS mode",
                    )
                })?,
                trusted_ca_bundle_path: self.trusted_ca_bundle_path.and_then(|path| {
                    let path = path.trim().to_string();
                    (!path.is_empty()).then_some(path)
                }),
            },
            "ws" => ConnectionConfig::Ws {
                url: self.url.unwrap_or_default(),
                template: self.template.filter(|t| !t.is_empty()),
            },
            "ssh" => ConnectionConfig::Ssh {
                destination: self.destination.filter(|value| !value.is_empty()),
                host: self.host.unwrap_or_default(),
                port: self.port.unwrap_or(22),
                user: self.user.unwrap_or_default(),
                host_key_fingerprint: self.host_key_fingerprint.unwrap_or_default(),
            },
            other => {
                return Err(FormError::global(
                    "system",
                    "unknown_connection_type",
                    "Couldn’t save this service",
                    Some(format!("unknown connection type {other:?}")),
                ))
            }
        };
        let secrets = match self.secret_id {
            Some(id) => vec![parse_id(&id).map_err(|_| {
                FormError::validation(
                    "secret_not_found",
                    "secret",
                    "This credential no longer exists; choose another",
                )
            })?],
            None => vec![],
        };
        Ok(ConnectionSpec {
            name: self.name,
            config,
            secrets,
        })
    }
}

/// Creating a connection binds a secret to a destination; the core demands
/// the native OS confirmation before it takes effect.
#[tauri::command]
pub fn add_connection(state: State<AppState>, mut input: ConnectionInput) -> FormResult<()> {
    let kind = input.kind.clone();
    let new_secret_name = input.new_secret_name.take();
    // Wrap the user-entered value before any fallible parsing below so every
    // error path zeroizes it rather than dropping an ordinary String.
    let new_secret_value = input.new_secret_value.take().map(Zeroizing::new);
    if kind == "ssh" {
        if let Some(value) = &new_secret_value {
            agentmfa_core::capability::ssh::validate_private_key(value.as_bytes()).map_err(
                |message| FormError::validation("invalid_ssh_identity", "newSecretValue", message),
            )?;
        }
    }
    let ssh_import_id = input.ssh_import_id.take();
    let identity_file = input.identity_file.take();
    let imported_value = match (&ssh_import_id, &identity_file) {
        (Some(import_id), Some(path)) if kind == "ssh" => {
            let resolved = state
                .ssh_imports
                .lock()
                .unwrap()
                .get(import_id)
                .map_err(|message| {
                    FormError::validation("ssh_import_expired", "newSecretValue", message)
                })?;
            if input.host.as_deref() != Some(resolved.host.as_str())
                || input.port != Some(resolved.port)
                || input.user.as_deref() != Some(resolved.user.as_str())
                || input.destination.as_deref() != Some(resolved.destination.as_str())
            {
                return Err(FormError::validation(
                    "ssh_import_changed",
                    "newSecretValue",
                    "SSH details changed after import; resolve the command again",
                ));
            }
            Some(
                crate::ssh_import::load_identity(&resolved, path).map_err(|message| {
                    FormError::validation("invalid_ssh_identity", "newSecretValue", message)
                })?,
            )
        }
        (None, None) => None,
        _ => {
            return Err(FormError::validation(
                "incomplete_ssh_import",
                "newSecretValue",
                "Resolve the SSH command and choose an identity file again",
            ))
        }
    };
    let spec = input.into_spec()?;
    let includes_new_secret =
        new_secret_name.is_some() || new_secret_value.is_some() || imported_value.is_some();
    let result = match (new_secret_name, new_secret_value.or(imported_value)) {
        (Some(name), Some(value)) if !name.is_empty() && !value.is_empty() => state
            .broker
            .ui_add_connection_with_secret(&name, value, spec)
            .map(|_| ()),
        (None, None) => state.broker.ui_add_connection(spec).map(|_| ()),
        _ => {
            return Err(FormError::validation(
                "incomplete_new_credential",
                "newSecretValue",
                "Credential name and value must be provided together",
            ))
        }
    };
    result.map_err(|error| {
        FormError::from_core(
            error,
            FormContext::Connection {
                kind: &kind,
                includes_new_secret,
            },
        )
    })?;
    if let Some(import_id) = ssh_import_id {
        state.ssh_imports.lock().unwrap().remove(&import_id);
    }
    Ok(())
}

/// Security-relevant connection edits are core-gated; metadata-only
/// edits are not. A target change drops the connection's standing rules.
#[tauri::command]
pub fn edit_connection(
    state: State<AppState>,
    id: String,
    input: ConnectionInput,
) -> FormResult<()> {
    let kind = input.kind.clone();
    let id = parse_id(&id).map_err(|detail| {
        FormError::global(
            "system",
            "invalid_connection_id",
            "Couldn’t edit this service",
            Some(detail),
        )
    })?;
    let spec = input.into_spec()?;
    state
        .broker
        .ui_update_connection(&id, spec)
        .map(|_| ())
        .map_err(|error| {
            FormError::from_core(
                error,
                FormContext::Connection {
                    kind: &kind,
                    includes_new_secret: false,
                },
            )
        })
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

/// Broker-side connectivity/credential test against the service's pinned
/// destination; only the pass/fail summary reaches the webview.
#[tauri::command]
pub async fn test_connection(
    state: State<'_, AppState>,
    id: String,
) -> CmdResult<agentmfa_core::broker::ConnectionTestReport> {
    let id = parse_id(&id)?;
    state
        .broker
        .ui_test_connection(&id)
        .await
        .map_err(|e| e.to_string())
}

/* -------------------------------- rules ---------------------------------- */

#[tauri::command]
pub fn remove_permission(state: State<AppState>, id: String) -> CmdResult<bool> {
    let id = parse_id(&id)?;
    state
        .broker
        .ui_remove_permission(&id)
        .map_err(|e| e.to_string())
}

/* ----------------------------- paired agents ----------------------------- */

#[tauri::command]
pub fn revoke_agent(state: State<AppState>, id: String) -> CmdResult<bool> {
    let id = parse_id(&id)?;
    state.broker.ui_revoke_agent(&id).map_err(|e| e.to_string())
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
pub fn set_menu_bar_hides_dock(state: State<AppState>, on: bool) -> CmdResult<()> {
    state
        .broker
        .ui_set_menu_bar_hides_dock(on)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn set_service_walkthrough_visible(state: State<AppState>, on: bool) -> CmdResult<()> {
    state
        .broker
        .ui_set_service_walkthrough_visible(on)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn set_agent_walkthrough_visible(state: State<AppState>, on: bool) -> CmdResult<()> {
    state
        .broker
        .ui_set_agent_walkthrough_visible(on)
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

/// Apply a decision to a queued approval. Deny is always one click. Allow once
/// on a pairing or mutating request, every access session, and Always allow in
/// every case complete only after the native OS confirmation, which the
/// **core** demands via `BrokerEvents::confirm_decision` before the decision
/// takes effect; this command only names the surface for attribution.
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
        clear_activity,
        get_queue,
        get_settings,
        get_agent_setup,
        get_broker_instructions,
        copy_agent_setup,
        inspect_ssh_import,
        check_known_hosts,
        add_secret,
        edit_secret,
        delete_secret,
        reveal_secret_prefix,
        copy_secret,
        add_connection,
        edit_connection,
        delete_connection,
        test_connection,
        remove_permission,
        revoke_agent,
        close_session,
        set_reauth_on_read,
        set_menu_bar_hides_dock,
        set_service_walkthrough_visible,
        set_agent_walkthrough_visible,
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
        assert_eq!(parse_pg_sslmode(None).unwrap(), PgSslMode::VerifyFull);
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

    #[test]
    fn connection_input_preserves_api_origin_and_ws_template() {
        let api = ConnectionInput {
            name: "local-api".into(),
            kind: "api".into(),
            host: Some("localhost".into()),
            scheme: Some("http".into()),
            port: Some(8080),
            template: Some("Authorization: Bearer {{TOKEN}}".into()),
            dbname: None,
            user: None,
            host_key_fingerprint: None,
            destination: None,
            sslmode: None,
            trusted_ca_bundle_path: None,
            url: None,
            secret_id: None,
            new_secret_name: None,
            new_secret_value: None,
            ssh_import_id: None,
            identity_file: None,
        }
        .into_spec()
        .unwrap();
        assert!(matches!(
            api.config,
            ConnectionConfig::Api { ref host, ref scheme, port: Some(8080), .. }
                if host == "localhost" && scheme == "http"
        ));

        let secret_id = Uuid::new_v4();
        let ws = ConnectionInput {
            name: "stream".into(),
            kind: "ws".into(),
            host: None,
            scheme: None,
            port: None,
            template: Some("X-Stream-Key: {{STREAM_TOKEN}}".into()),
            dbname: None,
            user: None,
            host_key_fingerprint: None,
            destination: None,
            sslmode: None,
            trusted_ca_bundle_path: None,
            url: Some("wss://stream.example.com/feed".into()),
            secret_id: Some(secret_id.to_string()),
            new_secret_name: None,
            new_secret_value: None,
            ssh_import_id: None,
            identity_file: None,
        }
        .into_spec()
        .unwrap();
        assert!(matches!(
            ws.config,
            ConnectionConfig::Ws { ref template, .. }
                if template.as_deref() == Some("X-Stream-Key: {{STREAM_TOKEN}}")
        ));
    }

    #[test]
    fn agent_setup_instructions_include_the_runtime_socket() {
        let instructions = agent_setup_instructions("/tmp/agentmfa-test.sock");
        assert!(instructions.contains("curl -fsS"));
        assert!(instructions.contains("--unix-socket /tmp/agentmfa-test.sock"));
        assert!(instructions.contains("with:\n\ncurl -fsS"));
        assert!(!instructions.contains("\\\n"));
        assert!(instructions.ends_with("http://localhost/instructions"));
        assert!(!instructions.contains("--max-time"));
        assert!(!instructions.contains("Reuse an existing token before pairing"));
    }

    #[test]
    fn form_errors_serialize_conflicts_with_the_relevant_field() {
        let error = FormError::from_core(
            CoreError::ConnectionNameTaken("github".into()),
            FormContext::Connection {
                kind: "api",
                includes_new_secret: false,
            },
        );
        assert_eq!(
            serde_json::to_value(error).unwrap(),
            serde_json::json!({
                "kind": "conflict",
                "code": "connection_name_taken",
                "field": "name",
                "message": "That service name is already in use"
            })
        );
    }

    #[test]
    fn form_errors_map_core_connection_fields_without_parsing_messages() {
        let error = FormError::from_core(
            CoreError::InvalidConnectionField {
                field: ConnectionField::HostKeyFingerprint,
                message: "Enter an OpenSSH SHA-256 or SHA-512 fingerprint".into(),
            },
            FormContext::Connection {
                kind: "ssh",
                includes_new_secret: false,
            },
        );
        assert_eq!(error.kind, "validation");
        assert_eq!(error.code, "invalid_connection_field");
        assert_eq!(error.field, Some("hostKeyFingerprint"));
        assert_eq!(
            error.message,
            "Enter an OpenSSH SHA-256 or SHA-512 fingerprint"
        );
    }
}
