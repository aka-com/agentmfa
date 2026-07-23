//! The Tauri command surface locked to the minimal set the UI needs:
//!
//! - there is **no** command that returns a stored secret value; reveal
//!   returns only the short prefix, copy writes core-side to the clipboard;
//! - confirmation-gated commands (attaching an already-stored secret to a
//!   new destination, changing a connection's capability, issuing a first
//!   direct endpoint, rotating the key) are gated by the **core itself**:
//!   the broker demands the native OS confirmation through the
//!   `BrokerEvents` hooks (implemented over [`crate::auth::confirm`] in
//!   this shell) before any effect happens — this command layer cannot
//!   apply a gated action without passing through it, so the webview cannot
//!   forge or skip the gate.

use aka_core::broker::Broker;
use aka_core::error::{ConnectionField, CoreError};
use aka_core::store::ConnectionSpec;
use aka_core::types::{ConnectionConfig, PgSslMode};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter as _, State};
use tauri_plugin_clipboard_manager::ClipboardExt as _;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::dto::*;

pub struct AppState {
    pub broker: std::sync::Arc<Broker>,
    pub ssh_imports: std::sync::Mutex<crate::ssh_import::ImportCache>,
    // Keeps the Node sidecar supervised; dropping it kills the process and
    // stops restarting it. `None` when no sidecar script is installed.
    // Declared before the runtime it spawned its supervisor on.
    pub _sidecar: Option<aka_core::sidecar::Sidecar>,
    // Keeps the daemon (control plane + WS/PG data planes) alive; dropping
    // it aborts the listeners.
    pub _daemon: aka_core::daemon::DaemonHandle,
    // Keeps the broker's tokio runtime (daemon + executions) alive for the
    // life of the app. Dropped last (after `_daemon`).
    pub _runtime: tokio::runtime::Runtime,
}

type CmdResult<T> = Result<T, String>;
type FormResult<T> = Result<T, FormError>;
const ACTIVITY_VIEW_LIMIT: usize = 200;

/// The local OS account name is presentation-only: connection forms use it
/// as a hint, never as a submitted or persisted value.
#[tauri::command]
pub fn get_local_username() -> String {
    ["USER", "LOGNAME", "USERNAME"]
        .into_iter()
        .filter_map(|name| std::env::var(name).ok())
        .find(|name| !name.trim().is_empty())
        .map(|name| name.trim().to_string())
        .unwrap_or_default()
}

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
                "That tool name is already in use",
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
                "Use 1–64 letters, numbers, spaces, or endpoint punctuation; start with a letter or number and don’t end with a space",
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
                    format!("{kind} tools require exactly one saved credential"),
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
                "Tool type cannot be changed after creation",
                None,
            ),
            CoreError::ConnectionNotFound => Self::global(
                "conflict",
                "connection_not_found",
                "This tool was removed elsewhere",
                None,
            ),
            CoreError::ApprovalConnectionChanged => Self::global(
                "conflict",
                "connection_changed",
                "The tool changed while you were confirming. Review it and save again.",
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
    broker
        .store
        .list_connections()
        .iter()
        .map(|c| ConnectionDto::from(c, broker))
        .collect()
}

#[tauri::command]
pub fn get_identity(state: State<AppState>) -> IdentityDto {
    let broker = &state.broker;
    IdentityDto::from(&broker.identity_info(), broker)
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
pub fn get_settings(state: State<AppState>) -> SettingsDto {
    let s = state.broker.settings();
    SettingsDto {
        reauth_on_read: s.reauth_on_read,
        show_websockets: s.show_websockets,
        menu_bar_hides_dock: s.menu_bar_hides_dock,
        presence_window_secs: s.presence_window_secs,
    }
}

fn agent_setup_instructions(socket: &str, token_path: &str) -> String {
    format!(
        "Connect to the local Multitool broker. Read its current instructions, then list the available connections:\n\ncurl -fsS --unix-socket {socket} http://localhost/instructions\n\nAuthenticate with this computer's shared key — read it from {token_path} and send it as `Authorization: Bearer <key>`."
    )
}

#[tauri::command]
pub fn get_agent_setup(state: State<AppState>) -> String {
    agent_setup_instructions(
        &state.broker.paths.socket_display(),
        &state.broker.paths.token_display(),
    )
}

#[tauri::command]
pub fn copy_agent_setup(app: AppHandle, state: State<AppState>) -> CmdResult<()> {
    let instructions = agent_setup_instructions(
        &state.broker.paths.socket_display(),
        &state.broker.paths.token_display(),
    );
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
    // The core refuses in-use deletion; the UI's inline confirm is the gate.
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
    /// Set when this API upstream speaks MCP at that path.
    pub mcp_path: Option<String>,
    // BYO-app OAuth (plain REST rows): non-secret provider coordinates.
    pub oauth_auth_url: Option<String>,
    pub oauth_token_url: Option<String>,
    pub oauth_client_id: Option<String>,
    pub oauth_scopes: Option<Vec<String>>,
    pub oauth_extra_params: Option<Vec<(String, String)>>,
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
                // Blank is treated as absent: an empty string here would
                // make the sidecar post JSON-RPC to the upstream's root.
                mcp_path: self
                    .mcp_path
                    .map(|path| path.trim().to_string())
                    .filter(|path| !path.is_empty()),
                oauth: match (
                    self.oauth_auth_url,
                    self.oauth_token_url,
                    self.oauth_client_id,
                ) {
                    (Some(auth_url), Some(token_url), Some(client_id)) => {
                        Some(aka_core::types::OAuthSpec {
                            auth_url: auth_url.trim().to_string(),
                            token_url: token_url.trim().to_string(),
                            client_id: client_id.trim().to_string(),
                            scopes: self.oauth_scopes.unwrap_or_default(),
                            extra_auth_params: self.oauth_extra_params.unwrap_or_default(),
                        })
                    }
                    _ => None,
                },
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
                    "Couldn’t save this tool",
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

/// Creating a connection optionally binds a secret to a destination. The
/// core gates the add behind native OS confirmation only when it attaches
/// an already-stored secret; a credential typed into the form (or none at
/// all) adds without a prompt.
#[tauri::command]
pub fn add_connection(state: State<AppState>, mut input: ConnectionInput) -> FormResult<()> {
    let kind = input.kind.clone();
    let new_secret_name = input.new_secret_name.take();
    // Wrap the user-entered value before any fallible parsing below so every
    // error path zeroizes it rather than dropping an ordinary String.
    let new_secret_value = input.new_secret_value.take().map(Zeroizing::new);
    if kind == "ssh" {
        if let Some(value) = &new_secret_value {
            aka_core::capability::ssh::validate_private_key(value.as_bytes()).map_err(
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
/// edits are not. A target change revokes the connection's direct endpoints.
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
            "Couldn’t edit this tool",
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
) -> CmdResult<aka_core::broker::ConnectionTestReport> {
    let id = parse_id(&id)?;
    state
        .broker
        .ui_test_connection(&id)
        .await
        .map_err(|e| e.to_string())
}

/// Test an add-form draft before anything is persisted. A typed-in
/// credential rides along for a full sign-in; a chosen stored secret is
/// never read here (the core's draft test refuses the store by design), so
/// this command needs no gate.
#[tauri::command]
pub async fn test_connection_draft(
    state: State<'_, AppState>,
    mut input: ConnectionInput,
) -> FormResult<aka_core::broker::ConnectionTestReport> {
    let kind = input.kind.clone();
    let _ = input.new_secret_name.take();
    let typed_secret = input.new_secret_value.take().map(Zeroizing::new);
    // The reachability test performs no key exchange, so a pending SSH
    // import needs no resolution for a draft dial.
    let _ = input.ssh_import_id.take();
    let _ = input.identity_file.take();
    let spec = input.into_spec()?;
    state
        .broker
        .ui_test_connection_draft(spec, typed_secret)
        .await
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

/* -------------------------------- MCP ------------------------------------ */

/// Begin the MCP sign-in flow (OAuth with discovery + PKCE). The token
/// never enters the webview: progress is observed through
/// `aka://mcp-auth-changed` events and `get_mcp_auth`.
#[tauri::command]
pub fn start_mcp_auth(
    state: State<AppState>,
    input: aka_core::mcp_auth::McpAuthDraft,
) -> FormResult<aka_core::mcp_auth::McpAuthState> {
    state.broker.ui_start_mcp_auth(input).map_err(|error| {
        FormError::from_core(
            error,
            FormContext::Connection {
                kind: "api",
                includes_new_secret: true,
            },
        )
    })
}

#[tauri::command]
pub fn get_mcp_auth(
    state: State<AppState>,
    id: String,
) -> CmdResult<Option<aka_core::mcp_auth::McpAuthState>> {
    let id = parse_id(&id)?;
    Ok(state.broker.ui_mcp_auth_state(&id))
}

#[tauri::command]
pub fn cancel_mcp_auth(state: State<AppState>, id: String) -> CmdResult<bool> {
    let id = parse_id(&id)?;
    Ok(state.broker.ui_cancel_mcp_auth(&id))
}

/// Broker-side MCP status check: reachability, acknowledged account,
/// tools vs. the template's expectations, and available resources. Only
/// the summary reaches the webview.
#[tauri::command]
pub async fn mcp_status(
    state: State<'_, AppState>,
    id: String,
    options: Option<aka_core::mcp::McpCheckOptions>,
) -> CmdResult<aka_core::mcp::McpStatusReport> {
    let id = parse_id(&id)?;
    state
        .broker
        .ui_mcp_check(&id, options.unwrap_or_default())
        .await
        .map_err(|e| e.to_string())
}

/// Open the sign-in URL in the system browser. Restricted to http(s) so
/// the webview cannot launch arbitrary schemes.
#[tauri::command]
pub fn open_url(url: String) -> CmdResult<()> {
    let url = url.trim().to_string();
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return Err("only http(s) URLs can be opened".into());
    }
    if url.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err("invalid URL".into());
    }
    #[cfg(target_os = "macos")]
    let launcher = "open";
    #[cfg(not(target_os = "macos"))]
    let launcher = "xdg-open";
    std::process::Command::new(launcher)
        .arg(&url)
        .spawn()
        .map(|_| ())
        .map_err(|e| format!("could not open the browser: {e}"))
}

/// Connect a tool with the user's own OAuth app: opens the provider's
/// consent page in the browser, exchanges the code (loopback PKCE), and
/// stores the token set + connection atomically. Long-running: it resolves
/// only when the browser dance completes or times out.
#[tauri::command]
pub async fn oauth_connect(
    state: State<'_, AppState>,
    input: ConnectionInput,
    client_secret: Option<String>,
) -> FormResult<()> {
    let name = input.name.clone();
    let secret_name = suggested_oauth_secret_name(&state, &name);
    let mut input = input;
    // The token secret does not exist yet; the template is synthesized to
    // reference it (binding + display), while the upstream leg injects a
    // live bearer from the token set directly.
    input.template = Some(format!("Authorization: Bearer {{{{{secret_name}}}}}"));
    let kind = input.kind.clone();
    let spec = input.into_spec()?;
    state
        .broker
        .ui_oauth_connect(
            &secret_name,
            client_secret
                .filter(|value| !value.trim().is_empty())
                .map(Zeroizing::new),
            spec,
        )
        .await
        .map_err(|error| {
            FormError::from_core(
                error,
                FormContext::Connection {
                    kind: &kind,
                    includes_new_secret: true,
                },
            )
        })?;
    Ok(())
}

/// `github` → `GITHUB_OAUTH_TOKEN`, suffixed if taken.
fn suggested_oauth_secret_name(state: &State<AppState>, connection_name: &str) -> String {
    let mut base: String = connection_name
        .to_uppercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    base.truncate(48);
    let base = base.trim_matches('_');
    let base = if base.is_empty() || base.starts_with(|c: char| c.is_ascii_digit()) {
        format!("OAUTH_{base}")
    } else {
        base.to_string()
    };
    let taken: std::collections::HashSet<String> = state
        .broker
        .store
        .list_secrets()
        .into_iter()
        .map(|meta| meta.name)
        .collect();
    let candidate = format!("{base}_OAUTH_TOKEN");
    if !taken.contains(&candidate) {
        return candidate;
    }
    for n in 2..100 {
        let candidate = format!("{base}_OAUTH_TOKEN_{n}");
        if !taken.contains(&candidate) {
            return candidate;
        }
    }
    format!("{base}_OAUTH_TOKEN_{}", uuid::Uuid::new_v4().simple())
}

/// Re-run the OAuth flow for a connection whose token was rejected or
/// expired, replacing the stored token set in place.
#[tauri::command]
pub async fn oauth_reconnect(state: State<'_, AppState>, id: String) -> CmdResult<()> {
    let id = parse_id(&id)?;
    state
        .broker
        .ui_oauth_reconnect(&id)
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/* ----------------------------- agent access -------------------------------- */

/// Enable or disable agent access for a connection. Editing this table is
/// the whole authorization model: enabled connections execute without
/// prompting, disabled ones are refused — for every local agent at once.
#[tauri::command]
pub fn set_tool_access(
    state: State<AppState>,
    connection_id: String,
    enabled: bool,
) -> CmdResult<bool> {
    let connection_id = parse_id(&connection_id)?;
    state
        .broker
        .ui_set_tool_access(&connection_id, enabled)
        .map_err(|e| e.to_string())
}

/// Curate which upstream MCP tools agents may call on a connection. `null`
/// restores the default (all tools). Enforced broker-side on every
/// `tools/call`; the sidecar's tool listing mirrors it.
#[tauri::command]
pub fn set_allowed_tools(
    state: State<AppState>,
    connection_id: String,
    tools: Option<Vec<String>>,
) -> CmdResult<bool> {
    let connection_id = parse_id(&connection_id)?;
    state
        .broker
        .ui_set_allowed_tools(&connection_id, tools)
        .map_err(|e| e.to_string())
}

/// List an MCP connection's upstream tools (names + descriptions), for the
/// per-wiring tool picker. Read-only against the upstream.
#[tauri::command]
pub async fn list_mcp_tools(
    state: State<'_, AppState>,
    id: String,
) -> CmdResult<Vec<aka_core::mcp::McpToolInfo>> {
    let id = parse_id(&id)?;
    state
        .broker
        .ui_list_mcp_tools(&id)
        .await
        .map_err(|e| e.to_string())
}

/// Issue (or rotate) a direct endpoint for a connection. The broker gates
/// this behind the configuration gate (a fresh native authentication is
/// reused, otherwise the OS prompt appears); the returned secret is retained
/// on the endpoint record, so the row's copyable DSN keeps carrying it.
#[tauri::command]
pub async fn issue_endpoint(
    state: State<'_, AppState>,
    connection_id: String,
) -> CmdResult<IssuedEndpointDto> {
    let connection_id = parse_id(&connection_id)?;
    state
        .broker
        .ui_issue_endpoint(&connection_id)
        .await
        .map(IssuedEndpointDto::from)
        .map_err(|e| e.to_string())
}

/// Revoke a direct endpoint: stop its listener and close its live sessions.
#[tauri::command]
pub fn revoke_endpoint(state: State<AppState>, endpoint_id: String) -> CmdResult<bool> {
    let endpoint_id = parse_id(&endpoint_id)?;
    state
        .broker
        .ui_revoke_endpoint(&endpoint_id)
        .map_err(|e| e.to_string())
}

/* ---------------------------- shared identity ----------------------------- */

/// Rotate this computer's key. The broker gates this behind the native
/// confirmation; every agent disconnects and re-reads the token file.
#[tauri::command]
pub async fn rotate_key(state: State<'_, AppState>) -> CmdResult<()> {
    let broker = state.broker.clone();
    // The native confirmation sheet blocks; keep it off the async runtime.
    tokio::task::spawn_blocking(move || broker.ui_rotate_key())
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())
}

/// Copy the shared key to the clipboard. The key never enters the webview:
/// the clipboard write happens here, like a secret copy. Most setups never
/// need it — agents read the token file themselves.
#[tauri::command]
pub fn copy_key(app: AppHandle, state: State<AppState>) -> CmdResult<()> {
    let token = state.broker.identity.token();
    app.clipboard()
        .write_text(token)
        .map_err(|error| error.to_string())?;
    state.broker.audit.append(aka_core::audit::AuditEntry::new(
        aka_core::audit::AuditKind::SecretCopied,
        "Shared key copied".to_string(),
    ));
    Ok(())
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
pub fn set_show_websockets(state: State<AppState>, on: bool) -> CmdResult<()> {
    state
        .broker
        .ui_set_show_websockets(on)
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
pub fn set_presence_window(state: State<AppState>, secs: u64) -> CmdResult<()> {
    state
        .broker
        .ui_set_presence_window(secs)
        .map_err(|e| e.to_string())
}

/// Register every command with the Tauri builder.
pub fn handler() -> impl Fn(tauri::ipc::Invoke<tauri::Wry>) -> bool + Send + Sync + 'static {
    tauri::generate_handler![
        get_local_username,
        list_secrets,
        list_connections,
        get_identity,
        list_sessions,
        list_activity,
        clear_activity,
        get_settings,
        get_agent_setup,
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
        test_connection_draft,
        start_mcp_auth,
        get_mcp_auth,
        cancel_mcp_auth,
        mcp_status,
        open_url,
        oauth_connect,
        oauth_reconnect,
        set_tool_access,
        set_allowed_tools,
        list_mcp_tools,
        issue_endpoint,
        revoke_endpoint,
        rotate_key,
        copy_key,
        close_session,
        set_reauth_on_read,
        set_show_websockets,
        set_menu_bar_hides_dock,
        set_presence_window,
        crate::windows::ui_set_mode,
        crate::windows::ui_hide_main,
        crate::windows::ui_hide_dropdown,
        crate::windows::ui_set_dropdown_form_active,
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

    /// A minimal API input the MCP tests vary one field of.
    fn api_input() -> ConnectionInput {
        ConnectionInput {
            mcp_path: None,
            name: "notion".into(),
            kind: "api".into(),
            host: Some("mcp.notion.com".into()),
            scheme: Some("https".into()),
            port: None,
            template: Some("Authorization: Bearer {{TOKEN}}".into()),
            oauth_auth_url: None,
            oauth_token_url: None,
            oauth_client_id: None,
            oauth_scopes: None,
            oauth_extra_params: None,
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
    }

    #[test]
    fn an_mcp_path_round_trips_and_blank_means_absent() {
        let with_path = ConnectionInput {
            mcp_path: Some("/mcp".into()),
            ..api_input()
        };
        assert!(matches!(
            with_path.into_spec().unwrap().config,
            ConnectionConfig::Api { mcp_path: Some(path), .. } if path == "/mcp"
        ));

        // A blank field is absent, not an empty path: an empty string would
        // post JSON-RPC to the upstream's root.
        for blank in ["", "   "] {
            let input = ConnectionInput {
                mcp_path: Some(blank.into()),
                ..api_input()
            };
            assert!(matches!(
                input.into_spec().unwrap().config,
                ConnectionConfig::Api { mcp_path: None, .. }
            ));
        }
    }

    #[test]
    fn connection_input_preserves_api_origin_and_ws_template() {
        let api = ConnectionInput {
            mcp_path: None,
            name: "local-api".into(),
            kind: "api".into(),
            host: Some("localhost".into()),
            scheme: Some("http".into()),
            port: Some(8080),
            template: Some("Authorization: Bearer {{TOKEN}}".into()),
            oauth_auth_url: None,
            oauth_token_url: None,
            oauth_client_id: None,
            oauth_scopes: None,
            oauth_extra_params: None,
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
            mcp_path: None,
            name: "stream".into(),
            kind: "ws".into(),
            host: None,
            scheme: None,
            port: None,
            template: Some("X-Stream-Key: {{STREAM_TOKEN}}".into()),
            oauth_auth_url: None,
            oauth_token_url: None,
            oauth_client_id: None,
            oauth_scopes: None,
            oauth_extra_params: None,
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
    fn agent_setup_instructions_include_the_runtime_paths() {
        let instructions = agent_setup_instructions("/tmp/aka-test.sock", "~/.aka/token");
        assert!(instructions.contains("curl -fsS"));
        assert!(instructions.contains("--unix-socket /tmp/aka-test.sock"));
        assert!(instructions.contains("Read its current instructions"));
        assert!(instructions.contains("~/.aka/token"));
        assert!(instructions.contains("Authorization: Bearer"));
        assert!(!instructions.contains("\\\n"));
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
                "message": "That tool name is already in use"
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
