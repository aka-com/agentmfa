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
//!
//! Every command reaches the broker through the [`ManagementBackend`]
//! seam: in local mode that is the in-process broker, in remote mode an
//! HTTP client against a hosted broker's manage API. The webview cannot
//! tell the difference.

use std::sync::Arc;

use aka_api::{IssuedEndpointDto, ManageError};
use aka_core::store::ConnectionSpec;
use aka_core::types::{ConnectionConfig, PgSslMode};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter as _, Manager as _, State};
use tauri_plugin_clipboard_manager::ClipboardExt as _;
use uuid::Uuid;
use zeroize::Zeroizing;

/// The in-process broker stack backing local mode. Dropping it stops the
/// sidecar, the daemon listeners, and finally the runtime, in that order.
pub struct LocalRuntime {
    pub broker: Arc<aka_core::broker::Broker>,
    // Keeps the Node sidecar supervised; dropping it kills the process and
    // stops restarting it. `None` when no sidecar script is installed.
    // Declared before the runtime it spawned its supervisor on.
    pub _sidecar: Option<aka_core::sidecar::Sidecar>,
    // Keeps the daemon (control plane + PG data plane) alive; dropping
    // it aborts the listeners.
    pub _daemon: aka_core::daemon::DaemonHandle,
    // Keeps the broker's tokio runtime (daemon + executions) alive for the
    // life of the app. Dropped last (after `_daemon`).
    pub _runtime: tokio::runtime::Runtime,
}

pub struct AppState {
    /// The mode-switchable broker seam every command goes through.
    pub brokers: Arc<crate::broker_mode::BrokerState>,
    pub ssh_imports: std::sync::Mutex<crate::ssh_import::ImportCache>,
}

type CmdResult<T> = Result<T, String>;
type FormResult<T> = Result<T, FormError>;
/// Ceiling on how much of the log one view read may pull across the IPC. The
/// activity list windows its rows, so the cost of a larger tail is the read
/// and the retained entries, not the DOM.
const ACTIVITY_VIEW_LIMIT: usize = 500;
pub const EVT_NOTIFICATION_SETTINGS: &str = "aka://notification-settings-changed";
pub const EVT_SETTINGS: &str = "aka://settings-changed";

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

/// Which broker this app is managing (local vs remote), its link state,
/// and whether a token is saved — the header switcher and takeover panes
/// render from this.
#[tauri::command]
pub fn get_broker_profile(state: State<AppState>) -> crate::broker_mode::BrokerProfileInfo {
    state.brokers.profile()
}

/// Connect to (and switch to) a remote broker. A missing token reuses the
/// saved one for that URL. Errors are messages for the connect form;
/// nothing changes on failure.
#[tauri::command]
pub async fn connect_remote_broker(
    app: AppHandle,
    state: State<'_, AppState>,
    url: String,
    token: Option<String>,
) -> Result<crate::broker_mode::BrokerProfileInfo, String> {
    state.brokers.connect_remote(&app, url, token).await
}

/// Re-attempt the saved remote connection (the error pane's Retry).
#[tauri::command]
pub async fn retry_remote_broker(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<crate::broker_mode::BrokerProfileInfo, String> {
    state.brokers.retry_remote(&app).await
}

/// Switch back to this Mac's local broker, starting it if needed.
#[tauri::command]
pub async fn switch_broker_local(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<crate::broker_mode::BrokerProfileInfo, String> {
    state.brokers.switch_local(&app).await
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

    fn from_manage(error: ManageError, context: FormContext<'_>) -> Self {
        use aka_api::ConnectionField;
        match error {
            ManageError::SecretNameTaken { .. } => {
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
            ManageError::ConnectionNameTaken { .. } => Self::validation(
                "connection_name_taken",
                "name",
                "That tool name is already in use",
            )
            .with_kind("conflict"),
            ManageError::ConnectionTargetTaken { name } => Self::validation(
                "connection_target_taken",
                "name",
                format!("An equivalent target is already saved as {name}"),
            )
            .with_kind("conflict"),
            ManageError::InvalidSecretName { .. } => {
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
            ManageError::InvalidConnectionName { .. } => Self::validation(
                "invalid_connection_name",
                "name",
                "Use 1–64 letters, numbers, spaces, or endpoint punctuation; start with a letter or number and don’t end with a space",
            ),
            ManageError::Template { message } => Self::validation(
                "invalid_template",
                "template",
                format!("Invalid template: {message}"),
            ),
            ManageError::UnknownTemplateRef { name } => Self::validation(
                "unknown_template_credential",
                "template",
                format!("{name} is not a saved credential"),
            ),
            ManageError::WrongSecretCount { kind } => {
                Self::validation(
                    "wrong_credential_count",
                    "secret",
                    format!("{kind} tools require exactly one saved credential"),
                )
            }
            ManageError::SecretNotFound => match context {
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
            ManageError::InvalidConnectionField { field, message } => {
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
            ManageError::InvalidConnectionConfig { message } => {
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
            ManageError::NotConfirmed => {
                Self::global("cancelled", "not_confirmed", "Nothing was saved", None)
            }
            ManageError::KindChange => Self::global(
                "validation",
                "connection_kind_fixed",
                "Tool type cannot be changed after creation",
                None,
            ),
            ManageError::ConnectionNotFound => Self::global(
                "conflict",
                "connection_not_found",
                "This tool was removed elsewhere",
                None,
            ),
            ManageError::EndpointRequiresWiring => Self::global(
                "conflict",
                "endpoint_requires_wiring",
                "Enable this tool for agents before issuing a direct endpoint",
                None,
            ),
            ManageError::EndpointLimit { max } => Self::global(
                "conflict",
                "endpoint_limit",
                format!("This broker already has its limit of {max} direct endpoints"),
                Some("Revoke an existing endpoint, then try again.".into()),
            ),
            ManageError::ApprovalConnectionChanged => Self::global(
                "conflict",
                "connection_changed",
                "The tool changed while you were confirming. Review it and save again.",
                None,
            ),
            ManageError::ConnectionChanged => Self::global(
                "conflict",
                "connection_changed",
                "This tool changed elsewhere. Review the latest settings and try again.",
                None,
            ),
            ManageError::Vault { message } => Self::global(
                "system",
                "keychain_unavailable",
                "Couldn’t save to macOS Keychain",
                Some(message),
            ),
            ManageError::RemoteUnsupported { feature } => Self::global(
                "system",
                "remote_unsupported",
                format!("{feature} isn’t available for a remote broker yet"),
                None,
            ),
            ManageError::InvalidManageToken { detail } => Self::global(
                "system",
                "invalid_manage_token",
                "The broker rejected the management token — re-enter it from `mfa manage token`",
                detail,
            ),
            ManageError::Unreachable { message } => Self::global(
                "system",
                "broker_unreachable",
                "Couldn’t reach the remote broker",
                Some(message),
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
pub async fn list_secrets(state: State<'_, AppState>) -> CmdResult<Vec<aka_api::SecretDto>> {
    state
        .brokers
        .backend()
        .list_secrets()
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn list_connections(
    state: State<'_, AppState>,
) -> CmdResult<Vec<aka_api::ConnectionDto>> {
    state
        .brokers
        .backend()
        .list_connections()
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_identity(state: State<'_, AppState>) -> CmdResult<aka_api::IdentityDto> {
    state
        .brokers
        .backend()
        .identity()
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn list_sessions(state: State<'_, AppState>) -> CmdResult<Vec<aka_api::SessionDto>> {
    state
        .brokers
        .backend()
        .sessions()
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn list_activity(
    state: State<'_, AppState>,
    limit: Option<usize>,
    before: Option<u64>,
) -> CmdResult<aka_api::ActivityPageDto> {
    let limit = activity_view_limit(limit);
    state
        .brokers
        .backend()
        .activity_page(limit, before)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn clear_activity(app: AppHandle, state: State<'_, AppState>) -> CmdResult<()> {
    state
        .brokers
        .backend()
        .clear_activity()
        .await
        .map_err(|e| e.to_string())?;
    let _ = app.emit(crate::events::EVT_ACTIVITY_CHANGED, ());
    Ok(())
}

#[tauri::command]
pub async fn get_settings(state: State<'_, AppState>) -> CmdResult<aka_api::SettingsDto> {
    state
        .brokers
        .backend()
        .settings()
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_agent_setup(state: State<'_, AppState>) -> CmdResult<String> {
    state
        .brokers
        .backend()
        .agent_setup()
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn copy_agent_setup(app: AppHandle, state: State<'_, AppState>) -> CmdResult<()> {
    let instructions = state
        .brokers
        .backend()
        .agent_setup()
        .await
        .map_err(|e| e.to_string())?;
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
) -> CmdResult<crate::ssh_import::KnownHostsLookup> {
    tokio::task::spawn_blocking(move || crate::ssh_import::known_hosts_lookup(&host, port))
        .await
        .map_err(|error| format!("known_hosts lookup stopped: {error}"))?
}

/* ------------------------------ secrets ---------------------------------- */

#[tauri::command]
pub async fn add_secret(state: State<'_, AppState>, name: String, value: String) -> FormResult<()> {
    state
        .brokers
        .backend()
        .add_secret(name, Zeroizing::new(value))
        .await
        .map_err(|error| FormError::from_manage(error, FormContext::Secret))
}

#[tauri::command]
pub async fn edit_secret(
    state: State<'_, AppState>,
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
        .brokers
        .backend()
        .edit_secret(id, new_name, value)
        .await
        .map_err(|error| FormError::from_manage(error, FormContext::Secret))
}

#[tauri::command]
pub async fn delete_secret(state: State<'_, AppState>, id: String) -> CmdResult<()> {
    let id = parse_id(&id)?;
    // The core refuses in-use deletion; the UI's inline confirm is the gate.
    state
        .brokers
        .backend()
        .delete_secret(id)
        .await
        .map_err(|e| e.to_string())
}

/// Audited, core-side Keychain read returning only the short prefix.
#[tauri::command]
pub async fn reveal_secret_prefix(state: State<'_, AppState>, id: String) -> CmdResult<String> {
    let id = parse_id(&id)?;
    state
        .brokers
        .backend()
        .reveal_secret_prefix(id)
        .await
        .map_err(|e| e.to_string())
}

/// Core-side copy: reads the value in the core, writes it straight to the
/// clipboard with hygiene, audits *that* a copy happened, never the value.
/// The value never re-enters the webview.
#[tauri::command]
pub async fn copy_secret(app: AppHandle, state: State<'_, AppState>, id: String) -> CmdResult<()> {
    let id = parse_id(&id)?;
    let value = state
        .brokers
        .backend()
        .secret_value_for_copy(id)
        .await
        .map_err(|e| e.to_string())?;
    crate::clipboard::copy_with_hygiene(&app, value)?;
    state
        .brokers
        .backend()
        .note_secret_copied(id)
        .await
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
    /// The path the Test button probes instead of the origin root.
    pub test_path: Option<String>,
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
    // pg/ssh single-secret binding (by id)
    pub secret_id: Option<String>,
    // Add-only connection-first setup. Both fields must be present together;
    // the core writes the vault item and connection atomically.
    pub new_secret_name: Option<String>,
    pub new_secret_value: Option<String>,
    // SSH import-only: an opaque preview id and one identity path returned by
    // that preview. The backend verifies the binding before reading the file.
    pub ssh_import_id: Option<String>,
    pub identity_file: Option<String>,
    /// Passphrase for an encrypted SSH private key, whether typed in or read
    /// from an identity file. Used once, here, to decrypt before the vault
    /// seals the cleartext OpenSSH form — the vault is the protection boundary
    /// for a stored key, and re-prompting per signature is not on offer. Never
    /// stored, never echoed back.
    pub key_passphrase: Option<String>,
}

/// A key-import failure as a form error.
///
/// "Needs a passphrase" and "wrong passphrase" carry their own codes and point
/// at the passphrase field, so the form reveals it (or says the one given is
/// wrong) instead of showing a dead end on the credential field — which is what
/// "store the decrypted OpenSSH key" used to do.
fn ssh_identity_error(error: aka_core::capability::ssh::KeyImportError) -> FormError {
    use aka_core::capability::ssh::KeyImportError;
    let message = error.message();
    match error {
        KeyImportError::NeedsPassphrase => {
            FormError::validation("ssh_key_passphrase_required", "keyPassphrase", message)
        }
        KeyImportError::WrongPassphrase => {
            FormError::validation("ssh_key_passphrase_wrong", "keyPassphrase", message)
        }
        KeyImportError::Unusable(_) => {
            FormError::validation("invalid_ssh_identity", "newSecretValue", message)
        }
    }
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
                trusted_ca_bundle_path: self.trusted_ca_bundle_path.and_then(|path| {
                    let path = path.trim().to_string();
                    (!path.is_empty()).then_some(path)
                }),
                template: self.template.unwrap_or_default(),
                // Blank is treated as absent: an empty string here would
                // make the sidecar post JSON-RPC to the upstream's root.
                mcp_path: self
                    .mcp_path
                    .map(|path| path.trim().to_string())
                    .filter(|path| !path.is_empty()),
                // Blank means "not configured", so the probe falls back to
                // the MCP path and then the origin root.
                test_path: self
                    .test_path
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
                            token_secret_id: None,
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
pub async fn add_connection(
    state: State<'_, AppState>,
    mut input: ConnectionInput,
) -> FormResult<()> {
    let kind = input.kind.clone();
    let new_secret_name = input.new_secret_name.take();
    // Wrap the user-entered value before any fallible parsing below so every
    // error path zeroizes it rather than dropping an ordinary String.
    let mut new_secret_value = input.new_secret_value.take().map(Zeroizing::new);
    let key_passphrase = input.key_passphrase.take().map(Zeroizing::new);
    if kind == "ssh" {
        if let Some(value) = &new_secret_value {
            // Decrypt now rather than refusing: what the vault seals is the
            // cleartext OpenSSH form, so an encrypted key must not reach it.
            let stored = aka_core::capability::ssh::private_key_for_vault(
                value.as_bytes(),
                key_passphrase.as_ref().map(|p| p.as_str()),
            )
            .map_err(ssh_identity_error)?;
            new_secret_value = Some(stored);
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
                crate::ssh_import::load_identity(
                    &resolved,
                    path,
                    key_passphrase.as_ref().map(|p| p.as_str()),
                )
                .map_err(ssh_identity_error)?,
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
        (Some(name), Some(value)) if !name.is_empty() && !value.is_empty() => {
            state
                .brokers
                .backend()
                .add_connection_with_secret(name, value, spec)
                .await
        }
        (None, None) => state.brokers.backend().add_connection(spec).await,
        _ => {
            return Err(FormError::validation(
                "incomplete_new_credential",
                "newSecretValue",
                "Credential name and value must be provided together",
            ))
        }
    };
    result.map_err(|error| {
        FormError::from_manage(
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
pub async fn edit_connection(
    state: State<'_, AppState>,
    id: String,
    expected_updated_at: String,
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
        .brokers
        .backend()
        .update_connection(id, expected_updated_at, spec)
        .await
        .map_err(|error| {
            FormError::from_manage(
                error,
                FormContext::Connection {
                    kind: &kind,
                    includes_new_secret: false,
                },
            )
        })
}

#[tauri::command]
pub async fn delete_connection(state: State<'_, AppState>, id: String) -> CmdResult<()> {
    let id = parse_id(&id)?;
    state
        .brokers
        .backend()
        .delete_connection(id)
        .await
        .map_err(|e| e.to_string())
}

/// Persist the user's drag-reordered Tools list. `ordered_ids` is the full
/// front-to-back order; the broker is lenient about a list that raced an
/// add/delete in another window.
#[tauri::command]
pub async fn reorder_connections(
    state: State<'_, AppState>,
    ordered_ids: Vec<String>,
) -> CmdResult<()> {
    let ordered_ids = ordered_ids
        .iter()
        .map(|id| parse_id(id))
        .collect::<Result<Vec<_>, _>>()?;
    state
        .brokers
        .backend()
        .reorder_connections(ordered_ids)
        .await
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
        .brokers
        .backend()
        .test_connection(id)
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
        .brokers
        .backend()
        .test_connection_draft(spec, typed_secret)
        .await
        .map_err(|error| {
            FormError::from_manage(
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
pub async fn start_mcp_auth(
    state: State<'_, AppState>,
    input: aka_core::mcp_auth::McpAuthDraft,
) -> FormResult<aka_core::mcp_auth::McpAuthState> {
    state
        .brokers
        .backend()
        .start_mcp_auth(input)
        .await
        .map_err(|error| {
            FormError::from_manage(
                error,
                FormContext::Connection {
                    kind: "api",
                    includes_new_secret: true,
                },
            )
        })
}

#[tauri::command]
pub async fn get_mcp_auth(
    state: State<'_, AppState>,
    id: String,
) -> CmdResult<Option<aka_core::mcp_auth::McpAuthState>> {
    let id = parse_id(&id)?;
    state
        .brokers
        .backend()
        .get_mcp_auth(id)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn cancel_mcp_auth(state: State<'_, AppState>, id: String) -> CmdResult<bool> {
    let id = parse_id(&id)?;
    state
        .brokers
        .backend()
        .cancel_mcp_auth(id)
        .await
        .map_err(|e| e.to_string())
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
        .brokers
        .backend()
        .mcp_status(id, options.unwrap_or_default())
        .await
        .map_err(|e| e.to_string())
}

/// Open the sign-in URL in the system browser. Restricted to http(s) so
/// the webview cannot launch arbitrary schemes.
#[tauri::command]
pub fn open_url(url: String) -> CmdResult<()> {
    let url = url.trim().to_string();
    if !crate::events::allowed_external_url(&url) {
        return Err("only HTTPS or loopback HTTP URLs can be opened".into());
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
    let secret_name = suggested_oauth_secret_name(&state, &name).await;
    let mut input = input;
    // The token secret does not exist yet; the template is synthesized to
    // reference it (binding + display), while the upstream leg injects a
    // live bearer from the token set directly.
    input.template = Some(format!("Authorization: Bearer {{{{{secret_name}}}}}"));
    let kind = input.kind.clone();
    let spec = input.into_spec()?;
    state
        .brokers
        .backend()
        .oauth_connect(
            secret_name,
            client_secret
                .filter(|value| !value.trim().is_empty())
                .map(Zeroizing::new),
            spec,
        )
        .await
        .map_err(|error| {
            FormError::from_manage(
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
async fn suggested_oauth_secret_name(state: &State<'_, AppState>, connection_name: &str) -> String {
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
        .brokers
        .backend()
        .list_secrets()
        .await
        .unwrap_or_default()
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
        .brokers
        .backend()
        .oauth_reconnect(id)
        .await
        .map_err(|e| e.to_string())
}

/* ----------------------------- agent access -------------------------------- */

/// Enable or disable agent access for a connection. Editing this table is
/// the whole authorization model: enabled connections execute without
/// prompting, disabled ones are refused — for every local agent at once.
#[tauri::command]
pub async fn set_tool_access(
    state: State<'_, AppState>,
    connection_id: String,
    enabled: bool,
) -> CmdResult<bool> {
    let connection_id = parse_id(&connection_id)?;
    state
        .brokers
        .backend()
        .set_tool_access(connection_id, enabled)
        .await
        .map_err(|e| e.to_string())
}

/// Ask the user to confirm this connection's traffic — or stop asking.
///
/// Turning it on only adds friction, so the switch itself is the gate.
/// Turning it off removes one the user put up, so the broker demands a
/// native authentication before it applies.
#[tauri::command]
pub async fn set_confirm_mode(
    state: State<'_, AppState>,
    connection_id: String,
    on: bool,
) -> CmdResult<bool> {
    let connection_id = parse_id(&connection_id)?;
    state
        .brokers
        .backend()
        .set_confirm_mode(connection_id, on)
        .await
        .map_err(|e| e.to_string())
}

/// Explicitly allow or contain upstream cookies and authentication response
/// fields. The broker applies the fresh confirmation when this widens access.
#[tauri::command]
pub async fn set_expose_response_credentials(
    state: State<'_, AppState>,
    connection_id: String,
    expose: bool,
) -> CmdResult<bool> {
    let connection_id = parse_id(&connection_id)?;
    state
        .brokers
        .backend()
        .set_expose_response_credentials(connection_id, expose)
        .await
        .map_err(|e| e.to_string())
}

/// Traffic parked on the user right now, oldest first.
#[tauri::command]
pub async fn list_approvals(state: State<'_, AppState>) -> CmdResult<Vec<aka_api::ApprovalDto>> {
    state
        .brokers
        .backend()
        .approvals()
        .await
        .map_err(|e| e.to_string())
}

/// Request decision lifecycles, including the bounded terminal history.
#[tauri::command]
pub async fn list_requests(state: State<'_, AppState>) -> CmdResult<Vec<aka_api::RequestDto>> {
    state
        .brokers
        .backend()
        .requests()
        .await
        .map_err(|e| e.to_string())
}

/// Answer one prompt. `false` means it was already answered, revoked, or
/// lapsed while the window was open — the UI drops it either way.
///
/// The decision is the webview's to *request*: "approve all" turns the
/// connection's switch off, and the broker runs its own native
/// authentication before applying that, exactly as it does for every other
/// gate the user removes.
#[tauri::command]
pub async fn respond_approval(
    state: State<'_, AppState>,
    id: String,
    decision: aka_api::ApprovalDecisionDto,
) -> CmdResult<bool> {
    let id = parse_id(&id)?;
    state
        .brokers
        .backend()
        .respond_approval(id, decision)
        .await
        .map_err(|e| e.to_string())
}

/// Upstream MCP tool calls parked on the user for input, oldest first. The
/// agent whose call is paused never sees these.
#[tauri::command]
pub async fn list_elicitations(
    state: State<'_, AppState>,
) -> CmdResult<Vec<aka_api::ElicitationDto>> {
    state
        .brokers
        .backend()
        .elicitations()
        .await
        .map_err(|e| e.to_string())
}

/// Answer one elicitation. `approved` with `values` accepts and sends them
/// upstream; otherwise it declines. `false` means it was already answered,
/// cancelled, or lapsed.
#[tauri::command]
pub async fn respond_elicitation(
    state: State<'_, AppState>,
    id: String,
    approved: bool,
    values: Option<std::collections::HashMap<String, String>>,
) -> CmdResult<bool> {
    let id = parse_id(&id)?;
    state
        .brokers
        .backend()
        .respond_elicitation(id, approved, values.unwrap_or_default())
        .await
        .map_err(|e| e.to_string())
}

/// Curate which upstream MCP tools agents may call on a connection. `null`
/// restores the default (all tools). Enforced broker-side on every
/// `tools/call`; the sidecar's tool listing mirrors it.
#[tauri::command]
pub async fn set_allowed_tools(
    state: State<'_, AppState>,
    connection_id: String,
    tools: Option<Vec<String>>,
) -> CmdResult<bool> {
    let connection_id = parse_id(&connection_id)?;
    state
        .brokers
        .backend()
        .set_allowed_tools(connection_id, tools)
        .await
        .map_err(|e| e.to_string())
}

/// Record this Postgres connection's statement text in the activity log, or
/// stop; `null` restores the broker-wide default.
///
/// Ungated in both directions: turning it on records the user's own traffic
/// rather than granting an agent anything, and turning it off narrows what a
/// durable log retains.
#[tauri::command]
pub async fn set_audit_statements(
    state: State<'_, AppState>,
    connection_id: String,
    audit_statements: Option<bool>,
) -> CmdResult<bool> {
    let connection_id = parse_id(&connection_id)?;
    state
        .brokers
        .backend()
        .set_audit_statements(connection_id, audit_statements)
        .await
        .map_err(|e| e.to_string())
}

/// Require (or stop requiring) the `authenticate@agentmfa.dev` extension on an
/// SSH endpoint's agent socket.
///
/// Gating is asymmetric and lives in the broker: turning it on only narrows,
/// while turning it off widens who may sign with a standing credential and
/// takes a fresh authentication there.
#[tauri::command]
pub async fn set_endpoint_require_auth(
    state: State<'_, AppState>,
    connection_id: String,
    require_auth: bool,
) -> CmdResult<bool> {
    let connection_id = parse_id(&connection_id)?;
    state
        .brokers
        .backend()
        .set_endpoint_require_auth(connection_id, require_auth)
        .await
        .map_err(|e| e.to_string())
}

/// List an MCP connection's upstream tools (names + descriptions), for the
/// per-wiring tool picker. Read-only against the upstream.
#[tauri::command]
pub async fn list_mcp_tools(
    state: State<'_, AppState>,
    id: String,
) -> CmdResult<aka_core::mcp::McpToolCatalog> {
    let id = parse_id(&id)?;
    state
        .brokers
        .backend()
        .list_mcp_tools(id)
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
        .brokers
        .backend()
        .issue_endpoint(connection_id)
        .await
        .map_err(|e| e.to_string())
}

/// Renew a direct endpoint without rotating its address or secret. The broker
/// performs the native confirmation because this extends standing access.
#[tauri::command]
pub async fn renew_endpoint(
    state: State<'_, AppState>,
    connection_id: String,
) -> CmdResult<IssuedEndpointDto> {
    let connection_id = parse_id(&connection_id)?;
    state
        .brokers
        .backend()
        .renew_endpoint(connection_id)
        .await
        .map_err(|e| e.to_string())
}

/// Read a connection's already-issued direct endpoint (address, retained
/// secret, example) without minting or rotating; `None` when none is issued.
/// This is an ungated display read used by list refreshes. Credential-bearing
/// copies use `copy_endpoint_text`, which carries the native gate and audit
/// boundary instead of relying on this display read as authorization.
#[tauri::command]
pub async fn get_endpoint(
    state: State<'_, AppState>,
    connection_id: String,
) -> CmdResult<Option<IssuedEndpointDto>> {
    let connection_id = parse_id(&connection_id)?;
    state
        .brokers
        .backend()
        .get_endpoint(connection_id)
        .await
        .map_err(|e| e.to_string())
}

/// Copy a direct-endpoint rendering without sending the credential-bearing
/// text through the webview. `format` is a small, closed vocabulary shared
/// with the UI's copy buttons.
#[tauri::command]
pub async fn copy_endpoint_text(
    app: AppHandle,
    state: State<'_, AppState>,
    connection_id: String,
    format: String,
    task_body: Option<String>,
) -> CmdResult<()> {
    let connection_id = parse_id(&connection_id)?;
    let backend = state.brokers.backend();
    // The copy path takes the gate and writes the "Direct endpoint copied"
    // audit entry; the ungated `get_endpoint` backs display only.
    let endpoint = backend
        .copy_endpoint(connection_id)
        .await
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "this tool has no direct endpoint".to_string())?;
    let connection = backend
        .list_connections()
        .await
        .map_err(|error| error.to_string())?
        .into_iter()
        .find(|connection| connection.id == connection_id.to_string())
        .ok_or_else(|| "this tool no longer exists".to_string())?;
    let text = endpoint_copy_text(&connection, &endpoint, &format, task_body.as_deref())?;
    crate::clipboard::copy_with_hygiene(&app, Zeroizing::new(text))
}

fn endpoint_copy_text(
    connection: &aka_api::ConnectionDto,
    endpoint: &IssuedEndpointDto,
    format: &str,
    task_body: Option<&str>,
) -> CmdResult<String> {
    match (endpoint.kind.as_str(), format) {
        ("pg", "first-task") => endpoint_first_task(endpoint, task_body),
        ("ssh", "first-task") => endpoint_first_task(endpoint, task_body),
        ("pg", "direct" | "dsn") => Ok(endpoint.dsn.clone()),
        ("pg", "example" | "env") => Ok(format!("DATABASE_URL=\"{}\"", endpoint.dsn)),
        ("pg", "psql") => Ok(format!("psql {}", shell_quoted(&endpoint.dsn))),
        ("pg", "libpq") => pg_libpq_keywords(&endpoint.dsn)
            .ok_or_else(|| "could not render this Postgres endpoint".into()),
        ("pg", "tcp") => endpoint
            .tcp_dsn
            .clone()
            .ok_or_else(|| "this endpoint has no TCP address".into()),
        ("ssh", "direct" | "example" | "ssh") => Ok(endpoint.example.clone()),
        ("ssh", "dsn") => Ok(endpoint.dsn.clone()),
        ("ssh", "scp") => Ok(ssh_scp_command(connection, &endpoint.dsn)),
        ("ssh", "ssh-config") => ssh_config_block(connection, &endpoint.dsn)
            .ok_or_else(|| "this SSH tool has no usable destination".into()),
        ("api", "direct" | "dsn") => Ok(endpoint.dsn.clone()),
        ("api", "secret") => Ok(endpoint.secret.clone()),
        ("api", "example" | "curl") => Ok(format!(
            "curl -H \"Authorization: Bearer {}\" {}/",
            endpoint.secret,
            endpoint.dsn.trim_end_matches('/')
        )),
        ("api", "env") => Ok(format!(
            "API_BASE_URL={}\nAPI_TOKEN={}",
            endpoint.dsn, endpoint.secret
        )),
        (_, "secret") => Ok(endpoint.secret.clone()),
        (_, _) => Err("unknown endpoint copy format".into()),
    }
}

fn endpoint_first_task(endpoint: &IssuedEndpointDto, task_body: Option<&str>) -> CmdResult<String> {
    let task = task_body
        .map(str::trim)
        .filter(|task| !task.is_empty() && task.chars().count() <= 2_000)
        .ok_or_else(|| "the first task is missing or too long".to_string())?;
    match endpoint.kind.as_str() {
        "pg" => Ok(format!(
            "Connect to this Postgres DSN: {}\n\nThen {task}",
            endpoint.dsn
        )),
        "ssh" => Ok(format!(
            "Use this SSH endpoint: {}\n\nThen {task}",
            endpoint.example
        )),
        _ => Err("this endpoint type has no direct first task".into()),
    }
}

fn shell_quoted(value: &str) -> String {
    let escaped = value.chars().fold(String::new(), |mut escaped, character| {
        if matches!(character, '\\' | '"' | '`' | '$') {
            escaped.push('\\');
        }
        escaped.push(character);
        escaped
    });
    format!("\"{escaped}\"")
}

fn ssh_destination(connection: &aka_api::ConnectionDto) -> Option<String> {
    connection
        .destination
        .as_deref()
        .map(str::trim)
        .filter(|destination| !destination.is_empty())
        .map(str::to_string)
        .or_else(|| match (&connection.user, &connection.host) {
            (Some(user), Some(host)) => Some(format!("{user}@{host}")),
            _ if !connection.target.trim().is_empty() => Some(connection.target.clone()),
            _ => None,
        })
}

fn ssh_flags() -> String {
    aka_core::capability::ssh::SSH_BROKER_OPTIONS
        .iter()
        .map(|option| format!("-o {option}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Whether this connection's agent socket refuses callers that have not
/// presented the endpoint secret. Such a socket cannot be named directly in
/// `SSH_AUTH_SOCK` or `IdentityAgent` — stock `ssh` has no way to send the
/// extension — so every copied form has to route through the forwarder.
fn endpoint_requires_auth(connection: &aka_api::ConnectionDto) -> bool {
    connection
        .agent_access
        .endpoint
        .as_ref()
        .is_some_and(|endpoint| endpoint.require_auth)
}

fn ssh_scp_command(connection: &aka_api::ConnectionDto, socket: &str) -> String {
    let destination = ssh_destination(connection).unwrap_or_else(|| connection.target.clone());
    let port = connection
        .port
        .filter(|port| *port != 22)
        .map(|port| format!(" -P {port}"))
        .unwrap_or_default();
    if endpoint_requires_auth(connection) {
        return format!(
            "mfa ssh-agent {} -- scp{port} {} <file> {destination}:",
            shell_quoted(&connection.name),
            ssh_flags()
        );
    }
    format!(
        "SSH_AUTH_SOCK={} scp{port} {} <file> {destination}:",
        shell_quoted(socket),
        ssh_flags()
    )
}

fn ssh_config_block(connection: &aka_api::ConnectionDto, socket: &str) -> Option<String> {
    let destination;
    let (user, host) = if let Some(host) = connection.host.as_deref() {
        (connection.user.as_deref(), host)
    } else {
        destination = ssh_destination(connection)?;
        destination
            .rsplit_once('@')
            .map_or((None, destination.as_str()), |(user, host)| {
                (Some(user), host)
            })
    };
    let alias = connection
        .name
        .split_whitespace()
        .collect::<Vec<_>>()
        .join("-");
    let mut lines = vec![format!("Host {alias}"), format!("  HostName {host}")];
    if let Some(port) = connection.port.filter(|port| *port != 22) {
        lines.push(format!("  Port {port}"));
    }
    if let Some(user) = user {
        lines.push(format!("  User {user}"));
    }
    // `IdentityAgent` names a path, never a command, so an authenticated
    // endpoint needs a forwarder already listening somewhere stable. The
    // comment is the missing half of the block: without it the config is
    // syntactically fine and silently signs nothing.
    if endpoint_requires_auth(connection) {
        let forwarder = format!("~/.ssh/agentmfa-{alias}.sock");
        lines.insert(
            0,
            format!(
                "# Needs a forwarder running: mfa ssh-agent {} --socket {forwarder}",
                shell_quoted(&connection.name)
            ),
        );
        lines.push(format!("  IdentityAgent {}", shell_quoted(&forwarder)));
    } else {
        lines.push(format!("  IdentityAgent {}", shell_quoted(socket)));
    }
    lines.extend(
        aka_core::capability::ssh::SSH_BROKER_OPTIONS
            .iter()
            .map(|option| {
                let (key, value) = option.split_once('=').unwrap_or((option, ""));
                format!("  {key} {value}")
            }),
    );
    Some(lines.join("\n"))
}

fn pg_libpq_keywords(dsn: &str) -> Option<String> {
    let body = dsn
        .strip_prefix("postgresql://")
        .or_else(|| dsn.strip_prefix("postgres://"))?;
    let (body, raw_query) = body.split_once('?').unwrap_or((body, ""));
    let (auth, target) = body.rsplit_once('@').unwrap_or(("", body));
    let (authority, dbname) = target.split_once('/').unwrap_or((target, ""));
    let (user, password) = auth.split_once(':').unwrap_or((auth, ""));
    let (authority_host, authority_port) = if let Some(bracketed) = authority.strip_prefix('[') {
        let (host, suffix) = bracketed.split_once(']')?;
        (host, suffix.strip_prefix(':').unwrap_or(""))
    } else if let Some((host, port)) = authority.rsplit_once(':') {
        (host, port)
    } else {
        (authority, "")
    };
    let query = url::form_urlencoded::parse(raw_query.as_bytes()).collect::<Vec<_>>();
    let query_value = |wanted: &str| {
        query
            .iter()
            .find(|(key, _)| key == wanted)
            .map(|(_, value)| value.to_string())
    };
    let mut pairs = Vec::<(String, String)>::new();
    let mut put = |key: &str, value: Option<String>| {
        if let Some(value) = value.filter(|value| !value.is_empty()) {
            pairs.push((key.to_string(), value));
        }
    };
    put(
        "host",
        query_value("host").or_else(|| Some(authority_host.to_string())),
    );
    put(
        "port",
        query_value("port").or_else(|| Some(authority_port.to_string())),
    );
    put("dbname", Some(decode_url_component(dbname)));
    put("user", Some(decode_url_component(user)));
    put("password", Some(decode_url_component(password)));
    for (key, value) in query {
        if key != "host" && key != "port" {
            put(&key, Some(value.into_owned()));
        }
    }
    Some(
        pairs
            .into_iter()
            .map(|(key, value)| format!("{key}={}", libpq_value(&value)))
            .collect::<Vec<_>>()
            .join(" "),
    )
}

fn decode_url_component(value: &str) -> String {
    // `form_urlencoded` applies HTML-form semantics, where `+` decodes to a
    // space — wrong for a URI userinfo/path component, where `+` is a literal
    // (a PG role or database named `report+ro` would become `report ro` and
    // fail to authenticate). Protect `+` as its escape before decoding so only
    // true percent-escapes are expanded.
    let protected = value.replace('+', "%2B");
    let encoded = format!("value={protected}");
    url::form_urlencoded::parse(encoded.as_bytes())
        .next()
        .map(|(_, value)| value.into_owned())
        .unwrap_or_else(|| value.to_string())
}

fn libpq_value(value: &str) -> String {
    if value
        .chars()
        .any(|character| character.is_whitespace() || matches!(character, '\'' | '\\'))
    {
        let escaped = value.chars().fold(String::new(), |mut escaped, character| {
            if matches!(character, '\\' | '\'') {
                escaped.push('\\');
            }
            escaped.push(character);
            escaped
        });
        format!("'{escaped}'")
    } else {
        value.to_string()
    }
}

/// Revoke a direct endpoint: stop its listener and close its live sessions.
#[tauri::command]
pub async fn revoke_endpoint(state: State<'_, AppState>, endpoint_id: String) -> CmdResult<bool> {
    let endpoint_id = parse_id(&endpoint_id)?;
    state
        .brokers
        .backend()
        .revoke_endpoint(endpoint_id)
        .await
        .map_err(|e| e.to_string())
}

/* ---------------------------- shared identity ----------------------------- */

/// Rotate this computer's key. The broker gates this behind the native
/// confirmation; every agent disconnects and re-reads the token file.
#[tauri::command]
pub async fn rotate_key(state: State<'_, AppState>) -> CmdResult<()> {
    // The backend keeps the blocking native sheet off the async runtime.
    state
        .brokers
        .backend()
        .rotate_key()
        .await
        .map_err(|e| e.to_string())
}

/// Copy the shared key to the clipboard. The key never enters the webview:
/// the clipboard write happens here, like a secret copy. Most setups never
/// need it — agents read the token file themselves.
#[tauri::command]
pub async fn copy_key(app: AppHandle, state: State<'_, AppState>) -> CmdResult<()> {
    let token = state
        .brokers
        .backend()
        .agent_key()
        .await
        .map_err(|e| e.to_string())?;
    crate::clipboard::copy_with_hygiene(&app, Zeroizing::new(token))
}

/* ------------------------------ sessions --------------------------------- */

#[tauri::command]
pub async fn close_session(state: State<'_, AppState>, id: u64) -> CmdResult<bool> {
    state
        .brokers
        .backend()
        .close_session(id)
        .await
        .map_err(|e| e.to_string())
}

/* ------------------------------ settings --------------------------------- */

#[tauri::command]
pub async fn set_reauth_on_read(
    app: AppHandle,
    state: State<'_, AppState>,
    on: bool,
) -> CmdResult<()> {
    state
        .brokers
        .backend()
        .set_reauth_on_read(on)
        .await
        .map_err(|e| e.to_string())?;
    let _ = app.emit(EVT_SETTINGS, ());
    Ok(())
}

#[tauri::command]
pub async fn set_menu_bar_hides_dock(
    app: AppHandle,
    state: State<'_, AppState>,
    on: bool,
) -> CmdResult<()> {
    state
        .brokers
        .backend()
        .set_menu_bar_hides_dock(on)
        .await
        .map_err(|e| e.to_string())?;
    let _ = app.emit(EVT_SETTINGS, ());
    Ok(())
}

/// Ask before trusting a first-seen SSH host key. Turning it off weakens a
/// gate the user put up, so the core authenticates before it applies.
#[tauri::command]
pub async fn set_confirm_ssh_host_keys(
    app: AppHandle,
    state: State<'_, AppState>,
    on: bool,
) -> CmdResult<()> {
    state
        .brokers
        .backend()
        .set_confirm_ssh_host_keys(on)
        .await
        .map_err(|e| e.to_string())?;
    let _ = app.emit(EVT_SETTINGS, ());
    Ok(())
}

#[tauri::command]
pub async fn set_presence_window(
    app: AppHandle,
    state: State<'_, AppState>,
    secs: u64,
) -> CmdResult<()> {
    state
        .brokers
        .backend()
        .set_presence_window(secs)
        .await
        .map_err(|e| e.to_string())?;
    let _ = app.emit(EVT_SETTINGS, ());
    Ok(())
}

/// This desktop's native request-notification preferences. They live beside
/// the local/remote shell choice, never on the managed broker.
#[tauri::command]
pub fn get_notification_settings(
    app: AppHandle,
    state: State<'_, AppState>,
) -> crate::attention::NotificationSettingsView {
    let settings = state.brokers.notification_settings();
    app.try_state::<crate::attention::RequestAttention>()
        .map(|attention| attention.settings_view())
        .unwrap_or(crate::attention::NotificationSettingsView {
            mode: settings.mode,
            show_context: settings.show_context,
            play_sound: settings.play_sound,
            time_sensitive: settings.time_sensitive,
            escalation_secs: settings.escalation_secs,
            available: false,
            unavailable_reason: Some("notification coordinator is unavailable".into()),
            can_open_system_settings: cfg!(target_os = "macos"),
        })
}

#[tauri::command]
pub fn set_notification_settings(
    app: AppHandle,
    state: State<'_, AppState>,
    settings: crate::broker_mode::NotificationSettings,
) -> CmdResult<crate::attention::NotificationSettingsView> {
    let saved = state.brokers.set_notification_settings(settings)?;
    let view = if let Some(attention) = app.try_state::<crate::attention::RequestAttention>() {
        attention.set_settings(&app, saved);
        attention.settings_view()
    } else {
        crate::attention::NotificationSettingsView {
            mode: saved.mode,
            show_context: saved.show_context,
            play_sound: saved.play_sound,
            time_sensitive: saved.time_sensitive,
            escalation_secs: saved.escalation_secs,
            available: false,
            unavailable_reason: Some("notification coordinator is unavailable".into()),
            can_open_system_settings: cfg!(target_os = "macos"),
        }
    };
    let _ = app.emit(EVT_NOTIFICATION_SETTINGS, view.clone());
    Ok(view)
}

/// Open the operating system's notification settings. This is a fixed,
/// user-invoked destination rather than the general URL launcher, whose
/// scheme allowlist deliberately excludes system-preference links.
#[tauri::command]
pub fn open_notification_settings() -> CmdResult<()> {
    #[cfg(target_os = "macos")]
    {
        return std::process::Command::new("open")
            .arg("x-apple.systempreferences:com.apple.Notifications-Settings.extension")
            .spawn()
            .map(|_| ())
            .map_err(|error| format!("could not open notification settings: {error}"));
    }
    #[cfg(not(target_os = "macos"))]
    Err("opening notification settings is not supported on this platform".into())
}

/// Register every command with the Tauri builder.
pub fn handler() -> impl Fn(tauri::ipc::Invoke<tauri::Wry>) -> bool + Send + Sync + 'static {
    tauri::generate_handler![
        get_local_username,
        get_broker_profile,
        connect_remote_broker,
        retry_remote_broker,
        switch_broker_local,
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
        reorder_connections,
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
        set_confirm_mode,
        set_expose_response_credentials,
        list_approvals,
        list_requests,
        respond_approval,
        list_elicitations,
        respond_elicitation,
        set_allowed_tools,
        set_audit_statements,
        set_endpoint_require_auth,
        list_mcp_tools,
        issue_endpoint,
        renew_endpoint,
        get_endpoint,
        copy_endpoint_text,
        revoke_endpoint,
        rotate_key,
        copy_key,
        close_session,
        set_reauth_on_read,
        set_menu_bar_hides_dock,
        set_confirm_ssh_host_keys,
        set_presence_window,
        get_notification_settings,
        set_notification_settings,
        open_notification_settings,
        crate::windows::ui_set_mode,
        crate::windows::ui_hide_main,
        crate::windows::ui_hide_dropdown,
        crate::windows::ui_set_dropdown_form_active,
        crate::windows::ui_set_request_inbox_visible,
        crate::windows::ui_take_open_requests,
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
            test_path: None,
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
            secret_id: None,
            new_secret_name: None,
            new_secret_value: None,
            ssh_import_id: None,
            identity_file: None,
            key_passphrase: None,
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
        // make the sidecar post JSON-RPC to the upstream's root.
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
            test_path: None,
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
            secret_id: None,
            new_secret_name: None,
            new_secret_value: None,
            ssh_import_id: None,
            identity_file: None,
            key_passphrase: None,
        }
        .into_spec()
        .unwrap();
        assert!(matches!(
            api.config,
            ConnectionConfig::Api { ref host, ref scheme, port: Some(8080), .. }
                if host == "localhost" && scheme == "http"
        ));
    }

    #[test]
    fn agent_setup_instructions_include_the_runtime_paths() {
        let instructions =
            aka_core::manage::agent_setup_instructions("/tmp/aka-test.sock", "~/.aka/token");
        assert!(instructions.contains("curl -fsS"));
        assert!(instructions.contains("--unix-socket /tmp/aka-test.sock"));
        assert!(instructions.contains("Read its current instructions"));
        assert!(instructions.contains("~/.aka/token"));
        assert!(instructions.contains("Authorization: Bearer"));
        assert!(instructions.contains("$(cat ~/.aka/token)"));
        assert!(!instructions.contains("Bearer <key>"));
        assert!(!instructions.contains("Authenticate with this computer"));
        assert!(instructions.contains("\\\n  -H"));
        assert!(!instructions.contains("--max-time"));
        assert!(!instructions.contains("Reuse an existing token before pairing"));
    }

    #[test]
    fn form_errors_serialize_conflicts_with_the_relevant_field() {
        let error = FormError::from_manage(
            ManageError::ConnectionNameTaken {
                name: "github".into(),
            },
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
    fn form_errors_map_manage_connection_fields_without_parsing_messages() {
        let error = FormError::from_manage(
            ManageError::InvalidConnectionField {
                field: aka_api::ConnectionField::HostKeyFingerprint,
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

    #[test]
    fn form_errors_map_target_and_endpoint_conflicts_explicitly() {
        let target = FormError::from_manage(
            ManageError::ConnectionTargetTaken {
                name: "production".into(),
            },
            FormContext::Connection {
                kind: "pg",
                includes_new_secret: false,
            },
        );
        assert_eq!(target.kind, "conflict");
        assert_eq!(target.code, "connection_target_taken");
        assert_eq!(target.field, Some("name"));
        assert!(target.message.contains("production"));

        let stale = FormError::from_manage(ManageError::ConnectionChanged, FormContext::Secret);
        assert_eq!(stale.kind, "conflict");
        assert_eq!(stale.code, "connection_changed");
        assert!(stale.message.contains("changed elsewhere"));

        let wiring =
            FormError::from_manage(ManageError::EndpointRequiresWiring, FormContext::Secret);
        assert_eq!(wiring.code, "endpoint_requires_wiring");
        let limit =
            FormError::from_manage(ManageError::EndpointLimit { max: 8 }, FormContext::Secret);
        assert_eq!(limit.code, "endpoint_limit");
        assert_eq!(
            limit.detail.as_deref(),
            Some("Revoke an existing endpoint, then try again.")
        );
    }

    #[test]
    fn endpoint_copy_renderers_preserve_credentials_and_shell_quoting() {
        let dsn =
            "postgresql://deploy:end_test@/app?host=/tmp/AKA Endpoints&port=5432&sslmode=disable";
        assert_eq!(
            pg_libpq_keywords(dsn).as_deref(),
            Some(
                "host='/tmp/AKA Endpoints' port=5432 dbname=app user=deploy \
                 password=end_test sslmode=disable"
            )
        );
        assert_eq!(
            shell_quoted("/tmp/a \"quoted\" $socket"),
            "\"/tmp/a \\\"quoted\\\" \\$socket\""
        );
    }

    #[test]
    fn endpoint_first_task_is_rendered_natively_and_bounded() {
        let endpoint = IssuedEndpointDto {
            endpoint_id: "ep_test".into(),
            kind: "pg".into(),
            dsn: "postgresql://deploy:end_test@localhost/app".into(),
            tcp_dsn: None,
            secret: "end_test".into(),
            example: "psql postgresql://deploy:end_test@localhost/app".into(),
            expires_at: String::new(),
            expires_in_secs: Some(60),
        };
        assert_eq!(
            endpoint_first_task(&endpoint, Some("  list the newest deploys  ")).unwrap(),
            "Connect to this Postgres DSN: postgresql://deploy:end_test@localhost/app\n\n\
             Then list the newest deploys"
        );
        assert!(endpoint_first_task(&endpoint, None).is_err());
        assert!(endpoint_first_task(&endpoint, Some("   ")).is_err());
        assert!(endpoint_first_task(&endpoint, Some(&"x".repeat(2_001))).is_err());
    }

    #[test]
    fn remote_errors_map_to_actionable_form_errors() {
        let error = FormError::from_manage(
            ManageError::RemoteUnsupported {
                feature: "OAuth sign-in".into(),
            },
            FormContext::Connection {
                kind: "api",
                includes_new_secret: true,
            },
        );
        assert_eq!(error.code, "remote_unsupported");
        let error = FormError::from_manage(
            ManageError::Unreachable {
                message: "connection refused".into(),
            },
            FormContext::Secret,
        );
        assert_eq!(error.code, "broker_unreachable");
        assert_eq!(error.detail.as_deref(), Some("connection refused"));
    }
}
