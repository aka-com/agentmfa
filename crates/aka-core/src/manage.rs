//! The management plane's backend seam.
//!
//! The desktop shell manages a broker exclusively through
//! [`ManagementBackend`]: in local mode the implementation is
//! [`LocalBackend`] wrapping an in-process [`Broker`]; in remote mode it is
//! an HTTP client speaking the same shapes to a hosted broker's manage API.
//! The wire types live in `aka-api` so the two cannot drift.
//!
//! Everything here is a thin adapter: authorization, confirmation gates, and
//! auditing stay in the core's `ui_*` entry points. `LocalBackend` runs
//! synchronous mutating calls on a blocking thread because they can demand
//! the shell's native confirmation, which must never park the async runtime
//! (the same rule the shell's `rotate_key` always followed).

use std::sync::Arc;

use aka_api::{
    AccessDto, ActivityDto, ConnectionDto, EndpointChip, IdentityDto, IssuedEndpointDto,
    ManageError, OAuthDto, SecretDto, SessionDto, SettingsDto,
};
use async_trait::async_trait;
use uuid::Uuid;

use crate::audit::AuditEntry;
use crate::broker::{Broker, ConnectionTestReport, IssuedEndpointInfo};
use crate::error::CoreError;
use crate::store::ConnectionSpec;
use crate::types::{Connection, SecretMeta, SecretValue};

/// A management call's result: the value, or the wire-shaped error the
/// shell maps onto form fields.
pub type ManageResult<T> = std::result::Result<T, ManageError>;

impl From<CoreError> for ManageError {
    fn from(error: CoreError) -> Self {
        match error {
            CoreError::SecretNameTaken(name) => Self::SecretNameTaken { name },
            CoreError::ConnectionNameTaken(name) => Self::ConnectionNameTaken { name },
            CoreError::ConnectionTargetTaken(name) => Self::ConnectionTargetTaken { name },
            CoreError::SecretNotFound => Self::SecretNotFound,
            CoreError::ConnectionNotFound => Self::ConnectionNotFound,
            CoreError::ApprovalConnectionChanged => Self::ApprovalConnectionChanged,
            CoreError::SecretInUse(connections) => Self::SecretInUse { connections },
            CoreError::InvalidSecretName(name) => Self::InvalidSecretName { name },
            CoreError::InvalidConnectionName(name) => Self::InvalidConnectionName { name },
            CoreError::Template(error) => Self::Template {
                message: error.to_string(),
            },
            CoreError::UnknownTemplateRef(name) => Self::UnknownTemplateRef { name },
            CoreError::WrongSecretCount { kind } => Self::WrongSecretCount { kind: kind.into() },
            CoreError::InvalidConnectionConfig(message) => {
                Self::InvalidConnectionConfig { message }
            }
            CoreError::InvalidSetting(message) => Self::InvalidSetting { message },
            CoreError::InvalidConnectionField { field, message } => {
                Self::InvalidConnectionField { field, message }
            }
            CoreError::KindChange => Self::KindChange,
            CoreError::EndpointNotFound => Self::EndpointNotFound,
            CoreError::EndpointLimit(max) => Self::EndpointLimit { max },
            CoreError::EndpointRequiresWiring => Self::EndpointRequiresWiring,
            CoreError::EndpointUnsupportedKind(kind) => {
                Self::EndpointUnsupportedKind { kind: kind.into() }
            }
            CoreError::SecretReadNotAuthenticated => Self::SecretReadNotAuthenticated,
            CoreError::NotConfirmed => Self::NotConfirmed,
            CoreError::OAuth(message) => Self::OAuth { message },
            CoreError::Vault(message) => Self::Vault { message },
            other => Self::Internal {
                message: other.to_string(),
            },
        }
    }
}

/* ------------------------------ DTO builders ------------------------------ */

pub fn secret_dto(broker: &Broker, meta: &SecretMeta) -> SecretDto {
    let names = broker.store.connections_using(&meta.id);
    SecretDto {
        id: meta.id.to_string(),
        name: meta.name.clone(),
        used_by: names.len(),
        used_by_names: names,
        created_at: meta.created_at.to_rfc3339(),
        updated_at: meta.updated_at.to_rfc3339(),
    }
}

pub fn connection_dto(broker: &Broker, conn: &Connection) -> ConnectionDto {
    use crate::types::ConnectionConfig::*;
    let secret_names = conn
        .secrets
        .iter()
        .filter_map(|id| broker.store.secret_by_id(id).ok().map(|s| s.name))
        .collect();
    let entry = broker.access.entry(&conn.id);
    let agent_access = AccessDto {
        enabled: entry.as_ref().map(|e| e.enabled).unwrap_or(true),
        allowed_tools: entry.and_then(|e| e.allowed_tools),
        endpoint: broker.endpoints.get_for_connection(&conn.id).map(|e| {
            let dsn = match &conn.config {
                // The retained secret rides in the password slot; a
                // pre-retention record (empty secret) falls back to
                // the password-less form until reissued.
                Pg { user, dbname, .. } => Some(crate::capability::pg::endpoint_dsn(
                    broker.paths.endpoint_dir(&e.id).as_path(),
                    user,
                    dbname,
                    (!e.secret.is_empty()).then_some(e.secret.as_str()),
                )),
                Api { .. } => e.port.map(|port| format!("http://127.0.0.1:{port}")),
                _ => None,
            };
            EndpointChip {
                endpoint_id: e.id.to_string(),
                kind: e.kind.as_str().to_string(),
                dsn,
            }
        }),
    };
    let health = broker.health.get(&conn.id);
    let mut dto = ConnectionDto {
        id: conn.id.to_string(),
        name: conn.name.clone(),
        kind: conn.kind().as_str().to_string(),
        target: conn.target(),
        secret_names,
        oauth: conn.oauth.is_some(),
        agent_access,
        host: None,
        scheme: None,
        port: None,
        template: None,
        dbname: None,
        user: None,
        host_key_fingerprint: None,
        destination: None,
        sslmode: None,
        trusted_ca_bundle_path: None,
        url: None,
        mcp_path: None,
        account: conn.account.clone(),
        oauth_spec: None,
        last_status: health.as_ref().map(|h| h.status.as_str().to_string()),
        last_detail: health.as_ref().map(|h| h.detail.clone()),
        last_checked_at: health.as_ref().map(|h| h.checked_at.to_rfc3339()),
    };
    match &conn.config {
        Api {
            host,
            scheme,
            port,
            template,
            mcp_path,
            oauth,
        } => {
            dto.host = Some(host.clone());
            dto.scheme = Some(scheme.clone());
            dto.port = *port;
            dto.template = Some(template.clone());
            dto.mcp_path = mcp_path.clone();
            dto.oauth_spec = oauth.as_ref().map(|o| OAuthDto {
                auth_url: o.auth_url.clone(),
                token_url: o.token_url.clone(),
                client_id: o.client_id.clone(),
                scopes: o.scopes.clone(),
            });
        }
        Pg {
            host,
            port,
            dbname,
            user,
            sslmode,
            trusted_ca_bundle_path,
        } => {
            dto.host = Some(host.clone());
            dto.port = Some(*port);
            dto.dbname = Some(dbname.clone());
            dto.user = Some(user.clone());
            dto.sslmode = Some(
                serde_json::to_value(sslmode)
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_string))
                    .unwrap_or_else(|| "prefer".into()),
            );
            dto.trusted_ca_bundle_path = trusted_ca_bundle_path.clone();
        }
        Ws { url, template } => {
            dto.url = Some(url.clone());
            dto.template = template.clone();
        }
        Ssh {
            destination,
            host,
            port,
            user,
            host_key_fingerprint,
        } => {
            dto.destination = destination.clone();
            dto.host = Some(host.clone());
            dto.port = Some(*port);
            dto.user = Some(user.clone());
            // None while unpinned so the UI can tell "trusted on first
            // use, pending" apart from a pinned fingerprint.
            dto.host_key_fingerprint =
                (!host_key_fingerprint.is_empty()).then(|| host_key_fingerprint.clone());
        }
    }
    dto
}

pub fn identity_dto(broker: &Broker) -> IdentityDto {
    let identity = broker.identity_info();
    IdentityDto {
        client_id: identity.id.to_string(),
        token_path: broker.paths.token_display(),
        socket_path: broker.paths.socket_display(),
        minted_at: identity.minted_at.to_rfc3339(),
        last_used: identity.last_used.to_rfc3339(),
        legacy_aliases: broker.identity.active_alias_count(),
    }
}

pub fn session_dto(session: &crate::sessions::SessionInfo) -> SessionDto {
    SessionDto {
        id: session.id,
        kind: session.kind.as_str().to_string(),
        agent: session.agent.clone(),
        connection: session.connection.clone(),
        detail: session.detail.clone(),
        opened_at: session.opened_at.to_rfc3339(),
    }
}

pub fn activity_dto(entry: &AuditEntry) -> ActivityDto {
    ActivityDto {
        icon: entry.kind.icon().to_string(),
        tone: entry.kind.tone().to_string(),
        text: entry.text.clone(),
        detail: entry.detail.clone(),
        agent: entry.agent.clone(),
        connection: entry.connection.clone(),
        duration_ms: entry.duration_ms,
        at: entry.ts.to_rfc3339(),
    }
}

pub fn settings_dto(broker: &Broker) -> SettingsDto {
    let settings = broker.settings();
    SettingsDto {
        reauth_on_read: settings.reauth_on_read,
        show_websockets: settings.show_websockets,
        menu_bar_hides_dock: settings.menu_bar_hides_dock,
        presence_window_secs: settings.presence_window_secs,
    }
}

fn issued_endpoint_dto(info: IssuedEndpointInfo) -> IssuedEndpointDto {
    IssuedEndpointDto {
        endpoint_id: info.endpoint_id.to_string(),
        kind: info.kind.as_str().to_string(),
        dsn: info.dsn,
        secret: info.secret,
        example: info.example,
    }
}

/// The agent-setup snippet the Connect page shows and copies, rendered for a
/// broker reached over its Unix socket.
pub fn agent_setup_instructions(socket: &str, token_path: &str) -> String {
    format!(
        "Connect to the local Multitool broker. Read its current instructions, then list the available connections:\n\ncurl -fsS --unix-socket {socket} http://localhost/instructions\n\nAuthenticate with this computer's shared key — read it from {token_path} and send it as `Authorization: Bearer <key>`."
    )
}

/* -------------------------------- backend --------------------------------- */

/// Which broker the shell is managing. The webview uses this to label the
/// header switcher and gate remote-incapable features.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum BackendProfile {
    /// The broker runs inside this app on this machine.
    Local,
    /// The broker is managed over its manage API.
    Remote { url: String },
}

/// Everything the desktop shell may do to a broker. One implementation wraps
/// the in-process broker; the other speaks HTTP to a hosted one. Methods
/// mirror the `ui_*` surface one-to-one so the command layer stays a thin
/// argument-parsing shell.
#[async_trait]
pub trait ManagementBackend: Send + Sync {
    fn profile(&self) -> BackendProfile;

    /* secrets */
    async fn list_secrets(&self) -> ManageResult<Vec<SecretDto>>;
    async fn add_secret(&self, name: String, value: SecretValue) -> ManageResult<()>;
    async fn edit_secret(
        &self,
        id: Uuid,
        new_name: Option<String>,
        new_value: Option<SecretValue>,
    ) -> ManageResult<()>;
    async fn delete_secret(&self, id: Uuid) -> ManageResult<()>;
    async fn reveal_secret_prefix(&self, id: Uuid) -> ManageResult<String>;
    async fn secret_value_for_copy(&self, id: Uuid) -> ManageResult<SecretValue>;
    async fn note_secret_copied(&self, id: Uuid) -> ManageResult<()>;

    /* connections */
    async fn list_connections(&self) -> ManageResult<Vec<ConnectionDto>>;
    async fn add_connection(&self, spec: ConnectionSpec) -> ManageResult<()>;
    async fn add_connection_with_secret(
        &self,
        secret_name: String,
        value: SecretValue,
        spec: ConnectionSpec,
    ) -> ManageResult<()>;
    async fn update_connection(&self, id: Uuid, spec: ConnectionSpec) -> ManageResult<()>;
    async fn delete_connection(&self, id: Uuid) -> ManageResult<()>;
    async fn test_connection(&self, id: Uuid) -> ManageResult<ConnectionTestReport>;
    async fn test_connection_draft(
        &self,
        spec: ConnectionSpec,
        typed_secret: Option<SecretValue>,
    ) -> ManageResult<ConnectionTestReport>;

    /* MCP */
    async fn start_mcp_auth(
        &self,
        draft: crate::mcp_auth::McpAuthDraft,
    ) -> ManageResult<crate::mcp_auth::McpAuthState>;
    async fn get_mcp_auth(&self, id: Uuid) -> ManageResult<Option<crate::mcp_auth::McpAuthState>>;
    async fn cancel_mcp_auth(&self, id: Uuid) -> ManageResult<bool>;
    async fn mcp_status(
        &self,
        id: Uuid,
        options: crate::mcp::McpCheckOptions,
    ) -> ManageResult<crate::mcp::McpStatusReport>;
    async fn list_mcp_tools(&self, id: Uuid) -> ManageResult<Vec<crate::mcp::McpToolInfo>>;

    /* OAuth (BYO app) */
    async fn oauth_connect(
        &self,
        secret_name: String,
        client_secret: Option<SecretValue>,
        spec: ConnectionSpec,
    ) -> ManageResult<()>;
    async fn oauth_reconnect(&self, id: Uuid) -> ManageResult<()>;

    /* agent access + endpoints */
    async fn set_tool_access(&self, connection_id: Uuid, enabled: bool) -> ManageResult<bool>;
    async fn set_allowed_tools(
        &self,
        connection_id: Uuid,
        tools: Option<Vec<String>>,
    ) -> ManageResult<bool>;
    async fn issue_endpoint(&self, connection_id: Uuid) -> ManageResult<IssuedEndpointDto>;
    async fn revoke_endpoint(&self, endpoint_id: Uuid) -> ManageResult<bool>;

    /* identity */
    async fn identity(&self) -> ManageResult<IdentityDto>;
    /// The shared agent key's plaintext, for the shell-side clipboard copy.
    /// It must never enter the webview.
    async fn agent_key(&self) -> ManageResult<String>;
    async fn rotate_key(&self) -> ManageResult<()>;

    /* sessions + activity */
    async fn sessions(&self) -> ManageResult<Vec<SessionDto>>;
    async fn close_session(&self, id: u64) -> ManageResult<bool>;
    async fn activity(&self, limit: usize) -> ManageResult<Vec<ActivityDto>>;
    async fn clear_activity(&self) -> ManageResult<()>;

    /* settings */
    async fn settings(&self) -> ManageResult<SettingsDto>;
    async fn set_reauth_on_read(&self, on: bool) -> ManageResult<()>;
    async fn set_show_websockets(&self, on: bool) -> ManageResult<()>;
    async fn set_menu_bar_hides_dock(&self, on: bool) -> ManageResult<()>;
    async fn set_presence_window(&self, secs: u64) -> ManageResult<()>;

    /* discovery */
    async fn agent_setup(&self) -> ManageResult<String>;
}

/// The in-process backend: the broker lives in this process and the shell's
/// native confirmation gates fire directly.
pub struct LocalBackend {
    broker: Arc<Broker>,
}

impl LocalBackend {
    pub fn new(broker: Arc<Broker>) -> Self {
        Self { broker }
    }

    /// Run a synchronous `ui_*` call on a blocking thread. Mutating entry
    /// points can demand the shell's native confirmation sheet, which blocks
    /// until the user answers — never on the async runtime.
    async fn blocking<T, F>(&self, call: F) -> ManageResult<T>
    where
        T: Send + 'static,
        F: FnOnce(Arc<Broker>) -> crate::Result<T> + Send + 'static,
    {
        let broker = self.broker.clone();
        tokio::task::spawn_blocking(move || call(broker))
            .await
            .map_err(|join| ManageError::Internal {
                message: format!("management call stopped: {join}"),
            })?
            .map_err(ManageError::from)
    }
}

#[async_trait]
impl ManagementBackend for LocalBackend {
    fn profile(&self) -> BackendProfile {
        BackendProfile::Local
    }

    async fn list_secrets(&self) -> ManageResult<Vec<SecretDto>> {
        let broker = &self.broker;
        Ok(broker
            .store
            .list_secrets()
            .iter()
            .map(|meta| secret_dto(broker, meta))
            .collect())
    }

    async fn add_secret(&self, name: String, value: SecretValue) -> ManageResult<()> {
        self.blocking(move |broker| broker.ui_add_secret(&name, value).map(|_| ()))
            .await
    }

    async fn edit_secret(
        &self,
        id: Uuid,
        new_name: Option<String>,
        new_value: Option<SecretValue>,
    ) -> ManageResult<()> {
        self.blocking(move |broker| {
            broker
                .ui_edit_secret(&id, new_name.as_deref(), new_value)
                .map(|_| ())
        })
        .await
    }

    async fn delete_secret(&self, id: Uuid) -> ManageResult<()> {
        self.blocking(move |broker| broker.ui_delete_secret(&id).map(|_| ()))
            .await
    }

    async fn reveal_secret_prefix(&self, id: Uuid) -> ManageResult<String> {
        Ok(self.broker.ui_reveal_secret_prefix(&id).await?)
    }

    async fn secret_value_for_copy(&self, id: Uuid) -> ManageResult<SecretValue> {
        Ok(self.broker.ui_secret_value_for_copy(&id).await?)
    }

    async fn note_secret_copied(&self, id: Uuid) -> ManageResult<()> {
        Ok(self.broker.ui_note_secret_copied(&id)?)
    }

    async fn list_connections(&self) -> ManageResult<Vec<ConnectionDto>> {
        let broker = &self.broker;
        Ok(broker
            .store
            .list_connections()
            .iter()
            .map(|conn| connection_dto(broker, conn))
            .collect())
    }

    async fn add_connection(&self, spec: ConnectionSpec) -> ManageResult<()> {
        self.blocking(move |broker| broker.ui_add_connection(spec).map(|_| ()))
            .await
    }

    async fn add_connection_with_secret(
        &self,
        secret_name: String,
        value: SecretValue,
        spec: ConnectionSpec,
    ) -> ManageResult<()> {
        self.blocking(move |broker| {
            broker
                .ui_add_connection_with_secret(&secret_name, value, spec)
                .map(|_| ())
        })
        .await
    }

    async fn update_connection(&self, id: Uuid, spec: ConnectionSpec) -> ManageResult<()> {
        self.blocking(move |broker| broker.ui_update_connection(&id, spec).map(|_| ()))
            .await
    }

    async fn delete_connection(&self, id: Uuid) -> ManageResult<()> {
        self.blocking(move |broker| broker.ui_delete_connection(&id).map(|_| ()))
            .await
    }

    async fn test_connection(&self, id: Uuid) -> ManageResult<ConnectionTestReport> {
        Ok(self.broker.ui_test_connection(&id).await?)
    }

    async fn test_connection_draft(
        &self,
        spec: ConnectionSpec,
        typed_secret: Option<SecretValue>,
    ) -> ManageResult<ConnectionTestReport> {
        Ok(self
            .broker
            .ui_test_connection_draft(spec, typed_secret)
            .await?)
    }

    async fn start_mcp_auth(
        &self,
        draft: crate::mcp_auth::McpAuthDraft,
    ) -> ManageResult<crate::mcp_auth::McpAuthState> {
        Ok(self.broker.ui_start_mcp_auth(draft)?)
    }

    async fn get_mcp_auth(&self, id: Uuid) -> ManageResult<Option<crate::mcp_auth::McpAuthState>> {
        Ok(self.broker.ui_mcp_auth_state(&id))
    }

    async fn cancel_mcp_auth(&self, id: Uuid) -> ManageResult<bool> {
        Ok(self.broker.ui_cancel_mcp_auth(&id))
    }

    async fn mcp_status(
        &self,
        id: Uuid,
        options: crate::mcp::McpCheckOptions,
    ) -> ManageResult<crate::mcp::McpStatusReport> {
        Ok(self.broker.ui_mcp_check(&id, options).await?)
    }

    async fn list_mcp_tools(&self, id: Uuid) -> ManageResult<Vec<crate::mcp::McpToolInfo>> {
        Ok(self.broker.ui_list_mcp_tools(&id).await?)
    }

    async fn oauth_connect(
        &self,
        secret_name: String,
        client_secret: Option<SecretValue>,
        spec: ConnectionSpec,
    ) -> ManageResult<()> {
        Ok(self
            .broker
            .ui_oauth_connect(&secret_name, client_secret, spec)
            .await
            .map(|_| ())?)
    }

    async fn oauth_reconnect(&self, id: Uuid) -> ManageResult<()> {
        Ok(self.broker.ui_oauth_reconnect(&id).await.map(|_| ())?)
    }

    async fn set_tool_access(&self, connection_id: Uuid, enabled: bool) -> ManageResult<bool> {
        self.blocking(move |broker| broker.ui_set_tool_access(&connection_id, enabled))
            .await
    }

    async fn set_allowed_tools(
        &self,
        connection_id: Uuid,
        tools: Option<Vec<String>>,
    ) -> ManageResult<bool> {
        self.blocking(move |broker| broker.ui_set_allowed_tools(&connection_id, tools))
            .await
    }

    async fn issue_endpoint(&self, connection_id: Uuid) -> ManageResult<IssuedEndpointDto> {
        Ok(self
            .broker
            .ui_issue_endpoint(&connection_id)
            .await
            .map(issued_endpoint_dto)?)
    }

    async fn revoke_endpoint(&self, endpoint_id: Uuid) -> ManageResult<bool> {
        self.blocking(move |broker| broker.ui_revoke_endpoint(&endpoint_id))
            .await
    }

    async fn identity(&self) -> ManageResult<IdentityDto> {
        Ok(identity_dto(&self.broker))
    }

    async fn agent_key(&self) -> ManageResult<String> {
        Ok(self.broker.identity.token())
    }

    async fn rotate_key(&self) -> ManageResult<()> {
        self.blocking(move |broker| broker.ui_rotate_key()).await
    }

    async fn sessions(&self) -> ManageResult<Vec<SessionDto>> {
        Ok(self.broker.sessions().iter().map(session_dto).collect())
    }

    async fn close_session(&self, id: u64) -> ManageResult<bool> {
        Ok(self.broker.ui_close_session(id)?)
    }

    async fn activity(&self, limit: usize) -> ManageResult<Vec<ActivityDto>> {
        Ok(self
            .broker
            .audit
            .recent(limit)
            .iter()
            .map(activity_dto)
            .collect())
    }

    async fn clear_activity(&self) -> ManageResult<()> {
        Ok(self.broker.audit.clear()?)
    }

    async fn settings(&self) -> ManageResult<SettingsDto> {
        Ok(settings_dto(&self.broker))
    }

    async fn set_reauth_on_read(&self, on: bool) -> ManageResult<()> {
        self.blocking(move |broker| broker.ui_change_reauth_on_read(on))
            .await
    }

    async fn set_show_websockets(&self, on: bool) -> ManageResult<()> {
        self.blocking(move |broker| broker.ui_set_show_websockets(on))
            .await
    }

    async fn set_menu_bar_hides_dock(&self, on: bool) -> ManageResult<()> {
        self.blocking(move |broker| broker.ui_set_menu_bar_hides_dock(on))
            .await
    }

    async fn set_presence_window(&self, secs: u64) -> ManageResult<()> {
        self.blocking(move |broker| broker.ui_set_presence_window(secs))
            .await
    }

    async fn agent_setup(&self) -> ManageResult<String> {
        Ok(agent_setup_instructions(
            &self.broker.paths.socket_display(),
            &self.broker.paths.token_display(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BrokerConfig;
    use crate::events::NoopEvents;
    use crate::paths::Paths;
    use crate::types::ConnectionConfig;
    use crate::vault::MemoryVault;
    use zeroize::Zeroizing;

    async fn backend(dir: &tempfile::TempDir) -> LocalBackend {
        let broker = Broker::new(
            Paths::under(dir.path()),
            Arc::new(MemoryVault::new()),
            BrokerConfig::default(),
            Arc::new(NoopEvents),
        )
        .await
        .unwrap();
        LocalBackend::new(broker)
    }

    fn api_spec(name: &str) -> ConnectionSpec {
        ConnectionSpec {
            name: name.into(),
            config: ConnectionConfig::Api {
                host: "api.github.com".into(),
                scheme: "https".into(),
                port: None,
                template: "Authorization: Bearer {{GITHUB_KEY}}".into(),
                mcp_path: None,
                oauth: None,
            },
            secrets: vec![],
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn local_backend_round_trips_secrets_and_connections() {
        let dir = tempfile::tempdir().unwrap();
        let backend = backend(&dir).await;

        backend
            .add_secret("GITHUB_KEY".into(), Zeroizing::new("ghp_test".into()))
            .await
            .unwrap();
        backend.add_connection(api_spec("github")).await.unwrap();

        let secrets = backend.list_secrets().await.unwrap();
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].name, "GITHUB_KEY");
        assert_eq!(secrets[0].used_by_names, vec!["github".to_string()]);

        let connections = backend.list_connections().await.unwrap();
        assert_eq!(connections.len(), 1);
        let conn = &connections[0];
        assert_eq!(conn.kind, "api");
        assert_eq!(conn.secret_names, vec!["GITHUB_KEY".to_string()]);
        assert!(conn.agent_access.enabled, "enabled is the default");

        let id: Uuid = conn.id.parse().unwrap();
        // Returns whether the setting changed; disabling from the default
        // (enabled) is a change.
        assert!(backend.set_tool_access(id, false).await.unwrap());
        assert!(!backend.list_connections().await.unwrap()[0]
            .agent_access
            .enabled);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn errors_cross_the_seam_with_their_shape_intact() {
        let dir = tempfile::tempdir().unwrap();
        let backend = backend(&dir).await;
        backend
            .add_secret("KEY".into(), Zeroizing::new("v".into()))
            .await
            .unwrap();
        let error = backend
            .add_secret("KEY".into(), Zeroizing::new("v".into()))
            .await
            .unwrap_err();
        assert_eq!(
            error,
            ManageError::SecretNameTaken { name: "KEY".into() }
        );

        let error = backend
            .add_connection(ConnectionSpec {
                name: "gh".into(),
                config: ConnectionConfig::Api {
                    host: "api.github.com".into(),
                    scheme: "https".into(),
                    port: None,
                    template: "Authorization: Bearer {{MISSING}}".into(),
                    mcp_path: None,
                    oauth: None,
                },
                secrets: vec![],
            })
            .await
            .unwrap_err();
        assert_eq!(
            error,
            ManageError::UnknownTemplateRef {
                name: "MISSING".into()
            }
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn identity_and_settings_surface_through_the_backend() {
        let dir = tempfile::tempdir().unwrap();
        let backend = backend(&dir).await;

        let identity = backend.identity().await.unwrap();
        assert!(identity.token_path.ends_with("token"));
        let key = backend.agent_key().await.unwrap();
        assert!(key.starts_with("aka_"));

        let settings = backend.settings().await.unwrap();
        assert!(settings.reauth_on_read);
        backend.set_show_websockets(true).await.unwrap();
        assert!(backend.settings().await.unwrap().show_websockets);

        let setup = backend.agent_setup().await.unwrap();
        assert!(setup.contains("--unix-socket"));
    }
}
