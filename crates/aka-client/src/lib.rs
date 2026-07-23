//! Manage-plane client: drives a broker's `/v1/manage` API over HTTP.
//!
//! [`RemoteBackend`] implements the same [`ManagementBackend`] trait the
//! in-process backend does, so the desktop shell's command layer cannot
//! tell a hosted broker from a local one. Transport security is the
//! operator's concern (a TLS proxy or tunnel in front of the broker's TCP
//! listener); this client just refuses to pretend — it sends the
//! management token as a bearer on whatever URL it was given.
//!
//! BYO-app OAuth flows are relayed: this client binds the loopback
//! catcher on the *user's* machine, the broker keeps the PKCE verifier,
//! and only the authorization code crosses back — tokens never touch this
//! machine. MCP sign-in is not yet relayable and answers
//! `RemoteUnsupported` until its relay ships.

pub mod credentials;
pub mod events;

use aka_api::{
    ActivityDto, ConnectionDto, IdentityDto, IssuedEndpointDto, ManageError, SecretDto,
    SessionDto, SettingsDto,
};
use aka_core::broker::ConnectionTestReport;
use aka_core::manage::{
    AccessBody, AllowedToolsBody, BackendProfile, ConnectionAddBody, ConnectionUpdateBody,
    DraftTestBody, ManageResult, ManagementBackend, OAuthCompleteBody, OAuthReconnectBody,
    OAuthStartBody, SecretAddBody, SecretEditBody, SettingsPatchBody,
};
use aka_core::store::ConnectionSpec;
use aka_core::types::SecretValue;
use async_trait::async_trait;
use serde::de::DeserializeOwned;
use uuid::Uuid;
use zeroize::Zeroizing;

/// How long a management call may take end to end. Connection tests and
/// MCP status checks dial upstreams, so this must comfortably exceed the
/// broker's own upstream timeout.
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(150);
/// How long establishing the TCP/TLS leg may take: this is what turns an
/// unreachable broker into a prompt, actionable error.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// A validated broker base URL + management token.
#[derive(Clone)]
pub struct RemoteConfig {
    base: url::Url,
    token: Zeroizing<String>,
}

/// Debug never prints the token.
impl std::fmt::Debug for RemoteConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteConfig")
            .field("base", &self.base.as_str())
            .field("token", &"<redacted>")
            .finish()
    }
}

impl RemoteConfig {
    /// Parse and normalize the user-entered URL (scheme required, trailing
    /// slash trimmed).
    pub fn new(url: &str, token: &str) -> Result<Self, String> {
        let trimmed = url.trim().trim_end_matches('/');
        if trimmed.is_empty() {
            return Err("enter the broker's URL".into());
        }
        let base: url::Url = trimmed
            .parse()
            .map_err(|_| "enter a full URL, e.g. https://broker.example.dev".to_string())?;
        match base.scheme() {
            "http" | "https" => {}
            other => return Err(format!("unsupported scheme {other:?}: use http or https")),
        }
        let token = token.trim();
        if token.is_empty() {
            return Err("enter the broker's management token".into());
        }
        Ok(Self {
            base,
            token: Zeroizing::new(token.to_string()),
        })
    }

    pub fn base_url(&self) -> String {
        self.base.as_str().trim_end_matches('/').to_string()
    }

    pub fn token(&self) -> &str {
        &self.token
    }
}

/// Opens a URL in the user's default browser (relayed OAuth consent
/// pages). Returns false when it could not.
pub type UrlOpener = std::sync::Arc<dyn Fn(&str) -> bool + Send + Sync>;

/// The manage-plane HTTP backend.
pub struct RemoteBackend {
    config: RemoteConfig,
    http: reqwest::Client,
    /// How to open a browser on *this* machine — relayed OAuth needs one.
    /// Defaults to "cannot", which surfaces the URL in the error.
    opener: Option<UrlOpener>,
}

impl RemoteBackend {
    pub fn new(config: RemoteConfig) -> Self {
        let http = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .connect_timeout(CONNECT_TIMEOUT)
            .build()
            .expect("http client");
        Self {
            config,
            http,
            opener: None,
        }
    }

    /// Attach the shell's browser opener (enables relayed OAuth flows).
    pub fn with_opener(mut self, opener: UrlOpener) -> Self {
        self.opener = Some(opener);
        self
    }

    /// Drive one relayed OAuth flow: catcher here, verifier on the broker.
    async fn run_relayed_oauth(
        &self,
        start: aka_core::broker::ManageOAuthStart,
        catcher: aka_core::oauth::LoopbackCatcher,
    ) -> ManageResult<()> {
        let opened = self
            .opener
            .as_ref()
            .map(|opener| opener(&start.authorize_url))
            .unwrap_or(false);
        if !opened {
            return Err(ManageError::OAuth {
                message: format!(
                    "could not open the browser; open this URL yourself: {}",
                    start.authorize_url
                ),
            });
        }
        let code = tokio::time::timeout(
            aka_core::oauth::CONNECT_TIMEOUT,
            catcher.wait_for_code(&start.state),
        )
        .await
        .map_err(|_| ManageError::OAuth {
            message: format!(
                "no sign-in within {} minutes; try connecting again",
                aka_core::oauth::CONNECT_TIMEOUT.as_secs() / 60
            ),
        })?
        .map_err(|message| ManageError::OAuth { message })?;
        let _: serde_json::Value = self
            .post(
                &format!("/v1/manage/oauth/complete/{}", start.flow_id),
                &OAuthCompleteBody {
                    code,
                    state: start.state,
                },
            )
            .await?;
        Ok(())
    }

    pub fn config(&self) -> &RemoteConfig {
        &self.config
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.config.base_url(), path)
    }

    fn authed(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        request.header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {}", self.config.token()),
        )
    }

    async fn send<T: DeserializeOwned>(
        &self,
        request: reqwest::RequestBuilder,
    ) -> ManageResult<T> {
        let response = self
            .authed(request)
            .send()
            .await
            .map_err(|error| ManageError::Unreachable {
                message: error.to_string(),
            })?;
        let status = response.status();
        let bytes = response
            .bytes()
            .await
            .map_err(|error| ManageError::Unreachable {
                message: error.to_string(),
            })?;
        if status.is_success() {
            return serde_json::from_slice(&bytes).map_err(|error| ManageError::Internal {
                message: format!("unexpected response shape: {error}"),
            });
        }
        // Failures cross as aka-api ManageError bodies; anything else (a
        // proxy error page, the agent-plane 401 shape) degrades to a
        // labeled error rather than a parse failure.
        if let Ok(error) = serde_json::from_slice::<ManageError>(&bytes) {
            return Err(error);
        }
        if status == reqwest::StatusCode::UNAUTHORIZED {
            return Err(ManageError::InvalidManageToken);
        }
        Err(ManageError::Internal {
            message: format!(
                "broker answered {status}: {}",
                String::from_utf8_lossy(&bytes[..bytes.len().min(200)])
            ),
        })
    }

    async fn get<T: DeserializeOwned>(&self, path: &str) -> ManageResult<T> {
        self.send(self.http.get(self.url(path))).await
    }

    async fn post<T: DeserializeOwned, B: serde::Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> ManageResult<T> {
        self.send(self.http.post(self.url(path)).json(body)).await
    }

    async fn post_empty<T: DeserializeOwned>(&self, path: &str) -> ManageResult<T> {
        self.send(self.http.post(self.url(path))).await
    }

    async fn delete<T: DeserializeOwned>(&self, path: &str) -> ManageResult<T> {
        self.send(self.http.delete(self.url(path))).await
    }

    /// Probe the broker: cheap, authenticated, version-carrying.
    pub async fn whoami(&self) -> ManageResult<serde_json::Value> {
        self.get("/v1/manage/whoami").await
    }
}

#[derive(serde::Deserialize)]
struct ChangedBody {
    changed: bool,
}

#[derive(serde::Deserialize)]
struct RevokedBody {
    revoked: bool,
}

#[derive(serde::Deserialize)]
struct ClosedBody {
    closed: bool,
}

#[derive(serde::Deserialize)]
struct PrefixBody {
    prefix: String,
}

#[derive(serde::Deserialize)]
struct ValueBody {
    value: String,
}

#[derive(serde::Deserialize)]
struct TokenBody {
    token: String,
}

#[derive(serde::Deserialize)]
struct InstructionsBody {
    instructions: String,
}

fn remote_unsupported(feature: &str) -> ManageError {
    ManageError::RemoteUnsupported {
        feature: feature.into(),
    }
}

#[async_trait]
impl ManagementBackend for RemoteBackend {
    fn profile(&self) -> BackendProfile {
        BackendProfile::Remote {
            url: self.config.base_url(),
        }
    }

    async fn list_secrets(&self) -> ManageResult<Vec<SecretDto>> {
        self.get("/v1/manage/secrets").await
    }

    async fn add_secret(&self, name: String, value: SecretValue) -> ManageResult<()> {
        self.post(
            "/v1/manage/secrets",
            &SecretAddBody {
                name,
                value: value.to_string(),
            },
        )
        .await
    }

    async fn edit_secret(
        &self,
        id: Uuid,
        new_name: Option<String>,
        new_value: Option<SecretValue>,
    ) -> ManageResult<()> {
        self.send(
            self.http
                .patch(self.url(&format!("/v1/manage/secrets/{id}")))
                .json(&SecretEditBody {
                    new_name,
                    new_value: new_value.map(|value| value.to_string()),
                }),
        )
        .await
    }

    async fn delete_secret(&self, id: Uuid) -> ManageResult<()> {
        self.delete(&format!("/v1/manage/secrets/{id}")).await
    }

    async fn reveal_secret_prefix(&self, id: Uuid) -> ManageResult<String> {
        self.post_empty::<PrefixBody>(&format!("/v1/manage/secrets/{id}/reveal-prefix"))
            .await
            .map(|body| body.prefix)
    }

    async fn secret_value_for_copy(&self, id: Uuid) -> ManageResult<SecretValue> {
        self.post_empty::<ValueBody>(&format!("/v1/manage/secrets/{id}/copy-value"))
            .await
            .map(|body| Zeroizing::new(body.value))
    }

    async fn note_secret_copied(&self, _id: Uuid) -> ManageResult<()> {
        // The broker audits the copy at value release; there is no
        // honor-system note to send.
        Ok(())
    }

    async fn list_connections(&self) -> ManageResult<Vec<ConnectionDto>> {
        self.get("/v1/manage/connections").await
    }

    async fn add_connection(&self, spec: ConnectionSpec) -> ManageResult<()> {
        self.post(
            "/v1/manage/connections",
            &ConnectionAddBody {
                spec,
                new_secret: None,
            },
        )
        .await
    }

    async fn add_connection_with_secret(
        &self,
        secret_name: String,
        value: SecretValue,
        spec: ConnectionSpec,
    ) -> ManageResult<()> {
        self.post(
            "/v1/manage/connections",
            &ConnectionAddBody {
                spec,
                new_secret: Some(SecretAddBody {
                    name: secret_name,
                    value: value.to_string(),
                }),
            },
        )
        .await
    }

    async fn update_connection(&self, id: Uuid, spec: ConnectionSpec) -> ManageResult<()> {
        self.send(
            self.http
                .put(self.url(&format!("/v1/manage/connections/{id}")))
                .json(&ConnectionUpdateBody { spec }),
        )
        .await
    }

    async fn delete_connection(&self, id: Uuid) -> ManageResult<()> {
        self.delete(&format!("/v1/manage/connections/{id}")).await
    }

    async fn test_connection(&self, id: Uuid) -> ManageResult<ConnectionTestReport> {
        self.post_empty(&format!("/v1/manage/connections/{id}/test"))
            .await
    }

    async fn test_connection_draft(
        &self,
        spec: ConnectionSpec,
        typed_secret: Option<SecretValue>,
    ) -> ManageResult<ConnectionTestReport> {
        self.post(
            "/v1/manage/connections/test-draft",
            &DraftTestBody {
                spec,
                typed_secret: typed_secret.map(|value| value.to_string()),
            },
        )
        .await
    }

    async fn start_mcp_auth(
        &self,
        _draft: aka_core::mcp_auth::McpAuthDraft,
    ) -> ManageResult<aka_core::mcp_auth::McpAuthState> {
        Err(remote_unsupported("MCP sign-in"))
    }

    async fn get_mcp_auth(
        &self,
        _id: Uuid,
    ) -> ManageResult<Option<aka_core::mcp_auth::McpAuthState>> {
        Ok(None)
    }

    async fn cancel_mcp_auth(&self, _id: Uuid) -> ManageResult<bool> {
        Ok(false)
    }

    async fn mcp_status(
        &self,
        id: Uuid,
        options: aka_core::mcp::McpCheckOptions,
    ) -> ManageResult<aka_core::mcp::McpStatusReport> {
        self.post(&format!("/v1/manage/connections/{id}/mcp-status"), &options)
            .await
    }

    async fn list_mcp_tools(&self, id: Uuid) -> ManageResult<Vec<aka_core::mcp::McpToolInfo>> {
        self.get(&format!("/v1/manage/connections/{id}/mcp-tools"))
            .await
    }

    /// Relayed BYO-app OAuth: the consent page opens in *this* machine's
    /// browser and redirects to a loopback catcher here; only the code goes
    /// to the broker, which holds the verifier and does the exchange. The
    /// token never touches this machine.
    async fn oauth_connect(
        &self,
        secret_name: String,
        client_secret: Option<SecretValue>,
        spec: ConnectionSpec,
    ) -> ManageResult<()> {
        let catcher = aka_core::oauth::LoopbackCatcher::bind()
            .await
            .map_err(|message| ManageError::OAuth { message })?;
        let start: aka_core::broker::ManageOAuthStart = self
            .post(
                "/v1/manage/oauth/start",
                &OAuthStartBody {
                    secret_name,
                    client_secret: client_secret.map(|value| value.to_string()),
                    spec,
                    redirect_uri: catcher.redirect_uri(),
                },
            )
            .await?;
        self.run_relayed_oauth(start, catcher).await
    }

    async fn oauth_reconnect(&self, id: Uuid) -> ManageResult<()> {
        let catcher = aka_core::oauth::LoopbackCatcher::bind()
            .await
            .map_err(|message| ManageError::OAuth { message })?;
        let start: aka_core::broker::ManageOAuthStart = self
            .post(
                &format!("/v1/manage/oauth/reconnect/{id}"),
                &OAuthReconnectBody {
                    redirect_uri: catcher.redirect_uri(),
                },
            )
            .await?;
        self.run_relayed_oauth(start, catcher).await
    }

    async fn set_tool_access(&self, connection_id: Uuid, enabled: bool) -> ManageResult<bool> {
        self.post::<ChangedBody, _>(
            &format!("/v1/manage/connections/{connection_id}/access"),
            &AccessBody { enabled },
        )
        .await
        .map(|body| body.changed)
    }

    async fn set_allowed_tools(
        &self,
        connection_id: Uuid,
        tools: Option<Vec<String>>,
    ) -> ManageResult<bool> {
        self.post::<ChangedBody, _>(
            &format!("/v1/manage/connections/{connection_id}/allowed-tools"),
            &AllowedToolsBody { tools },
        )
        .await
        .map(|body| body.changed)
    }

    async fn issue_endpoint(&self, connection_id: Uuid) -> ManageResult<IssuedEndpointDto> {
        self.post_empty(&format!("/v1/manage/connections/{connection_id}/endpoint"))
            .await
    }

    async fn revoke_endpoint(&self, endpoint_id: Uuid) -> ManageResult<bool> {
        self.delete::<RevokedBody>(&format!("/v1/manage/endpoints/{endpoint_id}"))
            .await
            .map(|body| body.revoked)
    }

    async fn identity(&self) -> ManageResult<IdentityDto> {
        self.get("/v1/manage/identity").await
    }

    async fn agent_key(&self) -> ManageResult<String> {
        self.get::<TokenBody>("/v1/manage/identity/agent-key")
            .await
            .map(|body| body.token)
    }

    async fn rotate_key(&self) -> ManageResult<()> {
        self.post_empty("/v1/manage/identity/rotate").await
    }

    async fn sessions(&self) -> ManageResult<Vec<SessionDto>> {
        self.get("/v1/manage/sessions").await
    }

    async fn close_session(&self, id: u64) -> ManageResult<bool> {
        self.delete::<ClosedBody>(&format!("/v1/manage/sessions/{id}"))
            .await
            .map(|body| body.closed)
    }

    async fn activity(&self, limit: usize) -> ManageResult<Vec<ActivityDto>> {
        self.get(&format!("/v1/manage/activity?limit={limit}")).await
    }

    async fn clear_activity(&self) -> ManageResult<()> {
        self.delete("/v1/manage/activity").await
    }

    async fn settings(&self) -> ManageResult<SettingsDto> {
        self.get("/v1/manage/settings").await
    }

    async fn set_reauth_on_read(&self, on: bool) -> ManageResult<()> {
        self.patch_settings(SettingsPatchBody {
            reauth_on_read: Some(on),
            ..Default::default()
        })
        .await
    }

    async fn set_show_websockets(&self, on: bool) -> ManageResult<()> {
        self.patch_settings(SettingsPatchBody {
            show_websockets: Some(on),
            ..Default::default()
        })
        .await
    }

    async fn set_menu_bar_hides_dock(&self, on: bool) -> ManageResult<()> {
        self.patch_settings(SettingsPatchBody {
            menu_bar_hides_dock: Some(on),
            ..Default::default()
        })
        .await
    }

    async fn set_presence_window(&self, secs: u64) -> ManageResult<()> {
        self.patch_settings(SettingsPatchBody {
            presence_window_secs: Some(secs),
            ..Default::default()
        })
        .await
    }

    async fn agent_setup(&self) -> ManageResult<String> {
        self.get::<InstructionsBody>("/v1/manage/agent-setup")
            .await
            .map(|body| body.instructions)
    }
}

impl RemoteBackend {
    async fn patch_settings(&self, patch: SettingsPatchBody) -> ManageResult<()> {
        let _: SettingsDto = self
            .send(
                self.http
                    .patch(self.url("/v1/manage/settings"))
                    .json(&patch),
            )
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_config_normalizes_and_validates() {
        let config = RemoteConfig::new(" https://broker.example.dev/ ", " akamgr_x ").unwrap();
        assert_eq!(config.base_url(), "https://broker.example.dev");
        assert_eq!(config.token(), "akamgr_x");

        assert!(RemoteConfig::new("", "t").is_err());
        assert!(RemoteConfig::new("broker.example.dev", "t")
            .unwrap_err()
            .contains("full URL"));
        assert!(RemoteConfig::new("ftp://x", "t").unwrap_err().contains("scheme"));
        assert!(RemoteConfig::new("http://127.0.0.1:4780", "")
            .unwrap_err()
            .contains("management token"));
    }
}
