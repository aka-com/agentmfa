//! Manage-plane client: drives a broker's `/v1/manage` API over HTTP.
//!
//! [`RemoteBackend`] implements the same [`ManagementBackend`] trait the
//! in-process backend does, so the desktop shell's command layer cannot
//! tell a hosted broker from a local one. Transport security is the
//! operator's concern (a TLS proxy or tunnel in front of the broker's TCP
//! listener); this client just refuses to pretend — it sends the
//! management token as a bearer on whatever URL it was given.
//!
//! OAuth flows (BYO-app and MCP sign-in) are relayed: this client binds
//! the loopback catcher on the *user's* machine, the broker keeps the
//! PKCE verifier, and only the authorization code crosses back — tokens
//! never touch this machine. Sign-in progress arrives over the SSE feed
//! exactly as it does locally.

pub mod credentials;
pub mod events;

use aka_api::{
    ActivityDto, ActivityPageDto, ApprovalDecisionDto, ApprovalDto, ApprovalSnapshotDto,
    ConnectionDto, IdentityDto, IssuedEndpointDto, ManageError, RequestDto, SecretDto, SessionDto,
    SettingsDto,
};
use aka_core::broker::ConnectionTestReport;
use aka_core::manage::{
    AccessBody, AllowedToolsBody, ApprovalResponseBody, AuditStatementsBody, BackendProfile,
    ConfirmBody,
    ConnectionAddBody, ConnectionConfigPatch, ConnectionConfigPatchBody, ConnectionRenameBody,
    ConnectionUpdateBody, ConnectionsReorderBody, DraftTestBody, ElicitationResponseBody,
    EndpointRequireAuthBody,
    ManageResult, ManagementBackend, McpAuthDeliverBody, McpAuthStartBody, OAuthCompleteBody,
    OAuthReconnectBody, OAuthStartBody, ResponseCredentialsBody, SecretAddBody, SecretEditBody,
    SettingsPatchBody,
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
/// How long the relayed MCP sign-in's catcher waits for the browser
/// (mirrors the broker's own browser deadline).
const MCP_SIGNIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

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
    /// Parse and validate a user-entered broker URL (scheme required).
    fn parse_base(url: &str) -> Result<url::Url, String> {
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
        if base.host_str().is_none() {
            return Err("enter a full URL with a host, e.g. https://broker.example.dev".into());
        }
        let loopback = match base.host() {
            Some(url::Host::Ipv4(address)) => address.is_loopback(),
            Some(url::Host::Ipv6(address)) => address.is_loopback(),
            Some(url::Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
            None => false,
        };
        if base.scheme() == "http" && !loopback {
            return Err(
                "remote brokers must use https; plain http is allowed only on loopback for a local tunnel"
                    .into(),
            );
        }
        if !base.username().is_empty() || base.password().is_some() {
            return Err(
                "the broker URL must not contain embedded credentials; use the management token"
                    .into(),
            );
        }
        if base.path() != "/" || base.query().is_some() || base.fragment().is_some() {
            return Err(
                "the broker URL must be an origin only (scheme, host, and optional port)".into(),
            );
        }
        Ok(base)
    }

    /// A user-entered URL's canonical form — exactly what [`Self::base_url`]
    /// returns after [`Self::new`] (the parser lowercases the host and drops
    /// default ports). Anything keyed by broker URL (the saved-token store)
    /// must look up with this, never the raw input, or textual variants of
    /// one broker stop matching their stored entry.
    pub fn normalize_url(url: &str) -> Result<String, String> {
        Ok(Self::parse_base(url)?
            .as_str()
            .trim_end_matches('/')
            .to_string())
    }

    /// Parse and normalize the user-entered URL (scheme required, trailing
    /// slash trimmed).
    pub fn new(url: &str, token: &str) -> Result<Self, String> {
        let base = Self::parse_base(url)?;
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

/// How a management request reaches the broker: HTTPS to a hosted broker's
/// manage URL, or HTTP over the local broker's Unix control socket (the
/// same `/v1/manage` routes, served on the 0600 socket). The management
/// token authorizes both — socket access alone must never grant manage
/// rights, because local agents share the OS user and the socket.
#[derive(Clone)]
enum Transport {
    Http {
        http: reqwest::Client,
        config: RemoteConfig,
    },
    Unix {
        socket: std::path::PathBuf,
        token: Zeroizing<String>,
    },
}

impl Transport {
    /// Where this backend points, for profiles and error messages.
    fn label(&self) -> String {
        match self {
            Transport::Http { config, .. } => config.base_url(),
            Transport::Unix { socket, .. } => socket.display().to_string(),
        }
    }

    /// One request → (status, body bytes). The HTTP arm rides reqwest; the
    /// Unix arm hand-rolls HTTP/1.1 over the socket (no HTTP client crate
    /// reaches a Unix socket portably), reading Content-Length, chunked,
    /// and EOF-delimited bodies alike.
    async fn raw(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<String>,
    ) -> ManageResult<(u16, Vec<u8>)> {
        match self {
            Transport::Http { http, config } => {
                let mut request = http
                    .request(method, format!("{}{path}", config.base_url()))
                    .header(
                        reqwest::header::AUTHORIZATION,
                        format!("Bearer {}", config.token()),
                    );
                if let Some(body) = body {
                    request = request
                        .header(reqwest::header::CONTENT_TYPE, "application/json")
                        .body(body);
                }
                let response = request
                    .send()
                    .await
                    .map_err(|error| ManageError::Unreachable {
                        message: if error.is_timeout() {
                            format!(
                                "no answer from the broker within {}s; if the command was waiting \
                                 on a gated action, confirm it in the AgentMFA app",
                                REQUEST_TIMEOUT.as_secs()
                            )
                        } else {
                            error.to_string()
                        },
                    })?;
                if response.status().is_redirection() {
                    return Err(ManageError::Unreachable {
                        message: redirect_diagnostic(&response),
                    });
                }
                let status = response.status().as_u16();
                let bytes = response
                    .bytes()
                    .await
                    .map_err(|error| ManageError::Unreachable {
                        message: error.to_string(),
                    })?;
                Ok((status, bytes.to_vec()))
            }
            Transport::Unix { socket, token } => tokio::time::timeout(
                REQUEST_TIMEOUT,
                unix_request(socket, method.as_str(), path, token, body.as_deref()),
            )
            .await
            .map_err(|_| ManageError::Unreachable {
                message: format!(
                    "no answer from the broker socket within {}s; if the command was waiting on a \
                     gated action, confirm it in the AgentMFA app",
                    REQUEST_TIMEOUT.as_secs()
                ),
            })?,
        }
    }
}

pub(crate) fn redirect_diagnostic(response: &reqwest::Response) -> String {
    let location = response
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("<missing or invalid Location header>");
    format!("the broker URL redirected to {location}; point --broker at the final origin")
}

/// One HTTP/1.1 request over the broker's Unix control socket.
/// `Connection: close` keeps the framing simple: the body is delimited by
/// Content-Length, chunked encoding, or EOF.
async fn unix_request(
    socket: &std::path::Path,
    method: &str,
    path: &str,
    token: &str,
    body: Option<&str>,
) -> ManageResult<(u16, Vec<u8>)> {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let unreachable = |message: String| ManageError::Unreachable { message };
    let mut stream = tokio::net::UnixStream::connect(socket)
        .await
        .map_err(|error| {
            unreachable(format!(
                "could not reach the broker at {}: {error}",
                socket.display()
            ))
        })?;
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\n\
         Connection: close\r\nAuthorization: Bearer {token}\r\n"
    );
    match body {
        Some(body) => request.push_str(&format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )),
        None => request.push_str("\r\n"),
    }
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|error| unreachable(format!("write to the broker socket failed: {error}")))?;
    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .await
        .map_err(|error| unreachable(format!("read from the broker socket failed: {error}")))?;

    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| unreachable("malformed HTTP response from the broker socket".into()))?;
    let head = String::from_utf8_lossy(&raw[..header_end]).into_owned();
    let payload = &raw[header_end + 4..];
    let status: u16 = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| unreachable("malformed HTTP status line from the broker socket".into()))?;
    let head_lower = head.to_ascii_lowercase();
    let body = if head_lower.contains("transfer-encoding: chunked") {
        decode_chunked(payload)
            .ok_or_else(|| unreachable("malformed chunked body from the broker socket".into()))?
    } else if let Some(length) = head_lower
        .lines()
        .find_map(|line| line.strip_prefix("content-length:"))
        .and_then(|value| value.trim().parse::<usize>().ok())
    {
        payload
            .get(..length)
            .map(<[u8]>::to_vec)
            .ok_or_else(|| unreachable("truncated response from the broker socket".into()))?
    } else {
        // Connection: close — EOF delimits the body.
        payload.to_vec()
    };
    Ok((status, body))
}

/// Decode a chunked transfer-encoded body; `None` on any framing error.
fn decode_chunked(mut input: &[u8]) -> Option<Vec<u8>> {
    let mut body = Vec::new();
    loop {
        let line_end = input.windows(2).position(|w| w == b"\r\n")?;
        let size_line = std::str::from_utf8(&input[..line_end]).ok()?;
        // Chunk extensions (";…") are permitted by the grammar; ignore them.
        let size = usize::from_str_radix(size_line.split(';').next()?.trim(), 16).ok()?;
        input = &input[line_end + 2..];
        if size == 0 {
            return Some(body);
        }
        body.extend_from_slice(input.get(..size)?);
        input = input.get(size..)?;
        input = input.strip_prefix(b"\r\n")?;
    }
}

/// The manage-plane client. One backend, two transports: HTTP(S) to a
/// hosted broker, or the local broker's Unix control socket.
pub struct RemoteBackend {
    transport: Transport,
    /// How to open a browser on *this* machine — relayed OAuth needs one.
    /// Defaults to "cannot", which surfaces the URL in the error.
    opener: Option<UrlOpener>,
}

impl RemoteBackend {
    pub fn new(config: RemoteConfig) -> Self {
        let http = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .connect_timeout(CONNECT_TIMEOUT)
            // Authorization is scoped to the configured broker origin.
            // Never replay it to a redirect destination.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("http client");
        Self {
            transport: Transport::Http { http, config },
            opener: None,
        }
    }

    /// Manage the local broker over its Unix control socket. The management
    /// token still authorizes every call — the 0600 socket is shared with
    /// agents, which must never reach the manage plane.
    pub fn over_unix_socket(socket: std::path::PathBuf, token: &str) -> Self {
        Self {
            transport: Transport::Unix {
                socket,
                token: Zeroizing::new(token.trim().to_string()),
            },
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

    /// The HTTP configuration, when this backend speaks HTTP — `None` over
    /// the Unix socket. The SSE event feed and anything else needing a URL
    /// checks here.
    pub fn config(&self) -> Option<&RemoteConfig> {
        match &self.transport {
            Transport::Http { config, .. } => Some(config),
            Transport::Unix { .. } => None,
        }
    }

    /// Versioned queue snapshot used by the remote desktop's attention
    /// reconciler. Ordinary UI reads keep using `ManagementBackend::approvals`.
    pub async fn approval_snapshot(&self) -> ManageResult<ApprovalSnapshotDto> {
        self.get("/v1/manage/approvals/snapshot").await
    }

    async fn send<T: DeserializeOwned>(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<String>,
    ) -> ManageResult<T> {
        let (status, bytes) = self.transport.raw(method, path, body).await?;
        if (200..300).contains(&status) {
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
        if status == 401 {
            let detail = serde_json::from_slice::<serde_json::Value>(&bytes)
                .ok()
                .and_then(|body| body["detail"].as_str().map(str::to_string));
            return Err(ManageError::InvalidManageToken { detail });
        }
        Err(ManageError::Internal {
            message: format!(
                "broker answered {status}: {}",
                String::from_utf8_lossy(&bytes[..bytes.len().min(200)])
            ),
        })
    }

    async fn get<T: DeserializeOwned>(&self, path: &str) -> ManageResult<T> {
        self.send(reqwest::Method::GET, path, None).await
    }

    async fn post<T: DeserializeOwned, B: serde::Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> ManageResult<T> {
        self.send(
            reqwest::Method::POST,
            path,
            Some(serde_json::to_string(body).expect("serializable body")),
        )
        .await
    }

    async fn post_empty<T: DeserializeOwned>(&self, path: &str) -> ManageResult<T> {
        self.send(reqwest::Method::POST, path, None).await
    }

    async fn put<T: DeserializeOwned, B: serde::Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> ManageResult<T> {
        self.send(
            reqwest::Method::PUT,
            path,
            Some(serde_json::to_string(body).expect("serializable body")),
        )
        .await
    }

    async fn patch<T: DeserializeOwned, B: serde::Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> ManageResult<T> {
        self.send(
            reqwest::Method::PATCH,
            path,
            Some(serde_json::to_string(body).expect("serializable body")),
        )
        .await
    }

    async fn delete<T: DeserializeOwned>(&self, path: &str) -> ManageResult<T> {
        self.send(reqwest::Method::DELETE, path, None).await
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
struct AnsweredBody {
    answered: bool,
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

#[async_trait]
impl ManagementBackend for RemoteBackend {
    fn profile(&self) -> BackendProfile {
        BackendProfile::Remote {
            url: self.transport.label(),
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
        self.patch(
            &format!("/v1/manage/secrets/{id}"),
            &SecretEditBody {
                new_name,
                new_value: new_value.map(|value| value.to_string()),
            },
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

    async fn update_connection(
        &self,
        id: Uuid,
        expected_updated_at: String,
        spec: ConnectionSpec,
    ) -> ManageResult<()> {
        self.put(
            &format!("/v1/manage/connections/{id}"),
            &ConnectionUpdateBody {
                expected_updated_at,
                spec,
            },
        )
        .await
    }

    async fn rename_connection(
        &self,
        id: Uuid,
        expected_updated_at: String,
        name: String,
    ) -> ManageResult<()> {
        self.patch(
            &format!("/v1/manage/connections/{id}"),
            &ConnectionRenameBody {
                expected_updated_at,
                name,
            },
        )
        .await
    }

    async fn patch_connection(
        &self,
        id: Uuid,
        expected_updated_at: String,
        patch: ConnectionConfigPatch,
    ) -> ManageResult<()> {
        self.patch(
            &format!("/v1/manage/connections/{id}/config"),
            &ConnectionConfigPatchBody {
                expected_updated_at,
                patch,
            },
        )
        .await
    }

    async fn delete_connection(&self, id: Uuid) -> ManageResult<()> {
        self.delete(&format!("/v1/manage/connections/{id}")).await
    }

    async fn reorder_connections(&self, ordered_ids: Vec<Uuid>) -> ManageResult<()> {
        self.post(
            "/v1/manage/connections/reorder",
            &ConnectionsReorderBody { ordered_ids },
        )
        .await
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

    /// Relayed MCP sign-in: the catcher binds here; the broker runs
    /// discovery/registration/exchange and streams phases over SSE. The UI
    /// opens the authorize URL itself (as it does locally), and a spawned
    /// task delivers the code the catcher receives.
    async fn start_mcp_auth(
        &self,
        draft: aka_core::mcp_auth::McpAuthDraft,
    ) -> ManageResult<aka_core::mcp_auth::McpAuthState> {
        let catcher = aka_core::oauth::LoopbackCatcher::bind()
            .await
            .map_err(|message| ManageError::OAuth { message })?;
        let state: aka_core::mcp_auth::McpAuthState = self
            .post(
                "/v1/manage/mcp-auth",
                &McpAuthStartBody {
                    draft,
                    redirect_uri: catcher.redirect_uri(),
                },
            )
            .await?;
        // The delivery leg outlives this call: the browser dance takes as
        // long as the user does. The broker verifies the state nonce.
        let session = state.id.clone();
        let transport = self.transport.clone();
        let deliver_path = format!("/v1/manage/mcp-auth/{session}/deliver");
        tokio::spawn(async move {
            let redirect =
                tokio::time::timeout(MCP_SIGNIN_TIMEOUT, catcher.wait_for_redirect()).await;
            let Ok(Ok((code, state, iss))) = redirect else {
                return;
            };
            let _ = transport
                .raw(
                    reqwest::Method::POST,
                    &deliver_path,
                    serde_json::to_string(&McpAuthDeliverBody { code, state, iss }).ok(),
                )
                .await;
        });
        Ok(state)
    }

    async fn get_mcp_auth(
        &self,
        id: Uuid,
    ) -> ManageResult<Option<aka_core::mcp_auth::McpAuthState>> {
        self.get(&format!("/v1/manage/mcp-auth/{id}")).await
    }

    async fn cancel_mcp_auth(&self, id: Uuid) -> ManageResult<bool> {
        #[derive(serde::Deserialize)]
        struct CancelledBody {
            cancelled: bool,
        }
        self.delete::<CancelledBody>(&format!("/v1/manage/mcp-auth/{id}"))
            .await
            .map(|body| body.cancelled)
    }

    async fn mcp_status(
        &self,
        id: Uuid,
        options: aka_core::mcp::McpCheckOptions,
    ) -> ManageResult<aka_core::mcp::McpStatusReport> {
        self.post(&format!("/v1/manage/connections/{id}/mcp-status"), &options)
            .await
    }

    async fn list_mcp_tools(&self, id: Uuid) -> ManageResult<aka_core::mcp::McpToolCatalog> {
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

    async fn set_confirm_mode(&self, connection_id: Uuid, on: bool) -> ManageResult<bool> {
        self.post::<ChangedBody, _>(
            &format!("/v1/manage/connections/{connection_id}/confirm"),
            &ConfirmBody { on },
        )
        .await
        .map(|body| body.changed)
    }

    async fn set_expose_response_credentials(
        &self,
        connection_id: Uuid,
        expose: bool,
    ) -> ManageResult<bool> {
        self.post::<ChangedBody, _>(
            &format!("/v1/manage/connections/{connection_id}/response-credentials"),
            &ResponseCredentialsBody { expose },
        )
        .await
        .map(|body| body.changed)
    }

    async fn approvals(&self) -> ManageResult<Vec<ApprovalDto>> {
        self.get("/v1/manage/approvals").await
    }

    async fn requests(&self) -> ManageResult<Vec<RequestDto>> {
        match self.get("/v1/manage/requests").await {
            // Request history is additive. A new shell can still manage an
            // older broker; it simply has no Recent section to fetch.
            Err(ManageError::Internal { message })
                if message.starts_with("broker answered 404:") =>
            {
                Ok(Vec::new())
            }
            result => result,
        }
    }

    async fn respond_approval(
        &self,
        id: Uuid,
        decision: ApprovalDecisionDto,
    ) -> ManageResult<bool> {
        self.post::<AnsweredBody, _>(
            &format!("/v1/manage/approvals/{id}"),
            &ApprovalResponseBody { decision },
        )
        .await
        .map(|body| body.answered)
    }

    async fn elicitations(&self) -> ManageResult<Vec<aka_api::ElicitationDto>> {
        match self.get("/v1/manage/elicitations").await {
            // Additive, like the request history: a new shell can still
            // manage an older broker that has no elicitation endpoint.
            Err(ManageError::Internal { message })
                if message.starts_with("broker answered 404:") =>
            {
                Ok(Vec::new())
            }
            result => result,
        }
    }

    async fn respond_elicitation(
        &self,
        id: Uuid,
        approved: bool,
        values: std::collections::HashMap<String, String>,
    ) -> ManageResult<bool> {
        self.post::<AnsweredBody, _>(
            &format!("/v1/manage/elicitations/{id}"),
            &ElicitationResponseBody { approved, values },
        )
        .await
        .map(|body| body.answered)
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

    async fn set_audit_statements(
        &self,
        connection_id: Uuid,
        audit_statements: Option<bool>,
    ) -> ManageResult<bool> {
        self.post::<ChangedBody, _>(
            &format!("/v1/manage/connections/{connection_id}/audit-statements"),
            &AuditStatementsBody { audit_statements },
        )
        .await
        .map(|body| body.changed)
    }

    async fn set_endpoint_require_auth(
        &self,
        connection_id: Uuid,
        require_auth: bool,
    ) -> ManageResult<bool> {
        self.post::<ChangedBody, _>(
            &format!("/v1/manage/connections/{connection_id}/endpoint/require-auth"),
            &EndpointRequireAuthBody { require_auth },
        )
        .await
        .map(|body| body.changed)
    }

    async fn issue_endpoint(&self, connection_id: Uuid) -> ManageResult<IssuedEndpointDto> {
        self.post_empty(&format!("/v1/manage/connections/{connection_id}/endpoint"))
            .await
    }

    async fn renew_endpoint(&self, connection_id: Uuid) -> ManageResult<IssuedEndpointDto> {
        self.post_empty(&format!(
            "/v1/manage/connections/{connection_id}/endpoint/renew"
        ))
        .await
    }

    async fn get_endpoint(&self, connection_id: Uuid) -> ManageResult<Option<IssuedEndpointDto>> {
        self.get(&format!("/v1/manage/connections/{connection_id}/endpoint"))
            .await
    }

    async fn copy_endpoint(&self, connection_id: Uuid) -> ManageResult<Option<IssuedEndpointDto>> {
        self.post_empty(&format!(
            "/v1/manage/connections/{connection_id}/endpoint/copy"
        ))
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
        self.get(&format!("/v1/manage/activity?limit={limit}"))
            .await
    }

    async fn activity_page(
        &self,
        limit: usize,
        before: Option<u64>,
    ) -> ManageResult<ActivityPageDto> {
        let mut path = format!("/v1/manage/activity/page?limit={limit}");
        if let Some(before) = before {
            path.push_str(&format!("&before={before}"));
        }
        self.get(&path).await
    }

    async fn clear_activity(&self) -> ManageResult<()> {
        self.delete("/v1/manage/activity").await
    }

    async fn settings(&self) -> ManageResult<SettingsDto> {
        self.get("/v1/manage/settings").await
    }

    async fn set_menu_bar_hides_dock(&self, on: bool) -> ManageResult<()> {
        self.patch_settings(SettingsPatchBody {
            menu_bar_hides_dock: Some(on),
            ..Default::default()
        })
        .await
    }

    async fn set_confirm_ssh_host_keys(&self, on: bool) -> ManageResult<()> {
        self.patch_settings(SettingsPatchBody {
            confirm_ssh_host_keys: Some(on),
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
        let _: SettingsDto = self.patch("/v1/manage/settings", &patch).await?;
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
        assert!(RemoteConfig::new("ftp://x", "t")
            .unwrap_err()
            .contains("scheme"));
        assert!(RemoteConfig::new("http://broker.example.dev", "t")
            .unwrap_err()
            .contains("must use https"));
        for url in [
            "https://broker.example.dev/manage",
            "https://broker.example.dev?tenant=a",
            "https://broker.example.dev#manage",
            "https://user:pass@broker.example.dev",
        ] {
            assert!(RemoteConfig::new(url, "t").is_err(), "{url}");
        }
        assert!(RemoteConfig::new("http://127.0.0.1:4780", "")
            .unwrap_err()
            .contains("management token"));
    }

    #[test]
    fn normalize_url_collapses_textual_variants_of_one_broker() {
        // The token store keys on this: every way a user might re-type the
        // same broker must land on the same string base_url() produces.
        for variant in [
            "https://broker.example.dev",
            "https://broker.example.dev/",
            " https://Broker.Example.dev ",
            "https://broker.example.dev:443",
        ] {
            assert_eq!(
                RemoteConfig::normalize_url(variant).unwrap(),
                "https://broker.example.dev",
                "{variant}"
            );
        }
        assert_eq!(
            RemoteConfig::normalize_url("http://127.0.0.1:4780").unwrap(),
            "http://127.0.0.1:4780"
        );
        assert!(RemoteConfig::normalize_url("").is_err());
        assert!(RemoteConfig::normalize_url("broker.example.dev").is_err());
    }

    #[test]
    fn chunked_bodies_decode_and_reject_bad_framing() {
        assert_eq!(
            decode_chunked(b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n").unwrap(),
            b"Wikipedia"
        );
        // Chunk extensions are ignored; a truncated chunk is refused.
        assert_eq!(
            decode_chunked(b"3;ext=1\r\nabc\r\n0\r\n\r\n").unwrap(),
            b"abc"
        );
        assert!(decode_chunked(b"5\r\nabc").is_none());
    }

    /// The Unix transport against a real manage-shaped server on a Unix
    /// socket: bearer auth rides every method, success bodies parse,
    /// ManageError bodies cross with their shape intact, and 401 maps to
    /// InvalidManageToken.
    #[tokio::test]
    async fn unix_transport_round_trips_the_manage_contract() {
        use axum::http::HeaderMap;
        use axum::routing::{get, patch, post};

        async fn check_auth(headers: &HeaderMap) -> bool {
            headers
                .get("authorization")
                .map(|v| v == "Bearer akamgr_test")
                .unwrap_or(false)
        }
        async fn secrets(headers: HeaderMap) -> axum::response::Response {
            use axum::response::IntoResponse as _;
            if !check_auth(&headers).await {
                return (
                    axum::http::StatusCode::UNAUTHORIZED,
                    axum::Json(serde_json::json!({
                        "reason": "invalid_manage_token",
                        "detail": "the management token has expired",
                    })),
                )
                    .into_response();
            }
            axum::Json(serde_json::json!([{
                "id": "9d5e2c9e-7c5d-4f5e-9b7a-111111111111",
                "name": "API_KEY", "used_by": 1,
                "used_by_names": ["github"],
                "created_at": "2026-01-01T00:00:00Z",
                "updated_at": "2026-01-01T00:00:00Z",
            }]))
            .into_response()
        }
        async fn edit(body: String) -> axum::response::Response {
            use axum::response::IntoResponse as _;
            let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(parsed["new_name"], "GH_TOKEN", "PATCH body crosses");
            axum::Json(serde_json::json!(())).into_response()
        }
        async fn rename_connection(body: String) -> axum::response::Response {
            use axum::response::IntoResponse as _;
            let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(parsed["expected_updated_at"], "opaque-version");
            assert_eq!(parsed["name"], "GitHub production");
            assert!(
                parsed.get("spec").is_none(),
                "rename must not carry reconstructed capability state"
            );
            axum::Json(serde_json::json!(())).into_response()
        }
        async fn taken() -> axum::response::Response {
            use axum::response::IntoResponse as _;
            (
                axum::http::StatusCode::CONFLICT,
                axum::Json(serde_json::json!({
                    "code": "secret_name_taken", "name": "PGPASS",
                })),
            )
                .into_response()
        }
        // The endpoint read crosses as Option<IssuedEndpointDto>: an issued
        // connection returns the DTO, an un-issued one returns JSON null.
        async fn endpoint(
            axum::extract::Path(id): axum::extract::Path<String>,
        ) -> axum::response::Response {
            use axum::response::IntoResponse as _;
            if id.ends_with("222222222222") {
                return axum::Json(serde_json::Value::Null).into_response();
            }
            axum::Json(serde_json::json!({
                "endpoint_id": "aaaaaaaa-0000-0000-0000-000000000000",
                "type": "api", "dsn": "http://127.0.0.1:52001",
                "secret": "end_abc", "example": "curl -H \"Authorization: Bearer end_abc\" http://127.0.0.1:52001/",
            }))
            .into_response()
        }

        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("manage.sock");
        let app = axum::Router::new()
            .route("/v1/manage/secrets", get(secrets).post(taken))
            .route("/v1/manage/secrets/{id}", patch(edit))
            .route(
                "/v1/manage/whoami",
                get(|| async { axum::Json(serde_json::json!({"ok": true})) }),
            )
            .route(
                "/v1/manage/identity/rotate",
                post(|| async { axum::Json(serde_json::json!(())) }),
            )
            .route("/v1/manage/connections/{id}", patch(rename_connection))
            .route("/v1/manage/connections/{id}/endpoint", get(endpoint));
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let backend = RemoteBackend::over_unix_socket(socket.clone(), "akamgr_test");
        assert!(backend.config().is_none(), "no HTTP config over a socket");
        assert!(matches!(
            backend.profile(),
            BackendProfile::Remote { url } if url.contains("manage.sock")
        ));

        // GET with auth → parsed DTOs.
        let secrets = backend.list_secrets().await.unwrap();
        assert_eq!(secrets[0].name, "API_KEY");
        assert_eq!(secrets[0].used_by_names, vec!["github"]);

        // PATCH body crosses; unit response parses.
        backend
            .edit_secret(
                secrets[0].id.parse().unwrap(),
                Some("GH_TOKEN".into()),
                None,
            )
            .await
            .unwrap();

        backend
            .rename_connection(
                "aaaaaaaa-0000-0000-0000-000000000000".parse().unwrap(),
                "opaque-version".into(),
                "GitHub production".into(),
            )
            .await
            .unwrap();

        // The endpoint read crosses as Some for an issued connection and None
        // for an un-issued one (JSON null), over the socket transport.
        let issued = backend
            .get_endpoint("aaaaaaaa-0000-0000-0000-000000000000".parse().unwrap())
            .await
            .unwrap()
            .expect("an issued endpoint parses to Some");
        assert_eq!(issued.dsn, "http://127.0.0.1:52001");
        assert_eq!(issued.secret, "end_abc");
        assert_eq!(
            issued.example,
            "curl -H \"Authorization: Bearer end_abc\" http://127.0.0.1:52001/"
        );
        let none = backend
            .get_endpoint("00000000-0000-0000-0000-222222222222".parse().unwrap())
            .await
            .unwrap();
        assert!(none.is_none(), "an un-issued endpoint parses to None");

        // A ManageError body crosses with its shape intact.
        let error = backend
            .add_secret("PGPASS".into(), Zeroizing::new("x".into()))
            .await
            .unwrap_err();
        assert!(
            matches!(error, ManageError::SecretNameTaken { ref name } if name == "PGPASS"),
            "{error:?}"
        );

        // The wrong token maps to InvalidManageToken and retains structured
        // server detail instead of collapsing an expiry into a generic 401.
        let wrong = RemoteBackend::over_unix_socket(socket, "akamgr_wrong");
        assert!(matches!(
            wrong.list_secrets().await.unwrap_err(),
            ManageError::InvalidManageToken {
                detail: Some(ref detail)
            } if detail == "the management token has expired"
        ));
    }
}
