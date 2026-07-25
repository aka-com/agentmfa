//! Agent-facing control plane. HTTP over a Unix domain socket, mode 0600.
//!
//! - `GET /.well-known/agent-broker.json`, `GET /instructions`,
//!   unauthenticated discovery, globally rate limited;
//! - `POST /v1/pair`, unauthenticated, globally rate limited, registered
//!   immediately (no approval);
//! - `GET /v1/connections`, `GET /v1/whoami`, `POST /v1/http` (+ the WS/PG
//!   opens added by later phases), authenticated with the shared broker
//!   key, rate limited per client label.

pub mod manage;
pub mod wellknown;

use std::collections::HashMap;
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::{DefaultBodyLimit, FromRequestParts, State};
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;
use tokio::net::UnixListener;

use crate::audit::{AuditEntry, AuditKind};
use crate::broker::Broker;
use crate::capability::http::{
    injection_form, is_mutating, parse_method, payload_hash, validate_headers, validate_path,
    HttpExecution, InjectionForm,
};
use crate::capability::SpooledBody;
use crate::error::CoreError;
use crate::executions::{ExecError, ExecOutcome, ExecRequest, Execution};
use crate::identity::{validate_agent_name, TokenError};
use crate::types::{ConnectionConfig, ConnectionKind};
use crate::wire::{ErrorReason, MissingTokenCause, REQUEST_ID_MAX_BYTES};

/* ------------------------------ plumbing --------------------------------- */

/// Which listener a request arrived on. TCP requests see remote-flavored
/// discovery documents and are refused `/v1/pair` (an unauthenticated
/// key-dispenser is only acceptable behind 0600 filesystem permissions).
#[derive(Clone, Debug)]
pub enum Transport {
    Uds,
    Tcp {
        /// The URL remote clients reach this broker at (the operator's TLS
        /// proxy or tunnel), advertised in TCP-served discovery documents.
        public_url: Option<Arc<str>>,
    },
}

impl Transport {
    fn is_tcp(&self) -> bool {
        matches!(self, Transport::Tcp { .. })
    }

    fn public_url(&self) -> Option<&str> {
        match self {
            Transport::Uds => None,
            Transport::Tcp { public_url } => public_url.as_deref(),
        }
    }
}

#[derive(Clone)]
pub struct AppState {
    pub broker: Arc<Broker>,
    /// The manage-plane backend the `/v1/manage` routes drive — the same
    /// implementation an in-process shell uses, so the two cannot drift.
    pub manage: Arc<crate::manage::LocalBackend>,
    /// The listener this router serves.
    pub transport: Transport,
}

fn err(status: StatusCode, reason: ErrorReason) -> Response {
    (status, Json(json!({ "reason": reason }))).into_response()
}

pub(crate) fn err_missing_token(cause: MissingTokenCause) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({
            "reason": ErrorReason::MissingToken,
            "cause": cause,
            "detail": cause.detail(),
        })),
    )
        .into_response()
}

pub(crate) fn bearer_token(headers: &axum::http::HeaderMap) -> Result<&str, MissingTokenCause> {
    let authorization = headers
        .get(axum::http::header::AUTHORIZATION)
        .ok_or(MissingTokenCause::AuthorizationHeaderAbsent)?;
    let authorization = authorization
        .to_str()
        .map_err(|_| MissingTokenCause::AuthorizationHeaderInvalid)?;

    let mut fields = authorization.splitn(2, char::is_whitespace);
    let scheme = fields.next().unwrap_or_default();
    if !scheme.eq_ignore_ascii_case("Bearer") {
        return Err(MissingTokenCause::AuthorizationSchemeInvalid);
    }

    let token = fields.next().unwrap_or_default().trim();
    if token.is_empty() {
        return Err(MissingTokenCause::BearerTokenEmpty);
    }
    Ok(token)
}

#[cfg(test)]
mod auth_header_tests {
    use super::*;
    use axum::http::{header::AUTHORIZATION, HeaderMap, HeaderValue};

    #[test]
    fn non_text_authorization_header_has_a_distinct_cause() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_bytes(b"\xff").unwrap());
        assert_eq!(
            bearer_token(&headers),
            Err(MissingTokenCause::AuthorizationHeaderInvalid)
        );
    }
}

/// `Json` with the error contract applied. Axum's default body rejections
/// (missing Content-Type, malformed JSON, a missing field) are plain-text
/// 415/400/422 responses — a shape break exactly when a fumbling agent
/// needs the `{"reason", "detail"}` envelope most. Fold them all into
/// `400 {"reason": "invalid_json"}` with axum's diagnosis as the detail.
pub(crate) struct ApiJson<T>(pub(crate) T);

impl<T, S> axum::extract::FromRequest<S> for ApiJson<T>
where
    Json<T>: axum::extract::FromRequest<S, Rejection = axum::extract::rejection::JsonRejection>,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request(req: axum::extract::Request, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(value)) => Ok(ApiJson(value)),
            Err(rejection) => Err(err_detail(
                StatusCode::BAD_REQUEST,
                ErrorReason::InvalidJson,
                rejection.body_text(),
            )),
        }
    }
}

/// The capability endpoint that accepts calls naming a connection of this
/// kind — the "use this instead" half of `wrong_connection_type`, and the
/// per-entry `endpoint` field in the listing. The type→endpoint mapping should
/// not live only in prose.
fn endpoint_for(kind: ConnectionKind) -> &'static str {
    match kind {
        ConnectionKind::Api => "/v1/http",
        ConnectionKind::Ws => "/v1/ws/open",
        ConnectionKind::Pg => "/v1/pg/open",
        ConnectionKind::Ssh => "/v1/ssh/open",
    }
}

fn err_detail(status: StatusCode, reason: ErrorReason, detail: impl Into<String>) -> Response {
    (
        status,
        Json(json!({ "reason": reason, "detail": detail.into() })),
    )
        .into_response()
}

fn outcome_response(outcome: ExecOutcome) -> Response {
    let status = StatusCode::from_u16(outcome.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (status, Json(outcome.body)).into_response()
}

/// 429 with machine-actionable backoff: a `Retry-After` header (whole
/// seconds, rounded up) plus the same value in the body, so an agent knows
/// how long to wait instead of guessing.
fn err_rate_limited(reason: ErrorReason, retry_after: std::time::Duration) -> Response {
    let secs = (retry_after.as_secs() + u64::from(retry_after.subsec_nanos() > 0)).max(1);
    (
        StatusCode::TOO_MANY_REQUESTS,
        [(axum::http::header::RETRY_AFTER, secs.to_string())],
        Json(json!({ "reason": reason, "retry_after_seconds": secs })),
    )
        .into_response()
}

/// 404 for a connection name that isn't configured. The detail lists the
/// valid names, which the agent is entitled to via `GET /v1/connections`
/// anyway; naming them here saves the round trip when its list is stale.
fn err_unknown_connection(broker: &Arc<Broker>) -> Response {
    let names: Vec<String> = broker
        .store
        .list_connections()
        .into_iter()
        .map(|c| c.name)
        .collect();
    let detail = if names.is_empty() {
        "no connections are configured".to_string()
    } else {
        format!("configured connections: {}", names.join(", "))
    };
    err_detail(
        StatusCode::NOT_FOUND,
        ErrorReason::UnknownConnection,
        detail,
    )
}

/// The header a client may set to label itself in the activity log and the
/// sessions band. Self-reported and cosmetic — never authorization.
pub const CLIENT_LABEL_HEADER: &str = "x-agentmfa-client";

/// The label used when a client does not name itself.
pub const DEFAULT_CLIENT_LABEL: &str = "agent";

/// Bearer-token authentication against the shared broker key.
pub struct Authed {
    /// Self-reported client label (`X-AgentMFA-Client`), for attribution
    /// only.
    pub client: String,
    /// The identity's stable principal id.
    pub client_id: uuid::Uuid,
    /// The presented token was a legacy per-agent alias still riding the
    /// migration grace period.
    pub via_alias: bool,
}

impl FromRequestParts<AppState> for Authed {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = bearer_token(&parts.headers).map_err(err_missing_token)?;
        match state.broker.identity.verify(token) {
            Ok(verified) => {
                let client = parts
                    .headers
                    .get(CLIENT_LABEL_HEADER)
                    .and_then(|v| v.to_str().ok())
                    .map(str::trim)
                    .filter(|v| validate_agent_name(v))
                    .unwrap_or(DEFAULT_CLIENT_LABEL)
                    .to_string();
                Ok(Authed {
                    client,
                    client_id: verified.client_id,
                    via_alias: verified.via_alias,
                })
            }
            Err(e) => {
                if e == TokenError::Superseded {
                    // The key was rotated. Without this hint each 401 reads
                    // as a dead token; `store_at` names the exact file so
                    // recovery is mechanical, not prose-guided.
                    return Err((
                        StatusCode::UNAUTHORIZED,
                        Json(json!({
                            "reason": e.reason(),
                            "detail": "the broker key was rotated; \
                                       re-read the token file instead of treating this as fatal",
                            "store_at": state.broker.paths.token_display(),
                        })),
                    )
                        .into_response());
                }
                if e == TokenError::Invalid {
                    return Err(err_detail(
                        StatusCode::UNAUTHORIZED,
                        ErrorReason::InvalidToken,
                        "A bearer token reached the broker but was not recognized. \
                         Re-read the broker's token file, or POST /v1/pair to fetch the shared key.",
                    ));
                }
                Err(err(StatusCode::UNAUTHORIZED, e.reason()))
            }
        }
    }
}

/* ------------------------------- server ---------------------------------- */

/// A running daemon (control plane + WS bridge and PG proxy data planes);
/// dropping the handle stops all of them.
pub struct DaemonHandle {
    pub socket_path: PathBuf,
    /// The bound TCP control-plane address, when `--listen` asked for one.
    pub tcp_addr: Option<std::net::SocketAddr>,
    /// The WS bridge's ephemeral loopback port (tests need it; agents only
    /// ever see it inside open responses).
    pub ws_bridge_port: u16,
    /// The PG proxy's ephemeral loopback port (tests need it; agents only
    /// ever see it inside open responses' DSNs).
    pub pg_proxy_port: u16,
    task: tokio::task::JoinHandle<()>,
    tcp_task: Option<tokio::task::JoinHandle<()>>,
    bridge_task: tokio::task::JoinHandle<()>,
    proxy_task: tokio::task::JoinHandle<()>,
    // Declared last so serving tasks are aborted/dropped before the
    // rendezvous point is unlinked.
    _socket_guard: SocketGuard,
}

impl Drop for DaemonHandle {
    fn drop(&mut self) {
        self.task.abort();
        if let Some(task) = &self.tcp_task {
            task.abort();
        }
        self.bridge_task.abort();
        self.proxy_task.abort();
    }
}

/// How to serve beyond the Unix socket.
#[derive(Clone, Debug, Default)]
pub struct ServeOptions {
    /// Serve the control plane on this TCP address as well (for remote
    /// agents and the remote desktop shell, behind the operator's TLS
    /// proxy or tunnel). `/v1/pair` is refused on it.
    pub listen: Option<std::net::SocketAddr>,
    /// The URL remote clients reach the TCP listener at; advertised in
    /// TCP-served discovery documents.
    pub public_url: Option<String>,
    /// Bind the WS/PG data-plane proxies and API direct endpoints to this
    /// address instead of loopback (for remote agents on the LAN). The
    /// credential legs on these are plaintext, so a non-loopback value must
    /// sit behind a trusted network.
    pub data_plane_listen: Option<std::net::IpAddr>,
    /// The host put into returned data-plane URLs/DSNs — what a remote
    /// agent dials. Defaults to loopback.
    pub advertise_host: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SocketIdentity {
    device: u64,
    inode: u64,
}

impl SocketIdentity {
    fn from(metadata: &std::fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

/// Removes a socket only when the path still names the inode we observed.
/// The lifetime-held instance lock serializes cooperating brokers; this
/// identity check additionally prevents normal shutdown from unlinking a
/// socket that was manually replaced underneath it.
struct SocketGuard {
    path: PathBuf,
    identity: SocketIdentity,
    armed: bool,
}

impl SocketGuard {
    fn capture(path: PathBuf) -> io::Result<Self> {
        let metadata = std::fs::symlink_metadata(&path)?;
        if !metadata.file_type().is_socket() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{} is not a Unix socket", path.display()),
            ));
        }
        Ok(Self {
            path,
            identity: SocketIdentity::from(&metadata),
            armed: true,
        })
    }

    fn remove_if_owned(&mut self) -> io::Result<bool> {
        if !self.armed {
            return Ok(false);
        }
        let metadata = match std::fs::symlink_metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                self.armed = false;
                return Ok(false);
            }
            Err(error) => return Err(error),
        };
        if !metadata.file_type().is_socket() || SocketIdentity::from(&metadata) != self.identity {
            return Ok(false);
        }
        std::fs::remove_file(&self.path)?;
        self.armed = false;
        Ok(true)
    }
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        if let Err(error) = self.remove_if_owned() {
            tracing::warn!(
                "failed to clean up control socket {}: {error}",
                self.path.display()
            );
        }
    }
}

/// Inspect an existing rendezvous point while the owning [`Broker`] holds the
/// process lease. Only a socket node that rejects a connection with
/// `ECONNREFUSED` is considered stale. Unexpected probe errors and non-socket
/// files are preserved so startup cannot destroy state it does not understand.
async fn remove_stale_socket(
    socket_path: &std::path::Path,
    socket_display: String,
) -> crate::Result<()> {
    let metadata = match std::fs::symlink_metadata(socket_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(CoreError::Io(error)),
    };
    if !metadata.file_type().is_socket() {
        return Err(CoreError::Io(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "refusing to replace non-socket path {}",
                socket_path.display()
            ),
        )));
    }
    let identity = SocketIdentity::from(&metadata);
    match tokio::net::UnixStream::connect(socket_path).await {
        Ok(_) => Err(CoreError::BrokerAlreadyRunning(socket_display)),
        Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
            tracing::info!("removing stale socket {}", socket_path.display());
            let mut stale = SocketGuard {
                path: socket_path.to_path_buf(),
                identity,
                armed: true,
            };
            if !stale.remove_if_owned()? {
                return Err(CoreError::Io(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    format!(
                        "control socket {} changed while checking whether it was stale",
                        socket_path.display()
                    ),
                )));
            }
            Ok(())
        }
        // A concurrent non-broker actor may remove the path after metadata;
        // bind below is then safe. Any replacement will make bind fail rather
        // than being unlinked here.
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(CoreError::Io(io::Error::new(
            error.kind(),
            format!(
                "failed to probe existing control socket {}; refusing to remove it: {error}",
                socket_path.display()
            ),
        ))),
    }
}

pub fn router(broker: Arc<Broker>) -> Router {
    router_for(broker, Transport::Uds)
}

pub fn router_for(broker: Arc<Broker>, transport: Transport) -> Router {
    let body_cap = broker.config.request_cap;
    Router::new()
        .nest("/v1/manage", manage::router())
        .route("/.well-known/agent-broker.json", get(get_manifest))
        .route("/instructions", get(get_instructions))
        .route("/v1/pair", post(post_pair))
        .route("/v1/connections", get(get_connections))
        .route("/v1/whoami", get(get_whoami))
        .route("/v1/http", post(post_http))
        .route("/v1/connect-requests", post(post_connect_request))
        .route("/v1/ws/open", post(post_ws_open))
        .route("/v1/pg/open", post(post_pg_open))
        .route("/v1/ssh/open", post(post_ssh_open))
        // The sidecar's MCP endpoint, reverse-proxied so one address (and
        // one operator proxy rule) covers the whole broker. The sidecar
        // authorizes every request against the broker itself, so this
        // proxy adds reach, not authority.
        .route("/mcp", axum::routing::any(proxy_mcp))
        // JSON string bodies inflate the wire size (escaping, base64): give
        // the transport head-room; the decoded body cap is enforced exactly.
        .layer(DefaultBodyLimit::max(body_cap + body_cap / 2 + 1024 * 1024))
        .with_state(AppState {
            manage: Arc::new(crate::manage::LocalBackend::new(broker.clone())),
            broker,
            transport,
        })
}

/// Bind the control-plane socket and serve. [`Broker::new`] acquired the OS
/// process lease before opening any persistent state and the broker holds it
/// for its full lifetime. A socket left by a crashed broker is unlinked only
/// when it is still the observed inode and rejects a connection with the
/// expected stale-socket error.
pub async fn serve(broker: Arc<Broker>) -> crate::Result<DaemonHandle> {
    serve_with(broker, ServeOptions::default()).await
}

/// [`serve`] plus the optional TCP listener.
pub async fn serve_with(broker: Arc<Broker>, options: ServeOptions) -> crate::Result<DaemonHandle> {
    broker.set_data_plane_address(options.data_plane_listen, options.advertise_host.clone());
    if let Some(bind) = options.data_plane_listen {
        if !bind.is_loopback() {
            tracing::warn!(
                %bind,
                "data planes bound to a non-loopback address; the WS/PG \
                 credential legs are plaintext — keep this on a trusted \
                 network behind TLS/tunnel"
            );
        }
    }
    let paths = broker.paths.clone();
    paths.ensure()?;
    let socket_path = paths.socket_file();
    // Unix socket paths are capped at sun_path (104 bytes on macOS, 108 on
    // Linux). Checked up front with a diagnosis naming the path and the fix,
    // because the bind error it becomes otherwise ("path must be shorter
    // than SUN_LEN") names neither. 100 leaves margin for the per-open SSH
    // agent sockets, which live under the same directory with longer names.
    if socket_path.as_os_str().len() > 100 {
        return Err(CoreError::Io(std::io::Error::other(format!(
            "socket path {} is {} bytes; Unix sockets are limited to ~104 — \
             use a shorter --root",
            socket_path.display(),
            socket_path.as_os_str().len()
        ))));
    }
    remove_stale_socket(&socket_path, paths.socket_display()).await?;
    let listener = UnixListener::bind(&socket_path)?;
    let socket_guard = SocketGuard::capture(socket_path.clone())?;
    std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))?;
    // Per-open SSH agent sockets self-clean on their deadline; sweep any a
    // crashed broker left behind, mirroring the stale control-socket check
    // above.
    crate::capability::ssh::sweep_stale_sockets(&paths.ssh_agent_dir());
    // The optional TCP control-plane listener is bound before any serving
    // task starts: a bad --listen address fails startup as a diagnosis, and
    // a failure past this point must not leave live data-plane tasks behind
    // (a dropped JoinHandle detaches its task rather than aborting it).
    let tcp_listener = match &options.listen {
        Some(addr) => {
            let tcp_listener = tokio::net::TcpListener::bind(addr).await?;
            let bound = tcp_listener.local_addr()?;
            if !bound.ip().is_loopback() {
                tracing::warn!(
                    %bound,
                    "control plane bound to a non-loopback address; every \
                     network client with the key can use enabled tools — \
                     front this with TLS (proxy or tunnel)"
                );
            }
            Some((tcp_listener, bound))
        }
        None => None,
    };
    // The WS bridge data plane: loopback-only, OS-assigned port.
    let (ws_bridge_port, bridge_task) = crate::capability::ws::start_bridge(broker.clone()).await?;
    let _ = broker.ws_bridge_port.set(ws_bridge_port);
    // The PG proxy data plane: loopback-only, OS-assigned port.
    let (pg_proxy_port, proxy_task) = match crate::capability::pg::start_proxy(broker.clone()).await
    {
        Ok(started) => started,
        Err(error) => {
            // A dropped JoinHandle detaches its task. Abort explicitly so
            // a partial startup cannot leave a loopback bridge behind.
            bridge_task.abort();
            return Err(CoreError::Io(error));
        }
    };
    let _ = broker.pg_proxy_port.set(pg_proxy_port);
    // Re-establish per-wiring direct-endpoint listeners persisted from a prior
    // run, so a stable DSN survives a broker restart with no agent lifecycle.
    broker.rebind_endpoints().await;

    // The TCP listener (bound above) serves the same router, marked so
    // pairing is refused and discovery renders for network clients.
    broker.set_public_url(options.public_url.clone());
    let (tcp_addr, tcp_task) = match tcp_listener {
        Some((tcp_listener, bound)) => {
            let tcp_app = router_for(
                broker.clone(),
                Transport::Tcp {
                    public_url: options.public_url.clone().map(Arc::from),
                },
            );
            let task = tokio::spawn(async move {
                if let Err(e) = axum::serve(tcp_listener, tcp_app).await {
                    tracing::error!("tcp control plane exited: {e}");
                }
            });
            (Some(bound), Some(task))
        }
        None => (None, None),
    };

    let app = router(broker);
    let task = tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            tracing::error!("daemon exited: {e}");
        }
    });
    Ok(DaemonHandle {
        socket_path,
        tcp_addr,
        ws_bridge_port,
        pg_proxy_port,
        task,
        tcp_task,
        bridge_task,
        proxy_task,
        _socket_guard: socket_guard,
    })
}

/* ------------------------------ discovery -------------------------------- */

async fn get_manifest(State(state): State<AppState>) -> Response {
    if let Err(wait) = state.broker.discovery_limiter.check() {
        return err_rate_limited(ErrorReason::RateLimited, wait);
    }
    if state.transport.is_tcp() {
        return Json(wellknown::manifest_remote(
            &state.broker.config,
            state.transport.public_url(),
            state.broker.sidecar_mcp_url().is_some(),
        ))
        .into_response();
    }
    Json(wellknown::manifest(
        &state.broker.config,
        &state.broker.paths,
        state.broker.sidecar_mcp_url(),
    ))
    .into_response()
}

async fn get_instructions(State(state): State<AppState>) -> Response {
    if let Err(wait) = state.broker.discovery_limiter.check() {
        return err_rate_limited(ErrorReason::RateLimited, wait);
    }
    let mut body = String::new();
    if state.transport.is_tcp() {
        body.push_str(&wellknown::remote_instructions_banner(
            state.transport.public_url(),
            state.broker.data_plane_advertised().as_deref(),
        ));
    }
    body.push_str(&wellknown::instructions(
        &state.broker.config,
        &state.broker.paths,
    ));
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/markdown; charset=utf-8",
        )],
        body,
    )
        .into_response()
}

/* -------------------------------- pairing -------------------------------- */

#[derive(Deserialize)]
struct PairBody {
    agent_name: String,
}

async fn post_pair(State(state): State<AppState>, ApiJson(body): ApiJson<PairBody>) -> Response {
    // Pairing is an unauthenticated key-dispenser, acceptable only behind
    // the 0600 socket's filesystem gate. A network listener must never
    // hand the key to whoever connects.
    if state.transport.is_tcp() {
        return err_detail(
            StatusCode::NOT_FOUND,
            ErrorReason::NotServedRemotely,
            "pairing is not served remotely; obtain this broker's shared key \
             from its operator",
        );
    }
    let broker = &state.broker;
    if let Err(wait) = broker.pairing_limiter.check() {
        return err_rate_limited(ErrorReason::PairingRateLimited, wait);
    }
    let name = body.agent_name.trim().to_string();
    if !validate_agent_name(&name) {
        return err_detail(
            StatusCode::BAD_REQUEST,
            ErrorReason::InvalidAgentName,
            "1-64 chars of [A-Za-z0-9._-]",
        );
    }

    // Compat shim from the per-agent era: there is one shared key for every
    // local agent, and "pairing" hands it back. Unauthenticated on a 0600
    // socket, which is exactly the pre-collapse trust model made honest —
    // per-agent pairing was never gated either, so any local process could
    // always mint itself a token. The name is recorded as an activity label
    // only; agents that can read the token file directly never need this.
    broker.identity.touch();
    broker.audit.append(
        AuditEntry::new(AuditKind::Paired, format!("Agent connected: {name}"))
            .agent(name.clone())
            .outcome("paired"),
    );
    broker.events.agents_changed();
    (
        StatusCode::OK,
        Json(json!({
            "token": broker.identity.token(),
            "client_id": broker.identity.client_id(),
            // Echo what was registered, so the agent can log its own
            // enrollment without a follow-up /v1/whoami.
            "agent": name,
            "expires_after_days": broker.config.token_ttl.as_secs() / 86400,
            // The storage guidance travels with the credential, not just in
            // prose: the shared key already lives at this path, so agents
            // that can read files skip pairing entirely.
            "store_at": broker.paths.token_display(),
        })),
    )
        .into_response()
}

/* ------------------------- connection listing ----------------------------- */

async fn get_connections(State(state): State<AppState>, authed: Authed) -> Response {
    let broker = &state.broker;
    if let Err(wait) = broker.token_limiter.check(&authed.client_id.to_string()) {
        return err_rate_limited(ErrorReason::RateLimited, wait);
    }
    // The one authenticated endpoint that bypasses the access check by
    // design, an agent must see what exists (and what is enabled).
    // Audited.
    broker.audit.append(
        AuditEntry::new(
            AuditKind::Listed,
            format!("{} listed connections", authed.client),
        )
        .agent(authed.client.clone()),
    );
    let list: Vec<serde_json::Value> = broker
        .store
        .list_connections()
        .into_iter()
        .map(|c| {
            let mut row = json!({
                "name": c.name,
                "type": c.kind().as_str(),
                "target": c.target(),
                // Where a call naming this connection goes; the
                // type→endpoint mapping shouldn't live only in prose.
                "endpoint": endpoint_for(c.kind()),
                // Whether agents may use the connection. Disabled
                // connections are visible but refused; the user flips
                // access in the app.
                "wired": broker.access.allows(&c.id),
            });
            // Present only when this upstream speaks MCP, so the payload
            // stays exactly as it was for every other connection.
            if let ConnectionConfig::Api {
                mcp_path: Some(path),
                ..
            } = &c.config
            {
                row["mcp_path"] = json!(path);
                // The curated tool subset, when one is set; the broker
                // enforces it on tools/call, this field lets the sidecar
                // list only what is callable.
                if let Some(tools) = broker.access.allowed_tools(&c.id) {
                    row["allowed_tools"] = json!(tools);
                }
            }
            row
        })
        .collect();
    Json(list).into_response()
}

/// `GET /v1/whoami`: a cheap probe for the reuse-then-pair startup flow.
/// Validating a stored token used to require a real capability call, which
/// spammed the audit trail with health checks; this endpoint is deliberately
/// not audited on success (failures are audited by the extractor like any
/// other call).
///
/// Deliberately exempt from the per-client capability limiter. The MCP sidecar
/// resolves the agent's token here on *every* request it serves (no caching,
/// so a revoked token stops working at once), so charging whoami against the
/// 60/min budget would halve an agent's real tool-call rate and surface as a
/// mystifying rate-limit. This is safe because whoami is read-only, cheap, and
/// already fronted by the 0600 socket's own access ceiling — it grants nothing
/// a capability call would, so it needs no throttle of its own.
async fn get_whoami(State(state): State<AppState>, authed: Authed) -> Response {
    let broker = &state.broker;
    let identity = broker.identity.info();
    let expires_at = identity.last_used
        + chrono::Duration::from_std(broker.config.token_ttl)
            .unwrap_or_else(|_| chrono::Duration::days(30));
    let mut body = json!({
        "client_id": authed.client_id,
        "agent": authed.client,
        "paired_at": identity.minted_at,
        // The sliding TTL's current horizon; refreshed on every
        // authenticated call.
        "expires_at": expires_at,
    });
    if authed.via_alias {
        // A legacy per-agent token riding the migration grace period: it
        // works, and it dies at the first rotation. Steer its holder to the
        // shared key file while everything is still green.
        body["token_deprecated"] = json!(true);
        body["store_at"] = json!(broker.paths.token_display());
    }
    Json(body).into_response()
}

/* ------------------------------ HTTP call --------------------------------- */

#[derive(Deserialize)]
struct HttpCallBody {
    connection: String,
    method: String,
    path: String,
    #[serde(default)]
    headers: HashMap<String, String>,
    /// JSON string → raw bytes; object/array → serialized JSON.
    #[serde(default)]
    body: Option<serde_json::Value>,
    /// Binary alternative to `body`.
    #[serde(default)]
    body_base64: Option<String>,
    /// Idempotency key: coalesces retried mutating calls.
    #[serde(default)]
    request_id: Option<String>,
}

fn request_id_error(request_id: Option<&str>) -> Option<Response> {
    if let Some(request_id) = request_id {
        if request_id.len() > REQUEST_ID_MAX_BYTES {
            return Some(err_detail(
                StatusCode::BAD_REQUEST,
                ErrorReason::InvalidBody,
                format!(
                    "request_id is {} UTF-8 bytes; the maximum is {REQUEST_ID_MAX_BYTES}",
                    request_id.len()
                ),
            ));
        }
    }
    None
}

async fn post_http(
    State(state): State<AppState>,
    authed: Authed,
    ApiJson(call): ApiJson<HttpCallBody>,
) -> Response {
    let broker = &state.broker;
    let limiter_key = authed.client_id.to_string();
    let client = authed.client;
    if let Err(wait) = broker.token_limiter.check(&limiter_key) {
        broker.audit.append(
            AuditEntry::new(AuditKind::RateLimited, format!("Rate limited: {client}"))
                .agent(client.clone()),
        );
        return err_rate_limited(ErrorReason::RateLimited, wait);
    }
    if let Some(response) = request_id_error(call.request_id.as_deref()) {
        return response;
    }

    // Resolve the connection: it supplies the *where* and the credential.
    let Some(conn) = broker.store.connection_by_name(&call.connection) else {
        return err_unknown_connection(broker);
    };
    if conn.kind() != ConnectionKind::Api {
        return err_detail(
            StatusCode::BAD_REQUEST,
            ErrorReason::WrongConnectionType,
            format!(
                "{} is a {} connection; use POST {}",
                conn.name,
                conn.kind().as_str(),
                endpoint_for(conn.kind())
            ),
        );
    }
    let ConnectionConfig::Api { template, .. } = &conn.config else {
        unreachable!()
    };

    // Validate the *what* before touching the wiring or executing.
    let method = match parse_method(&call.method) {
        Ok(m) => m,
        Err(e) => return err_detail(StatusCode::BAD_REQUEST, e.reason(), e.detail()),
    };
    if let Err(e) = validate_path(&call.path) {
        return err_detail(StatusCode::BAD_REQUEST, e.reason(), e.detail());
    }
    let credential_header = if matches!(&conn.config, ConnectionConfig::Api { oauth: Some(_), .. })
    {
        Some("authorization".to_string())
    } else {
        match injection_form(template) {
            Some(InjectionForm::Header { name }) => Some(name),
            Some(InjectionForm::Query) => None,
            // An empty template is a credential-less connection: nothing is
            // injected, so there is no reserved credential header.
            None if template.trim().is_empty() => None,
            None => {
                return err_detail(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    ErrorReason::BadConnectionConfig,
                    "connection template is neither a header line nor a query form",
                )
            }
        }
    };
    let wire_headers: Vec<(String, String)> = call.headers.clone().into_iter().collect();
    let header_map = match validate_headers(&wire_headers, credential_header.as_deref()) {
        Ok(map) => map,
        Err(e) => {
            let status = StatusCode::BAD_REQUEST;
            return err_detail(status, e.reason(), e.detail());
        }
    };

    // Decode the body: JSON string, JSON value, or base64 binary.
    let body_bytes: Vec<u8> = match (&call.body, &call.body_base64) {
        (Some(_), Some(_)) => {
            return err_detail(
                StatusCode::BAD_REQUEST,
                ErrorReason::InvalidBody,
                "send body or body_base64, not both",
            )
        }
        (Some(serde_json::Value::Null), None) | (None, None) => Vec::new(),
        (Some(serde_json::Value::String(s)), None) => s.clone().into_bytes(),
        (Some(other), None) => serde_json::to_vec(other).unwrap_or_default(),
        (None, Some(b64)) => {
            use base64::Engine as _;
            match base64::engine::general_purpose::STANDARD.decode(b64) {
                Ok(bytes) => bytes,
                Err(e) => {
                    return err_detail(
                        StatusCode::BAD_REQUEST,
                        ErrorReason::InvalidBody,
                        e.to_string(),
                    )
                }
            }
        }
    };
    if body_bytes.len() > broker.config.request_cap {
        return err_detail(
            StatusCode::PAYLOAD_TOO_LARGE,
            ErrorReason::RequestTooLarge,
            format!("request body cap is {} bytes", broker.config.request_cap),
        );
    }

    // A curated MCP wiring: `tools/call` for a tool outside the allowed
    // subset is refused here, at the same trust boundary as the wiring
    // check itself — the sidecar's filtered listing is a mirror, not the
    // enforcement.
    let on_mcp_path = match &conn.config {
        ConnectionConfig::Api {
            mcp_path: Some(mcp_path),
            ..
        } => call.path.split('?').next().unwrap_or("") == mcp_path.split('?').next().unwrap_or(""),
        _ => false,
    };
    let allowed_tools_snapshot = broker.access.allowed_tools(&conn.id);
    if let ConnectionConfig::Api {
        mcp_path: Some(mcp_path),
        ..
    } = &conn.config
    {
        let call_path = call.path.split('?').next().unwrap_or("");
        let pinned_path = mcp_path.split('?').next().unwrap_or("");
        if call_path == pinned_path {
            if let Some(allowed) = allowed_tools_snapshot.as_ref() {
                if let Some(tool) = disallowed_mcp_tool_call(&body_bytes, allowed) {
                    broker.audit.append(
                        AuditEntry::new(
                            AuditKind::Denied,
                            format!(
                                "Refused (tool not enabled): {client} → {} · {tool}",
                                conn.name
                            ),
                        )
                        .agent(client.clone())
                        .connection(conn.name.clone())
                        .outcome("denied_by_policy"),
                    );
                    return err_detail(
                        StatusCode::FORBIDDEN,
                        ErrorReason::DeniedByPolicy,
                        format!(
                            "the tool {tool:?} is not enabled on {}; the user can enable it in AgentMFA",
                            conn.name
                        ),
                    );
                }
            }
        }
    }
    // Parse and describe MCP traffic only when this request arrived with the
    // switch on. The historical/default off path should not pay an extra
    // full-body JSON parse for a feature it is not using.
    let approval = broker
        .access
        .confirm_mode(&conn.id)
        .is_on()
        .then(|| {
            approval_for_call(
                &conn,
                &client,
                &method,
                &call.path,
                &header_map,
                &body_bytes,
            )
        })
        .flatten();
    let hash = payload_hash(&conn.id, &method, &call.path, &wire_headers, &body_bytes);
    let body = match SpooledBody::from_bytes(body_bytes, broker.config.spool_threshold) {
        Ok(b) => Arc::new(b),
        Err(e) => {
            return err_detail(
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorReason::SpoolFailed,
                e.to_string(),
            )
        }
    };

    let mutating = is_mutating(&method);

    // Coalescing is keyed on (client label, request_id) for mutating calls
    // only; GET/HEAD are never coalesced, a request_id there is ignored.
    let coalesce_key = match (&call.request_id, mutating) {
        (Some(rid), true) => Some((client.clone(), rid.clone())),
        _ => None,
    };
    let payload_hash = coalesce_key.as_ref().map(|_| hash);

    let executor = HttpExecution {
        store: broker.store.clone(),
        audit: broker.audit.clone(),
        client: broker.http_client.clone(),
        config: broker.config.clone(),
        agent: client.clone(),
        connection: conn.clone(),
        method,
        path: call.path.clone(),
        headers: header_map,
        body: body.clone(),
        health: Some(broker.health.clone()),
    };
    let executor: crate::executions::Executor = Box::pin(executor.run());
    let access = broker.access.clone();
    let approvals = broker.approvals.clone();
    let connection_id = conn.id;
    let executor: crate::executions::Executor = Box::pin(async move {
        if on_mcp_path && access.allowed_tools(&connection_id) != allowed_tools_snapshot {
            // A subset change that raced just ahead of prompt insertion may
            // have found no pending prompt to revoke. Refuse this snapshot
            // and close any window its stale answer opened.
            approvals.revoke(&connection_id);
            return ExecOutcome::refusal(ErrorReason::DeniedByPolicy);
        }
        executor.await
    });

    run_allowed(
        broker,
        &client,
        &conn,
        approval,
        ExecRequest {
            coalesce_key,
            payload_hash,
            executor,
        },
    )
    .await
}

/// `POST /v1/connect-requests`: an agent asks for a service that is not
/// configured. Advisory only — the broker audits it and pokes the shell;
/// the user adds and wires the tool (or doesn't) in the app.
async fn post_connect_request(
    State(state): State<AppState>,
    authed: Authed,
    body: axum::Json<serde_json::Value>,
) -> Response {
    let broker = &state.broker;
    let Some(service) = body.0.get("service").and_then(|v| v.as_str()) else {
        return err_detail(
            StatusCode::BAD_REQUEST,
            ErrorReason::InvalidBody,
            "a `service` string is required",
        );
    };
    match broker.agent_connect_request(&authed.client, service) {
        Ok(fresh) => (
            StatusCode::ACCEPTED,
            Json(serde_json::json!({
                "status": if fresh { "requested" } else { "already_requested" },
                "detail": "Ask the user to add and wire this tool in AgentMFA; \
                           its tools appear once they do.",
            })),
        )
            .into_response(),
        Err(error) => err_detail(
            StatusCode::BAD_REQUEST,
            ErrorReason::InvalidBody,
            error.to_string(),
        ),
    }
}

/// The first JSON-RPC `tools/call` outside a curated subset, including calls
/// in a batch. Compare while the parsed value is alive so a malicious
/// request cannot make us clone a request-sized tool name just to reject it.
fn disallowed_mcp_tool_call(body: &[u8], allowed: &[String]) -> Option<String> {
    fn from_request(value: &serde_json::Value, allowed: &[String]) -> Option<String> {
        if value.get("method").and_then(|method| method.as_str()) != Some("tools/call") {
            return None;
        }
        let tool = value.pointer("/params/name").and_then(|name| name.as_str());
        if tool.is_some_and(|tool| allowed.iter().any(|name| name == tool)) {
            return None;
        }
        Some(crate::approvals::capped_text(
            tool.unwrap_or("(unnamed tool)"),
        ))
    }

    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return None;
    };
    match value {
        serde_json::Value::Array(requests) => requests
            .iter()
            .find_map(|request| from_request(request, allowed)),
        request => from_request(&request, allowed),
    }
}

/// How much of a body or an argument list the prompt shows. Enough to
/// recognize the call, far short of a payload dump.
const APPROVAL_PREVIEW_CAP: usize = 400;
const APPROVAL_PREVIEW_SCAN_CAP: usize = APPROVAL_PREVIEW_CAP * 4 + 4;
/// Parsing a large MCP body solely to label an approval prompt would create
/// a second full JSON tree beside the already-decoded HTTP call. Large calls
/// receive the same bounded generic request description instead.
const APPROVAL_RPC_PARSE_CAP: usize = 1024 * 1024;

fn preview_bytes(bytes: &[u8]) -> String {
    preview_bytes_with_tail(bytes, false)
}

fn preview_bytes_with_tail(bytes: &[u8], has_unscanned_tail: bool) -> String {
    // Never lossy-convert the full (potentially 150 MiB) request just to show
    // 400 characters. Four bytes per scalar plus a small boundary cushion is
    // enough to decide the preview.
    let scanned = bytes.len().min(APPROVAL_PREVIEW_SCAN_CAP);
    let text = String::from_utf8_lossy(&bytes[..scanned]);
    let mut chars = text.chars();
    let head: String = chars.by_ref().take(APPROVAL_PREVIEW_CAP).collect();
    if has_unscanned_tail || scanned < bytes.len() || chars.next().is_some() {
        format!("{head}…")
    } else {
        head
    }
}

fn preview_json(value: &serde_json::Value) -> String {
    struct PrefixWriter {
        bytes: Vec<u8>,
        truncated: bool,
    }
    impl std::io::Write for PrefixWriter {
        fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
            let remaining = APPROVAL_PREVIEW_SCAN_CAP.saturating_sub(self.bytes.len());
            if remaining == 0 {
                self.truncated |= !input.is_empty();
                return Err(std::io::Error::other("approval preview is full"));
            }
            let written = input.len().min(remaining);
            self.bytes.extend_from_slice(&input[..written]);
            self.truncated |= written < input.len();
            Ok(written)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let mut writer = PrefixWriter {
        bytes: Vec::with_capacity(APPROVAL_PREVIEW_SCAN_CAP),
        truncated: false,
    };
    let _ = serde_json::to_writer(&mut writer, value);
    preview_bytes_with_tail(&writer.bytes, writer.truncated)
}

/// MCP requests that are session plumbing rather than the agent's actual
/// work. They reach the upstream for metadata only, and every tool call is
/// wrapped in a fresh `initialize`/teardown pair, so prompting on them
/// would ask three times per call and again on every listing.
fn is_mcp_envelope(method: &str) -> bool {
    matches!(
        method,
        "initialize"
            | "ping"
            | "tools/list"
            | "resources/list"
            | "resources/templates/list"
            | "prompts/list"
            // Argument autocompletion is metadata the host fires as the user
            // types; prompting on each keystroke would be unusable, and it
            // reads nothing a list call does not. `resources/read` is left
            // out on purpose — that one is real data access and is confirmed.
            | "completion/complete"
            | "notifications/initialized"
            | "notifications/cancelled"
            | "notifications/progress"
            | "notifications/roots/list_changed"
    )
}

/// What the user is asked about for one `/v1/http` call, or `None` when the
/// call raises no question.
///
/// For a plain API tool that is the request itself. For an MCP tool it is
/// the `tools/call` — but only calls to the *pinned* MCP path are read as
/// MCP; a request the agent aims somewhere else on the same host is
/// ordinary traffic to a credentialed destination, and is asked about as
/// such rather than waved through for looking like plumbing.
fn approval_for_call(
    conn: &crate::types::Connection,
    client: &str,
    method: &http::Method,
    path: &str,
    headers: &http::HeaderMap,
    body: &[u8],
) -> Option<crate::approvals::ApprovalRequest> {
    use crate::approvals::{capped_text, ApprovalRequest};
    let mcp_path = match &conn.config {
        ConnectionConfig::Api { mcp_path, .. } => mcp_path.clone(),
        _ => None,
    };
    let on_mcp_path = mcp_path.as_deref().is_some_and(|pinned| {
        path.split('?').next().unwrap_or("") == pinned.split('?').next().unwrap_or("")
    });
    if !on_mcp_path {
        let request = ApprovalRequest::new(conn, client, format!("{method} {}", capped_text(path)));
        return Some(if body.is_empty() {
            request
        } else {
            request.detail(preview_bytes(body))
        });
    }
    if crate::capability::http::is_mcp_transport_leg(conn, method, path, headers, body.is_empty()) {
        return None;
    }
    let generic = || {
        ApprovalRequest::new(conn, client, format!("{method} {}", capped_text(path)))
            .maybe_detail((!body.is_empty()).then(|| preview_bytes(body)))
    };
    if body.len() > APPROVAL_RPC_PARSE_CAP {
        return Some(generic());
    }
    let Ok(rpc) = serde_json::from_slice::<serde_json::Value>(body) else {
        return Some(generic());
    };
    // A batch authorizes one HTTP request carrying several RPC messages.
    // Name its first methods and the total rather than making the user infer
    // everything from a raw prefix that a later call could hide behind.
    if let Some(batch) = rpc.as_array() {
        let methods: Vec<String> = batch
            .iter()
            // A malicious batch with millions of non-request values must
            // not make prompt construction walk it all looking for a label.
            .take(16)
            .filter_map(|request| request.get("method").and_then(|method| method.as_str()))
            .take(4)
            .map(|method| {
                let mut method = capped_text(method);
                if let Some((cutoff, _)) = method.char_indices().nth(60) {
                    method.truncate(cutoff);
                    method.push('…');
                }
                method
            })
            .collect();
        let summary = if methods.is_empty() {
            format!("MCP batch ({} messages)", batch.len())
        } else {
            let omitted = if batch.len() > methods.len() {
                ", …"
            } else {
                ""
            };
            format!(
                "MCP batch ({} messages): {}{omitted}",
                batch.len(),
                methods.join(", "),
            )
        };
        return Some(
            ApprovalRequest::new(conn, client, summary)
                .maybe_detail((!body.is_empty()).then(|| preview_bytes(body))),
        );
    }
    if rpc.get("jsonrpc").and_then(|value| value.as_str()) != Some("2.0") {
        return Some(generic());
    }
    let Some(rpc_method) = rpc.get("method").and_then(|m| m.as_str()) else {
        return Some(generic());
    };
    if is_mcp_envelope(rpc_method) {
        return None;
    }
    if rpc_method == "tools/call" {
        let tool = capped_text(
            rpc.get("params")
                .and_then(|p| p.get("name"))
                .and_then(|n| n.as_str())
                .unwrap_or("(unnamed tool)"),
        );
        let arguments = rpc
            .get("params")
            .and_then(|p| p.get("arguments"))
            .filter(|args| !matches!(args, serde_json::Value::Null))
            .map(preview_json);
        return Some(
            ApprovalRequest::new(conn, client, tool)
                .tool()
                .maybe_detail(arguments),
        );
    }
    let params = rpc
        .get("params")
        .filter(|params| !matches!(params, serde_json::Value::Null))
        .map(preview_json);
    Some(ApprovalRequest::new(conn, client, capped_text(rpc_method)).maybe_detail(params))
}

/// The response a refused call gets: the machine reason it can branch on,
/// plus prose naming what to do about it.
fn approval_refusal(verdict: crate::approvals::Verdict, connection: &str) -> ExecOutcome {
    let reason = verdict
        .reason()
        .unwrap_or(crate::wire::ErrorReason::ApprovalDenied);
    let status = match verdict {
        crate::approvals::Verdict::TimedOut => 408,
        _ => 403,
    };
    ExecOutcome {
        status,
        body: json!({
            "reason": reason,
            "detail": format!("{} on {connection}", verdict.detail()),
        }),
    }
}

/// Shared capability tail: an enabled connection executes immediately
/// (retries still coalesce under their idempotency key); a disabled one is
/// refused.
///
/// `approval` describes the traffic for the confirmation prompt, and is
/// `None` for calls that raise no question — MCP session plumbing, and the
/// data-plane opens, which only mint a capability. Postgres is confirmed
/// where it actually connects, in the proxy, not at the open that hands out
/// its ticket: a ticket may be minted and never used, and one ticket can
/// open many sessions.
async fn run_allowed(
    broker: &Arc<Broker>,
    client: &str,
    conn: &crate::types::Connection,
    approval: Option<crate::approvals::ApprovalRequest>,
    exec: ExecRequest,
) -> Response {
    if !broker.access.allows(&conn.id) {
        broker.audit.append(
            AuditEntry::new(
                AuditKind::Denied,
                format!("Refused (agents disabled): {client} → {}", conn.name),
            )
            .agent(client.to_string())
            .connection(conn.name.clone())
            .outcome("denied_by_policy"),
        );
        return err_detail(
            StatusCode::FORBIDDEN,
            ErrorReason::DeniedByPolicy,
            format!(
                "{} is not enabled for agents; the user can enable it in AgentMFA",
                conn.name
            ),
        );
    }

    // Re-check at the actual execution boundary. Access can change after the
    // request-level check above, especially while a confirmed call is parked.
    let access = broker.access.clone();
    let store = broker.store.clone();
    let approvals = broker.approvals.clone();
    let connection_id = conn.id;
    let expected_version = conn.updated_at;
    let executor = exec.executor;
    let exec = ExecRequest {
        executor: Box::pin(async move {
            let connection_is_current = store
                .connection_by_id(&connection_id)
                .is_ok_and(|current| current.updated_at == expected_version);
            if !connection_is_current {
                // A stale prompt may just have opened a window after a
                // retarget raced ahead of its insertion. Do not let that
                // grant cover the replacement authority.
                approvals.revoke(&connection_id);
                return ExecOutcome::refusal(ErrorReason::DeniedByPolicy);
            }
            if !access.allows(&connection_id) {
                return ExecOutcome::refusal(ErrorReason::DeniedByPolicy);
            }
            executor.await
        }),
        ..exec
    };

    // Park on the user's decision *inside* the execution, so a retry
    // re-sending the same `request_id` joins the wait instead of raising a
    // second prompt for work that is already being asked about.
    let exec = match approval {
        Some(request) if broker.access.confirm_mode(&conn.id).is_on() => {
            let approvals = broker.approvals.clone();
            let access = broker.access.clone();
            let store = broker.store.clone();
            let connection_id = conn.id;
            let expected_version = conn.updated_at;
            let connection = conn.name.clone();
            let executor = exec.executor;
            ExecRequest {
                executor: Box::pin(async move {
                    // Close the race where disabling the connection happened
                    // after the outer check, or where the connection was
                    // changed just before this prompt was inserted (and so
                    // neither revocation could find it yet).
                    let connection_is_current = store
                        .connection_by_id(&connection_id)
                        .is_ok_and(|current| current.updated_at == expected_version);
                    if !access.allows(&connection_id) || !connection_is_current {
                        return ExecOutcome::refusal(ErrorReason::DeniedByPolicy);
                    }
                    let verdict = approvals.gate(request).await;
                    if !verdict.is_allowed() {
                        return approval_refusal(verdict, &connection);
                    }
                    executor.await
                }),
                ..exec
            }
        }
        _ => exec,
    };

    match broker.executions.run(exec) {
        Ok(Execution::Wait(handle)) => match handle.wait().await {
            Some(outcome) => outcome_response(outcome),
            None => err(
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorReason::BrokerShutdown,
            ),
        },
        Ok(Execution::Replay(outcome)) => outcome_response(outcome),
        Err(ExecError::RequestIdMismatch) => {
            err(StatusCode::CONFLICT, ErrorReason::RequestIdMismatch)
        }
        Err(ExecError::OutcomeNotReplayable) => {
            err(StatusCode::CONFLICT, ErrorReason::OutcomeNotReplayable)
        }
        Err(ExecError::IdempotencyCapacity) => err(
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorReason::IdempotencyCapacity,
        ),
    }
}

/* ------------------------------ MCP proxy --------------------------------- */

/// Header fields owned by the transport on each leg; never forwarded.
fn hop_by_hop(name: &str) -> bool {
    matches!(
        name,
        "host"
            | "connection"
            | "content-length"
            | "transfer-encoding"
            | "keep-alive"
            | "upgrade"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
    )
}

/// Reverse-proxy `/mcp` to the sidecar's loopback MCP endpoint, so one
/// address (and one operator proxy rule) covers the whole broker for
/// remote agents. The sidecar authorizes every request against the broker
/// itself (the bearer rides through untouched), so this adds reach, not
/// authority. Streaming both ways: MCP's streamable-HTTP GET leg is a
/// long-lived event stream.
async fn proxy_mcp(State(state): State<AppState>, request: axum::extract::Request) -> Response {
    let Some(target) = state.broker.sidecar_mcp_url() else {
        return err_detail(
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorReason::McpUnavailable,
            "the broker's MCP host is not running",
        );
    };
    let (parts, body) = request.into_parts();
    let mut url = target;
    if let Some(query) = parts.uri.query() {
        url.push('?');
        url.push_str(query);
    }
    let mut headers = axum::http::HeaderMap::new();
    for (name, value) in parts.headers.iter() {
        if hop_by_hop(name.as_str()) {
            continue;
        }
        // append, not insert: iteration yields one entry per value, and a
        // repeated field must keep all of them.
        headers.append(name.clone(), value.clone());
    }
    let stream = http_body_util::BodyDataStream::new(body);
    let upstream = state
        .broker
        .http_client
        .request(parts.method.clone(), url)
        .headers(headers)
        .body(reqwest::Body::wrap_stream(stream))
        .send()
        .await;
    match upstream {
        Ok(upstream) => {
            let status = upstream.status();
            let mut builder = Response::builder().status(status);
            for (name, value) in upstream.headers() {
                if hop_by_hop(name.as_str()) {
                    continue;
                }
                builder = builder.header(name, value);
            }
            builder
                .body(axum::body::Body::from_stream(upstream.bytes_stream()))
                .unwrap_or_else(|_| err(StatusCode::BAD_GATEWAY, ErrorReason::UpstreamError))
        }
        Err(error) => err_detail(
            StatusCode::BAD_GATEWAY,
            ErrorReason::UpstreamConnectFailed,
            error.to_string(),
        ),
    }
}

/* ------------------------------ WS open ----------------------------------- */

#[derive(Deserialize)]
struct OpenBody {
    connection: String,
    /// Idempotency key, session-creating opens coalesce like mutating
    /// calls.
    #[serde(default)]
    request_id: Option<String>,
}

async fn post_ws_open(
    State(state): State<AppState>,
    authed: Authed,
    ApiJson(body): ApiJson<OpenBody>,
) -> Response {
    let broker = &state.broker;
    let limiter_key = authed.client_id.to_string();
    let client = authed.client;
    if let Err(wait) = broker.token_limiter.check(&limiter_key) {
        return err_rate_limited(ErrorReason::RateLimited, wait);
    }
    if let Some(response) = request_id_error(body.request_id.as_deref()) {
        return response;
    }
    let Some(conn) = broker.store.connection_by_name(&body.connection) else {
        return err_unknown_connection(broker);
    };
    if conn.kind() != ConnectionKind::Ws {
        return err_detail(
            StatusCode::BAD_REQUEST,
            ErrorReason::WrongConnectionType,
            format!(
                "{} is a {} connection; use POST {}",
                conn.name,
                conn.kind().as_str(),
                endpoint_for(conn.kind())
            ),
        );
    }
    let Some(&bridge_port) = broker.ws_bridge_port.get() else {
        return err(
            StatusCode::INTERNAL_SERVER_ERROR,
            ErrorReason::BridgeNotRunning,
        );
    };

    // The idempotency payload is the open itself: same key + same
    // connection = a genuine retry.
    let coalesce_key = body
        .request_id
        .as_ref()
        .map(|rid| (client.clone(), rid.clone()));
    let payload_hash = coalesce_key.as_ref().map(|_| {
        use sha2::{Digest as _, Sha256};
        let digest = Sha256::digest(format!("ws/open\0{}", conn.name).as_bytes());
        digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    });

    // Executor: dial the configured upstream with the credential injected
    // (validating reachability and auth), issue the ticket, hand back the
    // bridge URL.
    let executor: crate::executions::Executor = {
        let broker = broker.clone();
        let conn = conn.clone();
        let client_label = client.clone();
        Box::pin(async move {
            match crate::capability::ws::dial_upstream(&broker.store, &conn).await {
                Ok(upstream) => {
                    let ticket = broker.data_plane.issue(
                        &client_label,
                        &conn,
                        crate::sessions::TicketPayload::Ws {
                            pending_upstream: Some(upstream),
                        },
                    );
                    ExecOutcome {
                        status: 200,
                        body: json!({
                            "ws_url":
                                format!(
                                    "ws://{}:{bridge_port}/v1/ws/bridge/{ticket}",
                                    broker.advertise_host()
                                ),
                            // The redemption deadline, machine-actionable
                            // instead of prose-only.
                            "expires_in_seconds": broker.config.ticket_ttl.as_secs(),
                        }),
                    }
                }
                Err(e) => ExecOutcome {
                    status: 502,
                    body: json!({ "reason": ErrorReason::UpstreamConnectFailed, "detail": e.detail }),
                },
            }
        })
    };

    run_allowed(
        broker,
        &client,
        &conn,
        None,
        ExecRequest {
            coalesce_key,
            payload_hash,
            executor,
        },
    )
    .await
}

/* ------------------------------ SSH open ---------------------------------- */

async fn post_ssh_open(
    State(state): State<AppState>,
    authed: Authed,
    ApiJson(body): ApiJson<OpenBody>,
) -> Response {
    let broker = &state.broker;
    let limiter_key = authed.client_id.to_string();
    let client = authed.client;
    if let Err(wait) = broker.token_limiter.check(&limiter_key) {
        return err_rate_limited(ErrorReason::RateLimited, wait);
    }
    if let Some(response) = request_id_error(body.request_id.as_deref()) {
        return response;
    }
    let Some(conn) = broker.store.connection_by_name(&body.connection) else {
        return err_unknown_connection(broker);
    };
    if conn.kind() != ConnectionKind::Ssh {
        return err_detail(
            StatusCode::BAD_REQUEST,
            ErrorReason::WrongConnectionType,
            format!(
                "{} is a {} connection; use POST {}",
                conn.name,
                conn.kind().as_str(),
                endpoint_for(conn.kind())
            ),
        );
    }
    let ConnectionConfig::Ssh {
        destination,
        host,
        port,
        user,
        host_key_fingerprint,
    } = &conn.config
    else {
        unreachable!()
    };
    let (destination, host, port, user) = (
        destination.clone().unwrap_or_else(|| host.clone()),
        host.clone(),
        *port,
        user.clone(),
    );
    // `null` while unpinned: the key is confirmed with the user and pinned
    // at the first session-bind, so agents can distinguish "not yet trusted"
    // from a configured fingerprint.
    let host_key_fingerprint =
        (!host_key_fingerprint.is_empty()).then(|| host_key_fingerprint.clone());

    // The idempotency payload is the open itself: same key + same
    // connection = a genuine retry.
    let coalesce_key = body
        .request_id
        .as_ref()
        .map(|rid| (client.clone(), rid.clone()));
    let payload_hash = coalesce_key.as_ref().map(|_| {
        use sha2::{Digest as _, Sha256};
        let digest = Sha256::digest(format!("ssh/open\0{}", conn.name).as_bytes());
        digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    });

    // Executor: read + parse the key, bind the per-open agent socket, issue
    // the ticket, hand back the SSH_AUTH_SOCK path. The socket path is
    // the capability, so it is minted only when access is enabled.
    let executor: crate::executions::Executor = {
        let broker = broker.clone();
        let conn = conn.clone();
        let client_label = client.clone();
        Box::pin(async move {
            match crate::capability::ssh::open_agent(broker.clone(), client_label, conn).await {
                Ok(auth_sock) => ExecOutcome {
                    status: 200,
                    body: json!({
                        "auth_sock": auth_sock,
                        "destination": destination,
                        "host": host,
                        "port": port,
                        "user": user,
                        "host_key_fingerprint": host_key_fingerprint,
                        // The redemption deadline, machine-actionable
                        // instead of prose-only.
                        "expires_in_seconds": broker.config.ticket_ttl.as_secs(),
                    }),
                },
                Err(detail) => ExecOutcome {
                    status: 502,
                    body: json!({ "reason": ErrorReason::SshAgentOpenFailed, "detail": detail }),
                },
            }
        })
    };

    run_allowed(
        broker,
        &client,
        &conn,
        None,
        ExecRequest {
            coalesce_key,
            payload_hash,
            executor,
        },
    )
    .await
}

/* ------------------------------ PG open ----------------------------------- */

async fn post_pg_open(
    State(state): State<AppState>,
    authed: Authed,
    ApiJson(body): ApiJson<OpenBody>,
) -> Response {
    let broker = &state.broker;
    let limiter_key = authed.client_id.to_string();
    let client = authed.client;
    if let Err(wait) = broker.token_limiter.check(&limiter_key) {
        return err_rate_limited(ErrorReason::RateLimited, wait);
    }
    if let Some(response) = request_id_error(body.request_id.as_deref()) {
        return response;
    }
    let Some(conn) = broker.store.connection_by_name(&body.connection) else {
        return err_unknown_connection(broker);
    };
    if conn.kind() != ConnectionKind::Pg {
        return err_detail(
            StatusCode::BAD_REQUEST,
            ErrorReason::WrongConnectionType,
            format!(
                "{} is a {} connection; use POST {}",
                conn.name,
                conn.kind().as_str(),
                endpoint_for(conn.kind())
            ),
        );
    }
    let Some(&proxy_port) = broker.pg_proxy_port.get() else {
        return err(
            StatusCode::INTERNAL_SERVER_ERROR,
            ErrorReason::ProxyNotRunning,
        );
    };
    let ConnectionConfig::Pg { dbname, .. } = &conn.config else {
        unreachable!()
    };
    let dbname = dbname.clone();

    // The idempotency payload is the open itself: same key + same
    // connection = a genuine retry.
    let coalesce_key = body
        .request_id
        .as_ref()
        .map(|rid| (client.clone(), rid.clone()));
    let payload_hash = coalesce_key.as_ref().map(|_| {
        use sha2::{Digest as _, Sha256};
        let digest = Sha256::digest(format!("pg/open\0{}", conn.name).as_bytes());
        digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    });

    // Executor: issue the ticket and hand back the password-less DSN.
    // Unlike WS, nothing is dialed here, the proxy dials upstream at
    // redemption time. The ticket is NOT embedded in the DSN: returning
    // the two separately lets callers keep it out of ps-visible argv via
    // PGPASSWORD, while callers that accept the exposure for the ticket's
    // short window (`mfa dsn`) embed it themselves.
    let executor: crate::executions::Executor = {
        let broker = broker.clone();
        let conn = conn.clone();
        let client_label = client.clone();
        Box::pin(async move {
            let ticket =
                broker
                    .data_plane
                    .issue(&client_label, &conn, crate::sessions::TicketPayload::Pg);
            let dsn = format!(
                "postgres://ticket@{}:{proxy_port}/{dbname}?sslmode=disable",
                broker.advertise_host()
            );
            ExecOutcome {
                status: 200,
                body: json!({
                    // Ready-to-adapt invocation; the ticket goes via the
                    // environment, never argv.
                    "example": format!("PGPASSWORD=<ticket> psql \"{dsn}\""),
                    "dsn": dsn,
                    "ticket": ticket,
                    // The redemption deadline, machine-actionable instead
                    // of prose-only.
                    "expires_in_seconds": broker.config.ticket_ttl.as_secs(),
                }),
            }
        })
    };

    run_allowed(
        broker,
        &client,
        &conn,
        None,
        ExecRequest {
            coalesce_key,
            payload_hash,
            executor,
        },
    )
    .await
}
