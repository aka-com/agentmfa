//! Agent-facing control plane. HTTP over a Unix domain socket, mode 0600.
//!
//! - `GET /.well-known/agent-broker.json`, `GET /instructions`,
//!   unauthenticated discovery, globally rate limited;
//! - `POST /v1/pair`, unauthenticated, globally rate limited, registered
//!   immediately (no approval);
//! - `GET /v1/connections`, `GET /v1/whoami`, `POST /v1/http` (+ the WS/PG
//!   opens added by later phases), bearer-token authenticated, per-token
//!   rate limited.

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
use crate::pairing::{validate_agent_name, TokenError};
use crate::types::{ConnectionConfig, ConnectionKind, PairedAgent};
use crate::wire::{ErrorReason, MissingTokenCause, REQUEST_ID_MAX_BYTES};

/* ------------------------------ plumbing --------------------------------- */

#[derive(Clone)]
pub struct AppState {
    pub broker: Arc<Broker>,
}

fn err(status: StatusCode, reason: ErrorReason) -> Response {
    (status, Json(json!({ "reason": reason }))).into_response()
}

fn err_missing_token(cause: MissingTokenCause) -> Response {
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

fn bearer_token(headers: &axum::http::HeaderMap) -> Result<&str, MissingTokenCause> {
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
struct ApiJson<T>(T);

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

/// Bearer-token authentication.
pub struct Authed {
    pub agent: PairedAgent,
}

impl FromRequestParts<AppState> for Authed {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = bearer_token(&parts.headers).map_err(err_missing_token)?;
        match state.broker.pairing.verify(token) {
            Ok(agent) => Ok(Authed { agent }),
            Err(e) => {
                if let TokenError::Superseded { name } = &e {
                    // The two-instances case: without this hint each 401
                    // triggers a re-pair that breaks the *other* instance,
                    // and the human fields an endless stream of prompts.
                    // `store_at` names the exact file so recovery is
                    // mechanical, not prose-guided.
                    return Err((
                        StatusCode::UNAUTHORIZED,
                        Json(json!({
                            "reason": e.reason(),
                            "detail": "a later pairing under this name replaced the token; \
                                       re-read the shared token file instead of pairing again",
                            "store_at":
                                format!("{}/{name}", state.broker.paths.tokens_display()),
                        })),
                    )
                        .into_response());
                }
                if e == TokenError::Invalid {
                    return Err(err_detail(
                        StatusCode::UNAUTHORIZED,
                        ErrorReason::InvalidToken,
                        "A bearer token reached the broker but was not recognized. It may have been revoked or rewritten by a local application.",
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
    /// The WS bridge's ephemeral loopback port (tests need it; agents only
    /// ever see it inside open responses).
    pub ws_bridge_port: u16,
    /// The PG proxy's ephemeral loopback port (tests need it; agents only
    /// ever see it inside open responses' DSNs).
    pub pg_proxy_port: u16,
    task: tokio::task::JoinHandle<()>,
    bridge_task: tokio::task::JoinHandle<()>,
    proxy_task: tokio::task::JoinHandle<()>,
    // Declared last so serving tasks are aborted/dropped before the
    // rendezvous point is unlinked.
    _socket_guard: SocketGuard,
}

impl Drop for DaemonHandle {
    fn drop(&mut self) {
        self.task.abort();
        self.bridge_task.abort();
        self.proxy_task.abort();
    }
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
    let body_cap = broker.config.request_cap;
    Router::new()
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
        // JSON string bodies inflate the wire size (escaping, base64): give
        // the transport head-room; the decoded body cap is enforced exactly.
        .layer(DefaultBodyLimit::max(body_cap + body_cap / 2 + 1024 * 1024))
        .with_state(AppState { broker })
}

/// Bind the control-plane socket and serve. [`Broker::new`] acquired the OS
/// process lease before opening any persistent state and the broker holds it
/// for its full lifetime. A socket left by a crashed broker is unlinked only
/// when it is still the observed inode and rejects a connection with the
/// expected stale-socket error.
pub async fn serve(broker: Arc<Broker>) -> crate::Result<DaemonHandle> {
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

    let app = router(broker);
    let task = tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            tracing::error!("daemon exited: {e}");
        }
    });
    Ok(DaemonHandle {
        socket_path,
        ws_bridge_port,
        pg_proxy_port,
        task,
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
    Json(wellknown::manifest(
        &state.broker.config,
        &state.broker.paths,
    ))
    .into_response()
}

async fn get_instructions(State(state): State<AppState>) -> Response {
    if let Err(wait) = state.broker.discovery_limiter.check() {
        return err_rate_limited(ErrorReason::RateLimited, wait);
    }
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/markdown; charset=utf-8",
        )],
        wellknown::instructions(&state.broker.config, &state.broker.paths),
    )
        .into_response()
}

/* -------------------------------- pairing -------------------------------- */

#[derive(Deserialize)]
struct PairBody {
    agent_name: String,
}

async fn post_pair(State(state): State<AppState>, ApiJson(body): ApiJson<PairBody>) -> Response {
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

    // Registration is immediate: no approval prompt. The new agent simply
    // appears in the app, unwired — it can list connections but cannot use
    // any until the user wires it up. The one exception: the very first
    // agent is wired to every existing connection, so a fresh install works
    // end-to-end without a trip through the app.
    let is_first_agent = broker.pairing.list().is_empty();
    let replaces_existing_agent = broker.pairing.get(&name).is_some();
    match broker.pairing.pair(&name) {
        Ok((token, agent)) => {
            if is_first_agent {
                broker.bootstrap_first_agent_wirings(&agent);
            }
            if replaces_existing_agent {
                // A re-pair invalidates the prior token generation; close
                // the transports it carried.
                let sessions_closed = broker.data_plane.close_agent(&name);
                broker.audit.append(
                    AuditEntry::new(AuditKind::Paired, format!("Agent reconnected: {name}"))
                        .agent(name.clone())
                        .outcome("paired")
                        .field("prior_sessions_closed", sessions_closed),
                );
            } else {
                broker.audit.append(
                    AuditEntry::new(AuditKind::Paired, format!("Agent connected: {name}"))
                        .agent(name.clone())
                        .outcome("paired"),
                );
            }
            broker.events.agents_changed();
            (
                StatusCode::OK,
                Json(json!({
                    "token": token,
                    "client_id": agent.id,
                    // Echo what was registered, so the agent can log its own
                    // enrollment without a follow-up /v1/whoami.
                    "agent": agent.name,
                    "expires_after_days": broker.config.token_ttl.as_secs() / 86400,
                    // The storage guidance travels with the credential, not
                    // just in prose.
                    "store_at": format!("{}/{name}", broker.paths.tokens_display()),
                })),
            )
                .into_response()
        }
        Err(e) => err_detail(
            StatusCode::INTERNAL_SERVER_ERROR,
            ErrorReason::PairingFailed,
            e.to_string(),
        ),
    }
}

/* ------------------------- connection listing ----------------------------- */

async fn get_connections(State(state): State<AppState>, authed: Authed) -> Response {
    let broker = &state.broker;
    if let Err(wait) = broker.token_limiter.check(&authed.agent.token_hash) {
        return err_rate_limited(ErrorReason::RateLimited, wait);
    }
    // The one authenticated endpoint that bypasses the wiring check by
    // design, an agent must see what exists (and what it is wired to).
    // Audited.
    broker.audit.append(
        AuditEntry::new(
            AuditKind::Listed,
            format!("{} listed connections", authed.agent.name),
        )
        .agent(authed.agent.name.clone()),
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
                // Whether this agent may use the connection. Unwired
                // connections are visible but refused; the user wires
                // agents up in the app.
                "wired": broker.wirings.is_wired(&authed.agent.id, &c.id),
            });
            // Attenuation on a Postgres connection this agent is wired to, so
            // it knows up front that a read-only wiring will refuse writes.
            // Only Postgres enforces it, so only Postgres advertises it.
            if c.kind() == ConnectionKind::Pg {
                if let Some(mode) = broker.wirings.mode(&authed.agent.id, &c.id) {
                    row["mode"] = json!(mode.as_str());
                }
            }
            // Present only when this upstream speaks MCP, so the payload
            // stays exactly as it was for every other connection.
            if let ConnectionConfig::Api {
                mcp_path: Some(path),
                ..
            } = &c.config
            {
                row["mcp_path"] = json!(path);
                // A curated tool subset for this agent, when the wiring has
                // one; the broker enforces it on tools/call, this field lets
                // the sidecar list only what is callable.
                if let Some(tools) = broker
                    .wirings
                    .wiring_for(&authed.agent.id, &c.id)
                    .and_then(|w| w.allowed_tools)
                {
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
/// Deliberately exempt from the per-token capability limiter. The MCP sidecar
/// resolves the agent's token here on *every* request it serves (no caching,
/// so a revoked token stops working at once), so charging whoami against the
/// 60/min budget would halve an agent's real tool-call rate and surface as a
/// mystifying rate-limit. This is safe because whoami is read-only, cheap, and
/// already fronted by the 0600 socket's own access ceiling — it grants nothing
/// a capability call would, so it needs no throttle of its own.
async fn get_whoami(State(state): State<AppState>, authed: Authed) -> Response {
    let broker = &state.broker;
    let expires_at = authed.agent.last_used
        + chrono::Duration::from_std(broker.config.token_ttl)
            .unwrap_or_else(|_| chrono::Duration::days(30));
    Json(json!({
        "client_id": authed.agent.id,
        "agent": authed.agent.name,
        "paired_at": authed.agent.paired_at,
        // The sliding TTL's current horizon; refreshed on every
        // authenticated call.
        "expires_at": expires_at,
    }))
    .into_response()
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
    let agent = authed.agent;
    if let Err(wait) = broker.token_limiter.check(&agent.token_hash) {
        broker.audit.append(
            AuditEntry::new(
                AuditKind::RateLimited,
                format!("Rate limited: {}", agent.name),
            )
            .agent(agent.name.clone()),
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
    let credential_header = match injection_form(template) {
        Some(InjectionForm::Header { name }) => Some(name),
        Some(InjectionForm::Query) => None,
        None => {
            return err_detail(
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorReason::BadConnectionConfig,
                "connection template is neither a header line nor a query form",
            )
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
    if let ConnectionConfig::Api {
        mcp_path: Some(mcp_path),
        ..
    } = &conn.config
    {
        let call_path = call.path.split('?').next().unwrap_or("");
        let pinned_path = mcp_path.split('?').next().unwrap_or("");
        if call_path == pinned_path {
            let allowed = broker
                .wirings
                .wiring_for(&agent.id, &conn.id)
                .and_then(|w| w.allowed_tools);
            if let (Some(allowed), Some(tool)) = (allowed, mcp_tool_call_name(&body_bytes)) {
                if !allowed.iter().any(|name| name == &tool) {
                    broker.audit.append(
                        AuditEntry::new(
                            AuditKind::Denied,
                            format!(
                                "Refused (tool not enabled): {} → {} · {tool}",
                                agent.name, conn.name
                            ),
                        )
                        .agent(agent.name.clone())
                        .connection(conn.name.clone())
                        .outcome("denied_by_policy"),
                    );
                    return err_detail(
                        StatusCode::FORBIDDEN,
                        ErrorReason::DeniedByPolicy,
                        format!(
                            "the tool {tool:?} is not enabled for {} on {}; the user can enable it in Multitool",
                            agent.name, conn.name
                        ),
                    );
                }
            }
        }
    }
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

    // Coalescing is keyed on (agent, request_id) for mutating calls only;
    // GET/HEAD are never coalesced, a request_id there is ignored.
    let coalesce_key = match (&call.request_id, mutating) {
        (Some(rid), true) => Some((agent.name.clone(), rid.clone())),
        _ => None,
    };
    let payload_hash = coalesce_key.as_ref().map(|_| hash);

    let executor = HttpExecution {
        store: broker.store.clone(),
        audit: broker.audit.clone(),
        client: broker.http_client.clone(),
        config: broker.config.clone(),
        agent: agent.name.clone(),
        connection: conn.clone(),
        method,
        path: call.path.clone(),
        headers: header_map,
        body: body.clone(),
        health: Some(broker.health.clone()),
    };
    let executor: crate::executions::Executor = Box::pin(executor.run());

    run_wired(
        broker,
        &agent,
        &conn,
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
    match broker.agent_connect_request(&authed.agent, service) {
        Ok(fresh) => (
            StatusCode::ACCEPTED,
            Json(serde_json::json!({
                "status": if fresh { "requested" } else { "already_requested" },
                "detail": "Ask the user to add and wire this tool in Multitool; \
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

/// The tool a JSON-RPC `tools/call` body names, if that is what it is.
fn mcp_tool_call_name(body: &[u8]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    if value.get("method").and_then(|m| m.as_str()) != Some("tools/call") {
        return None;
    }
    value
        .get("params")
        .and_then(|p| p.get("name"))
        .and_then(|n| n.as_str())
        .map(String::from)
}

/// Shared capability tail: a wired agent executes immediately (retries
/// still coalesce under their idempotency key); an unwired one is refused.
async fn run_wired(
    broker: &Arc<Broker>,
    agent: &PairedAgent,
    conn: &crate::types::Connection,
    exec: ExecRequest,
) -> Response {
    if !broker.wirings.is_wired(&agent.id, &conn.id) {
        broker.audit.append(
            AuditEntry::new(
                AuditKind::Denied,
                format!("Refused (not wired): {} → {}", agent.name, conn.name),
            )
            .agent(agent.name.clone())
            .connection(conn.name.clone())
            .outcome("denied_by_policy"),
        );
        return err_detail(
            StatusCode::FORBIDDEN,
            ErrorReason::DeniedByPolicy,
            format!(
                "{} is not wired to {}; the user can wire it up in Multitool",
                agent.name, conn.name
            ),
        );
    }
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
    let agent = authed.agent;
    if let Err(wait) = broker.token_limiter.check(&agent.token_hash) {
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
        .map(|rid| (agent.name.clone(), rid.clone()));
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
        let agent_name = agent.name.clone();
        Box::pin(async move {
            match crate::capability::ws::dial_upstream(&broker.store, &conn).await {
                Ok(upstream) => {
                    let ticket = broker.data_plane.issue(
                        &agent_name,
                        &conn,
                        crate::sessions::TicketPayload::Ws {
                            pending_upstream: Some(upstream),
                        },
                    );
                    ExecOutcome {
                        status: 200,
                        body: json!({
                            "ws_url":
                                format!("ws://127.0.0.1:{bridge_port}/v1/ws/bridge/{ticket}"),
                            // The redemption deadline, machine-actionable
                            // instead of prose-only.
                            "expires_in_seconds": broker.config.ticket_ttl.as_secs(),
                        }),
                    }
                }
                Err(detail) => ExecOutcome {
                    status: 502,
                    body: json!({ "reason": ErrorReason::UpstreamConnectFailed, "detail": detail }),
                },
            }
        })
    };

    run_wired(
        broker,
        &agent,
        &conn,
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
    let agent = authed.agent;
    if let Err(wait) = broker.token_limiter.check(&agent.token_hash) {
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
        .map(|rid| (agent.name.clone(), rid.clone()));
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
    // the capability, so it is minted only for a wired agent.
    let executor: crate::executions::Executor = {
        let broker = broker.clone();
        let conn = conn.clone();
        let agent_name = agent.name.clone();
        Box::pin(async move {
            match crate::capability::ssh::open_agent(broker.clone(), agent_name, conn).await {
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

    run_wired(
        broker,
        &agent,
        &conn,
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
    let agent = authed.agent;
    if let Err(wait) = broker.token_limiter.check(&agent.token_hash) {
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
        .map(|rid| (agent.name.clone(), rid.clone()));
    let payload_hash = coalesce_key.as_ref().map(|_| {
        use sha2::{Digest as _, Sha256};
        let digest = Sha256::digest(format!("pg/open\0{}", conn.name).as_bytes());
        digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    });

    // The wiring's attenuation, resolved now so the ticket carries it: a
    // read-only wiring makes the proxy open the upstream read-only. An unwired
    // agent has no mode; `run_wired` refuses it below either way.
    let read_only = broker
        .wirings
        .mode(&agent.id, &conn.id)
        .map(|m| m.is_read_only())
        .unwrap_or(false);

    // Executor: issue the ticket and hand back the password-less DSN.
    // Unlike WS, nothing is dialed here, the proxy dials upstream at
    // redemption time. The ticket is deliberately NOT embedded in the DSN
    // (it would sit in ps-visible argv and shell history for its window):
    // agents supply it out-of-band via PGPASSWORD.
    let executor: crate::executions::Executor = {
        let broker = broker.clone();
        let conn = conn.clone();
        let agent_name = agent.name.clone();
        Box::pin(async move {
            let ticket = broker.data_plane.issue(
                &agent_name,
                &conn,
                crate::sessions::TicketPayload::Pg { read_only },
            );
            let dsn = format!("postgres://ticket@127.0.0.1:{proxy_port}/{dbname}?sslmode=disable");
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

    run_wired(
        broker,
        &agent,
        &conn,
        ExecRequest {
            coalesce_key,
            payload_hash,
            executor,
        },
    )
    .await
}
