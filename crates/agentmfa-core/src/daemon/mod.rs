//! The agent-facing control plane: HTTP over a Unix domain socket
//! (`~/.agentmfa/broker.sock`, mode 0600, DESIGN.md §2/§8).
//!
//! Endpoints:
//! - `GET /.well-known/agent-broker.json`, `GET /instructions`,
//!   unauthenticated discovery, globally rate limited;
//! - `POST /v1/pair`, unauthenticated, globally rate limited, gated by a
//!   held-open user approval;
//! - `GET /v1/connections`, `GET /v1/whoami`, `POST /v1/http` (+ the WS/PG
//!   opens added by later phases), bearer-token authenticated,
//!   identity-pinned, per-token rate limited.

pub mod wellknown;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::connect_info::{ConnectInfo, Connected};
use axum::extract::{DefaultBodyLimit, FromRequestParts, State};
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;
use tokio::net::UnixListener;
use uuid::Uuid;

use crate::approvals::{
    ApprovalKind, ApprovalRequest, ExecOutcome, HttpPayloadView, ParkError, ParkRequest, Parked,
};
use crate::audit::{AuditEntry, AuditKind};
use crate::broker::Broker;
use crate::capability::http::{
    injection_form, is_mutating, parse_method, payload_hash, validate_headers, validate_path,
    HttpExecution, InjectionForm,
};
use crate::capability::SpooledBody;
use crate::wire::ErrorReason;
use crate::error::CoreError;
use crate::pairing::{validate_agent_name, TokenError};
use crate::policy::PolicyEngine as _;
use crate::ratelimit::PairingBlock;
use crate::types::{ConnectionConfig, ConnectionKind, Decision, PairedAgent, PeerIdentity};

/* ------------------------------ plumbing --------------------------------- */

#[derive(Clone)]
pub struct AppState {
    pub broker: Arc<Broker>,
}

/// Per-connection peer info, resolved race-free at accept time (§8).
#[derive(Clone, Debug)]
pub struct PeerInfo {
    pub identity: PeerIdentity,
}

impl Connected<axum::serve::IncomingStream<'_, UnixListener>> for PeerInfo {
    fn connect_info(stream: axum::serve::IncomingStream<'_, UnixListener>) -> Self {
        Self {
            identity: crate::peer::resolve_peer(stream.io()),
        }
    }
}

fn err(status: StatusCode, reason: ErrorReason) -> Response {
    (status, Json(json!({ "reason": reason }))).into_response()
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

    async fn from_request(
        req: axum::extract::Request,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
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
/// per-entry `endpoint` field in the listing (§5b: the type→endpoint
/// mapping should not live only in prose).
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
/// how long to wait instead of guessing (§5b applied to backoff).
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
    err_detail(StatusCode::NOT_FOUND, ErrorReason::UnknownConnection, detail)
}

/// Bearer-token + identity-pin authentication (§8).
pub struct Authed {
    pub agent: PairedAgent,
}

impl FromRequestParts<AppState> for Authed {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let peer = parts
            .extensions
            .get::<ConnectInfo<PeerInfo>>()
            .map(|ci| ci.0.identity.clone())
            .unwrap_or(PeerIdentity::Unsigned {
                uid: None,
                executable_path: None,
                file_id: None,
                executable_sha256: None,
            });
        let token = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(str::trim)
            .filter(|t| !t.is_empty());
        let Some(token) = token else {
            return Err(err(StatusCode::UNAUTHORIZED, ErrorReason::MissingToken));
        };
        match state.broker.pairing.verify(token, &peer) {
            Ok(agent) => Ok(Authed { agent }),
            Err(e) => {
                if e == TokenError::IdentityMismatch {
                    state.broker.audit.append(
                        AuditEntry::new(
                            AuditKind::PeerIdentityMismatch,
                            format!(
                                "Rejected call: pin mismatch, valid token presented by {}",
                                peer.display()
                            ),
                        )
                        .outcome("peer_identity_mismatch"),
                    );
                }
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
}

impl Drop for DaemonHandle {
    fn drop(&mut self) {
        self.task.abort();
        self.bridge_task.abort();
        self.proxy_task.abort();
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
        .route("/v1/ws/open", post(post_ws_open))
        .route("/v1/pg/open", post(post_pg_open))
        .route("/v1/ssh/open", post(post_ssh_open))
        // JSON string bodies inflate the wire size (escaping, base64): give
        // the transport head-room; the decoded body cap is enforced exactly.
        .layer(DefaultBodyLimit::max(body_cap + body_cap / 2 + 1024 * 1024))
        .with_state(AppState { broker })
}

/// Bind the control-plane socket and serve. A stale socket file left by a
/// crashed broker is unlinked after a failed connect test (§12).
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
    if socket_path.exists() {
        match tokio::net::UnixStream::connect(&socket_path).await {
            Ok(_) => {
                return Err(CoreError::BrokerAlreadyRunning(paths.socket_display()));
            }
            Err(_) => {
                tracing::info!("removing stale socket {}", socket_path.display());
                std::fs::remove_file(&socket_path)?;
            }
        }
    }
    let listener = UnixListener::bind(&socket_path)?;
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))?;
    }
    // Per-open SSH agent sockets self-clean on their deadline; sweep any a
    // crashed broker left behind, mirroring the stale control-socket check
    // above (§4.4/§12).
    crate::capability::ssh::sweep_stale_sockets(&paths.ssh_agent_dir());
    // The WS bridge data plane: loopback-only, OS-assigned port (§8).
    let (ws_bridge_port, bridge_task) = crate::capability::ws::start_bridge(broker.clone()).await?;
    let _ = broker.ws_bridge_port.set(ws_bridge_port);
    // The PG proxy data plane: loopback-only, OS-assigned port (§4.3/§8).
    let (pg_proxy_port, proxy_task) = crate::capability::pg::start_proxy(broker.clone()).await?;
    let _ = broker.pg_proxy_port.set(pg_proxy_port);

    let app = router(broker);
    let task = tokio::spawn(async move {
        if let Err(e) = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<PeerInfo>(),
        )
        .await
        {
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

async fn post_pair(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<PeerInfo>,
    ApiJson(body): ApiJson<PairBody>,
) -> Response {
    let broker = &state.broker;
    // The brake's two causes read differently to an agent: a full window
    // means "slow down"; the post-denial cooldown means "the human just
    // said no, ask them before trying again" (§8).
    match broker.pairing_limiter.check() {
        Ok(()) => {}
        Err(PairingBlock::Window(wait)) => return err_rate_limited(ErrorReason::PairingRateLimited, wait),
        Err(PairingBlock::DeniedCooldown(wait)) => {
            return err_rate_limited(ErrorReason::PairingDeniedCooldown, wait)
        }
    }
    let name = body.agent_name.trim().to_string();
    if !validate_agent_name(&name) {
        return err_detail(
            StatusCode::BAD_REQUEST,
            ErrorReason::InvalidAgentName,
            "1-64 chars of [A-Za-z0-9._-]",
        );
    }

    let identity = peer.identity.clone();
    // Pairing under a name that already holds standing rules inherits them,
    // the dialog must disclose exactly what (§6).
    let inherited = broker.inherited_for(&name);

    broker.audit.append(
        AuditEntry::new(
            AuditKind::PairRequested,
            format!("Pair request from {name}"),
        )
        .agent(name.clone())
        .detail(identity.display())
        .field("identity", identity.display()),
    );

    let request = ApprovalRequest {
        id: Uuid::new_v4(),
        agent: name.clone(),
        kind: ApprovalKind::Pair,
        connection: None,
        action: format!("Pair new agent “{name}” with AgentMFA"),
        notification: format!("{name} requests to pair with AgentMFA"),
        received_at: chrono::Utc::now(),
        deadline: chrono::Utc::now(),
        identity: Some(identity.display()),
        inherited,
        http: None,
    };

    // Concurrent pairings under one name coalesce: identically-signed
    // processes (the two-terminals case) join the one held-open prompt and
    // receive the same minted token, which they share via the token file.
    // The key's `\0` cannot appear in a validated agent name, so it can
    // never collide with a capability call's `(agent, request_id)` key.
    let coalesce_key = Some((format!("pair\u{0}{name}"), String::new()));
    let payload_hash = Some({
        use sha2::{Digest as _, Sha256};
        let digest = Sha256::digest(identity.display().as_bytes());
        digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    });

    let executor = {
        let broker = broker.clone();
        let name = name.clone();
        Box::pin(async move {
            match broker.pairing.pair(&name, identity) {
                Ok((token, agent)) => {
                    broker.audit.append(
                        AuditEntry::new(AuditKind::Paired, format!("Agent paired: {name}"))
                            .agent(name.clone())
                            .outcome("paired"),
                    );
                    broker.events.agents_changed();
                    ExecOutcome {
                        status: 200,
                        body: json!({
                            "token": token,
                            // Echo what was registered and pinned, so the
                            // agent can log its own enrollment without a
                            // follow-up /v1/whoami.
                            "agent": agent.name,
                            "identity": agent.identity.display(),
                            "expires_after_days": broker.config.token_ttl.as_secs() / 86400,
                            // The storage guidance travels with the
                            // credential, not just in prose (§5b).
                            "store_at": format!("{}/{name}", broker.paths.tokens_display()),
                        }),
                    }
                }
                Err(e) => ExecOutcome {
                    status: 500,
                    body: json!({ "reason": ErrorReason::PairingFailed, "detail": e.to_string() }),
                },
            }
        })
    };

    // retain_outcome is off: replaying a minted token to a pairing that
    // arrives *after* completion would hand out a credential with no
    // approval; only in-flight pairings may share the prompt.
    let parked = broker.approvals.park(ParkRequest {
        request,
        coalesce_key,
        payload_hash,
        retain_outcome: false,
        executor,
    });
    match parked {
        Ok(Parked::Wait(handle)) => match handle.wait().await {
            Some(outcome) => outcome_response(outcome),
            None => err(StatusCode::INTERNAL_SERVER_ERROR, ErrorReason::BrokerShutdown),
        },
        Ok(Parked::Replay(outcome)) => outcome_response(outcome),
        // Same name, different peer identity, while a prompt is pending: a
        // second racing prompt would be confusing at best, so ask the agent
        // to come back once the first resolves.
        Err(ParkError::RequestIdMismatch) => err_detail(
            StatusCode::CONFLICT,
            ErrorReason::PairingAlreadyPending,
            "a pairing for this name from a different peer identity is \
             awaiting the user; retry after it resolves",
        ),
    }
}

/* ------------------------- connection listing ----------------------------- */

async fn get_connections(State(state): State<AppState>, authed: Authed) -> Response {
    let broker = &state.broker;
    if let Err(wait) = broker.token_limiter.check(&authed.agent.token_hash) {
        return err_rate_limited(ErrorReason::RateLimited, wait);
    }
    // The one authenticated endpoint that bypasses the policy engine by
    // design, an agent must see what it may ask for. Audited (§4.0/§8).
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
            // What a call costs the agent right now: `will_prompt` blocks on
            // a human decision, `auto_allowed` proceeds immediately under a
            // standing rule (§7). Not a secret; the agent learns the same
            // thing on its first call, but knowing up front lets it warn its
            // user before ringing the doorbell.
            let approval = match broker.policy.evaluate(&authed.agent.name, &c.id) {
                Decision::Allow => "auto_allowed",
                Decision::Prompt => "will_prompt",
                // Reserved vocabulary: the v1 policy engine has no deny
                // rules (policy.rs), so this arm is unreachable today —
                // don't build agent logic around it.
                Decision::Deny => ErrorReason::DeniedByPolicy.as_str(),
            };
            json!({
                "name": c.name,
                "type": c.kind().as_str(),
                "target": c.target(),
                // Where a call naming this connection goes; the
                // type→endpoint mapping shouldn't live only in prose.
                "endpoint": endpoint_for(c.kind()),
                // Whether one open's ticket may be redeemed repeatedly
                // within its window; the approval dialog shows the human
                // the same fact.
                "multi_connect": c.multi_connect,
                "approval": approval,
            })
        })
        .collect();
    Json(list).into_response()
}

/// `GET /v1/whoami`: a cheap probe for the reuse-then-pair startup flow.
/// Validating a stored token used to require a real capability call, which
/// spammed the audit trail with health checks; this endpoint is deliberately
/// not audited on success (failures are audited by the extractor like any
/// other call).
async fn get_whoami(State(state): State<AppState>, authed: Authed) -> Response {
    let broker = &state.broker;
    if let Err(wait) = broker.token_limiter.check(&authed.agent.token_hash) {
        return err_rate_limited(ErrorReason::RateLimited, wait);
    }
    let expires_at = authed.agent.last_used
        + chrono::Duration::from_std(broker.config.token_ttl)
            .unwrap_or_else(|_| chrono::Duration::days(30));
    Json(json!({
        "agent": authed.agent.name,
        "identity": authed.agent.identity.display(),
        "paired_at": authed.agent.paired_at,
        // The sliding TTL's current horizon; refreshed on every
        // authenticated call (§8).
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
    /// Idempotency key (§4): coalesces retried mutating calls.
    #[serde(default)]
    request_id: Option<String>,
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
    let ConnectionConfig::Api { template, host, .. } = &conn.config else {
        unreachable!()
    };

    // Validate the *what* (§4.1). Validation runs before any prompt, so a
    // rejected request never costs the user an approval.
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

    // Decode the body (§4.1): JSON string, JSON value, or base64 binary.
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
                    return err_detail(StatusCode::BAD_REQUEST, ErrorReason::InvalidBody, e.to_string())
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

    // The approval window's request-payload view (§6).
    let (preview, truncated) = body
        .preview(broker.config.approval_body_preview)
        .unwrap_or((None, false));
    let mutating = is_mutating(&method);
    let action = format!("{} {}{}", method, host, call.path);
    let request = ApprovalRequest {
        id: Uuid::new_v4(),
        agent: agent.name.clone(),
        kind: ApprovalKind::Http,
        connection: Some(broker.connection_summary(&conn)),
        action: action.clone(),
        notification: format!(
            "{} wants to use {}: {} {}",
            agent.name, conn.name, method, call.path
        ),
        received_at: chrono::Utc::now(),
        deadline: chrono::Utc::now(),
        identity: None,
        inherited: vec![],
        http: Some(HttpPayloadView {
            method: method.to_string(),
            path: call.path.clone(),
            headers: wire_headers,
            body_preview: preview,
            body_len: body.len(),
            body_truncated: truncated,
            mutating,
        }),
    };

    broker.audit.append(
        AuditEntry::new(
            AuditKind::Requested,
            format!("{} requested {}", agent.name, conn.name),
        )
        .agent(agent.name.clone())
        .connection(conn.name.clone())
        .detail(action)
        .field("method", method.to_string())
        .field("path", call.path.clone()),
    );

    // Coalescing is keyed on (agent, request_id) for mutating calls only;
    // GET/HEAD are never coalesced, a request_id there is ignored (§4).
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
    };
    let executor: crate::approvals::Executor = Box::pin(executor.run());

    let park = ParkRequest {
        request,
        coalesce_key,
        payload_hash,
        retain_outcome: true,
        executor,
    };
    run_policied(broker, &agent.name, &conn, park).await
}

/// Shared capability tail (§4/§7): evaluate policy, a standing rule goes
/// straight to execution (still coalesced), no rule parks a held-open
/// prompt, then wait and relay the outcome.
async fn run_policied(
    broker: &Arc<Broker>,
    agent_name: &str,
    conn: &crate::types::Connection,
    park: ParkRequest,
) -> Response {
    let parked = match broker.policy.evaluate(agent_name, &conn.id) {
        crate::types::Decision::Allow => {
            let rule = broker.policy.matching_rule(agent_name, &conn.id);
            let mut entry = AuditEntry::new(
                AuditKind::AutoAllowed,
                format!("Auto-approved: {} → {}", agent_name, conn.name),
            )
            .agent(agent_name.to_string())
            .connection(conn.name.clone())
            .outcome("auto_allowed")
            .field(
                "approval_state",
                crate::wire::ApprovalState::Executing.as_str(),
            );
            if let Some(rule) = rule {
                entry = entry.rule(rule.id);
            }
            broker.audit.append(entry);
            broker.approvals.run_preapproved(park)
        }
        crate::types::Decision::Deny => {
            return err(StatusCode::FORBIDDEN, ErrorReason::DeniedByPolicy);
        }
        crate::types::Decision::Prompt => broker.approvals.park(park),
    };

    match parked {
        Ok(Parked::Wait(handle)) => match handle.wait().await {
            Some(outcome) => outcome_response(outcome),
            None => err(StatusCode::INTERNAL_SERVER_ERROR, ErrorReason::BrokerShutdown),
        },
        Ok(Parked::Replay(outcome)) => outcome_response(outcome),
        Err(ParkError::RequestIdMismatch) => err(StatusCode::CONFLICT, ErrorReason::RequestIdMismatch),
    }
}

/* ------------------------------ WS open ----------------------------------- */

#[derive(Deserialize)]
struct OpenBody {
    connection: String,
    /// Idempotency key, session-creating opens coalesce like mutating
    /// calls (§4).
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
        return err(StatusCode::INTERNAL_SERVER_ERROR, ErrorReason::BridgeNotRunning);
    };

    let action = format!("Open WebSocket bridge → {}", conn.target());
    broker.audit.append(
        AuditEntry::new(
            AuditKind::Requested,
            format!("{} requested {}", agent.name, conn.name),
        )
        .agent(agent.name.clone())
        .connection(conn.name.clone())
        .detail(action.clone())
        .field("target", conn.target()),
    );

    let request = ApprovalRequest {
        id: Uuid::new_v4(),
        agent: agent.name.clone(),
        kind: ApprovalKind::Ws,
        connection: Some(broker.connection_summary(&conn)),
        action,
        notification: format!(
            "{} wants to use {}: {}",
            agent.name,
            conn.name,
            conn.target()
        ),
        received_at: chrono::Utc::now(),
        deadline: chrono::Utc::now(),
        identity: None,
        inherited: vec![],
        http: None,
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
    // bridge URL (§4.2).
    let executor: crate::approvals::Executor = {
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
                            // instead of prose-only (§5b).
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

    let park = ParkRequest {
        request,
        coalesce_key,
        payload_hash,
        retain_outcome: true,
        executor,
    };
    run_policied(broker, &agent.name, &conn, park).await
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
        host,
        port,
        user,
        host_key_fingerprint,
    } = &conn.config
    else {
        unreachable!()
    };
    let (host, port, user, host_key_fingerprint) = (
        host.clone(),
        *port,
        user.clone(),
        host_key_fingerprint.clone(),
    );

    let action = format!("Open SSH agent → {}", conn.target());
    broker.audit.append(
        AuditEntry::new(
            AuditKind::Requested,
            format!("{} requested {}", agent.name, conn.name),
        )
        .agent(agent.name.clone())
        .connection(conn.name.clone())
        .detail(action.clone()),
    );

    let request = ApprovalRequest {
        id: Uuid::new_v4(),
        agent: agent.name.clone(),
        kind: ApprovalKind::Ssh,
        connection: Some(broker.connection_summary(&conn)),
        action,
        notification: format!(
            "{} wants to use {}: {}",
            agent.name,
            conn.name,
            conn.target()
        ),
        received_at: chrono::Utc::now(),
        deadline: chrono::Utc::now(),
        identity: None,
        inherited: vec![],
        http: None,
    };

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
    // the ticket, hand back the SSH_AUTH_SOCK path (§4.4). The socket path is
    // the capability, so it is minted only after approval.
    let executor: crate::approvals::Executor = {
        let broker = broker.clone();
        let conn = conn.clone();
        let agent_name = agent.name.clone();
        Box::pin(async move {
            match crate::capability::ssh::open_agent(broker.clone(), agent_name, conn).await {
                Ok(auth_sock) => ExecOutcome {
                    status: 200,
                    body: json!({
                        "auth_sock": auth_sock,
                        "host": host,
                        "port": port,
                        "user": user,
                        "host_key_fingerprint": host_key_fingerprint,
                        // The redemption deadline, machine-actionable
                        // instead of prose-only (§5b).
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

    let park = ParkRequest {
        request,
        coalesce_key,
        payload_hash,
        retain_outcome: true,
        executor,
    };
    run_policied(broker, &agent.name, &conn, park).await
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
        return err(StatusCode::INTERNAL_SERVER_ERROR, ErrorReason::ProxyNotRunning);
    };
    let ConnectionConfig::Pg { dbname, .. } = &conn.config else {
        unreachable!()
    };
    let dbname = dbname.clone();

    let action = format!("Open Postgres session → {}", conn.target());
    broker.audit.append(
        AuditEntry::new(
            AuditKind::Requested,
            format!("{} requested {}", agent.name, conn.name),
        )
        .agent(agent.name.clone())
        .connection(conn.name.clone())
        .detail(action.clone())
        .field("target", conn.target()),
    );

    let request = ApprovalRequest {
        id: Uuid::new_v4(),
        agent: agent.name.clone(),
        kind: ApprovalKind::Pg,
        connection: Some(broker.connection_summary(&conn)),
        action,
        notification: format!(
            "{} wants to use {}: {}",
            agent.name,
            conn.name,
            conn.target()
        ),
        received_at: chrono::Utc::now(),
        deadline: chrono::Utc::now(),
        identity: None,
        inherited: vec![],
        http: None,
    };

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

    // Executor: issue the ticket and hand back the password-less DSN (§4.3).
    // Unlike WS, nothing is dialed here, the proxy dials upstream at
    // redemption time. The ticket is deliberately NOT embedded in the DSN
    // (it would sit in ps-visible argv and shell history for its window):
    // agents supply it out-of-band via PGPASSWORD.
    let executor: crate::approvals::Executor = {
        let broker = broker.clone();
        let conn = conn.clone();
        let agent_name = agent.name.clone();
        Box::pin(async move {
            let ticket =
                broker
                    .data_plane
                    .issue(&agent_name, &conn, crate::sessions::TicketPayload::Pg);
            let dsn =
                format!("postgres://ticket@127.0.0.1:{proxy_port}/{dbname}?sslmode=disable");
            ExecOutcome {
                status: 200,
                body: json!({
                    // Ready-to-adapt invocation; the ticket goes via the
                    // environment, never argv (§4.3).
                    "example": format!("PGPASSWORD=<ticket> psql \"{dsn}\""),
                    "dsn": dsn,
                    "ticket": ticket,
                    // The redemption deadline, machine-actionable instead
                    // of prose-only (§5b).
                    "expires_in_seconds": broker.config.ticket_ttl.as_secs(),
                }),
            }
        })
    };

    let park = ParkRequest {
        request,
        coalesce_key,
        payload_hash,
        retain_outcome: true,
        executor,
    };
    run_policied(broker, &agent.name, &conn, park).await
}
