//! Agent-facing MCP Streamable HTTP host.
//!
//! This is intentionally separate from [`crate::mcp`], the trusted UI's
//! short-lived upstream MCP client. The host accepts untrusted agent traffic,
//! authenticates every request against the broker identity, and owns
//! downstream session state. Tool projection is layered onto this transport;
//! authorization remains in the broker.

use std::collections::{HashMap, HashSet};
use std::convert::Infallible;
use std::future::Future;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::{to_bytes, Body, Bytes};
use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum::Router;
use base64::Engine as _;
use serde::Deserialize;
use serde_json::{json, Map, Value};
use sha2::{Digest as _, Sha256};
use tower::ServiceExt as _;

use crate::broker::Broker;
use crate::identity::{validate_agent_name, TokenError};
use crate::mcp::{PROTOCOL_VERSION, SUPPORTED_PROTOCOL_VERSIONS};

pub const MCP_PATH: &str = "/mcp";
const MAX_BODY_BYTES: usize = 8 * 1024 * 1024;
const SESSION_IDLE: Duration = Duration::from_secs(30 * 60);
const SESSION_LIMIT: usize = 256;

tokio::task_local! {
    static ACTIVE_REQUEST_KEY: String;
}

#[derive(Clone)]
struct HostState {
    broker: Arc<Broker>,
    port: u16,
    sessions: Arc<SessionStore>,
    active_requests: Arc<Mutex<HashMap<String, ActiveRequest>>>,
}

#[derive(Clone, Debug, Deserialize)]
struct BrokerConnection {
    name: String,
    #[serde(rename = "type")]
    kind: String,
    target: String,
    endpoint: String,
    wired: bool,
    #[serde(default)]
    mcp_path: Option<String>,
    #[serde(default)]
    allowed_tools: Option<Vec<String>>,
    #[serde(default)]
    recent_ssh_refusal: Option<Value>,
}

#[derive(Clone, Default)]
struct ProtocolCatalog {
    discovered: bool,
    tools: HashMap<String, UpstreamToolBinding>,
    search_only: Vec<UpstreamToolBinding>,
    resources: Vec<UpstreamResourceBinding>,
    templates: Vec<UpstreamTemplateBinding>,
    prompts: Vec<UpstreamPromptBinding>,
    errors: Vec<(String, String)>,
}

#[derive(Clone)]
struct UpstreamToolBinding {
    connection: BrokerConnection,
    upstream_name: String,
    definition: Value,
}

#[derive(Clone)]
struct UpstreamResourceBinding {
    connection: BrokerConnection,
    /// Original upstream URI, forwarded verbatim on `resources/read`.
    uri: String,
    /// Connection-namespaced URI published to agents; see [`expose_resource_uri`].
    exposed_uri: String,
    definition: Value,
}

#[derive(Clone)]
struct UpstreamTemplateBinding {
    connection: BrokerConnection,
    /// Original upstream URI template, forwarded verbatim on completion.
    uri_template: String,
    /// Connection-namespaced template published to agents.
    exposed_uri_template: String,
    definition: Value,
    supports_completion: bool,
}

#[derive(Clone)]
struct UpstreamPromptBinding {
    connection: BrokerConnection,
    upstream_name: String,
    exposed_name: String,
    definition: Value,
    supports_completion: bool,
}

struct BrokerResponse {
    status: StatusCode,
    body: Value,
    retry_after: Option<String>,
}

#[derive(Clone)]
struct Session {
    client_id: uuid::Uuid,
    protocol_version: String,
    initialized: bool,
    last_seen: Instant,
    native_tools: HashMap<String, BrokerConnection>,
    protocol_catalog: ProtocolCatalog,
    listed_tools: Option<HashSet<String>>,
    listed_resources: Option<HashSet<String>>,
    listed_templates: Option<HashSet<String>>,
    listed_prompts: Option<HashSet<String>>,
    events: tokio::sync::broadcast::Sender<Value>,
}

struct ActiveRequest {
    cancel: Option<tokio::sync::oneshot::Sender<()>>,
    upstreams: Vec<UpstreamCancellation>,
    elicitations: Vec<ElicitationCancellation>,
}

#[derive(Clone)]
struct UpstreamCancellation {
    connection: BrokerConnection,
    session_id: Option<String>,
    protocol_version: String,
    request_id: u64,
}

#[derive(Clone)]
struct ElicitationCancellation {
    connection: String,
    correlation_token: String,
}

#[derive(Default)]
struct SessionStore {
    sessions: Mutex<HashMap<String, Session>>,
}

impl SessionStore {
    fn insert(&self, id: String, session: Session) {
        let mut sessions = self.sessions.lock().unwrap();
        Self::sweep_locked(&mut sessions);
        if sessions.len() >= SESSION_LIMIT {
            if let Some(oldest) = sessions
                .iter()
                .min_by_key(|(_, session)| session.last_seen)
                .map(|(id, _)| id.clone())
            {
                sessions.remove(&oldest);
            }
        }
        sessions.insert(id, session);
    }

    fn get(&self, id: &str, client_id: uuid::Uuid) -> Option<Session> {
        let mut sessions = self.sessions.lock().unwrap();
        Self::sweep_locked(&mut sessions);
        let session = sessions.get_mut(id)?;
        if session.client_id != client_id {
            return None;
        }
        session.last_seen = Instant::now();
        Some(session.clone())
    }

    fn mark_initialized(&self, id: &str, client_id: uuid::Uuid) {
        if let Some(session) = self.sessions.lock().unwrap().get_mut(id) {
            if session.client_id == client_id {
                session.initialized = true;
                session.last_seen = Instant::now();
            }
        }
    }

    fn replace_native_tools(
        &self,
        id: &str,
        client_id: uuid::Uuid,
        tools: Vec<(String, BrokerConnection)>,
    ) {
        if let Some(session) = self.sessions.lock().unwrap().get_mut(id) {
            if session.client_id == client_id {
                session.native_tools = tools.into_iter().collect();
                session.last_seen = Instant::now();
            }
        }
    }

    fn replace_protocol_catalog(&self, id: &str, client_id: uuid::Uuid, catalog: ProtocolCatalog) {
        if let Some(session) = self.sessions.lock().unwrap().get_mut(id) {
            if session.client_id == client_id {
                session.protocol_catalog = catalog;
                session.last_seen = Instant::now();
            }
        }
    }

    fn note_catalog(
        &self,
        id: &str,
        client_id: uuid::Uuid,
        kind: CatalogKind,
        current: HashSet<String>,
    ) {
        let mut sessions = self.sessions.lock().unwrap();
        let Some(session) = sessions.get_mut(id) else {
            return;
        };
        if session.client_id != client_id {
            return;
        }
        let previous = match kind {
            CatalogKind::Tools => &mut session.listed_tools,
            CatalogKind::Resources => &mut session.listed_resources,
            CatalogKind::Templates => &mut session.listed_templates,
            CatalogKind::Prompts => &mut session.listed_prompts,
        };
        let changed = previous
            .as_ref()
            .is_some_and(|previous| previous != &current);
        *previous = Some(current);
        session.last_seen = Instant::now();
        if changed {
            let _ = session.events.send(json!({
                "jsonrpc": "2.0",
                "method": kind.notification(),
            }));
        }
    }

    fn remove(&self, id: &str, client_id: uuid::Uuid) -> bool {
        let mut sessions = self.sessions.lock().unwrap();
        if sessions
            .get(id)
            .is_some_and(|session| session.client_id == client_id)
        {
            sessions.remove(id);
            true
        } else {
            false
        }
    }

    fn sweep_locked(sessions: &mut HashMap<String, Session>) {
        let now = Instant::now();
        let cutoff = now.checked_sub(SESSION_IDLE).unwrap_or(now);
        sessions.retain(|_, session| session.last_seen >= cutoff);
    }
}

#[derive(Clone, Copy)]
enum CatalogKind {
    Tools,
    Resources,
    Templates,
    Prompts,
}

impl CatalogKind {
    fn notification(self) -> &'static str {
        match self {
            Self::Tools => "notifications/tools/list_changed",
            Self::Resources | Self::Templates => "notifications/resources/list_changed",
            Self::Prompts => "notifications/prompts/list_changed",
        }
    }
}

/// A running in-process MCP listener. Dropping it stops accepting traffic.
pub struct McpHostHandle {
    addr: std::net::SocketAddr,
    task: tokio::task::JoinHandle<()>,
}

impl McpHostHandle {
    pub fn addr(&self) -> std::net::SocketAddr {
        self.addr
    }

    pub fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub fn mcp_url(&self) -> String {
        format!("{}{}", self.base_url(), MCP_PATH)
    }
}

impl Drop for McpHostHandle {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Bind the Rust MCP host on an ephemeral loopback port.
pub async fn serve(broker: Arc<Broker>) -> io::Result<McpHostHandle> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let app = router(broker, addr.port());
    let task = tokio::spawn(async move {
        if let Err(error) = axum::serve(listener, app).await {
            tracing::error!("Rust MCP host exited: {error}");
        }
    });
    Ok(McpHostHandle { addr, task })
}

fn router(broker: Arc<Broker>, port: u16) -> Router {
    Router::new()
        .route(MCP_PATH, any(handle))
        .with_state(HostState {
            broker,
            port,
            sessions: Arc::new(SessionStore::default()),
            active_requests: Arc::new(Mutex::new(HashMap::new())),
        })
}

fn rpc_id(value: &Value) -> Value {
    match value.get("id") {
        Some(Value::String(id)) => Value::String(id.clone()),
        Some(Value::Number(id)) => Value::Number(id.clone()),
        Some(Value::Null) => Value::Null,
        _ => Value::Null,
    }
}

fn json_response(status: StatusCode, value: Value) -> Response {
    (status, axum::Json(value)).into_response()
}

fn rpc_error(status: StatusCode, code: i64, message: &str, id: Value) -> Response {
    json_response(
        status,
        json!({
            "jsonrpc": "2.0",
            "error": {"code": code, "message": message},
            "id": id,
        }),
    )
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(char::is_whitespace)?;
    (scheme.eq_ignore_ascii_case("Bearer") && !token.trim().is_empty()).then(|| token.trim())
}

fn host_is_loopback(host: Option<&HeaderValue>, port: u16) -> bool {
    let Some(host) = host.and_then(|value| value.to_str().ok()) else {
        return false;
    };
    host == format!("127.0.0.1:{port}")
        || host == format!("localhost:{port}")
        || host == format!("[::1]:{port}")
}

fn origin_is_loopback(origin: Option<&HeaderValue>) -> bool {
    let Some(origin) = origin.and_then(|value| value.to_str().ok()) else {
        return true;
    };
    let Ok(origin) = url::Url::parse(origin) else {
        return false;
    };
    if !matches!(origin.scheme(), "http" | "https") {
        return false;
    }
    match origin.host() {
        Some(url::Host::Domain(domain)) => domain == "localhost",
        Some(url::Host::Ipv4(ip)) => ip == std::net::Ipv4Addr::LOCALHOST,
        Some(url::Host::Ipv6(ip)) => ip == std::net::Ipv6Addr::LOCALHOST,
        None => false,
    }
}

async fn handle(State(state): State<HostState>, request: Request<Body>) -> Response {
    if !host_is_loopback(request.headers().get(header::HOST), state.port) {
        return rpc_error(
            StatusCode::MISDIRECTED_REQUEST,
            -32000,
            "Misdirected request",
            Value::Null,
        );
    }
    if !origin_is_loopback(request.headers().get(header::ORIGIN)) {
        return rpc_error(
            StatusCode::FORBIDDEN,
            -32000,
            "Cross-origin MCP requests are not allowed",
            Value::Null,
        );
    }

    let (parts, body) = request.into_parts();
    let body = if parts.method == http::Method::POST {
        let bytes = match to_bytes(body, MAX_BODY_BYTES + 1).await {
            Ok(bytes) if bytes.len() <= MAX_BODY_BYTES => bytes,
            _ => {
                return rpc_error(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    -32000,
                    "MCP request body exceeds the 8 MiB limit",
                    Value::Null,
                )
            }
        };
        if bytes.is_empty() {
            Value::Null
        } else {
            match serde_json::from_slice::<Value>(&bytes) {
                Ok(value) => value,
                Err(_) => {
                    return rpc_error(StatusCode::BAD_REQUEST, -32700, "Parse error", Value::Null)
                }
            }
        }
    } else {
        Value::Null
    };
    let id = rpc_id(&body);

    let Some(token) = bearer(&parts.headers) else {
        return unauthorized(id);
    };
    let verified = match state.broker.identity.verify(token) {
        Ok(verified) => verified,
        Err(error) => {
            state.broker.audit_auth_failure(
                "mcp",
                error.reason().as_str(),
                "loopback",
                Some("127.0.0.1"),
            );
            return unauthorized_with_reason(id, error);
        }
    };
    let label = parts
        .headers
        .get(crate::daemon::CLIENT_LABEL_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| validate_agent_name(value))
        .unwrap_or(crate::daemon::DEFAULT_CLIENT_LABEL);

    let session_id = parts
        .headers
        .get("mcp-session-id")
        .and_then(|value| value.to_str().ok());
    let session = session_id.and_then(|id| state.sessions.get(id, verified.client_id));

    if session_id.is_some() && session.is_none() {
        return rpc_error(
            StatusCode::NOT_FOUND,
            -32001,
            "Unknown or expired session",
            id,
        );
    }

    if parts.method == http::Method::DELETE {
        let Some(session_id) = session_id else {
            return rpc_error(
                StatusCode::BAD_REQUEST,
                -32000,
                "Expected an MCP session id",
                id,
            );
        };
        state.sessions.remove(session_id, verified.client_id);
        return StatusCode::NO_CONTENT.into_response();
    }

    if parts.method == http::Method::GET {
        let Some(session) = session else {
            return rpc_error(
                StatusCode::BAD_REQUEST,
                -32000,
                "Expected an MCP session id",
                id,
            );
        };
        if parts
            .headers
            .get("mcp-protocol-version")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|version| version != session.protocol_version)
        {
            return rpc_error(
                StatusCode::BAD_REQUEST,
                -32600,
                "MCP protocol version does not match the session",
                id,
            );
        }
        return event_stream(session);
    }

    if parts.method != http::Method::POST {
        return rpc_error(
            StatusCode::METHOD_NOT_ALLOWED,
            -32000,
            "Expected an initialize request",
            id,
        );
    }

    if let Some(session) = session {
        if let Some(version) = parts
            .headers
            .get("mcp-protocol-version")
            .and_then(|value| value.to_str().ok())
        {
            if version != session.protocol_version {
                return rpc_error(
                    StatusCode::BAD_REQUEST,
                    -32600,
                    "MCP protocol version does not match the session",
                    id,
                );
            }
        }
        return handle_session(
            &state,
            session_id.unwrap(),
            verified.client_id,
            session,
            body,
            token,
            label,
        )
        .await;
    }

    if body.get("method").and_then(Value::as_str) != Some("initialize") {
        return rpc_error(
            StatusCode::BAD_REQUEST,
            -32600,
            "Expected an initialize request",
            id,
        );
    }
    initialize(&state, verified.client_id, body)
}

fn initialize(state: &HostState, client_id: uuid::Uuid, request: Value) -> Response {
    let requested = request
        .pointer("/params/protocolVersion")
        .and_then(Value::as_str)
        .unwrap_or(PROTOCOL_VERSION);
    let protocol_version = if SUPPORTED_PROTOCOL_VERSIONS.contains(&requested) {
        requested
    } else {
        PROTOCOL_VERSION
    };
    let session_id = uuid::Uuid::new_v4().to_string();
    let (events, _) = tokio::sync::broadcast::channel(64);
    state.sessions.insert(
        session_id.clone(),
        Session {
            client_id,
            protocol_version: protocol_version.to_string(),
            initialized: false,
            last_seen: Instant::now(),
            native_tools: HashMap::new(),
            protocol_catalog: ProtocolCatalog::default(),
            listed_tools: None,
            listed_resources: None,
            listed_templates: None,
            listed_prompts: None,
            events,
        },
    );
    let mut response = json_response(
        StatusCode::OK,
        json!({
            "jsonrpc": "2.0",
            "id": rpc_id(&request),
            "result": {
                "protocolVersion": protocol_version,
                "capabilities": {
                    "tools": {"listChanged": true},
                    "resources": {"listChanged": true},
                    "prompts": {"listChanged": true},
                    "completions": {},
                },
                "serverInfo": {
                    "name": "agentmfa",
                    "version": env!("CARGO_PKG_VERSION"),
                },
                "instructions": "AgentMFA brokers API, database, SSH, and MCP access. \
                    Credentials are injected by the broker and never exposed to the agent. \
                    Use agentmfa_status when an expected tool is missing.",
            },
        }),
    );
    response.headers_mut().insert(
        "mcp-session-id",
        HeaderValue::from_str(&session_id).expect("UUID is a header value"),
    );
    response
}

fn event_stream(session: Session) -> Response {
    let receiver = session.events.subscribe();
    let stream = futures::stream::unfold(receiver, |mut receiver| async move {
        loop {
            match receiver.recv().await {
                Ok(message) => {
                    let frame = format!("event: message\ndata: {message}\n\n");
                    return Some((Ok::<Bytes, Infallible>(Bytes::from(frame)), receiver));
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
            }
        }
    });
    let mut response = Response::new(Body::from_stream(stream));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/event-stream"),
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-cache, no-transform"),
    );
    response
}

async fn handle_session(
    state: &HostState,
    session_id: &str,
    client_id: uuid::Uuid,
    session: Session,
    request: Value,
    token: &str,
    label: &str,
) -> Response {
    let method = request.get("method").and_then(Value::as_str);
    if method == Some("notifications/initialized") {
        state.sessions.mark_initialized(session_id, client_id);
        return StatusCode::ACCEPTED.into_response();
    }
    if method == Some("notifications/cancelled") {
        if let Some(request_id) = request.pointer("/params/requestId") {
            cancel_active_request(
                state,
                session_id,
                request_id,
                token.to_string(),
                label.to_string(),
            );
        }
        return StatusCode::ACCEPTED.into_response();
    }
    if method.is_some_and(|method| method.starts_with("notifications/")) {
        return StatusCode::ACCEPTED.into_response();
    }
    if method == Some("ping") {
        return json_response(
            StatusCode::OK,
            json!({"jsonrpc": "2.0", "id": rpc_id(&request), "result": {}}),
        );
    }
    // The MCP spec asks clients to send `notifications/initialized`, and we
    // record it when they do. The Node baseline also accepts the next request
    // from older/minimal clients that omit it, so compatibility cannot make
    // this notification an authorization gate.
    run_cancellable(state, session_id, &request, async {
        match method {
            Some("tools/list") => {
                list_tools(
                    state, session_id, client_id, &session, token, label, &request,
                )
                .await
            }
            Some("tools/call") => {
                call_tool(
                    state, session_id, client_id, &session, token, label, &request,
                )
                .await
            }
            Some("resources/list") => {
                list_resources(
                    state, session_id, client_id, &session, token, label, &request,
                )
                .await
            }
            Some("resources/templates/list") => {
                list_resource_templates(
                    state, session_id, client_id, &session, token, label, &request,
                )
                .await
            }
            Some("resources/read") => {
                read_resource(
                    state, session_id, client_id, &session, token, label, &request,
                )
                .await
            }
            Some("prompts/list") => {
                list_prompts(
                    state, session_id, client_id, &session, token, label, &request,
                )
                .await
            }
            Some("prompts/get") => {
                get_prompt(
                    state, session_id, client_id, &session, token, label, &request,
                )
                .await
            }
            Some("completion/complete") => {
                complete(
                    state, session_id, client_id, &session, token, label, &request,
                )
                .await
            }
            _ => rpc_error(StatusCode::OK, -32601, "Method not found", rpc_id(&request)),
        }
    })
    .await
}

fn request_key(session_id: &str, id: &Value) -> Option<String> {
    matches!(id, Value::String(_) | Value::Number(_)).then(|| {
        format!(
            "{session_id}:{}",
            serde_json::to_string(id).unwrap_or_default()
        )
    })
}

async fn run_cancellable<F>(
    state: &HostState,
    session_id: &str,
    request: &Value,
    future: F,
) -> Response
where
    F: Future<Output = Response>,
{
    let id = rpc_id(request);
    let Some(key) = request_key(session_id, &id) else {
        return future.await;
    };
    let (cancel, receiver) = tokio::sync::oneshot::channel();
    state.active_requests.lock().unwrap().insert(
        key.clone(),
        ActiveRequest {
            cancel: Some(cancel),
            upstreams: Vec::new(),
            elicitations: Vec::new(),
        },
    );
    let response = ACTIVE_REQUEST_KEY
        .scope(key.clone(), async move {
            tokio::select! {
                response = future => response,
                _ = receiver => rpc_error(StatusCode::OK, -32800, "Request cancelled", id),
            }
        })
        .await;
    state.active_requests.lock().unwrap().remove(&key);
    response
}

fn cancel_active_request(
    state: &HostState,
    session_id: &str,
    request_id: &Value,
    token: String,
    label: String,
) {
    let Some(key) = request_key(session_id, request_id) else {
        return;
    };
    let (cancel, upstreams, elicitations) = {
        let mut requests = state.active_requests.lock().unwrap();
        let Some(active) = requests.get_mut(&key) else {
            return;
        };
        (
            active.cancel.take(),
            active.upstreams.clone(),
            active.elicitations.clone(),
        )
    };
    if let Some(cancel) = cancel {
        let _ = cancel.send(());
    }
    let state = state.clone();
    tokio::spawn(async move {
        for upstream in upstreams {
            forward_upstream_cancellation(&state, &token, &label, &upstream).await;
        }
        for elicitation in elicitations {
            let _ = broker_call(
                &state,
                &token,
                &label,
                http::Method::POST,
                "/v1/elicit/cancel",
                Some(json!({
                    "connection": elicitation.connection,
                    "correlation_token": elicitation.correlation_token,
                })),
            )
            .await;
        }
    });
}

async fn broker_call(
    state: &HostState,
    token: &str,
    label: &str,
    method: http::Method,
    path: &str,
    body: Option<Value>,
) -> Result<BrokerResponse, String> {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(crate::daemon::CLIENT_LABEL_HEADER, label)
        .header(header::ACCEPT, "application/json");
    let body = match body {
        Some(body) => {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
            Body::from(serde_json::to_vec(&body).map_err(|error| error.to_string())?)
        }
        None => Body::empty(),
    };
    let request = builder.body(body).map_err(|error| error.to_string())?;
    let response = crate::daemon::router(state.broker.clone())
        .oneshot(request)
        .await
        .map_err(|error| error.to_string())?;
    let status = response.status();
    let retry_after = response
        .headers()
        .get(header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let bytes = to_bytes(response.into_body(), MAX_BODY_BYTES)
        .await
        .map_err(|error| error.to_string())?;
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes)
            .map_err(|error| format!("the broker returned invalid JSON: {error}"))?
    };
    Ok(BrokerResponse {
        status,
        body,
        retry_after,
    })
}

fn record_upstream_cancellation(state: &HostState, cancellation: UpstreamCancellation) {
    let _ = ACTIVE_REQUEST_KEY.try_with(|key| {
        if let Some(active) = state.active_requests.lock().unwrap().get_mut(key) {
            active.upstreams.push(cancellation);
        }
    });
}

fn clear_upstream_cancellation(
    state: &HostState,
    connection: &str,
    session_id: Option<&str>,
    request_id: u64,
) {
    let _ = ACTIVE_REQUEST_KEY.try_with(|key| {
        if let Some(active) = state.active_requests.lock().unwrap().get_mut(key) {
            active.upstreams.retain(|item| {
                item.connection.name != connection
                    || item.session_id.as_deref() != session_id
                    || item.request_id != request_id
            });
        }
    });
}

fn record_elicitation_cancellation(state: &HostState, cancellation: ElicitationCancellation) {
    let _ = ACTIVE_REQUEST_KEY.try_with(|key| {
        if let Some(active) = state.active_requests.lock().unwrap().get_mut(key) {
            active.elicitations.push(cancellation);
        }
    });
}

fn clear_elicitation_cancellation(state: &HostState, correlation_token: &str) {
    let _ = ACTIVE_REQUEST_KEY.try_with(|key| {
        if let Some(active) = state.active_requests.lock().unwrap().get_mut(key) {
            active
                .elicitations
                .retain(|item| item.correlation_token != correlation_token);
        }
    });
}

async fn forward_upstream_cancellation(
    state: &HostState,
    token: &str,
    label: &str,
    upstream: &UpstreamCancellation,
) {
    let mut headers = Map::from_iter([
        (
            "accept".into(),
            Value::String("application/json, text/event-stream".into()),
        ),
        (
            "content-type".into(),
            Value::String("application/json".into()),
        ),
        (
            "mcp-protocol-version".into(),
            Value::String(upstream.protocol_version.clone()),
        ),
        (
            "mcp-method".into(),
            Value::String("notifications/cancelled".into()),
        ),
    ]);
    if let Some(session_id) = &upstream.session_id {
        headers.insert("mcp-session-id".into(), Value::String(session_id.clone()));
    }
    let mut call = json!({
        "connection": upstream.connection.name,
        "method": "POST",
        "path": upstream.connection.mcp_path,
        "headers": headers,
        "body": {
            "jsonrpc": "2.0",
            "method": "notifications/cancelled",
            "params": {
                "requestId": upstream.request_id,
                "reason": "downstream request cancelled",
            },
        },
    });
    let _ = broker_call(
        state,
        token,
        label,
        http::Method::POST,
        "/v1/http",
        Some(call.clone()),
    )
    .await;
    if upstream.session_id.is_some() {
        call["method"] = Value::String("DELETE".into());
        call.as_object_mut().unwrap().remove("body");
        let _ = broker_call(
            state,
            token,
            label,
            http::Method::POST,
            "/v1/http",
            Some(call),
        )
        .await;
    }
}

async fn connections(
    state: &HostState,
    token: &str,
    label: &str,
) -> Result<Vec<BrokerConnection>, String> {
    let response = broker_call(
        state,
        token,
        label,
        http::Method::GET,
        "/v1/connections",
        None,
    )
    .await?;
    if !response.status.is_success() {
        return Err(broker_failure(&response));
    }
    serde_json::from_value(response.body)
        .map_err(|error| format!("the broker returned an invalid connection list: {error}"))
}

fn tool_name_candidate(connection: &BrokerConnection) -> String {
    let slug: String = connection
        .name
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '_' || character == '-' {
                character
            } else {
                '_'
            }
        })
        .collect();
    let suffix = if connection.kind == "api" {
        "request"
    } else {
        "open"
    };
    format!("agentmfa_{slug}_{suffix}")
}

fn short_hash(identity: &str) -> String {
    let digest = Sha256::digest(identity.as_bytes());
    digest
        .iter()
        .take(5)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn bounded_tool_name(candidate: &str, identity: &str) -> String {
    const LIMIT: usize = 64;
    if candidate.len() <= LIMIT {
        return candidate.to_string();
    }
    let suffix = format!("_{}", short_hash(identity));
    format!("{}{}", &candidate[..LIMIT - suffix.len()], suffix)
}

fn alternate_tool_name(candidate: &str, identity: &str, attempt: usize) -> String {
    const LIMIT: usize = 64;
    let suffix = format!("_{}", short_hash(&format!("{identity}\0{attempt}")));
    format!(
        "{}{}",
        &candidate[..candidate.len().min(LIMIT - suffix.len())],
        suffix
    )
}

fn native_tools<'a>(
    connections: &[BrokerConnection],
    reserved: impl IntoIterator<Item = &'a str>,
) -> Vec<(String, BrokerConnection)> {
    let mut taken = std::collections::HashSet::from([
        "agentmfa_status".to_string(),
        "agentmfa_connect".to_string(),
        "agentmfa_search_tools".to_string(),
        "agentmfa_call_tool".to_string(),
    ]);
    // A session's discovered upstream tool names are already on the surface;
    // a native connection wired afterwards must not collide with them.
    taken.extend(reserved.into_iter().map(str::to_string));
    let mut tools = Vec::new();
    for connection in connections
        .iter()
        .filter(|connection| connection.wired && connection.mcp_path.is_none())
    {
        let candidate = tool_name_candidate(connection);
        let identity = format!("{}\0{}", connection.kind, connection.name);
        let preferred = bounded_tool_name(&candidate, &identity);
        let mut name = preferred.clone();
        let mut attempt = 1;
        while taken.contains(&name) && attempt <= 32 {
            name =
                alternate_tool_name(&preferred, &format!("{}\0native", connection.name), attempt);
            attempt += 1;
        }
        if taken.insert(name.clone()) {
            tools.push((name, connection.clone()));
        }
    }
    tools
}

fn tool_schema(connection: &BrokerConnection) -> Value {
    if connection.kind != "api" {
        return json!({
            "type": "object",
            "properties": {
                "request_id": {
                    "type": "string",
                    "description": "Idempotency key; retries with the same value reuse the open",
                },
            },
            "additionalProperties": false,
        });
    }
    json!({
        "type": "object",
        "properties": {
            "method": {
                "type": "string",
                "enum": ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
            },
            "path": {"type": "string"},
            "headers": {
                "anyOf": [
                    {"type": "object", "additionalProperties": {"type": "string"}},
                    {
                        "type": "array",
                        "items": {
                            "type": "array",
                            "prefixItems": [{"type": "string"}, {"type": "string"}],
                            "minItems": 2,
                            "maxItems": 2
                        }
                    }
                ]
            },
            "body": {},
            "body_base64": {"type": "string"},
            "request_id": {"type": "string"}
        },
        "required": ["method", "path"],
        "additionalProperties": false,
    })
}

fn describe(connection: &BrokerConnection) -> String {
    match connection.kind.as_str() {
        "api" => format!(
            "Make an HTTP request to {} through AgentMFA. The API credential is \
             injected by the broker and never exposed here. The result is \
             {{status, headers, body, body_encoding}}.",
            connection.target
        ),
        "pg" => format!(
            "Open a Postgres session on {}. Returns a password-less DSN and \
             short-lived ticket.",
            connection.target
        ),
        "ssh" => format!(
            "Open an SSH session to {}. Returns an SSH_AUTH_SOCK path while the \
             private key stays in the broker.",
            connection.target
        ),
        _ => format!("Use the AgentMFA connection \"{}\".", connection.name),
    }
}

fn native_output_schema(connection: &BrokerConnection) -> Value {
    match connection.kind.as_str() {
        "api" => json!({
            "type": "object",
            "properties": {
                "status": {"type": "integer"},
                "headers": {"type": "object"},
                "body": {"type": "string"},
                "body_encoding": {"enum": ["utf8", "base64"]},
            },
            "additionalProperties": true,
        }),
        "pg" => json!({
            "type": "object",
            "properties": {
                "dsn": {"type": "string"},
                "ticket": {"type": "string"},
                "expires_in_seconds": {"type": "integer"},
            },
            "additionalProperties": true,
        }),
        _ => json!({
            "type": "object",
            "properties": {
                "auth_sock": {"type": "string"},
                "destination": {"type": "string"},
                "host": {"type": "string"},
                "port": {"type": "integer"},
                "user": {"type": "string"},
                "host_key_fingerprint": {"type": ["string", "null"]},
                "expires_in_seconds": {"type": "integer"},
            },
            "additionalProperties": true,
        }),
    }
}

fn native_tool_definition(name: &str, connection: &BrokerConnection) -> Value {
    json!({
        "name": name,
        "title": connection.name,
        "description": describe(connection),
        "inputSchema": tool_schema(connection),
        "outputSchema": native_output_schema(connection),
        "annotations": {
            "idempotentHint": false,
            "openWorldHint": connection.kind == "api",
        },
    })
}

fn status_tool_definition() -> Value {
    json!({
        "name": "agentmfa_status",
        "title": "AgentMFA status",
        "description": "Report which AgentMFA tools this agent can use and what to do when there are none.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": false},
        "annotations": {
            "readOnlyHint": true,
            "idempotentHint": true,
            "openWorldHint": false,
        },
    })
}

fn connect_tool_definition() -> Value {
    json!({
        "name": "agentmfa_connect",
        "title": "Request a new tool",
        "description": "Ask the user to connect a service that is not configured. This files a request in AgentMFA; it grants nothing.",
        "inputSchema": {
            "type": "object",
            "properties": {"service": {"type": "string", "minLength": 1, "maxLength": 120}},
            "required": ["service"],
            "additionalProperties": false,
        },
        "annotations": {
            "destructiveHint": false,
            "idempotentHint": true,
            "openWorldHint": false,
        },
    })
}

fn search_tools_definition(count: usize) -> Value {
    json!({
        "name": "agentmfa_search_tools",
        "title": "Search available tools",
        "description": format!(
            "{count} upstream tools are search-only because this session exceeded its tool budget."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {"query": {"type": "string", "minLength": 1, "maxLength": 200}},
            "required": ["query"],
            "additionalProperties": false,
        },
        "annotations": {
            "readOnlyHint": true,
            "idempotentHint": true,
            "openWorldHint": false,
        },
    })
}

fn call_search_tool_definition() -> Value {
    json!({
        "name": "agentmfa_call_tool",
        "title": "Call a searchable tool",
        "description": "Call an upstream tool found with agentmfa_search_tools.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "connection": {"type": "string", "minLength": 1},
                "tool": {"type": "string", "minLength": 1},
                "arguments": {"type": "object", "additionalProperties": true},
            },
            "required": ["connection", "tool"],
            "additionalProperties": false,
        },
    })
}

fn tool_catalog_names(
    native: &[(String, BrokerConnection)],
    protocol: &ProtocolCatalog,
) -> HashSet<String> {
    let mut names = HashSet::from([
        "agentmfa_status".to_string(),
        "agentmfa_connect".to_string(),
    ]);
    names.extend(native.iter().map(|(name, _)| name.clone()));
    names.extend(protocol.tools.keys().cloned());
    if !protocol.search_only.is_empty() {
        names.insert("agentmfa_search_tools".into());
        names.insert("agentmfa_call_tool".into());
    }
    names
}

fn note_protocol_catalogs(
    state: &HostState,
    session_id: &str,
    client_id: uuid::Uuid,
    native: &[(String, BrokerConnection)],
    protocol: &ProtocolCatalog,
) {
    state.sessions.note_catalog(
        session_id,
        client_id,
        CatalogKind::Tools,
        tool_catalog_names(native, protocol),
    );
    state.sessions.note_catalog(
        session_id,
        client_id,
        CatalogKind::Resources,
        protocol
            .resources
            .iter()
            .map(|item| item.uri.clone())
            .collect(),
    );
    state.sessions.note_catalog(
        session_id,
        client_id,
        CatalogKind::Templates,
        protocol
            .templates
            .iter()
            .map(|item| item.uri_template.clone())
            .collect(),
    );
    state.sessions.note_catalog(
        session_id,
        client_id,
        CatalogKind::Prompts,
        protocol
            .prompts
            .iter()
            .map(|item| item.exposed_name.clone())
            .collect(),
    );
}

async fn list_tools(
    state: &HostState,
    session_id: &str,
    client_id: uuid::Uuid,
    session: &Session,
    token: &str,
    label: &str,
    request: &Value,
) -> Response {
    let mut tools = vec![status_tool_definition(), connect_tool_definition()];
    let listed = connections(state, token, label).await;
    let native = match &listed {
        Ok(connections) => {
            let native = native_tools(
                connections,
                session.protocol_catalog.tools.keys().map(String::as_str),
            );
            state
                .sessions
                .replace_native_tools(session_id, client_id, native.clone());
            native
        }
        Err(_) => session
            .native_tools
            .iter()
            .map(|(name, connection)| (name.clone(), connection.clone()))
            .collect(),
    };
    tools.extend(
        native
            .iter()
            .map(|(name, connection)| native_tool_definition(name, connection)),
    );
    let protocol = ensure_protocol_catalog(
        state,
        session_id,
        client_id,
        session,
        token,
        label,
        listed.as_deref().ok(),
        native.iter().map(|(name, _)| name.as_str()),
    )
    .await;
    tools.extend(
        protocol
            .tools
            .values()
            .map(|binding| binding.definition.clone()),
    );
    if !protocol.search_only.is_empty() {
        tools.push(search_tools_definition(protocol.search_only.len()));
        tools.push(call_search_tool_definition());
    }
    state.sessions.note_catalog(
        session_id,
        client_id,
        CatalogKind::Tools,
        tools
            .iter()
            .filter_map(|tool| tool.get("name").and_then(Value::as_str).map(str::to_string))
            .collect(),
    );
    json_response(
        StatusCode::OK,
        json!({
            "jsonrpc": "2.0",
            "id": rpc_id(request),
            "result": {"tools": tools},
        }),
    )
}

async fn call_tool(
    state: &HostState,
    session_id: &str,
    client_id: uuid::Uuid,
    session: &Session,
    token: &str,
    label: &str,
    request: &Value,
) -> Response {
    let name = request.pointer("/params/name").and_then(Value::as_str);
    let arguments = request
        .pointer("/params/arguments")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let result = match name {
        Some("agentmfa_status") => {
            status_result(state, session_id, client_id, session, token, label).await
        }
        Some("agentmfa_connect") => connect_result(state, token, label, &arguments).await,
        Some("agentmfa_search_tools") if session.protocol_catalog.discovered => {
            search_upstream_tools(&session.protocol_catalog, &arguments)
        }
        Some("agentmfa_call_tool") if session.protocol_catalog.discovered => {
            call_search_only_tool(state, token, label, &session.protocol_catalog, &arguments).await
        }
        Some(name) if session.protocol_catalog.tools.contains_key(name) => {
            call_upstream_tool(
                state,
                token,
                label,
                session.protocol_catalog.tools.get(name).unwrap(),
                arguments,
            )
            .await
        }
        Some(name) if session.native_tools.contains_key(name) => {
            native_result(
                state,
                token,
                label,
                name,
                arguments,
                session.native_tools.get(name).cloned(),
            )
            .await
        }
        Some(name) => {
            // The session does not know the tool. On a fresh session — or one
            // the bridge recovered after an eviction — the client may call a
            // remembered tool without listing first, and the Node host served
            // that because it built the whole surface at session open. Rebuild
            // the surfaces once, then dispatch against what came back.
            let (native, catalog) =
                refreshed_surfaces(state, session_id, client_id, session, token, label).await;
            match name {
                "agentmfa_search_tools" => search_upstream_tools(&catalog, &arguments),
                "agentmfa_call_tool" => {
                    call_search_only_tool(state, token, label, &catalog, &arguments).await
                }
                name if catalog.tools.contains_key(name) => {
                    call_upstream_tool(
                        state,
                        token,
                        label,
                        catalog.tools.get(name).unwrap(),
                        arguments,
                    )
                    .await
                }
                name => {
                    native_result(
                        state,
                        token,
                        label,
                        name,
                        arguments,
                        native.get(name).cloned(),
                    )
                    .await
                }
            }
        }
        None => tool_error("Tool name is required"),
    };
    json_response(
        StatusCode::OK,
        json!({
            "jsonrpc": "2.0",
            "id": rpc_id(request),
            "result": result,
        }),
    )
}

/// Bring a session's native tools and protocol catalog up to date, the same
/// way `tools/list` does, and hand both back for immediate dispatch.
async fn refreshed_surfaces(
    state: &HostState,
    session_id: &str,
    client_id: uuid::Uuid,
    session: &Session,
    token: &str,
    label: &str,
) -> (HashMap<String, BrokerConnection>, ProtocolCatalog) {
    let listed = connections(state, token, label).await;
    let native = match &listed {
        Ok(connections) => {
            let native = native_tools(
                connections,
                session.protocol_catalog.tools.keys().map(String::as_str),
            );
            state
                .sessions
                .replace_native_tools(session_id, client_id, native.clone());
            native
        }
        Err(_) => session
            .native_tools
            .iter()
            .map(|(name, connection)| (name.clone(), connection.clone()))
            .collect(),
    };
    let catalog = ensure_protocol_catalog(
        state,
        session_id,
        client_id,
        session,
        token,
        label,
        listed.as_deref().ok(),
        native.iter().map(|(name, _)| name.as_str()),
    )
    .await;
    (native.into_iter().collect(), catalog)
}

async fn status_result(
    state: &HostState,
    session_id: &str,
    client_id: uuid::Uuid,
    session: &Session,
    token: &str,
    label: &str,
) -> Value {
    match connections(state, token, label).await {
        Ok(connections) => {
            let registered = native_tools(
                &connections,
                session.protocol_catalog.tools.keys().map(String::as_str),
            );
            state
                .sessions
                .replace_native_tools(session_id, client_id, registered.clone());
            let protocol = ensure_protocol_catalog(
                state,
                session_id,
                client_id,
                session,
                token,
                label,
                Some(&connections),
                registered.iter().map(|(name, _)| name.as_str()),
            )
            .await;
            let mut tools: Vec<Value> = registered
                .iter()
                .map(|(tool, connection)| {
                    json!({
                        "tool": tool,
                        "name": connection.name,
                        "type": connection.kind,
                        "target": connection.target,
                    })
                })
                .collect();
            tools.extend(protocol.tools.iter().map(|(tool, binding)| {
                json!({
                    "tool": tool,
                    "name": binding.connection.name,
                    "type": binding.connection.kind,
                    "target": binding.connection.target,
                })
            }));
            let recent_ssh_refusals: Vec<Value> = connections
                .iter()
                .filter_map(|connection| {
                    connection.recent_ssh_refusal.as_ref().map(|refusal| {
                        let mut row = refusal.as_object().cloned().unwrap_or_default();
                        row.insert("name".into(), Value::String(connection.name.clone()));
                        Value::Object(row)
                    })
                })
                .collect();
            let mut status = Map::new();
            status.insert("agent".into(), Value::String(label.to_string()));
            status.insert("tools".into(), Value::Array(tools));
            if registered.is_empty() && protocol.tools.is_empty() {
                status.insert(
                    "hint".into(),
                    Value::String(
                        "No tools are enabled for agents. Ask the user to open AgentMFA and enable or add the needed tool under Tools.".into(),
                    ),
                );
            }
            if !recent_ssh_refusals.is_empty() {
                status.insert(
                    "recent_ssh_refusals".into(),
                    Value::Array(recent_ssh_refusals),
                );
            }
            if !protocol.errors.is_empty() {
                status.insert(
                    "errors".into(),
                    Value::Array(
                        protocol
                            .errors
                            .iter()
                            .map(|(name, error)| {
                                json!({"scope": "upstream", "name": name, "error": error})
                            })
                            .collect(),
                    ),
                );
            }
            if !protocol.search_only.is_empty() {
                status.insert(
                    "search_only_tools".into(),
                    Value::Number(protocol.search_only.len().into()),
                );
                status.insert(
                    "search_hint".into(),
                    Value::String("More tools are available via agentmfa_search_tools".into()),
                );
            }
            note_protocol_catalogs(state, session_id, client_id, &registered, &protocol);
            tool_text(Value::Object(status))
        }
        Err(error) => tool_text(json!({
            "agent": label,
            "tools": [],
            "errors": [{"scope": "broker", "error": error}],
            "hint": "AgentMFA could not list connections. Reconnect after the broker is reachable.",
        })),
    }
}

async fn connect_result(
    state: &HostState,
    token: &str,
    label: &str,
    arguments: &Map<String, Value>,
) -> Value {
    let Some(service) = arguments.get("service").and_then(Value::as_str) else {
        return tool_error("service is required");
    };
    let response = broker_call(
        state,
        token,
        label,
        http::Method::POST,
        "/v1/connect-requests",
        Some(json!({"service": service})),
    )
    .await;
    match response {
        Ok(response) if response.status.is_success() => {
            let already = response.body["status"] == "already_requested";
            tool_text(Value::String(if already {
                format!("Already requested. Ask the user to approve \"{service}\" in AgentMFA.")
            } else {
                format!(
                    "Requested. Ask the user to add \"{service}\" in AgentMFA and enable it for agents."
                )
            }))
        }
        Ok(response) => tool_error(&format!(
            "could not file the request: {}",
            broker_failure(&response)
        )),
        Err(error) => tool_error(&format!("could not file the request: {error}")),
    }
}

/// Every upstream tool this session knows about — search-only first, then the
/// registered ones with the name they are exposed under. The search and
/// generic-call meta-tools work over the whole index, the way the Node host's
/// did, so a registered tool found by search is answered with its direct name.
fn upstream_tool_index(
    catalog: &ProtocolCatalog,
) -> impl Iterator<Item = (Option<&str>, &UpstreamToolBinding)> {
    catalog
        .search_only
        .iter()
        .map(|binding| (None, binding))
        .chain(
            catalog
                .tools
                .iter()
                .map(|(exposed, binding)| (Some(exposed.as_str()), binding)),
        )
}

fn search_upstream_tools(catalog: &ProtocolCatalog, arguments: &Map<String, Value>) -> Value {
    let Some(query) = arguments.get("query").and_then(Value::as_str) else {
        return tool_error("query is required");
    };
    let terms: Vec<String> = query
        .split_whitespace()
        .map(str::to_ascii_lowercase)
        .collect();
    let mut scored: Vec<(usize, Option<&str>, &UpstreamToolBinding)> = upstream_tool_index(catalog)
        .filter_map(|(registered_as, binding)| {
            let description = binding.definition["description"]
                .as_str()
                .unwrap_or_default()
                .to_ascii_lowercase();
            let name = binding.upstream_name.to_ascii_lowercase();
            let score = terms
                .iter()
                .map(|term| {
                    usize::from(name.contains(term)) * 2 + usize::from(description.contains(term))
                })
                .sum();
            (score > 0).then_some((score, registered_as, binding))
        })
        .collect();
    scored.sort_by(|left, right| {
        right
            .0
            .cmp(&left.0)
            .then_with(|| left.2.upstream_name.cmp(&right.2.upstream_name))
    });
    let results: Vec<Value> = scored
        .into_iter()
        .take(20)
        .map(|(_, registered_as, binding)| {
            json!({
                "tool": binding.upstream_name,
                "connection": binding.connection.name,
                "description": binding.definition["description"],
                "parameters": framed_upstream_text(
                    &binding.definition["inputSchema"].to_string(),
                    4_096,
                )
                .0,
                "call": match registered_as {
                    Some(exposed) => json!({"tool": exposed}),
                    None => json!({
                        "tool": "agentmfa_call_tool",
                        "arguments": {
                            "connection": binding.connection.name,
                            "tool": binding.upstream_name,
                        },
                    }),
                },
            })
        })
        .collect();
    let empty = results.is_empty();
    tool_text(json!({
        "results": results,
        "hint": empty.then_some("no tools matched; try broader terms"),
    }))
}

async fn call_search_only_tool(
    state: &HostState,
    token: &str,
    label: &str,
    catalog: &ProtocolCatalog,
    arguments: &Map<String, Value>,
) -> Value {
    let connection = arguments.get("connection").and_then(Value::as_str);
    let tool = arguments.get("tool").and_then(Value::as_str);
    let Some((_, binding)) = upstream_tool_index(catalog).find(|(_, binding)| {
        Some(binding.connection.name.as_str()) == connection
            && Some(binding.upstream_name.as_str()) == tool
    }) else {
        return tool_error("the requested searchable tool is not in this session's catalog");
    };
    let call_arguments = arguments
        .get("arguments")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    call_upstream_tool(state, token, label, binding, call_arguments).await
}

async fn native_result(
    state: &HostState,
    token: &str,
    label: &str,
    name: &str,
    arguments: Map<String, Value>,
    connection: Option<BrokerConnection>,
) -> Value {
    let Some(connection) = connection else {
        return tool_error(&format!("Tool {name} not found"));
    };
    let mut body = arguments;
    body.insert("connection".into(), Value::String(connection.name.clone()));
    let response = broker_call(
        state,
        token,
        label,
        http::Method::POST,
        &connection.endpoint,
        Some(Value::Object(body)),
    )
    .await;
    match response {
        Ok(response) if response.status.is_success() => {
            tool_text(project_for_mcp(&connection, response.body))
        }
        Ok(response) => broker_tool_refusal(&connection, &response),
        Err(error) => tool_error(&format!("AgentMFA call failed: {error}")),
    }
}

/// A broker refusal, told to the agent as what to do about it rather than a
/// bare status: the agent should learn it lacks access (or that a human said
/// no) instead of retrying a transport failure blindly.
fn broker_tool_refusal(connection: &BrokerConnection, response: &BrokerResponse) -> Value {
    let reason = response.body["reason"].as_str().unwrap_or("broker_error");
    let detail = response.body["detail"].as_str();
    if response.status == StatusCode::FORBIDDEN {
        return match reason {
            "approval_denied" => tool_error(&format!(
                "The user refused this call to \"{}\". Do not retry it; \
                 ask the user before trying a changed request.",
                connection.name
            )),
            "approval_unavailable" => tool_error(&format!(
                "Confirmation is enabled for \"{}\", but no AgentMFA approval \
                 window is attached. Ask the user to open AgentMFA.",
                connection.name
            )),
            _ => tool_error(&format!(
                "AgentMFA policy refused \"{}\". {}",
                connection.name,
                detail.map(str::to_string).unwrap_or_else(|| format!(
                    "Ask the user to enable \"{}\" for agents in AgentMFA.",
                    connection.name
                )),
            )),
        };
    }
    if response.status == StatusCode::REQUEST_TIMEOUT || reason == "approval_timeout" {
        return tool_error(&format!(
            "Nobody answered the confirmation for \"{}\" in time. \
             Retrying will ask the user again.",
            connection.name
        ));
    }
    if response.status == StatusCode::TOO_MANY_REQUESTS {
        let retry = response
            .body
            .get("retry_after_seconds")
            .and_then(Value::as_u64)
            .map(|seconds| seconds.to_string())
            .or_else(|| response.retry_after.clone());
        return tool_error(&format!(
            "AgentMFA rate limited this call: {}.{}",
            detail.unwrap_or(reason),
            retry
                .map(|seconds| format!(" Retry after {seconds} seconds."))
                .unwrap_or_default(),
        ));
    }
    tool_error(&broker_failure(response))
}

fn project_for_mcp(connection: &BrokerConnection, value: Value) -> Value {
    if connection.kind != "api" {
        return value;
    }
    let Value::Object(mut object) = value else {
        return value;
    };
    object.remove("set_cookie_headers");
    if let Some(Value::Object(headers)) = object.get_mut("headers") {
        for (name, value) in headers {
            if name.eq_ignore_ascii_case("cookie") || name.eq_ignore_ascii_case("set-cookie") {
                *value = Value::String("[OMITTED BY AGENTMFA]".into());
            }
        }
    }
    Value::Object(object)
}

fn tool_text(value: Value) -> Value {
    let text = bounded_tool_text(&value, 128 * 1024);
    let structured = serde_json::from_str::<Value>(&text)
        .ok()
        .filter(Value::is_object);
    if let Some(structured) = structured {
        json!({
            "content": [{"type": "text", "text": text}],
            "structuredContent": structured,
        })
    } else {
        json!({"content": [{"type": "text", "text": text}]})
    }
}

fn bounded_tool_text(value: &Value, limit: usize) -> String {
    let serialized = match value {
        Value::String(text) => text.clone(),
        _ => serde_json::to_string(value).unwrap_or_else(|_| "null".into()),
    };
    if serialized.len() <= limit {
        return serialized;
    }
    let original_bytes = serialized.len();
    let body = value
        .get("body")
        .and_then(Value::as_str)
        .unwrap_or(&serialized);
    let mut low = 0;
    let mut high = body.len().min(limit);
    let mut best = json!({
        "preview": "",
        "_truncated": {"original_bytes": original_bytes, "limit_bytes": limit},
    })
    .to_string();
    while low <= high {
        let middle = (low + high) / 2;
        let prefix = utf8_prefix(body, middle);
        let mut shell = match value {
            Value::Object(object) => Value::Object(object.clone()),
            _ => json!({"preview": ""}),
        };
        if let Value::Object(object) = &mut shell {
            if object.contains_key("body") {
                object.insert("body".into(), Value::String(prefix.to_string()));
            } else {
                object.insert("preview".into(), Value::String(prefix.to_string()));
            }
            object.insert(
                "_truncated".into(),
                json!({"original_bytes": original_bytes, "limit_bytes": limit}),
            );
        }
        let candidate = shell.to_string();
        if candidate.len() <= limit {
            best = candidate;
            low = middle + 1;
        } else if middle == 0 {
            break;
        } else {
            high = middle - 1;
        }
    }
    best
}

fn utf8_prefix(value: &str, max_bytes: usize) -> &str {
    let mut end = value.len().min(max_bytes);
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

fn tool_error(message: &str) -> Value {
    json!({
        "isError": true,
        "content": [{"type": "text", "text": message}],
    })
}

fn broker_failure(response: &BrokerResponse) -> String {
    let reason = response.body["reason"].as_str().unwrap_or("broker_error");
    let detail = response.body["detail"].as_str();
    let retry = response
        .body
        .get("retry_after_seconds")
        .and_then(Value::as_u64)
        .map(|seconds| seconds.to_string())
        .or_else(|| response.retry_after.clone());
    format!(
        "{reason}{}{}",
        detail
            .map(|detail| format!(": {detail}"))
            .unwrap_or_default(),
        retry
            .map(|seconds| format!("; retry after {seconds} seconds"))
            .unwrap_or_default(),
    )
}

struct UpstreamClient<'a> {
    state: &'a HostState,
    token: &'a str,
    label: &'a str,
    connection: &'a BrokerConnection,
    next_id: u64,
    session_id: Option<String>,
    protocol_version: String,
    initialized: bool,
    capabilities: Value,
}

impl<'a> UpstreamClient<'a> {
    fn new(
        state: &'a HostState,
        token: &'a str,
        label: &'a str,
        connection: &'a BrokerConnection,
    ) -> Self {
        Self {
            state,
            token,
            label,
            connection,
            next_id: 1,
            session_id: None,
            protocol_version: PROTOCOL_VERSION.to_string(),
            initialized: false,
            capabilities: json!({}),
        }
    }

    async fn send(&mut self, method: &str, payload: Option<Value>) -> Result<Value, String> {
        let mut headers = Map::new();
        headers.insert(
            "accept".into(),
            Value::String("application/json, text/event-stream".into()),
        );
        if payload.is_some() {
            headers.insert(
                "content-type".into(),
                Value::String("application/json".into()),
            );
        }
        if let Some(session_id) = &self.session_id {
            headers.insert("mcp-session-id".into(), Value::String(session_id.clone()));
        }
        if self.initialized {
            headers.insert(
                "mcp-protocol-version".into(),
                Value::String(self.protocol_version.clone()),
            );
        }
        if let Some(payload) = &payload {
            if let Some(rpc_method) = payload.get("method").and_then(Value::as_str) {
                headers.insert("mcp-method".into(), Value::String(rpc_method.into()));
            }
            // Printable ASCII only: this is a routing hint, and a name that
            // is not header-safe would fail the whole relay call instead of
            // merely going unrouted (the body still carries the real value).
            if let Some(name) = payload
                .pointer("/params/name")
                .and_then(Value::as_str)
                .filter(|name| name.bytes().all(|byte| (0x20..=0x7e).contains(&byte)))
            {
                headers.insert("mcp-name".into(), Value::String(name.into()));
            }
        }
        let mut call = json!({
            "connection": self.connection.name,
            "method": method,
            "path": self.connection.mcp_path,
            "headers": headers,
        });
        if let Some(payload) = payload {
            call["body"] = payload;
        }
        let response = broker_call(
            self.state,
            self.token,
            self.label,
            http::Method::POST,
            "/v1/http",
            Some(call),
        )
        .await?;
        if !response.status.is_success() {
            return Err(broker_failure(&response));
        }
        let relay = response.body;
        let status = relay.get("status").and_then(Value::as_u64).unwrap_or(500);
        if !(200..300).contains(&status) {
            return Err(format!("the MCP server answered {status}"));
        }
        if let Some(session_id) = relay_header(&relay, "mcp-session-id") {
            self.session_id = Some(session_id);
        }
        Ok(relay)
    }

    async fn initialize(&mut self) -> Result<(), String> {
        let result = self
            .request(
                "initialize",
                json!({
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {
                        "name": "agentmfa",
                        "version": env!("CARGO_PKG_VERSION"),
                    },
                }),
            )
            .await?;
        let protocol = result
            .get("protocolVersion")
            .and_then(Value::as_str)
            .ok_or_else(|| "initialize returned no protocolVersion".to_string())?;
        if !SUPPORTED_PROTOCOL_VERSIONS.contains(&protocol) {
            return Err(format!(
                "the MCP server negotiated unsupported protocol version {protocol}; supported: {}",
                SUPPORTED_PROTOCOL_VERSIONS.join(", ")
            ));
        }
        self.protocol_version = protocol.to_string();
        self.capabilities = result
            .get("capabilities")
            .cloned()
            .unwrap_or_else(|| json!({}));
        self.initialized = true;
        let _ = self
            .send(
                "POST",
                Some(json!({
                    "jsonrpc": "2.0",
                    "method": "notifications/initialized",
                })),
            )
            .await;
        Ok(())
    }

    async fn request(&mut self, method: &str, params: Value) -> Result<Value, String> {
        self.request_with_tokens(method, params)
            .await
            .map(|(result, _)| result)
    }

    async fn request_with_tokens(
        &mut self,
        method: &str,
        params: Value,
    ) -> Result<(Value, Map<String, Value>), String> {
        let id = self.next_id;
        self.next_id += 1;
        let cancellation_session = self.session_id.clone();
        record_upstream_cancellation(
            self.state,
            UpstreamCancellation {
                connection: self.connection.clone(),
                session_id: cancellation_session.clone(),
                protocol_version: self.protocol_version.clone(),
                request_id: id,
            },
        );
        let relay = self
            .send(
                "POST",
                Some(json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "method": method,
                    "params": params,
                })),
            )
            .await;
        clear_upstream_cancellation(
            self.state,
            &self.connection.name,
            cancellation_session.as_deref(),
            id,
        );
        let relay = relay?;
        let elicitation_tokens = relay
            .get("elicitation_tokens")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let answer = relay_messages(&relay)
            .into_iter()
            .find(|message| message.get("id").and_then(Value::as_u64) == Some(id))
            .ok_or_else(|| "the MCP server sent no response to the request".to_string())?;
        if let Some(error) = answer.get("error") {
            let code = error.get("code").and_then(Value::as_i64).unwrap_or(-32603);
            let message = error
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("the MCP server returned an error");
            return Err(format!("{message} (MCP {code})"));
        }
        Ok((
            answer.get("result").cloned().unwrap_or(Value::Null),
            elicitation_tokens,
        ))
    }

    async fn list_paged(
        &mut self,
        method: &str,
        key: &str,
        max_pages: usize,
    ) -> Result<Vec<Value>, String> {
        const MAX_ITEMS: usize = 2_000;
        let mut items = Vec::new();
        let mut cursor: Option<String> = None;
        for _ in 0..max_pages {
            let params = cursor
                .as_ref()
                .map(|cursor| json!({"cursor": cursor}))
                .unwrap_or_else(|| json!({}));
            let result = self.request(method, params).await?;
            if let Some(page) = result.get(key).and_then(Value::as_array) {
                for item in page {
                    if items.len() >= MAX_ITEMS {
                        return Ok(items);
                    }
                    items.push(item.clone());
                }
            }
            cursor = result
                .get("nextCursor")
                .and_then(Value::as_str)
                .map(str::to_string);
            if cursor.is_none() {
                return Ok(items);
            }
        }
        Ok(items)
    }

    async fn close(&mut self) {
        if self.session_id.is_none() {
            return;
        }
        let _ = self.send("DELETE", None).await;
    }
}

fn relay_header(relay: &Value, expected: &str) -> Option<String> {
    relay
        .get("headers")
        .and_then(Value::as_object)?
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(expected))
        .and_then(|(_, value)| value.as_str())
        .map(str::to_string)
}

fn relay_messages(relay: &Value) -> Vec<Value> {
    let body = relay.get("body").cloned().unwrap_or(Value::Null);
    if body.is_null() || body == "" {
        return Vec::new();
    }
    if !body.is_string() {
        return vec![body];
    }
    let mut text = body.as_str().unwrap_or_default().to_string();
    if relay.get("body_encoding").and_then(Value::as_str) == Some("base64") {
        let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(text.as_bytes()) else {
            return Vec::new();
        };
        text = String::from_utf8_lossy(&bytes).into_owned();
    }
    if let Ok(value) = serde_json::from_str(&text) {
        return vec![value];
    }
    text.replace("\r\n", "\n")
        .replace('\r', "\n")
        .split("\n\n")
        .filter_map(|frame| {
            let data = frame
                .lines()
                .filter_map(|line| line.strip_prefix("data:"))
                .map(|line| line.strip_prefix(' ').unwrap_or(line))
                .collect::<Vec<_>>()
                .join("\n");
            (!data.is_empty())
                .then(|| serde_json::from_str(&data).ok())
                .flatten()
        })
        .collect()
}

struct RawDiscovery {
    capabilities: Value,
    tools: Vec<Value>,
    resources: Vec<Value>,
    templates: Vec<Value>,
    prompts: Vec<Value>,
}

async fn discover_connection(
    state: &HostState,
    token: &str,
    label: &str,
    connection: &BrokerConnection,
) -> Result<RawDiscovery, String> {
    let mut client = UpstreamClient::new(state, token, label, connection);
    let result = async {
        client.initialize().await?;
        let capabilities = client.capabilities.clone();
        let tools = if capabilities.get("tools").is_some() {
            client.list_paged("tools/list", "tools", 32).await?
        } else {
            Vec::new()
        };
        let resources = if capabilities.get("resources").is_some() {
            client
                .list_paged("resources/list", "resources", 16)
                .await
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        let templates = if capabilities.get("resources").is_some() {
            client
                .list_paged("resources/templates/list", "resourceTemplates", 16)
                .await
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        let prompts = if capabilities.get("prompts").is_some() {
            client
                .list_paged("prompts/list", "prompts", 16)
                .await
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        Ok(RawDiscovery {
            capabilities,
            tools,
            resources,
            templates,
            prompts,
        })
    }
    .await;
    client.close().await;
    result
}

async fn discover_connection_bounded(
    state: &HostState,
    token: &str,
    label: &str,
    connection: &BrokerConnection,
) -> Result<RawDiscovery, String> {
    let deadline = std::env::var("AGENTMFA_DISCOVERY_DEADLINE_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(10_000);
    for attempt in 0..2 {
        match tokio::time::timeout(
            Duration::from_millis(deadline),
            discover_connection(state, token, label, connection),
        )
        .await
        {
            Ok(Ok(discovery)) => return Ok(discovery),
            Ok(Err(error)) if attempt == 1 => return Err(error),
            Err(_) if attempt == 1 => {
                return Err(format!(
                    "MCP discovery exceeded its {deadline}ms session-open deadline"
                ))
            }
            _ => tokio::time::sleep(Duration::from_millis(200)).await,
        }
    }
    unreachable!()
}

fn namespace(connection: &BrokerConnection) -> String {
    connection
        .name
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '_' || character == '-' {
                character
            } else {
                '_'
            }
        })
        .collect()
}

/// Wraps an upstream resource URI (or URI template) in a per-connection
/// namespace, so identical URIs from two connections can neither collide in
/// the catalog nor route a read through the other connection's credential.
/// The original URI is kept verbatim after the prefix and restored by
/// [`strip_resource_uri`] before anything is forwarded upstream.
fn expose_resource_uri(connection: &BrokerConnection, uri: &str) -> String {
    format!("agentmfa://{}/{uri}", namespace(connection))
}

fn strip_resource_uri<'a>(connection: &BrokerConnection, exposed: &'a str) -> Option<&'a str> {
    exposed.strip_prefix(&format!("agentmfa://{}/", namespace(connection)))
}

fn upstream_tool_candidate(connection: &BrokerConnection, tool: &str) -> String {
    let tool: String = tool
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '_' || character == '-' {
                character
            } else {
                '_'
            }
        })
        .collect();
    format!("agentmfa_{}_{}", namespace(connection), tool)
}

fn bounded_catalog_text(value: Option<&str>, max: usize) -> Option<String> {
    let value = value?;
    Some(crate::untrusted_text::cap(value, max))
}

fn insert_catalog_string(
    object: &mut Map<String, Value>,
    key: &str,
    value: Option<&str>,
    max: usize,
) {
    let value = if key == "description" {
        value.map(|value| framed_upstream_text(value, max).0)
    } else {
        bounded_catalog_text(value, max)
    };
    if let Some(value) = value {
        object.insert(key.into(), Value::String(value));
    }
}

fn upstream_tool_definition(
    exposed_name: &str,
    connection: &BrokerConnection,
    tool: &Value,
) -> Value {
    let upstream_name = tool.get("name").and_then(Value::as_str).unwrap_or("tool");
    let title = bounded_catalog_text(
        tool.get("title")
            .and_then(Value::as_str)
            .or(Some(upstream_name)),
        200,
    )
    .unwrap_or_else(|| upstream_name.to_string());
    let description = tool
        .get("description")
        .and_then(Value::as_str)
        .map(|description| framed_upstream_text(description, 8_192).0)
        .unwrap_or_else(|| upstream_name.to_string());
    let input_schema = tool
        .get("inputSchema")
        .filter(|schema| serde_json::to_vec(schema).is_ok_and(|bytes| bytes.len() <= 64 * 1024))
        .cloned()
        .unwrap_or_else(|| json!({"type": "object", "additionalProperties": true}));
    let mut definition = json!({
        "name": exposed_name,
        "title": title,
        "description": format!("Proxied from {}.\n{}", connection.name, description),
        "inputSchema": input_schema,
    });
    if let Some(output) = tool
        .get("outputSchema")
        .filter(|schema| serde_json::to_vec(schema).is_ok_and(|bytes| bytes.len() <= 64 * 1024))
    {
        definition["outputSchema"] = output.clone();
    }
    if let Some(annotations) = bounded_annotations(tool.get("annotations")) {
        definition["annotations"] = annotations;
    }
    definition
}

fn bounded_annotations(value: Option<&Value>) -> Option<Value> {
    let raw = value?.as_object()?;
    let mut annotations = Map::new();
    if let Some(title) = raw.get("title").and_then(Value::as_str) {
        annotations.insert(
            "title".into(),
            Value::String(crate::untrusted_text::cap(title, 200)),
        );
    }
    for hint in [
        "readOnlyHint",
        "destructiveHint",
        "idempotentHint",
        "openWorldHint",
    ] {
        if let Some(value) = raw.get(hint).and_then(Value::as_bool) {
            annotations.insert(hint.into(), Value::Bool(value));
        }
    }
    (!annotations.is_empty()).then_some(Value::Object(annotations))
}

async fn ensure_protocol_catalog(
    state: &HostState,
    session_id: &str,
    client_id: uuid::Uuid,
    session: &Session,
    token: &str,
    label: &str,
    listed: Option<&[BrokerConnection]>,
    native_names: impl Iterator<Item = &str>,
) -> ProtocolCatalog {
    if session.protocol_catalog.discovered {
        let mut catalog = session.protocol_catalog.clone();
        if let Some(connections) = listed {
            let current = |captured: &BrokerConnection| {
                connections.iter().any(|candidate| {
                    candidate.wired
                        && candidate.mcp_path.is_some()
                        && candidate.name == captured.name
                        && candidate.target == captured.target
                        && candidate.mcp_path == captured.mcp_path
                        && candidate.allowed_tools == captured.allowed_tools
                })
            };
            catalog
                .tools
                .retain(|_, binding| current(&binding.connection));
            catalog
                .search_only
                .retain(|binding| current(&binding.connection));
            catalog
                .resources
                .retain(|binding| current(&binding.connection));
            catalog
                .templates
                .retain(|binding| current(&binding.connection));
            catalog
                .prompts
                .retain(|binding| current(&binding.connection));
            let live_names: std::collections::HashSet<&str> = connections
                .iter()
                .filter(|connection| connection.wired && connection.mcp_path.is_some())
                .map(|connection| connection.name.as_str())
                .collect();
            catalog
                .errors
                .retain(|(name, _)| name == "broker" || live_names.contains(name.as_str()));
            state
                .sessions
                .replace_protocol_catalog(session_id, client_id, catalog.clone());
        }
        return catalog;
    }
    let mut catalog = ProtocolCatalog {
        discovered: true,
        ..ProtocolCatalog::default()
    };
    let Some(connections) = listed else {
        catalog.errors.push((
            "broker".into(),
            "could not list AgentMFA connections".into(),
        ));
        state
            .sessions
            .replace_protocol_catalog(session_id, client_id, catalog.clone());
        return catalog;
    };
    let mut taken: std::collections::HashSet<String> = native_names.map(str::to_string).collect();
    taken.extend([
        "agentmfa_status".into(),
        "agentmfa_connect".into(),
        "agentmfa_search_tools".into(),
        "agentmfa_call_tool".into(),
    ]);
    let mut taken_resources = std::collections::HashSet::new();
    let mut taken_templates = std::collections::HashSet::new();
    let mut taken_prompts = std::collections::HashSet::new();
    let tool_budget = std::env::var("AGENTMFA_TOOL_BUDGET")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(40);
    let mut registered_upstream_tools = 0usize;
    let upstreams: Vec<&BrokerConnection> = connections
        .iter()
        .filter(|connection| connection.wired && connection.mcp_path.is_some())
        .collect();
    let discoveries = futures::future::join_all(
        upstreams
            .iter()
            .map(|connection| discover_connection_bounded(state, token, label, connection)),
    )
    .await;
    for (connection, discovery) in upstreams.into_iter().zip(discoveries) {
        let discovery = match discovery {
            Ok(discovery) => discovery,
            Err(error) => {
                catalog.errors.push((connection.name.clone(), error));
                continue;
            }
        };
        let allowed = connection.allowed_tools.as_ref().map(|tools| {
            tools
                .iter()
                .map(String::as_str)
                .collect::<std::collections::HashSet<_>>()
        });
        for tool in discovery.tools.iter().filter(|tool| {
            let name = tool.get("name").and_then(Value::as_str);
            name.is_some()
                && allowed
                    .as_ref()
                    .is_none_or(|allowed| allowed.contains(name.unwrap()))
        }) {
            let upstream_name = tool.get("name").and_then(Value::as_str).unwrap();
            let candidate = upstream_tool_candidate(connection, upstream_name);
            let preferred =
                bounded_tool_name(&candidate, &format!("{}\0{upstream_name}", connection.name));
            let mut exposed = preferred.clone();
            let mut attempt = 1;
            while taken.contains(&exposed) && attempt <= 32 {
                exposed = alternate_tool_name(
                    &preferred,
                    &format!("{}\0{upstream_name}", connection.name),
                    attempt,
                );
                attempt += 1;
            }
            if taken.contains(&exposed) {
                continue;
            }
            let binding = UpstreamToolBinding {
                connection: connection.clone(),
                upstream_name: upstream_name.to_string(),
                definition: upstream_tool_definition(&exposed, connection, tool),
            };
            if registered_upstream_tools >= tool_budget {
                catalog.search_only.push(binding);
            } else {
                taken.insert(exposed.clone());
                catalog.tools.insert(exposed, binding);
                registered_upstream_tools += 1;
            }
        }
        // A curated tool subset fails closed for every non-tool capability:
        // a connection with `allowed_tools` set publishes no resources,
        // templates, or prompts, and — because reads, prompt gets, and
        // completions all route through catalog bindings — the corresponding
        // requests refuse rather than reach the upstream (MCP-U11).
        if connection.allowed_tools.is_none() {
            for resource in discovery.resources {
                let Some(uri) = resource.get("uri").and_then(Value::as_str) else {
                    continue;
                };
                let exposed_uri = expose_resource_uri(connection, uri);
                if !taken_resources.insert(exposed_uri.clone()) || catalog.resources.len() >= 100 {
                    tracing::warn!(
                        connection = %connection.name,
                        uri,
                        "dropping upstream resource: duplicate exposed URI or catalog cap"
                    );
                    continue;
                }
                let mut definition = Map::new();
                definition.insert("uri".into(), Value::String(exposed_uri.clone()));
                definition.insert(
                    "name".into(),
                    Value::String(
                        resource
                            .get("name")
                            .and_then(Value::as_str)
                            .unwrap_or(uri)
                            .to_string(),
                    ),
                );
                insert_catalog_string(
                    &mut definition,
                    "title",
                    resource.get("title").and_then(Value::as_str),
                    200,
                );
                insert_catalog_string(
                    &mut definition,
                    "description",
                    resource.get("description").and_then(Value::as_str),
                    8_192,
                );
                insert_catalog_string(
                    &mut definition,
                    "mimeType",
                    resource.get("mimeType").and_then(Value::as_str),
                    256,
                );
                catalog.resources.push(UpstreamResourceBinding {
                    connection: connection.clone(),
                    uri: uri.to_string(),
                    exposed_uri,
                    definition: Value::Object(definition),
                });
            }
            for template in discovery.templates {
                let Some(uri_template) = template.get("uriTemplate").and_then(Value::as_str) else {
                    continue;
                };
                let exposed_name = format!(
                    "{}/{}",
                    namespace(connection),
                    template
                        .get("name")
                        .and_then(Value::as_str)
                        .unwrap_or(uri_template)
                );
                if !taken_templates.insert(exposed_name.clone()) || catalog.templates.len() >= 100 {
                    tracing::warn!(
                        connection = %connection.name,
                        uri_template,
                        "dropping upstream resource template: duplicate name or catalog cap"
                    );
                    continue;
                }
                let exposed_uri_template = expose_resource_uri(connection, uri_template);
                let mut definition = Map::new();
                definition.insert(
                    "uriTemplate".into(),
                    Value::String(exposed_uri_template.clone()),
                );
                definition.insert("name".into(), Value::String(exposed_name.clone()));
                insert_catalog_string(
                    &mut definition,
                    "title",
                    template.get("title").and_then(Value::as_str),
                    200,
                );
                insert_catalog_string(
                    &mut definition,
                    "description",
                    template.get("description").and_then(Value::as_str),
                    8_192,
                );
                insert_catalog_string(
                    &mut definition,
                    "mimeType",
                    template.get("mimeType").and_then(Value::as_str),
                    256,
                );
                catalog.templates.push(UpstreamTemplateBinding {
                    connection: connection.clone(),
                    uri_template: uri_template.to_string(),
                    exposed_uri_template,
                    definition: Value::Object(definition),
                    supports_completion: discovery.capabilities.get("completions").is_some(),
                });
            }
        }
        if connection.allowed_tools.is_some() {
            // Same fail-closed rule as resources above: curated connections
            // expose their tool subset and nothing else.
            continue;
        }
        for prompt in discovery.prompts {
            let Some(upstream_name) = prompt.get("name").and_then(Value::as_str) else {
                continue;
            };
            let exposed_name = format!("{}/{}", namespace(connection), upstream_name);
            if !taken_prompts.insert(exposed_name.clone()) || catalog.prompts.len() >= 100 {
                continue;
            }
            let mut definition = Map::new();
            definition.insert("name".into(), Value::String(exposed_name.clone()));
            insert_catalog_string(
                &mut definition,
                "title",
                prompt.get("title").and_then(Value::as_str),
                200,
            );
            insert_catalog_string(
                &mut definition,
                "description",
                prompt.get("description").and_then(Value::as_str),
                8_192,
            );
            let arguments: Vec<Value> = prompt
                .get("arguments")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .take(64)
                .filter_map(|argument| {
                    let argument = argument.as_object()?;
                    let name = argument.get("name")?.as_str()?;
                    let mut projected = Map::new();
                    projected.insert(
                        "name".into(),
                        Value::String(crate::untrusted_text::cap(name, 256)),
                    );
                    insert_catalog_string(
                        &mut projected,
                        "description",
                        argument.get("description").and_then(Value::as_str),
                        8_192,
                    );
                    if let Some(required) = argument.get("required").and_then(Value::as_bool) {
                        projected.insert("required".into(), Value::Bool(required));
                    }
                    Some(Value::Object(projected))
                })
                .collect();
            if !arguments.is_empty() {
                definition.insert("arguments".into(), Value::Array(arguments));
            }
            catalog.prompts.push(UpstreamPromptBinding {
                connection: connection.clone(),
                upstream_name: upstream_name.to_string(),
                exposed_name,
                definition: Value::Object(definition),
                supports_completion: discovery.capabilities.get("completions").is_some(),
            });
        }
    }
    state
        .sessions
        .replace_protocol_catalog(session_id, client_id, catalog.clone());
    catalog
}

async fn call_upstream_tool(
    state: &HostState,
    token: &str,
    label: &str,
    binding: &UpstreamToolBinding,
    arguments: Map<String, Value>,
) -> Value {
    match upstream_operation(
        state,
        token,
        label,
        &binding.connection,
        "tools/call",
        json!({"name": binding.upstream_name, "arguments": arguments}),
    )
    .await
    {
        Ok(result) => sanitize_upstream_result(result, 128 * 1024, Some(&binding.connection)),
        Err(error) => tool_error(&format!(
            "The upstream MCP tool on \"{}\" failed: {error}",
            binding.connection.name
        )),
    }
}

const UNTRUSTED_BEGIN: &str = "[BEGIN UNTRUSTED UPSTREAM MCP CONTENT]";
const UNTRUSTED_END: &str = "[END UNTRUSTED UPSTREAM MCP CONTENT]";

fn framed_upstream_text(text: &str, budget: usize) -> (String, bool) {
    let sanitized = crate::untrusted_text::sanitize(text)
        .replace(UNTRUSTED_BEGIN, "‹elided upstream boundary marker›")
        .replace(UNTRUSTED_END, "‹elided upstream boundary marker›");
    let overhead = UNTRUSTED_BEGIN.len() + UNTRUSTED_END.len() + 2;
    let allowed = budget.saturating_sub(overhead);
    let prefix = utf8_prefix(&sanitized, allowed);
    (
        format!("{UNTRUSTED_BEGIN}\n{prefix}\n{UNTRUSTED_END}"),
        prefix.len() < sanitized.len(),
    )
}

/// Rewrites an upstream-provided resource URI on a result object to its
/// exposed, connection-namespaced form, so an agent that passes it back to
/// `resources/read` routes to the connection that produced it. Only a URI
/// already carrying *this* connection's namespace is left alone: a foreign
/// `agentmfa://` prefix is wrapped like any other upstream URI, so an
/// upstream cannot spoof a link that routes through another connection.
fn expose_result_uri(object: &mut Map<String, Value>, connection: &BrokerConnection) {
    if let Some(Value::String(uri)) = object.get("uri") {
        if strip_resource_uri(connection, uri).is_none() {
            let exposed = expose_resource_uri(connection, uri);
            object.insert("uri".into(), Value::String(exposed));
        }
    }
}

fn sanitize_upstream_result(
    value: Value,
    limit: usize,
    connection: Option<&BrokerConnection>,
) -> Value {
    let mut result = match value {
        Value::Object(result) => result,
        other => Map::from_iter([
            ("isError".into(), Value::Bool(true)),
            (
                "content".into(),
                json!([{"type": "text", "text": other.to_string()}]),
            ),
        ]),
    };
    result.retain(|key, _| {
        matches!(
            key.as_str(),
            "content" | "contents" | "structuredContent" | "isError" | "description" | "messages"
        )
    });
    let mut remaining = limit;
    let mut blocks = 64usize;
    let mut truncated = false;
    for field in ["content", "contents"] {
        let Some(Value::Array(items)) = result.remove(field) else {
            continue;
        };
        let mut sanitized_items = Vec::new();
        for mut item in items {
            if blocks == 0 {
                truncated = true;
                break;
            }
            blocks -= 1;
            let item_bytes = item.to_string().len();
            if let Value::Object(object) = &mut item {
                if let Some(Value::String(text)) = object.get("text") {
                    let shell_bytes = item_bytes.saturating_sub(text.len());
                    let (framed, was_truncated) = framed_upstream_text(
                        text,
                        remaining.saturating_sub(shell_bytes.saturating_add(256)),
                    );
                    object.insert("text".into(), Value::String(framed));
                    truncated |= was_truncated;
                } else if let Some(Value::Object(resource)) = object.get_mut("resource") {
                    if let Some(Value::String(text)) = resource.get("text") {
                        let shell_bytes = item_bytes.saturating_sub(text.len());
                        let (framed, was_truncated) = framed_upstream_text(
                            text,
                            remaining.saturating_sub(shell_bytes.saturating_add(256)),
                        );
                        resource.insert("text".into(), Value::String(framed));
                        truncated |= was_truncated;
                    }
                    if let Some(connection) = connection {
                        expose_result_uri(resource, connection);
                    }
                }
                // Resource URIs the agent may pass back to `resources/read`
                // (resource_link items, `resources/read` contents) must carry
                // the exposed namespace or the follow-up read will not route.
                if let Some(connection) = connection {
                    expose_result_uri(object, connection);
                }
            }
            let bytes = item.to_string().len();
            if bytes > remaining {
                truncated = true;
                break;
            }
            remaining -= bytes;
            sanitized_items.push(item);
        }
        if truncated && remaining > 256 {
            let (notice, _) =
                framed_upstream_text("[additional upstream content truncated]", remaining);
            sanitized_items.push(json!({"type": "text", "text": notice}));
        }
        result.insert(field.into(), Value::Array(sanitized_items));
    }
    if let Some(Value::String(description)) = result.remove("description") {
        let (description, was_truncated) = framed_upstream_text(&description, remaining);
        remaining = remaining.saturating_sub(description.len());
        truncated |= was_truncated;
        result.insert("description".into(), Value::String(description));
    }
    if let Some(Value::Array(messages)) = result.remove("messages") {
        let mut sanitized_messages = Vec::new();
        for mut message in messages.into_iter().take(64) {
            let item_bytes = message.to_string().len();
            if let Some(Value::Object(content)) = message
                .as_object_mut()
                .and_then(|message| message.get_mut("content"))
            {
                if let Some(Value::String(text)) = content.get("text") {
                    let shell_bytes = item_bytes.saturating_sub(text.len());
                    let (framed, was_truncated) = framed_upstream_text(
                        text,
                        remaining.saturating_sub(shell_bytes.saturating_add(256)),
                    );
                    content.insert("text".into(), Value::String(framed));
                    truncated |= was_truncated;
                }
                if let Some(connection) = connection {
                    if let Some(Value::Object(resource)) = content.get_mut("resource") {
                        expose_result_uri(resource, connection);
                    }
                    expose_result_uri(content, connection);
                }
            }
            let bytes = message.to_string().len();
            if bytes > remaining {
                truncated = true;
                break;
            }
            remaining -= bytes;
            sanitized_messages.push(message);
        }
        result.insert("messages".into(), Value::Array(sanitized_messages));
    }
    if let Some(structured) = result.get("structuredContent") {
        let bytes = structured.to_string().len();
        if bytes > remaining.min(32 * 1024) {
            result.insert(
                "structuredContent".into(),
                json!({"agentmfa_notice": "Upstream structured content was truncated"}),
            );
            truncated = true;
        } else {
            remaining = remaining.saturating_sub(bytes);
        }
    }
    let metadata = result
        .entry("_meta")
        .or_insert_with(|| json!({}))
        .as_object_mut();
    if let Some(metadata) = metadata {
        metadata.insert(
            "agentmfa".into(),
            json!({
                "provenance": "untrusted upstream MCP content",
                "text_truncated": truncated,
                "remaining_budget_bytes": remaining,
            }),
        );
    }
    Value::Object(result)
}

fn sanitize_completion_result(value: Value) -> Value {
    let values = value
        .pointer("/completion/values")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .take(100)
        .scan(32 * 1024usize, |remaining, item| {
            if *remaining == 0 {
                return None;
            }
            let item = crate::untrusted_text::cap(item, (*remaining).min(4_096));
            *remaining = remaining.saturating_sub(item.len());
            Some(Value::String(item))
        })
        .collect::<Vec<_>>();
    let mut completion = Map::from_iter([("values".into(), Value::Array(values))]);
    if let Some(has_more) = value
        .pointer("/completion/hasMore")
        .and_then(Value::as_bool)
    {
        completion.insert("hasMore".into(), Value::Bool(has_more));
    }
    if let Some(total) = value.pointer("/completion/total").and_then(Value::as_u64) {
        completion.insert("total".into(), Value::Number(total.into()));
    }
    json!({"completion": completion})
}

async fn upstream_operation(
    state: &HostState,
    token: &str,
    label: &str,
    connection: &BrokerConnection,
    method: &str,
    params: Value,
) -> Result<Value, String> {
    const MAX_ROUNDS: usize = 8;
    const TOTAL_BUDGET: Duration = Duration::from_secs(8 * 60);
    let started = Instant::now();
    let base = params.as_object().cloned().unwrap_or_default();
    let mut input_responses: Option<Map<String, Value>> = None;
    let mut request_state: Option<Value> = None;
    let mut terminal_answer_forwarded = false;
    for _ in 0..MAX_ROUNDS {
        let remaining = TOTAL_BUDGET
            .checked_sub(started.elapsed())
            .ok_or_else(|| "the MCP input flow exceeded its 8 minute time budget".to_string())?;
        let mut client = UpstreamClient::new(state, token, label, connection);
        let mut round_params = base.clone();
        if let Some(responses) = &input_responses {
            round_params.insert("inputResponses".into(), Value::Object(responses.clone()));
        }
        if let Some(request_state) = &request_state {
            round_params.insert("requestState".into(), request_state.clone());
        }
        let round = tokio::time::timeout(remaining, async {
            client.initialize().await?;
            client
                .request_with_tokens(method, Value::Object(round_params))
                .await
        })
        .await;
        client.close().await;
        let round = round
            .map_err(|_| "the MCP input flow exceeded its 8 minute time budget".to_string())?;
        let (result, tokens) = round?;
        if result.get("resultType").and_then(Value::as_str) != Some("input_required") {
            return Ok(result);
        }
        if terminal_answer_forwarded {
            return Err(
                "the MCP input flow remained open after the user declined or cancelled it".into(),
            );
        }
        let requests = result
            .get("inputRequests")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        if requests.is_empty() && result.get("requestState").is_none() {
            return Ok(result);
        }
        let mut responses = Map::new();
        let mut terminal = false;
        for (key, request) in requests {
            if request.get("method").and_then(Value::as_str) != Some("elicitation/create") {
                responses.insert(key, json!({"action": "decline"}));
                terminal = true;
                continue;
            }
            let correlation_token = tokens.get(&key).and_then(Value::as_str).unwrap_or_default();
            record_elicitation_cancellation(
                state,
                ElicitationCancellation {
                    connection: connection.name.clone(),
                    correlation_token: correlation_token.to_string(),
                },
            );
            // The wait for a human answer spends the same 8 minute budget as
            // the upstream rounds themselves, so a parked elicitation cannot
            // hold the call open past it.
            let remaining = TOTAL_BUDGET
                .checked_sub(started.elapsed())
                .ok_or_else(|| "the MCP input flow exceeded its 8 minute time budget".to_string());
            let answer = match remaining {
                Ok(remaining) => tokio::time::timeout(
                    remaining,
                    broker_call(
                        state,
                        token,
                        label,
                        http::Method::POST,
                        "/v1/elicit",
                        Some(json!({
                            "connection": connection.name,
                            "correlation_token": correlation_token,
                        })),
                    ),
                )
                .await
                .map_err(|_| "the MCP input flow exceeded its 8 minute time budget".to_string()),
                Err(error) => Err(error),
            };
            clear_elicitation_cancellation(state, correlation_token);
            let answer = answer??;
            if !answer.status.is_success() {
                return Err(broker_failure(&answer));
            }
            if matches!(
                answer.body.get("action").and_then(Value::as_str),
                Some("decline" | "cancel")
            ) {
                terminal = true;
            }
            responses.insert(key, answer.body);
        }
        input_responses = Some(responses);
        request_state = result.get("requestState").cloned();
        terminal_answer_forwarded = terminal;
    }
    Err(format!(
        "the MCP server kept requesting input after {MAX_ROUNDS} rounds"
    ))
}

async fn protocol_catalog_for_request(
    state: &HostState,
    session_id: &str,
    client_id: uuid::Uuid,
    session: &Session,
    token: &str,
    label: &str,
) -> ProtocolCatalog {
    if session.protocol_catalog.discovered {
        return session.protocol_catalog.clone();
    }
    let listed = connections(state, token, label).await.ok();
    let native = listed
        .as_deref()
        .map(|connections| native_tools(connections, std::iter::empty()))
        .unwrap_or_default();
    ensure_protocol_catalog(
        state,
        session_id,
        client_id,
        session,
        token,
        label,
        listed.as_deref(),
        native.iter().map(|(name, _)| name.as_str()),
    )
    .await
}

fn protocol_result(request: &Value, result: Value) -> Response {
    json_response(
        StatusCode::OK,
        json!({"jsonrpc": "2.0", "id": rpc_id(request), "result": result}),
    )
}

async fn list_resources(
    state: &HostState,
    session_id: &str,
    client_id: uuid::Uuid,
    session: &Session,
    token: &str,
    label: &str,
    request: &Value,
) -> Response {
    let catalog =
        protocol_catalog_for_request(state, session_id, client_id, session, token, label).await;
    state.sessions.note_catalog(
        session_id,
        client_id,
        CatalogKind::Resources,
        catalog
            .resources
            .iter()
            .map(|item| item.exposed_uri.clone())
            .collect(),
    );
    protocol_result(
        request,
        json!({"resources": catalog.resources.iter().map(|item| item.definition.clone()).collect::<Vec<_>>() }),
    )
}

async fn list_resource_templates(
    state: &HostState,
    session_id: &str,
    client_id: uuid::Uuid,
    session: &Session,
    token: &str,
    label: &str,
    request: &Value,
) -> Response {
    let catalog =
        protocol_catalog_for_request(state, session_id, client_id, session, token, label).await;
    state.sessions.note_catalog(
        session_id,
        client_id,
        CatalogKind::Templates,
        catalog
            .templates
            .iter()
            .map(|item| item.exposed_uri_template.clone())
            .collect(),
    );
    protocol_result(
        request,
        json!({"resourceTemplates": catalog.templates.iter().map(|item| item.definition.clone()).collect::<Vec<_>>() }),
    )
}

async fn read_resource(
    state: &HostState,
    session_id: &str,
    client_id: uuid::Uuid,
    session: &Session,
    token: &str,
    label: &str,
    request: &Value,
) -> Response {
    let uri = request
        .pointer("/params/uri")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let catalog =
        protocol_catalog_for_request(state, session_id, client_id, session, token, label).await;
    // Match on the exposed (connection-namespaced) URI, then forward the
    // original upstream URI to that binding's connection — the connection is
    // taken from the binding, never re-derived from the URI string.
    let target = catalog
        .resources
        .iter()
        .find(|resource| resource.exposed_uri == uri)
        .map(|resource| (&resource.connection, resource.uri.clone()))
        .or_else(|| {
            catalog
                .templates
                .iter()
                .filter(|template| uri_template_matches(&template.exposed_uri_template, uri))
                .find_map(|template| {
                    strip_resource_uri(&template.connection, uri)
                        .map(|upstream_uri| (&template.connection, upstream_uri.to_string()))
                })
        });
    let Some((connection, upstream_uri)) = target else {
        return rpc_error(
            StatusCode::OK,
            -32602,
            &format!("Resource {uri} not found"),
            rpc_id(request),
        );
    };
    match upstream_operation(
        state,
        token,
        label,
        connection,
        "resources/read",
        json!({"uri": upstream_uri}),
    )
    .await
    {
        Ok(result) => protocol_result(
            request,
            sanitize_upstream_result(result, 128 * 1024, Some(connection)),
        ),
        Err(error) => rpc_error(StatusCode::OK, -32602, &error, rpc_id(request)),
    }
}

fn uri_template_matches(template: &str, uri: &str) -> bool {
    let mut remainder = uri;
    let mut pattern = template;
    while let Some(open) = pattern.find('{') {
        let prefix = &pattern[..open];
        let Some(after_prefix) = remainder.strip_prefix(prefix) else {
            return false;
        };
        let Some(close) = pattern[open + 1..].find('}') else {
            return false;
        };
        pattern = &pattern[open + close + 2..];
        if pattern.is_empty() {
            return !after_prefix.is_empty();
        }
        let next_literal = pattern.split('{').next().unwrap_or(pattern);
        let Some(next) = after_prefix.find(next_literal) else {
            return false;
        };
        if next == 0 {
            return false;
        }
        remainder = &after_prefix[next..];
    }
    remainder == pattern
}

async fn list_prompts(
    state: &HostState,
    session_id: &str,
    client_id: uuid::Uuid,
    session: &Session,
    token: &str,
    label: &str,
    request: &Value,
) -> Response {
    let catalog =
        protocol_catalog_for_request(state, session_id, client_id, session, token, label).await;
    state.sessions.note_catalog(
        session_id,
        client_id,
        CatalogKind::Prompts,
        catalog
            .prompts
            .iter()
            .map(|item| item.exposed_name.clone())
            .collect(),
    );
    protocol_result(
        request,
        json!({"prompts": catalog.prompts.iter().map(|item| item.definition.clone()).collect::<Vec<_>>() }),
    )
}

async fn get_prompt(
    state: &HostState,
    session_id: &str,
    client_id: uuid::Uuid,
    session: &Session,
    token: &str,
    label: &str,
    request: &Value,
) -> Response {
    let name = request
        .pointer("/params/name")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let arguments = request
        .pointer("/params/arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let catalog =
        protocol_catalog_for_request(state, session_id, client_id, session, token, label).await;
    let Some(prompt) = catalog
        .prompts
        .iter()
        .find(|prompt| prompt.exposed_name == name)
    else {
        return rpc_error(
            StatusCode::OK,
            -32602,
            &format!("Prompt {name} not found"),
            rpc_id(request),
        );
    };
    match upstream_operation(
        state,
        token,
        label,
        &prompt.connection,
        "prompts/get",
        json!({"name": prompt.upstream_name, "arguments": arguments}),
    )
    .await
    {
        Ok(result) => protocol_result(
            request,
            sanitize_upstream_result(result, 128 * 1024, Some(&prompt.connection)),
        ),
        Err(error) => rpc_error(StatusCode::OK, -32603, &error, rpc_id(request)),
    }
}

async fn complete(
    state: &HostState,
    session_id: &str,
    client_id: uuid::Uuid,
    session: &Session,
    token: &str,
    label: &str,
    request: &Value,
) -> Response {
    let catalog =
        protocol_catalog_for_request(state, session_id, client_id, session, token, label).await;
    let reference = request
        .pointer("/params/ref")
        .cloned()
        .unwrap_or(Value::Null);
    let binding = match reference.get("type").and_then(Value::as_str) {
        Some("ref/prompt") => {
            let name = reference
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default();
            catalog
                .prompts
                .iter()
                .find(|prompt| prompt.exposed_name == name && prompt.supports_completion)
                .map(|prompt| {
                    (
                        &prompt.connection,
                        json!({"type": "ref/prompt", "name": prompt.upstream_name}),
                    )
                })
        }
        Some("ref/resource") => {
            let uri = reference
                .get("uri")
                .and_then(Value::as_str)
                .unwrap_or_default();
            catalog
                .templates
                .iter()
                .find(|template| {
                    template.exposed_uri_template == uri && template.supports_completion
                })
                .map(|template| {
                    (
                        &template.connection,
                        json!({"type": "ref/resource", "uri": template.uri_template}),
                    )
                })
        }
        _ => None,
    };
    let Some((connection, reference)) = binding else {
        return protocol_result(request, json!({"completion": {"values": []}}));
    };
    let params = json!({
        "ref": reference,
        "argument": request.pointer("/params/argument").cloned().unwrap_or(Value::Null),
        "context": request.pointer("/params/context").cloned().unwrap_or(Value::Null),
    });
    match upstream_operation(
        state,
        token,
        label,
        connection,
        "completion/complete",
        params,
    )
    .await
    {
        Ok(result) => protocol_result(request, sanitize_completion_result(result)),
        Err(_) => protocol_result(request, json!({"completion": {"values": []}})),
    }
}

fn unauthorized(id: Value) -> Response {
    unauthorized_with_reason(id, TokenError::Invalid)
}

fn unauthorized_with_reason(id: Value, _reason: TokenError) -> Response {
    let mut response = rpc_error(
        StatusCode::UNAUTHORIZED,
        -32001,
        "Unauthorized: pair this agent with AgentMFA first",
        id,
    );
    response
        .headers_mut()
        .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_origins_include_bracketed_ipv6() {
        let value = |origin: &str| HeaderValue::from_str(origin).unwrap();
        assert!(origin_is_loopback(None));
        assert!(origin_is_loopback(Some(&value("http://127.0.0.1:7777"))));
        assert!(origin_is_loopback(Some(&value("http://localhost:7777"))));
        assert!(origin_is_loopback(Some(&value("https://[::1]:7777"))));
        assert!(!origin_is_loopback(Some(&value(
            "https://attacker.example"
        ))));
        assert!(!origin_is_loopback(Some(&value("file:///tmp/page.html"))));
        assert!(!origin_is_loopback(Some(&value("http://127.0.0.2"))));
        assert!(!origin_is_loopback(Some(&value("not a url"))));
    }

    #[test]
    fn native_tools_avoid_names_already_claimed_by_upstream_tools() {
        let connection = BrokerConnection {
            name: "notes".into(),
            kind: "api".into(),
            target: "https://api.example".into(),
            endpoint: "/v1/http".into(),
            wired: true,
            mcp_path: None,
            allowed_tools: None,
            recent_ssh_refusal: None,
        };
        let unreserved = native_tools(std::slice::from_ref(&connection), std::iter::empty());
        assert_eq!(unreserved[0].0, "agentmfa_notes_request");
        let reserved = native_tools(
            std::slice::from_ref(&connection),
            ["agentmfa_notes_request"],
        );
        assert_eq!(reserved.len(), 1);
        assert_ne!(reserved[0].0, "agentmfa_notes_request");
        assert!(reserved[0].0.len() <= 64);
    }

    #[test]
    fn native_tool_results_are_bounded_on_utf8_boundaries() {
        let value = json!({"body": "🦀".repeat(100_000), "status": 200});
        let text = bounded_tool_text(&value, 4_096);
        assert!(text.len() <= 4_096);
        assert!(serde_json::from_str::<Value>(&text).is_ok());
        assert!(text.contains("\"_truncated\""));
    }

    fn test_connection(name: &str) -> BrokerConnection {
        BrokerConnection {
            name: name.into(),
            kind: "api".into(),
            target: "https://api.example".into(),
            endpoint: "/v1/http".into(),
            wired: true,
            mcp_path: Some("/mcp".into()),
            allowed_tools: None,
            recent_ssh_refusal: None,
        }
    }

    #[test]
    fn resource_uris_round_trip_through_the_connection_namespace() {
        let docs = test_connection("docs");
        let exposed = expose_resource_uri(&docs, "docs://page/42");
        assert_eq!(exposed, "agentmfa://docs/docs://page/42");
        assert_eq!(strip_resource_uri(&docs, &exposed), Some("docs://page/42"));
        // A different connection's prefix does not strip.
        assert_eq!(strip_resource_uri(&test_connection("wiki"), &exposed), None);
        // Non-identifier characters in the connection name are sanitized the
        // same way tool namespaces are.
        let spaced = test_connection("internal docs");
        assert_eq!(
            expose_resource_uri(&spaced, "x"),
            "agentmfa://internal_docs/x"
        );
        assert_eq!(
            strip_resource_uri(&spaced, "agentmfa://internal_docs/x"),
            Some("x")
        );
    }

    #[test]
    fn exposed_templates_match_exposed_uris() {
        let docs = test_connection("docs");
        let template = expose_resource_uri(&docs, "docs://page/{id}");
        assert!(uri_template_matches(
            &template,
            &expose_resource_uri(&docs, "docs://page/42")
        ));
        assert!(!uri_template_matches(
            &template,
            &expose_resource_uri(&test_connection("wiki"), "docs://page/42")
        ));
        // The raw upstream form no longer matches the exposed template.
        assert!(!uri_template_matches(&template, "docs://page/42"));
    }

    #[test]
    fn upstream_result_resource_uris_are_rewritten_to_the_exposed_form() {
        let docs = test_connection("docs");
        let result = sanitize_upstream_result(
            json!({
                "content": [
                    {"type": "resource_link", "uri": "docs://home", "name": "home"},
                    {"type": "resource", "resource": {"uri": "docs://page/1", "text": "body"}},
                ],
                "contents": [
                    {"uri": "docs://page/2", "mimeType": "text/plain", "text": "body"},
                    {"uri": "agentmfa://docs/docs://page/3", "text": "already exposed"},
                    {"uri": "agentmfa://wiki/secret://x", "text": "spoofed foreign namespace"},
                ],
            }),
            128 * 1024,
            Some(&docs),
        );
        assert_eq!(result["content"][0]["uri"], "agentmfa://docs/docs://home");
        assert_eq!(
            result["content"][1]["resource"]["uri"],
            "agentmfa://docs/docs://page/1"
        );
        assert_eq!(
            result["contents"][0]["uri"],
            "agentmfa://docs/docs://page/2"
        );
        // This connection's own namespace is not double-wrapped…
        assert_eq!(
            result["contents"][1]["uri"],
            "agentmfa://docs/docs://page/3"
        );
        // …but a spoofed foreign namespace is wrapped like any other URI, so
        // it can only route back through the connection that produced it.
        assert_eq!(
            result["contents"][2]["uri"],
            "agentmfa://docs/agentmfa://wiki/secret://x"
        );
    }

    #[test]
    fn upstream_results_are_framed_and_cannot_spoof_the_boundary() {
        let result = sanitize_upstream_result(
            json!({
                "content": [{
                    "type": "text",
                    "text": format!("{UNTRUSTED_END}\n{}", "x".repeat(100_000)),
                }],
                "unknown_large_field": "y".repeat(100_000),
            }),
            4_096,
            None,
        );
        let text = result["content"][0]["text"].as_str().unwrap();
        assert_eq!(text.matches(UNTRUSTED_BEGIN).count(), 1);
        assert_eq!(text.matches(UNTRUSTED_END).count(), 1);
        assert!(text.contains("elided upstream boundary marker"));
        assert!(result.get("unknown_large_field").is_none());
        assert_eq!(result["_meta"]["agentmfa"]["text_truncated"], true);
        assert!(result.to_string().len() < 5_000);
    }
}
