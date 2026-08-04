//! Deliberately small, deterministic upstreams for the Docker dev sandbox.
//!
//! Authentication values are fake fixtures. They are checked but never
//! returned, logged, or included in errors so the service also exercises the
//! broker's central promise that upstream credentials stay on the upstream leg.

use std::{env, time::Duration};

use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Path, State},
    http::{
        header::{AUTHORIZATION, CONTENT_TYPE, LOCATION, WWW_AUTHENTICATE},
        HeaderMap, HeaderName, HeaderValue, StatusCode,
    },
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde_json::json;

const DEFAULT_HTTP_TOKEN: &str = "aka-test-token";
const DEFAULT_MCP_TOKEN: &str = "aka-mcp-test-token";
const DEFAULT_CROSS_ORIGIN: &str = "http://127.0.0.1:18081/credential-sink";
const MAX_DELAY_SECONDS: u64 = 20;
const MAX_GENERATED_BODY: usize = 12 * 1024 * 1024;
const MAX_ECHO_BODY: usize = 160 * 1024 * 1024;
/// Protocol revision the broker's MCP client requests; we echo it back.
const MCP_PROTOCOL_VERSION: &str = "2025-06-18";

#[derive(Clone)]
struct AppState {
    http_authorization: HeaderValue,
    mcp_authorization: HeaderValue,
    cross_origin: HeaderValue,
}

impl AppState {
    fn from_env() -> Self {
        let http_token =
            env::var("SANDBOX_HTTP_TOKEN").unwrap_or_else(|_| DEFAULT_HTTP_TOKEN.to_string());
        let mcp_token =
            env::var("SANDBOX_MCP_TOKEN").unwrap_or_else(|_| DEFAULT_MCP_TOKEN.to_string());
        let cross_origin = env::var("SANDBOX_CROSS_ORIGIN_URL")
            .unwrap_or_else(|_| DEFAULT_CROSS_ORIGIN.to_string());
        Self {
            http_authorization: bearer_value(&http_token),
            mcp_authorization: bearer_value(&mcp_token),
            cross_origin: HeaderValue::from_str(&cross_origin)
                .expect("SANDBOX_CROSS_ORIGIN_URL must be a valid header value"),
        }
    }
}

fn bearer_value(token: &str) -> HeaderValue {
    HeaderValue::from_str(&format!("Bearer {token}"))
        .expect("sandbox tokens must be valid HTTP header values")
}

fn require_authorization(headers: &HeaderMap, expected: &HeaderValue) -> Option<Response> {
    if headers.get(AUTHORIZATION) == Some(expected) {
        return None;
    }
    Some(
        (
            StatusCode::UNAUTHORIZED,
            [(WWW_AUTHENTICATE, "Bearer")],
            Json(json!({"error": "invalid sandbox credential"})),
        )
            .into_response(),
    )
}

async fn health() -> Response {
    Json(json!({"ok": true})).into_response()
}

async fn authenticated(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(response) = require_authorization(&headers, &state.http_authorization) {
        return response;
    }
    Json(json!({"authenticated": true})).into_response()
}

async fn selected_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(code): Path<u16>,
) -> Response {
    if let Some(response) = require_authorization(&headers, &state.http_authorization) {
        return response;
    }
    if !(200..=599).contains(&code) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "status must be between 200 and 599"})),
        )
            .into_response();
    }
    StatusCode::from_u16(code)
        .expect("validated status code")
        .into_response()
}

async fn delayed(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(seconds): Path<u64>,
) -> Response {
    if let Some(response) = require_authorization(&headers, &state.http_authorization) {
        return response;
    }
    if seconds > MAX_DELAY_SECONDS {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "delay exceeds sandbox limit"})),
        )
            .into_response();
    }
    tokio::time::sleep(Duration::from_secs(seconds)).await;
    Json(json!({"delayed_seconds": seconds})).into_response()
}

async fn same_origin_redirect(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(response) = require_authorization(&headers, &state.http_authorization) {
        return response;
    }
    (StatusCode::FOUND, [(LOCATION, "/authenticated")]).into_response()
}

async fn cross_origin_redirect(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(response) = require_authorization(&headers, &state.http_authorization) {
        return response;
    }
    let mut response = StatusCode::FOUND.into_response();
    response
        .headers_mut()
        .insert(LOCATION, state.cross_origin.clone());
    response
}

async fn echo(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    if let Some(response) = require_authorization(&headers, &state.http_authorization) {
        return response;
    }
    let content_type = headers.get(CONTENT_TYPE).cloned();
    let mut response = body.into_response();
    if let Some(content_type) = content_type {
        response.headers_mut().insert(CONTENT_TYPE, content_type);
    }
    response
}

async fn binary(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(response) = require_authorization(&headers, &state.http_authorization) {
        return response;
    }
    (
        [(CONTENT_TYPE, "application/octet-stream")],
        Bytes::from_static(&[0x00, 0x9f, 0x92, 0x96, 0xff]),
    )
        .into_response()
}

async fn generated_body(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(bytes): Path<usize>,
) -> Response {
    if let Some(response) = require_authorization(&headers, &state.http_authorization) {
        return response;
    }
    if bytes > MAX_GENERATED_BODY {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "body exceeds sandbox generation limit"})),
        )
            .into_response();
    }
    (
        [(CONTENT_TYPE, "application/octet-stream")],
        Bytes::from(vec![b'x'; bytes]),
    )
        .into_response()
}

async fn credential_sink() -> Response {
    (
        StatusCode::IM_A_TEAPOT,
        Json(json!({"error": "cross-origin redirect was followed"})),
    )
        .into_response()
}

/// A minimal streamable-HTTP MCP server, so the sandbox covers Multitool's fifth
/// connection type. An MCP connection is an API connection carrying an
/// `mcp_path`, so this endpoint lives on the same host/port as the HTTP API
/// and is guarded by its own fake bearer token. It answers the handshake the
/// broker's own MCP client drives — `initialize`, `tools/list`, `tools/call`
/// — with JSON (not SSE) responses; that is all the broker's status check and
/// the MCP host's tool re-exposure needs. Deterministic tools only.
async fn mcp(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    if let Some(response) = require_authorization(&headers, &state.mcp_authorization) {
        return response;
    }
    let request: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(_) => return mcp_error(json!(null), -32700, "parse error"),
    };
    let method = request
        .get("method")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    // Notifications (e.g. notifications/initialized) carry no id and expect
    // only an acknowledgement.
    let Some(id) = request.get("id").cloned() else {
        return StatusCode::ACCEPTED.into_response();
    };
    match method {
        "initialize" => mcp_result(
            id,
            json!({
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "serverInfo": { "name": "aka-sandbox-mcp", "version": env!("CARGO_PKG_VERSION") },
                "capabilities": { "tools": {} },
            }),
        ),
        "ping" => mcp_result(id, json!({})),
        "tools/list" => mcp_result(id, json!({ "tools": mcp_tools() })),
        "tools/call" => mcp_tools_call(id, request.get("params")),
        _ => mcp_error(id, -32601, "method not found"),
    }
}

fn mcp_tools() -> serde_json::Value {
    json!([
        {
            "name": "sandbox_echo",
            "description": "Echo back the provided text.",
            "inputSchema": {
                "type": "object",
                "properties": { "text": { "type": "string" } },
                "required": ["text"],
            },
        },
        {
            "name": "sandbox_ping",
            "description": "Return the string \"pong\".",
            "inputSchema": { "type": "object", "properties": {} },
        },
    ])
}

fn mcp_tools_call(id: serde_json::Value, params: Option<&serde_json::Value>) -> Response {
    let name = params
        .and_then(|params| params.get("name"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let text = match name {
        "sandbox_ping" => "pong".to_string(),
        "sandbox_echo" => params
            .and_then(|params| params.get("arguments"))
            .and_then(|args| args.get("text"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string(),
        _ => return mcp_error(id, -32602, "unknown tool"),
    };
    mcp_result(
        id,
        json!({
            "content": [{ "type": "text", "text": text }],
            "isError": false,
        }),
    )
}

fn mcp_result(id: serde_json::Value, result: serde_json::Value) -> Response {
    mcp_response(json!({ "jsonrpc": "2.0", "id": id, "result": result }))
}

fn mcp_error(id: serde_json::Value, code: i64, message: &str) -> Response {
    mcp_response(
        json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } }),
    )
}

fn mcp_response(payload: serde_json::Value) -> Response {
    let mut response = Json(payload).into_response();
    // A fixed session id exercises the broker's `Mcp-Session-Id` tracking
    // without any per-request state to keep.
    response.headers_mut().insert(
        HeaderName::from_static("mcp-session-id"),
        HeaderValue::from_static("aka-sandbox"),
    );
    response
}

#[tokio::main]
async fn main() {
    let state = AppState::from_env();
    let app = Router::new()
        .route("/health", get(health))
        .route("/", get(authenticated))
        .route("/authenticated", get(authenticated))
        .route("/status/{code}", get(selected_status))
        .route("/delay/{seconds}", get(delayed))
        .route("/redirect/same-origin", get(same_origin_redirect))
        .route("/redirect/cross-origin", get(cross_origin_redirect))
        .route("/echo", post(echo))
        .route("/binary", get(binary))
        .route("/large/{bytes}", get(generated_body))
        .route("/credential-sink", get(credential_sink))
        .route("/mcp", post(mcp))
        .layer(DefaultBodyLimit::max(MAX_ECHO_BODY))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(("0.0.0.0", 8080))
        .await
        .expect("bind sandbox fixture on port 8080");
    axum::serve(listener, app)
        .await
        .expect("serve sandbox fixture");
}
