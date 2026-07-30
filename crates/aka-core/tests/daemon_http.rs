//! End-to-end control-plane tests: a real daemon on a real Unix socket, a
//! real upstream HTTP server, and a scripted "user" deciding approvals.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use aka_core::broker::Broker;
use aka_core::config::BrokerConfig;
use aka_core::daemon;
use aka_core::events::BrokerEvents;
use aka_core::paths::Paths;
use aka_core::store::ConnectionSpec;
use aka_core::types::{
    ConfirmMode, ConfirmationMethod, ConnectionConfig, ConnectionKind, PgSslMode, SecretMeta,
};
use aka_core::vault::MemoryVault;
use aka_core::wire::REQUEST_ID_MAX_BYTES;
use axum::routing::{any, get, post};
use axum::Router;
use http_body_util::BodyExt as _;
use serde_json::{json, Value};
use zeroize::Zeroizing;

/* ------------------------------ harness ---------------------------------- */

struct TestEvents;

impl BrokerEvents for TestEvents {
    fn confirm_secret_read(&self, _secret: &SecretMeta) -> bool {
        true
    }
    fn confirm_action(&self, _description: &str) -> Option<ConfirmationMethod> {
        Some(ConfirmationMethod::Waived)
    }
}

/// A shell whose user declines every native confirmation. Used to exercise
/// the key-rotation confirmation's cancel path.
struct DecliningEvents;

impl BrokerEvents for DecliningEvents {
    fn confirm_secret_read(&self, _secret: &SecretMeta) -> bool {
        true
    }
    fn confirm_action(&self, _description: &str) -> Option<ConfirmationMethod> {
        None
    }
}

struct Harness {
    broker: Arc<Broker>,
    _daemon: daemon::DaemonHandle,
    socket: std::path::PathBuf,
    _dir: tempfile::TempDir,
}

async fn harness(config: BrokerConfig) -> Harness {
    harness_with_events(config, Arc::new(TestEvents)).await
}

async fn harness_with_events(mut config: BrokerConfig, events: Arc<dyn BrokerEvents>) -> Harness {
    config.version = "test".into();
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::under(dir.path());
    let broker = Broker::new(paths, Arc::new(MemoryVault::new()), config, events)
        .await
        .unwrap();
    let handle = daemon::serve(broker.clone()).await.unwrap();
    let socket = handle.socket_path.clone();
    Harness {
        broker,
        _daemon: handle,
        socket,
        _dir: dir,
    }
}

impl Harness {
    /// The compat pair: registration is immediate and every name receives
    /// the same shared key.
    async fn pair(&mut self, name: &str) -> String {
        let (status, body) = uds_request(
            &self.socket,
            "POST",
            "/v1/pair",
            &[],
            Some(json!({ "agent_name": name })),
        )
        .await;
        assert_eq!(status, 200, "pair failed: {body}");
        body["token"].as_str().unwrap().to_string()
    }
}

/// Minimal HTTP/1.1 client over a Unix socket.
async fn uds_request(
    socket: &std::path::Path,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<Value>,
) -> (u16, Value) {
    let stream = tokio::net::UnixStream::connect(socket).await.unwrap();
    let io = hyper_util::rt::TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
    tokio::spawn(conn);

    let mut builder = hyper::Request::builder()
        .method(method)
        .uri(path)
        .header("host", "localhost");
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    let request = match body {
        Some(value) => builder
            .header("content-type", "application/json")
            .body(value.to_string())
            .unwrap(),
        None => builder.body(String::new()).unwrap(),
    };
    let response = sender.send_request(request).await.unwrap();
    let status = response.status().as_u16();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes)
            .unwrap_or(Value::String(String::from_utf8_lossy(&bytes).into_owned()))
    };
    (status, value)
}

/// Like `uds_request`, but returns the raw body — the streamed plane answers
/// `text/event-stream`, which is not one JSON value.
async fn uds_request_raw(
    socket: &std::path::Path,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<Value>,
) -> (u16, String, String) {
    let stream = tokio::net::UnixStream::connect(socket).await.unwrap();
    let io = hyper_util::rt::TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
    tokio::spawn(conn);
    let mut builder = hyper::Request::builder()
        .method(method)
        .uri(path)
        .header("host", "localhost");
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    let request = match body {
        Some(value) => builder
            .header("content-type", "application/json")
            .body(value.to_string())
            .unwrap(),
        None => builder.body(String::new()).unwrap(),
    };
    let response = sender.send_request(request).await.unwrap();
    let status = response.status().as_u16();
    let content_type = response
        .headers()
        .get("content-type")
        .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
        .unwrap_or_default();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        content_type,
        String::from_utf8_lossy(&bytes).into_owned(),
    )
}

/// Split an SSE body into `(event, data)` pairs in arrival order.
fn sse_frames(body: &str) -> Vec<(String, Value)> {
    body.split("\n\n")
        .filter(|block| !block.trim().is_empty())
        .map(|block| {
            let mut event = String::new();
            let mut data = String::new();
            for line in block.lines() {
                if let Some(rest) = line.strip_prefix("event: ") {
                    event = rest.to_string();
                } else if let Some(rest) = line.strip_prefix("data: ") {
                    data.push_str(rest);
                }
            }
            (event, serde_json::from_str(&data).unwrap_or(Value::Null))
        })
        .collect()
}

/// Concatenate the body carried by a streamed answer's `chunk` frames.
fn sse_body_bytes(frames: &[(String, Value)]) -> Vec<u8> {
    use base64::Engine as _;
    frames
        .iter()
        .filter(|(event, _)| event == "chunk")
        .flat_map(|(_, data)| {
            base64::engine::general_purpose::STANDARD
                .decode(data["b64"].as_str().unwrap_or_default())
                .unwrap_or_default()
        })
        .collect()
}

/// Local upstream the api connections point at. Counts executions.
struct Upstream {
    port: u16,
    hits: Arc<AtomicUsize>,
}

async fn upstream() -> Upstream {
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_clone = hits.clone();
    let app = Router::new()
        .route(
            "/user/repos",
            get(|| async { axum::Json(json!([{"name": "cred"}, {"name": "aka"}])) }),
        )
        .route(
            "/echo",
            any(|req: axum::extract::Request| async move {
                let (parts, body) = req.into_parts();
                let bytes = axum::body::to_bytes(body, 1024 * 1024).await.unwrap();
                let headers: HashMap<String, String> = parts
                    .headers
                    .iter()
                    .map(|(k, v)| {
                        (
                            k.as_str().to_string(),
                            String::from_utf8_lossy(v.as_bytes()).into_owned(),
                        )
                    })
                    .collect();
                let repeated: Vec<String> = parts
                    .headers
                    .get_all("x-repeat")
                    .iter()
                    .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
                    .collect();
                axum::Json(json!({
                    "method": parts.method.as_str(),
                    "uri": parts.uri.to_string(),
                    "headers": headers,
                    "x_repeat": repeated,
                    "body": String::from_utf8_lossy(&bytes),
                }))
            }),
        )
        .route(
            "/dispatch",
            post(move || {
                let hits = hits_clone.clone();
                async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    (axum::http::StatusCode::NO_CONTENT, "")
                }
            }),
        )
        .route(
            "/needs-input",
            post(|axum::Json(body): axum::Json<Value>| async move {
                axum::Json(json!({
                    "jsonrpc": "2.0",
                    "id": body["id"],
                    "result": {
                        "resultType": "input_required",
                        "inputRequests": {
                            "account": {
                                "method": "elicitation/create",
                                "params": {
                                    "message": "Which account?",
                                    "requestedSchema": {
                                        "type": "object",
                                        "properties": {
                                            "name": {"type": "string"}
                                        }
                                    }
                                }
                            }
                        },
                        "requestState": "opaque"
                    }
                }))
            }),
        )
        .route(
            "/large-mcp",
            post(|axum::Json(body): axum::Json<Value>| async move {
                axum::Json(json!({
                    "jsonrpc": "2.0",
                    "id": body["id"],
                    "result": {
                        "content": [{
                            "type": "text",
                            "text": format!("useful-prefix-{}", "x".repeat(16 * 1024)),
                        }]
                    }
                }))
            }),
        )
        .route(
            "/redirect-same",
            get(|| async {
                (
                    axum::http::StatusCode::FOUND,
                    [(axum::http::header::LOCATION, "/echo")],
                    "",
                )
            }),
        )
        .route(
            "/redirect-cross",
            get(|| async {
                (
                    axum::http::StatusCode::FOUND,
                    [(axum::http::header::LOCATION, "http://evil.invalid/steal")],
                    "",
                )
            }),
        )
        .route(
            "/binary",
            get(|| async {
                (
                    [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
                    vec![0u8, 159, 146, 150, 255],
                )
            }),
        )
        .route(
            "/cookies",
            get(|| async {
                let mut response = axum::response::Response::new(axum::body::Body::empty());
                response.headers_mut().append(
                    axum::http::header::SET_COOKIE,
                    axum::http::HeaderValue::from_static(
                        "session=one; Path=/; HttpOnly; SameSite=Lax",
                    ),
                );
                response.headers_mut().append(
                    axum::http::header::SET_COOKIE,
                    axum::http::HeaderValue::from_static(
                        "csrf=two; Path=/; Secure; SameSite=Strict",
                    ),
                );
                response
            }),
        )
        .route(
            "/unauthorized",
            get(|| async { (axum::http::StatusCode::UNAUTHORIZED, "nope") }),
        )
        // Comfortably past the 10 MB buffered cap, so the two relays disagree
        // about it and the test can say which is which.
        .route(
            "/large",
            get(|| async { "z".repeat(12 * 1024 * 1024) }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    Upstream { port, hits }
}

fn api_connection(harness: &Harness, name: &str, port: u16) {
    harness
        .broker
        .store
        .add_secret(
            "GITHUB_API_KEY",
            Zeroizing::new("ghp_test_secret_value".into()),
        )
        .unwrap();
    harness
        .broker
        .store
        .add_connection(ConnectionSpec {
            name: name.into(),
            config: ConnectionConfig::Api {
                host: "127.0.0.1".into(),
                scheme: "http".into(),
                port: Some(port),
                trusted_ca_bundle_path: None,
                template: "Authorization: Bearer {{GITHUB_API_KEY}}".into(),

                mcp_path: None,
                test_path: None,
                oauth: None,
            },
            secrets: vec![],
        })
        .unwrap();
}

/* -------------------------------- tests ---------------------------------- */

#[tokio::test]
async fn discovery_is_unauthenticated_and_complete() {
    let h = harness(BrokerConfig::default()).await;
    let (status, manifest) = uds_request(
        &h.socket,
        "GET",
        "/.well-known/agent-broker.json",
        &[],
        None,
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(manifest["transport"], "http-over-unix-socket");
    assert_eq!(manifest["endpoints"]["whoami"], "/v1/whoami");
    // The manifest names the socket actually serving it, not the
    // production default (this harness runs under a temp root).
    assert_eq!(manifest["socket"], h.socket.display().to_string());
    let (status, instructions) = uds_request(&h.socket, "GET", "/instructions", &[], None).await;
    assert_eq!(status, 200);
    assert!(instructions.as_str().unwrap().contains("PGPASSWORD"));
    assert!(instructions
        .as_str()
        .unwrap()
        .contains(&h.socket.display().to_string()));
}

#[tokio::test]
async fn overlong_socket_path_is_diagnosed() {
    // Unix sockets cap the path at sun_path (~104 bytes); a deep --root
    // (per-session temp dirs) must produce a diagnosis naming the path and
    // the fix, not a bare bind error.
    let dir = tempfile::tempdir().unwrap();
    let deep = dir.path().join("x".repeat(120));
    let paths = Paths::under(&deep);
    let broker = Broker::new(
        paths,
        Arc::new(MemoryVault::new()),
        BrokerConfig::default(),
        Arc::new(TestEvents),
    )
    .await
    .unwrap();
    let err = match daemon::serve(broker).await {
        Ok(_) => panic!("expected the overlong socket path to be refused"),
        Err(e) => e.to_string(),
    };
    assert!(err.contains("bytes"), "unhelpful diagnosis: {err}");
    assert!(err.contains("--root"), "no fix named: {err}");
}

#[tokio::test]
async fn socket_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let h = harness(BrokerConfig::default()).await;
    let mode = std::fs::metadata(&h.socket).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
}

#[tokio::test]
async fn pairing_flow_and_token_auth() {
    let mut h = harness(BrokerConfig::default()).await;
    // Unauthenticated capability call is rejected.
    let (status, body) = uds_request(&h.socket, "GET", "/v1/connections", &[], None).await;
    assert_eq!(status, 401);
    assert_eq!(body["reason"], "missing_token");
    assert_eq!(body["cause"], "authorization_header_absent");
    assert!(body["detail"]
        .as_str()
        .unwrap()
        .contains("reached the broker"));

    // Authentication errors describe what reached the broker without
    // blaming the calling agent for omission or rewriting along the way.
    let (status, body) = uds_request(
        &h.socket,
        "GET",
        "/v1/connections",
        &[("authorization", "Basic abc")],
        None,
    )
    .await;
    assert_eq!(status, 401);
    assert_eq!(body["reason"], "missing_token");
    assert_eq!(body["cause"], "authorization_scheme_invalid");

    let (status, body) = uds_request(
        &h.socket,
        "GET",
        "/v1/connections",
        &[("authorization", "Bearer ")],
        None,
    )
    .await;
    assert_eq!(status, 401);
    assert_eq!(body["reason"], "missing_token");
    assert_eq!(body["cause"], "bearer_token_empty");

    let token = h.pair("claude-code").await;
    assert!(token.starts_with("aka_"));

    // Every name receives the same shared key: pairing is a fetch, not an
    // enrollment.
    let again = h.pair("codex").await;
    assert_eq!(again, token);
    assert_eq!(h.broker.identity.token(), token);

    // Token works; garbage doesn't.
    let auth = format!("Bearer {token}");
    let (status, list) = uds_request(
        &h.socket,
        "GET",
        "/v1/connections",
        &[("authorization", &auth)],
        None,
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(list, json!([]));
    let lower_auth = format!("bearer {token}");
    let (status, _) = uds_request(
        &h.socket,
        "GET",
        "/v1/connections",
        &[("authorization", &lower_auth)],
        None,
    )
    .await;
    assert_eq!(status, 200);
    let (status, body) = uds_request(
        &h.socket,
        "GET",
        "/v1/connections",
        &[("authorization", "Bearer aka_bogus")],
        None,
    )
    .await;
    assert_eq!(status, 401);
    assert_eq!(body["reason"], "invalid_token");
    assert!(body["detail"]
        .as_str()
        .unwrap()
        .contains("reached the broker"));

    // Rotation invalidates the old key immediately, with the recovery hint.
    h.broker.ui_rotate_key().unwrap();
    let (status, body) = uds_request(
        &h.socket,
        "GET",
        "/v1/connections",
        &[("authorization", &auth)],
        None,
    )
    .await;
    assert_eq!(status, 401);
    assert_eq!(body["reason"], "token_superseded");
    assert_eq!(
        body["store_at"].as_str().unwrap(),
        h.broker.paths.token_display()
    );
    // The rewritten token file authenticates.
    let fresh = h.broker.identity.token();
    let fresh_auth = format!("Bearer {fresh}");
    let (status, _) = uds_request(
        &h.socket,
        "GET",
        "/v1/connections",
        &[("authorization", &fresh_auth)],
        None,
    )
    .await;
    assert_eq!(status, 200);
}

#[tokio::test]
async fn rotation_requires_the_native_confirmation() {
    let h = harness_with_events(BrokerConfig::default(), Arc::new(DecliningEvents)).await;
    let before = h.broker.identity.token();
    assert!(h.broker.ui_rotate_key().is_err(), "declined ⇒ no rotation");
    assert_eq!(h.broker.identity.token(), before);
}

#[tokio::test]
async fn pairing_attempts_are_rate_limited() {
    let config = BrokerConfig {
        pairing_max_attempts: 2,
        ..BrokerConfig::default()
    };
    let h = harness(config).await;
    for name in ["agent-one", "agent-two"] {
        let (status, _) = uds_request(
            &h.socket,
            "POST",
            "/v1/pair",
            &[],
            Some(json!({"agent_name": name})),
        )
        .await;
        assert_eq!(status, 200);
    }
    let (status, body) = uds_request(
        &h.socket,
        "POST",
        "/v1/pair",
        &[],
        Some(json!({"agent_name": "agent-three"})),
    )
    .await;
    assert_eq!(status, 429);
    assert_eq!(body["reason"], "pairing_rate_limited");
    let wait = body["retry_after_seconds"].as_u64().unwrap();
    assert!((1..=5).contains(&wait), "unexpected wait {wait}");
}

#[tokio::test]
async fn body_parse_errors_follow_the_error_contract() {
    // Axum's default rejections (missing Content-Type, malformed JSON, a
    // missing field) are plain text; agents are told every error is a
    // `{"reason", "detail"}` envelope, so these must be too.
    let h = harness(BrokerConfig::default()).await;
    // POST with no Content-Type and no body.
    let (status, body) = uds_request(&h.socket, "POST", "/v1/pair", &[], None).await;
    assert_eq!(status, 400);
    assert_eq!(body["reason"], "invalid_json", "got: {body}");
    assert!(!body["detail"].as_str().unwrap().is_empty());
    // Well-formed JSON of the wrong shape (missing field).
    let (status, body) = uds_request(
        &h.socket,
        "POST",
        "/v1/pair",
        &[],
        Some(json!({"name": "claude-code"})),
    )
    .await;
    assert_eq!(status, 400);
    assert_eq!(body["reason"], "invalid_json", "got: {body}");
    assert!(body["detail"].as_str().unwrap().contains("agent_name"));
}

#[tokio::test]
async fn request_ids_are_bounded_before_connection_lookup() {
    let mut h = harness(BrokerConfig::default()).await;
    let token = h.pair("claude-code").await;
    let auth = format!("Bearer {token}");
    let oversized = "x".repeat(REQUEST_ID_MAX_BYTES + 1);
    let cases = [
        (
            "/v1/http",
            json!({
                "connection": "missing",
                "method": "POST",
                "path": "/dispatch",
                "request_id": oversized.clone(),
            }),
        ),
        (
            "/v1/pg/open",
            json!({"connection": "missing", "request_id": oversized.clone()}),
        ),
        (
            "/v1/ssh/open",
            json!({"connection": "missing", "request_id": oversized}),
        ),
    ];

    for (endpoint, body) in cases {
        let (status, body) = uds_request(
            &h.socket,
            "POST",
            endpoint,
            &[("authorization", &auth)],
            Some(body),
        )
        .await;
        assert_eq!(status, 400, "wrong status from {endpoint}: {body}");
        assert_eq!(body["reason"], "invalid_body");
        assert!(body["detail"].as_str().unwrap().contains("maximum is 256"));
    }

    let (status, body) = uds_request(
        &h.socket,
        "POST",
        "/v1/http",
        &[("authorization", &auth)],
        Some(json!({
            "connection": "missing",
            "method": "POST",
            "path": "/dispatch",
            "request_id": "x".repeat(REQUEST_ID_MAX_BYTES),
        })),
    )
    .await;
    assert_eq!(
        status, 404,
        "the maximum-length ID should be accepted: {body}"
    );
    assert_eq!(body["reason"], "unknown_connection");
}

#[tokio::test]
async fn wrong_connection_type_names_the_right_endpoint() {
    let mut h = harness(BrokerConfig::default()).await;
    h.broker
        .store
        .add_secret("DATABASE_PASSWORD", Zeroizing::new("pg-pw".into()))
        .unwrap();
    let pw = h.broker.store.secret_by_name("DATABASE_PASSWORD").unwrap();
    h.broker
        .store
        .add_connection(ConnectionSpec {
            name: "prod-db".into(),
            config: ConnectionConfig::Pg {
                host: "db.internal.aka.com".into(),
                port: 5432,
                dbname: "app_production".into(),
                user: "app".into(),
                sslmode: PgSslMode::Require,
                trusted_ca_bundle_path: None,
            },
            secrets: vec![pw.id],
        })
        .unwrap();
    let token = h.pair("claude-code").await;
    let auth = format!("Bearer {token}");
    // An HTTP call naming a pg connection is redirected to the right
    // endpoint, not just told it's wrong.
    let (status, body) = uds_request(
        &h.socket,
        "POST",
        "/v1/http",
        &[("authorization", &auth)],
        Some(json!({"connection": "prod-db", "method": "GET", "path": "/x"})),
    )
    .await;
    assert_eq!(status, 400);
    assert_eq!(body["reason"], "wrong_connection_type");
    assert!(
        body["detail"]
            .as_str()
            .unwrap()
            .contains("use POST /v1/pg/open"),
        "detail should name the right endpoint: {body}"
    );
}

#[tokio::test]
async fn connections_listing_shows_targets_only() {
    let mut h = harness(BrokerConfig::default()).await;
    let up = upstream().await;
    api_connection(&h, "github", up.port);
    h.broker
        .store
        .add_secret("DATABASE_PASSWORD", Zeroizing::new("pg-pw".into()))
        .unwrap();
    let pw = h.broker.store.secret_by_name("DATABASE_PASSWORD").unwrap();
    h.broker
        .store
        .add_connection(ConnectionSpec {
            name: "prod-db".into(),
            config: ConnectionConfig::Pg {
                host: "db.internal.aka.com".into(),
                port: 5432,
                dbname: "app_production".into(),
                user: "app".into(),
                sslmode: PgSslMode::Require,
                trusted_ca_bundle_path: None,
            },
            secrets: vec![pw.id],
        })
        .unwrap();

    let token = h.pair("claude-code").await;
    let auth = format!("Bearer {token}");
    let (status, list) = uds_request(
        &h.socket,
        "GET",
        "/v1/connections",
        &[("authorization", &auth)],
        None,
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(
        list,
        json!([
            {"name": "github", "type": "api", "target": format!("http://127.0.0.1:{}", up.port),
             "endpoint": "/v1/http", "wired": true, "confirm": false},
            {"name": "prod-db", "type": "pg", "target": "app@db.internal.aka.com:5432/app_production",
             "endpoint": "/v1/pg/open", "wired": true, "confirm": false},
        ])
    );
    // No secret names, ids, or templates anywhere in the response.
    let raw = list.to_string();
    assert!(!raw.contains("GITHUB_API_KEY"));
    assert!(!raw.contains("Bearer {{"));

    // Disabling a tool flips its `wired` flag for every agent at once —
    // access is per connection, not per caller.
    let pg = h.broker.store.connection_by_name("prod-db").unwrap();
    h.broker.ui_set_tool_access(&pg.id, false).unwrap();
    let (status, list) = uds_request(
        &h.socket,
        "GET",
        "/v1/connections",
        &[("authorization", &auth)],
        None,
    )
    .await;
    assert_eq!(status, 200);
    for entry in list.as_array().unwrap() {
        let expected = entry["name"] != "prod-db";
        assert_eq!(entry["wired"], json!(expected), "entry: {entry}");
    }
}

#[tokio::test]
async fn http_get_executes_and_injects_credential() {
    let mut h = harness(BrokerConfig::default()).await;
    let up = upstream().await;
    api_connection(&h, "github", up.port);
    let token = h.pair("claude-code").await;
    let auth = format!("Bearer {token}");

    let (status, envelope) = uds_request(
        &h.socket,
        "POST",
        "/v1/http",
        &[("authorization", &auth)],
        Some(json!({
            "connection": "github",
            "method": "GET",
            "path": "/echo?x=1",
            "headers": {"Accept": "application/vnd.github+json"},
        })),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(envelope["status"], 200);
    assert_eq!(envelope["body_encoding"], "utf8");
    let echoed: Value = serde_json::from_str(envelope["body"].as_str().unwrap()).unwrap();
    // Credential injected by the broker on the upstream leg, then redacted
    // from the agent-visible echoed response.
    assert_eq!(echoed["headers"]["authorization"], "[REDACTED]");
    // …and the agent's own headers merged in, with the query preserved.
    assert_eq!(echoed["headers"]["accept"], "application/vnd.github+json");
    assert_eq!(echoed["uri"], "/echo?x=1");
    // The raw secret never appears in the agent-visible envelope.
    assert!(envelope["headers"].get("authorization").is_none());
    assert!(!envelope.to_string().contains("ghp_test_secret_value"));
}

#[tokio::test]
async fn request_contract_accepts_repeated_headers_and_base64_bodies() {
    let mut h = harness(BrokerConfig::default()).await;
    let up = upstream().await;
    api_connection(&h, "github", up.port);
    let token = h.pair("claude-code").await;
    let auth = format!("Bearer {token}");

    let (status, envelope) = uds_request(
        &h.socket,
        "POST",
        "/v1/http",
        &[("authorization", &auth)],
        Some(json!({
            "connection": "github",
            "method": "POST",
            "path": "/echo",
            "headers": [["X-Repeat", "first"], ["X-Repeat", "second"]],
            "body_base64": "AQID",
        })),
    )
    .await;
    assert_eq!(status, 200, "{envelope}");
    let echoed: Value = serde_json::from_str(envelope["body"].as_str().unwrap()).unwrap();
    assert_eq!(echoed["x_repeat"], json!(["first", "second"]));
    assert_eq!(echoed["body"].as_str().unwrap().as_bytes(), &[1, 2, 3]);
}

#[tokio::test]
async fn validation_rejects_before_execution() {
    let mut h = harness(BrokerConfig::default()).await;
    let up = upstream().await;
    api_connection(&h, "github", up.port);
    let token = h.pair("claude-code").await;
    let auth = format!("Bearer {token}");

    for (payload, want_reason) in [
        (
            json!({"connection": "github", "method": "GET", "path": "//evil.com/x"}),
            "invalid_path",
        ),
        (
            json!({"connection": "github", "method": "GET", "path": "https://evil.com/x"}),
            "invalid_path",
        ),
        (
            json!({"connection": "github", "method": "GET", "path": "user/repos"}),
            "invalid_path",
        ),
        (
            json!({"connection": "github", "method": "GET", "path": "/x", "headers": {"Host": "evil.com"}}),
            "reserved_header",
        ),
        (
            json!({"connection": "github", "method": "GET", "path": "/x", "headers": {"Authorization": "mine"}}),
            "reserved_header",
        ),
        (
            json!({"connection": "github", "method": "GET", "path": "/x", "headers": {"Transfer-Encoding": "chunked"}}),
            "reserved_header",
        ),
        (
            json!({"connection": "github", "method": "TRACE", "path": "/x"}),
            "invalid_method",
        ),
        (
            json!({"connection": "nope", "method": "GET", "path": "/x"}),
            "unknown_connection",
        ),
    ] {
        let (status, body) = uds_request(
            &h.socket,
            "POST",
            "/v1/http",
            &[("authorization", &auth)],
            Some(payload),
        )
        .await;
        assert!(
            status == 400 || status == 404,
            "unexpected status {status} for {want_reason}"
        );
        assert_eq!(body["reason"], want_reason);
        // A stale connection name gets pointed at the valid ones.
        if want_reason == "unknown_connection" {
            assert!(
                body["detail"].as_str().unwrap().contains("github"),
                "404 detail should list configured names: {body}"
            );
        }
    }
    // None of those reached the upstream.
    assert_eq!(up.hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn same_host_redirect_followed_cross_host_returned_raw() {
    let mut h = harness(BrokerConfig::default()).await;
    let up = upstream().await;
    api_connection(&h, "github", up.port);
    let token = h.pair("claude-code").await;
    let auth = format!("Bearer {token}");

    // Same-host: followed, credential re-injected on the next hop.
    let (status, envelope) = uds_request(
        &h.socket,
        "POST",
        "/v1/http",
        &[("authorization", &auth)],
        Some(json!({"connection": "github", "method": "GET", "path": "/redirect-same"})),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(envelope["status"], 200, "redirect should be followed");
    let echoed: Value = serde_json::from_str(envelope["body"].as_str().unwrap()).unwrap();
    assert_eq!(
        echoed["headers"]["authorization"], "[REDACTED]",
        "credential is re-rendered onto the followed hop but redacted from the relay"
    );
    assert!(!envelope.to_string().contains("ghp_test_secret_value"));

    // Cross-host: returned to the agent as the raw 3xx.
    let (status, envelope) = uds_request(
        &h.socket,
        "POST",
        "/v1/http",
        &[("authorization", &auth)],
        Some(json!({"connection": "github", "method": "GET", "path": "/redirect-cross"})),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(envelope["status"], 302, "cross-host 3xx is not followed");
    assert_eq!(envelope["headers"]["location"], "http://evil.invalid/steal");
}

#[tokio::test]
async fn query_injected_secret_not_leaked_in_upstream_error() {
    // A query-param injection connection carries the credential in the request
    // URL. reqwest's error Display embeds that URL, so returning the raw error
    // to the agent would leak the secret the broker exists to withhold.
    let mut h = harness(BrokerConfig::default()).await;
    const TOKEN: &str = "supersecretquerytoken123";
    h.broker
        .store
        .add_secret("STREAM_TOKEN", Zeroizing::new(TOKEN.into()))
        .unwrap();
    // A port with (essentially certainly) nothing listening: bind, then drop.
    let dead_port = {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        l.local_addr().unwrap().port()
    };
    h.broker
        .store
        .add_connection(ConnectionSpec {
            name: "feed".into(),
            config: ConnectionConfig::Api {
                host: "127.0.0.1".into(),
                scheme: "http".into(),
                port: Some(dead_port),
                trusted_ca_bundle_path: None,
                template: "?token={{url(STREAM_TOKEN)}}".into(),

                mcp_path: None,
                test_path: None,
                oauth: None,
            },
            secrets: vec![],
        })
        .unwrap();
    let token = h.pair("claude-code").await;
    let auth = format!("Bearer {token}");

    let (status, body) = uds_request(
        &h.socket,
        "POST",
        "/v1/http",
        &[("authorization", &auth)],
        Some(json!({"connection": "feed", "method": "GET", "path": "/x"})),
    )
    .await;
    // Upstream is unreachable → a broker error, but the injected credential
    // must never appear anywhere in the agent-visible response.
    assert_eq!(status, 502, "expected an upstream_error, got {body}");
    assert_eq!(body["reason"], "upstream_error");
    let raw = body.to_string();
    assert!(
        !raw.contains(TOKEN),
        "query-injected credential leaked in the error response: {raw}"
    );
}

#[tokio::test]
async fn mutating_retries_coalesce_to_one_execution() {
    let mut h = harness(BrokerConfig::default()).await;
    let up = upstream().await;
    api_connection(&h, "github", up.port);
    let token = h.pair("claude-code").await;
    let auth = format!("Bearer {token}");

    let payload = json!({
        "connection": "github",
        "method": "POST",
        "path": "/dispatch",
        "request_id": "req_5d2f8a1c4b9e",
        "headers": {"Content-Type": "application/json"},
        "body": {"event_type": "deploy"},
    });

    let (status, b1) = uds_request(
        &h.socket,
        "POST",
        "/v1/http",
        &[("authorization", &auth)],
        Some(payload.clone()),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(b1["status"], 204);
    assert_eq!(up.hits.load(Ordering::SeqCst), 1);

    // A genuine retry — same label, same payload — is replayed.
    let (status, b2) = uds_request(
        &h.socket,
        "POST",
        "/v1/http",
        &[("authorization", &auth)],
        Some(payload.clone()),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(b2["status"], 204);
    assert_eq!(
        up.hits.load(Ordering::SeqCst),
        1,
        "exactly one upstream execution"
    );

    // Another self-reported label shares the authenticated identity's
    // namespace, so its reuse of the id cannot split the namespace into a
    // second execution — but neither is it handed the first label's cached
    // outcome. Fail closed: refused, still one execution.
    let (status, body) = uds_request(
        &h.socket,
        "POST",
        "/v1/http",
        &[("authorization", &auth), ("x-agentmfa-client", "codex")],
        Some(payload.clone()),
    )
    .await;
    assert_eq!(status, 409);
    assert_eq!(body["reason"], "request_id_mismatch");
    assert_eq!(
        up.hits.load(Ordering::SeqCst),
        1,
        "exactly one upstream execution"
    );

    // Same request_id, different payload: a client bug, 409.
    let mut altered = payload.clone();
    altered["body"] = json!({"event_type": "delete-everything"});
    let (status, body) = uds_request(
        &h.socket,
        "POST",
        "/v1/http",
        &[
            ("authorization", &auth),
            ("x-agentmfa-client", "another-label"),
        ],
        Some(altered),
    )
    .await;
    assert_eq!(status, 409);
    assert_eq!(body["reason"], "request_id_mismatch");
    assert_eq!(up.hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn idempotency_capacity_fails_before_upstream_execution() {
    let config = BrokerConfig {
        outcome_retention_max_entries: 0,
        ..BrokerConfig::default()
    };
    let mut h = harness(config).await;
    let up = upstream().await;
    api_connection(&h, "github", up.port);
    let token = h.pair("claude-code").await;
    let auth = format!("Bearer {token}");

    let (status, body) = uds_request(
        &h.socket,
        "POST",
        "/v1/http",
        &[("authorization", &auth)],
        Some(json!({
            "connection": "github",
            "method": "POST",
            "path": "/dispatch",
            "request_id": "req_no_capacity",
        })),
    )
    .await;

    assert_eq!(status, 503);
    assert_eq!(body["reason"], "idempotency_capacity");
    assert_eq!(up.hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn non_replayable_tombstone_prevents_duplicate_upstream_execution() {
    let config = BrokerConfig {
        outcome_retention_max_bytes: 0,
        ..BrokerConfig::default()
    };
    let mut h = harness(config).await;
    let up = upstream().await;
    api_connection(&h, "github", up.port);
    let token = h.pair("claude-code").await;
    let auth = format!("Bearer {token}");
    let payload = json!({
        "connection": "github",
        "method": "POST",
        "path": "/dispatch",
        "request_id": "req_tombstoned",
    });

    let (status, body) = uds_request(
        &h.socket,
        "POST",
        "/v1/http",
        &[("authorization", &auth)],
        Some(payload.clone()),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body["status"], 204);
    assert_eq!(up.hits.load(Ordering::SeqCst), 1);

    let (status, body) = uds_request(
        &h.socket,
        "POST",
        "/v1/http",
        &[("authorization", &auth)],
        Some(payload),
    )
    .await;
    assert_eq!(status, 409);
    assert_eq!(body["reason"], "outcome_not_replayable");
    assert_eq!(up.hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn mutating_request_id_is_independent_per_connection() {
    let mut h = harness(BrokerConfig::default()).await;
    let up = upstream().await;
    api_connection(&h, "github", up.port);
    h.broker
        .store
        .add_connection(ConnectionSpec {
            name: "github-alt".into(),
            config: ConnectionConfig::Api {
                host: "127.0.0.1".into(),
                scheme: "http".into(),
                port: Some(up.port),
                trusted_ca_bundle_path: None,
                template: "Authorization: Bearer {{GITHUB_API_KEY}}".into(),

                mcp_path: None,
                test_path: None,
                oauth: None,
            },
            secrets: vec![],
        })
        .unwrap();
    let token = h.pair("claude-code").await;
    let auth = format!("Bearer {token}");

    let (status, body) = uds_request(
        &h.socket,
        "POST",
        "/v1/http",
        &[("authorization", &auth)],
        Some(json!({
            "connection": "github",
            "method": "POST",
            "path": "/dispatch",
            "request_id": "req_same_payload_different_connection",
            "body": {"event_type": "deploy"},
        })),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body["status"], 204);
    assert_eq!(up.hits.load(Ordering::SeqCst), 1);

    // A caller can use the same request id independently for another
    // connection. The target connection is part of the namespace, so this
    // is a second execution rather than a mismatch or a replay.
    let (status, body) = uds_request(
        &h.socket,
        "POST",
        "/v1/http",
        &[("authorization", &auth)],
        Some(json!({
            "connection": "github-alt",
            "method": "POST",
            "path": "/dispatch",
            "request_id": "req_same_payload_different_connection",
            "body": {"event_type": "deploy"},
        })),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body["status"], 204);
    assert_eq!(up.hits.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn changing_the_client_label_cannot_bypass_the_identity_rate_limit() {
    let config = BrokerConfig {
        per_identity_per_min: 2,
        ..BrokerConfig::default()
    };
    let mut h = harness(config).await;
    let up = upstream().await;
    api_connection(&h, "github", up.port);
    let token = h.pair("claude-code").await;
    let auth = format!("Bearer {token}");

    // Two listings pass under different self-reported labels. The third,
    // under yet another label, still shares the verified identity's bucket.
    for label in ["claude-code", "codex"] {
        let (status, _) = uds_request(
            &h.socket,
            "GET",
            "/v1/connections",
            &[("authorization", &auth), ("x-agentmfa-client", label)],
            None,
        )
        .await;
        assert_eq!(status, 200);
    }
    let (status, body) = uds_request(
        &h.socket,
        "GET",
        "/v1/connections",
        &[
            ("authorization", &auth),
            ("x-agentmfa-client", "fresh-label"),
        ],
        None,
    )
    .await;
    assert_eq!(status, 429);
    assert_eq!(body["reason"], "rate_limited");
    // The refusal says how long to back off instead of leaving the agent
    // to guess.
    let wait = body["retry_after_seconds"].as_u64().unwrap();
    assert!((1..=60).contains(&wait), "unexpected wait {wait}");
}

#[tokio::test]
async fn binary_bodies_come_back_base64() {
    let mut h = harness(BrokerConfig::default()).await;
    let up = upstream().await;
    api_connection(&h, "github", up.port);
    let token = h.pair("claude-code").await;
    let auth = format!("Bearer {token}");
    let (status, envelope) = uds_request(
        &h.socket,
        "POST",
        "/v1/http",
        &[("authorization", &auth)],
        Some(json!({"connection": "github", "method": "GET", "path": "/binary"})),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(envelope["body_encoding"], "base64");
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(envelope["body"].as_str().unwrap())
        .unwrap();
    assert_eq!(bytes, vec![0u8, 159, 146, 150, 255]);
}

#[tokio::test]
async fn connections_are_enabled_by_default_and_disable_refuses() {
    let mut h = harness(BrokerConfig::default()).await;
    let up = upstream().await;
    api_connection(&h, "github", up.port);
    let conn = h.broker.store.connection_by_name("github").unwrap();
    let token = h.pair("claude-code").await;
    let auth = format!("Bearer {token}");

    // A fresh connection works with no grant step: adding the tool in the
    // app was the deliberate act.
    let call = json!({"connection": "github", "method": "GET", "path": "/echo"});
    let (status, _) = uds_request(
        &h.socket,
        "POST",
        "/v1/http",
        &[("authorization", &auth)],
        Some(call.clone()),
    )
    .await;
    assert_eq!(status, 200);

    // Disabling the tool refuses every agent…
    assert!(h.broker.ui_set_tool_access(&conn.id, false).unwrap());
    let (status, body) = uds_request(
        &h.socket,
        "POST",
        "/v1/http",
        &[("authorization", &auth)],
        Some(call.clone()),
    )
    .await;
    assert_eq!(status, 403);
    assert_eq!(body["reason"], "denied_by_policy");
    assert!(
        body["detail"].as_str().unwrap().contains("not enabled"),
        "refusal should explain the access model: {body}"
    );

    // …and re-enabling flips the same call back to allowed.
    assert!(h.broker.ui_set_tool_access(&conn.id, true).unwrap());
    let (status, _) = uds_request(
        &h.socket,
        "POST",
        "/v1/http",
        &[("authorization", &auth)],
        Some(call),
    )
    .await;
    assert_eq!(status, 200);
}

#[tokio::test]
async fn pair_response_is_self_contained() {
    let h = harness(BrokerConfig::default()).await;
    let (status, body) = uds_request(
        &h.socket,
        "POST",
        "/v1/pair",
        &[],
        Some(json!({"agent_name": "claude-code"})),
    )
    .await;
    assert_eq!(status, 200);
    assert!(body["token"].as_str().unwrap().starts_with("aka_"));
    // The response echoes what was registered, so the agent can
    // log its enrollment without a follow-up /v1/whoami.
    assert_eq!(body["agent"], "claude-code");
    // The storage guidance travels with the credential: the shared key
    // already lives in the token file.
    assert_eq!(body["expires_after_days"], 30);
    assert_eq!(
        body["store_at"].as_str().unwrap(),
        h.broker.paths.token_display()
    );
    // The token file exists, owner-only, and holds the very key pairing
    // returned — file readers and pairers get the same credential.
    use std::os::unix::fs::PermissionsExt;
    let token_file = h.broker.paths.token_file();
    let meta = std::fs::metadata(&token_file).unwrap();
    assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    assert_eq!(
        std::fs::read_to_string(&token_file).unwrap(),
        body["token"].as_str().unwrap()
    );
}

#[tokio::test]
async fn whoami_probes_a_stored_token() {
    let mut h = harness(BrokerConfig::default()).await;
    let token = h.pair("claude-code").await;
    let auth = format!("Bearer {token}");
    // The label is per-request (self-reported header), not per-token: one
    // shared key serves every client.
    let (status, body) = uds_request(
        &h.socket,
        "GET",
        "/v1/whoami",
        &[
            ("authorization", &auth),
            ("x-agentmfa-client", "claude-code"),
        ],
        None,
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body["agent"], "claude-code");
    assert!(body["expires_at"].as_str().is_some());
    // Unlabeled calls fall back to the generic label.
    let (status, body) = uds_request(
        &h.socket,
        "GET",
        "/v1/whoami",
        &[("authorization", &auth)],
        None,
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body["agent"], "agent");
    // A garbage token is a plain 401, the signal to fall through to pairing.
    let (status, body) = uds_request(
        &h.socket,
        "GET",
        "/v1/whoami",
        &[("authorization", "Bearer aka_bogus")],
        None,
    )
    .await;
    assert_eq!(status, 401);
    assert_eq!(body["reason"], "invalid_token");
}

#[tokio::test]
async fn whoami_is_exempt_from_the_per_token_limit() {
    // The MCP sidecar resolves the token via whoami on *every* request it
    // serves (no caching, so a revoked token stops working at once). Charging
    // whoami against the capability budget would halve an agent's real
    // tool-call rate and surface as a mystifying rate limit, so whoami is
    // exempt — while capability calls stay limited.
    let config = BrokerConfig {
        per_identity_per_min: 2,
        ..BrokerConfig::default()
    };
    let mut h = harness(config).await;
    let up = upstream().await;
    api_connection(&h, "github", up.port);
    let token = h.pair("claude-code").await;
    let auth = format!("Bearer {token}");

    // Merely borrowing an envelope method name is not enough to bypass the
    // limiter: it must still be a JSON-RPC 2.0 message.
    let (status, body) = uds_request(
        &h.socket,
        "POST",
        "/v1/http",
        &[("authorization", &auth)],
        Some(json!({
            "connection": "github",
            "method": "POST",
            "path": "/echo",
            "body": { "id": 0, "method": "initialize" },
        })),
    )
    .await;
    assert_eq!(status, 200, "lookalike envelope: {body}");

    // Far more whoami calls than the limit; every one succeeds.
    for _ in 0..5 {
        let (status, body) = uds_request(
            &h.socket,
            "GET",
            "/v1/whoami",
            &[("authorization", &auth)],
            None,
        )
        .await;
        assert_eq!(status, 200, "whoami must not be rate limited: {body}");
    }

    // The limiter is still armed for capability traffic: the first listing
    // passes, the next 429s, proving whoami's exemption did not disarm it.
    let (status, _) = uds_request(
        &h.socket,
        "GET",
        "/v1/connections",
        &[("authorization", &auth)],
        None,
    )
    .await;
    assert_eq!(status, 200);
    let (status, body) = uds_request(
        &h.socket,
        "GET",
        "/v1/connections",
        &[("authorization", &auth)],
        None,
    )
    .await;
    assert_eq!(status, 429);
    assert_eq!(body["reason"], "rate_limited");
}

#[tokio::test]
async fn recognized_mcp_envelope_legs_do_not_spend_the_tool_call_budget() {
    let config = BrokerConfig {
        per_identity_per_min: 1,
        ..BrokerConfig::default()
    };
    let mut h = harness(config).await;
    let up = upstream().await;
    h.broker
        .store
        .add_secret("MCP_KEY", Zeroizing::new("mcp_test_secret_value".into()))
        .unwrap();
    h.broker
        .store
        .add_connection(ConnectionSpec {
            name: "docs".into(),
            config: ConnectionConfig::Api {
                host: "127.0.0.1".into(),
                scheme: "http".into(),
                port: Some(up.port),
                trusted_ca_bundle_path: None,
                template: "Authorization: Bearer {{MCP_KEY}}".into(),
                mcp_path: Some("/echo".into()),
                test_path: None,
                oauth: None,
            },
            secrets: vec![],
        })
        .unwrap();
    let token = h.pair("claude-code").await;
    let auth = format!("Bearer {token}");

    for method in ["initialize", "notifications/initialized", "tools/list"] {
        let (status, body) = uds_request(
            &h.socket,
            "POST",
            "/v1/http",
            &[("authorization", &auth)],
            Some(json!({
                "connection": "docs",
                "method": "POST",
                "path": "/echo",
                "body": { "jsonrpc": "2.0", "id": 1, "method": method },
            })),
        )
        .await;
        assert_eq!(status, 200, "{method}: {body}");
    }
    let (status, body) = uds_request(
        &h.socket,
        "POST",
        "/v1/http",
        &[("authorization", &auth)],
        Some(json!({
            "connection": "docs",
            "method": "DELETE",
            "path": "/echo",
            "headers": { "mcp-session-id": "session-1" },
        })),
    )
    .await;
    assert_eq!(status, 200, "teardown: {body}");

    let tool_call = || {
        json!({
            "connection": "docs",
            "method": "POST",
            "path": "/echo",
            "body": {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": { "name": "search", "arguments": {} },
            },
        })
    };
    let (status, body) = uds_request(
        &h.socket,
        "POST",
        "/v1/http",
        &[("authorization", &auth)],
        Some(tool_call()),
    )
    .await;
    assert_eq!(status, 200, "first tool call: {body}");
    let (status, body) = uds_request(
        &h.socket,
        "POST",
        "/v1/http",
        &[("authorization", &auth)],
        Some(tool_call()),
    )
    .await;
    assert_eq!(status, 429);
    assert_eq!(body["reason"], "rate_limited");
}

#[tokio::test]
async fn rotated_key_gets_a_distinct_reason() {
    let mut h = harness(BrokerConfig::default()).await;
    let token1 = h.pair("claude-code").await;
    // The user rotates the key in the app.
    h.broker.ui_rotate_key().unwrap();
    // The old key's next call is told what happened and what to do, not
    // just "invalid_token": re-read the token file the broker rewrote.
    let auth1 = format!("Bearer {token1}");
    let (status, body) = uds_request(
        &h.socket,
        "GET",
        "/v1/whoami",
        &[("authorization", &auth1)],
        None,
    )
    .await;
    assert_eq!(status, 401);
    assert_eq!(body["reason"], "token_superseded");
    assert!(body["detail"].as_str().unwrap().contains("token file"));
    // The refusal names the exact file to re-read, so recovery is
    // mechanical.
    assert_eq!(
        body["store_at"].as_str().unwrap(),
        h.broker.paths.token_display()
    );
    // The rewritten file holds the working key.
    let token2 = std::fs::read_to_string(h.broker.paths.token_file()).unwrap();
    assert_ne!(token1, token2);
    let auth2 = format!("Bearer {token2}");
    let (status, _) = uds_request(
        &h.socket,
        "GET",
        "/v1/whoami",
        &[("authorization", &auth2)],
        None,
    )
    .await;
    assert_eq!(status, 200);
}

#[tokio::test]
async fn a_brokered_401_flips_connection_health_to_needs_reconnect() {
    let mut h = harness(BrokerConfig::default()).await;
    let up = upstream().await;
    api_connection(&h, "github", up.port);
    let conn_id = h.broker.store.connection_by_name("github").unwrap().id;
    let token = h.pair("claude-code").await;
    let auth = format!("Bearer {token}");

    // Nothing checked yet.
    assert!(h.broker.health.get(&conn_id).is_none());

    let rejected = json!({ "connection": "github", "method": "GET", "path": "/unauthorized" });

    // One rejection is not evidence the credential is dead: the agent chose
    // the path, and a token merely unscoped for it answers 401 there while
    // working everywhere else. The badge does not move yet.
    let (status, _) = uds_request(
        &h.socket,
        "POST",
        "/v1/http",
        &[("authorization", &auth)],
        Some(rejected.clone()),
    )
    .await;
    assert_eq!(status, 200, "the broker relays the upstream response");
    assert!(
        h.broker.health.get(&conn_id).is_none(),
        "a single 401 must not tell the user to reconnect a working credential"
    );

    // A second consecutive rejection corroborates it.
    let (status, _) = uds_request(
        &h.socket,
        "POST",
        "/v1/http",
        &[("authorization", &auth)],
        Some(rejected),
    )
    .await;
    assert_eq!(status, 200);
    let health = h.broker.health.get(&conn_id).expect("health recorded");
    assert_eq!(health.status, aka_core::types::HealthStatus::NeedsReconnect);

    // A subsequent successful call upgrades it back to ok.
    let (status, _) = uds_request(
        &h.socket,
        "POST",
        "/v1/http",
        &[("authorization", &auth)],
        Some(json!({ "connection": "github", "method": "GET", "path": "/user/repos" })),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(
        h.broker.health.get(&conn_id).unwrap().status,
        aka_core::types::HealthStatus::Ok
    );
}

#[tokio::test]
async fn a_curated_wiring_refuses_tools_outside_its_subset() {
    let mut h = harness(BrokerConfig::default()).await;
    let up = upstream().await;
    // An MCP connection: an API connection with an mcp_path, pointed at the
    // upstream's /echo so tools/call round-trips.
    h.broker
        .store
        .add_secret("MCP_TOKEN", Zeroizing::new("tok".into()))
        .unwrap();
    h.broker
        .store
        .add_connection(ConnectionSpec {
            name: "docs".into(),
            config: ConnectionConfig::Api {
                host: "127.0.0.1".into(),
                scheme: "http".into(),
                port: Some(up.port),
                trusted_ca_bundle_path: None,
                template: "Authorization: Bearer {{MCP_TOKEN}}".into(),
                mcp_path: Some("/echo".into()),
                test_path: None,
                oauth: None,
            },
            secrets: vec![],
        })
        .unwrap();
    let conn = h.broker.store.connection_by_name("docs").unwrap();
    let token = h.pair("claude-code").await;
    let auth = format!("Bearer {token}");

    // Allow only "search"; "delete" is not in the subset.
    h.broker
        .ui_set_allowed_tools(&conn.id, Some(vec!["search".into()]))
        .unwrap();

    let call = |name: &str| {
        json!({
            "connection": "docs",
            "method": "POST",
            "path": "/echo",
            "body": { "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                      "params": { "name": name, "arguments": {} } }
        })
    };

    let (status, body) = uds_request(
        &h.socket,
        "POST",
        "/v1/http",
        &[("authorization", &auth)],
        Some(call("delete")),
    )
    .await;
    assert_eq!(status, 403, "a tool outside the subset is refused: {body}");
    assert_eq!(body["reason"], "denied_by_policy");

    let (status, body) = uds_request(
        &h.socket,
        "POST",
        "/v1/http",
        &[("authorization", &auth)],
        Some(json!({
            "connection": "docs",
            "method": "POST",
            "path": "/echo",
            "body": [
                { "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                  "params": { "name": "search", "arguments": {} } },
                { "jsonrpc": "2.0", "id": 3, "method": "tools/call",
                  "params": { "name": "delete", "arguments": {} } }
            ]
        })),
    )
    .await;
    assert_eq!(
        status, 403,
        "one disallowed call must fail the whole JSON-RPC batch: {body}"
    );
    assert_eq!(body["reason"], "denied_by_policy");

    let (status, _) = uds_request(
        &h.socket,
        "POST",
        "/v1/http",
        &[("authorization", &auth)],
        Some(call("search")),
    )
    .await;
    assert_eq!(status, 200, "an allowed tool passes through");

    // A non-tools/call body on the MCP path is untouched by the filter.
    let (status, _) = uds_request(
        &h.socket,
        "POST",
        "/v1/http",
        &[("authorization", &auth)],
        Some(json!({
            "connection": "docs",
            "method": "POST",
            "path": "/echo",
            "body": { "jsonrpc": "2.0", "id": 2, "method": "tools/list" }
        })),
    )
    .await;
    assert_eq!(status, 200, "listing is not a tools/call and passes");

    // Clearing the subset (None) allows everything again.
    h.broker.ui_set_allowed_tools(&conn.id, None).unwrap();
    let (status, _) = uds_request(
        &h.socket,
        "POST",
        "/v1/http",
        &[("authorization", &auth)],
        Some(call("delete")),
    )
    .await;
    assert_eq!(status, 200, "no subset means every tool is callable");
}

#[tokio::test]
async fn an_oversized_mcp_tool_result_becomes_a_bounded_explicit_tool_error() {
    let config = BrokerConfig {
        response_cap: 1024,
        ..BrokerConfig::default()
    };
    let mut h = harness(config).await;
    let up = upstream().await;
    h.broker
        .store
        .add_connection(ConnectionSpec {
            name: "large-docs".into(),
            config: ConnectionConfig::Api {
                host: "127.0.0.1".into(),
                scheme: "http".into(),
                port: Some(up.port),
                trusted_ca_bundle_path: None,
                template: String::new(),
                mcp_path: Some("/large-mcp".into()),
                test_path: None,
                oauth: None,
            },
            secrets: vec![],
        })
        .unwrap();
    let token = h.pair("claude-code").await;
    let auth = format!("Bearer {token}");
    let (status, envelope) = uds_request(
        &h.socket,
        "POST",
        "/v1/http",
        &[("authorization", &auth)],
        Some(json!({
            "connection": "large-docs",
            "method": "POST",
            "path": "/large-mcp",
            "headers": { "content-type": "application/json" },
            "body": {
                "jsonrpc": "2.0",
                "id": 77,
                "method": "tools/call",
                "params": { "name": "search", "arguments": {} },
            },
        })),
    )
    .await;
    assert_eq!(status, 200, "{envelope}");
    let response: Value =
        serde_json::from_str(envelope["body"].as_str().expect("relayed JSON-RPC")).unwrap();
    assert_eq!(response["id"], 77);
    assert_eq!(response["result"]["isError"], true);
    assert_eq!(
        response["result"]["_meta"]["agentmfa"]["result_truncated"],
        true
    );
    let text = response["result"]["content"][0]["text"]
        .as_str()
        .expect("tool error text");
    assert!(text.contains("exceeded the 1024 byte broker cap"), "{text}");
    assert!(text.contains("useful-prefix"), "{text}");
}

#[tokio::test]
async fn agent_connect_requests_are_audited_and_debounced() {
    let mut h = harness(BrokerConfig::default()).await;
    let token = h.pair("claude-code").await;
    let auth = format!("Bearer {token}");

    let (status, body) = uds_request(
        &h.socket,
        "POST",
        "/v1/connect-requests",
        &[
            ("authorization", &auth),
            ("x-agentmfa-client", "claude-code"),
        ],
        Some(json!({ "service": "linear" })),
    )
    .await;
    assert_eq!(status, 202, "{body}");
    assert_eq!(body["status"], "requested");

    // The ask is observable: an audit entry names the agent and service.
    let entries = h.broker.audit.recent(10);
    let entry = entries
        .iter()
        .find(|entry| matches!(entry.kind, aka_core::audit::AuditKind::ConnectRequested))
        .expect("connect request audited");
    assert_eq!(entry.agent.as_deref(), Some("claude-code"));
    assert_eq!(entry.fields["service"], json!("linear"));

    // The same agent asking again within the window is coalesced.
    let (status, body) = uds_request(
        &h.socket,
        "POST",
        "/v1/connect-requests",
        &[
            ("authorization", &auth),
            ("x-agentmfa-client", "claude-code"),
        ],
        Some(json!({ "service": "linear" })),
    )
    .await;
    assert_eq!(status, 202);
    assert_eq!(body["status"], "already_requested");

    // Garbage service names are refused, not audited.
    let (status, _) = uds_request(
        &h.socket,
        "POST",
        "/v1/connect-requests",
        &[
            ("authorization", &auth),
            ("x-agentmfa-client", "claude-code"),
        ],
        Some(json!({ "service": "" })),
    )
    .await;
    assert_eq!(status, 400);
}

#[tokio::test]
async fn elicitations_require_an_exact_upstream_correlation_capability() {
    let mut h = harness(BrokerConfig::default()).await;
    let up = upstream().await;
    h.broker
        .store
        .add_secret("MCP_TOKEN", Zeroizing::new("tok".into()))
        .unwrap();
    h.broker
        .store
        .add_connection(ConnectionSpec {
            name: "interactive".into(),
            config: ConnectionConfig::Api {
                host: "127.0.0.1".into(),
                scheme: "http".into(),
                port: Some(up.port),
                trusted_ca_bundle_path: None,
                template: "Authorization: Bearer {{MCP_TOKEN}}".into(),
                mcp_path: Some("/needs-input".into()),
                test_path: None,
                oauth: None,
            },
            secrets: vec![],
        })
        .unwrap();
    let token = h.pair("claude-code").await;
    let auth = format!("Bearer {token}");

    let (status, _) = uds_request(
        &h.socket,
        "POST",
        "/v1/elicit",
        &[("authorization", &auth)],
        Some(json!({
            "connection": "interactive",
            "correlation_token": "eli_agent_authored"
        })),
    )
    .await;
    assert_eq!(status, 403, "an agent bearer alone cannot raise a prompt");

    let (status, relay) = uds_request(
        &h.socket,
        "POST",
        "/v1/http",
        &[("authorization", &auth)],
        Some(json!({
            "connection": "interactive",
            "method": "POST",
            "path": "/needs-input",
            "headers": {"content-type": "application/json"},
            "body": {
                "jsonrpc": "2.0",
                "id": 7,
                "method": "tools/call",
                "params": {"name": "lookup", "arguments": {}}
            }
        })),
    )
    .await;
    assert_eq!(status, 200, "{relay}");
    let permit = relay["elicitation_tokens"]["account"]
        .as_str()
        .unwrap_or_else(|| panic!("the exact upstream elicitation received a permit: {relay}"));

    let (status, answer) = uds_request(
        &h.socket,
        "POST",
        "/v1/elicit",
        &[("authorization", &auth)],
        Some(json!({
            "connection": "interactive",
            "correlation_token": permit,
            // Unknown caller fields cannot replace the broker-recorded prompt.
            "message": "Type your password",
            "requested_schema": {"format": "password"}
        })),
    )
    .await;
    assert_eq!(status, 200, "{answer}");
    assert_eq!(answer["action"], "cancel");

    let (status, _) = uds_request(
        &h.socket,
        "POST",
        "/v1/elicit",
        &[("authorization", &auth)],
        Some(json!({
            "connection": "interactive",
            "correlation_token": permit
        })),
    )
    .await;
    assert_eq!(status, 403, "an elicitation permit is single-use");
}

#[tokio::test]
async fn elicitation_and_connect_request_endpoints_spend_the_identity_budget() {
    let mut config = BrokerConfig::default();
    config.per_identity_per_min = 1;
    let mut h = harness(config).await;
    let token = h.pair("claude-code").await;
    let auth = format!("Bearer {token}");

    let (status, _) = uds_request(
        &h.socket,
        "POST",
        "/v1/connect-requests",
        &[("authorization", &auth)],
        Some(json!({"service": "linear"})),
    )
    .await;
    assert_eq!(status, 202);
    let (status, _) = uds_request(
        &h.socket,
        "POST",
        "/v1/connect-requests",
        &[("authorization", &auth)],
        Some(json!({"service": "notion"})),
    )
    .await;
    assert_eq!(status, 429);

    let (status, _) = uds_request(
        &h.socket,
        "POST",
        "/v1/elicit",
        &[("authorization", &auth)],
        Some(json!({
            "connection": "anything",
            "correlation_token": "eli_untrusted"
        })),
    )
    .await;
    assert_eq!(status, 429);
}

#[tokio::test]
async fn brokered_calls_audit_attribution_duration_and_outcome() {
    let mut h = harness(BrokerConfig::default()).await;
    let up = upstream().await;
    api_connection(&h, "github", up.port);
    let token = h.pair("claude-code").await;
    let auth = format!("Bearer {token}");

    let (status, _) = uds_request(
        &h.socket,
        "POST",
        "/v1/http",
        &[
            ("authorization", &auth),
            ("x-agentmfa-client", "claude-code"),
        ],
        Some(json!({ "connection": "github", "method": "GET", "path": "/user/repos" })),
    )
    .await;
    assert_eq!(status, 200);

    // The activity view filters and chips on these columns; they are a
    // contract, not decoration.
    let entries = h.broker.audit.recent(10);
    let call = entries
        .iter()
        .find(|entry| matches!(entry.kind, aka_core::audit::AuditKind::HttpExecuted))
        .expect("brokered call audited");
    assert_eq!(call.agent.as_deref(), Some("claude-code"));
    assert_eq!(call.connection.as_deref(), Some("github"));
    assert_eq!(call.outcome.as_deref(), Some("200"));
    assert!(call.duration_ms.is_some(), "duration is measured");
    assert_eq!(call.fields["method"], json!("GET"));
    assert_eq!(call.fields["path"], json!("/user/repos"));
}

/* -------------------------- HTTP direct endpoint -------------------------- */

/// Minimal HTTP/1.1 client over a loopback TCP port (the reverse-proxy
/// endpoint). Returns (status, response headers, parsed-json-or-string body).
async fn loopback_request(
    port: u16,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&str>,
) -> (u16, axum::http::HeaderMap, Value) {
    let stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let io = hyper_util::rt::TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
    tokio::spawn(conn);
    let mut builder = hyper::Request::builder()
        .method(method)
        .uri(path)
        .header("host", "localhost");
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    let request = builder.body(body.unwrap_or("").to_string()).unwrap();
    let response = sender.send_request(request).await.unwrap();
    let status = response.status().as_u16();
    let (parts, body) = response.into_parts();
    let bytes = body.collect().await.unwrap().to_bytes();
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes)
            .unwrap_or(Value::String(String::from_utf8_lossy(&bytes).into_owned()))
    };
    (status, parts.headers, value)
}

/// Issue an HTTP direct endpoint on `github`; returns (info, port).
async fn issue_http_endpoint(h: &Harness) -> (aka_core::broker::IssuedEndpointInfo, u16) {
    let conn = h.broker.store.connection_by_name("github").unwrap();
    let info = h.broker.ui_issue_endpoint(&conn.id).await.unwrap();
    let port: u16 = info.dsn.rsplit(':').next().unwrap().parse().unwrap();
    (info, port)
}

#[tokio::test]
async fn http_direct_endpoint_proxies_with_injected_credential() {
    let mut h = harness(BrokerConfig::default()).await;
    let up = upstream().await;
    api_connection(&h, "github", up.port);
    h.pair("claude-code").await;
    let (info, port) = issue_http_endpoint(&h).await;

    assert_eq!(info.kind, ConnectionKind::Api);
    assert!(info.dsn.starts_with("http://127.0.0.1:"));
    assert!(info.secret.starts_with("end_"));
    // The secret is not in the pasteable base URL (it rides a header).
    assert!(!info.dsn.contains(&info.secret));

    let auth = format!("Bearer {}", info.secret);
    let (status, _, body) = loopback_request(
        port,
        "GET",
        "/echo",
        &[("authorization", &auth), ("x-test", "hello")],
        None,
    )
    .await;
    assert_eq!(status, 200, "proxied response: {body}");
    // The request reached the pinned upstream (echo reflects our header) …
    assert_eq!(body["headers"]["x-test"], "hello");
    // … the broker injected the real credential on the upstream leg …
    assert!(
        body["headers"]["authorization"].as_str().is_some(),
        "an Authorization header should have been injected: {body}"
    );
    // … and the credential is redacted out of the relayed response.
    assert!(
        !body.to_string().contains("ghp_test_secret_value"),
        "the injected credential must be redacted: {body}"
    );
}

#[tokio::test]
async fn http_direct_endpoint_fails_closed_before_reaching_upstream() {
    let h = harness(BrokerConfig::default()).await;
    let up = upstream().await;
    api_connection(&h, "github", up.port);
    let conn = h.broker.store.connection_by_name("github").unwrap();
    h.broker
        .ui_set_confirm_mode(&conn.id, ConfirmMode::On)
        .unwrap();
    let (info, port) = issue_http_endpoint(&h).await;

    let auth = format!("Bearer {}", info.secret);
    let (status, _, body) =
        loopback_request(port, "POST", "/dispatch", &[("authorization", &auth)], None).await;
    assert_eq!(status, 403, "{body}");
    assert_eq!(body["reason"], "approval_unavailable");
    assert_eq!(
        up.hits.load(Ordering::SeqCst),
        0,
        "the direct request must park before upload or upstream dispatch"
    );
}

#[tokio::test]
async fn http_direct_endpoint_only_exempts_identifiable_mcp_transport_legs() {
    let h = harness(BrokerConfig::default()).await;
    let up = upstream().await;
    api_connection(&h, "github", up.port);
    let conn = h.broker.store.connection_by_name("github").unwrap();
    let mut config = conn.config.clone();
    let ConnectionConfig::Api { mcp_path, .. } = &mut config else {
        unreachable!()
    };
    *mcp_path = Some("/dispatch".into());
    h.broker
        .ui_update_connection(
            &conn.id,
            ConnectionSpec {
                name: conn.name.clone(),
                config,
                secrets: vec![],
            },
        )
        .unwrap();
    h.broker
        .ui_set_confirm_mode(&conn.id, ConfirmMode::On)
        .unwrap();
    let (info, port) = issue_http_endpoint(&h).await;
    let auth = format!("Bearer {}", info.secret);

    let (status, _, _) = loopback_request(
        port,
        "GET",
        "/dispatch",
        &[
            ("authorization", &auth),
            ("accept", "application/json, text/event-stream"),
        ],
        None,
    )
    .await;
    assert_eq!(
        status, 405,
        "an exact event-stream GET should reach the POST-only fixture"
    );

    let (status, _, _) = loopback_request(
        port,
        "DELETE",
        "/dispatch",
        &[("authorization", &auth), ("mcp-session-id", "session-1")],
        None,
    )
    .await;
    assert_eq!(
        status, 405,
        "a named session DELETE should reach the POST-only fixture"
    );

    for (method, path, extra_header, body, case) in [
        ("GET", "/dispatch", None, None, "plain GET"),
        (
            "GET",
            "/dispatch",
            Some(("accept", "text/event-streaming")),
            None,
            "lookalike media type",
        ),
        (
            "GET",
            "/dispatch",
            Some(("accept", "text/event-stream; q=0")),
            None,
            "rejected media type",
        ),
        (
            "HEAD",
            "/dispatch",
            Some(("accept", "text/event-stream")),
            None,
            "HEAD request",
        ),
        (
            "GET",
            "/dispatch",
            Some(("accept", "text/event-stream")),
            Some("not empty"),
            "event-stream GET with a body",
        ),
        ("DELETE", "/dispatch", None, None, "unnamed session DELETE"),
        (
            "DELETE",
            "/dispatch",
            Some(("mcp-session-id", "session-1")),
            Some("not empty"),
            "session DELETE with a body",
        ),
        (
            "GET",
            "/echo",
            Some(("accept", "text/event-stream")),
            None,
            "event-stream GET off the pinned MCP path",
        ),
    ] {
        let mut headers = vec![("authorization", auth.as_str())];
        if let Some(header) = extra_header {
            headers.push(header);
        }
        let (status, _, response_body) = loopback_request(port, method, path, &headers, body).await;
        assert_eq!(status, 403, "{case} bypassed confirmation: {response_body}");
    }
    assert_eq!(
        up.hits.load(Ordering::SeqCst),
        0,
        "transport setup/teardown and refused lookalikes never hit the POST route"
    );
}

#[tokio::test]
async fn curated_mcp_tools_cannot_bypass_the_subset_through_a_direct_endpoint() {
    let h = harness(BrokerConfig::default()).await;
    let up = upstream().await;
    api_connection(&h, "docs", up.port);
    let conn = h.broker.store.connection_by_name("docs").unwrap();
    let mut config = conn.config.clone();
    let ConnectionConfig::Api { mcp_path, .. } = &mut config else {
        unreachable!()
    };
    *mcp_path = Some("/dispatch".into());
    h.broker
        .ui_update_connection(
            &conn.id,
            ConnectionSpec {
                name: conn.name.clone(),
                config,
                secrets: vec![],
            },
        )
        .unwrap();
    h.broker
        .ui_set_allowed_tools(&conn.id, Some(vec!["search".into()]))
        .unwrap();
    let info = h.broker.ui_issue_endpoint(&conn.id).await.unwrap();
    let port: u16 = info.dsn.rsplit(':').next().unwrap().parse().unwrap();

    let auth = format!("Bearer {}", info.secret);
    let call = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "search", "arguments": {}},
    })
    .to_string();
    let (status, _, body) = loopback_request(
        port,
        "POST",
        "/dispatch",
        &[("authorization", &auth)],
        Some(&call),
    )
    .await;
    assert_eq!(status, 403, "{body}");
    assert_eq!(body["reason"], "denied_by_policy");
    assert_eq!(
        up.hits.load(Ordering::SeqCst),
        0,
        "the direct path must not bypass MCP tool curation"
    );
}

#[tokio::test]
async fn http_direct_endpoint_contains_cookies_until_explicitly_enabled() {
    let mut h = harness(BrokerConfig::default()).await;
    let up = upstream().await;
    api_connection(&h, "github", up.port);
    h.pair("claude-code").await;
    let (info, port) = issue_http_endpoint(&h).await;
    let auth = format!("Bearer {}", info.secret);

    let (status, headers, _) =
        loopback_request(port, "GET", "/cookies", &[("authorization", &auth)], None).await;
    assert_eq!(status, 200);
    assert!(!headers.contains_key(axum::http::header::SET_COOKIE));

    let connection = h.broker.store.connection_by_name("github").unwrap();
    assert!(h
        .broker
        .ui_set_expose_response_credentials(&connection.id, true)
        .unwrap());
    let (status, headers, _) =
        loopback_request(port, "GET", "/cookies", &[("authorization", &auth)], None).await;
    assert_eq!(status, 200);
    let cookies: Vec<&str> = headers
        .get_all(axum::http::header::SET_COOKIE)
        .iter()
        .map(|value| value.to_str().unwrap())
        .collect();
    assert_eq!(
        cookies,
        vec![
            "session=one; Path=/; HttpOnly; SameSite=Lax",
            "csrf=two; Path=/; Secure; SameSite=Strict",
        ]
    );
}

#[tokio::test]
async fn disabling_access_during_http_upload_prevents_dispatch() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let mut h = harness(BrokerConfig::default()).await;
    let up = upstream().await;
    api_connection(&h, "github", up.port);
    h.pair("claude-code").await;
    let (info, port) = issue_http_endpoint(&h).await;
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let request = format!(
        "POST /dispatch HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\nContent-Length: 4\r\nConnection: close\r\n\r\nx",
        info.secret
    );
    stream.write_all(request.as_bytes()).await.unwrap();

    // Let the handler authenticate, then disable while it is still waiting
    // for the remainder of the body.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let connection = h.broker.store.connection_by_name("github").unwrap();
    h.broker.ui_set_tool_access(&connection.id, false).unwrap();
    let _ = stream.write_all(b"xxx").await;

    let mut response = Vec::new();
    let _read = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        stream.read_to_end(&mut response),
    )
    .await
    .expect("the refused upload should be terminated");
    if !response.is_empty() {
        let response = String::from_utf8_lossy(&response);
        assert!(
            response.starts_with("HTTP/1.1 403"),
            "response was {response}"
        );
    }
    // Hyper may reset an HTTP/1.1 connection after writing all or part of the
    // 403 when the server deliberately stops reading an incomplete request
    // body. That is an equally fail-closed outcome; the invariant is that the
    // request terminates promptly and never reaches the upstream.
    assert_eq!(up.hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn http_direct_endpoint_rejects_missing_or_wrong_secret() {
    let mut h = harness(BrokerConfig {
        per_identity_per_min: 2,
        ..BrokerConfig::default()
    })
    .await;
    let up = upstream().await;
    api_connection(&h, "github", up.port);
    h.pair("claude-code").await;
    let (_info, port) = issue_http_endpoint(&h).await;

    // No secret.
    let (status, _, body) = loopback_request(port, "GET", "/echo", &[], None).await;
    assert_eq!(status, 401);
    assert_eq!(body["reason"], "missing_secret");

    // Wrong secret.
    let (status, _, body) = loopback_request(
        port,
        "GET",
        "/echo",
        &[("authorization", "Bearer end_bogus0000")],
        None,
    )
    .await;
    assert_eq!(status, 401);
    assert_eq!(body["reason"], "invalid_secret");

    // Failed authentication has its own listener-local window. It neither
    // spends a legitimate endpoint holder's request budget nor permits an
    // unbounded secret probe.
    let (status, headers, body) = loopback_request(
        port,
        "GET",
        "/echo",
        &[("authorization", "Bearer end_still_wrong")],
        None,
    )
    .await;
    assert_eq!(status, 429);
    assert_eq!(body["reason"], "rate_limited");
    assert!(headers.contains_key("retry-after"));

    let denied: Vec<_> = h
        .broker
        .audit
        .recent(10)
        .into_iter()
        .filter(|entry| {
            entry.kind == aka_core::audit::AuditKind::Denied
                && entry.text.starts_with("Direct endpoint authentication ")
        })
        .collect();
    assert_eq!(denied.len(), 3);
    assert!(denied
        .iter()
        .all(|entry| entry.fields.contains_key("peer_addr")));
    // The upstream was never dialed on a refused request.
    assert_eq!(up.hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn http_direct_endpoint_rejects_client_supplied_custom_credential_header() {
    let mut h = harness(BrokerConfig::default()).await;
    let up = upstream().await;
    h.broker
        .store
        .add_secret("API_KEY", Zeroizing::new("real-key".into()))
        .unwrap();
    h.broker
        .store
        .add_connection(ConnectionSpec {
            name: "github".into(),
            config: ConnectionConfig::Api {
                host: "127.0.0.1".into(),
                scheme: "http".into(),
                port: Some(up.port),
                trusted_ca_bundle_path: None,
                template: "X-Api-Key: {{API_KEY}}".into(),
                mcp_path: None,
                test_path: None,
                oauth: None,
            },
            secrets: vec![],
        })
        .unwrap();
    h.pair("claude-code").await;
    let (info, port) = issue_http_endpoint(&h).await;
    let auth = format!("Bearer {}", info.secret);

    let (status, _, body) = loopback_request(
        port,
        "GET",
        "/echo",
        &[("authorization", &auth), ("x-api-key", "attacker-value")],
        None,
    )
    .await;
    assert_eq!(status, 400, "response: {body}");
    assert_eq!(body["reason"], "reserved_header");
    assert!(
        body["detail"]
            .as_str()
            .is_some_and(|detail| detail.contains("omit its native credential header")
                && detail.contains("Authorization: Bearer")),
        "response: {body}"
    );
    assert_eq!(up.hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn reissuing_http_endpoint_rotates_secret_without_rebinding_its_port() {
    let mut h = harness(BrokerConfig::default()).await;
    let up = upstream().await;
    api_connection(&h, "github", up.port);
    h.pair("claude-code").await;
    let (first, port) = issue_http_endpoint(&h).await;

    let (second, rotated_port) = issue_http_endpoint(&h).await;
    assert_eq!(second.endpoint_id, first.endpoint_id);
    assert_eq!(rotated_port, port);
    assert_ne!(second.secret, first.secret);

    let old_auth = format!("Bearer {}", first.secret);
    let (status, _, _) =
        loopback_request(port, "GET", "/echo", &[("authorization", &old_auth)], None).await;
    assert_eq!(status, 401);

    let new_auth = format!("Bearer {}", second.secret);
    let (status, _, _) =
        loopback_request(port, "GET", "/echo", &[("authorization", &new_auth)], None).await;
    assert_eq!(status, 200);
}

#[tokio::test]
async fn http_endpoint_survives_rebind_and_revoke_frees_the_port() {
    let mut h = harness(BrokerConfig::default()).await;
    let up = upstream().await;
    api_connection(&h, "github", up.port);
    h.pair("claude-code").await;
    let (info, port) = issue_http_endpoint(&h).await;
    let auth = format!("Bearer {}", info.secret);

    // Rebinding (as a restart does) reuses the persisted port; the same base
    // URL keeps working.
    h.broker.rebind_endpoints().await;
    let (status, _, _) =
        loopback_request(port, "POST", "/dispatch", &[("authorization", &auth)], None).await;
    assert_eq!(status, 204);
    assert_eq!(up.hits.load(Ordering::SeqCst), 1);

    // Revoking stops the listener and frees the loopback port.
    assert!(h.broker.ui_revoke_endpoint(&info.endpoint_id).unwrap());
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        while tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the port should be refused after revoke");
}

/* ---------------------------- streamed relay ------------------------------ */

/// API-3. The JSON-envelope plane answers once, at the end, with everything in
/// memory. A streamed call reports the same facts in the order they become
/// true — which is what lets a caller see a large transfer progressing rather
/// than a socket that has gone quiet.
#[tokio::test]
async fn a_streamed_call_reports_its_head_and_body_as_they_arrive() {
    let mut h = harness(BrokerConfig::default()).await;
    let up = upstream().await;
    api_connection(&h, "github", up.port);
    let token = h.pair("agent").await;

    let (status, content_type, body) = uds_request_raw(
        &h.socket,
        "POST",
        "/v1/http",
        &[("authorization", &format!("Bearer {token}"))],
        Some(json!({
            "connection": "github",
            "method": "GET",
            "path": "/user/repos",
            "stream": true,
        })),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert!(content_type.starts_with("text/event-stream"), "{content_type}");

    let frames = sse_frames(&body);
    let names: Vec<&str> = frames.iter().map(|(event, _)| event.as_str()).collect();
    assert_eq!(names.first(), Some(&"head"), "{names:?}");
    assert_eq!(names.last(), Some(&"end"), "{names:?}");
    assert!(!names.contains(&"error"), "{names:?}");
    assert_eq!(frames[0].1["status"], 200);
    assert_eq!(frames[0].1["headers"]["content-type"], "application/json");

    let relayed = sse_body_bytes(&frames);
    let parsed: Value = serde_json::from_slice(&relayed).unwrap();
    assert_eq!(parsed[1]["name"], "aka");
    let end = frames.last().unwrap();
    assert_eq!(
        end.1["bytes"].as_u64().unwrap() as usize,
        relayed.len(),
        "the end frame counts what actually crossed"
    );
}

#[tokio::test]
async fn streamed_response_credentials_follow_the_connection_opt_in() {
    let mut h = harness(BrokerConfig::default()).await;
    let up = upstream().await;
    api_connection(&h, "github", up.port);
    let token = h.pair("agent").await;
    let request = || {
        json!({
            "connection": "github",
            "method": "GET",
            "path": "/cookies",
            "stream": true,
        })
    };

    let (_, _, body) = uds_request_raw(
        &h.socket,
        "POST",
        "/v1/http",
        &[("authorization", &format!("Bearer {token}"))],
        Some(request()),
    )
    .await;
    let frames = sse_frames(&body);
    assert!(frames[0].1["headers"].get("set-cookie").is_none());

    let connection = h.broker.store.connection_by_name("github").unwrap();
    h.broker
        .ui_set_expose_response_credentials(&connection.id, true)
        .unwrap();
    let (_, _, body) = uds_request_raw(
        &h.socket,
        "POST",
        "/v1/http",
        &[("authorization", &format!("Bearer {token}"))],
        Some(request()),
    )
    .await;
    let frames = sse_frames(&body);
    let cookies = frames[0].1["headers"]["set-cookie"]
        .as_str()
        .unwrap_or_default();
    assert!(cookies.contains("session=one"));
    assert!(cookies.contains("csrf=two"));
}

/// The credential is scrubbed on the streaming path too, and — because a
/// needle can straddle a chunk boundary — by a relay that carries the
/// undecided tail forward rather than scanning each chunk alone.
#[tokio::test]
async fn a_streamed_body_is_redacted_across_chunk_boundaries() {
    let mut h = harness(BrokerConfig::default()).await;
    let up = upstream().await;
    api_connection(&h, "github", up.port);
    let token = h.pair("agent").await;

    // `/echo` reflects the injected Authorization header straight back.
    let (status, _, body) = uds_request_raw(
        &h.socket,
        "POST",
        "/v1/http",
        &[("authorization", &format!("Bearer {token}"))],
        Some(json!({
            "connection": "github",
            "method": "GET",
            "path": "/echo",
            "stream": true,
        })),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let relayed = String::from_utf8(sse_body_bytes(&sse_frames(&body))).unwrap();
    assert!(
        relayed.contains("[REDACTED]"),
        "the reflected credential should have been scrubbed: {relayed}"
    );
    assert!(
        !relayed.contains("ghp_test_secret_value"),
        "the credential must not survive the stream: {relayed}"
    );
}

/// API-3/API-25's other half: the buffered cap exists because the envelope
/// holds the whole body. The streamed relay never does, so the same response
/// that 502s buffered is simply a transfer.
#[tokio::test]
async fn a_streamed_response_is_not_bound_by_the_buffered_cap() {
    let mut h = harness(BrokerConfig::default()).await;
    let up = upstream().await;
    api_connection(&h, "github", up.port);
    let token = h.pair("agent").await;
    let auth = format!("Bearer {token}");

    let (status, buffered) = uds_request(
        &h.socket,
        "POST",
        "/v1/http",
        &[("authorization", &auth)],
        Some(json!({
            "connection": "github",
            "method": "GET",
            "path": "/large",
        })),
    )
    .await;
    assert_eq!(status, 502, "{buffered}");
    assert_eq!(buffered["reason"], "response_too_large");

    let (status, _, streamed) = uds_request_raw(
        &h.socket,
        "POST",
        "/v1/http",
        &[("authorization", &auth)],
        Some(json!({
            "connection": "github",
            "method": "GET",
            "path": "/large",
            "stream": true,
        })),
    )
    .await;
    assert_eq!(status, 200);
    let frames = sse_frames(&streamed);
    assert_eq!(frames[0].0, "head");
    assert_eq!(frames.last().unwrap().0, "end");
    assert_eq!(
        frames.last().unwrap().1["bytes"].as_u64().unwrap(),
        12 * 1024 * 1024,
        "the whole body crossed"
    );
}

/// A refusal that never reached the upstream is one terminal `error` frame and
/// nothing else: a caller that has seen a head is committed to that answer, so
/// the two can never both appear.
#[tokio::test]
async fn a_refused_stream_carries_one_error_frame_and_no_head() {
    let mut h = harness(BrokerConfig::default()).await;
    let up = upstream().await;
    api_connection(&h, "github", up.port);
    let conn = h.broker.store.connection_by_name("github").unwrap();
    h.broker.ui_set_tool_access(&conn.id, false).unwrap();
    let token = h.pair("agent").await;

    let (status, content_type, body) = uds_request_raw(
        &h.socket,
        "POST",
        "/v1/http",
        &[("authorization", &format!("Bearer {token}"))],
        Some(json!({
            "connection": "github",
            "method": "GET",
            "path": "/user/repos",
            "stream": true,
        })),
    )
    .await;
    // The refusal predates the stream, so it is an ordinary JSON error rather
    // than an event-stream carrying one frame.
    assert_eq!(status, 403, "{body}");
    assert!(!content_type.starts_with("text/event-stream"), "{content_type}");
    assert_eq!(up.hits.load(Ordering::SeqCst), 0);
}

/// Coalescing has to replay a completed outcome to a retry. A stream keeps
/// none, so asking for both is a contradiction the broker names rather than
/// silently resolving one way.
#[tokio::test]
async fn a_stream_cannot_also_ask_to_be_coalesced() {
    let mut h = harness(BrokerConfig::default()).await;
    let up = upstream().await;
    api_connection(&h, "github", up.port);
    let token = h.pair("agent").await;

    let (status, body) = uds_request(
        &h.socket,
        "POST",
        "/v1/http",
        &[("authorization", &format!("Bearer {token}"))],
        Some(json!({
            "connection": "github",
            "method": "POST",
            "path": "/dispatch",
            "request_id": "abc",
            "stream": true,
        })),
    )
    .await;
    assert_eq!(status, 400, "{body}");
    assert!(
        body["detail"].as_str().unwrap_or_default().contains("replaying"),
        "the refusal should say why: {body}"
    );
    assert_eq!(up.hits.load(Ordering::SeqCst), 0);
}

/// The buffered plane's answer is one object, so anything the broker attaches
/// after the relay — the elicitation permits an interactive MCP result mints —
/// rides along for free. A stream has to carry them deliberately, on the
/// terminal frame, or every interactive tool call over the streaming path
/// silently loses its ability to raise a prompt.
#[tokio::test]
async fn a_streamed_answer_still_carries_what_the_broker_attached_after_it() {
    let mut h = harness(BrokerConfig::default()).await;
    let up = upstream().await;
    h.broker
        .store
        .add_secret("MCP_TOKEN", Zeroizing::new("tok".into()))
        .unwrap();
    h.broker
        .store
        .add_connection(ConnectionSpec {
            name: "interactive".into(),
            config: ConnectionConfig::Api {
                host: "127.0.0.1".into(),
                scheme: "http".into(),
                port: Some(up.port),
                trusted_ca_bundle_path: None,
                template: "Authorization: Bearer {{MCP_TOKEN}}".into(),
                mcp_path: Some("/needs-input".into()),
                test_path: None,
                oauth: None,
            },
            secrets: vec![],
        })
        .unwrap();
    let token = h.pair("claude-code").await;
    let auth = format!("Bearer {token}");

    let (status, _, body) = uds_request_raw(
        &h.socket,
        "POST",
        "/v1/http",
        &[("authorization", &auth)],
        Some(json!({
            "connection": "interactive",
            "method": "POST",
            "path": "/needs-input",
            "headers": {"content-type": "application/json"},
            "stream": true,
            "body": {
                "jsonrpc": "2.0",
                "id": 7,
                "method": "tools/call",
                "params": {"name": "lookup", "arguments": {}}
            }
        })),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let frames = sse_frames(&body);
    let end = frames
        .iter()
        .find(|(event, _)| event == "end")
        .expect("the stream ends");
    let permit = end.1["elicitation_tokens"]["account"]
        .as_str()
        .unwrap_or_else(|| panic!("the end frame carries the minted permit: {}", end.1));

    // The permit works exactly as the buffered plane's does.
    let (status, answer) = uds_request(
        &h.socket,
        "POST",
        "/v1/elicit",
        &[("authorization", &auth)],
        Some(json!({
            "connection": "interactive",
            "correlation_token": permit,
        })),
    )
    .await;
    assert_eq!(status, 200, "{answer}");
    assert_eq!(answer["action"], "cancel");

    // The relayed body itself is not repeated on the end frame: it already
    // crossed as chunks, and sending it twice would double every response.
    assert!(end.1.get("body").is_none(), "{}", end.1);
    let relayed: Value = serde_json::from_slice(&sse_body_bytes(&frames)).unwrap();
    assert_eq!(relayed["result"]["resultType"], "input_required");
}
