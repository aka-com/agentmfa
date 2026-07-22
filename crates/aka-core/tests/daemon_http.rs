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
    ConfirmationMethod, ConnectionConfig, ConnectionKind, PgSslMode, SecretMeta,
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
                axum::Json(json!({
                    "method": parts.method.as_str(),
                    "uri": parts.uri.to_string(),
                    "headers": headers,
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
            "/unauthorized",
            get(|| async { (axum::http::StatusCode::UNAUTHORIZED, "nope") }),
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
                template: "Authorization: Bearer {{GITHUB_API_KEY}}".into(),

                mcp_path: None,
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
            "/v1/ws/open",
            json!({"connection": "missing", "request_id": oversized.clone()}),
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
             "endpoint": "/v1/http", "wired": true},
            {"name": "prod-db", "type": "pg", "target": "app@db.internal.aka.com:5432/app_production",
             "endpoint": "/v1/pg/open", "wired": true},
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
                template: "?token={{url(STREAM_TOKEN)}}".into(),

                mcp_path: None,
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

    // A retry with the same request_id: replayed, still one execution.
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

    // Same request_id, different payload: a client bug, 409.
    let mut altered = payload.clone();
    altered["body"] = json!({"event_type": "delete-everything"});
    let (status, body) = uds_request(
        &h.socket,
        "POST",
        "/v1/http",
        &[("authorization", &auth)],
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
async fn mutating_request_id_is_scoped_to_connection() {
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
                template: "Authorization: Bearer {{GITHUB_API_KEY}}".into(),

                mcp_path: None,
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

    // The same request_id against a different connection is a mismatch,
    // never a silent replay of the other connection's outcome.
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
    assert_eq!(status, 409);
    assert_eq!(body["reason"], "request_id_mismatch");
    assert_eq!(up.hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn per_token_rate_limit_bites() {
    let config = BrokerConfig {
        per_token_per_min: 2,
        ..BrokerConfig::default()
    };
    let mut h = harness(config).await;
    let up = upstream().await;
    api_connection(&h, "github", up.port);
    let token = h.pair("claude-code").await;
    let auth = format!("Bearer {token}");

    // Two listings pass, the third 429s.
    for _ in 0..2 {
        let (status, _) = uds_request(
            &h.socket,
            "GET",
            "/v1/connections",
            &[("authorization", &auth)],
            None,
        )
        .await;
        assert_eq!(status, 200);
    }
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
            ("x-multitool-client", "claude-code"),
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
        per_token_per_min: 1,
        ..BrokerConfig::default()
    };
    let mut h = harness(config).await;
    let up = upstream().await;
    api_connection(&h, "github", up.port);
    let token = h.pair("claude-code").await;
    let auth = format!("Bearer {token}");

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

    // A brokered call the upstream rejects (401) is a credential problem.
    let (status, _) = uds_request(
        &h.socket,
        "POST",
        "/v1/http",
        &[("authorization", &auth)],
        Some(json!({ "connection": "github", "method": "GET", "path": "/unauthorized" })),
    )
    .await;
    assert_eq!(status, 200, "the broker relays the upstream response");
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
                template: "Authorization: Bearer {{MCP_TOKEN}}".into(),
                mcp_path: Some("/echo".into()),
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
            ("x-multitool-client", "claude-code"),
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
            ("x-multitool-client", "claude-code"),
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
            ("x-multitool-client", "claude-code"),
        ],
        Some(json!({ "service": "" })),
    )
    .await;
    assert_eq!(status, 400);
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
            ("x-multitool-client", "claude-code"),
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
/// endpoint). Returns (status, parsed-json-or-string body).
async fn loopback_request(
    port: u16,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&str>,
) -> (u16, Value) {
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
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes)
            .unwrap_or(Value::String(String::from_utf8_lossy(&bytes).into_owned()))
    };
    (status, value)
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
    let (status, body) = loopback_request(
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
async fn http_direct_endpoint_rejects_missing_or_wrong_secret() {
    let mut h = harness(BrokerConfig::default()).await;
    let up = upstream().await;
    api_connection(&h, "github", up.port);
    h.pair("claude-code").await;
    let (_info, port) = issue_http_endpoint(&h).await;

    // No secret.
    let (status, body) = loopback_request(port, "GET", "/echo", &[], None).await;
    assert_eq!(status, 401);
    assert_eq!(body["reason"], "missing_secret");

    // Wrong secret.
    let (status, body) = loopback_request(
        port,
        "GET",
        "/echo",
        &[("authorization", "Bearer end_bogus0000")],
        None,
    )
    .await;
    assert_eq!(status, 401);
    assert_eq!(body["reason"], "invalid_secret");
    // The upstream was never dialed on a refused request.
    assert_eq!(up.hits.load(Ordering::SeqCst), 0);
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
    let (status, _) =
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
