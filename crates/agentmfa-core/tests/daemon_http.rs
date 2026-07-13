//! End-to-end control-plane tests: a real daemon on a real Unix socket, a
//! real upstream HTTP server, and a scripted "user" deciding approvals.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use agentmfa_core::approvals::ApprovalRequest;
use agentmfa_core::audit::AuditKind;
use agentmfa_core::broker::{Broker, UiDecision};
use agentmfa_core::config::BrokerConfig;
use agentmfa_core::daemon;
use agentmfa_core::error::CoreError;
use agentmfa_core::events::BrokerEvents;
use agentmfa_core::paths::Paths;
use agentmfa_core::store::ConnectionSpec;
use agentmfa_core::types::{
    ConfirmationMethod, ConnectionConfig, DecisionContext, DecisionSurface, PgSslMode, SecretMeta,
};
use agentmfa_core::vault::MemoryVault;
use agentmfa_core::wire::REQUEST_ID_MAX_BYTES;
use axum::routing::{any, get, post};
use axum::Router;
use http_body_util::BodyExt as _;
use serde_json::{json, Value};
use tokio::sync::mpsc;
use zeroize::Zeroizing;

/* ------------------------------ harness ---------------------------------- */

/// Captures prompts so tests can play the user.
struct TestEvents {
    prompts: mpsc::UnboundedSender<ApprovalRequest>,
    queue_len: Arc<Mutex<usize>>,
    access_changes: Arc<AtomicUsize>,
}

impl BrokerEvents for TestEvents {
    fn prompt_raised(&self, request: &ApprovalRequest) {
        let _ = self.prompts.send(request.clone());
    }
    fn queue_changed(&self, queue: &[ApprovalRequest]) {
        *self.queue_len.lock().unwrap() = queue.len();
    }
    fn rules_changed(&self) {
        self.access_changes.fetch_add(1, Ordering::SeqCst);
    }
    fn confirm_secret_read(&self, _secret: &SecretMeta) -> bool {
        true
    }
    fn confirm_decision(
        &self,
        _request: &ApprovalRequest,
        _decision: UiDecision,
    ) -> Option<ConfirmationMethod> {
        Some(ConfirmationMethod::Waived)
    }
    fn confirm_action(&self, _description: &str) -> Option<ConfirmationMethod> {
        Some(ConfirmationMethod::Waived)
    }
}

/// The scripted user's decision attribution.
fn ctx() -> DecisionContext {
    DecisionContext::local(DecisionSurface::Harness)
}

struct Harness {
    broker: Arc<Broker>,
    _daemon: daemon::DaemonHandle,
    socket: std::path::PathBuf,
    prompts: mpsc::UnboundedReceiver<ApprovalRequest>,
    queue_len: Arc<Mutex<usize>>,
    access_changes: Arc<AtomicUsize>,
    _dir: tempfile::TempDir,
}

async fn harness(mut config: BrokerConfig) -> Harness {
    config.version = "test".into();
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::under(dir.path());
    let (tx, rx) = mpsc::unbounded_channel();
    let queue_len = Arc::new(Mutex::new(0));
    let access_changes = Arc::new(AtomicUsize::new(0));
    let events = Arc::new(TestEvents {
        prompts: tx,
        queue_len: queue_len.clone(),
        access_changes: access_changes.clone(),
    });
    let broker = Broker::new(paths, Arc::new(MemoryVault::new()), config, events)
        .await
        .unwrap();
    let handle = daemon::serve(broker.clone()).await.unwrap();
    let socket = handle.socket_path.clone();
    Harness {
        broker,
        _daemon: handle,
        socket,
        prompts: rx,
        queue_len,
        access_changes,
        _dir: dir,
    }
}

impl Harness {
    /// Wait for the next prompt and decide it.
    async fn decide_next(&mut self, decision: UiDecision) -> ApprovalRequest {
        let request = tokio::time::timeout(Duration::from_secs(5), self.prompts.recv())
            .await
            .expect("timed out waiting for a prompt")
            .expect("events channel closed");
        self.broker.decide(&request.id, decision, &ctx()).unwrap();
        request
    }

    async fn pair(&mut self, name: &str) -> String {
        let socket = self.socket.clone();
        let name_owned = name.to_string();
        let call = tokio::spawn(async move {
            uds_request(
                &socket,
                "POST",
                "/v1/pair",
                &[],
                Some(json!({ "agent_name": name_owned })),
            )
            .await
        });
        self.decide_next(UiDecision::AllowOnce).await;
        let (status, body) = call.await.unwrap();
        assert_eq!(status, 200, "pair failed: {body}");
        body["token"].as_str().unwrap().to_string()
    }
}

// A standing rule's scope derives from the prompted request (mutating →
// full, otherwise read), and the callers here rely on the rule matching
// later POSTs — so the rule must be saved from a mutating request. /echo
// keeps the /dispatch hit counter untouched, and omitting request_id keeps
// idempotency retention out of play under the zero-capacity configs.
async fn save_always_allow_rule(harness: &mut Harness, authorization: &str) {
    let socket = harness.socket.clone();
    let authorization = authorization.to_string();
    let call = tokio::spawn(async move {
        uds_request(
            &socket,
            "POST",
            "/v1/http",
            &[("authorization", &authorization)],
            Some(json!({
                "connection": "github",
                "method": "POST",
                "path": "/echo",
            })),
        )
        .await
    });
    harness.decide_next(UiDecision::AlwaysAllow).await;
    assert_eq!(call.await.unwrap().0, 200);
}

fn auto_allowed_audit_count(harness: &Harness) -> usize {
    harness
        .broker
        .audit
        .recent(100)
        .into_iter()
        .filter(|entry| entry.kind == AuditKind::AutoAllowed)
        .count()
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
    assert_eq!(manifest["approval_timeout_seconds"], 900);
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
    let (tx, _rx) = mpsc::unbounded_channel();
    let events = Arc::new(TestEvents {
        prompts: tx,
        queue_len: Arc::new(Mutex::new(0)),
        access_changes: Arc::new(AtomicUsize::new(0)),
    });
    let broker = Broker::new(
        paths,
        Arc::new(MemoryVault::new()),
        BrokerConfig::default(),
        events,
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
    assert!(token.starts_with("amfa_"));

    // The paired agent shows up for the UI band.
    let agents = h.broker.paired_agents();
    assert_eq!(agents.len(), 1);
    assert_eq!(agents[0].name, "claude-code");

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
        &[("authorization", "Bearer amfa_bogus")],
        None,
    )
    .await;
    assert_eq!(status, 401);
    assert_eq!(body["reason"], "invalid_token");
    assert!(body["detail"]
        .as_str()
        .unwrap()
        .contains("reached the broker"));

    // Revocation invalidates immediately.
    let client = h.broker.pairing.get("claude-code").unwrap();
    assert!(h.broker.ui_revoke_agent(&client.id).unwrap());
    let (status, _) = uds_request(
        &h.socket,
        "GET",
        "/v1/connections",
        &[("authorization", &auth)],
        None,
    )
    .await;
    assert_eq!(status, 401);
}

#[tokio::test]
async fn denied_pairing_returns_403_and_arms_cooldown() {
    let mut h = harness(BrokerConfig::default()).await;
    let socket = h.socket.clone();
    let call = tokio::spawn(async move {
        uds_request(
            &socket,
            "POST",
            "/v1/pair",
            &[],
            Some(json!({"agent_name": "evil-tool"})),
        )
        .await
    });
    h.decide_next(UiDecision::Deny).await;
    let (status, body) = call.await.unwrap();
    assert_eq!(status, 403);
    assert_eq!(body["reason"], "denied_by_user");
    // Cooldown after a user denial: the refusal names its cause (the
    // human said no, distinct from a full attempt window) and how long to
    // wait.
    let (status, body) = uds_request(
        &h.socket,
        "POST",
        "/v1/pair",
        &[],
        Some(json!({"agent_name": "evil-tool"})),
    )
    .await;
    assert_eq!(status, 429);
    assert_eq!(body["reason"], "pairing_denied_cooldown");
    let wait = body["retry_after_seconds"].as_u64().unwrap();
    assert!((1..=30).contains(&wait), "unexpected wait {wait}");
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
async fn request_ids_are_bounded_before_prompting_or_connection_lookup() {
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
    assert!(h.prompts.try_recv().is_err());

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
             "endpoint": "/v1/http",
             "approval": "will_prompt", "access_session": null},
            {"name": "prod-db", "type": "pg", "target": "app@db.internal.aka.com:5432/app_production",
             "endpoint": "/v1/pg/open",
             "approval": "will_prompt", "access_session": null},
        ])
    );
    // No secret names, ids, or templates anywhere in the response.
    let raw = list.to_string();
    assert!(!raw.contains("GITHUB_API_KEY"));
    assert!(!raw.contains("Bearer {{"));
}

#[tokio::test]
async fn http_get_prompts_executes_and_injects_credential() {
    let mut h = harness(BrokerConfig::default()).await;
    let up = upstream().await;
    api_connection(&h, "github", up.port);
    let token = h.pair("claude-code").await;
    let auth = format!("Bearer {token}");

    let socket = h.socket.clone();
    let auth_clone = auth.clone();
    let call = tokio::spawn(async move {
        uds_request(
            &socket,
            "POST",
            "/v1/http",
            &[("authorization", &auth_clone)],
            Some(json!({
                "connection": "github",
                "method": "GET",
                "path": "/echo?x=1",
                "headers": {"Accept": "application/vnd.github+json"},
            })),
        )
        .await
    });
    let prompt = h.decide_next(UiDecision::AllowOnce).await;
    assert_eq!(prompt.agent, "claude-code");
    assert_eq!(prompt.connection.as_ref().unwrap().name, "github");
    assert!(prompt.action.contains("GET"));
    let http_view = prompt.http.as_ref().unwrap();
    assert!(!http_view.mutating);

    let (status, envelope) = call.await.unwrap();
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
async fn access_session_defaults_to_read_then_upgrades_to_full_and_expires() {
    let config = BrokerConfig {
        access_grant_ttl: Duration::from_secs(3),
        ..BrokerConfig::default()
    };
    let mut h = harness(config).await;
    let up = upstream().await;
    api_connection(&h, "github", up.port);
    let token = h.pair("claude-code").await;
    let auth = format!("Bearer {token}");

    // The first read creates the default read access session.
    let socket = h.socket.clone();
    let auth_clone = auth.clone();
    let first = tokio::spawn(async move {
        uds_request(
            &socket,
            "POST",
            "/v1/http",
            &[("authorization", &auth_clone)],
            Some(json!({"connection": "github", "method": "GET", "path": "/user/repos"})),
        )
        .await
    });
    h.decide_next(UiDecision::AllowSession).await;
    assert_eq!(first.await.unwrap().0, 200);

    // Another read is covered without a prompt.
    let (status, _) = tokio::time::timeout(
        Duration::from_secs(2),
        uds_request(
            &h.socket,
            "POST",
            "/v1/http",
            &[("authorization", &auth)],
            Some(json!({"connection": "github", "method": "GET", "path": "/user/repos"})),
        ),
    )
    .await
    .expect("read access session request stalled");
    assert_eq!(status, 200);
    assert!(h.prompts.try_recv().is_err());

    // A mutation is not covered by a read grant. Approving it upgrades the
    // connection to full access for the fixed session window.
    let socket = h.socket.clone();
    let auth_clone = auth.clone();
    let mutation = tokio::spawn(async move {
        uds_request(
            &socket,
            "POST",
            "/v1/http",
            &[("authorization", &auth_clone)],
            Some(json!({
                "connection": "github", "method": "POST", "path": "/dispatch",
                "request_id": "grant-upgrade-1"
            })),
        )
        .await
    });
    let upgrade = h.decide_next(UiDecision::AllowSession).await;
    assert!(upgrade.http.unwrap().mutating);
    assert_eq!(mutation.await.unwrap().0, 200);

    let (status, _) = tokio::time::timeout(
        Duration::from_secs(2),
        uds_request(
            &h.socket,
            "POST",
            "/v1/http",
            &[("authorization", &auth)],
            Some(json!({
                "connection": "github", "method": "POST", "path": "/dispatch",
                "request_id": "grant-upgrade-2"
            })),
        ),
    )
    .await
    .expect("full access session request stalled");
    assert_eq!(status, 200);
    assert!(h.prompts.try_recv().is_err());

    // Expiry is fixed, not sliding. It is removed, audited distinctly, and
    // tells access views to refresh at the deadline.
    let access_changes_before_expiry = h.access_changes.load(Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(3100)).await;
    let connection = h.broker.store.connection_by_name("github").unwrap();
    assert!(h.broker.grants_for_connection(&connection).is_empty());
    assert!(h.access_changes.load(Ordering::SeqCst) > access_changes_before_expiry);
    let expiry_entries: Vec<_> = h
        .broker
        .audit
        .recent(20)
        .into_iter()
        .filter(|entry| entry.kind == AuditKind::GrantExpired)
        .collect();
    assert_eq!(expiry_entries.len(), 1);
    assert_eq!(
        expiry_entries[0].outcome.as_deref(),
        Some("access_session_expired")
    );
    assert_eq!(expiry_entries[0].fields["reason"], "expired");
    assert_eq!(expiry_entries[0].fields["scope"], "full");
    assert!(expiry_entries[0].fields.contains_key("created_at"));
    assert!(expiry_entries[0].fields.contains_key("expires_at"));

    // The next request prompts again, and observing the expired state does
    // not append a duplicate expiry entry.
    let socket = h.socket.clone();
    let auth_clone = auth.clone();
    let after_expiry = tokio::spawn(async move {
        uds_request(
            &socket,
            "POST",
            "/v1/http",
            &[("authorization", &auth_clone)],
            Some(json!({"connection": "github", "method": "GET", "path": "/user/repos"})),
        )
        .await
    });
    h.decide_next(UiDecision::Deny).await;
    assert_eq!(after_expiry.await.unwrap().0, 403);
    assert_eq!(
        h.broker
            .audit
            .recent(20)
            .into_iter()
            .filter(|entry| entry.kind == AuditKind::GrantExpired)
            .count(),
        1
    );
}

#[tokio::test]
async fn access_session_absorbs_already_queued_matching_prompts() {
    let mut h = harness(BrokerConfig::default()).await;
    let up = upstream().await;
    api_connection(&h, "github", up.port);
    let token = h.pair("claude-code").await;
    let auth = format!("Bearer {token}");

    let mut calls = Vec::new();
    for _ in 0..2 {
        let socket = h.socket.clone();
        let auth = auth.clone();
        calls.push(tokio::spawn(async move {
            uds_request(
                &socket,
                "POST",
                "/v1/http",
                &[("authorization", &auth)],
                Some(json!({
                    "connection": "github",
                    "method": "GET",
                    "path": "/user/repos"
                })),
            )
            .await
        }));
    }

    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if *h.queue_len.lock().unwrap() == 2 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("both requests should be queued before approval");

    h.decide_next(UiDecision::AllowSession).await;
    for call in calls {
        assert_eq!(call.await.unwrap().0, 200);
    }
    assert_eq!(*h.queue_len.lock().unwrap(), 0);
    assert_eq!(h.broker.approvals_queue().len(), 0);
    let connection = h.broker.store.connection_by_name("github").unwrap();
    assert_eq!(h.broker.grants_for_connection(&connection).len(), 1);
}

#[tokio::test]
async fn full_access_session_covers_repeated_session_opens_until_revoked() {
    let mut h = harness(BrokerConfig::default()).await;
    let password = h
        .broker
        .store
        .add_secret("PG_PASSWORD", Zeroizing::new("test-password".into()))
        .unwrap();
    h.broker
        .store
        .add_connection(ConnectionSpec {
            name: "prod-db".into(),
            config: ConnectionConfig::Pg {
                host: "db.invalid".into(),
                port: 5432,
                dbname: "app".into(),
                user: "app".into(),
                sslmode: PgSslMode::Require,
                trusted_ca_bundle_path: None,
            },
            secrets: vec![password.id],
        })
        .unwrap();
    let token = h.pair("claude-code").await;
    let auth = format!("Bearer {token}");

    let socket = h.socket.clone();
    let auth_clone = auth.clone();
    let first = tokio::spawn(async move {
        uds_request(
            &socket,
            "POST",
            "/v1/pg/open",
            &[("authorization", &auth_clone)],
            Some(json!({"connection": "prod-db", "request_id": "pg-grant-1"})),
        )
        .await
    });
    h.decide_next(UiDecision::AllowSession).await;
    assert_eq!(first.await.unwrap().0, 200);

    let (status, _) = tokio::time::timeout(
        Duration::from_secs(2),
        uds_request(
            &h.socket,
            "POST",
            "/v1/pg/open",
            &[("authorization", &auth)],
            Some(json!({"connection": "prod-db", "request_id": "pg-grant-2"})),
        ),
    )
    .await
    .expect("repeated session open stalled");
    assert_eq!(status, 200);
    assert!(h.prompts.try_recv().is_err());

    let connection = h.broker.store.connection_by_name("prod-db").unwrap();
    let grant = h.broker.grants_for_connection(&connection).remove(0);
    assert!(h.broker.ui_remove_grant(&grant.id).unwrap());

    let socket = h.socket.clone();
    let auth_clone = auth.clone();
    let after_revoke = tokio::spawn(async move {
        uds_request(
            &socket,
            "POST",
            "/v1/pg/open",
            &[("authorization", &auth_clone)],
            Some(json!({"connection": "prod-db", "request_id": "pg-grant-3"})),
        )
        .await
    });
    h.decide_next(UiDecision::Deny).await;
    assert_eq!(after_revoke.await.unwrap().0, 403);
}

#[tokio::test]
async fn http_deny_returns_403_reason() {
    let mut h = harness(BrokerConfig::default()).await;
    let up = upstream().await;
    api_connection(&h, "github", up.port);
    let token = h.pair("claude-code").await;
    let auth = format!("Bearer {token}");
    let socket = h.socket.clone();
    let call = tokio::spawn(async move {
        uds_request(
            &socket,
            "POST",
            "/v1/http",
            &[("authorization", &auth)],
            Some(json!({"connection": "github", "method": "GET", "path": "/user/repos"})),
        )
        .await
    });
    h.decide_next(UiDecision::Deny).await;
    let (status, body) = call.await.unwrap();
    assert_eq!(status, 403);
    assert_eq!(body["reason"], "denied_by_user");
    assert_eq!(up.hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn always_allow_saves_rule_then_skips_prompts() {
    let mut h = harness(BrokerConfig::default()).await;
    let up = upstream().await;
    api_connection(&h, "github", up.port);
    let token = h.pair("claude-code").await;
    let auth = format!("Bearer {token}");

    let socket = h.socket.clone();
    let auth_clone = auth.clone();
    let call = tokio::spawn(async move {
        uds_request(
            &socket,
            "POST",
            "/v1/http",
            &[("authorization", &auth_clone)],
            Some(json!({"connection": "github", "method": "GET", "path": "/user/repos"})),
        )
        .await
    });
    h.decide_next(UiDecision::AlwaysAllow).await;
    let (status, _) = call.await.unwrap();
    assert_eq!(status, 200);
    assert_eq!(h.broker.rules().len(), 1);

    // The connections listing now tells the agent this is promptless.
    let (status, list) = uds_request(
        &h.socket,
        "GET",
        "/v1/connections",
        &[("authorization", &auth)],
        None,
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(list[0]["approval"], "read_auto_allowed");

    // Second request: no prompt, auto-approved by the standing rule.
    let (status, envelope) = uds_request(
        &h.socket,
        "POST",
        "/v1/http",
        &[("authorization", &auth)],
        Some(json!({"connection": "github", "method": "GET", "path": "/user/repos"})),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(envelope["status"], 200);
    assert!(
        h.prompts.try_recv().is_err(),
        "auto-allowed request must not prompt"
    );

    // The standing read permission does not silently expand to mutations.
    let socket = h.socket.clone();
    let auth_clone = auth.clone();
    let mutating = tokio::spawn(async move {
        uds_request(
            &socket,
            "POST",
            "/v1/http",
            &[("authorization", &auth_clone)],
            Some(json!({"connection": "github", "method": "POST", "path": "/repos"})),
        )
        .await
    });
    h.decide_next(UiDecision::Deny).await;
    assert_eq!(mutating.await.unwrap().0, 403);

    // Removing the rule restores prompting.
    let rule_id = h.broker.rules()[0].id;
    assert!(h.broker.ui_remove_rule(&rule_id).unwrap());
    let socket = h.socket.clone();
    let auth_clone = auth.clone();
    let call = tokio::spawn(async move {
        uds_request(
            &socket,
            "POST",
            "/v1/http",
            &[("authorization", &auth_clone)],
            Some(json!({"connection": "github", "method": "GET", "path": "/user/repos"})),
        )
        .await
    });
    h.decide_next(UiDecision::Deny).await;
    let (status, _) = call.await.unwrap();
    assert_eq!(status, 403);
}

#[tokio::test]
async fn always_allow_refuses_stale_connection_target() {
    let mut h = harness(BrokerConfig::default()).await;
    let up = upstream().await;
    api_connection(&h, "github", up.port);
    let conn = h.broker.store.connection_by_name("github").unwrap();
    let token = h.pair("claude-code").await;
    let auth = format!("Bearer {token}");

    let socket = h.socket.clone();
    let call = tokio::spawn(async move {
        uds_request(
            &socket,
            "POST",
            "/v1/http",
            &[("authorization", &auth)],
            Some(json!({"connection": "github", "method": "GET", "path": "/user/repos"})),
        )
        .await
    });
    let prompt = tokio::time::timeout(Duration::from_secs(5), h.prompts.recv())
        .await
        .unwrap()
        .unwrap();

    h.broker
        .ui_update_connection(
            &conn.id,
            ConnectionSpec {
                name: "github".into(),
                config: ConnectionConfig::Api {
                    host: "api.github.com".into(),
                    scheme: "https".into(),
                    port: None,
                    template: "Authorization: Bearer {{GITHUB_API_KEY}}".into(),
                },
                secrets: vec![],
            },
        )
        .unwrap();

    let err = h
        .broker
        .decide(&prompt.id, UiDecision::AlwaysAllow, &ctx())
        .unwrap_err();
    assert!(matches!(err, CoreError::ApprovalConnectionChanged));
    assert_eq!(h.broker.rules().len(), 0);
    assert_eq!(h.broker.approvals_queue().len(), 1);

    h.broker
        .decide(&prompt.id, UiDecision::AllowOnce, &ctx())
        .unwrap();
    let (status, _) = call.await.unwrap();
    assert_eq!(status, 200);
    assert_eq!(h.broker.rules().len(), 0);
}

#[tokio::test]
async fn validation_rejects_before_any_prompt() {
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
    // None of those produced a prompt.
    assert!(h.prompts.try_recv().is_err());
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
    let socket = h.socket.clone();
    let auth_clone = auth.clone();
    let call = tokio::spawn(async move {
        uds_request(
            &socket,
            "POST",
            "/v1/http",
            &[("authorization", &auth_clone)],
            Some(json!({"connection": "github", "method": "GET", "path": "/redirect-same"})),
        )
        .await
    });
    h.decide_next(UiDecision::AllowOnce).await;
    let (status, envelope) = call.await.unwrap();
    assert_eq!(status, 200);
    assert_eq!(envelope["status"], 200, "redirect should be followed");
    let echoed: Value = serde_json::from_str(envelope["body"].as_str().unwrap()).unwrap();
    assert_eq!(
        echoed["headers"]["authorization"], "[REDACTED]",
        "credential is re-rendered onto the followed hop but redacted from the relay"
    );
    assert!(!envelope.to_string().contains("ghp_test_secret_value"));

    // Cross-host: returned to the agent as the raw 3xx.
    let socket = h.socket.clone();
    let auth_clone = auth.clone();
    let call = tokio::spawn(async move {
        uds_request(
            &socket,
            "POST",
            "/v1/http",
            &[("authorization", &auth_clone)],
            Some(json!({"connection": "github", "method": "GET", "path": "/redirect-cross"})),
        )
        .await
    });
    h.decide_next(UiDecision::AllowOnce).await;
    let (status, envelope) = call.await.unwrap();
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
            },
            secrets: vec![],
        })
        .unwrap();
    let token = h.pair("claude-code").await;
    let auth = format!("Bearer {token}");

    let socket = h.socket.clone();
    let auth_clone = auth.clone();
    let call = tokio::spawn(async move {
        uds_request(
            &socket,
            "POST",
            "/v1/http",
            &[("authorization", &auth_clone)],
            Some(json!({"connection": "feed", "method": "GET", "path": "/x"})),
        )
        .await
    });
    h.decide_next(UiDecision::AllowOnce).await;
    let (status, body) = call.await.unwrap();
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

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn blocking_reauth_prompt_does_not_stall_the_daemon() {
    use std::io::{Read as _, Write as _};
    use std::sync::Condvar;

    // Events whose re-auth-on-read confirmation blocks until released,
    // signalling when it has started. Credential injection reads a secret, so
    // this fires during the approved HTTP request's execution. On a
    // single-worker runtime, running that blocking confirmation on a runtime
    // worker would wedge the whole daemon; the broker runs it on the blocking
    // pool instead, so other requests keep flowing.
    struct GateEvents {
        prompts: mpsc::UnboundedSender<ApprovalRequest>,
        blocked: Arc<(Mutex<bool>, Condvar)>,
        release: Arc<(Mutex<bool>, Condvar)>,
    }
    impl BrokerEvents for GateEvents {
        fn prompt_raised(&self, request: &ApprovalRequest) {
            let _ = self.prompts.send(request.clone());
        }
        fn confirm_secret_read(&self, _secret: &SecretMeta) -> bool {
            {
                let (m, cv) = &*self.blocked;
                *m.lock().unwrap() = true;
                cv.notify_all();
            }
            let (m, cv) = &*self.release;
            let mut released = m.lock().unwrap();
            while !*released {
                released = cv.wait(released).unwrap();
            }
            true
        }
        fn confirm_decision(
            &self,
            _request: &ApprovalRequest,
            _decision: UiDecision,
        ) -> Option<ConfirmationMethod> {
            Some(ConfirmationMethod::Waived)
        }
        fn confirm_action(&self, _description: &str) -> Option<ConfirmationMethod> {
            Some(ConfirmationMethod::Waived)
        }
    }

    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::under(dir.path());
    let (tx, mut prompts) = mpsc::unbounded_channel();
    let blocked = Arc::new((Mutex::new(false), Condvar::new()));
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    let broker = Broker::new(
        paths,
        Arc::new(MemoryVault::new()),
        BrokerConfig::default(),
        Arc::new(GateEvents {
            prompts: tx,
            blocked: blocked.clone(),
            release: release.clone(),
        }),
    )
    .await
    .unwrap();
    let up = upstream().await;
    broker
        .store
        .add_secret(
            "GITHUB_API_KEY",
            Zeroizing::new("ghp_test_secret_value".into()),
        )
        .unwrap();
    broker
        .store
        .add_connection(ConnectionSpec {
            name: "github".into(),
            config: ConnectionConfig::Api {
                host: "127.0.0.1".into(),
                scheme: "http".into(),
                port: Some(up.port),
                template: "Authorization: Bearer {{GITHUB_API_KEY}}".into(),
            },
            secrets: vec![],
        })
        .unwrap();
    let daemon = daemon::serve(broker.clone()).await.unwrap();
    let socket = daemon.socket_path.clone();

    // Pair (no secret read, so the gate is not touched).
    let token = {
        let s = socket.clone();
        let call = tokio::spawn(async move {
            uds_request(
                &s,
                "POST",
                "/v1/pair",
                &[],
                Some(json!({"agent_name": "claude-code"})),
            )
            .await
        });
        let prompt = tokio::time::timeout(Duration::from_secs(5), prompts.recv())
            .await
            .unwrap()
            .unwrap();
        broker
            .decide(&prompt.id, UiDecision::AllowOnce, &ctx())
            .unwrap();
        call.await.unwrap().1["token"].as_str().unwrap().to_string()
    };

    // Fire an HTTP GET; approving it runs the executor, which reads the
    // credential and blocks in the gated confirmation.
    let s = socket.clone();
    let auth = format!("Bearer {token}");
    let call = tokio::spawn(async move {
        uds_request(
            &s,
            "POST",
            "/v1/http",
            &[("authorization", &auth)],
            Some(json!({"connection": "github", "method": "GET", "path": "/user/repos"})),
        )
        .await
    });
    let prompt = tokio::time::timeout(Duration::from_secs(5), prompts.recv())
        .await
        .unwrap()
        .unwrap();
    broker
        .decide(&prompt.id, UiDecision::AllowOnce, &ctx())
        .unwrap();

    // Observer on a plain OS thread (immune to a wedged runtime): once the
    // confirmation is blocking, an unrelated GET /v1/connections must still
    // get a response. If the read blocked the one worker, this times out.
    let obs_socket = socket.clone();
    let obs_auth = format!("Bearer {token}");
    let blocked2 = blocked.clone();
    let release2 = release.clone();
    let observer = std::thread::spawn(move || -> bool {
        {
            let (m, cv) = &*blocked2;
            let mut b = m.lock().unwrap();
            while !*b {
                b = cv.wait(b).unwrap();
            }
        }
        let served = (|| -> std::io::Result<bool> {
            let mut s = std::os::unix::net::UnixStream::connect(&obs_socket)?;
            s.set_read_timeout(Some(Duration::from_secs(2)))?;
            let req = format!(
                "GET /v1/connections HTTP/1.1\r\nHost: localhost\r\n\
                 Authorization: {obs_auth}\r\nConnection: close\r\n\r\n"
            );
            s.write_all(req.as_bytes())?;
            let mut buf = Vec::new();
            let _ = s.read_to_end(&mut buf); // times out if the daemon is wedged
            Ok(String::from_utf8_lossy(&buf).contains("200 OK"))
        })()
        .unwrap_or(false);
        {
            let (m, cv) = &*release2;
            *m.lock().unwrap() = true;
            cv.notify_all();
        }
        served
    });

    let (status, _) = tokio::time::timeout(Duration::from_secs(10), call)
        .await
        .expect("request should complete once the confirmation is released")
        .unwrap();
    assert_eq!(status, 200);
    assert!(
        observer.join().unwrap(),
        "daemon must keep serving requests while a re-auth confirmation blocks"
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

    // Two concurrent calls with the same request_id.
    let socket = h.socket.clone();
    let (a1, p1) = (auth.clone(), payload.clone());
    let call1 = tokio::spawn(async move {
        uds_request(
            &socket,
            "POST",
            "/v1/http",
            &[("authorization", &a1)],
            Some(p1),
        )
        .await
    });
    let socket = h.socket.clone();
    let (a2, p2) = (auth.clone(), payload.clone());
    // Give the first call time to park so the second joins it.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let call2 = tokio::spawn(async move {
        uds_request(
            &socket,
            "POST",
            "/v1/http",
            &[("authorization", &a2)],
            Some(p2),
        )
        .await
    });

    // Exactly one prompt for the pair of calls.
    let prompt = tokio::time::timeout(Duration::from_secs(5), h.prompts.recv())
        .await
        .unwrap()
        .unwrap();
    let view = prompt.http.as_ref().unwrap();
    assert!(view.mutating);
    assert!(view.body_preview.as_ref().unwrap().contains("deploy"));
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        h.prompts.try_recv().is_err(),
        "retry must join, not re-prompt"
    );
    assert_eq!(*h.queue_len.lock().unwrap(), 1);

    h.broker
        .decide(&prompt.id, UiDecision::AllowOnce, &ctx())
        .unwrap();
    let ((s1, b1), (s2, b2)) = (call1.await.unwrap(), call2.await.unwrap());
    assert_eq!((s1, s2), (200, 200));
    assert_eq!(b1["status"], 204);
    assert_eq!(b2["status"], 204);
    assert_eq!(
        up.hits.load(Ordering::SeqCst),
        1,
        "exactly one upstream execution"
    );

    // Late retry with the same request_id: replayed, still one execution.
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
}

#[tokio::test]
async fn idempotency_capacity_fails_before_prompt_or_upstream_execution() {
    let config = BrokerConfig {
        outcome_retention_max_entries: 0,
        ..BrokerConfig::default()
    };
    let mut h = harness(config).await;
    let up = upstream().await;
    api_connection(&h, "github", up.port);
    let token = h.pair("claude-code").await;
    let auth = format!("Bearer {token}");
    save_always_allow_rule(&mut h, &auth).await;
    let auto_allowed_before = auto_allowed_audit_count(&h);

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
    assert!(h.prompts.try_recv().is_err(), "no prompt should be raised");
    assert_eq!(up.hits.load(Ordering::SeqCst), 0);
    assert_eq!(
        auto_allowed_audit_count(&h),
        auto_allowed_before,
        "a rejected request must not be audited as executing"
    );
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
    save_always_allow_rule(&mut h, &auth).await;
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
    let auto_allowed_after_execution = auto_allowed_audit_count(&h);

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
    assert!(h.prompts.try_recv().is_err(), "retry must not re-prompt");
    assert_eq!(
        auto_allowed_audit_count(&h),
        auto_allowed_after_execution,
        "a tombstoned retry must not be audited as a new execution"
    );
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
            },
            secrets: vec![],
        })
        .unwrap();
    let token = h.pair("claude-code").await;
    let auth = format!("Bearer {token}");

    let payload = json!({
        "connection": "github",
        "method": "POST",
        "path": "/dispatch",
        "request_id": "req_same_payload_different_connection",
        "body": {"event_type": "deploy"},
    });

    let socket = h.socket.clone();
    let auth_clone = auth.clone();
    let call = tokio::spawn(async move {
        uds_request(
            &socket,
            "POST",
            "/v1/http",
            &[("authorization", &auth_clone)],
            Some(payload),
        )
        .await
    });
    let prompt = tokio::time::timeout(Duration::from_secs(5), h.prompts.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(prompt.connection.as_ref().unwrap().name, "github");

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
    assert!(
        h.prompts.try_recv().is_err(),
        "cross-connection request_id reuse must not add a second prompt"
    );

    h.broker
        .decide(&prompt.id, UiDecision::AllowOnce, &ctx())
        .unwrap();
    let (status, body) = call.await.unwrap();
    assert_eq!(status, 200);
    assert_eq!(body["status"], 204);
    assert_eq!(up.hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn approval_timeout_auto_denies() {
    let config = BrokerConfig {
        approval_timeout: Duration::from_millis(300),
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
        Some(json!({"connection": "github", "method": "GET", "path": "/user/repos"})),
    )
    .await;
    assert_eq!(status, 403);
    assert_eq!(body["reason"], "approval_timeout");
    assert_eq!(*h.queue_len.lock().unwrap(), 0);
    let _ = h.prompts.try_recv();
}

#[tokio::test]
async fn disconnect_abandons_parked_request() {
    let mut h = harness(BrokerConfig::default()).await;
    let up = upstream().await;
    api_connection(&h, "github", up.port);
    let token = h.pair("claude-code").await;
    let auth = format!("Bearer {token}");

    // Open a raw connection, send the request, then slam the connection shut
    // before any decision.
    let socket = h.socket.clone();
    let call = tokio::spawn(async move {
        tokio::time::timeout(
            Duration::from_millis(400),
            uds_request(
                &socket,
                "POST",
                "/v1/http",
                &[("authorization", &auth)],
                Some(
                    json!({"connection": "github", "method": "POST", "path": "/dispatch",
                            "request_id": "req_abandon", "body": {"x": 1}}),
                ),
            ),
        )
        .await
    });
    let prompt = tokio::time::timeout(Duration::from_secs(5), h.prompts.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(*h.queue_len.lock().unwrap(), 1);
    // The client gives up (timeout aborts the request future / connection).
    let _ = call.await;
    // The prompt is withdrawn without execution.
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if *h.queue_len.lock().unwrap() == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("prompt should be withdrawn after disconnect");
    // Approving the withdrawn prompt does nothing.
    assert!(h
        .broker
        .decide(&prompt.id, UiDecision::AllowOnce, &ctx())
        .unwrap()
        .is_none());
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(up.hits.load(Ordering::SeqCst), 0, "never executed upstream");
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
    let socket = h.socket.clone();
    let auth_clone = auth.clone();
    let call = tokio::spawn(async move {
        uds_request(
            &socket,
            "POST",
            "/v1/http",
            &[("authorization", &auth_clone)],
            Some(json!({"connection": "github", "method": "GET", "path": "/binary"})),
        )
        .await
    });
    h.decide_next(UiDecision::AllowOnce).await;
    let (status, envelope) = call.await.unwrap();
    assert_eq!(status, 200);
    assert_eq!(envelope["body_encoding"], "base64");
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(envelope["body"].as_str().unwrap())
        .unwrap();
    assert_eq!(bytes, vec![0u8, 159, 146, 150, 255]);
}

#[tokio::test]
async fn pairing_inheritance_is_disclosed() {
    let mut h = harness(BrokerConfig::default()).await;
    let up = upstream().await;
    api_connection(&h, "github", up.port);
    let conn = h.broker.store.connection_by_name("github").unwrap();

    // The same verified client earned a standing rule before re-pairing.
    h.pair("claude-code").await;
    let client = h.broker.pairing.get("claude-code").unwrap();
    use agentmfa_core::policy::PolicyEngine as _;
    h.broker
        .policy
        .record_rule(
            client.id,
            "claude-code",
            conn.id,
            agentmfa_core::types::PermissionScope::Full,
        )
        .unwrap();

    let socket = h.socket.clone();
    let call = tokio::spawn(async move {
        uds_request(
            &socket,
            "POST",
            "/v1/pair",
            &[],
            Some(json!({"agent_name": "claude-code"})),
        )
        .await
    });
    let prompt = tokio::time::timeout(Duration::from_secs(5), h.prompts.recv())
        .await
        .unwrap()
        .unwrap();
    // The dialog data must disclose exactly what the new process inherits.
    assert_eq!(prompt.inherited.len(), 1);
    assert_eq!(prompt.inherited[0].name, "github");
    assert_eq!(
        prompt.inherited[0].target,
        format!("http://127.0.0.1:{}", up.port)
    );
    assert!(prompt.identity.is_some());
    h.broker
        .decide(&prompt.id, UiDecision::AllowOnce, &ctx())
        .unwrap();
    let (status, _) = call.await.unwrap();
    assert_eq!(status, 200);
}

#[tokio::test]
async fn pair_response_is_self_contained() {
    let mut h = harness(BrokerConfig::default()).await;
    let socket = h.socket.clone();
    let call = tokio::spawn(async move {
        uds_request(
            &socket,
            "POST",
            "/v1/pair",
            &[],
            Some(json!({"agent_name": "claude-code"})),
        )
        .await
    });
    h.decide_next(UiDecision::AllowOnce).await;
    let (status, body) = call.await.unwrap();
    assert_eq!(status, 200);
    assert!(body["token"].as_str().unwrap().starts_with("amfa_"));
    // The response echoes what was registered and pinned, so the agent can
    // log its enrollment without a follow-up /v1/whoami.
    assert_eq!(body["agent"], "claude-code");
    assert!(!body["identity"].as_str().unwrap().is_empty());
    // The storage guidance travels with the credential.
    assert_eq!(body["expires_after_days"], 30);
    assert_eq!(
        body["store_at"].as_str().unwrap(),
        format!("{}/claude-code", h.broker.paths.tokens_display())
    );
    // The advisory directory exists (ensure() created it owner-only), so
    // agents never need mkdir-and-chmod logic of their own.
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::metadata(h.broker.paths.tokens_dir()).unwrap();
    assert!(meta.is_dir());
    assert_eq!(meta.permissions().mode() & 0o777, 0o700);
}

#[tokio::test]
async fn whoami_probes_a_stored_token() {
    let mut h = harness(BrokerConfig::default()).await;
    let token = h.pair("claude-code").await;
    let auth = format!("Bearer {token}");
    let (status, body) = uds_request(
        &h.socket,
        "GET",
        "/v1/whoami",
        &[("authorization", &auth)],
        None,
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body["agent"], "claude-code");
    assert!(!body["identity"].as_str().unwrap().is_empty());
    assert!(body["expires_at"].as_str().is_some());
    // A garbage token is a plain 401, the signal to fall through to pairing.
    let (status, body) = uds_request(
        &h.socket,
        "GET",
        "/v1/whoami",
        &[("authorization", "Bearer amfa_bogus")],
        None,
    )
    .await;
    assert_eq!(status, 401);
    assert_eq!(body["reason"], "invalid_token");
}

#[tokio::test]
async fn superseded_token_gets_a_distinct_reason() {
    let mut h = harness(BrokerConfig::default()).await;
    let token1 = h.pair("claude-code").await;
    // A second instance re-pairs under the same name.
    let token2 = h.pair("claude-code").await;
    // The first instance's next call is told what happened and what to do,
    // not just "invalid_token" (whose remedy, re-pairing, would break the
    // second instance in turn).
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
        format!("{}/claude-code", h.broker.paths.tokens_display())
    );
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
async fn concurrent_same_name_pairings_coalesce() {
    let mut h = harness(BrokerConfig::default()).await;
    // Two instances of the same (identically-signed) agent race to pair.
    let socket = h.socket.clone();
    let call1 = tokio::spawn(async move {
        uds_request(
            &socket,
            "POST",
            "/v1/pair",
            &[],
            Some(json!({"agent_name": "claude-code"})),
        )
        .await
    });
    // Give the first call time to park so the second joins it.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let socket = h.socket.clone();
    let call2 = tokio::spawn(async move {
        uds_request(
            &socket,
            "POST",
            "/v1/pair",
            &[],
            Some(json!({"agent_name": "claude-code"})),
        )
        .await
    });

    // Exactly one prompt for the pair of calls.
    let prompt = tokio::time::timeout(Duration::from_secs(5), h.prompts.recv())
        .await
        .unwrap()
        .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        h.prompts.try_recv().is_err(),
        "the second pairing must join, not re-prompt"
    );
    assert_eq!(*h.queue_len.lock().unwrap(), 1);

    h.broker
        .decide(&prompt.id, UiDecision::AllowOnce, &ctx())
        .unwrap();
    let ((s1, b1), (s2, b2)) = (call1.await.unwrap(), call2.await.unwrap());
    assert_eq!((s1, s2), (200, 200));
    assert_eq!(
        b1["token"], b2["token"],
        "both instances receive the one minted token"
    );
    assert_eq!(h.broker.paired_agents().len(), 1);

    // A pairing arriving after completion is never handed the old token:
    // it raises its own prompt and mints afresh.
    let socket = h.socket.clone();
    let call3 = tokio::spawn(async move {
        uds_request(
            &socket,
            "POST",
            "/v1/pair",
            &[],
            Some(json!({"agent_name": "claude-code"})),
        )
        .await
    });
    let prompt = tokio::time::timeout(Duration::from_secs(5), h.prompts.recv())
        .await
        .unwrap()
        .unwrap();
    h.broker
        .decide(&prompt.id, UiDecision::AllowOnce, &ctx())
        .unwrap();
    let (s3, b3) = call3.await.unwrap();
    assert_eq!(s3, 200);
    assert_ne!(
        b3["token"], b1["token"],
        "a post-completion pairing gets a fresh prompt and token"
    );
}

/* --------------------------- connection proposals ------------------------- */

fn propose_pg_body(name: &str, credential_name: &str) -> serde_json::Value {
    json!({
        "name": name,
        "credential_name": credential_name,
        "config": {
            "kind": "pg", "host": "127.0.0.1", "port": 5432,
            "dbname": "app", "user": "app",
        },
    })
}

impl Harness {
    /// Wait for the next prompt and decide it carrying a proposal credential.
    async fn decide_next_with_credential(
        &mut self,
        decision: UiDecision,
        credential: Option<&str>,
    ) -> ApprovalRequest {
        let request = tokio::time::timeout(Duration::from_secs(5), self.prompts.recv())
            .await
            .expect("timed out waiting for a prompt")
            .expect("events channel closed");
        self.broker
            .decide_with_options(
                &request.id,
                decision,
                agentmfa_core::broker::DecisionOptions {
                    revoke_inherited_rules: false,
                    proposal_credential: credential.map(|value| Zeroizing::new(value.to_string())),
                },
                &ctx(),
            )
            .unwrap();
        request
    }
}

#[tokio::test]
async fn propose_prompts_and_creates_connection_with_user_credential() {
    let mut h = harness(BrokerConfig::default()).await;
    let token = h.pair("claude-code").await;
    let auth = format!("Bearer {token}");

    let socket = h.socket.clone();
    let call = tokio::spawn(async move {
        uds_request(
            &socket,
            "POST",
            "/v1/connections/propose",
            &[("authorization", &auth)],
            Some(propose_pg_body("sandbox-pg", "SANDBOX_PG_PASSWORD")),
        )
        .await
    });

    let prompt = h
        .decide_next_with_credential(UiDecision::AllowOnce, Some("s3cr3t"))
        .await;
    assert_eq!(prompt.kind, agentmfa_core::approvals::ApprovalKind::Propose);
    let proposal = prompt.proposal.as_ref().expect("proposal view");
    assert_eq!(proposal.name, "sandbox-pg");
    assert_eq!(proposal.credential_name, "SANDBOX_PG_PASSWORD");
    assert_eq!(proposal.target, "app@127.0.0.1:5432/app");
    assert_eq!(proposal.tls.as_deref(), Some("verify-full"));

    let (status, body) = call.await.unwrap();
    assert_eq!(status, 201, "propose failed: {body}");
    assert_eq!(body["name"], "sandbox-pg");
    assert_eq!(body["type"], "pg");
    assert_eq!(body["endpoint"], "/v1/pg/open");

    // The connection exists but grants nothing: listing shows will_prompt.
    let conn = h
        .broker
        .store
        .connection_by_name("sandbox-pg")
        .expect("connection saved");
    assert_eq!(conn.target(), "app@127.0.0.1:5432/app");
    assert!(h.broker.store.secret_by_name("SANDBOX_PG_PASSWORD").is_some());
}

#[tokio::test]
async fn propose_allow_without_credential_fails_closed_and_stays_pending() {
    let mut h = harness(BrokerConfig::default()).await;
    let token = h.pair("claude-code").await;
    let auth = format!("Bearer {token}");

    let socket = h.socket.clone();
    let call = tokio::spawn(async move {
        uds_request(
            &socket,
            "POST",
            "/v1/connections/propose",
            &[("authorization", &auth)],
            Some(propose_pg_body("sandbox-pg", "SANDBOX_PG_PASSWORD")),
        )
        .await
    });

    let request = tokio::time::timeout(Duration::from_secs(5), h.prompts.recv())
        .await
        .unwrap()
        .unwrap();
    // Allowing without a typed value must fail without consuming the prompt…
    let missing = h.broker.decide_with_options(
        &request.id,
        UiDecision::AllowOnce,
        agentmfa_core::broker::DecisionOptions::default(),
        &ctx(),
    );
    assert!(missing.is_err(), "allow without a credential must fail");
    // …then a real decision still works.
    h.broker
        .decide_with_options(
            &request.id,
            UiDecision::Deny,
            agentmfa_core::broker::DecisionOptions::default(),
            &ctx(),
        )
        .unwrap();
    let (status, body) = call.await.unwrap();
    assert_eq!(status, 403);
    assert_eq!(body["reason"], "denied_by_user");
    assert!(h.broker.store.connection_by_name("sandbox-pg").is_none());
}

#[tokio::test]
async fn propose_duplicate_target_is_refused_without_prompting() {
    let mut h = harness(BrokerConfig::default()).await;
    api_connection(&h, "github", 18080);
    let token = h.pair("claude-code").await;
    let auth = format!("Bearer {token}");

    // Same target under a different name: refused up front, no prompt.
    let (status, body) = uds_request(
        &h.socket,
        "POST",
        "/v1/connections/propose",
        &[("authorization", &auth)],
        Some(json!({
            "name": "github-two",
            "credential_name": "GITHUB_TOKEN_TWO",
            "config": {
                "kind": "api", "host": "127.0.0.1", "scheme": "http", "port": 18080,
                "template": "Authorization: Bearer {{GITHUB_TOKEN_TWO}}",
            },
        })),
    )
    .await;
    assert_eq!(status, 409, "expected conflict: {body}");
    assert_eq!(body["reason"], "connection_exists");
    assert!(body["detail"].as_str().unwrap().contains("github"));

    // Same name: also refused.
    let (status, body) = uds_request(
        &h.socket,
        "POST",
        "/v1/connections/propose",
        &[("authorization", &auth)],
        Some(json!({
            "name": "github",
            "credential_name": "GITHUB_TOKEN_TWO",
            "config": {
                "kind": "api", "host": "example.com", "template": "Authorization: Bearer {{GITHUB_TOKEN_TWO}}",
            },
        })),
    )
    .await;
    assert_eq!(status, 409);
    assert_eq!(body["reason"], "connection_exists");
}

#[tokio::test]
async fn propose_rejects_templates_referencing_existing_secrets() {
    let mut h = harness(BrokerConfig::default()).await;
    h.broker
        .store
        .add_secret("EXISTING_SECRET", Zeroizing::new("shh".into()))
        .unwrap();
    let token = h.pair("claude-code").await;
    let auth = format!("Bearer {token}");

    let (status, body) = uds_request(
        &h.socket,
        "POST",
        "/v1/connections/propose",
        &[("authorization", &auth)],
        Some(json!({
            "name": "exfil",
            "credential_name": "NEW_TOKEN",
            "config": {
                "kind": "api", "host": "evil.example.com",
                "template": "Authorization: Bearer {{EXISTING_SECRET}}",
            },
        })),
    )
    .await;
    assert_eq!(status, 400, "expected refusal: {body}");
    assert_eq!(body["reason"], "invalid_proposal");

    // Pre-pinned SSH trust is refused too.
    let (status, body) = uds_request(
        &h.socket,
        "POST",
        "/v1/connections/propose",
        &[("authorization", &auth)],
        Some(json!({
            "name": "box",
            "credential_name": "BOX_SSH_KEY",
            "config": {
                "kind": "ssh", "host": "host.example.com", "user": "deploy",
                "host_key_fingerprint": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            },
        })),
    )
    .await;
    assert_eq!(status, 400, "expected refusal: {body}");
    assert_eq!(body["reason"], "invalid_proposal");
}
