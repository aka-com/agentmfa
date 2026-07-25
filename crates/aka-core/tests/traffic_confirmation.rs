//! End-to-end traffic confirmation: a real daemon, a real upstream, and a
//! scripted user answering (or ignoring) the prompts.
//!
//! The switch is off by default, so every other test file exercises the
//! unconfirmed path. These cover the confirmed one: what the agent sees
//! while a call is parked, what it sees when the answer is no, and which
//! traffic raises a prompt at all.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aka_core::approvals::{ApprovalDecision, PendingApproval};
use aka_core::broker::Broker;
use aka_core::config::BrokerConfig;
use aka_core::daemon;
use aka_core::events::{ApprovalHandling, BrokerEvents};
use aka_core::paths::Paths;
use aka_core::request_history::RequestResolution;
use aka_core::store::ConnectionSpec;
use aka_core::types::{ConfirmMode, ConfirmationMethod, ConnectionConfig, SecretMeta};
use aka_core::vault::MemoryVault;
use axum::routing::{any, get, post};
use axum::Router;
use http_body_util::BodyExt as _;
use serde_json::{json, Value};
use zeroize::Zeroizing;

/* ------------------------------ the user --------------------------------- */

/// A scripted user: answers each prompt the way the test says, and records
/// what it was shown.
struct ScriptedUser {
    decision: Mutex<Option<ApprovalDecision>>,
    seen: Mutex<Vec<PendingApproval>>,
    prompts: AtomicUsize,
    /// Set after construction — the registry lives on the broker, and the
    /// broker is built with these events.
    broker: Mutex<Option<Arc<Broker>>>,
}

impl ScriptedUser {
    fn new(decision: Option<ApprovalDecision>) -> Arc<Self> {
        Arc::new(Self {
            decision: Mutex::new(decision),
            seen: Mutex::new(Vec::new()),
            prompts: AtomicUsize::new(0),
            broker: Mutex::new(None),
        })
    }

    fn prompts(&self) -> usize {
        self.prompts.load(Ordering::SeqCst)
    }

    fn last_prompt(&self) -> PendingApproval {
        self.seen
            .lock()
            .unwrap()
            .last()
            .cloned()
            .expect("the user should have been asked")
    }
}

impl BrokerEvents for ScriptedUser {
    fn confirm_secret_read(&self, _secret: &SecretMeta) -> bool {
        true
    }

    fn confirm_action(&self, _description: &str) -> Option<ConfirmationMethod> {
        Some(ConfirmationMethod::Waived)
    }

    fn approval_requested(&self, pending: &PendingApproval) -> ApprovalHandling {
        self.prompts.fetch_add(1, Ordering::SeqCst);
        self.seen.lock().unwrap().push(pending.clone());
        let decision = *self.decision.lock().unwrap();
        let Some(decision) = decision else {
            // Taken, but never answered: the deadline decides.
            return ApprovalHandling::Taken;
        };
        let broker = self.broker.lock().unwrap().clone();
        if let Some(broker) = broker {
            // A real shell answers from its UI thread; answering inline is
            // the same call, just sooner.
            broker
                .ui_respond_approval(&pending.id, decision)
                .expect("responding should not fail");
        }
        ApprovalHandling::Taken
    }
}

/* ------------------------------- harness --------------------------------- */

struct Harness {
    broker: Arc<Broker>,
    _daemon: daemon::DaemonHandle,
    socket: std::path::PathBuf,
    token: String,
    _dir: tempfile::TempDir,
}

async fn harness(user: Arc<ScriptedUser>) -> Harness {
    harness_with(
        BrokerConfig {
            // Short enough that the timeout test does not idle for a minute
            // and a half, long enough that a scripted answer always wins.
            approval_timeout: Duration::from_millis(300),
            ..BrokerConfig::default()
        },
        user,
    )
    .await
}

async fn harness_with(mut config: BrokerConfig, user: Arc<ScriptedUser>) -> Harness {
    config.version = "test".into();
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::under(dir.path());
    let broker = Broker::new(
        paths,
        Arc::new(MemoryVault::new()),
        config,
        user.clone() as Arc<dyn BrokerEvents>,
    )
    .await
    .unwrap();
    *user.broker.lock().unwrap() = Some(broker.clone());
    let handle = daemon::serve(broker.clone()).await.unwrap();
    let socket = handle.socket_path.clone();
    let token = broker.identity.token();
    Harness {
        broker,
        _daemon: handle,
        socket,
        token,
        _dir: dir,
    }
}

impl Harness {
    async fn http(&self, body: Value) -> (u16, Value) {
        uds_request(
            &self.socket,
            "POST",
            "/v1/http",
            &[("authorization", &format!("Bearer {}", self.token))],
            Some(body),
        )
        .await
    }

    /// A GET the upstream fixture answers, on the named connection.
    async fn get_repos(&self, connection: &str) -> (u16, Value) {
        self.http(json!({
            "connection": connection,
            "method": "GET",
            "path": "/user/repos",
        }))
        .await
    }

    fn confirm(&self, name: &str) {
        let conn = self.broker.store.connection_by_name(name).unwrap();
        self.broker
            .ui_set_confirm_mode(&conn.id, ConfirmMode::On)
            .unwrap();
    }
}

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
    for (key, value) in headers {
        builder = builder.header(*key, *value);
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

/// The upstream both an API tool and an MCP tool point at. Counts what
/// actually reached it, which is the whole question a refusal answers.
struct Upstream {
    port: u16,
    hits: Arc<AtomicUsize>,
    rpc_methods: Arc<Mutex<Vec<String>>>,
}

async fn upstream() -> Upstream {
    let hits = Arc::new(AtomicUsize::new(0));
    let rpc_methods: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let repo_hits = hits.clone();
    let echo_hits = hits.clone();
    let mcp_hits = hits.clone();
    let mcp_methods = rpc_methods.clone();
    let app = Router::new()
        .route(
            "/user/repos",
            get(move || {
                let hits = repo_hits.clone();
                async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    axum::Json(json!([{"name": "aka"}]))
                }
            }),
        )
        .route(
            "/echo",
            any(move |req: axum::extract::Request| {
                let hits = echo_hits.clone();
                async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    let (_, body) = req.into_parts();
                    let bytes = axum::body::to_bytes(body, 1024 * 1024).await.unwrap();
                    axum::Json(json!({ "len": bytes.len() }))
                }
            }),
        )
        .route(
            "/mcp",
            post(move |body: String| {
                let hits = mcp_hits.clone();
                let methods = mcp_methods.clone();
                async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    let rpc: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
                    let method = rpc
                        .get("method")
                        .and_then(|m| m.as_str())
                        .unwrap_or_default()
                        .to_string();
                    methods.lock().unwrap().push(method);
                    axum::Json(json!({ "jsonrpc": "2.0", "id": 1, "result": {} }))
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    Upstream {
        port,
        hits,
        rpc_methods,
    }
}

fn api_connection(harness: &Harness, name: &str, port: u16, mcp_path: Option<&str>) {
    let secret = format!("{}_KEY", name.to_uppercase().replace('-', "_"));
    harness
        .broker
        .store
        .add_secret(&secret, Zeroizing::new("token-value".into()))
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
                template: format!("Authorization: Bearer {{{{{secret}}}}}"),
                mcp_path: mcp_path.map(str::to_string),
                oauth: None,
            },
            secrets: vec![],
        })
        .unwrap();
}

fn reason(body: &Value) -> &str {
    body["reason"].as_str().unwrap_or_default()
}

/* -------------------------------- tests ---------------------------------- */

#[tokio::test]
async fn an_unconfirmed_tool_never_asks() {
    let user = ScriptedUser::new(Some(ApprovalDecision::Deny));
    let h = harness(user.clone()).await;
    let up = upstream().await;
    api_connection(&h, "github", up.port, None);

    let (status, _) = h.get_repos("github").await;
    assert_eq!(status, 200);
    assert_eq!(up.hits.load(Ordering::SeqCst), 1);
    assert_eq!(
        user.prompts(),
        0,
        "the switch is off by default; nothing should be asked"
    );
}

#[tokio::test]
async fn an_approved_request_executes_and_its_window_covers_the_next_ones() {
    let user = ScriptedUser::new(Some(ApprovalDecision::ApproveWindow));
    let h = harness(user.clone()).await;
    let up = upstream().await;
    api_connection(&h, "github", up.port, None);
    h.confirm("github");

    let (status, body) = h.get_repos("github").await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(up.hits.load(Ordering::SeqCst), 1);
    assert_eq!(user.prompts(), 1);

    // The prompt named the traffic, not just the tool.
    let prompt = user.last_prompt();
    assert_eq!(prompt.summary, "GET /user/repos");
    assert_eq!(prompt.connection, "github");
    assert!(
        prompt.target.starts_with("http://127.0.0.1:"),
        "the prompt names the pinned destination: {}",
        prompt.target
    );

    let (status, _) = h.get_repos("github").await;
    assert_eq!(status, 200);
    assert_eq!(up.hits.load(Ordering::SeqCst), 2);
    assert_eq!(
        user.prompts(),
        1,
        "the approval window covers what follows without asking again"
    );
}

#[tokio::test]
async fn a_request_body_is_shown_with_the_prompt() {
    let user = ScriptedUser::new(Some(ApprovalDecision::ApproveWindow));
    let h = harness(user.clone()).await;
    let up = upstream().await;
    api_connection(&h, "github", up.port, None);
    h.confirm("github");

    let (status, _) = h
        .http(json!({
            "connection": "github",
            "method": "POST",
            "path": "/echo",
            "body": {"title": "ship it"},
        }))
        .await;
    assert_eq!(status, 200);
    let prompt = user.last_prompt();
    assert_eq!(prompt.summary, "POST /echo");
    assert_eq!(
        prompt.detail.as_deref(),
        Some(r#"{"title":"ship it"}"#),
        "the decision is about the payload, so the payload is shown"
    );
}

#[tokio::test]
async fn a_refusal_stops_the_call_and_covers_the_retry() {
    let user = ScriptedUser::new(Some(ApprovalDecision::Deny));
    let h = harness(user.clone()).await;
    let up = upstream().await;
    api_connection(&h, "github", up.port, None);
    h.confirm("github");

    let (status, body) = h.get_repos("github").await;
    assert_eq!(status, 403);
    assert_eq!(reason(&body), "approval_denied");
    assert!(
        body["detail"].as_str().unwrap().contains("github"),
        "the refusal names the tool: {body}"
    );
    assert_eq!(
        up.hits.load(Ordering::SeqCst),
        0,
        "a refused call must never reach the upstream"
    );

    // An agent that retries the refusal must not become a prompt loop.
    let (status, body) = h.get_repos("github").await;
    assert_eq!(status, 403);
    assert_eq!(reason(&body), "approval_denied");
    assert_eq!(user.prompts(), 1, "the cooldown answers the retry");
    assert_eq!(up.hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn an_unanswered_prompt_lapses_into_a_refusal_the_agent_can_read() {
    let user = ScriptedUser::new(None); // takes the prompt, never answers
    let h = harness(user.clone()).await;
    let up = upstream().await;
    api_connection(&h, "github", up.port, None);
    h.confirm("github");

    let (status, body) = h.get_repos("github").await;
    assert_eq!(status, 408, "{body}");
    assert_eq!(reason(&body), "approval_timeout");
    assert_eq!(up.hits.load(Ordering::SeqCst), 0);
    assert!(
        h.broker.pending_approvals().is_empty(),
        "a lapsed prompt leaves the queue"
    );

    // Timing out decided nothing, so the next call asks again.
    let (status, _) = h.get_repos("github").await;
    assert_eq!(status, 408);
    assert_eq!(user.prompts(), 2);
}

#[tokio::test]
async fn with_nothing_able_to_ask_confirmed_traffic_is_refused() {
    struct NoSurface;
    impl BrokerEvents for NoSurface {
        fn confirm_secret_read(&self, _secret: &SecretMeta) -> bool {
            true
        }
        fn confirm_action(&self, _description: &str) -> Option<ConfirmationMethod> {
            Some(ConfirmationMethod::Waived)
        }
        // `approval_requested` is left at its fail-closed default.
    }

    let dir = tempfile::tempdir().unwrap();
    let broker = Broker::new(
        Paths::under(dir.path()),
        Arc::new(MemoryVault::new()),
        BrokerConfig::default(),
        Arc::new(NoSurface),
    )
    .await
    .unwrap();
    let handle = daemon::serve(broker.clone()).await.unwrap();
    let up = upstream().await;
    broker
        .store
        .add_secret("GITHUB_KEY", Zeroizing::new("token-value".into()))
        .unwrap();
    let conn = broker
        .store
        .add_connection(ConnectionSpec {
            name: "github".into(),
            config: ConnectionConfig::Api {
                host: "127.0.0.1".into(),
                scheme: "http".into(),
                port: Some(up.port),
                template: "Authorization: Bearer {{GITHUB_KEY}}".into(),
                mcp_path: None,
                oauth: None,
            },
            secrets: vec![],
        })
        .unwrap();
    broker
        .ui_set_confirm_mode(&conn.id, ConfirmMode::On)
        .unwrap();

    let token = broker.identity.token();
    // Monitoring the feed does not claim a user-facing request inbox.
    let events = broker.manage_bus().subscribe();
    let (status, body) = uds_request(
        &handle.socket_path,
        "POST",
        "/v1/http",
        &[("authorization", &format!("Bearer {token}"))],
        Some(json!({"connection": "github", "method": "GET", "path": "/user/repos"})),
    )
    .await;
    assert_eq!(status, 403, "{body}");
    assert_eq!(reason(&body), "approval_unavailable");
    assert_eq!(
        up.hits.load(Ordering::SeqCst),
        0,
        "the user asked to be asked; with no way to ask, the call does not go"
    );

    // A hosted broker has no local shell, but an authenticated management
    // stream can explicitly lease the remote app's request surface. It must
    // keep the call parked rather than replaying `Unavailable`.
    drop(events);
    let mut events = broker.manage_bus().subscribe();
    let surface = broker.manage_bus().lease_approval_surface();
    assert!(broker.manage_bus().renew_approval_surface(&surface.id()));
    let socket = handle.socket_path.clone();
    let token = token.clone();
    let call = tokio::spawn(async move {
        uds_request(
            &socket,
            "POST",
            "/v1/http",
            &[("authorization", &format!("Bearer {token}"))],
            Some(json!({"connection": "github", "method": "GET", "path": "/user/repos"})),
        )
        .await
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let item = events.recv().await.unwrap();
            if matches!(item.event, aka_api::ManageEvent::ApprovalsChanged) {
                break;
            }
        }
    })
    .await
    .expect("a remote surface should receive the new prompt event");
    let pending = broker.pending_approvals();
    assert_eq!(pending.len(), 1);
    assert!(broker
        .ui_respond_approval(&pending[0].id, ApprovalDecision::ApproveWindow)
        .unwrap());
    let (status, body) = call.await.unwrap();
    assert_eq!(status, 200, "{body}");
    assert_eq!(up.hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn mcp_plumbing_passes_but_tool_calls_are_confirmed() {
    let user = ScriptedUser::new(Some(ApprovalDecision::ApproveWindow));
    let h = harness(user.clone()).await;
    let up = upstream().await;
    api_connection(&h, "notion", up.port, Some("/mcp"));
    h.confirm("notion");

    let rpc = |body: Value| {
        h.http(json!({
            "connection": "notion",
            "method": "POST",
            "path": "/mcp",
            "body": body,
        }))
    };

    // Initialising a session and listing tools happen on every single tool
    // call the sidecar makes; prompting on them would ask three times per
    // call and again on every listing.
    let (status, _) = rpc(json!({"jsonrpc": "2.0", "id": 1, "method": "initialize"})).await;
    assert_eq!(status, 200);
    let (status, _) = rpc(json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})).await;
    assert_eq!(status, 200);
    assert_eq!(user.prompts(), 0, "session plumbing must not raise prompts");

    let (status, _) = rpc(json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {"name": "search_issues", "arguments": {"query": "flaky"}},
    }))
    .await;
    assert_eq!(status, 200);
    assert_eq!(user.prompts(), 1);
    let prompt = user.last_prompt();
    assert_eq!(
        prompt.summary, "search_issues",
        "the prompt names the tool the agent called"
    );
    assert_eq!(prompt.detail.as_deref(), Some(r#"{"query":"flaky"}"#));
    assert_eq!(
        up.rpc_methods.lock().unwrap().as_slice(),
        ["initialize", "tools/list", "tools/call"]
    );
}

#[tokio::test]
async fn resource_metadata_passes_but_reads_are_confirmed() {
    let user = ScriptedUser::new(Some(ApprovalDecision::ApproveWindow));
    let h = harness(user.clone()).await;
    let up = upstream().await;
    api_connection(&h, "notion", up.port, Some("/mcp"));
    h.confirm("notion");

    let rpc = |body: Value| {
        h.http(json!({
            "connection": "notion",
            "method": "POST",
            "path": "/mcp",
            "body": body,
        }))
    };

    // Listing templates and completing an argument are metadata the host
    // fires as the user browses or types; prompting on them would be unusable.
    let (status, _) =
        rpc(json!({"jsonrpc": "2.0", "id": 1, "method": "resources/templates/list"})).await;
    assert_eq!(status, 200);
    let (status, _) = rpc(json!({
        "jsonrpc": "2.0", "id": 2, "method": "completion/complete",
        "params": {
            "ref": {"type": "ref/resource", "uri": "notion://page/{id}"},
            "argument": {"name": "id", "value": "h"},
        },
    }))
    .await;
    assert_eq!(status, 200);
    assert_eq!(user.prompts(), 0, "resource metadata must not raise prompts");

    // Reading a resource is real data access: it is confirmed like a call.
    let (status, _) = rpc(json!({
        "jsonrpc": "2.0", "id": 3, "method": "resources/read",
        "params": {"uri": "notion://page/home"},
    }))
    .await;
    assert_eq!(status, 200);
    assert_eq!(user.prompts(), 1, "a resource read is confirmed");
    assert_eq!(user.last_prompt().summary, "resources/read");
}

#[tokio::test]
async fn an_empty_mutating_request_on_the_mcp_path_is_still_confirmed() {
    let user = ScriptedUser::new(Some(ApprovalDecision::Deny));
    let h = harness(user.clone()).await;
    let up = upstream().await;
    api_connection(&h, "notion", up.port, Some("/mcp"));
    h.confirm("notion");

    let (status, body) = h
        .http(json!({
            "connection": "notion",
            "method": "POST",
            "path": "/mcp",
        }))
        .await;
    assert_eq!(status, 403, "{body}");
    assert_eq!(reason(&body), "approval_denied");
    assert_eq!(user.last_prompt().summary, "POST /mcp");
    assert_eq!(up.hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_large_mcp_call_uses_a_bounded_generic_approval_description() {
    let user = ScriptedUser::new(Some(ApprovalDecision::Deny));
    let h = harness(user.clone()).await;
    let up = upstream().await;
    api_connection(&h, "notion", up.port, Some("/mcp"));
    h.confirm("notion");

    let (status, body) = h
        .http(json!({
            "connection": "notion",
            "method": "POST",
            "path": "/mcp",
            "body": {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "would_require_a_second_full_parse",
                    "arguments": {"blob": "x".repeat(1024 * 1024)},
                },
            },
        }))
        .await;
    assert_eq!(status, 403, "{body}");
    let prompt = user.last_prompt();
    assert_eq!(prompt.summary, "POST /mcp");
    let detail = prompt.detail.expect("the bounded prefix should be shown");
    assert!(
        detail.chars().count() <= 401,
        "approval detail exceeded its 400-character preview plus ellipsis"
    );
    assert!(detail.ends_with('…'), "the truncated preview is marked");
    assert_eq!(up.hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn only_recognized_mcp_transport_legs_bypass_confirmation() {
    let user = ScriptedUser::new(Some(ApprovalDecision::Deny));
    let h = harness(user.clone()).await;
    let up = upstream().await;

    api_connection(&h, "plain-get", up.port, Some("/mcp"));
    h.confirm("plain-get");
    let (status, body) = h
        .http(json!({
            "connection": "plain-get",
            "method": "GET",
            "path": "/mcp",
        }))
        .await;
    assert_eq!(status, 403, "{body}");
    assert_eq!(user.last_prompt().summary, "GET /mcp");

    api_connection(&h, "custom-notification", up.port, Some("/mcp"));
    h.confirm("custom-notification");
    let (status, body) = h
        .http(json!({
            "connection": "custom-notification",
            "method": "POST",
            "path": "/mcp",
            "body": {
                "jsonrpc": "2.0",
                "method": "notifications/custom_side_effect",
                "params": {"action": "rotate"},
            },
        }))
        .await;
    assert_eq!(status, 403, "{body}");
    let prompt = user.last_prompt();
    assert_eq!(prompt.summary, "notifications/custom_side_effect");
    assert_eq!(prompt.detail.as_deref(), Some(r#"{"action":"rotate"}"#));

    api_connection(&h, "event-stream", up.port, Some("/mcp"));
    h.confirm("event-stream");
    let prompts = user.prompts();
    let (status, body) = h
        .http(json!({
            "connection": "event-stream",
            "method": "GET",
            "path": "/mcp",
            "headers": {"Accept": "application/json, text/event-stream"},
        }))
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body["status"], 405,
        "the fixture has no GET route, but the broker carried it"
    );
    assert_eq!(
        user.prompts(),
        prompts,
        "a protocol event-stream GET is transport plumbing"
    );
    assert_eq!(up.hits.load(Ordering::SeqCst), 0);

    api_connection(&h, "lookalike-stream", up.port, Some("/mcp"));
    h.confirm("lookalike-stream");
    let (status, body) = h
        .http(json!({
            "connection": "lookalike-stream",
            "method": "GET",
            "path": "/mcp",
            "headers": {"Accept": "text/event-streaming"},
        }))
        .await;
    assert_eq!(status, 403, "{body}");
    assert_eq!(
        user.last_prompt().summary,
        "GET /mcp",
        "only the exact event-stream media type is protocol plumbing"
    );

    api_connection(&h, "q-zero-stream", up.port, Some("/mcp"));
    h.confirm("q-zero-stream");
    let (status, body) = h
        .http(json!({
            "connection": "q-zero-stream",
            "method": "GET",
            "path": "/mcp",
            "headers": {"Accept": "text/event-stream; q=0"},
        }))
        .await;
    assert_eq!(status, 403, "{body}");
    assert_eq!(
        user.last_prompt().summary,
        "GET /mcp",
        "a media type the client explicitly rejects is not an event-stream leg"
    );

    api_connection(&h, "batch", up.port, Some("/mcp"));
    h.confirm("batch");
    let (status, body) = h
        .http(json!({
            "connection": "batch",
            "method": "POST",
            "path": "/mcp",
            "body": [
                {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                 "params": {"name": "search", "arguments": {}}},
                {"jsonrpc": "2.0", "method": "notifications/custom_side_effect"},
            ],
        }))
        .await;
    assert_eq!(status, 403, "{body}");
    assert_eq!(
        user.last_prompt().summary,
        "MCP batch (2 messages): tools/call, notifications/custom_side_effect"
    );
}

#[tokio::test]
async fn a_request_aimed_off_the_mcp_path_is_still_confirmed() {
    // An MCP connection is still a credentialed destination. A request the
    // agent points somewhere else on that host is ordinary traffic, and
    // must not inherit the plumbing exemption.
    let user = ScriptedUser::new(Some(ApprovalDecision::Deny));
    let h = harness(user.clone()).await;
    let up = upstream().await;
    api_connection(&h, "notion", up.port, Some("/mcp"));
    h.confirm("notion");

    let (status, body) = h
        .http(json!({
            "connection": "notion",
            "method": "GET",
            "path": "/user/repos",
        }))
        .await;
    assert_eq!(status, 403, "{body}");
    assert_eq!(reason(&body), "approval_denied");
    assert_eq!(user.prompts(), 1);
    assert_eq!(up.hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn approving_all_turns_the_switch_off() {
    let user = ScriptedUser::new(Some(ApprovalDecision::ApproveAll));
    let h = harness(user.clone()).await;
    let up = upstream().await;
    api_connection(&h, "github", up.port, None);
    h.confirm("github");
    let conn = h.broker.store.connection_by_name("github").unwrap();

    let (status, _) = h.get_repos("github").await;
    assert_eq!(status, 200);
    assert_eq!(up.hits.load(Ordering::SeqCst), 1);
    assert_eq!(
        h.broker.access.confirm_mode(&conn.id),
        ConfirmMode::Off,
        "\"approve all\" is the switch going off, persisted"
    );
    assert_eq!(
        h.broker.request_records()[0].resolution,
        Some(RequestResolution::ApprovedAll)
    );

    let (status, _) = h.get_repos("github").await;
    assert_eq!(status, 200);
    assert_eq!(user.prompts(), 1);
}

#[tokio::test]
async fn turning_the_switch_off_releases_traffic_already_parked() {
    let user = ScriptedUser::new(None); // parks every call
    let h = harness(user.clone()).await;
    let up = upstream().await;
    api_connection(&h, "github", up.port, None);
    h.confirm("github");
    let conn = h.broker.store.connection_by_name("github").unwrap();

    let socket = h.socket.clone();
    let token = h.token.clone();
    let call = tokio::spawn(async move {
        uds_request(
            &socket,
            "POST",
            "/v1/http",
            &[("authorization", &format!("Bearer {token}"))],
            Some(json!({"connection": "github", "method": "GET", "path": "/user/repos"})),
        )
        .await
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        while h.broker.pending_approvals().is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the call should park on a prompt");

    // The user says this traffic needs no asking; refusing the very call
    // that raised the question would be a strange way to honour that.
    h.broker
        .ui_set_confirm_mode(&conn.id, ConfirmMode::Off)
        .unwrap();
    let (status, body) = call.await.unwrap();
    assert_eq!(status, 200, "{body}");
    assert_eq!(up.hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn disabling_the_tool_refuses_traffic_parked_on_it() {
    let user = ScriptedUser::new(None);
    let h = harness(user.clone()).await;
    let up = upstream().await;
    api_connection(&h, "github", up.port, None);
    h.confirm("github");
    let conn = h.broker.store.connection_by_name("github").unwrap();

    let socket = h.socket.clone();
    let token = h.token.clone();
    let call = tokio::spawn(async move {
        uds_request(
            &socket,
            "POST",
            "/v1/http",
            &[("authorization", &format!("Bearer {token}"))],
            Some(json!({"connection": "github", "method": "GET", "path": "/user/repos"})),
        )
        .await
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        while h.broker.pending_approvals().is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the call should park on a prompt");

    // Access going away is the opposite case: the authority itself is gone.
    h.broker.ui_set_tool_access(&conn.id, false).unwrap();
    let (status, body) = call.await.unwrap();
    assert_eq!(status, 403, "{body}");
    assert_eq!(reason(&body), "denied_by_policy");
    assert_eq!(up.hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_stale_prompt_cannot_open_a_window_after_the_connection_changes() {
    let user = ScriptedUser::new(None);
    let h = harness(user.clone()).await;
    let up = upstream().await;
    api_connection(&h, "github", up.port, None);
    h.confirm("github");
    let conn = h.broker.store.connection_by_name("github").unwrap();

    let socket = h.socket.clone();
    let token = h.token.clone();
    let call = tokio::spawn(async move {
        uds_request(
            &socket,
            "POST",
            "/v1/http",
            &[("authorization", &format!("Bearer {token}"))],
            Some(json!({"connection": "github", "method": "GET", "path": "/user/repos"})),
        )
        .await
    });
    let prompt = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if let Some(prompt) = h.broker.pending_approvals().first() {
                return prompt.clone();
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the call should park on a prompt");

    // A rename is enough to exercise the hard race: it changes the stored
    // version without proactively revoking a target-scoped prompt.
    h.broker
        .ui_update_connection(
            &conn.id,
            ConnectionSpec {
                name: "github-renamed".into(),
                config: conn.config.clone(),
                secrets: conn.secrets.clone(),
            },
        )
        .unwrap();
    assert!(h
        .broker
        .ui_respond_approval(&prompt.id, ApprovalDecision::ApproveWindow)
        .unwrap());

    let (status, body) = call.await.unwrap();
    assert_eq!(status, 403, "{body}");
    assert_eq!(reason(&body), "denied_by_policy");
    assert_eq!(up.hits.load(Ordering::SeqCst), 0);
    assert_eq!(
        h.broker.approvals.window_remaining(&conn.id),
        None,
        "the stale answer must not cover the replacement connection record"
    );
}

#[tokio::test]
async fn concurrent_calls_ride_one_prompt() {
    let user = ScriptedUser::new(None);
    let h = harness(user.clone()).await;
    let up = upstream().await;
    api_connection(&h, "github", up.port, None);
    h.confirm("github");

    let calls: Vec<_> = (0..5)
        .map(|_| {
            let socket = h.socket.clone();
            let token = h.token.clone();
            tokio::spawn(async move {
                uds_request(
                    &socket,
                    "POST",
                    "/v1/http",
                    &[("authorization", &format!("Bearer {token}"))],
                    Some(json!({"connection": "github", "method": "GET", "path": "/user/repos"})),
                )
                .await
            })
        })
        .collect();

    let pending = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let pending = h.broker.pending_approvals();
            if pending.first().is_some_and(|p| p.waiting == 5) {
                return pending;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("five calls should coalesce onto one prompt");
    assert_eq!(pending.len(), 1);
    assert_eq!(user.prompts(), 1);

    h.broker
        .ui_respond_approval(&pending[0].id, ApprovalDecision::ApproveWindow)
        .unwrap();
    for call in calls {
        let (status, _) = call.await.unwrap();
        assert_eq!(status, 200);
    }
    assert_eq!(up.hits.load(Ordering::SeqCst), 5);
}

#[tokio::test]
async fn the_queue_carries_what_the_app_renders() {
    let user = ScriptedUser::new(None);
    let h = harness(user.clone()).await;
    let up = upstream().await;
    api_connection(&h, "github", up.port, None);
    h.confirm("github");

    let socket = h.socket.clone();
    let token = h.token.clone();
    tokio::spawn(async move {
        uds_request(
            &socket,
            "POST",
            "/v1/http",
            &[
                ("authorization", &format!("Bearer {token}")),
                ("x-agentmfa-client", "codex"),
            ],
            Some(json!({"connection": "github", "method": "GET", "path": "/user/repos"})),
        )
        .await
    });

    let pending = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let pending = h.broker.pending_approvals();
            if !pending.is_empty() {
                return pending;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the prompt should reach the queue");
    let prompt = &pending[0];
    assert_eq!(prompt.agent, "codex", "the prompt attributes the caller");
    assert_eq!(prompt.connection, "github");
    assert_eq!(prompt.summary, "GET /user/repos");
    assert!(prompt.expires_at > prompt.requested_at);
    assert_eq!(prompt.window_secs, 15 * 60);
}

#[tokio::test]
async fn the_activity_log_records_the_ask_and_the_answer() {
    let user = ScriptedUser::new(Some(ApprovalDecision::Deny));
    let h = harness(user.clone()).await;
    let up = upstream().await;
    api_connection(&h, "github", up.port, None);
    h.confirm("github");
    h.get_repos("github").await;

    let recent = h.broker.audit.recent(10);
    let asks = recent
        .iter()
        .filter(|entry| entry.kind == aka_core::audit::AuditKind::Requested)
        .count();
    assert_eq!(asks, 1, "the ask is recorded: {recent:?}");
    let denied = recent
        .iter()
        .find(|entry| entry.kind == aka_core::audit::AuditKind::Denied)
        .expect("the answer is recorded");
    assert_eq!(denied.outcome.as_deref(), Some("denied"));
    assert_eq!(denied.connection.as_deref(), Some("github"));
}
