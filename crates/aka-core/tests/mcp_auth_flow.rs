//! The MCP sign-in flow, end to end against a mock OAuth stack.
//!
//! One axum server plays every role a real vendor would: the MCP resource
//! (401 + `WWW-Authenticate` until a bearer token arrives), the protected
//! resource metadata, the authorization server metadata, dynamic client
//! registration, an auto-approving authorization endpoint, and a token
//! endpoint that actually verifies PKCE. The test drives
//! `ui_start_mcp_auth`, plays the browser's part by following the
//! authorization URL, and then asserts what matters: a connection exists
//! only after the dance completed, the token landed in the vault (never in
//! any UI-visible state), the account was acknowledged, and the status
//! check reports tools and resources against the template's expectations.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aka_core::broker::Broker;
use aka_core::config::BrokerConfig;
use aka_core::daemon;
use aka_core::events::{ApprovalHandling, BrokerEvents};
use aka_core::mcp::McpCheckOptions;
use aka_core::mcp_auth::{McpAuthDraft, McpAuthPhase, McpAuthState};
use aka_core::paths::Paths;
use aka_core::types::ConnectionConfig;
use aka_core::vault::MemoryVault;
use base64::Engine as _;
use http_body_util::BodyExt as _;
use serde_json::{json, Value};
use sha2::Digest as _;
use uuid::Uuid;

const ACCESS_TOKEN: &str = "test-token-issued-by-mock";
const RENEWED_TOKEN: &str = "test-token-renewed-by-refresh";
const REFRESH_TOKEN: &str = "test-refresh-token-1";
const ROTATED_REFRESH_TOKEN: &str = "test-refresh-token-2";
const AUTH_CODE: &str = "test-code-1";

struct NoopEvents;
impl BrokerEvents for NoopEvents {
    fn approval_requested(
        &self,
        _pending: &aka_core::approvals::PendingApproval,
    ) -> ApprovalHandling {
        ApprovalHandling::Waived
    }
}

struct MockAuthServer {
    code_challenge: Option<String>,
    registered_redirect: Option<String>,
    token_requests: u32,
    refresh_requests: u32,
    mcp_authorized_requests: u32,
    mcp_rejected_requests: u32,
    mcp_session_deletes: u32,
    /// The bearer the MCP resource currently accepts; refresh rotates it.
    current_access: String,
    /// The refresh token the token endpoint currently honors; `None`
    /// makes every refresh answer 400 invalid_grant.
    valid_refresh: Option<String>,
    /// Issuer returned by the authorization response. `None` uses the
    /// discovered issuer; tests override it to exercise mix-up rejection.
    response_iss: Option<String>,
}

impl Default for MockAuthServer {
    fn default() -> Self {
        Self {
            code_challenge: None,
            registered_redirect: None,
            token_requests: 0,
            refresh_requests: 0,
            mcp_authorized_requests: 0,
            mcp_rejected_requests: 0,
            mcp_session_deletes: 0,
            current_access: ACCESS_TOKEN.into(),
            valid_refresh: Some(REFRESH_TOKEN.into()),
            response_iss: None,
        }
    }
}

fn mcp_result(method: Option<&str>) -> Value {
    match method {
        Some("initialize") => json!({
            "protocolVersion": "2025-06-18",
            "capabilities": { "tools": {}, "resources": {} },
            "serverInfo": { "name": "mock-mcp", "version": "1.0.0" },
        }),
        Some("tools/list") => json!({
            "tools": [
                {
                    "name": "get_me",
                    "inputSchema": { "type": "object" },
                    "annotations": { "readOnlyHint": true }
                },
                { "name": "search", "inputSchema": { "type": "object" } },
            ],
        }),
        Some("tools/call") => json!({
            "content": [{
                "type": "text",
                "text": "{\"login\":\"octocat\",\"name\":\"Octo Cat\"}",
            }],
        }),
        Some("resources/list") => json!({
            "resources": [
                { "uri": "mock://repos/one", "name": "Repo One", "description": "First repo" },
            ],
        }),
        _ => json!(null),
    }
}

/// The whole vendor: MCP resource + metadata + AS on one loopback origin.
async fn spawn_mock_vendor() -> (u16, Arc<Mutex<MockAuthServer>>) {
    let state: Arc<Mutex<MockAuthServer>> = Arc::default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind vendor");
    let port = listener.local_addr().expect("addr").port();
    let base = format!("http://127.0.0.1:{port}");

    let mcp = {
        let state = state.clone();
        move |headers: axum::http::HeaderMap, body: axum::Json<Value>| {
            let base = base.clone();
            let state = state.clone();
            async move {
                let expected = format!("Bearer {}", state.lock().unwrap().current_access);
                let authorized = headers
                    .get("authorization")
                    .and_then(|value| value.to_str().ok())
                    == Some(expected.as_str());
                if !authorized {
                    state.lock().unwrap().mcp_rejected_requests += 1;
                    return axum::http::Response::builder()
                        .status(401)
                        .header(
                            "WWW-Authenticate",
                            format!(
                                "Bearer resource_metadata=\"{base}/.well-known/oauth-protected-resource/mcp\""
                            ),
                        )
                        .body(axum::body::Body::from("unauthorized"))
                        .unwrap();
                }
                state.lock().unwrap().mcp_authorized_requests += 1;
                // A notification carries no id; the transport answers 202.
                if body.0.get("id").is_none() {
                    return axum::http::Response::builder()
                        .status(202)
                        .body(axum::body::Body::empty())
                        .unwrap();
                }
                let reply = json!({
                    "jsonrpc": "2.0",
                    "id": body.0["id"],
                    "result": mcp_result(body.0["method"].as_str()),
                });
                axum::http::Response::builder()
                    .status(200)
                    .header("content-type", "application/json")
                    .header("mcp-session-id", "mock-session-1")
                    .body(axum::body::Body::from(reply.to_string()))
                    .unwrap()
            }
        }
    };
    let mcp_delete = {
        let state = state.clone();
        move |headers: axum::http::HeaderMap| {
            let state = state.clone();
            async move {
                assert!(headers.get("mcp-session-id").is_some());
                state.lock().unwrap().mcp_session_deletes += 1;
                axum::http::StatusCode::NO_CONTENT
            }
        }
    };

    let base = format!("http://127.0.0.1:{port}");
    let resource_meta = {
        let base = base.clone();
        move || {
            let base = base.clone();
            async move {
                axum::Json(json!({
                    "resource": format!("{base}/mcp"),
                    "authorization_servers": [base],
                    "scopes_supported": ["mcp.read", "mcp.write"],
                }))
            }
        }
    };
    let as_meta = {
        let base = base.clone();
        move || {
            let base = base.clone();
            async move {
                axum::Json(json!({
                    "issuer": base,
                    "authorization_endpoint": format!("{base}/authorize"),
                    "token_endpoint": format!("{base}/token"),
                    "registration_endpoint": format!("{base}/register"),
                    "authorization_response_iss_parameter_supported": true,
                }))
            }
        }
    };
    let register = {
        let state = state.clone();
        move |body: axum::Json<Value>| {
            let state = state.clone();
            async move {
                assert_eq!(body.0["client_name"], json!("AgentMFA"));
                assert_eq!(body.0["token_endpoint_auth_method"], json!("none"));
                let redirect = body.0["redirect_uris"][0]
                    .as_str()
                    .expect("redirect uri")
                    .to_string();
                assert!(redirect.starts_with("http://127.0.0.1:"));
                state.lock().unwrap().registered_redirect = Some(redirect);
                axum::Json(json!({ "client_id": "client-abc" }))
            }
        }
    };
    // Auto-approving "user": bounce straight back to the loopback redirect
    // with a code, like a browser session that clicked Approve.
    let authorize = {
        let state = state.clone();
        let base = base.clone();
        move |axum::extract::Query(query): axum::extract::Query<HashMap<String, String>>| {
            let state = state.clone();
            let base = base.clone();
            async move {
                assert_eq!(query.get("response_type").map(String::as_str), Some("code"));
                assert_eq!(
                    query.get("client_id").map(String::as_str),
                    Some("client-abc")
                );
                assert_eq!(
                    query.get("code_challenge_method").map(String::as_str),
                    Some("S256")
                );
                assert!(query.get("resource").is_some_and(|r| r.ends_with("/mcp")));
                let redirect = query.get("redirect_uri").expect("redirect_uri").clone();
                let nonce = query.get("state").expect("state").clone();
                let issuer = {
                    let mut state = state.lock().unwrap();
                    state.code_challenge =
                        Some(query.get("code_challenge").expect("challenge").clone());
                    state.response_iss.clone().unwrap_or(base)
                };
                let mut callback = url::Url::parse(&redirect).unwrap();
                callback
                    .query_pairs_mut()
                    .append_pair("code", AUTH_CODE)
                    .append_pair("state", &nonce)
                    .append_pair("iss", &issuer);
                axum::response::Redirect::to(callback.as_str())
            }
        }
    };
    let token = {
        let state = state.clone();
        let base = base.clone();
        move |axum::extract::Form(form): axum::extract::Form<HashMap<String, String>>| {
            let state = state.clone();
            let base = base.clone();
            async move {
                let expected_resource = format!("{base}/mcp");
                assert_eq!(
                    form.get("resource").map(String::as_str),
                    Some(expected_resource.as_str())
                );
                // A silent renewal: honor the current refresh token, rotate
                // both tokens, and start rejecting the previous bearer.
                if form.get("grant_type").map(String::as_str) == Some("refresh_token") {
                    assert_eq!(
                        form.get("client_id").map(String::as_str),
                        Some("client-abc")
                    );
                    let mut locked = state.lock().unwrap();
                    locked.refresh_requests += 1;
                    if locked.valid_refresh.as_deref()
                        != form.get("refresh_token").map(String::as_str)
                    {
                        return axum::http::Response::builder()
                            .status(400)
                            .header("content-type", "application/json")
                            .body(axum::body::Body::from(
                                json!({ "error": "invalid_grant" }).to_string(),
                            ))
                            .unwrap();
                    }
                    locked.current_access = RENEWED_TOKEN.into();
                    locked.valid_refresh = Some(ROTATED_REFRESH_TOKEN.into());
                    return axum::http::Response::builder()
                        .status(200)
                        .header("content-type", "application/json")
                        .body(axum::body::Body::from(
                            json!({
                                "access_token": RENEWED_TOKEN,
                                "refresh_token": ROTATED_REFRESH_TOKEN,
                                "token_type": "Bearer",
                                "expires_in": 3600,
                            })
                            .to_string(),
                        ))
                        .unwrap();
                }
                assert_eq!(
                    form.get("grant_type").map(String::as_str),
                    Some("authorization_code")
                );
                assert_eq!(form.get("code").map(String::as_str), Some(AUTH_CODE));
                // PKCE actually verified: the verifier must hash to the
                // challenge captured at /authorize.
                let verifier = form.get("code_verifier").expect("code_verifier");
                let hashed = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(sha2::Sha256::digest(verifier.as_bytes()));
                let mut locked = state.lock().unwrap();
                assert_eq!(Some(hashed), locked.code_challenge);
                locked.token_requests += 1;
                axum::http::Response::builder()
                    .status(200)
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        json!({
                            "access_token": ACCESS_TOKEN,
                            "refresh_token": REFRESH_TOKEN,
                            "token_type": "Bearer",
                            "expires_in": 3600,
                        })
                        .to_string(),
                    ))
                    .unwrap()
            }
        }
    };

    let app = axum::Router::new()
        .route("/mcp", axum::routing::post(mcp).delete(mcp_delete))
        .route(
            "/.well-known/oauth-protected-resource/mcp",
            axum::routing::get(resource_meta),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            axum::routing::get(as_meta),
        )
        .route("/register", axum::routing::post(register))
        .route("/authorize", axum::routing::get(authorize))
        .route("/token", axum::routing::post(token));
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (port, state)
}

async fn uds_json_request(socket: &std::path::Path, token: &str, body: Value) -> (u16, Value) {
    let stream = tokio::net::UnixStream::connect(socket).await.unwrap();
    let io = hyper_util::rt::TokioIo::new(stream);
    let (mut sender, connection) = hyper::client::conn::http1::handshake(io).await.unwrap();
    tokio::spawn(connection);
    let request = hyper::Request::builder()
        .method("POST")
        .uri("/v1/http")
        .header("host", "localhost")
        .header("authorization", format!("Bearer {token}"))
        .header("x-agentmfa-client", "codex")
        .header("content-type", "application/json")
        .body(body.to_string())
        .unwrap();
    let response = sender.send_request(request).await.unwrap();
    let status = response.status().as_u16();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&bytes).unwrap())
}

/// A Google-style vendor: the MCP endpoint answers `initialize` without
/// authentication, the authorization server publishes no registration
/// endpoint, and the token endpoint expects the pre-registered client's
/// secret alongside PKCE.
async fn spawn_preset_client_vendor() -> u16 {
    const CLIENT_ID: &str = "preset-client-123";
    const CLIENT_SECRET: &str = "preset-secret-xyz";
    let challenge: Arc<Mutex<Option<String>>> = Arc::default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind vendor");
    let port = listener.local_addr().expect("addr").port();
    let base = format!("http://127.0.0.1:{port}");

    let mcp = move |body: axum::Json<Value>| async move {
        if body.0.get("id").is_none() {
            return axum::http::Response::builder()
                .status(202)
                .body(axum::body::Body::empty())
                .unwrap();
        }
        let reply = json!({
            "jsonrpc": "2.0",
            "id": body.0["id"],
            "result": mcp_result(body.0["method"].as_str()),
        });
        axum::http::Response::builder()
            .status(200)
            .header("content-type", "application/json")
            .header("mcp-session-id", "mock-session-2")
            .body(axum::body::Body::from(reply.to_string()))
            .unwrap()
    };
    let resource_meta = {
        let base = base.clone();
        move || {
            let base = base.clone();
            async move {
                axum::Json(json!({
                    "resource": format!("{base}/mcp"),
                    "authorization_servers": [base],
                    "scopes_supported": ["mail.everything"],
                }))
            }
        }
    };
    let as_meta = {
        let base = base.clone();
        move || {
            let base = base.clone();
            async move {
                axum::Json(json!({
                    "issuer": base,
                    "authorization_endpoint": format!("{base}/authorize"),
                    "token_endpoint": format!("{base}/token"),
                }))
            }
        }
    };
    let authorize = {
        let challenge = challenge.clone();
        move |axum::extract::Query(query): axum::extract::Query<HashMap<String, String>>| {
            let challenge = challenge.clone();
            async move {
                assert_eq!(query.get("client_id").map(String::as_str), Some(CLIENT_ID));
                // The draft's scope override wins over scopes_supported,
                // and the extra authorize params ride along.
                assert_eq!(query.get("scope").map(String::as_str), Some("mail.read"));
                assert_eq!(
                    query.get("access_type").map(String::as_str),
                    Some("offline")
                );
                let redirect = query.get("redirect_uri").expect("redirect_uri").clone();
                let nonce = query.get("state").expect("state").clone();
                *challenge.lock().unwrap() =
                    Some(query.get("code_challenge").expect("challenge").clone());
                axum::response::Redirect::to(&format!("{redirect}?code={AUTH_CODE}&state={nonce}"))
            }
        }
    };
    let token = {
        let challenge = challenge.clone();
        move |axum::extract::Form(form): axum::extract::Form<HashMap<String, String>>| {
            let challenge = challenge.clone();
            async move {
                assert_eq!(form.get("client_id").map(String::as_str), Some(CLIENT_ID));
                assert_eq!(
                    form.get("client_secret").map(String::as_str),
                    Some(CLIENT_SECRET)
                );
                let verifier = form.get("code_verifier").expect("code_verifier");
                let hashed = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(sha2::Sha256::digest(verifier.as_bytes()));
                assert_eq!(Some(hashed), *challenge.lock().unwrap());
                axum::Json(json!({
                    "access_token": ACCESS_TOKEN,
                    "refresh_token": REFRESH_TOKEN,
                    "token_type": "Bearer",
                    "expires_in": 3600,
                }))
            }
        }
    };

    let app = axum::Router::new()
        .route("/mcp", axum::routing::post(mcp))
        .route(
            "/.well-known/oauth-protected-resource/mcp",
            axum::routing::get(resource_meta),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            axum::routing::get(as_meta),
        )
        .route("/authorize", axum::routing::get(authorize))
        .route("/token", axum::routing::post(token));
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    port
}

async fn test_broker() -> (Arc<Broker>, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let paths = Paths::under(dir.path());
    paths.ensure().expect("paths");
    let broker = Broker::new(
        paths,
        Arc::new(MemoryVault::new()),
        BrokerConfig::default(),
        Arc::new(NoopEvents),
    )
    .await
    .expect("broker");
    (broker, dir)
}

async fn wait_for<F>(broker: &Broker, id: &Uuid, what: &str, predicate: F) -> McpAuthState
where
    F: Fn(&McpAuthState) -> bool,
{
    for _ in 0..200 {
        if let Some(state) = broker.ui_mcp_auth_state(id) {
            if predicate(&state) {
                return state;
            }
            if state.phase.is_terminal() {
                panic!("flow ended before {what}: {:?}", state.phase);
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out waiting for {what}");
}

/// Drive one full sign-in (playing the browser's part) and return the
/// minted connection.
async fn complete_sign_in(
    broker: &Arc<Broker>,
    port: u16,
    name: &str,
) -> aka_core::types::Connection {
    let started = broker
        .ui_start_mcp_auth(McpAuthDraft {
            name: name.into(),
            scheme: "http".into(),
            host: "127.0.0.1".into(),
            port: Some(port),
            mcp_path: "/mcp".into(),
            reauth_connection_id: None,
            whoami_tool: None,
            ..Default::default()
        })
        .expect("start auth");
    let session_id = Uuid::parse_str(&started.id).expect("session id");
    let awaiting = wait_for(broker, &session_id, "the browser step", |state| {
        matches!(state.phase, McpAuthPhase::AwaitingAuthorization { .. })
    })
    .await;
    let McpAuthPhase::AwaitingAuthorization { authorization_url } = &awaiting.phase else {
        unreachable!();
    };
    reqwest::Client::new()
        .get(authorization_url)
        .send()
        .await
        .expect("authorize hop");
    wait_for(broker, &session_id, "completion", |state| {
        matches!(state.phase, McpAuthPhase::Succeeded { .. })
    })
    .await;
    broker
        .store
        .connection_by_name(name)
        .expect("connection created")
}

#[tokio::test]
async fn auth_can_be_started_from_a_thread_without_a_tokio_context() {
    let (broker, _dir) = test_broker().await;
    let caller = broker.clone();

    let started = std::thread::spawn(move || {
        caller.ui_start_mcp_auth(McpAuthDraft {
            name: "Threaded MCP".into(),
            scheme: "http".into(),
            host: "127.0.0.1".into(),
            port: Some(9),
            mcp_path: "/mcp".into(),
            reauth_connection_id: None,
            whoami_tool: None,
            ..Default::default()
        })
    })
    .join()
    .expect("MCP auth start must not panic without an entered Tokio runtime")
    .expect("start auth");

    assert!(matches!(started.phase, McpAuthPhase::Probing));
    let session_id = Uuid::parse_str(&started.id).expect("session id");
    assert!(broker.ui_cancel_mcp_auth(&session_id));
}

#[tokio::test]
async fn oauth_sign_in_mints_a_connection_and_the_status_check_acknowledges_it() {
    let (port, vendor) = spawn_mock_vendor().await;
    let (broker, _dir) = test_broker().await;

    let started = broker
        .ui_start_mcp_auth(McpAuthDraft {
            name: "github-test".into(),
            scheme: "http".into(),
            host: "127.0.0.1".into(),
            port: Some(port),
            mcp_path: "/mcp".into(),
            reauth_connection_id: None,
            whoami_tool: Some("get_me".into()),
            ..Default::default()
        })
        .expect("start auth");
    let session_id = Uuid::parse_str(&started.id).expect("session id");

    // Nothing exists until the dance completes.
    assert!(broker.store.connection_by_name("github-test").is_none());

    // Play the browser: follow the authorization URL; the mock AS
    // auto-approves and redirects to the flow's loopback listener.
    let awaiting = wait_for(&broker, &session_id, "the browser step", |state| {
        matches!(state.phase, McpAuthPhase::AwaitingAuthorization { .. })
    })
    .await;
    let McpAuthPhase::AwaitingAuthorization { authorization_url } = &awaiting.phase else {
        unreachable!();
    };
    let browser = reqwest::Client::new();
    let landing = browser
        .get(authorization_url)
        .send()
        .await
        .expect("authorize hop");
    assert!(landing.status().is_success());
    assert!(landing
        .text()
        .await
        .expect("landing page")
        .contains("connected"));

    let done = wait_for(&broker, &session_id, "completion", |state| {
        state.phase.is_terminal()
    })
    .await;
    let McpAuthPhase::Succeeded {
        connection_name,
        account,
        expires_in,
        warning,
        ..
    } = &done.phase
    else {
        panic!("expected success, got {:?}", done.phase);
    };
    assert_eq!(connection_name, "github-test");
    assert_eq!(account.as_deref(), Some("Octo Cat (@octocat)"));
    assert_eq!(*expires_in, Some(3600));
    assert_eq!(*warning, None);
    assert_eq!(vendor.lock().unwrap().token_requests, 1);

    // The connection exists, pinned to the vendor, with the token in the
    // vault under the derived name and the account persisted.
    let connection = broker
        .store
        .connection_by_name("github-test")
        .expect("connection created");
    let ConnectionConfig::Api {
        template, mcp_path, ..
    } = &connection.config
    else {
        panic!("not an api connection");
    };
    assert_eq!(mcp_path.as_deref(), Some("/mcp"));
    assert_eq!(template, "Authorization: Bearer {{GITHUB_TEST_MCP_TOKEN}}");
    assert_eq!(connection.account.as_deref(), Some("Octo Cat (@octocat)"));
    let secret = broker
        .store
        .list_secrets()
        .into_iter()
        .find(|meta| meta.name == "GITHUB_TEST_MCP_TOKEN")
        .expect("token stored");
    let value = broker.store.secret_value(&secret.id).await.expect("value");
    assert_eq!(&*value, ACCESS_TOKEN);

    // The status button's path: reachable, account acknowledged, tools
    // checked against the template, resources listed.
    let report = broker
        .ui_mcp_check(
            &connection.id,
            McpCheckOptions {
                whoami_tool: Some("get_me".into()),
            },
        )
        .await
        .expect("status check");
    assert!(report.ok, "{}", report.detail);
    assert_eq!(report.server.as_deref(), Some("mock-mcp 1.0.0"));
    assert_eq!(report.account.as_deref(), Some("Octo Cat (@octocat)"));
    assert_eq!(report.tools, vec!["get_me", "search"]);
    assert!(report.resources_supported);
    assert_eq!(report.resources.len(), 1);
    assert_eq!(report.resources[0].uri, "mock://repos/one");
    assert_eq!(report.resources[0].name, "Repo One");
    let status_audit = broker
        .audit
        .recent(20)
        .into_iter()
        .find(|entry| {
            entry.fields.get("mcp_name") == Some(&json!("get_me"))
                && entry.fields.get("mcp_method") == Some(&json!("tools/call"))
        })
        .expect("the guarded status tool invocation is audited");
    assert_eq!(status_audit.connection.as_deref(), Some("github-test"));

    // A curated subset also governs the management-plane status helper.
    broker
        .ui_set_allowed_tools(&connection.id, Some(vec!["search".into()]))
        .unwrap();
    let restricted = broker
        .ui_mcp_check(
            &connection.id,
            McpCheckOptions {
                whoami_tool: Some("get_me".into()),
            },
        )
        .await
        .expect("restricted status check");
    assert!(restricted.ok);
    assert_eq!(restricted.account, None);

    // Nor can a compromised webview nominate an arbitrary listed tool.
    let arbitrary = broker
        .ui_mcp_check(
            &connection.id,
            McpCheckOptions {
                whoami_tool: Some("search".into()),
            },
        )
        .await
        .expect("guarded status check");
    assert!(arbitrary.ok);
    assert_eq!(arbitrary.account, None);
    assert!(
        vendor.lock().unwrap().mcp_session_deletes >= 2,
        "post-auth verification and the status check must tear down their sessions"
    );

    // Multiple accounts on one target: the same dance again is simply a
    // second connection with its own token — nothing deduplicates them.
    let second = broker
        .ui_start_mcp_auth(McpAuthDraft {
            name: "github-personal".into(),
            scheme: "http".into(),
            host: "127.0.0.1".into(),
            port: Some(port),
            mcp_path: "/mcp".into(),
            reauth_connection_id: None,
            whoami_tool: None,
            ..Default::default()
        })
        .expect("second auth");
    let second_id = Uuid::parse_str(&second.id).expect("session id");
    let awaiting = wait_for(&broker, &second_id, "the second browser step", |state| {
        matches!(state.phase, McpAuthPhase::AwaitingAuthorization { .. })
    })
    .await;
    let McpAuthPhase::AwaitingAuthorization { authorization_url } = &awaiting.phase else {
        unreachable!();
    };
    browser
        .get(authorization_url)
        .send()
        .await
        .expect("second authorize hop");
    wait_for(&broker, &second_id, "second completion", |state| {
        matches!(state.phase, McpAuthPhase::Succeeded { .. })
    })
    .await;
    let names: Vec<String> = broker
        .store
        .list_connections()
        .into_iter()
        .map(|connection| connection.name)
        .collect();
    assert!(names.contains(&"github-test".to_string()));
    assert!(names.contains(&"github-personal".to_string()));
    // Two tokens for one target MCP, held under distinct vault names.
    let secrets: Vec<String> = broker
        .store
        .list_secrets()
        .into_iter()
        .map(|meta| meta.name)
        .collect();
    assert!(secrets.contains(&"GITHUB_TEST_MCP_TOKEN".to_string()));
    assert!(secrets.contains(&"GITHUB_PERSONAL_MCP_TOKEN".to_string()));
}

#[tokio::test]
async fn an_authorization_response_from_the_wrong_issuer_is_rejected_end_to_end() {
    let (port, vendor) = spawn_mock_vendor().await;
    vendor.lock().unwrap().response_iss = Some("https://attacker.example".into());
    let (broker, _dir) = test_broker().await;
    let started = broker
        .ui_start_mcp_auth(McpAuthDraft {
            name: "issuer-mismatch".into(),
            scheme: "http".into(),
            host: "127.0.0.1".into(),
            port: Some(port),
            mcp_path: "/mcp".into(),
            ..Default::default()
        })
        .unwrap();
    let session_id = Uuid::parse_str(&started.id).unwrap();
    let awaiting = wait_for(&broker, &session_id, "the browser step", |state| {
        matches!(state.phase, McpAuthPhase::AwaitingAuthorization { .. })
    })
    .await;
    let McpAuthPhase::AwaitingAuthorization { authorization_url } = awaiting.phase else {
        unreachable!()
    };
    let _ = reqwest::Client::new().get(authorization_url).send().await;
    let failed = wait_for(&broker, &session_id, "issuer rejection", |state| {
        state.phase.is_terminal()
    })
    .await;
    let McpAuthPhase::Failed { message, .. } = failed.phase else {
        panic!("issuer mismatch unexpectedly succeeded")
    };
    assert!(message.contains("unexpected issuer"), "{message}");
    assert!(broker.store.connection_by_name("issuer-mismatch").is_none());
}

#[tokio::test]
async fn expired_tokens_refresh_silently_and_a_dead_refresh_token_falls_back_to_reconnect() {
    let (port, vendor) = spawn_mock_vendor().await;
    let (broker, _dir) = test_broker().await;
    let connection = complete_sign_in(&broker, port, "github-refresh").await;

    // Sign-in stored the refresh grant: the linkage and expiry on the
    // connection, and the grant JSON (refresh token, client identity,
    // token endpoint) in its own vault item — never a listed secret.
    let oauth = connection.oauth.clone().expect("refresh grant linkage");
    assert!(oauth.expires_at.is_some());
    let secret_names: Vec<String> = broker
        .store
        .list_secrets()
        .into_iter()
        .map(|meta| meta.name)
        .collect();
    assert_eq!(secret_names, ["GITHUB_REFRESH_MCP_TOKEN"]);
    let grant: Value = serde_json::from_str(
        &broker
            .store
            .connection_oauth_grant(&connection.id)
            .await
            .expect("grant stored"),
    )
    .expect("grant is JSON");
    assert_eq!(grant["refresh_token"], json!(REFRESH_TOKEN));
    assert_eq!(grant["client_id"], json!("client-abc"));

    // The upstream stops accepting the access token mid-life. The status
    // check does not surface "credential rejected": it renews silently
    // with the stored refresh token and retries.
    vendor.lock().unwrap().current_access = "no-longer-accepted".into();
    let report = broker
        .ui_mcp_check(&connection.id, McpCheckOptions::default())
        .await
        .expect("status check");
    assert!(report.ok, "{}", report.detail);
    assert_eq!(vendor.lock().unwrap().refresh_requests, 1);
    // A silent renewal is observable: its own activity kind, attributed to
    // the connection.
    let renewed = broker
        .audit
        .recent(10)
        .into_iter()
        .find(|entry| matches!(entry.kind, aka_core::audit::AuditKind::McpTokenRefreshed))
        .expect("renewal audited");
    assert_eq!(renewed.connection.as_deref(), Some("github-refresh"));
    // The vault-held token was replaced with the renewed one…
    let secret = broker
        .store
        .list_secrets()
        .into_iter()
        .find(|meta| meta.name == "GITHUB_REFRESH_MCP_TOKEN")
        .expect("token secret");
    assert_eq!(
        &*broker.store.secret_value(&secret.id).await.expect("value"),
        RENEWED_TOKEN
    );
    // …and the rotated refresh token was kept for next time.
    let grant: Value = serde_json::from_str(
        &broker
            .store
            .connection_oauth_grant(&connection.id)
            .await
            .expect("grant"),
    )
    .expect("grant is JSON");
    assert_eq!(grant["refresh_token"], json!(ROTATED_REFRESH_TOKEN));

    // Pre-emptive path: an expiry inside the refresh window renews before
    // the check runs, even though the upstream still accepts the token.
    let raw = broker
        .store
        .connection_oauth_grant(&connection.id)
        .await
        .expect("grant");
    broker
        .store
        .set_connection_oauth(&connection.id, raw, Some(chrono::Utc::now()))
        .expect("age the token");
    let report = broker
        .ui_mcp_check(&connection.id, McpCheckOptions::default())
        .await
        .expect("status check");
    assert!(report.ok, "{}", report.detail);
    assert_eq!(vendor.lock().unwrap().refresh_requests, 2);

    // A dead refresh token: the provider answers invalid_grant, the broker
    // retires the stored refresh token (no endless replays), and the check
    // finally reports the rejected credential — the Reconnect path.
    {
        let mut locked = vendor.lock().unwrap();
        locked.valid_refresh = None;
        locked.current_access = "rotated-away".into();
    }
    let raw = broker
        .store
        .connection_oauth_grant(&connection.id)
        .await
        .expect("grant");
    broker
        .store
        .set_connection_oauth(&connection.id, raw, Some(chrono::Utc::now()))
        .expect("age the token");
    let report = broker
        .ui_mcp_check(&connection.id, McpCheckOptions::default())
        .await
        .expect("status check");
    assert!(!report.ok);
    assert!(report.credential_rejected, "{}", report.detail);
    // The failed renewal is observable too — the activity trail explains
    // why the row now says "needs reconnect".
    assert!(
        broker.audit.recent(10).iter().any(|entry| matches!(
            entry.kind,
            aka_core::audit::AuditKind::McpTokenRefreshFailed
        )),
        "rejected renewal audited"
    );
    let health = broker.health.get(&connection.id).expect("health recorded");
    assert_eq!(health.status, aka_core::types::HealthStatus::NeedsReconnect);
    let grant: Value = serde_json::from_str(
        &broker
            .store
            .connection_oauth_grant(&connection.id)
            .await
            .expect("grant"),
    )
    .expect("grant is JSON");
    assert_eq!(grant["refresh_token"], json!(null), "refresh token retired");
}

#[tokio::test]
async fn agent_mcp_traffic_recovers_once_from_an_early_oauth_rejection() {
    let (port, vendor) = spawn_mock_vendor().await;
    let (broker, _dir) = test_broker().await;
    let connection = complete_sign_in(&broker, port, "github-agent-refresh").await;
    let before = {
        let locked = vendor.lock().unwrap();
        (
            locked.mcp_authorized_requests,
            locked.mcp_rejected_requests,
            locked.refresh_requests,
        )
    };

    // No expires_in signal changed: the upstream simply revoked this access
    // token early. The first tools/call gets a 401, renewal rotates the bearer,
    // and the broker replays exactly once. A 401 is a rejected operation, so
    // the mutating tool itself is accepted only once.
    vendor.lock().unwrap().current_access = "revoked-early".into();
    let daemon = daemon::serve(broker.clone()).await.unwrap();
    let token = broker.identity.token();
    let (status, response) = uds_json_request(
        &daemon.socket_path,
        &token,
        json!({
            "connection": connection.name,
            "method": "POST",
            "path": "/mcp",
            "headers": {
                "content-type": "application/json",
                "accept": "application/json, text/event-stream"
            },
            "body": {
                "jsonrpc": "2.0",
                "id": 91,
                "method": "tools/call",
                "params": { "name": "write_issue", "arguments": { "title": "one" } }
            }
        }),
    )
    .await;
    assert_eq!(status, 200, "{response}");
    assert_eq!(response["status"], 200, "{response}");
    let upstream_body: Value =
        serde_json::from_str(response["body"].as_str().expect("utf8 MCP body")).unwrap();
    assert_eq!(upstream_body["id"], 91);

    let after = vendor.lock().unwrap();
    assert_eq!(after.refresh_requests, before.2 + 1);
    assert_eq!(after.mcp_rejected_requests, before.1 + 1);
    assert_eq!(
        after.mcp_authorized_requests,
        before.0 + 1,
        "the tool operation must not execute twice"
    );
}

#[tokio::test]
async fn a_server_that_never_asks_for_auth_fails_with_a_token_hint() {
    // A wide-open server: initialize answers 200 with no challenge.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind open server");
    let port = listener.local_addr().expect("addr").port();
    let app = axum::Router::new().route(
        "/mcp",
        axum::routing::post(|body: axum::Json<Value>| async move {
            axum::Json(json!({
                "jsonrpc": "2.0", "id": body.0["id"],
                "result": mcp_result(body.0["method"].as_str()),
            }))
        }),
    );
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let (broker, _dir) = test_broker().await;
    let started = broker
        .ui_start_mcp_auth(McpAuthDraft {
            name: "open-server".into(),
            scheme: "http".into(),
            host: "127.0.0.1".into(),
            port: Some(port),
            mcp_path: "/mcp".into(),
            reauth_connection_id: None,
            whoami_tool: None,
            ..Default::default()
        })
        .expect("start auth");
    let session_id = Uuid::parse_str(&started.id).expect("session id");
    let done = wait_for(&broker, &session_id, "failure", |state| {
        state.phase.is_terminal()
    })
    .await;
    let McpAuthPhase::Failed { message, hint } = &done.phase else {
        panic!("expected failure, got {:?}", done.phase);
    };
    assert!(
        message.contains("without asking for authentication"),
        "{message}"
    );
    assert!(
        hint.as_deref().unwrap_or_default().contains("token"),
        "{hint:?}"
    );
    assert!(broker.store.connection_by_name("open-server").is_none());
}

#[tokio::test]
async fn a_preset_client_signs_in_without_dynamic_registration() {
    let port = spawn_preset_client_vendor().await;
    let (broker, _dir) = test_broker().await;

    let started = broker
        .ui_start_mcp_auth(McpAuthDraft {
            name: "gmail-style".into(),
            scheme: "http".into(),
            host: "127.0.0.1".into(),
            port: Some(port),
            mcp_path: "/mcp".into(),
            oauth_client_id: Some("preset-client-123".into()),
            oauth_client_secret: Some("preset-secret-xyz".into()),
            oauth_scope: Some("mail.read".into()),
            // The reserved-key duplicate must be dropped by the broker: on
            // a last-wins authorization server it would redirect the code
            // to the attacker. (The mock's Query extractor is last-wins,
            // so an unfiltered duplicate breaks the loopback callback and
            // this test times out.)
            extra_auth_params: vec![
                ("access_type".into(), "offline".into()),
                ("redirect_uri".into(), "https://evil.example/cb".into()),
            ],
            whoami_tool: Some("get_me".into()),
            ..Default::default()
        })
        .expect("start auth");
    let session_id = Uuid::parse_str(&started.id).expect("session id");

    // The open probe (2xx initialize) must not end the flow: with a client
    // in hand it proceeds to discovery and the browser step.
    let awaiting = wait_for(&broker, &session_id, "the browser step", |state| {
        matches!(state.phase, McpAuthPhase::AwaitingAuthorization { .. })
    })
    .await;
    let McpAuthPhase::AwaitingAuthorization { authorization_url } = &awaiting.phase else {
        unreachable!();
    };
    reqwest::Client::new()
        .get(authorization_url)
        .send()
        .await
        .expect("authorize hop");
    let done = wait_for(&broker, &session_id, "completion", |state| {
        matches!(state.phase, McpAuthPhase::Succeeded { .. })
    })
    .await;
    let McpAuthPhase::Succeeded { account, .. } = &done.phase else {
        unreachable!();
    };
    assert_eq!(account.as_deref(), Some("Octo Cat (@octocat)"));

    // The stored grant carries the preset client, so silent refresh and
    // reconnect can reuse it without asking again.
    let connection = broker
        .store
        .connection_by_name("gmail-style")
        .expect("connection created");
    let stored = broker
        .store
        .connection_oauth_grant(&connection.id)
        .await
        .expect("grant stored");
    let grant =
        aka_core::mcp_auth::McpOAuthGrant::from_secret_value(&stored).expect("grant parses");
    assert_eq!(grant.client_id, "preset-client-123");
    assert_eq!(grant.client_secret.as_deref(), Some("preset-secret-xyz"));
    assert_eq!(grant.refresh_token.as_deref(), Some(REFRESH_TOKEN));
}

#[tokio::test]
async fn a_bad_draft_is_rejected_before_any_browser_opens() {
    let (broker, _dir) = test_broker().await;
    // Plain http to a non-loopback host is refused up front.
    let error = broker
        .ui_start_mcp_auth(McpAuthDraft {
            name: "insecure".into(),
            scheme: "http".into(),
            host: "mcp.example.com".into(),
            port: None,
            mcp_path: "/mcp".into(),
            reauth_connection_id: None,
            whoami_tool: None,
            ..Default::default()
        })
        .unwrap_err();
    assert!(error.to_string().contains("https"), "{error}");
    assert!(broker.ui_mcp_auth_state(&Uuid::new_v4()).is_none());
}

#[tokio::test]
async fn an_external_redirect_sign_in_completes_via_code_delivery() {
    // The remote-shell shape: the catcher lives with the caller (here, the
    // test), the broker never binds a listener, and the code goes back in
    // through the manage-plane delivery entry point.
    let (port, _vendor) = spawn_mock_vendor().await;
    let (broker, _dir) = test_broker().await;

    let catcher = aka_core::oauth::LoopbackCatcher::bind()
        .await
        .expect("bind catcher");
    let started = broker
        .ui_start_mcp_auth_external(
            McpAuthDraft {
                name: "github-remote".into(),
                scheme: "http".into(),
                host: "127.0.0.1".into(),
                port: Some(port),
                mcp_path: "/mcp".into(),
                reauth_connection_id: None,
                whoami_tool: Some("get_me".into()),
                ..Default::default()
            },
            &catcher.redirect_uri(),
        )
        .expect("start external auth");
    let session_id = Uuid::parse_str(&started.id).expect("session id");

    // A non-loopback redirect target is refused up front.
    assert!(broker
        .ui_start_mcp_auth_external(
            McpAuthDraft {
                name: "evil".into(),
                scheme: "http".into(),
                host: "127.0.0.1".into(),
                port: Some(port),
                mcp_path: "/mcp".into(),
                ..Default::default()
            },
            "https://attacker.example.dev/callback",
        )
        .is_err());

    let awaiting = wait_for(&broker, &session_id, "the browser step", |state| {
        matches!(state.phase, McpAuthPhase::AwaitingAuthorization { .. })
    })
    .await;
    let McpAuthPhase::AwaitingAuthorization { authorization_url } = &awaiting.phase else {
        unreachable!();
    };
    // The authorize URL carries the *caller's* redirect, not a broker port.
    let parsed = reqwest::Url::parse(authorization_url).expect("authorize url");
    let pairs: HashMap<_, _> = parsed.query_pairs().into_owned().collect();
    assert_eq!(pairs["redirect_uri"], catcher.redirect_uri());

    // Play the browser: the mock AS auto-approves and redirects to the
    // catcher; hand its (code, state) back through delivery.
    let browser = reqwest::Client::new();
    let (landing, redirect) = tokio::join!(
        browser.get(authorization_url).send(),
        catcher.wait_for_redirect(),
    );
    assert!(landing.expect("authorize hop").status().is_success());
    let (code, state, iss) = redirect.expect("redirect reaches the catcher");
    // A wrong state is refused without consuming the session's waiter...
    // (the sender is one-shot, so verify only the happy path here.)
    assert!(broker.ui_mcp_auth_deliver_code(&session_id, code, state, iss));
    // A second delivery has nothing to fulfill.
    assert!(!broker.ui_mcp_auth_deliver_code(&session_id, "again".into(), "x".into(), None));

    let done = wait_for(&broker, &session_id, "completion", |state| {
        state.phase.is_terminal()
    })
    .await;
    let McpAuthPhase::Succeeded {
        connection_name, ..
    } = &done.phase
    else {
        panic!("expected success, got {:?}", done.phase);
    };
    assert_eq!(connection_name, "github-remote");
    assert!(broker.store.connection_by_name("github-remote").is_some());
}
