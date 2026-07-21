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
use aka_core::events::NoopEvents;
use aka_core::mcp::McpCheckOptions;
use aka_core::mcp_auth::{McpAuthDraft, McpAuthPhase, McpAuthState};
use aka_core::paths::Paths;
use aka_core::types::ConnectionConfig;
use aka_core::vault::MemoryVault;
use base64::Engine as _;
use serde_json::{json, Value};
use sha2::Digest as _;
use uuid::Uuid;

const ACCESS_TOKEN: &str = "test-token-issued-by-mock";
const AUTH_CODE: &str = "test-code-1";

#[derive(Default)]
struct MockAuthServer {
    code_challenge: Option<String>,
    registered_redirect: Option<String>,
    token_requests: u32,
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
                { "name": "get_me", "inputSchema": { "type": "object" } },
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
        move |headers: axum::http::HeaderMap, body: axum::Json<Value>| {
            let base = base.clone();
            async move {
                let authorized = headers
                    .get("authorization")
                    .and_then(|value| value.to_str().ok())
                    == Some(&format!("Bearer {ACCESS_TOKEN}"));
                if !authorized {
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
                }))
            }
        }
    };
    let register = {
        let state = state.clone();
        move |body: axum::Json<Value>| {
            let state = state.clone();
            async move {
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
        move |axum::extract::Query(query): axum::extract::Query<HashMap<String, String>>| {
            let state = state.clone();
            async move {
                assert_eq!(query.get("response_type").map(String::as_str), Some("code"));
                assert_eq!(query.get("client_id").map(String::as_str), Some("client-abc"));
                assert_eq!(
                    query.get("code_challenge_method").map(String::as_str),
                    Some("S256")
                );
                assert!(query.get("resource").is_some_and(|r| r.ends_with("/mcp")));
                let redirect = query.get("redirect_uri").expect("redirect_uri").clone();
                let nonce = query.get("state").expect("state").clone();
                state.lock().unwrap().code_challenge =
                    Some(query.get("code_challenge").expect("challenge").clone());
                axum::response::Redirect::to(&format!(
                    "{redirect}?code={AUTH_CODE}&state={nonce}"
                ))
            }
        }
    };
    let token = {
        let state = state.clone();
        move |axum::extract::Form(form): axum::extract::Form<HashMap<String, String>>| {
            let state = state.clone();
            async move {
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
                axum::Json(json!({
                    "access_token": ACCESS_TOKEN,
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
        .route("/register", axum::routing::post(register))
        .route("/authorize", axum::routing::get(authorize))
        .route("/token", axum::routing::post(token));
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (port, state)
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
            expected_tools: vec!["get_me".into(), "definitely_missing".into()],
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
    assert!(landing.text().await.expect("landing page").contains("connected"));

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
                expected_tools: vec!["get_me".into(), "definitely_missing".into()],
            },
        )
        .await
        .expect("status check");
    assert!(report.ok, "{}", report.detail);
    assert_eq!(report.server.as_deref(), Some("mock-mcp 1.0.0"));
    assert_eq!(report.account.as_deref(), Some("Octo Cat (@octocat)"));
    assert_eq!(report.tools, vec!["get_me", "search"]);
    assert_eq!(report.missing_tools, vec!["definitely_missing"]);
    assert!(report.resources_supported);
    assert_eq!(report.resources.len(), 1);
    assert_eq!(report.resources[0].uri, "mock://repos/one");
    assert_eq!(report.resources[0].name, "Repo One");

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
            expected_tools: vec![],
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
            expected_tools: vec![],
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
    assert!(message.contains("without asking for authentication"), "{message}");
    assert!(hint.as_deref().unwrap_or_default().contains("token"), "{hint:?}");
    assert!(broker.store.connection_by_name("open-server").is_none());
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
            expected_tools: vec![],
        })
        .unwrap_err();
    assert!(error.to_string().contains("https"), "{error}");
    assert!(broker.ui_mcp_auth_state(&Uuid::new_v4()).is_none());
}
