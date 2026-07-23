//! Manage-plane tests: a real daemon on a real Unix socket, driven the way
//! a remote desktop shell drives it — bearer `akamgr_…` token, JSON bodies,
//! `aka-api` error shapes, and the SSE change feed.

use std::sync::Arc;

use aka_core::broker::Broker;
use aka_core::config::BrokerConfig;
use aka_core::daemon;
use aka_core::events::BrokerEvents;
use aka_core::paths::Paths;
use aka_core::types::{ConfirmationMethod, SecretMeta};
use aka_core::vault::MemoryVault;
use http_body_util::BodyExt as _;
use serde_json::{json, Value};

struct TestEvents;

impl BrokerEvents for TestEvents {
    fn confirm_secret_read(&self, _secret: &SecretMeta) -> bool {
        true
    }
    fn confirm_action(&self, _description: &str) -> Option<ConfirmationMethod> {
        Some(ConfirmationMethod::ManagementToken)
    }
}

struct Harness {
    broker: Arc<Broker>,
    _daemon: daemon::DaemonHandle,
    socket: std::path::PathBuf,
    manage_token: String,
    _dir: tempfile::TempDir,
}

async fn harness() -> Harness {
    let config = BrokerConfig {
        version: "test".into(),
        ..BrokerConfig::default()
    };
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::under(dir.path());
    let broker = Broker::new(
        paths,
        Arc::new(MemoryVault::new()),
        config,
        Arc::new(TestEvents),
    )
    .await
    .unwrap();
    let manage_token = broker.identity.issue_manage_token().unwrap();
    let handle = daemon::serve(broker.clone()).await.unwrap();
    let socket = handle.socket_path.clone();
    Harness {
        broker,
        _daemon: handle,
        socket,
        manage_token,
        _dir: dir,
    }
}

impl Harness {
    async fn manage(
        &self,
        method: &str,
        path: &str,
        body: Option<Value>,
    ) -> (u16, Value) {
        let token = self.manage_token.clone();
        uds_request(&self.socket, method, path, &[("authorization", &format!("Bearer {token}"))], body)
            .await
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

fn api_spec(name: &str, template: &str) -> Value {
    json!({
        "name": name,
        "config": {
            "kind": "api",
            "host": "api.github.com",
            "scheme": "https",
            "template": template,
        },
        "secrets": [],
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn manage_routes_require_the_management_token() {
    let h = harness().await;

    // No token at all.
    let (status, body) = uds_request(&h.socket, "GET", "/v1/manage/secrets", &[], None).await;
    assert_eq!(status, 401, "{body}");

    // The agent key must never open the manage plane.
    let agent_key = h.broker.identity.token();
    let (status, body) = uds_request(
        &h.socket,
        "GET",
        "/v1/manage/secrets",
        &[("authorization", &format!("Bearer {agent_key}"))],
        None,
    )
    .await;
    assert_eq!(status, 401, "{body}");
    assert_eq!(body["reason"], "invalid_manage_token");

    // The manage token must never authenticate the agent plane.
    let (status, _) = uds_request(
        &h.socket,
        "GET",
        "/v1/connections",
        &[("authorization", &format!("Bearer {}", h.manage_token))],
        None,
    )
    .await;
    assert_eq!(status, 401);

    // With the manage token, whoami answers.
    let (status, body) = h.manage("GET", "/v1/manage/whoami", None).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["version"], "test");
}

#[tokio::test(flavor = "multi_thread")]
async fn secrets_and_connections_round_trip_over_the_manage_api() {
    let h = harness().await;

    let (status, body) = h
        .manage(
            "POST",
            "/v1/manage/secrets",
            Some(json!({ "name": "GITHUB_KEY", "value": "ghp_test" })),
        )
        .await;
    assert_eq!(status, 200, "{body}");

    // Conflict crosses the wire as the structured aka-api error.
    let (status, body) = h
        .manage(
            "POST",
            "/v1/manage/secrets",
            Some(json!({ "name": "GITHUB_KEY", "value": "again" })),
        )
        .await;
    assert_eq!(status, 409, "{body}");
    assert_eq!(body["code"], "secret_name_taken");
    assert_eq!(body["name"], "GITHUB_KEY");

    let (status, body) = h
        .manage(
            "POST",
            "/v1/manage/connections",
            Some(json!({
                "spec": api_spec("github", "Authorization: Bearer {{GITHUB_KEY}}"),
            })),
        )
        .await;
    assert_eq!(status, 200, "{body}");

    let (status, body) = h.manage("GET", "/v1/manage/connections", None).await;
    assert_eq!(status, 200);
    let list = body.as_array().unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["name"], "github");
    assert_eq!(list[0]["type"], "api");
    assert_eq!(list[0]["secret_names"][0], "GITHUB_KEY");
    assert_eq!(list[0]["agent_access"]["enabled"], true);
    let id = list[0]["id"].as_str().unwrap().to_string();

    // Toggle agent access off and observe it in the listing.
    let (status, body) = h
        .manage(
            "POST",
            &format!("/v1/manage/connections/{id}/access"),
            Some(json!({ "enabled": false })),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["changed"], true);
    let (_, body) = h.manage("GET", "/v1/manage/connections", None).await;
    assert_eq!(body[0]["agent_access"]["enabled"], false);

    // Reveal returns only the short prefix; copy-value returns the value
    // (the shell writes it to the clipboard, never the webview).
    let (_, secrets) = h.manage("GET", "/v1/manage/secrets", None).await;
    let secret_id = secrets[0]["id"].as_str().unwrap().to_string();
    let (status, body) = h
        .manage(
            "POST",
            &format!("/v1/manage/secrets/{secret_id}/reveal-prefix"),
            None,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let prefix = body["prefix"].as_str().unwrap();
    assert!(prefix.len() < "ghp_test".len());
    let (status, body) = h
        .manage(
            "POST",
            &format!("/v1/manage/secrets/{secret_id}/copy-value"),
            None,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["value"], "ghp_test");
    // Releasing the value is audited at the route, not on the client's
    // honor: the activity log carries the copy without any follow-up call.
    let (_, activity) = h.manage("GET", "/v1/manage/activity", None).await;
    assert!(
        activity.as_array().unwrap().iter().any(|entry| entry["text"]
            .as_str()
            .unwrap()
            .contains("Secret value copied")),
        "{activity}"
    );

    // Deleting an in-use secret is refused with the structured error.
    let (status, body) = h
        .manage("DELETE", &format!("/v1/manage/secrets/{secret_id}"), None)
        .await;
    assert_eq!(status, 409, "{body}");
    assert_eq!(body["code"], "secret_in_use");

    // Delete the connection, then the secret goes.
    let (status, _) = h
        .manage("DELETE", &format!("/v1/manage/connections/{id}"), None)
        .await;
    assert_eq!(status, 200);
    let (status, _) = h
        .manage("DELETE", &format!("/v1/manage/secrets/{secret_id}"), None)
        .await;
    assert_eq!(status, 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn identity_settings_and_activity_surface_over_the_manage_api() {
    let h = harness().await;

    let (status, body) = h.manage("GET", "/v1/manage/identity", None).await;
    assert_eq!(status, 200, "{body}");
    assert!(body["token_path"].as_str().unwrap().ends_with("token"));

    let (status, body) = h.manage("GET", "/v1/manage/identity/agent-key", None).await;
    assert_eq!(status, 200);
    assert!(body["token"].as_str().unwrap().starts_with("aka_"));

    let (status, body) = h
        .manage(
            "PATCH",
            "/v1/manage/settings",
            Some(json!({ "show_websockets": true })),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["show_websockets"], true);
    assert_eq!(body["reauth_on_read"], true, "untouched fields stay");

    // Rotating the agent key works over the manage API and leaves the
    // manage token itself valid (they are independent credentials).
    let key_before = h.broker.identity.token();
    let (status, _) = h.manage("POST", "/v1/manage/identity/rotate", None).await;
    assert_eq!(status, 200);
    assert_ne!(h.broker.identity.token(), key_before);
    let (status, _) = h.manage("GET", "/v1/manage/whoami", None).await;
    assert_eq!(status, 200);

    let (status, body) = h.manage("GET", "/v1/manage/activity?limit=50", None).await;
    assert_eq!(status, 200);
    assert!(!body.as_array().unwrap().is_empty(), "rotation was audited");
    let (status, _) = h.manage("DELETE", "/v1/manage/activity", None).await;
    assert_eq!(status, 200);
    let (_, body) = h.manage("GET", "/v1/manage/activity", None).await;
    assert!(body.as_array().unwrap().is_empty());

    let (status, body) = h.manage("GET", "/v1/manage/agent-setup", None).await;
    assert_eq!(status, 200);
    assert!(body["instructions"]
        .as_str()
        .unwrap()
        .contains("--unix-socket"));
}

#[tokio::test(flavor = "multi_thread")]
async fn the_event_stream_reports_manage_changes() {
    let h = harness().await;

    let mut rx = h.broker.subscribe_manage_events();
    let (status, _) = h
        .manage(
            "POST",
            "/v1/manage/secrets",
            Some(json!({ "name": "KEY", "value": "v" })),
        )
        .await;
    assert_eq!(status, 200);

    // The add is audited, so the feed carries an activity_appended entry.
    let mut saw_activity = false;
    for _ in 0..4 {
        match tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv()).await {
            Ok(Ok(aka_api::ManageEvent::ActivityAppended { entry })) => {
                assert!(entry.text.contains("KEY"));
                saw_activity = true;
                break;
            }
            Ok(Ok(_)) => continue,
            other => panic!("event stream stalled: {other:?}"),
        }
    }
    assert!(saw_activity);

    // The SSE endpoint itself streams those events over the socket.
    let stream = tokio::net::UnixStream::connect(&h.socket).await.unwrap();
    let io = hyper_util::rt::TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
    tokio::spawn(conn);
    let request = hyper::Request::builder()
        .method("GET")
        .uri("/v1/manage/events")
        .header("host", "localhost")
        .header("authorization", format!("Bearer {}", h.manage_token))
        .body(String::new())
        .unwrap();
    let response = sender.send_request(request).await.unwrap();
    assert_eq!(response.status(), 200);
    assert!(response
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("text/event-stream"));
    let mut body = response.into_body();

    // Trigger a change, then read frames until it shows up.
    let h2 = &h;
    let (status, _) = h2
        .manage(
            "POST",
            "/v1/manage/secrets",
            Some(json!({ "name": "KEY2", "value": "v" })),
        )
        .await;
    assert_eq!(status, 200);

    let mut collected = String::new();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(std::time::Duration::from_secs(2), body.frame()).await {
            Ok(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    collected.push_str(&String::from_utf8_lossy(data));
                    if collected.contains("activity_appended") && collected.contains("KEY2") {
                        return;
                    }
                }
            }
            _ => break,
        }
    }
    panic!("SSE stream never carried the change: {collected:?}");
}
