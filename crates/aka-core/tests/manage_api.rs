//! Manage-plane tests: a real daemon on a real Unix socket, driven the way
//! a remote desktop shell drives it — bearer `akamgr_…` token, JSON bodies,
//! `aka-api` error shapes, and the SSE change feed.

use std::sync::Arc;

use aka_core::approvals::{ApprovalRequest, Verdict};
use aka_core::broker::Broker;
use aka_core::config::BrokerConfig;
use aka_core::daemon;
use aka_core::events::BrokerEvents;
use aka_core::paths::Paths;
use aka_core::vault::MemoryVault;
use http_body_util::BodyExt as _;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

struct TestEvents;

impl BrokerEvents for TestEvents {}

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
    async fn manage(&self, method: &str, path: &str, body: Option<Value>) -> (u16, Value) {
        let token = self.manage_token.clone();
        uds_request(
            &self.socket,
            method,
            path,
            &[("authorization", &format!("Bearer {token}"))],
            body,
        )
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
async fn onepassword_integrations_and_links_cross_the_manage_boundary_without_values() {
    let h = harness().await;
    let connect = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let connect_address = connect.local_addr().unwrap();
    let connect_server = tokio::spawn(async move {
        for _ in 0..5 {
            let (mut stream, _) = connect.accept().await.unwrap();
            let mut request = Vec::new();
            let mut chunk = [0u8; 1024];
            loop {
                let read = stream.read(&mut chunk).await.unwrap();
                assert!(read > 0);
                request.extend_from_slice(&chunk[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let request = String::from_utf8(request).unwrap();
            let authorized = request.contains("Bearer connect-token")
                || request.contains("Bearer replacement-token");
            let (status, body) = if authorized {
                ("200 OK", r#"[{"id":"vault1","name":"Production"}]"#)
            } else {
                ("401 Unauthorized", r#"{"message":"unauthorized"}"#)
            };
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        }
    });

    let (status, rejected) = h
        .manage(
            "POST",
            "/v1/manage/integrations",
            Some(json!({
                "label": "Rejected",
                "method": "connect",
                "base_url": format!("http://{connect_address}"),
                "token": "bad-token",
            })),
        )
        .await;
    assert_eq!(status, 502, "{rejected}");
    assert_eq!(rejected["provider_code"], "auth_failed");
    let (status, integrations) = h.manage("GET", "/v1/manage/integrations", None).await;
    assert_eq!(status, 200, "{integrations}");
    assert!(integrations.as_array().unwrap().is_empty());

    let (status, integration) = h
        .manage(
            "POST",
            "/v1/manage/integrations",
            Some(json!({
                "label": "Work",
                "method": "connect",
                "base_url": format!("http://{connect_address}"),
                "token": "connect-token",
            })),
        )
        .await;
    assert_eq!(status, 200, "{integration}");
    let integration_id = integration["id"].as_str().unwrap();
    assert_eq!(integration["kind"], "connect");
    assert!(integration.get("token").is_none());

    let (status, integrations) = h.manage("GET", "/v1/manage/integrations", None).await;
    assert_eq!(status, 200, "{integrations}");
    assert_eq!(integrations.as_array().unwrap().len(), 1);
    assert!(!integrations.to_string().contains("secret-value"));

    let (status, linked) = h
        .manage(
            "POST",
            "/v1/manage/integrations/onepassword/secrets",
            Some(json!({
                "name": "GITHUB_TOKEN",
                "integration_id": integration_id,
                "vault_id": "vault1",
                "vault_label": "Production",
                "item_id": "item1",
                "item_label": "GitHub",
                "field_id": "password",
                "field_label": "password",
                "field_type": "CONCEALED",
            })),
        )
        .await;
    assert_eq!(status, 200, "{linked}");
    assert_eq!(linked["source"]["kind"], "one_password");
    assert_eq!(linked["source"]["field_type"], "CONCEALED");
    assert!(linked.get("value").is_none());
    let secret_id = linked["id"].as_str().unwrap();

    let (status, error) = h
        .manage(
            "PUT",
            &format!("/v1/manage/integrations/{integration_id}/token"),
            Some(json!({ "token": "bad-replacement" })),
        )
        .await;
    assert_eq!(status, 502, "{error}");
    assert_eq!(error["provider_code"], "auth_failed");
    assert!(!error.to_string().contains("bad-replacement"));

    // A rejected replacement never overwrites the credential that was
    // already working.
    let (status, vaults) = h
        .manage(
            "GET",
            &format!("/v1/manage/integrations/{integration_id}/vaults"),
            None,
        )
        .await;
    assert_eq!(status, 200, "{vaults}");
    assert_eq!(vaults[0]["id"], "vault1");

    let (status, updated) = h
        .manage(
            "PUT",
            &format!("/v1/manage/integrations/{integration_id}/token"),
            Some(json!({ "token": "replacement-token" })),
        )
        .await;
    assert_eq!(status, 200, "{updated}");

    let (status, error) = h
        .manage(
            "DELETE",
            &format!("/v1/manage/integrations/{integration_id}"),
            None,
        )
        .await;
    assert_eq!(status, 409, "{error}");
    assert_eq!(error["provider_code"], "integration_in_use");

    let (status, _) = h
        .manage("DELETE", &format!("/v1/manage/secrets/{secret_id}"), None)
        .await;
    assert_eq!(status, 200);
    let (status, _) = h
        .manage(
            "DELETE",
            &format!("/v1/manage/integrations/{integration_id}"),
            None,
        )
        .await;
    assert_eq!(status, 200);

    let entries = h.broker.audit.recent(20);
    assert!(entries
        .iter()
        .any(|entry| { entry.kind == aka_core::audit::AuditKind::OnePasswordSecretLinked }));
    assert!(entries
        .iter()
        .any(|entry| { entry.kind == aka_core::audit::AuditKind::OnePasswordIntegrationDeleted }));
    connect_server.await.unwrap();
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
    assert!(body["capabilities"].as_array().is_some_and(|items| items
        .iter()
        .any(|item| { item.as_str() == Some(aka_api::APPROVAL_SURFACE_CAPABILITY) })));
    assert!(body["capabilities"].as_array().is_some_and(|items| items
        .iter()
        .any(|item| { item.as_str() == Some(aka_api::ONEPASSWORD_PROVIDER_CAPABILITY) })));
    let auth_failures: Vec<_> = h
        .broker
        .audit
        .recent(20)
        .into_iter()
        .filter(|entry| entry.kind == aka_core::audit::AuditKind::AuthenticationFailed)
        .collect();
    assert!(
        auth_failures
            .iter()
            .any(|entry| entry.fields["plane"] == "manage"),
        "invalid manage credentials should be visible in activity"
    );
    assert!(
        auth_failures
            .iter()
            .any(|entry| entry.fields["plane"] == "agent"),
        "invalid agent credentials should be visible in activity"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn management_token_rotation_and_revocation_require_current_authority() {
    let h = harness().await;
    let first = h.manage_token.clone();

    let (status, invalid) = uds_request(
        &h.socket,
        "POST",
        "/v1/manage/management-token",
        &[("authorization", &format!("Bearer {first}"))],
        Some(json!({ "ttl_days": 0 })),
    )
    .await;
    assert_eq!(status, 422, "{invalid}");
    h.broker.identity.verify_manage(&first).unwrap();

    let (status, rotated) = uds_request(
        &h.socket,
        "POST",
        "/v1/manage/management-token",
        &[("authorization", &format!("Bearer {first}"))],
        Some(json!({ "ttl_days": 30 })),
    )
    .await;
    assert_eq!(status, 200, "{rotated}");
    let second = rotated["token"].as_str().unwrap().to_string();
    assert!(second.starts_with("akamgr_"));
    assert!(rotated["expires_at"].as_str().is_some());
    assert_eq!(
        h.broker.identity.verify_manage(&first),
        Err(aka_core::identity::TokenError::Invalid)
    );
    h.broker.identity.verify_manage(&second).unwrap();

    // A stale administrator cannot overwrite the winning rotation.
    let (status, stale) = uds_request(
        &h.socket,
        "POST",
        "/v1/manage/management-token",
        &[("authorization", &format!("Bearer {first}"))],
        Some(json!({ "ttl_days": 30 })),
    )
    .await;
    assert_eq!(status, 401, "{stale}");
    h.broker.identity.verify_manage(&second).unwrap();

    let (status, revoked) = uds_request(
        &h.socket,
        "DELETE",
        "/v1/manage/management-token",
        &[("authorization", &format!("Bearer {second}"))],
        None,
    )
    .await;
    assert_eq!(status, 200, "{revoked}");
    assert_eq!(revoked["revoked"], true);
    assert!(!h.broker.identity.manage_token_issued());

    let entries = h.broker.audit.recent(20);
    assert!(entries.iter().any(|entry| {
        entry.kind == aka_core::audit::AuditKind::ManagementTokenIssued
            && entry.outcome.as_deref() == Some("rotated")
            && entry.confirmation == Some(aka_core::types::ConfirmationMethod::ManagementToken)
    }));
    assert!(entries.iter().any(|entry| {
        entry.kind == aka_core::audit::AuditKind::ManagementTokenRevoked
            && entry.outcome.as_deref() == Some("revoked")
    }));
}

#[tokio::test(flavor = "multi_thread")]
async fn polling_request_surface_lease_round_trips_over_manage_api() {
    let h = harness().await;
    assert!(!h.broker.events.has_approval_surface());

    let (status, body) = h.manage("POST", "/v1/manage/approval-surfaces", None).await;
    assert_eq!(status, 200, "{body}");
    let id = body["id"].as_str().expect("surface id");
    assert_eq!(
        body["expires_in_ms"].as_u64(),
        Some(aka_api::APPROVAL_SURFACE_TTL_MS)
    );
    assert!(h.broker.events.has_approval_surface());

    let (status, _) = h
        .manage(
            "PUT",
            &format!("/v1/manage/approval-surfaces/{id}"),
            Some(json!({})),
        )
        .await;
    assert_eq!(status, 200);
    let (status, body) = h
        .manage(
            "DELETE",
            &format!("/v1/manage/approval-surfaces/{id}"),
            None,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["released"], true);
    assert!(!h.broker.events.has_approval_surface());
}

#[tokio::test(flavor = "multi_thread")]
async fn an_expired_manage_token_is_rejected_over_http() {
    let h = harness().await;
    // Issue a token that is already past its horizon; the live one the
    // harness holds keeps working, so this covers only the expiry path.
    let expired = h
        .broker
        .identity
        .issue_manage_token_with_ttl(Some(std::time::Duration::ZERO))
        .unwrap();
    let (status, body) = uds_request(
        &h.socket,
        "GET",
        "/v1/manage/whoami",
        &[("authorization", &format!("Bearer {expired}"))],
        None,
    )
    .await;
    assert_eq!(status, 401, "{body}");
    assert_eq!(body["reason"], "invalid_manage_token");
    // The detail steers the operator to re-issue rather than re-check.
    assert!(
        body["detail"].as_str().unwrap().contains("expired"),
        "{body}"
    );
    assert!(h.broker.audit.recent(10).iter().any(|entry| {
        entry.kind == aka_core::audit::AuditKind::ManagementTokenExpired
            && entry.fields["transport"] == "uds"
    }));
}

#[tokio::test(flavor = "multi_thread")]
async fn repeated_manage_auth_failures_are_coalesced_and_rate_limited() {
    let h = harness().await;
    for attempt in 0..11 {
        let (status, _) = uds_request(
            &h.socket,
            "GET",
            "/v1/manage/whoami",
            &[("authorization", "Bearer akamgr_invalid")],
            None,
        )
        .await;
        assert_eq!(status, if attempt < 10 { 401 } else { 429 });
    }
    let failures: Vec<_> = h
        .broker
        .audit
        .recent(50)
        .into_iter()
        .filter(|entry| entry.kind == aka_core::audit::AuditKind::AuthenticationFailed)
        .collect();
    assert_eq!(
        failures.len(),
        1,
        "one stale caller must not amplify the activity log"
    );
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
    assert_eq!(list[0]["agent_access"]["expose_response_credentials"], true);
    let id = list[0]["id"].as_str().unwrap().to_string();

    // Credential-bearing upstream response headers are returned by default;
    // containment and restoration cross the remote management boundary in
    // both directions.
    let (status, body) = h
        .manage(
            "POST",
            &format!("/v1/manage/connections/{id}/response-credentials"),
            Some(json!({ "expose": false })),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["changed"], true);
    let (_, body) = h.manage("GET", "/v1/manage/connections", None).await;
    assert_eq!(
        body[0]["agent_access"]["expose_response_credentials"],
        false
    );
    let (status, body) = h
        .manage(
            "POST",
            &format!("/v1/manage/connections/{id}/response-credentials"),
            Some(json!({ "expose": true })),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["changed"], true);

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

    // Add a second tool, then drag-reorder the list over the manage API and
    // observe the new order persist in the listing.
    let (status, _) = h
        .manage(
            "POST",
            "/v1/manage/connections",
            Some(json!({ "spec": {
                "name": "gitlab",
                "config": { "kind": "api", "host": "gitlab.com", "scheme": "https", "template": "" },
                "secrets": [],
            }})),
        )
        .await;
    assert_eq!(status, 200);
    let (_, body) = h.manage("GET", "/v1/manage/connections", None).await;
    let names: Vec<&str> = body
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        vec!["github", "gitlab"],
        "insertion order until reordered"
    );
    let gitlab_id = body[1]["id"].as_str().unwrap().to_string();

    let (status, _) = h
        .manage(
            "POST",
            "/v1/manage/connections/reorder",
            Some(json!({ "ordered_ids": [gitlab_id, id] })),
        )
        .await;
    assert_eq!(status, 200);
    let (_, body) = h.manage("GET", "/v1/manage/connections", None).await;
    let names: Vec<&str> = body
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["gitlab", "github"], "reorder persisted");

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
        activity
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["text"]
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
async fn rename_is_patch_shaped_and_preserves_authoritative_connection_state() {
    let h = harness().await;
    let (status, body) = h
        .manage(
            "POST",
            "/v1/manage/connections",
            Some(json!({
                "spec": {
                    "name": "github",
                    "config": {
                        "kind": "api",
                        "host": "api.github.com",
                        "scheme": "https",
                        "template": "",
                        "mcp_path": "/mcp",
                    },
                    "secrets": [],
                },
            })),
        )
        .await;
    assert_eq!(status, 200, "{body}");

    let (_, connections) = h.manage("GET", "/v1/manage/connections", None).await;
    let id = connections[0]["id"].as_str().unwrap().to_string();
    let stale_version = connections[0]["updated_at"].as_str().unwrap().to_string();
    let (status, body) = h
        .manage(
            "POST",
            &format!("/v1/manage/connections/{id}/access"),
            Some(json!({ "enabled": false })),
        )
        .await;
    assert_eq!(status, 200, "{body}");

    let (status, body) = h
        .manage(
            "PATCH",
            &format!("/v1/manage/connections/{id}"),
            Some(json!({
                "expected_updated_at": stale_version.clone(),
                "name": "github production",
            })),
        )
        .await;
    assert_eq!(status, 200, "{body}");

    let (_, connections) = h.manage("GET", "/v1/manage/connections", None).await;
    let renamed = &connections[0];
    assert_eq!(renamed["name"], "github production");
    assert_eq!(renamed["host"], "api.github.com");
    assert_eq!(renamed["mcp_path"], "/mcp");
    assert_eq!(renamed["agent_access"]["enabled"], false);
    assert_ne!(renamed["updated_at"], stale_version);

    let (status, body) = h
        .manage(
            "PATCH",
            &format!("/v1/manage/connections/{id}"),
            Some(json!({
                "expected_updated_at": stale_version.clone(),
                "name": "stale rename",
            })),
        )
        .await;
    assert_eq!(status, 409, "{body}");
    assert_eq!(body["code"], "connection_changed");
}

#[tokio::test(flavor = "multi_thread")]
async fn request_history_round_trips_pending_and_terminal_lifecycles() {
    let h = harness().await;
    let (status, body) = h
        .manage(
            "POST",
            "/v1/manage/secrets",
            Some(json!({ "name": "GITHUB_KEY", "value": "ghp_test" })),
        )
        .await;
    assert_eq!(status, 200, "{body}");
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

    // A connected remote inbox explicitly leases prompt capability. Passive
    // event observers do not keep confirmed traffic parked.
    let surface = h.broker.manage_bus().lease_approval_surface();
    assert!(h.broker.manage_bus().renew_approval_surface(&surface.id()));
    let connection = h.broker.store.connection_by_name("github").unwrap();
    let broker = h.broker.clone();
    let call = tokio::spawn(async move {
        broker
            .approvals
            .gate(
                ApprovalRequest::new(&connection, "codex", "GET /user")
                    .credentials_from(&broker.store)
                    .http_operation(&http::Method::GET, "/user"),
            )
            .await
    });

    let approval = tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            let (status, approvals) = h.manage("GET", "/v1/manage/approvals", None).await;
            assert_eq!(status, 200, "{approvals}");
            if let Some(approval) = approvals.as_array().and_then(|items| items.first()) {
                break approval.clone();
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the approval should enter the management queue");
    let id = approval["id"].as_str().unwrap();

    let (status, snapshot) = h.manage("GET", "/v1/manage/approvals/snapshot", None).await;
    assert_eq!(status, 200, "{snapshot}");
    assert_eq!(snapshot["approvals"][0]["id"], id);
    assert_eq!(snapshot["elicitations"], json!([]));
    let (epoch, sequence) = snapshot["version"]
        .as_str()
        .and_then(|version| version.split_once(':'))
        .expect("snapshot version is <event epoch>:<head sequence>");
    assert!(!epoch.is_empty());
    assert!(sequence.parse::<u64>().is_ok());

    let (status, requests) = h.manage("GET", "/v1/manage/requests", None).await;
    assert_eq!(status, 200, "{requests}");
    assert_eq!(requests[0]["id"], id);
    assert_eq!(requests[0]["kind"], "approval");
    assert_eq!(requests[0]["status"], "pending");
    assert_eq!(requests[0]["summary"], "GET /user");
    assert_eq!(requests[0]["credential_names"], json!(["GITHUB_KEY"]));
    assert_eq!(requests[0]["method"], "GET");
    assert_eq!(requests[0]["path"], "/user");

    let (status, answer) = h
        .manage(
            "POST",
            &format!("/v1/manage/approvals/{id}"),
            Some(json!({ "decision": "deny" })),
        )
        .await;
    assert_eq!(status, 200, "{answer}");
    assert_eq!(answer["answered"], true);
    assert_eq!(call.await.unwrap(), Verdict::Denied);

    let (status, requests) = h.manage("GET", "/v1/manage/requests", None).await;
    assert_eq!(status, 200, "{requests}");
    assert_eq!(requests[0]["id"], id);
    assert_eq!(requests[0]["status"], "denied");
    assert_eq!(requests[0]["resolution"], "denied");
    assert!(requests[0]["resolved_at"].as_str().is_some());
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
    // The key's release is audited (in `LocalBackend::agent_key`) — a
    // manage-token holder cannot read it without leaving a trace.
    let (_, activity) = h.manage("GET", "/v1/manage/activity", None).await;
    assert!(
        activity
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["text"]
                .as_str()
                .is_some_and(|text| text.contains("Shared key copied"))),
        "agent-key release missing from the activity log: {activity}"
    );

    let (status, body) = h
        .manage(
            "PATCH",
            "/v1/manage/settings",
            Some(json!({ "menu_bar_hides_dock": true })),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["menu_bar_hides_dock"], true);
    assert_eq!(
        body["confirm_ssh_host_keys"], false,
        "untouched fields stay"
    );

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
    let body = body.as_array().unwrap();
    assert_eq!(body.len(), 1);
    assert_eq!(body[0]["text"], "Activity history cleared");

    let (status, body) = h.manage("GET", "/v1/manage/agent-setup", None).await;
    assert_eq!(status, 200);
    assert!(body["instructions"]
        .as_str()
        .unwrap()
        .contains("--unix-socket"));
}

/// Read SSE frames off a manage `/events` stream until `want` completes on
/// the accumulated text or the deadline passes; returns everything read.
async fn read_sse_until(
    socket: &std::path::Path,
    token: &str,
    last_event_id: Option<&str>,
    want: impl Fn(&str) -> bool,
) -> String {
    use http_body_util::BodyExt as _;
    let stream = tokio::net::UnixStream::connect(socket).await.unwrap();
    let io = hyper_util::rt::TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
    tokio::spawn(conn);
    let mut builder = hyper::Request::builder()
        .method("GET")
        .uri("/v1/manage/events")
        .header("host", "localhost")
        .header("authorization", format!("Bearer {token}"));
    if let Some(id) = last_event_id {
        builder = builder.header("last-event-id", id);
    }
    let response = sender
        .send_request(builder.body(String::new()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let mut body = response.into_body();
    let mut collected = String::new();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(std::time::Duration::from_millis(1500), body.frame()).await {
            Ok(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    collected.push_str(&String::from_utf8_lossy(data));
                    if want(&collected) {
                        break;
                    }
                }
            }
            _ => break,
        }
    }
    collected
}

/// Pull the last `id:` field out of an accumulated SSE text.
fn last_id(sse: &str) -> Option<String> {
    sse.lines()
        .filter_map(|l| l.strip_prefix("id:"))
        .map(|l| l.trim().to_string())
        .next_back()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_reconnect_resumes_from_last_event_id_instead_of_resyncing() {
    let h = harness().await;

    // First connection: fresh client → a resync leads, then live events.
    // Make one change so the stream advances and we capture an id.
    let sse = {
        let socket = h.socket.clone();
        let token = h.manage_token.clone();
        let reader = tokio::spawn(async move {
            read_sse_until(&socket, &token, None, |s| s.contains("SEEN")).await
        });
        // Give the reader a moment to attach, then add a secret.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let (status, _) = h
            .manage(
                "POST",
                "/v1/manage/secrets",
                Some(json!({ "name": "SEEN", "value": "v" })),
            )
            .await;
        assert_eq!(status, 200);
        reader.await.unwrap()
    };
    assert!(
        sse.contains("\"event\":\"resync\""),
        "fresh client resyncs: {sse}"
    );
    let resume_id = last_id(&sse).expect("stream carried an id");

    // While "offline", make two more changes.
    for name in ["MISSED_A", "MISSED_B"] {
        let (status, _) = h
            .manage(
                "POST",
                "/v1/manage/secrets",
                Some(json!({ "name": name, "value": "v" })),
            )
            .await;
        assert_eq!(status, 200);
    }

    // Reconnect with the saved id: the broker replays the missed events and
    // does NOT lead with another resync.
    let resumed = read_sse_until(&h.socket, &h.manage_token, Some(&resume_id), |s| {
        s.contains("MISSED_A") && s.contains("MISSED_B")
    })
    .await;
    assert!(
        resumed.contains("MISSED_A"),
        "replayed the first miss: {resumed}"
    );
    assert!(
        resumed.contains("MISSED_B"),
        "replayed the second miss: {resumed}"
    );
    assert!(
        !resumed.contains("\"event\":\"resync\""),
        "a valid resume must not force a full refetch: {resumed}"
    );

    // A foreign/garbage id forces a resync (a different broker process, or a
    // position aged out of the buffer).
    let foreign = read_sse_until(&h.socket, &h.manage_token, Some("deadbeef:1"), |s| {
        s.contains("resync")
    })
    .await;
    assert!(
        foreign.contains("\"event\":\"resync\""),
        "foreign id resyncs: {foreign}"
    );
}

/// A client resuming from a *foreign* position whose seq is far above this
/// process's own head (a long-lived previous broker, then a restart) must
/// be resynced onto this process's numbering — not have every subsequent
/// live event swallowed by a stale dedupe baseline.
#[tokio::test(flavor = "multi_thread")]
async fn a_high_foreign_resume_position_does_not_swallow_live_events() {
    let h = harness().await;

    // Give the stream a real (small) head first.
    let (status, _) = h
        .manage(
            "POST",
            "/v1/manage/secrets",
            Some(json!({ "name": "BEFORE", "value": "v" })),
        )
        .await;
    assert_eq!(status, 200);

    let sse = {
        let socket = h.socket.clone();
        let token = h.manage_token.clone();
        let reader = tokio::spawn(async move {
            read_sse_until(&socket, &token, Some("deadbeef:5000"), |s| {
                s.contains("AFTER")
            })
            .await
        });
        // Let the subscriber attach, then publish a live change.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let (status, _) = h
            .manage(
                "POST",
                "/v1/manage/secrets",
                Some(json!({ "name": "AFTER", "value": "v" })),
            )
            .await;
        assert_eq!(status, 200);
        reader.await.unwrap()
    };
    assert!(
        sse.contains("\"event\":\"resync\""),
        "foreign id resyncs: {sse}"
    );
    assert!(
        sse.contains("AFTER"),
        "live events after the resync must still be delivered: {sse}"
    );
    // The resync's baseline id is this process's numbering, not the
    // client's poisoned position (which would wedge every later resume).
    let id = last_id(&sse).expect("frames carry ids");
    let seq: u64 = id.split_once(':').expect("epoch:seq").1.parse().unwrap();
    assert!(seq < 5000, "ids restart from this process's own seq: {id}");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_event_stream_reports_manage_changes() {
    let h = harness().await;

    let mut rx = h.broker.manage_bus().subscribe();
    let (status, _) = h
        .manage(
            "POST",
            "/v1/manage/secrets",
            Some(json!({ "name": "KEY", "value": "v" })),
        )
        .await;
    assert_eq!(status, 200);

    // The add is audited, so the feed carries an activity_appended entry —
    // numbered, so a reconnecting client could resume from its seq.
    let mut saw_activity = false;
    for _ in 0..4 {
        match tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv()).await {
            Ok(Ok(item)) => {
                assert!(item.seq > 0, "events are numbered from 1");
                if let aka_api::ManageEvent::ActivityAppended { entry } = item.event {
                    assert!(entry.text.contains("KEY"));
                    saw_activity = true;
                    break;
                }
            }
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
                    // Frames carry an id: <epoch>:<seq> for reconnect resume.
                    if collected.contains("activity_appended") && collected.contains("KEY2") {
                        assert!(
                            collected.contains("id:"),
                            "frames must carry ids: {collected}"
                        );
                        return;
                    }
                }
            }
            _ => break,
        }
    }
    panic!("SSE stream never carried the change: {collected:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn revoking_a_manage_token_closes_its_live_event_stream() {
    use http_body_util::BodyExt as _;

    let h = harness().await;
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
    let mut body = response.into_body();

    // Consume the readiness comment and initial resync so the next frame
    // reflects post-revocation behavior, not bytes queued while the
    // credential was valid.
    loop {
        let frame = tokio::time::timeout(std::time::Duration::from_secs(2), body.frame())
            .await
            .expect("initial event timed out")
            .expect("stream ended before its resync")
            .expect("initial event failed");
        if frame
            .data_ref()
            .is_some_and(|data| String::from_utf8_lossy(data).contains("\"event\":\"resync\""))
        {
            break;
        }
    }

    assert!(h.broker.identity.revoke_manage_token().unwrap());
    let ended = tokio::time::timeout(std::time::Duration::from_secs(3), body.frame())
        .await
        .expect("revoked stream did not close");
    assert!(ended.is_none(), "revoked stream disclosed another frame");
}
