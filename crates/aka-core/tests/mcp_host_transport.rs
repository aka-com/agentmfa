use std::sync::Arc;

use aka_core::broker::Broker;
use aka_core::config::BrokerConfig;
use aka_core::events::BrokerEvents;
use aka_core::mcp_host;
use aka_core::paths::Paths;
use aka_core::store::ConnectionSpec;
use aka_core::types::ConnectionConfig;
use aka_core::vault::MemoryVault;
use futures::StreamExt as _;
use reqwest::StatusCode;
use serde_json::{json, Value};
use zeroize::Zeroizing;

struct NoopEvents;
impl BrokerEvents for NoopEvents {}

#[tokio::test]
async fn rust_host_owns_the_streamable_http_session_lifecycle() {
    let dir = tempfile::tempdir().unwrap();
    let broker = Broker::new(
        Paths::under(dir.path()),
        Arc::new(MemoryVault::new()),
        BrokerConfig::default(),
        Arc::new(NoopEvents),
    )
    .await
    .unwrap();
    let token = broker.identity.token();
    let host = mcp_host::serve(broker).await.unwrap();
    let client = reqwest::Client::new();

    let malformed = client
        .post(host.mcp_url())
        .header("authorization", "Bearer wrong")
        .header("content-type", "application/json")
        .body("{")
        .send()
        .await
        .unwrap();
    assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        malformed.json::<Value>().await.unwrap()["error"]["code"],
        -32700
    );

    let initialize = client
        .post(host.mcp_url())
        .bearer_auth(&token)
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .json(&json!({
            "jsonrpc": "2.0",
            "id": "init-1",
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "rust-contract", "version": "1"},
            },
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(initialize.status(), StatusCode::OK);
    let session = initialize
        .headers()
        .get("mcp-session-id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let initialized = initialize.json::<Value>().await.unwrap();
    assert_eq!(initialized["id"], "init-1");
    assert_eq!(initialized["result"]["protocolVersion"], "2025-06-18");

    let notification = client
        .post(host.mcp_url())
        .bearer_auth(&token)
        .header("mcp-session-id", &session)
        .header("mcp-protocol-version", "2025-06-18")
        .json(&json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(notification.status(), StatusCode::ACCEPTED);

    let ping = client
        .post(host.mcp_url())
        .bearer_auth(&token)
        .header("mcp-session-id", &session)
        .header("mcp-protocol-version", "2025-06-18")
        .json(&json!({"jsonrpc": "2.0", "id": 2, "method": "ping"}))
        .send()
        .await
        .unwrap();
    assert_eq!(ping.status(), StatusCode::OK);
    assert_eq!(ping.json::<Value>().await.unwrap()["result"], json!({}));

    let listed = rpc(
        &client,
        &host.mcp_url(),
        &token,
        &session,
        3,
        "tools/list",
        json!({}),
    )
    .await;
    let mut names: Vec<&str> = listed["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect();
    names.sort_unstable();
    assert_eq!(names, ["agentmfa_connect", "agentmfa_status"]);

    let status = rpc(
        &client,
        &host.mcp_url(),
        &token,
        &session,
        4,
        "tools/call",
        json!({"name": "agentmfa_status", "arguments": {}}),
    )
    .await;
    let status = tool_payload(&status);
    assert_eq!(status["tools"], json!([]));
    assert!(status["hint"].as_str().unwrap().contains("No tools"));

    let revoked = client
        .post(host.mcp_url())
        .bearer_auth("not-a-real-token")
        .header("mcp-session-id", &session)
        .json(&json!({"jsonrpc": "2.0", "id": 5, "method": "ping"}))
        .send()
        .await
        .unwrap();
    assert_eq!(revoked.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        revoked.headers()["www-authenticate"],
        reqwest::header::HeaderValue::from_static("Bearer")
    );

    let deleted = client
        .delete(host.mcp_url())
        .bearer_auth(&token)
        .header("mcp-session-id", &session)
        .send()
        .await
        .unwrap();
    assert_eq!(deleted.status(), StatusCode::NO_CONTENT);

    let expired = client
        .post(host.mcp_url())
        .bearer_auth(&token)
        .header("mcp-session-id", &session)
        .json(&json!({"jsonrpc": "2.0", "id": 6, "method": "ping"}))
        .send()
        .await
        .unwrap();
    assert_eq!(expired.status(), StatusCode::NOT_FOUND);
    assert_eq!(expired.json::<Value>().await.unwrap()["id"], 6);
}

#[tokio::test]
async fn rust_host_rejects_non_loopback_browser_origins() {
    let dir = tempfile::tempdir().unwrap();
    let broker = Broker::new(
        Paths::under(dir.path()),
        Arc::new(MemoryVault::new()),
        BrokerConfig::default(),
        Arc::new(NoopEvents),
    )
    .await
    .unwrap();
    let host = mcp_host::serve(broker).await.unwrap();
    let response = reqwest::Client::new()
        .post(host.mcp_url())
        .header("origin", "https://attacker.example")
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn rust_host_projects_and_invokes_native_broker_tools() {
    let seen_auth: Arc<std::sync::Mutex<Option<String>>> = Arc::default();
    let captured = seen_auth.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_port = listener.local_addr().unwrap().port();
    let upstream = axum::Router::new().route(
        "/whoami",
        axum::routing::get(move |headers: axum::http::HeaderMap| {
            let captured = captured.clone();
            async move {
                *captured.lock().unwrap() = headers
                    .get("authorization")
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_string);
                "ok"
            }
        }),
    );
    tokio::spawn(async move {
        let _ = axum::serve(listener, upstream).await;
    });

    let dir = tempfile::tempdir().unwrap();
    let broker = Broker::new(
        Paths::under(dir.path()),
        Arc::new(MemoryVault::new()),
        BrokerConfig::default(),
        Arc::new(NoopEvents),
    )
    .await
    .unwrap();
    broker
        .store
        .add_secret("API_KEY", Zeroizing::new("secret-value".into()))
        .unwrap();
    broker
        .store
        .add_connection(ConnectionSpec {
            name: "prod-db".into(),
            config: ConnectionConfig::Api {
                host: "127.0.0.1".into(),
                scheme: "http".into(),
                port: Some(upstream_port),
                trusted_ca_bundle_path: None,
                template: "Authorization: Bearer {{API_KEY}}".into(),
                mcp_path: None,
                test_path: None,
                oauth: None,
                signer: None,
                client_cert_path: None,
                client_key_path: None,
            },
            secrets: vec![],
        })
        .unwrap();
    let connection = broker.store.list_connections().pop().unwrap();
    let token = broker.identity.token();
    let host = mcp_host::serve(broker.clone()).await.unwrap();
    let client = reqwest::Client::new();
    let session = initialize(&client, &host.mcp_url(), &token).await;

    let listed = rpc(
        &client,
        &host.mcp_url(),
        &token,
        &session,
        2,
        "tools/list",
        json!({}),
    )
    .await;
    assert!(listed["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .any(|tool| tool["name"] == "agentmfa_prod-db_request"));

    let called = rpc(
        &client,
        &host.mcp_url(),
        &token,
        &session,
        3,
        "tools/call",
        json!({
            "name": "agentmfa_prod-db_request",
            "arguments": {"method": "GET", "path": "/whoami"},
        }),
    )
    .await;
    let result = tool_payload(&called);
    assert_eq!(result["status"], 200);
    assert_eq!(
        seen_auth.lock().unwrap().as_deref(),
        Some("Bearer secret-value")
    );
    assert!(!called.to_string().contains("secret-value"));

    let events = client
        .get(host.mcp_url())
        .bearer_auth(&token)
        .header("mcp-session-id", &session)
        .header("mcp-protocol-version", "2025-06-18")
        .header("accept", "text/event-stream")
        .send()
        .await
        .unwrap();
    assert_eq!(events.status(), StatusCode::OK);
    assert!(events.headers()["content-type"]
        .to_str()
        .unwrap()
        .starts_with("text/event-stream"));
    let mut event_bytes = events.bytes_stream();

    broker.ui_set_tool_access(&connection.id, false).unwrap();
    let listed = rpc(
        &client,
        &host.mcp_url(),
        &token,
        &session,
        4,
        "tools/list",
        json!({}),
    )
    .await;
    assert!(!listed["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .any(|tool| tool["name"] == "agentmfa_prod-db_request"));
    let event = tokio::time::timeout(std::time::Duration::from_secs(2), event_bytes.next())
        .await
        .expect("tools/list_changed event")
        .expect("open event stream")
        .expect("event bytes");
    assert!(String::from_utf8_lossy(&event).contains("notifications/tools/list_changed"));
}

#[tokio::test]
async fn rust_host_cancels_active_calls_and_notifies_the_upstream() {
    let started = Arc::new(tokio::sync::Notify::new());
    let cancelled = Arc::new(tokio::sync::Notify::new());
    let started_by_route = started.clone();
    let cancelled_by_route = cancelled.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_port = listener.local_addr().unwrap().port();
    let upstream = axum::Router::new()
        .route(
            "/mcp",
            axum::routing::post(move |axum::Json(body): axum::Json<Value>| {
                let started = started_by_route.clone();
                let cancelled = cancelled_by_route.clone();
                async move {
                    let id = body["id"].clone();
                    let result = match body["method"].as_str() {
                        Some("initialize") => json!({
                            "protocolVersion": "2025-06-18",
                            "capabilities": {"tools": {}},
                            "serverInfo": {"name": "slow", "version": "1"},
                        }),
                        Some("tools/list") => json!({
                            "tools": [{
                                "name": "wait",
                                "description": "Wait until cancelled",
                                "inputSchema": {"type": "object"},
                            }],
                        }),
                        Some("tools/call") => {
                            started.notify_one();
                            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                            json!({"content": [{"type": "text", "text": "too late"}]})
                        }
                        Some("notifications/cancelled") => {
                            cancelled.notify_one();
                            Value::Null
                        }
                        _ => Value::Null,
                    };
                    axum::Json(json!({"jsonrpc": "2.0", "id": id, "result": result}))
                }
            }),
        )
        .route(
            "/mcp",
            axum::routing::delete(|| async { StatusCode::NO_CONTENT }),
        );
    tokio::spawn(async move {
        let _ = axum::serve(listener, upstream).await;
    });

    let dir = tempfile::tempdir().unwrap();
    let broker = Broker::new(
        Paths::under(dir.path()),
        Arc::new(MemoryVault::new()),
        BrokerConfig::default(),
        Arc::new(NoopEvents),
    )
    .await
    .unwrap();
    broker
        .store
        .add_connection(ConnectionSpec {
            name: "slow".into(),
            config: ConnectionConfig::Api {
                host: "127.0.0.1".into(),
                scheme: "http".into(),
                port: Some(upstream_port),
                trusted_ca_bundle_path: None,
                template: String::new(),
                mcp_path: Some("/mcp".into()),
                test_path: None,
                oauth: None,
                signer: None,
                client_cert_path: None,
                client_key_path: None,
            },
            secrets: vec![],
        })
        .unwrap();
    let token = broker.identity.token();
    let host = mcp_host::serve(broker).await.unwrap();
    let client = reqwest::Client::new();
    let session = initialize(&client, &host.mcp_url(), &token).await;
    let listed = rpc(
        &client,
        &host.mcp_url(),
        &token,
        &session,
        2,
        "tools/list",
        json!({}),
    )
    .await;
    assert!(listed["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .any(|tool| tool["name"] == "agentmfa_slow_wait"));

    let call_client = client.clone();
    let call_url = host.mcp_url();
    let call_token = token.clone();
    let call_session = session.clone();
    let call = tokio::spawn(async move {
        rpc(
            &call_client,
            &call_url,
            &call_token,
            &call_session,
            10,
            "tools/call",
            json!({"name": "agentmfa_slow_wait", "arguments": {}}),
        )
        .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(2), started.notified())
        .await
        .expect("upstream call started");
    let response = client
        .post(host.mcp_url())
        .bearer_auth(&token)
        .header("mcp-session-id", &session)
        .header("mcp-protocol-version", "2025-06-18")
        .json(&json!({
            "jsonrpc": "2.0",
            "method": "notifications/cancelled",
            "params": {"requestId": 10, "reason": "test cancellation"},
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let cancelled_call = tokio::time::timeout(std::time::Duration::from_secs(2), call)
        .await
        .expect("cancelled call returned")
        .unwrap();
    assert_eq!(cancelled_call["error"]["code"], -32800);
    tokio::time::timeout(std::time::Duration::from_secs(2), cancelled.notified())
        .await
        .expect("upstream received notifications/cancelled");
}

#[tokio::test]
async fn rust_host_keeps_catalog_overflow_searchable_and_callable() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_port = listener.local_addr().unwrap().port();
    let upstream = axum::Router::new().route(
        "/mcp",
        axum::routing::post(|axum::Json(body): axum::Json<Value>| async move {
            let id = body["id"].clone();
            let result = match body["method"].as_str() {
                Some("initialize") => json!({
                    "protocolVersion": "2025-06-18",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "catalog", "version": "1"},
                }),
                Some("tools/list") => json!({
                    "tools": (0..42).map(|index| json!({
                        "name": format!("tool{index:02}"),
                        "description": format!("Catalog tool {index:02}"),
                        "inputSchema": {"type": "object"},
                    })).collect::<Vec<_>>(),
                }),
                Some("tools/call") => json!({
                    "content": [{
                        "type": "text",
                        "text": format!("called {}", body["params"]["name"]),
                    }],
                }),
                _ => Value::Null,
            };
            axum::Json(json!({"jsonrpc": "2.0", "id": id, "result": result}))
        }),
    );
    tokio::spawn(async move {
        let _ = axum::serve(listener, upstream).await;
    });

    let dir = tempfile::tempdir().unwrap();
    let broker = Broker::new(
        Paths::under(dir.path()),
        Arc::new(MemoryVault::new()),
        BrokerConfig::default(),
        Arc::new(NoopEvents),
    )
    .await
    .unwrap();
    add_mcp_connection(&broker, "catalog", upstream_port);
    let token = broker.identity.token();
    let host = mcp_host::serve(broker).await.unwrap();
    let client = reqwest::Client::new();
    let session = initialize(&client, &host.mcp_url(), &token).await;

    let listed = rpc(
        &client,
        &host.mcp_url(),
        &token,
        &session,
        2,
        "tools/list",
        json!({}),
    )
    .await;
    let names: Vec<&str> = listed["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|tool| tool["name"].as_str())
        .collect();
    assert!(names.contains(&"agentmfa_search_tools"));
    assert!(names.contains(&"agentmfa_call_tool"));
    assert!(!names.contains(&"agentmfa_catalog_tool41"));

    let searched = rpc(
        &client,
        &host.mcp_url(),
        &token,
        &session,
        3,
        "tools/call",
        json!({
            "name": "agentmfa_search_tools",
            "arguments": {"query": "tool41"},
        }),
    )
    .await;
    assert_eq!(tool_payload(&searched)["results"][0]["tool"], "tool41");

    let called = rpc(
        &client,
        &host.mcp_url(),
        &token,
        &session,
        4,
        "tools/call",
        json!({
            "name": "agentmfa_call_tool",
            "arguments": {"connection": "catalog", "tool": "tool41", "arguments": {}},
        }),
    )
    .await;
    assert!(
        called["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("tool41"),
        "{called}"
    );

    // Registered tools stay in the search index too, answered with the
    // direct name they are exposed under rather than the generic invoker.
    let searched = rpc(
        &client,
        &host.mcp_url(),
        &token,
        &session,
        5,
        "tools/call",
        json!({
            "name": "agentmfa_search_tools",
            "arguments": {"query": "tool00"},
        }),
    )
    .await;
    let results = tool_payload(&searched);
    assert_eq!(results["results"][0]["tool"], "tool00");
    assert_eq!(
        results["results"][0]["call"]["tool"],
        "agentmfa_catalog_tool00"
    );

    let called = rpc(
        &client,
        &host.mcp_url(),
        &token,
        &session,
        6,
        "tools/call",
        json!({
            "name": "agentmfa_call_tool",
            "arguments": {"connection": "catalog", "tool": "tool00", "arguments": {}},
        }),
    )
    .await;
    assert!(
        called["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("tool00"),
        "{called}"
    );
}

#[tokio::test]
async fn rust_host_serves_tool_calls_before_the_first_listing() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_port = listener.local_addr().unwrap().port();
    let upstream = axum::Router::new()
        .route("/ping", axum::routing::get(|| async { "pong" }))
        .route(
            "/mcp",
            axum::routing::post(|axum::Json(body): axum::Json<Value>| async move {
                let id = body["id"].clone();
                let result = match body["method"].as_str() {
                    Some("initialize") => json!({
                        "protocolVersion": "2025-06-18",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "notes", "version": "1"},
                    }),
                    Some("tools/list") => json!({
                        "tools": [{
                            "name": "search",
                            "description": "Search notes",
                            "inputSchema": {"type": "object"},
                        }],
                    }),
                    Some("tools/call") => json!({
                        "content": [{
                            "type": "text",
                            "text": format!("found: {}", body["params"]["arguments"]),
                        }],
                    }),
                    _ => Value::Null,
                };
                axum::Json(json!({"jsonrpc": "2.0", "id": id, "result": result}))
            }),
        );
    tokio::spawn(async move {
        let _ = axum::serve(listener, upstream).await;
    });

    let dir = tempfile::tempdir().unwrap();
    let broker = Broker::new(
        Paths::under(dir.path()),
        Arc::new(MemoryVault::new()),
        BrokerConfig::default(),
        Arc::new(NoopEvents),
    )
    .await
    .unwrap();
    broker
        .store
        .add_connection(ConnectionSpec {
            name: "prod-db".into(),
            config: ConnectionConfig::Api {
                host: "127.0.0.1".into(),
                scheme: "http".into(),
                port: Some(upstream_port),
                trusted_ca_bundle_path: None,
                template: String::new(),
                mcp_path: None,
                test_path: None,
                oauth: None,
                signer: None,
                client_cert_path: None,
                client_key_path: None,
            },
            secrets: vec![],
        })
        .unwrap();
    add_mcp_connection(&broker, "notes", upstream_port);
    let token = broker.identity.token();
    let host = mcp_host::serve(broker).await.unwrap();
    let client = reqwest::Client::new();

    // No tools/list first: a client that remembers its tools from an earlier
    // session — the stdio bridge replays a pending call this way after it
    // recovers an evicted session — must still get them served.
    let session = initialize(&client, &host.mcp_url(), &token).await;
    let called = rpc(
        &client,
        &host.mcp_url(),
        &token,
        &session,
        2,
        "tools/call",
        json!({
            "name": "agentmfa_prod-db_request",
            "arguments": {"method": "GET", "path": "/ping"},
        }),
    )
    .await;
    assert_eq!(tool_payload(&called)["status"], 200, "{called}");

    let searched = rpc(
        &client,
        &host.mcp_url(),
        &token,
        &session,
        3,
        "tools/call",
        json!({
            "name": "agentmfa_notes_search",
            "arguments": {"query": "roadmap"},
        }),
    )
    .await;
    assert!(
        searched["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("roadmap"),
        "{searched}"
    );
}

#[tokio::test]
async fn rust_host_completes_a_multi_round_input_flow() {
    let second_round: Arc<std::sync::Mutex<Option<Value>>> = Arc::default();
    let captured = second_round.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_port = listener.local_addr().unwrap().port();
    let upstream = axum::Router::new().route(
        "/mcp",
        axum::routing::post(move |axum::Json(body): axum::Json<Value>| {
            let captured = captured.clone();
            async move {
                let id = body["id"].clone();
                let result = match body["method"].as_str() {
                    Some("initialize") => json!({
                        "protocolVersion": "2025-06-18",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "input", "version": "1"},
                    }),
                    Some("tools/list") => json!({
                        "tools": [{
                            "name": "needs_input",
                            "inputSchema": {"type": "object"},
                        }],
                    }),
                    Some("tools/call") if body["params"].get("inputResponses").is_none() => json!({
                        "resultType": "input_required",
                        "inputRequests": {
                            "ask": {
                                "method": "elicitation/create",
                                "params": {
                                    "message": "Choose a value",
                                    "requestedSchema": {
                                        "type": "object",
                                        "properties": {"value": {"type": "string"}},
                                    },
                                },
                            },
                        },
                        "requestState": {"round": 1},
                    }),
                    Some("tools/call") => {
                        *captured.lock().unwrap() = Some(body["params"].clone());
                        json!({
                            "resultType": "complete",
                            "content": [{"type": "text", "text": "input handled"}],
                        })
                    }
                    _ => Value::Null,
                };
                axum::Json(json!({"jsonrpc": "2.0", "id": id, "result": result}))
            }
        }),
    );
    tokio::spawn(async move {
        let _ = axum::serve(listener, upstream).await;
    });

    let dir = tempfile::tempdir().unwrap();
    let broker = Broker::new(
        Paths::under(dir.path()),
        Arc::new(MemoryVault::new()),
        BrokerConfig::default(),
        Arc::new(NoopEvents),
    )
    .await
    .unwrap();
    add_mcp_connection(&broker, "input", upstream_port);
    let token = broker.identity.token();
    let host = mcp_host::serve(broker).await.unwrap();
    let client = reqwest::Client::new();
    let session = initialize(&client, &host.mcp_url(), &token).await;
    let _ = rpc(
        &client,
        &host.mcp_url(),
        &token,
        &session,
        2,
        "tools/list",
        json!({}),
    )
    .await;
    let called = rpc(
        &client,
        &host.mcp_url(),
        &token,
        &session,
        3,
        "tools/call",
        json!({"name": "agentmfa_input_needs_input", "arguments": {}}),
    )
    .await;
    assert!(called["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("input handled"));
    let second_round = second_round.lock().unwrap().clone().unwrap();
    assert_eq!(second_round["requestState"], json!({"round": 1}));
    assert_eq!(
        second_round["inputResponses"]["ask"]["action"],
        json!("cancel")
    );
}

#[tokio::test]
async fn rust_host_projects_upstream_resources_prompts_and_completion() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_port = listener.local_addr().unwrap().port();
    let upstream = axum::Router::new().route(
        "/mcp",
        axum::routing::post(|axum::Json(body): axum::Json<Value>| async move {
            let id = body["id"].clone();
            let result = match body["method"].as_str() {
                Some("initialize") => json!({
                    "protocolVersion": "2025-06-18",
                    "capabilities": {
                        "tools": {},
                        "resources": {},
                        "prompts": {},
                        "completions": {},
                    },
                    "serverInfo": {"name": "docs", "version": "1"},
                }),
                Some("tools/list") => json!({"tools": []}),
                Some("resources/list") => json!({
                    "resources": [{
                        "uri": "docs://home",
                        "name": "home",
                        "mimeType": "text/plain",
                    }],
                }),
                Some("resources/templates/list") => json!({
                    "resourceTemplates": [{
                        "uriTemplate": "docs://page/{id}",
                        "name": "page",
                    }],
                }),
                Some("prompts/list") => json!({
                    "prompts": [{
                        "name": "review",
                        "arguments": [{"name": "topic", "required": true}],
                    }],
                }),
                Some("resources/read") => json!({
                    "contents": [{
                        "uri": body["params"]["uri"],
                        "mimeType": "text/plain",
                        "text": "resource body",
                    }],
                }),
                Some("prompts/get") => json!({
                    "description": "review prompt",
                    "messages": [{
                        "role": "user",
                        "content": {"type": "text", "text": body["params"]["arguments"]["topic"]},
                    }],
                }),
                Some("completion/complete") => {
                    json!({"completion": {"values": ["one", "two"], "hasMore": false}})
                }
                _ => Value::Null,
            };
            axum::Json(json!({"jsonrpc": "2.0", "id": id, "result": result}))
        }),
    );
    tokio::spawn(async move {
        let _ = axum::serve(listener, upstream).await;
    });

    let dir = tempfile::tempdir().unwrap();
    let broker = Broker::new(
        Paths::under(dir.path()),
        Arc::new(MemoryVault::new()),
        BrokerConfig::default(),
        Arc::new(NoopEvents),
    )
    .await
    .unwrap();
    broker
        .store
        .add_connection(ConnectionSpec {
            name: "docs".into(),
            config: ConnectionConfig::Api {
                host: "127.0.0.1".into(),
                scheme: "http".into(),
                port: Some(upstream_port),
                trusted_ca_bundle_path: None,
                template: String::new(),
                mcp_path: Some("/mcp".into()),
                test_path: None,
                oauth: None,
                signer: None,
                client_cert_path: None,
                client_key_path: None,
            },
            secrets: vec![],
        })
        .unwrap();
    let token = broker.identity.token();
    let host = mcp_host::serve(broker).await.unwrap();
    let client = reqwest::Client::new();
    let session = initialize(&client, &host.mcp_url(), &token).await;

    // Any protocol list triggers the one session-scoped discovery.
    let resources = rpc(
        &client,
        &host.mcp_url(),
        &token,
        &session,
        2,
        "resources/list",
        json!({}),
    )
    .await;
    assert_eq!(resources["result"]["resources"][0]["uri"], "docs://home");

    let templates = rpc(
        &client,
        &host.mcp_url(),
        &token,
        &session,
        3,
        "resources/templates/list",
        json!({}),
    )
    .await;
    assert_eq!(
        templates["result"]["resourceTemplates"][0]["uriTemplate"],
        "docs://page/{id}"
    );

    let read = rpc(
        &client,
        &host.mcp_url(),
        &token,
        &session,
        4,
        "resources/read",
        json!({"uri": "docs://page/42"}),
    )
    .await;
    assert!(read["result"]["contents"][0]["text"]
        .as_str()
        .unwrap()
        .contains("resource body"));
    assert!(read["result"]["contents"][0]["text"]
        .as_str()
        .unwrap()
        .contains("BEGIN UNTRUSTED UPSTREAM MCP CONTENT"));

    let prompts = rpc(
        &client,
        &host.mcp_url(),
        &token,
        &session,
        5,
        "prompts/list",
        json!({}),
    )
    .await;
    assert_eq!(prompts["result"]["prompts"][0]["name"], "docs/review");

    let prompt = rpc(
        &client,
        &host.mcp_url(),
        &token,
        &session,
        6,
        "prompts/get",
        json!({"name": "docs/review", "arguments": {"topic": "roadmap"}}),
    )
    .await;
    assert!(prompt["result"]["messages"][0]["content"]["text"]
        .as_str()
        .unwrap()
        .contains("roadmap"));
    assert!(prompt["result"]["messages"][0]["content"]["text"]
        .as_str()
        .unwrap()
        .contains("BEGIN UNTRUSTED UPSTREAM MCP CONTENT"));

    let completion = rpc(
        &client,
        &host.mcp_url(),
        &token,
        &session,
        7,
        "completion/complete",
        json!({
            "ref": {"type": "ref/resource", "uri": "docs://page/{id}"},
            "argument": {"name": "id", "value": ""},
        }),
    )
    .await;
    assert_eq!(
        completion["result"]["completion"]["values"],
        json!(["one", "two"])
    );
}

async fn initialize(client: &reqwest::Client, url: &str, token: &str) -> String {
    let response = client
        .post(url)
        .bearer_auth(token)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "rust-test", "version": "1"},
            },
        }))
        .send()
        .await
        .unwrap();
    let session = response.headers()["mcp-session-id"]
        .to_str()
        .unwrap()
        .to_string();
    let notification = client
        .post(url)
        .bearer_auth(token)
        .header("mcp-session-id", &session)
        .header("mcp-protocol-version", "2025-06-18")
        .json(&json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(notification.status(), StatusCode::ACCEPTED);
    session
}

async fn rpc(
    client: &reqwest::Client,
    url: &str,
    token: &str,
    session: &str,
    id: u64,
    method: &str,
    params: Value,
) -> Value {
    client
        .post(url)
        .bearer_auth(token)
        .header("mcp-session-id", session)
        .header("mcp-protocol-version", "2025-06-18")
        .json(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

fn tool_payload(response: &Value) -> Value {
    serde_json::from_str(response["result"]["content"][0]["text"].as_str().unwrap()).unwrap()
}

fn add_mcp_connection(broker: &Broker, name: &str, port: u16) {
    broker
        .store
        .add_connection(ConnectionSpec {
            name: name.into(),
            config: ConnectionConfig::Api {
                host: "127.0.0.1".into(),
                scheme: "http".into(),
                port: Some(port),
                trusted_ca_bundle_path: None,
                template: String::new(),
                mcp_path: Some("/mcp".into()),
                test_path: None,
                oauth: None,
                signer: None,
                client_cert_path: None,
                client_key_path: None,
            },
            secrets: vec![],
        })
        .unwrap();
}
