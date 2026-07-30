//! The MCP host against a real broker.
//!
//! This runs the real thing end to end: a real broker on a real Unix socket,
//! the production Rust host, and MCP spoken over loopback. It catches the
//! broker and host disagreeing about what a wiring means.

use std::sync::Arc;
use std::time::Duration;

use aka_core::broker::Broker;
use aka_core::config::BrokerConfig;
use aka_core::daemon;
use aka_core::events::BrokerEvents;
use aka_core::mcp::SUPPORTED_PROTOCOL_VERSIONS;
use aka_core::paths::Paths;
use aka_core::store::ConnectionSpec;
use aka_core::types::ConnectionConfig;
use aka_core::vault::MemoryVault;
use serde_json::{json, Value};
use zeroize::Zeroizing;

struct NoopEvents;
impl BrokerEvents for NoopEvents {}

struct RunningMcpHost {
    base_url: String,
    _host: aka_core::mcp_host::McpHostHandle,
}

async fn start_mcp_host(broker: Arc<Broker>) -> RunningMcpHost {
    let host = aka_core::mcp_host::serve(broker)
        .await
        .expect("start Rust MCP host");
    RunningMcpHost {
        base_url: host.base_url(),
        _host: host,
    }
}

fn host_contract() -> Value {
    serde_json::from_str(include_str!("../../../fixtures/mcp-host-contract.json"))
        .expect("golden MCP host fixture")
}

fn contract_strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .expect("contract string array")
        .iter()
        .map(|value| value.as_str().expect("contract string").to_string())
        .collect()
}

#[test]
fn mcp_host_contract_freezes_the_supported_protocol_revisions() {
    let contract = host_contract();
    assert_eq!(
        contract_strings(&contract["protocol"]["supported_upstream_versions"]),
        SUPPORTED_PROTOCOL_VERSIONS
    );
}

/// A minimal MCP client: initialize, then call tools over one session.
struct McpClient {
    base: String,
    token: String,
    session: Option<String>,
    last_content_type: Option<String>,
    next_id: u64,
    http: reqwest::Client,
}

impl McpClient {
    fn new(base_url: &str, path: &str, token: &str) -> Self {
        Self {
            base: format!("{}{}", base_url.trim_end_matches('/'), path),
            token: token.to_string(),
            session: None,
            last_content_type: None,
            next_id: 0,
            http: reqwest::Client::new(),
        }
    }

    async fn send(&mut self, method: &str, params: Value) -> (u16, Value) {
        self.next_id += 1;
        let mut request = self
            .http
            .post(&self.base)
            .bearer_auth(&self.token)
            // The streamable-HTTP transport replies with either, and will
            // refuse a request that does not accept both.
            .header("accept", "application/json, text/event-stream")
            .json(&json!({
                "jsonrpc": "2.0",
                "id": self.next_id,
                "method": method,
                "params": params,
            }));
        if let Some(session) = &self.session {
            request = request.header("mcp-session-id", session.clone());
        }

        let response = request.send().await.expect("mcp request");
        let status = response.status().as_u16();
        if let Some(session) = response.headers().get("mcp-session-id") {
            self.session = Some(session.to_str().expect("session id").to_string());
        }
        self.last_content_type = response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        let body = response.text().await.expect("body");
        (status, parse_body(&body))
    }

    /// The names of every tool this session exposes, sorted.
    async fn list_tools(&mut self) -> Vec<String> {
        let (status, body) = self.send("tools/list", json!({})).await;
        assert_eq!(status, 200, "tools/list failed: {body}");
        let mut names: Vec<String> = body["result"]["tools"]
            .as_array()
            .expect("tools array")
            .iter()
            .map(|tool| tool["name"].as_str().expect("name").to_string())
            .collect();
        names.sort();
        names
    }

    async fn initialize(&mut self, protocol_version: &str) -> (u16, Value) {
        self.send(
            "initialize",
            json!({
                "protocolVersion": protocol_version,
                "capabilities": {},
                "clientInfo": {"name": "aka-test", "version": "1.0.0"},
            }),
        )
        .await
    }

    /// The parsed JSON payload of a tool result's first text block.
    async fn call_tool(&mut self, name: &str, arguments: Value) -> Value {
        let (status, body) = self
            .send("tools/call", json!({"name": name, "arguments": arguments}))
            .await;
        assert_eq!(status, 200, "tools/call failed: {body}");
        body["result"].clone()
    }
}

/// The transport answers as JSON or as a single SSE `data:` frame.
fn parse_body(body: &str) -> Value {
    if let Ok(value) = serde_json::from_str::<Value>(body) {
        return value;
    }
    for line in body.lines() {
        if let Some(data) = line.strip_prefix("data: ") {
            if let Ok(value) = serde_json::from_str::<Value>(data) {
                return value;
            }
        }
    }
    Value::Null
}

fn tool_payload(result: &Value) -> Value {
    let text = result["content"][0]["text"].as_str().unwrap_or("null");
    serde_json::from_str(text).unwrap_or(Value::Null)
}

#[tokio::test]
async fn broker_http_relay_matches_the_shared_mcp_fixture() {
    let fixture: Value =
        serde_json::from_str(include_str!("../../../fixtures/mcp-http-relay.json"))
            .expect("golden relay fixture");
    let upstream_body = fixture["body"].as_str().unwrap().to_string();
    let session = fixture["headers"]["mcp-session-id"]
        .as_str()
        .unwrap()
        .to_string();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream");
    let port = listener.local_addr().unwrap().port();
    let app = axum::Router::new().route(
        "/mcp",
        axum::routing::post(move || {
            let body = upstream_body.clone();
            let session = session.clone();
            async move {
                axum::http::Response::builder()
                    .status(200)
                    .header("content-type", "application/json")
                    .header("mcp-session-id", session)
                    .body(axum::body::Body::from(body))
                    .unwrap()
            }
        }),
    );
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
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
            name: "golden-mcp".into(),
            config: ConnectionConfig::Api {
                host: "127.0.0.1".into(),
                scheme: "http".into(),
                port: Some(port),
                trusted_ca_bundle_path: None,
                template: String::new(),
                mcp_path: Some("/mcp".into()),
                test_path: None,
                oauth: None,
            },
            secrets: vec![],
        })
        .unwrap();
    let daemon = daemon::serve(broker).await.unwrap();
    let token = pair(&daemon.socket_path, "golden-test").await;
    let relayed = uds_post_auth(
        &daemon.socket_path,
        "/v1/http",
        &token,
        &json!({
            "connection": "golden-mcp",
            "method": "POST",
            "path": "/mcp",
            "headers": {"content-type": "application/json"},
            "body": {"jsonrpc": "2.0", "id": 7, "method": "tools/list", "params": {}},
        }),
    )
    .await;

    for field in ["status", "body", "body_encoding", "set_cookie_headers"] {
        assert_eq!(relayed[field], fixture[field], "relay field {field}");
    }
    for (name, value) in fixture["headers"].as_object().unwrap() {
        assert_eq!(&relayed["headers"][name], value, "relay header {name}");
    }
}

#[tokio::test]
async fn broker_mcp_relay_returns_when_the_matching_sse_frame_arrives() {
    use futures::StreamExt as _;
    use std::convert::Infallible;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream");
    let port = listener.local_addr().unwrap().port();
    let app = axum::Router::new().route(
        "/mcp",
        axum::routing::post(|| async move {
            let frames = axum::body::Bytes::from_static(
                b"data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\n\
                  data: {\"jsonrpc\":\"2.0\",\"id\":6,\"result\":{\"wrong\":true}}\n\n\
                  data: {\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"ok\":true}}\n\n",
            );
            let stream =
                futures::stream::once(async move { Ok::<axum::body::Bytes, Infallible>(frames) })
                    .chain(futures::stream::pending());
            axum::http::Response::builder()
                .status(200)
                .header("content-type", "text/event-stream")
                .body(axum::body::Body::from_stream(stream))
                .unwrap()
        }),
    );
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
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
            name: "streaming-mcp".into(),
            config: ConnectionConfig::Api {
                host: "127.0.0.1".into(),
                scheme: "http".into(),
                port: Some(port),
                trusted_ca_bundle_path: None,
                template: String::new(),
                mcp_path: Some("/mcp".into()),
                test_path: None,
                oauth: None,
            },
            secrets: vec![],
        })
        .unwrap();
    let daemon = daemon::serve(broker).await.unwrap();
    let token = pair(&daemon.socket_path, "stream-test").await;
    let relayed = tokio::time::timeout(
        Duration::from_secs(2),
        uds_post_auth(
            &daemon.socket_path,
            "/v1/http",
            &token,
            &json!({
                "connection": "streaming-mcp",
                "method": "POST",
                "path": "/mcp",
                "headers": {"accept": "text/event-stream"},
                "body": {"jsonrpc": "2.0", "id": 7, "method": "tools/list", "params": {}},
            }),
        ),
    )
    .await
    .expect("the matching frame should end the relay");
    let body = relayed["body"].as_str().expect("relayed SSE");
    assert!(body.contains("\"id\":6"), "earlier frames are preserved");
    assert!(body.contains("\"id\":7"), "matching response is preserved");
}

#[tokio::test]
async fn the_broker_decides_what_an_agent_sees_over_mcp() {
    let contract = host_contract();
    let transport = &contract["transport"];
    let protocol = &contract["protocol"];
    let expected = &contract["real_broker"];

    // A real upstream, so the credential injection is observable rather
    // than assumed.
    let upstream_auth: Arc<std::sync::Mutex<Option<String>>> = Arc::default();
    let seen = upstream_auth.clone();
    let mcp_auth: Arc<std::sync::Mutex<Option<String>>> = Arc::default();
    let mcp_seen = mcp_auth.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream");
    let upstream_port = listener.local_addr().expect("addr").port();
    let app = axum::Router::new()
        .route(
            "/mcp",
            axum::routing::post(
                move |headers: axum::http::HeaderMap, body: axum::Json<Value>| {
                    let seen = mcp_seen.clone();
                    async move {
                        *seen.lock().expect("lock") = headers
                            .get("authorization")
                            .and_then(|value| value.to_str().ok())
                            .map(str::to_string);
                        let id = body.0["id"].clone();
                        let result = match body.0["method"].as_str() {
                            // A conforming server declares every capability it
                            // offers; the MCP host only calls `tools/list` when
                            // `tools` is advertised, so omitting it here would
                            // make this upstream contribute nothing.
                            Some("initialize") => json!({
                                "protocolVersion": "2025-06-18",
                                "capabilities": {"tools": {}},
                                "serverInfo": {"name": "notes", "version": "1.0.0"},
                            }),
                            Some("tools/list") => json!({
                                "tools": [{
                                    "name": "search",
                                    "description": "Search notes",
                                    "inputSchema": {
                                        "type": "object",
                                        "properties": {"query": {"type": "string"}},
                                    },
                                }],
                            }),
                            Some("tools/call") => json!({
                                "content": [{
                                    "type": "text",
                                    "text": format!("found: {}", body.0["params"]["arguments"]),
                                }],
                            }),
                            _ => json!(null),
                        };
                        axum::Json(json!({"jsonrpc": "2.0", "id": id, "result": result}))
                    }
                },
            ),
        )
        .route(
            "/whoami",
            axum::routing::get(move |headers: axum::http::HeaderMap| {
                let seen = seen.clone();
                async move {
                    *seen.lock().expect("lock") = headers
                        .get("authorization")
                        .and_then(|value| value.to_str().ok())
                        .map(str::to_string);
                    "ok"
                }
            }),
        );
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let dir = tempfile::tempdir().expect("tempdir");
    let paths = Paths::under(dir.path());
    paths.ensure().expect("paths");
    let broker = Broker::new(
        paths.clone(),
        Arc::new(MemoryVault::new()),
        BrokerConfig::default(),
        Arc::new(NoopEvents),
    )
    .await
    .expect("broker");
    let daemon = daemon::serve(broker.clone()).await.expect("daemon");

    // Two connections, so "wired" has something to be distinguished from.
    broker
        .store
        .add_secret("API_KEY", Zeroizing::new("secret-value".into()))
        .expect("secret");
    for name in ["prod-db", "deploy-host"] {
        broker
            .store
            .add_connection(ConnectionSpec {
                name: name.into(),
                config: ConnectionConfig::Api {
                    host: "127.0.0.1".into(),
                    scheme: "http".into(),
                    port: Some(upstream_port),
                    trusted_ca_bundle_path: None,
                    template: "Authorization: Bearer {{API_KEY}}".into(),

                    mcp_path: None,
                    test_path: None,
                    oauth: None,
                },
                secrets: vec![],
            })
            .expect("connection");
    }

    broker
        .store
        .add_connection(ConnectionSpec {
            name: "notes".into(),
            config: ConnectionConfig::Api {
                host: "127.0.0.1".into(),
                scheme: "http".into(),
                port: Some(upstream_port),
                trusted_ca_bundle_path: None,
                template: "Authorization: Bearer {{API_KEY}}".into(),
                mcp_path: Some("/mcp".into()),
                test_path: None,
                oauth: None,
            },
            secrets: vec![],
        })
        .expect("mcp connection");

    // Every agent shares one key; access is a property of the connection.
    let first = pair(&daemon.socket_path, "claude-code").await;

    // Disable one connection so "enabled" and "exists" cannot be confused
    // for each other.
    let deploy = broker
        .store
        .list_connections()
        .into_iter()
        .find(|c| c.name == "deploy-host")
        .expect("deploy-host");
    broker
        .ui_set_tool_access(&deploy.id, false)
        .expect("disable");

    let host = start_mcp_host(broker.clone()).await;
    let mcp_path = transport["path"].as_str().expect("MCP path");
    let protocol_version = protocol["initialize_version"]
        .as_str()
        .expect("initialize protocol version");
    let initialize_status = transport["initialize_status"]
        .as_u64()
        .expect("initialize status") as u16;

    // A paired agent gets a session.
    let mut wired = McpClient::new(&host.base_url, mcp_path, &first);
    let (status, initialized) = wired.initialize(protocol_version).await;
    assert_eq!(status, initialize_status);
    assert_eq!(
        initialized["result"]["protocolVersion"], protocol["initialize_version"],
        "the host negotiated a different protocol revision"
    );
    assert!(
        wired.session.is_some(),
        "initialize must return an mcp-session-id"
    );
    let content_type = wired
        .last_content_type
        .as_deref()
        .and_then(|value| value.split(';').next())
        .expect("initialize content-type");
    assert!(
        contract_strings(&transport["response_content_types"])
            .iter()
            .any(|expected| expected == content_type),
        "unexpected MCP content-type {content_type:?}"
    );

    // …whose tool list is exactly what the broker says it is wired to.
    let tools = wired.list_tools().await;
    assert_eq!(
        tools,
        contract_strings(&expected["wired_tools"]),
        "an MCP upstream contributes its own tools; disabled ones contribute none"
    );

    // The real thing: a call that reaches the upstream server, with the
    // credential injected by the broker and never seen by the agent.
    let result = wired
        .call_tool(
            expected["http_call"]["tool"].as_str().expect("HTTP tool"),
            expected["http_call"]["arguments"].clone(),
        )
        .await;
    let response = tool_payload(&result);
    assert_eq!(
        response["status"], expected["http_call"]["response_status"],
        "upstream call failed: {response}"
    );
    let seen = upstream_auth.lock().expect("lock").clone();
    assert_eq!(
        seen.as_deref(),
        expected["http_call"]["upstream_authorization"].as_str(),
        "the broker must inject the credential on the upstream leg"
    );
    let forbidden_response_text = expected["http_call"]["forbidden_response_text"]
        .as_str()
        .expect("forbidden response text");
    assert!(
        !serde_json::to_string(&result)
            .expect("json")
            .contains(forbidden_response_text),
        "the secret must not come back to the agent: {result}"
    );

    // The MCP upstream is reached *through* the broker, so its credential
    // is injected on the upstream leg exactly like any other API call.
    let searched = wired
        .call_tool(
            expected["mcp_call"]["tool"].as_str().expect("MCP tool"),
            expected["mcp_call"]["arguments"].clone(),
        )
        .await;
    let text = searched["content"][0]["text"].as_str().unwrap_or_default();
    let response_contains = expected["mcp_call"]["response_contains"]
        .as_str()
        .expect("MCP response substring");
    assert!(
        text.contains(response_contains),
        "the upstream tool should have run: {searched}"
    );
    assert_eq!(
        mcp_auth.lock().expect("lock").as_deref(),
        expected["mcp_call"]["upstream_authorization"].as_str(),
        "the broker must inject the credential for MCP traffic too"
    );
    assert!(
        !text.contains(&first),
        "the agent's own token must not reach the MCP upstream"
    );
    let mcp_audit = broker
        .audit
        .recent(50)
        .into_iter()
        .find(|entry| {
            entry.connection.as_deref() == expected["mcp_call"]["audit"]["connection"].as_str()
                && entry.fields.get("mcp_method") == Some(&expected["mcp_call"]["audit"]["method"])
                && entry.fields.get("mcp_name") == Some(&expected["mcp_call"]["audit"]["name"])
        })
        .expect("the proxied MCP tool call must carry method and name audit fields");
    assert_eq!(
        mcp_audit.fields["path"],
        expected["mcp_call"]["audit"]["path"]
    );

    // `agentmfa_status` — the tool an agent is told to trust when confused —
    // names the upstream by its real tool names, not the request-tool naming
    // convention. Regression: it used to advertise `agentmfa_notes_request`,
    // a tool that does not exist.
    let status = tool_payload(
        &wired
            .call_tool(
                expected["status"]["tool"].as_str().expect("status tool"),
                json!({}),
            )
            .await,
    );
    let named: Vec<&str> = status["tools"]
        .as_array()
        .expect("status tools array")
        .iter()
        .map(|entry| entry["tool"].as_str().expect("tool name"))
        .collect();
    assert!(
        named.contains(
            &expected["status"]["contains_tool"]
                .as_str()
                .expect("status tool name")
        ),
        "status must report the upstream by its real tool name: {status}"
    );
    let excluded_status_fragment = expected["status"]["excludes_tool_fragment"]
        .as_str()
        .expect("excluded status fragment");
    assert!(
        !named
            .iter()
            .any(|name| name.contains(excluded_status_fragment)),
        "status must not advertise a phantom request tool for an MCP upstream: {status}"
    );

    // With every connection disabled, a session gets the status +
    // connect-request tools and nothing else — access is per tool, shared
    // by every client of the one key.
    for connection in broker.store.list_connections() {
        broker
            .ui_set_tool_access(&connection.id, false)
            .expect("disable");
    }
    let mut bare = McpClient::new(&host.base_url, mcp_path, &first);
    let (status, _) = bare.initialize(protocol_version).await;
    assert_eq!(status, initialize_status);
    assert_eq!(
        bare.list_tools().await,
        contract_strings(&expected["bare_tools"])
    );
    let status = tool_payload(
        &bare
            .call_tool(
                expected["status"]["tool"].as_str().expect("status tool"),
                json!({}),
            )
            .await,
    );
    assert_eq!(
        status["tools"], expected["status"]["bare_tools"],
        "every tool disabled ⇒ nothing to report"
    );

    // An unpaired token cannot open a session at all.
    let mut stranger = McpClient::new(&host.base_url, mcp_path, "not-a-real-token");
    let (status, _) = stranger.initialize(protocol_version).await;
    assert_eq!(
        status,
        transport["unauthorized_initialize_status"]
            .as_u64()
            .expect("unauthorized initialize status") as u16
    );
}

async fn pair(socket: &std::path::Path, name: &str) -> String {
    let body = uds_post(socket, "/v1/pair", &json!({"agent_name": name})).await;
    body["token"].as_str().expect("token").to_string()
}

/// Minimal HTTP/1.1 POST over a Unix socket.
async fn uds_post(socket: &std::path::Path, path: &str, body: &Value) -> Value {
    uds_post_inner(socket, path, None, body).await
}

async fn uds_post_auth(socket: &std::path::Path, path: &str, token: &str, body: &Value) -> Value {
    uds_post_inner(socket, path, Some(token), body).await
}

async fn uds_post_inner(
    socket: &std::path::Path,
    path: &str,
    token: Option<&str>,
    body: &Value,
) -> Value {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let mut stream = tokio::net::UnixStream::connect(socket)
        .await
        .expect("connect");
    let payload = serde_json::to_vec(body).expect("serialize");
    let auth = token
        .map(|token| format!("Authorization: Bearer {token}\r\n"))
        .unwrap_or_default();
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: localhost\r\n{auth}Content-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        payload.len()
    );
    stream.write_all(request.as_bytes()).await.expect("write");
    stream.write_all(&payload).await.expect("write body");

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.expect("read");
    let text = String::from_utf8_lossy(&raw);
    let body = text.split("\r\n\r\n").nth(1).unwrap_or_default();
    serde_json::from_str(body).unwrap_or(Value::Null)
}
