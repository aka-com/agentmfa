//! The MCP host against a real broker.
//!
//! The sidecar's own tests use a fake broker, which proves the translation
//! but not the contract. This one runs the real thing end to end: a real
//! broker on a real Unix socket, the real Node sidecar, and MCP spoken over
//! loopback. It is the test that would catch the broker and the sidecar
//! disagreeing about what a wiring means.
//!
//! Skips when the sidecar bundle or Node is missing, like
//! `sidecar_process.rs`.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use aka_core::broker::Broker;
use aka_core::config::BrokerConfig;
use aka_core::daemon;
use aka_core::events::BrokerEvents;
use aka_core::paths::Paths;
use aka_core::sidecar::{Sidecar, SidecarConfig, SidecarEndpoint};
use aka_core::store::ConnectionSpec;
use aka_core::types::{ConfirmationMethod, ConnectionConfig};
use aka_core::vault::MemoryVault;
use serde_json::{json, Value};
use zeroize::Zeroizing;

struct NoopEvents;
impl BrokerEvents for NoopEvents {
    fn confirm_action(&self, _description: &str) -> Option<ConfirmationMethod> {
        Some(ConfirmationMethod::Waived)
    }
}

fn bundle() -> Option<PathBuf> {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../dist/sidecar/main.mjs")
        .canonicalize()
        .ok()
        .filter(|path| path.is_file())
}

fn have_node() -> bool {
    std::process::Command::new("node")
        .arg("--version")
        .output()
        .is_ok_and(|out| out.status.success())
}

/// A minimal MCP client: initialize, then call tools over one session.
struct McpClient {
    base: String,
    token: String,
    session: Option<String>,
    next_id: u64,
    http: reqwest::Client,
}

impl McpClient {
    fn new(endpoint: &SidecarEndpoint, token: &str) -> Self {
        Self {
            base: format!("{}/mcp", endpoint.base_url()),
            token: token.to_string(),
            session: None,
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

    async fn initialize(&mut self) -> u16 {
        let (status, _) = self
            .send(
                "initialize",
                json!({
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "aka-test", "version": "1.0.0"},
                }),
            )
            .await;
        status
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
async fn the_broker_decides_what_an_agent_sees_over_mcp() {
    let Some(script) = bundle() else {
        eprintln!("skipping: no dist/sidecar/main.mjs (run `npm run sidecar:build`)");
        return;
    };
    if !have_node() {
        eprintln!("skipping: no node on PATH");
        return;
    }

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
                            // offers; the sidecar only calls `tools/list` when
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
                    template: "Authorization: Bearer {{API_KEY}}".into(),

                    mcp_path: None,
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
                template: "Authorization: Bearer {{API_KEY}}".into(),
                mcp_path: Some("/mcp".into()),
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

    let sidecar = Sidecar::spawn(SidecarConfig {
        node: PathBuf::from("node"),
        script,
        broker_socket: daemon.socket_path.clone(),
    });
    let endpoint = sidecar
        .wait_ready(Duration::from_secs(20))
        .await
        .expect("sidecar ready");

    // A paired agent gets a session.
    let mut wired = McpClient::new(&endpoint, &first);
    assert_eq!(wired.initialize().await, 200);

    // …whose tool list is exactly what the broker says it is wired to.
    let tools = wired.list_tools().await;
    assert_eq!(
        tools,
        vec![
            "agentmfa_connect",
            "agentmfa_notes_search",
            "agentmfa_prod-db_request",
            "agentmfa_status"
        ],
        "an MCP upstream contributes its own tools; disabled ones contribute none"
    );

    // The real thing: a call that reaches the upstream server, with the
    // credential injected by the broker and never seen by the agent.
    let result = wired
        .call_tool(
            "agentmfa_prod-db_request",
            json!({"method": "GET", "path": "/whoami"}),
        )
        .await;
    let response = tool_payload(&result);
    assert_eq!(response["status"], 200, "upstream call failed: {response}");
    let seen = upstream_auth.lock().expect("lock").clone();
    assert_eq!(
        seen.as_deref(),
        Some("Bearer secret-value"),
        "the broker must inject the credential on the upstream leg"
    );
    assert!(
        !serde_json::to_string(&result)
            .expect("json")
            .contains("secret-value"),
        "the secret must not come back to the agent: {result}"
    );

    // The MCP upstream is reached *through* the broker, so its credential
    // is injected on the upstream leg exactly like any other API call.
    let searched = wired
        .call_tool("agentmfa_notes_search", json!({"query": "roadmap"}))
        .await;
    let text = searched["content"][0]["text"].as_str().unwrap_or_default();
    assert!(
        text.contains("roadmap"),
        "the upstream tool should have run: {searched}"
    );
    assert_eq!(
        mcp_auth.lock().expect("lock").as_deref(),
        Some("Bearer secret-value"),
        "the broker must inject the credential for MCP traffic too"
    );
    assert!(
        !text.contains(&first),
        "the agent's own token must not reach the MCP upstream"
    );

    // `agentmfa_status` — the tool an agent is told to trust when confused —
    // names the upstream by its real tool names, not the request-tool naming
    // convention. Regression: it used to advertise `agentmfa_notes_request`,
    // a tool that does not exist.
    let status = tool_payload(&wired.call_tool("agentmfa_status", json!({})).await);
    let named: Vec<&str> = status["tools"]
        .as_array()
        .expect("status tools array")
        .iter()
        .map(|entry| entry["tool"].as_str().expect("tool name"))
        .collect();
    assert!(
        named.contains(&"agentmfa_notes_search"),
        "status must report the upstream by its real tool name: {status}"
    );
    assert!(
        !named.iter().any(|name| name.contains("notes_request")),
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
    let mut bare = McpClient::new(&endpoint, &first);
    assert_eq!(bare.initialize().await, 200);
    assert_eq!(
        bare.list_tools().await,
        vec!["agentmfa_connect", "agentmfa_status"]
    );
    let status = tool_payload(&bare.call_tool("agentmfa_status", json!({})).await);
    assert_eq!(
        status["tools"],
        json!([]),
        "every tool disabled ⇒ nothing to report"
    );

    // An unpaired token cannot open a session at all.
    let mut stranger = McpClient::new(&endpoint, "not-a-real-token");
    assert_eq!(stranger.initialize().await, 401);
}

async fn pair(socket: &std::path::Path, name: &str) -> String {
    let body = uds_post(socket, "/v1/pair", &json!({"agent_name": name})).await;
    body["token"].as_str().expect("token").to_string()
}

/// Minimal HTTP/1.1 POST over a Unix socket.
async fn uds_post(socket: &std::path::Path, path: &str, body: &Value) -> Value {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let mut stream = tokio::net::UnixStream::connect(socket)
        .await
        .expect("connect");
    let payload = serde_json::to_vec(body).expect("serialize");
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n\
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
