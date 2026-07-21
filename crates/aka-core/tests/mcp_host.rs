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
use aka_core::types::ConnectionConfig;
use aka_core::vault::MemoryVault;
use serde_json::{json, Value};
use zeroize::Zeroizing;

struct NoopEvents;
impl BrokerEvents for NoopEvents {}

fn bundle() -> Option<PathBuf> {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../dist/sidecar/main.js")
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
        eprintln!("skipping: no dist/sidecar/main.js (run `npm run sidecar:build`)");
        return;
    };
    if !have_node() {
        eprintln!("skipping: no node on PATH");
        return;
    }

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
                    host: "example.invalid".into(),
                    scheme: "https".into(),
                    port: None,
                    template: "Authorization: Bearer {{API_KEY}}".into(),
                },
                secrets: vec![],
            })
            .expect("connection");
    }

    // The first agent is auto-wired to everything by design; the second
    // starts with nothing. That asymmetry is exactly what we want to test.
    let first = pair(&daemon.socket_path, "claude-code").await;
    let second = pair(&daemon.socket_path, "other-agent").await;

    // Narrow the first agent down to one connection so "wired" and
    // "exists" cannot be confused for each other.
    let deploy = broker
        .store
        .list_connections()
        .into_iter()
        .find(|c| c.name == "deploy-host")
        .expect("deploy-host");
    let agents = broker.paired_agents();
    let claude = agents
        .iter()
        .find(|a| a.name == "claude-code")
        .expect("claude-code");
    broker
        .ui_set_wiring(&claude.id, &deploy.id, false)
        .expect("unwire");

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

    // …and sees only what the broker says it is wired to.
    let listed = tool_payload(&wired.call_tool("multitool_list_tools", json!({})).await);
    let names: Vec<&str> = listed
        .as_array()
        .expect("array")
        .iter()
        .map(|entry| entry["name"].as_str().expect("name"))
        .collect();
    assert_eq!(names, vec!["prod-db"], "unwired connections must not appear");

    // Naming the unwired one directly is still refused.
    let refused = wired
        .call_tool("multitool_describe_tool", json!({"name": "deploy-host"}))
        .await;
    assert_eq!(
        refused["isError"], true,
        "an unwired connection must be refused: {refused}"
    );

    // A second agent, wired to nothing, sees nothing.
    let mut bare = McpClient::new(&endpoint, &second);
    assert_eq!(bare.initialize().await, 200);
    let empty = tool_payload(&bare.call_tool("multitool_list_tools", json!({})).await);
    assert_eq!(empty, json!([]), "a fresh agent starts with no wirings");

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

    let mut stream = tokio::net::UnixStream::connect(socket).await.expect("connect");
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
