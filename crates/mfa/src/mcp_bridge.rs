//! `mfa mcp`: a stdio ⇄ streamable-HTTP MCP bridge.
//!
//! Every MCP client that can launch a stdio server — Claude Code, Claude
//! Desktop, Codex, custom harnesses — can be pointed at `mfa mcp` and needs
//! no token pasting and no port discovery: the bridge reads this computer's
//! shared key from the broker's token file and finds the MCP host through
//! the broker's discovery manifest (the sidecar's loopback port is dynamic,
//! so it is advertised, not pinned).
//!
//! The bridge is a translator, not a gate: each newline-delimited JSON-RPC
//! message from stdin is POSTed to the MCP endpoint with the shared key,
//! and the response — a single JSON body or a text/event-stream — comes
//! back out as newline-delimited JSON on stdout. Authorization stays where
//! it was: the sidecar resolves the key against the broker on every call.

use std::path::Path;
use std::time::Duration;

use aka_core::paths::Paths;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::client::{shared_key, unix_http};

/// How long to wait for the broker (and its MCP host) to appear before
/// giving up, and how often to re-probe while waiting.
const DISCOVER_TIMEOUT: Duration = Duration::from_secs(60);
const DISCOVER_INTERVAL: Duration = Duration::from_secs(2);

/* ------------------------------ discovery --------------------------------- */

/// The broker's discovery manifest.
async fn manifest(socket: &Path) -> std::io::Result<serde_json::Value> {
    let (status, body) = unix_http(
        socket,
        "GET",
        "/.well-known/agent-broker.json",
        None,
        None,
        None,
    )
    .await?;
    if status != 200 {
        return Err(std::io::Error::other(format!(
            "manifest fetch failed with HTTP {status}"
        )));
    }
    serde_json::from_str(&body).map_err(std::io::Error::other)
}

/// Wait for the broker's manifest to advertise a running MCP host.
async fn discover_mcp_url(socket: &Path) -> Result<String, String> {
    let deadline = tokio::time::Instant::now() + DISCOVER_TIMEOUT;
    let mut reported_waiting = false;
    let mut reported_no_mcp = false;
    loop {
        match manifest(socket).await {
            Ok(manifest) => {
                if let Some(url) = manifest["mcp_url"].as_str() {
                    return Ok(url.to_string());
                }
                if !reported_no_mcp {
                    eprintln!(
                        "mfa mcp: the broker is running but its MCP host is not; \
                         open the AgentMFA app (waiting)"
                    );
                    reported_no_mcp = true;
                }
            }
            Err(_) if !reported_waiting => {
                eprintln!(
                    "mfa mcp: waiting for the AgentMFA broker at {}",
                    socket.display()
                );
                reported_waiting = true;
            }
            Err(_) => {}
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(format!(
                "no MCP host within {}s — is the AgentMFA app running?",
                DISCOVER_TIMEOUT.as_secs()
            ));
        }
        tokio::time::sleep(DISCOVER_INTERVAL).await;
    }
}

/* ------------------------------- SSE frames ------------------------------- */

/// Incremental text/event-stream parser: push chunks in, get completed
/// events' data payloads out. Multi-line `data:` fields join with `\n`
/// (the SSE rule); `event:`/`id:`/comment lines are ignored — MCP rides
/// entirely in `data`.
#[derive(Default)]
pub struct SseParser {
    buffer: String,
    data: Vec<String>,
}

impl SseParser {
    pub fn push(&mut self, chunk: &str) -> Vec<String> {
        self.buffer.push_str(chunk);
        let mut events = Vec::new();
        while let Some(newline) = self.buffer.find('\n') {
            let line: String = self.buffer.drain(..=newline).collect();
            let line = line.trim_end_matches(['\n', '\r']);
            if line.is_empty() {
                if !self.data.is_empty() {
                    events.push(self.data.join("\n"));
                    self.data.clear();
                }
            } else if let Some(value) = line.strip_prefix("data:") {
                self.data
                    .push(value.strip_prefix(' ').unwrap_or(value).to_string());
            }
        }
        events
    }

    /// EOF: flush an unterminated final event, if the server closed without
    /// the trailing blank line.
    pub fn finish(&mut self) -> Option<String> {
        if self.data.is_empty() {
            None
        } else {
            let event = self.data.join("\n");
            self.data.clear();
            Some(event)
        }
    }
}

/* -------------------------------- bridge ---------------------------------- */

struct Bridge {
    http: reqwest::Client,
    paths: Paths,
    mcp_url: String,
    token: String,
    label: Option<String>,
    /// The streamable-HTTP session, captured from the initialize response's
    /// `Mcp-Session-Id` header and echoed on every later request.
    session: Option<String>,
}

/// One request's outcome: the JSON-RPC messages to emit on stdout.
enum Relay {
    Messages(Vec<String>),
    /// The key was rotated or the MCP host moved; the caller refreshes the
    /// named state and retries once.
    StaleToken,
    Unreachable,
}

impl Bridge {
    async fn post(&mut self, message: &str) -> Result<Relay, String> {
        let mut request = self
            .http
            .post(&self.mcp_url)
            .header("authorization", format!("Bearer {}", self.token))
            .header("accept", "application/json, text/event-stream")
            .header("content-type", "application/json")
            .body(message.to_string());
        if let Some(session) = &self.session {
            request = request.header("mcp-session-id", session.clone());
        }
        if let Some(label) = &self.label {
            request = request.header("x-agentmfa-client", label.clone());
        }
        // SEP-2243: surface the JSON-RPC method (and named tool/prompt) as
        // routing headers so the host and any load balancer between it and
        // us can route without parsing the body. A batch or non-JSON line
        // carries none — the body stays authoritative either way.
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(message) {
            if let Some(method) = value.get("method").and_then(|m| m.as_str()) {
                request = request.header("mcp-method", method);
                if let Some(name) = value
                    .get("params")
                    .and_then(|params| params.get("name"))
                    .and_then(|name| name.as_str())
                {
                    if let Ok(header) = reqwest::header::HeaderValue::from_str(name) {
                        request = request.header("mcp-name", header);
                    }
                }
            }
        }
        let response = match request.send().await {
            Ok(response) => response,
            Err(error) if error.is_connect() => return Ok(Relay::Unreachable),
            Err(error) => return Err(format!("MCP request failed: {error}")),
        };

        if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            return Ok(Relay::StaleToken);
        }
        if let Some(session) = response
            .headers()
            .get("mcp-session-id")
            .and_then(|v| v.to_str().ok())
        {
            self.session = Some(session.to_string());
        }
        let status = response.status().as_u16();
        if status == 202 || status == 204 {
            // An accepted notification produces no reply.
            return Ok(Relay::Messages(Vec::new()));
        }
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        if content_type.starts_with("text/event-stream") {
            let mut parser = SseParser::default();
            let mut messages = Vec::new();
            let mut body = response;
            while let Some(chunk) = body
                .chunk()
                .await
                .map_err(|error| format!("MCP stream failed: {error}"))?
            {
                for event in parser.push(&String::from_utf8_lossy(&chunk)) {
                    messages.push(event);
                }
            }
            if let Some(event) = parser.finish() {
                messages.push(event);
            }
            return Ok(Relay::Messages(messages));
        }

        let body = response
            .text()
            .await
            .map_err(|error| format!("MCP response read failed: {error}"))?;
        if body.trim().is_empty() {
            return Ok(Relay::Messages(Vec::new()));
        }
        Ok(Relay::Messages(vec![body]))
    }

    /// Refresh the shared key from the token file (rotation rewrote it).
    async fn refresh_token(&mut self) -> Result<(), String> {
        self.token = shared_key(&self.paths, self.label.as_deref()).await?;
        Ok(())
    }

    /// Re-discover the MCP host (a sidecar restart moves the port).
    async fn rediscover(&mut self) -> Result<(), String> {
        self.mcp_url = discover_mcp_url(&self.paths.socket_file()).await?;
        Ok(())
    }
}

/// Serialize a JSON-RPC message to exactly one stdout line. Anything that
/// parses is re-serialized compactly (SSE payloads may span lines); anything
/// that doesn't is dropped with a note — emitting a malformed line would
/// desynchronize the whole stdio framing.
fn one_line(message: &str) -> Option<String> {
    match serde_json::from_str::<serde_json::Value>(message) {
        Ok(value) => Some(value.to_string()),
        Err(_) => {
            eprintln!("mfa mcp: dropped a non-JSON frame from the MCP host");
            None
        }
    }
}

/// Run the bridge until stdin closes (the MCP client hanging up).
pub async fn run(paths: Paths, label: Option<String>) -> Result<(), String> {
    let socket = paths.socket_file();
    let mcp_url = discover_mcp_url(&socket).await?;
    let token = shared_key(&paths, label.as_deref()).await?;
    let mut bridge = Bridge {
        http: reqwest::Client::new(),
        paths,
        mcp_url,
        token,
        label,
        session: None,
    };

    let stdin = BufReader::new(tokio::io::stdin());
    let mut stdout = tokio::io::stdout();
    let mut lines = stdin.lines();
    while let Some(line) = lines
        .next_line()
        .await
        .map_err(|error| format!("stdin read failed: {error}"))?
    {
        if line.trim().is_empty() {
            continue;
        }
        let mut relay = bridge.post(&line).await?;
        // One recovery attempt per failure mode: a rotated key is re-read
        // from the token file; a moved MCP host is re-discovered. A repeat
        // failure surfaces instead of looping.
        if matches!(relay, Relay::StaleToken) {
            bridge.refresh_token().await?;
            relay = bridge.post(&line).await?;
        } else if matches!(relay, Relay::Unreachable) {
            bridge.rediscover().await?;
            bridge.session = None;
            relay = bridge.post(&line).await?;
        }
        let messages = match relay {
            Relay::Messages(messages) => messages,
            Relay::StaleToken => {
                return Err("the broker refused the shared key even after re-reading it".into())
            }
            Relay::Unreachable => return Err("the MCP host went away".into()),
        };
        for message in messages {
            if let Some(line) = one_line(&message) {
                stdout
                    .write_all(format!("{line}\n").as_bytes())
                    .await
                    .map_err(|error| format!("stdout write failed: {error}"))?;
            }
        }
        stdout
            .flush()
            .await
            .map_err(|error| format!("stdout flush failed: {error}"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sse_parser_yields_completed_events() {
        let mut parser = SseParser::default();
        assert!(parser.push("data: {\"a\"").is_empty());
        assert!(parser.push(":1}\n").is_empty());
        assert_eq!(parser.push("\n"), vec!["{\"a\":1}".to_string()]);
        // Two events in one chunk, one with an event: field to ignore.
        assert_eq!(
            parser.push("event: message\ndata: one\n\ndata: two\n\n"),
            vec!["one".to_string(), "two".to_string()]
        );
        assert!(parser.finish().is_none());
    }

    #[test]
    fn sse_parser_joins_multiline_data_and_flushes_at_eof() {
        let mut parser = SseParser::default();
        assert!(parser.push("data: line1\r\ndata: line2\r\n").is_empty());
        assert_eq!(parser.finish(), Some("line1\nline2".to_string()));
    }

    #[test]
    fn one_line_compacts_and_refuses_garbage() {
        assert_eq!(
            one_line("{\n  \"jsonrpc\": \"2.0\"\n}"),
            Some("{\"jsonrpc\":\"2.0\"}".to_string())
        );
        assert_eq!(one_line("not json"), None);
    }

    /// End-to-end over a real loopback server: JSON responses, SSE
    /// responses, the session header round-trip, and 202 notifications.
    #[tokio::test]
    async fn bridge_posts_and_relays_json_sse_and_sessions() {
        use axum::http::HeaderMap;
        use axum::response::IntoResponse;
        use axum::routing::post;

        async fn handler(headers: HeaderMap, body: String) -> axum::response::Response {
            assert_eq!(
                headers.get("authorization").unwrap(),
                "Bearer aka_testkey",
                "the shared key must ride every request"
            );
            let message: serde_json::Value = serde_json::from_str(&body).unwrap();
            match message["method"].as_str().unwrap() {
                "initialize" => (
                    [
                        ("mcp-session-id", "sess-1"),
                        ("content-type", "application/json"),
                    ],
                    r#"{"jsonrpc":"2.0","id":1,"result":{}}"#,
                )
                    .into_response(),
                "notifications/initialized" => {
                    assert_eq!(headers.get("mcp-session-id").unwrap(), "sess-1");
                    axum::http::StatusCode::ACCEPTED.into_response()
                }
                "tools/call" => {
                    assert_eq!(headers.get("mcp-session-id").unwrap(), "sess-1");
                    assert_eq!(headers.get("x-agentmfa-client").unwrap(), "test-client");
                    // SEP-2243 routing headers, derived from the body.
                    assert_eq!(headers.get("mcp-method").unwrap(), "tools/call");
                    assert_eq!(headers.get("mcp-name").unwrap(), "search");
                    (
                        [("content-type", "text/event-stream")],
                        "event: message\ndata: {\"jsonrpc\":\"2.0\",\n\
                         data: \"id\":2,\"result\":{\"ok\":true}}\n\n",
                    )
                        .into_response()
                }
                other => panic!("unexpected method {other}"),
            }
        }

        let app = axum::Router::new().route("/mcp", post(handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let dir = tempfile::tempdir().unwrap();
        let mut bridge = Bridge {
            http: reqwest::Client::new(),
            paths: Paths::under(dir.path()),
            mcp_url: format!("http://127.0.0.1:{port}/mcp"),
            token: "aka_testkey".into(),
            label: Some("test-client".into()),
            session: None,
        };

        let Relay::Messages(init) = bridge
            .post(r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#)
            .await
            .unwrap()
        else {
            panic!("initialize should relay")
        };
        assert_eq!(init, vec![r#"{"jsonrpc":"2.0","id":1,"result":{}}"#]);
        assert_eq!(bridge.session.as_deref(), Some("sess-1"));

        let Relay::Messages(none) = bridge
            .post(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#)
            .await
            .unwrap()
        else {
            panic!("notification should relay")
        };
        assert!(none.is_empty(), "202 carries no reply");

        let Relay::Messages(called) = bridge
            .post(r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"search"}}"#)
            .await
            .unwrap()
        else {
            panic!("call should relay")
        };
        // The SSE payload spanned two data lines; joined, it is one message.
        assert_eq!(called.len(), 1);
        let value: serde_json::Value = serde_json::from_str(&called[0]).unwrap();
        assert_eq!(value["result"]["ok"], true);
    }

    #[tokio::test]
    async fn unauthorized_reports_a_stale_token() {
        use axum::routing::post;
        let app = axum::Router::new().route(
            "/mcp",
            post(|| async { axum::http::StatusCode::UNAUTHORIZED }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let dir = tempfile::tempdir().unwrap();
        let mut bridge = Bridge {
            http: reqwest::Client::new(),
            paths: Paths::under(dir.path()),
            mcp_url: format!("http://127.0.0.1:{port}/mcp"),
            token: "aka_old".into(),
            label: None,
            session: None,
        };
        assert!(matches!(
            bridge
                .post(r#"{"jsonrpc":"2.0","id":1,"method":"x"}"#)
                .await,
            Ok(Relay::StaleToken)
        ));
    }
}
