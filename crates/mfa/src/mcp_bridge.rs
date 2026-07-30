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
    buffer: Vec<u8>,
    data: Vec<String>,
}

impl SseParser {
    /// Feed a `str` chunk. The wire is bytes — the reader hands us
    /// `push_bytes` — so this exists for tests that spell their chunks as
    /// literals and split them at awkward boundaries.
    #[cfg(test)]
    pub fn push(&mut self, chunk: &str) -> Vec<String> {
        self.push_bytes(chunk.as_bytes())
    }

    pub fn push_bytes(&mut self, chunk: &[u8]) -> Vec<String> {
        self.buffer.extend_from_slice(chunk);
        let mut events = Vec::new();
        while let Some(newline) = self.buffer.iter().position(|byte| *byte == b'\n') {
            let mut line: Vec<u8> = self.buffer.drain(..=newline).collect();
            while matches!(line.last(), Some(b'\n' | b'\r')) {
                line.pop();
            }
            let line = String::from_utf8_lossy(&line);
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
    /// The client's handshake, retained so a sidecar restart or idle session
    /// eviction can be recovered without restarting the stdio MCP process.
    initialize_message: Option<String>,
    initialized_notification: Option<String>,
    /// The revision `initialize` settled on, echoed on the notification leg
    /// so a server that checks the header there accepts the stream.
    protocol_version: Option<String>,
}

/// One request's outcome: the JSON-RPC messages to emit on stdout.
enum Relay {
    Messages(Vec<String>),
    /// The key was rotated or the MCP host moved; the caller refreshes the
    /// named state and retries once.
    StaleToken,
    Unreachable,
    SessionGone,
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
        let status = response.status();
        if status == 202 || status == 204 {
            // An accepted notification produces no reply.
            return Ok(Relay::Messages(Vec::new()));
        }
        let retry_after = response
            .headers()
            .get("retry-after")
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
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
                for event in parser.push_bytes(&chunk) {
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
        if status == reqwest::StatusCode::NOT_FOUND && self.session.is_some() {
            return Ok(Relay::SessionGone);
        }
        if !status.is_success() {
            return Ok(Relay::Messages(vec![correlate_http_error(
                message,
                status.as_u16(),
                retry_after.as_deref(),
                &body,
            )]));
        }
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

    fn remember_handshake(&mut self, message: &str, value: &serde_json::Value) {
        match value.get("method").and_then(serde_json::Value::as_str) {
            Some("initialize") => self.initialize_message = Some(message.to_string()),
            Some("notifications/initialized") => {
                self.initialized_notification = Some(message.to_string())
            }
            _ => {}
        }
    }

    /// Capture the revision `initialize` settled on, so the notification leg
    /// can present the header a conforming server requires on every request
    /// after the handshake.
    fn remember_negotiated_version(&mut self, messages: &[String]) {
        for message in messages {
            let Ok(value) = serde_json::from_str::<serde_json::Value>(message) else {
                continue;
            };
            if let Some(version) = value
                .pointer("/result/protocolVersion")
                .and_then(serde_json::Value::as_str)
            {
                self.protocol_version = Some(version.to_string());
                return;
            }
        }
    }

    async fn recover_session(&mut self, current_method: Option<&str>) -> Result<(), String> {
        let initialize = self
            .initialize_message
            .clone()
            .ok_or_else(|| "the MCP session expired before initialize was observed".to_string())?;
        self.session = None;

        let mut relay = self.post(&initialize).await?;
        if matches!(relay, Relay::StaleToken) {
            self.refresh_token().await?;
            relay = self.post(&initialize).await?;
        }
        match relay {
            Relay::Messages(_) if self.session.is_some() => {}
            Relay::Messages(_) => {
                return Err("the MCP host did not establish a replacement session".into())
            }
            Relay::StaleToken => {
                return Err("the MCP host refused the refreshed key during recovery".into())
            }
            Relay::Unreachable => {
                return Err("the MCP host remained unreachable during recovery".into())
            }
            Relay::SessionGone => {
                return Err("the replacement MCP session expired during recovery".into())
            }
        }

        // If the failed message is itself the initialized notification, its
        // retry below completes the handshake. Otherwise replay the retained
        // notification before retrying the application request.
        if current_method != Some("notifications/initialized") {
            if let Some(initialized) = self.initialized_notification.clone() {
                match self.post(&initialized).await? {
                    Relay::Messages(_) => {}
                    Relay::StaleToken => {
                        return Err(
                            "the MCP host refused the key while restoring the session".into()
                        )
                    }
                    Relay::Unreachable => {
                        return Err("the MCP host went away while restoring the session".into())
                    }
                    Relay::SessionGone => {
                        return Err("the restored MCP session expired immediately".into())
                    }
                }
            }
        }
        Ok(())
    }

    async fn relay_message(&mut self, message: &str, value: &serde_json::Value) -> Vec<String> {
        self.remember_handshake(message, value);
        let method = value.get("method").and_then(serde_json::Value::as_str);
        let mut retried_token = false;
        let mut recovered_session = false;

        loop {
            let relay = match self.post(message).await {
                Ok(relay) => relay,
                Err(error) => return vec![internal_error(message, &error)],
            };
            match relay {
                Relay::Messages(messages) => {
                    self.remember_negotiated_version(&messages);
                    return messages;
                }
                Relay::StaleToken if !retried_token => {
                    retried_token = true;
                    if let Err(error) = self.refresh_token().await {
                        return vec![internal_error(message, &error)];
                    }
                }
                Relay::Unreachable if !recovered_session => {
                    recovered_session = true;
                    if let Err(error) = self.rediscover().await {
                        return vec![internal_error(message, &error)];
                    }
                    self.session = None;
                    if method != Some("initialize") {
                        if let Err(error) = self.recover_session(method).await {
                            return vec![internal_error(message, &error)];
                        }
                    }
                }
                Relay::SessionGone if !recovered_session => {
                    recovered_session = true;
                    if let Err(error) = self.recover_session(method).await {
                        return vec![internal_error(message, &error)];
                    }
                }
                Relay::StaleToken => {
                    return vec![internal_error(
                        message,
                        "the broker refused the shared key even after re-reading it",
                    )]
                }
                Relay::Unreachable => {
                    return vec![internal_error(message, "the MCP host went away")]
                }
                Relay::SessionGone => {
                    return vec![internal_error(
                        message,
                        "the MCP session expired again after recovery",
                    )]
                }
            }
        }
    }
}

fn request_id(message: &str) -> serde_json::Value {
    serde_json::from_str::<serde_json::Value>(message)
        .ok()
        .and_then(|value| value.get("id").cloned())
        .filter(|id| id.is_null() || id.is_string() || id.is_number())
        .unwrap_or(serde_json::Value::Null)
}

fn internal_error(message: &str, detail: &str) -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": request_id(message),
        "error": {
            "code": -32603,
            "message": "AgentMFA MCP transport error",
            "data": { "detail": detail },
        },
    })
    .to_string()
}

fn parse_error(detail: &str) -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": null,
        "error": {
            "code": -32700,
            "message": "Parse error",
            "data": { "detail": detail },
        },
    })
    .to_string()
}

fn correlate_http_error(
    request: &str,
    status: u16,
    retry_after: Option<&str>,
    body: &str,
) -> String {
    let id = request_id(request);
    // Adopt the upstream body only when it is itself a JSON-RPC response —
    // `jsonrpc: "2.0"` with an `error` object or a `result`. A body that
    // merely parses as JSON (a bare string, `null`, an array, or a plain
    // `{"error":"not_found"}` like the host's own root router emits) is not a
    // frame the MCP client can correlate: it would be forwarded verbatim,
    // rejected by the client's schema, and leave the request hanging until its
    // own timeout — the very uncorrelated failure this function exists to fix.
    let adopted = serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .filter(|value| {
            value.get("jsonrpc").and_then(serde_json::Value::as_str) == Some("2.0")
                && (value.get("error").is_some_and(serde_json::Value::is_object)
                    || value.get("result").is_some())
        });
    let mut response = adopted.unwrap_or_else(|| {
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": -32000,
                "message": format!("AgentMFA MCP host returned HTTP {status}"),
                "data": { "detail": body.chars().take(256).collect::<String>() },
            },
        })
    });
    if let Some(object) = response.as_object_mut() {
        if object.get("id").is_none_or(serde_json::Value::is_null) {
            object.insert("id".into(), id);
        }
        if let Some(error) = object
            .get_mut("error")
            .and_then(serde_json::Value::as_object_mut)
        {
            let data = error.entry("data").or_insert_with(|| serde_json::json!({}));
            if let Some(data) = data.as_object_mut() {
                data.entry("http_status")
                    .or_insert_with(|| serde_json::json!(status));
                if let Some(retry_after) = retry_after {
                    data.entry("retry_after")
                        .or_insert_with(|| serde_json::json!(retry_after));
                }
            }
        }
    }
    response.to_string()
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

/// Follow the streamable-HTTP GET leg, forwarding server-initiated messages.
///
/// A POST carries only the answer to the request that made it, so without this
/// leg nothing the *server* starts ever reaches a stdio client — including the
/// `notifications/tools/list_changed` the host sends when the user enables or
/// renames a tool mid-session. The host advertises that as a live capability
/// and it was true for HTTP clients and silently false through this bridge.
///
/// Only `method`-bearing messages are forwarded: responses belong to the POST
/// that asked for them, and relaying one from here would answer a request
/// twice. A server with no GET leg answers 405 and this stops quietly — that
/// is a conforming, common answer, not a failure worth reporting.
async fn follow_notifications(
    http: reqwest::Client,
    mcp_url: String,
    token: String,
    label: Option<String>,
    session: String,
    protocol_version: Option<String>,
    out: tokio::sync::mpsc::UnboundedSender<String>,
) {
    // A dropped stream is reconnected, because an idle event stream being
    // closed by a proxy is ordinary. The backoff keeps a server that refuses
    // the leg outright from becoming a hot loop.
    let mut backoff = Duration::from_millis(500);
    loop {
        let mut request = http
            .get(&mcp_url)
            .header("authorization", format!("Bearer {token}"))
            .header("accept", "text/event-stream")
            .header("mcp-session-id", session.clone());
        if let Some(label) = &label {
            request = request.header("x-agentmfa-client", label.clone());
        }
        if let Some(version) = &protocol_version {
            request = request.header("mcp-protocol-version", version.clone());
        }
        let response = match request.send().await {
            Ok(response) => response,
            // The host is gone or restarting; the POST path reports that
            // properly, so this leg just waits for it to come back.
            Err(_) => {
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(30));
                continue;
            }
        };
        let status = response.status();
        // 405 is "no GET leg here"; 401 means the POST path will re-key and
        // rebuild this stream. Either way there is nothing to follow.
        if status == reqwest::StatusCode::METHOD_NOT_ALLOWED
            || status == reqwest::StatusCode::UNAUTHORIZED
            || status == reqwest::StatusCode::NOT_FOUND
        {
            return;
        }
        let is_stream = response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with("text/event-stream"));
        if !is_stream {
            return;
        }
        backoff = Duration::from_millis(500);
        let mut parser = SseParser::default();
        let mut body = response;
        loop {
            match body.chunk().await {
                Ok(Some(chunk)) => {
                    for event in parser.push_bytes(&chunk) {
                        if !forward_server_message(&out, event) {
                            return;
                        }
                    }
                }
                Ok(None) => break,
                Err(_) => break,
            }
        }
        if let Some(event) = parser.finish() {
            if !forward_server_message(&out, event) {
                return;
            }
        }
        tokio::time::sleep(backoff).await;
    }
}

/// Emit one frame from the notification leg. Returns false when stdout has
/// gone, which is the bridge shutting down.
fn forward_server_message(
    out: &tokio::sync::mpsc::UnboundedSender<String>,
    message: String,
) -> bool {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&message) else {
        return true;
    };
    if value.get("method").and_then(serde_json::Value::as_str).is_none() {
        return true;
    }
    out.send(message).is_ok()
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
        initialize_message: None,
        initialized_notification: None,
        protocol_version: None,
    };

    // Two sources write stdout — request answers and the server's own
    // notifications — so one task owns the handle and both queue through it.
    // Interleaving them any other way would risk splicing two JSON-RPC lines
    // into one.
    let (out, mut outbox) = tokio::sync::mpsc::unbounded_channel::<String>();
    let writer = tokio::spawn(async move {
        let mut stdout = tokio::io::stdout();
        while let Some(message) = outbox.recv().await {
            let Some(line) = one_line(&message) else {
                continue;
            };
            if stdout.write_all(format!("{line}\n").as_bytes()).await.is_err() {
                return;
            }
            if stdout.flush().await.is_err() {
                return;
            }
        }
    });

    // The notification leg is bound to one session; a re-initialize (a sidecar
    // restart, an evicted session) mints a new one and this follows it there.
    let mut notifications: Option<tokio::task::JoinHandle<()>> = None;
    let mut followed_session: Option<String> = None;

    let mut stdin = BufReader::new(tokio::io::stdin());
    let mut input = Vec::new();
    loop {
        input.clear();
        let read = stdin
            .read_until(b'\n', &mut input)
            .await
            .map_err(|error| format!("stdin read failed: {error}"))?;
        if read == 0 {
            break;
        }
        while matches!(input.last(), Some(b'\n' | b'\r')) {
            input.pop();
        }
        let line = match std::str::from_utf8(&input) {
            Ok(line) => line,
            Err(error) => {
                let _ = out.send(parse_error(&format!("stdin was not UTF-8: {error}")));
                continue;
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        let value = match serde_json::from_str::<serde_json::Value>(line) {
            Ok(value) => value,
            Err(error) => {
                let _ = out.send(parse_error(&format!("invalid JSON on stdin: {error}")));
                continue;
            }
        };
        let messages = bridge.relay_message(line, &value).await;
        for message in messages {
            if out.send(message).is_err() {
                return Ok(());
            }
        }
        if bridge.session != followed_session {
            if let Some(task) = notifications.take() {
                task.abort();
            }
            followed_session = bridge.session.clone();
            if let Some(session) = bridge.session.clone() {
                notifications = Some(tokio::spawn(follow_notifications(
                    bridge.http.clone(),
                    bridge.mcp_url.clone(),
                    bridge.token.clone(),
                    bridge.label.clone(),
                    session,
                    bridge.protocol_version.clone(),
                    out.clone(),
                )));
            }
        }
    }
    if let Some(task) = notifications.take() {
        task.abort();
    }
    drop(out);
    let _ = writer.await;
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
    fn sse_parser_preserves_utf8_split_across_transport_chunks() {
        let mut parser = SseParser::default();
        let frame = "data: {\"text\":\"working…\"}\n\n".as_bytes();
        let split = frame
            .windows("…".len())
            .position(|bytes| bytes == "…".as_bytes())
            .unwrap()
            + 1;
        assert!(parser.push_bytes(&frame[..split]).is_empty());
        assert_eq!(
            parser.push_bytes(&frame[split..]),
            vec!["{\"text\":\"working…\"}".to_string()]
        );
    }

    #[test]
    fn one_line_compacts_and_refuses_garbage() {
        assert_eq!(
            one_line("{\n  \"jsonrpc\": \"2.0\"\n}"),
            Some("{\"jsonrpc\":\"2.0\"}".to_string())
        );
        assert_eq!(one_line("not json"), None);
    }

    #[test]
    fn transport_errors_are_correlated_to_the_request() {
        let response: serde_json::Value = serde_json::from_str(&internal_error(
            r#"{"jsonrpc":"2.0","id":"call-7"}"#,
            "boom",
        ))
        .unwrap();
        assert_eq!(response["id"], "call-7");
        assert_eq!(response["error"]["code"], -32603);

        let response: serde_json::Value = serde_json::from_str(&correlate_http_error(
            r#"{"jsonrpc":"2.0","id":9}"#,
            429,
            Some("7"),
            r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32029,"message":"slow down"}}"#,
        ))
        .unwrap();
        assert_eq!(response["id"], 9);
        assert_eq!(response["error"]["data"]["http_status"], 429);
        assert_eq!(response["error"]["data"]["retry_after"], "7");

        // A JSON body that is not a JSON-RPC response (the host's own root
        // router emits `{"error":"not_found"}`) must be replaced with a
        // well-formed frame the client can correlate, not forwarded verbatim.
        let response: serde_json::Value = serde_json::from_str(&correlate_http_error(
            r#"{"jsonrpc":"2.0","id":11,"method":"tools/call"}"#,
            502,
            None,
            r#"{"error":"not_found"}"#,
        ))
        .unwrap();
        assert_eq!(response["jsonrpc"], "2.0");
        assert_eq!(response["id"], 11);
        assert_eq!(response["error"]["code"], -32000);
        assert_eq!(response["error"]["data"]["http_status"], 502);

        // A bare JSON scalar is likewise not adoptable.
        let response: serde_json::Value = serde_json::from_str(&correlate_http_error(
            r#"{"jsonrpc":"2.0","id":12}"#,
            500,
            None,
            r#""Internal Server Error""#,
        ))
        .unwrap();
        assert_eq!(response["id"], 12);
        assert!(response["error"].is_object());
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
                "missing" => (
                    axum::http::StatusCode::TOO_MANY_REQUESTS,
                    [("content-type", "application/json")],
                    r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32029,"message":"slow down"}}"#,
                )
                    .into_response(),
                "failed" => (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    [("content-type", "application/json")],
                    r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"failed"}}"#,
                )
                    .into_response(),
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
            initialize_message: None,
            initialized_notification: None,
            protocol_version: None,
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

        // Non-success HTTP statuses still carry correlated JSON-RPC replies;
        // the bridge must relay their request ids instead of synthesizing an
        // uncorrelated transport error.
        for (id, method, code, status) in
            [(41, "missing", -32029, 429), (42, "failed", -32603, 500)]
        {
            let Relay::Messages(messages) = bridge
                .post(
                    &serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "method": method,
                    })
                    .to_string(),
                )
                .await
                .unwrap()
            else {
                panic!("{method} should relay")
            };
            let value: serde_json::Value = serde_json::from_str(&messages[0]).unwrap();
            assert_eq!(value["id"], id);
            assert_eq!(value["error"]["code"], code);
            assert_eq!(value["error"]["data"]["http_status"], status);
        }
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
            initialize_message: None,
            initialized_notification: None,
            protocol_version: None,
        };
        assert!(matches!(
            bridge
                .post(r#"{"jsonrpc":"2.0","id":1,"method":"x"}"#)
                .await,
            Ok(Relay::StaleToken)
        ));
    }

    #[tokio::test]
    async fn an_expired_session_replays_the_handshake_once() {
        use std::sync::{Arc, Mutex};

        use axum::extract::State;
        use axum::http::HeaderMap;
        use axum::response::IntoResponse;
        use axum::routing::post;

        #[derive(Default)]
        struct ServerState {
            generation: usize,
            initialized: bool,
        }

        async fn handler(
            State(state): State<Arc<Mutex<ServerState>>>,
            headers: HeaderMap,
            body: String,
        ) -> axum::response::Response {
            let message: serde_json::Value = serde_json::from_str(&body).unwrap();
            let method = message["method"].as_str().unwrap();
            let mut state = state.lock().unwrap();
            if method == "initialize" {
                state.generation += 1;
                state.initialized = false;
                return (
                    [("mcp-session-id", format!("session-{}", state.generation))],
                    r#"{"jsonrpc":"2.0","id":1,"result":{}}"#,
                )
                    .into_response();
            }

            let expected = format!("session-{}", state.generation);
            if headers
                .get("mcp-session-id")
                .and_then(|value| value.to_str().ok())
                != Some(expected.as_str())
            {
                return (
                    axum::http::StatusCode::NOT_FOUND,
                    [("content-type", "application/json")],
                    r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32001,"message":"expired"}}"#,
                )
                    .into_response();
            }
            if method == "notifications/initialized" {
                state.initialized = true;
                return axum::http::StatusCode::ACCEPTED.into_response();
            }
            assert!(
                state.initialized,
                "the initialized notification was replayed"
            );
            (
                [("content-type", "application/json")],
                r#"{"jsonrpc":"2.0","id":7,"result":{"recovered":true}}"#,
            )
                .into_response()
        }

        let state = Arc::new(Mutex::new(ServerState::default()));
        let app = axum::Router::new()
            .route("/mcp", post(handler))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let dir = tempfile::tempdir().unwrap();
        let mut bridge = Bridge {
            http: reqwest::Client::new(),
            paths: Paths::under(dir.path()),
            mcp_url: format!("http://127.0.0.1:{port}/mcp"),
            token: "aka_testkey".into(),
            label: None,
            session: None,
            initialize_message: None,
            initialized_notification: None,
            protocol_version: None,
        };
        let initialize = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {},
        });
        let initialized = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
        });
        bridge
            .relay_message(&initialize.to_string(), &initialize)
            .await;
        bridge
            .relay_message(&initialized.to_string(), &initialized)
            .await;

        // Simulate an idle eviction or a sidecar restart on the same port.
        bridge.session = Some("stale-session".into());
        let call = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/list",
            "params": {},
        });
        let messages = bridge.relay_message(&call.to_string(), &call).await;
        let response: serde_json::Value = serde_json::from_str(&messages[0]).unwrap();
        assert_eq!(response["id"], 7);
        assert_eq!(response["result"]["recovered"], true);
        assert_eq!(state.lock().unwrap().generation, 2);
        assert_eq!(bridge.session.as_deref(), Some("session-2"));
    }

    /// M2. The host announces tool-list changes on the streamable-HTTP GET
    /// leg. A POST-only bridge never opened it, so a stdio client's tool list
    /// silently went stale while the app said it was live.
    #[tokio::test]
    async fn the_notification_leg_relays_server_initiated_messages() {
        use axum::response::IntoResponse;
        use axum::routing::get;

        async fn stream() -> axum::response::Response {
            (
                [("content-type", "text/event-stream")],
                // A response frame shares the leg with notifications; relaying
                // it would answer a POST's request a second time.
                concat!(
                    "data: {\"jsonrpc\":\"2.0\",\"id\":9,\"result\":{}}\n\n",
                    "data: {\"jsonrpc\":\"2.0\",",
                    "\"method\":\"notifications/tools/list_changed\"}\n\n",
                ),
            )
                .into_response()
        }

        let app = axum::Router::new().route("/mcp", get(stream));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let (out, mut inbox) = tokio::sync::mpsc::unbounded_channel();
        let task = tokio::spawn(follow_notifications(
            reqwest::Client::new(),
            format!("http://127.0.0.1:{port}/mcp"),
            "aka_testkey".into(),
            None,
            "sess-1".into(),
            Some("2025-06-18".into()),
            out,
        ));

        let relayed = tokio::time::timeout(Duration::from_secs(5), inbox.recv())
            .await
            .expect("a notification within the deadline")
            .expect("the leg forwarded a message");
        let value: serde_json::Value = serde_json::from_str(&relayed).unwrap();
        assert_eq!(value["method"], "notifications/tools/list_changed");
        task.abort();
    }

    /// A server with no GET leg answers 405. That is conforming, so the bridge
    /// stops following rather than retrying forever or reporting a failure.
    #[tokio::test]
    async fn a_server_without_a_notification_leg_is_not_retried() {
        use axum::routing::get;

        let app = axum::Router::new().route(
            "/mcp",
            get(|| async { axum::http::StatusCode::METHOD_NOT_ALLOWED }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let (out, mut inbox) = tokio::sync::mpsc::unbounded_channel::<String>();
        tokio::time::timeout(
            Duration::from_secs(5),
            follow_notifications(
                reqwest::Client::new(),
                format!("http://127.0.0.1:{port}/mcp"),
                "aka_testkey".into(),
                None,
                "sess-1".into(),
                None,
                out,
            ),
        )
        .await
        .expect("the follower returns rather than retrying");
        assert!(inbox.recv().await.is_none(), "nothing was forwarded");
    }
}
