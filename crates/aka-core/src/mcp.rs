//! Broker-side MCP client for UI-initiated checks.
//!
//! The sidecar owns the *agent-facing* MCP surface; this module is the
//! broker's own, much smaller client, used for two trusted-UI jobs:
//!
//! - the **status check** on an MCP connection ("is the server reachable,
//!   which account am I, what tools and resources does it offer"), and
//! - the **post-authentication verification** at the end of the OAuth flow.
//!
//! It speaks streamable HTTP only (JSON or SSE responses to POSTed
//! JSON-RPC), always against the connection's pinned origin, with the
//! credential rendered exactly the way the agent plane renders it — the
//! secret rides the upstream leg and only a summary comes back.

use std::time::Duration;

use http::{HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use url::Url;
use zeroize::Zeroizing;

use crate::capability::http::{render_injection, RenderedInjection};
use crate::store::Store;
use crate::types::{Connection, ConnectionConfig};

/// Protocol revision this client requests; servers may negotiate down.
pub const PROTOCOL_VERSION: &str = "2025-06-18";

const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const RESPONSE_CAP: usize = 4 * 1024 * 1024;
const MAX_TOOL_PAGES: usize = 5;
const MAX_RESOURCE_PAGES: usize = 3;
const MAX_LISTED_RESOURCES: usize = 100;

/// One resource the server advertises, trimmed to display metadata.
#[derive(Debug, Clone, Serialize)]
pub struct McpResourceInfo {
    pub uri: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// What the UI's status button renders. Never credential material.
#[derive(Debug, Clone, Serialize)]
pub struct McpStatusReport {
    pub ok: bool,
    /// One-line human summary (success or the failure reason).
    pub detail: String,
    /// The upstream answered but refused the credential (401/403) — the
    /// signal for the broker's silent-refresh rescue, and for the UI's
    /// Reconnect affordance when no refresh is possible.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub credential_rejected: bool,
    /// `serverInfo.name (version)` from initialize.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol_version: Option<String>,
    /// The upstream account acknowledged by the whoami tool, when one was
    /// configured and answered.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    pub tools: Vec<String>,
    /// Template-expected tools the server did not advertise.
    pub missing_tools: Vec<String>,
    /// Whether the server advertises the resources capability at all.
    pub resources_supported: bool,
    pub resources: Vec<McpResourceInfo>,
}

/// The marker `post` puts in a 401/403 failure; `failed` keys the
/// `credential_rejected` flag off it so both stay in one module.
const CREDENTIAL_REJECTED_MARKER: &str = "rejected the credential";

impl McpStatusReport {
    fn failed(detail: impl Into<String>) -> Self {
        let detail = detail.into();
        Self {
            ok: false,
            credential_rejected: detail.contains(CREDENTIAL_REJECTED_MARKER),
            detail,
            server: None,
            protocol_version: None,
            account: None,
            tools: Vec::new(),
            missing_tools: Vec::new(),
            resources_supported: false,
            resources: Vec::new(),
        }
    }

    /// The whole check ran out of time (the caller's outer timeout).
    pub fn timed_out(after: Duration) -> Self {
        Self::failed(format!("no answer within {} seconds", after.as_secs()))
    }
}

/// Template-supplied expectations for a status check. Both optional: a
/// generic MCP server checks reachability and lists what it finds.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct McpCheckOptions {
    /// Tool that identifies the connected account (e.g. GitHub's `get_me`).
    pub whoami_tool: Option<String>,
    /// Tools the catalog template expects this server to advertise.
    #[serde(default)]
    pub expected_tools: Vec<String>,
}

/// The credential attached to every upstream request.
enum Credential {
    Header(HeaderName, HeaderValue),
    Query(Zeroizing<String>),
}

impl Credential {
    fn from_rendered(rendered: RenderedInjection) -> Self {
        match rendered {
            RenderedInjection::Header(name, value) => Credential::Header(name, value),
            RenderedInjection::Query(fragment) => Credential::Query(fragment),
        }
    }

    /// A bare bearer token (the OAuth flow's just-issued access token).
    pub(crate) fn bearer(token: &str) -> Result<Self, String> {
        let mut value = HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|_| "access token contains invalid header bytes".to_string())?;
        value.set_sensitive(true);
        Ok(Credential::Header(http::header::AUTHORIZATION, value))
    }
}

/// Minimal streamable-HTTP MCP session: POSTed JSON-RPC, JSON or SSE
/// responses, `Mcp-Session-Id` tracked across calls.
struct McpSession {
    client: reqwest::Client,
    endpoint: Url,
    credential: Credential,
    session_id: Option<String>,
    protocol_sent: bool,
    next_id: u64,
}

impl McpSession {
    fn new(client: reqwest::Client, endpoint: Url, credential: Credential) -> Self {
        Self {
            client,
            endpoint,
            credential,
            session_id: None,
            protocol_sent: false,
            next_id: 1,
        }
    }

    async fn notify(&mut self, method: &str) -> Result<(), String> {
        self.post(json!({ "jsonrpc": "2.0", "method": method }), None)
            .await
            .map(|_| ())
    }

    async fn request(&mut self, method: &str, params: Value) -> Result<Value, String> {
        let id = self.next_id;
        self.next_id += 1;
        let body = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
        let response = self.post(body, Some(id)).await?;
        let response = response.ok_or_else(|| format!("{method}: empty response"))?;
        if let Some(error) = response.get("error") {
            let message = error
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("unknown error");
            let code = error.get("code").and_then(Value::as_i64).unwrap_or(0);
            return Err(format!("{method} failed: {message} (code {code})"));
        }
        Ok(response.get("result").cloned().unwrap_or(Value::Null))
    }

    /// POST one JSON-RPC message; when `expect_id` is set, return the
    /// response object with that id (scanning SSE frames when the server
    /// streams).
    async fn post(&mut self, body: Value, expect_id: Option<u64>) -> Result<Option<Value>, String> {
        let mut url = self.endpoint.clone();
        if let Credential::Query(fragment) = &self.credential {
            let combined = match url.query() {
                Some(existing) if !existing.is_empty() => format!("{existing}&{}", &**fragment),
                _ => fragment.to_string(),
            };
            url.set_query(Some(&combined));
        }
        let mut request = self
            .client
            .post(url)
            .timeout(REQUEST_TIMEOUT)
            .header(http::header::CONTENT_TYPE, "application/json")
            .header(http::header::ACCEPT, "application/json, text/event-stream")
            .json(&body);
        if let Credential::Header(name, value) = &self.credential {
            request = request.header(name.clone(), value.clone());
        }
        if let Some(session) = &self.session_id {
            request = request.header("Mcp-Session-Id", session.clone());
        }
        if self.protocol_sent {
            request = request.header("MCP-Protocol-Version", PROTOCOL_VERSION);
        }
        let response = request
            .send()
            .await
            .map_err(|e| e.without_url().to_string())?;
        if let Some(session) = response
            .headers()
            .get("mcp-session-id")
            .and_then(|v| v.to_str().ok())
        {
            self.session_id = Some(session.to_string());
        }
        let status = response.status();
        if status.as_u16() == 401 || status.as_u16() == 403 {
            return Err(format!(
                "the server answered but {CREDENTIAL_REJECTED_MARKER} (HTTP {status})"
            ));
        }
        if status.as_u16() == 202 || status.as_u16() == 204 {
            return Ok(None);
        }
        if !status.is_success() {
            return Err(format!("the server answered HTTP {status}"));
        }
        let is_sse = response
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.starts_with("text/event-stream"));
        let expect_id = match expect_id {
            Some(id) => id,
            None => return Ok(None),
        };

        let mut body = Vec::new();
        let mut stream = response;
        loop {
            match stream.chunk().await {
                Ok(Some(chunk)) => {
                    if body.len() + chunk.len() > RESPONSE_CAP {
                        return Err("response exceeded the size cap".into());
                    }
                    body.extend_from_slice(&chunk);
                    // Streams can stay open after the response we need; stop
                    // as soon as a completed SSE frame answers our id.
                    if is_sse {
                        if let Some(found) = find_sse_response(&body, expect_id) {
                            return Ok(Some(found));
                        }
                    }
                }
                Ok(None) => break,
                Err(e) => return Err(e.without_url().to_string()),
            }
        }
        if is_sse {
            return find_sse_response(&body, expect_id)
                .map(Some)
                .ok_or_else(|| "the SSE stream ended without a response".to_string());
        }
        let parsed: Value = serde_json::from_slice(&body)
            .map_err(|e| format!("the server returned invalid JSON: {e}"))?;
        Ok(Some(parsed))
    }
}

/// Scan (possibly partial) SSE bytes for a complete `data:` frame carrying
/// the JSON-RPC response with the given id.
fn find_sse_response(bytes: &[u8], expect_id: u64) -> Option<Value> {
    let text = String::from_utf8_lossy(bytes);
    for frame in text.replace("\r\n", "\n").split("\n\n") {
        let data: String = frame
            .lines()
            .filter_map(|line| line.strip_prefix("data:"))
            .map(|line| line.strip_prefix(' ').unwrap_or(line))
            .collect::<Vec<_>>()
            .join("\n");
        if data.is_empty() {
            continue;
        }
        if let Ok(value) = serde_json::from_str::<Value>(&data) {
            if value.get("id").and_then(Value::as_u64) == Some(expect_id) {
                return Some(value);
            }
        }
    }
    None
}

/// The MCP endpoint of an API connection, or why it has none.
pub fn mcp_endpoint(connection: &Connection) -> Result<Url, String> {
    let ConnectionConfig::Api {
        host,
        scheme,
        port,
        mcp_path,
        ..
    } = &connection.config
    else {
        return Err("not an API connection".into());
    };
    let Some(path) = mcp_path else {
        return Err("this connection has no MCP path".into());
    };
    let mut base =
        Url::parse(&format!("{scheme}://{host}")).map_err(|e| format!("bad origin: {e}"))?;
    if base.set_port(*port).is_err() {
        return Err("cannot set port".into());
    }
    base.join(path).map_err(|e| format!("bad MCP path: {e}"))
}

/// UI-initiated status check against a stored connection: renders the
/// credential from the connection's template (the same late-fetch path the
/// agent plane uses) and drives the handshake.
pub async fn check_connection(
    store: &Store,
    client: &reqwest::Client,
    connection: &Connection,
    options: &McpCheckOptions,
) -> McpStatusReport {
    let endpoint = match mcp_endpoint(connection) {
        Ok(endpoint) => endpoint,
        Err(detail) => return McpStatusReport::failed(detail),
    };
    let ConnectionConfig::Api { template, .. } = &connection.config else {
        return McpStatusReport::failed("not an API connection");
    };
    let credential = match render_injection(store, template).await {
        Ok(rendered) => Credential::from_rendered(rendered),
        Err(detail) => {
            return McpStatusReport::failed(format!("could not render credential: {detail}"))
        }
    };
    check_endpoint(client.clone(), endpoint, credential, options).await
}

/// One upstream tool, as the per-wiring tool picker lists it.
#[derive(Debug, Clone, Serialize)]
pub struct McpToolInfo {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Ask an MCP connection's upstream for its tool list (names +
/// descriptions), for the per-wiring tool picker. Same handshake and
/// credential path as the status check, minus whoami and resources.
pub async fn list_tools(
    store: &Store,
    client: &reqwest::Client,
    connection: &Connection,
) -> Result<Vec<McpToolInfo>, String> {
    let endpoint = mcp_endpoint(connection)?;
    let ConnectionConfig::Api { template, .. } = &connection.config else {
        return Err("not an API connection".into());
    };
    let rendered = render_injection(store, template)
        .await
        .map_err(|detail| format!("could not render credential: {detail}"))?;
    let mut session = McpSession::new(
        client.clone(),
        endpoint,
        Credential::from_rendered(rendered),
    );
    session
        .request(
            "initialize",
            json!({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": { "name": "aka-multitool", "version": env!("CARGO_PKG_VERSION") },
            }),
        )
        .await?;
    session.protocol_sent = true;
    let _ = session.notify("notifications/initialized").await;

    let mut tools: Vec<McpToolInfo> = Vec::new();
    let mut cursor: Option<String> = None;
    for _ in 0..MAX_TOOL_PAGES {
        let params = match &cursor {
            Some(cursor) => json!({ "cursor": cursor }),
            None => json!({}),
        };
        let page = session.request("tools/list", params).await?;
        if let Some(list) = page.get("tools").and_then(Value::as_array) {
            for tool in list {
                let Some(name) = tool.get("name").and_then(Value::as_str) else {
                    continue;
                };
                tools.push(McpToolInfo {
                    name: name.to_string(),
                    description: tool
                        .get("description")
                        .and_then(Value::as_str)
                        .map(str::to_string),
                });
            }
        }
        cursor = page
            .get("nextCursor")
            .and_then(Value::as_str)
            .map(str::to_string);
        if cursor.is_none() {
            break;
        }
    }
    Ok(tools)
}

/// Post-OAuth verification: same handshake, with the just-issued bearer
/// token supplied directly (it is not in the vault yet, or was just
/// replaced, and reading it back could demand a native re-auth prompt).
pub(crate) async fn check_with_bearer(
    client: reqwest::Client,
    endpoint: Url,
    token: &str,
    options: &McpCheckOptions,
) -> McpStatusReport {
    let credential = match Credential::bearer(token) {
        Ok(credential) => credential,
        Err(detail) => return McpStatusReport::failed(detail),
    };
    check_endpoint(client, endpoint, credential, options).await
}

async fn check_endpoint(
    client: reqwest::Client,
    endpoint: Url,
    credential: Credential,
    options: &McpCheckOptions,
) -> McpStatusReport {
    let mut session = McpSession::new(client, endpoint, credential);

    let init = match session
        .request(
            "initialize",
            json!({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": { "name": "aka-multitool", "version": env!("CARGO_PKG_VERSION") },
            }),
        )
        .await
    {
        Ok(result) => result,
        Err(detail) => return McpStatusReport::failed(detail),
    };
    session.protocol_sent = true;
    let protocol_version = init
        .get("protocolVersion")
        .and_then(Value::as_str)
        .map(str::to_string);
    let server = init.get("serverInfo").map(|info| {
        let name = info.get("name").and_then(Value::as_str).unwrap_or("server");
        match info.get("version").and_then(Value::as_str) {
            Some(version) => format!("{name} {version}"),
            None => name.to_string(),
        }
    });
    let resources_supported = init
        .get("capabilities")
        .and_then(|caps| caps.get("resources"))
        .is_some();
    // Spec requires the client to acknowledge before other requests; a
    // server that dislikes the notification still answered initialize, so
    // don't fail the whole check over it.
    let _ = session.notify("notifications/initialized").await;

    let mut tools: Vec<String> = Vec::new();
    let mut cursor: Option<String> = None;
    for _ in 0..MAX_TOOL_PAGES {
        let params = match &cursor {
            Some(cursor) => json!({ "cursor": cursor }),
            None => json!({}),
        };
        let page = match session.request("tools/list", params).await {
            Ok(result) => result,
            Err(detail) => return McpStatusReport::failed(detail),
        };
        if let Some(list) = page.get("tools").and_then(Value::as_array) {
            tools.extend(
                list.iter()
                    .filter_map(|tool| tool.get("name").and_then(Value::as_str))
                    .map(str::to_string),
            );
        }
        cursor = page
            .get("nextCursor")
            .and_then(Value::as_str)
            .map(str::to_string);
        if cursor.is_none() {
            break;
        }
    }
    let missing_tools: Vec<String> = options
        .expected_tools
        .iter()
        .filter(|expected| !tools.iter().any(|tool| tool == *expected))
        .cloned()
        .collect();

    let mut account = None;
    if let Some(whoami) = &options.whoami_tool {
        if tools.iter().any(|tool| tool == whoami) {
            match session
                .request("tools/call", json!({ "name": whoami, "arguments": {} }))
                .await
            {
                Ok(result) => account = extract_account(&result),
                Err(_) => { /* reachability already proven; whoami is best-effort */ }
            }
        }
    }

    let mut resources = Vec::new();
    if resources_supported {
        let mut cursor: Option<String> = None;
        'pages: for _ in 0..MAX_RESOURCE_PAGES {
            let params = match &cursor {
                Some(cursor) => json!({ "cursor": cursor }),
                None => json!({}),
            };
            // Tolerate servers that advertise the capability but refuse the
            // list call; the rest of the report stands.
            let Ok(page) = session.request("resources/list", params).await else {
                break;
            };
            if let Some(list) = page.get("resources").and_then(Value::as_array) {
                for resource in list {
                    let Some(uri) = resource.get("uri").and_then(Value::as_str) else {
                        continue;
                    };
                    resources.push(McpResourceInfo {
                        uri: uri.to_string(),
                        name: resource
                            .get("name")
                            .and_then(Value::as_str)
                            .unwrap_or(uri)
                            .to_string(),
                        description: resource
                            .get("description")
                            .and_then(Value::as_str)
                            .map(str::to_string),
                    });
                    if resources.len() >= MAX_LISTED_RESOURCES {
                        break 'pages;
                    }
                }
            }
            cursor = page
                .get("nextCursor")
                .and_then(Value::as_str)
                .map(str::to_string);
            if cursor.is_none() {
                break;
            }
        }
    }

    let mut summary = vec![format!(
        "{} answered",
        server.clone().unwrap_or_else(|| "The server".into())
    )];
    if let Some(account) = &account {
        summary.push(format!("as {account}"));
    }
    summary.push(format!(
        "with {} tool{}",
        tools.len(),
        if tools.len() == 1 { "" } else { "s" }
    ));
    if resources_supported {
        summary.push(format!(
            "and {} resource{}",
            resources.len(),
            if resources.len() == 1 { "" } else { "s" }
        ));
    }
    let mut detail = summary.join(" ");
    if !missing_tools.is_empty() {
        detail.push_str(&format!("; missing expected: {}", missing_tools.join(", ")));
    }

    McpStatusReport {
        ok: true,
        credential_rejected: false,
        detail,
        server,
        protocol_version,
        account,
        tools,
        missing_tools,
        resources_supported,
        resources,
    }
}

/// Pull a human account label out of a whoami tool result: prefer
/// structured content, then a JSON text payload, then a text snippet.
fn extract_account(result: &Value) -> Option<String> {
    if let Some(structured) = result.get("structuredContent") {
        if let Some(account) = account_from_json(structured) {
            return Some(account);
        }
    }
    let text = result
        .get("content")
        .and_then(Value::as_array)
        .and_then(|content| {
            content.iter().find_map(|item| {
                (item.get("type").and_then(Value::as_str) == Some("text"))
                    .then(|| item.get("text").and_then(Value::as_str))
                    .flatten()
            })
        })?;
    if let Ok(parsed) = serde_json::from_str::<Value>(text) {
        if let Some(account) = account_from_json(&parsed) {
            return Some(account);
        }
    }
    let snippet: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if snippet.is_empty() {
        return None;
    }
    Some(if snippet.chars().count() > 120 {
        let mut cut: String = snippet.chars().take(119).collect();
        cut.push('…');
        cut
    } else {
        snippet
    })
}

/// Depth-limited search for identity-ish string fields.
fn account_from_json(value: &Value) -> Option<String> {
    fn find(value: &Value, key: &str, depth: usize) -> Option<String> {
        if depth == 0 {
            return None;
        }
        match value {
            Value::Object(map) => {
                if let Some(found) = map.get(key).and_then(Value::as_str) {
                    if !found.is_empty() {
                        return Some(found.to_string());
                    }
                }
                map.values().find_map(|v| find(v, key, depth - 1))
            }
            Value::Array(items) => items.iter().find_map(|v| find(v, key, depth - 1)),
            _ => None,
        }
    }
    let login = find(value, "login", 4).or_else(|| find(value, "username", 4));
    let name = find(value, "name", 4);
    let email = find(value, "email", 4);
    match (login, name, email) {
        (Some(login), Some(name), _) if login != name => Some(format!("{name} (@{login})")),
        (Some(login), _, _) => Some(login),
        (None, Some(name), Some(email)) => Some(format!("{name} ({email})")),
        (None, Some(name), None) => Some(name),
        (None, None, Some(email)) => Some(email),
        (None, None, None) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sse_frames_are_scanned_for_the_matching_id() {
        let bytes =
            b"event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"ok\":true}}\n\n";
        let found = find_sse_response(bytes, 7).unwrap();
        assert_eq!(found["result"]["ok"], json!(true));
        assert!(find_sse_response(bytes, 8).is_none());
        // Partial frame (no terminating blank line yet): not returned.
        let partial = b"data: {\"jsonrpc\":\"2.0\",\"id\":7";
        assert!(find_sse_response(partial, 7).is_none());
    }

    #[test]
    fn accounts_are_extracted_from_common_shapes() {
        // GitHub get_me: text content carrying JSON.
        let github = json!({
            "content": [{ "type": "text",
                "text": "{\"login\":\"octocat\",\"name\":\"Octo Cat\",\"email\":null}" }]
        });
        assert_eq!(extract_account(&github).unwrap(), "Octo Cat (@octocat)");

        // Structured content wins over text.
        let structured = json!({
            "structuredContent": { "user": { "login": "raymond" } },
            "content": [{ "type": "text", "text": "irrelevant" }]
        });
        assert_eq!(extract_account(&structured).unwrap(), "raymond");

        // Name+email without a login.
        let notion = json!({
            "content": [{ "type": "text",
                "text": "{\"object\":\"user\",\"name\":\"Raymond\",\"person\":{\"email\":\"raymond@aka.com\"}}" }]
        });
        assert_eq!(
            extract_account(&notion).unwrap(),
            "Raymond (raymond@aka.com)"
        );

        // Plain prose falls back to a snippet.
        let prose = json!({
            "content": [{ "type": "text", "text": "You are signed\nin as demo." }]
        });
        assert_eq!(
            extract_account(&prose).unwrap(),
            "You are signed in as demo."
        );
    }

    #[test]
    fn endpoint_requires_an_mcp_path() {
        let conn = Connection {
            id: uuid::Uuid::new_v4(),
            name: "github".into(),
            config: ConnectionConfig::Api {
                host: "api.githubcopilot.com".into(),
                scheme: "https".into(),
                port: None,
                template: "Authorization: Bearer {{T}}".into(),
                mcp_path: Some("/mcp".into()),
            },
            secrets: vec![],
            account: None,
            oauth: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        assert_eq!(
            mcp_endpoint(&conn).unwrap().as_str(),
            "https://api.githubcopilot.com/mcp"
        );
        let mut no_path = conn.clone();
        if let ConnectionConfig::Api { mcp_path, .. } = &mut no_path.config {
            *mcp_path = None;
        }
        assert!(mcp_endpoint(&no_path).is_err());
    }
}
