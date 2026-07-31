//! Broker-side MCP client for UI-initiated checks.
//!
//! [`crate::mcp_host`] owns the *agent-facing* MCP surface; this module is the
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

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use http::{HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use url::Url;
use zeroize::Zeroizing;

use crate::capability::http::{render_connection_injection, RenderedInjection};
use crate::store::Store;
use crate::types::{Connection, ConnectionConfig};

/// Protocol revisions this client can actually speak, newest first.
///
/// `initialize` offers the newest and the server answers with the revision it
/// chose; both are accepted here because nothing this client does differs
/// between them — it POSTs JSON-RPC, reads tools and resources, and tears the
/// session down. Refusing the older one meant a server that negotiated
/// perfectly correctly was reported as unusable.
pub const PROTOCOL_VERSION: &str = "2025-06-18";
pub const PROTOCOL_VERSION_2025_03_26: &str = "2025-03-26";
pub const SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &[PROTOCOL_VERSION, PROTOCOL_VERSION_2025_03_26];

const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const RESPONSE_CAP: usize = 4 * 1024 * 1024;
// Keep these catalog bounds aligned with the agent-facing MCP host. The two
// clients cannot share a compiled constant across Rust/TypeScript, so tests
// assert the behavior at both boundaries.
const MAX_TOOL_PAGES: usize = 32;
const MAX_RESOURCE_PAGES: usize = 16;
const MAX_CATALOG_ITEMS: usize = 2_000;

/// One resource the server advertises, trimmed to display metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpResourceInfo {
    pub uri: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// What the UI's status button renders. Never credential material.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    /// Whether the server advertises the resources capability at all.
    pub resources_supported: bool,
    pub resources: Vec<McpResourceInfo>,
    /// The upstream advertised another catalog page (or more items) after
    /// the bounded status check stopped.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub truncated: bool,
    /// Internal audit handoff: set only when the guarded status tool was
    /// actually invoked, never serialized to a management caller.
    #[serde(skip)]
    pub(crate) status_tool_invoked: Option<String>,
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
            resources_supported: false,
            resources: Vec::new(),
            truncated: false,
            status_tool_invoked: None,
        }
    }

    /// The whole check ran out of time (the caller's outer timeout).
    pub fn timed_out(after: Duration) -> Self {
        Self::failed(format!("no answer within {} seconds", after.as_secs()))
    }
}

/// Template-supplied expectations for a status check. Both optional: a
/// generic MCP server checks reachability and lists what it finds.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct McpCheckOptions {
    /// Tool that identifies the connected account (e.g. GitHub's `get_me`).
    pub whoami_tool: Option<String>,
}

/// Account-status tools shipped by the product catalog. The webview may ask
/// for one of these names, but cannot turn the status button into an
/// arbitrary tool-call primitive. The upstream must independently annotate
/// the selected tool read-only before it is invoked.
fn catalog_status_tool(candidate: Option<&str>) -> Option<String> {
    const TOOLS: &[&str] = &[
        "get_me",
        "notion-get-self",
        "whoami",
        "get_stripe_account_info",
    ];
    candidate
        .filter(|candidate| TOOLS.contains(candidate))
        .map(str::to_string)
}

/// The credential attached to every upstream request. `None` is a
/// credential-less connection (a public MCP server): nothing is injected.
enum Credential {
    None,
    Header(HeaderName, HeaderValue),
    Query(Zeroizing<String>),
}

impl Credential {
    fn from_rendered(rendered: RenderedInjection) -> Result<Self, String> {
        match rendered {
            RenderedInjection::None => Ok(Credential::None),
            RenderedInjection::Header(name, value) => Ok(Credential::Header(name, value)),
            RenderedInjection::Query(fragment) => Ok(Credential::Query(fragment)),
            // The store refuses signer+mcp_path, so this cannot be reached
            // through configuration; fail closed rather than ever letting an
            // MCP session proceed unsigned.
            RenderedInjection::Sigv4(_) => {
                Err("SigV4-signed connections do not speak MCP".to_string())
            }
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
    protocol_version: String,
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
            protocol_version: PROTOCOL_VERSION.to_string(),
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
            request = request.header("MCP-Protocol-Version", &self.protocol_version);
        }
        // SEP-2243: mirror the JSON-RPC method (and, for a named call, the
        // tool/prompt name) into headers so a load balancer can route
        // without reading the body, and a server that rejects headers
        // disagreeing with the body sees them agree.
        if let Some(method) = body.get("method").and_then(Value::as_str) {
            request = request.header("Mcp-Method", method);
            if let Some(name) = body
                .get("params")
                .and_then(|params| params.get("name"))
                .and_then(Value::as_str)
            {
                // A name that is not header-safe is dropped, not fatal: the
                // header is a routing hint and the body stays authoritative.
                if let Ok(value) = HeaderValue::from_str(name) {
                    request = request.header("Mcp-Name", value);
                }
            }
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

    fn adopt_protocol_version(&mut self, initialize: &Value) -> Result<String, String> {
        let version = initialize
            .get("protocolVersion")
            .and_then(Value::as_str)
            .ok_or_else(|| "initialize returned no protocolVersion".to_string())?;
        if !SUPPORTED_PROTOCOL_VERSIONS.contains(&version) {
            return Err(format!(
                "the server negotiated unsupported protocol version {version}; supported: {}",
                SUPPORTED_PROTOCOL_VERSIONS.join(", ")
            ));
        }
        self.protocol_version = version.to_string();
        self.protocol_sent = true;
        Ok(version.to_string())
    }

    /// Best-effort teardown for a stateful streamable-HTTP session.
    async fn close(&mut self) {
        let Some(session_id) = self.session_id.take() else {
            return;
        };
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
            .delete(url)
            .timeout(REQUEST_TIMEOUT)
            .header(http::header::ACCEPT, "application/json, text/event-stream")
            .header("Mcp-Session-Id", session_id);
        if let Credential::Header(name, value) = &self.credential {
            request = request.header(name.clone(), value.clone());
        }
        if self.protocol_sent {
            request = request.header("MCP-Protocol-Version", &self.protocol_version);
        }
        let _ = request.send().await;
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
    store: &Arc<Store>,
    client: &reqwest::Client,
    connection: &Connection,
    options: &McpCheckOptions,
) -> McpStatusReport {
    let endpoint = match mcp_endpoint(connection) {
        Ok(endpoint) => endpoint,
        Err(detail) => return McpStatusReport::failed(detail),
    };
    let credential = match render_connection_injection(store, client, connection).await {
        Ok(rendered) => match Credential::from_rendered(rendered) {
            Ok(credential) => credential,
            Err(detail) => return McpStatusReport::failed(detail),
        },
        Err(failure) => {
            let detail = failure.to_string();
            return McpStatusReport::failed(format!("could not render credential: {detail}"));
        }
    };
    let client = match crate::capability::http::client_for_connection(client, connection) {
        Ok(client) => client,
        Err(detail) => return McpStatusReport::failed(detail),
    };
    check_endpoint(client, endpoint, credential, options).await
}

/// One upstream tool, as the per-wiring tool picker lists it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpToolInfo {
    /// Exact upstream identifier, sent back when the user curates access.
    pub name: String,
    /// Display-safe form when the exact identifier contains invisible text or
    /// is too long. The raw name remains the policy key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// One bounded upstream tool listing before cache metadata is attached.
#[derive(Debug, Clone)]
pub struct McpToolListing {
    pub tools: Vec<McpToolInfo>,
    pub truncated: bool,
}

/// Tool-picker response. Cache provenance belongs to the catalog rather
/// than each tool so an empty cached listing can still be identified.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpToolCatalog {
    pub tools: Vec<McpToolInfo>,
    pub truncated: bool,
    pub stale: bool,
    pub fetched_at: DateTime<Utc>,
    pub cache_age_seconds: u64,
}

fn tool_info(value: &Value) -> Option<McpToolInfo> {
    let name = value.get("name").and_then(Value::as_str)?;
    let safe_name = crate::untrusted_text::cap(name, 200);
    Some(McpToolInfo {
        name: name.to_string(),
        display_name: (safe_name != name).then_some(safe_name),
        description: value
            .get("description")
            .and_then(Value::as_str)
            .map(|description| crate::untrusted_text::cap(description, 400)),
    })
}

/// Ask an MCP connection's upstream for its tool list (names +
/// descriptions), for the per-wiring tool picker. Same handshake and
/// credential path as the status check, minus whoami and resources.
pub async fn list_tools(
    store: &Arc<Store>,
    client: &reqwest::Client,
    connection: &Connection,
) -> Result<McpToolListing, String> {
    let endpoint = mcp_endpoint(connection)?;
    let rendered = render_connection_injection(store, client, connection)
        .await
        .map_err(|failure| format!("could not render credential: {failure}"))?;
    let client = crate::capability::http::client_for_connection(client, connection)?;
    let mut session = McpSession::new(client, endpoint, Credential::from_rendered(rendered)?);
    let result = async {
        let initialize = session
            .request(
                "initialize",
                json!({
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": { "name": "aka-agentmfa", "version": env!("CARGO_PKG_VERSION") },
                }),
            )
            .await?;
        session.adopt_protocol_version(&initialize)?;
        let _ = session.notify("notifications/initialized").await;

        let mut tools: Vec<McpToolInfo> = Vec::new();
        let mut cursor: Option<String> = None;
        let mut truncated = false;
        for _ in 0..MAX_TOOL_PAGES {
            let params = match &cursor {
                Some(cursor) => json!({ "cursor": cursor }),
                None => json!({}),
            };
            let page = session.request("tools/list", params).await?;
            if let Some(list) = page.get("tools").and_then(Value::as_array) {
                for tool in list {
                    if let Some(info) = tool_info(tool) {
                        if tools.len() >= MAX_CATALOG_ITEMS {
                            truncated = true;
                            break;
                        }
                        tools.push(info);
                    }
                }
            }
            cursor = page
                .get("nextCursor")
                .and_then(Value::as_str)
                .map(str::to_string);
            if cursor.is_none() || tools.len() >= MAX_CATALOG_ITEMS {
                break;
            }
        }
        if cursor.is_some() {
            truncated = true;
        }
        Ok(McpToolListing { truncated, tools })
    }
    .await;
    session.close().await;
    result
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
    let guarded_options = McpCheckOptions {
        whoami_tool: catalog_status_tool(options.whoami_tool.as_deref()),
    };
    let report = check_session(&mut session, &guarded_options).await;
    session.close().await;
    report
}

async fn check_session(session: &mut McpSession, options: &McpCheckOptions) -> McpStatusReport {
    let init = match session
        .request(
            "initialize",
            json!({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": { "name": "aka-agentmfa", "version": env!("CARGO_PKG_VERSION") },
            }),
        )
        .await
    {
        Ok(result) => result,
        Err(detail) => return McpStatusReport::failed(detail),
    };
    let protocol_version = match session.adopt_protocol_version(&init) {
        Ok(version) => Some(version),
        Err(detail) => return McpStatusReport::failed(detail),
    };
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
    let mut read_only_tools: Vec<String> = Vec::new();
    let mut truncated = false;
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
            for tool in list {
                let Some(name) = tool.get("name").and_then(Value::as_str) else {
                    continue;
                };
                if tools.len() >= MAX_CATALOG_ITEMS {
                    truncated = true;
                    break;
                }
                tools.push(name.to_string());
                if tool
                    .get("annotations")
                    .and_then(|annotations| annotations.get("readOnlyHint"))
                    .and_then(Value::as_bool)
                    == Some(true)
                {
                    read_only_tools.push(name.to_string());
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
        if tools.len() >= MAX_CATALOG_ITEMS {
            truncated = true;
            break;
        }
    }
    if cursor.is_some() {
        truncated = true;
    }
    let mut account = None;
    let mut status_tool_invoked = None;
    if let Some(whoami) = &options.whoami_tool {
        // A catalog template may nominate an account-status tool, but it is
        // still upstream code. Invoke it only when the upstream explicitly
        // marks that exact tool read-only.
        if read_only_tools.iter().any(|tool| tool == whoami) {
            status_tool_invoked = Some(whoami.clone());
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
                    if resources.len() >= MAX_CATALOG_ITEMS {
                        truncated = true;
                        break 'pages;
                    }
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
        if cursor.is_some() {
            truncated = true;
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
    let detail = summary.join(" ");

    McpStatusReport {
        ok: true,
        credential_rejected: false,
        detail,
        server,
        protocol_version,
        account,
        tools,
        resources_supported,
        resources,
        truncated,
        status_tool_invoked,
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
                trusted_ca_bundle_path: None,
                template: "Authorization: Bearer {{T}}".into(),
                mcp_path: Some("/mcp".into()),
                test_path: None,
                oauth: None,
                signer: None,
                client_cert_path: None,
                client_key_path: None,
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

    #[test]
    fn negotiated_protocol_versions_must_be_supported() {
        let mut session = McpSession::new(
            reqwest::Client::new(),
            Url::parse("https://mcp.example.test/mcp").unwrap(),
            Credential::None,
        );
        let error = session
            .adopt_protocol_version(&json!({ "protocolVersion": "2099-01-01" }))
            .unwrap_err();
        assert!(error.contains("unsupported protocol version 2099-01-01"));
        assert!(!session.protocol_sent);

        let version = session
            .adopt_protocol_version(&json!({ "protocolVersion": PROTOCOL_VERSION }))
            .unwrap();
        assert_eq!(version, PROTOCOL_VERSION);
        assert_eq!(session.protocol_version, PROTOCOL_VERSION);
        assert!(session.protocol_sent);
    }

    #[test]
    fn tool_picker_text_is_safe_without_changing_the_policy_identifier() {
        let info = tool_info(&json!({
            "name": "delete\u{200B}all",
            "description": format!("Looks safe\u{202E}{}", "x".repeat(500)),
        }))
        .unwrap();
        assert_eq!(info.name, "delete\u{200B}all");
        assert_eq!(info.display_name.as_deref(), Some("delete\u{FFFD}all"));
        let description = info.description.unwrap();
        assert!(description.starts_with("Looks safe\u{FFFD}"));
        assert_eq!(description.chars().count(), 401);
        assert!(description.ends_with('…'));
    }
}
