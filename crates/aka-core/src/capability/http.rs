//! HTTP capability, `POST /v1/http`.
//!
//! Host-pinning is only as good as the URL assembly, so agent input is
//! validated, not trusted: paths must begin with exactly one `/`, the
//! upstream URL is built from parsed components, a broker-controlled header
//! denylist is non-overridable, and redirects are followed by a hand-rolled
//! loop only when the resolved hop matches the connection's pinned
//! scheme/host/port, re-rendering the injection template onto every hop
//! from scratch.

use std::sync::Arc;
use std::time::Instant;

use http::{HeaderMap, HeaderName, HeaderValue, Method};
use percent_encoding::percent_decode_str;
use serde_json::json;
use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::audit::{AuditEntry, AuditKind, AuditLog};
use crate::broker::Broker;
use crate::capability::SpooledBody;
use crate::config::BrokerConfig;
use crate::endpoints::EndpointListenerHandle;
use crate::executions::ExecOutcome;
use crate::store::Store;
use crate::template::Template;
use crate::types::{Connection, ConnectionConfig, ConnectionKind, WiringEndpoint};
use crate::wire::ErrorReason;

/// Machine-readable validation failure (wire: `400 {"reason": …}`).
#[derive(Debug, PartialEq, Eq)]
pub enum HttpValidationError {
    InvalidMethod,
    InvalidPath,
    ReservedHeader(String),
    InvalidHeader(String),
}

impl HttpValidationError {
    pub fn reason(&self) -> ErrorReason {
        match self {
            HttpValidationError::InvalidMethod => ErrorReason::InvalidMethod,
            HttpValidationError::InvalidPath => ErrorReason::InvalidPath,
            HttpValidationError::ReservedHeader(_) => ErrorReason::ReservedHeader,
            HttpValidationError::InvalidHeader(_) => ErrorReason::InvalidHeader,
        }
    }
    pub fn detail(&self) -> String {
        match self {
            HttpValidationError::InvalidMethod => "unsupported HTTP method".into(),
            HttpValidationError::InvalidPath => {
                "path must begin with exactly one '/' and carry no authority, userinfo or backslashes"
                    .into()
            }
            HttpValidationError::ReservedHeader(h) => {
                format!("header {h:?} is broker-controlled and cannot be set by agents")
            }
            HttpValidationError::InvalidHeader(h) => format!("invalid header {h:?}"),
        }
    }
}

/// Broker-controlled, non-overridable header denylist: the injected
/// credential header is added per connection at validation time.
const DENYLIST: &[&str] = &[
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "upgrade",
    "proxy-authorization",
    "proxy-authenticate",
    "proxy-connection",
    "keep-alive",
    "te",
    "trailer",
    "expect",
];

pub fn is_mutating(method: &Method) -> bool {
    !matches!(*method, Method::GET | Method::HEAD)
}

pub fn parse_method(method: &str) -> Result<Method, HttpValidationError> {
    match method.to_ascii_uppercase().as_str() {
        "GET" => Ok(Method::GET),
        "HEAD" => Ok(Method::HEAD),
        "POST" => Ok(Method::POST),
        "PUT" => Ok(Method::PUT),
        "PATCH" => Ok(Method::PATCH),
        "DELETE" => Ok(Method::DELETE),
        "OPTIONS" => Ok(Method::OPTIONS),
        _ => Err(HttpValidationError::InvalidMethod),
    }
}

/// Path validation: must begin with exactly one `/`; absolute URLs,
/// protocol-relative `//host/…` paths, userinfo tricks, backslashes and
/// control bytes are rejected. Any query string is part of the path.
pub fn validate_path(path: &str) -> Result<(), HttpValidationError> {
    if !path.starts_with('/') || path.starts_with("//") {
        return Err(HttpValidationError::InvalidPath);
    }
    if path.contains('\\') || path.contains('#') {
        return Err(HttpValidationError::InvalidPath);
    }
    if path.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(HttpValidationError::InvalidPath);
    }
    // '@' before the first '/'-terminated segment can't smuggle userinfo,
    // the path never becomes an authority (we reject "//"), but reject a
    // leading "/@" style anyway if it parses as userinfo when joined.
    Ok(())
}

/// Validate agent-supplied headers against grammar + denylist. The injected
/// credential header name (if the template is a header form) joins the
/// denylist. Returns the parsed header map.
pub fn validate_headers(
    headers: &[(String, String)],
    credential_header: Option<&str>,
) -> Result<HeaderMap, HttpValidationError> {
    let mut map = HeaderMap::new();
    for (name, value) in headers {
        let lower = name.to_ascii_lowercase();
        if DENYLIST.contains(&lower.as_str())
            || credential_header.is_some_and(|c| c.eq_ignore_ascii_case(&lower))
        {
            return Err(HttpValidationError::ReservedHeader(name.clone()));
        }
        let header_name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| HttpValidationError::InvalidHeader(name.clone()))?;
        let header_value = HeaderValue::from_str(value)
            .map_err(|_| HttpValidationError::InvalidHeader(name.clone()))?;
        map.append(header_name, header_value);
    }
    Ok(map)
}

/// How the connection's rendered template is injected: a header line
/// (`Name: value`) or a query-param form (template starting with `?`,
/// e.g. `?token={{url(STREAM_TOKEN)}}`).
pub enum InjectionForm {
    Header { name: String },
    Query,
}

/// Inspect the (already parse-validated) template to learn the injection
/// form without rendering any secret.
pub fn injection_form(template_src: &str) -> Option<InjectionForm> {
    let trimmed = template_src.trim_start();
    if let Some(stripped) = trimmed.strip_prefix('?') {
        let _ = stripped;
        return Some(InjectionForm::Query);
    }
    trimmed
        .split_once(':')
        .map(|(name, _)| InjectionForm::Header {
            name: name.trim().to_string(),
        })
}

/// The rendered credential, applied fresh to every hop.
pub(crate) enum RenderedInjection {
    Header(HeaderName, HeaderValue),
    /// Raw query-string fragment (already percent-encoded by the template's
    /// `url(…)` transform), e.g. `token=abc%20def`.
    Query(Zeroizing<String>),
}

/// Best-effort response scrubber for reflected credentials. This deliberately
/// treats redaction material as sensitive and only exposes replacement text.
struct Redactions {
    needles: Vec<Zeroizing<String>>,
}

impl Redactions {
    fn from_injection(injection: &RenderedInjection) -> Self {
        let mut redactions = Self {
            needles: Vec::new(),
        };
        match injection {
            RenderedInjection::Header(name, value) => {
                if let Ok(value) = value.to_str() {
                    redactions.add(value);
                    redactions.add(format!("{}: {value}", name.as_str()));
                    for part in value.split(|c: char| c.is_ascii_whitespace()) {
                        redactions.add_component(part);
                    }
                }
            }
            RenderedInjection::Query(fragment) => {
                redactions.add(&**fragment);
                if let Ok(decoded) = percent_decode_str(fragment).decode_utf8() {
                    redactions.add(decoded.as_ref());
                }
                for pair in fragment.split('&') {
                    if let Some((_, value)) = pair.split_once('=') {
                        redactions.add_component(value);
                        if let Ok(decoded) = percent_decode_str(value).decode_utf8() {
                            redactions.add_component(decoded.as_ref());
                        }
                    }
                }
            }
        }
        redactions
    }

    fn add(&mut self, value: impl AsRef<str>) {
        let value = value.as_ref();
        if value.is_empty() || self.needles.iter().any(|needle| needle.as_str() == value) {
            return;
        }
        self.needles.push(Zeroizing::new(value.to_string()));
    }

    fn add_component(&mut self, value: impl AsRef<str>) {
        let value = value.as_ref();
        if value.len() >= 4 {
            self.add(value);
        }
    }

    fn apply_to_string(&self, value: &str) -> String {
        self.needles.iter().fold(value.to_string(), |acc, needle| {
            acc.replace(needle.as_str(), "[REDACTED]")
        })
    }

    fn apply_to_bytes(&self, value: &[u8]) -> Vec<u8> {
        if self.needles.is_empty() {
            return value.to_vec();
        }
        let mut out = value.to_vec();
        for needle in &self.needles {
            let needle = needle.as_bytes();
            if needle.is_empty() {
                continue;
            }
            let mut redacted = Vec::with_capacity(out.len());
            let mut i = 0usize;
            while i < out.len() {
                if out[i..].starts_with(needle) {
                    redacted.extend_from_slice(b"[REDACTED]");
                    i += needle.len();
                } else {
                    redacted.push(out[i]);
                    i += 1;
                }
            }
            out = redacted;
        }
        out
    }
}

/// Everything the executor needs, captured at submission time, the
/// connection is snapshotted so a concurrent edit can't repoint what the
/// user approved.
pub struct HttpExecution {
    pub store: Arc<Store>,
    pub audit: Arc<AuditLog>,
    pub client: reqwest::Client,
    pub config: BrokerConfig,
    pub agent: String,
    pub connection: Connection,
    pub method: Method,
    pub path: String,
    pub headers: HeaderMap,
    pub body: Arc<SpooledBody>,
    /// When present, the outcome updates the connection's last-known health:
    /// an upstream 401/403 flips it to needs-reconnect, a served response
    /// upgrades it to ok.
    pub health: Option<Arc<crate::health::HealthRegistry>>,
}

/// Pinned upstream authority from an API connection config.
fn pinned_base(config: &ConnectionConfig) -> Option<(String, String, Option<u16>)> {
    match config {
        ConnectionConfig::Api {
            host, scheme, port, ..
        } => Some((scheme.clone(), host.clone(), *port)),
        _ => None,
    }
}

fn same_pinned_authority(url: &Url, scheme: &str, host: &str, port: Option<u16>) -> bool {
    let pinned_port = port.unwrap_or(match scheme {
        "https" => 443,
        _ => 80,
    });
    url.scheme() == scheme
        && url.host_str().is_some_and(|h| h.eq_ignore_ascii_case(host))
        && url.port_or_known_default() == Some(pinned_port)
}

fn broker_error(status: u16, reason: ErrorReason, detail: impl Into<String>) -> ExecOutcome {
    ExecOutcome {
        status,
        body: json!({ "reason": reason, "detail": detail.into() }),
    }
}

impl HttpExecution {
    /// Perform the approved request: render the credential, drive the
    /// redirect loop, relay `{status, headers, body}`. Runs exactly once
    /// per approval.
    pub async fn run(self) -> ExecOutcome {
        let started = Instant::now();
        let outcome = self.run_inner().await;
        let upstream_status = outcome
            .body
            .get("status")
            .and_then(|s| s.as_u64())
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("broker:{}", outcome.status));
        self.record_health(&outcome);
        self.audit.append(
            AuditEntry::new(
                AuditKind::HttpExecuted,
                format!("{} {} via {}", self.method, self.path, self.connection.name),
            )
            .agent(self.agent.clone())
            .connection(self.connection.name.clone())
            .outcome(upstream_status)
            .duration_ms(started.elapsed().as_millis() as u64)
            .field("method", self.method.to_string())
            .field("path", self.path.clone()),
        );
        outcome
    }

    /// Health bookkeeping from one outcome: a relayed upstream 401/403 means
    /// the destination rejected the credential; any other relayed response
    /// proves the connection works; broker-side errors are not conclusive.
    fn record_health(&self, outcome: &ExecOutcome) {
        let Some(health) = &self.health else { return };
        let id = self.connection.id;
        match outcome.body.get("status").and_then(|s| s.as_u64()) {
            Some(status @ (401 | 403)) => health.record(
                &id,
                crate::types::HealthStatus::NeedsReconnect,
                format!("The destination answered but rejected the credential (HTTP {status})"),
            ),
            Some(_) => health.record_ok_if_changed(&id, "A brokered call reached the destination"),
            None => {
                let oauth = matches!(
                    &self.connection.config,
                    ConnectionConfig::Api { oauth: Some(_), .. }
                );
                let render_failed = outcome
                    .body
                    .get("reason")
                    .and_then(|r| r.as_str())
                    .is_some_and(|r| r == "credential_render_failed");
                if oauth && render_failed {
                    let detail = outcome
                        .body
                        .get("detail")
                        .and_then(|d| d.as_str())
                        .unwrap_or("The OAuth token could not be refreshed");
                    health.record(
                        &id,
                        crate::types::HealthStatus::NeedsReconnect,
                        detail.to_string(),
                    );
                }
            }
        }
    }

    async fn run_inner(&self) -> ExecOutcome {
        // An OAuth-minted token at expiry is renewed before it rides the
        // upstream leg, so agent calls never present a token the broker
        // already knew was stale. Best-effort: on failure the current token
        // goes out as-is and the upstream's verdict lands in health.
        if self.connection.oauth.is_some() {
            let ctx = crate::mcp_refresh::RefreshContext {
                store: self.store.as_ref(),
                http: &self.client,
                audit: self.audit.as_ref(),
                health: self.health.as_deref(),
            };
            crate::mcp_refresh::ensure_fresh(&ctx, &self.connection).await;
        }
        // Render the credential as late as possible; values are zeroized on
        // drop.
        if !matches!(&self.connection.config, ConnectionConfig::Api { .. }) {
            return broker_error(
                500,
                ErrorReason::WrongConnectionType,
                "not an api connection",
            );
        }
        let (scheme, host, port) = pinned_base(&self.connection.config).expect("api config");

        let injection =
            match render_connection_injection(&self.store, &self.client, &self.connection).await {
                Ok(i) => i,
                Err(e) => return broker_error(502, ErrorReason::CredentialRenderFailed, e),
            };
        let redactions = Redactions::from_injection(&injection);

        // Build the initial URL from parsed components, never string
        // concatenation.
        let mut base = match Url::parse(&format!("{scheme}://{host}")) {
            Ok(u) => u,
            Err(e) => return broker_error(500, ErrorReason::BadConnectionConfig, e.to_string()),
        };
        if base.set_port(port).is_err() {
            return broker_error(500, ErrorReason::BadConnectionConfig, "cannot set port");
        }
        let mut current = match base.join(&self.path) {
            Ok(u) => u,
            Err(e) => return broker_error(400, ErrorReason::InvalidPath, e.to_string()),
        };
        // Belt and braces: the joined URL must still point at the pinned
        // authority, with no userinfo.
        if !same_pinned_authority(&current, &scheme, &host, port)
            || !current.username().is_empty()
            || current.password().is_some()
        {
            return broker_error(
                400,
                ErrorReason::InvalidPath,
                "path escaped the pinned authority",
            );
        }
        base.set_path("");

        let mut method = self.method.clone();
        let mut send_body = true;
        let mut hops = 0usize;

        loop {
            let mut request = self
                .client
                .request(method.clone(), current.clone())
                .timeout(self.config.upstream_timeout)
                .headers(self.headers.clone());
            match &injection {
                RenderedInjection::Header(name, value) => {
                    request = request.header(name.clone(), value.clone());
                }
                RenderedInjection::Query(fragment) => {
                    // Append the credential fragment to whatever query the
                    // hop carries; the fragment is pre-encoded.
                    let mut hop = current.clone();
                    let combined = match hop.query() {
                        Some(q) if !q.is_empty() => format!("{q}&{}", &**fragment),
                        _ => fragment.to_string(),
                    };
                    hop.set_query(Some(&combined));
                    request = self
                        .client
                        .request(method.clone(), hop)
                        .timeout(self.config.upstream_timeout)
                        .headers(self.headers.clone());
                }
            }
            if send_body && !self.body.is_empty() {
                match self.body.bytes() {
                    Ok(bytes) => request = request.body(bytes),
                    Err(e) => {
                        return broker_error(500, ErrorReason::BodyUnavailable, e.to_string())
                    }
                }
            }

            let response = match request.send().await {
                Ok(r) => r,
                // Strip the URL from the error before it reaches the agent:
                // reqwest's Display embeds the full request URL, and a
                // query-param injection form (`?token={{url(SECRET)}}`) carries
                // the credential in that URL, so the raw error string would
                // leak the secret the broker exists to withhold.
                Err(e) if e.is_timeout() => {
                    return broker_error(
                        504,
                        ErrorReason::UpstreamTimeout,
                        e.without_url().to_string(),
                    )
                }
                Err(e) => {
                    return broker_error(
                        502,
                        ErrorReason::UpstreamError,
                        e.without_url().to_string(),
                    )
                }
            };

            let status = response.status();
            if status.is_redirection() {
                let location = response
                    .headers()
                    .get(http::header::LOCATION)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string);
                if let Some(location) = location {
                    if hops < self.config.max_redirects
                        && matches!(status.as_u16(), 301 | 302 | 303 | 307 | 308)
                    {
                        match current.join(&location) {
                            Ok(resolved) => {
                                let clean =
                                    resolved.username().is_empty() && resolved.password().is_none();
                                if clean && same_pinned_authority(&resolved, &scheme, &host, port) {
                                    // Same pinned upstream: follow, with the
                                    // credential re-rendered onto the new
                                    // request from scratch.
                                    hops += 1;
                                    match status.as_u16() {
                                        303 => {
                                            method = Method::GET;
                                            send_body = false;
                                        }
                                        301 | 302 if method == Method::POST => {
                                            method = Method::GET;
                                            send_body = false;
                                        }
                                        _ => {}
                                    }
                                    let mut next = resolved;
                                    next.set_fragment(None);
                                    current = next;
                                    continue;
                                }
                            }
                            Err(_) => {
                                // Unresolvable Location: return the 3xx raw.
                            }
                        }
                    }
                }
                // Cross-host, unresolvable, over-budget, or non-followable
                // 3xx: return it to the agent instead of following,
                // following would send the credential somewhere no
                // connection was configured for.
                return relay_response(response, &self.config, &redactions).await;
            }

            return relay_response(response, &self.config, &redactions).await;
        }
    }
}

/// UI-initiated test: GET the pinned origin root with the credential
/// injected, reporting the upstream status. A 401/403 means the service
/// answered but rejected the credential.
pub async fn test_upstream(
    store: &Arc<Store>,
    client: &reqwest::Client,
    timeout: std::time::Duration,
    connection: &Connection,
) -> Result<String, String> {
    if !matches!(&connection.config, ConnectionConfig::Api { .. }) {
        return Err("not an api connection".into());
    }
    let (scheme, host, port) = pinned_base(&connection.config).expect("api config");
    let injection = render_connection_injection(store, client, connection).await?;
    let mut url =
        Url::parse(&format!("{scheme}://{host}/")).map_err(|e| format!("bad origin: {e}"))?;
    if url.set_port(port).is_err() {
        return Err("cannot set port".into());
    }
    let request = match &injection {
        RenderedInjection::Header(name, value) => client
            .request(Method::GET, url.clone())
            .header(name.clone(), value.clone()),
        RenderedInjection::Query(fragment) => {
            url.set_query(Some(fragment));
            client.request(Method::GET, url.clone())
        }
    };
    let response = request
        .timeout(timeout)
        .send()
        .await
        // reqwest's Display embeds the URL, which can carry a query-injected
        // credential; strip it exactly as the relay path does.
        .map_err(|e| e.without_url().to_string())?;
    let status = response.status();
    if matches!(status.as_u16(), 401 | 403) {
        return Err(format!(
            "{host} answered but rejected the credential (HTTP {status})"
        ));
    }
    Ok(format!("GET {scheme}://{host}/ answered HTTP {status}"))
}

/// The credential for a connection's upstream leg: a fresh OAuth bearer
/// for BYO-app OAuth connections (refreshing on expiry), the rendered
/// injection template otherwise.
pub(crate) async fn render_connection_injection(
    store: &Arc<Store>,
    client: &reqwest::Client,
    connection: &Connection,
) -> Result<RenderedInjection, String> {
    let ConnectionConfig::Api {
        template, oauth, ..
    } = &connection.config
    else {
        return Err("not an api connection".into());
    };
    if oauth.is_some() {
        let token = crate::oauth::fresh_bearer(store, client, connection).await?;
        let mut value = HeaderValue::from_str(&format!("Bearer {}", &*token))
            .map_err(|_| "the stored access token is not a valid header value".to_string())?;
        value.set_sensitive(true);
        return Ok(RenderedInjection::Header(
            HeaderName::from_static("authorization"),
            value,
        ));
    }
    render_injection(store, template).await
}

pub(crate) async fn render_injection(
    store: &Store,
    template_src: &str,
) -> Result<RenderedInjection, String> {
    let template = Template::parse(template_src).map_err(|e| e.to_string())?;
    let rendered = store
        .render_template(&template)
        .await
        .map_err(|e| e.to_string())?;
    let trimmed = rendered.trim_start();
    if let Some(fragment) = trimmed.strip_prefix('?') {
        return Ok(RenderedInjection::Query(Zeroizing::new(
            fragment.to_string(),
        )));
    }
    let (name, value) = trimmed
        .split_once(':')
        .ok_or_else(|| "template must render 'Header: value' or a '?query=form'".to_string())?;
    // Rendered output is validated against the HTTP field grammar before it
    // is attached, so a secret containing control bytes can't smuggle a
    // second header.
    let header_name = HeaderName::from_bytes(name.trim().as_bytes())
        .map_err(|_| "rendered header name invalid".to_string())?;
    let header_value = HeaderValue::from_str(value.trim())
        .map_err(|_| "rendered header value invalid (control bytes?)".to_string())?;
    Ok(RenderedInjection::Header(header_name, header_value))
}

/// Relay `{status, headers, body}` to the agent, size-capping the body and
/// base64-encoding non-UTF-8 bodies.
async fn relay_response(
    response: reqwest::Response,
    config: &BrokerConfig,
    redactions: &Redactions,
) -> ExecOutcome {
    let status = response.status().as_u16();
    let mut headers = serde_json::Map::new();
    for (name, value) in response.headers() {
        let value_lossy = String::from_utf8_lossy(value.as_bytes());
        let value_str = redactions.apply_to_string(value_lossy.as_ref());
        match headers.get_mut(name.as_str()) {
            Some(serde_json::Value::String(existing)) => {
                *existing = format!("{existing}, {value_str}");
            }
            _ => {
                headers.insert(name.as_str().to_string(), json!(value_str));
            }
        }
    }

    let mut body = Vec::new();
    let mut stream = response;
    loop {
        match stream.chunk().await {
            Ok(Some(chunk)) => {
                if body.len() + chunk.len() > config.response_cap {
                    return broker_error(
                        502,
                        ErrorReason::ResponseTooLarge,
                        format!("upstream body exceeds the {} byte cap", config.response_cap),
                    );
                }
                body.extend_from_slice(&chunk);
            }
            Ok(None) => break,
            // Same reasoning as the send path: keep any query-injected
            // credential in the URL out of the agent-visible error.
            Err(e) => {
                return broker_error(502, ErrorReason::UpstreamError, e.without_url().to_string())
            }
        }
    }
    let body = redactions.apply_to_bytes(&body);

    let (body_value, encoding) = match String::from_utf8(body) {
        Ok(text) => (json!(text), "utf8"),
        Err(e) => {
            use base64::Engine as _;
            (
                json!(base64::engine::general_purpose::STANDARD.encode(e.as_bytes())),
                "base64",
            )
        }
    };

    ExecOutcome {
        status: 200,
        body: json!({
            "status": status,
            "headers": headers,
            "body": body_value,
            "body_encoding": encoding,
        }),
    }
}

/// Idempotency-key payload hash: the full normalized request, a genuine
/// retry matches byte-for-byte.
pub fn payload_hash(
    connection_id: &Uuid,
    method: &Method,
    path: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(connection_id.as_bytes());
    hasher.update([0]);
    hasher.update(method.as_str().as_bytes());
    hasher.update([0]);
    hasher.update(path.as_bytes());
    hasher.update([0]);
    let mut normalized: Vec<String> = headers
        .iter()
        .map(|(k, v)| format!("{}:{}", k.to_ascii_lowercase(), v.trim()))
        .collect();
    normalized.sort();
    for line in normalized {
        hasher.update(line.as_bytes());
        hasher.update([0]);
    }
    hasher.update(body);
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/* --------------------------- per-wiring endpoint -------------------------- */

/// State shared by one HTTP reverse-proxy endpoint's request handler.
struct HttpEndpointState {
    broker: Arc<Broker>,
    endpoint_id: Uuid,
}

/// Bind a per-wiring HTTP reverse proxy on a loopback TCP port. An unmodified
/// HTTP client reaches the pinned origin with `http://127.0.0.1:<port>/<path>`,
/// presenting the per-wiring secret as `Authorization: Bearer <secret>`; the
/// proxy authenticates and strips it, re-checks the wiring, injects the
/// connection's real credential on the upstream leg (origin-pinned, with the
/// same redirect and response-redaction rules as `/v1/http`), and relays the
/// response. This is the one direct endpoint that reuses `/v1/http`'s whole
/// execution core — so it also *loses* that path's `request_id` idempotency
/// and reserved-header validation; agents that need coalescing keep using
/// `/v1/http`.
///
/// The 256-bit secret is the capability. A loopback port is reachable by any
/// local process (even another user), so — unlike the PG/SSH sockets, which
/// filesystem permissions restrict to the owner — the secret is the *only*
/// boundary here, exactly as the WS/PG ticket data planes rely on an
/// unguessable ticket over loopback. Returns the handle and the bound port
/// (persisted so a pasted base URL survives a restart).
pub async fn bind_endpoint(
    broker: Arc<Broker>,
    endpoint: &WiringEndpoint,
) -> std::io::Result<(EndpointListenerHandle, u16)> {
    let requested_port = endpoint.port.unwrap_or(0);
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", requested_port)).await?;
    let port = listener.local_addr()?.port();

    let state = Arc::new(HttpEndpointState {
        broker,
        endpoint_id: endpoint.id,
    });
    let app = axum::Router::new()
        .fallback(proxy_handler)
        .with_state(state);
    let shutdown = Arc::new(tokio::sync::Notify::new());
    let sd = shutdown.clone();
    let task = tokio::spawn(async move {
        let served = axum::serve(listener, app)
            .with_graceful_shutdown(async move { sd.notified().await });
        if let Err(e) = served.await {
            tracing::error!("http endpoint serve ended: {e}");
        }
    });
    Ok((EndpointListenerHandle { shutdown, task }, port))
}

/// A machine-readable endpoint-plane error, mirroring the control plane's
/// `{"reason","detail"}` shape.
fn endpoint_error(
    status: axum::http::StatusCode,
    reason: &str,
    detail: &str,
) -> axum::response::Response {
    use axum::response::IntoResponse as _;
    (status, axum::Json(json!({ "reason": reason, "detail": detail }))).into_response()
}

async fn proxy_handler(
    axum::extract::State(state): axum::extract::State<Arc<HttpEndpointState>>,
    req: axum::extract::Request,
) -> axum::response::Response {
    use axum::http::StatusCode;
    let broker = &state.broker;
    let (parts, body) = req.into_parts();

    // Authenticate the per-wiring secret (Authorization: Bearer …) to THIS
    // endpoint; a secret for another endpoint (or none) is refused.
    let presented = parts
        .headers
        .get(http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            v.strip_prefix("Bearer ")
                .or_else(|| v.strip_prefix("bearer "))
        })
        .map(str::trim);
    let Some(presented) = presented.filter(|s| !s.is_empty()) else {
        return endpoint_error(
            StatusCode::UNAUTHORIZED,
            "missing_secret",
            "present the endpoint secret as `Authorization: Bearer <secret>`",
        );
    };
    let Some(endpoint) = broker
        .endpoints
        .resolve_secret(presented)
        .filter(|e| e.id == state.endpoint_id)
    else {
        return endpoint_error(
            StatusCode::UNAUTHORIZED,
            "invalid_secret",
            "the endpoint secret is not recognized",
        );
    };

    // Authorization is enforced here, on every request, at connect time.
    if !broker
        .wirings
        .is_wired(&endpoint.client_id, &endpoint.connection_id)
    {
        return endpoint_error(
            StatusCode::FORBIDDEN,
            "denied_by_policy",
            "this agent is no longer wired to the tool",
        );
    }
    let Ok(connection) = broker.store.connection_by_id(&endpoint.connection_id) else {
        return endpoint_error(
            StatusCode::BAD_GATEWAY,
            "unknown_connection",
            "the connection has been removed",
        );
    };
    if connection.kind() != ConnectionKind::Api {
        return endpoint_error(
            StatusCode::BAD_GATEWAY,
            "wrong_connection_type",
            "the connection is no longer an HTTP tool",
        );
    }

    let method = parts.method.clone();
    let path = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    if validate_path(&path).is_err() {
        return endpoint_error(
            StatusCode::BAD_REQUEST,
            "invalid_path",
            "the path must begin with a single `/`",
        );
    }

    // Forward the client's headers minus the endpoint auth, the proxy's own
    // Host, and framing/encoding headers the upstream leg recomputes. The real
    // credential is injected on the upstream leg by the shared core.
    let mut headers = HeaderMap::new();
    for (name, value) in parts.headers.iter() {
        if matches!(
            name.as_str(),
            "authorization"
                | "host"
                | "content-length"
                | "connection"
                | "transfer-encoding"
                | "accept-encoding"
        ) {
            continue;
        }
        headers.insert(name.clone(), value.clone());
    }

    let bytes = match axum::body::to_bytes(body, broker.config.request_cap).await {
        Ok(b) => b,
        Err(_) => {
            return endpoint_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "request_too_large",
                "the request body exceeds the configured cap",
            )
        }
    };
    let spooled = match SpooledBody::from_bytes(bytes.to_vec(), broker.config.spool_threshold) {
        Ok(b) => Arc::new(b),
        Err(e) => {
            return endpoint_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "spool_failed",
                &e.to_string(),
            )
        }
    };

    // Reuse `/v1/http`'s whole execution core. The wiring is the
    // authorization, so the vault read is pre-authorized (scope confirmed).
    let execution = HttpExecution {
        store: broker.store.clone(),
        audit: broker.audit.clone(),
        client: broker.http_client.clone(),
        config: broker.config.clone(),
        agent: endpoint.agent.clone(),
        connection,
        method,
        path,
        headers,
        body: spooled,
        health: Some(broker.health.clone()),
    };
    let outcome = crate::authorization::scope(true, execution.run()).await;
    translate_outcome(outcome)
}

/// Translate `/v1/http`'s relayed `{status, headers, body, body_encoding}`
/// envelope back into a raw HTTP response for the reverse-proxy client. A
/// broker-side error (`status != 200`, a `{reason, detail}` body) is returned
/// as that status directly.
fn translate_outcome(outcome: ExecOutcome) -> axum::response::Response {
    use axum::http::StatusCode;
    if outcome.status != 200 {
        let status = StatusCode::from_u16(outcome.status).unwrap_or(StatusCode::BAD_GATEWAY);
        return endpoint_error(
            status,
            outcome
                .body
                .get("reason")
                .and_then(|r| r.as_str())
                .unwrap_or("upstream_error"),
            outcome
                .body
                .get("detail")
                .and_then(|d| d.as_str())
                .unwrap_or(""),
        );
    }
    let env = outcome.body;
    let status = env
        .get("status")
        .and_then(|s| s.as_u64())
        .and_then(|s| StatusCode::from_u16(s as u16).ok())
        .unwrap_or(StatusCode::BAD_GATEWAY);
    let body_str = env.get("body").and_then(|b| b.as_str()).unwrap_or("");
    let body_bytes: Vec<u8> = match env.get("body_encoding").and_then(|e| e.as_str()) {
        Some("base64") => {
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD
                .decode(body_str)
                .unwrap_or_default()
        }
        _ => body_str.as_bytes().to_vec(),
    };

    let mut response = axum::response::Response::builder().status(status);
    if let Some(headers) = env.get("headers").and_then(|h| h.as_object()) {
        for (name, value) in headers {
            // Framing/length headers are recomputed for the client leg.
            if matches!(
                name.to_ascii_lowercase().as_str(),
                "content-length" | "transfer-encoding" | "connection"
            ) {
                continue;
            }
            if let (Ok(hn), Some(vs)) = (HeaderName::from_bytes(name.as_bytes()), value.as_str()) {
                if let Ok(hv) = HeaderValue::from_str(vs) {
                    response = response.header(hn, hv);
                }
            }
        }
    }
    response
        .body(axum::body::Body::from(body_bytes))
        .unwrap_or_else(|_| {
            use axum::response::IntoResponse as _;
            StatusCode::BAD_GATEWAY.into_response()
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_validated() {
        assert!(validate_path("/user/repos").is_ok());
        assert!(validate_path("/search?q=a%20b&x=1").is_ok());
        assert_eq!(
            validate_path("//attacker.com/x").unwrap_err(),
            HttpValidationError::InvalidPath
        );
        assert_eq!(
            validate_path("https://attacker.com/x").unwrap_err(),
            HttpValidationError::InvalidPath
        );
        assert_eq!(
            validate_path("user/repos").unwrap_err(),
            HttpValidationError::InvalidPath
        );
        assert_eq!(
            validate_path("/a\\b").unwrap_err(),
            HttpValidationError::InvalidPath
        );
        assert_eq!(
            validate_path("/a\r\nHost: evil").unwrap_err(),
            HttpValidationError::InvalidPath
        );
        assert_eq!(
            validate_path("").unwrap_err(),
            HttpValidationError::InvalidPath
        );
    }

    #[test]
    fn denylist_is_case_insensitive_and_covers_credential_header() {
        for name in [
            "Host",
            "host",
            "HOST",
            "Transfer-Encoding",
            "connection",
            "TE",
        ] {
            assert!(matches!(
                validate_headers(&[(name.to_string(), "x".into())], None).unwrap_err(),
                HttpValidationError::ReservedHeader(_)
            ));
        }
        assert!(matches!(
            validate_headers(
                &[("authorization".to_string(), "Bearer mine".into())],
                Some("Authorization"),
            )
            .unwrap_err(),
            HttpValidationError::ReservedHeader(_)
        ));
        // A custom credential header is likewise protected.
        assert!(matches!(
            validate_headers(&[("X-Api-Key".to_string(), "v".into())], Some("x-api-key"))
                .unwrap_err(),
            HttpValidationError::ReservedHeader(_)
        ));
        // Ordinary headers pass.
        let map = validate_headers(
            &[("Accept".to_string(), "application/vnd.github+json".into())],
            Some("authorization"),
        )
        .unwrap();
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn header_grammar_enforced() {
        assert!(matches!(
            validate_headers(&[("Bad Name".to_string(), "v".into())], None).unwrap_err(),
            HttpValidationError::InvalidHeader(_)
        ));
        assert!(matches!(
            validate_headers(&[("X-Ok".to_string(), "bad\r\nvalue".into())], None).unwrap_err(),
            HttpValidationError::InvalidHeader(_)
        ));
    }

    #[test]
    fn injection_forms_detected() {
        match injection_form("Authorization: Bearer {{K}}") {
            Some(InjectionForm::Header { name }) => assert_eq!(name, "Authorization"),
            _ => panic!(),
        }
        assert!(matches!(
            injection_form("?token={{url(K)}}"),
            Some(InjectionForm::Query)
        ));
        assert!(injection_form("no separator").is_none());
    }

    #[test]
    fn redactions_cover_header_value_and_secret_component() {
        let injection = RenderedInjection::Header(
            HeaderName::from_static("authorization"),
            HeaderValue::from_static("Bearer ghp_test_secret_value"),
        );
        let redactions = Redactions::from_injection(&injection);

        assert_eq!(
            redactions.apply_to_string("authorization=Bearer ghp_test_secret_value"),
            "authorization=[REDACTED]"
        );
        assert_eq!(
            redactions.apply_to_string("token ghp_test_secret_value reflected"),
            "token [REDACTED] reflected"
        );
    }

    #[test]
    fn redactions_cover_query_fragment_and_decoded_value() {
        let injection =
            RenderedInjection::Query(Zeroizing::new("token=abc%20123&other=ok".to_string()));
        let redactions = Redactions::from_injection(&injection);

        assert_eq!(
            redactions.apply_to_string("/echo?token=abc%20123&other=ok"),
            "/echo?[REDACTED]"
        );
        assert_eq!(
            redactions.apply_to_string("decoded abc 123"),
            "decoded [REDACTED]"
        );
    }

    #[test]
    fn redactions_cover_binary_body_bytes() {
        let injection = RenderedInjection::Header(
            HeaderName::from_static("authorization"),
            HeaderValue::from_static("Bearer ghp_test_secret_value"),
        );
        let redactions = Redactions::from_injection(&injection);

        assert_eq!(
            redactions.apply_to_bytes(b"\x00ghp_test_secret_value\xff"),
            b"\x00[REDACTED]\xff"
        );
    }

    #[test]
    fn same_authority_matching() {
        let pinned = ("https", "api.github.com", None::<u16>);
        let ok = Url::parse("https://API.GITHUB.COM/next").unwrap();
        assert!(same_pinned_authority(&ok, pinned.0, pinned.1, pinned.2));
        let wrong_host = Url::parse("https://evil.com/x").unwrap();
        assert!(!same_pinned_authority(
            &wrong_host,
            pinned.0,
            pinned.1,
            pinned.2
        ));
        let wrong_scheme = Url::parse("http://api.github.com/x").unwrap();
        assert!(!same_pinned_authority(
            &wrong_scheme,
            pinned.0,
            pinned.1,
            pinned.2
        ));
        let wrong_port = Url::parse("https://api.github.com:8443/x").unwrap();
        assert!(!same_pinned_authority(
            &wrong_port,
            pinned.0,
            pinned.1,
            pinned.2
        ));
        // Explicit default port matches.
        let explicit = Url::parse("https://api.github.com:443/x").unwrap();
        assert!(same_pinned_authority(
            &explicit, pinned.0, pinned.1, pinned.2
        ));
    }

    #[test]
    fn payload_hash_normalizes_headers() {
        let conn = Uuid::new_v4();
        let a = payload_hash(
            &conn,
            &Method::POST,
            "/x",
            &[("Accept".into(), "json".into()), ("B".into(), "2".into())],
            b"body",
        );
        let b = payload_hash(
            &conn,
            &Method::POST,
            "/x",
            &[("b".into(), "2".into()), ("accept".into(), "json".into())],
            b"body",
        );
        assert_eq!(a, b);
        let c = payload_hash(&conn, &Method::POST, "/x", &[], b"other");
        assert_ne!(a, c);
        let d = payload_hash(&Uuid::new_v4(), &Method::POST, "/x", &[], b"other");
        assert_ne!(c, d);
    }
}
