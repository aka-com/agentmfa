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

use axum::body::HttpBody as _;
use http::{HeaderMap, HeaderName, HeaderValue, Method};
use http_body_util::BodyExt as _;
use percent_encoding::percent_decode_str;
use serde_json::json;
use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::audit::{AuditEntry, AuditKind, AuditLog};
use crate::broker::Broker;
use crate::capability::{BodySpool, SpoolError, SpooledBody, TestError, TestErrorKind};
use crate::config::BrokerConfig;
use crate::endpoints::EndpointListenerHandle;
use crate::executions::ExecOutcome;
use crate::store::Store;
use crate::template::Template;
use crate::types::{Connection, ConnectionConfig, ConnectionKind, DirectEndpoint};
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
    // Nothing here can decompress: reqwest is built without `gzip`/`brotli`,
    // so a compressed body would be relayed as opaque base64 the agent cannot
    // read and `apply_to_bytes` cannot scrub a reflected credential out of.
    // The direct endpoint plane already strips both; this is the same rule.
    "accept-encoding",
    "content-encoding",
];

pub fn is_mutating(method: &Method) -> bool {
    !matches!(*method, Method::GET | Method::HEAD)
}

/// Whether an empty request is an identifiable Streamable HTTP transport
/// leg on this connection's pinned MCP path. Generic bodyless methods are
/// still traffic: opening the event stream requires an accepted exact
/// `text/event-stream` media type, and teardown requires a named session.
pub(crate) fn is_mcp_transport_leg(
    connection: &Connection,
    method: &Method,
    path: &str,
    headers: &HeaderMap,
    body_is_definitely_empty: bool,
) -> bool {
    if !body_is_definitely_empty {
        return false;
    }
    let ConnectionConfig::Api {
        mcp_path: Some(mcp_path),
        ..
    } = &connection.config
    else {
        return false;
    };
    if !resolves_to_mcp_path(path, mcp_path) {
        return false;
    }

    match *method {
        Method::GET => headers
            .get_all(http::header::ACCEPT)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(','))
            .any(|value| {
                let mut parts = value.trim().split(';');
                let event_stream = parts.next().is_some_and(|media_type| {
                    media_type.trim().eq_ignore_ascii_case("text/event-stream")
                });
                let quality = parts.find_map(|parameter| {
                    let (name, value) = parameter.trim().split_once('=')?;
                    name.trim()
                        .eq_ignore_ascii_case("q")
                        .then(|| value.trim().parse::<f32>().ok())
                });
                event_stream && quality.unwrap_or(Some(1.0)).is_some_and(|q| q > 0.0)
            }),
        Method::DELETE => headers
            .get("mcp-session-id")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| !value.trim().is_empty()),
        _ => false,
    }
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
/// Headers an agent may never set on an API call, whatever the connection's
/// injection form.
///
/// `authorization` is here rather than derived from the template because it was
/// only reserved when the template *happened* to inject it: a query-form or
/// credential-less connection let the agent's own `Authorization` through to be
/// attached upstream, which is both a credential the broker did not choose and
/// (for an agent sending its broker token) a leak of the pairing key to a third
/// party. The endpoint plane strips it unconditionally; this is the same rule.
const ALWAYS_RESERVED: &[&str] = &["authorization"];

pub fn validate_headers(
    headers: &[(String, String)],
    credential_header: Option<&str>,
) -> Result<HeaderMap, HttpValidationError> {
    let mut map = HeaderMap::new();
    for (name, value) in headers {
        let lower = name.to_ascii_lowercase();
        if DENYLIST.contains(&lower.as_str())
            || ALWAYS_RESERVED.contains(&lower.as_str())
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

fn connection_credential_header(connection: &Connection) -> Option<String> {
    let ConnectionConfig::Api {
        template, oauth, ..
    } = &connection.config
    else {
        return None;
    };
    if oauth.is_some() {
        return Some("authorization".to_string());
    }
    match injection_form(template) {
        Some(InjectionForm::Header { name }) => Some(name),
        Some(InjectionForm::Query) | None => None,
    }
}

/// Sanitize the raw direct-endpoint client leg before the configured
/// credential is injected. In addition to ordinary hop-by-hop headers, strip
/// fields nominated by `Connection`; reject any attempt to supply a custom
/// credential header instead of silently allowing it to shadow the broker.
fn endpoint_forward_headers(
    source: &HeaderMap,
    credential_header: Option<&str>,
) -> Result<HeaderMap, HttpValidationError> {
    let mut connection_nominated = Vec::new();
    for value in source.get_all(http::header::CONNECTION) {
        let value = value
            .to_str()
            .map_err(|_| HttpValidationError::InvalidHeader("connection".to_string()))?;
        for token in value
            .split(',')
            .map(str::trim)
            .filter(|token| !token.is_empty())
        {
            let name = HeaderName::from_bytes(token.as_bytes())
                .map_err(|_| HttpValidationError::InvalidHeader(token.to_string()))?;
            connection_nominated.push(name);
        }
    }

    let mut forwarded = HeaderMap::new();
    for (name, value) in source.iter() {
        let lower = name.as_str();
        if credential_header.is_some_and(|credential| {
            !credential.eq_ignore_ascii_case("authorization")
                && credential.eq_ignore_ascii_case(lower)
        }) {
            return Err(HttpValidationError::ReservedHeader(lower.to_string()));
        }
        if lower == "authorization"
            || lower == "accept-encoding"
            || DENYLIST.contains(&lower)
            || connection_nominated.iter().any(|n| n == name)
        {
            continue;
        }
        forwarded.append(name.clone(), value.clone());
    }
    Ok(forwarded)
}

/// The rendered credential, applied fresh to every hop.
pub(crate) enum RenderedInjection {
    /// A credential-less connection: nothing is injected onto the request.
    None,
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
            RenderedInjection::None => {}
            RenderedInjection::Header(name, value) => {
                if let Ok(value) = value.to_str() {
                    redactions.add(value);
                    redactions.add(format!("{}: {value}", name.as_str()));
                    // Only the credential, never the auth-scheme word in front
                    // of it. Splitting `Bearer <token>` into components and
                    // adding both made the literal `Bearer` a needle, so every
                    // occurrence in every relayed body and header was rewritten
                    // to `[REDACTED]` — corrupting OpenAPI documents, MCP tool
                    // descriptions, and `WWW-Authenticate: Bearer realm=…`,
                    // none of which contain the secret. The credential is
                    // everything after the scheme word; a value with no space
                    // is itself the credential.
                    let credential = value
                        .split_once(|c: char| c.is_ascii_whitespace())
                        .map(|(_scheme, rest)| rest.trim_start())
                        .unwrap_or(value);
                    redactions.add_component(credential);
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

/// Whether an agent-supplied path resolves to the connection's pinned
/// `mcp_path`.
///
/// Comparing the raw strings is not enough. The upstream URL is built with
/// `Url::join`, which applies WHATWG dot-segment removal, so `/./mcp`,
/// `/a/../mcp`, and `/%2e/mcp` all reach `/mcp` upstream while failing a
/// string compare. Trailing slashes are the same story from the other side:
/// the common HTTP routers serve `/mcp/` and `/mcp` off one handler, so a
/// caller that appends a slash reaches the same upstream MCP endpoint. Every
/// gate asking "is this the MCP leg?" — the curated tool-subset checks on both
/// the broker and direct-endpoint paths, the approval classifier, and the
/// transport-leg probe — has to ask it the way the dial will answer, or a
/// normalizing variant walks straight past.
///
/// Resolution is relative to a fixed opaque base: only the path matters here,
/// and the real dial separately re-checks that the joined URL never left the
/// pinned authority.
pub fn resolves_to_mcp_path(path: &str, mcp_path: &str) -> bool {
    fn resolved(path: &str) -> Option<String> {
        // A path that escapes to another authority (or another scheme) is not
        // the MCP leg whatever it normalizes to; `validate_path` rejects those
        // separately, and returning `None` keeps them out of this comparison.
        let base = Url::parse("http://mcp-path-compare.invalid").ok()?;
        let joined = base.join(path).ok()?;
        (joined.authority() == base.authority() && joined.scheme() == base.scheme())
            .then(|| joined.path().trim_end_matches('/').to_string())
    }
    match (resolved(path), resolved(mcp_path)) {
        (Some(call), Some(pinned)) => call == pinned,
        _ => false,
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
        // `RequestBuilder::timeout` below applies to one redirect hop. Keep
        // a second, outer deadline around the whole upstream operation so a
        // redirect chain, OAuth refresh, or slow response body cannot
        // multiply the advertised timeout. The operation budget exceeds the
        // per-hop budget, so one slow leg cannot starve the rest.
        let outcome =
            match tokio::time::timeout(self.config.upstream_operation_timeout, self.run_inner())
                .await
            {
                Ok(outcome) => outcome,
                Err(_) => broker_error(
                    504,
                    ErrorReason::UpstreamTimeout,
                    "the complete upstream operation exceeded its timeout",
                ),
            };
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
                // A credential that cannot be rendered is conclusive about the
                // connection whatever kind it is: a malformed template, a
                // missing secret, or a failed vault read fails every call, not
                // just this one. Gating this on `oauth` left a plain API
                // connection returning 502 forever while the app showed `Ok`.
                let reason = outcome.body.get("reason").and_then(|r| r.as_str());
                // A refresh the *network* prevented is not conclusive: the
                // credential is probably still good, so this reports a failure
                // to reach the destination rather than telling the user to
                // re-consent a working connection.
                if reason == Some("credential_refresh_unavailable") {
                    let detail = outcome
                        .body
                        .get("detail")
                        .and_then(|d| d.as_str())
                        .unwrap_or("The OAuth token could not be renewed just now");
                    health.record_if_changed(
                        &id,
                        crate::types::HealthStatus::Failed,
                        detail.to_string(),
                    );
                    return;
                }
                let render_failed = reason.is_some_and(|r| {
                    r == "credential_render_failed" || r == "bad_connection_config"
                });
                if render_failed {
                    let oauth = matches!(
                        &self.connection.config,
                        ConnectionConfig::Api { oauth: Some(_), .. }
                    );
                    let fallback = if oauth {
                        "The OAuth token could not be refreshed"
                    } else {
                        "The saved credential could not be prepared for this call"
                    };
                    let detail = outcome
                        .body
                        .get("detail")
                        .and_then(|d| d.as_str())
                        .unwrap_or(fallback);
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
                Err(e) => return broker_error(502, e.reason, e.message),
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
                RenderedInjection::None => {}
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
) -> Result<String, TestError> {
    if !matches!(&connection.config, ConnectionConfig::Api { .. }) {
        return Err("not an api connection".into());
    }
    let (scheme, host, port) = pinned_base(&connection.config).expect("api config");
    let injection = render_connection_injection(store, client, connection)
        .await
        .map_err(|e| TestError::from(e.message))?;
    let mut url =
        Url::parse(&format!("{scheme}://{host}/")).map_err(|e| format!("bad origin: {e}"))?;
    if url.set_port(port).is_err() {
        return Err("cannot set port".into());
    }
    let request = match &injection {
        RenderedInjection::None => client.request(Method::GET, url.clone()),
        RenderedInjection::Header(name, value) => client
            .request(Method::GET, url.clone())
            .header(name.clone(), value.clone()),
        RenderedInjection::Query(fragment) => {
            url.set_query(Some(fragment));
            client.request(Method::GET, url.clone())
        }
    };
    let response = request.timeout(timeout).send().await.map_err(|e| {
        let kind = if e.is_connect() {
            TestErrorKind::Unreachable
        } else if e.is_timeout() {
            TestErrorKind::Timeout
        } else {
            TestErrorKind::Other
        };
        let cause = match kind {
            TestErrorKind::Unreachable => format!("Could not reach {host}"),
            TestErrorKind::Timeout => format!("The server at {host} did not answer in time"),
            _ => format!("The request to {host} failed"),
        };
        // reqwest's Display embeds the URL, which can carry a query-injected
        // credential; strip it exactly as the relay path does.
        TestError::new(kind, format!("{cause}: {}", e.without_url()))
    })?;
    let status = response.status();
    if matches!(status.as_u16(), 401 | 403) {
        return Err(TestError::new(
            TestErrorKind::AuthRejected,
            format!("The server at {host} answered but rejected the credential (HTTP {status})"),
        ));
    }
    Ok(format!("GET {scheme}://{host}/ answered HTTP {status}"))
}

/// The credential for a connection's upstream leg: a fresh OAuth bearer
/// for BYO-app OAuth connections (refreshing on expiry), the rendered
/// injection template otherwise.
/// Why a call's credential could not be produced, carrying the reason the
/// caller should report.
///
/// The distinction matters because health is graded from it: a template that
/// will not render, or a grant the provider has refused, is conclusive about the
/// connection and should show "reconnect". A token endpoint that timed out is
/// not — it used to be reported identically, so a 30-second outage told the user
/// to re-consent a perfectly good connection.
pub(crate) struct CredentialFailure {
    pub message: String,
    pub reason: ErrorReason,
}

impl From<String> for CredentialFailure {
    fn from(message: String) -> Self {
        Self {
            message,
            reason: ErrorReason::CredentialRenderFailed,
        }
    }
}

impl std::fmt::Display for CredentialFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

pub(crate) async fn render_connection_injection(
    store: &Arc<Store>,
    client: &reqwest::Client,
    connection: &Connection,
) -> Result<RenderedInjection, CredentialFailure> {
    let ConnectionConfig::Api {
        template, oauth, ..
    } = &connection.config
    else {
        return Err("not an api connection".to_string().into());
    };
    if oauth.is_some() {
        let token = crate::oauth::fresh_bearer(store, client, connection)
            .await
            .map_err(|failure| CredentialFailure {
                message: failure.message().to_string(),
                reason: if failure.needs_reconnect() {
                    ErrorReason::CredentialRenderFailed
                } else {
                    ErrorReason::CredentialRefreshUnavailable
                },
            })?;
        let mut value = HeaderValue::from_str(&format!("Bearer {}", &*token))
            .map_err(|_| "the stored access token is not a valid header value".to_string())?;
        value.set_sensitive(true);
        return Ok(RenderedInjection::Header(
            HeaderName::from_static("authorization"),
            value,
        ));
    }
    // A template that will not render is conclusive about the connection, which
    // is the `From<String>` default.
    render_injection(store, template).await.map_err(Into::into)
}

pub(crate) async fn render_injection(
    store: &Store,
    template_src: &str,
) -> Result<RenderedInjection, String> {
    // An empty template is a credential-less connection: nothing to render,
    // nothing to inject.
    if template_src.trim().is_empty() {
        return Ok(RenderedInjection::None);
    }
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
    // Preserve Set-Cookie separately for the raw direct-endpoint response:
    // unlike ordinary HTTP fields it cannot be combined with commas. Keep
    // the existing flattened `headers` object for control-plane compatibility.
    let mut set_cookie_headers = Vec::new();
    for (name, value) in response.headers() {
        let value_lossy = String::from_utf8_lossy(value.as_bytes());
        let value_str = redactions.apply_to_string(value_lossy.as_ref());
        if name == http::header::SET_COOKIE {
            set_cookie_headers.push(value_str.clone());
        }
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
            "set_cookie_headers": set_cookie_headers,
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
    uploads: Arc<tokio::sync::Semaphore>,
    /// Per-endpoint request budget. `/v1/http` charges `token_limiter` on every
    /// call; this plane charged nothing, so its only bound was the upload
    /// semaphores — a *concurrency* limit, which a fast serial client never
    /// touches. Same budget as the control plane, so choosing the endpoint is
    /// not a way to escape the rate limit.
    requests: Arc<crate::ratelimit::KeyedLimiter>,
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
/// boundary here, exactly as the PG ticket data plane relies on an
/// unguessable ticket over loopback. Returns the handle and the bound port
/// (persisted so a pasted base URL survives a restart).
pub async fn bind_endpoint(
    broker: Arc<Broker>,
    endpoint: &DirectEndpoint,
) -> std::io::Result<(EndpointListenerHandle, u16)> {
    let requested_port = endpoint.port.unwrap_or(0);
    let listener =
        tokio::net::TcpListener::bind((broker.data_plane_bind(), requested_port)).await?;
    let port = listener.local_addr()?.port();

    let state = Arc::new(HttpEndpointState {
        uploads: Arc::new(tokio::sync::Semaphore::new(
            broker.config.endpoint_uploads_per_listener,
        )),
        requests: Arc::new(crate::ratelimit::KeyedLimiter::new(
            broker.config.per_identity_per_min,
            std::time::Duration::from_secs(60),
        )),
        broker,
        endpoint_id: endpoint.id,
    });
    let app = axum::Router::new()
        .fallback(proxy_handler)
        .with_state(state);
    let shutdown = Arc::new(tokio::sync::Notify::new());
    let sd = shutdown.clone();
    let task = tokio::spawn(async move {
        let served =
            axum::serve(listener, app).with_graceful_shutdown(async move { sd.notified().await });
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
    (
        status,
        axum::Json(json!({ "reason": reason, "detail": detail })),
    )
        .into_response()
}

enum EndpointUploadError {
    TooLarge,
    TimedOut,
    InvalidBody(String),
    Spool(std::io::Error),
}

async fn spool_endpoint_body(
    mut body: axum::body::Body,
    cap: usize,
    spool_threshold: usize,
    total_timeout: std::time::Duration,
    idle_timeout: std::time::Duration,
) -> Result<SpooledBody, EndpointUploadError> {
    let absolute_deadline = tokio::time::Instant::now() + total_timeout;
    let mut spool = BodySpool::new(spool_threshold, cap);
    loop {
        let next = tokio::select! {
            _ = tokio::time::sleep_until(absolute_deadline) => {
                return Err(EndpointUploadError::TimedOut);
            }
            next = tokio::time::timeout(idle_timeout, body.frame()) => {
                next.map_err(|_| EndpointUploadError::TimedOut)?
            }
        };
        let Some(frame) = next else {
            break;
        };
        let frame = frame.map_err(|error| EndpointUploadError::InvalidBody(error.to_string()))?;
        if let Ok(data) = frame.into_data() {
            spool.push(&data).map_err(|error| match error {
                SpoolError::TooLarge => EndpointUploadError::TooLarge,
                SpoolError::Io(error) => EndpointUploadError::Spool(error),
            })?;
        }
    }
    spool.finish().map_err(|error| match error {
        SpoolError::TooLarge => EndpointUploadError::TooLarge,
        SpoolError::Io(error) => EndpointUploadError::Spool(error),
    })
}

async fn proxy_handler(
    axum::extract::State(state): axum::extract::State<Arc<HttpEndpointState>>,
    req: axum::extract::Request,
) -> axum::response::Response {
    use axum::http::StatusCode;
    let broker = &state.broker;
    let (parts, body) = req.into_parts();
    // An incoming body's exact zero size hint is authoritative. Unknown-size
    // bodies (including chunked/HTTP2 uploads without Content-Length) must
    // not inherit an empty MCP transport-leg exemption.
    let body_is_definitely_empty = body.size_hint().exact() == Some(0);

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

    // Charged after authentication, so an unauthenticated prober cannot spend a
    // legitimate holder's budget, and keyed on the endpoint so one endpoint
    // cannot starve another.
    if let Err(retry_after) = state.requests.check(&endpoint.id.to_string()) {
        let mut response = endpoint_error(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            &format!(
                "this endpoint's budget is {} requests per minute",
                broker.config.per_identity_per_min
            ),
        );
        // Machine-actionable in the header as well as the body, matching the
        // control plane's contract.
        if let Ok(value) = http::HeaderValue::from_str(&retry_after.as_secs().max(1).to_string()) {
            response.headers_mut().insert("retry-after", value);
        }
        return response;
    }

    // Authorization is enforced here, on every request, at connect time.
    if !broker.access.allows(&endpoint.connection_id) {
        return endpoint_error(
            StatusCode::FORBIDDEN,
            "denied_by_policy",
            "agent access is disabled for this tool",
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

    // The endpoint is a base URL, not a forward proxy. A proxy-style request
    // line carries the authority the client wants, and reading only the path
    // out of it silently rewrote the request onto the pinned host — so setting
    // `HTTP_PROXY` to this endpoint sent *every* host's traffic here with the
    // real credential injected. `CONNECT host:443` has no path at all and
    // would have been serviced as `/`.
    if parts.method == Method::CONNECT {
        return endpoint_error(
            StatusCode::BAD_REQUEST,
            "wrong_connection_type",
            "this endpoint is a base URL for one pinned host, not a forward \
             proxy; CONNECT is not served. Point your client's base URL at it \
             instead of its proxy setting.",
        );
    }
    if parts.uri.authority().is_some() {
        return endpoint_error(
            StatusCode::BAD_REQUEST,
            "invalid_path",
            "this endpoint is a base URL for one pinned host, not a forward \
             proxy; send an origin-form request (a path) rather than an \
             absolute URL.",
        );
    }
    // One allow-list for both planes: the control plane already refused
    // anything outside it, while the endpoint forwarded TRACE, PROPFIND and
    // PURGE to the pinned upstream with the credential attached.
    let Ok(method) = parse_method(parts.method.as_str()) else {
        return endpoint_error(
            StatusCode::BAD_REQUEST,
            "invalid_method",
            "unsupported method: use GET, HEAD, POST, PUT, PATCH, DELETE or \
             OPTIONS",
        );
    };
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

    // Curated MCP subsets are enforced by `/v1/http` while its JSON body is
    // in memory. A direct endpoint deliberately gates before body upload and
    // spools large bodies to disk, so it cannot safely inspect a tool call
    // without defeating that memory boundary. Fail closed on the pinned MCP
    // path; callers that need curation use the broker/sidecar path. Generic
    // API paths on the same connection remain available.
    let on_mcp_path = match &connection.config {
        ConnectionConfig::Api {
            mcp_path: Some(mcp_path),
            ..
        } => resolves_to_mcp_path(&path, mcp_path),
        _ => false,
    };
    let allowed_tools_snapshot = broker.access.allowed_tools(&endpoint.connection_id);
    if on_mcp_path && allowed_tools_snapshot.is_some() {
        return endpoint_error(
            StatusCode::FORBIDDEN,
            "denied_by_policy",
            "curated MCP tools must be called through the broker or MCP sidecar, not the direct HTTP endpoint",
        );
    }

    // The endpoint Authorization value authenticates only this listener. The
    // configured upstream credential header is broker-controlled as well,
    // including custom header templates such as X-Api-Key.
    let credential_header = connection_credential_header(&connection);
    let headers = match endpoint_forward_headers(&parts.headers, credential_header.as_deref()) {
        Ok(headers) => headers,
        Err(error) => {
            let reason = match &error {
                HttpValidationError::ReservedHeader(_) => "reserved_header",
                HttpValidationError::InvalidHeader(_) => "invalid_header",
                HttpValidationError::InvalidMethod | HttpValidationError::InvalidPath => {
                    "invalid_header"
                }
            };
            return endpoint_error(StatusCode::BAD_REQUEST, reason, &error.detail());
        }
    };

    // Confirm traffic before admitting the upload, except for exact empty
    // MCP transport setup/teardown legs. Parking here rather than after the
    // body means a prompt the user leaves sitting cannot hold this listener's
    // upload budget hostage — at the cost of a preview in the prompt, which
    // is the right trade for a stable endpoint that any tool may be pointed at.
    let confirmation_enabled = broker.access.confirm_mode(&endpoint.connection_id).is_on();
    let mcp_transport_leg = is_mcp_transport_leg(
        &connection,
        &method,
        &path,
        &parts.headers,
        body_is_definitely_empty,
    );
    let policy_version = confirmation_enabled.then_some(connection.updated_at);
    let confirmed_version = if confirmation_enabled && !mcp_transport_leg {
        let version = connection.updated_at;
        let verdict = broker
            .approvals
            .gate(crate::approvals::ApprovalRequest::new(
                &connection,
                "endpoint",
                format!("{method} {}", crate::approvals::capped_text(&path)),
            ))
            .await;
        if !verdict.is_allowed() {
            let status = match verdict {
                crate::approvals::Verdict::TimedOut => StatusCode::REQUEST_TIMEOUT,
                _ => StatusCode::FORBIDDEN,
            };
            let reason = verdict
                .reason()
                .unwrap_or(crate::wire::ErrorReason::ApprovalDenied);
            return endpoint_error(status, reason.as_str(), verdict.detail());
        }
        Some(version)
    } else {
        None
    };

    // A revoke, disable, or connection edit can race with either prompt
    // insertion or the transport exemption check. Revalidate immediately,
    // and close any window a stale prompt might just have opened.
    if let Some(expected_version) = policy_version.as_ref() {
        let endpoint_still_valid = broker
            .endpoints
            .resolve_secret(presented)
            .is_some_and(|current| current.id == endpoint.id);
        let connection_is_current = broker
            .store
            .connection_by_id(&endpoint.connection_id)
            .is_ok_and(|current| current.updated_at == *expected_version);
        if !endpoint_still_valid
            || !broker.access.allows(&endpoint.connection_id)
            || !connection_is_current
            || broker.access.allowed_tools(&endpoint.connection_id) != allowed_tools_snapshot
        {
            if confirmed_version.is_some() {
                broker.approvals.revoke(&endpoint.connection_id);
            }
            return endpoint_error(
                StatusCode::FORBIDDEN,
                "denied_by_policy",
                "the endpoint or connection changed while the request was being admitted",
            );
        }
    }

    // Admit the upload before reading even its first body frame. A malicious
    // holder of a valid endpoint secret can therefore occupy only the fixed
    // per-listener and broker-wide budgets.
    let _global_upload = match broker.endpoint_uploads.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            return endpoint_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "endpoint_busy",
                "the broker's direct-endpoint upload limit has been reached",
            )
        }
    };
    let _listener_upload = match state.uploads.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            return endpoint_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "endpoint_busy",
                "this direct endpoint's upload limit has been reached",
            )
        }
    };

    // Register before receiving the body so endpoint revocation can interrupt
    // an upload rather than waiting for its deadline.
    let session = match broker.data_plane.start_endpoint_session(
        "endpoint",
        &connection,
        endpoint.id,
        ConnectionKind::Api,
    ) {
        Ok(session) => session,
        Err(_) => {
            return endpoint_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "broker_session_limit",
                "the broker's live-session limit has been reached",
            )
        }
    };
    let endpoint_still_valid = broker
        .endpoints
        .resolve_secret(presented)
        .is_some_and(|current| current.id == endpoint.id);
    if !endpoint_still_valid || !broker.access.allows(&endpoint.connection_id) {
        if confirmed_version.is_some() {
            broker.approvals.revoke(&endpoint.connection_id);
        }
        session.finish("access_revoked");
        return endpoint_error(
            StatusCode::FORBIDDEN,
            "denied_by_policy",
            "the endpoint was revoked or agent access was disabled",
        );
    }

    let close_signal = session.close_signal.clone();
    let upload = tokio::select! {
        _ = close_signal.notified() => {
            session.finish("access_revoked");
            return endpoint_error(
                StatusCode::FORBIDDEN,
                "denied_by_policy",
                "the endpoint was revoked or agent access was disabled",
            );
        }
        upload = spool_endpoint_body(
            body,
            broker.config.request_cap,
            broker.config.spool_threshold,
            broker.config.endpoint_upload_timeout,
            broker.config.endpoint_upload_idle_timeout,
        ) => upload,
    };
    let spooled = match upload {
        Ok(body) => Arc::new(body),
        Err(EndpointUploadError::TooLarge) => {
            session.finish("request_too_large");
            return endpoint_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "request_too_large",
                "the request body exceeds the configured cap",
            );
        }
        Err(EndpointUploadError::TimedOut) => {
            session.finish("upload_timeout");
            return endpoint_error(
                StatusCode::REQUEST_TIMEOUT,
                "upload_timeout",
                "the request body upload exceeded its time limit",
            );
        }
        Err(EndpointUploadError::InvalidBody(detail)) => {
            session.finish("invalid_request_body");
            return endpoint_error(StatusCode::BAD_REQUEST, "invalid_body", &detail);
        }
        Err(EndpointUploadError::Spool(error)) => {
            session.finish("spool_failed");
            return endpoint_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "spool_failed",
                &error.to_string(),
            );
        }
    };

    // Receiving a request body can take arbitrarily long. Reauthenticate and
    // re-check access immediately before dispatch so a disable, revoke, or
    // secret rotation that landed during the upload wins.
    let Some(endpoint) = broker
        .endpoints
        .resolve_secret(presented)
        .filter(|endpoint| endpoint.id == state.endpoint_id)
    else {
        if confirmed_version.is_some() {
            broker.approvals.revoke(&connection.id);
        }
        session.finish("access_revoked");
        return endpoint_error(
            StatusCode::UNAUTHORIZED,
            "invalid_secret",
            "the endpoint was revoked or its secret was rotated",
        );
    };
    if !broker.access.allows(&endpoint.connection_id) {
        if confirmed_version.is_some() {
            broker.approvals.revoke(&endpoint.connection_id);
        }
        session.finish("access_revoked");
        return endpoint_error(
            StatusCode::FORBIDDEN,
            "denied_by_policy",
            "agent access is disabled for this tool",
        );
    }
    let Ok(connection) = broker.store.connection_by_id(&endpoint.connection_id) else {
        if confirmed_version.is_some() {
            broker.approvals.revoke(&endpoint.connection_id);
        }
        session.finish("connection_removed");
        return endpoint_error(
            StatusCode::BAD_GATEWAY,
            "unknown_connection",
            "the connection has been removed",
        );
    };
    if connection.kind() != ConnectionKind::Api {
        if confirmed_version.is_some() {
            broker.approvals.revoke(&endpoint.connection_id);
        }
        session.finish("connection_changed");
        return endpoint_error(
            StatusCode::BAD_GATEWAY,
            "wrong_connection_type",
            "the connection is no longer an HTTP tool",
        );
    }
    let current_on_mcp_path = match &connection.config {
        ConnectionConfig::Api {
            mcp_path: Some(mcp_path),
            ..
        } => resolves_to_mcp_path(&path, mcp_path),
        _ => false,
    };
    if current_on_mcp_path
        && broker
            .access
            .allowed_tools(&endpoint.connection_id)
            .is_some()
    {
        if confirmed_version.is_some() {
            broker.approvals.revoke(&endpoint.connection_id);
        }
        session.finish("denied_by_policy");
        return endpoint_error(
            StatusCode::FORBIDDEN,
            "denied_by_policy",
            "curated MCP tools must be called through the broker or MCP sidecar, not the direct HTTP endpoint",
        );
    }
    if policy_version
        .as_ref()
        .is_some_and(|expected| connection.updated_at != *expected)
    {
        if confirmed_version.is_some() {
            broker.approvals.revoke(&endpoint.connection_id);
        }
        session.finish("connection_changed");
        return endpoint_error(
            StatusCode::FORBIDDEN,
            "denied_by_policy",
            "the connection changed after request policy was checked",
        );
    }

    // The session was registered before upload. Re-check once more after
    // resolving current connection state to close races with rotation.
    let endpoint_still_valid = broker
        .endpoints
        .resolve_secret(presented)
        .is_some_and(|current| current.id == endpoint.id);
    if !endpoint_still_valid || !broker.access.allows(&endpoint.connection_id) {
        if confirmed_version.is_some() {
            broker.approvals.revoke(&endpoint.connection_id);
        }
        session.finish("access_revoked");
        return endpoint_error(
            StatusCode::FORBIDDEN,
            "denied_by_policy",
            "the endpoint was revoked or agent access was disabled",
        );
    }

    // Reuse `/v1/http`'s whole execution core. The wiring is the
    // authorization, so the vault read is pre-authorized (scope confirmed).
    let execution = HttpExecution {
        store: broker.store.clone(),
        audit: broker.audit.clone(),
        client: broker.http_client.clone(),
        config: broker.config.clone(),
        agent: "endpoint".to_string(),
        connection,
        method,
        path,
        headers,
        body: spooled,
        health: Some(broker.health.clone()),
    };
    let outcome = tokio::select! {
        _ = close_signal.notified() => {
            session.finish("access_revoked");
            return endpoint_error(
                StatusCode::FORBIDDEN,
                "denied_by_policy",
                "the endpoint was revoked or agent access was disabled",
            );
        }
        outcome = crate::authorization::scope(true, execution.run()) => outcome,
    };
    session.finish("request_complete");
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
                "content-length" | "transfer-encoding" | "connection" | "set-cookie"
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
    if let Some(cookies) = env.get("set_cookie_headers").and_then(|h| h.as_array()) {
        for cookie in cookies.iter().filter_map(|cookie| cookie.as_str()) {
            if let Ok(value) = HeaderValue::from_str(cookie) {
                response = response.header(http::header::SET_COOKIE, value);
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

    #[tokio::test]
    async fn endpoint_upload_stream_enforces_cap_while_spooling() {
        let body = axum::body::Body::from(vec![7_u8; 9]);
        let result = spool_endpoint_body(
            body,
            8,
            2,
            std::time::Duration::from_secs(1),
            std::time::Duration::from_secs(1),
        )
        .await;
        assert!(matches!(result, Err(EndpointUploadError::TooLarge)));
    }

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
    fn direct_headers_cannot_shadow_custom_credentials() {
        let mut source = HeaderMap::new();
        source.insert("authorization", HeaderValue::from_static("Bearer endpoint"));
        source.insert("x-api-key", HeaderValue::from_static("attacker"));
        assert!(matches!(
            endpoint_forward_headers(&source, Some("X-Api-Key")).unwrap_err(),
            HttpValidationError::ReservedHeader(_)
        ));
    }

    #[test]
    fn direct_headers_strip_connection_nominated_fields() {
        let mut source = HeaderMap::new();
        source.insert("authorization", HeaderValue::from_static("Bearer endpoint"));
        source.insert(
            "connection",
            HeaderValue::from_static("x-remove, keep-alive"),
        );
        source.insert("x-remove", HeaderValue::from_static("private"));
        source.insert("x-keep", HeaderValue::from_static("public"));
        let forwarded = endpoint_forward_headers(&source, Some("Authorization")).unwrap();
        assert!(!forwarded.contains_key("authorization"));
        assert!(!forwarded.contains_key("x-remove"));
        assert_eq!(forwarded["x-keep"], "public");
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
    fn credential_less_injection_redacts_nothing() {
        let redactions = Redactions::from_injection(&RenderedInjection::None);
        // Nothing was injected, so nothing is scrubbed from the response.
        assert_eq!(
            redactions.apply_to_string("plain upstream body"),
            "plain upstream body"
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
    fn direct_response_preserves_each_set_cookie_field() {
        let response = translate_outcome(ExecOutcome {
            status: 200,
            body: json!({
                "status": 200,
                "headers": {
                    "content-type": "text/plain",
                    "set-cookie": "session=one, csrf=two",
                },
                "set_cookie_headers": [
                    "session=one; Path=/; HttpOnly",
                    "csrf=two; Path=/; Secure",
                ],
                "body": "ok",
                "body_encoding": "utf8",
            }),
        });

        let cookies: Vec<&str> = response
            .headers()
            .get_all(http::header::SET_COOKIE)
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect();
        assert_eq!(
            cookies,
            vec!["session=one; Path=/; HttpOnly", "csrf=two; Path=/; Secure"]
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

    /// The upstream URL is built with `Url::join`, so a normalizing variant
    /// reaches the pinned MCP path even though it is a different string. The
    /// curated-subset gate must see those as the MCP leg or it is bypassable.
    #[test]
    fn dot_segment_variants_resolve_to_the_pinned_mcp_path() {
        for path in [
            "/mcp",
            "/./mcp",
            "/a/../mcp",
            "/%2e/mcp",
            "/a/b/../../mcp",
            "/mcp?session=1",
        ] {
            assert!(
                resolves_to_mcp_path(path, "/mcp"),
                "{path} reaches /mcp upstream and must be treated as the MCP leg"
            );
        }
    }

    #[test]
    fn unrelated_or_escaping_paths_are_not_the_mcp_leg() {
        for path in [
            "/mcpx",
            "/mcp/extra",
            "/other",
            "/",
            "//evil.example.com/mcp",
            "http://evil.example.com/mcp",
        ] {
            assert!(
                !resolves_to_mcp_path(path, "/mcp"),
                "{path} must not be treated as the MCP leg"
            );
        }
    }

    /// A pinned path that itself needs normalizing still matches.
    #[test]
    fn the_pinned_path_is_normalized_too() {
        assert!(resolves_to_mcp_path("/mcp", "/./mcp"));
        assert!(resolves_to_mcp_path("/api/mcp", "/api/./mcp"));
    }

    /// The common HTTP routers serve `/mcp/` and `/mcp` off one handler, so a
    /// trailing slash reaches the same upstream endpoint. Treating the two as
    /// different paths would leave a one-character bypass of the curated gate.
    #[test]
    fn a_trailing_slash_is_still_the_mcp_leg() {
        for (path, pinned) in [
            ("/mcp/", "/mcp"),
            ("/mcp", "/mcp/"),
            ("/mcp///", "/mcp"),
            ("/./mcp/", "/mcp"),
            ("/api/mcp/", "/api/mcp"),
        ] {
            assert!(
                resolves_to_mcp_path(path, pinned),
                "{path} reaches {pinned} upstream and must be treated as the MCP leg"
            );
        }
        // Normalizing the slash must not start collapsing distinct paths.
        assert!(!resolves_to_mcp_path("/mcp/extra/", "/mcp"));
        assert!(!resolves_to_mcp_path("/mcpx/", "/mcp"));
    }
}
