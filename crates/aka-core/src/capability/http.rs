//! HTTP capability, `POST /v1/http`.
//!
//! Host-pinning is only as good as the URL assembly, so agent input is
//! validated, not trusted: paths must begin with exactly one `/`, the
//! upstream URL is built from parsed components, a broker-controlled header
//! denylist is non-overridable, and redirects are followed by a hand-rolled
//! loop only when the resolved hop matches the connection's pinned
//! scheme/host/port, re-applying the one freshly rendered injection to every
//! permitted hop.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;

use axum::body::HttpBody as _;
use http::{HeaderMap, HeaderName, HeaderValue, Method};
use http_body_util::BodyExt as _;
use percent_encoding::percent_decode_str;
use serde_json::{json, Value};
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

/// The direct endpoint's idempotency key, carrying `/v1/http`'s `request_id`
/// on a plane that has no JSON envelope to put it in.
///
/// Deliberately not `Idempotency-Key`: that name belongs to the upstreams
/// (Stripe and friends define their own semantics for it), and a broker that
/// swallowed it would silently disable the vendor's own retry safety. A
/// broker-namespaced header is unambiguous and is stripped before the upstream
/// leg, like every other piece of broker plumbing.
pub const ENDPOINT_REQUEST_ID_HEADER: &str = "x-agentmfa-request-id";

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
            || lower == ENDPOINT_REQUEST_ID_HEADER
            || DENYLIST.contains(&lower)
            || connection_nominated.iter().any(|n| n == name)
        {
            continue;
        }
        forwarded.append(name.clone(), value.clone());
    }
    Ok(forwarded)
}

/// The rendered credential, re-applied to every permitted redirect hop.
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
pub(crate) struct Redactions {
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
                    // Multi-token credentials (AWS SigV4, Digest) can reflect
                    // in parts, so each post-scheme component is its own
                    // needle too — the scheme word stays excluded either way.
                    for part in credential.split_ascii_whitespace() {
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

    /// The longest needle, which is how much tail a streaming relay has to
    /// hold back: a credential split across two chunks is only recognizable
    /// once the bytes on both sides of the boundary are in hand.
    fn max_needle_len(&self) -> usize {
        self.needles
            .iter()
            .map(|needle| needle.len())
            .max()
            .unwrap_or(0)
    }

    /// Redact everything that can be decided from `buf` alone, returning the
    /// scrubbed prefix and the tail that must wait for more bytes.
    ///
    /// A match is taken wherever one fits. Anything short of `max_needle_len`
    /// from the end is deferred instead of emitted, because a needle could
    /// still start there and complete in the next chunk — which is exactly the
    /// case a naive per-chunk `apply_to_bytes` would leak.
    fn split_redacted(&self, buf: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let hold = self.max_needle_len().saturating_sub(1);
        if hold == 0 {
            return (buf.to_vec(), Vec::new());
        }
        let undecided_from = buf.len().saturating_sub(hold);
        let mut out = Vec::with_capacity(buf.len());
        let mut i = 0usize;
        while i < buf.len() {
            if let Some(needle) = self
                .needles
                .iter()
                .find(|needle| !needle.is_empty() && buf[i..].starts_with(needle.as_bytes()))
            {
                out.extend_from_slice(b"[REDACTED]");
                i += needle.len();
                continue;
            }
            if i >= undecided_from {
                break;
            }
            out.push(buf[i]);
            i += 1;
        }
        (out, buf[i..].to_vec())
    }
}

/// Why a streamed response stopped producing bytes.
pub(crate) enum StreamFinish {
    Complete,
    UpstreamError(String),
    ConsumerDropped,
}

/// Forward an upstream body chunk by chunk, scrubbing reflected credentials
/// across chunk boundaries, and report the byte total when the stream ends.
///
/// The buffered relay can scan a whole body at once; a streaming one cannot,
/// so it carries the boundary tail forward. `on_finish` runs exactly once,
/// whether the stream completed, failed, or the client hung up mid-transfer —
/// a session the broker opened must be retired either way.
pub(crate) fn redacting_stream(
    response: reqwest::Response,
    redactions: Redactions,
    on_finish: impl FnOnce(u64, StreamFinish) + Send + 'static,
) -> impl futures::Stream<Item = Result<bytes::Bytes, std::io::Error>> + Send {
    use futures::StreamExt as _;

    struct Finish<F: FnOnce(u64, StreamFinish)> {
        callback: Option<F>,
        bytes: u64,
        reason: StreamFinish,
    }
    impl<F: FnOnce(u64, StreamFinish)> Finish<F> {
        /// Counted through a method rather than by touching the field: a
        /// closure that only names `finish.bytes` captures that field alone,
        /// leaving the guard itself to drop here — firing the callback (and
        /// retiring the session) before a single byte has been forwarded.
        fn count(&mut self, bytes: usize) {
            self.bytes = self.bytes.saturating_add(bytes as u64);
        }
    }
    impl<F: FnOnce(u64, StreamFinish)> Drop for Finish<F> {
        fn drop(&mut self) {
            if let Some(callback) = self.callback.take() {
                callback(
                    self.bytes,
                    std::mem::replace(&mut self.reason, StreamFinish::ConsumerDropped),
                );
            }
        }
    }

    let mut upstream = response.bytes_stream();
    let mut carry: Vec<u8> = Vec::new();
    let mut finish = Finish {
        callback: Some(on_finish),
        bytes: 0,
        reason: StreamFinish::ConsumerDropped,
    };
    futures::stream::poll_fn(move |cx| {
        loop {
            match futures::ready!(upstream.poll_next_unpin(cx)) {
                Some(Ok(chunk)) => {
                    finish.count(chunk.len());
                    carry.extend_from_slice(&chunk);
                    let (emit, held) = redactions.split_redacted(&carry);
                    carry = held;
                    if emit.is_empty() {
                        // Everything so far could still be the head of a
                        // credential; ask the upstream for more rather than
                        // emitting a chunk that might complete one.
                        continue;
                    }
                    return std::task::Poll::Ready(Some(Ok(bytes::Bytes::from(emit))));
                }
                Some(Err(error)) => {
                    // The URL is stripped for the same reason the buffered
                    // path strips it: a query-form credential lives in it.
                    let detail = error.without_url().to_string();
                    finish.reason = StreamFinish::UpstreamError(detail.clone());
                    return std::task::Poll::Ready(Some(Err(std::io::Error::other(detail))));
                }
                None => {
                    if carry.is_empty() {
                        finish.reason = StreamFinish::Complete;
                        return std::task::Poll::Ready(None);
                    }
                    // End of stream: nothing more can complete a needle, so
                    // the held tail is scrubbed on its own terms and flushed.
                    let tail = redactions.apply_to_bytes(&std::mem::take(&mut carry));
                    return std::task::Poll::Ready(Some(Ok(bytes::Bytes::from(tail))));
                }
            }
        }
    })
}

/// Everything the executor needs, captured at submission time, the
/// connection is snapshotted so a concurrent edit can't repoint what the
/// user approved.
pub struct HttpExecution {
    pub store: Arc<Store>,
    pub access: Arc<crate::policy::AccessTable>,
    pub audit: Arc<AuditLog>,
    pub client: reqwest::Client,
    pub config: BrokerConfig,
    pub agent: String,
    pub connection: Connection,
    pub method: Method,
    pub path: String,
    pub headers: HeaderMap,
    pub body: Arc<SpooledBody>,
    /// When present, upstream responses and broker-side failures update the
    /// connection's last-known health.
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

/// Whether one parsed HTTP body is an MCP client request (or batch) that was
/// rejected before authentication. Merely aiming arbitrary JSON at the MCP
/// path is not enough to opt a mutating HTTP call into automatic replay.
fn is_mcp_client_message(value: &Value) -> bool {
    let request = |message: &Value| {
        message.get("jsonrpc").and_then(Value::as_str) == Some("2.0")
            && message.get("method").and_then(Value::as_str).is_some()
    };
    match value {
        Value::Array(messages) => !messages.is_empty() && messages.iter().all(request),
        message => request(message),
    }
}

fn same_pinned_authority(url: &Url, scheme: &str, host: &str, port: Option<u16>) -> bool {
    let pinned_port = port.unwrap_or(match scheme {
        "https" => 443,
        _ => 80,
    });
    let same_host = url
        .host_str()
        .is_some_and(|candidate| candidate.eq_ignore_ascii_case(host));
    let same_scheme_and_port =
        url.scheme() == scheme && url.port_or_known_default() == Some(pinned_port);
    // A pinned plaintext origin may upgrade to the same host's standard TLS
    // origin. The inverse is never accepted, nor is an upgrade to an
    // arbitrary port.
    let safe_upgrade =
        scheme == "http" && url.scheme() == "https" && url.port_or_known_default() == Some(443);
    same_host && (same_scheme_and_port || safe_upgrade)
}

pub(crate) fn client_for_connection(
    default: &reqwest::Client,
    connection: &Connection,
) -> Result<reqwest::Client, String> {
    let ConnectionConfig::Api {
        trusted_ca_bundle_path,
        ..
    } = &connection.config
    else {
        return Ok(default.clone());
    };
    let Some(tls) = trusted_ca_tls_config(trusted_ca_bundle_path.as_deref())? else {
        return Ok(default.clone());
    };
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .use_preconfigured_tls(tls)
        .build()
        .map_err(|error| format!("trusted CA client could not be built: {error}"))
}

pub(crate) fn trusted_ca_tls_config(
    path: Option<&str>,
) -> Result<Option<rustls::ClientConfig>, String> {
    let Some(path) = path.filter(|path| !path.trim().is_empty()) else {
        return Ok(None);
    };
    // Match Postgres' `sslrootcert` semantics: a configured private bundle
    // replaces public roots, rather than widening trust to both sets.
    let roots = crate::capability::pg::root_cert_store(Some(path))?;
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|error| format!("trusted CA TLS configuration failed: {error}"))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(Some(tls))
}

fn test_request_error(error: reqwest::Error, host: &str) -> TestError {
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(&error);
    let mut tls = false;
    let mut cert = false;
    while let Some(current) = source {
        if let Some(rustls) = current.downcast_ref::<rustls::Error>() {
            tls = true;
            cert |= matches!(rustls, rustls::Error::InvalidCertificate(_));
        }
        source = current.source();
    }
    // hyper-util's connector error does not expose its nested rustls error
    // through `source()` on every version. Its Debug chain still retains the
    // typed variant. Sniff only the *source* chain's Debug, never the
    // top-level `reqwest::Error`: that one embeds the request URL, so a host,
    // path, or query-injected credential containing "rustls" or "tls
    // handshake" would misclassify a plain timeout or connection refusal as a
    // TLS/cert failure. The source errors carry the variant, not the URL.
    if !tls {
        let mut debug = String::new();
        let mut current = (&error as &(dyn std::error::Error + 'static)).source();
        while let Some(src) = current {
            debug.push_str(&format!("{src:?} ").to_ascii_lowercase());
            current = src.source();
        }
        cert = debug.contains("invalidcertificate")
            || debug.contains("invalid peer certificate")
            || debug.contains("certificateunknown");
        tls = cert || debug.contains("rustls") || debug.contains("tls handshake");
    }
    let kind = if cert {
        TestErrorKind::CertUnverified
    } else if tls {
        TestErrorKind::TlsDeclined
    } else if error.is_timeout() {
        TestErrorKind::Timeout
    } else if error.is_connect() {
        TestErrorKind::Unreachable
    } else {
        TestErrorKind::Other
    };
    let cause = match kind {
        TestErrorKind::CertUnverified => {
            format!("The certificate presented by {host} could not be verified")
        }
        TestErrorKind::TlsDeclined => format!("The server at {host} did not complete TLS"),
        TestErrorKind::Unreachable => format!("Could not reach {host}"),
        TestErrorKind::Timeout => format!("The server at {host} did not answer in time"),
        _ => format!("The request to {host} failed"),
    };
    TestError::new(kind, format!("{cause}: {}", error.without_url()))
}

fn broker_error(status: u16, reason: ErrorReason, detail: impl Into<String>) -> ExecOutcome {
    ExecOutcome {
        status,
        body: json!({ "reason": reason, "detail": detail.into() }),
    }
}

/// Grade a response while its authentication challenge is still visible.
/// A business/policy 403 is proof of reachability, not proof that the
/// connection's credential died.
fn record_relayed_health(
    health: &crate::health::HealthRegistry,
    id: &Uuid,
    status: u16,
    auth_challenge: bool,
) {
    if status == 401 || (status == 403 && auth_challenge) {
        health.record_credential_rejection(
            id,
            format!("The destination answered but rejected the credential (HTTP {status})"),
        );
    } else {
        health.record_ok_if_changed(id, "A brokered call reached the destination");
    }
}

fn record_upstream_failure_health(
    health: &crate::health::HealthRegistry,
    id: &Uuid,
    detail: impl Into<String>,
) {
    health.record_if_changed(id, crate::types::HealthStatus::Failed, detail.into());
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
        self.record_broker_failure_health(&outcome);
        let mut audit = AuditEntry::new(
            AuditKind::HttpExecuted,
            format!("{} {} via {}", self.method, self.path, self.connection.name),
        )
        .agent(self.agent.clone())
        .connection(self.connection.name.clone())
        .outcome(upstream_status)
        .duration_ms(started.elapsed().as_millis() as u64)
        .field("method", self.method.to_string())
        .field("path", self.path.clone());
        if let ConnectionConfig::Api {
            mcp_path: Some(mcp_path),
            ..
        } = &self.connection.config
        {
            if resolves_to_mcp_path(&self.path, mcp_path) {
                if let Some(method) = self
                    .headers
                    .get("mcp-method")
                    .and_then(|value| value.to_str().ok())
                {
                    audit = audit.field("mcp_method", method);
                }
                if let Some(name) = self
                    .headers
                    .get("mcp-name")
                    .and_then(|value| value.to_str().ok())
                {
                    audit = audit.field("mcp_name", name);
                }
            }
        }
        self.audit.append(audit);
        outcome
    }

    /// Grade broker-side failures that never produced a usable upstream
    /// status. Relayed statuses are graded before response headers are
    /// contained, so a 403 can still be qualified by `WWW-Authenticate`.
    fn record_broker_failure_health(&self, outcome: &ExecOutcome) {
        let Some(health) = &self.health else { return };
        let id = self.connection.id;
        let reason = outcome.body.get("reason").and_then(|r| r.as_str());
        let detail = || outcome.body.get("detail").and_then(|d| d.as_str());
        if reason == Some("credential_refresh_unavailable") {
            health.record_if_changed(
                &id,
                crate::types::HealthStatus::Failed,
                detail()
                    .unwrap_or("The OAuth token could not be renewed just now")
                    .to_string(),
            );
            return;
        }
        if matches!(reason, Some("upstream_error" | "upstream_timeout")) {
            record_upstream_failure_health(
                health,
                &id,
                detail().unwrap_or("The destination could not be reached"),
            );
            return;
        }
        if matches!(
            reason,
            Some("credential_render_failed" | "bad_connection_config")
        ) {
            let oauth = matches!(
                &self.connection.config,
                ConnectionConfig::Api { oauth: Some(_), .. }
            );
            let fallback = if oauth {
                "The OAuth token could not be refreshed"
            } else {
                "The saved credential could not be prepared for this call"
            };
            health.record_if_changed(
                &id,
                crate::types::HealthStatus::NeedsReconnect,
                detail().unwrap_or(fallback).to_string(),
            );
        }
    }

    async fn run_inner(&self) -> ExecOutcome {
        let dialed = match self.dial(self.config.upstream_timeout).await {
            Ok(dialed) => dialed,
            Err(outcome) => return outcome,
        };
        if let Some(health) = &self.health {
            record_relayed_health(
                health,
                &self.connection.id,
                dialed.response.status().as_u16(),
                dialed
                    .response
                    .headers()
                    .contains_key(http::header::WWW_AUTHENTICATE),
            );
        }
        relay_response(
            dialed.response,
            &self.config,
            &dialed.redactions,
            self.access.expose_response_credentials(&self.connection.id),
            dialed.mcp_response_id.as_ref(),
            dialed.mcp_tool_call_id.as_ref(),
        )
        .await
    }

    /// Perform the approved request and report it as it happens, instead of
    /// as one object once it is over.
    ///
    /// Returns an `ExecOutcome` like the buffered path so the shared policy
    /// wrappers can refuse it in the same shape — but a call that reached the
    /// upstream has already answered through the sink by then, and the
    /// returned outcome is only a record of how it went.
    ///
    /// The response cap does not apply: it exists because the JSON envelope
    /// must hold the whole body, and this path never does. That is the point —
    /// a large artifact is a transfer here rather than a 502.
    pub(crate) async fn run_streamed(self, sink: StreamSink) -> ExecOutcome {
        let started = Instant::now();
        let (response, redactions) = match self.dial_for_streaming().await {
            Ok(dialed) => dialed,
            Err(outcome) => {
                self.record_broker_failure_health(&outcome);
                self.audit_streamed(started, &outcome_status_label(&outcome), None);
                return outcome;
            }
        };
        let status = response.status().as_u16();
        let auth_challenge = response
            .headers()
            .contains_key(http::header::WWW_AUTHENTICATE);
        let expose_response_credentials =
            self.access.expose_response_credentials(&self.connection.id);
        let mut headers = serde_json::Map::new();
        for (name, value) in response.headers() {
            if !response_header_is_relayable(name, expose_response_credentials) {
                continue;
            }
            let scrubbed = redactions.apply_to_string(&String::from_utf8_lossy(value.as_bytes()));
            match headers.get_mut(name.as_str()) {
                Some(Value::String(existing)) => *existing = format!("{existing}, {scrubbed}"),
                _ => {
                    headers.insert(name.as_str().to_string(), json!(scrubbed));
                }
            }
        }
        if let Some(health) = &self.health {
            record_relayed_health(health, &self.connection.id, status, auth_challenge);
        }
        // Committing the head is what makes every later failure a truncation
        // rather than a refusal, so it is set before the first chunk can race
        // the executor's own error path.
        sink.began.store(true, std::sync::atomic::Ordering::SeqCst);
        sink.send(StreamEvent::Head {
            status,
            headers: Value::Object(headers),
        })
        .await;

        let mut body = std::pin::pin!(redacting_stream(response, redactions, |_, _| {}));
        let mut bytes = 0u64;
        let mut failure = None;
        // Kept only so the steps that run *after* the relay can still read the
        // response they were written against — most importantly the SEP-2322
        // scan that mints elicitation permits. Bounded, and abandoned the
        // moment the body outgrows it: an interactive `input_required` result
        // is a small JSON document, never the large artifact this path exists
        // for, so a response past the bound cannot be one.
        let mut retained: Option<Vec<u8>> = Some(Vec::new());
        {
            use futures::StreamExt as _;
            while let Some(chunk) = body.next().await {
                match chunk {
                    Ok(chunk) => {
                        bytes = bytes.saturating_add(chunk.len() as u64);
                        match &mut retained {
                            Some(kept) if kept.len() + chunk.len() <= INSPECTABLE_STREAM_CAP => {
                                kept.extend_from_slice(&chunk)
                            }
                            slot => *slot = None,
                        }
                        if !sink.send(StreamEvent::Chunk(chunk)).await {
                            // The caller hung up. Dropping the body stream
                            // here is what stops the broker paying for a
                            // transfer nobody is receiving.
                            failure = Some(("the caller closed the stream".to_string(), false));
                            break;
                        }
                    }
                    Err(error) => {
                        failure = Some((error.to_string(), true));
                        break;
                    }
                }
            }
        }
        match failure {
            // A body that died mid-transfer cannot be un-sent, so it ends the
            // stream where it stopped. The activity log is where the caller
            // finds out it was short — the wire has no way left to say so.
            Some((detail, upstream_failed)) => {
                if upstream_failed {
                    if let Some(health) = &self.health {
                        record_upstream_failure_health(health, &self.connection.id, detail.clone());
                    }
                }
                self.audit_streamed(started, "stream_interrupted", Some(bytes));
                broker_error(502, ErrorReason::UpstreamError, detail)
            }
            None => {
                self.audit_streamed(started, &status.to_string(), Some(bytes));
                let mut record = json!({
                    "status": status,
                    "streamed": true,
                    "bytes": bytes,
                });
                if let Some(text) = retained.and_then(|kept| String::from_utf8(kept).ok()) {
                    record["body"] = json!(text);
                    record["body_encoding"] = json!("utf8");
                }
                ExecOutcome {
                    status: 200,
                    body: record,
                }
            }
        }
    }

    /// The activity entry for a streamed call. Written when the body is done,
    /// so `response_bytes` is what actually crossed rather than what was
    /// promised.
    fn audit_streamed(&self, started: Instant, outcome: &str, bytes: Option<u64>) {
        let mut entry = AuditEntry::new(
            AuditKind::HttpExecuted,
            format!("{} {} via {}", self.method, self.path, self.connection.name),
        )
        .agent(self.agent.clone())
        .connection(self.connection.name.clone())
        .outcome(outcome)
        .duration_ms(started.elapsed().as_millis() as u64)
        .field("method", self.method.as_str())
        .field("path", self.path.clone())
        .field("relay", "streamed");
        if let Some(bytes) = bytes {
            entry = entry.field("response_bytes", bytes);
        }
        self.audit.append(entry);
    }

    /// Dial for a relay that forwards the body as it arrives rather than
    /// buffering it whole.
    ///
    /// The per-hop budget is the *operation* budget here, not the hop budget:
    /// a streamed response may be a large artifact whose transfer legitimately
    /// outlasts what a buffered call is allowed, and cutting it at the hop
    /// deadline would make the streaming path useless for the case it exists
    /// for. Everything else — pinning, redirect rules, re-injection — is the
    /// same code the buffered path runs.
    pub(crate) async fn dial_for_streaming(
        &self,
    ) -> Result<(reqwest::Response, Redactions), ExecOutcome> {
        let dialed = self.dial(self.config.upstream_operation_timeout).await?;
        Ok((dialed.response, dialed.redactions))
    }

    /// Everything up to the final upstream response: token refresh, credential
    /// render, authority pinning, and the hand-rolled redirect loop. Shared so
    /// the buffered and streaming relays cannot drift on any of it.
    async fn dial(&self, per_request_timeout: std::time::Duration) -> Result<Dialed, ExecOutcome> {
        if !matches!(&self.connection.config, ConnectionConfig::Api { .. }) {
            return Err(broker_error(
                500,
                ErrorReason::WrongConnectionType,
                "not an api connection",
            ));
        }
        let upstream_client = match client_for_connection(&self.client, &self.connection) {
            Ok(client) => client,
            Err(error) => {
                return Err(broker_error(500, ErrorReason::BadConnectionConfig, error));
            }
        };
        // An OAuth-minted token at expiry is renewed before it rides the
        // upstream leg, so agent calls never present a token the broker
        // already knew was stale. Best-effort: on failure the current token
        // goes out as-is and the upstream's verdict lands in health.
        if self.connection.oauth.is_some() {
            let ctx = crate::mcp_refresh::RefreshContext {
                store: self.store.as_ref(),
                http: &upstream_client,
                audit: self.audit.as_ref(),
                health: self.health.as_deref(),
            };
            crate::mcp_refresh::ensure_fresh(&ctx, &self.connection).await;
        }
        // Render the credential as late as possible; values are zeroized on
        // drop.
        let (scheme, host, port) = pinned_base(&self.connection.config).expect("api config");

        let mut injection = match render_connection_injection(
            &self.store,
            &upstream_client,
            &self.connection,
        )
        .await
        {
            Ok(i) => i,
            Err(e) => return Err(broker_error(502, e.reason, e.message)),
        };
        let mut redactions = Redactions::from_injection(&injection);
        let mcp_request = match &self.connection.config {
            ConnectionConfig::Api {
                mcp_path: Some(mcp_path),
                ..
            } if resolves_to_mcp_path(&self.path, mcp_path) => self
                .body
                .bytes()
                .ok()
                .and_then(|body| serde_json::from_slice::<Value>(&body).ok()),
            _ => None,
        };
        let mcp_response_id = mcp_request
            .as_ref()
            .filter(|body| body.get("method").and_then(Value::as_str).is_some())
            .and_then(|body| body.get("id").cloned());
        let mcp_tool_call_id = mcp_request
            .as_ref()
            .filter(|body| body.get("method").and_then(Value::as_str) == Some("tools/call"))
            .and_then(|body| body.get("id").cloned());
        let authenticated_mcp_message = mcp_request.as_ref().is_some_and(is_mcp_client_message);

        // Build the initial URL from parsed components, never string
        // concatenation.
        let mut base = match Url::parse(&format!("{scheme}://{host}")) {
            Ok(u) => u,
            Err(e) => {
                return Err(broker_error(
                    500,
                    ErrorReason::BadConnectionConfig,
                    e.to_string(),
                ))
            }
        };
        if base.set_port(port).is_err() {
            return Err(broker_error(
                500,
                ErrorReason::BadConnectionConfig,
                "cannot set port",
            ));
        }
        let mut current = match base.join(&self.path) {
            Ok(u) => u,
            Err(e) => return Err(broker_error(400, ErrorReason::InvalidPath, e.to_string())),
        };
        // Belt and braces: the joined URL must still point at the pinned
        // authority, with no userinfo.
        if !same_pinned_authority(&current, &scheme, &host, port)
            || !current.username().is_empty()
            || current.password().is_some()
        {
            return Err(broker_error(
                400,
                ErrorReason::InvalidPath,
                "path escaped the pinned authority",
            ));
        }
        base.set_path("");

        let mut method = self.method.clone();
        let mut send_body = true;
        let mut hops = 0usize;
        // An MCP server that rejects an OAuth token has not accepted the
        // JSON-RPC operation. Renew once and replay that same request with the
        // replacement token. The bound prevents a bad grant or a permissions
        // 403 from looping; limiting this to an explicit MCP message prevents
        // ordinary mutating API calls from ever being retried here.
        let mut oauth_recovery_attempted = false;

        loop {
            let mut request = upstream_client
                .request(method.clone(), current.clone())
                .timeout(per_request_timeout)
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
                    request = upstream_client
                        .request(method.clone(), hop)
                        .timeout(per_request_timeout)
                        .headers(self.headers.clone());
                }
            }
            if send_body && !self.body.is_empty() {
                match self.body.bytes() {
                    Ok(bytes) => request = request.body(bytes),
                    Err(e) => {
                        return Err(broker_error(
                            500,
                            ErrorReason::BodyUnavailable,
                            e.to_string(),
                        ))
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
                    return Err(broker_error(
                        504,
                        ErrorReason::UpstreamTimeout,
                        e.without_url().to_string(),
                    ))
                }
                Err(e) => {
                    return Err(broker_error(
                        502,
                        ErrorReason::UpstreamError,
                        e.without_url().to_string(),
                    ))
                }
            };

            let status = response.status();
            let credential_rejected = status.as_u16() == 401
                || (status.as_u16() == 403
                    && response
                        .headers()
                        .contains_key(http::header::WWW_AUTHENTICATE));
            if !oauth_recovery_attempted
                && self.connection.oauth.is_some()
                && authenticated_mcp_message
                && credential_rejected
            {
                oauth_recovery_attempted = true;
                let ctx = crate::mcp_refresh::RefreshContext {
                    store: self.store.as_ref(),
                    http: &upstream_client,
                    audit: self.audit.as_ref(),
                    health: self.health.as_deref(),
                };
                if crate::mcp_refresh::refresh_connection_token(
                    &ctx,
                    &self.connection.id,
                    crate::mcp_refresh::RefreshMode::Force,
                )
                .await
                .is_ok()
                {
                    match render_connection_injection(
                        &self.store,
                        &upstream_client,
                        &self.connection,
                    )
                    .await
                    {
                        Ok(refreshed) => {
                            injection = refreshed;
                            redactions = Redactions::from_injection(&injection);
                            continue;
                        }
                        Err(error) => {
                            return Err(broker_error(502, error.reason, error.message));
                        }
                    }
                }
            }
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
                                    // Same pinned upstream: follow and
                                    // re-apply the already-rendered credential
                                    // to the new request.
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
                // 3xx: hand it back to the agent instead of following,
                // following would send the credential somewhere no
                // connection was configured for.
                return Ok(Dialed {
                    response,
                    redactions,
                    mcp_response_id,
                    mcp_tool_call_id,
                });
            }

            return Ok(Dialed {
                response,
                redactions,
                mcp_response_id,
                mcp_tool_call_id,
            });
        }
    }
}

/// The upstream response a dial arrived at, plus what the relay needs to
/// present it: the credential needles to scrub, and the MCP request ids that
/// tell a buffered SSE relay which frame ends the exchange.
struct Dialed {
    response: reqwest::Response,
    redactions: Redactions,
    mcp_response_id: Option<Value>,
    mcp_tool_call_id: Option<Value>,
}

/// The path the Test button probes: the connection's configured `test_path`,
/// else its pinned MCP path, else the origin root.
///
/// The root is the weakest of the three and the default only because it is the
/// one path every origin has. Most APIs answer 404 or 403 there, which proves
/// reachability and TLS and nothing about the credential — so a connection that
/// wants the button to mean something names a route that reads the identity.
fn probe_path(config: &ConnectionConfig) -> &str {
    match config {
        ConnectionConfig::Api {
            test_path: Some(path),
            ..
        } => path.as_str(),
        ConnectionConfig::Api {
            mcp_path: Some(path),
            ..
        } => path.as_str(),
        _ => "/",
    }
}

/// UI-initiated test: GET the connection's probe path with the credential
/// injected and the connection's TLS trust.
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
    let upstream_client = client_for_connection(client, connection)
        .map_err(|error| TestError::new(TestErrorKind::CertUnverified, error))?;
    let injection = render_connection_injection(store, &upstream_client, connection)
        .await
        .map_err(|e| TestError::from(e.message))?;
    let mut base =
        Url::parse(&format!("{scheme}://{host}/")).map_err(|e| format!("bad origin: {e}"))?;
    if base.set_port(port).is_err() {
        return Err("cannot set port".into());
    }
    let test_path = probe_path(&connection.config);
    let configured_probe = !matches!(test_path, "/");
    let mut url = base
        .join(test_path)
        .map_err(|error| format!("bad test path: {error}"))?;
    if !same_pinned_authority(&url, &scheme, &host, port) {
        return Err("test path escaped the pinned authority".into());
    }
    let request = match &injection {
        RenderedInjection::None => upstream_client.request(Method::GET, url.clone()),
        RenderedInjection::Header(name, value) => upstream_client
            .request(Method::GET, url.clone())
            .header(name.clone(), value.clone()),
        RenderedInjection::Query(fragment) => {
            let query = match url.query() {
                Some(existing) if !existing.is_empty() => format!("{existing}&{}", &**fragment),
                _ => fragment.to_string(),
            };
            url.set_query(Some(&query));
            upstream_client.request(Method::GET, url.clone())
        }
    };
    let response = request
        .timeout(timeout)
        .send()
        .await
        .map_err(|error| test_request_error(error, &host))?;
    let status = response.status();
    let auth_challenge = response
        .headers()
        .contains_key(http::header::WWW_AUTHENTICATE);
    if status.as_u16() == 401 || (status.as_u16() == 403 && auth_challenge) {
        return Err(TestError::new(
            TestErrorKind::AuthRejected,
            format!("The server at {host} answered but rejected the credential (HTTP {status})"),
        ));
    }
    // Everything below is a pass, but not every pass proves the same thing,
    // and a green badge that proved nothing is worse than no badge. A 403
    // without a `WWW-Authenticate` challenge is not a credential rejection the
    // broker can name — it is equally a WAF, a permission the token lacks, or
    // a path that is simply not for reading — and 404/405 on an unconfigured
    // root is the normal answer for an API that has no root resource. Say
    // which of those happened rather than reporting a bare "HTTP 403".
    let inconclusive = match status.as_u16() {
        403 => Some(
            "the server answered but would not serve this path; if it needs \
             different permissions, set a test path that reads the account",
        ),
        404 | 405 if !configured_probe => Some(
            "the origin root has no resource, which is normal; set a test path \
             to probe a route that reads the account",
        ),
        _ => None,
    };
    Ok(match inconclusive {
        Some(caveat) => format!(
            "GET {scheme}://{host}{test_path} answered HTTP {status} — \
             reachable and TLS is fine, but the credential was not exercised: \
             {caveat}"
        ),
        None => format!("GET {scheme}://{host}{test_path} answered HTTP {status}"),
    })
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
    expose_response_credentials: bool,
    mcp_response_id: Option<&Value>,
    mcp_tool_call_id: Option<&Value>,
) -> ExecOutcome {
    let status = response.status().as_u16();
    let is_sse = response
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("text/event-stream"));
    let mut headers = serde_json::Map::new();
    // Preserve Set-Cookie separately for the raw direct-endpoint response:
    // unlike ordinary HTTP fields it cannot be combined with commas. Keep
    // the existing flattened `headers` object for control-plane compatibility.
    let mut set_cookie_headers = Vec::new();
    for (name, value) in response.headers() {
        if !response_header_is_relayable(name, expose_response_credentials) {
            continue;
        }
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
                    if let Some(id) = mcp_tool_call_id {
                        const PREVIEW_CAP: usize = 64 * 1024;
                        let mut preview_bytes = body[..body.len().min(PREVIEW_CAP)].to_vec();
                        let remaining = PREVIEW_CAP.saturating_sub(preview_bytes.len());
                        preview_bytes.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
                        let preview = redactions.apply_to_bytes(&preview_bytes);
                        let preview = String::from_utf8_lossy(&preview);
                        let result = json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": {
                                "isError": true,
                                "content": [{
                                    "type": "text",
                                    "text": format!(
                                        "The upstream MCP result exceeded the {} byte broker cap. \
                                         Narrow the request or ask for a smaller page. \
                                         Truncated upstream preview (first {} bytes):\n{}",
                                        config.response_cap,
                                        preview.len(),
                                        preview,
                                    ),
                                }],
                                "_meta": {
                                    "agentmfa": {
                                        "result_truncated": true,
                                        "response_cap_bytes": config.response_cap,
                                    }
                                }
                            }
                        });
                        return ExecOutcome {
                            status: 200,
                            body: json!({
                                "status": status,
                                "headers": headers,
                                "set_cookie_headers": set_cookie_headers,
                                "body": result.to_string(),
                                "body_encoding": "utf8",
                            }),
                        };
                    }
                    return broker_error(
                        502,
                        ErrorReason::ResponseTooLarge,
                        format!("upstream body exceeds the {} byte cap", config.response_cap),
                    );
                }
                body.extend_from_slice(&chunk);
                // Streamable HTTP servers may leave an SSE response open for
                // later notifications. Once the complete response frame for
                // this request arrives, relay through that frame and release
                // the upstream operation instead of waiting for stream close.
                if is_sse {
                    if let Some(end) =
                        mcp_response_id.and_then(|id| matching_sse_response_end(&body, id))
                    {
                        body.truncate(end);
                        break;
                    }
                }
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

/// Headers that can create, carry, or negotiate authority follow the HTTP
/// connection's response-credential policy.
fn response_header_is_relayable(name: &HeaderName, expose_response_credentials: bool) -> bool {
    expose_response_credentials
        || !matches!(
            name.as_str(),
            "set-cookie"
                | "set-cookie2"
                | "cookie"
                | "cookie2"
                | "www-authenticate"
                | "proxy-authenticate"
                | "authentication-info"
                | "proxy-authentication-info"
                | "authorization"
                | "proxy-authorization"
        )
}

/// End offset of the first complete SSE frame carrying the JSON-RPC response
/// for `expected_id`. Notifications and responses for other in-flight ids do
/// not end the relay.
fn matching_sse_response_end(bytes: &[u8], expected_id: &Value) -> Option<usize> {
    let mut start = 0usize;
    while start < bytes.len() {
        let mut separator = None;
        for index in start..bytes.len() {
            if bytes[index..].starts_with(b"\r\n\r\n") {
                separator = Some((index, 4));
                break;
            }
            if bytes[index..].starts_with(b"\n\n") {
                separator = Some((index, 2));
                break;
            }
        }
        let (frame_end, separator_len) = separator?;
        let frame = String::from_utf8_lossy(&bytes[start..frame_end]);
        let data = frame
            .lines()
            .filter_map(|line| line.trim_end_matches('\r').strip_prefix("data:"))
            .map(|line| line.strip_prefix(' ').unwrap_or(line))
            .collect::<Vec<_>>()
            .join("\n");
        if let Ok(message) = serde_json::from_str::<Value>(&data) {
            let is_response = message.get("jsonrpc").and_then(Value::as_str) == Some("2.0")
                && (message.get("result").is_some() || message.get("error").is_some());
            if is_response && message.get("id") == Some(expected_id) {
                return Some(frame_end + separator_len);
            }
        }
        start = frame_end + separator_len;
    }
    None
}

/// Idempotency-key payload hash: the full normalized request, a genuine
/// retry matches byte-for-byte. The self-reported client label is part of
/// the hashed material: every label on a machine shares one authenticated
/// identity (and so one coalesce namespace), and folding the label in here
/// turns another label's reuse of a request id into a refusal instead of
/// silently handing it the first label's cached outcome.
/// The same fingerprint over a body that may be spooled to disk, for the
/// direct endpoint plane. Streamed through the hasher rather than materialized
/// so a large upload is fingerprinted without being pulled back into memory.
pub fn spooled_payload_hash(
    client: &str,
    connection_id: &Uuid,
    method: &Method,
    path: &str,
    headers: &[(String, String)],
    body: &SpooledBody,
) -> std::io::Result<String> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hash_request_prefix(&mut hasher, client, connection_id, method, path, headers);
    body.for_each_chunk(|chunk| hasher.update(chunk))?;
    Ok(hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

/// Everything before the body, hashed identically for both planes.
fn hash_request_prefix(
    hasher: &mut sha2::Sha256,
    client: &str,
    connection_id: &Uuid,
    method: &Method,
    path: &str,
    headers: &[(String, String)],
) {
    use sha2::Digest as _;
    hasher.update(client.as_bytes());
    hasher.update([0]);
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
}

pub fn payload_hash(
    client: &str,
    connection_id: &Uuid,
    method: &Method,
    path: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hash_request_prefix(&mut hasher, client, connection_id, method, path, headers);
    hasher.update(body);
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/* ------------------------------- streamed relay --------------------------- */

/// How many frames a slow reader may fall behind before the relay parks.
///
/// Small on purpose: the point of streaming is that the broker does not hold
/// the body, and a deep queue would put it back — just in a channel instead of
/// a `Vec`.
const STREAM_QUEUE: usize = 8;

/// How much of a streamed body is kept for the post-relay steps that read it.
///
/// Only large enough for the small JSON documents those steps look for; past
/// it the body is forgotten as it is forwarded, which is the whole point of
/// streaming.
const INSPECTABLE_STREAM_CAP: usize = 256 * 1024;

/// One frame of a streamed `/v1/http` answer.
///
/// The buffered plane answers with a single JSON object, which means the
/// caller learns nothing until the last byte and the broker must hold every
/// byte to say anything at all. The same call asked to stream reports the same
/// facts in the order they become true.
#[derive(Debug)]
pub(crate) enum StreamEvent {
    /// The call is parked on the user. Sent before the wait, not after, since
    /// its whole purpose is to be visible during it.
    Waiting,
    /// The upstream answered; body bytes follow.
    Head { status: u16, headers: Value },
    /// Redacted body bytes, in arrival order.
    Chunk(bytes::Bytes),
    /// The body ended normally. Carries the execution's own record of the
    /// call — anything the wrappers attached after the relay finished, such
    /// as the elicitation permits an interactive MCP result mints.
    End { body: Value },
    /// The call failed or was refused. Terminal, and mutually exclusive with
    /// `Head` — a caller that has seen a head will never see this.
    Error(ExecOutcome),
}

/// The writer half of a streamed answer.
///
/// Cloneable so the approval gate can announce the wait on the same channel
/// the relay will later use, without either of them owning the other.
#[derive(Clone)]
pub(crate) struct StreamSink {
    tx: tokio::sync::mpsc::Sender<StreamEvent>,
    /// Set once a head has gone out. After that the answer is committed:
    /// a later failure can only truncate the body, never become a refusal,
    /// because the status line is already on the wire.
    began: Arc<std::sync::atomic::AtomicBool>,
}

impl StreamSink {
    pub(crate) fn new() -> (Self, tokio::sync::mpsc::Receiver<StreamEvent>) {
        let (tx, rx) = tokio::sync::mpsc::channel(STREAM_QUEUE);
        (
            Self {
                tx,
                began: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            },
            rx,
        )
    }

    /// Send one frame. `false` means the reader is gone, which is the relay's
    /// cue to stop pulling an upstream body nobody will receive.
    async fn send(&self, event: StreamEvent) -> bool {
        self.tx.send(event).await.is_ok()
    }

    pub(crate) async fn waiting(&self) {
        self.send(StreamEvent::Waiting).await;
    }

    /// Close the stream with how the execution ended.
    ///
    /// Sent from one place, after the whole wrapped executor — including the
    /// steps that run *after* the relay and add to the outcome — so the
    /// terminal frame carries everything the buffered plane's single object
    /// would have. A call that never produced a head was refused before it
    /// reached the upstream, and ends as an error instead.
    pub(crate) async fn finish(&self, outcome: ExecOutcome) {
        if self.began.load(std::sync::atomic::Ordering::SeqCst) {
            self.send(StreamEvent::End { body: outcome.body }).await;
            return;
        }
        self.send(StreamEvent::Error(outcome)).await;
    }
}

/// Encode `StreamEvent`s as `text/event-stream` frames.
///
/// SSE rather than a bespoke framing because the one consumer that matters —
/// an MCP transport leg — is already reading SSE, and because a line-oriented
/// format survives the proxies a JSON-envelope plane is expected to sit
/// behind. Bodies ride base64 so an arbitrary upstream byte string cannot
/// break the framing.
pub(crate) fn stream_events_body(
    rx: tokio::sync::mpsc::Receiver<StreamEvent>,
) -> axum::body::Body {
    let stream = futures::stream::unfold(rx, |mut rx| async move {
        let event = rx.recv().await?;
        Some((Ok::<_, std::io::Error>(stream_frame(event)), rx))
    });
    axum::body::Body::from_stream(stream)
}

/// One SSE frame. Split out so the encoding is testable without a socket.
pub(crate) fn stream_frame(event: StreamEvent) -> bytes::Bytes {
    use base64::Engine as _;
    let frame = match event {
        StreamEvent::Waiting => {
            format!("event: waiting\ndata: {}\n\n", json!({ "reason": "approval" }))
        }
        StreamEvent::Head { status, headers } => format!(
            "event: head\ndata: {}\n\n",
            json!({ "status": status, "headers": headers })
        ),
        StreamEvent::Chunk(bytes) => format!(
            "event: chunk\ndata: {}\n\n",
            json!({ "b64": base64::engine::general_purpose::STANDARD.encode(&bytes) })
        ),
        StreamEvent::End { mut body } => {
            // The relayed bytes already crossed as `chunk` frames; repeating
            // them here would double every streamed response. What is left is
            // the call's own record — status, byte count, permits.
            if let Some(object) = body.as_object_mut() {
                object.remove("body");
                object.remove("body_encoding");
            }
            format!("event: end\ndata: {body}\n\n")
        }
        StreamEvent::Error(outcome) => format!(
            "event: error\ndata: {}\n\n",
            json!({ "status": outcome.status, "body": outcome.body })
        ),
    };
    bytes::Bytes::from(frame)
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
    /// Unauthenticated failures share one small listener-local window: there
    /// is no trustworthy identity to key before the endpoint secret verifies.
    auth_failures: Arc<crate::ratelimit::WindowLimiter>,
    /// Whether the current throttle episode has already been audited. The
    /// sealed audit log is an unbounded synchronous write under a shared
    /// mutex, so an unauthenticated flood must not get one entry per request
    /// — one per episode says the same thing at none of the cost.
    auth_flood_noted: std::sync::atomic::AtomicBool,
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
        auth_failures: Arc::new(crate::ratelimit::WindowLimiter::new(
            broker.config.per_identity_per_min,
            std::time::Duration::from_secs(60),
        )),
        auth_flood_noted: std::sync::atomic::AtomicBool::new(false),
        broker,
        endpoint_id: endpoint.id,
    });
    let app = axum::Router::new()
        .fallback(proxy_handler)
        .with_state(state);
    let shutdown = Arc::new(tokio::sync::Notify::new());
    let sd = shutdown.clone();
    let task = tokio::spawn(async move {
        let served = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
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
    reason: ErrorReason,
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

fn endpoint_auth_failure(
    state: &HttpEndpointState,
    peer: std::net::SocketAddr,
    reason: ErrorReason,
    detail: &str,
) -> axum::response::Response {
    use axum::http::StatusCode;

    // The window bounds the sealed audit log too: this plane is reachable by
    // any local process, and appending before the throttle verdict gave an
    // unauthenticated flood one MAC-chained write (and one UI event) per
    // request, forever — the throttle only spared the hash comparison.
    if let Err(retry_after) = state.auth_failures.check() {
        return endpoint_auth_throttled(state, peer, retry_after);
    }
    state
        .auth_flood_noted
        .store(false, std::sync::atomic::Ordering::Relaxed);
    state.broker.audit.append(
        AuditEntry::new(AuditKind::Denied, "Direct endpoint authentication refused")
            .outcome(reason.as_str())
            .field("endpoint_id", state.endpoint_id.to_string())
            .field("peer_addr", peer.to_string()),
    );
    endpoint_error(StatusCode::UNAUTHORIZED, reason, detail)
}

fn endpoint_auth_throttled(
    state: &HttpEndpointState,
    peer: std::net::SocketAddr,
    retry_after: std::time::Duration,
) -> axum::response::Response {
    use axum::http::StatusCode;

    // One audit entry per throttle episode, not per suppressed request; the
    // flag re-arms when a failure is next admitted within the window.
    if !state
        .auth_flood_noted
        .swap(true, std::sync::atomic::Ordering::Relaxed)
    {
        state.broker.audit.append(
            AuditEntry::new(
                AuditKind::Denied,
                "Direct endpoint authentication throttled",
            )
            .outcome(ErrorReason::RateLimited.as_str())
            .field("endpoint_id", state.endpoint_id.to_string())
            .field("peer_addr", peer.to_string()),
        );
    }
    let mut response = endpoint_error(
        StatusCode::TOO_MANY_REQUESTS,
        ErrorReason::RateLimited,
        "too many failed authentication attempts on this endpoint",
    );
    if let Ok(value) = HeaderValue::from_str(&retry_after.as_secs().max(1).to_string()) {
        response
            .headers_mut()
            .insert(http::header::RETRY_AFTER, value);
    }
    response
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
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
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
        return endpoint_auth_failure(
            &state,
            peer,
            ErrorReason::MissingSecret,
            "present the endpoint secret as `Authorization: Bearer <secret>`",
        );
    };
    // Once the listener-local failure window is exhausted, reject before
    // hashing and comparing another candidate. Successful authentication
    // never spends this budget, so a holder is affected only while the
    // endpoint is actively being brute-forced.
    if let Some(retry_after) = state.auth_failures.retry_after() {
        return endpoint_auth_throttled(&state, peer, retry_after);
    }
    let Some(endpoint) = broker
        .endpoints
        .resolve_secret(presented)
        .filter(|e| e.id == state.endpoint_id)
    else {
        return endpoint_auth_failure(
            &state,
            peer,
            ErrorReason::InvalidSecret,
            "the endpoint secret is not recognized",
        );
    };

    // Charged after authentication, so an unauthenticated prober cannot spend a
    // legitimate holder's budget, and keyed on the endpoint so one endpoint
    // cannot starve another.
    if let Err(retry_after) = state.requests.check(&endpoint.id.to_string()) {
        let mut response = endpoint_error(
            StatusCode::TOO_MANY_REQUESTS,
            ErrorReason::RateLimited,
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
            ErrorReason::DeniedByPolicy,
            "agent access is disabled for this tool",
        );
    }
    let Ok(connection) = broker.store.connection_by_id(&endpoint.connection_id) else {
        return endpoint_error(
            StatusCode::BAD_GATEWAY,
            ErrorReason::UnknownConnection,
            "the connection has been removed",
        );
    };
    if connection.kind() != ConnectionKind::Api {
        return endpoint_error(
            StatusCode::BAD_GATEWAY,
            ErrorReason::WrongConnectionType,
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
            ErrorReason::WrongConnectionType,
            "this endpoint is a base URL for one pinned host, not a forward \
             proxy; CONNECT is not served. Point your client's base URL at it \
             instead of its proxy setting.",
        );
    }
    if parts.uri.authority().is_some() {
        return endpoint_error(
            StatusCode::BAD_REQUEST,
            ErrorReason::InvalidPath,
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
            ErrorReason::InvalidMethod,
            "unsupported method: use GET, HEAD, POST, PUT, PATCH, DELETE or \
             OPTIONS",
        );
    };
    // The idempotency key, if the caller offered one. Reads are never
    // coalesced — the same rule `/v1/http` follows — so a key on a GET is
    // inert rather than an error, and such a call streams like any other.
    let coalesce_request_id = match parts
        .headers
        .get(ENDPOINT_REQUEST_ID_HEADER)
        .map(|value| value.to_str().map(str::trim))
    {
        None => None,
        Some(Err(_)) => {
            return endpoint_error(
                StatusCode::BAD_REQUEST,
                ErrorReason::InvalidHeader,
                "the request id must be printable ASCII",
            )
        }
        Some(Ok("")) => None,
        Some(Ok(request_id)) if request_id.len() > crate::wire::REQUEST_ID_MAX_BYTES => {
            return endpoint_error(
                StatusCode::BAD_REQUEST,
                ErrorReason::InvalidBody,
                &format!(
                    "the request id is {} UTF-8 bytes; the maximum is {}",
                    request_id.len(),
                    crate::wire::REQUEST_ID_MAX_BYTES
                ),
            )
        }
        Some(Ok(request_id)) => is_mutating(&method).then(|| request_id.to_string()),
    };
    let path = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    if validate_path(&path).is_err() {
        return endpoint_error(
            StatusCode::BAD_REQUEST,
            ErrorReason::InvalidPath,
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
            ErrorReason::DeniedByPolicy,
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
                HttpValidationError::ReservedHeader(_) => ErrorReason::ReservedHeader,
                HttpValidationError::InvalidHeader(_) => ErrorReason::InvalidHeader,
                HttpValidationError::InvalidMethod | HttpValidationError::InvalidPath => {
                    ErrorReason::InvalidHeader
                }
            };
            let detail = match &error {
                HttpValidationError::ReservedHeader(_) => format!(
                    "{}; configure the SDK to omit its native credential header and put this \
                     endpoint's secret in Authorization: Bearer instead; if the SDK cannot omit \
                     that header, use a request or transport hook before calling this endpoint",
                    error.detail()
                ),
                _ => error.detail(),
            };
            return endpoint_error(StatusCode::BAD_REQUEST, reason, &detail);
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
    let policy_version = connection.updated_at;
    let confirmed_version = if confirmation_enabled && !mcp_transport_leg {
        let version = connection.updated_at;
        let verdict = broker
            .approvals
            .gate(
                crate::approvals::ApprovalRequest::new(
                    &connection,
                    "endpoint",
                    format!("{method} {}", crate::approvals::capped_text(&path)),
                )
                .credentials_from(&broker.store)
                .http_operation(&method, &path),
            )
            .await;
        if !verdict.is_allowed() {
            let status = match verdict {
                crate::approvals::Verdict::TimedOut => StatusCode::REQUEST_TIMEOUT,
                _ => StatusCode::FORBIDDEN,
            };
            let reason = verdict
                .reason()
                .unwrap_or(crate::wire::ErrorReason::ApprovalDenied);
            return endpoint_error(status, reason, verdict.detail());
        }
        Some(version)
    } else {
        None
    };

    // A revoke, disable, or connection edit can race with either prompt
    // insertion or the transport exemption check. Revalidate immediately,
    // and close any window a stale prompt might just have opened.
    let endpoint_still_valid = broker
        .endpoints
        .resolve_secret(presented)
        .is_some_and(|current| current.id == endpoint.id);
    let connection_is_current = broker
        .store
        .connection_by_id(&endpoint.connection_id)
        .is_ok_and(|current| current.updated_at == policy_version);
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
            ErrorReason::DeniedByPolicy,
            "the endpoint or connection changed while the request was being admitted",
        );
    }

    // Admit the upload before reading even its first body frame. A malicious
    // holder of a valid endpoint secret can therefore occupy only the fixed
    // per-listener and broker-wide budgets.
    let _global_upload = match broker.endpoint_uploads.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            return endpoint_error(
                StatusCode::SERVICE_UNAVAILABLE,
                ErrorReason::EndpointBusy,
                "the broker's direct-endpoint upload limit has been reached",
            )
        }
    };
    let _listener_upload = match state.uploads.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            return endpoint_error(
                StatusCode::SERVICE_UNAVAILABLE,
                ErrorReason::EndpointBusy,
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
                ErrorReason::BrokerSessionLimit,
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
            ErrorReason::DeniedByPolicy,
            "the endpoint was revoked or agent access was disabled",
        );
    }

    let close_signal = session.close_signal.clone();
    let upload = tokio::select! {
        reason = close_signal.reason() => {
            session.finish(reason);
            return endpoint_error(
                StatusCode::FORBIDDEN,
                ErrorReason::DeniedByPolicy,
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
                ErrorReason::RequestTooLarge,
                "the request body exceeds the configured cap",
            );
        }
        Err(EndpointUploadError::TimedOut) => {
            session.finish("upload_timeout");
            return endpoint_error(
                StatusCode::REQUEST_TIMEOUT,
                ErrorReason::UploadTimeout,
                "the request body upload exceeded its time limit",
            );
        }
        Err(EndpointUploadError::InvalidBody(detail)) => {
            session.finish("invalid_request_body");
            return endpoint_error(StatusCode::BAD_REQUEST, ErrorReason::InvalidBody, &detail);
        }
        Err(EndpointUploadError::Spool(error)) => {
            session.finish("spool_failed");
            return endpoint_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorReason::SpoolFailed,
                &error.to_string(),
            );
        }
    };
    session
        .bytes_up
        .fetch_add(spooled.len(), Ordering::Relaxed);
    // These permits bound only concurrently received uploads. Once the body
    // is safely spooled, the registered data-plane session is the independent
    // bound on the upstream leg; holding upload permits through a slow
    // response would let unrelated endpoints starve.
    drop(_listener_upload);
    drop(_global_upload);

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
            ErrorReason::InvalidSecret,
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
            ErrorReason::DeniedByPolicy,
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
            ErrorReason::UnknownConnection,
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
            ErrorReason::WrongConnectionType,
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
            ErrorReason::DeniedByPolicy,
            "curated MCP tools must be called through the broker or MCP sidecar, not the direct HTTP endpoint",
        );
    }
    if connection.updated_at != policy_version {
        if confirmed_version.is_some() {
            broker.approvals.revoke(&endpoint.connection_id);
        }
        session.finish("connection_changed");
        return endpoint_error(
            StatusCode::FORBIDDEN,
            ErrorReason::DeniedByPolicy,
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
            ErrorReason::DeniedByPolicy,
            "the endpoint was revoked or agent access was disabled",
        );
    }

    // Reuse `/v1/http`'s whole execution core. The wiring is the
    // authorization, so the vault read is pre-authorized (scope confirmed).
    let execution = HttpExecution {
        store: broker.store.clone(),
        access: broker.access.clone(),
        audit: broker.audit.clone(),
        client: broker.http_client.clone(),
        config: broker.config.clone(),
        agent: "endpoint".to_string(),
        connection: connection.clone(),
        method: method.clone(),
        path: path.clone(),
        headers: headers.clone(),
        body: spooled.clone(),
        health: Some(broker.health.clone()),
    };

    // Two relays, and the request chooses between them.
    //
    // Coalescing needs a replayable outcome, which means holding the whole
    // response — so a keyed call takes the buffered path and inherits its size
    // cap. An unkeyed one has nothing to replay to, so it streams: the body
    // goes out as it arrives, past the cap, which is the only way this plane
    // can carry an artifact bigger than `response_cap`. Naming a request id is
    // therefore an explicit trade of size for retry safety.
    if let Some(request_id) = coalesce_request_id {
        let outcome = tokio::select! {
            reason = close_signal.reason() => {
                session.finish(reason);
                return endpoint_error(
                    StatusCode::FORBIDDEN,
                    ErrorReason::DeniedByPolicy,
                    "the endpoint was revoked or agent access was disabled",
                );
            }
            outcome = run_coalesced(broker, &endpoint, &connection, &method, &path,
                                    &headers, &spooled, request_id, execution) => outcome,
        };
        if let Ok(outcome) = &outcome {
            session
                .bytes_down
                .fetch_add(outcome_body_len(outcome), Ordering::Relaxed);
        }
        session.finish("request_complete");
        let expose_response_credentials = broker
            .access
            .expose_response_credentials(&endpoint.connection_id);
        return match outcome {
            Ok(outcome) => translate_outcome(outcome, &method, expose_response_credentials),
            Err(response) => response,
        };
    }

    let dialed = tokio::select! {
        reason = close_signal.reason() => {
            session.finish(reason);
            return endpoint_error(
                StatusCode::FORBIDDEN,
                ErrorReason::DeniedByPolicy,
                "the endpoint was revoked or agent access was disabled",
            );
        }
        dialed = crate::authorization::scope(true, execution.dial_for_streaming()) => dialed,
    };
    let relay = StreamAudit {
        audit: broker.audit.clone(),
        connection: connection.name.clone(),
        method: method.to_string(),
        path: path.clone(),
        started: Instant::now(),
    };
    match dialed {
        Ok((response, redactions)) => {
            record_streamed_health(
                broker,
                &connection,
                response.status().as_u16(),
                response
                    .headers()
                    .contains_key(http::header::WWW_AUTHENTICATE),
            );
            stream_response(
                response,
                redactions,
                broker
                    .access
                    .expose_response_credentials(&endpoint.connection_id),
                &method,
                broker.health.clone(),
                connection.id,
                relay,
                session,
            )
        }
        Err(outcome) => {
            execution.record_broker_failure_health(&outcome);
            relay.finish(&outcome_status_label(&outcome), None);
            session.finish("request_failed");
            translate_outcome(
                outcome,
                &method,
                broker
                    .access
                    .expose_response_credentials(&endpoint.connection_id),
            )
        }
    }
}

/// Grade a streamed relay's health from the status line, which is all a
/// stream knows before its body has gone anywhere. Same rule as the buffered
/// path: a rejection needs corroboration, anything else served is proof the
/// credential works.
fn record_streamed_health(
    broker: &Arc<Broker>,
    connection: &Connection,
    status: u16,
    auth_challenge: bool,
) {
    record_relayed_health(&broker.health, &connection.id, status, auth_challenge);
}

/// Forward an upstream response to the endpoint's client as it arrives.
///
/// The buffered relay's size cap does not apply here — that cap exists because
/// a JSON envelope has to hold the whole body in memory, and this one never
/// does. What still applies is redaction, which runs across chunk boundaries,
/// and the session accounting, which is retired by the stream's own guard so a
/// client that disconnects mid-transfer is not left holding a live session.
fn stream_response(
    response: reqwest::Response,
    redactions: Redactions,
    expose_response_credentials: bool,
    request_method: &Method,
    health: Arc<crate::health::HealthRegistry>,
    connection_id: Uuid,
    relay: StreamAudit,
    session: crate::sessions::SessionHandle,
) -> axum::response::Response {
    use axum::http::StatusCode;

    let status =
        StatusCode::from_u16(response.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    // A HEAD or 304 carries the upstream's length without a body; everything
    // else is re-framed for this leg, since redaction changes the length.
    let preserve_content_length =
        request_method == Method::HEAD || status == StatusCode::NOT_MODIFIED;
    let mut builder = axum::response::Response::builder().status(status);
    for (name, value) in response.headers() {
        if !response_header_is_relayable(name, expose_response_credentials) {
            continue;
        }
        let lower = name.as_str().to_ascii_lowercase();
        if matches!(lower.as_str(), "transfer-encoding" | "connection")
            || (lower == "content-length" && !preserve_content_length)
        {
            continue;
        }
        // Header values are scrubbed too: a reflected credential in a
        // `Location` or a custom echo header must not survive the relay.
        let scrubbed = redactions.apply_to_string(&String::from_utf8_lossy(value.as_bytes()));
        if let Ok(value) = HeaderValue::from_str(&scrubbed) {
            builder = builder.header(name.clone(), value);
        }
    }
    let status_label = status.as_u16().to_string();
    let body = redacting_stream(response, redactions, move |bytes, finish| match finish {
        StreamFinish::Complete => {
            session.bytes_down.fetch_add(bytes, Ordering::Relaxed);
            relay.finish(&status_label, Some(bytes));
            session.finish("request_complete");
        }
        StreamFinish::UpstreamError(detail) => {
            session.bytes_down.fetch_add(bytes, Ordering::Relaxed);
            record_upstream_failure_health(&health, &connection_id, detail);
            relay.finish("stream_interrupted", Some(bytes));
            session.finish("request_failed");
        }
        StreamFinish::ConsumerDropped => {
            session.bytes_down.fetch_add(bytes, Ordering::Relaxed);
            relay.finish("caller_disconnected", Some(bytes));
            session.finish("client_closed");
        }
    });
    builder
        .body(axum::body::Body::from_stream(body))
        .unwrap_or_else(|_| {
            use axum::response::IntoResponse as _;
            StatusCode::BAD_GATEWAY.into_response()
        })
}

/// Run the request through the shared idempotency table so a retried mutating
/// call joins the in-flight execution (or replays its outcome) instead of
/// hitting the upstream twice.
///
/// Keyed on the *endpoint* rather than an agent identity: this plane has no
/// authenticated principal beyond the endpoint secret itself, and the endpoint
/// is exactly the right namespace — one pasted credential, one retry space,
/// revoked as a unit.
#[allow(clippy::too_many_arguments)]
async fn run_coalesced(
    broker: &Arc<Broker>,
    endpoint: &DirectEndpoint,
    connection: &Connection,
    method: &Method,
    path: &str,
    headers: &HeaderMap,
    body: &Arc<SpooledBody>,
    request_id: String,
    execution: HttpExecution,
) -> Result<ExecOutcome, axum::response::Response> {
    use axum::http::StatusCode;
    use crate::executions::{ExecError, ExecRequest, Execution};

    let wire_headers: Vec<(String, String)> = headers
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_string(),
                String::from_utf8_lossy(value.as_bytes()).into_owned(),
            )
        })
        .collect();
    let hash = match spooled_payload_hash(
        "endpoint",
        &connection.id,
        method,
        path,
        &wire_headers,
        body,
    ) {
        Ok(hash) => hash,
        Err(error) => {
            return Err(endpoint_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorReason::BodyUnavailable,
                &error.to_string(),
            ))
        }
    };
    let request = ExecRequest {
        coalesce_key: Some((endpoint.id, connection.id, request_id)),
        payload_hash: Some(hash),
        executor: Box::pin(crate::authorization::scope(true, execution.run())),
        abandon: None,
    };
    match broker.executions.run(request) {
        Ok(Execution::Wait(handle)) => handle.wait().await.ok_or_else(|| {
            endpoint_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorReason::BrokerShutdown,
                "the broker is shutting down",
            )
        }),
        Ok(Execution::Replay(outcome)) => Ok(outcome),
        Err(ExecError::RequestIdMismatch) => Err(endpoint_error(
            StatusCode::CONFLICT,
            ErrorReason::RequestIdMismatch,
            "this request id was already used for a different request",
        )),
        Err(ExecError::OutcomeNotReplayable) => Err(endpoint_error(
            StatusCode::CONFLICT,
            ErrorReason::OutcomeNotReplayable,
            "that request completed, but its response is no longer available to replay",
        )),
        Err(ExecError::IdempotencyCapacity) => Err(endpoint_error(
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorReason::IdempotencyCapacity,
            "the broker's idempotency table is full; retry shortly",
        )),
    }
}

/// What a streamed relay still owes the activity log once its body has gone
/// out: the buffered path audits inside `HttpExecution::run`, which a stream
/// never reaches.
struct StreamAudit {
    audit: Arc<AuditLog>,
    connection: String,
    method: String,
    path: String,
    started: Instant,
}

impl StreamAudit {
    /// One entry per streamed call, written when the body finishes rather
    /// than when it starts, so `response_bytes` is what actually crossed.
    fn finish(&self, outcome: &str, bytes: Option<u64>) {
        let mut entry = AuditEntry::new(
            AuditKind::HttpExecuted,
            format!("{} {} via {}", self.method, self.path, self.connection),
        )
        .agent("endpoint")
        .connection(self.connection.clone())
        .outcome(outcome)
        .duration_ms(self.started.elapsed().as_millis() as u64)
        .field("method", self.method.clone())
        .field("path", self.path.clone())
        .field("relay", "streamed");
        if let Some(bytes) = bytes {
            entry = entry.field("response_bytes", bytes);
        }
        self.audit.append(entry);
    }
}

fn outcome_status_label(outcome: &ExecOutcome) -> String {
    outcome
        .body
        .get("status")
        .and_then(|status| status.as_u64())
        .map(|status| status.to_string())
        .unwrap_or_else(|| format!("broker:{}", outcome.status))
}

fn outcome_body_len(outcome: &ExecOutcome) -> u64 {
    if outcome.status != 200 {
        return 0;
    }
    let Some(body) = outcome.body.get("body").and_then(Value::as_str) else {
        return 0;
    };
    match outcome
        .body
        .get("body_encoding")
        .and_then(Value::as_str)
    {
        Some("base64") => {
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD
                .decode(body)
                .map(|bytes| bytes.len() as u64)
                .unwrap_or(0)
        }
        _ => body.len() as u64,
    }
}

/// Translate `/v1/http`'s relayed `{status, headers, body, body_encoding}`
/// envelope back into a raw HTTP response for the reverse-proxy client. A
/// broker-side error (`status != 200`, a `{reason, detail}` body) is returned
/// as that status directly.
fn translate_outcome(
    outcome: ExecOutcome,
    request_method: &Method,
    expose_response_credentials: bool,
) -> axum::response::Response {
    use axum::http::StatusCode;
    if outcome.status != 200 {
        let status = StatusCode::from_u16(outcome.status).unwrap_or(StatusCode::BAD_GATEWAY);
        return endpoint_error(
            status,
            ErrorReason::from_str(
                outcome
                    .body
                    .get("reason")
                    .and_then(|r| r.as_str())
                    .unwrap_or(ErrorReason::UpstreamError.as_str()),
            )
            .unwrap_or(ErrorReason::UpstreamError),
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
            match base64::engine::general_purpose::STANDARD.decode(body_str) {
                Ok(body) => body,
                Err(_) => {
                    return endpoint_error(
                        StatusCode::BAD_GATEWAY,
                        ErrorReason::UpstreamError,
                        "the cached upstream response body was not valid base64",
                    )
                }
            }
        }
        _ => body_str.as_bytes().to_vec(),
    };

    let mut response = axum::response::Response::builder().status(status);
    let preserve_content_length =
        request_method == Method::HEAD || status == StatusCode::NOT_MODIFIED;
    if let Some(headers) = env.get("headers").and_then(|h| h.as_object()) {
        for (name, value) in headers {
            // Framing/length headers are recomputed for the client leg.
            let lower = name.to_ascii_lowercase();
            let Ok(header_name) = HeaderName::from_bytes(name.as_bytes()) else {
                continue;
            };
            if !response_header_is_relayable(&header_name, expose_response_credentials) {
                continue;
            }
            if matches!(
                lower.as_str(),
                "transfer-encoding" | "connection" | "set-cookie"
            ) || (lower == "content-length" && !preserve_content_length)
            {
                continue;
            }
            if let Some(vs) = value.as_str() {
                if let Ok(hv) = HeaderValue::from_str(vs) {
                    response = response.header(header_name, hv);
                }
            }
        }
    }
    if expose_response_credentials {
        if let Some(cookies) = env.get("set_cookie_headers").and_then(|h| h.as_array()) {
            for cookie in cookies.iter().filter_map(|cookie| cookie.as_str()) {
                if let Ok(value) = HeaderValue::from_str(cookie) {
                    response = response.header(http::header::SET_COOKIE, value);
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

    /// H2. A streamed relay sees the body in whatever chunks the upstream
    /// sends, so a credential straddling a chunk boundary is exactly the case
    /// a naive per-chunk scrub misses — and the one an upstream could arrange
    /// deliberately. Every split point must scrub identically to the buffered
    /// relay's single-pass scan.
    #[test]
    fn streamed_redaction_survives_every_chunk_boundary() {
        let injection = RenderedInjection::Header(
            HeaderName::from_static("authorization"),
            HeaderValue::from_static("Bearer ghp_test_secret_value"),
        );
        let redactions = Redactions::from_injection(&injection);
        let body = b"prefix ghp_test_secret_value suffix ghp_test_secret_value end";
        let expected = redactions.apply_to_bytes(body);

        for split in 0..=body.len() {
            let mut emitted = Vec::new();
            let mut carry: Vec<u8> = Vec::new();
            for chunk in [&body[..split], &body[split..]] {
                carry.extend_from_slice(chunk);
                let (emit, held) = redactions.split_redacted(&carry);
                emitted.extend_from_slice(&emit);
                carry = held;
            }
            emitted.extend_from_slice(&redactions.apply_to_bytes(&carry));
            assert_eq!(
                emitted,
                expected,
                "a credential split at byte {split} escaped the stream"
            );
        }
    }

    /// The tail a stream holds back is bounded by the longest needle, so a
    /// body with nothing to scrub still flows rather than accumulating.
    #[test]
    fn streamed_redaction_holds_back_only_a_boundary_tail() {
        let injection = RenderedInjection::Header(
            HeaderName::from_static("authorization"),
            HeaderValue::from_static("Bearer ghp_test_secret_value"),
        );
        let redactions = Redactions::from_injection(&injection);
        let hold = redactions.max_needle_len() - 1;
        let body = vec![b'x'; hold * 4];
        let (emit, held) = redactions.split_redacted(&body);
        assert_eq!(held.len(), hold);
        assert_eq!(emit.len(), body.len() - hold);

        // A credential-less connection scrubs nothing and therefore holds
        // nothing: the stream is a straight pass-through.
        let none = Redactions::from_injection(&RenderedInjection::None);
        let (emit, held) = none.split_redacted(&body);
        assert_eq!(emit, body);
        assert!(held.is_empty());
    }

    /// H1. The endpoint plane's idempotency key must fingerprint a spooled
    /// body exactly as the control plane fingerprints an in-memory one, or a
    /// genuine retry would read as a payload mismatch.
    #[test]
    fn spooled_and_inline_payload_hashes_agree() {
        let connection = Uuid::new_v4();
        let body = vec![b'z'; 512 * 1024];
        let headers = [("Accept".to_string(), "application/json".to_string())];

        let inline = payload_hash(
            "endpoint",
            &connection,
            &Method::POST,
            "/things",
            &headers,
            &body,
        );
        // Threshold below the body length, so this one is on disk.
        let spooled = SpooledBody::from_bytes(body, 4096).unwrap();
        assert!(matches!(spooled, SpooledBody::Spooled { .. }));
        let streamed = spooled_payload_hash(
            "endpoint",
            &connection,
            &Method::POST,
            "/things",
            &headers,
            &spooled,
        )
        .unwrap();
        assert_eq!(inline, streamed);
    }

    #[test]
    fn endpoint_session_accounting_decodes_buffered_response_lengths() {
        let utf8 = ExecOutcome {
            status: 200,
            body: json!({
                "status": 200,
                "body": "hello",
                "body_encoding": "utf8",
            }),
        };
        assert_eq!(outcome_body_len(&utf8), 5);

        let binary = ExecOutcome {
            status: 200,
            body: json!({
                "status": 200,
                "body": "AAECAw==",
                "body_encoding": "base64",
            }),
        };
        assert_eq!(outcome_body_len(&binary), 4);
        assert_eq!(
            outcome_body_len(&ExecOutcome {
                status: 502,
                body: json!({"reason": "upstream_error"}),
            }),
            0
        );
    }

    #[test]
    fn direct_response_credentials_follow_policy_and_preserve_cookie_fields() {
        let outcome = || ExecOutcome {
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
        };
        let contained = translate_outcome(outcome(), &Method::GET, false);
        assert!(!contained.headers().contains_key(http::header::SET_COOKIE));

        let response = translate_outcome(outcome(), &Method::GET, true);

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

    #[tokio::test]
    async fn invalid_cached_base64_is_an_upstream_error() {
        let response = translate_outcome(
            ExecOutcome {
                status: 200,
                body: json!({
                    "status": 200,
                    "headers": {},
                    "body": "not base64!",
                    "body_encoding": "base64",
                }),
            },
            &Method::GET,
            false,
        );
        assert_eq!(response.status(), http::StatusCode::BAD_GATEWAY);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["reason"], ErrorReason::UpstreamError.as_str());
    }

    #[test]
    fn every_credential_bearing_response_header_can_be_contained() {
        for name in [
            "set-cookie",
            "set-cookie2",
            "cookie",
            "cookie2",
            "www-authenticate",
            "proxy-authenticate",
            "authentication-info",
            "proxy-authentication-info",
            "authorization",
            "proxy-authorization",
        ] {
            let name = HeaderName::from_bytes(name.as_bytes()).unwrap();
            assert!(
                !response_header_is_relayable(&name, false),
                "{name} escaped the configured containment boundary"
            );
            assert!(response_header_is_relayable(&name, true));
        }
        assert!(response_header_is_relayable(
            &http::header::CONTENT_TYPE,
            false
        ));
    }

    #[test]
    fn direct_head_and_not_modified_responses_preserve_upstream_length() {
        let outcome = || ExecOutcome {
            status: 200,
            body: json!({
                "status": 200,
                "headers": { "content-length": "1234" },
                "body": "",
                "body_encoding": "utf8",
            }),
        };
        let head = translate_outcome(outcome(), &Method::HEAD, false);
        assert_eq!(head.headers()[http::header::CONTENT_LENGTH], "1234");

        let not_modified = translate_outcome(
            ExecOutcome {
                status: 200,
                body: json!({
                    "status": 304,
                    "headers": { "content-length": "1234" },
                    "body": "",
                    "body_encoding": "utf8",
                }),
            },
            &Method::GET,
            false,
        );
        assert_eq!(not_modified.headers()[http::header::CONTENT_LENGTH], "1234");

        let get = translate_outcome(outcome(), &Method::GET, false);
        assert_ne!(
            get.headers()
                .get(http::header::CONTENT_LENGTH)
                .and_then(|value| value.to_str().ok()),
            Some("1234")
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

        let plaintext = ("http", "api.github.com", None::<u16>);
        let upgrade = Url::parse("https://api.github.com/next").unwrap();
        assert!(same_pinned_authority(
            &upgrade,
            plaintext.0,
            plaintext.1,
            plaintext.2
        ));
        let upgrade_wrong_port = Url::parse("https://api.github.com:8443/next").unwrap();
        assert!(!same_pinned_authority(
            &upgrade_wrong_port,
            plaintext.0,
            plaintext.1,
            plaintext.2
        ));
    }

    #[test]
    fn payload_hash_normalizes_headers() {
        let conn = Uuid::new_v4();
        let a = payload_hash(
            "claude-code",
            &conn,
            &Method::POST,
            "/x",
            &[("Accept".into(), "json".into()), ("B".into(), "2".into())],
            b"body",
        );
        let b = payload_hash(
            "claude-code",
            &conn,
            &Method::POST,
            "/x",
            &[("b".into(), "2".into()), ("accept".into(), "json".into())],
            b"body",
        );
        assert_eq!(a, b);
        let c = payload_hash("claude-code", &conn, &Method::POST, "/x", &[], b"other");
        assert_ne!(a, c);
        let d = payload_hash(
            "claude-code",
            &Uuid::new_v4(),
            &Method::POST,
            "/x",
            &[],
            b"other",
        );
        assert_ne!(c, d);
        // A different self-reported label shares the identity's coalesce
        // namespace; the hash is what keeps its reuse of an id from being
        // replayed another label's outcome.
        let e = payload_hash("codex", &conn, &Method::POST, "/x", &[], b"other");
        assert_ne!(c, e);
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

    #[test]
    fn only_mcp_client_messages_are_replay_eligible() {
        let request = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {}
        });
        assert!(is_mcp_client_message(&request));
        assert!(is_mcp_client_message(&json!([
            request,
            {
                "jsonrpc": "2.0",
                "method": "notifications/initialized"
            }
        ])));

        assert!(!is_mcp_client_message(&json!({"not": "mcp"})));
        assert!(!is_mcp_client_message(&json!([])));
        assert!(!is_mcp_client_message(&json!([
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/list"
            },
            {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {}
            }
        ])));
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

    #[test]
    fn sse_early_exit_waits_for_the_matching_response_frame() {
        let bytes = concat!(
            "event: message\n",
            "data:{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\n",
            "data: {\"jsonrpc\":\"2.0\",\"id\":6,\"result\":{\"wrong\":true}}\r\n\r\n",
            "data: {\"jsonrpc\":\"2.0\",\"id\":7,\n",
            "data: \"result\":{\"ok\":true}}\n\n",
            "data: {\"jsonrpc\":\"2.0\",\"id\":8,\"result\":{}}\n\n",
        )
        .as_bytes();
        let end = matching_sse_response_end(bytes, &json!(7)).expect("matching frame");
        let relayed = &bytes[..end];
        assert!(String::from_utf8_lossy(relayed).contains("\"id\":7"));
        assert!(!String::from_utf8_lossy(relayed).contains("\"id\":8"));
        assert_eq!(matching_sse_response_end(bytes, &json!(9)), None);
    }
}
