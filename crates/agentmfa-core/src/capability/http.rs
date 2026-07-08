//! HTTP capability, `POST /v1/http` (DESIGN.md §4.1).
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
use serde_json::json;
use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::approvals::ExecOutcome;
use crate::audit::{AuditEntry, AuditKind, AuditLog};
use crate::capability::SpooledBody;
use crate::config::BrokerConfig;
use crate::store::Store;
use crate::template::Template;
use crate::wire::ErrorReason;
use crate::types::{Connection, ConnectionConfig};

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

/// Broker-controlled, non-overridable header denylist (§4.1): the injected
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

/// Path validation (§4.1): must begin with exactly one `/`; absolute URLs,
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

/// How the connection's rendered template is injected (§4.1): a header line
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
enum RenderedInjection {
    Header(HeaderName, HeaderValue),
    /// Raw query-string fragment (already percent-encoded by the template's
    /// `url(…)` transform), e.g. `token=abc%20def`.
    Query(Zeroizing<String>),
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
    /// per approval (§4).
    pub async fn run(self) -> ExecOutcome {
        let started = Instant::now();
        let outcome = self.run_inner().await;
        let upstream_status = outcome
            .body
            .get("status")
            .and_then(|s| s.as_u64())
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("broker:{}", outcome.status));
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

    async fn run_inner(&self) -> ExecOutcome {
        // Render the credential as late as possible; values are zeroized on
        // drop (§3).
        let ConnectionConfig::Api { template, .. } = &self.connection.config else {
            return broker_error(500, ErrorReason::WrongConnectionType, "not an api connection");
        };
        let (scheme, host, port) = pinned_base(&self.connection.config).expect("api config");

        let injection = match render_injection(&self.store, template).await {
            Ok(i) => i,
            Err(e) => return broker_error(502, ErrorReason::CredentialRenderFailed, e),
        };

        // Build the initial URL from parsed components, never string
        // concatenation (§4.1).
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
            return broker_error(400, ErrorReason::InvalidPath, "path escaped the pinned authority");
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
                    Err(e) => return broker_error(500, ErrorReason::BodyUnavailable, e.to_string()),
                }
            }

            let response = match request.send().await {
                Ok(r) => r,
                // Strip the URL from the error before it reaches the agent:
                // reqwest's Display embeds the full request URL, and a
                // query-param injection form (`?token={{url(SECRET)}}`) carries
                // the credential in that URL, so the raw error string would
                // leak the secret the broker exists to withhold (§1/§4.1).
                Err(e) if e.is_timeout() => {
                    return broker_error(504, ErrorReason::UpstreamTimeout, e.without_url().to_string())
                }
                Err(e) => {
                    return broker_error(502, ErrorReason::UpstreamError, e.without_url().to_string())
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
                                    // request from scratch (§4.1).
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
                // connection was configured for (§4.1).
                return relay_response(response, &self.config).await;
            }

            return relay_response(response, &self.config).await;
        }
    }
}

async fn render_injection(store: &Store, template_src: &str) -> Result<RenderedInjection, String> {
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
    // second header (§4.1).
    let header_name = HeaderName::from_bytes(name.trim().as_bytes())
        .map_err(|_| "rendered header name invalid".to_string())?;
    let header_value = HeaderValue::from_str(value.trim())
        .map_err(|_| "rendered header value invalid (control bytes?)".to_string())?;
    Ok(RenderedInjection::Header(header_name, header_value))
}

/// Relay `{status, headers, body}` to the agent, size-capping the body and
/// base64-encoding non-UTF-8 bodies (§4.1).
async fn relay_response(response: reqwest::Response, config: &BrokerConfig) -> ExecOutcome {
    let status = response.status().as_u16();
    let mut headers = serde_json::Map::new();
    for (name, value) in response.headers() {
        let value_str = String::from_utf8_lossy(value.as_bytes()).into_owned();
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
            // credential in the URL out of the agent-visible error (§4.1).
            Err(e) => return broker_error(502, ErrorReason::UpstreamError, e.without_url().to_string()),
        }
    }

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
/// retry matches byte-for-byte (§4).
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
