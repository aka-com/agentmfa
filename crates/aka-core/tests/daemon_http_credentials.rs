//! The HTTP plane's credential paths: redaction, reserved headers, the caps,
//! the direct endpoint's request line, and BYO-OAuth refresh.
//!
//! These were the review's biggest coverage hole: no test anywhere built an
//! `oauth: Some(..)` API connection, so `oauth.rs`'s refresh path, its failure
//! classification, and the health it grades were entirely unexecuted — and the
//! redaction needle that corrupts relayed bodies passed the existing unit tests
//! because every input they used also contained the full secret.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use aka_core::broker::Broker;
use aka_core::config::BrokerConfig;
use aka_core::events::BrokerEvents;
use aka_core::paths::Paths;
use aka_core::store::ConnectionSpec;
use aka_core::types::{ConnectionConfig, ConnectionHealth, HealthStatus, OAuthSpec, SecretMeta};
use aka_core::vault::MemoryVault;
use aka_core::{daemon, types::ConfirmationMethod};
use axum::routing::{any, get, post};
use axum::Router;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zeroize::Zeroizing;

const API_KEY: &str = "ghp_the_real_secret_value";

/* -------------------------------- harness --------------------------------- */

struct TestEvents;

impl BrokerEvents for TestEvents {
    fn confirm_secret_read(&self, _secret: &SecretMeta) -> bool {
        true
    }
    fn confirm_action(&self, _description: &str) -> Option<ConfirmationMethod> {
        Some(ConfirmationMethod::Waived)
    }
}

struct Harness {
    broker: Arc<Broker>,
    daemon: daemon::DaemonHandle,
    token: String,
    _dir: tempfile::TempDir,
}

async fn harness(config: BrokerConfig) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let broker = Broker::new(
        Paths::under(dir.path()),
        Arc::new(MemoryVault::new()),
        config,
        Arc::new(TestEvents),
    )
    .await
    .unwrap();
    let daemon = daemon::serve(broker.clone()).await.unwrap();
    let mut h = Harness {
        broker,
        daemon,
        token: String::new(),
        _dir: dir,
    };
    h.token = h.pair().await;
    h
}

impl Harness {
    /// Registration is immediate; every name receives the same shared key.
    async fn pair(&self) -> String {
        let (status, body) = self
            .raw("POST", "/v1/pair", None, json!({ "agent_name": "tester" }))
            .await;
        assert_eq!(status, 200, "pair failed: {body}");
        body["token"].as_str().unwrap().to_string()
    }

    /// One authenticated control-plane request over the broker's Unix socket.
    async fn post(&self, path: &str, body: Value) -> (u16, Value) {
        self.raw("POST", path, Some(&self.token), body).await
    }

    async fn raw(
        &self,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: Value,
    ) -> (u16, Value) {
        let text = body.to_string();
        let auth = match token {
            Some(token) => format!("Authorization: Bearer {token}\r\n"),
            None => String::new(),
        };
        let request = format!(
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\n{auth}\
             Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
            text.len()
        );
        let mut stream: tokio::net::UnixStream =
            tokio::net::UnixStream::connect(&self.daemon.socket_path)
                .await
                .unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).await.unwrap();
        let text = String::from_utf8_lossy(&raw).into_owned();
        let status: u16 = text
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let body = text
            .split_once("\r\n\r\n")
            .map(|(_, b)| b)
            .unwrap_or_default();
        let value = serde_json::from_str(body).unwrap_or(Value::Null);
        (status, value)
    }

    async fn call(&self, connection: &str, body: Value) -> (u16, Value) {
        let mut envelope = body;
        envelope["connection"] = json!(connection);
        self.post("/v1/http", envelope).await
    }

    fn health_of(&self, name: &str) -> Option<ConnectionHealth> {
        let id = self.broker.store.connection_by_name(name).unwrap().id;
        self.broker.health.get(&id)
    }
}

/* ------------------------------ fake upstream ----------------------------- */

struct Upstream {
    port: u16,
    /// Every `Authorization` header the upstream was presented, in order.
    seen_auth: Arc<std::sync::Mutex<Vec<String>>>,
}

/// An upstream that echoes, mentions bearer auth without ever containing the
/// secret, and can serve an oversized or slow body.
async fn upstream() -> Upstream {
    let seen_auth: Arc<std::sync::Mutex<Vec<String>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
    let record = seen_auth.clone();
    let app = Router::new()
        .route(
            "/docs",
            get(|| async {
                // Prose that talks *about* bearer auth. Contains no secret, so
                // nothing in it should ever be rewritten.
                axum::Json(json!({
                    "auth": "Send a Bearer token in the Authorization header",
                    "scheme": "Bearer",
                }))
            }),
        )
        .route(
            "/challenge",
            get(|| async {
                (
                    axum::http::StatusCode::UNAUTHORIZED,
                    [(
                        axum::http::header::WWW_AUTHENTICATE,
                        "Bearer realm=\"api\", error=\"invalid_token\"",
                    )],
                    "unauthorized",
                )
            }),
        )
        .route(
            "/reflect",
            get(|| async {
                // Actually reflects the secret: this one *must* be scrubbed.
                axum::Json(json!({ "you_sent": format!("Bearer {API_KEY}") }))
            }),
        )
        .route("/huge", get(|| async { "x".repeat(4 * 1024 * 1024) }))
        .route(
            "/echo",
            any(move |req: axum::extract::Request| {
                let record = record.clone();
                async move {
                    let (parts, body) = req.into_parts();
                    if let Some(value) = parts.headers.get(axum::http::header::AUTHORIZATION) {
                        record
                            .lock()
                            .unwrap()
                            .push(String::from_utf8_lossy(value.as_bytes()).into_owned());
                    }
                    let bytes = axum::body::to_bytes(body, 64 * 1024 * 1024).await.unwrap();
                    let headers: HashMap<String, String> = parts
                        .headers
                        .iter()
                        .map(|(k, v)| {
                            (
                                k.as_str().to_string(),
                                String::from_utf8_lossy(v.as_bytes()).into_owned(),
                            )
                        })
                        .collect();
                    axum::Json(json!({
                        "method": parts.method.as_str(),
                        "uri": parts.uri.to_string(),
                        "headers": headers,
                        "len": bytes.len(),
                    }))
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    Upstream { port, seen_auth }
}

/// A header-injected API connection with a real secret behind it.
fn api_connection(h: &Harness, name: &str, port: u16) {
    h.broker
        .store
        .add_secret("GITHUB_API_KEY", Zeroizing::new(API_KEY.into()))
        .unwrap();
    h.broker
        .store
        .add_connection(ConnectionSpec {
            name: name.into(),
            config: ConnectionConfig::Api {
                host: "127.0.0.1".into(),
                scheme: "http".into(),
                port: Some(port),
                trusted_ca_bundle_path: None,
                template: "Authorization: Bearer {{GITHUB_API_KEY}}".into(),
                mcp_path: None,
                oauth: None,
            },
            secrets: vec![],
        })
        .unwrap();
}

/* ---------------------------- API-1: redaction ---------------------------- */

/// The scheme word must not become a global needle. `Bearer` is not a secret,
/// and treating it as one rewrote every occurrence in every relayed body and
/// header — corrupting API documentation, MCP tool descriptions, and
/// `WWW-Authenticate` challenges that never contained the credential.
#[tokio::test]
async fn the_auth_scheme_word_is_not_redacted_from_relayed_bodies() {
    let up = upstream().await;
    let h = harness(BrokerConfig::default()).await;
    api_connection(&h, "github", up.port);

    let (status, body) = h
        .call("github", json!({ "method": "GET", "path": "/docs" }))
        .await;
    assert_eq!(status, 200, "{body}");
    let relayed = body["body"].as_str().unwrap_or_default();
    assert!(
        relayed.contains("Bearer token in the Authorization header"),
        "the scheme word was rewritten: {relayed}"
    );
    assert!(
        !relayed.contains("[REDACTED]"),
        "nothing in this body is a secret: {relayed}"
    );
}

/// The same, for a header the upstream sends. A `WWW-Authenticate` challenge
/// is exactly what a client needs to read to recover.
#[tokio::test]
async fn a_www_authenticate_challenge_survives_redaction() {
    let up = upstream().await;
    let h = harness(BrokerConfig::default()).await;
    api_connection(&h, "github", up.port);

    let (_, body) = h
        .call("github", json!({ "method": "GET", "path": "/challenge" }))
        .await;
    let challenge = body["headers"]["www-authenticate"]
        .as_str()
        .unwrap_or_default();
    assert!(
        challenge.starts_with("Bearer realm="),
        "the challenge was corrupted: {challenge}"
    );
}

/// And the credential itself is still scrubbed — the guarantee this whole
/// mechanism exists for.
#[tokio::test]
async fn a_reflected_credential_is_still_scrubbed() {
    let up = upstream().await;
    let h = harness(BrokerConfig::default()).await;
    api_connection(&h, "github", up.port);

    let (_, body) = h
        .call("github", json!({ "method": "GET", "path": "/reflect" }))
        .await;
    let relayed = body["body"].as_str().unwrap_or_default();
    assert!(
        !relayed.contains(API_KEY),
        "the secret was reflected back to the agent: {relayed}"
    );
    assert!(relayed.contains("[REDACTED]"), "{relayed}");
}

/* -------------------- API-2 / API-21: reserved headers -------------------- */

/// Nothing here can decompress, so a compressed response would reach the agent
/// as unreadable base64 the redactor also cannot scrub.
#[tokio::test]
async fn encoding_headers_are_reserved() {
    let up = upstream().await;
    let h = harness(BrokerConfig::default()).await;
    api_connection(&h, "github", up.port);

    for header in ["Accept-Encoding", "Content-Encoding"] {
        let (status, body) = h
            .call(
                "github",
                json!({
                    "method": "GET",
                    "path": "/echo",
                    "headers": { header: "gzip" },
                }),
            )
            .await;
        assert_eq!(status, 400, "{header}: {body}");
        assert_eq!(body["reason"], "reserved_header", "{header}: {body}");
    }
}

/// `authorization` is reserved for every API connection, not only the ones
/// whose template happens to inject it. A query-form connection used to let the
/// agent's own `Authorization` through to be attached upstream.
#[tokio::test]
async fn authorization_is_reserved_even_for_a_query_form_connection() {
    let up = upstream().await;
    let h = harness(BrokerConfig::default()).await;
    h.broker
        .store
        .add_secret("STREAM_TOKEN", Zeroizing::new("tok_abcdef123456".into()))
        .unwrap();
    h.broker
        .store
        .add_connection(ConnectionSpec {
            name: "feed".into(),
            config: ConnectionConfig::Api {
                host: "127.0.0.1".into(),
                scheme: "http".into(),
                port: Some(up.port),
                trusted_ca_bundle_path: None,
                template: "?token={{url(STREAM_TOKEN)}}".into(),
                mcp_path: None,
                oauth: None,
            },
            secrets: vec![],
        })
        .unwrap();

    let (status, body) = h
        .call(
            "feed",
            json!({
                "method": "GET",
                "path": "/echo",
                "headers": { "Authorization": "Bearer agents-own-token" },
            }),
        )
        .await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["reason"], "reserved_header", "{body}");
    assert!(
        up.seen_auth.lock().unwrap().is_empty(),
        "the agent's own Authorization must never reach the upstream"
    );
}

/* --------------------------- API-4: control cap --------------------------- */

/// The JSON-envelope plane buffers the body several times over, so its cap is
/// far below the endpoint plane's — and the refusal says where large uploads go.
#[tokio::test]
async fn the_control_plane_body_cap_names_the_direct_endpoint() {
    let up = upstream().await;
    let config = BrokerConfig {
        control_plane_request_cap: 4096,
        ..Default::default()
    };
    let h = harness(config).await;
    api_connection(&h, "github", up.port);

    let (status, body) = h
        .call(
            "github",
            json!({ "method": "POST", "path": "/echo", "body": "y".repeat(8192) }),
        )
        .await;
    assert_eq!(status, 413, "{body}");
    assert_eq!(body["reason"], "request_too_large", "{body}");
    let detail = body["detail"].as_str().unwrap_or_default();
    assert!(detail.contains("direct endpoint"), "{detail}");

    // Just under the cap still works, so the bound is the cap and not an
    // accidental refusal of everything.
    let (status, _) = h
        .call(
            "github",
            json!({ "method": "POST", "path": "/echo", "body": "y".repeat(1024) }),
        )
        .await;
    assert_eq!(status, 200);
}

/* ------------------------- API-6: render failures ------------------------- */

/// A credential that cannot be rendered fails every call, so it is conclusive
/// about the connection whatever kind it is. Gating the health write on `oauth`
/// left a plain API connection returning 502 forever behind a green badge.
#[tokio::test]
async fn a_render_failure_flips_health_on_a_non_oauth_connection() {
    let up = upstream().await;
    let h = harness(BrokerConfig::default()).await;
    api_connection(&h, "github", up.port);
    assert!(h.health_of("github").is_none(), "no health yet");

    // Replace the secret with a value that cannot form a header, so the
    // template renders but the credential does not.
    let secret = h.broker.store.secret_by_name("GITHUB_API_KEY").unwrap();
    h.broker
        .store
        .replace_secret_value(&secret.id, Zeroizing::new("bad\nvalue".into()))
        .unwrap();

    let (status, body) = h
        .call("github", json!({ "method": "GET", "path": "/echo" }))
        .await;
    assert_eq!(status, 502, "{body}");
    assert_eq!(body["reason"], "credential_render_failed", "{body}");

    let health = h.health_of("github").expect("a render failure is graded");
    assert_eq!(health.status, HealthStatus::NeedsReconnect, "{health:?}");
}

/* ------------------------ API-5 / API-30: BYO-OAuth ----------------------- */

/// A fake OAuth provider. `answer` decides what the token endpoint does, so a
/// test can drive the refused / unavailable / renewed cases apart.
struct TokenEndpoint {
    port: u16,
    hits: Arc<AtomicUsize>,
}

#[derive(Clone, Copy)]
enum TokenAnswer {
    /// A renewed access token.
    Renew,
    /// `invalid_grant`: the refresh token is spent. Conclusive.
    Refuse,
    /// A 503. The credential is probably fine; try later.
    Unavailable,
}

async fn token_endpoint(answer: TokenAnswer) -> TokenEndpoint {
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    let app = Router::new().route(
        "/token",
        post(move || {
            let counter = counter.clone();
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                match answer {
                    TokenAnswer::Renew => (
                        axum::http::StatusCode::OK,
                        axum::Json(json!({
                            "access_token": "renewed_access_token",
                            "refresh_token": "rt-rotated",
                            "expires_in": 3600,
                        })),
                    ),
                    TokenAnswer::Refuse => (
                        axum::http::StatusCode::BAD_REQUEST,
                        axum::Json(json!({ "error": "invalid_grant" })),
                    ),
                    TokenAnswer::Unavailable => (
                        axum::http::StatusCode::SERVICE_UNAVAILABLE,
                        axum::Json(json!({ "error": "temporarily_unavailable" })),
                    ),
                }
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    TokenEndpoint { port, hits }
}

/// A BYO-OAuth connection whose stored token set is already expired, so the
/// next call must refresh.
fn oauth_connection(h: &Harness, upstream_port: u16, token_port: u16, refresh: Option<&str>) {
    let expired = chrono::Utc::now() - chrono::Duration::hours(1);
    let mut tokens = json!({
        "access_token": "stale_access_token",
        "expires_at": expired.to_rfc3339(),
    });
    if let Some(refresh) = refresh {
        tokens["refresh_token"] = json!(refresh);
    }
    h.broker
        .store
        .add_secret("OAUTH_TOKENS", Zeroizing::new(tokens.to_string()))
        .unwrap();
    let secret = h.broker.store.secret_by_name("OAUTH_TOKENS").unwrap();
    h.broker
        .store
        .add_connection(ConnectionSpec {
            name: "slack".into(),
            config: ConnectionConfig::Api {
                host: "127.0.0.1".into(),
                scheme: "http".into(),
                port: Some(upstream_port),
                trusted_ca_bundle_path: None,
                // The token secret is bound through the template ref, which is
                // the shape `ui_oauth_connect` generates; the OAuth branch of
                // `render_connection_injection` then mints a fresh bearer from
                // the stored token set rather than rendering this.
                template: "Authorization: Bearer {{OAUTH_TOKENS}}".into(),
                mcp_path: None,
                oauth: Some(OAuthSpec {
                    auth_url: "http://127.0.0.1/authorize".into(),
                    token_url: format!("http://127.0.0.1:{token_port}/token"),
                    client_id: "client-abc".into(),
                    scopes: vec!["chat:write".into()],
                    extra_auth_params: Vec::new(),
                }),
            },
            secrets: vec![secret.id],
        })
        .unwrap();
}

/// The happy path, which nothing exercised before: an expired access token is
/// renewed at the provider and the *new* bearer rides the upstream leg.
#[tokio::test]
async fn an_expired_oauth_token_is_renewed_before_the_call() {
    let up = upstream().await;
    let provider = token_endpoint(TokenAnswer::Renew).await;
    let h = harness(BrokerConfig::default()).await;
    oauth_connection(&h, up.port, provider.port, Some("rt-1"));

    let (status, body) = h
        .call("slack", json!({ "method": "GET", "path": "/echo" }))
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(provider.hits.load(Ordering::SeqCst), 1);
    assert_eq!(
        up.seen_auth.lock().unwrap().clone(),
        vec!["Bearer renewed_access_token".to_string()],
        "the upstream must see the renewed token, not the stale one"
    );
}

/// A refused refresh is conclusive: reconnect language, needs-reconnect health,
/// and — the part that mattered — the spent refresh token is retired, so the
/// next call fails fast instead of firing another doomed token request. Leaving
/// it in place turned every subsequent call into a hot loop against the
/// provider that can get the client id throttled.
#[tokio::test]
async fn a_rejected_refresh_retires_the_grant_and_asks_for_a_reconnect() {
    let up = upstream().await;
    let provider = token_endpoint(TokenAnswer::Refuse).await;
    let h = harness(BrokerConfig::default()).await;
    oauth_connection(&h, up.port, provider.port, Some("rt-1"));

    let (status, body) = h
        .call("slack", json!({ "method": "GET", "path": "/echo" }))
        .await;
    assert_eq!(status, 502, "{body}");
    assert_eq!(body["reason"], "credential_render_failed", "{body}");
    assert_eq!(provider.hits.load(Ordering::SeqCst), 1);
    let health = h.health_of("slack").expect("graded");
    assert_eq!(health.status, HealthStatus::NeedsReconnect, "{health:?}");

    // The second call must not spend the dead grant again.
    let (status, _) = h
        .call("slack", json!({ "method": "GET", "path": "/echo" }))
        .await;
    assert_eq!(status, 502);
    assert_eq!(
        provider.hits.load(Ordering::SeqCst),
        1,
        "a retired refresh token must not be replayed at the provider"
    );
    assert!(
        up.seen_auth.lock().unwrap().is_empty(),
        "no call reached the upstream"
    );
}

/// A refresh the *network* prevented is not conclusive. Reporting it as a dead
/// grant told the user to re-consent a working connection because the provider
/// had a 30-second blip.
#[tokio::test]
async fn a_transient_refresh_failure_is_not_reported_as_needing_a_reconnect() {
    let up = upstream().await;
    let provider = token_endpoint(TokenAnswer::Unavailable).await;
    let h = harness(BrokerConfig::default()).await;
    oauth_connection(&h, up.port, provider.port, Some("rt-1"));

    let (status, body) = h
        .call("slack", json!({ "method": "GET", "path": "/echo" }))
        .await;
    assert_eq!(status, 502, "{body}");
    assert_eq!(body["reason"], "credential_refresh_unavailable", "{body}");
    let health = h.health_of("slack").expect("graded");
    assert_eq!(
        health.status,
        HealthStatus::Failed,
        "a passing outage is not a reason to re-consent: {health:?}"
    );

    // And the refresh token survives, so recovery is automatic.
    let (_, _) = h
        .call("slack", json!({ "method": "GET", "path": "/echo" }))
        .await;
    assert_eq!(
        provider.hits.load(Ordering::SeqCst),
        2,
        "a transient failure must keep retrying"
    );
}

/// Expired with nothing to refresh with: only a new sign-in helps, and it says
/// so without contacting the provider at all.
#[tokio::test]
async fn an_expired_token_with_no_refresh_grant_asks_for_a_reconnect() {
    let up = upstream().await;
    let provider = token_endpoint(TokenAnswer::Renew).await;
    let h = harness(BrokerConfig::default()).await;
    oauth_connection(&h, up.port, provider.port, None);

    let (status, body) = h
        .call("slack", json!({ "method": "GET", "path": "/echo" }))
        .await;
    assert_eq!(status, 502, "{body}");
    assert_eq!(body["reason"], "credential_render_failed", "{body}");
    assert_eq!(provider.hits.load(Ordering::SeqCst), 0);
    assert_eq!(
        h.health_of("slack").unwrap().status,
        HealthStatus::NeedsReconnect
    );
}

/* ------------------------ the direct endpoint's plane --------------------- */

/// Issue a direct endpoint and return `(base_url, secret)`.
async fn endpoint_for(h: &Harness, name: &str) -> (String, String) {
    let id = h.broker.store.connection_by_name(name).unwrap().id;
    let info = h.broker.ui_issue_endpoint(&id).await.unwrap();
    (info.dsn, info.secret)
}

/// One raw request line against the endpoint, so a test can send shapes no
/// well-behaved client would (an absolute URI, CONNECT, TRACE).
async fn endpoint_raw(base: &str, line: &str, secret: &str) -> (u16, String) {
    let addr = base.trim_start_matches("http://");
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let request = format!(
        "{line}\r\nHost: {addr}\r\nAuthorization: Bearer {secret}\r\n\
         Content-Length: 0\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.unwrap();
    let text = String::from_utf8_lossy(&raw).into_owned();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    (status, text)
}

/// API-8. The endpoint is a base URL, not a forward proxy. Reading only the path
/// out of a proxy-style request line silently rewrote it onto the pinned host,
/// so pointing `HTTP_PROXY` at the endpoint sent every host's traffic there with
/// the real credential injected.
#[tokio::test]
async fn the_endpoint_refuses_proxy_style_requests() {
    let up = upstream().await;
    let h = harness(BrokerConfig::default()).await;
    api_connection(&h, "github", up.port);
    let (base, secret) = endpoint_for(&h, "github").await;

    let (status, body) =
        endpoint_raw(&base, "GET http://evil.invalid/steal HTTP/1.1", &secret).await;
    assert_eq!(status, 400, "{body}");
    assert!(body.contains("forward proxy"), "{body}");

    let (status, body) = endpoint_raw(&base, "CONNECT evil.invalid:443 HTTP/1.1", &secret).await;
    assert_eq!(status, 400, "{body}");

    // Nothing reached the pinned upstream on either attempt.
    assert!(up.seen_auth.lock().unwrap().is_empty());
}

/// The endpoint and the control plane now share one method allow-list. TRACE was
/// refused on `/v1/http` and forwarded here, credential attached.
#[tokio::test]
async fn the_endpoint_and_the_control_plane_allow_the_same_methods() {
    let up = upstream().await;
    let h = harness(BrokerConfig::default()).await;
    api_connection(&h, "github", up.port);
    let (base, secret) = endpoint_for(&h, "github").await;

    for method in ["TRACE", "PROPFIND", "PURGE"] {
        let (status, body) =
            endpoint_raw(&base, &format!("{method} /echo HTTP/1.1"), &secret).await;
        assert_eq!(status, 400, "{method}: {body}");
        assert!(body.contains("unsupported method"), "{method}: {body}");
    }
    assert!(up.seen_auth.lock().unwrap().is_empty());

    // An allowed method still works.
    let (status, _) = endpoint_raw(&base, "GET /echo HTTP/1.1", &secret).await;
    assert_eq!(status, 200);
}

/// API-14. `/v1/http` charges the per-identity limiter on every call; this plane
/// charged nothing, so its only bound was the upload semaphores — a concurrency
/// limit a fast serial client never touches.
#[tokio::test]
async fn the_endpoint_plane_is_rate_limited() {
    let up = upstream().await;
    let config = BrokerConfig {
        per_identity_per_min: 3,
        ..Default::default()
    };
    let h = harness(config).await;
    api_connection(&h, "github", up.port);
    let (base, secret) = endpoint_for(&h, "github").await;

    for i in 0..3 {
        let (status, body) = endpoint_raw(&base, "GET /echo HTTP/1.1", &secret).await;
        assert_eq!(status, 200, "call {i} should be inside the budget: {body}");
    }
    let (status, body) = endpoint_raw(&base, "GET /echo HTTP/1.1", &secret).await;
    assert_eq!(status, 429, "{body}");
    assert!(body.to_lowercase().contains("retry-after"), "{body}");
    assert!(body.contains("rate_limited"), "{body}");
}

/// The budget is charged after authentication, so an unauthenticated prober
/// cannot spend a legitimate holder's allowance.
#[tokio::test]
async fn a_wrong_endpoint_secret_does_not_spend_the_budget() {
    let up = upstream().await;
    let config = BrokerConfig {
        per_identity_per_min: 2,
        ..Default::default()
    };
    let h = harness(config).await;
    api_connection(&h, "github", up.port);
    let (base, secret) = endpoint_for(&h, "github").await;

    for _ in 0..5 {
        let (status, _) = endpoint_raw(&base, "GET /echo HTTP/1.1", "end_wrong").await;
        assert_eq!(status, 401);
    }
    // The real holder still has its full budget.
    for i in 0..2 {
        let (status, body) = endpoint_raw(&base, "GET /echo HTTP/1.1", &secret).await;
        assert_eq!(status, 200, "call {i}: {body}");
    }
}

/// API-29. The endpoint secret is recoverable for a copy-back, but never from
/// `endpoints.json` — it lives in the vault under the endpoint's id.
#[tokio::test]
async fn the_endpoint_secret_is_not_written_to_the_state_file() {
    let up = upstream().await;
    let h = harness(BrokerConfig::default()).await;
    api_connection(&h, "github", up.port);
    let (_, secret) = endpoint_for(&h, "github").await;
    assert!(secret.starts_with("end_"));

    let on_disk = std::fs::read_to_string(h.broker.paths.endpoints_file()).unwrap();
    assert!(
        !on_disk.contains(&secret),
        "the state file must not be a second credential store"
    );

    // And it still reads back, so the copy-again affordance survives.
    let id = h.broker.store.connection_by_name("github").unwrap().id;
    let read = h.broker.ui_get_endpoint(&id).await.unwrap().unwrap();
    assert_eq!(read.secret, secret);
}

/// API-29, the half that matters. The previous test passes even if nothing was
/// ever written to the vault, because the issuing process still holds the
/// plaintext on its own in-memory record. What has to be true for a copy-again
/// to work after a restart is: the secret is *in the vault* under the endpoint
/// id, and the record reloaded from disk carries no plaintext — which is what
/// sends `endpoint_secret` down its vault branch.
#[tokio::test]
async fn the_endpoint_secret_is_recoverable_from_the_vault_after_a_reload() {
    use aka_core::vault::SecretVault as _;

    let up = upstream().await;
    let dir = tempfile::tempdir().unwrap();
    let vault: Arc<MemoryVault> = Arc::new(MemoryVault::new());
    let broker = Broker::new(
        Paths::under(dir.path()),
        vault.clone(),
        BrokerConfig::default(),
        Arc::new(TestEvents),
    )
    .await
    .unwrap();
    broker
        .store
        .add_secret("GITHUB_API_KEY", Zeroizing::new(API_KEY.into()))
        .unwrap();
    broker
        .store
        .add_connection(ConnectionSpec {
            name: "github".into(),
            config: ConnectionConfig::Api {
                host: "127.0.0.1".into(),
                scheme: "http".into(),
                port: Some(up.port),
                trusted_ca_bundle_path: None,
                template: "Authorization: Bearer {{GITHUB_API_KEY}}".into(),
                mcp_path: None,
                oauth: None,
            },
            secrets: vec![],
        })
        .unwrap();
    let id = broker.store.connection_by_name("github").unwrap().id;
    let issued = broker.ui_issue_endpoint(&id).await.unwrap();
    let endpoint_id = broker.endpoints.get_for_connection(&id).expect("issued").id;

    // 1. The plaintext really is in the vault, under the endpoint's id.
    let stored = vault.get(&endpoint_id).await.expect("vault holds it");
    assert_eq!(&*stored, &issued.secret);

    // 2. A registry reloaded from the same sealed file — what a restart does —
    //    carries only the hash, so the read-back has to consult the vault.
    // The seal key is a vault item, so a reader with the same vault can open the
    // same sealed file — exactly what a restarted broker does.
    let integrity = Arc::new(
        aka_core::integrity::StateIntegrity::open(&*vault.clone())
            .await
            .unwrap(),
    );
    let reloaded = aka_core::endpoints::EndpointRegistry::open(
        Paths::under(dir.path()).endpoints_file(),
        64,
        integrity,
    )
    .unwrap();
    let record = reloaded
        .get_for_connection(&id)
        .expect("the endpoint persisted");
    assert_eq!(record.secret_hash, {
        use sha2::{Digest as _, Sha256};
        Sha256::digest(issued.secret.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    });
    assert!(
        record.secret.is_empty(),
        "a reloaded record must carry no plaintext, or nothing changed"
    );
}
