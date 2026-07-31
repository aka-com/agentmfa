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
use aka_core::daemon;
use aka_core::events::BrokerEvents;
use aka_core::paths::Paths;
use aka_core::store::ConnectionSpec;
use aka_core::types::{ConnectionConfig, ConnectionHealth, HealthStatus, OAuthSpec, SignerSpec};
use aka_core::vault::MemoryVault;
use axum::routing::{any, get, post};
use axum::Router;
use rustls_pki_types::PrivateKeyDer;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zeroize::Zeroizing;

const API_KEY: &str = "ghp_the_real_secret_value";

/* -------------------------------- harness --------------------------------- */

struct TestEvents;

impl BrokerEvents for TestEvents {}

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

type SeenHeaders = Arc<std::sync::Mutex<Vec<HashMap<String, String>>>>;

struct Upstream {
    port: u16,
    /// Every `Authorization` header the upstream was presented, in order.
    seen_auth: Arc<std::sync::Mutex<Vec<String>>>,
    /// Every request's full header set, as the upstream saw it. Credentials
    /// must be asserted from here rather than from the relayed response: the
    /// relay scrubs them, which is the behaviour under test elsewhere.
    seen_headers: SeenHeaders,
}

impl Upstream {
    fn last_headers(&self) -> HashMap<String, String> {
        self.seen_headers
            .lock()
            .unwrap()
            .last()
            .cloned()
            .expect("the upstream received a request")
    }
}

/// An upstream that echoes, mentions bearer auth without ever containing the
/// secret, and can serve an oversized or slow body.
async fn upstream() -> Upstream {
    let seen_auth: Arc<std::sync::Mutex<Vec<String>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
    let record = seen_auth.clone();
    let seen_headers: SeenHeaders = Arc::new(std::sync::Mutex::new(Vec::new()));
    let record_headers = seen_headers.clone();
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
        .route(
            "/binary-safe",
            get(|| async {
                (
                    [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
                    vec![0, 1, 2, 0xff],
                )
            }),
        )
        .route(
            "/binary-reflect",
            get(|| async {
                let mut body = vec![0, 1, 2];
                body.extend_from_slice(API_KEY.as_bytes());
                body.push(0xff);
                (
                    [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
                    body,
                )
            }),
        )
        .route("/huge", get(|| async { "x".repeat(4 * 1024 * 1024) }))
        .route(
            "/slow",
            get(|| async {
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                "late"
            }),
        )
        .route(
            "/status/{code}",
            any(|axum::extract::Path(code): axum::extract::Path<u16>| async move {
                axum::http::StatusCode::from_u16(code)
                    .unwrap_or(axum::http::StatusCode::INTERNAL_SERVER_ERROR)
            }),
        )
        .route(
            "/redirect/{code}/{remaining}",
            any(
                |axum::extract::Path((code, remaining)): axum::extract::Path<(u16, u8)>| async move {
                    let location = if remaining > 1 {
                        format!("/redirect/{code}/{}", remaining - 1)
                    } else {
                        "/echo".to_string()
                    };
                    axum::http::Response::builder()
                        .status(code)
                        .header(axum::http::header::LOCATION, location)
                        .body(axum::body::Body::empty())
                        .unwrap()
                },
            ),
        )
        .route(
            "/echo",
            any(move |req: axum::extract::Request| {
                let record = record.clone();
                let record_headers = record_headers.clone();
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
                    record_headers.lock().unwrap().push(headers.clone());
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
    Upstream {
        port,
        seen_auth,
        seen_headers,
    }
}

async fn https_upstream() -> (tempfile::TempDir, u16, String) {
    let dir = tempfile::tempdir().unwrap();
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut ca_params = rcgen::CertificateParams::new(vec!["API Test CA".into()]).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key).unwrap();

    let leaf_key = rcgen::KeyPair::generate().unwrap();
    let leaf_params = rcgen::CertificateParams::new(vec!["127.0.0.1".into()]).unwrap();
    let issuer = rcgen::Issuer::from_params(&ca_params, &ca_key);
    let leaf = leaf_params.signed_by(&leaf_key, &issuer).unwrap();
    let ca_path = dir.path().join("api-ca.pem");
    std::fs::write(&ca_path, ca.pem()).unwrap();

    let tls = Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![leaf.der().clone()],
            PrivateKeyDer::try_from(leaf_key.serialize_der()).unwrap(),
        )
        .unwrap(),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let acceptor = tokio_rustls::TlsAcceptor::from(tls.clone());
            tokio::spawn(async move {
                let Ok(mut stream) = acceptor.accept(socket).await else {
                    return;
                };
                let mut request = vec![0u8; 8192];
                let _ = stream.read(&mut request).await;
                let body = "secure";
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    });
    (dir, port, ca_path.to_string_lossy().into_owned())
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
                test_path: None,
                oauth: None,
                signer: None,
                client_cert_path: None,
                client_key_path: None,
            },
            secrets: vec![],
        })
        .unwrap();
}

fn api_tls_connection(h: &Harness, name: &str, port: u16, ca: Option<String>) {
    h.broker
        .store
        .add_connection(ConnectionSpec {
            name: name.into(),
            config: ConnectionConfig::Api {
                host: "127.0.0.1".into(),
                scheme: "https".into(),
                port: Some(port),
                trusted_ca_bundle_path: ca,
                template: String::new(),
                mcp_path: None,
                test_path: None,
                oauth: None,
                signer: None,
                client_cert_path: None,
                client_key_path: None,
            },
            secrets: vec![],
        })
        .unwrap();
}

/* ------------------------------- API: SigV4 -------------------------------- */

const AWS_ACCESS_KEY: &str = "AKIDEXAMPLE";
const AWS_SECRET_KEY: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
const SIGV4_REGION: &str = "us-east-1";
const SIGV4_SERVICE: &str = "execute-api";

/// A SigV4-signed API connection. The secret access key is stored with a
/// trailing newline on purpose: pasted AWS keys often carry one, and an
/// untrimmed key corrupts every signature with no legible error.
fn sigv4_connection(h: &Harness, name: &str, port: u16) {
    h.broker
        .store
        .add_secret("AWS_ACCESS_KEY_ID", Zeroizing::new(AWS_ACCESS_KEY.into()))
        .unwrap();
    h.broker
        .store
        .add_secret(
            "AWS_SECRET_ACCESS_KEY",
            Zeroizing::new(format!("{AWS_SECRET_KEY}\n")),
        )
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
                template: String::new(),
                mcp_path: None,
                test_path: None,
                oauth: None,
                signer: Some(SignerSpec::AwsSigv4 {
                    region: SIGV4_REGION.into(),
                    service: SIGV4_SERVICE.into(),
                    access_key_ref: "AWS_ACCESS_KEY_ID".into(),
                    secret_key_ref: "AWS_SECRET_ACCESS_KEY".into(),
                    session_token_ref: None,
                }),
                client_cert_path: None,
                client_key_path: None,
            },
            secrets: vec![],
        })
        .unwrap();
}

/// Recompute the SigV4 signature from what the upstream actually received —
/// a test-local implementation, so a broker-side canonicalisation bug cannot
/// vouch for itself. Queries in these tests use pre-sorted, unreserved
/// key/value pairs so both sides canonicalise them identically.
fn expected_sigv4(
    method: &str,
    path_and_query: &str,
    received: &HashMap<String, String>,
    payload_sha256: &str,
) -> String {
    use hmac::Mac;
    type HmacSha256 = hmac::Hmac<sha2::Sha256>;
    let hex = |bytes: &[u8]| -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() };
    let mac = |key: &[u8], data: &str| -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(key).unwrap();
        mac.update(data.as_bytes());
        mac.finalize().into_bytes().to_vec()
    };
    let (path, query) = path_and_query
        .split_once('?')
        .unwrap_or((path_and_query, ""));
    let mut pairs: Vec<String> = query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            if pair.contains('=') {
                pair.to_string()
            } else {
                format!("{pair}=")
            }
        })
        .collect();
    pairs.sort();
    let amz_date = received["x-amz-date"].clone();
    let date = &amz_date[..8];
    // Every `x-amz-*` header the upstream saw is signed, plus host. Sorted by
    // name, which for these fixtures is plain lexicographic order.
    let mut signed: Vec<(String, String)> = received
        .iter()
        .filter(|(name, _)| name.starts_with("x-amz-"))
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect();
    signed.push(("host".to_string(), received["host"].clone()));
    signed.sort();
    let signed_names = signed
        .iter()
        .map(|(name, _)| name.as_str())
        .collect::<Vec<_>>()
        .join(";");
    let canonical_headers: String = signed
        .iter()
        .map(|(name, value)| format!("{name}:{value}\n"))
        .collect();
    let canonical = format!(
        "{method}\n{path}\n{}\n{canonical_headers}\n{signed_names}\n{payload_sha256}",
        pairs.join("&"),
    );
    let scope = format!("{date}/{SIGV4_REGION}/{SIGV4_SERVICE}/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        hex(&<sha2::Sha256 as sha2::Digest>::digest(
            canonical.as_bytes()
        )),
    );
    let key = mac(format!("AWS4{AWS_SECRET_KEY}").as_bytes(), date);
    let key = mac(&key, SIGV4_REGION);
    let key = mac(&key, SIGV4_SERVICE);
    let key = mac(&key, "aws4_request");
    format!(
        "AWS4-HMAC-SHA256 Credential={AWS_ACCESS_KEY}/{scope}, \
         SignedHeaders={signed_names}, Signature={}",
        hex(&mac(&key, &string_to_sign)),
    )
}

fn sha256_hex(bytes: &[u8]) -> String {
    <sha2::Sha256 as sha2::Digest>::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// HTTP-C3: a SigV4 connection signs the request at dispatch time, the
/// signature verifies against an independent recomputation of what the
/// upstream received, and the payload hash covers the actual body. The
/// stored secret key carries a trailing newline, which must not reach the
/// signing key.
///
/// Everything is asserted from the upstream's own record rather than the
/// relayed response, because the relay deliberately scrubs the signature
/// (see `a_reflected_sigv4_signature_is_scrubbed`).
#[tokio::test]
async fn sigv4_signature_verifies_and_covers_the_payload() {
    let up = upstream().await;
    let h = harness(BrokerConfig::default()).await;
    sigv4_connection(&h, "aws", up.port);

    let (status, body) = h
        .call(
            "aws",
            json!({ "method": "POST", "path": "/echo?a=1&b=2", "body": "payload" }),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let received = up.last_headers();

    assert_eq!(
        received["x-amz-content-sha256"],
        sha256_hex(b"payload"),
        "the signed payload hash must cover the actual body"
    );
    assert_eq!(
        received["authorization"],
        expected_sigv4("POST", "/echo?a=1&b=2", &received, &sha256_hex(b"payload")),
        "the broker's signature must verify against an independent recomputation"
    );
}

/// HTTP-C3: each redirect hop is re-signed. A 307 keeps the method and body;
/// the final hop's signature must verify against the *final* URI — the
/// original hop's signature could not, since the canonical request differs.
#[tokio::test]
async fn sigv4_resigns_each_redirect_hop() {
    let up = upstream().await;
    let h = harness(BrokerConfig::default()).await;
    sigv4_connection(&h, "aws", up.port);

    let (status, body) = h
        .call(
            "aws",
            json!({ "method": "POST", "path": "/redirect/307/1", "body": "payload" }),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let received = up.last_headers();
    assert_eq!(
        received["authorization"],
        expected_sigv4("POST", "/echo", &received, &sha256_hex(b"payload")),
        "the delivered hop must carry a signature over its own URI"
    );
}

/// GCP-1: a service-account connection mints a bearer token through the
/// key's own token endpoint, injects it on the upstream leg, serves the
/// second call from cache, and scrubs the token from reflected responses.
#[tokio::test]
async fn gcp_service_account_tokens_are_minted_injected_and_scrubbed() {
    // The token endpoint the SA key document points at, counting exchanges.
    let exchanges = Arc::new(AtomicUsize::new(0));
    let counted = exchanges.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let token_port = listener.local_addr().unwrap().port();
    let token_endpoint = Router::new().route(
        "/token",
        post(move |body: String| {
            let counted = counted.clone();
            async move {
                counted.fetch_add(1, Ordering::SeqCst);
                assert!(body.contains("grant-type%3Ajwt-bearer"), "{body}");
                axum::Json(json!({
                    "access_token": "ya29.e2e-minted-token",
                    "expires_in": 3600,
                    "token_type": "Bearer",
                }))
            }
        }),
    );
    tokio::spawn(async move {
        let _ = axum::serve(listener, token_endpoint).await;
    });

    let up = upstream().await;
    let h = harness(BrokerConfig::default()).await;
    // A throwaway key generated for this test only (the OsRng-via-ssh-key
    // pattern the SSH agent tests use).
    let test_key_pem = {
        use rsa::pkcs8::EncodePrivateKey as _;
        let key = rsa::RsaPrivateKey::new(&mut ssh_key::rand_core::OsRng, 2048).unwrap();
        use base64::Engine as _;
        format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            base64::engine::general_purpose::STANDARD
                .encode(key.to_pkcs8_der().unwrap().as_bytes())
        )
    };
    let key_json = json!({
        "type": "service_account",
        "client_email": "agent@project.iam.gserviceaccount.com",
        "private_key": test_key_pem,
        "token_uri": format!("http://127.0.0.1:{token_port}/token"),
    })
    .to_string();
    h.broker
        .store
        .add_secret("GCP_SA_KEY", Zeroizing::new(key_json))
        .unwrap();
    h.broker
        .store
        .add_connection(ConnectionSpec {
            name: "gcs".into(),
            config: ConnectionConfig::Api {
                host: "127.0.0.1".into(),
                scheme: "http".into(),
                port: Some(up.port),
                trusted_ca_bundle_path: None,
                template: String::new(),
                mcp_path: None,
                test_path: None,
                oauth: None,
                signer: Some(SignerSpec::GcpServiceAccount {
                    key_ref: "GCP_SA_KEY".into(),
                    scope: "https://www.googleapis.com/auth/devstorage.read_only".into(),
                }),
                client_cert_path: None,
                client_key_path: None,
            },
            secrets: vec![],
        })
        .unwrap();

    let (status, body) = h
        .call("gcs", json!({ "method": "GET", "path": "/echo" }))
        .await;
    assert_eq!(status, 200, "{body}");
    // The upstream saw the minted token…
    let received = up.last_headers();
    assert_eq!(received["authorization"], "Bearer ya29.e2e-minted-token");
    // …while the reflected echo reaching the agent has it scrubbed.
    let relayed = body.to_string();
    assert!(!relayed.contains("ya29.e2e-minted-token"), "{relayed}");
    assert!(relayed.contains("[REDACTED]"), "{relayed}");

    // A second call rides the cached token: one exchange total.
    let (status, _) = h
        .call("gcs", json!({ "method": "GET", "path": "/echo" }))
        .await;
    assert_eq!(status, 200);
    assert_eq!(
        exchanges.load(Ordering::SeqCst),
        1,
        "token served from cache"
    );
}

/// HTTP-C3: the broker owns the fields that carry the authentication. An
/// agent-supplied `x-amz-date` is replaced, not signed — otherwise the agent
/// could skew the signing clock — and `authorization` is refused outright by
/// the reserved-header rule.
#[tokio::test]
async fn sigv4_headers_are_broker_owned() {
    let up = upstream().await;
    let h = harness(BrokerConfig::default()).await;
    sigv4_connection(&h, "aws", up.port);

    let (status, body) = h
        .call(
            "aws",
            json!({
                "method": "GET",
                "path": "/echo",
                "headers": { "x-amz-date": "19700101T000000Z" },
            }),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let received = up.last_headers();
    assert_ne!(
        received["x-amz-date"], "19700101T000000Z",
        "the agent-supplied signing date must be replaced by the broker's"
    );
    assert_eq!(
        received["authorization"],
        expected_sigv4("GET", "/echo", &received, &sha256_hex(b"")),
    );

    let (status, body) = h
        .call(
            "aws",
            json!({
                "method": "GET",
                "path": "/echo",
                "headers": { "authorization": "Bearer mine" },
            }),
        )
        .await;
    assert_ne!(status, 200, "agent-supplied authorization must be refused");
    let _ = body;
}

/// HTTP-C3: an agent-supplied `x-amz-*` header that is *not* one of the
/// broker's own is forwarded and included in `SignedHeaders`. S3 rejects a
/// request whose `x-amz-*` fields are not covered by the signature, so
/// forwarding one unsigned would break the call rather than merely leave it
/// unauthenticated.
#[tokio::test]
async fn sigv4_signs_forwarded_amz_headers() {
    let up = upstream().await;
    let h = harness(BrokerConfig::default()).await;
    sigv4_connection(&h, "aws", up.port);

    let (status, body) = h
        .call(
            "aws",
            json!({
                "method": "PUT",
                "path": "/echo",
                "headers": { "x-amz-acl": "private" },
                "body": "object",
            }),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let received = up.last_headers();
    assert_eq!(received["x-amz-acl"], "private", "the header is forwarded");
    assert!(
        received["authorization"].contains("SignedHeaders=host;x-amz-acl;"),
        "a forwarded x-amz header must be signed: {}",
        received["authorization"]
    );
    assert_eq!(
        received["authorization"],
        expected_sigv4("PUT", "/echo", &received, &sha256_hex(b"object")),
    );
}

/// HTTP-C3: a SigV4 signature is itself a replayable credential for the
/// request it covers, so an upstream that reflects request headers must not
/// hand it back to the agent. Without scrubbing, the agent could replay the
/// signed request directly against AWS inside the clock-skew window, escaping
/// the audit, rate limit, and confirmation the broker exists to impose.
#[tokio::test]
async fn a_reflected_sigv4_signature_is_scrubbed() {
    let up = upstream().await;
    let h = harness(BrokerConfig::default()).await;
    sigv4_connection(&h, "aws", up.port);

    // `/echo` reflects every request header into its response body.
    let (status, body) = h
        .call("aws", json!({ "method": "GET", "path": "/echo" }))
        .await;
    assert_eq!(status, 200, "{body}");
    let signature = up.last_headers()["authorization"].clone();
    let signature_hex = signature.rsplit_once("Signature=").unwrap().1.to_string();
    let relayed = body.to_string();

    assert!(
        !relayed.contains(&signature),
        "the signature was reflected back to the agent: {relayed}"
    );
    assert!(
        !relayed.contains(&signature_hex),
        "the bare signature hex was reflected back to the agent: {relayed}"
    );
    // The access key ID is an identifier, not a credential: it stays legible
    // so IAM responses that legitimately mention key IDs are not corrupted.
    assert!(
        relayed.contains(AWS_ACCESS_KEY) || relayed.contains("[REDACTED]"),
        "the reflection was relayed in some form: {relayed}"
    );
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

/// Authentication challenges are returned by default. A connection can
/// contain them without corrupting the scheme word during credential
/// redaction.
#[tokio::test]
async fn a_www_authenticate_challenge_can_be_explicitly_contained() {
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

    let connection = h.broker.store.connection_by_name("github").unwrap();
    assert!(h
        .broker
        .ui_set_expose_response_credentials(&connection.id, false)
        .unwrap());
    let (_, body) = h
        .call("github", json!({ "method": "GET", "path": "/challenge" }))
        .await;
    assert!(
        body["headers"].get("www-authenticate").is_none(),
        "the configured boundary must contain authentication challenges: {body}"
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

#[tokio::test]
async fn safe_binary_responses_are_relayed_byte_for_byte() {
    let up = upstream().await;
    let h = harness(BrokerConfig::default()).await;
    api_connection(&h, "github", up.port);

    let (status, body) = h
        .call("github", json!({ "method": "GET", "path": "/binary-safe" }))
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["body_encoding"], "base64");
    use base64::Engine as _;
    assert_eq!(
        base64::engine::general_purpose::STANDARD
            .decode(body["body"].as_str().unwrap())
            .unwrap(),
        vec![0, 1, 2, 0xff],
    );
}

#[tokio::test]
async fn binary_responses_that_reflect_a_credential_are_refused() {
    let up = upstream().await;
    let h = harness(BrokerConfig::default()).await;
    api_connection(&h, "github", up.port);

    let (status, body) = h
        .call(
            "github",
            json!({ "method": "GET", "path": "/binary-reflect" }),
        )
        .await;
    assert_eq!(status, 502, "{body}");
    assert_eq!(body["reason"], "upstream_error");
    assert_eq!(
        body["detail"],
        "upstream binary response contained the injected credential; response refused",
    );
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
                test_path: None,
                oauth: None,
                signer: None,
                client_cert_path: None,
                client_key_path: None,
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

/// API-30: the broker's response ceiling and operation deadline are distinct,
/// machine-actionable outcomes rather than a truncated success or a hung call.
#[tokio::test]
async fn response_caps_and_upstream_deadlines_are_enforced() {
    let up = upstream().await;
    let config = BrokerConfig {
        response_cap: 1024,
        upstream_timeout: std::time::Duration::from_millis(100),
        upstream_operation_timeout: std::time::Duration::from_millis(250),
        ..Default::default()
    };
    let h = harness(config).await;
    api_connection(&h, "github", up.port);

    let (status, body) = h
        .call("github", json!({ "method": "GET", "path": "/huge" }))
        .await;
    assert_eq!(status, 502, "{body}");
    assert_eq!(body["reason"], "response_too_large");

    let (status, body) = h
        .call("github", json!({ "method": "GET", "path": "/slow" }))
        .await;
    assert_eq!(status, 504, "{body}");
    assert_eq!(body["reason"], "upstream_timeout");
    let health = h.health_of("github").expect("the timeout is graded");
    assert_eq!(health.status, HealthStatus::Failed, "{health:?}");
}

/// A destination that cannot be dialed is a connection failure, not an
/// inconclusive broker error that leaves a stale green badge behind.
#[tokio::test]
async fn upstream_dial_errors_are_recorded_as_failed_health() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let unused_port = listener.local_addr().unwrap().port();
    drop(listener);

    let h = harness(BrokerConfig::default()).await;
    api_connection(&h, "github", unused_port);

    let (status, body) = h
        .call("github", json!({ "method": "GET", "path": "/unreachable" }))
        .await;
    assert_eq!(status, 502, "{body}");
    assert_eq!(body["reason"], "upstream_error");
    let health = h.health_of("github").expect("the dial error is graded");
    assert_eq!(health.status, HealthStatus::Failed, "{health:?}");
}

/// API-30: every advertised method crosses the JSON plane, including a body
/// large enough to take the disk-spool branch.
#[tokio::test]
async fn all_advertised_methods_and_the_spool_threshold_reach_upstream() {
    let up = upstream().await;
    let config = BrokerConfig {
        spool_threshold: 32,
        control_plane_request_cap: 16 * 1024,
        ..Default::default()
    };
    let h = harness(config).await;
    api_connection(&h, "github", up.port);

    for method in ["PUT", "PATCH", "OPTIONS"] {
        let (status, body) = h
            .call(
                "github",
                json!({
                    "method": method,
                    "path": "/echo",
                    "body": "s".repeat(4096),
                }),
            )
            .await;
        assert_eq!(status, 200, "{method}: {body}");
        let echoed: Value = serde_json::from_str(body["body"].as_str().unwrap()).unwrap();
        assert_eq!(echoed["method"], method);
        assert_eq!(echoed["len"], 4096);
    }
}

/// API-9/API-30: all redirect status codes follow HTTP method rules, and a
/// same-origin chain stops exactly at the configured hop budget.
#[tokio::test]
async fn redirect_methods_and_budget_match_http_semantics() {
    let up = upstream().await;
    let config = BrokerConfig {
        max_redirects: 1,
        ..Default::default()
    };
    let h = harness(config).await;
    api_connection(&h, "github", up.port);

    for (code, expected_method) in [(301, "GET"), (303, "GET"), (307, "POST"), (308, "POST")] {
        let (status, body) = h
            .call(
                "github",
                json!({
                    "method": "POST",
                    "path": format!("/redirect/{code}/1"),
                    "body": "payload",
                }),
            )
            .await;
        assert_eq!(status, 200, "{code}: {body}");
        let echoed: Value = serde_json::from_str(body["body"].as_str().unwrap()).unwrap();
        assert_eq!(echoed["method"], expected_method, "redirect {code}");
    }

    let (status, body) = h
        .call(
            "github",
            json!({
                "method": "POST",
                "path": "/redirect/307/2",
                "body": "payload",
            }),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], 307, "the over-budget redirect is relayed");
}

/// API-30: ordinary upstream failures are relayed as upstream statuses, not
/// confused with broker failures.
#[tokio::test]
async fn upstream_429_and_5xx_statuses_are_relayed() {
    let up = upstream().await;
    let h = harness(BrokerConfig::default()).await;
    api_connection(&h, "github", up.port);
    for code in [429, 500, 503] {
        let (status, body) = h
            .call(
                "github",
                json!({ "method": "GET", "path": format!("/status/{code}") }),
            )
            .await;
        assert_eq!(status, 200, "{code}: {body}");
        assert_eq!(body["status"], code);
    }
}

/// API-11/API-11b/API-30: a private bundle is used by both real calls and the
/// Test action, while the same leaf is classified as an unverifiable
/// certificate without that bundle.
#[tokio::test]
async fn private_api_ca_is_honored_and_tls_failures_are_classified() {
    let (_certs, port, ca) = https_upstream().await;
    let h = harness(BrokerConfig::default()).await;
    api_tls_connection(&h, "private-api", port, Some(ca));
    api_tls_connection(&h, "untrusted-api", port, None);

    let (status, body) = h
        .call("private-api", json!({ "method": "GET", "path": "/" }))
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["body"], "secure");

    let test_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let trusted = h.broker.store.connection_by_name("private-api").unwrap();
    let report = aka_core::capability::http::test_upstream(
        &h.broker.store,
        &test_client,
        std::time::Duration::from_secs(2),
        &trusted,
    )
    .await;
    assert!(report.is_ok(), "{report:?}");

    let untrusted = h.broker.store.connection_by_name("untrusted-api").unwrap();
    let error = aka_core::capability::http::test_upstream(
        &h.broker.store,
        &test_client,
        std::time::Duration::from_secs(2),
        &untrusted,
    )
    .await
    .expect_err("the private leaf must not validate against public roots");
    assert_eq!(
        error.kind,
        aka_core::capability::TestErrorKind::CertUnverified,
        "{error:?}"
    );
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
                test_path: None,
                oauth: Some(OAuthSpec {
                    auth_url: "http://127.0.0.1/authorize".into(),
                    token_url: format!("http://127.0.0.1:{token_port}/token"),
                    client_id: "client-abc".into(),
                    scopes: vec!["chat:write".into()],
                    extra_auth_params: Vec::new(),
                    token_secret_id: None,
                }),
                signer: None,
                client_cert_path: None,
                client_key_path: None,
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

/// API-16. Even with confirmation disabled, the endpoint is pinned to the
/// connection version it admitted before reading a potentially slow upload.
/// A retarget during that upload must refuse rather than dispatching the
/// already-authorized body to the replacement host with its credential.
#[tokio::test]
async fn endpoint_retarget_during_upload_is_refused_without_confirmation() {
    let original = upstream().await;
    let replacement = upstream().await;
    let h = harness(BrokerConfig::default()).await;
    api_connection(&h, "github", original.port);
    let connection = h.broker.store.connection_by_name("github").unwrap();
    let (base, secret) = endpoint_for(&h, "github").await;
    let addr = base.trim_start_matches("http://");
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let request = format!(
        "POST /echo HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer {secret}\r\n\
         Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n"
    );
    stream.write_all(request.as_bytes()).await.unwrap();

    // Session registration happens before the body is consumed. Waiting for
    // it removes timing guesses from the retarget race.
    for _ in 0..100 {
        if !h.broker.sessions().is_empty() {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(
        !h.broker.sessions().is_empty(),
        "upload never reached admission"
    );

    let mut changed = connection.config.clone();
    let ConnectionConfig::Api { port, .. } = &mut changed else {
        unreachable!()
    };
    *port = Some(replacement.port);
    // Use the store boundary directly to isolate version pinning from the UI
    // facade's additional endpoint-revocation behavior.
    h.broker
        .store
        .update_connection(
            &connection.id,
            ConnectionSpec {
                name: connection.name.clone(),
                config: changed,
                secrets: vec![],
            },
        )
        .unwrap();

    stream.write_all(b"0\r\n\r\n").await.unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.unwrap();
    let text = String::from_utf8_lossy(&raw);
    assert!(text.starts_with("HTTP/1.1 403"), "{text}");
    assert!(
        replacement.seen_auth.lock().unwrap().is_empty(),
        "the admitted upload reached the replacement credential target"
    );
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
        per_identity_per_min: 3,
        ..Default::default()
    };
    let h = harness(config).await;
    api_connection(&h, "github", up.port);
    let (base, secret) = endpoint_for(&h, "github").await;

    for _ in 0..2 {
        let (status, _) = endpoint_raw(&base, "GET /echo HTTP/1.1", "end_wrong").await;
        assert_eq!(status, 401);
    }
    // The real holder still has its full budget.
    for i in 0..3 {
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
                test_path: None,
                oauth: None,
                signer: None,
                client_cert_path: None,
                client_key_path: None,
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
