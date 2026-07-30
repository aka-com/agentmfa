//! Postgres upstream TLS: what each `sslmode` accepts, what it refuses, and
//! what the broker records when TLS is lost.
//!
//! Every live Postgres test before this one used `PgSslMode::Disable`, so the
//! whole TLS surface — the verifiers, the private-CA path, the `prefer`
//! fallback — was reachable only by reading it. These drive a real rustls
//! server with certificates generated per test: one CA, a leaf it signed, and
//! a leaf it did not.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use aka_core::audit::AuditKind;
use aka_core::broker::Broker;
use aka_core::capability::{pg, TestError, TestErrorKind};
use aka_core::config::BrokerConfig;
use aka_core::events::BrokerEvents;
use aka_core::paths::Paths;
use aka_core::store::ConnectionSpec;
use aka_core::types::{ConnectionConfig, PgSslMode, SecretMeta};
use aka_core::vault::MemoryVault;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use zeroize::Zeroizing;

const PG_PASSWORD: &str = "s3cret-upstream";

/* -------------------------------- harness --------------------------------- */

struct TestEvents {
    confirms: AtomicUsize,
}

impl BrokerEvents for TestEvents {
    fn confirm_secret_read(&self, _secret: &SecretMeta) -> bool {
        true
    }
    fn confirm_action(&self, _description: &str) -> Option<aka_core::types::ConfirmationMethod> {
        self.confirms.fetch_add(1, Ordering::SeqCst);
        Some(aka_core::types::ConfirmationMethod::Waived)
    }
}

struct Harness {
    broker: Arc<Broker>,
    _dir: tempfile::TempDir,
}

async fn harness(config: BrokerConfig) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let broker = Broker::new(
        Paths::under(dir.path()),
        Arc::new(MemoryVault::new()),
        config,
        Arc::new(TestEvents {
            confirms: AtomicUsize::new(0),
        }),
    )
    .await
    .unwrap();
    Harness { broker, _dir: dir }
}

/// Add a pg connection pointed at `port` with the given TLS settings.
fn add_connection(
    broker: &Broker,
    host: &str,
    port: u16,
    sslmode: PgSslMode,
    ca_bundle: Option<String>,
) -> aka_core::types::Connection {
    broker
        .store
        .add_secret("PG_PASSWORD", Zeroizing::new(PG_PASSWORD.into()))
        .unwrap();
    let secret = broker.store.secret_by_name("PG_PASSWORD").unwrap();
    broker
        .store
        .add_connection(ConnectionSpec {
            name: "prod-db".into(),
            config: ConnectionConfig::Pg {
                host: host.into(),
                port,
                dbname: "app_production".into(),
                user: "app".into(),
                sslmode,
                trusted_ca_bundle_path: ca_bundle,
            },
            secrets: vec![secret.id],
        })
        .unwrap()
}

/* ------------------------------ certificates ------------------------------ */

struct Ca {
    params: rcgen::CertificateParams,
    key: rcgen::KeyPair,
    pem: String,
}

fn new_ca(name: &str) -> Ca {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec![name.to_string()]).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let pem = params.self_signed(&key).unwrap().pem();
    Ca { params, key, pem }
}

/// A leaf for `dns_name`, signed by `ca`.
fn leaf_signed_by(
    ca: &Ca,
    dns_name: &str,
) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let key = rcgen::KeyPair::generate().unwrap();
    let params = rcgen::CertificateParams::new(vec![dns_name.to_string()]).unwrap();
    let issuer = rcgen::Issuer::from_params(&ca.params, &ca.key);
    let cert = params.signed_by(&key, &issuer).unwrap();
    (
        vec![cert.der().clone()],
        PrivateKeyDer::try_from(key.serialize_der()).unwrap(),
    )
}

/// A leaf nothing else vouches for.
fn self_signed_leaf(dns_name: &str) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let key = rcgen::KeyPair::generate().unwrap();
    let params = rcgen::CertificateParams::new(vec![dns_name.to_string()]).unwrap();
    let cert = params.self_signed(&key).unwrap();
    (
        vec![cert.der().clone()],
        PrivateKeyDer::try_from(key.serialize_der()).unwrap(),
    )
}

fn bundle_file(dir: &std::path::Path, ca: &Ca) -> String {
    let path = dir.join("ca.pem");
    std::fs::write(&path, &ca.pem).unwrap();
    path.to_str().unwrap().to_string()
}

/* ----------------------------- fake pg server ----------------------------- */

fn frame(tag: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 5);
    out.push(tag);
    out.extend_from_slice(&((payload.len() + 4) as i32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn pair(name: &str, value: &str) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(name.as_bytes());
    out.push(0);
    out.extend_from_slice(value.as_bytes());
    out.push(0);
    out
}

/// How the fake answers the client's `SSLRequest`.
#[derive(Clone, Copy, PartialEq)]
enum SslAnswer {
    /// 'S' — proceed with a TLS handshake.
    Accept,
    /// 'N' — refuse, as a server built without TLS support does.
    Refuse,
}

/// Knobs the fake upstream needs so a test can hold the protocol still at the
/// exact moment it wants to act on the broker.
#[derive(Clone, Default)]
struct FakeOpts {
    /// Wait this long before answering a simple query, standing in for a slow
    /// `SELECT`, a big `COPY`, or a `CREATE INDEX`.
    query_delay: std::time::Duration,
    /// Block just before completing the startup exchange until notified, so a
    /// test can change policy while the dial is in flight.
    hold_startup: Option<Arc<tokio::sync::Notify>>,
}

/// Drive the startup + cleartext-password exchange to ReadyForQuery, then
/// answer whatever arrives until the peer goes away.
async fn serve_startup<S>(s: &mut S, opts: &FakeOpts) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    // StartupMessage.
    let mut len = [0u8; 4];
    s.read_exact(&mut len).await?;
    let len = i32::from_be_bytes(len) as usize;
    let mut body = vec![0u8; len - 4];
    s.read_exact(&mut body).await?;

    // AuthenticationCleartextPassword, then take whatever password arrives.
    s.write_all(&frame(b'R', &3i32.to_be_bytes())).await?;
    let mut head = [0u8; 5];
    s.read_exact(&mut head).await?;
    let mut payload = vec![0u8; i32::from_be_bytes(head[1..5].try_into().unwrap()) as usize - 4];
    s.read_exact(&mut payload).await?;
    if head[0] != b'p' {
        return Ok(());
    }

    // The broker has authenticated and is waiting on the startup completion:
    // the window a test uses to withdraw authority mid-establishment.
    if let Some(gate) = &opts.hold_startup {
        gate.notified().await;
    }

    let mut ready = frame(b'R', &0i32.to_be_bytes());
    ready.extend_from_slice(&frame(b'S', &pair("server_version", "16.2")));
    let mut keydata = Vec::new();
    keydata.extend_from_slice(&4242i32.to_be_bytes());
    keydata.extend_from_slice(&99i32.to_be_bytes());
    ready.extend_from_slice(&frame(b'K', &keydata));
    ready.extend_from_slice(&frame(b'Z', b"I"));
    s.write_all(&ready).await?;

    // Answer simple queries with an empty result so a client can complete a
    // round trip; anything else just keeps the connection open.
    let mut buf = vec![0u8; 4096];
    loop {
        let n = s.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        if buf[..n].contains(&b'Q') {
            // A backend that takes its time. The broker must not read this as
            // an idle session: no bytes flow either way while it runs.
            tokio::time::sleep(opts.query_delay).await;
            let mut out = frame(b'C', b"SELECT 0\x00");
            out.extend_from_slice(&frame(b'Z', b"I"));
            let _ = s.write_all(&out).await;
        }
        if buf[..n].first() == Some(&b'X') {
            return Ok(());
        }
    }
}

/// A Postgres server that terminates TLS with `chain`/`key`, or refuses it.
async fn fake_tls_pg(
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    answer: SslAnswer,
) -> u16 {
    fake_tls_pg_with(chain, key, answer, FakeOpts::default()).await
}

async fn fake_tls_pg_with(
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    answer: SslAnswer,
    opts: FakeOpts,
) -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let config = Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap(),
    );
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let config = config.clone();
            let opts = opts.clone();
            tokio::spawn(async move {
                // SSLRequest: Int32 len = 8, Int32 code = 80877103.
                let mut probe = [0u8; 8];
                if sock.read_exact(&mut probe).await.is_err() {
                    return;
                }
                if i32::from_be_bytes(probe[4..8].try_into().unwrap()) != 80877103 {
                    return;
                }
                match answer {
                    SslAnswer::Accept => {
                        if sock.write_all(b"S").await.is_err() {
                            return;
                        }
                        let acceptor = tokio_rustls::TlsAcceptor::from(config);
                        if let Ok(mut tls) = acceptor.accept(sock).await {
                            let _ = serve_startup(&mut tls, &opts).await;
                        }
                    }
                    SslAnswer::Refuse => {
                        if sock.write_all(b"N").await.is_err() {
                            return;
                        }
                        let _ = serve_startup(&mut sock, &opts).await;
                    }
                }
            });
        }
    });
    port
}

/// A listener that accepts and then says nothing, for deadline tests.
async fn black_hole() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((sock, _)) = listener.accept().await {
            held.push(sock);
        }
    });
    port
}

async fn fake_repeating_password_challenge() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let Ok((mut socket, _)) = listener.accept().await else {
            return;
        };
        let mut len = [0u8; 4];
        if socket.read_exact(&mut len).await.is_err() {
            return;
        }
        let mut startup = vec![0u8; i32::from_be_bytes(len) as usize - 4];
        if socket.read_exact(&mut startup).await.is_err() {
            return;
        }
        for _ in 0..16 {
            if socket
                .write_all(&frame(b'R', &3i32.to_be_bytes()))
                .await
                .is_err()
            {
                return;
            }
            let mut head = [0u8; 5];
            if socket.read_exact(&mut head).await.is_err() {
                return;
            }
            let mut password =
                vec![0u8; i32::from_be_bytes(head[1..5].try_into().unwrap()) as usize - 4];
            if socket.read_exact(&mut password).await.is_err() {
                return;
            }
        }
    });
    port
}

async fn fake_startup_metadata_flood() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let Ok((mut socket, _)) = listener.accept().await else {
            return;
        };
        let mut len = [0u8; 4];
        if socket.read_exact(&mut len).await.is_err() {
            return;
        }
        let mut startup = vec![0u8; i32::from_be_bytes(len) as usize - 4];
        if socket.read_exact(&mut startup).await.is_err() {
            return;
        }
        if socket
            .write_all(&frame(b'R', &0i32.to_be_bytes()))
            .await
            .is_err()
        {
            return;
        }
        let notice = vec![b'x'; 9 * 1024];
        for _ in 0..8 {
            if socket.write_all(&frame(b'N', &notice)).await.is_err() {
                return;
            }
        }
    });
    port
}

async fn test_pg(
    h: &Harness,
    connection: &aka_core::types::Connection,
) -> Result<String, TestError> {
    pg::test_upstream(&h.broker.store, connection)
        .await
        .map(|success| success.detail)
}

/// One read from the proxy, bounded so a wedged assertion fails as a test
/// failure rather than as a hung suite.
async fn read_reply(client: &mut TcpStream) -> Vec<u8> {
    let mut buf = vec![0u8; 8192];
    let n = tokio::time::timeout(std::time::Duration::from_secs(5), client.read(&mut buf))
        .await
        .expect("the proxy answered nothing before the test deadline")
        .expect("read failed");
    buf.truncate(n);
    buf
}

/// Connect to the ticket proxy, complete the 3.0 startup, and present `ticket`
/// as the password. Leaves the socket at the proxy's first post-auth reply.
async fn present_ticket(proxy_port: u16, ticket: &str) -> TcpStream {
    let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
    let mut body = 196608i32.to_be_bytes().to_vec();
    body.extend_from_slice(&pair("user", "ticket"));
    body.extend_from_slice(&pair("database", "app_production"));
    body.push(0);
    let mut startup = ((body.len() + 4) as i32).to_be_bytes().to_vec();
    startup.extend_from_slice(&body);
    client.write_all(&startup).await.unwrap();

    // AuthenticationCleartextPassword (R, 3) — 9 bytes.
    let mut head = [0u8; 9];
    client.read_exact(&mut head).await.unwrap();
    assert_eq!(head[0], b'R', "expected an auth request");

    let mut pw = ticket.as_bytes().to_vec();
    pw.push(0);
    client.write_all(&frame(b'p', &pw)).await.unwrap();
    client
}

/* ---------------------------------- tests --------------------------------- */

/// `require` encrypts but does not judge the certificate, which is what libpq
/// does and what the connection sheet says.
#[tokio::test]
async fn require_accepts_a_certificate_it_cannot_verify() {
    let (chain, key) = self_signed_leaf("db.internal");
    let port = fake_tls_pg(chain, key, SslAnswer::Accept).await;
    let h = harness(BrokerConfig::default()).await;
    let conn = add_connection(&h.broker, "127.0.0.1", port, PgSslMode::Require, None);

    let report = test_pg(&h, &conn).await.unwrap();
    assert!(report.contains("SELECT 1 succeeded"), "{report}");
    assert!(report.contains("PostgreSQL 16.2"), "{report}");
}

#[tokio::test]
async fn repeated_password_challenges_hit_the_auth_iteration_bound() {
    let port = fake_repeating_password_challenge().await;
    let h = harness(BrokerConfig::default()).await;
    let conn = add_connection(&h.broker, "127.0.0.1", port, PgSslMode::Disable, None);

    let error = test_pg(&h, &conn)
        .await
        .expect_err("the auth loop must stop");
    assert_eq!(error.kind, TestErrorKind::WrongProtocol);
    assert!(error.detail.contains("within 8 messages"), "{error}");
}

#[tokio::test]
async fn startup_metadata_hits_the_accumulation_bound() {
    let port = fake_startup_metadata_flood().await;
    let h = harness(BrokerConfig::default()).await;
    let conn = add_connection(&h.broker, "127.0.0.1", port, PgSslMode::Disable, None);

    let error = test_pg(&h, &conn)
        .await
        .expect_err("startup metadata must be bounded");
    assert_eq!(error.kind, TestErrorKind::WrongProtocol);
    assert!(error.detail.contains("64 KiB"), "{error}");
}

/// `verify-full` fails closed on a certificate no trusted root vouches for,
/// and says *why* — the fix is trusting the CA, not retrying.
#[tokio::test]
async fn verify_full_refuses_an_unverifiable_certificate() {
    let (chain, key) = self_signed_leaf("db.internal");
    let port = fake_tls_pg(chain, key, SslAnswer::Accept).await;
    let h = harness(BrokerConfig::default()).await;
    let conn = add_connection(&h.broker, "127.0.0.1", port, PgSslMode::VerifyFull, None);

    let error = test_pg(&h, &conn).await.expect_err("must refuse");
    assert_eq!(error.kind, TestErrorKind::CertUnverified, "{error:?}");
}

/// The private-CA path end to end: `verify-full` against a leaf the configured
/// bundle signed and whose SAN is the address actually dialed. This is the
/// configuration a user pinning an internal CA is trying to reach, and it had
/// no coverage at all.
#[tokio::test]
async fn verify_full_accepts_a_leaf_from_the_configured_ca_bundle() {
    let dir = tempfile::tempdir().unwrap();
    let ca = new_ca("AgentMFA Test CA");
    // An IP SAN, so `verify-full`'s name check is satisfied by the loopback
    // address the test can actually connect to.
    let (chain, key) = leaf_signed_by(&ca, "127.0.0.1");
    let port = fake_tls_pg(chain, key, SslAnswer::Accept).await;
    let bundle = bundle_file(dir.path(), &ca);

    let h = harness(BrokerConfig::default()).await;
    let conn = add_connection(
        &h.broker,
        "127.0.0.1",
        port,
        PgSslMode::VerifyFull,
        Some(bundle),
    );
    let report = test_pg(&h, &conn).await;
    assert!(report.is_ok(), "the pinned CA must be trusted: {report:?}");
}

/// `verify-full` still checks the name: the same private CA signing a leaf for
/// a different host is refused.
#[tokio::test]
async fn verify_full_refuses_a_bundle_signed_leaf_for_another_host() {
    let dir = tempfile::tempdir().unwrap();
    let ca = new_ca("AgentMFA Test CA");
    let (chain, key) = leaf_signed_by(&ca, "db.internal");
    let port = fake_tls_pg(chain, key, SslAnswer::Accept).await;
    let bundle = bundle_file(dir.path(), &ca);

    let h = harness(BrokerConfig::default()).await;
    let conn = add_connection(
        &h.broker,
        "127.0.0.1",
        port,
        PgSslMode::VerifyFull,
        Some(bundle),
    );
    let error = test_pg(&h, &conn).await.expect_err("name must not match");
    assert_eq!(error.kind, TestErrorKind::CertUnverified, "{error:?}");
}

/// `verify-ca` validates the chain but not the name, so a bundle-signed leaf
/// issued for another host is accepted — libpq's documented distinction, and
/// the case that proves the configured bundle is really being used as a trust
/// anchor.
#[tokio::test]
async fn verify_ca_accepts_a_bundle_signed_leaf_whose_name_does_not_match() {
    let dir = tempfile::tempdir().unwrap();
    let ca = new_ca("AgentMFA Test CA");
    let (chain, key) = leaf_signed_by(&ca, "db.internal");
    let port = fake_tls_pg(chain, key, SslAnswer::Accept).await;
    let bundle = bundle_file(dir.path(), &ca);

    let h = harness(BrokerConfig::default()).await;
    let conn = add_connection(
        &h.broker,
        "127.0.0.1",
        port,
        PgSslMode::VerifyCa,
        Some(bundle),
    );
    let report = test_pg(&h, &conn).await;
    assert!(report.is_ok(), "verify-ca ignores the name: {report:?}");
}

/// PG-3. A configured bundle replaces the trust store, so a leaf signed by a
/// *different* CA is refused even though that CA is perfectly valid — the
/// property that makes pinning an internal CA mean anything.
#[tokio::test]
async fn a_configured_bundle_refuses_a_leaf_signed_by_another_ca() {
    let dir = tempfile::tempdir().unwrap();
    let pinned = new_ca("Pinned CA");
    let other = new_ca("Some Other CA");
    let (chain, key) = leaf_signed_by(&other, "db.internal");
    let port = fake_tls_pg(chain, key, SslAnswer::Accept).await;
    let bundle = bundle_file(dir.path(), &pinned);

    let h = harness(BrokerConfig::default()).await;
    let conn = add_connection(
        &h.broker,
        "127.0.0.1",
        port,
        PgSslMode::VerifyCa,
        Some(bundle),
    );
    let error = test_pg(&h, &conn).await.expect_err("must refuse");
    assert_eq!(error.kind, TestErrorKind::CertUnverified, "{error:?}");
}

/// `verify-ca` with no bundle falls back to the public roots, which cannot
/// vouch for a private leaf.
#[tokio::test]
async fn verify_ca_without_a_bundle_uses_the_public_roots() {
    let ca = new_ca("Unpublished CA");
    let (chain, key) = leaf_signed_by(&ca, "db.internal");
    let port = fake_tls_pg(chain, key, SslAnswer::Accept).await;

    let h = harness(BrokerConfig::default()).await;
    let conn = add_connection(&h.broker, "127.0.0.1", port, PgSslMode::VerifyCa, None);
    let error = test_pg(&h, &conn).await.expect_err("must refuse");
    assert_eq!(error.kind, TestErrorKind::CertUnverified, "{error:?}");
}

/// `require` means TLS is not optional: a server that answers 'N' is refused
/// with the kind that names the disagreement.
#[tokio::test]
async fn require_refuses_a_server_that_declines_tls() {
    let (chain, key) = self_signed_leaf("db.internal");
    let port = fake_tls_pg(chain, key, SslAnswer::Refuse).await;
    let h = harness(BrokerConfig::default()).await;
    let conn = add_connection(&h.broker, "127.0.0.1", port, PgSslMode::Require, None);

    let error = test_pg(&h, &conn).await.expect_err("must refuse");
    assert_eq!(error.kind, TestErrorKind::TlsDeclined, "{error:?}");
}

/// `prefer` continues in clear text when the server declines TLS, which is
/// libpq's behaviour and deliberately kept.
#[tokio::test]
async fn prefer_falls_back_to_plaintext() {
    let (chain, key) = self_signed_leaf("db.internal");
    let port = fake_tls_pg(chain, key, SslAnswer::Refuse).await;
    let h = harness(BrokerConfig::default()).await;
    let conn = add_connection(&h.broker, "127.0.0.1", port, PgSslMode::Prefer, None);

    let report = test_pg(&h, &conn).await;
    assert!(report.is_ok(), "prefer continues in clear text: {report:?}");
}

/// A successful Test action must preserve the same degraded verdict as a
/// brokered session instead of repainting a plaintext fallback green.
#[tokio::test]
async fn testing_a_tls_downgrade_records_warning_health() {
    let (chain, key) = self_signed_leaf("db.internal");
    let port = fake_tls_pg(chain, key, SslAnswer::Refuse).await;
    let h = harness(BrokerConfig::default()).await;
    let conn = add_connection(&h.broker, "127.0.0.1", port, PgSslMode::Prefer, None);

    let report = h.broker.ui_test_connection(&conn.id).await.unwrap();
    assert!(report.ok, "{report:?}");
    assert!(
        report.detail.contains("traffic used plaintext"),
        "{report:?}"
    );
    let health = h.broker.health.get(&conn.id).expect("health recorded");
    assert_eq!(health.status, aka_core::types::HealthStatus::Warning);
    assert!(
        health.detail.contains("traffic used plaintext"),
        "{health:?}"
    );
}

/// PG-19, on the path that audits: a brokered session over a downgraded
/// connection writes a `TlsDowngraded` entry naming the connection.
#[tokio::test]
async fn a_downgraded_session_writes_an_audit_entry() {
    let (chain, key) = self_signed_leaf("db.internal");
    let port = fake_tls_pg(chain, key, SslAnswer::Refuse).await;
    let h = harness(BrokerConfig::default()).await;
    let conn = add_connection(&h.broker, "127.0.0.1", port, PgSslMode::Prefer, None);

    // Open a real brokered session through the ticket proxy.
    let (proxy_port, _task) = pg::start_proxy(h.broker.clone()).await.unwrap();
    let ticket = h.broker.data_plane.issue("test-agent", &conn);
    let mut client = present_ticket(proxy_port, &ticket).await;

    let reply = read_reply(&mut client).await;
    assert!(
        reply.contains(&b'Z'),
        "the session never reached ReadyForQuery: {:?}",
        String::from_utf8_lossy(&reply)
    );

    let entries = h.broker.audit.recent(50);
    let downgrade = entries
        .iter()
        .find(|e| e.kind == AuditKind::TlsDowngraded)
        .expect("a downgraded session must be recorded");
    assert_eq!(downgrade.connection.as_deref(), Some("prod-db"));
    assert!(
        downgrade.text.contains("clear text"),
        "the summary must say what happened: {:?}",
        downgrade.text
    );
    assert!(
        downgrade
            .detail
            .as_deref()
            .unwrap_or_default()
            .contains("prefer"),
        "the detail must name the setting to change: {:?}",
        downgrade.detail
    );
    // Health carries the caveat too, so the state is visible in the app and
    // not only in the log.
    let health = h.broker.health.get(&conn.id).expect("health recorded");
    assert_eq!(health.status, aka_core::types::HealthStatus::Warning);
    assert!(health.detail.contains("clear text"), "{:?}", health.detail);
}

/// PG-7. A host that accepts the connection and then never answers is bounded
/// by the broker's own upstream deadline on the **data path**, not by the OS
/// TCP timeout. Only the Test button was wrapped before, so the brokered
/// session hung while holding a redemption slot and `TestErrorKind::Timeout`
/// was unreachable from here.
#[tokio::test]
async fn an_unresponsive_host_hits_the_upstream_deadline_on_the_data_path() {
    let port = black_hole().await;
    let config = BrokerConfig {
        upstream_timeout: std::time::Duration::from_millis(300),
        ..Default::default()
    };
    let h = harness(config).await;
    let conn = add_connection(&h.broker, "127.0.0.1", port, PgSslMode::Disable, None);

    let (proxy_port, _task) = pg::start_proxy(h.broker.clone()).await.unwrap();
    let ticket = h.broker.data_plane.issue("test-agent", &conn);
    let mut client = present_ticket(proxy_port, &ticket).await;

    // The refusal has to arrive on its own, well inside a deadline that would
    // otherwise be the OS TCP timeout.
    let started = std::time::Instant::now();
    let reply = tokio::time::timeout(std::time::Duration::from_secs(10), read_reply(&mut client))
        .await
        .expect("the proxy must not hang waiting on a black-holed host");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "took {:?}",
        started.elapsed()
    );

    // 08001 is sqlclient_unable_to_establish_sqlconnection, and the reason
    // names the broker rather than leaving the driver to guess.
    assert!(
        reply.starts_with(b"E"),
        "{:?}",
        String::from_utf8_lossy(&reply)
    );
    let text = String::from_utf8_lossy(&reply);
    assert!(text.contains("08001"), "{text:?}");
    assert!(text.contains("upstream_connect_failed"), "{text:?}");

    // And it is recorded, with the timeout graded into health rather than left
    // as a stale green badge.
    let refusal = h
        .broker
        .audit
        .recent(20)
        .into_iter()
        .find(|e| e.kind == AuditKind::Denied)
        .expect("a refused session must be recorded");
    assert_eq!(refusal.outcome.as_deref(), Some("upstream_connect_failed"));
    let health = h.broker.health.get(&conn.id).expect("health recorded");
    assert!(
        health.detail.to_lowercase().contains("did not answer"),
        "{:?}",
        health.detail
    );
}

/// PG-8. An unauthenticated client that connects and says nothing must not be
/// able to hold a task, an fd, and a read buffer for as long as it likes — no
/// ticket is needed to reach this point.
#[tokio::test]
async fn a_silent_client_is_dropped_on_the_handshake_deadline() {
    let config = BrokerConfig {
        pg_handshake_timeout: std::time::Duration::from_millis(200),
        ..Default::default()
    };
    let h = harness(config).await;
    let (proxy_port, _task) = pg::start_proxy(h.broker.clone()).await.unwrap();

    let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
    // Send a truncated startup length and then nothing more.
    client.write_all(&[0, 0, 0, 64]).await.unwrap();

    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(std::time::Duration::from_secs(5), client.read(&mut buf))
        .await
        .expect("the deadline must close the socket")
        .unwrap_or(0);
    assert_eq!(n, 0, "the proxy should hang up, not answer");
}

/// PG-15. A 3.x minor the proxy does not implement is negotiated down rather
/// than met with a closed socket — PostgreSQL 18 opens with 3.2.
#[tokio::test]
async fn a_newer_protocol_minor_is_negotiated_down_to_three_zero() {
    let (chain, key) = self_signed_leaf("db.internal");
    let port = fake_tls_pg(chain, key, SslAnswer::Refuse).await;
    let h = harness(BrokerConfig::default()).await;
    // `prefer`, so the upstream leg still begins with the SSLRequest the fake
    // answers; the downstream negotiation under test is independent of it.
    let conn = add_connection(&h.broker, "127.0.0.1", port, PgSslMode::Prefer, None);
    let (proxy_port, _task) = pg::start_proxy(h.broker.clone()).await.unwrap();
    let ticket = h.broker.data_plane.issue("test-agent", &conn);

    let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
    // Protocol 3.2 (major 3, minor 2), plus an unknown `_pq_.*` option.
    let mut body = ((3i32 << 16) | 2).to_be_bytes().to_vec();
    body.extend_from_slice(&pair("user", "ticket"));
    body.extend_from_slice(&pair("_pq_.something", "1"));
    body.push(0);
    let mut startup = ((body.len() + 4) as i32).to_be_bytes().to_vec();
    startup.extend_from_slice(&body);
    client.write_all(&startup).await.unwrap();

    // NegotiateProtocolVersion first: highest supported minor 0, and the one
    // protocol option that went unhonoured.
    let reply = read_reply(&mut client).await;
    assert_eq!(reply[0], b'v', "{:?}", String::from_utf8_lossy(&reply));
    assert_eq!(i32::from_be_bytes(reply[5..9].try_into().unwrap()), 0);
    assert_eq!(i32::from_be_bytes(reply[9..13].try_into().unwrap()), 1);
    assert!(String::from_utf8_lossy(&reply[13..]).contains("_pq_.something"));

    // …and the connection then continues as 3.0: the ticket still works.
    let mut pw = ticket.into_bytes();
    pw.push(0);
    client.write_all(&frame(b'p', &pw)).await.unwrap();
    let reply = read_reply(&mut client).await;
    assert!(
        reply.contains(&b'Z'),
        "the negotiated-down session must complete: {:?}",
        String::from_utf8_lossy(&reply)
    );
}

/// A protocol this proxy cannot speak at all gets a SQLSTATE, not a dropped
/// socket that reads to the user as "the server went away".
#[tokio::test]
async fn an_unsupported_major_protocol_is_refused_with_a_sqlstate() {
    let h = harness(BrokerConfig::default()).await;
    let (proxy_port, _task) = pg::start_proxy(h.broker.clone()).await.unwrap();

    let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
    let mut body = (4i32 << 16).to_be_bytes().to_vec();
    body.push(0);
    let mut startup = ((body.len() + 4) as i32).to_be_bytes().to_vec();
    startup.extend_from_slice(&body);
    client.write_all(&startup).await.unwrap();

    let reply = read_reply(&mut client).await;
    let text = String::from_utf8_lossy(&reply);
    assert_eq!(reply[0], b'E', "{text:?}");
    // 0A000 is feature_not_supported.
    assert!(text.contains("0A000"), "{text:?}");
    assert!(text.contains("4.0"), "{text:?}");
}

/* --------------------- session lifetime and observation -------------------- */

/// Open a plaintext-upstream connection plus a running proxy, and hand back a
/// client that has already presented its ticket and read ReadyForQuery.
async fn live_session(h: &Harness, port: u16) -> (aka_core::types::Connection, TcpStream) {
    let conn = add_connection(&h.broker, "127.0.0.1", port, PgSslMode::Prefer, None);
    let (proxy_port, task) = pg::start_proxy(h.broker.clone()).await.unwrap();
    // The accept loop must outlive this helper.
    std::mem::forget(task);
    let ticket = h.broker.data_plane.issue("test-agent", &conn);
    let mut client = present_ticket(proxy_port, &ticket).await;
    let reply = read_reply(&mut client).await;
    assert!(
        reply.contains(&b'Z'),
        "session did not open: {:?}",
        String::from_utf8_lossy(&reply)
    );
    (conn, client)
}

/// PG-2. The idle timer measures a client that has stopped asking, not a
/// backend that is taking its time. A query outlasting the idle timeout used to
/// be torn down mid-flight, which is what made `pg_sleep`, a large `COPY`, and a
/// long `CREATE INDEX` unusable through the proxy.
#[tokio::test]
async fn a_slow_query_is_not_mistaken_for_an_idle_session() {
    let (chain, key) = self_signed_leaf("db.internal");
    let port = fake_tls_pg_with(
        chain,
        key,
        SslAnswer::Refuse,
        FakeOpts {
            query_delay: std::time::Duration::from_millis(1200),
            ..Default::default()
        },
    )
    .await;
    let config = BrokerConfig {
        // Four times shorter than the query it must not interrupt.
        session_idle_timeout: std::time::Duration::from_millis(300),
        ..Default::default()
    };
    let h = harness(config).await;
    let (_conn, mut client) = live_session(&h, port).await;

    client
        .write_all(&frame(b'Q', b"SELECT pg_sleep(1)\x00"))
        .await
        .unwrap();

    // The result arrives; nothing tears the session down while the backend owes
    // a reply.
    let mut seen = Vec::new();
    for _ in 0..4 {
        let reply = read_reply(&mut client).await;
        if reply.is_empty() {
            break;
        }
        seen.extend_from_slice(&reply);
        if seen.contains(&b'Z') {
            break;
        }
    }
    let text = String::from_utf8_lossy(&seen);
    assert!(seen.contains(&b'Z'), "no ReadyForQuery: {text:?}");
    assert!(
        !text.contains("idle_timeout"),
        "the slow query was reaped: {text:?}"
    );
}

/// PG-13, and the other half of PG-2: a session whose client really has gone
/// quiet is still reaped — and the teardown now says so in Postgres's own
/// terms instead of closing the socket without a word.
#[tokio::test]
async fn an_idle_session_is_reaped_with_an_admin_shutdown_error() {
    let (chain, key) = self_signed_leaf("db.internal");
    let port = fake_tls_pg(chain, key, SslAnswer::Refuse).await;
    let config = BrokerConfig {
        session_idle_timeout: std::time::Duration::from_millis(300),
        ..Default::default()
    };
    let h = harness(config).await;
    let (_conn, mut client) = live_session(&h, port).await;

    // Ask nothing at all.
    let reply = read_reply(&mut client).await;
    let text = String::from_utf8_lossy(&reply);
    assert_eq!(
        reply.first(),
        Some(&b'E'),
        "expected an ErrorResponse: {text:?}"
    );
    // 57P01 is admin_shutdown, which libpq and every driver already handle.
    assert!(text.contains("57P01"), "{text:?}");
    assert!(text.contains("idle_timeout"), "{text:?}");
}

/// PG-13 for the user's Close button: the same courtesy, with the reason the
/// user caused.
#[tokio::test]
async fn a_user_closed_session_says_why_it_ended() {
    let (chain, key) = self_signed_leaf("db.internal");
    let port = fake_tls_pg(chain, key, SslAnswer::Refuse).await;
    let h = harness(BrokerConfig::default()).await;
    let (_conn, mut client) = live_session(&h, port).await;

    let live = h.broker.sessions();
    assert_eq!(live.len(), 1, "{live:?}");
    assert!(h.broker.ui_close_session(live[0].id).unwrap());

    let reply = read_reply(&mut client).await;
    let text = String::from_utf8_lossy(&reply);
    assert_eq!(reply.first(), Some(&b'E'), "{text:?}");
    assert!(text.contains("57P01"), "{text:?}");
    assert!(text.contains("closed_by_user"), "{text:?}");
}

/// PG-14. Withdrawing access while the upstream dial is in flight must not
/// leave a session running against authority that was just revoked. The
/// teardown sweep cannot see a session that is not registered yet, so the
/// post-registration check is the only thing standing between the two.
#[tokio::test]
async fn access_revoked_during_establishment_refuses_the_session() {
    let gate = Arc::new(tokio::sync::Notify::new());
    let (chain, key) = self_signed_leaf("db.internal");
    let port = fake_tls_pg_with(
        chain,
        key,
        SslAnswer::Refuse,
        FakeOpts {
            hold_startup: Some(gate.clone()),
            ..Default::default()
        },
    )
    .await;
    let h = harness(BrokerConfig::default()).await;
    let conn = add_connection(&h.broker, "127.0.0.1", port, PgSslMode::Prefer, None);
    let (proxy_port, _task) = pg::start_proxy(h.broker.clone()).await.unwrap();
    let ticket = h.broker.data_plane.issue("test-agent", &conn);

    // Present the ticket; the proxy authenticates it and dials, where the fake
    // holds the startup exchange open.
    let mut client = present_ticket(proxy_port, &ticket).await;
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    // Withdraw access mid-dial. No session exists to sweep yet.
    assert!(h.broker.ui_set_tool_access(&conn.id, false).unwrap());

    // Let the dial finish. The proxy registers the session, sees the new policy
    // and retires it before ReadyForQuery goes out.
    gate.notify_waiters();

    let reply = read_reply(&mut client).await;
    let text = String::from_utf8_lossy(&reply);
    assert_eq!(reply.first(), Some(&b'E'), "expected a refusal: {text:?}");
    assert!(text.contains("28000"), "{text:?}");
    assert!(text.contains("denied_by_policy"), "{text:?}");
    assert!(
        h.broker.sessions().is_empty(),
        "the session must not survive: {:?}",
        h.broker.sessions()
    );
}

/// PG-30. With statement auditing on, the activity log answers "what ran" and
/// not only "how much data moved".
#[tokio::test]
async fn statements_reach_the_activity_log_when_enabled() {
    let (chain, key) = self_signed_leaf("db.internal");
    let port = fake_tls_pg(chain, key, SslAnswer::Refuse).await;
    let config = BrokerConfig {
        audit_pg_statements: true,
        ..Default::default()
    };
    let h = harness(config).await;
    let (_conn, mut client) = live_session(&h, port).await;

    client
        .write_all(&frame(b'Q', b"SELECT id FROM orders\x00"))
        .await
        .unwrap();
    let _ = read_reply(&mut client).await;
    // Extended-protocol statements are recorded too.
    client
        .write_all(&frame(b'P', b"s1\x00DROP TABLE audit_me\x00\x00\x00"))
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    drop(client);
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let entry = h
        .broker
        .audit
        .recent(20)
        .into_iter()
        .find(|e| e.kind == AuditKind::PgStatements)
        .expect("statements must be recorded");
    assert_eq!(entry.connection.as_deref(), Some("prod-db"));
    assert_eq!(entry.agent.as_deref(), Some("test-agent"));
    let detail = entry.detail.clone().unwrap_or_default();
    assert!(detail.contains("SELECT id FROM orders"), "{detail:?}");
    assert!(detail.contains("DROP TABLE audit_me"), "{detail:?}");
    assert_eq!(
        entry.fields.get("statements").and_then(|v| v.as_u64()),
        Some(2)
    );
}

/// Off by default: the count still reaches the log, the text does not. Storing
/// statement text is a retention decision, and SQL literals can carry
/// credentials and personal data.
#[tokio::test]
async fn statements_are_counted_but_not_quoted_by_default() {
    let (chain, key) = self_signed_leaf("db.internal");
    let port = fake_tls_pg(chain, key, SslAnswer::Refuse).await;
    let h = harness(BrokerConfig::default()).await;
    assert!(!h.broker.config.audit_pg_statements, "default must be off");
    let (_conn, mut client) = live_session(&h, port).await;

    client
        .write_all(&frame(b'Q', b"SELECT secret FROM vault\x00"))
        .await
        .unwrap();
    let _ = read_reply(&mut client).await;
    drop(client);
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let entry = h
        .broker
        .audit
        .recent(20)
        .into_iter()
        .find(|e| e.kind == AuditKind::PgStatements)
        .expect("the count is always recorded");
    assert_eq!(
        entry.fields.get("statements").and_then(|v| v.as_u64()),
        Some(1)
    );
    assert!(
        entry.detail.is_none(),
        "text must not be stored: {:?}",
        entry.detail
    );
    let whole = format!("{entry:?}");
    assert!(
        !whole.contains("SELECT secret"),
        "statement text leaked: {whole}"
    );
}
