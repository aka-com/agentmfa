//! End-to-end Postgres proxy tests: real daemon, an in-process fake
//! Postgres upstream (cleartext and SCRAM-SHA-256 server sides), and
//! a real `tokio-postgres` client against the proxied DSN.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aka_core::approvals::ApprovalRequest;
use aka_core::broker::{Broker, UiDecision};
use aka_core::config::BrokerConfig;
use aka_core::daemon;
use aka_core::events::BrokerEvents;
use aka_core::paths::Paths;
use aka_core::store::ConnectionSpec;
use aka_core::types::{
    ConfirmationMethod, ConnectionConfig, ConnectionKind, DecisionContext, DecisionSurface,
    PgSslMode, SecretMeta,
};
use aka_core::vault::MemoryVault;
use base64::Engine as _;
use hmac::{Hmac, Mac as _};
use http_body_util::BodyExt as _;
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_postgres::error::SqlState;
use tokio_postgres::{NoTls, SimpleQueryMessage};
use zeroize::Zeroizing;

const REAL_PG_PASSWORD: &str = "s3cr3t-pg-pass-77";

/* -------------------------------- harness --------------------------------- */

struct TestEvents {
    prompts: mpsc::UnboundedSender<ApprovalRequest>,
    secret_read_confirmations: Arc<AtomicUsize>,
}

impl BrokerEvents for TestEvents {
    fn prompt_raised(&self, request: &ApprovalRequest) {
        let _ = self.prompts.send(request.clone());
    }
    fn confirm_secret_read(&self, _secret: &SecretMeta) -> bool {
        self.secret_read_confirmations
            .fetch_add(1, Ordering::SeqCst);
        true
    }
    fn confirm_decision(
        &self,
        _request: &ApprovalRequest,
        _decision: UiDecision,
    ) -> Option<ConfirmationMethod> {
        Some(ConfirmationMethod::Waived)
    }
    fn confirm_action(&self, _description: &str) -> Option<ConfirmationMethod> {
        Some(ConfirmationMethod::Waived)
    }
}

/// The scripted user's decision attribution.
fn ctx() -> DecisionContext {
    DecisionContext::local(DecisionSurface::Harness)
}

struct Harness {
    broker: Arc<Broker>,
    daemon: daemon::DaemonHandle,
    prompts: mpsc::UnboundedReceiver<ApprovalRequest>,
    secret_read_confirmations: Arc<AtomicUsize>,
    _dir: tempfile::TempDir,
}

async fn harness(config: BrokerConfig) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::under(dir.path());
    let (tx, rx) = mpsc::unbounded_channel();
    let secret_read_confirmations = Arc::new(AtomicUsize::new(0));
    let broker = Broker::new(
        paths,
        Arc::new(MemoryVault::new()),
        config,
        Arc::new(TestEvents {
            prompts: tx,
            secret_read_confirmations: secret_read_confirmations.clone(),
        }),
    )
    .await
    .unwrap();
    let daemon = daemon::serve(broker.clone()).await.unwrap();
    Harness {
        broker,
        daemon,
        prompts: rx,
        secret_read_confirmations,
        _dir: dir,
    }
}

fn add_pg_connection(broker: &Broker, upstream_port: u16) {
    broker
        .store
        .add_secret("PG_PASSWORD", Zeroizing::new(REAL_PG_PASSWORD.into()))
        .unwrap();
    let secret = broker.store.secret_by_name("PG_PASSWORD").unwrap();
    broker
        .store
        .add_connection(ConnectionSpec {
            name: "prod-db".into(),
            config: ConnectionConfig::Pg {
                host: "127.0.0.1".into(),
                port: upstream_port,
                dbname: "app_production".into(),
                user: "app".into(),
                sslmode: PgSslMode::Disable,
                trusted_ca_bundle_path: None,
            },
            secrets: vec![secret.id],
        })
        .unwrap();
}

async fn uds_request(
    socket: &std::path::Path,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<Value>,
) -> (u16, Value) {
    let stream = tokio::net::UnixStream::connect(socket).await.unwrap();
    let io = hyper_util::rt::TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
    tokio::spawn(conn);
    let mut builder = hyper::Request::builder()
        .method(method)
        .uri(path)
        .header("host", "localhost");
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    let request = match body {
        Some(value) => builder
            .header("content-type", "application/json")
            .body(value.to_string())
            .unwrap(),
        None => builder.body(String::new()).unwrap(),
    };
    let response = sender.send_request(request).await.unwrap();
    let status = response.status().as_u16();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes)
            .unwrap_or(Value::String(String::from_utf8_lossy(&bytes).into_owned()))
    };
    (status, value)
}

impl Harness {
    async fn pair(&mut self) -> String {
        let socket = self.daemon.socket_path.clone();
        let call = tokio::spawn(async move {
            uds_request(
                &socket,
                "POST",
                "/v1/pair",
                &[],
                Some(json!({"agent_name": "claude-code"})),
            )
            .await
        });
        let prompt = tokio::time::timeout(Duration::from_secs(5), self.prompts.recv())
            .await
            .unwrap()
            .unwrap();
        self.broker
            .decide(&prompt.id, UiDecision::AllowOnce, &ctx())
            .unwrap();
        let (status, body) = call.await.unwrap();
        assert_eq!(status, 200);
        body["token"].as_str().unwrap().to_string()
    }

    /// POST /v1/pg/open and approve the prompt; returns (dsn, ticket).
    async fn open_pg(&mut self, token: &str) -> (String, String) {
        let socket = self.daemon.socket_path.clone();
        let auth = format!("Bearer {token}");
        let call = tokio::spawn(async move {
            uds_request(
                &socket,
                "POST",
                "/v1/pg/open",
                &[("authorization", &auth)],
                Some(json!({"connection": "prod-db"})),
            )
            .await
        });
        let prompt = tokio::time::timeout(Duration::from_secs(5), self.prompts.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(prompt.connection.as_ref().unwrap().name, "prod-db");
        self.broker
            .decide(&prompt.id, UiDecision::AllowOnce, &ctx())
            .unwrap();
        let (status, body) = call.await.unwrap();
        assert_eq!(status, 200, "open failed: {body}");
        (
            body["dsn"].as_str().unwrap().to_string(),
            body["ticket"].as_str().unwrap().to_string(),
        )
    }

    fn pg_conn_str(&self, ticket: &str) -> String {
        format!(
            "host=127.0.0.1 port={} user=ticket password={} dbname=app_production \
             application_name=agent-test sslmode=disable",
            self.daemon.pg_proxy_port, ticket
        )
    }
}

/* ------------------------------ wire helpers ------------------------------ */

fn be_i32(bytes: &[u8]) -> i32 {
    let mut arr = [0u8; 4];
    arr.copy_from_slice(&bytes[..4]);
    i32::from_be_bytes(arr)
}

fn put_cstr(buf: &mut Vec<u8>, s: &str) {
    buf.extend_from_slice(s.as_bytes());
    buf.push(0);
}

fn frame(tag: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 5);
    out.push(tag);
    out.extend_from_slice(&(payload.len() as i32 + 4).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// First NUL-terminated string in a payload.
fn cstr(payload: &[u8]) -> String {
    let end = payload
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(payload.len());
    String::from_utf8_lossy(&payload[..end]).into_owned()
}

fn parse_params(mut rest: &[u8]) -> Vec<(String, String)> {
    let mut params = Vec::new();
    loop {
        let name = cstr(rest);
        if name.is_empty() {
            return params;
        }
        rest = &rest[name.len() + 1..];
        let value = cstr(rest);
        rest = &rest[value.len() + 1..];
        params.push((name, value));
    }
}

async fn read_startup(s: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    s.read_exact(&mut len).await?;
    let len = be_i32(&len) as usize;
    let mut payload = vec![0u8; len - 4];
    s.read_exact(&mut payload).await?;
    Ok(payload)
}

async fn read_msg(s: &mut TcpStream) -> std::io::Result<(u8, Vec<u8>)> {
    let mut head = [0u8; 5];
    s.read_exact(&mut head).await?;
    let len = be_i32(&head[1..5]) as usize;
    let mut payload = vec![0u8; len - 4];
    s.read_exact(&mut payload).await?;
    Ok((head[0], payload))
}

fn error_msg(severity: &str, sqlstate: &str, message: &str) -> Vec<u8> {
    let mut p = Vec::new();
    p.push(b'S');
    put_cstr(&mut p, severity);
    p.push(b'V');
    put_cstr(&mut p, severity);
    p.push(b'C');
    put_cstr(&mut p, sqlstate);
    p.push(b'M');
    put_cstr(&mut p, message);
    p.push(0);
    frame(b'E', &p)
}

fn pair_payload(name: &str, value: &str) -> Vec<u8> {
    let mut p = Vec::new();
    put_cstr(&mut p, name);
    put_cstr(&mut p, value);
    p
}

/// RowDescription(x int4) + DataRow("1") + CommandComplete + ReadyForQuery.
fn select_one() -> Vec<u8> {
    let mut rd = Vec::new();
    rd.extend_from_slice(&1i16.to_be_bytes());
    put_cstr(&mut rd, "x");
    rd.extend_from_slice(&0i32.to_be_bytes()); // table oid
    rd.extend_from_slice(&0i16.to_be_bytes()); // attnum
    rd.extend_from_slice(&23i32.to_be_bytes()); // int4
    rd.extend_from_slice(&4i16.to_be_bytes()); // typlen
    rd.extend_from_slice(&(-1i32).to_be_bytes()); // typmod
    rd.extend_from_slice(&0i16.to_be_bytes()); // text format
    let mut dr = Vec::new();
    dr.extend_from_slice(&1i16.to_be_bytes());
    dr.extend_from_slice(&1i32.to_be_bytes());
    dr.extend_from_slice(b"1");
    let mut cc = Vec::new();
    put_cstr(&mut cc, "SELECT 1");
    let mut out = Vec::new();
    out.extend(frame(b'T', &rd));
    out.extend(frame(b'D', &dr));
    out.extend(frame(b'C', &cc));
    out.extend(frame(b'Z', b"I"));
    out
}

/* ---------------------------- fake Postgres ------------------------------- */

#[derive(Clone, Copy, PartialEq)]
enum FakeAuth {
    Cleartext,
    Scram,
}

type StartupParams = Vec<(String, String)>;

#[derive(Clone, Default)]
struct FakeState {
    startups: Arc<Mutex<Vec<StartupParams>>>,
    passwords: Arc<Mutex<Vec<String>>>,
    cancels: Arc<Mutex<Vec<(i32, i32)>>>,
    queries: Arc<Mutex<Vec<String>>>,
}

struct FakePg {
    port: u16,
    state: FakeState,
}

async fn fake_pg(auth: FakeAuth) -> FakePg {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let state = FakeState::default();
    let accept_state = state.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let st = accept_state.clone();
            tokio::spawn(async move {
                let _ = fake_conn(stream, auth, st).await;
            });
        }
    });
    FakePg { port, state }
}

async fn fake_conn(mut s: TcpStream, auth: FakeAuth, st: FakeState) -> std::io::Result<()> {
    // Pre-startup: decline SSLRequest/GSSENCRequest probes with 'N'; a
    // CancelRequest conn carries no StartupMessage.
    let params = loop {
        let payload = read_startup(&mut s).await?;
        match be_i32(&payload[..4]) {
            80877103 | 80877104 => s.write_all(b"N").await?,
            80877102 => {
                st.cancels
                    .lock()
                    .unwrap()
                    .push((be_i32(&payload[4..8]), be_i32(&payload[8..12])));
                return Ok(());
            }
            196608 => break parse_params(&payload[4..]),
            _ => return Ok(()),
        }
    };
    st.startups.lock().unwrap().push(params);

    match auth {
        FakeAuth::Cleartext => {
            s.write_all(&frame(b'R', &3i32.to_be_bytes())).await?;
            let (tag, payload) = read_msg(&mut s).await?;
            if tag != b'p' {
                return Ok(());
            }
            let password = cstr(&payload);
            st.passwords.lock().unwrap().push(password.clone());
            if password != REAL_PG_PASSWORD {
                s.write_all(&error_msg(
                    "FATAL",
                    "28P01",
                    "password authentication failed",
                ))
                .await?;
                return Ok(());
            }
        }
        FakeAuth::Scram => {
            if !scram_server(&mut s).await? {
                return Ok(());
            }
        }
    }

    // AuthenticationOk + ParameterStatus + BackendKeyData(4242,7777) + RFQ.
    let mut out = Vec::new();
    out.extend(frame(b'R', &0i32.to_be_bytes()));
    out.extend(frame(b'S', &pair_payload("server_version", "14.0")));
    out.extend(frame(b'S', &pair_payload("client_encoding", "UTF8")));
    let mut kd = Vec::new();
    kd.extend_from_slice(&4242i32.to_be_bytes());
    kd.extend_from_slice(&7777i32.to_be_bytes());
    out.extend(frame(b'K', &kd));
    out.extend(frame(b'Z', b"I"));
    s.write_all(&out).await?;

    // Simple-query serving loop.
    loop {
        let (tag, payload) = read_msg(&mut s).await?;
        match tag {
            b'Q' => {
                let sql = cstr(&payload);
                st.queries.lock().unwrap().push(sql.clone());
                if sql.contains("pg_sleep") {
                    // Park until a CancelRequest for OUR key arrives on
                    // another connection, or 10 s.
                    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
                    let mut cancelled = false;
                    while tokio::time::Instant::now() < deadline {
                        if st.cancels.lock().unwrap().contains(&(4242, 7777)) {
                            cancelled = true;
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                    if cancelled {
                        s.write_all(&error_msg(
                            "ERROR",
                            "57014",
                            "canceling statement due to user request",
                        ))
                        .await?;
                        s.write_all(&frame(b'Z', b"I")).await?;
                    } else {
                        s.write_all(&select_one()).await?;
                    }
                } else {
                    s.write_all(&select_one()).await?;
                }
            }
            b'X' => return Ok(()),
            _ => {}
        }
    }
}

/* --------------------------- fake SCRAM server ----------------------------- */

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// RFC 5802 Hi(): PBKDF2-HMAC-SHA-256, hand-rolled with hmac+sha2.
fn scram_hi(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(password).unwrap();
    mac.update(salt);
    mac.update(&1u32.to_be_bytes());
    let mut prev: [u8; 32] = mac.finalize().into_bytes().into();
    let mut out = prev;
    for _ in 1..iterations {
        prev = hmac_sha256(password, &prev);
        for (o, p) in out.iter_mut().zip(prev.iter()) {
            *o ^= p;
        }
    }
    out
}

/// Server side of RFC 5802/7677 SCRAM-SHA-256. Returns whether the client
/// proof verified.
async fn scram_server(s: &mut TcpStream) -> std::io::Result<bool> {
    let b64 = base64::engine::general_purpose::STANDARD;

    // AuthenticationSASL offering SCRAM-SHA-256.
    let mut p = Vec::new();
    p.extend_from_slice(&10i32.to_be_bytes());
    put_cstr(&mut p, "SCRAM-SHA-256");
    p.push(0);
    s.write_all(&frame(b'R', &p)).await?;

    // SASLInitialResponse: mechanism + i32 len + client-first-message.
    let (tag, payload) = read_msg(s).await?;
    assert_eq!(tag, b'p');
    let mechanism = cstr(&payload);
    assert_eq!(mechanism, "SCRAM-SHA-256");
    let rest = &payload[mechanism.len() + 1..];
    let data_len = be_i32(&rest[..4]) as usize;
    let client_first = String::from_utf8(rest[4..4 + data_len].to_vec()).unwrap();

    // gs2 header ("y,," / "n,,") + client-first-message-bare.
    let mut parts = client_first.splitn(3, ',');
    let flag = parts.next().unwrap();
    let authzid = parts.next().unwrap();
    let bare = parts.next().unwrap().to_string();
    let gs2 = format!("{flag},{authzid},");
    let client_nonce = bare
        .split(',')
        .find_map(|f| f.strip_prefix("r="))
        .unwrap()
        .to_string();

    let server_nonce = format!("{client_nonce}srv-nonce-0123456789");
    let salt = b"agentmfa-test-salt";
    let iterations = 4096u32;
    let server_first = format!("r={server_nonce},s={},i={iterations}", b64.encode(salt));
    let mut p = Vec::new();
    p.extend_from_slice(&11i32.to_be_bytes());
    p.extend_from_slice(server_first.as_bytes());
    s.write_all(&frame(b'R', &p)).await?;

    // SASLResponse: client-final-message.
    let (tag, payload) = read_msg(s).await?;
    assert_eq!(tag, b'p');
    let client_final = String::from_utf8(payload).unwrap();
    let (without_proof, proof_b64) = client_final.rsplit_once(",p=").unwrap();
    let proof = b64.decode(proof_b64).unwrap();
    let cbind = client_final
        .split(',')
        .find_map(|f| f.strip_prefix("c="))
        .unwrap();
    assert_eq!(cbind, b64.encode(gs2.as_bytes()), "channel binding input");
    let final_nonce = client_final
        .split(',')
        .find_map(|f| f.strip_prefix("r="))
        .unwrap();
    assert_eq!(final_nonce, server_nonce, "combined nonce");

    // Verify the proof against the REAL password.
    let salted = scram_hi(REAL_PG_PASSWORD.as_bytes(), salt, iterations);
    let client_key = hmac_sha256(&salted, b"Client Key");
    let stored_key = Sha256::digest(client_key);
    let auth_message = format!("{bare},{server_first},{without_proof}");
    let signature = hmac_sha256(&stored_key, auth_message.as_bytes());
    let recovered: Vec<u8> = proof
        .iter()
        .zip(signature.iter())
        .map(|(a, b)| a ^ b)
        .collect();
    if Sha256::digest(&recovered).as_slice() != stored_key.as_slice() {
        s.write_all(&error_msg(
            "FATAL",
            "28P01",
            "password authentication failed",
        ))
        .await?;
        return Ok(false);
    }

    // AuthenticationSASLFinal with the server signature.
    let server_key = hmac_sha256(&salted, b"Server Key");
    let server_sig = hmac_sha256(&server_key, auth_message.as_bytes());
    let mut p = Vec::new();
    p.extend_from_slice(&12i32.to_be_bytes());
    p.extend_from_slice(format!("v={}", b64.encode(server_sig)).as_bytes());
    s.write_all(&frame(b'R', &p)).await?;
    Ok(true)
}

/* ---------------------------------- tests --------------------------------- */

fn row_value(messages: &[SimpleQueryMessage]) -> Option<String> {
    messages.iter().find_map(|m| match m {
        SimpleQueryMessage::Row(row) => row.get(0).map(str::to_string),
        _ => None,
    })
}

#[tokio::test]
async fn open_flow_end_to_end_with_cleartext_upstream() {
    let mut h = harness(BrokerConfig::default()).await;
    let fake = fake_pg(FakeAuth::Cleartext).await;
    add_pg_connection(&h.broker, fake.port);
    let token = h.pair().await;
    let (dsn, ticket) = h.open_pg(&token).await;

    // Password-less DSN: the ticket travels out-of-band (PGPASSWORD).
    assert_eq!(
        dsn,
        format!(
            "postgres://ticket@127.0.0.1:{}/app_production?sslmode=disable",
            h.daemon.pg_proxy_port
        )
    );
    assert!(ticket.starts_with("tkt_"));
    assert!(!dsn.contains(&ticket), "ticket must not be in the DSN");

    let (client, connection) = tokio_postgres::connect(&h.pg_conn_str(&ticket), NoTls)
        .await
        .unwrap();
    let conn_task = tokio::spawn(connection);
    let rows = client.simple_query("SELECT 1").await.unwrap();
    assert_eq!(row_value(&rows).as_deref(), Some("1"));

    // The upstream saw the CONFIGURED user/dbname, the forwarded
    // application_name, and the REAL password, never the ticket.
    let startups = fake.state.startups.lock().unwrap().clone();
    assert_eq!(startups.len(), 1);
    let has = |k: &str, v: &str| {
        startups[0]
            .iter()
            .any(|(name, value)| name == k && value == v)
    };
    assert!(has("user", "app"), "startup params: {:?}", startups[0]);
    assert!(has("database", "app_production"));
    assert!(has("application_name", "agent-test"));
    assert_eq!(
        fake.state.passwords.lock().unwrap().clone(),
        vec![REAL_PG_PASSWORD.to_string()]
    );

    // Live session listed for the UI.
    let sessions = h.broker.sessions();
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].kind, ConnectionKind::Pg);
    assert_eq!(sessions[0].connection, "prod-db");

    // Client drop tears the session down.
    drop(client);
    let _ = tokio::time::timeout(Duration::from_secs(3), conn_task).await;
    tokio::time::timeout(Duration::from_secs(5), async {
        while !h.broker.sessions().is_empty() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("session should end after client drop");
}

#[tokio::test]
async fn wrong_ticket_is_rejected_with_invalid_password() {
    let mut h = harness(BrokerConfig::default()).await;
    let fake = fake_pg(FakeAuth::Cleartext).await;
    add_pg_connection(&h.broker, fake.port);
    let token = h.pair().await;
    let (_dsn, _ticket) = h.open_pg(&token).await;

    let err =
        match tokio_postgres::connect(&h.pg_conn_str("tkt_bogus0000000000000000000000"), NoTls)
            .await
        {
            Ok(_) => panic!("connect with a bogus ticket must fail"),
            Err(e) => e,
        };
    let db = err.as_db_error().expect("expected a database error");
    assert_eq!(db.code(), &SqlState::INVALID_PASSWORD);
    assert!(
        db.message().contains("unknown_ticket"),
        "message: {}",
        db.message()
    );
    // The upstream was never dialed.
    assert!(fake.state.startups.lock().unwrap().is_empty());
}

#[tokio::test]
async fn one_ticket_allows_concurrent_clients() {
    let mut h = harness(BrokerConfig::default()).await;
    let fake = fake_pg(FakeAuth::Cleartext).await;
    add_pg_connection(&h.broker, fake.port);
    let token = h.pair().await;
    let (_dsn, ticket) = h.open_pg(&token).await;

    let (c1, conn1) = tokio_postgres::connect(&h.pg_conn_str(&ticket), NoTls)
        .await
        .unwrap();
    tokio::spawn(conn1);
    let (c2, conn2) = tokio_postgres::connect(&h.pg_conn_str(&ticket), NoTls)
        .await
        .unwrap();
    tokio::spawn(conn2);

    assert_eq!(h.broker.sessions().len(), 2);
    assert_eq!(
        h.secret_read_confirmations.load(Ordering::SeqCst),
        1,
        "one approval ticket should require at most one credential-read confirmation"
    );
    // Each session has its own authenticated upstream connection.
    assert_eq!(fake.state.startups.lock().unwrap().len(), 2);
    for c in [&c1, &c2] {
        let rows = c.simple_query("SELECT 1").await.unwrap();
        assert_eq!(row_value(&rows).as_deref(), Some("1"));
    }
}

#[tokio::test]
async fn cancel_request_translates_to_the_upstream_key() {
    let mut h = harness(BrokerConfig::default()).await;
    let fake = fake_pg(FakeAuth::Cleartext).await;
    add_pg_connection(&h.broker, fake.port);
    let token = h.pair().await;
    let (_dsn, ticket) = h.open_pg(&token).await;

    let (client, connection) = tokio_postgres::connect(&h.pg_conn_str(&ticket), NoTls)
        .await
        .unwrap();
    tokio::spawn(connection);
    let cancel_token = client.cancel_token();

    let query = tokio::spawn(async move {
        let result = client.simple_query("SELECT pg_sleep(10)").await;
        (client, result)
    });

    // Wait until the fake upstream is executing the query.
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if fake
                .state
                .queries
                .lock()
                .unwrap()
                .iter()
                .any(|q| q.contains("pg_sleep"))
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("fake upstream should receive the query");

    // psql's Ctrl-C: a separate connection with the SYNTHESIZED key; the
    // proxy must translate it to the upstream's real (4242, 7777).
    cancel_token.cancel_query(NoTls).await.unwrap();

    let (_client, result) = tokio::time::timeout(Duration::from_secs(5), query)
        .await
        .unwrap()
        .unwrap();
    let err = result.unwrap_err();
    assert_eq!(err.code(), Some(&SqlState::QUERY_CANCELED));
    assert_eq!(
        fake.state.cancels.lock().unwrap().clone(),
        vec![(4242, 7777)],
        "upstream must see ITS OWN key, not the synthesized one"
    );
}

#[tokio::test]
async fn scram_upstream_auth_end_to_end() {
    let mut h = harness(BrokerConfig::default()).await;
    let fake = fake_pg(FakeAuth::Scram).await;
    add_pg_connection(&h.broker, fake.port);
    let token = h.pair().await;
    let (_dsn, ticket) = h.open_pg(&token).await;

    let (client, connection) = tokio_postgres::connect(&h.pg_conn_str(&ticket), NoTls)
        .await
        .unwrap();
    tokio::spawn(connection);
    let rows = client.simple_query("SELECT 1").await.unwrap();
    assert_eq!(row_value(&rows).as_deref(), Some("1"));

    let startups = fake.state.startups.lock().unwrap().clone();
    assert_eq!(startups.len(), 1);
    assert!(startups[0]
        .iter()
        .any(|(name, value)| name == "user" && value == "app"));
}

#[tokio::test]
async fn user_close_drops_the_client_connection() {
    let mut h = harness(BrokerConfig::default()).await;
    let fake = fake_pg(FakeAuth::Cleartext).await;
    add_pg_connection(&h.broker, fake.port);
    let token = h.pair().await;
    let (_dsn, ticket) = h.open_pg(&token).await;

    let (client, connection) = tokio_postgres::connect(&h.pg_conn_str(&ticket), NoTls)
        .await
        .unwrap();
    let conn_task = tokio::spawn(connection);
    let sessions = h.broker.sessions();
    assert_eq!(sessions.len(), 1);

    assert!(h.broker.ui_close_session(sessions[0].id).unwrap());
    // The agent's connection is dropped: its background task terminates.
    tokio::time::timeout(Duration::from_secs(3), conn_task)
        .await
        .expect("user close must drop the agent's connection")
        .unwrap()
        .ok();
    assert!(client.simple_query("SELECT 1").await.is_err());
    tokio::time::timeout(Duration::from_secs(3), async {
        while !h.broker.sessions().is_empty() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    assert!(!h.broker.ui_close_session(sessions[0].id).unwrap());
}

/// TCP may deliver the client's first 'Q' in the same segment as handshake
/// bytes; the splice must be seeded with the handshake reader's residual
/// buffer or the query is swallowed. A raw client pipelines the
/// PasswordMessage and the Query in a single write.
#[tokio::test]
async fn pipelined_first_query_survives_the_handoff() {
    let mut h = harness(BrokerConfig::default()).await;
    let fake = fake_pg(FakeAuth::Cleartext).await;
    add_pg_connection(&h.broker, fake.port);
    let token = h.pair().await;
    let (_dsn, ticket) = h.open_pg(&token).await;

    let mut s = TcpStream::connect(("127.0.0.1", h.daemon.pg_proxy_port))
        .await
        .unwrap();
    // StartupMessage.
    let mut body = Vec::new();
    body.extend_from_slice(&196608i32.to_be_bytes());
    put_cstr(&mut body, "user");
    put_cstr(&mut body, "ticket");
    put_cstr(&mut body, "database");
    put_cstr(&mut body, "app_production");
    body.push(0);
    let mut startup = Vec::new();
    startup.extend_from_slice(&(body.len() as i32 + 4).to_be_bytes());
    startup.extend_from_slice(&body);
    s.write_all(&startup).await.unwrap();

    // AuthenticationCleartextPassword.
    let (tag, payload) = read_msg(&mut s).await.unwrap();
    assert_eq!((tag, be_i32(&payload[..4])), (b'R', 3));

    // Pipeline PasswordMessage + Query in ONE segment.
    let mut pw = Vec::new();
    put_cstr(&mut pw, &ticket);
    let mut q = Vec::new();
    put_cstr(&mut q, "SELECT 1");
    let mut pipelined = frame(b'p', &pw);
    pipelined.extend(frame(b'Q', &q));
    s.write_all(&pipelined).await.unwrap();

    // AuthenticationOk … ReadyForQuery, then the query results.
    let mut saw_auth_ok = false;
    let mut saw_key_data = false;
    let mut row: Option<String> = None;
    let mut ready = 0;
    while ready < 2 {
        let (tag, payload) = tokio::time::timeout(Duration::from_secs(5), read_msg(&mut s))
            .await
            .expect("proxy must relay the pipelined query")
            .unwrap();
        match tag {
            b'R' if be_i32(&payload[..4]) == 0 => saw_auth_ok = true,
            b'K' => {
                saw_key_data = true;
                // Synthesized, not the upstream's real key.
                assert_ne!(
                    (be_i32(&payload[..4]), be_i32(&payload[4..8])),
                    (4242, 7777)
                );
            }
            b'D' => row = Some(cstr(&payload[6..])),
            b'Z' => ready += 1,
            _ => {}
        }
    }
    assert!(saw_auth_ok && saw_key_data);
    assert_eq!(row.as_deref(), Some("1"));
}
