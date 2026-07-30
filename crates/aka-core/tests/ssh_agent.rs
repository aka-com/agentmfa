//! End-to-end SSH agent tests: a real daemon, a real vault-stored private
//! key, and a stock ssh-agent-protocol client speaking to the per-open
//! `SSH_AUTH_SOCK` socket. Exercises identity listing, the user-pinned
//! signing oracle (accept + refuse), and session accounting — for both
//! ed25519 and RSA keys.

use std::path::Path;
use std::time::Duration;

use aka_core::broker::Broker;
use aka_core::config::BrokerConfig;
use aka_core::daemon;
use aka_core::events::BrokerEvents;
use aka_core::paths::Paths;
use aka_core::store::ConnectionSpec;
use aka_core::types::{ConfirmationMethod, ConnectionConfig, SecretMeta};
use aka_core::vault::MemoryVault;
use http_body_util::BodyExt as _;
use serde_json::{json, Value};
use signature::{Signer as _, Verifier as _};
use ssh_key::public::KeyData as PublicKeyData;
use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, HashAlg, LineEnding, PrivateKey, PublicKey, Signature};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::UnixStream;
use zeroize::Zeroizing;

/* ------------------------------ ssh-agent wire ---------------------------- */

const SSH_AGENT_FAILURE: u8 = 5;
const SSH_AGENT_SUCCESS: u8 = 6;
const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
const SSH_AGENT_SIGN_RESPONSE: u8 = 14;
const SSH_AGENTC_EXTENSION: u8 = 27;
const SSH_AGENT_RSA_SHA2_256: u32 = 2;
const SSH_AGENT_RSA_SHA2_512: u32 = 4;
const SSH_MSG_USERAUTH_REQUEST: u8 = 50;

fn put_string(buf: &mut Vec<u8>, s: &[u8]) {
    buf.extend_from_slice(&(s.len() as u32).to_be_bytes());
    buf.extend_from_slice(s);
}

fn frame(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 5);
    out.extend_from_slice(&((body.len() + 1) as u32).to_be_bytes());
    out.push(kind);
    out.extend_from_slice(body);
    out
}

async fn write_message(stream: &mut UnixStream, kind: u8, body: &[u8]) {
    stream.write_all(&frame(kind, body)).await.unwrap();
}

async fn read_message(stream: &mut UnixStream) -> (u8, Vec<u8>) {
    let mut len = [0u8; 4];
    stream.read_exact(&mut len).await.unwrap();
    let len = u32::from_be_bytes(len) as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await.unwrap();
    (buf[0], buf.split_off(1))
}

/// Take a length-prefixed SSH string off the front of a slice.
fn take_string(data: &[u8]) -> (&[u8], &[u8]) {
    let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    (&data[4..4 + len], &data[4 + len..])
}

/// Build the publickey `SSH_MSG_USERAUTH_REQUEST` blob an ssh client signs.
fn userauth_blob(user: &str, alg: &str, key_blob: &[u8], host_key: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    put_string(&mut b, b"test-session-id");
    b.push(SSH_MSG_USERAUTH_REQUEST);
    put_string(&mut b, user.as_bytes());
    put_string(&mut b, b"ssh-connection");
    put_string(&mut b, b"publickey-hostbound-v00@openssh.com");
    b.push(1); // has signature
    put_string(&mut b, alg.as_bytes());
    put_string(&mut b, key_blob);
    put_string(&mut b, host_key);
    b
}

/* -------------------------------- harness --------------------------------- */

struct TestEvents {
    /// How the scripted user answers login prompts. `None` takes the prompt
    /// and never answers it, so the deadline decides.
    approval: Option<aka_core::approvals::ApprovalDecision>,
    prompts: Arc<AtomicUsize>,
    /// The most recent prompt as the app would render it.
    last_prompt: Arc<Mutex<Option<aka_core::approvals::PendingApproval>>>,
    /// Set after construction: the registry lives on the broker these events
    /// are built into.
    broker: Mutex<Option<Arc<Broker>>>,
}

impl BrokerEvents for TestEvents {
    fn confirm_secret_read(&self, _secret: &SecretMeta) -> bool {
        true
    }
    fn confirm_action(&self, _description: &str) -> Option<ConfirmationMethod> {
        Some(ConfirmationMethod::Waived)
    }
    fn approval_requested(
        &self,
        pending: &aka_core::approvals::PendingApproval,
    ) -> aka_core::events::ApprovalHandling {
        self.prompts.fetch_add(1, Ordering::SeqCst);
        *self.last_prompt.lock().unwrap() = Some(pending.clone());
        if let (Some(decision), Some(broker)) = (self.approval, self.broker.lock().unwrap().clone())
        {
            broker.ui_respond_approval(&pending.id, decision).unwrap();
        }
        aka_core::events::ApprovalHandling::Taken
    }
}

struct Harness {
    broker: Arc<Broker>,
    daemon: daemon::DaemonHandle,
    /// How many login prompts the scripted user was shown.
    prompts: Arc<AtomicUsize>,
    /// The last of those prompts, for asserting on its content.
    last_prompt: Arc<Mutex<Option<aka_core::approvals::PendingApproval>>>,
    _dir: tempfile::TempDir,
}

async fn harness(config: BrokerConfig) -> Harness {
    harness_answering(config, None).await
}

async fn harness_answering(
    config: BrokerConfig,
    decision: Option<aka_core::approvals::ApprovalDecision>,
) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::under(dir.path());
    let prompts = Arc::new(AtomicUsize::new(0));
    let last_prompt = Arc::new(Mutex::new(None));
    let events = Arc::new(TestEvents {
        approval: decision,
        prompts: prompts.clone(),
        last_prompt: last_prompt.clone(),
        broker: Mutex::new(None),
    });
    let broker = Broker::new(paths, Arc::new(MemoryVault::new()), config, events.clone())
        .await
        .unwrap();
    *events.broker.lock().unwrap() = Some(broker.clone());
    let daemon = daemon::serve(broker.clone()).await.unwrap();
    Harness {
        broker,
        daemon,
        prompts,
        last_prompt,
        _dir: dir,
    }
}

/// Store `key` as the connection's private-key secret and register a
/// `prod-ssh` connection for `user` with the given pinned fingerprint
/// (empty = unpinned, trusted on first use).
fn add_ssh_connection_with_fingerprint(
    broker: &Broker,
    key: &PrivateKey,
    user: &str,
    host_key_fingerprint: String,
) {
    let pem = key.to_openssh(LineEnding::LF).unwrap();
    broker
        .store
        .add_secret("DEPLOY_SSH_KEY", Zeroizing::new(pem.to_string()))
        .unwrap();
    let secret = broker.store.secret_by_name("DEPLOY_SSH_KEY").unwrap();
    broker
        .store
        .add_connection(ConnectionSpec {
            name: "prod-ssh".into(),
            config: ConnectionConfig::Ssh {
                destination: Some("prod".into()),
                host: "prod.example.com".into(),
                port: 22,
                user: user.into(),
                host_key_fingerprint,
            },
            secrets: vec![secret.id],
        })
        .unwrap();
}

/// Register `prod-ssh` pinned to a fresh random host key; returns that key.
fn add_ssh_connection(broker: &Broker, key: &PrivateKey, user: &str) -> PrivateKey {
    let host_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    add_ssh_connection_with_fingerprint(
        broker,
        key,
        user,
        host_key
            .public_key()
            .fingerprint(HashAlg::Sha256)
            .to_string(),
    );
    host_key
}

fn add_passwordless_ssh_connection(broker: &Broker) -> PrivateKey {
    let host_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    broker
        .store
        .add_connection(ConnectionSpec {
            name: "prod-ssh".into(),
            config: ConnectionConfig::Ssh {
                destination: Some("prod".into()),
                host: "prod.example.com".into(),
                port: 22,
                user: "deploy".into(),
                host_key_fingerprint: host_key
                    .public_key()
                    .fingerprint(HashAlg::Sha256)
                    .to_string(),
            },
            secrets: vec![],
        })
        .unwrap();
    host_key
}

/// The `prod-ssh` connection's stored fingerprint ("" while unpinned).
fn stored_fingerprint(broker: &Broker) -> String {
    let conn = broker.store.connection_by_name("prod-ssh").unwrap();
    match conn.config {
        ConnectionConfig::Ssh {
            host_key_fingerprint,
            ..
        } => host_key_fingerprint,
        _ => unreachable!("prod-ssh is ssh"),
    }
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
        let (status, body) = uds_request(
            &self.daemon.socket_path,
            "POST",
            "/v1/pair",
            &[],
            Some(json!({"agent_name": "claude-code"})),
        )
        .await;
        assert_eq!(status, 200);
        body["token"].as_str().unwrap().to_string()
    }

    /// POST /v1/ssh/open (connections are enabled for agents by default);
    /// returns the auth_sock path and the full open-response body (its
    /// `host_key_fingerprint` is null while the connection is unpinned).
    async fn open_ssh(&mut self, token: &str) -> (String, Value) {
        let auth = format!("Bearer {token}");
        let (status, body) = uds_request(
            &self.daemon.socket_path,
            "POST",
            "/v1/ssh/open",
            &[("authorization", &auth)],
            Some(json!({"connection": "prod-ssh"})),
        )
        .await;
        assert_eq!(status, 200, "open failed: {body}");
        assert_eq!(body["user"], "deploy");
        assert_eq!(body["host"], "prod.example.com");
        assert_eq!(body["destination"], "prod");
        (body["auth_sock"].as_str().unwrap().to_string(), body)
    }

    /// Issue an SSH direct endpoint; its `dsn` is the stable
    /// `SSH_AUTH_SOCK` path.
    async fn issue_ssh_endpoint(&self) -> aka_core::broker::IssuedEndpointInfo {
        let conn = self.broker.store.connection_by_name("prod-ssh").unwrap();
        self.broker.ui_issue_endpoint(&conn.id).await.unwrap()
    }
}

/// Connect a fresh agent connection and session-bind `host_key` on it, in a
/// background task.
fn spawn_bind(auth_sock: &str, host_key: &PrivateKey) -> tokio::task::JoinHandle<(u8, UnixStream)> {
    let auth_sock = auth_sock.to_string();
    let host_key = host_key.clone();
    tokio::spawn(async move {
        let mut stream = UnixStream::connect(&auth_sock).await.unwrap();
        let kind = bind_host(&mut stream, &host_key).await;
        (kind, stream)
    })
}

/// List the agent's single identity; assert it matches `key`.
async fn assert_lists_identity(stream: &mut UnixStream, key: &PrivateKey) {
    write_message(stream, SSH_AGENTC_REQUEST_IDENTITIES, &[]).await;
    let (kind, body) = read_message(stream).await;
    assert_eq!(kind, SSH_AGENT_IDENTITIES_ANSWER);
    let nkeys = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
    assert_eq!(nkeys, 1);
    let (blob, rest) = take_string(&body[4..]);
    assert_eq!(blob, key.public_key().to_bytes().unwrap());
    let (comment, _) = take_string(rest);
    assert_eq!(comment, b"aka:prod-ssh");
}

/// Sign a userauth blob for `user`/`alg` with `flags`; return the raw
/// SIGN_RESPONSE (type, body).
async fn sign(stream: &mut UnixStream, key_blob: &[u8], data: &[u8], flags: u32) -> (u8, Vec<u8>) {
    let mut body = Vec::new();
    put_string(&mut body, key_blob);
    put_string(&mut body, data);
    body.extend_from_slice(&flags.to_be_bytes());
    write_message(stream, SSH_AGENTC_SIGN_REQUEST, &body).await;
    read_message(stream).await
}

async fn bind_host(stream: &mut UnixStream, host_key: &PrivateKey) -> u8 {
    let host_blob = host_key.public_key().to_bytes().unwrap();
    let session_id = b"test-session-id";
    let signature: Signature = host_key.try_sign(session_id).unwrap();
    let signature = Vec::<u8>::try_from(signature).unwrap();
    let mut body = Vec::new();
    put_string(&mut body, b"session-bind@openssh.com");
    put_string(&mut body, &host_blob);
    put_string(&mut body, session_id);
    put_string(&mut body, &signature);
    body.push(0);
    write_message(stream, SSH_AGENTC_EXTENSION, &body).await;
    read_message(stream).await.0
}

async fn bound_stream(auth_sock: &str, host_key: &PrivateKey) -> UnixStream {
    let mut stream = UnixStream::connect(auth_sock).await.unwrap();
    let kind = bind_host(&mut stream, host_key).await;
    assert_eq!(kind, SSH_AGENT_SUCCESS, "session bind failed");
    stream
}

/// Verify a SIGN_RESPONSE body against `public` over `data`. `PublicKey`'s
/// inherent `verify` is the `sshsig` (namespaced) form, so call the
/// `signature::Verifier` impl on the underlying key data explicitly.
fn verify_signature(public: &PublicKey, response_body: &[u8], data: &[u8]) {
    let (sig_blob, _) = take_string(response_body);
    let signature = Signature::try_from(sig_blob).expect("decode ssh signature");
    let key_data: &PublicKeyData = public.key_data();
    key_data
        .verify(data, &signature)
        .expect("signature verifies");
}

/* --------------------------------- tests ---------------------------------- */

#[tokio::test]
async fn no_secret_exposes_an_empty_agent() {
    let mut h = harness(BrokerConfig::default()).await;
    let host_key = add_passwordless_ssh_connection(&h.broker);
    let token = h.pair().await;
    let (auth_sock, _) = h.open_ssh(&token).await;

    let mut stream = bound_stream(&auth_sock, &host_key).await;
    write_message(&mut stream, SSH_AGENTC_REQUEST_IDENTITIES, &[]).await;
    let (kind, body) = read_message(&mut stream).await;
    assert_eq!(kind, SSH_AGENT_IDENTITIES_ANSWER);
    assert_eq!(body, 0u32.to_be_bytes());

    let (kind, _) = sign(&mut stream, b"unknown-key", b"anything", 0).await;
    assert_eq!(kind, SSH_AGENT_FAILURE);
}

#[tokio::test]
async fn ed25519_lists_signs_and_pins_user() {
    let mut h = harness(BrokerConfig::default()).await;
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let host_key = add_ssh_connection(&h.broker, &key, "deploy");
    let token = h.pair().await;
    let (auth_sock, body) = h.open_ssh(&token).await;
    assert!(body["host_key_fingerprint"]
        .as_str()
        .is_some_and(|value| value.starts_with("SHA256:")));

    let key_blob = key.public_key().to_bytes().unwrap();
    let host_blob = host_key.public_key().to_bytes().unwrap();

    // A signature request without a verified session binding is refused.
    let data = userauth_blob("deploy", "ssh-ed25519", &key_blob, &host_blob);
    let mut unbound = UnixStream::connect(&auth_sock).await.unwrap();
    let (kind, _) = sign(&mut unbound, &key_blob, &data, 0).await;
    assert_eq!(kind, SSH_AGENT_FAILURE, "unbound signing must be refused");
    drop(unbound);

    // A session binding signed by any host key except the configured one is
    // refused before authentication can be attempted.
    let wrong_host = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let mut wrong = UnixStream::connect(&auth_sock).await.unwrap();
    assert_eq!(bind_host(&mut wrong, &wrong_host).await, SSH_AGENT_FAILURE);
    drop(wrong);

    // Identity listing.
    let mut s = bound_stream(&auth_sock, &host_key).await;
    assert_lists_identity(&mut s, &key).await;

    // A userauth signature for the pinned user is produced and verifies.
    let data = userauth_blob("deploy", "ssh-ed25519", &key_blob, &host_blob);
    let (kind, body) = sign(&mut s, &key_blob, &data, 0).await;
    assert_eq!(kind, SSH_AGENT_SIGN_RESPONSE);
    verify_signature(key.public_key(), &body, &data);

    // A live session is listed while the connection is held open.
    assert_eq!(h.broker.sessions().len(), 1);
    assert_eq!(h.broker.sessions()[0].connection, "prod-ssh");

    // Refuse: a userauth naming another user.
    let other = userauth_blob("root", "ssh-ed25519", &key_blob, &host_blob);
    let (kind, _) = sign(&mut s, &key_blob, &other, 0).await;
    assert_eq!(kind, SSH_AGENT_FAILURE, "wrong user must be refused");

    // Refuse: signing over data that is not a publickey userauth request.
    let (kind, _) = sign(&mut s, &key_blob, b"arbitrary bytes to sign", 0).await;
    assert_eq!(kind, SSH_AGENT_FAILURE, "non-userauth data must be refused");

    // Closing the client tears the session down.
    drop(s);
    tokio::time::timeout(Duration::from_secs(5), async {
        while !h.broker.sessions().is_empty() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("session should end after client disconnect");
}

#[tokio::test]
async fn rsa_signs_with_requested_hash() {
    let mut h = harness(BrokerConfig::default()).await;
    // A 2048-bit key keeps generation fast for the test.
    let keypair = ssh_key::private::RsaKeypair::random(&mut OsRng, 2048).unwrap();
    let key = PrivateKey::from(keypair);
    let host_key = add_ssh_connection(&h.broker, &key, "deploy");
    let token = h.pair().await;
    let (auth_sock, _) = h.open_ssh(&token).await;
    let key_blob = key.public_key().to_bytes().unwrap();
    let host_blob = host_key.public_key().to_bytes().unwrap();

    let mut s = bound_stream(&auth_sock, &host_key).await;
    assert_lists_identity(&mut s, &key).await;

    // Both RSA SHA-2 variants sign and verify against the public key.
    for (flags, alg) in [
        (SSH_AGENT_RSA_SHA2_256, "rsa-sha2-256"),
        (SSH_AGENT_RSA_SHA2_512, "rsa-sha2-512"),
    ] {
        let data = userauth_blob("deploy", alg, &key_blob, &host_blob);
        let (kind, body) = sign(&mut s, &key_blob, &data, flags).await;
        assert_eq!(kind, SSH_AGENT_SIGN_RESPONSE, "sign failed for {alg}");
        verify_signature(key.public_key(), &body, &data);
    }
}

#[tokio::test]
async fn wrong_key_blob_is_refused() {
    let mut h = harness(BrokerConfig::default()).await;
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let host_key = add_ssh_connection(&h.broker, &key, "deploy");
    let token = h.pair().await;
    let (auth_sock, _) = h.open_ssh(&token).await;

    // A different key's blob in the sign request → refused.
    let attacker = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let attacker_blob = attacker.public_key().to_bytes().unwrap();
    let host_blob = host_key.public_key().to_bytes().unwrap();
    let data = userauth_blob("deploy", "ssh-ed25519", &attacker_blob, &host_blob);
    let mut s = bound_stream(&auth_sock, &host_key).await;
    let (kind, _) = sign(&mut s, &attacker_blob, &data, 0).await;
    assert_eq!(kind, SSH_AGENT_FAILURE);
}

#[tokio::test]
async fn one_ticket_serves_many_invocations() {
    let mut h = harness(BrokerConfig::default()).await;
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let host_key = add_ssh_connection(&h.broker, &key, "deploy");
    let token = h.pair().await;
    let (auth_sock, _) = h.open_ssh(&token).await;
    let key_blob = key.public_key().to_bytes().unwrap();
    let host_blob = host_key.public_key().to_bytes().unwrap();
    let data = userauth_blob("deploy", "ssh-ed25519", &key_blob, &host_blob);

    // Three separate ssh invocations (connections) all succeed under one
    // approval, each its own session.
    let mut streams = Vec::new();
    for _ in 0..3 {
        let mut s = bound_stream(&auth_sock, &host_key).await;
        let (kind, body) = sign(&mut s, &key_blob, &data, 0).await;
        assert_eq!(kind, SSH_AGENT_SIGN_RESPONSE);
        verify_signature(key.public_key(), &body, &data);
        streams.push(s);
    }
    assert_eq!(h.broker.sessions().len(), 3);
}

#[tokio::test]
async fn unparseable_key_fails_open() {
    let mut h = harness(BrokerConfig::default()).await;
    // The bound secret is not a valid OpenSSH private key: the open must
    // fail up front (SshSigner::load), not each later signature.
    h.broker
        .store
        .add_secret("DEPLOY_SSH_KEY", Zeroizing::new("not a private key".into()))
        .unwrap();
    let secret = h.broker.store.secret_by_name("DEPLOY_SSH_KEY").unwrap();
    let host_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    h.broker
        .store
        .add_connection(ConnectionSpec {
            name: "prod-ssh".into(),
            config: ConnectionConfig::Ssh {
                destination: None,
                host: "prod.example.com".into(),
                port: 22,
                user: "deploy".into(),
                host_key_fingerprint: host_key
                    .public_key()
                    .fingerprint(HashAlg::Sha256)
                    .to_string(),
            },
            secrets: vec![secret.id],
        })
        .unwrap();
    let token = h.pair().await;

    let auth = format!("Bearer {token}");
    let (status, body) = uds_request(
        &h.daemon.socket_path,
        "POST",
        "/v1/ssh/open",
        &[("authorization", &auth)],
        Some(json!({"connection": "prod-ssh"})),
    )
    .await;
    assert_eq!(status, 502, "unparseable key must fail the open");
    assert_eq!(body["reason"], "ssh_agent_open_failed");
    // Nothing was left listening.
    assert!(h.broker.sessions().is_empty());
}

/* --------------------------- trust on first use --------------------------- */

#[tokio::test]
async fn tofu_first_bind_pins_and_signs() {
    let mut h = harness(BrokerConfig::default()).await;
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    add_ssh_connection_with_fingerprint(&h.broker, &key, "deploy", String::new());
    let host_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let observed = host_key
        .public_key()
        .fingerprint(HashAlg::Sha256)
        .to_string();

    let token = h.pair().await;
    let (auth_sock, body) = h.open_ssh(&token).await;
    assert!(
        body["host_key_fingerprint"].is_null(),
        "unpinned open must report a null fingerprint, got {body}"
    );

    // The first bind pins the observed key automatically — no prompt.
    let (kind, mut stream) = spawn_bind(&auth_sock, &host_key).await.unwrap();
    assert_eq!(kind, SSH_AGENT_SUCCESS, "first bind succeeds");
    assert_eq!(stored_fingerprint(&h.broker), observed, "pin persisted");

    // The now-bound connection signs exactly as a pre-pinned one would.
    let key_blob = key.public_key().to_bytes().unwrap();
    let host_blob = host_key.public_key().to_bytes().unwrap();
    let data = userauth_blob("deploy", "ssh-ed25519", &key_blob, &host_blob);
    let (kind, body) = sign(&mut stream, &key_blob, &data, 0).await;
    assert_eq!(kind, SSH_AGENT_SIGN_RESPONSE);
    verify_signature(key.public_key(), &body, &data);

    // A later open reports the pinned fingerprint instead of null.
    let (_, body) = h.open_ssh(&token).await;
    assert_eq!(body["host_key_fingerprint"], json!(observed));
}

#[tokio::test]
async fn tofu_confirmation_carries_a_structured_host_key_decision() {
    let mut h = harness_answering(
        BrokerConfig::default(),
        Some(aka_core::approvals::ApprovalDecision::ApproveWindow),
    )
    .await;
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    add_ssh_connection_with_fingerprint(&h.broker, &key, "deploy", String::new());
    confirm_logins(&h.broker);
    h.broker.ui_set_confirm_ssh_host_keys(true).unwrap();
    let host_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let observed = host_key
        .public_key()
        .fingerprint(HashAlg::Sha256)
        .to_string();

    let token = h.pair().await;
    let (auth_sock, _) = h.open_ssh(&token).await;
    assert_eq!(
        spawn_bind(&auth_sock, &host_key).await.unwrap().0,
        SSH_AGENT_SUCCESS
    );

    let prompt = h.last_prompt.lock().unwrap().clone().expect("TOFU prompt");
    assert_eq!(
        prompt.unit,
        aka_core::approvals::ApprovalUnit::HostKey,
        "a permanent pin must not look like a login approval window"
    );
    assert_eq!(
        prompt.host_key_fingerprint.as_deref(),
        Some(observed.as_str())
    );
    assert_eq!(stored_fingerprint(&h.broker), observed);

    // Trusting the host key must not silently approve the login that follows.
    let key_blob = key.public_key().to_bytes().unwrap();
    let host_blob = host_key.public_key().to_bytes().unwrap();
    let data = userauth_blob("deploy", "ssh-ed25519", &key_blob, &host_blob);
    let (_, mut stream) = spawn_bind(&auth_sock, &host_key).await.unwrap();
    let (kind, _) = sign(&mut stream, &key_blob, &data, 0).await;
    assert_eq!(kind, SSH_AGENT_SIGN_RESPONSE);
    assert_eq!(
        h.prompts.load(Ordering::SeqCst),
        2,
        "host-key trust must not open a login approval window"
    );
}

#[tokio::test]
async fn tofu_pin_holds_for_later_binds_and_refuses_other_keys() {
    let mut h = harness(BrokerConfig::default()).await;
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    add_ssh_connection_with_fingerprint(&h.broker, &key, "deploy", String::new());
    let host_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let token = h.pair().await;
    let (auth_sock, _) = h.open_ssh(&token).await;

    assert_eq!(
        spawn_bind(&auth_sock, &host_key).await.unwrap().0,
        SSH_AGENT_SUCCESS
    );

    // A second connection binds the pinned key without re-pinning.
    let mut again = UnixStream::connect(&auth_sock).await.unwrap();
    assert_eq!(bind_host(&mut again, &host_key).await, SSH_AGENT_SUCCESS);
    // A different server key is refused outright.
    let imposter = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let mut wrong = UnixStream::connect(&auth_sock).await.unwrap();
    assert_eq!(bind_host(&mut wrong, &imposter).await, SSH_AGENT_FAILURE);
    assert_eq!(
        stored_fingerprint(&h.broker),
        host_key
            .public_key()
            .fingerprint(HashAlg::Sha256)
            .to_string(),
        "the imposter never displaces the pinned key"
    );
}

#[tokio::test]
async fn tofu_concurrent_binds_pin_once_and_both_succeed() {
    let mut h = harness(BrokerConfig::default()).await;
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    add_ssh_connection_with_fingerprint(&h.broker, &key, "deploy", String::new());
    let host_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let token = h.pair().await;
    let (auth_sock, _) = h.open_ssh(&token).await;

    // Two clients race the first bind; the gate serializes them so exactly
    // one pin is written, and the loser re-checks the pinned state.
    let first = spawn_bind(&auth_sock, &host_key);
    let second = spawn_bind(&auth_sock, &host_key);
    assert_eq!(first.await.unwrap().0, SSH_AGENT_SUCCESS);
    assert_eq!(second.await.unwrap().0, SSH_AGENT_SUCCESS);
    assert_eq!(
        stored_fingerprint(&h.broker),
        host_key
            .public_key()
            .fingerprint(HashAlg::Sha256)
            .to_string()
    );
}

#[tokio::test]
async fn tofu_pin_reaches_agent_sockets_opened_before_it() {
    let mut h = harness(BrokerConfig::default()).await;
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    add_ssh_connection_with_fingerprint(&h.broker, &key, "deploy", String::new());
    let host_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let token = h.pair().await;
    // Both sockets open while the connection is still unpinned.
    let (first_sock, _) = h.open_ssh(&token).await;
    let (second_sock, _) = h.open_ssh(&token).await;

    assert_eq!(
        spawn_bind(&first_sock, &host_key).await.unwrap().0,
        SSH_AGENT_SUCCESS
    );

    // The second socket re-reads the store instead of re-pinning.
    let mut stream = UnixStream::connect(&second_sock).await.unwrap();
    assert_eq!(bind_host(&mut stream, &host_key).await, SSH_AGENT_SUCCESS);
    let imposter = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let mut wrong = UnixStream::connect(&second_sock).await.unwrap();
    assert_eq!(bind_host(&mut wrong, &imposter).await, SSH_AGENT_FAILURE);
}

/// The stale-socket sweep removes dead files but keeps live ones.
#[test]
fn stale_socket_sweep_cleans_dead_files() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    // A dead socket file (a plain file with the .sock name — connect fails).
    let dead = root.join("tkt_dead.sock");
    std::fs::write(&dead, b"").unwrap();
    // A non-socket file is left alone.
    let other = root.join("notes.txt");
    std::fs::write(&other, b"keep").unwrap();

    aka_core::capability::ssh::sweep_stale_sockets(Path::new(root));
    assert!(!dead.exists(), "dead .sock file should be removed");
    assert!(other.exists(), "non-socket files are left untouched");
}

/* ----------------------------- direct endpoint ---------------------------- */

#[tokio::test]
async fn direct_endpoint_serves_the_ssh_agent_protocol() {
    let mut h = harness(BrokerConfig::default()).await;
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let host_key = add_ssh_connection(&h.broker, &key, "deploy");
    h.pair().await;
    let info = h.issue_ssh_endpoint().await;

    assert_eq!(info.kind, aka_core::types::ConnectionKind::Ssh);
    assert!(info.example.contains("SSH_AUTH_SOCK"));
    // SSH-1. The ssh-agent protocol has no password, so the socket path *is*
    // the capability — which is why the name is derived from the endpoint
    // secret rather than fixed. A fixed `agent.sock` under a deterministic
    // directory was enumerable: `ls ~/.aka/endpoints/*/agent.sock` found every
    // issued endpoint, so any process running as this user could log in as the
    // pinned user, including an agent deliberately not enabled for it.
    let name = std::path::Path::new(&info.dsn)
        .file_name()
        .and_then(|n| n.to_str())
        .expect("a socket filename");
    assert!(
        name.starts_with("agent-") && name.ends_with(".sock"),
        "{name}"
    );
    assert_ne!(name, "agent.sock", "the socket name must not be guessable");
    // Not derivable from `endpoints.json` either: that file holds the plain
    // SHA-256 of the secret, and the name is a *domain-separated* hash of it.
    let endpoint = h
        .broker
        .endpoints
        .get_for_connection(&h.broker.store.connection_by_name("prod-ssh").unwrap().id)
        .expect("issued");
    assert!(
        !name.contains(&endpoint.secret_hash[..16]),
        "the name must not be computable from the persisted hash"
    );
    // The presented secret stays empty: no client sends one.
    assert!(info.secret.is_empty());

    // SSH-1's other half: the path is not in the ordinary connection listing,
    // which every manage caller receives. Only an explicit endpoint read-back
    // hands out a working signing oracle.
    let conn = h.broker.store.connection_by_name("prod-ssh").unwrap();
    let chip = aka_core::manage::connection_dto(&h.broker, &conn)
        .agent_access
        .endpoint
        .expect("the endpoint is still reported as issued");
    assert_eq!(chip.kind, "ssh");
    assert_eq!(
        chip.dsn, None,
        "the agent socket path must not ride the connection listing"
    );

    let key_blob = key.public_key().to_bytes().unwrap();
    let host_blob = host_key.public_key().to_bytes().unwrap();
    let data = userauth_blob("deploy", "ssh-ed25519", &key_blob, &host_blob);

    // Unbound signing is refused on the stable socket, exactly as per-open.
    let mut unbound = UnixStream::connect(&info.dsn).await.unwrap();
    let (kind, _) = sign(&mut unbound, &key_blob, &data, 0).await;
    assert_eq!(kind, SSH_AGENT_FAILURE, "unbound signing must be refused");
    drop(unbound);

    // Bind, list the identity, and produce a verifying signature for the
    // pinned user.
    let mut s = bound_stream(&info.dsn, &host_key).await;
    assert_lists_identity(&mut s, &key).await;
    let (kind, body) = sign(&mut s, &key_blob, &data, 0).await;
    assert_eq!(kind, SSH_AGENT_SIGN_RESPONSE);
    verify_signature(key.public_key(), &body, &data);

    // A wrong user is still refused by the scoped signer.
    let other = userauth_blob("root", "ssh-ed25519", &key_blob, &host_blob);
    let (kind, _) = sign(&mut s, &key_blob, &other, 0).await;
    assert_eq!(kind, SSH_AGENT_FAILURE, "wrong user must be refused");

    // Listed as a live session, tagged to the connection.
    assert_eq!(h.broker.sessions().len(), 1);
    assert_eq!(h.broker.sessions()[0].connection, "prod-ssh");

    drop(s);
    tokio::time::timeout(Duration::from_secs(5), async {
        while !h.broker.sessions().is_empty() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("session should end after client disconnect");
}

#[tokio::test]
async fn disabling_access_refuses_the_ssh_endpoint_and_revoke_tears_it_down() {
    let mut h = harness(BrokerConfig::default()).await;
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let host_key = add_ssh_connection(&h.broker, &key, "deploy");
    h.pair().await;
    let info = h.issue_ssh_endpoint().await;

    // Works while enabled: a bound stream signs.
    let mut s = bound_stream(&info.dsn, &host_key).await;
    assert_lists_identity(&mut s, &key).await;

    // Disabling agent access keeps the endpoint issued but refuses fresh
    // connections at the access re-check (the listener shuts them down
    // before serving the agent protocol).
    let conn = h.broker.store.connection_by_name("prod-ssh").unwrap();
    h.broker.ui_set_tool_access(&conn.id, false).unwrap();
    assert_eq!(h.broker.endpoints().len(), 1);
    let mut byte = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(2), s.read(&mut byte))
        .await
        .expect("the established connection should close promptly");
    assert!(
        matches!(read, Ok(0) | Err(_)),
        "a disabled tool must close an established agent connection"
    );
    assert!(h.broker.sessions().is_empty());
    let mut refused = UnixStream::connect(&info.dsn)
        .await
        .expect("the socket persists while disabled");
    let mut byte = [0u8; 1];
    use tokio::io::AsyncReadExt as _;
    let read = tokio::time::timeout(Duration::from_secs(2), refused.read(&mut byte))
        .await
        .expect("the refused connection should close promptly");
    assert!(
        matches!(read, Ok(0) | Err(_)),
        "a disabled tool must not serve the agent protocol"
    );

    // Re-enabling restores service without re-issuing.
    h.broker.ui_set_tool_access(&conn.id, true).unwrap();
    let mut s = bound_stream(&info.dsn, &host_key).await;
    assert_lists_identity(&mut s, &key).await;

    // Revoking the endpoint stops the listener and removes the socket.
    h.broker.ui_revoke_endpoint(&info.endpoint_id).unwrap();
    assert!(h.broker.endpoints().is_empty());
    tokio::time::timeout(Duration::from_secs(5), async {
        while !h.broker.sessions().is_empty() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("revoke should close the live session");
    assert!(
        UnixStream::connect(&info.dsn).await.is_err(),
        "the socket must be gone after teardown"
    );
}

/* ------------------------- per-login confirmation ------------------------- */

/// Turn the switch on for `prod-ssh`.
fn confirm_logins(broker: &Broker) {
    let conn = broker.store.connection_by_name("prod-ssh").unwrap();
    broker
        .ui_set_confirm_mode(&conn.id, aka_core::types::ConfirmMode::On)
        .unwrap();
}

/// The gate is in SIGN_REQUEST, so it fires per authentication — and only for
/// a request that would otherwise succeed.
#[tokio::test]
async fn a_confirmed_connection_asks_before_each_login() {
    let mut h = harness_answering(
        BrokerConfig::default(),
        Some(aka_core::approvals::ApprovalDecision::ApproveWindow),
    )
    .await;
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let host_key = add_ssh_connection(&h.broker, &key, "deploy");
    confirm_logins(&h.broker);

    let token = h.pair().await;
    let (auth_sock, _) = h.open_ssh(&token).await;
    let key_blob = key.public_key().to_bytes().unwrap();
    let host_blob = host_key.public_key().to_bytes().unwrap();

    // Opening the socket and binding the host key ask nothing: neither
    // authenticates, and prompting there would ask about `ssh` merely
    // considering the key.
    let mut s = bound_stream(&auth_sock, &host_key).await;
    assert_lists_identity(&mut s, &key).await;
    assert_eq!(h.prompts.load(Ordering::SeqCst), 0);

    let data = userauth_blob("deploy", "ssh-ed25519", &key_blob, &host_blob);
    let (kind, body) = sign(&mut s, &key_blob, &data, 0).await;
    assert_eq!(kind, SSH_AGENT_SIGN_RESPONSE);
    verify_signature(key.public_key(), &body, &data);
    assert_eq!(
        h.prompts.load(Ordering::SeqCst),
        1,
        "the login was asked about"
    );

    // The prompt names the verified destination and is honest about the gap
    // between confirming a login and confirming what the login goes on to do.
    let prompt = h.last_prompt.lock().unwrap().clone().expect("a prompt");
    assert_eq!(prompt.unit, aka_core::approvals::ApprovalUnit::Login);
    assert!(
        prompt.summary.contains("deploy@") && prompt.summary.contains("prod.example.com"),
        "the prompt names the login: {}",
        prompt.summary
    );
    let consequence = prompt
        .consequence
        .expect("the prompt states what it grants");
    assert!(
        consequence.contains("cannot see the commands"),
        "the prompt does not imply a per-command gate: {consequence}"
    );

    // A second login on the same connection rides the window, so a `git`
    // loop asks once rather than once per fetch.
    let (kind, _) = sign(&mut s, &key_blob, &data, 0).await;
    assert_eq!(kind, SSH_AGENT_SIGN_RESPONSE);
    assert_eq!(h.prompts.load(Ordering::SeqCst), 1);
}

/// Denying must actually withhold the signature — the whole point of the
/// gate is that `ssh` cannot authenticate without one.
#[tokio::test]
async fn a_refused_login_is_not_signed() {
    let mut h = harness_answering(
        BrokerConfig::default(),
        Some(aka_core::approvals::ApprovalDecision::Deny),
    )
    .await;
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let host_key = add_ssh_connection(&h.broker, &key, "deploy");
    confirm_logins(&h.broker);

    let token = h.pair().await;
    let (auth_sock, _) = h.open_ssh(&token).await;
    let key_blob = key.public_key().to_bytes().unwrap();
    let host_blob = host_key.public_key().to_bytes().unwrap();
    let mut s = bound_stream(&auth_sock, &host_key).await;

    let data = userauth_blob("deploy", "ssh-ed25519", &key_blob, &host_blob);
    let (kind, _) = sign(&mut s, &key_blob, &data, 0).await;
    assert_eq!(
        kind, SSH_AGENT_FAILURE,
        "a refused login must not be signed"
    );
    assert_eq!(h.prompts.load(Ordering::SeqCst), 1);

    // The refusal cools down, so a client retrying in a loop does not
    // re-prompt on every attempt.
    let (kind, _) = sign(&mut s, &key_blob, &data, 0).await;
    assert_eq!(kind, SSH_AGENT_FAILURE);
    assert_eq!(h.prompts.load(Ordering::SeqCst), 1);

    // Refusing an authentication is a decision about it, not a reason to
    // drop the socket: the agent stays usable.
    assert_lists_identity(&mut s, &key).await;
}

/// A request that fails validation is refused on its own terms. Prompting
/// first would ask the user about a login that was never going to happen.
#[tokio::test]
async fn an_invalid_sign_request_is_refused_without_asking() {
    let mut h = harness_answering(
        BrokerConfig::default(),
        Some(aka_core::approvals::ApprovalDecision::ApproveWindow),
    )
    .await;
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let host_key = add_ssh_connection(&h.broker, &key, "deploy");
    confirm_logins(&h.broker);

    let token = h.pair().await;
    let (auth_sock, _) = h.open_ssh(&token).await;
    let key_blob = key.public_key().to_bytes().unwrap();
    let host_blob = host_key.public_key().to_bytes().unwrap();
    let mut s = bound_stream(&auth_sock, &host_key).await;

    let wrong_user = userauth_blob("root", "ssh-ed25519", &key_blob, &host_blob);
    let (kind, _) = sign(&mut s, &key_blob, &wrong_user, 0).await;
    assert_eq!(kind, SSH_AGENT_FAILURE);

    let (kind, _) = sign(&mut s, &key_blob, b"arbitrary bytes to sign", 0).await;
    assert_eq!(kind, SSH_AGENT_FAILURE);

    assert_eq!(
        h.prompts.load(Ordering::SeqCst),
        0,
        "only a login that would otherwise succeed reaches the user"
    );
}

/// The switch is off by default, so an existing setup keeps working exactly
/// as it did before per-login confirmation existed.
#[tokio::test]
async fn logins_are_not_confirmed_unless_the_switch_is_on() {
    let mut h = harness(BrokerConfig::default()).await;
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let host_key = add_ssh_connection(&h.broker, &key, "deploy");

    let token = h.pair().await;
    let (auth_sock, _) = h.open_ssh(&token).await;
    let key_blob = key.public_key().to_bytes().unwrap();
    let host_blob = host_key.public_key().to_bytes().unwrap();
    let mut s = bound_stream(&auth_sock, &host_key).await;

    let data = userauth_blob("deploy", "ssh-ed25519", &key_blob, &host_blob);
    let (kind, _) = sign(&mut s, &key_blob, &data, 0).await;
    assert_eq!(kind, SSH_AGENT_SIGN_RESPONSE);
    assert_eq!(h.prompts.load(Ordering::SeqCst), 0);
}

/// Closing the session from the app must not wait behind a prompt nobody is
/// answering: the lifetime bounds keep running underneath a parked login.
#[tokio::test]
async fn closing_the_session_interrupts_a_parked_login() {
    // `None` takes every prompt and never answers it.
    let mut h = harness_answering(BrokerConfig::default(), None).await;
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let host_key = add_ssh_connection(&h.broker, &key, "deploy");
    confirm_logins(&h.broker);

    let token = h.pair().await;
    let (auth_sock, _) = h.open_ssh(&token).await;
    let key_blob = key.public_key().to_bytes().unwrap();
    let host_blob = host_key.public_key().to_bytes().unwrap();
    let mut s = bound_stream(&auth_sock, &host_key).await;

    let data = userauth_blob("deploy", "ssh-ed25519", &key_blob, &host_blob);
    let mut body = Vec::new();
    put_string(&mut body, &key_blob);
    put_string(&mut body, &data);
    body.extend_from_slice(&0u32.to_be_bytes());
    write_message(&mut s, SSH_AGENTC_SIGN_REQUEST, &body).await;

    // Wait for the login to park on the user.
    tokio::time::timeout(Duration::from_secs(5), async {
        while h.prompts.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the login should reach the user");
    assert_eq!(h.broker.sessions().len(), 1);

    // Closing it from the app takes effect immediately rather than after the
    // prompt's own deadline.
    let session = h.broker.sessions()[0].id;
    h.broker.ui_close_session(session).unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while !h.broker.sessions().is_empty() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("a parked login must not hold the session open");

    // And the prompt it was riding goes with it: nothing is left on screen
    // asking about a socket that is gone.
    tokio::time::timeout(Duration::from_secs(5), async {
        while !h.broker.pending_approvals().is_empty() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the abandoned prompt should retire");
}

/* ------------------- per-open authorization and lifetime ------------------ */

/// SSH-2. `redeem` checks expiry, invalidation and budget — never whether the
/// tool is still enabled. So a socket opened before the user switched the
/// connection off went on signing, and the endpoint path's re-check had no
/// counterpart here.
///
/// The user-facing switch now trips two independent gates: `ui_set_tool_access`
/// invalidates the connection's tickets (SSH-3), and `handle_conn` re-checks the
/// access table (SSH-2). Whichever fires first, the guarantee is the same —
/// nothing is served, and the reason is recoverable from Activity, because a
/// closed socket is all the client is told. `the_access_table_is_rechecked_...`
/// below pins the second gate on its own.
#[tokio::test]
async fn disabling_access_refuses_a_live_per_open_socket() {
    let mut h = harness(BrokerConfig::default()).await;
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let host_key = add_ssh_connection(&h.broker, &key, "deploy");
    let token = h.pair().await;
    let (auth_sock, _) = h.open_ssh(&token).await;

    // Works while enabled.
    let mut before = bound_stream(&auth_sock, &host_key).await;
    assert_lists_identity(&mut before, &key).await;
    drop(before);

    let conn = h.broker.store.connection_by_name("prod-ssh").unwrap();
    assert!(h.broker.ui_set_tool_access(&conn.id, false).unwrap());

    // The socket file is still there — the listener's window has not lapsed —
    // but a fresh connection is refused before the protocol is served.
    let mut after = UnixStream::connect(&auth_sock).await.unwrap();
    let mut probe = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(5), after.read(&mut probe))
        .await
        .expect("the refusal must not hang");
    assert!(
        matches!(read, Ok(0) | Err(_)),
        "a disabled tool must not serve the agent protocol"
    );

    let refusal = h
        .broker
        .audit
        .recent(20)
        .into_iter()
        .find(|e| {
            e.kind == aka_core::audit::AuditKind::Denied
                && e.fields.get("kind").and_then(|v| v.as_str()) == Some("ssh")
        })
        .expect("the refusal is recorded — the client only sees a closed socket");
    assert_eq!(refusal.connection.as_deref(), Some("prod-ssh"));
}

/// SSH-2 on its own. Flipping the access table without going through
/// `ui_set_tool_access` leaves the socket's ticket valid, so `redeem` succeeds
/// and only `handle_conn`'s re-check stands between the caller and a signing
/// oracle. Any path that narrows access — a reload of the wiring state, a future
/// caller that forgets to invalidate — lands here.
#[tokio::test]
async fn the_access_table_is_rechecked_when_a_socket_connection_arrives() {
    let mut h = harness(BrokerConfig::default()).await;
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let host_key = add_ssh_connection(&h.broker, &key, "deploy");
    let token = h.pair().await;
    let (auth_sock, _) = h.open_ssh(&token).await;

    let mut before = bound_stream(&auth_sock, &host_key).await;
    assert_lists_identity(&mut before, &key).await;
    drop(before);

    let conn = h.broker.store.connection_by_name("prod-ssh").unwrap();
    assert!(h.broker.access.set_enabled(conn.id, false).unwrap());

    let mut after = UnixStream::connect(&auth_sock).await.unwrap();
    let mut probe = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(5), after.read(&mut probe))
        .await
        .expect("the refusal must not hang");
    assert!(
        matches!(read, Ok(0) | Err(_)),
        "a disabled tool must not serve the agent protocol"
    );

    let refusal = h
        .broker
        .audit
        .recent(20)
        .into_iter()
        .find(|e| {
            e.kind == aka_core::audit::AuditKind::Denied
                && e.outcome.as_deref() == Some("denied_by_policy")
        })
        .expect("the access re-check records its refusal");
    assert_eq!(refusal.connection.as_deref(), Some("prod-ssh"));
    assert_eq!(
        refusal.detail.as_deref(),
        Some("agent access is disabled"),
        "the entry must say which gate refused"
    );
}

/// Retargeting the connection invalidates a socket opened against the old
/// target: the user repointed the tool at something other than what they
/// approved.
#[tokio::test]
async fn retargeting_refuses_a_live_per_open_socket() {
    let mut h = harness(BrokerConfig::default()).await;
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let _host_key = add_ssh_connection(&h.broker, &key, "deploy");
    let token = h.pair().await;
    let (auth_sock, _) = h.open_ssh(&token).await;

    let conn = h.broker.store.connection_by_name("prod-ssh").unwrap();
    let ConnectionConfig::Ssh {
        host,
        port,
        user,
        host_key_fingerprint,
        ..
    } = conn.config.clone()
    else {
        unreachable!()
    };
    h.broker
        .store
        .update_connection(
            &conn.id,
            aka_core::store::ConnectionSpec {
                name: conn.name.clone(),
                config: ConnectionConfig::Ssh {
                    // A different host entirely.
                    host: format!("other-{host}"),
                    port,
                    destination: None,
                    user,
                    host_key_fingerprint,
                },
                secrets: conn.secrets.clone(),
            },
        )
        .unwrap();

    let mut after = UnixStream::connect(&auth_sock).await.unwrap();
    let mut probe = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(5), after.read(&mut probe))
        .await
        .expect("must not hang");
    assert!(
        matches!(read, Ok(0) | Err(_)),
        "a retargeted tool must refuse"
    );
}

/// SSH-3. A connection accepted just before the socket's window closes must not
/// outlive it. It used to run to `session_max_ttl` — an hour of unlimited
/// signatures, after the socket file was gone, regardless of disable or delete.
#[tokio::test]
async fn an_agent_connection_dies_with_its_socket_window() {
    let config = BrokerConfig {
        // The socket accepts for `ticket_ttl + 30s`; make the whole window
        // short. `session_max_ttl` stays long, so only the socket bound can
        // end this.
        ticket_ttl: Duration::from_millis(200),
        session_max_ttl: Duration::from_secs(3600),
        session_idle_timeout: Duration::from_secs(3600),
        ..Default::default()
    };
    let mut h = harness(config).await;
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let host_key = add_ssh_connection(&h.broker, &key, "deploy");
    let token = h.pair().await;
    let (auth_sock, _) = h.open_ssh(&token).await;

    // Hold a bound connection open and idle.
    let mut s = bound_stream(&auth_sock, &host_key).await;
    assert_lists_identity(&mut s, &key).await;

    // SOCKET_GRACE is 30s, so allow for it: the point is that this ends at all
    // rather than at the hour `session_max_ttl` would allow.
    let mut probe = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(45), s.read(&mut probe))
        .await
        .expect("the socket window must end the connection");
    assert!(matches!(read, Ok(0) | Err(_)));
    assert!(
        h.broker.sessions().is_empty(),
        "the session must be retired: {:?}",
        h.broker.sessions()
    );
}

/// SSH-3's other half: a withdrawn connection closes established agent
/// connections, not only future ones.
#[tokio::test]
async fn withdrawing_a_connection_closes_a_live_agent_connection() {
    let mut h = harness(BrokerConfig::default()).await;
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let host_key = add_ssh_connection(&h.broker, &key, "deploy");
    let token = h.pair().await;
    let (auth_sock, _) = h.open_ssh(&token).await;

    let mut s = bound_stream(&auth_sock, &host_key).await;
    assert_lists_identity(&mut s, &key).await;
    assert_eq!(h.broker.sessions().len(), 1);

    let conn = h.broker.store.connection_by_name("prod-ssh").unwrap();
    assert!(h.broker.ui_set_tool_access(&conn.id, false).unwrap());

    let mut probe = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(5), s.read(&mut probe))
        .await
        .expect("close_connection_sessions must reach an established connection");
    assert!(matches!(read, Ok(0) | Err(_)));
}

/* ------------------------- protocol-level refusals ------------------------ */

/// SSH-16. Routine capability probes are not security events. Every EXTENSION
/// used to fall into the session-bind parser, reach "unsupported agent
/// extension", and be recorded as `SSH signature refused` — so `ssh`'s own
/// `query` probe looked like an attack in the activity log.
#[tokio::test]
async fn an_unknown_extension_fails_without_being_audited() {
    let mut h = harness(BrokerConfig::default()).await;
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let _host_key = add_ssh_connection(&h.broker, &key, "deploy");
    let token = h.pair().await;
    let (auth_sock, _) = h.open_ssh(&token).await;

    let mut s = UnixStream::connect(&auth_sock).await.unwrap();
    let mut body = Vec::new();
    put_string(&mut body, b"query");
    write_message(&mut s, SSH_AGENTC_EXTENSION, &body).await;
    let (kind, _) = read_message(&mut s).await;
    assert_eq!(kind, SSH_AGENT_FAILURE, "an unknown extension just fails");

    assert!(
        h.broker
            .audit
            .recent(20)
            .iter()
            .all(|e| e.kind != aka_core::audit::AuditKind::SshSigned),
        "a capability probe must not be recorded as a refused signature"
    );
}

/// SSH-17. `flags == 0` asks for legacy SHA-1 `ssh-rsa`. Signing SHA-512 anyway
/// produced a signature the client rejects (`sshkey_check_sigtype` compares it
/// against the `ssh-rsa` in its own userauth blob), so the key signed for a
/// login that then failed. Refusing lets the client ask again properly.
#[tokio::test]
async fn legacy_ssh_rsa_is_refused_rather_than_signed_with_the_wrong_algorithm() {
    let mut h = harness(BrokerConfig::default()).await;
    let key = PrivateKey::random(&mut OsRng, Algorithm::Rsa { hash: None }).unwrap();
    let host_key = add_ssh_connection(&h.broker, &key, "deploy");
    let token = h.pair().await;
    let (auth_sock, _) = h.open_ssh(&token).await;

    let key_blob = key.public_key().to_bytes().unwrap();
    let host_blob = host_key.public_key().to_bytes().unwrap();
    let data = userauth_blob("deploy", "ssh-rsa", &key_blob, &host_blob);
    let mut s = bound_stream(&auth_sock, &host_key).await;

    let (kind, _) = sign(&mut s, &key_blob, &data, 0).await;
    assert_eq!(kind, SSH_AGENT_FAILURE, "flags==0 must be refused for RSA");

    // Asking for a real algorithm works, so this is not a blanket RSA refusal.
    let (kind, body) = sign(&mut s, &key_blob, &data, SSH_AGENT_RSA_SHA2_512).await;
    assert_eq!(kind, SSH_AGENT_SIGN_RESPONSE);
    verify_signature(key.public_key(), &body, &data);
}

/// SSH-20. Signing is the authority-granting operation and it was unbounded:
/// the token limiter covers `POST /v1/ssh/open`, never the socket it returns.
#[tokio::test]
async fn signatures_are_rate_limited_per_socket() {
    let config = BrokerConfig {
        per_identity_per_min: 2,
        ..Default::default()
    };
    let mut h = harness(config).await;
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let host_key = add_ssh_connection(&h.broker, &key, "deploy");
    let token = h.pair().await;
    let (auth_sock, _) = h.open_ssh(&token).await;

    let key_blob = key.public_key().to_bytes().unwrap();
    let host_blob = host_key.public_key().to_bytes().unwrap();
    let data = userauth_blob("deploy", "ssh-ed25519", &key_blob, &host_blob);
    let mut s = bound_stream(&auth_sock, &host_key).await;

    for i in 0..2 {
        let (kind, _) = sign(&mut s, &key_blob, &data, 0).await;
        assert_eq!(kind, SSH_AGENT_SIGN_RESPONSE, "signature {i} is in budget");
    }
    let (kind, _) = sign(&mut s, &key_blob, &data, 0).await;
    assert_eq!(kind, SSH_AGENT_FAILURE, "over budget must be refused");

    let limited = h
        .broker
        .audit
        .recent(20)
        .into_iter()
        .find(|e| e.outcome.as_deref() == Some("rate_limited"))
        .expect("the refusal names its reason");
    assert_eq!(limited.connection.as_deref(), Some("prod-ssh"));
}

/// SSH-26. The sweep used to probe each socket by connecting, which *is* a
/// redemption: it spent one of the owning ticket's budget slots per swept file.
#[tokio::test]
async fn the_stale_socket_sweep_does_not_spend_a_redemption() {
    let mut h = harness(BrokerConfig::default()).await;
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let _host_key = add_ssh_connection(&h.broker, &key, "deploy");
    let token = h.pair().await;
    let (auth_sock, _) = h.open_ssh(&token).await;
    let dir = std::path::Path::new(&auth_sock)
        .parent()
        .unwrap()
        .to_owned();

    aka_core::capability::ssh::sweep_stale_sockets(&dir);

    // No session was opened by the sweep itself.
    assert!(
        h.broker.sessions().is_empty(),
        "the sweep must not open sessions: {:?}",
        h.broker.sessions()
    );
    assert!(
        h.broker
            .audit
            .recent(20)
            .iter()
            .all(|e| e.kind != aka_core::audit::AuditKind::SessionOpened),
        "the sweep must not register a use nobody made"
    );
}

/// SSH-28. A server with a CA-signed host key sends the **certificate** blob in
/// `session-bind`. It parses (ssh-key maps the unrecognized algorithm to an
/// opaque key) and then fails verification with a bare "unsupported", which
/// reached the activity log as "SSH signature refused" — a correctly configured
/// server reading as a host-key attack. Verifying certificates is a separate,
/// unbuilt feature; the refusal must at least say what happened.
#[tokio::test]
async fn a_certificate_host_key_is_refused_by_name_not_as_a_bad_signature() {
    let mut h = harness(BrokerConfig::default()).await;
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let host_key = add_ssh_connection(&h.broker, &key, "deploy");
    let token = h.pair().await;
    let (auth_sock, _) = h.open_ssh(&token).await;

    // A certificate blob: the algorithm name OpenSSH uses, then the plain key's
    // remaining fields. Enough for the algorithm check, which is what runs
    // before any verification is attempted.
    let plain = host_key.public_key().to_bytes().unwrap();
    let (_, rest) = take_string(&plain);
    let mut cert = Vec::new();
    put_string(&mut cert, b"ssh-ed25519-cert-v01@openssh.com");
    cert.extend_from_slice(rest);

    let mut s = UnixStream::connect(&auth_sock).await.unwrap();
    let mut body = Vec::new();
    put_string(&mut body, b"session-bind@openssh.com");
    put_string(&mut body, &cert);
    put_string(&mut body, b"test-session-id");
    // A syntactically valid signature over the session id, made with the real
    // host key: the point is that the certificate is rejected *before* the
    // signature is even looked at, so a valid one must not rescue it.
    let sig = host_key.key_data().sign(b"test-session-id" as &[u8]);
    put_string(&mut body, sig.as_bytes());
    body.push(0);
    write_message(&mut s, SSH_AGENTC_EXTENSION, &body).await;
    let (kind, _) = read_message(&mut s).await;
    assert_eq!(
        kind, SSH_AGENT_FAILURE,
        "a certificate bind must not succeed"
    );

    let refusal = h
        .broker
        .audit
        .recent(20)
        .into_iter()
        .find(|e| e.outcome.as_deref() == Some("refused"))
        .expect("the refusal is recorded");
    let detail = refusal.detail.unwrap_or_default();
    assert!(
        detail.contains("certificate host key"),
        "the reason must name the certificate: {detail}"
    );
    assert!(
        detail.contains("ssh-ed25519-cert-v01@openssh.com"),
        "and the algorithm: {detail}"
    );
    assert!(
        !detail.contains("host signature failed"),
        "and must not read as a bad signature: {detail}"
    );
}

/// SSH-28. `ssh-add -D`, `ssh-add <key>` and the other agent-management requests
/// are not implemented. The protocol's answer for an unimplemented request is a
/// bare `SSH_AGENT_FAILURE`; routing them anywhere near `refuse()` would file a
/// key-management no-op as a refused signature.
#[tokio::test]
async fn unimplemented_agent_requests_fail_without_being_audited() {
    let mut h = harness(BrokerConfig::default()).await;
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let _host_key = add_ssh_connection(&h.broker, &key, "deploy");
    let token = h.pair().await;
    let (auth_sock, _) = h.open_ssh(&token).await;

    let mut s = UnixStream::connect(&auth_sock).await.unwrap();
    // ADD_IDENTITY (17), REMOVE_IDENTITY (18), REMOVE_ALL_IDENTITIES (19,
    // `ssh-add -D`), LOCK (22), UNLOCK (23).
    for kind in [17u8, 18, 19, 22, 23] {
        write_message(&mut s, kind, &[]).await;
        let (answer, body) = read_message(&mut s).await;
        assert_eq!(answer, SSH_AGENT_FAILURE, "request {kind}");
        assert!(body.is_empty(), "request {kind} answered with a body");
    }
    // `ssh-add -l` is REQUEST_IDENTITIES, which *is* implemented — included so
    // the loop above cannot pass by the agent simply having died.
    assert_lists_identity(&mut s, &key).await;

    assert!(
        h.broker
            .audit
            .recent(20)
            .iter()
            .all(|e| e.kind != aka_core::audit::AuditKind::SshSigned),
        "key-management no-ops are not signature events"
    );
}

/// SSH-28 and the fact behind SSH-22: OpenSSH closes its agent fd as soon as
/// userauth completes, so the live-session row a per-open agent connection
/// registers is gone seconds after it appears while the real SSH session runs
/// on. Pinned here because the existing tests only ever hold the stream open,
/// which is not what a real client does.
#[tokio::test]
async fn the_session_ends_when_the_client_closes_its_agent_fd_after_signing() {
    let mut h = harness(BrokerConfig::default()).await;
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let host_key = add_ssh_connection(&h.broker, &key, "deploy");
    let token = h.pair().await;
    let (auth_sock, _) = h.open_ssh(&token).await;

    let mut s = bound_stream(&auth_sock, &host_key).await;
    let blob = key.public_key().to_bytes().unwrap();
    let data = userauth_blob(
        "deploy",
        "ssh-ed25519",
        &blob,
        &host_key.public_key().to_bytes().unwrap(),
    );
    let (kind, _) = sign(&mut s, &blob, &data, 0).await;
    assert_eq!(kind, SSH_AGENT_SIGN_RESPONSE, "the login must be signed");
    assert_eq!(
        h.broker.sessions().len(),
        1,
        "signing runs inside a session"
    );

    // What `ssh` does next: it has its signature, so the agent is done with.
    drop(s);

    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !h.broker.sessions().is_empty() && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        h.broker.sessions().is_empty(),
        "the row outlives the client's fd: {:?}",
        h.broker.sessions()
    );
    // The signature is what remains in the record — the authority that was
    // granted, rather than a connection that lasted moments.
    assert!(
        h.broker
            .audit
            .recent(20)
            .iter()
            .any(|e| e.kind == aka_core::audit::AuditKind::SshSigned
                && e.outcome.as_deref() == Some("signed")),
        "the signature must be recorded"
    );
}

/* --------------------- authenticated endpoint sockets --------------------- */

const SSH_AGENT_EXTENSION_FAILURE: u8 = 28;
const AUTHENTICATE_EXTENSION: &[u8] = b"authenticate@agentmfa.dev";

/// Present `secret` on this connection and return the reply type.
async fn authenticate(stream: &mut UnixStream, secret: &str) -> u8 {
    let mut body = Vec::new();
    put_string(&mut body, AUTHENTICATE_EXTENSION);
    put_string(&mut body, secret.as_bytes());
    write_message(stream, SSH_AGENTC_EXTENSION, &body).await;
    read_message(stream).await.0
}

/// Turn on the socket's authentication requirement and hand back the secret a
/// client must now present, read the way the app reads it.
async fn require_endpoint_auth(h: &Harness) -> String {
    let conn = h.broker.store.connection_by_name("prod-ssh").unwrap();
    assert!(
        h.broker
            .ui_set_endpoint_require_auth(&conn.id, true)
            .await
            .unwrap(),
        "the flag should have changed"
    );
    let info = h
        .broker
        .ui_get_endpoint(&conn.id)
        .await
        .unwrap()
        .expect("issued");
    assert!(
        !info.secret.is_empty(),
        "an authenticated endpoint surfaces the secret a client has to send"
    );
    assert!(
        info.example.contains("mfa ssh-agent"),
        "the example must name the forwarder that can send it: {}",
        info.example
    );
    info.secret
}

/// SSH-1 / SEC-28. The ssh-agent protocol carries no credential, so a standing
/// endpoint socket was authorized by whoever could open it. With
/// `require_auth`, the socket does nothing until the caller proves it holds
/// the endpoint secret.
#[tokio::test]
async fn an_authenticated_endpoint_refuses_everything_until_the_secret_arrives() {
    let mut h = harness(BrokerConfig::default()).await;
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let host_key = add_ssh_connection(&h.broker, &key, "deploy");
    h.pair().await;
    let info = h.issue_ssh_endpoint().await;
    let secret = require_endpoint_auth(&h).await;

    // Listing identities is the reconnaissance step, so it is refused too:
    // exempting it would hand out the public key and the connection's comment.
    let mut s = UnixStream::connect(&info.dsn).await.unwrap();
    write_message(&mut s, SSH_AGENTC_REQUEST_IDENTITIES, &[]).await;
    assert_eq!(read_message(&mut s).await.0, SSH_AGENT_FAILURE);

    // So is session-bind, which would otherwise pin a host key on an
    // unauthenticated connection.
    let mut body = Vec::new();
    put_string(&mut body, b"session-bind@openssh.com");
    put_string(&mut body, &host_key.public_key().to_bytes().unwrap());
    put_string(&mut body, b"session-id");
    put_string(&mut body, b"sig");
    body.push(0);
    write_message(&mut s, SSH_AGENTC_EXTENSION, &body).await;
    assert_eq!(read_message(&mut s).await.0, SSH_AGENT_FAILURE);

    // With the secret, the same connection works exactly as before.
    assert_eq!(authenticate(&mut s, &secret).await, SSH_AGENT_SUCCESS);
    assert_eq!(bind_host(&mut s, &host_key).await, SSH_AGENT_SUCCESS);
    assert_lists_identity(&mut s, &key).await;
    let key_blob = key.public_key().to_bytes().unwrap();
    let host_blob = host_key.public_key().to_bytes().unwrap();
    let data = userauth_blob("deploy", "ssh-ed25519", &key_blob, &host_blob);
    let (kind, sig) = sign(&mut s, &key_blob, &data, 0).await;
    assert_eq!(kind, SSH_AGENT_SIGN_RESPONSE);
    verify_signature(key.public_key(), &sig, &data);
}

/// A wrong secret leaves the connection exactly where it was, and says so in
/// the activity log — nothing legitimate presents one, and a closed socket is
/// otherwise the only trace.
#[tokio::test]
async fn a_wrong_endpoint_secret_is_refused_and_recorded() {
    let mut h = harness(BrokerConfig::default()).await;
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let _host_key = add_ssh_connection(&h.broker, &key, "deploy");
    h.pair().await;
    let info = h.issue_ssh_endpoint().await;
    let _secret = require_endpoint_auth(&h).await;

    let mut s = UnixStream::connect(&info.dsn).await.unwrap();
    assert_eq!(
        authenticate(&mut s, "not-the-secret").await,
        SSH_AGENT_EXTENSION_FAILURE
    );
    write_message(&mut s, SSH_AGENTC_REQUEST_IDENTITIES, &[]).await;
    assert_eq!(
        read_message(&mut s).await.0,
        SSH_AGENT_FAILURE,
        "a refused attempt must not leave the connection authenticated"
    );

    assert!(
        h.broker.audit.recent(20).iter().any(|e| {
            e.kind == aka_core::audit::AuditKind::Denied
                && e.outcome.as_deref() == Some("invalid_secret")
        }),
        "the refusal must be recorded"
    );
}

/// One guess per connection. Otherwise the socket is a free oracle: a caller
/// could try secrets as fast as it can write frames, and each attempt would
/// add a line to the activity log the user is supposed to be able to read.
#[tokio::test]
async fn a_connection_that_guesses_wrong_stops_answering() {
    let mut h = harness(BrokerConfig::default()).await;
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let _host_key = add_ssh_connection(&h.broker, &key, "deploy");
    h.pair().await;
    let info = h.issue_ssh_endpoint().await;
    let secret = require_endpoint_auth(&h).await;

    let mut s = UnixStream::connect(&info.dsn).await.unwrap();
    assert_eq!(authenticate(&mut s, "guess-one").await, SSH_AGENT_EXTENSION_FAILURE);
    // Even the correct secret cannot rescue this connection.
    assert_eq!(
        authenticate(&mut s, &secret).await,
        SSH_AGENT_FAILURE,
        "a burned connection must not accept a second attempt"
    );
    assert_eq!(
        h.broker
            .audit
            .recent(50)
            .iter()
            .filter(|e| e.outcome.as_deref() == Some("invalid_secret"))
            .count(),
        1,
        "one connection writes at most one refusal"
    );

    // A fresh connection is unaffected — this bounds guessing, it does not
    // lock the endpoint out.
    let mut fresh = UnixStream::connect(&info.dsn).await.unwrap();
    assert_eq!(authenticate(&mut fresh, &secret).await, SSH_AGENT_SUCCESS);
}

/// The proof is per connection. If it were per socket, one authenticated
/// client would reopen the socket for every other process on the machine.
#[tokio::test]
async fn one_connections_authentication_does_not_carry_to_another() {
    let mut h = harness(BrokerConfig::default()).await;
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let _host_key = add_ssh_connection(&h.broker, &key, "deploy");
    h.pair().await;
    let info = h.issue_ssh_endpoint().await;
    let secret = require_endpoint_auth(&h).await;

    let mut authenticated = UnixStream::connect(&info.dsn).await.unwrap();
    assert_eq!(
        authenticate(&mut authenticated, &secret).await,
        SSH_AGENT_SUCCESS
    );

    let mut other = UnixStream::connect(&info.dsn).await.unwrap();
    write_message(&mut other, SSH_AGENTC_REQUEST_IDENTITIES, &[]).await;
    assert_eq!(read_message(&mut other).await.0, SSH_AGENT_FAILURE);
}

/// Turning it on is a decision that the processes already holding the socket
/// must stop signing; leaving them connected would make the switch mean
/// "…starting next reboot".
#[tokio::test]
async fn turning_authentication_on_closes_the_connections_it_was_not_asked_of() {
    let mut h = harness(BrokerConfig::default()).await;
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let host_key = add_ssh_connection(&h.broker, &key, "deploy");
    h.pair().await;
    let info = h.issue_ssh_endpoint().await;

    let mut before = bound_stream(&info.dsn, &host_key).await;
    assert_lists_identity(&mut before, &key).await;
    assert_eq!(h.broker.sessions().len(), 1);

    let _secret = require_endpoint_auth(&h).await;
    tokio::time::timeout(Duration::from_secs(5), async {
        while !h.broker.sessions().is_empty() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the live endpoint session should be closed");
}

/// A per-open ticket socket has no endpoint secret behind it: it is already
/// bounded by the ticket that minted it and by its own expiry, so it neither
/// demands the extension nor pretends to implement it.
#[tokio::test]
async fn a_per_open_socket_neither_requires_nor_implements_the_extension() {
    let mut h = harness(BrokerConfig::default()).await;
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let _host_key = add_ssh_connection(&h.broker, &key, "deploy");
    let token = h.pair().await;
    let (auth_sock, _) = h.open_ssh(&token).await;

    let mut s = UnixStream::connect(&auth_sock).await.unwrap();
    // Serves without any proof…
    write_message(&mut s, SSH_AGENTC_REQUEST_IDENTITIES, &[]).await;
    assert_eq!(read_message(&mut s).await.0, SSH_AGENT_IDENTITIES_ANSWER);
    // …and answers the extension honestly rather than claiming success.
    assert_eq!(
        authenticate(&mut s, "anything").await,
        SSH_AGENT_EXTENSION_FAILURE
    );
}

/// Rotating the secret is not a decision to weaken the socket. Silently
/// clearing the flag during a reissue would relax the posture at exactly the
/// moment the user was tightening it.
#[tokio::test]
async fn reissuing_an_endpoint_keeps_it_authenticated() {
    let mut h = harness(BrokerConfig::default()).await;
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let _host_key = add_ssh_connection(&h.broker, &key, "deploy");
    h.pair().await;
    h.issue_ssh_endpoint().await;
    let first = require_endpoint_auth(&h).await;

    let reissued = h.issue_ssh_endpoint().await;
    assert_ne!(reissued.secret, first, "the secret rotates");
    assert!(
        !reissued.secret.is_empty() && reissued.example.contains("mfa ssh-agent"),
        "the socket still requires authentication after a rotation"
    );

    let mut s = UnixStream::connect(&reissued.dsn).await.unwrap();
    assert_eq!(
        authenticate(&mut s, &first).await,
        SSH_AGENT_EXTENSION_FAILURE,
        "the retired secret must not still open the socket"
    );
    let mut s = UnixStream::connect(&reissued.dsn).await.unwrap();
    assert_eq!(
        authenticate(&mut s, &reissued.secret).await,
        SSH_AGENT_SUCCESS
    );
}
