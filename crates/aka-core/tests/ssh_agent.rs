//! End-to-end SSH agent tests: a real daemon, a real vault-stored private
//! key, and a stock ssh-agent-protocol client speaking to the per-open
//! `SSH_AUTH_SOCK` socket. Exercises identity listing, the user-pinned
//! signing oracle (accept + refuse), and session accounting — for both
//! ed25519 and RSA keys.

use std::path::Path;
use std::time::Duration;

use aka_core::approvals::ApprovalRequest;
use aka_core::broker::{Broker, UiDecision};
use aka_core::config::BrokerConfig;
use aka_core::daemon;
use aka_core::events::BrokerEvents;
use aka_core::paths::Paths;
use aka_core::store::ConnectionSpec;
use aka_core::types::{
    ConfirmationMethod, ConnectionConfig, DecisionContext, DecisionSurface, SecretMeta,
};
use aka_core::vault::MemoryVault;
use http_body_util::BodyExt as _;
use serde_json::{json, Value};
use signature::{Signer as _, Verifier as _};
use ssh_key::public::KeyData as PublicKeyData;
use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, HashAlg, LineEnding, PrivateKey, PublicKey, Signature};
use std::sync::Arc;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::UnixStream;
use tokio::sync::mpsc;
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
    prompts: mpsc::UnboundedSender<ApprovalRequest>,
}

impl BrokerEvents for TestEvents {
    fn prompt_raised(&self, request: &ApprovalRequest) {
        let _ = self.prompts.send(request.clone());
    }
    fn confirm_secret_read(&self, _secret: &SecretMeta) -> bool {
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
    _dir: tempfile::TempDir,
}

async fn harness(config: BrokerConfig) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::under(dir.path());
    let (tx, rx) = mpsc::unbounded_channel();
    let broker = Broker::new(
        paths,
        Arc::new(MemoryVault::new()),
        config,
        Arc::new(TestEvents { prompts: tx }),
    )
    .await
    .unwrap();
    let daemon = daemon::serve(broker.clone()).await.unwrap();
    Harness {
        broker,
        daemon,
        prompts: rx,
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

    /// POST /v1/ssh/open and approve; returns the auth_sock path and the
    /// full open-response body (its `host_key_fingerprint` is null while
    /// the connection is unpinned).
    async fn open_ssh(&mut self, token: &str) -> (String, Value) {
        let socket = self.daemon.socket_path.clone();
        let auth = format!("Bearer {token}");
        let call = tokio::spawn(async move {
            uds_request(
                &socket,
                "POST",
                "/v1/ssh/open",
                &[("authorization", &auth)],
                Some(json!({"connection": "prod-ssh"})),
            )
            .await
        });
        let prompt = tokio::time::timeout(Duration::from_secs(5), self.prompts.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(prompt.connection.as_ref().unwrap().name, "prod-ssh");
        assert!(prompt.ssh.is_none(), "an open prompt is not a trust prompt");
        self.broker
            .decide(&prompt.id, UiDecision::AllowOnce, &ctx())
            .unwrap();
        let (status, body) = call.await.unwrap();
        assert_eq!(status, 200, "open failed: {body}");
        assert_eq!(body["user"], "deploy");
        assert_eq!(body["host"], "prod.example.com");
        assert_eq!(body["destination"], "prod");
        (body["auth_sock"].as_str().unwrap().to_string(), body)
    }
}

/// Connect a fresh agent connection and session-bind `host_key` on it, in a
/// background task — a trust-on-first-use bind blocks on the approval
/// decision, so the test thread must stay free to decide it.
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

    let socket = h.daemon.socket_path.clone();
    let auth = format!("Bearer {token}");
    let call = tokio::spawn(async move {
        uds_request(
            &socket,
            "POST",
            "/v1/ssh/open",
            &[("authorization", &auth)],
            Some(json!({"connection": "prod-ssh"})),
        )
        .await
    });
    let prompt = tokio::time::timeout(Duration::from_secs(5), h.prompts.recv())
        .await
        .unwrap()
        .unwrap();
    h.broker
        .decide(&prompt.id, UiDecision::AllowOnce, &ctx())
        .unwrap();
    let (status, body) = call.await.unwrap();
    assert_eq!(status, 502, "unparseable key must fail the open");
    assert_eq!(body["reason"], "ssh_agent_open_failed");
    // Nothing was left listening.
    assert!(h.broker.sessions().is_empty());
}

/* --------------------------- trust on first use --------------------------- */

#[tokio::test]
async fn tofu_first_bind_prompts_pins_and_signs() {
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

    // The bind parks on the trust prompt; decide it from the test thread.
    let bind = spawn_bind(&auth_sock, &host_key);
    let prompt = tokio::time::timeout(Duration::from_secs(5), h.prompts.recv())
        .await
        .unwrap()
        .unwrap();
    let view = prompt.ssh.as_ref().expect("trust prompt carries the key");
    assert_eq!(view.observed_fingerprint, observed);
    assert_eq!(view.algorithm, "ssh-ed25519");
    assert_eq!(view.host, "prod.example.com");
    assert_eq!(view.port, 22);
    assert!(prompt.action.contains("Trust SSH host key"));
    assert_eq!(prompt.connection.as_ref().unwrap().name, "prod-ssh");
    h.broker
        .decide(&prompt.id, UiDecision::AllowOnce, &ctx())
        .unwrap();

    let (kind, mut stream) = bind.await.unwrap();
    assert_eq!(kind, SSH_AGENT_SUCCESS, "approved bind succeeds");
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
async fn tofu_denied_bind_fails_and_stays_unpinned() {
    let mut h = harness(BrokerConfig::default()).await;
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    add_ssh_connection_with_fingerprint(&h.broker, &key, "deploy", String::new());
    let host_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let token = h.pair().await;
    let (auth_sock, _) = h.open_ssh(&token).await;

    let bind = spawn_bind(&auth_sock, &host_key);
    let prompt = tokio::time::timeout(Duration::from_secs(5), h.prompts.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(prompt.ssh.is_some());
    h.broker
        .decide(&prompt.id, UiDecision::Deny, &ctx())
        .unwrap();
    let (kind, _stream) = bind.await.unwrap();
    assert_eq!(kind, SSH_AGENT_FAILURE, "denied bind fails");
    assert_eq!(stored_fingerprint(&h.broker), "", "denial pins nothing");

    // Denial is not a standing decision: the next bind asks again, and an
    // approval then pins normally.
    let bind = spawn_bind(&auth_sock, &host_key);
    let prompt = tokio::time::timeout(Duration::from_secs(5), h.prompts.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(prompt.ssh.is_some(), "denial does not suppress re-asking");
    h.broker
        .decide(&prompt.id, UiDecision::AllowOnce, &ctx())
        .unwrap();
    let (kind, _stream) = bind.await.unwrap();
    assert_eq!(kind, SSH_AGENT_SUCCESS);
    assert_eq!(
        stored_fingerprint(&h.broker),
        host_key
            .public_key()
            .fingerprint(HashAlg::Sha256)
            .to_string()
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

    let bind = spawn_bind(&auth_sock, &host_key);
    let prompt = tokio::time::timeout(Duration::from_secs(5), h.prompts.recv())
        .await
        .unwrap()
        .unwrap();
    h.broker
        .decide(&prompt.id, UiDecision::AllowOnce, &ctx())
        .unwrap();
    assert_eq!(bind.await.unwrap().0, SSH_AGENT_SUCCESS);

    // A second connection binds the pinned key with no prompt at all.
    let mut again = UnixStream::connect(&auth_sock).await.unwrap();
    assert_eq!(bind_host(&mut again, &host_key).await, SSH_AGENT_SUCCESS);
    // A different server key is refused outright — and silently.
    let imposter = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let mut wrong = UnixStream::connect(&auth_sock).await.unwrap();
    assert_eq!(bind_host(&mut wrong, &imposter).await, SSH_AGENT_FAILURE);
    assert!(
        h.prompts.try_recv().is_err(),
        "no prompt after the key is pinned"
    );
}

#[tokio::test]
async fn tofu_concurrent_binds_prompt_once_and_both_succeed() {
    let mut h = harness(BrokerConfig::default()).await;
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    add_ssh_connection_with_fingerprint(&h.broker, &key, "deploy", String::new());
    let host_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let token = h.pair().await;
    let (auth_sock, _) = h.open_ssh(&token).await;

    // Two clients race the first bind; the gate serializes them so exactly
    // one trust prompt is raised, and the loser re-checks the pinned state.
    let first = spawn_bind(&auth_sock, &host_key);
    let second = spawn_bind(&auth_sock, &host_key);
    let prompt = tokio::time::timeout(Duration::from_secs(5), h.prompts.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(prompt.ssh.is_some());
    h.broker
        .decide(&prompt.id, UiDecision::AllowOnce, &ctx())
        .unwrap();
    assert_eq!(first.await.unwrap().0, SSH_AGENT_SUCCESS);
    assert_eq!(second.await.unwrap().0, SSH_AGENT_SUCCESS);
    assert!(h.prompts.try_recv().is_err(), "exactly one trust prompt");
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

    let bind = spawn_bind(&first_sock, &host_key);
    let prompt = tokio::time::timeout(Duration::from_secs(5), h.prompts.recv())
        .await
        .unwrap()
        .unwrap();
    h.broker
        .decide(&prompt.id, UiDecision::AllowOnce, &ctx())
        .unwrap();
    assert_eq!(bind.await.unwrap().0, SSH_AGENT_SUCCESS);

    // The second socket re-reads the store instead of prompting again.
    let mut stream = UnixStream::connect(&second_sock).await.unwrap();
    assert_eq!(bind_host(&mut stream, &host_key).await, SSH_AGENT_SUCCESS);
    let imposter = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let mut wrong = UnixStream::connect(&second_sock).await.unwrap();
    assert_eq!(bind_host(&mut wrong, &imposter).await, SSH_AGENT_FAILURE);
    assert!(h.prompts.try_recv().is_err(), "no second trust prompt");
}

#[tokio::test]
async fn tofu_timeout_auto_denies_and_stays_unpinned() {
    let config = BrokerConfig {
        approval_timeout: Duration::from_millis(1500),
        ..BrokerConfig::default()
    };
    let mut h = harness(config).await;
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    add_ssh_connection_with_fingerprint(&h.broker, &key, "deploy", String::new());
    let host_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let token = h.pair().await;
    let (auth_sock, _) = h.open_ssh(&token).await;

    // Nobody decides: the approval auto-denies and the bind fails closed.
    let bind = spawn_bind(&auth_sock, &host_key);
    let prompt = tokio::time::timeout(Duration::from_secs(5), h.prompts.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(prompt.ssh.is_some());
    let (kind, _stream) = tokio::time::timeout(Duration::from_secs(10), bind)
        .await
        .expect("auto-deny resolves the bind")
        .unwrap();
    assert_eq!(kind, SSH_AGENT_FAILURE);
    assert_eq!(stored_fingerprint(&h.broker), "", "timeout pins nothing");
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
