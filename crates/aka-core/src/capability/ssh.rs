//! SSH capability — `POST /v1/ssh/open` + a per-open ssh-agent socket
//!
//! SSH has no request/response envelope and no DSN: a stock `ssh` (and
//! therefore `git`, `scp`, `rsync`, `ssh -L`, …) authenticates by talking
//! the **ssh-agent protocol** over the socket named by `SSH_AUTH_SOCK`. So
//! the broker acts as a **scoped signing oracle**: on an approved open it
//! reads the connection's private key from the vault when one is configured,
//! binds a fresh agent socket, and hands the agent back its path. The agent points
//! `SSH_AUTH_SOCK` at it and runs any unmodified SSH client — the key never
//! leaves the broker.
//!
//! Unlike the PG proxy (one shared loopback-TCP listener bound
//! at daemon start), each SSH open binds its **own** Unix-domain socket:
//! the ssh-agent wire protocol carries no ticket field, so the socket path
//! *is* the capability. The socket lives under `~/.aka/ssh/`, created
//! `0700`, and the socket itself `0600` — only the same local user can reach
//! it, a strictly tighter boundary than the loopback-TCP data planes.
//!
//! What the oracle will and won't do:
//! - **REQUEST_IDENTITIES** returns the pinned public key, or an empty list
//!   for a connection configured without a brokered secret.
//! - **session-bind@openssh.com** must prove possession of the configured
//!   host key for this SSH transport.
//! - **SIGN_REQUEST** is honored only for host-bound public-key userauth that
//!   names the configured user, pinned authentication key, verified session
//!   id, and configured host key. Every signature and refusal is audited,
//!   attributed to the agent the socket was opened for.
//!
//! # What the switch confirms
//!
//! With traffic confirmation on, each **login** is confirmed: the gate sits in
//! `SIGN_REQUEST`, after the userauth blob has been checked against the pinned
//! key, user, and session-bound host key, so the prompt names a destination
//! that has been verified rather than merely configured. Listing identities
//! and session-bind are not gated — neither authenticates anything.
//!
//! A login is the narrowest unit this plane has, and it is worth being plain
//! about the gap between it and a command. The agent signs the handshake and
//! is then out of the connection: `ssh` talks to the host directly, so nothing
//! here can see the commands that follow, bound the session's length, or close
//! it. Confirming a login means confirming everything that login goes on to
//! do. The prompt says so ([`LOGIN_CONSEQUENCE`]) rather than implying a
//! per-command gate that does not exist; getting one would take a full SSH
//! transport proxy in place of agent forwarding.
//!
//! Repeated logins ride the approval window like any other plane, so a `git`
//! loop against one host asks once rather than once per fetch.
//!
//! v1 signs **ed25519** and **RSA** (`rsa-sha2-256` / `rsa-sha2-512`,
//! selected by the client's SIGN_REQUEST flags) keys.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rsa::pkcs1v15;
use sha2::{Sha256, Sha512};
use signature::{SignatureEncoding as _, Signer as _, Verifier as _};
use ssh_key::private::KeypairData;
use ssh_key::{Algorithm, Fingerprint, HashAlg, PrivateKey, PublicKey, Signature};
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Notify;

use uuid::Uuid;

use super::{TestError, TestErrorKind};
use crate::audit::{AuditEntry, AuditKind};
use crate::broker::Broker;
use crate::endpoints::EndpointListenerHandle;
use crate::sessions::SessionHandle;
use crate::store::{PinOutcome, Store};
use crate::types::{Connection, ConnectionConfig, ConnectionKind, DirectEndpoint};

/* --------------------------- ssh-agent protocol --------------------------- */

// Message numbers (OpenSSH PROTOCOL.agent).
const SSH_AGENT_FAILURE: u8 = 5;
const SSH_AGENT_SUCCESS: u8 = 6;
const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
const SSH_AGENT_SIGN_RESPONSE: u8 = 14;
const SSH_AGENTC_EXTENSION: u8 = 27;

const SESSION_BIND_EXTENSION: &[u8] = b"session-bind@openssh.com";
const HOSTBOUND_AUTH_METHOD: &[u8] = b"publickey-hostbound-v00@openssh.com";

// SIGN_REQUEST flags selecting the RSA hash (OpenSSH PROTOCOL.agent).
const SSH_AGENT_RSA_SHA2_256: u32 = 2;
const SSH_AGENT_RSA_SHA2_512: u32 = 4;

// SSH_MSG_USERAUTH_REQUEST message number (RFC 4252 §5).
const SSH_MSG_USERAUTH_REQUEST: u8 = 50;

/// Agent messages are tiny (a key blob, a userauth blob); cap defensively.
const MAX_AGENT_MESSAGE: usize = 256 * 1024;

/// How long past the ticket window the socket file lingers so an in-window
/// reconnect still finds it; redemption expiry is enforced independently.
const SOCKET_GRACE: Duration = Duration::from_secs(30);

/* ------------------------------ wire helpers ------------------------------ */

/// Cursor over an SSH-encoded byte string (RFC 4251 §5): `u32` length-prefixed
/// blobs, `byte`, `boolean`, `u32`.
struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data }
    }
    fn u8(&mut self) -> Option<u8> {
        let (first, rest) = self.data.split_first()?;
        self.data = rest;
        Some(*first)
    }
    fn u32(&mut self) -> Option<u32> {
        if self.data.len() < 4 {
            return None;
        }
        let (head, rest) = self.data.split_at(4);
        self.data = rest;
        Some(u32::from_be_bytes([head[0], head[1], head[2], head[3]]))
    }
    fn string(&mut self) -> Option<&'a [u8]> {
        let len = self.u32()? as usize;
        if self.data.len() < len {
            return None;
        }
        let (s, rest) = self.data.split_at(len);
        self.data = rest;
        Some(s)
    }
    fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

fn put_string(buf: &mut Vec<u8>, s: &[u8]) {
    buf.extend_from_slice(&(s.len() as u32).to_be_bytes());
    buf.extend_from_slice(s);
}

/// Frame an agent message: `u32` self-exclusive length + `byte` type + body.
fn frame(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 5);
    out.extend_from_slice(&((body.len() + 1) as u32).to_be_bytes());
    out.push(kind);
    out.extend_from_slice(body);
    out
}

/// Read one length-prefixed agent message; returns `(type, payload)`.
async fn read_message<R: tokio::io::AsyncRead + Unpin>(
    stream: &mut R,
) -> std::io::Result<(u8, Vec<u8>)> {
    let mut len = [0u8; 4];
    stream.read_exact(&mut len).await?;
    let len = u32::from_be_bytes(len) as usize;
    if len == 0 || len > MAX_AGENT_MESSAGE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid agent message length {len}"),
        ));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    let kind = buf[0];
    Ok((kind, buf.split_off(1)))
}

/* -------------------------------- signer ---------------------------------- */

/// Rebuild an `rsa::RsaPrivateKey` from an ssh-key `RsaKeypair`'s components.
///
/// ssh-key 0.6's own `TryFrom<&RsaKeypair> for rsa::RsaPrivateKey` (and thus
/// its blanket RSA `Signer`) is buggy — it passes prime `p` twice instead of
/// `p, q`, so `from_components` rejects the key. We assemble it correctly
/// from the public `(n, e)` and private `(d, p, q)` fields.
fn rsa_private_key(keypair: &ssh_key::private::RsaKeypair) -> Result<rsa::RsaPrivateKey, String> {
    let big = |m: &ssh_key::Mpint, what: &str| {
        rsa::BigUint::try_from(m).map_err(|e| format!("rsa {what}: {e}"))
    };
    let n = big(&keypair.public.n, "modulus")?;
    let e = big(&keypair.public.e, "exponent")?;
    let d = big(&keypair.private.d, "private exponent")?;
    let p = big(&keypair.private.p, "prime p")?;
    let q = big(&keypair.private.q, "prime q")?;
    rsa::RsaPrivateKey::from_components(n, e, d, vec![p, q])
        .map_err(|e| format!("rsa key assembly failed: {e}"))
}

/// A parsed private key ready to answer the two agent requests we honor. The
/// key material is read from the vault once, at open time, and held for the
/// ticket's life (same shape as the PG proxy reading its password at dial).
pub struct SshSigner {
    key: PrivateKey,
    /// SSH wire encoding of the public key — the identity we advertise and
    /// the blob a SIGN_REQUEST must match.
    public_blob: Vec<u8>,
}

/// Validate an SSH private key before it is saved by a trusted onboarding
/// surface. This deliberately enforces the same format and algorithm rules as
/// the runtime signer so an imported credential cannot fail only at first use.
pub fn validate_private_key(pem: &[u8]) -> Result<(), String> {
    parse_supported_private_key(pem).map(|_| ())
}

fn parse_supported_private_key(pem: &[u8]) -> Result<PrivateKey, String> {
    let key =
        PrivateKey::from_openssh(pem).map_err(|e| format!("private key parse failed: {e}"))?;
    if key.is_encrypted() {
        return Err("private key is passphrase-encrypted; store the decrypted OpenSSH key".into());
    }
    match key.key_data() {
        KeypairData::Ed25519(_) | KeypairData::Rsa(_) => {}
        other => {
            return Err(format!(
                "unsupported key type {:?} (v1 signs ed25519 and rsa)",
                other.algorithm().map(|a| a.as_str().to_string())
            ))
        }
    }
    Ok(key)
}

impl SshSigner {
    async fn load_optional(store: &Store, connection: &Connection) -> Result<Option<Self>, String> {
        if connection.secrets.is_empty() {
            Ok(None)
        } else {
            Self::load(store, connection).await.map(Some)
        }
    }

    /// Read and parse the connection's bound private key. Fails the open (not
    /// each later signature) on a missing, encrypted, or unsupported key.
    pub async fn load(store: &Store, connection: &Connection) -> Result<Self, String> {
        let secret_id = connection
            .secrets
            .first()
            .ok_or_else(|| "connection binds no secret".to_string())?;
        let pem = store
            .secret_value(secret_id)
            .await
            .map_err(|e| format!("The saved credential could not be read: {e}"))?;
        let key = parse_supported_private_key(pem.as_bytes())?;
        let public_blob = key
            .public_key()
            .to_bytes()
            .map_err(|e| format!("public key encode failed: {e}"))?;
        Ok(Self { key, public_blob })
    }

    /// Sign `data` honoring the SIGN_REQUEST `flags` (they select the RSA
    /// hash; ed25519 has one algorithm). Returns the SSH-encoded signature
    /// blob (`string alg` + `string sig`) the SIGN_RESPONSE carries.
    ///
    /// RSA signing can take long enough to matter on an async worker; callers
    /// should run this through `sign_on_blocking_thread`.
    fn sign(&self, data: &[u8], flags: u32) -> Result<Vec<u8>, String> {
        let signature: Signature = match self.key.key_data() {
            KeypairData::Ed25519(_) => self
                .key
                .try_sign(data)
                .map_err(|e| format!("ed25519 sign failed: {e}"))?,
            KeypairData::Rsa(keypair) => {
                let hash = if flags & SSH_AGENT_RSA_SHA2_256 != 0 {
                    HashAlg::Sha256
                } else if flags & SSH_AGENT_RSA_SHA2_512 != 0 {
                    HashAlg::Sha512
                } else {
                    // No hash flag → the client asked for legacy SHA-1
                    // `ssh-rsa`, which modern servers reject; sign SHA-512
                    // rather than produce a signature nothing will accept.
                    HashAlg::Sha512
                };
                let private = rsa_private_key(keypair)?;
                let raw = match hash {
                    HashAlg::Sha256 => pkcs1v15::SigningKey::<Sha256>::new(private)
                        .try_sign(data)
                        .map_err(|e| format!("rsa sign failed: {e}"))?
                        .to_vec(),
                    HashAlg::Sha512 => pkcs1v15::SigningKey::<Sha512>::new(private)
                        .try_sign(data)
                        .map_err(|e| format!("rsa sign failed: {e}"))?
                        .to_vec(),
                    _ => unreachable!("hash pinned to sha256/sha512 above"),
                };
                Signature::new(Algorithm::Rsa { hash: Some(hash) }, raw)
                    .map_err(|e| format!("rsa signature encode failed: {e}"))?
            }
            _ => return Err("unsupported key type".into()),
        };
        Vec::<u8>::try_from(signature).map_err(|e| format!("signature encode failed: {e}"))
    }

    /// The IDENTITIES_ANSWER body advertising our single identity.
    fn identities_answer(&self, comment: &str) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&1u32.to_be_bytes()); // one key
        put_string(&mut body, &self.public_blob);
        put_string(&mut body, comment.as_bytes());
        body
    }
}

async fn sign_on_blocking_thread(
    signer: Arc<SshSigner>,
    data: Vec<u8>,
    flags: u32,
) -> Result<Vec<u8>, String> {
    tokio::task::spawn_blocking(move || signer.sign(&data, flags))
        .await
        .map_err(|e| format!("sign task failed: {e}"))?
}

struct HostboundUserauth<'a> {
    session_id: &'a [u8],
    user: &'a str,
    host_key: &'a [u8],
}

/// Parse the OpenSSH host-bound public-key request carried by SIGN_REQUEST.
fn hostbound_userauth<'a>(data: &'a [u8], public_blob: &[u8]) -> Option<HostboundUserauth<'a>> {
    let mut r = Reader::new(data);
    let session_id = r.string()?;
    if r.u8()? != SSH_MSG_USERAUTH_REQUEST {
        return None;
    }
    let user = std::str::from_utf8(r.string()?).ok()?;
    let service = r.string()?;
    if service != b"ssh-connection" {
        return None;
    }
    if r.string()? != HOSTBOUND_AUTH_METHOD {
        return None;
    }
    // has-signature boolean is TRUE for the blob the client signs.
    if r.u8()? == 0 {
        return None;
    }
    let _alg = r.string()?;
    let key_blob = r.string()?;
    if key_blob != public_blob {
        return None;
    }
    let host_key = r.string()?;
    if !r.is_empty() {
        return None;
    }
    Some(HostboundUserauth {
        session_id,
        user,
        host_key,
    })
}

#[derive(Debug, Clone)]
struct SessionBinding {
    host_key: Vec<u8>,
    session_id: Vec<u8>,
}

/// A session-bind that passed every structural and cryptographic check —
/// parse, forwarding refusal, and the host key's signature over the session
/// id — before any comparison against a pinned fingerprint. The caller
/// decides what to compare `public` against (or, on the first-use path, to
/// ask the user to trust it).
#[derive(Debug)]
struct ObservedBinding {
    binding: SessionBinding,
    public: PublicKey,
}

fn parse_and_verify_session_bind(payload: &[u8]) -> Result<ObservedBinding, String> {
    let mut r = Reader::new(payload);
    if r.string() != Some(SESSION_BIND_EXTENSION) {
        return Err("unsupported agent extension".into());
    }
    let host_key = r.string().ok_or("missing session-bind host key")?;
    let session_id = r.string().ok_or("missing session-bind session id")?;
    let signature = r.string().ok_or("missing session-bind signature")?;
    let forwarding = r.u8().ok_or("missing session-bind forwarding flag")?;
    if !r.is_empty() || forwarding > 1 {
        return Err("malformed session-bind request".into());
    }
    if forwarding != 0 {
        return Err("forwarded SSH agent sessions are not allowed".into());
    }

    let public = PublicKey::from_bytes(host_key)
        .map_err(|e| format!("invalid session-bind host key: {e}"))?;
    let signature = Signature::try_from(signature)
        .map_err(|e| format!("invalid session-bind signature: {e}"))?;
    public
        .key_data()
        .verify(session_id, &signature)
        .map_err(|e| format!("session-bind host signature failed: {e}"))?;

    Ok(ObservedBinding {
        binding: SessionBinding {
            host_key: host_key.to_vec(),
            session_id: session_id.to_vec(),
        },
        public,
    })
}

fn verify_session_bind(payload: &[u8], expected: Fingerprint) -> Result<SessionBinding, String> {
    let observed = parse_and_verify_session_bind(payload)?;
    let actual = observed.public.fingerprint(expected.algorithm());
    if actual != expected {
        return Err(format!(
            "host key fingerprint {actual} does not match configured {expected}"
        ));
    }
    Ok(observed.binding)
}

/* -------------------------------- listener -------------------------------- */

/// Removes the socket file when the accept loop ends, however it ends.
struct SocketGuard(PathBuf);
impl Drop for SocketGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

struct AgentState {
    broker: Arc<Broker>,
    ticket: String,
    /// Pinned login the userauth blob must name.
    user: String,
    /// The pinned host key: `Some` from open time when the connection was
    /// already pinned, otherwise `None` until trust-on-first-use pins it at
    /// the first session-bind. A `Mutex` because the TOFU path writes it
    /// while other connections on this socket read it.
    host_key_fingerprint: tokio::sync::Mutex<Option<Fingerprint>>,
    /// Serializes unpinned session-binds across this socket's connections so
    /// one open raises at most one trust prompt at a time; the loser of the
    /// race re-checks the (then pinned) state instead of double-prompting.
    bind_gate: tokio::sync::Mutex<()>,
    connection_id: Uuid,
    connection_name: String,
    /// Self-reported label of the agent this socket was opened for, or
    /// `"endpoint"` for a standing one. Attribution for the prompt and the
    /// signature log, never authorization — the socket path is the capability.
    agent: String,
    comment: String,
    signer: Option<Arc<SshSigner>>,
}

/// UI-initiated reachability test: load a stored key when configured
/// (validating that it parses) and read the server's version banner.
/// No key exchange is performed, so login and the host key stay unverified.
pub async fn test_reachability(
    store: &Store,
    connection: &Connection,
) -> Result<String, TestError> {
    let ConnectionConfig::Ssh { host, port, .. } = &connection.config else {
        return Err("not an ssh connection".into());
    };
    let has_key = SshSigner::load_optional(store, connection).await?.is_some();
    let stream = tokio::net::TcpStream::connect((host.as_str(), *port))
        .await
        .map_err(|e| {
            TestError::new(
                TestErrorKind::Unreachable,
                format!("Could not reach {host}:{port}: {e}"),
            )
        })?;
    let banner = read_version_banner(stream).await?;
    let key_detail = if has_key { "Key loaded; " } else { "" };
    Ok(format!(
        "{key_detail}{host}:{port} answered with {banner}. Login and host key are not verified by this test."
    ))
}

/// UI-initiated saved-connection test: authenticate a stock OpenSSH client
/// through a short-lived, connection-scoped agent. The private key stays in
/// the broker; the client receives only signatures. A configured host-key
/// fingerprint is enforced by the agent's OpenSSH session binding.
///
/// A connection with no brokered key has nothing to log in *with*, so it
/// falls back to the reachability probe rather than grading as a rejection:
/// an empty identity list is a supported configuration here, not a fault.
pub async fn test_login(broker: &Broker, connection: &Connection) -> Result<String, TestError> {
    let ConnectionConfig::Ssh {
        destination,
        host,
        port,
        user,
        host_key_fingerprint,
    } = &connection.config
    else {
        return Err("not an ssh connection".into());
    };
    let Some(signer) = SshSigner::load_optional(&broker.store, connection).await? else {
        return test_reachability(&broker.store, connection).await;
    };
    let expected_host_key = if host_key_fingerprint.is_empty() {
        None
    } else {
        Some(
            host_key_fingerprint
                .parse::<Fingerprint>()
                .map_err(|e| format!("SSH host key fingerprint is invalid: {e}"))?,
        )
    };

    let socket_dir = tempfile::Builder::new()
        .prefix("aka-ssh-test-")
        .tempdir()
        .map_err(|e| format!("Could not create the SSH test socket: {e}"))?;
    let socket_path = socket_dir.path().join("agent.sock");
    let listener = UnixListener::bind(&socket_path)
        .map_err(|e| format!("Could not create the SSH test agent: {e}"))?;
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("Could not secure the SSH test agent: {e}"))?;
    }

    // `ssh -E` sends the client's own diagnostics here instead of stderr.
    // That separation is load-bearing: stderr also carries the server's
    // pre-auth banner verbatim, so a server could otherwise write any
    // sentence this function looks for into the text it grades.
    let log_path = socket_dir.path().join("ssh.log");

    let state = Arc::new(TestAgentState {
        user: user.clone(),
        expected_host_key,
        observed_host_key: std::sync::Mutex::new(None),
        signer: Arc::new(signer),
        signed: AtomicBool::new(false),
        refusal: std::sync::Mutex::new(None),
    });
    let listener_state = state.clone();
    let _listener_task = AbortOnDrop(tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let state = listener_state.clone();
            tokio::spawn(async move {
                let mut binding = None;
                loop {
                    let Ok((kind, payload)) = read_message(&mut stream).await else {
                        break;
                    };
                    let response = handle_test_request(&state, &mut binding, kind, &payload).await;
                    if stream.write_all(&response).await.is_err() {
                        break;
                    }
                }
                let _ = stream.shutdown().await;
            });
        }
    }));

    // Use the original alias when one was imported so ProxyJump and other
    // routing from ~/.ssh/config still apply. User/port and all credential
    // sources are pinned on the command line; an existing control socket
    // cannot make the test pass without a fresh authentication.
    let target = destination.as_deref().unwrap_or(host);
    let mut command = tokio::process::Command::new("ssh");
    command
        .kill_on_drop(true)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        // With `-E` carrying the diagnostics, stderr holds only the peer's
        // banner. Nothing reads it, so let it go nowhere rather than buffer
        // an arbitrary amount of remote text.
        .stderr(std::process::Stdio::null())
        .arg("-v")
        .arg("-E")
        .arg(&log_path)
        .arg("-o")
        .arg("BatchMode=yes")
        .arg("-o")
        .arg("PasswordAuthentication=no")
        .arg("-o")
        .arg("KbdInteractiveAuthentication=no")
        .arg("-o")
        .arg("PreferredAuthentications=publickey")
        .arg("-o")
        .arg("IdentityFile=none")
        .arg("-o")
        .arg("CertificateFile=none")
        .arg("-o")
        .arg(format!("IdentityAgent={}", socket_path.display()))
        .arg("-o")
        .arg("StrictHostKeyChecking=no")
        .arg("-o")
        .arg("UserKnownHostsFile=/dev/null")
        .arg("-o")
        .arg("GlobalKnownHostsFile=/dev/null")
        .arg("-o")
        .arg("ControlMaster=no")
        .arg("-o")
        .arg("ControlPath=none")
        .arg("-o")
        .arg("ClearAllForwardings=yes")
        .arg("-o")
        .arg("PermitLocalCommand=no")
        .arg("-o")
        .arg("RequestTTY=no")
        .arg("-l")
        .arg(user)
        .arg("-p")
        .arg(port.to_string())
        .arg("--")
        .arg(target)
        .arg("true")
        .env_remove("SSH_AUTH_SOCK");
    let output = command.output().await.map_err(|e| {
        TestError::new(
            TestErrorKind::Other,
            format!("Could not start the system SSH client: {e}"),
        )
    });
    let output = output?;
    // Only ssh's own log is evidence. Anything the peer chose — the banner,
    // a jump host's inherited stderr — is read for nothing.
    let log = std::fs::read_to_string(&log_path).unwrap_or_default();

    let graded = grade_login(broker, connection, &state, output.status, &log);
    audit_login_attempt(broker, connection, &state, &graded);
    graded
}

/// Grade the finished `ssh` run. Split out of `test_login` so the attempt
/// audits exactly once whichever way it went, without an audit call before
/// each of the early returns.
fn grade_login(
    broker: &Broker,
    connection: &Connection,
    state: &TestAgentState,
    status: std::process::ExitStatus,
    log: &str,
) -> Result<String, TestError> {
    let ConnectionConfig::Ssh {
        host, port, user, ..
    } = &connection.config
    else {
        return Err("not an ssh connection".into());
    };

    // A signature is the one thing that proves *this* connection's key
    // authenticated: the agent issues it only after a session-bind matching
    // the configured host key and for userauth naming the configured user.
    // The exit status alone would also accept a login that got in some other
    // way; the log line alone would accept a session the server cut off
    // after the banner. Requiring both a signature and a completed login
    // leaves no path to a false success.
    let signed = state.signed.load(Ordering::Relaxed);
    // A restricted shell (git-shell and friends) refuses `true` and exits
    // non-zero long after authenticating, so the log line stands in for the
    // exit status there.
    let authenticated = log.contains("Authenticated to ");
    if signed && (status.success() || authenticated) {
        let host_key_detail = if state.expected_host_key.is_some() {
            " Verified the pinned host key.".to_string()
        } else {
            let (observed, observed_sha512) =
                state.observed_host_key.lock().unwrap().ok_or_else(|| {
                    TestError::new(
                        TestErrorKind::Other,
                        "SSH signed in without reporting the server host key",
                    )
                })?;
            let pinned = match broker.store.pin_ssh_host_key(&connection.id, &observed) {
                // Trust-on-first-use, same as the open path: record the pin
                // and tell the UI, or the newly pinned fingerprint sits in
                // the store with nothing to show it arrived.
                Ok(PinOutcome::Pinned(pinned)) => {
                    broker.audit.append(
                        AuditEntry::new(
                            AuditKind::SshHostKeyPinned,
                            format!("SSH host key trusted: {}", connection.name),
                        )
                        .connection(connection.name.clone())
                        .detail(format!("{pinned} pinned by a connection test"))
                        .outcome("pinned"),
                    );
                    broker.events.connections_changed();
                    pinned
                }
                Ok(PinOutcome::AlreadyPinned(pinned))
                    if pinned == observed || pinned == observed_sha512 =>
                {
                    pinned
                }
                Ok(PinOutcome::AlreadyPinned(pinned)) => {
                    return Err(TestError::new(
                        TestErrorKind::AuthRejected,
                        format!(
                            "SSH login saw host key {observed}, but the tool was pinned to {pinned}"
                        ),
                    ))
                }
                Err(error) => {
                    return Err(TestError::new(
                        TestErrorKind::Other,
                        format!("Signed in, but could not pin the SSH host key: {error}"),
                    ))
                }
            };
            format!(" Pinned host key {pinned}.")
        };
        return Ok(format!(
            "Signed in to {host}:{port} as {user} with the saved key.{host_key_detail}"
        ));
    }

    // Cloned, not taken: the audit pass reads the same reason afterwards.
    if let Some(reason) = state.refusal.lock().unwrap().clone() {
        return Err(TestError::new(
            TestErrorKind::AuthRejected,
            format!("SSH login was refused: {reason}"),
        ));
    }
    let log_lower = log.to_ascii_lowercase();
    if log_lower.contains("permission denied")
        || log_lower.contains("no supported authentication methods")
    {
        return Err(TestError::new(
            TestErrorKind::AuthRejected,
            format!("The server rejected the saved key for {user}@{host}"),
        ));
    }
    if log_lower.contains("could not resolve hostname")
        || log_lower.contains("connection refused")
        || log_lower.contains("connection timed out")
        || log_lower.contains("operation timed out")
        || log_lower.contains("no route to host")
    {
        return Err(TestError::new(
            TestErrorKind::Unreachable,
            format!("Could not reach {host}:{port}"),
        ));
    }
    Err(TestError::new(
        TestErrorKind::Other,
        format!("SSH login to {host}:{port} as {user} failed"),
    ))
}

/// One activity line per login test. The open path audits per agent message
/// because each one is an independent grant; a test is a single attempt the
/// user asked for, so it reads better as a single entry — but it is still a
/// real signature with the connection's key, and must not be silent.
fn audit_login_attempt(
    broker: &Broker,
    connection: &Connection,
    state: &TestAgentState,
    graded: &Result<String, TestError>,
) {
    let refusal = state.refusal.lock().unwrap().clone();
    let (outcome, detail) = match (graded, refusal) {
        (Ok(detail), _) => ("signed", detail.clone()),
        (Err(_), Some(reason)) => ("refused", reason),
        (Err(error), None) => ("failed", error.detail.clone()),
    };
    broker.audit.append(
        AuditEntry::new(
            AuditKind::SshSigned,
            format!("SSH login tested: {}", connection.name),
        )
        .connection(connection.name.clone())
        .detail(detail)
        .outcome(outcome),
    );
}

/// Ends the agent's accept loop however `test_login` ends. An inline abort
/// after the `ssh` run would be skipped entirely when the caller's timeout
/// drops the whole future, leaking the task and its listening socket for the
/// life of the process — dropping a `JoinHandle` does not cancel its task.
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct TestAgentState {
    user: String,
    expected_host_key: Option<Fingerprint>,
    observed_host_key: std::sync::Mutex<Option<(Fingerprint, Fingerprint)>>,
    signer: Arc<SshSigner>,
    /// Set once the agent has actually signed a host-bound userauth for this
    /// connection's key. The login report is gated on it.
    signed: AtomicBool,
    refusal: std::sync::Mutex<Option<String>>,
}

/// Record why the agent said no. The *first* refusal is kept: it is the root
/// cause, and later ones (a second connection re-binding, say) would bury it.
fn refuse_test(state: &TestAgentState, reason: impl Into<String>) -> Vec<u8> {
    let mut refusal = state.refusal.lock().unwrap();
    if refusal.is_none() {
        *refusal = Some(reason.into());
    }
    frame(SSH_AGENT_FAILURE, &[])
}

async fn handle_test_request(
    state: &Arc<TestAgentState>,
    binding: &mut Option<SessionBinding>,
    kind: u8,
    payload: &[u8],
) -> Vec<u8> {
    match kind {
        SSH_AGENTC_REQUEST_IDENTITIES => frame(
            SSH_AGENT_IDENTITIES_ANSWER,
            &state.signer.identities_answer("aka:test"),
        ),
        SSH_AGENTC_EXTENSION => {
            if binding.is_some() {
                return refuse_test(state, "agent connection is already session-bound");
            }
            let observed = match parse_and_verify_session_bind(payload) {
                Ok(observed) => observed,
                Err(reason) => return refuse_test(state, reason),
            };
            if let Some(expected) = state.expected_host_key {
                let actual = observed.public.fingerprint(expected.algorithm());
                if actual != expected {
                    return refuse_test(
                        state,
                        format!(
                            "host key fingerprint {actual} does not match configured {expected}"
                        ),
                    );
                }
            }
            *state.observed_host_key.lock().unwrap() = Some((
                observed.public.fingerprint(HashAlg::Sha256),
                observed.public.fingerprint(HashAlg::Sha512),
            ));
            *binding = Some(observed.binding);
            frame(SSH_AGENT_SUCCESS, &[])
        }
        SSH_AGENTC_SIGN_REQUEST => {
            let Some(binding) = binding.as_ref() else {
                return refuse_test(state, "SSH client did not bind the configured host key");
            };
            let mut r = Reader::new(payload);
            let (Some(key_blob), Some(data), Some(flags)) = (r.string(), r.string(), r.u32())
            else {
                return refuse_test(state, "malformed sign request");
            };
            if !r.is_empty() || key_blob != state.signer.public_blob {
                return refuse_test(state, "sign request names a different key");
            }
            let Some(auth) = hostbound_userauth(data, &state.signer.public_blob) else {
                return refuse_test(
                    state,
                    "data is not host-bound publickey userauth for the configured key",
                );
            };
            if auth.session_id != binding.session_id || auth.host_key != binding.host_key {
                return refuse_test(state, "userauth does not match the bound SSH session");
            }
            if auth.user != state.user {
                return refuse_test(
                    state,
                    format!(
                        "userauth names {:?}, connection pins {:?}",
                        auth.user, state.user
                    ),
                );
            }
            match sign_on_blocking_thread(state.signer.clone(), data.to_vec(), flags).await {
                Ok(sig_blob) => {
                    state.signed.store(true, Ordering::Relaxed);
                    let mut body = Vec::new();
                    put_string(&mut body, &sig_blob);
                    frame(SSH_AGENT_SIGN_RESPONSE, &body)
                }
                Err(error) => refuse_test(state, format!("sign failed: {error}")),
            }
        }
        _ => frame(SSH_AGENT_FAILURE, &[]),
    }
}

/// Read until the SSH identification line arrives. RFC 4253 §4.2 lets the
/// server send other lines first, so scan complete lines for the `SSH-`
/// prefix, capped so a non-SSH endpoint cannot stall the test.
async fn read_version_banner(mut stream: tokio::net::TcpStream) -> Result<String, TestError> {
    const BANNER_SCAN_CAP: usize = 4096;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 512];
    loop {
        let n = stream.read(&mut chunk).await.map_err(|e| {
            format!("The connection was lost while waiting for the SSH banner: {e}")
        })?;
        if n == 0 {
            return Err(TestError::new(
                TestErrorKind::WrongProtocol,
                "The server closed the connection before sending an SSH banner — \
                 check that this is an SSH server",
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
        let mut start = 0;
        while let Some(pos) = buf[start..].iter().position(|b| *b == b'\n') {
            let line = String::from_utf8_lossy(&buf[start..start + pos]);
            let line = line.trim_end_matches('\r').trim();
            if line.starts_with("SSH-") {
                return Ok(line.to_string());
            }
            start += pos + 1;
        }
        if buf.len() > BANNER_SCAN_CAP {
            return Err(TestError::new(
                TestErrorKind::WrongProtocol,
                "The server answered with something other than an SSH banner — \
                 check that this is an SSH server",
            ));
        }
    }
}

/// Bind the per-open agent socket, issue the ticket, and spawn its accept
/// loop. Returns the socket path (`SSH_AUTH_SOCK`) the agent should use.
///
/// The key is parsed *before* the ticket is issued, so a broken or
/// unsupported key fails the open rather than every later signature.
pub async fn open_agent(
    broker: Arc<Broker>,
    agent_name: String,
    connection: Connection,
) -> Result<String, String> {
    let ConnectionConfig::Ssh {
        user,
        host_key_fingerprint,
        ..
    } = &connection.config
    else {
        return Err("not an ssh connection".into());
    };
    let user = user.clone();
    // Empty means unpinned: the key the server presents at the first
    // session-bind is pinned automatically (trust on first use).
    let host_key_fingerprint = if host_key_fingerprint.is_empty() {
        None
    } else {
        Some(
            host_key_fingerprint
                .parse::<Fingerprint>()
                .map_err(|e| format!("SSH host key fingerprint is invalid: {e}"))?,
        )
    };
    let signer = SshSigner::load_optional(&broker.store, &connection)
        .await?
        .map(Arc::new);

    let ticket = broker.data_plane.issue(&agent_name, &connection);
    let dir = broker.paths.ssh_agent_dir();
    crate::paths::create_private_dir(&dir).map_err(|e| format!("ssh socket dir: {e}"))?;
    // The name only needs uniqueness — the 0700 dir is the access control —
    // and must stay short: sun_path caps the whole socket path at ~104 bytes.
    // An independent suffix also keeps the ticket value out of `lsof`/`ls`.
    let mut suffix = [0u8; 8];
    getrandom::fill(&mut suffix).map_err(|e| format!("ssh socket name: {e}"))?;
    let suffix: String = suffix.iter().map(|b| format!("{b:02x}")).collect();
    let socket_path = dir.join(format!("agent-{suffix}.sock"));
    // A crash could have left a same-named file (the ticket is random, so
    // this is belt-and-suspenders); bind fails on a live socket otherwise.
    let _ = std::fs::remove_file(&socket_path);
    let listener =
        UnixListener::bind(&socket_path).map_err(|e| format!("ssh socket bind failed: {e}"))?;
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("ssh socket perms: {e}"))?;
    }

    let state = Arc::new(AgentState {
        broker: broker.clone(),
        ticket,
        user,
        host_key_fingerprint: tokio::sync::Mutex::new(host_key_fingerprint),
        bind_gate: tokio::sync::Mutex::new(()),
        connection_id: connection.id,
        connection_name: connection.name.clone(),
        agent: agent_name,
        comment: format!("aka:{}", connection.name),
        signer,
    });
    let socket_display = socket_path.to_string_lossy().into_owned();
    let deadline = broker.config.ticket_ttl + SOCKET_GRACE;
    tokio::spawn(run_listener(listener, socket_path, state, deadline));
    Ok(socket_display)
}

/// Accept connections until the redemption window closes, then remove the
/// socket file. Connections established before that keep serving under their
/// own session TTL/idle rules (a held fd needs no socket file).
async fn run_listener(
    listener: UnixListener,
    socket_path: PathBuf,
    state: Arc<AgentState>,
    deadline: Duration,
) {
    let _guard = SocketGuard(socket_path);
    let stop = tokio::time::sleep(deadline);
    tokio::pin!(stop);
    loop {
        tokio::select! {
            _ = &mut stop => break,
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => {
                    let state = state.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_conn(state, stream).await {
                            tracing::debug!("ssh agent connection ended: {e}");
                        }
                    });
                }
                Err(e) => {
                    tracing::debug!("ssh agent accept failed: {e}");
                    break;
                }
            },
        }
    }
}

/// One accepted agent connection: redeem the ticket (budget-checked), then
/// serve REQUEST_IDENTITIES / SIGN_REQUEST until the client closes or a
/// lifetime bound fires.
async fn handle_conn(state: Arc<AgentState>, mut stream: UnixStream) -> std::io::Result<()> {
    // The socket path is the capability; every accepted connection redeems
    // the ticket, so per-ticket and global session budgets bound how much
    // one approval can spawn — exactly as the PG data plane does.
    let redemption = match state.broker.data_plane.redeem(&state.ticket) {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!("ssh agent redeem refused: {}", e.reason());
            // The agent wire protocol has no "expired" reply, so a closed
            // connection is all the client gets — it reads as "agent refused",
            // indistinguishable from a wrong key or a revoked authorized_keys
            // entry. Record it so the reason is at least recoverable from
            // Activity.
            state.broker.audit.append(
                AuditEntry::new(
                    AuditKind::Denied,
                    format!("SSH agent connection refused: {}", e.reason()),
                )
                .detail("the socket's ticket could not be redeemed".to_string())
                .outcome(e.reason().as_str().to_string())
                .field("kind", "ssh")
                .field("reason", e.reason().as_str()),
            );
            let _ = stream.shutdown().await;
            return Ok(());
        }
    };

    // Establishment succeeded: register the live session (dropping the
    // redemption without `start` would release the reserved budget slot).
    let max_ttl = state.broker.config.session_max_ttl;
    let session = redemption.start(ConnectionKind::Ssh);
    let idle = state.broker.config.session_idle_timeout;
    let reason = serve(&state, &mut stream, &session, max_ttl, idle).await;
    let _ = stream.shutdown().await;
    session.finish(reason);
    Ok(())
}

/* ------------------------- per-connection endpoint ------------------------ */

/// The filename of a direct SSH endpoint's agent socket, under the
/// endpoint's private directory. Stable across restarts so the user can point
/// `~/.ssh/config`'s `IdentityAgent` at it once.
pub const ENDPOINT_SOCK: &str = "agent.sock";

/// Direct SSH endpoint context: which connection this persistent socket
/// serves, re-checked on every connection.
#[derive(Clone)]
struct SshEndpointCtx {
    endpoint_id: Uuid,
    connection_id: Uuid,
}

/// Bind a persistent direct SSH endpoint: an `SSH_AUTH_SOCK` at a stable
/// path the user points `~/.ssh/config` at (`IdentityAgent …/agent.sock`). It
/// signs only for the connection's pinned user and host key, exactly like the
/// per-open agent, but outlives any single `open`. Unlike a 60 s ticket it is
/// a *standing* signing oracle reachable by any same-user process that knows
/// the path — the same same-user posture the shared-identity model documents,
/// and the reason issuing one is an explicit, confirmed action. Agent access
/// is re-checked on every connection.
pub async fn bind_endpoint(
    broker: Arc<Broker>,
    endpoint: &DirectEndpoint,
) -> std::io::Result<EndpointListenerHandle> {
    let connection = broker
        .store
        .connection_by_id(&endpoint.connection_id)
        .map_err(|e| std::io::Error::other(format!("ssh endpoint: {e}")))?;
    let ConnectionConfig::Ssh {
        user,
        host_key_fingerprint,
        ..
    } = &connection.config
    else {
        return Err(std::io::Error::other("not an ssh connection"));
    };
    let user = user.clone();
    let host_key_fingerprint = if host_key_fingerprint.is_empty() {
        None
    } else {
        Some(
            host_key_fingerprint
                .parse::<Fingerprint>()
                .map_err(|e| std::io::Error::other(format!("bad host key fingerprint: {e}")))?,
        )
    };
    // Parse the key up front so a broken key fails issuance, not every later
    // signature.
    let signer = SshSigner::load_optional(&broker.store, &connection)
        .await
        .map_err(std::io::Error::other)?
        .map(Arc::new);

    let dir = broker.paths.endpoint_dir(&endpoint.id);
    crate::paths::create_private_dir(&dir)?;
    let socket_path = dir.join(ENDPOINT_SOCK);
    let _ = std::fs::remove_file(&socket_path);
    let listener = UnixListener::bind(&socket_path)?;
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))?;
    }

    let state = Arc::new(AgentState {
        broker: broker.clone(),
        // Endpoints never redeem a ticket; the per-connection access re-check
        // gates them instead.
        ticket: String::new(),
        user,
        host_key_fingerprint: tokio::sync::Mutex::new(host_key_fingerprint),
        bind_gate: tokio::sync::Mutex::new(()),
        connection_id: connection.id,
        connection_name: connection.name.clone(),
        // A standing socket is not opened by any one agent; the same label
        // the endpoint's sessions are registered under.
        agent: "endpoint".to_string(),
        comment: format!("aka:{}", connection.name),
        signer,
    });
    let ctx = SshEndpointCtx {
        endpoint_id: endpoint.id,
        connection_id: endpoint.connection_id,
    };
    let shutdown = Arc::new(Notify::new());
    let sd = shutdown.clone();
    let task = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = sd.notified() => break,
                accepted = listener.accept() => match accepted {
                    Ok((stream, _)) => {
                        let state = state.clone();
                        let ctx = ctx.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_endpoint_conn(state, ctx, stream).await {
                                tracing::debug!("ssh endpoint connection ended: {e}");
                            }
                        });
                    }
                    Err(e) => {
                        tracing::debug!("ssh endpoint accept failed: {e}");
                        break;
                    }
                }
            }
        }
    });
    Ok(EndpointListenerHandle { shutdown, task })
}

/// One accepted endpoint connection: re-check access, register a live
/// session, and serve the ssh-agent protocol with the bound signer.
async fn handle_endpoint_conn(
    state: Arc<AgentState>,
    ctx: SshEndpointCtx,
    mut stream: UnixStream,
) -> std::io::Result<()> {
    // Authorization is enforced here, at connect time: a disabled tool is
    // refused even if a stale listener briefly outlived its teardown.
    if !state.broker.access.allows(&ctx.connection_id) {
        let _ = stream.shutdown().await;
        return Ok(());
    }
    let Ok(connection) = state.broker.store.connection_by_id(&ctx.connection_id) else {
        let _ = stream.shutdown().await;
        return Ok(());
    };
    if connection.kind() != ConnectionKind::Ssh {
        let _ = stream.shutdown().await;
        return Ok(());
    }
    let session = match state.broker.data_plane.start_endpoint_session(
        "endpoint",
        &connection,
        ctx.endpoint_id,
        ConnectionKind::Ssh,
    ) {
        Ok(session) => session,
        Err(_) => {
            let _ = stream.shutdown().await;
            return Ok(());
        }
    };
    // Close the establishment race with disable/revoke: either teardown sees
    // the registered session, or this post-registration check sees that the
    // endpoint or access disappeared before the protocol is served.
    let endpoint_still_valid = state
        .broker
        .endpoints
        .get(&ctx.endpoint_id)
        .is_some_and(|endpoint| endpoint.connection_id == ctx.connection_id);
    if !endpoint_still_valid || !state.broker.access.allows(&ctx.connection_id) {
        session.finish("access_revoked");
        let _ = stream.shutdown().await;
        return Ok(());
    }
    let max_ttl = state.broker.config.session_max_ttl;
    let idle = state.broker.config.session_idle_timeout;
    let reason = serve(&state, &mut stream, &session, max_ttl, idle).await;
    let _ = stream.shutdown().await;
    session.finish(reason);
    Ok(())
}

async fn serve(
    state: &Arc<AgentState>,
    stream: &mut UnixStream,
    session: &SessionHandle,
    max_ttl: Duration,
    idle: Duration,
) -> &'static str {
    let ttl_deadline = tokio::time::Instant::now() + max_ttl;
    let mut idle_deadline = tokio::time::Instant::now() + idle;
    let close_signal = session.close_signal.clone();
    let mut binding = None;

    // Buffered read half: answering a request can park on the user, and
    // watching the client for departure while it does must not consume the
    // bytes a pipelining client already sent.
    let (read_half, mut writer) = stream.split();
    let mut reader = BufReader::new(read_half);

    loop {
        tokio::select! {
            _ = close_signal.notified() => return "closed_by_user",
            _ = tokio::time::sleep_until(ttl_deadline) => return "session_ttl",
            _ = tokio::time::sleep_until(idle_deadline) => return "idle_timeout",
            msg = read_message(&mut reader) => {
                let (kind, payload) = match msg {
                    Ok(m) => m,
                    Err(_) => return "client_closed",
                };
                idle_deadline = tokio::time::Instant::now() + idle;
                session
                    .bytes_up
                    .fetch_add(payload.len() as u64 + 1, Ordering::Relaxed);
                // A confirmed SIGN_REQUEST parks here until the user answers,
                // so every bound has to keep running underneath it: closing
                // the session from the app, or its TTL lapsing, must not wait
                // behind a prompt nobody is going to answer. Dropping the
                // request future also drops its approval waiter, which is how
                // the registry learns the prompt has nobody left on it.
                let response = tokio::select! {
                    _ = close_signal.notified() => return "closed_by_user",
                    _ = tokio::time::sleep_until(ttl_deadline) => return "session_ttl",
                    _ = client_gone(&mut reader) => return "client_closed",
                    response = handle_request(state, &mut binding, kind, &payload) => response,
                };
                session
                    .bytes_down
                    .fetch_add(response.len() as u64, Ordering::Relaxed);
                if writer.write_all(&response).await.is_err() {
                    return "client_closed";
                }
            }
        }
    }
}

/// Resolves when the client hangs up while its request is being answered.
///
/// `ssh` waits for the signature and sends nothing meanwhile, so readable
/// bytes mean a pipelining client rather than a departing one: stop watching
/// and leave them buffered for the next read. Mirrors the PG proxy's watch on
/// a parked session.
async fn client_gone<R: tokio::io::AsyncBufRead + Unpin>(reader: &mut R) {
    match reader.fill_buf().await {
        Ok([]) => {}
        Ok(_) => std::future::pending().await,
        Err(_) => {}
    }
}

/// Answer one agent request. Unknown requests and refused signatures both
/// return SSH_AGENT_FAILURE — the ssh client's cue to move on.
async fn handle_request(
    state: &Arc<AgentState>,
    binding: &mut Option<SessionBinding>,
    kind: u8,
    payload: &[u8],
) -> Vec<u8> {
    match kind {
        SSH_AGENTC_REQUEST_IDENTITIES => {
            let body = state
                .signer
                .as_ref()
                .map(|signer| signer.identities_answer(&state.comment))
                .unwrap_or_else(|| 0u32.to_be_bytes().to_vec());
            frame(SSH_AGENT_IDENTITIES_ANSWER, &body)
        }
        SSH_AGENTC_EXTENSION => {
            if binding.is_some() {
                return refuse(state, "agent connection is already session-bound");
            }
            session_bind(state, binding, payload).await
        }
        SSH_AGENTC_SIGN_REQUEST => sign_response(state, binding.as_ref(), payload).await,
        _ => frame(SSH_AGENT_FAILURE, &[]),
    }
}

/// Answer a `session-bind@openssh.com` request. Pinned connections verify
/// against the cached fingerprint exactly as before; an unpinned connection
/// takes the trust-on-first-use path.
async fn session_bind(
    state: &Arc<AgentState>,
    binding: &mut Option<SessionBinding>,
    payload: &[u8],
) -> Vec<u8> {
    let pinned = *state.host_key_fingerprint.lock().await;
    if let Some(expected) = pinned {
        return match verify_session_bind(payload, expected) {
            Ok(verified) => {
                *binding = Some(verified);
                frame(SSH_AGENT_SUCCESS, &[])
            }
            Err(reason) => refuse(state, &reason),
        };
    }
    tofu_session_bind(state, binding, payload).await
}

/// Trust-on-first-use: the connection was opened unpinned, so the key the
/// server presents at the first session-bind is pinned immediately and the
/// pin is recorded in the activity log. Every later connection is verified
/// against it; a server that later presents a different key is refused.
async fn tofu_session_bind(
    state: &Arc<AgentState>,
    binding: &mut Option<SessionBinding>,
    payload: &[u8],
) -> Vec<u8> {
    // One trust prompt at a time per open: a second connection racing this
    // one parks here and re-checks the (then pinned) state instead of
    // raising a duplicate prompt.
    let _gate = state.bind_gate.lock().await;
    if let Some(expected) = *state.host_key_fingerprint.lock().await {
        return match verify_session_bind(payload, expected) {
            Ok(verified) => {
                *binding = Some(verified);
                frame(SSH_AGENT_SUCCESS, &[])
            }
            Err(reason) => refuse(state, &reason),
        };
    }

    // Re-read the store: another agent socket for the same connection (or a
    // manual edit) may have pinned a key since this socket opened. If so,
    // cache and verify against it — no prompt.
    let conn = match state.broker.store.connection_by_id(&state.connection_id) {
        Ok(conn) => conn,
        Err(_) => return refuse(state, "connection no longer exists"),
    };
    let ConnectionConfig::Ssh {
        host_key_fingerprint: stored,
        ..
    } = &conn.config
    else {
        return refuse(state, "connection is no longer ssh");
    };
    if !stored.is_empty() {
        let expected = match stored.parse::<Fingerprint>() {
            Ok(expected) => expected,
            Err(e) => return refuse(state, &format!("stored host key fingerprint invalid: {e}")),
        };
        *state.host_key_fingerprint.lock().await = Some(expected);
        return match verify_session_bind(payload, expected) {
            Ok(verified) => {
                *binding = Some(verified);
                frame(SSH_AGENT_SUCCESS, &[])
            }
            Err(reason) => refuse(state, &reason),
        };
    }

    let observed_binding = match parse_and_verify_session_bind(payload) {
        Ok(observed) => observed,
        Err(reason) => return refuse(state, &reason),
    };
    let observed = observed_binding.public.fingerprint(HashAlg::Sha256);

    // Pin the observed key immediately and record it; there is no prompt.
    let pinned = match state
        .broker
        .store
        .pin_ssh_host_key(&state.connection_id, &observed)
    {
        Ok(PinOutcome::Pinned(pinned)) => {
            state.broker.audit.append(
                AuditEntry::new(
                    AuditKind::SshHostKeyPinned,
                    format!("SSH host key trusted: {}", state.connection_name),
                )
                .connection(state.connection_name.clone())
                .detail(format!("{pinned} pinned at first connection"))
                .outcome("pinned"),
            );
            state.broker.events.connections_changed();
            pinned
        }
        // A concurrent pin won; accept it only if it is the same key
        // (possibly under a different hash algorithm), else fail closed —
        // the server presented a different key than the one on record.
        Ok(PinOutcome::AlreadyPinned(existing)) => {
            if observed_binding.public.fingerprint(existing.algorithm()) == existing {
                existing
            } else {
                return refuse(state, "connection meanwhile pinned a different host key");
            }
        }
        Err(e) => return refuse(state, &format!("host key pin failed: {e}")),
    };
    *state.host_key_fingerprint.lock().await = Some(pinned);
    *binding = Some(observed_binding.binding);
    frame(SSH_AGENT_SUCCESS, &[])
}

fn refuse(state: &AgentState, reason: &str) -> Vec<u8> {
    refuse_with(state, reason, "refused")
}

fn refuse_with(state: &AgentState, reason: &str, outcome: &str) -> Vec<u8> {
    state.broker.audit.append(
        AuditEntry::new(
            AuditKind::SshSigned,
            format!("SSH signature refused: {}", state.connection_name),
        )
        .agent(state.agent.clone())
        .connection(state.connection_name.clone())
        .detail(reason.to_string())
        .outcome(outcome.to_string()),
    );
    frame(SSH_AGENT_FAILURE, &[])
}

/// What approving one SSH login hands over.
///
/// The honest limit of this gate, stated up front. The agent signs the
/// *authentication*; once the handshake completes the client talks to the
/// host directly and the broker is not in that connection at all. It cannot
/// see the commands, cap the session's length, or close it — the socket's
/// TTL bounds further *logins*, not this one's lifetime.
const LOGIN_CONSEQUENCE: &str =
    "Approving signs one SSH login. What runs afterwards is between the client and the host: \
     AgentMFA is not in that connection, so it cannot see the commands, time the session out, \
     or close it.";

/// Ask the user about one login, if this connection's switch is on.
///
/// Gated here rather than at `open` because this is the first point where
/// the destination is *verified* rather than merely configured: the userauth
/// blob has been checked against the pinned key, the pinned login, and the
/// session-bound host key, so the prompt names what the client will actually
/// authenticate to. It also means a refused or malformed signature never
/// raises a prompt — only one that would otherwise succeed.
///
/// Identity listing and session-bind are deliberately not gated: neither
/// authenticates anything, and prompting on them would ask about `ssh`
/// merely considering the key.
async fn confirm_login(state: &Arc<AgentState>, user: &str) -> Option<Vec<u8>> {
    if !state.broker.access.confirm_mode(&state.connection_id).is_on() {
        return None;
    }
    let Ok(connection) = state.broker.store.connection_by_id(&state.connection_id) else {
        return Some(refuse(state, "the connection has been removed"));
    };
    let summary = format!("SSH login as {user}@{}", connection.target());
    let verdict = state
        .broker
        .approvals
        .gate(
            crate::approvals::ApprovalRequest::new(&connection, state.agent.clone(), summary)
                .maybe_detail(
                    state
                        .host_key_fingerprint
                        .lock()
                        .await
                        .map(|fingerprint| format!("host key {fingerprint}")),
                )
                .consequence(LOGIN_CONSEQUENCE),
        )
        .await;
    if verdict.is_allowed() {
        return None;
    }
    // The agent wire protocol has one refusal, so the reason lives in the
    // audit entry; `ssh` reports it as the agent declining the key.
    Some(refuse_with(
        state,
        verdict.detail(),
        verdict
            .reason()
            .map(|reason| reason.as_str())
            .unwrap_or("refused"),
    ))
}

async fn sign_response(
    state: &Arc<AgentState>,
    binding: Option<&SessionBinding>,
    payload: &[u8],
) -> Vec<u8> {
    let Some(signer) = state.signer.as_ref() else {
        return refuse(state, "connection has no SSH private key");
    };
    let Some(binding) = binding else {
        return refuse(state, "SSH client did not bind the configured host key");
    };
    let mut r = Reader::new(payload);
    let (Some(key_blob), Some(data), Some(flags)) = (r.string(), r.string(), r.u32()) else {
        return refuse(state, "malformed sign request");
    };
    if !r.is_empty() {
        return refuse(state, "malformed sign request");
    }
    if key_blob != signer.public_blob {
        return refuse(state, "sign request names a different key");
    }
    let Some(auth) = hostbound_userauth(data, &signer.public_blob) else {
        return refuse(
            state,
            "data is not host-bound publickey userauth for the pinned key",
        );
    };
    if auth.session_id != binding.session_id {
        return refuse(state, "userauth session id does not match session-bind");
    }
    if auth.host_key != binding.host_key {
        return refuse(state, "userauth host key does not match session-bind");
    }
    if auth.user != state.user {
        return refuse(
            state,
            &format!(
                "userauth names {:?}, connection pins {:?}",
                auth.user, state.user
            ),
        );
    }
    let user = auth.user.to_string();
    let data = data.to_vec();

    // Everything the prompt would name is verified by this point, and
    // nothing has been signed yet.
    if let Some(refusal) = confirm_login(state, &user).await {
        return refusal;
    }

    // A bound connection always cached the pinned fingerprint at bind time.
    let pinned = state
        .host_key_fingerprint
        .lock()
        .await
        .map(|fingerprint| fingerprint.to_string())
        .unwrap_or_else(|| "(unpinned)".into());

    match sign_on_blocking_thread(signer.clone(), data, flags).await {
        Ok(sig_blob) => {
            state.broker.audit.append(
                AuditEntry::new(
                    AuditKind::SshSigned,
                    format!("SSH authentication signed: {}", state.connection_name),
                )
                .agent(state.agent.clone())
                .connection(state.connection_name.clone())
                .detail(format!("host-bound userauth as {user} · {pinned}"))
                .outcome("signed"),
            );
            let mut body = Vec::new();
            put_string(&mut body, &sig_blob);
            frame(SSH_AGENT_SIGN_RESPONSE, &body)
        }
        Err(e) => refuse(state, &format!("sign failed: {e}")),
    }
}

/// Remove any leftover agent sockets from a previous run.
/// Called at daemon start, mirroring the stale control-socket sweep. Live
/// sockets from another running broker are left untouched.
pub fn sweep_stale_sockets(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("sock") {
            continue;
        }
        // This probe opens an agent connection, which would consume one
        // redemption in its owning broker. Today this runs only after the
        // control socket is known dead, so any live listener here belongs to
        // another active broker and should be left alone.
        match std::os::unix::net::UnixStream::connect(&path) {
            Ok(_) => {} // a live listener owns it; leave it
            Err(_) => {
                let _ = std::fs::remove_file(&path);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_key::rand_core::OsRng;

    fn userauth_blob(
        user: &str,
        service: &str,
        method: &str,
        key_blob: &[u8],
        host_key: &[u8],
    ) -> Vec<u8> {
        let mut b = Vec::new();
        put_string(&mut b, b"session-id");
        b.push(SSH_MSG_USERAUTH_REQUEST);
        put_string(&mut b, user.as_bytes());
        put_string(&mut b, service.as_bytes());
        put_string(&mut b, method.as_bytes());
        b.push(1); // has signature
        put_string(&mut b, b"ssh-ed25519");
        put_string(&mut b, key_blob);
        put_string(&mut b, host_key);
        b
    }

    fn session_bind(key: &PrivateKey, session_id: &[u8], forwarding: u8) -> Vec<u8> {
        let host_key = key.public_key().to_bytes().unwrap();
        let signature: Signature = key.try_sign(session_id).unwrap();
        let signature = Vec::<u8>::try_from(signature).unwrap();
        let mut body = Vec::new();
        put_string(&mut body, SESSION_BIND_EXTENSION);
        put_string(&mut body, &host_key);
        put_string(&mut body, session_id);
        put_string(&mut body, &signature);
        body.push(forwarding);
        body
    }

    #[test]
    fn frame_round_trips_through_reader() {
        let msg = frame(SSH_AGENT_SIGN_RESPONSE, b"payload");
        let declared = u32::from_be_bytes([msg[0], msg[1], msg[2], msg[3]]) as usize;
        assert_eq!(declared, msg.len() - 4);
        assert_eq!(msg[4], SSH_AGENT_SIGN_RESPONSE);
        assert_eq!(&msg[5..], b"payload");
    }

    #[test]
    fn reader_parses_strings_and_ints() {
        let mut buf = Vec::new();
        put_string(&mut buf, b"hello");
        buf.extend_from_slice(&7u32.to_be_bytes());
        buf.push(9);
        let mut r = Reader::new(&buf);
        assert_eq!(r.string(), Some(&b"hello"[..]));
        assert_eq!(r.u32(), Some(7));
        assert_eq!(r.u8(), Some(9));
        assert_eq!(r.u8(), None);
    }

    #[test]
    fn hostbound_userauth_accepts_pinned_shape_and_rejects_others() {
        let key = b"the-public-blob";
        let host_key = b"the-host-key";
        let good = userauth_blob(
            "deploy",
            "ssh-connection",
            "publickey-hostbound-v00@openssh.com",
            key,
            host_key,
        );
        let parsed = hostbound_userauth(&good, key).unwrap();
        assert_eq!(parsed.user, "deploy");
        assert_eq!(parsed.host_key, host_key);

        // Wrong key blob.
        assert!(hostbound_userauth(&good, b"other-key").is_none());
        // Wrong service.
        let bad_service = userauth_blob(
            "deploy",
            "ssh-userauth",
            "publickey-hostbound-v00@openssh.com",
            key,
            host_key,
        );
        assert!(hostbound_userauth(&bad_service, key).is_none());
        // Legacy unbound publickey authentication is refused.
        let unbound = userauth_blob("deploy", "ssh-connection", "publickey", key, host_key);
        assert!(hostbound_userauth(&unbound, key).is_none());
        // Not a userauth request at all.
        assert!(hostbound_userauth(b"random bytes", key).is_none());
    }

    #[test]
    fn session_bind_verifies_the_configured_host_key() {
        let host_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let expected = host_key.public_key().fingerprint(HashAlg::Sha256);
        let session_id = b"verified-session-id";
        let binding = verify_session_bind(&session_bind(&host_key, session_id, 0), expected)
            .expect("configured host key binds");
        assert_eq!(binding.session_id, session_id);
        assert_eq!(binding.host_key, host_key.public_key().to_bytes().unwrap());

        let other = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        assert!(verify_session_bind(&session_bind(&other, session_id, 0), expected).is_err());
        assert!(verify_session_bind(&session_bind(&host_key, session_id, 1), expected).is_err());
    }

    #[test]
    fn parse_and_verify_checks_structure_and_signature_but_pins_nothing() {
        let host_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let session_id = b"observed-session-id";

        // Any structurally valid, host-signed bind parses — no fingerprint
        // comparison happens at this layer.
        let observed = parse_and_verify_session_bind(&session_bind(&host_key, session_id, 0))
            .expect("valid bind parses without a pinned key");
        assert_eq!(observed.binding.session_id, session_id);
        assert_eq!(
            observed.public.fingerprint(HashAlg::Sha256),
            host_key.public_key().fingerprint(HashAlg::Sha256)
        );

        // Forwarded sessions are refused before any trust decision.
        assert!(
            parse_and_verify_session_bind(&session_bind(&host_key, session_id, 1))
                .unwrap_err()
                .contains("forwarded")
        );
        // A signature over a different session id fails verification.
        let mut wrong_session = Vec::new();
        let host_blob = host_key.public_key().to_bytes().unwrap();
        let signature: Signature = host_key.try_sign(b"some-other-session").unwrap();
        put_string(&mut wrong_session, SESSION_BIND_EXTENSION);
        put_string(&mut wrong_session, &host_blob);
        put_string(&mut wrong_session, session_id);
        put_string(&mut wrong_session, &Vec::<u8>::try_from(signature).unwrap());
        wrong_session.push(0);
        assert!(parse_and_verify_session_bind(&wrong_session)
            .unwrap_err()
            .contains("signature failed"));
        // Truncated and non-session-bind payloads are refused.
        assert!(parse_and_verify_session_bind(b"junk").is_err());
        let mut truncated = Vec::new();
        put_string(&mut truncated, SESSION_BIND_EXTENSION);
        put_string(&mut truncated, &host_blob);
        assert!(parse_and_verify_session_bind(&truncated).is_err());
    }

    #[tokio::test]
    async fn login_test_agent_requires_a_bound_matching_host_and_user() {
        let auth_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let public_blob = auth_key.public_key().to_bytes().unwrap();
        let signer = Arc::new(SshSigner {
            key: auth_key,
            public_blob: public_blob.clone(),
        });
        let host_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let host_blob = host_key.public_key().to_bytes().unwrap();
        let state = Arc::new(TestAgentState {
            user: "deploy".into(),
            expected_host_key: Some(host_key.public_key().fingerprint(HashAlg::Sha256)),
            observed_host_key: std::sync::Mutex::new(None),
            signer,
            signed: AtomicBool::new(false),
            refusal: std::sync::Mutex::new(None),
        });
        let mut binding = None;

        let response = handle_test_request(
            &state,
            &mut binding,
            SSH_AGENTC_EXTENSION,
            &session_bind(&host_key, b"session-id", 0),
        )
        .await;
        assert_eq!(response[4], SSH_AGENT_SUCCESS);

        let auth = userauth_blob(
            "deploy",
            "ssh-connection",
            "publickey-hostbound-v00@openssh.com",
            &public_blob,
            &host_blob,
        );
        let mut request = Vec::new();
        put_string(&mut request, &public_blob);
        put_string(&mut request, &auth);
        request.extend_from_slice(&0u32.to_be_bytes());
        assert!(!state.signed.load(Ordering::Relaxed));
        let response =
            handle_test_request(&state, &mut binding, SSH_AGENTC_SIGN_REQUEST, &request).await;
        assert_eq!(response[4], SSH_AGENT_SIGN_RESPONSE);
        // The signature is what the login report is gated on.
        assert!(state.signed.load(Ordering::Relaxed));

        let wrong_host = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let mut wrong_binding = None;
        let response = handle_test_request(
            &state,
            &mut wrong_binding,
            SSH_AGENTC_EXTENSION,
            &session_bind(&wrong_host, b"session-id", 0),
        )
        .await;
        assert_eq!(response[4], SSH_AGENT_FAILURE);
        assert!(wrong_binding.is_none());
    }

    /// The report a caller can build from a refused login: no signature was
    /// ever issued, and the reason kept is the one that started the failure.
    #[tokio::test]
    async fn a_refused_login_never_signs_and_keeps_the_first_reason() {
        let auth_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let public_blob = auth_key.public_key().to_bytes().unwrap();
        let host_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let state = Arc::new(TestAgentState {
            user: "deploy".into(),
            expected_host_key: Some(host_key.public_key().fingerprint(HashAlg::Sha256)),
            observed_host_key: std::sync::Mutex::new(None),
            signer: Arc::new(SshSigner {
                key: auth_key,
                public_blob: public_blob.clone(),
            }),
            signed: AtomicBool::new(false),
            refusal: std::sync::Mutex::new(None),
        });

        // A server presenting the wrong host key is refused at session-bind.
        let wrong_host = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let mut binding = None;
        let response = handle_test_request(
            &state,
            &mut binding,
            SSH_AGENTC_EXTENSION,
            &session_bind(&wrong_host, b"session-id", 0),
        )
        .await;
        assert_eq!(response[4], SSH_AGENT_FAILURE);

        // A sign request on the unbound connection is refused in turn, but
        // the mismatch — not this follow-on — is what the user is told.
        let auth = userauth_blob(
            "deploy",
            "ssh-connection",
            "publickey-hostbound-v00@openssh.com",
            &public_blob,
            &wrong_host.public_key().to_bytes().unwrap(),
        );
        let mut request = Vec::new();
        put_string(&mut request, &public_blob);
        put_string(&mut request, &auth);
        request.extend_from_slice(&0u32.to_be_bytes());
        let response =
            handle_test_request(&state, &mut binding, SSH_AGENTC_SIGN_REQUEST, &request).await;
        assert_eq!(response[4], SSH_AGENT_FAILURE);

        assert!(!state.signed.load(Ordering::Relaxed));
        let refusal = state.refusal.lock().unwrap().clone().unwrap();
        assert!(
            refusal.contains("does not match configured"),
            "kept {refusal:?}"
        );
        // Nothing was observed, so there is no key a caller could pin.
        assert!(state.observed_host_key.lock().unwrap().is_none());
    }

    #[test]
    fn rsa_hash_selection_follows_flags() {
        // Flag arithmetic the signer relies on.
        assert_ne!(0x02 & SSH_AGENT_RSA_SHA2_256, 0);
        assert_eq!(0x04 & SSH_AGENT_RSA_SHA2_256, 0);
        assert_ne!(0x04 & SSH_AGENT_RSA_SHA2_512, 0);
    }
}
