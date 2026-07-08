//! SSH capability — `POST /v1/ssh/open` + a per-open ssh-agent socket
//! (DESIGN.md §4.4).
//!
//! SSH has no request/response envelope and no DSN: a stock `ssh` (and
//! therefore `git`, `scp`, `rsync`, `ssh -L`, …) authenticates by talking
//! the **ssh-agent protocol** over the socket named by `SSH_AUTH_SOCK`. So
//! the broker acts as a **scoped signing oracle**: on an approved open it
//! reads the connection's private key from the vault, binds a fresh
//! agent socket, and hands the agent back its path. The agent points
//! `SSH_AUTH_SOCK` at it and runs any unmodified SSH client — the key never
//! leaves the broker.
//!
//! Unlike the WS bridge and PG proxy (one shared loopback-TCP listener bound
//! at daemon start), each SSH open binds its **own** Unix-domain socket:
//! the ssh-agent wire protocol carries no ticket field, so the socket path
//! *is* the capability. The socket lives under `~/.agentmfa/ssh/`, created
//! `0700`, and the socket itself `0600` — only the same local user can reach
//! it, a strictly tighter boundary than the loopback-TCP data planes.
//!
//! What the oracle will and won't do:
//! - **REQUEST_IDENTITIES** returns exactly the one pinned public key.
//! - **SIGN_REQUEST** is honored only when the data to sign is a well-formed
//!   *publickey* `SSH_MSG_USERAUTH_REQUEST` naming the connection's pinned
//!   **user** and the pinned key — so the broker can only ever authenticate
//!   you as `deploy@host`, never sign arbitrary bytes or a login as another
//!   user. Every signature (and every refusal) is audited.
//!
//! The **host is not** cryptographically pinned — the ssh-agent protocol
//! never sees the destination, only the userauth blob does, and that names
//! the user, not the host. The configured host is what the approval and
//! `/v1/connections` display and what the agent is told to connect to; a
//! process that has already been approved for this connection could aim the
//! same key at another host. That is an honest v1 limitation (see §4.4).
//!
//! v1 signs **ed25519** and **RSA** (`rsa-sha2-256` / `rsa-sha2-512`,
//! selected by the client's SIGN_REQUEST flags) keys.

use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use rsa::pkcs1v15;
use sha2::{Sha256, Sha512};
use signature::{SignatureEncoding as _, Signer as _};
use ssh_key::private::KeypairData;
use ssh_key::{Algorithm, HashAlg, PrivateKey, Signature};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{UnixListener, UnixStream};

use crate::audit::{AuditEntry, AuditKind};
use crate::broker::Broker;
use crate::sessions::SessionHandle;
use crate::store::Store;
use crate::types::{Connection, ConnectionConfig, ConnectionKind};

/* --------------------------- ssh-agent protocol --------------------------- */

// Message numbers (OpenSSH PROTOCOL.agent).
const SSH_AGENT_FAILURE: u8 = 5;
const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
const SSH_AGENT_SIGN_RESPONSE: u8 = 14;

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
async fn read_message(stream: &mut UnixStream) -> std::io::Result<(u8, Vec<u8>)> {
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

impl SshSigner {
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
            .map_err(|e| format!("credential unavailable: {e}"))?;
        let key = PrivateKey::from_openssh(pem.as_bytes())
            .map_err(|e| format!("private key parse failed: {e}"))?;
        if key.is_encrypted() {
            return Err(
                "private key is passphrase-encrypted; store the decrypted OpenSSH key".into(),
            );
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
        let public_blob = key
            .public_key()
            .to_bytes()
            .map_err(|e| format!("public key encode failed: {e}"))?;
        Ok(Self { key, public_blob })
    }

    /// Sign `data` honoring the SIGN_REQUEST `flags` (they select the RSA
    /// hash; ed25519 has one algorithm). Returns the SSH-encoded signature
    /// blob (`string alg` + `string sig`) the SIGN_RESPONSE carries.
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

/// The pinned user carried by a SIGN_REQUEST's userauth blob, when the blob
/// is a well-formed publickey `SSH_MSG_USERAUTH_REQUEST` for `public_blob`.
/// Anything else — non-userauth data, a different method, a mismatched key —
/// yields `None`, and the broker refuses to sign it.
fn userauth_user<'a>(data: &'a [u8], public_blob: &[u8]) -> Option<&'a str> {
    let mut r = Reader::new(data);
    let _session_id = r.string()?;
    if r.u8()? != SSH_MSG_USERAUTH_REQUEST {
        return None;
    }
    let user = std::str::from_utf8(r.string()?).ok()?;
    let service = r.string()?;
    if service != b"ssh-connection" {
        return None;
    }
    if r.string()? != b"publickey" {
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
    Some(user)
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
    connection_name: String,
    comment: String,
    signer: Arc<SshSigner>,
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
    let ConnectionConfig::Ssh { user, .. } = &connection.config else {
        return Err("not an ssh connection".into());
    };
    let user = user.clone();
    let signer = Arc::new(SshSigner::load(&broker.store, &connection).await?);

    let ticket = broker.data_plane.issue(
        &agent_name,
        &connection,
        crate::sessions::TicketPayload::Ssh,
    );
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
        connection_name: connection.name.clone(),
        comment: format!("agentmfa:{}", connection.name),
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
    // one approval can spawn — exactly as the WS/PG data planes do (§8).
    let redemption = match state.broker.data_plane.redeem(&state.ticket) {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!("ssh agent redeem refused: {}", e.reason());
            // The agent wire protocol has no "expired" reply; a closed
            // connection reads to the client as "agent refused". A
            // budget/expiry hit here is expected, not an error.
            let _ = stream.shutdown().await;
            return Ok(());
        }
    };

    // Establishment succeeded: register the live session (dropping the
    // redemption without `start` would release the reserved budget slot).
    let session = redemption.start(ConnectionKind::Ssh);
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

    loop {
        tokio::select! {
            _ = close_signal.notified() => return "closed_by_user",
            _ = tokio::time::sleep_until(ttl_deadline) => return "session_ttl",
            _ = tokio::time::sleep_until(idle_deadline) => return "idle_timeout",
            msg = read_message(stream) => {
                let (kind, payload) = match msg {
                    Ok(m) => m,
                    Err(_) => return "client_closed",
                };
                idle_deadline = tokio::time::Instant::now() + idle;
                session
                    .bytes_up
                    .fetch_add(payload.len() as u64 + 1, Ordering::Relaxed);
                let response = handle_request(state, kind, &payload);
                session
                    .bytes_down
                    .fetch_add(response.len() as u64, Ordering::Relaxed);
                if stream.write_all(&response).await.is_err() {
                    return "client_closed";
                }
            }
        }
    }
}

/// Answer one agent request. Unknown requests and refused signatures both
/// return SSH_AGENT_FAILURE — the ssh client's cue to move on.
fn handle_request(state: &Arc<AgentState>, kind: u8, payload: &[u8]) -> Vec<u8> {
    match kind {
        SSH_AGENTC_REQUEST_IDENTITIES => {
            frame(
                SSH_AGENT_IDENTITIES_ANSWER,
                &state.signer.identities_answer(&state.comment),
            )
        }
        SSH_AGENTC_SIGN_REQUEST => sign_response(state, payload),
        _ => frame(SSH_AGENT_FAILURE, &[]),
    }
}

fn sign_response(state: &Arc<AgentState>, payload: &[u8]) -> Vec<u8> {
    let refuse = |reason: &str| -> Vec<u8> {
        state.broker.audit.append(
            AuditEntry::new(
                AuditKind::SshSigned,
                format!("SSH signature refused: {}", state.connection_name),
            )
            .connection(state.connection_name.clone())
            .detail(reason.to_string())
            .outcome("refused"),
        );
        frame(SSH_AGENT_FAILURE, &[])
    };

    let mut r = Reader::new(payload);
    let (Some(key_blob), Some(data), Some(flags)) = (r.string(), r.string(), r.u32()) else {
        return refuse("malformed sign request");
    };
    if key_blob != state.signer.public_blob {
        return refuse("sign request names a different key");
    }
    // The core pin: only sign a publickey userauth for the configured user,
    // so the oracle can authenticate as nobody else and sign nothing else.
    let Some(user) = userauth_user(data, &state.signer.public_blob) else {
        return refuse("data is not a publickey userauth request for the pinned key");
    };
    if user != state.user {
        return refuse(&format!(
            "userauth names {user:?}, connection pins {:?}",
            state.user
        ));
    }

    match state.signer.sign(data, flags) {
        Ok(sig_blob) => {
            state.broker.audit.append(
                AuditEntry::new(
                    AuditKind::SshSigned,
                    format!("SSH authentication signed: {}", state.connection_name),
                )
                .connection(state.connection_name.clone())
                .detail(format!("userauth as {user}"))
                .outcome("signed"),
            );
            let mut body = Vec::new();
            put_string(&mut body, &sig_blob);
            frame(SSH_AGENT_SIGN_RESPONSE, &body)
        }
        Err(e) => refuse(&format!("sign failed: {e}")),
    }
}

/// Remove any leftover agent sockets from a previous run (DESIGN.md §4.4/§12).
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

    fn userauth_blob(user: &str, service: &str, method: &str, key_blob: &[u8]) -> Vec<u8> {
        let mut b = Vec::new();
        put_string(&mut b, b"session-id");
        b.push(SSH_MSG_USERAUTH_REQUEST);
        put_string(&mut b, user.as_bytes());
        put_string(&mut b, service.as_bytes());
        put_string(&mut b, method.as_bytes());
        b.push(1); // has signature
        put_string(&mut b, b"ssh-ed25519");
        put_string(&mut b, key_blob);
        b
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
    fn userauth_user_accepts_pinned_shape_and_rejects_others() {
        let key = b"the-public-blob";
        // Well-formed publickey userauth for the pinned key.
        let good = userauth_blob("deploy", "ssh-connection", "publickey", key);
        assert_eq!(userauth_user(&good, key), Some("deploy"));

        // Wrong key blob.
        assert_eq!(userauth_user(&good, b"other-key"), None);
        // Wrong service.
        let bad_service = userauth_blob("deploy", "ssh-userauth", "publickey", key);
        assert_eq!(userauth_user(&bad_service, key), None);
        // Wrong method.
        let bad_method = userauth_blob("deploy", "ssh-connection", "password", key);
        assert_eq!(userauth_user(&bad_method, key), None);
        // Not a userauth request at all.
        assert_eq!(userauth_user(b"random bytes", key), None);
    }

    #[test]
    fn rsa_hash_selection_follows_flags() {
        // Flag arithmetic the signer relies on.
        assert_ne!(0x02 & SSH_AGENT_RSA_SHA2_256, 0);
        assert_eq!(0x04 & SSH_AGENT_RSA_SHA2_256, 0);
        assert_ne!(0x04 & SSH_AGENT_RSA_SHA2_512, 0);
    }
}
