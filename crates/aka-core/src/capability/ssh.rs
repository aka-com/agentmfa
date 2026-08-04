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
//! The signer handles **ed25519**, **RSA** (`rsa-sha2-256` / `rsa-sha2-512`,
//! selected by the client's SIGN_REQUEST flags), and **ECDSA** on nistp256 and
//! nistp384, whose curve fixes the hash.

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
const SSH_AGENT_EXTENSION_FAILURE: u8 = 28;

const SESSION_BIND_EXTENSION: &[u8] = b"session-bind@openssh.com";
/// Multitool's own agent extension: proves the caller holds this endpoint's
/// secret before the socket will list identities or sign.
///
/// The ssh-agent wire protocol has no credential field, which is why a
/// standing endpoint socket was authorized by whoever could open it. This adds
/// the missing field as an extension — the one place the protocol leaves for
/// it — carrying the same secret the PG and HTTP endpoints already present.
/// Vendor-named per PROTOCOL.agent so it cannot collide with OpenSSH's own.
const AUTHENTICATE_EXTENSION: &[u8] = b"authenticate@multitool.dev";
const LEGACY_AUTHENTICATE_EXTENSION: &[u8] = b"authenticate@agentmfa.dev";
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
    /// The assembled RSA key, built once at load.
    ///
    /// `from_components` validates the key and precomputes CRT values, and
    /// doing that per signature meant every login rebuilt it — leaving fresh
    /// un-zeroized `BigUint` copies of `d`, `p` and `q` on the heap each time.
    /// `None` for ed25519, which needs no assembly.
    rsa: Option<rsa::RsaPrivateKey>,
}

/// Why an offered private key cannot be stored.
///
/// `NeedsPassphrase` and `WrongPassphrase` are separate because the form has to
/// react differently: reveal a passphrase field, or say the one given is wrong.
/// Collapsing them into a string — as the old "store the decrypted OpenSSH key"
/// message did — is what dead-ended the common case with advice to weaken the
/// credential before handing it over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyImportError {
    /// The key is encrypted and no passphrase was offered.
    NeedsPassphrase,
    /// A passphrase was offered and did not decrypt the key.
    WrongPassphrase,
    /// Malformed, or an algorithm the signer cannot use.
    Unusable(String),
}

impl KeyImportError {
    pub fn message(&self) -> String {
        match self {
            Self::NeedsPassphrase => {
                "this private key is passphrase-protected; enter its passphrase".to_string()
            }
            Self::WrongPassphrase => "that passphrase did not decrypt the private key".to_string(),
            Self::Unusable(message) => message.clone(),
        }
    }

    /// Whether the surface should ask for (or re-ask for) a passphrase.
    pub fn wants_passphrase(&self) -> bool {
        matches!(self, Self::NeedsPassphrase | Self::WrongPassphrase)
    }
}

impl std::fmt::Display for KeyImportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message())
    }
}

/// Validate an SSH private key before it is saved by a trusted onboarding
/// surface. This deliberately enforces the same format and algorithm rules as
/// the runtime signer so an imported credential cannot fail only at first use.
pub fn validate_private_key(pem: &[u8]) -> Result<(), String> {
    parse_supported_private_key(pem).map(|_| ())
}

/// The OpenSSH-form private key to seal in the vault, decrypting first when the
/// offered key is passphrase-protected.
///
/// The passphrase is used here and discarded: the vault is the protection
/// boundary for a stored key — Keychain on macOS, XChaCha20-Poly1305 elsewhere —
/// so a second layer inside it would only mean prompting the user on every
/// signature. Refusing encrypted keys outright, which is what happened before,
/// dead-ended the common case with instructions to `ssh-keygen -p` the
/// passphrase off first: strictly worse, because the stripped key then sits on
/// disk unprotected while the user finds the import button.
///
/// Runs in the trusted onboarding surface only. The plaintext never leaves this
/// function except into the caller's `Zeroizing` buffer.
pub fn private_key_for_vault(
    pem: &[u8],
    passphrase: Option<&str>,
) -> std::result::Result<zeroize::Zeroizing<String>, KeyImportError> {
    let key = PrivateKey::from_openssh(pem)
        .map_err(|e| KeyImportError::Unusable(format!("private key parse failed: {e}")))?;
    let key = if key.is_encrypted() {
        let passphrase = passphrase
            .map(str::as_bytes)
            .filter(|bytes| !bytes.is_empty())
            .ok_or(KeyImportError::NeedsPassphrase)?;
        // `decrypt` reports a MAC failure for a wrong passphrase, which is
        // indistinguishable from corruption here — and "wrong passphrase" is
        // overwhelmingly the likelier of the two, so say that.
        key.decrypt(passphrase)
            .map_err(|_| KeyImportError::WrongPassphrase)?
    } else {
        key
    };
    check_supported(&key).map_err(KeyImportError::Unusable)?;
    let encoded = key
        .to_openssh(ssh_key::LineEnding::LF)
        .map_err(|e| KeyImportError::Unusable(format!("private key re-encode failed: {e}")))?;
    // `to_openssh` yields a zeroizing string already; rewrap so the signature
    // does not depend on that being true.
    Ok(zeroize::Zeroizing::new(encoded.to_string()))
}

/// Whether the signer can use this key.
///
/// ECDSA is admitted only on the curves that are actually compiled in
/// (`p256`/`p384`): `ssh-key` parses every curve it knows regardless, so a
/// P-521 key would import cleanly and then fail at the first login — which is
/// the failure mode this check exists to prevent.
fn check_supported(key: &PrivateKey) -> Result<(), String> {
    let unsupported = |key: &PrivateKey| {
        format!(
            "unsupported key type {:?} (Multitool signs ed25519, rsa, and ecdsa \
             on nistp256/nistp384)",
            key.key_data().algorithm().map(|a| a.as_str().to_string())
        )
    };
    match key.key_data() {
        KeypairData::Ed25519(_) | KeypairData::Rsa(_) => Ok(()),
        KeypairData::Ecdsa(keypair) => match keypair.curve() {
            ssh_key::EcdsaCurve::NistP256 | ssh_key::EcdsaCurve::NistP384 => Ok(()),
            _ => Err(unsupported(key)),
        },
        _ => Err(unsupported(key)),
    }
}

fn parse_supported_private_key(pem: &[u8]) -> Result<PrivateKey, String> {
    let key =
        PrivateKey::from_openssh(pem).map_err(|e| format!("private key parse failed: {e}"))?;
    if key.is_encrypted() {
        // Reached only for a key that was stored encrypted by an older build:
        // import decrypts before sealing, so the vault holds cleartext OpenSSH.
        return Err(
            "the stored private key is passphrase-encrypted; re-import it to have the \
             passphrase removed once, at import"
                .into(),
        );
    }
    check_supported(&key)?;
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
        Self::from_pem(pem.as_bytes())
    }

    /// Build a signer from OpenSSH-form key material — the shape the vault
    /// holds after import decrypts anything encrypted.
    fn from_pem(pem: &[u8]) -> Result<Self, String> {
        let key = parse_supported_private_key(pem)?;
        let public_blob = key
            .public_key()
            .to_bytes()
            .map_err(|e| format!("public key encode failed: {e}"))?;
        let rsa = match key.key_data() {
            KeypairData::Rsa(keypair) => Some(rsa_private_key(keypair)?),
            _ => None,
        };
        Ok(Self {
            key,
            public_blob,
            rsa,
        })
    }

    /// Sign `data` honoring the SIGN_REQUEST `flags` (they select the RSA
    /// hash; ed25519 and ECDSA each have one algorithm per key). Returns the
    /// SSH-encoded signature blob (`string alg` + `string sig`) the
    /// SIGN_RESPONSE carries.
    ///
    /// RSA signing can take long enough to matter on an async worker; callers
    /// should run this through `sign_on_blocking_thread`.
    fn sign(&self, data: &[u8], flags: u32) -> Result<Vec<u8>, String> {
        let signature: Signature = match self.key.key_data() {
            KeypairData::Ed25519(_) => self
                .key
                .try_sign(data)
                .map_err(|e| format!("ed25519 sign failed: {e}"))?,
            // The curve fixes the hash, so the RSA flags have nothing to say
            // here; `ssh-key` produces the `ecdsa-sha2-nistp*` blob itself.
            KeypairData::Ecdsa(_) => self
                .key
                .try_sign(data)
                .map_err(|e| format!("ecdsa sign failed: {e}"))?,
            KeypairData::Rsa(_) => {
                let hash = if flags & SSH_AGENT_RSA_SHA2_256 != 0 {
                    HashAlg::Sha256
                } else if flags & SSH_AGENT_RSA_SHA2_512 != 0 {
                    HashAlg::Sha512
                } else {
                    // No hash flag means the client asked for legacy SHA-1
                    // `ssh-rsa`. Signing SHA-512 anyway does not help: the
                    // client's own userauth blob says `ssh-rsa`, and OpenSSH's
                    // `sshkey_check_sigtype` rejects a `rsa-sha2-512` signature
                    // against it — so the old fallback produced a signature
                    // *and* a failed login, with the key having signed for
                    // nothing. Refusing lets the client fall back to an
                    // algorithm it actually asked for.
                    return Err(
                        "client requested legacy ssh-rsa (SHA-1); ask for rsa-sha2-256 or \
                         rsa-sha2-512"
                            .into(),
                    );
                };
                let private = self
                    .rsa
                    .clone()
                    .ok_or_else(|| "rsa key was not assembled at load".to_string())?;
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

/// The certificate algorithm name in an SSH public-key blob, if it is one.
///
/// The blob's first field is its algorithm name, and OpenSSH spells every host
/// certificate `<base>-cert-v01@openssh.com`. Read straight off the wire rather
/// than through `PublicKey`, because the whole point is that `PublicKey` accepts
/// these as opaque and only fails later, at verification.
fn certificate_algorithm(host_key: &[u8]) -> Option<String> {
    let name = Reader::new(host_key).string()?;
    let name = std::str::from_utf8(name).ok()?;
    name.ends_with("-cert-v01@openssh.com")
        .then(|| name.to_string())
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
    // A `*-cert-v01@openssh.com` blob parses — ssh-key maps an unrecognized
    // algorithm to an opaque key — and then fails verification with a bare
    // "unsupported", which reached the audit log as "SSH signature refused":
    // a server with a CA-signed host key looked exactly like a host-key attack.
    // Say what it is instead. Verifying the certificate (and matching the pin
    // against either the CA or the embedded host key) is the actual feature and
    // is not implemented; this is only about not lying in the meantime.
    if let Some(algorithm) = certificate_algorithm(host_key) {
        return Err(format!(
            "the server presented a certificate host key ({algorithm}), which is not yet \
             supported; configure this server to also offer a plain host key"
        ));
    }
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

/// Extension of the transient name a socket is bound under before being
/// tightened and renamed into place. Deliberately the same byte length as
/// `sock` so the staging path can never exceed `sun_path` where the final
/// `.sock` path would have fit — a longer staging name (e.g. `binding`) would
/// fail to bind near the length limit even though the real socket is legal.
/// `sweep_stale_sockets` reaps orphans of this extension too, since a crash
/// between `bind` and `rename` leaves one behind under a name never reused.
const SOCKET_STAGING_EXT: &str = "bind";

/// Maximum pathname bytes accepted by `sockaddr_un::sun_path`, excluding its
/// terminating NUL. Linux provides 108 bytes including the NUL; the Apple/BSD
/// layout used by the desktop build provides 104.
#[cfg(target_os = "linux")]
const UNIX_SOCKET_PATH_MAX: usize = 107;
#[cfg(not(target_os = "linux"))]
const UNIX_SOCKET_PATH_MAX: usize = 103;

fn validate_unix_socket_path(path: &Path) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt as _;

    let len = path.as_os_str().as_bytes().len();
    if len > UNIX_SOCKET_PATH_MAX {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "SSH agent socket path {} is {len} bytes; this platform's Unix socket limit is \
                 {UNIX_SOCKET_PATH_MAX} bytes (excluding the terminating NUL) — use a shorter \
                 --root",
                path.display()
            ),
        ));
    }
    Ok(())
}

/// Bind a Unix socket that is never observable with looser permissions than
/// 0600.
///
/// `bind` creates the node with the process umask applied and the caller
/// chmod-ed it afterwards, which leaves a window where the socket exists and is
/// connectable at whatever the umask allowed. The enclosing 0700 directory
/// closes that window in practice, but for a signing oracle the guarantee
/// should not rest on the ordering of two syscalls: bind under a staging name,
/// tighten it, then rename into place — a rename moves the name, and the
/// listener keeps its own fd.
fn bind_private_socket(path: &Path) -> std::io::Result<UnixListener> {
    use std::os::unix::fs::PermissionsExt;
    validate_unix_socket_path(path)?;
    let staging = path.with_extension(SOCKET_STAGING_EXT);
    // A crash could have left either name behind; bind fails on an existing
    // path even when nothing is listening.
    let _ = std::fs::remove_file(&staging);
    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(&staging)?;
    if let Err(e) = std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o600)) {
        let _ = std::fs::remove_file(&staging);
        return Err(e);
    }
    if let Err(e) = std::fs::rename(&staging, path) {
        let _ = std::fs::remove_file(&staging);
        return Err(e);
    }
    Ok(listener)
}

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
    /// The standing endpoint this socket serves, if any. `None` on the
    /// per-open ticket path, whose socket is already bounded by the ticket
    /// that minted it and by its own expiry.
    ///
    /// Held as an id, not as a resolved posture: whether the endpoint demands
    /// `authenticate@multitool.dev` is read from the registry when a connection
    /// is accepted, the same place the access re-check happens. Capturing it
    /// at bind time would have made a posture change need a rebind, and
    /// rebinding a Unix socket in place is how you delete the socket you just
    /// created — the retiring listener's guard unlinks the path by name.
    endpoint_id: Option<Uuid>,
    /// Pinned login the userauth blob must name.
    user: String,
    /// The pinned host key: `Some` from open time when the connection was
    /// already pinned, otherwise `None` until trust-on-first-use pins it at
    /// the first session-bind. A `Mutex` because the TOFU path writes it
    /// while other connections on this socket read it.
    host_key_fingerprint: tokio::sync::Mutex<Option<Fingerprint>>,
    /// Serializes unpinned session-binds across this socket's connections so
    /// one open performs at most one first-use pin (and, when configured, one
    /// confirmation); the loser of the race re-checks the then-pinned state.
    bind_gate: tokio::sync::Mutex<()>,
    connection_id: Uuid,
    connection_name: String,
    /// The connection's `updated_at` when the socket was opened. A retarget
    /// after that point invalidates the socket: the user repointed the tool at
    /// something other than what they approved.
    approved_version: chrono::DateTime<chrono::Utc>,
    /// When this socket stops signing, whatever a client still holds.
    ///
    /// A per-open socket is bounded by its own redemption window, not by
    /// `session_max_ttl`: a client sending one agent message every few minutes
    /// used to keep an hour of unlimited signatures alive, long after the socket
    /// file was gone and regardless of disable or delete. `None` for a standing
    /// endpoint, which is bounded by its own existence.
    expires_at: Option<tokio::time::Instant>,
    /// Self-reported label of the agent this socket was opened for, or
    /// `"endpoint"` for a standing one. Attribution for the prompt and the
    /// signature log, never authorization — the socket path is the capability.
    agent: String,
    comment: String,
    /// Per-socket signature budget.
    ///
    /// Signing is both the expensive operation here (RSA runs on a blocking
    /// thread) and the authority-granting one, and it was unbounded: the token
    /// limiter covers `POST /v1/ssh/open`, never the socket it hands back. One
    /// socket could be driven as fast as a client cared to ask.
    signatures: crate::ratelimit::WindowLimiter,
    /// The signer, for a socket that loads it once.
    ///
    /// `Some` on the per-open path: its ticket lives 60 seconds, and the read is
    /// authorized by the open that captured the scope. `None` for a standing
    /// endpoint, which loads per connection instead (see `bind_endpoint`).
    signer: Option<Arc<SshSigner>>,
}

/// How many signatures one agent socket may issue per minute.
const SIGNATURE_WINDOW: Duration = Duration::from_secs(60);

/// The `-o` options every emitted `ssh` invocation carries — the single source
/// of truth for the CLI hint, the endpoint example, and the UI's snippets.
///
/// `SSH_AUTH_SOCK` (or `IdentityAgent`) points the agent at the broker but
/// leaves the default `IdentityFile` list in place, so a user who already has a
/// working `~/.ssh/id_ed25519` gets a successful login with **no** broker
/// involvement and no activity-log entry — a false success, which is worse than
/// a failure because it comes with the belief the broker mediated it.
/// `IdentityFile=none` and `CertificateFile=none` close that path.
///
/// `IdentitiesOnly=yes` is the flag that looks right and is wrong: OpenSSH's
/// `pubkey_prepare` drops agent identities matching no configured
/// `IdentityFile`, and the brokered key has no on-disk `.pub`, so the identity
/// is discarded and the login fails.
///
/// `ForwardAgent=no` because forwarding is unsupported — `session-bind`'s
/// forwarding flag is asserted by the client, so refusing it stops an honest
/// client and not a hostile one. `ControlMaster=no` because a multiplexed
/// connection is authorized once and then reused by invocations that never
/// reach the agent again: no audit entry, no expiry, nothing to revoke.
///
/// `ProxyJump=none` because the broker cannot authenticate a jump hop. `-J`
/// spawns a child `ssh -W` that inherits `IdentityAgent` and logs in to the
/// *jump* host, so the agent is asked to bind the jump host's key — and a
/// connection pins one host key, so `verify_session_bind` refuses it. Leaving
/// the jump enabled turned that into an audit line reading like a host-key
/// attack on a destination the user had configured correctly. Refusing the jump
/// outright fails at connect, where the message is about routing.
pub const SSH_BROKER_OPTIONS: &[&str] = &[
    "IdentityFile=none",
    "CertificateFile=none",
    "ForwardAgent=no",
    "ControlMaster=no",
    "ProxyJump=none",
];

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
        .map_err(|_e| {
            TestError::new(
                TestErrorKind::Unreachable,
                format!("Could not reach {host}:{port}"),
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
        destination: _,
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

    let mut command = test_login_command(&log_path, &socket_path, host, user, *port);
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

/// Build the stock-client probe without consulting user or system SSH config.
///
/// OpenSSH evaluates `Match exec` while loading configuration and may execute
/// `ProxyCommand` when connecting. The broker already persisted the resolved
/// host/user/port, so testing those explicit fields under an empty config is
/// deterministic and prevents a UI "Test" click from running local commands.
fn test_login_command(
    log_path: &Path,
    socket_path: &Path,
    host: &str,
    user: &str,
    port: u16,
) -> tokio::process::Command {
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
        .arg("-F")
        .arg("/dev/null")
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
        .arg("ProxyJump=none")
        .arg("-o")
        .arg("ProxyCommand=none")
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
        .arg(host)
        .arg("true")
        .env_remove("SSH_AUTH_SOCK");
    command
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
        host,
        port,
        user,
        ..
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
        || log_lower.contains("nodename nor servname provided")
        || log_lower.contains("name or service not known")
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
    let listener =
        bind_private_socket(&socket_path).map_err(|e| format!("ssh socket bind failed: {e}"))?;

    let state = Arc::new(AgentState {
        broker: broker.clone(),
        ticket,
        // A per-open socket is already bounded by the ticket that minted it
        // and by its own expiry, so it is not the standing authority the
        // extension exists to protect.
        endpoint_id: None,
        user,
        host_key_fingerprint: tokio::sync::Mutex::new(host_key_fingerprint),
        bind_gate: tokio::sync::Mutex::new(()),
        connection_id: connection.id,
        connection_name: connection.name.clone(),
        approved_version: connection.updated_at,
        // The socket stops accepting at `ticket_ttl + SOCKET_GRACE`; a
        // connection accepted just before that must not outlive it either.
        expires_at: Some(tokio::time::Instant::now() + broker.config.ticket_ttl + SOCKET_GRACE),
        agent: agent_name,
        comment: format!("aka:{}", connection.name),
        signatures: crate::ratelimit::WindowLimiter::new(
            broker.config.per_identity_per_min,
            SIGNATURE_WINDOW,
        ),
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
            audit_refused_connection(
                &state,
                e.reason().as_str(),
                "the socket's ticket could not be redeemed",
            );
            let _ = stream.shutdown().await;
            return Ok(());
        }
    };

    // `redeem` checks expiry, invalidation and budget — never whether the tool
    // is still enabled or still points where it did. So a socket opened before
    // the user switched the connection off went on signing, and a retarget was
    // invisible to it. The endpoint path has always re-checked both; this is the
    // same check, on the path that hands out a signing oracle from a ticket.
    if !state.broker.access.allows(&state.connection_id) {
        audit_refused_connection(&state, "denied_by_policy", "agent access is disabled");
        let _ = stream.shutdown().await;
        return Ok(());
    }
    match state.broker.store.connection_by_id(&state.connection_id) {
        Ok(current) if current.updated_at == state.approved_version => {}
        Ok(_) => {
            audit_refused_connection(
                &state,
                "denied_by_policy",
                "the tool was retargeted after this socket was opened",
            );
            let _ = stream.shutdown().await;
            return Ok(());
        }
        Err(_) => {
            audit_refused_connection(&state, "denied_by_policy", "the tool no longer exists");
            let _ = stream.shutdown().await;
            return Ok(());
        }
    }

    // Establishment succeeded: register the live session (dropping the
    // redemption without `start` would release the reserved budget slot).
    let max_ttl = state.broker.config.session_max_ttl;
    let session = redemption.start(ConnectionKind::Ssh);
    let idle = state.broker.config.session_idle_timeout;
    let signer = state.signer.clone();
    let reason = serve(&state, signer, &mut stream, &session, max_ttl, idle).await;
    let _ = stream.shutdown().await;
    session.finish(reason);
    Ok(())
}

/* ------------------------- per-connection endpoint ------------------------ */

/// The filename a pre-secret endpoint's socket was bound at.
///
/// Retained only so an endpoint issued before the name was derived keeps
/// working until it is reissued; nothing new binds here.
pub const LEGACY_ENDPOINT_SOCK: &str = "agent.sock";

/// The filename of a direct SSH endpoint's agent socket, derived from the
/// endpoint secret.
///
/// The ssh-agent protocol has no place to present a credential: whoever can
/// open the socket gets signatures. With a fixed name under a deterministic
/// directory the path was *enumerable* — `ls ~/.aka/endpoints/*/agent.sock`
/// found every issued endpoint — so any process running as this user could log
/// into the pinned host as the pinned user, including an agent deliberately not
/// enabled for that connection. Deriving the name from the secret makes finding
/// the socket require the secret, which lives in the vault and not in any file
/// the attacker can read.
///
/// Domain-separated on purpose: `secret_hash` in `endpoints.json` is the plain
/// SHA-256 of the same secret and is readable by that attacker, so the name
/// must not be computable from it. Sixteen hex characters keep the whole path
/// inside `sun_path`'s ~104-byte limit.
///
/// This is unguessability, not authentication — a same-user process that can
/// read the vault still wins. It raises the bar from "list a directory" to
/// "defeat the Keychain", and the real fix remains an agent-extension
/// handshake carrying the secret.
pub fn endpoint_sock_name(secret: &str) -> String {
    use sha2::{Digest as _, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"multitool/ssh-endpoint-socket/v1\0");
    hasher.update(secret.as_bytes());
    let digest = hasher.finalize();
    let name: String = digest.iter().take(8).map(|b| format!("{b:02x}")).collect();
    format!("agent-{name}.sock")
}

/// Where an endpoint's socket lives: the derived name when its secret can be
/// recovered, else the legacy fixed name.
pub fn endpoint_sock_path(dir: &Path, secret: &str) -> PathBuf {
    if secret.is_empty() {
        dir.join(LEGACY_ENDPOINT_SOCK)
    } else {
        dir.join(endpoint_sock_name(secret))
    }
}

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
    // The private key is deliberately *not* read here.
    //
    // Reading it at bind time froze one signer for the listener's whole life,
    // so rotating a *compromised* key left the compromised key signing until
    // the broker restarted. Each accepted connection loads it instead, where
    // access re-check already lives.
    let dir = broker.paths.endpoint_dir(&endpoint.id);
    crate::paths::create_private_dir(&dir)?;
    // Needs the plaintext secret, which lives in the vault; an endpoint whose
    // secret cannot be recovered keeps the legacy fixed name so it goes on
    // working until reissued.
    let secret = broker.endpoint_secret_for(endpoint).await;
    if secret.is_empty() {
        tracing::warn!(
            endpoint = %endpoint.id,
            "SSH endpoint secret unavailable; binding the legacy guessable socket \
             name — reissue this endpoint to get an unguessable one"
        );
    }
    let socket_path = endpoint_sock_path(&dir, &secret);
    // A rebind may find a sibling from before: the legacy fixed name, or the
    // previous secret's derived name when a reissue rotated the path. Only
    // ours is removed by the bind guard, so clear the rest — one endpoint
    // owns this directory, so any other socket here is dead or about to be.
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let stale = entry.path();
            if stale != socket_path && stale.extension().and_then(|e| e.to_str()) == Some("sock") {
                let _ = std::fs::remove_file(&stale);
            }
        }
    }
    let listener = bind_private_socket(&socket_path)?;

    let state = Arc::new(AgentState {
        broker: broker.clone(),
        // Endpoints never redeem a ticket; the per-connection access re-check
        // gates them instead.
        ticket: String::new(),
        endpoint_id: Some(endpoint.id),
        user,
        host_key_fingerprint: tokio::sync::Mutex::new(host_key_fingerprint),
        bind_gate: tokio::sync::Mutex::new(()),
        connection_id: connection.id,
        connection_name: connection.name.clone(),
        approved_version: connection.updated_at,
        // Standing by design: bounded by the endpoint existing, and re-checked
        // on every accepted connection.
        expires_at: None,
        // A standing socket is not opened by any one agent; the same label
        // the endpoint's sessions are registered under.
        agent: "endpoint".to_string(),
        comment: format!("aka:{}", connection.name),
        signatures: crate::ratelimit::WindowLimiter::new(
            broker.config.per_identity_per_min,
            SIGNATURE_WINDOW,
        ),
        // Loaded per accepted connection, not held here.
        signer: None,
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
    // Authorization is enforced here, at connect time: a disabled, revoked,
    // or expired endpoint is refused even if a stale listener briefly
    // outlived its teardown. This explicit endpoint check is essential for
    // unauthenticated SSH sockets, which do not otherwise present a secret to
    // the shared resolver.
    let endpoint_is_active = state
        .broker
        .endpoints
        .get(&ctx.endpoint_id)
        .is_some_and(|endpoint| {
            endpoint.connection_id == ctx.connection_id && !endpoint.is_expired()
        });
    if !endpoint_is_active {
        audit_refused_connection(
            &state,
            "endpoint_revoked",
            "the direct endpoint is missing, expired, or no longer names this tool",
        );
        let _ = stream.shutdown().await;
        return Ok(());
    }
    if !state.broker.access.allows(&ctx.connection_id) {
        audit_refused_connection(&state, "denied_by_policy", "agent access is disabled");
        let _ = stream.shutdown().await;
        return Ok(());
    }
    let Ok(connection) = state.broker.store.connection_by_id(&ctx.connection_id) else {
        audit_refused_connection(&state, "unknown_connection", "the tool no longer exists");
        let _ = stream.shutdown().await;
        return Ok(());
    };
    if connection.kind() != ConnectionKind::Ssh {
        audit_refused_connection(
            &state,
            "wrong_connection_type",
            "the tool is no longer an SSH connection",
        );
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
    let endpoint_still_valid =
        state
            .broker
            .endpoints
            .get(&ctx.endpoint_id)
            .is_some_and(|endpoint| {
                endpoint.connection_id == ctx.connection_id && !endpoint.is_expired()
            });
    if !endpoint_still_valid || !state.broker.access.allows(&ctx.connection_id) {
        session.finish("access_revoked");
        let _ = stream.shutdown().await;
        return Ok(());
    }
    // Load the key for this connection at each login so rotating a
    // compromised key takes effect without restarting the broker.
    let signer = match SshSigner::load_optional(&state.broker.store, &connection).await {
        Ok(signer) => signer.map(Arc::new),
        Err(e) => {
            // A key that cannot be read is not a signature the client should
            // wait for. Record it: the client only sees "agent refused".
            state.broker.audit.append(
                AuditEntry::new(
                    AuditKind::Denied,
                    format!("SSH endpoint could not read its key: {}", connection.name),
                )
                .connection(connection.name.clone())
                .detail(e)
                .outcome("credential_unavailable")
                .field("kind", "ssh"),
            );
            session.finish("credential_unavailable");
            let _ = stream.shutdown().await;
            return Ok(());
        }
    };

    let max_ttl = state.broker.config.session_max_ttl;
    let idle = state.broker.config.session_idle_timeout;
    let reason = serve(&state, signer, &mut stream, &session, max_ttl, idle).await;
    let _ = stream.shutdown().await;
    session.finish(reason);
    Ok(())
}

async fn serve(
    state: &Arc<AgentState>,
    signer: Option<Arc<SshSigner>>,
    stream: &mut UnixStream,
    session: &SessionHandle,
    max_ttl: Duration,
    idle: Duration,
) -> &'static str {
    // Whichever comes first: the session TTL, or the socket's own window. A
    // per-open socket sets the latter, so a client holding the fd cannot keep
    // signing for an hour after the socket is gone.
    let ttl_deadline = match state.expires_at {
        Some(expiry) => expiry.min(tokio::time::Instant::now() + max_ttl),
        None => tokio::time::Instant::now() + max_ttl,
    };
    let mut idle_deadline = tokio::time::Instant::now() + idle;
    let close_signal = session.close_signal.clone();
    let mut binding = None;
    let mut auth = AgentAuthState::for_connection(state);

    // Buffered read half: answering a request can park on the user, and
    // watching the client for departure while it does must not consume the
    // bytes a pipelining client already sent.
    let (read_half, mut writer) = stream.split();
    let mut reader = BufReader::new(read_half);

    loop {
        tokio::select! {
            reason = close_signal.reason() => return reason,
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
                    reason = close_signal.reason() => return reason,
                    _ = tokio::time::sleep_until(ttl_deadline) => return "session_ttl",
                    _ = client_gone(&mut reader) => return "client_closed",
                    response = handle_request(
                        state, signer.as_ref(), &mut binding, &mut auth, kind, &payload,
                    ) => response,
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

/// Whether one accepted connection must prove it holds the endpoint secret,
/// and whether it has.
///
/// Per connection, not per socket: an unauthenticated caller must not be able
/// to ride a state another caller established, which is the whole point.
/// `required` is sampled once when the connection is accepted, so flipping the
/// endpoint's posture mid-connection cannot strand a client that has already
/// authenticated — turning it *on* closes the live sessions instead.
struct AgentAuthState {
    required: bool,
    authenticated: bool,
    /// One wrong secret ends this connection's usefulness. Guessing then
    /// costs a fresh connection per attempt instead of a frame, and the
    /// activity log records attackers rather than their keystrokes.
    refused: bool,
}

impl AgentAuthState {
    fn for_connection(state: &AgentState) -> Self {
        let required = state
            .endpoint_id
            .and_then(|id| state.broker.endpoints.get(&id))
            .is_some_and(|endpoint| endpoint.require_auth);
        Self {
            required,
            authenticated: false,
            refused: false,
        }
    }
}

/// Answer one agent request. Unknown requests and refused signatures both
/// return SSH_AGENT_FAILURE — the ssh client's cue to move on.
async fn handle_request(
    state: &Arc<AgentState>,
    signer: Option<&Arc<SshSigner>>,
    binding: &mut Option<SessionBinding>,
    auth: &mut AgentAuthState,
    kind: u8,
    payload: &[u8],
) -> Vec<u8> {
    // On an authenticated endpoint nothing but the authentication extension
    // itself is served until the caller proves it holds the secret — not the
    // identity list, and not a session-bind. Listing identities is the
    // reconnaissance step, so exempting it would hand an unauthenticated
    // caller the public key and the connection's name for free.
    if auth.required && !auth.authenticated && (auth.refused || kind != SSH_AGENTC_EXTENSION) {
        return frame(SSH_AGENT_FAILURE, &[]);
    }
    match kind {
        SSH_AGENTC_REQUEST_IDENTITIES => {
            let body = signer
                .map(|signer| signer.identities_answer(&state.comment))
                .unwrap_or_else(|| 0u32.to_be_bytes().to_vec());
            frame(SSH_AGENT_IDENTITIES_ANSWER, &body)
        }
        SSH_AGENTC_EXTENSION
            if matches!(
                extension_name(payload),
                AUTHENTICATE_EXTENSION | LEGACY_AUTHENTICATE_EXTENSION
            ) =>
        {
            authenticate_extension(state, auth, payload)
        }
        SSH_AGENTC_EXTENSION => {
            // Route on the extension name. Every EXTENSION used to fall into
            // `session_bind`, so a routine client probe (`query`,
            // `restrict-destination-v00`) reached "unsupported agent extension"
            // and then `refuse()` — which writes an `SshSigned` /
            // "SSH signature refused" entry. Ordinary capability discovery
            // therefore looked like a security event in the activity log.
            // An unknown extension gets the bare failure the protocol defines
            // for it and no record at all.
            if extension_name(payload) != SESSION_BIND_EXTENSION {
                return frame(SSH_AGENT_FAILURE, &[]);
            }
            if binding.is_some() {
                // A second bind on one connection *is* worth recording: it is
                // not something a conforming client does.
                return refuse(state, "agent connection is already session-bound");
            }
            session_bind(state, binding, payload).await
        }
        SSH_AGENTC_SIGN_REQUEST => sign_response(state, signer, binding.as_ref(), payload).await,
        _ => frame(SSH_AGENT_FAILURE, &[]),
    }
}

/// The extension name at the head of an EXTENSION payload.
fn extension_name(payload: &[u8]) -> &[u8] {
    Reader::new(payload).string().unwrap_or_default()
}

/// Answer `authenticate@multitool.dev`: the caller presents this endpoint's
/// secret, and the connection is marked authenticated when it matches.
///
/// Resolved through the registry by hash and required to resolve to *this*
/// endpoint: a valid secret for a different endpoint is that endpoint's
/// authority, not this one's. A failure is recorded because nothing
/// legitimate presents a wrong secret here, and the only other trace would be
/// a closed socket — and it is recorded once, because the connection stops
/// answering after it, so a guesser cannot use the log as an amplifier.
///
/// Accepted on any endpoint socket, not only one that currently demands it: a
/// forwarder that read the posture a moment ago and connected a moment later
/// should not be broken by the race, and proving a secret you already hold
/// grants nothing the socket was withholding.
fn authenticate_extension(
    state: &Arc<AgentState>,
    auth: &mut AgentAuthState,
    payload: &[u8],
) -> Vec<u8> {
    let Some(endpoint_id) = state.endpoint_id else {
        // Nothing to prove: a per-open ticket socket has no endpoint secret.
        // Answering success would let a client believe it had authenticated
        // something, so this is the protocol's "I don't implement that".
        return frame(SSH_AGENT_EXTENSION_FAILURE, &[]);
    };
    let mut reader = Reader::new(payload);
    let (Some(_name), Some(secret)) = (reader.string(), reader.string()) else {
        return frame(SSH_AGENT_EXTENSION_FAILURE, &[]);
    };
    if !reader.is_empty() {
        return frame(SSH_AGENT_EXTENSION_FAILURE, &[]);
    }
    let presented = zeroize::Zeroizing::new(String::from_utf8_lossy(secret).into_owned());
    let matches = state
        .broker
        .endpoints
        .resolve_secret(&presented)
        .is_some_and(|resolved| resolved.id == endpoint_id);
    if !matches {
        auth.refused = true;
        state.broker.audit.append(
            AuditEntry::new(
                AuditKind::Denied,
                format!(
                    "SSH endpoint authentication refused: {}",
                    state.connection_name
                ),
            )
            .agent(state.agent.clone())
            .connection(state.connection_name.clone())
            .detail("the presented secret is not this endpoint's".to_string())
            .outcome("invalid_secret")
            .field("kind", "ssh")
            .field("endpoint_id", endpoint_id.to_string()),
        );
        return frame(SSH_AGENT_EXTENSION_FAILURE, &[]);
    }
    auth.authenticated = true;
    frame(SSH_AGENT_SUCCESS, &[])
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
    // One first-use pin at a time per open: a second connection racing this
    // one parks here and re-checks the then-pinned state. When first-use
    // confirmation is enabled, this also prevents duplicate prompts.
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

    // Ask before trusting, when the user has asked to be asked.
    //
    // The key has been proved to belong to whoever answered — `session-bind`
    // carries its signature over the session id — but nothing yet says that
    // whoever answered is the server the user meant. That is the question a
    // pin settles permanently, and it is the one moment it can be asked.
    if state.broker.store.settings().confirm_ssh_host_keys {
        if let Some(refusal) = confirm_host_key(state, &observed).await {
            return refusal;
        }
    }

    // Pin the observed key and record it.
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

/// What trusting a first-seen host key commits the user to.
const HOST_KEY_CONSEQUENCE: &str =
    "Pinning is permanent for this tool: from now on only this key is accepted, and a server \
     presenting any other is refused. If this is not the server you meant, the pin makes that \
     mistake durable — check the fingerprint against one you already trust.";

/// Ask the user to trust a host key seen for the first time.
///
/// Refuses on anything but approval, including a broker with no surface able
/// to ask: an unattended machine must not answer a trust question by assuming
/// yes. The refusal reaches the client as an ordinary agent failure, so the
/// reason lives in the activity log like every other one here.
async fn confirm_host_key(state: &Arc<AgentState>, observed: &Fingerprint) -> Option<Vec<u8>> {
    let Ok(connection) = state.broker.store.connection_by_id(&state.connection_id) else {
        return Some(refuse(state, "the connection has been removed"));
    };
    let verdict = state
        .broker
        .approvals
        .gate(
            crate::approvals::ApprovalRequest::new(
                &connection,
                state.agent.clone(),
                format!("Trust the SSH host key for {}", connection.target()),
            )
            .detail(observed.to_string())
            .host_key(observed)
            .consequence(HOST_KEY_CONSEQUENCE),
        )
        .await;
    if verdict.is_allowed() {
        return None;
    }
    Some(refuse_with(
        state,
        &format!("the host key was not trusted: {}", verdict.detail()),
        verdict
            .reason()
            .map(|reason| reason.as_str())
            .unwrap_or("refused"),
    ))
}

/// Record an agent *connection* refused before the protocol was served.
///
/// Deliberately not `refuse()`: that writes an `SshSigned` entry, and nothing
/// was ever asked to sign here. The client sees only a closed socket, so without
/// this the reason existed nowhere.
fn audit_refused_connection(state: &AgentState, outcome: &str, detail: &str) {
    let mut entry = AuditEntry::new(
        AuditKind::Denied,
        format!("SSH agent connection refused: {}", state.connection_name),
    )
    .agent(state.agent.clone())
    .connection(state.connection_name.clone())
    .detail(detail.to_string())
    .outcome(outcome.to_string())
    .field("kind", "ssh")
    .field("reason", outcome);
    if let Some(endpoint_id) = state.endpoint_id {
        entry = entry
            .field("via", "endpoint")
            .field("endpoint_id", endpoint_id.to_string());
    } else {
        entry = entry.field("via", "ticket");
    }
    state.broker.audit.append(entry);
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
     Multitool is not in that connection, so it cannot see the commands, time the session out, \
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
    if !state
        .broker
        .access
        .confirm_mode(&state.connection_id)
        .is_on()
    {
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
                .credentials_from(&state.broker.store)
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
    signer: Option<&Arc<SshSigner>>,
    binding: Option<&SessionBinding>,
    payload: &[u8],
) -> Vec<u8> {
    let Some(signer) = signer else {
        return refuse(state, "connection has no SSH private key");
    };
    // Charged before any parsing, so a client cannot spend CPU on malformed
    // requests either. Refusals are cheap and are not charged.
    if let Err(retry_after) = state.signatures.check() {
        return refuse_with(
            state,
            &format!(
                "signature budget exhausted; {}s until the next slot",
                retry_after.as_secs().max(1)
            ),
            "rate_limited",
        );
    }
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
        let ext = path.extension().and_then(|e| e.to_str());
        if ext != Some("sock") && ext != Some(SOCKET_STAGING_EXT) {
            continue;
        }
        // No liveness probe. Connecting to an agent socket *is* a redemption:
        // the old check spent one of the owning ticket's budget slots on every
        // swept file, and on a live socket it counted as a use nobody made.
        // It is also unnecessary — this runs from daemon startup, which already
        // holds the broker instance lease for this root, so no other broker can
        // own a socket in this directory. Anything here is from a dead run.
        let _ = std::fs::remove_file(&path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_key::rand_core::OsRng;

    #[test]
    fn login_test_ignores_executable_ssh_configuration() {
        let command = test_login_command(
            Path::new("/tmp/ssh.log"),
            Path::new("/tmp/agent.sock"),
            "resolved.example",
            "deploy",
            2222,
        );
        let args: Vec<String> = command
            .as_std()
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();

        assert!(args.windows(2).any(|pair| pair == ["-F", "/dev/null"]));
        assert!(args.iter().any(|arg| arg == "ProxyCommand=none"));
        assert!(args.iter().any(|arg| arg == "ProxyJump=none"));
        assert_eq!(args.iter().filter(|arg| *arg == "-p").count(), 1);
        assert!(args
            .windows(2)
            .any(|pair| pair == ["--", "resolved.example"]));
    }

    /// S4. An ECDSA key used to import cleanly and then fail at first login,
    /// because `ssh-key` parses curves it cannot sign. Import validation and
    /// the signer now agree, and both cover exactly the curves compiled in.
    #[test]
    fn ecdsa_keys_on_supported_curves_import_and_sign() {
        for curve in [
            Algorithm::Ecdsa {
                curve: ssh_key::EcdsaCurve::NistP256,
            },
            Algorithm::Ecdsa {
                curve: ssh_key::EcdsaCurve::NistP384,
            },
        ] {
            let key = PrivateKey::random(&mut OsRng, curve.clone()).unwrap();
            let pem = key.to_openssh(ssh_key::LineEnding::LF).unwrap();

            validate_private_key(pem.as_bytes())
                .unwrap_or_else(|e| panic!("{curve:?} must import: {e}"));
            let signer = SshSigner::from_pem(pem.as_bytes())
                .unwrap_or_else(|e| panic!("{curve:?} must load: {e}"));

            // Flags select the RSA hash and mean nothing here; the signature
            // must verify against the key's own public half either way.
            let blob = signer
                .sign(b"session-id-and-userauth", 0)
                .unwrap_or_else(|e| panic!("{curve:?} must sign: {e}"));
            let signature = Signature::try_from(blob.as_slice()).unwrap();
            key.public_key()
                .key_data()
                .verify(b"session-id-and-userauth", &signature)
                .unwrap_or_else(|e| panic!("{curve:?} signature must verify: {e}"));
        }
    }

    /// A curve the build cannot sign must be refused at import rather than
    /// accepted and discovered at the first login.
    #[test]
    fn an_unsignable_curve_is_refused_at_import() {
        let key = PrivateKey::random(
            &mut OsRng,
            Algorithm::Ecdsa {
                curve: ssh_key::EcdsaCurve::NistP521,
            },
        );
        // The build may not even be able to generate it; either way it must
        // never reach the vault as a usable key.
        if let Ok(key) = key {
            let pem = key.to_openssh(ssh_key::LineEnding::LF).unwrap();
            let error = validate_private_key(pem.as_bytes()).unwrap_err();
            assert!(error.contains("unsupported key type"), "{error}");
        }
    }

    /// SSH-23. A passphrase-protected key was refused with instructions to
    /// "store the decrypted OpenSSH key" — advice to run `ssh-keygen -p` and
    /// leave the stripped key sitting on disk before importing it. The vault is
    /// the protection boundary for a stored key, so the passphrase is spent once
    /// here and discarded.
    #[test]
    fn an_encrypted_key_is_decrypted_at_import_with_its_passphrase() {
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let expected = key.public_key().fingerprint(HashAlg::Sha256);
        let encrypted = key
            .encrypt(&mut OsRng, b"correct horse")
            .unwrap()
            .to_openssh(ssh_key::LineEnding::LF)
            .unwrap();

        // No passphrase: say so, distinctly, so the form can reveal a field.
        let error = private_key_for_vault(encrypted.as_bytes(), None).unwrap_err();
        assert_eq!(error, KeyImportError::NeedsPassphrase);
        assert!(error.wants_passphrase());
        // An empty string is "not offered", not "the passphrase is empty".
        assert_eq!(
            private_key_for_vault(encrypted.as_bytes(), Some("")).unwrap_err(),
            KeyImportError::NeedsPassphrase
        );

        // Wrong passphrase is its own answer: the field is already on screen.
        let error = private_key_for_vault(encrypted.as_bytes(), Some("battery")).unwrap_err();
        assert_eq!(error, KeyImportError::WrongPassphrase);
        assert!(error.wants_passphrase());

        // Right passphrase yields cleartext OpenSSH for the same key, which the
        // runtime signer accepts — the point of decrypting at import rather
        // than failing at first use.
        let stored = private_key_for_vault(encrypted.as_bytes(), Some("correct horse")).unwrap();
        validate_private_key(stored.as_bytes()).expect("the stored form must load at runtime");
        let reloaded = PrivateKey::from_openssh(stored.as_bytes()).unwrap();
        assert!(!reloaded.is_encrypted());
        assert_eq!(reloaded.public_key().fingerprint(HashAlg::Sha256), expected);
        let signer = SshSigner::from_pem(stored.as_bytes()).expect("a usable signer");
        assert_eq!(signer.public_blob, key.public_key().to_bytes().unwrap());
    }

    /// A cleartext key passes through unchanged in substance, and a passphrase
    /// offered for one is ignored rather than treated as an error.
    #[test]
    fn a_cleartext_key_needs_no_passphrase_and_tolerates_a_stray_one() {
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let pem = key.to_openssh(ssh_key::LineEnding::LF).unwrap();
        for passphrase in [None, Some("ignored")] {
            let stored = private_key_for_vault(pem.as_bytes(), passphrase).unwrap();
            let reloaded = PrivateKey::from_openssh(stored.as_bytes()).unwrap();
            assert_eq!(
                reloaded.public_key().fingerprint(HashAlg::Sha256),
                key.public_key().fingerprint(HashAlg::Sha256)
            );
        }
    }

    /// Decryption does not widen the algorithm set: an ECDSA key the signer
    /// cannot use is refused as unusable whether or not it was encrypted, and
    /// the surface must not offer a passphrase field for it.
    #[test]
    fn an_unusable_key_is_refused_without_asking_for_a_passphrase() {
        let error = private_key_for_vault(b"not a key at all", None).unwrap_err();
        assert!(matches!(error, KeyImportError::Unusable(_)), "{error:?}");
        assert!(!error.wants_passphrase());
        assert!(error.message().contains("parse failed"), "{error}");
    }

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
            // Ed25519 needs no RSA assembly.
            rsa: None,
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
                // Ed25519 needs no RSA assembly.
                rsa: None,
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

    #[test]
    fn socket_paths_are_rejected_before_bind_at_the_platform_limit() {
        let too_long = PathBuf::from(format!("/tmp/{}.sock", "x".repeat(UNIX_SOCKET_PATH_MAX)));
        let error = validate_unix_socket_path(&too_long).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        let detail = error.to_string();
        assert!(detail.contains(&UNIX_SOCKET_PATH_MAX.to_string()));
        assert!(detail.contains("--root"));
    }
}
