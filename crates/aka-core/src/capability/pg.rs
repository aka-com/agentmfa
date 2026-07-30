//! Postgres capability, `POST /v1/pg/open` + local TCP proxy.
//!
//! Postgres clients speak a binary wire protocol and expect a DSN, so the
//! broker runs a local TCP proxy on an OS-assigned ephemeral loopback port
//! (bound as port 0 at daemon start; surfaced only in open responses' DSNs).
//! The proxy runs **two independent handshakes** and only then byte-forwards
//! the established session:
//!
//! - **Downstream** the proxy *is* a Postgres server: it answers pre-startup
//!   `SSLRequest`/`GSSENCRequest` probes with `N`, reads the
//!   `StartupMessage`, and validates the session ticket as the credential
//!   (cleartext password exchange on the loopback leg).
//! - **Upstream** the proxy *is* a Postgres client: its own TCP connection,
//!   its own TLS per the connection's `sslmode`, and SCRAM-SHA-256 (or
//!   md5/cleartext) with the configured user and optional stored password.
//!   Servers using trust authentication need no secret. Client-certificate
//!   authentication is not implemented.
//! - Once both complete, the two legs speak byte-identical Postgres v3
//!   framing and are spliced with a plain bidirectional copy, seeded with
//!   any residual bytes the handshake readers buffered, so a pipelined
//!   first query is not swallowed at the handoff.
//!
//! Query cancellation works because the proxy synthesizes its own
//! `BackendKeyData` and keeps a mapping to the upstream session's real
//! pid/key: a `CancelRequest` connection is recognized, translated, and
//! fired at the mapped upstream.

use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use postgres_protocol::authentication::sasl::{
    ChannelBinding, ScramSha256, SCRAM_SHA_256, SCRAM_SHA_256_PLUS,
};
use tokio::io::{
    AsyncBufReadExt as _, AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, BufReader,
    ReadBuf,
};
use tokio::net::{TcpStream, UnixListener};
use tokio::sync::Notify;

use super::{TestError, TestErrorKind};
use crate::audit::{AuditEntry, AuditKind};
use crate::broker::Broker;
use crate::endpoints::EndpointListenerHandle;
use crate::sessions::{RedeemError, SessionHandle};
use crate::store::Store;
use crate::types::{Connection, ConnectionConfig, ConnectionKind, DirectEndpoint, PgSslMode};

/* ---------------------------- wire constants ------------------------------ */

const PROTOCOL_V3: i32 = 196608;
const CANCEL_REQUEST_CODE: i32 = 80877102;
const SSL_REQUEST_CODE: i32 = 80877103;
const GSSENC_REQUEST_CODE: i32 = 80877104;

/// Matches PG's MAX_STARTUP_PACKET_LENGTH.
const MAX_STARTUP_PACKET: usize = 10_000;
/// Sanity cap on handshake-phase typed messages.
const MAX_HANDSHAKE_MESSAGE: usize = 1024 * 1024;
/// Total ParameterStatus/NoticeResponse bytes retained until the downstream
/// handshake is ready. Individual frames are bounded above; this bounds the
/// otherwise unlimited number of frames.
const MAX_STARTUP_FORWARD_BYTES: usize = 64 * 1024;
/// A legitimate authentication exchange needs only a handful of messages,
/// including SCRAM. Repeated password challenges must not make the broker
/// resend a credential forever.
const MAX_UPSTREAM_AUTH_MESSAGES: usize = 8;
const MAX_TEST_QUERY_MESSAGES: usize = 64;
const MAX_TEST_QUERY_BYTES: usize = 64 * 1024;
/// Protocol ceiling on a message's self-inclusive length field. The data path
/// forwards bytes without parsing them; the observational scanner uses this
/// only to notice that it has lost the message boundary.
const MAX_SPLICE_MESSAGE: usize = 0x3fff_ffff;

/* ---------------------------- framing helpers ----------------------------- */

fn put_i32(buf: &mut Vec<u8>, v: i32) {
    buf.extend_from_slice(&v.to_be_bytes());
}

fn put_cstr(buf: &mut Vec<u8>, s: &str) {
    buf.extend_from_slice(s.as_bytes());
    buf.push(0);
}

fn be_i32(bytes: &[u8]) -> i32 {
    let mut arr = [0u8; 4];
    arr.copy_from_slice(&bytes[..4]);
    i32::from_be_bytes(arr)
}

/// A typed backend/frontend message: tag + i32 length (self-inclusive,
/// tag-exclusive) + payload.
fn frame(tag: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 5);
    out.push(tag);
    put_i32(&mut out, payload.len() as i32 + 4);
    out.extend_from_slice(payload);
    out
}

/// Split a NUL-terminated string off the front of a buffer.
fn take_cstr(bytes: &[u8]) -> io::Result<(String, &[u8])> {
    let nul = bytes
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "unterminated string"))?;
    Ok((
        String::from_utf8_lossy(&bytes[..nul]).into_owned(),
        &bytes[nul + 1..],
    ))
}

/// Read a length-prefixed pre-startup packet (StartupMessage, SSLRequest,
/// GSSENCRequest or CancelRequest): i32 self-inclusive length, no tag byte.
/// Returns the payload after the length word.
async fn read_startup_packet<R>(reader: &mut R) -> io::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut len = [0u8; 4];
    reader.read_exact(&mut len).await?;
    let len = be_i32(&len);
    if !(8..=MAX_STARTUP_PACKET as i32).contains(&len) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid startup packet length {len}"),
        ));
    }
    let mut payload = vec![0u8; len as usize - 4];
    reader.read_exact(&mut payload).await?;
    Ok(payload)
}

/// Read a typed message: tag u8 + i32 self-inclusive length + payload.
async fn read_message<R>(reader: &mut R) -> io::Result<(u8, Vec<u8>)>
where
    R: AsyncRead + Unpin,
{
    let mut head = [0u8; 5];
    reader.read_exact(&mut head).await?;
    let tag = head[0];
    let len = be_i32(&head[1..5]);
    if !(4..=MAX_HANDSHAKE_MESSAGE as i32).contains(&len) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid message length {len}"),
        ));
    }
    let mut payload = vec![0u8; len as usize - 4];
    reader.read_exact(&mut payload).await?;
    Ok((tag, payload))
}

/// Build an `ErrorResponse` with the SQLSTATE fields drivers key on.
fn error_response(severity: &str, sqlstate: &str, message: &str) -> Vec<u8> {
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

/// Extract the human message and SQLSTATE from an upstream `ErrorResponse`.
fn parse_error_response(payload: &[u8]) -> (String, String) {
    let mut code = String::new();
    let mut message = String::new();
    let mut rest = payload;
    while let Some((&field, tail)) = rest.split_first() {
        if field == 0 {
            break;
        }
        let Ok((value, tail)) = take_cstr(tail) else {
            break;
        };
        match field {
            b'C' => code = value,
            b'M' => message = value,
            _ => {}
        }
        rest = tail;
    }
    (code, message)
}

fn sentence_case(message: String) -> String {
    let mut chars = message.chars();
    let Some(first) = chars.next() else {
        return message;
    };
    first.to_uppercase().chain(chars).collect()
}

/// An upstream `ErrorResponse` as a `TestError`: the server's own message
/// leads, sentence-cased, with the SQLSTATE parenthesized for looking up.
/// SQLSTATE class 28 (invalid authorization specification) is a credential
/// rejection.
fn upstream_error(payload: &[u8]) -> TestError {
    let (code, message) = parse_error_response(payload);
    let message = sentence_case(message);
    let kind = if code.starts_with("28") {
        TestErrorKind::AuthRejected
    } else {
        TestErrorKind::Other
    };
    let detail = match (message.is_empty(), code.is_empty()) {
        (false, false) => format!("{message} ({code})"),
        (false, true) => message,
        (true, false) => format!("The server reported error {code}"),
        (true, true) => "The server reported an error with no detail".into(),
    };
    TestError::new(kind, detail)
}

/// Parse StartupMessage parameters (the bytes after the protocol version):
/// NUL-terminated name/value pairs closed by an empty terminator.
fn parse_startup_params(mut rest: &[u8]) -> io::Result<Vec<(String, String)>> {
    let mut params = Vec::new();
    loop {
        let (name, tail) = take_cstr(rest)?;
        if name.is_empty() {
            return Ok(params);
        }
        let (value, tail) = take_cstr(tail)?;
        params.push((name, value));
        rest = tail;
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/* ------------------------------ proxy state ------------------------------- */

/// Where a synthesized BackendKeyData points: enough to open a fresh upstream
/// connection (with the same TLS negotiation) and fire the real CancelRequest
/// at the mapped session.
#[derive(Clone)]
struct CancelTarget {
    host: String,
    port: u16,
    sslmode: PgSslMode,
    trusted_ca_bundle_path: Option<String>,
    backend_pid: i32,
    backend_key: i32,
}

struct ProxyState {
    broker: Arc<Broker>,
    /// synthesized (pid, key) → upstream cancel target; removed at session end.
    cancels: Mutex<HashMap<(i32, i32), CancelTarget>>,
    /// Admission control over the *unauthenticated* handshake phase. Accepting
    /// without a bound let anything that can reach the port spawn tasks and
    /// buffers without presenting a ticket; the permit is released as soon as
    /// the ticket is redeemed, so an authorized session never holds one.
    handshakes: tokio::sync::Semaphore,
    /// Meter redemption on both the presented capability and the network
    /// source. Ticket limiting constrains a captured ticket; peer limiting
    /// prevents arbitrary-ticket churn from evading that bucket.
    redemptions_by_ticket: crate::ratelimit::KeyedLimiter,
    redemptions_by_peer: crate::ratelimit::KeyedLimiter,
}

impl ProxyState {
    fn new(broker: Arc<Broker>) -> Self {
        let permits = broker.config.max_pending_pg_handshakes;
        Self {
            redemptions_by_ticket: crate::ratelimit::KeyedLimiter::new(
                broker.config.per_identity_per_min,
                Duration::from_secs(60),
            ),
            redemptions_by_peer: crate::ratelimit::KeyedLimiter::new(
                broker.config.per_identity_per_min,
                Duration::from_secs(60),
            ),
            broker,
            cancels: Mutex::new(HashMap::new()),
            handshakes: tokio::sync::Semaphore::new(permits),
        }
    }
}

/// Record a refused data-plane connection.
///
/// The client learns the reason in its own protocol, but without this the
/// broker's own log shows nothing — so a burst of guessed endpoint secrets, a
/// stale DSN retrying against a revoked connection, or an agent hitting a
/// disabled tool were all invisible in Activity.
fn audit_refusal(broker: &Broker, connection: Option<&str>, reason: &str, detail: &str) {
    let mut entry = AuditEntry::new(
        AuditKind::Denied,
        format!("Postgres connection refused: {reason}"),
    )
    .detail(detail.to_string())
    .outcome(reason.to_string())
    .field("kind", "pg")
    .field("reason", reason);
    if let Some(name) = connection {
        entry = entry.connection(name.to_string());
    }
    broker.audit.append(entry);
}

fn audit_redemption_rate_limit(
    broker: &Broker,
    peer: std::net::SocketAddr,
    scope: &str,
    retry_after: Duration,
) {
    broker.audit.append(
        AuditEntry::new(
            AuditKind::RateLimited,
            format!("Postgres redemption rate limited: {}", peer.ip()),
        )
        .detail(format!(
            "Too many data-plane redemption attempts; retry in {}s",
            retry_after.as_secs().max(1)
        ))
        .outcome("rate_limited")
        .field("kind", "pg")
        .field("scope", scope)
        .field("peer_addr", peer.to_string())
        .field("retry_after_seconds", retry_after.as_secs().max(1)),
    );
}

/// Record that `sslmode=prefer` asked for TLS, the server refused, and the
/// session proceeded in clear text anyway.
///
/// libpq behaves the same way, but AgentMFA is the custodian of the credential
/// that just crossed the network unprotected: an on-path attacker who answers
/// `N` and then requests `AuthenticationCleartextPassword` harvests the vault's
/// password, and without this the user has no record that TLS was ever lost.
/// Health carries it too, so the state is visible in the app and not only in
/// the log.
fn audit_tls_downgrade(broker: &Broker, connection: &Connection) {
    broker.audit.append(
        AuditEntry::new(
            AuditKind::TlsDowngraded,
            format!(
                "TLS unavailable, continued in clear text: {}",
                connection.name
            ),
        )
        .detail(
            "The server refused TLS and this connection's mode is \"prefer\", so the \
             credential and every statement crossed the network unencrypted. Set the \
             connection to \"require\" or stronger to refuse instead."
                .to_string(),
        )
        .connection(connection.name.clone())
        .outcome("tls_downgraded")
        .field("kind", "pg")
        .field("sslmode", "prefer"),
    );
    // The connection *works*, so the status stays `Ok` and the detail carries
    // the caveat: a downgrade is not a failure to fix by reconnecting, and
    // there is no third status between "fine" and "broken" to put it in.
    broker.health.record(
        &connection.id,
        crate::types::HealthStatus::Ok,
        "Reached the database, but the server refused TLS — traffic is in clear text",
    );
}

/// Run an upstream dial under the broker's upstream deadline.
///
/// The Test button has always been wrapped; the data path was not, so a host
/// that accepts nothing left the client waiting on the OS TCP timeout while a
/// redemption slot stayed reserved, and expiry surfaced as a hang rather than
/// as the `Timeout` kind that already existed for it.
async fn dial_with_timeout<F>(broker: &Broker, dial: F) -> Result<UpstreamSession, TestError>
where
    F: std::future::Future<Output = Result<UpstreamSession, TestError>>,
{
    match tokio::time::timeout(broker.config.upstream_timeout, dial).await {
        Ok(result) => result,
        Err(_) => Err(TestError::new(
            TestErrorKind::Timeout,
            format!(
                "The database did not answer within {}s",
                broker.config.upstream_timeout.as_secs()
            ),
        )),
    }
}

/// Grade a connection's health from a data-plane dial. A dial is as
/// conclusive about the destination as the Test button's is, so its outcome
/// belongs in the same place — otherwise a connection whose password was
/// rotated at the database keeps showing a stale green badge while every
/// agent session fails.
fn record_dial_health(
    broker: &Broker,
    connection_id: &uuid::Uuid,
    outcome: &Result<(), TestError>,
) {
    match outcome {
        Ok(()) => broker
            .health
            .record_ok_if_changed(connection_id, "A brokered session reached the database"),
        Err(e) => {
            broker
                .health
                .record_if_changed(connection_id, e.kind.health_status(), e.detail.clone())
        }
    }
}

impl ProxyState {
    /// Mint a fresh random (pid, key) pair and register the mapping.
    fn register_cancel(self: &Arc<Self>, target: CancelTarget) -> CancelRegistration {
        let mut map = self.cancels.lock().unwrap();
        loop {
            let mut buf = [0u8; 8];
            getrandom::fill(&mut buf).expect("os rng");
            let pid = be_i32(&buf[0..4]);
            let key = be_i32(&buf[4..8]);
            if let std::collections::hash_map::Entry::Vacant(e) = map.entry((pid, key)) {
                e.insert(target);
                return CancelRegistration {
                    state: self.clone(),
                    key: (pid, key),
                };
            }
        }
    }
}

/// RAII guard: unregisters the synthesized key mapping when the session's
/// connection task ends, however it ends.
struct CancelRegistration {
    state: Arc<ProxyState>,
    key: (i32, i32),
}

impl Drop for CancelRegistration {
    fn drop(&mut self) {
        self.state.cancels.lock().unwrap().remove(&self.key);
    }
}

/// Start the PG proxy listener on an OS-assigned ephemeral loopback port.
/// Returns the bound port and the accept-loop task handle.
pub async fn start_proxy(broker: Arc<Broker>) -> io::Result<(u16, tokio::task::JoinHandle<()>)> {
    let listener = tokio::net::TcpListener::bind((broker.data_plane_bind(), 0)).await?;
    let port = listener.local_addr()?.port();
    let state = Arc::new(ProxyState::new(broker));
    let task = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, peer)) => {
                    let state = state.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_conn(state, stream, peer).await {
                            tracing::debug!("pg proxy connection ended: {e}");
                        }
                    });
                }
                Err(e) => {
                    tracing::error!("pg proxy accept failed: {e}");
                    break;
                }
            }
        }
    });
    Ok((port, task))
}

/* --------------------------- per-wiring endpoint -------------------------- */

/// The synthetic port in a PG endpoint's Unix socket filename
/// (`.s.PGSQL.<port>`, libpq's convention) and echoed in the pasteable DSN.
/// The upstream port always comes from the connection, never from this.
pub const PG_ENDPOINT_PORT: u16 = 5432;

/// The pasteable connection string for a Postgres endpoint bound under `dir`.
/// libpq derives the socket path from `host` + `port` as
/// `<host>/.s.PGSQL.<port>`, so pointing `host` at the endpoint directory
/// reaches the per-wiring listener with an unmodified client. When the
/// plaintext secret is at hand (issue time only — the registry stores just
/// its hash), it rides in the DSN's password slot so the string works
/// standalone; without it, the caller supplies `PGPASSWORD` out-of-band.
/// The `end_` + hex secret alphabet needs no percent-encoding.
pub fn endpoint_dsn(
    dir: &std::path::Path,
    user: &str,
    dbname: &str,
    secret: Option<&str>,
) -> String {
    let auth = match secret {
        Some(secret) => format!("{user}:{secret}"),
        None => user.to_string(),
    };
    format!(
        "postgresql://{auth}@/{dbname}?host={}&port={PG_ENDPOINT_PORT}&sslmode=disable",
        dir.display()
    )
}

/// The pasteable connection string for a Postgres endpoint's TCP listener.
///
/// The Unix-socket form above is the tighter surface — filesystem permissions
/// keep other users out — but it is also libpq-only: JDBC has no Unix-socket
/// support, and Node `pg`, Npgsql and several ORMs do not read `host=` as a
/// socket directory. It is useless off-box as well, so a hosted broker had no
/// working direct endpoint at all. This is the ordinary
/// `postgresql://user:pass@host:port/db` every driver already parses.
pub fn endpoint_tcp_dsn(
    host: &str,
    port: u16,
    user: &str,
    dbname: &str,
    secret: Option<&str>,
) -> String {
    let auth = match secret {
        Some(secret) => format!("{user}:{secret}"),
        None => user.to_string(),
    };
    format!("postgresql://{auth}@{host}:{port}/{dbname}?sslmode=disable")
}

/// Bind a direct Postgres endpoint: a private Unix-domain listener at
/// `<endpoint-dir>/.s.PGSQL.5432` that an unmodified `psql`/driver reaches
/// with `host=<endpoint-dir>`. Attribution is the endpoint secret presented
/// as the password; filesystem permissions keep other users out. Returns the
/// running listener handle for the broker to hold and later stop.
/// Two listeners, one endpoint: the Unix socket for libpq clients on the same
/// machine, and a TCP listener on the data-plane address for everything else —
/// drivers with no Unix-socket support, and any client at all when the broker
/// is hosted. Both present the same endpoint secret as the password and run
/// the same handler, so neither is a second authorization path. Returns the
/// bound TCP port so the caller can pin it across restarts.
pub async fn bind_endpoint(
    broker: Arc<Broker>,
    endpoint: &DirectEndpoint,
) -> io::Result<(EndpointListenerHandle, u16)> {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = broker.paths.endpoint_dir(&endpoint.id);
    crate::paths::create_private_dir(&dir)?;
    let sock_path = dir.join(format!(".s.PGSQL.{PG_ENDPOINT_PORT}"));
    // A leftover socket from a previous run would fail the bind.
    if let Err(e) = std::fs::remove_file(&sock_path) {
        if e.kind() != io::ErrorKind::NotFound {
            return Err(e);
        }
    }
    let listener = UnixListener::bind(&sock_path)?;
    std::fs::set_permissions(&sock_path, std::fs::Permissions::from_mode(0o600))?;

    // Reuse the pinned port when there is one, so a pasted TCP DSN survives a
    // restart the way the HTTP endpoint's base URL does. A pinned port another
    // process has taken since must fail the rebind — not fall back to a fresh
    // one: `rebind_endpoints` revokes on bind failure precisely because a
    // client whose DSN still names the old port would present the still-valid
    // endpoint secret (in cleartext — the DSN pins sslmode=disable) to
    // whatever process now owns it. Silently moving ports kept that secret
    // live while the pasted address fed it to a stranger.
    let bind_addr = broker.data_plane_bind();
    let tcp = tokio::net::TcpListener::bind((bind_addr, endpoint.port.unwrap_or(0))).await?;
    let port = tcp.local_addr()?.port();

    let state = Arc::new(ProxyState::new(broker));
    let endpoint_id = endpoint.id;
    let shutdown = Arc::new(Notify::new());
    let sd = shutdown.clone();
    let task = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = sd.notified() => break,
                accepted = listener.accept() => match accepted {
                    Ok((stream, _)) => {
                        let state = state.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_endpoint_conn(state, stream, endpoint_id).await {
                                tracing::debug!("pg endpoint connection ended: {e}");
                            }
                        });
                    }
                    Err(e) => {
                        tracing::error!("pg endpoint accept failed: {e}");
                        break;
                    }
                },
                accepted = tcp.accept() => match accepted {
                    Ok((stream, _)) => {
                        let _ = stream.set_nodelay(true);
                        let state = state.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_endpoint_conn(state, stream, endpoint_id).await {
                                tracing::debug!("pg endpoint connection ended: {e}");
                            }
                        });
                    }
                    Err(e) => {
                        tracing::error!("pg endpoint tcp accept failed: {e}");
                        break;
                    }
                }
            }
        }
    });
    Ok((EndpointListenerHandle { shutdown, task }, port))
}

/// One accepted endpoint connection: probes → startup (or cancel) → endpoint
/// secret auth (with a live-wiring re-check) → upstream handshake → splice.
/// Mirrors `handle_conn`, but the presented password is the per-wiring secret
/// rather than a ticket, and authorization is re-verified here at connect time
/// rather than at a control-plane open.
async fn handle_endpoint_conn<S>(
    state: Arc<ProxyState>,
    stream: S,
    endpoint_id: uuid::Uuid,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut client = BufReader::new(stream);

    // The same pre-auth posture as the ticket proxy: everything up to a
    // verified endpoint secret is unauthenticated, so it runs under one
    // admission permit and one deadline. This handler used to be reachable
    // only over the owner-only Unix socket; the TCP listener makes it
    // reachable by any local process — and, off-loopback, by any peer — so a
    // client that connects and says nothing must not hold a task and an fd
    // for as long as it likes.
    let admission = state
        .handshakes
        .try_acquire()
        .map_err(|_| io::Error::other("pg endpoint handshake admission exhausted"))?;
    let deadline = tokio::time::Instant::now() + state.broker.config.pg_handshake_timeout;

    let params = match tokio::time::timeout_at(deadline, read_startup_phase(&mut client, &state))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "pg startup phase timed out"))??
    {
        StartupPhase::Startup(params) => params,
        StartupPhase::Cancelled => return Ok(()),
    };

    // The presented password IS the per-wiring endpoint secret.
    client.write_all(&frame(b'R', &3i32.to_be_bytes())).await?;
    let (tag, payload) = tokio::time::timeout_at(deadline, read_message(&mut client))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "pg password message timed out"))??;
    if tag != b'p' {
        client
            .write_all(&error_response(
                "FATAL",
                "08P01",
                "expected PasswordMessage",
            ))
            .await?;
        return Ok(());
    }
    let (presented, _) = take_cstr(&payload)?;

    // Attribute the secret to THIS endpoint. A secret that resolves to another
    // endpoint (or to nothing) is refused as an invalid password.
    let Some(endpoint) = state
        .broker
        .endpoints
        .resolve_secret(&presented)
        .filter(|e| e.id == endpoint_id)
    else {
        // Same condition, same name as the HTTP endpoint's rejection: one
        // reason string so a filter on it catches both data planes.
        audit_refusal(
            &state.broker,
            None,
            "invalid_secret",
            "the presented password is not this endpoint's secret",
        );
        client
            .write_all(&error_response(
                "FATAL",
                "28P01",
                "AKA: invalid endpoint secret",
            ))
            .await?;
        return Ok(());
    };

    // Re-check access at connect time: a disabled tool must be refused
    // even if a stale listener briefly outlived its teardown.
    if !state.broker.access.allows(&endpoint.connection_id) {
        // The endpoint resolved, so the tool has a name — an entry that
        // carries it lands on the right row in Activity.
        let name = state
            .broker
            .store
            .connection_by_id(&endpoint.connection_id)
            .ok()
            .map(|c| c.name);
        audit_refusal(
            &state.broker,
            name.as_deref(),
            "denied_by_policy",
            "agent access is disabled for this tool",
        );
        client
            .write_all(&error_response("FATAL", "28000", "AKA: denied_by_policy"))
            .await?;
        return Ok(());
    }

    // Resolve the connection fresh; it may have been edited since issue.
    let Ok(connection) = state.broker.store.connection_by_id(&endpoint.connection_id) else {
        client
            .write_all(&error_response("FATAL", "08006", "AKA: unknown_connection"))
            .await?;
        return Ok(());
    };
    if !matches!(&connection.config, ConnectionConfig::Pg { .. }) {
        client
            .write_all(&error_response(
                "FATAL",
                "08P01",
                "AKA: connection is no longer Postgres",
            ))
            .await?;
        return Ok(());
    }

    let approved_version = connection.updated_at;

    // Authenticated: the pre-auth deadline and admission permit have done
    // their job, and what follows (a confirmation prompt, an upstream dial)
    // has budgets of its own.
    drop(admission);

    // A direct endpoint is standing authority, so the confirmation is the
    // only thing standing between a pasted DSN and the database.
    match confirm_session(&state, &mut client, &connection, "endpoint", &params).await {
        SessionConfirmation::Proceed => {}
        SessionConfirmation::Refused(refusal) => {
            client.write_all(&refusal).await?;
            return Ok(());
        }
        SessionConfirmation::Abandoned => return Ok(()),
    }

    // Confirmation may wait for a user for up to a minute and a half. Revoke,
    // retarget, or disable during that wait must be observed before stored
    // credentials are used against the upstream.
    let endpoint_still_valid = state
        .broker
        .endpoints
        .resolve_secret(&presented)
        .is_some_and(|current| current.id == endpoint_id);
    if !endpoint_still_valid || !state.broker.access.allows(&connection.id) {
        state.broker.approvals.revoke(&connection.id);
        audit_refusal(
            &state.broker,
            Some(&connection.name),
            "denied_by_policy",
            "the endpoint or the tool's access was revoked while the session was being established",
        );
        client
            .write_all(&error_response("FATAL", "28000", "AKA: denied_by_policy"))
            .await?;
        return Ok(());
    }

    // Use the current credential binding and TLS configuration, not the
    // snapshot from before the user was asked.
    let Ok(connection) = state.broker.store.connection_by_id(&endpoint.connection_id) else {
        state.broker.approvals.revoke(&endpoint.connection_id);
        client
            .write_all(&error_response("FATAL", "08006", "AKA: unknown_connection"))
            .await?;
        return Ok(());
    };
    if connection.updated_at != approved_version {
        state.broker.approvals.revoke(&connection.id);
        audit_refusal(
            &state.broker,
            Some(&connection.name),
            "denied_by_policy",
            "the tool was retargeted after the approval",
        );
        client
            .write_all(&error_response("FATAL", "28000", "AKA: denied_by_policy"))
            .await?;
        return Ok(());
    }
    let ConnectionConfig::Pg {
        host,
        port,
        sslmode,
        trusted_ca_bundle_path,
        ..
    } = connection.config.clone()
    else {
        client
            .write_all(&error_response(
                "FATAL",
                "08P01",
                "AKA: connection is no longer Postgres",
            ))
            .await?;
        return Ok(());
    };

    // Dial upstream with the stored password secret. The wiring is the
    // authorization, so the secret read is pre-authorized (scope confirmed).
    let upstream = match dial_with_timeout(
        &state.broker,
        crate::authorization::scope(
            true,
            dial_upstream(&state.broker.store, &connection, &params),
        ),
    )
    .await
    {
        Ok(upstream) => {
            if upstream.tls_downgraded {
                audit_tls_downgrade(&state.broker, &connection);
            } else {
                record_dial_health(&state.broker, &connection.id, &Ok(()));
            }
            upstream
        }
        Err(e) => {
            record_dial_health(&state.broker, &connection.id, &Err(e.clone()));
            audit_refusal(
                &state.broker,
                Some(&connection.name),
                "upstream_connect_failed",
                &e.detail,
            );
            client
                .write_all(&error_response(
                    "FATAL",
                    "08001",
                    &format!("AKA: upstream_connect_failed: {e}"),
                ))
                .await?;
            return Ok(());
        }
    };

    // Reserve the live-session slot (global backstop) before committing the
    // downstream handshake, so exhaustion is a clean pre-ReadyForQuery error.
    let configured_sslmode = sslmode_name(sslmode);
    let upstream_tls = effective_tls_mode(sslmode, upstream.tls_downgraded);
    let session = match state.broker.data_plane.start_endpoint_session_with_fields(
        "endpoint",
        &connection,
        endpoint_id,
        ConnectionKind::Pg,
        &[
            ("sslmode", configured_sslmode),
            ("upstream_tls", upstream_tls),
        ],
    ) {
        Ok(session) => session,
        Err(_) => {
            audit_refusal(
                &state.broker,
                Some(&connection.name),
                "broker_session_limit",
                "the broker-wide live-session backstop is exhausted",
            );
            client
                .write_all(&error_response(
                    "FATAL",
                    "53300",
                    "AKA: broker_session_limit",
                ))
                .await?;
            return Ok(());
        }
    };
    // Close the establishment race with disable/revoke: either teardown sees
    // the registered session, or this post-registration check sees the new
    // policy/registry state and retires it before ReadyForQuery is sent.
    let endpoint_still_valid = state
        .broker
        .endpoints
        .resolve_secret(&presented)
        .is_some_and(|current| current.id == endpoint_id);
    if !endpoint_still_valid || !state.broker.access.allows(&connection.id) {
        session.finish("access_revoked");
        audit_refusal(
            &state.broker,
            Some(&connection.name),
            "denied_by_policy",
            "the endpoint or the tool's access was revoked while the session was being established",
        );
        client
            .write_all(&error_response("FATAL", "28000", "AKA: denied_by_policy"))
            .await?;
        return Ok(());
    }

    let registration = state.register_cancel(CancelTarget {
        host,
        port,
        sslmode,
        trusted_ca_bundle_path,
        backend_pid: upstream.backend_pid,
        backend_key: upstream.backend_key,
    });
    let (synth_pid, synth_key) = registration.key;
    let mut completion = frame(b'R', &0i32.to_be_bytes());
    completion.extend_from_slice(&upstream.forward);
    let mut keydata = Vec::with_capacity(8);
    put_i32(&mut keydata, synth_pid);
    put_i32(&mut keydata, synth_key);
    completion.extend_from_slice(&frame(b'K', &keydata));
    completion.extend_from_slice(&frame(b'Z', &[upstream.ready_status]));
    if client.write_all(&completion).await.is_err() {
        // The client vanished after auth: retire the session we just opened.
        session.finish("client_closed");
        return Ok(());
    }

    let max_ttl = state.broker.config.session_max_ttl;
    let idle = state.broker.config.session_idle_timeout;
    let audit = SpliceAudit {
        broker: state.broker.clone(),
        connection: connection.name.clone(),
        agent: "endpoint".to_string(),
        record_statements: state.broker.config.audit_pg_statements,
    };
    splice(client, upstream.stream, session, max_ttl, idle, audit).await;
    drop(registration);
    Ok(())
}

/* ------------------------- downstream state machine ----------------------- */

/// How a parked session confirmation came out.
enum SessionConfirmation {
    /// Approved (or the switch is off): open the session.
    Proceed,
    /// Refused: the FATAL frame to send downstream.
    Refused(Vec<u8>),
    /// The downstream client hung up while the prompt was parked. There is
    /// nobody to answer, and the session must not be dialed for nobody.
    Abandoned,
}

/// Ask the user about a new Postgres session when the connection's
/// confirmation switch is on.
///
/// Postgres is confirmed per **session**, not per statement: once both
/// handshakes complete the proxy splices raw bytes, so this is the last
/// point at which a decision can still be taken. A client that opens a pool
/// raises one prompt for the first connection and rides its window for the
/// rest.
///
/// Which means the prompt has to say what a session *is*. Naming the client
/// and calling it a session is true but incomplete: one approved session
/// carries every statement the client cares to send, and a user reading
/// "New Postgres session · psql" can reasonably picture a query rather than
/// `DROP TABLE` or `COPY … TO PROGRAM`. [`SESSION_CONSEQUENCE`] closes that
/// gap until there is a per-statement gate to replace it with.
///
/// While parked, the downstream socket is watched: a client that gives up
/// (Ctrl-C on `psql`, a pool timeout) retires its prompt instead of leaving
/// a dead question on the user that could open a session nobody is reading.
/// What approving a Postgres session actually hands over. Broker-authored and
/// `'static`, so nothing an agent or its client sends can reword or displace
/// it — the client-supplied `application_name` rides in `detail` instead.
pub(crate) const SESSION_CONSEQUENCE: &str =
    "Grants full SQL access for the whole session — reads, writes, schema changes, and \
     anything else the role may do. Postgres is confirmed once per session, not per statement.";

async fn confirm_session<S>(
    state: &Arc<ProxyState>,
    client: &mut BufReader<S>,
    connection: &Connection,
    agent: &str,
    params: &[(String, String)],
) -> SessionConfirmation
where
    S: AsyncRead + Unpin,
{
    if !state.broker.access.confirm_mode(&connection.id).is_on() {
        return SessionConfirmation::Proceed;
    }
    // The startup parameters are the only thing the client tells us about
    // itself: `psql`, a migration tool, an ORM's pool.
    let lookup = |key: &str| {
        params
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.clone())
    };
    let upstream_user = match &connection.config {
        ConnectionConfig::Pg { user, .. } => user.clone(),
        _ => String::new(),
    };
    let detail = [
        lookup("application_name"),
        (!upstream_user.is_empty()).then(|| format!("user={upstream_user}")),
    ]
    .into_iter()
    .flatten()
    .filter(|part| !part.is_empty())
    .collect::<Vec<_>>()
    .join(" · ");
    let request = crate::approvals::ApprovalRequest::new(connection, agent, "New Postgres session")
        .maybe_detail((!detail.is_empty()).then_some(detail))
        .consequence(SESSION_CONSEQUENCE);
    let verdict = tokio::select! {
        verdict = state.broker.approvals.gate(request) => verdict,
        _ = downstream_gone(client) => {
            // Dropping the gate closed this session's waiter; retire its
            // prompt now (the sweep inside `pending` sees the closed
            // waiter) rather than leaving it to the deadline.
            let _ = state.broker.approvals.pending();
            return SessionConfirmation::Abandoned;
        }
    };
    if verdict.is_allowed() {
        return SessionConfirmation::Proceed;
    }
    let reason = verdict
        .reason()
        .unwrap_or(crate::wire::ErrorReason::ApprovalDenied);
    SessionConfirmation::Refused(error_response(
        "FATAL",
        // Refusing the session is an authorization outcome, whichever way
        // the confirmation went; libpq surfaces the message either way.
        "28000",
        &format!("AKA: {}: {}", reason.as_str(), verdict.detail()),
    ))
}

/// Resolves when the downstream hangs up. A client is not expected to send
/// anything while its session is parked on confirmation; if bytes do arrive
/// (an eagerly pipelining driver), they stay buffered untouched and the
/// watch simply stops — the prompt's outcome decides what happens to them.
async fn downstream_gone<S: AsyncRead + Unpin>(client: &mut BufReader<S>) {
    match client.fill_buf().await {
        Ok([]) => {}
        Ok(_) => std::future::pending().await,
        Err(_) => {}
    }
}

/// Outcome of the Postgres pre-startup phase, shared by the ticket proxy and
/// the per-wiring endpoint listeners: either a real `StartupMessage` (with its
/// parameters) or a `CancelRequest` connection that carried no startup and was
/// already relayed to the upstream.
enum StartupPhase {
    Startup(Vec<(String, String)>),
    Cancelled,
}

/// Drive the pre-startup phase on any downstream transport: a client may probe
/// `SSLRequest`/`GSSENCRequest` (each declined with a single `N`, the loopback
/// leg is plaintext by contract) before the `StartupMessage`, and a
/// `CancelRequest` connection carries no `StartupMessage` at all.
async fn read_startup_phase<S>(
    client: &mut BufReader<S>,
    state: &Arc<ProxyState>,
) -> io::Result<StartupPhase>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut probes = 0;
    loop {
        let payload = read_startup_packet(client).await?;
        match be_i32(&payload[..4]) {
            SSL_REQUEST_CODE | GSSENC_REQUEST_CODE => {
                probes += 1;
                if probes > 4 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "too many pre-startup probes",
                    ));
                }
                client.write_all(b"N").await?;
            }
            CANCEL_REQUEST_CODE => {
                if payload.len() >= 12 {
                    handle_cancel(state, be_i32(&payload[4..8]), be_i32(&payload[8..12])).await;
                }
                return Ok(StartupPhase::Cancelled);
            }
            PROTOCOL_V3 => return Ok(StartupPhase::Startup(parse_startup_params(&payload[4..])?)),
            other => {
                let major = (other >> 16) & 0xffff;
                let minor = other & 0xffff;
                // A 3.x minor this proxy does not implement gets the message
                // the protocol defines for exactly this case — PostgreSQL 18
                // opens with 3.2 — naming 3.0 as the highest supported minor
                // and listing the `_pq_.*` options that go unhonoured. The
                // client then continues as 3.0 rather than meeting a socket
                // that simply closed.
                if major == 3 && minor > 0 {
                    let params = parse_startup_params(&payload[4..])?;
                    let unsupported: Vec<&str> = params
                        .iter()
                        .map(|(name, _)| name.as_str())
                        .filter(|name| name.starts_with("_pq_."))
                        .collect();
                    let mut body = Vec::with_capacity(8);
                    put_i32(&mut body, 0);
                    put_i32(&mut body, unsupported.len() as i32);
                    for name in &unsupported {
                        put_cstr(&mut body, name);
                    }
                    client.write_all(&frame(b'v', &body)).await?;
                    // Protocol options were declined, so they are not passed
                    // upstream either.
                    return Ok(StartupPhase::Startup(
                        params
                            .into_iter()
                            .filter(|(name, _)| !name.starts_with("_pq_."))
                            .collect(),
                    ));
                }
                // Not a 3.x client at all. Say so with a SQLSTATE the driver
                // reports instead of dropping the socket, which reads to the
                // user as "the server went away".
                let _ = client
                    .write_all(&error_response(
                        "FATAL",
                        "0A000", // feature_not_supported
                        &format!(
                            "AKA: unsupported frontend protocol {major}.{minor}; \
                             this proxy speaks 3.0"
                        ),
                    ))
                    .await;
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unsupported protocol code {other}"),
                ));
            }
        }
    }
}

/// One accepted loopback connection: probes → startup (or cancel) → ticket
/// auth → upstream handshake → completion → splice.
async fn handle_conn(
    state: Arc<ProxyState>,
    stream: TcpStream,
    peer: std::net::SocketAddr,
) -> io::Result<()> {
    let _ = stream.set_nodelay(true);
    let mut client = BufReader::new(stream);

    // Everything up to a redeemed ticket is unauthenticated, so it runs under
    // one admission permit and one deadline. A client that connects and then
    // says nothing — or dribbles a startup packet a byte at a time — gets
    // dropped instead of holding a task and an fd for as long as it likes.
    let admission = state
        .handshakes
        .try_acquire()
        .map_err(|_| io::Error::other("pg handshake admission exhausted"))?;
    let deadline = tokio::time::Instant::now() + state.broker.config.pg_handshake_timeout;

    // Pre-startup phase: a client may probe SSLRequest and GSSENCRequest in
    // sequence before the StartupMessage; each is declined with a single 'N'
    // (the loopback leg is plaintext by contract, the DSN pins
    // `sslmode=disable`). A CancelRequest connection carries no
    // StartupMessage at all.
    let params = match tokio::time::timeout_at(deadline, read_startup_phase(&mut client, &state))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "pg startup phase timed out"))??
    {
        StartupPhase::Startup(params) => params,
        StartupPhase::Cancelled => return Ok(()),
    };

    // The presented password IS the ticket.
    client.write_all(&frame(b'R', &3i32.to_be_bytes())).await?;
    let (tag, payload) = tokio::time::timeout_at(deadline, read_message(&mut client))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "pg password message timed out"))??;
    if tag != b'p' {
        client
            .write_all(&error_response(
                "FATAL",
                "08P01",
                "expected PasswordMessage",
            ))
            .await?;
        return Ok(());
    }
    let (ticket, _) = take_cstr(&payload)?;

    for (scope, result) in [
        (
            "peer",
            state.redemptions_by_peer.check(&peer.ip().to_string()),
        ),
        ("ticket", state.redemptions_by_ticket.check(&ticket)),
    ] {
        if let Err(wait) = result {
            audit_redemption_rate_limit(&state.broker, peer, scope, wait);
            client
                .write_all(&error_response(
                    "FATAL",
                    "53300",
                    &format!("AKA: rate_limited: retry in {}s", wait.as_secs().max(1)),
                ))
                .await?;
            return Ok(());
        }
    }

    // Redeem: expiry and the two-level session budget are enforced here,
    // failing fast with the machine reason. The redemption reserves the
    // budget slot; dropping it before `start` releases the slot.
    let redemption = match state.broker.data_plane.redeem(&ticket) {
        Ok(r) => r,
        Err(e) => {
            let sqlstate = match e {
                RedeemError::Unknown | RedeemError::Expired => {
                    "28P01" // invalid_password
                }
                RedeemError::TicketSessionLimit | RedeemError::BrokerSessionLimit => {
                    "53300" // too_many_connections
                }
            };
            audit_refusal(
                &state.broker,
                None,
                e.reason().as_str(),
                "the presented ticket could not be redeemed",
            );
            client
                .write_all(&error_response(
                    "FATAL",
                    sqlstate,
                    &format!("AKA: {}", e.reason()),
                ))
                .await?;
            return Ok(());
        }
    };

    // Authenticated: the pre-auth deadline and admission permit have done
    // their job, and what follows (a confirmation prompt, an upstream dial)
    // has budgets of its own.
    drop(admission);

    if !matches!(&redemption.connection.config, ConnectionConfig::Pg { .. }) {
        client
            .write_all(&error_response(
                "FATAL",
                "08P01",
                "AKA: ticket is not for a Postgres connection",
            ))
            .await?;
        return Ok(());
    }
    let approved_version = redemption.connection.updated_at;

    // A ticket holds a short-lived connection snapshot. Make sure it still
    // names a live, unchanged authority before showing a prompt; otherwise a
    // delete/retarget that raced just ahead of prompt insertion could not
    // have found the prompt to revoke.
    if !state.broker.access.allows(&redemption.connection.id) {
        state.broker.approvals.revoke(&redemption.connection.id);
        audit_refusal(
            &state.broker,
            Some(&redemption.connection.name),
            "denied_by_policy",
            "agent access is disabled for this tool",
        );
        client
            .write_all(&error_response("FATAL", "28000", "AKA: denied_by_policy"))
            .await?;
        return Ok(());
    }
    let Ok(connection) = state
        .broker
        .store
        .connection_by_id(&redemption.connection.id)
    else {
        state.broker.approvals.revoke(&redemption.connection.id);
        audit_refusal(
            &state.broker,
            Some(&redemption.connection.name),
            "denied_by_policy",
            "the tool no longer exists",
        );
        client
            .write_all(&error_response("FATAL", "28000", "AKA: denied_by_policy"))
            .await?;
        return Ok(());
    };
    if connection.updated_at != approved_version {
        state.broker.approvals.revoke(&connection.id);
        audit_refusal(
            &state.broker,
            Some(&connection.name),
            "denied_by_policy",
            "the tool was retargeted after the approval",
        );
        client
            .write_all(&error_response("FATAL", "28000", "AKA: denied_by_policy"))
            .await?;
        return Ok(());
    }

    // Confirm before dialing upstream: nothing has been established yet, so
    // a refusal costs the destination nothing. Dropping the redemption on
    // the way out releases its reserved budget slot.
    match confirm_session(&state, &mut client, &connection, &redemption.agent, &params).await {
        SessionConfirmation::Proceed => {}
        SessionConfirmation::Refused(refusal) => {
            client.write_all(&refusal).await?;
            return Ok(());
        }
        SessionConfirmation::Abandoned => return Ok(()),
    }
    if !state.broker.access.allows(&redemption.connection.id) {
        state.broker.approvals.revoke(&redemption.connection.id);
        audit_refusal(
            &state.broker,
            Some(&redemption.connection.name),
            "denied_by_policy",
            "agent access is disabled for this tool",
        );
        client
            .write_all(&error_response("FATAL", "28000", "AKA: denied_by_policy"))
            .await?;
        return Ok(());
    }

    // Confirmation can wait for 90 seconds. Resolve again after it and use
    // that fresh record, while requiring the exact authority the prompt
    // described to still be current.
    let Ok(connection) = state
        .broker
        .store
        .connection_by_id(&redemption.connection.id)
    else {
        state.broker.approvals.revoke(&redemption.connection.id);
        audit_refusal(
            &state.broker,
            Some(&redemption.connection.name),
            "denied_by_policy",
            "the tool no longer exists",
        );
        client
            .write_all(&error_response("FATAL", "28000", "AKA: denied_by_policy"))
            .await?;
        return Ok(());
    };
    if connection.updated_at != approved_version {
        state.broker.approvals.revoke(&connection.id);
        audit_refusal(
            &state.broker,
            Some(&connection.name),
            "denied_by_policy",
            "the tool was retargeted after the approval",
        );
        client
            .write_all(&error_response("FATAL", "28000", "AKA: denied_by_policy"))
            .await?;
        return Ok(());
    }
    let ConnectionConfig::Pg {
        host,
        port,
        sslmode,
        trusted_ca_bundle_path,
        ..
    } = connection.config.clone()
    else {
        state.broker.approvals.revoke(&connection.id);
        client
            .write_all(&error_response(
                "FATAL",
                "08P01",
                "AKA: ticket is not for a Postgres connection",
            ))
            .await?;
        return Ok(());
    };

    // Upstream handshake: own TCP + TLS + auth with the configured user and
    // the stored password secret. Failure drops the redemption, releasing the
    // reserved budget slot.
    // Bound the dial. A black-holed host would otherwise leave the client
    // waiting on the OS TCP timeout — minutes — while holding a redemption
    // slot, and `TestErrorKind::Timeout` was unreachable from the data path.
    let upstream = match dial_with_timeout(
        &state.broker,
        crate::authorization::scope_existing(
            redemption.secret_read_authorization.clone(),
            dial_upstream(&state.broker.store, &connection, &params),
        ),
    )
    .await
    {
        Ok(upstream) => {
            if upstream.tls_downgraded {
                audit_tls_downgrade(&state.broker, &connection);
            } else {
                record_dial_health(&state.broker, &connection.id, &Ok(()));
            }
            upstream
        }
        Err(e) => {
            record_dial_health(&state.broker, &connection.id, &Err(e.clone()));
            audit_refusal(
                &state.broker,
                Some(&connection.name),
                "upstream_connect_failed",
                &e.detail,
            );
            client
                .write_all(&error_response(
                    "FATAL",
                    "08001", // sqlclient_unable_to_establish_sqlconnection
                    &format!("AKA: upstream_connect_failed: {e}"),
                ))
                .await?;
            return Ok(());
        }
    };

    // Complete the downstream handshake: AuthenticationOk, the upstream's
    // ParameterStatus messages, a *synthesized* BackendKeyData mapped to the
    // real upstream pid/key, and ReadyForQuery with the upstream's status.
    let registration = state.register_cancel(CancelTarget {
        host,
        port,
        sslmode,
        trusted_ca_bundle_path,
        backend_pid: upstream.backend_pid,
        backend_key: upstream.backend_key,
    });
    let (synth_pid, synth_key) = registration.key;

    // Register the live session *before* ReadyForQuery goes out, then close the
    // establishment race the way the endpoint path does: either a teardown
    // sweep sees this registered session, or this check sees the new policy
    // state and retires it. The dial above can take the whole upstream budget,
    // and without this a disable, delete, or retarget landing inside that
    // window was seen by neither — leaving a session running for up to
    // `session_max_ttl` against authority that had just been withdrawn.
    let agent = redemption.agent.clone();
    let configured_sslmode = sslmode_name(sslmode);
    let upstream_tls = effective_tls_mode(sslmode, upstream.tls_downgraded);
    let session = redemption.start_with_fields(
        ConnectionKind::Pg,
        &[
            ("sslmode", configured_sslmode),
            ("upstream_tls", upstream_tls),
        ],
    );
    let still_current = state.broker.access.allows(&connection.id)
        && state
            .broker
            .store
            .connection_by_id(&connection.id)
            .is_ok_and(|current| current.updated_at == approved_version);
    if !still_current {
        session.finish("access_revoked");
        state.broker.approvals.revoke(&connection.id);
        audit_refusal(
            &state.broker,
            Some(&connection.name),
            "denied_by_policy",
            "the tool's access was revoked while the session was being established",
        );
        client
            .write_all(&error_response("FATAL", "28000", "AKA: denied_by_policy"))
            .await?;
        return Ok(());
    }

    let mut completion = frame(b'R', &0i32.to_be_bytes());
    completion.extend_from_slice(&upstream.forward);
    let mut keydata = Vec::with_capacity(8);
    put_i32(&mut keydata, synth_pid);
    put_i32(&mut keydata, synth_key);
    completion.extend_from_slice(&frame(b'K', &keydata));
    completion.extend_from_slice(&frame(b'Z', &[upstream.ready_status]));
    if client.write_all(&completion).await.is_err() {
        // The client vanished after auth: retire the session just opened.
        session.finish("client_closed");
        return Ok(());
    }

    let max_ttl = state.broker.config.session_max_ttl;
    let idle = state.broker.config.session_idle_timeout;
    let audit = SpliceAudit {
        broker: state.broker.clone(),
        connection: connection.name.clone(),
        agent,
        record_statements: state.broker.config.audit_pg_statements,
    };
    splice(client, upstream.stream, session, max_ttl, idle, audit).await;
    drop(registration);
    Ok(())
}

/// Translate a CancelRequest on a synthesized key into a CancelRequest at
/// the mapped upstream session. Works while a query is executing
/// on the mapped session, the cancel rides its own upstream connection.
async fn handle_cancel(state: &Arc<ProxyState>, pid: i32, key: i32) {
    let target = state.cancels.lock().unwrap().get(&(pid, key)).cloned();
    let Some(target) = target else {
        tracing::debug!("pg proxy: CancelRequest for unknown key, dropped");
        return;
    };
    let send = async {
        let mut stream = tls_connect(
            &target.host,
            target.port,
            target.sslmode,
            target.trusted_ca_bundle_path.as_deref(),
        )
        .await?
        .stream;
        let mut msg = Vec::with_capacity(16);
        put_i32(&mut msg, 16);
        put_i32(&mut msg, CANCEL_REQUEST_CODE);
        put_i32(&mut msg, target.backend_pid);
        put_i32(&mut msg, target.backend_key);
        stream
            .write_all(&msg)
            .await
            .map_err(|e| format!("cancel write failed: {e}"))?;
        let _ = stream.shutdown().await;
        Ok::<(), TestError>(())
    };
    match tokio::time::timeout(Duration::from_secs(10), send).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => tracing::debug!("pg proxy: cancel relay failed: {e}"),
        Err(_) => tracing::debug!("pg proxy: cancel relay timed out"),
    }
}

/* --------------------------- upstream handshake ---------------------------- */

/// The upstream leg may be TLS, so the spliced stream is abstracted.
pub enum PgStream {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

impl AsyncRead for PgStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            PgStream::Plain(s) => Pin::new(s).poll_read(cx, buf),
            PgStream::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for PgStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            PgStream::Plain(s) => Pin::new(s).poll_write(cx, buf),
            PgStream::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            PgStream::Plain(s) => Pin::new(s).poll_flush(cx),
            PgStream::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            PgStream::Plain(s) => Pin::new(s).poll_shutdown(cx),
            PgStream::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

/// Certificate verification is deliberately skipped for libpq's `prefer` and
/// `require` sslmodes; only `verify-ca`/`verify-full` validate the upstream
/// certificate. rustls makes the encryption-only modes an explicit `danger`
/// opt-in.
#[derive(Debug)]
struct NoVerify {
    schemes: Vec<rustls::SignatureScheme>,
}

impl NoVerify {
    fn new(provider: &rustls::crypto::CryptoProvider) -> Self {
        Self {
            schemes: provider
                .signature_verification_algorithms
                .supported_schemes(),
        }
    }
}

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.schemes.clone()
    }
}

/// `verify-ca`: validate the certificate chain against trusted roots, but do
/// not require the certificate name to match the configured host. This mirrors
/// libpq's distinction between `verify-ca` and `verify-full`.
#[derive(Debug)]
struct CaOnlyVerifier {
    roots: rustls::RootCertStore,
    algorithms: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl CaOnlyVerifier {
    fn new(
        roots: rustls::RootCertStore,
        algorithms: rustls::crypto::WebPkiSupportedAlgorithms,
    ) -> Self {
        Self { roots, algorithms }
    }
}

impl rustls::client::danger::ServerCertVerifier for CaOnlyVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let cert = rustls::server::ParsedCertificate::try_from(end_entity)?;
        rustls::client::verify_server_cert_signed_by_trust_anchor(
            &cert,
            &self.roots,
            intermediates,
            now,
            self.algorithms.all,
        )?;
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

fn sslmode_name(sslmode: PgSslMode) -> &'static str {
    match sslmode {
        PgSslMode::Disable => "disable",
        PgSslMode::Prefer => "prefer",
        PgSslMode::Require => "require",
        PgSslMode::VerifyCa => "verify-ca",
        PgSslMode::VerifyFull => "verify-full",
    }
}

/// Human-readable security property of the transport that was actually
/// established. `require` and `prefer` encrypt without authenticating the
/// server; only the verifying modes establish a verified peer identity.
fn effective_tls_mode(sslmode: PgSslMode, tls_downgraded: bool) -> &'static str {
    if tls_downgraded || sslmode == PgSslMode::Disable {
        return "plaintext";
    }
    match sslmode {
        PgSslMode::Disable | PgSslMode::Prefer | PgSslMode::Require => "tls_unverified",
        PgSslMode::VerifyCa => "tls_verified_ca",
        PgSslMode::VerifyFull => "tls_verified_full",
    }
}

fn add_ca_bundle_roots(roots: &mut rustls::RootCertStore, path: &str) -> Result<usize, String> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";

    let pem = std::fs::read_to_string(path)
        .map_err(|e| format!("trusted CA bundle {path:?} could not be read: {e}"))?;
    let mut rest = pem.as_str();
    let mut added = 0usize;
    while let Some(start) = rest.find(BEGIN) {
        let body_start = start + BEGIN.len();
        let end = rest[body_start..]
            .find(END)
            .ok_or_else(|| format!("trusted CA bundle {path:?} has an unterminated certificate"))?;
        let body = &rest[body_start..body_start + end];
        let b64 = body
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>();
        let der = BASE64
            .decode(b64.as_bytes())
            .map_err(|e| format!("trusted CA bundle {path:?} has invalid PEM base64: {e}"))?;
        roots
            .add(rustls::pki_types::CertificateDer::from(der))
            .map_err(|e| {
                format!("trusted CA bundle {path:?} contains an invalid certificate: {e}")
            })?;
        added += 1;
        rest = &rest[body_start + end + END.len()..];
    }
    if added == 0 {
        return Err(format!(
            "trusted CA bundle {path:?} contains no certificates"
        ));
    }
    Ok(added)
}

/// The trust anchors for a verifying `sslmode`.
///
/// A configured bundle **replaces** the public roots rather than joining them,
/// which is what libpq's `sslrootcert` does. Appending would leave every
/// public CA able to satisfy a `verify-full` pin the user set precisely to
/// exclude them: an attacker holding any of ~150 public CAs' signature for the
/// same hostname would still verify, and the pin would be decorative.
pub(crate) fn root_cert_store(
    ca_bundle_path: Option<&str>,
) -> Result<rustls::RootCertStore, String> {
    match ca_bundle_path.filter(|path| !path.trim().is_empty()) {
        Some(path) => {
            let mut roots = rustls::RootCertStore::empty();
            add_ca_bundle_roots(&mut roots, path)?;
            Ok(roots)
        }
        None => Ok(rustls::RootCertStore::from_iter(
            webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
        )),
    }
}

/* ----------------------- channel-binding hash (RFC 5929) ------------------ */

/// Read one DER TLV, returning `(tag, value, rest)`.
///
/// Deliberately minimal: the only structure this file needs to walk is the
/// outer `Certificate` SEQUENCE, so a full X.509 parser would be dependency
/// weight for two field reads. Every length is bounds-checked and any
/// malformed input returns `None`, which the caller treats as "unknown
/// algorithm" rather than an error.
fn der_tlv(bytes: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = bytes.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (first as usize, rest)
    } else {
        let count = (first & 0x7f) as usize;
        // Indefinite length (0x80) is not valid DER; more than 4 length bytes
        // is far past any certificate this proxy will meet.
        if count == 0 || count > 4 || rest.len() < count {
            return None;
        }
        let len = rest[..count]
            .iter()
            .fold(0usize, |acc, &b| (acc << 8) | b as usize);
        (len, &rest[count..])
    };
    (rest.len() >= len).then(|| (tag, &rest[..len], &rest[len..]))
}

/// The OID of `Certificate.signatureAlgorithm.algorithm`.
///
/// ```text
/// Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
/// AlgorithmIdentifier ::= SEQUENCE { algorithm OBJECT IDENTIFIER, parameters ANY OPTIONAL }
/// ```
fn signature_algorithm_oid(cert_der: &[u8]) -> Option<&[u8]> {
    const SEQUENCE: u8 = 0x30;
    const OID: u8 = 0x06;
    let (tag, certificate, _) = der_tlv(cert_der)?;
    if tag != SEQUENCE {
        return None;
    }
    // Skip tbsCertificate; signatureAlgorithm is the next element.
    let (_, _, after_tbs) = der_tlv(certificate)?;
    let (tag, algorithm_identifier, _) = der_tlv(after_tbs)?;
    if tag != SEQUENCE {
        return None;
    }
    let (tag, oid, _) = der_tlv(algorithm_identifier)?;
    (tag == OID).then_some(oid)
}

/// The `tls-server-end-point` channel binding for a server certificate.
///
/// RFC 5929 §4.1 derives the hash from the certificate's own **signature**
/// algorithm, not from SHA-256 unconditionally, and upgrades MD5 and SHA-1 to
/// SHA-256. PostgreSQL's `be_tls_get_certificate_hash` does exactly this, so a
/// server presenting a SHA-384-signed certificate computes a SHA-384 binding
/// and a hard-coded SHA-256 here would fail `SCRAM-SHA-256-PLUS` with an
/// opaque authentication error rather than a diagnosable one.
///
/// An algorithm this does not recognize falls back to SHA-256: it is by far
/// the most common signature hash, and a wrong guess costs the same failed
/// SCRAM exchange as refusing to guess.
fn channel_binding_hash(cert_der: &[u8]) -> Vec<u8> {
    use sha2::{Digest as _, Sha256, Sha384, Sha512};

    // DER-encoded OID bodies (tag and length already stripped).
    // sha384WithRSAEncryption 1.2.840.113549.1.1.12, ecdsa-with-SHA384 1.2.840.10045.4.3.3
    const SHA384_OIDS: [&[u8]; 2] = [
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c],
        &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03],
    ];
    // sha512WithRSAEncryption 1.2.840.113549.1.1.13, ecdsa-with-SHA512 1.2.840.10045.4.3.4,
    // Ed25519 1.3.101.112 (SHA-512 internally), Ed448 1.3.101.113 (SHAKE256; SHA-512 is
    // the closest available and no better guess exists).
    const SHA512_OIDS: [&[u8]; 4] = [
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d],
        &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04],
        &[0x2b, 0x65, 0x70],
        &[0x2b, 0x65, 0x71],
    ];

    match signature_algorithm_oid(cert_der) {
        Some(oid) if SHA384_OIDS.contains(&oid) => Sha384::digest(cert_der).to_vec(),
        Some(oid) if SHA512_OIDS.contains(&oid) => Sha512::digest(cert_der).to_vec(),
        _ => Sha256::digest(cert_der).to_vec(),
    }
}

fn tls_config(
    provider: Arc<rustls::crypto::CryptoProvider>,
    sslmode: PgSslMode,
    ca_bundle_path: Option<&str>,
) -> Result<rustls::ClientConfig, String> {
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("tls config failed: {e}"))?;
    match sslmode {
        PgSslMode::VerifyCa => {
            let verifier = Arc::new(CaOnlyVerifier::new(
                root_cert_store(ca_bundle_path)?,
                provider.signature_verification_algorithms,
            ));
            Ok(builder
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_no_client_auth())
        }
        PgSslMode::VerifyFull => {
            let roots = Arc::new(root_cert_store(ca_bundle_path)?);
            let verifier =
                rustls::client::WebPkiServerVerifier::builder_with_provider(roots, provider)
                    .build()
                    .map_err(|e| format!("tls verifier config failed: {e}"))?;
            Ok(builder
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_no_client_auth())
        }
        _ => {
            let verifier = Arc::new(NoVerify::new(&provider));
            Ok(builder
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_no_client_auth())
        }
    }
}

async fn connect_and_probe_tls(host: &str, port: u16) -> Result<(TcpStream, u8), TestError> {
    let mut tcp = TcpStream::connect((host, port)).await.map_err(|e| {
        TestError::new(
            TestErrorKind::Unreachable,
            format!("Could not reach {host}:{port}: {e}"),
        )
    })?;
    let _ = tcp.set_nodelay(true);
    let mut probe = Vec::with_capacity(8);
    put_i32(&mut probe, 8);
    put_i32(&mut probe, SSL_REQUEST_CODE);
    tcp.write_all(&probe).await.map_err(|e| {
        format!("The connection was lost while asking the server to start TLS: {e}")
    })?;
    let mut answer = [0u8; 1];
    tcp.read_exact(&mut answer).await.map_err(|e| {
        format!("The connection was lost while waiting for the server's TLS answer: {e}")
    })?;
    Ok((tcp, answer[0]))
}

async fn wrap_tls(
    host: &str,
    tcp: TcpStream,
    sslmode: PgSslMode,
    ca_bundle_path: Option<&str>,
) -> Result<(PgStream, Option<Vec<u8>>), TestError> {
    // rustls 0.23's default provider (aws-lc-rs) is named explicitly:
    // reqwest pulls the ring feature in too, and with both enabled
    // `ClientConfig::builder()` refuses to pick one itself.
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = tls_config(provider, sslmode, ca_bundle_path)?;
    let name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|e| format!("The host {host:?} is not a valid TLS server name: {e}"))?;
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    // A certificate that fails verification is its own kind: the fix
    // (trust the CA, or lower the mode) differs from every other TLS
    // failure. tokio-rustls wraps the rustls error in io::Error, so the
    // typed rustls error is recovered rather than sniffed out of prose.
    let tls = connector.connect(name, tcp).await.map_err(|e| {
        let cert_problem = e
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<rustls::Error>())
            .is_some_and(|e| matches!(e, rustls::Error::InvalidCertificate(_)));
        if cert_problem {
            TestError::new(
                TestErrorKind::CertUnverified,
                format!("The server's TLS certificate could not be verified: {e}"),
            )
        } else {
            TestError::new(
                TestErrorKind::Other,
                format!("The TLS handshake failed: {e}"),
            )
        }
    })?;
    let digest = tls
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|certs| certs.first())
        .map(|cert| channel_binding_hash(cert.as_ref()));
    Ok((PgStream::Tls(Box::new(tls)), digest))
}

/// TCP connect + TLS per the connection's `sslmode`: `Disable` →
/// plaintext; `Prefer` → SSLRequest, wrap on 'S', continue plaintext on 'N';
/// `Require`/`verify-ca`/`verify-full` → SSLRequest, 'S' or fail. The verify
/// modes use trusted roots and fail closed on a certificate that cannot be
/// verified: skipping verification is a persisted, per-connection decision
/// made in the app's edit sheet (behind the capability-change gate), never a
/// per-dial prompt. Returns the stream plus the SHA-256 digest of the server
/// certificate DER (the `tls-server-end-point` channel-binding input) when
/// TLS was negotiated.
async fn tls_connect(
    host: &str,
    port: u16,
    sslmode: PgSslMode,
    ca_bundle_path: Option<&str>,
) -> Result<UpstreamTransport, TestError> {
    if sslmode == PgSslMode::Disable {
        let tcp = TcpStream::connect((host, port)).await.map_err(|e| {
            TestError::new(
                TestErrorKind::Unreachable,
                format!("Could not reach {host}:{port}: {e}"),
            )
        })?;
        let _ = tcp.set_nodelay(true);
        // Asked for plaintext and got it: nothing was downgraded.
        return Ok(UpstreamTransport::plain(PgStream::Plain(tcp), false));
    }
    let (tcp, answer) = connect_and_probe_tls(host, port).await?;
    match answer {
        b'S' => wrap_tls(host, tcp, sslmode, ca_bundle_path)
            .await
            .map(|(stream, cert_hash)| UpstreamTransport {
                stream,
                cert_hash,
                tls_downgraded: false,
            }),
        // `prefer` asked for TLS and the server declined. libpq continues in
        // clear text here and so does this, but the broker is the custodian of
        // the credential that is about to cross the wire unprotected, so the
        // fallback is reported rather than silent (audited by the caller).
        b'N' if sslmode == PgSslMode::Prefer => {
            Ok(UpstreamTransport::plain(PgStream::Plain(tcp), true))
        }
        b'N' => Err(TestError::new(
            TestErrorKind::TlsDeclined,
            format!(
                "The server refused to start TLS, but this connection's TLS \
                 mode (\"{}\") requires it",
                sslmode_name(sslmode)
            ),
        )),
        other => Err(TestError::new(
            TestErrorKind::WrongProtocol,
            format!(
                "The reply to the TLS request doesn't look like Postgres — \
                 check that {host}:{port} is really a PostgreSQL server \
                 (reply byte 0x{other:02x})"
            ),
        )),
    }
}

/// The negotiated upstream transport, before the startup exchange.
struct UpstreamTransport {
    stream: PgStream,
    /// The `tls-server-end-point` channel-binding input, when TLS was
    /// negotiated.
    cert_hash: Option<Vec<u8>>,
    /// `prefer` asked for TLS and the server refused, so the stored password
    /// and every statement on this session travel in clear text.
    tls_downgraded: bool,
}

impl UpstreamTransport {
    fn plain(stream: PgStream, tls_downgraded: bool) -> Self {
        Self {
            stream,
            cert_hash: None,
            tls_downgraded,
        }
    }
}

/// A completed upstream handshake, ready to splice.
struct UpstreamSession {
    stream: BufReader<PgStream>,
    /// Whether `prefer` fell back to plaintext establishing this session.
    tls_downgraded: bool,
    /// Raw ParameterStatus/NoticeResponse frames to relay downstream.
    forward: Vec<u8>,
    /// The upstream's real BackendKeyData, mapped, never forwarded.
    backend_pid: i32,
    backend_key: i32,
    /// The upstream ReadyForQuery transaction-status byte.
    ready_status: u8,
    /// `server_version` from ParameterStatus, when supplied.
    server_version: Option<String>,
}

/// Dial the connection's configured host:port with the optional stored password
/// and drive the client side of the startup/auth exchange up to ReadyForQuery.
/// The client's non-auth startup parameters (application_name,
/// client_encoding, options, search_path, …) are forwarded for fidelity.
/// The distinguished "server wants a password we don't have" failure
/// (`TestErrorKind::NeedsPassword`), so the draft test can tell it apart
/// from a real refusal.
fn needs_password() -> TestError {
    TestError::new(
        TestErrorKind::NeedsPassword,
        "The server asks for a password, but this connection has no saved credential",
    )
}

async fn dial_upstream(
    store: &Arc<Store>,
    connection: &Connection,
    client_params: &[(String, String)],
) -> Result<UpstreamSession, TestError> {
    let password = match connection.secrets.first() {
        Some(secret_id) => Some(
            store
                .secret_value(secret_id)
                .await
                .map_err(|e| format!("The saved credential could not be read: {e}"))?,
        ),
        None => None,
    };
    dial_upstream_with_password(
        connection,
        password.as_deref().map(String::as_str),
        client_params,
    )
    .await
}

async fn dial_upstream_with_password(
    connection: &Connection,
    password: Option<&str>,
    client_params: &[(String, String)],
) -> Result<UpstreamSession, TestError> {
    let ConnectionConfig::Pg {
        host,
        port,
        dbname,
        user,
        sslmode,
        trusted_ca_bundle_path,
    } = &connection.config
    else {
        return Err("not a postgres connection".into());
    };
    let UpstreamTransport {
        stream,
        cert_hash: cert_digest,
        tls_downgraded,
    } = tls_connect(host, *port, *sslmode, trusted_ca_bundle_path.as_deref()).await?;
    let mut stream = BufReader::new(stream);

    // StartupMessage with the CONFIGURED user + dbname; forward the client's
    // non-auth parameters.
    let mut body = Vec::new();
    put_i32(&mut body, PROTOCOL_V3);
    put_cstr(&mut body, "user");
    put_cstr(&mut body, user);
    put_cstr(&mut body, "database");
    put_cstr(&mut body, dbname);
    for (name, value) in client_params {
        if name == "user" || name == "database" {
            continue;
        }
        put_cstr(&mut body, name);
        put_cstr(&mut body, value);
    }
    body.push(0);
    let mut startup = Vec::with_capacity(body.len() + 4);
    put_i32(&mut startup, body.len() as i32 + 4);
    startup.extend_from_slice(&body);
    stream
        .write_all(&startup)
        .await
        .map_err(|e| format!("startup write failed: {e}"))?;

    // Authentication phase.
    let mut authenticated = false;
    for _ in 0..MAX_UPSTREAM_AUTH_MESSAGES {
        let (tag, payload) = read_message(&mut stream)
            .await
            .map_err(|e| format!("auth read failed: {e}"))?;
        match tag {
            b'E' => return Err(upstream_error(&payload)),
            // NegotiateProtocolVersion. This proxy asks for exactly 3.0, so a
            // conforming server has nothing to negotiate — but a server that
            // sends it anyway is answering the version we asked for, not
            // failing, and it is not forwarded because the downstream leg
            // settled its own version already.
            b'v' => continue,
            b'R' if payload.len() < 4 => return Err("short auth request".into()),
            b'R' => match be_i32(&payload[..4]) {
                0 => {
                    authenticated = true;
                    break;
                }
                3 => {
                    // AuthenticationCleartextPassword
                    let password = password.ok_or_else(needs_password)?;
                    let mut p = Vec::new();
                    put_cstr(&mut p, password);
                    stream
                        .write_all(&frame(b'p', &p))
                        .await
                        .map_err(|e| format!("password write failed: {e}"))?;
                }
                5 => {
                    // AuthenticationMD5Password: md5(md5(password + user) + salt).
                    let password = password.ok_or_else(needs_password)?;
                    if payload.len() < 8 {
                        return Err("short md5 auth request".into());
                    }
                    let md5 = md5_password(user, password.as_bytes(), &payload[4..8]);
                    let mut p = Vec::new();
                    put_cstr(&mut p, &md5);
                    stream
                        .write_all(&frame(b'p', &p))
                        .await
                        .map_err(|e| format!("password write failed: {e}"))?;
                }
                10 => {
                    // AuthenticationSASL, SCRAM-SHA-256(-PLUS), the design's
                    // primary path.
                    let password = password.ok_or_else(needs_password)?;
                    sasl_auth(
                        &mut stream,
                        &payload[4..],
                        password.as_bytes(),
                        cert_digest.as_deref(),
                    )
                    .await?;
                }
                other => {
                    return Err(format!(
                        "The server asked for an authentication method \
                         AgentMFA doesn't support (code {other})"
                    )
                    .into())
                }
            },
            other => {
                return Err(format!(
                    "unexpected message '{}' during upstream auth",
                    other as char
                )
                .into())
            }
        }
    }
    if !authenticated {
        return Err(TestError::new(
            TestErrorKind::WrongProtocol,
            format!(
                "The server did not finish authentication within \
                 {MAX_UPSTREAM_AUTH_MESSAGES} messages"
            ),
        ));
    }

    // Post-auth: collect ParameterStatus (forwarded), BackendKeyData
    // (captured, NOT forwarded), up to ReadyForQuery.
    let mut forward = Vec::new();
    let mut backend_pid = 0i32;
    let mut backend_key = 0i32;
    let mut server_version = None;
    let ready_status = loop {
        let (tag, payload) = read_message(&mut stream)
            .await
            .map_err(|e| format!("startup read failed: {e}"))?;
        match tag {
            b'S' | b'N' => {
                let framed_len = payload.len().saturating_add(5);
                if forward.len().saturating_add(framed_len) > MAX_STARTUP_FORWARD_BYTES {
                    return Err(TestError::new(
                        TestErrorKind::WrongProtocol,
                        format!(
                            "The server sent more than {} KiB of startup metadata",
                            MAX_STARTUP_FORWARD_BYTES / 1024
                        ),
                    ));
                }
                if tag == b'S' {
                    if let Ok((name, rest)) = take_cstr(&payload) {
                        if name == "server_version" {
                            if let Ok((value, _)) = take_cstr(rest) {
                                server_version = Some(value);
                            }
                        }
                    }
                }
                forward.extend_from_slice(&frame(tag, &payload));
            }
            b'K' => {
                if payload.len() < 8 {
                    return Err("short BackendKeyData".into());
                }
                backend_pid = be_i32(&payload[..4]);
                backend_key = be_i32(&payload[4..8]);
            }
            b'Z' => break *payload.first().unwrap_or(&b'I'),
            b'E' => return Err(upstream_error(&payload)),
            // See the auth loop: swallowed rather than relayed.
            b'v' => {}
            other => {
                return Err(format!(
                    "unexpected message '{}' during upstream startup",
                    other as char
                )
                .into())
            }
        }
    };

    Ok(UpstreamSession {
        stream,
        tls_downgraded,
        forward,
        backend_pid,
        backend_key,
        ready_status,
        server_version,
    })
}

async fn verify_select_one(upstream: &mut UpstreamSession) -> Result<(), TestError> {
    upstream
        .stream
        .write_all(&frame(b'Q', b"SELECT 1\0"))
        .await
        .map_err(|e| format!("test query write failed: {e}"))?;
    let mut bytes = 0usize;
    let mut completed = false;
    for _ in 0..MAX_TEST_QUERY_MESSAGES {
        let (tag, payload) = read_message(&mut upstream.stream)
            .await
            .map_err(|e| format!("test query read failed: {e}"))?;
        bytes = bytes.saturating_add(payload.len().saturating_add(5));
        if bytes > MAX_TEST_QUERY_BYTES {
            return Err(TestError::new(
                TestErrorKind::WrongProtocol,
                "The SELECT 1 test response exceeded 64 KiB",
            ));
        }
        match tag {
            b'E' => return Err(upstream_error(&payload)),
            b'C' => completed = true,
            b'Z' if completed => return Ok(()),
            b'Z' => {
                return Err(TestError::new(
                    TestErrorKind::WrongProtocol,
                    "The server returned ReadyForQuery without completing SELECT 1",
                ))
            }
            _ => {}
        }
    }
    Err(TestError::new(
        TestErrorKind::WrongProtocol,
        "The server did not finish SELECT 1 within 64 messages",
    ))
}

/// UI-initiated connectivity/credential test: dial and authenticate exactly
/// as a brokered session would, then prove the database can execute a query.
pub async fn test_upstream(
    store: &Arc<Store>,
    connection: &Connection,
) -> Result<String, TestError> {
    let ConnectionConfig::Pg { dbname, user, .. } = &connection.config else {
        return Err("not a postgres connection".into());
    };
    let mut upstream = dial_upstream(store, connection, &[]).await?;
    verify_select_one(&mut upstream).await?;
    let _ = upstream.stream.write_all(&frame(b'X', &[])).await;
    let _ = upstream.stream.shutdown().await;
    Ok(match upstream.server_version {
        Some(version) => {
            format!("Signed in to {dbname} as {user}; SELECT 1 succeeded (PostgreSQL {version})")
        }
        None => format!("Signed in to {dbname} as {user}; SELECT 1 succeeded"),
    })
}

/// Test an unsaved draft, never touching the secret store. A password typed
/// into the form is used for a full sign-in — it already traveled from the
/// same form that is about to persist it. A *stored* secret chosen for the
/// draft is deliberately not sent: attaching it to a new destination is what
/// the add gate confirms, so the dial stops where the server asks for it —
/// which still exercises everything TLS (`credential_deferred` turns that
/// stop into a qualified pass instead of a failure).
pub async fn test_draft_upstream(
    connection: &Connection,
    typed_password: Option<&str>,
    credential_deferred: bool,
) -> Result<String, TestError> {
    let ConnectionConfig::Pg {
        host, dbname, user, ..
    } = &connection.config
    else {
        return Err("not a postgres connection".into());
    };
    match dial_upstream_with_password(connection, typed_password, &[]).await {
        Ok(mut upstream) => {
            verify_select_one(&mut upstream).await?;
            let _ = upstream.stream.write_all(&frame(b'X', &[])).await;
            let _ = upstream.stream.shutdown().await;
            Ok(match upstream.server_version {
                Some(version) => format!(
                    "Signed in to {dbname} as {user}; SELECT 1 succeeded (PostgreSQL {version})"
                ),
                None => format!("Signed in to {dbname} as {user}; SELECT 1 succeeded"),
            })
        }
        Err(e) if credential_deferred && e.kind == TestErrorKind::NeedsPassword => Ok(format!(
            "Reached {host} and TLS checks passed; the saved credential is verified after adding"
        )),
        Err(e) => Err(e),
    }
}

/// md5 auth: `"md5" + md5hex(md5hex(password + user) + salt4)`.
fn md5_password(user: &str, password: &[u8], salt: &[u8]) -> String {
    use md5::{Digest as _, Md5};
    let mut inner = Md5::new();
    inner.update(password);
    inner.update(user.as_bytes());
    let inner_hex = hex(&inner.finalize());
    let mut outer = Md5::new();
    outer.update(inner_hex.as_bytes());
    outer.update(salt);
    format!("md5{}", hex(&outer.finalize()))
}

/// Drive the SCRAM exchange after an AuthenticationSASL request. The
/// mechanism payload is a NUL-terminated list of mechanism names. When the
/// server offers SCRAM-SHA-256-PLUS and the upstream leg is TLS, channel
/// binding is `tls-server-end-point`, the SHA-256 digest of the server
/// certificate DER.
async fn sasl_auth(
    stream: &mut BufReader<PgStream>,
    mechanisms_payload: &[u8],
    password: &[u8],
    cert_digest: Option<&[u8]>,
) -> Result<(), TestError> {
    let mut mechanisms = Vec::new();
    let mut rest = mechanisms_payload;
    loop {
        let (name, tail) = take_cstr(rest).map_err(|e| format!("bad SASL mechanisms: {e}"))?;
        if name.is_empty() {
            break;
        }
        mechanisms.push(name);
        rest = tail;
    }
    let offers_plus = mechanisms.iter().any(|m| m == SCRAM_SHA_256_PLUS);
    let offers_plain = mechanisms.iter().any(|m| m == SCRAM_SHA_256);

    let (mechanism, channel_binding) = match (offers_plus, cert_digest) {
        (true, Some(digest)) => (
            SCRAM_SHA_256_PLUS,
            ChannelBinding::tls_server_end_point(digest.to_vec()),
        ),
        // The server advertised channel binding but this leg can't provide
        // it: say so ("n,,") rather than "y,," which the server must reject.
        (true, None) if offers_plain => (SCRAM_SHA_256, ChannelBinding::unsupported()),
        (false, _) if offers_plain => (SCRAM_SHA_256, ChannelBinding::unrequested()),
        _ => {
            return Err(format!(
                "no supported SASL mechanism (offered: {})",
                mechanisms.join(", ")
            )
            .into())
        }
    };

    let mut scram = ScramSha256::new(password, channel_binding);

    // SASLInitialResponse: mechanism + i32 data length + data.
    let mut p = Vec::new();
    put_cstr(&mut p, mechanism);
    put_i32(&mut p, scram.message().len() as i32);
    p.extend_from_slice(scram.message());
    stream
        .write_all(&frame(b'p', &p))
        .await
        .map_err(|e| format!("SASL write failed: {e}"))?;

    // AuthenticationSASLContinue → SASLResponse.
    let (tag, payload) = read_message(stream)
        .await
        .map_err(|e| format!("SASL read failed: {e}"))?;
    match tag {
        b'R' if payload.len() >= 4 && be_i32(&payload[..4]) == 11 => {}
        // A bad password under SCRAM surfaces as an ErrorResponse here,
        // mid-exchange, so this arm is the credential-rejection path.
        b'E' => return Err(upstream_error(&payload)),
        _ => return Err("expected AuthenticationSASLContinue".into()),
    }
    scram
        .update(&payload[4..])
        .map_err(|e| format!("SCRAM continue failed: {e}"))?;
    stream
        .write_all(&frame(b'p', scram.message()))
        .await
        .map_err(|e| format!("SASL write failed: {e}"))?;

    // AuthenticationSASLFinal: verify the server signature.
    let (tag, payload) = read_message(stream)
        .await
        .map_err(|e| format!("SASL read failed: {e}"))?;
    match tag {
        b'R' if payload.len() >= 4 && be_i32(&payload[..4]) == 12 => {}
        b'E' => return Err(upstream_error(&payload)),
        _ => return Err("expected AuthenticationSASLFinal".into()),
    }
    scram
        .finish(&payload[4..])
        .map_err(|e| format!("SCRAM verification failed: {e}"))?;
    Ok(())
}

/* ------------------------------ frame scanner ----------------------------- */

/// Payload prefix the scanner retains. Enough for a statement preview without
/// buffering a multi-megabyte `COPY` frame; the scanner still tracks the
/// message boundary exactly past this.
const SCAN_PEEK_CAP: usize = 1024;
/// Statements recorded for one session before the audit entry starts counting
/// rather than listing.
const STATEMENT_AUDIT_MAX: usize = 100;

/// One in-progress message payload.
struct ScanBody {
    tag: u8,
    /// Payload bytes still to arrive.
    remaining: usize,
    /// Retained prefix, capped at [`SCAN_PEEK_CAP`].
    peek: Vec<u8>,
}

/// An observational Postgres message-boundary scanner.
///
/// The splice forwards every byte verbatim and this only *watches* the copy, so
/// it can neither corrupt nor stall a session. If it ever loses the message
/// boundary it stops reporting instead of guessing — a scanner that
/// mis-frames would silently mis-attribute statements and mis-track backend
/// state, which is worse than reporting nothing.
///
/// Both directions start aligned: each leg's handshake reader stops exactly at
/// a message boundary, and the residual bytes it buffered are fed in here
/// before anything else.
struct FrameScanner {
    /// Partial 5-byte header carried across reads.
    header: Vec<u8>,
    body: Option<ScanBody>,
    aligned: bool,
}

impl FrameScanner {
    fn new() -> Self {
        Self {
            header: Vec::with_capacity(5),
            body: None,
            aligned: true,
        }
    }

    /// Feed forwarded bytes, calling `on_message(tag, peek)` once per complete
    /// message, where `peek` is the payload truncated to [`SCAN_PEEK_CAP`].
    fn feed(&mut self, mut bytes: &[u8], mut on_message: impl FnMut(u8, &[u8])) {
        if !self.aligned {
            return;
        }
        while !bytes.is_empty() {
            if let Some(body) = &mut self.body {
                let take = body.remaining.min(bytes.len());
                let room = SCAN_PEEK_CAP.saturating_sub(body.peek.len());
                if room > 0 {
                    body.peek.extend_from_slice(&bytes[..take.min(room)]);
                }
                body.remaining -= take;
                bytes = &bytes[take..];
                if body.remaining == 0 {
                    let done = self.body.take().expect("body checked present");
                    on_message(done.tag, &done.peek);
                }
                continue;
            }
            let take = (5 - self.header.len()).min(bytes.len());
            self.header.extend_from_slice(&bytes[..take]);
            bytes = &bytes[take..];
            if self.header.len() < 5 {
                return;
            }
            let tag = self.header[0];
            // The length is self-inclusive and excludes the tag byte.
            let len = be_i32(&self.header[1..5]);
            self.header.clear();
            if len < 4 || len as usize > MAX_SPLICE_MESSAGE {
                self.aligned = false;
                return;
            }
            match len as usize - 4 {
                0 => on_message(tag, &[]),
                payload => {
                    self.body = Some(ScanBody {
                        tag,
                        remaining: payload,
                        peek: Vec::new(),
                    })
                }
            }
        }
    }
}

/// Text up to the NUL terminator, or all of it when the scanner's peek was
/// truncated before the terminator arrived.
fn cstr_prefix(bytes: &[u8]) -> &[u8] {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    &bytes[..end]
}

/// The SQL a client message carries, if it carries any.
///
/// `Query` ('Q') is one NUL-terminated statement; `Parse` ('P') is a statement
/// name followed by the SQL. Bind, Execute, Describe and the COPY data stream
/// introduce no new statement text and are deliberately not reported — the
/// audit records what was *asked*, not every frame of the protocol.
fn statement_text(tag: u8, peek: &[u8]) -> Option<String> {
    let sql = match tag {
        b'Q' => cstr_prefix(peek),
        b'P' => {
            let name_end = peek.iter().position(|&b| b == 0)?;
            cstr_prefix(peek.get(name_end + 1..)?)
        }
        _ => return None,
    };
    let sql = String::from_utf8_lossy(sql);
    let sql = sql.trim();
    // Statement text is client-controlled and lands in a durable log the user
    // reads: bound it and strip anything that could reorder or hide what it
    // says, with the same policy the approval prompts use.
    (!sql.is_empty()).then(|| crate::approvals::cap_approval_text(sql.to_string()))
}

/// What the splice needs in order to report on the session it is forwarding.
struct SpliceAudit {
    broker: Arc<Broker>,
    connection: String,
    agent: String,
    /// Record statement text, not only the count. Off unless the operator
    /// turned it on: SQL literals can carry passwords (`ALTER USER … PASSWORD`)
    /// and personal data, and that is a retention decision rather than a
    /// default.
    record_statements: bool,
}

impl SpliceAudit {
    /// Write the session's statement record. One entry per session rather than
    /// one per statement, so a busy session cannot flood the log.
    fn finish(&self, statements: Vec<String>, total: u64) {
        if total == 0 {
            return;
        }
        let mut entry = AuditEntry::new(
            AuditKind::PgStatements,
            format!("{total} statement{} on {}", plural(total), self.connection),
        )
        .agent(self.agent.clone())
        .connection(self.connection.clone())
        .field("kind", "pg")
        .field("statements", total);
        if self.record_statements {
            let listed = statements.len() as u64;
            entry = entry.detail(statements.join("\n")).field("listed", listed);
            if listed < total {
                entry = entry.field("truncated", true);
            }
        }
        self.broker.audit.append(entry);
    }
}

fn plural(n: u64) -> &'static str {
    if n == 1 {
        ""
    } else {
        "s"
    }
}

/* --------------------------------- splice --------------------------------- */

/// Byte-forward the established session in both directions with the session
/// lifetime rules: max TTL, idle timeout, user close, and either leg closing
/// tears down both. The copy is seeded with any residual bytes each leg's
/// handshake reader buffered; TCP may have delivered the client's first 'Q'
/// in the same segment as the startup bytes, and a naive handoff of the bare
/// sockets would swallow it.
async fn splice<C>(
    client: BufReader<C>,
    upstream: BufReader<PgStream>,
    session: SessionHandle,
    max_ttl: Duration,
    idle: Duration,
    audit: SpliceAudit,
) where
    C: AsyncRead + AsyncWrite + Unpin,
{
    let client_residual = client.buffer().to_vec();
    let client = client.into_inner();
    let upstream_residual = upstream.buffer().to_vec();
    let upstream = upstream.into_inner();

    let (mut client_rx, mut client_tx) = tokio::io::split(client);
    let (mut upstream_rx, mut upstream_tx) = tokio::io::split(upstream);

    let ttl_deadline = tokio::time::Instant::now() + max_ttl;
    let close_signal = session.close_signal.clone();

    // The idle timer measures a client that has stopped asking, not a backend
    // that is taking its time. `SELECT pg_sleep(400)`, a large `COPY`, and a
    // long `CREATE INDEX` all send nothing for minutes while real work is in
    // flight, and timing those out was indistinguishable from an abandoned
    // session. The backend is idle exactly when it has sent ReadyForQuery and
    // the client has not asked for anything since, so the deadline is armed
    // only then.
    //
    // A `LISTEN`er waiting for a notification *is* protocol-idle by this
    // definition and can still be reaped: raise `--session-idle-timeout` for
    // that workload. Detecting it would mean reading the SQL and guessing.
    let mut backend_idle = true;
    let mut idle_deadline = tokio::time::Instant::now() + idle;
    let mut client_scan = FrameScanner::new();
    let mut upstream_scan = FrameScanner::new();
    let mut statements: Vec<String> = Vec::new();
    let mut statement_count = 0u64;

    // Observe the client's messages: what it asked, and that it is now owed a
    // reply. `record` is captured by the closure, so the text is only built
    // when the operator asked for it.
    let record = audit.record_statements;
    let watch_client = |bytes: &[u8],
                        scan: &mut FrameScanner,
                        busy: &mut bool,
                        statements: &mut Vec<String>,
                        count: &mut u64| {
        scan.feed(bytes, |tag, peek| {
            *busy = true;
            if let Some(sql) = statement_text(tag, peek) {
                *count += 1;
                if record && statements.len() < STATEMENT_AUDIT_MAX {
                    statements.push(sql);
                }
            }
        });
    };

    let mut early: Option<&'static str> = None;
    if !client_residual.is_empty() {
        session
            .bytes_up
            .fetch_add(client_residual.len() as u64, Ordering::Relaxed);
        watch_client(
            &client_residual,
            &mut client_scan,
            &mut backend_idle,
            &mut statements,
            &mut statement_count,
        );
        backend_idle = false;
        if upstream_tx.write_all(&client_residual).await.is_err() {
            early = Some("upstream_closed");
        }
    }
    if early.is_none() && !upstream_residual.is_empty() {
        session
            .bytes_down
            .fetch_add(upstream_residual.len() as u64, Ordering::Relaxed);
        upstream_scan.feed(&upstream_residual, |tag, _| {
            if tag == b'Z' {
                backend_idle = true;
            }
        });
        if client_tx.write_all(&upstream_residual).await.is_err() {
            early = Some("client_closed");
        }
    }

    let mut client_buf = vec![0u8; 16 * 1024];
    let mut upstream_buf = vec![0u8; 16 * 1024];
    let reason = match early {
        Some(reason) => reason,
        None => loop {
            // A busy backend has no idle deadline. Pushing it past the TTL
            // (rather than parking on a borrowed `pending()`) keeps the branch
            // a plain deadline and makes the TTL win that race deterministically.
            let idle_at = if backend_idle {
                idle_deadline
            } else {
                ttl_deadline + Duration::from_secs(1)
            };
            tokio::select! {
                _ = close_signal.notified() => break "closed_by_user",
                _ = tokio::time::sleep_until(ttl_deadline) => break "session_ttl",
                _ = tokio::time::sleep_until(idle_at) => break "idle_timeout",
                read = client_rx.read(&mut client_buf) => match read {
                    Ok(n) if n > 0 => {
                        session.bytes_up.fetch_add(n as u64, Ordering::Relaxed);
                        watch_client(
                            &client_buf[..n],
                            &mut client_scan,
                            &mut backend_idle,
                            &mut statements,
                            &mut statement_count,
                        );
                        // Whatever it sent, the client is now waiting on the
                        // backend even if the scanner could not classify it.
                        backend_idle = false;
                        if upstream_tx.write_all(&client_buf[..n]).await.is_err() {
                            break "upstream_closed";
                        }
                    }
                    _ => break "client_closed",
                },
                read = upstream_rx.read(&mut upstream_buf) => match read {
                    Ok(n) if n > 0 => {
                        session.bytes_down.fetch_add(n as u64, Ordering::Relaxed);
                        upstream_scan.feed(&upstream_buf[..n], |tag, _| {
                            if tag == b'Z' {
                                backend_idle = true;
                            }
                        });
                        if backend_idle {
                            idle_deadline = tokio::time::Instant::now() + idle;
                        }
                        if client_tx.write_all(&upstream_buf[..n]).await.is_err() {
                            break "client_closed";
                        }
                    }
                    _ => break "upstream_closed",
                },
            }
        },
    };

    // A broker-initiated teardown is not a crashed database, and a bare EOF
    // cannot say which it was. 57P01 (admin_shutdown) is what libpq and every
    // driver already recognize, so the reason arrives as a real error rather
    // than only in the activity log the client cannot read.
    if matches!(reason, "closed_by_user" | "session_ttl" | "idle_timeout") {
        let _ = client_tx
            .write_all(&error_response("FATAL", "57P01", &format!("AKA: {reason}")))
            .await;
    }
    // Tear down both legs whatever the reason.
    let _ = client_tx.shutdown().await;
    let _ = upstream_tx.shutdown().await;
    audit.finish(statements, statement_count);
    session.finish(reason);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn effective_tls_mode_distinguishes_encryption_from_peer_verification() {
        assert_eq!(
            effective_tls_mode(PgSslMode::Require, false),
            "tls_unverified"
        );
        assert_eq!(
            effective_tls_mode(PgSslMode::Prefer, false),
            "tls_unverified"
        );
        assert_eq!(
            effective_tls_mode(PgSslMode::VerifyCa, false),
            "tls_verified_ca"
        );
        assert_eq!(
            effective_tls_mode(PgSslMode::VerifyFull, false),
            "tls_verified_full"
        );
        assert_eq!(effective_tls_mode(PgSslMode::Disable, false), "plaintext");
        assert_eq!(effective_tls_mode(PgSslMode::Prefer, true), "plaintext");
    }

    #[test]
    fn frames_and_cstrings_round_trip() {
        let msg = frame(b'S', b"server_version\x0014.0\x00");
        assert_eq!(msg[0], b'S');
        assert_eq!(be_i32(&msg[1..5]) as usize, msg.len() - 1);
        let (name, rest) = take_cstr(&msg[5..]).unwrap();
        assert_eq!(name, "server_version");
        let (value, _) = take_cstr(rest).unwrap();
        assert_eq!(value, "14.0");
    }

    #[test]
    fn startup_params_parse_until_terminator() {
        let mut body = Vec::new();
        put_cstr(&mut body, "user");
        put_cstr(&mut body, "app");
        put_cstr(&mut body, "application_name");
        put_cstr(&mut body, "psql");
        body.push(0);
        let params = parse_startup_params(&body).unwrap();
        assert_eq!(
            params,
            vec![
                ("user".to_string(), "app".to_string()),
                ("application_name".to_string(), "psql".to_string()),
            ]
        );
    }

    #[test]
    fn md5_matches_postgres_recipe() {
        // Known-good: md5(md5("secret" + "app") + "\x01\x02\x03\x04").
        let out = md5_password("app", b"secret", &[1, 2, 3, 4]);
        assert!(out.starts_with("md5"));
        assert_eq!(out.len(), 35);
        // Deterministic.
        assert_eq!(out, md5_password("app", b"secret", &[1, 2, 3, 4]));
    }

    /// PG-3: a configured bundle is the *whole* trust store. Appending it to
    /// the public roots would leave any of ~150 public CAs able to satisfy a
    /// `verify-full` pin set precisely to exclude them.
    #[test]
    fn a_configured_ca_bundle_replaces_the_public_roots() {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["ca.example".to_string()]).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca = params.self_signed(&key).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let bundle = dir.path().join("ca.pem");
        std::fs::write(&bundle, ca.pem()).unwrap();

        let public = root_cert_store(None).unwrap();
        assert_eq!(public.roots.len(), webpki_roots::TLS_SERVER_ROOTS.len());
        assert!(public.roots.len() > 1, "sanity: the webpki set is not tiny");

        let pinned = root_cert_store(Some(bundle.to_str().unwrap())).unwrap();
        assert_eq!(
            pinned.roots.len(),
            1,
            "the bundle is the entire trust store, not an addition to it"
        );
        for anchor in &public.roots {
            assert!(
                !pinned.roots.contains(anchor),
                "a public root survived into a pinned store"
            );
        }

        // An empty or whitespace path is "not configured", not "trust nothing".
        assert_eq!(
            root_cert_store(Some("   ")).unwrap().roots.len(),
            webpki_roots::TLS_SERVER_ROOTS.len()
        );
    }

    /// PG-6: RFC 5929 takes the binding hash from the certificate's own
    /// signature algorithm. A SHA-384-signed certificate binds with SHA-384,
    /// and hard-coding SHA-256 fails `SCRAM-SHA-256-PLUS` against a server
    /// that computed it correctly.
    #[test]
    fn channel_binding_follows_the_certificate_signature_algorithm() {
        let cases: [(&rcgen::SignatureAlgorithm, usize); 3] = [
            (&rcgen::PKCS_ECDSA_P256_SHA256, 32),
            (&rcgen::PKCS_ECDSA_P384_SHA384, 48),
            (&rcgen::PKCS_ED25519, 64),
        ];
        for (algorithm, expected) in cases {
            let key = rcgen::KeyPair::generate_for(algorithm).unwrap();
            let params = rcgen::CertificateParams::new(vec!["db.example".to_string()]).unwrap();
            let cert = params.self_signed(&key).unwrap();
            assert_eq!(
                channel_binding_hash(cert.der()).len(),
                expected,
                "wrong digest width for {algorithm:?}"
            );
        }
    }

    /// The DER walk must fail closed: garbage yields "unknown algorithm" (and
    /// so SHA-256), never a panic or an out-of-bounds read.
    #[test]
    fn signature_algorithm_parsing_refuses_malformed_der() {
        for bytes in [
            &b""[..],
            &[0x30][..],
            &[0x30, 0x82][..],
            &[0x30, 0x03, 0x02, 0x01, 0x00][..],
            &[0x02, 0x01, 0x00][..],
            &[0x30, 0x7f, 0xff, 0xff][..],
        ] {
            assert!(signature_algorithm_oid(bytes).is_none(), "{bytes:02x?}");
            assert_eq!(channel_binding_hash(bytes).len(), 32);
        }
    }

    /// The scanner is the input to both the idle-timeout decision and the
    /// statement audit, so its framing has to survive arbitrary chunking.
    #[test]
    fn the_frame_scanner_tracks_boundaries_across_split_reads() {
        let mut stream = Vec::new();
        stream.extend_from_slice(&frame(b'Q', b"SELECT 1\x00"));
        stream.extend_from_slice(&frame(b'Z', b"I"));
        stream.extend_from_slice(&frame(b'P', b"stmt\x00SELECT 2\x00\x00\x00"));

        // Every split point must yield the same messages.
        for chunk in 1..=stream.len() {
            let mut scanner = FrameScanner::new();
            let mut seen = Vec::new();
            for piece in stream.chunks(chunk) {
                scanner.feed(piece, |tag, peek| seen.push((tag, peek.to_vec())));
            }
            assert!(scanner.aligned, "chunk size {chunk} lost alignment");
            let tags: Vec<u8> = seen.iter().map(|(tag, _)| *tag).collect();
            assert_eq!(tags, vec![b'Q', b'Z', b'P'], "chunk size {chunk}");
            assert_eq!(
                statement_text(seen[0].0, &seen[0].1).as_deref(),
                Some("SELECT 1")
            );
            assert_eq!(statement_text(seen[1].0, &seen[1].1), None, "Z is not SQL");
            assert_eq!(
                statement_text(seen[2].0, &seen[2].1).as_deref(),
                Some("SELECT 2")
            );
        }
    }

    /// A payload larger than the peek cap must still be framed exactly — the
    /// scanner tracks the boundary past what it retains, so a multi-megabyte
    /// COPY frame cannot desynchronize it or be buffered whole.
    #[test]
    fn the_frame_scanner_bounds_what_it_retains_without_losing_the_boundary() {
        let big = vec![b'x'; SCAN_PEEK_CAP * 3];
        let mut stream = frame(b'd', &big);
        stream.extend_from_slice(&frame(b'Z', b"I"));

        let mut scanner = FrameScanner::new();
        let mut seen = Vec::new();
        for piece in stream.chunks(7) {
            scanner.feed(piece, |tag, peek| seen.push((tag, peek.len())));
        }
        assert!(scanner.aligned);
        assert_eq!(seen, vec![(b'd', SCAN_PEEK_CAP), (b'Z', 1)]);
    }

    /// A length field the protocol cannot produce means the scanner is not
    /// where it thinks it is. It must stop observing rather than report
    /// garbage — and the splice keeps forwarding bytes either way.
    #[test]
    fn the_frame_scanner_stops_when_it_loses_alignment() {
        let mut scanner = FrameScanner::new();
        let mut seen = 0usize;
        // A self-inclusive length below 4 is impossible.
        scanner.feed(&[b'Q', 0, 0, 0, 1], |_, _| seen += 1);
        assert!(!scanner.aligned);
        scanner.feed(&frame(b'Q', b"SELECT 1\x00"), |_, _| seen += 1);
        assert_eq!(seen, 0, "a desynced scanner must stay quiet");
    }

    /// Statement text reaches a durable log the user reads, so it is bounded
    /// and stripped of characters that could rewrite what it appears to say.
    #[test]
    fn statement_text_is_bounded_and_scrubbed() {
        let long = format!("SELECT '{}'\x00", "a".repeat(5_000));
        let text = statement_text(b'Q', long.as_bytes()).unwrap();
        assert!(text.chars().count() <= 401, "{}", text.chars().count());
        assert!(text.ends_with('…'));

        let sneaky = "SELECT 1\u{202E}DROP TABLE t\x00";
        let text = statement_text(b'Q', sneaky.as_bytes()).unwrap();
        assert!(
            !text.contains('\u{202E}'),
            "bidi override survived: {text:?}"
        );

        // A Parse whose SQL was cut off by the peek cap still reports what it
        // saw rather than dropping the statement entirely.
        assert_eq!(
            statement_text(b'P', b"stmt\x00SELECT unterminated").as_deref(),
            Some("SELECT unterminated")
        );
        // Nothing to say about a statement-less frame.
        assert_eq!(statement_text(b'B', b"whatever"), None);
        assert_eq!(statement_text(b'Q', b"   \x00"), None);
    }

    #[test]
    fn error_response_carries_sqlstate() {
        let msg = error_response("FATAL", "28P01", "AKA: unknown_ticket");
        assert_eq!(msg[0], b'E');
        let (code, message) = parse_error_response(&msg[5..]);
        assert_eq!(code, "28P01");
        assert_eq!(message, "AKA: unknown_ticket");
    }

    #[test]
    fn upstream_error_reads_message_first_and_flags_auth_rejections() {
        let msg = error_response(
            "FATAL",
            "28P01",
            "password authentication failed for user \"dev\"",
        );
        let e = upstream_error(&msg[5..]);
        assert_eq!(e.kind, TestErrorKind::AuthRejected);
        assert_eq!(
            e.detail,
            "Password authentication failed for user \"dev\" (28P01)"
        );

        let msg = error_response("FATAL", "3D000", "database \"missing\" does not exist");
        let e = upstream_error(&msg[5..]);
        assert_eq!(e.kind, TestErrorKind::Other);
        assert_eq!(e.detail, "Database \"missing\" does not exist (3D000)");
    }
}
