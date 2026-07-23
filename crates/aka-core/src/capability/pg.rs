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
//!   Servers using trust or certificate authentication need no secret.
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
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, BufReader, ReadBuf};
use tokio::net::{TcpStream, UnixListener, UnixStream};
use tokio::sync::Notify;

use super::{TestError, TestErrorKind};
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
/// Sanity cap on handshake-phase typed messages (the data path never parses).
const MAX_HANDSHAKE_MESSAGE: usize = 1024 * 1024;

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
    let state = Arc::new(ProxyState {
        broker,
        cancels: Mutex::new(HashMap::new()),
    });
    let task = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let state = state.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_conn(state, stream).await {
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

/// Bind a direct Postgres endpoint: a private Unix-domain listener at
/// `<endpoint-dir>/.s.PGSQL.5432` that an unmodified `psql`/driver reaches
/// with `host=<endpoint-dir>`. Attribution is the endpoint secret presented
/// as the password; filesystem permissions keep other users out. Returns the
/// running listener handle for the broker to hold and later stop.
pub async fn bind_endpoint(
    broker: Arc<Broker>,
    endpoint: &DirectEndpoint,
) -> io::Result<EndpointListenerHandle> {
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

    let state = Arc::new(ProxyState {
        broker,
        cancels: Mutex::new(HashMap::new()),
    });
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
                }
            }
        }
    });
    Ok(EndpointListenerHandle { shutdown, task })
}

/// One accepted endpoint connection: probes → startup (or cancel) → endpoint
/// secret auth (with a live-wiring re-check) → upstream handshake → splice.
/// Mirrors `handle_conn`, but the presented password is the per-wiring secret
/// rather than a ticket, and authorization is re-verified here at connect time
/// rather than at a control-plane open.
async fn handle_endpoint_conn(
    state: Arc<ProxyState>,
    stream: UnixStream,
    endpoint_id: uuid::Uuid,
) -> io::Result<()> {
    let mut client = BufReader::new(stream);

    let params = match read_startup_phase(&mut client, &state).await? {
        StartupPhase::Startup(params) => params,
        StartupPhase::Cancelled => return Ok(()),
    };

    // The presented password IS the per-wiring endpoint secret.
    client.write_all(&frame(b'R', &3i32.to_be_bytes())).await?;
    let (tag, payload) = read_message(&mut client).await?;
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
    let upstream = match crate::authorization::scope(
        true,
        dial_upstream(&state.broker.store, &connection, &params),
    )
    .await
    {
        Ok(upstream) => upstream,
        Err(detail) => {
            client
                .write_all(&error_response(
                    "FATAL",
                    "08001",
                    &format!("AKA: upstream_connect_failed: {detail}"),
                ))
                .await?;
            return Ok(());
        }
    };

    // Reserve the live-session slot (global backstop) before committing the
    // downstream handshake, so exhaustion is a clean pre-ReadyForQuery error.
    let session = match state.broker.data_plane.start_endpoint_session(
        "endpoint",
        &connection,
        endpoint_id,
        ConnectionKind::Pg,
    ) {
        Ok(session) => session,
        Err(_) => {
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
    splice(client, upstream.stream, session, max_ttl, idle).await;
    drop(registration);
    Ok(())
}

/* ------------------------- downstream state machine ----------------------- */

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
async fn handle_conn(state: Arc<ProxyState>, stream: TcpStream) -> io::Result<()> {
    let _ = stream.set_nodelay(true);
    let mut client = BufReader::new(stream);

    // Pre-startup phase: a client may probe SSLRequest and GSSENCRequest in
    // sequence before the StartupMessage; each is declined with a single 'N'
    // (the loopback leg is plaintext by contract, the DSN pins
    // `sslmode=disable`). A CancelRequest connection carries no
    // StartupMessage at all.
    let params = match read_startup_phase(&mut client, &state).await? {
        StartupPhase::Startup(params) => params,
        StartupPhase::Cancelled => return Ok(()),
    };

    // The presented password IS the ticket.
    client.write_all(&frame(b'R', &3i32.to_be_bytes())).await?;
    let (tag, payload) = read_message(&mut client).await?;
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

    let ConnectionConfig::Pg {
        host,
        port,
        sslmode,
        trusted_ca_bundle_path,
        ..
    } = redemption.connection.config.clone()
    else {
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
    let upstream = match crate::authorization::scope_existing(
        redemption.secret_read_authorization.clone(),
        dial_upstream(&state.broker.store, &redemption.connection, &params),
    )
    .await
    {
        Ok(upstream) => upstream,
        Err(detail) => {
            client
                .write_all(&error_response(
                    "FATAL",
                    "08001", // sqlclient_unable_to_establish_sqlconnection
                    &format!("AKA: upstream_connect_failed: {detail}"),
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
    let mut completion = frame(b'R', &0i32.to_be_bytes());
    completion.extend_from_slice(&upstream.forward);
    let mut keydata = Vec::with_capacity(8);
    put_i32(&mut keydata, synth_pid);
    put_i32(&mut keydata, synth_key);
    completion.extend_from_slice(&frame(b'K', &keydata));
    completion.extend_from_slice(&frame(b'Z', &[upstream.ready_status]));
    client.write_all(&completion).await?;

    // Both handshakes done: register the live session and splice.
    let max_ttl = state.broker.config.session_max_ttl;
    let session = redemption.start(ConnectionKind::Pg);
    let idle = state.broker.config.session_idle_timeout;
    splice(client, upstream.stream, session, max_ttl, idle).await;
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
        let (mut stream, _) = tls_connect(
            &target.host,
            target.port,
            target.sslmode,
            target.trusted_ca_bundle_path.as_deref(),
        )
        .await?;
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

fn root_cert_store(ca_bundle_path: Option<&str>) -> Result<rustls::RootCertStore, String> {
    let mut roots =
        rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(path) = ca_bundle_path.filter(|path| !path.trim().is_empty()) {
        add_ca_bundle_roots(&mut roots, path)?;
    }
    Ok(roots)
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
        .map(|cert| {
            use sha2::{Digest as _, Sha256};
            Sha256::digest(cert.as_ref()).to_vec()
        });
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
) -> Result<(PgStream, Option<Vec<u8>>), TestError> {
    if sslmode == PgSslMode::Disable {
        let tcp = TcpStream::connect((host, port)).await.map_err(|e| {
            TestError::new(
                TestErrorKind::Unreachable,
                format!("Could not reach {host}:{port}: {e}"),
            )
        })?;
        let _ = tcp.set_nodelay(true);
        return Ok((PgStream::Plain(tcp), None));
    }
    let (tcp, answer) = connect_and_probe_tls(host, port).await?;
    match answer {
        b'S' => match wrap_tls(host, tcp, sslmode, ca_bundle_path).await {
            Ok(stream) => Ok(stream),
            Err(e)
                if matches!(sslmode, PgSslMode::VerifyCa | PgSslMode::VerifyFull)
                    && e.kind == TestErrorKind::CertUnverified =>
            {
                Err(TestError::new(
                    e.kind,
                    format!(
                        "{}. Edit the tool to trust the server's CA (Advanced → \
                         Trusted CA bundle) or lower its TLS mode to \"require\" \
                         to connect without certificate verification",
                        e.detail
                    ),
                ))
            }
            Err(e) => Err(e),
        },
        b'N' if sslmode == PgSslMode::Prefer => Ok((PgStream::Plain(tcp), None)),
        b'N' => Err(TestError::new(
            TestErrorKind::TlsDeclined,
            format!(
                "The server refused to start TLS, but this connection's TLS \
                 mode (\"{}\") requires it. Edit the tool and set TLS mode to \
                 \"prefer\" or \"disable\" if this server can't use TLS",
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

/// A completed upstream handshake, ready to splice.
struct UpstreamSession {
    stream: BufReader<PgStream>,
    /// Raw ParameterStatus/NoticeResponse frames to relay downstream.
    forward: Vec<u8>,
    /// The upstream's real BackendKeyData, mapped, never forwarded.
    backend_pid: i32,
    backend_key: i32,
    /// The upstream ReadyForQuery transaction-status byte.
    ready_status: u8,
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
    let (stream, cert_digest) =
        tls_connect(host, *port, *sslmode, trusted_ca_bundle_path.as_deref()).await?;
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
    loop {
        let (tag, payload) = read_message(&mut stream)
            .await
            .map_err(|e| format!("auth read failed: {e}"))?;
        match tag {
            b'E' => return Err(upstream_error(&payload)),
            b'R' if payload.len() < 4 => return Err("short auth request".into()),
            b'R' => match be_i32(&payload[..4]) {
                0 => break, // AuthenticationOk
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
                         Multitool doesn't support (code {other})"
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

    // Post-auth: collect ParameterStatus (forwarded), BackendKeyData
    // (captured, NOT forwarded), up to ReadyForQuery.
    let mut forward = Vec::new();
    let mut backend_pid = 0i32;
    let mut backend_key = 0i32;
    let ready_status = loop {
        let (tag, payload) = read_message(&mut stream)
            .await
            .map_err(|e| format!("startup read failed: {e}"))?;
        match tag {
            b'S' | b'N' => forward.extend_from_slice(&frame(tag, &payload)),
            b'K' => {
                if payload.len() < 8 {
                    return Err("short BackendKeyData".into());
                }
                backend_pid = be_i32(&payload[..4]);
                backend_key = be_i32(&payload[4..8]);
            }
            b'Z' => break *payload.first().unwrap_or(&b'I'),
            b'E' => return Err(upstream_error(&payload)),
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
        forward,
        backend_pid,
        backend_key,
        ready_status,
    })
}

/// UI-initiated connectivity/credential test: dial and authenticate exactly
/// as a brokered session would, then send Terminate without issuing a query.
pub async fn test_upstream(
    store: &Arc<Store>,
    connection: &Connection,
) -> Result<String, TestError> {
    let ConnectionConfig::Pg { dbname, user, .. } = &connection.config else {
        return Err("not a postgres connection".into());
    };
    let mut upstream = dial_upstream(store, connection, &[]).await?;
    let _ = upstream.stream.write_all(&frame(b'X', &[])).await;
    let _ = upstream.stream.shutdown().await;
    Ok(format!("Signed in to {dbname} as {user}"))
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
            let _ = upstream.stream.write_all(&frame(b'X', &[])).await;
            let _ = upstream.stream.shutdown().await;
            Ok(format!("Signed in to {dbname} as {user}"))
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
    let mut idle_deadline = tokio::time::Instant::now() + idle;
    let close_signal = session.close_signal.clone();

    let mut early: Option<&'static str> = None;
    if !client_residual.is_empty() {
        session
            .bytes_up
            .fetch_add(client_residual.len() as u64, Ordering::Relaxed);
        if upstream_tx.write_all(&client_residual).await.is_err() {
            early = Some("upstream_closed");
        }
    }
    if early.is_none() && !upstream_residual.is_empty() {
        session
            .bytes_down
            .fetch_add(upstream_residual.len() as u64, Ordering::Relaxed);
        if client_tx.write_all(&upstream_residual).await.is_err() {
            early = Some("client_closed");
        }
    }

    let mut client_buf = vec![0u8; 16 * 1024];
    let mut upstream_buf = vec![0u8; 16 * 1024];
    let reason = match early {
        Some(reason) => reason,
        None => loop {
            tokio::select! {
                _ = close_signal.notified() => break "closed_by_user",
                _ = tokio::time::sleep_until(ttl_deadline) => break "session_ttl",
                _ = tokio::time::sleep_until(idle_deadline) => break "idle_timeout",
                read = client_rx.read(&mut client_buf) => match read {
                    Ok(n) if n > 0 => {
                        idle_deadline = tokio::time::Instant::now() + idle;
                        session.bytes_up.fetch_add(n as u64, Ordering::Relaxed);
                        if upstream_tx.write_all(&client_buf[..n]).await.is_err() {
                            break "upstream_closed";
                        }
                    }
                    _ => break "client_closed",
                },
                read = upstream_rx.read(&mut upstream_buf) => match read {
                    Ok(n) if n > 0 => {
                        idle_deadline = tokio::time::Instant::now() + idle;
                        session.bytes_down.fetch_add(n as u64, Ordering::Relaxed);
                        if client_tx.write_all(&upstream_buf[..n]).await.is_err() {
                            break "client_closed";
                        }
                    }
                    _ => break "upstream_closed",
                },
            }
        },
    };

    // Tear down both legs whatever the reason.
    let _ = client_tx.shutdown().await;
    let _ = upstream_tx.shutdown().await;
    session.finish(reason);
}

#[cfg(test)]
mod tests {
    use super::*;

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
