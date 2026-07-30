//! A local ssh-agent socket that authenticates to a broker endpoint on the
//! caller's behalf.
//!
//! An SSH direct endpoint with `require_auth` set refuses to list identities
//! or sign until the connection has sent `authenticate@agentmfa.dev` carrying
//! the endpoint secret. Stock `ssh` cannot send an agent extension, so without
//! this forwarder an authenticated endpoint would be unusable by the very
//! clients endpoints exist for.
//!
//! So: bind a private socket this process owns, and for each client that
//! arrives, dial the endpoint, present the secret, and splice the two together
//! byte for byte. The forwarder adds no policy of its own — every request
//! still reaches the broker, which still asks the user. What it removes is the
//! one thing `ssh` cannot say.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{UnixListener, UnixStream};
use zeroize::Zeroizing;

/// The endpoint secret, shared by every in-flight connection and scrubbed once
/// the last of them is gone. Shared rather than cloned per connection so the
/// plaintext exists in exactly one allocation.
pub type EndpointSecret = Arc<Zeroizing<String>>;

/// `SSH_AGENTC_EXTENSION` (PROTOCOL.agent).
const SSH_AGENTC_EXTENSION: u8 = 27;
/// `SSH_AGENT_SUCCESS`.
const SSH_AGENT_SUCCESS: u8 = 6;
/// The extension the broker's endpoint sockets answer.
const AUTHENTICATE_EXTENSION: &str = "authenticate@agentmfa.dev";

/// Refuse to read a reply larger than any agent reply legitimately is. The
/// only frame this module reads itself is a one-byte status; the splice that
/// follows is opaque and unbounded.
const MAX_REPLY: u32 = 64 * 1024;

/// The forwarder's listening socket, unlinked on drop.
///
/// This socket is the un-authenticated capability the endpoint used to be: a
/// process that opens it signs through us. It is created 0600 — and, when we
/// chose the path, inside a 0700 directory of our own — so "same user" is the
/// boundary rather than "same machine".
pub struct AgentSocket {
    /// The directory to remove on drop — only when we created it.
    dir: Option<PathBuf>,
    path: PathBuf,
    listener: UnixListener,
}

impl AgentSocket {
    /// Bind a fresh socket under the system temp directory.
    pub fn bind() -> io::Result<Self> {
        use std::os::unix::fs::PermissionsExt as _;
        // The counter only distinguishes sockets within one process; the pid
        // is what keeps concurrent runs apart.
        static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let seq = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("mfa-ssh-agent-{}-{seq}", std::process::id()));
        // Fail rather than reuse: an existing directory at this path is either
        // a stale run whose socket would confuse `ssh`, or someone else's.
        std::fs::create_dir(&dir)?;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        let path = dir.join("agent.sock");
        let listener = bind_private(&path)?;
        Ok(Self {
            dir: Some(dir),
            path,
            listener,
        })
    }

    /// Bind at a path the caller chose.
    ///
    /// `IdentityAgent` needs a name that outlives one command, which a
    /// temp-directory socket keyed to a pid cannot be. The caller owns the
    /// directory, so this only creates (and later removes) the socket itself.
    pub fn bind_at(path: PathBuf) -> io::Result<Self> {
        // A file here is either a crashed run's leftover or a live forwarder.
        // Taking the path from a live one would silently break whatever is
        // using it, so probe before unlinking.
        if std::os::unix::net::UnixStream::connect(&path).is_ok() {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                format!("something is already serving {}", path.display()),
            ));
        }
        let listener = bind_private(&path)?;
        Ok(Self {
            dir: None,
            path,
            listener,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Serve until the future `until` resolves. Each accepted client gets its
    /// own upstream connection: the endpoint tracks authentication per
    /// connection, so sharing one upstream would let a second client ride the
    /// first one's proof.
    ///
    /// `secret` is `None` for an endpoint that requires no authentication —
    /// sending the extension there would draw EXTENSION_FAILURE and abort a
    /// connection the endpoint was perfectly willing to serve.
    pub async fn serve(
        &self,
        upstream: PathBuf,
        secret: Option<EndpointSecret>,
        until: impl std::future::Future,
    ) {
        tokio::pin!(until);
        loop {
            let client = tokio::select! {
                _ = &mut until => return,
                accepted = self.listener.accept() => match accepted {
                    Ok((client, _)) => client,
                    // A failed accept is per-connection (fd exhaustion, a
                    // client that left between poll and accept) and says
                    // nothing about the listener, so keep serving.
                    Err(error) => {
                        eprintln!("mfa ssh-agent: could not accept a client: {error}");
                        continue;
                    }
                },
            };
            let upstream = upstream.clone();
            let secret = secret.clone();
            tokio::spawn(async move {
                let secret = secret.as_ref().map(|secret| secret.as_str());
                if let Err(error) = forward(client, &upstream, secret).await {
                    // The agent protocol has no error channel, so a client
                    // sees only "Permission denied (publickey)". Saying why
                    // here is the only chance to name the real cause.
                    eprintln!("mfa ssh-agent: {error}");
                }
            });
        }
    }
}

impl Drop for AgentSocket {
    fn drop(&mut self) {
        // Best-effort: a leftover socket file would otherwise sit there
        // refusing connections, which reads as a broken agent rather than an
        // absent one.
        let _ = std::fs::remove_file(&self.path);
        if let Some(dir) = &self.dir {
            let _ = std::fs::remove_dir(dir);
        }
    }
}

/// Bind a socket only this user can open.
///
/// Staged and renamed, as the broker's own agent sockets are: binding puts a
/// world-accessible node on the filesystem for as long as it takes to chmod
/// it, and this socket is a signing capability for whoever gets in.
fn bind_private(path: &Path) -> io::Result<UnixListener> {
    use std::os::unix::fs::PermissionsExt as _;
    let staging = path.with_extension("binding");
    // Either name can be a crashed run's leftover; bind fails on an existing
    // path even when nothing is listening.
    let _ = std::fs::remove_file(&staging);
    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(&staging)?;
    if let Err(error) = std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o600)) {
        let _ = std::fs::remove_file(&staging);
        return Err(error);
    }
    if let Err(error) = std::fs::rename(&staging, path) {
        let _ = std::fs::remove_file(&staging);
        return Err(error);
    }
    Ok(listener)
}

/// Dial the endpoint, authenticate, then splice.
async fn forward(client: UnixStream, upstream: &Path, secret: Option<&str>) -> io::Result<()> {
    let mut server = UnixStream::connect(upstream).await.map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "could not reach the endpoint socket at {}: {error}",
                upstream.display()
            ),
        )
    })?;
    if let Some(secret) = secret {
        authenticate(&mut server, secret).await?;
    }
    let (mut client, mut server) = (client, server);
    // Both directions until either side hangs up, which is exactly what an
    // agent proxy is. Nothing here inspects the frames: the broker is the one
    // that decides, and re-deciding here would be a second policy to keep in
    // sync with it.
    tokio::io::copy_bidirectional(&mut client, &mut server)
        .await
        .map(|_| ())
}

/// Send `authenticate@agentmfa.dev` and require success.
async fn authenticate(server: &mut UnixStream, secret: &str) -> io::Result<()> {
    server.write_all(&authenticate_frame(secret)).await?;
    let kind = read_reply_kind(server).await?;
    if kind != SSH_AGENT_SUCCESS {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the endpoint refused this secret — reissue the endpoint \
             (`mfa conn endpoint <name> --issue`) if it was rotated",
        ));
    }
    Ok(())
}

/// `uint32 len | byte 27 | string name | string secret`.
///
/// Zeroized: this buffer holds the plaintext secret, and it is built once per
/// accepted client rather than once per process.
fn authenticate_frame(secret: &str) -> Zeroizing<Vec<u8>> {
    let mut payload = Zeroizing::new(Vec::new());
    put_string(&mut payload, AUTHENTICATE_EXTENSION.as_bytes());
    put_string(&mut payload, secret.as_bytes());
    let mut frame = Zeroizing::new(Vec::with_capacity(payload.len() + 5));
    frame.extend_from_slice(&((payload.len() + 1) as u32).to_be_bytes());
    frame.push(SSH_AGENTC_EXTENSION);
    frame.extend_from_slice(&payload);
    frame
}

fn put_string(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
}

/// Read one reply frame and return its type byte, discarding the body.
async fn read_reply_kind(server: &mut UnixStream) -> io::Result<u8> {
    let mut len = [0u8; 4];
    server.read_exact(&mut len).await.map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("the endpoint closed the connection without answering: {error}"),
        )
    })?;
    let len = u32::from_be_bytes(len);
    if len == 0 || len > MAX_REPLY {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("the endpoint answered with an implausible {len}-byte frame"),
        ));
    }
    let mut body = vec![0u8; len as usize];
    server.read_exact(&mut body).await?;
    Ok(body[0])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_authenticate_frame_is_a_well_formed_extension_request() {
        let frame = authenticate_frame("s3cret");
        let len = u32::from_be_bytes(frame[0..4].try_into().unwrap()) as usize;
        assert_eq!(len, frame.len() - 4, "the length prefix covers the rest");
        assert_eq!(frame[4], SSH_AGENTC_EXTENSION);
        let name_len = u32::from_be_bytes(frame[5..9].try_into().unwrap()) as usize;
        assert_eq!(&frame[9..9 + name_len], AUTHENTICATE_EXTENSION.as_bytes());
        let rest = &frame[9 + name_len..];
        let secret_len = u32::from_be_bytes(rest[0..4].try_into().unwrap()) as usize;
        assert_eq!(&rest[4..4 + secret_len], b"s3cret");
        assert_eq!(
            rest.len(),
            4 + secret_len,
            "nothing trails the secret — the broker rejects a payload with a tail"
        );
    }

    /// A serving endpoint that records what it was sent and answers with a
    /// fixed status, standing in for the broker's agent socket.
    async fn fake_endpoint(
        path: PathBuf,
        reply: u8,
    ) -> (
        tokio::task::JoinHandle<Vec<u8>>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        let listener = UnixListener::bind(&path).unwrap();
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
        let handle = tokio::spawn(async move {
            let mut seen = Vec::new();
            tokio::pin!(stop_rx);
            loop {
                let (mut stream, _) = tokio::select! {
                    _ = &mut stop_rx => return seen,
                    accepted = listener.accept() => accepted.unwrap(),
                };
                let mut len = [0u8; 4];
                if stream.read_exact(&mut len).await.is_err() {
                    continue;
                }
                let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
                stream.read_exact(&mut body).await.unwrap();
                seen = body;
                stream.write_all(&[0, 0, 0, 1, reply]).await.unwrap();
                // Echo whatever follows, so the splice is observable —
                // detached, so a client that stays open does not stop this
                // endpoint from accepting or from noticing `stop`.
                tokio::spawn(async move {
                    let (mut read, mut write) = stream.split();
                    let _ = tokio::io::copy(&mut read, &mut write).await;
                });
            }
        });
        (handle, stop_tx)
    }

    #[tokio::test]
    async fn a_client_reaches_the_endpoint_only_after_the_secret_is_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let upstream = dir.path().join("endpoint.sock");
        let (endpoint, stop) = fake_endpoint(upstream.clone(), SSH_AGENT_SUCCESS).await;

        let socket = AgentSocket::bind().unwrap();
        let path = socket.path().to_path_buf();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
        let serving = tokio::spawn(async move {
            socket
                .serve(
                    upstream,
                    Some(Arc::new(Zeroizing::new("s3cret".to_string()))),
                    async {
                        let _ = done_rx.await;
                    },
                )
                .await;
        });

        let mut client = UnixStream::connect(&path).await.unwrap();
        client.write_all(b"hello").await.unwrap();
        let mut echoed = [0u8; 5];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"hello", "bytes reach the endpoint after auth");

        drop(client);
        let _ = done_tx.send(());
        serving.await.unwrap();
        let _ = stop.send(());
        let seen = endpoint.await.unwrap();
        assert_eq!(
            seen[0], SSH_AGENTC_EXTENSION,
            "the forwarder authenticates before it forwards anything"
        );
    }

    #[tokio::test]
    async fn a_refused_secret_closes_the_client_instead_of_forwarding() {
        let dir = tempfile::tempdir().unwrap();
        let upstream = dir.path().join("endpoint.sock");
        // 28 is SSH_AGENT_EXTENSION_FAILURE, what the broker answers a secret
        // that is not this endpoint's.
        let (endpoint, stop) = fake_endpoint(upstream.clone(), 28).await;
        let mut server = UnixStream::connect(&upstream).await.unwrap();
        let refused = authenticate(&mut server, "wrong").await;
        assert!(
            refused.is_err(),
            "a non-success status is an error, not a silent pass-through"
        );
        drop(server);
        let _ = stop.send(());
        let _ = endpoint.await;
    }

    #[tokio::test]
    async fn an_implausible_reply_length_is_refused_rather_than_allocated() {
        let dir = tempfile::tempdir().unwrap();
        let upstream = dir.path().join("endpoint.sock");
        let listener = UnixListener::bind(&upstream).unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut discard = [0u8; 64];
            let _ = stream.read(&mut discard).await;
            stream.write_all(&u32::MAX.to_be_bytes()).await.unwrap();
            // Never sends the body; a forwarder that trusted the length would
            // allocate 4 GiB and wait forever.
            futures_hang().await;
        });
        let mut server = UnixStream::connect(&upstream).await.unwrap();
        let error = authenticate(&mut server, "s3cret").await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    async fn futures_hang() {
        std::future::pending::<()>().await
    }
}
