//! Supervision of the Node sidecar.
//!
//! The sidecar hosts the executor engine (MCP serving and, later, the
//! Multitool tool plugin). It is a child process, not a library: it runs a
//! different language runtime, and it is deliberately *not* trusted to
//! authorize anything. This module owns only its lifecycle — spawn, learn
//! the loopback port it chose, forward its logs, restart it if it dies, and
//! reap it when we go away.
//!
//! Path policy lives with the caller: the desktop shell knows where the
//! bundled Node and the bundled script are, and the tests hand us a stub.
//! Keeping [`SidecarConfig`] path-agnostic is what makes this testable
//! without a Node toolchain.

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use serde::Deserialize;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::watch;
use tokio::task::JoinHandle;

/// How long a freshly spawned sidecar has to announce its port.
const READY_TIMEOUT: Duration = Duration::from_secs(15);
/// First restart delay after a failure; doubles up to [`MAX_BACKOFF`].
const MIN_BACKOFF: Duration = Duration::from_millis(500);
const MAX_BACKOFF: Duration = Duration::from_secs(30);
/// A sidecar that stayed up this long is considered healthy, so its next
/// failure restarts promptly instead of inheriting an old backoff.
const STABLE_AFTER: Duration = Duration::from_secs(10);

/// Everything needed to launch one sidecar process.
#[derive(Clone, Debug)]
pub struct SidecarConfig {
    /// The Node binary to run — bundled in the app, or `node` on PATH in dev.
    pub node: PathBuf,
    /// The sidecar's bundled entry script.
    pub script: PathBuf,
    /// The broker's Unix socket; the sidecar's only route back to us.
    pub broker_socket: PathBuf,
}

/// Where a running sidecar can be reached, and with what credential.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SidecarEndpoint {
    pub port: u16,
    pub token: String,
}

impl SidecarEndpoint {
    pub fn base_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SidecarError {
    #[error("sidecar did not become ready within {0:?}")]
    ReadyTimeout(Duration),
    #[error("sidecar exited before becoming ready")]
    ExitedEarly,
    #[error("sidecar spawn failed: {0}")]
    Spawn(#[from] std::io::Error),
}

/// The `{"event":"ready","port":N}` line the sidecar prints on stdout.
#[derive(Deserialize)]
struct ReadyLine {
    event: String,
    port: u16,
}

/// A JSON log line from the sidecar's stderr.
#[derive(Deserialize)]
struct LogLine {
    level: String,
    msg: String,
}

/// An observer of sidecar readiness that does not borrow the [`Sidecar`],
/// so it can be moved into a task that outlives the call site.
#[derive(Clone)]
pub struct SidecarWatch(watch::Receiver<Option<SidecarEndpoint>>);

impl SidecarWatch {
    /// The current endpoint, or `None` while no sidecar is running.
    pub fn endpoint(&self) -> Option<SidecarEndpoint> {
        self.0.borrow().clone()
    }

    /// Wait for a running sidecar, up to `timeout`.
    pub async fn wait_ready(&self, timeout: Duration) -> Result<SidecarEndpoint, SidecarError> {
        let mut rx = self.0.clone();
        let wait = async {
            loop {
                if let Some(endpoint) = rx.borrow_and_update().clone() {
                    return endpoint;
                }
                // Only errors when the supervisor is gone, which Drop covers.
                if rx.changed().await.is_err() {
                    std::future::pending::<()>().await;
                }
            }
        };
        tokio::time::timeout(timeout, wait)
            .await
            .map_err(|_| SidecarError::ReadyTimeout(timeout))
    }
}

/// A supervised sidecar. Dropping this kills the process and stops
/// restarting it.
pub struct Sidecar {
    endpoint: watch::Receiver<Option<SidecarEndpoint>>,
    supervisor: JoinHandle<()>,
}

impl Sidecar {
    /// Start supervising. Returns immediately; the first process may still
    /// be starting. Use [`Sidecar::wait_ready`] to wait for it.
    pub fn spawn(config: SidecarConfig) -> Self {
        let (tx, rx) = watch::channel(None);
        let supervisor = tokio::spawn(supervise(config, tx));
        Self {
            endpoint: rx,
            supervisor,
        }
    }

    /// A detachable readiness observer.
    pub fn watch(&self) -> SidecarWatch {
        SidecarWatch(self.endpoint.clone())
    }

    /// The current endpoint, or `None` while no sidecar is running.
    pub fn endpoint(&self) -> Option<SidecarEndpoint> {
        self.endpoint.borrow().clone()
    }

    /// Wait for a running sidecar, up to `timeout`.
    pub async fn wait_ready(&self, timeout: Duration) -> Result<SidecarEndpoint, SidecarError> {
        self.watch().wait_ready(timeout).await
    }
}

impl Drop for Sidecar {
    fn drop(&mut self) {
        // Aborting drops the `Child`, which was spawned with `kill_on_drop`.
        self.supervisor.abort();
    }
}

/// Restart loop. Never returns; the task is aborted on drop.
async fn supervise(config: SidecarConfig, tx: watch::Sender<Option<SidecarEndpoint>>) {
    let mut backoff = MIN_BACKOFF;
    loop {
        let started = tokio::time::Instant::now();
        match run_once(&config, &tx).await {
            Ok(status) => tracing::warn!(?status, "sidecar exited; restarting"),
            Err(error) => tracing::error!(%error, "sidecar failed; restarting"),
        }
        let _ = tx.send(None);

        // A process that ran for a while and then died is a different
        // problem from one that cannot start at all; only the latter should
        // back off hard.
        if started.elapsed() >= STABLE_AFTER {
            backoff = MIN_BACKOFF;
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

/// Run one sidecar process to completion. Publishes its endpoint once the
/// ready line arrives, and clears nothing — the caller owns that.
async fn run_once(
    config: &SidecarConfig,
    tx: &watch::Sender<Option<SidecarEndpoint>>,
) -> Result<std::process::ExitStatus, SidecarError> {
    let token = mint_token();

    let mut child: Child = Command::new(&config.node)
        .arg(&config.script)
        .env("AKA_SIDECAR_TOKEN", &token)
        .env("AKA_BROKER_SOCKET", &config.broker_socket)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;

    // Both pipes must be drained for the lifetime of the process, or the
    // sidecar blocks on a full buffer the moment it logs enough.
    let stdout = child.stdout.take().expect("stdout was piped");
    let stderr = child.stderr.take().expect("stderr was piped");
    let logs = tokio::spawn(forward_logs(stderr));

    let ready = read_ready(stdout, token, tx);
    tokio::pin!(ready);

    // Race the handshake against an early exit so a sidecar that dies on
    // startup surfaces as `ExitedEarly` rather than a 15-second timeout.
    let status = tokio::select! {
        result = tokio::time::timeout(READY_TIMEOUT, &mut ready) => {
            match result {
                Ok(Ok(())) => child.wait().await?,
                Ok(Err(error)) => {
                    let _ = child.kill().await;
                    logs.abort();
                    return Err(error);
                }
                Err(_) => {
                    let _ = child.kill().await;
                    logs.abort();
                    return Err(SidecarError::ReadyTimeout(READY_TIMEOUT));
                }
            }
        }
        status = child.wait() => status?,
    };

    logs.abort();
    Ok(status)
}

/// Read stdout until the ready line arrives, then keep draining it.
async fn read_ready(
    stdout: tokio::process::ChildStdout,
    token: String,
    tx: &watch::Sender<Option<SidecarEndpoint>>,
) -> Result<(), SidecarError> {
    let mut lines = BufReader::new(stdout).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        match serde_json::from_str::<ReadyLine>(&line) {
            Ok(ready) if ready.event == "ready" => {
                tracing::info!(port = ready.port, "sidecar ready");
                let _ = tx.send(Some(SidecarEndpoint {
                    port: ready.port,
                    token,
                }));
                // Keep draining so the pipe never fills.
                while let Ok(Some(line)) = lines.next_line().await {
                    tracing::debug!(target: "sidecar", "{line}");
                }
                return Ok(());
            }
            _ => tracing::debug!(target: "sidecar", "{line}"),
        }
    }
    Err(SidecarError::ExitedEarly)
}

/// Forward the sidecar's JSON log lines into our own tracing output.
async fn forward_logs(stderr: tokio::process::ChildStderr) {
    let mut lines = BufReader::new(stderr).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        match serde_json::from_str::<LogLine>(&line) {
            Ok(entry) => match entry.level.as_str() {
                "error" => tracing::error!(target: "sidecar", "{}", entry.msg),
                "warn" => tracing::warn!(target: "sidecar", "{}", entry.msg),
                _ => tracing::info!(target: "sidecar", "{}", entry.msg),
            },
            // Anything the sidecar's runtime writes directly (a Node stack
            // trace, say) is not JSON but is exactly what we want to see.
            Err(_) => tracing::warn!(target: "sidecar", "{line}"),
        }
    }
}

/// A fresh per-process bearer token. Regenerated on every restart so a
/// token that leaked from a dead process is worthless.
fn mint_token() -> String {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("system randomness");
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// A stub "node" that runs a shell script, so these tests exercise the
    /// supervisor without needing a Node toolchain.
    fn stub(script: &str) -> (tempfile::TempDir, SidecarConfig) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("stub.sh");
        let mut file = std::fs::File::create(&path).expect("create stub");
        file.write_all(script.as_bytes()).expect("write stub");
        drop(file);
        let config = SidecarConfig {
            node: PathBuf::from("/bin/sh"),
            script: path,
            broker_socket: dir.path().join("aka.sock"),
        };
        (dir, config)
    }

    #[tokio::test]
    async fn a_ready_line_publishes_the_endpoint() {
        let (_dir, config) = stub(
            r#"echo '{"event":"ready","port":45678}'
               sleep 30"#,
        );
        let sidecar = Sidecar::spawn(config);
        let endpoint = sidecar
            .wait_ready(Duration::from_secs(5))
            .await
            .expect("ready");
        assert_eq!(endpoint.port, 45678);
        assert_eq!(endpoint.token.len(), 64);
        assert_eq!(endpoint.base_url(), "http://127.0.0.1:45678");
    }

    #[tokio::test]
    async fn the_token_reaches_the_process_and_changes_on_restart() {
        // The stub echoes back the token it was handed as its "port" line's
        // sibling, so we can prove the environment plumbing works.
        let (_dir, config) = stub(
            r#"echo "$AKA_SIDECAR_TOKEN" > "$(dirname "$0")/seen-$$"
               echo '{"event":"ready","port":45679}'
               exit 0"#,
        );
        let dir = config.script.parent().expect("parent").to_path_buf();
        let sidecar = Sidecar::spawn(config);
        sidecar
            .wait_ready(Duration::from_secs(5))
            .await
            .expect("ready");

        // Give the restart loop time to run the stub at least twice.
        tokio::time::sleep(Duration::from_secs(2)).await;
        let mut tokens: Vec<String> = std::fs::read_dir(&dir)
            .expect("read dir")
            .filter_map(|entry| {
                let entry = entry.ok()?;
                let name = entry.file_name().into_string().ok()?;
                name.starts_with("seen-").then(|| {
                    std::fs::read_to_string(entry.path())
                        .unwrap_or_default()
                        .trim()
                        .to_string()
                })
            })
            .collect();
        tokens.sort();
        tokens.dedup();
        assert!(tokens.len() >= 2, "expected a restart, saw {tokens:?}");
        assert!(tokens.iter().all(|token| token.len() == 64));
    }

    #[tokio::test]
    async fn a_process_that_never_announces_is_not_ready() {
        let (_dir, config) = stub("sleep 30");
        let sidecar = Sidecar::spawn(config);
        let result = sidecar.wait_ready(Duration::from_millis(300)).await;
        assert!(matches!(result, Err(SidecarError::ReadyTimeout(_))));
        assert_eq!(sidecar.endpoint(), None);
    }

    #[tokio::test]
    async fn a_missing_node_binary_does_not_panic_the_supervisor() {
        let (_dir, mut config) = stub("echo unused");
        config.node = PathBuf::from("/nonexistent/node");
        let sidecar = Sidecar::spawn(config);
        let result = sidecar.wait_ready(Duration::from_millis(300)).await;
        assert!(matches!(result, Err(SidecarError::ReadyTimeout(_))));
    }
}
