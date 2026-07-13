//! `agentmfa` CLI.
//!
//! - `agentmfa skill` emits the `/instructions` content as a checked-in
//!   skill file, the same content the daemon serves, so the convention
//!   layer can't drift from the daemon.
//! - `agentmfa serve` runs the broker headless with a terminal approver, so
//!   the whole control plane + WS/PG data planes can be exercised without
//!   the desktop UI (useful for agent integration and CI).
//! - `agentmfa secret add` / `agentmfa conn add` / `agentmfa conn list`
//!   seed the store from the terminal — the dev/headless counterpart of the
//!   app's Secrets and Connections tabs — with the same validation, so a
//!   `serve --root` harness never hand-writes (sealed) store files.

use std::io::Write as _;
use std::ops::Deref;
use std::os::unix::fs::FileTypeExt as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use agentmfa_core::approvals::{ApprovalKind, ApprovalRequest};
use agentmfa_core::broker::{Broker, DecisionOptions, UiDecision};
use agentmfa_core::config::BrokerConfig;
use agentmfa_core::daemon;
use agentmfa_core::daemon::wellknown;
use agentmfa_core::error::CoreError;
use agentmfa_core::events::BrokerEvents;
use agentmfa_core::paths::{BrokerInstanceLock, Paths};
use agentmfa_core::store::{ConnectionSpec, Store};
use agentmfa_core::types::{
    ConfirmationMethod, ConnectionConfig, DecisionContext, DecisionSurface, PgSslMode, SecretMeta,
    SecretValue,
};
use agentmfa_core::vault::{platform_vault, platform_vault_for_root, SecretVault};
use clap::{Args, Parser, Subcommand, ValueEnum};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(name = "agentmfa", version, about = "AgentMFA broker CLI")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Emit the /instructions content as a skill file. Prints to stdout by
    /// default; `--write` writes .claude/skills/agentmfa/SKILL.md.
    Skill {
        /// Write the file to `path` (default .claude/skills/agentmfa/SKILL.md)
        /// instead of printing to stdout.
        #[arg(long)]
        write: bool,
        /// Override the output path used with --write.
        #[arg(long, conflicts_with = "user")]
        path: Option<PathBuf>,
        /// With --write, target the user-level skills directory
        /// (~/.claude/skills/agentmfa/SKILL.md) instead of the repo-local
        /// default, so every project's agents see it.
        #[arg(long)]
        user: bool,
        /// Render the document for a broker rooted here (`serve --root`)
        /// instead of the production layout, so a dev harness's skill file
        /// names the socket it actually serves.
        #[arg(long)]
        root: Option<PathBuf>,
    },
    /// Print the raw /instructions markdown to stdout.
    Instructions {
        /// Render for a broker rooted here instead of the production layout.
        #[arg(long)]
        root: Option<PathBuf>,
    },
    /// Run the broker headless with a terminal approver (no desktop UI).
    Serve {
        /// Use an isolated root dir (data + socket under it) instead of the
        /// default per-user locations. Handy for testing.
        #[arg(long)]
        root: Option<PathBuf>,
        /// Auto-approve everything (⚠ DANGER: for CI/local demos only; the
        /// whole point of the broker is human approval).
        #[arg(long)]
        yes: bool,
    },
    /// Manage secrets from the terminal (dev/headless use; the desktop app
    /// is the primary interface).
    Secret {
        #[command(subcommand)]
        command: SecretCommand,
    },
    /// Manage connections from the terminal (dev/headless use).
    Conn {
        #[command(subcommand)]
        command: ConnCommand,
    },
}

#[derive(Subcommand)]
enum SecretCommand {
    /// Add a secret. The value is read from stdin (or --value-env), never
    /// from argv, where it would sit in `ps` output and shell history.
    Add {
        /// Secret name, as referenced by connection templates.
        name: String,
        /// Read the value from this environment variable instead of stdin.
        #[arg(long, value_name = "VAR")]
        value_env: Option<String>,
        /// Operate on a broker rooted here instead of the default layout.
        #[arg(long)]
        root: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)] // one short-lived instance per invocation
enum ConnCommand {
    /// Add a connection agents can name on capability calls.
    Add(ConnAdd),
    /// List configured connections.
    List {
        /// Operate on a broker rooted here instead of the default layout.
        #[arg(long)]
        root: Option<PathBuf>,
    },
}

#[derive(Args)]
struct ConnAdd {
    /// Connection name, what agents name on capability calls.
    name: String,
    #[arg(long, value_enum)]
    kind: ConnKind,
    /// api/pg/ssh: upstream host (bare hostname, no scheme/port/path).
    #[arg(long)]
    host: Option<String>,
    /// api: "https" (the default) or "http" (dev/test upstreams).
    #[arg(long)]
    scheme: Option<String>,
    /// Upstream port (api: the scheme's; pg: 5432; ssh: 22).
    #[arg(long)]
    port: Option<u16>,
    /// api: injection template, e.g. 'Authorization: Bearer {{KEY}}' — its
    /// {{refs}} name the secrets. ws: optional header-line template
    /// referencing exactly one secret (default: Authorization Bearer).
    #[arg(long)]
    template: Option<String>,
    /// ws: full upstream URL (ws:// or wss://).
    #[arg(long)]
    url: Option<String>,
    /// pg: database name.
    #[arg(long)]
    dbname: Option<String>,
    /// pg/ssh: login user.
    #[arg(long)]
    user: Option<String>,
    /// ssh: pinned server host key fingerprint (SHA256:... or SHA512:...).
    /// Omit it to trust on first use: the key is confirmed with the user and
    /// pinned at the first agent connection.
    #[arg(long)]
    host_key_fingerprint: Option<String>,
    /// pg/ws/ssh: name of the one bound secret (api connections derive
    /// theirs from the template).
    #[arg(long)]
    secret: Option<String>,
    /// pg: disable | prefer | require | verify-ca | verify-full
    /// (default: verify-full).
    #[arg(long)]
    sslmode: Option<String>,
    /// pg: optional PEM bundle for a private certificate authority.
    #[arg(long)]
    ca_bundle: Option<String>,
    /// Operate on a broker rooted here instead of the default layout.
    #[arg(long)]
    root: Option<PathBuf>,
}

#[derive(ValueEnum, Clone, Copy)]
enum ConnKind {
    Api,
    Pg,
    Ws,
    Ssh,
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Command::Skill {
            write,
            path,
            user,
            root,
        } => cmd_skill(write, path, user, root),
        Command::Instructions { root } => {
            print!(
                "{}",
                wellknown::instructions(&BrokerConfig::default(), &doc_paths(root))
            );
        }
        Command::Serve { root, yes } => cmd_serve(root, yes),
        Command::Secret {
            command:
                SecretCommand::Add {
                    name,
                    value_env,
                    root,
                },
        } => cmd_secret_add(name, value_env, root),
        Command::Conn { command } => match command {
            ConnCommand::Add(args) => cmd_conn_add(args),
            ConnCommand::List { root } => cmd_conn_list(root),
        },
    }
}

fn die(message: impl std::fmt::Display) -> ! {
    eprintln!("error: {message}");
    std::process::exit(1);
}

fn store_paths(root: Option<&Path>) -> Paths {
    match root {
        Some(root) => Paths::under(root),
        None => Paths::default_locations().expect("default paths"),
    }
}

fn open_vault(
    paths: &Paths,
    root: Option<&Path>,
) -> Result<Arc<dyn SecretVault>, agentmfa_core::error::CoreError> {
    match root {
        Some(root) => platform_vault_for_root(paths, root),
        None => platform_vault(paths),
    }
}

/// An offline store handle coupled to the exclusive lease protecting it.
struct OfflineStore {
    store: Store,
    // Declared last so state handles close before another process can acquire
    // the lease and open the same files.
    _instance_lock: BrokerInstanceLock,
}

impl Deref for OfflineStore {
    type Target = Store;

    fn deref(&self) -> &Self::Target {
        &self.store
    }
}

fn acquire_offline_store_lock(paths: &Paths) -> Result<BrokerInstanceLock, CoreError> {
    paths.ensure()?;
    let instance_lock = paths
        .try_acquire_broker_lock()?
        .ok_or_else(|| CoreError::BrokerAlreadyRunning(paths.socket_display()))?;

    // A broker from before `broker.lock` may still own the rendezvous point.
    // Once the new lease is held, reject a live legacy socket before opening
    // any state; only the expected crash residue is safe to ignore here.
    let socket = paths.socket_file();
    let metadata = match std::fs::symlink_metadata(&socket) {
        Ok(metadata) => Some(metadata),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(CoreError::Io(error)),
    };
    if let Some(metadata) = metadata {
        if !metadata.file_type().is_socket() {
            return Err(CoreError::Io(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!(
                    "refusing to open state while {} is not a Unix socket",
                    socket.display()
                ),
            )));
        }
        match std::os::unix::net::UnixStream::connect(&socket) {
            Ok(_) => return Err(CoreError::BrokerAlreadyRunning(paths.socket_display())),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
                ) => {}
            Err(error) => {
                return Err(CoreError::Io(std::io::Error::new(
                    error.kind(),
                    format!(
                    "failed to probe existing control socket {}; refusing to open state: {error}",
                    socket.display()
                ),
                )))
            }
        }
    }
    Ok(instance_lock)
}

/// Open the store for offline edits (`secret add`, `conn add`): the same
/// files a broker on this root serves, so a live broker — which holds the
/// store in memory and would overwrite the edit on its next persist — is
/// refused before any state is opened.
fn open_store(root: Option<PathBuf>) -> OfflineStore {
    let paths = store_paths(root.as_deref());
    let instance_lock = match acquire_offline_store_lock(&paths) {
        Ok(instance_lock) => instance_lock,
        Err(CoreError::BrokerAlreadyRunning(_)) => die(format!(
            "a broker is running on {} — stop it first (its in-memory state \
             would overwrite this change), or add through the app",
            paths.socket_file().display()
        )),
        Err(error) => die(format!("could not acquire the broker state lease: {error}")),
    };
    let vault = match open_vault(&paths, root.as_deref()) {
        Ok(vault) => vault,
        Err(e) => die(format!("could not open the secret vault: {e}")),
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    match runtime.block_on(Store::open(paths, vault)) {
        Ok(store) => OfflineStore {
            store,
            _instance_lock: instance_lock,
        },
        Err(e) => die(format!("could not open the store: {e}")),
    }
}

fn cmd_secret_add(name: String, value_env: Option<String>, root: Option<PathBuf>) {
    let value: SecretValue = match &value_env {
        Some(var) => match std::env::var(var) {
            Ok(value) => Zeroizing::new(value),
            Err(_) => die(format!("environment variable {var} is not set")),
        },
        None => {
            if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
                eprintln!("  reading the secret value from stdin; end with Ctrl-D");
            }
            match std::io::read_to_string(std::io::stdin()) {
                // Strip the line ending an `echo`/heredoc appends; a real
                // trailing newline in a secret is vanishingly rarer than an
                // accidental one.
                Ok(text) => Zeroizing::new(text.trim_end_matches(['\r', '\n']).to_string()),
                Err(e) => die(format!("could not read the value from stdin: {e}")),
            }
        }
    };
    if value.is_empty() {
        die("the secret value is empty");
    }
    let store = open_store(root);
    match store.add_secret(&name, value) {
        Ok(meta) => eprintln!("added secret {}", meta.name),
        Err(e) => die(e),
    }
}

fn cmd_conn_add(args: ConnAdd) {
    let store = open_store(args.root.clone());
    let config = match conn_config(&args) {
        Ok(config) => config,
        Err(e) => die(e),
    };
    // pg/ws/ssh bind exactly one secret by name; api derives its secrets
    // from the template's refs inside add_connection.
    let secrets = match (&args.secret, args.kind) {
        (_, ConnKind::Api) => Vec::new(),
        (Some(name), _) => match store.secret_by_name(name) {
            Some(meta) => vec![meta.id],
            None => die(format!(
                "no secret named {name:?}; add it first with `agentmfa secret add {name}`"
            )),
        },
        (None, _) => Vec::new(),
    };
    let spec = ConnectionSpec {
        name: args.name,
        config,
        secrets,
    };
    match store.add_connection(spec) {
        Ok(conn) => eprintln!(
            "added connection {} ({} · {})",
            conn.name,
            conn.kind().as_str(),
            conn.target()
        ),
        Err(e) => die(e),
    }
}

/// Build the type-specific config, naming exactly which flag is missing or
/// stray for the kind; the deep validation (hosts, schemes, template refs)
/// stays in the store, one place.
fn conn_config(args: &ConnAdd) -> Result<ConnectionConfig, String> {
    let require = |flag: &str, value: &Option<String>| -> Result<String, String> {
        value
            .clone()
            .ok_or_else(|| format!("--{flag} is required for this kind"))
    };
    let forbid = |present: &[(&str, bool)]| -> Result<(), String> {
        match present.iter().find(|(_, given)| *given) {
            Some((flag, _)) => Err(format!("--{flag} does not apply to this kind")),
            None => Ok(()),
        }
    };
    match args.kind {
        ConnKind::Api => {
            forbid(&[
                ("url", args.url.is_some()),
                ("dbname", args.dbname.is_some()),
                ("user", args.user.is_some()),
                ("secret", args.secret.is_some()),
                ("sslmode", args.sslmode.is_some()),
                ("ca-bundle", args.ca_bundle.is_some()),
                ("host-key-fingerprint", args.host_key_fingerprint.is_some()),
            ])?;
            Ok(ConnectionConfig::Api {
                host: require("host", &args.host)?,
                scheme: args.scheme.clone().unwrap_or_else(|| "https".into()),
                port: args.port,
                template: require("template", &args.template)?,
            })
        }
        ConnKind::Pg => {
            forbid(&[
                ("scheme", args.scheme.is_some()),
                ("template", args.template.is_some()),
                ("url", args.url.is_some()),
                ("host-key-fingerprint", args.host_key_fingerprint.is_some()),
            ])?;
            require("secret", &args.secret)?;
            Ok(ConnectionConfig::Pg {
                host: require("host", &args.host)?,
                port: args.port.unwrap_or(5432),
                dbname: require("dbname", &args.dbname)?,
                user: require("user", &args.user)?,
                sslmode: parse_sslmode(args.sslmode.as_deref())?,
                trusted_ca_bundle_path: args.ca_bundle.clone(),
            })
        }
        ConnKind::Ws => {
            forbid(&[
                ("host", args.host.is_some()),
                ("scheme", args.scheme.is_some()),
                ("port", args.port.is_some()),
                ("dbname", args.dbname.is_some()),
                ("user", args.user.is_some()),
                ("sslmode", args.sslmode.is_some()),
                ("ca-bundle", args.ca_bundle.is_some()),
                ("host-key-fingerprint", args.host_key_fingerprint.is_some()),
            ])?;
            if args.secret.is_none() && args.template.is_none() {
                return Err("--secret (or --template) is required for this kind".into());
            }
            Ok(ConnectionConfig::Ws {
                url: require("url", &args.url)?,
                template: args.template.clone(),
            })
        }
        ConnKind::Ssh => {
            forbid(&[
                ("scheme", args.scheme.is_some()),
                ("template", args.template.is_some()),
                ("url", args.url.is_some()),
                ("dbname", args.dbname.is_some()),
                ("sslmode", args.sslmode.is_some()),
                ("ca-bundle", args.ca_bundle.is_some()),
            ])?;
            require("secret", &args.secret)?;
            Ok(ConnectionConfig::Ssh {
                destination: None,
                host: require("host", &args.host)?,
                port: args.port.unwrap_or(22),
                user: require("user", &args.user)?,
                // Empty = unpinned; the broker pins the observed key at the
                // first agent connection after a trust prompt.
                host_key_fingerprint: args.host_key_fingerprint.clone().unwrap_or_default(),
            })
        }
    }
}

fn parse_sslmode(value: Option<&str>) -> Result<PgSslMode, String> {
    Ok(match value {
        None => PgSslMode::default(),
        Some("disable") => PgSslMode::Disable,
        Some("prefer") => PgSslMode::Prefer,
        Some("require") => PgSslMode::Require,
        Some("verify-ca") => PgSslMode::VerifyCa,
        Some("verify-full") => PgSslMode::VerifyFull,
        Some(other) => {
            return Err(format!(
                "unknown sslmode {other:?} (disable | prefer | require | \
                 verify-ca | verify-full)"
            ))
        }
    })
}

fn cmd_conn_list(root: Option<PathBuf>) {
    let store = open_store(root);
    let connections = store.list_connections();
    if connections.is_empty() {
        eprintln!("no connections configured (add one with `agentmfa conn add`)");
        return;
    }
    for conn in connections {
        println!("{}  {}  {}", conn.name, conn.kind().as_str(), conn.target());
    }
}

/// The layout the generated documents describe: the production defaults,
/// or — with `--root` — a dev broker's actual layout.
fn doc_paths(root: Option<PathBuf>) -> Paths {
    match root {
        Some(root) => Paths::under(&root),
        None => Paths::default_locations().expect("default paths"),
    }
}

fn cmd_skill(write: bool, path: Option<PathBuf>, user: bool, root: Option<PathBuf>) {
    let content = wellknown::skill_file(&BrokerConfig::default(), &doc_paths(root));
    if !write {
        print!("{content}");
        return;
    }
    let path = match (path, user) {
        (Some(path), _) => path,
        (None, true) => dirs::home_dir()
            .expect("home directory")
            .join(".claude/skills/agentmfa/SKILL.md"),
        (None, false) => PathBuf::from(".claude/skills/agentmfa/SKILL.md"),
    };
    if let Some(dir) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(dir) {
            eprintln!("error: could not create {}: {e}", dir.display());
            std::process::exit(1);
        }
    }
    if let Err(e) = std::fs::write(&path, content) {
        eprintln!("error: could not write {}: {e}", path.display());
        std::process::exit(1);
    }
    eprintln!("wrote {}", path.display());
}

/// A terminal approver: prints each prompt and reads a decision from stdin.
struct CliEvents {
    tx: std::sync::mpsc::Sender<ApprovalRequest>,
    /// `--yes` mode: confirmations are explicitly waived, not interactive.
    auto_yes: bool,
}

impl CliEvents {
    fn confirmation(&self) -> ConfirmationMethod {
        if self.auto_yes {
            ConfirmationMethod::Waived
        } else {
            // The decision the human just typed at the interactive prompt
            // *is* the acknowledgement; there is no second gate to show.
            ConfirmationMethod::Terminal
        }
    }
}

impl BrokerEvents for CliEvents {
    fn prompt_raised(&self, request: &ApprovalRequest) {
        let _ = self.tx.send(request.clone());
    }

    fn confirm_secret_read(&self, secret: &SecretMeta) -> bool {
        eprintln!(
            "  secret read re-auth requested for {} (headless CLI allows this dev path)",
            secret.name
        );
        true
    }

    fn confirm_decision(
        &self,
        _request: &ApprovalRequest,
        _decision: UiDecision,
    ) -> Option<ConfirmationMethod> {
        Some(self.confirmation())
    }

    fn confirm_action(&self, _description: &str) -> Option<ConfirmationMethod> {
        Some(self.confirmation())
    }
}

fn cmd_serve(root: Option<PathBuf>, auto_yes: bool) {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "agentmfa_core=info".into()),
        )
        .init();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    // Startup failures here are configuration problems (a socket path over
    // the sun_path limit, an unreadable root, a vault that won't open) —
    // diagnose in one line rather than panicking with a backtrace.
    let fail = |what: &str, e: &dyn std::fmt::Display| -> ! {
        eprintln!("error: {what}: {e}");
        std::process::exit(1);
    };
    let paths = store_paths(root.as_deref());
    let vault = match open_vault(&paths, root.as_deref()) {
        Ok(vault) => vault,
        Err(e) => fail("could not open the secret vault", &e),
    };

    let (tx, rx) = std::sync::mpsc::channel::<ApprovalRequest>();
    let events: Arc<dyn BrokerEvents> = Arc::new(CliEvents { tx, auto_yes });

    let broker: Arc<Broker> =
        match runtime.block_on(Broker::new(paths, vault, BrokerConfig::default(), events)) {
            Ok(broker) => broker,
            Err(e) => fail("could not start the broker", &e),
        };
    let daemon = match runtime.block_on(daemon::serve(broker.clone())) {
        Ok(daemon) => daemon,
        Err(e) => fail("could not serve the control plane", &e),
    };

    eprintln!(
        "AgentMFA broker listening on {}",
        daemon.socket_path.display()
    );
    if cfg!(not(target_os = "macos")) {
        eprintln!(
            "  ⚠ dev build: peer identity is uid-pinned only on this OS \
             (code-signature pinning is macOS-only)"
        );
    }
    eprintln!(
        "  discovery: curl --unix-socket {} http://localhost/instructions",
        daemon.socket_path.display()
    );
    eprintln!(
        "  skill file: `agentmfa skill --write` in a repo (or --write --user) \
         teaches agents this broker"
    );
    if auto_yes {
        eprintln!("  ⚠ --yes: auto-approving every request (no human in the loop)");
    } else {
        let access_duration = format_duration(broker.config.access_grant_ttl);
        eprintln!(
            "  approve prompts below with: [a]llow {access_duration} · allow [o]nce · allow [f]orever · [d]eny"
        );
    }
    eprintln!("  Ctrl-C to quit.\n");

    // Catch Ctrl-C inside Tokio so the daemon handle gets a normal Drop and
    // can remove only the control-socket inode it owns. Polling with a short
    // timeout wakes the otherwise blocking std channel when no approvals are
    // arriving.
    let stopping = Arc::new(AtomicBool::new(false));
    let signal_flag = stopping.clone();
    runtime.spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            signal_flag.store(true, Ordering::Release);
        }
    });

    // Terminal approval loop on the main thread.
    while !stopping.load(Ordering::Acquire) {
        let request = match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(request) => request,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        };
        let decided = if auto_yes {
            if request.kind == ApprovalKind::Propose {
                // A proposal needs a human-typed credential; --yes has none.
                eprintln!("  ⚠ --yes cannot supply a proposal credential; denying");
                Some((UiDecision::Deny, None))
            } else {
                Some((UiDecision::AllowOnce, None))
            }
        } else {
            prompt_decision_until_shutdown(
                &request,
                broker.config.access_grant_ttl,
                stopping.clone(),
            )
        };
        let Some((decision, proposal_credential)) = decided else {
            break;
        };
        // Auto-approve rebounds the pairing brake fairly; on a real denial
        // the core arms the cooldown itself.
        let ctx = DecisionContext::local(DecisionSurface::Cli);
        let options = DecisionOptions {
            revoke_inherited_rules: false,
            proposal_credential,
        };
        if let Err(e) = broker.decide_with_options(&request.id, decision, options, &ctx) {
            eprintln!("  (decision failed: {e})");
        }
    }
    drop(daemon);
}

/// Keep terminal input off the shutdown-owning thread. Once Tokio installs a
/// SIGINT handler, a blocking `stdin.read_line()` is not guaranteed to wake on
/// Ctrl-C; polling this result channel lets the main thread drop the daemon
/// promptly while the process tears down the detached input thread.
fn prompt_decision_until_shutdown(
    request: &ApprovalRequest,
    access_grant_ttl: Duration,
    stopping: Arc<AtomicBool>,
) -> Option<(UiDecision, Option<agentmfa_core::types::SecretValue>)> {
    if stopping.load(Ordering::Acquire) {
        return None;
    }
    let request = request.clone();
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let _ = tx.send(prompt_decision(&request, access_grant_ttl));
    });
    wait_for_decision_or_shutdown(rx, stopping)
}

fn wait_for_decision_or_shutdown(
    rx: std::sync::mpsc::Receiver<(UiDecision, Option<agentmfa_core::types::SecretValue>)>,
    stopping: Arc<AtomicBool>,
) -> Option<(UiDecision, Option<agentmfa_core::types::SecretValue>)> {
    loop {
        if stopping.load(Ordering::Acquire) {
            return None;
        }
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(decision) => return Some(decision),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return Some((UiDecision::Deny, None)),
        }
    }
}

fn prompt_decision(
    req: &ApprovalRequest,
    access_grant_ttl: Duration,
) -> (UiDecision, Option<agentmfa_core::types::SecretValue>) {
    eprintln!("── approval required ──────────────────────────────");
    eprintln!("  agent:   {}", req.agent);
    if req.kind == ApprovalKind::Pair {
        eprintln!(
            "  identity: {}",
            req.identity.as_deref().unwrap_or("unsigned")
        );
        if !req.inherited.is_empty() {
            eprintln!("  ⚠ inherits standing access to:");
            for c in &req.inherited {
                eprintln!("      {} ({} · {})", c.name, c.kind.as_str(), c.target);
            }
        }
    }
    if let Some(conn) = &req.connection {
        eprintln!(
            "  connection: {} ({} · {})",
            conn.name,
            conn.kind.as_str(),
            conn.target
        );
        if matches!(
            req.kind,
            ApprovalKind::Pg | ApprovalKind::Ws | ApprovalKind::Ssh
        ) {
            eprintln!("  scope: all connects within the 60 s ticket window");
        }
    }
    eprintln!("  action:  {}", req.action);
    if let Some(http) = &req.http {
        if http.mutating {
            eprintln!(
                "  ⚠ mutating {}, headers: {}",
                http.method,
                http.headers.len()
            );
            if let Some(body) = &http.body_preview {
                eprintln!("  body: {}", body.lines().next().unwrap_or(""));
            }
        }
    }
    if let Some(ssh) = &req.ssh {
        eprintln!(
            "  ⚠ first connection to {}:{} — trust this host key?",
            ssh.host, ssh.port
        );
        eprintln!("      {} ({})", ssh.observed_fingerprint, ssh.algorithm);
        eprintln!("      verify it out-of-band (e.g. `ssh-keygen -lf` on the server)");
    }
    if let Some(proposal) = &req.proposal {
        eprintln!(
            "  proposed service: {} ({} · {})",
            proposal.name,
            proposal.kind.as_str(),
            proposal.target
        );
        if let Some(tls) = &proposal.tls {
            eprintln!("  TLS mode: {tls}");
        }
        if let Some(template) = &proposal.template {
            eprintln!("  auth template: {template}");
        }
        eprintln!(
            "  approving will ask you to type the credential (saved as {})",
            proposal.credential_name
        );
    }
    // Pairing and host-key trust are yes/no decisions: no session or
    // standing-rule shapes (the broker coerces them to allow-once anyway).
    let binary_prompt =
        matches!(req.kind, ApprovalKind::Pair | ApprovalKind::Propose) || req.ssh.is_some();
    let decision = loop {
        eprint!("  decide [a/o/f/d]: ");
        let _ = std::io::stderr().flush();
        let mut line = String::new();
        if std::io::stdin().read_line(&mut line).is_err() || line.is_empty() {
            break UiDecision::Deny; // EOF → safe default
        }
        match line.trim() {
            "a" | "allow" if binary_prompt => break UiDecision::AllowOnce,
            "a" | "allow" => break UiDecision::AllowSession,
            "o" | "once" => break UiDecision::AllowOnce,
            "f" | "forever" if !binary_prompt => break UiDecision::AlwaysAllow,
            "d" | "deny" | "" => break UiDecision::Deny,
            _ if req.kind == ApprovalKind::Pair => {
                eprintln!("  ? enter a (allow pairing) or d (deny)")
            }
            _ if req.kind == ApprovalKind::Propose => {
                eprintln!("  ? enter a (save this service) or d (deny)")
            }
            _ if req.ssh.is_some() => {
                eprintln!("  ? enter a (trust this host key) or d (deny)")
            }
            _ => eprintln!(
                "  ? enter a (allow {}), o (allow once), f (allow forever), or d (deny)",
                format_duration(access_grant_ttl)
            ),
        }
    };
    // A proposal approval needs the credential the wire schema deliberately
    // cannot carry: the human types it here, into the trusted terminal.
    if req.kind == ApprovalKind::Propose && decision != UiDecision::Deny {
        let credential_name = req
            .proposal
            .as_ref()
            .map(|proposal| proposal.credential_name.clone())
            .unwrap_or_else(|| "credential".to_string());
        eprint!("  value for {credential_name}: ");
        let _ = std::io::stderr().flush();
        let mut value = String::new();
        if std::io::stdin().read_line(&mut value).is_err() {
            return (UiDecision::Deny, None);
        }
        let value = value.trim_end_matches(['\r', '\n']).to_string();
        return (
            decision,
            Some(agentmfa_core::types::SecretValue::new(value)),
        );
    }
    (decision, None)
}

fn format_duration(duration: Duration) -> String {
    let seconds = duration.as_secs();
    if seconds > 0 && seconds.is_multiple_of(3_600) {
        let hours = seconds / 3_600;
        format!("{hours} hour{}", if hours == 1 { "" } else { "s" })
    } else if seconds > 0 && seconds.is_multiple_of(60) {
        let minutes = seconds / 60;
        format!("{minutes} minute{}", if minutes == 1 { "" } else { "s" })
    } else {
        format!("{seconds} second{}", if seconds == 1 { "" } else { "s" })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentmfa_core::events::NoopEvents;
    use agentmfa_core::vault::MemoryVault;

    #[test]
    fn access_duration_uses_the_configured_value() {
        assert_eq!(format_duration(Duration::from_secs(90)), "90 seconds");
        assert_eq!(format_duration(Duration::from_secs(15 * 60)), "15 minutes");
        assert_eq!(format_duration(Duration::from_secs(60 * 60)), "1 hour");
    }

    #[test]
    fn terminal_decision_wait_stops_without_stdin_finishing() {
        let (tx, rx) = std::sync::mpsc::channel();
        let stopping = Arc::new(AtomicBool::new(false));
        let signal_flag = stopping.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            signal_flag.store(true, Ordering::Release);
            // Keep the decision channel connected until after shutdown is
            // visible, modelling a prompt thread blocked in read_line().
            std::thread::sleep(Duration::from_secs(1));
            drop(tx);
        });

        let started = std::time::Instant::now();
        assert_eq!(wait_for_decision_or_shutdown(rx, stopping), None);
        assert!(started.elapsed() < Duration::from_millis(750));
    }

    #[test]
    fn offline_store_writer_respects_the_broker_lease() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::under(dir.path());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let broker = runtime
            .block_on(Broker::new(
                paths.clone(),
                Arc::new(MemoryVault::new()),
                BrokerConfig::default(),
                Arc::new(NoopEvents),
            ))
            .unwrap();

        assert!(matches!(
            acquire_offline_store_lock(&paths),
            Err(CoreError::BrokerAlreadyRunning(_))
        ));
        drop(broker);
        assert!(acquire_offline_store_lock(&paths).is_ok());
    }

    fn args(kind: ConnKind) -> ConnAdd {
        ConnAdd {
            name: "test".into(),
            kind,
            host: None,
            scheme: None,
            port: None,
            template: None,
            url: None,
            dbname: None,
            user: None,
            host_key_fingerprint: None,
            secret: None,
            sslmode: None,
            ca_bundle: None,
            root: None,
        }
    }

    #[test]
    fn api_names_its_missing_and_stray_flags() {
        let mut a = args(ConnKind::Api);
        assert!(conn_config(&a).unwrap_err().contains("--host"));
        a.host = Some("api.github.com".into());
        assert!(conn_config(&a).unwrap_err().contains("--template"));
        a.template = Some("Authorization: Bearer {{KEY}}".into());
        let config = conn_config(&a).unwrap();
        assert!(matches!(config, ConnectionConfig::Api { ref scheme, .. } if scheme == "https"));
        // api derives secrets from the template; a stray --secret is a
        // misunderstanding worth naming, not ignoring.
        a.secret = Some("KEY".into());
        assert!(conn_config(&a).unwrap_err().contains("--secret"));
    }

    #[test]
    fn pg_defaults_port_and_sslmode() {
        let mut a = args(ConnKind::Pg);
        a.host = Some("db.internal".into());
        a.dbname = Some("app".into());
        a.user = Some("app".into());
        assert!(conn_config(&a).unwrap_err().contains("--secret"));
        a.secret = Some("PGPASS".into());
        match conn_config(&a).unwrap() {
            ConnectionConfig::Pg { port, sslmode, .. } => {
                assert_eq!(port, 5432);
                assert_eq!(sslmode, PgSslMode::VerifyFull);
            }
            other => panic!("wrong config: {other:?}"),
        }
        a.sslmode = Some("bogus".into());
        assert!(conn_config(&a).unwrap_err().contains("bogus"));
    }

    #[test]
    fn ws_needs_url_and_a_credential_source() {
        let mut a = args(ConnKind::Ws);
        a.url = Some("wss://stream.example.com/feed".into());
        assert!(conn_config(&a).unwrap_err().contains("--secret"));
        a.secret = Some("FEED_TOKEN".into());
        assert!(matches!(
            conn_config(&a).unwrap(),
            ConnectionConfig::Ws { .. }
        ));
        a.host = Some("stray".into());
        assert!(conn_config(&a).unwrap_err().contains("--host"));
    }

    #[test]
    fn ssh_defaults_port_22() {
        let mut a = args(ConnKind::Ssh);
        a.host = Some("prod.example.com".into());
        a.user = Some("deploy".into());
        a.secret = Some("DEPLOY_KEY".into());
        a.host_key_fingerprint = Some("SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into());
        match conn_config(&a).unwrap() {
            ConnectionConfig::Ssh { port, .. } => assert_eq!(port, 22),
            other => panic!("wrong config: {other:?}"),
        }
    }
}
