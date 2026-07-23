//! `aka` CLI.
//!
//! - `aka skill` emits the `/instructions` content as a checked-in
//!   skill file, the same content the daemon serves, so the convention
//!   layer can't drift from the daemon.
//! - `aka serve` runs the broker headless, so the whole control plane +
//!   WS/PG data planes can be exercised without the desktop UI (useful for
//!   agent integration and CI).
//! - `aka secret add` / `aka conn add` / `aka conn list`
//!   seed the store from the terminal — the dev/headless counterpart of the
//!   app's Secrets and Connections tabs — with the same validation, so a
//!   `serve --root` harness never hand-writes (sealed) store files.

use std::ops::Deref;
use std::os::unix::fs::FileTypeExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use aka_core::broker::Broker;
use aka_core::config::BrokerConfig;
use aka_core::daemon;
use aka_core::daemon::wellknown;
use aka_core::error::CoreError;
use aka_core::events::BrokerEvents;
use aka_core::paths::{BrokerInstanceLock, Paths};
use aka_core::store::{ConnectionSpec, Store};
use aka_core::types::{ConfirmationMethod, ConnectionConfig, PgSslMode, SecretMeta, SecretValue};
use aka_core::vault::{platform_vault, platform_vault_for_root, SecretVault};
use clap::{Args, Parser, Subcommand, ValueEnum};
use zeroize::Zeroizing;

mod mcp_bridge;

#[derive(Parser)]
#[command(name = "aka", version, about = "AKA broker CLI")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)] // one short-lived instance per invocation
enum Command {
    /// Emit the /instructions content as a skill file. Prints to stdout by
    /// default; `--write` writes .claude/skills/aka/SKILL.md.
    Skill {
        /// Write the file to `path` (default .claude/skills/aka/SKILL.md)
        /// instead of printing to stdout.
        #[arg(long)]
        write: bool,
        /// Override the output path used with --write.
        #[arg(long, conflicts_with = "user")]
        path: Option<PathBuf>,
        /// With --write, target the user-level skills directory
        /// (~/.claude/skills/aka/SKILL.md) instead of the repo-local
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
    /// Run the broker headless (no desktop UI). Every local agent shares
    /// one key (~/.aka/token under the root); tools are enabled for agents
    /// by default and managed remotely via the manage API (`aka manage
    /// token`) or locally from the desktop app.
    Serve {
        /// Use an isolated root dir (data + socket under it) instead of the
        /// default per-user locations. Handy for testing.
        #[arg(long)]
        root: Option<PathBuf>,
        /// Also serve the control plane on this TCP address (e.g.
        /// 127.0.0.1:4780) for remote agents and the remote desktop app.
        /// Put your TLS proxy or tunnel in front of it; /v1/pair is not
        /// served on it.
        #[arg(long)]
        listen: Option<std::net::SocketAddr>,
        /// The URL remote clients reach this broker at (your proxy or
        /// tunnel address); advertised in discovery served over TCP.
        #[arg(long)]
        public_url: Option<String>,
        /// Bind the WS/PG data planes and API direct endpoints to this
        /// address (e.g. 0.0.0.0 or a LAN IP) for remote agents, instead of
        /// loopback. These legs are plaintext — keep them on a trusted
        /// network behind your TLS/tunnel.
        #[arg(long)]
        data_plane_listen: Option<std::net::IpAddr>,
        /// The host to put in returned DSNs / ws:// URLs — what a remote
        /// agent dials (defaults to 127.0.0.1). Usually your broker host's
        /// LAN name or the tunnel address.
        #[arg(long)]
        advertise_host: Option<String>,
        /// Do not start the MCP sidecar even when its script is found.
        #[arg(long)]
        no_sidecar: bool,
    },
    /// Bridge stdio MCP to the local Multitool broker's MCP host. Point any
    /// MCP client at `aka mcp` — it reads this computer's shared key and
    /// discovers the MCP endpoint itself, so configs stay static.
    Mcp {
        /// Bridge to a broker rooted here instead of the default layout.
        #[arg(long)]
        root: Option<PathBuf>,
        /// Label this client in the user's activity log (e.g. claude-code).
        /// Attribution only, never authorization.
        #[arg(long)]
        client: Option<String>,
    },
    /// Manage secrets from the terminal (dev/headless use; the desktop app
    /// is the primary interface).
    Secret {
        #[command(subcommand)]
        command: SecretCommand,
    },
    /// The broker's management plane (the desktop app's remote-management
    /// API).
    Manage {
        #[command(subcommand)]
        command: ManageCommand,
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
enum ManageCommand {
    /// Issue (or rotate) this broker's management token and print it once.
    /// Enter it in the desktop app to manage this broker remotely. Offline:
    /// run on the broker host while the broker is stopped.
    Token {
        /// Revoke the management token instead (closes the manage API).
        #[arg(long)]
        revoke: bool,
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
    /// Omit it to trust on first use: the key the server presents at the
    /// first agent connection is pinned automatically.
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
        Command::Serve {
            root,
            listen,
            public_url,
            data_plane_listen,
            advertise_host,
            no_sidecar,
        } => cmd_serve(ServeArgs {
            root,
            listen,
            public_url,
            data_plane_listen,
            advertise_host,
            no_sidecar,
        }),
        Command::Mcp { root, client } => cmd_mcp(root, client),
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
        Command::Manage {
            command: ManageCommand::Token { revoke, root },
        } => cmd_manage_token(revoke, root),
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
) -> Result<Arc<dyn SecretVault>, aka_core::error::CoreError> {
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
                "no secret named {name:?}; add it first with `aka secret add {name}`"
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

                mcp_path: None,
                oauth: None,
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
        eprintln!("no connections configured (add one with `aka conn add`)");
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
            .join(".claude/skills/aka/SKILL.md"),
        (None, false) => PathBuf::from(".claude/skills/aka/SKILL.md"),
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

/// Headless events: under `serve` no user is at the machine, and gated
/// configuration actions can only arrive through the manage API — so
/// possession of the management token is what authorizes them, and the
/// audit trail records exactly that.
struct CliEvents;

impl BrokerEvents for CliEvents {
    fn confirm_secret_read(&self, secret: &SecretMeta) -> bool {
        eprintln!(
            "  secret read authorized for {} (headless broker; the manage \
             token is the gate)",
            secret.name
        );
        true
    }

    fn confirm_action(&self, _description: &str) -> Option<ConfirmationMethod> {
        Some(ConfirmationMethod::ManagementToken)
    }
}

/// Issue, rotate, or revoke the management token. Offline like `secret add`:
/// a live broker holds identity state in memory and would overwrite the
/// edit, so it must be stopped first.
fn cmd_manage_token(revoke: bool, root: Option<PathBuf>) {
    let paths = store_paths(root.as_deref());
    let _lock = match acquire_offline_store_lock(&paths) {
        Ok(lock) => lock,
        Err(CoreError::BrokerAlreadyRunning(_)) => die(format!(
            "a broker is running on {} — stop it first (its in-memory \
             identity would overwrite this change)",
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
    let integrity = match runtime.block_on(aka_core::integrity::StateIntegrity::open(&*vault)) {
        Ok(integrity) => Arc::new(integrity),
        Err(e) => die(format!("could not open the state integrity key: {e}")),
    };
    let identity = match aka_core::identity::IdentityStore::open(
        paths.identity_file(),
        paths.token_file(),
        Some(&paths.agents_file()),
        BrokerConfig::default().token_ttl,
        integrity,
    ) {
        Ok(identity) => identity,
        Err(e) => die(format!("could not open the broker identity: {e}")),
    };
    if revoke {
        match identity.revoke_manage_token() {
            Ok(true) => eprintln!("management token revoked; the manage API is closed"),
            Ok(false) => eprintln!("no management token was issued"),
            Err(e) => die(e),
        }
        return;
    }
    match identity.issue_manage_token() {
        Ok(token) => {
            eprintln!("management token (shown once — only its hash is stored):\n");
            println!("{token}");
            eprintln!("\nEnter it in the Multitool app to manage this broker remotely.");
            eprintln!("Re-run this command to rotate it, or --revoke to close the manage API.");
        }
        Err(e) => die(e),
    }
}

fn cmd_mcp(root: Option<PathBuf>, client: Option<String>) {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let paths = store_paths(root.as_deref());
    if let Err(message) = runtime.block_on(mcp_bridge::run(paths, client)) {
        die(message);
    }
}

/// Where the MCP sidecar's pieces are, when a checkout or install carries
/// them. `AKA_SIDECAR_SCRIPT`/`AKA_SIDECAR_NODE` override; otherwise the
/// bundled `dist/sidecar/main.mjs` of the working directory is used and
/// `node` resolves through PATH at spawn time.
fn resolve_sidecar(broker_socket: PathBuf) -> Option<aka_core::sidecar::SidecarConfig> {
    let script = match std::env::var_os("AKA_SIDECAR_SCRIPT") {
        Some(script) => {
            let script = PathBuf::from(script);
            if !script.exists() {
                // Warn once here instead of letting the supervisor loop on
                // spawn failures with backoff noise.
                eprintln!(
                    "  MCP host not started: AKA_SIDECAR_SCRIPT={} does not exist",
                    script.display()
                );
                return None;
            }
            script
        }
        None => {
            let bundled = PathBuf::from("dist/sidecar/main.mjs");
            if !bundled.exists() {
                return None;
            }
            bundled
        }
    };
    let node = std::env::var_os("AKA_SIDECAR_NODE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("node"));
    Some(aka_core::sidecar::SidecarConfig {
        node,
        script,
        broker_socket,
    })
}

/// Everything `aka serve` accepts, bundled so the call site stays legible.
struct ServeArgs {
    root: Option<PathBuf>,
    listen: Option<std::net::SocketAddr>,
    public_url: Option<String>,
    data_plane_listen: Option<std::net::IpAddr>,
    advertise_host: Option<String>,
    no_sidecar: bool,
}

fn cmd_serve(args: ServeArgs) {
    let ServeArgs {
        root,
        listen,
        public_url,
        data_plane_listen,
        advertise_host,
        no_sidecar,
    } = args;
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "aka_core=info".into()),
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

    let events: Arc<dyn BrokerEvents> = Arc::new(CliEvents);
    let broker: Arc<Broker> =
        match runtime.block_on(Broker::new(paths, vault, BrokerConfig::default(), events)) {
            Ok(broker) => broker,
            Err(e) => fail("could not start the broker", &e),
        };
    let options = daemon::ServeOptions {
        listen,
        public_url: public_url.clone(),
        data_plane_listen,
        advertise_host: advertise_host.clone(),
    };
    let daemon = match runtime.block_on(daemon::serve_with(broker.clone(), options)) {
        Ok(daemon) => daemon,
        Err(e) => fail("could not serve the control plane", &e),
    };

    // Supervise the MCP sidecar when its script is available, and keep the
    // discovery manifest told where its endpoint is (restarts move the
    // port). Without a script the broker still serves everything but MCP.
    let sidecar = if no_sidecar {
        None
    } else {
        match resolve_sidecar(daemon.socket_path.clone()) {
            Some(config) => {
                let sidecar = runtime.block_on(async {
                    aka_core::sidecar::Sidecar::spawn(config)
                });
                let watch = sidecar.watch();
                let broker_for_watch = broker.clone();
                runtime.spawn(watch.follow(move |endpoint| {
                    broker_for_watch.set_sidecar_mcp_port(endpoint.map(|e| e.port));
                }));
                Some(sidecar)
            }
            None => {
                eprintln!(
                    "  MCP host not started: no sidecar script found (set \
                     AKA_SIDECAR_SCRIPT or run from a checkout with \
                     dist/sidecar/main.mjs built)"
                );
                None
            }
        }
    };

    eprintln!("AKA broker listening on {}", daemon.socket_path.display());
    if let Some(addr) = daemon.tcp_addr {
        eprintln!("  TCP control plane on {addr} (put TLS in front; /v1/pair is not served there)");
        if let Some(host) = &advertise_host {
            eprintln!("  data planes advertised to agents as {host} (WS/PG legs are plaintext)");
        }
        match &public_url {
            Some(url) => eprintln!("  advertised to remote clients as {url}"),
            None => eprintln!("  no --public-url set: TCP discovery omits absolute URLs"),
        }
        eprintln!("  remote management: enter this broker's `aka manage token` in the app");
    }
    eprintln!(
        "  discovery: curl --unix-socket {} http://localhost/instructions",
        daemon.socket_path.display()
    );
    eprintln!(
        "  skill file: `aka skill --write` in a repo (or --write --user) \
         teaches agents this broker"
    );
    eprintln!("  agents authenticate with the shared key at the root's token file");
    eprintln!("  Ctrl-C to quit.\n");

    // Block until Ctrl-C, then drop the daemon handle so it removes only
    // the control-socket inode it owns.
    runtime.block_on(async {
        let _ = tokio::signal::ctrl_c().await;
    });
    drop(sidecar);
    drop(daemon);
}

#[cfg(test)]
mod tests {
    use super::*;
    use aka_core::events::NoopEvents;
    use aka_core::vault::MemoryVault;

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
