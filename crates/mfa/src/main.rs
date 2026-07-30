//! `mfa` CLI.
//!
//! - `mfa skill` emits the `/instructions` content as a checked-in
//!   skill file, the same content the daemon serves, so the convention
//!   layer can't drift from the daemon.
//! - `mfa serve` runs the broker headless, so the whole control plane +
//!   the PG data plane can be exercised without the desktop UI (useful for
//!   agent integration and CI).
//! - `mfa secret add|list|rename|replace|rm` and
//!   `mfa conn add|list|update|rename|rm|enable|disable|test` manage the
//!   store from the terminal — the dev/headless counterpart of the app's
//!   Secrets and Tools tabs — with the same validation, so a `serve --root`
//!   harness never hand-writes (sealed) store files. Mutations beyond
//!   seeding run through the broker's own `ui_*` layer, so audit entries
//!   and access/endpoint side effects cannot drift from the app.
//! - `mfa dsn` / `mfa ssh` open data-plane sessions on a running broker
//!   and print the one value a stock client needs — a ticket-embedded DSN,
//!   an `SSH_AUTH_SOCK` path — so `psql "$(mfa dsn …)"` works as a
//!   one-liner.
//! - `mfa key` / `mfa status` / `mfa activity` are the operator's view:
//!   the shared agent key (and its rotation), whether a broker is up and
//!   what it serves, and the audit trail.
//! - Management commands work online too: against the running local
//!   broker over its socket, or a hosted broker via `--broker <url>` —
//!   both through the manage API, authorized by the management token
//!   (`mfa manage login` stores it). With no broker running they fall
//!   back to the offline construction above.

use std::os::unix::fs::FileTypeExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use aka_api::{ConnectionDto, ManageError, SecretDto};
use aka_client::credentials::TokenStore;
use aka_client::{RemoteBackend, RemoteConfig};
use aka_core::broker::Broker;
use aka_core::config::BrokerConfig;
use aka_core::daemon;
use aka_core::daemon::wellknown;
use aka_core::error::CoreError;
use aka_core::events::BrokerEvents;
use aka_core::manage::{LocalBackend, ManageResult, ManagementBackend};
use aka_core::paths::{BrokerInstanceLock, Paths};
use aka_core::store::ConnectionSpec;
use aka_core::types::{
    ConfirmationMethod, ConnectionConfig, OAuthSpec, PgSslMode, SecretMeta, SecretValue,
};
use aka_core::vault::{platform_vault, platform_vault_for_root, SecretVault};
use clap::{Args, Parser, Subcommand, ValueEnum};
use uuid::Uuid;
use zeroize::Zeroizing;

mod client;
mod mcp_bridge;

#[derive(Parser)]
#[command(name = "mfa", version, about = "AgentMFA broker CLI")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)] // one short-lived instance per invocation
enum Command {
    /// Emit the /instructions content as a skill file. Prints to stdout by
    /// default; `--write` writes .claude/skills/mfa/SKILL.md.
    Skill {
        /// Write the file to `path` (default .claude/skills/mfa/SKILL.md)
        /// instead of printing to stdout.
        #[arg(long)]
        write: bool,
        /// Override the output path used with --write.
        #[arg(long, conflicts_with = "user")]
        path: Option<PathBuf>,
        /// With --write, target the user-level skills directory
        /// (~/.claude/skills/mfa/SKILL.md) instead of the repo-local
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
    /// by default and managed remotely via the manage API (`mfa manage
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
        /// Bind the PG data plane and API direct endpoints to this
        /// address (e.g. 0.0.0.0 or a LAN IP) for remote agents, instead of
        /// loopback. These legs are plaintext, so a non-loopback value is
        /// refused unless --data-plane-insecure says you accept that; keep it
        /// on a trusted network behind your TLS/tunnel.
        #[arg(long)]
        data_plane_listen: Option<std::net::IpAddr>,
        /// The host to put in returned DSNs and endpoint URLs — what a remote
        /// agent dials (defaults to 127.0.0.1). Usually your broker host's
        /// LAN name or the tunnel address.
        #[arg(long)]
        advertise_host: Option<String>,
        /// Accept that a non-loopback --data-plane-listen puts the Postgres
        /// ticket, statements, and results on the network in clear text. The
        /// bind is refused without this.
        #[arg(long)]
        data_plane_insecure: bool,
        /// Tear a brokered session down after this many seconds with the
        /// backend idle and the client silent (default 300). Raise it for
        /// LISTEN/NOTIFY workloads, which are protocol-idle while waiting.
        #[arg(long, value_name = "SECS")]
        session_idle_timeout: Option<u64>,
        /// Hard ceiling on one brokered session, in seconds (default 3600).
        /// Raise it for long COPY/pg_dump runs, which are severed mid-stream
        /// when it expires.
        #[arg(long, value_name = "SECS")]
        session_max_ttl: Option<u64>,
        /// Record the SQL of each statement on a brokered Postgres session in
        /// the activity log. Off by default: statement text can carry
        /// credentials and personal data into a durable log.
        #[arg(long)]
        audit_pg_statements: bool,
        /// Do not start the MCP sidecar even when its script is found.
        #[arg(long)]
        no_sidecar: bool,
    },
    /// Bridge stdio MCP to the local AgentMFA broker's MCP host. Point any
    /// MCP client at `mfa mcp` — it reads this computer's shared key and
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
    /// Open a Postgres session on a running broker and print a ready-to-run
    /// DSN with the short-lived session ticket embedded:
    /// `psql "$(mfa dsn analytics)"`. The ticket sits in ps-visible argv
    /// and shell history for its short window; POST /v1/pg/open with
    /// PGPASSWORD keeps it out when that matters.
    Dsn {
        /// The pg connection's name.
        connection: String,
        /// Open against a broker rooted here instead of the default layout.
        #[arg(long)]
        root: Option<PathBuf>,
        /// Label this client in the user's activity log (e.g. claude-code).
        /// Attribution only, never authorization.
        #[arg(long)]
        client: Option<String>,
    },
    /// Open an SSH session on a running broker and print the agent socket
    /// path: `export SSH_AUTH_SOCK="$(mfa ssh production)"` — then stock
    /// `ssh`/`git`/`scp`/`rsync` work while the broker signs only for the
    /// connection's pinned user and server host key. The command prints the
    /// destination, the pinned fingerprint, the absolute deadline, and the
    /// `-o` flags to pass; add those flags, or a working on-disk key can
    /// authenticate the login instead with no broker involvement.
    Ssh {
        /// The ssh connection's name.
        connection: String,
        /// Open against a broker rooted here instead of the default layout.
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
    /// Print this computer's shared agent key — what agents send as their
    /// Bearer token, and what remote agents need from the operator.
    Key {
        /// Rotate the key instead: agents' old keys stop working, and
        /// agents that read the token file reconnect on their own.
        /// Offline: stop the broker first.
        #[arg(long)]
        rotate: bool,
        /// Operate on a broker rooted here instead of the default layout.
        #[arg(long)]
        root: Option<PathBuf>,
        /// Manage the broker at this manage-API URL instead of this
        /// machine's.
        #[arg(long)]
        broker: Option<String>,
    },
    /// Report whether a broker is running on this layout and what it
    /// serves (MCP host, tools, key file). Exits nonzero when none is up.
    Status {
        /// Check a broker rooted here instead of the default layout.
        #[arg(long)]
        root: Option<PathBuf>,
        /// Manage the broker at this manage-API URL instead of this
        /// machine's.
        #[arg(long)]
        broker: Option<String>,
    },
    /// Show the broker's audit trail, newest last. Reads the append-only
    /// log directly, so it works while the broker is running.
    Activity {
        /// Show only the last N entries; 0 shows everything.
        #[arg(long, default_value_t = 20)]
        limit: usize,
        /// Print the raw JSON lines instead of formatted text.
        #[arg(long)]
        json: bool,
        /// Read a broker rooted here instead of the default layout.
        #[arg(long)]
        root: Option<PathBuf>,
        /// Manage the broker at this manage-API URL instead of this
        /// machine's.
        #[arg(long)]
        broker: Option<String>,
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
        /// Manage the broker at this manage-API URL instead of this
        /// machine's.
        #[arg(long)]
        broker: Option<String>,
    },
    /// List secrets and the connections using them.
    List {
        /// Operate on a broker rooted here instead of the default layout.
        #[arg(long)]
        root: Option<PathBuf>,
        /// Manage the broker at this manage-API URL instead of this
        /// machine's.
        #[arg(long)]
        broker: Option<String>,
    },
    /// Rename a secret; every injection template referencing it is
    /// rewritten atomically with the rename.
    Rename {
        /// The secret's current name.
        name: String,
        /// The new name.
        new_name: String,
        /// Operate on a broker rooted here instead of the default layout.
        #[arg(long)]
        root: Option<PathBuf>,
        /// Manage the broker at this manage-API URL instead of this
        /// machine's.
        #[arg(long)]
        broker: Option<String>,
    },
    /// Replace a secret's value (rotation). Like add, the value is read
    /// from stdin or --value-env, never from argv.
    Replace {
        /// The secret to rotate.
        name: String,
        /// Read the value from this environment variable instead of stdin.
        #[arg(long, value_name = "VAR")]
        value_env: Option<String>,
        /// Operate on a broker rooted here instead of the default layout.
        #[arg(long)]
        root: Option<PathBuf>,
        /// Manage the broker at this manage-API URL instead of this
        /// machine's.
        #[arg(long)]
        broker: Option<String>,
    },
    /// Delete a secret. Refused while a connection still uses it.
    Rm {
        /// The secret to delete.
        name: String,
        /// Operate on a broker rooted here instead of the default layout.
        #[arg(long)]
        root: Option<PathBuf>,
        /// Manage the broker at this manage-API URL instead of this
        /// machine's.
        #[arg(long)]
        broker: Option<String>,
    },
}

#[derive(Subcommand)]
enum ManageCommand {
    /// Store a management token so management commands can drive a broker
    /// while it runs — this machine's broker over its socket, or a hosted
    /// one by URL. The token is read from stdin (or --token-env), never
    /// argv, and is verified against the broker when it is reachable.
    Login {
        /// The hosted broker's manage URL; omit to store the token for
        /// this machine's broker (keyed by its socket path).
        #[arg(long)]
        broker: Option<String>,
        /// Read the token from this environment variable instead of stdin.
        #[arg(long, value_name = "VAR")]
        token_env: Option<String>,
        /// Operate on a broker rooted here instead of the default layout.
        #[arg(long)]
        root: Option<PathBuf>,
    },
    /// Forget a stored management token.
    Logout {
        /// The hosted broker's manage URL; omit for this machine's broker.
        #[arg(long)]
        broker: Option<String>,
        /// Operate on a broker rooted here instead of the default layout.
        #[arg(long)]
        root: Option<PathBuf>,
    },
    /// Issue (or rotate) this broker's management token and print it once.
    /// Enter it in the desktop app to manage this broker remotely. Offline:
    /// run on the broker host while the broker is stopped.
    Token {
        /// Revoke the management token instead (closes the manage API).
        #[arg(long)]
        revoke: bool,
        /// Expire the token this many days after issue (bounds a leaked
        /// token's blast radius). Omit for a token that never expires; the
        /// desktop app re-prompts for a fresh one when it does.
        #[arg(long, conflicts_with = "revoke")]
        ttl_days: Option<u64>,
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
        /// Manage the broker at this manage-API URL instead of this
        /// machine's.
        #[arg(long)]
        broker: Option<String>,
    },
    /// Update fields on a connection (its kind is fixed). Only the flags
    /// you pass change; changing the destination revokes the tool's direct
    /// endpoints, exactly as in the app.
    Update(ConnUpdate),
    /// Rename a connection without touching its capability fields.
    Rename {
        /// The connection's current name.
        name: String,
        /// The new name.
        new_name: String,
        /// Operate on a broker rooted here instead of the default layout.
        #[arg(long)]
        root: Option<PathBuf>,
        /// Manage the broker at this manage-API URL instead of this
        /// machine's.
        #[arg(long)]
        broker: Option<String>,
    },
    /// Delete a connection. Its agent access and direct endpoints die with
    /// it; its secrets stay in the vault.
    Rm {
        /// The connection to delete.
        name: String,
        /// Operate on a broker rooted here instead of the default layout.
        #[arg(long)]
        root: Option<PathBuf>,
        /// Manage the broker at this manage-API URL instead of this
        /// machine's.
        #[arg(long)]
        broker: Option<String>,
    },
    /// Enable agent access for a connection: calls execute immediately,
    /// for every agent at once.
    Enable {
        /// The connection to enable.
        name: String,
        /// Operate on a broker rooted here instead of the default layout.
        #[arg(long)]
        root: Option<PathBuf>,
        /// Manage the broker at this manage-API URL instead of this
        /// machine's.
        #[arg(long)]
        broker: Option<String>,
    },
    /// Ask the user to confirm this connection's traffic before it goes
    /// anywhere, or stop asking. What gets confirmed depends on the kind:
    /// one request for an API tool, one `tools/call` for an MCP tool, one
    /// session for Postgres. An attached AgentMFA app answers prompts; a
    /// broker with no attached approval surface refuses the traffic.
    Confirm {
        /// The connection to change.
        name: String,
        /// Stop confirming (the default is to start).
        #[arg(long)]
        off: bool,
        /// Operate on a broker rooted here instead of the default layout.
        #[arg(long)]
        root: Option<PathBuf>,
        /// Manage the broker at this manage-API URL instead of this
        /// machine's.
        #[arg(long)]
        broker: Option<String>,
    },
    /// Disable agent access for a connection: every agent's calls are
    /// refused with 403 denied_by_policy until re-enabled.
    Disable {
        /// The connection to disable.
        name: String,
        /// Operate on a broker rooted here instead of the default layout.
        #[arg(long)]
        root: Option<PathBuf>,
        /// Manage the broker at this manage-API URL instead of this
        /// machine's.
        #[arg(long)]
        broker: Option<String>,
    },
    /// Test a connection against its pinned destination with its stored
    /// credential (the credential travels only on the upstream leg).
    /// Exits nonzero when the test fails.
    Test {
        /// The connection to test.
        name: String,
        /// Operate on a broker rooted here instead of the default layout.
        #[arg(long)]
        root: Option<PathBuf>,
        /// Manage the broker at this manage-API URL instead of this
        /// machine's.
        #[arg(long)]
        broker: Option<String>,
    },
    /// Print the connection's already-issued direct endpoint: the pasteable
    /// address and its endpoint secret. Read-only — issue or rotate the
    /// endpoint from the desktop app. Like the other `conn` subcommands this
    /// reads the offline store, so stop the broker first. Exits nonzero when
    /// no endpoint has been issued yet.
    Endpoint {
        /// The connection whose endpoint to print.
        name: String,
        /// Print only the pasteable address (the base URL / DSN / agent
        /// socket), for `$(mfa conn endpoint <name> --url)`.
        #[arg(long, conflicts_with = "secret")]
        url: bool,
        /// Print only the endpoint secret (empty for SSH, whose socket path
        /// is the whole capability), for scripting.
        #[arg(long)]
        secret: bool,
        /// Operate on a broker rooted here instead of the default layout.
        #[arg(long)]
        root: Option<PathBuf>,
        /// Read from the broker at this manage-API URL instead of this
        /// machine's.
        #[arg(long)]
        broker: Option<String>,
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
    /// {{refs}} name the secrets.
    /// referencing exactly one secret (default: Authorization Bearer).
    #[arg(long)]
    template: Option<String>,
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
    /// pg/ssh: name of the one bound secret (api connections derive
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
    /// api: expose this connection as an MCP server by giving the upstream's
    /// JSON-RPC path (e.g. `/mcp`). The sidecar then re-exposes its tools;
    /// the credential still rides the pinned host's `/v1/http` plane.
    #[arg(long)]
    mcp_path: Option<String>,
    /// Operate on a broker rooted here instead of the default layout.
    #[arg(long)]
    root: Option<PathBuf>,
    /// Manage the broker at this manage-API URL instead of this
    /// machine's.
    #[arg(long)]
    broker: Option<String>,
}

#[derive(ValueEnum, Clone, Copy)]
enum ConnKind {
    Api,
    Pg,
    Ssh,
}

/// `conn update`: the same field flags as `conn add`, all optional — the
/// kind comes from the existing connection and unspecified flags keep
/// their current values.
#[derive(Args)]
struct ConnUpdate {
    /// The connection to update.
    name: String,
    /// api/pg/ssh: upstream host (bare hostname, no scheme/port/path).
    #[arg(long)]
    host: Option<String>,
    /// api: "https" or "http" (dev/test upstreams).
    #[arg(long)]
    scheme: Option<String>,
    /// Upstream port.
    #[arg(long)]
    port: Option<u16>,
    /// api: injection template, e.g. 'Authorization: Bearer {{KEY}}'.
    #[arg(long)]
    template: Option<String>,
    /// pg: database name.
    #[arg(long)]
    dbname: Option<String>,
    /// pg/ssh: login user.
    #[arg(long)]
    user: Option<String>,
    /// ssh: pinned server host key fingerprint (SHA256:... or SHA512:...).
    /// Pass '' to clear the pin: the key the server presents at the next
    /// agent connection is pinned again.
    #[arg(long)]
    host_key_fingerprint: Option<String>,
    /// pg/ssh: rebind to this secret (api connections derive theirs
    /// from the template).
    #[arg(long)]
    secret: Option<String>,
    /// pg: disable | prefer | require | verify-ca | verify-full.
    #[arg(long)]
    sslmode: Option<String>,
    /// pg: PEM bundle for a private certificate authority; pass '' to
    /// clear it.
    #[arg(long)]
    ca_bundle: Option<String>,
    /// Operate on a broker rooted here instead of the default layout.
    #[arg(long)]
    root: Option<PathBuf>,
    /// Manage the broker at this manage-API URL instead of this
    /// machine's.
    #[arg(long)]
    broker: Option<String>,
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
            data_plane_insecure,
            session_idle_timeout,
            session_max_ttl,
            audit_pg_statements,
            no_sidecar,
        } => cmd_serve(ServeArgs {
            root,
            listen,
            public_url,
            data_plane_listen,
            advertise_host,
            data_plane_insecure,
            session_idle_timeout,
            session_max_ttl,
            audit_pg_statements,
            no_sidecar,
        }),
        Command::Mcp { root, client } => cmd_mcp(root, client),
        Command::Dsn {
            connection,
            root,
            client,
        } => cmd_dsn(connection, root, client),
        Command::Ssh {
            connection,
            root,
            client,
        } => cmd_ssh(connection, root, client),
        Command::Secret { command } => match command {
            SecretCommand::Add {
                name,
                value_env,
                root,
                broker,
            } => cmd_secret_add(name, value_env, root, broker),
            SecretCommand::List { root, broker } => cmd_secret_list(root, broker),
            SecretCommand::Rename {
                name,
                new_name,
                root,
                broker,
            } => cmd_secret_rename(name, new_name, root, broker),
            SecretCommand::Replace {
                name,
                value_env,
                root,
                broker,
            } => cmd_secret_replace(name, value_env, root, broker),
            SecretCommand::Rm { name, root, broker } => cmd_secret_rm(name, root, broker),
        },
        Command::Conn { command } => match command {
            ConnCommand::Add(args) => cmd_conn_add(args),
            ConnCommand::List { root, broker } => cmd_conn_list(root, broker),
            ConnCommand::Update(args) => cmd_conn_update(args),
            ConnCommand::Rename {
                name,
                new_name,
                root,
                broker,
            } => cmd_conn_rename(name, new_name, root, broker),
            ConnCommand::Rm { name, root, broker } => cmd_conn_rm(name, root, broker),
            ConnCommand::Enable { name, root, broker } => cmd_conn_access(name, root, broker, true),
            ConnCommand::Disable { name, root, broker } => {
                cmd_conn_access(name, root, broker, false)
            }
            ConnCommand::Confirm {
                name,
                off,
                root,
                broker,
            } => cmd_conn_confirm(name, root, broker, !off),
            ConnCommand::Test { name, root, broker } => cmd_conn_test(name, root, broker),
            ConnCommand::Endpoint {
                name,
                url,
                secret,
                root,
                broker,
            } => cmd_conn_endpoint(name, url, secret, root, broker),
        },
        Command::Manage { command } => match command {
            ManageCommand::Login {
                broker,
                token_env,
                root,
            } => cmd_manage_login(broker, token_env, root),
            ManageCommand::Logout { broker, root } => cmd_manage_logout(broker, root),
            ManageCommand::Token {
                revoke,
                ttl_days,
                root,
            } => cmd_manage_token(revoke, ttl_days, root),
        },
        Command::Key {
            rotate,
            root,
            broker,
        } => cmd_key(rotate, root, broker),
        Command::Status { root, broker } => cmd_status(root, broker),
        Command::Activity {
            limit,
            json,
            root,
            broker,
        } => cmd_activity(limit, json, root, broker),
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

/// Read a secret value from `--value-env` or stdin — never argv, where it
/// would sit in `ps` output and shell history.
fn read_secret_value(value_env: &Option<String>) -> SecretValue {
    let value: SecretValue = match value_env {
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
    value
}

fn cmd_secret_add(
    name: String,
    value_env: Option<String>,
    root: Option<PathBuf>,
    url: Option<String>,
) {
    let value = read_secret_value(&value_env);
    let managed = management_backend(root, url);
    managed.run(managed.backend.add_secret(name.clone(), value));
    eprintln!("added secret {name}");
}

fn cmd_secret_list(root: Option<PathBuf>, url: Option<String>) {
    let managed = management_backend(root, url);
    let secrets = managed.run(managed.backend.list_secrets());
    if secrets.is_empty() {
        eprintln!("no secrets configured (add one with `mfa secret add <name>`)");
        return;
    }
    for dto in secrets {
        if dto.used_by_names.is_empty() {
            println!("{}", dto.name);
        } else {
            println!("{}  used by {}", dto.name, dto.used_by_names.join(", "));
        }
    }
}

/// A management backend plus the runtime driving it. Every mode routes
/// through the broker's own management layer — the same audit entries and
/// side effects as the app — the modes differ only in how calls reach it.
struct Managed {
    runtime: tokio::runtime::Runtime,
    backend: Arc<dyn ManagementBackend>,
}

impl Managed {
    /// Run one management call to completion; a failure exits with the
    /// broker's own error line.
    fn run<T>(&self, call: impl std::future::Future<Output = ManageResult<T>>) -> T {
        match self.runtime.block_on(call) {
            Ok(value) => value,
            Err(e) => die(e),
        }
    }
}

fn manage_token_store(paths: &Paths) -> TokenStore {
    TokenStore::new(paths.manage_tokens_dir())
}

/// Resolve the management token for `key` (a manage URL, or the local
/// socket path): the AKA_MANAGE_TOKEN environment variable wins, then the
/// token stored by `mfa manage login`.
fn manage_token(paths: &Paths, key: &str) -> Option<Zeroizing<String>> {
    if let Ok(token) = std::env::var("AKA_MANAGE_TOKEN") {
        let token = token.trim().to_string();
        if !token.is_empty() {
            return Some(Zeroizing::new(token));
        }
    }
    manage_token_store(paths).load(key)
}

/// Pick how a management command reaches its broker:
/// - `--url` → that broker's manage API over HTTP (a hosted broker, or a
///   local one serving `--listen`);
/// - no URL with a broker running on the socket → its manage API over the
///   Unix socket, so live edits need no stop/start. The management token
///   still authorizes every call: the 0600 socket is shared with agents,
///   which must never reach the manage plane;
/// - no broker running → construct the broker offline, as before.
fn management_backend(root: Option<PathBuf>, url: Option<String>) -> Managed {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let paths = store_paths(root.as_deref());
    if let Some(url) = url {
        let url = match RemoteConfig::normalize_url(&url) {
            Ok(url) => url,
            Err(e) => die(e),
        };
        let Some(token) = manage_token(&paths, &url) else {
            die(format!(
                "no management token for {url} — set AKA_MANAGE_TOKEN, or store \
                 one with `mfa manage login --broker {url}` (issued by `mfa \
                 manage token` on the broker host)"
            ));
        };
        let config = match RemoteConfig::new(&url, &token) {
            Ok(config) => config,
            Err(e) => die(e),
        };
        eprintln!("  managing the broker at {url}");
        return Managed {
            runtime,
            backend: Arc::new(RemoteBackend::new(config)),
        };
    }
    let socket = paths.socket_file();
    let broker_running = runtime
        .block_on(tokio::net::UnixStream::connect(&socket))
        .is_ok();
    if broker_running {
        let key = socket.display().to_string();
        let Some(token) = manage_token(&paths, &key) else {
            die(format!(
                "a broker is running on {key}.\n\
                 To edit it live, store its management token with `mfa manage \
                 login` (issue one with `mfa manage token` while the broker is \
                 stopped) or set AKA_MANAGE_TOKEN — or stop the broker for an \
                 offline edit."
            ));
        };
        eprintln!("  managing the running broker over {key}");
        return Managed {
            runtime,
            backend: Arc::new(RemoteBackend::over_unix_socket(socket, &token)),
        };
    }
    let vault = match open_vault(&paths, root.as_deref()) {
        Ok(vault) => vault,
        Err(e) => die(format!("could not open the secret vault: {e}")),
    };
    let events: Arc<dyn BrokerEvents> = Arc::new(OfflineEvents);
    let broker = match runtime.block_on(Broker::new_for_offline_management(
        paths.clone(),
        vault,
        BrokerConfig::default(),
        events,
    )) {
        Ok(broker) => broker,
        Err(CoreError::BrokerAlreadyRunning(_)) => die(format!(
            "a broker started on {} while this command was connecting — retry \
             to manage it live, or stop it for an offline edit",
            paths.socket_file().display()
        )),
        Err(e) => die(format!("could not open the broker state: {e}")),
    };
    Managed {
        runtime,
        backend: Arc::new(LocalBackend::new(broker)),
    }
}

/// Events for offline lifecycle edits: the operator typed the command on
/// the broker host, and local file access is what the platform gates — the
/// typed command is the deliberate act a confirmation would otherwise ask
/// for.
struct OfflineEvents;

impl BrokerEvents for OfflineEvents {
    fn confirm_secret_read(&self, secret: &SecretMeta) -> bool {
        eprintln!(
            "  secret read authorized for {} (offline edit)",
            secret.name
        );
        true
    }

    fn confirm_action(&self, _description: &str) -> Option<ConfirmationMethod> {
        Some(ConfirmationMethod::Terminal)
    }
}

/// Parse an id the broker handed out; it minted it, so failure is a wire
/// bug worth naming, not a user error.
fn dto_id(id: &str) -> Uuid {
    id.parse()
        .unwrap_or_else(|_| die(format!("malformed id {id:?} from the broker")))
}

fn secret_dto(managed: &Managed, name: &str) -> SecretDto {
    let secrets = managed.run(managed.backend.list_secrets());
    match secrets.into_iter().find(|s| s.name == name) {
        Some(dto) => dto,
        None => die(format!("no secret named {name:?} (see `mfa secret list`)")),
    }
}

fn conn_dto(managed: &Managed, name: &str) -> ConnectionDto {
    let connections = managed.run(managed.backend.list_connections());
    match connections.into_iter().find(|c| c.name == name) {
        Some(dto) => dto,
        None => die(format!(
            "no connection named {name:?} (see `mfa conn list`)"
        )),
    }
}

/// Resolve secret names to ids in one listing round trip (keeping a
/// connection's existing bindings across an update).
fn secret_ids_by_names(managed: &Managed, names: &[String]) -> Vec<Uuid> {
    let secrets = managed.run(managed.backend.list_secrets());
    names
        .iter()
        .map(|name| match secrets.iter().find(|s| &s.name == name) {
            Some(dto) => dto_id(&dto.id),
            None => die(format!("no secret named {name:?} (see `mfa secret list`)")),
        })
        .collect()
}

fn cmd_secret_rename(name: String, new_name: String, root: Option<PathBuf>, url: Option<String>) {
    let managed = management_backend(root, url);
    let dto = secret_dto(&managed, &name);
    managed.run(
        managed
            .backend
            .edit_secret(dto_id(&dto.id), Some(new_name.clone()), None),
    );
    eprintln!("renamed secret {name} → {new_name}");
}

fn cmd_secret_replace(
    name: String,
    value_env: Option<String>,
    root: Option<PathBuf>,
    url: Option<String>,
) {
    let value = read_secret_value(&value_env);
    let managed = management_backend(root, url);
    let dto = secret_dto(&managed, &name);
    managed.run(
        managed
            .backend
            .edit_secret(dto_id(&dto.id), None, Some(value)),
    );
    eprintln!("replaced the value of secret {name}");
}

fn cmd_secret_rm(name: String, root: Option<PathBuf>, url: Option<String>) {
    let managed = management_backend(root, url);
    let dto = secret_dto(&managed, &name);
    managed.run(managed.backend.delete_secret(dto_id(&dto.id)));
    eprintln!("deleted secret {name}");
}

fn cmd_conn_add(args: ConnAdd) {
    let config = match conn_config(&args) {
        Ok(config) => config,
        Err(e) => die(e),
    };
    let managed = management_backend(args.root.clone(), args.broker.clone());
    // pg/ssh bind at most one secret by name; api derives its secrets
    // from the template's refs inside add_connection.
    let secrets = match (&args.secret, args.kind) {
        (_, ConnKind::Api) => Vec::new(),
        (Some(name), _) => vec![dto_id(&secret_dto(&managed, name).id)],
        (None, _) => Vec::new(),
    };
    let name = args.name.clone();
    managed.run(managed.backend.add_connection(ConnectionSpec {
        name: name.clone(),
        config,
        secrets,
    }));
    let dto = conn_dto(&managed, &name);
    eprintln!(
        "added connection {} ({} · {})",
        dto.name, dto.kind, dto.target
    );
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
                ("dbname", args.dbname.is_some()),
                ("user", args.user.is_some()),
                ("secret", args.secret.is_some()),
                ("sslmode", args.sslmode.is_some()),
                ("host-key-fingerprint", args.host_key_fingerprint.is_some()),
            ])?;
            Ok(ConnectionConfig::Api {
                host: require("host", &args.host)?,
                scheme: args.scheme.clone().unwrap_or_else(|| "https".into()),
                port: args.port,
                trusted_ca_bundle_path: args.ca_bundle.clone(),
                template: require("template", &args.template)?,

                mcp_path: args.mcp_path.clone(),
                oauth: None,
            })
        }
        ConnKind::Pg => {
            forbid(&[
                ("scheme", args.scheme.is_some()),
                ("template", args.template.is_some()),
                ("host-key-fingerprint", args.host_key_fingerprint.is_some()),
                ("mcp-path", args.mcp_path.is_some()),
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
        ConnKind::Ssh => {
            forbid(&[
                ("scheme", args.scheme.is_some()),
                ("template", args.template.is_some()),
                ("dbname", args.dbname.is_some()),
                ("sslmode", args.sslmode.is_some()),
                ("ca-bundle", args.ca_bundle.is_some()),
                ("mcp-path", args.mcp_path.is_some()),
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

fn cmd_conn_list(root: Option<PathBuf>, url: Option<String>) {
    let managed = management_backend(root, url);
    let connections = managed.run(managed.backend.list_connections());
    if connections.is_empty() {
        eprintln!("no connections configured (add one with `mfa conn add`)");
        return;
    }
    for dto in connections {
        let state = if dto.agent_access.enabled {
            ""
        } else {
            "  disabled"
        };
        println!("{}  {}  {}{}", dto.name, dto.kind, dto.target, state);
    }
}

/// Rebuild a connection's `ConnectionConfig` from its listing DTO, so
/// `conn update` can merge flags over it in any mode. The DTO carries every
/// field the CLI manages; OAuth-managed connections are refused before this
/// runs (their credential config cannot be reconstructed client-side).
fn config_from_dto(dto: &ConnectionDto) -> Result<ConnectionConfig, String> {
    let need = |field: &str, value: &Option<String>| -> Result<String, String> {
        value
            .clone()
            .ok_or_else(|| format!("the broker's listing omitted {field} for {}", dto.name))
    };
    let need_port = || -> Result<u16, String> {
        dto.port
            .ok_or_else(|| format!("the broker's listing omitted port for {}", dto.name))
    };
    match dto.kind.as_str() {
        "api" => Ok(ConnectionConfig::Api {
            host: need("host", &dto.host)?,
            scheme: need("scheme", &dto.scheme)?,
            port: dto.port,
            trusted_ca_bundle_path: dto.trusted_ca_bundle_path.clone(),
            template: need("template", &dto.template)?,
            mcp_path: dto.mcp_path.clone(),
            oauth: dto.oauth_spec.as_ref().map(|oauth| OAuthSpec {
                auth_url: oauth.auth_url.clone(),
                token_url: oauth.token_url.clone(),
                client_id: oauth.client_id.clone(),
                scopes: oauth.scopes.clone(),
                extra_auth_params: oauth.extra_auth_params.clone(),
                token_secret_id: None,
            }),
        }),
        "pg" => Ok(ConnectionConfig::Pg {
            host: need("host", &dto.host)?,
            port: need_port()?,
            dbname: need("dbname", &dto.dbname)?,
            user: need("user", &dto.user)?,
            sslmode: parse_sslmode(dto.sslmode.as_deref())?,
            trusted_ca_bundle_path: dto.trusted_ca_bundle_path.clone(),
        }),
        "ssh" => Ok(ConnectionConfig::Ssh {
            destination: dto.destination.clone(),
            host: need("host", &dto.host)?,
            port: need_port()?,
            user: need("user", &dto.user)?,
            host_key_fingerprint: dto.host_key_fingerprint.clone().unwrap_or_default(),
        }),
        other => Err(format!("unknown connection kind {other:?}")),
    }
}

/// The CLI edits capability fields; a broker-managed OAuth grant is not
/// reconstructible client-side, so those connections are app-managed.
fn refuse_oauth_managed(dto: &ConnectionDto) {
    if dto.oauth || dto.oauth_spec.is_some() {
        die(format!(
            "{} is an OAuth-managed connection; edit it in the AgentMFA app",
            dto.name
        ));
    }
}

/// Build `conn update`'s new config: the existing config with the given
/// flags overlaid, naming any flag stray for the kind. Fields the CLI does
/// not manage (api `mcp_path`/`oauth`, ssh `destination`) carry over
/// untouched; the deep validation stays in the store, one place.
fn merged_config(
    existing: &ConnectionConfig,
    args: &ConnUpdate,
) -> Result<ConnectionConfig, String> {
    let forbid = |present: &[(&str, bool)]| -> Result<(), String> {
        match present.iter().find(|(_, given)| *given) {
            Some((flag, _)) => Err(format!("--{flag} does not apply to this connection's kind")),
            None => Ok(()),
        }
    };
    let keep = |new: &Option<String>, current: &str| -> String {
        new.clone().unwrap_or_else(|| current.to_string())
    };
    match existing {
        ConnectionConfig::Api {
            host,
            scheme,
            port,
            trusted_ca_bundle_path,
            template,
            mcp_path,
            oauth,
        } => {
            forbid(&[
                ("dbname", args.dbname.is_some()),
                ("user", args.user.is_some()),
                ("secret", args.secret.is_some()),
                ("sslmode", args.sslmode.is_some()),
                ("host-key-fingerprint", args.host_key_fingerprint.is_some()),
            ])?;
            Ok(ConnectionConfig::Api {
                host: keep(&args.host, host),
                scheme: keep(&args.scheme, scheme),
                port: args.port.or(*port),
                trusted_ca_bundle_path: match &args.ca_bundle {
                    Some(path) if path.is_empty() => None,
                    Some(path) => Some(path.clone()),
                    None => trusted_ca_bundle_path.clone(),
                },
                template: keep(&args.template, template),
                mcp_path: mcp_path.clone(),
                oauth: oauth.clone(),
            })
        }
        ConnectionConfig::Pg {
            host,
            port,
            dbname,
            user,
            sslmode,
            trusted_ca_bundle_path,
        } => {
            forbid(&[
                ("scheme", args.scheme.is_some()),
                ("template", args.template.is_some()),
                ("host-key-fingerprint", args.host_key_fingerprint.is_some()),
            ])?;
            Ok(ConnectionConfig::Pg {
                host: keep(&args.host, host),
                port: args.port.unwrap_or(*port),
                dbname: keep(&args.dbname, dbname),
                user: keep(&args.user, user),
                sslmode: match args.sslmode.as_deref() {
                    Some(value) => parse_sslmode(Some(value))?,
                    None => *sslmode,
                },
                trusted_ca_bundle_path: match &args.ca_bundle {
                    Some(path) if path.is_empty() => None,
                    Some(path) => Some(path.clone()),
                    None => trusted_ca_bundle_path.clone(),
                },
            })
        }
        ConnectionConfig::Ssh {
            destination,
            host,
            port,
            user,
            host_key_fingerprint,
        } => {
            forbid(&[
                ("scheme", args.scheme.is_some()),
                ("template", args.template.is_some()),
                ("dbname", args.dbname.is_some()),
                ("sslmode", args.sslmode.is_some()),
                ("ca-bundle", args.ca_bundle.is_some()),
            ])?;
            Ok(ConnectionConfig::Ssh {
                destination: destination.clone(),
                host: keep(&args.host, host),
                port: args.port.unwrap_or(*port),
                user: keep(&args.user, user),
                // '' clears the pin: the next agent connection re-pins the
                // observed key.
                host_key_fingerprint: keep(&args.host_key_fingerprint, host_key_fingerprint),
            })
        }
    }
}

fn cmd_conn_update(args: ConnUpdate) {
    let managed = management_backend(args.root.clone(), args.broker.clone());
    let dto = conn_dto(&managed, &args.name);
    refuse_oauth_managed(&dto);
    let existing = match config_from_dto(&dto) {
        Ok(config) => config,
        Err(e) => die(e),
    };
    let config = match merged_config(&existing, &args) {
        Ok(config) => config,
        Err(e) => die(e),
    };
    // api derives its secrets from the template; pg/ssh rebind when
    // --secret is given and keep the current binding otherwise.
    let secrets = match (&args.secret, dto.kind.as_str()) {
        (_, "api") => Vec::new(),
        (Some(name), _) => vec![dto_id(&secret_dto(&managed, name).id)],
        (None, _) => secret_ids_by_names(&managed, &dto.secret_names),
    };
    managed.run(managed.backend.update_connection(
        dto_id(&dto.id),
        ConnectionSpec {
            name: dto.name.clone(),
            config,
            secrets,
        },
    ));
    let updated = conn_dto(&managed, &dto.name);
    eprintln!(
        "updated connection {} ({} · {})",
        updated.name, updated.kind, updated.target
    );
    if updated.target != dto.target {
        eprintln!("  target changed: its direct endpoints are revoked");
    }
}

fn cmd_conn_rename(name: String, new_name: String, root: Option<PathBuf>, url: Option<String>) {
    let managed = management_backend(root, url);
    let dto = conn_dto(&managed, &name);
    let config = match config_from_dto(&dto) {
        Ok(config) => config,
        Err(e) => die(e),
    };
    let secrets = if dto.kind == "api" {
        Vec::new()
    } else {
        secret_ids_by_names(&managed, &dto.secret_names)
    };
    managed.run(managed.backend.update_connection(
        dto_id(&dto.id),
        ConnectionSpec {
            name: new_name.clone(),
            config,
            secrets,
        },
    ));
    eprintln!("renamed connection {name} → {new_name}");
}

fn cmd_conn_rm(name: String, root: Option<PathBuf>, url: Option<String>) {
    let managed = management_backend(root, url);
    let dto = conn_dto(&managed, &name);
    managed.run(managed.backend.delete_connection(dto_id(&dto.id)));
    eprintln!("deleted connection {name} (its secrets stay in the vault)");
}

fn cmd_conn_access(name: String, root: Option<PathBuf>, url: Option<String>, enabled: bool) {
    let managed = management_backend(root, url);
    let dto = conn_dto(&managed, &name);
    let state = if enabled { "enabled" } else { "disabled" };
    let changed = managed.run(managed.backend.set_tool_access(dto_id(&dto.id), enabled));
    if changed {
        eprintln!("agent access {state} for {name}");
    } else {
        eprintln!("agent access was already {state} for {name}");
    }
}

fn cmd_conn_confirm(name: String, root: Option<PathBuf>, url: Option<String>, on: bool) {
    let managed = management_backend(root, url);
    let dto = conn_dto(&managed, &name);
    let state = if on { "on" } else { "off" };
    let changed = managed.run(managed.backend.set_confirm_mode(dto_id(&dto.id), on));
    if changed {
        eprintln!("traffic confirmation {state} for {name}");
        if on {
            eprintln!("  prompts are answered in the AgentMFA app; without it, this tool's traffic is refused");
        }
    } else {
        eprintln!("traffic confirmation was already {state} for {name}");
    }
}

fn cmd_conn_test(name: String, root: Option<PathBuf>, url: Option<String>) {
    let managed = management_backend(root, url);
    let dto = conn_dto(&managed, &name);
    let report = managed.run(managed.backend.test_connection(dto_id(&dto.id)));
    if report.ok {
        eprintln!("ok: {}", report.detail);
    } else {
        match report.kind {
            Some(kind) => eprintln!("failed ({kind:?}): {}", report.detail),
            None => eprintln!("failed: {}", report.detail),
        }
        std::process::exit(1);
    }
}

/// Print an already-issued direct endpoint's address and secret. Read-only:
/// issuance/rotation binds a live listener, so it belongs to the app; this
/// reads the persisted record through the same managed backend as the other
/// `conn` subcommands (live over the socket with a stored token, hosted with
/// `--broker`, or offline with the broker stopped). `--url`/`--secret` print a
/// single field for `$(...)` use.
fn cmd_conn_endpoint(
    name: String,
    url: bool,
    secret: bool,
    root: Option<PathBuf>,
    broker: Option<String>,
) {
    let managed = management_backend(root, broker);
    let dto = conn_dto(&managed, &name);
    let info = match managed.run(managed.backend.get_endpoint(dto_id(&dto.id))) {
        Some(info) => info,
        None => die(format!(
            "no direct endpoint issued for {name} — issue one from the AgentMFA app first"
        )),
    };
    // Selectors print exactly one field with no decoration, so a `$(...)`
    // capture carries only the value. `--url` prefers the TCP form when the
    // endpoint has one: it is the address that works from another machine and
    // in drivers with no Unix-socket support, which is what a script capturing
    // this almost always wants.
    if url {
        println!("{}", info.tcp_dsn.as_deref().unwrap_or(&info.dsn));
        return;
    }
    if secret {
        println!("{}", info.secret);
        return;
    }
    // Default: the copy-ready example on stderr (guidance), the address on
    // stdout (the pasteable value), and the secret when the kind has one.
    eprintln!("{}", info.example);
    println!("{}", info.dsn);
    if let Some(tcp) = &info.tcp_dsn {
        eprintln!("tcp (drivers without unix-socket support, and remote clients):");
        eprintln!("{tcp}");
    }
    if !info.secret.is_empty() {
        eprintln!("endpoint secret: {}", info.secret);
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
            .join(".claude/skills/mfa/SKILL.md"),
        (None, false) => PathBuf::from(".claude/skills/mfa/SKILL.md"),
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

/// Store a management token for later online edits: keyed by the hosted
/// broker's manage URL, or by the local socket path. Verified against the
/// broker when it is reachable — a rejected token is never stored.
fn cmd_manage_login(url: Option<String>, token_env: Option<String>, root: Option<PathBuf>) {
    if std::io::IsTerminal::is_terminal(&std::io::stdin()) && token_env.is_none() {
        eprintln!("  paste the management token (akamgr_…); end with Ctrl-D");
    }
    let token = read_secret_value(&token_env);
    let paths = store_paths(root.as_deref());
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let (key, backend) = match url {
        Some(url) => {
            let url = match RemoteConfig::normalize_url(&url) {
                Ok(url) => url,
                Err(e) => die(e),
            };
            let config = match RemoteConfig::new(&url, &token) {
                Ok(config) => config,
                Err(e) => die(e),
            };
            (url, RemoteBackend::new(config))
        }
        None => {
            let socket = paths.socket_file();
            let key = socket.display().to_string();
            (key, RemoteBackend::over_unix_socket(socket, &token))
        }
    };
    match runtime.block_on(backend.whoami()) {
        Ok(_) => eprintln!("token verified against the running broker"),
        Err(ManageError::InvalidManageToken) => die(
            "the broker rejected this management token — issue a fresh one \
             with `mfa manage token`",
        ),
        Err(ManageError::Unreachable { .. }) => {
            eprintln!("the broker is not reachable right now; storing the token unverified");
        }
        Err(e) => die(e),
    }
    if let Err(e) = manage_token_store(&paths).save(&key, &token) {
        die(format!("could not store the token: {e}"));
    }
    eprintln!("management token stored for {key}");
}

fn cmd_manage_logout(url: Option<String>, root: Option<PathBuf>) {
    let paths = store_paths(root.as_deref());
    let key = match url {
        Some(url) => match RemoteConfig::normalize_url(&url) {
            Ok(url) => url,
            Err(e) => die(e),
        },
        None => paths.socket_file().display().to_string(),
    };
    if let Err(e) = manage_token_store(&paths).delete(&key) {
        die(format!("could not forget the management token: {e}"));
    }
    eprintln!("management token forgotten for {key}");
}

/// Issue, rotate, or revoke the management token. Offline like `secret add`:
/// a live broker holds identity state in memory and would overwrite the
/// edit, so it must be stopped first.
fn cmd_manage_token(revoke: bool, ttl_days: Option<u64>, root: Option<PathBuf>) {
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
    let integrity = match runtime.block_on(aka_core::integrity::StateIntegrity::open_for_paths(
        &*vault, &paths,
    )) {
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
    let ttl = ttl_days.map(|days| std::time::Duration::from_secs(days * 86400));
    match identity.issue_manage_token_with_ttl(ttl) {
        Ok(token) => {
            eprintln!("management token (shown once — only its hash is stored):\n");
            println!("{token}");
            eprintln!("\nEnter it in the AgentMFA app to manage this broker remotely.");
            match ttl_days {
                Some(days) => eprintln!(
                    "Expires in {days} day{}; re-run to rotate, or --revoke to close the manage API.",
                    if days == 1 { "" } else { "s" }
                ),
                None => eprintln!(
                    "Never expires; re-run this command to rotate it, or --revoke to close the manage API."
                ),
            }
        }
        Err(e) => die(e),
    }
}

/// Open a capability session on the running broker and hand back the
/// parsed 200 body; any failure dies with the client module's one-liner.
fn open_session(
    endpoint: &str,
    connection: &str,
    root: Option<PathBuf>,
    label: Option<String>,
) -> serde_json::Value {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let paths = store_paths(root.as_deref());
    match runtime.block_on(client::open_session(
        &paths,
        endpoint,
        connection,
        label.as_deref(),
    )) {
        Ok(body) => body,
        Err(message) => die(message),
    }
}

/// Embed the session ticket as the DSN's password. The broker returns the
/// two separately so callers can keep the ticket out of ps-visible argv
/// (PGPASSWORD); `mfa dsn` exists for the one-liner and accepts that
/// exposure for the ticket's short window.
fn embed_ticket(dsn: &str, ticket: &str) -> Result<String, String> {
    match dsn.split_once("://ticket@") {
        Some((scheme, rest)) => Ok(format!("{scheme}://ticket:{ticket}@{rest}")),
        None => Err(format!("unexpected DSN shape from the broker: {dsn}")),
    }
}

fn cmd_dsn(connection: String, root: Option<PathBuf>, client: Option<String>) {
    let body = open_session("/v1/pg/open", &connection, root, client);
    let (Some(dsn), Some(ticket)) = (body["dsn"].as_str(), body["ticket"].as_str()) else {
        die("the broker's response carried no DSN and ticket");
    };
    let dsn = match embed_ticket(dsn, ticket) {
        Ok(dsn) => dsn,
        Err(message) => die(message),
    };
    if let Some(secs) = body["expires_in_seconds"].as_u64() {
        eprintln!("  ticket expires in {secs}s — connect before then; a later connection needs a fresh open");
    }
    println!("{dsn}");
}

/// The `-o` flags every brokered `ssh` invocation should carry; see the core's
/// definition for why each is present and why `IdentitiesOnly` is not.
use aka_core::capability::ssh::SSH_BROKER_OPTIONS;

/// The stderr lines accompanying `mfa ssh`'s socket path.
///
/// Everything here was already in the broker's response and thrown away: the
/// destination to actually type (an imported alias is not `user@host`), the
/// fingerprint the broker enforces (the pinned *host* is not what authorizes
/// anything), the absolute deadline, and the flags without which a local
/// on-disk key can quietly win the login instead. Built separately from
/// printing so the shape is testable.
fn ssh_open_hints(
    body: &serde_json::Value,
    auth_sock: &str,
    now: chrono::DateTime<chrono::Local>,
) -> Vec<String> {
    let mut lines = Vec::new();
    if let (Some(user), Some(host)) = (body["user"].as_str(), body["host"].as_str()) {
        lines.push(format!("signs only for {user}@{host}"));
    }
    if let Some(secs) = body["expires_in_seconds"].as_u64() {
        // Relative alone leaves nothing to compare a later failure against. The
        // agent protocol has no error channel, so a 61-second-old export reads
        // as "Permission denied (publickey)" and nothing else.
        let deadline = now + chrono::Duration::seconds(secs as i64);
        lines.push(format!(
            "connect within {secs}s — by {} (a later connection needs a fresh open)",
            deadline.format("%H:%M:%S %Z")
        ));
    }
    lines.push(match body["host_key_fingerprint"].as_str() {
        Some(fingerprint) if !fingerprint.is_empty() => {
            format!("server host key pinned to {fingerprint}")
        }
        _ => "server host key not pinned — the first server key seen will be trusted and pinned"
            .to_string(),
    });
    let destination = body["destination"]
        .as_str()
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .or_else(|| {
            let (user, host) = (body["user"].as_str()?, body["host"].as_str()?);
            Some(format!("{user}@{host}"))
        });
    if let Some(destination) = destination {
        let port = match body["port"].as_u64() {
            Some(port) if port != 22 => format!(" -p {port}"),
            _ => String::new(),
        };
        let flags = SSH_BROKER_OPTIONS
            .iter()
            .map(|option| format!("-o {option}"))
            .collect::<Vec<_>>()
            .join(" ");
        lines.push(format!("export SSH_AUTH_SOCK=\"{auth_sock}\""));
        lines.push(format!("ssh{port} {flags} {destination}"));
    }
    lines
}

fn cmd_ssh(connection: String, root: Option<PathBuf>, client: Option<String>) {
    let body = open_session("/v1/ssh/open", &connection, root, client);
    let Some(auth_sock) = body["auth_sock"].as_str() else {
        die("the broker's response carried no agent socket path");
    };
    for line in ssh_open_hints(&body, auth_sock, chrono::Local::now()) {
        eprintln!("  {line}");
    }
    println!("{auth_sock}");
}

/// Print the shared agent key, rotating it first when asked. The plain
/// print without `--url` is a file read of the key's plaintext home (the
/// same file agents read), so it works alongside a running broker with no
/// token; rotation and remote reads go through the management backend.
fn cmd_key(rotate: bool, root: Option<PathBuf>, url: Option<String>) {
    if url.is_none() && !rotate {
        let paths = store_paths(root.as_deref());
        let token_file = paths.token_file();
        match std::fs::read_to_string(&token_file) {
            Ok(token) if !token.trim().is_empty() => println!("{}", token.trim()),
            _ => die(format!(
                "no shared key at {} — the broker mints it when it first starts",
                token_file.display()
            )),
        }
        return;
    }
    let managed = management_backend(root, url);
    if rotate {
        managed.run(managed.backend.rotate_key());
        eprintln!("key rotated; agents that read the token file reconnect on their own");
    }
    let key = managed.run(managed.backend.agent_key());
    println!("{key}");
}

/// The tools listing shared by local and remote status output.
fn print_tools(connections: &[ConnectionDto]) {
    if connections.is_empty() {
        println!("  tools: none configured");
        return;
    }
    println!("  tools:");
    for dto in connections {
        println!(
            "    {}  {}  {}  {}",
            dto.name,
            dto.kind,
            dto.target,
            if dto.agent_access.enabled {
                "enabled"
            } else {
                "disabled"
            }
        );
    }
}

/// `status --url`: the broker as its manage API reports it.
fn cmd_status_remote(root: Option<PathBuf>, url: String) {
    let managed = management_backend(root, Some(url.clone()));
    let identity = managed.run(managed.backend.identity());
    let connections = managed.run(managed.backend.list_connections());
    println!("broker reachable at {url} (manage API)");
    println!("  client id: {}", identity.client_id);
    println!(
        "  agent key file (on the broker host): {}",
        identity.token_path
    );
    print_tools(&connections);
}

/// Which macOS keychain this store's secret values are in — the difference
/// between reads that are silent and reads that put an OS approval dialog in
/// front of whoever is at the machine. Nothing to say before the first write,
/// or on a platform with one keychain.
fn print_keychain_line(paths: &Paths) {
    #[cfg(target_os = "macos")]
    if let Some(keychain) = aka_core::keychain::read_record(&paths.keychain_file()) {
        let note = match keychain {
            aka_core::keychain::Keychain::DataProtection => "no prompts",
            aka_core::keychain::Keychain::Login => "prompts per secret; build is unsigned",
        };
        println!("  keychain: {keychain} ({note})");
    }
    #[cfg(not(target_os = "macos"))]
    let _ = paths;
}

fn cmd_status(root: Option<PathBuf>, url: Option<String>) {
    if let Some(url) = url {
        cmd_status_remote(root, url);
        return;
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let paths = store_paths(root.as_deref());
    let socket = paths.socket_file();
    let key_present = std::fs::read_to_string(paths.token_file())
        .map(|t| !t.trim().is_empty())
        .unwrap_or(false);
    let manifest = runtime.block_on(client::unix_http(
        &socket,
        "GET",
        "/.well-known/agent-broker.json",
        None,
        None,
        None,
    ));
    let manifest: serde_json::Value = match manifest {
        Ok((200, body)) => serde_json::from_str(&body).unwrap_or_default(),
        Ok((status, _)) => die(format!(
            "the broker at {} answered discovery with HTTP {status}",
            socket.display()
        )),
        Err(_) => {
            println!("no broker is running at {}", socket.display());
            println!(
                "  shared key: {}",
                if key_present {
                    format!("present at {}", paths.token_file().display())
                } else {
                    "not minted yet (starts with the broker)".to_string()
                }
            );
            std::process::exit(1);
        }
    };
    println!("broker running on {}", socket.display());
    if let (Some(version), Some(protocol)) = (
        manifest["version"].as_str(),
        manifest["protocol_version"].as_u64(),
    ) {
        println!("  version: {version} (protocol {protocol})");
    }
    match manifest["mcp_url"].as_str() {
        Some(url) => println!("  MCP host: {url}"),
        None => println!("  MCP host: not running"),
    }
    println!(
        "  shared key: {}",
        if key_present {
            format!("{}", paths.token_file().display())
        } else {
            "not minted yet".to_string()
        }
    );
    print_keychain_line(&paths);
    // The tools, as an agent sees them (this appears in the activity log
    // as a listing by mfa-status).
    let listing = runtime.block_on(async {
        let key = client::shared_key(&paths, Some("mfa-status")).await?;
        let (status, body) = client::unix_http(
            &socket,
            "GET",
            "/v1/connections",
            None,
            Some(&key),
            Some("mfa-status"),
        )
        .await
        .map_err(|e| e.to_string())?;
        if status != 200 {
            return Err(format!("HTTP {status}"));
        }
        serde_json::from_str::<serde_json::Value>(&body).map_err(|e| e.to_string())
    });
    match listing {
        Ok(listing) => {
            let rows = listing["connections"]
                .as_array()
                .cloned()
                .or_else(|| listing.as_array().cloned())
                .unwrap_or_default();
            if rows.is_empty() {
                println!("  tools: none configured");
            } else {
                println!("  tools:");
                for row in rows {
                    println!(
                        "    {}  {}  {}  {}",
                        row["name"].as_str().unwrap_or("?"),
                        row["type"].as_str().unwrap_or("?"),
                        row["target"].as_str().unwrap_or("?"),
                        if row["wired"].as_bool().unwrap_or(false) {
                            "enabled"
                        } else {
                            "disabled"
                        }
                    );
                }
            }
        }
        Err(e) => println!("  tools: could not list ({e})"),
    }
}

/// One formatted line per audit entry: timestamp (seconds precision),
/// kind, summary, detail, and the acting agent when recorded.
fn format_audit_line(entry: &serde_json::Value) -> String {
    let ts = entry["ts"].as_str().unwrap_or("-");
    let ts = if ts.len() >= 19 { &ts[..19] } else { ts };
    let kind = entry["kind"].as_str().unwrap_or("?");
    let text = entry["text"].as_str().unwrap_or("");
    let mut line = format!("{ts}  {kind:<20}  {text}");
    if let Some(detail) = entry["detail"].as_str() {
        line.push_str(&format!(" — {detail}"));
    }
    if let Some(agent) = entry["agent"].as_str() {
        line.push_str(&format!("  [{agent}]"));
    }
    line
}

/// `activity --url`: entries as the manage API renders them.
fn cmd_activity_remote(limit: usize, json: bool, root: Option<PathBuf>, url: String) {
    let managed = management_backend(root, Some(url));
    let mut entries = managed.run(managed.backend.activity(limit));
    // The manage API returns newest first; match the local newest-last view.
    entries.reverse();
    for entry in entries {
        if json {
            println!(
                "{}",
                serde_json::to_string(&entry).expect("serializable entry")
            );
            continue;
        }
        let ts = entry.at.get(..19).unwrap_or(&entry.at);
        let mut line = format!("{ts}  {}", entry.text);
        if let Some(detail) = &entry.detail {
            line.push_str(&format!(" — {detail}"));
        }
        if let Some(agent) = &entry.agent {
            line.push_str(&format!("  [{agent}]"));
        }
        println!("{line}");
    }
}

fn cmd_activity(limit: usize, json: bool, root: Option<PathBuf>, url: Option<String>) {
    if let Some(url) = url {
        cmd_activity_remote(limit, json, root, url);
        return;
    }
    let paths = store_paths(root.as_deref());
    let file = paths.audit_file();
    let content = match std::fs::read_to_string(&file) {
        Ok(content) => content,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!(
                "no activity recorded yet ({} does not exist)",
                file.display()
            );
            return;
        }
        Err(e) => die(format!("could not read {}: {e}", file.display())),
    };
    let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();
    let start = if limit == 0 {
        0
    } else {
        lines.len().saturating_sub(limit)
    };
    for line in &lines[start..] {
        if json {
            println!("{line}");
            continue;
        }
        // A trailing line the broker is mid-append on parses as garbage;
        // skip it rather than break the listing.
        if let Ok(entry) = serde_json::from_str::<serde_json::Value>(line) {
            println!("{}", format_audit_line(&entry));
        }
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

/// Everything `mfa serve` accepts, bundled so the call site stays legible.
struct ServeArgs {
    root: Option<PathBuf>,
    listen: Option<std::net::SocketAddr>,
    public_url: Option<String>,
    data_plane_listen: Option<std::net::IpAddr>,
    advertise_host: Option<String>,
    data_plane_insecure: bool,
    session_idle_timeout: Option<u64>,
    session_max_ttl: Option<u64>,
    audit_pg_statements: bool,
    no_sidecar: bool,
}

fn cmd_serve(args: ServeArgs) {
    let ServeArgs {
        root,
        listen,
        public_url,
        data_plane_listen,
        advertise_host,
        data_plane_insecure,
        session_idle_timeout,
        session_max_ttl,
        audit_pg_statements,
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
    // Session lifetimes are deployment-shaped: the defaults suit an
    // interactive desktop, while a nightly `pg_dump` or a LISTEN/NOTIFY worker
    // needs longer ones. They were compile-time constants before, which left
    // those workloads with no way to run at all.
    let mut config = BrokerConfig::default();
    if let Some(secs) = session_idle_timeout {
        config.session_idle_timeout = std::time::Duration::from_secs(secs);
    }
    if let Some(secs) = session_max_ttl {
        config.session_max_ttl = std::time::Duration::from_secs(secs);
    }
    config.audit_pg_statements = audit_pg_statements;
    let broker: Arc<Broker> = match runtime.block_on(Broker::new(paths, vault, config, events)) {
        Ok(broker) => broker,
        Err(e) => fail("could not start the broker", &e),
    };
    let options = daemon::ServeOptions {
        listen,
        public_url: public_url.clone(),
        data_plane_listen,
        advertise_host: advertise_host.clone(),
        data_plane_insecure,
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
                let sidecar = runtime.block_on(async { aka_core::sidecar::Sidecar::spawn(config) });
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
            eprintln!("  data planes advertised to agents as {host} (the PG leg is plaintext)");
        }
        match &public_url {
            Some(url) => eprintln!("  advertised to remote clients as {url}"),
            None => eprintln!("  no --public-url set: TCP discovery omits absolute URLs"),
        }
        eprintln!("  remote management: enter this broker's `mfa manage token` in the app");
    }
    eprintln!(
        "  discovery: curl --unix-socket {} http://localhost/instructions",
        daemon.socket_path.display()
    );
    eprintln!(
        "  skill file: `mfa skill --write` in a repo (or --write --user) \
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
    use chrono::TimeZone as _;

    /// SSH-24 and SSH-9. Everything printed here was already in the response
    /// and discarded: the destination an alias-imported tool is reached by, the
    /// fingerprint the broker actually enforces, an absolute deadline (the agent
    /// protocol has no error channel, so an expired socket reads only as
    /// "Permission denied (publickey)"), and the flags without which a local
    /// on-disk key can win the login with no broker involvement.
    #[test]
    fn ssh_open_hints_name_what_the_socket_honors() {
        let now = chrono::Local
            .with_ymd_and_hms(2026, 7, 29, 9, 30, 0)
            .single()
            .expect("an unambiguous local time");
        let body = serde_json::json!({
            "auth_sock": "/tmp/agent-3f1c9a2b04d7e685.sock",
            "destination": "production",
            "host": "prod.example.com",
            "port": 2222,
            "user": "deploy",
            "host_key_fingerprint": "SHA256:abc123",
            "expires_in_seconds": 60,
        });
        let lines = ssh_open_hints(&body, "/tmp/agent-3f1c9a2b04d7e685.sock", now);
        let joined = lines.join("\n");
        assert!(
            joined.contains("signs only for deploy@prod.example.com"),
            "{joined}"
        );
        assert!(joined.contains("SHA256:abc123"), "{joined}");
        assert!(joined.contains("connect within 60s"), "{joined}");
        assert!(
            joined.contains("09:31:00"),
            "an absolute deadline: {joined}"
        );
        // The imported alias, not user@host: ~/.ssh/config is what supplies the
        // rest of the routing, and the pinned host may not even be typeable.
        assert!(joined.contains("ssh -p 2222 "), "{joined}");
        assert!(joined.ends_with(" production"), "{joined}");
        for option in SSH_BROKER_OPTIONS {
            assert!(
                joined.contains(&format!("-o {option}")),
                "{option} missing: {joined}"
            );
        }
        assert!(
            !joined.contains("IdentitiesOnly"),
            "that flag breaks the agent: {joined}"
        );
    }

    /// An unpinned connection says so rather than staying silent: the next
    /// server key seen becomes the permanent anchor.
    #[test]
    fn ssh_open_hints_say_when_no_host_key_is_pinned() {
        let now = chrono::Local
            .with_ymd_and_hms(2026, 7, 29, 9, 30, 0)
            .single()
            .expect("an unambiguous local time");
        let body = serde_json::json!({
            "host": "prod.example.com",
            "user": "deploy",
            "host_key_fingerprint": serde_json::Value::Null,
        });
        let joined = ssh_open_hints(&body, "/tmp/a.sock", now).join("\n");
        assert!(joined.contains("not pinned"), "{joined}");
        assert!(joined.contains("will be trusted and pinned"), "{joined}");
        // No port key at all: port 22 is left implicit rather than spelled out.
        assert!(joined.contains("ssh -o IdentityFile=none"), "{joined}");
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

    #[test]
    fn embed_ticket_fills_the_password_slot() {
        assert_eq!(
            embed_ticket(
                "postgres://ticket@127.0.0.1:5599/app?sslmode=disable",
                "tkt_ab12"
            )
            .unwrap(),
            "postgres://ticket:tkt_ab12@127.0.0.1:5599/app?sslmode=disable"
        );
        // A DSN without the expected placeholder user is a contract change
        // worth failing loudly on, not silently mangling.
        assert!(embed_ticket("postgres://other@host/db", "tkt_x").is_err());
    }

    fn args(kind: ConnKind) -> ConnAdd {
        ConnAdd {
            name: "test".into(),
            kind,
            host: None,
            scheme: None,
            port: None,
            template: None,
            dbname: None,
            user: None,
            host_key_fingerprint: None,
            secret: None,
            sslmode: None,
            ca_bundle: None,
            mcp_path: None,
            root: None,
            broker: None,
        }
    }

    #[test]
    fn api_names_its_missing_and_stray_flags() {
        let mut a = args(ConnKind::Api);
        assert!(conn_config(&a).unwrap_err().contains("--host"));
        a.host = Some("api.github.com".into());
        assert!(conn_config(&a).unwrap_err().contains("--template"));
        a.template = Some("Authorization: Bearer {{KEY}}".into());
        a.ca_bundle = Some("/etc/api-ca.pem".into());
        let config = conn_config(&a).unwrap();
        assert!(matches!(
            config,
            ConnectionConfig::Api {
                ref scheme,
                trusted_ca_bundle_path: Some(ref path),
                ..
            } if scheme == "https" && path == "/etc/api-ca.pem"
        ));
        // api derives secrets from the template; a stray --secret is a
        // misunderstanding worth naming, not ignoring.
        a.secret = Some("KEY".into());
        assert!(conn_config(&a).unwrap_err().contains("--secret"));
    }

    #[test]
    fn api_carries_an_optional_mcp_path() {
        let mut a = args(ConnKind::Api);
        a.host = Some("mcp.example.com".into());
        a.template = Some("Authorization: Bearer {{KEY}}".into());
        // Absent by default; set when --mcp-path is given.
        assert!(matches!(
            conn_config(&a).unwrap(),
            ConnectionConfig::Api { mcp_path: None, .. }
        ));
        a.mcp_path = Some("/mcp".into());
        assert!(matches!(
            conn_config(&a).unwrap(),
            ConnectionConfig::Api { mcp_path: Some(ref path), .. } if path == "/mcp"
        ));
        // --mcp-path is an api-only concept; naming it on another kind is an
        // error, not a silent no-op.
        let mut p = args(ConnKind::Pg);
        p.host = Some("db.internal".into());
        p.dbname = Some("app".into());
        p.user = Some("app".into());
        p.secret = Some("PGPASS".into());
        p.mcp_path = Some("/mcp".into());
        assert!(conn_config(&p).unwrap_err().contains("--mcp-path"));
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
    fn audit_lines_format_with_optional_fields() {
        let entry = serde_json::json!({
            "ts": "2026-07-24T12:00:00.123456Z",
            "kind": "http_request",
            "text": "claude-code requested github",
            "detail": "GET api.github.com/user/repos",
            "agent": "claude-code",
        });
        assert_eq!(
            format_audit_line(&entry),
            "2026-07-24T12:00:00  http_request          claude-code requested github \
             — GET api.github.com/user/repos  [claude-code]"
        );
        let bare = serde_json::json!({ "kind": "wired", "text": "Agent access enabled" });
        assert_eq!(
            format_audit_line(&bare),
            "-  wired                 Agent access enabled"
        );
    }

    fn update_args() -> ConnUpdate {
        ConnUpdate {
            name: "test".into(),
            host: None,
            scheme: None,
            port: None,
            template: None,
            dbname: None,
            user: None,
            host_key_fingerprint: None,
            secret: None,
            sslmode: None,
            ca_bundle: None,
            root: None,
            broker: None,
        }
    }

    #[test]
    fn dto_reconstruction_preserves_byo_oauth_coordinates_for_renames() {
        use aka_api::{AccessDto, OAuthDto};

        let dto = ConnectionDto {
            id: Uuid::new_v4().to_string(),
            name: "calendar".into(),
            kind: "api".into(),
            target: "https://api.example.com".into(),
            secret_names: vec!["CALENDAR_OAUTH".into()],
            oauth: false,
            agent_access: AccessDto {
                enabled: true,
                confirm: false,
                confirm_window_until: None,
                confirm_window_agents: vec![],
                confirm_cooldown_until: None,
                allowed_tools: None,
                endpoint: None,
            },
            host: Some("api.example.com".into()),
            scheme: Some("https".into()),
            port: None,
            template: Some("Authorization: Bearer {{CALENDAR_OAUTH}}".into()),
            dbname: None,
            user: None,
            host_key_fingerprint: None,
            destination: None,
            sslmode: None,
            trusted_ca_bundle_path: None,
            mcp_path: None,
            account: Some("operator@example.com".into()),
            oauth_spec: Some(OAuthDto {
                auth_url: "https://accounts.example.com/authorize".into(),
                token_url: "https://accounts.example.com/token".into(),
                client_id: "client-id".into(),
                scopes: vec!["calendar.read".into()],
                extra_auth_params: vec![("access_type".into(), "offline".into())],
            }),
            last_status: None,
            last_detail: None,
            last_checked_at: None,
        };

        let ConnectionConfig::Api { oauth, .. } = config_from_dto(&dto).unwrap() else {
            panic!("expected API config");
        };
        let oauth = oauth.expect("BYO OAuth coordinates survive DTO reconstruction");
        assert_eq!(oauth.client_id, "client-id");
        assert_eq!(oauth.scopes, vec!["calendar.read"]);
        assert_eq!(
            oauth.extra_auth_params,
            vec![("access_type".into(), "offline".into())]
        );
    }

    #[test]
    fn update_merges_over_existing_and_preserves_unmanaged_fields() {
        let existing = ConnectionConfig::Api {
            host: "api.github.com".into(),
            scheme: "https".into(),
            port: None,
            trusted_ca_bundle_path: Some("/etc/api-ca.pem".into()),
            template: "Authorization: Bearer {{KEY}}".into(),
            mcp_path: Some("/mcp".into()),
            oauth: None,
        };
        let mut a = update_args();
        a.host = Some("api.example.com".into());
        match merged_config(&existing, &a).unwrap() {
            ConnectionConfig::Api {
                host,
                scheme,
                trusted_ca_bundle_path,
                template,
                mcp_path,
                ..
            } => {
                assert_eq!(host, "api.example.com");
                assert_eq!(scheme, "https", "unspecified flags keep their values");
                assert_eq!(
                    trusted_ca_bundle_path.as_deref(),
                    Some("/etc/api-ca.pem"),
                    "unspecified --ca-bundle keeps its value"
                );
                assert_eq!(template, "Authorization: Bearer {{KEY}}");
                assert_eq!(mcp_path.as_deref(), Some("/mcp"), "mcp_path carries over");
            }
            other => panic!("wrong config: {other:?}"),
        }
        // A stray flag for the kind is named, same as `conn add`.
        a.dbname = Some("stray".into());
        assert!(merged_config(&existing, &a)
            .unwrap_err()
            .contains("--dbname"));
    }

    #[test]
    fn update_clears_pg_ca_bundle_and_ssh_pin_with_empty_strings() {
        let pg = ConnectionConfig::Pg {
            host: "db.internal".into(),
            port: 5432,
            dbname: "app".into(),
            user: "app".into(),
            sslmode: PgSslMode::VerifyCa,
            trusted_ca_bundle_path: Some("/etc/ca.pem".into()),
        };
        let mut a = update_args();
        a.ca_bundle = Some(String::new());
        match merged_config(&pg, &a).unwrap() {
            ConnectionConfig::Pg {
                sslmode,
                trusted_ca_bundle_path,
                ..
            } => {
                assert_eq!(trusted_ca_bundle_path, None, "'' clears the bundle");
                assert_eq!(sslmode, PgSslMode::VerifyCa, "sslmode kept");
            }
            other => panic!("wrong config: {other:?}"),
        }

        let ssh = ConnectionConfig::Ssh {
            destination: Some("prod".into()),
            host: "prod.example.com".into(),
            port: 22,
            user: "deploy".into(),
            host_key_fingerprint: "SHA256:AAAA".into(),
        };
        let mut a = update_args();
        a.host_key_fingerprint = Some(String::new());
        match merged_config(&ssh, &a).unwrap() {
            ConnectionConfig::Ssh {
                destination,
                host_key_fingerprint,
                ..
            } => {
                assert_eq!(host_key_fingerprint, "", "'' clears the pin for re-TOFU");
                assert_eq!(
                    destination.as_deref(),
                    Some("prod"),
                    "destination carries over"
                );
            }
            other => panic!("wrong config: {other:?}"),
        }
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
