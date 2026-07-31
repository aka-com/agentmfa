//! `mfa` CLI.
//!
//! - `mfa skill` emits the `/instructions` content as a checked-in
//!   skill file, the same content the daemon serves, so the convention
//!   layer can't drift from the daemon.
//! - `mfa serve` runs the broker headless, so the whole control plane +
//!   the PG data plane can be exercised without the desktop UI (useful for
//!   agent integration and CI).
//! - `mfa secret add|list|rename|replace|rm` and
//!   `mfa conn add|list|show|update|rename|rm|enable|disable|test` manage the
//!   store from the terminal — the dev/headless counterpart of the app's
//!   Secrets and Tools tabs — with the same validation, so a `serve --root`
//!   harness never hand-writes (sealed) store files. Mutations beyond
//!   seeding run through the broker's own `ui_*` layer, so audit entries
//!   and access/endpoint side effects cannot drift from the app.
//! - `mfa sessions`, `mfa requests`, and `mfa settings` expose the remaining
//!   day-to-day broker visibility and lifecycle controls without requiring
//!   the desktop UI. The request command can hold a leased headless inbox and
//!   answer approvals or elicitations.
//! - `mfa dsn` / `mfa ssh` open data-plane sessions on a running broker.
//!   Postgres prints shell-safe `PG*` exports by default so the ticket stays
//!   out of argv; SSH prints the `SSH_AUTH_SOCK` path.
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

use aka_api::{ActivityDto, ConnectionDto, ManageError, SecretDto};
use aka_client::credentials::TokenStore;
use aka_client::{RemoteBackend, RemoteConfig};
use aka_core::broker::Broker;
use aka_core::config::BrokerConfig;
use aka_core::daemon;
use aka_core::daemon::wellknown;
use aka_core::error::CoreError;
use aka_core::events::BrokerEvents;
use aka_core::manage::{
    activity_dto, ConnectionConfigPatch, LocalBackend, ManageResult, ManagementBackend,
};
use aka_core::paths::{BrokerInstanceLock, BrokerLockAttempt, BrokerLockRole, Paths};
use aka_core::store::ConnectionSpec;
use aka_core::types::{ConnectionConfig, PgSslMode, SecretValue, SignerSpec};
use aka_core::vault::{
    platform_vault, platform_vault_for_root, recorded_platform_vault_backend,
    selected_platform_vault_backend, PlatformVaultBackend, SecretVault,
};
use clap::{Args, Parser, Subcommand, ValueEnum};
use uuid::Uuid;
use zeroize::Zeroizing;

mod client;
mod mcp_bridge;
mod ssh_agent;

fn parse_client_label(value: &str) -> Result<String, String> {
    if !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        Ok(value.to_string())
    } else {
        Err("must be 1-64 ASCII letters, digits, dots, underscores, or hyphens".into())
    }
}

fn parse_manage_ttl_days(value: &str) -> Result<u64, String> {
    let days: u64 = value
        .parse()
        .map_err(|_| "must be a whole number of days".to_string())?;
    if (1..=3650).contains(&days) {
        Ok(days)
    } else {
        Err("must be between 1 and 3650 days".to_string())
    }
}

const DEFAULT_MANAGE_TOKEN_TTL_DAYS: u64 = 30;

fn parse_positive_seconds(value: &str) -> Result<u64, String> {
    let secs: u64 = value
        .parse()
        .map_err(|_| "must be a whole number of seconds".to_string())?;
    if secs == 0 {
        Err("must be at least 1 second".to_string())
    } else {
        Ok(secs)
    }
}

fn parse_public_url(value: &str) -> Result<String, String> {
    RemoteConfig::normalize_url(value)
}

fn parse_field_value(value: &str) -> Result<String, String> {
    let Some((name, _)) = value.split_once('=') else {
        return Err("must be NAME=VALUE".into());
    };
    if name.trim().is_empty() {
        return Err("field name must not be empty".into());
    }
    Ok(value.to_string())
}

#[derive(Parser)]
#[command(
    name = "mfa",
    version,
    about = "AgentMFA broker CLI",
    after_help = "EXIT CODES:\n  1  generic/internal failure\n  2  invalid command usage or input\n  3  broker is not running\n  4  authentication or confirmation failed\n  5  requested object was not found\n  6  state conflict\n  7  remote broker is unreachable\n  8  connection test failed"
)]
struct Cli {
    /// Emit one machine-readable JSON document for commands with bounded output.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)] // one short-lived instance per invocation
enum Command {
    /// Emit broker instructions as a skill file. With --broker, fetches that
    /// broker's authoritative setup. Prints to stdout by default; `--write`
    /// writes .claude/skills/mfa/SKILL.md.
    Skill {
        /// Write the file to `path` (default .claude/skills/mfa/SKILL.md)
        /// instead of printing to stdout.
        #[arg(long)]
        write: bool,
        /// Override the output path used with --write.
        #[arg(long, conflicts_with = "user", requires = "write")]
        path: Option<PathBuf>,
        /// With --write, target the user-level skills directory
        /// (~/.claude/skills/mfa/SKILL.md) instead of the repo-local
        /// default, so every project's agents see it.
        #[arg(long, requires = "write")]
        user: bool,
        /// Overwrite a non-AgentMFA skill file. Generated AgentMFA skill
        /// files can be refreshed without this flag.
        #[arg(long, requires = "write")]
        force: bool,
        /// Render the document for a broker rooted here (`serve --root`)
        /// instead of the production layout, so a dev harness's skill file
        /// names the socket it actually serves.
        #[arg(long)]
        root: Option<PathBuf>,
        /// Fetch setup from this hosted broker instead of rendering local
        /// defaults. Requires its current management token.
        #[arg(long)]
        broker: Option<String>,
    },
    /// Print a shell completion script to stdout.
    ///
    /// `mfa completions zsh > "${fpath[1]}/_mfa"`, or source it from your
    /// shell's rc file. The script is generated from this CLI's own command
    /// tree, so it cannot drift from the commands it completes.
    Completions {
        /// The shell to generate for.
        shell: clap_complete::Shell,
    },
    /// Print local /instructions markdown, or a hosted broker's authoritative
    /// agent setup with --broker.
    Instructions {
        /// Render for a broker rooted here instead of the production layout.
        #[arg(long)]
        root: Option<PathBuf>,
        /// Fetch this hosted broker's authoritative agent setup instead of
        /// rendering local defaults. Requires its management token.
        #[arg(long)]
        broker: Option<String>,
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
        #[arg(long, requires = "listen", value_parser = parse_public_url)]
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
        #[arg(long, requires = "data_plane_listen")]
        data_plane_insecure: bool,
        /// Tear a brokered session down after this many seconds with the
        /// backend idle and the client silent (default 300). Raise it for
        /// LISTEN/NOTIFY workloads, which are protocol-idle while waiting.
        #[arg(long, value_name = "SECS", value_parser = parse_positive_seconds)]
        session_idle_timeout: Option<u64>,
        /// Hard ceiling on one brokered session, in seconds (default 3600).
        /// Raise it for long COPY/pg_dump runs, which are severed mid-stream
        /// when it expires.
        #[arg(long, value_name = "SECS", value_parser = parse_positive_seconds)]
        session_max_ttl: Option<u64>,
        /// Record the SQL of each statement on a brokered Postgres session in
        /// the activity log. Off by default: statement text can carry
        /// credentials and personal data into a durable log.
        #[arg(long)]
        audit_pg_statements: bool,
        /// Do not start the MCP host.
        #[arg(long, alias = "no-sidecar")]
        no_mcp: bool,
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
        #[arg(long, value_parser = parse_client_label)]
        client: Option<String>,
    },
    /// Open a Postgres session on a running broker. By default this prints
    /// shell-safe PGHOST/PGPORT/PGDATABASE/PGUSER/PGPASSWORD/PGSSLMODE exports:
    /// `eval "$(mfa dsn analytics)" && psql`. The ticket stays out of argv.
    Dsn {
        /// The pg connection's name.
        connection: String,
        /// Open against a broker rooted here instead of the default layout.
        #[arg(long)]
        root: Option<PathBuf>,
        /// Label this client in the user's activity log (e.g. claude-code).
        /// Attribution only, never authorization.
        #[arg(long, value_parser = parse_client_label)]
        client: Option<String>,
        /// Output shape. `env` (the default) keeps the ticket in PGPASSWORD;
        /// `uri` embeds it in a DSN and is visible in argv.
        #[arg(long, value_enum)]
        format: Option<DsnFormat>,
        /// Print only the short-lived ticket, for an explicit PGPASSWORD
        /// assignment. Mutually exclusive with --format.
        #[arg(long, conflicts_with = "format")]
        password_only: bool,
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
        #[arg(long, value_parser = parse_client_label)]
        client: Option<String>,
    },
    /// Run a local ssh-agent socket that speaks for a connection's *direct
    /// endpoint*, presenting the endpoint secret the agent protocol gives
    /// stock `ssh` no way to send.
    ///
    /// Only needed for an endpoint issued with `--require-auth`: an
    /// unauthenticated endpoint socket can be used directly as
    /// `IdentityAgent`. Every request still reaches the broker and the broker
    /// still asks — this adds the credential, never a decision.
    ///
    /// With a trailing `-- <command…>`, runs that command with SSH_AUTH_SOCK
    /// already pointing at the socket and exits with its status; without one,
    /// prints the socket path and stays in the foreground until interrupted.
    #[command(name = "ssh-agent")]
    SshAgent {
        /// The ssh connection whose endpoint to speak for.
        connection: String,
        /// Use this broker root for local management; with --broker, use its
        /// local management-credential store.
        #[arg(long)]
        root: Option<PathBuf>,
        /// Manage the broker at this manage-API URL instead of this machine's.
        #[arg(long)]
        broker: Option<String>,
        /// Bind here instead of a private temporary path, so a
        /// `~/.ssh/config` `IdentityAgent` line can name it. The path outlives
        /// no run: the socket is removed when this command exits.
        #[arg(long)]
        socket: Option<PathBuf>,
        /// Run this with SSH_AUTH_SOCK set, then exit with its status.
        #[arg(last = true)]
        command: Vec<String>,
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
    /// List live data-plane sessions, or close one by id.
    Sessions {
        /// Close this session instead of listing sessions.
        #[arg(long)]
        close: Option<u64>,
        /// Use this broker root for local management; with --broker, use its
        /// local management-credential store.
        #[arg(long)]
        root: Option<PathBuf>,
        /// Manage the broker at this manage-API URL instead of this machine's.
        #[arg(long)]
        broker: Option<String>,
    },
    /// List pending and recent approval/elicitation decision records.
    Requests {
        /// Attach a polling request inbox until Ctrl-C. Use another terminal
        /// with --approve or --deny to answer an id it prints.
        #[arg(long, conflicts_with_all = ["approve", "deny"])]
        watch: bool,
        /// Approve one pending request for its bounded confirmation window.
        #[arg(long, value_name = "ID", conflicts_with = "deny")]
        approve: Option<Uuid>,
        /// Deny one pending approval or elicitation.
        #[arg(long, value_name = "ID")]
        deny: Option<Uuid>,
        /// Elicitation answer in NAME=VALUE form; repeat for multiple fields.
        #[arg(
            long = "value",
            value_name = "NAME=VALUE",
            requires = "approve",
            value_parser = parse_field_value
        )]
        values: Vec<String>,
        /// Operate on a broker rooted here instead of the default layout.
        #[arg(long)]
        root: Option<PathBuf>,
        /// Manage the broker at this manage-API URL instead of this machine's.
        #[arg(long)]
        broker: Option<String>,
    },
    /// Read or update broker settings.
    Settings {
        #[command(subcommand)]
        command: SettingsCommand,
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
    /// Show the broker's audit trail, newest last. Local reads project the
    /// append-only log onto the same schema returned by a remote broker.
    Activity {
        /// Show only the last N entries; 0 shows everything.
        #[arg(long, default_value_t = 20)]
        limit: usize,
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
        /// Preserve the input byte-for-byte. By default one trailing CRLF,
        /// LF, or CR (commonly added by echo or a heredoc) is removed.
        #[arg(long)]
        raw: bool,
        /// Operate on a broker rooted here instead of the default layout.
        #[arg(long)]
        root: Option<PathBuf>,
        /// Create a missing explicit --root before seeding this first secret.
        #[arg(long, requires = "root")]
        create_root: bool,
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
        /// Preserve the input byte-for-byte. By default one trailing CRLF,
        /// LF, or CR (commonly added by echo or a heredoc) is removed.
        #[arg(long)]
        raw: bool,
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
        /// For CI, prefer AKA_MANAGE_TOKEN so the token is not persisted.
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
    /// Rotate this broker's management token and print it once. When the
    /// broker is running, authorizes with the current saved/environment
    /// token or its owner-only first-start token file. Falls back to an
    /// offline issue when the local broker is stopped.
    Token {
        /// Revoke the management token instead (closes the manage API).
        #[arg(long)]
        revoke: bool,
        /// Expire the token this many days after issue (default 30, maximum
        /// 3650). The desktop app re-prompts for a fresh one when it expires.
        #[arg(
            long,
            default_value = "30",
            value_parser = parse_manage_ttl_days
        )]
        ttl_days: Option<u64>,
        /// Operate on a broker rooted here instead of the default layout.
        #[arg(long)]
        root: Option<PathBuf>,
        /// Rotate a hosted broker through its manage API.
        #[arg(long, conflicts_with = "create_root")]
        broker: Option<String>,
        /// Create a missing explicit --root before issuing its first token.
        #[arg(long, requires = "root", conflicts_with = "broker")]
        create_root: bool,
    },
}

#[derive(Subcommand)]
enum SettingsCommand {
    /// Print the broker's effective settings.
    Get {
        /// Operate on a broker rooted here instead of the default layout.
        #[arg(long)]
        root: Option<PathBuf>,
        /// Manage the broker at this manage-API URL instead of this
        /// machine's.
        #[arg(long)]
        broker: Option<String>,
    },
    /// Change one or more broker settings.
    Set {
        /// Hide the Dock icon while the menu-bar window is active.
        #[arg(long)]
        menu_bar_hides_dock: Option<bool>,
        /// Ask before trusting an SSH server's host key the first time it is
        /// seen, instead of pinning it silently. Needs an attached approval
        /// surface: with none, the first login to an unpinned server is
        /// refused rather than trusted.
        #[arg(long)]
        confirm_ssh_host_keys: Option<bool>,
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
    /// Show one connection's policy, endpoint, health, and capability fields.
    Show {
        name: String,
        #[arg(long)]
        root: Option<PathBuf>,
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
    /// Report or change whether an API connection may return credential-bearing
    /// upstream response headers to agents. They are returned by default.
    ResponseCredentials {
        /// The API connection to inspect or change.
        name: String,
        /// Restore the default and allow credential-bearing headers.
        #[arg(long, conflicts_with = "contain")]
        allow: bool,
        /// Contain credential-bearing headers at the broker boundary.
        #[arg(long)]
        contain: bool,
        /// Operate on a broker rooted here instead of the default layout.
        #[arg(long)]
        root: Option<PathBuf>,
        /// Manage the broker at this manage-API URL instead of this machine's.
        #[arg(long)]
        broker: Option<String>,
    },
    /// Record the SQL of this Postgres connection's statements in the
    /// activity log, or stop. Without --on or --off, prints the effective
    /// setting. Statement text can carry credentials and personal data, so
    /// this is a per-destination retention choice on top of the broker-wide
    /// --audit-pg-statements default.
    AuditStatements {
        /// The connection to change.
        name: String,
        /// Start recording statement text for this connection.
        #[arg(long, conflicts_with_all = ["off", "default"])]
        on: bool,
        /// Stop recording statement text for this connection.
        #[arg(long, conflicts_with = "default")]
        off: bool,
        /// Drop the override and follow the broker-wide default.
        #[arg(long)]
        default: bool,
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
    /// Print, issue/rotate, renew, or revoke a connection's direct endpoint.
    /// Issuance requires a running local or remote broker to own the listener;
    /// reads and revocation also work as offline edits.
    Endpoint {
        /// The connection whose endpoint to print.
        name: String,
        /// Issue a new endpoint, or rotate the existing endpoint's secret.
        /// The broker must be running so it can own the endpoint listener.
        #[arg(long, conflicts_with = "revoke")]
        issue: bool,
        /// Extend the existing endpoint for 30 days without changing its
        /// address or secret. The broker must be running.
        #[arg(long, conflicts_with_all = ["issue", "revoke"])]
        renew: bool,
        /// Revoke this connection's issued endpoint. Unlike issuance, this
        /// can be performed as an offline edit while the broker is stopped.
        #[arg(long, conflicts_with_all = ["issue", "renew", "url", "secret"])]
        revoke: bool,
        /// ssh: make the agent socket refuse to list or sign until the caller
        /// presents the endpoint secret, so finding the socket is no longer
        /// enough to use it. Stock `ssh` cannot send the extension that does
        /// this — reach an authenticated endpoint through `mfa ssh-agent`.
        #[arg(long, conflicts_with_all = ["revoke", "no_require_auth"])]
        require_auth: bool,
        /// ssh: stop requiring authentication on the agent socket, returning
        /// it to "whoever can open it can sign". Takes a fresh confirmation.
        #[arg(long, conflicts_with = "revoke")]
        no_require_auth: bool,
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
        /// Manage the broker at this manage-API URL instead of this machine's.
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
    /// JSON-RPC path (e.g. `/mcp`). The MCP host then re-exposes its tools;
    /// the credential still rides the pinned host's `/v1/http` plane.
    #[arg(long)]
    mcp_path: Option<String>,
    /// api: the path `conn test` fetches (e.g. `/user`). Most APIs answer
    /// 404 or 403 at the origin root, so a test there proves reachability
    /// and TLS but never exercises the credential. Name a route that reads
    /// the account and the test answers the question it is being asked.
    #[arg(long)]
    test_path: Option<String>,
    /// api: sign each request with AWS SigV4 for this region instead of
    /// injecting a template. Requires --sigv4-service and both credential
    /// refs; replaces --template.
    #[arg(long)]
    sigv4_region: Option<String>,
    /// api: SigV4 signing service name (e.g. s3, execute-api, bedrock).
    #[arg(long, requires = "sigv4_region")]
    sigv4_service: Option<String>,
    /// api: vault secret name holding the AWS access key ID.
    #[arg(long, requires = "sigv4_region")]
    sigv4_access_key_ref: Option<String>,
    /// api: vault secret name holding the AWS secret access key.
    #[arg(long, requires = "sigv4_region")]
    sigv4_secret_key_ref: Option<String>,
    /// api: vault secret name holding a session token (temporary
    /// credentials), signed and sent as x-amz-security-token.
    #[arg(long, requires = "sigv4_region")]
    sigv4_session_token_ref: Option<String>,
    /// api: mint GCP access tokens from the service-account JSON key stored
    /// under this vault secret name instead of injecting a template.
    /// Requires --gcp-scope; replaces --template.
    #[arg(long, conflicts_with = "sigv4_region")]
    gcp_key_ref: Option<String>,
    /// api: space-separated OAuth scopes for minted GCP tokens (e.g.
    /// https://www.googleapis.com/auth/devstorage.read_only).
    #[arg(long, requires = "gcp_key_ref")]
    gcp_scope: Option<String>,
    /// api: PEM client-certificate chain presented on the upstream TLS leg
    /// (mTLS). Requires --client-key.
    #[arg(long, requires = "client_key")]
    client_cert: Option<String>,
    /// api: PEM private key for --client-cert (PKCS#8, PKCS#1, or SEC1).
    #[arg(long, requires = "client_cert")]
    client_key: Option<String>,
    /// Operate on a broker rooted here instead of the default layout.
    #[arg(long)]
    root: Option<PathBuf>,
    /// Create a missing explicit --root before seeding this first connection.
    #[arg(long, requires = "root")]
    create_root: bool,
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

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum DsnFormat {
    Env,
    Uri,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EndpointAction {
    Read,
    Issue,
    Renew,
    Revoke,
}

fn endpoint_action(issue: bool, renew: bool, revoke: bool) -> Result<EndpointAction, &'static str> {
    match (issue, renew, revoke) {
        (false, false, false) => Ok(EndpointAction::Read),
        (true, false, false) => Ok(EndpointAction::Issue),
        (false, true, false) => Ok(EndpointAction::Renew),
        (false, false, true) => Ok(EndpointAction::Revoke),
        _ => Err("--issue, --renew, and --revoke are mutually exclusive"),
    }
}

/// The requested socket-authentication posture, or `None` to leave it alone.
/// Clap already refuses both flags together, so this only names the mapping.
fn endpoint_require_auth(require_auth: bool, no_require_auth: bool) -> Option<bool> {
    match (require_auth, no_require_auth) {
        (true, _) => Some(true),
        (_, true) => Some(false),
        _ => None,
    }
}

fn endpoint_action_supported(action: EndpointAction, online: bool) -> Result<(), &'static str> {
    if matches!(action, EndpointAction::Issue | EndpointAction::Renew) && !online {
        Err(
            "direct endpoint issuance and renewal require a running broker to own the listener; \
             start AgentMFA or `mfa serve`, then retry",
        )
    } else {
        Ok(())
    }
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
    /// api: the path `conn test` fetches (e.g. `/user`); pass '' to fall
    /// back to the MCP path or the origin root.
    #[arg(long)]
    test_path: Option<String>,
    /// Operate on a broker rooted here instead of the default layout.
    #[arg(long)]
    root: Option<PathBuf>,
    /// Manage the broker at this manage-API URL instead of this
    /// machine's.
    #[arg(long)]
    broker: Option<String>,
}

fn main() {
    match std::panic::catch_unwind(run_cli) {
        Ok(()) => {}
        Err(payload) => match payload.downcast::<CliExit>() {
            Ok(exit) => std::process::exit(exit.code),
            Err(payload) => std::panic::resume_unwind(payload),
        },
    }
}

fn run_cli() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "warn,aka_core=info".into()),
        )
        .with_writer(std::io::stderr)
        .try_init()
        .ok();
    let cli = Cli::parse();
    let json = cli.json;
    match cli.command {
        Command::Skill {
            write,
            path,
            user,
            force,
            root,
            broker,
        } => cmd_skill(write, path, user, force, root, broker),
        Command::Completions { shell } => {
            use clap::CommandFactory as _;
            let mut command = Cli::command();
            let name = command.get_name().to_string();
            clap_complete::generate(shell, &mut command, name, &mut std::io::stdout());
        }
        Command::Instructions { root, broker } => cmd_instructions(root, broker),
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
            no_mcp,
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
            no_mcp,
        }),
        Command::Mcp { root, client } => cmd_mcp(root, client),
        Command::Dsn {
            connection,
            root,
            client,
            format,
            password_only,
        } => cmd_dsn(connection, root, client, format, password_only, json),
        Command::Ssh {
            connection,
            root,
            client,
        } => cmd_ssh(connection, root, client, json),
        Command::SshAgent {
            connection,
            root,
            broker,
            socket,
            command,
        } => cmd_ssh_agent(connection, root, broker, socket, command),
        Command::Secret { command } => match command {
            SecretCommand::Add {
                name,
                value_env,
                raw,
                root,
                create_root,
                broker,
            } => {
                reject_json_for_mutation(json);
                cmd_secret_add(name, value_env, raw, root, create_root, broker)
            }
            SecretCommand::List { root, broker } => cmd_secret_list(root, broker, json),
            SecretCommand::Rename {
                name,
                new_name,
                root,
                broker,
            } => {
                reject_json_for_mutation(json);
                cmd_secret_rename(name, new_name, root, broker)
            }
            SecretCommand::Replace {
                name,
                value_env,
                raw,
                root,
                broker,
            } => {
                reject_json_for_mutation(json);
                cmd_secret_replace(name, value_env, raw, root, broker)
            }
            SecretCommand::Rm { name, root, broker } => {
                reject_json_for_mutation(json);
                cmd_secret_rm(name, root, broker)
            }
        },
        Command::Conn { command } => match command {
            ConnCommand::Add(args) => {
                reject_json_for_mutation(json);
                cmd_conn_add(args)
            }
            ConnCommand::List { root, broker } => cmd_conn_list(root, broker, json),
            ConnCommand::Show { name, root, broker } => cmd_conn_show(name, root, broker, json),
            ConnCommand::Update(args) => {
                reject_json_for_mutation(json);
                cmd_conn_update(args)
            }
            ConnCommand::Rename {
                name,
                new_name,
                root,
                broker,
            } => {
                reject_json_for_mutation(json);
                cmd_conn_rename(name, new_name, root, broker)
            }
            ConnCommand::Rm { name, root, broker } => {
                reject_json_for_mutation(json);
                cmd_conn_rm(name, root, broker)
            }
            ConnCommand::Enable { name, root, broker } => {
                reject_json_for_mutation(json);
                cmd_conn_access(name, root, broker, true)
            }
            ConnCommand::Disable { name, root, broker } => {
                reject_json_for_mutation(json);
                cmd_conn_access(name, root, broker, false)
            }
            ConnCommand::Confirm {
                name,
                off,
                root,
                broker,
            } => {
                reject_json_for_mutation(json);
                cmd_conn_confirm(name, root, broker, !off)
            }
            ConnCommand::ResponseCredentials {
                name,
                allow,
                contain,
                root,
                broker,
            } => {
                reject_json_for_mutation(json);
                cmd_conn_response_credentials(name, root, broker, allow, contain)
            }
            ConnCommand::AuditStatements {
                name,
                on,
                off,
                default,
                root,
                broker,
            } => {
                reject_json_for_mutation(json);
                cmd_conn_audit_statements(name, root, broker, on, off, default)
            }
            ConnCommand::Test { name, root, broker } => cmd_conn_test(name, root, broker, json),
            ConnCommand::Endpoint {
                name,
                issue,
                renew,
                revoke,
                require_auth,
                no_require_auth,
                url,
                secret,
                root,
                broker,
            } => cmd_conn_endpoint(
                name,
                issue,
                renew,
                revoke,
                endpoint_require_auth(require_auth, no_require_auth),
                url,
                secret,
                root,
                broker,
                json,
            ),
        },
        Command::Sessions {
            close,
            root,
            broker,
        } => cmd_sessions(close, root, broker, json),
        Command::Requests {
            watch,
            approve,
            deny,
            values,
            root,
            broker,
        } => cmd_requests(watch, approve, deny, values, root, broker, json),
        Command::Settings { command } => match command {
            SettingsCommand::Get { root, broker } => cmd_settings_get(root, broker, json),
            SettingsCommand::Set {
                menu_bar_hides_dock,
                confirm_ssh_host_keys,
                root,
                broker,
            } => cmd_settings_set(
                menu_bar_hides_dock,
                confirm_ssh_host_keys,
                root,
                broker,
                json,
            ),
        },
        Command::Manage { command } => match command {
            ManageCommand::Login {
                broker,
                token_env,
                root,
            } => {
                reject_json_for_mutation(json);
                cmd_manage_login(broker, token_env, root)
            }
            ManageCommand::Logout { broker, root } => {
                reject_json_for_mutation(json);
                cmd_manage_logout(broker, root)
            }
            ManageCommand::Token {
                revoke,
                ttl_days,
                root,
                broker,
                create_root,
            } => {
                reject_json_for_mutation(json);
                cmd_manage_token(revoke, ttl_days, root, broker, create_root)
            }
        },
        Command::Key {
            rotate,
            root,
            broker,
        } => cmd_key(rotate, root, broker, json),
        Command::Status { root, broker } => cmd_status(json, root, broker),
        Command::Activity {
            limit,
            root,
            broker,
        } => cmd_activity(limit, json, root, broker),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
enum ExitCode {
    Generic = 1,
    Usage = 2,
    NoBroker = 3,
    Authentication = 4,
    NotFound = 5,
    Conflict = 6,
    RemoteUnreachable = 7,
    TestFailed = 8,
}

#[derive(Debug)]
struct CliExit {
    code: i32,
}

/// Unwind the active command before the process exits. In particular, this
/// gives every `Zeroizing<String>` holding a secret, management token, or
/// short-lived credential a chance to scrub its allocation.
fn exit_with(code: ExitCode) -> ! {
    exit_with_raw(code as i32)
}

/// Exit carrying a status this process did not choose: the exit code of a
/// child command run on the user's behalf. Flattening those to a generic
/// failure would hide the distinctions a caller acts on — `ssh`'s 255 for
/// "could not connect" reads very differently from the remote command's 1.
fn exit_with_raw(code: i32) -> ! {
    std::panic::resume_unwind(Box::new(CliExit { code }))
}

fn die_with(code: ExitCode, message: impl std::fmt::Display) -> ! {
    eprintln!("error: {message}");
    exit_with(code);
}

fn die(message: impl std::fmt::Display) -> ! {
    die_with(ExitCode::Generic, message)
}

fn manage_error_exit_code(error: &ManageError) -> ExitCode {
    match error {
        ManageError::InvalidSecretName { .. }
        | ManageError::InvalidConnectionName { .. }
        | ManageError::Template { .. }
        | ManageError::UnknownTemplateRef { .. }
        | ManageError::WrongSecretCount { .. }
        | ManageError::InvalidConnectionConfig { .. }
        | ManageError::InvalidSetting { .. }
        | ManageError::InvalidConnectionField { .. }
        | ManageError::KindChange
        | ManageError::EndpointExpired
        | ManageError::EndpointRequiresWiring => ExitCode::Usage,
        ManageError::InvalidManageToken { .. } => ExitCode::Authentication,
        ManageError::SecretNotFound
        | ManageError::ConnectionNotFound
        | ManageError::EndpointNotFound => ExitCode::NotFound,
        ManageError::SecretNameTaken { .. }
        | ManageError::ConnectionNameTaken { .. }
        | ManageError::ConnectionTargetTaken { .. }
        | ManageError::ConnectionChanged
        | ManageError::ApprovalConnectionChanged
        | ManageError::SecretInUse { .. }
        | ManageError::EndpointLimit { .. } => ExitCode::Conflict,
        ManageError::Unreachable { .. } => ExitCode::RemoteUnreachable,
        ManageError::OAuth { .. }
        | ManageError::Vault { .. }
        | ManageError::RemoteUnsupported { .. }
        | ManageError::Internal { .. } => ExitCode::Generic,
    }
}

fn die_manage(error: ManageError) -> ! {
    die_with(manage_error_exit_code(&error), error)
}

fn print_json(value: &impl serde::Serialize) {
    println!(
        "{}",
        serde_json::to_string(value).expect("CLI result is serializable")
    );
}

fn reject_json_for_mutation(json: bool) {
    if json {
        die_with(
            ExitCode::Usage,
            "--json is not supported for this mutation; omit it to continue",
        );
    }
}

fn store_paths(root: Option<&Path>) -> Paths {
    match root {
        Some(root) => Paths::under(root),
        None => Paths::default_locations().unwrap_or_else(|error| {
            die(format!(
                "could not determine the per-user data and socket directories: {error}; \
                 set HOME (and, where applicable, XDG_DATA_HOME), or pass --root"
            ))
        }),
    }
}

/// A typo in `--root` must not make a command silently create and operate on
/// a brand-new broker. Remote commands use the root only as an optional
/// management-token location, so the broker URL remains authoritative.
fn require_existing_root_for_read(root: Option<&Path>, remote: bool) {
    let Some(root) = root.filter(|_| !remote) else {
        return;
    };
    let data_dir = Paths::under(root).data_dir;
    if !data_dir.is_dir() {
        die(format!(
            "{} is not an existing broker root (expected its data directory at {})",
            root.display(),
            data_dir.display()
        ));
    }
}

fn open_vault(
    paths: &Paths,
    root: Option<&Path>,
) -> Result<Arc<dyn SecretVault>, aka_core::error::CoreError> {
    let vault = match root {
        Some(root) => platform_vault_for_root(paths, root),
        None => platform_vault(paths),
    }?;
    if selected_platform_vault_backend(paths) == PlatformVaultBackend::PlaintextDevFile {
        eprintln!(
            "  vault: plaintext dev fallback at {} (set AKA_VAULT_KEY or \
             AKA_VAULT_KEY_FILE)",
            paths.dev_vault_file().display()
        );
    }
    Ok(vault)
}

fn acquire_offline_store_lock(paths: &Paths) -> Result<BrokerInstanceLock, CoreError> {
    paths.ensure()?;
    let instance_lock = match paths.try_acquire_broker_lock_for(BrokerLockRole::Cli)? {
        BrokerLockAttempt::Acquired(lock) => lock,
        BrokerLockAttempt::Held(Some(holder)) if holder.role == BrokerLockRole::Cli => {
            return Err(CoreError::BrokerStateBusy(Some(holder.pid)));
        }
        BrokerLockAttempt::Held(_) => {
            return Err(CoreError::BrokerAlreadyRunning(paths.socket_display()));
        }
    };

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

/// Remove exactly the one line ending normally contributed by `echo`, a
/// terminal paste, or a heredoc. Environment and stdin inputs deliberately
/// share this rule; `--raw` preserves every byte.
fn normalize_secret_input(mut value: String, raw: bool) -> String {
    if raw {
        return value;
    }
    let trim = if value.ends_with("\r\n") {
        2
    } else if value.ends_with('\n') || value.ends_with('\r') {
        1
    } else {
        0
    };
    value.truncate(value.len() - trim);
    value
}

/// Read a secret value from `--value-env` or stdin — never argv, where it
/// would sit in `ps` output and shell history.
fn read_secret_value(value_env: &Option<String>, raw: bool) -> SecretValue {
    let value = match value_env {
        Some(var) => match std::env::var(var) {
            Ok(value) => value,
            Err(_) => die(format!("environment variable {var} is not set")),
        },
        None => {
            if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
                eprintln!("  reading the secret value from stdin; end with Ctrl-D");
            }
            match std::io::read_to_string(std::io::stdin()) {
                Ok(text) => text,
                Err(e) => die(format!("could not read the value from stdin: {e}")),
            }
        }
    };
    let value = Zeroizing::new(normalize_secret_input(value, raw));
    if value.is_empty() {
        die("the secret value is empty");
    }
    value
}

fn cmd_secret_add(
    name: String,
    value_env: Option<String>,
    raw: bool,
    root: Option<PathBuf>,
    create_root: bool,
    url: Option<String>,
) {
    let managed = management_backend_with_create(root, url, create_root);
    let value = read_secret_value(&value_env, raw);
    let byte_len = value.len();
    managed.run(managed.backend.add_secret(name.clone(), value));
    eprintln!("added secret {name} ({byte_len} bytes)");
}

fn cmd_secret_list(root: Option<PathBuf>, url: Option<String>, json: bool) {
    let managed = management_backend(root, url);
    let secrets = managed.run(managed.backend.list_secrets());
    if json {
        print_json(&secrets);
        return;
    }
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
    remote: Option<Arc<RemoteBackend>>,
    profile: Option<serde_json::Value>,
}

impl Managed {
    /// Run one management call to completion; a failure exits with the
    /// broker's own error line.
    fn run<T>(&self, call: impl std::future::Future<Output = ManageResult<T>>) -> T {
        match self.runtime.block_on(call) {
            Ok(value) => value,
            Err(e) => die_manage(e),
        }
    }

    /// A live desktop-owned broker may show a native confirmation outside
    /// this terminal. Make that wait visible before the request blocks.
    fn run_gated<T>(&self, call: impl std::future::Future<Output = ManageResult<T>>) -> T {
        if self.approval_surface_attached() {
            eprintln!("  waiting for confirmation in the AgentMFA app…");
        }
        self.run(call)
    }

    fn approval_surface_attached(&self) -> bool {
        self.profile
            .as_ref()
            .and_then(|profile| profile["approval_surface_attached"].as_bool())
            .unwrap_or(false)
    }

    fn require_approval_surface(&self) {
        if self.remote.is_none() {
            die(
                "cannot enable traffic confirmation in an offline/headless edit: no approval \
                 surface is attached",
            );
        }
        if !self.approval_surface_attached() {
            die(
                "cannot enable traffic confirmation: no approval surface is attached; open the \
                 AgentMFA app and keep its request inbox connected, then retry",
            );
        }
    }
}

fn warn_version_skew(profile: &serde_json::Value) {
    let Some(broker_version) = profile["version"].as_str() else {
        return;
    };
    let cli_version = env!("CARGO_PKG_VERSION");
    if broker_version != cli_version {
        eprintln!(
            "warning: broker version {broker_version} differs from mfa CLI version {cli_version}; \
             update them together before making changes"
        );
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
        let token = Zeroizing::new(token);
        if !token.trim().is_empty() {
            return Some(Zeroizing::new(token.trim().to_string()));
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
    management_backend_with_create(root, url, false)
}

fn effective_broker_url(url: Option<String>) -> Option<String> {
    url.or_else(|| {
        std::env::var("AKA_BROKER_URL")
            .ok()
            .filter(|value| !value.trim().is_empty())
    })
}

fn management_backend_with_create(
    root: Option<PathBuf>,
    url: Option<String>,
    create_root: bool,
) -> Managed {
    let url = effective_broker_url(url);
    if !create_root {
        require_existing_root_for_read(root.as_deref(), url.is_some());
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let paths = store_paths(root.as_deref());
    if let Some(url) = url {
        let url = match RemoteConfig::normalize_url(&url) {
            Ok(url) => url,
            Err(e) => die_with(ExitCode::Usage, e),
        };
        let Some(token) = manage_token(&paths, &url) else {
            die_with(
                ExitCode::Authentication,
                format!(
                    "no management token for {url} — set AKA_MANAGE_TOKEN, or store \
                 one with `mfa manage login --broker {url}` (issued by `mfa \
                 manage token` on the broker host)"
                ),
            );
        };
        let config = match RemoteConfig::new(&url, &token) {
            Ok(config) => config,
            Err(e) => die_with(ExitCode::Usage, e),
        };
        eprintln!("  managing the broker at {url}");
        let remote = Arc::new(RemoteBackend::new(config));
        let profile = runtime
            .block_on(remote.whoami())
            .unwrap_or_else(|error| die_manage(error));
        warn_version_skew(&profile);
        return Managed {
            runtime,
            backend: remote.clone(),
            remote: Some(remote),
            profile: Some(profile),
        };
    }
    let socket = paths.socket_file();
    let broker_running = runtime
        .block_on(tokio::net::UnixStream::connect(&socket))
        .is_ok();
    if broker_running {
        let key = socket.display().to_string();
        let Some(token) = manage_token(&paths, &key) else {
            die_with(
                ExitCode::Authentication,
                format!(
                    "a broker is running on {key}.\n\
                 To edit it live, run `mfa manage token` to consume its \
                 first-start credential or rotate a saved token, store a token \
                 with `mfa manage login`, or set AKA_MANAGE_TOKEN."
                ),
            );
        };
        eprintln!("  managing the running broker over {key}");
        let remote = Arc::new(RemoteBackend::over_unix_socket(socket, &token));
        let profile = runtime
            .block_on(remote.whoami())
            .unwrap_or_else(|error| die_manage(error));
        warn_version_skew(&profile);
        return Managed {
            runtime,
            backend: remote.clone(),
            remote: Some(remote),
            profile: Some(profile),
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
        Err(CoreError::BrokerStateBusy(pid)) => die(format!(
            "another CLI process{} is editing this broker state — wait for it to finish, then retry",
            pid.map(|pid| format!(" (pid {pid})")).unwrap_or_default()
        )),
        Err(e) => die(format!("could not open the broker state: {e}")),
    };
    Managed {
        runtime,
        backend: Arc::new(LocalBackend::new(broker)),
        remote: None,
        profile: None,
    }
}

struct OfflineEvents;
impl BrokerEvents for OfflineEvents {}

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
        None => die_with(
            ExitCode::NotFound,
            format!("no secret named {name:?} (see `mfa secret list`)"),
        ),
    }
}

fn conn_dto(managed: &Managed, name: &str) -> ConnectionDto {
    let connections = managed.run(managed.backend.list_connections());
    match connections.into_iter().find(|c| c.name == name) {
        Some(dto) => dto,
        None => die_with(
            ExitCode::NotFound,
            format!("no connection named {name:?} (see `mfa conn list`)"),
        ),
    }
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
    raw: bool,
    root: Option<PathBuf>,
    url: Option<String>,
) {
    let value = read_secret_value(&value_env, raw);
    let byte_len = value.len();
    let managed = management_backend(root, url);
    let dto = secret_dto(&managed, &name);
    managed.run(
        managed
            .backend
            .edit_secret(dto_id(&dto.id), None, Some(value)),
    );
    eprintln!("replaced the value of secret {name} ({byte_len} bytes)");
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
        Err(e) => die_with(ExitCode::Usage, e),
    };
    let managed =
        management_backend_with_create(args.root.clone(), args.broker.clone(), args.create_root);
    // pg/ssh bind at most one secret by name; api derives its secrets
    // from the template's refs inside add_connection.
    let secrets = match (&args.secret, args.kind) {
        (_, ConnKind::Api) => Vec::new(),
        (Some(name), _) => vec![dto_id(&secret_dto(&managed, name).id)],
        (None, _) => Vec::new(),
    };
    let name = args.name.clone();
    managed.run_gated(managed.backend.add_connection(ConnectionSpec {
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
            let signer = match (&args.sigv4_region, &args.gcp_key_ref) {
                (Some(_), _) | (_, Some(_)) if args.template.is_some() => {
                    return Err(
                        "--template does not apply to a signed connection; the signer \
                         computes the Authorization header"
                            .into(),
                    );
                }
                (Some(region), _) => Some(SignerSpec::AwsSigv4 {
                    region: region.clone(),
                    service: require("sigv4-service", &args.sigv4_service)?,
                    access_key_ref: require("sigv4-access-key-ref", &args.sigv4_access_key_ref)?,
                    secret_key_ref: require("sigv4-secret-key-ref", &args.sigv4_secret_key_ref)?,
                    session_token_ref: args.sigv4_session_token_ref.clone(),
                }),
                (_, Some(key_ref)) => Some(SignerSpec::GcpServiceAccount {
                    key_ref: key_ref.clone(),
                    scope: require("gcp-scope", &args.gcp_scope)?,
                }),
                (None, None) => None,
            };
            // Host before template, so a bare `--kind api` still names
            // `--host` as the first thing missing.
            let host = require("host", &args.host)?;
            let template = if signer.is_some() {
                String::new()
            } else {
                require("template", &args.template)?
            };
            Ok(ConnectionConfig::Api {
                host,
                scheme: args.scheme.clone().unwrap_or_else(|| "https".into()),
                port: args.port,
                trusted_ca_bundle_path: args.ca_bundle.clone(),
                template,
                mcp_path: args.mcp_path.clone(),
                test_path: args.test_path.clone(),
                oauth: None,
                signer,
                client_cert_path: args.client_cert.clone(),
                client_key_path: args.client_key.clone(),
            })
        }
        ConnKind::Pg => {
            forbid(&[
                ("scheme", args.scheme.is_some()),
                ("template", args.template.is_some()),
                ("host-key-fingerprint", args.host_key_fingerprint.is_some()),
                ("mcp-path", args.mcp_path.is_some()),
                ("test-path", args.test_path.is_some()),
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
                ("test-path", args.test_path.is_some()),
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

fn cmd_conn_list(root: Option<PathBuf>, url: Option<String>, json: bool) {
    let managed = management_backend(root, url);
    let connections = managed.run(managed.backend.list_connections());
    if json {
        print_json(&connections);
        return;
    }
    if connections.is_empty() {
        eprintln!("no connections configured (add one with `mfa conn add`)");
        return;
    }
    for dto in connections {
        let mut state = Vec::new();
        if !dto.agent_access.enabled {
            state.push("disabled");
        }
        if dto.agent_access.confirm {
            state.push(if managed.approval_surface_attached() {
                "confirm: on"
            } else {
                "confirm: on (no approval surface attached — traffic will be refused)"
            });
        }
        if dto.agent_access.expose_response_credentials {
            state.push("response credentials: exposed");
        }
        println!(
            "{}  {}  {}{}",
            dto.name,
            dto.kind,
            dto.target,
            if state.is_empty() {
                String::new()
            } else {
                format!("  {}", state.join(" · "))
            }
        );
    }
}

fn cmd_conn_show(name: String, root: Option<PathBuf>, url: Option<String>, json: bool) {
    let managed = management_backend(root, url);
    let dto = conn_dto(&managed, &name);
    if json {
        print_json(&dto);
        return;
    }
    println!("name: {}", dto.name);
    println!("type: {}", dto.kind);
    println!("target: {}", dto.target);
    println!(
        "credentials: {}",
        if dto.secret_names.is_empty() {
            "none".into()
        } else {
            dto.secret_names.join(", ")
        }
    );
    println!(
        "agent access: {}",
        if dto.agent_access.enabled {
            "enabled"
        } else {
            "disabled"
        }
    );
    println!(
        "confirmation: {}",
        if dto.agent_access.confirm {
            "on"
        } else {
            "off"
        }
    );
    if let Some(until) = &dto.agent_access.confirm_window_until {
        let agents = if dto.agent_access.confirm_window_agents.is_empty() {
            "unknown agent".into()
        } else {
            dto.agent_access.confirm_window_agents.join(", ")
        };
        println!("confirmation window: until {until} for {agents}");
    }
    if let Some(until) = &dto.agent_access.confirm_cooldown_until {
        println!("denial cooldown: until {until}");
    }
    if dto.kind == "api" {
        println!(
            "upstream response credentials: {}",
            if dto.agent_access.expose_response_credentials {
                "exposed to agents"
            } else {
                "contained"
            }
        );
    }
    println!(
        "allowed MCP tools: {}",
        dto.agent_access
            .allowed_tools
            .as_ref()
            .map(|tools| {
                if tools.is_empty() {
                    "none".into()
                } else {
                    tools.join(", ")
                }
            })
            .unwrap_or_else(|| "all".into())
    );
    match &dto.agent_access.endpoint {
        Some(endpoint) => {
            let expiry = if endpoint.expires_at.is_empty() {
                String::new()
            } else {
                format!(", expires {}", endpoint.expires_at)
            };
            println!(
                "direct endpoint: {} ({}){}{}",
                endpoint
                    .dsn
                    .as_deref()
                    .unwrap_or("issued; use `mfa conn endpoint` to copy"),
                endpoint.kind,
                // Whether the socket is a standing signing oracle for anything
                // that can open it is the most consequential fact about an SSH
                // endpoint, so it belongs on the line that reports one.
                if endpoint.require_auth {
                    ", authenticated"
                } else {
                    ""
                },
                expiry,
            )
        }
        None => println!("direct endpoint: none"),
    }
    match (&dto.last_status, &dto.last_detail, &dto.last_checked_at) {
        (Some(status), detail, checked) => {
            println!("health: {status}");
            if let Some(detail) = detail {
                println!("health detail: {detail}");
            }
            if let Some(checked) = checked {
                println!("last checked: {checked}");
            }
        }
        _ => println!("health: untested"),
    }
}

fn cmd_sessions(close: Option<u64>, root: Option<PathBuf>, url: Option<String>, json: bool) {
    let managed = management_backend(root, url);
    if let Some(id) = close {
        let closed = managed.run(managed.backend.close_session(id));
        if !closed {
            die_with(ExitCode::NotFound, format!("no live session with id {id}"));
        }
        if json {
            print_json(&serde_json::json!({ "closed": true, "id": id }));
        } else {
            eprintln!("closed session {id}");
        }
        return;
    }
    let sessions = managed.run(managed.backend.sessions());
    if json {
        print_json(&sessions);
    } else if sessions.is_empty() {
        eprintln!("no live sessions");
    } else {
        for session in sessions {
            println!(
                "{}  {}  {}  {}  {}",
                session.id, session.kind, session.connection, session.agent, session.detail
            );
        }
    }
}

fn cmd_requests(
    watch: bool,
    approve: Option<Uuid>,
    deny: Option<Uuid>,
    values: Vec<String>,
    root: Option<PathBuf>,
    url: Option<String>,
    json: bool,
) {
    let managed = management_backend(root, url);
    if watch {
        if json {
            die_with(
                ExitCode::Usage,
                "--json cannot be combined with the unbounded --watch mode",
            );
        }
        watch_requests(&managed);
        return;
    }
    if let Some(id) = approve.or(deny) {
        answer_request(&managed, id, approve.is_some(), values, json);
        return;
    }
    let requests = managed.run(managed.backend.requests());
    if json {
        print_json(&requests);
    } else if requests.is_empty() {
        eprintln!("no pending or recent requests");
    } else {
        for request in requests {
            let at = request
                .resolved_at
                .as_deref()
                .unwrap_or(&request.requested_at);
            println!(
                "{}  {}  {}  {}  {}  {}",
                at,
                request.status,
                request.kind,
                request.connection,
                request.agent,
                request.summary
            );
        }
    }
}

fn answer_request(managed: &Managed, id: Uuid, approve: bool, values: Vec<String>, json: bool) {
    let Some(remote) = managed.remote.clone() else {
        die_with(
            ExitCode::NoBroker,
            "request decisions require a running broker",
        );
    };
    let surface = managed.run(remote.open_approval_surface());
    let surface_id = dto_id(&surface.id);

    let approvals = managed.run(managed.backend.approvals());
    let elicitations = managed.run(managed.backend.elicitations());
    let answered = if approvals.iter().any(|request| request.id == id.to_string()) {
        if !values.is_empty() {
            let _ = managed.run(remote.close_approval_surface(surface_id));
            die_with(
                ExitCode::Usage,
                "--value applies only when approving an elicitation",
            );
        }
        managed.run(managed.backend.respond_approval(
            id,
            if approve {
                aka_api::ApprovalDecisionDto::ApproveWindow
            } else {
                aka_api::ApprovalDecisionDto::Deny
            },
        ))
    } else if elicitations
        .iter()
        .any(|request| request.id == id.to_string())
    {
        let mut fields = std::collections::HashMap::new();
        if approve {
            for value in values {
                let (name, value) = value.split_once('=').expect("validated by clap");
                if fields.insert(name.to_string(), value.to_string()).is_some() {
                    let _ = managed.run(remote.close_approval_surface(surface_id));
                    die_with(
                        ExitCode::Usage,
                        format!("elicitation field {name:?} was supplied more than once"),
                    );
                }
            }
        }
        managed.run(managed.backend.respond_elicitation(id, approve, fields))
    } else {
        let _ = managed.run(remote.close_approval_surface(surface_id));
        die_with(
            ExitCode::NotFound,
            format!("no pending approval or elicitation with id {id}"),
        );
    };
    let _ = managed.run(remote.close_approval_surface(surface_id));
    if !answered {
        die_with(
            ExitCode::Conflict,
            format!("request {id} was already answered, revoked, or expired"),
        );
    }
    let decision = if approve { "approved" } else { "denied" };
    if json {
        print_json(&serde_json::json!({
            "answered": true,
            "id": id,
            "decision": decision,
        }));
    } else {
        eprintln!("{decision} request {id}");
    }
}

fn watch_requests(managed: &Managed) {
    let Some(remote) = managed.remote.clone() else {
        die_with(
            ExitCode::NoBroker,
            "the request inbox requires a running broker",
        );
    };
    let surface = managed.run(remote.open_approval_surface());
    let surface_id = dto_id(&surface.id);
    eprintln!(
        "request inbox attached; press Ctrl-C to detach\n\
         answer from another terminal with `mfa requests --approve ID` or `--deny ID`"
    );

    let backend = managed.backend.clone();
    let result: ManageResult<()> = managed.runtime.block_on(async {
        let mut seen = std::collections::HashSet::new();
        let mut poll = tokio::time::interval(std::time::Duration::from_millis(500));
        let mut heartbeat = tokio::time::interval(std::time::Duration::from_millis(
            aka_api::APPROVAL_SURFACE_HEARTBEAT_MS,
        ));
        let shutdown = tokio::signal::ctrl_c();
        tokio::pin!(shutdown);
        // The lease minted above covers startup; do not immediately issue a
        // redundant heartbeat.
        poll.tick().await;
        heartbeat.tick().await;
        loop {
            tokio::select! {
                _ = &mut shutdown => break,
                _ = heartbeat.tick() => remote.renew_approval_surface(surface_id).await?,
                _ = poll.tick() => {
                    for request in backend.approvals().await? {
                        if seen.insert(request.id.clone()) {
                            println!(
                                "{}  approval  {}  {}  {}",
                                request.id, request.connection, request.agent, request.summary
                            );
                            if let Some(detail) = request.detail {
                                println!("  {detail}");
                            }
                            if let Some(consequence) = request.consequence {
                                println!("  {consequence}");
                            }
                        }
                    }
                    for request in backend.elicitations().await? {
                        if seen.insert(request.id.clone()) {
                            println!(
                                "{}  elicitation  {}  {}  {}",
                                request.id, request.connection, request.agent, request.prompt
                            );
                            for field in request.fields {
                                let required = if field.required { " (required)" } else { "" };
                                println!("  {}{required}", field.name);
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    });
    let _ = managed.run(remote.close_approval_surface(surface_id));
    if let Err(error) = result {
        die_manage(error);
    }
    eprintln!("request inbox detached");
}

fn cmd_settings_get(root: Option<PathBuf>, url: Option<String>, json: bool) {
    let managed = management_backend(root, url);
    let settings = managed.run(managed.backend.settings());
    if json {
        print_json(&settings);
    } else {
        println!("menu bar hides Dock: {}", settings.menu_bar_hides_dock);
        println!(
            "confirm new SSH host keys: {}",
            settings.confirm_ssh_host_keys
        );
    }
}

fn cmd_settings_set(
    menu_bar_hides_dock: Option<bool>,
    confirm_ssh_host_keys: Option<bool>,
    root: Option<PathBuf>,
    url: Option<String>,
    json: bool,
) {
    if menu_bar_hides_dock.is_none() && confirm_ssh_host_keys.is_none() {
        die_with(
            ExitCode::Usage,
            "settings set requires at least one setting flag",
        );
    }
    let managed = management_backend(root, url);
    if let Some(on) = menu_bar_hides_dock {
        managed.run_gated(managed.backend.set_menu_bar_hides_dock(on));
    }
    if let Some(on) = confirm_ssh_host_keys {
        if on {
            managed.require_approval_surface();
        }
        managed.run_gated(managed.backend.set_confirm_ssh_host_keys(on));
    }
    let settings = managed.run(managed.backend.settings());
    if json {
        print_json(&settings);
    } else {
        eprintln!("settings updated");
        println!("menu bar hides Dock: {}", settings.menu_bar_hides_dock);
        println!(
            "confirm new SSH host keys: {}",
            settings.confirm_ssh_host_keys
        );
    }
}

/// The CLI deliberately leaves OAuth-managed capability coordinates to the
/// broker/app flow. Ordinary updates below are field patches, never a
/// reconstruction of the complete config.
fn refuse_oauth_managed(dto: &ConnectionDto) {
    if dto.oauth || dto.oauth_spec.is_some() {
        die(format!(
            "{} is an OAuth-managed connection; edit it in the AgentMFA app",
            dto.name
        ));
    }
}

/// Build a patch containing only flags the caller supplied. The broker merges
/// it into authoritative state after checking `updated_at`, so fields unknown
/// to this CLI version cannot be reset.
fn connection_config_patch(
    dto: &ConnectionDto,
    args: &ConnUpdate,
    secret_id: Option<Uuid>,
) -> Result<ConnectionConfigPatch, String> {
    let forbid = |present: &[(&str, bool)]| -> Result<(), String> {
        match present.iter().find(|(_, given)| *given) {
            Some((flag, _)) => Err(format!("--{flag} does not apply to this connection's kind")),
            None => Ok(()),
        }
    };
    if args.host.is_none()
        && args.scheme.is_none()
        && args.port.is_none()
        && args.template.is_none()
        && args.dbname.is_none()
        && args.user.is_none()
        && args.host_key_fingerprint.is_none()
        && args.secret.is_none()
        && args.sslmode.is_none()
        && args.ca_bundle.is_none()
        && args.test_path.is_none()
    {
        return Err("conn update requires at least one field flag".into());
    }
    if args.port == Some(0) {
        return Err("--port must be 1–65535".into());
    }
    let (trusted_ca_bundle_path, clear_trusted_ca_bundle) = match &args.ca_bundle {
        Some(path) if path.is_empty() => (None, true),
        Some(path) => (Some(path.clone()), false),
        None => (None, false),
    };
    // An empty string clears, matching --ca-bundle and --host-key-fingerprint.
    let (test_path, clear_test_path) = match &args.test_path {
        Some(path) if path.is_empty() => (None, true),
        Some(path) => (Some(path.clone()), false),
        None => (None, false),
    };
    let patch = ConnectionConfigPatch {
        host: args.host.clone(),
        scheme: args.scheme.clone(),
        port: args.port,
        template: args.template.clone(),
        dbname: args.dbname.clone(),
        user: args.user.clone(),
        sslmode: match args.sslmode.as_deref() {
            Some(value) => Some(parse_sslmode(Some(value))?),
            None => None,
        },
        trusted_ca_bundle_path,
        clear_trusted_ca_bundle,
        host_key_fingerprint: args.host_key_fingerprint.clone(),
        test_path,
        clear_test_path,
        secret_id,
    };
    match dto.kind.as_str() {
        "api" => {
            forbid(&[
                ("dbname", args.dbname.is_some()),
                ("user", args.user.is_some()),
                ("secret", args.secret.is_some()),
                ("sslmode", args.sslmode.is_some()),
                ("host-key-fingerprint", args.host_key_fingerprint.is_some()),
            ])?;
            Ok(patch)
        }
        "pg" => {
            forbid(&[
                ("scheme", args.scheme.is_some()),
                ("template", args.template.is_some()),
                ("host-key-fingerprint", args.host_key_fingerprint.is_some()),
                ("test-path", args.test_path.is_some()),
            ])?;
            Ok(patch)
        }
        "ssh" => {
            forbid(&[
                ("scheme", args.scheme.is_some()),
                ("template", args.template.is_some()),
                ("dbname", args.dbname.is_some()),
                ("sslmode", args.sslmode.is_some()),
                ("ca-bundle", args.ca_bundle.is_some()),
                ("test-path", args.test_path.is_some()),
            ])?;
            Ok(patch)
        }
        other => Err(format!("unknown connection kind {other:?}")),
    }
}

fn cmd_conn_update(args: ConnUpdate) {
    let managed = management_backend(args.root.clone(), args.broker.clone());
    let dto = conn_dto(&managed, &args.name);
    refuse_oauth_managed(&dto);
    let secret_id = match (&args.secret, dto.kind.as_str()) {
        (Some(name), "pg" | "ssh") => Some(dto_id(&secret_dto(&managed, name).id)),
        _ => None,
    };
    let patch = match connection_config_patch(&dto, &args, secret_id) {
        Ok(patch) => patch,
        Err(e) => die_with(ExitCode::Usage, e),
    };
    managed.run_gated(managed.backend.patch_connection(
        dto_id(&dto.id),
        dto.updated_at.clone(),
        patch,
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
    managed.run(managed.backend.rename_connection(
        dto_id(&dto.id),
        dto.updated_at,
        new_name.clone(),
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
    if on {
        managed.require_approval_surface();
    }
    let dto = conn_dto(&managed, &name);
    let state = if on { "on" } else { "off" };
    let changed = if on {
        managed.run(managed.backend.set_confirm_mode(dto_id(&dto.id), on))
    } else {
        managed.run_gated(managed.backend.set_confirm_mode(dto_id(&dto.id), on))
    };
    if changed {
        eprintln!("traffic confirmation {state} for {name}");
        if on {
            eprintln!("  prompts are answered in the AgentMFA app; without it, this tool's traffic is refused");
        }
    } else {
        eprintln!("traffic confirmation was already {state} for {name}");
    }
}

fn cmd_conn_response_credentials(
    name: String,
    root: Option<PathBuf>,
    url: Option<String>,
    allow: bool,
    contain: bool,
) {
    let managed = management_backend(root, url);
    let dto = conn_dto(&managed, &name);
    if dto.kind != "api" {
        die_with(
            ExitCode::Usage,
            format!(
                "{name} is a {} connection; upstream response credentials apply to API connections",
                dto.kind
            ),
        );
    }
    if !allow && !contain {
        println!(
            "{}",
            if dto.agent_access.expose_response_credentials {
                "exposed to agents"
            } else {
                "contained"
            }
        );
        return;
    }

    let expose = allow;
    let changed = if expose {
        managed.run_gated(
            managed
                .backend
                .set_expose_response_credentials(dto_id(&dto.id), true),
        )
    } else {
        managed.run(
            managed
                .backend
                .set_expose_response_credentials(dto_id(&dto.id), false),
        )
    };
    let state = if expose {
        "exposed to agents"
    } else {
        "contained"
    };
    if changed {
        eprintln!("upstream response credentials are now {state} for {name}");
        if expose {
            eprintln!(
                "  warning: Set-Cookie and authentication response headers can now reach agents"
            );
        }
    } else {
        eprintln!("upstream response credentials were already {state} for {name}");
    }
}

fn cmd_conn_audit_statements(
    name: String,
    root: Option<PathBuf>,
    url: Option<String>,
    on: bool,
    off: bool,
    default: bool,
) {
    let managed = management_backend(root, url);
    let dto = conn_dto(&managed, &name);
    if dto.kind != "pg" {
        die_with(
            ExitCode::Usage,
            format!(
                "{name} is a {} connection; statement recording applies to Postgres",
                dto.kind
            ),
        );
    }
    let requested = match (on, off, default) {
        (true, _, _) => Some(Some(true)),
        (_, true, _) => Some(Some(false)),
        (_, _, true) => Some(None),
        _ => None,
    };
    let Some(requested) = requested else {
        // No flag: report rather than change, so the effective state is
        // readable without guessing at the broker's launch flags.
        let source = match dto.agent_access.audit_statements {
            Some(_) => "set on this tool",
            None => "inherited from the broker default",
        };
        println!(
            "statement recording is {} for {name} ({source})",
            if dto.agent_access.audit_statements_effective {
                "on"
            } else {
                "off"
            }
        );
        return;
    };
    let changed = managed.run(
        managed
            .backend
            .set_audit_statements(dto_id(&dto.id), requested),
    );
    let updated = conn_dto(&managed, &name);
    let state = if updated.agent_access.audit_statements_effective {
        "on"
    } else {
        "off"
    };
    if changed {
        eprintln!("statement recording {state} for {name}");
        if updated.agent_access.audit_statements_effective {
            eprintln!(
                "  statement text can carry credentials and personal data into the activity log"
            );
        }
    } else {
        eprintln!("statement recording was already {state} for {name}");
    }
}

fn cmd_conn_test(name: String, root: Option<PathBuf>, url: Option<String>, json: bool) {
    let managed = management_backend(root, url);
    let dto = conn_dto(&managed, &name);
    let report = managed.run_gated(managed.backend.test_connection(dto_id(&dto.id)));
    if json {
        print_json(&report);
    }
    if report.ok {
        if !json {
            eprintln!("ok: {}", report.detail);
        }
    } else {
        if !json {
            match report.kind {
                Some(kind) => eprintln!("failed ({kind:?}): {}", report.detail),
                None => eprintln!("failed: {}", report.detail),
            }
        }
        exit_with(ExitCode::TestFailed);
    }
}

/// Read, issue/rotate, renew, or revoke a direct endpoint through the same management
/// backend as the app. Issuance is deliberately online-only: a short-lived
/// offline broker would drop the newly bound listener as soon as this command
/// exits. Revocation only narrows access, so it remains a safe offline edit.
fn cmd_conn_endpoint(
    name: String,
    issue: bool,
    renew: bool,
    revoke: bool,
    require_auth: Option<bool>,
    url: bool,
    secret: bool,
    root: Option<PathBuf>,
    broker: Option<String>,
    json: bool,
) {
    let action = endpoint_action(issue, renew, revoke)
        .unwrap_or_else(|message| die_with(ExitCode::Usage, message));
    if json && (url || secret) {
        die_with(
            ExitCode::Usage,
            "--json cannot be combined with --url or --secret",
        );
    }
    let managed = management_backend(root, broker);
    let dto = conn_dto(&managed, &name);
    if let Err(message) = endpoint_action_supported(action, managed.remote.is_some()) {
        die_with(ExitCode::NoBroker, message);
    }
    let connection_id = dto_id(&dto.id);

    if action == EndpointAction::Revoke {
        let Some(endpoint) = dto.agent_access.endpoint.as_ref() else {
            die_with(
                ExitCode::NotFound,
                format!("no direct endpoint is issued for {name}"),
            );
        };
        let endpoint_id = endpoint.endpoint_id.clone();
        let revoked = managed.run(
            managed
                .backend
                .revoke_endpoint(dto_id(&endpoint.endpoint_id)),
        );
        if !revoked {
            die_with(
                ExitCode::NotFound,
                format!("the direct endpoint for {name} was already revoked"),
            );
        }
        if json {
            print_json(&serde_json::json!({
                "connection": name,
                "endpoint_id": endpoint_id,
                "revoked": true,
            }));
        } else {
            eprintln!("revoked direct endpoint for {name}");
        }
        return;
    }

    let mut info = match action {
        EndpointAction::Issue => managed.run_gated(managed.backend.issue_endpoint(connection_id)),
        EndpointAction::Renew => managed.run_gated(managed.backend.renew_endpoint(connection_id)),
        EndpointAction::Read => match managed.run(managed.backend.get_endpoint(connection_id)) {
            Some(info) => info,
            None => die_with(
                ExitCode::NotFound,
                format!(
                    "no direct endpoint issued for {name} — start the broker and retry with \
                         `mfa conn endpoint {name} --issue`"
                ),
            ),
        },
        EndpointAction::Revoke => unreachable!("revocation returns above"),
    };
    // Applied after issuance so `--issue --require-auth` is one command, and
    // re-read afterwards so the example and secret printed below describe the
    // posture the endpoint actually ends up in rather than the one it had.
    if let Some(require_auth) = require_auth {
        // Only turning it *off* is gated in the broker; announcing a wait for
        // a confirmation that is not coming would be its own small lie.
        let call = managed
            .backend
            .set_endpoint_require_auth(connection_id, require_auth);
        let changed = if require_auth {
            managed.run(call)
        } else {
            managed.run_gated(call)
        };
        if changed {
            eprintln!(
                "the agent socket for {name} {}",
                if require_auth {
                    "now requires the endpoint secret — reach it through `mfa ssh-agent`"
                } else {
                    "no longer requires the endpoint secret"
                }
            );
            if let Some(reread) = managed.run(managed.backend.get_endpoint(connection_id)) {
                info = reread;
            }
        }
    }
    if json {
        print_json(&info);
        return;
    }
    let expired = info.expires_in_secs == Some(0);
    if expired && (url || secret) {
        die_with(
            ExitCode::Usage,
            format!(
                "the direct endpoint for {name} has expired — renew it with \
                 `mfa conn endpoint {name} --renew`"
            ),
        );
    }
    if expired {
        eprintln!(
            "expired — renew without changing this address with \
             `mfa conn endpoint {name} --renew`"
        );
    }
    if action == EndpointAction::Issue {
        eprintln!("issued direct endpoint for {name}");
    } else if action == EndpointAction::Renew {
        eprintln!("renewed direct endpoint for {name}");
    }
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
    if !info.expires_at.is_empty() {
        eprintln!("expires: {}", info.expires_at);
    }
}

/// The layout the generated documents describe: the production defaults,
/// or — with `--root` — a dev broker's actual layout.
fn doc_paths(root: Option<PathBuf>) -> Paths {
    match root {
        Some(root) => Paths::under(&root),
        None => Paths::default_locations().unwrap_or_else(|error| {
            die(format!(
                "could not determine the per-user data and socket directories: {error}; \
                 set HOME (and, where applicable, XDG_DATA_HOME), or pass --root"
            ))
        }),
    }
}

const GENERATED_SKILL_MARKER: &str = "<!-- Generated by `mfa skill`. Do not edit:";

fn generated_skill_file(content: &str) -> bool {
    content.contains(GENERATED_SKILL_MARKER)
}

fn authoritative_agent_setup(root: Option<PathBuf>, broker: String) -> String {
    let managed = management_backend(root, Some(broker));
    managed.run(managed.backend.agent_setup())
}

fn cmd_instructions(root: Option<PathBuf>, broker: Option<String>) {
    match effective_broker_url(broker) {
        Some(broker) => println!("{}", authoritative_agent_setup(root, broker).trim()),
        None => print!(
            "{}",
            wellknown::instructions(&BrokerConfig::default(), &doc_paths(root))
        ),
    }
}

fn cmd_skill(
    write: bool,
    path: Option<PathBuf>,
    user: bool,
    force: bool,
    root: Option<PathBuf>,
    broker: Option<String>,
) {
    let content = match effective_broker_url(broker) {
        Some(broker) => {
            let setup = authoritative_agent_setup(root, broker);
            wellknown::skill_file_for_broker(&setup)
        }
        None => wellknown::skill_file(&BrokerConfig::default(), &doc_paths(root)),
    };
    if !write {
        print!("{content}");
        return;
    }
    let path = match (path, user) {
        (Some(path), _) => path,
        (None, true) => dirs::home_dir()
            .unwrap_or_else(|| {
                die("could not determine the home directory; set HOME or pass --path")
            })
            .join(".claude/skills/mfa/SKILL.md"),
        (None, false) => PathBuf::from(".claude/skills/mfa/SKILL.md"),
    };
    if path.exists() && !force {
        let existing = std::fs::read_to_string(&path).unwrap_or_else(|error| {
            die(format!(
                "could not inspect existing skill file {}: {error}",
                path.display()
            ))
        });
        if !generated_skill_file(&existing) {
            die(format!(
                "refusing to overwrite non-AgentMFA skill file {}; pass --force to replace it",
                path.display()
            ));
        }
    }
    if let Some(dir) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(dir) {
            die(format!("could not create {}: {e}", dir.display()));
        }
    }
    if let Err(e) = std::fs::write(&path, content) {
        die(format!("could not write {}: {e}", path.display()));
    }
    eprintln!("wrote {}", path.display());
}

struct CliEvents;
impl BrokerEvents for CliEvents {}

/// Store a management token for later online edits: keyed by the hosted
/// broker's manage URL, or by the local socket path. Verified against the
/// broker when it is reachable — a rejected token is never stored.
fn cmd_manage_login(url: Option<String>, token_env: Option<String>, root: Option<PathBuf>) {
    let url = effective_broker_url(url);
    require_existing_root_for_read(root.as_deref(), url.is_some());
    if std::io::IsTerminal::is_terminal(&std::io::stdin()) && token_env.is_none() {
        eprintln!("  paste the management token (akamgr_…); end with Ctrl-D");
    }
    let token = read_secret_value(&token_env, false);
    let paths = store_paths(root.as_deref());
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let (key, backend) = match url {
        Some(url) => {
            let url = match RemoteConfig::normalize_url(&url) {
                Ok(url) => url,
                Err(e) => die_with(ExitCode::Usage, e),
            };
            let config = match RemoteConfig::new(&url, &token) {
                Ok(config) => config,
                Err(e) => die_with(ExitCode::Usage, e),
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
        Ok(profile) => {
            warn_version_skew(&profile);
            eprintln!("token verified against the running broker");
        }
        Err(ManageError::InvalidManageToken { detail }) => die_with(
            ExitCode::Authentication,
            detail.unwrap_or_else(|| {
                "the broker rejected this management token — issue a fresh one with `mfa manage token`"
                    .into()
            }),
        ),
        Err(ManageError::Unreachable { .. }) => {
            eprintln!("the broker is not reachable right now; storing the token unverified");
        }
        Err(e) => die_manage(e),
    }
    let token_store = manage_token_store(&paths);
    if let Err(e) = token_store.save(&key, &token) {
        die(format!("could not store the token: {e}"));
    }
    eprintln!(
        "management token stored for {key} ({})",
        token_store.storage_description(&key)
    );
}

fn cmd_manage_logout(url: Option<String>, root: Option<PathBuf>) {
    let url = effective_broker_url(url);
    require_existing_root_for_read(root.as_deref(), url.is_some());
    let paths = store_paths(root.as_deref());
    let key = match url {
        Some(url) => match RemoteConfig::normalize_url(&url) {
            Ok(url) => url,
            Err(e) => die_with(ExitCode::Usage, e),
        },
        None => paths.socket_file().display().to_string(),
    };
    if let Err(e) = manage_token_store(&paths).delete(&key) {
        die(format!("could not forget the management token: {e}"));
    }
    eprintln!("management token forgotten for {key}");
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum ManageTokenSource {
    Environment,
    Stored,
    Bootstrap,
}

fn online_manage_token(
    paths: &Paths,
    url: Option<String>,
    revoke: bool,
    ttl_days: Option<u64>,
    runtime: &tokio::runtime::Runtime,
) {
    let (key, backend, source) = match url {
        Some(url) => {
            let url = match RemoteConfig::normalize_url(&url) {
                Ok(url) => url,
                Err(error) => die_with(ExitCode::Usage, error),
            };
            let (token, source) = if let Ok(token) = std::env::var("AKA_MANAGE_TOKEN") {
                let token = token.trim();
                if token.is_empty() {
                    die_with(
                        ExitCode::Authentication,
                        format!(
                            "AKA_MANAGE_TOKEN is empty; set the current token or run \
                             `mfa manage login --broker {url}`"
                        ),
                    );
                }
                (
                    Zeroizing::new(token.to_string()),
                    ManageTokenSource::Environment,
                )
            } else if let Some(token) = manage_token_store(paths).load(&url) {
                (token, ManageTokenSource::Stored)
            } else {
                die_with(
                    ExitCode::Authentication,
                    format!(
                        "no current management token for {url} — set AKA_MANAGE_TOKEN \
                         or store one with `mfa manage login --broker {url}`; initial \
                         bootstrap must be run on the broker host"
                    ),
                );
            };
            let config = match RemoteConfig::new(&url, &token) {
                Ok(config) => config,
                Err(error) => die_with(ExitCode::Usage, error),
            };
            (url, RemoteBackend::new(config), source)
        }
        None => {
            let socket = paths.socket_file();
            let key = socket.display().to_string();
            let (token, source) = if let Ok(token) = std::env::var("AKA_MANAGE_TOKEN") {
                let token = token.trim();
                if token.is_empty() {
                    die_with(
                        ExitCode::Authentication,
                        "AKA_MANAGE_TOKEN is empty; set the current token or unset it \
                         to use a saved or first-start token",
                    );
                }
                (
                    Zeroizing::new(token.to_string()),
                    ManageTokenSource::Environment,
                )
            } else if let Some(token) = manage_token_store(paths).load(&key) {
                (token, ManageTokenSource::Stored)
            } else {
                let path = paths.manage_bootstrap_token_file();
                let token = std::fs::read_to_string(&path).unwrap_or_else(|error| {
                    die_with(
                        ExitCode::Authentication,
                        format!(
                            "no saved management token and could not read the first-start \
                             credential {}: {error}",
                            path.display()
                        ),
                    )
                });
                let token = token.trim();
                if token.is_empty() {
                    die_with(
                        ExitCode::Authentication,
                        format!("the first-start credential {} is empty", path.display()),
                    );
                }
                (
                    Zeroizing::new(token.to_string()),
                    ManageTokenSource::Bootstrap,
                )
            };
            (key, RemoteBackend::over_unix_socket(socket, &token), source)
        }
    };

    if revoke {
        match runtime.block_on(backend.revoke_management_token()) {
            Ok(true) => {
                if let Err(error) = manage_token_store(paths).delete(&key) {
                    eprintln!("warning: could not forget the saved token for {key}: {error}");
                }
                if source == ManageTokenSource::Environment {
                    eprintln!("warning: unset AKA_MANAGE_TOKEN; its value is now revoked");
                }
                eprintln!("management token revoked; the manage API is closed");
            }
            Ok(false) => eprintln!("no management token was issued"),
            Err(error) => die_manage(error),
        }
        return;
    }

    let days = ttl_days.expect("the CLI always supplies a bounded management-token TTL");
    let issued = runtime
        .block_on(backend.rotate_management_token(days))
        .unwrap_or_else(|error| die_manage(error));
    eprintln!("management token (shown once — the broker stores only its hash):\n");
    println!("{}", issued.token.as_str());
    if source == ManageTokenSource::Environment {
        eprintln!(
            "\nwarning: AKA_MANAGE_TOKEN still contains the superseded token; update or unset it"
        );
    } else {
        let store = manage_token_store(paths);
        if let Err(error) = store.save(&key, &issued.token) {
            eprintln!(
                "\nwarning: the token was rotated but could not be saved ({error}); \
                 capture the value printed above before it is lost"
            );
        } else {
            eprintln!(
                "\nmanagement token stored for {key} ({})",
                store.storage_description(&key)
            );
        }
    }
    eprintln!("expires: {}", issued.expires_at);
}

/// Rotate or revoke through a running broker when possible. A stopped local
/// broker retains the explicit offline path for recovery and first setup.
fn cmd_manage_token(
    revoke: bool,
    ttl_days: Option<u64>,
    root: Option<PathBuf>,
    url: Option<String>,
    create_root: bool,
) {
    let url = effective_broker_url(url);
    if create_root && url.is_some() {
        die_with(
            ExitCode::Usage,
            "--create-root is only valid for offline local issuance; unset AKA_BROKER_URL \
             or omit --broker",
        );
    }
    if !create_root {
        require_existing_root_for_read(root.as_deref(), url.is_some());
    }
    let paths = store_paths(root.as_deref());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let broker_running = match &url {
        Some(_) => true,
        None => runtime
            .block_on(tokio::net::UnixStream::connect(paths.socket_file()))
            .is_ok(),
    };
    if broker_running {
        return online_manage_token(&paths, url, revoke, ttl_days, &runtime);
    }

    let _lock = match acquire_offline_store_lock(&paths) {
        Ok(lock) => lock,
        Err(CoreError::BrokerAlreadyRunning(_)) => die_with(
            ExitCode::Conflict,
            format!(
                "a broker is running on {} — stop it first (its in-memory \
                 identity would overwrite this change)",
                paths.socket_file().display()
            ),
        ),
        Err(CoreError::BrokerStateBusy(pid)) => die_with(
            ExitCode::Conflict,
            format!(
                "another CLI process{} is editing this broker state — wait for it to finish, then retry",
                pid.map(|pid| format!(" (pid {pid})")).unwrap_or_default()
            ),
        ),
        Err(error) => die(format!("could not acquire the broker state lease: {error}")),
    };
    let vault = match open_vault(&paths, root.as_deref()) {
        Ok(vault) => vault,
        Err(e) => die(format!("could not open the secret vault: {e}")),
    };
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
        integrity.clone(),
    ) {
        Ok(identity) => identity,
        Err(e) => die(format!("could not open the broker identity: {e}")),
    };
    let audit = match aka_core::audit::AuditLog::open_sealed(
        paths.audit_file(),
        paths.audit_seal_file(),
        integrity,
    ) {
        Ok(audit) => audit,
        Err(e) => die(format!("could not open the activity log: {e}")),
    };
    if revoke {
        match identity.revoke_manage_token() {
            Ok(true) => {
                if let Err(error) = paths.remove_manage_bootstrap_token() {
                    eprintln!(
                        "warning: could not remove {}: {error}",
                        paths.manage_bootstrap_token_file().display()
                    );
                }
                audit.append(aka_core::audit::AuditEntry::new(
                    aka_core::audit::AuditKind::ManagementTokenRevoked,
                    "Management token revoked",
                ));
                eprintln!("management token revoked; the manage API is closed");
            }
            Ok(false) => eprintln!("no management token was issued"),
            Err(e) => die(e),
        }
        return;
    }
    let ttl = ttl_days.map(|days| std::time::Duration::from_secs(days * 86400));
    match identity.issue_manage_token_with_ttl(ttl) {
        Ok(token) => {
            let token = Zeroizing::new(token);
            if let Err(error) = paths.remove_manage_bootstrap_token() {
                eprintln!(
                    "warning: could not remove {}: {error}",
                    paths.manage_bootstrap_token_file().display()
                );
            }
            let mut entry = aka_core::audit::AuditEntry::new(
                aka_core::audit::AuditKind::ManagementTokenIssued,
                "Management token issued",
            )
            .outcome("issued");
            if let Some(expires_at) = identity.manage_token_expires_at() {
                entry = entry.field("expires_at", expires_at.to_rfc3339());
            }
            audit.append(entry);
            eprintln!("management token (shown once — only its hash is stored):\n");
            println!("{}", token.as_str());
            eprintln!("\nEnter it in the AgentMFA app to manage this broker remotely.");
            match ttl_days {
                Some(days) => eprintln!(
                    "Expires in {days} day{}; re-run to rotate, or --revoke to close the manage API.",
                    if days == 1 { "" } else { "s" }
                ),
                None => unreachable!("the CLI always supplies a bounded management-token TTL"),
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
        Err(error) => die_with(open_session_exit_code(&error), error),
    }
}

fn open_session_exit_code(error: &client::OpenSessionError) -> ExitCode {
    use client::OpenSessionError;
    match error {
        OpenSessionError::NoBroker { .. } => ExitCode::NoBroker,
        OpenSessionError::Refused { status, reason, .. } => match reason.as_deref() {
            Some("unknown_connection") => ExitCode::NotFound,
            Some(
                "missing_token"
                | "invalid_token"
                | "token_expired"
                | "token_superseded"
                | "denied_by_policy"
                | "approval_denied"
                | "approval_timeout"
                | "approval_unavailable",
            ) => ExitCode::Authentication,
            Some(
                "request_id_mismatch"
                | "outcome_not_replayable"
                | "rate_limited"
                | "ticket_session_limit"
                | "broker_session_limit"
                | "endpoint_busy",
            ) => ExitCode::Conflict,
            _ => match status {
                401 | 403 => ExitCode::Authentication,
                404 => ExitCode::NotFound,
                409 | 429 => ExitCode::Conflict,
                _ => ExitCode::Generic,
            },
        },
        OpenSessionError::Transport { .. } | OpenSessionError::Malformed(_) => ExitCode::Generic,
    }
}

/// Embed the session ticket as the DSN's password for the explicit legacy
/// `--format uri` output.
fn embed_ticket(dsn: &str, ticket: &str) -> Result<String, String> {
    match dsn.split_once("://ticket@") {
        Some((scheme, rest)) => Ok(format!("{scheme}://ticket:{ticket}@{rest}")),
        None => Err(format!("unexpected DSN shape from the broker: {dsn}")),
    }
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn pg_env_exports(dsn: &str, ticket: &str) -> Result<String, String> {
    let parsed = url::Url::parse(dsn).map_err(|e| format!("invalid DSN from the broker: {e}"))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| format!("the broker's DSN has no host: {dsn}"))?;
    let port = parsed
        .port()
        .ok_or_else(|| format!("the broker's DSN has no port: {dsn}"))?;
    let database = parsed.path().trim_start_matches('/');
    if database.is_empty() {
        return Err(format!("the broker's DSN has no database: {dsn}"));
    }
    Ok([
        ("PGHOST", host.to_string()),
        ("PGPORT", port.to_string()),
        ("PGDATABASE", database.to_string()),
        ("PGUSER", parsed.username().to_string()),
        ("PGPASSWORD", ticket.to_string()),
        ("PGSSLMODE", "disable".to_string()),
    ]
    .into_iter()
    .map(|(name, value)| format!("export {name}={}", shell_quote(&value)))
    .collect::<Vec<_>>()
    .join("\n"))
}

fn cmd_dsn(
    connection: String,
    root: Option<PathBuf>,
    client: Option<String>,
    format: Option<DsnFormat>,
    password_only: bool,
    json: bool,
) {
    if json && (format.is_some() || password_only) {
        die_with(
            ExitCode::Usage,
            "--json cannot be combined with --format or --password-only",
        );
    }
    let client = Some(client.unwrap_or_else(|| "mfa-dsn".to_string()));
    let body = open_session("/v1/pg/open", &connection, root, client);
    let (Some(dsn), Some(ticket)) = (body["dsn"].as_str(), body["ticket"].as_str()) else {
        die("the broker's response carried no DSN and ticket");
    };
    if json {
        print_json(&body);
        return;
    }
    if let Some(secs) = body["expires_in_seconds"].as_u64() {
        eprintln!("  ticket expires in {secs}s — connect before then; a later connection needs a fresh open");
    }
    if let Some(note) = body["sslmode_note"].as_str() {
        eprintln!("  note: {note}");
    }
    if password_only {
        println!("{ticket}");
        return;
    }
    match format.unwrap_or(DsnFormat::Env) {
        DsnFormat::Env => match pg_env_exports(dsn, ticket) {
            Ok(exports) => println!("{exports}"),
            Err(message) => die(message),
        },
        DsnFormat::Uri => match embed_ticket(dsn, ticket) {
            Ok(dsn) => {
                eprintln!("  warning: --format uri puts the ticket in process-visible argv");
                println!("{dsn}");
            }
            Err(message) => die(message),
        },
    }
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
        // The flags above are not optional decoration. `SSH_AUTH_SOCK` alone
        // leaves the default IdentityFile list in place, so a user with a
        // working ~/.ssh/id_ed25519 logs in with no broker involvement and no
        // activity entry — a success that looks brokered and is not. A config
        // block is how that becomes hard to get wrong, and it is also what
        // ssh-config-aware clients (VS Code Remote-SSH, plain `ssh <name>`)
        // can use at all.
        lines.push(String::new());
        lines.push("or add to ~/.ssh/config so plain `ssh` and editors use it too:".to_string());
        lines.extend(ssh_config_block(body, auth_sock, &destination));
    }
    lines
}

/// A `~/.ssh/config` stanza pointing `IdentityAgent` at the issued socket,
/// carrying the same options as the one-liner above.
fn ssh_config_block(body: &serde_json::Value, auth_sock: &str, destination: &str) -> Vec<String> {
    // An alias with whitespace is not a legal Host pattern; the destination is
    // already the alias when one was imported.
    let alias = destination
        .rsplit('@')
        .next()
        .unwrap_or(destination)
        .replace(char::is_whitespace, "-");
    let mut block = vec![format!("  Host {alias}")];
    if let Some(host) = body["host"].as_str() {
        block.push(format!("    HostName {host}"));
    }
    if let Some(port) = body["port"].as_u64().filter(|port| *port != 22) {
        block.push(format!("    Port {port}"));
    }
    if let Some(user) = body["user"].as_str().filter(|user| !user.is_empty()) {
        block.push(format!("    User {user}"));
    }
    block.push(format!("    IdentityAgent \"{auth_sock}\""));
    for option in SSH_BROKER_OPTIONS {
        let (key, value) = option.split_once('=').unwrap_or((option, ""));
        block.push(format!("    {key} {value}"));
    }
    block
}

fn cmd_ssh(connection: String, root: Option<PathBuf>, client: Option<String>, json: bool) {
    let client = Some(client.unwrap_or_else(|| "mfa-ssh".to_string()));
    let body = open_session("/v1/ssh/open", &connection, root, client);
    let Some(auth_sock) = body["auth_sock"].as_str() else {
        die("the broker's response carried no agent socket path");
    };
    if json {
        print_json(&body);
        return;
    }
    for line in ssh_open_hints(&body, auth_sock, chrono::Local::now()) {
        eprintln!("  {line}");
    }
    println!("{auth_sock}");
}

/// Serve a local ssh-agent socket that presents a direct endpoint's secret.
///
/// Reads the endpoint through the *gated copy* path when it requires
/// authentication: starting a forwarder hands a standing signing credential to
/// a process, which is the same act as putting it on the clipboard and
/// deserves the same confirmation and the same audit entry. An endpoint that
/// requires nothing takes the ungated read, because prompting for a secret
/// that will not be sent would train the user to click through.
fn cmd_ssh_agent(
    connection: String,
    root: Option<PathBuf>,
    broker: Option<String>,
    socket_path: Option<PathBuf>,
    command: Vec<String>,
) {
    let managed = management_backend(root, broker);
    let dto = conn_dto(&managed, &connection);
    if dto.kind != "ssh" {
        die_with(
            ExitCode::Usage,
            format!(
                "{connection} is a {} connection; only ssh connections have an agent socket",
                dto.kind
            ),
        );
    }
    if managed.remote.is_none() {
        die_with(
            ExitCode::NoBroker,
            "the endpoint socket is served by a running broker; start AgentMFA or \
             `mfa serve`, then retry",
        );
    }
    let connection_id = dto_id(&dto.id);
    let Some(info) = managed.run(managed.backend.get_endpoint(connection_id)) else {
        die_with(
            ExitCode::NotFound,
            format!(
                "no direct endpoint is issued for {connection} — issue one with \
                 `mfa conn endpoint {connection} --issue --require-auth`"
            ),
        );
    };
    if info.expires_in_secs == Some(0) {
        die_with(
            ExitCode::Usage,
            format!(
                "the direct endpoint for {connection} has expired — renew it with \
                 `mfa conn endpoint {connection} --renew`"
            ),
        );
    }
    // A secret on an SSH endpoint *is* the require-auth flag: the broker
    // surfaces it only for a socket that will demand it.
    let secret = if info.secret.is_empty() {
        eprintln!(
            "  note: this endpoint does not require authentication; its socket can be used \
             directly as IdentityAgent"
        );
        None
    } else {
        let copied = managed.run_gated(managed.backend.copy_endpoint(connection_id));
        match copied {
            Some(copied) if !copied.secret.is_empty() => {
                Some(std::sync::Arc::new(Zeroizing::new(copied.secret)))
            }
            // Revoked between the two reads; the socket below would be gone
            // too, so say what happened rather than serving a dead path.
            _ => die_with(
                ExitCode::NotFound,
                format!("the direct endpoint for {connection} was revoked while starting"),
            ),
        }
    };
    let upstream = PathBuf::from(&info.dsn);

    managed.runtime.block_on(async move {
        let socket = match socket_path {
            Some(path) => ssh_agent::AgentSocket::bind_at(path),
            None => ssh_agent::AgentSocket::bind(),
        }
        .unwrap_or_else(|error| die(format!("could not bind a local agent socket: {error}")));
        let path = socket.path().display().to_string();
        if command.is_empty() {
            // Same shape as `mfa ssh`: guidance on stderr, the one pasteable
            // value on stdout, so `$(…)` captures only the path. Unlike
            // `mfa ssh` the path dies with this process, so the export is
            // only useful to another terminal while this one is running.
            eprintln!("  serving {connection}'s endpoint until you press Ctrl-C");
            eprintln!("  in another terminal:  export SSH_AUTH_SOCK=\"{path}\"");
            // Not `$(mfa ssh-agent …)`: this command does not exit, so a
            // command substitution around it waits forever. The socket dies
            // with this process, which is also why the path is only useful
            // while it is on screen.
            eprintln!("  or run the client here:  mfa ssh-agent {connection} -- ssh ...");
            println!("{path}");
            socket
                .serve(upstream, secret, async {
                    let _ = tokio::signal::ctrl_c().await;
                })
                .await;
            return;
        }
        let mut child = tokio::process::Command::new(&command[0]);
        child.args(&command[1..]).env("SSH_AUTH_SOCK", &path);
        let mut child = match child.spawn() {
            Ok(child) => child,
            Err(error) => die(format!("could not run {}: {error}", command[0])),
        };
        let mut status = None;
        socket
            .serve(upstream, secret, async {
                status = child.wait().await.ok();
            })
            .await;
        // The command's status is this command's status: `mfa ssh-agent x --
        // ssh host` must fail when the ssh does, or a script wrapping it
        // cannot tell.
        let Some(status) = status else { return };
        match status.code() {
            Some(0) => {}
            Some(code) => exit_with_raw(code),
            // Killed by a signal: report it the way a shell does, so a
            // Ctrl-C'd `ssh` is not indistinguishable from one that succeeded.
            None => {
                use std::os::unix::process::ExitStatusExt as _;
                exit_with_raw(128 + status.signal().unwrap_or(0))
            }
        }
    });
}

/// Print the shared agent key, rotating it first when asked. The plain
/// print without `--url` is a file read of the key's plaintext home (the
/// same file agents read), so it works alongside a running broker with no
/// token; rotation and remote reads go through the management backend.
fn print_key(key: &str, json: bool) {
    if json {
        print_json(&serde_json::json!({ "key": key }));
    } else {
        println!("{key}");
    }
}

fn cmd_key(rotate: bool, root: Option<PathBuf>, url: Option<String>, json: bool) {
    let url = effective_broker_url(url);
    if url.is_none() && !rotate {
        require_existing_root_for_read(root.as_deref(), false);
        let paths = store_paths(root.as_deref());
        let token_file = paths.token_file();
        match std::fs::read_to_string(&token_file) {
            Ok(token) if !token.trim().is_empty() => {
                let token = Zeroizing::new(token);
                print_key(token.trim(), json);
            }
            _ => die(format!(
                "no shared key at {} — the broker mints it when it first starts",
                token_file.display()
            )),
        }
        return;
    }
    let managed = management_backend(root, url);
    if rotate {
        managed.run_gated(managed.backend.rotate_key());
        eprintln!("key rotated; agents that read the token file reconnect on their own");
    }
    let key = Zeroizing::new(managed.run(managed.backend.agent_key()));
    print_key(&key, json);
}

#[derive(Debug, serde::Serialize)]
struct StatusTool {
    name: String,
    #[serde(rename = "type")]
    kind: String,
    target: String,
    enabled: bool,
    confirm: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    response_credentials_exposed: bool,
    /// Whether a direct endpoint is issued for this tool.
    ///
    /// Status listed what agents *could* reach through the control plane and
    /// said nothing about standing access already handed out, which is the
    /// longer-lived of the two and the one a reader is more likely to have
    /// forgotten.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    endpoint: bool,
}

impl From<&ConnectionDto> for StatusTool {
    fn from(connection: &ConnectionDto) -> Self {
        Self {
            name: connection.name.clone(),
            kind: connection.kind.clone(),
            target: connection.target.clone(),
            enabled: connection.agent_access.enabled,
            confirm: connection.agent_access.confirm,
            response_credentials_exposed: connection.agent_access.expose_response_credentials,
            endpoint: connection.agent_access.endpoint.is_some(),
        }
    }
}

#[derive(Debug, serde::Serialize)]
struct StatusReport {
    running: bool,
    transport: String,
    location: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    broker_version: Option<String>,
    cli_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    protocol_version: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mcp_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    shared_key_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    shared_key_present: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    vault: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    approval_surface_attached: Option<bool>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    recent_ssh_refusals: Vec<StatusSshRefusal>,
    tools: Vec<StatusTool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tools_error: Option<String>,
}

#[derive(Debug, serde::Serialize)]
struct StatusSshRefusal {
    connection: String,
    at: String,
    reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
}

fn status_ssh_refusals(entries: &[ActivityDto]) -> Vec<StatusSshRefusal> {
    let mut seen = std::collections::HashSet::new();
    entries
        .iter()
        .filter(|entry| entry.kind.as_deref() == Some("denied"))
        .filter(|entry| entry.protocol.as_deref() == Some("ssh"))
        .filter_map(|entry| {
            let connection = entry.connection.as_ref()?;
            let reason = entry.outcome.as_ref()?;
            if !seen.insert(connection.clone()) {
                return None;
            }
            Some(StatusSshRefusal {
                connection: connection.clone(),
                at: entry.at.clone(),
                reason: reason.clone(),
                detail: entry.detail.clone(),
            })
        })
        .collect()
}

fn status_tools(connections: &[ConnectionDto]) -> Vec<StatusTool> {
    connections.iter().map(StatusTool::from).collect()
}

fn print_status_report(report: &StatusReport) {
    let location_note = if report.transport == "manage_api" {
        " (manage API)"
    } else {
        ""
    };
    println!("broker running on {}{}", report.location, location_note);
    if let Some(version) = &report.broker_version {
        match report.protocol_version {
            Some(protocol) => println!(
                "  version: broker {version}, mfa CLI {} (protocol {protocol})",
                report.cli_version
            ),
            None => println!(
                "  version: broker {version}, mfa CLI {}",
                report.cli_version
            ),
        }
    }
    if let Some(url) = &report.mcp_url {
        println!("  MCP host: {url}");
    } else if report.transport == "unix" {
        println!("  MCP host: not running");
    }
    if let Some(client_id) = &report.client_id {
        println!("  client id: {client_id}");
    }
    if let Some(path) = &report.shared_key_path {
        let qualifier = match report.shared_key_present {
            Some(true) => "",
            Some(false) => " (not minted yet)",
            None => " (on the broker host)",
        };
        println!("  shared key: {path}{qualifier}");
    }
    if let Some(vault) = &report.vault {
        println!("  vault: {vault}");
    }
    if !report.recent_ssh_refusals.is_empty() {
        println!("  recent SSH refusals:");
        for refusal in &report.recent_ssh_refusals {
            println!(
                "    {}  {}  {}{}",
                refusal.connection,
                refusal.at,
                refusal.reason,
                refusal
                    .detail
                    .as_deref()
                    .map(|detail| format!(" · {detail}"))
                    .unwrap_or_default()
            );
        }
    }
    if let Some(error) = &report.tools_error {
        println!("  tools: unavailable ({error})");
        return;
    }
    if report.tools.is_empty() {
        println!("  tools: none configured");
        return;
    }
    println!("  tools:");
    let approval_surface_attached = report.approval_surface_attached.unwrap_or(false);
    for tool in &report.tools {
        let confirm = if tool.confirm {
            if approval_surface_attached {
                " · confirm: on"
            } else {
                " · confirm: on (no approval surface attached — traffic will be refused)"
            }
        } else {
            ""
        };
        // A direct endpoint outlives any session and is revoked separately, so
        // it is named on the row rather than left to the app to reveal.
        let endpoint = if tool.endpoint {
            " · direct endpoint issued"
        } else {
            ""
        };
        println!(
            "    {}  {}  {}  {}{}{}",
            tool.name,
            tool.kind,
            tool.target,
            if tool.enabled { "enabled" } else { "disabled" },
            confirm,
            endpoint,
        );
    }
    if !approval_surface_attached {
        if let Some(warning) =
            headless_confirmation_warning(report.tools.iter().filter(|tool| tool.confirm).count())
        {
            eprintln!("{warning}");
        }
    }
}

fn headless_confirmation_warning(count: usize) -> Option<String> {
    (count > 0).then(|| {
        format!(
            "warning: {count} tool{} {} set to confirm traffic and this broker has no approval \
             surface; {} calls will be refused",
            if count == 1 { "" } else { "s" },
            if count == 1 { "is" } else { "are" },
            if count == 1 { "its" } else { "their" },
        )
    })
}

/// `status --broker`: the broker as its manage API reports it.
fn remote_status(root: Option<PathBuf>, url: String) -> StatusReport {
    let managed = management_backend(root, Some(url.clone()));
    let identity = managed.run(managed.backend.identity());
    let connections = managed.run(managed.backend.list_connections());
    let activity = managed.run(managed.backend.activity(100));
    StatusReport {
        running: true,
        transport: "manage_api".into(),
        location: url,
        broker_version: managed
            .profile
            .as_ref()
            .and_then(|profile| profile["version"].as_str())
            .map(str::to_string),
        cli_version: env!("CARGO_PKG_VERSION").into(),
        protocol_version: managed
            .profile
            .as_ref()
            .and_then(|profile| profile["protocol_version"].as_u64()),
        mcp_url: managed
            .profile
            .as_ref()
            .and_then(|profile| profile["mcp_url"].as_str())
            .map(str::to_string),
        client_id: Some(identity.client_id),
        shared_key_path: Some(identity.token_path),
        shared_key_present: None,
        vault: None,
        approval_surface_attached: Some(managed.approval_surface_attached()),
        recent_ssh_refusals: status_ssh_refusals(&activity),
        tools: status_tools(&connections),
        tools_error: None,
    }
}

/// Report the backend that owns this store's secrets. On macOS, include which
/// keychain controls prompts; on Linux, make encrypted versus plaintext
/// fallback (and a missing configured master key) explicit.
fn vault_description(paths: &Paths) -> String {
    #[cfg(target_os = "macos")]
    if let Some(keychain) = aka_core::keychain::read_record(&paths.keychain_file()) {
        let note = match keychain {
            aka_core::keychain::Keychain::DataProtection => "no prompts",
            aka_core::keychain::Keychain::Login => "prompts per secret; build is unsigned",
        };
        return format!("macOS {keychain} keychain ({note})");
    }
    let backend = recorded_platform_vault_backend(paths)
        .unwrap_or_else(|| selected_platform_vault_backend(paths));
    match backend {
        PlatformVaultBackend::MacosKeychain => "macOS Keychain (not initialized yet)".into(),
        PlatformVaultBackend::EncryptedFile => {
            let configured =
                selected_platform_vault_backend(paths) == PlatformVaultBackend::EncryptedFile;
            let note = if configured {
                "master key configured"
            } else {
                "set AKA_VAULT_KEY or AKA_VAULT_KEY_FILE"
            };
            format!(
                "encrypted file at {} ({note})",
                paths.encrypted_vault_file().display()
            )
        }
        PlatformVaultBackend::PlaintextDevFile => format!(
            "plaintext dev fallback at {} (set AKA_VAULT_KEY or AKA_VAULT_KEY_FILE)",
            paths.dev_vault_file().display()
        ),
    }
}

fn socket_status_error(socket: &Path, error: &std::io::Error) -> String {
    if error.raw_os_error() == Some(libc::ENOTSOCK) {
        return format!("{} exists but is not a Unix socket", socket.display());
    }
    match error.kind() {
        std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused => {
            format!("no broker is running at {}", socket.display())
        }
        std::io::ErrorKind::PermissionDenied => format!(
            "permission denied opening broker socket {}; check its owner and mode",
            socket.display()
        ),
        _ => format!(
            "could not inspect broker socket {}: {error}",
            socket.display()
        ),
    }
}

fn socket_status_exit_code(error: &std::io::Error) -> ExitCode {
    match error.kind() {
        std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused => ExitCode::NoBroker,
        _ => ExitCode::Generic,
    }
}

fn local_status(root: Option<PathBuf>) -> Result<StatusReport, (StatusReport, ExitCode, String)> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let paths = store_paths(root.as_deref());
    let socket = paths.socket_file();
    let key_present = std::fs::metadata(paths.token_file())
        .map(|metadata| metadata.len() > 0)
        .unwrap_or(false);
    let base = || StatusReport {
        running: false,
        transport: "unix".into(),
        location: socket.display().to_string(),
        broker_version: None,
        cli_version: env!("CARGO_PKG_VERSION").into(),
        protocol_version: None,
        mcp_url: None,
        client_id: None,
        shared_key_path: Some(paths.token_file().display().to_string()),
        shared_key_present: Some(key_present),
        vault: Some(vault_description(&paths)),
        approval_surface_attached: None,
        recent_ssh_refusals: Vec::new(),
        tools: Vec::new(),
        tools_error: None,
    };
    let manifest = match runtime.block_on(client::unix_http(
        &socket,
        "GET",
        "/.well-known/agent-broker.json",
        None,
        None,
        None,
    )) {
        Ok((200, body)) => {
            serde_json::from_str::<serde_json::Value>(&body).unwrap_or_else(|error| {
                die(format!("the broker returned malformed discovery: {error}"))
            })
        }
        Ok((status, _)) => die(format!(
            "the broker at {} answered discovery with HTTP {status}",
            socket.display()
        )),
        Err(error) => {
            let report = base();
            return Err((
                report,
                socket_status_exit_code(&error),
                socket_status_error(&socket, &error),
            ));
        }
    };

    // Status never authenticates as an agent and never pairs. If an existing
    // management credential is available, use the read-only manage plane for
    // tool detail; otherwise report that subsection as unavailable.
    let manage_key = socket.display().to_string();
    let (client_id, approval_surface_attached, recent_ssh_refusals, tools, tools_error) =
        match manage_token(&paths, &manage_key) {
            Some(token) => {
                let backend = RemoteBackend::over_unix_socket(socket.clone(), &token);
                match runtime.block_on(async {
                    let profile = backend.whoami().await?;
                    let connections = backend.list_connections().await?;
                    let activity = backend.activity(100).await?;
                    Ok::<_, ManageError>((profile, connections, activity))
                }) {
                    Ok((profile, connections, activity)) => (
                        profile["client_id"].as_str().map(str::to_string),
                        profile["approval_surface_attached"].as_bool(),
                        status_ssh_refusals(&activity),
                        status_tools(&connections),
                        None,
                    ),
                    Err(error) => (
                        None,
                        None,
                        Vec::new(),
                        Vec::new(),
                        Some(format!("manage API read failed: {error}")),
                    ),
                }
            }
            None => (
                None,
                None,
                Vec::new(),
                Vec::new(),
                Some(
                    "no management token configured; run `mfa manage login` to include tools"
                        .into(),
                ),
            ),
        };
    Ok(StatusReport {
        running: true,
        transport: "unix".into(),
        location: socket.display().to_string(),
        broker_version: manifest["version"].as_str().map(str::to_string),
        cli_version: env!("CARGO_PKG_VERSION").into(),
        protocol_version: manifest["protocol_version"].as_u64(),
        mcp_url: manifest["mcp_url"].as_str().map(str::to_string),
        client_id,
        shared_key_path: Some(paths.token_file().display().to_string()),
        shared_key_present: Some(key_present),
        vault: Some(vault_description(&paths)),
        approval_surface_attached,
        recent_ssh_refusals,
        tools,
        tools_error,
    })
}

fn cmd_status(json: bool, root: Option<PathBuf>, url: Option<String>) {
    let url = effective_broker_url(url);
    require_existing_root_for_read(root.as_deref(), url.is_some());
    let result = match url {
        Some(url) => Ok(remote_status(root, url)),
        None => local_status(root),
    };
    match result {
        Ok(report) => {
            if report.transport == "unix"
                && report
                    .broker_version
                    .as_deref()
                    .is_some_and(|version| version != report.cli_version)
            {
                eprintln!(
                    "warning: broker version {} differs from mfa CLI version {}; update them together before making changes",
                    report.broker_version.as_deref().unwrap_or("unknown"),
                    report.cli_version
                );
            }
            if json {
                print_json(&report);
            } else {
                print_status_report(&report);
            }
        }
        Err((report, code, diagnostic)) => {
            if json {
                print_json(&report);
            } else {
                if let Some(vault) = &report.vault {
                    eprintln!("  vault: {vault}");
                }
                if let Some(path) = &report.shared_key_path {
                    let state = if report.shared_key_present == Some(true) {
                        "present"
                    } else {
                        "not minted yet"
                    };
                    eprintln!("  shared key: {state} at {path}");
                }
            }
            die_with(code, diagnostic);
        }
    }
}

/// One formatted line per projected activity entry: timestamp (seconds
/// precision), summary, detail, and the acting agent when recorded.
fn format_activity_line(entry: &ActivityDto) -> String {
    let ts = entry.at.get(..19).unwrap_or(&entry.at);
    let mut line = format!("{ts}  {}", entry.text);
    if let Some(detail) = &entry.detail {
        line.push_str(&format!(" — {detail}"));
    }
    if let Some(agent) = &entry.agent {
        line.push_str(&format!("  [{agent}]"));
    }
    line
}

fn print_activity(entries: &[ActivityDto], json: bool) {
    if json {
        print_json(&entries);
    } else {
        for entry in entries {
            println!("{}", format_activity_line(entry));
        }
    }
}

/// Remote activity as the manage API renders it.
fn cmd_activity_remote(limit: usize, root: Option<PathBuf>, url: String) -> Vec<ActivityDto> {
    let managed = management_backend(root, Some(url));
    let mut entries = managed.run(managed.backend.activity(limit));
    // The manage API returns newest first; match the local newest-last view.
    entries.reverse();
    entries
}

fn cmd_activity(limit: usize, json: bool, root: Option<PathBuf>, url: Option<String>) {
    let url = effective_broker_url(url);
    require_existing_root_for_read(root.as_deref(), url.is_some());
    if let Some(url) = url {
        let entries = cmd_activity_remote(limit, root, url);
        print_activity(&entries, json);
        return;
    }
    let paths = store_paths(root.as_deref());
    let file = paths.audit_file();
    match std::fs::metadata(&file) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if json {
                print_activity(&[], true);
            } else {
                eprintln!(
                    "no activity recorded yet ({} does not exist)",
                    file.display()
                );
            }
            return;
        }
        Err(e) => die(format!("could not inspect {}: {e}", file.display())),
    }
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
    // Check an existing seal before `open_sealed`: opening is allowed to
    // adopt a genuinely absent legacy seal, but must not turn a damaged seal
    // into a fresh legacy baseline merely because this is a CLI read.
    if paths.audit_seal_file().exists() {
        if let Err(error) = integrity.read_verified(&paths.audit_seal_file()) {
            die(format!("activity log integrity check failed: {error}"));
        }
    }
    let audit =
        match aka_core::audit::AuditLog::open_sealed(file, paths.audit_seal_file(), integrity) {
            Ok(audit) => audit,
            Err(e) => die(format!("could not open the activity log: {e}")),
        };
    let verification = audit.verify();
    match &verification {
        aka_core::audit::AuditIntegrity::Tampered { .. } => die(verification.summary()),
        aka_core::audit::AuditIntegrity::Unsealed { .. } => {
            eprintln!("warning: {}", verification.summary())
        }
        aka_core::audit::AuditIntegrity::Verified { legacy, .. } if *legacy > 0 => {
            eprintln!("warning: {}", verification.summary())
        }
        aka_core::audit::AuditIntegrity::Verified { .. } => {}
    }
    let mut entries = audit.recent(if limit == 0 { usize::MAX } else { limit });
    entries.reverse();
    let entries = entries.iter().map(activity_dto).collect::<Vec<_>>();
    print_activity(&entries, json);
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
    no_mcp: bool,
}

/// Give a never-managed headless broker one bounded, owner-only credential.
/// This is bootstrap, not an unauthenticated API: possession of the file is
/// what lets the host operator make the first authenticated online rotation.
fn ensure_first_start_management_token(broker: &Broker) -> Result<Option<PathBuf>, String> {
    if broker.identity.manage_token_issued() {
        return Ok(None);
    }
    let ttl = std::time::Duration::from_secs(DEFAULT_MANAGE_TOKEN_TTL_DAYS * 86_400);
    let token = Zeroizing::new(
        broker
            .identity
            .issue_manage_token_with_ttl(Some(ttl))
            .map_err(|error| format!("could not issue first-start management token: {error}"))?,
    );
    if let Err(error) = broker.paths.write_manage_bootstrap_token(&token) {
        let rollback = broker.identity.revoke_manage_token();
        return Err(match rollback {
            Ok(_) => format!("could not write first-start management token: {error}"),
            Err(rollback) => format!(
                "could not write first-start management token: {error}; \
                 could not close the partially opened management plane: {rollback}"
            ),
        });
    }
    let expires_at = broker
        .identity
        .manage_token_expires_at()
        .expect("first-start management tokens are bounded");
    broker.audit.append(
        aka_core::audit::AuditEntry::new(
            aka_core::audit::AuditKind::ManagementTokenIssued,
            "First-start management token issued",
        )
        .outcome("bootstrap")
        .field("expires_at", expires_at.to_rfc3339()),
    );
    Ok(Some(broker.paths.manage_bootstrap_token_file()))
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
        no_mcp,
    } = args;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    // Startup failures here are configuration problems (a socket path over
    // the sun_path limit, an unreadable root, a vault that won't open) —
    // diagnose in one line rather than panicking with a backtrace.
    let fail = |what: &str, e: &dyn std::fmt::Display| -> ! {
        die(format!("{what}: {e}"));
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
    // Environment first, explicit flags after: a flag always wins.
    let mut config = BrokerConfig::default().overridden_from_env();
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
    let first_start_manage_token = match ensure_first_start_management_token(&broker) {
        Ok(path) => path,
        Err(error) => die(error),
    };
    let options = daemon::ServeOptions {
        listen,
        public_url: public_url.clone(),
        data_plane_listen,
        advertise_host: advertise_host.clone(),
        data_plane_insecure,
    };
    let mut daemon = match runtime.block_on(daemon::serve_with(broker.clone(), options)) {
        Ok(daemon) => daemon,
        Err(e) => fail("could not serve the control plane", &e),
    };

    // The agent-facing MCP listener is another task on the broker runtime.
    // Keep its loopback port in discovery so local bridges and the public
    // daemon proxy can reach it without a second process or runtime.
    let mcp_host = if no_mcp {
        None
    } else {
        match runtime.block_on(aka_core::mcp_host::serve(broker.clone())) {
            Ok(host) => {
                broker.set_mcp_host_port(Some(host.addr().port()));
                Some(host)
            }
            Err(error) => {
                eprintln!("  MCP host not started: {error}");
                None
            }
        }
    };

    eprintln!("AKA broker listening on {}", daemon.socket_path.display());
    if let Some(path) = first_start_manage_token {
        eprintln!(
            "  first-start management token: {} (0600, expires in {} days)",
            path.display(),
            DEFAULT_MANAGE_TOKEN_TTL_DAYS,
        );
        eprintln!(
            "  run `mfa manage token{}` while the broker is live to rotate and store it",
            root.as_ref()
                .map(|root| format!(" --root {}", shell_quote(&root.display().to_string())))
                .unwrap_or_default(),
        );
    }
    let confirm_count = broker
        .store
        .list_connections()
        .iter()
        .filter(|connection| broker.access.confirm_mode(&connection.id).is_on())
        .count();
    if let Some(warning) = headless_confirmation_warning(confirm_count) {
        eprintln!("  {warning}");
    }
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
    eprintln!("  Ctrl-C or SIGTERM to quit.\n");

    let signal = runtime.block_on(wait_for_shutdown_signal());
    eprintln!("  {signal} received; draining active sessions");
    daemon.stop_accepting();
    let sessions = broker.begin_shutdown();
    let drained =
        runtime.block_on(broker.wait_for_session_drain(std::time::Duration::from_secs(10)));
    if !drained {
        eprintln!("  shutdown deadline reached with active sessions still closing");
    } else if sessions > 0 {
        eprintln!("  drained {sessions} active data-plane session(s)");
    }
    drop(mcp_host);
    drop(daemon);
}

async fn wait_for_shutdown_signal() -> &'static str {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("install SIGTERM handler");
    tokio::select! {
        result = tokio::signal::ctrl_c() => {
            if let Err(error) = result {
                eprintln!("  warning: SIGINT handler failed: {error}");
            }
            "SIGINT"
        }
        _ = terminate.recv() => "SIGTERM",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aka_core::vault::MemoryVault;
    use chrono::TimeZone as _;

    struct TestEvents;
    impl BrokerEvents for TestEvents {}

    #[test]
    fn cli_exit_codes_are_stable_and_documented() {
        assert_eq!(ExitCode::Generic as i32, 1);
        assert_eq!(ExitCode::Usage as i32, 2);
        assert_eq!(ExitCode::NoBroker as i32, 3);
        assert_eq!(ExitCode::Authentication as i32, 4);
        assert_eq!(ExitCode::NotFound as i32, 5);
        assert_eq!(ExitCode::Conflict as i32, 6);
        assert_eq!(ExitCode::RemoteUnreachable as i32, 7);
        assert_eq!(ExitCode::TestFailed as i32, 8);

        let help = match Cli::try_parse_from(["mfa", "--help"]) {
            Ok(_) => panic!("--help unexpectedly parsed as a command"),
            Err(error) => error.to_string(),
        };
        for code in 1..=8 {
            assert!(help.contains(&format!("  {code}  ")), "{help}");
        }
    }

    #[test]
    fn cli_failures_unwind_sensitive_command_state_before_exiting() {
        struct DropProbe(Arc<std::sync::atomic::AtomicBool>);
        impl Drop for DropProbe {
            fn drop(&mut self) {
                self.0.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }

        let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let failure = std::panic::catch_unwind({
            let dropped = dropped.clone();
            move || {
                let _sensitive_state = DropProbe(dropped);
                exit_with(ExitCode::Authentication);
            }
        })
        .expect_err("CLI exit should unwind to the process boundary");
        let exit = failure
            .downcast::<CliExit>()
            .expect("CLI exit carries its typed status");
        assert_eq!(exit.code, ExitCode::Authentication as i32);
        assert!(
            dropped.load(std::sync::atomic::Ordering::SeqCst),
            "sensitive command state must be dropped before process exit"
        );
    }

    #[test]
    fn structured_management_failures_have_specific_exit_codes() {
        assert_eq!(
            manage_error_exit_code(&ManageError::InvalidConnectionName {
                name: "bad/name".into()
            }),
            ExitCode::Usage
        );
        assert_eq!(
            manage_error_exit_code(&ManageError::InvalidManageToken { detail: None }),
            ExitCode::Authentication
        );
        assert_eq!(
            manage_error_exit_code(&ManageError::ConnectionNotFound),
            ExitCode::NotFound
        );
        assert_eq!(
            manage_error_exit_code(&ManageError::ConnectionChanged),
            ExitCode::Conflict
        );
        assert_eq!(
            manage_error_exit_code(&ManageError::Unreachable {
                message: "offline".into()
            }),
            ExitCode::RemoteUnreachable
        );
    }

    #[test]
    fn management_tokens_default_to_a_bounded_ttl() {
        let cli = Cli::try_parse_from(["mfa", "manage", "token"]).unwrap();
        let Command::Manage {
            command: ManageCommand::Token {
                ttl_days, revoke, ..
            },
        } = cli.command
        else {
            panic!("wrong command");
        };
        assert!(!revoke);
        assert_eq!(ttl_days, Some(30));
        assert!(parse_manage_ttl_days("0").is_err());
        assert!(parse_manage_ttl_days("3651").is_err());
        assert!(Cli::try_parse_from([
            "mfa",
            "manage",
            "token",
            "--broker",
            "https://broker.example.test",
            "--create-root",
            "--root",
            "/tmp/example",
        ])
        .is_err());
    }

    #[test]
    fn agent_plane_labels_and_serve_flags_are_validated_by_clap() {
        for command in ["dsn", "ssh"] {
            assert!(Cli::try_parse_from([
                "mfa",
                command,
                "production",
                "--client",
                "honest\r\nX-Forged: yes",
            ])
            .is_err());
            assert!(
                Cli::try_parse_from(["mfa", command, "production", "--client", "ci-runner"])
                    .is_ok()
            );
        }

        assert!(Cli::try_parse_from([
            "mfa",
            "serve",
            "--public-url",
            "https://broker.example.test",
        ])
        .is_err());
        assert!(Cli::try_parse_from(["mfa", "serve", "--data-plane-insecure"]).is_err());
        for flag in ["--session-idle-timeout", "--session-max-ttl"] {
            assert!(Cli::try_parse_from(["mfa", "serve", flag, "0"]).is_err());
            assert!(Cli::try_parse_from(["mfa", "serve", flag, "1"]).is_ok());
        }
        assert!(Cli::try_parse_from(["mfa", "serve", "--no-mcp"]).is_ok());
        assert!(Cli::try_parse_from(["mfa", "serve", "--no-sidecar"]).is_ok());
        assert!(Cli::try_parse_from([
            "mfa",
            "serve",
            "--listen",
            "127.0.0.1:4780",
            "--public-url",
            "not-a-url",
        ])
        .is_err());
    }

    #[test]
    fn structured_open_failures_follow_the_documented_exit_codes() {
        use client::OpenSessionError;
        let refused = |status: u16, reason: &str| OpenSessionError::Refused {
            status,
            reason: Some(reason.to_string()),
            detail: "refused".into(),
        };
        assert_eq!(
            open_session_exit_code(&refused(404, "unknown_connection")),
            ExitCode::NotFound
        );
        assert_eq!(
            open_session_exit_code(&refused(403, "denied_by_policy")),
            ExitCode::Authentication
        );
        assert_eq!(
            open_session_exit_code(&refused(429, "rate_limited")),
            ExitCode::Conflict
        );
        assert_eq!(
            open_session_exit_code(&OpenSessionError::NoBroker {
                socket: "/tmp/missing.sock".into(),
            }),
            ExitCode::NoBroker
        );
    }

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
        assert!(joined.contains(" production\n"), "{joined}");
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

        // The config stanza carries the same authority as the one-liner, in the
        // form ssh-config-aware clients can use: the routing fields plus every
        // broker option, spelled the way a config file spells them.
        assert!(joined.contains("Host production"), "{joined}");
        assert!(joined.contains("HostName prod.example.com"), "{joined}");
        assert!(joined.contains("Port 2222"), "{joined}");
        assert!(joined.contains("User deploy"), "{joined}");
        assert!(
            joined.contains("IdentityAgent \"/tmp/agent-3f1c9a2b04d7e685.sock\""),
            "{joined}"
        );
        for option in SSH_BROKER_OPTIONS {
            let (key, value) = option.split_once('=').unwrap();
            assert!(
                joined.contains(&format!("    {key} {value}")),
                "{option} missing from the config block: {joined}"
            );
        }
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
                Arc::new(TestEvents),
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
    fn first_start_management_token_is_private_bounded_and_not_reissued() {
        use std::os::unix::fs::PermissionsExt as _;

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
                Arc::new(TestEvents),
            ))
            .unwrap();

        let path = ensure_first_start_management_token(&broker)
            .unwrap()
            .expect("a new broker needs a bootstrap credential");
        let token = std::fs::read_to_string(&path).unwrap();
        broker.identity.verify_manage(token.trim()).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(broker.identity.manage_token_expires_at().is_some());
        assert!(
            ensure_first_start_management_token(&broker)
                .unwrap()
                .is_none(),
            "restart must not overwrite the only available bootstrap token"
        );
        assert_eq!(std::fs::read_to_string(path).unwrap(), token);
    }

    #[test]
    fn offline_store_writer_reports_cli_lock_contention() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::under(dir.path());
        let _first = acquire_offline_store_lock(&paths).unwrap();

        assert!(matches!(
            acquire_offline_store_lock(&paths),
            Err(CoreError::BrokerStateBusy(Some(pid))) if pid == std::process::id()
        ));
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

    #[test]
    fn pg_env_output_keeps_the_ticket_out_of_the_connection_arguments() {
        let exports = pg_env_exports(
            "postgres://ticket@127.0.0.1:6543/app_production?sslmode=disable",
            "tkt_secret",
        )
        .unwrap();
        assert!(exports.contains("export PGHOST='127.0.0.1'"));
        assert!(exports.contains("export PGPORT='6543'"));
        assert!(exports.contains("export PGDATABASE='app_production'"));
        assert!(exports.contains("export PGUSER='ticket'"));
        assert!(exports.contains("export PGPASSWORD='tkt_secret'"));
        assert!(exports.contains("export PGSSLMODE='disable'"));
        assert!(!exports.contains("postgres://ticket:tkt_secret"));
    }

    #[test]
    fn shell_exports_quote_broker_controlled_values() {
        assert_eq!(shell_quote("a'b"), "'a'\"'\"'b'");
    }

    #[test]
    fn secret_input_strips_one_line_ending_unless_raw() {
        assert_eq!(normalize_secret_input("secret\n".into(), false), "secret");
        assert_eq!(normalize_secret_input("secret\r\n".into(), false), "secret");
        assert_eq!(
            normalize_secret_input("secret\n\n".into(), false),
            "secret\n"
        );
        assert_eq!(normalize_secret_input("secret\n".into(), true), "secret\n");
    }

    #[test]
    fn json_is_global_across_read_commands() {
        let cli = Cli::try_parse_from(["mfa", "status", "--json"]).unwrap();
        assert!(cli.json);
        assert!(matches!(
            cli.command,
            Command::Status {
                root: None,
                broker: None,
            }
        ));
        let cli = Cli::try_parse_from(["mfa", "--json", "secret", "list"]).unwrap();
        assert!(cli.json);
        assert!(matches!(
            cli.command,
            Command::Secret {
                command: SecretCommand::List { .. }
            }
        ));
    }

    #[test]
    fn endpoint_lifecycle_flags_parse_and_conflict() {
        let cli = Cli::try_parse_from(["mfa", "conn", "endpoint", "database", "--issue"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Conn {
                command: ConnCommand::Endpoint {
                    issue: true,
                    revoke: false,
                    ..
                }
            }
        ));

        let cli = Cli::try_parse_from(["mfa", "conn", "endpoint", "database", "--revoke"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Conn {
                command: ConnCommand::Endpoint {
                    issue: false,
                    revoke: true,
                    ..
                }
            }
        ));

        assert!(Cli::try_parse_from([
            "mfa", "conn", "endpoint", "database", "--issue", "--revoke",
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "mfa", "conn", "endpoint", "database", "--revoke", "--secret",
        ])
        .is_err());
    }

    #[test]
    fn response_credential_flags_parse_and_conflict() {
        let cli =
            Cli::try_parse_from(["mfa", "conn", "response-credentials", "api", "--allow"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Conn {
                command: ConnCommand::ResponseCredentials {
                    allow: true,
                    contain: false,
                    ..
                }
            }
        ));
        assert!(Cli::try_parse_from([
            "mfa",
            "conn",
            "response-credentials",
            "api",
            "--allow",
            "--contain",
        ])
        .is_err());
        assert!(
            Cli::try_parse_from(["mfa", "conn", "response-credentials", "api"]).is_ok(),
            "no flag reports the effective state"
        );
    }

    #[test]
    fn endpoint_issuance_and_renewal_require_online_broker_but_revocation_does_not() {
        assert_eq!(
            endpoint_action(false, false, false).unwrap(),
            EndpointAction::Read
        );
        assert_eq!(
            endpoint_action(true, false, false).unwrap(),
            EndpointAction::Issue
        );
        assert_eq!(
            endpoint_action(false, true, false).unwrap(),
            EndpointAction::Renew
        );
        assert_eq!(
            endpoint_action(false, false, true).unwrap(),
            EndpointAction::Revoke
        );
        assert!(endpoint_action(true, true, false).is_err());

        let error = endpoint_action_supported(EndpointAction::Issue, false).unwrap_err();
        assert!(error.contains("running broker"));
        assert!(endpoint_action_supported(EndpointAction::Issue, true).is_ok());
        assert!(endpoint_action_supported(EndpointAction::Renew, false).is_err());
        assert!(endpoint_action_supported(EndpointAction::Renew, true).is_ok());
        assert!(endpoint_action_supported(EndpointAction::Read, false).is_ok());
        assert!(endpoint_action_supported(EndpointAction::Revoke, false).is_ok());
        assert!(Cli::try_parse_from([
            "mfa",
            "conn",
            "endpoint",
            "production",
            "--renew",
            "--issue",
        ])
        .is_err());
    }

    /// SSH-1 / SEC-28. The two flags are opposites rather than a tri-state,
    /// so an unmentioned posture must stay untouched — `--issue` alone must
    /// not silently take authentication off a socket that had it.
    #[test]
    fn endpoint_authentication_flags_only_speak_when_asked() {
        assert_eq!(endpoint_require_auth(false, false), None);
        assert_eq!(endpoint_require_auth(true, false), Some(true));
        assert_eq!(endpoint_require_auth(false, true), Some(false));

        assert!(Cli::try_parse_from([
            "mfa",
            "conn",
            "endpoint",
            "production",
            "--require-auth",
            "--no-require-auth",
        ])
        .is_err());
        // Revocation removes the endpoint, so a posture for it is nonsense.
        assert!(Cli::try_parse_from([
            "mfa",
            "conn",
            "endpoint",
            "production",
            "--revoke",
            "--require-auth",
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "mfa",
            "conn",
            "endpoint",
            "production",
            "--issue",
            "--require-auth",
        ])
        .is_ok());
    }

    /// The forwarder takes its command after `--`, so the flags of the thing
    /// being run (`ssh -o …`) cannot be mistaken for the forwarder's own.
    #[test]
    fn the_ssh_agent_forwarder_passes_its_command_through_untouched() {
        let cli = Cli::try_parse_from([
            "mfa",
            "ssh-agent",
            "production",
            "--socket",
            "/tmp/a.sock",
            "--",
            "ssh",
            "-o",
            "IdentitiesOnly=no",
            "prod",
        ])
        .expect("a command after -- parses");
        let Command::SshAgent {
            connection,
            socket,
            command,
            ..
        } = cli.command
        else {
            panic!("expected the ssh-agent command");
        };
        assert_eq!(connection, "production");
        assert_eq!(socket.as_deref(), Some(Path::new("/tmp/a.sock")));
        assert_eq!(command, ["ssh", "-o", "IdentitiesOnly=no", "prod"]);

        let cli = Cli::try_parse_from(["mfa", "ssh-agent", "production"]).unwrap();
        let Command::SshAgent { command, .. } = cli.command else {
            panic!("expected the ssh-agent command");
        };
        assert!(
            command.is_empty(),
            "no command means serve in the foreground"
        );
    }

    #[test]
    fn status_distinguishes_socket_failure_classes() {
        let socket = Path::new("/tmp/aka.sock");
        assert!(
            socket_status_error(socket, &std::io::Error::from_raw_os_error(libc::ENOTSOCK))
                .contains("not a Unix socket")
        );
        assert!(socket_status_error(
            socket,
            &std::io::Error::from(std::io::ErrorKind::PermissionDenied)
        )
        .contains("permission denied"));
        assert!(socket_status_error(
            socket,
            &std::io::Error::from(std::io::ErrorKind::ConnectionRefused)
        )
        .contains("no broker is running"));
    }

    #[test]
    fn local_status_does_not_pair_or_authenticate_as_an_agent() {
        use std::io::{Read as _, Write as _};

        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::under(dir.path());
        paths.ensure().unwrap();
        let listener = std::os::unix::net::UnixListener::bind(paths.socket_file()).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 4096];
            let read = stream.read(&mut request).unwrap();
            let request = String::from_utf8_lossy(&request[..read]).into_owned();
            let body = serde_json::json!({
                "version": env!("CARGO_PKG_VERSION"),
                "protocol_version": 1,
                "mcp_url": null,
            })
            .to_string();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
            request
        });

        let report = local_status(Some(dir.path().to_path_buf())).unwrap();
        let request = server.join().unwrap();
        assert!(request.starts_with("GET /.well-known/agent-broker.json "));
        assert!(!request.contains("/v1/pair"));
        assert!(report.running);
        assert!(report.tools.is_empty());
        assert!(report
            .tools_error
            .as_deref()
            .is_some_and(|error| error.contains("no management token")));
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["running"], true);
        assert_eq!(json["transport"], "unix");
    }

    #[test]
    fn skill_write_options_are_not_silently_ignored() {
        assert!(Cli::try_parse_from(["mfa", "skill", "--path", "SKILL.md"]).is_err());
        assert!(Cli::try_parse_from(["mfa", "skill", "--user"]).is_err());
        assert!(Cli::try_parse_from(["mfa", "skill", "--write", "--path", "SKILL.md"]).is_ok());
        assert!(
            Cli::try_parse_from(["mfa", "skill", "--broker", "https://broker.example.test"])
                .is_ok()
        );
        assert!(Cli::try_parse_from([
            "mfa",
            "instructions",
            "--broker",
            "https://broker.example.test"
        ])
        .is_ok());
        assert!(generated_skill_file(&format!(
            "---\nname: mfa\n---\n{GENERATED_SKILL_MARKER} generated -->"
        )));
        assert!(!generated_skill_file("# A hand-written skill\n"));
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
            test_path: None,
            sigv4_region: None,
            sigv4_service: None,
            sigv4_access_key_ref: None,
            sigv4_secret_key_ref: None,
            sigv4_session_token_ref: None,
            gcp_key_ref: None,
            gcp_scope: None,
            client_cert: None,
            client_key: None,
            root: None,
            create_root: false,
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
    fn api_builds_a_sigv4_signer_instead_of_a_template() {
        let mut a = args(ConnKind::Api);
        a.host = Some("s3.amazonaws.com".into());
        a.sigv4_region = Some("us-east-1".into());
        // The region alone is not enough: each companion flag is named.
        assert!(conn_config(&a).unwrap_err().contains("--sigv4-service"));
        a.sigv4_service = Some("s3".into());
        assert!(conn_config(&a)
            .unwrap_err()
            .contains("--sigv4-access-key-ref"));
        a.sigv4_access_key_ref = Some("AWS_ACCESS_KEY_ID".into());
        assert!(conn_config(&a)
            .unwrap_err()
            .contains("--sigv4-secret-key-ref"));
        a.sigv4_secret_key_ref = Some("AWS_SECRET_ACCESS_KEY".into());
        // A signer connection needs no --template and renders an empty one.
        let config = conn_config(&a).unwrap();
        assert!(matches!(
            &config,
            ConnectionConfig::Api {
                template,
                signer: Some(SignerSpec::AwsSigv4 { region, service, .. }),
                ..
            } if template.is_empty() && region == "us-east-1" && service == "s3"
        ));
        // The two injection mechanisms are mutually exclusive at the flag
        // level too, rather than being caught only by the store.
        a.template = Some("Authorization: Bearer {{KEY}}".into());
        assert!(conn_config(&a).unwrap_err().contains("--template"));
    }

    #[test]
    fn api_builds_a_gcp_signer_and_names_its_missing_scope() {
        let mut a = args(ConnKind::Api);
        a.host = Some("storage.googleapis.com".into());
        a.gcp_key_ref = Some("GCP_SA_KEY".into());
        assert!(conn_config(&a).unwrap_err().contains("--gcp-scope"));
        a.gcp_scope = Some("https://www.googleapis.com/auth/devstorage.read_only".into());
        let config = conn_config(&a).unwrap();
        assert!(matches!(
            &config,
            ConnectionConfig::Api {
                template,
                signer: Some(SignerSpec::GcpServiceAccount { key_ref, scope }),
                ..
            } if template.is_empty()
                && key_ref == "GCP_SA_KEY"
                && scope == "https://www.googleapis.com/auth/devstorage.read_only"
        ));
        a.template = Some("Authorization: Bearer {{KEY}}".into());
        assert!(conn_config(&a).unwrap_err().contains("--template"));
    }

    #[test]
    fn api_carries_optional_client_certificate_paths() {
        let mut a = args(ConnKind::Api);
        a.host = Some("api.internal".into());
        a.template = Some("Authorization: Bearer {{KEY}}".into());
        a.client_cert = Some("/etc/client.pem".into());
        a.client_key = Some("/etc/client.key".into());
        assert!(matches!(
            conn_config(&a).unwrap(),
            ConnectionConfig::Api {
                client_cert_path: Some(ref cert),
                client_key_path: Some(ref key),
                ..
            } if cert == "/etc/client.pem" && key == "/etc/client.key"
        ));
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
    fn activity_lines_format_with_optional_fields() {
        let entry = ActivityDto {
            icon: "network".into(),
            tone: "blue".into(),
            kind: Some("http_executed".into()),
            text: "claude-code requested github".into(),
            detail: Some("GET api.github.com/user/repos".into()),
            agent: Some("claude-code".into()),
            connection: Some("github".into()),
            outcome: Some("ok".into()),
            protocol: Some("http".into()),
            duration_ms: None,
            approver: None,
            surface: None,
            confirmation: None,
            at: "2026-07-24T12:00:00.123456Z".into(),
        };
        assert_eq!(
            format_activity_line(&entry),
            "2026-07-24T12:00:00  claude-code requested github — GET \
             api.github.com/user/repos  [claude-code]"
        );
        let bare = ActivityDto {
            kind: Some("settings_changed".into()),
            text: "Agent access enabled".into(),
            detail: None,
            agent: None,
            connection: None,
            outcome: None,
            protocol: None,
            at: "-".into(),
            ..entry
        };
        assert_eq!(format_activity_line(&bare), "-  Agent access enabled");
    }

    #[test]
    fn ssh_status_ignores_normal_session_closes_when_finding_refusals() {
        let normal_close = ActivityDto {
            icon: "logOut".into(),
            tone: "neutral".into(),
            kind: Some("session_closed".into()),
            text: "SSH session closed".into(),
            detail: Some("idle timeout".into()),
            agent: Some("codex".into()),
            connection: Some("deploy".into()),
            outcome: Some("idle_timeout".into()),
            protocol: Some("ssh".into()),
            duration_ms: Some(120_000),
            approver: None,
            surface: None,
            confirmation: None,
            at: "2026-07-30T12:01:00Z".into(),
        };
        let denial = ActivityDto {
            icon: "circleX".into(),
            tone: "danger".into(),
            kind: Some("denied".into()),
            text: "SSH agent connection refused: deploy".into(),
            detail: Some("agent access is disabled".into()),
            agent: Some("endpoint".into()),
            connection: Some("deploy".into()),
            outcome: Some("denied_by_policy".into()),
            protocol: Some("ssh".into()),
            duration_ms: None,
            approver: None,
            surface: None,
            confirmation: None,
            at: "2026-07-30T12:00:00Z".into(),
        };

        let refusals = status_ssh_refusals(&[normal_close, denial]);
        assert_eq!(refusals.len(), 1);
        assert_eq!(refusals[0].reason, "denied_by_policy");
        assert_eq!(refusals[0].at, "2026-07-30T12:00:00Z");
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
            test_path: None,
            root: None,
            broker: None,
        }
    }

    fn update_dto(kind: &str) -> ConnectionDto {
        use aka_api::AccessDto;
        ConnectionDto {
            id: Uuid::new_v4().to_string(),
            name: "test".into(),
            updated_at: "2026-07-29T12:00:00.000000000Z".into(),
            kind: kind.into(),
            target: "example.com".into(),
            secret_names: vec![],
            oauth: false,
            agent_access: AccessDto {
                enabled: true,
                confirm: false,
                expose_response_credentials: false,
                confirm_window_until: None,
                confirm_window_agents: vec![],
                confirm_cooldown_until: None,
                allowed_tools: None,
                audit_statements: None,
                audit_statements_effective: false,
                endpoint: None,
            },
            host: None,
            scheme: None,
            port: None,
            template: None,
            dbname: None,
            user: None,
            host_key_fingerprint: None,
            destination: None,
            sslmode: None,
            trusted_ca_bundle_path: None,
            mcp_path: None,
            test_path: None,
            account: Some("operator@example.com".into()),
            oauth_spec: None,
            last_status: None,
            last_detail: None,
            last_checked_at: None,
            signer: None,
            client_cert_path: None,
            client_key_path: None,
        }
    }

    #[test]
    fn update_sends_only_supplied_fields_and_names_stray_flags() {
        let dto = update_dto("api");
        let mut a = update_args();
        assert!(connection_config_patch(&dto, &a, None)
            .unwrap_err()
            .contains("at least one field flag"));

        a.host = Some("api.example.com".into());
        let patch = connection_config_patch(&dto, &a, None).unwrap();
        assert_eq!(patch.host.as_deref(), Some("api.example.com"));
        assert_eq!(patch.scheme, None);
        assert_eq!(patch.template, None);
        assert_eq!(patch.trusted_ca_bundle_path, None);
        assert!(!patch.clear_trusted_ca_bundle);

        a.dbname = Some("stray".into());
        assert!(connection_config_patch(&dto, &a, None)
            .unwrap_err()
            .contains("--dbname"));
    }

    #[test]
    fn update_represents_explicit_clears_without_rebuilding_config() {
        let mut a = update_args();
        a.ca_bundle = Some(String::new());
        let patch = connection_config_patch(&update_dto("pg"), &a, None).unwrap();
        assert!(patch.clear_trusted_ca_bundle);
        assert_eq!(patch.trusted_ca_bundle_path, None);

        let mut a = update_args();
        a.host_key_fingerprint = Some(String::new());
        let patch = connection_config_patch(&update_dto("ssh"), &a, None).unwrap();
        assert_eq!(patch.host_key_fingerprint.as_deref(), Some(""));
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

    #[test]
    fn mcp_client_labels_are_valid_http_header_values() {
        assert_eq!(parse_client_label("claude-code").unwrap(), "claude-code");
        for invalid in ["", "has space", "line\nbreak", "é", &"x".repeat(65)] {
            assert!(parse_client_label(invalid).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn headless_confirmation_warning_is_counted_and_actionable() {
        assert_eq!(headless_confirmation_warning(0), None);
        assert_eq!(
            headless_confirmation_warning(1).as_deref(),
            Some(
                "warning: 1 tool is set to confirm traffic and this broker has no approval \
                 surface; its calls will be refused"
            )
        );
        assert!(headless_confirmation_warning(3)
            .unwrap()
            .contains("3 tools are set"));
    }
}
