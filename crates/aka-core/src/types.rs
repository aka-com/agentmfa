//! Core data model.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

/// A secret's sensitive material, scrubbed on drop.
pub type SecretValue = Zeroizing<String>;

/// Masked metadata, the only thing the UI (or anything else outside the
/// vault) ever sees about a secret. Deliberately no value material, not even
/// a masked preview.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretMeta {
    pub id: Uuid,
    /// e.g. "GITHUB_API_KEY", unique; templates resolve secrets by name.
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// The wire vocabulary is `api` / `pg` / `ws` / `ssh`, the same taxonomy the
/// UI type badges and `GET /v1/connections` share.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConnectionKind {
    Api,
    Pg,
    Ws,
    Ssh,
}

impl ConnectionKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            ConnectionKind::Api => "api",
            ConnectionKind::Pg => "pg",
            ConnectionKind::Ws => "ws",
            ConnectionKind::Ssh => "ssh",
        }
    }
    /// UI badge label.
    pub fn label(&self) -> &'static str {
        match self {
            ConnectionKind::Api => "API",
            ConnectionKind::Pg => "PG",
            ConnectionKind::Ws => "WS",
            ConnectionKind::Ssh => "SSH",
        }
    }
}

/// How the upstream leg of a Postgres connection is secured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum PgSslMode {
    /// Plaintext upstream. Dev/local only.
    Disable,
    /// Try TLS, fall back to plaintext if the server declines.
    Prefer,
    /// TLS or fail, without certificate validation. Compatibility mode for
    /// servers that cannot yet present a verifiable certificate.
    Require,
    /// TLS, verify the certificate chain against trusted roots, ignore host name.
    VerifyCa,
    /// TLS, verify both the certificate chain and host name.
    #[default]
    VerifyFull,
}

/// Type-specific connection config: the *where* plus how the credential is
/// injected. The agent never supplies any of this.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum ConnectionConfig {
    Api {
        /// Pinned upstream host, e.g. "api.github.com".
        host: String,
        /// Upstream scheme; "https" unless explicitly configured otherwise
        /// (plain "http" is for dev/test upstreams).
        #[serde(default = "default_scheme")]
        scheme: String,
        /// Pinned port; defaults to the scheme's well-known port.
        #[serde(default)]
        port: Option<u16>,
        /// Injection template, a header line (or query-param form) mixing
        /// literal text with `{{ … }}` placeholders,
        /// e.g. `Authorization: Bearer {{GITHUB_API_KEY}}`.
        template: String,
        /// When set, this upstream speaks MCP at that path (e.g. `/mcp`),
        /// and the sidecar re-exposes its tools under this connection's
        /// name.
        ///
        /// An MCP server reached over HTTP is an API connection in every
        /// way that matters here — same pinned host, same credential
        /// injected on the upstream leg — so it is a field rather than a
        /// separate kind. That is also what keeps the secret out of the
        /// sidecar: the MCP traffic rides the existing HTTP plane.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mcp_path: Option<String>,
    },
    Pg {
        host: String,
        #[serde(default = "default_pg_port")]
        port: u16,
        dbname: String,
        user: String,
        #[serde(default)]
        sslmode: PgSslMode,
        /// Optional PEM bundle for a private CA. When absent, verified modes
        /// use the platform/web PKI roots.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        trusted_ca_bundle_path: Option<String>,
    },
    Ws {
        /// Full upstream URL, e.g. "wss://stream.example.com/feed".
        url: String,
        /// Header-line injection template. When absent the referenced
        /// secret is injected as `Authorization: Bearer {{SECRET}}`.
        #[serde(default)]
        template: Option<String>,
    },
    Ssh {
        /// Original OpenSSH destination (usually an alias) to invoke. The
        /// resolved host below remains the displayed and pinned identity.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        destination: Option<String>,
        /// Destination host the agent is told to connect to, e.g.
        /// "prod.example.com".
        host: String,
        #[serde(default = "default_ssh_port")]
        port: u16,
        /// Login user the key authenticates as; the broker refuses to sign
        /// an authentication request naming any other user.
        user: String,
        /// OpenSSH SHA-256/SHA-512 fingerprint of the destination host key.
        /// Empty means unpinned: the key is trusted on first use — the broker
        /// observes it at the first agent `session-bind`, raises a dedicated
        /// approval prompt, and pins it on approval. Once set, a mismatching
        /// server key is refused.
        #[serde(default)]
        host_key_fingerprint: String,
    },
}

fn default_scheme() -> String {
    "https".into()
}

fn default_pg_port() -> u16 {
    5432
}

fn default_ssh_port() -> u16 {
    22
}

impl ConnectionConfig {
    pub fn kind(&self) -> ConnectionKind {
        match self {
            ConnectionConfig::Api { .. } => ConnectionKind::Api,
            ConnectionConfig::Pg { .. } => ConnectionKind::Pg,
            ConnectionConfig::Ws { .. } => ConnectionKind::Ws,
            ConnectionConfig::Ssh { .. } => ConnectionKind::Ssh,
        }
    }

    /// The human-readable pinned destination, what `GET /v1/connections`
    /// returns and what the approval window shows:
    /// api → origin, pg → `user@host:port/dbname`, ws → URL,
    /// ssh → `user@host[:port]` (port shown only when non-default).
    pub fn target(&self) -> String {
        match self {
            ConnectionConfig::Api {
                host, scheme, port, ..
            } => {
                let default_port = match scheme.as_str() {
                    "https" => 443,
                    "http" => 80,
                    _ => 0,
                };
                match port {
                    Some(port) if *port != default_port => format!("{scheme}://{host}:{port}"),
                    _ => format!("{scheme}://{host}"),
                }
            }
            ConnectionConfig::Pg {
                host,
                port,
                dbname,
                user,
                ..
            } => format!("{user}@{host}:{port}/{dbname}"),
            ConnectionConfig::Ws { url, .. } => url.clone(),
            ConnectionConfig::Ssh {
                host, port, user, ..
            } => {
                if *port == 22 {
                    format!("{user}@{host}")
                } else {
                    format!("{user}@{host}:{port}")
                }
            }
        }
    }

    /// Whether two configurations identify the same upstream destination.
    /// This is stricter than comparing display strings where identity is
    /// case-sensitive (database/user/path), but canonicalizes the parts whose
    /// wire semantics are equivalent (DNS host case/trailing dot, default
    /// ports, and URL normalization).
    pub fn has_equivalent_target(&self, other: &Self) -> bool {
        fn host_key(host: &str) -> String {
            host.trim_end_matches('.').to_ascii_lowercase()
        }

        match (self, other) {
            (
                Self::Api {
                    host: a_host,
                    scheme: a_scheme,
                    port: a_port,
                    ..
                },
                Self::Api {
                    host: b_host,
                    scheme: b_scheme,
                    port: b_port,
                    ..
                },
            ) => {
                let effective_port = |scheme: &str, port: Option<u16>| {
                    port.unwrap_or(if scheme == "https" { 443 } else { 80 })
                };
                a_scheme == b_scheme
                    && host_key(a_host) == host_key(b_host)
                    && effective_port(a_scheme, *a_port) == effective_port(b_scheme, *b_port)
            }
            (
                Self::Pg {
                    host: a_host,
                    port: a_port,
                    dbname: a_dbname,
                    user: a_user,
                    ..
                },
                Self::Pg {
                    host: b_host,
                    port: b_port,
                    dbname: b_dbname,
                    user: b_user,
                    ..
                },
            ) => {
                host_key(a_host) == host_key(b_host)
                    && a_port == b_port
                    && a_dbname == b_dbname
                    && a_user == b_user
            }
            (Self::Ws { url: a, .. }, Self::Ws { url: b, .. }) => {
                match (url::Url::parse(a), url::Url::parse(b)) {
                    (Ok(a), Ok(b)) => a == b,
                    _ => a == b,
                }
            }
            (
                Self::Ssh {
                    host: a_host,
                    port: a_port,
                    user: a_user,
                    ..
                },
                Self::Ssh {
                    host: b_host,
                    port: b_port,
                    user: b_user,
                    ..
                },
            ) => host_key(a_host) == host_key(b_host) && a_port == b_port && a_user == b_user,
            _ => false,
        }
    }

    /// OpenSSH destination an agent should invoke. Imported aliases are kept
    /// so OpenSSH can apply ProxyJump and the rest of the user's config.
    pub fn ssh_destination(&self) -> Option<&str> {
        match self {
            ConnectionConfig::Ssh {
                destination, host, ..
            } => Some(destination.as_deref().unwrap_or(host)),
            _ => None,
        }
    }
}

/// Persisted per-connection health, updated by tests and brokered calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthStatus {
    /// Last check reached the destination and the credential was accepted.
    Ok,
    /// Last check failed to reach the destination or errored.
    Failed,
    /// The destination answered but rejected the credential (HTTP 401/403,
    /// auth failure): the fix is reconnecting/replacing the credential, not
    /// retrying.
    NeedsReconnect,
}

impl HealthStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            HealthStatus::Ok => "ok",
            HealthStatus::Failed => "failed",
            HealthStatus::NeedsReconnect => "needs_reconnect",
        }
    }
}

/// One connection's last-known health: the verdict, the check's one-line
/// summary, and when it was learned. Display state only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionHealth {
    pub status: HealthStatus,
    pub detail: String,
    pub checked_at: DateTime<Utc>,
}

/// The index-side half of an OAuth-connected MCP connection: which vault
/// item holds the refresh grant, and when the access token expires. The
/// secret material (refresh token, client secret) lives in the vault item;
/// this record only schedules and locates it. Living in the sealed index
/// means the linkage cannot be repointed at another vault item on disk.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConnectionOAuth {
    /// Vault item holding the JSON refresh grant. Not a user-visible
    /// secret: it appears in no secrets list and dies with the connection.
    pub grant_id: Uuid,
    /// When the current access token expires; `None` when the provider
    /// did not say. Drives the silent background refresh.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

/// A connection binds secret(s) to a destination.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Connection {
    /// Stable id, standing rules key on it, never on the renamable name.
    pub id: Uuid,
    /// Unique; how agents and the UI address the connection.
    pub name: String,
    pub config: ConnectionConfig,
    /// Referenced secret ids. API connections may compose several (derived
    /// from the template's refs); pg/ws/ssh bind exactly one.
    pub secrets: Vec<Uuid>,
    /// The upstream account this connection's credential was last verified
    /// as (an MCP server's whoami answer). Display metadata, never
    /// authorization — it distinguishes several connections to the same
    /// service (multiple GitHub accounts, say) in the UI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    /// OAuth refresh linkage for MCP sign-in connections; `None` for
    /// everything added with a pasted credential.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth: Option<ConnectionOAuth>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Connection {
    pub fn kind(&self) -> ConnectionKind {
        self.config.kind()
    }
    pub fn target(&self) -> String {
        self.config.target()
    }
}

/// A registered agent record. Persisted in `agents.json`;
/// the pair token itself is stored only as a SHA-256 hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairedAgent {
    /// Stable authorization principal. Display names and bearer tokens may
    /// change, but wirings always bind to this id.
    #[serde(default)]
    pub id: Uuid,
    /// Self-asserted at registration; a label, not an authenticated identity.
    pub name: String,
    /// SHA-256 of the 256-bit bearer token, hex-encoded.
    pub token_hash: String,
    /// First characters of the token for the UI's masked preview.
    pub token_preview: String,
    pub paired_at: DateTime<Utc>,
    /// Refreshed on use; tokens expire 30 days after this.
    pub last_used: DateTime<Utc>,
}

/// A persistent agent → connection wiring. A wired agent may use the
/// connection without prompting; an unwired agent is refused.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Wiring {
    pub id: Uuid,
    /// Stable paired-client principal.
    pub client_id: Uuid,
    /// Display-name snapshot for audit and UI copy; never authorization.
    pub agent: String,
    /// The connection's stable id, never its renamable name.
    pub connection_id: Uuid,
    /// Curated subset of the upstream MCP tools this wiring may call;
    /// `None` means every tool. Enforced broker-side on `tools/call` and
    /// mirrored by the sidecar's tool listing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_tools: Option<Vec<String>>,
    pub created_at: DateTime<Utc>,
}

/// The surface a human decision came from (audit attribution).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionSurface {
    /// The desktop app's approval window.
    AppWindow,
    /// The headless CLI's terminal approver.
    Cli,
    /// Test harnesses and dev tooling.
    Harness,
}

/// How a confirmation-required decision was confirmed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfirmationMethod {
    /// Native OS authentication (Touch ID / account password).
    OsAuthentication,
    /// An interactive terminal acknowledged the action.
    Terminal,
    /// The shell explicitly waived confirmation (auto-approve / dev modes).
    Waived,
}

/// Attribution carried with every decision: who decided, from where. The
/// confirmation method is not part of this — the core demands it itself
/// through [`crate::events::BrokerEvents::confirm_decision`] and records
/// what the shell reports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionContext {
    /// The deciding principal. `None` means the local machine's single
    /// user; multi-approver surfaces carry a real identity.
    pub approver: Option<String>,
    pub surface: DecisionSurface,
}

impl DecisionContext {
    /// The local single-user case: no separate principal, just a surface.
    pub fn local(surface: DecisionSurface) -> Self {
        Self {
            approver: None,
            surface,
        }
    }
}

/// User settings.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Settings {
    /// "Require OS authentication to read secrets", default on. The macOS
    /// app gates each broker-side vault read with LocalAuthentication.
    pub reauth_on_read: bool,
    /// Read-only migration source for pre-connection-scoped CA settings.
    #[serde(
        default,
        rename = "pg_trusted_ca_bundle_path",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) legacy_pg_trusted_ca_bundle_path: Option<String>,
    /// "Show WebSockets" in the tool catalog, default off: the capability
    /// works, but most setups never need it, so it stays out of the way
    /// until asked for.
    #[serde(default)]
    pub show_websockets: bool,
    /// "Hide the Dock icon when minimized to the menu bar", default off.
    /// The app is a regular windowed app by default (Dock + app switcher);
    /// with this on, explicitly minimizing to the menu bar also drops the
    /// Dock icon (accessory activation) until the window is reopened.
    #[serde(default)]
    pub menu_bar_hides_dock: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            reauth_on_read: true,
            legacy_pg_trusted_ca_bundle_path: None,
            show_websockets: false,
            menu_bar_hides_dock: false,
        }
    }
}

/// Compute the reveal prefix: the value's first `min(6, ⌊len/2⌋)` characters,
/// at most half the value, so a short secret isn't mostly exposed.
/// Returns the prefix with a trailing ellipsis when truncated.
pub fn reveal_prefix(value: &str) -> String {
    let len = value.chars().count();
    let n = std::cmp::min(6, len / 2);
    if n >= len {
        return value.to_string();
    }
    let mut out: String = value.chars().take(n).collect();
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_written_by_older_versions_still_load() {
        // Retired keys (the walkthrough toggles) must not fail the parse.
        let settings: Settings = serde_json::from_str(
            r#"{"reauth_on_read":true,"menu_bar_hides_dock":false,
                "show_service_walkthrough":true,"show_agent_walkthrough":false}"#,
        )
        .unwrap();
        assert!(settings.reauth_on_read);
        assert!(!settings.menu_bar_hides_dock);
        assert!(!settings.show_websockets, "a new opt-in defaults off");
    }

    #[test]
    fn reveal_prefix_never_exposes_more_than_half() {
        assert_eq!(reveal_prefix("ghp_9aXf2Qe7LmNoP3demoToken41c"), "ghp_9a…");
        assert_eq!(reveal_prefix("abcd"), "ab…");
        assert_eq!(reveal_prefix("abc"), "a…");
        assert_eq!(reveal_prefix("ab"), "a…");
        assert_eq!(reveal_prefix("a"), "…");
        assert_eq!(reveal_prefix(""), "");
    }

    #[test]
    fn targets_match_the_wire_format() {
        let api = ConnectionConfig::Api {
            host: "api.github.com".into(),
            scheme: "https".into(),
            port: None,
            template: "Authorization: Bearer {{GITHUB_API_KEY}}".into(),

            mcp_path: None,
        };
        assert_eq!(api.target(), "https://api.github.com");
        let pg = ConnectionConfig::Pg {
            host: "db.internal.aka.com".into(),
            port: 5432,
            dbname: "app_production".into(),
            user: "app".into(),
            sslmode: PgSslMode::Require,
            trusted_ca_bundle_path: None,
        };
        assert_eq!(pg.target(), "app@db.internal.aka.com:5432/app_production");
        let ws = ConnectionConfig::Ws {
            url: "wss://stream.example.com/feed".into(),
            template: None,
        };
        assert_eq!(ws.target(), "wss://stream.example.com/feed");
        let ssh = ConnectionConfig::Ssh {
            destination: None,
            host: "prod.example.com".into(),
            port: 22,
            user: "deploy".into(),
            host_key_fingerprint: "SHA256:test".into(),
        };
        assert_eq!(ssh.target(), "deploy@prod.example.com");
        assert_eq!(ssh.ssh_destination(), Some("prod.example.com"));
        let mut aliased_ssh = ssh.clone();
        if let ConnectionConfig::Ssh { destination, .. } = &mut aliased_ssh {
            *destination = Some("prod".into());
        }
        assert_eq!(aliased_ssh.ssh_destination(), Some("prod"));
        let ssh_alt_port = ConnectionConfig::Ssh {
            destination: None,
            host: "bastion.example.com".into(),
            port: 2222,
            user: "ops".into(),
            host_key_fingerprint: "SHA256:test".into(),
        };
        assert_eq!(ssh_alt_port.target(), "ops@bastion.example.com:2222");
    }

    #[test]
    fn ssh_port_defaults_to_22() {
        let conf: ConnectionConfig =
            serde_json::from_str(r#"{"kind":"ssh","host":"prod.example.com","user":"deploy"}"#)
                .unwrap();
        assert_eq!(
            conf,
            ConnectionConfig::Ssh {
                destination: None,
                host: "prod.example.com".into(),
                port: 22,
                user: "deploy".into(),
                host_key_fingerprint: String::new(),
            }
        );
        assert_eq!(conf.kind().as_str(), "ssh");
    }

    #[test]
    fn pg_port_defaults_to_5432() {
        let conf: ConnectionConfig = serde_json::from_str(
            r#"{"kind":"pg","host":"db.example.com","dbname":"app","user":"app"}"#,
        )
        .unwrap();
        assert!(matches!(conf, ConnectionConfig::Pg { port: 5432, .. }));
    }

    #[test]
    fn equivalent_targets_canonicalize_hosts_ports_and_urls() {
        let api_a = ConnectionConfig::Api {
            host: "API.Example.com.".into(),
            scheme: "https".into(),
            port: None,
            template: "Authorization: Bearer {{A}}".into(),

            mcp_path: None,
        };
        let api_b = ConnectionConfig::Api {
            host: "api.example.com".into(),
            scheme: "https".into(),
            port: Some(443),
            template: "Authorization: Bearer {{B}}".into(),

            mcp_path: None,
        };
        assert!(api_a.has_equivalent_target(&api_b));

        let ws_a = ConnectionConfig::Ws {
            url: "wss://EXAMPLE.com".into(),
            template: None,
        };
        let ws_b = ConnectionConfig::Ws {
            url: "wss://example.com/".into(),
            template: Some("Authorization: Bearer {{TOKEN}}".into()),
        };
        assert!(ws_a.has_equivalent_target(&ws_b));

        let mut different_port = api_b.clone();
        if let ConnectionConfig::Api { port, .. } = &mut different_port {
            *port = Some(444);
        }
        assert!(!api_a.has_equivalent_target(&different_port));
        assert!(!api_a.has_equivalent_target(&ws_a));
    }

    #[test]
    fn legacy_connection_reconnect_flag_is_ignored() {
        let connection: Connection = serde_json::from_str(
            r#"{
              "id":"00000000-0000-0000-0000-000000000001",
              "name":"market-feed",
              "config":{"kind":"ws","url":"wss://example.com/feed"},
              "secrets":[],
              "multi_connect":false,
              "created_at":"2026-01-01T00:00:00Z",
              "updated_at":"2026-01-01T00:00:00Z"
            }"#,
        )
        .unwrap();
        assert_eq!(connection.name, "market-feed");
    }

    #[test]
    fn pg_sslmodes_match_libpq_names() {
        assert_eq!(PgSslMode::default(), PgSslMode::VerifyFull);
        assert_eq!(
            serde_json::to_string(&PgSslMode::VerifyCa).unwrap(),
            "\"verify-ca\""
        );
        assert_eq!(
            serde_json::from_str::<PgSslMode>("\"verify-full\"").unwrap(),
            PgSslMode::VerifyFull
        );
    }

    #[test]
    fn paired_agent_ignores_legacy_identity_records() {
        let now = chrono::Utc::now().to_rfc3339();
        let agent: PairedAgent = serde_json::from_str(&format!(
            r#"{{
              "name": "claude-code",
              "token_hash": "hash",
              "token_preview": "aka_legacy",
              "identity": {{"kind": "dev_unverified", "uid": 501}},
              "paired_at": "{now}",
              "last_used": "{now}"
            }}"#
        ))
        .unwrap();
        assert_eq!(agent.name, "claude-code");
    }
}
