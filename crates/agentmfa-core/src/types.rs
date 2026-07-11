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
    },
    Pg {
        host: String,
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

/// The peer identity pinned to a pair token at pairing time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PeerIdentity {
    /// Verified signature: signing identifier + Team ID.
    Signed {
        signing_id: String,
        team_id: Option<String>,
    },
    /// Ad-hoc / unsigned peer. There is no code-signing anchor, so the token
    /// is pinned to best-effort local executable metadata instead.
    Unsigned {
        #[serde(default)]
        uid: Option<u32>,
        #[serde(default)]
        executable_path: Option<String>,
        #[serde(default)]
        file_id: Option<String>,
        #[serde(default)]
        executable_sha256: Option<String>,
    },
    /// Non-macOS dev builds have no code-signature oracle; the pin is the
    /// peer UID only. Documented divergence, not a production path.
    DevUnverified { uid: u32 },
}

impl PeerIdentity {
    /// Display string for the pairing dialog and the paired-agents band.
    pub fn display(&self) -> String {
        match self {
            PeerIdentity::Signed {
                signing_id,
                team_id: Some(team),
            } => format!("{signing_id} · Team {team}"),
            PeerIdentity::Signed {
                signing_id,
                team_id: None,
            } => signing_id.clone(),
            PeerIdentity::Unsigned {
                uid,
                executable_path,
                executable_sha256,
                ..
            } => {
                let mut parts = Vec::new();
                if let Some(path) = executable_path {
                    parts.push(path.clone());
                }
                if let Some(uid) = uid {
                    parts.push(format!("uid {uid}"));
                }
                if let Some(hash) = executable_sha256 {
                    let preview = &hash[..hash.len().min(12)];
                    parts.push(format!("sha256 {preview}…"));
                }
                if parts.is_empty() {
                    "Unsigned/ad-hoc, no local fingerprint (legacy)".into()
                } else {
                    format!("Unsigned/ad-hoc · {}", parts.join(" · "))
                }
            }
            PeerIdentity::DevUnverified { uid } => format!("Dev build: uid {uid} (unverified)"),
        }
    }
}

/// A paired agent record. Persisted in `agents.json`;
/// the pair token itself is stored only as a SHA-256 hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairedAgent {
    /// Stable authorization principal. Display names and bearer tokens may
    /// change, but permissions always bind to this id.
    #[serde(default)]
    pub id: Uuid,
    /// Self-asserted at pairing, a label, not an authenticated identity.
    pub name: String,
    /// SHA-256 of the 256-bit bearer token, hex-encoded.
    pub token_hash: String,
    /// First characters of the token for the UI's masked preview.
    pub token_preview: String,
    /// Identity the token is pinned to.
    pub identity: PeerIdentity,
    pub paired_at: DateTime<Utc>,
    /// Refreshed on use; tokens expire 30 days after this.
    pub last_used: DateTime<Utc>,
}

/// A standing "always allow" rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum PermissionScope {
    Read,
    #[default]
    Full,
}

impl PermissionScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Full => "full",
        }
    }

    pub fn allows(self, required: Self) -> bool {
        self == Self::Full || required == Self::Read
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Read => "read access",
            Self::Full => "full access",
        }
    }
}

/// A persistent permission. Temporary permissions use the same scope model
/// but remain memory-only because they carry live OS-auth authorization.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Rule {
    pub id: Uuid,
    /// Stable paired-client principal. Legacy rules deserialize as nil and
    /// are migrated only when their display name maps to a current client.
    #[serde(default)]
    pub client_id: Uuid,
    /// Display-name snapshot for audit and UI copy; never authorization.
    pub agent: String,
    /// The connection's stable id, never its renamable name.
    pub connection_id: Uuid,
    #[serde(default)]
    pub scope: PermissionScope,
    pub created_at: DateTime<Utc>,
}

/// Decision produced by the policy engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
    Prompt,
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
    /// "Hide the Dock icon when minimized to the menu bar", default off.
    /// The app is a regular windowed app by default (Dock + app switcher);
    /// with this on, explicitly minimizing to the menu bar also drops the
    /// Dock icon (accessory activation) until the window is reopened.
    #[serde(default)]
    pub menu_bar_hides_dock: bool,
    /// Whether the first-service walkthrough is visible while no services
    /// have been configured. Defaults on for existing installations.
    #[serde(default = "default_walkthrough_visible")]
    pub show_service_walkthrough: bool,
    /// Whether the agent-pairing walkthrough is visible while no agents are
    /// connected. Defaults on for existing installations.
    #[serde(default = "default_walkthrough_visible")]
    pub show_agent_walkthrough: bool,
}

fn default_walkthrough_visible() -> bool {
    true
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            reauth_on_read: true,
            legacy_pg_trusted_ca_bundle_path: None,
            menu_bar_hides_dock: false,
            show_service_walkthrough: true,
            show_agent_walkthrough: true,
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
    fn legacy_settings_keep_walkthroughs_visible() {
        let settings: Settings =
            serde_json::from_str(r#"{"reauth_on_read":true,"menu_bar_hides_dock":false}"#).unwrap();
        assert!(settings.show_service_walkthrough);
        assert!(settings.show_agent_walkthrough);
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
    fn unsigned_peer_identity_accepts_legacy_records() {
        let identity: PeerIdentity = serde_json::from_str(r#"{"kind":"unsigned"}"#).unwrap();
        assert_eq!(
            identity,
            PeerIdentity::Unsigned {
                uid: None,
                executable_path: None,
                file_id: None,
                executable_sha256: None,
            }
        );
        assert!(identity.display().contains("legacy"));
    }

    #[test]
    fn unsigned_peer_identity_displays_local_fingerprint() {
        let identity = PeerIdentity::Unsigned {
            uid: Some(501),
            executable_path: Some("/Applications/Unsigned Agent.app/Contents/MacOS/agent".into()),
            file_id: Some("dev:1 ino:2".into()),
            executable_sha256: Some("0123456789abcdef".repeat(4)),
        };

        let display = identity.display();
        assert!(display.contains("Unsigned/ad-hoc"));
        assert!(display.contains("uid 501"));
        assert!(display.contains("sha256 0123456789ab"));
    }
}
