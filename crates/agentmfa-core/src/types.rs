//! Core data model (DESIGN.md §9).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

/// A secret's sensitive material, scrubbed on drop (DESIGN.md §3).
pub type SecretValue = Zeroizing<String>;

/// Masked metadata, the only thing the UI (or anything else outside the
/// vault) ever sees about a secret. Deliberately no value material, not even
/// a masked preview (DESIGN.md §2/§3).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretMeta {
    pub id: Uuid,
    /// e.g. "GITHUB_API_KEY", unique; templates resolve secrets by name.
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// The wire vocabulary is `api` / `pg` / `ws` / `ssh`, the same taxonomy the
/// UI type badges and `GET /v1/connections` share (DESIGN.md §4.0).
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

/// How the upstream leg of a Postgres connection is secured (DESIGN.md §4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum PgSslMode {
    /// Plaintext upstream. Dev/local only.
    Disable,
    /// Try TLS, fall back to plaintext if the server declines.
    #[default]
    Prefer,
    /// TLS or fail.
    Require,
    /// TLS, verify the certificate chain against trusted roots, ignore host name.
    VerifyCa,
    /// TLS, verify both the certificate chain and host name.
    VerifyFull,
}

/// Type-specific connection config: the *where* plus how the credential is
/// injected. The agent never supplies any of this (DESIGN.md §4).
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
        /// literal text with `{{ … }}` placeholders (DESIGN.md §4.1),
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
        /// Destination host the agent is told to connect to, e.g.
        /// "prod.example.com". Shown in approvals and `/v1/connections`;
        /// the ssh-agent protocol cannot cryptographically pin it — the
        /// enforced pins are the user and the key (DESIGN.md §4.4).
        host: String,
        #[serde(default = "default_ssh_port")]
        port: u16,
        /// Login user the key authenticates as; the broker refuses to sign
        /// an authentication request naming any other user.
        user: String,
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
    /// returns and what the approval window shows (DESIGN.md §4.0):
    /// api → host, pg → `user@host:port/dbname`, ws → URL,
    /// ssh → `user@host[:port]` (port shown only when non-default).
    pub fn target(&self) -> String {
        match self {
            ConnectionConfig::Api { host, .. } => host.clone(),
            ConnectionConfig::Pg {
                host,
                port,
                dbname,
                user,
                ..
            } => format!("{user}@{host}:{port}/{dbname}"),
            ConnectionConfig::Ws { url, .. } => url.clone(),
            ConnectionConfig::Ssh { host, port, user } => {
                if *port == 22 {
                    format!("{user}@{host}")
                } else {
                    format!("{user}@{host}:{port}")
                }
            }
        }
    }
}

/// A connection binds secret(s) to a destination (DESIGN.md §1/§9).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Connection {
    /// Stable id, standing rules key on it, never on the renamable name
    /// (DESIGN.md §7).
    pub id: Uuid,
    /// Unique; how agents and the UI address the connection.
    pub name: String,
    pub config: ConnectionConfig,
    /// Referenced secret ids. API connections may compose several (derived
    /// from the template's refs); pg/ws bind exactly one (DESIGN.md §9).
    pub secrets: Vec<Uuid>,
    /// pg/ws only: the session ticket may be redeemed any number of times
    /// within its 60 s window (default true, DESIGN.md §4.2/§4.3).
    #[serde(default = "default_true")]
    pub multi_connect: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

fn default_true() -> bool {
    true
}

impl Connection {
    pub fn kind(&self) -> ConnectionKind {
        self.config.kind()
    }
    pub fn target(&self) -> String {
        self.config.target()
    }
}

/// The peer's code-signing identity, pinned to a pair token at pairing time
/// (DESIGN.md §8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PeerIdentity {
    /// Verified signature: signing identifier + Team ID.
    Signed {
        signing_id: String,
        team_id: Option<String>,
    },
    /// Ad-hoc / unsigned peer, the pairing dialog calls this out loudly.
    Unsigned,
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
            PeerIdentity::Unsigned => "Unsigned, no pinned identity".into(),
            PeerIdentity::DevUnverified { uid } => format!("Dev build: uid {uid} (unverified)"),
        }
    }
}

/// A paired agent record (DESIGN.md §8/§9). Persisted in `agents.json`;
/// the pair token itself is stored only as a SHA-256 hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairedAgent {
    /// Self-asserted at pairing (§8), a label, not an authenticated identity.
    pub name: String,
    /// SHA-256 of the 256-bit bearer token, hex-encoded.
    pub token_hash: String,
    /// First characters of the token for the UI's masked preview.
    pub token_preview: String,
    /// Identity the token is pinned to.
    pub identity: PeerIdentity,
    pub paired_at: DateTime<Utc>,
    /// Refreshed on use; tokens expire 30 days after this (DESIGN.md §8).
    pub last_used: DateTime<Utc>,
}

/// A standing "always allow" rule (DESIGN.md §7).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Rule {
    pub id: Uuid,
    /// Self-asserted agent name (see the honesty note in §7).
    pub agent: String,
    /// The connection's stable id, never its renamable name.
    pub connection_id: Uuid,
    pub created_at: DateTime<Utc>,
}

/// Decision produced by the policy engine (DESIGN.md §7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
    Prompt,
}

/// The surface a human decision came from (audit attribution, §8).
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

/// How a high-consequence decision's confirmation was satisfied (§8).
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

/// User settings (DESIGN.md §3/§9).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Settings {
    /// "Sync secrets via iCloud Keychain", default on.
    pub icloud_sync: bool,
    /// "Require Touch ID to read secrets", default on. The macOS app
    /// gates each broker-side vault read with LocalAuthentication.
    pub reauth_on_read: bool,
    /// "Hide secret prefixes", default on. When on, the secrets list offers
    /// no reveal-prefix affordance; values stay copy-only.
    #[serde(default = "default_true")]
    pub hide_secret_prefixes: bool,
    /// Optional PEM CA bundle trusted for Postgres `verify-ca` /
    /// `verify-full` upstream TLS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pg_trusted_ca_bundle_path: Option<String>,
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
            icloud_sync: true,
            reauth_on_read: true,
            hide_secret_prefixes: true,
            pg_trusted_ca_bundle_path: None,
            menu_bar_hides_dock: false,
        }
    }
}

/// Compute the reveal prefix: the value's first `min(6, ⌊len/2⌋)` characters,
/// at most half the value, so a short secret isn't mostly exposed
/// (DESIGN.md §2). Returns the prefix with a trailing ellipsis when truncated.
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
        assert_eq!(api.target(), "api.github.com");
        let pg = ConnectionConfig::Pg {
            host: "db.internal.aka.com".into(),
            port: 5432,
            dbname: "app_production".into(),
            user: "app".into(),
            sslmode: PgSslMode::Require,
        };
        assert_eq!(pg.target(), "app@db.internal.aka.com:5432/app_production");
        let ws = ConnectionConfig::Ws {
            url: "wss://stream.example.com/feed".into(),
            template: None,
        };
        assert_eq!(ws.target(), "wss://stream.example.com/feed");
        let ssh = ConnectionConfig::Ssh {
            host: "prod.example.com".into(),
            port: 22,
            user: "deploy".into(),
        };
        assert_eq!(ssh.target(), "deploy@prod.example.com");
        let ssh_alt_port = ConnectionConfig::Ssh {
            host: "bastion.example.com".into(),
            port: 2222,
            user: "ops".into(),
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
                host: "prod.example.com".into(),
                port: 22,
                user: "deploy".into(),
            }
        );
        assert_eq!(conf.kind().as_str(), "ssh");
    }

    #[test]
    fn pg_sslmodes_match_libpq_names() {
        assert_eq!(
            serde_json::to_string(&PgSslMode::VerifyCa).unwrap(),
            "\"verify-ca\""
        );
        assert_eq!(
            serde_json::from_str::<PgSslMode>("\"verify-full\"").unwrap(),
            PgSslMode::VerifyFull
        );
    }
}
