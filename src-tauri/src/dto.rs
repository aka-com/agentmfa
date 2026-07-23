//! Data-transfer types crossing the Tauri boundary to the webview.
//!
//! These carry masked metadata only, including a secret's name and
//! timestamps, never any fragment of its value. Reveal is a separate,
//! audited command that returns a short prefix on demand.

use aka_core::audit::AuditEntry;
use aka_core::broker::Broker;
use aka_core::sessions::SessionInfo;
use aka_core::types::{BrokerIdentity, Connection, SecretMeta};
use serde::Serialize;

#[derive(Serialize)]
pub struct SecretDto {
    pub id: String,
    pub name: String,
    /// How many services reference it (the "Used by N services" line).
    pub used_by: usize,
    pub used_by_names: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl SecretDto {
    pub fn from(meta: &SecretMeta, broker: &Broker) -> Self {
        let names = broker.store.connections_using(&meta.id);
        Self {
            id: meta.id.to_string(),
            name: meta.name.clone(),
            used_by: names.len(),
            used_by_names: names,
            created_at: meta.created_at.to_rfc3339(),
            updated_at: meta.updated_at.to_rfc3339(),
        }
    }
}

/// Non-secret OAuth coordinates, so the UI can label the connection and
/// offer Reconnect. Never token material.
#[derive(Serialize)]
pub struct OAuthDto {
    pub auth_url: String,
    pub token_url: String,
    pub client_id: String,
    pub scopes: Vec<String>,
}

/// A connection's agent access, as the UI toggles it. There is one shared
/// identity, so this is per connection, not per agent.
#[derive(Serialize)]
pub struct AccessDto {
    /// Whether agents may use the connection (default true).
    pub enabled: bool,
    /// Curated upstream MCP tool subset; absent means all tools.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_tools: Option<Vec<String>>,
    /// The direct endpoint issued for this connection, if any. Its presence
    /// flips the row's control from "Issue" to "Reissue / Revoke".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<EndpointChip>,
}

/// The direct endpoint on a wiring row. `dsn` is the pasteable address with
/// the retained endpoint secret in its password slot, so copying the chip is
/// enough to connect; it is omitted for SSH, whose socket path is itself the
/// capability and is shown only in the issue sheet.
#[derive(Serialize)]
pub struct EndpointChip {
    pub endpoint_id: String,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dsn: Option<String>,
}

/// The result of issuing a direct endpoint: the pasteable address, a
/// ready-to-run example, and the secret (also retained on the record, so
/// the row's chip stays copyable with the credential in place).
#[derive(Serialize)]
pub struct IssuedEndpointDto {
    pub endpoint_id: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub dsn: String,
    pub secret: String,
    pub example: String,
}

impl From<aka_core::broker::IssuedEndpointInfo> for IssuedEndpointDto {
    fn from(info: aka_core::broker::IssuedEndpointInfo) -> Self {
        Self {
            endpoint_id: info.endpoint_id.to_string(),
            kind: info.kind.as_str().to_string(),
            dsn: info.dsn,
            secret: info.secret,
            example: info.example,
        }
    }
}

#[derive(Serialize)]
pub struct ConnectionDto {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub target: String,
    /// Referenced secret names (the 🔑 chips).
    pub secret_names: Vec<String>,
    /// Whether this connection uses a broker-managed OAuth grant. The grant
    /// itself lives in the vault and is never exposed to the webview.
    pub oauth: bool,
    /// Agent access for this connection (shared identity — one setting
    /// covers every agent).
    pub agent_access: AccessDto,
    // Type-specific config, prefilled into the Edit sheet.
    pub host: Option<String>,
    pub scheme: Option<String>,
    pub port: Option<u16>,
    pub template: Option<String>,
    pub dbname: Option<String>,
    pub user: Option<String>,
    pub host_key_fingerprint: Option<String>,
    pub destination: Option<String>,
    pub sslmode: Option<String>,
    pub trusted_ca_bundle_path: Option<String>,
    pub url: Option<String>,
    /// Set when an API upstream speaks MCP at that path; the sidecar
    /// re-exposes its tools under this connection's name.
    pub mcp_path: Option<String>,
    /// The upstream account this connection's credential was last verified
    /// as (an MCP whoami answer). Display metadata, never authorization.
    pub account: Option<String>,
    /// Set when the credential is a BYO-app OAuth token set.
    pub oauth_spec: Option<OAuthDto>,
    /// Last-known health: "ok" | "failed" | "needs_reconnect", with the
    /// check's summary and timestamp. All absent while untested.
    pub last_status: Option<String>,
    pub last_detail: Option<String>,
    pub last_checked_at: Option<String>,
}

impl ConnectionDto {
    pub fn from(conn: &Connection, broker: &Broker) -> Self {
        use aka_core::types::ConnectionConfig::*;
        let secret_names = conn
            .secrets
            .iter()
            .filter_map(|id| broker.store.secret_by_id(id).ok().map(|s| s.name))
            .collect();
        let entry = broker.access.entry(&conn.id);
        let agent_access = AccessDto {
            enabled: entry.as_ref().map(|e| e.enabled).unwrap_or(true),
            allowed_tools: entry.and_then(|e| e.allowed_tools),
            endpoint: broker
                .endpoints
                .get_for_connection(&conn.id)
                .map(|e| {
                    let dsn = match &conn.config {
                        // The retained secret rides in the password slot; a
                        // pre-retention record (empty secret) falls back to
                        // the password-less form until reissued.
                        Pg { user, dbname, .. } => Some(aka_core::capability::pg::endpoint_dsn(
                            broker.paths.endpoint_dir(&e.id).as_path(),
                            user,
                            dbname,
                            (!e.secret.is_empty()).then_some(e.secret.as_str()),
                        )),
                        Api { .. } => e.port.map(|port| format!("http://127.0.0.1:{port}")),
                        _ => None,
                    };
                    EndpointChip {
                        endpoint_id: e.id.to_string(),
                        kind: e.kind.as_str().to_string(),
                        dsn,
                    }
                }),
        };
        let health = broker.health.get(&conn.id);
        let mut dto = ConnectionDto {
            id: conn.id.to_string(),
            name: conn.name.clone(),
            kind: conn.kind().as_str().to_string(),
            target: conn.target(),
            secret_names,
            oauth: conn.oauth.is_some(),
            agent_access,
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
            url: None,
            mcp_path: None,
            account: conn.account.clone(),
            oauth_spec: None,
            last_status: health.as_ref().map(|h| h.status.as_str().to_string()),
            last_detail: health.as_ref().map(|h| h.detail.clone()),
            last_checked_at: health.as_ref().map(|h| h.checked_at.to_rfc3339()),
        };
        match &conn.config {
            Api {
                host,
                scheme,
                port,
                template,
                mcp_path,
                oauth,
            } => {
                dto.host = Some(host.clone());
                dto.scheme = Some(scheme.clone());
                dto.port = *port;
                dto.template = Some(template.clone());
                dto.mcp_path = mcp_path.clone();
                dto.oauth_spec = oauth.as_ref().map(|o| OAuthDto {
                    auth_url: o.auth_url.clone(),
                    token_url: o.token_url.clone(),
                    client_id: o.client_id.clone(),
                    scopes: o.scopes.clone(),
                });
            }
            Pg {
                host,
                port,
                dbname,
                user,
                sslmode,
                trusted_ca_bundle_path,
            } => {
                dto.host = Some(host.clone());
                dto.port = Some(*port);
                dto.dbname = Some(dbname.clone());
                dto.user = Some(user.clone());
                dto.sslmode = Some(
                    serde_json::to_value(sslmode)
                        .ok()
                        .and_then(|v| v.as_str().map(str::to_string))
                        .unwrap_or_else(|| "prefer".into()),
                );
                dto.trusted_ca_bundle_path = trusted_ca_bundle_path.clone();
            }
            Ws { url, template } => {
                dto.url = Some(url.clone());
                dto.template = template.clone();
            }
            Ssh {
                destination,
                host,
                port,
                user,
                host_key_fingerprint,
            } => {
                dto.destination = destination.clone();
                dto.host = Some(host.clone());
                dto.port = Some(*port);
                dto.user = Some(user.clone());
                // None while unpinned so the UI can tell "trusted on first
                // use, pending" apart from a pinned fingerprint.
                dto.host_key_fingerprint =
                    (!host_key_fingerprint.is_empty()).then(|| host_key_fingerprint.clone());
            }
        }
        dto
    }
}

/// The shared broker identity, for the Connect page's key card. Never the
/// key itself — only its home and lifecycle metadata.
#[derive(Serialize)]
pub struct IdentityDto {
    pub client_id: String,
    /// Where the plaintext key lives (`~/.aka/token`), for display and copy
    /// instructions.
    pub token_path: String,
    /// The broker socket, for the Connect page's setup snippets.
    pub socket_path: String,
    pub minted_at: String,
    pub last_used: String,
    /// How many legacy per-agent tokens still work as aliases (cleared by
    /// the first rotation).
    pub legacy_aliases: usize,
}

impl IdentityDto {
    pub fn from(identity: &BrokerIdentity, broker: &Broker) -> Self {
        Self {
            client_id: identity.id.to_string(),
            token_path: broker.paths.token_display(),
            socket_path: broker.paths.socket_display(),
            minted_at: identity.minted_at.to_rfc3339(),
            last_used: identity.last_used.to_rfc3339(),
            legacy_aliases: broker.identity.active_alias_count(),
        }
    }
}

#[derive(Serialize)]
pub struct SessionDto {
    pub id: u64,
    #[serde(rename = "type")]
    pub kind: String,
    pub agent: String,
    pub connection: String,
    pub detail: String,
    pub opened_at: String,
}

impl From<&SessionInfo> for SessionDto {
    fn from(s: &SessionInfo) -> Self {
        Self {
            id: s.id,
            kind: s.kind.as_str().to_string(),
            agent: s.agent.clone(),
            connection: s.connection.clone(),
            detail: s.detail.clone(),
            opened_at: s.opened_at.to_rfc3339(),
        }
    }
}

#[derive(Serialize, Clone)]
pub struct ActivityDto {
    pub icon: String,
    pub tone: String,
    pub text: String,
    pub detail: Option<String>,
    /// Structured attribution for filtering: which agent acted and which
    /// connection was touched (both optional per entry).
    pub agent: Option<String>,
    pub connection: Option<String>,
    /// How long a brokered call or session took, when measured.
    pub duration_ms: Option<u64>,
    /// RFC 3339 timestamp; the UI renders it relative (<24h) or absolute and
    /// shows the full value in a hover tooltip.
    pub at: String,
}

impl From<&AuditEntry> for ActivityDto {
    fn from(e: &AuditEntry) -> Self {
        Self {
            icon: e.kind.icon().to_string(),
            tone: e.kind.tone().to_string(),
            text: e.text.clone(),
            detail: e.detail.clone(),
            agent: e.agent.clone(),
            connection: e.connection.clone(),
            duration_ms: e.duration_ms,
            at: e.ts.to_rfc3339(),
        }
    }
}

#[derive(Serialize)]
pub struct SettingsDto {
    pub reauth_on_read: bool,
    pub show_websockets: bool,
    pub menu_bar_hides_dock: bool,
    pub presence_window_secs: u64,
}
