//! Data-transfer types crossing the Tauri boundary to the webview.
//!
//! These carry masked metadata only, including a secret's name and
//! timestamps, never any fragment of its value. Reveal is a separate,
//! audited command that returns a short prefix on demand.

use aka_core::audit::AuditEntry;
use aka_core::broker::Broker;
use aka_core::sessions::SessionInfo;
use aka_core::types::{Connection, PairedAgent, SecretMeta, Wiring};
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

/// One agent wired to a connection, as the UI toggles it.
#[derive(Serialize)]
pub struct WiringChip {
    pub agent_id: String,
    pub agent: String,
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
    /// Agents wired to this connection.
    pub wired_agents: Vec<WiringChip>,
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
}

impl ConnectionDto {
    pub fn from(conn: &Connection, all_wirings: &[Wiring], broker: &Broker) -> Self {
        use aka_core::types::ConnectionConfig::*;
        let secret_names = conn
            .secrets
            .iter()
            .filter_map(|id| broker.store.secret_by_id(id).ok().map(|s| s.name))
            .collect();
        let wired_agents: Vec<WiringChip> = all_wirings
            .iter()
            .filter(|w| w.connection_id == conn.id)
            .map(|w| WiringChip {
                agent_id: w.client_id.to_string(),
                agent: w.agent.clone(),
            })
            .collect();
        let mut dto = ConnectionDto {
            id: conn.id.to_string(),
            name: conn.name.clone(),
            kind: conn.kind().as_str().to_string(),
            target: conn.target(),
            secret_names,
            wired_agents,
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
        };
        match &conn.config {
            Api {
                host,
                scheme,
                port,
                template,
            } => {
                dto.host = Some(host.clone());
                dto.scheme = Some(scheme.clone());
                dto.port = *port;
                dto.template = Some(template.clone());
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

#[derive(Serialize)]
pub struct AgentDto {
    pub id: String,
    pub name: String,
    pub paired_at: String,
    pub last_used: String,
    pub wiring_count: usize,
}

impl AgentDto {
    pub fn from(agent: &PairedAgent, wirings: &[Wiring]) -> Self {
        Self {
            id: agent.id.to_string(),
            name: agent.name.clone(),
            paired_at: agent.paired_at.to_rfc3339(),
            last_used: agent.last_used.to_rfc3339(),
            wiring_count: wirings
                .iter()
                .filter(|wiring| wiring.client_id == agent.id)
                .count(),
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
            at: e.ts.to_rfc3339(),
        }
    }
}

#[derive(Serialize)]
pub struct SettingsDto {
    pub reauth_on_read: bool,
    pub menu_bar_hides_dock: bool,
}
