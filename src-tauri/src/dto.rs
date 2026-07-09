//! Data-transfer types crossing the Tauri boundary to the webview.
//!
//! These carry masked metadata only (DESIGN.md §2): a secret's name and
//! timestamps, never any fragment of its value. Reveal is a separate,
//! audited command that returns a short prefix on demand.

use agentmfa_core::approvals::ApprovalRequest;
use agentmfa_core::audit::AuditEntry;
use agentmfa_core::broker::Broker;
use agentmfa_core::sessions::SessionInfo;
use agentmfa_core::types::{Connection, PairedAgent, Rule, SecretMeta};
use serde::Serialize;

#[derive(Serialize)]
pub struct SecretDto {
    pub id: String,
    pub name: String,
    /// How many connections reference it (the "Used by N connections" line).
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

#[derive(Serialize)]
pub struct RuleChip {
    pub id: String,
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
    pub multi_connect: bool,
    /// Standing auto-allow rules on this connection (the ⚡ chips).
    pub rules: Vec<RuleChip>,
    // Type-specific config, prefilled into the Edit sheet.
    pub host: Option<String>,
    pub scheme: Option<String>,
    pub port: Option<u16>,
    pub template: Option<String>,
    pub dbname: Option<String>,
    pub user: Option<String>,
    pub host_key_fingerprint: Option<String>,
    pub sslmode: Option<String>,
    pub url: Option<String>,
}

impl ConnectionDto {
    pub fn from(conn: &Connection, all_rules: &[Rule], broker: &Broker) -> Self {
        use agentmfa_core::types::ConnectionConfig::*;
        let secret_names = conn
            .secrets
            .iter()
            .filter_map(|id| broker.store.secret_by_id(id).ok().map(|s| s.name))
            .collect();
        let rules = all_rules
            .iter()
            .filter(|r| r.connection_id == conn.id)
            .map(|r| RuleChip {
                id: r.id.to_string(),
                agent: r.agent.clone(),
            })
            .collect();
        let mut dto = ConnectionDto {
            id: conn.id.to_string(),
            name: conn.name.clone(),
            kind: conn.kind().as_str().to_string(),
            target: conn.target(),
            secret_names,
            multi_connect: conn.multi_connect,
            rules,
            host: None,
            scheme: None,
            port: None,
            template: None,
            dbname: None,
            user: None,
            host_key_fingerprint: None,
            sslmode: None,
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
            }
            Ws { url, template } => {
                dto.url = Some(url.clone());
                dto.template = template.clone();
            }
            Ssh {
                host,
                port,
                user,
                host_key_fingerprint,
            } => {
                dto.host = Some(host.clone());
                dto.port = Some(*port);
                dto.user = Some(user.clone());
                dto.host_key_fingerprint = Some(host_key_fingerprint.clone());
            }
        }
        dto
    }
}

#[derive(Serialize)]
pub struct AgentDto {
    pub name: String,
    pub identity: String,
    pub token_preview: String,
    pub paired_at: String,
    pub rule_count: usize,
}

impl AgentDto {
    pub fn from(agent: &PairedAgent, rules: &[Rule]) -> Self {
        Self {
            name: agent.name.clone(),
            identity: agent.identity.display(),
            token_preview: format!("{}…", agent.token_preview),
            paired_at: agent.paired_at.to_rfc3339(),
            rule_count: rules.iter().filter(|r| r.agent == agent.name).count(),
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
            text: e.text.clone(),
            detail: e.detail.clone(),
            at: e.ts.to_rfc3339(),
        }
    }
}

#[derive(Serialize)]
pub struct SettingsDto {
    pub icloud_sync: bool,
    pub reauth_on_read: bool,
    pub hide_secret_prefixes: bool,
    pub pg_trusted_ca_bundle_path: Option<String>,
    pub menu_bar_hides_dock: bool,
}

/// The queued approval, as the approval window renders it. Serialized via
/// serde on `ApprovalRequest` directly, but we add the `high_consequence`
/// hint the UI uses to label the Touch-ID-gated buttons.
#[derive(Serialize, Clone)]
pub struct ApprovalDto {
    #[serde(flatten)]
    pub request: ApprovalRequest,
    pub high_consequence: bool,
}

impl From<ApprovalRequest> for ApprovalDto {
    fn from(request: ApprovalRequest) -> Self {
        let high_consequence = request.is_high_consequence();
        Self {
            request,
            high_consequence,
        }
    }
}
