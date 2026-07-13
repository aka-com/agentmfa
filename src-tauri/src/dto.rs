//! Data-transfer types crossing the Tauri boundary to the webview.
//!
//! These carry masked metadata only, including a secret's name and
//! timestamps, never any fragment of its value. Reveal is a separate,
//! audited command that returns a short prefix on demand.

use agentmfa_core::approvals::ApprovalRequest;
use agentmfa_core::audit::AuditEntry;
use agentmfa_core::broker::Broker;
use agentmfa_core::sessions::SessionInfo;
use agentmfa_core::types::{Connection, PairedAgent, PeerIdentity, Rule, SecretMeta};
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

#[derive(Serialize)]
pub struct PermissionChip {
    pub id: String,
    pub agent: String,
    pub scope: String,
    pub expires_at: Option<String>,
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
    /// Scoped access, whether expiring or standing.
    pub permissions: Vec<PermissionChip>,
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
    pub fn from(conn: &Connection, all_rules: &[Rule], broker: &Broker) -> Self {
        use agentmfa_core::types::ConnectionConfig::*;
        let secret_names = conn
            .secrets
            .iter()
            .filter_map(|id| broker.store.secret_by_id(id).ok().map(|s| s.name))
            .collect();
        let mut permissions: Vec<PermissionChip> = all_rules
            .iter()
            .filter(|r| r.connection_id == conn.id)
            .map(|r| PermissionChip {
                id: r.id.to_string(),
                agent: r.agent.clone(),
                scope: r.scope.as_str().to_string(),
                expires_at: None,
            })
            .collect();
        permissions.extend(broker.grants_for_connection(conn).into_iter().map(|grant| {
            PermissionChip {
                id: grant.id.to_string(),
                agent: grant.agent,
                scope: grant.scope.as_str().to_string(),
                expires_at: Some(grant.expires_at.to_rfc3339()),
            }
        }));
        let mut dto = ConnectionDto {
            id: conn.id.to_string(),
            name: conn.name.clone(),
            kind: conn.kind().as_str().to_string(),
            target: conn.target(),
            secret_names,
            permissions,
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
    pub program: String,
    pub verification: &'static str,
    pub identity: String,
    pub paired_at: String,
    pub last_used: String,
    pub permission_count: usize,
}

impl AgentDto {
    pub fn from(agent: &PairedAgent, rules: &[Rule], broker: &Broker) -> Self {
        let (program, verification) = match &agent.identity {
            PeerIdentity::Signed { signing_id, .. } => (signing_id.clone(), "Signed application"),
            PeerIdentity::Unsigned {
                executable_path, ..
            } => (
                executable_path
                    .as_deref()
                    .and_then(|path| std::path::Path::new(path).file_name())
                    .and_then(|name| name.to_str())
                    .unwrap_or("Unsigned local program")
                    .to_string(),
                "Local executable",
            ),
            PeerIdentity::DevUnverified { .. } => {
                ("Development process".into(), "Development identity")
            }
        };
        Self {
            id: agent.id.to_string(),
            name: agent.name.clone(),
            program,
            verification,
            identity: agent.identity.display(),
            paired_at: agent.paired_at.to_rfc3339(),
            last_used: agent.last_used.to_rfc3339(),
            permission_count: rules
                .iter()
                .filter(|rule| rule.client_id == agent.id)
                .count()
                + broker.grant_count_for_agent(&agent.name),
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
    pub show_service_walkthrough: bool,
    pub show_agent_walkthrough: bool,
}

/// The queued approval, as the approval window renders it. Serialized via
/// serde on `ApprovalRequest` directly, but we add the `high_consequence`
/// hint describing whether this request's exact *Allow once* decision needs
/// native authentication. Access-session and standing-rule decisions are
/// always gated independently of this hint.
#[derive(Serialize, Clone)]
pub struct ApprovalDto {
    #[serde(flatten)]
    pub request: ApprovalRequest,
    pub high_consequence: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temporary_access: Option<TemporaryAccessDto>,
}

#[derive(Serialize, Clone)]
pub struct TemporaryAccessDto {
    pub scope: &'static str,
    pub duration_seconds: u64,
}

impl ApprovalDto {
    pub fn new(request: ApprovalRequest, access_duration_seconds: u64) -> Self {
        let high_consequence = request.is_high_consequence();
        // Pairing and host-key trust prompts have no access-session shape;
        // the broker coerces any such decision to allow-once regardless.
        let temporary_access = if matches!(
            request.kind,
            agentmfa_core::approvals::ApprovalKind::Pair
                | agentmfa_core::approvals::ApprovalKind::Propose
        ) || request.ssh.is_some()
        {
            None
        } else {
            Some(TemporaryAccessDto {
                scope: match request.http.as_ref() {
                    Some(http) if !http.mutating => "read",
                    _ => "full",
                },
                duration_seconds: access_duration_seconds,
            })
        };
        Self {
            request,
            high_consequence,
            temporary_access,
        }
    }
}
