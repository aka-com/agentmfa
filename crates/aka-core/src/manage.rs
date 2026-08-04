//! The management plane's backend seam.
//!
//! The desktop shell manages a broker exclusively through
//! [`ManagementBackend`]: in local mode the implementation is
//! [`LocalBackend`] wrapping an in-process [`Broker`]; in remote mode it is
//! an HTTP client speaking the same shapes to a hosted broker's manage API.
//! The wire types live in `aka-api` so the two cannot drift.
//!
//! Everything here is a thin adapter: authorization, confirmation gates, and
//! auditing stay in the core's `ui_*` entry points. `LocalBackend` runs
//! synchronous mutating calls on a blocking thread because they can demand
//! the shell's native confirmation, which must never park the async runtime
//! (the same rule the shell's `rotate_key` always followed).

use std::sync::Arc;

use aka_api::{
    AccessDto, ActivityDto, ApprovalDecisionDto, ApprovalDto, ConnectionDto, ElicitationDto,
    EndpointChip, IdentityDto, IssuedEndpointDto, ManageError, OAuthDto, OnePasswordFieldDto,
    OnePasswordHealthDto, OnePasswordIntegrationDto, OnePasswordItemDto, OnePasswordVaultDto,
    RequestDto, SecretDto, SecretKindDto, SessionDto, SettingsDto, TotpCodeDto,
};
use async_trait::async_trait;
use uuid::Uuid;

use crate::audit::AuditEntry;
use crate::broker::{Broker, ConnectionTestReport, IssuedEndpointInfo};
use crate::error::CoreError;
use crate::store::ConnectionSpec;
use crate::types::{
    Connection, ConnectionConfig, DecisionSurface, PgSslMode, SecretKind, SecretMeta, SecretValue,
};

/// A management call's result: the value, or the wire-shaped error the
/// shell maps onto form fields.
pub type ManageResult<T> = std::result::Result<T, ManageError>;

impl From<CoreError> for ManageError {
    fn from(error: CoreError) -> Self {
        match error {
            CoreError::SecretNameTaken(name) => Self::SecretNameTaken { name },
            CoreError::ConnectionNameTaken(name) => Self::ConnectionNameTaken { name },
            CoreError::ConnectionTargetTaken(name) => Self::ConnectionTargetTaken { name },
            CoreError::SecretNotFound => Self::SecretNotFound,
            CoreError::OnePasswordIntegrationNotFound => Self::OnePassword {
                provider_code: "integration_not_found".into(),
                message: "no such 1Password integration".into(),
            },
            CoreError::OnePasswordIntegrationInUse(secrets) => Self::OnePassword {
                provider_code: "integration_in_use".into(),
                message: format!("the integration is used by: {}", secrets.join(", ")),
            },
            CoreError::InvalidOnePasswordIntegration(message) => Self::OnePassword {
                provider_code: "invalid_configuration".into(),
                message,
            },
            CoreError::OnePassword { code, message } => Self::OnePassword {
                provider_code: code,
                message,
            },
            CoreError::ExternalSecretReadOnly => Self::OnePassword {
                provider_code: "linked_secret_read_only".into(),
                message: "linked 1Password secrets are read-only".into(),
            },
            CoreError::ConnectionNotFound => Self::ConnectionNotFound,
            CoreError::ConnectionChanged => Self::ConnectionChanged,
            CoreError::ApprovalConnectionChanged => Self::ApprovalConnectionChanged,
            CoreError::SecretInUse(connections) => Self::SecretInUse { connections },
            CoreError::InvalidSecretName(name) => Self::InvalidSecretName { name },
            CoreError::InvalidSite(message) => Self::InvalidSite { message },
            CoreError::InvalidTotpSeed(message) => Self::InvalidTotpSeed { message },
            CoreError::TotpNotConfigured => Self::TotpNotConfigured,
            CoreError::NotAPassword => Self::NotAPassword,
            CoreError::InvalidConnectionName(name) => Self::InvalidConnectionName { name },
            CoreError::Template(error) => Self::Template {
                message: error.to_string(),
            },
            CoreError::UnknownTemplateRef(name) => Self::UnknownTemplateRef { name },
            CoreError::WrongSecretCount { kind } => Self::WrongSecretCount { kind: kind.into() },
            CoreError::InvalidConnectionConfig(message) => {
                Self::InvalidConnectionConfig { message }
            }
            CoreError::InvalidSetting(message) => Self::InvalidSetting { message },
            CoreError::InvalidConnectionField { field, message } => {
                Self::InvalidConnectionField { field, message }
            }
            CoreError::KindChange => Self::KindChange,
            CoreError::EndpointNotFound => Self::EndpointNotFound,
            CoreError::EndpointExpired => Self::EndpointExpired,
            CoreError::EndpointLimit(max) => Self::EndpointLimit { max },
            CoreError::EndpointRequiresWiring => Self::EndpointRequiresWiring,
            CoreError::OAuth(message) => Self::OAuth { message },
            CoreError::Vault(message) => Self::Vault { message },
            other => Self::Internal {
                message: other.to_string(),
            },
        }
    }
}

/* ------------------------------ DTO builders ------------------------------ */

pub fn secret_dto(broker: &Broker, meta: &SecretMeta) -> SecretDto {
    let names = broker.store.connections_using(&meta.id);
    SecretDto {
        id: meta.id.to_string(),
        name: meta.name.clone(),
        used_by: names.len(),
        used_by_names: names,
        created_at: meta.created_at.to_rfc3339(),
        updated_at: meta.updated_at.to_rfc3339(),
        source: crate::onepassword::source_dto(
            &meta.source,
            &broker.store.list_onepassword_integrations(),
        ),
        kind: match meta.kind {
            crate::types::SecretKind::Secret => aka_api::SecretKindDto::Secret,
            crate::types::SecretKind::Password => aka_api::SecretKindDto::Password,
        },
        site: meta.site.clone(),
        username: meta.username.clone(),
        totp: meta.has_totp(),
    }
}

pub fn connection_dto(broker: &Broker, conn: &Connection) -> ConnectionDto {
    use crate::types::ConnectionConfig::*;
    let secret_names = conn
        .secrets
        .iter()
        .filter_map(|id| broker.store.secret_by_id(id).ok().map(|s| s.name))
        .collect();
    let entry = broker.access.entry(&conn.id);
    let agent_access = AccessDto {
        enabled: entry.as_ref().map(|e| e.enabled).unwrap_or(true),
        confirm: entry
            .as_ref()
            .map(|e| e.confirm.is_on())
            .unwrap_or_default(),
        expose_response_credentials: matches!(&conn.config, Api { .. })
            && broker.access.expose_response_credentials(&conn.id),
        confirm_window_until: broker.approvals.window_remaining(&conn.id).map(|left| {
            (chrono::Utc::now()
                + chrono::Duration::from_std(left).unwrap_or_else(|_| chrono::Duration::zero()))
            .to_rfc3339()
        }),
        confirm_window_agents: broker.approvals.window_agents(&conn.id),
        confirm_cooldown_until: broker.approvals.cooldown_remaining(&conn.id).map(|left| {
            (chrono::Utc::now()
                + chrono::Duration::from_std(left).unwrap_or_else(|_| chrono::Duration::zero()))
            .to_rfc3339()
        }),
        audit_statements: entry.as_ref().and_then(|e| e.audit_statements),
        audit_statements_effective: broker
            .access
            .audit_statements(&conn.id, broker.config.audit_pg_statements),
        allowed_tools: entry.and_then(|e| e.allowed_tools),
        endpoint: broker.endpoints.get_for_connection(&conn.id).map(|e| {
            let dsn = match &conn.config {
                // The retained secret rides in the password slot; a
                // pre-retention record (empty secret) falls back to
                // the password-less form until reissued.
                Pg { user, dbname, .. } => Some(crate::capability::pg::endpoint_dsn(
                    broker.paths.endpoint_dir(&e.id).as_path(),
                    user,
                    dbname,
                    (!e.secret.is_empty()).then_some(e.secret.as_str()),
                )),
                // Deliberately omitted for SSH. The socket path *is* the
                // capability — the ssh-agent protocol offers no place to
                // present a secret — so putting it in the ordinary connection
                // listing handed a working signing oracle to every manage
                // caller that asked for the list, not only to one that asked
                // for the endpoint. `GET .../endpoint` still returns it.
                Ssh { .. } => None,
                Api { .. } => e
                    .port
                    .map(|port| format!("http://{}:{port}", broker.advertise_host())),
            };
            EndpointChip {
                endpoint_id: e.id.to_string(),
                kind: e.kind.as_str().to_string(),
                dsn,
                require_auth: e.require_auth,
                expires_at: e.expires_at.map(|at| at.to_rfc3339()).unwrap_or_default(),
                expires_in_secs: e.expires_at.map(secs_until),
            }
        }),
    };
    let health = broker.health.get(&conn.id);
    let mut dto = ConnectionDto {
        id: conn.id.to_string(),
        name: conn.name.clone(),
        updated_at: conn.version(),
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
        mcp_path: None,
        test_path: None,
        account: conn.account.clone(),
        oauth_spec: None,
        last_status: health.as_ref().map(|h| h.status.as_str().to_string()),
        last_detail: health.as_ref().map(|h| h.detail.clone()),
        last_checked_at: health.as_ref().map(|h| h.checked_at.to_rfc3339()),
        signer: None,
        client_cert_path: None,
        client_key_path: None,
    };
    match &conn.config {
        Api {
            host,
            scheme,
            port,
            trusted_ca_bundle_path,
            template,
            mcp_path,
            test_path,
            oauth,
            signer,
            client_cert_path,
            client_key_path,
        } => {
            dto.host = Some(host.clone());
            dto.scheme = Some(scheme.clone());
            dto.port = *port;
            dto.trusted_ca_bundle_path = trusted_ca_bundle_path.clone();
            dto.template = Some(template.clone());
            dto.mcp_path = mcp_path.clone();
            dto.test_path = test_path.clone();
            dto.oauth_spec = oauth.as_ref().map(|o| OAuthDto {
                auth_url: o.auth_url.clone(),
                token_url: o.token_url.clone(),
                client_id: o.client_id.clone(),
                scopes: o.scopes.clone(),
                extra_auth_params: o.extra_auth_params.clone(),
            });
            dto.signer = signer.as_ref().map(|spec| match spec {
                crate::types::SignerSpec::AwsSigv4 {
                    region,
                    service,
                    access_key_ref,
                    secret_key_ref,
                    session_token_ref,
                } => aka_api::SignerDto {
                    algorithm: "aws_sigv4".to_string(),
                    region: region.clone(),
                    service: service.clone(),
                    access_key_ref: access_key_ref.clone(),
                    secret_key_ref: secret_key_ref.clone(),
                    session_token_ref: session_token_ref.clone(),
                    key_ref: None,
                    scope: None,
                },
                crate::types::SignerSpec::GcpServiceAccount { key_ref, scope } => {
                    aka_api::SignerDto {
                        algorithm: "gcp_service_account".to_string(),
                        region: String::new(),
                        service: String::new(),
                        access_key_ref: String::new(),
                        secret_key_ref: String::new(),
                        session_token_ref: None,
                        key_ref: Some(key_ref.clone()),
                        scope: Some(scope.clone()),
                    }
                }
            });
            dto.client_cert_path = client_cert_path.clone();
            dto.client_key_path = client_key_path.clone();
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

pub fn identity_dto(broker: &Broker) -> IdentityDto {
    let identity = broker.identity_info();
    IdentityDto {
        client_id: identity.id.to_string(),
        token_path: broker.paths.token_display(),
        socket_path: broker.paths.socket_display(),
        minted_at: identity.minted_at.to_rfc3339(),
        last_used: identity.last_used.to_rfc3339(),
        legacy_aliases: broker.identity.active_alias_count(),
    }
}

pub fn session_dto(session: &crate::sessions::SessionInfo) -> SessionDto {
    SessionDto {
        id: session.id,
        kind: session.kind.as_str().to_string(),
        agent: session.agent.clone(),
        connection: session.connection.clone(),
        detail: session.detail.clone(),
        opened_at: session.opened_at.to_rfc3339(),
    }
}

/// Seconds until a deadline, on this broker's clock right now. Rides beside
/// the absolute RFC 3339 form so a client can anchor the countdown to its
/// own clock instead of trusting the two clocks to agree.
fn secs_until(deadline: chrono::DateTime<chrono::Utc>) -> u64 {
    (deadline - chrono::Utc::now()).num_seconds().max(0) as u64
}

/// One waiting prompt, as the app renders it.
pub fn approval_dto(pending: &crate::approvals::PendingApproval) -> ApprovalDto {
    ApprovalDto {
        id: pending.id.to_string(),
        connection_id: pending.connection_id.to_string(),
        connection: pending.connection.clone(),
        kind: pending.kind.as_str().to_string(),
        unit: Some(pending.unit.as_str().to_string()),
        target: pending.target.clone(),
        agent: pending.agent.clone(),
        summary: pending.summary.clone(),
        detail: pending.detail.clone(),
        credential_names: pending.credential_names.clone(),
        method: pending.method.clone(),
        path: pending.path.clone(),
        host_key_fingerprint: pending.host_key_fingerprint.clone(),
        consequence: pending.consequence.map(str::to_string),
        waiting: pending.waiting,
        requested_at: pending.requested_at.to_rfc3339(),
        expires_at: pending.expires_at.to_rfc3339(),
        expires_in_secs: Some(secs_until(pending.expires_at)),
        window_secs: pending.window_secs,
    }
}

pub fn request_dto(record: &crate::request_history::RequestRecord) -> RequestDto {
    RequestDto {
        id: record.id.to_string(),
        kind: record.kind.as_str().to_string(),
        status: record.status.as_str().to_string(),
        connection_id: record.connection_id.map(|id| id.to_string()),
        connection: record.connection.clone(),
        connection_type: record.connection_kind.map(|kind| kind.as_str().to_string()),
        unit: record.unit.map(|unit| unit.as_str().to_string()),
        target: record.target.clone(),
        agent: record.agent.clone(),
        summary: record.summary.clone(),
        detail: record.detail.clone(),
        credential_names: record.credential_names.clone(),
        method: record.method.clone(),
        path: record.path.clone(),
        host_key_fingerprint: record.host_key_fingerprint.clone(),
        waiting: record.waiting,
        requested_at: record.requested_at.to_rfc3339(),
        expires_at: record.expires_at.map(|at| at.to_rfc3339()),
        // Only a pending record still counts down; a terminal one shows its
        // resolution time instead.
        expires_in_secs: (record.status == crate::request_history::RequestStatus::Pending)
            .then(|| record.expires_at.map(secs_until))
            .flatten(),
        resolved_at: record.resolved_at.map(|at| at.to_rfc3339()),
        resolution: record
            .resolution
            .map(|resolution| resolution.as_str().to_string()),
        window_secs: record.window_secs,
    }
}

pub fn elicitation_dto(pending: &crate::elicitations::PendingElicitation) -> ElicitationDto {
    ElicitationDto {
        id: pending.id.to_string(),
        agent: pending.agent.clone(),
        connection: pending.connection.clone(),
        tool: pending.tool.clone(),
        prompt: pending.message.clone(),
        fields: pending
            .fields
            .iter()
            .map(|field| aka_api::ElicitationFieldDto {
                name: field.name.clone(),
                label: field.label.clone(),
                required: field.required,
                boolean: field.boolean,
                options: field.options.clone(),
            })
            .collect(),
        credential_warning: pending.credential_warning,
        requested_at: pending.requested_at.to_rfc3339(),
        expires_at: pending.expires_at.to_rfc3339(),
        expires_in_secs: Some(secs_until(pending.expires_at)),
    }
}

fn approval_decision(decision: ApprovalDecisionDto) -> crate::approvals::ApprovalDecision {
    match decision {
        ApprovalDecisionDto::ApproveWindow => crate::approvals::ApprovalDecision::ApproveWindow,
        ApprovalDecisionDto::ApproveAll => crate::approvals::ApprovalDecision::ApproveAll,
        ApprovalDecisionDto::Deny => crate::approvals::ApprovalDecision::Deny,
    }
}

pub fn activity_dto(entry: &AuditEntry) -> ActivityDto {
    let surface = entry.surface.map(|surface| match surface {
        DecisionSurface::AppWindow => "app_window",
        DecisionSurface::Cli => "cli",
        DecisionSurface::Remote { .. } => "remote",
        DecisionSurface::Harness => "harness",
    });
    ActivityDto {
        icon: entry.kind.icon().to_string(),
        tone: entry.kind.tone().to_string(),
        kind: serde_json::to_value(entry.kind)
            .ok()
            .and_then(|value| value.as_str().map(str::to_string)),
        text: entry.text.clone(),
        detail: entry.detail.clone(),
        agent: entry.agent.clone(),
        connection: entry.connection.clone(),
        outcome: entry.outcome.clone(),
        protocol: entry
            .fields
            .get("kind")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string),
        duration_ms: entry.duration_ms,
        approver: entry.approver.clone(),
        surface: surface.map(str::to_string),
        confirmation: entry.confirmation.and_then(|method| {
            serde_json::to_value(method)
                .ok()
                .and_then(|value| value.as_str().map(str::to_string))
        }),
        at: entry.ts.to_rfc3339(),
    }
}

pub fn settings_dto(broker: &Broker) -> SettingsDto {
    let settings = broker.settings();
    SettingsDto {
        menu_bar_hides_dock: settings.menu_bar_hides_dock,
        confirm_ssh_host_keys: settings.confirm_ssh_host_keys,
    }
}

fn issued_endpoint_dto(info: IssuedEndpointInfo) -> IssuedEndpointDto {
    IssuedEndpointDto {
        endpoint_id: info.endpoint_id.to_string(),
        kind: info.kind.as_str().to_string(),
        dsn: info.dsn,
        tcp_dsn: info.tcp_dsn,
        secret: info.secret,
        example: info.example,
        // On the wire "no deadline" is the empty string, which every
        // consumer already parses as expiry-unknown → never expires.
        expires_at: info
            .expires_at
            .map(|at| at.to_rfc3339())
            .unwrap_or_default(),
        expires_in_secs: info.expires_at.map(secs_until),
    }
}

/// The agent-setup snippet the Connect page shows and copies, rendered for a
/// broker reached over its Unix socket.
pub fn agent_setup_instructions(socket: &str, token_path: &str) -> String {
    format!(
        concat!(
            "Connect to the local Multitool broker. Read its current instructions, ",
            "then list the available connections:\n\n",
            "curl -fsS --unix-socket {socket} \\\n",
            "  -H \"Authorization: Bearer $(cat {token_path})\" \\\n",
            "  http://localhost/instructions"
        ),
        socket = socket,
        token_path = token_path,
    )
}

/// The agent-setup snippet for a broker reached over the network: agents on
/// other machines use the public URL and the operator-provided shared key.
pub fn agent_setup_instructions_remote(base: &str) -> String {
    let base = base.trim_end_matches('/');
    format!(
        "Connect to the Multitool broker at {base}. Read its current instructions, then list the available connections:\n\ncurl -fsS -H \"Authorization: Bearer <key>\" {base}/instructions\n\nAuthenticate with the broker's shared key — ask the broker's operator for it (on the broker host it lives in ~/.aka/token). MCP clients connect straight to {base}/mcp with the same Authorization header."
    )
}

/* ------------------------------- event bus -------------------------------- */

/// One numbered manage event. The seq lets a reconnecting client resume from
/// where it left off (SSE `Last-Event-ID`) instead of refetching everything.
#[derive(Clone, Debug)]
pub struct SeqEvent {
    pub seq: u64,
    pub event: aka_api::ManageEvent,
}

/// How much history the bus keeps for reconnect replay. A client offline
/// long enough to fall off the back of this window gets a resync instead —
/// safe, just less efficient.
const MANAGE_RING_CAP: usize = 512;

/// What a reconnecting client should be sent.
pub enum ManageReplay {
    /// The client is caught up (its last id is the current head).
    UpToDate,
    /// Deliver exactly these missed events, in order.
    Replay(Vec<SeqEvent>),
    /// The client's position is unknown, foreign, or evicted: it must
    /// refetch everything.
    Resync,
}

/// The manage-plane event bus: a broadcast channel for live delivery plus a
/// bounded ring buffer and monotonic sequence for reconnect replay. The
/// `epoch` is minted per broker process, so a client resuming against a
/// restarted broker (whose seq reset) is detected and resynced rather than
/// silently misaligned.
pub struct ManageBus {
    tx: tokio::sync::broadcast::Sender<SeqEvent>,
    seq: std::sync::atomic::AtomicU64,
    ring: std::sync::Mutex<std::collections::VecDeque<SeqEvent>>,
    approval_surfaces: std::sync::Mutex<std::collections::HashMap<Uuid, ApprovalSurfaceExpiry>>,
    epoch: String,
}

/// A request surface has to heartbeat over a separate authenticated request
/// to renew this lease. The timeout is deliberately much shorter than an
/// approval's deadline: a frozen client or black-holed response stream must
/// stop making new traffic wait for a UI that is no longer responsive.
const APPROVAL_SURFACE_TTL: std::time::Duration =
    std::time::Duration::from_millis(aka_api::APPROVAL_SURFACE_TTL_MS);

struct ApprovalSurfaceExpiry {
    monotonic: std::time::Instant,
    wall: chrono::DateTime<chrono::Utc>,
}

/// Capability lease held by an authenticated manage-event stream that
/// promises it can surface and answer requests. Dropping the stream releases
/// it immediately; expiration is a backstop for suspended or wedged tasks.
pub struct ApprovalSurfaceLease {
    bus: Arc<ManageBus>,
    id: Uuid,
}

impl ApprovalSurfaceLease {
    /// Broker-minted identifier the attached client must heartbeat.
    pub fn id(&self) -> Uuid {
        self.id
    }
}

impl Drop for ApprovalSurfaceLease {
    fn drop(&mut self) {
        self.bus.release_approval_surface(&self.id);
    }
}

impl Default for ManageBus {
    fn default() -> Self {
        Self::new()
    }
}

impl ManageBus {
    pub fn new() -> Self {
        let (tx, _) = tokio::sync::broadcast::channel(MANAGE_RING_CAP);
        let mut bytes = [0u8; 8];
        getrandom::fill(&mut bytes).expect("os rng");
        let epoch = bytes.iter().map(|b| format!("{b:02x}")).collect();
        Self {
            tx,
            seq: std::sync::atomic::AtomicU64::new(0),
            ring: std::sync::Mutex::new(std::collections::VecDeque::new()),
            approval_surfaces: std::sync::Mutex::new(std::collections::HashMap::new()),
            epoch,
        }
    }

    /// This process's event epoch, part of every event id.
    pub fn epoch(&self) -> &str {
        &self.epoch
    }

    /// Number and publish an event: append to the ring (evicting the oldest
    /// past the cap) and broadcast to live subscribers. Numbering, the ring
    /// append, and the broadcast all happen under the ring lock so the ring
    /// and the live stream both see seqs in order — two concurrent emits
    /// must not interleave, or `replay_since`'s head/oldest reasoning (and a
    /// client's monotonic last-id tracking) would miss events.
    pub fn emit(&self, event: aka_api::ManageEvent) {
        let mut ring = self.ring.lock().unwrap();
        let seq = self.seq.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
        let item = SeqEvent { seq, event };
        ring.push_back(item.clone());
        while ring.len() > MANAGE_RING_CAP {
            ring.pop_front();
        }
        // A send error only means no live subscribers; the ring still has it.
        let _ = self.tx.send(item);
    }

    /// The newest published seq (0 when nothing was emitted yet): the
    /// resume baseline handed to a client that is being resynced.
    pub fn head_seq(&self) -> u64 {
        self.ring.lock().unwrap().back().map(|e| e.seq).unwrap_or(0)
    }

    /// Subscribe to live events. Subscribe *before* snapshotting the ring so
    /// no event slips through the gap between the two.
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<SeqEvent> {
        self.tx.subscribe()
    }

    /// Register an authenticated event stream that explicitly advertised a
    /// user-facing request inbox. An ordinary SSE receiver is only an
    /// observer and must not make confirmed traffic wait. Minting grants one
    /// TTL of grace so a reconnect or broker restart does not refuse
    /// confirmed traffic during the ready-comment/first-heartbeat round
    /// trip; a surface that never heartbeats (a proxy black-holing the
    /// response body, say) lapses at that TTL and stays inactive.
    pub fn lease_approval_surface(self: &Arc<Self>) -> ApprovalSurfaceLease {
        self.lease_approval_surface_for(APPROVAL_SURFACE_TTL)
    }

    /// Mint a TTL-backed lease for a polling request inbox. Unlike an event
    /// stream lease there is no server-side guard to own, so the client
    /// heartbeats while attached and explicitly releases on a clean exit.
    pub fn mint_polling_approval_surface(&self) -> Uuid {
        let id = Uuid::new_v4();
        self.insert_approval_surface(id, APPROVAL_SURFACE_TTL);
        id
    }

    fn lease_approval_surface_for(
        self: &Arc<Self>,
        ttl: std::time::Duration,
    ) -> ApprovalSurfaceLease {
        let id = Uuid::new_v4();
        self.insert_approval_surface(id, ttl);
        ApprovalSurfaceLease {
            bus: self.clone(),
            id,
        }
    }

    fn expiry_after(ttl: std::time::Duration) -> ApprovalSurfaceExpiry {
        let wall_ttl =
            chrono::Duration::from_std(ttl).unwrap_or_else(|_| chrono::Duration::seconds(15));
        ApprovalSurfaceExpiry {
            monotonic: std::time::Instant::now() + ttl,
            wall: chrono::Utc::now() + wall_ttl,
        }
    }

    fn insert_approval_surface(&self, id: Uuid, ttl: std::time::Duration) {
        let monotonic_now = std::time::Instant::now();
        let wall_now = chrono::Utc::now();
        let mut surfaces = self.approval_surfaces.lock().unwrap();
        // Polling clients can disappear without sending DELETE. Expired
        // leases carry no capability and need not accumulate forever.
        surfaces.retain(|_, expiry| expiry.monotonic > monotonic_now && expiry.wall > wall_now);
        surfaces.insert(id, Self::expiry_after(ttl));
    }

    /// Renew an attached request surface after a client-originated
    /// heartbeat. A guessed or stale id cannot create capability by itself.
    pub fn renew_approval_surface(&self, id: &Uuid) -> bool {
        let mut surfaces = self.approval_surfaces.lock().unwrap();
        let Some(expiry) = surfaces.get_mut(id) else {
            return false;
        };
        *expiry = Self::expiry_after(APPROVAL_SURFACE_TTL);
        true
    }

    /// Release a polling lease explicitly, or the event-stream guard on Drop.
    pub fn release_approval_surface(&self, id: &Uuid) -> bool {
        self.approval_surfaces.lock().unwrap().remove(id).is_some()
    }

    /// Whether a currently leased management client can receive and display
    /// a prompt. Both clocks must still be live: wall time closes the gap on
    /// systems whose monotonic clock pauses during suspend.
    pub fn has_approval_surface(&self) -> bool {
        let monotonic_now = std::time::Instant::now();
        let wall_now = chrono::Utc::now();
        self.approval_surfaces
            .lock()
            .unwrap()
            .values()
            .any(|expiry| expiry.monotonic > monotonic_now && expiry.wall > wall_now)
    }

    /// Whether anything at all is reading the event stream. Only meaningful
    /// as a diagnostic: an attached client that holds no surface lease is
    /// either a passive observer or a shell too old to negotiate one, and
    /// telling those apart in a log beats a mystery refusal.
    pub fn has_event_observers(&self) -> bool {
        self.tx.receiver_count() > 0
    }

    /// Decide what to send a (re)connecting client. `last` is the parsed
    /// `Last-Event-ID` (`epoch`, `seq`); `None` (fresh client, or a header
    /// from another broker process) means resync.
    pub fn replay_since(&self, last: Option<(&str, u64)>) -> ManageReplay {
        let Some((epoch, last_seq)) = last else {
            return ManageReplay::Resync;
        };
        if epoch != self.epoch {
            // A different broker process (restart): the client's seq refers
            // to a history this process never had.
            return ManageReplay::Resync;
        }
        let ring = self.ring.lock().unwrap();
        let head = ring.back().map(|e| e.seq).unwrap_or(0);
        if last_seq >= head {
            return ManageReplay::UpToDate;
        }
        // Replayable only if the first event we'd need (last_seq + 1) is
        // still retained; otherwise events were evicted and we must resync.
        match ring.front().map(|e| e.seq) {
            Some(oldest) if last_seq + 1 >= oldest => {
                ManageReplay::Replay(ring.iter().filter(|e| e.seq > last_seq).cloned().collect())
            }
            _ => ManageReplay::Resync,
        }
    }
}

/// Parse an SSE `Last-Event-ID` of the form `epoch:seq`.
pub fn parse_event_id(id: &str) -> Option<(&str, u64)> {
    let (epoch, seq) = id.split_once(':')?;
    Some((epoch, seq.parse().ok()?))
}

/* ----------------------------- event fanout ------------------------------- */

/// Wraps a shell's `BrokerEvents` observer so every state-change
/// notification also lands on the broker's manage-event bus (the SSE stream
/// remote shells subscribe to). The browser hook delegates untouched.
pub struct FanoutEvents {
    inner: Arc<dyn crate::events::BrokerEvents>,
    bus: Arc<ManageBus>,
}

impl FanoutEvents {
    pub fn new(inner: Arc<dyn crate::events::BrokerEvents>, bus: Arc<ManageBus>) -> Self {
        Self { inner, bus }
    }
}

impl crate::events::BrokerEvents for FanoutEvents {
    fn has_approval_surface(&self) -> bool {
        self.inner.has_approval_surface() || self.bus.has_approval_surface()
    }

    fn sessions_changed(&self) {
        self.inner.sessions_changed();
        self.bus.emit(aka_api::ManageEvent::SessionsChanged);
    }

    fn agents_changed(&self) {
        self.inner.agents_changed();
        self.bus.emit(aka_api::ManageEvent::AgentsChanged);
    }

    fn wirings_changed(&self) {
        self.inner.wirings_changed();
        self.bus.emit(aka_api::ManageEvent::WiringsChanged);
    }

    fn connections_changed(&self) {
        self.inner.connections_changed();
        self.bus.emit(aka_api::ManageEvent::ConnectionsChanged);
    }

    fn secrets_changed(&self) {
        self.inner.secrets_changed();
        self.bus.emit(aka_api::ManageEvent::SecretsChanged);
    }

    fn integrations_changed(&self) {
        self.inner.integrations_changed();
        self.bus.emit(aka_api::ManageEvent::IntegrationsChanged);
    }

    fn audit_appended(&self, entry: &AuditEntry) {
        self.inner.audit_appended(entry);
        self.bus.emit(aka_api::ManageEvent::ActivityAppended {
            entry: activity_dto(entry),
        });
    }

    fn mcp_auth_changed(&self, state: &crate::mcp_auth::McpAuthState) {
        self.inner.mcp_auth_changed(state);
        if let Ok(value) = serde_json::to_value(state) {
            self.bus
                .emit(aka_api::ManageEvent::McpAuthChanged { state: value });
        }
    }

    fn connect_requested(&self, agent: &str, service: &str) {
        self.inner.connect_requested(agent, service);
        self.bus.emit(aka_api::ManageEvent::ConnectRequested {
            agent: agent.to_string(),
            service: service.to_string(),
        });
    }

    fn open_external_url(&self, url: &str) -> bool {
        self.inner.open_external_url(url)
    }

    fn approval_requested(
        &self,
        pending: &crate::approvals::PendingApproval,
    ) -> crate::events::ApprovalHandling {
        // Only a management stream that explicitly leased the request-inbox
        // capability can answer. Passive SSE observers still receive the
        // event, but cannot make traffic wait for a UI they do not have.
        let remote_surface = self.bus.has_approval_surface();
        self.bus.emit(aka_api::ManageEvent::ApprovalsChanged);
        match self.inner.approval_requested(pending) {
            crate::events::ApprovalHandling::Unavailable if remote_surface => {
                crate::events::ApprovalHandling::Taken
            }
            crate::events::ApprovalHandling::Unavailable => {
                if self.bus.has_event_observers() {
                    // Something is attached but holds no request-inbox lease:
                    // a passive observer, or a desktop app predating surface
                    // negotiation. Either way the refusal is not "nothing is
                    // attached", and saying so saves the operator a hunt.
                    tracing::warn!(
                        connection = %pending.connection,
                        "confirmed traffic has no decision surface: a management client is attached but holds no \
                         request-inbox lease (a passive observer, or an app too old to negotiate \
                         one — update it)"
                    );
                }
                crate::events::ApprovalHandling::Unavailable
            }
            handling => handling,
        }
    }

    fn approval_updated(&self, pending: &crate::approvals::PendingApproval) {
        self.inner.approval_updated(pending);
        self.bus.emit(aka_api::ManageEvent::ApprovalsChanged);
    }

    fn approval_resolved(&self, id: &Uuid, resolution: crate::request_history::RequestResolution) {
        self.inner.approval_resolved(id, resolution);
        if resolution == crate::request_history::RequestResolution::TimedOut {
            self.bus
                .emit(aka_api::ManageEvent::ApprovalExpired { id: id.to_string() });
        }
        self.bus.emit(aka_api::ManageEvent::ApprovalsChanged);
    }

    fn elicitation_requested(
        &self,
        pending: &crate::elicitations::PendingElicitation,
    ) -> crate::events::ElicitationHandling {
        // Same lease gate as approvals: a passive SSE observer still gets the
        // event, but only a stream that leased the request-inbox capability
        // can make an upstream call wait for a form it can render.
        let remote_surface = self.bus.has_approval_surface();
        self.bus.emit(aka_api::ManageEvent::ElicitationsChanged);
        match self.inner.elicitation_requested(pending) {
            crate::events::ElicitationHandling::Unavailable if remote_surface => {
                crate::events::ElicitationHandling::Taken
            }
            handling => handling,
        }
    }

    fn elicitation_resolved(&self, id: &Uuid) {
        self.inner.elicitation_resolved(id);
        self.bus.emit(aka_api::ManageEvent::ElicitationsChanged);
    }
}

/* ---------------------------- request bodies ------------------------------ */

/// `POST /v1/manage/secrets`. The value (and any TOTP seed) crosses as
/// plaintext inside the (Unix-socket or tunneled) manage transport, exactly
/// like the app's own IPC; both are wrapped zeroizing immediately after
/// parse. Pre-typing clients send only `name` + `value` and get a plain
/// secret, which is also what a typed body defaults to.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct SecretAddBody {
    /// Required for secrets. Ignored for passwords, whose name derives
    /// from site + username broker-side.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub value: String,
    #[serde(default)]
    pub kind: SecretKindDto,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub site: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// A raw 2FA seed (Base32 or otpauth:// URI), validated broker-side.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp: Option<String>,
}

impl SecretAddBody {
    /// The classic named-secret body, for callers that predate typing.
    pub fn plain(name: String, value: String) -> Self {
        Self {
            name: Some(name),
            value,
            kind: SecretKindDto::Secret,
            site: None,
            username: None,
            totp: None,
        }
    }

    /// The broker-side spec: wire strings become zeroizing values here, at
    /// the first parse boundary.
    pub fn into_spec(self) -> CredentialAddSpec {
        CredentialAddSpec {
            kind: match self.kind {
                SecretKindDto::Secret => SecretKind::Secret,
                SecretKindDto::Password => SecretKind::Password,
            },
            name: self.name,
            site: self.site,
            username: self.username,
            value: zeroize::Zeroizing::new(self.value),
            totp: self.totp.map(zeroize::Zeroizing::new),
        }
    }
}

/// What `Broker::ui_add_credential` validates and stores.
pub struct CredentialAddSpec {
    pub kind: SecretKind,
    pub name: Option<String>,
    pub site: Option<String>,
    pub username: Option<String>,
    pub value: SecretValue,
    /// Raw seed input; parsed and canonicalized by the broker.
    pub totp: Option<SecretValue>,
}

/// `PATCH /v1/manage/secrets/{id}`. Absent fields stay unchanged; an empty
/// `new_username` or `new_totp` clears that field (passwords only).
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct SecretEditBody {
    #[serde(default)]
    pub new_name: Option<String>,
    #[serde(default)]
    pub new_value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_site: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_totp: Option<String>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct OnePasswordIntegrationAddBody {
    pub label: String,
    #[serde(flatten)]
    pub authentication: OnePasswordAuthenticationBody,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum OnePasswordAuthenticationBody {
    DesktopApp { account: String },
    ServiceAccount { token: String },
    Connect { base_url: String, token: String },
}

impl OnePasswordAuthenticationBody {
    pub fn into_parts(
        self,
    ) -> (
        crate::onepassword::OnePasswordAuth,
        Option<crate::types::SecretValue>,
    ) {
        match self {
            Self::DesktopApp { account } => (
                crate::onepassword::OnePasswordAuth::DesktopApp { account },
                None,
            ),
            Self::ServiceAccount { token } => (
                crate::onepassword::OnePasswordAuth::ServiceAccount,
                Some(zeroize::Zeroizing::new(token)),
            ),
            Self::Connect { base_url, token } => (
                crate::onepassword::OnePasswordAuth::Connect { base_url },
                Some(zeroize::Zeroizing::new(token)),
            ),
        }
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct OnePasswordTokenBody {
    pub token: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct OnePasswordSecretAddBody {
    pub name: String,
    pub integration_id: Uuid,
    pub vault_id: String,
    pub vault_label: String,
    pub item_id: String,
    pub item_label: String,
    #[serde(default)]
    pub section_id: Option<String>,
    #[serde(default)]
    pub section_label: Option<String>,
    pub field_id: String,
    pub field_label: String,
    #[serde(default)]
    pub field_type: Option<String>,
}

impl OnePasswordSecretAddBody {
    pub fn into_reference(self) -> (String, crate::onepassword::OnePasswordSecretRef) {
        let reference = crate::onepassword::OnePasswordSecretRef {
            integration_id: self.integration_id,
            vault_id: self.vault_id,
            vault_label: self.vault_label,
            item_id: self.item_id,
            item_label: self.item_label,
            section_id: self.section_id,
            section_label: self.section_label,
            field_id: self.field_id,
            field_label: self.field_label,
            field_type: self.field_type,
        };
        (self.name, reference)
    }
}

/// `POST /v1/manage/connections`: the spec plus, for connection-first
/// setup, the new credential stored atomically with it.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct ConnectionAddBody {
    pub spec: ConnectionSpec,
    #[serde(default)]
    pub new_secret: Option<SecretAddBody>,
}

/// `PUT /v1/manage/connections/{id}`.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct ConnectionUpdateBody {
    /// Version returned by the GET that supplied `spec`. This is deliberately
    /// required: older clients must fail closed instead of overwriting a
    /// connection they cannot prove is still current.
    pub expected_updated_at: String,
    pub spec: ConnectionSpec,
}

/// `PATCH /v1/manage/connections/{id}`. Rename is deliberately separate from
/// full replacement so a client never has to reconstruct capability fields it
/// does not intend to edit.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct ConnectionRenameBody {
    /// Version returned by the GET that supplied the connection name.
    pub expected_updated_at: String,
    pub name: String,
}

/// Capability-field changes for `PATCH /v1/manage/connections/{id}/config`.
///
/// The broker applies these fields to its authoritative connection under an
/// optimistic version check. Management clients therefore never reconstruct
/// a complete `ConnectionConfig` merely to change one field.
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct ConnectionConfigPatch {
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub scheme: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub template: Option<String>,
    #[serde(default)]
    pub dbname: Option<String>,
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub sslmode: Option<PgSslMode>,
    #[serde(default)]
    pub trusted_ca_bundle_path: Option<String>,
    #[serde(default)]
    pub clear_trusted_ca_bundle: bool,
    #[serde(default)]
    pub host_key_fingerprint: Option<String>,
    /// The path the Test button probes on an API connection. Absence
    /// preserves the current one.
    #[serde(default)]
    pub test_path: Option<String>,
    #[serde(default)]
    pub clear_test_path: bool,
    /// Rebind the one credential used by Postgres or SSH. Absence preserves
    /// the current binding.
    #[serde(default)]
    pub secret_id: Option<Uuid>,
}

/// `PATCH /v1/manage/connections/{id}/config`.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct ConnectionConfigPatchBody {
    pub expected_updated_at: String,
    pub patch: ConnectionConfigPatch,
}

fn invalid_patch(field: &str, kind: &str) -> ManageError {
    ManageError::InvalidConnectionConfig {
        message: format!("{field} does not apply to a {kind} connection"),
    }
}

fn patched_connection_spec(
    connection: &Connection,
    patch: ConnectionConfigPatch,
) -> ManageResult<ConnectionSpec> {
    if patch.clear_trusted_ca_bundle && patch.trusted_ca_bundle_path.is_some() {
        return Err(ManageError::InvalidConnectionConfig {
            message: "cannot set and clear the CA bundle in one update".into(),
        });
    }
    if patch.clear_test_path && patch.test_path.is_some() {
        return Err(ManageError::InvalidConnectionConfig {
            message: "cannot set and clear the test path in one update".into(),
        });
    }
    let ca_bundle = |current: &Option<String>| {
        if patch.clear_trusted_ca_bundle {
            None
        } else {
            patch
                .trusted_ca_bundle_path
                .clone()
                .or_else(|| current.clone())
        }
    };
    let config = match &connection.config {
        ConnectionConfig::Api {
            host,
            scheme,
            port,
            trusted_ca_bundle_path,
            template,
            mcp_path,
            test_path,
            oauth,
            signer,
            client_cert_path,
            client_key_path,
        } => {
            for (field, present) in [
                ("dbname", patch.dbname.is_some()),
                ("user", patch.user.is_some()),
                ("sslmode", patch.sslmode.is_some()),
                ("host_key_fingerprint", patch.host_key_fingerprint.is_some()),
                ("secret_id", patch.secret_id.is_some()),
            ] {
                if present {
                    return Err(invalid_patch(field, "API"));
                }
            }
            // A signer connection's template is fixed empty; a template
            // patch against it would silently create the combination the
            // store refuses.
            if signer.is_some()
                && patch
                    .template
                    .as_deref()
                    .is_some_and(|t| !t.trim().is_empty())
            {
                return Err(ManageError::InvalidConnectionConfig {
                    message: "this connection signs requests; it has no injection template".into(),
                });
            }
            ConnectionConfig::Api {
                host: patch.host.unwrap_or_else(|| host.clone()),
                scheme: patch.scheme.unwrap_or_else(|| scheme.clone()),
                port: patch.port.or(*port),
                trusted_ca_bundle_path: ca_bundle(trusted_ca_bundle_path),
                template: patch.template.unwrap_or_else(|| template.clone()),
                mcp_path: mcp_path.clone(),
                test_path: if patch.clear_test_path {
                    None
                } else {
                    patch.test_path.clone().or_else(|| test_path.clone())
                },
                oauth: oauth.clone(),
                signer: signer.clone(),
                client_cert_path: client_cert_path.clone(),
                client_key_path: client_key_path.clone(),
            }
        }
        ConnectionConfig::Pg {
            host,
            port,
            dbname,
            user,
            sslmode,
            trusted_ca_bundle_path,
        } => {
            for (field, present) in [
                ("scheme", patch.scheme.is_some()),
                ("template", patch.template.is_some()),
                ("host_key_fingerprint", patch.host_key_fingerprint.is_some()),
                (
                    "test_path",
                    patch.test_path.is_some() || patch.clear_test_path,
                ),
            ] {
                if present {
                    return Err(invalid_patch(field, "Postgres"));
                }
            }
            ConnectionConfig::Pg {
                host: patch.host.unwrap_or_else(|| host.clone()),
                port: patch.port.unwrap_or(*port),
                dbname: patch.dbname.unwrap_or_else(|| dbname.clone()),
                user: patch.user.unwrap_or_else(|| user.clone()),
                sslmode: patch.sslmode.unwrap_or(*sslmode),
                trusted_ca_bundle_path: ca_bundle(trusted_ca_bundle_path),
            }
        }
        ConnectionConfig::Ssh {
            destination,
            host,
            port,
            user,
            host_key_fingerprint,
        } => {
            for (field, present) in [
                ("scheme", patch.scheme.is_some()),
                ("template", patch.template.is_some()),
                ("dbname", patch.dbname.is_some()),
                ("sslmode", patch.sslmode.is_some()),
                (
                    "trusted_ca_bundle_path",
                    patch.trusted_ca_bundle_path.is_some() || patch.clear_trusted_ca_bundle,
                ),
                (
                    "test_path",
                    patch.test_path.is_some() || patch.clear_test_path,
                ),
            ] {
                if present {
                    return Err(invalid_patch(field, "SSH"));
                }
            }
            ConnectionConfig::Ssh {
                destination: destination.clone(),
                host: patch.host.unwrap_or_else(|| host.clone()),
                port: patch.port.unwrap_or(*port),
                user: patch.user.unwrap_or_else(|| user.clone()),
                host_key_fingerprint: patch
                    .host_key_fingerprint
                    .unwrap_or_else(|| host_key_fingerprint.clone()),
            }
        }
    };
    let secrets = patch
        .secret_id
        .map(|id| vec![id])
        .unwrap_or_else(|| connection.secrets.clone());
    Ok(ConnectionSpec {
        name: connection.name.clone(),
        config,
        secrets,
    })
}

/// `POST /v1/manage/connections/reorder`: the full desired front-to-back
/// order of connection ids.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct ConnectionsReorderBody {
    pub ordered_ids: Vec<Uuid>,
}

/// `POST /v1/manage/connections/test-draft`.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct DraftTestBody {
    pub spec: ConnectionSpec,
    #[serde(default)]
    pub typed_secret: Option<String>,
}

/// `POST /v1/manage/connections/{id}/access`.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct AccessBody {
    pub enabled: bool,
}

/// `POST /v1/manage/connections/{id}/confirm`: ask (or stop asking) the
/// user to confirm this connection's traffic.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct ConfirmBody {
    pub on: bool,
}

/// `POST /v1/manage/connections/{id}/response-credentials`: explicitly
/// expose or contain credential-bearing upstream response headers.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct ResponseCredentialsBody {
    pub expose: bool,
}

/// `POST /v1/manage/approvals/{id}`: answer a waiting prompt.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct ApprovalResponseBody {
    pub decision: ApprovalDecisionDto,
}

/// `POST /v1/manage/elicitations/{id}`: answer a waiting elicitation.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct ElicitationResponseBody {
    /// True to accept with `values`; false declines.
    pub approved: bool,
    /// The user's field answers (name → value). Empty on decline.
    #[serde(default)]
    pub values: std::collections::HashMap<String, String>,
}

/// `POST /v1/manage/connections/{id}/allowed-tools`. `tools: null` restores
/// the default (all tools).
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct AllowedToolsBody {
    #[serde(default)]
    pub tools: Option<Vec<String>>,
}

/// `POST /v1/manage/connections/{id}/endpoint/require-auth`.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct EndpointRequireAuthBody {
    pub require_auth: bool,
}

/// `POST /v1/manage/connections/{id}/endpoint/expiry`.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct EndpointExpiryBody {
    pub expire: bool,
}

/// `POST /v1/manage/connections/{id}/audit-statements`. `audit_statements:
/// null` restores the broker-wide default.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct AuditStatementsBody {
    #[serde(default)]
    pub audit_statements: Option<bool>,
}

/// `POST /v1/manage/oauth/start`: begin a relayed BYO-app OAuth connect.
/// The redirect URI is the shell's own loopback catcher.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct OAuthStartBody {
    pub secret_name: String,
    #[serde(default)]
    pub client_secret: Option<String>,
    pub spec: ConnectionSpec,
    pub redirect_uri: String,
}

/// `POST /v1/manage/oauth/reconnect/{connection_id}`.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct OAuthReconnectBody {
    pub redirect_uri: String,
}

/// `POST /v1/manage/oauth/complete/{flow_id}`: the browser came back.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct OAuthCompleteBody {
    pub code: String,
    pub state: String,
}

/// `POST /v1/manage/mcp-auth`: begin a relayed MCP sign-in. The redirect
/// URI is the shell's own loopback catcher.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct McpAuthStartBody {
    pub draft: crate::mcp_auth::McpAuthDraft,
    pub redirect_uri: String,
}

/// `POST /v1/manage/mcp-auth/{id}/deliver`: the browser came back.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct McpAuthDeliverBody {
    pub code: String,
    pub state: String,
    /// RFC 9207 issuer from the redirect, when the catcher forwarded it.
    /// Optional so an older shell that omits it still deserializes.
    #[serde(default)]
    pub iss: Option<String>,
}

/// `PATCH /v1/manage/settings`: partial update, absent fields unchanged.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct SettingsPatchBody {
    #[serde(default)]
    pub menu_bar_hides_dock: Option<bool>,
    #[serde(default)]
    pub confirm_ssh_host_keys: Option<bool>,
}

/* -------------------------------- backend --------------------------------- */

/// Which broker the shell is managing. The webview uses this to label the
/// header switcher and gate remote-incapable features.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum BackendProfile {
    /// The broker runs inside this app on this machine.
    Local,
    /// The broker is managed over its manage API.
    Remote { url: String },
}

/// Everything the desktop shell may do to a broker. One implementation wraps
/// the in-process broker; the other speaks HTTP to a hosted one. Methods
/// mirror the `ui_*` surface one-to-one so the command layer stays a thin
/// argument-parsing shell.
#[async_trait]
pub trait ManagementBackend: Send + Sync {
    fn profile(&self) -> BackendProfile;

    /* secrets */
    async fn list_secrets(&self) -> ManageResult<Vec<SecretDto>>;
    async fn add_credential(&self, body: SecretAddBody) -> ManageResult<()>;
    /// The classic named-secret add, for callers that predate typing.
    async fn add_secret(&self, name: String, value: SecretValue) -> ManageResult<()> {
        self.add_credential(SecretAddBody::plain(name, value.to_string()))
            .await
    }
    async fn edit_secret(&self, id: Uuid, body: SecretEditBody) -> ManageResult<()>;
    async fn delete_secret(&self, id: Uuid) -> ManageResult<()>;
    async fn reveal_secret(&self, id: Uuid) -> ManageResult<SecretValue>;
    async fn secret_value_for_copy(&self, id: Uuid) -> ManageResult<SecretValue>;
    async fn note_secret_copied(&self, id: Uuid) -> ManageResult<()>;
    /// The current 2FA code for a password with a TOTP factor.
    async fn secret_totp_code(&self, id: Uuid) -> ManageResult<TotpCodeDto>;

    /* 1Password integrations */
    async fn list_onepassword_integrations(&self) -> ManageResult<Vec<OnePasswordIntegrationDto>>;
    async fn add_onepassword_integration(
        &self,
        label: String,
        auth: crate::onepassword::OnePasswordAuth,
        token: Option<SecretValue>,
    ) -> ManageResult<OnePasswordIntegrationDto>;
    async fn replace_onepassword_token(
        &self,
        id: Uuid,
        token: SecretValue,
    ) -> ManageResult<OnePasswordIntegrationDto>;
    async fn delete_onepassword_integration(&self, id: Uuid) -> ManageResult<()>;
    async fn onepassword_health(&self, id: Uuid) -> ManageResult<OnePasswordHealthDto>;
    async fn onepassword_vaults(&self, id: Uuid) -> ManageResult<Vec<OnePasswordVaultDto>>;
    async fn onepassword_items(
        &self,
        id: Uuid,
        vault_id: String,
    ) -> ManageResult<Vec<OnePasswordItemDto>>;
    async fn onepassword_fields(
        &self,
        id: Uuid,
        vault_id: String,
        item_id: String,
    ) -> ManageResult<Vec<OnePasswordFieldDto>>;
    async fn add_onepassword_secret(
        &self,
        name: String,
        reference: crate::onepassword::OnePasswordSecretRef,
    ) -> ManageResult<SecretDto>;

    /* connections */
    async fn list_connections(&self) -> ManageResult<Vec<ConnectionDto>>;
    async fn add_connection(&self, spec: ConnectionSpec) -> ManageResult<()>;
    async fn add_connection_with_secret(
        &self,
        secret_name: String,
        value: SecretValue,
        spec: ConnectionSpec,
    ) -> ManageResult<()>;
    async fn update_connection(
        &self,
        id: Uuid,
        expected_updated_at: String,
        spec: ConnectionSpec,
    ) -> ManageResult<()>;
    async fn rename_connection(
        &self,
        id: Uuid,
        expected_updated_at: String,
        name: String,
    ) -> ManageResult<()>;
    async fn patch_connection(
        &self,
        id: Uuid,
        expected_updated_at: String,
        patch: ConnectionConfigPatch,
    ) -> ManageResult<()>;
    async fn delete_connection(&self, id: Uuid) -> ManageResult<()>;
    /// Persist a user-chosen order for the Tools list. `ordered_ids` is the
    /// full desired front-to-back order.
    async fn reorder_connections(&self, ordered_ids: Vec<Uuid>) -> ManageResult<()>;
    async fn test_connection(&self, id: Uuid) -> ManageResult<ConnectionTestReport>;
    async fn test_connection_draft(
        &self,
        spec: ConnectionSpec,
        typed_secret: Option<SecretValue>,
    ) -> ManageResult<ConnectionTestReport>;

    /* MCP */
    async fn start_mcp_auth(
        &self,
        draft: crate::mcp_auth::McpAuthDraft,
    ) -> ManageResult<crate::mcp_auth::McpAuthState>;
    async fn get_mcp_auth(&self, id: Uuid) -> ManageResult<Option<crate::mcp_auth::McpAuthState>>;
    async fn cancel_mcp_auth(&self, id: Uuid) -> ManageResult<bool>;
    async fn mcp_status(
        &self,
        id: Uuid,
        options: crate::mcp::McpCheckOptions,
    ) -> ManageResult<crate::mcp::McpStatusReport>;
    async fn list_mcp_tools(&self, id: Uuid) -> ManageResult<crate::mcp::McpToolCatalog>;

    /* OAuth (BYO app) */
    async fn oauth_connect(
        &self,
        secret_name: String,
        client_secret: Option<SecretValue>,
        spec: ConnectionSpec,
    ) -> ManageResult<()>;
    async fn oauth_reconnect(&self, id: Uuid) -> ManageResult<()>;

    /* agent access + endpoints */
    async fn set_tool_access(&self, connection_id: Uuid, enabled: bool) -> ManageResult<bool>;
    /// Ask the user to confirm this connection's traffic, or stop asking.
    /// Turning it off weakens a gate and takes its own authentication.
    async fn set_confirm_mode(&self, connection_id: Uuid, on: bool) -> ManageResult<bool>;
    async fn set_expose_response_credentials(
        &self,
        connection_id: Uuid,
        expose: bool,
    ) -> ManageResult<bool>;
    async fn set_allowed_tools(
        &self,
        connection_id: Uuid,
        tools: Option<Vec<String>>,
    ) -> ManageResult<bool>;
    /// Record this Postgres connection's statement text, or stop; `None`
    /// restores the broker-wide `--audit-pg-statements` default.
    async fn set_audit_statements(
        &self,
        connection_id: Uuid,
        audit_statements: Option<bool>,
    ) -> ManageResult<bool>;
    /// Require the `authenticate@multitool.dev` extension on this connection's
    /// SSH endpoint socket, or stop requiring it.
    async fn set_endpoint_require_auth(
        &self,
        connection_id: Uuid,
        require_auth: bool,
    ) -> ManageResult<bool>;
    async fn issue_endpoint(&self, connection_id: Uuid) -> ManageResult<IssuedEndpointDto>;
    /// Extend an existing endpoint without changing the address or secret.
    /// `POST /v1/manage/connections/{id}/endpoint/renew`.
    async fn renew_endpoint(&self, connection_id: Uuid) -> ManageResult<IssuedEndpointDto>;
    /// Opt the connection's endpoint into (or out of) expiry: on starts a
    /// fresh lifetime window, off removes the deadline.
    /// `POST /v1/manage/connections/{id}/endpoint/expiry`.
    async fn set_endpoint_expiry(
        &self,
        connection_id: Uuid,
        expire: bool,
    ) -> ManageResult<IssuedEndpointDto>;
    /// Read the connection's already-issued direct endpoint without minting or
    /// rotating; `None` when none is issued. Ungated display read — it takes no
    /// native gate and writes no audit entry. `GET
    /// /v1/manage/connections/{id}/endpoint`.
    async fn get_endpoint(&self, connection_id: Uuid) -> ManageResult<Option<IssuedEndpointDto>>;
    /// Read the endpoint for an explicit copy-to-clipboard: same address, but
    /// takes the native gate and writes a "Direct endpoint copied" audit entry.
    /// `POST /v1/manage/connections/{id}/endpoint/copy`.
    async fn copy_endpoint(&self, connection_id: Uuid) -> ManageResult<Option<IssuedEndpointDto>>;
    async fn revoke_endpoint(&self, endpoint_id: Uuid) -> ManageResult<bool>;

    /* identity */
    async fn identity(&self) -> ManageResult<IdentityDto>;
    /// The shared agent key's plaintext, for the shell-side clipboard copy.
    /// It must never enter the webview.
    async fn agent_key(&self) -> ManageResult<String>;
    async fn rotate_key(&self) -> ManageResult<()>;

    /* traffic confirmation */
    /// Prompts waiting on the user, oldest first.
    async fn approvals(&self) -> ManageResult<Vec<ApprovalDto>>;
    /// Requests that entered a decision flow, including terminal history.
    async fn requests(&self) -> ManageResult<Vec<RequestDto>>;
    /// Answer one. `false` means it was already answered, revoked, or has
    /// lapsed. `ApproveAll` turns the connection's switch off first, so a
    /// refused authentication leaves the traffic parked.
    async fn respond_approval(&self, id: Uuid, decision: ApprovalDecisionDto)
        -> ManageResult<bool>;

    /* upstream elicitation */
    /// Upstream tool calls parked on the user for input, oldest first.
    async fn elicitations(&self) -> ManageResult<Vec<ElicitationDto>>;
    /// Answer one. `approved` with `values` accepts; otherwise it declines.
    /// `false` means it was already answered, cancelled, or has lapsed.
    async fn respond_elicitation(
        &self,
        id: Uuid,
        approved: bool,
        values: std::collections::HashMap<String, String>,
    ) -> ManageResult<bool>;

    /* sessions + activity */
    async fn sessions(&self) -> ManageResult<Vec<SessionDto>>;
    async fn close_session(&self, id: u64) -> ManageResult<bool>;
    /// Newest-first activity tail; `0` requests the full retained log.
    async fn activity(&self, limit: usize) -> ManageResult<Vec<ActivityDto>>;
    /// Stable newest-first page; `before` is the opaque cursor returned by
    /// the preceding page.
    async fn activity_page(
        &self,
        limit: usize,
        before: Option<u64>,
    ) -> ManageResult<aka_api::ActivityPageDto>;
    async fn clear_activity(&self) -> ManageResult<()>;

    /* settings */
    async fn settings(&self) -> ManageResult<SettingsDto>;
    async fn set_menu_bar_hides_dock(&self, on: bool) -> ManageResult<()>;
    /// Ask before trusting a first-seen SSH host key.
    async fn set_confirm_ssh_host_keys(&self, on: bool) -> ManageResult<()>;

    /* discovery */
    async fn agent_setup(&self) -> ManageResult<String>;
}

/// The in-process backend: the broker lives in this process.
pub struct LocalBackend {
    broker: Arc<Broker>,
}

impl LocalBackend {
    pub fn new(broker: Arc<Broker>) -> Self {
        Self { broker }
    }

    /// Run a synchronous `ui_*` call on a blocking thread. Mutating entry
    /// points can demand the shell's native confirmation sheet, which blocks
    /// until the user answers — never on the async runtime.
    async fn blocking<T, F>(&self, call: F) -> ManageResult<T>
    where
        T: Send + 'static,
        F: FnOnce(Arc<Broker>) -> crate::Result<T> + Send + 'static,
    {
        let broker = self.broker.clone();
        let context = crate::audit::current_decision_context();
        tokio::task::spawn_blocking(move || {
            crate::audit::with_blocking_decision_context(context, || call(broker))
        })
        .await
        .map_err(|join| ManageError::Internal {
            message: format!("management call stopped: {join}"),
        })?
        .map_err(ManageError::from)
    }
}

#[async_trait]
impl ManagementBackend for LocalBackend {
    fn profile(&self) -> BackendProfile {
        BackendProfile::Local
    }

    async fn list_secrets(&self) -> ManageResult<Vec<SecretDto>> {
        let broker = &self.broker;
        Ok(broker
            .store
            .list_secrets()
            .iter()
            .map(|meta| secret_dto(broker, meta))
            .collect())
    }

    async fn add_credential(&self, body: SecretAddBody) -> ManageResult<()> {
        self.blocking(move |broker| broker.ui_add_credential(body.into_spec()).map(|_| ()))
            .await
    }

    async fn edit_secret(&self, id: Uuid, body: SecretEditBody) -> ManageResult<()> {
        self.blocking(move |broker| {
            let value = body
                .new_value
                .filter(|value| !value.is_empty())
                .map(zeroize::Zeroizing::new);
            broker
                .ui_edit_credential(
                    &id,
                    body.new_name.as_deref(),
                    value,
                    body.new_site,
                    body.new_username,
                    body.new_totp,
                )
                .map(|_| ())
        })
        .await
    }

    async fn delete_secret(&self, id: Uuid) -> ManageResult<()> {
        self.blocking(move |broker| broker.ui_delete_secret(&id).map(|_| ()))
            .await
    }

    async fn reveal_secret(&self, id: Uuid) -> ManageResult<SecretValue> {
        Ok(self.broker.ui_reveal_secret_value(&id).await?)
    }

    async fn secret_value_for_copy(&self, id: Uuid) -> ManageResult<SecretValue> {
        Ok(self.broker.ui_managed_secret_value_for_copy(&id).await?)
    }

    async fn note_secret_copied(&self, id: Uuid) -> ManageResult<()> {
        Ok(self.broker.ui_note_secret_copied(&id)?)
    }

    async fn secret_totp_code(&self, id: Uuid) -> ManageResult<TotpCodeDto> {
        let (code, seconds_remaining) = self.broker.ui_secret_totp_code(&id).await?;
        Ok(TotpCodeDto {
            code,
            seconds_remaining,
        })
    }

    async fn list_onepassword_integrations(&self) -> ManageResult<Vec<OnePasswordIntegrationDto>> {
        Ok(self
            .broker
            .store
            .list_onepassword_integrations()
            .iter()
            .map(crate::onepassword::OnePasswordIntegration::dto)
            .collect())
    }

    async fn add_onepassword_integration(
        &self,
        label: String,
        auth: crate::onepassword::OnePasswordAuth,
        token: Option<SecretValue>,
    ) -> ManageResult<OnePasswordIntegrationDto> {
        let id = Uuid::new_v4();
        self.broker
            .store
            .validate_new_onepassword_integration(
                id,
                &label,
                &auth,
                token.as_ref().map(|token| token.as_str()),
            )
            .await
            .map_err(ManageError::from)?;
        let result = self
            .blocking(move |broker| {
                broker
                    .ui_add_onepassword_integration(id, &label, auth, token)
                    .map(|integration| integration.dto())
            })
            .await;
        if result.is_err() {
            self.broker.store.invalidate_onepassword_integration(&id);
        }
        result
    }

    async fn replace_onepassword_token(
        &self,
        id: Uuid,
        token: SecretValue,
    ) -> ManageResult<OnePasswordIntegrationDto> {
        self.broker
            .store
            .validate_onepassword_replacement_token(&id, token.as_str())
            .await
            .map_err(ManageError::from)?;
        self.blocking(move |broker| {
            broker
                .ui_replace_onepassword_token(&id, token)
                .map(|integration| integration.dto())
        })
        .await
    }

    async fn delete_onepassword_integration(&self, id: Uuid) -> ManageResult<()> {
        self.blocking(move |broker| broker.ui_delete_onepassword_integration(&id).map(|_| ()))
            .await
    }

    async fn onepassword_health(&self, id: Uuid) -> ManageResult<OnePasswordHealthDto> {
        Ok(self.broker.onepassword_health(&id).await?)
    }

    async fn onepassword_vaults(&self, id: Uuid) -> ManageResult<Vec<OnePasswordVaultDto>> {
        Ok(self.broker.onepassword_vaults(&id).await?)
    }

    async fn onepassword_items(
        &self,
        id: Uuid,
        vault_id: String,
    ) -> ManageResult<Vec<OnePasswordItemDto>> {
        Ok(self.broker.onepassword_items(&id, &vault_id).await?)
    }

    async fn onepassword_fields(
        &self,
        id: Uuid,
        vault_id: String,
        item_id: String,
    ) -> ManageResult<Vec<OnePasswordFieldDto>> {
        Ok(self
            .broker
            .onepassword_fields(&id, &vault_id, &item_id)
            .await?)
    }

    async fn add_onepassword_secret(
        &self,
        name: String,
        reference: crate::onepassword::OnePasswordSecretRef,
    ) -> ManageResult<SecretDto> {
        self.blocking(move |broker| {
            let meta = broker.ui_add_onepassword_secret(&name, reference)?;
            Ok(secret_dto(&broker, &meta))
        })
        .await
    }

    async fn list_connections(&self) -> ManageResult<Vec<ConnectionDto>> {
        let broker = &self.broker;
        Ok(broker
            .store
            .list_connections()
            .iter()
            .map(|conn| connection_dto(broker, conn))
            .collect())
    }

    async fn add_connection(&self, spec: ConnectionSpec) -> ManageResult<()> {
        self.broker
            .validate_ssh_connection_credential(&spec, None)
            .await?;
        let id = self
            .blocking(move |broker| broker.ui_add_connection(spec).map(|conn| conn.id))
            .await?;
        self.broker.auto_issue_api_endpoint(&id).await;
        Ok(())
    }

    async fn add_connection_with_secret(
        &self,
        secret_name: String,
        value: SecretValue,
        spec: ConnectionSpec,
    ) -> ManageResult<()> {
        self.broker
            .validate_ssh_connection_credential(&spec, Some(&value))
            .await?;
        let id = self
            .blocking(move |broker| {
                broker
                    .ui_add_connection_with_secret(&secret_name, value, spec)
                    .map(|conn| conn.id)
            })
            .await?;
        self.broker.auto_issue_api_endpoint(&id).await;
        Ok(())
    }

    async fn update_connection(
        &self,
        id: Uuid,
        expected_updated_at: String,
        spec: ConnectionSpec,
    ) -> ManageResult<()> {
        let old = self.broker.store.connection_by_id(&id)?;
        if old.version() != expected_updated_at {
            return Err(ManageError::ConnectionChanged);
        }
        if old.config != spec.config || old.secrets != spec.secrets {
            self.broker
                .validate_ssh_connection_credential(&spec, None)
                .await?;
        }
        self.blocking(move |broker| {
            broker
                .ui_update_connection_if_current(&id, &expected_updated_at, spec)
                .map(|_| ())
        })
        .await
    }

    async fn rename_connection(
        &self,
        id: Uuid,
        expected_updated_at: String,
        name: String,
    ) -> ManageResult<()> {
        self.blocking(move |broker| {
            broker
                .ui_rename_connection_if_current(&id, &expected_updated_at, name)
                .map(|_| ())
        })
        .await
    }

    async fn patch_connection(
        &self,
        id: Uuid,
        expected_updated_at: String,
        patch: ConnectionConfigPatch,
    ) -> ManageResult<()> {
        let current = self.broker.store.connection_by_id(&id)?;
        if current.version() != expected_updated_at {
            return Err(ManageError::ConnectionChanged);
        }
        let spec = patched_connection_spec(&current, patch)?;
        if current.config != spec.config || current.secrets != spec.secrets {
            self.broker
                .validate_ssh_connection_credential(&spec, None)
                .await?;
        }
        self.blocking(move |broker| {
            broker
                .ui_update_connection_if_current(&id, &expected_updated_at, spec)
                .map(|_| ())
        })
        .await
    }

    async fn delete_connection(&self, id: Uuid) -> ManageResult<()> {
        self.blocking(move |broker| broker.ui_delete_connection(&id).map(|_| ()))
            .await
    }

    async fn reorder_connections(&self, ordered_ids: Vec<Uuid>) -> ManageResult<()> {
        self.blocking(move |broker| broker.ui_reorder_connections(&ordered_ids))
            .await
    }

    async fn test_connection(&self, id: Uuid) -> ManageResult<ConnectionTestReport> {
        Ok(self.broker.ui_test_connection(&id).await?)
    }

    async fn test_connection_draft(
        &self,
        spec: ConnectionSpec,
        typed_secret: Option<SecretValue>,
    ) -> ManageResult<ConnectionTestReport> {
        Ok(self
            .broker
            .ui_test_connection_draft(spec, typed_secret)
            .await?)
    }

    async fn start_mcp_auth(
        &self,
        draft: crate::mcp_auth::McpAuthDraft,
    ) -> ManageResult<crate::mcp_auth::McpAuthState> {
        Ok(self.broker.ui_start_mcp_auth(draft)?)
    }

    async fn get_mcp_auth(&self, id: Uuid) -> ManageResult<Option<crate::mcp_auth::McpAuthState>> {
        Ok(self.broker.ui_mcp_auth_state(&id))
    }

    async fn cancel_mcp_auth(&self, id: Uuid) -> ManageResult<bool> {
        Ok(self.broker.ui_cancel_mcp_auth(&id))
    }

    async fn mcp_status(
        &self,
        id: Uuid,
        options: crate::mcp::McpCheckOptions,
    ) -> ManageResult<crate::mcp::McpStatusReport> {
        Ok(self.broker.ui_mcp_check(&id, options).await?)
    }

    async fn list_mcp_tools(&self, id: Uuid) -> ManageResult<crate::mcp::McpToolCatalog> {
        Ok(self.broker.ui_list_mcp_tools(&id).await?)
    }

    async fn oauth_connect(
        &self,
        secret_name: String,
        client_secret: Option<SecretValue>,
        spec: ConnectionSpec,
    ) -> ManageResult<()> {
        Ok(self
            .broker
            .ui_oauth_connect(&secret_name, client_secret, spec)
            .await
            .map(|_| ())?)
    }

    async fn oauth_reconnect(&self, id: Uuid) -> ManageResult<()> {
        Ok(self.broker.ui_oauth_reconnect(&id).await.map(|_| ())?)
    }

    async fn set_confirm_mode(&self, connection_id: Uuid, on: bool) -> ManageResult<bool> {
        let confirm = if on {
            crate::types::ConfirmMode::On
        } else {
            crate::types::ConfirmMode::Off
        };
        self.blocking(move |broker| broker.ui_set_confirm_mode(&connection_id, confirm))
            .await
    }

    async fn set_expose_response_credentials(
        &self,
        connection_id: Uuid,
        expose: bool,
    ) -> ManageResult<bool> {
        self.blocking(move |broker| {
            broker.ui_set_expose_response_credentials(&connection_id, expose)
        })
        .await
    }

    async fn approvals(&self) -> ManageResult<Vec<ApprovalDto>> {
        Ok(self
            .broker
            .pending_approvals()
            .iter()
            .map(approval_dto)
            .collect())
    }

    async fn requests(&self) -> ManageResult<Vec<RequestDto>> {
        Ok(self
            .broker
            .request_records()
            .iter()
            .map(request_dto)
            .collect())
    }

    async fn respond_approval(
        &self,
        id: Uuid,
        decision: ApprovalDecisionDto,
    ) -> ManageResult<bool> {
        // "Approve all" turns the switch off, which runs the native
        // confirmation — never on the async runtime.
        self.blocking(move |broker| broker.ui_respond_approval(&id, approval_decision(decision)))
            .await
    }

    async fn elicitations(&self) -> ManageResult<Vec<ElicitationDto>> {
        Ok(self
            .broker
            .pending_elicitations()
            .iter()
            .map(elicitation_dto)
            .collect())
    }

    async fn respond_elicitation(
        &self,
        id: Uuid,
        approved: bool,
        values: std::collections::HashMap<String, String>,
    ) -> ManageResult<bool> {
        // The values ride down as strings; the registry coerces each to its
        // field's JSON type (a boolean field becomes a real true/false) where
        // it has the schema to do so.
        self.blocking(move |broker| broker.ui_respond_elicitation(&id, approved, values))
            .await
    }

    async fn set_tool_access(&self, connection_id: Uuid, enabled: bool) -> ManageResult<bool> {
        let changed = self
            .blocking(move |broker| broker.ui_set_tool_access(&connection_id, enabled))
            .await?;
        if enabled {
            self.broker.auto_issue_api_endpoint(&connection_id).await;
        }
        Ok(changed)
    }

    async fn set_allowed_tools(
        &self,
        connection_id: Uuid,
        tools: Option<Vec<String>>,
    ) -> ManageResult<bool> {
        self.blocking(move |broker| broker.ui_set_allowed_tools(&connection_id, tools))
            .await
    }

    async fn set_audit_statements(
        &self,
        connection_id: Uuid,
        audit_statements: Option<bool>,
    ) -> ManageResult<bool> {
        self.blocking(move |broker| {
            broker.ui_set_audit_statements(&connection_id, audit_statements)
        })
        .await
    }

    async fn set_endpoint_require_auth(
        &self,
        connection_id: Uuid,
        require_auth: bool,
    ) -> ManageResult<bool> {
        Ok(self
            .broker
            .ui_set_endpoint_require_auth(&connection_id, require_auth)
            .await?)
    }

    async fn issue_endpoint(&self, connection_id: Uuid) -> ManageResult<IssuedEndpointDto> {
        Ok(self
            .broker
            .ui_issue_endpoint(&connection_id)
            .await
            .map(issued_endpoint_dto)?)
    }

    async fn renew_endpoint(&self, connection_id: Uuid) -> ManageResult<IssuedEndpointDto> {
        Ok(self
            .broker
            .ui_renew_endpoint(&connection_id)
            .await
            .map(issued_endpoint_dto)?)
    }

    async fn set_endpoint_expiry(
        &self,
        connection_id: Uuid,
        expire: bool,
    ) -> ManageResult<IssuedEndpointDto> {
        Ok(self
            .broker
            .ui_set_endpoint_expiry(&connection_id, expire)
            .await
            .map(issued_endpoint_dto)?)
    }

    async fn get_endpoint(&self, connection_id: Uuid) -> ManageResult<Option<IssuedEndpointDto>> {
        Ok(self
            .broker
            .ui_get_endpoint(&connection_id)
            .await?
            .map(issued_endpoint_dto))
    }

    async fn copy_endpoint(&self, connection_id: Uuid) -> ManageResult<Option<IssuedEndpointDto>> {
        Ok(self
            .broker
            .ui_copy_endpoint(&connection_id)
            .await?
            .map(issued_endpoint_dto))
    }

    async fn revoke_endpoint(&self, endpoint_id: Uuid) -> ManageResult<bool> {
        self.blocking(move |broker| broker.ui_revoke_endpoint(&endpoint_id))
            .await
    }

    async fn identity(&self) -> ManageResult<IdentityDto> {
        Ok(identity_dto(&self.broker))
    }

    async fn agent_key(&self) -> ManageResult<String> {
        // Gated and audited at release: the trait's only caller is the
        // shell's clipboard affordance, and a remote shell reaches this same
        // path through the manage route. The gate prompts, so it runs through
        // `blocking` like every other prompting entry point.
        self.blocking(move |broker| broker.ui_agent_key_for_copy())
            .await
    }

    async fn rotate_key(&self) -> ManageResult<()> {
        self.blocking(move |broker| broker.ui_rotate_key()).await
    }

    async fn sessions(&self) -> ManageResult<Vec<SessionDto>> {
        Ok(self.broker.sessions().iter().map(session_dto).collect())
    }

    async fn close_session(&self, id: u64) -> ManageResult<bool> {
        Ok(self.broker.ui_close_session(id)?)
    }

    async fn activity(&self, limit: usize) -> ManageResult<Vec<ActivityDto>> {
        let limit = if limit == 0 { usize::MAX } else { limit };
        Ok(self
            .broker
            .audit
            .recent(limit)
            .iter()
            .map(activity_dto)
            .collect())
    }

    async fn activity_page(
        &self,
        limit: usize,
        before: Option<u64>,
    ) -> ManageResult<aka_api::ActivityPageDto> {
        let page = self.broker.audit.recent_page(limit, before);
        Ok(aka_api::ActivityPageDto {
            entries: page.entries.iter().map(activity_dto).collect(),
            next_before: page.next_before,
        })
    }

    async fn clear_activity(&self) -> ManageResult<()> {
        self.blocking(move |broker| broker.ui_clear_activity())
            .await?;
        // A clear has no `BrokerEvents` counterpart; publish the manage
        // event here so every caller — the manage route and an in-process
        // shell alike — refreshes SSE subscribers' activity views.
        self.broker
            .publish_manage_event(aka_api::ManageEvent::ActivityCleared);
        Ok(())
    }

    async fn settings(&self) -> ManageResult<SettingsDto> {
        Ok(settings_dto(&self.broker))
    }

    async fn set_confirm_ssh_host_keys(&self, on: bool) -> ManageResult<()> {
        self.blocking(move |broker| broker.ui_set_confirm_ssh_host_keys(on))
            .await
    }

    async fn set_menu_bar_hides_dock(&self, on: bool) -> ManageResult<()> {
        self.blocking(move |broker| broker.ui_set_menu_bar_hides_dock(on))
            .await
    }

    async fn agent_setup(&self) -> ManageResult<String> {
        // A broker serving a public URL is being reached by remote agents;
        // the setup snippet must describe their path, not the host's socket.
        if let Some(base) = self.broker.public_url() {
            return Ok(agent_setup_instructions_remote(&base));
        }
        Ok(agent_setup_instructions(
            &self.broker.paths.socket_display(),
            &self.broker.paths.token_display(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::AuditKind;
    use crate::config::BrokerConfig;
    use crate::events::NoopEvents;
    use crate::paths::Paths;
    use crate::types::{ConfirmationMethod, ConnectionConfig};
    use crate::vault::MemoryVault;
    use zeroize::Zeroizing;

    #[test]
    fn only_explicit_request_surfaces_hold_approval_capability() {
        let bus = Arc::new(ManageBus::new());
        let _observer = bus.subscribe();
        assert!(
            !bus.has_approval_surface(),
            "a passive event observer must not park confirmed traffic"
        );

        let surface = bus.lease_approval_surface();
        assert!(
            bus.has_approval_surface(),
            "a fresh lease covers the handshake round trip"
        );
        assert!(bus.renew_approval_surface(&surface.id()));
        assert!(bus.has_approval_surface());
        drop(surface);
        assert!(!bus.has_approval_surface());
    }

    #[test]
    fn request_surface_leases_expire_without_renewal() {
        let bus = Arc::new(ManageBus::new());
        let surface = bus.lease_approval_surface_for(std::time::Duration::from_millis(1));
        std::thread::sleep(std::time::Duration::from_millis(10));
        assert!(!bus.has_approval_surface());
        assert!(bus.renew_approval_surface(&surface.id()));
        assert!(bus.has_approval_surface());
    }

    #[test]
    fn polling_request_surfaces_can_be_renewed_and_released() {
        let bus = ManageBus::new();
        let id = bus.mint_polling_approval_surface();
        assert!(bus.has_approval_surface());
        assert!(bus.renew_approval_surface(&id));
        assert!(bus.release_approval_surface(&id));
        assert!(!bus.has_approval_surface());
        assert!(!bus.renew_approval_surface(&id));
    }

    #[test]
    fn fanout_publishes_structured_secret_changes() {
        let bus = Arc::new(ManageBus::new());
        let mut events = bus.subscribe();
        let fanout = FanoutEvents::new(Arc::new(NoopEvents), bus);
        crate::events::BrokerEvents::secrets_changed(&fanout);
        assert!(matches!(
            events.try_recv().unwrap().event,
            aka_api::ManageEvent::SecretsChanged
        ));
    }

    #[test]
    fn a_fresh_lease_carries_confirmed_traffic_through_the_handshake() {
        // A reconnect or broker restart costs one ready-comment plus
        // heartbeat round trip. Refusing confirmed traffic during it would
        // fail closed against a desktop that is right there, so minting
        // grants exactly one TTL of grace — and no more.
        let bus = Arc::new(ManageBus::new());
        let surface = bus.lease_approval_surface();
        assert!(bus.has_approval_surface());
        assert_eq!(
            APPROVAL_SURFACE_TTL,
            std::time::Duration::from_millis(aka_api::APPROVAL_SURFACE_TTL_MS),
            "the grace period is one advertised TTL"
        );

        // A surface that never heartbeats lapses at that TTL: expire the
        // grace by hand rather than sleeping it out.
        bus.approval_surfaces.lock().unwrap().insert(
            surface.id(),
            ManageBus::expiry_after(std::time::Duration::ZERO),
        );
        assert!(
            !bus.has_approval_surface(),
            "grace is not a standing capability"
        );
    }

    async fn backend(dir: &tempfile::TempDir) -> LocalBackend {
        let broker = Broker::new(
            Paths::under(dir.path()),
            Arc::new(MemoryVault::new()),
            BrokerConfig::default(),
            Arc::new(NoopEvents),
        )
        .await
        .unwrap();
        LocalBackend::new(broker)
    }

    fn api_spec(name: &str) -> ConnectionSpec {
        ConnectionSpec {
            name: name.into(),
            config: ConnectionConfig::Api {
                host: "api.github.com".into(),
                scheme: "https".into(),
                port: None,
                trusted_ca_bundle_path: None,
                template: "Authorization: Bearer {{GITHUB_KEY}}".into(),
                mcp_path: None,
                test_path: None,
                oauth: None,
                signer: None,
                client_cert_path: None,
                client_key_path: None,
            },
            secrets: vec![],
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn local_backend_round_trips_secrets_and_connections() {
        let dir = tempfile::tempdir().unwrap();
        let backend = backend(&dir).await;
        let mut events = backend.broker.manage_bus().subscribe();

        backend
            .add_secret("GITHUB_KEY".into(), Zeroizing::new("ghp_test".into()))
            .await
            .unwrap();
        let mut saw_secrets_changed = false;
        while let Ok(item) = events.try_recv() {
            saw_secrets_changed |= matches!(item.event, aka_api::ManageEvent::SecretsChanged);
        }
        assert!(
            saw_secrets_changed,
            "a management mutation must refresh every attached secret view"
        );
        backend.add_connection(api_spec("github")).await.unwrap();

        let secrets = backend.list_secrets().await.unwrap();
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].name, "GITHUB_KEY");
        assert_eq!(secrets[0].used_by_names, vec!["github".to_string()]);

        let connections = backend.list_connections().await.unwrap();
        assert_eq!(connections.len(), 1);
        let conn = &connections[0];
        assert_eq!(conn.kind, "api");
        assert_eq!(conn.secret_names, vec!["GITHUB_KEY".to_string()]);
        assert!(conn.agent_access.enabled, "enabled is the default");

        let id: Uuid = conn.id.parse().unwrap();
        // Returns whether the setting changed; disabling from the default
        // (enabled) is a change.
        assert!(backend.set_tool_access(id, false).await.unwrap());
        assert!(
            !backend.list_connections().await.unwrap()[0]
                .agent_access
                .enabled
        );

        backend
            .rename_connection(id, conn.updated_at.clone(), "github renamed".into())
            .await
            .unwrap();
        let renamed = backend.list_connections().await.unwrap().remove(0);
        assert_eq!(renamed.name, "github renamed");
        assert_eq!(renamed.target, conn.target);
        assert_eq!(renamed.secret_names, conn.secret_names);
        assert!(
            !renamed.agent_access.enabled,
            "rename preserves access state"
        );
        assert_eq!(
            backend
                .rename_connection(id, conn.updated_at.clone(), "stale rename".into())
                .await
                .unwrap_err(),
            ManageError::ConnectionChanged
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn errors_cross_the_seam_with_their_shape_intact() {
        let dir = tempfile::tempdir().unwrap();
        let backend = backend(&dir).await;
        backend
            .add_secret("KEY".into(), Zeroizing::new("v".into()))
            .await
            .unwrap();
        let error = backend
            .add_secret("KEY".into(), Zeroizing::new("v".into()))
            .await
            .unwrap_err();
        assert_eq!(error, ManageError::SecretNameTaken { name: "KEY".into() });

        let error = backend
            .add_connection(ConnectionSpec {
                name: "gh".into(),
                config: ConnectionConfig::Api {
                    host: "api.github.com".into(),
                    scheme: "https".into(),
                    port: None,
                    trusted_ca_bundle_path: None,
                    template: "Authorization: Bearer {{MISSING}}".into(),
                    mcp_path: None,
                    test_path: None,
                    oauth: None,
                    signer: None,
                    client_cert_path: None,
                    client_key_path: None,
                },
                secrets: vec![],
            })
            .await
            .unwrap_err();
        assert_eq!(
            error,
            ManageError::UnknownTemplateRef {
                name: "MISSING".into()
            }
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn ssh_connections_reject_unusable_private_keys_at_the_backend_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let backend = backend(&dir).await;
        let spec = ConnectionSpec {
            name: "production ssh".into(),
            config: ConnectionConfig::Ssh {
                destination: Some("deploy@prod.example.com".into()),
                host: "prod.example.com".into(),
                port: 22,
                user: "deploy".into(),
                host_key_fingerprint: String::new(),
            },
            secrets: vec![],
        };
        let error = backend
            .add_connection_with_secret(
                "SSH_KEY".into(),
                Zeroizing::new("not a private key".into()),
                spec,
            )
            .await
            .unwrap_err();
        assert!(
            matches!(
                error,
                ManageError::InvalidConnectionConfig { ref message }
                    if message.contains("private key")
            ),
            "{error:?}"
        );
        assert!(backend.list_connections().await.unwrap().is_empty());
        assert!(backend.list_secrets().await.unwrap().is_empty());
    }

    #[test]
    fn remote_agent_setup_names_the_public_url_not_host_paths() {
        let text = agent_setup_instructions_remote("https://broker.example.dev/");
        assert!(text.contains("https://broker.example.dev/instructions"));
        assert!(text.contains("https://broker.example.dev/mcp"));
        assert!(text.contains("Authorization: Bearer"));
        assert!(!text.contains("--unix-socket"));
    }

    #[test]
    fn management_token_authority_survives_the_activity_projection() {
        let context =
            crate::types::DecisionContext::remote(Some("192.0.2.7:4242".parse().unwrap()));
        let dto = activity_dto(
            &AuditEntry::new(AuditKind::SettingsChanged, "Remote setting changed")
                .confirmation(ConfirmationMethod::ManagementToken)
                .context(&context),
        );
        assert_eq!(dto.confirmation.as_deref(), Some("management_token"));
        assert_eq!(dto.surface.as_deref(), Some("remote"));
        assert_eq!(dto.approver.as_deref(), Some("192.0.2.7:4242"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn identity_and_settings_surface_through_the_backend() {
        let dir = tempfile::tempdir().unwrap();
        let backend = backend(&dir).await;

        let identity = backend.identity().await.unwrap();
        assert!(identity.token_path.ends_with("token"));
        let key = backend.agent_key().await.unwrap();
        assert!(key.starts_with("aka_"));
        assert!(
            !backend.activity(0).await.unwrap().is_empty(),
            "zero requests the full activity log"
        );

        let settings = backend.settings().await.unwrap();
        assert!(!settings.menu_bar_hides_dock);

        let setup = backend.agent_setup().await.unwrap();
        assert!(setup.contains("--unix-socket"));
    }

    #[test]
    fn config_patch_preserves_broker_authoritative_fields() {
        let now = chrono::Utc::now();
        let secret = Uuid::new_v4();
        let connection = Connection {
            id: Uuid::new_v4(),
            name: "calendar".into(),
            config: ConnectionConfig::Api {
                host: "api.example.com".into(),
                scheme: "https".into(),
                port: None,
                trusted_ca_bundle_path: Some("/etc/company-ca.pem".into()),
                template: "Authorization: Bearer {{CALENDAR}}".into(),
                mcp_path: Some("/mcp".into()),
                test_path: None,
                oauth: None,
                signer: None,
                client_cert_path: None,
                client_key_path: None,
            },
            secrets: vec![secret],
            account: Some("operator@example.com".into()),
            oauth: None,
            created_at: now,
            updated_at: now,
        };

        let spec = patched_connection_spec(
            &connection,
            ConnectionConfigPatch {
                host: Some("api2.example.com".into()),
                ..Default::default()
            },
        )
        .unwrap();
        let ConnectionConfig::Api {
            host,
            scheme,
            trusted_ca_bundle_path,
            template,
            mcp_path,
            ..
        } = spec.config
        else {
            panic!("expected API config");
        };
        assert_eq!(host, "api2.example.com");
        assert_eq!(scheme, "https");
        assert_eq!(
            trusted_ca_bundle_path.as_deref(),
            Some("/etc/company-ca.pem")
        );
        assert_eq!(template, "Authorization: Bearer {{CALENDAR}}");
        assert_eq!(mcp_path.as_deref(), Some("/mcp"));
        assert_eq!(spec.secrets, vec![secret]);
    }
}
