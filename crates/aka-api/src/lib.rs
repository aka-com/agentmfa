//! Management-plane wire types.
//!
//! Every shape that crosses the management boundary lives here: the DTOs the
//! webview renders, the structured error a management call can fail with, and
//! the change events the broker pushes. The desktop shell consumes these
//! in-process (local mode) or over HTTP (remote mode) — one set of shapes, so
//! the two modes cannot drift.
//!
//! Serialization is the compatibility contract with the webview: field names
//! and `rename` attributes must not change without updating `ui/src/types.ts`
//! and the dev mock together.

use serde::{Deserialize, Serialize};

/// An authenticated manage-event stream carrying this header promises that
/// it has a user-facing request inbox and can bring pending requests to the
/// user's attention. Passive SSE observers deliberately omit it.
pub const APPROVAL_SURFACE_HEADER: &str = "x-aka-approval-surface";
/// Versioned value for [`APPROVAL_SURFACE_HEADER`]. Unknown values are
/// treated as observers so adding future surface protocols stays fail-closed.
pub const APPROVAL_SURFACE_V1: &str = "request-inbox-v1";
/// Entry in `/v1/manage/whoami.capabilities` that distinguishes a legacy
/// broker from a proxy that removed the surface-negotiation response.
pub const APPROVAL_SURFACE_CAPABILITY: &str = "request_surface_v1";
/// Response header acknowledging how a manage-event stream was classified.
pub const APPROVAL_SURFACE_STATUS_HEADER: &str = "x-aka-approval-surface-status";
pub const APPROVAL_SURFACE_STATUS_ACTIVE: &str = "active";
pub const APPROVAL_SURFACE_STATUS_OBSERVER: &str = "observer";
/// Response header carrying the broker-minted lease identifier that an
/// active request surface must heartbeat.
pub const APPROVAL_SURFACE_ID_HEADER: &str = "x-aka-approval-surface-id";
/// A live surface renews every five seconds; the broker allows three missed
/// heartbeats before new confirmed traffic fails closed.
pub const APPROVAL_SURFACE_HEARTBEAT_MS: u64 = 5_000;
pub const APPROVAL_SURFACE_TTL_MS: u64 = 15_000;

/// A short-lived request-inbox lease minted for a polling management client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalSurfaceDto {
    pub id: String,
    pub expires_in_ms: u64,
}

/// A connection field whose authoritative validation failed. Keeping this
/// structured lets desktop clients attach the error to the relevant input
/// without parsing human-readable error strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionField {
    Host,
    Scheme,
    Port,
    Database,
    User,
    Url,
    Template,
    HostKeyFingerprint,
}

/// A management call's failure, as it crosses the backend boundary.
///
/// This mirrors the `CoreError` cases a `ui_*` entry point can produce, with
/// owned data so it survives serialization. The desktop shell maps it onto
/// form fields; `Display` keeps the human-readable line the core would have
/// printed, so plain string surfaces read identically in both modes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum ManageError {
    SecretNameTaken {
        name: String,
    },
    ConnectionNameTaken {
        name: String,
    },
    ConnectionTargetTaken {
        name: String,
    },
    SecretNotFound,
    ConnectionNotFound,
    ConnectionChanged,
    ApprovalConnectionChanged,
    SecretInUse {
        connections: Vec<String>,
    },
    InvalidSecretName {
        name: String,
    },
    InvalidConnectionName {
        name: String,
    },
    Template {
        message: String,
    },
    UnknownTemplateRef {
        name: String,
    },
    WrongSecretCount {
        kind: String,
    },
    InvalidConnectionConfig {
        message: String,
    },
    InvalidSetting {
        message: String,
    },
    InvalidConnectionField {
        field: ConnectionField,
        message: String,
    },
    KindChange,
    EndpointNotFound,
    EndpointExpired,
    EndpointLimit {
        max: usize,
    },
    EndpointRequiresWiring,
    OAuth {
        message: String,
    },
    Vault {
        message: String,
    },
    /// The management feature exists but this backend cannot perform it —
    /// e.g. OAuth sign-in against a remote broker before the relay ships.
    RemoteUnsupported {
        feature: String,
    },
    /// The remote broker rejected the management token. The optional
    /// broker-supplied detail distinguishes expiry from a bad, revoked, or
    /// rotated token without collapsing every 401 to the same advice.
    /// Local backends never produce this.
    InvalidManageToken {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        detail: Option<String>,
    },
    /// The remote broker could not be reached (or answered outside the
    /// protocol). Local backends never produce this.
    Unreachable {
        message: String,
    },
    /// Everything without a field mapping (I/O, corrupt state, internals).
    Internal {
        message: String,
    },
}

impl std::fmt::Display for ManageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SecretNameTaken { name } => {
                write!(f, "secret name {name:?} is already in use")
            }
            Self::ConnectionNameTaken { name } => {
                write!(f, "tool name {name:?} is already in use")
            }
            Self::ConnectionTargetTaken { name } => {
                write!(f, "an equivalent target is already saved as tool {name:?}")
            }
            Self::SecretNotFound => write!(f, "no such secret"),
            Self::ConnectionNotFound => write!(f, "no such tool"),
            Self::ConnectionChanged => write!(
                f,
                "the tool changed after you read it; review the latest settings and try again"
            ),
            Self::ApprovalConnectionChanged => write!(
                f,
                "the tool changed while you were confirming; review it and save again"
            ),
            Self::SecretInUse { connections } => {
                write!(f, "secret is in use by tool(s): {}", connections.join(", "))
            }
            Self::InvalidSecretName { name } => write!(
                f,
                "invalid name {name:?}: names are 1-64 chars of [A-Za-z0-9_] not starting with a digit"
            ),
            Self::InvalidConnectionName { name } => write!(
                f,
                "invalid tool name {name:?}: use 1-64 ASCII letters, numbers, spaces, or safe endpoint punctuation; start with a letter or number and do not end with a space"
            ),
            Self::Template { message } => write!(f, "invalid template: {message}"),
            Self::UnknownTemplateRef { name } => {
                write!(f, "template references unknown secret {name:?}")
            }
            Self::WrongSecretCount { kind } => {
                write!(f, "{kind} tools bind exactly one secret")
            }
            Self::InvalidConnectionConfig { message } => {
                write!(f, "invalid tool config: {message}")
            }
            Self::InvalidSetting { message } => write!(f, "invalid setting: {message}"),
            Self::InvalidConnectionField { field, message } => {
                write!(f, "invalid tool field {field:?}: {message}")
            }
            Self::KindChange => write!(f, "a tool's type is fixed after creation"),
            Self::EndpointNotFound => write!(f, "no such endpoint"),
            Self::EndpointExpired => write!(
                f,
                "this direct endpoint has expired; renew it before using or rotating it"
            ),
            Self::EndpointLimit { max } => write!(
                f,
                "too many direct endpoints ({max}); revoke one before issuing another"
            ),
            Self::EndpointRequiresWiring => write!(
                f,
                "enable this tool for agents before issuing a direct endpoint"
            ),
            Self::OAuth { message } => write!(f, "OAuth: {message}"),
            Self::Vault { message } => write!(f, "keychain: {message}"),
            Self::RemoteUnsupported { feature } => write!(
                f,
                "{feature} is not available while managing a remote broker"
            ),
            Self::InvalidManageToken { detail: Some(detail) } => f.write_str(detail),
            Self::InvalidManageToken { detail: None } => write!(
                f,
                "the broker rejected the management token; re-issue it with `mfa manage token` and enter the new one"
            ),
            Self::Unreachable { message } => {
                write!(f, "the remote broker could not be reached: {message}")
            }
            Self::Internal { message } => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for ManageError {}

/* --------------------------------- DTOs ---------------------------------- */

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretDto {
    pub id: String,
    pub name: String,
    /// How many services reference it (the "Used by N services" line).
    pub used_by: usize,
    pub used_by_names: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// Non-secret OAuth coordinates, so the UI can label the connection and
/// offer Reconnect. Never token material.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthDto {
    pub auth_url: String,
    pub token_url: String,
    pub client_id: String,
    pub scopes: Vec<String>,
    /// Non-secret authorize-endpoint parameters required by some providers
    /// (for example, requesting an offline refresh token). Clients that
    /// round-trip a connection config must preserve these.
    #[serde(default)]
    pub extra_auth_params: Vec<(String, String)>,
}

/// A connection's agent access, as the UI toggles it. There is one shared
/// identity, so this is per connection, not per agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessDto {
    /// Whether agents may use the connection (default true).
    pub enabled: bool,
    /// Whether traffic asks the user when no approval window is open
    /// (default false). What one decision gates depends on the kind: one
    /// request for an API tool, one `tools/call` for an MCP tool, one
    /// session for Postgres, one login for SSH.
    #[serde(default)]
    pub confirm: bool,
    /// Whether to relay upstream response credential headers (`Set-Cookie`,
    /// authentication challenges, and authentication-info). New HTTP
    /// connections default to true; an explicit false contains them.
    #[serde(default)]
    pub expose_response_credentials: bool,
    /// While an approval window is open, the RFC 3339 time the last of them
    /// lapses — so the app can say why nothing is being asked. Absent when no
    /// window is open.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirm_window_until: Option<String>,
    /// Which agents those windows cover. An approval is scoped to the agent
    /// the prompt named, so the app has to name them rather than imply the
    /// whole connection is open; other agents are still asked about.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub confirm_window_agents: Vec<String>,
    /// While a denial's cooldown is running, the RFC 3339 time it lifts —
    /// retries during it are refused without a fresh prompt, and the app
    /// has to be able to say so. Absent when no cooldown is running.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirm_cooldown_until: Option<String>,
    /// Curated upstream MCP tool subset; absent means all tools.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_tools: Option<Vec<String>>,
    /// Per-connection override for recording Postgres statement text; absent
    /// means the broker-wide default applies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_statements: Option<bool>,
    /// What that resolves to for this connection, override or default, so a
    /// client can render the effective state without knowing the broker's
    /// launch flags.
    #[serde(default)]
    pub audit_statements_effective: bool,
    /// The direct endpoint issued for this connection, if any. Its presence
    /// flips the row's control from "Issue" to "Reissue / Revoke".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<EndpointChip>,
}

/// The direct endpoint on a wiring row. `dsn` is the pasteable address with
/// the retained endpoint secret in its password slot, so copying the chip is
/// enough to connect. For SSH it carries the stable agent-socket path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointChip {
    pub endpoint_id: String,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dsn: Option<String>,
    /// SSH only: whether the agent socket makes a caller present the endpoint
    /// secret before it will list or sign. Carried on the chip because it
    /// changes what the row must say — an authenticated socket is reached
    /// through `mfa ssh-agent`, not by pointing `IdentityAgent` at the path.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub require_auth: bool,
    /// Restart-safe endpoint deadline, plus broker-clock remaining seconds for
    /// clients whose clock differs from a remote broker.
    #[serde(default)]
    pub expires_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_in_secs: Option<u64>,
}

/// The result of issuing a direct endpoint: the pasteable address, a
/// ready-to-run example, and the secret (also retained on the record, so
/// the row's chip stays copyable with the credential in place).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuedEndpointDto {
    pub endpoint_id: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub dsn: String,
    /// A second address for the same endpoint where one exists: for Postgres
    /// the TCP form, which non-libpq drivers can parse and a remote client can
    /// actually reach. Absent for kinds with only one address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp_dsn: Option<String>,
    pub secret: String,
    pub example: String,
    #[serde(default)]
    pub expires_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_in_secs: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionDto {
    pub id: String,
    pub name: String,
    /// Opaque optimistic-concurrency token. Clients must return the value
    /// from the version they edited when replacing the connection. Defaulted
    /// on deserialization so a newer client can still *read* connections
    /// from an older broker that predates the token; updates stay fail-closed
    /// because the update body requires the field.
    #[serde(default)]
    pub updated_at: String,
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
    pub host_key_fingerprint: Option<String>,
    #[serde(default)]
    pub destination: Option<String>,
    #[serde(default)]
    pub sslmode: Option<String>,
    #[serde(default)]
    pub trusted_ca_bundle_path: Option<String>,
    /// Set when an API upstream speaks MCP at that path; the MCP host
    /// re-exposes its tools under this connection's name.
    #[serde(default)]
    pub mcp_path: Option<String>,
    /// The path the Test button probes instead of the origin root, when the
    /// root is not a useful answer to "does this credential work".
    #[serde(default)]
    pub test_path: Option<String>,
    /// The upstream account this connection's credential was last verified
    /// as (an MCP whoami answer). Display metadata, never authorization.
    #[serde(default)]
    pub account: Option<String>,
    /// Set when the credential is a BYO-app OAuth token set.
    #[serde(default)]
    pub oauth_spec: Option<OAuthDto>,
    /// Last-known health: "ok" | "warning" | "failed" |
    /// "needs_reconnect", with the check's summary and timestamp. All absent
    /// while untested.
    #[serde(default)]
    pub last_status: Option<String>,
    #[serde(default)]
    pub last_detail: Option<String>,
    #[serde(default)]
    pub last_checked_at: Option<String>,
    /// Set when the connection signs each request at dispatch time (e.g.
    /// AWS SigV4) instead of injecting a rendered template.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<SignerDto>,
    /// PEM client-certificate chain presented on the upstream TLS leg.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_cert_path: Option<String>,
    /// PEM private key for `client_cert_path`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_key_path: Option<String>,
}

/// A dispatch-time request signer, mirrored from the connection config.
/// Only credential *references* (vault secret names) appear here; the key
/// material never rides the manage plane. The populated fields follow the
/// algorithm: `aws_sigv4` carries region/service and the AWS credential
/// refs; `gcp_service_account` carries the key ref and OAuth scope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignerDto {
    /// "aws_sigv4" or "gcp_service_account".
    pub algorithm: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub region: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub service: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub access_key_ref: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub secret_key_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_token_ref: Option<String>,
    /// Vault secret name holding the GCP service-account JSON key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_ref: Option<String>,
    /// Space-separated OAuth scopes for minted GCP tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

/// The shared broker identity, for the Connect page's key card. Never the
/// key itself — only its home and lifecycle metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityDto {
    pub client_id: String,
    /// Where the plaintext key lives (`~/.aka/token`), for display and copy
    /// instructions.
    pub token_path: String,
    /// The broker socket, for the Connect page's setup snippets.
    pub socket_path: String,
    pub minted_at: String,
    pub last_used: String,
    /// How many older agent keys still work inside a bounded recovery window.
    /// Rotating the current key revokes them immediately.
    pub legacy_aliases: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionDto {
    pub id: u64,
    #[serde(rename = "type")]
    pub kind: String,
    pub agent: String,
    pub connection: String,
    pub detail: String,
    pub opened_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityDto {
    pub icon: String,
    pub tone: String,
    /// Stable audit event classification (for example `denied` or
    /// `session_closed`). Optional so newer clients can read older brokers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub text: String,
    pub detail: Option<String>,
    /// Structured attribution for filtering: which agent acted and which
    /// connection was touched (both optional per entry).
    pub agent: Option<String>,
    pub connection: Option<String>,
    /// Stable machine outcome and protocol, when the audit entry carries
    /// them. Consumers must not reverse-engineer either from presentation
    /// prose.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    /// How long a brokered call or session took, when measured.
    pub duration_ms: Option<u64>,
    /// The decision surface and its directly observed principal, when the
    /// core could attribute one. A remote approver is a socket peer, not an
    /// authenticated human identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approver: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub surface: Option<String>,
    /// How a confirmation-required action was authorized, when one was
    /// (e.g. "os_authentication", "management_token"). Lets the activity
    /// view mark actions a hosted broker authorized by token possession.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirmation: Option<String>,
    /// RFC 3339 timestamp; the UI renders it relative (<24h) or absolute and
    /// shows the full value in a hover tooltip.
    pub at: String,
}

/// One newest-first activity page. `next_before` is an opaque cursor for the
/// next older page and must be passed back unchanged.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityPageDto {
    pub entries: Vec<ActivityDto>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_before: Option<u64>,
}

/// One prompt waiting on the user: agent traffic parked until it is
/// answered. Carries what was summarized for the decision — never a
/// credential, never the request body itself.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalDto {
    pub id: String,
    pub connection_id: String,
    pub connection: String,
    /// Connection kind (`api`, `pg`), so the prompt can speak the right
    /// language: a request, a tool call, a session.
    #[serde(rename = "type")]
    pub kind: String,
    /// What this decision authorizes (`request`, `tool`, `session`, `login`,
    /// or a durable `host_key` pin).
    /// Optional so a new app can still manage an older broker.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    /// The pinned destination the traffic would reach.
    pub target: String,
    /// Self-reported agent label. Attribution, never authorization.
    pub agent: String,
    /// The headline: `GET /user/repos`, `search_issues`, `New Postgres session`.
    pub summary: String,
    /// A second line when there is one: a body preview, a tool's arguments,
    /// the client's application name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Saved credential names that will be used. Values never enter this DTO.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credential_names: Vec<String>,
    /// Structured HTTP operation fields; do not parse these out of `summary`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Present only for a first-seen SSH trust decision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_key_fingerprint: Option<String>,
    /// What approving hands over, written by the broker rather than derived
    /// from the request — a Postgres session, for instance, carries every
    /// statement the client sends, not the one that raised the prompt.
    /// Render it as the broker's own voice, never as part of `detail`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consequence: Option<String>,
    /// How many calls are riding this one prompt.
    pub waiting: usize,
    /// RFC 3339 timestamps: when it was raised, and when it gives up on its
    /// own and the parked traffic is refused.
    pub requested_at: String,
    pub expires_at: String,
    /// Seconds until `expires_at`, measured on the broker's clock as this
    /// DTO was built. Clients render the countdown from this — anchored to
    /// their own clock at receipt — so a remote broker's clock offset cannot
    /// distort it. Optional so a new app can still manage an older broker.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_in_secs: Option<u64>,
    /// How long "approve for now" would last, so the button can name it.
    pub window_secs: u64,
}

/// An authoritative approval queue paired with the manage event-bus position
/// it was read against. Remote shells order snapshots by this broker-minted
/// version instead of by local fetch timing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalSnapshotDto {
    /// `<broker event epoch>:<head sequence>`.
    pub version: String,
    pub approvals: Vec<ApprovalDto>,
    /// Included in the same versioned read so a remote request surface can
    /// reconcile every kind of parked user work from one event.
    #[serde(default)]
    pub elicitations: Vec<ElicitationDto>,
}

/// A request's decision lifecycle. Unlike [`ApprovalDto`], terminal records
/// remain available for the bounded Recent Inbox after traffic has resumed or
/// been refused.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestDto {
    pub id: String,
    /// Request family: `approval` for traffic confirmation or `elicitation`
    /// for an upstream MCP input request.
    pub kind: String,
    /// `pending`, `approved`, `denied`, `expired`, `revoked`, `unavailable`,
    /// or `abandoned`.
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection_id: Option<String>,
    pub connection: String,
    /// The connection transport (`api`, `pg`, …), distinct from request kind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    pub agent: String,
    pub summary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credential_names: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_key_fingerprint: Option<String>,
    pub waiting: usize,
    pub requested_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    /// Seconds until `expires_at` on the broker's clock, present only while
    /// pending — see [`ApprovalDto::expires_in_secs`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_in_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_at: Option<String>,
    /// Machine-readable terminal cause, absent while pending.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolution: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window_secs: Option<u64>,
}

/// One input an upstream MCP server asked for, as the app renders it.
/// Mirrors the UI's `ElicitationField`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElicitationFieldDto {
    pub name: String,
    pub label: String,
    /// Whether the field appears in the schema object's `required` array.
    /// Always serialized (an omitted flag is indistinguishable from a broker
    /// that predates it, and consumers fail closed on absence by requiring
    /// the field); defaulted on deserialization for those older brokers.
    #[serde(default)]
    pub required: bool,
    /// A JSON Schema `boolean`: render a toggle; the answer rides upstream as a
    /// real JSON boolean rather than a string.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub boolean: bool,
    /// A fixed set of choices (a JSON Schema `enum`): render a dropdown rather
    /// than a text field. Absent for free-text fields.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub options: Option<Vec<String>>,
}

/// A paused upstream MCP tool call waiting on the user (SEP-2322). The agent
/// whose call is parked never sees this prompt or its answer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElicitationDto {
    pub id: String,
    /// Agent whose tool call is paused.
    pub agent: String,
    /// Connection (upstream MCP server) that asked.
    pub connection: String,
    /// The MCP tool name the agent called.
    pub tool: String,
    /// The upstream's own prompt, shown verbatim but never interpreted.
    pub prompt: String,
    pub fields: Vec<ElicitationFieldDto>,
    /// The schema asked for something credential-shaped. Fields are plain
    /// text regardless — no `format` an upstream sends changes that — so this
    /// is a cue to warn the user, never a rendering instruction.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub credential_warning: bool,
    pub requested_at: String,
    /// The request disappears on its own at this time.
    pub expires_at: String,
    /// Seconds until `expires_at` on the broker's clock — see
    /// [`ApprovalDto::expires_in_secs`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_in_secs: Option<u64>,
}

/// What the user chose on a prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalDecisionDto {
    /// Allow this and everything else on the connection for the window.
    ApproveWindow,
    /// Allow this and turn the connection's confirmation off.
    ApproveAll,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettingsDto {
    pub menu_bar_hides_dock: bool,
    /// Ask before trusting an SSH server's host key the first time it is seen.
    #[serde(default)]
    pub confirm_ssh_host_keys: bool,
}

/* -------------------------------- events ---------------------------------- */

/// A state-change notification from the broker's management plane. Local
/// mode receives these through `BrokerEvents` directly; remote mode receives
/// exactly these shapes over the manage event stream, so both re-emit the
/// same webview events.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum ManageEvent {
    SessionsChanged,
    AgentsChanged,
    /// A prompt was raised, updated, answered, or lapsed: refetch the queue.
    ApprovalsChanged,
    /// A prompt specifically left the queue because its decision window
    /// elapsed. Request surfaces use this precise terminal signal for a
    /// coalesced expiry notification; `ApprovalsChanged` still follows so
    /// older queue-reconciliation behavior remains intact.
    ApprovalExpired {
        id: String,
    },
    /// An elicitation was raised, answered, or lapsed: refetch the queue.
    ElicitationsChanged,
    WiringsChanged,
    ConnectionsChanged,
    SecretsChanged,
    ActivityAppended {
        entry: ActivityDto,
    },
    /// The activity log was cleared (as opposed to appended to).
    ActivityCleared,
    /// An MCP sign-in flow progressed; the payload is the core's
    /// `McpAuthState` serialization, passed through opaquely.
    McpAuthChanged {
        state: serde_json::Value,
    },
    ConnectRequested {
        agent: String,
        service: String,
    },
    /// The event stream dropped notifications (a slow consumer): refetch
    /// everything instead of trusting incremental updates.
    Resync,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manage_error_display_matches_the_core_wording() {
        assert_eq!(
            ManageError::SecretNameTaken { name: "KEY".into() }.to_string(),
            "secret name \"KEY\" is already in use"
        );
        assert_eq!(
            ManageError::WrongSecretCount {
                kind: "postgres".into()
            }
            .to_string(),
            "postgres tools bind exactly one secret"
        );
    }

    #[test]
    fn manage_error_round_trips_through_json() {
        let error = ManageError::InvalidConnectionField {
            field: ConnectionField::HostKeyFingerprint,
            message: "Enter an OpenSSH SHA-256 or SHA-512 fingerprint".into(),
        };
        let json = serde_json::to_string(&error).unwrap();
        assert!(json.contains("\"code\":\"invalid_connection_field\""));
        let back: ManageError = serde_json::from_str(&json).unwrap();
        assert_eq!(back, error);
    }

    #[test]
    fn connection_dto_serializes_kind_as_type() {
        let dto = ConnectionDto {
            id: "id".into(),
            name: "github".into(),
            updated_at: "2026-07-29T12:00:00.000000000Z".into(),
            kind: "api".into(),
            target: "https://api.github.com".into(),
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
            account: None,
            oauth_spec: None,
            last_status: None,
            last_detail: None,
            last_checked_at: None,
            signer: None,
            client_cert_path: None,
            client_key_path: None,
        };
        let value = serde_json::to_value(&dto).unwrap();
        assert_eq!(value["type"], "api");
        assert_eq!(value["updated_at"], "2026-07-29T12:00:00.000000000Z");
        // Optional config fields serialize as null (the webview relies on
        // their presence), while agent_access omits its absent options.
        assert!(value.as_object().unwrap().contains_key("host"));
        assert!(value["host"].is_null());
        assert!(!value["agent_access"]
            .as_object()
            .unwrap()
            .contains_key("allowed_tools"));
    }

    #[test]
    fn manage_events_tag_themselves() {
        let event = ManageEvent::ActivityAppended {
            entry: ActivityDto {
                icon: "plug".into(),
                tone: "neutral".into(),
                kind: Some("connection_added".into()),
                text: "Connection added".into(),
                detail: None,
                agent: None,
                connection: None,
                outcome: None,
                protocol: None,
                duration_ms: None,
                approver: None,
                surface: None,
                confirmation: None,
                at: "2026-01-01T00:00:00Z".into(),
            },
        };
        let value = serde_json::to_value(&event).unwrap();
        assert_eq!(value["event"], "activity_appended");
        assert_eq!(value["entry"]["icon"], "plug");

        let expiry = serde_json::to_value(ManageEvent::ApprovalExpired {
            id: "request-id".into(),
        })
        .unwrap();
        assert_eq!(expiry["event"], "approval_expired");
        assert_eq!(expiry["id"], "request-id");

        let secrets = serde_json::to_value(ManageEvent::SecretsChanged).unwrap();
        assert_eq!(secrets["event"], "secrets_changed");
    }
}
