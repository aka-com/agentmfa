use thiserror::Error;

/// A connection field whose authoritative validation failed. Defined in
/// `aka-api` (it crosses the management wire); re-exported here so core
/// callers keep their `crate::error::ConnectionField` path.
pub use aka_api::ConnectionField;

/// Core-level errors. Daemon handlers map these onto wire responses with
/// machine-readable `{"reason": …}` bodies.
#[derive(Debug, Error)]
pub enum CoreError {
    #[error("secret name {0:?} is already in use")]
    SecretNameTaken(String),

    #[error("tool name {0:?} is already in use")]
    ConnectionNameTaken(String),

    #[error("an equivalent target is already saved as tool {0:?}")]
    ConnectionTargetTaken(String),

    #[error("no such secret")]
    SecretNotFound,

    #[error("no such tool")]
    ConnectionNotFound,

    #[error("the tool changed after you read it; review the latest settings and try again")]
    ConnectionChanged,

    #[error("the tool changed while you were confirming; review it and save again")]
    ApprovalConnectionChanged,

    #[error("secret is in use by tool(s): {}", .0.join(", "))]
    SecretInUse(Vec<String>),

    #[error("invalid name {0:?}: names are 1-64 chars of [A-Za-z0-9_] not starting with a digit")]
    InvalidSecretName(String),

    #[error(
        "invalid tool name {0:?}: use 1-64 ASCII letters, numbers, spaces, or safe endpoint punctuation; start with a letter or number and do not end with a space"
    )]
    InvalidConnectionName(String),

    #[error("invalid template: {0}")]
    Template(#[from] crate::template::TemplateError),

    #[error("template references unknown secret {0:?}")]
    UnknownTemplateRef(String),

    #[error("{kind} tools bind exactly one secret")]
    WrongSecretCount { kind: &'static str },

    #[error("invalid tool config: {0}")]
    InvalidConnectionConfig(String),

    #[error("invalid setting: {0}")]
    InvalidSetting(String),

    #[error("invalid tool field {field:?}: {message}")]
    InvalidConnectionField {
        field: ConnectionField,
        message: String,
    },

    #[error("a tool's type is fixed after creation")]
    KindChange,

    #[error("no such endpoint")]
    EndpointNotFound,

    #[error("too many direct endpoints ({0}); revoke one before issuing another")]
    EndpointLimit(usize),

    #[error("enable this tool for agents before issuing a direct endpoint")]
    EndpointRequiresWiring,

    #[error("Secret read was not authenticated")]
    SecretReadNotAuthenticated,

    #[error("the native confirmation did not complete; nothing was applied")]
    NotConfirmed,

    #[error("{0}")]
    ProposalCredential(String),

    #[error("the proposing agent is no longer connected with the token that made this request")]
    ProposalStale,

    #[error("another broker is already listening on {0}")]
    BrokerAlreadyRunning(String),

    #[error(
        "another CLI process is editing broker state{}",
        .0.map(|pid| format!(" (pid {pid})")).unwrap_or_default()
    )]
    BrokerStateBusy(Option<u32>),

    #[error("OAuth: {0}")]
    OAuth(String),

    #[error("keychain: {0}")]
    Vault(String),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("state file is corrupt: {0}")]
    CorruptState(#[from] serde_json::Error),

    #[error("state file {0} failed integrity verification (possible tampering); refusing to load")]
    StateTampered(String),

    #[error(
        "state file {path} uses schema version {found}, but this build supports up to {supported}; upgrade AKA before opening this store"
    )]
    UnsupportedStateVersion {
        path: String,
        found: u32,
        supported: u32,
    },
}
