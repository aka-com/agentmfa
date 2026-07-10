use thiserror::Error;

/// A connection field whose authoritative validation failed. Keeping this
/// structured lets desktop clients attach the error to the relevant input
/// without parsing human-readable error strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

/// Core-level errors. Daemon handlers map these onto wire responses with
/// machine-readable `{"reason": …}` bodies (DESIGN.md §4).
#[derive(Debug, Error)]
pub enum CoreError {
    #[error("secret name {0:?} is already in use")]
    SecretNameTaken(String),

    #[error("connection name {0:?} is already in use")]
    ConnectionNameTaken(String),

    #[error("no such secret")]
    SecretNotFound,

    #[error("no such connection")]
    ConnectionNotFound,

    #[error("approval connection changed; review a fresh prompt before saving a rule")]
    ApprovalConnectionChanged,

    #[error("secret is in use by connection(s): {}", .0.join(", "))]
    SecretInUse(Vec<String>),

    #[error("invalid name {0:?}: names are 1-64 chars of [A-Za-z0-9_] not starting with a digit")]
    InvalidSecretName(String),

    #[error("invalid connection name {0:?}: 1-64 chars of [a-z0-9-_]")]
    InvalidConnectionName(String),

    #[error("invalid template: {0}")]
    Template(#[from] crate::template::TemplateError),

    #[error("template references unknown secret {0:?}")]
    UnknownTemplateRef(String),

    #[error("{kind} connections bind exactly one secret")]
    WrongSecretCount { kind: &'static str },

    #[error("invalid connection config: {0}")]
    InvalidConnectionConfig(String),

    #[error("invalid connection field {field:?}: {message}")]
    InvalidConnectionField {
        field: ConnectionField,
        message: String,
    },

    #[error("a connection's type is fixed after creation")]
    KindChange,

    #[error("Secret read was not authenticated")]
    SecretReadNotAuthenticated,

    #[error("the native confirmation did not complete; nothing was applied")]
    NotConfirmed,

    #[error("another broker is already listening on {0}")]
    BrokerAlreadyRunning(String),

    #[error("keychain: {0}")]
    Vault(String),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("state file is corrupt: {0}")]
    CorruptState(#[from] serde_json::Error),

    #[error("state file {0} failed integrity verification (possible tampering); refusing to load")]
    StateTampered(String),
}
