//! Structured audit log.
//!
//! Pairing, policy decisions, brokered calls, and vault-touching UI actions
//! like reveal/copy emit entries to the activity view and are appended to
//! `~/Library/Application Support/aka/audit.jsonl` on a best-effort
//! basis. Append failures are logged but do not fail the associated operation.
//!
//! # Tamper evidence
//!
//! The log is the record of what the broker did with the user's credentials,
//! so a local process that can write the data directory must not be able to
//! edit or quietly shorten it. Every entry therefore carries a `mac` chained
//! onto the entry before it ([`StateIntegrity::chain`]), keyed from the
//! Keychain: editing or inserting a line breaks that line and every line
//! after it.
//!
//! A chain alone cannot see a truncation — lopping entries off the tail
//! leaves a shorter but self-consistent chain — so the head of the chain and
//! the number of entries under it live in `audit-seal.json`, sealed whole by
//! [`StateIntegrity`]. [`AuditLog::verify`] replays the chain and checks it
//! arrives at the sealed head with the sealed count.
//!
//! Appending is still best-effort and still never fails the operation it
//! describes. The line is written first and the head resealed after, so a
//! crash in between leaves entries the seal does not yet cover — reported as
//! [`AuditIntegrity::Unsealed`], distinct from tampering, because those
//! entries still carry MACs only the key could have produced.
//!
//! Entries written before this existed have no `mac`. They are counted once,
//! at adoption, as [`AuditIntegrity::Verified::legacy`] and excluded from the
//! chain: unverifiable by construction, and reported as such rather than
//! silently vouched for.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead as _, BufReader, Read as _, Seek as _, SeekFrom, Write as _};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::integrity::StateIntegrity;
use crate::types::{ConfirmationMethod, DecisionContext, DecisionSurface};
use crate::Result;

const TAIL_CHUNK_BYTES: usize = 16 * 1024;
const MAX_AUDIT_LINE_BYTES: usize = 1024 * 1024;

/// Schema version written on every new entry. Entries with no `v` field
/// predate versioning and read back as version 1.
///
/// History: v1 — unversioned entries (typed columns only, machine facts
/// sometimes embedded in `text`/`detail` prose); v2 — adds `v` and the
/// structured `fields` map; every fact an aggregator would query lives in
/// a typed column or `fields`, and `text`/`detail` are presentation only.
pub const AUDIT_SCHEMA_VERSION: u32 = 2;

fn schema_v1() -> u32 {
    1
}

/// One audit entry. `kind` is the stable machine key; `text`/`detail` are
/// the human strings the activity view renders.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Schema version (see [`AUDIT_SCHEMA_VERSION`]).
    #[serde(default = "schema_v1")]
    pub v: u32,
    pub ts: DateTime<Utc>,
    pub kind: AuditKind,
    /// Human-readable summary ("claude-code requested github").
    pub text: String,
    /// Optional second line ("GET api.github.com/user/repos").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
    /// Matching rule for rule-based allows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<Uuid>,
    /// Decision attribution: the deciding principal (absent for the
    /// local machine's single user), the surface the decision came from,
    /// and how a required decision confirmation was satisfied (absent
    /// when no confirmation was required).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approver: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub surface: Option<DecisionSurface>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirmation: Option<ConfirmationMethod>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    /// Session byte counts for data-plane sessions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes_up: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes_down: Option<u64>,
    /// Structured machine-readable facts that have no dedicated column:
    /// counts, old/new names, methods, targets. Anything a future
    /// aggregator would query belongs here (or in a typed column above),
    /// never only in `text`/`detail` prose.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, serde_json::Value>,
    /// This entry's link in the tamper-evidence chain: HMAC over the previous
    /// entry's `mac` and this entry's own JSON with `mac` omitted. Written by
    /// [`AuditLog::append`], absent on entries predating it, and never set by
    /// the builders — an entry's content must not be able to name its own MAC.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditKind {
    // Pairing lifecycle
    /// Retained so activity logs written by older versions still deserialize.
    /// Registration is immediate now; nothing emits this.
    PairRequested,
    Paired,
    /// Retained so activity logs written by older versions still deserialize.
    /// Registration is immediate now; nothing emits this.
    PairDenied,
    TokenRevoked,
    ManagementTokenIssued,
    ManagementTokenRevoked,
    ManagementTokenExpired,
    AuthenticationFailed,
    /// Retained so activity logs written by older versions still deserialize.
    /// Peer identity verification was removed; nothing emits this.
    PeerIdentityMismatch,
    // Requests + decisions. Most decision kinds are retained only so
    // activity logs written by older versions still deserialize; with the
    // wiring model there are no prompts, grants, or per-request decisions.
    Requested,
    /// Retained for older logs; nothing emits this.
    AllowedOnce,
    /// Retained for older logs; nothing emits this.
    GrantStarted,
    /// Retained for older logs; nothing emits this.
    GrantExpired,
    /// Retained for older logs; nothing emits this.
    GrantRevoked,
    AutoAllowed,
    Denied,
    /// Retained for older logs; nothing emits this.
    ApprovalTimeout,
    /// Retained for older logs; nothing emits this.
    Abandoned,
    Listed,
    // Wirings (and their standing-rule ancestors, retained for older logs)
    Wired,
    Unwired,
    /// Retained for older logs; nothing emits this.
    RuleSaved,
    RuleRemoved,
    // Upstream execution / sessions
    HttpExecuted,
    SessionOpened,
    SessionClosed,
    /// One SSH signature issued (or refused) by the agent adapter.
    SshSigned,
    /// An SSH host key pinned trust-on-first-use at the first agent
    /// session-bind (outcome `pinned`), or that trust denied (`denied`).
    SshHostKeyPinned,
    /// A Postgres session asked for TLS under `sslmode=prefer`, the server
    /// refused, and the session continued in clear text with the stored
    /// credential.
    TlsDowngraded,
    /// Statements observed on a brokered Postgres session, recorded when
    /// statement auditing is enabled for the broker.
    PgStatements,
    // Vault + config actions from the UI
    SecretAdded,
    SecretUpdated,
    SecretDeleted,
    /// Retained so activity logs written by older versions still deserialize.
    /// New prefix reveals do not create activity entries.
    SecretRevealed,
    SecretCopied,
    ConnectionAdded,
    ConnectionUpdated,
    ConnectionDeleted,
    /// A guarded MCP account-status tool was invoked by a management-plane
    /// status check. Retained name keeps older activity logs compatible.
    ConnectionTested,
    // MCP sign-in (OAuth) outcomes
    McpAuthCompleted,
    McpAuthFailed,
    /// An expiring MCP access token was silently renewed with the stored
    /// refresh token.
    McpTokenRefreshed,
    /// A silent renewal attempt failed (the status check's Reconnect path
    /// is the recovery).
    McpTokenRefreshFailed,
    /// An agent asked for a tool that is not configured. A request only:
    /// nothing exists until the user adds and wires it in the app.
    ConnectRequested,
    /// The user deliberately cleared the preceding activity. This is written
    /// as the first entry of the fresh log so a clear never erases itself.
    ActivityCleared,
    SettingsChanged,
    // Rate limiting / budgets
    RateLimited,
    /// On-disk state failed its integrity seal: the activity log's chain, or
    /// the advisory health file. Recorded rather than merely logged, because
    /// the log is where the user would go looking afterwards.
    IntegrityAlert,
}

impl AuditKind {
    /// Vendored Lucide icon key used by the activity view.
    pub fn icon(&self) -> &'static str {
        match self {
            AuditKind::PairRequested => "userRoundPlus",
            AuditKind::Paired => "userRoundCheck",
            AuditKind::PairDenied => "userRoundX",
            AuditKind::TokenRevoked => "unplug",
            AuditKind::ManagementTokenIssued => "keyRound",
            AuditKind::ManagementTokenRevoked => "keyRound",
            AuditKind::ManagementTokenExpired => "clockAlert",
            AuditKind::AuthenticationFailed => "shieldAlert",
            AuditKind::PeerIdentityMismatch => "shieldAlert",
            AuditKind::Requested => "bell",
            AuditKind::AllowedOnce => "circleCheck",
            AuditKind::GrantStarted => "timer",
            AuditKind::GrantExpired => "timerOff",
            AuditKind::GrantRevoked => "shieldX",
            AuditKind::AutoAllowed => "zap",
            AuditKind::Denied => "circleX",
            AuditKind::ApprovalTimeout => "clockAlert",
            AuditKind::Abandoned => "circleSlash",
            AuditKind::Listed => "list",
            AuditKind::Wired => "plug",
            AuditKind::Unwired => "unplug",
            AuditKind::RuleSaved => "shieldPlus",
            AuditKind::RuleRemoved => "shieldMinus",
            AuditKind::HttpExecuted => "globe",
            AuditKind::SessionOpened => "logIn",
            AuditKind::SessionClosed => "logOut",
            AuditKind::SshSigned => "keyRound",
            AuditKind::SshHostKeyPinned => "lock",
            AuditKind::TlsDowngraded => "shieldAlert",
            AuditKind::PgStatements => "database",
            AuditKind::SecretAdded => "fileKey",
            AuditKind::SecretUpdated => "pencil",
            AuditKind::SecretDeleted => "trash",
            AuditKind::SecretRevealed => "eye",
            AuditKind::SecretCopied => "clipboardCopy",
            AuditKind::ConnectionAdded => "plug",
            AuditKind::ConnectionUpdated => "pencil",
            AuditKind::ConnectionDeleted => "unplug",
            AuditKind::ConnectionTested => "flaskConical",
            AuditKind::McpAuthCompleted => "circleCheck",
            AuditKind::McpAuthFailed => "circleX",
            AuditKind::McpTokenRefreshed => "refresh",
            AuditKind::ConnectRequested => "botMessageSquare",
            AuditKind::McpTokenRefreshFailed => "circleX",
            AuditKind::ActivityCleared => "trash",
            AuditKind::SettingsChanged => "gear",
            AuditKind::RateLimited => "gauge",
            AuditKind::IntegrityAlert => "shieldAlert",
        }
    }

    /// Restrained semantic color used by the activity icon. Ordinary events
    /// stay neutral; color is reserved for outcomes that benefit from it.
    pub fn tone(&self) -> &'static str {
        match self {
            AuditKind::Paired
            | AuditKind::AllowedOnce
            | AuditKind::AutoAllowed
            | AuditKind::McpAuthCompleted => "success",
            AuditKind::PairRequested
            | AuditKind::Requested
            | AuditKind::GrantStarted
            | AuditKind::ConnectRequested => "warning",
            AuditKind::PairDenied
            | AuditKind::TokenRevoked
            | AuditKind::ManagementTokenRevoked
            | AuditKind::ManagementTokenExpired
            | AuditKind::AuthenticationFailed
            | AuditKind::PeerIdentityMismatch
            | AuditKind::GrantRevoked
            | AuditKind::Denied
            | AuditKind::ApprovalTimeout
            | AuditKind::McpAuthFailed
            | AuditKind::McpTokenRefreshFailed
            | AuditKind::RateLimited
            | AuditKind::IntegrityAlert => "danger",
            // A downgrade is not a refusal — the session worked — but it is
            // the one outcome here the user would want to notice.
            AuditKind::TlsDowngraded => "warning",
            _ => "neutral",
        }
    }
}

impl AuditEntry {
    pub fn new(kind: AuditKind, text: impl Into<String>) -> Self {
        Self {
            v: AUDIT_SCHEMA_VERSION,
            ts: Utc::now(),
            kind,
            text: text.into(),
            detail: None,
            agent: None,
            connection: None,
            outcome: None,
            rule_id: None,
            approver: None,
            surface: None,
            confirmation: None,
            duration_ms: None,
            bytes_up: None,
            bytes_down: None,
            fields: BTreeMap::new(),
            mac: None,
        }
    }
    /// Attach a structured fact (see the `fields` doc).
    pub fn field(mut self, key: &str, value: impl Into<serde_json::Value>) -> Self {
        self.fields.insert(key.to_string(), value.into());
        self
    }
    /// Attach decision attribution: who decided and from which surface.
    pub fn context(mut self, ctx: &DecisionContext) -> Self {
        self.approver = ctx.approver.clone();
        self.surface = Some(ctx.surface);
        self
    }
    pub fn confirmation(mut self, method: ConfirmationMethod) -> Self {
        self.confirmation = Some(method);
        self
    }
    /// For actions gated in only one direction: records how the change was
    /// authorized when it took a gate, and leaves the field absent when the
    /// same call in the other direction did not need one.
    pub fn maybe_confirmation(mut self, method: Option<ConfirmationMethod>) -> Self {
        self.confirmation = method;
        self
    }
    pub fn detail(mut self, d: impl Into<String>) -> Self {
        self.detail = Some(d.into());
        self
    }
    pub fn agent(mut self, a: impl Into<String>) -> Self {
        self.agent = Some(a.into());
        self
    }
    pub fn connection(mut self, c: impl Into<String>) -> Self {
        self.connection = Some(c.into());
        self
    }
    pub fn outcome(mut self, o: impl Into<String>) -> Self {
        self.outcome = Some(o.into());
        self
    }
    pub fn rule(mut self, id: Uuid) -> Self {
        self.rule_id = Some(id);
        self
    }
    pub fn duration_ms(mut self, ms: u64) -> Self {
        self.duration_ms = Some(ms);
        self
    }
    pub fn bytes(mut self, up: u64, down: u64) -> Self {
        self.bytes_up = Some(up);
        self.bytes_down = Some(down);
        self
    }
}

/// Observer callback notified on every appended entry.
type AuditListener = Box<dyn Fn(&AuditEntry) + Send + Sync>;

/// The chain head at the start of a log, before any entry is linked on.
/// Entries are already bound to the file by the basename argument, so this
/// only has to be a fixed starting point.
const CHAIN_GENESIS: &str = "";

/// The sealed record of how far the chain has been carried. Written whole
/// through [`StateIntegrity`], so a process that cannot forge the MAC cannot
/// walk `sealed` back to hide a truncation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct AuditSeal {
    /// Chain head after the last sealed entry, hex.
    #[serde(default)]
    head: String,
    /// Entries the chain covers, not counting `legacy`.
    #[serde(default)]
    sealed: u64,
    /// Leading entries that predate sealing. Unverifiable by construction:
    /// counted once at adoption so the chain knows where to start, and
    /// reported so they are never mistaken for verified ones.
    #[serde(default)]
    legacy: u64,
}

impl AuditSeal {
    fn genesis() -> Self {
        Self {
            head: CHAIN_GENESIS.to_string(),
            sealed: 0,
            legacy: 0,
        }
    }
}

/// What [`AuditLog::verify`] found. Anything other than `Verified` is worth
/// showing the user: the log is the record they would consult after a
/// suspected compromise, and one that cannot vouch for itself should say so
/// rather than read as a clean history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditIntegrity {
    /// Every chained entry verified and the chain arrived at the sealed head.
    Verified {
        /// Entries covered by the chain.
        entries: u64,
        /// Leading entries that predate sealing and cannot be checked.
        legacy: u64,
    },
    /// The chain verified as far as the seal covers, and the entries past it
    /// carry valid MACs too — the shape a crash between the append and the
    /// reseal leaves behind. Forged entries cannot land here: they would need
    /// the key to chain.
    Unsealed { entries: u64, trailing: u64 },
    /// An entry does not match its MAC, entries the seal counted are gone, or
    /// the seal itself failed to load.
    Tampered { detail: String },
}

impl AuditIntegrity {
    pub fn is_verified(&self) -> bool {
        matches!(self, Self::Verified { .. })
    }

    /// One line for the audit entry and the process log.
    pub fn summary(&self) -> String {
        match self {
            Self::Verified { entries, legacy: 0 } => {
                format!("activity log verified ({entries} entries)")
            }
            Self::Verified { entries, legacy } => format!(
                "activity log verified ({entries} entries; {legacy} predate sealing and \
                 cannot be checked)"
            ),
            Self::Unsealed { entries, trailing } => format!(
                "activity log verified ({entries} entries); {trailing} newer entries are not \
                 covered by the sealed head yet, which is what an interrupted shutdown leaves"
            ),
            Self::Tampered { detail } => format!("activity log integrity check failed: {detail}"),
        }
    }
}

/// JSONL writer plus a tail reader for the activity view.
pub struct AuditLog {
    path: PathBuf,
    file: Mutex<std::fs::File>,
    /// Observers (the UI event bridge) notified on every append.
    listeners: Mutex<Vec<AuditListener>>,
    /// Absent for the unsealed logs tests build directly; every log the
    /// broker opens has one.
    seal: Option<SealState>,
}

struct SealState {
    integrity: Arc<StateIntegrity>,
    seal_path: PathBuf,
    /// Guarded by the same lock as the file so a line and the head it
    /// produces can never be written out of order.
    head: Mutex<AuditSeal>,
}

impl AuditLog {
    /// Open without tamper evidence. For tests and for callers that have no
    /// vault; the broker uses [`Self::open_sealed`].
    pub fn open(path: PathBuf) -> Result<Self> {
        Self::open_inner(path, None)
    }

    /// Open with per-entry chaining against `integrity`, sealing the chain
    /// head into `seal_path`.
    ///
    /// A log that already has entries but no seal is *adopted*: its existing
    /// lines are counted as legacy and the chain starts after them. That is
    /// the only honest migration — the broker cannot retroactively vouch for
    /// bytes written before it held a key — and unlike the whole-file seal it
    /// is not restricted to first-key-use, because sealing the activity log
    /// is new for installs whose key was established long ago.
    pub fn open_sealed(
        path: PathBuf,
        seal_path: PathBuf,
        integrity: Arc<StateIntegrity>,
    ) -> Result<Self> {
        let log = Self::open_inner(
            path,
            Some(SealState {
                integrity,
                seal_path,
                head: Mutex::new(AuditSeal::genesis()),
            }),
        )?;
        log.load_or_adopt_seal()?;
        Ok(log)
    }

    fn open_inner(path: PathBuf, seal: Option<SealState>) -> Result<Self> {
        if let Some(dir) = path.parent() {
            crate::paths::create_private_dir(dir)?;
        }
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        Ok(Self {
            path,
            file: Mutex::new(file),
            listeners: Mutex::new(Vec::new()),
            seal,
        })
    }

    /// Load the sealed head, or adopt the current file as the legacy baseline
    /// when there is no seal yet.
    fn load_or_adopt_seal(&self) -> Result<()> {
        let Some(seal) = self.seal.as_ref() else {
            return Ok(());
        };
        let loaded = match seal.integrity.read_verified(&seal.seal_path) {
            Ok(Some(bytes)) => serde_json::from_slice::<AuditSeal>(&bytes).ok(),
            // A seal that fails verification is a real signal, but refusing to
            // start would turn a tampered log into a denial of service on the
            // whole broker. Keep the finding for `verify` to report and carry
            // on with a fresh chain over whatever is already there.
            Ok(None) => None,
            Err(error) => {
                tracing::error!("activity log seal did not verify: {error}");
                None
            }
        };
        let seal_value = match loaded {
            Some(loaded) => loaded,
            None => {
                let existing = count_lines(&self.path)?;
                let adopted = AuditSeal {
                    head: CHAIN_GENESIS.to_string(),
                    sealed: 0,
                    legacy: existing,
                };
                if existing > 0 {
                    tracing::info!(
                        "adopting {existing} existing activity entries as unsealed legacy; \
                         tamper evidence starts from the next entry"
                    );
                }
                Self::persist_seal(seal, &adopted);
                adopted
            }
        };
        *seal.head.lock().unwrap() = seal_value;
        Ok(())
    }

    fn persist_seal(seal: &SealState, value: &AuditSeal) {
        match serde_json::to_vec(value) {
            Ok(bytes) => {
                if let Err(error) = seal.integrity.write(&seal.seal_path, &bytes) {
                    tracing::error!("could not seal the activity log head: {error}");
                }
            }
            Err(error) => tracing::error!("could not serialize the activity log head: {error}"),
        }
    }

    /// Register an observer called (synchronously) for every appended entry.
    pub fn subscribe(&self, f: impl Fn(&AuditEntry) + Send + Sync + 'static) {
        self.listeners.lock().unwrap().push(Box::new(f));
    }

    /// Notify live listeners even if durable persistence fails. The activity
    /// log is an operator aid, so a failure here never fails the operation
    /// being described — but what does land is chained, so it can be checked.
    pub fn append(&self, mut entry: AuditEntry) {
        {
            let mut file = self.file.lock().unwrap();
            // A caller must not be able to dictate its own entry's MAC.
            entry.mac = None;
            let mut head = self.seal.as_ref().map(|seal| seal.head.lock().unwrap());

            // Encode once bare to chain over, then again carrying the MAC.
            // `verify` re-runs exactly this round trip, so the two encodings
            // have to agree — they do, because the struct's field order is
            // fixed and `fields` is a `BTreeMap`.
            let line = serde_json::to_string(&entry).and_then(|bare| {
                match (self.seal.as_ref(), head.as_deref()) {
                    (Some(seal), Some(head)) => {
                        entry.mac = Some(seal.integrity.chain(
                            &basename(&self.path),
                            &head.head,
                            bare.as_bytes(),
                        ));
                        serde_json::to_string(&entry)
                    }
                    _ => Ok(bare),
                }
            });

            match line {
                Ok(line) => match writeln!(file, "{line}") {
                    Ok(()) => {
                        // Reseal after the line, not before: an interruption
                        // here leaves entries the head does not cover yet,
                        // which `verify` tells apart from tampering, whereas
                        // the reverse order would look like a truncation.
                        if let (Some(seal), Some(head), Some(mac)) =
                            (self.seal.as_ref(), head.as_deref_mut(), entry.mac.clone())
                        {
                            head.head = mac;
                            head.sealed += 1;
                            Self::persist_seal(seal, head);
                        }
                    }
                    Err(e) => {
                        tracing::error!("audit append failed: {e}");
                        // Nothing landed, so the chain must not move.
                        entry.mac = None;
                    }
                },
                Err(e) => tracing::error!("audit serialize failed: {e}"),
            }
        }
        for listener in self.listeners.lock().unwrap().iter() {
            listener(&entry);
        }
    }

    /// Remove all persisted activity while keeping the log ready for new
    /// entries. Clearing and appending share the writer lock so an entry can
    /// never be partially truncated.
    ///
    /// The chain restarts from genesis. Clearing is a deliberate management
    /// action that goes through the broker's own gates; a tamperer with only
    /// file access cannot reach it, and truncating the file behind the
    /// broker's back leaves the sealed head pointing at entries that are gone.
    pub fn clear(&self) -> Result<()> {
        let file = self.file.lock().unwrap();
        let head = self.seal.as_ref().map(|seal| seal.head.lock().unwrap());
        file.set_len(0)?;
        file.sync_data()?;
        if let (Some(seal), Some(mut head)) = (self.seal.as_ref(), head) {
            *head = AuditSeal::genesis();
            Self::persist_seal(seal, &head);
        }
        Ok(())
    }

    /// Replay the chain and compare it with the sealed head.
    ///
    /// Reads the whole file, so this is a startup and on-demand check rather
    /// than something on the append path.
    pub fn verify(&self) -> AuditIntegrity {
        let Some(seal) = self.seal.as_ref() else {
            return AuditIntegrity::Verified {
                entries: 0,
                legacy: 0,
            };
        };
        // Hold the writer lock so an append cannot move the head underneath
        // the replay and manufacture a mismatch.
        let _writer = self.file.lock().unwrap();
        let expected = seal.head.lock().unwrap().clone();
        let basename = basename(&self.path);

        let file = match File::open(&self.path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return if expected.sealed == 0 {
                    AuditIntegrity::Verified {
                        entries: 0,
                        legacy: expected.legacy,
                    }
                } else {
                    AuditIntegrity::Tampered {
                        detail: format!("the log is gone; {} entries were sealed", expected.sealed),
                    }
                };
            }
            Err(error) => {
                return AuditIntegrity::Tampered {
                    detail: format!("the log could not be read: {error}"),
                }
            }
        };

        let mut head = CHAIN_GENESIS.to_string();
        let mut chained: u64 = 0;
        let mut index: u64 = 0;
        for line in BufReader::new(file).lines() {
            let Ok(line) = line else {
                return AuditIntegrity::Tampered {
                    detail: format!("entry {} could not be read", index + 1),
                };
            };
            if line.trim().is_empty() {
                continue;
            }
            index += 1;
            // The legacy prefix predates the key; it is counted, not checked.
            if index <= expected.legacy {
                continue;
            }
            let Ok(entry) = serde_json::from_str::<AuditEntry>(&line) else {
                return AuditIntegrity::Tampered {
                    detail: format!("entry {index} is not valid JSON"),
                };
            };
            let Some(found) = entry.mac.as_deref() else {
                return AuditIntegrity::Tampered {
                    detail: format!("entry {index} carries no MAC"),
                };
            };
            let mut bare = entry.clone();
            bare.mac = None;
            let Ok(body) = serde_json::to_string(&bare) else {
                return AuditIntegrity::Tampered {
                    detail: format!("entry {index} could not be re-encoded"),
                };
            };
            let computed = seal.integrity.chain(&basename, &head, body.as_bytes());
            if !seal.integrity.chain_matches(&computed, found) {
                return AuditIntegrity::Tampered {
                    detail: format!("entry {index} does not match its MAC"),
                };
            }
            head = computed;
            chained += 1;
        }

        if chained < expected.sealed {
            return AuditIntegrity::Tampered {
                detail: format!(
                    "{} sealed entries are missing ({chained} of {} remain)",
                    expected.sealed - chained,
                    expected.sealed
                ),
            };
        }
        if chained > expected.sealed {
            // Every one of these chained, so only the key could have written
            // them; the seal simply did not get resealed before shutdown.
            return AuditIntegrity::Unsealed {
                entries: expected.sealed,
                trailing: chained - expected.sealed,
            };
        }
        if !seal.integrity.chain_matches(&head, &expected.head) {
            return AuditIntegrity::Tampered {
                detail: "the chain does not arrive at the sealed head".to_string(),
            };
        }
        AuditIntegrity::Verified {
            entries: chained,
            legacy: expected.legacy,
        }
    }

    /// Newest-first tail for the activity view. Unparseable lines are
    /// skipped (the log survives partial writes). Reads backward and stops
    /// after `limit` valid entries so refresh cost does not grow with the log.
    pub fn recent(&self, limit: usize) -> Vec<AuditEntry> {
        if limit == 0 {
            return Vec::new();
        }
        let Ok(mut file) = File::open(&self.path) else {
            return Vec::new();
        };
        let Ok(mut position) = file.seek(SeekFrom::End(0)) else {
            return Vec::new();
        };

        // Callers may use usize::MAX for an explicitly unbounded management
        // read. Grow with the data instead of trying to reserve that sentinel.
        let mut entries = Vec::with_capacity(limit.min(1_024));
        let mut chunk = vec![0u8; TAIL_CHUNK_BYTES];
        let mut reversed_line = Vec::new();
        let mut oversized = false;

        while position > 0 && entries.len() < limit {
            let read_len = position.min(TAIL_CHUNK_BYTES as u64) as usize;
            position -= read_len as u64;
            if file.seek(SeekFrom::Start(position)).is_err()
                || file.read_exact(&mut chunk[..read_len]).is_err()
            {
                break;
            }

            for &byte in chunk[..read_len].iter().rev() {
                if byte == b'\n' {
                    push_reversed_entry(&mut entries, &mut reversed_line, oversized);
                    oversized = false;
                    if entries.len() == limit {
                        break;
                    }
                } else if !oversized {
                    if reversed_line.len() < MAX_AUDIT_LINE_BYTES {
                        reversed_line.push(byte);
                    } else {
                        reversed_line.clear();
                        oversized = true;
                    }
                }
            }
        }

        if entries.len() < limit {
            push_reversed_entry(&mut entries, &mut reversed_line, oversized);
        }
        entries
    }
}

/// The file's own name, mixed into every MAC so a chain cannot be lifted out
/// of one sealed file and dropped into another.
fn basename(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// Count the non-empty lines already in a log, for adoption.
fn count_lines(path: &Path) -> Result<u64> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error.into()),
    };
    let mut count = 0;
    for line in BufReader::new(file).lines() {
        if !line?.trim().is_empty() {
            count += 1;
        }
    }
    Ok(count)
}

fn push_reversed_entry(
    entries: &mut Vec<AuditEntry>,
    reversed_line: &mut Vec<u8>,
    oversized: bool,
) {
    if !oversized && !reversed_line.is_empty() {
        reversed_line.reverse();
        if let Ok(entry) = serde_json::from_slice(reversed_line) {
            entries.push(entry);
        }
    }
    reversed_line.clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_and_tail() {
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::open(dir.path().join("audit.jsonl")).unwrap();
        log.append(
            AuditEntry::new(AuditKind::PairRequested, "Pair request from claude-code")
                .agent("claude-code"),
        );
        log.append(
            AuditEntry::new(AuditKind::Requested, "claude-code requested github")
                .agent("claude-code")
                .connection("github")
                .detail("GET api.github.com/user/repos"),
        );
        let recent = log.recent(10);
        assert_eq!(recent.len(), 2);
        // newest first
        assert_eq!(recent[0].kind, AuditKind::Requested);
        assert_eq!(recent[0].connection.as_deref(), Some("github"));
        assert_eq!(recent[1].kind, AuditKind::PairRequested);
    }

    #[test]
    fn listeners_fire() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::open(dir.path().join("audit.jsonl")).unwrap();
        let count = Arc::new(AtomicUsize::new(0));
        let c2 = count.clone();
        log.subscribe(move |_| {
            c2.fetch_add(1, Ordering::SeqCst);
        });
        log.append(AuditEntry::new(AuditKind::SecretAdded, "Secret added: X"));
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn clear_removes_history_and_allows_future_appends() {
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::open(dir.path().join("audit.jsonl")).unwrap();
        log.append(AuditEntry::new(AuditKind::SecretAdded, "before clear"));

        log.clear().unwrap();
        assert!(log.recent(10).is_empty());

        log.append(AuditEntry::new(AuditKind::SecretAdded, "after clear"));
        let recent = log.recent(10);
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].text, "after clear");
    }

    /* --------------------------- tamper evidence -------------------------- */

    async fn sealed_log(dir: &Path) -> (AuditLog, Arc<StateIntegrity>, PathBuf) {
        let integrity = Arc::new(
            StateIntegrity::open(&crate::vault::MemoryVault::new())
                .await
                .unwrap(),
        );
        let path = dir.join("audit.jsonl");
        let log = AuditLog::open_sealed(
            path.clone(),
            dir.join("audit-seal.json"),
            integrity.clone(),
        )
        .unwrap();
        (log, integrity, path)
    }

    fn reopen(dir: &Path, integrity: Arc<StateIntegrity>) -> AuditLog {
        AuditLog::open_sealed(
            dir.join("audit.jsonl"),
            dir.join("audit-seal.json"),
            integrity,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn a_sealed_log_verifies_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let (log, integrity, _) = sealed_log(dir.path()).await;
        for n in 0..3 {
            log.append(AuditEntry::new(AuditKind::SecretAdded, format!("entry {n}")));
        }
        assert_eq!(
            log.verify(),
            AuditIntegrity::Verified {
                entries: 3,
                legacy: 0
            }
        );
        // The head survives the process, so the chain keeps running rather
        // than restarting (which would forgive a truncation across restarts).
        let reopened = reopen(dir.path(), integrity);
        reopened.append(AuditEntry::new(AuditKind::SecretAdded, "entry 3"));
        assert_eq!(
            reopened.verify(),
            AuditIntegrity::Verified {
                entries: 4,
                legacy: 0
            }
        );
    }

    #[tokio::test]
    async fn an_edited_entry_is_caught() {
        let dir = tempfile::tempdir().unwrap();
        let (log, integrity, path) = sealed_log(dir.path()).await;
        log.append(AuditEntry::new(AuditKind::Denied, "Refused: agent → prod-db"));
        log.append(AuditEntry::new(AuditKind::SecretAdded, "after"));

        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, text.replace("Refused", "Allowed")).unwrap();

        assert!(matches!(
            reopen(dir.path(), integrity).verify(),
            AuditIntegrity::Tampered { .. }
        ));
    }

    /// The case a per-line MAC cannot see on its own: the remaining prefix is
    /// a perfectly valid chain, and only the sealed count and head give it away.
    #[tokio::test]
    async fn a_truncated_tail_is_caught() {
        let dir = tempfile::tempdir().unwrap();
        let (log, integrity, path) = sealed_log(dir.path()).await;
        for n in 0..4 {
            log.append(AuditEntry::new(AuditKind::SecretAdded, format!("entry {n}")));
        }
        let text = std::fs::read_to_string(&path).unwrap();
        let kept: Vec<&str> = text.lines().take(2).collect();
        std::fs::write(&path, format!("{}\n", kept.join("\n"))).unwrap();

        match reopen(dir.path(), integrity).verify() {
            AuditIntegrity::Tampered { detail } => {
                assert!(detail.contains("missing"), "{detail}");
            }
            other => panic!("expected a truncation to be caught, got {other:?}"),
        }
    }

    /// Deleting the whole log is the crudest version of the same attack.
    #[tokio::test]
    async fn a_deleted_log_is_caught() {
        let dir = tempfile::tempdir().unwrap();
        let (log, integrity, path) = sealed_log(dir.path()).await;
        log.append(AuditEntry::new(AuditKind::SecretAdded, "entry"));
        std::fs::remove_file(&path).unwrap();
        assert!(matches!(
            reopen(dir.path(), integrity).verify(),
            AuditIntegrity::Tampered { .. }
        ));
    }

    #[tokio::test]
    async fn forged_entries_cannot_be_appended_without_the_key() {
        let dir = tempfile::tempdir().unwrap();
        let (log, integrity, path) = sealed_log(dir.path()).await;
        log.append(AuditEntry::new(AuditKind::SecretAdded, "real"));

        let forged = serde_json::to_string(&AuditEntry::new(
            AuditKind::AutoAllowed,
            "invented after the fact",
        ))
        .unwrap();
        let mut text = std::fs::read_to_string(&path).unwrap();
        text.push_str(&forged);
        text.push('\n');
        std::fs::write(&path, text).unwrap();

        match reopen(dir.path(), integrity).verify() {
            AuditIntegrity::Tampered { detail } => assert!(detail.contains("MAC"), "{detail}"),
            other => panic!("expected a forged entry to be caught, got {other:?}"),
        }
    }

    /// A crash between the append and the reseal leaves entries the head does
    /// not cover. They still chained, so only the key could have written them:
    /// that is a distinct report, not an accusation.
    #[tokio::test]
    async fn entries_past_the_sealed_head_read_as_unsealed() {
        let dir = tempfile::tempdir().unwrap();
        let (log, integrity, _) = sealed_log(dir.path()).await;
        for n in 0..3 {
            log.append(AuditEntry::new(AuditKind::SecretAdded, format!("entry {n}")));
        }
        // Rewind the seal to where it would have been one append earlier.
        let rewound = {
            let head = log.seal.as_ref().unwrap().head.lock().unwrap();
            AuditSeal {
                head: CHAIN_GENESIS.to_string(),
                sealed: 0,
                legacy: head.legacy,
            }
        };
        AuditLog::persist_seal(log.seal.as_ref().unwrap(), &rewound);

        assert_eq!(
            reopen(dir.path(), integrity).verify(),
            AuditIntegrity::Unsealed {
                entries: 0,
                trailing: 3
            }
        );
    }

    /// Sealing is new for installs whose key is years old, so an existing log
    /// is adopted rather than refused — and reported as unverifiable rather
    /// than counted as verified.
    #[tokio::test]
    async fn existing_entries_are_adopted_as_legacy() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        {
            let bare = AuditLog::open(path.clone()).unwrap();
            bare.append(AuditEntry::new(AuditKind::SecretAdded, "from before"));
            bare.append(AuditEntry::new(AuditKind::SecretAdded, "also from before"));
        }
        let (log, _integrity, _) = sealed_log(dir.path()).await;
        log.append(AuditEntry::new(AuditKind::SecretAdded, "sealed from here on"));
        assert_eq!(
            log.verify(),
            AuditIntegrity::Verified {
                entries: 1,
                legacy: 2
            }
        );
        assert_eq!(log.recent(10).len(), 3, "adoption reads back every entry");
    }

    #[tokio::test]
    async fn clearing_restarts_the_chain() {
        let dir = tempfile::tempdir().unwrap();
        let (log, integrity, _) = sealed_log(dir.path()).await;
        log.append(AuditEntry::new(AuditKind::SecretAdded, "before clear"));
        log.clear().unwrap();
        log.append(AuditEntry::new(AuditKind::SecretAdded, "after clear"));
        assert_eq!(
            reopen(dir.path(), integrity).verify(),
            AuditIntegrity::Verified {
                entries: 1,
                legacy: 0
            }
        );
    }

    /// The MAC is derived, never dictated: an entry that arrives claiming one
    /// has it replaced before anything is chained or written.
    #[tokio::test]
    async fn a_caller_supplied_mac_is_discarded() {
        let dir = tempfile::tempdir().unwrap();
        let (log, _integrity, _) = sealed_log(dir.path()).await;
        let mut entry = AuditEntry::new(AuditKind::SecretAdded, "entry");
        entry.mac = Some("de1e7ed".into());
        log.append(entry);
        assert!(log.verify().is_verified());
        assert_ne!(log.recent(1)[0].mac.as_deref(), Some("de1e7ed"));
    }

    #[test]
    fn activity_metadata_uses_restrained_semantic_tones() {
        assert_eq!(AuditKind::AutoAllowed.icon(), "zap");
        assert_eq!(AuditKind::AutoAllowed.tone(), "success");
        assert_eq!(AuditKind::Requested.tone(), "warning");
        assert_eq!(AuditKind::Denied.tone(), "danger");
        assert_eq!(AuditKind::SecretCopied.tone(), "neutral");
    }

    #[test]
    fn schema_is_versioned_and_legacy_entries_read_as_v1() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let log = AuditLog::open(path.clone()).unwrap();
        log.append(
            AuditEntry::new(AuditKind::SecretUpdated, "Secret updated: X")
                .field("renamed_from", "X_OLD")
                .field("templates_rewritten", 2),
        );
        // A pre-versioning line: no `v`, no `fields`.
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .and_then(|mut f| {
                writeln!(
                    f,
                    r#"{{"ts":"2026-01-01T00:00:00Z","kind":"secret_added","text":"Secret added: Y"}}"#
                )
            })
            .unwrap();
        let recent = log.recent(10);
        assert_eq!(recent[0].v, 1, "legacy entry defaults to v1");
        assert!(recent[0].fields.is_empty());
        assert_eq!(recent[1].v, AUDIT_SCHEMA_VERSION);
        assert_eq!(recent[1].fields["renamed_from"], "X_OLD");
        assert_eq!(recent[1].fields["templates_rewritten"], 2);
    }

    #[test]
    fn corrupt_lines_are_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let log = AuditLog::open(path.clone()).unwrap();
        log.append(AuditEntry::new(AuditKind::SecretAdded, "ok"));
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .and_then(|mut f| writeln!(f, "{{not json"))
            .unwrap();
        log.append(AuditEntry::new(AuditKind::SecretDeleted, "also ok"));
        assert_eq!(log.recent(10).len(), 2);
    }

    #[test]
    fn tail_is_bounded_and_newest_first_for_large_logs() {
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::open(dir.path().join("audit.jsonl")).unwrap();
        for i in 0..1_000 {
            log.append(AuditEntry::new(
                AuditKind::Requested,
                format!("request {i}"),
            ));
        }

        let recent = log.recent(25);
        assert_eq!(recent.len(), 25);
        assert_eq!(recent.first().unwrap().text, "request 999");
        assert_eq!(recent.last().unwrap().text, "request 975");
        assert!(log.recent(0).is_empty());
        assert_eq!(
            log.recent(usize::MAX).len(),
            1_000,
            "an unbounded management read grows with the log"
        );
    }

    #[test]
    fn invalid_utf8_before_the_tail_does_not_hide_recent_entries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        std::fs::write(&path, [0xff, b'\n']).unwrap();
        let log = AuditLog::open(path).unwrap();
        log.append(AuditEntry::new(AuditKind::SecretAdded, "recent"));

        let recent = log.recent(1);
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].text, "recent");
    }
}
