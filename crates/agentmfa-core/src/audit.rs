//! Structured audit log.
//!
//! Pairing, policy decisions, brokered calls, and vault-touching UI actions
//! like reveal/copy emit entries to the activity view and are appended to
//! `~/Library/Application Support/agentmfa/audit.jsonl` on a best-effort
//! basis. Append failures are logged but do not fail the associated operation.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

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
    /// Session byte counts for WS/PG sessions.
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditKind {
    // Pairing lifecycle
    PairRequested,
    Paired,
    PairDenied,
    TokenRevoked,
    PeerIdentityMismatch,
    // Requests + decisions
    Requested,
    AllowedOnce,
    GrantStarted,
    GrantExpired,
    GrantRevoked,
    AutoAllowed,
    Denied,
    ApprovalTimeout,
    Abandoned,
    Listed,
    // Rules
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
    // Vault + config actions from the UI
    SecretAdded,
    SecretUpdated,
    SecretDeleted,
    SecretRevealed,
    SecretCopied,
    ConnectionAdded,
    ConnectionUpdated,
    ConnectionDeleted,
    /// A user-initiated connectivity/credential test from the UI.
    ConnectionTested,
    SettingsChanged,
    // Rate limiting / budgets
    RateLimited,
}

impl AuditKind {
    /// Vendored Lucide icon key used by the activity view.
    pub fn icon(&self) -> &'static str {
        match self {
            AuditKind::PairRequested => "userRoundPlus",
            AuditKind::Paired => "userRoundCheck",
            AuditKind::PairDenied => "userRoundX",
            AuditKind::TokenRevoked => "unplug",
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
            AuditKind::RuleSaved => "shieldPlus",
            AuditKind::RuleRemoved => "shieldMinus",
            AuditKind::HttpExecuted => "globe",
            AuditKind::SessionOpened => "logIn",
            AuditKind::SessionClosed => "logOut",
            AuditKind::SshSigned => "keyRound",
            AuditKind::SshHostKeyPinned => "lock",
            AuditKind::SecretAdded => "fileKey",
            AuditKind::SecretUpdated => "pencil",
            AuditKind::SecretDeleted => "trash",
            AuditKind::SecretRevealed => "eye",
            AuditKind::SecretCopied => "clipboardCopy",
            AuditKind::ConnectionAdded => "plug",
            AuditKind::ConnectionUpdated => "pencil",
            AuditKind::ConnectionDeleted => "unplug",
            AuditKind::ConnectionTested => "flaskConical",
            AuditKind::SettingsChanged => "gear",
            AuditKind::RateLimited => "gauge",
        }
    }

    /// Restrained semantic color used by the activity icon. Ordinary events
    /// stay neutral; color is reserved for outcomes that benefit from it.
    pub fn tone(&self) -> &'static str {
        match self {
            AuditKind::Paired | AuditKind::AllowedOnce | AuditKind::AutoAllowed => "success",
            AuditKind::PairRequested | AuditKind::Requested | AuditKind::GrantStarted => "warning",
            AuditKind::PairDenied
            | AuditKind::TokenRevoked
            | AuditKind::PeerIdentityMismatch
            | AuditKind::GrantRevoked
            | AuditKind::Denied
            | AuditKind::ApprovalTimeout
            | AuditKind::RateLimited => "danger",
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

/// JSONL writer plus a tail reader for the activity view.
pub struct AuditLog {
    path: PathBuf,
    file: Mutex<std::fs::File>,
    /// Observers (the UI event bridge) notified on every append.
    listeners: Mutex<Vec<AuditListener>>,
}

impl AuditLog {
    pub fn open(path: PathBuf) -> Result<Self> {
        if let Some(dir) = path.parent() {
            crate::paths::create_private_dir(dir)?;
        }
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        Ok(Self {
            path,
            file: Mutex::new(file),
            listeners: Mutex::new(Vec::new()),
        })
    }

    /// Register an observer called (synchronously) for every appended entry.
    pub fn subscribe(&self, f: impl Fn(&AuditEntry) + Send + Sync + 'static) {
        self.listeners.lock().unwrap().push(Box::new(f));
    }

    /// Notify live listeners even if durable persistence fails. The activity
    /// log is an operator aid, not a transaction or tamper-evident ledger.
    pub fn append(&self, entry: AuditEntry) {
        {
            let mut file = self.file.lock().unwrap();
            match serde_json::to_string(&entry) {
                Ok(line) => {
                    if let Err(e) = writeln!(file, "{line}") {
                        tracing::error!("audit append failed: {e}");
                    }
                }
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
    pub fn clear(&self) -> Result<()> {
        let file = self.file.lock().unwrap();
        file.set_len(0)?;
        file.sync_data()?;
        Ok(())
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

        let mut entries = Vec::with_capacity(limit);
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
