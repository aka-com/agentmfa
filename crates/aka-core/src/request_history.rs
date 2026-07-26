//! Bounded lifecycle history for requests that entered a human-decision flow.
//!
//! The active approval registry owns whether traffic may proceed. This store
//! is deliberately observational: it records what the broker attempted to
//! surface and its terminal disposition so management clients can render a
//! Recent section without reconstructing request lifecycles from audit prose.
//!
//! History is process-local. That keeps potentially sensitive summaries out
//! of a second durable file while still surviving webview restarts and remote
//! management reconnects. The audit log remains the durable security record.

use std::collections::VecDeque;
use std::sync::Mutex;

use chrono::{DateTime, Duration, Utc};
use uuid::Uuid;

use crate::approvals::{ApprovalUnit, PendingApproval};
use crate::elicitations::PendingElicitation;
use crate::types::ConnectionKind;

const TERMINAL_RETENTION: Duration = Duration::days(7);
const TERMINAL_CAP: usize = 500;

/// The protocol-level family of a request. Approvals and upstream MCP
/// elicitations share this lifecycle and the same bounded history.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestKind {
    Approval,
    Elicitation,
}

impl RequestKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Approval => "approval",
            Self::Elicitation => "elicitation",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestStatus {
    Pending,
    Approved,
    Denied,
    Expired,
    Revoked,
    Unavailable,
    Abandoned,
}

impl RequestStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Denied => "denied",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
            Self::Unavailable => "unavailable",
            Self::Abandoned => "abandoned",
        }
    }
}

/// Why a request reached its terminal status. Status is the compact UI state;
/// resolution preserves the behavior that produced it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestResolution {
    ApprovedForWindow,
    ApprovedAll,
    Denied,
    TimedOut,
    PolicyChanged,
    NoSurface,
    ConfirmationDisabled,
    Waived,
    CallerDisconnected,
    InputProvided,
    InputRefused,
}

impl RequestResolution {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ApprovedForWindow => "approved_for_window",
            Self::ApprovedAll => "approved_all",
            Self::Denied => "denied",
            Self::TimedOut => "timed_out",
            Self::PolicyChanged => "policy_changed",
            Self::NoSurface => "no_surface",
            Self::ConfirmationDisabled => "confirmation_disabled",
            Self::Waived => "waived",
            Self::CallerDisconnected => "caller_disconnected",
            Self::InputProvided => "input_provided",
            Self::InputRefused => "input_refused",
        }
    }

    fn status(self) -> RequestStatus {
        match self {
            Self::ApprovedForWindow
            | Self::ApprovedAll
            | Self::ConfirmationDisabled
            | Self::Waived
            | Self::InputProvided => RequestStatus::Approved,
            Self::Denied | Self::InputRefused => RequestStatus::Denied,
            Self::TimedOut => RequestStatus::Expired,
            Self::PolicyChanged => RequestStatus::Revoked,
            Self::NoSurface => RequestStatus::Unavailable,
            Self::CallerDisconnected => RequestStatus::Abandoned,
        }
    }
}

/// One request from creation through resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestRecord {
    pub id: Uuid,
    pub kind: RequestKind,
    pub status: RequestStatus,
    pub connection_id: Option<Uuid>,
    pub connection: String,
    pub connection_kind: Option<ConnectionKind>,
    pub unit: Option<ApprovalUnit>,
    pub target: Option<String>,
    pub agent: String,
    pub summary: String,
    pub detail: Option<String>,
    pub waiting: usize,
    pub requested_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub resolution: Option<RequestResolution>,
    pub window_secs: Option<u64>,
}

impl From<&PendingApproval> for RequestRecord {
    fn from(pending: &PendingApproval) -> Self {
        Self {
            id: pending.id,
            kind: RequestKind::Approval,
            status: RequestStatus::Pending,
            connection_id: Some(pending.connection_id),
            connection: pending.connection.clone(),
            connection_kind: Some(pending.kind),
            unit: Some(pending.unit),
            target: Some(pending.target.clone()),
            agent: pending.agent.clone(),
            summary: pending.summary.clone(),
            detail: pending.detail.clone(),
            waiting: pending.waiting,
            requested_at: pending.requested_at,
            expires_at: Some(pending.expires_at),
            resolved_at: None,
            resolution: None,
            window_secs: Some(pending.window_secs),
        }
    }
}

impl From<&PendingElicitation> for RequestRecord {
    fn from(pending: &PendingElicitation) -> Self {
        Self {
            id: pending.id,
            kind: RequestKind::Elicitation,
            status: RequestStatus::Pending,
            connection_id: Some(pending.connection_id),
            connection: pending.connection.clone(),
            // An elicitation is scoped to its tool call, not a connection
            // transport unit, so the approval-shaped fields stay empty.
            connection_kind: None,
            unit: None,
            target: None,
            agent: pending.agent.clone(),
            summary: pending.tool.clone(),
            detail: Some(pending.message.clone()),
            waiting: 1,
            requested_at: pending.requested_at,
            expires_at: Some(pending.expires_at),
            resolved_at: None,
            resolution: None,
            window_secs: None,
        }
    }
}

/// Thread-safe request history shared by every clone of the approval registry.
#[derive(Default)]
pub struct RequestHistory {
    records: Mutex<VecDeque<RequestRecord>>,
}

impl RequestHistory {
    /// Insert a request before publishing its first change event. UUIDs are
    /// global across request kinds so one lifecycle cannot overwrite another.
    pub fn record(&self, record: RequestRecord) {
        let mut records = self.records.lock().unwrap();
        if records.iter().any(|existing| existing.id == record.id) {
            return;
        }
        records.push_back(record);
        Self::prune(&mut records, Utc::now());
    }

    /// Insert a new approval before publishing its change event.
    pub fn record_approval(&self, pending: &PendingApproval) {
        self.record(RequestRecord::from(pending));
    }

    /// Insert a new elicitation before publishing its change event.
    pub fn record_elicitation(&self, pending: &PendingElicitation) {
        self.record(RequestRecord::from(pending));
    }

    /// Refresh coalesced waiter counts while the prompt remains pending.
    pub fn update_approval(&self, pending: &PendingApproval) {
        let mut records = self.records.lock().unwrap();
        if let Some(record) = records
            .iter_mut()
            .find(|record| record.id == pending.id && record.status == RequestStatus::Pending)
        {
            record.waiting = pending.waiting;
            record.expires_at = Some(pending.expires_at);
        }
    }

    /// Resolve once. A late timeout or duplicate response cannot rewrite the
    /// disposition already shown to the user.
    pub fn resolve(&self, id: &Uuid, resolution: RequestResolution) -> bool {
        self.resolve_at(id, resolution, Utc::now())
    }

    fn resolve_at(
        &self,
        id: &Uuid,
        resolution: RequestResolution,
        resolved_at: DateTime<Utc>,
    ) -> bool {
        let mut records = self.records.lock().unwrap();
        let Some(record) = records
            .iter_mut()
            .find(|record| &record.id == id && record.status == RequestStatus::Pending)
        else {
            return false;
        };
        record.status = resolution.status();
        record.resolution = Some(resolution);
        record.resolved_at = Some(resolved_at);
        Self::prune(&mut records, resolved_at);
        true
    }

    /// Newest state change first. Pending records use their request time;
    /// terminal records use their resolution time.
    pub fn records(&self) -> Vec<RequestRecord> {
        let mut records = self.records.lock().unwrap();
        Self::prune(&mut records, Utc::now());
        let mut snapshot: Vec<_> = records.iter().cloned().collect();
        snapshot.sort_by(|left, right| {
            let left_at = left.resolved_at.unwrap_or(left.requested_at);
            let right_at = right.resolved_at.unwrap_or(right.requested_at);
            right_at
                .cmp(&left_at)
                .then_with(|| right.requested_at.cmp(&left.requested_at))
                .then_with(|| right.id.cmp(&left.id))
        });
        snapshot
    }

    fn prune(records: &mut VecDeque<RequestRecord>, now: DateTime<Utc>) {
        let cutoff = now - TERMINAL_RETENTION;
        records.retain(|record| {
            record.status == RequestStatus::Pending
                || record
                    .resolved_at
                    .is_none_or(|resolved_at| resolved_at >= cutoff)
        });

        let mut terminal_count = records
            .iter()
            .filter(|record| record.status != RequestStatus::Pending)
            .count();
        while terminal_count > TERMINAL_CAP {
            let Some(index) = records
                .iter()
                .enumerate()
                .filter(|(_, record)| record.status != RequestStatus::Pending)
                .min_by_key(|(_, record)| record.resolved_at.unwrap_or(record.requested_at))
                .map(|(index, _)| index)
            else {
                break;
            };
            records.remove(index);
            terminal_count -= 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pending(id: Uuid, requested_at: DateTime<Utc>) -> PendingApproval {
        PendingApproval {
            id,
            connection_id: Uuid::new_v4(),
            connection: "github".into(),
            kind: ConnectionKind::Api,
            unit: ApprovalUnit::Request,
            target: "https://api.github.com".into(),
            agent: "codex".into(),
            summary: "GET /user".into(),
            detail: None,
            consequence: None,
            waiting: 1,
            requested_at,
            expires_at: requested_at + Duration::seconds(90),
            window_secs: 900,
        }
    }

    #[test]
    fn approval_lifecycle_is_one_correlated_record() {
        let history = RequestHistory::default();
        let id = Uuid::new_v4();
        let mut prompt = pending(id, Utc::now());

        history.record_approval(&prompt);
        prompt.waiting = 3;
        history.update_approval(&prompt);
        assert!(history.resolve(&id, RequestResolution::ApprovedForWindow));
        assert!(!history.resolve(&id, RequestResolution::TimedOut));

        let records = history.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].waiting, 3);
        assert_eq!(records[0].status, RequestStatus::Approved);
        assert_eq!(
            records[0].resolution,
            Some(RequestResolution::ApprovedForWindow)
        );
        assert!(records[0].resolved_at.is_some());
    }

    #[test]
    fn retention_never_evicts_pending_records() {
        let history = RequestHistory::default();
        let old = Utc::now() - Duration::days(8);
        let terminal_id = Uuid::new_v4();
        let pending_id = Uuid::new_v4();
        history.record_approval(&pending(terminal_id, old));
        history.record_approval(&pending(pending_id, old));
        assert!(history.resolve_at(
            &terminal_id,
            RequestResolution::Denied,
            old + Duration::seconds(1)
        ));

        let records = history.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].id, pending_id);
        assert_eq!(records[0].status, RequestStatus::Pending);
    }

    #[test]
    fn terminal_history_is_bounded() {
        let history = RequestHistory::default();
        let base = Utc::now();
        let pending_id = Uuid::new_v4();
        let resolved_last_id = Uuid::new_v4();
        history.record_approval(&pending(pending_id, base));
        history.record_approval(&pending(resolved_last_id, base));
        let mut oldest_terminal_id = None;
        for offset in 0..TERMINAL_CAP {
            let id = Uuid::new_v4();
            oldest_terminal_id.get_or_insert(id);
            let at = base + Duration::milliseconds(offset as i64);
            history.record_approval(&pending(id, at));
            assert!(history.resolve_at(&id, RequestResolution::Denied, at));
        }
        assert!(history.resolve_at(
            &resolved_last_id,
            RequestResolution::Denied,
            base + Duration::milliseconds(TERMINAL_CAP as i64)
        ));

        let records = history.records();
        assert_eq!(
            records
                .iter()
                .filter(|record| record.status != RequestStatus::Pending)
                .count(),
            TERMINAL_CAP
        );
        assert!(records.iter().any(|record| record.id == pending_id));
        assert!(
            records.iter().any(|record| record.id == resolved_last_id),
            "the oldest-created record was resolved most recently and must survive"
        );
        assert!(
            records
                .iter()
                .all(|record| Some(record.id) != oldest_terminal_id),
            "the oldest terminal outcome should be evicted"
        );
    }
}
