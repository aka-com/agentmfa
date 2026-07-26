//! Data-plane tickets and live sessions.
//!
//! PG DSN tickets and SSH agent-socket tickets are 128-bit random values that
//! expire 60 s after issue. A ticket may be redeemed any number of times
//! within that window, each redemption opening its own proxied session, all
//! under the single approval. Concurrent sessions are
//! bounded at two levels, a per-ticket cap (default 60) inside a global
//! backstop (default 300), with distinct reasons naming the budget hit.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde::Serialize;
use tokio::sync::Notify;
use uuid::Uuid;

use crate::audit::{AuditEntry, AuditKind, AuditLog};
use crate::events::BrokerEvents;
use crate::types::{Connection, ConnectionKind};
use crate::wire::ErrorReason;

/// User-facing audit label for a data-plane connection.
fn kind_label(kind: ConnectionKind) -> &'static str {
    match kind {
        ConnectionKind::Pg => "Postgres",
        ConnectionKind::Ssh => "SSH",
        ConnectionKind::Api => "API",
    }
}

struct TicketEntry {
    agent: String,
    connection: Connection,
    issued: Instant,
    active_sessions: usize,
    secret_read_authorization: Option<crate::authorization::SecretReadAuthorization>,
    invalidated: bool,
}

/// One live bridged/proxied session, as shown in the live-sessions band.
#[derive(Debug, Clone, Serialize)]
pub struct SessionInfo {
    pub id: u64,
    pub kind: ConnectionKind,
    pub agent: String,
    pub connection: String,
    /// Pinned target, e.g. `user@host:port/db`.
    pub detail: String,
    pub opened_at: DateTime<Utc>,
}

struct SessionEntry {
    info: SessionInfo,
    /// The ticket that opened this session, or `None` for a session served by
    /// a per-wiring direct endpoint (which has no ticket).
    ticket: Option<String>,
    /// The direct endpoint that opened this session, when one did. Lets a
    /// wiring revocation close exactly the endpoint's live sessions.
    endpoint_id: Option<Uuid>,
    /// The connection this session was opened against. Endpoint sessions are
    /// reachable through `endpoint_id`, but a ticket session is not — and it
    /// outlives its ticket by up to `session_max_ttl`, so disabling or
    /// deleting the connection needs this to reach it.
    connection_id: Uuid,
    close: Arc<Notify>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum RedeemError {
    /// Unknown value (or long-gone ticket).
    Unknown,
    /// Past its 60 s window.
    Expired,
    /// This approval's session budget is exhausted.
    TicketSessionLimit,
    /// The broker-wide backstop is exhausted.
    BrokerSessionLimit,
}

impl RedeemError {
    pub fn reason(&self) -> ErrorReason {
        match self {
            RedeemError::Unknown => ErrorReason::UnknownTicket,
            RedeemError::Expired => ErrorReason::TicketExpired,
            RedeemError::TicketSessionLimit => ErrorReason::TicketSessionLimit,
            RedeemError::BrokerSessionLimit => ErrorReason::BrokerSessionLimit,
        }
    }
    /// HTTP status for the data-plane response.
    pub fn status(&self) -> u16 {
        match self {
            RedeemError::Unknown => 404,
            RedeemError::Expired => 410,
            RedeemError::TicketSessionLimit | RedeemError::BrokerSessionLimit => 503,
        }
    }
}

/// A successful redemption: a reserved budget slot plus what the session
/// needs to establish itself. Dropping it without `start(…)` releases the
/// slot (failed upstream dial must not leak budget).
pub struct Redemption {
    plane: Arc<DataPlaneInner>,
    ticket: String,
    pub agent: String,
    pub connection: Connection,
    pub(crate) secret_read_authorization: Option<crate::authorization::SecretReadAuthorization>,
    started: bool,
}

/// Handles a running session task holds.
pub struct SessionHandle {
    plane: Arc<DataPlaneInner>,
    pub id: u64,
    pub close_signal: Arc<Notify>,
    pub bytes_up: Arc<AtomicU64>,
    pub bytes_down: Arc<AtomicU64>,
    kind: ConnectionKind,
    agent: String,
    connection: String,
}

struct DataPlaneInner {
    ticket_ttl: Duration,
    per_ticket: usize,
    global: usize,
    audit: Arc<AuditLog>,
    events: Arc<dyn BrokerEvents>,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    tickets: HashMap<String, TicketEntry>,
    sessions: HashMap<u64, SessionEntry>,
    next_session: u64,
}

#[derive(Clone)]
pub struct DataPlane {
    inner: Arc<DataPlaneInner>,
}

fn mint_ticket() -> String {
    let mut buf = [0u8; 16]; // 128-bit
    getrandom::fill(&mut buf).expect("os rng");
    let hex: String = buf.iter().map(|b| format!("{b:02x}")).collect();
    format!("tkt_{hex}")
}

impl DataPlane {
    pub fn new(
        ticket_ttl: Duration,
        per_ticket: usize,
        global: usize,
        audit: Arc<AuditLog>,
        events: Arc<dyn BrokerEvents>,
    ) -> Self {
        Self {
            inner: Arc::new(DataPlaneInner {
                ticket_ttl,
                per_ticket,
                global,
                audit,
                events,
                state: Mutex::new(State::default()),
            }),
        }
    }

    /// Issue a ticket under one approval.
    pub fn issue(&self, agent: &str, connection: &Connection) -> String {
        let value = mint_ticket();
        let mut state = self.inner.state.lock().unwrap();
        Self::sweep(&self.inner, &mut state);
        state.tickets.insert(
            value.clone(),
            TicketEntry {
                agent: agent.to_string(),
                connection: connection.clone(),
                issued: Instant::now(),
                active_sessions: 0,
                secret_read_authorization: crate::authorization::current(),
                invalidated: false,
            },
        );
        value
    }

    /// Redeem a ticket for a new session slot. Budget is reserved here and
    /// released if the redemption is dropped before `start`.
    pub fn redeem(&self, value: &str) -> Result<Redemption, RedeemError> {
        let mut state = self.inner.state.lock().unwrap();
        Self::sweep(&self.inner, &mut state);
        let global_active = state.sessions.len();
        let entry = state.tickets.get_mut(value).ok_or(RedeemError::Unknown)?;
        if entry.invalidated {
            return Err(RedeemError::Expired);
        }
        if entry.issued.elapsed() > self.inner.ticket_ttl {
            return Err(RedeemError::Expired);
        }
        // Fail fast with the budget it hit.
        if entry.active_sessions >= self.inner.per_ticket {
            return Err(RedeemError::TicketSessionLimit);
        }
        if global_active >= self.inner.global {
            return Err(RedeemError::BrokerSessionLimit);
        }
        entry.active_sessions += 1;
        Ok(Redemption {
            plane: self.inner.clone(),
            ticket: value.to_string(),
            agent: entry.agent.clone(),
            connection: entry.connection.clone(),
            secret_read_authorization: entry.secret_read_authorization.clone(),
            started: false,
        })
    }

    /// Register a live session served by a per-wiring **direct endpoint**.
    /// Unlike the ticket path there is no redemption to reserve a slot ahead
    /// of the upstream dial, so the global backstop is enforced here at
    /// registration (the per-ticket cap does not apply — an endpoint is not a
    /// ticket). The session is tagged with its `endpoint_id` so revoking the
    /// wiring can close exactly its sessions.
    pub fn start_endpoint_session(
        &self,
        agent: &str,
        connection: &Connection,
        endpoint_id: Uuid,
        kind: ConnectionKind,
    ) -> Result<SessionHandle, RedeemError> {
        let inner = self.inner.clone();
        let mut state = inner.state.lock().unwrap();
        Self::sweep(&inner, &mut state);
        if state.sessions.len() >= inner.global {
            return Err(RedeemError::BrokerSessionLimit);
        }
        state.next_session += 1;
        let id = state.next_session;
        let info = SessionInfo {
            id,
            kind,
            agent: agent.to_string(),
            connection: connection.name.clone(),
            detail: connection.target(),
            opened_at: Utc::now(),
        };
        let close = Arc::new(Notify::new());
        let bytes_up = Arc::new(AtomicU64::new(0));
        let bytes_down = Arc::new(AtomicU64::new(0));
        state.sessions.insert(
            id,
            SessionEntry {
                info: info.clone(),
                ticket: None,
                endpoint_id: Some(endpoint_id),
                connection_id: connection.id,
                close: close.clone(),
            },
        );
        drop(state);
        inner.audit.append(
            AuditEntry::new(
                AuditKind::SessionOpened,
                format!("{} session opened: {}", kind_label(kind), info.connection),
            )
            .agent(info.agent.clone())
            .connection(info.connection.clone())
            .detail(info.detail.clone())
            .field("kind", kind.as_str())
            .field("target", info.detail.clone())
            .field("session_id", id)
            .field("via", "endpoint"),
        );
        inner.events.sessions_changed();
        Ok(SessionHandle {
            plane: inner,
            id,
            close_signal: close,
            bytes_up,
            bytes_down,
            kind,
            agent: agent.to_string(),
            connection: connection.name.clone(),
        })
    }

    /// Live sessions for the UI band.
    pub fn sessions(&self) -> Vec<SessionInfo> {
        let state = self.inner.state.lock().unwrap();
        let mut sessions: Vec<SessionInfo> =
            state.sessions.values().map(|s| s.info.clone()).collect();
        sessions.sort_by_key(|s| s.id);
        sessions
    }

    /// User-initiated close from the immediate remediation control.
    /// Returns whether the session existed.
    pub fn close_session(&self, id: u64) -> bool {
        let state = self.inner.state.lock().unwrap();
        match state.sessions.get(&id) {
            Some(entry) => {
                entry.close.notify_one();
                true
            }
            None => false,
        }
    }

    /// Invalidate every unredeemed capability and close every live transport,
    /// regardless of which agent opened it. Rotating the shared key must not
    /// leave the old generation's data-plane capabilities usable.
    pub fn close_all(&self) -> usize {
        let mut state = self.inner.state.lock().unwrap();
        for ticket in state.tickets.values_mut() {
            ticket.invalidated = true;
        }
        let sessions: Vec<_> = state
            .sessions
            .values()
            .map(|session| session.close.clone())
            .collect();
        let count = sessions.len();
        drop(state);
        for close in sessions {
            // One transport waits on each session. `notify_one` retains a
            // permit if closure races the transport beginning its wait.
            close.notify_one();
        }
        count
    }

    /// Withdraw a connection from the data plane: invalidate every ticket
    /// issued against it and close every live session it is serving.
    ///
    /// Refusing the *next* open is not enough for pg/ssh, whose sessions run
    /// to `session_max_ttl` (an hour) once established, nor for an
    /// already-issued ticket still inside its redemption window. Disabling or
    /// deleting a connection has to reach both, or "turn it off" leaves an
    /// authenticated upstream connection running against the credential the
    /// user just revoked.
    pub fn close_connection_sessions(&self, connection_id: &Uuid) -> usize {
        let mut state = self.inner.state.lock().unwrap();
        for ticket in state.tickets.values_mut() {
            if ticket.connection.id != *connection_id {
                continue;
            }
            ticket.invalidated = true;
        }
        let sessions: Vec<_> = state
            .sessions
            .values()
            .filter(|session| session.connection_id == *connection_id)
            .map(|session| session.close.clone())
            .collect();
        let count = sessions.len();
        drop(state);
        for close in sessions {
            // One transport waits on each session. Preserve a permit in case
            // revocation races the transport beginning its close wait.
            close.notify_one();
        }
        count
    }

    /// Close every live session a per-wiring direct endpoint is serving.
    /// Unlike a ticket (short-lived; the next open is simply refused), an
    /// endpoint grants standing access, so revoking its wiring must chase down
    /// established sessions rather than wait them out. Returns how many were
    /// signalled.
    pub fn close_endpoint_sessions(&self, endpoint_id: &Uuid) -> usize {
        let state = self.inner.state.lock().unwrap();
        let sessions: Vec<_> = state
            .sessions
            .values()
            .filter(|session| session.endpoint_id.as_ref() == Some(endpoint_id))
            .map(|session| session.close.clone())
            .collect();
        let count = sessions.len();
        drop(state);
        for close in sessions {
            // One transport waits on each session. Preserve a permit if
            // revocation races the transport beginning its close wait.
            close.notify_one();
        }
        count
    }

    /// Drop long-expired tickets (closing any unclaimed pre-dialed upstream
    /// by dropping it). Freshly-expired tickets are kept for a grace period
    /// so a late redemption gets the informative `410 ticket_expired`
    /// rather than a bare 404.
    fn sweep(inner: &DataPlaneInner, state: &mut State) {
        let keep_until = inner.ticket_ttl + Duration::from_secs(600);
        state
            .tickets
            .retain(|_, t| t.active_sessions > 0 || t.issued.elapsed() <= keep_until);
    }
}

impl Redemption {
    /// Establishments succeeded: register the live session.
    pub fn start(mut self, kind: ConnectionKind) -> SessionHandle {
        self.started = true;
        let inner = self.plane.clone();
        let mut state = inner.state.lock().unwrap();
        state.next_session += 1;
        let id = state.next_session;
        let info = SessionInfo {
            id,
            kind,
            agent: self.agent.clone(),
            connection: self.connection.name.clone(),
            detail: self.connection.target(),
            opened_at: Utc::now(),
        };
        let close = Arc::new(Notify::new());
        let bytes_up = Arc::new(AtomicU64::new(0));
        let bytes_down = Arc::new(AtomicU64::new(0));
        state.sessions.insert(
            id,
            SessionEntry {
                info: info.clone(),
                ticket: Some(self.ticket.clone()),
                endpoint_id: None,
                connection_id: self.connection.id,
                close: close.clone(),
            },
        );
        drop(state);
        inner.audit.append(
            AuditEntry::new(
                AuditKind::SessionOpened,
                format!("{} session opened: {}", kind_label(kind), info.connection),
            )
            .agent(info.agent.clone())
            .connection(info.connection.clone())
            .detail(info.detail.clone())
            .field("kind", kind.as_str())
            .field("target", info.detail.clone())
            .field("session_id", id),
        );
        inner.events.sessions_changed();
        SessionHandle {
            plane: inner,
            id,
            close_signal: close,
            bytes_up,
            bytes_down,
            kind,
            agent: self.agent.clone(),
            connection: self.connection.name.clone(),
        }
    }
}

impl Drop for Redemption {
    fn drop(&mut self) {
        if self.started {
            return;
        }
        // Establishment failed: release the reserved budget slot.
        let mut state = self.plane.state.lock().unwrap();
        if let Some(ticket) = state.tickets.get_mut(&self.ticket) {
            ticket.active_sessions = ticket.active_sessions.saturating_sub(1);
        }
    }
}

impl SessionHandle {
    /// Session over (either leg closed, TTL, idle, or user close): tear
    /// down accounting and audit with byte counts.
    pub fn finish(self, reason: &str) {
        self.finish_inner(reason);
    }

    fn finish_inner(&self, reason: &str) {
        let mut state = self.plane.state.lock().unwrap();
        let entry = state.sessions.remove(&self.id);
        if let Some(entry) = &entry {
            if let Some(ticket_key) = &entry.ticket {
                if let Some(ticket) = state.tickets.get_mut(ticket_key) {
                    ticket.active_sessions = ticket.active_sessions.saturating_sub(1);
                }
            }
        }
        drop(state);
        if entry.is_some() {
            self.plane.audit.append(
                AuditEntry::new(
                    AuditKind::SessionClosed,
                    format!(
                        "{} session closed: {}",
                        kind_label(self.kind),
                        self.connection
                    ),
                )
                .agent(self.agent.clone())
                .connection(self.connection.clone())
                .outcome(reason.to_string())
                .bytes(
                    self.bytes_up.load(Ordering::Relaxed),
                    self.bytes_down.load(Ordering::Relaxed),
                )
                .field("kind", self.kind.as_str())
                .field("session_id", self.id),
            );
            self.plane.events.sessions_changed();
        }
    }
}

impl Drop for SessionHandle {
    fn drop(&mut self) {
        // Async request/connection tasks can be cancelled by their runtime or
        // client. Never leave a ghost session consuming the global budget.
        self.finish_inner("transport_dropped");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::NoopEvents;
    use crate::types::ConnectionConfig;
    use uuid::Uuid;

    fn expect_err(r: Result<Redemption, RedeemError>) -> RedeemError {
        match r {
            Err(e) => e,
            Ok(_) => panic!("expected a redemption error"),
        }
    }

    fn pg_connection() -> Connection {
        Connection {
            id: Uuid::new_v4(),
            name: "analytics".into(),
            config: ConnectionConfig::Pg {
                host: "db.internal".into(),
                port: 5432,
                dbname: "analytics".into(),
                user: "app".into(),
                sslmode: Default::default(),
                trusted_ca_bundle_path: None,
            },
            secrets: vec![],
            account: None,
            oauth: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn ssh_connection() -> Connection {
        Connection {
            id: Uuid::new_v4(),
            name: "prod-ssh".into(),
            config: ConnectionConfig::Ssh {
                destination: None,
                host: "prod.example.com".into(),
                port: 22,
                user: "deploy".into(),
                host_key_fingerprint: "SHA256:test".into(),
            },
            secrets: vec![],
            account: None,
            oauth: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn plane(ttl: Duration, per_ticket: usize, global: usize) -> (DataPlane, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let audit = Arc::new(AuditLog::open(dir.path().join("audit.jsonl")).unwrap());
        (
            DataPlane::new(ttl, per_ticket, global, audit, Arc::new(NoopEvents)),
            dir,
        )
    }

    #[test]
    fn one_ticket_can_open_multiple_sessions() {
        let (plane, _dir) = plane(Duration::from_secs(60), 60, 300);
        let ticket = plane.issue("claude-code", &pg_connection());
        let s1 = plane.redeem(&ticket).unwrap().start(ConnectionKind::Pg);
        let s2 = plane.redeem(&ticket).unwrap().start(ConnectionKind::Pg);
        assert_eq!(plane.sessions().len(), 2);
        s1.finish("test");
        s2.finish("test");
        assert_eq!(plane.sessions().len(), 0);
    }

    #[test]
    fn dropping_a_handle_retires_the_session() {
        let (plane, _dir) = plane(Duration::from_secs(60), 60, 300);
        let endpoint_id = Uuid::new_v4();
        let session = plane
            .start_endpoint_session(
                "endpoint",
                &ssh_connection(),
                endpoint_id,
                ConnectionKind::Ssh,
            )
            .unwrap();
        assert_eq!(plane.sessions().len(), 1);
        drop(session);
        assert!(plane.sessions().is_empty());
    }

    #[test]
    fn ssh_ticket_supports_multiple_client_connections() {
        let (plane, _dir) = plane(Duration::from_secs(60), 60, 300);
        let ticket = plane.issue("claude-code", &ssh_connection());
        let s1 = plane.redeem(&ticket).unwrap().start(ConnectionKind::Ssh);
        let s2 = plane.redeem(&ticket).unwrap().start(ConnectionKind::Ssh);
        assert_eq!(plane.sessions().len(), 2);
        s1.finish("test");
        s2.finish("test");
    }

    #[test]
    fn tickets_expire() {
        let (plane, _dir) = plane(Duration::from_millis(10), 60, 300);
        let t = plane.issue("a", &pg_connection());
        std::thread::sleep(Duration::from_millis(30));
        assert_eq!(expect_err(plane.redeem(&t)), RedeemError::Expired);
        assert_eq!(expect_err(plane.redeem("tkt_nope")), RedeemError::Unknown);
    }

    #[test]
    fn budgets_fail_fast_with_the_right_reason() {
        let (plane, _dir) = plane(Duration::from_secs(60), 1, 300);
        let t = plane.issue("a", &pg_connection());
        let _s = plane.redeem(&t).unwrap().start(ConnectionKind::Pg);
        assert_eq!(
            expect_err(plane.redeem(&t)),
            RedeemError::TicketSessionLimit
        );

        let (plane, _dir2) = plane_global_one();
        let t1 = plane.issue("a", &pg_connection());
        let t2 = plane.issue("a", &pg_connection());
        let _s1 = plane.redeem(&t1).unwrap().start(ConnectionKind::Pg);
        assert_eq!(
            expect_err(plane.redeem(&t2)),
            RedeemError::BrokerSessionLimit
        );
    }

    fn plane_global_one() -> (DataPlane, tempfile::TempDir) {
        plane(Duration::from_secs(60), 60, 1)
    }

    #[test]
    fn failed_establishment_releases_budget() {
        let (plane, _dir) = plane(Duration::from_secs(60), 1, 300);
        let t = plane.issue("a", &pg_connection());
        {
            let redemption = plane.redeem(&t).unwrap();
            drop(redemption); // dial failed
        }
        // Slot released: redeem works again.
        let s = plane.redeem(&t).unwrap().start(ConnectionKind::Pg);
        s.finish("test");
    }

    #[test]
    fn active_sessions_keep_ticket_accounting_alive_past_ttl() {
        let (plane, _dir) = plane(Duration::from_millis(20), 60, 300);
        let t = plane.issue("a", &pg_connection());
        let s = plane.redeem(&t).unwrap().start(ConnectionKind::Pg);
        std::thread::sleep(Duration::from_millis(40));
        // New redemptions fail (window elapsed) …
        assert_eq!(expect_err(plane.redeem(&t)), RedeemError::Expired);
        // … but the live session still tears down cleanly.
        s.finish("test");
        assert!(plane.sessions().is_empty());
    }

    #[tokio::test]
    async fn key_rotation_blocks_all_tickets_and_signals_live_sessions() {
        let (plane, _dir) = plane(Duration::from_secs(60), 60, 300);
        let ticket = plane.issue("codex", &pg_connection());
        let other_ticket = plane.issue("claude", &pg_connection());
        let session = plane.redeem(&ticket).unwrap().start(ConnectionKind::Pg);
        let closed = session.close_signal.clone();
        let notified = closed.notified();
        assert_eq!(plane.close_all(), 1);
        tokio::time::timeout(Duration::from_secs(1), notified)
            .await
            .expect("live session should receive the close signal");
        assert_eq!(expect_err(plane.redeem(&ticket)), RedeemError::Expired);
        assert_eq!(
            expect_err(plane.redeem(&other_ticket)),
            RedeemError::Expired,
            "rotation invalidates every outstanding ticket"
        );
        session.finish("key_rotated");
    }

    #[tokio::test]
    async fn endpoint_close_signal_survives_waiter_registration_race() {
        let (plane, _dir) = plane(Duration::from_secs(60), 60, 300);
        let endpoint_id = Uuid::new_v4();
        let session = plane
            .start_endpoint_session(
                "endpoint",
                &ssh_connection(),
                endpoint_id,
                ConnectionKind::Ssh,
            )
            .unwrap();
        let closed = session.close_signal.clone();

        // Close before the transport begins awaiting. `notify_one` retains a
        // permit, so the late waiter must still wake immediately.
        assert_eq!(plane.close_endpoint_sessions(&endpoint_id), 1);
        tokio::time::timeout(Duration::from_secs(1), closed.notified())
            .await
            .expect("the close permit must survive a late waiter");
        session.finish("access_revoked");
    }

    /// A ticket session outlives its ticket by up to `session_max_ttl`, so
    /// withdrawing the connection has to reach the established session, not
    /// just refuse the next open.
    #[tokio::test]
    async fn withdrawing_a_connection_closes_its_live_ticket_session() {
        let (plane, _dir) = plane(Duration::from_secs(60), 60, 300);
        let connection = ssh_connection();
        let ticket = plane.issue("claude-code", &connection);
        let session = plane
            .redeem(&ticket)
            .expect("redeem")
            .start(ConnectionKind::Ssh);
        let closed = session.close_signal.clone();

        assert_eq!(plane.close_connection_sessions(&connection.id), 1);
        tokio::time::timeout(Duration::from_secs(1), closed.notified())
            .await
            .expect("the live session must be signalled to close");
        session.finish("access_revoked");
    }

    /// An already-issued ticket is still inside its redemption window when the
    /// user disables the connection, so it must stop redeeming too — otherwise
    /// revocation is bypassable for the ticket's remaining lifetime.
    #[tokio::test]
    async fn withdrawing_a_connection_invalidates_its_outstanding_tickets() {
        let (plane, _dir) = plane(Duration::from_secs(60), 60, 300);
        let connection = ssh_connection();
        let ticket = plane.issue("claude-code", &connection);

        assert_eq!(plane.close_connection_sessions(&connection.id), 0);
        assert_eq!(expect_err(plane.redeem(&ticket)), RedeemError::Expired);
    }

    /// Withdrawing one connection must not disturb another's traffic.
    #[tokio::test]
    async fn withdrawing_a_connection_leaves_other_connections_alone() {
        let (plane, _dir) = plane(Duration::from_secs(60), 60, 300);
        let withdrawn = ssh_connection();
        let untouched = pg_connection();
        let other = plane.issue("claude-code", &untouched);
        let other_session = plane
            .redeem(&other)
            .expect("redeem")
            .start(ConnectionKind::Ssh);

        assert_eq!(plane.close_connection_sessions(&withdrawn.id), 0);
        assert_eq!(plane.sessions().len(), 1, "the other session must survive");
        // And its ticket must still redeem.
        let second = plane
            .redeem(&other)
            .expect("redeem")
            .start(ConnectionKind::Ssh);
        second.finish("done");
        other_session.finish("done");
    }
}
