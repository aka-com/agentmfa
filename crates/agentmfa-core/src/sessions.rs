//! Data-plane tickets and live sessions (DESIGN.md §4.2/§4.3/§8).
//!
//! WS bridge tickets and PG DSN tickets are 128-bit random values that
//! expire 60 s after issue. On multi-connect connections (the default) a
//! ticket may be redeemed any number of times within that window, each
//! redemption opening its own bridged session, all under the single
//! approval; otherwise it is strictly single-use. Concurrent sessions are
//! bounded at two levels, a per-ticket cap (default 60) inside a global
//! backstop (default 300), with distinct reasons naming the budget hit.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde::Serialize;
use tokio::sync::Notify;

use crate::audit::{AuditEntry, AuditKind, AuditLog};
use crate::events::BrokerEvents;
use crate::types::{Connection, ConnectionKind};
use crate::wire::ErrorReason;

/// Kind-specific state carried by a ticket.
#[allow(clippy::large_enum_variant)] // one live WS stream per ticket, boxedness buys nothing
pub enum TicketPayload {
    Ws {
        /// The upstream connection dialed (and authenticated) at open time,
        /// claimed by the first redemption (§4.2 step 3).
        pending_upstream: Option<crate::capability::ws::WsUpstream>,
    },
    Pg,
    Ssh,
}

/// Session-audit label for a connection kind ("WebSocket session opened").
fn kind_label(kind: ConnectionKind) -> &'static str {
    match kind {
        ConnectionKind::Ws => "WebSocket",
        ConnectionKind::Pg => "Postgres",
        ConnectionKind::Ssh => "SSH",
        ConnectionKind::Api => "API",
    }
}

struct TicketEntry {
    agent: String,
    connection: Connection,
    multi_connect: bool,
    issued: Instant,
    redeemed: bool,
    active_sessions: usize,
    payload: TicketPayload,
}

/// One live bridged/proxied session, as shown in the live-sessions band.
#[derive(Debug, Clone, Serialize)]
pub struct SessionInfo {
    pub id: u64,
    pub kind: ConnectionKind,
    pub agent: String,
    pub connection: String,
    /// Pinned target, e.g. the WS URL or `user@host:port/db`.
    pub detail: String,
    pub opened_at: DateTime<Utc>,
}

struct SessionEntry {
    info: SessionInfo,
    ticket: String,
    close: Arc<Notify>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum RedeemError {
    /// Unknown value (or long-gone ticket).
    Unknown,
    /// Past its 60 s window.
    Expired,
    /// Single-use ticket already redeemed (§4.2: `410 Gone`).
    AlreadyRedeemed,
    /// This approval's session budget is exhausted (§8).
    TicketSessionLimit,
    /// The broker-wide backstop is exhausted (§8).
    BrokerSessionLimit,
}

impl RedeemError {
    pub fn reason(&self) -> ErrorReason {
        match self {
            RedeemError::Unknown => ErrorReason::UnknownTicket,
            RedeemError::Expired => ErrorReason::TicketExpired,
            RedeemError::AlreadyRedeemed => ErrorReason::TicketAlreadyRedeemed,
            RedeemError::TicketSessionLimit => ErrorReason::TicketSessionLimit,
            RedeemError::BrokerSessionLimit => ErrorReason::BrokerSessionLimit,
        }
    }
    /// HTTP status for the data-plane response.
    pub fn status(&self) -> u16 {
        match self {
            RedeemError::Unknown => 404,
            RedeemError::Expired | RedeemError::AlreadyRedeemed => 410,
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
    pub payload_ws_upstream: Option<crate::capability::ws::WsUpstream>,
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

pub struct DataPlane {
    inner: Arc<DataPlaneInner>,
}

fn mint_ticket() -> String {
    let mut buf = [0u8; 16]; // 128-bit (§8)
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

    /// Issue a ticket under one approval (§4.2/§4.3).
    pub fn issue(&self, agent: &str, connection: &Connection, payload: TicketPayload) -> String {
        let value = mint_ticket();
        let mut state = self.inner.state.lock().unwrap();
        Self::sweep(&self.inner, &mut state);
        // OpenSSH can use more than one agent socket connection during a
        // single login (identity listing, then signing). Store validation
        // rejects single-connect SSH now; this keeps old persisted state from
        // turning one approved SSH invocation into a failed second redemption.
        let multi_connect = connection.multi_connect || matches!(payload, TicketPayload::Ssh);
        state.tickets.insert(
            value.clone(),
            TicketEntry {
                agent: agent.to_string(),
                connection: connection.clone(),
                multi_connect,
                issued: Instant::now(),
                redeemed: false,
                active_sessions: 0,
                payload,
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
        if entry.issued.elapsed() > self.inner.ticket_ttl {
            return Err(RedeemError::Expired);
        }
        if !entry.multi_connect && entry.redeemed {
            return Err(RedeemError::AlreadyRedeemed);
        }
        // Fail fast with the budget it hit (§8).
        if entry.active_sessions >= self.inner.per_ticket {
            return Err(RedeemError::TicketSessionLimit);
        }
        if global_active >= self.inner.global {
            return Err(RedeemError::BrokerSessionLimit);
        }
        entry.redeemed = true;
        entry.active_sessions += 1;
        let pending = match &mut entry.payload {
            TicketPayload::Ws { pending_upstream } => pending_upstream.take(),
            TicketPayload::Pg | TicketPayload::Ssh => None,
        };
        Ok(Redemption {
            plane: self.inner.clone(),
            ticket: value.to_string(),
            agent: entry.agent.clone(),
            connection: entry.connection.clone(),
            payload_ws_upstream: pending,
            started: false,
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

    /// User-initiated close (the inline-confirmed control, §9). Returns
    /// whether the session existed.
    pub fn close_session(&self, id: u64) -> bool {
        let state = self.inner.state.lock().unwrap();
        match state.sessions.get(&id) {
            Some(entry) => {
                entry.close.notify_waiters();
                true
            }
            None => false,
        }
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
                ticket: self.ticket.clone(),
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
    /// down accounting and audit with byte counts (§8).
    pub fn finish(self, reason: &str) {
        let mut state = self.plane.state.lock().unwrap();
        let entry = state.sessions.remove(&self.id);
        if let Some(entry) = &entry {
            if let Some(ticket) = state.tickets.get_mut(&entry.ticket) {
                ticket.active_sessions = ticket.active_sessions.saturating_sub(1);
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

    fn ws_connection(multi: bool) -> Connection {
        Connection {
            id: Uuid::new_v4(),
            name: "market-feed".into(),
            config: ConnectionConfig::Ws {
                url: "wss://stream.example.com/feed".into(),
                template: None,
            },
            secrets: vec![],
            multi_connect: multi,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn ssh_connection(multi: bool) -> Connection {
        Connection {
            id: Uuid::new_v4(),
            name: "prod-ssh".into(),
            config: ConnectionConfig::Ssh {
                host: "prod.example.com".into(),
                port: 22,
                user: "deploy".into(),
            },
            secrets: vec![],
            multi_connect: multi,
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
    fn multi_connect_redeems_many_single_use_once() {
        let (plane, _dir) = plane(Duration::from_secs(60), 60, 300);
        let multi = plane.issue("claude-code", &ws_connection(true), TicketPayload::Pg);
        let s1 = plane.redeem(&multi).unwrap().start(ConnectionKind::Ws);
        let s2 = plane.redeem(&multi).unwrap().start(ConnectionKind::Ws);
        assert_eq!(plane.sessions().len(), 2);
        s1.finish("test");
        s2.finish("test");
        assert_eq!(plane.sessions().len(), 0);

        let single = plane.issue("claude-code", &ws_connection(false), TicketPayload::Pg);
        let s = plane.redeem(&single).unwrap().start(ConnectionKind::Ws);
        assert_eq!(
            expect_err(plane.redeem(&single)),
            RedeemError::AlreadyRedeemed
        );
        s.finish("test");
    }

    #[test]
    fn ssh_tickets_are_never_single_use() {
        let (plane, _dir) = plane(Duration::from_secs(60), 60, 300);
        let ticket = plane.issue("claude-code", &ssh_connection(false), TicketPayload::Ssh);
        let s1 = plane.redeem(&ticket).unwrap().start(ConnectionKind::Ssh);
        let s2 = plane.redeem(&ticket).unwrap().start(ConnectionKind::Ssh);
        assert_eq!(plane.sessions().len(), 2);
        s1.finish("test");
        s2.finish("test");
    }

    #[test]
    fn tickets_expire() {
        let (plane, _dir) = plane(Duration::from_millis(10), 60, 300);
        let t = plane.issue("a", &ws_connection(true), TicketPayload::Pg);
        std::thread::sleep(Duration::from_millis(30));
        assert_eq!(expect_err(plane.redeem(&t)), RedeemError::Expired);
        assert_eq!(expect_err(plane.redeem("tkt_nope")), RedeemError::Unknown);
    }

    #[test]
    fn budgets_fail_fast_with_the_right_reason() {
        let (plane, _dir) = plane(Duration::from_secs(60), 1, 300);
        let t = plane.issue("a", &ws_connection(true), TicketPayload::Pg);
        let _s = plane.redeem(&t).unwrap().start(ConnectionKind::Ws);
        assert_eq!(
            expect_err(plane.redeem(&t)),
            RedeemError::TicketSessionLimit
        );

        let (plane, _dir2) = plane_global_one();
        let t1 = plane.issue("a", &ws_connection(true), TicketPayload::Pg);
        let t2 = plane.issue("a", &ws_connection(true), TicketPayload::Pg);
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
        let t = plane.issue("a", &ws_connection(true), TicketPayload::Pg);
        {
            let redemption = plane.redeem(&t).unwrap();
            drop(redemption); // dial failed
        }
        // Slot released: redeem works again.
        let s = plane.redeem(&t).unwrap().start(ConnectionKind::Ws);
        s.finish("test");
    }

    #[test]
    fn active_sessions_keep_ticket_accounting_alive_past_ttl() {
        let (plane, _dir) = plane(Duration::from_millis(20), 60, 300);
        let t = plane.issue("a", &ws_connection(true), TicketPayload::Pg);
        let s = plane.redeem(&t).unwrap().start(ConnectionKind::Ws);
        std::thread::sleep(Duration::from_millis(40));
        // New redemptions fail (window elapsed) …
        assert_eq!(expect_err(plane.redeem(&t)), RedeemError::Expired);
        // … but the live session still tears down cleanly.
        s.finish("test");
        assert!(plane.sessions().is_empty());
    }
}
