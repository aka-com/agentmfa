//! Native attention delivery for requests waiting on the user.
//!
//! The broker remains authoritative. This coordinator only remembers the
//! active IDs it has already observed so reconnects and coalesced waiters do
//! not produce duplicate desktop notifications. The inbox itself always
//! refetches from the broker.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;
use std::time::Duration;

use aka_api::ApprovalDto;
use tauri::{AppHandle, Manager as _};

use crate::broker_mode::{NotificationMode, NotificationSettings};

const NOTIFICATION_DEBOUNCE: Duration = Duration::from_millis(400);
const OPEN_INBOX_ACTION: &str = "open_request_inbox";

#[derive(Clone, Debug, PartialEq, Eq)]
struct RequestSummary {
    id: String,
    agent: String,
    connection: String,
}

impl From<ApprovalDto> for RequestSummary {
    fn from(approval: ApprovalDto) -> Self {
        Self {
            id: approval.id,
            agent: approval.agent,
            connection: approval.connection,
        }
    }
}

#[derive(Default)]
struct AttentionTracker {
    scope: String,
    active: BTreeMap<String, RequestSummary>,
    pending_notification: BTreeSet<String>,
}

impl AttentionTracker {
    fn set_scope(&mut self, scope: String) -> bool {
        if self.scope == scope {
            return false;
        }
        self.scope = scope;
        self.active.clear();
        self.pending_notification.clear();
        true
    }

    fn upsert(&mut self, request: RequestSummary, announce_if_new: bool) -> TrackerChange {
        let old_count = self.active.len();
        let is_new = !self.active.contains_key(&request.id);
        let id = request.id.clone();
        self.active.insert(id.clone(), request);
        if is_new && announce_if_new {
            self.pending_notification.insert(id);
        }
        TrackerChange {
            count: self.active.len(),
            count_changed: old_count != self.active.len(),
            notification_added: is_new && announce_if_new,
        }
    }

    fn reconcile(&mut self, approvals: Vec<ApprovalDto>) -> TrackerChange {
        let old_count = self.active.len();
        let next = approvals
            .into_iter()
            .map(RequestSummary::from)
            .map(|request| (request.id.clone(), request))
            .collect::<BTreeMap<_, _>>();
        let new_ids = next
            .keys()
            .filter(|id| !self.active.contains_key(*id))
            .cloned()
            .collect::<Vec<_>>();
        self.active = next;
        self.pending_notification
            .retain(|id| self.active.contains_key(id));
        self.pending_notification.extend(new_ids.iter().cloned());
        TrackerChange {
            count: self.active.len(),
            count_changed: old_count != self.active.len(),
            notification_added: !new_ids.is_empty(),
        }
    }

    fn resolve(&mut self, id: &str) -> TrackerChange {
        let old_count = self.active.len();
        self.active.remove(id);
        self.pending_notification.remove(id);
        TrackerChange {
            count: self.active.len(),
            count_changed: old_count != self.active.len(),
            notification_added: false,
        }
    }

    fn take_pending(&mut self) -> Vec<RequestSummary> {
        let ids = std::mem::take(&mut self.pending_notification);
        ids.into_iter()
            .filter_map(|id| self.active.get(&id).cloned())
            .collect()
    }
}

struct TrackerChange {
    count: usize,
    count_changed: bool,
    notification_added: bool,
}

struct AttentionInner {
    tracker: AttentionTracker,
    settings: NotificationSettings,
    flush_generation: u64,
    flush_scheduled: bool,
    /// Authoritative remote reads can complete out of order. Only the latest
    /// event-triggered read may replace the active snapshot.
    remote_refresh_generation: u64,
    /// Parked upstream elicitations, tracked only for the tray/inbox count.
    /// They notify on their own path (a single distinct question, not folded
    /// into the approval coalescing tracker) but still contribute to the badge.
    elicitations: std::collections::HashSet<uuid::Uuid>,
}

impl AttentionInner {
    /// The badge total: approvals waiting plus elicitations parked.
    fn total(&self) -> usize {
        self.tracker.active.len() + self.elicitations.len()
    }
}

/// Managed Tauri state shared by local broker callbacks and the remote SSE
/// reconciliation path.
pub struct RequestAttention {
    inner: Mutex<AttentionInner>,
}

impl RequestAttention {
    pub fn new(settings: NotificationSettings) -> Self {
        Self {
            inner: Mutex::new(AttentionInner {
                tracker: AttentionTracker::default(),
                settings,
                flush_generation: 0,
                flush_scheduled: false,
                remote_refresh_generation: 0,
                elicitations: std::collections::HashSet::new(),
            }),
        }
    }

    fn upsert(&self, app: &AppHandle, request: RequestSummary, announce_if_new: bool) {
        let (change, generation) = {
            let mut inner = self.inner.lock().unwrap();
            let mut change = inner.tracker.upsert(request, announce_if_new);
            // The badge counts elicitations too, so the pushed total is both.
            change.count = inner.total();
            let generation = schedule_generation(&mut inner, change.notification_added);
            (change, generation)
        };
        apply_change(app, change, generation);
    }

    fn resolve(&self, app: &AppHandle, id: &str) {
        let change = {
            let mut inner = self.inner.lock().unwrap();
            let mut change = inner.tracker.resolve(id);
            change.count = inner.total();
            change
        };
        apply_change(app, change, None);
    }

    /// Track a parked elicitation for the badge and push the new total. The
    /// notification itself is raised separately.
    fn add_elicitation(&self, app: &AppHandle, id: uuid::Uuid) {
        let total = {
            let mut inner = self.inner.lock().unwrap();
            inner.elicitations.insert(id);
            inner.total()
        };
        crate::windows::update_request_count(app, total);
    }

    /// Drop a resolved elicitation from the badge and push the new total.
    fn remove_elicitation(&self, app: &AppHandle, id: uuid::Uuid) {
        let (total, changed) = {
            let mut inner = self.inner.lock().unwrap();
            let changed = inner.elicitations.remove(&id);
            (inner.total(), changed)
        };
        if changed {
            crate::windows::update_request_count(app, total);
        }
    }

    fn set_scope(&self, app: &AppHandle, scope: String) {
        let changed = {
            let mut inner = self.inner.lock().unwrap();
            if !inner.tracker.set_scope(scope) {
                false
            } else {
                inner.flush_generation = inner.flush_generation.wrapping_add(1);
                inner.flush_scheduled = false;
                inner.remote_refresh_generation = inner.remote_refresh_generation.wrapping_add(1);
                true
            }
        };
        if changed {
            crate::windows::update_request_count(app, 0);
        }
    }

    pub fn set_settings(&self, settings: NotificationSettings) {
        self.inner.lock().unwrap().settings = settings;
    }

    pub fn count(&self) -> usize {
        self.inner.lock().unwrap().total()
    }

    fn begin_remote_refresh(&self) -> u64 {
        let mut inner = self.inner.lock().unwrap();
        inner.remote_refresh_generation = inner.remote_refresh_generation.wrapping_add(1);
        inner.remote_refresh_generation
    }

    fn reconcile_remote(&self, app: &AppHandle, generation: u64, approvals: Vec<ApprovalDto>) {
        let (change, flush_generation) = {
            let mut inner = self.inner.lock().unwrap();
            if generation != inner.remote_refresh_generation {
                return;
            }
            let mut change = inner.tracker.reconcile(approvals);
            change.count = inner.total();
            let flush_generation = schedule_generation(&mut inner, change.notification_added);
            (change, flush_generation)
        };
        apply_change(app, change, flush_generation);
    }

    fn remote_refresh_is_current(&self, generation: u64) -> bool {
        generation == self.inner.lock().unwrap().remote_refresh_generation
    }
}

fn schedule_generation(inner: &mut AttentionInner, notification_added: bool) -> Option<u64> {
    if !notification_added || inner.flush_scheduled {
        return None;
    }
    inner.flush_scheduled = true;
    Some(inner.flush_generation)
}

fn apply_change(app: &AppHandle, change: TrackerChange, generation: Option<u64>) {
    if change.count_changed {
        crate::windows::update_request_count(app, change.count);
    }
    if let Some(generation) = generation {
        let app = app.clone();
        tauri::async_runtime::spawn(async move {
            tokio::time::sleep(NOTIFICATION_DEBOUNCE).await;
            flush_notification(&app, generation);
        });
    }
}

fn flush_notification(app: &AppHandle, generation: u64) {
    let Some(attention) = app.try_state::<RequestAttention>() else {
        return;
    };
    let (requests, total, settings) = {
        let mut inner = attention.inner.lock().unwrap();
        if generation != inner.flush_generation {
            return;
        }
        inner.flush_scheduled = false;
        let requests = inner.tracker.take_pending();
        (requests, inner.tracker.active.len(), inner.settings)
    };
    if requests.is_empty() {
        return;
    }

    match settings.mode {
        NotificationMode::Off => {
            crate::windows::surface_for_approval(app);
            return;
        }
        NotificationMode::WhenHidden if crate::windows::request_surface_focused(app) => return,
        NotificationMode::WhenHidden | NotificationMode::Always => {}
    }

    if let Err(error) = show_notification(app, &requests, total, settings.show_context) {
        tracing::warn!(%error, "could not deliver a native request notification");
        crate::windows::surface_for_approval(app);
    }
}

fn show_notification(
    app: &AppHandle,
    requests: &[RequestSummary],
    total: usize,
    show_context: bool,
) -> Result<(), String> {
    let title = if requests.len() == 1 {
        "AgentMFA needs your approval".to_string()
    } else {
        format!("{} new requests need your approval", requests.len())
    };
    let body = if show_context && requests.len() == 1 {
        let request = &requests[0];
        let agent = agent_display(&request.agent, "An agent");
        let connection = notification_label(&request.connection, "a tool");
        format!(
            "{} is waiting to use {}. Open the Request Inbox to review.",
            agent, connection
        )
    } else if total == 1 {
        "Open the Request Inbox to review this request.".to_string()
    } else {
        format!("Open the Request Inbox to review {total} waiting requests.")
    };

    deliver_notification(app, &title, &body)
}

/// Show one native notification whose activation opens the Request Inbox, and
/// observe that activation off the main/async threads. Shared by the approval
/// batch and the single-elicitation paths.
fn deliver_notification(app: &AppHandle, title: &str, body: &str) -> Result<(), String> {
    let mut notification = notify_rust::Notification::new();
    notification
        .summary(title)
        .body(body)
        .action(OPEN_INBOX_ACTION, "Open Inbox")
        .auto_icon();
    // XDG servers only emit body activation when the special default action
    // is advertised; some desktops hide named buttons entirely.
    #[cfg(all(unix, not(target_os = "macos")))]
    notification.action("default", "Open Inbox");
    configure_notification_identity(app, &mut notification)?;
    let handle = notification.show().map_err(|error| error.to_string())?;

    // All supported desktop backends deliver activation through a blocking
    // handle. Keep that wait off Tauri's main and async-runtime threads; the
    // main run loop remains available for the platform callback itself.
    let response_app = app.clone();
    std::thread::Builder::new()
        .name("aka-notification-action".into())
        .spawn(move || {
            let fallback_app = response_app.clone();
            if let Err(error) =
                handle.wait_for_response(move |response: &notify_rust::NotificationResponse| {
                    if notification_opens_inbox(response) {
                        crate::windows::open_request_inbox(&response_app);
                    }
                })
            {
                tracing::warn!(%error, "could not observe native notification interaction");
                crate::windows::surface_for_approval(&fallback_app);
            }
        })
        .map_err(|error| error.to_string())?;
    Ok(())
}

fn notification_opens_inbox(response: &notify_rust::NotificationResponse) -> bool {
    matches!(response, notify_rust::NotificationResponse::Default)
        || matches!(
            response,
            notify_rust::NotificationResponse::Action(action)
                if action == OPEN_INBOX_ACTION
        )
}

#[cfg(target_os = "macos")]
fn configure_notification_identity(
    _app: &AppHandle,
    _notification: &mut notify_rust::Notification,
) -> Result<(), String> {
    // Match the Tauri plugin's delivery identity. Development binaries are
    // not installed application bundles, so Notification Center attributes
    // them to Terminal; packaged builds use AKA's bundle identifier.
    #[allow(deprecated)]
    let _ = notify_rust::set_application(if tauri::is_dev() {
        "com.apple.Terminal"
    } else {
        _app.config().identifier.as_str()
    });
    Ok(())
}

#[cfg(target_os = "windows")]
fn configure_notification_identity(
    app: &AppHandle,
    notification: &mut notify_rust::Notification,
) -> Result<(), String> {
    // Windows accepts the configured AppUserModel ID only for an installed
    // application. Development builds retain notify-rust's PowerShell ID.
    let executable = tauri::utils::platform::current_exe().map_err(|error| error.to_string())?;
    let directory = executable
        .parent()
        .ok_or_else(|| "the application executable has no parent directory".to_string())?
        .display()
        .to_string();
    let separator = std::path::MAIN_SEPARATOR;
    if !(directory.ends_with(format!("{separator}target{separator}debug"))
        || directory.ends_with(format!("{separator}target{separator}release")))
    {
        notification.app_id(&app.config().identifier);
    }
    Ok(())
}

#[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
fn configure_notification_identity(
    _app: &AppHandle,
    _notification: &mut notify_rust::Notification,
) -> Result<(), String> {
    Ok(())
}

/// The broker's direct-endpoint planes attribute their traffic to the
/// literal agent label `endpoint` — an audit-stable wire value, not prose.
/// Spell that one out for the humans reading a notification; every other
/// label is untrusted agent text and goes through [`notification_label`].
fn agent_display(agent: &str, fallback: &str) -> String {
    if agent == "endpoint" {
        "A direct endpoint client".into()
    } else {
        notification_label(agent, fallback)
    }
}

fn notification_label(value: &str, fallback: &str) -> String {
    let normalized = value
        .chars()
        // Directional formatting can make an untrusted agent label look
        // like OS-owned text or reorder the trusted suffix around it.
        .filter(|character| !is_bidi_formatting(*character))
        .map(|character| {
            if character.is_control() || character.is_whitespace() {
                ' '
            } else {
                character
            }
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(80)
        .collect::<String>();
    if normalized.is_empty() {
        fallback.into()
    } else {
        normalized
    }
}

fn is_bidi_formatting(character: char) -> bool {
    matches!(
        character,
        '\u{061c}'
            | '\u{200e}'
            | '\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2066}'..='\u{2069}'
    )
}

fn scope_key(mode: &str, url: Option<&str>) -> String {
    match (mode, url) {
        ("remote", Some(url)) => format!("remote:{url}"),
        _ => "local".into(),
    }
}

pub fn set_scope(app: &AppHandle, mode: &str, url: Option<&str>) {
    if let Some(attention) = app.try_state::<RequestAttention>() {
        attention.set_scope(app, scope_key(mode, url));
    }
}

pub fn approval_requested(app: &AppHandle, pending: &aka_core::approvals::PendingApproval) {
    if let Some(attention) = app.try_state::<RequestAttention>() {
        let dto = aka_core::manage::approval_dto(pending);
        attention.upsert(app, RequestSummary::from(dto), true);
    }
}

pub fn approval_updated(app: &AppHandle, pending: &aka_core::approvals::PendingApproval) {
    if let Some(attention) = app.try_state::<RequestAttention>() {
        let dto = aka_core::manage::approval_dto(pending);
        attention.upsert(app, RequestSummary::from(dto), false);
    }
}

pub fn approval_resolved(app: &AppHandle, id: &uuid::Uuid) {
    if let Some(attention) = app.try_state::<RequestAttention>() {
        attention.resolve(app, &id.to_string());
    }
}

/// A paused tool call is waiting on the user for input. Unlike approvals this
/// is not folded into the coalescing tracker or the tray count — an upstream
/// elicitation is a single, distinct question — so it raises one notification
/// directly, honoring the same notification-mode setting.
pub fn elicitation_requested(
    app: &AppHandle,
    pending: &aka_core::elicitations::PendingElicitation,
) {
    let Some(attention) = app.try_state::<RequestAttention>() else {
        return;
    };
    // Count it toward the tray/inbox badge (idempotent on repeat events).
    attention.add_elicitation(app, pending.id);
    let (mode, show_context) = {
        let inner = attention.inner.lock().unwrap();
        (inner.settings.mode, inner.settings.show_context)
    };
    match mode {
        NotificationMode::Off => {
            crate::windows::surface_for_approval(app);
            return;
        }
        NotificationMode::WhenHidden if crate::windows::request_surface_focused(app) => return,
        NotificationMode::WhenHidden | NotificationMode::Always => {}
    }
    let title = "AgentMFA needs your input".to_string();
    let body = if show_context {
        let agent = notification_label(&pending.agent, "An agent");
        let connection = notification_label(&pending.connection, "a tool");
        format!("{connection} asked {agent} for input. Open the Request Inbox to respond.")
    } else {
        "An upstream asked for input. Open the Request Inbox to respond.".to_string()
    };
    if let Err(error) = deliver_notification(app, &title, &body) {
        tracing::warn!(%error, "could not deliver an elicitation notification");
        crate::windows::surface_for_approval(app);
    }
}

/// A parked elicitation left the queue (answered, cancelled, or lapsed): drop
/// it from the tray/inbox badge.
pub fn elicitation_resolved(app: &AppHandle, id: &uuid::Uuid) {
    if let Some(attention) = app.try_state::<RequestAttention>() {
        attention.remove_elicitation(app, *id);
    }
}

pub fn begin_remote_refresh(app: &AppHandle) -> Option<u64> {
    app.try_state::<RequestAttention>()
        .map(|attention| attention.begin_remote_refresh())
}

pub fn reconcile_remote(app: &AppHandle, generation: u64, approvals: Vec<ApprovalDto>) {
    if let Some(attention) = app.try_state::<RequestAttention>() {
        attention.reconcile_remote(app, generation, approvals);
    }
}

pub fn remote_refresh_is_current(app: &AppHandle, generation: u64) -> bool {
    app.try_state::<RequestAttention>()
        .is_some_and(|attention| attention.remote_refresh_is_current(generation))
}

pub fn sync_tray(app: &AppHandle) {
    let count = app
        .try_state::<RequestAttention>()
        .map(|attention| attention.count())
        .unwrap_or(0);
    crate::windows::update_request_count(app, count);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approval(id: &str, agent: &str) -> ApprovalDto {
        ApprovalDto {
            id: id.into(),
            connection_id: "connection-id".into(),
            connection: "github".into(),
            kind: "api".into(),
            unit: Some("request".into()),
            target: "https://api.github.com".into(),
            agent: agent.into(),
            summary: "GET /user".into(),
            detail: None,
            waiting: 1,
            requested_at: "2026-07-24T12:00:00Z".into(),
            expires_at: "2026-07-24T12:01:30Z".into(),
            expires_in_secs: Some(90),
            window_secs: 900,
        }
    }

    #[test]
    fn updates_do_not_queue_duplicate_notifications() {
        let mut tracker = AttentionTracker::default();
        tracker.set_scope("local".into());
        let first = tracker.upsert(RequestSummary::from(approval("one", "codex")), true);
        let update = tracker.upsert(RequestSummary::from(approval("one", "claude")), false);

        assert!(first.notification_added);
        assert!(!update.notification_added);
        assert_eq!(tracker.take_pending().len(), 1);
        assert!(tracker.take_pending().is_empty());
    }

    #[test]
    fn authoritative_reconcile_adds_and_removes_exactly_once() {
        let mut tracker = AttentionTracker::default();
        tracker.set_scope("remote:https://broker.example".into());

        let first = tracker.reconcile(vec![approval("one", "codex")]);
        let replay = tracker.reconcile(vec![approval("one", "codex")]);
        let replacement = tracker.reconcile(vec![approval("two", "claude")]);

        assert!(first.notification_added);
        assert!(!replay.notification_added);
        assert!(replacement.notification_added);
        assert_eq!(replacement.count, 1);
        assert_eq!(
            tracker.take_pending(),
            vec![RequestSummary::from(approval("two", "claude"))]
        );
    }

    #[test]
    fn resolving_before_the_debounce_cancels_delivery() {
        let mut tracker = AttentionTracker::default();
        tracker.set_scope("local".into());
        tracker.upsert(RequestSummary::from(approval("one", "codex")), true);
        tracker.resolve("one");

        assert!(tracker.take_pending().is_empty());
        assert_eq!(tracker.active.len(), 0);
    }

    #[test]
    fn changing_brokers_clears_active_and_pending_state() {
        let mut tracker = AttentionTracker::default();
        tracker.set_scope("local".into());
        tracker.upsert(RequestSummary::from(approval("one", "codex")), true);

        assert!(tracker.set_scope("remote:https://broker.example".into()));
        assert!(tracker.active.is_empty());
        assert!(tracker.take_pending().is_empty());
        assert!(!tracker.set_scope("remote:https://broker.example".into()));
    }

    #[test]
    fn only_the_latest_remote_snapshot_may_apply() {
        let attention = RequestAttention::new(NotificationSettings::default());
        let first = attention.begin_remote_refresh();
        let second = attention.begin_remote_refresh();

        assert!(!attention.remote_refresh_is_current(first));
        assert!(attention.remote_refresh_is_current(second));
    }

    #[test]
    fn notification_labels_are_single_line_and_bounded() {
        assert_eq!(
            notification_label("codex\npretend this is a system alert", "An agent"),
            "codex pretend this is a system alert"
        );
        assert_eq!(notification_label("\n\t", "An agent"), "An agent");
        assert_eq!(
            notification_label(&"a".repeat(120), "An agent")
                .chars()
                .count(),
            80
        );
        assert_eq!(
            notification_label("codex\u{202e}gpj.exe\u{202c}", "An agent"),
            "codexgpj.exe"
        );
    }

    #[test]
    fn only_notification_activation_routes_to_the_inbox() {
        assert!(notification_opens_inbox(
            &notify_rust::NotificationResponse::Default
        ));
        assert!(notification_opens_inbox(
            &notify_rust::NotificationResponse::Action(OPEN_INBOX_ACTION.into())
        ));
        assert!(!notification_opens_inbox(
            &notify_rust::NotificationResponse::Action("something_else".into())
        ));
        assert!(!notification_opens_inbox(
            &notify_rust::NotificationResponse::Closed(notify_rust::CloseReason::Dismissed)
        ));
    }
}
