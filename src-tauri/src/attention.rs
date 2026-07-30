//! Native attention delivery for requests waiting on the user.
//!
//! The broker remains authoritative. This coordinator only remembers the
//! active IDs it has already observed so reconnects and coalesced waiters do
//! not produce duplicate desktop notifications. The inbox itself always
//! refetches from the broker.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{mpsc, Mutex};
use std::time::{Duration, Instant};

use aka_api::{ApprovalDto, ApprovalSnapshotDto, ElicitationDto};
use serde::Serialize;
use tauri::{AppHandle, Emitter as _, Manager as _};
use tauri_plugin_notification::{NotificationExt as _, PermissionState};

use crate::broker_mode::{NotificationMode, NotificationSettings};

const NOTIFICATION_DEBOUNCE: Duration = Duration::from_millis(400);
const NOTIFICATION_DELIVERY_DEADLINE: Duration = Duration::from_secs(3);
const NOTIFICATION_RESPONSE_DEADLINE: Duration = Duration::from_secs(5 * 60);
const NOTIFICATION_QUEUE_DEPTH: usize = 2;
const NOTIFICATION_RATE_WINDOW: Duration = Duration::from_secs(60);
const NOTIFICATION_RATE_LIMIT: usize = 4;
const OPEN_INBOX_ACTION: &str = "open_request_inbox";

#[derive(Clone, Debug, PartialEq, Eq)]
struct ElicitationSummary {
    id: String,
    agent: String,
    connection: String,
}

impl From<ElicitationDto> for ElicitationSummary {
    fn from(elicitation: ElicitationDto) -> Self {
        Self {
            id: elicitation.id,
            agent: elicitation.agent,
            connection: elicitation.connection,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RemoteSnapshotVersion {
    epoch: String,
    seq: u64,
}

impl RemoteSnapshotVersion {
    fn parse(value: &str) -> Option<Self> {
        let (epoch, seq) = value.split_once(':')?;
        if epoch.is_empty() {
            return None;
        }
        Some(Self {
            epoch: epoch.to_string(),
            seq: seq.parse().ok()?,
        })
    }
}

struct NotificationJob {
    app: AppHandle,
    title: String,
    body: String,
}

/// Preferences plus this process's delivery health. The health fields are
/// intentionally not persisted: a relaunch probes the platform again.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NotificationSettingsView {
    pub mode: NotificationMode,
    pub show_context: bool,
    pub available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unavailable_reason: Option<String>,
    pub can_open_system_settings: bool,
}

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

    /// Take an authoritative snapshot as the active set *without* queueing
    /// notifications. Used when the shell adopts a broker that was already
    /// running: anything parked on it has had its notification attempt
    /// already, so this restores tracking without alerting twice.
    fn adopt(&mut self, approvals: Vec<ApprovalDto>) -> TrackerChange {
        let old_count = self.active.len();
        self.active = approvals
            .into_iter()
            .map(RequestSummary::from)
            .map(|request| (request.id.clone(), request))
            .collect();
        self.pending_notification
            .retain(|id| self.active.contains_key(id));
        TrackerChange {
            count: self.active.len(),
            count_changed: old_count != self.active.len(),
            notification_added: false,
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
    /// event-triggered read may establish a new broker epoch; within one
    /// epoch, the broker's sequence orders snapshots by data freshness.
    remote_refresh_generation: u64,
    last_remote_version: Option<RemoteSnapshotVersion>,
    /// Parked upstream elicitations contribute to the badge and retain just
    /// enough safe context for a genuinely-new remote id to notify.
    elicitations: BTreeMap<String, ElicitationSummary>,
    notifications_available: bool,
    notification_unavailable_reason: Option<String>,
    /// Native banners are deliberately scarce: the Inbox and tray remain
    /// authoritative when a noisy upstream keeps creating distinct prompts.
    notification_times: VecDeque<Instant>,
    notification_storm_announced: bool,
}

impl AttentionInner {
    /// The badge total: approvals waiting plus elicitations parked.
    fn total(&self) -> usize {
        self.tracker.active.len() + self.elicitations.len()
    }

    fn accepts_remote_version(&self, generation: u64, version: &RemoteSnapshotVersion) -> bool {
        match &self.last_remote_version {
            Some(last) if last.epoch == version.epoch => version.seq > last.seq,
            // A broker restart changes the epoch. A read dispatched before a
            // later refresh cannot establish the new epoch, even if it
            // happens to complete last.
            Some(_) | None => generation == self.remote_refresh_generation,
        }
    }

    fn set_scope(&mut self, scope: String) -> Option<usize> {
        if !self.tracker.set_scope(scope) {
            return None;
        }
        self.flush_generation = self.flush_generation.wrapping_add(1);
        self.flush_scheduled = false;
        self.remote_refresh_generation = self.remote_refresh_generation.wrapping_add(1);
        self.last_remote_version = None;
        self.elicitations.clear();
        self.notification_times.clear();
        self.notification_storm_announced = false;
        Some(self.total())
    }

    fn admit_notification(&mut self, now: Instant) -> NotificationAdmission {
        while self
            .notification_times
            .front()
            .is_some_and(|sent| now.saturating_duration_since(*sent) >= NOTIFICATION_RATE_WINDOW)
        {
            self.notification_times.pop_front();
        }
        if self.notification_times.is_empty() {
            self.notification_storm_announced = false;
        }
        if self.notification_times.len() < NOTIFICATION_RATE_LIMIT {
            self.notification_times.push_back(now);
            NotificationAdmission::Normal
        } else if !self.notification_storm_announced {
            self.notification_storm_announced = true;
            NotificationAdmission::Storm
        } else {
            NotificationAdmission::Suppressed
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NotificationAdmission {
    Normal,
    Storm,
    Suppressed,
}

/// Managed Tauri state shared by local broker callbacks and the remote SSE
/// reconciliation path.
pub struct RequestAttention {
    inner: Mutex<AttentionInner>,
    notification_tx: mpsc::SyncSender<NotificationJob>,
}

impl RequestAttention {
    pub fn new(settings: NotificationSettings) -> Self {
        let (notification_tx, notification_rx) = mpsc::sync_channel(NOTIFICATION_QUEUE_DEPTH);
        std::thread::Builder::new()
            .name("aka-notification-worker".into())
            .spawn(move || notification_worker(notification_rx))
            .expect("notification worker thread");
        Self {
            inner: Mutex::new(AttentionInner {
                tracker: AttentionTracker::default(),
                settings,
                flush_generation: 0,
                flush_scheduled: false,
                remote_refresh_generation: 0,
                last_remote_version: None,
                elicitations: BTreeMap::new(),
                notifications_available: true,
                notification_unavailable_reason: None,
                notification_times: VecDeque::new(),
                notification_storm_announced: false,
            }),
            notification_tx,
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
    fn add_elicitation(&self, app: &AppHandle, elicitation: ElicitationSummary) -> bool {
        let (total, added) = {
            let mut inner = self.inner.lock().unwrap();
            let added = !inner.elicitations.contains_key(&elicitation.id);
            inner
                .elicitations
                .insert(elicitation.id.clone(), elicitation);
            (inner.total(), added)
        };
        if added {
            crate::windows::update_request_count(app, total);
        }
        added
    }

    /// Drop a resolved elicitation from the badge and push the new total.
    fn remove_elicitation(&self, app: &AppHandle, id: &str) {
        let (total, changed) = {
            let mut inner = self.inner.lock().unwrap();
            let changed = inner.elicitations.remove(id).is_some();
            (inner.total(), changed)
        };
        if changed {
            crate::windows::update_request_count(app, total);
        }
    }

    fn set_scope(&self, app: &AppHandle, scope: String) {
        let total = self.inner.lock().unwrap().set_scope(scope);
        if let Some(total) = total {
            crate::windows::update_request_count(app, total);
        }
    }

    /// Adopt a just-attached broker's authoritative queues as the active set.
    fn reseed(
        &self,
        app: &AppHandle,
        approvals: Vec<ApprovalDto>,
        elicitations: Vec<ElicitationSummary>,
    ) {
        let total = {
            let mut inner = self.inner.lock().unwrap();
            let _ = inner.tracker.adopt(approvals);
            inner.elicitations = elicitations
                .into_iter()
                .map(|elicitation| (elicitation.id.clone(), elicitation))
                .collect();
            inner.total()
        };
        crate::windows::update_request_count(app, total);
    }

    pub fn set_settings(&self, settings: NotificationSettings) {
        self.inner.lock().unwrap().settings = settings;
    }

    pub fn settings_view(&self) -> NotificationSettingsView {
        let inner = self.inner.lock().unwrap();
        NotificationSettingsView {
            mode: inner.settings.mode,
            show_context: inner.settings.show_context,
            available: inner.notifications_available,
            unavailable_reason: inner.notification_unavailable_reason.clone(),
            can_open_system_settings: cfg!(target_os = "macos"),
        }
    }

    fn mark_notifications_unavailable(&self, reason: String) -> Option<NotificationSettingsView> {
        let mut inner = self.inner.lock().unwrap();
        if !inner.notifications_available
            && inner.notification_unavailable_reason.as_deref() == Some(reason.as_str())
        {
            return None;
        }
        inner.notifications_available = false;
        inner.notification_unavailable_reason = Some(reason);
        Some(NotificationSettingsView {
            mode: inner.settings.mode,
            show_context: inner.settings.show_context,
            available: false,
            unavailable_reason: inner.notification_unavailable_reason.clone(),
            can_open_system_settings: cfg!(target_os = "macos"),
        })
    }

    fn enqueue_notification(
        &self,
        app: &AppHandle,
        title: String,
        body: String,
    ) -> Result<(), String> {
        {
            let inner = self.inner.lock().unwrap();
            if !inner.notifications_available {
                return Err(inner
                    .notification_unavailable_reason
                    .clone()
                    .unwrap_or_else(|| "native notifications are unavailable".into()));
            }
        }
        self.notification_tx
            .try_send(NotificationJob {
                app: app.clone(),
                title,
                body,
            })
            .map_err(|error| match error {
                mpsc::TrySendError::Full(_) => {
                    "native notification queue is full; requests were coalesced into the Inbox"
                        .into()
                }
                mpsc::TrySendError::Disconnected(_) => {
                    "native notification worker is unavailable".into()
                }
            })
    }

    pub fn count(&self) -> usize {
        self.inner.lock().unwrap().total()
    }

    fn begin_remote_refresh(&self) -> u64 {
        let mut inner = self.inner.lock().unwrap();
        inner.remote_refresh_generation = inner.remote_refresh_generation.wrapping_add(1);
        inner.remote_refresh_generation
    }

    fn reconcile_remote(&self, app: &AppHandle, generation: u64, snapshot: ApprovalSnapshotDto) {
        let Some(version) = RemoteSnapshotVersion::parse(&snapshot.version) else {
            tracing::warn!(version = %snapshot.version, "ignored malformed remote queue version");
            if self.remote_refresh_is_current(generation) {
                crate::windows::surface_for_approval(app);
            }
            return;
        };
        let (change, flush_generation, new_elicitations) = {
            let mut inner = self.inner.lock().unwrap();
            if !inner.accepts_remote_version(generation, &version) {
                return;
            }
            let old_total = inner.total();
            inner.last_remote_version = Some(version);
            let mut change = inner.tracker.reconcile(snapshot.approvals);
            let next_elicitations = snapshot
                .elicitations
                .into_iter()
                .map(ElicitationSummary::from)
                .map(|elicitation| (elicitation.id.clone(), elicitation))
                .collect::<BTreeMap<_, _>>();
            let new_elicitations = next_elicitations
                .iter()
                .filter(|(id, _)| !inner.elicitations.contains_key(*id))
                .map(|(_, elicitation)| elicitation.clone())
                .collect::<Vec<_>>();
            inner.elicitations = next_elicitations;
            change.count = inner.total();
            change.count_changed = old_total != change.count;
            let flush_generation = schedule_generation(&mut inner, change.notification_added);
            (change, flush_generation, new_elicitations)
        };
        apply_change(app, change, flush_generation);
        for elicitation in new_elicitations {
            notify_elicitation(app, &elicitation);
        }
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
        let total = inner.total();
        (requests, total, inner.settings)
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

    match attention
        .inner
        .lock()
        .unwrap()
        .admit_notification(Instant::now())
    {
        NotificationAdmission::Normal => {}
        NotificationAdmission::Storm => {
            crate::windows::surface_for_approval(app);
            let body = format!(
                "Open the Request Inbox to review {total} waiting requests. Further notifications are paused for one minute."
            );
            if let Err(error) =
                deliver_notification(app, "Many AgentMFA requests are waiting", &body)
            {
                tracing::warn!(%error, "could not deliver the notification rate-limit warning");
            }
            return;
        }
        NotificationAdmission::Suppressed => return,
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

/// Queue one native notification. One worker owns delivery and interaction
/// observation for the process, so an unacknowledged banner cannot leak one
/// blocked thread and one platform timer per request.
fn deliver_notification(app: &AppHandle, title: &str, body: &str) -> Result<(), String> {
    let attention = app
        .try_state::<RequestAttention>()
        .ok_or_else(|| "notification coordinator is unavailable".to_string())?;
    attention.enqueue_notification(app, title.to_string(), body.to_string())
}

fn notification_worker(rx: mpsc::Receiver<NotificationJob>) {
    while let Ok(job) = rx.recv() {
        let Some(attention) = job.app.try_state::<RequestAttention>() else {
            continue;
        };
        if !attention.inner.lock().unwrap().notifications_available {
            continue;
        }
        deliver_notification_job(job);
    }
}

fn deliver_notification_job(job: NotificationJob) {
    let mut notification = notify_rust::Notification::new();
    notification
        .summary(&job.title)
        .body(&job.body)
        .action(OPEN_INBOX_ACTION, "Open Inbox");
    // XDG servers only emit body activation when the special default action
    // is advertised; some desktops hide named buttons entirely.
    #[cfg(all(unix, not(target_os = "macos")))]
    notification.action("default", "Open Inbox");
    if let Err(error) = configure_notification_identity(&job.app, &mut notification) {
        notification_delivery_failed(&job.app, error);
        return;
    }
    let shown_at = Instant::now();
    let handle = match notification.show() {
        Ok(handle) => handle,
        Err(error) => {
            notification_delivery_failed(&job.app, error.to_string());
            return;
        }
    };

    // The deprecated macOS backend can block forever after delivery. One
    // short-lived watchdog guards the single worker; on timeout delivery is
    // disabled for the session, so this worker is the only thread that can
    // remain parked and no further platform timers are created.
    let (done_tx, done_rx) = mpsc::sync_channel(1);
    let watchdog_app = job.app.clone();
    let _ = std::thread::Builder::new()
        .name("aka-notification-watchdog".into())
        .spawn(move || {
            if done_rx
                .recv_timeout(NOTIFICATION_RESPONSE_DEADLINE)
                .is_err()
            {
                notification_delivery_failed(
                    &watchdog_app,
                    "native notification interaction timed out; using the Request Inbox instead"
                        .into(),
                );
            }
        });

    let response_app = job.app.clone();
    let result = handle.wait_for_response(move |response: &notify_rust::NotificationResponse| {
        if notification_opens_inbox(response) {
            crate::windows::open_request_inbox(&response_app);
        }
        if matches!(
            response,
            notify_rust::NotificationResponse::Closed(notify_rust::CloseReason::Expired)
        ) && shown_at.elapsed() <= NOTIFICATION_DELIVERY_DEADLINE
        {
            notification_delivery_failed(
                &response_app,
                "Notifications appear to be blocked by the operating system".into(),
            );
        }
    });
    let _ = done_tx.try_send(());
    if let Err(error) = result {
        notification_delivery_failed(
            &job.app,
            format!("could not observe native notification delivery: {error}"),
        );
    }
}

fn notification_delivery_failed(app: &AppHandle, reason: String) {
    tracing::warn!(%reason, "native request notifications unavailable");
    mark_notifications_unavailable(app, reason);
    crate::windows::surface_for_approval(app);
}

fn mark_notifications_unavailable(app: &AppHandle, reason: String) {
    if let Some(attention) = app.try_state::<RequestAttention>() {
        if let Some(view) = attention.mark_notifications_unavailable(reason) {
            let _ = app.emit(crate::commands::EVT_NOTIFICATION_SETTINGS, view);
        }
    }
}

/// Establish the platform notification identity and probe authorization once,
/// before either broker can park work on this surface.
pub fn initialize_notification_delivery(app: &AppHandle) {
    #[cfg(target_os = "macos")]
    {
        if tauri::is_dev() {
            mark_notifications_unavailable(
                app,
                "Development build: native notifications are disabled".into(),
            );
            return;
        }
        let expected = app.config().identifier.as_str();
        #[allow(deprecated)]
        let configured = notify_rust::set_application(expected);
        let actual = main_bundle_identifier();
        if let Err(error) = configured {
            mark_notifications_unavailable(
                app,
                format!("Could not configure native notifications: {error}"),
            );
            return;
        }
        if actual.as_deref() != Some(expected) {
            mark_notifications_unavailable(
                app,
                format!(
                    "Native notification identity changed unexpectedly (expected {expected}, got {})",
                    actual.as_deref().unwrap_or("no bundle identifier")
                ),
            );
            return;
        }
    }

    match app.notification().permission_state() {
        Ok(PermissionState::Granted) => {}
        Ok(PermissionState::Denied) => mark_notifications_unavailable(
            app,
            "Notifications are blocked in operating-system settings".into(),
        ),
        Ok(PermissionState::Prompt | PermissionState::PromptWithRationale) => {
            mark_notifications_unavailable(
                app,
                "Notification permission has not been granted".into(),
            )
        }
        Err(error) => mark_notifications_unavailable(
            app,
            format!("Could not check notification permission: {error}"),
        ),
    }
}

#[cfg(target_os = "macos")]
fn main_bundle_identifier() -> Option<String> {
    use objc2_foundation::NSBundle;
    NSBundle::mainBundle()
        .bundleIdentifier()
        .map(|identifier| identifier.to_string())
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
    // Initialized exactly once during setup. Calling set_application here
    // would process-wide swizzle NSBundle after a request was already parked.
    Ok(())
}

#[cfg(target_os = "windows")]
fn configure_notification_identity(
    app: &AppHandle,
    notification: &mut notify_rust::Notification,
) -> Result<(), String> {
    // Windows accepts the configured AppUserModel ID only for an installed
    // application. Development builds retain notify-rust's PowerShell ID.
    if !tauri::is_dev() {
        notification.app_id(&app.config().identifier);
    }
    Ok(())
}

#[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
fn configure_notification_identity(
    app: &AppHandle,
    notification: &mut notify_rust::Notification,
) -> Result<(), String> {
    use tauri::path::BaseDirectory;

    // The icon is cosmetic. An error here would abort delivery and mark
    // notifications unavailable for the rest of the session, so a missing
    // or odd resource layout merely loses the icon, never the notification.
    match app.path().resolve("icons/icon.png", BaseDirectory::Resource) {
        Ok(icon) => match icon.to_str() {
            Some(icon) => {
                notification.icon(icon);
            }
            None => tracing::warn!("bundled notification icon path is not valid UTF-8"),
        },
        Err(error) => {
            tracing::warn!(%error, "could not resolve the bundled notification icon")
        }
    }
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
    let normalized = aka_core::untrusted_text::sanitize(value)
        .chars()
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

/// Point attention at a local broker that is already running, and adopt
/// whatever is parked on it.
///
/// The local stack starts *before* the shell commits to it, so a prompt
/// raised during that window is tracked under the outgoing broker's scope
/// and cleared by the scope change. The remote path self-heals through its
/// event stream's authoritative refetch; local mode has no such stream, so
/// it reseeds explicitly here.
pub fn adopt_local(app: &AppHandle, broker: &aka_core::broker::Broker) {
    let Some(attention) = app.try_state::<RequestAttention>() else {
        return;
    };
    attention.set_scope(app, scope_key("local", None));
    attention.reseed(
        app,
        broker
            .pending_approvals()
            .iter()
            .map(aka_core::manage::approval_dto)
            .collect(),
        broker
            .pending_elicitations()
            .iter()
            .map(|pending| ElicitationSummary {
                id: pending.id.to_string(),
                agent: pending.agent.clone(),
                connection: pending.connection.clone(),
            })
            .collect(),
    );
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
/// is not folded into the coalescing tracker — an upstream elicitation is a
/// single, distinct question — so it raises one notification directly while
/// still contributing to the shared tray count.
pub fn elicitation_requested(
    app: &AppHandle,
    pending: &aka_core::elicitations::PendingElicitation,
) {
    let Some(attention) = app.try_state::<RequestAttention>() else {
        return;
    };
    let elicitation = ElicitationSummary {
        id: pending.id.to_string(),
        agent: pending.agent.clone(),
        connection: pending.connection.clone(),
    };
    // Count and notify only on the first observation of this id.
    if !attention.add_elicitation(app, elicitation.clone()) {
        return;
    }
    notify_elicitation(app, &elicitation);
}

fn notify_elicitation(app: &AppHandle, pending: &ElicitationSummary) {
    let Some(attention) = app.try_state::<RequestAttention>() else {
        return;
    };
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
    let total = attention.count();
    match attention
        .inner
        .lock()
        .unwrap()
        .admit_notification(Instant::now())
    {
        NotificationAdmission::Normal => {}
        NotificationAdmission::Storm => {
            crate::windows::surface_for_approval(app);
            let body = format!(
                "Open the Request Inbox to review {total} waiting requests. Further notifications are paused for one minute."
            );
            if let Err(error) =
                deliver_notification(app, "Many AgentMFA requests are waiting", &body)
            {
                tracing::warn!(%error, "could not deliver the notification rate-limit warning");
            }
            return;
        }
        NotificationAdmission::Suppressed => return,
    }
    let title = "AgentMFA needs your input".to_string();
    let body = if show_context {
        let agent = notification_label(&pending.agent, "An agent");
        let connection = notification_label(&pending.connection, "a tool");
        format!(
            "{connection} needs your input. {agent} is paused. Open the Request Inbox to respond."
        )
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
        attention.remove_elicitation(app, &id.to_string());
    }
}

pub fn begin_remote_refresh(app: &AppHandle) -> Option<u64> {
    app.try_state::<RequestAttention>()
        .map(|attention| attention.begin_remote_refresh())
}

pub fn reconcile_remote(app: &AppHandle, generation: u64, snapshot: ApprovalSnapshotDto) {
    if let Some(attention) = app.try_state::<RequestAttention>() {
        attention.reconcile_remote(app, generation, snapshot);
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
            consequence: None,
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
    fn changing_brokers_clears_elicitations_from_the_total() {
        let attention = RequestAttention::new(NotificationSettings::default());
        let mut inner = attention.inner.lock().unwrap();
        assert_eq!(inner.set_scope("local".into()), Some(0));
        inner.elicitations.insert(
            "elicitation".into(),
            ElicitationSummary {
                id: "elicitation".into(),
                agent: "codex".into(),
                connection: "github".into(),
            },
        );
        assert_eq!(inner.total(), 1);
        assert_eq!(
            inner.set_scope("remote:https://broker.example".into()),
            Some(0)
        );
        assert!(inner.elicitations.is_empty());
    }

    #[test]
    fn sustained_notifications_are_bounded_and_recover() {
        let attention = RequestAttention::new(NotificationSettings::default());
        let start = Instant::now();
        let mut inner = attention.inner.lock().unwrap();
        for offset in 0..NOTIFICATION_RATE_LIMIT {
            assert_eq!(
                inner.admit_notification(start + Duration::from_secs(offset as u64)),
                NotificationAdmission::Normal
            );
        }
        assert_eq!(
            inner.admit_notification(start + Duration::from_secs(5)),
            NotificationAdmission::Storm
        );
        assert_eq!(
            inner.admit_notification(start + Duration::from_secs(6)),
            NotificationAdmission::Suppressed
        );
        assert_eq!(
            inner.admit_notification(start + NOTIFICATION_RATE_WINDOW),
            NotificationAdmission::Normal
        );
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
    fn broker_sequence_not_fetch_start_orders_same_epoch_snapshots() {
        let attention = RequestAttention::new(NotificationSettings::default());
        let older_fetch = attention.begin_remote_refresh();
        let newer_fetch = attention.begin_remote_refresh();
        let mut inner = attention.inner.lock().unwrap();
        inner.last_remote_version = Some(RemoteSnapshotVersion {
            epoch: "broker-a".into(),
            seq: 8,
        });

        assert!(inner.accepts_remote_version(
            older_fetch,
            &RemoteSnapshotVersion {
                epoch: "broker-a".into(),
                seq: 9,
            },
        ));
        assert!(!inner.accepts_remote_version(
            newer_fetch,
            &RemoteSnapshotVersion {
                epoch: "broker-a".into(),
                seq: 7,
            },
        ));
    }

    #[test]
    fn only_latest_fetch_can_establish_a_new_broker_epoch() {
        let attention = RequestAttention::new(NotificationSettings::default());
        let older_fetch = attention.begin_remote_refresh();
        let latest_fetch = attention.begin_remote_refresh();
        let mut inner = attention.inner.lock().unwrap();
        inner.last_remote_version = Some(RemoteSnapshotVersion {
            epoch: "broker-a".into(),
            seq: 8,
        });
        let restarted = RemoteSnapshotVersion {
            epoch: "broker-b".into(),
            seq: 1,
        };

        assert!(!inner.accepts_remote_version(older_fetch, &restarted));
        assert!(inner.accepts_remote_version(latest_fetch, &restarted));
    }

    #[test]
    fn notification_failure_is_sticky_and_preserves_preferences() {
        let attention = RequestAttention::new(NotificationSettings {
            mode: NotificationMode::Always,
            show_context: true,
        });

        let changed = attention
            .mark_notifications_unavailable("blocked by settings".into())
            .unwrap();
        assert!(!changed.available);
        assert_eq!(changed.mode, NotificationMode::Always);
        assert!(changed.show_context);
        assert_eq!(
            changed.unavailable_reason.as_deref(),
            Some("blocked by settings")
        );
        assert!(attention
            .mark_notifications_unavailable("blocked by settings".into())
            .is_none());
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
            "codex\u{FFFD}gpj.exe\u{FFFD}"
        );
        assert_eq!(
            notification_label("codex\u{200B}\u{3164}\u{E0001}", "An agent"),
            "codex\u{FFFD}\u{FFFD}\u{FFFD}"
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
