//! Native attention delivery for requests waiting on the user.
//!
//! The broker remains authoritative. This coordinator only remembers the
//! active IDs it has already observed so reconnects and coalesced waiters do
//! not produce duplicate desktop notifications. The inbox itself always
//! refetches from the broker.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use aka_api::{ApprovalDto, ApprovalSnapshotDto, ElicitationDto};
use serde::Serialize;
use tauri::{AppHandle, Emitter as _, Manager as _};
#[cfg(not(target_os = "macos"))]
use tauri_plugin_notification::{NotificationExt as _, PermissionState};

use crate::broker_mode::{NotificationMode, NotificationSettings};

const NOTIFICATION_DEBOUNCE: Duration = Duration::from_millis(400);
const NOTIFICATION_DELIVERY_DEADLINE: Duration = Duration::from_secs(3);
const NOTIFICATION_RESPONSE_DEADLINE: Duration = Duration::from_secs(5 * 60);
const NOTIFICATION_QUEUE_DEPTH: usize = 2;
const NOTIFICATION_RATE_WINDOW: Duration = Duration::from_secs(60);
const NOTIFICATION_RATE_LIMIT: usize = 4;
/// Four admitted banners per minute with a five-minute watchdog can have at
/// most twenty legitimate observers live at once. Keep that as a hard cap too
/// so a broken platform callback cannot leak response threads indefinitely.
const NOTIFICATION_OBSERVER_LIMIT: usize = 20;
const OPEN_INBOX_ACTION: &str = "open_request_inbox";
/// Even with optional native re-alerts disabled, bring the Inbox forward
/// shortly before parked work expires. Focus/DND can accept a notification
/// without ever making it visible, so high-consequence requests need an
/// in-app fallback that does not depend on notification delivery.
const DEADLINE_FALLBACK_LEAD: Duration = Duration::from_secs(10);
const UNKNOWN_DEADLINE_FALLBACK_DELAY: Duration = Duration::from_secs(60);

struct NotificationObserverPermit(Arc<AtomicUsize>);

impl Drop for NotificationObserverPermit {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

fn try_notification_observer(observers: &Arc<AtomicUsize>) -> Option<NotificationObserverPermit> {
    observers
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
            (active < NOTIFICATION_OBSERVER_LIMIT).then_some(active + 1)
        })
        .ok()
        .map(|_| NotificationObserverPermit(observers.clone()))
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ElicitationSummary {
    id: String,
    agent: String,
    connection: String,
    deadline: Option<Instant>,
}

impl From<ElicitationDto> for ElicitationSummary {
    fn from(elicitation: ElicitationDto) -> Self {
        Self {
            id: elicitation.id,
            agent: elicitation.agent,
            connection: elicitation.connection,
            deadline: deadline_from_now(elicitation.expires_in_secs),
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
    key: String,
    title: String,
    body: String,
    play_sound: bool,
    time_sensitive: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum NativeNotificationId {
    #[cfg(target_os = "macos")]
    Mac(String),
    #[cfg(all(unix, not(target_os = "macos")))]
    Xdg(u32),
}

#[derive(Debug)]
struct TrackedNotification {
    subjects: BTreeSet<String>,
    native_id: Option<NativeNotificationId>,
}

fn approval_subject(id: &str) -> String {
    format!("approval:{id}")
}

fn elicitation_subject(id: &str) -> String {
    format!("elicitation:{id}")
}

/// Preferences plus this process's delivery health. The health fields are
/// intentionally not persisted: a relaunch probes the platform again.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NotificationSettingsView {
    pub mode: NotificationMode,
    pub show_context: bool,
    pub play_sound: bool,
    pub time_sensitive: bool,
    pub escalation_secs: u64,
    pub available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unavailable_reason: Option<String>,
    pub can_open_system_settings: bool,
    pub can_request_permission: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RequestSummary {
    id: String,
    agent: String,
    connection: String,
    deadline: Option<Instant>,
}

impl From<ApprovalDto> for RequestSummary {
    fn from(approval: ApprovalDto) -> Self {
        Self {
            id: approval.id,
            agent: approval.agent,
            connection: approval.connection,
            deadline: deadline_from_now(approval.expires_in_secs),
        }
    }
}

fn deadline_from_now(expires_in_secs: Option<u64>) -> Option<Instant> {
    expires_in_secs.and_then(|secs| Instant::now().checked_add(Duration::from_secs(secs)))
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
            resolved_requests: Vec::new(),
        }
    }

    fn reconcile(&mut self, approvals: Vec<ApprovalDto>) -> TrackerChange {
        let old_count = self.active.len();
        let next: BTreeMap<String, RequestSummary> = approvals
            .into_iter()
            .map(RequestSummary::from)
            .map(|request| (request.id.clone(), request))
            .collect::<BTreeMap<_, _>>();
        let resolved_requests = self
            .active
            .iter()
            .filter(|(id, _)| !next.contains_key(*id))
            .map(|(_, request)| request.clone())
            .collect();
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
            resolved_requests,
        }
    }

    /// Take an authoritative snapshot as the active set *without* queueing
    /// notifications. Used when the shell adopts a broker that was already
    /// running: anything parked on it has had its notification attempt
    /// already, so this restores tracking without alerting twice.
    fn adopt(&mut self, approvals: Vec<ApprovalDto>) -> TrackerChange {
        let old_count = self.active.len();
        let next: BTreeMap<String, RequestSummary> = approvals
            .into_iter()
            .map(RequestSummary::from)
            .map(|request| (request.id.clone(), request))
            .collect();
        let resolved_requests = self
            .active
            .iter()
            .filter(|(id, _)| !next.contains_key(*id))
            .map(|(_, request)| request.clone())
            .collect();
        self.active = next;
        self.pending_notification
            .retain(|id| self.active.contains_key(id));
        TrackerChange {
            count: self.active.len(),
            count_changed: old_count != self.active.len(),
            notification_added: false,
            resolved_requests,
        }
    }

    fn resolve(&mut self, id: &str) -> TrackerChange {
        let old_count = self.active.len();
        let resolved_requests = self.active.remove(id).into_iter().collect();
        self.pending_notification.remove(id);
        TrackerChange {
            count: self.active.len(),
            count_changed: old_count != self.active.len(),
            notification_added: false,
            resolved_requests,
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
    resolved_requests: Vec<RequestSummary>,
}

struct AttentionInner {
    tracker: AttentionTracker,
    settings: NotificationSettings,
    flush_generation: u64,
    flush_scheduled: bool,
    expiry_flush_generation: u64,
    expiry_flush_scheduled: bool,
    pending_expirations: BTreeMap<String, RequestSummary>,
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
    notification_permission_prompt: bool,
    /// Native banners are deliberately scarce: the Inbox and tray remain
    /// authoritative when a noisy upstream keeps creating distinct prompts.
    notification_times: VecDeque<Instant>,
    notification_storm_announced: bool,
    /// Setting changes invalidate already-spawned timers. Subjects remain in
    /// this set across those changes so each request gets at most one
    /// escalation attempt.
    escalation_generation: u64,
    escalated_subjects: BTreeSet<String>,
    /// A debounced banner can represent several requests. Keep the native
    /// identifier plus the unresolved subjects it represents so one resolved
    /// member does not withdraw a banner that still describes live work.
    tracked_notifications: BTreeMap<String, TrackedNotification>,
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

    fn set_scope(&mut self, scope: String) -> Option<(usize, Vec<NativeNotificationId>)> {
        if !self.tracker.set_scope(scope) {
            return None;
        }
        let native_notifications = self.clear_notifications();
        self.flush_generation = self.flush_generation.wrapping_add(1);
        self.flush_scheduled = false;
        self.expiry_flush_generation = self.expiry_flush_generation.wrapping_add(1);
        self.expiry_flush_scheduled = false;
        self.pending_expirations.clear();
        self.remote_refresh_generation = self.remote_refresh_generation.wrapping_add(1);
        self.last_remote_version = None;
        self.elicitations.clear();
        self.notification_times.clear();
        self.notification_storm_announced = false;
        self.escalation_generation = self.escalation_generation.wrapping_add(1);
        self.escalated_subjects.clear();
        Some((self.total(), native_notifications))
    }

    fn track_notification(&mut self, key: String, subjects: BTreeSet<String>) {
        self.tracked_notifications.insert(
            key,
            TrackedNotification {
                subjects,
                native_id: None,
            },
        );
    }

    /// Record delivery and attach the platform identifier when one exists.
    /// `false` means every represented request resolved while the job was
    /// waiting in the bounded queue, so the just-shown banner must be
    /// withdrawn immediately on platforms that support it.
    fn attach_native_notification(
        &mut self,
        key: &str,
        native_id: Option<NativeNotificationId>,
    ) -> bool {
        let Some(tracked) = self.tracked_notifications.get_mut(key) else {
            return false;
        };
        if tracked.subjects.is_empty() {
            self.tracked_notifications.remove(key);
            return false;
        }
        tracked.native_id = native_id;
        true
    }

    fn notification_is_pending(&self, key: &str) -> bool {
        self.tracked_notifications
            .get(key)
            .is_some_and(|tracked| !tracked.subjects.is_empty())
    }

    fn notification_finished(&mut self, key: &str) {
        self.tracked_notifications.remove(key);
    }

    fn resolve_notification_subject(&mut self, subject: &str) -> Vec<NativeNotificationId> {
        let mut empty = Vec::new();
        for (key, tracked) in &mut self.tracked_notifications {
            tracked.subjects.remove(subject);
            if tracked.subjects.is_empty() {
                empty.push(key.clone());
            }
        }
        empty
            .into_iter()
            .filter_map(|key| {
                self.tracked_notifications
                    .remove(&key)
                    .and_then(|tracked| tracked.native_id)
            })
            .collect()
    }

    fn clear_notifications(&mut self) -> Vec<NativeNotificationId> {
        std::mem::take(&mut self.tracked_notifications)
            .into_values()
            .filter_map(|tracked| tracked.native_id)
            .collect()
    }

    fn notification_subject_is_active(&self, subject: &str) -> bool {
        subject
            .strip_prefix("approval:")
            .is_some_and(|id| self.tracker.active.contains_key(id))
            || subject
                .strip_prefix("elicitation:")
                .is_some_and(|id| self.elicitations.contains_key(id))
    }

    fn active_notification_subjects(&self) -> BTreeSet<String> {
        self.tracker
            .active
            .keys()
            .map(|id| approval_subject(id))
            .chain(self.elicitations.keys().map(|id| elicitation_subject(id)))
            .collect()
    }

    fn active_subject_deadlines(&self) -> Vec<(String, Option<Instant>)> {
        self.tracker
            .active
            .iter()
            .map(|(id, request)| (approval_subject(id), request.deadline))
            .chain(
                self.elicitations
                    .iter()
                    .map(|(id, elicitation)| (elicitation_subject(id), elicitation.deadline)),
            )
            .collect()
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

#[derive(Clone, Debug, PartialEq, Eq)]
struct NotificationContent {
    title: String,
    body: String,
    play_sound: bool,
    time_sensitive: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum DeliveryPlan {
    Notify(NotificationContent),
    SurfaceWindow,
    Suppress,
}

trait NotificationSink {
    fn deliver(&self, content: &NotificationContent) -> Result<(), String>;
}

struct QueueNotificationSink<'a> {
    attention: &'a RequestAttention,
    app: &'a AppHandle,
    subjects: BTreeSet<String>,
}

impl NotificationSink for QueueNotificationSink<'_> {
    fn deliver(&self, content: &NotificationContent) -> Result<(), String> {
        self.attention.enqueue_notification(
            self.app,
            content.title.clone(),
            content.body.clone(),
            content.play_sound,
            content.time_sensitive,
            self.subjects.clone(),
            true,
        )
    }
}

/// Managed Tauri state shared by local broker callbacks and the remote SSE
/// reconciliation path.
pub struct RequestAttention {
    inner: Mutex<AttentionInner>,
    notification_tx: mpsc::SyncSender<NotificationJob>,
}

impl Drop for RequestAttention {
    fn drop(&mut self) {
        let Ok(inner) = self.inner.get_mut() else {
            return;
        };
        for notification in inner.clear_notifications() {
            if let Err(error) = withdraw_native_notification(&notification) {
                tracing::warn!(%error, "could not withdraw a native notification during shutdown");
            }
        }
    }
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
                expiry_flush_generation: 0,
                expiry_flush_scheduled: false,
                pending_expirations: BTreeMap::new(),
                remote_refresh_generation: 0,
                last_remote_version: None,
                elicitations: BTreeMap::new(),
                // The platform probe runs after managed state is installed.
                // Until it completes, fail closed into the in-app surface so
                // an early request cannot race past onboarding or disappear.
                notifications_available: false,
                notification_unavailable_reason: Some(
                    "Checking operating-system notification permission".into(),
                ),
                notification_permission_prompt: false,
                notification_times: VecDeque::new(),
                notification_storm_announced: false,
                escalation_generation: 0,
                escalated_subjects: BTreeSet::new(),
                tracked_notifications: BTreeMap::new(),
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

    fn resolve(&self, app: &AppHandle, id: &str, expired: bool) {
        let (change, notifications, expiry_generation) = {
            let mut inner = self.inner.lock().unwrap();
            let mut change = inner.tracker.resolve(id);
            change.count = inner.total();
            let expiry_generation = if expired {
                change
                    .resolved_requests
                    .first()
                    .cloned()
                    .and_then(|request| queue_expiration(&mut inner, request))
            } else {
                None
            };
            let notifications = inner.resolve_notification_subject(&approval_subject(id));
            inner.escalated_subjects.remove(&approval_subject(id));
            (change, notifications, expiry_generation)
        };
        withdraw_notifications(notifications);
        apply_change(app, change, None);
        schedule_expiry_flush(app, expiry_generation);
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
        let (total, changed, notifications) = {
            let mut inner = self.inner.lock().unwrap();
            let changed = inner.elicitations.remove(id).is_some();
            let notifications = inner.resolve_notification_subject(&elicitation_subject(id));
            inner.escalated_subjects.remove(&elicitation_subject(id));
            (inner.total(), changed, notifications)
        };
        withdraw_notifications(notifications);
        if changed {
            crate::windows::update_request_count(app, total);
        }
    }

    fn set_scope(&self, app: &AppHandle, scope: String) {
        let change = self.inner.lock().unwrap().set_scope(scope);
        if let Some((total, notifications)) = change {
            withdraw_notifications(notifications);
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
        let (total, notifications) = {
            let mut inner = self.inner.lock().unwrap();
            let change = inner.tracker.adopt(approvals);
            let next_elicitations: BTreeMap<String, ElicitationSummary> = elicitations
                .into_iter()
                .map(|elicitation| (elicitation.id.clone(), elicitation))
                .collect();
            let resolved_elicitations = inner
                .elicitations
                .keys()
                .filter(|id| !next_elicitations.contains_key(*id))
                .cloned()
                .collect::<Vec<_>>();
            inner.elicitations = next_elicitations;
            let mut notifications = Vec::new();
            for request in change.resolved_requests {
                let subject = approval_subject(&request.id);
                notifications.extend(inner.resolve_notification_subject(&subject));
                inner.escalated_subjects.remove(&subject);
            }
            for id in resolved_elicitations {
                let subject = elicitation_subject(&id);
                notifications.extend(inner.resolve_notification_subject(&subject));
                inner.escalated_subjects.remove(&subject);
            }
            (inner.total(), notifications)
        };
        withdraw_notifications(notifications);
        crate::windows::update_request_count(app, total);
    }

    pub fn set_settings(&self, app: &AppHandle, settings: NotificationSettings) {
        let reschedule = {
            let mut inner = self.inner.lock().unwrap();
            let schedule_changed = inner.settings.escalation_secs != settings.escalation_secs
                || inner.settings.mode != settings.mode;
            inner.settings = settings;
            if schedule_changed {
                inner.escalation_generation = inner.escalation_generation.wrapping_add(1);
            }
            (schedule_changed && settings.mode != NotificationMode::Off)
                .then(|| inner.active_subject_deadlines())
        };
        if let Some(subjects) = reschedule {
            for (subject, deadline) in subjects {
                schedule_escalation(
                    app,
                    BTreeSet::from([subject]),
                    deadline,
                    settings.escalation_secs,
                );
            }
        }
    }

    pub fn settings_view(&self) -> NotificationSettingsView {
        let inner = self.inner.lock().unwrap();
        NotificationSettingsView {
            mode: inner.settings.mode,
            show_context: inner.settings.show_context,
            play_sound: inner.settings.play_sound,
            time_sensitive: inner.settings.time_sensitive,
            escalation_secs: inner.settings.escalation_secs,
            available: inner.notifications_available,
            unavailable_reason: inner.notification_unavailable_reason.clone(),
            can_open_system_settings: cfg!(target_os = "macos"),
            can_request_permission: inner.notification_permission_prompt,
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
        inner.notification_permission_prompt = false;
        Some(NotificationSettingsView {
            mode: inner.settings.mode,
            show_context: inner.settings.show_context,
            play_sound: inner.settings.play_sound,
            time_sensitive: inner.settings.time_sensitive,
            escalation_secs: inner.settings.escalation_secs,
            available: false,
            unavailable_reason: inner.notification_unavailable_reason.clone(),
            can_open_system_settings: cfg!(target_os = "macos"),
            can_request_permission: false,
        })
    }

    fn mark_notification_permission_required(&self) -> NotificationSettingsView {
        let mut inner = self.inner.lock().unwrap();
        inner.notifications_available = false;
        inner.notification_unavailable_reason = Some(
            "Multitool needs notification permission to alert you before requests expire.".into(),
        );
        inner.notification_permission_prompt = true;
        NotificationSettingsView {
            mode: inner.settings.mode,
            show_context: inner.settings.show_context,
            play_sound: inner.settings.play_sound,
            time_sensitive: inner.settings.time_sensitive,
            escalation_secs: inner.settings.escalation_secs,
            available: false,
            unavailable_reason: inner.notification_unavailable_reason.clone(),
            can_open_system_settings: cfg!(target_os = "macos"),
            can_request_permission: true,
        }
    }

    fn mark_notifications_available(&self) -> NotificationSettingsView {
        let mut inner = self.inner.lock().unwrap();
        inner.notifications_available = true;
        inner.notification_unavailable_reason = None;
        inner.notification_permission_prompt = false;
        NotificationSettingsView {
            mode: inner.settings.mode,
            show_context: inner.settings.show_context,
            play_sound: inner.settings.play_sound,
            time_sensitive: inner.settings.time_sensitive,
            escalation_secs: inner.settings.escalation_secs,
            available: true,
            unavailable_reason: None,
            can_open_system_settings: cfg!(target_os = "macos"),
            can_request_permission: false,
        }
    }

    fn enqueue_notification(
        &self,
        app: &AppHandle,
        title: String,
        body: String,
        play_sound: bool,
        time_sensitive: bool,
        mut subjects: BTreeSet<String>,
        filter_active: bool,
    ) -> Result<(), String> {
        let key = uuid::Uuid::new_v4().to_string();
        {
            let mut inner = self.inner.lock().unwrap();
            if !inner.notifications_available {
                return Err(inner
                    .notification_unavailable_reason
                    .clone()
                    .unwrap_or_else(|| "native notifications are unavailable".into()));
            }
            if filter_active {
                subjects.retain(|subject| inner.notification_subject_is_active(subject));
            }
            if subjects.is_empty() {
                return Ok(());
            }
            inner.track_notification(key.clone(), subjects);
        }
        let result = self
            .notification_tx
            .try_send(NotificationJob {
                app: app.clone(),
                key: key.clone(),
                title,
                body,
                play_sound,
                time_sensitive,
            })
            .map_err(|error| match error {
                mpsc::TrySendError::Full(_) => {
                    "native notification queue is full; requests were coalesced into the Inbox"
                        .into()
                }
                mpsc::TrySendError::Disconnected(_) => {
                    "native notification worker is unavailable".into()
                }
            });
        if result.is_err() {
            self.inner.lock().unwrap().notification_finished(&key);
        }
        result
    }

    pub fn count(&self) -> usize {
        self.inner.lock().unwrap().total()
    }

    fn active_notification_subjects(&self) -> BTreeSet<String> {
        self.inner.lock().unwrap().active_notification_subjects()
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
        let (change, flush_generation, new_elicitations, notifications) = {
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
            let resolved_elicitations = inner
                .elicitations
                .keys()
                .filter(|id| !next_elicitations.contains_key(*id))
                .cloned()
                .collect::<Vec<_>>();
            inner.elicitations = next_elicitations;
            change.count = inner.total();
            change.count_changed = old_total != change.count;
            let flush_generation = schedule_generation(&mut inner, change.notification_added);
            let resolved_approvals = change.resolved_requests.clone();
            let mut notifications = Vec::new();
            for request in resolved_approvals {
                let subject = approval_subject(&request.id);
                notifications.extend(inner.resolve_notification_subject(&subject));
                inner.escalated_subjects.remove(&subject);
            }
            for id in resolved_elicitations {
                let subject = elicitation_subject(&id);
                notifications.extend(inner.resolve_notification_subject(&subject));
                inner.escalated_subjects.remove(&subject);
            }
            (change, flush_generation, new_elicitations, notifications)
        };
        withdraw_notifications(notifications);
        apply_change(app, change, flush_generation);
        for elicitation in new_elicitations {
            notify_elicitation(app, &elicitation);
        }
    }

    fn remote_refresh_is_current(&self, generation: u64) -> bool {
        generation == self.inner.lock().unwrap().remote_refresh_generation
    }

    fn attach_native_notification(
        &self,
        key: &str,
        native_id: Option<NativeNotificationId>,
    ) -> bool {
        self.inner
            .lock()
            .unwrap()
            .attach_native_notification(key, native_id)
    }

    fn notification_is_pending(&self, key: &str) -> bool {
        self.inner.lock().unwrap().notification_is_pending(key)
    }

    fn notification_finished(&self, key: &str) {
        self.inner.lock().unwrap().notification_finished(key);
    }
}

fn schedule_generation(inner: &mut AttentionInner, notification_added: bool) -> Option<u64> {
    if !notification_added || inner.flush_scheduled {
        return None;
    }
    inner.flush_scheduled = true;
    Some(inner.flush_generation)
}

fn queue_expiration(inner: &mut AttentionInner, request: RequestSummary) -> Option<u64> {
    inner
        .pending_expirations
        .insert(request.id.clone(), request);
    if inner.expiry_flush_scheduled {
        return None;
    }
    inner.expiry_flush_scheduled = true;
    Some(inner.expiry_flush_generation)
}

fn schedule_expiry_flush(app: &AppHandle, generation: Option<u64>) {
    let Some(generation) = generation else {
        return;
    };
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(NOTIFICATION_DEBOUNCE).await;
        flush_expirations(&app, generation);
    });
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

struct PendingFlush {
    requests: Vec<RequestSummary>,
    total: usize,
    settings: NotificationSettings,
}

struct PendingExpirations {
    requests: Vec<RequestSummary>,
    settings: NotificationSettings,
}

fn take_pending_flush(inner: &mut AttentionInner, generation: u64) -> Option<PendingFlush> {
    if generation != inner.flush_generation {
        return None;
    }
    inner.flush_scheduled = false;
    let requests = inner.tracker.take_pending();
    if requests.is_empty() {
        return None;
    }
    Some(PendingFlush {
        requests,
        total: inner.total(),
        settings: inner.settings,
    })
}

fn take_pending_expirations(
    inner: &mut AttentionInner,
    generation: u64,
) -> Option<PendingExpirations> {
    if generation != inner.expiry_flush_generation {
        return None;
    }
    inner.expiry_flush_scheduled = false;
    let requests = std::mem::take(&mut inner.pending_expirations)
        .into_values()
        .collect::<Vec<_>>();
    if requests.is_empty() {
        return None;
    }
    Some(PendingExpirations {
        requests,
        settings: inner.settings,
    })
}

fn flush_notification(app: &AppHandle, generation: u64) {
    let Some(attention) = app.try_state::<RequestAttention>() else {
        return;
    };
    let Some(pending) = ({
        let mut inner = attention.inner.lock().unwrap();
        take_pending_flush(&mut inner, generation)
    }) else {
        return;
    };
    if pending.settings.mode != NotificationMode::Off {
        for request in &pending.requests {
            schedule_escalation(
                app,
                BTreeSet::from([approval_subject(&request.id)]),
                request.deadline,
                pending.settings.escalation_secs,
            );
        }
    }

    let content = match request_delivery_plan(
        &pending.requests,
        pending.total,
        pending.settings,
        crate::windows::request_surface_focused(),
    ) {
        DeliveryPlan::SurfaceWindow => {
            crate::windows::surface_for_approval(app);
            return;
        }
        DeliveryPlan::Suppress => return,
        DeliveryPlan::Notify(content) => content,
    };
    let subjects = pending
        .requests
        .iter()
        .map(|request| approval_subject(&request.id))
        .collect::<BTreeSet<_>>();
    if pending.settings.mode == NotificationMode::Always {
        crate::windows::request_critical_attention(app);
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
            let storm_subjects = attention.active_notification_subjects();
            let body = format!(
                "Open the Request Inbox to review {} waiting requests. Further notifications are paused for one minute.",
                pending.total
            );
            let storm = notification_content(
                pending.settings,
                "Many Multitool requests are waiting",
                body,
            );
            if let Err(error) = deliver_notification(app, &storm, storm_subjects) {
                tracing::warn!(%error, "could not deliver the notification rate-limit warning");
            }
            return;
        }
        NotificationAdmission::Suppressed => return,
    }

    if let Err(error) = deliver_notification(app, &content, subjects.clone()) {
        tracing::warn!(%error, "could not deliver a native request notification");
        crate::windows::surface_for_approval(app);
    }
}

fn flush_expirations(app: &AppHandle, generation: u64) {
    let Some(attention) = app.try_state::<RequestAttention>() else {
        return;
    };
    let Some(pending) = ({
        let mut inner = attention.inner.lock().unwrap();
        take_pending_expirations(&mut inner, generation)
    }) else {
        return;
    };
    let Some(content) = expiration_delivery_plan(
        &pending.requests,
        pending.settings,
        crate::windows::request_surface_focused(),
    ) else {
        return;
    };
    let subjects = pending
        .requests
        .iter()
        .map(|request| format!("expired:{}", request.id))
        .collect::<BTreeSet<_>>();
    match attention
        .inner
        .lock()
        .unwrap()
        .admit_notification(Instant::now())
    {
        NotificationAdmission::Normal => {}
        NotificationAdmission::Storm => {
            let storm = notification_content(
                pending.settings,
                "Several Multitool requests expired",
                "Open Recent in the Request Inbox for details. Further notifications are paused for one minute.",
            );
            if let Err(error) = deliver_terminal_notification(app, &storm, subjects) {
                tracing::warn!(%error, "could not deliver the expiry rate-limit warning");
            }
            return;
        }
        NotificationAdmission::Suppressed => return,
    }
    if let Err(error) = deliver_terminal_notification(app, &content, subjects) {
        tracing::warn!(%error, "could not deliver an approval-expiry notification");
    }
}

fn expiration_delivery_plan(
    requests: &[RequestSummary],
    settings: NotificationSettings,
    surface_focused: bool,
) -> Option<NotificationContent> {
    if settings.mode == NotificationMode::Off
        || (settings.mode == NotificationMode::WhenHidden && surface_focused)
    {
        return None;
    }
    let title = if requests.len() == 1 {
        "An Multitool request expired".to_string()
    } else {
        format!("{} Multitool requests expired", requests.len())
    };
    let body = if settings.show_context && requests.len() == 1 {
        let request = &requests[0];
        let agent = agent_display(&request.agent, "An agent");
        let connection = notification_label(&request.connection, "a tool");
        format!(
            "{agent} was refused access to {connection} because no decision arrived in time. Open Recent for details."
        )
    } else if requests.len() == 1 {
        "The waiting agent was refused because no decision arrived in time. Open Recent for details."
            .to_string()
    } else {
        "The waiting agents were refused because no decisions arrived in time. Open Recent for details."
            .to_string()
    };
    Some(notification_content(settings, title, body))
}

fn notification_content(
    settings: NotificationSettings,
    title: impl Into<String>,
    body: impl Into<String>,
) -> NotificationContent {
    NotificationContent {
        title: title.into(),
        body: body.into(),
        play_sound: settings.play_sound,
        time_sensitive: settings.time_sensitive,
    }
}

fn request_delivery_plan(
    requests: &[RequestSummary],
    total: usize,
    settings: NotificationSettings,
    surface_focused: bool,
) -> DeliveryPlan {
    match settings.mode {
        NotificationMode::Off => return DeliveryPlan::SurfaceWindow,
        NotificationMode::WhenHidden if surface_focused => return DeliveryPlan::Suppress,
        NotificationMode::WhenHidden | NotificationMode::Always => {}
    }
    let title = if requests.len() == 1 {
        "Multitool needs your approval".to_string()
    } else {
        format!("{} new requests need your approval", requests.len())
    };
    let body = if settings.show_context && requests.len() == 1 {
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

    DeliveryPlan::Notify(notification_content(settings, title, body))
}

/// Queue one native notification. A dispatcher owns the bounded queue and
/// gives each admitted banner an independent, watchdog-bounded response
/// observer, so one ignored banner never serializes later requests.
fn deliver_notification(
    app: &AppHandle,
    content: &NotificationContent,
    subjects: BTreeSet<String>,
) -> Result<(), String> {
    let attention = app
        .try_state::<RequestAttention>()
        .ok_or_else(|| "notification coordinator is unavailable".to_string())?;
    deliver_with_sink(
        &QueueNotificationSink {
            attention: &attention,
            app,
            subjects,
        },
        content,
    )
}

fn deliver_terminal_notification(
    app: &AppHandle,
    content: &NotificationContent,
    subjects: BTreeSet<String>,
) -> Result<(), String> {
    let attention = app
        .try_state::<RequestAttention>()
        .ok_or_else(|| "notification coordinator is unavailable".to_string())?;
    attention.enqueue_notification(
        app,
        content.title.clone(),
        content.body.clone(),
        content.play_sound,
        content.time_sensitive,
        subjects,
        false,
    )
}

fn schedule_escalation(
    app: &AppHandle,
    subjects: BTreeSet<String>,
    deadline: Option<Instant>,
    lead_secs: u64,
) {
    if subjects.is_empty() {
        return;
    }
    let generation = app
        .try_state::<RequestAttention>()
        .map(|attention| attention.inner.lock().unwrap().escalation_generation)
        .unwrap_or_default();
    let delay = escalation_delay(Instant::now(), deadline, lead_secs);
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(delay).await;
        let due = app.try_state::<RequestAttention>().and_then(|attention| {
            let mut inner = attention.inner.lock().unwrap();
            take_due_escalation(&mut inner, &subjects, lead_secs, generation)
        });
        let Some((settings, due_subjects)) = due else {
            return;
        };
        crate::windows::request_critical_attention(&app);
        if !crate::windows::request_surface_focused() {
            crate::windows::surface_for_approval(&app);
        }
        // Zero disables the optional second native banner, but the Inbox
        // fallback above is mandatory because Focus/DND may hide a
        // successfully-delivered first notification.
        if lead_secs == 0 {
            return;
        }
        if let Some(attention) = app.try_state::<RequestAttention>() {
            let content = notification_content(
                settings,
                "Multitool is still waiting",
                "A request is nearing its deadline. Open the Request Inbox to respond.",
            );
            if let Err(error) = attention.enqueue_notification(
                &app,
                content.title,
                content.body,
                content.play_sound,
                content.time_sensitive,
                due_subjects,
                true,
            ) {
                tracing::warn!(%error, "could not deliver the waiting-request re-alert");
            }
        }
    });
}

fn escalation_delay(now: Instant, deadline: Option<Instant>, lead_secs: u64) -> Duration {
    let lead = if lead_secs == 0 {
        DEADLINE_FALLBACK_LEAD
    } else {
        Duration::from_secs(lead_secs)
    };
    deadline
        .map(|deadline| deadline.saturating_duration_since(now).saturating_sub(lead))
        .unwrap_or_else(|| {
            if lead_secs == 0 {
                UNKNOWN_DEADLINE_FALLBACK_DELAY
            } else {
                Duration::from_secs(lead_secs)
            }
        })
}

fn take_due_escalation(
    inner: &mut AttentionInner,
    subjects: &BTreeSet<String>,
    lead_secs: u64,
    generation: u64,
) -> Option<(NotificationSettings, BTreeSet<String>)> {
    if inner.escalation_generation != generation
        || inner.settings.escalation_secs != lead_secs
        || inner.settings.mode == NotificationMode::Off
    {
        return None;
    }
    let due = subjects
        .iter()
        .filter(|subject| {
            inner.notification_subject_is_active(subject)
                && !inner.escalated_subjects.contains(*subject)
        })
        .cloned()
        .collect::<BTreeSet<_>>();
    if due.is_empty() {
        return None;
    }
    inner.escalated_subjects.extend(due.iter().cloned());
    Some((inner.settings, due))
}

fn deliver_with_sink(
    sink: &dyn NotificationSink,
    content: &NotificationContent,
) -> Result<(), String> {
    sink.deliver(content)
}

fn notification_worker(rx: mpsc::Receiver<NotificationJob>) {
    let observers = Arc::new(AtomicUsize::new(0));
    while let Ok(job) = rx.recv() {
        let Some(attention) = job.app.try_state::<RequestAttention>() else {
            continue;
        };
        if !attention.inner.lock().unwrap().notifications_available {
            attention.notification_finished(&job.key);
            continue;
        }
        let Some(observer_permit) = try_notification_observer(&observers) else {
            attention.notification_finished(&job.key);
            crate::windows::surface_for_approval(&job.app);
            continue;
        };
        // `wait_for_response` remains parked for the banner's lifetime. Give
        // each admitted banner its own bounded-lived observer so an ignored
        // request cannot hold every later notification behind it.
        let fallback_app = job.app.clone();
        let fallback_key = job.key.clone();
        if let Err(error) = std::thread::Builder::new()
            .name("aka-notification-response".into())
            .spawn(move || {
                let _observer_permit = observer_permit;
                deliver_notification_job(job);
            })
        {
            if let Some(attention) = fallback_app.try_state::<RequestAttention>() {
                attention.notification_finished(&fallback_key);
            }
            notification_delivery_failed(
                &fallback_app,
                format!("could not start native notification observer: {error}"),
            );
        }
    }
}

fn deliver_notification_job(job: NotificationJob) {
    let mut notification = notify_rust::Notification::new();
    notification
        .summary(&job.title)
        .body(&job.body)
        .action(OPEN_INBOX_ACTION, "Open Inbox");
    if job.play_sound {
        #[cfg(target_os = "windows")]
        notification.sound_name("Default");
        #[cfg(target_os = "macos")]
        notification.sound_name("default");
        #[cfg(all(unix, not(target_os = "macos")))]
        notification.sound_name("message-new-instant");
    }
    if job.time_sensitive {
        notification.urgency(notify_rust::Urgency::Critical);
    }
    // This is a platform-owned timeout, not a detached watchdog. On macOS
    // notify-rust forwards it to mac-usernotifications, whose response future
    // resolves with a synthetic expiry and removes the delivered banner. The
    // blocking observer therefore always returns and releases its permit.
    notification.timeout(NOTIFICATION_RESPONSE_DEADLINE);
    #[cfg(target_os = "macos")]
    notification.id(job.key.as_str());
    // XDG servers only emit body activation when the special default action
    // is advertised; some desktops hide named buttons entirely.
    #[cfg(all(unix, not(target_os = "macos")))]
    notification.action("default", "Open Inbox");
    if let Err(error) = configure_notification_identity(&job.app, &mut notification) {
        if let Some(attention) = job.app.try_state::<RequestAttention>() {
            attention.notification_finished(&job.key);
        }
        notification_delivery_failed(&job.app, error);
        return;
    }
    // A bounded queue can hold a job after every request represented by it
    // has resolved. Check before calling the platform so identifier-less
    // Windows notifications do not flash stale work merely because there is
    // no native handle available to withdraw afterward.
    let should_deliver = job
        .app
        .try_state::<RequestAttention>()
        .is_some_and(|attention| attention.notification_is_pending(&job.key));
    if !should_deliver {
        return;
    }
    let shown_at = Instant::now();
    let handle = match notification.show() {
        Ok(handle) => handle,
        Err(error) => {
            if let Some(attention) = job.app.try_state::<RequestAttention>() {
                attention.notification_finished(&job.key);
            }
            notification_delivery_failed(&job.app, error.to_string());
            return;
        }
    };
    let native_id = native_notification_id(&handle);
    let should_observe = job
        .app
        .try_state::<RequestAttention>()
        .is_some_and(|attention| attention.attach_native_notification(&job.key, native_id.clone()));
    if !should_observe {
        if let Some(native_id) = native_id {
            if let Err(error) = withdraw_native_notification(&native_id) {
                tracing::warn!(%error, "could not withdraw a resolved native notification");
            }
        }
        return;
    }

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
    if let Some(attention) = job.app.try_state::<RequestAttention>() {
        attention.notification_finished(&job.key);
    }
    if let Err(error) = result {
        notification_delivery_failed(
            &job.app,
            format!("could not observe native notification delivery: {error}"),
        );
    }
}

#[cfg(target_os = "macos")]
fn native_notification_id(
    handle: &notify_rust::NotificationHandle,
) -> Option<NativeNotificationId> {
    match handle.id() {
        notify_rust::NotificationId::Mac(id) => Some(NativeNotificationId::Mac(id)),
        notify_rust::NotificationId::Xdg(_) => None,
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
fn native_notification_id(
    handle: &notify_rust::NotificationHandle,
) -> Option<NativeNotificationId> {
    Some(NativeNotificationId::Xdg(handle.id()))
}

#[cfg(windows)]
fn native_notification_id(
    _handle: &notify_rust::NotificationHandle,
) -> Option<NativeNotificationId> {
    None
}

fn withdraw_notifications(notifications: Vec<NativeNotificationId>) {
    if notifications.is_empty() {
        return;
    }
    tauri::async_runtime::spawn_blocking(move || {
        for notification in notifications {
            if let Err(error) = withdraw_native_notification(&notification) {
                tracing::warn!(%error, "could not withdraw a resolved native notification");
            }
        }
    });
}

fn withdraw_native_notification(notification: &NativeNotificationId) -> Result<(), String> {
    match notification {
        #[cfg(target_os = "macos")]
        NativeNotificationId::Mac(id) => {
            mac_usernotifications::blocking::close_delivered(id);
            Ok(())
        }
        #[cfg(all(unix, not(target_os = "macos")))]
        NativeNotificationId::Xdg(id) => {
            let connection =
                zbus::blocking::Connection::session().map_err(|error| error.to_string())?;
            connection
                .call_method(
                    Some("org.freedesktop.Notifications"),
                    "/org/freedesktop/Notifications",
                    Some("org.freedesktop.Notifications"),
                    "CloseNotification",
                    &(*id,),
                )
                .map_err(|error| error.to_string())?;
            Ok(())
        }
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

fn mark_notification_permission_required(app: &AppHandle) {
    if let Some(attention) = app.try_state::<RequestAttention>() {
        let view = attention.mark_notification_permission_required();
        let _ = app.emit(crate::commands::EVT_NOTIFICATION_SETTINGS, view);
    }
}

fn mark_notifications_available(app: &AppHandle) {
    if let Some(attention) = app.try_state::<RequestAttention>() {
        let view = attention.mark_notifications_available();
        let _ = app.emit(crate::commands::EVT_NOTIFICATION_SETTINGS, view);
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
        // Probe on a worker because UNUserNotificationCenter is blocking.
        // NotDetermined becomes an in-app rationale; only the explicit
        // Settings action below is allowed to present the system dialog.
        let app = app.clone();
        let _ = std::thread::Builder::new()
            .name("aka-notification-init".into())
            .spawn(
                move || match initialize_macos_notification_delivery(false) {
                    Ok(true) => mark_notifications_available(&app),
                    Ok(false) => mark_notification_permission_required(&app),
                    Err(error) => {
                        mark_notifications_unavailable(
                            &app,
                            format!("Could not enable native notifications: {error}"),
                        );
                    }
                },
            );
        return;
    }

    #[cfg(not(target_os = "macos"))]
    match app.notification().permission_state() {
        Ok(PermissionState::Granted) => mark_notifications_available(app),
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
fn initialize_macos_notification_delivery(request_permission: bool) -> Result<bool, String> {
    use mac_usernotifications::AuthorizationStatus;

    // UNUserNotificationCenter requires a real application bundle. Unlike
    // notify-rust's legacy backend, this validates the bundle without
    // process-wide NSBundle method swizzling.
    notify_rust::check_bundle().map_err(|error| error.to_string())?;
    let mut settings =
        notify_rust::get_notification_settings_blocking().map_err(|error| error.to_string())?;
    if settings.authorization_status == AuthorizationStatus::NotDetermined {
        if !request_permission {
            return Ok(false);
        }
        if !notify_rust::request_auth_blocking().map_err(|error| error.to_string())? {
            return Err("notification permission was denied".into());
        }
        settings =
            notify_rust::get_notification_settings_blocking().map_err(|error| error.to_string())?;
    }
    match settings.authorization_status {
        AuthorizationStatus::Authorized
        | AuthorizationStatus::Provisional
        | AuthorizationStatus::Ephemeral => Ok(true),
        AuthorizationStatus::Denied => {
            Err("notifications are blocked in operating-system settings".into())
        }
        AuthorizationStatus::NotDetermined => {
            Err("notification permission has not been granted".into())
        }
        AuthorizationStatus::Unknown => {
            Err("the operating system returned an unknown notification permission state".into())
        }
    }
}

/// The Settings rationale calls this explicitly; first launch only detects
/// that permission is needed and never races a context-free system dialog.
pub async fn request_notification_permission(
    app: &AppHandle,
) -> Result<NotificationSettingsView, String> {
    #[cfg(target_os = "macos")]
    {
        let result =
            tauri::async_runtime::spawn_blocking(|| initialize_macos_notification_delivery(true))
                .await
                .map_err(|error| error.to_string())?;
        let granted = match result {
            Ok(granted) => granted,
            Err(error) => {
                mark_notifications_unavailable(
                    app,
                    format!("Could not enable native notifications: {error}"),
                );
                return Err(error);
            }
        };
        if !granted {
            return Err("notification permission was not granted".into());
        }
        let attention = app
            .try_state::<RequestAttention>()
            .ok_or_else(|| "notification coordinator is unavailable".to_string())?;
        let view = attention.mark_notifications_available();
        let _ = app.emit(crate::commands::EVT_NOTIFICATION_SETTINGS, view.clone());
        return Ok(view);
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = app;
        Err("Grant notification permission in operating-system settings".into())
    }
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
    // UNUserNotificationCenter reads identity from the signed application
    // bundle; setup validated authorization before requests could be parked.
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
    match app
        .path()
        .resolve("icons/icon.png", BaseDirectory::Resource)
    {
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
            .map(aka_core::manage::elicitation_dto)
            .map(ElicitationSummary::from)
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

pub fn approval_resolved(
    app: &AppHandle,
    id: &uuid::Uuid,
    resolution: aka_core::request_history::RequestResolution,
) {
    if let Some(attention) = app.try_state::<RequestAttention>() {
        attention.resolve(
            app,
            &id.to_string(),
            resolution == aka_core::request_history::RequestResolution::TimedOut,
        );
    }
}

pub fn remote_approval_expired(app: &AppHandle, id: &str) {
    if let Some(attention) = app.try_state::<RequestAttention>() {
        attention.resolve(app, id, true);
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
    let elicitation = ElicitationSummary::from(aka_core::manage::elicitation_dto(pending));
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
    let settings = {
        let inner = attention.inner.lock().unwrap();
        inner.settings
    };
    let subjects = BTreeSet::from([elicitation_subject(&pending.id)]);
    if settings.mode != NotificationMode::Off {
        schedule_escalation(
            app,
            subjects.clone(),
            pending.deadline,
            settings.escalation_secs,
        );
    }
    let content = match elicitation_delivery_plan(
        pending,
        settings,
        crate::windows::request_surface_focused(),
    ) {
        DeliveryPlan::SurfaceWindow => {
            crate::windows::surface_for_approval(app);
            return;
        }
        DeliveryPlan::Suppress => return,
        DeliveryPlan::Notify(content) => content,
    };
    let total = attention.count();
    if settings.mode == NotificationMode::Always {
        crate::windows::request_critical_attention(app);
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
            let storm_subjects = attention.active_notification_subjects();
            let body = format!(
                "Open the Request Inbox to review {total} waiting requests. Further notifications are paused for one minute."
            );
            let storm = notification_content(settings, "Many Multitool requests are waiting", body);
            if let Err(error) = deliver_notification(app, &storm, storm_subjects) {
                tracing::warn!(%error, "could not deliver the notification rate-limit warning");
            }
            return;
        }
        NotificationAdmission::Suppressed => return,
    }
    if let Err(error) = deliver_notification(app, &content, subjects.clone()) {
        tracing::warn!(%error, "could not deliver an elicitation notification");
        crate::windows::surface_for_approval(app);
    }
}

fn elicitation_delivery_plan(
    pending: &ElicitationSummary,
    settings: NotificationSettings,
    surface_focused: bool,
) -> DeliveryPlan {
    match settings.mode {
        NotificationMode::Off => return DeliveryPlan::SurfaceWindow,
        NotificationMode::WhenHidden if surface_focused => return DeliveryPlan::Suppress,
        NotificationMode::WhenHidden | NotificationMode::Always => {}
    }
    let title = "Multitool needs your input".to_string();
    let body = if settings.show_context {
        let agent = notification_label(&pending.agent, "An agent");
        let connection = notification_label(&pending.connection, "a tool");
        format!(
            "{connection} needs your input. {agent} is paused. Open the Request Inbox to respond."
        )
    } else {
        "An upstream asked for input. Open the Request Inbox to respond.".to_string()
    };
    DeliveryPlan::Notify(notification_content(settings, title, body))
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

    #[derive(Default)]
    struct FakeNotificationSink {
        delivered: Mutex<Vec<NotificationContent>>,
        failure: Option<String>,
    }

    impl NotificationSink for FakeNotificationSink {
        fn deliver(&self, content: &NotificationContent) -> Result<(), String> {
            if let Some(failure) = &self.failure {
                return Err(failure.clone());
            }
            self.delivered.lock().unwrap().push(content.clone());
            Ok(())
        }
    }

    fn settings(mode: NotificationMode, show_context: bool) -> NotificationSettings {
        NotificationSettings {
            mode,
            show_context,
            ..NotificationSettings::default()
        }
    }

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
            credential_names: vec!["github-token".into()],
            method: Some("GET".into()),
            path: Some("/user".into()),
            host_key_fingerprint: None,
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
            replacement
                .resolved_requests
                .iter()
                .map(|request| request.id.as_str())
                .collect::<Vec<_>>(),
            vec!["one"]
        );
        let pending = tracker.take_pending();
        assert_eq!(
            pending
                .iter()
                .map(|request| (request.id.as_str(), request.agent.as_str()))
                .collect::<Vec<_>>(),
            vec![("two", "claude")]
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

    #[cfg(not(windows))]
    fn test_native_id(value: &str) -> NativeNotificationId {
        #[cfg(target_os = "macos")]
        {
            NativeNotificationId::Mac(value.into())
        }
        #[cfg(all(unix, not(target_os = "macos")))]
        {
            let _ = value;
            NativeNotificationId::Xdg(42)
        }
    }

    #[test]
    #[cfg(not(windows))]
    fn a_batched_banner_withdraws_only_after_its_last_request_resolves() {
        let attention = RequestAttention::new(NotificationSettings::default());
        let mut inner = attention.inner.lock().unwrap();
        let key = "notification";
        inner.track_notification(
            key.into(),
            BTreeSet::from([approval_subject("one"), approval_subject("two")]),
        );
        let native_id = test_native_id(key);
        assert!(inner.attach_native_notification(key, Some(native_id.clone())));

        assert!(inner
            .resolve_notification_subject(&approval_subject("one"))
            .is_empty());
        assert!(inner.tracked_notifications.contains_key(key));
        assert_eq!(
            inner.resolve_notification_subject(&approval_subject("two")),
            vec![native_id]
        );
        assert!(!inner.tracked_notifications.contains_key(key));
    }

    #[test]
    fn a_request_resolved_in_the_delivery_queue_is_not_shown() {
        let attention = RequestAttention::new(NotificationSettings::default());
        let mut inner = attention.inner.lock().unwrap();
        let key = "queued";
        inner.track_notification(
            key.into(),
            BTreeSet::from([elicitation_subject("question")]),
        );

        assert!(inner
            .resolve_notification_subject(&elicitation_subject("question"))
            .is_empty());
        assert!(!inner.notification_is_pending(key));
        assert!(!inner.attach_native_notification(key, None));
        assert!(!inner.tracked_notifications.contains_key(key));
    }

    #[test]
    #[cfg(not(windows))]
    fn a_scope_change_returns_every_delivered_identifier_for_withdrawal() {
        let attention = RequestAttention::new(NotificationSettings::default());
        let mut inner = attention.inner.lock().unwrap();
        assert_eq!(inner.set_scope("local".into()), Some((0, Vec::new())));
        inner.track_notification("old".into(), BTreeSet::from([approval_subject("one")]));
        let native_id = test_native_id("old");
        assert!(inner.attach_native_notification("old", Some(native_id.clone())));

        assert_eq!(
            inner.set_scope("remote:https://broker.example".into()),
            Some((0, vec![native_id]))
        );
        assert!(inner.tracked_notifications.is_empty());
    }

    #[test]
    fn request_delivery_mode_and_focus_matrix_is_explicit() {
        let requests = vec![RequestSummary::from(approval("one", "codex"))];
        for focused in [false, true] {
            assert_eq!(
                request_delivery_plan(
                    &requests,
                    1,
                    settings(NotificationMode::Off, false),
                    focused,
                ),
                DeliveryPlan::SurfaceWindow
            );
            assert!(matches!(
                request_delivery_plan(
                    &requests,
                    1,
                    settings(NotificationMode::Always, false),
                    focused,
                ),
                DeliveryPlan::Notify(_)
            ));
        }
        assert!(matches!(
            request_delivery_plan(
                &requests,
                1,
                settings(NotificationMode::WhenHidden, false),
                false,
            ),
            DeliveryPlan::Notify(_)
        ));
        assert_eq!(
            request_delivery_plan(
                &requests,
                1,
                settings(NotificationMode::WhenHidden, false),
                true,
            ),
            DeliveryPlan::Suppress
        );
    }

    #[test]
    fn request_delivery_content_covers_single_batch_and_privacy_modes() {
        let request = RequestSummary::from(approval("one", "codex\nagent"));
        let contextual = request_delivery_plan(
            std::slice::from_ref(&request),
            1,
            settings(NotificationMode::Always, true),
            true,
        );
        assert_eq!(
            contextual,
            DeliveryPlan::Notify(NotificationContent {
                title: "Multitool needs your approval".into(),
                body: "codex agent is waiting to use github. Open the Request Inbox to review."
                    .into(),
                play_sound: true,
                time_sensitive: false,
            })
        );

        let private = request_delivery_plan(
            std::slice::from_ref(&request),
            1,
            settings(NotificationMode::Always, false),
            false,
        );
        assert_eq!(
            private,
            DeliveryPlan::Notify(NotificationContent {
                title: "Multitool needs your approval".into(),
                body: "Open the Request Inbox to review this request.".into(),
                play_sound: true,
                time_sensitive: false,
            })
        );

        let batch = request_delivery_plan(
            &[request, RequestSummary::from(approval("two", "claude"))],
            4,
            settings(NotificationMode::Always, true),
            false,
        );
        assert_eq!(
            batch,
            DeliveryPlan::Notify(NotificationContent {
                title: "2 new requests need your approval".into(),
                body: "Open the Request Inbox to review 4 waiting requests.".into(),
                play_sound: true,
                time_sensitive: false,
            })
        );
    }

    #[test]
    fn sound_and_time_sensitive_preferences_reach_the_native_payload() {
        let mut preferences = settings(NotificationMode::Always, false);
        preferences.play_sound = false;
        preferences.time_sensitive = true;
        let request = RequestSummary::from(approval("one", "codex"));

        assert_eq!(
            request_delivery_plan(&[request], 1, preferences, false),
            DeliveryPlan::Notify(NotificationContent {
                title: "Multitool needs your approval".into(),
                body: "Open the Request Inbox to review this request.".into(),
                play_sound: false,
                time_sensitive: true,
            })
        );
    }

    #[test]
    fn expirations_coalesce_and_respect_delivery_privacy() {
        let attention = RequestAttention::new(settings(NotificationMode::Always, true));
        let mut inner = attention.inner.lock().unwrap();
        let one = RequestSummary::from(approval("one", "codex"));
        let two = RequestSummary::from(approval("two", "claude"));
        let generation = queue_expiration(&mut inner, one.clone()).unwrap();
        assert!(queue_expiration(&mut inner, two).is_none());
        let pending = take_pending_expirations(&mut inner, generation).unwrap();
        assert_eq!(pending.requests.len(), 2);
        assert!(!inner.expiry_flush_scheduled);
        assert!(take_pending_expirations(&mut inner, generation).is_none());

        let single =
            expiration_delivery_plan(&[one], settings(NotificationMode::Always, true), false)
                .unwrap();
        assert_eq!(single.title, "An Multitool request expired");
        assert!(single.body.contains("codex was refused access to github"));
        assert!(expiration_delivery_plan(
            &pending.requests,
            settings(NotificationMode::WhenHidden, false),
            true,
        )
        .is_none());
        assert!(expiration_delivery_plan(
            &pending.requests,
            settings(NotificationMode::Off, false),
            false,
        )
        .is_none());
    }

    #[test]
    fn escalation_is_deadline_aware_single_shot_and_generation_bound() {
        let attention = RequestAttention::new(settings(NotificationMode::Always, false));
        let mut inner = attention.inner.lock().unwrap();
        inner
            .tracker
            .upsert(RequestSummary::from(approval("one", "codex")), true);
        let subjects = BTreeSet::from([approval_subject("one")]);
        let generation = inner.escalation_generation;
        let (_, due) = take_due_escalation(&mut inner, &subjects, 30, generation).unwrap();
        assert_eq!(due, subjects);
        assert!(take_due_escalation(&mut inner, &subjects, 30, generation).is_none());

        inner.escalated_subjects.clear();
        inner.settings.escalation_secs = 15;
        inner.escalation_generation = inner.escalation_generation.wrapping_add(1);
        assert!(take_due_escalation(&mut inner, &subjects, 30, generation).is_none());
        let latest = inner.escalation_generation;
        assert!(take_due_escalation(&mut inner, &subjects, 15, latest).is_some());

        inner.escalated_subjects.clear();
        inner.tracker.resolve("one");
        assert!(take_due_escalation(&mut inner, &subjects, 15, latest).is_none());

        let now = Instant::now();
        assert_eq!(
            escalation_delay(now, now.checked_add(Duration::from_secs(12)), 30),
            Duration::ZERO
        );
        assert_eq!(
            escalation_delay(now, now.checked_add(Duration::from_secs(90)), 30),
            Duration::from_secs(60)
        );
        assert_eq!(
            escalation_delay(now, now.checked_add(Duration::from_secs(90)), 0),
            Duration::from_secs(80)
        );
    }

    #[test]
    fn elicitation_delivery_mode_focus_and_context_are_covered() {
        let elicitation = ElicitationSummary {
            id: "question".into(),
            agent: "codex".into(),
            connection: "postgres".into(),
            deadline: None,
        };
        assert_eq!(
            elicitation_delivery_plan(&elicitation, settings(NotificationMode::Off, true), false,),
            DeliveryPlan::SurfaceWindow
        );
        assert_eq!(
            elicitation_delivery_plan(
                &elicitation,
                settings(NotificationMode::WhenHidden, true),
                true,
            ),
            DeliveryPlan::Suppress
        );
        assert_eq!(
            elicitation_delivery_plan(&elicitation, settings(NotificationMode::Always, true), true,),
            DeliveryPlan::Notify(NotificationContent {
                title: "Multitool needs your input".into(),
                body:
                    "postgres needs your input. codex is paused. Open the Request Inbox to respond."
                        .into(),
                play_sound: true,
                time_sensitive: false,
            })
        );
    }

    #[test]
    fn notification_sink_observes_payloads_and_can_fail() {
        let content = NotificationContent {
            title: "A title".into(),
            body: "A body".into(),
            play_sound: false,
            time_sensitive: false,
        };
        let sink = FakeNotificationSink::default();
        deliver_with_sink(&sink, &content).unwrap();
        assert_eq!(*sink.delivered.lock().unwrap(), vec![content.clone()]);

        let failing = FakeNotificationSink {
            delivered: Mutex::new(Vec::new()),
            failure: Some("blocked".into()),
        };
        assert_eq!(
            deliver_with_sink(&failing, &content).unwrap_err(),
            "blocked"
        );
        assert!(failing.delivered.lock().unwrap().is_empty());
    }

    #[test]
    fn debounced_flush_drains_once_then_resolution_clears_the_count() {
        let attention = RequestAttention::new(settings(NotificationMode::Always, false));
        let mut inner = attention.inner.lock().unwrap();
        assert_eq!(inner.set_scope("local".into()), Some((0, Vec::new())));
        let change = inner
            .tracker
            .upsert(RequestSummary::from(approval("one", "codex")), true);
        let generation = schedule_generation(&mut inner, change.notification_added).unwrap();
        assert!(inner.flush_scheduled);
        assert!(schedule_generation(&mut inner, true).is_none());

        let pending = take_pending_flush(&mut inner, generation).unwrap();
        assert_eq!(pending.requests.len(), 1);
        assert_eq!(pending.total, 1);
        assert!(!inner.flush_scheduled);
        assert!(take_pending_flush(&mut inner, generation).is_none());

        let content = match request_delivery_plan(
            &pending.requests,
            pending.total,
            pending.settings,
            false,
        ) {
            DeliveryPlan::Notify(content) => content,
            other => panic!("expected a notification, got {other:?}"),
        };
        let sink = FakeNotificationSink::default();
        deliver_with_sink(&sink, &content).unwrap();
        assert_eq!(sink.delivered.lock().unwrap().len(), 1);

        let resolved = inner.tracker.resolve("one");
        assert_eq!(resolved.count, 0);
        assert_eq!(inner.total(), 0);
    }

    #[test]
    fn scope_switch_invalidates_a_scheduled_flush() {
        let attention = RequestAttention::new(settings(NotificationMode::Always, false));
        let mut inner = attention.inner.lock().unwrap();
        inner.set_scope("local".into());
        let change = inner
            .tracker
            .upsert(RequestSummary::from(approval("one", "codex")), true);
        let old_generation = schedule_generation(&mut inner, change.notification_added).unwrap();

        assert_eq!(
            inner.set_scope("remote:https://broker.example".into()),
            Some((0, Vec::new()))
        );
        assert!(take_pending_flush(&mut inner, old_generation).is_none());
        assert!(inner.tracker.active.is_empty());
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
        assert_eq!(inner.set_scope("local".into()), Some((0, Vec::new())));
        inner.elicitations.insert(
            "elicitation".into(),
            ElicitationSummary {
                id: "elicitation".into(),
                agent: "codex".into(),
                connection: "github".into(),
                deadline: None,
            },
        );
        assert_eq!(inner.total(), 1);
        assert_eq!(
            inner.set_scope("remote:https://broker.example".into()),
            Some((0, Vec::new()))
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
    fn notification_response_observers_have_a_hard_cap_and_release_slots() {
        let observers = Arc::new(AtomicUsize::new(0));
        let permits = (0..NOTIFICATION_OBSERVER_LIMIT)
            .map(|_| try_notification_observer(&observers).expect("slot"))
            .collect::<Vec<_>>();
        assert!(try_notification_observer(&observers).is_none());

        drop(permits);
        assert!(try_notification_observer(&observers).is_some());
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
            ..NotificationSettings::default()
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
    fn notification_permission_rationale_can_recover_without_losing_preferences() {
        let attention = RequestAttention::new(NotificationSettings {
            mode: NotificationMode::Always,
            play_sound: false,
            time_sensitive: true,
            ..NotificationSettings::default()
        });

        let checking = attention.settings_view();
        assert!(!checking.available);
        assert_eq!(
            checking.unavailable_reason.as_deref(),
            Some("Checking operating-system notification permission")
        );
        assert!(!checking.can_request_permission);

        let rationale = attention.mark_notification_permission_required();
        assert!(!rationale.available);
        assert!(rationale.can_request_permission);
        assert_eq!(rationale.mode, NotificationMode::Always);
        assert!(!rationale.play_sound);
        assert!(rationale.time_sensitive);

        let recovered = attention.mark_notifications_available();
        assert!(recovered.available);
        assert!(!recovered.can_request_permission);
        assert!(recovered.unavailable_reason.is_none());
        assert_eq!(recovered.mode, NotificationMode::Always);
        assert!(!recovered.play_sound);
        assert!(recovered.time_sensitive);
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
