//! Upstream MCP elicitation: parking an agent's tool call on a human answer.
//!
//! When an upstream MCP server needs interactive input mid-call (the
//! [multi round-trip requests](https://modelcontextprotocol.io/specification/draft/basic/patterns/mrtr)
//! pattern — the upstream returns an `input_required` result carrying an
//! `elicitation/create` request), the sidecar cannot answer for the user and
//! the agent must not: the agent never sees the prompt or its answer. So the
//! request parks here, the app raises a form, and the user's answer is handed
//! back to the sidecar to complete the upstream round trip.
//!
//! This is the sibling of [`crate::approvals`], and shares its shape: an
//! async park on a `oneshot`, a fail-closed "nobody can ask" path, a deadline,
//! and the same [`crate::request_history`] store so both land in one Recent
//! Inbox. It is deliberately simpler — there is no window, no cooldown, and no
//! coalescing, because each elicitation is a unique question with a unique
//! answer.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::{Map, Value};
use tokio::sync::oneshot;
use uuid::Uuid;

use crate::audit::{AuditEntry, AuditKind, AuditLog};
use crate::events::{BrokerEvents, ElicitationHandling};
use crate::request_history::{RequestHistory, RequestResolution};
use crate::types::Connection;

/// How long an elicitation waits for the user before it gives up and the
/// upstream call is answered with a cancel.
const ELICITATION_TIMEOUT: Duration = Duration::from_secs(300);
/// Backstop on prompts waiting at once, so a server that elicits in a loop
/// cannot pile the queue up without bound.
const MAX_PENDING: usize = 64;
/// The whole prompt text an upstream can put in front of the user is bounded,
/// and stripped of characters that could visually rewrite it — the same
/// treatment [`crate::approvals`] gives agent-controlled strings.
const ELICITATION_TEXT_CAP: usize = 2000;
const FIELD_TEXT_CAP: usize = 200;

/// One input the form asks for, as the app renders it. Mirrors the UI's
/// `ElicitationField` exactly: a label and whether to mask the value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ElicitationField {
    pub name: String,
    pub label: String,
    /// Render as a password field; the value rides upstream, never shown again.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub secret: bool,
    /// A JSON Schema `boolean`: the app renders a toggle, and the answer rides
    /// upstream as a real JSON boolean rather than a string.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub boolean: bool,
    /// A fixed set of choices (a JSON Schema `enum`): the app renders a
    /// dropdown instead of a text field. Absent for free-text fields.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<Vec<String>>,
}

/// One elicitation waiting on the user, as the app renders it. Carries the
/// upstream's prompt and field descriptors, but never the submitted values.
#[derive(Debug, Clone, Serialize)]
pub struct PendingElicitation {
    pub id: Uuid,
    pub connection_id: Uuid,
    pub connection: String,
    /// Agent whose tool call is paused. It cannot see this prompt or its answer.
    pub agent: String,
    /// The MCP tool name the agent called.
    pub tool: String,
    /// The upstream's own prompt, shown verbatim but never interpreted.
    pub message: String,
    pub fields: Vec<ElicitationField>,
    pub requested_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// What the sidecar asks about: one upstream `elicitation/create`, in the
/// terms the broker needs to render and route it.
#[derive(Debug, Clone)]
pub struct ElicitationRequest {
    pub connection: Connection,
    pub agent: String,
    pub tool: String,
    pub message: String,
    /// The upstream's `requestedSchema` (JSON Schema object), turned into
    /// form fields for the app.
    pub requested_schema: Value,
}

/// The MCP `ElicitResult` action the user's answer maps to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElicitAction {
    Accept,
    Decline,
    Cancel,
}

impl ElicitAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accept => "accept",
            Self::Decline => "decline",
            Self::Cancel => "cancel",
        }
    }
}

/// The answer handed back to the sidecar, shaped as an MCP `ElicitResult`.
#[derive(Debug, Clone)]
pub struct ElicitationOutcome {
    pub action: ElicitAction,
    /// The user's field values, present only on `accept`.
    pub content: Option<Map<String, Value>>,
}

impl ElicitationOutcome {
    fn cancelled() -> Self {
        Self {
            action: ElicitAction::Cancel,
            content: None,
        }
    }
}

/// Directional-override and isolate characters, stripped so an upstream
/// cannot visually reorder the prompt the user is deciding on. Mirrors
/// [`crate::approvals`].
const BIDI_CONTROLS: [char; 12] = [
    '\u{061C}', '\u{200E}', '\u{200F}', '\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}', '\u{202E}',
    '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}',
];

fn safe_char(c: char) -> char {
    if BIDI_CONTROLS.contains(&c) || (c.is_control() && c != '\n' && c != '\t') {
        '\u{FFFD}'
    } else {
        c
    }
}

fn cap_text(text: &str, cap: usize) -> String {
    let mut capped: String = text.chars().take(cap).map(safe_char).collect();
    if text.chars().nth(cap).is_some() {
        capped.push('…');
    }
    capped
}

/// Turn an upstream `requestedSchema` into the form fields the app renders.
/// Only `properties` matter to the UI, which offers text and password inputs;
/// the type/enum keywords are advisory and left to the upstream to validate.
fn fields_from_schema(schema: &Value) -> Vec<ElicitationField> {
    let Some(properties) = schema.get("properties").and_then(Value::as_object) else {
        return Vec::new();
    };
    properties
        .iter()
        .map(|(name, spec)| {
            let label = spec
                .get("title")
                .and_then(Value::as_str)
                .filter(|title| !title.is_empty())
                .unwrap_or(name);
            let secret = spec.get("format").and_then(Value::as_str) == Some("password")
                || spec.get("writeOnly").and_then(Value::as_bool) == Some(true);
            let boolean = spec.get("type").and_then(Value::as_str) == Some("boolean");
            // A JSON Schema `enum` of scalars becomes a dropdown. Non-string
            // choices are rendered by their JSON text (the answer still rides
            // upstream as the chosen string); an empty enum is treated as free
            // text so the form is never a dropdown with nothing to pick.
            let options = spec
                .get("enum")
                .and_then(Value::as_array)
                .map(|choices| {
                    choices
                        .iter()
                        .map(|choice| match choice {
                            Value::String(text) => text.clone(),
                            other => other.to_string(),
                        })
                        .map(|choice| cap_text(&choice, FIELD_TEXT_CAP))
                        .collect::<Vec<_>>()
                })
                .filter(|choices| !choices.is_empty());
            ElicitationField {
                name: cap_text(name, FIELD_TEXT_CAP),
                label: cap_text(label, FIELD_TEXT_CAP),
                secret,
                boolean,
                options,
            }
        })
        .collect()
}

/// Turn the form's string answers into MCP `ElicitResult` content, typed to
/// match the fields the upstream asked for. Boolean fields become real JSON
/// booleans; everything else rides upstream as the string the user entered.
/// Unknown keys (values with no matching field) pass through as strings.
fn coerce_content(fields: &[ElicitationField], values: HashMap<String, String>) -> Map<String, Value> {
    let booleans: std::collections::HashSet<&str> = fields
        .iter()
        .filter(|field| field.boolean)
        .map(|field| field.name.as_str())
        .collect();
    values
        .into_iter()
        .map(|(name, value)| {
            let typed = if booleans.contains(name.as_str()) {
                Value::Bool(value == "true")
            } else {
                Value::String(value)
            };
            (name, typed)
        })
        .collect()
}

struct Pending {
    info: PendingElicitation,
    waiter: oneshot::Sender<ElicitationOutcome>,
    deadline: Instant,
}

struct Lapsed {
    id: Uuid,
    resolution: RequestResolution,
}

#[derive(Default)]
struct State {
    pending: HashMap<Uuid, Pending>,
}

struct Inner {
    audit: Arc<AuditLog>,
    events: Arc<dyn BrokerEvents>,
    history: Arc<RequestHistory>,
    timeout: Duration,
    state: Mutex<State>,
}

/// The broker's pending-elicitation registry.
#[derive(Clone)]
pub struct Elicitations {
    inner: Arc<Inner>,
}

impl Elicitations {
    /// Build against the broker-owned request history so elicitation records
    /// land in the same Recent Inbox as approvals.
    pub fn with_history(
        audit: Arc<AuditLog>,
        events: Arc<dyn BrokerEvents>,
        history: Arc<RequestHistory>,
    ) -> Self {
        Self::with_timeout(audit, events, history, ELICITATION_TIMEOUT)
    }

    fn with_timeout(
        audit: Arc<AuditLog>,
        events: Arc<dyn BrokerEvents>,
        history: Arc<RequestHistory>,
        timeout: Duration,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                audit,
                events,
                history,
                timeout,
                state: Mutex::new(State::default()),
            }),
        }
    }

    /// Ask the user for one upstream elicitation, and wait for the answer.
    /// A shell that cannot ask, a lapse, or a broker teardown all resolve to
    /// `cancel` — a valid MCP `ElicitResult` the upstream knows how to handle.
    pub async fn elicit(&self, request: ElicitationRequest) -> ElicitationOutcome {
        let now = Instant::now();
        let lapsed = {
            let mut state = self.inner.state.lock().unwrap();
            Self::sweep(&mut state, now)
        };
        self.announce_lapsed(&lapsed);

        let (receiver, id, deadline) = {
            let inner = &self.inner;
            let mut state = inner.state.lock().unwrap();
            if state.pending.len() >= MAX_PENDING {
                drop(state);
                return ElicitationOutcome::cancelled();
            }
            let id = Uuid::new_v4();
            let requested_at = Utc::now();
            let expires_at = requested_at
                + chrono::Duration::from_std(inner.timeout)
                    .unwrap_or_else(|_| chrono::Duration::seconds(300));
            let info = PendingElicitation {
                id,
                connection_id: request.connection.id,
                connection: request.connection.name.clone(),
                agent: request.agent.clone(),
                tool: cap_text(&request.tool, FIELD_TEXT_CAP),
                message: cap_text(&request.message, ELICITATION_TEXT_CAP),
                fields: fields_from_schema(&request.requested_schema),
                requested_at,
                expires_at,
            };
            let (tx, rx) = oneshot::channel();
            let deadline = now + inner.timeout;
            state.pending.insert(
                id,
                Pending {
                    info: info.clone(),
                    waiter: tx,
                    deadline,
                },
            );
            drop(state);

            inner.history.record_elicitation(&info);
            inner.audit.append(
                AuditEntry::new(
                    AuditKind::Requested,
                    format!(
                        "Input requested: {} → {} · {}",
                        request.agent, request.connection.name, info.tool
                    ),
                )
                .agent(request.agent.clone())
                .connection(request.connection.name.clone())
                .detail(info.message.clone())
                .field("kind", "elicitation")
                .field("elicitation_id", id.to_string()),
            );

            match inner.events.elicitation_requested(&info) {
                ElicitationHandling::Taken => {
                    let elicitations = self.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await;
                        elicitations.resolve(
                            &id,
                            ElicitationOutcome::cancelled(),
                            RequestResolution::TimedOut,
                        );
                    });
                    (rx, id, deadline)
                }
                ElicitationHandling::Unavailable => {
                    self.resolve(
                        &id,
                        ElicitationOutcome::cancelled(),
                        RequestResolution::NoSurface,
                    );
                    return ElicitationOutcome::cancelled();
                }
            }
        };

        match tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), receiver).await {
            Ok(Ok(outcome)) => outcome,
            // Sender dropped (broker teardown) or deadline passed: the call is
            // cancelled. The deadline task already resolved history on timeout.
            Ok(Err(_)) => ElicitationOutcome::cancelled(),
            Err(_) => {
                self.resolve(
                    &id,
                    ElicitationOutcome::cancelled(),
                    RequestResolution::TimedOut,
                );
                ElicitationOutcome::cancelled()
            }
        }
    }

    /// Answer a pending elicitation from the app. `approved` with the user's
    /// field values accepts; otherwise it declines. The values arrive as
    /// strings (the form's inputs) and are coerced to the field's JSON type —
    /// a boolean field becomes a real `true`/`false` — before riding upstream.
    /// Returns whether one was waiting under that id.
    pub fn respond(&self, id: &Uuid, approved: bool, values: HashMap<String, String>) -> bool {
        let pending = {
            let mut state = self.inner.state.lock().unwrap();
            let Some(pending) = state.pending.remove(id) else {
                return false;
            };
            pending
        };
        let (outcome, resolution, outcome_word) = if approved {
            (
                ElicitationOutcome {
                    action: ElicitAction::Accept,
                    content: Some(coerce_content(&pending.info.fields, values)),
                },
                RequestResolution::InputProvided,
                "provided",
            )
        } else {
            (
                ElicitationOutcome {
                    action: ElicitAction::Decline,
                    content: None,
                },
                RequestResolution::InputRefused,
                "refused",
            )
        };
        self.inner.history.resolve(id, resolution);
        self.inner.audit.append(
            AuditEntry::new(
                if approved {
                    AuditKind::AllowedOnce
                } else {
                    AuditKind::Denied
                },
                format!(
                    "Input {outcome_word}: {} → {} · {}",
                    pending.info.agent, pending.info.connection, pending.info.tool
                ),
            )
            .agent(pending.info.agent.clone())
            .connection(pending.info.connection.clone())
            .field("kind", "elicitation")
            .field("elicitation_id", id.to_string()),
        );
        let _ = pending.waiter.send(outcome);
        self.inner.events.elicitation_resolved(id);
        true
    }

    /// Every elicitation waiting on the user, oldest first.
    pub fn pending(&self) -> Vec<PendingElicitation> {
        let (mut pending, lapsed) = {
            let mut state = self.inner.state.lock().unwrap();
            let lapsed = Self::sweep(&mut state, Instant::now());
            let pending: Vec<PendingElicitation> =
                state.pending.values().map(|p| p.info.clone()).collect();
            (pending, lapsed)
        };
        self.announce_lapsed(&lapsed);
        pending.sort_by_key(|p| p.requested_at);
        pending
    }

    /// Refuse whatever is parked on a connection and forget it — its access
    /// was switched off, retargeted, or deleted, so the answer the user would
    /// give no longer maps to anything.
    pub fn revoke(&self, connection_id: &Uuid) {
        let ids: Vec<Uuid> = {
            let state = self.inner.state.lock().unwrap();
            state
                .pending
                .iter()
                .filter(|(_, pending)| pending.info.connection_id == *connection_id)
                .map(|(id, _)| *id)
                .collect()
        };
        for id in ids {
            self.resolve(
                &id,
                ElicitationOutcome::cancelled(),
                RequestResolution::PolicyChanged,
            );
        }
    }

    fn announce_lapsed(&self, lapsed: &[Lapsed]) {
        for item in lapsed {
            self.inner.history.resolve(&item.id, item.resolution);
            self.inner.events.elicitation_resolved(&item.id);
        }
    }

    fn resolve(&self, id: &Uuid, outcome: ElicitationOutcome, resolution: RequestResolution) {
        let pending = {
            let mut state = self.inner.state.lock().unwrap();
            let Some(pending) = state.pending.remove(id) else {
                return;
            };
            pending
        };
        self.inner.history.resolve(id, resolution);
        let _ = pending.waiter.send(outcome);
        self.inner.events.elicitation_resolved(id);
    }

    /// Drop and answer prompts whose deadline has passed, or whose caller
    /// disconnected. Returns what left the queue so history and the shell can
    /// be told once the lock is released.
    #[must_use]
    fn sweep(state: &mut State, now: Instant) -> Vec<Lapsed> {
        let retired: Vec<(Uuid, bool)> = state
            .pending
            .iter()
            .filter(|(_, pending)| pending.deadline <= now || pending.waiter.is_closed())
            .map(|(id, pending)| (*id, pending.deadline <= now))
            .collect();
        let mut lapsed = Vec::with_capacity(retired.len());
        for (id, timed_out) in retired {
            if let Some(pending) = state.pending.remove(&id) {
                if timed_out {
                    let _ = pending.waiter.send(ElicitationOutcome::cancelled());
                }
                lapsed.push(Lapsed {
                    id,
                    resolution: if timed_out {
                        RequestResolution::TimedOut
                    } else {
                        RequestResolution::CallerDisconnected
                    },
                });
            }
        }
        lapsed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request_history::RequestStatus;
    use crate::types::ConnectionConfig;
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A shell that answers every elicitation the moment it is raised.
    struct AutoAnswer {
        approved: bool,
        seen: AtomicUsize,
        elicitations: Mutex<Option<Elicitations>>,
    }

    impl BrokerEvents for AutoAnswer {
        fn elicitation_requested(&self, pending: &PendingElicitation) -> ElicitationHandling {
            self.seen.fetch_add(1, Ordering::SeqCst);
            let elicitations = self.elicitations.lock().unwrap().clone();
            if let Some(elicitations) = elicitations {
                let mut values = HashMap::new();
                values.insert("name".to_string(), "octocat".to_string());
                values.insert("dry_run".to_string(), "true".to_string());
                elicitations.respond(&pending.id, self.approved, values);
            }
            ElicitationHandling::Taken
        }
    }

    struct NeverAnswers;
    impl BrokerEvents for NeverAnswers {
        fn elicitation_requested(&self, _pending: &PendingElicitation) -> ElicitationHandling {
            ElicitationHandling::Taken
        }
    }

    /// The trait default: no surface can ask.
    struct NoSurface;
    impl BrokerEvents for NoSurface {}

    fn connection() -> Connection {
        Connection {
            id: Uuid::new_v4(),
            name: "notion".into(),
            config: ConnectionConfig::Api {
                host: "mcp.notion.com".into(),
                scheme: "https".into(),
                port: None,
                template: "Authorization: Bearer {{T}}".into(),
                mcp_path: Some("/mcp".into()),
                oauth: None,
            },
            secrets: vec![],
            account: None,
            oauth: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn request() -> ElicitationRequest {
        ElicitationRequest {
            connection: connection(),
            agent: "claude-code".into(),
            tool: "search".into(),
            message: "Please provide your GitHub username".into(),
            requested_schema: json!({
                "type": "object",
                "properties": {
                    "name": { "type": "string", "title": "Username" },
                    "dry_run": { "type": "boolean", "title": "Dry run" },
                },
                "required": ["name"],
            }),
        }
    }

    fn registry(events: Arc<dyn BrokerEvents>) -> (Elicitations, Arc<RequestHistory>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let audit = Arc::new(AuditLog::open(dir.path().join("audit.jsonl")).unwrap());
        let history = Arc::new(RequestHistory::default());
        let elicitations = Elicitations::with_timeout(
            audit,
            events,
            history.clone(),
            Duration::from_millis(200),
        );
        (elicitations, history, dir)
    }

    fn auto(approved: bool) -> (Elicitations, Arc<RequestHistory>, tempfile::TempDir) {
        let events = Arc::new(AutoAnswer {
            approved,
            seen: AtomicUsize::new(0),
            elicitations: Mutex::new(None),
        });
        let (elicitations, history, dir) = registry(events.clone());
        *events.elicitations.lock().unwrap() = Some(elicitations.clone());
        (elicitations, history, dir)
    }

    #[test]
    fn schema_becomes_form_fields() {
        let fields = fields_from_schema(&json!({
            "type": "object",
            "properties": {
                "name": { "type": "string", "title": "Full name" },
                "dry_run": { "type": "boolean", "title": "Dry run" },
                "env": { "type": "string", "title": "Environment", "enum": ["prod", "staging"] },
            },
        }));
        let by_name: HashMap<_, _> = fields.iter().map(|f| (f.name.as_str(), f)).collect();
        assert_eq!(by_name["name"].label, "Full name");
        assert!(!by_name["name"].secret);
        assert_eq!(by_name["name"].options, None);
        assert!(by_name["dry_run"].boolean);
        assert!(!by_name["dry_run"].secret);
        assert_eq!(
            by_name["env"].options.as_deref(),
            Some(["prod".to_string(), "staging".to_string()].as_slice())
        );
    }

    #[tokio::test]
    async fn accepting_provides_input() {
        let (elicitations, history, _dir) = auto(true);
        let outcome = elicitations.elicit(request()).await;
        assert_eq!(outcome.action, ElicitAction::Accept);
        let content = outcome.content.unwrap();
        assert_eq!(content["name"], json!("octocat"));
        // A boolean field rides upstream as a real JSON boolean, not "true".
        assert_eq!(content["dry_run"], json!(true));
        let records = history.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].status, RequestStatus::Approved);
        assert_eq!(records[0].resolution, Some(RequestResolution::InputProvided));
    }

    #[tokio::test]
    async fn declining_refuses_input() {
        let (elicitations, history, _dir) = auto(false);
        let outcome = elicitations.elicit(request()).await;
        assert_eq!(outcome.action, ElicitAction::Decline);
        assert!(outcome.content.is_none());
        assert_eq!(history.records()[0].resolution, Some(RequestResolution::InputRefused));
    }

    #[tokio::test]
    async fn an_unanswered_elicitation_times_out_to_cancel() {
        let (elicitations, history, _dir) = registry(Arc::new(NeverAnswers));
        let outcome = elicitations.elicit(request()).await;
        assert_eq!(outcome.action, ElicitAction::Cancel);
        assert!(elicitations.pending().is_empty());
        assert_eq!(history.records()[0].status, RequestStatus::Expired);
    }

    #[tokio::test]
    async fn no_surface_cancels_and_records_unavailable() {
        let (elicitations, history, _dir) = registry(Arc::new(NoSurface));
        let outcome = elicitations.elicit(request()).await;
        assert_eq!(outcome.action, ElicitAction::Cancel);
        assert!(elicitations.pending().is_empty());
        assert_eq!(history.records()[0].status, RequestStatus::Unavailable);
        assert_eq!(history.records()[0].resolution, Some(RequestResolution::NoSurface));
    }

    #[tokio::test]
    async fn answering_an_unknown_elicitation_reports_it() {
        let (elicitations, _history, _dir) = registry(Arc::new(NeverAnswers));
        assert!(!elicitations.respond(&Uuid::new_v4(), true, HashMap::new()));
    }
}
