//! The manage plane: the desktop shell's HTTP surface onto a broker.
//!
//! Routes mirror the [`ManagementBackend`] trait one-to-one; the handlers
//! drive a [`LocalBackend`] so a remote shell exercises exactly the code
//! path an in-process shell does. Authorization is the management token
//! (`akamgr_…`) — a credential distinct from the agent key, closed until
//! `mfa manage token` issues one. Agent keys never authenticate here and
//! the manage token never authenticates the agent plane.
//!
//! Failures cross the wire as the `aka-api` [`ManageError`] serialization,
//! so a remote shell reconstructs the same structured error an in-process
//! shell receives; the HTTP status is a coarse hint for humans and curl.

use std::convert::Infallible;

use aka_api::{ManageError, ManageEvent};
use axum::extract::{FromRequestParts, Path, Query, State};
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, patch, post, put};
use axum::{Json, Router};
use futures::Stream;
use serde_json::json;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{bearer_token, err_missing_token, ApiJson, AppState};
use crate::manage::{
    AccessBody, AllowedToolsBody, ConnectionAddBody, ConnectionUpdateBody, ConnectionsReorderBody,
    DraftTestBody, ManagementBackend, McpAuthDeliverBody, McpAuthStartBody, OAuthCompleteBody,
    OAuthReconnectBody, OAuthStartBody, SecretAddBody, SecretEditBody, SettingsPatchBody,
};

/// Bearer authentication against the management token.
pub struct ManageAuthed;

impl FromRequestParts<AppState> for ManageAuthed {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = bearer_token(&parts.headers).map_err(err_missing_token)?;
        match state.broker.identity.verify_manage(token) {
            Ok(()) => Ok(ManageAuthed),
            Err(error) => {
                // Both map to InvalidManageToken client-side (re-enter the
                // token), but the detail names the cause so a curl user
                // knows whether to re-issue or check what they pasted.
                let detail = if error == crate::identity::TokenError::Expired {
                    "the management token has expired; issue a fresh one on the \
                     broker host with `mfa manage token`"
                } else {
                    "manage routes require this broker's management token \
                     (issue one on the broker host with `mfa manage token`)"
                };
                Err((
                    StatusCode::UNAUTHORIZED,
                    Json(json!({ "reason": "invalid_manage_token", "detail": detail })),
                )
                    .into_response())
            }
        }
    }
}

fn manage_error_response(error: ManageError) -> Response {
    let status = match &error {
        ManageError::SecretNotFound
        | ManageError::ConnectionNotFound
        | ManageError::EndpointNotFound => StatusCode::NOT_FOUND,
        ManageError::SecretNameTaken { .. }
        | ManageError::ConnectionNameTaken { .. }
        | ManageError::ConnectionTargetTaken { .. }
        | ManageError::ApprovalConnectionChanged
        | ManageError::SecretInUse { .. }
        | ManageError::KindChange
        | ManageError::EndpointLimit { .. }
        | ManageError::EndpointRequiresWiring
        | ManageError::EndpointUnsupportedKind { .. } => StatusCode::CONFLICT,
        ManageError::InvalidSecretName { .. }
        | ManageError::InvalidConnectionName { .. }
        | ManageError::Template { .. }
        | ManageError::UnknownTemplateRef { .. }
        | ManageError::WrongSecretCount { .. }
        | ManageError::InvalidConnectionConfig { .. }
        | ManageError::InvalidSetting { .. }
        | ManageError::InvalidConnectionField { .. } => StatusCode::UNPROCESSABLE_ENTITY,
        ManageError::NotConfirmed | ManageError::SecretReadNotAuthenticated => {
            StatusCode::FORBIDDEN
        }
        ManageError::RemoteUnsupported { .. } => StatusCode::NOT_IMPLEMENTED,
        ManageError::InvalidManageToken => StatusCode::UNAUTHORIZED,
        ManageError::Unreachable { .. } => StatusCode::BAD_GATEWAY,
        ManageError::OAuth { .. } | ManageError::Vault { .. } | ManageError::Internal { .. } => {
            StatusCode::INTERNAL_SERVER_ERROR
        }
    };
    (status, Json(error)).into_response()
}

fn ok<T: serde::Serialize>(value: T) -> Response {
    Json(value).into_response()
}

fn respond<T: serde::Serialize>(result: Result<T, ManageError>) -> Response {
    match result {
        Ok(value) => ok(value),
        Err(error) => manage_error_response(error),
    }
}

/// The manage router, nested at `/v1/manage` by the daemon.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/whoami", get(whoami))
        .route("/events", get(events))
        .route("/secrets", get(list_secrets).post(add_secret))
        .route("/secrets/{id}", patch(edit_secret).delete(delete_secret))
        .route("/secrets/{id}/reveal-prefix", post(reveal_secret_prefix))
        .route("/secrets/{id}/copy-value", post(secret_value_for_copy))
        .route("/connections", get(list_connections).post(add_connection))
        .route("/connections/test-draft", post(test_connection_draft))
        .route("/connections/reorder", post(reorder_connections))
        .route(
            "/connections/{id}",
            put(update_connection).delete(delete_connection),
        )
        .route("/connections/{id}/test", post(test_connection))
        .route("/connections/{id}/access", post(set_tool_access))
        .route("/connections/{id}/allowed-tools", post(set_allowed_tools))
        .route("/connections/{id}/mcp-tools", get(list_mcp_tools))
        .route("/connections/{id}/mcp-status", post(mcp_status))
        .route(
            "/connections/{id}/endpoint",
            post(issue_endpoint).get(get_endpoint),
        )
        .route("/endpoints/{id}", delete(revoke_endpoint))
        .route("/mcp-auth", post(mcp_auth_start))
        .route(
            "/mcp-auth/{id}",
            get(mcp_auth_state).delete(mcp_auth_cancel),
        )
        .route("/mcp-auth/{id}/deliver", post(mcp_auth_deliver))
        .route("/oauth/start", post(oauth_start))
        .route("/oauth/reconnect/{id}", post(oauth_reconnect_start))
        .route("/oauth/complete/{id}", post(oauth_complete))
        .route("/identity", get(identity))
        .route("/identity/agent-key", get(agent_key))
        .route("/identity/rotate", post(rotate_key))
        .route("/sessions", get(sessions))
        .route("/sessions/{id}", delete(close_session))
        .route("/activity", get(activity).delete(clear_activity))
        .route("/settings", get(settings).patch(patch_settings))
        .route("/agent-setup", get(agent_setup))
}

async fn whoami(State(state): State<AppState>, _authed: ManageAuthed) -> Response {
    ok(json!({
        "ok": true,
        "version": state.broker.config.version,
        "client_id": state.broker.identity.client_id(),
    }))
}

/// The SSE change feed with reconnect resume. Each frame carries an
/// `id: <epoch>:<seq>`; a client reconnecting with `Last-Event-ID` is sent
/// only the events it missed (or a single `resync` when its position is
/// unknown, foreign to this broker process, or has aged out of the buffer).
/// Live delivery still emits `resync` on broadcast lag.
async fn events(
    State(state): State<AppState>,
    _authed: ManageAuthed,
    headers: axum::http::HeaderMap,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    use crate::manage::{parse_event_id, ManageReplay, SeqEvent};

    let bus = state.broker.manage_bus().clone();
    // Subscribe *before* asking for replay so nothing slips through the gap
    // between the ring snapshot and going live; live events at or below the
    // replayed head are then deduped by seq.
    let rx = bus.subscribe();
    let last = headers
        .get("last-event-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let parsed = last.as_deref().and_then(parse_event_id);

    let epoch = bus.epoch().to_string();
    let mut backlog: std::collections::VecDeque<SeqEvent> = std::collections::VecDeque::new();
    let mut delivered_head = parsed.map(|(_, seq)| seq).unwrap_or(0);
    let mut resync_first = false;
    match bus.replay_since(parsed) {
        ManageReplay::Replay(events) => {
            delivered_head = events.last().map(|e| e.seq).unwrap_or(delivered_head);
            backlog.extend(events);
        }
        ManageReplay::UpToDate => {}
        ManageReplay::Resync => {
            resync_first = true;
            // The client's position is meaningless here (fresh, foreign
            // epoch, or aged out), so it must not become the live-dedupe
            // baseline: a foreign id whose seq is *above* this process's
            // head would otherwise swallow every live event after the
            // resync — and the resync frame would teach the client that
            // same poisoned position back. Baseline on this process's own
            // head instead; anything at or below it is covered by the
            // refetch the resync triggers.
            delivered_head = bus.head_seq();
        }
    }

    struct StreamState {
        rx: tokio::sync::broadcast::Receiver<SeqEvent>,
        backlog: std::collections::VecDeque<SeqEvent>,
        epoch: String,
        // Highest seq already sent, so a live event the backlog covered is
        // not sent twice.
        delivered_head: u64,
        resync_first: bool,
    }
    let init = StreamState {
        rx,
        backlog,
        epoch,
        delivered_head,
        resync_first,
    };

    let stream = futures::stream::unfold(init, |mut st| async move {
        // A resync marker leads, carrying the current head id so the client
        // has a baseline to resume from next time.
        if std::mem::take(&mut st.resync_first) {
            let id = format!("{}:{}", st.epoch, st.delivered_head);
            let sse = Event::default()
                .id(id)
                .json_data(&ManageEvent::Resync)
                .ok()?;
            return Some((Ok::<_, Infallible>(sse), st));
        }
        // Drain any replay backlog before live events.
        if let Some(item) = st.backlog.pop_front() {
            st.delivered_head = item.seq;
            let sse = Event::default()
                .id(format!("{}:{}", st.epoch, item.seq))
                .json_data(&item.event)
                .ok()?;
            return Some((Ok(sse), st));
        }
        loop {
            let item = match st.rx.recv().await {
                Ok(item) => item,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                    // Dropped live notifications: force a full refetch.
                    let id = format!("{}:{}", st.epoch, st.delivered_head);
                    let sse = Event::default()
                        .id(id)
                        .json_data(&ManageEvent::Resync)
                        .ok()?;
                    return Some((Ok(sse), st));
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
            };
            // Skip anything the replay backlog already covered.
            if item.seq <= st.delivered_head {
                continue;
            }
            st.delivered_head = item.seq;
            let sse = Event::default()
                .id(format!("{}:{}", st.epoch, item.seq))
                .json_data(&item.event)
                .ok()?;
            return Some((Ok(sse), st));
        }
    });
    Sse::new(stream).keep_alive(KeepAlive::default())
}

/* ------------------------------- secrets ---------------------------------- */

async fn list_secrets(State(state): State<AppState>, _authed: ManageAuthed) -> Response {
    respond(state.manage.list_secrets().await)
}

async fn add_secret(
    State(state): State<AppState>,
    _authed: ManageAuthed,
    ApiJson(body): ApiJson<SecretAddBody>,
) -> Response {
    respond(
        state
            .manage
            .add_secret(body.name, Zeroizing::new(body.value))
            .await,
    )
}

async fn edit_secret(
    State(state): State<AppState>,
    _authed: ManageAuthed,
    Path(id): Path<Uuid>,
    ApiJson(body): ApiJson<SecretEditBody>,
) -> Response {
    let value = body.new_value.filter(|v| !v.is_empty()).map(Zeroizing::new);
    respond(state.manage.edit_secret(id, body.new_name, value).await)
}

async fn delete_secret(
    State(state): State<AppState>,
    _authed: ManageAuthed,
    Path(id): Path<Uuid>,
) -> Response {
    respond(state.manage.delete_secret(id).await)
}

async fn reveal_secret_prefix(
    State(state): State<AppState>,
    _authed: ManageAuthed,
    Path(id): Path<Uuid>,
) -> Response {
    respond(
        state
            .manage
            .reveal_secret_prefix(id)
            .await
            .map(|prefix| json!({ "prefix": prefix })),
    )
}

/// The one route that returns a stored secret's full value: the remote
/// shell's clipboard copy (the value goes shell-side to the clipboard and
/// never enters the webview, mirroring the local flow). Gated by the same
/// core read-confirmation path as a local copy — and audited *here*, at
/// release: once the value leaves the broker the copy has happened for
/// audit purposes, whatever the client does next. (The local flow audits
/// through `note_secret_copied` after its own clipboard write; there is no
/// honor-system note route for remote clients.)
async fn secret_value_for_copy(
    State(state): State<AppState>,
    _authed: ManageAuthed,
    Path(id): Path<Uuid>,
) -> Response {
    let result = state.manage.secret_value_for_copy(id).await;
    if result.is_ok() {
        if let Ok(meta) = state.broker.store.secret_by_id(&id) {
            state.broker.audit.append(crate::audit::AuditEntry::new(
                crate::audit::AuditKind::SecretCopied,
                format!("Secret value copied (manage API): {}", meta.name),
            ));
        }
    }
    respond(result.map(|value| json!({ "value": value.to_string() })))
}

/* ----------------------------- connections -------------------------------- */

async fn list_connections(State(state): State<AppState>, _authed: ManageAuthed) -> Response {
    respond(state.manage.list_connections().await)
}

async fn add_connection(
    State(state): State<AppState>,
    _authed: ManageAuthed,
    ApiJson(body): ApiJson<ConnectionAddBody>,
) -> Response {
    match body.new_secret {
        Some(new_secret) => respond(
            state
                .manage
                .add_connection_with_secret(
                    new_secret.name,
                    Zeroizing::new(new_secret.value),
                    body.spec,
                )
                .await,
        ),
        None => respond(state.manage.add_connection(body.spec).await),
    }
}

async fn update_connection(
    State(state): State<AppState>,
    _authed: ManageAuthed,
    Path(id): Path<Uuid>,
    ApiJson(body): ApiJson<ConnectionUpdateBody>,
) -> Response {
    respond(state.manage.update_connection(id, body.spec).await)
}

async fn delete_connection(
    State(state): State<AppState>,
    _authed: ManageAuthed,
    Path(id): Path<Uuid>,
) -> Response {
    respond(state.manage.delete_connection(id).await)
}

async fn reorder_connections(
    State(state): State<AppState>,
    _authed: ManageAuthed,
    ApiJson(body): ApiJson<ConnectionsReorderBody>,
) -> Response {
    respond(state.manage.reorder_connections(body.ordered_ids).await)
}

async fn test_connection(
    State(state): State<AppState>,
    _authed: ManageAuthed,
    Path(id): Path<Uuid>,
) -> Response {
    respond(state.manage.test_connection(id).await)
}

async fn test_connection_draft(
    State(state): State<AppState>,
    _authed: ManageAuthed,
    ApiJson(body): ApiJson<DraftTestBody>,
) -> Response {
    let typed = body
        .typed_secret
        .filter(|value| !value.is_empty())
        .map(Zeroizing::new);
    respond(state.manage.test_connection_draft(body.spec, typed).await)
}

async fn set_tool_access(
    State(state): State<AppState>,
    _authed: ManageAuthed,
    Path(id): Path<Uuid>,
    ApiJson(body): ApiJson<AccessBody>,
) -> Response {
    respond(
        state
            .manage
            .set_tool_access(id, body.enabled)
            .await
            .map(|changed| json!({ "changed": changed })),
    )
}

async fn set_allowed_tools(
    State(state): State<AppState>,
    _authed: ManageAuthed,
    Path(id): Path<Uuid>,
    ApiJson(body): ApiJson<AllowedToolsBody>,
) -> Response {
    respond(
        state
            .manage
            .set_allowed_tools(id, body.tools)
            .await
            .map(|changed| json!({ "changed": changed })),
    )
}

async fn list_mcp_tools(
    State(state): State<AppState>,
    _authed: ManageAuthed,
    Path(id): Path<Uuid>,
) -> Response {
    respond(state.manage.list_mcp_tools(id).await)
}

/// The check options ride as a required JSON body; `{}` means defaults.
async fn mcp_status(
    State(state): State<AppState>,
    _authed: ManageAuthed,
    Path(id): Path<Uuid>,
    ApiJson(options): ApiJson<crate::mcp::McpCheckOptions>,
) -> Response {
    respond(state.manage.mcp_status(id, options).await)
}

async fn issue_endpoint(
    State(state): State<AppState>,
    _authed: ManageAuthed,
    Path(id): Path<Uuid>,
) -> Response {
    respond(state.manage.issue_endpoint(id).await)
}

async fn get_endpoint(
    State(state): State<AppState>,
    _authed: ManageAuthed,
    Path(id): Path<Uuid>,
) -> Response {
    respond(state.manage.get_endpoint(id).await)
}

async fn revoke_endpoint(
    State(state): State<AppState>,
    _authed: ManageAuthed,
    Path(id): Path<Uuid>,
) -> Response {
    respond(
        state
            .manage
            .revoke_endpoint(id)
            .await
            .map(|revoked| json!({ "revoked": revoked })),
    )
}

/* -------------------------- relayed MCP sign-in --------------------------- */

/// Begin a relayed MCP sign-in. Progress rides the SSE feed as
/// `mcp_auth_changed`; the shell opens the authorize URL itself and
/// delivers the code its catcher receives.
async fn mcp_auth_start(
    State(state): State<AppState>,
    _authed: ManageAuthed,
    ApiJson(body): ApiJson<McpAuthStartBody>,
) -> Response {
    let result = state
        .broker
        .ui_start_mcp_auth_external(body.draft, &body.redirect_uri);
    respond(result.map_err(ManageError::from))
}

async fn mcp_auth_state(
    State(state): State<AppState>,
    _authed: ManageAuthed,
    Path(id): Path<Uuid>,
) -> Response {
    ok(state.broker.ui_mcp_auth_state(&id))
}

async fn mcp_auth_cancel(
    State(state): State<AppState>,
    _authed: ManageAuthed,
    Path(id): Path<Uuid>,
) -> Response {
    ok(json!({ "cancelled": state.broker.ui_cancel_mcp_auth(&id) }))
}

async fn mcp_auth_deliver(
    State(state): State<AppState>,
    _authed: ManageAuthed,
    Path(id): Path<Uuid>,
    ApiJson(body): ApiJson<McpAuthDeliverBody>,
) -> Response {
    ok(json!({
        "delivered": state
            .broker
            .ui_mcp_auth_deliver_code(&id, body.code, body.state)
    }))
}

/* ------------------------- relayed OAuth (BYO app) ------------------------ */

/// Begin a relayed OAuth connect. The shell's loopback catcher receives the
/// browser redirect on the *user's* machine; the broker keeps the verifier
/// and completes on `/oauth/complete/{flow_id}`.
async fn oauth_start(
    State(state): State<AppState>,
    _authed: ManageAuthed,
    ApiJson(body): ApiJson<OAuthStartBody>,
) -> Response {
    let result = state.broker.manage_oauth_start(
        &body.secret_name,
        body.client_secret.map(Zeroizing::new),
        body.spec,
        &body.redirect_uri,
    );
    respond(result.map_err(ManageError::from))
}

async fn oauth_reconnect_start(
    State(state): State<AppState>,
    _authed: ManageAuthed,
    Path(id): Path<Uuid>,
    ApiJson(body): ApiJson<OAuthReconnectBody>,
) -> Response {
    let result = state
        .broker
        .manage_oauth_reconnect_start(&id, &body.redirect_uri)
        .await;
    respond(result.map_err(ManageError::from))
}

async fn oauth_complete(
    State(state): State<AppState>,
    _authed: ManageAuthed,
    Path(id): Path<Uuid>,
    ApiJson(body): ApiJson<OAuthCompleteBody>,
) -> Response {
    let result = state
        .broker
        .manage_oauth_complete(&id, &body.code, &body.state)
        .await;
    respond(result.map_err(ManageError::from))
}

/* ---------------------- identity, sessions, activity ---------------------- */

async fn identity(State(state): State<AppState>, _authed: ManageAuthed) -> Response {
    respond(state.manage.identity().await)
}

/// The agent key's plaintext, for the shell-side "copy key" affordance.
/// Holders of the manage token could read the token file on the host
/// anyway; this keeps the Connect page's copy button working remotely.
/// (`LocalBackend::agent_key` audits the release, so remote copies land
/// in the activity log exactly once.)
async fn agent_key(State(state): State<AppState>, _authed: ManageAuthed) -> Response {
    respond(
        state
            .manage
            .agent_key()
            .await
            .map(|token| json!({ "token": token })),
    )
}

async fn rotate_key(State(state): State<AppState>, _authed: ManageAuthed) -> Response {
    respond(state.manage.rotate_key().await)
}

async fn sessions(State(state): State<AppState>, _authed: ManageAuthed) -> Response {
    respond(state.manage.sessions().await)
}

async fn close_session(
    State(state): State<AppState>,
    _authed: ManageAuthed,
    Path(id): Path<u64>,
) -> Response {
    respond(
        state
            .manage
            .close_session(id)
            .await
            .map(|closed| json!({ "closed": closed })),
    )
}

#[derive(serde::Deserialize)]
struct ActivityQuery {
    #[serde(default)]
    limit: Option<usize>,
}

/// Default activity tail when the caller does not choose a limit. Matches the
/// desktop view's ceiling so a default read and the app's own read agree.
const ACTIVITY_VIEW_LIMIT: usize = 500;

async fn activity(
    State(state): State<AppState>,
    _authed: ManageAuthed,
    Query(query): Query<ActivityQuery>,
) -> Response {
    let limit = query.limit.unwrap_or(ACTIVITY_VIEW_LIMIT);
    respond(state.manage.activity(limit).await)
}

async fn clear_activity(State(state): State<AppState>, _authed: ManageAuthed) -> Response {
    // `LocalBackend::clear_activity` publishes the ActivityCleared manage
    // event itself, so route-driven and in-process clears both reach SSE
    // subscribers.
    respond(state.manage.clear_activity().await)
}

/* ------------------------------- settings ---------------------------------- */

async fn settings(State(state): State<AppState>, _authed: ManageAuthed) -> Response {
    respond(state.manage.settings().await)
}

async fn patch_settings(
    State(state): State<AppState>,
    _authed: ManageAuthed,
    ApiJson(body): ApiJson<SettingsPatchBody>,
) -> Response {
    if let Some(on) = body.reauth_on_read {
        if let Err(error) = state.manage.set_reauth_on_read(on).await {
            return manage_error_response(error);
        }
    }
    if let Some(on) = body.show_websockets {
        if let Err(error) = state.manage.set_show_websockets(on).await {
            return manage_error_response(error);
        }
    }
    if let Some(on) = body.menu_bar_hides_dock {
        if let Err(error) = state.manage.set_menu_bar_hides_dock(on).await {
            return manage_error_response(error);
        }
    }
    if let Some(secs) = body.presence_window_secs {
        if let Err(error) = state.manage.set_presence_window(secs).await {
            return manage_error_response(error);
        }
    }
    respond(state.manage.settings().await)
}

async fn agent_setup(State(state): State<AppState>, _authed: ManageAuthed) -> Response {
    respond(
        state
            .manage
            .agent_setup()
            .await
            .map(|instructions| json!({ "instructions": instructions })),
    )
}
