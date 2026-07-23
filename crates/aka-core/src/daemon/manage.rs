//! The manage plane: the desktop shell's HTTP surface onto a broker.
//!
//! Routes mirror the [`ManagementBackend`] trait one-to-one; the handlers
//! drive a [`LocalBackend`] so a remote shell exercises exactly the code
//! path an in-process shell does. Authorization is the management token
//! (`akamgr_…`) — a credential distinct from the agent key, closed until
//! `aka manage token` issues one. Agent keys never authenticate here and
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
    AccessBody, AllowedToolsBody, ConnectionAddBody, ConnectionUpdateBody, DraftTestBody,
    ManagementBackend, SecretAddBody, SecretEditBody, SettingsPatchBody,
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
            Err(_) => Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "reason": "invalid_manage_token",
                    "detail": "manage routes require this broker's management token \
                               (issue one on the broker host with `aka manage token`)",
                })),
            )
                .into_response()),
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
        .route(
            "/connections/test-draft",
            post(test_connection_draft),
        )
        .route(
            "/connections/{id}",
            put(update_connection).delete(delete_connection),
        )
        .route("/connections/{id}/test", post(test_connection))
        .route("/connections/{id}/access", post(set_tool_access))
        .route("/connections/{id}/allowed-tools", post(set_allowed_tools))
        .route("/connections/{id}/mcp-tools", get(list_mcp_tools))
        .route("/connections/{id}/mcp-status", post(mcp_status))
        .route("/connections/{id}/endpoint", post(issue_endpoint))
        .route("/endpoints/{id}", delete(revoke_endpoint))
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

/// The SSE change feed. On lag (a slow consumer dropped notifications) the
/// stream emits `resync` so the client refetches everything rather than
/// trusting incremental updates.
async fn events(
    State(state): State<AppState>,
    _authed: ManageAuthed,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = state.broker.subscribe_manage_events();
    let stream = futures::stream::unfold(rx, |mut rx| async move {
        let event = match rx.recv().await {
            Ok(event) => event,
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => ManageEvent::Resync,
            Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
        };
        let sse = Event::default().json_data(&event).ok()?;
        Some((Ok::<_, Infallible>(sse), rx))
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

/* ---------------------- identity, sessions, activity ---------------------- */

async fn identity(State(state): State<AppState>, _authed: ManageAuthed) -> Response {
    respond(state.manage.identity().await)
}

/// The agent key's plaintext, for the shell-side "copy key" affordance.
/// Holders of the manage token could read the token file on the host
/// anyway; this keeps the Connect page's copy button working remotely.
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

/// The manage view's activity cap, mirroring the shell's own limit.
const ACTIVITY_VIEW_LIMIT: usize = 200;

async fn activity(
    State(state): State<AppState>,
    _authed: ManageAuthed,
    Query(query): Query<ActivityQuery>,
) -> Response {
    let limit = query
        .limit
        .unwrap_or(ACTIVITY_VIEW_LIMIT)
        .min(ACTIVITY_VIEW_LIMIT);
    respond(state.manage.activity(limit).await)
}

async fn clear_activity(State(state): State<AppState>, _authed: ManageAuthed) -> Response {
    let result = state.manage.clear_activity().await;
    if result.is_ok() {
        // No BrokerEvents counterpart exists for a clear; tell SSE
        // subscribers directly so remote activity views refresh.
        state
            .broker
            .publish_manage_event(ManageEvent::ActivityCleared);
    }
    respond(result)
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
