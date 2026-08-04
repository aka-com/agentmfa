//! The manage plane: the desktop shell's HTTP surface onto a broker.
//!
//! Routes mirror the [`ManagementBackend`] trait one-to-one; the handlers
//! drive a [`LocalBackend`] so a remote shell exercises exactly the code
//! path an in-process shell does. Authorization is the management token
//! (`akamgr_…`) — a credential distinct from the agent key, closed until
//! `multitool manage token` issues one. Agent keys never authenticate here and
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
use axum::middleware::Next;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, patch, post, put};
use axum::{Json, Router};
use serde_json::json;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{bearer_token, err_missing_token, request_peer, ApiJson, AppState};
use crate::manage::{
    AccessBody, AllowedToolsBody, ApprovalResponseBody, AuditStatementsBody, ConfirmBody,
    ConnectionAddBody, ConnectionConfigPatchBody, ConnectionRenameBody, ConnectionUpdateBody,
    ConnectionsReorderBody, DraftTestBody, ElicitationResponseBody, EndpointExpiryBody,
    EndpointRequireAuthBody, ManagementBackend, McpAuthDeliverBody, McpAuthStartBody,
    OAuthCompleteBody, OAuthReconnectBody, OAuthStartBody, OnePasswordIntegrationAddBody,
    OnePasswordSecretAddBody, OnePasswordTokenBody, ResponseCredentialsBody, SecretAddBody,
    SecretEditBody, SettingsPatchBody,
};

/// Bearer authentication against the management token.
pub struct ManageAuthed {
    // The SSE handler revalidates long-lived streams. Keep the copied
    // credential zeroizing so it is not left in freed heap memory.
    token: Zeroizing<String>,
}

impl ManageAuthed {
    fn token(&self) -> &str {
        &self.token
    }
}

impl FromRequestParts<AppState> for ManageAuthed {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = bearer_token(&parts.headers).map_err(err_missing_token)?;
        match state.broker.identity.verify_manage(token) {
            Ok(()) => Ok(ManageAuthed {
                token: Zeroizing::new(token.to_string()),
            }),
            Err(error) => {
                let peer = request_peer(parts);
                let source = peer
                    .map(|peer| peer.ip().to_string())
                    .unwrap_or_else(|| state.transport.audit_label().to_string());
                let peer = peer.map(|peer| peer.ip().to_string());
                state.broker.audit_auth_failure(
                    "manage",
                    error.reason().as_str(),
                    state.transport.audit_label(),
                    peer.as_deref(),
                );
                if let Err(wait) = state.broker.manage_auth_limiter.check(&source) {
                    return Err(super::err_rate_limited(
                        crate::wire::ErrorReason::RateLimited,
                        wait,
                    ));
                }
                // Both map to InvalidManageToken client-side (re-enter the
                // token), but the detail names the cause so a curl user
                // knows whether to re-issue or check what they pasted.
                let detail = if error == crate::identity::TokenError::Expired {
                    "the management token has expired; issue a fresh one on the \
                     broker host with `multitool manage token`"
                } else {
                    "manage routes require this broker's management token \
                     (issue one on the broker host with `multitool manage token`)"
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
        ManageError::EndpointExpired => StatusCode::GONE,
        ManageError::SecretNameTaken { .. }
        | ManageError::ConnectionNameTaken { .. }
        | ManageError::ConnectionTargetTaken { .. }
        | ManageError::ConnectionChanged
        | ManageError::ApprovalConnectionChanged
        | ManageError::SecretInUse { .. }
        | ManageError::KindChange
        | ManageError::EndpointLimit { .. }
        | ManageError::EndpointRequiresWiring => StatusCode::CONFLICT,
        ManageError::InvalidSecretName { .. }
        | ManageError::InvalidConnectionName { .. }
        | ManageError::Template { .. }
        | ManageError::UnknownTemplateRef { .. }
        | ManageError::WrongSecretCount { .. }
        | ManageError::InvalidConnectionConfig { .. }
        | ManageError::InvalidSetting { .. }
        | ManageError::InvalidConnectionField { .. } => StatusCode::UNPROCESSABLE_ENTITY,
        ManageError::RemoteUnsupported { .. } => StatusCode::NOT_IMPLEMENTED,
        ManageError::InvalidManageToken { .. } => StatusCode::UNAUTHORIZED,
        ManageError::Unreachable { .. } => StatusCode::BAD_GATEWAY,
        ManageError::OnePassword { provider_code, .. }
            if matches!(
                provider_code.as_str(),
                "integration_not_found" | "not_found"
            ) =>
        {
            StatusCode::NOT_FOUND
        }
        ManageError::OnePassword { provider_code, .. } if provider_code == "integration_in_use" => {
            StatusCode::CONFLICT
        }
        ManageError::OnePassword { provider_code, .. }
            if matches!(
                provider_code.as_str(),
                "invalid_configuration" | "invalid_request" | "linked_secret_read_only"
            ) =>
        {
            StatusCode::UNPROCESSABLE_ENTITY
        }
        ManageError::OnePassword { provider_code, .. } if provider_code == "rate_limited" => {
            StatusCode::TOO_MANY_REQUESTS
        }
        ManageError::OnePassword { .. } => StatusCode::BAD_GATEWAY,
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
        .route(
            "/management-token",
            post(rotate_management_token).delete(revoke_management_token),
        )
        .route("/events", get(events))
        .route("/approval-surfaces", post(create_approval_surface))
        .route(
            "/approval-surfaces/{id}",
            put(heartbeat_approval_surface).delete(release_approval_surface),
        )
        .route("/secrets", get(list_secrets).post(add_secret))
        .route("/secrets/{id}", patch(edit_secret).delete(delete_secret))
        .route("/secrets/{id}/reveal-prefix", post(reveal_secret_prefix))
        .route("/secrets/{id}/copy-value", post(secret_value_for_copy))
        .route(
            "/integrations",
            get(list_onepassword_integrations).post(add_onepassword_integration),
        )
        .route(
            "/integrations/onepassword/secrets",
            post(add_onepassword_secret),
        )
        .route("/integrations/{id}", delete(delete_onepassword_integration))
        .route("/integrations/{id}/token", put(replace_onepassword_token))
        .route("/integrations/{id}/health", get(onepassword_health))
        .route("/integrations/{id}/vaults", get(onepassword_vaults))
        .route(
            "/integrations/{id}/vaults/{vault_id}/items",
            get(onepassword_items),
        )
        .route(
            "/integrations/{id}/vaults/{vault_id}/items/{item_id}/fields",
            get(onepassword_fields),
        )
        .route("/connections", get(list_connections).post(add_connection))
        .route("/connections/test-draft", post(test_connection_draft))
        .route("/connections/reorder", post(reorder_connections))
        .route(
            "/connections/{id}",
            put(update_connection)
                .patch(rename_connection)
                .delete(delete_connection),
        )
        .route("/connections/{id}/config", patch(patch_connection))
        .route("/connections/{id}/test", post(test_connection))
        .route("/connections/{id}/access", post(set_tool_access))
        .route("/connections/{id}/confirm", post(set_confirm_mode))
        .route(
            "/connections/{id}/response-credentials",
            post(set_expose_response_credentials),
        )
        .route("/connections/{id}/allowed-tools", post(set_allowed_tools))
        .route(
            "/connections/{id}/audit-statements",
            post(set_audit_statements),
        )
        .route("/connections/{id}/mcp-tools", get(list_mcp_tools))
        .route("/connections/{id}/mcp-status", post(mcp_status))
        .route(
            "/connections/{id}/endpoint",
            post(issue_endpoint).get(get_endpoint),
        )
        .route("/connections/{id}/endpoint/copy", post(copy_endpoint))
        .route("/connections/{id}/endpoint/renew", post(renew_endpoint))
        .route(
            "/connections/{id}/endpoint/expiry",
            post(set_endpoint_expiry),
        )
        .route(
            "/connections/{id}/endpoint/require-auth",
            post(set_endpoint_require_auth),
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
        .route("/approvals", get(approvals))
        .route("/approvals/snapshot", get(approval_snapshot))
        .route("/approvals/{id}", post(respond_approval))
        .route("/elicitations", get(elicitations))
        .route("/elicitations/{id}", post(respond_elicitation))
        .route("/requests", get(requests))
        .route("/sessions", get(sessions))
        .route("/sessions/{id}", delete(close_session))
        .route("/activity", get(activity).delete(clear_activity))
        .route("/activity/page", get(activity_page))
        .route("/settings", get(settings).patch(patch_settings))
        .route("/agent-setup", get(agent_setup))
        .layer(axum::middleware::from_fn(remote_decision_context))
}

/// Everything under `/v1/manage` is a management-token surface, including
/// requests arriving over the local control socket. Scope its direct socket
/// peer across the handler so every audit entry produced by the core carries
/// honest remote attribution. A reverse proxy remains the observed peer; this
/// is operational provenance, not a human identity.
async fn remote_decision_context(request: axum::extract::Request, next: Next) -> Response {
    let peer = request
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|info| info.0);
    crate::audit::with_request_decision_context(
        crate::types::DecisionContext::remote(peer),
        next.run(request),
    )
    .await
}

async fn whoami(State(state): State<AppState>, _authed: ManageAuthed) -> Response {
    ok(json!({
        "ok": true,
        "version": state.broker.config.version,
        "client_id": state.broker.identity.client_id(),
        "capabilities": [
            aka_api::APPROVAL_SURFACE_CAPABILITY,
            aka_api::ONEPASSWORD_PROVIDER_CAPABILITY,
        ],
        "approval_surface_attached": state.broker.events.has_approval_surface(),
    }))
}

#[derive(serde::Deserialize)]
struct RotateManagementTokenBody {
    ttl_days: u64,
}

fn token_mutation_error(error: crate::identity::ManageTokenMutationError) -> Response {
    match error {
        crate::identity::ManageTokenMutationError::Unauthorized(error) => {
            let detail = if error == crate::identity::TokenError::Expired {
                "the management token expired before it could authorize rotation"
            } else {
                "the management token was rotated or revoked before this request completed"
            };
            manage_error_response(ManageError::InvalidManageToken {
                detail: Some(detail.into()),
            })
        }
        crate::identity::ManageTokenMutationError::Persist(error) => {
            manage_error_response(ManageError::from(error))
        }
    }
}

/// Rotate only under authority of the still-current management token. The
/// identity store performs the second verification and mutation under one
/// lock, closing the extractor-to-handler race between concurrent rotations.
async fn rotate_management_token(
    State(state): State<AppState>,
    authed: ManageAuthed,
    ApiJson(body): ApiJson<RotateManagementTokenBody>,
) -> Response {
    if !(1..=3650).contains(&body.ttl_days) {
        return manage_error_response(ManageError::InvalidSetting {
            message: "management-token TTL must be between 1 and 3650 days".into(),
        });
    }
    let ttl = std::time::Duration::from_secs(body.ttl_days * 86_400);
    match state
        .broker
        .identity
        .rotate_manage_token_with_ttl(authed.token(), Some(ttl))
    {
        Ok(token) => {
            if let Err(error) = state.broker.paths.remove_manage_bootstrap_token() {
                tracing::warn!("could not remove consumed management bootstrap token: {error}");
            }
            let expires_at = state
                .broker
                .identity
                .manage_token_expires_at()
                .expect("online rotations always carry a TTL");
            let mut entry = crate::audit::AuditEntry::new(
                crate::audit::AuditKind::ManagementTokenIssued,
                "Management token rotated online",
            )
            .outcome("rotated")
            .field("expires_at", expires_at.to_rfc3339())
            .confirmation(crate::types::ConfirmationMethod::ManagementToken);
            if let Some(context) = crate::audit::current_decision_context() {
                entry = entry.context(&context);
            }
            state.broker.audit.append(entry);
            ok(json!({
                "token": token,
                "expires_at": expires_at.to_rfc3339(),
            }))
        }
        Err(error) => token_mutation_error(error),
    }
}

async fn revoke_management_token(State(state): State<AppState>, authed: ManageAuthed) -> Response {
    match state
        .broker
        .identity
        .revoke_manage_token_with_token(authed.token())
    {
        Ok(()) => {
            if let Err(error) = state.broker.paths.remove_manage_bootstrap_token() {
                tracing::warn!("could not remove consumed management bootstrap token: {error}");
            }
            let mut entry = crate::audit::AuditEntry::new(
                crate::audit::AuditKind::ManagementTokenRevoked,
                "Management token revoked online",
            )
            .outcome("revoked")
            .confirmation(crate::types::ConfirmationMethod::ManagementToken);
            if let Some(context) = crate::audit::current_decision_context() {
                entry = entry.context(&context);
            }
            state.broker.audit.append(entry);
            ok(json!({ "revoked": true }))
        }
        Err(error) => token_mutation_error(error),
    }
}

async fn create_approval_surface(State(state): State<AppState>, _authed: ManageAuthed) -> Response {
    let id = state.broker.manage_bus().mint_polling_approval_surface();
    ok(serde_json::to_value(aka_api::ApprovalSurfaceDto {
        id: id.to_string(),
        expires_in_ms: aka_api::APPROVAL_SURFACE_TTL_MS,
    })
    .expect("approval surface DTO serializes"))
}

/// Renew a capability minted for an attached event-stream or polling inbox.
/// Heartbeats cannot create capabilities: a released or unknown id fails
/// closed.
async fn heartbeat_approval_surface(
    State(state): State<AppState>,
    _authed: ManageAuthed,
    Path(id): Path<Uuid>,
) -> Response {
    if state.broker.manage_bus().renew_approval_surface(&id) {
        ok(json!({
            "expires_in_ms": aka_api::APPROVAL_SURFACE_TTL_MS,
        }))
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(json!({ "reason": "approval_surface_not_attached" })),
        )
            .into_response()
    }
}

async fn release_approval_surface(
    State(state): State<AppState>,
    _authed: ManageAuthed,
    Path(id): Path<Uuid>,
) -> Response {
    ok(json!({
        "released": state.broker.manage_bus().release_approval_surface(&id),
    }))
}

/// The SSE change feed with reconnect resume. Each frame carries an
/// `id: <epoch>:<seq>`; a client reconnecting with `Last-Event-ID` is sent
/// only the events it missed (or a single `resync` when its position is
/// unknown, foreign to this broker process, or has aged out of the buffer).
/// Live delivery still emits `resync` on broadcast lag.
async fn events(
    State(state): State<AppState>,
    authed: ManageAuthed,
    headers: axum::http::HeaderMap,
) -> Response {
    use crate::manage::{parse_event_id, ManageReplay, SeqEvent};

    let bus = state.broker.manage_bus().clone();
    let approval_surface = headers
        .get(aka_api::APPROVAL_SURFACE_HEADER)
        .and_then(|value| value.to_str().ok())
        .filter(|value| *value == aka_api::APPROVAL_SURFACE_V1)
        .map(|_| bus.lease_approval_surface());
    let mut response_headers = axum::http::HeaderMap::new();
    // Nginx otherwise commonly buffers tiny SSE frames, which would leave a
    // desktop heartbeating a stream whose approval events it cannot see.
    response_headers.insert(
        axum::http::HeaderName::from_static("x-accel-buffering"),
        axum::http::HeaderValue::from_static("no"),
    );
    response_headers.insert(
        aka_api::APPROVAL_SURFACE_STATUS_HEADER,
        axum::http::HeaderValue::from_static(if approval_surface.is_some() {
            aka_api::APPROVAL_SURFACE_STATUS_ACTIVE
        } else {
            aka_api::APPROVAL_SURFACE_STATUS_OBSERVER
        }),
    );
    if let Some(surface) = &approval_surface {
        response_headers.insert(
            aka_api::APPROVAL_SURFACE_ID_HEADER,
            axum::http::HeaderValue::from_str(&surface.id().to_string())
                .expect("UUID is a header-safe value"),
        );
    }
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
        identity: std::sync::Arc<crate::identity::IdentityStore>,
        token: Zeroizing<String>,
        // Present only when the authenticated client explicitly promised a
        // user-facing request inbox. Its Drop releases capability as soon as
        // the response stream goes away.
        _approval_surface: Option<crate::manage::ApprovalSurfaceLease>,
        revalidate: tokio::time::Interval,
        // Highest seq already sent, so a live event the backlog covered is
        // not sent twice.
        delivered_head: u64,
        // An immediate comment proves the response body is not being
        // buffered before the desktop activates its capability lease.
        ready_first: bool,
        resync_first: bool,
    }
    let init = StreamState {
        rx,
        backlog,
        epoch,
        identity: state.broker.identity.clone(),
        token: authed.token,
        _approval_surface: approval_surface,
        revalidate: tokio::time::interval(std::time::Duration::from_secs(1)),
        delivered_head,
        ready_first: true,
        resync_first,
    };

    let stream = futures::stream::unfold(init, |mut st| async move {
        // Authentication on the initial HTTP request is not enough for a
        // stream that can live indefinitely. Rotation, revocation, and TTL
        // expiry must stop both event disclosure and the stream counting as
        // an approval surface.
        if st.identity.verify_manage(&st.token).is_err() {
            return None;
        }
        if std::mem::take(&mut st.ready_first) {
            return Some((Ok::<_, Infallible>(Event::default().comment("ready")), st));
        }
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
            let item = tokio::select! {
                biased;
                _ = st.revalidate.tick() => {
                    if st.identity.verify_manage(&st.token).is_err() {
                        return None;
                    }
                    continue;
                }
                result = st.rx.recv() => match result {
                    Ok(item) => item,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        // Dropped live notifications: force a full refetch,
                        // but never disclose it after the stream's credential
                        // has ceased to be valid.
                        if st.identity.verify_manage(&st.token).is_err() {
                            return None;
                        }
                        let id = format!("{}:{}", st.epoch, st.delivered_head);
                        let sse = Event::default()
                            .id(id)
                            .json_data(&ManageEvent::Resync)
                            .ok()?;
                        return Some((Ok(sse), st));
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
                },
            };
            // Skip anything the replay backlog already covered.
            if item.seq <= st.delivered_head {
                continue;
            }
            if st.identity.verify_manage(&st.token).is_err() {
                return None;
            }
            st.delivered_head = item.seq;
            let sse = Event::default()
                .id(format!("{}:{}", st.epoch, item.seq))
                .json_data(&item.event)
                .ok()?;
            return Some((Ok(sse), st));
        }
    });
    (
        response_headers,
        Sse::new(stream).keep_alive(KeepAlive::default()),
    )
        .into_response()
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

/* -------------------------- 1Password provider -------------------------- */

async fn list_onepassword_integrations(
    State(state): State<AppState>,
    _authed: ManageAuthed,
) -> Response {
    respond(state.manage.list_onepassword_integrations().await)
}

async fn add_onepassword_integration(
    State(state): State<AppState>,
    _authed: ManageAuthed,
    ApiJson(body): ApiJson<OnePasswordIntegrationAddBody>,
) -> Response {
    let (auth, token) = body.authentication.into_parts();
    respond(
        state
            .manage
            .add_onepassword_integration(body.label, auth, token)
            .await,
    )
}

async fn replace_onepassword_token(
    State(state): State<AppState>,
    _authed: ManageAuthed,
    Path(id): Path<Uuid>,
    ApiJson(body): ApiJson<OnePasswordTokenBody>,
) -> Response {
    respond(
        state
            .manage
            .replace_onepassword_token(id, Zeroizing::new(body.token))
            .await,
    )
}

async fn delete_onepassword_integration(
    State(state): State<AppState>,
    _authed: ManageAuthed,
    Path(id): Path<Uuid>,
) -> Response {
    respond(state.manage.delete_onepassword_integration(id).await)
}

async fn onepassword_health(
    State(state): State<AppState>,
    _authed: ManageAuthed,
    Path(id): Path<Uuid>,
) -> Response {
    respond(state.manage.onepassword_health(id).await)
}

async fn onepassword_vaults(
    State(state): State<AppState>,
    _authed: ManageAuthed,
    Path(id): Path<Uuid>,
) -> Response {
    respond(state.manage.onepassword_vaults(id).await)
}

async fn onepassword_items(
    State(state): State<AppState>,
    _authed: ManageAuthed,
    Path((id, vault_id)): Path<(Uuid, String)>,
) -> Response {
    respond(state.manage.onepassword_items(id, vault_id).await)
}

async fn onepassword_fields(
    State(state): State<AppState>,
    _authed: ManageAuthed,
    Path((id, vault_id, item_id)): Path<(Uuid, String, String)>,
) -> Response {
    respond(state.manage.onepassword_fields(id, vault_id, item_id).await)
}

async fn add_onepassword_secret(
    State(state): State<AppState>,
    _authed: ManageAuthed,
    ApiJson(body): ApiJson<OnePasswordSecretAddBody>,
) -> Response {
    let (name, reference) = body.into_reference();
    respond(state.manage.add_onepassword_secret(name, reference).await)
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
    respond(
        state
            .manage
            .update_connection(id, body.expected_updated_at, body.spec)
            .await,
    )
}

async fn rename_connection(
    State(state): State<AppState>,
    _authed: ManageAuthed,
    Path(id): Path<Uuid>,
    ApiJson(body): ApiJson<ConnectionRenameBody>,
) -> Response {
    respond(
        state
            .manage
            .rename_connection(id, body.expected_updated_at, body.name)
            .await,
    )
}

async fn patch_connection(
    State(state): State<AppState>,
    _authed: ManageAuthed,
    Path(id): Path<Uuid>,
    ApiJson(body): ApiJson<ConnectionConfigPatchBody>,
) -> Response {
    respond(
        state
            .manage
            .patch_connection(id, body.expected_updated_at, body.patch)
            .await,
    )
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

async fn set_confirm_mode(
    State(state): State<AppState>,
    _authed: ManageAuthed,
    Path(id): Path<Uuid>,
    ApiJson(body): ApiJson<ConfirmBody>,
) -> Response {
    respond(
        state
            .manage
            .set_confirm_mode(id, body.on)
            .await
            .map(|changed| json!({ "changed": changed })),
    )
}

async fn set_expose_response_credentials(
    State(state): State<AppState>,
    _authed: ManageAuthed,
    Path(id): Path<Uuid>,
    ApiJson(body): ApiJson<ResponseCredentialsBody>,
) -> Response {
    respond(
        state
            .manage
            .set_expose_response_credentials(id, body.expose)
            .await
            .map(|changed| json!({ "changed": changed })),
    )
}

async fn approvals(State(state): State<AppState>, _authed: ManageAuthed) -> Response {
    respond(state.manage.approvals().await)
}

async fn approval_snapshot(State(state): State<AppState>, _authed: ManageAuthed) -> Response {
    // Capture the bus head first. A mutation racing the following queue read
    // can make the data newer than its version (safe and self-correcting),
    // but can never label stale data with a newer version.
    let version = format!(
        "{}:{}",
        state.broker.manage_bus().epoch(),
        state.broker.manage_bus().head_seq()
    );
    let result = match state.manage.approvals().await {
        Ok(approvals) => {
            state
                .manage
                .elicitations()
                .await
                .map(|elicitations| aka_api::ApprovalSnapshotDto {
                    version,
                    approvals,
                    elicitations,
                })
        }
        Err(error) => Err(error),
    };
    respond(result)
}

async fn elicitations(State(state): State<AppState>, _authed: ManageAuthed) -> Response {
    respond(state.manage.elicitations().await)
}

async fn respond_elicitation(
    State(state): State<AppState>,
    _authed: ManageAuthed,
    Path(id): Path<Uuid>,
    ApiJson(body): ApiJson<ElicitationResponseBody>,
) -> Response {
    respond(
        state
            .manage
            .respond_elicitation(id, body.approved, body.values)
            .await
            .map(|answered| json!({ "answered": answered })),
    )
}

async fn requests(State(state): State<AppState>, _authed: ManageAuthed) -> Response {
    respond(state.manage.requests().await)
}

async fn respond_approval(
    State(state): State<AppState>,
    _authed: ManageAuthed,
    Path(id): Path<Uuid>,
    ApiJson(body): ApiJson<ApprovalResponseBody>,
) -> Response {
    respond(
        state
            .manage
            .respond_approval(id, body.decision)
            .await
            .map(|answered| json!({ "answered": answered })),
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

async fn set_audit_statements(
    State(state): State<AppState>,
    _authed: ManageAuthed,
    Path(id): Path<Uuid>,
    ApiJson(body): ApiJson<AuditStatementsBody>,
) -> Response {
    respond(
        state
            .manage
            .set_audit_statements(id, body.audit_statements)
            .await
            .map(|changed| json!({ "changed": changed })),
    )
}

async fn set_endpoint_require_auth(
    State(state): State<AppState>,
    _authed: ManageAuthed,
    Path(id): Path<Uuid>,
    ApiJson(body): ApiJson<EndpointRequireAuthBody>,
) -> Response {
    respond(
        state
            .manage
            .set_endpoint_require_auth(id, body.require_auth)
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

async fn renew_endpoint(
    State(state): State<AppState>,
    _authed: ManageAuthed,
    Path(id): Path<Uuid>,
) -> Response {
    respond(state.manage.renew_endpoint(id).await)
}

async fn set_endpoint_expiry(
    State(state): State<AppState>,
    _authed: ManageAuthed,
    Path(id): Path<Uuid>,
    ApiJson(body): ApiJson<EndpointExpiryBody>,
) -> Response {
    respond(state.manage.set_endpoint_expiry(id, body.expire).await)
}

async fn get_endpoint(
    State(state): State<AppState>,
    _authed: ManageAuthed,
    Path(id): Path<Uuid>,
) -> Response {
    respond(state.manage.get_endpoint(id).await)
}

async fn copy_endpoint(
    State(state): State<AppState>,
    _authed: ManageAuthed,
    Path(id): Path<Uuid>,
) -> Response {
    respond(state.manage.copy_endpoint(id).await)
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
            .ui_mcp_auth_deliver_code(&id, body.code, body.state, body.iss)
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

#[derive(serde::Deserialize)]
struct ActivityPageQuery {
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    before: Option<u64>,
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

async fn activity_page(
    State(state): State<AppState>,
    _authed: ManageAuthed,
    Query(query): Query<ActivityPageQuery>,
) -> Response {
    let limit = query
        .limit
        .unwrap_or(ACTIVITY_VIEW_LIMIT)
        .min(ACTIVITY_VIEW_LIMIT);
    respond(state.manage.activity_page(limit, query.before).await)
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
    if let Some(on) = body.menu_bar_hides_dock {
        if let Err(error) = state.manage.set_menu_bar_hides_dock(on).await {
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
