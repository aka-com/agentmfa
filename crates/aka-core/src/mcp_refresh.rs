//! Silent renewal of MCP OAuth access tokens.
//!
//! Sign-in (`mcp_auth`) stores a refresh grant next to each OAuth-minted
//! connection: the refresh token, the registered client identity, and the
//! token endpoint, in a vault item of their own. This module spends that
//! grant so an expiring access token never becomes user-visible friction:
//!
//! - a background sweeper renews tokens shortly before they expire, and
//! - the status check calls in here to renew an already-expired (or
//!   upstream-rejected) token and retry, instead of telling the user to
//!   reconnect.
//!
//! The refresh token leaves the process only toward the grant's own pinned
//! token endpoint (https, or loopback for tests), mirroring how access
//! tokens ride only the upstream leg. A refresh the provider *rejects*
//! permanently retires the stored refresh token — the next recovery is the
//! Reconnect sign-in — while network trouble is retried with backoff.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde_json::Value;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::audit::{AuditEntry, AuditKind};
use crate::broker::Broker;
use crate::mcp_auth::{is_loopback_host, parse_token_payload, McpOAuthGrant};
use crate::types::Connection;

/// Renew when the access token is within this window of expiry.
pub(crate) const REFRESH_SKEW: chrono::Duration = chrono::Duration::minutes(5);
/// How often the sweeper looks for tokens entering the skew window.
const SWEEP_INTERVAL: Duration = Duration::from_secs(60);
/// Wait between attempts after a transient (network-ish) failure.
const RETRY_BACKOFF: chrono::Duration = chrono::Duration::minutes(5);
/// One refresh round-trip may take this long.
const REFRESH_TIMEOUT: Duration = Duration::from_secs(20);

/// Why a refresh did not happen. The distinction drives retry policy.
#[derive(Debug)]
pub(crate) enum RefreshError {
    /// No grant, no refresh token in it, or a malformed record: only a new
    /// sign-in can help, so never retry on a timer.
    NotRefreshable(String),
    /// The provider refused the refresh token (it is spent or revoked).
    /// The stored token is retired; Reconnect is the recovery.
    Rejected(String),
    /// Network or server trouble; worth retrying later.
    Transient(String),
}

impl RefreshError {
    fn message(&self) -> &str {
        match self {
            RefreshError::NotRefreshable(message)
            | RefreshError::Rejected(message)
            | RefreshError::Transient(message) => message,
        }
    }
}

/// Whether this connection's access token is (about to be) expired,
/// making a pre-emptive refresh worthwhile.
pub(crate) fn wants_refresh(connection: &Connection) -> bool {
    connection
        .oauth
        .as_ref()
        .and_then(|oauth| oauth.expires_at)
        .is_some_and(|at| Utc::now() + REFRESH_SKEW >= at)
}

/// Renew a connection's access token with its stored refresh grant: trade
/// the refresh token at the grant's token endpoint, replace the vault-held
/// access token, and persist the (possibly rotated) grant and new expiry.
pub(crate) async fn refresh_connection_token(
    broker: &Broker,
    connection: &Connection,
) -> Result<(), RefreshError> {
    let outcome = try_refresh(broker, connection).await;
    match &outcome {
        Ok(()) => {
            broker.audit.append(
                AuditEntry::new(
                    AuditKind::McpTokenRefreshed,
                    format!("MCP access token renewed: {}", connection.name),
                )
                .connection(connection.name.clone())
                .detail("Renewed silently with the stored refresh token"),
            );
        }
        Err(RefreshError::NotRefreshable(_)) => {
            // Nothing was attempted; nothing to log. The status check's
            // Reconnect path narrates the user-visible consequence.
        }
        Err(error) => {
            broker.audit.append(
                AuditEntry::new(
                    AuditKind::McpTokenRefreshFailed,
                    format!("MCP access token renewal failed: {}", connection.name),
                )
                .connection(connection.name.clone())
                .detail(error.message().to_string()),
            );
        }
    }
    if let Err(RefreshError::Rejected(_)) = &outcome {
        // The refresh token is spent; retire it so neither the sweeper nor
        // the status check keeps replaying a grant the provider refused.
        retire_refresh_token(broker, connection).await;
    }
    outcome
}

async fn try_refresh(broker: &Broker, connection: &Connection) -> Result<(), RefreshError> {
    let grant = read_grant(broker, connection).await?;
    let Some(refresh_token) = grant.refresh_token.clone() else {
        return Err(RefreshError::NotRefreshable(
            "the provider granted no refresh token".into(),
        ));
    };
    let secret_id = *connection.secrets.first().ok_or_else(|| {
        RefreshError::NotRefreshable("the connection has no bound token to replace".into())
    })?;
    let endpoint = secure_token_endpoint(&grant.token_endpoint)?;

    let mut form: Vec<(&str, &str)> = vec![
        ("grant_type", "refresh_token"),
        ("refresh_token", &refresh_token),
        ("client_id", &grant.client_id),
        ("resource", &grant.resource),
    ];
    if let Some(secret) = grant.client_secret.as_deref() {
        form.push(("client_secret", secret));
    }
    let request = broker
        .http_client
        .post(endpoint)
        .timeout(REFRESH_TIMEOUT)
        .header(http::header::ACCEPT, "application/json")
        .form(&form)
        .send();
    let response = match tokio::time::timeout(REFRESH_TIMEOUT, request).await {
        Ok(Ok(response)) => response,
        Ok(Err(error)) => {
            return Err(RefreshError::Transient(format!(
                "token refresh failed: {}",
                error.without_url()
            )))
        }
        Err(_) => {
            return Err(RefreshError::Transient(format!(
                "the token endpoint did not answer within {} seconds",
                REFRESH_TIMEOUT.as_secs()
            )))
        }
    };
    let status = response.status();
    let payload: Value = response.json().await.unwrap_or(Value::Null);
    if !status.is_success() {
        let detail = payload
            .get("error_description")
            .or_else(|| payload.get("error"))
            .and_then(Value::as_str)
            .unwrap_or("no detail");
        let message = format!("the token endpoint refused the refresh (HTTP {status}: {detail})");
        // 4xx means the grant itself is bad (invalid_grant, revoked client):
        // replaying it cannot succeed. Anything else may be a passing outage.
        return Err(if status.is_client_error() {
            RefreshError::Rejected(message)
        } else {
            RefreshError::Transient(message)
        });
    }
    let tokens = parse_token_payload(&payload).map_err(RefreshError::Rejected)?;

    broker
        .store
        .replace_secret_value(&secret_id, Zeroizing::new(tokens.access_token.to_string()))
        .map_err(|error| {
            RefreshError::Transient(format!("could not store the renewed token: {error}"))
        })?;
    // Providers may rotate the refresh token; keep the old one when they
    // answer without one.
    let renewed = McpOAuthGrant {
        refresh_token: tokens
            .refresh_token
            .as_ref()
            .map(|token| token.to_string())
            .or(Some(refresh_token)),
        ..grant
    };
    let expires_at = tokens
        .expires_in
        .and_then(|seconds| i64::try_from(seconds).ok())
        .map(|seconds| Utc::now() + chrono::Duration::seconds(seconds));
    broker
        .store
        .set_connection_oauth(&connection.id, renewed.to_secret_value(), expires_at)
        .map_err(|error| {
            RefreshError::Transient(format!("could not store the renewed grant: {error}"))
        })?;
    Ok(())
}

async fn read_grant(
    broker: &Broker,
    connection: &Connection,
) -> Result<McpOAuthGrant, RefreshError> {
    if connection.oauth.is_none() {
        return Err(RefreshError::NotRefreshable(
            "this connection was not added by sign-in".into(),
        ));
    }
    let stored = broker
        .store
        .connection_oauth_grant(&connection.id)
        .await
        .map_err(|error| {
            RefreshError::Transient(format!("could not read the refresh grant: {error}"))
        })?;
    McpOAuthGrant::from_secret_value(&stored).map_err(RefreshError::NotRefreshable)
}

fn secure_token_endpoint(raw: &str) -> Result<url::Url, RefreshError> {
    let url = url::Url::parse(raw)
        .map_err(|_| RefreshError::NotRefreshable("the stored token endpoint is invalid".into()))?;
    let host = url.host_str().unwrap_or("");
    if url.scheme() == "https" || (url.scheme() == "http" && is_loopback_host(host)) {
        return Ok(url);
    }
    Err(RefreshError::NotRefreshable(format!(
        "the stored token endpoint is not https ({url})"
    )))
}

async fn retire_refresh_token(broker: &Broker, connection: &Connection) {
    let Ok(grant) = read_grant(broker, connection).await else {
        return;
    };
    let expires_at = connection.oauth.as_ref().and_then(|oauth| oauth.expires_at);
    let retired = McpOAuthGrant {
        refresh_token: None,
        ..grant
    };
    if let Err(error) =
        broker
            .store
            .set_connection_oauth(&connection.id, retired.to_secret_value(), expires_at)
    {
        tracing::warn!(
            "could not retire the rejected refresh token for {}: {error}",
            connection.name
        );
    }
}

/// Background sweeper: renew every OAuth connection's access token as it
/// enters the expiry window, so agents and status checks keep working
/// without anyone noticing the token ever aged. Holds only a weak broker
/// reference and dies with it.
pub(crate) fn spawn_refresh_sweeper(broker: &Arc<Broker>) {
    let weak = Arc::downgrade(broker);
    tokio::spawn(async move {
        // A connection the refresh gave up on (no refresh token, or the
        // provider rejected it) stays parked until a new sign-in changes
        // its expiry; transient failures back off instead.
        let mut parked: HashSet<(Uuid, Option<DateTime<Utc>>)> = HashSet::new();
        let mut retry_after: HashMap<Uuid, DateTime<Utc>> = HashMap::new();
        // Sweep immediately: a token that expired while the app was closed
        // should be fresh again before the first agent call, not a minute in.
        loop {
            let Some(broker) = weak.upgrade() else { return };
            let now = Utc::now();
            for connection in broker.store.list_connections() {
                if !wants_refresh(&connection) {
                    continue;
                }
                let expires_at = connection.oauth.as_ref().and_then(|oauth| oauth.expires_at);
                if parked.contains(&(connection.id, expires_at)) {
                    continue;
                }
                if retry_after.get(&connection.id).is_some_and(|at| now < *at) {
                    continue;
                }
                match refresh_connection_token(&broker, &connection).await {
                    Ok(()) => {
                        retry_after.remove(&connection.id);
                    }
                    Err(RefreshError::Transient(_)) => {
                        retry_after.insert(connection.id, now + RETRY_BACKOFF);
                    }
                    Err(_) => {
                        parked.insert((connection.id, expires_at));
                    }
                }
            }
            drop(broker);
            tokio::time::sleep(SWEEP_INTERVAL).await;
        }
    });
}
