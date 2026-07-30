//! Silent renewal of MCP OAuth access tokens.
//!
//! Sign-in (`mcp_auth`) stores a refresh grant next to each OAuth-minted
//! connection: the refresh token, the registered client identity, and the
//! token endpoint, in a vault item of their own. This module spends that
//! grant so an expiring access token never becomes user-visible friction:
//!
//! - a background sweeper renews tokens shortly before they expire,
//! - every credential *use* (a brokered agent call, a connection test, the
//!   status check) renews first when the token is at expiry, and
//! - the status check renews-and-retries once on an upstream 401/403,
//!   instead of telling the user to reconnect.
//!
//! Renewals are serialized per connection: providers may rotate the
//! refresh token on use, so two concurrent renewals would spend it twice
//! and kill the grant. Whoever waits re-reads the connection under the
//! lock and finds the work already done.
//!
//! The refresh token leaves the process only toward the grant's own pinned
//! token endpoint (https, or loopback for tests), mirroring how access
//! tokens ride only the upstream leg. A refresh the provider *rejects*
//! permanently retires the stored refresh token — the next recovery is the
//! Reconnect sign-in — while network trouble is retried with backoff.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde_json::Value;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::audit::{AuditEntry, AuditKind, AuditLog};
use crate::broker::Broker;
use crate::health::HealthRegistry;
use crate::mcp_auth::{is_loopback_host, parse_token_payload, McpOAuthGrant};
use crate::store::Store;
use crate::types::{Connection, HealthStatus};

/// Renew when the access token is within this window of expiry.
pub(crate) const REFRESH_SKEW: chrono::Duration = chrono::Duration::minutes(5);
/// How often the sweeper looks for tokens entering the skew window.
const SWEEP_INTERVAL: Duration = Duration::from_secs(60);
/// Wait between attempts after a transient (network-ish) failure.
const RETRY_BACKOFF: chrono::Duration = chrono::Duration::minutes(5);
/// One refresh round-trip may take this long.
const REFRESH_TIMEOUT: Duration = Duration::from_secs(20);

/// What one renewal needs from its caller. Every credential-using path can
/// build one (the broker, an HTTP execution) without dragging the whole
/// broker along.
pub(crate) struct RefreshContext<'a> {
    pub store: &'a Store,
    pub http: &'a reqwest::Client,
    pub audit: &'a AuditLog,
    /// When present, a rejected renewal records needs-reconnect health.
    pub health: Option<&'a HealthRegistry>,
}

impl Broker {
    pub(crate) fn refresh_context(&self) -> RefreshContext<'_> {
        RefreshContext {
            store: self.store.as_ref(),
            http: &self.http_client,
            audit: self.audit.as_ref(),
            health: Some(self.health.as_ref()),
        }
    }
}

/// Why the caller wants a renewal; decides what counts as already done.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RefreshMode {
    /// Renew only when the token is at/near expiry (sweeper, pre-use).
    IfStale,
    /// The upstream just rejected the token: renew even if the stored
    /// expiry claims it is fine — unless another path replaced the token
    /// while this caller waited, in which case that renewal is the answer.
    Force,
}

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

/// When the connection's bound token secret last changed — the "version"
/// concurrent renewals compare to avoid spending the refresh token twice.
fn bound_token_version(ctx: &RefreshContext<'_>, connection_id: &Uuid) -> Option<DateTime<Utc>> {
    let connection = ctx.store.connection_by_id(connection_id).ok()?;
    let secret_id = connection.secrets.first()?;
    Some(ctx.store.secret_by_id(secret_id).ok()?.updated_at)
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

/// Best-effort pre-use renewal: called before a credential rides the
/// upstream leg, so agent calls and tests never present a token the broker
/// already knew was expired. Failures fall through silently — the current
/// token is rendered as-is and the upstream's verdict (and health
/// bookkeeping) tells the rest of the story.
pub(crate) async fn ensure_fresh(ctx: &RefreshContext<'_>, connection: &Connection) {
    if !wants_refresh(connection) {
        return;
    }
    let _ = refresh_connection_token(ctx, &connection.id, RefreshMode::IfStale).await;
}

/// One process-wide async lock per connection. The broker instance lock
/// guarantees a single broker per state dir, so process-wide is
/// grant-wide.
pub(crate) fn connection_lock(id: &Uuid) -> Arc<tokio::sync::Mutex<()>> {
    static LOCKS: OnceLock<Mutex<HashMap<Uuid, Arc<tokio::sync::Mutex<()>>>>> = OnceLock::new();
    LOCKS
        .get_or_init(Default::default)
        .lock()
        .unwrap()
        .entry(*id)
        .or_default()
        .clone()
}

/// Renew a connection's access token with its stored refresh grant: trade
/// the refresh token at the grant's token endpoint, replace the vault-held
/// access token, and persist the (possibly rotated) grant and new expiry.
///
/// Serialized per connection; the connection is re-read under the lock so
/// a caller that waited behind a successful renewal sees it and returns
/// `Ok` without spending the rotated refresh token again.
pub(crate) async fn refresh_connection_token(
    ctx: &RefreshContext<'_>,
    connection_id: &Uuid,
    mode: RefreshMode,
) -> Result<(), RefreshError> {
    // The token version the caller acted on: if it changes while we wait
    // for the lock, another path already renewed and this 401 is stale.
    let observed = bound_token_version(ctx, connection_id);
    let lock = connection_lock(connection_id);
    let _guard = lock.lock().await;
    let connection = ctx
        .store
        .connection_by_id(connection_id)
        .map_err(|_| RefreshError::NotRefreshable("the connection no longer exists".into()))?;
    match mode {
        RefreshMode::IfStale => {
            if !wants_refresh(&connection) {
                return Ok(());
            }
        }
        RefreshMode::Force => {
            if observed.is_some() && bound_token_version(ctx, connection_id) != observed {
                return Ok(());
            }
        }
    }

    let outcome = try_refresh(ctx, &connection).await;
    match &outcome {
        Ok(()) => {
            ctx.audit.append(
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
            ctx.audit.append(
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
        retire_refresh_token(ctx, &connection).await;
        // Passive signal: the row can say "reconnect" before anyone runs a
        // check by hand.
        if let Some(health) = ctx.health {
            health.record(
                &connection.id,
                HealthStatus::NeedsReconnect,
                "The provider refused the token renewal; reconnect this tool",
            );
        }
    }
    outcome
}

async fn try_refresh(
    ctx: &RefreshContext<'_>,
    connection: &Connection,
) -> Result<(), RefreshError> {
    let grant = read_grant(ctx, connection).await?;
    let Some(refresh_token) = grant.refresh_token.clone() else {
        return Err(RefreshError::NotRefreshable(
            "the provider granted no refresh token".into(),
        ));
    };
    let secret_id = *connection.secrets.first().ok_or_else(|| {
        RefreshError::NotRefreshable("the connection has no bound token to replace".into())
    })?;
    let endpoint = secure_token_endpoint(&grant.token_endpoint)?;
    let http = crate::capability::http::client_for_connection(ctx.http, connection)
        .map_err(|error| RefreshError::Transient(format!("trusted CA: {error}")))?;

    let mut form: Vec<(&str, &str)> = vec![
        ("grant_type", "refresh_token"),
        ("refresh_token", &refresh_token),
        ("client_id", &grant.client_id),
        ("resource", &grant.resource),
    ];
    if let Some(secret) = grant.client_secret.as_deref() {
        form.push(("client_secret", secret));
    }
    let request = http
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

    ctx.store
        .replace_secret_value(&secret_id, Zeroizing::new(tokens.access_token.to_string()))
        .map_err(|error| {
            RefreshError::Transient(format!("could not store the renewed token: {error}"))
        })?;
    // Providers may rotate the refresh token; keep the old one when they
    // answer without one.
    let renewed = grant.with_refresh_token(
        tokens
            .refresh_token
            .as_ref()
            .map(|token| token.to_string())
            .or(Some(refresh_token)),
    );
    let expires_at = tokens
        .expires_in
        .and_then(|seconds| i64::try_from(seconds).ok())
        .map(|seconds| Utc::now() + chrono::Duration::seconds(seconds));
    ctx.store
        .set_connection_oauth(&connection.id, renewed.to_secret_value(), expires_at)
        .map_err(|error| {
            RefreshError::Transient(format!("could not store the renewed grant: {error}"))
        })?;
    Ok(())
}

async fn read_grant(
    ctx: &RefreshContext<'_>,
    connection: &Connection,
) -> Result<McpOAuthGrant, RefreshError> {
    if connection.oauth.is_none() {
        return Err(RefreshError::NotRefreshable(
            "this connection was not added by sign-in".into(),
        ));
    }
    let stored = ctx
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

async fn retire_refresh_token(ctx: &RefreshContext<'_>, connection: &Connection) {
    let Ok(grant) = read_grant(ctx, connection).await else {
        return;
    };
    let expires_at = connection.oauth.as_ref().and_then(|oauth| oauth.expires_at);
    let retired = grant.with_refresh_token(None);
    if let Err(error) =
        ctx.store
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
                // BYO-OAuth (`Api { oauth: Some(_) }`) keeps its token set in a
                // secret rather than in `connection.oauth`, so `wants_refresh`
                // cannot see it and these connections refreshed only when an
                // agent happened to call them. Providers that expire a refresh
                // token after N idle days therefore killed the connection
                // silently. `fresh_bearer` checks staleness itself and returns
                // the cached token untouched when there is nothing to do.
                if matches!(
                    &connection.config,
                    crate::types::ConnectionConfig::Api { oauth: Some(_), .. }
                ) {
                    if parked.contains(&(connection.id, None)) {
                        continue;
                    }
                    if retry_after.get(&connection.id).is_some_and(|at| now < *at) {
                        continue;
                    }
                    // Pre-authorized: the broker is renewing a grant it already
                    // holds, on a timer, and discards the value. A background
                    // sweep must never put a native sheet on screen.
                    let outcome = match crate::capability::http::client_for_connection(
                        &broker.http_client,
                        &connection,
                    ) {
                        Ok(http) => {
                            crate::authorization::scope(
                                true,
                                crate::oauth::fresh_bearer(&broker.store, &http, &connection),
                            )
                            .await
                        }
                        Err(error) => Err(crate::oauth::RefreshFailure::Transient(format!(
                            "trusted CA: {error}"
                        ))),
                    };
                    match outcome {
                        Ok(_) => {
                            retry_after.remove(&connection.id);
                        }
                        Err(failure) if failure.needs_reconnect() => {
                            // Only a new sign-in helps; stop asking.
                            parked.insert((connection.id, None));
                        }
                        Err(_) => {
                            retry_after.insert(connection.id, now + RETRY_BACKOFF);
                        }
                    }
                    continue;
                }
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
                match refresh_connection_token(
                    &broker.refresh_context(),
                    &connection.id,
                    RefreshMode::IfStale,
                )
                .await
                {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp_auth::McpOAuthGrant;
    use crate::store::ConnectionSpec;
    use crate::types::{ConnectionConfig, OAuthSpec};
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Events;
    impl crate::events::BrokerEvents for Events {
        fn confirm_secret_read(&self, _secret: &crate::types::SecretMeta) -> bool {
            // A background sweep must never need this: if it is reached, the
            // read was not pre-authorized and a real shell would show a sheet.
            panic!("a background refresh must not prompt for a secret read");
        }
        fn confirm_action(&self, _description: &str) -> Option<crate::types::ConfirmationMethod> {
            Some(crate::types::ConfirmationMethod::Waived)
        }
    }

    #[derive(Clone)]
    struct TokenState {
        status: axum::http::StatusCode,
        payload: Value,
        hits: Arc<AtomicUsize>,
        forms: Arc<Mutex<Vec<HashMap<String, String>>>>,
        release: Option<Arc<tokio::sync::Notify>>,
    }

    async fn token_fixture(
        status: axum::http::StatusCode,
        payload: Value,
        release: Option<Arc<tokio::sync::Notify>>,
    ) -> (
        u16,
        Arc<AtomicUsize>,
        Arc<Mutex<Vec<HashMap<String, String>>>>,
    ) {
        let hits = Arc::new(AtomicUsize::new(0));
        let forms = Arc::new(Mutex::new(Vec::new()));
        let state = TokenState {
            status,
            payload,
            hits: hits.clone(),
            forms: forms.clone(),
            release,
        };
        let app =
            axum::Router::new()
                .route(
                    "/token",
                    axum::routing::post(
                        |axum::extract::State(state): axum::extract::State<TokenState>,
                         axum::extract::Form(form): axum::extract::Form<
                            HashMap<String, String>,
                        >| async move {
                            state.hits.fetch_add(1, Ordering::SeqCst);
                            state.forms.lock().unwrap().push(form);
                            if let Some(release) = state.release {
                                release.notified().await;
                            }
                            (state.status, axum::Json(state.payload))
                        },
                    ),
                )
                .with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (port, hits, forms)
    }

    async fn managed_oauth_broker(
        token_endpoint: String,
    ) -> (Arc<Broker>, tempfile::TempDir, crate::types::Connection) {
        let dir = tempfile::tempdir().unwrap();
        let broker = Broker::new(
            crate::paths::Paths::under(dir.path()),
            Arc::new(crate::vault::MemoryVault::new()),
            crate::config::BrokerConfig::default(),
            Arc::new(Events),
        )
        .await
        .unwrap();
        broker
            .store
            .add_secret("MCP_TOKEN", Zeroizing::new("old-access".into()))
            .unwrap();
        let secret = broker.store.secret_by_name("MCP_TOKEN").unwrap();
        let connection = broker
            .store
            .add_connection(ConnectionSpec {
                name: format!("mcp-refresh-{}", Uuid::new_v4()),
                config: ConnectionConfig::Api {
                    host: "127.0.0.1".into(),
                    scheme: "http".into(),
                    port: Some(9),
                    trusted_ca_bundle_path: None,
                    template: "Authorization: Bearer {{MCP_TOKEN}}".into(),
                    mcp_path: Some("/mcp".into()),
                    oauth: None,
                },
                secrets: vec![secret.id],
            })
            .unwrap();
        let grant = McpOAuthGrant {
            refresh_token: Some("refresh-live".into()),
            client_id: "client-1".into(),
            client_secret: None,
            token_endpoint,
            resource: "http://127.0.0.1/mcp".into(),
        };
        broker
            .store
            .set_connection_oauth(
                &connection.id,
                grant.to_secret_value(),
                Some(Utc::now() - chrono::Duration::minutes(1)),
            )
            .unwrap();
        let connection = broker.store.connection_by_id(&connection.id).unwrap();
        (broker, dir, connection)
    }

    async fn force_refresh(broker: Arc<Broker>, connection_id: Uuid) -> Result<(), RefreshError> {
        crate::authorization::scope(true, async move {
            refresh_connection_token(
                &broker.refresh_context(),
                &connection_id,
                RefreshMode::Force,
            )
            .await
        })
        .await
    }

    async fn stored_grant(broker: &Broker, connection_id: Uuid) -> McpOAuthGrant {
        let raw =
            crate::authorization::scope(true, broker.store.connection_oauth_grant(&connection_id))
                .await
                .unwrap();
        McpOAuthGrant::from_secret_value(&raw).unwrap()
    }

    #[tokio::test]
    async fn concurrent_forced_refreshes_spend_the_rotating_grant_once() {
        let release = Arc::new(tokio::sync::Notify::new());
        let (port, hits, forms) = token_fixture(
            axum::http::StatusCode::OK,
            serde_json::json!({
                "access_token": "new-access",
                "refresh_token": "refresh-rotated",
                "expires_in": 3600,
            }),
            Some(release.clone()),
        )
        .await;
        let (broker, _dir, connection) =
            managed_oauth_broker(format!("http://127.0.0.1:{port}/token")).await;

        let first = tokio::spawn(force_refresh(broker.clone(), connection.id));
        for _ in 0..100 {
            if hits.load(Ordering::SeqCst) == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        let second = tokio::spawn(force_refresh(broker.clone(), connection.id));
        tokio::task::yield_now().await;
        release.notify_one();
        first.await.unwrap().unwrap();
        second.await.unwrap().unwrap();

        assert_eq!(hits.load(Ordering::SeqCst), 1);
        assert_eq!(forms.lock().unwrap()[0]["resource"], "http://127.0.0.1/mcp");
        assert_eq!(
            stored_grant(&broker, connection.id)
                .await
                .refresh_token
                .as_deref(),
            Some("refresh-rotated")
        );
    }

    #[tokio::test]
    async fn transient_refresh_failure_preserves_the_refresh_token() {
        let (port, hits, _) = token_fixture(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({ "error": "temporarily_unavailable" }),
            None,
        )
        .await;
        let (broker, _dir, connection) =
            managed_oauth_broker(format!("http://127.0.0.1:{port}/token")).await;
        assert!(matches!(
            force_refresh(broker.clone(), connection.id).await,
            Err(RefreshError::Transient(_))
        ));
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        assert_eq!(
            stored_grant(&broker, connection.id)
                .await
                .refresh_token
                .as_deref(),
            Some("refresh-live")
        );
    }

    #[tokio::test]
    async fn rejected_refresh_retires_the_refresh_token() {
        let (port, _, _) = token_fixture(
            axum::http::StatusCode::BAD_REQUEST,
            serde_json::json!({ "error": "invalid_grant" }),
            None,
        )
        .await;
        let (broker, _dir, connection) =
            managed_oauth_broker(format!("http://127.0.0.1:{port}/token")).await;
        assert!(matches!(
            force_refresh(broker.clone(), connection.id).await,
            Err(RefreshError::Rejected(_))
        ));
        assert_eq!(
            stored_grant(&broker, connection.id).await.refresh_token,
            None
        );
    }

    #[tokio::test]
    async fn non_https_non_loopback_token_endpoint_is_not_contacted() {
        let (broker, _dir, connection) =
            managed_oauth_broker("http://example.com/token".into()).await;
        assert!(matches!(
            force_refresh(broker, connection.id).await,
            Err(RefreshError::NotRefreshable(_))
        ));
    }

    /// API-19. A BYO-OAuth connection keeps its token set in a secret rather
    /// than in `connection.oauth`, so `wants_refresh` cannot see it and the
    /// sweeper skipped it entirely — these connections refreshed only when an
    /// agent happened to call one. A provider that expires refresh tokens after
    /// N idle days therefore killed the connection while the app sat open.
    #[tokio::test]
    async fn the_sweeper_renews_a_byo_oauth_connection() {
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = hits.clone();
        let app = axum::Router::new().route(
            "/token",
            axum::routing::post(move || {
                let counter = counter.clone();
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    axum::Json(serde_json::json!({
                        "access_token": "renewed_by_the_sweeper",
                        "refresh_token": "rt-2",
                        "expires_in": 3600,
                    }))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let dir = tempfile::tempdir().unwrap();
        let broker = Broker::new(
            crate::paths::Paths::under(dir.path()),
            Arc::new(crate::vault::MemoryVault::new()),
            crate::config::BrokerConfig::default(),
            Arc::new(Events),
        )
        .await
        .unwrap();

        // An access token that expired an hour ago, with a live refresh token.
        let expired = Utc::now() - chrono::Duration::hours(1);
        let tokens = serde_json::json!({
            "access_token": "stale",
            "refresh_token": "rt-1",
            "expires_at": expired.to_rfc3339(),
        });
        broker
            .store
            .add_secret("OAUTH_TOKENS", Zeroizing::new(tokens.to_string()))
            .unwrap();
        let secret = broker.store.secret_by_name("OAUTH_TOKENS").unwrap();
        broker
            .store
            .add_connection(ConnectionSpec {
                name: "slack".into(),
                config: ConnectionConfig::Api {
                    host: "127.0.0.1".into(),
                    scheme: "http".into(),
                    port: Some(port),
                    trusted_ca_bundle_path: None,
                    template: "Authorization: Bearer {{OAUTH_TOKENS}}".into(),
                    mcp_path: None,
                    oauth: Some(OAuthSpec {
                        auth_url: "http://127.0.0.1/authorize".into(),
                        token_url: format!("http://127.0.0.1:{port}/token"),
                        client_id: "client-abc".into(),
                        scopes: Vec::new(),
                        extra_auth_params: Vec::new(),
                    }),
                },
                secrets: vec![secret.id],
            })
            .unwrap();

        // The sweeper's first pass is immediate.
        spawn_refresh_sweeper(&broker);
        for _ in 0..50 {
            if hits.load(Ordering::SeqCst) > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "the sweeper must renew BYO-OAuth grants, not only MCP ones"
        );

        // And the renewed token is what a later call would present.
        let stored = crate::authorization::scope(true, broker.store.secret_value(&secret.id))
            .await
            .unwrap();
        assert!(
            stored.contains("renewed_by_the_sweeper"),
            "the renewed token must be persisted: {}",
            &*stored
        );
    }
}
