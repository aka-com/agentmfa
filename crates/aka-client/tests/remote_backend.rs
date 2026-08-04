//! Parity tests: the remote backend against a real broker serving TCP —
//! the exact stack a hosted deployment runs.

use std::sync::Arc;

use aka_api::{ManageError, ManageEvent};
use aka_client::{events::LinkState, RemoteBackend, RemoteConfig};
use aka_core::broker::Broker;
use aka_core::config::BrokerConfig;
use aka_core::daemon::{self, ServeOptions};
use aka_core::events::BrokerEvents;
use aka_core::manage::ManagementBackend as _;
use aka_core::paths::Paths;
use aka_core::store::ConnectionSpec;
use aka_core::types::ConnectionConfig;
use aka_core::vault::MemoryVault;
use zeroize::Zeroizing;

struct TestEvents;

impl BrokerEvents for TestEvents {}

struct Harness {
    _broker: Arc<Broker>,
    _daemon: daemon::DaemonHandle,
    backend: Arc<RemoteBackend>,
    base: String,
    _dir: tempfile::TempDir,
}

async fn harness() -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let broker = Broker::new(
        Paths::under(dir.path()),
        Arc::new(MemoryVault::new()),
        BrokerConfig::default(),
        Arc::new(TestEvents),
    )
    .await
    .unwrap();
    let token = broker.identity.issue_manage_token().await.unwrap();
    let handle = daemon::serve_with(
        broker.clone(),
        ServeOptions {
            listen: Some("127.0.0.1:0".parse().unwrap()),
            public_url: None,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let base = format!("http://{}", handle.tcp_addr.unwrap());
    let backend = Arc::new(RemoteBackend::new(
        RemoteConfig::new(&base, &token).unwrap(),
    ));
    Harness {
        _broker: broker,
        _daemon: handle,
        backend,
        base,
        _dir: dir,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn polling_request_surface_lease_works_through_remote_backend() {
    let h = harness().await;
    let surface = h.backend.open_approval_surface().await.unwrap();
    let id = surface.id.parse().unwrap();
    assert_eq!(surface.expires_in_ms, aka_api::APPROVAL_SURFACE_TTL_MS);
    h.backend.renew_approval_surface(id).await.unwrap();
    assert!(h.backend.close_approval_surface(id).await.unwrap());
    assert!(!h.backend.close_approval_surface(id).await.unwrap());
}

fn api_spec(name: &str, template: &str) -> ConnectionSpec {
    ConnectionSpec {
        name: name.into(),
        config: ConnectionConfig::Api {
            host: "api.github.com".into(),
            scheme: "https".into(),
            port: None,
            trusted_ca_bundle_path: None,
            template: template.into(),
            mcp_path: None,
            test_path: None,
            oauth: None,
            signer: None,
            client_cert_path: None,
            client_key_path: None,
        },
        secrets: vec![],
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_remote_backend_manages_a_tcp_broker_end_to_end() {
    let h = harness().await;
    let backend = &h.backend;

    backend.whoami().await.unwrap();
    backend
        .add_secret("GITHUB_KEY".into(), Zeroizing::new("ghp_remote".into()))
        .await
        .unwrap();
    backend
        .add_connection(api_spec("github", "Authorization: Bearer {{GITHUB_KEY}}"))
        .await
        .unwrap();

    let connections = backend.list_connections().await.unwrap();
    assert_eq!(connections.len(), 1);
    assert_eq!(connections[0].secret_names, vec!["GITHUB_KEY".to_string()]);
    let id = connections[0].id.parse().unwrap();

    assert!(backend.set_tool_access(id, false).await.unwrap());
    assert!(
        !backend.list_connections().await.unwrap()[0]
            .agent_access
            .enabled
    );

    // Structured errors survive the wire.
    let error = backend
        .add_secret("GITHUB_KEY".into(), Zeroizing::new("again".into()))
        .await
        .unwrap_err();
    assert_eq!(
        error,
        ManageError::SecretNameTaken {
            name: "GITHUB_KEY".into()
        }
    );

    // Value copy releases the plaintext (audited broker-side).
    let secrets = backend.list_secrets().await.unwrap();
    let secret_id = secrets[0].id.parse().unwrap();
    let value = backend.secret_value_for_copy(secret_id).await.unwrap();
    assert_eq!(value.as_str(), "ghp_remote");

    let key = backend.agent_key().await.unwrap();
    assert!(key.starts_with("aka_"));

    // Settings round-trip: read, patch, and read back over the wire, so a
    // broken `patch_settings` cannot pass on the read path alone.
    backend.set_menu_bar_hides_dock(true).await.unwrap();
    let settings = backend.settings().await.unwrap();
    assert!(settings.menu_bar_hides_dock);
    // One patch must not disturb the fields it did not name.
    assert!(!settings.confirm_ssh_host_keys);

    let snapshot = backend.approval_snapshot().await.unwrap();
    assert!(snapshot.approvals.is_empty());
    assert!(snapshot.elicitations.is_empty());
    assert!(snapshot.version.split_once(':').is_some());

    assert!(!backend.activity(50).await.unwrap().is_empty());
    let activity_page = backend.activity_page(1, None).await.unwrap();
    assert_eq!(activity_page.entries.len(), 1);

    // BYO OAuth relays now; reconnecting a non-OAuth connection is the
    // structured config error, not a transport failure.
    let error = backend.oauth_reconnect(id).await.unwrap_err();
    assert!(matches!(error, ManageError::InvalidConnectionConfig { .. }));
}

#[tokio::test(flavor = "multi_thread")]
async fn stale_connection_replacements_are_rejected_without_losing_the_newer_edit() {
    let h = harness().await;
    let backend = &h.backend;
    backend
        .add_connection(api_spec("github", ""))
        .await
        .unwrap();

    let stale = backend.list_connections().await.unwrap().remove(0);
    let id = stale.id.parse().unwrap();
    backend
        .update_connection(
            id,
            stale.updated_at.clone(),
            api_spec("github from app", ""),
        )
        .await
        .unwrap();

    let current = backend.list_connections().await.unwrap().remove(0);
    assert_ne!(
        current.updated_at, stale.updated_at,
        "every edit must advance the optimistic-lock version"
    );
    let error = backend
        .update_connection(id, stale.updated_at, api_spec("github from stale cli", ""))
        .await
        .unwrap_err();
    assert_eq!(error, ManageError::ConnectionChanged);

    let preserved = backend.list_connections().await.unwrap().remove(0);
    assert_eq!(preserved.name, "github from app");
    assert_eq!(preserved.updated_at, current.updated_at);
}

#[tokio::test(flavor = "multi_thread")]
async fn bad_tokens_and_dead_brokers_map_to_distinct_errors() {
    let h = harness().await;

    let wrong = RemoteBackend::new(
        RemoteConfig::new(&h.base, "akamgr_00000000000000000000000000000000").unwrap(),
    );
    assert_eq!(
        wrong.list_secrets().await.unwrap_err(),
        ManageError::InvalidManageToken {
            detail: Some(
                "manage routes require this broker's management token (issue one on the broker \
                 host with `multitool manage token`)"
                    .into()
            )
        }
    );

    let dead = RemoteBackend::new(RemoteConfig::new("http://127.0.0.1:9", "akamgr_x").unwrap());
    assert!(matches!(
        dead.list_secrets().await.unwrap_err(),
        ManageError::Unreachable { .. }
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn management_bearers_are_never_replayed_across_redirects() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let followed = Arc::new(AtomicUsize::new(0));
    let followed_for_route = followed.clone();
    let target_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = format!("http://{}/stolen", target_listener.local_addr().unwrap());
    let target_app = axum::Router::new().route(
        "/stolen",
        axum::routing::any(move || {
            let followed = followed_for_route.clone();
            async move {
                followed.fetch_add(1, Ordering::SeqCst);
                axum::Json(serde_json::json!({"ok": true}))
            }
        }),
    );
    tokio::spawn(async move {
        axum::serve(target_listener, target_app).await.unwrap();
    });

    let redirect_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_for_route = target.clone();
    let redirect_app = axum::Router::new().route(
        "/v1/manage/whoami",
        axum::routing::get(move || {
            let target = target_for_route.clone();
            async move {
                (
                    axum::http::StatusCode::TEMPORARY_REDIRECT,
                    [(axum::http::header::LOCATION, target)],
                )
            }
        }),
    );
    let redirect_base = format!("http://{}", redirect_listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(redirect_listener, redirect_app).await.unwrap();
    });

    let backend =
        RemoteBackend::new(RemoteConfig::new(&redirect_base, "akamgr_redirect_test").unwrap());
    let error = backend.whoami().await.unwrap_err();
    assert!(
        matches!(
            error,
            ManageError::Unreachable { ref message }
                if message.contains(&target) && message.contains("final origin")
        ),
        "{error:?}"
    );
    assert_eq!(
        followed.load(Ordering::SeqCst),
        0,
        "the redirect target must never receive the management bearer"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn byo_oauth_relays_through_the_client_loopback() {
    let h = harness().await;

    // A stub provider: only the token endpoint is ever dialed (by the
    // broker); the authorize page is "visited" by this test acting as the
    // browser. Loopback http is allowed for exactly this kind of harness.
    let provider = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let provider_port = provider.local_addr().unwrap().port();
    let app = axum::Router::new().route(
        "/token",
        axum::routing::post(|body: String| async move {
            assert!(body.contains("grant_type=authorization_code"), "{body}");
            assert!(body.contains("code=test-code"), "{body}");
            assert!(body.contains("code_verifier="), "{body}");
            axum::Json(serde_json::json!({
                "access_token": "at-relayed",
                "refresh_token": "rt-relayed",
                "expires_in": 3600,
            }))
        }),
    );
    tokio::spawn(async move {
        axum::serve(provider, app).await.unwrap();
    });

    // The opener stands in for the user's browser: capture the consent URL.
    let (url_tx, mut url_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let backend = RemoteBackend::new(
        RemoteConfig::new(&h.base, h.backend.config().expect("http backend").token()).unwrap(),
    )
    .with_opener(std::sync::Arc::new(move |url: &str| {
        let _ = url_tx.send(url.to_string());
        true
    }));

    // "The browser": follow the consent page's redirect back to the
    // client-side catcher with a code and the flow's state.
    let browser = tokio::spawn(async move {
        let authorize_url = url_rx.recv().await.expect("consent URL opened");
        let parsed = url::Url::parse(&authorize_url).unwrap();
        let pairs: std::collections::HashMap<_, _> = parsed.query_pairs().into_owned().collect();
        let redirect = format!(
            "{}?code=test-code&state={}",
            pairs["redirect_uri"], pairs["state"]
        );
        assert!(pairs["redirect_uri"].starts_with("http://127.0.0.1:"));
        let response = reqwest::get(redirect).await.unwrap();
        assert_eq!(response.status().as_u16(), 200);
    });

    let spec = ConnectionSpec {
        name: "github-oauth".into(),
        config: ConnectionConfig::Api {
            host: "api.github.com".into(),
            scheme: "https".into(),
            port: None,
            trusted_ca_bundle_path: None,
            template: "Authorization: Bearer {{GH_OAUTH_TOKEN}}".into(),
            mcp_path: None,
            test_path: None,
            oauth: Some(aka_core::types::OAuthSpec {
                auth_url: format!("http://127.0.0.1:{provider_port}/authorize"),
                token_url: format!("http://127.0.0.1:{provider_port}/token"),
                client_id: "Iv1.test".into(),
                scopes: vec!["repo".into()],
                extra_auth_params: vec![],
                token_secret_id: None,
            }),
            signer: None,
            client_cert_path: None,
            client_key_path: None,
        },
        secrets: vec![],
    };
    backend
        .oauth_connect("GH_OAUTH_TOKEN".into(), None, spec)
        .await
        .expect("relayed OAuth completes");
    browser.await.unwrap();

    // The connection landed on the broker with its token secret bound.
    let connections = backend.list_connections().await.unwrap();
    let conn = connections
        .iter()
        .find(|c| c.name == "github-oauth")
        .expect("connection exists");
    // BYO-app connections carry their oauth_spec (conn.oauth is the MCP
    // grant marker, a different mechanism).
    assert!(conn.oauth_spec.is_some());
    assert_eq!(conn.secret_names, vec!["GH_OAUTH_TOKEN".to_string()]);
    let activity = backend.activity(50).await.unwrap();
    assert!(activity
        .iter()
        .any(|entry| entry.text.contains("connected via OAuth")));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_completed_or_stale_relay_flow_cannot_be_replayed() {
    let h = harness().await;
    // Completing an unknown flow id fails cleanly.
    let bogus = uuid::Uuid::new_v4();
    let error = h
        ._broker
        .manage_oauth_complete(&bogus, "code", "state")
        .await
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("expired or was already completed"));
}

#[tokio::test(flavor = "multi_thread")]
async fn the_event_stream_connects_and_carries_changes() {
    let h = harness().await;
    let (event_tx, mut event_rx) = tokio::sync::mpsc::unbounded_channel();
    let (state_tx, mut state_rx) = tokio::sync::mpsc::unbounded_channel();
    let backend = h.backend.clone();
    let task = tokio::spawn(aka_client::events::subscribe_request_surface(
        backend,
        move |event| {
            let _ = event_tx.send(event);
        },
        move |state| {
            let _ = state_tx.send(state);
        },
    ));

    let state = tokio::time::timeout(std::time::Duration::from_secs(5), state_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(state, LinkState::Connected);
    assert!(
        h._broker.manage_bus().has_approval_surface(),
        "the desktop event stream advertises its request inbox"
    );

    // A fresh client (no Last-Event-ID) gets a server-driven resync first.
    let first = tokio::time::timeout(std::time::Duration::from_secs(5), event_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(first, ManageEvent::Resync));

    h.backend
        .add_secret("EVENTED".into(), Zeroizing::new("v".into()))
        .await
        .unwrap();
    let mut saw_activity = false;
    for _ in 0..5 {
        match tokio::time::timeout(std::time::Duration::from_secs(5), event_rx.recv()).await {
            Ok(Some(ManageEvent::ActivityAppended { entry })) => {
                assert!(entry.text.contains("EVENTED"));
                saw_activity = true;
                break;
            }
            Ok(Some(_)) => continue,
            other => panic!("stream stalled: {other:?}"),
        }
    }
    assert!(saw_activity);
    task.abort();
    let _ = task.await;
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while h._broker.manage_bus().has_approval_surface() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("dropping the response stream releases its surface lease");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_passive_event_observer_does_not_claim_an_approval_surface() {
    let h = harness().await;
    let (state_tx, mut state_rx) = tokio::sync::mpsc::unbounded_channel();
    let task = tokio::spawn(aka_client::events::subscribe(
        h.backend.clone(),
        |_| {},
        move |state| {
            let _ = state_tx.send(state);
        },
    ));

    let state = tokio::time::timeout(std::time::Duration::from_secs(5), state_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(state, LinkState::Connected);
    assert!(
        !h._broker.manage_bus().has_approval_surface(),
        "using the generic event API must remain observer-only"
    );

    task.abort();
    let _ = task.await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_request_surface_remains_compatible_with_a_legacy_broker() {
    async fn legacy_events() -> axum::response::sse::Sse<
        impl futures::Stream<Item = Result<axum::response::sse::Event, std::convert::Infallible>>,
    > {
        let event = axum::response::sse::Event::default()
            .json_data(&ManageEvent::Resync)
            .unwrap();
        axum::response::sse::Sse::new(futures::stream::iter([Ok(event)]))
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let app = axum::Router::new()
        .route("/v1/manage/events", axum::routing::get(legacy_events))
        .route(
            "/v1/manage/whoami",
            axum::routing::get(|| async {
                axum::Json(serde_json::json!({ "ok": true, "version": "legacy" }))
            }),
        );
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let backend = Arc::new(RemoteBackend::new(
        RemoteConfig::new(&base, "akamgr_legacy").unwrap(),
    ));
    let (state_tx, mut state_rx) = tokio::sync::mpsc::unbounded_channel();
    let task = tokio::spawn(aka_client::events::subscribe_request_surface(
        backend,
        |_| {},
        move |state| {
            let _ = state_tx.send(state);
        },
    ));

    let state = tokio::time::timeout(std::time::Duration::from_secs(5), state_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(state, LinkState::Connected);

    task.abort();
    let _ = task.await;
    server.abort();
    let _ = server.await;
}

#[tokio::test(flavor = "multi_thread")]
async fn stripped_surface_headers_do_not_silently_degrade_a_modern_broker() {
    async fn stripped_events() -> axum::response::sse::Sse<
        impl futures::Stream<Item = Result<axum::response::sse::Event, std::convert::Infallible>>,
    > {
        axum::response::sse::Sse::new(futures::stream::pending())
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let app = axum::Router::new()
        .route("/v1/manage/events", axum::routing::get(stripped_events))
        .route(
            "/v1/manage/whoami",
            axum::routing::get(|| async {
                axum::Json(serde_json::json!({
                    "ok": true,
                    "capabilities": [aka_api::APPROVAL_SURFACE_CAPABILITY],
                }))
            }),
        );
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let backend = Arc::new(RemoteBackend::new(
        RemoteConfig::new(&base, "akamgr_modern").unwrap(),
    ));
    let (state_tx, mut state_rx) = tokio::sync::mpsc::unbounded_channel();
    let task = tokio::spawn(aka_client::events::subscribe_request_surface(
        backend,
        |_| {},
        move |state| {
            let _ = state_tx.send(state);
        },
    ));

    let state = tokio::time::timeout(std::time::Duration::from_secs(5), state_rx.recv())
        .await
        .unwrap()
        .unwrap();
    let LinkState::Disconnected { message } = state else {
        panic!("a stripped capability negotiation must not report connected");
    };
    assert!(message.contains("proxy may have removed"), "{message}");

    task.abort();
    let _ = task.await;
    server.abort();
    let _ = server.await;
}
