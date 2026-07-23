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
use aka_core::types::{ConfirmationMethod, ConnectionConfig, SecretMeta};
use aka_core::vault::MemoryVault;
use zeroize::Zeroizing;

struct TestEvents;

impl BrokerEvents for TestEvents {
    fn confirm_secret_read(&self, _secret: &SecretMeta) -> bool {
        true
    }
    fn confirm_action(&self, _description: &str) -> Option<ConfirmationMethod> {
        Some(ConfirmationMethod::ManagementToken)
    }
}

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
    let token = broker.identity.issue_manage_token().unwrap();
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

fn api_spec(name: &str, template: &str) -> ConnectionSpec {
    ConnectionSpec {
        name: name.into(),
        config: ConnectionConfig::Api {
            host: "api.github.com".into(),
            scheme: "https".into(),
            port: None,
            template: template.into(),
            mcp_path: None,
            oauth: None,
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
    assert!(!backend.list_connections().await.unwrap()[0]
        .agent_access
        .enabled);

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

    let settings = backend.settings().await.unwrap();
    assert!(!settings.show_websockets);
    backend.set_show_websockets(true).await.unwrap();
    assert!(backend.settings().await.unwrap().show_websockets);

    assert!(!backend.activity(50).await.unwrap().is_empty());

    // BYO OAuth relays now; reconnecting a non-OAuth connection is the
    // structured config error, not a transport failure.
    let error = backend.oauth_reconnect(id).await.unwrap_err();
    assert!(matches!(error, ManageError::InvalidConnectionConfig { .. }));
}

#[tokio::test(flavor = "multi_thread")]
async fn bad_tokens_and_dead_brokers_map_to_distinct_errors() {
    let h = harness().await;

    let wrong = RemoteBackend::new(
        RemoteConfig::new(&h.base, "akamgr_00000000000000000000000000000000").unwrap(),
    );
    assert_eq!(
        wrong.list_secrets().await.unwrap_err(),
        ManageError::InvalidManageToken
    );

    let dead = RemoteBackend::new(
        RemoteConfig::new("http://127.0.0.1:9", "akamgr_x").unwrap(),
    );
    assert!(matches!(
        dead.list_secrets().await.unwrap_err(),
        ManageError::Unreachable { .. }
    ));
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
        RemoteConfig::new(
            &h.base,
            h.backend.config().token(),
        )
        .unwrap(),
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
        let pairs: std::collections::HashMap<_, _> =
            parsed.query_pairs().into_owned().collect();
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
            template: "Authorization: Bearer {{GH_OAUTH_TOKEN}}".into(),
            mcp_path: None,
            oauth: Some(aka_core::types::OAuthSpec {
                auth_url: format!("http://127.0.0.1:{provider_port}/authorize"),
                token_url: format!("http://127.0.0.1:{provider_port}/token"),
                client_id: "Iv1.test".into(),
                scopes: vec!["repo".into()],
                extra_auth_params: vec![],
            }),
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
    assert!(error.to_string().contains("expired or was already completed"));
}

#[tokio::test(flavor = "multi_thread")]
async fn the_event_stream_connects_and_carries_changes() {
    let h = harness().await;
    let (event_tx, mut event_rx) = tokio::sync::mpsc::unbounded_channel();
    let (state_tx, mut state_rx) = tokio::sync::mpsc::unbounded_channel();
    let backend = h.backend.clone();
    let task = tokio::spawn(aka_client::events::subscribe(
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

    // The first event after connecting is the synthetic resync.
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
}
