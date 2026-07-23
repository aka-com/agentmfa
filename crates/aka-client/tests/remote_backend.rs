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

    // OAuth flows are explicitly not relayable yet.
    let error = backend.oauth_reconnect(id).await.unwrap_err();
    assert!(matches!(error, ManageError::RemoteUnsupported { .. }));
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
