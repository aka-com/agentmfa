//! Management actions are authorized by the explicit app or CLI action that
//! invokes them. Native authentication is not part of the core contract.
//!
//! This suite protects that boundary while retaining the security properties
//! that matter for a broker: traffic confirmation, capability revocation,
//! session teardown, and auditable destructive actions.

use std::sync::Arc;

use aka_core::approvals::{ApprovalDecision, ApprovalRequest, Verdict};
use aka_core::audit::{AuditEntry, AuditKind};
use aka_core::broker::Broker;
use aka_core::config::BrokerConfig;
use aka_core::events::{ApprovalHandling, BrokerEvents};
use aka_core::paths::Paths;
use aka_core::sessions::RedeemError;
use aka_core::store::ConnectionSpec;
use aka_core::types::{ConfirmMode, Connection, ConnectionConfig, ConnectionKind};
use aka_core::vault::MemoryVault;
use zeroize::Zeroizing;

struct AppEvents;

impl BrokerEvents for AppEvents {
    fn approval_requested(
        &self,
        _pending: &aka_core::approvals::PendingApproval,
    ) -> ApprovalHandling {
        ApprovalHandling::Taken
    }
}

async fn broker_with(events: Arc<dyn BrokerEvents>) -> (Arc<Broker>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let broker = Broker::new(
        Paths::under(dir.path()),
        Arc::new(MemoryVault::new()),
        BrokerConfig::default(),
        events,
    )
    .await
    .unwrap();
    (broker, dir)
}

fn add_github(broker: &Broker) -> Connection {
    futures::executor::block_on(async {
        broker
            .store
            .add_secret("GITHUB_API_KEY", Zeroizing::new("ghp_x".into()))
            .await
            .unwrap();
        broker
            .store
            .add_connection(ConnectionSpec {
                name: "github".into(),
                config: ConnectionConfig::Api {
                    host: "api.github.com".into(),
                    scheme: "https".into(),
                    port: None,
                    trusted_ca_bundle_path: None,
                    template: "Authorization: Bearer {{GITHUB_API_KEY}}".into(),
                    mcp_path: None,
                    test_path: None,
                    oauth: None,
                    signer: None,
                    client_cert_path: None,
                    client_key_path: None,
                },
                secrets: vec![],
            })
            .await
            .unwrap()
    })
}

#[tokio::test]
async fn explicit_management_actions_do_not_consult_native_authentication() {
    let (broker, _dir) = broker_with(Arc::new(AppEvents)).await;
    let conn = add_github(&broker);
    let secret = broker.store.secret_by_name("GITHUB_API_KEY").unwrap();

    assert_eq!(
        &*broker.ui_secret_value_for_copy(&secret.id).await.unwrap(),
        "ghp_x"
    );
    broker
        .ui_edit_secret(&secret.id, None, Some(Zeroizing::new("ghp_rotated".into())))
        .await
        .unwrap();

    broker
        .ui_update_connection(
            &conn.id,
            ConnectionSpec {
                name: conn.name.clone(),
                config: ConnectionConfig::Api {
                    host: "api.enterprise.github.com".into(),
                    scheme: "https".into(),
                    port: None,
                    trusted_ca_bundle_path: None,
                    template: "Authorization: Bearer {{GITHUB_API_KEY}}".into(),
                    mcp_path: None,
                    test_path: None,
                    oauth: None,
                    signer: None,
                    client_cert_path: None,
                    client_key_path: None,
                },
                secrets: vec![],
            },
        )
        .await
        .unwrap();
    assert!(broker.ui_set_tool_access(&conn.id, false).await.unwrap());
    assert!(broker.ui_set_tool_access(&conn.id, true).await.unwrap());
    assert!(broker
        .ui_set_confirm_mode(&conn.id, ConfirmMode::On)
        .await
        .unwrap());
    assert!(broker
        .ui_set_confirm_mode(&conn.id, ConfirmMode::Off)
        .await
        .unwrap());
    assert!(broker
        .ui_set_expose_response_credentials(&conn.id, false)
        .await
        .unwrap());
    assert!(broker
        .ui_set_expose_response_credentials(&conn.id, true)
        .await
        .unwrap());
    assert!(!broker.ui_agent_key_for_copy().unwrap().is_empty());
    broker.ui_rotate_key().await.unwrap();
    broker.ui_clear_activity().unwrap();
}

#[tokio::test]
async fn key_rotation_closes_sessions_and_revokes_standing_endpoints() {
    let (broker, _dir) = broker_with(Arc::new(AppEvents)).await;
    let old_token = broker.identity.token();
    let conn = add_github(&broker);
    let ticket = broker.data_plane.issue("claude-code", &conn);
    let session = broker
        .data_plane
        .redeem(&ticket)
        .unwrap()
        .start(ConnectionKind::Api);
    let close = session.close_signal.clone();
    let endpoint = broker
        .endpoints
        .issue(conn.id, ConnectionKind::Api)
        .await
        .unwrap();

    broker.ui_rotate_key().await.unwrap();

    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(1), close.reason())
            .await
            .expect("rotation should close live data-plane sessions"),
        "key_rotated"
    );
    assert!(matches!(
        broker.data_plane.redeem(&ticket),
        Err(RedeemError::Expired)
    ));
    session.finish("key_rotated");
    assert_ne!(broker.identity.token(), old_token);
    assert!(broker.endpoints.list().is_empty());
    assert!(broker.endpoints.resolve_secret(&endpoint.secret).is_none());

    let revoked = broker
        .audit
        .recent(10)
        .into_iter()
        .find(|entry| entry.kind == AuditKind::TokenRevoked)
        .expect("rotation should be audited");
    assert_eq!(revoked.confirmation, None);
    assert_eq!(
        revoked.fields.get("endpoints_revoked"),
        Some(&serde_json::json!(1))
    );
}

#[tokio::test]
async fn secret_rotation_closes_bound_sessions_and_approval_windows() {
    let (broker, _dir) = broker_with(Arc::new(AppEvents)).await;
    let secret = broker
        .store
        .add_secret("PG_PASSWORD", Zeroizing::new("before".into()))
        .await
        .unwrap();
    let conn = broker
        .store
        .add_connection(ConnectionSpec {
            name: "warehouse".into(),
            config: ConnectionConfig::Pg {
                host: "db.example.com".into(),
                port: 5432,
                user: "reader".into(),
                dbname: "analytics".into(),
                sslmode: aka_core::types::PgSslMode::VerifyFull,
                trusted_ca_bundle_path: None,
            },
            secrets: vec![secret.id],
        })
        .await
        .unwrap();

    let ticket = broker.data_plane.issue("claude-code", &conn);
    let session = broker
        .data_plane
        .redeem(&ticket)
        .unwrap()
        .start(ConnectionKind::Pg);
    let closed = session.close_signal.clone();

    let approvals = broker.approvals.clone();
    let gate = tokio::spawn(async move {
        approvals
            .gate(ApprovalRequest::new(&conn, "codex", "psql session"))
            .await
    });
    let pending = tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            if let Some(pending) = broker.pending_approvals().first().cloned() {
                break pending;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("approval prompt");
    assert!(broker
        .ui_respond_approval(&pending.id, ApprovalDecision::ApproveWindow)
        .await
        .unwrap());
    assert_eq!(gate.await.unwrap(), Verdict::Allowed);
    assert!(broker
        .approvals
        .window_remaining(&pending.connection_id)
        .is_some());

    broker
        .ui_edit_secret(&secret.id, None, Some(Zeroizing::new("after".into())))
        .await
        .unwrap();

    assert_eq!(
        broker.approvals.window_remaining(&pending.connection_id),
        None
    );
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(1), closed.reason())
            .await
            .expect("credential rotation should close the session"),
        "secret_rotated"
    );
    assert_eq!(
        broker.data_plane.redeem(&ticket).err(),
        Some(RedeemError::Expired)
    );
    session.finish("secret_rotated");
}

#[tokio::test]
async fn approve_all_remains_a_traffic_decision_and_disables_future_prompts() {
    let (broker, _dir) = broker_with(Arc::new(AppEvents)).await;
    let conn = add_github(&broker);
    broker
        .ui_set_confirm_mode(&conn.id, ConfirmMode::On)
        .await
        .unwrap();

    let approvals = broker.approvals.clone();
    let request_connection = conn.clone();
    let gate = tokio::spawn(async move {
        approvals
            .gate(ApprovalRequest::new(
                &request_connection,
                "codex",
                "GET /repos",
            ))
            .await
    });
    let pending = tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            if let Some(pending) = broker.pending_approvals().first().cloned() {
                break pending;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("approval prompt");

    assert!(broker
        .ui_respond_approval(&pending.id, ApprovalDecision::ApproveAll)
        .await
        .unwrap());
    assert_eq!(gate.await.unwrap(), Verdict::Allowed);
    assert_eq!(broker.access.confirm_mode(&conn.id), ConfirmMode::Off);
}

#[tokio::test]
async fn clearing_activity_leaves_an_audited_tombstone() {
    let (broker, _dir) = broker_with(Arc::new(AppEvents)).await;
    broker
        .audit
        .append(AuditEntry::new(AuditKind::Listed, "old activity"));
    broker
        .audit
        .append(AuditEntry::new(AuditKind::Denied, "older activity"));

    broker.ui_clear_activity().unwrap();

    let recent = broker.audit.recent(10);
    assert_eq!(recent.len(), 1);
    assert_eq!(recent[0].kind, AuditKind::ActivityCleared);
    assert_eq!(recent[0].fields["entries_removed"], 2);
    assert_eq!(recent[0].confirmation, None);
}
