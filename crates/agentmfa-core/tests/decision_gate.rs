//! The core-owned high-consequence gate (DESIGN.md §8): the broker itself
//! demands the shell's native confirmation through `BrokerEvents` before a
//! gated decision or configuration action takes effect — a shell (or a
//! compromised webview driving one) cannot apply them without passing
//! through the gate, and the gate fails closed when unimplemented.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use agentmfa_core::approvals::{
    ApprovalKind, ApprovalRequest, ConnectionSummary, ExecOutcome, HttpPayloadView, ParkRequest,
    Parked,
};
use agentmfa_core::broker::{Broker, UiDecision};
use agentmfa_core::config::BrokerConfig;
use agentmfa_core::error::CoreError;
use agentmfa_core::events::BrokerEvents;
use agentmfa_core::paths::Paths;
use agentmfa_core::policy::PolicyEngine;
use agentmfa_core::store::ConnectionSpec;
use agentmfa_core::types::{
    ConfirmationMethod, Connection, ConnectionConfig, DecisionContext, DecisionSurface,
    PeerIdentity,
};
use agentmfa_core::vault::MemoryVault;
use chrono::Utc;
use uuid::Uuid;
use zeroize::Zeroizing;

/// Counting gate: `allow: false` refuses every confirmation (and the
/// unimplemented-default case is covered by not overriding at all).
struct GateEvents {
    allow: bool,
    confirms: AtomicUsize,
}

struct UnifiedAuthEvents {
    decision_confirms: AtomicUsize,
    secret_read_confirms: AtomicUsize,
}

impl BrokerEvents for UnifiedAuthEvents {
    fn confirm_secret_read(&self, _secret: &agentmfa_core::types::SecretMeta) -> bool {
        self.secret_read_confirms.fetch_add(1, Ordering::SeqCst);
        true
    }

    fn confirm_decision(
        &self,
        _request: &ApprovalRequest,
        _decision: UiDecision,
    ) -> Option<ConfirmationMethod> {
        self.decision_confirms.fetch_add(1, Ordering::SeqCst);
        Some(ConfirmationMethod::OsAuthentication)
    }
}

impl BrokerEvents for GateEvents {
    fn confirm_decision(
        &self,
        _request: &ApprovalRequest,
        _decision: UiDecision,
    ) -> Option<ConfirmationMethod> {
        self.confirms.fetch_add(1, Ordering::SeqCst);
        self.allow.then_some(ConfirmationMethod::Waived)
    }

    fn confirm_action(&self, _description: &str) -> Option<ConfirmationMethod> {
        self.confirms.fetch_add(1, Ordering::SeqCst);
        self.allow.then_some(ConfirmationMethod::Waived)
    }
}

/// A shell that never implemented the gates: the trait defaults fail closed.
struct UnimplementedShell;
impl BrokerEvents for UnimplementedShell {}

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

fn ctx() -> DecisionContext {
    DecisionContext::local(DecisionSurface::Harness)
}

fn add_github(broker: &Broker) -> Connection {
    broker
        .store
        .add_secret("GITHUB_API_KEY", Zeroizing::new("ghp_x".into()))
        .unwrap();
    broker
        .store
        .add_connection(ConnectionSpec {
            name: "github".into(),
            config: ConnectionConfig::Api {
                host: "api.github.com".into(),
                scheme: "https".into(),
                port: None,
                template: "Authorization: Bearer {{GITHUB_API_KEY}}".into(),
            },
            secrets: vec![],
            multi_connect: false,
        })
        .unwrap()
}

fn http_request(conn: &Connection, mutating: bool) -> ApprovalRequest {
    let method = if mutating { "POST" } else { "GET" };
    let now = Utc::now();
    ApprovalRequest {
        id: Uuid::new_v4(),
        agent: "claude-code".into(),
        agent_token_hash: None,
        kind: ApprovalKind::Http,
        connection: Some(ConnectionSummary {
            id: conn.id,
            name: conn.name.clone(),
            kind: conn.kind(),
            target: conn.target(),
            multi_connect: conn.multi_connect,
        }),
        action: format!("{method} api.github.com/x"),
        notification: String::new(),
        received_at: now,
        deadline: now,
        identity: None,
        inherited: vec![],
        http: Some(HttpPayloadView {
            method: method.into(),
            path: "/x".into(),
            headers: vec![],
            body_preview: None,
            body_len: 0,
            body_truncated: false,
            mutating,
        }),
    }
}

fn pair_request(agent: &str, inherited: Vec<ConnectionSummary>) -> ApprovalRequest {
    let now = Utc::now();
    ApprovalRequest {
        id: Uuid::new_v4(),
        agent: agent.into(),
        agent_token_hash: None,
        kind: ApprovalKind::Pair,
        connection: None,
        action: format!("Pair new agent \"{agent}\" with AgentMFA"),
        notification: String::new(),
        received_at: now,
        deadline: now,
        identity: Some(PeerIdentity::DevUnverified { uid: 501 }.display()),
        inherited,
        http: None,
    }
}

fn park(broker: &Broker, request: ApprovalRequest) -> Parked {
    broker
        .approvals
        .park(ParkRequest {
            request,
            coalesce_key: None,
            payload_hash: None,
            retain_outcome: true,
            executor: Box::pin(async {
                ExecOutcome {
                    status: 200,
                    body: serde_json::json!({"ok": true}),
                }
            }),
        })
        .unwrap()
}

fn park_with_executor(
    broker: &Broker,
    request: ApprovalRequest,
    executor: agentmfa_core::approvals::Executor,
) -> Parked {
    broker
        .approvals
        .park(ParkRequest {
            request,
            coalesce_key: None,
            payload_hash: None,
            retain_outcome: true,
            executor,
        })
        .unwrap()
}

#[tokio::test]
async fn refused_confirmation_blocks_the_allow_but_not_deny() {
    let events = Arc::new(GateEvents {
        allow: false,
        confirms: AtomicUsize::new(0),
    });
    let (broker, _dir) = broker_with(events.clone()).await;
    let conn = add_github(&broker);
    let request = http_request(&conn, true);
    let id = request.id;
    let parked = park(&broker, request);

    // The gate refuses: the mutating allow must not apply...
    assert!(matches!(
        broker.decide(&id, UiDecision::AllowOnce, &ctx()),
        Err(CoreError::NotConfirmed)
    ));
    // ...and the request is still pending, not consumed.
    assert_eq!(broker.approvals_queue().len(), 1);
    assert_eq!(events.confirms.load(Ordering::SeqCst), 1);

    // Deny needs no confirmation: always one click (§6).
    broker
        .decide(&id, UiDecision::Deny, &ctx())
        .unwrap()
        .expect("still pending");
    assert_eq!(events.confirms.load(Ordering::SeqCst), 1);
    let Parked::Wait(handle) = parked else {
        panic!()
    };
    let outcome = handle.wait().await.unwrap();
    assert_eq!(outcome.status, 403);
}

#[tokio::test]
async fn unimplemented_shell_fails_closed() {
    let (broker, _dir) = broker_with(Arc::new(UnimplementedShell)).await;
    let conn = add_github(&broker);

    // Decisions on high-consequence requests are blocked...
    let request = http_request(&conn, true);
    let id = request.id;
    let _parked = park(&broker, request);
    assert!(matches!(
        broker.decide(&id, UiDecision::AllowOnce, &ctx()),
        Err(CoreError::NotConfirmed)
    ));

    // ...and so are high-consequence configuration actions.
    assert!(matches!(
        broker.ui_delete_connection(&conn.id),
        Err(CoreError::NotConfirmed)
    ));
    assert!(broker.store.connection_by_id(&conn.id).is_ok());
}

#[tokio::test]
async fn pairing_revocation_is_immediate_without_confirmation() {
    let events = Arc::new(GateEvents {
        allow: false,
        confirms: AtomicUsize::new(0),
    });
    let (broker, _dir) = broker_with(events.clone()).await;
    broker
        .pairing
        .pair("claude-code", PeerIdentity::DevUnverified { uid: 501 })
        .unwrap();

    assert!(broker.ui_revoke_agent("claude-code").unwrap());
    assert!(broker.paired_agents().is_empty());
    assert_eq!(events.confirms.load(Ordering::SeqCst), 0);
    let revoked = broker
        .audit
        .recent(10)
        .into_iter()
        .find(|entry| entry.kind == agentmfa_core::audit::AuditKind::TokenRevoked)
        .expect("revocation should be audited");
    assert_eq!(revoked.confirmation, None);
}

#[tokio::test]
async fn non_mutating_allow_needs_no_confirmation() {
    let events = Arc::new(GateEvents {
        allow: false, // would refuse if ever asked
        confirms: AtomicUsize::new(0),
    });
    let (broker, _dir) = broker_with(events.clone()).await;
    let conn = add_github(&broker);
    let request = http_request(&conn, false);
    let id = request.id;
    let parked = park(&broker, request);

    broker
        .decide(&id, UiDecision::AllowOnce, &ctx())
        .unwrap()
        .expect("pending");
    assert_eq!(events.confirms.load(Ordering::SeqCst), 0);
    let Parked::Wait(handle) = parked else {
        panic!()
    };
    assert_eq!(handle.wait().await.unwrap().status, 200);
}

#[tokio::test]
async fn confirmed_decision_authorizes_its_executor_secret_reads_only() {
    let events = Arc::new(UnifiedAuthEvents {
        decision_confirms: AtomicUsize::new(0),
        secret_read_confirms: AtomicUsize::new(0),
    });
    let (broker, _dir) = broker_with(events.clone()).await;
    let conn = add_github(&broker);
    let request = http_request(&conn, true);
    let id = request.id;
    let executor_broker = broker.clone();
    let parked = park_with_executor(
        &broker,
        request,
        Box::pin(async move {
            // Multiple credential reads in the same approved execution reuse
            // the decision's native authentication.
            executor_broker
                .store
                .secret_value_by_name("GITHUB_API_KEY")
                .await
                .unwrap();
            executor_broker
                .store
                .secret_value_by_name("GITHUB_API_KEY")
                .await
                .unwrap();
            ExecOutcome {
                status: 200,
                body: serde_json::json!({"ok": true}),
            }
        }),
    );

    broker
        .decide(&id, UiDecision::AllowOnce, &ctx())
        .unwrap()
        .expect("pending");
    let Parked::Wait(handle) = parked else {
        panic!()
    };
    assert_eq!(handle.wait().await.unwrap().status, 200);
    assert_eq!(events.decision_confirms.load(Ordering::SeqCst), 1);
    assert_eq!(events.secret_read_confirms.load(Ordering::SeqCst), 0);

    // The authorization is execution-scoped: an independent read still
    // requires its own confirmation.
    broker
        .store
        .secret_value_by_name("GITHUB_API_KEY")
        .await
        .unwrap();
    assert_eq!(events.secret_read_confirms.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn always_allow_confirms_once_and_attributes_the_audit_trail() {
    let events = Arc::new(GateEvents {
        allow: true,
        confirms: AtomicUsize::new(0),
    });
    let (broker, _dir) = broker_with(events.clone()).await;
    let conn = add_github(&broker);
    let request = http_request(&conn, false);
    let id = request.id;
    let parked = park(&broker, request);

    broker
        .decide(&id, UiDecision::AlwaysAllow, &ctx())
        .unwrap()
        .expect("pending");
    // One confirmation covers the rule save AND the allow it implies —
    // the internal AlwaysAllow → AllowOnce step must not re-confirm.
    assert_eq!(events.confirms.load(Ordering::SeqCst), 1);
    assert_eq!(broker.rules().len(), 1);
    let Parked::Wait(handle) = parked else {
        panic!()
    };
    assert_eq!(handle.wait().await.unwrap().status, 200);

    // Both decision entries carry the attribution and the confirmation.
    let recent = broker.audit.recent(10);
    let attributed: Vec<_> = recent
        .iter()
        .filter(|e| e.surface == Some(DecisionSurface::Harness))
        .collect();
    assert_eq!(attributed.len(), 2, "RuleSaved + AllowedOnce: {recent:?}");
    for entry in attributed {
        assert_eq!(entry.confirmation, Some(ConfirmationMethod::Waived));
        assert_eq!(entry.approver, None);
    }
}

#[tokio::test]
async fn config_actions_confirm_and_record_the_method() {
    let events = Arc::new(GateEvents {
        allow: true,
        confirms: AtomicUsize::new(0),
    });
    let (broker, _dir) = broker_with(events.clone()).await;
    let conn = add_github(&broker);
    assert_eq!(
        events.confirms.load(Ordering::SeqCst),
        0,
        "store-level setup is not gated"
    );

    broker.ui_delete_connection(&conn.id).unwrap();
    assert_eq!(events.confirms.load(Ordering::SeqCst), 1);
    let recent = broker.audit.recent(5);
    let deleted = recent
        .iter()
        .find(|e| e.text.starts_with("Connection deleted"))
        .unwrap();
    assert_eq!(deleted.confirmation, Some(ConfirmationMethod::Waived));

    // In-use secrets are refused before the user is asked to authenticate.
    let secret = broker.store.secret_by_name("GITHUB_API_KEY").unwrap();
    broker.ui_delete_secret(&secret.id).unwrap();
    assert_eq!(events.confirms.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn connection_renames_skip_confirmation_but_capability_changes_do_not() {
    let events = Arc::new(GateEvents {
        allow: true,
        confirms: AtomicUsize::new(0),
    });
    let (broker, _dir) = broker_with(events.clone()).await;
    let conn = add_github(&broker);

    let renamed = broker
        .ui_update_connection(
            &conn.id,
            ConnectionSpec {
                name: "github-renamed".into(),
                config: conn.config.clone(),
                secrets: conn.secrets.clone(),
                multi_connect: conn.multi_connect,
            },
        )
        .unwrap();
    assert_eq!(events.confirms.load(Ordering::SeqCst), 0);
    let renamed_entry = broker
        .audit
        .recent(5)
        .into_iter()
        .find(|entry| entry.kind == agentmfa_core::audit::AuditKind::ConnectionUpdated)
        .unwrap();
    assert_eq!(renamed_entry.confirmation, None);
    assert_eq!(renamed_entry.fields["capability_changed"], false);

    let ConnectionConfig::Api {
        scheme,
        port,
        template,
        ..
    } = renamed.config.clone()
    else {
        panic!("expected API connection")
    };
    broker
        .ui_update_connection(
            &renamed.id,
            ConnectionSpec {
                name: renamed.name.clone(),
                config: ConnectionConfig::Api {
                    host: "api.enterprise.github.com".into(),
                    scheme,
                    port,
                    template,
                },
                secrets: renamed.secrets.clone(),
                multi_connect: renamed.multi_connect,
            },
        )
        .unwrap();
    assert_eq!(events.confirms.load(Ordering::SeqCst), 1);
    let changed_entry = broker
        .audit
        .recent(5)
        .into_iter()
        .find(|entry| entry.kind == agentmfa_core::audit::AuditKind::ConnectionUpdated)
        .unwrap();
    assert_eq!(changed_entry.confirmation, Some(ConfirmationMethod::Waived));
    assert_eq!(changed_entry.fields["capability_changed"], true);
}

#[tokio::test]
async fn secret_binding_and_session_scope_changes_require_confirmation() {
    let events = Arc::new(GateEvents {
        allow: true,
        confirms: AtomicUsize::new(0),
    });
    let (broker, _dir) = broker_with(events.clone()).await;
    let first = broker
        .store
        .add_secret("WS_TOKEN", Zeroizing::new("first".into()))
        .unwrap();
    let second = broker
        .store
        .add_secret("WS_TOKEN_NEXT", Zeroizing::new("second".into()))
        .unwrap();
    let conn = broker
        .store
        .add_connection(ConnectionSpec {
            name: "events".into(),
            config: ConnectionConfig::Ws {
                url: "wss://events.example.com".into(),
                template: None,
            },
            secrets: vec![first.id],
            multi_connect: true,
        })
        .unwrap();

    let rebound = broker
        .ui_update_connection(
            &conn.id,
            ConnectionSpec {
                name: conn.name.clone(),
                config: conn.config.clone(),
                secrets: vec![second.id],
                multi_connect: conn.multi_connect,
            },
        )
        .unwrap();
    assert_eq!(events.confirms.load(Ordering::SeqCst), 1);

    broker
        .ui_update_connection(
            &rebound.id,
            ConnectionSpec {
                name: rebound.name.clone(),
                config: rebound.config.clone(),
                secrets: rebound.secrets.clone(),
                multi_connect: false,
            },
        )
        .unwrap();
    assert_eq!(events.confirms.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn sensitive_settings_fail_closed_before_mutating() {
    let events = Arc::new(GateEvents {
        allow: false,
        confirms: AtomicUsize::new(0),
    });
    let (broker, _dir) = broker_with(events.clone()).await;

    assert!(matches!(
        broker.ui_change_reauth_on_read(false),
        Err(CoreError::NotConfirmed)
    ));
    assert!(broker.settings().reauth_on_read);
    assert_eq!(events.confirms.load(Ordering::SeqCst), 1);

    assert!(matches!(
        broker.ui_change_pg_trusted_ca_bundle_path(Some("/tmp/pg-ca.pem".into())),
        Err(CoreError::NotConfirmed)
    ));
    assert_eq!(broker.settings().pg_trusted_ca_bundle_path, None);
    assert_eq!(events.confirms.load(Ordering::SeqCst), 2);

    // Re-enabling the stricter read gate is not security-reducing.
    broker.ui_change_reauth_on_read(true).unwrap();
    assert_eq!(events.confirms.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn sensitive_settings_record_confirmation() {
    let events = Arc::new(GateEvents {
        allow: true,
        confirms: AtomicUsize::new(0),
    });
    let (broker, _dir) = broker_with(events.clone()).await;

    broker.ui_change_reauth_on_read(false).unwrap();
    broker
        .ui_change_pg_trusted_ca_bundle_path(Some("/tmp/pg-ca.pem".into()))
        .unwrap();
    assert_eq!(events.confirms.load(Ordering::SeqCst), 2);
    let recent = broker.audit.recent(10);
    let confirmed_settings = recent
        .iter()
        .filter(|entry| {
            entry.kind == agentmfa_core::audit::AuditKind::SettingsChanged
                && entry.confirmation == Some(ConfirmationMethod::Waived)
        })
        .count();
    assert_eq!(confirmed_settings, 2, "{recent:?}");
}

#[tokio::test]
async fn inherited_rules_are_removed_before_pairing_executes() {
    let events = Arc::new(GateEvents {
        allow: true,
        confirms: AtomicUsize::new(0),
    });
    let (broker, _dir) = broker_with(events.clone()).await;
    let conn = add_github(&broker);
    broker.policy.record_rule("claude-code", conn.id).unwrap();
    assert_eq!(broker.rules().len(), 1);

    let request = pair_request("claude-code", broker.inherited_for("claude-code"));
    let id = request.id;
    let broker_for_executor = broker.clone();
    let parked = park_with_executor(
        &broker,
        request,
        Box::pin(async move {
            ExecOutcome {
                status: 200,
                body: serde_json::json!({
                    "rules_at_execution": broker_for_executor.rules().len(),
                }),
            }
        }),
    );

    broker
        .decide_with_pairing_options(&id, UiDecision::AllowOnce, true, &ctx())
        .unwrap()
        .expect("pending");

    let Parked::Wait(handle) = parked else {
        panic!()
    };
    let outcome = handle.wait().await.unwrap();
    assert_eq!(outcome.status, 200);
    assert_eq!(outcome.body["rules_at_execution"], 0);
    assert_eq!(broker.rules().len(), 0);
    assert_eq!(events.confirms.load(Ordering::SeqCst), 1);

    let recent = broker.audit.recent(10);
    let removed = recent
        .iter()
        .find(|entry| entry.kind == agentmfa_core::audit::AuditKind::RuleRemoved)
        .expect("rule removal audit entry");
    assert_eq!(removed.confirmation, Some(ConfirmationMethod::Waived));
    assert_eq!(removed.surface, Some(DecisionSurface::Harness));
}
