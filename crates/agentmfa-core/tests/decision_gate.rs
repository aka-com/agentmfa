//! The core-owned decision gate. The broker itself demands the
//! shell's native confirmation through `BrokerEvents` before a gated
//! decision or configuration action takes effect — a shell (or a
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
use agentmfa_core::sessions::{RedeemError, TicketPayload};
use agentmfa_core::store::ConnectionSpec;
use agentmfa_core::types::{
    ConfirmationMethod, Connection, ConnectionConfig, ConnectionKind, DecisionContext,
    DecisionSurface, PeerIdentity,
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
        })
        .unwrap()
}

fn http_request(conn: &Connection, mutating: bool) -> ApprovalRequest {
    let method = if mutating { "POST" } else { "GET" };
    let now = Utc::now();
    ApprovalRequest {
        id: Uuid::new_v4(),
        agent: "claude-code".into(),
        client_id: Some(Uuid::new_v4()),
        agent_token_hash: None,
        kind: ApprovalKind::Http,
        connection: Some(ConnectionSummary {
            id: conn.id,
            name: conn.name.clone(),
            kind: conn.kind(),
            target: conn.target(),
            connection_updated_at: conn.updated_at,
        }),
        action: format!("{method} api.github.com/x"),
        notification: String::new(),
        received_at: now,
        deadline: now,
        identity: None,
        pairing_identity: None,
        replaces_existing_agent: false,
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
        ssh: None,
        proposal: None,
        proposal_credential: None,
    }
}

fn pair_request(agent: &str, inherited: Vec<ConnectionSummary>) -> ApprovalRequest {
    let now = Utc::now();
    ApprovalRequest {
        id: Uuid::new_v4(),
        agent: agent.into(),
        client_id: Some(Uuid::new_v4()),
        agent_token_hash: None,
        kind: ApprovalKind::Pair,
        connection: None,
        action: format!("Pair new agent \"{agent}\" with AgentMFA"),
        notification: String::new(),
        received_at: now,
        deadline: now,
        identity: Some(PeerIdentity::DevUnverified { uid: 501 }.display()),
        pairing_identity: Some(
            agentmfa_core::approvals::PairingIdentitySummary::from_identity(
                &PeerIdentity::DevUnverified { uid: 501 },
            ),
        ),
        replaces_existing_agent: false,
        inherited,
        http: None,
        ssh: None,
        proposal: None,
        proposal_credential: None,
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

    // Deny needs no confirmation: always one click.
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
    let (_, client) = broker
        .pairing
        .pair("claude-code", PeerIdentity::DevUnverified { uid: 501 })
        .unwrap();
    let conn = add_github(&broker);
    let ticket = broker
        .data_plane
        .issue("claude-code", &conn, TicketPayload::Pg);
    let session = broker
        .data_plane
        .redeem(&ticket)
        .unwrap()
        .start(ConnectionKind::Pg);
    let close = session.close_signal.clone();
    let notified = close.notified();

    assert!(broker.ui_revoke_agent(&client.id).unwrap());
    tokio::time::timeout(std::time::Duration::from_secs(1), notified)
        .await
        .expect("disconnect should close live data-plane sessions");
    assert!(matches!(
        broker.data_plane.redeem(&ticket),
        Err(RedeemError::Expired)
    ));
    session.finish("agent_disconnected");
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
async fn copy_auth_is_reused_across_secrets_but_not_outside_copying() {
    let events = Arc::new(UnifiedAuthEvents {
        decision_confirms: AtomicUsize::new(0),
        secret_read_confirms: AtomicUsize::new(0),
    });
    let (broker, _dir) = broker_with(events.clone()).await;
    let first = broker
        .store
        .add_secret("FIRST_SECRET", Zeroizing::new("first".into()))
        .unwrap();
    let second = broker
        .store
        .add_secret("SECOND_SECRET", Zeroizing::new("second".into()))
        .unwrap();

    assert_eq!(
        &*broker.ui_secret_value_for_copy(&first.id).await.unwrap(),
        "first"
    );
    assert_eq!(
        &*broker.ui_secret_value_for_copy(&second.id).await.unwrap(),
        "second"
    );
    assert_eq!(events.secret_read_confirms.load(Ordering::SeqCst), 1);

    // The copy window is not a general secret-read authorization. An agent
    // execution or another direct broker read still needs its own gate.
    assert_eq!(
        &*broker.store.secret_value(&first.id).await.unwrap(),
        "first"
    );
    assert_eq!(events.secret_read_confirms.load(Ordering::SeqCst), 2);
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
    assert_eq!(
        broker.rules()[0].scope,
        agentmfa_core::types::PermissionScope::Read
    );
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
async fn durable_decisions_refuse_a_same_target_connection_revision_change() {
    let events = Arc::new(GateEvents {
        allow: true,
        confirms: AtomicUsize::new(0),
    });
    let (broker, _dir) = broker_with(events).await;
    let mut conn = add_github(&broker);

    let request = http_request(&conn, false);
    let always_id = request.id;
    let always_waiter = park(&broker, request);
    conn = broker
        .ui_update_connection(
            &conn.id,
            ConnectionSpec {
                name: conn.name.clone(),
                config: ConnectionConfig::Api {
                    host: "api.github.com".into(),
                    scheme: "https".into(),
                    port: None,
                    template: "X-Api-Key: {{GITHUB_API_KEY}}".into(),
                },
                secrets: vec![],
            },
        )
        .unwrap();
    assert!(matches!(
        broker.decide(&always_id, UiDecision::AlwaysAllow, &ctx()),
        Err(CoreError::ApprovalConnectionChanged)
    ));
    assert!(broker.rules().is_empty());
    broker.decide(&always_id, UiDecision::Deny, &ctx()).unwrap();
    let Parked::Wait(always_waiter) = always_waiter else {
        panic!()
    };
    assert_eq!(always_waiter.wait().await.unwrap().status, 403);

    let (_, paired) = broker
        .pairing
        .pair("claude-code", PeerIdentity::DevUnverified { uid: 501 })
        .unwrap();
    let mut request = http_request(&conn, false);
    request.agent_token_hash = Some(paired.token_hash);
    let session_id = request.id;
    let session_waiter = park(&broker, request);
    broker
        .ui_update_connection(
            &conn.id,
            ConnectionSpec {
                name: conn.name.clone(),
                config: ConnectionConfig::Api {
                    host: "api.github.com".into(),
                    scheme: "https".into(),
                    port: None,
                    template: "Authorization: token {{GITHUB_API_KEY}}".into(),
                },
                secrets: vec![],
            },
        )
        .unwrap();
    assert!(matches!(
        broker.decide(&session_id, UiDecision::AllowSession, &ctx()),
        Err(CoreError::ApprovalConnectionChanged)
    ));
    assert!(broker.grants_for_connection(&conn).is_empty());
    broker
        .decide(&session_id, UiDecision::Deny, &ctx())
        .unwrap();
    let Parked::Wait(session_waiter) = session_waiter else {
        panic!()
    };
    assert_eq!(session_waiter.wait().await.unwrap().status, 403);
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
        .find(|e| e.text.starts_with("Service deleted"))
        .unwrap();
    assert_eq!(deleted.confirmation, Some(ConfirmationMethod::Waived));

    // In-use secrets are refused before the user is asked to authenticate.
    let secret = broker.store.secret_by_name("GITHUB_API_KEY").unwrap();
    broker.ui_delete_secret(&secret.id).unwrap();
    assert_eq!(events.confirms.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn connection_add_preflight_rejects_failures_before_confirmation() {
    let events = Arc::new(GateEvents {
        allow: true,
        confirms: AtomicUsize::new(0),
    });
    let (broker, _dir) = broker_with(events.clone()).await;
    let existing = add_github(&broker);
    let api_spec = |name: &str, host: &str, template: &str| ConnectionSpec {
        name: name.into(),
        config: ConnectionConfig::Api {
            host: host.into(),
            scheme: "https".into(),
            port: None,
            template: template.into(),
        },
        secrets: vec![],
    };

    let duplicate = broker
        .ui_add_connection(api_spec(
            &existing.name,
            "api.example.com",
            "Authorization: Bearer {{GITHUB_API_KEY}}",
        ))
        .unwrap_err();
    assert!(matches!(duplicate, CoreError::ConnectionNameTaken(_)));

    let invalid_target = broker
        .ui_add_connection(api_spec(
            "invalid-target",
            "https://api.example.com",
            "Authorization: Bearer {{GITHUB_API_KEY}}",
        ))
        .unwrap_err();
    assert!(matches!(
        invalid_target,
        CoreError::InvalidConnectionField { .. }
    ));

    let unknown_credential = broker
        .ui_add_connection(api_spec(
            "unknown-credential",
            "api.example.com",
            "Authorization: Bearer {{MISSING_TOKEN}}",
        ))
        .unwrap_err();
    assert!(matches!(
        unknown_credential,
        CoreError::UnknownTemplateRef(_)
    ));

    let duplicate_credential = broker
        .ui_add_connection_with_secret(
            "GITHUB_API_KEY",
            Zeroizing::new("replacement".into()),
            api_spec(
                "duplicate-credential",
                "api.example.com",
                "Authorization: Bearer {{GITHUB_API_KEY}}",
            ),
        )
        .unwrap_err();
    assert!(matches!(
        duplicate_credential,
        CoreError::SecretNameTaken(_)
    ));

    let unbound_new_credential = broker
        .ui_add_connection_with_secret(
            "NEW_TOKEN",
            Zeroizing::new("new-token".into()),
            api_spec(
                "unbound-new-credential",
                "api.example.com",
                "Authorization: Bearer {{GITHUB_API_KEY}}",
            ),
        )
        .unwrap_err();
    assert!(matches!(
        unbound_new_credential,
        CoreError::InvalidConnectionConfig(_)
    ));

    assert_eq!(
        events.confirms.load(Ordering::SeqCst),
        0,
        "no invalid add should reach native authentication"
    );

    broker
        .ui_add_connection_with_secret(
            "NEW_TOKEN",
            Zeroizing::new("new-token".into()),
            api_spec(
                "valid-service",
                "api.example.com",
                "Authorization: Bearer {{NEW_TOKEN}}",
            ),
        )
        .unwrap();
    assert_eq!(
        events.confirms.load(Ordering::SeqCst),
        1,
        "a valid add still authenticates exactly once"
    );
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
async fn secret_binding_changes_confirm_but_noop_updates_do_not() {
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
        })
        .unwrap();

    let rebound = broker
        .ui_update_connection(
            &conn.id,
            ConnectionSpec {
                name: conn.name.clone(),
                config: conn.config.clone(),
                secrets: vec![second.id],
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
            },
        )
        .unwrap();
    assert_eq!(
        events.confirms.load(Ordering::SeqCst),
        1,
        "an identical update must not request another confirmation"
    );
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

    // Re-enabling the stricter read gate is not security-reducing.
    broker.ui_change_reauth_on_read(true).unwrap();
    assert_eq!(events.confirms.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn settings_changes_are_not_added_to_the_activity_log() {
    let events = Arc::new(GateEvents {
        allow: true,
        confirms: AtomicUsize::new(0),
    });
    let (broker, _dir) = broker_with(events.clone()).await;

    broker.ui_change_reauth_on_read(false).unwrap();
    broker.ui_set_menu_bar_hides_dock(true).unwrap();
    assert_eq!(events.confirms.load(Ordering::SeqCst), 1);
    let recent = broker.audit.recent(10);
    assert!(
        recent
            .iter()
            .all(|entry| entry.kind != agentmfa_core::audit::AuditKind::SettingsChanged),
        "{recent:?}"
    );
}

#[tokio::test]
async fn prefix_reveals_are_not_added_to_the_activity_log() {
    let events = Arc::new(UnifiedAuthEvents {
        decision_confirms: AtomicUsize::new(0),
        secret_read_confirms: AtomicUsize::new(0),
    });
    let (broker, _dir) = broker_with(events.clone()).await;
    let secret = broker
        .store
        .add_secret("TOKEN", Zeroizing::new("abcdefghijkl".into()))
        .unwrap();

    assert_eq!(
        broker.ui_reveal_secret_prefix(&secret.id).await.unwrap(),
        "abcdef…"
    );
    assert_eq!(events.secret_read_confirms.load(Ordering::SeqCst), 1);
    assert!(broker
        .audit
        .recent(10)
        .iter()
        .all(|entry| entry.kind != agentmfa_core::audit::AuditKind::SecretRevealed));
}

#[tokio::test]
async fn service_tests_are_not_added_to_the_activity_log() {
    let (broker, _dir) = broker_with(Arc::new(UnimplementedShell)).await;
    broker
        .store
        .add_secret("API_KEY", Zeroizing::new("bad\nvalue".into()))
        .unwrap();
    let connection = broker
        .store
        .add_connection(ConnectionSpec {
            name: "local-api".into(),
            config: ConnectionConfig::Api {
                host: "127.0.0.1".into(),
                scheme: "http".into(),
                port: None,
                template: "Authorization: Bearer {{API_KEY}}".into(),
            },
            secrets: vec![],
        })
        .unwrap();

    assert!(!broker.ui_test_connection(&connection.id).await.unwrap().ok);
    assert!(broker
        .audit
        .recent(10)
        .iter()
        .all(|entry| entry.kind != agentmfa_core::audit::AuditKind::ConnectionTested));
}

#[tokio::test]
async fn inherited_rules_are_removed_before_pairing_executes() {
    let events = Arc::new(GateEvents {
        allow: true,
        confirms: AtomicUsize::new(0),
    });
    let (broker, _dir) = broker_with(events.clone()).await;
    let conn = add_github(&broker);
    let client_id = Uuid::new_v4();
    broker
        .policy
        .record_rule(
            client_id,
            "claude-code",
            conn.id,
            agentmfa_core::types::PermissionScope::Full,
        )
        .unwrap();
    assert_eq!(broker.rules().len(), 1);

    let mut request = pair_request("claude-code", broker.inherited_for(&client_id));
    request.client_id = Some(client_id);
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
