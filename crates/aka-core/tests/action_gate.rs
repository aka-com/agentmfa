//! The core-owned confirmation gate on configuration actions, plus the
//! broker-level wiring lifecycle. The broker itself demands the shell's
//! native confirmation through `BrokerEvents::confirm_action` before a
//! high-consequence configuration action takes effect — a shell (or a
//! compromised webview driving one) cannot apply them without passing
//! through the gate, and the gate fails closed when unimplemented.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use aka_core::broker::Broker;
use aka_core::config::BrokerConfig;
use aka_core::error::CoreError;
use aka_core::events::BrokerEvents;
use aka_core::paths::Paths;
use aka_core::sessions::{RedeemError, TicketPayload};
use aka_core::store::ConnectionSpec;
use aka_core::types::{ConfirmationMethod, Connection, ConnectionConfig, ConnectionKind};
use aka_core::vault::MemoryVault;
use zeroize::Zeroizing;

/// Counting gate: `allow: false` refuses every confirmation (and the
/// unimplemented-default case is covered by not overriding at all).
struct GateEvents {
    allow: bool,
    confirms: AtomicUsize,
}

struct UnifiedAuthEvents {
    secret_read_confirms: AtomicUsize,
}

impl BrokerEvents for UnifiedAuthEvents {
    fn confirm_secret_read(&self, _secret: &aka_core::types::SecretMeta) -> bool {
        self.secret_read_confirms.fetch_add(1, Ordering::SeqCst);
        true
    }

    fn confirm_action(&self, _description: &str) -> Option<ConfirmationMethod> {
        Some(ConfirmationMethod::Waived)
    }
}

impl BrokerEvents for GateEvents {
    fn confirm_secret_read(&self, _secret: &aka_core::types::SecretMeta) -> bool {
        true
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

                mcp_path: None,
            },
            secrets: vec![],
        })
        .unwrap()
}

#[tokio::test]
async fn unimplemented_shell_fails_closed_on_config_actions() {
    let (broker, _dir) = broker_with(Arc::new(UnimplementedShell)).await;
    let conn = add_github(&broker);

    assert!(matches!(
        broker.ui_delete_connection(&conn.id),
        Err(CoreError::NotConfirmed)
    ));
    assert!(broker.store.connection_by_id(&conn.id).is_ok());
}

#[tokio::test]
async fn agent_revocation_is_immediate_without_confirmation() {
    let events = Arc::new(GateEvents {
        allow: false,
        confirms: AtomicUsize::new(0),
    });
    let (broker, _dir) = broker_with(events.clone()).await;
    let (_, client) = broker.pairing.pair("claude-code").unwrap();
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
        .find(|entry| entry.kind == aka_core::audit::AuditKind::TokenRevoked)
        .expect("revocation should be audited");
    assert_eq!(revoked.confirmation, None);
}

#[tokio::test]
async fn copy_auth_is_reused_across_secrets_but_not_outside_copying() {
    let events = Arc::new(UnifiedAuthEvents {
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

    // The copy window is not a general secret-read authorization. A direct
    // broker read (a UI-plane read) still needs its own gate.
    assert_eq!(
        &*broker.store.secret_value(&first.id).await.unwrap(),
        "first"
    );
    assert_eq!(events.secret_read_confirms.load(Ordering::SeqCst), 2);
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
        .find(|e| e.text.starts_with("Tool deleted"))
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

            mcp_path: None,
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
        .find(|entry| entry.kind == aka_core::audit::AuditKind::ConnectionUpdated)
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

                    mcp_path: None,
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
        .find(|entry| entry.kind == aka_core::audit::AuditKind::ConnectionUpdated)
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
            .all(|entry| entry.kind != aka_core::audit::AuditKind::SettingsChanged),
        "{recent:?}"
    );
}

#[tokio::test]
async fn prefix_reveals_are_not_added_to_the_activity_log() {
    let events = Arc::new(UnifiedAuthEvents {
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
        .all(|entry| entry.kind != aka_core::audit::AuditKind::SecretRevealed));
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

                mcp_path: None,
            },
            secrets: vec![],
        })
        .unwrap();

    assert!(!broker.ui_test_connection(&connection.id).await.unwrap().ok);
    assert!(broker
        .audit
        .recent(10)
        .iter()
        .all(|entry| entry.kind != aka_core::audit::AuditKind::ConnectionTested));
}

/* ------------------------------- wirings ---------------------------------- */

#[tokio::test]
async fn revoking_an_agent_removes_its_wirings() {
    let events = Arc::new(GateEvents {
        allow: true,
        confirms: AtomicUsize::new(0),
    });
    let (broker, _dir) = broker_with(events.clone()).await;
    let conn = add_github(&broker);
    let (_, client) = broker.pairing.pair("claude-code").unwrap();
    assert!(broker.ui_set_wiring(&client.id, &conn.id, true).unwrap());
    assert_eq!(broker.wirings().len(), 1);

    assert!(broker.ui_revoke_agent(&client.id).unwrap());
    assert_eq!(broker.wirings().len(), 0);
}

#[tokio::test]
async fn wirings_die_with_a_deleted_connection() {
    let events = Arc::new(GateEvents {
        allow: true,
        confirms: AtomicUsize::new(0),
    });
    let (broker, _dir) = broker_with(events.clone()).await;
    let conn = add_github(&broker);
    let (_, client) = broker.pairing.pair("claude-code").unwrap();
    assert!(broker.ui_set_wiring(&client.id, &conn.id, true).unwrap());

    broker.ui_delete_connection(&conn.id).unwrap();
    assert_eq!(broker.wirings().len(), 0);
    assert!(!broker.wirings.is_wired(&client.id, &conn.id));
}

#[tokio::test]
async fn target_changes_drop_the_connection_wirings() {
    let events = Arc::new(GateEvents {
        allow: true,
        confirms: AtomicUsize::new(0),
    });
    let (broker, _dir) = broker_with(events.clone()).await;
    let conn = add_github(&broker);
    let (_, client) = broker.pairing.pair("claude-code").unwrap();
    assert!(broker.ui_set_wiring(&client.id, &conn.id, true).unwrap());

    // A wiring granted for one destination must not silently cover another.
    broker
        .ui_update_connection(
            &conn.id,
            ConnectionSpec {
                name: conn.name.clone(),
                config: ConnectionConfig::Api {
                    host: "api.enterprise.github.com".into(),
                    scheme: "https".into(),
                    port: None,
                    template: "Authorization: Bearer {{GITHUB_API_KEY}}".into(),

                    mcp_path: None,
                },
                secrets: vec![],
            },
        )
        .unwrap();
    assert!(!broker.wirings.is_wired(&client.id, &conn.id));

    // A rename alone keeps the wiring: same destination, same authority.
    let renamed = broker
        .ui_set_wiring(&client.id, &conn.id, true)
        .and_then(|_| {
            let current = broker.store.connection_by_id(&conn.id)?;
            broker.ui_update_connection(
                &conn.id,
                ConnectionSpec {
                    name: "github-renamed".into(),
                    config: current.config.clone(),
                    secrets: current.secrets.clone(),
                },
            )
        })
        .unwrap();
    assert_eq!(renamed.name, "github-renamed");
    assert!(broker.wirings.is_wired(&client.id, &conn.id));
}

#[tokio::test]
async fn wiring_an_unknown_agent_or_connection_is_refused() {
    let events = Arc::new(GateEvents {
        allow: true,
        confirms: AtomicUsize::new(0),
    });
    let (broker, _dir) = broker_with(events.clone()).await;
    let conn = add_github(&broker);
    let (_, client) = broker.pairing.pair("claude-code").unwrap();

    // Unknown agent: report false rather than persisting a dangling wiring.
    assert!(!broker
        .ui_set_wiring(&uuid::Uuid::new_v4(), &conn.id, true)
        .unwrap());
    // Unknown connection: an error, nothing persisted.
    assert!(broker
        .ui_set_wiring(&client.id, &uuid::Uuid::new_v4(), true)
        .is_err());
    assert_eq!(broker.wirings().len(), 0);
}
