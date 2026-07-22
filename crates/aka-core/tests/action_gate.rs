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

/// Counts both gate kinds, so a test can tell an action-gate prompt from a
/// secret-read prompt and observe which one a later action rides.
struct CountingEvents {
    action_confirms: AtomicUsize,
    secret_read_confirms: AtomicUsize,
}

impl BrokerEvents for CountingEvents {
    fn confirm_secret_read(&self, _secret: &aka_core::types::SecretMeta) -> bool {
        self.secret_read_confirms.fetch_add(1, Ordering::SeqCst);
        true
    }

    fn confirm_action(&self, _description: &str) -> Option<ConfirmationMethod> {
        self.action_confirms.fetch_add(1, Ordering::SeqCst);
        Some(ConfirmationMethod::Waived)
    }
}

struct SerializedEvents {
    active: AtomicUsize,
    max_active: AtomicUsize,
    calls: AtomicUsize,
}

impl SerializedEvents {
    fn prompt(&self) {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.max_active.fetch_max(active, Ordering::SeqCst);
        std::thread::sleep(std::time::Duration::from_millis(75));
        self.active.fetch_sub(1, Ordering::SeqCst);
    }
}

impl BrokerEvents for SerializedEvents {
    fn confirm_secret_read(&self, _secret: &aka_core::types::SecretMeta) -> bool {
        self.prompt();
        true
    }

    fn confirm_action(&self, _description: &str) -> Option<ConfirmationMethod> {
        self.prompt();
        Some(ConfirmationMethod::Waived)
    }
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
                oauth: None,
            },
            secrets: vec![],
        })
        .unwrap()
}

#[tokio::test]
async fn unimplemented_shell_fails_closed_on_config_actions() {
    let (broker, _dir) = broker_with(Arc::new(UnimplementedShell)).await;
    let conn = add_github(&broker);

    // Attaching an already-stored secret to a new destination is the gated
    // escalation, and the unimplemented default fails closed.
    assert!(matches!(
        broker.ui_add_connection(ConnectionSpec {
            name: "github-second".into(),
            config: ConnectionConfig::Api {
                host: "api.example.com".into(),
                scheme: "https".into(),
                port: None,
                template: "Authorization: Bearer {{GITHUB_API_KEY}}".into(),
                mcp_path: None,
                oauth: None,
            },
            secrets: vec![],
        }),
        Err(CoreError::NotConfirmed)
    ));

    // Deleting a tool only narrows access: no gate, even on this shell.
    broker.ui_delete_connection(&conn.id).unwrap();
    assert!(broker.store.connection_by_id(&conn.id).is_err());
}

#[tokio::test]
async fn key_rotation_is_confirmed_and_closes_live_sessions() {
    let events = Arc::new(GateEvents {
        allow: true,
        confirms: AtomicUsize::new(0),
    });
    let (broker, _dir) = broker_with(events.clone()).await;
    let old_token = broker.identity.token();
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

    // Rotation touches the credential, so it always re-prompts.
    broker.ui_rotate_key().unwrap();
    assert_eq!(events.confirms.load(Ordering::SeqCst), 1);
    tokio::time::timeout(std::time::Duration::from_secs(1), notified)
        .await
        .expect("rotation should close live data-plane sessions");
    assert!(matches!(
        broker.data_plane.redeem(&ticket),
        Err(RedeemError::Expired)
    ));
    session.finish("key_rotated");
    assert_ne!(broker.identity.token(), old_token);
    let revoked = broker
        .audit
        .recent(10)
        .into_iter()
        .find(|entry| entry.kind == aka_core::audit::AuditKind::TokenRevoked)
        .expect("rotation should be audited");
    assert!(revoked.confirmation.is_some());
}

#[tokio::test]
async fn key_rotation_fails_closed_without_confirmation() {
    let events = Arc::new(GateEvents {
        allow: false,
        confirms: AtomicUsize::new(0),
    });
    let (broker, _dir) = broker_with(events.clone()).await;
    let before = broker.identity.token();
    assert!(matches!(
        broker.ui_rotate_key(),
        Err(CoreError::NotConfirmed)
    ));
    assert_eq!(broker.identity.token(), before);
}

#[tokio::test]
async fn one_confirmation_opens_the_presence_window_for_reads() {
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

    // The presence window that one authentication opened also covers other
    // user-plane reads (reveal, tests) for its duration.
    assert_eq!(
        &*broker.store.secret_value(&first.id).await.unwrap(),
        "first"
    );
    assert_eq!(events.secret_read_confirms.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn an_action_gate_prompt_opens_the_user_plane_presence_window() {
    // A full-authority native auth (here, key rotation) is the strongest
    // prompt there is; opening the presence window afterward keeps the "one OS
    // authentication keeps Multitool unlocked" model, so an immediately
    // following read or configuration change rides it instead of surprising
    // the user with a second prompt.
    let events = Arc::new(CountingEvents {
        action_confirms: AtomicUsize::new(0),
        secret_read_confirms: AtomicUsize::new(0),
    });
    let (broker, _dir) = broker_with(events.clone()).await;
    let conn = add_github(&broker);
    let secret = broker.store.secret_by_name("GITHUB_API_KEY").unwrap();

    broker.ui_rotate_key().unwrap();
    assert_eq!(events.action_confirms.load(Ordering::SeqCst), 1);

    // A following user-plane read rides the window the action gate opened…
    broker.ui_reveal_secret_prefix(&secret.id).await.unwrap();
    assert_eq!(events.secret_read_confirms.load(Ordering::SeqCst), 0);

    // …and so does a following gated configuration change (deleting the
    // now-unused secret), recorded honestly as a ridden authentication.
    broker.ui_delete_connection(&conn.id).unwrap();
    broker.ui_delete_secret(&secret.id).unwrap();
    assert_eq!(events.action_confirms.load(Ordering::SeqCst), 1);
    let deleted = broker
        .audit
        .recent(5)
        .into_iter()
        .find(|e| e.text.starts_with("Secret deleted"))
        .unwrap();
    assert_eq!(
        deleted.confirmation,
        Some(ConfirmationMethod::RecentAuthentication)
    );
}

#[tokio::test]
async fn copy_presence_does_not_authorize_configuration_changes() {
    let events = Arc::new(GateEvents {
        allow: true,
        confirms: AtomicUsize::new(0),
    });
    let (broker, _dir) = broker_with(events.clone()).await;
    let conn = add_github(&broker);
    let secret = broker.store.secret_by_name("GITHUB_API_KEY").unwrap();

    broker.ui_secret_value_for_copy(&secret.id).await.unwrap();
    // A gated capability change (retargeting the tool) must still prompt on
    // its own: copy presence covers reads, not configuration authority.
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
                    oauth: None,
                },
                secrets: vec![],
            },
        )
        .unwrap();

    assert_eq!(events.confirms.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn presence_prompts_are_globally_serialized_across_purposes() {
    let events = Arc::new(SerializedEvents {
        active: AtomicUsize::new(0),
        max_active: AtomicUsize::new(0),
        calls: AtomicUsize::new(0),
    });
    let (broker, _dir) = broker_with(events.clone()).await;
    let conn = add_github(&broker);
    let secret = broker.store.secret_by_name("GITHUB_API_KEY").unwrap();

    let copy_broker = broker.clone();
    let copy = tokio::spawn(async move {
        copy_broker
            .ui_secret_value_for_copy(&secret.id)
            .await
            .unwrap();
    });
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while events.active.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("copy prompt should start");

    let config_broker = broker.clone();
    let configure = tokio::task::spawn_blocking(move || {
        // A gated capability change: retarget the tool while the copy
        // prompt is still up.
        config_broker
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
                        oauth: None,
                    },
                    secrets: vec![],
                },
            )
            .unwrap();
    });
    copy.await.unwrap();
    configure.await.unwrap();

    assert_eq!(events.calls.load(Ordering::SeqCst), 2);
    assert_eq!(events.max_active.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn an_expired_presence_window_prompts_again() {
    let events = Arc::new(UnifiedAuthEvents {
        secret_read_confirms: AtomicUsize::new(0),
    });
    let (broker, _dir) = broker_with(events.clone()).await;
    // A zero-length window is stale the moment it is noted (store-level:
    // the UI command only offers the real choices).
    broker.store.set_presence_window_secs(0).unwrap();
    let secret = broker
        .store
        .add_secret("TOKEN", Zeroizing::new("abcdefghijkl".into()))
        .unwrap();

    broker.ui_secret_value_for_copy(&secret.id).await.unwrap();
    broker.ui_secret_value_for_copy(&secret.id).await.unwrap();
    assert_eq!(
        events.secret_read_confirms.load(Ordering::SeqCst),
        2,
        "each full-value copy outside the window authenticates"
    );
}

#[tokio::test]
async fn post_save_test_rides_the_add_confirmation() {
    let events = Arc::new(UnifiedAuthEvents {
        secret_read_confirms: AtomicUsize::new(0),
    });
    let (broker, _dir) = broker_with(events.clone()).await;
    let conn = broker
        .ui_add_connection_with_secret(
            "API_KEY",
            Zeroizing::new("k".into()),
            ConnectionSpec {
                name: "local-api".into(),
                config: ConnectionConfig::Api {
                    host: "127.0.0.1".into(),
                    scheme: "http".into(),
                    port: Some(9),
                    template: "Authorization: Bearer {{API_KEY}}".into(),
                    mcp_path: None,
                    oauth: None,
                },
                secrets: vec![],
            },
        )
        .unwrap();

    // Tests ride the agent-plane pre-authorization: the automatic post-save
    // test (and any later manual test) reads without prompting.
    let _ = broker.ui_test_connection(&conn.id).await.unwrap();
    let _ = broker.ui_test_connection(&conn.id).await.unwrap();
    assert_eq!(events.secret_read_confirms.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_manual_test_never_prompts() {
    let events = Arc::new(UnifiedAuthEvents {
        secret_read_confirms: AtomicUsize::new(0),
    });
    let (broker, _dir) = broker_with(events.clone()).await;
    broker
        .store
        .add_secret("A_KEY", Zeroizing::new("a".into()))
        .unwrap();
    broker
        .store
        .add_secret("B_KEY", Zeroizing::new("b".into()))
        .unwrap();
    let conn = broker
        .store
        .add_connection(ConnectionSpec {
            name: "local-api".into(),
            config: ConnectionConfig::Api {
                host: "127.0.0.1".into(),
                scheme: "http".into(),
                port: Some(9),
                template: "Authorization: Bearer {{A_KEY}}.{{B_KEY}}".into(),
                mcp_path: None,
                oauth: None,
            },
            secrets: vec![],
        })
        .unwrap();

    // Testing rides the same pre-authorization as the agent plane: any
    // enabled agent could open this connection promptlessly, so the user's
    // own Test button never re-authenticates either.
    let _ = broker.ui_test_connection(&conn.id).await.unwrap();
    assert_eq!(events.secret_read_confirms.load(Ordering::SeqCst), 0);
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

    // Deleting a tool only narrows access: no gate, and the audit entry
    // honestly carries no confirmation method.
    broker.ui_delete_connection(&conn.id).unwrap();
    assert_eq!(events.confirms.load(Ordering::SeqCst), 0);
    let recent = broker.audit.recent(5);
    let deleted = recent
        .iter()
        .find(|e| e.text.starts_with("Tool deleted"))
        .unwrap();
    assert_eq!(deleted.confirmation, None);

    // Deleting the now-unused secret destroys Keychain material: gated,
    // and the method is recorded.
    let secret = broker.store.secret_by_name("GITHUB_API_KEY").unwrap();
    broker.ui_delete_secret(&secret.id).unwrap();
    assert_eq!(events.confirms.load(Ordering::SeqCst), 1);
    let recent = broker.audit.recent(5);
    let deleted_secret = recent
        .iter()
        .find(|e| e.text.starts_with("Secret deleted"))
        .unwrap();
    assert_eq!(
        deleted_secret.confirmation,
        Some(ConfirmationMethod::Waived)
    );
}

#[tokio::test]
async fn the_presence_window_never_covers_weakening_the_gates() {
    let events = Arc::new(GateEvents {
        allow: true,
        confirms: AtomicUsize::new(0),
    });
    let (broker, _dir) = broker_with(events.clone()).await;
    let conn = add_github(&broker);

    // Open the window with a gated user-plane action (a capability change)…
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
                    oauth: None,
                },
                secrets: vec![],
            },
        )
        .unwrap();
    assert_eq!(events.confirms.load(Ordering::SeqCst), 1);

    // …which does not extend to disabling the read gate: that prompts on
    // its own, like every grant of new agent authority.
    broker.ui_change_reauth_on_read(false).unwrap();
    assert_eq!(events.confirms.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn presence_window_setting_is_validated_and_persisted() {
    let events = Arc::new(GateEvents {
        allow: true,
        confirms: AtomicUsize::new(0),
    });
    let (broker, _dir) = broker_with(events.clone()).await;
    assert_eq!(
        broker.settings().presence_window_secs,
        15 * 60,
        "defaults to 15 minutes"
    );

    assert!(matches!(
        broker.ui_set_presence_window(1234),
        Err(CoreError::InvalidSetting(_))
    ));
    assert_eq!(
        events.confirms.load(Ordering::SeqCst),
        0,
        "an invalid choice is refused before authentication"
    );

    broker.ui_set_presence_window(3600).unwrap();
    assert_eq!(broker.settings().presence_window_secs, 3600);
    assert_eq!(events.confirms.load(Ordering::SeqCst), 1);

    // Within the window the change itself rides it.
    broker.ui_set_presence_window(7200).unwrap();
    assert_eq!(broker.settings().presence_window_secs, 7200);
    assert_eq!(events.confirms.load(Ordering::SeqCst), 1);
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
            oauth: None,
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
        0,
        "a new-in-form credential is self-authorizing: no prompt"
    );

    // Attaching the already-stored secret to a new destination is the
    // escalation that still authenticates.
    broker
        .ui_add_connection(api_spec(
            "github-reuse",
            "api.other.example.com",
            "Authorization: Bearer {{GITHUB_API_KEY}}",
        ))
        .unwrap();
    assert_eq!(
        events.confirms.load(Ordering::SeqCst),
        1,
        "reusing a stored credential authenticates exactly once"
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
                    oauth: None,
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
    // The prefix is deliberately low-sensitivity: revealing it never
    // re-authenticates (the full-value copy keeps its gate).
    assert_eq!(events.secret_read_confirms.load(Ordering::SeqCst), 0);
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
                oauth: None,
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

/* ----------------------------- agent access -------------------------------- */

#[tokio::test]
async fn access_survives_key_rotation() {
    let events = Arc::new(GateEvents {
        allow: true,
        confirms: AtomicUsize::new(0),
    });
    let (broker, _dir) = broker_with(events.clone()).await;
    let conn = add_github(&broker);
    assert!(broker.ui_set_tool_access(&conn.id, false).unwrap());
    assert!(!broker.access.allows(&conn.id));

    // Rotation replaces the credential, not the policy.
    broker.ui_rotate_key().unwrap();
    assert!(!broker.access.allows(&conn.id));
    assert_eq!(broker.tool_access().len(), 1);
}

#[tokio::test]
async fn access_records_die_with_a_deleted_connection() {
    let events = Arc::new(GateEvents {
        allow: true,
        confirms: AtomicUsize::new(0),
    });
    let (broker, _dir) = broker_with(events.clone()).await;
    let conn = add_github(&broker);
    assert!(broker.ui_set_tool_access(&conn.id, false).unwrap());

    broker.ui_delete_connection(&conn.id).unwrap();
    assert_eq!(broker.tool_access().len(), 0);
}

#[tokio::test]
async fn target_changes_keep_the_flag_but_reset_the_tool_subset() {
    let events = Arc::new(GateEvents {
        allow: true,
        confirms: AtomicUsize::new(0),
    });
    let (broker, _dir) = broker_with(events.clone()).await;
    let conn = add_github(&broker);
    // A disabled tool with a curated subset (the subset names the *old*
    // upstream's tools).
    assert!(broker.ui_set_tool_access(&conn.id, false).unwrap());
    assert!(broker
        .ui_set_allowed_tools(&conn.id, Some(vec!["search".into()]))
        .unwrap());

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
                    oauth: None,
                },
                secrets: vec![],
            },
        )
        .unwrap();
    // A disabled tool must not silently re-enable on retarget…
    assert!(!broker.access.allows(&conn.id));
    // …but the curated subset named the old upstream's tools and is reset.
    assert_eq!(broker.access.allowed_tools(&conn.id), None);

    // A rename alone keeps everything: same destination, same authority.
    assert!(broker.ui_set_tool_access(&conn.id, true).unwrap());
    assert!(broker
        .ui_set_allowed_tools(&conn.id, Some(vec!["search".into()]))
        .unwrap());
    let current = broker.store.connection_by_id(&conn.id).unwrap();
    let renamed = broker
        .ui_update_connection(
            &conn.id,
            ConnectionSpec {
                name: "github-renamed".into(),
                config: current.config.clone(),
                secrets: current.secrets.clone(),
            },
        )
        .unwrap();
    assert_eq!(renamed.name, "github-renamed");
    assert!(broker.access.allows(&conn.id));
    assert_eq!(
        broker.access.allowed_tools(&conn.id),
        Some(vec!["search".into()])
    );
}

#[tokio::test]
async fn access_for_an_unknown_connection_is_refused() {
    let events = Arc::new(GateEvents {
        allow: true,
        confirms: AtomicUsize::new(0),
    });
    let (broker, _dir) = broker_with(events.clone()).await;
    add_github(&broker);

    // Unknown connection: an error, nothing persisted.
    assert!(broker
        .ui_set_tool_access(&uuid::Uuid::new_v4(), false)
        .is_err());
    assert_eq!(broker.tool_access().len(), 0);
}
