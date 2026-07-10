//! Control-socket startup and shutdown invariants. These are separate from
//! the HTTP contract suite so lifecycle regressions are easy to run alone.

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::sync::Arc;

use agentmfa_core::broker::Broker;
use agentmfa_core::config::BrokerConfig;
use agentmfa_core::daemon;
use agentmfa_core::error::CoreError;
use agentmfa_core::events::NoopEvents;
use agentmfa_core::paths::Paths;
use agentmfa_core::vault::MemoryVault;

async fn broker(paths: Paths, vault: Arc<MemoryVault>) -> Arc<Broker> {
    Broker::new(paths, vault, BrokerConfig::default(), Arc::new(NoopEvents))
        .await
        .unwrap()
}

#[tokio::test]
async fn stale_control_socket_is_rebound_and_cleaned_on_drop() {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::under(dir.path());
    paths.ensure().unwrap();
    let socket = paths.socket_file();

    // Dropping a UnixListener leaves its filesystem rendezvous point behind
    // but makes connect return ECONNREFUSED: the one error startup may treat
    // as evidence of a stale socket.
    let stale = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    drop(stale);
    assert!(socket.exists());

    let handle = daemon::serve(broker(paths, Arc::new(MemoryVault::new())).await)
        .await
        .unwrap();
    tokio::net::UnixStream::connect(&socket).await.unwrap();

    drop(handle);
    assert!(!socket.exists(), "normal shutdown must unlink its socket");
}

#[tokio::test]
async fn live_foreign_socket_is_rejected_and_preserved() {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::under(dir.path());
    paths.ensure().unwrap();
    let socket = paths.socket_file();
    let foreign = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    let identity = std::fs::metadata(&socket).unwrap().ino();

    let result = Broker::new(
        paths.clone(),
        Arc::new(MemoryVault::new()),
        BrokerConfig::default(),
        Arc::new(NoopEvents),
    )
    .await;
    assert!(
        matches!(result, Err(CoreError::BrokerAlreadyRunning(_))),
        "a connectable pre-lock-era rendezvous point must be rejected before state opens"
    );
    assert_eq!(std::fs::metadata(&socket).unwrap().ino(), identity);
    assert!(
        !paths.audit_file().exists(),
        "legacy live-socket detection must happen before persistent state opens"
    );

    // The startup probe connected to this listener. It remains bound and can
    // accept that connection, proving the failed startup did not replace it.
    foreign.set_nonblocking(true).unwrap();
    foreign.accept().unwrap();
}

#[tokio::test]
async fn concurrent_starts_have_exactly_one_winner() {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::under(dir.path());
    let vault = Arc::new(MemoryVault::new());
    let construct = |paths: Paths, vault: Arc<MemoryVault>| async move {
        Broker::new(paths, vault, BrokerConfig::default(), Arc::new(NoopEvents)).await
    };

    // The lease is acquired in Broker::new, before audit/integrity/store are
    // opened. Exactly one construction attempt may reach daemon startup.
    let (left, right) = tokio::join!(
        construct(paths.clone(), vault.clone()),
        construct(paths.clone(), vault)
    );
    let (broker, loser) = match (left, right) {
        (Ok(broker), Err(loser)) | (Err(loser), Ok(broker)) => (broker, loser),
        (Ok(_), Ok(_)) => panic!("both brokers acquired the same instance lock"),
        (Err(left), Err(right)) => panic!("both brokers failed: {left}; {right}"),
    };
    assert!(matches!(loser, CoreError::BrokerAlreadyRunning(_)));
    let daemon = daemon::serve(broker.clone()).await.unwrap();
    tokio::net::UnixStream::connect(paths.socket_file())
        .await
        .unwrap();

    let lock_mode = std::fs::metadata(paths.broker_lock_file())
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(lock_mode & 0o777, 0o600);

    drop(daemon);
    assert!(!paths.socket_file().exists());
    drop(broker);
}

#[tokio::test]
async fn drop_does_not_unlink_a_replacement_socket() {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::under(dir.path());
    let socket = paths.socket_file();
    let handle = daemon::serve(broker(paths, Arc::new(MemoryVault::new())).await)
        .await
        .unwrap();
    let original_inode = std::fs::metadata(&socket).unwrap().ino();

    // Model an external supervisor replacing the rendezvous point without
    // participating in the broker's lock protocol.
    std::fs::remove_file(&socket).unwrap();
    let replacement = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    assert_ne!(std::fs::metadata(&socket).unwrap().ino(), original_inode);

    drop(handle);
    assert!(socket.exists(), "old handle removed a replacement socket");
    std::os::unix::net::UnixStream::connect(&socket).unwrap();
    drop(replacement);
}

#[tokio::test]
async fn non_socket_rendezvous_path_is_never_removed() {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::under(dir.path());
    paths.ensure().unwrap();
    let socket = paths.socket_file();
    std::fs::write(&socket, b"user-owned marker").unwrap();

    let result = Broker::new(
        paths,
        Arc::new(MemoryVault::new()),
        BrokerConfig::default(),
        Arc::new(NoopEvents),
    )
    .await;
    assert!(matches!(result, Err(CoreError::Io(_))));
    assert_eq!(std::fs::read(&socket).unwrap(), b"user-owned marker");
}
