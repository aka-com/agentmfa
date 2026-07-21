//! The supervisor against the real sidecar bundle.
//!
//! The unit tests in `sidecar.rs` use a shell stub so they run anywhere.
//! This one runs the actual Node bundle, which is the only way to catch a
//! drift between the ready-line contract and what the sidecar prints. It
//! skips when the bundle or Node is absent, so `cargo test` still passes on
//! a checkout that has not run `npm run sidecar:build`.

use std::path::PathBuf;
use std::time::Duration;

use aka_core::sidecar::{Sidecar, SidecarConfig};

fn bundle() -> Option<PathBuf> {
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../dist/sidecar/main.js")
        .canonicalize()
        .ok()?;
    script.is_file().then_some(script)
}

fn have_node() -> bool {
    std::process::Command::new("node")
        .arg("--version")
        .output()
        .is_ok_and(|out| out.status.success())
}

#[tokio::test]
async fn the_real_sidecar_announces_a_port_and_serves_health() {
    let Some(script) = bundle() else {
        eprintln!("skipping: no dist/sidecar/main.js (run `npm run sidecar:build`)");
        return;
    };
    if !have_node() {
        eprintln!("skipping: no node on PATH");
        return;
    }

    let dir = tempfile::tempdir().expect("tempdir");
    let sidecar = Sidecar::spawn(SidecarConfig {
        node: PathBuf::from("node"),
        script,
        broker_socket: dir.path().join("aka.sock"),
    });

    let endpoint = sidecar
        .wait_ready(Duration::from_secs(20))
        .await
        .expect("sidecar becomes ready");
    assert!(endpoint.port > 0);

    let client = reqwest::Client::new();
    let url = format!("{}/health", endpoint.base_url());

    // The token is the whole access control story on loopback, so prove
    // both sides of it.
    let denied = client.get(&url).send().await.expect("request");
    assert_eq!(denied.status(), 401, "no token must be refused");

    let wrong = client
        .get(&url)
        .bearer_auth("0".repeat(endpoint.token.len()))
        .send()
        .await
        .expect("request");
    assert_eq!(wrong.status(), 401, "a wrong token must be refused");

    let allowed = client
        .get(&url)
        .bearer_auth(&endpoint.token)
        .send()
        .await
        .expect("request");
    assert_eq!(allowed.status(), 200);
    let body: serde_json::Value = allowed.json().await.expect("json");
    assert_eq!(body["status"], "ok");

    // Dropping the supervisor must reap the process, not orphan it.
    let pid = body["pid"].as_u64().expect("pid") as i32;
    drop(sidecar);
    let reaped = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            // Signal 0 probes for existence without delivering anything.
            if unsafe { libc::kill(pid, 0) } != 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(reaped.is_ok(), "sidecar {pid} outlived its supervisor");
}
