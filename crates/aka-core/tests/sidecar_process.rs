//! The supervisor against the real sidecar bundle.
//!
//! The unit tests in `sidecar.rs` use a shell stub so they run anywhere.
//! This one runs the actual Node bundle, which is the only way to catch a
//! drift between the ready-line contract and what the sidecar prints. It
//! skips when the bundle or Node is absent for an ordinary local run. CI sets
//! `AGENTMFA_REQUIRE_SIDECAR=1`, making missing prerequisites a hard failure.

use std::path::PathBuf;
use std::time::Duration;

use aka_core::sidecar::{Sidecar, SidecarConfig};

fn bundle() -> Option<PathBuf> {
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../dist/sidecar/main.mjs")
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

fn sidecar_required() -> bool {
    std::env::var("AGENTMFA_REQUIRE_SIDECAR").as_deref() == Ok("1")
}

#[tokio::test]
async fn the_real_sidecar_announces_a_port_and_serves_health() {
    let Some(script) = bundle() else {
        assert!(
            !sidecar_required(),
            "AGENTMFA_REQUIRE_SIDECAR=1 but dist/sidecar/main.mjs is missing; run `npm run sidecar:build`"
        );
        eprintln!("skipping: no dist/sidecar/main.mjs (run `npm run sidecar:build`)");
        return;
    };
    if !have_node() {
        assert!(
            !sidecar_required(),
            "AGENTMFA_REQUIRE_SIDECAR=1 but node is not on PATH"
        );
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
    assert_eq!(
        endpoint.sidecar_version.as_deref(),
        Some(env!("CARGO_PKG_VERSION"))
    );
    assert!(!endpoint.version_skew);

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
    assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(body["broker_version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(body["version_skew"], false);

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
