//! Locating the sidecar's two files, and starting it.
//!
//! `aka_core::sidecar` owns the lifecycle but deliberately knows nothing
//! about where things live. That policy is here, because only the shell
//! knows whether it is running from a bundle or from `cargo`.

use std::path::PathBuf;
use std::time::Duration;

use aka_core::sidecar::{Sidecar, SidecarConfig};
use tauri::{AppHandle, Manager};

/// How long we wait for the first sidecar before logging that it is late.
/// Not fatal: the supervisor keeps retrying, and nothing in the app needs
/// the sidecar to start up.
const FIRST_READY: Duration = Duration::from_secs(20);

/// The Node binary. Bundled next to our own executable in a packaged app
/// (Tauri's `externalBin` puts it there); `node` on PATH during `cargo`
/// runs. `AKA_SIDECAR_NODE` overrides both, for testing against a
/// different runtime.
fn resolve_node() -> PathBuf {
    if let Some(path) = std::env::var_os("AKA_SIDECAR_NODE") {
        return PathBuf::from(path);
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(bundled) = exe.parent().map(|dir| dir.join("node")) {
            if bundled.is_file() {
                return bundled;
            }
        }
    }
    PathBuf::from("node")
}

/// The bundled entry script, or the `npm run sidecar:build` output when
/// running from a source checkout.
fn resolve_script(app: &AppHandle) -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("AKA_SIDECAR_SCRIPT") {
        return Some(PathBuf::from(path));
    }
    if let Ok(dir) = app.path().resource_dir() {
        let bundled = dir.join("sidecar/main.mjs");
        if bundled.is_file() {
            return Some(bundled);
        }
    }
    script_near(&std::env::current_exe().ok()?)
}

/// Find `dist/sidecar/main.mjs` by walking up from the executable — the
/// layout of a source checkout, where the shell runs out of
/// `src-tauri/target/<profile>/`. Walking rather than counting levels,
/// because a `--target` build nests one directory deeper.
fn script_near(exe: &std::path::Path) -> Option<PathBuf> {
    exe.ancestors()
        .map(|dir| dir.join("dist/sidecar/main.mjs"))
        .find(|candidate| candidate.is_file())
}

/// Start supervising the sidecar. Returns `None` when the script is
/// missing, which is the normal state of a checkout that has not run
/// `npm run sidecar:build` — the rest of the app works without it.
pub fn start(app: &AppHandle, broker_socket: PathBuf) -> Option<Sidecar> {
    let script = match resolve_script(app) {
        Some(script) => script,
        None => {
            tracing::info!(
                "sidecar script not found; MCP is unavailable \
                 (run `npm run sidecar:build`)"
            );
            return None;
        }
    };

    let sidecar = Sidecar::spawn(SidecarConfig {
        node: resolve_node(),
        script,
        broker_socket,
    });

    // Report the first startup, so a misconfigured runtime is visible in
    // the log rather than silently retried forever.
    let watch = sidecar.watch();
    tokio::spawn(async move {
        match watch.wait_ready(FIRST_READY).await {
            Ok(endpoint) => tracing::info!(port = endpoint.port, "sidecar listening"),
            Err(error) => tracing::warn!(%error, "sidecar has not started yet; still retrying"),
        }
    });

    Some(sidecar)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both layouts a source checkout produces, so a `--target` build is
    /// not silently left without a sidecar.
    #[test]
    fn the_checkout_script_is_found_at_either_build_depth() {
        let root = tempfile::tempdir().expect("tempdir");
        let script = root.path().join("dist/sidecar/main.mjs");
        std::fs::create_dir_all(script.parent().expect("parent")).expect("mkdir");
        std::fs::write(&script, "// bundle").expect("write");

        for relative in [
            "src-tauri/target/debug/aka-desktop",
            "src-tauri/target/aarch64-apple-darwin/release/aka-desktop",
        ] {
            let exe = root.path().join(relative);
            assert_eq!(
                script_near(&exe).as_deref(),
                Some(script.as_path()),
                "not found from {relative}"
            );
        }
    }

    #[test]
    fn an_unbuilt_checkout_resolves_to_nothing() {
        let root = tempfile::tempdir().expect("tempdir");
        let exe = root.path().join("src-tauri/target/debug/aka-desktop");
        assert_eq!(script_near(&exe), None);
    }
}
