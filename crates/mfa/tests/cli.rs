use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;

use serde_json::{json, Value};

#[derive(Clone)]
struct Reply {
    method: &'static str,
    path: &'static str,
    body: Value,
}

fn read_request(mut stream: &TcpStream) -> String {
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        let read = stream.read(&mut chunk).unwrap();
        assert!(read > 0, "client closed before sending a complete request");
        bytes.extend_from_slice(&chunk[..read]);
        if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break index + 4;
        }
    };
    let headers = String::from_utf8_lossy(&bytes[..header_end]);
    let content_length = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().unwrap())
        })
        .unwrap_or(0);
    while bytes.len() < header_end + content_length {
        let read = stream.read(&mut chunk).unwrap();
        assert!(read > 0, "client closed before sending its request body");
        bytes.extend_from_slice(&chunk[..read]);
    }
    String::from_utf8(bytes).unwrap()
}

fn stub(replies: Vec<Reply>) -> (String, Arc<Mutex<Vec<String>>>, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let requests = Arc::new(Mutex::new(Vec::new()));
    let captured = requests.clone();
    let handle = thread::spawn(move || {
        for reply in replies {
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_request(&stream);
            let first = request.lines().next().unwrap_or_default();
            assert_eq!(first, format!("{} {} HTTP/1.1", reply.method, reply.path));
            captured.lock().unwrap().push(request);
            let body = serde_json::to_string(&reply.body).unwrap();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
        }
    });
    (url, requests, handle)
}

fn whoami() -> Reply {
    Reply {
        method: "GET",
        path: "/v1/manage/whoami",
        body: json!({
            "version": env!("CARGO_PKG_VERSION"),
            "approval_surface_attached": false
        }),
    }
}

fn run(args: &[&str], root: &std::path::Path, broker: Option<&str>, stdin: Option<&str>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_mfa"));
    command.args(args).env("AKA_MANAGE_TOKEN", "akamgr_test");
    if let Some(broker) = broker {
        command.args(["--broker", broker]);
    }
    command.args(["--root", root.to_str().unwrap()]);
    if stdin.is_some() {
        command.stdin(Stdio::piped());
    }
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    if let Some(stdin) = stdin {
        child
            .stdin
            .take()
            .unwrap()
            .write_all(stdin.as_bytes())
            .unwrap();
    }
    child.wait_with_output().unwrap()
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "status={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn connection() -> Value {
    json!({
        "id": "00000000-0000-0000-0000-000000000001",
        "name": "github",
        "updated_at": "version-1",
        "type": "api",
        "target": "https://api.github.com",
        "secret_names": ["GITHUB_TOKEN"],
        "oauth": false,
        "agent_access": {
            "enabled": true,
            "confirm": true,
            "allowed_tools": ["search"],
            "endpoint": null
        },
        "host": "api.github.com",
        "scheme": "https",
        "port": null,
        "template": "Authorization: Bearer {{GITHUB_TOKEN}}",
        "last_status": "ok",
        "last_detail": "Signed in",
        "last_checked_at": "2026-07-29T12:00:00Z"
    })
}

#[test]
fn status_is_machine_readable_and_classifies_a_missing_broker() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("data")).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_mfa"))
        .args(["--json", "status", "--root", root.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(3),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["running"], false);
    assert!(String::from_utf8_lossy(&output.stderr).contains("no broker is running"));
}

#[test]
fn remote_status_surfaces_structured_recent_ssh_refusals() {
    let root = tempfile::tempdir().unwrap();
    let (url, _, handle) = stub(vec![
        whoami(),
        Reply {
            method: "GET",
            path: "/v1/manage/identity",
            body: json!({
                "client_id": "00000000-0000-0000-0000-000000000001",
                "token_path": "/srv/aka/token",
                "socket_path": "/srv/aka/broker.sock",
                "minted_at": "2026-07-30T12:00:00Z",
                "last_used": "2026-07-30T12:00:00Z",
                "legacy_aliases": 0
            }),
        },
        Reply {
            method: "GET",
            path: "/v1/manage/connections",
            body: json!([]),
        },
        Reply {
            method: "GET",
            path: "/v1/manage/activity?limit=100",
            body: json!([{
                "icon": "lock",
                "tone": "warning",
                "kind": "denied",
                "text": "SSH agent connection refused: deploy",
                "detail": "agent access is disabled",
                "agent": "endpoint",
                "connection": "deploy",
                "outcome": "denied_by_policy",
                "protocol": "ssh",
                "duration_ms": null,
                "at": "2026-07-30T12:00:00Z"
            }]),
        },
    ]);
    let output = run(&["--json", "status"], root.path(), Some(&url), None);
    assert_success(&output);
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        report["recent_ssh_refusals"][0]["reason"],
        "denied_by_policy"
    );
    assert_eq!(report["recent_ssh_refusals"][0]["connection"], "deploy");
    handle.join().unwrap();
}

#[test]
fn json_mutations_are_rejected_instead_of_silently_ignoring_the_flag() {
    let root = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_mfa"))
        .args([
            "--json",
            "secret",
            "rm",
            "unused",
            "--root",
            root.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("--json is not supported"));
}

#[test]
fn explicit_missing_roots_are_not_created_by_mutations() {
    let parent = tempfile::tempdir().unwrap();
    let missing = parent.path().join("typo");
    let output = Command::new(env!("CARGO_BIN_EXE_mfa"))
        .args(["conn", "rm", "unused", "--root", missing.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("not an existing broker root"));
    assert!(!missing.exists(), "a typo must not create broker state");
}

#[test]
fn broker_url_environment_variable_matches_the_broker_flag() {
    let root = tempfile::tempdir().unwrap();
    let (url, _, handle) = stub(vec![
        whoami(),
        Reply {
            method: "GET",
            path: "/v1/manage/connections",
            body: json!([]),
        },
    ]);
    let output = Command::new(env!("CARGO_BIN_EXE_mfa"))
        .args([
            "--json",
            "conn",
            "list",
            "--root",
            root.path().to_str().unwrap(),
        ])
        .env("AKA_MANAGE_TOKEN", "akamgr_test")
        .env("AKA_BROKER_URL", &url)
        .output()
        .unwrap();
    assert_success(&output);
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap(),
        json!([])
    );
    handle.join().unwrap();
}

#[test]
fn broker_url_environment_cannot_bypass_local_only_root_guards() {
    let parent = tempfile::tempdir().unwrap();
    let missing = parent.path().join("typo");
    let output = Command::new(env!("CARGO_BIN_EXE_mfa"))
        .args(["manage", "token", "--root", missing.to_str().unwrap()])
        .env("AKA_BROKER_URL", "https://broker.example.test")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("not an existing broker root"));
    assert!(
        !missing.exists(),
        "the local-only command created a typoed root"
    );
}

#[test]
fn broker_url_environment_applies_to_agent_key_reads() {
    let root = tempfile::tempdir().unwrap();
    let (url, _, handle) = stub(vec![
        whoami(),
        Reply {
            method: "GET",
            path: "/v1/manage/identity/agent-key",
            body: json!({ "token": "aka_remote_key" }),
        },
    ]);
    let output = Command::new(env!("CARGO_BIN_EXE_mfa"))
        .args(["--json", "key", "--root", root.path().to_str().unwrap()])
        .env("AKA_MANAGE_TOKEN", "akamgr_test")
        .env("AKA_BROKER_URL", &url)
        .output()
        .unwrap();
    assert_success(&output);
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap()["key"],
        "aka_remote_key"
    );
    handle.join().unwrap();
}

#[test]
fn visibility_commands_project_sessions_requests_settings_and_connection_detail() {
    let root = tempfile::tempdir().unwrap();
    let cases = [
        (
            vec!["--json", "sessions"],
            Reply {
                method: "GET",
                path: "/v1/manage/sessions",
                body: json!([{
                    "id": 7, "type": "pg", "agent": "codex", "connection": "db",
                    "detail": "app@db.example/app", "opened_at": "2026-07-29T12:00:00Z"
                }]),
            },
            "7",
        ),
        (
            vec!["--json", "requests"],
            Reply {
                method: "GET",
                path: "/v1/manage/requests",
                body: json!([{
                    "id": "00000000-0000-0000-0000-000000000002",
                    "kind": "approval", "status": "pending", "connection": "github",
                    "agent": "codex", "summary": "GET /user", "waiting": 1,
                    "requested_at": "2026-07-29T12:00:00Z"
                }]),
            },
            "pending",
        ),
        (
            vec!["--json", "settings", "get"],
            Reply {
                method: "GET",
                path: "/v1/manage/settings",
                body: json!({
                    "menu_bar_hides_dock": false,
                    "confirm_ssh_host_keys": false
                }),
            },
            "confirm_ssh_host_keys",
        ),
        (
            vec!["--json", "conn", "show", "github"],
            Reply {
                method: "GET",
                path: "/v1/manage/connections",
                body: json!([connection()]),
            },
            "last_status",
        ),
    ];
    for (args, reply, needle) in cases {
        let (url, _, handle) = stub(vec![whoami(), reply]);
        let output = run(&args, root.path(), Some(&url), None);
        assert_success(&output);
        assert!(String::from_utf8_lossy(&output.stdout).contains(needle));
        handle.join().unwrap();
    }
}

#[test]
fn requests_can_approve_a_pending_confirmation_with_a_surface_lease() {
    let root = tempfile::tempdir().unwrap();
    let request_id = "00000000-0000-0000-0000-000000000002";
    let surface_id = "00000000-0000-0000-0000-000000000099";
    let (url, requests, handle) = stub(vec![
        whoami(),
        Reply {
            method: "POST",
            path: "/v1/manage/approval-surfaces",
            body: json!({
                "id": surface_id,
                "expires_in_ms": 15000,
            }),
        },
        Reply {
            method: "GET",
            path: "/v1/manage/approvals",
            body: json!([{
                "id": request_id,
                "connection_id": "00000000-0000-0000-0000-000000000003",
                "connection": "github",
                "type": "api",
                "target": "api.github.com",
                "agent": "codex",
                "summary": "GET /user",
                "waiting": 1,
                "requested_at": "2026-07-29T12:00:00Z",
                "expires_at": "2026-07-29T12:01:00Z",
                "window_secs": 300
            }]),
        },
        Reply {
            method: "GET",
            path: "/v1/manage/elicitations",
            body: json!([]),
        },
        Reply {
            method: "POST",
            path: "/v1/manage/approvals/00000000-0000-0000-0000-000000000002",
            body: json!({"answered": true}),
        },
        Reply {
            method: "DELETE",
            path: "/v1/manage/approval-surfaces/00000000-0000-0000-0000-000000000099",
            body: json!({"released": true}),
        },
    ]);
    let output = run(
        &["--json", "requests", "--approve", request_id],
        root.path(),
        Some(&url),
        None,
    );
    assert_success(&output);
    let body: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(body["decision"], "approved");
    assert_eq!(body["id"], request_id);
    handle.join().unwrap();
    let requests = requests.lock().unwrap();
    assert!(requests[4].contains(r#""decision":"approve_window""#));
}

#[test]
fn session_close_and_setting_updates_use_the_existing_management_contracts() {
    let root = tempfile::tempdir().unwrap();
    let (url, _, handle) = stub(vec![
        whoami(),
        Reply {
            method: "DELETE",
            path: "/v1/manage/sessions/7",
            body: json!({ "closed": true }),
        },
    ]);
    let output = run(
        &["--json", "sessions", "--close", "7"],
        root.path(),
        Some(&url),
        None,
    );
    assert_success(&output);
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap()["closed"],
        true
    );
    handle.join().unwrap();

    let (url, requests, handle) = stub(vec![
        whoami(),
        Reply {
            method: "PATCH",
            path: "/v1/manage/settings",
            body: json!({
                "menu_bar_hides_dock": false,
                "confirm_ssh_host_keys": false
            }),
        },
        Reply {
            method: "GET",
            path: "/v1/manage/settings",
            body: json!({
                "menu_bar_hides_dock": false,
                "confirm_ssh_host_keys": false
            }),
        },
    ]);
    let output = run(
        &[
            "--json",
            "settings",
            "set",
            "--menu-bar-hides-dock",
            "false",
        ],
        root.path(),
        Some(&url),
        None,
    );
    assert_success(&output);
    handle.join().unwrap();
    assert!(requests.lock().unwrap()[1].contains(r#""menu_bar_hides_dock":false"#));
}

#[test]
fn conn_update_sends_a_sparse_patch_instead_of_reconstructing_configuration() {
    let root = tempfile::tempdir().unwrap();
    let mut updated = connection();
    updated["host"] = json!("api2.github.com");
    updated["target"] = json!("https://api2.github.com");
    updated["updated_at"] = json!("version-2");
    let (url, requests, handle) = stub(vec![
        whoami(),
        Reply {
            method: "GET",
            path: "/v1/manage/connections",
            body: json!([connection()]),
        },
        Reply {
            method: "PATCH",
            path: "/v1/manage/connections/00000000-0000-0000-0000-000000000001/config",
            body: Value::Null,
        },
        Reply {
            method: "GET",
            path: "/v1/manage/connections",
            body: json!([updated]),
        },
    ]);
    let output = run(
        &["conn", "update", "github", "--host", "api2.github.com"],
        root.path(),
        Some(&url),
        None,
    );
    assert_success(&output);
    handle.join().unwrap();
    let request = &requests.lock().unwrap()[2];
    let body = request.split_once("\r\n\r\n").unwrap().1;
    let payload: Value = serde_json::from_str(body).unwrap();
    assert_eq!(payload["expected_updated_at"], "version-1");
    assert_eq!(payload["patch"]["host"], "api2.github.com");
    assert!(payload["patch"].get("mcp_path").is_none());
    assert!(payload["patch"].get("oauth").is_none());
    assert!(!body.contains("Authorization: Bearer"));
}

#[test]
fn secret_input_is_normalized_identically_from_stdin_and_environment() {
    let root = tempfile::tempdir().unwrap();
    for (from_env, value) in [(false, "line\n"), (true, "line\n")] {
        let (url, requests, handle) = stub(vec![
            whoami(),
            Reply {
                method: "POST",
                path: "/v1/manage/secrets",
                body: Value::Null,
            },
        ]);
        let mut command = Command::new(env!("CARGO_BIN_EXE_mfa"));
        command
            .env("AKA_MANAGE_TOKEN", "akamgr_test")
            .args(["secret", "add", "TOKEN", "--broker", &url, "--root"])
            .arg(root.path());
        if from_env {
            command
                .env("CLI_TEST_SECRET", value)
                .args(["--value-env", "CLI_TEST_SECRET"]);
        } else {
            command.stdin(Stdio::piped());
        }
        let mut child = command.spawn().unwrap();
        if !from_env {
            child
                .stdin
                .take()
                .unwrap()
                .write_all(value.as_bytes())
                .unwrap();
        }
        let output = child.wait_with_output().unwrap();
        assert_success(&output);
        handle.join().unwrap();
        let body = requests.lock().unwrap()[1]
            .split_once("\r\n\r\n")
            .unwrap()
            .1
            .to_string();
        assert_eq!(
            serde_json::from_str::<Value>(&body).unwrap()["value"],
            "line"
        );
    }
}

#[test]
fn remote_commands_fail_with_auth_exit_code_before_network_without_a_token() {
    let root = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_mfa"))
        .env_remove("AKA_MANAGE_TOKEN")
        .args([
            "settings",
            "get",
            "--broker",
            "http://127.0.0.1:9",
            "--root",
            root.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(4));
    assert!(String::from_utf8_lossy(&output.stderr).contains("no management token"));
}
