//! TCP control-plane tests: the same daemon serving a network listener the
//! way a hosted broker does — remote-flavored discovery, no pairing, agent
//! and manage planes authenticated, and `/mcp` reverse-proxied to the
//! in-process host's loopback endpoint.

use std::sync::Arc;

use aka_core::broker::Broker;
use aka_core::config::BrokerConfig;
use aka_core::daemon::{self, ServeOptions};
use aka_core::events::BrokerEvents;
use aka_core::paths::Paths;
use aka_core::types::DecisionSurface;
use aka_core::vault::MemoryVault;
use serde_json::{json, Value};

struct TestEvents;

impl BrokerEvents for TestEvents {}

struct Harness {
    broker: Arc<Broker>,
    _daemon: daemon::DaemonHandle,
    base: String,
    manage_token: String,
    _dir: tempfile::TempDir,
}

async fn harness(public_url: Option<&str>) -> Harness {
    let config = BrokerConfig {
        version: "test".into(),
        ..BrokerConfig::default()
    };
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::under(dir.path());
    let broker = Broker::new(
        paths,
        Arc::new(MemoryVault::new()),
        config,
        Arc::new(TestEvents),
    )
    .await
    .unwrap();
    let manage_token = broker.identity.issue_manage_token().unwrap();
    let handle = daemon::serve_with(
        broker.clone(),
        ServeOptions {
            listen: Some("127.0.0.1:0".parse().unwrap()),
            public_url: public_url.map(String::from),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let base = format!("http://{}", handle.tcp_addr.unwrap());
    Harness {
        broker,
        _daemon: handle,
        base,
        manage_token,
        _dir: dir,
    }
}

/// C6. The plaintext development vault exists so a non-macOS checkout runs
/// without a master key; it announces itself in the log and nothing more. A
/// log line is not a boundary, so serving that broker to a network is refused
/// rather than warned about — while loopback, which is the same trust boundary
/// the Unix socket already has, still works.
#[tokio::test]
async fn a_plaintext_vault_refuses_to_serve_a_network() {
    async fn serve(options: ServeOptions) -> Result<daemon::DaemonHandle, String> {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::under(dir.path());
        paths.ensure().unwrap();
        let vault = aka_core::vault::FileVault::open(paths.dev_vault_file()).unwrap();
        let broker = Broker::new(
            paths,
            Arc::new(vault),
            BrokerConfig::default(),
            Arc::new(TestEvents),
        )
        .await
        .unwrap();
        assert!(broker.vault_is_plaintext_development());
        let served = daemon::serve_with(broker, options).await;
        // The directory must outlive the handle, so leak it deliberately
        // rather than letting the socket vanish underneath a live daemon.
        std::mem::forget(dir);
        served.map_err(|error| error.to_string())
    }

    for (label, options) in [
        (
            "control plane",
            ServeOptions {
                listen: Some("0.0.0.0:0".parse().unwrap()),
                ..Default::default()
            },
        ),
        (
            "data plane",
            ServeOptions {
                data_plane_listen: Some("0.0.0.0".parse().unwrap()),
                data_plane_insecure: true,
                ..Default::default()
            },
        ),
    ] {
        let error = serve(options)
            .await
            .err()
            .unwrap_or_else(|| panic!("{label}: a network bind must be refused"));
        assert!(
            error.contains("unencrypted") && error.contains("AKA_VAULT_KEY"),
            "{label}: the refusal must name the cause and the fix: {error}"
        );
    }

    // Loopback is the boundary the 0600 control socket already has, so it is
    // allowed — refusing it would break every non-macOS development run.
    serve(ServeOptions {
        listen: Some("127.0.0.1:0".parse().unwrap()),
        ..Default::default()
    })
    .await
    .expect("loopback stays available to a development vault");
}

async fn get_json(url: &str, bearer: Option<&str>) -> (u16, Value) {
    let client = reqwest::Client::new();
    let mut request = client.get(url);
    if let Some(token) = bearer {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    let response = request.send().await.unwrap();
    let status = response.status().as_u16();
    let text = response.text().await.unwrap();
    let value = serde_json::from_str(&text).unwrap_or(Value::String(text));
    (status, value)
}

#[tokio::test(flavor = "multi_thread")]
async fn tcp_discovery_is_remote_flavored_and_pair_is_refused() {
    let h = harness(Some("https://broker.example.dev")).await;

    let (status, manifest) =
        get_json(&format!("{}/.well-known/agent-broker.json", h.base), None).await;
    assert_eq!(status, 200, "{manifest}");
    assert_eq!(manifest["transport"], "http");
    assert_eq!(manifest["base_url"], "https://broker.example.dev");
    assert!(manifest.get("socket").is_none(), "no host-local paths");
    assert!(manifest.get("token_file").is_none());
    assert!(manifest["endpoints"].get("pair").is_none());
    assert!(manifest["endpoints"].get("ssh_open").is_none());
    assert!(!manifest["capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .any(|capability| capability == "ssh"));
    assert!(
        manifest.get("mcp_url").is_none(),
        "no MCP host is running yet"
    );

    // Pairing is refused on TCP with a distinct reason.
    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/v1/pair", h.base))
        .json(&json!({ "agent_name": "remote" }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 404);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["reason"], "not_served_remotely");

    // SSH agent sockets are broker-host-local capabilities. Even an
    // authenticated remote caller must not cause one to be created.
    let response = client
        .post(format!("{}/v1/ssh/open", h.base))
        .header(
            "authorization",
            format!("Bearer {}", h.broker.identity.token()),
        )
        .json(&json!({ "connection": "missing" }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 404);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["reason"], "not_served_remotely");

    // The instructions carry the network banner up front.
    let text = client
        .get(format!("{}/instructions", h.base))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(text.starts_with("> **You are reaching this broker over the network.**"));
    assert!(text.contains("https://broker.example.dev"));
}

#[tokio::test(flavor = "multi_thread")]
async fn both_planes_authenticate_over_tcp() {
    let h = harness(None).await;

    // Agent plane: the shared key works over TCP.
    let agent_key = h.broker.identity.token();
    let (status, body) = get_json(&format!("{}/v1/whoami", h.base), Some(&agent_key)).await;
    assert_eq!(status, 200, "{body}");

    // Manage plane: the manage token works over TCP; the agent key does not.
    let (status, body) = get_json(
        &format!("{}/v1/manage/whoami", h.base),
        Some(&h.manage_token),
    )
    .await;
    assert_eq!(status, 200, "{body}");

    // A successful manage mutation records the directly connected TCP peer
    // as remote decision provenance. It remains socket attribution, not a
    // claim that the peer is the human who possessed the management token.
    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/v1/manage/secrets", h.base))
        .header("authorization", format!("Bearer {}", h.manage_token))
        .json(&json!({ "name": "REMOTE_TEST", "value": "secret" }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let entry = h
        .broker
        .audit
        .recent(20)
        .into_iter()
        .find(|entry| entry.kind == aka_core::audit::AuditKind::SecretAdded)
        .expect("the remote mutation is audited");
    assert!(matches!(
        entry.surface,
        Some(DecisionSurface::Remote {
            peer: Some(peer)
        }) if peer.ip().is_loopback()
    ));
    assert!(
        entry
            .approver
            .as_deref()
            .is_some_and(|value| value.starts_with("127.0.0.1:")),
        "{entry:?}"
    );

    let (status, _) = get_json(&format!("{}/v1/manage/whoami", h.base), Some(&agent_key)).await;
    assert_eq!(status, 401);

    // Unauthenticated agent-plane calls still 401 over TCP.
    let (status, _) = get_json(&format!("{}/v1/connections", h.base), None).await;
    assert_eq!(status, 401);
}

#[tokio::test(flavor = "multi_thread")]
async fn mcp_is_reverse_proxied_to_the_loopback_host() {
    let h = harness(Some("https://broker.example.dev")).await;

    // Without an MCP host, /mcp answers 503 with a distinct reason.
    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/mcp", h.base))
        .json(&json!({ "jsonrpc": "2.0" }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 503);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["reason"], "mcp_unavailable");

    // Stand in a stub MCP host that echoes what it received.
    let stub = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = stub.local_addr().unwrap().port();
    let app = axum::Router::new().route(
        "/mcp",
        axum::routing::any(|request: axum::extract::Request| async move {
            let (parts, body) = request.into_parts();
            let bytes = axum::body::to_bytes(body, 1024 * 1024).await.unwrap();
            axum::Json(json!({
                "method": parts.method.as_str(),
                "authorization": parts
                    .headers
                    .get("authorization")
                    .and_then(|v| v.to_str().ok()),
                "body": String::from_utf8_lossy(&bytes),
            }))
        }),
    );
    tokio::spawn(async move {
        axum::serve(stub, app).await.unwrap();
    });
    h.broker.set_mcp_host_port(Some(port));

    // The manifest now advertises the proxied endpoint.
    let (_, manifest) = get_json(&format!("{}/.well-known/agent-broker.json", h.base), None).await;
    assert_eq!(manifest["mcp_path"], "/mcp");
    assert_eq!(manifest["mcp_url"], "https://broker.example.dev/mcp");

    // Requests ride through with method, bearer, and body intact.
    let response = client
        .post(format!("{}/mcp", h.base))
        .header("authorization", "Bearer aka_agent_key")
        .body(r#"{"jsonrpc":"2.0","method":"tools/list"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["method"], "POST");
    assert_eq!(body["authorization"], "Bearer aka_agent_key");
    assert_eq!(body["body"], r#"{"jsonrpc":"2.0","method":"tools/list"}"#);

    // The production Rust host also completes its authenticated handshake
    // through the public proxy (whose Host header differs from loopback).
    let host = aka_core::mcp_host::serve(h.broker.clone()).await.unwrap();
    h.broker.set_mcp_host_port(Some(host.addr().port()));
    let response = client
        .post(format!("{}/mcp", h.base))
        .bearer_auth(h.broker.identity.token())
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "proxy-test", "version": "1"},
            },
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    assert!(response.headers().get("mcp-session-id").is_some());
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["result"]["serverInfo"]["name"], "multitool");
}

#[tokio::test(flavor = "multi_thread")]
async fn data_plane_opens_advertise_the_configured_host() {
    // A broker serving remote agents advertises a reachable host in its
    // PG open responses instead of loopback, while still binding
    // loopback here (the bind address and the advertised host are separate
    // knobs; the test keeps the bind on loopback so it stays hermetic).
    let config = BrokerConfig {
        version: "test".into(),
        ..BrokerConfig::default()
    };
    let dir = tempfile::tempdir().unwrap();
    let broker = Broker::new(
        Paths::under(dir.path()),
        Arc::new(MemoryVault::new()),
        config,
        Arc::new(TestEvents),
    )
    .await
    .unwrap();
    let _daemon = daemon::serve_with(
        broker.clone(),
        ServeOptions {
            advertise_host: Some("broker.lan".into()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(broker.advertise_host(), "broker.lan");
    assert!(
        broker.data_plane_bind().is_loopback(),
        "bind stays loopback"
    );

    let agent_key = broker.identity.token();
    let socket = _daemon.socket_path.clone();

    // PG advertises the host in its DSN unconditionally (no upstream dial
    // at open time).
    broker
        .ui_add_secret("PGPW", zeroize::Zeroizing::new("pw".into()))
        .unwrap();
    let pg_secret = broker
        .store
        .list_secrets()
        .into_iter()
        .find(|s| s.name == "PGPW")
        .unwrap()
        .id;
    broker
        .ui_add_connection(aka_core::store::ConnectionSpec {
            name: "db".into(),
            config: aka_core::types::ConnectionConfig::Pg {
                host: "db.internal".into(),
                port: 5432,
                dbname: "app".into(),
                user: "app".into(),
                sslmode: aka_core::types::PgSslMode::Disable,
                trusted_ca_bundle_path: None,
            },
            secrets: vec![pg_secret],
        })
        .unwrap();
    let (status, body) = uds_json(
        &socket,
        "POST",
        "/v1/pg/open",
        &agent_key,
        json!({ "connection": "db" }),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let dsn = body["dsn"].as_str().unwrap();
    assert!(dsn.contains("@broker.lan:"), "{dsn}");
    assert_eq!(body["downstream_tls"], "not_supported");
    assert!(
        body["sslmode_note"]
            .as_str()
            .is_some_and(|note| note.contains("does not support TLS")),
        "{body}"
    );
}

async fn uds_json(
    socket: &std::path::Path,
    method: &str,
    path: &str,
    bearer: &str,
    body: Value,
) -> (u16, Value) {
    let stream = tokio::net::UnixStream::connect(socket).await.unwrap();
    let io = hyper_util::rt::TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
    tokio::spawn(conn);
    let request = hyper::Request::builder()
        .method(method)
        .uri(path)
        .header("host", "localhost")
        .header("authorization", format!("Bearer {bearer}"))
        .header("content-type", "application/json")
        .body(body.to_string())
        .unwrap();
    let response = sender.send_request(request).await.unwrap();
    let status = response.status().as_u16();
    use http_body_util::BodyExt as _;
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, value)
}

#[tokio::test(flavor = "multi_thread")]
async fn uds_discovery_is_unchanged_by_the_tcp_listener() {
    let h = harness(Some("https://broker.example.dev")).await;
    // The Unix socket keeps serving the local manifest with local paths and
    // the pair endpoint — TCP flavor must not leak across listeners.
    let socket = h._daemon.socket_path.clone();
    let stream = tokio::net::UnixStream::connect(&socket).await.unwrap();
    let io = hyper_util::rt::TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
    tokio::spawn(conn);
    let request = hyper::Request::builder()
        .method("GET")
        .uri("/.well-known/agent-broker.json")
        .header("host", "localhost")
        .body(String::new())
        .unwrap();
    let response = sender.send_request(request).await.unwrap();
    assert_eq!(response.status(), 200);
    use http_body_util::BodyExt as _;
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let manifest: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(manifest["transport"], "http-over-unix-socket");
    assert!(manifest.get("socket").is_some());
    assert_eq!(manifest["endpoints"]["pair"], "/v1/pair");
}

/// PG-4. The Postgres data plane declines every `SSLRequest`, so off loopback
/// the ticket, every statement, and every result cross the network in clear
/// text. That takes an explicit acknowledgement rather than a warning in a log
/// nobody reads — and the refusal has to name the flag that accepts it.
#[tokio::test]
async fn a_non_loopback_data_plane_is_refused_without_the_acknowledgement() {
    let dir = tempfile::tempdir().unwrap();
    let broker = Broker::new(
        Paths::under(dir.path()),
        Arc::new(MemoryVault::new()),
        BrokerConfig::default(),
        Arc::new(TestEvents),
    )
    .await
    .unwrap();

    let started = daemon::serve_with(
        broker.clone(),
        ServeOptions {
            data_plane_listen: Some("0.0.0.0".parse().unwrap()),
            ..Default::default()
        },
    )
    .await;
    let message = match started {
        Ok(_) => panic!("a plaintext data plane off loopback must not start silently"),
        Err(error) => error.to_string(),
    };
    assert!(message.contains("--data-plane-insecure"), "{message}");
    assert!(message.contains("plaintext"), "{message}");
}

/// With the acknowledgement it starts, because the operator has said they
/// understand what they are exposing.
#[tokio::test]
async fn the_acknowledgement_allows_a_non_loopback_data_plane() {
    let dir = tempfile::tempdir().unwrap();
    let broker = Broker::new(
        Paths::under(dir.path()),
        Arc::new(MemoryVault::new()),
        BrokerConfig::default(),
        Arc::new(TestEvents),
    )
    .await
    .unwrap();

    let handle = daemon::serve_with(
        broker.clone(),
        ServeOptions {
            data_plane_listen: Some("0.0.0.0".parse().unwrap()),
            data_plane_insecure: true,
            ..Default::default()
        },
    )
    .await
    .expect("the acknowledged bind starts");
    drop(handle);
}

/// Loopback is the default and needs no flag.
#[tokio::test]
async fn a_loopback_data_plane_needs_no_acknowledgement() {
    let dir = tempfile::tempdir().unwrap();
    let broker = Broker::new(
        Paths::under(dir.path()),
        Arc::new(MemoryVault::new()),
        BrokerConfig::default(),
        Arc::new(TestEvents),
    )
    .await
    .unwrap();

    let handle = daemon::serve_with(
        broker.clone(),
        ServeOptions {
            data_plane_listen: Some("127.0.0.1".parse().unwrap()),
            ..Default::default()
        },
    )
    .await
    .expect("loopback is fine");
    drop(handle);
}
