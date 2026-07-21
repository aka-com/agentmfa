//! End-to-end WebSocket bridge tests: real daemon, real upstream WS echo
//! server, real stock WebSocket client against the bridge URL.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aka_core::broker::Broker;
use aka_core::config::BrokerConfig;
use aka_core::daemon;
use aka_core::events::BrokerEvents;
use aka_core::paths::Paths;
use aka_core::store::ConnectionSpec;
use aka_core::types::{ConfirmationMethod, ConnectionConfig, SecretMeta};
use aka_core::vault::MemoryVault;
use futures::{SinkExt as _, StreamExt as _};
use http_body_util::BodyExt as _;
use serde_json::{json, Value};
use tokio_tungstenite::tungstenite::handshake::server::{Request, Response as WsResponse};
use tokio_tungstenite::tungstenite::Message;
use zeroize::Zeroizing;

struct TestEvents {
    action_confirmations: Arc<AtomicUsize>,
}

impl BrokerEvents for TestEvents {
    fn confirm_secret_read(&self, _secret: &SecretMeta) -> bool {
        true
    }
    fn confirm_action(&self, _description: &str) -> Option<ConfirmationMethod> {
        self.action_confirmations.fetch_add(1, Ordering::SeqCst);
        Some(ConfirmationMethod::Waived)
    }
}

struct Harness {
    broker: Arc<Broker>,
    daemon: daemon::DaemonHandle,
    action_confirmations: Arc<AtomicUsize>,
    _dir: tempfile::TempDir,
}

async fn harness(config: BrokerConfig) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::under(dir.path());
    let action_confirmations = Arc::new(AtomicUsize::new(0));
    let broker = Broker::new(
        paths,
        Arc::new(MemoryVault::new()),
        config,
        Arc::new(TestEvents {
            action_confirmations: action_confirmations.clone(),
        }),
    )
    .await
    .unwrap();
    let daemon = daemon::serve(broker.clone()).await.unwrap();
    Harness {
        broker,
        daemon,
        action_confirmations,
        _dir: dir,
    }
}

/// Upstream echo server. Records the Authorization header (and URI) of each
/// accepted handshake.
struct EchoUpstream {
    port: u16,
    seen: Arc<Mutex<Vec<(String, String)>>>, // (uri, authorization)
}

async fn echo_upstream() -> EchoUpstream {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let seen_clone = seen.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let seen = seen_clone.clone();
            tokio::spawn(async move {
                #[allow(clippy::result_large_err)]
                let callback = |req: &Request, resp: WsResponse| {
                    let auth = req
                        .headers()
                        .get("authorization")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_string();
                    seen.lock().unwrap().push((req.uri().to_string(), auth));
                    Ok(resp)
                };
                let Ok(mut ws) = tokio_tungstenite::accept_hdr_async(stream, callback).await else {
                    return;
                };
                while let Some(Ok(msg)) = ws.next().await {
                    match msg {
                        Message::Text(t) => {
                            let echo = format!("echo:{t}");
                            if ws.send(Message::Text(echo.into())).await.is_err() {
                                break;
                            }
                        }
                        Message::Binary(b) => match ws.send(Message::Binary(b)).await {
                            Ok(()) => {}
                            Err(_) => break,
                        },
                        Message::Ping(p) => {
                            let _ = ws.send(Message::Pong(p)).await;
                        }
                        Message::Close(_) => break,
                        _ => {}
                    }
                }
            });
        }
    });
    EchoUpstream { port, seen }
}

fn add_ws_connection(broker: &Broker, port: u16) {
    broker
        .store
        .add_secret("STREAM_TOKEN", Zeroizing::new("wss-tok-8f31d2".into()))
        .unwrap();
    let tok = broker.store.secret_by_name("STREAM_TOKEN").unwrap();
    broker
        .store
        .add_connection(ConnectionSpec {
            name: "market-feed".into(),
            config: ConnectionConfig::Ws {
                url: format!("ws://127.0.0.1:{port}/feed"),
                template: None,
            },
            secrets: vec![tok.id],
        })
        .unwrap();
}

async fn uds_request(
    socket: &std::path::Path,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<Value>,
) -> (u16, Value) {
    let stream = tokio::net::UnixStream::connect(socket).await.unwrap();
    let io = hyper_util::rt::TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
    tokio::spawn(conn);
    let mut builder = hyper::Request::builder()
        .method(method)
        .uri(path)
        .header("host", "localhost");
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    let request = match body {
        Some(value) => builder
            .header("content-type", "application/json")
            .body(value.to_string())
            .unwrap(),
        None => builder.body(String::new()).unwrap(),
    };
    let response = sender.send_request(request).await.unwrap();
    let status = response.status().as_u16();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes)
            .unwrap_or(Value::String(String::from_utf8_lossy(&bytes).into_owned()))
    };
    (status, value)
}

impl Harness {
    async fn pair(&mut self) -> String {
        let (status, body) = uds_request(
            &self.daemon.socket_path,
            "POST",
            "/v1/pair",
            &[],
            Some(json!({"agent_name": "claude-code"})),
        )
        .await;
        assert_eq!(status, 200);
        let client = self.broker.pairing.get("claude-code").unwrap();
        let conn = self
            .broker
            .store
            .connection_by_name("market-feed")
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while !self.broker.wirings.is_wired(&client.id, &conn.id) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("first-agent wiring was not applied asynchronously");
        body["token"].as_str().unwrap().to_string()
    }

    /// POST /v1/ws/open (the first paired agent is auto-wired); returns
    /// the bridge URL.
    async fn open_ws(&mut self, token: &str) -> String {
        let auth = format!("Bearer {token}");
        let (status, body) = uds_request(
            &self.daemon.socket_path,
            "POST",
            "/v1/ws/open",
            &[("authorization", &auth)],
            Some(json!({"connection": "market-feed"})),
        )
        .await;
        assert_eq!(status, 200, "open failed: {body}");
        body["ws_url"].as_str().unwrap().to_string()
    }
}

#[tokio::test]
async fn open_bridge_pipe_frames_and_inject_credential() {
    let mut h = harness(BrokerConfig::default()).await;
    let up = echo_upstream().await;
    add_ws_connection(&h.broker, up.port);
    let token = h.pair().await;
    let ws_url = h.open_ws(&token).await;
    assert!(ws_url.starts_with("ws://127.0.0.1:"));
    assert!(ws_url.contains("/v1/ws/bridge/tkt_"));

    // A stock WebSocket client connects to the bridge URL.
    let (mut client, _) = tokio_tungstenite::connect_async(&ws_url).await.unwrap();
    client.send(Message::Text("hello".into())).await.unwrap();
    let reply = tokio::time::timeout(Duration::from_secs(5), client.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(reply, Message::Text("echo:hello".into()));

    // Binary frames pipe verbatim.
    client
        .send(Message::Binary(vec![1u8, 2, 3].into()))
        .await
        .unwrap();
    let reply = tokio::time::timeout(Duration::from_secs(5), client.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(reply, Message::Binary(vec![1u8, 2, 3].into()));

    // The upstream saw the injected credential; the agent never did.
    let seen = up.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].1, "Bearer wss-tok-8f31d2");

    // Live session is listed for the UI.
    let sessions = h.broker.sessions();
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].connection, "market-feed");

    // Client close tears the session down.
    client.send(Message::Close(None)).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while !h.broker.sessions().is_empty() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("session should end after client close");
}

#[tokio::test]
async fn one_ticket_redeems_many_times() {
    let mut h = harness(BrokerConfig::default()).await;
    let up = echo_upstream().await;
    add_ws_connection(&h.broker, up.port);
    let token = h.pair().await;
    let ws_url = h.open_ws(&token).await;

    let (mut c1, _) = tokio_tungstenite::connect_async(&ws_url).await.unwrap();
    let (mut c2, _) = tokio_tungstenite::connect_async(&ws_url).await.unwrap();
    let (mut c3, _) = tokio_tungstenite::connect_async(&ws_url).await.unwrap();
    assert_eq!(h.broker.sessions().len(), 3);
    // Each session has its own upstream connection, all authenticated.
    assert_eq!(up.seen.lock().unwrap().len(), 3);
    for c in [&mut c1, &mut c2, &mut c3] {
        c.send(Message::Text("ping".into())).await.unwrap();
        let reply = tokio::time::timeout(Duration::from_secs(5), c.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(reply, Message::Text("echo:ping".into()));
    }
}

#[tokio::test]
async fn expired_ticket_is_rejected() {
    let config = BrokerConfig {
        ticket_ttl: Duration::from_millis(100),
        ..BrokerConfig::default()
    };
    let mut h = harness(config).await;
    let up = echo_upstream().await;
    add_ws_connection(&h.broker, up.port);
    let token = h.pair().await;
    let ws_url = h.open_ws(&token).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let err = tokio_tungstenite::connect_async(&ws_url).await.unwrap_err();
    match err {
        tokio_tungstenite::tungstenite::Error::Http(resp) => {
            assert_eq!(resp.status(), 410);
        }
        other => panic!("expected HTTP error, got {other:?}"),
    }
}

#[tokio::test]
async fn session_budgets_hit_with_distinct_reasons() {
    // Per-ticket cap of 1.
    let config = BrokerConfig {
        per_ticket_sessions: 1,
        ..BrokerConfig::default()
    };
    let mut h = harness(config).await;
    let up = echo_upstream().await;
    add_ws_connection(&h.broker, up.port);
    let token = h.pair().await;
    let ws_url = h.open_ws(&token).await;
    let (_c1, _) = tokio_tungstenite::connect_async(&ws_url).await.unwrap();
    let err = tokio_tungstenite::connect_async(&ws_url).await.unwrap_err();
    match err {
        tokio_tungstenite::tungstenite::Error::Http(resp) => {
            assert_eq!(resp.status(), 503);
            let body =
                String::from_utf8_lossy(resp.body().as_deref().unwrap_or_default()).into_owned();
            assert!(body.contains("ticket_session_limit"), "body: {body}");
        }
        other => panic!("expected HTTP error, got {other:?}"),
    }
}

#[tokio::test]
async fn idle_timeout_tears_down_but_pings_keep_alive() {
    let config = BrokerConfig {
        session_idle_timeout: Duration::from_millis(400),
        ..BrokerConfig::default()
    };
    let mut h = harness(config).await;
    let up = echo_upstream().await;
    add_ws_connection(&h.broker, up.port);
    let token = h.pair().await;
    let ws_url = h.open_ws(&token).await;

    // Session A: pings every 150 ms, stays alive well past the idle window.
    let (mut alive, _) = tokio_tungstenite::connect_async(&ws_url).await.unwrap();
    let keep = tokio::spawn(async move {
        for _ in 0..8 {
            tokio::time::sleep(Duration::from_millis(150)).await;
            if alive.send(Message::Ping(vec![1].into())).await.is_err() {
                return false;
            }
            // Drain any pong.
            let _ = tokio::time::timeout(Duration::from_millis(50), alive.next()).await;
        }
        true
    });
    // Session B: silent, torn down by the idle timeout.
    let (mut silent, _) = tokio_tungstenite::connect_async(&ws_url).await.unwrap();
    assert_eq!(h.broker.sessions().len(), 2);
    let closed = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            match silent.next().await {
                Some(Ok(Message::Close(_))) | None => break,
                _ => {}
            }
        }
    })
    .await;
    assert!(
        closed.is_ok(),
        "idle session should be closed by the broker"
    );
    assert!(keep.await.unwrap(), "pinging session must stay alive");
    assert_eq!(
        h.broker.sessions().len(),
        1,
        "only the pinging session survives"
    );
}

#[tokio::test]
async fn user_close_control_drops_the_agent_connection() {
    let mut h = harness(BrokerConfig::default()).await;
    let up = echo_upstream().await;
    add_ws_connection(&h.broker, up.port);
    let token = h.pair().await;
    let ws_url = h.open_ws(&token).await;
    let (mut client, _) = tokio_tungstenite::connect_async(&ws_url).await.unwrap();
    let sessions = h.broker.sessions();
    assert_eq!(sessions.len(), 1);

    let confirmations_before = h.action_confirmations.load(Ordering::SeqCst);
    assert!(h.broker.ui_close_session(sessions[0].id).unwrap());
    assert_eq!(
        h.action_confirmations.load(Ordering::SeqCst),
        confirmations_before,
        "closing a session must not request OS authentication"
    );
    let closed = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            match client.next().await {
                Some(Ok(Message::Close(_))) | None => break,
                _ => {}
            }
        }
    })
    .await;
    assert!(
        closed.is_ok(),
        "user close must drop the agent's connection"
    );
    tokio::time::timeout(Duration::from_secs(3), async {
        while !h.broker.sessions().is_empty() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    // Closing a gone session reports false.
    assert!(!h.broker.ui_close_session(sessions[0].id).unwrap());
}

#[tokio::test]
async fn open_coalesces_on_request_id_and_replays_ticket() {
    let mut h = harness(BrokerConfig::default()).await;
    let up = echo_upstream().await;
    add_ws_connection(&h.broker, up.port);
    let token = h.pair().await;

    let payload = json!({"connection": "market-feed", "request_id": "open-1"});
    let socket = h.daemon.socket_path.clone();
    let auth = format!("Bearer {token}");
    let (a1, p1) = (auth.clone(), payload.clone());
    let call1 = tokio::spawn(async move {
        uds_request(
            &socket,
            "POST",
            "/v1/ws/open",
            &[("authorization", &a1)],
            Some(p1),
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    let socket = h.daemon.socket_path.clone();
    let (a2, p2) = (auth.clone(), payload.clone());
    let call2 = tokio::spawn(async move {
        uds_request(
            &socket,
            "POST",
            "/v1/ws/open",
            &[("authorization", &a2)],
            Some(p2),
        )
        .await
    });

    let ((s1, b1), (s2, b2)) = (call1.await.unwrap(), call2.await.unwrap());
    assert_eq!((s1, s2), (200, 200));
    // One execution → the same ticket for every waiter.
    assert_eq!(b1["ws_url"], b2["ws_url"]);
    // Only one upstream dial happened at open time.
    assert_eq!(up.seen.lock().unwrap().len(), 1);

    // A late retry replays the same ticket without re-executing.
    let (status, b3) = uds_request(
        &h.daemon.socket_path,
        "POST",
        "/v1/ws/open",
        &[("authorization", &auth)],
        Some(payload),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(b3["ws_url"], b1["ws_url"]);
    assert_eq!(up.seen.lock().unwrap().len(), 1);
}
