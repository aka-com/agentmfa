//! WebSocket capability, `POST /v1/ws/open` + local bridge (DESIGN.md §4.2).
//!
//! WebSockets are long-lived, so instead of an envelope the broker acts as a
//! local bridge: policy/approval runs once at open time; the broker dials
//! the connection's configured URL with the credential injected and hands
//! back `ws://127.0.0.1:<port>/v1/ws/bridge/<ticket>`. The agent connects
//! any stock WebSocket client to that URL and the broker pipes frames
//! verbatim. The bridge binds an OS-assigned ephemeral loopback port at
//! daemon start, surfaced only in open responses.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::{CloseFrame as AxumCloseFrame, Message as AxumMessage, WebSocket};
use axum::extract::{Path, State, WebSocketUpgrade};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Json;
use futures::{SinkExt as _, StreamExt as _};
use serde_json::json;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::CloseFrame as TCloseFrame;
use tokio_tungstenite::tungstenite::Message as TMessage;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

use crate::broker::Broker;
use crate::capability::http::{injection_form, InjectionForm};
use crate::sessions::SessionHandle;
use crate::store::Store;
use crate::template::Template;
use crate::types::{Connection, ConnectionConfig, ConnectionKind};

pub type WsUpstream = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// Dial the connection's configured URL with the stored credential injected
/// (as a header or URL token, per the connection's config; default
/// `Authorization: Bearer <secret>`).
pub async fn dial_upstream(
    store: &Arc<Store>,
    connection: &Connection,
) -> Result<WsUpstream, String> {
    let ConnectionConfig::Ws { url, template } = &connection.config else {
        return Err("not a websocket connection".into());
    };
    let mut url = url::Url::parse(url).map_err(|e| format!("bad url: {e}"))?;
    let mut header: Option<(String, String)> = None;
    match template {
        None => {
            let secret_id = connection
                .secrets
                .first()
                .ok_or_else(|| "connection binds no secret".to_string())?;
            let value = store
                .secret_value(secret_id)
                .await
                .map_err(|e| format!("credential unavailable: {e}"))?;
            header = Some(("Authorization".into(), format!("Bearer {}", &*value)));
        }
        Some(src) => {
            let parsed = Template::parse(src).map_err(|e| e.to_string())?;
            let rendered = store
                .render_template(&parsed)
                .await
                .map_err(|e| format!("credential unavailable: {e}"))?;
            let trimmed = rendered.trim_start();
            match injection_form(src) {
                Some(InjectionForm::Query) => {
                    let fragment = trimmed.trim_start_matches('?');
                    let combined = match url.query() {
                        Some(q) if !q.is_empty() => format!("{q}&{fragment}"),
                        _ => fragment.to_string(),
                    };
                    url.set_query(Some(&combined));
                }
                Some(InjectionForm::Header { .. }) => {
                    let (name, value) = trimmed
                        .split_once(':')
                        .ok_or_else(|| "template must render 'Header: value'".to_string())?;
                    header = Some((name.trim().to_string(), value.trim().to_string()));
                }
                None => return Err("bad ws template".into()),
            }
        }
    }

    let mut request = url
        .as_str()
        .into_client_request()
        .map_err(|e| format!("bad request: {e}"))?;
    if let Some((name, value)) = header {
        let name = http::HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| "rendered header name invalid".to_string())?;
        let value = http::HeaderValue::from_str(&value)
            .map_err(|_| "rendered header value invalid".to_string())?;
        request.headers_mut().insert(name, value);
    }
    let (stream, _response) = tokio_tungstenite::connect_async(request)
        .await
        .map_err(|e| format!("upstream connect failed: {e}"))?;
    Ok(stream)
}

/* ------------------------------- bridge ---------------------------------- */

#[derive(Clone)]
struct BridgeState {
    broker: Arc<Broker>,
}

/// Start the WS bridge listener on an OS-assigned ephemeral loopback port.
/// Returns the bound port and the serve task handle.
pub async fn start_bridge(
    broker: Arc<Broker>,
) -> std::io::Result<(u16, tokio::task::JoinHandle<()>)> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    let app = axum::Router::new()
        .route("/v1/ws/bridge/{ticket}", get(bridge_handler))
        .with_state(BridgeState { broker });
    let task = tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            tracing::error!("ws bridge exited: {e}");
        }
    });
    Ok((port, task))
}

async fn bridge_handler(
    State(state): State<BridgeState>,
    Path(ticket): Path<String>,
    upgrade: WebSocketUpgrade,
) -> Response {
    let broker = state.broker;
    // Redeem: expiry, single-use, and the two-level session budget are all
    // enforced here, failing fast with the reason (§4.2/§8).
    let mut redemption = match broker.data_plane.redeem(&ticket) {
        Ok(r) => r,
        Err(e) => {
            let status = axum::http::StatusCode::from_u16(e.status())
                .unwrap_or(axum::http::StatusCode::GONE);
            return (status, Json(json!({ "reason": e.reason() }))).into_response();
        }
    };

    // First redemption claims the upstream dialed at open time; later
    // redemptions (multi-connect) dial their own (§4.2).
    let upstream = match redemption.payload_ws_upstream.take() {
        Some(upstream) => upstream,
        None => match crate::authorization::scope_existing(
            redemption.secret_read_authorization.clone(),
            dial_upstream(&broker.store, &redemption.connection),
        )
        .await
        {
            Ok(upstream) => upstream,
            Err(e) => {
                // Redemption drops → budget slot released.
                return (
                    axum::http::StatusCode::BAD_GATEWAY,
                    Json(json!({ "reason": "upstream_connect_failed", "detail": e })),
                )
                    .into_response();
            }
        },
    };

    let session = redemption.start(ConnectionKind::Ws);
    let max_ttl = broker.config.session_max_ttl;
    let idle = broker.config.session_idle_timeout;
    upgrade.on_upgrade(move |client| pipe(client, upstream, session, max_ttl, idle))
}

fn to_tungstenite(msg: AxumMessage) -> TMessage {
    match msg {
        AxumMessage::Text(t) => TMessage::Text(t.as_str().into()),
        AxumMessage::Binary(b) => TMessage::Binary(b),
        AxumMessage::Ping(b) => TMessage::Ping(b),
        AxumMessage::Pong(b) => TMessage::Pong(b),
        AxumMessage::Close(frame) => TMessage::Close(frame.map(|f| TCloseFrame {
            code: CloseCode::from(f.code),
            reason: f.reason.as_str().into(),
        })),
    }
}

fn to_axum(msg: TMessage) -> Option<AxumMessage> {
    match msg {
        TMessage::Text(t) => Some(AxumMessage::Text(t.as_str().into())),
        TMessage::Binary(b) => Some(AxumMessage::Binary(b)),
        TMessage::Ping(b) => Some(AxumMessage::Ping(b)),
        TMessage::Pong(b) => Some(AxumMessage::Pong(b)),
        TMessage::Close(frame) => Some(AxumMessage::Close(frame.map(|f| AxumCloseFrame {
            code: f.code.into(),
            reason: f.reason.as_str().into(),
        }))),
        // Raw frames never surface from a read.
        TMessage::Frame(_) => None,
    }
}

fn message_len(msg: &TMessage) -> u64 {
    match msg {
        TMessage::Text(t) => t.len() as u64,
        TMessage::Binary(b) | TMessage::Ping(b) | TMessage::Pong(b) => b.len() as u64,
        _ => 0,
    }
}

/// Pipe frames verbatim in both directions with the session lifetime rules
/// (§4.2): max TTL, idle timeout (ping/pong counts as activity), user
/// close, and either side closing tears down both legs.
async fn pipe(
    client: WebSocket,
    upstream: WsUpstream,
    session: SessionHandle,
    max_ttl: Duration,
    idle: Duration,
) {
    let (mut client_tx, mut client_rx) = client.split();
    let (mut upstream_tx, mut upstream_rx) = upstream.split();
    let ttl_deadline = tokio::time::Instant::now() + max_ttl;
    let mut idle_deadline = tokio::time::Instant::now() + idle;
    let close_signal = session.close_signal.clone();

    let reason = loop {
        tokio::select! {
            _ = close_signal.notified() => {
                let _ = client_tx
                    .send(AxumMessage::Close(Some(AxumCloseFrame {
                        code: 1000,
                        reason: "closed from AgentMFA".into(),
                    })))
                    .await;
                let _ = upstream_tx.send(TMessage::Close(None)).await;
                break "closed_by_user";
            }
            _ = tokio::time::sleep_until(ttl_deadline) => {
                let _ = client_tx.send(AxumMessage::Close(None)).await;
                let _ = upstream_tx.send(TMessage::Close(None)).await;
                break "session_ttl";
            }
            _ = tokio::time::sleep_until(idle_deadline) => {
                let _ = client_tx.send(AxumMessage::Close(None)).await;
                let _ = upstream_tx.send(TMessage::Close(None)).await;
                break "idle_timeout";
            }
            msg = client_rx.next() => {
                match msg {
                    Some(Ok(msg)) => {
                        idle_deadline = tokio::time::Instant::now() + idle;
                        let msg = to_tungstenite(msg);
                        session.bytes_up.fetch_add(message_len(&msg), Ordering::Relaxed);
                        let is_close = matches!(msg, TMessage::Close(_));
                        if upstream_tx.send(msg).await.is_err() || is_close {
                            break "client_closed";
                        }
                    }
                    _ => {
                        let _ = upstream_tx.send(TMessage::Close(None)).await;
                        break "client_closed";
                    }
                }
            }
            msg = upstream_rx.next() => {
                match msg {
                    Some(Ok(msg)) => {
                        idle_deadline = tokio::time::Instant::now() + idle;
                        session.bytes_down.fetch_add(message_len(&msg), Ordering::Relaxed);
                        let is_close = matches!(msg, TMessage::Close(_));
                        match to_axum(msg) {
                            Some(msg) => {
                                if client_tx.send(msg).await.is_err() || is_close {
                                    break "upstream_closed";
                                }
                            }
                            None => continue,
                        }
                    }
                    _ => {
                        let _ = client_tx.send(AxumMessage::Close(None)).await;
                        break "upstream_closed";
                    }
                }
            }
        }
    };
    session.finish(reason);
}
