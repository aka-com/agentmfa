//! The manage event stream: a resilient SSE subscriber.
//!
//! Connects to `/v1/manage/events`, parses `data:` frames into
//! [`ManageEvent`]s, and reports link state alongside — the shell renders
//! "connected" from this, so state changes are edge-triggered and honest:
//! `Connected` fires only after the stream is actually established, and
//! every disconnect carries the reason.

use std::time::Duration;

use aka_api::ManageEvent;
use futures::StreamExt as _;

use crate::RemoteBackend;

/// Link state, reported on every transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkState {
    Connected,
    /// Not connected; retrying with backoff. The message names the cause.
    Disconnected {
        message: String,
    },
}

/// Minimum/maximum reconnect backoff.
const MIN_BACKOFF: Duration = Duration::from_millis(500);
const MAX_BACKOFF: Duration = Duration::from_secs(15);

/// How long the stream may go silent before the link is declared dead. The
/// broker sends an SSE keep-alive comment every 15 seconds, so a healthy
/// link never approaches this; without it a connection dropped without a
/// FIN (sleep/wake, network change, an idle proxy) would keep the shell
/// showing "connected" forever while receiving nothing.
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// The broker emits a keep-alive every 15 seconds. Stop renewing before the
/// HTTP read timeout when the body path is buffered or black-holed even
/// though separate heartbeat requests still succeed.
const SURFACE_STREAM_FRESHNESS: Duration = Duration::from_millis(
    aka_api::APPROVAL_SURFACE_TTL_MS + aka_api::APPROVAL_SURFACE_HEARTBEAT_MS,
);
const SURFACE_READY_TIMEOUT: Duration = Duration::from_secs(5);

/// Subscribe forever as a passive observer (until the task is aborted):
/// connect, stream events, and reconnect with backoff. Observers receive
/// every change but do not claim they can display or answer approvals.
///
/// Reconnects resume rather than refetch: the last event id seen is sent as
/// `Last-Event-ID`, and the broker replays only the missed events (or, when
/// the client's position has aged out or the broker restarted, sends a
/// single [`ManageEvent::Resync`] itself). The synthetic resync is the
/// broker's to emit — this loop just forwards frames.
pub async fn subscribe(
    backend: std::sync::Arc<RemoteBackend>,
    on_event: impl FnMut(ManageEvent) + Send,
    on_state: impl FnMut(LinkState) + Send,
) {
    subscribe_inner(backend, false, on_event, on_state).await;
}

/// Subscribe as a desktop request surface. In addition to streaming events,
/// this advertises a visible Inbox and heartbeats its broker-minted
/// capability lease. If the stream or heartbeat path fails, the lease
/// expires and new confirmed traffic fails closed.
pub async fn subscribe_request_surface(
    backend: std::sync::Arc<RemoteBackend>,
    on_event: impl FnMut(ManageEvent) + Send,
    on_state: impl FnMut(LinkState) + Send,
) {
    subscribe_inner(backend, true, on_event, on_state).await;
}

async fn subscribe_inner(
    backend: std::sync::Arc<RemoteBackend>,
    request_surface: bool,
    mut on_event: impl FnMut(ManageEvent) + Send,
    mut on_state: impl FnMut(LinkState) + Send,
) {
    let mut backoff = MIN_BACKOFF;
    let mut state = None::<LinkState>;
    // The id of the last event delivered, carried across reconnects so the
    // broker knows where to resume from.
    let mut last_event_id: Option<String> = None;
    let mut transition = |next: LinkState, on_state: &mut dyn FnMut(LinkState)| {
        if state.as_ref() != Some(&next) {
            state = Some(next.clone());
            on_state(next);
        }
    };

    loop {
        match open_stream(&backend, last_event_id.as_deref(), request_surface).await {
            Ok((mut stream, surface_id, client)) => {
                // A modern request surface becomes connected only after an
                // immediate SSE body marker crosses the full streaming path
                // and its first client-originated heartbeat succeeds.
                let mut surface_active = surface_id.is_none();
                if surface_active {
                    backoff = MIN_BACKOFF;
                    transition(LinkState::Connected, &mut on_state);
                }
                let mut buffer = String::new();
                let mut last_stream_activity = tokio::time::Instant::now();
                let heartbeat_period =
                    Duration::from_millis(aka_api::APPROVAL_SURFACE_HEARTBEAT_MS);
                let mut heartbeat = tokio::time::interval_at(
                    tokio::time::Instant::now() + heartbeat_period,
                    heartbeat_period,
                );
                heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                let ready_timeout = tokio::time::sleep(SURFACE_READY_TIMEOUT);
                tokio::pin!(ready_timeout);
                loop {
                    let next = tokio::select! {
                        // Lease safety wins over draining an event burst; the
                        // response stream buffers while this tiny request runs.
                        biased;
                        _ = heartbeat.tick(), if surface_id.is_some() && surface_active => {
                            if last_stream_activity.elapsed() > SURFACE_STREAM_FRESHNESS {
                                transition(
                                    LinkState::Disconnected {
                                        message: "the broker event stream stopped delivering keep-alives".into(),
                                    },
                                    &mut on_state,
                                );
                                break;
                            }
                            let id = surface_id.expect("guarded by is_some");
                            if let Err(message) = heartbeat_surface(&client, &backend, id).await {
                                transition(
                                    LinkState::Disconnected { message },
                                    &mut on_state,
                                );
                                break;
                            }
                            continue;
                        }
                        item = stream.next() => item,
                        _ = ready_timeout.as_mut(), if !surface_active => {
                            transition(
                                LinkState::Disconnected {
                                    message: "the broker event stream did not deliver its request-surface handshake".into(),
                                },
                                &mut on_state,
                            );
                            break;
                        }
                    };
                    match next {
                        Some(Ok(bytes)) => {
                            last_stream_activity = tokio::time::Instant::now();
                            if !surface_active {
                                let id = surface_id.expect("inactive only for modern surfaces");
                                if let Err(message) = heartbeat_surface(&client, &backend, id).await
                                {
                                    transition(LinkState::Disconnected { message }, &mut on_state);
                                    break;
                                }
                                surface_active = true;
                                backoff = MIN_BACKOFF;
                                transition(LinkState::Connected, &mut on_state);
                            }
                            buffer.push_str(&String::from_utf8_lossy(&bytes));
                            for frame in drain_frames(&mut buffer) {
                                if let Some(id) = frame.id {
                                    last_event_id = Some(id);
                                }
                                on_event(frame.event);
                            }
                        }
                        Some(Err(error)) => {
                            transition(
                                LinkState::Disconnected {
                                    message: error.to_string(),
                                },
                                &mut on_state,
                            );
                            break;
                        }
                        None => {
                            transition(
                                LinkState::Disconnected {
                                    message: "the broker closed the event stream".into(),
                                },
                                &mut on_state,
                            );
                            break;
                        }
                    }
                }
            }
            Err(message) => {
                transition(LinkState::Disconnected { message }, &mut on_state);
            }
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

async fn open_stream(
    backend: &RemoteBackend,
    last_event_id: Option<&str>,
    request_surface: bool,
) -> Result<
    (
        impl futures::Stream<Item = Result<bytes::Bytes, reqwest::Error>>,
        Option<uuid::Uuid>,
        reqwest::Client,
    ),
    String,
> {
    // A dedicated client without the request timeout: the event stream is
    // deliberately long-lived (keep-alives ride it). The per-read timeout
    // is the dead-link detector — see [`IDLE_TIMEOUT`].
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .read_timeout(IDLE_TIMEOUT)
        .build()
        .map_err(|error| error.to_string())?;
    // The SSE feed is HTTP-only: a Unix-socket backend (the CLI's local
    // online mode) has no event stream, and nothing subscribes one.
    let config = backend
        .config()
        .ok_or_else(|| "the manage event stream requires an HTTP broker URL".to_string())?;
    let mut request = client
        .get(format!("{}/v1/manage/events", config.base_url()))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {}", config.token()),
        );
    if request_surface {
        // New brokers mint a client-heartbeated capability in response. Old
        // brokers harmlessly ignore the additive header and retain their
        // historical subscriber-presence behavior.
        request = request.header(
            aka_api::APPROVAL_SURFACE_HEADER,
            aka_api::APPROVAL_SURFACE_V1,
        );
    }
    if let Some(id) = last_event_id {
        request = request.header("last-event-id", id);
    }
    let response = request.send().await.map_err(|error| error.to_string())?;
    if response.status() == reqwest::StatusCode::UNAUTHORIZED {
        return Err("the management token was rejected".into());
    }
    if !response.status().is_success() {
        return Err(format!("the broker answered {}", response.status()));
    }
    let event_stream = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("text/event-stream"))
        });
    if !event_stream {
        return Err("the broker did not return an event stream".into());
    }
    let surface_id = if request_surface {
        let status = response
            .headers()
            .get(aka_api::APPROVAL_SURFACE_STATUS_HEADER)
            .map(|value| {
                value
                    .to_str()
                    .map_err(|_| "the broker returned an invalid request-surface status")
            })
            .transpose()?;
        match status {
            // No status header can mean an older broker, or a proxy that
            // stripped the negotiation response. The authenticated
            // capability document distinguishes them without guessing.
            None => {
                let whoami = backend.whoami().await.map_err(|error| {
                    format!("could not verify request-surface compatibility: {error}")
                })?;
                let modern = whoami
                    .get("capabilities")
                    .and_then(serde_json::Value::as_array)
                    .is_some_and(|capabilities| {
                        capabilities.iter().any(|capability| {
                            capability.as_str() == Some(aka_api::APPROVAL_SURFACE_CAPABILITY)
                        })
                    });
                if modern {
                    return Err(
                        "the broker supports request surfaces, but its negotiation headers \
                         did not arrive; a proxy may have removed them"
                            .into(),
                    );
                }
                // Legacy brokers count this live subscriber directly.
                None
            }
            Some(aka_api::APPROVAL_SURFACE_STATUS_ACTIVE) => {
                let id = response
                    .headers()
                    .get(aka_api::APPROVAL_SURFACE_ID_HEADER)
                    .and_then(|value| value.to_str().ok())
                    .ok_or_else(|| {
                        "the broker accepted the request surface without a lease id".to_string()
                    })?
                    .parse::<uuid::Uuid>()
                    .map_err(|_| "the broker returned an invalid request-surface id".to_string())?;
                Some(id)
            }
            Some(status) => {
                return Err(format!(
                    "the broker classified this request-inbox stream as {status:?}; \
                     a proxy may have removed its capability header"
                ));
            }
        }
    } else {
        None
    };
    Ok((response.bytes_stream(), surface_id, client))
}

async fn heartbeat_surface(
    client: &reqwest::Client,
    backend: &RemoteBackend,
    id: uuid::Uuid,
) -> Result<(), String> {
    let config = backend
        .config()
        .ok_or_else(|| "request surfaces require an HTTP broker URL".to_string())?;
    let request = async {
        let response = client
            .put(format!(
                "{}/v1/manage/approval-surfaces/{id}",
                config.base_url()
            ))
            .header(
                reqwest::header::AUTHORIZATION,
                format!("Bearer {}", config.token()),
            )
            .send()
            .await?;
        let status = response.status();
        // Consume the tiny response so the heartbeat connection remains
        // reusable instead of accumulating one TCP connection per tick.
        let _ = response.bytes().await?;
        Ok::<_, reqwest::Error>(status)
    };
    let status = tokio::time::timeout(Duration::from_secs(5), request)
        .await
        .map_err(|_| "the request-surface heartbeat timed out".to_string())?
        .map_err(|error| format!("the request-surface heartbeat failed: {error}"))?;
    if status == reqwest::StatusCode::UNAUTHORIZED {
        return Err("the management token was rejected".into());
    }
    if !status.is_success() {
        return Err(format!(
            "the broker rejected the request-surface heartbeat with {status}"
        ));
    }
    Ok(())
}

/// A parsed SSE frame: its event and the `id:` that lets a reconnect resume.
struct ParsedFrame {
    event: ManageEvent,
    id: Option<String>,
}

/// Pull complete SSE frames (`…\n\n`) out of the buffer, parsing their
/// `data:` payload and `id:` field. Comments/keep-alives (`: …`) are dropped.
fn drain_frames(buffer: &mut String) -> Vec<ParsedFrame> {
    let mut frames = Vec::new();
    while let Some(end) = buffer.find("\n\n") {
        let frame: String = buffer[..end].to_string();
        buffer.drain(..end + 2);
        let data: String = frame
            .lines()
            .filter_map(|line| line.strip_prefix("data:"))
            .map(|line| line.strip_prefix(' ').unwrap_or(line))
            .collect::<Vec<_>>()
            .join("\n");
        let id = frame
            .lines()
            .filter_map(|line| line.strip_prefix("id:"))
            .map(|line| line.strip_prefix(' ').unwrap_or(line).to_string())
            .next_back();
        if data.is_empty() {
            continue;
        }
        match serde_json::from_str::<ManageEvent>(&data) {
            Ok(event) => frames.push(ParsedFrame { event, id }),
            Err(error) => {
                tracing::warn!(%error, "unparseable manage event; forcing resync");
                frames.push(ParsedFrame {
                    event: ManageEvent::Resync,
                    id,
                });
            }
        }
    }
    frames
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_are_drained_incrementally_with_ids() {
        let mut buffer = String::new();
        buffer.push_str("id: ab12:7\ndata: {\"event\":\"connections_changed\"}\n");
        assert!(drain_frames(&mut buffer).is_empty(), "incomplete frame");
        buffer.push('\n');
        let frames = drain_frames(&mut buffer);
        assert_eq!(frames.len(), 1);
        assert!(matches!(frames[0].event, ManageEvent::ConnectionsChanged));
        assert_eq!(frames[0].id.as_deref(), Some("ab12:7"));
        assert!(buffer.is_empty());
    }

    #[test]
    fn keepalive_comments_are_dropped_and_garbage_forces_resync() {
        let mut buffer = ": keep-alive\n\nid: ab12:9\ndata: not json\n\n".to_string();
        let frames = drain_frames(&mut buffer);
        assert_eq!(frames.len(), 1);
        assert!(matches!(frames[0].event, ManageEvent::Resync));
        // The id still tracks, so a resume after garbage doesn't rewind.
        assert_eq!(frames[0].id.as_deref(), Some("ab12:9"));
    }
}
