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
    Disconnected { message: String },
}

/// Minimum/maximum reconnect backoff.
const MIN_BACKOFF: Duration = Duration::from_millis(500);
const MAX_BACKOFF: Duration = Duration::from_secs(15);

/// Subscribe forever (until the task is aborted): connect, stream events,
/// reconnect with backoff. `on_event` receives every parsed event;
/// `on_state` every link-state *transition*.
///
/// Reconnects resume rather than refetch: the last event id seen is sent as
/// `Last-Event-ID`, and the broker replays only the missed events (or, when
/// the client's position has aged out or the broker restarted, sends a
/// single [`ManageEvent::Resync`] itself). The synthetic resync is the
/// broker's to emit — this loop just forwards frames.
pub async fn subscribe(
    backend: std::sync::Arc<RemoteBackend>,
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
        match open_stream(&backend, last_event_id.as_deref()).await {
            Ok(mut stream) => {
                backoff = MIN_BACKOFF;
                transition(LinkState::Connected, &mut on_state);
                let mut buffer = String::new();
                loop {
                    match stream.next().await {
                        Some(Ok(bytes)) => {
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
) -> Result<impl futures::Stream<Item = Result<bytes::Bytes, reqwest::Error>>, String> {
    // A dedicated client without the request timeout: the event stream is
    // deliberately long-lived (keep-alives ride it).
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .build()
        .map_err(|error| error.to_string())?;
    let mut request = client
        .get(format!("{}/v1/manage/events", backend.config().base_url()))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {}", backend.config().token()),
        );
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
    Ok(response.bytes_stream())
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
