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
/// `on_state` every link-state *transition*. A successful (re)connect also
/// emits a synthetic [`ManageEvent::Resync`] so the shell refetches what it
/// missed while the link was down.
pub async fn subscribe(
    backend: std::sync::Arc<RemoteBackend>,
    mut on_event: impl FnMut(ManageEvent) + Send,
    mut on_state: impl FnMut(LinkState) + Send,
) {
    let mut backoff = MIN_BACKOFF;
    let mut state = None::<LinkState>;
    let mut transition = |next: LinkState, on_state: &mut dyn FnMut(LinkState)| {
        if state.as_ref() != Some(&next) {
            state = Some(next.clone());
            on_state(next);
        }
    };

    loop {
        match open_stream(&backend).await {
            Ok(mut stream) => {
                backoff = MIN_BACKOFF;
                transition(LinkState::Connected, &mut on_state);
                on_event(ManageEvent::Resync);
                let mut buffer = String::new();
                loop {
                    match stream.next().await {
                        Some(Ok(bytes)) => {
                            buffer.push_str(&String::from_utf8_lossy(&bytes));
                            for event in drain_frames(&mut buffer) {
                                on_event(event);
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
) -> Result<impl futures::Stream<Item = Result<bytes::Bytes, reqwest::Error>>, String> {
    // A dedicated client without the request timeout: the event stream is
    // deliberately long-lived (keep-alives ride it).
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .build()
        .map_err(|error| error.to_string())?;
    let response = client
        .get(format!("{}/v1/manage/events", backend.config().base_url()))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {}", backend.config().token()),
        )
        .send()
        .await
        .map_err(|error| error.to_string())?;
    if response.status() == reqwest::StatusCode::UNAUTHORIZED {
        return Err("the management token was rejected".into());
    }
    if !response.status().is_success() {
        return Err(format!("the broker answered {}", response.status()));
    }
    Ok(response.bytes_stream())
}

/// Pull complete SSE frames (`…\n\n`) out of the buffer, parsing their
/// `data:` payloads. Comments/keep-alives (`: …`) are dropped.
fn drain_frames(buffer: &mut String) -> Vec<ManageEvent> {
    let mut events = Vec::new();
    while let Some(end) = buffer.find("\n\n") {
        let frame: String = buffer[..end].to_string();
        buffer.drain(..end + 2);
        let data: String = frame
            .lines()
            .filter_map(|line| line.strip_prefix("data:"))
            .map(|line| line.strip_prefix(' ').unwrap_or(line))
            .collect::<Vec<_>>()
            .join("\n");
        if data.is_empty() {
            continue;
        }
        match serde_json::from_str::<ManageEvent>(&data) {
            Ok(event) => events.push(event),
            Err(error) => {
                tracing::warn!(%error, "unparseable manage event; forcing resync");
                events.push(ManageEvent::Resync);
            }
        }
    }
    events
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_are_drained_incrementally() {
        let mut buffer = String::new();
        buffer.push_str("data: {\"event\":\"connections_changed\"}\n");
        assert!(drain_frames(&mut buffer).is_empty(), "incomplete frame");
        buffer.push('\n');
        let events = drain_frames(&mut buffer);
        assert!(matches!(
            events.as_slice(),
            [ManageEvent::ConnectionsChanged]
        ));
        assert!(buffer.is_empty());
    }

    #[test]
    fn keepalive_comments_are_dropped_and_garbage_forces_resync() {
        let mut buffer = ": keep-alive\n\ndata: not json\n\n".to_string();
        let events = drain_frames(&mut buffer);
        assert!(matches!(events.as_slice(), [ManageEvent::Resync]));
    }
}
