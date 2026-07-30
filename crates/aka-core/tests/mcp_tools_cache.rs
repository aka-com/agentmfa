//! The per-wiring tool picker must keep working after an MCP connection's
//! credential lapses. `ui_list_mcp_tools` caches the last good listing and
//! falls back to it when a live listing can't be fetched, so curating and
//! saving a tool subset never forces a reconnect first. Retargeting the
//! connection drops the cache — the old server's tools say nothing about the
//! new destination.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use aka_core::broker::Broker;
use aka_core::config::BrokerConfig;
use aka_core::events::BrokerEvents;
use aka_core::paths::Paths;
use aka_core::store::ConnectionSpec;
use aka_core::types::{ConfirmationMethod, ConnectionConfig};
use aka_core::vault::MemoryVault;
use axum::response::IntoResponse;
use axum::routing::{delete, post};
use axum::Router;
use serde_json::{json, Value};
use zeroize::Zeroizing;

struct NoopEvents;
impl BrokerEvents for NoopEvents {
    fn confirm_action(&self, _description: &str) -> Option<ConfirmationMethod> {
        Some(ConfirmationMethod::Waived)
    }
}

/// A mock MCP server whose `healthy` flag flips a live listing on and off.
/// When unhealthy every request is answered `401`, exactly as an upstream
/// does once an access token has lapsed.
struct MockMcp {
    port: u16,
    healthy: Arc<AtomicBool>,
    deleted: Arc<AtomicUsize>,
}

async fn mock_mcp() -> MockMcp {
    let healthy = Arc::new(AtomicBool::new(true));
    let flag = healthy.clone();
    let deleted = Arc::new(AtomicUsize::new(0));
    let deleted_for_route = deleted.clone();
    let app = Router::new().route(
        "/mcp",
        post(move |body: axum::Json<Value>| {
            let flag = flag.clone();
            async move {
                if !flag.load(Ordering::SeqCst) {
                    return (axum::http::StatusCode::UNAUTHORIZED, axum::Json(json!({})))
                        .into_response();
                    // credential rejected
                }
                let id = body.0.get("id").cloned().unwrap_or(Value::Null);
                let method = body.0.get("method").and_then(Value::as_str).unwrap_or("");
                let result = match method {
                    "initialize" => json!({
                        "protocolVersion": "2025-06-18",
                        "serverInfo": { "name": "mock", "version": "1.0" }
                    }),
                    "tools/list" => json!({
                        "tools": [
                            { "name": "search", "description": "Search the docs" },
                            { "name": "delete", "description": "Delete a doc" },
                        ]
                    }),
                    _ => json!({}),
                };
                (
                    axum::http::StatusCode::OK,
                    [("mcp-session-id", "mock-session")],
                    axum::Json(json!({ "jsonrpc": "2.0", "id": id, "result": result })),
                )
                    .into_response()
            }
        })
        .merge(delete(move || {
            let deleted = deleted_for_route.clone();
            async move {
                deleted.fetch_add(1, Ordering::SeqCst);
                axum::http::StatusCode::NO_CONTENT
            }
        })),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    MockMcp {
        port,
        healthy,
        deleted,
    }
}

async fn broker() -> (Arc<Broker>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let broker = Broker::new(
        Paths::under(dir.path()),
        Arc::new(MemoryVault::new()),
        BrokerConfig::default(),
        Arc::new(NoopEvents),
    )
    .await
    .unwrap();
    (broker, dir)
}

fn add_mcp_connection(broker: &Broker, port: u16) -> aka_core::types::Connection {
    broker
        .store
        .add_secret("MCP_TOKEN", Zeroizing::new("tok".into()))
        .unwrap();
    broker
        .store
        .add_connection(ConnectionSpec {
            name: "docs".into(),
            config: ConnectionConfig::Api {
                host: "127.0.0.1".into(),
                scheme: "http".into(),
                port: Some(port),
                trusted_ca_bundle_path: None,
                template: "Authorization: Bearer {{MCP_TOKEN}}".into(),
                mcp_path: Some("/mcp".into()),
                oauth: None,
            },
            secrets: vec![],
        })
        .unwrap()
}

fn names(tools: &[aka_core::mcp::McpToolInfo]) -> Vec<String> {
    tools.iter().map(|t| t.name.clone()).collect()
}

#[tokio::test]
async fn a_lapsed_credential_falls_back_to_the_cached_listing() {
    let (broker, _dir) = broker().await;
    let server = mock_mcp().await;
    let conn = add_mcp_connection(&broker, server.port);

    // A healthy server answers live, and the listing is remembered.
    let live = broker.ui_list_mcp_tools(&conn.id).await.unwrap();
    assert_eq!(names(&live), vec!["search", "delete"]);
    assert_eq!(
        server.deleted.load(Ordering::SeqCst),
        1,
        "a successful tool listing must tear down its upstream session"
    );

    // The credential lapses: every request now 401s, as it would once an
    // OAuth access token expired with no refresh left.
    server.healthy.store(false, Ordering::SeqCst);

    // The picker still lists — from the cache — so a subset can be curated
    // and saved without reconnecting first.
    let cached = broker.ui_list_mcp_tools(&conn.id).await.unwrap();
    assert_eq!(names(&cached), vec!["search", "delete"]);
}

#[tokio::test]
async fn no_cache_and_a_dead_credential_still_errors() {
    let (broker, _dir) = broker().await;
    let server = mock_mcp().await;
    let conn = add_mcp_connection(&broker, server.port);

    // Never listed successfully, and the server refuses: there is nothing to
    // fall back to, so the caller learns the listing failed.
    server.healthy.store(false, Ordering::SeqCst);
    assert!(broker.ui_list_mcp_tools(&conn.id).await.is_err());
}

#[tokio::test]
async fn retargeting_drops_the_cached_listing() {
    let (broker, _dir) = broker().await;
    let server = mock_mcp().await;
    let conn = add_mcp_connection(&broker, server.port);

    broker.ui_list_mcp_tools(&conn.id).await.unwrap();

    // Point the connection at a different destination. The old server's tools
    // are meaningless there, so the cache must not answer for the new target.
    broker
        .ui_update_connection(
            &conn.id,
            ConnectionSpec {
                name: conn.name.clone(),
                config: ConnectionConfig::Api {
                    host: "127.0.0.1".into(),
                    scheme: "http".into(),
                    // A port nothing listens on: a live listing cannot succeed.
                    port: Some(1),
                    trusted_ca_bundle_path: None,
                    template: "Authorization: Bearer {{MCP_TOKEN}}".into(),
                    mcp_path: Some("/mcp".into()),
                    oauth: None,
                },
                secrets: vec![],
            },
        )
        .unwrap();

    assert!(
        broker.ui_list_mcp_tools(&conn.id).await.is_err(),
        "a retarget must clear the previous destination's cached tools"
    );
}
