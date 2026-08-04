//! Sign-in flow for MCP servers: OAuth 2.1 with discovery, dynamic client
//! registration, and PKCE.
//!
//! Adding a templated MCP server (GitHub, Notion, …) should not require the
//! user to mint a token by hand. This module drives the standard remote-MCP
//! authorization dance end to end:
//!
//! 1. **Probe** — POST an unauthenticated `initialize`; a conforming server
//!    answers 401 with a `WWW-Authenticate` pointer to its protected
//!    resource metadata (RFC 9728).
//! 2. **Discover** — fetch the resource metadata, then the authorization
//!    server metadata (RFC 8414).
//! 3. **Register** — dynamic client registration (RFC 7591), a public
//!    client with a loopback redirect.
//! 4. **Authorize** — open the system browser at the authorization URL
//!    (PKCE S256 + `state`), and catch the redirect on a one-shot loopback
//!    listener.
//! 5. **Exchange** — trade the code for tokens at the token endpoint.
//! 6. **Store & verify** — save the access token to the vault, create the
//!    connection (or replace an existing connection's token on
//!    reconnect), then run the MCP status check to acknowledge the
//!    account the credential belongs to.
//!
//! Every step is a visible state: the UI renders progress, errors carry a
//! actionable hint (e.g. "this server has no automatic registration — use
//! a token instead"), and cancel works at any point. The access token
//! never crosses to the webview: it goes straight into the vault and rides
//! only the upstream leg, like every other credential here.
//!
//! Because a connection is only created once its token exists, connecting
//! the same service twice simply runs the flow twice — two connections,
//! two vault items, two accounts. Nothing in the model limits how many
//! tokens one upstream host can have.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Digest as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::audit::{AuditEntry, AuditKind};
use crate::broker::Broker;
use crate::error::CoreError;
use crate::mcp::{self, McpCheckOptions};
use crate::store::ConnectionSpec;
use crate::types::ConnectionConfig;
use crate::Result;

/// How long each discovery/registration/exchange request may take.
const STEP_TIMEOUT: Duration = Duration::from_secs(20);
/// How long the user has to approve in the browser.
const BROWSER_TIMEOUT: Duration = Duration::from_secs(300);
/// Terminal sessions kept for the UI to read back before pruning.
const MAX_FINISHED_SESSIONS: usize = 16;

/* --------------------------------- state --------------------------------- */

/// Everything the UI needs to render one step of the flow. Serialized to
/// the webview verbatim — no token material may ever appear here.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case")]
pub enum McpAuthPhase {
    /// Asking the server whether (and how) it wants authentication.
    Probing,
    /// Reading protected-resource and authorization-server metadata.
    Discovering,
    /// Dynamic client registration.
    Registering,
    /// The browser is open; waiting for the user to approve.
    AwaitingAuthorization {
        authorization_url: String,
    },
    /// Trading the authorization code for tokens.
    Exchanging,
    /// Token stored; running the status check to acknowledge the account.
    Verifying,
    Succeeded {
        connection_id: String,
        connection_name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        account: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expires_in: Option<u64>,
        /// Set when the token was stored but post-auth verification could
        /// not confirm the server (the connection still exists).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        warning: Option<String>,
    },
    Failed {
        message: String,
        /// What to try instead, when there is a sensible fallback.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        hint: Option<String>,
    },
    Cancelled,
}

impl McpAuthPhase {
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            McpAuthPhase::Succeeded { .. } | McpAuthPhase::Failed { .. } | McpAuthPhase::Cancelled
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpAuthState {
    /// Auth-session id (not a connection id).
    pub id: String,
    /// The connection name being created or reconnected.
    pub name: String,
    /// Pinned destination, e.g. `https://mcp.notion.com/mcp`.
    pub target: String,
    #[serde(flatten)]
    pub phase: McpAuthPhase,
    pub updated_at: DateTime<Utc>,
}

/// What the UI submits to start a sign-in.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct McpAuthDraft {
    pub name: String,
    pub scheme: String,
    pub host: String,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub trusted_ca_bundle_path: Option<String>,
    pub mcp_path: String,
    /// Re-authenticate an existing connection instead of creating one: the
    /// flow targets that connection's pinned destination and replaces its
    /// bound token. The other destination fields are ignored.
    #[serde(default)]
    pub reauth_connection_id: Option<String>,
    /// The whoami tool carried into the post-auth verification, to
    /// acknowledge which account the new token belongs to.
    #[serde(default)]
    pub whoami_tool: Option<String>,
    /// Pre-registered OAuth client, for authorization servers without
    /// dynamic client registration (Google Workspace, Slack). When set,
    /// the registration step is skipped and these ride the authorize +
    /// exchange legs; the secret lands in the vault with the grant.
    #[serde(default)]
    pub oauth_client_id: Option<String>,
    #[serde(default)]
    pub oauth_client_secret: Option<String>,
    /// Scopes to request instead of everything the resource advertises.
    #[serde(default)]
    pub oauth_scope: Option<String>,
    /// Extra authorize-URL parameters some providers need (e.g. Google's
    /// `access_type=offline` for a refresh token).
    #[serde(default)]
    pub extra_auth_params: Vec<(String, String)>,
}

/// A caller-supplied OAuth client carried through the flow in place of
/// dynamic registration.
#[derive(Default)]
struct ClientPreset {
    client_id: Option<String>,
    client_secret: Option<Zeroizing<String>>,
    scope: Option<String>,
    extra_auth_params: Vec<(String, String)>,
}

impl ClientPreset {
    fn from_draft(draft: &McpAuthDraft) -> Self {
        Self {
            client_id: draft
                .oauth_client_id
                .as_deref()
                .map(str::trim)
                .filter(|id| !id.is_empty())
                .map(str::to_string),
            client_secret: draft
                .oauth_client_secret
                .as_deref()
                .map(str::trim)
                .filter(|secret| !secret.is_empty())
                .map(|secret| Zeroizing::new(secret.to_string())),
            scope: draft
                .oauth_scope
                .as_deref()
                .map(str::trim)
                .filter(|scope| !scope.is_empty())
                .map(str::to_string),
            extra_auth_params: draft.extra_auth_params.clone(),
        }
    }
}

/// Where the token lands when the dance completes.
enum CompletionPlan {
    /// Create `secret_name` + a fresh connection from `spec`.
    New {
        secret_name: String,
        spec: Box<ConnectionSpec>,
    },
    /// Replace the token bound to an existing connection.
    Reauth {
        connection_id: Uuid,
        secret_id: Uuid,
    },
}

struct SessionSlot {
    state: McpAuthState,
    reauth_connection_id: Option<Uuid>,
    task: Option<tokio::task::JoinHandle<()>>,
    /// External-redirect sessions: fulfilled by the remote shell's code
    /// delivery; the flow task is waiting on the paired receiver. The tuple
    /// is `(code, state, iss)` — the RFC 9207 issuer, when the catcher
    /// forwarded it.
    code_tx: Option<tokio::sync::oneshot::Sender<(String, String, Option<String>)>>,
}

/// Live and recently finished auth sessions, owned by the broker.
#[derive(Default)]
pub struct McpAuthSessions {
    slots: Mutex<HashMap<Uuid, SessionSlot>>,
}

impl McpAuthSessions {
    fn insert(&self, id: Uuid, state: McpAuthState, reauth_connection_id: Option<Uuid>) -> bool {
        let mut slots = self.slots.lock().unwrap();
        if reauth_connection_id.is_some_and(|connection_id| {
            slots.values().any(|slot| {
                slot.reauth_connection_id == Some(connection_id) && !slot.state.phase.is_terminal()
            })
        }) {
            return false;
        }
        // Prune old terminal sessions so the map cannot grow unbounded.
        if slots.len() >= MAX_FINISHED_SESSIONS {
            let stale: Vec<Uuid> = slots
                .iter()
                .filter(|(_, slot)| slot.state.phase.is_terminal())
                .map(|(id, _)| *id)
                .collect();
            for id in stale {
                slots.remove(&id);
            }
        }
        slots.insert(
            id,
            SessionSlot {
                state,
                reauth_connection_id,
                task: None,
                code_tx: None,
            },
        );
        true
    }

    fn attach_task(&self, id: &Uuid, task: tokio::task::JoinHandle<()>) {
        if let Some(slot) = self.slots.lock().unwrap().get_mut(id) {
            slot.task = Some(task);
        }
    }

    fn attach_code_tx(
        &self,
        id: &Uuid,
        tx: tokio::sync::oneshot::Sender<(String, String, Option<String>)>,
    ) {
        if let Some(slot) = self.slots.lock().unwrap().get_mut(id) {
            slot.code_tx = Some(tx);
        }
    }

    fn take_code_tx(
        &self,
        id: &Uuid,
    ) -> Option<tokio::sync::oneshot::Sender<(String, String, Option<String>)>> {
        self.slots
            .lock()
            .unwrap()
            .get_mut(id)
            .and_then(|slot| slot.code_tx.take())
    }

    pub fn get(&self, id: &Uuid) -> Option<McpAuthState> {
        self.slots
            .lock()
            .unwrap()
            .get(id)
            .map(|slot| slot.state.clone())
    }

    /// Set a session's phase unless it already ended (a cancel must not be
    /// overwritten by the aborted task's final write). Returns the updated
    /// state for event fan-out.
    fn set_phase(&self, id: &Uuid, phase: McpAuthPhase) -> Option<McpAuthState> {
        let mut slots = self.slots.lock().unwrap();
        let slot = slots.get_mut(id)?;
        if slot.state.phase.is_terminal() {
            return None;
        }
        slot.state.phase = phase;
        slot.state.updated_at = Utc::now();
        if slot.state.phase.is_terminal() {
            slot.task = None;
        }
        Some(slot.state.clone())
    }

    fn cancel(&self, id: &Uuid) -> Option<McpAuthState> {
        let handle = {
            let mut slots = self.slots.lock().unwrap();
            let slot = slots.get_mut(id)?;
            if slot.state.phase.is_terminal() {
                return None;
            }
            slot.task.take()
        };
        if let Some(handle) = handle {
            handle.abort();
        }
        self.set_phase(id, McpAuthPhase::Cancelled)
    }
}

/// Where the sign-in's browser redirect lands: a listener the flow binds
/// on this host (local shells), or the remote shell's own loopback catcher
/// with the code delivered back over the manage API.
enum RedirectMode {
    Loopback,
    External {
        redirect_uri: String,
        code_rx: tokio::sync::oneshot::Receiver<(String, String, Option<String>)>,
    },
}

/* ------------------------------ broker API -------------------------------- */

impl Broker {
    /// Begin the sign-in flow. Validates the draft, reserves nothing, and
    /// returns the session's initial state; progress arrives through
    /// [`crate::events::BrokerEvents::mcp_auth_changed`] and
    /// [`Broker::ui_mcp_auth_state`].
    pub fn ui_start_mcp_auth(self: &Arc<Self>, draft: McpAuthDraft) -> Result<McpAuthState> {
        self.start_mcp_auth_with(draft, RedirectMode::Loopback)
    }

    /// Begin a sign-in whose browser redirect lands on the remote shell's
    /// loopback catcher; the code comes back via
    /// [`Broker::ui_mcp_auth_deliver_code`]. Loopback redirect targets only.
    pub fn ui_start_mcp_auth_external(
        self: &Arc<Self>,
        draft: McpAuthDraft,
        redirect_uri: &str,
    ) -> Result<McpAuthState> {
        let parsed = url::Url::parse(redirect_uri)
            .map_err(|_| CoreError::OAuth("the redirect URI is not a valid URL".into()))?;
        let loopback = matches!(
            parsed.host_str(),
            Some("127.0.0.1") | Some("localhost") | Some("[::1]")
        );
        if parsed.scheme() != "http" || !loopback || parsed.path() != "/callback" {
            return Err(CoreError::OAuth(
                "the redirect URI must be a loopback http://127.0.0.1:<port>/callback".into(),
            ));
        }
        let (tx, rx) = tokio::sync::oneshot::channel();
        let state = self.start_mcp_auth_with(
            draft,
            RedirectMode::External {
                redirect_uri: redirect_uri.to_string(),
                code_rx: rx,
            },
        )?;
        let session_id = Uuid::parse_str(&state.id).expect("session id is a uuid");
        self.mcp_auth.attach_code_tx(&session_id, tx);
        Ok(state)
    }

    /// Deliver the authorization code a remote shell's catcher received,
    /// with the RFC 9207 `iss` if the catcher forwarded it. Returns false
    /// when the session is unknown or not waiting.
    pub fn ui_mcp_auth_deliver_code(
        &self,
        id: &Uuid,
        code: String,
        state: String,
        iss: Option<String>,
    ) -> bool {
        match self.mcp_auth.take_code_tx(id) {
            Some(tx) => tx.send((code, state, iss)).is_ok(),
            None => false,
        }
    }

    fn start_mcp_auth_with(
        self: &Arc<Self>,
        draft: McpAuthDraft,
        mode: RedirectMode,
    ) -> Result<McpAuthState> {
        let (name, config, plan) = self.plan_auth(&draft)?;
        let endpoint = endpoint_for(&config)?;
        let trusted_ca_bundle_path = match &config {
            ConnectionConfig::Api {
                trusted_ca_bundle_path,
                ..
            } => trusted_ca_bundle_path.clone(),
            _ => None,
        };

        let session_id = Uuid::new_v4();
        let reauth_connection_id = match &plan {
            CompletionPlan::Reauth { connection_id, .. } => Some(*connection_id),
            CompletionPlan::New { .. } => None,
        };
        let state = McpAuthState {
            id: session_id.to_string(),
            name: name.clone(),
            target: endpoint.to_string(),
            phase: McpAuthPhase::Probing,
            updated_at: Utc::now(),
        };
        if !self
            .mcp_auth
            .insert(session_id, state.clone(), reauth_connection_id)
        {
            return Err(CoreError::OAuth(
                "a reconnect is already in progress for this connection".into(),
            ));
        }
        self.events.mcp_auth_changed(&state);

        let broker = self.clone();
        let options = McpCheckOptions {
            whoami_tool: draft.whoami_tool.clone(),
        };
        let preset = ClientPreset::from_draft(&draft);
        // This is also called by a synchronous Tauri command on the app's
        // main thread, where no Tokio reactor is entered. Always put the
        // flow on the broker-owned runtime instead of the caller's context.
        let task = broker.task_runtime().spawn(async move {
            let outcome = run_flow(
                &broker,
                session_id,
                endpoint,
                plan,
                options,
                preset,
                mode,
                trusted_ca_bundle_path,
            )
            .await;
            let phase = match outcome {
                Ok(phase) => phase,
                Err(failure) => {
                    broker.audit.append(
                        AuditEntry::new(
                            AuditKind::McpAuthFailed,
                            format!("MCP sign-in failed: {name}"),
                        )
                        .connection(name.clone())
                        .detail(failure.message.clone()),
                    );
                    McpAuthPhase::Failed {
                        message: failure.message,
                        hint: failure.hint,
                    }
                }
            };
            broadcast(&broker, &session_id, phase);
        });
        self.mcp_auth.attach_task(&session_id, task);
        Ok(state)
    }

    pub fn ui_mcp_auth_state(&self, id: &Uuid) -> Option<McpAuthState> {
        self.mcp_auth.get(id)
    }

    /// Abort a running sign-in. Terminal sessions are left as they ended.
    pub fn ui_cancel_mcp_auth(&self, id: &Uuid) -> bool {
        match self.mcp_auth.cancel(id) {
            Some(state) => {
                self.events.mcp_auth_changed(&state);
                true
            }
            None => false,
        }
    }

    /// Validate a draft into the connection config the flow will pin and
    /// the completion plan (create vs. reconnect).
    fn plan_auth(
        &self,
        draft: &McpAuthDraft,
    ) -> Result<(String, ConnectionConfig, CompletionPlan)> {
        if let Some(raw) = &draft.reauth_connection_id {
            let id = Uuid::parse_str(raw).map_err(|_| CoreError::ConnectionNotFound)?;
            let connection = self.store.connection_by_id(&id)?;
            let ConnectionConfig::Api {
                mcp_path: Some(_), ..
            } = &connection.config
            else {
                return Err(CoreError::InvalidConnectionConfig(
                    "not an MCP connection".into(),
                ));
            };
            let secret_id = *connection.secrets.first().ok_or_else(|| {
                CoreError::InvalidConnectionConfig(
                    "this connection has no bound credential to replace".into(),
                )
            })?;
            return Ok((
                connection.name.clone(),
                connection.config.clone(),
                CompletionPlan::Reauth {
                    connection_id: id,
                    secret_id,
                },
            ));
        }

        let name = draft.name.trim().to_string();
        let secret_name = self.available_secret_name(&name);
        let config = ConnectionConfig::Api {
            host: draft.host.clone(),
            scheme: draft.scheme.clone(),
            port: draft.port,
            trusted_ca_bundle_path: draft.trusted_ca_bundle_path.clone(),
            template: format!("Authorization: Bearer {{{{{secret_name}}}}}"),
            mcp_path: Some(draft.mcp_path.clone()),
            // An MCP connection's probe is its own MCP path, which
            // `test_upstream` already falls back to.
            test_path: None,
            oauth: None,
            signer: None,
            client_cert_path: None,
            client_key_path: None,
        };
        let spec = ConnectionSpec {
            name: name.clone(),
            config: config.clone(),
            secrets: vec![],
        };
        // Surface invalid input (bad host, taken name) before any browser
        // opens; `add_connection_with_secret` re-checks at completion.
        self.store
            .preflight_add_connection_with_secret(&secret_name, &spec)?;
        Ok((
            name,
            config,
            CompletionPlan::New {
                secret_name,
                spec: Box::new(spec),
            },
        ))
    }

    /// `github` → `GITHUB_MCP_TOKEN`, suffixed if taken.
    fn available_secret_name(&self, connection_name: &str) -> String {
        let mut base: String = connection_name
            .to_uppercase()
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect();
        base.truncate(48);
        let base = base.trim_matches('_');
        let base = if base.is_empty() || base.starts_with(|c: char| c.is_ascii_digit()) {
            format!("MCP_{base}")
        } else {
            base.to_string()
        };
        let taken: std::collections::HashSet<String> = self
            .store
            .list_secrets()
            .into_iter()
            .map(|meta| meta.name)
            .collect();
        let candidate = format!("{base}_MCP_TOKEN");
        if !taken.contains(&candidate) {
            return candidate;
        }
        for n in 2..100 {
            let candidate = format!("{base}_MCP_TOKEN_{n}");
            if !taken.contains(&candidate) {
                return candidate;
            }
        }
        format!("{base}_MCP_TOKEN_{}", Uuid::new_v4().simple())
    }
}

fn broadcast(broker: &Broker, session_id: &Uuid, phase: McpAuthPhase) {
    if let Some(state) = broker.mcp_auth.set_phase(session_id, phase) {
        broker.events.mcp_auth_changed(&state);
    }
}

fn endpoint_for(config: &ConnectionConfig) -> Result<Url> {
    let ConnectionConfig::Api {
        host,
        scheme,
        port,
        mcp_path: Some(path),
        ..
    } = config
    else {
        return Err(CoreError::InvalidConnectionConfig(
            "not an MCP connection".into(),
        ));
    };
    if scheme != "https" && !is_loopback_host(host) {
        return Err(CoreError::InvalidConnectionConfig(
            "MCP sign-in requires an https server URL".into(),
        ));
    }
    if !path.starts_with('/') {
        return Err(CoreError::InvalidConnectionConfig(
            "the MCP path must start with /".into(),
        ));
    }
    let mut base = Url::parse(&format!("{scheme}://{host}"))
        .map_err(|e| CoreError::InvalidConnectionConfig(format!("bad origin: {e}")))?;
    if base.set_port(*port).is_err() {
        return Err(CoreError::InvalidConnectionConfig("cannot set port".into()));
    }
    base.join(path)
        .map_err(|e| CoreError::InvalidConnectionConfig(format!("bad MCP path: {e}")))
}

pub(crate) fn is_loopback_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]")
}

/// Discovery, registration and token URLs must not lead the flow onto
/// plaintext transports (loopback excepted, for tests and local servers).
fn require_secure(url: &Url, what: &str) -> std::result::Result<(), FlowFailure> {
    let host = url.host_str().unwrap_or("");
    if url.scheme() == "https" || (url.scheme() == "http" && is_loopback_host(host)) {
        return Ok(());
    }
    Err(FlowFailure::plain(format!(
        "{what} is not an https URL ({url})"
    )))
}

/// RFC 9207 mix-up defence: the authorization response's `iss` must name the
/// server we discovered. A present `iss` is always checked; an absent one is
/// only fatal when the server declared it would send one — today's servers
/// mostly do not, and the spec asks clients to validate now and reject
/// unconditionally later.
fn validate_iss(
    returned: Option<&str>,
    expected: &str,
    iss_supported: bool,
) -> std::result::Result<(), FlowFailure> {
    match returned {
        Some(iss) if iss.trim_end_matches('/') == expected.trim_end_matches('/') => Ok(()),
        Some(iss) => Err(FlowFailure::hinted(
            format!("the authorization response came from an unexpected issuer ({iss})"),
            "Run the sign-in again.",
        )),
        None if iss_supported => Err(FlowFailure::hinted(
            "the authorization response omitted its issuer identity",
            "Run the sign-in again.",
        )),
        None => Ok(()),
    }
}

/* ------------------------------ flow driver ------------------------------- */

struct FlowFailure {
    message: String,
    hint: Option<String>,
}

fn capitalize_message(mut message: String) -> String {
    if let Some(first) = message.get_mut(..1) {
        first.make_ascii_uppercase();
    }
    message
}

impl FlowFailure {
    fn plain(message: impl Into<String>) -> Self {
        Self {
            message: capitalize_message(message.into()),
            hint: None,
        }
    }
    fn hinted(message: impl Into<String>, hint: impl Into<String>) -> Self {
        Self {
            message: capitalize_message(message.into()),
            hint: Some(hint.into()),
        }
    }
}

async fn step<T, F>(what: &str, future: F) -> std::result::Result<T, FlowFailure>
where
    F: std::future::Future<Output = std::result::Result<T, FlowFailure>>,
{
    match tokio::time::timeout(STEP_TIMEOUT, future).await {
        Ok(result) => result,
        Err(_) => Err(FlowFailure::plain(format!(
            "{what} did not answer within {} seconds",
            STEP_TIMEOUT.as_secs()
        ))),
    }
}

async fn run_flow(
    broker: &Arc<Broker>,
    session_id: Uuid,
    endpoint: Url,
    plan: CompletionPlan,
    options: McpCheckOptions,
    preset: ClientPreset,
    mode: RedirectMode,
    trusted_ca_bundle_path: Option<String>,
) -> std::result::Result<McpAuthPhase, FlowFailure> {
    // The flow follows cross-origin hops (resource → authorization server),
    // so it uses its own client with bounded redirects rather than the
    // broker's no-redirect upstream client. No stored credential ever rides
    // these requests.
    let mut client = reqwest::Client::builder().redirect(reqwest::redirect::Policy::limited(5));
    if let Some(tls) =
        crate::capability::http::trusted_ca_tls_config(trusted_ca_bundle_path.as_deref(), None)
            .map_err(|error| FlowFailure::plain(format!("trusted CA: {error}")))?
    {
        client = client.use_preconfigured_tls(tls);
    }
    let client = client
        .build()
        .map_err(|e| FlowFailure::plain(format!("http client: {e}")))?;

    /* 1 — probe. Some servers with pre-registered clients (Google's
    Workspace endpoints) answer an unauthenticated initialize with 2xx and
    gate the actual tools instead; with a client in hand the flow can
    proceed straight to discovery. */
    let www_authenticate = step(
        "the MCP server",
        probe(&client, &endpoint, preset.client_id.is_some()),
    )
    .await?;

    /* 2 — discover */
    broadcast(broker, &session_id, McpAuthPhase::Discovering);
    let discovered = step(
        "authorization discovery",
        discover(&client, &endpoint, www_authenticate.as_deref()),
    )
    .await?;

    /* 3 — register (redirect first: registration pins the redirect URI).
    Local shells get a listener bound here; a remote shell supplied its own
    catcher's URI and will deliver the code over the manage API. */
    broadcast(broker, &session_id, McpAuthPhase::Registering);
    enum CodeSource {
        Listener(TcpListener),
        Delivery(tokio::sync::oneshot::Receiver<(String, String, Option<String>)>),
    }
    let (redirect_uri, code_source) = match mode {
        RedirectMode::Loopback => {
            let listener = TcpListener::bind(("127.0.0.1", 0)).await.map_err(|e| {
                FlowFailure::plain(format!("could not open a loopback listener: {e}"))
            })?;
            let port = listener
                .local_addr()
                .map_err(|e| FlowFailure::plain(format!("loopback listener: {e}")))?
                .port();
            (
                format!("http://127.0.0.1:{port}/callback"),
                CodeSource::Listener(listener),
            )
        }
        RedirectMode::External {
            redirect_uri,
            code_rx,
        } => (redirect_uri, CodeSource::Delivery(code_rx)),
    };
    let registration = if let Some(client_id) = &preset.client_id {
        Registration {
            client_id: client_id.clone(),
            client_secret: preset.client_secret.clone(),
        }
    } else {
        match step(
            "client registration",
            register(&client, &discovered, &redirect_uri),
        )
        .await
        {
            Ok(registration) => registration,
            Err(failure) => {
                // No dynamic registration: a reconnect may reuse the
                // client stored with the original grant, so the user is
                // not asked for the client ID twice.
                let stored = match &plan {
                    CompletionPlan::Reauth { connection_id, .. }
                        if discovered.registration_endpoint.is_none() =>
                    {
                        broker
                            .store
                            .connection_oauth_grant(connection_id)
                            .await
                            .ok()
                            .and_then(|value| McpOAuthGrant::from_secret_value(&value).ok())
                    }
                    _ => None,
                };
                match stored {
                    // Clone rather than move: the grant scrubs its secret
                    // material on drop, so its fields can't be moved out.
                    Some(grant) => Registration {
                        client_id: grant.client_id.clone(),
                        client_secret: grant.client_secret.clone().map(Zeroizing::new),
                    },
                    None => return Err(failure),
                }
            }
        }
    };

    /* 4 — authorize in the browser */
    let pkce_verifier = random_urlsafe(48);
    let pkce_challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(sha2::Sha256::digest(pkce_verifier.as_bytes()));
    let state_nonce = random_urlsafe(24);
    let mut authorize = discovered.authorization_endpoint.clone();
    {
        let mut query = authorize.query_pairs_mut();
        query
            .append_pair("response_type", "code")
            .append_pair("client_id", &registration.client_id)
            .append_pair("redirect_uri", &redirect_uri)
            .append_pair("state", &state_nonce)
            .append_pair("code_challenge", &pkce_challenge)
            .append_pair("code_challenge_method", "S256")
            .append_pair("resource", &discovered.resource);
        if let Some(scope) = preset.scope.as_ref().or(discovered.scope.as_ref()) {
            query.append_pair("scope", scope);
        }
        // Extra params must never shadow the flow's own: `append_pair`
        // does not deduplicate, and on a last-wins authorization server a
        // duplicated redirect_uri or code_challenge would hand the code
        // (or the PKCE binding) to whoever supplied the parameter.
        const RESERVED_AUTH_PARAMS: [&str; 8] = [
            "response_type",
            "client_id",
            "redirect_uri",
            "state",
            "code_challenge",
            "code_challenge_method",
            "resource",
            "scope",
        ];
        for (key, value) in &preset.extra_auth_params {
            if RESERVED_AUTH_PARAMS.contains(&key.as_str()) {
                tracing::warn!("ignoring reserved extra auth param {key:?}");
                continue;
            }
            query.append_pair(key, value);
        }
    }
    broadcast(
        broker,
        &session_id,
        McpAuthPhase::AwaitingAuthorization {
            authorization_url: authorize.to_string(),
        },
    );
    let wait_for_code = async {
        match code_source {
            CodeSource::Listener(listener) => wait_for_callback(listener, &state_nonce).await,
            CodeSource::Delivery(code_rx) => {
                let (code, state, iss) = code_rx.await.map_err(|_| {
                    FlowFailure::plain("the sign-in was cancelled before the browser returned")
                })?;
                // The remote shell's catcher forwards whatever state came
                // back; the nonce is verified here, where it was minted.
                if state != state_nonce {
                    return Err(FlowFailure::hinted(
                        "authorization state mismatch",
                        "Run the sign-in again.",
                    ));
                }
                Ok((code, iss))
            }
        }
    };
    let (code, returned_iss) = match tokio::time::timeout(BROWSER_TIMEOUT, wait_for_code).await {
        Ok(result) => result?,
        Err(_) => {
            return Err(FlowFailure::hinted(
                "the browser approval did not complete in time",
                "Run the sign-in again and approve the request in your browser.",
            ))
        }
    };
    // RFC 9207: confirm the redirect came from the issuer we discovered
    // before the code is spent, closing the mix-up attack.
    validate_iss(
        returned_iss.as_deref(),
        &discovered.issuer,
        discovered.iss_supported,
    )?;

    /* 5 — exchange */
    broadcast(broker, &session_id, McpAuthPhase::Exchanging);
    let tokens = step(
        "the token endpoint",
        exchange(
            &client,
            &discovered,
            &registration,
            &redirect_uri,
            &code,
            &pkce_verifier,
        ),
    )
    .await?;

    /* 6 — store & verify */
    broadcast(broker, &session_id, McpAuthPhase::Verifying);
    // Refresh and reconnect both replace the same access/refresh-token pair.
    // Serialize the write and verification with refresh so neither path can
    // orphan a newly rotated provider grant.
    let reauth_lock = match &plan {
        CompletionPlan::Reauth { connection_id, .. } => {
            Some(crate::mcp_refresh::connection_lock(connection_id))
        }
        CompletionPlan::New { .. } => None,
    };
    let _reauth_guard = match reauth_lock.as_ref() {
        Some(lock) => Some(lock.lock().await),
        None => None,
    };
    let (connection_id, connection_name) = match plan {
        CompletionPlan::New { secret_name, spec } => {
            let spec = *spec;
            let blocking_broker = broker.clone();
            let value = Zeroizing::new(tokens.access_token.to_string());
            let name_for_error = spec.name.clone();
            let connection = tokio::task::spawn_blocking(move || {
                blocking_broker.ui_add_connection_with_secret(&secret_name, value, spec)
            })
            .await
            .map_err(|e| FlowFailure::plain(format!("save task failed: {e}")))?
            .map_err(|error| {
                FlowFailure::plain(format!("could not save “{name_for_error}”: {error}"))
            })?;
            // This creation happened outside a UI command round-trip, so
            // push the refresh to every window.
            broker.events.connections_changed();
            (connection.id, connection.name)
        }
        CompletionPlan::Reauth {
            connection_id,
            secret_id,
        } => {
            let connection = broker
                .store
                .connection_by_id(&connection_id)
                .map_err(|e| FlowFailure::plain(e.to_string()))?;
            broker
                .store
                .replace_secret_value(&secret_id, Zeroizing::new(tokens.access_token.to_string()))
                .map_err(|e| FlowFailure::plain(format!("could not store the new token: {e}")))?;
            broker.events.connections_changed();
            (connection.id, connection.name)
        }
    };

    // Persist the refresh grant so the access token can be renewed
    // silently when it expires. Best-effort: sign-in already succeeded,
    // and without a grant the status check's Reconnect path still works.
    let grant = McpOAuthGrant {
        refresh_token: tokens.refresh_token.as_ref().map(|token| token.to_string()),
        client_id: registration.client_id.clone(),
        client_secret: registration
            .client_secret
            .as_ref()
            .map(|secret| secret.to_string()),
        token_endpoint: discovered.token_endpoint.to_string(),
        resource: discovered.resource.clone(),
    };
    let expires_at = tokens
        .expires_in
        .and_then(|seconds| i64::try_from(seconds).ok())
        .map(|seconds| Utc::now() + chrono::Duration::seconds(seconds));
    if let Err(error) =
        broker
            .store
            .set_connection_oauth(&connection_id, grant.to_secret_value(), expires_at)
    {
        tracing::warn!("could not store the OAuth refresh grant for {connection_name}: {error}");
    }

    let report = mcp::check_with_bearer(
        client.clone(),
        endpoint.clone(),
        &tokens.access_token,
        &options,
    )
    .await;
    if let Some(tool) = report.status_tool_invoked.as_deref() {
        broker.audit.append(
            AuditEntry::new(
                AuditKind::ConnectionTested,
                format!("MCP account status checked: {connection_name}"),
            )
            .connection(connection_name.clone())
            .outcome(if report.ok { "ok" } else { "failed" })
            .field("mcp_method", "tools/call")
            .field("mcp_name", tool),
        );
    }
    let (account, warning) = if report.ok {
        if report.account.is_some() {
            let _ = broker
                .store
                .set_connection_account(&connection_id, report.account.clone());
            broker.events.connections_changed();
        }
        (report.account, None)
    } else {
        (None, Some(report.detail))
    };

    broker.audit.append(
        AuditEntry::new(
            AuditKind::McpAuthCompleted,
            format!("MCP sign-in completed: {connection_name}"),
        )
        .connection(connection_name.clone())
        .detail(match &account {
            Some(account) => format!("Connected as {account}"),
            None => "Token stored".to_string(),
        }),
    );

    Ok(McpAuthPhase::Succeeded {
        connection_id: connection_id.to_string(),
        connection_name,
        account,
        expires_in: tokens.expires_in,
        warning,
    })
}

/* ------------------------------- the steps -------------------------------- */

/// POST an unauthenticated `initialize`. 401 hands back `WWW-Authenticate`
/// (or None when absent — discovery falls back to well-known locations); a
/// 2xx answer means there is no account to connect.
async fn probe(
    client: &reqwest::Client,
    endpoint: &Url,
    allow_open: bool,
) -> std::result::Result<Option<String>, FlowFailure> {
    let body = json!({
        "jsonrpc": "2.0", "id": 0, "method": "initialize",
        "params": {
            "protocolVersion": mcp::PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": { "name": "aka-multitool", "version": env!("CARGO_PKG_VERSION") },
        },
    });
    let response = client
        .post(endpoint.clone())
        .header(http::header::CONTENT_TYPE, "application/json")
        .header(http::header::ACCEPT, "application/json, text/event-stream")
        .json(&body)
        .send()
        .await
        .map_err(|e| {
            FlowFailure::plain(format!("could not reach the server: {}", e.without_url()))
        })?;
    let status = response.status();
    if status.is_success() {
        if allow_open {
            return Ok(None);
        }
        return Err(FlowFailure::hinted(
            "the server answered without asking for authentication",
            "There is no account to sign in to — add this server with a token instead.",
        ));
    }
    if status.as_u16() != 401 {
        return Err(FlowFailure::plain(format!(
            "the server answered HTTP {status} instead of requesting authentication"
        )));
    }
    Ok(response
        .headers()
        .get(http::header::WWW_AUTHENTICATE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string))
}

struct Discovered {
    authorization_endpoint: Url,
    token_endpoint: Url,
    registration_endpoint: Option<Url>,
    /// RFC 8707 resource indicator carried through authorize + exchange.
    resource: String,
    scope: Option<String>,
    /// The authorization server's issuer identifier (RFC 8414 `issuer`),
    /// used to validate the `iss` on the redirect (RFC 9207).
    issuer: String,
    /// The server advertised `authorization_response_iss_parameter_supported`:
    /// an `iss`-less redirect must then be rejected, not tolerated.
    iss_supported: bool,
}

async fn discover(
    client: &reqwest::Client,
    endpoint: &Url,
    www_authenticate: Option<&str>,
) -> std::result::Result<Discovered, FlowFailure> {
    // Protected resource metadata (RFC 9728): from the challenge parameter
    // when present, else the path-aware well-known fallback.
    let mut metadata_urls: Vec<Url> = Vec::new();
    if let Some(challenge) = www_authenticate {
        if let Some(explicit) = challenge_param(challenge, "resource_metadata") {
            if let Ok(url) = Url::parse(&explicit) {
                metadata_urls.push(url);
            }
        }
    }
    let origin = origin_of(endpoint);
    for candidate in [
        format!(
            "{origin}/.well-known/oauth-protected-resource{}",
            endpoint.path()
        ),
        format!("{origin}/.well-known/oauth-protected-resource"),
    ] {
        if let Ok(url) = Url::parse(&candidate) {
            if !metadata_urls.contains(&url) {
                metadata_urls.push(url);
            }
        }
    }

    let mut resource = endpoint.to_string();
    let mut scope: Option<String> = None;
    let mut issuer: Option<Url> = None;
    for url in metadata_urls {
        if require_secure(&url, "the resource metadata URL").is_err() {
            continue;
        }
        let Ok(response) = client.get(url).send().await else {
            continue;
        };
        if !response.status().is_success() {
            continue;
        }
        let Ok(metadata) = response.json::<Value>().await else {
            continue;
        };
        if let Some(value) = metadata.get("resource").and_then(Value::as_str) {
            resource = value.to_string();
        }
        scope = metadata
            .get("scopes_supported")
            .and_then(Value::as_array)
            .map(|scopes| {
                scopes
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .filter(|joined| !joined.is_empty());
        issuer = metadata
            .get("authorization_servers")
            .and_then(Value::as_array)
            .and_then(|servers| servers.first())
            .and_then(Value::as_str)
            .and_then(|raw| Url::parse(raw).ok());
        break;
    }
    // No resource metadata at all: per the MCP fallback, the server's own
    // origin acts as the authorization server.
    let issuer = issuer
        .or_else(|| Url::parse(&origin).ok())
        .ok_or_else(|| FlowFailure::plain("could not determine the authorization server"))?;
    require_secure(&issuer, "the authorization server")?;

    // Authorization server metadata (RFC 8414, then OIDC discovery).
    let issuer_origin = origin_of(&issuer);
    let issuer_path = issuer.path().trim_end_matches('/');
    let mut candidates = vec![
        format!("{issuer_origin}/.well-known/oauth-authorization-server{issuer_path}"),
        format!("{issuer_origin}/.well-known/openid-configuration{issuer_path}"),
    ];
    if !issuer_path.is_empty() {
        candidates.push(format!(
            "{issuer_origin}{issuer_path}/.well-known/openid-configuration"
        ));
    }
    for candidate in candidates {
        let Ok(url) = Url::parse(&candidate) else {
            continue;
        };
        let Ok(response) = client.get(url).send().await else {
            continue;
        };
        if !response.status().is_success() {
            continue;
        }
        let Ok(metadata) = response.json::<Value>().await else {
            continue;
        };
        let Some(authorization_endpoint) = metadata
            .get("authorization_endpoint")
            .and_then(Value::as_str)
            .and_then(|raw| Url::parse(raw).ok())
        else {
            continue;
        };
        let Some(token_endpoint) = metadata
            .get("token_endpoint")
            .and_then(Value::as_str)
            .and_then(|raw| Url::parse(raw).ok())
        else {
            continue;
        };
        require_secure(&authorization_endpoint, "the authorization endpoint")?;
        require_secure(&token_endpoint, "the token endpoint")?;
        let registration_endpoint = metadata
            .get("registration_endpoint")
            .and_then(Value::as_str)
            .and_then(|raw| Url::parse(raw).ok());
        if let Some(registration) = &registration_endpoint {
            require_secure(registration, "the registration endpoint")?;
        }
        // The issuer we validate the redirect against (RFC 9207). Prefer the
        // metadata's own `issuer`; fall back to the URL we discovered it at.
        let issuer_id = metadata
            .get("issuer")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| issuer.as_str().trim_end_matches('/').to_string());
        let iss_supported = metadata
            .get("authorization_response_iss_parameter_supported")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        return Ok(Discovered {
            authorization_endpoint,
            token_endpoint,
            registration_endpoint,
            resource,
            scope,
            issuer: issuer_id,
            iss_supported,
        });
    }
    Err(FlowFailure::hinted(
        "The authorization server published no usable metadata",
        "The server may not support browser sign-in — add it with a token instead.",
    ))
}

struct Registration {
    client_id: String,
    client_secret: Option<Zeroizing<String>>,
}

async fn register(
    client: &reqwest::Client,
    discovered: &Discovered,
    redirect_uri: &str,
) -> std::result::Result<Registration, FlowFailure> {
    let Some(registration_endpoint) = &discovered.registration_endpoint else {
        return Err(FlowFailure::hinted(
            "The authorization server does not offer automatic client registration",
            "Register an OAuth client with the provider and paste its client ID here, or add this server with a token instead.",
        ));
    };
    let mut body = json!({
        "client_name": "Multitool",
        "redirect_uris": [redirect_uri],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
        // SEP-837: a desktop app catching the redirect on a loopback socket
        // is an OIDC native client. Declaring it lets an OpenID-Connect
        // authorization server apply the right redirect-URI rules.
        "application_type": "native",
    });
    if let Some(scope) = &discovered.scope {
        body["scope"] = json!(scope);
    }
    let response = client
        .post(registration_endpoint.clone())
        .json(&body)
        .send()
        .await
        .map_err(|e| {
            FlowFailure::plain(format!("client registration failed: {}", e.without_url()))
        })?;
    let status = response.status();
    let payload: Value = response.json().await.unwrap_or(Value::Null);
    if !status.is_success() {
        let detail = payload
            .get("error_description")
            .or_else(|| payload.get("error"))
            .and_then(Value::as_str)
            .unwrap_or("no detail");
        return Err(FlowFailure::hinted(
            format!("client registration was refused (HTTP {status}: {detail})"),
            "Add this server with a token instead.",
        ));
    }
    let client_id = payload
        .get("client_id")
        .and_then(Value::as_str)
        .ok_or_else(|| FlowFailure::plain("client registration returned no client_id"))?
        .to_string();
    let client_secret = payload
        .get("client_secret")
        .and_then(Value::as_str)
        .map(|secret| Zeroizing::new(secret.to_string()));
    Ok(Registration {
        client_id,
        client_secret,
    })
}

/// Accept loopback connections until the OAuth redirect for our `state`
/// arrives. Anything else (favicons, port scans, mismatched state) is
/// answered and ignored — a stray request must not consume the flow.
async fn wait_for_callback(
    listener: TcpListener,
    expected_state: &str,
) -> std::result::Result<(String, Option<String>), FlowFailure> {
    for _ in 0..64 {
        let Ok((mut stream, _)) = listener.accept().await else {
            continue;
        };
        let mut buf = vec![0u8; 8192];
        let mut read = 0usize;
        let header_end = loop {
            match stream.read(&mut buf[read..]).await {
                Ok(0) => break None,
                Ok(n) => {
                    read += n;
                    if let Some(pos) = find_header_end(&buf[..read]) {
                        break Some(pos);
                    }
                    if read == buf.len() {
                        break None;
                    }
                }
                Err(_) => break None,
            }
        };
        let Some(_) = header_end else {
            let _ = respond(&mut stream, 400, "Bad request").await;
            continue;
        };
        let request_line = String::from_utf8_lossy(&buf[..read]);
        let path = request_line
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .unwrap_or("");
        let Ok(url) = Url::parse(&format!("http://127.0.0.1{path}")) else {
            let _ = respond(&mut stream, 400, "Bad request").await;
            continue;
        };
        if url.path() != "/callback" {
            let _ = respond(&mut stream, 404, "Not found").await;
            continue;
        }
        let mut code = None;
        let mut state = None;
        let mut iss = None;
        let mut error = None;
        let mut error_description = None;
        for (key, value) in url.query_pairs() {
            match key.as_ref() {
                "code" => code = Some(value.to_string()),
                "state" => state = Some(value.to_string()),
                "iss" => iss = Some(value.to_string()),
                "error" => error = Some(value.to_string()),
                "error_description" => error_description = Some(value.to_string()),
                _ => {}
            }
        }
        if state.as_deref() != Some(expected_state) {
            // Not our redirect (or a forgery): answer and keep waiting.
            let _ = respond(&mut stream, 400, "State mismatch").await;
            continue;
        }
        if let Some(error) = error {
            let description = error_description.unwrap_or_else(|| "no detail".into());
            let _ = respond(
                &mut stream,
                200,
                "Sign-in was not completed. You can close this tab.",
            )
            .await;
            if error == "access_denied" {
                return Err(FlowFailure::plain(
                    "you declined the authorization in the browser",
                ));
            }
            return Err(FlowFailure::plain(format!(
                "the authorization server reported {error}: {description}"
            )));
        }
        let Some(code) = code else {
            let _ = respond(&mut stream, 400, "Missing code").await;
            continue;
        };
        let _ = respond(
            &mut stream,
            200,
            "You’re connected. You can close this tab and return to Multitool.",
        )
        .await;
        return Ok((code, iss));
    }
    Err(FlowFailure::plain(
        "too many unrelated requests hit the sign-in listener",
    ))
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

async fn respond(
    stream: &mut tokio::net::TcpStream,
    status: u16,
    message: &str,
) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        404 => "Not Found",
        _ => "Bad Request",
    };
    let body = format!(
        "<!doctype html><meta charset=\"utf-8\"><title>Multitool</title>\
         <body style=\"font-family:system-ui;display:grid;place-items:center;height:100vh;margin:0\">\
         <p>{message}</p></body>"
    );
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await
}

pub(crate) struct Tokens {
    pub(crate) access_token: Zeroizing<String>,
    pub(crate) refresh_token: Option<Zeroizing<String>>,
    pub(crate) expires_in: Option<u64>,
}

/// The vault payload behind a connection's silent token refresh: the
/// refresh token together with everything a `refresh_token` grant needs
/// (client identity, token endpoint, RFC 8707 resource). Stored as JSON in
/// its own vault item — it is not a listed secret, and no command returns
/// it — so an expiring access token can be renewed without re-running the
/// browser dance.
#[derive(Debug, Serialize, Deserialize)]
pub struct McpOAuthGrant {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    pub client_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    pub token_endpoint: String,
    pub resource: String,
}

/// The refresh and client-secret material is scrubbed when a grant is
/// dropped, so it does not linger in freed heap — matching the
/// `Zeroizing` handling the token flow uses everywhere else. (`zeroize` v1
/// implements `Zeroize` for `String`/`Option<String>` without the derive
/// feature, so this needs no manual field bookkeeping beyond the two
/// secrets.)
impl Drop for McpOAuthGrant {
    fn drop(&mut self) {
        use zeroize::Zeroize as _;
        self.refresh_token.zeroize();
        self.client_secret.zeroize();
    }
}

impl McpOAuthGrant {
    pub fn to_secret_value(&self) -> Zeroizing<String> {
        Zeroizing::new(serde_json::to_string(self).expect("grant serializes"))
    }

    /// Return this grant with its refresh token replaced. Takes `self` by
    /// value so no field is moved out of a `Drop` type (struct-update
    /// syntax can't be used here for that reason).
    pub fn with_refresh_token(mut self, refresh_token: Option<String>) -> Self {
        self.refresh_token = refresh_token;
        self
    }

    pub fn from_secret_value(value: &str) -> std::result::Result<Self, String> {
        serde_json::from_str(value).map_err(|_| "stored OAuth grant is unreadable".to_string())
    }
}

async fn exchange(
    client: &reqwest::Client,
    discovered: &Discovered,
    registration: &Registration,
    redirect_uri: &str,
    code: &str,
    pkce_verifier: &str,
) -> std::result::Result<Tokens, FlowFailure> {
    let mut form: Vec<(&str, &str)> = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("client_id", &registration.client_id),
        ("code_verifier", pkce_verifier),
        ("resource", &discovered.resource),
    ];
    if let Some(secret) = &registration.client_secret {
        form.push(("client_secret", secret));
    }
    let response = client
        .post(discovered.token_endpoint.clone())
        // GitHub's token endpoint answers form-encoded unless JSON is
        // requested explicitly.
        .header(http::header::ACCEPT, "application/json")
        .form(&form)
        .send()
        .await
        .map_err(|e| FlowFailure::plain(format!("token exchange failed: {}", e.without_url())))?;
    let status = response.status();
    let payload: Value = response
        .json()
        .await
        .map_err(|e| FlowFailure::plain(format!("token endpoint returned invalid JSON: {e}")))?;
    if !status.is_success() {
        let detail = payload
            .get("error_description")
            .or_else(|| payload.get("error"))
            .and_then(Value::as_str)
            .unwrap_or("no detail");
        return Err(FlowFailure::plain(format!(
            "the token endpoint refused the exchange (HTTP {status}: {detail})"
        )));
    }
    parse_token_payload(&payload).map_err(FlowFailure::plain)
}

/// Shared shape of a successful token-endpoint answer, used by the
/// authorization-code exchange and the silent refresh alike.
pub(crate) fn parse_token_payload(payload: &Value) -> std::result::Result<Tokens, String> {
    let token_type = payload
        .get("token_type")
        .and_then(Value::as_str)
        .unwrap_or("bearer");
    if !token_type.eq_ignore_ascii_case("bearer") {
        return Err(format!("unsupported token type {token_type:?}"));
    }
    let access_token = payload
        .get("access_token")
        .and_then(Value::as_str)
        .map(|token| Zeroizing::new(token.to_string()))
        .ok_or_else(|| "the token endpoint returned no access token".to_string())?;
    Ok(Tokens {
        access_token,
        refresh_token: payload
            .get("refresh_token")
            .and_then(Value::as_str)
            .map(|token| Zeroizing::new(token.to_string())),
        expires_in: payload.get("expires_in").and_then(Value::as_u64),
    })
}

/* -------------------------------- helpers --------------------------------- */

fn origin_of(url: &Url) -> String {
    let mut origin = format!("{}://{}", url.scheme(), url.host_str().unwrap_or(""));
    if let Some(port) = url.port() {
        origin.push_str(&format!(":{port}"));
    }
    origin
}

/// Pull a quoted parameter out of a `WWW-Authenticate` challenge.
fn challenge_param(challenge: &str, name: &str) -> Option<String> {
    let lower = challenge.to_ascii_lowercase();
    let needle = format!("{name}=");
    let start = lower.find(&needle)? + needle.len();
    let rest = &challenge[start..];
    if let Some(stripped) = rest.strip_prefix('"') {
        return stripped.split('"').next().map(str::to_string);
    }
    rest.split([',', ' '])
        .next()
        .map(|value| value.trim().to_string())
}

fn random_urlsafe(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    getrandom::fill(&mut buf).expect("os rng");
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_params_parse_quoted_and_bare_forms() {
        let quoted = r#"Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource", error="invalid_token""#;
        assert_eq!(
            challenge_param(quoted, "resource_metadata").unwrap(),
            "https://mcp.example.com/.well-known/oauth-protected-resource"
        );
        let bare = "Bearer realm=mcp, resource_metadata=https://x.test/meta";
        assert_eq!(
            challenge_param(bare, "resource_metadata").unwrap(),
            "https://x.test/meta"
        );
        assert!(challenge_param("Bearer realm=mcp", "resource_metadata").is_none());
    }

    #[test]
    fn secure_urls_are_https_or_loopback() {
        let ok = Url::parse("https://auth.example.com/authorize").unwrap();
        assert!(require_secure(&ok, "x").is_ok());
        let local = Url::parse("http://127.0.0.1:8080/authorize").unwrap();
        assert!(require_secure(&local, "x").is_ok());
        let plain = Url::parse("http://auth.example.com/authorize").unwrap();
        assert!(require_secure(&plain, "x").is_err());
    }

    #[test]
    fn flow_failures_start_with_a_capital() {
        assert_eq!(
            FlowFailure::plain("the server did not answer").message,
            "The server did not answer"
        );
        assert_eq!(
            FlowFailure::hinted("could not sign in", "Try again.").message,
            "Could not sign in"
        );
    }

    #[test]
    fn header_end_detection() {
        assert_eq!(
            find_header_end(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
            Some(23)
        );
        assert_eq!(find_header_end(b"GET / HTTP/1.1\r\n"), None);
    }

    #[test]
    fn iss_is_validated_per_rfc_9207() {
        let expected = "https://auth.example.com";
        // A matching issuer passes, trailing slash and all.
        assert!(validate_iss(Some("https://auth.example.com"), expected, true).is_ok());
        assert!(validate_iss(Some("https://auth.example.com/"), expected, true).is_ok());
        // A different issuer is a mix-up attempt.
        assert!(validate_iss(Some("https://evil.example.com"), expected, true).is_err());
        // Absent iss: fatal only when the server said it would send one.
        assert!(validate_iss(None, expected, true).is_err());
        assert!(validate_iss(None, expected, false).is_ok());
    }

    #[test]
    fn pkce_material_is_urlsafe() {
        let verifier = random_urlsafe(48);
        assert_eq!(verifier.len(), 64);
        assert!(verifier
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn reconnect_sessions_are_serialized_per_connection() {
        fn state(id: Uuid) -> McpAuthState {
            McpAuthState {
                id: id.to_string(),
                name: "tool".into(),
                target: "https://example.test/mcp".into(),
                phase: McpAuthPhase::Probing,
                updated_at: Utc::now(),
            }
        }

        let sessions = McpAuthSessions::default();
        let connection = Uuid::new_v4();
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        assert!(sessions.insert(first, state(first), Some(connection)));
        assert!(
            !sessions.insert(second, state(second), Some(connection)),
            "a second live reconnect must be refused"
        );
        sessions.set_phase(&first, McpAuthPhase::Cancelled);
        assert!(
            sessions.insert(second, state(second), Some(connection)),
            "a terminal reconnect releases the connection"
        );
    }
}
