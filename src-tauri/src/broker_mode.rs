//! Local/remote broker switching.
//!
//! The shell manages exactly one broker at a time: the in-process local
//! stack, or a remote broker over its manage API. This module owns the
//! active backend, the persisted choice, the remote link (SSE → Tauri
//! events), and the transitions between the two — including tearing the
//! local runtime down off the async runtime (dropping a tokio runtime on
//! an async thread panics).

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};

use aka_client::{credentials::TokenStore, RemoteBackend, RemoteConfig};
use aka_core::manage::ManagementBackend;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter as _};

use crate::commands::LocalRuntime;

/// What the webview renders the header switcher and takeover panes from.
#[derive(Debug, Clone, Serialize)]
pub struct BrokerProfileInfo {
    /// "local" | "remote".
    pub mode: String,
    /// The remote broker's URL (remote mode only).
    pub url: Option<String>,
    /// Whether the managed broker is reachable right now. Local mode is
    /// always connected — the broker lives in this process.
    pub connected: bool,
    /// Why not, when it isn't.
    pub error: Option<String>,
    /// A saved management token exists for `url`, so the connect form can
    /// offer to reuse it.
    pub has_saved_token: bool,
}

impl BrokerProfileInfo {
    fn local() -> Self {
        Self {
            mode: "local".into(),
            url: None,
            connected: true,
            error: None,
            has_saved_token: false,
        }
    }
}

/// The persisted mode choice (`shell.json` in the app data dir). The token
/// itself lives in the token store, never here.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ShellConfig {
    #[serde(default)]
    mode: Option<String>,
    #[serde(default)]
    remote_url: Option<String>,
}

/// The remote link: the backend plus its event-stream task.
struct RemoteRuntime {
    /// Kept so the link's backend lives as long as its stream task.
    _backend: Arc<RemoteBackend>,
    sse_task: tauri::async_runtime::JoinHandle<()>,
}

impl Drop for RemoteRuntime {
    fn drop(&mut self) {
        self.sse_task.abort();
    }
}

pub struct BrokerState {
    backend: RwLock<Arc<dyn ManagementBackend>>,
    local: Mutex<Option<LocalRuntime>>,
    remote: Mutex<Option<RemoteRuntime>>,
    profile: Mutex<BrokerProfileInfo>,
    data_dir: PathBuf,
    tokens: TokenStore,
    /// Transition attempts, monotonically numbered. A transition captures
    /// the counter when it begins and refuses to commit if another attempt
    /// began while it awaited (probe/startup): the user's latest choice
    /// wins, and a slow earlier attempt can never override it. Commits run
    /// holding this lock, so they are also mutually exclusive.
    transition_epoch: Mutex<u64>,
}

/// The error a transition reports when it lost to a newer one. Compared by
/// [`BrokerState::start_saved_remote`] to keep a lost startup attempt from
/// stomping the link state the winning transition established.
const TRANSITION_SUPERSEDED: &str =
    "the broker choice changed while connecting; nothing was applied";

/// The event the webview listens to for switcher/link state.
pub const EVT_BROKER: &str = "aka://broker-changed";

fn config_path(data_dir: &Path) -> PathBuf {
    data_dir.join("shell.json")
}

fn load_config(data_dir: &Path) -> ShellConfig {
    std::fs::read(config_path(data_dir))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

fn save_config(data_dir: &Path, config: &ShellConfig) {
    let _ = std::fs::create_dir_all(data_dir);
    if let Ok(bytes) = serde_json::to_vec_pretty(config) {
        if let Err(error) = std::fs::write(config_path(data_dir), bytes) {
            tracing::warn!(%error, "could not persist the broker-mode choice");
        }
    }
}

/// The saved remote URL, when the persisted mode choice is remote.
pub fn saved_remote(data_dir: &Path) -> Option<String> {
    let config = load_config(data_dir);
    match config.mode.as_deref() {
        Some("remote") => config.remote_url,
        _ => None,
    }
}

impl BrokerState {
    /// Construct for local mode with an already-started local runtime.
    pub fn new_local(data_dir: PathBuf, runtime: LocalRuntime) -> Self {
        let backend: Arc<dyn ManagementBackend> = Arc::new(
            aka_core::manage::LocalBackend::new(runtime.broker.clone()),
        );
        Self {
            backend: RwLock::new(backend),
            local: Mutex::new(Some(runtime)),
            remote: Mutex::new(None),
            profile: Mutex::new(BrokerProfileInfo::local()),
            tokens: TokenStore::new(data_dir.clone()),
            data_dir,
            transition_epoch: Mutex::new(0),
        }
    }

    /// Construct for remote mode from the saved choice; the connection is
    /// attempted by [`Self::start_saved_remote`] after the app is up.
    pub fn new_remote_pending(data_dir: PathBuf, url: String) -> Self {
        let tokens = TokenStore::new(data_dir.clone());
        let has_saved_token = tokens.load(&url).is_some();
        // Until the probe finishes there is still a backend to answer
        // commands: the remote one (with a placeholder token when none is
        // saved — every call then fails with a clear auth error rather
        // than a crash, and the takeover pane is what the user sees).
        let token = tokens
            .load(&url)
            .unwrap_or_else(|| zeroize::Zeroizing::new("akamgr_unconfigured".into()));
        let config = RemoteConfig::new(&url, &token)
            .unwrap_or_else(|_| RemoteConfig::new("http://127.0.0.1:1", "akamgr_unconfigured").expect("static config"));
        let backend: Arc<dyn ManagementBackend> = Arc::new(
            RemoteBackend::new(config)
                .with_opener(Arc::new(crate::events::open_consent_url)),
        );
        Self {
            backend: RwLock::new(backend),
            local: Mutex::new(None),
            remote: Mutex::new(None),
            profile: Mutex::new(BrokerProfileInfo {
                mode: "remote".into(),
                url: Some(url),
                connected: false,
                error: None,
                has_saved_token,
            }),
            tokens,
            data_dir,
            transition_epoch: Mutex::new(0),
        }
    }

    /// Begin a transition attempt: bump the counter, invalidating any
    /// attempt still in flight.
    fn begin_transition(&self) -> u64 {
        let mut epoch = self.transition_epoch.lock().unwrap();
        *epoch += 1;
        *epoch
    }

    /// Take the commit lock — `None` when a newer attempt began, in which
    /// case the caller must apply nothing. No awaiting while held.
    fn transition_guard(&self, epoch: u64) -> Option<std::sync::MutexGuard<'_, u64>> {
        let guard = self.transition_epoch.lock().unwrap();
        (*guard == epoch).then_some(guard)
    }

    /// The active backend (cloned out so no lock is held across awaits).
    pub fn backend(&self) -> Arc<dyn ManagementBackend> {
        self.backend.read().unwrap().clone()
    }

    /// The local broker, when local mode is active (window chrome reads a
    /// setting synchronously).
    pub fn local_broker(&self) -> Option<Arc<aka_core::broker::Broker>> {
        self.local
            .lock()
            .unwrap()
            .as_ref()
            .map(|runtime| runtime.broker.clone())
    }

    pub fn profile(&self) -> BrokerProfileInfo {
        self.profile.lock().unwrap().clone()
    }

    fn set_profile(&self, app: &AppHandle, profile: BrokerProfileInfo) {
        *self.profile.lock().unwrap() = profile.clone();
        let _ = app.emit(EVT_BROKER, profile);
    }

    fn update_link(&self, app: &AppHandle, connected: bool, error: Option<String>) {
        let mut profile = self.profile.lock().unwrap();
        if profile.mode != "remote" {
            return;
        }
        profile.connected = connected;
        profile.error = error;
        let snapshot = profile.clone();
        drop(profile);
        let _ = app.emit(EVT_BROKER, snapshot);
    }

    /// Connect to (and switch to) a remote broker. `token: None` reuses the
    /// saved one for that URL. On success the choice and token persist and
    /// the local stack (if any) is torn down; on failure nothing changes
    /// and the message is for the connect form.
    pub async fn connect_remote(
        self: &Arc<Self>,
        app: &AppHandle,
        url: String,
        token: Option<String>,
    ) -> Result<BrokerProfileInfo, String> {
        let saved = self.tokens.load(&url);
        let token = match token.as_deref().map(str::trim).filter(|t| !t.is_empty()) {
            Some(token) => token.to_string(),
            None => match &saved {
                Some(saved) => saved.to_string(),
                None => return Err("enter the broker's management token".into()),
            },
        };
        let config = RemoteConfig::new(&url, &token)?;
        let url = config.base_url();
        let backend = Arc::new(
            RemoteBackend::new(config)
                .with_opener(Arc::new(crate::events::open_consent_url)),
        );
        let epoch = self.begin_transition();
        backend
            .whoami()
            .await
            .map_err(|error| error.to_string())?;

        // The probe succeeded: persist, swap, and (re)arm the link — unless
        // another transition began while the probe was in flight (the user
        // switched to this Mac, retried, or connected elsewhere); the later
        // choice wins and this attempt applies nothing.
        let (profile, stale_local) = {
            let Some(_commit) = self.transition_guard(epoch) else {
                return Err(TRANSITION_SUPERSEDED.into());
            };
            if let Err(error) = self.tokens.save(&url, &token) {
                tracing::warn!(%error, "could not store the management token");
            }
            save_config(
                &self.data_dir,
                &ShellConfig {
                    mode: Some("remote".into()),
                    remote_url: Some(url.clone()),
                },
            );
            self.teardown_remote();
            let stale_local = self.local.lock().unwrap().take();
            *self.backend.write().unwrap() = backend.clone();
            self.arm_sse(app, backend);
            let profile = BrokerProfileInfo {
                mode: "remote".into(),
                url: Some(url),
                connected: true,
                error: None,
                has_saved_token: true,
            };
            self.set_profile(app, profile.clone());
            (profile, stale_local)
        };
        // The displaced local stack (if any) is dropped after the commit,
        // off the async runtime: dropping a tokio runtime from async
        // context panics.
        if let Some(runtime) = stale_local {
            let _ = tauri::async_runtime::spawn_blocking(move || drop(runtime)).await;
        }
        Ok(profile)
    }

    /// Re-attempt the saved remote connection (the error pane's Retry).
    pub async fn retry_remote(
        self: &Arc<Self>,
        app: &AppHandle,
    ) -> Result<BrokerProfileInfo, String> {
        let url = self
            .profile()
            .url
            .ok_or_else(|| "no remote broker is configured".to_string())?;
        self.connect_remote(app, url, None).await
    }

    /// Called once at startup when the saved mode is remote: try the saved
    /// connection in the background; the webview renders the takeover pane
    /// from the profile either way.
    pub fn start_saved_remote(self: Arc<Self>, app: AppHandle) {
        tauri::async_runtime::spawn(async move {
            let Some(url) = self.profile().url else { return };
            match self.connect_remote(&app, url, None).await {
                Ok(_) => {}
                // A superseded attempt lost to a user-initiated transition
                // that already set the profile; reporting it as a link
                // failure would stomp the winner's state.
                Err(message) if message == TRANSITION_SUPERSEDED => {}
                Err(message) => self.update_link(&app, false, Some(message)),
            }
        });
    }

    /// Switch to this Mac's local broker, starting the local stack.
    pub async fn switch_local(
        self: &Arc<Self>,
        app: &AppHandle,
    ) -> Result<BrokerProfileInfo, String> {
        if self.profile().mode == "local" && self.local.lock().unwrap().is_some() {
            return Ok(self.profile());
        }
        let epoch = self.begin_transition();
        // Start the local stack first: if it cannot start (another broker
        // holds the instance lock, say), the remote link must stay armed so
        // the user still has a working mode to stand on.
        let handle = app.clone();
        let runtime = tauri::async_runtime::spawn_blocking(move || {
            crate::start_local_runtime(&handle)
        })
        .await
        .map_err(|error| format!("local broker start stopped: {error}"))?
        .map_err(|error| error.to_string())?;
        // Commit under the transition lock; `runtime` stays in the slot
        // when the commit is refused so it can be dropped off-thread below
        // (the guard must not be held across an await).
        let mut runtime = Some(runtime);
        let committed = {
            match self.transition_guard(epoch) {
                Some(_commit) => {
                    self.teardown_remote();
                    let started = runtime.take().expect("freshly started runtime");
                    let backend: Arc<dyn ManagementBackend> = Arc::new(
                        aka_core::manage::LocalBackend::new(started.broker.clone()),
                    );
                    *self.local.lock().unwrap() = Some(started);
                    *self.backend.write().unwrap() = backend;
                    save_config(
                        &self.data_dir,
                        &ShellConfig {
                            mode: Some("local".into()),
                            remote_url: self.profile().url,
                        },
                    );
                    let profile = BrokerProfileInfo::local();
                    self.set_profile(app, profile.clone());
                    Some(profile)
                }
                None => None,
            }
        };
        match committed {
            Some(profile) => Ok(profile),
            None => {
                // A newer transition began while the stack was starting;
                // drop the fresh runtime off the async thread (dropping a
                // tokio runtime in async context panics) and apply nothing.
                if let Some(started) = runtime.take() {
                    let _ =
                        tauri::async_runtime::spawn_blocking(move || drop(started)).await;
                }
                Err(TRANSITION_SUPERSEDED.into())
            }
        }
    }

    /// Stop the remote link (keeps the saved token and URL).
    fn teardown_remote(&self) {
        *self.remote.lock().unwrap() = None;
    }

    /// Start the remote event stream, re-emitting manage events as the
    /// same Tauri events local mode produces so the webview stays mode-
    /// blind, and reflecting link transitions into the profile.
    fn arm_sse(self: &Arc<Self>, app: &AppHandle, backend: Arc<RemoteBackend>) {
        let state = self.clone();
        let app = app.clone();
        let event_app = app.clone();
        let sse_backend = backend.clone();
        let task = tauri::async_runtime::spawn(async move {
            aka_client::events::subscribe(
                sse_backend,
                move |event| crate::events::emit_manage_event(&event_app, event),
                move |link| match link {
                    aka_client::events::LinkState::Connected => {
                        state.update_link(&app, true, None);
                    }
                    aka_client::events::LinkState::Disconnected { message } => {
                        state.update_link(&app, false, Some(message));
                    }
                },
            )
            .await;
        });
        *self.remote.lock().unwrap() = Some(RemoteRuntime {
            _backend: backend,
            sse_task: task,
        });
    }
}
