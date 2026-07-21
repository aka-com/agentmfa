//! Filesystem layout.
//!
//! - Non-secret state (`index.json`, `rules.json`, `agents.json`,
//!   `audit.jsonl`) lives under the per-user data directory,
//!   `~/Library/Application Support/aka` on macOS.
//! - The control-plane rendezvous point is `~/.aka/broker.sock`
//!   (short and space-free: it never needs shell quoting and stays well
//!   clear of the 104-byte `sun_path` limit). A persistent `broker.lock`
//!   serializes startup and stale-socket repair. `~/.aka` is created
//!   `0700`; the lock and socket are `0600`.

use std::fs;
use std::io;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct Paths {
    /// Non-secret app state: index.json, rules.json, agents.json, audit.jsonl.
    pub data_dir: PathBuf,
    /// `~/.aka`, the socket directory (also the advisory token home
    /// that `/instructions` names for agents).
    pub socket_dir: PathBuf,
}

/// Process lifetime lease for the broker's state and rendezvous point.
///
/// The lock file itself deliberately persists. Removing it on Drop would let
/// another process create and lock a different inode before this process had
/// closed the old locked file. The OS releases the advisory lock when this
/// value is dropped or the process exits.
#[must_use = "dropping the broker lease releases it immediately"]
pub struct BrokerInstanceLock {
    _file: fs::File,
}

impl BrokerInstanceLock {
    /// Try to acquire the broker lease without blocking. `Ok(None)` means a
    /// live process already owns it; other filesystem/locking failures retain
    /// their underlying I/O diagnosis.
    fn try_acquire(path: &Path) -> io::Result<Option<Self>> {
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(path)?;
        match file.try_lock() {
            Ok(()) => {}
            Err(fs::TryLockError::WouldBlock) => return Ok(None),
            Err(fs::TryLockError::Error(error)) => return Err(error),
        }
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        Ok(Some(Self { _file: file }))
    }
}

impl Paths {
    /// Production layout, rooted at the user's home.
    pub fn default_locations() -> io::Result<Self> {
        let data_dir = dirs::data_dir()
            .ok_or_else(|| io::Error::other("no per-user data directory"))?
            .join("aka");
        let socket_dir = dirs::home_dir()
            .ok_or_else(|| io::Error::other("no home directory"))?
            .join(".aka");
        Ok(Self {
            data_dir,
            socket_dir,
        })
    }

    /// Everything under one root, used by tests and the dev harness.
    pub fn under(root: &Path) -> Self {
        Self {
            data_dir: root.join("data"),
            socket_dir: root.join("sock"),
        }
    }

    pub fn index_file(&self) -> PathBuf {
        self.data_dir.join("index.json")
    }
    pub fn wirings_file(&self) -> PathBuf {
        self.data_dir.join("wirings.json")
    }
    /// Legacy standing-rules file; read once to migrate into wirings.
    pub fn rules_file(&self) -> PathBuf {
        self.data_dir.join("rules.json")
    }
    pub fn agents_file(&self) -> PathBuf {
        self.data_dir.join("agents.json")
    }
    pub fn audit_file(&self) -> PathBuf {
        self.data_dir.join("audit.jsonl")
    }
    /// Dev-only fallback vault (non-macOS builds); see `vault::FileVault`.
    pub fn dev_vault_file(&self) -> PathBuf {
        self.data_dir.join("dev-vault.json")
    }
    pub fn socket_file(&self) -> PathBuf {
        self.socket_dir.join("broker.sock")
    }
    /// Persistent advisory lock whose OS lock, not filesystem presence,
    /// serializes broker startup and stale-socket recovery.
    pub fn broker_lock_file(&self) -> PathBuf {
        self.socket_dir.join("broker.lock")
    }
    /// Try to acquire the process lease guarding both persistent broker state
    /// and the control-plane rendezvous point. Every process that opens the
    /// state for writing, including offline CLI commands, must hold this guard
    /// until its state handles have been dropped.
    pub fn try_acquire_broker_lock(&self) -> io::Result<Option<BrokerInstanceLock>> {
        BrokerInstanceLock::try_acquire(&self.broker_lock_file())
    }
    /// The advisory token home `/instructions` tells agents to persist
    /// pair tokens in (one file per agent name, mode 0600).
    pub fn tokens_dir(&self) -> PathBuf {
        self.socket_dir.join("tokens")
    }
    /// Per-open SSH agent sockets live here, one `agent-<suffix>.sock` per
    /// approved `/v1/ssh/open`.
    pub fn ssh_agent_dir(&self) -> PathBuf {
        self.socket_dir.join("ssh")
    }

    /// `socket_file()` for display: home shortened to `~`.
    pub fn socket_display(&self) -> String {
        display_tilde(&self.socket_file())
    }
    /// `tokens_dir()` for display: home shortened to `~`.
    pub fn tokens_display(&self) -> String {
        display_tilde(&self.tokens_dir())
    }

    /// Create the directories with owner-only permissions, including the
    /// advisory token home, so agents following the instructions never have
    /// to mkdir (and get the permissions right) themselves.
    pub fn ensure(&self) -> io::Result<()> {
        create_private_dir(&self.data_dir)?;
        create_private_dir(&self.socket_dir)?;
        create_private_dir(&self.tokens_dir())?;
        create_private_dir(&self.ssh_agent_dir())?;
        Ok(())
    }

    /// Move the persistent app data directory aside so the next boot starts
    /// with fresh local state while preserving the old files for inspection or
    /// manual restore. Runtime sockets/tokens under `socket_dir` are left alone.
    pub fn archive_data_dir(&self) -> io::Result<PathBuf> {
        archive_dir_with_suffix(&self.data_dir, "bak")
    }
}

/// Render a path with the user's home directory shortened to `~`, the form
/// the discovery documents use.
pub fn display_tilde(path: &Path) -> String {
    if let Some(home) = dirs::home_dir() {
        if let Ok(rest) = path.strip_prefix(&home) {
            return format!("~/{}", rest.display());
        }
    }
    path.display().to_string()
}

pub(crate) fn create_private_dir(dir: &Path) -> io::Result<()> {
    fs::create_dir_all(dir)?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

/// Write `bytes` to `path` atomically (temp file + rename) with `0600` perms.
pub(crate) fn write_private_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| io::Error::other("path has no parent"))?;
    fs::create_dir_all(dir)?;
    let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
    io::Write::write_all(&mut tmp, bytes)?;
    tmp.as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(|e| e.error)?;
    Ok(())
}

fn archive_dir_with_suffix(dir: &Path, suffix: &str) -> io::Result<PathBuf> {
    let parent = dir
        .parent()
        .ok_or_else(|| io::Error::other("data directory has no parent"))?;
    fs::create_dir_all(parent)?;

    if !dir.exists() {
        return Ok(unique_archive_path(dir, suffix));
    }

    let archive = unique_archive_path(dir, suffix);
    fs::rename(dir, &archive)?;
    Ok(archive)
}

fn unique_archive_path(dir: &Path, suffix: &str) -> PathBuf {
    let base_name = dir
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "aka".into());
    let stamp = chrono::Utc::now().format("%Y%m%d-%H%M%S");
    let base = dir.with_file_name(format!("{base_name}.{suffix}-{stamp}"));
    if !base.exists() {
        return base;
    }
    for i in 1.. {
        let candidate = dir.with_file_name(format!("{base_name}.{suffix}-{stamp}-{i}"));
        if !candidate.exists() {
            return candidate;
        }
    }
    unreachable!("unbounded archive suffix search")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_locations_use_aka_directories() {
        let paths = Paths::default_locations().unwrap();
        assert_eq!(paths.data_dir.file_name().unwrap(), "aka");
        assert_eq!(paths.socket_dir.file_name().unwrap(), ".aka");
    }

    #[test]
    fn archive_data_dir_moves_data_but_not_socket_state() {
        let root = tempfile::tempdir().unwrap();
        let paths = Paths::under(root.path());
        paths.ensure().unwrap();
        fs::write(paths.index_file(), b"index").unwrap();
        fs::write(paths.rules_file(), b"rules").unwrap();
        fs::write(paths.agents_file(), b"agents").unwrap();
        fs::write(paths.audit_file(), b"audit").unwrap();
        fs::write(paths.tokens_dir().join("agent"), b"token").unwrap();

        let archive = paths.archive_data_dir().unwrap();

        assert!(!paths.data_dir.exists());
        assert_eq!(fs::read(archive.join("index.json")).unwrap(), b"index");
        assert_eq!(fs::read(archive.join("rules.json")).unwrap(), b"rules");
        assert_eq!(fs::read(archive.join("agents.json")).unwrap(), b"agents");
        assert_eq!(fs::read(archive.join("audit.jsonl")).unwrap(), b"audit");
        assert_eq!(
            fs::read(paths.tokens_dir().join("agent")).unwrap(),
            b"token"
        );
    }

    #[test]
    fn archive_data_dir_chooses_unique_backup_name() {
        let root = tempfile::tempdir().unwrap();
        let paths = Paths::under(root.path());
        paths.ensure().unwrap();

        let first = paths.archive_data_dir().unwrap();
        paths.ensure().unwrap();
        let second = paths.archive_data_dir().unwrap();

        assert_ne!(first, second);
        assert!(first.exists());
        assert!(second.exists());
    }
}
