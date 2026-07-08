//! Filesystem layout (DESIGN.md §3, §8).
//!
//! - Non-secret state (`index.json`, `rules.json`, `agents.json`,
//!   `audit.jsonl`) lives under the per-user data directory,
//!   `~/Library/Application Support/agentmfa` on macOS.
//! - The control-plane rendezvous point is `~/.agentmfa/broker.sock`
//!   (short and space-free: it never needs shell quoting and stays well
//!   clear of the 104-byte `sun_path` limit). `~/.agentmfa` is created
//!   `0700`; the socket itself is `0600`.

use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct Paths {
    /// Non-secret app state: index.json, rules.json, agents.json, audit.jsonl.
    pub data_dir: PathBuf,
    /// `~/.agentmfa`, the socket directory (also the advisory token home
    /// that `/instructions` names for agents).
    pub socket_dir: PathBuf,
}

impl Paths {
    /// Production layout, rooted at the user's home.
    pub fn default_locations() -> io::Result<Self> {
        let data_dir = dirs::data_dir()
            .ok_or_else(|| io::Error::other("no per-user data directory"))?
            .join("agentmfa");
        let socket_dir = dirs::home_dir()
            .ok_or_else(|| io::Error::other("no home directory"))?
            .join(".agentmfa");
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
    /// The advisory token home `/instructions` tells agents to persist
    /// pair tokens in (one file per agent name, mode 0600).
    pub fn tokens_dir(&self) -> PathBuf {
        self.socket_dir.join("tokens")
    }
    /// Per-open SSH agent sockets live here (DESIGN.md §4.4), one
    /// `agent-<suffix>.sock` per approved `/v1/ssh/open`.
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
