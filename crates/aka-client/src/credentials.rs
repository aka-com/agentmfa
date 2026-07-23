//! Client-side storage for the management token.
//!
//! The token authorizes full management of a (possibly remote) broker, so
//! it gets the same treatment the broker gives its own secrets: the macOS
//! login Keychain where available, and a 0600 file fallback elsewhere
//! (dev/CI parity with the core's `FileVault`, with the same warning).
//! One token is stored per broker URL, so switching brokers never silently
//! reuses the wrong credential.

use std::path::PathBuf;

use zeroize::Zeroizing;

/// Keychain service for stored management tokens.
#[cfg(target_os = "macos")]
const KEYCHAIN_SERVICE: &str = "com.aka.desktop.manage";

pub struct TokenStore {
    /// Directory for the non-macOS fallback file(s).
    dir: PathBuf,
}

/// The account/filename key for a broker URL: scheme, host, and port only,
/// filesystem- and keychain-safe.
fn key_for(url: &str) -> String {
    url.trim_end_matches('/')
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

impl TokenStore {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    #[cfg(target_os = "macos")]
    fn entry(url: &str) -> Result<keyring::Entry, String> {
        keyring::Entry::new(KEYCHAIN_SERVICE, &key_for(url)).map_err(|error| error.to_string())
    }

    #[cfg(target_os = "macos")]
    pub fn save(&self, url: &str, token: &str) -> Result<(), String> {
        Self::entry(url)?
            .set_password(token)
            .map_err(|error| error.to_string())
    }

    #[cfg(target_os = "macos")]
    pub fn load(&self, url: &str) -> Option<Zeroizing<String>> {
        Self::entry(url)
            .ok()?
            .get_password()
            .ok()
            .map(Zeroizing::new)
    }

    #[cfg(target_os = "macos")]
    pub fn delete(&self, url: &str) {
        if let Ok(entry) = Self::entry(url) {
            let _ = entry.delete_credential();
        }
    }

    #[cfg(not(target_os = "macos"))]
    fn path_for(&self, url: &str) -> PathBuf {
        self.dir.join(format!("manage-token-{}", key_for(url)))
    }

    #[cfg(not(target_os = "macos"))]
    pub fn save(&self, url: &str, token: &str) -> Result<(), String> {
        use std::io::Write as _;
        use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
        tracing::warn!(
            "storing the management token in a plain file (no keychain on \
             this platform); dev fallback only"
        );
        std::fs::create_dir_all(&self.dir).map_err(|error| error.to_string())?;
        let path = self.path_for(url);
        // Created 0600 from the first byte — never world-readable, not even
        // between a write and a chmod.
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)
            .map_err(|error| error.to_string())?;
        file.write_all(token.as_bytes())
            .map_err(|error| error.to_string())?;
        // `mode` only applies at creation; tighten a pre-existing file too.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .map_err(|error| error.to_string())
    }

    #[cfg(not(target_os = "macos"))]
    pub fn load(&self, url: &str) -> Option<Zeroizing<String>> {
        let token = std::fs::read_to_string(self.path_for(url)).ok()?;
        let token = token.trim();
        (!token.is_empty()).then(|| Zeroizing::new(token.to_string()))
    }

    #[cfg(not(target_os = "macos"))]
    pub fn delete(&self, url: &str) {
        let _ = std::fs::remove_file(self.path_for(url));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_scoped_per_url_and_safe() {
        assert_eq!(
            key_for("https://broker.example.dev/"),
            "https___broker_example_dev"
        );
        assert_ne!(key_for("http://a:1"), key_for("http://a:2"));
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn file_fallback_round_trips_per_url() {
        let dir = tempfile::tempdir().unwrap();
        let store = TokenStore::new(dir.path().to_path_buf());
        assert!(store.load("http://a:1").is_none());
        store.save("http://a:1", "akamgr_one").unwrap();
        store.save("http://a:2", "akamgr_two").unwrap();
        assert_eq!(store.load("http://a:1").unwrap().as_str(), "akamgr_one");
        assert_eq!(store.load("http://a:2").unwrap().as_str(), "akamgr_two");
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(dir.path().join("manage-token-http___a_1"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        store.delete("http://a:1");
        assert!(store.load("http://a:1").is_none());
    }
}
