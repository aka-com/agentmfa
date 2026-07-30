//! The broker capability surface: the agent supplies the
//! *what* (method, path, body); the connection supplies the *where* (host,
//! database, URL) and the credential.

pub mod http;
pub mod pg;
pub mod ssh;

use std::io::{Read as _, Seek as _, Write as _};
use std::sync::Mutex;

/// Why a connection dial or test failed, as a value the UI (and the broker's
/// own health grading) can branch on. The prose in [`TestError::detail`] is
/// presentation only — nothing may match on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TestErrorKind {
    /// Nothing usable answered at the configured destination.
    Unreachable,
    /// The server answered but refused to start TLS while the connection's
    /// TLS mode requires it.
    TlsDeclined,
    /// TLS started but the server's certificate could not be verified.
    CertUnverified,
    /// The server asked for a password the dial deliberately did not carry
    /// (a draft test referencing a stored secret, or a connection with no
    /// secret bound).
    NeedsPassword,
    /// The destination answered and rejected the credential.
    AuthRejected,
    /// The destination answered with something other than the expected
    /// protocol (e.g. the port is not actually Postgres).
    WrongProtocol,
    /// The test hit its deadline.
    Timeout,
    /// Any other failure; the detail carries all there is to know.
    Other,
}

/// A failed connection dial or test: machine-readable kind + human prose.
#[derive(Debug, Clone)]
pub struct TestError {
    pub kind: TestErrorKind,
    pub detail: String,
}

impl TestErrorKind {
    /// The connection health a failure of this kind implies. A credential the
    /// destination actively rejected reads as "reconnect" — retrying will not
    /// help — while everything else is a plain failure worth retrying.
    ///
    /// Shared so a brokered call and the Test button grade the same failure
    /// the same way; a data-plane dial is as conclusive about the destination
    /// as an explicit test is.
    pub fn health_status(&self) -> crate::types::HealthStatus {
        match self {
            TestErrorKind::AuthRejected => crate::types::HealthStatus::NeedsReconnect,
            _ => crate::types::HealthStatus::Failed,
        }
    }
}

impl TestError {
    pub fn new(kind: TestErrorKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
        }
    }
}

/// Plain-string errors (the long tail of internal failures) carry no kind.
impl From<String> for TestError {
    fn from(detail: String) -> Self {
        Self::new(TestErrorKind::Other, detail)
    }
}

impl From<&str> for TestError {
    fn from(detail: &str) -> Self {
        Self::new(TestErrorKind::Other, detail.to_string())
    }
}

impl std::fmt::Display for TestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.detail)
    }
}

/// A request body, held in memory below the spool threshold and in an
/// unlinked temp file above it, a parked, awaiting-approval request holds
/// its body, so concurrent uploads must not pin RAM.
pub enum SpooledBody {
    Empty,
    Inline(Vec<u8>),
    Spooled {
        file: Mutex<std::fs::File>,
        len: u64,
    },
}

#[derive(Debug)]
pub enum SpoolError {
    TooLarge,
    Io(std::io::Error),
}

impl From<std::io::Error> for SpoolError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

/// Incremental request-body spool. It retains at most `spool_threshold`
/// bytes in memory, switches to an unlinked file once crossed, and enforces
/// the wire-size cap before accepting each chunk.
pub struct BodySpool {
    inline: Vec<u8>,
    file: Option<std::fs::File>,
    len: usize,
    spool_threshold: usize,
    cap: usize,
}

impl BodySpool {
    pub fn new(spool_threshold: usize, cap: usize) -> Self {
        Self {
            inline: Vec::with_capacity(spool_threshold.min(cap)),
            file: None,
            len: 0,
            spool_threshold,
            cap,
        }
    }

    pub fn push(&mut self, chunk: &[u8]) -> Result<(), SpoolError> {
        let next_len = self
            .len
            .checked_add(chunk.len())
            .filter(|len| *len <= self.cap)
            .ok_or(SpoolError::TooLarge)?;
        if let Some(file) = self.file.as_mut() {
            file.write_all(chunk)?;
        } else if next_len <= self.spool_threshold {
            self.inline.extend_from_slice(chunk);
        } else {
            let mut file = tempfile::tempfile()?;
            file.write_all(&self.inline)?;
            file.write_all(chunk)?;
            self.inline.clear();
            self.file = Some(file);
        }
        self.len = next_len;
        Ok(())
    }

    pub fn finish(self) -> Result<SpooledBody, SpoolError> {
        let Some(mut file) = self.file else {
            return if self.inline.is_empty() {
                Ok(SpooledBody::Empty)
            } else {
                Ok(SpooledBody::Inline(self.inline))
            };
        };
        file.flush()?;
        Ok(SpooledBody::Spooled {
            file: Mutex::new(file),
            len: self.len as u64,
        })
    }
}

impl SpooledBody {
    pub fn from_bytes(bytes: Vec<u8>, spool_threshold: usize) -> std::io::Result<Self> {
        if bytes.is_empty() {
            return Ok(SpooledBody::Empty);
        }
        if bytes.len() <= spool_threshold {
            return Ok(SpooledBody::Inline(bytes));
        }
        let mut file = tempfile::tempfile()?; // unlinked on creation
        file.write_all(&bytes)?;
        file.flush()?;
        Ok(SpooledBody::Spooled {
            len: bytes.len() as u64,
            file: Mutex::new(file),
        })
    }

    pub fn len(&self) -> u64 {
        match self {
            SpooledBody::Empty => 0,
            SpooledBody::Inline(b) => b.len() as u64,
            SpooledBody::Spooled { len, .. } => *len,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Feed the body through `sink` in bounded chunks.
    ///
    /// Hashing a spooled request for its idempotency key must not undo the
    /// spooling: `bytes()` would pull a 150 MB upload back into memory purely
    /// to fingerprint it, which is the allocation the disk spool exists to
    /// avoid.
    pub fn for_each_chunk(&self, mut sink: impl FnMut(&[u8])) -> std::io::Result<()> {
        match self {
            SpooledBody::Empty => Ok(()),
            SpooledBody::Inline(bytes) => {
                sink(bytes);
                Ok(())
            }
            SpooledBody::Spooled { file, .. } => {
                let mut file = file.lock().unwrap();
                file.rewind()?;
                let mut buf = vec![0u8; 64 * 1024];
                loop {
                    let read = file.read(&mut buf)?;
                    if read == 0 {
                        return Ok(());
                    }
                    sink(&buf[..read]);
                }
            }
        }
    }

    /// Materialize the bytes (per upstream attempt; 307/308 replays re-read).
    pub fn bytes(&self) -> std::io::Result<Vec<u8>> {
        match self {
            SpooledBody::Empty => Ok(Vec::new()),
            SpooledBody::Inline(b) => Ok(b.clone()),
            SpooledBody::Spooled { file, .. } => {
                let mut file = file.lock().unwrap();
                file.rewind()?;
                let mut out = Vec::new();
                file.read_to_end(&mut out)?;
                Ok(out)
            }
        }
    }

    /// Size-capped, lossy-UTF-8 preview for the approval window.
    pub fn preview(&self, cap: usize) -> std::io::Result<(Option<String>, bool)> {
        if self.is_empty() {
            return Ok((None, false));
        }
        let bytes = self.bytes()?;
        let truncated = bytes.len() > cap;
        let slice = &bytes[..bytes.len().min(cap)];
        Ok((Some(String::from_utf8_lossy(slice).into_owned()), truncated))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inline_below_threshold_spooled_above() {
        let small = SpooledBody::from_bytes(vec![1, 2, 3], 10).unwrap();
        assert!(matches!(small, SpooledBody::Inline(_)));
        assert_eq!(small.bytes().unwrap(), vec![1, 2, 3]);

        let big = SpooledBody::from_bytes(vec![7u8; 100], 10).unwrap();
        assert!(matches!(big, SpooledBody::Spooled { .. }));
        assert_eq!(big.len(), 100);
        assert_eq!(big.bytes().unwrap(), vec![7u8; 100]);
        // Repeat reads work (the redirect loop re-reads for 307/308).
        assert_eq!(big.bytes().unwrap().len(), 100);
    }

    #[test]
    fn preview_caps_and_flags_truncation() {
        let body = SpooledBody::from_bytes(b"hello world".to_vec(), 1024).unwrap();
        let (preview, truncated) = body.preview(5).unwrap();
        assert_eq!(preview.as_deref(), Some("hello"));
        assert!(truncated);
        let (_, truncated) = body.preview(1024).unwrap();
        assert!(!truncated);
    }

    #[test]
    fn incremental_spool_switches_to_disk_and_enforces_cap() {
        let mut writer = BodySpool::new(4, 8);
        writer.push(b"123").unwrap();
        writer.push(b"456").unwrap();
        assert!(matches!(writer.push(b"789"), Err(SpoolError::TooLarge)));
        let body = writer.finish().unwrap();
        assert!(matches!(body, SpooledBody::Spooled { .. }));
        assert_eq!(body.bytes().unwrap(), b"123456");
    }
}
