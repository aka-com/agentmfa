//! The broker capability surface (DESIGN.md §4): the agent supplies the
//! *what* (method, path, body); the connection supplies the *where* (host,
//! database, URL) and the credential.

pub mod http;
pub mod pg;
pub mod ssh;
pub mod ws;

use std::io::{Read as _, Seek as _, Write as _};
use std::sync::Mutex;

/// A request body, held in memory below the spool threshold and in an
/// unlinked temp file above it, a parked, awaiting-approval request holds
/// its body, so concurrent uploads must not pin RAM (§4.1).
pub enum SpooledBody {
    Empty,
    Inline(Vec<u8>),
    Spooled {
        file: Mutex<std::fs::File>,
        len: u64,
    },
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

    /// Size-capped, lossy-UTF-8 preview for the approval window (§6).
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
}
