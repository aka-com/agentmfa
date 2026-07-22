//! The broker capability surface: the agent supplies the
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
