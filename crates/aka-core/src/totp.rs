//! RFC 6238 TOTP for locally stored 2FA seeds.
//!
//! A password credential may carry one TOTP factor. The seed is accepted as
//! either a bare Base32 secret (what "enter this code manually" setup pages
//! show) or a full `otpauth://totp/…` URI (what the QR code encodes), is
//! canonicalized to an `otpauth` URI, and lives in the vault as its own
//! sensitive item. Codes are computed broker-side at use time; the seed never
//! leaves the vault.

use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

use crate::error::CoreError;
use crate::types::SecretValue;
use crate::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TotpAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

impl TotpAlgorithm {
    fn as_str(self) -> &'static str {
        match self {
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha512 => "SHA512",
        }
    }
}

/// A parsed, validated TOTP configuration. The secret is scrubbed on drop.
pub struct TotpSpec {
    secret: Zeroizing<Vec<u8>>,
    algorithm: TotpAlgorithm,
    digits: u32,
    period: u64,
}

const MIN_SECRET_BYTES: usize = 8;
const MIN_PERIOD_SECS: u64 = 15;
const MAX_PERIOD_SECS: u64 = 120;

fn invalid(message: &str) -> CoreError {
    CoreError::InvalidTotpSeed(message.to_string())
}

impl TotpSpec {
    /// Parse user input: a bare Base32 seed or an `otpauth://totp/…` URI.
    pub fn parse(input: &str) -> Result<Self> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(invalid("enter the 2FA secret or otpauth:// URI"));
        }
        if trimmed.len() > 2048 {
            return Err(invalid("the 2FA secret is too long"));
        }
        let lower = trimmed.to_ascii_lowercase();
        if lower.starts_with("otpauth://") {
            return Self::parse_otpauth(trimmed);
        }
        if lower.contains("://") {
            return Err(invalid("only otpauth://totp/ URIs are supported"));
        }
        Ok(Self {
            secret: decode_base32(trimmed)?,
            algorithm: TotpAlgorithm::Sha1,
            digits: 6,
            period: 30,
        })
    }

    fn parse_otpauth(input: &str) -> Result<Self> {
        let uri =
            url::Url::parse(input).map_err(|_| invalid("that otpauth:// URI could not be read"))?;
        // HOTP is counter-based and needs persisted counter state; refuse it
        // plainly rather than generating codes that will never match.
        if !uri
            .host_str()
            .is_some_and(|host| host.eq_ignore_ascii_case("totp"))
        {
            return Err(invalid(
                "only time-based otpauth://totp/ URIs are supported",
            ));
        }
        let mut secret = None;
        let mut algorithm = TotpAlgorithm::Sha1;
        let mut digits = 6u32;
        let mut period = 30u64;
        for (key, value) in uri.query_pairs() {
            match key.to_ascii_lowercase().as_str() {
                "secret" => secret = Some(decode_base32(&value)?),
                "algorithm" => {
                    algorithm = match value.to_ascii_uppercase().as_str() {
                        "SHA1" => TotpAlgorithm::Sha1,
                        "SHA256" => TotpAlgorithm::Sha256,
                        "SHA512" => TotpAlgorithm::Sha512,
                        other => {
                            return Err(invalid(&format!("unsupported algorithm {other}")));
                        }
                    }
                }
                "digits" => {
                    digits = value
                        .parse()
                        .ok()
                        .filter(|digits| (6..=8).contains(digits))
                        .ok_or_else(|| invalid("digits must be between 6 and 8"))?;
                }
                "period" => {
                    period = value
                        .parse()
                        .ok()
                        .filter(|period| (MIN_PERIOD_SECS..=MAX_PERIOD_SECS).contains(period))
                        .ok_or_else(|| invalid("period must be between 15 and 120 seconds"))?;
                }
                _ => {}
            }
        }
        let secret = secret.ok_or_else(|| invalid("the otpauth:// URI has no secret"))?;
        Ok(Self {
            secret,
            algorithm,
            digits,
            period,
        })
    }

    /// The canonical vault representation: an `otpauth://totp/` URI carrying
    /// only what code computation needs. Label and issuer are deliberately
    /// dropped — the credential's own site/username already carry identity.
    pub fn canonical(&self) -> SecretValue {
        Zeroizing::new(format!(
            "otpauth://totp/multitool?secret={}&algorithm={}&digits={}&period={}",
            encode_base32(&self.secret),
            self.algorithm.as_str(),
            self.digits,
            self.period,
        ))
    }

    /// The code for the step containing `unix_secs`, plus whole seconds
    /// until it rolls over.
    pub fn code_at(&self, unix_secs: u64) -> (String, u64) {
        let counter = unix_secs / self.period;
        macro_rules! mac {
            ($digest:ty) => {{
                let mut mac = <Hmac<$digest>>::new_from_slice(&self.secret)
                    .expect("HMAC accepts keys of any length");
                mac.update(&counter.to_be_bytes());
                mac.finalize().into_bytes().to_vec()
            }};
        }
        let mac: Vec<u8> = match self.algorithm {
            TotpAlgorithm::Sha1 => mac!(Sha1),
            TotpAlgorithm::Sha256 => mac!(Sha256),
            TotpAlgorithm::Sha512 => mac!(Sha512),
        };
        // RFC 4226 dynamic truncation.
        let offset = (mac[mac.len() - 1] & 0x0f) as usize;
        let binary = (u32::from(mac[offset] & 0x7f) << 24)
            | (u32::from(mac[offset + 1]) << 16)
            | (u32::from(mac[offset + 2]) << 8)
            | u32::from(mac[offset + 3]);
        let code = binary % 10u32.pow(self.digits);
        let remaining = self.period - (unix_secs % self.period);
        (
            format!("{code:0width$}", width = self.digits as usize),
            remaining,
        )
    }

    /// The current code for a canonical seed fetched from the vault.
    pub fn current_code(canonical: &str) -> Result<(String, u64)> {
        let spec = Self::parse(canonical)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| invalid("system clock is before 1970"))?
            .as_secs();
        Ok(spec.code_at(now))
    }
}

/* ------------------------------- Base32 ---------------------------------- */
// RFC 4648 Base32, the alphabet every authenticator seed uses. Hand-rolled
// (~30 lines) rather than a new dependency; accepts the formatting setup
// pages use: lowercase, spaces/dashes between groups, optional `=` padding.

fn decode_base32(input: &str) -> Result<Zeroizing<Vec<u8>>> {
    let mut bits: u32 = 0;
    let mut nbits: u32 = 0;
    let mut out = Zeroizing::new(Vec::with_capacity(input.len() * 5 / 8 + 1));
    let mut padding = false;
    for ch in input.chars() {
        let value = match ch {
            ' ' | '-' => continue,
            '=' => {
                padding = true;
                continue;
            }
            'A'..='Z' => ch as u32 - 'A' as u32,
            'a'..='z' => ch as u32 - 'a' as u32,
            '2'..='7' => ch as u32 - '2' as u32 + 26,
            _ => {
                return Err(invalid(
                    "the 2FA secret has characters outside the Base32 alphabet",
                ));
            }
        };
        if padding {
            return Err(invalid("the 2FA secret has characters after its padding"));
        }
        bits = (bits << 5) | value;
        nbits += 5;
        if nbits >= 8 {
            nbits -= 8;
            out.push((bits >> nbits) as u8);
            bits &= (1 << nbits) - 1;
        }
    }
    if out.len() < MIN_SECRET_BYTES {
        return Err(invalid("the 2FA secret is too short — paste the full code"));
    }
    Ok(out)
}

fn encode_base32(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut bits: u32 = 0;
    let mut nbits: u32 = 0;
    let mut out = String::with_capacity(bytes.len() * 8 / 5 + 1);
    for &byte in bytes {
        bits = (bits << 8) | u32::from(byte);
        nbits += 8;
        while nbits >= 5 {
            nbits -= 5;
            out.push(ALPHABET[((bits >> nbits) & 0x1f) as usize] as char);
        }
    }
    if nbits > 0 {
        out.push(ALPHABET[((bits << (5 - nbits)) & 0x1f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 Appendix B test vectors use the ASCII seed "12345678901234567890"
    // (and length-scaled variants for SHA256/512), 8 digits, period 30.
    fn rfc_spec(algorithm: TotpAlgorithm, seed: &[u8]) -> TotpSpec {
        TotpSpec {
            secret: Zeroizing::new(seed.to_vec()),
            algorithm,
            digits: 8,
            period: 30,
        }
    }

    #[test]
    fn rfc6238_vectors() {
        let sha1 = rfc_spec(TotpAlgorithm::Sha1, b"12345678901234567890");
        let sha256 = rfc_spec(TotpAlgorithm::Sha256, b"12345678901234567890123456789012");
        let sha512 = rfc_spec(
            TotpAlgorithm::Sha512,
            b"1234567890123456789012345678901234567890123456789012345678901234",
        );
        assert_eq!(sha1.code_at(59).0, "94287082");
        assert_eq!(sha256.code_at(59).0, "46119246");
        assert_eq!(sha512.code_at(59).0, "90693936");
        assert_eq!(sha1.code_at(1_111_111_109).0, "07081804");
        assert_eq!(sha1.code_at(1_234_567_890).0, "89005924");
        assert_eq!(sha256.code_at(2_000_000_000).0, "90698825");
        assert_eq!(sha512.code_at(20_000_000_000).0, "47863826");
    }

    #[test]
    fn seconds_remaining_counts_down_to_the_step_boundary() {
        let spec = rfc_spec(TotpAlgorithm::Sha1, b"12345678901234567890");
        assert_eq!(spec.code_at(59).1, 1);
        assert_eq!(spec.code_at(60).1, 30);
        assert_eq!(spec.code_at(74).1, 16);
    }

    #[test]
    fn bare_base32_round_trips_through_the_canonical_uri() {
        let spec = TotpSpec::parse("gezd gnbv gy3t qojq gezd gnbv gy3t qojq").unwrap();
        assert_eq!(spec.secret.as_slice(), b"12345678901234567890");
        assert_eq!(spec.digits, 6);
        assert_eq!(spec.period, 30);
        let canonical = spec.canonical();
        let reparsed = TotpSpec::parse(&canonical).unwrap();
        assert_eq!(reparsed.secret.as_slice(), spec.secret.as_slice());
        assert_eq!(reparsed.code_at(59).0, spec.code_at(59).0);
    }

    #[test]
    fn otpauth_uris_carry_their_parameters() {
        let spec = TotpSpec::parse(
            "otpauth://totp/Example:alice@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example&algorithm=SHA256&digits=8&period=60",
        )
        .unwrap();
        assert_eq!(spec.algorithm, TotpAlgorithm::Sha256);
        assert_eq!(spec.digits, 8);
        assert_eq!(spec.period, 60);
        // Canonicalization drops the label and issuer.
        assert!(!spec.canonical().contains("alice"));
        assert!(!spec.canonical().contains("issuer"));
    }

    #[test]
    fn bad_seeds_are_refused() {
        assert!(TotpSpec::parse("").is_err());
        assert!(TotpSpec::parse("not!base32").is_err());
        assert!(TotpSpec::parse("GEZD").is_err()); // too short
        assert!(TotpSpec::parse("GE=ZDGNBVGY3TQOJQ").is_err()); // chars after padding
        assert!(TotpSpec::parse("otpauth://hotp/x?secret=GEZDGNBVGY3TQOJQ").is_err());
        assert!(TotpSpec::parse("otpauth://totp/x").is_err()); // no secret
        assert!(TotpSpec::parse("otpauth://totp/x?secret=GEZDGNBVGY3TQOJQ&digits=4").is_err());
        assert!(TotpSpec::parse("otpauth://totp/x?secret=GEZDGNBVGY3TQOJQ&period=5").is_err());
        assert!(TotpSpec::parse("https://example.com").is_err());
    }

    #[test]
    fn padded_lowercase_seeds_decode() {
        let spec = TotpSpec::parse("gezdgnbvgy3tqojq====").unwrap();
        assert_eq!(spec.secret.as_slice(), b"1234567890");
    }
}
