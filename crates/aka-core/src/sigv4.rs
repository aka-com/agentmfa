//! AWS Signature Version 4 request signing.
//!
//! A SigV4 `Authorization` header is an HMAC over a canonical form of the
//! entire request — method, path, query, selected headers, and a payload
//! hash — so unlike a template credential it cannot be rendered once and
//! re-applied: every hop of a redirect chain is signed individually at
//! dispatch time. This module is the pure computation; the dial loop in
//! `capability::http` decides what to sign and attaches the result.
//!
//! Hand-rolled rather than pulled from the AWS SDK because the crate universe
//! does not carry `aws-sigv4`, and the primitives (`hmac`, `sha2`,
//! `percent-encoding`) are already dependencies. Correctness is anchored to
//! the official AWS SigV4 test vectors in the tests below.

use hmac::{Hmac, Mac};
use percent_encoding::{percent_decode_str, percent_encode, AsciiSet, NON_ALPHANUMERIC};
use sha2::{Digest, Sha256};
use url::Url;

type HmacSha256 = Hmac<Sha256>;

/// Hex SHA-256 of an empty payload, for bodiless requests.
pub(crate) const EMPTY_PAYLOAD_SHA256: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// Sentinel accepted by AWS in place of a real payload hash. Used for
/// spooled request bodies, where re-reading the spool to hash it would
/// double the I/O for every large upload.
pub(crate) const UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";

/// Everything one signature needs. Header names must be lowercase and must
/// include `host`; the caller decides the set (the dial loop signs `host`,
/// `x-amz-date`, `x-amz-content-sha256`, and the session token when present).
pub(crate) struct SignParams<'a> {
    pub access_key: &'a str,
    pub secret_key: &'a str,
    pub region: &'a str,
    pub service: &'a str,
    pub method: &'a str,
    pub url: &'a Url,
    /// `(lowercase-name, value)` pairs to sign; sorted internally.
    pub headers: &'a [(String, String)],
    /// Hex SHA-256 of the payload, [`EMPTY_PAYLOAD_SHA256`], or
    /// [`UNSIGNED_PAYLOAD`].
    pub payload_hash: &'a str,
    /// `YYYYMMDD'T'HHMMSS'Z'`, also sent as `x-amz-date`.
    pub timestamp: &'a str,
}

/// AWS "unreserved" characters; everything else is percent-encoded.
const AWS_STRICT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// As above but keeping `/`, for path encoding.
const AWS_STRICT_PATH: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~')
    .remove(b'/');

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// Canonical URI: the already-percent-encoded absolute path, encoded once
/// more for every service except S3 (which signs the single-encoded form).
/// `url::Url` has already applied dot-segment removal, which is also what
/// the canonical form requires for non-S3 services.
fn canonical_uri(url: &Url, service: &str) -> String {
    let path = url.path();
    if path.is_empty() {
        return "/".to_string();
    }
    if service == "s3" {
        return path.to_string();
    }
    percent_encode(path.as_bytes(), AWS_STRICT_PATH).to_string()
}

/// Canonical query: decode each pair, re-encode with the AWS strict set,
/// sort by encoded key then encoded value. The raw query is split manually
/// rather than through `Url::query_pairs`, which applies form-encoding
/// semantics (`+` as space) the canonical form does not share.
fn canonical_query(url: &Url) -> String {
    let Some(query) = url.query() else {
        return String::new();
    };
    let recode = |part: &str| -> String {
        let decoded = percent_decode_str(part).collect::<Vec<u8>>();
        percent_encode(&decoded, AWS_STRICT).to_string()
    };
    let mut pairs: Vec<(String, String)> = query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| match pair.split_once('=') {
            Some((key, value)) => (recode(key), recode(value)),
            None => (recode(pair), String::new()),
        })
        .collect();
    pairs.sort();
    pairs
        .into_iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// Canonical header value: trimmed, with runs of interior whitespace
/// collapsed to one space.
fn canonical_header_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut last_space = false;
    for c in value.trim().chars() {
        if c.is_ascii_whitespace() {
            if !last_space {
                out.push(' ');
            }
            last_space = true;
        } else {
            out.push(c);
            last_space = false;
        }
    }
    out
}

pub(crate) struct Signed {
    /// Complete `Authorization` header value.
    pub authorization: String,
}

pub(crate) fn sign(params: &SignParams<'_>) -> Signed {
    let mut headers: Vec<(String, String)> = params
        .headers
        .iter()
        .map(|(name, value)| (name.to_ascii_lowercase(), canonical_header_value(value)))
        .collect();
    headers.sort();
    let signed_header_names = headers
        .iter()
        .map(|(name, _)| name.as_str())
        .collect::<Vec<_>>()
        .join(";");
    let canonical_headers = headers
        .iter()
        .map(|(name, value)| format!("{name}:{value}\n"))
        .collect::<String>();

    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        params.method.to_ascii_uppercase(),
        canonical_uri(params.url, params.service),
        canonical_query(params.url),
        canonical_headers,
        signed_header_names,
        params.payload_hash,
    );

    let date = &params.timestamp[..8];
    let scope = format!("{date}/{}/{}/aws4_request", params.region, params.service);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{scope}\n{}",
        params.timestamp,
        sha256_hex(canonical_request.as_bytes()),
    );

    let k_date = hmac(
        format!("AWS4{}", params.secret_key).as_bytes(),
        date.as_bytes(),
    );
    let k_region = hmac(&k_date, params.region.as_bytes());
    let k_service = hmac(&k_region, params.service.as_bytes());
    let k_signing = hmac(&k_service, b"aws4_request");
    let signature = hex(&hmac(&k_signing, string_to_sign.as_bytes()));

    Signed {
        authorization: format!(
            "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_header_names}, \
             Signature={signature}",
            params.access_key,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The official AWS SigV4 test-suite credentials and clock.
    const ACCESS_KEY: &str = "AKIDEXAMPLE";
    const SECRET_KEY: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    const REGION: &str = "us-east-1";
    const SERVICE: &str = "service";
    const TIMESTAMP: &str = "20150830T123600Z";

    fn suite_sign(method: &str, url: &str, extra_headers: &[(&str, &str)]) -> String {
        let url = Url::parse(url).unwrap();
        let mut headers = vec![
            ("host".to_string(), url.host_str().unwrap().to_string()),
            ("x-amz-date".to_string(), TIMESTAMP.to_string()),
        ];
        for (name, value) in extra_headers {
            headers.push((name.to_string(), value.to_string()));
        }
        sign(&SignParams {
            access_key: ACCESS_KEY,
            secret_key: SECRET_KEY,
            region: REGION,
            service: SERVICE,
            method,
            url: &url,
            headers: &headers,
            payload_hash: EMPTY_PAYLOAD_SHA256,
            timestamp: TIMESTAMP,
        })
        .authorization
    }

    fn signature_of(authorization: &str) -> &str {
        authorization.split("Signature=").nth(1).unwrap()
    }

    // aws-sig-v4-test-suite/get-vanilla
    #[test]
    fn get_vanilla() {
        let auth = suite_sign("GET", "https://example.amazonaws.com/", &[]);
        assert_eq!(
            auth,
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
             SignedHeaders=host;x-amz-date, \
             Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
        );
    }

    // aws-sig-v4-test-suite/get-vanilla-query-order-key-case
    #[test]
    fn get_query_order_and_case() {
        let auth = suite_sign(
            "GET",
            "https://example.amazonaws.com/?Param2=value2&Param1=value1",
            &[],
        );
        assert_eq!(
            signature_of(&auth),
            "b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500"
        );
    }

    // aws-sig-v4-test-suite/get-vanilla-empty-query-key
    #[test]
    fn get_query_unreserved() {
        let auth = suite_sign("GET", "https://example.amazonaws.com/?Param1=value1", &[]);
        assert_eq!(
            signature_of(&auth),
            "a67d582fa61cc504c4bae71f336f98b97f1ea3c7a6bfe1b6e45aec72011b9aeb"
        );
    }

    // aws-sig-v4-test-suite/post-header-value-case (lowercased name, spaces
    // collapse) — adapted: our canonicaliser lowercases and collapses.
    #[test]
    fn header_value_canonicalisation() {
        assert_eq!(canonical_header_value("  a   b\t c  "), "a b c");
    }

    // aws-sig-v4-test-suite/post-vanilla
    #[test]
    fn post_vanilla() {
        let auth = suite_sign("POST", "https://example.amazonaws.com/", &[]);
        assert_eq!(
            signature_of(&auth),
            "5da7c1a2acd57cee7505fc6676e4e544621c30862966e37dddb68e92efbe5d6b"
        );
    }

    // Path segments are double-encoded for non-S3 services; S3 signs the
    // single-encoded path.
    #[test]
    fn path_encoding_by_service() {
        let url = Url::parse("https://example.amazonaws.com/a%20b/c").unwrap();
        assert_eq!(canonical_uri(&url, "execute-api"), "/a%2520b/c");
        assert_eq!(canonical_uri(&url, "s3"), "/a%20b/c");
    }

    // Query values decode-then-recode to the strict set, so a pre-encoded
    // `%2F` and a literal `/` canonicalise identically.
    #[test]
    fn query_recode_stability() {
        let a = Url::parse("https://h/?k=a%2Fb").unwrap();
        let b = Url::parse("https://h/?k=a/b").unwrap();
        assert_eq!(canonical_query(&a), canonical_query(&b));
        assert_eq!(canonical_query(&a), "k=a%2Fb");
    }

    // A session token rides as an extra signed header without disturbing
    // the rest of the canonical form.
    #[test]
    fn session_token_header_signs() {
        let auth = suite_sign(
            "GET",
            "https://example.amazonaws.com/",
            &[("x-amz-security-token", "the-token")],
        );
        assert!(auth.contains("SignedHeaders=host;x-amz-date;x-amz-security-token"));
    }
}
