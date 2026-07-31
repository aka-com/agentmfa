//! GCP service-account token minting.
//!
//! GCP APIs authenticate with OAuth2 bearer tokens that expire hourly, so a
//! static credential template can never hold one. This module mints them at
//! dispatch time: an RS256 JWT signed with the vaulted service-account key,
//! exchanged at the key's own `token_uri` for an access token, cached until
//! near expiry. The private key is read from the vault per mint and never
//! rides a request; only the short-lived access token does, and the caller
//! registers that token for response redaction like any injected credential.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use base64::Engine as _;
use zeroize::Zeroizing;

/// Configuration problems (bad key document, unsigned-able key) are
/// conclusive about the connection; exchange problems are transient network
/// weather. The caller maps them to distinct error reasons.
pub(crate) enum GcpTokenError {
    Config(String),
    Exchange(String),
}

/// The fields of the JSON key document GCP issues for a service account.
/// Everything else in the document is ignored.
#[derive(serde::Deserialize)]
struct ServiceAccountKey {
    client_email: String,
    /// PKCS#8 (or PKCS#1) PEM. Held only for the duration of one mint.
    private_key: String,
    #[serde(default = "default_token_uri")]
    token_uri: String,
}

fn default_token_uri() -> String {
    "https://oauth2.googleapis.com/token".to_string()
}

struct CachedToken {
    token: Zeroizing<String>,
    expires: Instant,
}

/// Minted tokens per (connection, key-ref, scope). Process-local: a restart
/// simply mints afresh. A rotated key document can leave one already-minted
/// token cached for its remaining lifetime, which matches how GCP treats
/// tokens minted before a key was disabled.
fn cache() -> &'static Mutex<HashMap<String, CachedToken>> {
    static CACHE: OnceLock<Mutex<HashMap<String, CachedToken>>> = OnceLock::new();
    CACHE.get_or_init(Mutex::default)
}

/// Refresh slack: a token is re-minted this long before its stated expiry so
/// an in-flight request never rides a token that dies mid-call.
const EXPIRY_SLACK: Duration = Duration::from_secs(300);

fn base64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Parse the key document's PEM into an RSA key. GCP emits PKCS#8
/// (`BEGIN PRIVATE KEY`); PKCS#1 (`BEGIN RSA PRIVATE KEY`) is accepted for
/// keys converted by hand.
fn private_key_from_pem(pem: &str) -> Result<rsa::RsaPrivateKey, String> {
    let body: String = pem
        .lines()
        .map(str::trim)
        .filter(|line| !line.starts_with("-----") && !line.is_empty())
        .collect();
    let der = base64::engine::general_purpose::STANDARD
        .decode(body)
        .map_err(|_| "the service-account private key is not valid PEM".to_string())?;
    let der = Zeroizing::new(der);
    if pem.contains("BEGIN RSA PRIVATE KEY") {
        use rsa::pkcs1::DecodeRsaPrivateKey as _;
        rsa::RsaPrivateKey::from_pkcs1_der(&der)
            .map_err(|_| "the service-account private key could not be parsed".to_string())
    } else {
        use rsa::pkcs8::DecodePrivateKey as _;
        rsa::RsaPrivateKey::from_pkcs8_der(&der)
            .map_err(|_| "the service-account private key could not be parsed".to_string())
    }
}

/// The signed JWT-bearer assertion for one token exchange. Pure so the shape
/// and signature can be tested against a fixed clock.
fn mint_assertion(
    key: &ServiceAccountKey,
    scope: &str,
    issued_at: i64,
) -> Result<Zeroizing<String>, String> {
    use rsa::sha2::Sha256;
    use rsa::signature::{SignatureEncoding as _, Signer as _};
    let header = base64url(br#"{"alg":"RS256","typ":"JWT"}"#);
    let claims = base64url(
        serde_json::json!({
            "iss": key.client_email,
            "scope": scope,
            "aud": key.token_uri,
            "iat": issued_at,
            "exp": issued_at + 3600,
        })
        .to_string()
        .as_bytes(),
    );
    let signing_input = format!("{header}.{claims}");
    let private_key = private_key_from_pem(&key.private_key)?;
    let signing_key = rsa::pkcs1v15::SigningKey::<Sha256>::new(private_key);
    let signature = signing_key.sign(signing_input.as_bytes());
    Ok(Zeroizing::new(format!(
        "{signing_input}.{}",
        base64url(&signature.to_bytes())
    )))
}

/// A live access token for `scope`, minted through `key_json` (the vaulted
/// service-account document) unless a cached one has usable life left.
/// `cache_key` scopes the cache entry; the caller derives it from the
/// connection, key reference, and scope.
pub(crate) async fn fresh_bearer(
    client: &reqwest::Client,
    key_json: &str,
    scope: &str,
    cache_key: &str,
) -> Result<Zeroizing<String>, GcpTokenError> {
    if let Some(cached) = cache().lock().unwrap().get(cache_key) {
        if cached.expires > Instant::now() {
            return Ok(cached.token.clone());
        }
    }
    let key: ServiceAccountKey = serde_json::from_str(key_json).map_err(|_| {
        GcpTokenError::Config(
            "the referenced secret is not a GCP service-account JSON key".to_string(),
        )
    })?;
    let assertion = mint_assertion(&key, scope, chrono::Utc::now().timestamp())
        .map_err(GcpTokenError::Config)?;
    let response = client
        .post(&key.token_uri)
        .form(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("assertion", assertion.as_str()),
        ])
        .send()
        .await
        .map_err(|error| {
            GcpTokenError::Exchange(format!(
                "the GCP token endpoint could not be reached: {}",
                error.without_url()
            ))
        })?;
    let status = response.status();
    let body: serde_json::Value = response.json().await.map_err(|_| {
        GcpTokenError::Exchange("the GCP token endpoint answered unreadably".to_string())
    })?;
    if !status.is_success() {
        let detail = body
            .get("error_description")
            .or_else(|| body.get("error"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("no detail");
        return Err(GcpTokenError::Exchange(format!(
            "the GCP token exchange was refused ({status}): {detail}"
        )));
    }
    let token = body
        .get("access_token")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            GcpTokenError::Exchange("the GCP token endpoint returned no access token".to_string())
        })?;
    let token = Zeroizing::new(token.to_string());
    let lifetime = body
        .get("expires_in")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(3600);
    let expires = Instant::now() + Duration::from_secs(lifetime).saturating_sub(EXPIRY_SLACK);
    cache().lock().unwrap().insert(
        cache_key.to_string(),
        CachedToken {
            token: token.clone(),
            expires,
        },
    );
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A throwaway 2048-bit key generated once per test run (the same
    /// OsRng-via-ssh-key pattern the SSH agent tests use).
    pub(crate) fn test_key_pem() -> &'static str {
        static PEM: OnceLock<String> = OnceLock::new();
        PEM.get_or_init(|| {
            use rsa::pkcs8::EncodePrivateKey as _;
            let key = rsa::RsaPrivateKey::new(&mut ssh_key::rand_core::OsRng, 2048).unwrap();
            let der = key.to_pkcs8_der().unwrap();
            format!(
                "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
                base64::engine::general_purpose::STANDARD.encode(der.as_bytes())
            )
        })
    }

    fn test_key(token_uri: &str) -> String {
        serde_json::json!({
            "type": "service_account",
            "client_email": "agent@project.iam.gserviceaccount.com",
            "private_key": test_key_pem(),
            "token_uri": token_uri,
        })
        .to_string()
    }

    #[test]
    fn the_assertion_carries_the_grant_claims_and_verifies() {
        use rsa::sha2::Sha256;
        use rsa::signature::Verifier as _;
        let key: ServiceAccountKey = serde_json::from_str(&test_key("https://t.example")).unwrap();
        let assertion = mint_assertion(&key, "scope-a scope-b", 1_753_000_000).unwrap();
        let parts: Vec<&str> = assertion.split('.').collect();
        assert_eq!(parts.len(), 3);
        let decode = |part: &str| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(part)
                .unwrap()
        };
        let header: serde_json::Value = serde_json::from_slice(&decode(parts[0])).unwrap();
        assert_eq!(header, serde_json::json!({"alg": "RS256", "typ": "JWT"}));
        let claims: serde_json::Value = serde_json::from_slice(&decode(parts[1])).unwrap();
        assert_eq!(claims["iss"], "agent@project.iam.gserviceaccount.com");
        assert_eq!(claims["scope"], "scope-a scope-b");
        assert_eq!(claims["aud"], "https://t.example");
        assert_eq!(
            claims["exp"].as_i64().unwrap() - claims["iat"].as_i64().unwrap(),
            3600
        );
        // The signature verifies against the key's public half — what the
        // token endpoint will do with the uploaded key.
        let private = private_key_from_pem(test_key_pem()).unwrap();
        let verifying =
            rsa::pkcs1v15::VerifyingKey::<Sha256>::new(rsa::RsaPublicKey::from(&private));
        let signature = rsa::pkcs1v15::Signature::try_from(decode(parts[2]).as_slice()).unwrap();
        verifying
            .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
            .unwrap();
    }

    #[tokio::test]
    async fn tokens_are_exchanged_once_and_cached_until_expiry() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let hits = std::sync::Arc::new(AtomicUsize::new(0));
        let counted = hits.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let token_endpoint = axum::Router::new().route(
            "/token",
            axum::routing::post(move |body: String| {
                let counted = counted.clone();
                async move {
                    counted.fetch_add(1, Ordering::SeqCst);
                    // The exchange is the JWT-bearer grant with the signed
                    // assertion as form data.
                    assert!(body.contains(
                        "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer"
                    ));
                    assert!(body.contains("assertion=eyJ"));
                    axum::Json(serde_json::json!({
                        "access_token": "ya29.minted-token",
                        "expires_in": 3600,
                        "token_type": "Bearer",
                    }))
                }
            }),
        );
        tokio::spawn(async move {
            let _ = axum::serve(listener, token_endpoint).await;
        });
        let key_json = test_key(&format!("http://127.0.0.1:{port}/token"));
        let client = reqwest::Client::new();
        let first = fresh_bearer(&client, &key_json, "scope", "test-cache-key")
            .await
            .map_err(|_| "exchange failed")
            .unwrap();
        assert_eq!(&*first, "ya29.minted-token");
        let second = fresh_bearer(&client, &key_json, "scope", "test-cache-key")
            .await
            .map_err(|_| "exchange failed")
            .unwrap();
        assert_eq!(&*second, "ya29.minted-token");
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "second call served from cache"
        );

        // A non-key secret is conclusive about the connection.
        match fresh_bearer(&client, "not-json", "scope", "bad-key").await {
            Err(GcpTokenError::Config(_)) => {}
            _ => panic!("a malformed key document must be a config error"),
        }
    }
}
