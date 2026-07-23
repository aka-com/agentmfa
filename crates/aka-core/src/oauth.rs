//! OAuth 2.0 for API connections: bring-your-own-app, loopback-redirect
//! PKCE (RFC 7636 + RFC 8252), tokens in the vault, refresh on expiry.
//!
//! The shape mirrors what native apps do: the user registers their own
//! OAuth app with the provider, pastes its client id (and, for providers
//! that demand one, the client secret), and the broker runs the
//! authorization-code flow against a one-shot listener on
//! `http://127.0.0.1:{port}/callback`. What lands in the vault is a single
//! token secret holding the JSON [`TokenSet`]; agents only ever see the
//! brokered upstream leg with `Authorization: Bearer …` injected.

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use url::Url;
use zeroize::Zeroizing;

use crate::store::Store;
use crate::types::{Connection, ConnectionConfig, OAuthSpec, SecretValue};

/// How long the loopback listener waits for the browser to come back.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(300);
/// Refresh when the access token is within this window of expiry.
const REFRESH_SKEW: chrono::Duration = chrono::Duration::seconds(60);

/// The vault payload of an OAuth connection's token secret. The optional
/// client secret rides along so refresh needs no second vault item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenSet {
    pub access_token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
}

impl TokenSet {
    pub fn to_secret_value(&self) -> SecretValue {
        Zeroizing::new(serde_json::to_string(self).expect("token set serializes"))
    }

    pub fn from_secret_value(value: &str) -> Result<Self, String> {
        serde_json::from_str(value).map_err(|_| "stored OAuth token set is unreadable".to_string())
    }

    fn needs_refresh(&self) -> bool {
        match self.expires_at {
            Some(at) => Utc::now() + REFRESH_SKEW >= at,
            None => false,
        }
    }
}

/// Whether a URL's host is loopback (dev/test providers run on
/// 127.0.0.1; production providers must be https).
fn is_loopback_url(url: &Url) -> bool {
    matches!(url.host_str(), Some("127.0.0.1") | Some("localhost") | Some("[::1]"))
}

fn require_https_or_loopback(url: &Url, what: &str) -> Result<(), String> {
    match url.scheme() {
        "https" => Ok(()),
        "http" if is_loopback_url(url) => Ok(()),
        _ => Err(format!("the {what} URL must be https")),
    }
}

fn base64url(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn random_token() -> Result<String, String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|e| format!("could not gather entropy: {e}"))?;
    Ok(base64url(&bytes))
}

/// Everything one authorization attempt needs: the URL to open in the
/// user's browser, and the listener that consumes the redirect.
pub struct PendingAuthorization {
    pub authorize_url: String,
    pub redirect_uri: String,
    listener: tokio::net::TcpListener,
    verifier: Zeroizing<String>,
    state: String,
}

fn authorize_url_for(
    spec: &OAuthSpec,
    redirect_uri: &str,
    state: &str,
    verifier: &str,
) -> Result<String, String> {
    let challenge = {
        use sha2::{Digest, Sha256};
        base64url(&Sha256::digest(verifier.as_bytes()))
    };
    let mut authorize = Url::parse(&spec.auth_url)
        .map_err(|_| "the authorization URL is not a valid URL".to_string())?;
    require_https_or_loopback(&authorize, "authorization")?;
    {
        let mut query = authorize.query_pairs_mut();
        query
            .append_pair("response_type", "code")
            .append_pair("client_id", &spec.client_id)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("scope", &spec.scopes.join(" "))
            .append_pair("state", state)
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256");
        // Provider-specific extras (e.g. Google's access_type=offline) so a
        // refresh token comes back; applied verbatim.
        for (key, value) in &spec.extra_auth_params {
            query.append_pair(key, value);
        }
    }
    Ok(authorize.to_string())
}

/// Build the authorization URL (PKCE S256) and bind the loopback listener.
pub async fn begin(spec: &OAuthSpec) -> Result<PendingAuthorization, String> {
    let verifier = Zeroizing::new(random_token()?);
    let state = random_token()?;
    let catcher = LoopbackCatcher::bind().await?;
    let redirect_uri = catcher.redirect_uri();
    let authorize_url = authorize_url_for(spec, &redirect_uri, &state, &verifier)?;
    Ok(PendingAuthorization {
        authorize_url,
        redirect_uri,
        listener: catcher.listener,
        verifier,
        state,
    })
}

/// One authorization attempt whose redirect lands on *another machine* (the
/// desktop shell managing this broker remotely): the caller supplies the
/// redirect URI its own loopback catcher is bound to, and later brings the
/// code back for [`exchange_code`]. Loopback redirect targets only
/// (RFC 8252) — this must never become an open relay.
pub struct ExternalAuthorization {
    pub authorize_url: String,
    pub state: String,
    pub verifier: Zeroizing<String>,
}

pub fn begin_external(
    spec: &OAuthSpec,
    redirect_uri: &str,
) -> Result<ExternalAuthorization, String> {
    let parsed = Url::parse(redirect_uri)
        .map_err(|_| "the redirect URI is not a valid URL".to_string())?;
    if parsed.scheme() != "http" || !is_loopback_url(&parsed) || parsed.path() != "/callback" {
        return Err(
            "the redirect URI must be a loopback http://127.0.0.1:<port>/callback".into(),
        );
    }
    let verifier = Zeroizing::new(random_token()?);
    let state = random_token()?;
    let authorize_url = authorize_url_for(spec, redirect_uri, &state, &verifier)?;
    Ok(ExternalAuthorization {
        authorize_url,
        state,
        verifier,
    })
}

/// Exchange an authorization code for tokens (the tail of both the local
/// flow and the remote relay).
pub async fn exchange_code(
    code: &str,
    redirect_uri: &str,
    verifier: &str,
    spec: &OAuthSpec,
    client_secret: Option<SecretValue>,
    http: &reqwest::Client,
) -> Result<TokenSet, String> {
    let mut form: Vec<(&str, &str)> = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("client_id", &spec.client_id),
        ("code_verifier", verifier),
    ];
    if let Some(secret) = client_secret.as_deref() {
        form.push(("client_secret", secret));
    }
    let response = token_request(http, &spec.token_url, &form).await?;
    parse_token_response(
        &response,
        client_secret.as_deref().map(String::as_str),
        None,
    )
}

/// A one-shot loopback listener for the browser redirect, usable on either
/// side: the broker's own flow binds one here, and a remote shell binds one
/// on the user's machine.
pub struct LoopbackCatcher {
    listener: tokio::net::TcpListener,
}

impl LoopbackCatcher {
    pub async fn bind() -> Result<Self, String> {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .map_err(|e| format!("could not open the loopback listener: {e}"))?;
        Ok(Self { listener })
    }

    pub fn redirect_uri(&self) -> String {
        let port = self
            .listener
            .local_addr()
            .map(|addr| addr.port())
            .unwrap_or(0);
        format!("http://127.0.0.1:{port}/callback")
    }

    /// Await the state-matching redirect and hand back the code.
    pub async fn wait_for_code(&self, expected_state: &str) -> Result<String, String> {
        wait_for_code_on(&self.listener, expected_state).await
    }

    /// Await any redirect and hand back `(code, state)` unverified — for
    /// relays where the party that minted the state nonce (the broker)
    /// verifies it, not this catcher.
    pub async fn wait_for_redirect(&self) -> Result<(String, String), String> {
        wait_for_redirect_on(&self.listener).await
    }
}

/// Await the browser redirect and exchange the code for tokens.
pub async fn finish(
    pending: PendingAuthorization,
    spec: &OAuthSpec,
    client_secret: Option<SecretValue>,
    http: &reqwest::Client,
) -> Result<TokenSet, String> {
    let code = tokio::time::timeout(
        CONNECT_TIMEOUT,
        wait_for_code_on(&pending.listener, &pending.state),
    )
    .await
    .map_err(|_| {
        format!(
            "no sign-in within {} minutes; try connecting again",
            CONNECT_TIMEOUT.as_secs() / 60
        )
    })??;
    exchange_code(
        &code,
        &pending.redirect_uri,
        pending.verifier.as_str(),
        spec,
        client_secret,
        http,
    )
    .await
}

/// One redirect, parsed by hand: the listener serves exactly one request and
/// closes. Anything but a state-matching `GET /callback?code=…` fails.
async fn wait_for_code_on(
    listener: &tokio::net::TcpListener,
    expected_state: &str,
) -> Result<String, String> {
    let (code, state) = wait_for_redirect_on(listener).await?;
    if state != expected_state {
        return Err("authorization state mismatch; try connecting again".into());
    }
    Ok(code)
}

/// The redirect-catching core: hands back `(code, state)`.
async fn wait_for_redirect_on(
    listener: &tokio::net::TcpListener,
) -> Result<(String, String), String> {
    loop {
        let (mut stream, peer) = listener
            .accept()
            .await
            .map_err(|e| format!("loopback accept failed: {e}"))?;
        if !peer.ip().is_loopback() {
            continue;
        }
        let mut buf = vec![0u8; 8192];
        let n = stream.read(&mut buf).await.unwrap_or(0);
        let request = String::from_utf8_lossy(&buf[..n]);
        let Some(target) = request
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
        else {
            let _ = respond(&mut stream, "400 Bad Request", "Bad request.").await;
            continue;
        };
        // Browsers probe for /favicon.ico etc.; only /callback ends the wait.
        let Ok(url) = Url::parse(&format!("http://127.0.0.1{target}")) else {
            let _ = respond(&mut stream, "400 Bad Request", "Bad request.").await;
            continue;
        };
        if url.path() != "/callback" {
            let _ = respond(&mut stream, "404 Not Found", "Not found.").await;
            continue;
        }
        let mut code = None;
        let mut state = None;
        let mut error = None;
        for (key, value) in url.query_pairs() {
            match key.as_ref() {
                "code" => code = Some(value.into_owned()),
                "state" => state = Some(value.into_owned()),
                "error" => error = Some(value.into_owned()),
                _ => {}
            }
        }
        if let Some(error) = error {
            let _ = respond(
                &mut stream,
                "200 OK",
                "Sign-in was cancelled. You can close this window.",
            )
            .await;
            return Err(format!("the provider reported: {error}"));
        }
        let (Some(code), Some(state)) = (code, state) else {
            let _ = respond(&mut stream, "400 Bad Request", "Missing code or state.").await;
            return Err("the provider sent no authorization code".into());
        };
        // This page is written before the state nonce is checked (locally in
        // wait_for_code_on, or broker-side in the relayed flow), so it must
        // not claim the connection succeeded — only hand the user back.
        let _ = respond(
            &mut stream,
            "200 OK",
            "You can close this window and return to Multitool.",
        )
        .await;
        return Ok((code, state));
    }
}

async fn respond(
    stream: &mut tokio::net::TcpStream,
    status: &str,
    body: &str,
) -> std::io::Result<()> {
    let page = format!(
        "<!doctype html><meta charset=\"utf-8\"><title>Multitool</title>\
         <body style=\"font-family:system-ui;margin:4rem auto;max-width:26rem;text-align:center\">\
         <h3>{body}</h3></body>"
    );
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{page}",
        page.len()
    );
    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await
}

async fn token_request(
    http: &reqwest::Client,
    token_url: &str,
    form: &[(&str, &str)],
) -> Result<String, String> {
    let url = Url::parse(token_url).map_err(|_| "the token URL is not a valid URL".to_string())?;
    require_https_or_loopback(&url, "token")?;
    let response = http
        .post(url)
        // GitHub answers form-encoded unless JSON is requested explicitly.
        .header("Accept", "application/json")
        .form(form)
        .timeout(Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| format!("token exchange failed: {}", e.without_url()))?;
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|e| format!("token response unreadable: {}", e.without_url()))?;
    if !status.is_success() {
        // Provider error bodies name codes like invalid_grant; do not echo
        // the whole body in case it reflects request material.
        let code = serde_json::from_str::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(String::from))
            .unwrap_or_default();
        return Err(format!(
            "the token endpoint answered HTTP {status}{}",
            if code.is_empty() {
                String::new()
            } else {
                format!(" ({code})")
            }
        ));
    }
    Ok(body)
}

/// Parse a token endpoint response (JSON or form-encoded), folding in the
/// carried client secret and the previous refresh token when the provider
/// does not rotate it.
fn parse_token_response(
    body: &str,
    client_secret: Option<&str>,
    previous_refresh: Option<&str>,
) -> Result<TokenSet, String> {
    let mut access = None;
    let mut refresh = None;
    let mut expires_in: Option<i64> = None;
    let mut error = None;
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(body) {
        access = value
            .get("access_token")
            .and_then(|v| v.as_str())
            .map(String::from);
        refresh = value
            .get("refresh_token")
            .and_then(|v| v.as_str())
            .map(String::from);
        expires_in = value.get("expires_in").and_then(|v| {
            v.as_i64()
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        });
        error = value
            .get("error")
            .and_then(|v| v.as_str())
            .map(String::from);
    } else {
        for pair in body.split('&') {
            let Some((key, value)) = pair.split_once('=') else {
                continue;
            };
            let value = percent_encoding::percent_decode_str(value)
                .decode_utf8_lossy()
                .into_owned();
            match key {
                "access_token" => access = Some(value),
                "refresh_token" => refresh = Some(value),
                "expires_in" => expires_in = value.parse().ok(),
                "error" => error = Some(value),
                _ => {}
            }
        }
    }
    if let Some(error) = error {
        return Err(format!("the provider refused: {error}"));
    }
    let access_token = access.ok_or_else(|| "the provider sent no access token".to_string())?;
    Ok(TokenSet {
        access_token,
        refresh_token: refresh.or_else(|| previous_refresh.map(String::from)),
        expires_at: expires_in.map(|s| Utc::now() + chrono::Duration::seconds(s)),
        client_secret: client_secret.map(String::from),
    })
}

/// The connection's OAuth spec and bound token secret, or why not.
fn oauth_parts(connection: &Connection) -> Result<(&OAuthSpec, uuid::Uuid), String> {
    let ConnectionConfig::Api {
        oauth: Some(spec), ..
    } = &connection.config
    else {
        return Err("not an OAuth connection".into());
    };
    let secret_id = *connection
        .secrets
        .first()
        .ok_or_else(|| "the OAuth connection has no bound token secret".to_string())?;
    Ok((spec, secret_id))
}

/// A fresh access token for the upstream leg, refreshing (and persisting)
/// when the stored one is expired or near expiry.
///
/// Refreshes are serialized per connection (shared with the MCP token
/// renewal): providers may rotate the refresh token on use, so concurrent
/// renewals would spend it twice. The token set is read through the same
/// authorization scope as any other credential on this path: agent
/// executions are pre-authorized by their wiring, UI-initiated tests keep
/// their usual confirmation behavior.
pub async fn fresh_bearer(
    store: &Arc<Store>,
    http: &reqwest::Client,
    connection: &Connection,
) -> Result<SecretValue, String> {
    let (spec, secret_id) = oauth_parts(connection)?;
    let lock = crate::mcp_refresh::connection_lock(&connection.id);
    let _guard = lock.lock().await;
    let stored = store
        .secret_value(&secret_id)
        .await
        .map_err(|e| e.to_string())?;
    let tokens = TokenSet::from_secret_value(&stored)?;
    if !tokens.needs_refresh() {
        return Ok(Zeroizing::new(tokens.access_token));
    }
    let Some(refresh_token) = tokens.refresh_token.as_deref() else {
        // Expired with nothing to refresh with: surface reconnect language,
        // the caller records NeedsReconnect health.
        return Err(
            "the OAuth access token expired and no refresh token was granted; reconnect this tool"
                .into(),
        );
    };
    let mut form: Vec<(&str, &str)> = vec![
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
        ("client_id", &spec.client_id),
    ];
    if let Some(secret) = tokens.client_secret.as_deref() {
        form.push(("client_secret", secret));
    }
    let body = token_request(http, &spec.token_url, &form).await?;
    let refreshed = parse_token_response(
        &body,
        tokens.client_secret.as_deref(),
        tokens.refresh_token.as_deref(),
    )?;
    let access = refreshed.access_token.clone();
    store
        .replace_secret_value(&secret_id, refreshed.to_secret_value())
        .map_err(|e| format!("could not persist the refreshed token: {e}"))?;
    Ok(Zeroizing::new(access))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn authorize_url_carries_pkce_and_loopback_redirect() {
        let spec = OAuthSpec {
            auth_url: "https://github.com/login/oauth/authorize".into(),
            token_url: "https://github.com/login/oauth/access_token".into(),
            client_id: "Iv1.example".into(),
            scopes: vec!["repo".into(), "read:org".into()],
            extra_auth_params: vec![],
        };
        let pending = begin(&spec).await.unwrap();
        let url = Url::parse(&pending.authorize_url).unwrap();
        let pairs: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(pairs["response_type"], "code");
        assert_eq!(pairs["client_id"], "Iv1.example");
        assert_eq!(pairs["scope"], "repo read:org");
        assert_eq!(pairs["code_challenge_method"], "S256");
        assert!(!pairs["code_challenge"].is_empty());
        assert!(pairs["redirect_uri"].starts_with("http://127.0.0.1:"));
        assert!(pairs["redirect_uri"].ends_with("/callback"));
        assert_eq!(pending.redirect_uri, pairs["redirect_uri"]);
    }

    #[tokio::test]
    async fn plain_http_authorize_url_is_refused() {
        let spec = OAuthSpec {
            auth_url: "http://github.com/login/oauth/authorize".into(),
            token_url: "https://github.com/login/oauth/access_token".into(),
            client_id: "x".into(),
            scopes: vec![],
            extra_auth_params: vec![],
        };
        assert!(begin(&spec).await.is_err());
    }

    #[test]
    fn token_responses_parse_json_and_form_encodings() {
        let json = parse_token_response(
            r#"{"access_token":"at1","refresh_token":"rt1","expires_in":3600}"#,
            Some("cs"),
            None,
        )
        .unwrap();
        assert_eq!(json.access_token, "at1");
        assert_eq!(json.refresh_token.as_deref(), Some("rt1"));
        assert!(json.expires_at.unwrap() > Utc::now());
        assert_eq!(json.client_secret.as_deref(), Some("cs"));

        let form =
            parse_token_response("access_token=at2&token_type=bearer&scope=repo", None, None)
                .unwrap();
        assert_eq!(form.access_token, "at2");
        assert!(form.refresh_token.is_none());
        assert!(form.expires_at.is_none());
    }

    #[test]
    fn refresh_keeps_the_old_refresh_token_when_not_rotated() {
        let refreshed = parse_token_response(
            r#"{"access_token":"at3","expires_in":1800}"#,
            None,
            Some("rt-old"),
        )
        .unwrap();
        assert_eq!(refreshed.refresh_token.as_deref(), Some("rt-old"));
    }

    #[test]
    fn provider_errors_surface_without_echoing_the_body() {
        let err =
            parse_token_response(r#"{"error":"bad_verification_code"}"#, None, None).unwrap_err();
        assert!(err.contains("bad_verification_code"));
    }

    #[test]
    fn token_set_round_trips_and_knows_expiry() {
        let mut set = TokenSet {
            access_token: "at".into(),
            refresh_token: Some("rt".into()),
            expires_at: Some(Utc::now() + chrono::Duration::hours(1)),
            client_secret: None,
        };
        let round = TokenSet::from_secret_value(&set.to_secret_value()).unwrap();
        assert_eq!(round.access_token, "at");
        assert!(!set.needs_refresh());
        set.expires_at = Some(Utc::now() + chrono::Duration::seconds(30));
        assert!(set.needs_refresh(), "inside the refresh skew window");
        set.expires_at = None;
        assert!(!set.needs_refresh(), "no expiry means no proactive refresh");
    }
}
