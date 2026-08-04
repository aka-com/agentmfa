//! Live 1Password-backed secret resolution.
//!
//! Desktop-app and service-account authentication are implemented by the
//! official Go SDK in a long-lived helper process. 1Password Connect is kept
//! native: its private REST API is small, and resolving it directly avoids an
//! unnecessary second process on hosted brokers.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aka_api::{
    OnePasswordFieldDto, OnePasswordHealthDto, OnePasswordIntegrationDto,
    OnePasswordIntegrationKindDto, OnePasswordItemDto, OnePasswordVaultDto,
};
use chrono::{DateTime, Utc};
use futures::StreamExt as _;
use reqwest::{Client, StatusCode};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tokio::io::{AsyncBufRead, AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::CoreError;
use crate::types::{SecretSource, SecretValue};
use crate::vault::SecretVault;
use crate::Result;

const PROVIDER_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_PROVIDER_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

fn is_totp_field_type(field_type: &str) -> bool {
    matches!(
        field_type.trim().to_ascii_lowercase().as_str(),
        "totp" | "otp"
    )
}

fn is_unsupported_field_type(field_type: &str) -> bool {
    matches!(
        field_type.trim().to_ascii_lowercase().as_str(),
        "unsupported" | "unknown"
    )
}

/// Stable IDs select an exact field; labels are display-only snapshots.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OnePasswordSecretRef {
    pub integration_id: Uuid,
    pub vault_id: String,
    pub vault_label: String,
    pub item_id: String,
    pub item_label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub section_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub section_label: Option<String>,
    pub field_id: String,
    pub field_label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum OnePasswordAuth {
    DesktopApp { account: String },
    ServiceAccount,
    Connect { base_url: String },
}

impl OnePasswordAuth {
    pub fn requires_token(&self) -> bool {
        matches!(self, Self::ServiceAccount | Self::Connect { .. })
    }

    pub fn kind_dto(&self) -> OnePasswordIntegrationKindDto {
        match self {
            Self::DesktopApp { .. } => OnePasswordIntegrationKindDto::DesktopApp,
            Self::ServiceAccount => OnePasswordIntegrationKindDto::ServiceAccount,
            Self::Connect { .. } => OnePasswordIntegrationKindDto::Connect,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OnePasswordIntegration {
    pub id: Uuid,
    pub label: String,
    pub auth: OnePasswordAuth,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl OnePasswordIntegration {
    pub fn dto(&self) -> OnePasswordIntegrationDto {
        let (account, connect_url) = match &self.auth {
            OnePasswordAuth::DesktopApp { account } => (Some(account.clone()), None),
            OnePasswordAuth::ServiceAccount => (None, None),
            OnePasswordAuth::Connect { base_url } => (None, Some(base_url.clone())),
        };
        OnePasswordIntegrationDto {
            id: self.id.to_string(),
            label: self.label.clone(),
            kind: self.auth.kind_dto(),
            account,
            connect_url,
            created_at: self.created_at.to_rfc3339(),
            updated_at: self.updated_at.to_rfc3339(),
        }
    }
}

#[derive(Debug)]
struct ProviderError {
    code: &'static str,
    message: String,
}

impl ProviderError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    fn into_core(self) -> CoreError {
        CoreError::OnePassword {
            code: self.code.to_string(),
            message: self.message,
        }
    }

    /// Provider-level failures do not necessarily mean the helper process is
    /// unhealthy. Keep an authenticated SDK session alive for ordinary
    /// not-found, permission, and rate-limit responses; only discard it when
    /// the transport/session boundary itself can no longer be trusted.
    fn invalidates_sidecar(&self) -> bool {
        matches!(
            self.code,
            "provider_unavailable" | "timeout" | "invalid_response" | "desktop_session_expired"
        )
    }
}

pub fn validate_integration(label: &str, auth: &OnePasswordAuth) -> Result<()> {
    let label = label.trim();
    if label.is_empty() || label.chars().count() > 64 || label.chars().any(char::is_control) {
        return Err(CoreError::InvalidOnePasswordIntegration(
            "the integration label must be 1–64 printable characters".into(),
        ));
    }
    match auth {
        OnePasswordAuth::DesktopApp { account } => {
            let account = account.trim();
            if account.is_empty()
                || account.chars().count() > 128
                || account.chars().any(char::is_control)
            {
                return Err(CoreError::InvalidOnePasswordIntegration(
                    "a 1Password account name or account UUID is required".into(),
                ));
            }
        }
        OnePasswordAuth::ServiceAccount => {}
        OnePasswordAuth::Connect { base_url } => validate_connect_url(base_url)?,
    }
    Ok(())
}

pub(crate) fn validate_reference(reference: &OnePasswordSecretRef) -> Result<()> {
    for (name, value) in [
        ("vault", reference.vault_id.as_str()),
        ("item", reference.item_id.as_str()),
        ("field", reference.field_id.as_str()),
    ] {
        if value.is_empty()
            || value.len() > 128
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            return Err(CoreError::InvalidOnePasswordIntegration(format!(
                "invalid 1Password {name} identifier"
            )));
        }
    }
    if reference
        .section_id
        .as_ref()
        .is_some_and(|section| section.is_empty() || section.len() > 128)
    {
        return Err(CoreError::InvalidOnePasswordIntegration(
            "invalid 1Password section identifier".into(),
        ));
    }
    for (name, value) in [
        ("vault label", reference.vault_label.as_str()),
        ("item label", reference.item_label.as_str()),
        ("field label", reference.field_label.as_str()),
    ] {
        if value.is_empty() || value.chars().count() > 256 || value.chars().any(char::is_control) {
            return Err(CoreError::InvalidOnePasswordIntegration(format!(
                "invalid 1Password {name}"
            )));
        }
    }
    if reference.section_label.as_ref().is_some_and(|value| {
        value.is_empty() || value.chars().count() > 256 || value.chars().any(char::is_control)
    }) {
        return Err(CoreError::InvalidOnePasswordIntegration(
            "invalid 1Password section label".into(),
        ));
    }
    if reference.field_type.as_ref().is_some_and(|value| {
        value.is_empty()
            || value.len() > 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    }) {
        return Err(CoreError::InvalidOnePasswordIntegration(
            "invalid 1Password field type".into(),
        ));
    }
    if reference
        .field_type
        .as_deref()
        .is_some_and(is_unsupported_field_type)
    {
        return Err(CoreError::InvalidOnePasswordIntegration(
            "unsupported 1Password fields cannot be linked".into(),
        ));
    }
    Ok(())
}

fn validate_connect_url(raw: &str) -> Result<()> {
    let url = Url::parse(raw).map_err(|_| {
        CoreError::InvalidOnePasswordIntegration("the Connect URL is invalid".into())
    })?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(CoreError::InvalidOnePasswordIntegration(
            "the Connect URL must not contain credentials, a query, or a fragment".into(),
        ));
    }
    let host = url.host_str().unwrap_or_default();
    let loopback = host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback());
    if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
        return Err(CoreError::InvalidOnePasswordIntegration(
            "Connect requires HTTPS; plain HTTP is accepted only on loopback".into(),
        ));
    }
    if url.path() != "/" && !url.path().is_empty() {
        return Err(CoreError::InvalidOnePasswordIntegration(
            "the Connect URL must be an origin without a path".into(),
        ));
    }
    Ok(())
}

/// Dispatches linked fields to either the SDK sidecar or Connect REST.
pub struct OnePasswordResolver {
    vault: Arc<dyn SecretVault>,
    sdk: SdkSidecarBridge,
    connect: ConnectClient,
}

impl OnePasswordResolver {
    pub fn new(vault: Arc<dyn SecretVault>) -> Self {
        Self {
            vault,
            sdk: SdkSidecarBridge::discover(),
            connect: ConnectClient::new(),
        }
    }

    #[cfg(any(test, feature = "test-harness"))]
    pub fn with_sidecar(vault: Arc<dyn SecretVault>, path: PathBuf) -> Self {
        Self {
            vault,
            sdk: SdkSidecarBridge::new(Some(path)),
            connect: ConnectClient::new(),
        }
    }

    pub fn invalidate(&self, integration_id: &Uuid) {
        self.sdk.invalidate(integration_id);
    }

    /// Probe credentials before their integration metadata/token is
    /// committed. `token` is supplied directly so a failed credential never
    /// has to be written to the broker vault merely to test it.
    pub async fn validate_credentials(
        &self,
        integration: &OnePasswordIntegration,
        token: Option<&str>,
    ) -> Result<()> {
        let result = match &integration.auth {
            OnePasswordAuth::DesktopApp { .. } => self.sdk.list_vaults(integration, None).await,
            OnePasswordAuth::ServiceAccount => match token {
                Some(token) => self.sdk.list_vaults(integration, Some(token)).await,
                None => Err(ProviderError::new(
                    "auth_failed",
                    "the service-account token is missing",
                )),
            },
            OnePasswordAuth::Connect { base_url } => match token {
                Some(token) => self.connect.list_vaults(base_url, token).await,
                None => Err(ProviderError::new(
                    "auth_failed",
                    "the Connect access token is missing",
                )),
            },
        };
        result.map(|_| ()).map_err(ProviderError::into_core)
    }

    async fn token(&self, integration: &OnePasswordIntegration) -> Result<SecretValue> {
        self.vault.get(&integration.id).await
    }

    pub async fn resolve(
        &self,
        integration: &OnePasswordIntegration,
        reference: &OnePasswordSecretRef,
    ) -> Result<SecretValue> {
        validate_reference(reference)?;
        if integration.id != reference.integration_id {
            return Err(CoreError::InvalidOnePasswordIntegration(
                "the secret reference belongs to a different integration".into(),
            ));
        }
        match &integration.auth {
            OnePasswordAuth::DesktopApp { .. } => self
                .sdk
                .resolve(integration, None, reference)
                .await
                .map_err(ProviderError::into_core),
            OnePasswordAuth::ServiceAccount => {
                let token = self.token(integration).await?;
                self.sdk
                    .resolve(integration, Some(&token), reference)
                    .await
                    .map_err(ProviderError::into_core)
            }
            OnePasswordAuth::Connect { base_url } => {
                let token = self.token(integration).await?;
                self.connect
                    .resolve(base_url, &token, reference)
                    .await
                    .map_err(ProviderError::into_core)
            }
        }
    }

    pub async fn health(
        &self,
        integration: &OnePasswordIntegration,
    ) -> Result<OnePasswordHealthDto> {
        let vaults = self.list_vaults(integration).await?;
        Ok(OnePasswordHealthDto {
            ok: true,
            detail: format!(
                "Connected · {} vault{} available",
                vaults.len(),
                if vaults.len() == 1 { "" } else { "s" }
            ),
        })
    }

    pub async fn list_vaults(
        &self,
        integration: &OnePasswordIntegration,
    ) -> Result<Vec<OnePasswordVaultDto>> {
        match &integration.auth {
            OnePasswordAuth::DesktopApp { .. } => self
                .sdk
                .list_vaults(integration, None)
                .await
                .map_err(ProviderError::into_core),
            OnePasswordAuth::ServiceAccount => {
                let token = self.token(integration).await?;
                self.sdk
                    .list_vaults(integration, Some(&token))
                    .await
                    .map_err(ProviderError::into_core)
            }
            OnePasswordAuth::Connect { base_url } => {
                let token = self.token(integration).await?;
                self.connect
                    .list_vaults(base_url, &token)
                    .await
                    .map_err(ProviderError::into_core)
            }
        }
    }

    pub async fn list_items(
        &self,
        integration: &OnePasswordIntegration,
        vault_id: &str,
    ) -> Result<Vec<OnePasswordItemDto>> {
        validate_catalog_id("vault", vault_id)?;
        match &integration.auth {
            OnePasswordAuth::DesktopApp { .. } => self
                .sdk
                .list_items(integration, None, vault_id)
                .await
                .map_err(ProviderError::into_core),
            OnePasswordAuth::ServiceAccount => {
                let token = self.token(integration).await?;
                self.sdk
                    .list_items(integration, Some(&token), vault_id)
                    .await
                    .map_err(ProviderError::into_core)
            }
            OnePasswordAuth::Connect { base_url } => {
                let token = self.token(integration).await?;
                self.connect
                    .list_items(base_url, &token, vault_id)
                    .await
                    .map_err(ProviderError::into_core)
            }
        }
    }

    pub async fn list_fields(
        &self,
        integration: &OnePasswordIntegration,
        vault_id: &str,
        item_id: &str,
    ) -> Result<Vec<OnePasswordFieldDto>> {
        validate_catalog_id("vault", vault_id)?;
        validate_catalog_id("item", item_id)?;
        match &integration.auth {
            OnePasswordAuth::DesktopApp { .. } => self
                .sdk
                .list_fields(integration, None, vault_id, item_id)
                .await
                .map_err(ProviderError::into_core),
            OnePasswordAuth::ServiceAccount => {
                let token = self.token(integration).await?;
                self.sdk
                    .list_fields(integration, Some(&token), vault_id, item_id)
                    .await
                    .map_err(ProviderError::into_core)
            }
            OnePasswordAuth::Connect { base_url } => {
                let token = self.token(integration).await?;
                self.connect
                    .list_fields(base_url, &token, vault_id, item_id)
                    .await
                    .map_err(ProviderError::into_core)
            }
        }
    }
}

fn validate_catalog_id(kind: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(CoreError::InvalidOnePasswordIntegration(format!(
            "invalid 1Password {kind} identifier"
        )));
    }
    Ok(())
}

/* ----------------------------- SDK sidecar ----------------------------- */

struct SdkSidecarBridge {
    executable: Option<PathBuf>,
    processes: Mutex<HashMap<Uuid, Arc<SidecarProcess>>>,
}

impl SdkSidecarBridge {
    fn discover() -> Self {
        let explicit = std::env::var_os("MULTITOOL_ONEPASSWORD_SIDECAR")
            .map(PathBuf::from)
            .filter(|path| path.is_absolute());
        let adjacent = std::env::current_exe().ok().and_then(|path| {
            path.parent()
                .map(|parent| parent.join("multitool-onepassword"))
        });
        let executable = explicit
            .filter(|path| path.is_file())
            .or_else(|| adjacent.filter(|path| path.is_file()));
        Self::new(executable)
    }

    fn new(executable: Option<PathBuf>) -> Self {
        Self {
            executable,
            processes: Mutex::new(HashMap::new()),
        }
    }

    fn invalidate(&self, id: &Uuid) {
        self.processes.lock().unwrap().remove(id);
    }

    async fn process(
        &self,
        integration: &OnePasswordIntegration,
        token: Option<&str>,
    ) -> std::result::Result<Arc<SidecarProcess>, ProviderError> {
        if let Some(process) = self.processes.lock().unwrap().get(&integration.id).cloned() {
            return Ok(process);
        }
        let path = self.executable.as_ref().ok_or_else(|| {
            ProviderError::new(
                "sidecar_unavailable",
                "the 1Password SDK helper is not installed beside Multitool",
            )
        })?;
        let process = Arc::new(SidecarProcess::spawn(path, integration, token).await?);
        let mut processes = self.processes.lock().unwrap();
        Ok(processes
            .entry(integration.id)
            .or_insert_with(|| process.clone())
            .clone())
    }

    async fn call<T: DeserializeOwned>(
        &self,
        integration: &OnePasswordIntegration,
        token: Option<&str>,
        operation: &str,
        payload: serde_json::Value,
    ) -> std::result::Result<T, ProviderError> {
        let process = self.process(integration, token).await?;
        match process.call(operation, payload).await {
            Ok(value) => Ok(value),
            Err(error) => {
                if error.invalidates_sidecar() {
                    self.invalidate(&integration.id);
                }
                Err(error)
            }
        }
    }

    async fn resolve(
        &self,
        integration: &OnePasswordIntegration,
        token: Option<&str>,
        reference: &OnePasswordSecretRef,
    ) -> std::result::Result<SecretValue, ProviderError> {
        #[derive(Deserialize)]
        struct Resolved {
            #[serde(deserialize_with = "deserialize_secret_value")]
            value: SecretValue,
        }
        let result: Resolved = self
            .call(
                integration,
                token,
                "resolve",
                serde_json::json!({
                    "vault_id": reference.vault_id,
                    "item_id": reference.item_id,
                    "section_id": reference.section_id,
                    "field_id": reference.field_id,
                    "field_type": reference.field_type,
                }),
            )
            .await?;
        Ok(result.value)
    }

    async fn list_vaults(
        &self,
        integration: &OnePasswordIntegration,
        token: Option<&str>,
    ) -> std::result::Result<Vec<OnePasswordVaultDto>, ProviderError> {
        self.call(integration, token, "list_vaults", serde_json::json!({}))
            .await
    }

    async fn list_items(
        &self,
        integration: &OnePasswordIntegration,
        token: Option<&str>,
        vault_id: &str,
    ) -> std::result::Result<Vec<OnePasswordItemDto>, ProviderError> {
        self.call(
            integration,
            token,
            "list_items",
            serde_json::json!({ "vault_id": vault_id }),
        )
        .await
    }

    async fn list_fields(
        &self,
        integration: &OnePasswordIntegration,
        token: Option<&str>,
        vault_id: &str,
        item_id: &str,
    ) -> std::result::Result<Vec<OnePasswordFieldDto>, ProviderError> {
        self.call(
            integration,
            token,
            "list_fields",
            serde_json::json!({ "vault_id": vault_id, "item_id": item_id }),
        )
        .await
    }
}

struct SidecarProcess {
    sequence: AtomicU64,
    io: tokio::sync::Mutex<SidecarIo>,
}

struct SidecarIo {
    _child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

#[derive(Deserialize)]
struct SidecarResponse {
    id: u64,
    ok: bool,
    #[serde(default)]
    result: serde_json::Value,
    #[serde(default)]
    error: Option<SidecarProtocolError>,
}

#[derive(Deserialize)]
struct SidecarProtocolError {
    code: String,
    message: String,
}

impl SidecarProcess {
    async fn spawn(
        executable: &Path,
        integration: &OnePasswordIntegration,
        token: Option<&str>,
    ) -> std::result::Result<Self, ProviderError> {
        let mut command = Command::new(executable);
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .env_clear();
        for name in [
            "HOME",
            "TMPDIR",
            "XDG_RUNTIME_DIR",
            "USER",
            "LANG",
            "HTTPS_PROXY",
            "HTTP_PROXY",
            "NO_PROXY",
            "https_proxy",
            "http_proxy",
            "no_proxy",
            "SSL_CERT_FILE",
            "SSL_CERT_DIR",
        ] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        let mut child = command.spawn().map_err(|_| {
            ProviderError::new(
                "sidecar_unavailable",
                "could not start the 1Password SDK helper",
            )
        })?;
        let stdin = child.stdin.take().ok_or_else(|| {
            ProviderError::new(
                "sidecar_unavailable",
                "the 1Password SDK helper has no input pipe",
            )
        })?;
        let stdout = child.stdout.take().ok_or_else(|| {
            ProviderError::new(
                "sidecar_unavailable",
                "the 1Password SDK helper has no output pipe",
            )
        })?;
        let process = Self {
            sequence: AtomicU64::new(0),
            io: tokio::sync::Mutex::new(SidecarIo {
                _child: child,
                stdin,
                stdout: BufReader::new(stdout),
            }),
        };
        let auth = match &integration.auth {
            OnePasswordAuth::DesktopApp { account } => {
                serde_json::json!({ "method": "desktop_app", "account": account })
            }
            OnePasswordAuth::ServiceAccount => serde_json::json!({
                "method": "service_account",
                "token": token.ok_or_else(|| ProviderError::new("auth_failed", "the service-account token is missing"))?,
            }),
            OnePasswordAuth::Connect { .. } => {
                return Err(ProviderError::new(
                    "invalid_configuration",
                    "Connect does not use the SDK helper",
                ));
            }
        };
        let _: serde_json::Value = process
            .call("initialize", serde_json::json!({ "auth": auth }))
            .await?;
        Ok(process)
    }

    async fn call<T: DeserializeOwned>(
        &self,
        operation: &str,
        payload: serde_json::Value,
    ) -> std::result::Result<T, ProviderError> {
        let id = self.sequence.fetch_add(1, Ordering::Relaxed) + 1;
        let request = serde_json::json!({
            "id": id,
            "operation": operation,
            "payload": payload,
        });
        let bytes = Zeroizing::new(serde_json::to_vec(&request).map_err(|_| {
            ProviderError::new(
                "invalid_request",
                "could not encode a 1Password SDK request",
            )
        })?);
        let response = tokio::time::timeout(PROVIDER_TIMEOUT, async {
            let mut io = self.io.lock().await;
            io.stdin.write_all(&bytes).await?;
            io.stdin.write_all(b"\n").await?;
            io.stdin.flush().await?;
            let line = read_bounded_line(&mut io.stdout).await?;
            Ok::<_, std::io::Error>(line)
        })
        .await
        .map_err(|_| ProviderError::new("timeout", "the 1Password SDK request timed out"))?
        .map_err(|_| {
            ProviderError::new("provider_unavailable", "the 1Password SDK helper stopped")
        })?;
        let response: SidecarResponse = serde_json::from_slice(&response).map_err(|_| {
            ProviderError::new(
                "invalid_response",
                "the 1Password SDK helper returned invalid data",
            )
        })?;
        if response.id != id {
            return Err(ProviderError::new(
                "invalid_response",
                "the 1Password SDK helper response was out of sequence",
            ));
        }
        if !response.ok {
            let error = response.error.unwrap_or(SidecarProtocolError {
                code: "request_failed".into(),
                message: "the 1Password request failed".into(),
            });
            let code: &'static str = match error.code.as_str() {
                "auth_failed" => "auth_failed",
                "desktop_session_expired" => "desktop_session_expired",
                "not_found" => "not_found",
                "rate_limited" => "rate_limited",
                "timeout" => "timeout",
                "invalid_request" => "invalid_request",
                _ => "request_failed",
            };
            return Err(ProviderError::new(code, error.message));
        }
        serde_json::from_value(response.result).map_err(|_| {
            ProviderError::new(
                "invalid_response",
                "the 1Password SDK result had an unexpected shape",
            )
        })
    }
}

async fn read_bounded_line<R: AsyncBufRead + Unpin>(
    reader: &mut R,
) -> std::io::Result<Zeroizing<Vec<u8>>> {
    let mut output = Zeroizing::new(Vec::new());
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "sidecar output closed",
            ));
        }
        let length = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |position| position + 1);
        if output.len().saturating_add(length) > MAX_PROVIDER_RESPONSE_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "sidecar response too large",
            ));
        }
        output.extend_from_slice(&available[..length]);
        reader.consume(length);
        if output.last() == Some(&b'\n') {
            output.pop();
            return Ok(output);
        }
    }
}

/* ----------------------------- Connect REST ---------------------------- */

struct ConnectClient {
    http: Client,
}

impl ConnectClient {
    fn new() -> Self {
        let http = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(CONNECT_TIMEOUT)
            .build()
            .expect("static Connect HTTP client configuration");
        Self { http }
    }

    async fn get<T: DeserializeOwned>(
        &self,
        base_url: &str,
        token: &str,
        segments: &[&str],
    ) -> std::result::Result<T, ProviderError> {
        let mut url = Url::parse(base_url).map_err(|_| {
            ProviderError::new("invalid_configuration", "the Connect URL is invalid")
        })?;
        {
            let mut path = url.path_segments_mut().map_err(|_| {
                ProviderError::new("invalid_configuration", "the Connect URL cannot be used")
            })?;
            path.pop_if_empty();
            path.extend(segments.iter().copied());
        }
        let response = self
            .http
            .get(url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(|_| {
                ProviderError::new(
                    "provider_unavailable",
                    "1Password Connect could not be reached",
                )
            })?;
        let status = response.status();
        if !status.is_success() {
            let (code, message) = match status {
                StatusCode::UNAUTHORIZED => ("auth_failed", "Connect rejected its access token"),
                StatusCode::FORBIDDEN => {
                    ("forbidden", "Connect denied access to this vault or item")
                }
                StatusCode::NOT_FOUND => {
                    ("not_found", "the linked 1Password field no longer exists")
                }
                StatusCode::TOO_MANY_REQUESTS => {
                    ("rate_limited", "Connect asked the broker to retry later")
                }
                _ if status.is_server_error() => {
                    ("provider_unavailable", "Connect is temporarily unavailable")
                }
                _ => ("request_failed", "Connect rejected the request"),
            };
            return Err(ProviderError::new(code, message));
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_PROVIDER_RESPONSE_BYTES as u64)
        {
            return Err(ProviderError::new(
                "invalid_response",
                "Connect returned an oversized response",
            ));
        }
        // Item responses contain every field value, not only the one a link
        // eventually selects. Scrub the raw response as well as each parsed
        // value so unrelated credentials do not remain in freed heap memory.
        let mut bytes = Zeroizing::new(Vec::new());
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| {
                ProviderError::new(
                    "invalid_response",
                    "Connect returned an incomplete response",
                )
            })?;
            if bytes.len().saturating_add(chunk.len()) > MAX_PROVIDER_RESPONSE_BYTES {
                return Err(ProviderError::new(
                    "invalid_response",
                    "Connect returned an oversized response",
                ));
            }
            bytes.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&bytes)
            .map_err(|_| ProviderError::new("invalid_response", "Connect returned invalid JSON"))
    }

    async fn list_vaults(
        &self,
        base_url: &str,
        token: &str,
    ) -> std::result::Result<Vec<OnePasswordVaultDto>, ProviderError> {
        let mut vaults: Vec<ConnectVault> = self.get(base_url, token, &["v1", "vaults"]).await?;
        vaults.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(vaults
            .into_iter()
            .map(|vault| OnePasswordVaultDto {
                id: vault.id,
                title: vault.name,
                item_count: vault.items,
            })
            .collect())
    }

    async fn list_items(
        &self,
        base_url: &str,
        token: &str,
        vault_id: &str,
    ) -> std::result::Result<Vec<OnePasswordItemDto>, ProviderError> {
        let mut items: Vec<ConnectItemOverview> = self
            .get(base_url, token, &["v1", "vaults", vault_id, "items"])
            .await?;
        items.sort_by(|left, right| left.title.cmp(&right.title));
        Ok(items
            .into_iter()
            .map(|item| OnePasswordItemDto {
                id: item.id,
                title: item.title,
                category: item.category,
            })
            .collect())
    }

    async fn item(
        &self,
        base_url: &str,
        token: &str,
        vault_id: &str,
        item_id: &str,
    ) -> std::result::Result<ConnectItem, ProviderError> {
        self.get(
            base_url,
            token,
            &["v1", "vaults", vault_id, "items", item_id],
        )
        .await
    }

    async fn list_fields(
        &self,
        base_url: &str,
        token: &str,
        vault_id: &str,
        item_id: &str,
    ) -> std::result::Result<Vec<OnePasswordFieldDto>, ProviderError> {
        let item = self.item(base_url, token, vault_id, item_id).await?;
        let sections: HashMap<String, String> = item
            .sections
            .into_iter()
            .map(|section| (section.id, section.label))
            .collect();
        let mut fields: Vec<_> = item
            .fields
            .into_iter()
            .map(|field| {
                let section_id = field.section.map(|section| section.id);
                OnePasswordFieldDto {
                    id: field.id,
                    title: field.label,
                    section_title: section_id.as_ref().and_then(|id| sections.get(id).cloned()),
                    section_id,
                    field_type: field.field_type,
                }
            })
            .collect();
        fields.sort_by(|left, right| {
            left.section_title
                .cmp(&right.section_title)
                .then_with(|| left.title.cmp(&right.title))
        });
        Ok(fields)
    }

    async fn resolve(
        &self,
        base_url: &str,
        token: &str,
        reference: &OnePasswordSecretRef,
    ) -> std::result::Result<SecretValue, ProviderError> {
        let item = self
            .item(base_url, token, &reference.vault_id, &reference.item_id)
            .await?;
        let field = item
            .fields
            .into_iter()
            .find(|field| {
                field.id == reference.field_id
                    && field.section.as_ref().map(|section| section.id.as_str())
                        == reference.section_id.as_deref()
            })
            .ok_or_else(|| {
                ProviderError::new("not_found", "the linked 1Password field no longer exists")
            })?;
        field.into_resolved_value()
    }
}

#[derive(Deserialize)]
struct ConnectVault {
    id: String,
    name: String,
    #[serde(default)]
    items: u32,
}

#[derive(Deserialize)]
struct ConnectItemOverview {
    id: String,
    title: String,
    #[serde(default)]
    category: Option<String>,
}

#[derive(Deserialize)]
struct ConnectItem {
    #[serde(default)]
    fields: Vec<ConnectField>,
    #[serde(default)]
    sections: Vec<ConnectSection>,
}

#[derive(Deserialize)]
struct ConnectField {
    id: String,
    #[serde(default)]
    label: String,
    #[serde(rename = "type", default)]
    field_type: String,
    #[serde(default, deserialize_with = "deserialize_optional_secret_value")]
    value: Option<SecretValue>,
    #[serde(default, deserialize_with = "deserialize_optional_secret_value")]
    totp: Option<SecretValue>,
    #[serde(default)]
    section: Option<ConnectSectionRef>,
}

impl ConnectField {
    fn into_resolved_value(self) -> std::result::Result<SecretValue, ProviderError> {
        if is_totp_field_type(&self.field_type) {
            return self.totp.ok_or_else(|| {
                ProviderError::new(
                    "request_failed",
                    "1Password Connect could not generate the one-time password",
                )
            });
        }
        self.value.ok_or_else(|| {
            ProviderError::new("not_found", "the linked 1Password field no longer exists")
        })
    }
}

fn deserialize_secret_value<'de, D>(deserializer: D) -> std::result::Result<SecretValue, D::Error>
where
    D: serde::Deserializer<'de>,
{
    String::deserialize(deserializer).map(Zeroizing::new)
}

fn deserialize_optional_secret_value<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<SecretValue>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer).map(|value| value.map(Zeroizing::new))
}

#[derive(Deserialize)]
struct ConnectSectionRef {
    id: String,
}

#[derive(Deserialize)]
struct ConnectSection {
    id: String,
    #[serde(default)]
    label: String,
}

pub fn source_dto(
    source: &SecretSource,
    integrations: &[OnePasswordIntegration],
) -> aka_api::SecretSourceDto {
    match source {
        SecretSource::Local => aka_api::SecretSourceDto::Local,
        SecretSource::OnePassword { reference } => {
            let integration_label = integrations
                .iter()
                .find(|integration| integration.id == reference.integration_id)
                .map(|integration| integration.label.clone())
                .unwrap_or_else(|| "Missing integration".into());
            aka_api::SecretSourceDto::OnePassword {
                reference: Box::new(aka_api::OnePasswordSecretSourceDto {
                    integration_id: reference.integration_id.to_string(),
                    integration_label,
                    vault_id: reference.vault_id.clone(),
                    vault_label: reference.vault_label.clone(),
                    item_id: reference.item_id.clone(),
                    item_label: reference.item_label.clone(),
                    section_id: reference.section_id.clone(),
                    section_label: reference.section_label.clone(),
                    field_id: reference.field_id.clone(),
                    field_label: reference.field_label.clone(),
                    field_type: reference.field_type.clone(),
                }),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;
    use tokio::io::AsyncReadExt as _;

    use crate::vault::{MemoryVault, VaultAttrs};

    fn integration(id: Uuid, auth: OnePasswordAuth) -> OnePasswordIntegration {
        let now = Utc::now();
        OnePasswordIntegration {
            id,
            label: "Work".into(),
            auth,
            created_at: now,
            updated_at: now,
        }
    }

    fn reference(id: Uuid) -> OnePasswordSecretRef {
        OnePasswordSecretRef {
            integration_id: id,
            vault_id: "vault1".into(),
            vault_label: "Production".into(),
            item_id: "item1".into(),
            item_label: "GitHub".into(),
            section_id: Some("auth".into()),
            section_label: Some("Authentication".into()),
            field_id: "token".into(),
            field_label: "Token".into(),
            field_type: Some("Concealed".into()),
        }
    }

    #[test]
    fn connect_requires_a_safe_origin() {
        assert!(validate_connect_url("http://127.0.0.1:8080").is_ok());
        assert!(validate_connect_url("https://connect.example.com").is_ok());
        assert!(validate_connect_url("http://connect.example.com").is_err());
        assert!(validate_connect_url("https://user@example.com").is_err());
        assert!(validate_connect_url("https://connect.example.com/prefix").is_err());
    }

    #[test]
    fn reference_rejects_an_invalid_section_label() {
        let id = Uuid::new_v4();
        let mut invalid = reference(id);
        invalid.section_label = Some("Authentication\nsecret".into());
        assert!(validate_reference(&invalid).is_err());

        invalid.section_label = Some("Authentication".into());
        assert!(validate_reference(&invalid).is_ok());
    }

    #[test]
    fn reference_rejects_unsupported_fields_but_accepts_totp() {
        let id = Uuid::new_v4();
        let mut reference = reference(id);
        reference.field_type = Some("Unsupported".into());
        assert!(validate_reference(&reference).is_err());

        reference.field_type = Some("Totp".into());
        assert!(validate_reference(&reference).is_ok());
    }

    #[test]
    fn connect_totp_never_falls_back_to_the_seed_value() {
        let field = ConnectField {
            id: "otp".into(),
            label: "one-time password".into(),
            field_type: "OTP".into(),
            value: Some(Zeroizing::new(
                "otpauth://totp/example?secret=private".into(),
            )),
            totp: None,
            section: None,
        };
        let error = field.into_resolved_value().unwrap_err();
        assert_eq!(error.code, "request_failed");
        assert!(!error.message.contains("private"));
    }

    #[tokio::test]
    async fn connect_catalog_and_resolution_keep_values_out_of_catalog_dtos() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for _ in 0..5 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                let mut chunk = [0u8; 1024];
                loop {
                    let read = stream.read(&mut chunk).await.unwrap();
                    assert!(read > 0);
                    request.extend_from_slice(&chunk[..read]);
                    if request.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                let request = String::from_utf8(request).unwrap();
                assert!(request.contains("authorization: Bearer connect-token"));
                let first = request.lines().next().unwrap();
                let body = if first.contains("GET /v1/vaults ") {
                    r#"[{"id":"vault1","name":"Production","items":1}]"#
                } else if first.contains("GET /v1/vaults/vault1/items ") {
                    r#"[{"id":"item1","title":"GitHub","category":"API_CREDENTIAL"}]"#
                } else {
                    r#"{"fields":[{"id":"token","label":"Token","type":"CONCEALED","value":"rotated-secret","section":{"id":"auth"}},{"id":"otp","label":"one-time password","type":"OTP","value":"otpauth://totp/example?secret=seed-must-stay-private","totp":"123456","section":{"id":"auth"}}],"sections":[{"id":"auth","label":"Authentication"}]}"#
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(), body
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });

        let vault = Arc::new(MemoryVault::new());
        let id = Uuid::new_v4();
        vault
            .set(
                &id,
                &VaultAttrs {
                    name: "Connect token".into(),
                    created_at: Utc::now(),
                },
                &Zeroizing::new("connect-token".into()),
            )
            .unwrap();
        let resolver = OnePasswordResolver::new(vault);
        let integration = integration(
            id,
            OnePasswordAuth::Connect {
                base_url: format!("http://{address}"),
            },
        );
        let vaults = resolver.list_vaults(&integration).await.unwrap();
        assert_eq!(vaults[0].title, "Production");
        assert_eq!(vaults[0].item_count, 1);
        assert_eq!(
            resolver.list_items(&integration, "vault1").await.unwrap()[0].title,
            "GitHub"
        );
        let fields = resolver
            .list_fields(&integration, "vault1", "item1")
            .await
            .unwrap();
        assert_eq!(fields[0].section_title.as_deref(), Some("Authentication"));
        let serialized = serde_json::to_string(&fields).unwrap();
        assert!(!serialized.contains("rotated-secret"));
        assert!(!serialized.contains("123456"));
        assert!(!serialized.contains("seed-must-stay-private"));
        assert_eq!(
            resolver
                .resolve(&integration, &reference(id))
                .await
                .unwrap()
                .as_str(),
            "rotated-secret"
        );
        let mut otp = reference(id);
        otp.field_id = "otp".into();
        otp.field_label = "one-time password".into();
        otp.field_type = Some("OTP".into());
        assert_eq!(
            resolver.resolve(&integration, &otp).await.unwrap().as_str(),
            "123456"
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn sdk_helper_is_initialized_once_and_resolves_over_private_pipes() {
        let directory = tempfile::tempdir().unwrap();
        let helper = directory.path().join("fake-onepassword");
        std::fs::write(
            &helper,
            r#"#!/bin/sh
while IFS= read -r line; do
  id=$(/usr/bin/sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p' <<EOF
$line
EOF
)
  case "$line" in
    *'"operation":"initialize"'*) result='{"initialized":true}' ;;
    *'"operation":"list_vaults"'*) result='[{"id":"vault1","title":"Production","item_count":3}]' ;;
    *'"operation":"resolve"'*) result='{"value":"sdk-secret"}' ;;
    *) printf '{"id":%s,"ok":false,"error":{"code":"invalid_request","message":"unsupported"}}\n' "$id"; continue ;;
  esac
  printf '{"id":%s,"ok":true,"result":%s}\n' "$id" "$result"
done
"#,
        )
        .unwrap();
        let mut permissions = std::fs::metadata(&helper).unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&helper, permissions).unwrap();

        let vault = Arc::new(MemoryVault::new());
        let id = Uuid::new_v4();
        let resolver = OnePasswordResolver::with_sidecar(vault, helper);
        let integration = integration(
            id,
            OnePasswordAuth::DesktopApp {
                account: "Work".into(),
            },
        );
        let vaults = resolver.list_vaults(&integration).await.unwrap();
        assert_eq!(vaults[0].id, "vault1");
        assert_eq!(vaults[0].item_count, 3);
        assert_eq!(
            resolver
                .resolve(&integration, &reference(id))
                .await
                .unwrap()
                .as_str(),
            "sdk-secret"
        );
    }

    #[tokio::test]
    async fn sdk_provider_errors_keep_the_authenticated_process_alive() {
        let directory = tempfile::tempdir().unwrap();
        let helper = directory.path().join("recovering-onepassword");
        std::fs::write(
            &helper,
            r#"#!/bin/sh
failed=0
while IFS= read -r line; do
  id=$(/usr/bin/sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p' <<EOF
$line
EOF
)
  case "$line" in
    *'"operation":"initialize"'*) result='{"initialized":true}' ;;
    *'"operation":"list_vaults"'*)
      if [ "$failed" -eq 0 ]; then
        failed=1
        printf '{"id":%s,"ok":false,"error":{"code":"request_failed","message":"temporary provider rejection"}}\n' "$id"
        continue
      fi
      result='[{"id":"vault1","title":"Production"}]'
      ;;
    *) printf '{"id":%s,"ok":false,"error":{"code":"invalid_request","message":"unsupported"}}\n' "$id"; continue ;;
  esac
  printf '{"id":%s,"ok":true,"result":%s}\n' "$id" "$result"
done
"#,
        )
        .unwrap();
        let mut permissions = std::fs::metadata(&helper).unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&helper, permissions).unwrap();

        let id = Uuid::new_v4();
        let resolver = OnePasswordResolver::with_sidecar(Arc::new(MemoryVault::new()), helper);
        let integration = integration(
            id,
            OnePasswordAuth::DesktopApp {
                account: "Work".into(),
            },
        );
        assert!(resolver.list_vaults(&integration).await.is_err());
        assert_eq!(
            resolver.list_vaults(&integration).await.unwrap()[0].id,
            "vault1"
        );
    }
}
