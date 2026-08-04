//! Durable broker-state boundaries.
//!
//! The local product still persists through [`crate::store::Store`].  These
//! interfaces describe the broker operations rather than that store's JSON
//! layout, so a hosted implementation can perform the same operations in a
//! database transaction.  Cached reads remain synchronous: they are on every
//! agent request today, and a remote implementation is expected to maintain a
//! workspace-scoped read model rather than turn one capability call into a
//! sequence of database round trips.  Operations which may durably mutate
//! state are asynchronous.

use uuid::Uuid;

use crate::audit::{AuditEntry, AuditIntegrity, AuditPage};
use crate::endpoints::{EndpointRegistry, IssuedEndpoint};
use crate::health::HealthRegistry;
use crate::identity::{IdentityStore, ManageTokenMutationError, TokenError, VerifiedToken};
use crate::onepassword::{OnePasswordAuth, OnePasswordIntegration, OnePasswordSecretRef};
use crate::policy::AccessTable;
use crate::store::{ConnectionSpec, NewCredential, PinOutcome, Store};
use crate::template::Template;
use crate::types::{
    BrokerIdentity, ConfirmMode, Connection, ConnectionHealth, ConnectionKind, DirectEndpoint,
    HealthStatus, SecretMeta, SecretValue, Settings, ToolAccess,
};
use crate::Result;

/// The read model needed by request execution and management rendering.
///
/// Implementations may serve these methods from an in-process snapshot.  The
/// returned values are owned so a refresh can replace that snapshot without
/// tying callers to repository locks.
#[async_trait::async_trait]
pub trait CatalogReader: Send + Sync {
    fn retired_connections_dropped(&self) -> Vec<String>;
    fn list_secrets(&self) -> Vec<SecretMeta>;
    fn secret_by_id(&self, id: &Uuid) -> Result<SecretMeta>;
    fn secret_by_name(&self, name: &str) -> Option<SecretMeta>;
    async fn secret_totp_code(&self, id: &Uuid) -> Result<(String, u64)>;
    async fn secret_value(&self, id: &Uuid) -> Result<SecretValue>;
    async fn secret_value_by_name(&self, name: &str) -> Result<SecretValue>;

    fn list_onepassword_integrations(&self) -> Vec<OnePasswordIntegration>;
    fn onepassword_integration(&self, id: &Uuid) -> Result<OnePasswordIntegration>;
    fn invalidate_onepassword_integration(&self, id: &Uuid);
    async fn validate_new_onepassword_integration(
        &self,
        id: Uuid,
        label: &str,
        auth: &OnePasswordAuth,
        token: Option<&str>,
    ) -> Result<()>;
    async fn validate_onepassword_replacement_token(&self, id: &Uuid, token: &str) -> Result<()>;
    async fn onepassword_health(&self, id: &Uuid) -> Result<aka_api::OnePasswordHealthDto>;
    async fn onepassword_vaults(&self, id: &Uuid) -> Result<Vec<aka_api::OnePasswordVaultDto>>;
    async fn onepassword_items(
        &self,
        id: &Uuid,
        vault_id: &str,
    ) -> Result<Vec<aka_api::OnePasswordItemDto>>;
    async fn onepassword_fields(
        &self,
        id: &Uuid,
        vault_id: &str,
        item_id: &str,
    ) -> Result<Vec<aka_api::OnePasswordFieldDto>>;
    async fn render_template(&self, template: &Template) -> Result<SecretValue>;

    fn connections_using(&self, id: &Uuid) -> Vec<String>;
    fn list_connections(&self) -> Vec<Connection>;
    fn connection_by_id(&self, id: &Uuid) -> Result<Connection>;
    fn connection_by_name(&self, name: &str) -> Option<Connection>;
    fn preflight_add_connection(&self, spec: &ConnectionSpec) -> Result<()>;
    fn preflight_add_connection_with_secret(
        &self,
        secret_name: &str,
        spec: &ConnectionSpec,
    ) -> Result<()>;
    async fn connection_oauth_grant(&self, id: &Uuid) -> Result<SecretValue>;
    fn settings(&self) -> Settings;
}

/// Atomic durable catalog operations.
///
/// Methods intentionally correspond to domain operations rather than table
/// writes.  In particular, secret rename owns template rewrites and combined
/// secret/connection creation stays one call.
#[async_trait::async_trait]
pub trait CatalogRepository: CatalogReader {
    async fn add_secret(&self, name: &str, value: SecretValue) -> Result<SecretMeta>;
    async fn add_credential(&self, spec: NewCredential) -> Result<SecretMeta>;
    async fn set_password_profile(
        &self,
        id: &Uuid,
        site: Option<String>,
        username: Option<Option<String>>,
    ) -> Result<SecretMeta>;
    async fn set_totp_factor(&self, id: &Uuid, seed: Option<SecretValue>) -> Result<SecretMeta>;
    async fn rename_secret(&self, id: &Uuid, new_name: &str) -> Result<(SecretMeta, usize)>;
    async fn replace_secret_value(&self, id: &Uuid, value: SecretValue) -> Result<SecretMeta>;
    async fn delete_secret(&self, id: &Uuid) -> Result<SecretMeta>;

    async fn add_onepassword_integration_with_id(
        &self,
        id: Uuid,
        label: &str,
        auth: OnePasswordAuth,
        token: Option<SecretValue>,
    ) -> Result<OnePasswordIntegration>;
    async fn replace_onepassword_token(
        &self,
        id: &Uuid,
        token: SecretValue,
    ) -> Result<OnePasswordIntegration>;
    async fn delete_onepassword_integration(&self, id: &Uuid) -> Result<OnePasswordIntegration>;
    async fn add_onepassword_secret(
        &self,
        name: &str,
        reference: OnePasswordSecretRef,
    ) -> Result<SecretMeta>;

    async fn add_connection(&self, spec: ConnectionSpec) -> Result<Connection>;
    async fn add_connection_with_secret(
        &self,
        secret_name: &str,
        value: SecretValue,
        spec: ConnectionSpec,
    ) -> Result<(SecretMeta, Connection)>;
    async fn update_connection(
        &self,
        id: &Uuid,
        spec: ConnectionSpec,
    ) -> Result<(Connection, bool)>;
    async fn update_connection_if_current(
        &self,
        id: &Uuid,
        expected_updated_at: &str,
        spec: ConnectionSpec,
    ) -> Result<(Connection, bool)>;
    async fn rename_connection_if_current(
        &self,
        id: &Uuid,
        expected_updated_at: &str,
        name: String,
    ) -> Result<Connection>;
    async fn rename_connection(&self, id: &Uuid, name: String) -> Result<Connection>;
    async fn set_connection_account(
        &self,
        id: &Uuid,
        account: Option<String>,
    ) -> Result<Connection>;
    async fn set_connection_oauth(
        &self,
        id: &Uuid,
        payload: SecretValue,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<Connection>;
    async fn pin_ssh_host_key(
        &self,
        id: &Uuid,
        observed: &ssh_key::Fingerprint,
    ) -> Result<PinOutcome>;
    async fn delete_connection(&self, id: &Uuid) -> Result<Connection>;
    async fn reorder_connections(&self, ordered_ids: &[Uuid]) -> Result<Vec<Connection>>;
    async fn set_menu_bar_hides_dock(&self, on: bool) -> Result<()>;
    async fn set_confirm_ssh_host_keys(&self, on: bool) -> Result<()>;
}

#[async_trait::async_trait]
impl CatalogReader for Store {
    fn retired_connections_dropped(&self) -> Vec<String> {
        Store::retired_connections_dropped(self).to_vec()
    }

    fn list_secrets(&self) -> Vec<SecretMeta> {
        Store::list_secrets(self)
    }

    fn secret_by_id(&self, id: &Uuid) -> Result<SecretMeta> {
        Store::secret_by_id(self, id)
    }

    fn secret_by_name(&self, name: &str) -> Option<SecretMeta> {
        Store::secret_by_name(self, name)
    }

    async fn secret_totp_code(&self, id: &Uuid) -> Result<(String, u64)> {
        Store::secret_totp_code(self, id).await
    }

    async fn secret_value(&self, id: &Uuid) -> Result<SecretValue> {
        Store::secret_value(self, id).await
    }

    async fn secret_value_by_name(&self, name: &str) -> Result<SecretValue> {
        Store::secret_value_by_name(self, name).await
    }

    fn list_onepassword_integrations(&self) -> Vec<OnePasswordIntegration> {
        Store::list_onepassword_integrations(self)
    }

    fn onepassword_integration(&self, id: &Uuid) -> Result<OnePasswordIntegration> {
        Store::onepassword_integration(self, id)
    }

    fn invalidate_onepassword_integration(&self, id: &Uuid) {
        Store::invalidate_onepassword_integration(self, id)
    }

    async fn validate_new_onepassword_integration(
        &self,
        id: Uuid,
        label: &str,
        auth: &OnePasswordAuth,
        token: Option<&str>,
    ) -> Result<()> {
        Store::validate_new_onepassword_integration(self, id, label, auth, token).await
    }

    async fn validate_onepassword_replacement_token(&self, id: &Uuid, token: &str) -> Result<()> {
        Store::validate_onepassword_replacement_token(self, id, token).await
    }

    async fn onepassword_health(&self, id: &Uuid) -> Result<aka_api::OnePasswordHealthDto> {
        Store::onepassword_health(self, id).await
    }

    async fn onepassword_vaults(&self, id: &Uuid) -> Result<Vec<aka_api::OnePasswordVaultDto>> {
        Store::onepassword_vaults(self, id).await
    }

    async fn onepassword_items(
        &self,
        id: &Uuid,
        vault_id: &str,
    ) -> Result<Vec<aka_api::OnePasswordItemDto>> {
        Store::onepassword_items(self, id, vault_id).await
    }

    async fn onepassword_fields(
        &self,
        id: &Uuid,
        vault_id: &str,
        item_id: &str,
    ) -> Result<Vec<aka_api::OnePasswordFieldDto>> {
        Store::onepassword_fields(self, id, vault_id, item_id).await
    }

    async fn render_template(&self, template: &Template) -> Result<SecretValue> {
        Store::render_template(self, template).await
    }

    fn connections_using(&self, id: &Uuid) -> Vec<String> {
        Store::connections_using(self, id)
    }

    fn list_connections(&self) -> Vec<Connection> {
        Store::list_connections(self)
    }

    fn connection_by_id(&self, id: &Uuid) -> Result<Connection> {
        Store::connection_by_id(self, id)
    }

    fn connection_by_name(&self, name: &str) -> Option<Connection> {
        Store::connection_by_name(self, name)
    }

    fn preflight_add_connection(&self, spec: &ConnectionSpec) -> Result<()> {
        Store::preflight_add_connection(self, spec)
    }

    fn preflight_add_connection_with_secret(
        &self,
        secret_name: &str,
        spec: &ConnectionSpec,
    ) -> Result<()> {
        Store::preflight_add_connection_with_secret(self, secret_name, spec)
    }

    async fn connection_oauth_grant(&self, id: &Uuid) -> Result<SecretValue> {
        Store::connection_oauth_grant(self, id).await
    }

    fn settings(&self) -> Settings {
        Store::settings(self)
    }
}

#[async_trait::async_trait]
impl CatalogRepository for Store {
    async fn add_secret(&self, name: &str, value: SecretValue) -> Result<SecretMeta> {
        Store::add_secret(self, name, value)
    }

    async fn add_credential(&self, spec: NewCredential) -> Result<SecretMeta> {
        Store::add_credential(self, spec)
    }

    async fn set_password_profile(
        &self,
        id: &Uuid,
        site: Option<String>,
        username: Option<Option<String>>,
    ) -> Result<SecretMeta> {
        Store::set_password_profile(self, id, site, username)
    }

    async fn set_totp_factor(&self, id: &Uuid, seed: Option<SecretValue>) -> Result<SecretMeta> {
        Store::set_totp_factor(self, id, seed)
    }

    async fn rename_secret(&self, id: &Uuid, new_name: &str) -> Result<(SecretMeta, usize)> {
        Store::rename_secret(self, id, new_name)
    }

    async fn replace_secret_value(&self, id: &Uuid, value: SecretValue) -> Result<SecretMeta> {
        Store::replace_secret_value(self, id, value)
    }

    async fn delete_secret(&self, id: &Uuid) -> Result<SecretMeta> {
        Store::delete_secret(self, id)
    }

    async fn add_onepassword_integration_with_id(
        &self,
        id: Uuid,
        label: &str,
        auth: OnePasswordAuth,
        token: Option<SecretValue>,
    ) -> Result<OnePasswordIntegration> {
        Store::add_onepassword_integration_with_id(self, id, label, auth, token)
    }

    async fn replace_onepassword_token(
        &self,
        id: &Uuid,
        token: SecretValue,
    ) -> Result<OnePasswordIntegration> {
        Store::replace_onepassword_token(self, id, token)
    }

    async fn delete_onepassword_integration(&self, id: &Uuid) -> Result<OnePasswordIntegration> {
        Store::delete_onepassword_integration(self, id)
    }

    async fn add_onepassword_secret(
        &self,
        name: &str,
        reference: OnePasswordSecretRef,
    ) -> Result<SecretMeta> {
        Store::add_onepassword_secret(self, name, reference)
    }

    async fn add_connection(&self, spec: ConnectionSpec) -> Result<Connection> {
        Store::add_connection(self, spec)
    }

    async fn add_connection_with_secret(
        &self,
        secret_name: &str,
        value: SecretValue,
        spec: ConnectionSpec,
    ) -> Result<(SecretMeta, Connection)> {
        Store::add_connection_with_secret(self, secret_name, value, spec)
    }

    async fn update_connection(
        &self,
        id: &Uuid,
        spec: ConnectionSpec,
    ) -> Result<(Connection, bool)> {
        Store::update_connection(self, id, spec)
    }

    async fn update_connection_if_current(
        &self,
        id: &Uuid,
        expected_updated_at: &str,
        spec: ConnectionSpec,
    ) -> Result<(Connection, bool)> {
        Store::update_connection_if_current(self, id, expected_updated_at, spec)
    }

    async fn rename_connection_if_current(
        &self,
        id: &Uuid,
        expected_updated_at: &str,
        name: String,
    ) -> Result<Connection> {
        Store::rename_connection_if_current(self, id, expected_updated_at, name)
    }

    async fn rename_connection(&self, id: &Uuid, name: String) -> Result<Connection> {
        Store::rename_connection(self, id, name)
    }

    async fn set_connection_account(
        &self,
        id: &Uuid,
        account: Option<String>,
    ) -> Result<Connection> {
        Store::set_connection_account(self, id, account)
    }

    async fn set_connection_oauth(
        &self,
        id: &Uuid,
        payload: SecretValue,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<Connection> {
        Store::set_connection_oauth(self, id, payload, expires_at)
    }

    async fn pin_ssh_host_key(
        &self,
        id: &Uuid,
        observed: &ssh_key::Fingerprint,
    ) -> Result<PinOutcome> {
        Store::pin_ssh_host_key(self, id, observed)
    }

    async fn delete_connection(&self, id: &Uuid) -> Result<Connection> {
        Store::delete_connection(self, id)
    }

    async fn reorder_connections(&self, ordered_ids: &[Uuid]) -> Result<Vec<Connection>> {
        Store::reorder_connections(self, ordered_ids)
    }

    async fn set_menu_bar_hides_dock(&self, on: bool) -> Result<()> {
        Store::set_menu_bar_hides_dock(self, on)
    }

    async fn set_confirm_ssh_host_keys(&self, on: bool) -> Result<()> {
        Store::set_confirm_ssh_host_keys(self, on)
    }
}

/// Per-connection policy, scoped to the repository's logical broker.
#[async_trait::async_trait]
pub trait PolicyRepository: Send + Sync {
    fn allows(&self, connection_id: &Uuid) -> bool;
    fn allowed_tools(&self, connection_id: &Uuid) -> Option<Vec<String>>;
    fn confirm_mode(&self, connection_id: &Uuid) -> ConfirmMode;
    fn expose_response_credentials(&self, connection_id: &Uuid) -> bool;
    fn audit_statements(&self, connection_id: &Uuid, default: bool) -> bool;
    fn entry(&self, connection_id: &Uuid) -> Option<ToolAccess>;
    fn entries(&self) -> Vec<ToolAccess>;

    async fn set_enabled(&self, connection_id: Uuid, enabled: bool) -> Result<bool>;
    async fn set_allowed_tools(
        &self,
        connection_id: Uuid,
        tools: Option<Vec<String>>,
    ) -> Result<bool>;
    async fn set_confirm_mode(&self, connection_id: Uuid, confirm: ConfirmMode) -> Result<bool>;
    async fn set_expose_response_credentials(
        &self,
        connection_id: Uuid,
        expose: bool,
    ) -> Result<bool>;
    async fn set_audit_statements(
        &self,
        connection_id: Uuid,
        audit_statements: Option<bool>,
    ) -> Result<bool>;
    async fn remove_for_connection(&self, connection_id: &Uuid) -> Result<bool>;
}

#[async_trait::async_trait]
impl PolicyRepository for AccessTable {
    fn allows(&self, connection_id: &Uuid) -> bool {
        AccessTable::allows(self, connection_id)
    }

    fn allowed_tools(&self, connection_id: &Uuid) -> Option<Vec<String>> {
        AccessTable::allowed_tools(self, connection_id)
    }

    fn confirm_mode(&self, connection_id: &Uuid) -> ConfirmMode {
        AccessTable::confirm_mode(self, connection_id)
    }

    fn expose_response_credentials(&self, connection_id: &Uuid) -> bool {
        AccessTable::expose_response_credentials(self, connection_id)
    }

    fn audit_statements(&self, connection_id: &Uuid, default: bool) -> bool {
        AccessTable::audit_statements(self, connection_id, default)
    }

    fn entry(&self, connection_id: &Uuid) -> Option<ToolAccess> {
        AccessTable::entry(self, connection_id)
    }

    fn entries(&self) -> Vec<ToolAccess> {
        AccessTable::entries(self)
    }

    async fn set_enabled(&self, connection_id: Uuid, enabled: bool) -> Result<bool> {
        AccessTable::set_enabled(self, connection_id, enabled)
    }

    async fn set_allowed_tools(
        &self,
        connection_id: Uuid,
        tools: Option<Vec<String>>,
    ) -> Result<bool> {
        AccessTable::set_allowed_tools(self, connection_id, tools)
    }

    async fn set_confirm_mode(&self, connection_id: Uuid, confirm: ConfirmMode) -> Result<bool> {
        AccessTable::set_confirm_mode(self, connection_id, confirm)
    }

    async fn set_expose_response_credentials(
        &self,
        connection_id: Uuid,
        expose: bool,
    ) -> Result<bool> {
        AccessTable::set_expose_response_credentials(self, connection_id, expose)
    }

    async fn set_audit_statements(
        &self,
        connection_id: Uuid,
        audit_statements: Option<bool>,
    ) -> Result<bool> {
        AccessTable::set_audit_statements(self, connection_id, audit_statements)
    }

    async fn remove_for_connection(&self, connection_id: &Uuid) -> Result<bool> {
        AccessTable::remove_for_connection(self, connection_id)
    }
}

/// Authentication material for one logical broker.
#[async_trait::async_trait]
pub trait IdentityRepository: Send + Sync {
    fn client_id(&self) -> Uuid;
    fn token(&self) -> String;
    fn info(&self) -> BrokerIdentity;
    fn active_alias_count(&self) -> usize;
    fn verify(&self, token: &str) -> std::result::Result<VerifiedToken, TokenError>;
    fn verify_manage(&self, token: &str) -> std::result::Result<(), TokenError>;
    fn manage_token_issued(&self) -> bool;
    fn manage_token_expires_at(&self) -> Option<chrono::DateTime<chrono::Utc>>;

    async fn touch(&self);
    async fn issue_manage_token(&self) -> Result<String> {
        self.issue_manage_token_with_ttl(None).await
    }
    async fn issue_manage_token_with_ttl(&self, ttl: Option<std::time::Duration>)
        -> Result<String>;
    async fn rotate_manage_token_with_ttl(
        &self,
        current: &str,
        ttl: Option<std::time::Duration>,
    ) -> std::result::Result<String, ManageTokenMutationError>;
    async fn revoke_manage_token(&self) -> Result<bool>;
    async fn revoke_manage_token_with_token(
        &self,
        current: &str,
    ) -> std::result::Result<(), ManageTokenMutationError>;
    async fn rotate(&self) -> Result<String>;
}

#[async_trait::async_trait]
impl IdentityRepository for IdentityStore {
    fn client_id(&self) -> Uuid {
        IdentityStore::client_id(self)
    }

    fn token(&self) -> String {
        IdentityStore::token(self)
    }

    fn info(&self) -> BrokerIdentity {
        IdentityStore::info(self)
    }

    fn active_alias_count(&self) -> usize {
        IdentityStore::active_alias_count(self)
    }

    fn verify(&self, token: &str) -> std::result::Result<VerifiedToken, TokenError> {
        IdentityStore::verify(self, token)
    }

    fn verify_manage(&self, token: &str) -> std::result::Result<(), TokenError> {
        IdentityStore::verify_manage(self, token)
    }

    fn manage_token_issued(&self) -> bool {
        IdentityStore::manage_token_issued(self)
    }

    fn manage_token_expires_at(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        IdentityStore::manage_token_expires_at(self)
    }

    async fn touch(&self) {
        IdentityStore::touch(self)
    }

    async fn issue_manage_token_with_ttl(
        &self,
        ttl: Option<std::time::Duration>,
    ) -> Result<String> {
        IdentityStore::issue_manage_token_with_ttl(self, ttl)
    }

    async fn rotate_manage_token_with_ttl(
        &self,
        current: &str,
        ttl: Option<std::time::Duration>,
    ) -> std::result::Result<String, ManageTokenMutationError> {
        IdentityStore::rotate_manage_token_with_ttl(self, current, ttl)
    }

    async fn revoke_manage_token(&self) -> Result<bool> {
        IdentityStore::revoke_manage_token(self)
    }

    async fn revoke_manage_token_with_token(
        &self,
        current: &str,
    ) -> std::result::Result<(), ManageTokenMutationError> {
        IdentityStore::revoke_manage_token_with_token(self, current)
    }

    async fn rotate(&self) -> Result<String> {
        IdentityStore::rotate(self)
    }
}

/// Standing direct-endpoint registry.
#[async_trait::async_trait]
pub trait EndpointRepository: Send + Sync {
    fn list(&self) -> Vec<DirectEndpoint>;
    fn get(&self, id: &Uuid) -> Option<DirectEndpoint>;
    fn get_for_connection(&self, connection_id: &Uuid) -> Option<DirectEndpoint>;
    fn resolve_secret(&self, presented: &str) -> Option<DirectEndpoint>;

    async fn issue(&self, connection_id: Uuid, kind: ConnectionKind) -> Result<IssuedEndpoint>;
    async fn renew(&self, id: &Uuid) -> Result<DirectEndpoint>;
    async fn set_expiry(&self, id: &Uuid, expire: bool) -> Result<DirectEndpoint>;
    async fn set_require_auth(&self, id: &Uuid, require_auth: bool) -> Result<bool>;
    async fn set_port(&self, id: &Uuid, port: u16) -> Result<()>;
    async fn revoke(&self, id: &Uuid) -> Result<Option<DirectEndpoint>>;
    async fn revoke_all(&self) -> Result<Vec<DirectEndpoint>>;
    async fn remove_for_connection(&self, connection_id: &Uuid) -> Result<Vec<DirectEndpoint>>;
}

#[async_trait::async_trait]
impl EndpointRepository for EndpointRegistry {
    fn list(&self) -> Vec<DirectEndpoint> {
        EndpointRegistry::list(self)
    }

    fn get(&self, id: &Uuid) -> Option<DirectEndpoint> {
        EndpointRegistry::get(self, id)
    }

    fn get_for_connection(&self, connection_id: &Uuid) -> Option<DirectEndpoint> {
        EndpointRegistry::get_for_connection(self, connection_id)
    }

    fn resolve_secret(&self, presented: &str) -> Option<DirectEndpoint> {
        EndpointRegistry::resolve_secret(self, presented)
    }

    async fn issue(&self, connection_id: Uuid, kind: ConnectionKind) -> Result<IssuedEndpoint> {
        EndpointRegistry::issue(self, connection_id, kind)
    }

    async fn renew(&self, id: &Uuid) -> Result<DirectEndpoint> {
        EndpointRegistry::renew(self, id)
    }

    async fn set_expiry(&self, id: &Uuid, expire: bool) -> Result<DirectEndpoint> {
        EndpointRegistry::set_expiry(self, id, expire)
    }

    async fn set_require_auth(&self, id: &Uuid, require_auth: bool) -> Result<bool> {
        EndpointRegistry::set_require_auth(self, id, require_auth)
    }

    async fn set_port(&self, id: &Uuid, port: u16) -> Result<()> {
        EndpointRegistry::set_port(self, id, port)
    }

    async fn revoke(&self, id: &Uuid) -> Result<Option<DirectEndpoint>> {
        EndpointRegistry::revoke(self, id)
    }

    async fn revoke_all(&self) -> Result<Vec<DirectEndpoint>> {
        EndpointRegistry::revoke_all(self)
    }

    async fn remove_for_connection(&self, connection_id: &Uuid) -> Result<Vec<DirectEndpoint>> {
        EndpointRegistry::remove_for_connection(self, connection_id)
    }
}

/// Durable activity storage. Appends stay non-failing to preserve the current
/// operational-log contract; implementations that perform network I/O should
/// enqueue them and make delivery health observable separately.
#[async_trait::async_trait]
pub trait AuditRepository: Send + Sync {
    fn append(&self, entry: AuditEntry);
    async fn clear(&self) -> Result<()>;
    async fn verify(&self) -> AuditIntegrity;
    async fn recent(&self, limit: usize) -> Vec<AuditEntry>;
    async fn recent_page(&self, limit: usize, before: Option<u64>) -> AuditPage;
}

#[async_trait::async_trait]
impl AuditRepository for crate::audit::AuditLog {
    fn append(&self, entry: AuditEntry) {
        crate::audit::AuditLog::append(self, entry)
    }

    async fn clear(&self) -> Result<()> {
        crate::audit::AuditLog::clear(self)
    }

    async fn verify(&self) -> AuditIntegrity {
        crate::audit::AuditLog::verify(self)
    }

    async fn recent(&self, limit: usize) -> Vec<AuditEntry> {
        crate::audit::AuditLog::recent(self, limit)
    }

    async fn recent_page(&self, limit: usize, before: Option<u64>) -> AuditPage {
        crate::audit::AuditLog::recent_page(self, limit, before)
    }
}

/// Last-observed upstream health. Writes are best-effort telemetry, not part
/// of the configuration transaction.
pub trait HealthRepository: Send + Sync {
    fn was_discarded(&self) -> bool;
    fn get(&self, id: &Uuid) -> Option<ConnectionHealth>;
    fn record(&self, id: &Uuid, status: HealthStatus, detail: String);
    fn record_ok_if_changed(&self, id: &Uuid, detail: String);
    fn record_credential_rejection(&self, id: &Uuid, detail: String) -> bool;
    fn record_if_changed(&self, id: &Uuid, status: HealthStatus, detail: String);
    fn clear_rejection_streak(&self, id: &Uuid);
    fn forget(&self, id: &Uuid);
}

impl HealthRepository for HealthRegistry {
    fn was_discarded(&self) -> bool {
        HealthRegistry::was_discarded(self)
    }

    fn get(&self, id: &Uuid) -> Option<ConnectionHealth> {
        HealthRegistry::get(self, id)
    }

    fn record(&self, id: &Uuid, status: HealthStatus, detail: String) {
        HealthRegistry::record(self, id, status, detail)
    }

    fn record_ok_if_changed(&self, id: &Uuid, detail: String) {
        HealthRegistry::record_ok_if_changed(self, id, detail)
    }

    fn record_credential_rejection(&self, id: &Uuid, detail: String) -> bool {
        HealthRegistry::record_credential_rejection(self, id, detail)
    }

    fn record_if_changed(&self, id: &Uuid, status: HealthStatus, detail: String) {
        HealthRegistry::record_if_changed(self, id, status, detail)
    }

    fn clear_rejection_streak(&self, id: &Uuid) {
        HealthRegistry::clear_rejection_streak(self, id)
    }

    fn forget(&self, id: &Uuid) {
        HealthRegistry::forget(self, id)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use zeroize::Zeroizing;

    use super::*;
    use crate::integrity::StateIntegrity;
    use crate::paths::Paths;
    use crate::types::{ConnectionConfig, PgSslMode};
    use crate::vault::MemoryVault;

    #[tokio::test]
    async fn local_catalog_satisfies_the_async_repository_contract() {
        let dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn CatalogRepository> = Arc::new(
            Store::open(Paths::under(dir.path()), Arc::new(MemoryVault::new()))
                .await
                .unwrap(),
        );

        let secret = store
            .add_secret("DATABASE_PASSWORD", Zeroizing::new("first".into()))
            .await
            .unwrap();
        assert_eq!(
            store.secret_by_name("DATABASE_PASSWORD").unwrap().id,
            secret.id
        );
        store
            .replace_secret_value(&secret.id, Zeroizing::new("second".into()))
            .await
            .unwrap();
        assert_eq!(&*store.secret_value(&secret.id).await.unwrap(), "second");

        let connection = store
            .add_connection(ConnectionSpec {
                name: "warehouse".into(),
                config: ConnectionConfig::Pg {
                    host: "db.example.com".into(),
                    port: 5432,
                    dbname: "app".into(),
                    user: "app".into(),
                    sslmode: PgSslMode::VerifyFull,
                    trusted_ca_bundle_path: None,
                },
                secrets: vec![secret.id],
            })
            .await
            .unwrap();
        assert_eq!(
            store.connection_by_id(&connection.id).unwrap().name,
            "warehouse"
        );
    }

    #[tokio::test]
    async fn local_policy_identity_and_endpoints_are_object_safe() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::under(dir.path());
        paths.ensure().unwrap();
        let vault = Arc::new(MemoryVault::new());
        let integrity = Arc::new(StateIntegrity::open(vault.as_ref()).await.unwrap());

        let policy: Arc<dyn PolicyRepository> =
            Arc::new(AccessTable::open(paths.access_file(), integrity.clone()).unwrap());
        let connection_id = Uuid::new_v4();
        assert!(policy.set_enabled(connection_id, false).await.unwrap());
        assert!(!policy.allows(&connection_id));

        let endpoints: Arc<dyn EndpointRepository> =
            Arc::new(EndpointRegistry::open(paths.endpoints_file(), 8, integrity.clone()).unwrap());
        let issued = endpoints
            .issue(connection_id, ConnectionKind::Pg)
            .await
            .unwrap();
        assert_eq!(
            endpoints.get_for_connection(&connection_id).unwrap().id,
            issued.endpoint.id
        );

        let identity: Arc<dyn IdentityRepository> = Arc::new(
            IdentityStore::open(
                paths.identity_file(),
                paths.token_file(),
                None,
                std::time::Duration::from_secs(60),
                integrity,
            )
            .unwrap(),
        );
        let manage_token = identity.issue_manage_token().await.unwrap();
        assert!(identity.verify_manage(&manage_token).is_ok());
    }
}
