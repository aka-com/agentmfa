//! Atomic configuration mutations spanning durable repository boundaries.
//!
//! Catalog, policy, and endpoint repositories remain useful read models and
//! focused persistence interfaces. User-visible configuration actions often
//! span more than one of them, though: deleting a connection also removes its
//! policy and endpoints, and retargeting one revokes endpoints for the old
//! destination. [`DomainRepository`] is the unit-of-work boundary for those
//! actions.
//!
//! Successful mutations return the outbox entries committed with their state.
//! The broker applies those entries only after `Ok`, keeping live-session and
//! notification side effects outside the durable transaction. A Postgres
//! implementation must insert the same entries in its transaction so a
//! worker can replay them after a crash. The local adapter emits them directly
//! after its existing sealed-file writes; it exists for the single-workspace
//! product and does not pretend separate files share a database transaction.

use std::sync::Arc;

use uuid::Uuid;

use crate::repository::{
    CatalogRepository, EndpointRepository, PolicyRepository, WorkspaceContext,
};
use crate::store::{ConnectionSpec, NewCredential};
use crate::types::{
    ConfirmMode, Connection, ConnectionKind, SecretMeta, SecretSource, SecretValue,
};
use crate::{CoreError, Result};

/// Why committed authority changed. The stable string is also used when
/// closing live sessions and is suitable for a serialized outbox payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorityChange {
    CredentialRotated,
    ConnectionChanged,
    ConnectionDeleted,
    AccessDisabled,
}

impl AuthorityChange {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CredentialRotated => "secret_rotated",
            Self::ConnectionChanged => "connection_changed",
            Self::ConnectionDeleted => "connection_deleted",
            Self::AccessDisabled => "access_disabled",
        }
    }
}

/// Which durable policy field changed.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyChange {
    Enabled(bool),
    Confirm(ConfirmMode),
    ExposeResponseCredentials(bool),
    AllowedTools(Option<Vec<String>>),
    AuditStatements(Option<bool>),
}

/// A committed event for post-transaction runtime handling.
///
/// `id` makes delivery naturally deduplicatable when a future durable outbox
/// retries an event. Handlers must remain idempotent: closing an already
/// closed session or refreshing an already refreshed view is a no-op.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DomainOutboxEvent {
    pub id: Uuid,
    pub workspace_id: Uuid,
    pub kind: DomainOutboxEventKind,
}

impl DomainOutboxEvent {
    fn new(workspace: &WorkspaceContext, kind: DomainOutboxEventKind) -> Self {
        Self {
            id: Uuid::new_v4(),
            workspace_id: workspace.workspace_id(),
            kind,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DomainOutboxEventKind {
    CredentialChanged {
        credential_id: Uuid,
        value_replaced: bool,
        templates_rewritten: usize,
    },
    ConnectionCreated {
        connection_id: Uuid,
        credential_created: bool,
    },
    ConnectionChanged {
        connection_id: Uuid,
        capability_changed: bool,
        target_changed: bool,
        removed_endpoint_ids: Vec<Uuid>,
    },
    ConnectionDeleted {
        connection_id: Uuid,
        policy_removed: bool,
        removed_endpoint_ids: Vec<Uuid>,
    },
    PolicyChanged {
        connection_id: Uuid,
        change: PolicyChange,
    },
}

/// The value committed by a domain operation and its transactional outbox.
pub struct DomainCommit<T> {
    pub value: T,
    pub outbox: Vec<DomainOutboxEvent>,
}

impl<T> DomainCommit<T> {
    fn one(workspace: &WorkspaceContext, value: T, event: DomainOutboxEventKind) -> Self {
        Self {
            value,
            outbox: vec![DomainOutboxEvent::new(workspace, event)],
        }
    }

    fn without_event(value: T) -> Self {
        Self {
            value,
            outbox: Vec::new(),
        }
    }
}

/// A normalized credential edit. Validation of user-facing site/TOTP input
/// stays in the broker; this request contains only values ready to commit.
pub struct CredentialEdit {
    pub id: Uuid,
    pub new_name: Option<String>,
    pub new_value: Option<SecretValue>,
    /// `None` leaves the site unchanged.
    pub new_site: Option<String>,
    /// `None` leaves the username unchanged; `Some(None)` clears it.
    pub new_username: Option<Option<String>>,
    /// `None` leaves TOTP alone; `Some(None)` removes it.
    pub new_totp: Option<Option<SecretValue>>,
}

pub struct CredentialEditResult {
    pub meta: SecretMeta,
    pub renamed_from: Option<String>,
    pub templates_rewritten: usize,
    pub value_replaced: bool,
    pub profile_changed: bool,
    pub totp_changed: bool,
}

pub struct ConnectionUpdate {
    pub id: Uuid,
    pub expected_version: Option<String>,
    pub spec: ConnectionSpec,
}

pub struct ConnectionUpdateResult {
    pub previous: Connection,
    pub connection: Connection,
    pub capability_changed: bool,
    pub target_changed: bool,
    pub removed_endpoint_ids: Vec<Uuid>,
}

pub struct ConnectionDeleteResult {
    pub connection: Connection,
    pub policy_removed: bool,
    pub removed_endpoint_ids: Vec<Uuid>,
}

/// A policy compare-and-set evaluated inside the domain transaction. Broker
/// callers populate both expectations from the read model; background jobs
/// may omit them when last-writer-wins is intentional.
pub struct PolicyUpdate {
    pub connection_id: Uuid,
    pub expected_connection_version: Option<String>,
    pub expected: Option<PolicyChange>,
    pub change: PolicyChange,
}

pub struct PolicyUpdateResult {
    pub connection: Connection,
    pub changed: bool,
    pub change: PolicyChange,
}

/// Unit-of-work boundary for user-visible configuration actions.
///
/// A durable hosted implementation must update every participating table and
/// insert the returned outbox entries in one transaction. No SQL transaction
/// object escapes this trait. The local compatibility adapter retains the
/// sealed-file backend's documented cross-file failure limitation.
#[async_trait::async_trait]
pub trait DomainRepository: Send + Sync {
    async fn add_credential(
        &self,
        workspace: &WorkspaceContext,
        spec: NewCredential,
    ) -> Result<DomainCommit<SecretMeta>>;

    async fn edit_credential(
        &self,
        workspace: &WorkspaceContext,
        edit: CredentialEdit,
    ) -> Result<DomainCommit<CredentialEditResult>>;

    async fn delete_credential(
        &self,
        workspace: &WorkspaceContext,
        id: &Uuid,
    ) -> Result<DomainCommit<SecretMeta>>;

    async fn add_connection(
        &self,
        workspace: &WorkspaceContext,
        spec: ConnectionSpec,
    ) -> Result<DomainCommit<Connection>>;

    async fn add_connection_with_secret(
        &self,
        workspace: &WorkspaceContext,
        secret_name: &str,
        value: SecretValue,
        spec: ConnectionSpec,
    ) -> Result<DomainCommit<(SecretMeta, Connection)>>;

    async fn update_connection(
        &self,
        workspace: &WorkspaceContext,
        update: ConnectionUpdate,
    ) -> Result<DomainCommit<ConnectionUpdateResult>>;

    async fn delete_connection(
        &self,
        workspace: &WorkspaceContext,
        id: &Uuid,
        expected_version: &str,
    ) -> Result<DomainCommit<ConnectionDeleteResult>>;

    async fn update_policy(
        &self,
        workspace: &WorkspaceContext,
        update: PolicyUpdate,
    ) -> Result<DomainCommit<PolicyUpdateResult>>;
}

/// Compatibility unit of work for the current local sealed-file stores.
///
/// The gate makes every domain action linearizable within a process. The
/// individual local repositories retain their existing rollback behavior;
/// unlike a hosted implementation they cannot make distinct files share one
/// physical commit. Keeping that limitation here, outside `Broker`, is what
/// lets the hosted implementation replace it with a real database transaction.
pub struct LocalDomainRepository {
    catalog: Arc<dyn CatalogRepository>,
    policy: Arc<dyn PolicyRepository>,
    endpoints: Arc<dyn EndpointRepository>,
    gate: Arc<tokio::sync::Mutex<()>>,
}

impl LocalDomainRepository {
    pub fn new(
        catalog: Arc<dyn CatalogRepository>,
        policy: Arc<dyn PolicyRepository>,
        endpoints: Arc<dyn EndpointRepository>,
    ) -> Self {
        Self::with_gate(
            catalog,
            policy,
            endpoints,
            Arc::new(tokio::sync::Mutex::new(())),
        )
    }

    pub(crate) fn with_gate(
        catalog: Arc<dyn CatalogRepository>,
        policy: Arc<dyn PolicyRepository>,
        endpoints: Arc<dyn EndpointRepository>,
        gate: Arc<tokio::sync::Mutex<()>>,
    ) -> Self {
        Self {
            catalog,
            policy,
            endpoints,
            gate,
        }
    }

    fn current_policy_value(
        &self,
        workspace: &WorkspaceContext,
        connection_id: &Uuid,
        field: &PolicyChange,
    ) -> PolicyChange {
        match field {
            PolicyChange::Enabled(_) => {
                PolicyChange::Enabled(self.policy.allows(workspace, connection_id))
            }
            PolicyChange::Confirm(_) => {
                PolicyChange::Confirm(self.policy.confirm_mode(workspace, connection_id))
            }
            PolicyChange::ExposeResponseCredentials(_) => PolicyChange::ExposeResponseCredentials(
                self.policy
                    .expose_response_credentials(workspace, connection_id),
            ),
            PolicyChange::AllowedTools(_) => {
                PolicyChange::AllowedTools(self.policy.allowed_tools(workspace, connection_id))
            }
            PolicyChange::AuditStatements(_) => PolicyChange::AuditStatements(
                self.policy
                    .entry(workspace, connection_id)
                    .and_then(|entry| entry.audit_statements),
            ),
        }
    }
}

#[async_trait::async_trait]
impl DomainRepository for LocalDomainRepository {
    async fn add_credential(
        &self,
        workspace: &WorkspaceContext,
        spec: NewCredential,
    ) -> Result<DomainCommit<SecretMeta>> {
        let _gate = self.gate.lock().await;
        let meta = self.catalog.add_credential(workspace, spec).await?;
        Ok(DomainCommit::one(
            workspace,
            meta.clone(),
            DomainOutboxEventKind::CredentialChanged {
                credential_id: meta.id,
                value_replaced: false,
                templates_rewritten: 0,
            },
        ))
    }

    async fn edit_credential(
        &self,
        workspace: &WorkspaceContext,
        mut edit: CredentialEdit,
    ) -> Result<DomainCommit<CredentialEditResult>> {
        let _gate = self.gate.lock().await;
        let mut meta = self.catalog.secret_by_id(workspace, &edit.id)?;
        if edit.new_value.is_some() && !matches!(meta.source, SecretSource::Local) {
            return Err(CoreError::ExternalSecretReadOnly);
        }
        if (edit.new_site.is_some() || edit.new_username.is_some() || edit.new_totp.is_some())
            && meta.kind != crate::types::SecretKind::Password
        {
            return Err(CoreError::NotAPassword);
        }
        if edit.new_totp.is_some() && !matches!(meta.source, SecretSource::Local) {
            return Err(CoreError::ExternalSecretReadOnly);
        }

        let mut renamed_from = None;
        let mut templates_rewritten = 0;
        if let Some(new_name) = edit.new_name.take() {
            if new_name != meta.name {
                renamed_from = Some(meta.name.clone());
                let renamed = self
                    .catalog
                    .rename_secret(workspace, &edit.id, &new_name)
                    .await?;
                meta = renamed.0;
                templates_rewritten = renamed.1;
            }
        }
        let value_replaced = edit.new_value.is_some();
        if let Some(value) = edit.new_value {
            meta = self
                .catalog
                .replace_secret_value(workspace, &edit.id, value)
                .await?;
        }
        let profile_changed = edit.new_site.is_some() || edit.new_username.is_some();
        if profile_changed {
            meta = self
                .catalog
                .set_password_profile(workspace, &edit.id, edit.new_site, edit.new_username)
                .await?;
        }
        let totp_changed = edit.new_totp.is_some();
        if let Some(totp) = edit.new_totp {
            meta = self
                .catalog
                .set_totp_factor(workspace, &edit.id, totp)
                .await?;
        }

        let result = CredentialEditResult {
            meta,
            renamed_from,
            templates_rewritten,
            value_replaced,
            profile_changed,
            totp_changed,
        };
        if !result.value_replaced
            && result.renamed_from.is_none()
            && !result.profile_changed
            && !result.totp_changed
        {
            return Ok(DomainCommit::without_event(result));
        }
        Ok(DomainCommit::one(
            workspace,
            result,
            DomainOutboxEventKind::CredentialChanged {
                credential_id: edit.id,
                value_replaced,
                templates_rewritten,
            },
        ))
    }

    async fn delete_credential(
        &self,
        workspace: &WorkspaceContext,
        id: &Uuid,
    ) -> Result<DomainCommit<SecretMeta>> {
        let _gate = self.gate.lock().await;
        let meta = self.catalog.delete_secret(workspace, id).await?;
        Ok(DomainCommit::one(
            workspace,
            meta,
            DomainOutboxEventKind::CredentialChanged {
                credential_id: *id,
                value_replaced: false,
                templates_rewritten: 0,
            },
        ))
    }

    async fn add_connection(
        &self,
        workspace: &WorkspaceContext,
        spec: ConnectionSpec,
    ) -> Result<DomainCommit<Connection>> {
        let _gate = self.gate.lock().await;
        let connection = self.catalog.add_connection(workspace, spec).await?;
        Ok(DomainCommit::one(
            workspace,
            connection.clone(),
            DomainOutboxEventKind::ConnectionCreated {
                connection_id: connection.id,
                credential_created: false,
            },
        ))
    }

    async fn add_connection_with_secret(
        &self,
        workspace: &WorkspaceContext,
        secret_name: &str,
        value: SecretValue,
        spec: ConnectionSpec,
    ) -> Result<DomainCommit<(SecretMeta, Connection)>> {
        let _gate = self.gate.lock().await;
        let created = self
            .catalog
            .add_connection_with_secret(workspace, secret_name, value, spec)
            .await?;
        Ok(DomainCommit::one(
            workspace,
            created.clone(),
            DomainOutboxEventKind::ConnectionCreated {
                connection_id: created.1.id,
                credential_created: true,
            },
        ))
    }

    async fn update_connection(
        &self,
        workspace: &WorkspaceContext,
        update: ConnectionUpdate,
    ) -> Result<DomainCommit<ConnectionUpdateResult>> {
        let _gate = self.gate.lock().await;
        let previous = self.catalog.connection_by_id(workspace, &update.id)?;
        if update
            .expected_version
            .as_deref()
            .is_some_and(|expected| previous.version() != expected)
        {
            return Err(CoreError::ConnectionChanged);
        }
        let explicit_secrets_changed =
            previous.kind() != ConnectionKind::Api && previous.secrets != update.spec.secrets;
        let capability_changed = previous.config != update.spec.config || explicit_secrets_changed;
        let (connection, target_changed) = if capability_changed {
            match update.expected_version.as_deref() {
                Some(expected) => {
                    self.catalog
                        .update_connection_if_current(workspace, &update.id, expected, update.spec)
                        .await?
                }
                None => {
                    self.catalog
                        .update_connection(workspace, &update.id, update.spec)
                        .await?
                }
            }
        } else {
            let connection = match update.expected_version.as_deref() {
                Some(expected) => {
                    self.catalog
                        .rename_connection_if_current(
                            workspace,
                            &update.id,
                            expected,
                            update.spec.name,
                        )
                        .await?
                }
                None => {
                    self.catalog
                        .rename_connection(workspace, &update.id, update.spec.name)
                        .await?
                }
            };
            (connection, false)
        };
        let removed_endpoint_ids = if target_changed {
            self.endpoints
                .remove_for_connection(workspace, &update.id)
                .await?
                .into_iter()
                .map(|endpoint| endpoint.id)
                .collect()
        } else {
            Vec::new()
        };
        let result = ConnectionUpdateResult {
            previous,
            connection,
            capability_changed,
            target_changed,
            removed_endpoint_ids: removed_endpoint_ids.clone(),
        };
        Ok(DomainCommit::one(
            workspace,
            result,
            DomainOutboxEventKind::ConnectionChanged {
                connection_id: update.id,
                capability_changed,
                target_changed,
                removed_endpoint_ids,
            },
        ))
    }

    async fn delete_connection(
        &self,
        workspace: &WorkspaceContext,
        id: &Uuid,
        expected_version: &str,
    ) -> Result<DomainCommit<ConnectionDeleteResult>> {
        let _gate = self.gate.lock().await;
        let current = self.catalog.connection_by_id(workspace, id)?;
        if current.version() != expected_version {
            return Err(CoreError::ApprovalConnectionChanged);
        }
        let connection = self.catalog.delete_connection(workspace, id).await?;
        let policy_removed = self.policy.remove_for_connection(workspace, id).await?;
        let removed_endpoint_ids: Vec<Uuid> = self
            .endpoints
            .remove_for_connection(workspace, id)
            .await?
            .into_iter()
            .map(|endpoint| endpoint.id)
            .collect();
        let result = ConnectionDeleteResult {
            connection,
            policy_removed,
            removed_endpoint_ids: removed_endpoint_ids.clone(),
        };
        Ok(DomainCommit::one(
            workspace,
            result,
            DomainOutboxEventKind::ConnectionDeleted {
                connection_id: *id,
                policy_removed,
                removed_endpoint_ids,
            },
        ))
    }

    async fn update_policy(
        &self,
        workspace: &WorkspaceContext,
        update: PolicyUpdate,
    ) -> Result<DomainCommit<PolicyUpdateResult>> {
        let _gate = self.gate.lock().await;
        let connection = self
            .catalog
            .connection_by_id(workspace, &update.connection_id)?;
        if update
            .expected_connection_version
            .as_deref()
            .is_some_and(|expected| connection.version() != expected)
        {
            return Err(CoreError::ApprovalConnectionChanged);
        }
        if update.expected.as_ref().is_some_and(|expected| {
            self.current_policy_value(workspace, &update.connection_id, expected) != *expected
        }) {
            return Err(CoreError::ApprovalConnectionChanged);
        }
        if matches!(&update.change, PolicyChange::ExposeResponseCredentials(_))
            && connection.kind() != ConnectionKind::Api
        {
            return Err(CoreError::InvalidSetting(
                "upstream response credentials apply only to API connections".into(),
            ));
        }
        let changed = match &update.change {
            PolicyChange::Enabled(enabled) => {
                self.policy
                    .set_enabled(workspace, update.connection_id, *enabled)
                    .await?
            }
            PolicyChange::Confirm(confirm) => {
                self.policy
                    .set_confirm_mode(workspace, update.connection_id, *confirm)
                    .await?
            }
            PolicyChange::ExposeResponseCredentials(expose) => {
                self.policy
                    .set_expose_response_credentials(workspace, update.connection_id, *expose)
                    .await?
            }
            PolicyChange::AllowedTools(tools) => {
                self.policy
                    .set_allowed_tools(workspace, update.connection_id, tools.clone())
                    .await?
            }
            PolicyChange::AuditStatements(audit) => {
                self.policy
                    .set_audit_statements(workspace, update.connection_id, *audit)
                    .await?
            }
        };
        let result = PolicyUpdateResult {
            connection,
            changed,
            change: update.change.clone(),
        };
        if !changed {
            return Ok(DomainCommit::without_event(result));
        }
        Ok(DomainCommit::one(
            workspace,
            result,
            DomainOutboxEventKind::PolicyChanged {
                connection_id: update.connection_id,
                change: update.change,
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endpoints::EndpointRegistry;
    use crate::integrity::StateIntegrity;
    use crate::paths::Paths;
    use crate::policy::AccessTable;
    use crate::store::Store;
    use crate::types::{ConnectionConfig, PgSslMode, SecretKind};
    use crate::vault::MemoryVault;
    use zeroize::Zeroizing;

    struct Fixture {
        _dir: tempfile::TempDir,
        workspace: WorkspaceContext,
        catalog: Arc<dyn CatalogRepository>,
        policy: Arc<dyn PolicyRepository>,
        endpoints: Arc<dyn EndpointRepository>,
        domain: LocalDomainRepository,
    }

    impl Fixture {
        async fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let paths = Paths::under(dir.path());
            paths.ensure().unwrap();
            let vault = Arc::new(MemoryVault::new());
            let catalog: Arc<dyn CatalogRepository> =
                Arc::new(Store::open(paths.clone(), vault.clone()).await.unwrap());
            let integrity = Arc::new(StateIntegrity::open(vault.as_ref()).await.unwrap());
            let policy: Arc<dyn PolicyRepository> =
                Arc::new(AccessTable::open(paths.access_file(), integrity.clone()).unwrap());
            let endpoints: Arc<dyn EndpointRepository> =
                Arc::new(EndpointRegistry::open(paths.endpoints_file(), 8, integrity).unwrap());
            let domain =
                LocalDomainRepository::new(catalog.clone(), policy.clone(), endpoints.clone());
            Self {
                _dir: dir,
                workspace: WorkspaceContext::new(Uuid::new_v4()),
                catalog,
                policy,
                endpoints,
                domain,
            }
        }

        async fn add_pg_connection(&self) -> (SecretMeta, Connection) {
            self.domain
                .add_connection_with_secret(
                    &self.workspace,
                    "DATABASE_PASSWORD",
                    Zeroizing::new("first".into()),
                    pg_spec("db.example.com"),
                )
                .await
                .unwrap()
                .value
        }
    }

    fn pg_spec(host: &str) -> ConnectionSpec {
        ConnectionSpec {
            name: "warehouse".into(),
            config: ConnectionConfig::Pg {
                host: host.into(),
                port: 5432,
                dbname: "app".into(),
                user: "app".into(),
                sslmode: PgSslMode::VerifyFull,
                trusted_ca_bundle_path: None,
            },
            secrets: Vec::new(),
        }
    }

    #[tokio::test]
    async fn credential_edit_commits_one_workspace_scoped_outbox_event() {
        let fixture = Fixture::new().await;
        let created = fixture
            .domain
            .add_credential(
                &fixture.workspace,
                NewCredential {
                    kind: SecretKind::Secret,
                    name: Some("API_TOKEN".into()),
                    site: None,
                    username: None,
                    value: Zeroizing::new("first".into()),
                    totp: None,
                },
            )
            .await
            .unwrap();
        let credential_id = created.value.id;
        fixture
            .domain
            .add_connection(
                &fixture.workspace,
                ConnectionSpec {
                    name: "api".into(),
                    config: ConnectionConfig::Api {
                        host: "api.example.com".into(),
                        scheme: "https".into(),
                        port: None,
                        trusted_ca_bundle_path: None,
                        template: "Authorization: Bearer {{API_TOKEN}}".into(),
                        mcp_path: None,
                        test_path: None,
                        oauth: None,
                        signer: None,
                        client_cert_path: None,
                        client_key_path: None,
                    },
                    secrets: Vec::new(),
                },
            )
            .await
            .unwrap();

        let committed = fixture
            .domain
            .edit_credential(
                &fixture.workspace,
                CredentialEdit {
                    id: credential_id,
                    new_name: Some("RENAMED_TOKEN".into()),
                    new_value: Some(Zeroizing::new("second".into())),
                    new_site: None,
                    new_username: None,
                    new_totp: None,
                },
            )
            .await
            .unwrap();

        assert_eq!(committed.value.templates_rewritten, 1);
        assert!(committed.value.value_replaced);
        assert_eq!(committed.outbox.len(), 1);
        assert_eq!(
            committed.outbox[0].workspace_id,
            fixture.workspace.workspace_id()
        );
        let serialized = serde_json::to_value(&committed.outbox[0]).unwrap();
        assert!(serialized.get("affected_connections").is_none());
        let DomainOutboxEventKind::CredentialChanged { value_replaced, .. } =
            &committed.outbox[0].kind
        else {
            panic!("expected credential outbox event")
        };
        assert!(*value_replaced);
        assert_eq!(
            &*fixture
                .catalog
                .secret_value(&fixture.workspace, &credential_id)
                .await
                .unwrap(),
            "second"
        );
        let connection = fixture
            .catalog
            .list_connections(&fixture.workspace)
            .remove(0);
        let ConnectionConfig::Api { template, .. } = connection.config else {
            panic!("expected api connection")
        };
        assert!(template.contains("{{RENAMED_TOKEN}}"));
    }

    #[tokio::test]
    async fn retarget_and_delete_include_dependent_cleanup() {
        let fixture = Fixture::new().await;
        let (_, connection) = fixture.add_pg_connection().await;
        let issued = fixture
            .endpoints
            .issue(&fixture.workspace, connection.id, ConnectionKind::Pg)
            .await
            .unwrap();
        fixture
            .policy
            .set_enabled(&fixture.workspace, connection.id, false)
            .await
            .unwrap();

        let updated = fixture
            .domain
            .update_connection(
                &fixture.workspace,
                ConnectionUpdate {
                    id: connection.id,
                    expected_version: Some(connection.version()),
                    spec: pg_spec("new.example.com"),
                },
            )
            .await
            .unwrap();
        assert!(updated.value.target_changed);
        assert_eq!(updated.value.removed_endpoint_ids, [issued.endpoint.id]);
        assert!(fixture.endpoints.list(&fixture.workspace).is_empty());

        let deleted = fixture
            .domain
            .delete_connection(
                &fixture.workspace,
                &connection.id,
                &updated.value.connection.version(),
            )
            .await
            .unwrap();
        assert!(deleted.value.policy_removed);
        assert!(fixture
            .catalog
            .connection_by_id(&fixture.workspace, &connection.id)
            .is_err());
        assert!(fixture
            .policy
            .entry(&fixture.workspace, &connection.id)
            .is_none());
    }

    #[tokio::test]
    async fn rejected_or_noop_mutations_emit_no_outbox() {
        let fixture = Fixture::new().await;
        let (_, connection) = fixture.add_pg_connection().await;
        let issued = fixture
            .endpoints
            .issue(&fixture.workspace, connection.id, ConnectionKind::Pg)
            .await
            .unwrap();
        let current = fixture
            .catalog
            .rename_connection(
                &fixture.workspace,
                &connection.id,
                "renamed warehouse".into(),
            )
            .await
            .unwrap();

        let stale = fixture
            .domain
            .update_connection(
                &fixture.workspace,
                ConnectionUpdate {
                    id: connection.id,
                    expected_version: Some(connection.version()),
                    spec: pg_spec("new.example.com"),
                },
            )
            .await;
        assert!(matches!(stale, Err(CoreError::ConnectionChanged)));
        assert_eq!(
            fixture
                .endpoints
                .get_for_connection(&fixture.workspace, &connection.id)
                .unwrap()
                .id,
            issued.endpoint.id
        );
        assert_eq!(
            fixture
                .catalog
                .connection_by_id(&fixture.workspace, &connection.id)
                .unwrap()
                .version(),
            current.version()
        );

        let no_change = fixture
            .domain
            .update_policy(
                &fixture.workspace,
                PolicyUpdate {
                    connection_id: connection.id,
                    expected_connection_version: None,
                    expected: None,
                    change: PolicyChange::Enabled(true),
                },
            )
            .await
            .unwrap();
        assert!(!no_change.value.changed);
        assert!(no_change.outbox.is_empty());

        let raced = fixture
            .domain
            .update_policy(
                &fixture.workspace,
                PolicyUpdate {
                    connection_id: connection.id,
                    expected_connection_version: Some(current.version()),
                    expected: Some(PolicyChange::Enabled(false)),
                    change: PolicyChange::Enabled(false),
                },
            )
            .await;
        assert!(matches!(raced, Err(CoreError::ApprovalConnectionChanged)));
        assert!(fixture.policy.allows(&fixture.workspace, &connection.id));
    }
}
