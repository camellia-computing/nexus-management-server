use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::Arc,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Row, Transaction, postgres::PgRow};
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    crypto::{random_id, sha256_hex},
    domain::AuditEventRecord,
    error::{ApiError, Result},
    plan_catalog::{
        CURRENT_PLAN_REVISION, TEAM_MAX_ALERT_RULES, TEAM_MAX_AUDIT_EXPORT_EVENTS,
        TEAM_WORKSPACE_STORAGE_BYTES,
    },
    secret_file::{read_secret_file, valid_keyring_key_count},
    store::PostgresRepository,
    team::workspace_role_has_permission as role_has_permission,
    webhooks::{NewWebhookEvent, WebhookError, enqueue_webhook_event_tx},
};

pub const MAX_ACTIVE_DOCUMENTS: i64 = 200;
pub const MAX_CONFIGURATION_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_WORKSPACE_PLAINTEXT_BYTES: i64 = TEAM_WORKSPACE_STORAGE_BYTES as i64;
pub const CONFIGURATION_HTTP_BODY_LIMIT: usize = 8 * 1024 * 1024 + 64 * 1024;
pub const MAX_PAGE_SIZE: u32 = 200;
pub const MAX_AUDIT_EXPORT_SIZE: u32 = TEAM_MAX_AUDIT_EXPORT_EVENTS as u32;
pub const MAX_ALERT_RULES: u32 = TEAM_MAX_ALERT_RULES as u32;
pub const DELETED_CONFIGURATION_RETENTION_SECONDS: i64 = 30 * 24 * 60 * 60;
const MAX_AUDIT_EVENT_TYPES: i64 = 256;

pub const SHARED_READ_SCOPE: &str = "workspace:shared:read";
pub const SHARED_WRITE_SCOPE: &str = "workspace:shared:write";
pub const SHARED_PUBLISH_SCOPE: &str = "workspace:shared:publish";
pub const SHARED_PURGE_SCOPE: &str = "workspace:shared:purge";
pub const SYNC_READ_SCOPE: &str = "workspace:sync:read";
pub const SYNC_WRITE_SCOPE: &str = "workspace:sync:write";
pub const ALERTS_READ_SCOPE: &str = "workspace:alerts:read";
pub const ALERTS_MANAGE_SCOPE: &str = "workspace:alerts:manage";
pub const ALERTS_ACK_SCOPE: &str = "workspace:alerts:ack";
pub const AUDIT_READ_SCOPE: &str = "workspace:audit:read";
pub const AUDIT_EXPORT_SCOPE: &str = "workspace:audit:export";

const MAX_NAME_BYTES: usize = 160;
const MAX_INPUT_BYTES: usize = 4 * 1024;
const MAX_ID_BYTES: usize = 128;
const DEFAULT_PAGE_SIZE: u32 = 50;
const QUOTA_WARNING_NUMERATOR: i64 = 4;
const QUOTA_WARNING_DENOMINATOR: i64 = 5;

#[derive(Debug, Error)]
#[error("workspace keyring configuration is invalid")]
pub struct WorkspaceKeyringError;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WorkspaceKeyringDocument {
    active_key_id: String,
    keys: BTreeMap<String, String>,
}

impl Drop for WorkspaceKeyringDocument {
    fn drop(&mut self) {
        self.active_key_id.zeroize();
        for (mut key_id, mut encoded_key) in std::mem::take(&mut self.keys) {
            key_id.zeroize();
            encoded_key.zeroize();
        }
    }
}

pub struct WorkspaceKeyring {
    active_key_id: String,
    keys: BTreeMap<String, [u8; 32]>,
}

impl Drop for WorkspaceKeyring {
    fn drop(&mut self) {
        self.active_key_id.zeroize();
        for key in self.keys.values_mut() {
            key.zeroize();
        }
    }
}

impl WorkspaceKeyring {
    pub fn load(path: impl AsRef<Path>) -> std::result::Result<Self, WorkspaceKeyringError> {
        let bytes = read_secret_file(path).map_err(|_| WorkspaceKeyringError)?;
        let mut document: WorkspaceKeyringDocument =
            serde_json::from_slice(&bytes).map_err(|_| WorkspaceKeyringError)?;
        let active_key_id = validate_key_id(&document.active_key_id)?;
        if !valid_keyring_key_count(document.keys.len()) {
            return Err(WorkspaceKeyringError);
        }
        let mut keys = BTreeMap::new();
        for (mut raw_id, encoded) in std::mem::take(&mut document.keys) {
            let id = validate_key_id(&raw_id)?;
            raw_id.zeroize();
            let encoded = Zeroizing::new(encoded);
            if encoded.as_str() != encoded.trim() {
                return Err(WorkspaceKeyringError);
            }
            let decoded = Zeroizing::new(
                URL_SAFE_NO_PAD
                    .decode(encoded.as_bytes())
                    .map_err(|_| WorkspaceKeyringError)?,
            );
            let key: [u8; 32] = decoded
                .as_slice()
                .try_into()
                .map_err(|_| WorkspaceKeyringError)?;
            if keys.insert(id, key).is_some() {
                return Err(WorkspaceKeyringError);
            }
        }
        if !keys.contains_key(&active_key_id) {
            return Err(WorkspaceKeyringError);
        }
        Ok(Self {
            active_key_id,
            keys,
        })
    }

    pub fn ephemeral_for_development() -> Self {
        let mut key = [0_u8; 32];
        rand::fill(&mut key);
        Self {
            active_key_id: "ephemeral-development".to_owned(),
            keys: BTreeMap::from([("ephemeral-development".to_owned(), key)]),
        }
    }

    pub(crate) fn contains_key_id(&self, key_id: &str) -> bool {
        self.keys.contains_key(key_id)
    }

    pub(crate) fn seal_team_operation_response(
        &self,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<(String, Vec<u8>, Vec<u8>)> {
        let key = Zeroizing::new(self.derive_team_operation_key(&self.active_key_id)?);
        let mut nonce = [0_u8; 24];
        rand::fill(&mut nonce);
        let ciphertext = XChaCha20Poly1305::new_from_slice(key.as_ref())
            .map_err(|_| ApiError::WorkspaceKeyUnavailable)?
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| ApiError::WorkspaceIntegrity)?;
        Ok((self.active_key_id.clone(), nonce.to_vec(), ciphertext))
    }

    pub(crate) fn open_team_operation_response(
        &self,
        key_id: &str,
        nonce: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>> {
        let nonce: [u8; 24] = nonce.try_into().map_err(|_| ApiError::WorkspaceIntegrity)?;
        let key = Zeroizing::new(self.derive_team_operation_key(key_id)?);
        XChaCha20Poly1305::new_from_slice(key.as_ref())
            .map_err(|_| ApiError::WorkspaceKeyUnavailable)?
            .decrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| ApiError::WorkspaceIntegrity)
    }

    fn derive_team_operation_key(&self, key_id: &str) -> Result<[u8; 32]> {
        let key = self
            .keys
            .get(key_id)
            .ok_or(ApiError::WorkspaceKeyUnavailable)?;
        let hkdf = Hkdf::<Sha256>::new(Some(b"camellia-nexus-team-operation-v1"), key);
        let mut derived = [0_u8; 32];
        hkdf.expand(b"encrypted-response", &mut derived)
            .map_err(|_| ApiError::WorkspaceKeyUnavailable)?;
        Ok(derived)
    }

    fn derive_key(&self, key_id: &str) -> Result<[u8; 32]> {
        let key = self
            .keys
            .get(key_id)
            .ok_or(ApiError::WorkspaceKeyUnavailable)?;
        let hkdf = Hkdf::<Sha256>::new(Some(b"camellia-nexus-workspace-v1"), key);
        let mut derived = [0_u8; 32];
        hkdf.expand(b"shared-configuration-data-key", &mut derived)
            .map_err(|_| ApiError::WorkspaceKeyUnavailable)?;
        Ok(derived)
    }

    fn seal(
        &self,
        account_id: &str,
        document_id: &str,
        revision: u64,
        plaintext: &[u8],
        content: &[u8],
    ) -> Result<ContentEnvelope> {
        let mut data_key = Zeroizing::new([0_u8; 32]);
        let mut content_nonce = [0_u8; 24];
        let mut wrapped_key_nonce = [0_u8; 24];
        rand::fill(data_key.as_mut());
        rand::fill(&mut content_nonce);
        rand::fill(&mut wrapped_key_nonce);
        let aad = content_aad(account_id, document_id, revision);
        let ciphertext = XChaCha20Poly1305::new_from_slice(data_key.as_ref())
            .map_err(|_| ApiError::WorkspaceKeyUnavailable)?
            .encrypt(
                &XNonce::from(content_nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| ApiError::WorkspaceIntegrity)?;
        let wrapping_key = Zeroizing::new(self.derive_key(&self.active_key_id)?);
        let wrapped_data_key = XChaCha20Poly1305::new_from_slice(wrapping_key.as_ref())
            .map_err(|_| ApiError::WorkspaceKeyUnavailable)?
            .encrypt(
                &XNonce::from(wrapped_key_nonce),
                Payload {
                    msg: data_key.as_ref(),
                    aad: &wrapping_aad(&aad),
                },
            )
            .map_err(|_| ApiError::WorkspaceIntegrity)?;
        Ok(ContentEnvelope {
            key_id: self.active_key_id.clone(),
            wrapped_key_nonce: wrapped_key_nonce.to_vec(),
            wrapped_data_key,
            content_nonce: content_nonce.to_vec(),
            ciphertext,
            payload_sha256: Sha256::digest(plaintext).into(),
            content_sha256: Sha256::digest(content).into(),
            plaintext_bytes: i64::try_from(plaintext.len())
                .map_err(|_| ApiError::InvalidRequest)?,
        })
    }

    fn open(
        &self,
        account_id: &str,
        document_id: &str,
        revision: u64,
        envelope: &ContentEnvelope,
    ) -> Result<Vec<u8>> {
        let content_nonce: [u8; 24] = envelope
            .content_nonce
            .as_slice()
            .try_into()
            .map_err(|_| ApiError::WorkspaceIntegrity)?;
        let wrapped_key_nonce: [u8; 24] = envelope
            .wrapped_key_nonce
            .as_slice()
            .try_into()
            .map_err(|_| ApiError::WorkspaceIntegrity)?;
        let aad = content_aad(account_id, document_id, revision);
        let wrapping_key = Zeroizing::new(self.derive_key(&envelope.key_id)?);
        let data_key = Zeroizing::new(
            XChaCha20Poly1305::new_from_slice(wrapping_key.as_ref())
                .map_err(|_| ApiError::WorkspaceKeyUnavailable)?
                .decrypt(
                    &XNonce::from(wrapped_key_nonce),
                    Payload {
                        msg: &envelope.wrapped_data_key,
                        aad: &wrapping_aad(&aad),
                    },
                )
                .map_err(|_| ApiError::WorkspaceIntegrity)?,
        );
        if data_key.len() != 32 {
            return Err(ApiError::WorkspaceIntegrity);
        }
        let plaintext = XChaCha20Poly1305::new_from_slice(data_key.as_ref())
            .map_err(|_| ApiError::WorkspaceIntegrity)?
            .decrypt(
                &XNonce::from(content_nonce),
                Payload {
                    msg: &envelope.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| ApiError::WorkspaceIntegrity)?;
        let actual: [u8; 32] = Sha256::digest(&plaintext).into();
        if plaintext.len() as i64 != envelope.plaintext_bytes
            || !bool::from(actual.ct_eq(&envelope.payload_sha256))
        {
            return Err(ApiError::WorkspaceIntegrity);
        }
        Ok(plaintext)
    }
}

#[derive(Clone)]
pub struct WorkspaceRepository {
    pool: PgPool,
    keyring: Arc<WorkspaceKeyring>,
}

impl WorkspaceRepository {
    pub fn new(repository: &PostgresRepository, keyring: impl Into<Arc<WorkspaceKeyring>>) -> Self {
        Self {
            pool: repository.pool.clone(),
            keyring: keyring.into(),
        }
    }

    pub async fn readiness_check(&self) -> Result<()> {
        let ready: bool = sqlx::query_scalar(
            "SELECT to_regclass('public.workspace_storage_usage') IS NOT NULL
                AND to_regclass('public.workspace_documents') IS NOT NULL
                AND to_regclass('public.workspace_document_revisions') IS NOT NULL
                AND to_regclass('public.workspace_operations') IS NOT NULL
                AND to_regclass('public.workspace_changes') IS NOT NULL
                AND to_regclass('public.workspace_device_checkpoints') IS NOT NULL
                AND to_regclass('public.workspace_alert_rules') IS NOT NULL
                AND to_regclass('public.workspace_alert_incidents') IS NOT NULL",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|_| ApiError::Database)?;
        if !ready {
            return Err(ApiError::DatabaseSchemaNotReady);
        }
        let referenced_key_ids = sqlx::query_scalar::<_, String>(
            "SELECT key_id FROM (
                 SELECT key_id FROM workspace_document_revisions
                 UNION SELECT response_key_id AS key_id FROM team_operations
             ) AS referenced_keys ORDER BY key_id",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|_| ApiError::Database)?;
        if referenced_key_ids
            .iter()
            .any(|key_id| !self.keyring.contains_key_id(key_id))
        {
            return Err(ApiError::WorkspaceKeyUnavailable);
        }
        Ok(())
    }

    pub async fn shared_configurations(
        &self,
        account_id: &str,
        device_id: &str,
        request: SharedConfigurationPageRequest,
        now: i64,
    ) -> Result<SharedConfigurationPage> {
        let limit = page_limit(request.limit, MAX_PAGE_SIZE)?;
        let cursor = request.cursor.as_deref().map(decode_cursor).transpose()?;
        let mut tx = self.pool.begin().await.map_err(|_| ApiError::Database)?;
        let authorization =
            require_permissions_tx(&mut tx, account_id, device_id, &["shared.read"], now).await?;
        let view_policy = configuration_view_policy(&authorization.role, request.include_deleted);
        let rows = sqlx::query(
            "SELECT documents.id, documents.row_version,
                    CASE WHEN $6 THEN documents.published_revision
                         ELSE documents.draft_revision END AS draft_revision,
                    documents.published_revision, documents.deleted_at, documents.created_at,
                    documents.updated_at, revisions.name, revisions.program_kind,
                    revisions.content_sha256, revisions.plaintext_bytes
             FROM workspace_documents AS documents
             JOIN workspace_document_revisions AS revisions
               ON revisions.account_id = documents.account_id
              AND revisions.document_id = documents.id
              AND revisions.revision = CASE WHEN $6
                                            THEN documents.published_revision
                                            ELSE documents.draft_revision END
             WHERE documents.account_id = $1
               AND ((NOT $6 AND ($2 OR documents.deleted_at IS NULL))
                    OR ($6 AND documents.deleted_at IS NULL
                        AND documents.published_revision IS NOT NULL))
               AND ($3::BIGINT IS NULL OR (documents.updated_at, documents.id) < ($3, $4))
             ORDER BY documents.updated_at DESC, documents.id DESC
             LIMIT $5",
        )
        .bind(account_id)
        .bind(view_policy.include_deleted)
        .bind(cursor.as_ref().map(|value| value.timestamp))
        .bind(cursor.as_ref().map(|value| value.id.as_str()))
        .bind(i64::from(limit.saturating_add(1)))
        .bind(view_policy.published_only)
        .fetch_all(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        let usage = storage_usage_tx(&mut tx, account_id).await?;
        tx.commit().await.map_err(|_| ApiError::Database)?;
        let has_more = rows.len() > limit as usize;
        let configurations = rows
            .into_iter()
            .take(limit as usize)
            .map(row_configuration_summary)
            .collect::<Result<Vec<_>>>()?;
        let next_cursor = if has_more {
            configurations
                .last()
                .map(|configuration| {
                    encode_cursor(&KeysetCursor {
                        timestamp: configuration.updated_at,
                        id: configuration.id.clone(),
                    })
                })
                .transpose()?
        } else {
            None
        };
        Ok(SharedConfigurationPage {
            configurations,
            usage,
            next_cursor,
            has_more,
        })
    }

    pub async fn shared_configuration_content(
        &self,
        account_id: &str,
        device_id: &str,
        document_id: &str,
        request: SharedConfigurationContentRequest,
        now: i64,
    ) -> Result<SharedConfigurationContent> {
        validate_resource_id(document_id)?;
        if request.revision == Some(0) {
            return Err(ApiError::InvalidRequest);
        }
        let mut tx = self.pool.begin().await.map_err(|_| ApiError::Database)?;
        let authorization =
            require_permissions_tx(&mut tx, account_id, device_id, &["shared.read"], now).await?;
        let document = sqlx::query(
            "SELECT draft_revision, published_revision, deleted_at
             FROM workspace_documents WHERE account_id = $1 AND id = $2 FOR SHARE",
        )
        .bind(account_id)
        .bind(document_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?
        .ok_or(ApiError::WorkspaceNotFound)?;
        let draft_revision = positive_u64(
            document
                .try_get("draft_revision")
                .map_err(|_| ApiError::Database)?,
        )?;
        let published_revision = document
            .try_get::<Option<i64>, _>("published_revision")
            .map_err(|_| ApiError::Database)?
            .map(positive_u64)
            .transpose()?;
        let deleted_at: Option<i64> = document
            .try_get("deleted_at")
            .map_err(|_| ApiError::Database)?;
        let revision = visible_configuration_revision(
            &authorization.role,
            request.revision,
            draft_revision,
            published_revision,
            deleted_at,
        )?;
        let published_only = authorization.role == "viewer";
        let row = sqlx::query(
            "SELECT documents.id, documents.row_version,
                    CASE WHEN $4 THEN documents.published_revision
                         ELSE documents.draft_revision END AS draft_revision,
                    documents.published_revision, documents.deleted_at, documents.created_at,
                    documents.updated_at, revisions.revision, revisions.name,
                    revisions.program_kind, revisions.key_id,
                    revisions.wrapped_key_nonce, revisions.wrapped_data_key,
                    revisions.content_nonce, revisions.ciphertext, revisions.payload_sha256,
                    revisions.content_sha256,
                    revisions.plaintext_bytes, revisions.created_at AS revision_created_at
             FROM workspace_documents AS documents
             JOIN workspace_document_revisions AS revisions
               ON revisions.account_id = documents.account_id
              AND revisions.document_id = documents.id
              AND revisions.revision = $3
             WHERE documents.account_id = $1 AND documents.id = $2",
        )
        .bind(account_id)
        .bind(document_id)
        .bind(u64_to_i64(revision)?)
        .bind(published_only)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?
        .ok_or(ApiError::WorkspaceNotFound)?;
        tx.commit().await.map_err(|_| ApiError::Database)?;
        let revision = positive_u64(row.try_get("revision").map_err(|_| ApiError::Database)?)?;
        let envelope = row_content_envelope(&row)?;
        let plaintext = self
            .keyring
            .open(account_id, document_id, revision, &envelope)?;
        let (input, content) = decode_configuration_payload(&plaintext)?;
        let actual_content_sha256: [u8; 32] = Sha256::digest(content.as_bytes()).into();
        if !bool::from(actual_content_sha256.ct_eq(&envelope.content_sha256)) {
            return Err(ApiError::WorkspaceIntegrity);
        }
        let revision_created_at = row
            .try_get("revision_created_at")
            .map_err(|_| ApiError::Database)?;
        Ok(SharedConfigurationContent {
            configuration: row_configuration_summary(row)?,
            revision,
            input,
            content,
            revision_created_at,
        })
    }

    pub async fn sync_feed(
        &self,
        account_id: &str,
        device_id: &str,
        request: WorkspaceSyncFeedRequest,
        now: i64,
    ) -> Result<WorkspaceSyncFeed> {
        let limit = page_limit(request.limit, MAX_PAGE_SIZE)?;
        let cursor = request.cursor.unwrap_or(0);
        let cursor_i64 = u64_to_i64(cursor)?;
        let mut tx = self.pool.begin().await.map_err(|_| ApiError::Database)?;
        require_permissions_tx(&mut tx, account_id, device_id, &["sync.read"], now).await?;
        let rows = sqlx::query(
            "SELECT cursor, operation_id, change_kind, resource_type, resource_id,
                    row_version, occurred_at, metadata
             FROM workspace_changes
             WHERE account_id = $1 AND cursor > $2
             ORDER BY cursor ASC
             LIMIT $3",
        )
        .bind(account_id)
        .bind(cursor_i64)
        .bind(i64::from(limit.saturating_add(1)))
        .fetch_all(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        tx.commit().await.map_err(|_| ApiError::Database)?;
        let has_more = rows.len() > limit as usize;
        let changes = rows
            .into_iter()
            .take(limit as usize)
            .map(row_sync_change)
            .collect::<Result<Vec<_>>>()?;
        let next_cursor = changes.last().map_or(cursor, |change| change.cursor);
        Ok(WorkspaceSyncFeed {
            changes,
            next_cursor,
            has_more,
        })
    }

    pub async fn device_checkpoint(
        &self,
        account_id: &str,
        device_id: &str,
        now: i64,
    ) -> Result<Option<WorkspaceDeviceCheckpoint>> {
        let mut tx = self.pool.begin().await.map_err(|_| ApiError::Database)?;
        require_permissions_tx(&mut tx, account_id, device_id, &["sync.read"], now).await?;
        let row = sqlx::query(
            "SELECT cursor, row_version, updated_at FROM workspace_device_checkpoints
             WHERE account_id = $1 AND device_id = $2",
        )
        .bind(account_id)
        .bind(device_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        tx.commit().await.map_err(|_| ApiError::Database)?;
        row.map(|row| {
            Ok(WorkspaceDeviceCheckpoint {
                cursor: nonnegative_u64(row.try_get("cursor").map_err(|_| ApiError::Database)?)?,
                row_version: positive_u64(
                    row.try_get("row_version").map_err(|_| ApiError::Database)?,
                )?,
                updated_at: row.try_get("updated_at").map_err(|_| ApiError::Database)?,
            })
        })
        .transpose()
    }

    pub async fn alert_rules(
        &self,
        account_id: &str,
        device_id: &str,
        request: WorkspaceAlertRulePageRequest,
        now: i64,
    ) -> Result<WorkspaceAlertRulePage> {
        let limit = page_limit(request.limit, MAX_PAGE_SIZE)?;
        let cursor = request.cursor.as_deref().map(decode_cursor).transpose()?;
        let mut tx = self.pool.begin().await.map_err(|_| ApiError::Database)?;
        require_permissions_tx(&mut tx, account_id, device_id, &["alerts.read"], now).await?;
        let rows = sqlx::query(
            "SELECT id, name, event_kind, severity, enabled, row_version, created_at, updated_at
             FROM workspace_alert_rules
             WHERE account_id = $1 AND deleted_at IS NULL
               AND ($2::BIGINT IS NULL OR (created_at, id) < ($2, $3))
             ORDER BY created_at DESC, id DESC LIMIT $4",
        )
        .bind(account_id)
        .bind(cursor.as_ref().map(|value| value.timestamp))
        .bind(cursor.as_ref().map(|value| value.id.as_str()))
        .bind(i64::from(limit.saturating_add(1)))
        .fetch_all(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        tx.commit().await.map_err(|_| ApiError::Database)?;
        let has_more = rows.len() > limit as usize;
        let rules = rows
            .into_iter()
            .take(limit as usize)
            .map(row_alert_rule)
            .collect::<Result<Vec<_>>>()?;
        let next_cursor = if has_more {
            rules
                .last()
                .map(|rule| {
                    encode_cursor(&KeysetCursor {
                        timestamp: rule.created_at,
                        id: rule.id.clone(),
                    })
                })
                .transpose()?
        } else {
            None
        };
        Ok(WorkspaceAlertRulePage {
            rules,
            next_cursor,
            has_more,
        })
    }

    pub async fn alert_incidents(
        &self,
        account_id: &str,
        device_id: &str,
        request: WorkspaceIncidentPageRequest,
        now: i64,
    ) -> Result<WorkspaceIncidentPage> {
        let limit = page_limit(request.limit, MAX_PAGE_SIZE)?;
        let cursor = request.cursor.as_deref().map(decode_cursor).transpose()?;
        let mut tx = self.pool.begin().await.map_err(|_| ApiError::Database)?;
        let authorization = require_permissions_tx(
            &mut tx,
            account_id,
            device_id,
            &["alerts.read", "alerts.history.read"],
            now,
        )
        .await?;
        let can_read_history =
            incident_status_visible(&authorization.role, WorkspaceIncidentStatus::Resolved);
        let rows = sqlx::query(
            "SELECT id, rule_id, event_kind, severity, status, summary, metadata,
                    row_version, occurred_at, acknowledged_at, resolved_at
             FROM workspace_alert_incidents
             WHERE account_id = $1
               AND ($2::BIGINT IS NULL OR (occurred_at, id) < ($2, $3))
               AND ($4::TEXT IS NULL OR status = $4)
               AND ($5::TEXT IS NULL OR event_kind = $5)
               AND ($6::TEXT IS NULL OR severity = $6)
               AND ($8 OR status <> 'resolved')
             ORDER BY occurred_at DESC, id DESC LIMIT $7",
        )
        .bind(account_id)
        .bind(cursor.as_ref().map(|value| value.timestamp))
        .bind(cursor.as_ref().map(|value| value.id.as_str()))
        .bind(request.status.map(incident_status_name))
        .bind(request.event_kind.map(alert_event_kind_name))
        .bind(request.severity.map(alert_severity_name))
        .bind(i64::from(limit.saturating_add(1)))
        .bind(can_read_history)
        .fetch_all(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        tx.commit().await.map_err(|_| ApiError::Database)?;
        let has_more = rows.len() > limit as usize;
        let incidents = rows
            .into_iter()
            .take(limit as usize)
            .map(row_alert_incident)
            .collect::<Result<Vec<_>>>()?;
        let next_cursor = if has_more {
            incidents
                .last()
                .map(|incident| {
                    encode_cursor(&KeysetCursor {
                        timestamp: incident.occurred_at,
                        id: incident.id.clone(),
                    })
                })
                .transpose()?
        } else {
            None
        };
        Ok(WorkspaceIncidentPage {
            incidents,
            next_cursor,
            has_more,
        })
    }

    pub async fn audit_page(
        &self,
        account_id: &str,
        device_id: &str,
        request: WorkspaceAuditPageRequest,
        now: i64,
    ) -> Result<WorkspaceAuditPage> {
        let limit = page_limit(request.limit, MAX_PAGE_SIZE)?;
        let (events, next_cursor, has_more) = self
            .audit_events(account_id, device_id, request, limit, "audit.read", now)
            .await?;
        Ok(WorkspaceAuditPage {
            events,
            next_cursor,
            has_more,
        })
    }

    pub async fn audit_event_types(
        &self,
        account_id: &str,
        device_id: &str,
        now: i64,
    ) -> Result<WorkspaceAuditEventTypes> {
        let mut tx = self.pool.begin().await.map_err(|_| ApiError::Database)?;
        require_permissions_tx(&mut tx, account_id, device_id, &["audit.read"], now).await?;
        let event_types = sqlx::query_scalar::<_, String>(
            "SELECT event_type
             FROM audit_events
             WHERE account_id = $1
             GROUP BY event_type
             ORDER BY MAX(occurred_at) DESC, event_type
             LIMIT $2",
        )
        .bind(account_id)
        .bind(MAX_AUDIT_EVENT_TYPES)
        .fetch_all(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        tx.commit().await.map_err(|_| ApiError::Database)?;
        Ok(WorkspaceAuditEventTypes { event_types })
    }

    pub async fn audit_export(
        &self,
        account_id: &str,
        device_id: &str,
        request: WorkspaceAuditPageRequest,
        now: i64,
    ) -> Result<WorkspaceAuditExport> {
        let limit = page_limit(request.limit, MAX_AUDIT_EXPORT_SIZE)?;
        let (events, next_cursor, truncated) = self
            .audit_events(account_id, device_id, request, limit, "audit.export", now)
            .await?;
        Ok(WorkspaceAuditExport {
            events,
            next_cursor,
            truncated,
        })
    }

    async fn audit_events(
        &self,
        account_id: &str,
        device_id: &str,
        request: WorkspaceAuditPageRequest,
        limit: u32,
        permission: &str,
        now: i64,
    ) -> Result<(Vec<WorkspaceAuditEvent>, Option<String>, bool)> {
        let cursor = request.cursor.as_deref().map(decode_cursor).transpose()?;
        let event_type = request
            .event_type
            .as_deref()
            .map(validate_event_type)
            .transpose()?;
        let mut tx = self.pool.begin().await.map_err(|_| ApiError::Database)?;
        require_permissions_tx(&mut tx, account_id, device_id, &[permission], now).await?;
        let rows = sqlx::query(
            "SELECT id, event_type, outcome, occurred_at, device_id, reason_code, metadata
             FROM audit_events
             WHERE account_id = $1
               AND ($2::BIGINT IS NULL OR (occurred_at, id) < ($2, $3))
               AND ($4::TEXT IS NOT NULL OR event_type <> 'challenge_issued')
               AND ($4::TEXT IS NULL OR event_type = $4)
             ORDER BY occurred_at DESC, id DESC LIMIT $5",
        )
        .bind(account_id)
        .bind(cursor.as_ref().map(|value| value.timestamp))
        .bind(cursor.as_ref().map(|value| value.id.as_str()))
        .bind(event_type.as_deref())
        .bind(i64::from(limit.saturating_add(1)))
        .fetch_all(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        tx.commit().await.map_err(|_| ApiError::Database)?;
        let truncated = rows.len() > limit as usize;
        let events = rows
            .into_iter()
            .take(limit as usize)
            .map(row_audit_event)
            .collect::<Result<Vec<_>>>()?;
        let next_cursor = if truncated {
            events
                .last()
                .map(|event| {
                    encode_cursor(&KeysetCursor {
                        timestamp: event.occurred_at,
                        id: event.id.clone(),
                    })
                })
                .transpose()?
        } else {
            None
        };
        Ok((events, next_cursor, truncated))
    }

    pub async fn create_shared_configuration(
        &self,
        account_id: &str,
        device_id: &str,
        request: CreateSharedConfiguration,
        now: i64,
    ) -> Result<WorkspaceMutationReceipt> {
        let (name, input) = validate_configuration_input(
            &request.name,
            &request.input,
            request.content.as_bytes(),
        )?;
        validate_operation_id(&request.operation_id)?;
        let request_sha256 = request_digest("shared.create", &request)?;
        let document_id = random_id("shared_config");
        let payload = encode_configuration_payload(&input, &request.content)?;
        let envelope = self.keyring.seal(
            account_id,
            &document_id,
            1,
            &payload,
            request.content.as_bytes(),
        )?;
        let mut tx = self.pool.begin().await.map_err(|_| ApiError::Database)?;
        require_permissions_tx(&mut tx, account_id, device_id, &["shared.write"], now).await?;
        if let Some(receipt) = claim_operation_tx(
            &mut tx,
            account_id,
            device_id,
            &request.operation_id,
            "shared.create",
            &request_sha256,
        )
        .await?
        {
            tx.commit().await.map_err(|_| ApiError::Database)?;
            return Ok(receipt);
        }
        let usage = lock_storage_usage_tx(&mut tx, account_id, now).await?;
        if usage.active_document_count >= MAX_ACTIVE_DOCUMENTS {
            record_limit_failure_tx(
                &mut tx,
                account_id,
                device_id,
                &request.operation_id,
                "shared.create",
                &request_sha256,
                "document_limit",
                ApiError::WorkspaceDocumentLimitReached,
                now,
            )
            .await?;
            require_permissions_tx(&mut tx, account_id, device_id, &["shared.write"], now).await?;
            tx.commit().await.map_err(|_| ApiError::Database)?;
            return Err(ApiError::WorkspaceDocumentLimitReached);
        }
        if usage
            .revision_plaintext_bytes
            .saturating_add(envelope.plaintext_bytes)
            > MAX_WORKSPACE_PLAINTEXT_BYTES
        {
            record_limit_failure_tx(
                &mut tx,
                account_id,
                device_id,
                &request.operation_id,
                "shared.create",
                &request_sha256,
                "quota_exceeded",
                ApiError::WorkspaceQuotaExceeded,
                now,
            )
            .await?;
            require_permissions_tx(&mut tx, account_id, device_id, &["shared.write"], now).await?;
            tx.commit().await.map_err(|_| ApiError::Database)?;
            return Err(ApiError::WorkspaceQuotaExceeded);
        }
        sqlx::query(
            "INSERT INTO workspace_documents
                (id, account_id, row_version, last_revision, draft_revision,
                 published_revision, deleted_at, created_at, updated_at)
             VALUES ($1, $2, 1, 0, NULL, NULL, NULL, $3, $3)",
        )
        .bind(&document_id)
        .bind(account_id)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        insert_revision_tx(
            &mut tx,
            account_id,
            device_id,
            &document_id,
            1,
            &name,
            request.program_kind,
            &envelope,
            now,
        )
        .await?;
        sqlx::query(
            "UPDATE workspace_documents
             SET last_revision = 1, draft_revision = 1
             WHERE account_id = $1 AND id = $2",
        )
        .bind(account_id)
        .bind(&document_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        let new_usage_bytes = usage
            .revision_plaintext_bytes
            .saturating_add(envelope.plaintext_bytes);
        sqlx::query(
            "UPDATE workspace_storage_usage
             SET active_document_count = active_document_count + 1,
                 revision_plaintext_bytes = $2, row_version = row_version + 1, updated_at = $3
             WHERE account_id = $1",
        )
        .bind(account_id)
        .bind(new_usage_bytes)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        let metadata = BTreeMap::from([
            ("document_id".to_owned(), document_id.clone()),
            ("revision".to_owned(), "1".to_owned()),
            ("row_version".to_owned(), "1".to_owned()),
        ]);
        let cursor = insert_change_tx(
            &mut tx,
            account_id,
            device_id,
            &request.operation_id,
            "configuration_created",
            "shared_configuration",
            &document_id,
            1,
            now,
            &metadata,
        )
        .await?;
        record_alert_event_tx(
            &mut tx,
            account_id,
            device_id,
            &request.operation_id,
            &ServerWorkspaceAlertEvent {
                event_kind: WorkspaceAlertEventKind::ConfigurationCreated,
                dedupe_key: format!("configuration:{document_id}:created:1"),
                summary: "A shared configuration was created.".to_owned(),
                metadata: metadata.clone(),
            },
            now,
        )
        .await?;
        maybe_record_quota_warning_tx(
            &mut tx,
            account_id,
            device_id,
            &request.operation_id,
            new_usage_bytes,
            now,
        )
        .await?;
        insert_workspace_audit_tx(
            &mut tx,
            "workspace_configuration_created",
            "succeeded",
            account_id,
            device_id,
            None,
            now,
            metadata,
        )
        .await?;
        let receipt = WorkspaceMutationReceipt {
            resource_type: "shared_configuration".to_owned(),
            resource_id: document_id,
            row_version: 1,
            cursor: Some(cursor),
        };
        insert_operation_tx(
            &mut tx,
            account_id,
            device_id,
            &request.operation_id,
            "shared.create",
            &request_sha256,
            "succeeded",
            &receipt,
            now,
        )
        .await?;
        enqueue_workspace_webhook_tx(
            &mut tx,
            account_id,
            "configuration.created",
            serde_json::json!({
                "documentId": &receipt.resource_id,
                "rowVersion": receipt.row_version,
                "revision": 1,
            }),
            now,
        )
        .await?;
        require_permissions_tx(&mut tx, account_id, device_id, &["shared.write"], now).await?;
        tx.commit().await.map_err(|_| ApiError::Database)?;
        Ok(receipt)
    }

    pub async fn revise_shared_configuration(
        &self,
        account_id: &str,
        device_id: &str,
        document_id: &str,
        request: ReviseSharedConfiguration,
        now: i64,
    ) -> Result<WorkspaceMutationReceipt> {
        validate_resource_id(document_id)?;
        if request.base_row_version == 0 {
            return Err(ApiError::InvalidRequest);
        }
        let (name, input) = validate_configuration_input(
            &request.name,
            &request.input,
            request.content.as_bytes(),
        )?;
        validate_operation_id(&request.operation_id)?;
        let request_sha256 = request_digest("shared.revise", &request)?;
        let mut tx = self.pool.begin().await.map_err(|_| ApiError::Database)?;
        require_permissions_tx(&mut tx, account_id, device_id, &["shared.write"], now).await?;
        if let Some(receipt) = claim_operation_tx(
            &mut tx,
            account_id,
            device_id,
            &request.operation_id,
            "shared.revise",
            &request_sha256,
        )
        .await?
        {
            tx.commit().await.map_err(|_| ApiError::Database)?;
            return Ok(receipt);
        }
        let row = lock_document_tx(&mut tx, account_id, document_id).await?;
        let current_row_version =
            positive_u64(row.try_get("row_version").map_err(|_| ApiError::Database)?)?;
        let deleted_at: Option<i64> = row.try_get("deleted_at").map_err(|_| ApiError::Database)?;
        if current_row_version != request.base_row_version || deleted_at.is_some() {
            record_version_conflict_tx(
                &mut tx,
                account_id,
                device_id,
                document_id,
                current_row_version,
                &request.operation_id,
                "shared.revise",
                &request_sha256,
                now,
            )
            .await?;
            require_permissions_tx(&mut tx, account_id, device_id, &["shared.write"], now).await?;
            tx.commit().await.map_err(|_| ApiError::Database)?;
            return Err(ApiError::WorkspaceVersionConflict);
        }
        let current_revision = nonnegative_u64(
            row.try_get("last_revision")
                .map_err(|_| ApiError::Database)?,
        )?;
        let revision = current_revision
            .checked_add(1)
            .ok_or(ApiError::InvalidRequest)?;
        let payload = encode_configuration_payload(&input, &request.content)?;
        let envelope = self.keyring.seal(
            account_id,
            document_id,
            revision,
            &payload,
            request.content.as_bytes(),
        )?;
        let usage = lock_storage_usage_tx(&mut tx, account_id, now).await?;
        if usage
            .revision_plaintext_bytes
            .saturating_add(envelope.plaintext_bytes)
            > MAX_WORKSPACE_PLAINTEXT_BYTES
        {
            record_limit_failure_for_resource_tx(
                &mut tx,
                account_id,
                device_id,
                &request.operation_id,
                "shared.revise",
                &request_sha256,
                "quota_exceeded",
                "shared_configuration",
                document_id,
                current_row_version,
                now,
            )
            .await?;
            require_permissions_tx(&mut tx, account_id, device_id, &["shared.write"], now).await?;
            tx.commit().await.map_err(|_| ApiError::Database)?;
            return Err(ApiError::WorkspaceQuotaExceeded);
        }
        insert_revision_tx(
            &mut tx,
            account_id,
            device_id,
            document_id,
            revision,
            &name,
            request.program_kind,
            &envelope,
            now,
        )
        .await?;
        let next_row_version = current_row_version.saturating_add(1);
        sqlx::query(
            "UPDATE workspace_documents
             SET last_revision = $3, draft_revision = $3,
                 row_version = row_version + 1, updated_at = $4
             WHERE account_id = $1 AND id = $2 AND row_version = $5 AND deleted_at IS NULL",
        )
        .bind(account_id)
        .bind(document_id)
        .bind(u64_to_i64(revision)?)
        .bind(now)
        .bind(u64_to_i64(current_row_version)?)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        let new_usage_bytes = usage
            .revision_plaintext_bytes
            .saturating_add(envelope.plaintext_bytes);
        sqlx::query(
            "UPDATE workspace_storage_usage
             SET revision_plaintext_bytes = $2, row_version = row_version + 1, updated_at = $3
             WHERE account_id = $1",
        )
        .bind(account_id)
        .bind(new_usage_bytes)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        let metadata = BTreeMap::from([
            ("document_id".to_owned(), document_id.to_owned()),
            ("revision".to_owned(), revision.to_string()),
            ("row_version".to_owned(), next_row_version.to_string()),
        ]);
        let cursor = insert_change_tx(
            &mut tx,
            account_id,
            device_id,
            &request.operation_id,
            "configuration_revised",
            "shared_configuration",
            document_id,
            next_row_version,
            now,
            &metadata,
        )
        .await?;
        record_alert_event_tx(
            &mut tx,
            account_id,
            device_id,
            &request.operation_id,
            &ServerWorkspaceAlertEvent {
                event_kind: WorkspaceAlertEventKind::ConfigurationRevised,
                dedupe_key: format!("configuration:{document_id}:revision:{revision}"),
                summary: "A shared configuration was revised.".to_owned(),
                metadata: metadata.clone(),
            },
            now,
        )
        .await?;
        maybe_record_quota_warning_tx(
            &mut tx,
            account_id,
            device_id,
            &request.operation_id,
            new_usage_bytes,
            now,
        )
        .await?;
        insert_workspace_audit_tx(
            &mut tx,
            "workspace_configuration_revised",
            "succeeded",
            account_id,
            device_id,
            None,
            now,
            metadata,
        )
        .await?;
        let receipt = WorkspaceMutationReceipt {
            resource_type: "shared_configuration".to_owned(),
            resource_id: document_id.to_owned(),
            row_version: next_row_version,
            cursor: Some(cursor),
        };
        insert_operation_tx(
            &mut tx,
            account_id,
            device_id,
            &request.operation_id,
            "shared.revise",
            &request_sha256,
            "succeeded",
            &receipt,
            now,
        )
        .await?;
        enqueue_workspace_webhook_tx(
            &mut tx,
            account_id,
            "configuration.revised",
            serde_json::json!({
                "documentId": &receipt.resource_id,
                "rowVersion": receipt.row_version,
                "revision": revision,
            }),
            now,
        )
        .await?;
        require_permissions_tx(&mut tx, account_id, device_id, &["shared.write"], now).await?;
        tx.commit().await.map_err(|_| ApiError::Database)?;
        Ok(receipt)
    }

    pub async fn publish_shared_configuration(
        &self,
        account_id: &str,
        device_id: &str,
        document_id: &str,
        request: PublishSharedConfiguration,
        now: i64,
    ) -> Result<WorkspaceMutationReceipt> {
        validate_resource_id(document_id)?;
        if request.base_row_version == 0 || request.revision == Some(0) {
            return Err(ApiError::InvalidRequest);
        }
        validate_operation_id(&request.operation_id)?;
        let request_sha256 = request_digest("shared.publish", &request)?;
        let mut tx = self.pool.begin().await.map_err(|_| ApiError::Database)?;
        require_permissions_tx(&mut tx, account_id, device_id, &["shared.publish"], now).await?;
        if let Some(receipt) = claim_operation_tx(
            &mut tx,
            account_id,
            device_id,
            &request.operation_id,
            "shared.publish",
            &request_sha256,
        )
        .await?
        {
            tx.commit().await.map_err(|_| ApiError::Database)?;
            return Ok(receipt);
        }
        let row = lock_document_tx(&mut tx, account_id, document_id).await?;
        let current_row_version =
            positive_u64(row.try_get("row_version").map_err(|_| ApiError::Database)?)?;
        let deleted_at: Option<i64> = row.try_get("deleted_at").map_err(|_| ApiError::Database)?;
        if current_row_version != request.base_row_version || deleted_at.is_some() {
            record_version_conflict_tx(
                &mut tx,
                account_id,
                device_id,
                document_id,
                current_row_version,
                &request.operation_id,
                "shared.publish",
                &request_sha256,
                now,
            )
            .await?;
            require_permissions_tx(&mut tx, account_id, device_id, &["shared.publish"], now)
                .await?;
            tx.commit().await.map_err(|_| ApiError::Database)?;
            return Err(ApiError::WorkspaceVersionConflict);
        }
        let draft_revision = positive_u64(
            row.try_get("draft_revision")
                .map_err(|_| ApiError::Database)?,
        )?;
        let revision = request.revision.unwrap_or(draft_revision);
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(
                 SELECT 1 FROM workspace_document_revisions
                 WHERE account_id = $1 AND document_id = $2 AND revision = $3
             )",
        )
        .bind(account_id)
        .bind(document_id)
        .bind(u64_to_i64(revision)?)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        if !exists {
            return Err(ApiError::WorkspaceNotFound);
        }
        let next_row_version = current_row_version.saturating_add(1);
        sqlx::query(
            "UPDATE workspace_documents
             SET published_revision = $3, row_version = row_version + 1, updated_at = $4
             WHERE account_id = $1 AND id = $2 AND row_version = $5 AND deleted_at IS NULL",
        )
        .bind(account_id)
        .bind(document_id)
        .bind(u64_to_i64(revision)?)
        .bind(now)
        .bind(u64_to_i64(current_row_version)?)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        let metadata = BTreeMap::from([
            ("document_id".to_owned(), document_id.to_owned()),
            ("revision".to_owned(), revision.to_string()),
            ("row_version".to_owned(), next_row_version.to_string()),
        ]);
        let cursor = insert_change_tx(
            &mut tx,
            account_id,
            device_id,
            &request.operation_id,
            "configuration_published",
            "shared_configuration",
            document_id,
            next_row_version,
            now,
            &metadata,
        )
        .await?;
        record_alert_event_tx(
            &mut tx,
            account_id,
            device_id,
            &request.operation_id,
            &ServerWorkspaceAlertEvent {
                event_kind: WorkspaceAlertEventKind::ConfigurationPublished,
                dedupe_key: format!("configuration:{document_id}:published:{revision}"),
                summary: "A shared configuration revision was published.".to_owned(),
                metadata: metadata.clone(),
            },
            now,
        )
        .await?;
        insert_workspace_audit_tx(
            &mut tx,
            "workspace_configuration_published",
            "succeeded",
            account_id,
            device_id,
            None,
            now,
            metadata,
        )
        .await?;
        let receipt = WorkspaceMutationReceipt {
            resource_type: "shared_configuration".to_owned(),
            resource_id: document_id.to_owned(),
            row_version: next_row_version,
            cursor: Some(cursor),
        };
        insert_operation_tx(
            &mut tx,
            account_id,
            device_id,
            &request.operation_id,
            "shared.publish",
            &request_sha256,
            "succeeded",
            &receipt,
            now,
        )
        .await?;
        enqueue_workspace_webhook_tx(
            &mut tx,
            account_id,
            "configuration.published",
            serde_json::json!({
                "documentId": &receipt.resource_id,
                "rowVersion": receipt.row_version,
                "revision": revision,
            }),
            now,
        )
        .await?;
        require_permissions_tx(&mut tx, account_id, device_id, &["shared.publish"], now).await?;
        tx.commit().await.map_err(|_| ApiError::Database)?;
        Ok(receipt)
    }

    pub async fn delete_shared_configuration(
        &self,
        account_id: &str,
        device_id: &str,
        document_id: &str,
        request: VersionedWorkspaceMutation,
        now: i64,
    ) -> Result<WorkspaceMutationReceipt> {
        self.set_shared_configuration_deleted(
            account_id,
            device_id,
            document_id,
            request,
            true,
            now,
        )
        .await
    }

    pub async fn restore_shared_configuration(
        &self,
        account_id: &str,
        device_id: &str,
        document_id: &str,
        request: VersionedWorkspaceMutation,
        now: i64,
    ) -> Result<WorkspaceMutationReceipt> {
        self.set_shared_configuration_deleted(
            account_id,
            device_id,
            document_id,
            request,
            false,
            now,
        )
        .await
    }

    async fn set_shared_configuration_deleted(
        &self,
        account_id: &str,
        device_id: &str,
        document_id: &str,
        request: VersionedWorkspaceMutation,
        delete: bool,
        now: i64,
    ) -> Result<WorkspaceMutationReceipt> {
        validate_resource_id(document_id)?;
        if request.base_row_version == 0 {
            return Err(ApiError::InvalidRequest);
        }
        validate_operation_id(&request.operation_id)?;
        let action = if delete {
            "shared.delete"
        } else {
            "shared.restore"
        };
        let request_sha256 = request_digest(action, &request)?;
        let mut tx = self.pool.begin().await.map_err(|_| ApiError::Database)?;
        require_permissions_tx(&mut tx, account_id, device_id, &["shared.write"], now).await?;
        if let Some(receipt) = claim_operation_tx(
            &mut tx,
            account_id,
            device_id,
            &request.operation_id,
            action,
            &request_sha256,
        )
        .await?
        {
            tx.commit().await.map_err(|_| ApiError::Database)?;
            return Ok(receipt);
        }
        let row = lock_document_tx(&mut tx, account_id, document_id).await?;
        let current_row_version =
            positive_u64(row.try_get("row_version").map_err(|_| ApiError::Database)?)?;
        let deleted_at: Option<i64> = row.try_get("deleted_at").map_err(|_| ApiError::Database)?;
        let expected_state = if delete {
            deleted_at.is_none()
        } else {
            deleted_at.is_some()
        };
        if current_row_version != request.base_row_version || !expected_state {
            record_version_conflict_tx(
                &mut tx,
                account_id,
                device_id,
                document_id,
                current_row_version,
                &request.operation_id,
                action,
                &request_sha256,
                now,
            )
            .await?;
            require_permissions_tx(&mut tx, account_id, device_id, &["shared.write"], now).await?;
            tx.commit().await.map_err(|_| ApiError::Database)?;
            return Err(ApiError::WorkspaceVersionConflict);
        }
        let usage = lock_storage_usage_tx(&mut tx, account_id, now).await?;
        if !delete && usage.active_document_count >= MAX_ACTIVE_DOCUMENTS {
            record_limit_failure_for_resource_tx(
                &mut tx,
                account_id,
                device_id,
                &request.operation_id,
                action,
                &request_sha256,
                "document_limit",
                "shared_configuration",
                document_id,
                current_row_version,
                now,
            )
            .await?;
            require_permissions_tx(&mut tx, account_id, device_id, &["shared.write"], now).await?;
            tx.commit().await.map_err(|_| ApiError::Database)?;
            return Err(ApiError::WorkspaceDocumentLimitReached);
        }
        if delete && usage.active_document_count <= 0 {
            return Err(ApiError::Database);
        }
        let next_row_version = current_row_version.saturating_add(1);
        sqlx::query(
            "UPDATE workspace_documents
             SET deleted_at = $3, row_version = row_version + 1, updated_at = $4
             WHERE account_id = $1 AND id = $2 AND row_version = $5",
        )
        .bind(account_id)
        .bind(document_id)
        .bind(if delete { Some(now) } else { None })
        .bind(now)
        .bind(u64_to_i64(current_row_version)?)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        let active_count = if delete {
            usage.active_document_count - 1
        } else {
            usage.active_document_count + 1
        };
        sqlx::query(
            "UPDATE workspace_storage_usage
             SET active_document_count = $2, row_version = row_version + 1, updated_at = $3
             WHERE account_id = $1",
        )
        .bind(account_id)
        .bind(active_count)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        let (change_kind, event_kind, audit_type, summary) = if delete {
            (
                "configuration_deleted",
                WorkspaceAlertEventKind::ConfigurationDeleted,
                "workspace_configuration_deleted",
                "A shared configuration was deleted.",
            )
        } else {
            (
                "configuration_restored",
                WorkspaceAlertEventKind::ConfigurationRestored,
                "workspace_configuration_restored",
                "A shared configuration was restored.",
            )
        };
        let metadata = BTreeMap::from([
            ("document_id".to_owned(), document_id.to_owned()),
            ("row_version".to_owned(), next_row_version.to_string()),
        ]);
        let cursor = insert_change_tx(
            &mut tx,
            account_id,
            device_id,
            &request.operation_id,
            change_kind,
            "shared_configuration",
            document_id,
            next_row_version,
            now,
            &metadata,
        )
        .await?;
        record_alert_event_tx(
            &mut tx,
            account_id,
            device_id,
            &request.operation_id,
            &ServerWorkspaceAlertEvent {
                event_kind,
                dedupe_key: format!("configuration:{document_id}:{change_kind}:{next_row_version}"),
                summary: summary.to_owned(),
                metadata: metadata.clone(),
            },
            now,
        )
        .await?;
        insert_workspace_audit_tx(
            &mut tx,
            audit_type,
            "succeeded",
            account_id,
            device_id,
            None,
            now,
            metadata,
        )
        .await?;
        let receipt = WorkspaceMutationReceipt {
            resource_type: "shared_configuration".to_owned(),
            resource_id: document_id.to_owned(),
            row_version: next_row_version,
            cursor: Some(cursor),
        };
        insert_operation_tx(
            &mut tx,
            account_id,
            device_id,
            &request.operation_id,
            action,
            &request_sha256,
            "succeeded",
            &receipt,
            now,
        )
        .await?;
        enqueue_workspace_webhook_tx(
            &mut tx,
            account_id,
            if delete {
                "configuration.deleted"
            } else {
                "configuration.restored"
            },
            serde_json::json!({
                "documentId": &receipt.resource_id,
                "rowVersion": receipt.row_version,
            }),
            now,
        )
        .await?;
        require_permissions_tx(&mut tx, account_id, device_id, &["shared.write"], now).await?;
        tx.commit().await.map_err(|_| ApiError::Database)?;
        Ok(receipt)
    }

    pub async fn advance_device_checkpoint(
        &self,
        account_id: &str,
        device_id: &str,
        request: AdvanceWorkspaceCheckpoint,
        now: i64,
    ) -> Result<WorkspaceMutationReceipt> {
        validate_operation_id(&request.operation_id)?;
        let request_sha256 = request_digest("sync.checkpoint", &request)?;
        let requested_cursor = u64_to_i64(request.cursor)?;
        let mut tx = self.pool.begin().await.map_err(|_| ApiError::Database)?;
        require_permissions_tx(&mut tx, account_id, device_id, &["sync.write"], now).await?;
        if let Some(receipt) = claim_operation_tx(
            &mut tx,
            account_id,
            device_id,
            &request.operation_id,
            "sync.checkpoint",
            &request_sha256,
        )
        .await?
        {
            tx.commit().await.map_err(|_| ApiError::Database)?;
            return Ok(receipt);
        }
        let checkpoint = sqlx::query(
            "SELECT cursor, row_version FROM workspace_device_checkpoints
             WHERE account_id = $1 AND device_id = $2 FOR UPDATE",
        )
        .bind(account_id)
        .bind(device_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        let (current_cursor, current_row_version) = checkpoint
            .as_ref()
            .map(|row| {
                Ok::<_, ApiError>((
                    nonnegative_u64(row.try_get("cursor").map_err(|_| ApiError::Database)?)?,
                    positive_u64(row.try_get("row_version").map_err(|_| ApiError::Database)?)?,
                ))
            })
            .transpose()?
            .unwrap_or((0, 0));
        if current_row_version != request.base_row_version || request.cursor < current_cursor {
            record_generic_version_conflict_tx(
                &mut tx,
                account_id,
                device_id,
                "device_checkpoint",
                device_id,
                current_row_version,
                &request.operation_id,
                "sync.checkpoint",
                &request_sha256,
                now,
            )
            .await?;
            require_permissions_tx(&mut tx, account_id, device_id, &["sync.write"], now).await?;
            tx.commit().await.map_err(|_| ApiError::Database)?;
            return Err(ApiError::WorkspaceVersionConflict);
        }
        let maximum_cursor: i64 = sqlx::query_scalar(
            "SELECT COALESCE(MAX(cursor), 0) FROM workspace_changes WHERE account_id = $1",
        )
        .bind(account_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        if requested_cursor > maximum_cursor {
            return Err(ApiError::InvalidRequest);
        }
        let next_row_version = current_row_version.saturating_add(1);
        if checkpoint.is_some() {
            sqlx::query(
                "UPDATE workspace_device_checkpoints
                 SET cursor = $3, row_version = row_version + 1, updated_at = $4
                 WHERE account_id = $1 AND device_id = $2 AND row_version = $5",
            )
            .bind(account_id)
            .bind(device_id)
            .bind(requested_cursor)
            .bind(now)
            .bind(u64_to_i64(current_row_version)?)
            .execute(&mut *tx)
            .await
            .map_err(|_| ApiError::Database)?;
        } else {
            sqlx::query(
                "INSERT INTO workspace_device_checkpoints
                    (account_id, device_id, cursor, row_version, updated_at)
                 VALUES ($1, $2, $3, 1, $4)",
            )
            .bind(account_id)
            .bind(device_id)
            .bind(requested_cursor)
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(|_| ApiError::Database)?;
        }
        let metadata = BTreeMap::from([
            ("cursor".to_owned(), request.cursor.to_string()),
            ("row_version".to_owned(), next_row_version.to_string()),
        ]);
        insert_workspace_audit_tx(
            &mut tx,
            "workspace_sync_checkpoint_advanced",
            "succeeded",
            account_id,
            device_id,
            None,
            now,
            metadata,
        )
        .await?;
        let receipt = WorkspaceMutationReceipt {
            resource_type: "device_checkpoint".to_owned(),
            resource_id: device_id.to_owned(),
            row_version: next_row_version,
            cursor: Some(request.cursor),
        };
        insert_operation_tx(
            &mut tx,
            account_id,
            device_id,
            &request.operation_id,
            "sync.checkpoint",
            &request_sha256,
            "succeeded",
            &receipt,
            now,
        )
        .await?;
        require_permissions_tx(&mut tx, account_id, device_id, &["sync.write"], now).await?;
        tx.commit().await.map_err(|_| ApiError::Database)?;
        Ok(receipt)
    }

    pub async fn create_alert_rule(
        &self,
        account_id: &str,
        device_id: &str,
        request: CreateWorkspaceAlertRule,
        now: i64,
    ) -> Result<WorkspaceMutationReceipt> {
        let name = validate_name(&request.name)?;
        validate_operation_id(&request.operation_id)?;
        let request_sha256 = request_digest("alerts.rule.create", &request)?;
        let rule_id = random_id("alert_rule");
        let mut tx = self.pool.begin().await.map_err(|_| ApiError::Database)?;
        require_permissions_tx(&mut tx, account_id, device_id, &["alerts.manage"], now).await?;
        if let Some(receipt) = claim_operation_tx(
            &mut tx,
            account_id,
            device_id,
            &request.operation_id,
            "alerts.rule.create",
            &request_sha256,
        )
        .await?
        {
            tx.commit().await.map_err(|_| ApiError::Database)?;
            return Ok(receipt);
        }
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 7252026))")
            .bind(account_id)
            .execute(&mut *tx)
            .await
            .map_err(|_| ApiError::Database)?;
        let active_rules: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM workspace_alert_rules
             WHERE account_id = $1 AND deleted_at IS NULL",
        )
        .bind(account_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        if active_rules >= i64::from(MAX_ALERT_RULES) {
            record_alert_rule_limit_tx(
                &mut tx,
                account_id,
                device_id,
                &request.operation_id,
                &request_sha256,
                now,
            )
            .await?;
            require_permissions_tx(&mut tx, account_id, device_id, &["alerts.manage"], now).await?;
            tx.commit().await.map_err(|_| ApiError::Database)?;
            return Err(ApiError::WorkspaceAlertRuleLimitReached);
        }
        sqlx::query(
            "INSERT INTO workspace_alert_rules
                (id, account_id, name, event_kind, severity, enabled, row_version,
                 deleted_at, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, 1, NULL, $7, $7)",
        )
        .bind(&rule_id)
        .bind(account_id)
        .bind(name)
        .bind(alert_event_kind_name(request.event_kind))
        .bind(alert_severity_name(request.severity))
        .bind(request.enabled)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        let metadata = BTreeMap::from([
            ("rule_id".to_owned(), rule_id.clone()),
            (
                "event_kind".to_owned(),
                alert_event_kind_name(request.event_kind).to_owned(),
            ),
            (
                "severity".to_owned(),
                alert_severity_name(request.severity).to_owned(),
            ),
            ("row_version".to_owned(), "1".to_owned()),
        ]);
        let cursor = insert_change_tx(
            &mut tx,
            account_id,
            device_id,
            &request.operation_id,
            "alert_rule_created",
            "alert_rule",
            &rule_id,
            1,
            now,
            &metadata,
        )
        .await?;
        insert_workspace_audit_tx(
            &mut tx,
            "workspace_alert_rule_created",
            "succeeded",
            account_id,
            device_id,
            None,
            now,
            metadata,
        )
        .await?;
        let receipt = WorkspaceMutationReceipt {
            resource_type: "alert_rule".to_owned(),
            resource_id: rule_id,
            row_version: 1,
            cursor: Some(cursor),
        };
        insert_operation_tx(
            &mut tx,
            account_id,
            device_id,
            &request.operation_id,
            "alerts.rule.create",
            &request_sha256,
            "succeeded",
            &receipt,
            now,
        )
        .await?;
        require_permissions_tx(&mut tx, account_id, device_id, &["alerts.manage"], now).await?;
        tx.commit().await.map_err(|_| ApiError::Database)?;
        Ok(receipt)
    }

    pub async fn update_alert_rule(
        &self,
        account_id: &str,
        device_id: &str,
        rule_id: &str,
        request: UpdateWorkspaceAlertRule,
        now: i64,
    ) -> Result<WorkspaceMutationReceipt> {
        validate_resource_id(rule_id)?;
        if request.base_row_version == 0 {
            return Err(ApiError::InvalidRequest);
        }
        let name = validate_name(&request.name)?;
        validate_operation_id(&request.operation_id)?;
        let request_sha256 = request_digest("alerts.rule.update", &request)?;
        let mut tx = self.pool.begin().await.map_err(|_| ApiError::Database)?;
        require_permissions_tx(&mut tx, account_id, device_id, &["alerts.manage"], now).await?;
        if let Some(receipt) = claim_operation_tx(
            &mut tx,
            account_id,
            device_id,
            &request.operation_id,
            "alerts.rule.update",
            &request_sha256,
        )
        .await?
        {
            tx.commit().await.map_err(|_| ApiError::Database)?;
            return Ok(receipt);
        }
        let row = lock_alert_rule_tx(&mut tx, account_id, rule_id).await?;
        let current_row_version =
            positive_u64(row.try_get("row_version").map_err(|_| ApiError::Database)?)?;
        let deleted_at: Option<i64> = row.try_get("deleted_at").map_err(|_| ApiError::Database)?;
        if current_row_version != request.base_row_version || deleted_at.is_some() {
            record_generic_version_conflict_tx(
                &mut tx,
                account_id,
                device_id,
                "alert_rule",
                rule_id,
                current_row_version,
                &request.operation_id,
                "alerts.rule.update",
                &request_sha256,
                now,
            )
            .await?;
            require_permissions_tx(&mut tx, account_id, device_id, &["alerts.manage"], now).await?;
            tx.commit().await.map_err(|_| ApiError::Database)?;
            return Err(ApiError::WorkspaceVersionConflict);
        }
        let next_row_version = current_row_version.saturating_add(1);
        sqlx::query(
            "UPDATE workspace_alert_rules
             SET name = $3, event_kind = $4, severity = $5, enabled = $6,
                 row_version = row_version + 1, updated_at = $7
             WHERE account_id = $1 AND id = $2 AND row_version = $8 AND deleted_at IS NULL",
        )
        .bind(account_id)
        .bind(rule_id)
        .bind(name)
        .bind(alert_event_kind_name(request.event_kind))
        .bind(alert_severity_name(request.severity))
        .bind(request.enabled)
        .bind(now)
        .bind(u64_to_i64(current_row_version)?)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        let metadata = BTreeMap::from([
            ("rule_id".to_owned(), rule_id.to_owned()),
            (
                "event_kind".to_owned(),
                alert_event_kind_name(request.event_kind).to_owned(),
            ),
            (
                "severity".to_owned(),
                alert_severity_name(request.severity).to_owned(),
            ),
            ("row_version".to_owned(), next_row_version.to_string()),
        ]);
        let cursor = insert_change_tx(
            &mut tx,
            account_id,
            device_id,
            &request.operation_id,
            "alert_rule_updated",
            "alert_rule",
            rule_id,
            next_row_version,
            now,
            &metadata,
        )
        .await?;
        insert_workspace_audit_tx(
            &mut tx,
            "workspace_alert_rule_updated",
            "succeeded",
            account_id,
            device_id,
            None,
            now,
            metadata,
        )
        .await?;
        let receipt = WorkspaceMutationReceipt {
            resource_type: "alert_rule".to_owned(),
            resource_id: rule_id.to_owned(),
            row_version: next_row_version,
            cursor: Some(cursor),
        };
        insert_operation_tx(
            &mut tx,
            account_id,
            device_id,
            &request.operation_id,
            "alerts.rule.update",
            &request_sha256,
            "succeeded",
            &receipt,
            now,
        )
        .await?;
        require_permissions_tx(&mut tx, account_id, device_id, &["alerts.manage"], now).await?;
        tx.commit().await.map_err(|_| ApiError::Database)?;
        Ok(receipt)
    }

    pub async fn delete_alert_rule(
        &self,
        account_id: &str,
        device_id: &str,
        rule_id: &str,
        request: VersionedWorkspaceMutation,
        now: i64,
    ) -> Result<WorkspaceMutationReceipt> {
        validate_resource_id(rule_id)?;
        if request.base_row_version == 0 {
            return Err(ApiError::InvalidRequest);
        }
        validate_operation_id(&request.operation_id)?;
        let request_sha256 = request_digest("alerts.rule.delete", &request)?;
        let mut tx = self.pool.begin().await.map_err(|_| ApiError::Database)?;
        require_permissions_tx(&mut tx, account_id, device_id, &["alerts.manage"], now).await?;
        if let Some(receipt) = claim_operation_tx(
            &mut tx,
            account_id,
            device_id,
            &request.operation_id,
            "alerts.rule.delete",
            &request_sha256,
        )
        .await?
        {
            tx.commit().await.map_err(|_| ApiError::Database)?;
            return Ok(receipt);
        }
        let row = lock_alert_rule_tx(&mut tx, account_id, rule_id).await?;
        let current_row_version =
            positive_u64(row.try_get("row_version").map_err(|_| ApiError::Database)?)?;
        let deleted_at: Option<i64> = row.try_get("deleted_at").map_err(|_| ApiError::Database)?;
        if current_row_version != request.base_row_version || deleted_at.is_some() {
            record_generic_version_conflict_tx(
                &mut tx,
                account_id,
                device_id,
                "alert_rule",
                rule_id,
                current_row_version,
                &request.operation_id,
                "alerts.rule.delete",
                &request_sha256,
                now,
            )
            .await?;
            require_permissions_tx(&mut tx, account_id, device_id, &["alerts.manage"], now).await?;
            tx.commit().await.map_err(|_| ApiError::Database)?;
            return Err(ApiError::WorkspaceVersionConflict);
        }
        let next_row_version = current_row_version.saturating_add(1);
        sqlx::query(
            "UPDATE workspace_alert_rules
             SET deleted_at = $3, enabled = false, row_version = row_version + 1, updated_at = $3
             WHERE account_id = $1 AND id = $2 AND row_version = $4 AND deleted_at IS NULL",
        )
        .bind(account_id)
        .bind(rule_id)
        .bind(now)
        .bind(u64_to_i64(current_row_version)?)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        let metadata = BTreeMap::from([
            ("rule_id".to_owned(), rule_id.to_owned()),
            ("row_version".to_owned(), next_row_version.to_string()),
        ]);
        let cursor = insert_change_tx(
            &mut tx,
            account_id,
            device_id,
            &request.operation_id,
            "alert_rule_deleted",
            "alert_rule",
            rule_id,
            next_row_version,
            now,
            &metadata,
        )
        .await?;
        insert_workspace_audit_tx(
            &mut tx,
            "workspace_alert_rule_deleted",
            "succeeded",
            account_id,
            device_id,
            None,
            now,
            metadata,
        )
        .await?;
        let receipt = WorkspaceMutationReceipt {
            resource_type: "alert_rule".to_owned(),
            resource_id: rule_id.to_owned(),
            row_version: next_row_version,
            cursor: Some(cursor),
        };
        insert_operation_tx(
            &mut tx,
            account_id,
            device_id,
            &request.operation_id,
            "alerts.rule.delete",
            &request_sha256,
            "succeeded",
            &receipt,
            now,
        )
        .await?;
        require_permissions_tx(&mut tx, account_id, device_id, &["alerts.manage"], now).await?;
        tx.commit().await.map_err(|_| ApiError::Database)?;
        Ok(receipt)
    }

    pub async fn acknowledge_incident(
        &self,
        account_id: &str,
        device_id: &str,
        incident_id: &str,
        request: VersionedWorkspaceMutation,
        now: i64,
    ) -> Result<WorkspaceMutationReceipt> {
        self.transition_incident(
            account_id,
            device_id,
            incident_id,
            request,
            WorkspaceIncidentStatus::Acknowledged,
            now,
        )
        .await
    }

    pub async fn resolve_incident(
        &self,
        account_id: &str,
        device_id: &str,
        incident_id: &str,
        request: VersionedWorkspaceMutation,
        now: i64,
    ) -> Result<WorkspaceMutationReceipt> {
        self.transition_incident(
            account_id,
            device_id,
            incident_id,
            request,
            WorkspaceIncidentStatus::Resolved,
            now,
        )
        .await
    }

    async fn transition_incident(
        &self,
        account_id: &str,
        device_id: &str,
        incident_id: &str,
        request: VersionedWorkspaceMutation,
        target: WorkspaceIncidentStatus,
        now: i64,
    ) -> Result<WorkspaceMutationReceipt> {
        validate_resource_id(incident_id)?;
        if request.base_row_version == 0 {
            return Err(ApiError::InvalidRequest);
        }
        validate_operation_id(&request.operation_id)?;
        let (action, required_status, change_kind, audit_type, permission) = match target {
            WorkspaceIncidentStatus::Acknowledged => (
                "alerts.incident.acknowledge",
                WorkspaceIncidentStatus::Open,
                "alert_incident_acknowledged",
                "workspace_alert_incident_acknowledged",
                "alerts.ack",
            ),
            WorkspaceIncidentStatus::Resolved => (
                "alerts.incident.resolve",
                WorkspaceIncidentStatus::Acknowledged,
                "alert_incident_resolved",
                "workspace_alert_incident_resolved",
                "alerts.manage",
            ),
            WorkspaceIncidentStatus::Open => return Err(ApiError::InvalidRequest),
        };
        let request_sha256 = request_digest(action, &request)?;
        let mut tx = self.pool.begin().await.map_err(|_| ApiError::Database)?;
        require_permissions_tx(&mut tx, account_id, device_id, &[permission], now).await?;
        if let Some(receipt) = claim_operation_tx(
            &mut tx,
            account_id,
            device_id,
            &request.operation_id,
            action,
            &request_sha256,
        )
        .await?
        {
            tx.commit().await.map_err(|_| ApiError::Database)?;
            return Ok(receipt);
        }
        let row = sqlx::query(
            "SELECT status, row_version FROM workspace_alert_incidents
             WHERE account_id = $1 AND id = $2 FOR UPDATE",
        )
        .bind(account_id)
        .bind(incident_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?
        .ok_or(ApiError::WorkspaceNotFound)?;
        let current_status = parse_incident_status(
            &row.try_get::<String, _>("status")
                .map_err(|_| ApiError::Database)?,
        )?;
        let current_row_version =
            positive_u64(row.try_get("row_version").map_err(|_| ApiError::Database)?)?;
        if current_row_version != request.base_row_version || current_status != required_status {
            record_generic_version_conflict_tx(
                &mut tx,
                account_id,
                device_id,
                "alert_incident",
                incident_id,
                current_row_version,
                &request.operation_id,
                action,
                &request_sha256,
                now,
            )
            .await?;
            require_permissions_tx(&mut tx, account_id, device_id, &[permission], now).await?;
            tx.commit().await.map_err(|_| ApiError::Database)?;
            return Err(ApiError::WorkspaceVersionConflict);
        }
        let next_row_version = current_row_version.saturating_add(1);
        match target {
            WorkspaceIncidentStatus::Acknowledged => {
                sqlx::query(
                    "UPDATE workspace_alert_incidents
                     SET status = 'acknowledged', acknowledged_at = $3,
                         acknowledged_by_device_id = $4, row_version = row_version + 1
                     WHERE account_id = $1 AND id = $2 AND status = 'open' AND row_version = $5",
                )
                .bind(account_id)
                .bind(incident_id)
                .bind(now)
                .bind(device_id)
                .bind(u64_to_i64(current_row_version)?)
                .execute(&mut *tx)
                .await
                .map_err(|_| ApiError::Database)?;
            }
            WorkspaceIncidentStatus::Resolved => {
                sqlx::query(
                    "UPDATE workspace_alert_incidents
                     SET status = 'resolved', resolved_at = $3,
                         resolved_by_device_id = $4, row_version = row_version + 1
                     WHERE account_id = $1 AND id = $2 AND status = 'acknowledged'
                       AND row_version = $5",
                )
                .bind(account_id)
                .bind(incident_id)
                .bind(now)
                .bind(device_id)
                .bind(u64_to_i64(current_row_version)?)
                .execute(&mut *tx)
                .await
                .map_err(|_| ApiError::Database)?;
            }
            WorkspaceIncidentStatus::Open => return Err(ApiError::InvalidRequest),
        }
        let metadata = BTreeMap::from([
            ("incident_id".to_owned(), incident_id.to_owned()),
            ("status".to_owned(), incident_status_name(target).to_owned()),
            ("row_version".to_owned(), next_row_version.to_string()),
        ]);
        let cursor = insert_change_tx(
            &mut tx,
            account_id,
            device_id,
            &request.operation_id,
            change_kind,
            "alert_incident",
            incident_id,
            next_row_version,
            now,
            &metadata,
        )
        .await?;
        insert_workspace_audit_tx(
            &mut tx,
            audit_type,
            "succeeded",
            account_id,
            device_id,
            None,
            now,
            metadata,
        )
        .await?;
        let receipt = WorkspaceMutationReceipt {
            resource_type: "alert_incident".to_owned(),
            resource_id: incident_id.to_owned(),
            row_version: next_row_version,
            cursor: Some(cursor),
        };
        insert_operation_tx(
            &mut tx,
            account_id,
            device_id,
            &request.operation_id,
            action,
            &request_sha256,
            "succeeded",
            &receipt,
            now,
        )
        .await?;
        enqueue_workspace_webhook_tx(
            &mut tx,
            account_id,
            match target {
                WorkspaceIncidentStatus::Acknowledged => "alert.incident.acknowledged",
                WorkspaceIncidentStatus::Resolved => "alert.incident.resolved",
                WorkspaceIncidentStatus::Open => return Err(ApiError::Internal),
            },
            serde_json::json!({
                "incidentId": &receipt.resource_id,
                "rowVersion": receipt.row_version,
                "status": incident_status_name(target),
            }),
            now,
        )
        .await?;
        require_permissions_tx(&mut tx, account_id, device_id, &[permission], now).await?;
        tx.commit().await.map_err(|_| ApiError::Database)?;
        Ok(receipt)
    }

    pub async fn record_server_alert_event(
        &self,
        account_id: &str,
        device_id: &str,
        mut event: ServerWorkspaceAlertEvent,
        now: i64,
    ) -> Result<u32> {
        event.dedupe_key = validate_internal_text(&event.dedupe_key, 512)?;
        event.summary = validate_internal_text(&event.summary, 512)?;
        event.metadata = sanitize_internal_metadata(event.metadata)?;
        let operation_id = random_id("server_event");
        let permissions = ["alerts.read", "alerts.history.read"];
        let mut tx = self.pool.begin().await.map_err(|_| ApiError::Database)?;
        require_permissions_tx(&mut tx, account_id, device_id, &permissions, now).await?;
        let incident_count =
            record_alert_event_tx(&mut tx, account_id, device_id, &operation_id, &event, now)
                .await?;
        insert_workspace_audit_tx(
            &mut tx,
            "workspace_server_alert_event_received",
            "succeeded",
            account_id,
            device_id,
            None,
            now,
            BTreeMap::from([
                (
                    "event_kind".to_owned(),
                    alert_event_kind_name(event.event_kind).to_owned(),
                ),
                ("incident_count".to_owned(), incident_count.to_string()),
            ]),
        )
        .await?;
        require_permissions_tx(&mut tx, account_id, device_id, &permissions, now).await?;
        tx.commit().await.map_err(|_| ApiError::Database)?;
        Ok(incident_count)
    }

    pub async fn purge_shared_configuration(
        &self,
        account_id: &str,
        device_id: &str,
        document_id: &str,
        request: VersionedWorkspaceMutation,
        now: i64,
    ) -> Result<WorkspaceMutationReceipt> {
        validate_resource_id(document_id)?;
        if request.base_row_version == 0 {
            return Err(ApiError::InvalidRequest);
        }
        validate_operation_id(&request.operation_id)?;
        let request_sha256 = request_digest("shared.purge", &request)?;
        let mut tx = self.pool.begin().await.map_err(|_| ApiError::Database)?;
        require_permissions_tx(&mut tx, account_id, device_id, &["shared.purge"], now).await?;
        if let Some(receipt) = claim_operation_tx(
            &mut tx,
            account_id,
            device_id,
            &request.operation_id,
            "shared.purge",
            &request_sha256,
        )
        .await?
        {
            tx.commit().await.map_err(|_| ApiError::Database)?;
            return Ok(receipt);
        }
        let row = lock_document_tx(&mut tx, account_id, document_id).await?;
        let current_row_version =
            positive_u64(row.try_get("row_version").map_err(|_| ApiError::Database)?)?;
        let deleted_at: Option<i64> = row.try_get("deleted_at").map_err(|_| ApiError::Database)?;
        if current_row_version != request.base_row_version || deleted_at.is_none() {
            record_version_conflict_tx(
                &mut tx,
                account_id,
                device_id,
                document_id,
                current_row_version,
                &request.operation_id,
                "shared.purge",
                &request_sha256,
                now,
            )
            .await?;
            require_permissions_tx(&mut tx, account_id, device_id, &["shared.purge"], now).await?;
            tx.commit().await.map_err(|_| ApiError::Database)?;
            return Err(ApiError::WorkspaceVersionConflict);
        }
        let deleted_at = deleted_at.unwrap_or_default();
        if !configuration_retention_elapsed(deleted_at, now) {
            let metadata = BTreeMap::from([
                ("document_id".to_owned(), document_id.to_owned()),
                ("row_version".to_owned(), current_row_version.to_string()),
                ("deleted_at".to_owned(), deleted_at.to_string()),
            ]);
            insert_workspace_audit_tx(
                &mut tx,
                "workspace_configuration_purge_denied",
                "denied",
                account_id,
                device_id,
                Some("retention_active"),
                now,
                metadata,
            )
            .await?;
            insert_operation_tx(
                &mut tx,
                account_id,
                device_id,
                &request.operation_id,
                "shared.purge",
                &request_sha256,
                "retention_active",
                &WorkspaceMutationReceipt {
                    resource_type: "shared_configuration".to_owned(),
                    resource_id: document_id.to_owned(),
                    row_version: current_row_version,
                    cursor: None,
                },
                now,
            )
            .await?;
            require_permissions_tx(&mut tx, account_id, device_id, &["shared.purge"], now).await?;
            tx.commit().await.map_err(|_| ApiError::Database)?;
            return Err(ApiError::WorkspaceRetentionActive);
        }
        let usage = lock_storage_usage_tx(&mut tx, account_id, now).await?;
        let released_bytes: i64 = sqlx::query_scalar(
            "SELECT COALESCE(SUM(plaintext_bytes), 0)
             FROM workspace_document_revisions
             WHERE account_id = $1 AND document_id = $2",
        )
        .bind(account_id)
        .bind(document_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        let remaining_usage =
            remaining_usage_after_purge(usage.revision_plaintext_bytes, released_bytes)?;
        sqlx::query("DELETE FROM workspace_documents WHERE account_id = $1 AND id = $2")
            .bind(account_id)
            .bind(document_id)
            .execute(&mut *tx)
            .await
            .map_err(|_| ApiError::Database)?;
        sqlx::query(
            "UPDATE workspace_storage_usage
             SET revision_plaintext_bytes = $2,
                 row_version = row_version + 1, updated_at = $3
             WHERE account_id = $1",
        )
        .bind(account_id)
        .bind(remaining_usage)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        let tombstone_row_version = current_row_version.saturating_add(1);
        let metadata = BTreeMap::from([
            ("document_id".to_owned(), document_id.to_owned()),
            ("row_version".to_owned(), tombstone_row_version.to_string()),
            ("released_bytes".to_owned(), released_bytes.to_string()),
        ]);
        let cursor = insert_change_tx(
            &mut tx,
            account_id,
            device_id,
            &request.operation_id,
            "configuration_purged",
            "shared_configuration",
            document_id,
            tombstone_row_version,
            now,
            &metadata,
        )
        .await?;
        insert_workspace_audit_tx(
            &mut tx,
            "workspace_configuration_purged",
            "succeeded",
            account_id,
            device_id,
            None,
            now,
            metadata,
        )
        .await?;
        let receipt = WorkspaceMutationReceipt {
            resource_type: "shared_configuration".to_owned(),
            resource_id: document_id.to_owned(),
            row_version: tombstone_row_version,
            cursor: Some(cursor),
        };
        insert_operation_tx(
            &mut tx,
            account_id,
            device_id,
            &request.operation_id,
            "shared.purge",
            &request_sha256,
            "succeeded",
            &receipt,
            now,
        )
        .await?;
        enqueue_workspace_webhook_tx(
            &mut tx,
            account_id,
            "configuration.purged",
            serde_json::json!({
                "documentId": &receipt.resource_id,
                "rowVersion": receipt.row_version,
            }),
            now,
        )
        .await?;
        require_permissions_tx(&mut tx, account_id, device_id, &["shared.purge"], now).await?;
        tx.commit().await.map_err(|_| ApiError::Database)?;
        Ok(receipt)
    }
}

struct ContentEnvelope {
    key_id: String,
    wrapped_key_nonce: Vec<u8>,
    wrapped_data_key: Vec<u8>,
    content_nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    payload_sha256: [u8; 32],
    content_sha256: [u8; 32],
    plaintext_bytes: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SharedProgramKind {
    Generic,
    SingBox,
    Xray,
    Mihomo,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateSharedConfiguration {
    pub name: String,
    pub program_kind: SharedProgramKind,
    /// Program launch/config-source input. It is encrypted in the same envelope as `content`.
    pub input: String,
    /// UTF-8 configuration body, limited to 4 MiB before encryption.
    pub content: String,
    pub operation_id: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviseSharedConfiguration {
    pub base_row_version: u64,
    pub name: String,
    pub program_kind: SharedProgramKind,
    /// Program launch/config-source input. It is encrypted in the same envelope as `content`.
    pub input: String,
    /// UTF-8 configuration body, limited to 4 MiB before encryption.
    pub content: String,
    pub operation_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublishSharedConfiguration {
    pub base_row_version: u64,
    pub revision: Option<u64>,
    pub operation_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VersionedWorkspaceMutation {
    pub base_row_version: u64,
    pub operation_id: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SharedConfigurationPageRequest {
    pub cursor: Option<String>,
    pub limit: Option<u32>,
    #[serde(default)]
    pub include_deleted: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SharedConfigurationContentRequest {
    pub revision: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceStorageUsage {
    pub active_document_count: u32,
    pub max_active_documents: u32,
    pub revision_plaintext_bytes: u64,
    pub max_revision_plaintext_bytes: u64,
    pub row_version: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SharedConfigurationSummary {
    pub id: String,
    pub name: String,
    pub program_kind: SharedProgramKind,
    pub row_version: u64,
    pub draft_revision: u64,
    pub published_revision: Option<u64>,
    pub deleted_at: Option<i64>,
    pub content_sha256: String,
    pub plaintext_bytes: u64,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SharedConfigurationContent {
    #[serde(flatten)]
    pub configuration: SharedConfigurationSummary,
    pub revision: u64,
    pub input: String,
    pub content: String,
    pub revision_created_at: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SharedConfigurationPage {
    pub configurations: Vec<SharedConfigurationSummary>,
    pub usage: WorkspaceStorageUsage,
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceMutationReceipt {
    pub resource_type: String,
    pub resource_id: String,
    pub row_version: u64,
    pub cursor: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceAlertEventKind {
    SyncConflict,
    QuotaWarning,
    ConfigurationCreated,
    ConfigurationRevised,
    ConfigurationPublished,
    ConfigurationDeleted,
    ConfigurationRestored,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceAlertSeverity {
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceIncidentStatus {
    Open,
    Acknowledged,
    Resolved,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateWorkspaceAlertRule {
    pub name: String,
    pub event_kind: WorkspaceAlertEventKind,
    pub severity: WorkspaceAlertSeverity,
    pub enabled: bool,
    pub operation_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateWorkspaceAlertRule {
    pub base_row_version: u64,
    pub name: String,
    pub event_kind: WorkspaceAlertEventKind,
    pub severity: WorkspaceAlertSeverity,
    pub enabled: bool,
    pub operation_id: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkspaceAlertRulePageRequest {
    pub cursor: Option<String>,
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceAlertRule {
    pub id: String,
    pub name: String,
    pub event_kind: WorkspaceAlertEventKind,
    pub severity: WorkspaceAlertSeverity,
    pub enabled: bool,
    pub row_version: u64,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceAlertRulePage {
    pub rules: Vec<WorkspaceAlertRule>,
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkspaceIncidentPageRequest {
    pub cursor: Option<String>,
    pub limit: Option<u32>,
    pub status: Option<WorkspaceIncidentStatus>,
    pub event_kind: Option<WorkspaceAlertEventKind>,
    pub severity: Option<WorkspaceAlertSeverity>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceAlertIncident {
    pub id: String,
    pub rule_id: String,
    pub event_kind: WorkspaceAlertEventKind,
    pub severity: WorkspaceAlertSeverity,
    pub status: WorkspaceIncidentStatus,
    pub summary: String,
    pub metadata: BTreeMap<String, String>,
    pub row_version: u64,
    pub occurred_at: i64,
    pub acknowledged_at: Option<i64>,
    pub resolved_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceIncidentPage {
    pub incidents: Vec<WorkspaceAlertIncident>,
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

#[derive(Debug, Clone)]
pub struct ServerWorkspaceAlertEvent {
    pub event_kind: WorkspaceAlertEventKind,
    pub dedupe_key: String,
    pub summary: String,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkspaceSyncFeedRequest {
    pub cursor: Option<u64>,
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceSyncChange {
    pub cursor: u64,
    pub operation_id: String,
    pub change_kind: String,
    pub resource_type: String,
    pub resource_id: String,
    pub row_version: u64,
    pub occurred_at: i64,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceSyncFeed {
    pub changes: Vec<WorkspaceSyncChange>,
    pub next_cursor: u64,
    pub has_more: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdvanceWorkspaceCheckpoint {
    pub cursor: u64,
    pub base_row_version: u64,
    pub operation_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceDeviceCheckpoint {
    pub cursor: u64,
    pub row_version: u64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkspaceAuditPageRequest {
    pub cursor: Option<String>,
    pub limit: Option<u32>,
    pub event_type: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceAuditEvent {
    pub id: String,
    pub event_type: String,
    pub outcome: String,
    pub occurred_at: i64,
    pub device_id: Option<String>,
    pub reason_code: Option<String>,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceAuditPage {
    pub events: Vec<WorkspaceAuditEvent>,
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceAuditEventTypes {
    pub event_types: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceAuditExport {
    pub events: Vec<WorkspaceAuditEvent>,
    pub next_cursor: Option<String>,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct KeysetCursor {
    timestamp: i64,
    id: String,
}

fn validate_key_id(value: &str) -> std::result::Result<String, WorkspaceKeyringError> {
    if value != value.trim()
        || value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        Err(WorkspaceKeyringError)
    } else {
        Ok(value.to_owned())
    }
}

fn content_aad(account_id: &str, document_id: &str, revision: u64) -> Vec<u8> {
    let mut aad = b"camellia-nexus:workspace:shared-configuration:v1".to_vec();
    append_aad_part(&mut aad, account_id.as_bytes());
    append_aad_part(&mut aad, document_id.as_bytes());
    append_aad_part(&mut aad, &revision.to_be_bytes());
    aad
}

fn wrapping_aad(content_aad: &[u8]) -> Vec<u8> {
    let mut aad = content_aad.to_vec();
    append_aad_part(&mut aad, b"wrapped-data-key");
    aad
}

fn append_aad_part(target: &mut Vec<u8>, value: &[u8]) {
    target.extend_from_slice(&(value.len() as u64).to_be_bytes());
    target.extend_from_slice(value);
}

fn encode_configuration_payload(input: &str, content: &str) -> Result<Vec<u8>> {
    if input.len() > MAX_INPUT_BYTES || content.len() > MAX_CONFIGURATION_BYTES {
        return Err(ApiError::InvalidRequest);
    }
    let input_len = u32::try_from(input.len()).map_err(|_| ApiError::InvalidRequest)?;
    let mut payload = Vec::with_capacity(4 + input.len() + content.len());
    payload.extend_from_slice(&input_len.to_be_bytes());
    payload.extend_from_slice(input.as_bytes());
    payload.extend_from_slice(content.as_bytes());
    Ok(payload)
}

fn decode_configuration_payload(payload: &[u8]) -> Result<(String, String)> {
    let prefix: [u8; 4] = payload
        .get(..4)
        .ok_or(ApiError::WorkspaceIntegrity)?
        .try_into()
        .map_err(|_| ApiError::WorkspaceIntegrity)?;
    let input_len = u32::from_be_bytes(prefix) as usize;
    if input_len > MAX_INPUT_BYTES || payload.len() < 4 + input_len {
        return Err(ApiError::WorkspaceIntegrity);
    }
    let content_len = payload.len() - 4 - input_len;
    if content_len > MAX_CONFIGURATION_BYTES {
        return Err(ApiError::WorkspaceIntegrity);
    }
    let input = String::from_utf8(payload[4..4 + input_len].to_vec())
        .map_err(|_| ApiError::WorkspaceIntegrity)?;
    let content = String::from_utf8(payload[4 + input_len..].to_vec())
        .map_err(|_| ApiError::WorkspaceIntegrity)?;
    Ok((input, content))
}

fn validate_configuration_input(
    name: &str,
    input: &str,
    content: &[u8],
) -> Result<(String, String)> {
    let name = validate_name(name)?;
    if input.len() > MAX_INPUT_BYTES
        || input
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\t'))
        || content.len() > MAX_CONFIGURATION_BYTES
    {
        return Err(ApiError::InvalidRequest);
    }
    Ok((name, input.to_owned()))
}

fn validate_name(value: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty() || value.len() > MAX_NAME_BYTES || value.chars().any(char::is_control) {
        Err(ApiError::InvalidRequest)
    } else {
        Ok(value.to_owned())
    }
}

fn validate_internal_text(value: &str, max: usize) -> Result<String> {
    let value = value.trim();
    if value.is_empty() || value.len() > max || value.chars().any(char::is_control) {
        Err(ApiError::InvalidRequest)
    } else {
        Ok(value.to_owned())
    }
}

fn validate_operation_id(value: &str) -> Result<()> {
    let parsed = uuid::Uuid::parse_str(value).map_err(|_| ApiError::InvalidRequest)?;
    if parsed.get_version() != Some(uuid::Version::Random)
        || parsed.get_variant() != uuid::Variant::RFC4122
        || parsed.hyphenated().to_string() != value
    {
        Err(ApiError::InvalidRequest)
    } else {
        Ok(())
    }
}

fn validate_resource_id(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_ID_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        Err(ApiError::InvalidRequest)
    } else {
        Ok(())
    }
}

fn validate_event_type(value: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        Err(ApiError::InvalidRequest)
    } else {
        Ok(value.to_owned())
    }
}

fn request_digest<T: Serialize>(action: &str, request: &T) -> Result<[u8; 32]> {
    let bytes = serde_json::to_vec(request).map_err(|_| ApiError::Internal)?;
    let mut digest = Sha256::new();
    digest.update((action.len() as u64).to_be_bytes());
    digest.update(action.as_bytes());
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
    Ok(digest.finalize().into())
}

fn page_limit(value: Option<u32>, maximum: u32) -> Result<u32> {
    let value = value.unwrap_or(DEFAULT_PAGE_SIZE);
    if value == 0 || value > maximum {
        Err(ApiError::InvalidRequest)
    } else {
        Ok(value)
    }
}

fn encode_cursor(cursor: &KeysetCursor) -> Result<String> {
    serde_json::to_vec(cursor)
        .map(|bytes| URL_SAFE_NO_PAD.encode(bytes))
        .map_err(|_| ApiError::Internal)
}

fn decode_cursor(value: &str) -> Result<KeysetCursor> {
    if value.is_empty() || value.len() > 512 {
        return Err(ApiError::InvalidRequest);
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| ApiError::InvalidRequest)?;
    let cursor: KeysetCursor =
        serde_json::from_slice(&bytes).map_err(|_| ApiError::InvalidRequest)?;
    validate_resource_id(&cursor.id)?;
    Ok(cursor)
}

fn u64_to_i64(value: u64) -> Result<i64> {
    i64::try_from(value).map_err(|_| ApiError::InvalidRequest)
}

fn positive_u64(value: i64) -> Result<u64> {
    if value <= 0 {
        Err(ApiError::Database)
    } else {
        u64::try_from(value).map_err(|_| ApiError::Database)
    }
}

fn nonnegative_u64(value: i64) -> Result<u64> {
    u64::try_from(value).map_err(|_| ApiError::Database)
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn program_kind_name(kind: SharedProgramKind) -> &'static str {
    match kind {
        SharedProgramKind::Generic => "generic",
        SharedProgramKind::SingBox => "singBox",
        SharedProgramKind::Xray => "xray",
        SharedProgramKind::Mihomo => "mihomo",
    }
}

fn parse_program_kind(value: &str) -> Result<SharedProgramKind> {
    match value {
        "generic" => Ok(SharedProgramKind::Generic),
        "singBox" => Ok(SharedProgramKind::SingBox),
        "xray" => Ok(SharedProgramKind::Xray),
        "mihomo" => Ok(SharedProgramKind::Mihomo),
        _ => Err(ApiError::Database),
    }
}

fn alert_event_kind_name(kind: WorkspaceAlertEventKind) -> &'static str {
    match kind {
        WorkspaceAlertEventKind::SyncConflict => "sync_conflict",
        WorkspaceAlertEventKind::QuotaWarning => "quota_warning",
        WorkspaceAlertEventKind::ConfigurationCreated => "configuration_created",
        WorkspaceAlertEventKind::ConfigurationRevised => "configuration_revised",
        WorkspaceAlertEventKind::ConfigurationPublished => "configuration_published",
        WorkspaceAlertEventKind::ConfigurationDeleted => "configuration_deleted",
        WorkspaceAlertEventKind::ConfigurationRestored => "configuration_restored",
    }
}

fn parse_alert_event_kind(value: &str) -> Result<WorkspaceAlertEventKind> {
    match value {
        "sync_conflict" => Ok(WorkspaceAlertEventKind::SyncConflict),
        "quota_warning" => Ok(WorkspaceAlertEventKind::QuotaWarning),
        "configuration_created" => Ok(WorkspaceAlertEventKind::ConfigurationCreated),
        "configuration_revised" => Ok(WorkspaceAlertEventKind::ConfigurationRevised),
        "configuration_published" => Ok(WorkspaceAlertEventKind::ConfigurationPublished),
        "configuration_deleted" => Ok(WorkspaceAlertEventKind::ConfigurationDeleted),
        "configuration_restored" => Ok(WorkspaceAlertEventKind::ConfigurationRestored),
        _ => Err(ApiError::Database),
    }
}

fn alert_severity_name(severity: WorkspaceAlertSeverity) -> &'static str {
    match severity {
        WorkspaceAlertSeverity::Info => "info",
        WorkspaceAlertSeverity::Warning => "warning",
        WorkspaceAlertSeverity::Critical => "critical",
    }
}

fn parse_alert_severity(value: &str) -> Result<WorkspaceAlertSeverity> {
    match value {
        "info" => Ok(WorkspaceAlertSeverity::Info),
        "warning" => Ok(WorkspaceAlertSeverity::Warning),
        "critical" => Ok(WorkspaceAlertSeverity::Critical),
        _ => Err(ApiError::Database),
    }
}

fn incident_status_name(status: WorkspaceIncidentStatus) -> &'static str {
    match status {
        WorkspaceIncidentStatus::Open => "open",
        WorkspaceIncidentStatus::Acknowledged => "acknowledged",
        WorkspaceIncidentStatus::Resolved => "resolved",
    }
}

fn parse_incident_status(value: &str) -> Result<WorkspaceIncidentStatus> {
    match value {
        "open" => Ok(WorkspaceIncidentStatus::Open),
        "acknowledged" => Ok(WorkspaceIncidentStatus::Acknowledged),
        "resolved" => Ok(WorkspaceIncidentStatus::Resolved),
        _ => Err(ApiError::Database),
    }
}

fn row_configuration_summary(row: PgRow) -> Result<SharedConfigurationSummary> {
    let content_sha256: Vec<u8> = row
        .try_get("content_sha256")
        .map_err(|_| ApiError::Database)?;
    if content_sha256.len() != 32 {
        return Err(ApiError::Database);
    }
    Ok(SharedConfigurationSummary {
        id: row.try_get("id").map_err(|_| ApiError::Database)?,
        name: row.try_get("name").map_err(|_| ApiError::Database)?,
        program_kind: parse_program_kind(
            &row.try_get::<String, _>("program_kind")
                .map_err(|_| ApiError::Database)?,
        )?,
        row_version: positive_u64(row.try_get("row_version").map_err(|_| ApiError::Database)?)?,
        draft_revision: positive_u64(
            row.try_get("draft_revision")
                .map_err(|_| ApiError::Database)?,
        )?,
        published_revision: row
            .try_get::<Option<i64>, _>("published_revision")
            .map_err(|_| ApiError::Database)?
            .map(positive_u64)
            .transpose()?,
        deleted_at: row.try_get("deleted_at").map_err(|_| ApiError::Database)?,
        content_sha256: hex_bytes(&content_sha256),
        plaintext_bytes: nonnegative_u64(
            row.try_get("plaintext_bytes")
                .map_err(|_| ApiError::Database)?,
        )?,
        created_at: row.try_get("created_at").map_err(|_| ApiError::Database)?,
        updated_at: row.try_get("updated_at").map_err(|_| ApiError::Database)?,
    })
}

fn row_content_envelope(row: &PgRow) -> Result<ContentEnvelope> {
    let payload_sha256: Vec<u8> = row
        .try_get("payload_sha256")
        .map_err(|_| ApiError::Database)?;
    let content_sha256: Vec<u8> = row
        .try_get("content_sha256")
        .map_err(|_| ApiError::Database)?;
    Ok(ContentEnvelope {
        key_id: row.try_get("key_id").map_err(|_| ApiError::Database)?,
        wrapped_key_nonce: row
            .try_get("wrapped_key_nonce")
            .map_err(|_| ApiError::Database)?,
        wrapped_data_key: row
            .try_get("wrapped_data_key")
            .map_err(|_| ApiError::Database)?,
        content_nonce: row
            .try_get("content_nonce")
            .map_err(|_| ApiError::Database)?,
        ciphertext: row.try_get("ciphertext").map_err(|_| ApiError::Database)?,
        payload_sha256: payload_sha256.try_into().map_err(|_| ApiError::Database)?,
        content_sha256: content_sha256.try_into().map_err(|_| ApiError::Database)?,
        plaintext_bytes: row
            .try_get("plaintext_bytes")
            .map_err(|_| ApiError::Database)?,
    })
}

fn row_sync_change(row: PgRow) -> Result<WorkspaceSyncChange> {
    Ok(WorkspaceSyncChange {
        cursor: positive_u64(row.try_get("cursor").map_err(|_| ApiError::Database)?)?,
        operation_id: row
            .try_get("operation_id")
            .map_err(|_| ApiError::Database)?,
        change_kind: row.try_get("change_kind").map_err(|_| ApiError::Database)?,
        resource_type: row
            .try_get("resource_type")
            .map_err(|_| ApiError::Database)?,
        resource_id: row.try_get("resource_id").map_err(|_| ApiError::Database)?,
        row_version: nonnegative_u64(row.try_get("row_version").map_err(|_| ApiError::Database)?)?,
        occurred_at: row.try_get("occurred_at").map_err(|_| ApiError::Database)?,
        metadata: safe_metadata(
            row.try_get("metadata").map_err(|_| ApiError::Database)?,
            MetadataPolicy::Workspace,
        ),
    })
}

fn row_alert_rule(row: PgRow) -> Result<WorkspaceAlertRule> {
    Ok(WorkspaceAlertRule {
        id: row.try_get("id").map_err(|_| ApiError::Database)?,
        name: row.try_get("name").map_err(|_| ApiError::Database)?,
        event_kind: parse_alert_event_kind(
            &row.try_get::<String, _>("event_kind")
                .map_err(|_| ApiError::Database)?,
        )?,
        severity: parse_alert_severity(
            &row.try_get::<String, _>("severity")
                .map_err(|_| ApiError::Database)?,
        )?,
        enabled: row.try_get("enabled").map_err(|_| ApiError::Database)?,
        row_version: positive_u64(row.try_get("row_version").map_err(|_| ApiError::Database)?)?,
        created_at: row.try_get("created_at").map_err(|_| ApiError::Database)?,
        updated_at: row.try_get("updated_at").map_err(|_| ApiError::Database)?,
    })
}

fn row_alert_incident(row: PgRow) -> Result<WorkspaceAlertIncident> {
    Ok(WorkspaceAlertIncident {
        id: row.try_get("id").map_err(|_| ApiError::Database)?,
        rule_id: row.try_get("rule_id").map_err(|_| ApiError::Database)?,
        event_kind: parse_alert_event_kind(
            &row.try_get::<String, _>("event_kind")
                .map_err(|_| ApiError::Database)?,
        )?,
        severity: parse_alert_severity(
            &row.try_get::<String, _>("severity")
                .map_err(|_| ApiError::Database)?,
        )?,
        status: parse_incident_status(
            &row.try_get::<String, _>("status")
                .map_err(|_| ApiError::Database)?,
        )?,
        summary: row.try_get("summary").map_err(|_| ApiError::Database)?,
        metadata: safe_metadata(
            row.try_get("metadata").map_err(|_| ApiError::Database)?,
            MetadataPolicy::Workspace,
        ),
        row_version: positive_u64(row.try_get("row_version").map_err(|_| ApiError::Database)?)?,
        occurred_at: row.try_get("occurred_at").map_err(|_| ApiError::Database)?,
        acknowledged_at: row
            .try_get("acknowledged_at")
            .map_err(|_| ApiError::Database)?,
        resolved_at: row.try_get("resolved_at").map_err(|_| ApiError::Database)?,
    })
}

fn row_audit_event(row: PgRow) -> Result<WorkspaceAuditEvent> {
    Ok(WorkspaceAuditEvent {
        id: row.try_get("id").map_err(|_| ApiError::Database)?,
        event_type: row.try_get("event_type").map_err(|_| ApiError::Database)?,
        outcome: row.try_get("outcome").map_err(|_| ApiError::Database)?,
        occurred_at: row.try_get("occurred_at").map_err(|_| ApiError::Database)?,
        device_id: row.try_get("device_id").map_err(|_| ApiError::Database)?,
        reason_code: row.try_get("reason_code").map_err(|_| ApiError::Database)?,
        metadata: safe_metadata(
            row.try_get("metadata").map_err(|_| ApiError::Database)?,
            MetadataPolicy::Audit,
        ),
    })
}

#[derive(Clone, Copy)]
enum MetadataPolicy {
    Workspace,
    Audit,
}

fn safe_metadata(value: serde_json::Value, policy: MetadataPolicy) -> BTreeMap<String, String> {
    let Some(object) = value.as_object() else {
        return BTreeMap::new();
    };
    let audit_allowlist = BTreeSet::from([
        "cursor",
        "document_id",
        "event_kind",
        "incident_count",
        "incident_id",
        "member_id",
        "max_alert_rules",
        "released_bytes",
        "resource_id",
        "resource_type",
        "revision",
        "row_version",
        "rule_id",
        "severity",
        "status",
        "target_device_id",
        "usage_bytes",
    ]);
    object
        .iter()
        .filter(|(key, _)| {
            matches!(policy, MetadataPolicy::Workspace) || audit_allowlist.contains(key.as_str())
        })
        .take(32)
        .filter_map(|(key, value)| {
            let value = match value {
                serde_json::Value::String(value) if value.len() <= 256 => value.clone(),
                serde_json::Value::Number(value) => value.to_string(),
                serde_json::Value::Bool(value) => value.to_string(),
                _ => return None,
            };
            Some((key.clone(), value))
        })
        .collect()
}

fn sanitize_internal_metadata(
    metadata: BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>> {
    if metadata.len() > 32 {
        return Err(ApiError::InvalidRequest);
    }
    let mut sanitized = BTreeMap::new();
    for (key, value) in metadata {
        let key = key.trim().to_ascii_lowercase();
        let sensitive = [
            "content",
            "input",
            "key",
            "nonce",
            "password",
            "secret",
            "signature",
            "token",
        ]
        .iter()
        .any(|needle| key.contains(needle));
        if key.is_empty()
            || key.len() > 64
            || sensitive
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
            || value.len() > 256
            || value.chars().any(char::is_control)
        {
            return Err(ApiError::InvalidRequest);
        }
        sanitized.insert(key, value);
    }
    Ok(sanitized)
}

pub(crate) struct WorkspaceAuthorization {
    pub member_id: String,
    pub role: String,
}

pub(crate) async fn require_permissions_tx(
    tx: &mut Transaction<'_, Postgres>,
    account_id: &str,
    device_id: &str,
    allowed_permissions: &[&str],
    now: i64,
) -> Result<WorkspaceAuthorization> {
    if allowed_permissions.is_empty() {
        return Err(ApiError::Internal);
    }
    let row = sqlx::query(
        "SELECT members.id AS member_id, members.role,
                members.status AS member_status, devices.state AS device_state,
                COALESCE(accounts.document ->> 'state', 'active') AS account_state,
                licenses.plan, licenses.plan_revision, licenses.status AS license_status,
                licenses.expires_at, licenses.purchased_seats
         FROM device_member_bindings AS bindings
         JOIN workspace_members AS members ON members.id = bindings.member_id
         JOIN devices ON devices.device_id = bindings.device_id
           AND devices.account_id = members.account_id
         JOIN accounts ON accounts.id = devices.account_id
         JOIN licenses ON licenses.id = devices.license_id
           AND licenses.account_id = devices.account_id
         WHERE devices.account_id = $1 AND devices.device_id = $2
           AND members.account_id = $1
         FOR SHARE OF members, devices, accounts, licenses",
    )
    .bind(account_id)
    .bind(device_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| ApiError::Database)?
    .ok_or(ApiError::PermissionDenied)?;
    let member_status: String = row
        .try_get("member_status")
        .map_err(|_| ApiError::Database)?;
    let device_state: String = row
        .try_get("device_state")
        .map_err(|_| ApiError::Database)?;
    if member_status != "active" || device_state != "active" {
        return Err(ApiError::PermissionDenied);
    }
    match row
        .try_get::<String, _>("account_state")
        .map_err(|_| ApiError::Database)?
        .as_str()
    {
        "active" => {}
        "suspended" => return Err(ApiError::AccountSuspended),
        "denylisted" => return Err(ApiError::AccountDenylisted),
        _ => return Err(ApiError::Database),
    }
    let plan: String = row.try_get("plan").map_err(|_| ApiError::Database)?;
    let plan_revision: i32 = row
        .try_get("plan_revision")
        .map_err(|_| ApiError::Database)?;
    let purchased_seats: i32 = row
        .try_get("purchased_seats")
        .map_err(|_| ApiError::Database)?;
    if plan != "team"
        || plan_revision != i32::try_from(CURRENT_PLAN_REVISION).map_err(|_| ApiError::Internal)?
        || purchased_seats < 3
    {
        return Err(ApiError::CapabilityDenied);
    }
    let license_status: String = row
        .try_get("license_status")
        .map_err(|_| ApiError::Database)?;
    let expires_at: Option<i64> = row.try_get("expires_at").map_err(|_| ApiError::Database)?;
    match license_status.as_str() {
        "active" if expires_at.is_none_or(|expires_at| expires_at > now) => {}
        "past_due" | "canceled" if expires_at.is_some_and(|expires_at| expires_at > now) => {}
        "past_due" => return Err(ApiError::LicensePastDue),
        "canceled" => return Err(ApiError::LicenseCanceled),
        "active" => return Err(ApiError::LicenseExpired),
        _ => return Err(ApiError::Database),
    }
    let member_id: String = row.try_get("member_id").map_err(|_| ApiError::Database)?;
    let role: String = row.try_get("role").map_err(|_| ApiError::Database)?;
    if allowed_permissions
        .iter()
        .any(|permission| role_has_permission(&role, permission))
    {
        Ok(WorkspaceAuthorization { member_id, role })
    } else {
        Err(ApiError::PermissionDenied)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ConfigurationViewPolicy {
    published_only: bool,
    include_deleted: bool,
}

fn configuration_view_policy(
    role: &str,
    requested_include_deleted: bool,
) -> ConfigurationViewPolicy {
    let published_only = role == "viewer";
    ConfigurationViewPolicy {
        published_only,
        include_deleted: requested_include_deleted && !published_only,
    }
}

fn visible_configuration_revision(
    role: &str,
    requested_revision: Option<u64>,
    draft_revision: u64,
    published_revision: Option<u64>,
    deleted_at: Option<i64>,
) -> Result<u64> {
    if role != "viewer" {
        return Ok(requested_revision.unwrap_or(draft_revision));
    }
    let published_revision = published_revision.ok_or(ApiError::WorkspaceNotFound)?;
    if deleted_at.is_some()
        || requested_revision.is_some_and(|requested| requested != published_revision)
    {
        Err(ApiError::WorkspaceNotFound)
    } else {
        Ok(published_revision)
    }
}

fn can_read_incident_history(role: &str) -> bool {
    role_has_permission(role, "alerts.history.read")
}

fn incident_status_visible(role: &str, status: WorkspaceIncidentStatus) -> bool {
    status != WorkspaceIncidentStatus::Resolved || can_read_incident_history(role)
}

fn configuration_retention_elapsed(deleted_at: i64, now: i64) -> bool {
    deleted_at.saturating_add(DELETED_CONFIGURATION_RETENTION_SECONDS) <= now
}

fn remaining_usage_after_purge(current: i64, released: i64) -> Result<i64> {
    if current < 0 || released < 0 || released > current {
        Err(ApiError::Database)
    } else {
        Ok(current - released)
    }
}

struct StorageUsageState {
    active_document_count: i64,
    revision_plaintext_bytes: i64,
}

async fn lock_storage_usage_tx(
    tx: &mut Transaction<'_, Postgres>,
    account_id: &str,
    now: i64,
) -> Result<StorageUsageState> {
    sqlx::query(
        "INSERT INTO workspace_storage_usage
            (account_id, active_document_count, revision_plaintext_bytes, row_version, updated_at)
         VALUES ($1, 0, 0, 1, $2)
         ON CONFLICT (account_id) DO NOTHING",
    )
    .bind(account_id)
    .bind(now)
    .execute(&mut **tx)
    .await
    .map_err(|_| ApiError::Database)?;
    let row = sqlx::query(
        "SELECT active_document_count, revision_plaintext_bytes, row_version
         FROM workspace_storage_usage WHERE account_id = $1 FOR UPDATE",
    )
    .bind(account_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(|_| ApiError::Database)?;
    let active_document_count: i32 = row
        .try_get("active_document_count")
        .map_err(|_| ApiError::Database)?;
    Ok(StorageUsageState {
        active_document_count: i64::from(active_document_count),
        revision_plaintext_bytes: row
            .try_get("revision_plaintext_bytes")
            .map_err(|_| ApiError::Database)?,
    })
}

async fn storage_usage_tx(
    tx: &mut Transaction<'_, Postgres>,
    account_id: &str,
) -> Result<WorkspaceStorageUsage> {
    let row = sqlx::query(
        "SELECT active_document_count, revision_plaintext_bytes, row_version
         FROM workspace_storage_usage WHERE account_id = $1",
    )
    .bind(account_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| ApiError::Database)?;
    let Some(row) = row else {
        return Ok(WorkspaceStorageUsage {
            active_document_count: 0,
            max_active_documents: MAX_ACTIVE_DOCUMENTS as u32,
            revision_plaintext_bytes: 0,
            max_revision_plaintext_bytes: MAX_WORKSPACE_PLAINTEXT_BYTES as u64,
            row_version: 0,
        });
    };
    let active_document_count: i32 = row
        .try_get("active_document_count")
        .map_err(|_| ApiError::Database)?;
    Ok(WorkspaceStorageUsage {
        active_document_count: u32::try_from(active_document_count)
            .map_err(|_| ApiError::Database)?,
        max_active_documents: MAX_ACTIVE_DOCUMENTS as u32,
        revision_plaintext_bytes: nonnegative_u64(
            row.try_get("revision_plaintext_bytes")
                .map_err(|_| ApiError::Database)?,
        )?,
        max_revision_plaintext_bytes: MAX_WORKSPACE_PLAINTEXT_BYTES as u64,
        row_version: positive_u64(row.try_get("row_version").map_err(|_| ApiError::Database)?)?,
    })
}

async fn lock_document_tx(
    tx: &mut Transaction<'_, Postgres>,
    account_id: &str,
    document_id: &str,
) -> Result<PgRow> {
    sqlx::query(
        "SELECT row_version, last_revision, draft_revision, published_revision, deleted_at
         FROM workspace_documents WHERE account_id = $1 AND id = $2 FOR UPDATE",
    )
    .bind(account_id)
    .bind(document_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| ApiError::Database)?
    .ok_or(ApiError::WorkspaceNotFound)
}

async fn lock_alert_rule_tx(
    tx: &mut Transaction<'_, Postgres>,
    account_id: &str,
    rule_id: &str,
) -> Result<PgRow> {
    sqlx::query(
        "SELECT row_version, deleted_at FROM workspace_alert_rules
         WHERE account_id = $1 AND id = $2 FOR UPDATE",
    )
    .bind(account_id)
    .bind(rule_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| ApiError::Database)?
    .ok_or(ApiError::WorkspaceNotFound)
}

#[allow(clippy::too_many_arguments)]
async fn insert_revision_tx(
    tx: &mut Transaction<'_, Postgres>,
    account_id: &str,
    device_id: &str,
    document_id: &str,
    revision: u64,
    name: &str,
    program_kind: SharedProgramKind,
    envelope: &ContentEnvelope,
    now: i64,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO workspace_document_revisions
            (account_id, document_id, revision, name, program_kind, key_id,
             wrapped_key_nonce, wrapped_data_key, content_nonce, ciphertext,
             payload_sha256, content_sha256, plaintext_bytes, created_by_device_id, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)",
    )
    .bind(account_id)
    .bind(document_id)
    .bind(u64_to_i64(revision)?)
    .bind(name)
    .bind(program_kind_name(program_kind))
    .bind(&envelope.key_id)
    .bind(&envelope.wrapped_key_nonce)
    .bind(&envelope.wrapped_data_key)
    .bind(&envelope.content_nonce)
    .bind(&envelope.ciphertext)
    .bind(envelope.payload_sha256.as_slice())
    .bind(envelope.content_sha256.as_slice())
    .bind(envelope.plaintext_bytes)
    .bind(device_id)
    .bind(now)
    .execute(&mut **tx)
    .await
    .map_err(|_| ApiError::Database)?;
    Ok(())
}

async fn claim_operation_tx(
    tx: &mut Transaction<'_, Postgres>,
    account_id: &str,
    device_id: &str,
    operation_id: &str,
    action: &str,
    request_sha256: &[u8; 32],
) -> Result<Option<WorkspaceMutationReceipt>> {
    let lock_key = format!("{account_id}:{operation_id}");
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 7232026))")
        .bind(lock_key)
        .execute(&mut **tx)
        .await
        .map_err(|_| ApiError::Database)?;
    let row = sqlx::query(
        "SELECT device_id, action, request_sha256, outcome, resource_type, resource_id,
                response_row_version, sync_cursor
         FROM workspace_operations WHERE account_id = $1 AND operation_id = $2 FOR UPDATE",
    )
    .bind(account_id)
    .bind(operation_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| ApiError::Database)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let stored_digest: Vec<u8> = row
        .try_get("request_sha256")
        .map_err(|_| ApiError::Database)?;
    if row
        .try_get::<String, _>("device_id")
        .map_err(|_| ApiError::Database)?
        != device_id
        || row
            .try_get::<String, _>("action")
            .map_err(|_| ApiError::Database)?
            != action
        || stored_digest.len() != request_sha256.len()
        || !bool::from(stored_digest.as_slice().ct_eq(request_sha256))
    {
        return Err(ApiError::IdempotencyConflict);
    }
    match row
        .try_get::<String, _>("outcome")
        .map_err(|_| ApiError::Database)?
        .as_str()
    {
        "succeeded" => Ok(Some(WorkspaceMutationReceipt {
            resource_type: row
                .try_get("resource_type")
                .map_err(|_| ApiError::Database)?,
            resource_id: row.try_get("resource_id").map_err(|_| ApiError::Database)?,
            row_version: nonnegative_u64(
                row.try_get("response_row_version")
                    .map_err(|_| ApiError::Database)?,
            )?,
            cursor: row
                .try_get::<Option<i64>, _>("sync_cursor")
                .map_err(|_| ApiError::Database)?
                .map(nonnegative_u64)
                .transpose()?,
        })),
        "version_conflict" => Err(ApiError::WorkspaceVersionConflict),
        "quota_exceeded" => Err(ApiError::WorkspaceQuotaExceeded),
        "document_limit" => Err(ApiError::WorkspaceDocumentLimitReached),
        "alert_rule_limit" => Err(ApiError::WorkspaceAlertRuleLimitReached),
        "retention_active" => Err(ApiError::WorkspaceRetentionActive),
        _ => Err(ApiError::Database),
    }
}

#[allow(clippy::too_many_arguments)]
async fn insert_operation_tx(
    tx: &mut Transaction<'_, Postgres>,
    account_id: &str,
    device_id: &str,
    operation_id: &str,
    action: &str,
    request_sha256: &[u8; 32],
    outcome: &str,
    receipt: &WorkspaceMutationReceipt,
    now: i64,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO workspace_operations
            (account_id, operation_id, device_id, action, request_sha256, outcome,
             resource_type, resource_id, response_row_version, sync_cursor, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
    )
    .bind(account_id)
    .bind(operation_id)
    .bind(device_id)
    .bind(action)
    .bind(request_sha256.as_slice())
    .bind(outcome)
    .bind(&receipt.resource_type)
    .bind(&receipt.resource_id)
    .bind(u64_to_i64(receipt.row_version)?)
    .bind(receipt.cursor.map(u64_to_i64).transpose()?)
    .bind(now)
    .execute(&mut **tx)
    .await
    .map_err(|_| ApiError::Database)?;
    Ok(())
}

async fn enqueue_workspace_webhook_tx(
    tx: &mut Transaction<'_, Postgres>,
    account_id: &str,
    event_type: &str,
    payload: serde_json::Value,
    now: i64,
) -> Result<()> {
    let event = NewWebhookEvent {
        event_id: uuid::Uuid::new_v4().to_string(),
        event_type: event_type.to_owned(),
        payload,
    };
    enqueue_webhook_event_tx(tx, account_id, &event, now)
        .await
        .map(|_| ())
        .map_err(|error| match error {
            WebhookError::Database | WebhookError::DatabaseSchemaNotReady => ApiError::Database,
            _ => ApiError::Internal,
        })
}

#[allow(clippy::too_many_arguments)]
async fn insert_change_tx(
    tx: &mut Transaction<'_, Postgres>,
    account_id: &str,
    device_id: &str,
    operation_id: &str,
    change_kind: &str,
    resource_type: &str,
    resource_id: &str,
    row_version: u64,
    now: i64,
    metadata: &BTreeMap<String, String>,
) -> Result<u64> {
    let cursor: i64 = sqlx::query_scalar(
        "INSERT INTO workspace_changes
            (account_id, device_id, operation_id, change_kind, resource_type,
             resource_id, row_version, occurred_at, metadata)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         RETURNING cursor",
    )
    .bind(account_id)
    .bind(device_id)
    .bind(operation_id)
    .bind(change_kind)
    .bind(resource_type)
    .bind(resource_id)
    .bind(u64_to_i64(row_version)?)
    .bind(now)
    .bind(serde_json::to_value(metadata).map_err(|_| ApiError::Internal)?)
    .fetch_one(&mut **tx)
    .await
    .map_err(|_| ApiError::Database)?;
    positive_u64(cursor)
}

#[allow(clippy::too_many_arguments)]
async fn insert_workspace_audit_tx(
    tx: &mut Transaction<'_, Postgres>,
    event_type: &str,
    outcome: &str,
    account_id: &str,
    device_id: &str,
    reason_code: Option<&str>,
    now: i64,
    metadata: BTreeMap<String, String>,
) -> Result<()> {
    let metadata = sanitize_internal_metadata(metadata)?;
    let record = AuditEventRecord {
        id: random_id("audit"),
        event_type: event_type.to_owned(),
        outcome: outcome.to_owned(),
        occurred_at: now,
        account_id: Some(account_id.to_owned()),
        license_id: None,
        device_id: Some(device_id.to_owned()),
        reason_code: reason_code.map(str::to_owned),
        metadata,
    };
    sqlx::query(
        "INSERT INTO audit_events
            (id, event_type, outcome, occurred_at, account_id, license_id, device_id,
             reason_code, metadata, document, actor_type, actor_id)
         VALUES ($1, $2, $3, $4, $5, NULL, $6, $7, $8, $9, 'device', $6)",
    )
    .bind(&record.id)
    .bind(&record.event_type)
    .bind(&record.outcome)
    .bind(record.occurred_at)
    .bind(account_id)
    .bind(device_id)
    .bind(&record.reason_code)
    .bind(serde_json::to_value(&record.metadata).map_err(|_| ApiError::Internal)?)
    .bind(serde_json::to_value(&record).map_err(|_| ApiError::Internal)?)
    .execute(&mut **tx)
    .await
    .map_err(|_| ApiError::Database)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn record_version_conflict_tx(
    tx: &mut Transaction<'_, Postgres>,
    account_id: &str,
    device_id: &str,
    document_id: &str,
    current_row_version: u64,
    operation_id: &str,
    action: &str,
    request_sha256: &[u8; 32],
    now: i64,
) -> Result<()> {
    record_generic_version_conflict_tx(
        tx,
        account_id,
        device_id,
        "shared_configuration",
        document_id,
        current_row_version,
        operation_id,
        action,
        request_sha256,
        now,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn record_generic_version_conflict_tx(
    tx: &mut Transaction<'_, Postgres>,
    account_id: &str,
    device_id: &str,
    resource_type: &str,
    resource_id: &str,
    current_row_version: u64,
    operation_id: &str,
    action: &str,
    request_sha256: &[u8; 32],
    now: i64,
) -> Result<()> {
    let metadata = BTreeMap::from([
        ("resource_id".to_owned(), resource_id.to_owned()),
        ("resource_type".to_owned(), resource_type.to_owned()),
        ("row_version".to_owned(), current_row_version.to_string()),
    ]);
    let cursor = insert_change_tx(
        tx,
        account_id,
        device_id,
        operation_id,
        "sync_conflict",
        resource_type,
        resource_id,
        current_row_version,
        now,
        &metadata,
    )
    .await?;
    record_alert_event_tx(
        tx,
        account_id,
        device_id,
        operation_id,
        &ServerWorkspaceAlertEvent {
            event_kind: WorkspaceAlertEventKind::SyncConflict,
            dedupe_key: format!(
                "sync-conflict:{resource_type}:{resource_id}:{current_row_version}:{device_id}"
            ),
            summary: "A cloud synchronization version conflict requires review.".to_owned(),
            metadata: metadata.clone(),
        },
        now,
    )
    .await?;
    insert_workspace_audit_tx(
        tx,
        "workspace_sync_conflict",
        "denied",
        account_id,
        device_id,
        Some("version_conflict"),
        now,
        metadata,
    )
    .await?;
    insert_operation_tx(
        tx,
        account_id,
        device_id,
        operation_id,
        action,
        request_sha256,
        "version_conflict",
        &WorkspaceMutationReceipt {
            resource_type: resource_type.to_owned(),
            resource_id: resource_id.to_owned(),
            row_version: current_row_version,
            cursor: Some(cursor),
        },
        now,
    )
    .await?;
    enqueue_workspace_webhook_tx(
        tx,
        account_id,
        "sync.conflict",
        serde_json::json!({
            "resourceType": resource_type,
            "resourceId": resource_id,
            "rowVersion": current_row_version,
        }),
        now,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn record_limit_failure_tx(
    tx: &mut Transaction<'_, Postgres>,
    account_id: &str,
    device_id: &str,
    operation_id: &str,
    action: &str,
    request_sha256: &[u8; 32],
    outcome: &str,
    error: ApiError,
    now: i64,
) -> Result<()> {
    record_limit_failure_for_resource_tx(
        tx,
        account_id,
        device_id,
        operation_id,
        action,
        request_sha256,
        outcome,
        "workspace",
        account_id,
        0,
        now,
    )
    .await?;
    if !matches!(
        error,
        ApiError::WorkspaceQuotaExceeded | ApiError::WorkspaceDocumentLimitReached
    ) {
        return Err(ApiError::Internal);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn record_limit_failure_for_resource_tx(
    tx: &mut Transaction<'_, Postgres>,
    account_id: &str,
    device_id: &str,
    operation_id: &str,
    action: &str,
    request_sha256: &[u8; 32],
    outcome: &str,
    resource_type: &str,
    resource_id: &str,
    row_version: u64,
    now: i64,
) -> Result<()> {
    let reason_code = match outcome {
        "quota_exceeded" => "workspace_quota_exceeded",
        "document_limit" => "workspace_document_limit_reached",
        _ => return Err(ApiError::Internal),
    };
    let metadata = BTreeMap::from([
        ("resource_id".to_owned(), resource_id.to_owned()),
        ("resource_type".to_owned(), resource_type.to_owned()),
        ("row_version".to_owned(), row_version.to_string()),
    ]);
    record_alert_event_tx(
        tx,
        account_id,
        device_id,
        operation_id,
        &ServerWorkspaceAlertEvent {
            event_kind: WorkspaceAlertEventKind::QuotaWarning,
            dedupe_key: format!("workspace-limit:{outcome}:{account_id}"),
            summary: if outcome == "quota_exceeded" {
                "The shared-configuration history quota has been reached."
            } else {
                "The active shared-configuration limit has been reached."
            }
            .to_owned(),
            metadata: metadata.clone(),
        },
        now,
    )
    .await?;
    insert_workspace_audit_tx(
        tx,
        "workspace_configuration_limit_denied",
        "denied",
        account_id,
        device_id,
        Some(reason_code),
        now,
        metadata,
    )
    .await?;
    insert_operation_tx(
        tx,
        account_id,
        device_id,
        operation_id,
        action,
        request_sha256,
        outcome,
        &WorkspaceMutationReceipt {
            resource_type: resource_type.to_owned(),
            resource_id: resource_id.to_owned(),
            row_version,
            cursor: None,
        },
        now,
    )
    .await
}

async fn record_alert_rule_limit_tx(
    tx: &mut Transaction<'_, Postgres>,
    account_id: &str,
    device_id: &str,
    operation_id: &str,
    request_sha256: &[u8; 32],
    now: i64,
) -> Result<()> {
    let metadata = BTreeMap::from([("max_alert_rules".to_owned(), MAX_ALERT_RULES.to_string())]);
    record_alert_event_tx(
        tx,
        account_id,
        device_id,
        operation_id,
        &ServerWorkspaceAlertEvent {
            event_kind: WorkspaceAlertEventKind::QuotaWarning,
            dedupe_key: format!("workspace-alert-rule-limit:{account_id}"),
            summary: "The active workspace alert-rule limit has been reached.".to_owned(),
            metadata: metadata.clone(),
        },
        now,
    )
    .await?;
    insert_workspace_audit_tx(
        tx,
        "workspace_alert_rule_limit_denied",
        "denied",
        account_id,
        device_id,
        Some("workspace_alert_rule_limit_reached"),
        now,
        metadata,
    )
    .await?;
    insert_operation_tx(
        tx,
        account_id,
        device_id,
        operation_id,
        "alerts.rule.create",
        request_sha256,
        "alert_rule_limit",
        &WorkspaceMutationReceipt {
            resource_type: "workspace".to_owned(),
            resource_id: account_id.to_owned(),
            row_version: 0,
            cursor: None,
        },
        now,
    )
    .await
}

async fn maybe_record_quota_warning_tx(
    tx: &mut Transaction<'_, Postgres>,
    account_id: &str,
    device_id: &str,
    operation_id: &str,
    usage_bytes: i64,
    now: i64,
) -> Result<()> {
    if usage_bytes.saturating_mul(QUOTA_WARNING_DENOMINATOR)
        < MAX_WORKSPACE_PLAINTEXT_BYTES.saturating_mul(QUOTA_WARNING_NUMERATOR)
    {
        return Ok(());
    }
    record_alert_event_tx(
        tx,
        account_id,
        device_id,
        operation_id,
        &ServerWorkspaceAlertEvent {
            event_kind: WorkspaceAlertEventKind::QuotaWarning,
            dedupe_key: format!("workspace-quota-warning-80:{account_id}"),
            summary: "Shared-configuration history storage is at least 80% full.".to_owned(),
            metadata: BTreeMap::from([("usage_bytes".to_owned(), usage_bytes.to_string())]),
        },
        now,
    )
    .await?;
    Ok(())
}

async fn record_alert_event_tx(
    tx: &mut Transaction<'_, Postgres>,
    account_id: &str,
    device_id: &str,
    operation_id: &str,
    event: &ServerWorkspaceAlertEvent,
    now: i64,
) -> Result<u32> {
    let dedupe_lock = format!(
        "{account_id}:{}:{}",
        alert_event_kind_name(event.event_kind),
        event.dedupe_key
    );
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 7242026))")
        .bind(dedupe_lock)
        .execute(&mut **tx)
        .await
        .map_err(|_| ApiError::Database)?;
    let metadata = sanitize_internal_metadata(event.metadata.clone())?;
    let summary = validate_internal_text(&event.summary, 512)?;
    let dedupe_key = sha256_hex(&event.dedupe_key);
    let rules = sqlx::query(
        "SELECT id, severity FROM workspace_alert_rules
         WHERE account_id = $1 AND event_kind = $2 AND enabled AND deleted_at IS NULL
         ORDER BY id FOR SHARE",
    )
    .bind(account_id)
    .bind(alert_event_kind_name(event.event_kind))
    .fetch_all(&mut **tx)
    .await
    .map_err(|_| ApiError::Database)?;
    let mut incident_count = 0_u32;
    for rule in rules {
        let rule_id: String = rule.try_get("id").map_err(|_| ApiError::Database)?;
        let severity: String = rule.try_get("severity").map_err(|_| ApiError::Database)?;
        let existing = sqlx::query(
            "SELECT id, status, row_version FROM workspace_alert_incidents
             WHERE account_id = $1 AND rule_id = $2 AND dedupe_key = $3
               AND status IN ('open', 'acknowledged') FOR UPDATE",
        )
        .bind(account_id)
        .bind(&rule_id)
        .bind(&dedupe_key)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| ApiError::Database)?;
        let (incident_id, row_version, change_kind, audit_type, opened) =
            if let Some(existing) = existing {
                let incident_id: String = existing.try_get("id").map_err(|_| ApiError::Database)?;
                let current_row_version = positive_u64(
                    existing
                        .try_get("row_version")
                        .map_err(|_| ApiError::Database)?,
                )?;
                sqlx::query(
                    "UPDATE workspace_alert_incidents
                 SET severity = $3, summary = $4, metadata = $5,
                     occurred_at = $6, row_version = row_version + 1
                 WHERE account_id = $1 AND id = $2",
                )
                .bind(account_id)
                .bind(&incident_id)
                .bind(&severity)
                .bind(&summary)
                .bind(serde_json::to_value(&metadata).map_err(|_| ApiError::Internal)?)
                .bind(now)
                .execute(&mut **tx)
                .await
                .map_err(|_| ApiError::Database)?;
                (
                    incident_id,
                    current_row_version.saturating_add(1),
                    "alert_incident_updated",
                    "workspace_alert_incident_updated",
                    false,
                )
            } else {
                let incident_id = random_id("alert_incident");
                sqlx::query(
                    "INSERT INTO workspace_alert_incidents
                    (id, account_id, rule_id, event_kind, severity, dedupe_key, status,
                     summary, metadata, row_version, occurred_at, acknowledged_at,
                     acknowledged_by_device_id, resolved_at, resolved_by_device_id)
                 VALUES ($1, $2, $3, $4, $5, $6, 'open', $7, $8, 1, $9,
                         NULL, NULL, NULL, NULL)",
                )
                .bind(&incident_id)
                .bind(account_id)
                .bind(&rule_id)
                .bind(alert_event_kind_name(event.event_kind))
                .bind(&severity)
                .bind(&dedupe_key)
                .bind(&summary)
                .bind(serde_json::to_value(&metadata).map_err(|_| ApiError::Internal)?)
                .bind(now)
                .execute(&mut **tx)
                .await
                .map_err(|_| ApiError::Database)?;
                (
                    incident_id,
                    1,
                    "alert_incident_opened",
                    "workspace_alert_incident_opened",
                    true,
                )
            };
        if opened {
            enqueue_workspace_webhook_tx(
                tx,
                account_id,
                "alert.incident.opened",
                serde_json::json!({
                    "incidentId": &incident_id,
                    "ruleId": &rule_id,
                    "eventKind": alert_event_kind_name(event.event_kind),
                    "severity": &severity,
                    "rowVersion": row_version,
                }),
                now,
            )
            .await?;
        }
        let incident_metadata = BTreeMap::from([
            ("incident_id".to_owned(), incident_id.clone()),
            ("rule_id".to_owned(), rule_id),
            (
                "event_kind".to_owned(),
                alert_event_kind_name(event.event_kind).to_owned(),
            ),
            ("severity".to_owned(), severity),
            ("row_version".to_owned(), row_version.to_string()),
        ]);
        insert_change_tx(
            tx,
            account_id,
            device_id,
            operation_id,
            change_kind,
            "alert_incident",
            &incident_id,
            row_version,
            now,
            &incident_metadata,
        )
        .await?;
        insert_workspace_audit_tx(
            tx,
            audit_type,
            "succeeded",
            account_id,
            device_id,
            None,
            now,
            incident_metadata,
        )
        .await?;
        incident_count = incident_count.saturating_add(1);
    }
    Ok(incident_count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        contracts::{DeviceRegistrationMetadata, DeviceState, Plan},
        domain::{Account, Device, License},
        store::LicenseRepository,
    };

    fn test_keyring() -> WorkspaceKeyring {
        WorkspaceKeyring {
            active_key_id: "workspace-test-key".to_owned(),
            keys: BTreeMap::from([("workspace-test-key".to_owned(), [7_u8; 32])]),
        }
    }

    #[test]
    fn encrypted_payload_round_trips_and_is_bound_to_tenant_document_and_revision() {
        let keyring = test_keyring();
        let payload = encode_configuration_payload("--config production.json", "{\"secret\":1}")
            .expect("valid payload");
        let envelope = keyring
            .seal(
                "account-a",
                "shared_config-a",
                4,
                &payload,
                b"{\"secret\":1}",
            )
            .expect("encrypt");
        assert_eq!(
            keyring
                .open("account-a", "shared_config-a", 4, &envelope)
                .expect("decrypt"),
            payload
        );
        assert!(matches!(
            keyring.open("account-b", "shared_config-a", 4, &envelope),
            Err(ApiError::WorkspaceIntegrity)
        ));
        assert!(matches!(
            keyring.open("account-a", "shared_config-b", 4, &envelope),
            Err(ApiError::WorkspaceIntegrity)
        ));
        assert!(matches!(
            keyring.open("account-a", "shared_config-a", 5, &envelope),
            Err(ApiError::WorkspaceIntegrity)
        ));
    }

    #[test]
    fn encrypted_payload_detects_tampering_and_does_not_store_input_in_plaintext() {
        let keyring = test_keyring();
        let input = "--password highly-sensitive";
        let content = "configuration";
        let payload = encode_configuration_payload(input, content).expect("valid payload");
        let mut envelope = keyring
            .seal(
                "account-a",
                "shared_config-a",
                1,
                &payload,
                content.as_bytes(),
            )
            .expect("encrypt");
        assert!(
            !envelope
                .ciphertext
                .windows(input.len())
                .any(|window| window == input.as_bytes())
        );
        envelope.ciphertext[0] ^= 0x01;
        assert!(matches!(
            keyring.open("account-a", "shared_config-a", 1, &envelope),
            Err(ApiError::WorkspaceIntegrity)
        ));
    }

    #[test]
    fn payload_codec_keeps_input_and_content_boundaries() {
        let input = "--flag\tvalue";
        let content = "\n{\"route\": []}\n";
        let payload = encode_configuration_payload(input, content).expect("encode");
        assert_eq!(
            decode_configuration_payload(&payload).expect("decode"),
            (input.to_owned(), content.to_owned())
        );
        assert!(decode_configuration_payload(&[0, 0, 0]).is_err());
        assert!(encode_configuration_payload(&"x".repeat(MAX_INPUT_BYTES + 1), content).is_err());
        assert!(
            encode_configuration_payload(input, &"x".repeat(MAX_CONFIGURATION_BYTES + 1)).is_err()
        );
    }

    #[test]
    fn team_operation_response_encryption_is_aad_bound_and_detects_tampering() {
        let keyring = test_keyring();
        let aad = b"account-a/device-a/operation-a/create-invitation";
        let plaintext = b"{\"invitationToken\":\"one-time-secret\"}";
        let (key_id, nonce, ciphertext) = keyring
            .seal_team_operation_response(aad, plaintext)
            .expect("encrypt Team operation response");
        assert_eq!(
            keyring
                .open_team_operation_response(&key_id, &nonce, &ciphertext, aad)
                .expect("decrypt Team operation response"),
            plaintext
        );
        assert!(
            keyring
                .open_team_operation_response(
                    &key_id,
                    &nonce,
                    &ciphertext,
                    b"account-b/device-a/operation-a/create-invitation",
                )
                .is_err()
        );
        let mut tampered = ciphertext;
        tampered[0] ^= 0x01;
        assert!(
            keyring
                .open_team_operation_response(&key_id, &nonce, &tampered, aad)
                .is_err()
        );
    }

    #[test]
    fn operation_ids_are_canonical_lowercase_uuid_v4() {
        assert!(validate_operation_id("00000000-0000-4000-8000-000000000000").is_ok());
        assert!(validate_operation_id("00000000-0000-4000-8000-00000000000A").is_err());
        assert!(validate_operation_id("00000000-0000-7000-8000-000000000000").is_err());
        assert!(validate_operation_id("not-a-uuid").is_err());
    }

    #[test]
    fn role_permissions_are_fixed_and_least_privilege() {
        assert!(role_has_permission("owner", "shared.purge"));
        assert!(role_has_permission("admin", "alerts.manage"));
        assert!(!role_has_permission("admin", "shared.purge"));
        assert!(role_has_permission("operator", "shared.write"));
        assert!(role_has_permission("operator", "alerts.ack"));
        assert!(!role_has_permission("operator", "alerts.manage"));
        assert!(role_has_permission("viewer", "shared.read"));
        assert!(!role_has_permission("viewer", "shared.write"));
        assert!(role_has_permission("auditor", "alerts.history.read"));
        assert!(role_has_permission("auditor", "audit.export"));
        assert!(!role_has_permission("billing", "shared.read"));
    }

    #[test]
    fn viewer_projection_exposes_only_the_current_published_revision() {
        assert_eq!(
            configuration_view_policy("viewer", true),
            ConfigurationViewPolicy {
                published_only: true,
                include_deleted: false,
            }
        );
        assert_eq!(
            visible_configuration_revision("viewer", None, 8, Some(5), None).unwrap(),
            5
        );
        assert!(visible_configuration_revision("viewer", Some(4), 8, Some(5), None).is_err());
        assert!(visible_configuration_revision("viewer", None, 8, None, None).is_err());
        assert!(visible_configuration_revision("viewer", None, 8, Some(5), Some(10)).is_err());
        assert_eq!(
            visible_configuration_revision("operator", Some(4), 8, Some(5), Some(10)).unwrap(),
            4
        );
    }

    #[test]
    fn incident_history_is_not_visible_to_read_only_alert_roles() {
        for role in ["operator", "viewer"] {
            assert!(incident_status_visible(role, WorkspaceIncidentStatus::Open));
            assert!(incident_status_visible(
                role,
                WorkspaceIncidentStatus::Acknowledged
            ));
            assert!(!incident_status_visible(
                role,
                WorkspaceIncidentStatus::Resolved
            ));
        }
        for role in ["owner", "admin", "auditor"] {
            assert!(incident_status_visible(
                role,
                WorkspaceIncidentStatus::Resolved
            ));
        }
    }

    #[test]
    fn soft_delete_retention_and_quota_release_are_explicit() {
        let deleted_at = 1_000;
        assert!(!configuration_retention_elapsed(
            deleted_at,
            deleted_at + DELETED_CONFIGURATION_RETENTION_SECONDS - 1
        ));
        assert!(configuration_retention_elapsed(
            deleted_at,
            deleted_at + DELETED_CONFIGURATION_RETENTION_SECONDS
        ));
        assert_eq!(remaining_usage_after_purge(10_000, 4_000).unwrap(), 6_000);
        assert!(remaining_usage_after_purge(4_000, 4_001).is_err());
        assert!(remaining_usage_after_purge(4_000, -1).is_err());
    }

    #[test]
    fn audit_metadata_uses_an_allowlist_and_redacts_credentials() {
        let metadata = safe_metadata(
            serde_json::json!({
                "document_id": "shared_config-a",
                "row_version": 2,
                "token_id": "secret-token",
                "nonce": "secret-nonce",
                "content": "secret-content"
            }),
            MetadataPolicy::Audit,
        );
        assert_eq!(
            metadata.get("document_id").map(String::as_str),
            Some("shared_config-a")
        );
        assert_eq!(metadata.get("row_version").map(String::as_str), Some("2"));
        assert!(!metadata.contains_key("token_id"));
        assert!(!metadata.contains_key("nonce"));
        assert!(!metadata.contains_key("content"));
    }

    #[test]
    fn request_contracts_reject_unknown_fields_and_use_camel_case() {
        let value = serde_json::json!({
            "baseRowVersion": 1,
            "operationId": "00000000-0000-4000-8000-000000000000"
        });
        let request: VersionedWorkspaceMutation =
            serde_json::from_value(value).expect("camelCase contract");
        assert_eq!(request.base_row_version, 1);
        assert!(
            serde_json::from_value::<VersionedWorkspaceMutation>(serde_json::json!({
                "baseRowVersion": 1,
                "operationId": "00000000-0000-4000-8000-000000000000",
                "unexpected": true
            }))
            .is_err()
        );
    }

    #[test]
    fn shared_program_kinds_include_mihomo_in_api_and_storage_contracts() {
        assert_eq!(
            serde_json::to_value(SharedProgramKind::Mihomo).expect("serialize Mihomo kind"),
            serde_json::json!("mihomo")
        );
        assert_eq!(
            serde_json::from_value::<SharedProgramKind>(serde_json::json!("mihomo"))
                .expect("deserialize Mihomo kind"),
            SharedProgramKind::Mihomo
        );
        assert_eq!(program_kind_name(SharedProgramKind::Mihomo), "mihomo");
        assert_eq!(
            parse_program_kind("mihomo").expect("parse stored Mihomo kind"),
            SharedProgramKind::Mihomo
        );
        assert!(parse_program_kind("Mihomo").is_err());
        let baseline = include_str!("../migrations/0001_prelaunch_baseline.sql");
        let revisions = baseline
            .split_once("CREATE TABLE public.workspace_document_revisions (")
            .expect("workspace revision table belongs in the prelaunch baseline")
            .1
            .split_once("\n);\n")
            .expect("workspace revision table definition is terminated")
            .0;
        for kind in ["generic", "singBox", "xray", "mihomo"] {
            assert!(
                revisions.contains(&format!("'{kind}'::text")),
                "missing {kind}"
            );
        }
    }

    #[tokio::test]
    async fn postgres_workspace_schema_is_verified_when_test_database_is_configured() {
        let Ok(database_url) = std::env::var("TEST_DATABASE_URL") else {
            return;
        };
        let repository =
            PostgresRepository::connect(&database_url, 1, std::time::Duration::from_secs(10))
                .await
                .expect("connect test database");
        repository.migrate().await.expect("migrate test database");
        let ready: bool = sqlx::query_scalar(
            "SELECT to_regclass('public.workspace_documents') IS NOT NULL
                AND to_regclass('public.workspace_document_revisions') IS NOT NULL
                AND to_regclass('public.workspace_changes') IS NOT NULL
                AND to_regclass('public.workspace_alert_incidents') IS NOT NULL",
        )
        .fetch_one(&repository.pool)
        .await
        .expect("inspect workspace schema");
        assert!(ready);
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn retention_denial_is_idempotent_audited_and_non_destructive() {
        let database_url = std::env::var("TEST_DATABASE_URL")
            .expect("TEST_DATABASE_URL is required for the PostgreSQL integration test");
        let repository =
            PostgresRepository::connect(&database_url, 2, std::time::Duration::from_secs(10))
                .await
                .expect("connect test database");
        repository.migrate().await.expect("migrate test database");

        let suffix = random_id("workspace_retention_test");
        let account_id = format!("account_{suffix}");
        let license = License::new(&account_id, Plan::Team);
        let device_id = uuid::Uuid::new_v4().to_string();
        let document_id = format!("shared_config_{suffix}");
        let operation_id = uuid::Uuid::new_v4().to_string();
        let now = 2_000_000_000;
        repository
            .upsert_account(Account::active(&account_id, now))
            .await
            .expect("create account");
        repository
            .upsert_license(license.clone())
            .await
            .expect("create Team license");
        repository
            .upsert_device(Device {
                account_id: account_id.clone(),
                license_id: license.id,
                metadata: DeviceRegistrationMetadata {
                    device_id: device_id.clone(),
                    public_key_pem: "workspace-retention-test-public-key".to_owned(),
                    public_key_thumbprint: format!("sha256:{device_id}"),
                    platform: "test".to_owned(),
                    app_version: "1.0.0".to_owned(),
                    display_name: Some("Workspace retention test".to_owned()),
                },
                state: DeviceState::Active,
                pending_activation_code_hash: None,
                pending_activation_expires_at: None,
                created_at: now,
                last_seen_at: Some(now),
            })
            .await
            .expect("create owner device");
        let workspace = WorkspaceRepository::new(&repository, test_keyring());
        sqlx::query(
            "INSERT INTO workspace_documents
                (id, account_id, row_version, last_revision, draft_revision,
                 published_revision, deleted_at, created_at, updated_at)
             VALUES ($1, $2, 1, 0, NULL, NULL, $3, $4, $3)",
        )
        .bind(&document_id)
        .bind(&account_id)
        .bind(now - 60)
        .bind(now - 120)
        .execute(&repository.pool)
        .await
        .expect("insert deleted workspace document");

        let request = VersionedWorkspaceMutation {
            base_row_version: 1,
            operation_id,
        };
        for attempt in 0..2 {
            assert!(matches!(
                workspace
                    .purge_shared_configuration(
                        &account_id,
                        &device_id,
                        &document_id,
                        request.clone(),
                        now + attempt,
                    )
                    .await,
                Err(ApiError::WorkspaceRetentionActive)
            ));
        }

        let document_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (
                 SELECT 1 FROM workspace_documents WHERE account_id = $1 AND id = $2
             )",
        )
        .bind(&account_id)
        .bind(&document_id)
        .fetch_one(&repository.pool)
        .await
        .expect("verify retained document");
        let denial_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_events
             WHERE account_id = $1 AND event_type = 'workspace_configuration_purge_denied'
               AND outcome = 'denied' AND reason_code = 'retention_active'",
        )
        .bind(&account_id)
        .fetch_one(&repository.pool)
        .await
        .expect("verify retention audit");
        let operation_outcome: String = sqlx::query_scalar(
            "SELECT outcome FROM workspace_operations
             WHERE account_id = $1 AND operation_id = $2",
        )
        .bind(&account_id)
        .bind(&request.operation_id)
        .fetch_one(&repository.pool)
        .await
        .expect("verify retention operation");
        assert!(document_exists);
        assert_eq!(denial_count, 1);
        assert_eq!(operation_outcome, "retention_active");

        sqlx::query("DELETE FROM audit_events WHERE account_id = $1")
            .bind(&account_id)
            .execute(&repository.pool)
            .await
            .expect("delete test audits");
        sqlx::query("DELETE FROM accounts WHERE id = $1")
            .bind(&account_id)
            .execute(&repository.pool)
            .await
            .expect("clean up retention test");
        repository.close().await;
    }
}
