use std::{env, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use bytes::Bytes;
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use futures_util::StreamExt;
use object_store::{
    GetOptions, ObjectStore, ObjectStoreExt, aws::AmazonS3Builder, local::LocalFileSystem,
    path::Path as ObjectPath,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Row, Transaction};
use subtle::ConstantTimeEq;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zeroize::Zeroize;

use crate::{
    admin_app::{AdminAppError, AdminApplication, MutationContext},
    admin_auth::{AdminAuthError, AdminKeyring, AdminPermission, authorize_admin_mutation},
    crypto::{random_id, random_secret, sha256_hex},
    error::ApiError,
    store::PostgresRepository,
};

const DATABASE_CHUNK_SIZE: usize = 1024 * 1024;
const DEFAULT_MAX_OBJECT_BYTES: usize = 64 * 1024 * 1024;
const DEFAULT_DATABASE_HARD_LIMIT_BYTES: i64 = 20 * 1024 * 1024 * 1024;
const XCHACHA20_POLY1305_TAG_BYTES: u64 = 16;
const OBJECT_STORAGE_READINESS_PREFIX: &str = "camellia-nexus-readiness-v1";
const OBJECT_STORAGE_READINESS_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Error)]
pub enum ObjectStorageError {
    #[error("invalid object: {0}")]
    Validation(String),
    #[error("stored object not found")]
    NotFound,
    #[error("stored object is not ready")]
    NotReady,
    #[error("object storage quota exceeded")]
    QuotaExceeded,
    #[error("stored object integrity check failed")]
    Integrity,
    #[error("object storage backend failed")]
    Backend,
    #[error("malware scanner is unavailable")]
    ScannerUnavailable,
    #[error("uploaded content was rejected by malware scanning")]
    MalwareDetected,
    #[error(transparent)]
    Authentication(#[from] AdminAuthError),
    #[error(transparent)]
    Service(#[from] ApiError),
}

pub type ObjectStorageResult<T> = Result<T, ObjectStorageError>;

#[derive(Clone)]
pub enum EvidenceScanner {
    Disabled,
    ClamAv { address: String, timeout: Duration },
}

impl EvidenceScanner {
    pub fn from_env(production: bool) -> Result<Self, String> {
        let mode = env::var("CAMELLIA_NEXUS_EVIDENCE_SCANNER")
            .unwrap_or_else(|_| if production { "clamav" } else { "disabled" }.to_owned());
        match mode.trim().to_ascii_lowercase().as_str() {
            "disabled" if !production => Ok(Self::Disabled),
            "disabled" => {
                Err("CAMELLIA_NEXUS_EVIDENCE_SCANNER cannot be disabled in production".to_owned())
            }
            "clamav" => {
                let address = parse_clamav_address(
                    &env::var("CAMELLIA_NEXUS_CLAMAV_ADDRESS")
                        .unwrap_or_else(|_| "127.0.0.1:3310".to_owned()),
                )?;
                let seconds = env_i64("CAMELLIA_NEXUS_CLAMAV_TIMEOUT_SECONDS", 15)?;
                if !(1..=120).contains(&seconds) {
                    return Err(
                        "CAMELLIA_NEXUS_CLAMAV_TIMEOUT_SECONDS must be between 1 and 120"
                            .to_owned(),
                    );
                }
                Ok(Self::ClamAv {
                    address,
                    timeout: Duration::from_secs(seconds as u64),
                })
            }
            _ => Err("CAMELLIA_NEXUS_EVIDENCE_SCANNER must be disabled or clamav".to_owned()),
        }
    }

    pub async fn readiness_check(&self) -> ObjectStorageResult<()> {
        match self {
            Self::Disabled => Ok(()),
            Self::ClamAv { address, timeout } => tokio::time::timeout(*timeout, async {
                let mut stream = tokio::net::TcpStream::connect(address.as_str())
                    .await
                    .map_err(|_| ObjectStorageError::ScannerUnavailable)?;
                stream
                    .write_all(b"zPING\0")
                    .await
                    .map_err(|_| ObjectStorageError::ScannerUnavailable)?;
                let mut response = Vec::with_capacity(16);
                stream
                    .take(64)
                    .read_to_end(&mut response)
                    .await
                    .map_err(|_| ObjectStorageError::ScannerUnavailable)?;
                if response
                    .strip_suffix(b"\0")
                    .or_else(|| response.strip_suffix(b"\n"))
                    == Some(b"PONG")
                {
                    Ok(())
                } else {
                    Err(ObjectStorageError::ScannerUnavailable)
                }
            })
            .await
            .map_err(|_| ObjectStorageError::ScannerUnavailable)?,
        }
    }

    pub async fn scan(&self, content: &[u8]) -> ObjectStorageResult<()> {
        match self {
            Self::Disabled => Err(ObjectStorageError::ScannerUnavailable),
            Self::ClamAv { address, timeout } => tokio::time::timeout(*timeout, async {
                let mut stream = tokio::net::TcpStream::connect(address.as_str())
                    .await
                    .map_err(|_| ObjectStorageError::ScannerUnavailable)?;
                stream
                    .write_all(b"zINSTREAM\0")
                    .await
                    .map_err(|_| ObjectStorageError::ScannerUnavailable)?;
                for chunk in content.chunks(64 * 1024) {
                    stream
                        .write_all(&(chunk.len() as u32).to_be_bytes())
                        .await
                        .map_err(|_| ObjectStorageError::ScannerUnavailable)?;
                    stream
                        .write_all(chunk)
                        .await
                        .map_err(|_| ObjectStorageError::ScannerUnavailable)?;
                }
                stream
                    .write_all(&0_u32.to_be_bytes())
                    .await
                    .map_err(|_| ObjectStorageError::ScannerUnavailable)?;
                let mut response = Vec::with_capacity(256);
                stream
                    .take(4096)
                    .read_to_end(&mut response)
                    .await
                    .map_err(|_| ObjectStorageError::ScannerUnavailable)?;
                let response = String::from_utf8_lossy(&response);
                if response.contains(" FOUND") {
                    Err(ObjectStorageError::MalwareDetected)
                } else if response.contains(" OK") {
                    Ok(())
                } else {
                    Err(ObjectStorageError::ScannerUnavailable)
                }
            })
            .await
            .map_err(|_| ObjectStorageError::ScannerUnavailable)?,
        }
    }
}

fn parse_clamav_address(value: &str) -> Result<String, String> {
    let invalid = || "CAMELLIA_NEXUS_CLAMAV_ADDRESS must be a valid host:port address".to_owned();
    let value = value.trim();
    if value.is_empty()
        || value.len() > 260
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(invalid());
    }

    if let Ok(address) = value.parse::<SocketAddr>() {
        return (address.port() != 0)
            .then(|| address.to_string())
            .ok_or_else(invalid);
    }

    let (host, port) = value.rsplit_once(':').ok_or_else(invalid)?;
    let port = port.parse::<u16>().map_err(|_| invalid())?;
    let dns_name = host.strip_suffix('.').unwrap_or(host);
    let valid_host = !dns_name.is_empty()
        && dns_name.len() <= 253
        && dns_name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.is_ascii()
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        });
    if port == 0 || !valid_host {
        return Err(invalid());
    }

    Ok(value.to_owned())
}

pub fn evidence_media_type(content: &[u8]) -> Option<&'static str> {
    if content.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some("image/png")
    } else if content.starts_with(&[0xff, 0xd8, 0xff]) {
        Some("image/jpeg")
    } else if content.starts_with(b"%PDF-") {
        Some("application/pdf")
    } else {
        None
    }
}

const SECRET_DELIVERY_TTL_SECONDS: i64 = 10 * 60;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretDeliveryTicket {
    pub id: String,
    pub claim_token: String,
    pub expires_at: i64,
}

pub struct SecretDeliveryPreparation {
    pub ticket: SecretDeliveryTicket,
    pub claim_token_hash: String,
}

pub struct ClaimedSecret {
    pub purpose: String,
    pub plaintext: Vec<u8>,
}

#[derive(Clone)]
pub struct SecretDeliveryService {
    repository: PostgresRepository,
    keyring: Arc<AdminKeyring>,
}

impl SecretDeliveryService {
    pub fn new(repository: PostgresRepository, keyring: Arc<AdminKeyring>) -> Self {
        Self {
            repository,
            keyring,
        }
    }

    pub fn prepare(&self, now: i64) -> SecretDeliveryPreparation {
        let claim_token = random_secret();
        let claim_token_hash = sha256_hex(&claim_token);
        SecretDeliveryPreparation {
            ticket: SecretDeliveryTicket {
                id: random_id("delivery"),
                claim_token,
                expires_at: now.saturating_add(SECRET_DELIVERY_TTL_SECONDS),
            },
            claim_token_hash,
        }
    }

    pub fn prepare_for_operation(
        &self,
        now: i64,
        operation_id: &str,
        actor_id: &str,
        session_id: &str,
    ) -> ObjectStorageResult<(SecretDeliveryPreparation, String)> {
        let key_id = self.keyring.active_key_id().to_owned();
        let claim_token =
            self.operation_claim_token(&key_id, operation_id, actor_id, session_id)?;
        let claim_token_hash = sha256_hex(&claim_token);
        Ok((
            SecretDeliveryPreparation {
                ticket: SecretDeliveryTicket {
                    id: random_id("delivery"),
                    claim_token,
                    expires_at: now.saturating_add(SECRET_DELIVERY_TTL_SECONDS),
                },
                claim_token_hash,
            },
            key_id,
        ))
    }

    pub fn replay_operation_ticket(
        &self,
        id: String,
        expires_at: i64,
        key_id: &str,
        operation_id: &str,
        actor_id: &str,
        session_id: &str,
    ) -> ObjectStorageResult<SecretDeliveryTicket> {
        Ok(SecretDeliveryTicket {
            id,
            claim_token: self.operation_claim_token(key_id, operation_id, actor_id, session_id)?,
            expires_at,
        })
    }

    fn operation_claim_token(
        &self,
        key_id: &str,
        operation_id: &str,
        actor_id: &str,
        session_id: &str,
    ) -> ObjectStorageResult<String> {
        self.keyring
            .deterministic_secret(
                key_id,
                b"admin-delivery-claim",
                &[operation_id, actor_id, session_id],
            )
            .map_err(Into::into)
    }

    pub fn seal(
        &self,
        delivery_id: &str,
        plaintext: &[u8],
    ) -> ObjectStorageResult<(String, Vec<u8>, Vec<u8>)> {
        self.keyring
            .seal(b"code-delivery", delivery_id.as_bytes(), plaintext)
            .map_err(Into::into)
    }

    pub async fn claim(
        &self,
        id: &str,
        claim_token: &str,
        context: &MutationContext,
        permission: AdminPermission,
        now: i64,
    ) -> ObjectStorageResult<ClaimedSecret> {
        let session_id = context
            .principal
            .session_id
            .as_deref()
            .ok_or(AdminAuthError::PermissionDenied)?;
        let mut tx = self
            .repository
            .pool
            .begin()
            .await
            .map_err(|_| ApiError::Database)?;
        authorize_admin_mutation(&mut tx, context, permission, false, now).await?;
        let row = sqlx::query(
            "SELECT purpose, key_id, nonce, ciphertext, claim_token_hash, expires_at, acknowledged_at
             FROM admin_secret_deliveries
             WHERE id = $1 AND actor_id = $2 AND session_id = $3
             FOR UPDATE",
        )
        .bind(id)
        .bind(&context.principal.id)
        .bind(session_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?
        .ok_or(ObjectStorageError::NotFound)?;
        let expected: String = row
            .try_get("claim_token_hash")
            .map_err(|_| ApiError::Database)?;
        let actual = sha256_hex(claim_token);
        if !bool::from(actual.as_bytes().ct_eq(expected.as_bytes())) {
            return Err(ObjectStorageError::NotFound);
        }
        let expires_at: i64 = row.try_get("expires_at").map_err(|_| ApiError::Database)?;
        let acknowledged_at: Option<i64> = row
            .try_get("acknowledged_at")
            .map_err(|_| ApiError::Database)?;
        if expires_at <= now || acknowledged_at.is_some() {
            return Err(ObjectStorageError::NotFound);
        }
        let key_id: String = row.try_get("key_id").map_err(|_| ApiError::Database)?;
        let nonce: Vec<u8> = row.try_get("nonce").map_err(|_| ApiError::Database)?;
        let ciphertext: Vec<u8> = row.try_get("ciphertext").map_err(|_| ApiError::Database)?;
        let plaintext = self.keyring.open(
            &key_id,
            b"code-delivery",
            id.as_bytes(),
            &nonce,
            &ciphertext,
        )?;
        sqlx::query(
            "UPDATE admin_secret_deliveries SET claimed_at = coalesce(claimed_at, $2)
             WHERE id = $1 AND acknowledged_at IS NULL AND expires_at > $2",
        )
        .bind(id)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        tx.commit().await.map_err(|_| ApiError::Database)?;
        Ok(ClaimedSecret {
            purpose: row.try_get("purpose").map_err(|_| ApiError::Database)?,
            plaintext,
        })
    }

    pub async fn acknowledge(
        &self,
        id: &str,
        claim_token: &str,
        context: &MutationContext,
        permission: AdminPermission,
        now: i64,
    ) -> ObjectStorageResult<()> {
        let session_id = context
            .principal
            .session_id
            .as_deref()
            .ok_or(AdminAuthError::PermissionDenied)?;
        let mut tx = self
            .repository
            .pool
            .begin()
            .await
            .map_err(|_| ApiError::Database)?;
        authorize_admin_mutation(&mut tx, context, permission, false, now).await?;
        let updated = sqlx::query(
            "UPDATE admin_secret_deliveries
             SET acknowledged_at = $5, key_id = '', nonce = ''::bytea, ciphertext = ''::bytea
             WHERE id = $1 AND actor_id = $2 AND session_id = $3
               AND claim_token_hash = $4 AND acknowledged_at IS NULL AND expires_at > $5",
        )
        .bind(id)
        .bind(&context.principal.id)
        .bind(session_id)
        .bind(sha256_hex(claim_token))
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?
        .rows_affected();
        if updated == 1 {
            tx.commit().await.map_err(|_| ApiError::Database)?;
            return Ok(());
        }
        let acknowledged: bool = sqlx::query_scalar(
            "SELECT EXISTS (
                 SELECT 1 FROM admin_secret_deliveries
                 WHERE id = $1 AND actor_id = $2 AND session_id = $3
                   AND claim_token_hash = $4 AND acknowledged_at IS NOT NULL
             )",
        )
        .bind(id)
        .bind(&context.principal.id)
        .bind(session_id)
        .bind(sha256_hex(claim_token))
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        if acknowledged {
            tx.commit().await.map_err(|_| ApiError::Database)?;
            Ok(())
        } else {
            Err(ObjectStorageError::NotFound)
        }
    }

    pub async fn acknowledgement_purpose(
        &self,
        id: &str,
        claim_token: &str,
        actor_id: &str,
        session_id: &str,
        now: i64,
    ) -> ObjectStorageResult<String> {
        let row = sqlx::query(
            "SELECT purpose, claim_token_hash, expires_at, acknowledged_at
             FROM admin_secret_deliveries
             WHERE id = $1 AND actor_id = $2 AND session_id = $3",
        )
        .bind(id)
        .bind(actor_id)
        .bind(session_id)
        .fetch_optional(&self.repository.pool)
        .await
        .map_err(|_| ApiError::Database)?
        .ok_or(ObjectStorageError::NotFound)?;
        let expected: String = row
            .try_get("claim_token_hash")
            .map_err(|_| ApiError::Database)?;
        let actual = sha256_hex(claim_token);
        if !bool::from(actual.as_bytes().ct_eq(expected.as_bytes())) {
            return Err(ObjectStorageError::NotFound);
        }
        let expires_at: i64 = row.try_get("expires_at").map_err(|_| ApiError::Database)?;
        let acknowledged_at: Option<i64> = row
            .try_get("acknowledged_at")
            .map_err(|_| ApiError::Database)?;
        if acknowledged_at.is_none() && expires_at <= now {
            return Err(ObjectStorageError::NotFound);
        }
        row.try_get("purpose")
            .map_err(|_| ApiError::Database.into())
    }

    pub async fn purge_expired(&self, now: i64) -> ObjectStorageResult<u64> {
        Ok(sqlx::query(
            "DELETE FROM admin_secret_deliveries
             WHERE expires_at <= $1 OR acknowledged_at IS NOT NULL",
        )
        .bind(now)
        .execute(&self.repository.pool)
        .await
        .map_err(|_| ApiError::Database)?
        .rows_affected())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectBackend {
    Filesystem,
    Database,
    S3,
}

impl ObjectBackend {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Filesystem => "filesystem",
            Self::Database => "database",
            Self::S3 => "s3",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StoredObjectStatus {
    Staging,
    Quarantined,
    Ready,
    Rejected,
    Deleting,
}

impl StoredObjectStatus {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Staging => "staging",
            Self::Quarantined => "quarantined",
            Self::Ready => "ready",
            Self::Rejected => "rejected",
            Self::Deleting => "deleting",
        }
    }

    fn parse(value: &str) -> ObjectStorageResult<Self> {
        match value {
            "staging" => Ok(Self::Staging),
            "quarantined" => Ok(Self::Quarantined),
            "ready" => Ok(Self::Ready),
            "rejected" => Ok(Self::Rejected),
            "deleting" => Ok(Self::Deleting),
            _ => Err(ApiError::Database.into()),
        }
    }

    const fn is_final(self) -> bool {
        matches!(self, Self::Quarantined | Self::Ready | Self::Rejected)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StagingReconciliation {
    Finalized,
    Removed,
    Unchanged,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExternalObjectReadError {
    Missing,
    Integrity,
    Backend,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredObject {
    pub id: String,
    pub namespace: String,
    pub backend: ObjectBackend,
    pub media_type: String,
    pub original_name: Option<String>,
    pub byte_length: i64,
    pub sha256: String,
    pub status: StoredObjectStatus,
    pub created_by: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ObjectStorageStatus {
    pub backend: ObjectBackend,
    pub object_count: i64,
    pub stored_bytes: i64,
    pub hard_limit_bytes: i64,
    pub usage_ratio: f64,
}

struct ObjectEnvelope<'a> {
    key_id: &'a str,
    wrapped_key_nonce: &'a [u8],
    wrapped_key: &'a [u8],
    content_nonce: &'a [u8],
}

#[derive(Debug, Clone)]
pub struct ObjectStorageConfig {
    pub backend: ObjectBackend,
    pub filesystem_root: Option<PathBuf>,
    pub s3_bucket: Option<String>,
    pub hard_limit_bytes: i64,
    pub max_object_bytes: usize,
}

impl ObjectStorageConfig {
    pub fn from_env() -> Result<Self, String> {
        let backend = match env::var("CAMELLIA_NEXUS_OBJECT_STORAGE")
            .unwrap_or_else(|_| "database".to_owned())
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "filesystem" => ObjectBackend::Filesystem,
            "database" => ObjectBackend::Database,
            "s3" => ObjectBackend::S3,
            _ => {
                return Err(
                    "CAMELLIA_NEXUS_OBJECT_STORAGE must be filesystem, database or s3".to_owned(),
                );
            }
        };
        let filesystem_root = env::var("CAMELLIA_NEXUS_OBJECT_FILESYSTEM_ROOT")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .map(PathBuf::from)
            .or_else(|| {
                (backend == ObjectBackend::Filesystem).then(|| PathBuf::from("data/admin-objects"))
            });
        let s3_bucket = env::var("CAMELLIA_NEXUS_OBJECT_S3_BUCKET")
            .ok()
            .filter(|value| !value.trim().is_empty());
        if backend == ObjectBackend::S3 && s3_bucket.is_none() {
            return Err("CAMELLIA_NEXUS_OBJECT_S3_BUCKET is required for S3 storage".to_owned());
        }
        let hard_limit_bytes = env_i64(
            "CAMELLIA_NEXUS_OBJECT_HARD_LIMIT_BYTES",
            DEFAULT_DATABASE_HARD_LIMIT_BYTES,
        )?;
        let max_object_bytes = usize::try_from(env_i64(
            "CAMELLIA_NEXUS_OBJECT_MAX_BYTES",
            DEFAULT_MAX_OBJECT_BYTES as i64,
        )?)
        .map_err(|_| "CAMELLIA_NEXUS_OBJECT_MAX_BYTES is too large".to_owned())?;
        if hard_limit_bytes <= 0 || max_object_bytes == 0 {
            return Err("object storage limits must be greater than zero".to_owned());
        }
        Ok(Self {
            backend,
            filesystem_root,
            s3_bucket,
            hard_limit_bytes,
            max_object_bytes,
        })
    }
}

enum BlobBackend {
    Database,
    External(Arc<dyn ObjectStore>),
}

#[derive(Clone)]
pub struct ObjectStorageService {
    repository: PostgresRepository,
    application: AdminApplication,
    keyring: Arc<AdminKeyring>,
    backend_kind: ObjectBackend,
    backend: Arc<BlobBackend>,
    hard_limit_bytes: i64,
    max_object_bytes: usize,
}

impl ObjectStorageService {
    pub fn new(
        application: AdminApplication,
        keyring: Arc<AdminKeyring>,
        config: ObjectStorageConfig,
    ) -> ObjectStorageResult<Self> {
        let backend = match config.backend {
            ObjectBackend::Database => BlobBackend::Database,
            ObjectBackend::Filesystem => {
                let root = config.filesystem_root.ok_or_else(|| {
                    ObjectStorageError::Validation("filesystem root is required".to_owned())
                })?;
                std::fs::create_dir_all(&root).map_err(|_| ObjectStorageError::Backend)?;
                let store = LocalFileSystem::new_with_prefix(root)
                    .map_err(|_| ObjectStorageError::Backend)?;
                BlobBackend::External(Arc::new(store))
            }
            ObjectBackend::S3 => {
                let store = AmazonS3Builder::from_env()
                    .with_bucket_name(config.s3_bucket.ok_or_else(|| {
                        ObjectStorageError::Validation("S3 bucket is required".to_owned())
                    })?)
                    .build()
                    .map_err(|_| ObjectStorageError::Backend)?;
                BlobBackend::External(Arc::new(store))
            }
        };
        Ok(Self {
            repository: application.repository().clone(),
            application,
            keyring,
            backend_kind: config.backend,
            backend: Arc::new(backend),
            hard_limit_bytes: config.hard_limit_bytes,
            max_object_bytes: config.max_object_bytes,
        })
    }

    pub async fn readiness_check(&self) -> ObjectStorageResult<()> {
        match self.backend.as_ref() {
            BlobBackend::Database => Ok(()),
            BlobBackend::External(store) => external_backend_readiness(store.as_ref()).await,
        }
    }

    async fn trusted_now(&self) -> ObjectStorageResult<i64> {
        self.application
            .trusted_now()
            .await
            .map_err(|error| match error {
                AdminAppError::Service(error) => ObjectStorageError::Service(error),
                _ => ObjectStorageError::Service(ApiError::Internal),
            })
    }

    pub async fn put(
        &self,
        namespace: &str,
        media_type: &str,
        original_name: Option<&str>,
        plaintext: &[u8],
        created_by: &str,
        status: StoredObjectStatus,
    ) -> ObjectStorageResult<StoredObject> {
        validate_namespace(namespace)?;
        validate_media_type(media_type)?;
        if !status.is_final() {
            return Err(ObjectStorageError::Validation(
                "new objects must target quarantined, ready or rejected status".to_owned(),
            ));
        }
        if plaintext.is_empty() || plaintext.len() > self.max_object_bytes {
            return Err(ObjectStorageError::Validation(format!(
                "object must contain 1 to {} bytes",
                self.max_object_bytes
            )));
        }
        if original_name.is_some_and(|name| name.is_empty() || name.chars().count() > 255) {
            return Err(ObjectStorageError::Validation(
                "original filename must contain 1 to 255 characters".to_owned(),
            ));
        }
        let byte_length = i64::try_from(plaintext.len())
            .map_err(|_| ObjectStorageError::Validation("object is too large".to_owned()))?;
        let id = random_id("object");
        let locator = format!("{namespace}/{id}.cnxo");
        let now = self.trusted_now().await?;
        let mut data_key = [0_u8; 32];
        let mut content_nonce = [0_u8; 24];
        rand::fill(&mut data_key);
        rand::fill(&mut content_nonce);
        let aad = object_aad(&id, namespace, media_type, byte_length);
        let nonce_value = XNonce::from(content_nonce);
        let ciphertext = XChaCha20Poly1305::new((&data_key).into())
            .encrypt(
                &nonce_value,
                Payload {
                    msg: plaintext,
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| ObjectStorageError::Integrity)?;
        let (key_id, wrapped_key_nonce, wrapped_key) =
            self.keyring.seal(b"object-key", id.as_bytes(), &data_key)?;
        data_key.zeroize();
        let object = StoredObject {
            id: id.clone(),
            namespace: namespace.to_owned(),
            backend: self.backend_kind,
            media_type: media_type.to_owned(),
            original_name: original_name.map(str::to_owned),
            byte_length,
            sha256: sha256_bytes_hex(plaintext),
            status,
            created_by: created_by.to_owned(),
            created_at: now,
        };
        match self.backend.as_ref() {
            BlobBackend::Database => {
                let mut tx = self
                    .repository
                    .pool
                    .begin()
                    .await
                    .map_err(|_| ApiError::Database)?;
                ensure_storage_quota(&mut tx, byte_length, self.hard_limit_bytes).await?;
                insert_object_metadata(
                    &mut tx,
                    &object,
                    &locator,
                    ObjectEnvelope {
                        key_id: &key_id,
                        wrapped_key_nonce: &wrapped_key_nonce,
                        wrapped_key: &wrapped_key,
                        content_nonce: &content_nonce,
                    },
                    status,
                    None,
                )
                .await?;
                for (index, chunk) in ciphertext.chunks(DATABASE_CHUNK_SIZE).enumerate() {
                    sqlx::query(
                        "INSERT INTO stored_object_chunks (object_id, chunk_index, ciphertext)
                         VALUES ($1, $2, $3)",
                    )
                    .bind(&id)
                    .bind(i32::try_from(index).map_err(|_| ObjectStorageError::Backend)?)
                    .bind(chunk)
                    .execute(&mut *tx)
                    .await
                    .map_err(|_| ApiError::Database)?;
                }
                tx.commit().await.map_err(|_| ApiError::Database)?;
            }
            BlobBackend::External(store) => {
                let mut tx = self
                    .repository
                    .pool
                    .begin()
                    .await
                    .map_err(|_| ApiError::Database)?;
                ensure_storage_quota(&mut tx, byte_length, self.hard_limit_bytes).await?;
                insert_object_metadata(
                    &mut tx,
                    &object,
                    &locator,
                    ObjectEnvelope {
                        key_id: &key_id,
                        wrapped_key_nonce: &wrapped_key_nonce,
                        wrapped_key: &wrapped_key,
                        content_nonce: &content_nonce,
                    },
                    StoredObjectStatus::Staging,
                    Some(status),
                )
                .await?;
                tx.commit().await.map_err(|_| ApiError::Database)?;
                if store
                    .put(
                        &ObjectPath::from(locator.as_str()),
                        Bytes::from(ciphertext).into(),
                    )
                    .await
                    .is_err()
                {
                    return Err(ObjectStorageError::Backend);
                }
                self.finalize_staging(&id, status, now).await?;
            }
        }
        Ok(object)
    }

    pub async fn get(&self, id: &str) -> ObjectStorageResult<(StoredObject, Bytes)> {
        self.get_with_status(id, false).await
    }

    pub async fn get_for_scan(&self, id: &str) -> ObjectStorageResult<(StoredObject, Bytes)> {
        self.get_with_status(id, true).await
    }

    async fn get_with_status(
        &self,
        id: &str,
        allow_quarantined: bool,
    ) -> ObjectStorageResult<(StoredObject, Bytes)> {
        let row = sqlx::query(
            "SELECT id, namespace, backend, locator, media_type, original_name, byte_length,
                    sha256, key_id, wrapped_key_nonce, wrapped_key, content_nonce,
                    status, created_by, created_at
             FROM stored_objects WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.repository.pool)
        .await
        .map_err(|_| ApiError::Database)?
        .ok_or(ObjectStorageError::NotFound)?;
        let object = row_object(&row)?;
        if object.status != StoredObjectStatus::Ready
            && !(allow_quarantined && object.status == StoredObjectStatus::Quarantined)
        {
            return Err(ObjectStorageError::NotReady);
        }
        let backend = parse_backend(
            &row.try_get::<String, _>("backend")
                .map_err(|_| ApiError::Database)?,
        )?;
        if backend != self.backend_kind {
            return Err(ObjectStorageError::Backend);
        }
        let locator: String = row.try_get("locator").map_err(|_| ApiError::Database)?;
        let ciphertext = match self.backend.as_ref() {
            BlobBackend::Database => {
                let chunks: Vec<Vec<u8>> = sqlx::query_scalar(
                    "SELECT ciphertext FROM stored_object_chunks
                     WHERE object_id = $1 ORDER BY chunk_index ASC",
                )
                .bind(id)
                .fetch_all(&self.repository.pool)
                .await
                .map_err(|_| ApiError::Database)?;
                chunks.concat()
            }
            BlobBackend::External(store) => {
                let expected_size =
                    expected_ciphertext_size(object.byte_length, self.max_object_bytes)?;
                read_external_ciphertext(
                    store.as_ref(),
                    &ObjectPath::from(locator.as_str()),
                    expected_size,
                )
                .await
                .map_err(|error| match error {
                    ExternalObjectReadError::Integrity => ObjectStorageError::Integrity,
                    ExternalObjectReadError::Missing | ExternalObjectReadError::Backend => {
                        ObjectStorageError::Backend
                    }
                })?
            }
        };
        let plaintext = self.decrypt_and_validate(&row, &object, &ciphertext)?;
        Ok((object, plaintext))
    }

    async fn finalize_staging(
        &self,
        id: &str,
        target: StoredObjectStatus,
        now: i64,
    ) -> ObjectStorageResult<()> {
        if !target.is_final() {
            return Err(ObjectStorageError::Integrity);
        }
        let updated = sqlx::query(
            "UPDATE stored_objects
             SET status = $2, staging_target_status = NULL, updated_at = $3
             WHERE id = $1 AND status = 'staging' AND staging_target_status = $2",
        )
        .bind(id)
        .bind(target.as_str())
        .bind(now)
        .execute(&self.repository.pool)
        .await
        .map_err(|_| ApiError::Database)?
        .rows_affected();
        if updated == 1 {
            return Ok(());
        }
        let finalized: bool = sqlx::query_scalar(
            "SELECT EXISTS (
                 SELECT 1 FROM stored_objects
                 WHERE id = $1 AND status = $2 AND staging_target_status IS NULL
             )",
        )
        .bind(id)
        .bind(target.as_str())
        .fetch_one(&self.repository.pool)
        .await
        .map_err(|_| ApiError::Database)?;
        if finalized {
            Ok(())
        } else {
            Err(ObjectStorageError::Backend)
        }
    }

    pub(crate) async fn reconcile_staging(
        &self,
        id: &str,
        now: i64,
    ) -> ObjectStorageResult<StagingReconciliation> {
        let Some(row) = sqlx::query(
            "SELECT id, namespace, backend, locator, media_type, original_name, byte_length,
                    sha256, key_id, wrapped_key_nonce, wrapped_key, content_nonce,
                    status, staging_target_status, created_by, created_at
             FROM stored_objects WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.repository.pool)
        .await
        .map_err(|_| ApiError::Database)?
        else {
            return Ok(StagingReconciliation::Unchanged);
        };
        let object = row_object(&row)?;
        if object.status != StoredObjectStatus::Staging {
            return Ok(StagingReconciliation::Unchanged);
        }
        let target = row
            .try_get::<Option<String>, _>("staging_target_status")
            .map_err(|_| ApiError::Database)?
            .ok_or(ObjectStorageError::Integrity)
            .and_then(|status| StoredObjectStatus::parse(&status))?;
        if !target.is_final() {
            return Err(ObjectStorageError::Integrity);
        }
        let backend = parse_backend(
            &row.try_get::<String, _>("backend")
                .map_err(|_| ApiError::Database)?,
        )?;
        if backend != self.backend_kind {
            return Err(ObjectStorageError::Backend);
        }
        let BlobBackend::External(store) = self.backend.as_ref() else {
            return Err(ObjectStorageError::Backend);
        };
        let locator: String = row.try_get("locator").map_err(|_| ApiError::Database)?;
        let path = ObjectPath::from(locator.as_str());
        let expected_size =
            match expected_ciphertext_size(object.byte_length, self.max_object_bytes) {
                Ok(size) => size,
                Err(ObjectStorageError::Integrity) => {
                    return self.discard_staging(id, store.as_ref(), &path, now).await;
                }
                Err(error) => return Err(error),
            };
        let ciphertext = match read_external_ciphertext(store.as_ref(), &path, expected_size).await
        {
            Ok(ciphertext) => ciphertext,
            Err(ExternalObjectReadError::Missing | ExternalObjectReadError::Integrity) => {
                return self.discard_staging(id, store.as_ref(), &path, now).await;
            }
            Err(ExternalObjectReadError::Backend) => {
                return Err(ObjectStorageError::Backend);
            }
        };
        match self.decrypt_and_validate(&row, &object, &ciphertext) {
            Ok(_) => {
                self.finalize_staging(id, target, now).await?;
                Ok(StagingReconciliation::Finalized)
            }
            Err(ObjectStorageError::Integrity) => {
                self.discard_staging(id, store.as_ref(), &path, now).await
            }
            Err(error) => Err(error),
        }
    }

    async fn discard_staging(
        &self,
        id: &str,
        store: &dyn ObjectStore,
        path: &ObjectPath,
        now: i64,
    ) -> ObjectStorageResult<StagingReconciliation> {
        let claimed = sqlx::query(
            "UPDATE stored_objects
             SET status = 'deleting', staging_target_status = NULL, updated_at = $2
             WHERE id = $1 AND status = 'staging'",
        )
        .bind(id)
        .bind(now)
        .execute(&self.repository.pool)
        .await
        .map_err(|_| ApiError::Database)?
        .rows_affected();
        if claimed == 0 {
            return Ok(StagingReconciliation::Unchanged);
        }
        match store.delete(path).await {
            Ok(()) | Err(object_store::Error::NotFound { .. }) => {}
            Err(_) => return Err(ObjectStorageError::Backend),
        }
        sqlx::query("DELETE FROM stored_objects WHERE id = $1 AND status = 'deleting'")
            .bind(id)
            .execute(&self.repository.pool)
            .await
            .map_err(|_| ApiError::Database)?;
        Ok(StagingReconciliation::Removed)
    }

    fn decrypt_and_validate(
        &self,
        row: &sqlx::postgres::PgRow,
        object: &StoredObject,
        ciphertext: &[u8],
    ) -> ObjectStorageResult<Bytes> {
        let key_id: String = row.try_get("key_id").map_err(|_| ApiError::Database)?;
        let wrapped_key_nonce: Vec<u8> = row
            .try_get("wrapped_key_nonce")
            .map_err(|_| ApiError::Database)?;
        let wrapped_key: Vec<u8> = row.try_get("wrapped_key").map_err(|_| ApiError::Database)?;
        let content_nonce: [u8; 24] = row
            .try_get::<Vec<u8>, _>("content_nonce")
            .map_err(|_| ApiError::Database)?
            .try_into()
            .map_err(|_| ObjectStorageError::Integrity)?;
        let mut data_key = self.keyring.open(
            &key_id,
            b"object-key",
            object.id.as_bytes(),
            &wrapped_key_nonce,
            &wrapped_key,
        )?;
        let mut data_key_array: [u8; 32] = match data_key.as_slice().try_into() {
            Ok(key) => key,
            Err(_) => {
                data_key.zeroize();
                return Err(ObjectStorageError::Integrity);
            }
        };
        let aad = object_aad(
            &object.id,
            &object.namespace,
            &object.media_type,
            object.byte_length,
        );
        let decrypted = XChaCha20Poly1305::new((&data_key_array).into()).decrypt(
            &XNonce::from(content_nonce),
            Payload {
                msg: ciphertext,
                aad: aad.as_bytes(),
            },
        );
        data_key.zeroize();
        data_key_array.zeroize();
        let plaintext = decrypted.map_err(|_| ObjectStorageError::Integrity)?;
        let actual = Sha256::digest(&plaintext);
        let expected = hex_digest(&object.sha256)?;
        if i64::try_from(plaintext.len()).ok() != Some(object.byte_length)
            || !bool::from(actual.as_slice().ct_eq(&expected))
        {
            return Err(ObjectStorageError::Integrity);
        }
        Ok(Bytes::from(plaintext))
    }

    pub async fn set_status(
        &self,
        id: &str,
        status: StoredObjectStatus,
    ) -> ObjectStorageResult<()> {
        let updated = sqlx::query(
            "UPDATE stored_objects SET status = $2, updated_at = $3
             WHERE id = $1 AND status IN ('quarantined', 'ready')",
        )
        .bind(id)
        .bind(status.as_str())
        .bind(self.trusted_now().await?)
        .execute(&self.repository.pool)
        .await
        .map_err(|_| ApiError::Database)?
        .rows_affected();
        if updated == 1 {
            Ok(())
        } else {
            Err(ObjectStorageError::NotFound)
        }
    }

    pub(crate) async fn set_status_in_transaction(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        id: &str,
        status: StoredObjectStatus,
        now: i64,
    ) -> ObjectStorageResult<()> {
        let updated = sqlx::query(
            "UPDATE stored_objects SET status = $2, updated_at = $3
             WHERE id = $1 AND status IN ('quarantined', 'ready')",
        )
        .bind(id)
        .bind(status.as_str())
        .bind(now)
        .execute(&mut **tx)
        .await
        .map_err(|_| ApiError::Database)?
        .rows_affected();
        if updated == 1 {
            Ok(())
        } else {
            Err(ObjectStorageError::NotFound)
        }
    }

    pub async fn delete(&self, id: &str) -> ObjectStorageResult<()> {
        let row = sqlx::query("SELECT backend, locator FROM stored_objects WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.repository.pool)
            .await
            .map_err(|_| ApiError::Database)?
            .ok_or(ObjectStorageError::NotFound)?;
        let backend = parse_backend(
            &row.try_get::<String, _>("backend")
                .map_err(|_| ApiError::Database)?,
        )?;
        if backend != self.backend_kind {
            return Err(ObjectStorageError::Backend);
        }
        let locator: String = row.try_get("locator").map_err(|_| ApiError::Database)?;
        sqlx::query(
            "UPDATE stored_objects
             SET status = 'deleting', staging_target_status = NULL, updated_at = $2
             WHERE id = $1",
        )
        .bind(id)
        .bind(self.trusted_now().await?)
        .execute(&self.repository.pool)
        .await
        .map_err(|_| ApiError::Database)?;
        if let BlobBackend::External(store) = self.backend.as_ref() {
            match store.delete(&ObjectPath::from(locator.as_str())).await {
                Ok(()) | Err(object_store::Error::NotFound { .. }) => {}
                Err(_) => return Err(ObjectStorageError::Backend),
            }
        }
        sqlx::query("DELETE FROM stored_objects WHERE id = $1 AND status = 'deleting'")
            .bind(id)
            .execute(&self.repository.pool)
            .await
            .map_err(|_| ApiError::Database)?;
        Ok(())
    }

    pub async fn status(&self) -> ObjectStorageResult<ObjectStorageStatus> {
        let row = sqlx::query(
            "SELECT count(*) AS object_count, coalesce(sum(byte_length), 0)::bigint AS stored_bytes
             FROM stored_objects WHERE status <> 'deleting'",
        )
        .fetch_one(&self.repository.pool)
        .await
        .map_err(|_| ApiError::Database)?;
        let object_count = row
            .try_get("object_count")
            .map_err(|_| ApiError::Database)?;
        let stored_bytes: i64 = row
            .try_get("stored_bytes")
            .map_err(|_| ApiError::Database)?;
        Ok(ObjectStorageStatus {
            backend: self.backend_kind,
            object_count,
            stored_bytes,
            hard_limit_bytes: self.hard_limit_bytes,
            usage_ratio: stored_bytes as f64 / self.hard_limit_bytes as f64,
        })
    }
}

async fn external_backend_readiness(store: &dyn ObjectStore) -> ObjectStorageResult<()> {
    let prefix = ObjectPath::from(OBJECT_STORAGE_READINESS_PREFIX);
    tokio::time::timeout(
        OBJECT_STORAGE_READINESS_TIMEOUT,
        store.list_with_delimiter(Some(&prefix)),
    )
    .await
    .map_err(|_| ObjectStorageError::Backend)?
    .map(|_| ())
    .map_err(|_| ObjectStorageError::Backend)
}

async fn ensure_storage_quota(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    incoming_bytes: i64,
    hard_limit_bytes: i64,
) -> ObjectStorageResult<()> {
    sqlx::query("SELECT pg_advisory_xact_lock(1128354383)")
        .execute(&mut **tx)
        .await
        .map_err(|_| ApiError::Database)?;
    let stored_bytes: i64 = sqlx::query_scalar(
        "SELECT coalesce(sum(byte_length), 0)::bigint
         FROM stored_objects WHERE status <> 'deleting'",
    )
    .fetch_one(&mut **tx)
    .await
    .map_err(|_| ApiError::Database)?;
    if stored_bytes.saturating_add(incoming_bytes) > hard_limit_bytes {
        Err(ObjectStorageError::QuotaExceeded)
    } else {
        Ok(())
    }
}

fn expected_ciphertext_size(
    plaintext_size: i64,
    max_object_bytes: usize,
) -> ObjectStorageResult<u64> {
    let plaintext_size =
        u64::try_from(plaintext_size).map_err(|_| ObjectStorageError::Integrity)?;
    let max_object_bytes =
        u64::try_from(max_object_bytes).map_err(|_| ObjectStorageError::Integrity)?;
    if plaintext_size == 0 || plaintext_size > max_object_bytes {
        return Err(ObjectStorageError::Integrity);
    }
    plaintext_size
        .checked_add(XCHACHA20_POLY1305_TAG_BYTES)
        .ok_or(ObjectStorageError::Integrity)
}

async fn read_external_ciphertext(
    store: &dyn ObjectStore,
    path: &ObjectPath,
    expected_size: u64,
) -> Result<Vec<u8>, ExternalObjectReadError> {
    let head = store
        .head(path)
        .await
        .map_err(classify_external_read_error)?;
    if head.location != *path || head.size != expected_size {
        return Err(ExternalObjectReadError::Integrity);
    }
    let options = GetOptions::new()
        .with_if_match(head.e_tag.clone())
        .with_version(head.version.clone());
    let result = store
        .get_opts(path, options)
        .await
        .map_err(classify_external_read_error)?;
    if result.meta.location != *path
        || result.meta.size != expected_size
        || result.range != (0..expected_size)
        || (head.e_tag.is_some() && result.meta.e_tag.as_deref() != head.e_tag.as_deref())
        || (head.version.is_some() && result.meta.version.as_deref() != head.version.as_deref())
    {
        return Err(ExternalObjectReadError::Integrity);
    }
    let expected_size =
        usize::try_from(expected_size).map_err(|_| ExternalObjectReadError::Integrity)?;
    let mut ciphertext = Vec::with_capacity(expected_size);
    let mut stream = result.into_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(classify_external_read_error)?;
        let next_size = ciphertext
            .len()
            .checked_add(chunk.len())
            .ok_or(ExternalObjectReadError::Integrity)?;
        if next_size > expected_size {
            return Err(ExternalObjectReadError::Integrity);
        }
        ciphertext.extend_from_slice(&chunk);
    }
    if ciphertext.len() != expected_size {
        return Err(ExternalObjectReadError::Integrity);
    }
    Ok(ciphertext)
}

fn classify_external_read_error(error: object_store::Error) -> ExternalObjectReadError {
    match error {
        object_store::Error::NotFound { .. } => ExternalObjectReadError::Missing,
        _ => ExternalObjectReadError::Backend,
    }
}

async fn insert_object_metadata(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    object: &StoredObject,
    locator: &str,
    envelope: ObjectEnvelope<'_>,
    status: StoredObjectStatus,
    staging_target_status: Option<StoredObjectStatus>,
) -> ObjectStorageResult<()> {
    sqlx::query(
        "INSERT INTO stored_objects
         (id, namespace, backend, locator, media_type, original_name, byte_length,
          sha256, key_id, wrapped_key_nonce, wrapped_key, content_nonce,
          status, staging_target_status, created_by, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $16)",
    )
    .bind(&object.id)
    .bind(&object.namespace)
    .bind(object.backend.as_str())
    .bind(locator)
    .bind(&object.media_type)
    .bind(&object.original_name)
    .bind(object.byte_length)
    .bind(&object.sha256)
    .bind(envelope.key_id)
    .bind(envelope.wrapped_key_nonce)
    .bind(envelope.wrapped_key)
    .bind(envelope.content_nonce)
    .bind(status.as_str())
    .bind(staging_target_status.map(StoredObjectStatus::as_str))
    .bind(&object.created_by)
    .bind(object.created_at)
    .execute(&mut **tx)
    .await
    .map_err(|_| ApiError::Database)?;
    Ok(())
}

fn row_object(row: &sqlx::postgres::PgRow) -> ObjectStorageResult<StoredObject> {
    Ok(StoredObject {
        id: row.try_get("id").map_err(|_| ApiError::Database)?,
        namespace: row.try_get("namespace").map_err(|_| ApiError::Database)?,
        backend: parse_backend(
            &row.try_get::<String, _>("backend")
                .map_err(|_| ApiError::Database)?,
        )?,
        media_type: row.try_get("media_type").map_err(|_| ApiError::Database)?,
        original_name: row
            .try_get("original_name")
            .map_err(|_| ApiError::Database)?,
        byte_length: row.try_get("byte_length").map_err(|_| ApiError::Database)?,
        sha256: row.try_get("sha256").map_err(|_| ApiError::Database)?,
        status: StoredObjectStatus::parse(
            &row.try_get::<String, _>("status")
                .map_err(|_| ApiError::Database)?,
        )?,
        created_by: row.try_get("created_by").map_err(|_| ApiError::Database)?,
        created_at: row.try_get("created_at").map_err(|_| ApiError::Database)?,
    })
}

fn parse_backend(value: &str) -> ObjectStorageResult<ObjectBackend> {
    match value {
        "filesystem" => Ok(ObjectBackend::Filesystem),
        "database" => Ok(ObjectBackend::Database),
        "s3" => Ok(ObjectBackend::S3),
        _ => Err(ApiError::Database.into()),
    }
}

fn validate_namespace(value: &str) -> ObjectStorageResult<()> {
    if value.is_empty()
        || value.len() > 64
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
    {
        return Err(ObjectStorageError::Validation(
            "namespace must use lowercase ASCII letters, digits, dashes or underscores".to_owned(),
        ));
    }
    Ok(())
}

fn validate_media_type(value: &str) -> ObjectStorageResult<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'+' | b'.'))
    {
        return Err(ObjectStorageError::Validation(
            "media type is invalid".to_owned(),
        ));
    }
    Ok(())
}

fn object_aad(id: &str, namespace: &str, media_type: &str, byte_length: i64) -> String {
    format!("{id}\0{namespace}\0{media_type}\0{byte_length}")
}

fn hex_digest(value: &str) -> ObjectStorageResult<[u8; 32]> {
    if value.len() != 64 {
        return Err(ObjectStorageError::Integrity);
    }
    let mut output = [0_u8; 32];
    for (index, slot) in output.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| ObjectStorageError::Integrity)?;
    }
    Ok(output)
}

fn sha256_bytes_hex(value: &[u8]) -> String {
    Sha256::digest(value)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn env_i64(key: &str, default: i64) -> Result<i64, String> {
    env::var(key)
        .ok()
        .map(|value| {
            value
                .parse()
                .map_err(|_| format!("{key} must be an integer"))
        })
        .transpose()
        .map(|value| value.unwrap_or(default))
}

#[cfg(test)]
mod tests {
    use std::{
        fmt,
        ops::Range,
        sync::{
            Mutex,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use futures_util::stream::BoxStream;
    use object_store::{
        CopyOptions, GetResult, ListResult, MultipartUpload, ObjectMeta, PutMultipartOptions,
        PutOptions, PutPayload, PutResult, Result as ObjectStoreResult, memory::InMemory,
    };

    use super::*;

    #[derive(Debug, Default)]
    struct FakeObjectStore {
        inner: InMemory,
        fail_next_put_after_write: AtomicBool,
        fail_readiness: AtomicBool,
        reported_size: Mutex<Option<u64>>,
        body_gets: AtomicUsize,
    }

    impl FakeObjectStore {
        fn ambiguous_put() -> Self {
            Self {
                fail_next_put_after_write: AtomicBool::new(true),
                ..Self::default()
            }
        }

        fn unavailable() -> Self {
            Self {
                fail_readiness: AtomicBool::new(true),
                ..Self::default()
            }
        }

        async fn overwrite(&self, path: &ObjectPath, value: Vec<u8>) {
            self.inner
                .put(path, Bytes::from(value).into())
                .await
                .expect("overwrite fake object");
        }

        fn report_size(&self, size: Option<u64>) {
            *self.reported_size.lock().expect("lock fake reported size") = size;
        }

        fn body_gets(&self) -> usize {
            self.body_gets.load(Ordering::SeqCst)
        }
    }

    impl fmt::Display for FakeObjectStore {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("FakeObjectStore")
        }
    }

    #[async_trait::async_trait]
    impl ObjectStore for FakeObjectStore {
        async fn put_opts(
            &self,
            location: &ObjectPath,
            payload: PutPayload,
            options: PutOptions,
        ) -> ObjectStoreResult<PutResult> {
            let result = self.inner.put_opts(location, payload, options).await?;
            if self.fail_next_put_after_write.swap(false, Ordering::SeqCst) {
                return Err(object_store::Error::Generic {
                    store: "fake",
                    source: Box::new(std::io::Error::other(
                        "put completed before the response failed",
                    )),
                });
            }
            Ok(result)
        }

        async fn put_multipart_opts(
            &self,
            location: &ObjectPath,
            options: PutMultipartOptions,
        ) -> ObjectStoreResult<Box<dyn MultipartUpload>> {
            self.inner.put_multipart_opts(location, options).await
        }

        async fn get_opts(
            &self,
            location: &ObjectPath,
            options: GetOptions,
        ) -> ObjectStoreResult<GetResult> {
            let head = options.head;
            let mut result = self.inner.get_opts(location, options).await?;
            if !head {
                self.body_gets.fetch_add(1, Ordering::SeqCst);
            }
            if let Some(size) = *self.reported_size.lock().expect("lock fake reported size") {
                result.meta.size = size;
                result.range = 0..size;
            }
            Ok(result)
        }

        fn delete_stream(
            &self,
            locations: BoxStream<'static, ObjectStoreResult<ObjectPath>>,
        ) -> BoxStream<'static, ObjectStoreResult<ObjectPath>> {
            self.inner.delete_stream(locations)
        }

        fn list(
            &self,
            prefix: Option<&ObjectPath>,
        ) -> BoxStream<'static, ObjectStoreResult<ObjectMeta>> {
            self.inner.list(prefix)
        }

        async fn list_with_delimiter(
            &self,
            prefix: Option<&ObjectPath>,
        ) -> ObjectStoreResult<ListResult> {
            if self.fail_readiness.load(Ordering::SeqCst) {
                return Err(object_store::Error::Generic {
                    store: "fake",
                    source: Box::new(std::io::Error::other("object backend is unavailable")),
                });
            }
            self.inner.list_with_delimiter(prefix).await
        }

        async fn copy_opts(
            &self,
            from: &ObjectPath,
            to: &ObjectPath,
            options: CopyOptions,
        ) -> ObjectStoreResult<()> {
            self.inner.copy_opts(from, to, options).await
        }

        async fn get_ranges(
            &self,
            location: &ObjectPath,
            ranges: &[Range<u64>],
        ) -> ObjectStoreResult<Vec<Bytes>> {
            self.inner.get_ranges(location, ranges).await
        }
    }

    async fn external_test_storage(
        store: Arc<dyn ObjectStore>,
        max_object_bytes: usize,
    ) -> (PostgresRepository, ObjectStorageService) {
        let database_url = std::env::var("TEST_DATABASE_URL")
            .expect("TEST_DATABASE_URL is required for the PostgreSQL integration test");
        let repository = PostgresRepository::connect(&database_url, 2, Duration::from_secs(5))
            .await
            .expect("connect PostgreSQL");
        repository.migrate().await.expect("run migrations");
        let application = AdminApplication::new(repository.clone(), 24 * 60 * 60)
            .await
            .expect("initialize admin application");
        let storage = ObjectStorageService {
            repository: repository.clone(),
            application,
            keyring: Arc::new(AdminKeyring::ephemeral()),
            backend_kind: ObjectBackend::Filesystem,
            backend: Arc::new(BlobBackend::External(store)),
            hard_limit_bytes: 1024 * 1024,
            max_object_bytes,
        };
        (repository, storage)
    }

    #[test]
    fn namespaces_and_media_types_are_strict() {
        assert!(validate_namespace("payment_evidence").is_ok());
        assert!(validate_namespace("../escape").is_err());
        assert!(validate_media_type("application/pdf").is_ok());
        assert!(validate_media_type("text/html; charset=utf-8").is_err());
    }

    #[test]
    fn digest_parser_rejects_non_hex_values() {
        assert!(hex_digest(&"a".repeat(64)).is_ok());
        assert!(hex_digest(&"z".repeat(64)).is_err());
    }

    #[test]
    fn evidence_type_comes_from_file_signature() {
        assert_eq!(
            evidence_media_type(b"\x89PNG\r\n\x1a\ncontent"),
            Some("image/png")
        );
        assert_eq!(evidence_media_type(b"%PDF-1.7\n"), Some("application/pdf"));
        assert_eq!(evidence_media_type(b"<script>"), None);
    }

    #[tokio::test]
    async fn external_backend_readiness_probes_the_configured_store() {
        external_backend_readiness(&FakeObjectStore::default())
            .await
            .expect("available external backend is ready");
        assert!(matches!(
            external_backend_readiness(&FakeObjectStore::unavailable()).await,
            Err(ObjectStorageError::Backend)
        ));
    }

    #[test]
    fn clamav_addresses_accept_dns_names_and_numeric_addresses() {
        assert_eq!(
            parse_clamav_address("clamav:3310").as_deref(),
            Ok("clamav:3310")
        );
        assert_eq!(
            parse_clamav_address("scanner.internal.example:13310").as_deref(),
            Ok("scanner.internal.example:13310")
        );
        assert_eq!(
            parse_clamav_address("127.0.0.1:3310").as_deref(),
            Ok("127.0.0.1:3310")
        );
        assert_eq!(
            parse_clamav_address("[::1]:3310").as_deref(),
            Ok("[::1]:3310")
        );
    }

    #[test]
    fn clamav_addresses_reject_ambiguous_or_unusable_values() {
        for value in [
            "",
            "clamav",
            "clamav:0",
            "clamav:70000",
            "-clamav:3310",
            "clamav-.internal:3310",
            "clamav..internal:3310",
            "https://clamav:3310",
            "clamav:3310/path",
            "clamav: 3310",
        ] {
            assert!(parse_clamav_address(value).is_err(), "accepted {value:?}");
        }
    }

    #[tokio::test]
    async fn clamav_readiness_requires_the_bounded_ping_protocol() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake ClamAV");
        let address = listener.local_addr().expect("fake ClamAV address");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept readiness probe");
            let mut command = [0_u8; 6];
            stream
                .read_exact(&mut command)
                .await
                .expect("read readiness command");
            assert_eq!(&command, b"zPING\0");
            stream
                .write_all(b"PONG\0")
                .await
                .expect("write readiness response");
        });
        let scanner = EvidenceScanner::ClamAv {
            address: address.to_string(),
            timeout: Duration::from_secs(1),
        };
        scanner.readiness_check().await.expect("accept ClamAV PONG");
        server.await.expect("join fake ClamAV");

        let unavailable = EvidenceScanner::ClamAv {
            address: address.to_string(),
            timeout: Duration::from_millis(50),
        };
        assert!(matches!(
            unavailable.readiness_check().await,
            Err(ObjectStorageError::ScannerUnavailable)
        ));
        assert!(EvidenceScanner::Disabled.readiness_check().await.is_ok());
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn ambiguous_external_put_keeps_metadata_for_worker_reconciliation() {
        let fake = Arc::new(FakeObjectStore::ambiguous_put());
        let (repository, storage) = external_test_storage(fake.clone(), 1024).await;
        let created_by = random_id("ambiguous_put_test");
        assert!(matches!(
            storage
                .put(
                    "payment_evidence",
                    "application/pdf",
                    Some("receipt.pdf"),
                    b"%PDF-ambiguous-response",
                    &created_by,
                    StoredObjectStatus::Quarantined,
                )
                .await,
            Err(ObjectStorageError::Backend)
        ));
        let row: (String, String, Option<String>) = sqlx::query_as(
            "SELECT id, status, staging_target_status
             FROM stored_objects WHERE created_by = $1",
        )
        .bind(&created_by)
        .fetch_one(&repository.pool)
        .await
        .expect("load preserved staging metadata");
        assert_eq!(row.1, "staging");
        assert_eq!(row.2.as_deref(), Some("quarantined"));

        let now = storage.trusted_now().await.expect("trusted time");
        sqlx::query("UPDATE stored_objects SET updated_at = $2 WHERE id = $1")
            .bind(&row.0)
            .bind(now.saturating_sub(60 * 60 + 1))
            .execute(&repository.pool)
            .await
            .expect("age staging metadata");
        crate::admin_jobs::purge_stale_objects(&repository, &storage, now)
            .await
            .expect("reconcile ambiguous put");

        let finalized: (String, Option<String>) = sqlx::query_as(
            "SELECT status, staging_target_status FROM stored_objects WHERE id = $1",
        )
        .bind(&row.0)
        .fetch_one(&repository.pool)
        .await
        .expect("load finalized metadata");
        assert_eq!(finalized.0, "quarantined");
        assert_eq!(finalized.1, None);
        assert_eq!(fake.body_gets(), 1);

        storage.delete(&row.0).await.expect("delete test object");
        repository.pool.close().await;
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn external_get_rejects_oversized_replacements_before_and_during_streaming() {
        let fake = Arc::new(FakeObjectStore::default());
        let max_object_bytes = 32;
        let (repository, storage) = external_test_storage(fake.clone(), max_object_bytes).await;
        let object = storage
            .put(
                "payment_evidence",
                "application/pdf",
                Some("receipt.pdf"),
                b"%PDF-ok",
                &random_id("oversized_get_test"),
                StoredObjectStatus::Quarantined,
            )
            .await
            .expect("store bounded object");
        let path = ObjectPath::from(format!("{}/{}.cnxo", object.namespace, object.id).as_str());
        let oversized_ciphertext =
            vec![0_u8; max_object_bytes + XCHACHA20_POLY1305_TAG_BYTES as usize + 1];
        fake.overwrite(&path, oversized_ciphertext).await;

        assert!(matches!(
            storage.get_for_scan(&object.id).await,
            Err(ObjectStorageError::Integrity)
        ));
        assert_eq!(
            fake.body_gets(),
            0,
            "an oversized HEAD response must prevent a body request"
        );

        let expected_size = expected_ciphertext_size(object.byte_length, max_object_bytes)
            .expect("expected ciphertext size");
        fake.report_size(Some(expected_size));
        assert!(matches!(
            storage.get_for_scan(&object.id).await,
            Err(ObjectStorageError::Integrity)
        ));
        assert_eq!(
            fake.body_gets(),
            1,
            "the streaming cap must reject a body larger than its metadata"
        );

        fake.report_size(None);
        storage
            .delete(&object.id)
            .await
            .expect("delete test object");
        repository.pool.close().await;
    }
}
