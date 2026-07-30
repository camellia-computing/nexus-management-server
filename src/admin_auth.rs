use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::Arc,
    time::Duration,
};

use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::Sha256;
use sqlx::{Postgres, Row, Transaction};
use subtle::ConstantTimeEq;
use thiserror::Error;
use tokio::sync::Semaphore;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    admin_app::{AdminAppError, AdminApplication, MutationContext},
    admin_operation,
    crypto::{random_id, sha256_hex},
    domain::AuditEventRecord,
    error::ApiError,
    secret_file::{read_secret_file, valid_keyring_key_count},
    store::PostgresRepository,
};

const ENROLLMENT_TTL_SECONDS: i64 = 10 * 60;
const SESSION_IDLE_SECONDS: i64 = 30 * 60;
const SESSION_ABSOLUTE_SECONDS: i64 = 8 * 60 * 60;
const STEP_UP_SECONDS: i64 = 10 * 60;
const LOGIN_WINDOW_SECONDS: i64 = 15 * 60;
const LOGIN_BLOCK_SECONDS: i64 = 15 * 60;
const MAX_LOGIN_ATTEMPTS: i32 = 10;
const SESSION_TOUCH_SECONDS: i64 = 5 * 60;
const PASSWORD_CHANGE_OPERATION: &str = "admin.identity.password.change";

#[derive(Debug, Error)]
pub enum AdminAuthError {
    #[error("invalid administrator credentials")]
    InvalidCredentials,
    #[error("administrator session is invalid or expired")]
    InvalidSession,
    #[error("administrator enrollment token is invalid or expired")]
    InvalidEnrollment,
    #[error("administrator login is temporarily rate limited")]
    RateLimited,
    #[error("permission denied")]
    PermissionDenied,
    #[error("recent password and TOTP verification is required")]
    StepUpRequired,
    #[error("administrator resource conflict")]
    Conflict,
    #[error("administrator resource version conflict")]
    VersionConflict,
    #[error("administrator resource not found")]
    NotFound,
    #[error("invalid administrator input: {0}")]
    Validation(String),
    #[error("administrator keyring is unavailable")]
    Keyring,
    #[error(transparent)]
    Service(#[from] ApiError),
}

pub type AdminAuthResult<T> = Result<T, AdminAuthError>;

impl From<AdminAppError> for AdminAuthError {
    fn from(error: AdminAppError) -> Self {
        match error {
            AdminAppError::Validation(message) => Self::Validation(message),
            AdminAppError::NotFound => Self::NotFound,
            AdminAppError::VersionConflict => Self::VersionConflict,
            AdminAppError::IdempotencyConflict | AdminAppError::SecretReplayUnavailable => {
                Self::Conflict
            }
            AdminAppError::PermissionDenied => Self::PermissionDenied,
            AdminAppError::Service(error) => Self::Service(error),
            AdminAppError::Serialization(_) | AdminAppError::SecretDelivery => {
                Self::Service(ApiError::Internal)
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdminRole {
    PlatformOwner,
    LicensingAdmin,
    SecurityAdmin,
    BillingAdmin,
    SupportOperator,
    Auditor,
}

impl AdminRole {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PlatformOwner => "platform_owner",
            Self::LicensingAdmin => "licensing_admin",
            Self::SecurityAdmin => "security_admin",
            Self::BillingAdmin => "billing_admin",
            Self::SupportOperator => "support_operator",
            Self::Auditor => "auditor",
        }
    }

    pub(crate) fn parse(value: &str) -> AdminAuthResult<Self> {
        match value {
            "platform_owner" => Ok(Self::PlatformOwner),
            "licensing_admin" => Ok(Self::LicensingAdmin),
            "security_admin" => Ok(Self::SecurityAdmin),
            "billing_admin" => Ok(Self::BillingAdmin),
            "support_operator" => Ok(Self::SupportOperator),
            "auditor" => Ok(Self::Auditor),
            _ => Err(AdminAuthError::Service(ApiError::Database)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminPermission {
    IdentityManage,
    AccountRead,
    AccountWrite,
    AccountDenylist,
    LicenseRead,
    LicenseWrite,
    CodeRead,
    CodeIssue,
    CodeWrite,
    DeviceRead,
    DeviceRemove,
    DeviceSecurity,
    BillingRead,
    BillingWrite,
    BillingReview,
    BillingOverride,
    TeamRead,
    TeamWrite,
    AuditRead,
    AuditExport,
    JobManage,
    SystemRead,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminUser {
    pub id: String,
    pub username: String,
    pub display_name: String,
    pub status: String,
    pub roles: BTreeSet<AdminRole>,
    pub row_version: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PasswordChangeOperationResponse {
    user: AdminUser,
}

impl AdminUser {
    pub fn allows(&self, permission: AdminPermission) -> bool {
        self.roles.iter().any(|role| role_allows(*role, permission))
    }

    pub fn require(&self, permission: AdminPermission) -> AdminAuthResult<()> {
        if self.allows(permission) {
            Ok(())
        } else {
            Err(AdminAuthError::PermissionDenied)
        }
    }
}

impl AdminPermission {
    pub const ALL: [Self; 21] = [
        Self::IdentityManage,
        Self::AccountRead,
        Self::AccountWrite,
        Self::AccountDenylist,
        Self::LicenseRead,
        Self::LicenseWrite,
        Self::CodeRead,
        Self::CodeIssue,
        Self::CodeWrite,
        Self::DeviceRead,
        Self::DeviceRemove,
        Self::DeviceSecurity,
        Self::BillingRead,
        Self::BillingWrite,
        Self::BillingReview,
        Self::BillingOverride,
        Self::TeamRead,
        Self::TeamWrite,
        Self::AuditRead,
        Self::AuditExport,
        Self::JobManage,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::IdentityManage => "identity.manage",
            Self::AccountRead => "account.read",
            Self::AccountWrite => "account.write",
            Self::AccountDenylist => "account.denylist",
            Self::LicenseRead => "license.read",
            Self::LicenseWrite => "license.write",
            Self::CodeRead => "code.read",
            Self::CodeIssue => "code.issue",
            Self::CodeWrite => "code.write",
            Self::DeviceRead => "device.read",
            Self::DeviceRemove => "device.remove",
            Self::DeviceSecurity => "device.security",
            Self::BillingRead => "billing.read",
            Self::BillingWrite => "billing.write",
            Self::BillingReview => "billing.review",
            Self::BillingOverride => "billing.override",
            Self::TeamRead => "team.read",
            Self::TeamWrite => "team.write",
            Self::AuditRead => "audit.read",
            Self::AuditExport => "audit.export",
            Self::JobManage => "job.manage",
            Self::SystemRead => "system.read",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnrollmentChallenge {
    pub username: String,
    pub display_name: String,
    pub totp_secret: String,
    pub otpauth_uri: String,
    pub expires_at: i64,
}

#[derive(Debug, Clone)]
pub struct SessionCredentials {
    pub session_id: String,
    pub session_token: String,
    pub csrf_token: String,
    pub expires_at: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnrollmentResult {
    pub user: AdminUser,
    pub recovery_codes: Vec<String>,
    #[serde(skip)]
    pub session: Option<SessionCredentials>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryEnrollment {
    pub token: String,
    pub challenge: EnrollmentChallenge,
}

#[derive(Debug, Clone)]
pub struct AuthenticatedAdmin {
    pub user: AdminUser,
    pub session_id: String,
    pub csrf_hash: String,
    pub elevated_until: i64,
    pub expires_at: i64,
}

impl AuthenticatedAdmin {
    pub fn require_step_up(&self, now: i64) -> AdminAuthResult<()> {
        if self.elevated_until >= now {
            Ok(())
        } else {
            Err(AdminAuthError::StepUpRequired)
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct KeyringDocument {
    active_key_id: String,
    keys: BTreeMap<String, String>,
}

impl Drop for KeyringDocument {
    fn drop(&mut self) {
        self.active_key_id.zeroize();
        for (mut key_id, mut encoded_key) in std::mem::take(&mut self.keys) {
            key_id.zeroize();
            encoded_key.zeroize();
        }
    }
}

pub struct AdminKeyring {
    active_key_id: String,
    keys: BTreeMap<String, [u8; 32]>,
}

impl Drop for AdminKeyring {
    fn drop(&mut self) {
        self.active_key_id.zeroize();
        for key in self.keys.values_mut() {
            key.zeroize();
        }
    }
}

impl AdminKeyring {
    pub fn load(path: impl AsRef<Path>) -> AdminAuthResult<Self> {
        let bytes = read_secret_file(path).map_err(|_| AdminAuthError::Keyring)?;
        Self::from_slice(&bytes)
    }

    fn from_slice(bytes: &[u8]) -> AdminAuthResult<Self> {
        let mut document: KeyringDocument =
            serde_json::from_slice(bytes).map_err(|_| AdminAuthError::Keyring)?;
        let active_key_id = canonical_admin_key_id(&document.active_key_id)?;
        if !valid_keyring_key_count(document.keys.len()) {
            return Err(AdminAuthError::Keyring);
        }
        let mut keys = BTreeMap::new();
        for (mut raw_id, encoded) in std::mem::take(&mut document.keys) {
            let key_id = canonical_admin_key_id(&raw_id)?;
            raw_id.zeroize();
            let encoded = Zeroizing::new(encoded);
            if encoded.as_str() != encoded.trim() {
                return Err(AdminAuthError::Keyring);
            }
            let decoded = Zeroizing::new(
                URL_SAFE_NO_PAD
                    .decode(encoded.as_bytes())
                    .map_err(|_| AdminAuthError::Keyring)?,
            );
            let key: [u8; 32] = decoded
                .as_slice()
                .try_into()
                .map_err(|_| AdminAuthError::Keyring)?;
            if keys.insert(key_id, key).is_some() {
                return Err(AdminAuthError::Keyring);
            }
        }
        if !keys.contains_key(&active_key_id) {
            return Err(AdminAuthError::Keyring);
        }
        Ok(Self {
            active_key_id,
            keys,
        })
    }

    pub fn ephemeral() -> Self {
        let mut key = [0_u8; 32];
        rand::fill(&mut key);
        Self {
            active_key_id: "ephemeral-development".to_owned(),
            keys: BTreeMap::from([("ephemeral-development".to_owned(), key)]),
        }
    }

    pub fn active_key_id(&self) -> &str {
        &self.active_key_id
    }

    pub async fn readiness_check(&self, repository: &PostgresRepository) -> AdminAuthResult<()> {
        let referenced_key_ids = sqlx::query_scalar::<_, String>(
            "SELECT key_id FROM (
                 SELECT key_id FROM admin_password_credentials
                 UNION SELECT key_id FROM admin_totp_credentials
                 UNION SELECT key_id FROM admin_enrollment_states
                 UNION SELECT key_id FROM admin_secret_deliveries WHERE key_id <> ''
                 UNION SELECT key_id FROM stored_objects
             ) AS referenced_keys
             ORDER BY key_id",
        )
        .fetch_all(&repository.pool)
        .await
        .map_err(|_| AdminAuthError::Service(ApiError::Database))?;
        if referenced_key_ids
            .iter()
            .any(|key_id| !self.keys.contains_key(key_id))
        {
            return Err(AdminAuthError::Keyring);
        }
        Ok(())
    }

    pub fn seal(
        &self,
        label: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> AdminAuthResult<(String, Vec<u8>, Vec<u8>)> {
        encrypt_secret(self, plaintext, aad, label)
    }

    pub fn open(
        &self,
        key_id: &str,
        label: &[u8],
        aad: &[u8],
        nonce: &[u8],
        ciphertext: &[u8],
    ) -> AdminAuthResult<Vec<u8>> {
        decrypt_secret(self, key_id, nonce, ciphertext, aad, label)
    }

    pub(crate) fn derive(&self, key_id: &str, label: &[u8]) -> AdminAuthResult<[u8; 32]> {
        let key = self.keys.get(key_id).ok_or(AdminAuthError::Keyring)?;
        let hkdf = Hkdf::<Sha256>::new(Some(b"camellia-nexus-admin-v1"), key);
        let mut output = [0_u8; 32];
        hkdf.expand(label, &mut output)
            .map_err(|_| AdminAuthError::Keyring)?;
        Ok(output)
    }

    pub(crate) fn deterministic_secret(
        &self,
        key_id: &str,
        label: &[u8],
        parts: &[&str],
    ) -> AdminAuthResult<String> {
        let key = Zeroizing::new(self.derive(key_id, label)?);
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key.as_ref())
            .map_err(|_| AdminAuthError::Keyring)?;
        for part in parts {
            mac.update(&(part.len() as u64).to_be_bytes());
            mac.update(part.as_bytes());
        }
        Ok(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
    }
}

fn canonical_admin_key_id(value: &str) -> AdminAuthResult<String> {
    if value != value.trim()
        || value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        Err(AdminAuthError::Keyring)
    } else {
        Ok(value.to_owned())
    }
}

#[derive(Clone)]
struct PasswordHashExecutor {
    permits: Arc<Semaphore>,
}

impl PasswordHashExecutor {
    fn new(max_concurrency: usize) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(max_concurrency)),
        }
    }

    async fn hash(
        &self,
        password: &str,
        keyring: Arc<AdminKeyring>,
        key_id: String,
    ) -> AdminAuthResult<String> {
        let permit =
            tokio::time::timeout(Duration::from_secs(2), self.permits.clone().acquire_owned())
                .await
                .map_err(|_| AdminAuthError::RateLimited)?
                .map_err(|_| AdminAuthError::Service(ApiError::Internal))?;
        let password = Zeroizing::new(password.to_owned());
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            hash_password(password.as_str(), &keyring, &key_id)
        })
        .await
        .map_err(|_| AdminAuthError::Service(ApiError::Internal))?
    }

    async fn verify(
        &self,
        password: &str,
        encoded: String,
        keyring: Arc<AdminKeyring>,
        key_id: String,
    ) -> AdminAuthResult<bool> {
        let permit =
            tokio::time::timeout(Duration::from_secs(2), self.permits.clone().acquire_owned())
                .await
                .map_err(|_| AdminAuthError::RateLimited)?
                .map_err(|_| AdminAuthError::Service(ApiError::Internal))?;
        let password = Zeroizing::new(password.to_owned());
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            verify_password(password.as_str(), &encoded, &keyring, &key_id)
        })
        .await
        .map_err(|_| AdminAuthError::Service(ApiError::Internal))?
    }
}

#[derive(Clone)]
pub struct AdminAuthService {
    repository: PostgresRepository,
    application: AdminApplication,
    keyring: Arc<AdminKeyring>,
    dummy_password_hash: Arc<str>,
    password_hashes: PasswordHashExecutor,
}

impl AdminAuthService {
    pub fn new(application: AdminApplication, keyring: Arc<AdminKeyring>) -> AdminAuthResult<Self> {
        let dummy_password = Zeroizing::new(random_id("invalid_admin_credential"));
        let dummy_password_hash =
            hash_password(dummy_password.as_str(), &keyring, keyring.active_key_id())?;
        Ok(Self {
            repository: application.repository().clone(),
            application,
            keyring,
            dummy_password_hash: dummy_password_hash.into(),
            password_hashes: PasswordHashExecutor::new(2),
        })
    }

    async fn trusted_now(&self) -> AdminAuthResult<i64> {
        self.application
            .trusted_now()
            .await
            .map_err(|error| match error {
                AdminAppError::Service(error) => AdminAuthError::Service(error),
                _ => AdminAuthError::Service(ApiError::Internal),
            })
    }

    pub async fn bootstrap_owner(
        &self,
        username: &str,
        display_name: &str,
        actor: &str,
        reason: &str,
    ) -> AdminAuthResult<String> {
        let username = normalize_username(username)?;
        validate_display_name(display_name)?;
        validate_audit_text(actor, "actor", 128)?;
        validate_audit_text(reason, "reason", 512)?;
        let now = self.trusted_now().await?;
        let user_id = random_id("admin");
        let token = random_secret(32);
        let token_hash = sha256_hex(&token);
        let mut tx = self
            .repository
            .pool
            .begin()
            .await
            .map_err(|_| ApiError::Database)?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext('camellia_admin_bootstrap'))")
            .execute(&mut *tx)
            .await
            .map_err(|_| ApiError::Database)?;
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM admin_users")
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| ApiError::Database)?;
        if count != 0 {
            return Err(AdminAuthError::Conflict);
        }
        sqlx::query(
            "INSERT INTO admin_users
             (id, username, display_name, status, created_at, updated_at)
             VALUES ($1, $2, $3, 'pending', $4, $4)",
        )
        .bind(&user_id)
        .bind(&username)
        .bind(display_name.trim())
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        sqlx::query(
            "INSERT INTO admin_role_bindings
             (user_id, role, granted_by, reason, created_at)
             VALUES ($1, 'platform_owner', $2, $3, $4)",
        )
        .bind(&user_id)
        .bind(actor.trim())
        .bind(reason.trim())
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        insert_enrollment_token(&mut tx, &token_hash, &user_id, "enroll", actor, reason, now)
            .await?;
        insert_auth_audit(
            &mut tx,
            "admin_owner_bootstrapped",
            "succeeded",
            actor,
            reason,
            Some(&user_id),
            now,
        )
        .await?;
        tx.commit().await.map_err(|_| ApiError::Database)?;
        Ok(token)
    }

    pub async fn begin_enrollment(&self, token: &str) -> AdminAuthResult<EnrollmentChallenge> {
        let token_hash = sha256_hex(token.trim());
        let now = self.trusted_now().await?;
        let mut tx = self
            .repository
            .pool
            .begin()
            .await
            .map_err(|_| ApiError::Database)?;
        let row = sqlx::query(
            "SELECT u.username, u.display_name, t.expires_at, s.key_id, s.nonce, s.ciphertext
             FROM admin_enrollment_tokens t
             JOIN admin_users u ON u.id = t.user_id
             LEFT JOIN admin_enrollment_states s ON s.token_hash = t.token_hash
             WHERE t.token_hash = $1 AND t.consumed_at IS NULL AND t.expires_at > $2
               AND u.status = 'pending'
             FOR UPDATE OF t",
        )
        .bind(&token_hash)
        .bind(now)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?
        .ok_or(AdminAuthError::InvalidEnrollment)?;
        let username: String = row.try_get("username").map_err(|_| ApiError::Database)?;
        let display_name: String = row
            .try_get("display_name")
            .map_err(|_| ApiError::Database)?;
        let expires_at: i64 = row.try_get("expires_at").map_err(|_| ApiError::Database)?;
        let secret = Zeroizing::new(match row.try_get::<Option<String>, _>("key_id") {
            Ok(Some(key_id)) => decrypt_secret(
                &self.keyring,
                &key_id,
                &row.try_get::<Vec<u8>, _>("nonce")
                    .map_err(|_| ApiError::Database)?,
                &row.try_get::<Vec<u8>, _>("ciphertext")
                    .map_err(|_| ApiError::Database)?,
                token_hash.as_bytes(),
                b"admin-totp",
            )?,
            _ => {
                let mut secret = vec![0_u8; 20];
                rand::fill(&mut secret[..]);
                let (key_id, nonce, ciphertext) =
                    encrypt_secret(&self.keyring, &secret, token_hash.as_bytes(), b"admin-totp")?;
                sqlx::query(
                    "INSERT INTO admin_enrollment_states
                     (token_hash, key_id, nonce, ciphertext, created_at)
                     VALUES ($1, $2, $3, $4, $5)",
                )
                .bind(&token_hash)
                .bind(key_id)
                .bind(nonce)
                .bind(ciphertext)
                .bind(now)
                .execute(&mut *tx)
                .await
                .map_err(|_| ApiError::Database)?;
                secret
            }
        });
        tx.commit().await.map_err(|_| ApiError::Database)?;
        let totp_secret = base32_encode(&secret);
        let label =
            url::form_urlencoded::byte_serialize(format!("Camellia Nexus:{username}").as_bytes())
                .collect::<String>();
        let issuer = url::form_urlencoded::byte_serialize(b"Camellia Nexus").collect::<String>();
        Ok(EnrollmentChallenge {
            username,
            display_name,
            otpauth_uri: format!(
                "otpauth://totp/{label}?secret={totp_secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30"
            ),
            totp_secret,
            expires_at,
        })
    }

    pub async fn complete_enrollment(
        &self,
        token: &str,
        password: &str,
        totp: &str,
        source_ip: Option<&str>,
        user_agent: Option<&str>,
    ) -> AdminAuthResult<EnrollmentResult> {
        validate_password(password, None)?;
        let token_hash = sha256_hex(token.trim());
        let now = self.trusted_now().await?;
        let mut tx = self
            .repository
            .pool
            .begin()
            .await
            .map_err(|_| ApiError::Database)?;
        let row = sqlx::query(
            "SELECT u.id, u.username, u.display_name, u.status, u.row_version,
                    t.created_by, t.reason, s.key_id, s.nonce, s.ciphertext
             FROM admin_enrollment_tokens t
             JOIN admin_users u ON u.id = t.user_id
             JOIN admin_enrollment_states s ON s.token_hash = t.token_hash
             WHERE t.token_hash = $1 AND t.consumed_at IS NULL AND t.expires_at > $2
               AND u.status = 'pending'
             FOR UPDATE OF t, u, s",
        )
        .bind(&token_hash)
        .bind(now)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?
        .ok_or(AdminAuthError::InvalidEnrollment)?;
        let user_id: String = row.try_get("id").map_err(|_| ApiError::Database)?;
        let username: String = row.try_get("username").map_err(|_| ApiError::Database)?;
        validate_password(password, Some(&username))?;
        let enrollment_key_id: String = row.try_get("key_id").map_err(|_| ApiError::Database)?;
        let secret = Zeroizing::new(decrypt_secret(
            &self.keyring,
            &enrollment_key_id,
            &row.try_get::<Vec<u8>, _>("nonce")
                .map_err(|_| ApiError::Database)?,
            &row.try_get::<Vec<u8>, _>("ciphertext")
                .map_err(|_| ApiError::Database)?,
            token_hash.as_bytes(),
            b"admin-totp",
        )?);
        let step = verify_totp(&secret, totp, now, None)?;
        let credential_key_id = self.keyring.active_key_id().to_owned();
        let password_hash = self
            .password_hashes
            .hash(password, self.keyring.clone(), credential_key_id.clone())
            .await?;
        let (totp_key_id, nonce, ciphertext) =
            encrypt_secret(&self.keyring, &secret, user_id.as_bytes(), b"admin-totp")?;
        sqlx::query("DELETE FROM admin_password_credentials WHERE user_id = $1")
            .bind(&user_id)
            .execute(&mut *tx)
            .await
            .map_err(|_| ApiError::Database)?;
        sqlx::query("DELETE FROM admin_totp_credentials WHERE user_id = $1")
            .bind(&user_id)
            .execute(&mut *tx)
            .await
            .map_err(|_| ApiError::Database)?;
        sqlx::query("DELETE FROM admin_recovery_codes WHERE user_id = $1")
            .bind(&user_id)
            .execute(&mut *tx)
            .await
            .map_err(|_| ApiError::Database)?;
        sqlx::query(
            "INSERT INTO admin_password_credentials (user_id, password_hash, key_id, changed_at)
             VALUES ($1, $2, $3, $4)",
        )
        .bind(&user_id)
        .bind(password_hash)
        .bind(&credential_key_id)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        sqlx::query(
            "INSERT INTO admin_totp_credentials
             (user_id, key_id, nonce, ciphertext, last_used_step, confirmed_at)
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(&user_id)
        .bind(totp_key_id)
        .bind(nonce)
        .bind(ciphertext)
        .bind(step)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        let recovery_codes = recovery_codes();
        for code in &recovery_codes {
            sqlx::query(
                "INSERT INTO admin_recovery_codes (user_id, code_hash, created_at)
                 VALUES ($1, $2, $3)",
            )
            .bind(&user_id)
            .bind(sha256_hex(code))
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(|_| ApiError::Database)?;
        }
        sqlx::query(
            "UPDATE admin_users
             SET status = 'active', row_version = row_version + 1, updated_at = $2 WHERE id = $1",
        )
        .bind(&user_id)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        sqlx::query("UPDATE admin_enrollment_tokens SET consumed_at = $2 WHERE token_hash = $1")
            .bind(&token_hash)
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(|_| ApiError::Database)?;
        sqlx::query("DELETE FROM admin_enrollment_states WHERE token_hash = $1")
            .bind(&token_hash)
            .execute(&mut *tx)
            .await
            .map_err(|_| ApiError::Database)?;
        sqlx::query(
            "UPDATE admin_sessions SET revoked_at = $2
             WHERE user_id = $1 AND revoked_at IS NULL",
        )
        .bind(&user_id)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        let session = create_session(&mut tx, &user_id, source_ip, user_agent, now).await?;
        let actor: String = row.try_get("created_by").map_err(|_| ApiError::Database)?;
        let reason: String = row.try_get("reason").map_err(|_| ApiError::Database)?;
        insert_auth_audit(
            &mut tx,
            "admin_enrollment_completed",
            "succeeded",
            &actor,
            &reason,
            Some(&user_id),
            now,
        )
        .await?;
        tx.commit().await.map_err(|_| ApiError::Database)?;
        let mut user = self.user_by_id(&user_id).await?;
        user.status = "active".to_owned();
        Ok(EnrollmentResult {
            user,
            recovery_codes,
            session: Some(session),
        })
    }

    pub async fn login(
        &self,
        username: &str,
        password: &str,
        totp: &str,
        source_ip: Option<&str>,
        user_agent: Option<&str>,
    ) -> AdminAuthResult<(AdminUser, SessionCredentials)> {
        let normalized = normalize_username_for_login(username);
        let bucket_key = login_bucket_key(&normalized, source_ip);
        let now = self.trusted_now().await?;
        self.check_login_bucket(&bucket_key, now).await?;
        let row = sqlx::query(
            "SELECT u.id, u.username, u.status, p.password_hash, p.key_id,
                    t.key_id AS totp_key_id, t.nonce, t.ciphertext, t.last_used_step
             FROM admin_users u
             JOIN admin_password_credentials p ON p.user_id = u.id
             JOIN admin_totp_credentials t ON t.user_id = u.id
             WHERE u.username = $1",
        )
        .bind(&normalized)
        .fetch_optional(&self.repository.pool)
        .await
        .map_err(|_| ApiError::Database)?;
        let eligible = row
            .as_ref()
            .map(|row| {
                row.try_get::<String, _>("status")
                    .map(|status| status == "active")
                    .map_err(|_| ApiError::Database)
            })
            .transpose()?
            .unwrap_or(false);
        let (password_hash, password_key_id) = if eligible {
            let row = row.as_ref().expect("eligible administrator row exists");
            (
                row.try_get("password_hash")
                    .map_err(|_| ApiError::Database)?,
                row.try_get("key_id").map_err(|_| ApiError::Database)?,
            )
        } else {
            (
                self.dummy_password_hash.to_string(),
                self.keyring.active_key_id().to_owned(),
            )
        };
        let password_ok = self
            .password_hashes
            .verify(
                password,
                password_hash,
                self.keyring.clone(),
                password_key_id,
            )
            .await?;
        if !eligible || !password_ok {
            self.record_login_denial(&bucket_key, "invalid_credentials", None, now)
                .await?;
            return Err(AdminAuthError::InvalidCredentials);
        }
        let row = row.expect("eligible administrator row exists");
        let user_id: String = row.try_get("id").map_err(|_| ApiError::Database)?;
        let totp_key_id: String = row.try_get("totp_key_id").map_err(|_| ApiError::Database)?;
        let mut secret = decrypt_secret(
            &self.keyring,
            &totp_key_id,
            &row.try_get::<Vec<u8>, _>("nonce")
                .map_err(|_| ApiError::Database)?,
            &row.try_get::<Vec<u8>, _>("ciphertext")
                .map_err(|_| ApiError::Database)?,
            user_id.as_bytes(),
            b"admin-totp",
        )?;
        let last_step: Option<i64> = row
            .try_get("last_used_step")
            .map_err(|_| ApiError::Database)?;
        let verification = verify_totp(&secret, totp, now, last_step);
        secret.zeroize();
        let step = match verification {
            Ok(step) => step,
            Err(AdminAuthError::InvalidCredentials) => {
                self.record_login_denial(&bucket_key, "invalid_totp", Some(&user_id), now)
                    .await?;
                return Err(AdminAuthError::InvalidCredentials);
            }
            Err(error) => return Err(error),
        };
        let mut tx = self
            .repository
            .pool
            .begin()
            .await
            .map_err(|_| ApiError::Database)?;
        let updated = sqlx::query(
            "UPDATE admin_totp_credentials SET last_used_step = $2
             WHERE user_id = $1 AND (last_used_step IS NULL OR last_used_step < $2)",
        )
        .bind(&user_id)
        .bind(step)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?
        .rows_affected();
        if updated != 1 {
            tx.rollback().await.map_err(|_| ApiError::Database)?;
            self.record_login_denial(&bucket_key, "totp_replay", Some(&user_id), now)
                .await?;
            return Err(AdminAuthError::InvalidCredentials);
        }
        let session = create_session(&mut tx, &user_id, source_ip, user_agent, now).await?;
        sqlx::query("DELETE FROM admin_login_buckets WHERE bucket_key = $1")
            .bind(&bucket_key)
            .execute(&mut *tx)
            .await
            .map_err(|_| ApiError::Database)?;
        insert_auth_audit(
            &mut tx,
            "admin_login",
            "succeeded",
            &user_id,
            "password_totp",
            Some(&user_id),
            now,
        )
        .await?;
        tx.commit().await.map_err(|_| ApiError::Database)?;
        Ok((self.user_by_id(&user_id).await?, session))
    }

    pub async fn step_up(
        &self,
        admin: &AuthenticatedAdmin,
        password: &str,
        totp: &str,
        source_ip: Option<&str>,
    ) -> AdminAuthResult<i64> {
        let now = self.trusted_now().await?;
        let bucket_key = login_bucket_key(&format!("step-up:{}", admin.user.username), source_ip);
        self.check_login_bucket(&bucket_key, now).await?;
        let row = sqlx::query(
            "SELECT u.status, p.password_hash, p.key_id,
                    t.key_id AS totp_key_id, t.nonce, t.ciphertext, t.last_used_step
             FROM admin_users u
             JOIN admin_password_credentials p ON p.user_id = u.id
             JOIN admin_totp_credentials t ON t.user_id = u.id
             WHERE u.id = $1",
        )
        .bind(&admin.user.id)
        .fetch_optional(&self.repository.pool)
        .await
        .map_err(|_| ApiError::Database)?
        .ok_or(AdminAuthError::InvalidCredentials)?;
        let status: String = row.try_get("status").map_err(|_| ApiError::Database)?;
        let password_key_id: String = row.try_get("key_id").map_err(|_| ApiError::Database)?;
        let password_hash: String = row
            .try_get("password_hash")
            .map_err(|_| ApiError::Database)?;
        let eligible = status == "active";
        let (selected_hash, selected_key_id) = if eligible {
            (password_hash, password_key_id)
        } else {
            (
                self.dummy_password_hash.to_string(),
                self.keyring.active_key_id().to_owned(),
            )
        };
        let password_ok = self
            .password_hashes
            .verify(
                password,
                selected_hash,
                self.keyring.clone(),
                selected_key_id,
            )
            .await?;
        if !eligible || !password_ok {
            self.record_login_denial(
                &bucket_key,
                "step_up_invalid_credentials",
                Some(&admin.user.id),
                now,
            )
            .await?;
            return Err(AdminAuthError::InvalidCredentials);
        }
        let totp_key_id: String = row.try_get("totp_key_id").map_err(|_| ApiError::Database)?;
        let mut secret = decrypt_secret(
            &self.keyring,
            &totp_key_id,
            &row.try_get::<Vec<u8>, _>("nonce")
                .map_err(|_| ApiError::Database)?,
            &row.try_get::<Vec<u8>, _>("ciphertext")
                .map_err(|_| ApiError::Database)?,
            admin.user.id.as_bytes(),
            b"admin-totp",
        )?;
        let last_step: Option<i64> = row
            .try_get("last_used_step")
            .map_err(|_| ApiError::Database)?;
        let verification = verify_totp(&secret, totp, now, last_step);
        secret.zeroize();
        let step = match verification {
            Ok(step) => step,
            Err(AdminAuthError::InvalidCredentials) => {
                self.record_login_denial(
                    &bucket_key,
                    "step_up_invalid_totp",
                    Some(&admin.user.id),
                    now,
                )
                .await?;
                return Err(AdminAuthError::InvalidCredentials);
            }
            Err(error) => return Err(error),
        };
        let elevated_until = now.saturating_add(STEP_UP_SECONDS);
        let mut tx = self
            .repository
            .pool
            .begin()
            .await
            .map_err(|_| ApiError::Database)?;
        let credential_updated = sqlx::query(
            "UPDATE admin_totp_credentials SET last_used_step = $2
             WHERE user_id = $1 AND (last_used_step IS NULL OR last_used_step < $2)",
        )
        .bind(&admin.user.id)
        .bind(step)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?
        .rows_affected();
        let session_updated = sqlx::query(
            "UPDATE admin_sessions SET elevated_until = $3, last_seen_at = $2
             WHERE id = $1 AND user_id = $4 AND revoked_at IS NULL AND expires_at > $2",
        )
        .bind(&admin.session_id)
        .bind(now)
        .bind(elevated_until)
        .bind(&admin.user.id)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?
        .rows_affected();
        if credential_updated != 1 || session_updated != 1 {
            tx.rollback().await.map_err(|_| ApiError::Database)?;
            self.record_login_denial(&bucket_key, "step_up_replay", Some(&admin.user.id), now)
                .await?;
            return Err(AdminAuthError::InvalidCredentials);
        }
        sqlx::query("DELETE FROM admin_login_buckets WHERE bucket_key = $1")
            .bind(&bucket_key)
            .execute(&mut *tx)
            .await
            .map_err(|_| ApiError::Database)?;
        insert_auth_audit(
            &mut tx,
            "admin_step_up",
            "succeeded",
            &admin.user.id,
            "password_totp",
            Some(&admin.user.id),
            now,
        )
        .await?;
        tx.commit().await.map_err(|_| ApiError::Database)?;
        Ok(elevated_until)
    }

    pub async fn change_password(
        &self,
        user_id: &str,
        new_password: &str,
        expected_version: i64,
        context: &MutationContext,
    ) -> AdminAuthResult<AdminUser> {
        if user_id != context.principal.id {
            return Err(AdminAuthError::PermissionDenied);
        }
        let key_id = self.keyring.active_key_id().to_owned();
        let password_fingerprint = self.keyring.deterministic_secret(
            &key_id,
            b"admin-password-change-request",
            &[user_id, new_password],
        )?;
        let request_hash = admin_operation::request_hash(&serde_json::json!({
            "userId": user_id,
            "expectedVersion": expected_version,
            "passwordFingerprint": password_fingerprint,
        }))?;
        let operation = admin_operation::from_parts(
            admin_operation::operation_id(context)?,
            PASSWORD_CHANGE_OPERATION,
            &request_hash,
            &context.principal.id,
            &context.reason,
        )?;
        if let Some(response) = admin_operation::replay::<PasswordChangeOperationResponse>(
            &self.repository.pool,
            &operation,
        )
        .await?
        {
            return Ok(response.user);
        }
        let row = sqlx::query(
            "SELECT u.username, u.status, u.row_version, p.password_hash, p.key_id
             FROM admin_users u
             JOIN admin_password_credentials p ON p.user_id = u.id
             WHERE u.id = $1",
        )
        .bind(user_id)
        .fetch_optional(&self.repository.pool)
        .await
        .map_err(|_| ApiError::Database)?
        .ok_or(AdminAuthError::NotFound)?;
        let username: String = row.try_get("username").map_err(|_| ApiError::Database)?;
        validate_password(new_password, Some(&username))?;
        if row
            .try_get::<String, _>("status")
            .map_err(|_| ApiError::Database)?
            != "active"
        {
            return Err(AdminAuthError::PermissionDenied);
        }
        if row
            .try_get::<i64, _>("row_version")
            .map_err(|_| ApiError::Database)?
            != expected_version
        {
            return Err(AdminAuthError::VersionConflict);
        }
        if self
            .password_hashes
            .verify(
                new_password,
                row.try_get("password_hash")
                    .map_err(|_| ApiError::Database)?,
                self.keyring.clone(),
                row.try_get("key_id").map_err(|_| ApiError::Database)?,
            )
            .await?
        {
            return Err(AdminAuthError::Validation(
                "new password must differ from the current password".to_owned(),
            ));
        }
        let password_hash = self
            .password_hashes
            .hash(new_password, self.keyring.clone(), key_id.clone())
            .await?;
        let now = self.trusted_now().await?;
        let mut tx = self
            .repository
            .pool
            .begin()
            .await
            .map_err(|_| ApiError::Database)?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext('camellia_admin_identity'))")
            .execute(&mut *tx)
            .await
            .map_err(|_| ApiError::Database)?;
        if let Some(response) =
            admin_operation::claim_prepared::<PasswordChangeOperationResponse>(&mut tx, &operation)
                .await?
        {
            tx.commit().await.map_err(|_| ApiError::Database)?;
            return Ok(response.user);
        }
        let locked =
            sqlx::query("SELECT status, row_version FROM admin_users WHERE id = $1 FOR UPDATE")
                .bind(user_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|_| ApiError::Database)?
                .ok_or(AdminAuthError::NotFound)?;
        if locked
            .try_get::<String, _>("status")
            .map_err(|_| ApiError::Database)?
            != "active"
        {
            return Err(AdminAuthError::PermissionDenied);
        }
        if locked
            .try_get::<i64, _>("row_version")
            .map_err(|_| ApiError::Database)?
            != expected_version
        {
            return Err(AdminAuthError::VersionConflict);
        }
        let updated = sqlx::query(
            "UPDATE admin_password_credentials
             SET password_hash = $2, key_id = $3, changed_at = $4 WHERE user_id = $1",
        )
        .bind(user_id)
        .bind(password_hash)
        .bind(key_id)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?
        .rows_affected();
        if updated != 1 {
            return Err(AdminAuthError::Service(ApiError::Database));
        }
        sqlx::query(
            "UPDATE admin_users SET row_version = row_version + 1, updated_at = $2
             WHERE id = $1",
        )
        .bind(user_id)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        sqlx::query(
            "UPDATE admin_sessions SET revoked_at = $2
             WHERE user_id = $1 AND revoked_at IS NULL",
        )
        .bind(user_id)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        let user = admin_user_in_transaction(&mut tx, user_id).await?;
        insert_context_auth_audit(&mut tx, "admin_password_changed", context, user_id, now).await?;
        admin_operation::finish_prepared(
            &mut tx,
            &PasswordChangeOperationResponse { user: user.clone() },
            &operation,
        )
        .await?;
        tx.commit().await.map_err(|_| ApiError::Database)?;
        Ok(user)
    }

    pub async fn begin_recovery(
        &self,
        username: &str,
        password: &str,
        recovery_code: &str,
        source_ip: Option<&str>,
    ) -> AdminAuthResult<RecoveryEnrollment> {
        let username = normalize_username_for_login(username);
        let bucket_key = login_bucket_key(&format!("recovery:{username}"), source_ip);
        let now = self.trusted_now().await?;
        self.check_login_bucket(&bucket_key, now).await?;
        let row = sqlx::query(
            "SELECT u.id, u.status, p.password_hash, p.key_id
             FROM admin_users u
             JOIN admin_password_credentials p ON p.user_id = u.id
             WHERE u.username = $1",
        )
        .bind(&username)
        .fetch_optional(&self.repository.pool)
        .await
        .map_err(|_| ApiError::Database)?;
        let eligible = row
            .as_ref()
            .map(|row| {
                row.try_get::<String, _>("status")
                    .map(|status| matches!(status.as_str(), "active" | "pending"))
                    .map_err(|_| ApiError::Database)
            })
            .transpose()?
            .unwrap_or(false);
        let (password_hash, key_id) = if eligible {
            let row = row
                .as_ref()
                .expect("eligible recovery administrator exists");
            (
                row.try_get("password_hash")
                    .map_err(|_| ApiError::Database)?,
                row.try_get("key_id").map_err(|_| ApiError::Database)?,
            )
        } else {
            (
                self.dummy_password_hash.to_string(),
                self.keyring.active_key_id().to_owned(),
            )
        };
        let password_ok = self
            .password_hashes
            .verify(password, password_hash, self.keyring.clone(), key_id)
            .await?;
        if !eligible || !password_ok {
            self.record_login_denial(&bucket_key, "recovery_invalid_credentials", None, now)
                .await?;
            return Err(AdminAuthError::InvalidCredentials);
        }
        let row = row.expect("eligible recovery administrator exists");
        let user_id: String = row.try_get("id").map_err(|_| ApiError::Database)?;
        let code_hash = sha256_hex(&recovery_code.trim().to_ascii_uppercase());
        let token = recovery_enrollment_token(&self.keyring, &user_id, &code_hash)?;
        let token_hash = sha256_hex(&token);
        let mut tx = self
            .repository
            .pool
            .begin()
            .await
            .map_err(|_| ApiError::Database)?;
        let consumed = sqlx::query(
            "UPDATE admin_recovery_codes SET consumed_at = $3
             WHERE user_id = $1 AND code_hash = $2 AND consumed_at IS NULL",
        )
        .bind(&user_id)
        .bind(code_hash)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?
        .rows_affected();
        if consumed == 1 {
            sqlx::query(
                "DELETE FROM admin_enrollment_states s
                 USING admin_enrollment_tokens t
                 WHERE s.token_hash = t.token_hash AND t.user_id = $1",
            )
            .bind(&user_id)
            .execute(&mut *tx)
            .await
            .map_err(|_| ApiError::Database)?;
            sqlx::query(
                "UPDATE admin_enrollment_tokens SET consumed_at = $2
                 WHERE user_id = $1 AND purpose = 'reset' AND consumed_at IS NULL",
            )
            .bind(&user_id)
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(|_| ApiError::Database)?;
            sqlx::query("DELETE FROM admin_totp_credentials WHERE user_id = $1")
                .bind(&user_id)
                .execute(&mut *tx)
                .await
                .map_err(|_| ApiError::Database)?;
            sqlx::query("DELETE FROM admin_recovery_codes WHERE user_id = $1")
                .bind(&user_id)
                .execute(&mut *tx)
                .await
                .map_err(|_| ApiError::Database)?;
            sqlx::query(
                "UPDATE admin_users
                 SET status = 'pending', row_version = row_version + 1, updated_at = $2
                 WHERE id = $1",
            )
            .bind(&user_id)
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(|_| ApiError::Database)?;
            insert_enrollment_token(
                &mut tx,
                &token_hash,
                &user_id,
                "reset",
                &user_id,
                "recovery_code",
                now,
            )
            .await?;
            sqlx::query(
                "UPDATE admin_sessions SET revoked_at = $2
                 WHERE user_id = $1 AND revoked_at IS NULL",
            )
            .bind(&user_id)
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(|_| ApiError::Database)?;
            insert_auth_audit(
                &mut tx,
                "admin_recovery_started",
                "succeeded",
                &user_id,
                "recovery_code",
                Some(&user_id),
                now,
            )
            .await?;
        } else {
            let safe_retry: bool = sqlx::query_scalar(
                "SELECT EXISTS (
                    SELECT 1 FROM admin_enrollment_tokens
                    WHERE token_hash = $1 AND user_id = $2 AND purpose = 'reset'
                      AND consumed_at IS NULL AND expires_at > $3
                 )",
            )
            .bind(&token_hash)
            .bind(&user_id)
            .bind(now)
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| ApiError::Database)?;
            if !safe_retry {
                tx.rollback().await.map_err(|_| ApiError::Database)?;
                self.record_login_denial(&bucket_key, "recovery_invalid_code", Some(&user_id), now)
                    .await?;
                return Err(AdminAuthError::InvalidCredentials);
            }
        }
        sqlx::query("DELETE FROM admin_login_buckets WHERE bucket_key = $1")
            .bind(&bucket_key)
            .execute(&mut *tx)
            .await
            .map_err(|_| ApiError::Database)?;
        tx.commit().await.map_err(|_| ApiError::Database)?;
        let challenge = self.begin_enrollment(&token).await?;
        Ok(RecoveryEnrollment { token, challenge })
    }

    pub async fn authenticate(&self, token: &str) -> AdminAuthResult<AuthenticatedAdmin> {
        let now = self.trusted_now().await?;
        let token_hash = sha256_hex(token);
        let row = sqlx::query(
            "SELECT s.id, s.user_id, s.csrf_hash, s.elevated_until, s.last_seen_at,
                    s.expires_at, u.username, u.display_name, u.status, u.row_version
             FROM admin_sessions s
             JOIN admin_users u ON u.id = s.user_id
             WHERE s.token_hash = $1 AND s.revoked_at IS NULL",
        )
        .bind(&token_hash)
        .fetch_optional(&self.repository.pool)
        .await
        .map_err(|_| ApiError::Database)?
        .ok_or(AdminAuthError::InvalidSession)?;
        let session_id: String = row.try_get("id").map_err(|_| ApiError::Database)?;
        let user_id: String = row.try_get("user_id").map_err(|_| ApiError::Database)?;
        let status: String = row.try_get("status").map_err(|_| ApiError::Database)?;
        let last_seen_at: i64 = row
            .try_get("last_seen_at")
            .map_err(|_| ApiError::Database)?;
        let expires_at: i64 = row.try_get("expires_at").map_err(|_| ApiError::Database)?;
        if status != "active"
            || expires_at <= now
            || last_seen_at.saturating_add(SESSION_IDLE_SECONDS) <= now
        {
            let _ = sqlx::query(
                "UPDATE admin_sessions SET revoked_at = $2 WHERE id = $1 AND revoked_at IS NULL",
            )
            .bind(&session_id)
            .bind(now)
            .execute(&self.repository.pool)
            .await;
            return Err(AdminAuthError::InvalidSession);
        }
        if last_seen_at.saturating_add(SESSION_TOUCH_SECONDS) <= now {
            sqlx::query("UPDATE admin_sessions SET last_seen_at = $2 WHERE id = $1")
                .bind(&session_id)
                .bind(now)
                .execute(&self.repository.pool)
                .await
                .map_err(|_| ApiError::Database)?;
        }
        Ok(AuthenticatedAdmin {
            user: AdminUser {
                id: user_id.clone(),
                username: row.try_get("username").map_err(|_| ApiError::Database)?,
                display_name: row
                    .try_get("display_name")
                    .map_err(|_| ApiError::Database)?,
                status,
                roles: self.roles(&user_id).await?,
                row_version: row.try_get("row_version").map_err(|_| ApiError::Database)?,
            },
            session_id,
            csrf_hash: row.try_get("csrf_hash").map_err(|_| ApiError::Database)?,
            elevated_until: row
                .try_get("elevated_until")
                .map_err(|_| ApiError::Database)?,
            expires_at,
        })
    }

    pub fn verify_csrf(&self, session: &AuthenticatedAdmin, token: &str) -> AdminAuthResult<()> {
        let actual = sha256_hex(token);
        if actual.as_bytes().ct_eq(session.csrf_hash.as_bytes()).into() {
            Ok(())
        } else {
            Err(AdminAuthError::PermissionDenied)
        }
    }

    pub async fn logout(&self, session_id: &str) -> AdminAuthResult<()> {
        sqlx::query(
            "UPDATE admin_sessions SET revoked_at = $2 WHERE id = $1 AND revoked_at IS NULL",
        )
        .bind(session_id)
        .bind(self.trusted_now().await?)
        .execute(&self.repository.pool)
        .await
        .map_err(|_| ApiError::Database)?;
        Ok(())
    }

    pub async fn user_by_id(&self, user_id: &str) -> AdminAuthResult<AdminUser> {
        let row = sqlx::query(
            "SELECT id, username, display_name, status, row_version
             FROM admin_users WHERE id = $1",
        )
        .bind(user_id)
        .fetch_optional(&self.repository.pool)
        .await
        .map_err(|_| ApiError::Database)?
        .ok_or(AdminAuthError::InvalidCredentials)?;
        Ok(AdminUser {
            id: row.try_get("id").map_err(|_| ApiError::Database)?,
            username: row.try_get("username").map_err(|_| ApiError::Database)?,
            display_name: row
                .try_get("display_name")
                .map_err(|_| ApiError::Database)?,
            status: row.try_get("status").map_err(|_| ApiError::Database)?,
            roles: self.roles(user_id).await?,
            row_version: row.try_get("row_version").map_err(|_| ApiError::Database)?,
        })
    }

    async fn roles(&self, user_id: &str) -> AdminAuthResult<BTreeSet<AdminRole>> {
        let values: Vec<String> =
            sqlx::query_scalar("SELECT role FROM admin_role_bindings WHERE user_id = $1")
                .bind(user_id)
                .fetch_all(&self.repository.pool)
                .await
                .map_err(|_| ApiError::Database)?;
        values
            .into_iter()
            .map(|value| AdminRole::parse(&value))
            .collect()
    }

    async fn check_login_bucket(&self, bucket_key: &str, now: i64) -> AdminAuthResult<()> {
        let blocked: Option<i64> = sqlx::query_scalar(
            "SELECT blocked_until FROM admin_login_buckets WHERE bucket_key = $1",
        )
        .bind(bucket_key)
        .fetch_optional(&self.repository.pool)
        .await
        .map_err(|_| ApiError::Database)?
        .flatten();
        if blocked.is_some_and(|blocked_until| blocked_until > now) {
            Err(AdminAuthError::RateLimited)
        } else {
            Ok(())
        }
    }

    async fn record_login_failure(&self, bucket_key: &str, now: i64) -> AdminAuthResult<()> {
        sqlx::query(
            "INSERT INTO admin_login_buckets
             (bucket_key, window_started_at, attempts, blocked_until)
             VALUES ($1, $2, 1, NULL)
             ON CONFLICT (bucket_key) DO UPDATE SET
                 window_started_at = CASE
                     WHEN admin_login_buckets.window_started_at + $3 <= $2 THEN $2
                     ELSE admin_login_buckets.window_started_at END,
                 attempts = CASE
                     WHEN admin_login_buckets.window_started_at + $3 <= $2 THEN 1
                     ELSE admin_login_buckets.attempts + 1 END,
                 blocked_until = CASE
                     WHEN (CASE WHEN admin_login_buckets.window_started_at + $3 <= $2
                                THEN 1 ELSE admin_login_buckets.attempts + 1 END) >= $4
                     THEN $2 + $5 ELSE admin_login_buckets.blocked_until END",
        )
        .bind(bucket_key)
        .bind(now)
        .bind(LOGIN_WINDOW_SECONDS)
        .bind(MAX_LOGIN_ATTEMPTS)
        .bind(LOGIN_BLOCK_SECONDS)
        .execute(&self.repository.pool)
        .await
        .map_err(|_| ApiError::Database)?;
        Ok(())
    }

    async fn record_login_denial(
        &self,
        bucket_key: &str,
        reason: &str,
        target_id: Option<&str>,
        now: i64,
    ) -> AdminAuthResult<()> {
        self.record_login_failure(bucket_key, now).await?;
        let mut tx = self
            .repository
            .pool
            .begin()
            .await
            .map_err(|_| ApiError::Database)?;
        insert_auth_audit(
            &mut tx,
            "admin_login",
            "failed",
            "anonymous",
            reason,
            target_id,
            now,
        )
        .await?;
        tx.commit().await.map_err(|_| ApiError::Database)?;
        Ok(())
    }
}

fn role_allows(role: AdminRole, permission: AdminPermission) -> bool {
    use AdminPermission as P;
    use AdminRole as R;
    match role {
        R::PlatformOwner => true,
        R::LicensingAdmin => matches!(
            permission,
            P::AccountRead
                | P::AccountWrite
                | P::LicenseRead
                | P::LicenseWrite
                | P::CodeRead
                | P::CodeIssue
                | P::CodeWrite
                | P::DeviceRead
                | P::DeviceRemove
                | P::TeamRead
                | P::TeamWrite
                | P::AuditRead
                | P::JobManage
                | P::SystemRead
        ),
        R::SecurityAdmin => matches!(
            permission,
            P::AccountRead
                | P::AccountDenylist
                | P::LicenseRead
                | P::CodeRead
                | P::DeviceRead
                | P::DeviceSecurity
                | P::AuditRead
                | P::AuditExport
                | P::JobManage
                | P::SystemRead
        ),
        R::BillingAdmin => matches!(
            permission,
            P::AccountRead
                | P::LicenseRead
                | P::BillingRead
                | P::BillingWrite
                | P::BillingReview
                | P::TeamRead
                | P::AuditRead
                | P::SystemRead
        ),
        R::SupportOperator => matches!(
            permission,
            P::AccountRead
                | P::LicenseRead
                | P::CodeRead
                | P::DeviceRead
                | P::DeviceRemove
                | P::BillingRead
                | P::TeamRead
                | P::SystemRead
        ),
        R::Auditor => matches!(
            permission,
            P::AccountRead
                | P::LicenseRead
                | P::CodeRead
                | P::DeviceRead
                | P::BillingRead
                | P::TeamRead
                | P::AuditRead
                | P::AuditExport
                | P::SystemRead
        ),
    }
}

pub(crate) async fn insert_enrollment_token(
    tx: &mut Transaction<'_, Postgres>,
    token_hash: &str,
    user_id: &str,
    purpose: &str,
    actor: &str,
    reason: &str,
    now: i64,
) -> AdminAuthResult<()> {
    sqlx::query(
        "INSERT INTO admin_enrollment_tokens
         (token_hash, user_id, purpose, created_by, reason, expires_at, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(token_hash)
    .bind(user_id)
    .bind(purpose)
    .bind(actor.trim())
    .bind(reason.trim())
    .bind(now.saturating_add(ENROLLMENT_TTL_SECONDS))
    .bind(now)
    .execute(&mut **tx)
    .await
    .map_err(|_| ApiError::Database)?;
    Ok(())
}

async fn create_session(
    tx: &mut Transaction<'_, Postgres>,
    user_id: &str,
    source_ip: Option<&str>,
    user_agent: Option<&str>,
    now: i64,
) -> AdminAuthResult<SessionCredentials> {
    let session_id = random_id("admin_session");
    let session_token = random_secret(32);
    let csrf_token = random_secret(32);
    let expires_at = now.saturating_add(SESSION_ABSOLUTE_SECONDS);
    sqlx::query(
        "INSERT INTO admin_sessions
         (id, user_id, token_hash, csrf_hash, source_ip, user_agent_hash,
          auth_time, elevated_until, last_seen_at, expires_at, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $7, $9, $7)",
    )
    .bind(&session_id)
    .bind(user_id)
    .bind(sha256_hex(&session_token))
    .bind(sha256_hex(&csrf_token))
    .bind(source_ip.map(|value| value.chars().take(128).collect::<String>()))
    .bind(user_agent.map(sha256_hex))
    .bind(now)
    .bind(now.saturating_add(STEP_UP_SECONDS))
    .bind(expires_at)
    .execute(&mut **tx)
    .await
    .map_err(|_| ApiError::Database)?;
    Ok(SessionCredentials {
        session_id,
        session_token,
        csrf_token,
        expires_at,
    })
}

async fn admin_user_in_transaction(
    tx: &mut Transaction<'_, Postgres>,
    user_id: &str,
) -> AdminAuthResult<AdminUser> {
    let row = sqlx::query(
        "SELECT u.id, u.username, u.display_name, u.status, u.row_version,
                coalesce(array_agg(r.role ORDER BY r.role)
                    FILTER (WHERE r.role IS NOT NULL), ARRAY[]::text[]) AS roles
         FROM admin_users u
         LEFT JOIN admin_role_bindings r ON r.user_id = u.id
         WHERE u.id = $1
         GROUP BY u.id",
    )
    .bind(user_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| ApiError::Database)?
    .ok_or(AdminAuthError::NotFound)?;
    let roles = row
        .try_get::<Vec<String>, _>("roles")
        .map_err(|_| ApiError::Database)?
        .into_iter()
        .map(|role| AdminRole::parse(&role))
        .collect::<AdminAuthResult<BTreeSet<_>>>()?;
    Ok(AdminUser {
        id: row.try_get("id").map_err(|_| ApiError::Database)?,
        username: row.try_get("username").map_err(|_| ApiError::Database)?,
        display_name: row
            .try_get("display_name")
            .map_err(|_| ApiError::Database)?,
        status: row.try_get("status").map_err(|_| ApiError::Database)?,
        roles,
        row_version: row.try_get("row_version").map_err(|_| ApiError::Database)?,
    })
}

async fn insert_context_auth_audit(
    tx: &mut Transaction<'_, Postgres>,
    event_type: &str,
    context: &MutationContext,
    target_id: &str,
    now: i64,
) -> AdminAuthResult<()> {
    let mut metadata = BTreeMap::from([
        ("actor".to_owned(), context.principal.id.clone()),
        ("actor_type".to_owned(), "admin".to_owned()),
        ("reason".to_owned(), context.reason.clone()),
        ("target_type".to_owned(), "admin_user".to_owned()),
        ("target_id".to_owned(), target_id.to_owned()),
    ]);
    if let Some(operation_id) = &context.operation_id {
        metadata.insert("operation_id".to_owned(), operation_id.clone());
    }
    let record = AuditEventRecord {
        id: random_id("audit"),
        event_type: event_type.to_owned(),
        outcome: "succeeded".to_owned(),
        occurred_at: now,
        account_id: None,
        license_id: None,
        device_id: None,
        reason_code: Some("admin_auth".to_owned()),
        metadata,
    };
    sqlx::query(
        "INSERT INTO audit_events
         (id, event_type, outcome, occurred_at, reason_code, metadata, document,
          actor_type, actor_id, admin_session_id, request_id, source_ip, user_agent_hash,
          target_type, target_id, operation_id)
         VALUES ($1, $2, 'succeeded', $3, 'admin_auth', $4, $5,
                 'admin', $6, $7, $8, $9, $10, 'admin_user', $11, $12)",
    )
    .bind(&record.id)
    .bind(event_type)
    .bind(now)
    .bind(serde_json::to_value(&record.metadata).map_err(|_| ApiError::Internal)?)
    .bind(serde_json::to_value(&record).map_err(|_| ApiError::Internal)?)
    .bind(&context.principal.id)
    .bind(&context.principal.session_id)
    .bind(&context.principal.request_id)
    .bind(&context.principal.source_ip)
    .bind(&context.principal.user_agent_hash)
    .bind(target_id)
    .bind(&context.operation_id)
    .execute(&mut **tx)
    .await
    .map_err(|_| ApiError::Database)?;
    Ok(())
}

async fn insert_auth_audit(
    tx: &mut Transaction<'_, Postgres>,
    event_type: &str,
    outcome: &str,
    actor: &str,
    reason: &str,
    target_id: Option<&str>,
    now: i64,
) -> AdminAuthResult<()> {
    let mut metadata = BTreeMap::from([
        ("actor".to_owned(), actor.to_owned()),
        ("actor_type".to_owned(), "admin".to_owned()),
        ("reason".to_owned(), reason.to_owned()),
        ("target_type".to_owned(), "admin_user".to_owned()),
    ]);
    if let Some(target_id) = target_id {
        metadata.insert("target_id".to_owned(), target_id.to_owned());
    }
    let record = AuditEventRecord {
        id: random_id("audit"),
        event_type: event_type.to_owned(),
        outcome: outcome.to_owned(),
        occurred_at: now,
        account_id: None,
        license_id: None,
        device_id: None,
        reason_code: Some("admin_auth".to_owned()),
        metadata,
    };
    sqlx::query(
        "INSERT INTO audit_events
         (id, event_type, outcome, occurred_at, reason_code, metadata, document,
          actor_type, actor_id, target_type, target_id)
         VALUES ($1, $2, $3, $4, 'admin_auth', $5, $6, 'admin', $7, 'admin_user', $8)",
    )
    .bind(&record.id)
    .bind(event_type)
    .bind(outcome)
    .bind(now)
    .bind(serde_json::to_value(&record.metadata).map_err(|_| ApiError::Internal)?)
    .bind(serde_json::to_value(&record).map_err(|_| ApiError::Internal)?)
    .bind(actor)
    .bind(target_id)
    .execute(&mut **tx)
    .await
    .map_err(|_| ApiError::Database)?;
    Ok(())
}

fn hash_password(password: &str, keyring: &AdminKeyring, key_id: &str) -> AdminAuthResult<String> {
    let pepper = Zeroizing::new(keyring.derive(key_id, b"password-pepper")?);
    let params = Params::new(64 * 1024, 3, 1, None).map_err(|_| AdminAuthError::Keyring)?;
    let argon2 =
        Argon2::new_with_secret(pepper.as_ref(), Algorithm::Argon2id, Version::V0x13, params)
            .map_err(|_| AdminAuthError::Keyring)?;
    let mut salt_bytes = [0_u8; 16];
    rand::fill(&mut salt_bytes);
    let salt = SaltString::encode_b64(&salt_bytes).map_err(|_| AdminAuthError::Keyring)?;
    argon2
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|_| AdminAuthError::Keyring)
}

fn verify_password(
    password: &str,
    encoded: &str,
    keyring: &AdminKeyring,
    key_id: &str,
) -> AdminAuthResult<bool> {
    let pepper = Zeroizing::new(keyring.derive(key_id, b"password-pepper")?);
    let hash = PasswordHash::new(encoded).map_err(|_| AdminAuthError::InvalidCredentials)?;
    let params = Params::new(64 * 1024, 3, 1, None).map_err(|_| AdminAuthError::Keyring)?;
    let argon2 =
        Argon2::new_with_secret(pepper.as_ref(), Algorithm::Argon2id, Version::V0x13, params)
            .map_err(|_| AdminAuthError::Keyring)?;
    Ok(argon2.verify_password(password.as_bytes(), &hash).is_ok())
}

fn encrypt_secret(
    keyring: &AdminKeyring,
    plaintext: &[u8],
    aad: &[u8],
    label: &[u8],
) -> AdminAuthResult<(String, Vec<u8>, Vec<u8>)> {
    let key_id = keyring.active_key_id().to_owned();
    let key = Zeroizing::new(keyring.derive(&key_id, label)?);
    let cipher =
        XChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| AdminAuthError::Keyring)?;
    let mut nonce = [0_u8; 24];
    rand::fill(&mut nonce);
    let nonce_value = XNonce::from(nonce);
    let ciphertext = cipher
        .encrypt(
            &nonce_value,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| AdminAuthError::Keyring)?;
    Ok((key_id, nonce.to_vec(), ciphertext))
}

fn decrypt_secret(
    keyring: &AdminKeyring,
    key_id: &str,
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
    label: &[u8],
) -> AdminAuthResult<Vec<u8>> {
    let nonce: [u8; 24] = nonce.try_into().map_err(|_| AdminAuthError::Keyring)?;
    let key = Zeroizing::new(keyring.derive(key_id, label)?);
    let nonce_value = XNonce::from(nonce);
    XChaCha20Poly1305::new_from_slice(key.as_ref())
        .map_err(|_| AdminAuthError::Keyring)?
        .decrypt(
            &nonce_value,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| AdminAuthError::Keyring)
}

fn verify_totp(
    secret: &[u8],
    input: &str,
    now: i64,
    last_used_step: Option<i64>,
) -> AdminAuthResult<i64> {
    let normalized = input.trim();
    if normalized.len() != 6 || !normalized.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(AdminAuthError::InvalidCredentials);
    }
    for offset in [-1_i64, 0, 1] {
        let step = now.div_euclid(30).saturating_add(offset);
        if last_used_step.is_some_and(|last| step <= last) {
            continue;
        }
        if totp(secret, step)
            .as_bytes()
            .ct_eq(normalized.as_bytes())
            .into()
        {
            return Ok(step);
        }
    }
    Err(AdminAuthError::InvalidCredentials)
}

fn totp(secret: &[u8], step: i64) -> String {
    type HmacSha1 = Hmac<Sha1>;
    let mut mac = <HmacSha1 as KeyInit>::new_from_slice(secret).expect("HMAC accepts any key size");
    mac.update(&(step.max(0) as u64).to_be_bytes());
    let output = mac.finalize().into_bytes();
    let offset = usize::from(output[19] & 0x0f);
    let value = (u32::from(output[offset] & 0x7f) << 24)
        | (u32::from(output[offset + 1]) << 16)
        | (u32::from(output[offset + 2]) << 8)
        | u32::from(output[offset + 3]);
    format!("{:06}", value % 1_000_000)
}

fn validate_password(password: &str, username: Option<&str>) -> AdminAuthResult<()> {
    let length = password.chars().count();
    if !(14..=128).contains(&length) {
        return Err(AdminAuthError::Validation(
            "password must contain 14 to 128 characters".to_owned(),
        ));
    }
    let lower = password.to_lowercase();
    if username.is_some_and(|username| lower.contains(username))
        || COMMON_PASSWORDS.iter().any(|common| lower.contains(common))
    {
        return Err(AdminAuthError::Validation(
            "password is too predictable".to_owned(),
        ));
    }
    Ok(())
}

pub(crate) fn normalize_username(username: &str) -> AdminAuthResult<String> {
    let normalized = normalize_username_for_login(username);
    let valid = (3..=64).contains(&normalized.len())
        && normalized
            .bytes()
            .enumerate()
            .all(|(index, byte)| match byte {
                b'a'..=b'z' | b'0'..=b'9' => true,
                b'.' | b'_' | b'-' => index != 0,
                _ => false,
            });
    if valid {
        Ok(normalized)
    } else {
        Err(AdminAuthError::Validation(
            "username must use 3 to 64 lowercase ASCII letters, digits, dots, dashes or underscores"
                .to_owned(),
        ))
    }
}

fn normalize_username_for_login(username: &str) -> String {
    username.trim().to_ascii_lowercase()
}

pub(crate) fn validate_display_name(value: &str) -> AdminAuthResult<()> {
    validate_audit_text(value, "display name", 128)
}

fn validate_audit_text(value: &str, name: &str, maximum: usize) -> AdminAuthResult<()> {
    let length = value.trim().chars().count();
    if length == 0 || length > maximum {
        return Err(AdminAuthError::Validation(format!(
            "{name} must contain 1 to {maximum} characters"
        )));
    }
    Ok(())
}

fn login_bucket_key(username: &str, source_ip: Option<&str>) -> String {
    sha256_hex(&format!("{username}\0{}", source_ip.unwrap_or("unknown")))
}

fn random_secret(bytes: usize) -> String {
    let mut value = vec![0_u8; bytes];
    rand::fill(&mut value[..]);
    URL_SAFE_NO_PAD.encode(value)
}

fn recovery_enrollment_token(
    keyring: &AdminKeyring,
    user_id: &str,
    code_hash: &str,
) -> AdminAuthResult<String> {
    type HmacSha256 = Hmac<Sha256>;
    let mut key = keyring.derive(keyring.active_key_id(), b"admin-recovery-enrollment")?;
    let mut mac =
        <HmacSha256 as KeyInit>::new_from_slice(&key).map_err(|_| AdminAuthError::Keyring)?;
    key.zeroize();
    mac.update(b"camellia.nexus.admin-recovery.v1");
    mac.update(&(user_id.len() as u64).to_be_bytes());
    mac.update(user_id.as_bytes());
    mac.update(&(code_hash.len() as u64).to_be_bytes());
    mac.update(code_hash.as_bytes());
    Ok(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
}

fn recovery_codes() -> Vec<String> {
    (0..10)
        .map(|_| {
            let value = random_secret(12).to_ascii_uppercase();
            format!("CNXR-{}-{}-{}", &value[0..5], &value[5..10], &value[10..])
        })
        .collect()
}

fn base32_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut output = String::with_capacity((input.len() * 8).div_ceil(5));
    let mut buffer = 0_u32;
    let mut bits = 0_u8;
    for &byte in input {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            output.push(char::from(ALPHABET[((buffer >> bits) & 0x1f) as usize]));
        }
    }
    if bits > 0 {
        output.push(char::from(
            ALPHABET[((buffer << (5 - bits)) & 0x1f) as usize],
        ));
    }
    output
}

const COMMON_PASSWORDS: &[&str] = &[
    "password",
    "qwerty",
    "administrator",
    "camellia-nexus",
    "letmein",
    "welcome",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_keyring_requires_one_strict_canonical_contract() {
        let root = URL_SAFE_NO_PAD.encode([7_u8; 32]);
        let document = |active_key_id: &str, key_id: &str, encoded_key: &str| {
            let mut keys = serde_json::Map::new();
            keys.insert(key_id.to_owned(), serde_json::json!(encoded_key));
            serde_json::to_vec(&serde_json::json!({
                "activeKeyId": active_key_id,
                "keys": keys,
            }))
            .expect("serialize keyring test document")
        };

        let valid = document("admin-2026-07", "admin-2026-07", &root);
        let keyring = AdminKeyring::from_slice(&valid).expect("load canonical admin keyring");
        assert_eq!(keyring.active_key_id(), "admin-2026-07");

        for invalid in [
            document(" admin-2026-07", "admin-2026-07", &root),
            document("admin-2026-07", "admin key", &root),
            document("admin-2026-07", "admin-2026-07", &format!(" {root}")),
            document("missing-key", "admin-2026-07", &root),
            document("admin-2026-07", "admin-2026-07", "too-short"),
        ] {
            assert!(matches!(
                AdminKeyring::from_slice(&invalid),
                Err(AdminAuthError::Keyring)
            ));
        }

        let mut unknown: serde_json::Value =
            serde_json::from_slice(&valid).expect("parse keyring test document");
        unknown["unexpected"] = serde_json::json!(true);
        assert!(matches!(
            AdminKeyring::from_slice(
                &serde_json::to_vec(&unknown).expect("serialize invalid keyring")
            ),
            Err(AdminAuthError::Keyring)
        ));
    }

    #[test]
    fn role_permissions_keep_financial_override_owner_only() {
        assert!(role_allows(
            AdminRole::PlatformOwner,
            AdminPermission::BillingOverride
        ));
        assert!(!role_allows(
            AdminRole::BillingAdmin,
            AdminPermission::BillingOverride
        ));
    }

    #[test]
    fn base32_matches_rfc_example() {
        assert_eq!(base32_encode(b"foo"), "MZXW6");
    }

    #[test]
    fn totp_matches_rfc_6238_sha1_vector() {
        assert_eq!(totp(b"12345678901234567890", 1), "287082");
    }

    #[test]
    fn username_is_canonicalized() {
        assert_eq!(normalize_username("  Admin.One ").unwrap(), "admin.one");
        assert!(normalize_username("invalid name").is_err());
    }

    #[test]
    fn recovery_enrollment_tokens_are_retry_safe_and_subject_bound() {
        let keyring = AdminKeyring::ephemeral();
        let code_hash = sha256_hex("RECOVERY-CODE");
        let first = recovery_enrollment_token(&keyring, "user-a", &code_hash).unwrap();
        let retry = recovery_enrollment_token(&keyring, "user-a", &code_hash).unwrap();
        let other_user = recovery_enrollment_token(&keyring, "user-b", &code_hash).unwrap();
        let other_code =
            recovery_enrollment_token(&keyring, "user-a", &sha256_hex("OTHER-CODE")).unwrap();

        assert_eq!(first, retry);
        assert_ne!(first, other_user);
        assert_ne!(first, other_code);
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn recovery_revokes_old_factors_and_remains_retry_safe() {
        let database_url = std::env::var("TEST_DATABASE_URL")
            .expect("TEST_DATABASE_URL is required for the PostgreSQL integration test");
        let repository =
            PostgresRepository::connect(&database_url, 2, std::time::Duration::from_secs(5))
                .await
                .expect("connect PostgreSQL");
        repository.migrate().await.expect("run migrations");
        let application = AdminApplication::new(repository.clone(), 24 * 60 * 60)
            .await
            .expect("initialize admin application");
        let keyring = Arc::new(AdminKeyring::ephemeral());
        let service = AdminAuthService::new(application.clone(), keyring.clone()).unwrap();
        let now = application.trusted_now().await.unwrap();
        let suffix = random_id("recovery_test");
        let user_id = format!("admin_{suffix}");
        let username = format!("recover-{suffix}");
        let session_id = format!("session_{suffix}");
        let password = "Unrelated-Volcano-72!Orbit";
        let recovery_code = "CNXR-ABCDE-FGHIJ-KLMNO";
        let key_id = keyring.active_key_id().to_owned();
        let password_hash = hash_password(password, &keyring, &key_id).unwrap();
        let (totp_key_id, nonce, ciphertext) = keyring
            .seal(b"admin-totp", user_id.as_bytes(), b"test-totp-secret")
            .unwrap();
        let mut tx = repository.pool.begin().await.unwrap();
        sqlx::query(
            "INSERT INTO admin_users
             (id, username, display_name, status, created_at, updated_at)
             VALUES ($1, $2, 'Recovery test', 'active', $3, $3)",
        )
        .bind(&user_id)
        .bind(&username)
        .bind(now)
        .execute(&mut *tx)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO admin_password_credentials
             (user_id, password_hash, key_id, changed_at) VALUES ($1, $2, $3, $4)",
        )
        .bind(&user_id)
        .bind(password_hash)
        .bind(&key_id)
        .bind(now)
        .execute(&mut *tx)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO admin_totp_credentials
             (user_id, key_id, nonce, ciphertext, confirmed_at)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(&user_id)
        .bind(totp_key_id)
        .bind(nonce)
        .bind(ciphertext)
        .bind(now)
        .execute(&mut *tx)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO admin_recovery_codes (user_id, code_hash, created_at)
             VALUES ($1, $2, $3)",
        )
        .bind(&user_id)
        .bind(sha256_hex(recovery_code))
        .bind(now)
        .execute(&mut *tx)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO admin_sessions
             (id, user_id, token_hash, csrf_hash, auth_time, elevated_until,
              last_seen_at, expires_at, created_at)
             VALUES ($1, $2, $3, $4, $5, $5, $5, $6, $5)",
        )
        .bind(&session_id)
        .bind(&user_id)
        .bind(sha256_hex(&format!("token-{suffix}")))
        .bind(sha256_hex(&format!("csrf-{suffix}")))
        .bind(now)
        .bind(now + 3600)
        .execute(&mut *tx)
        .await
        .unwrap();
        tx.commit().await.unwrap();

        keyring.readiness_check(&repository).await.unwrap();
        sqlx::query(
            "UPDATE admin_password_credentials SET key_id = 'missing-test-key' WHERE user_id = $1",
        )
        .bind(&user_id)
        .execute(&repository.pool)
        .await
        .unwrap();
        assert!(matches!(
            keyring.readiness_check(&repository).await,
            Err(AdminAuthError::Keyring)
        ));
        sqlx::query("UPDATE admin_password_credentials SET key_id = $2 WHERE user_id = $1")
            .bind(&user_id)
            .bind(&key_id)
            .execute(&repository.pool)
            .await
            .unwrap();

        let first = service
            .begin_recovery(&username, password, recovery_code, Some("127.0.0.1"))
            .await
            .unwrap();
        let retry = service
            .begin_recovery(&username, password, recovery_code, Some("127.0.0.1"))
            .await
            .unwrap();
        assert_eq!(first.token, retry.token);
        let row = sqlx::query(
            "SELECT u.status,
                    EXISTS (SELECT 1 FROM admin_password_credentials p WHERE p.user_id = u.id) AS has_password,
                    EXISTS (SELECT 1 FROM admin_totp_credentials t WHERE t.user_id = u.id) AS has_totp,
                    EXISTS (SELECT 1 FROM admin_recovery_codes r WHERE r.user_id = u.id) AS has_recovery,
                    EXISTS (SELECT 1 FROM admin_sessions s WHERE s.user_id = u.id AND s.revoked_at IS NULL) AS has_session
             FROM admin_users u WHERE u.id = $1",
        )
        .bind(&user_id)
        .fetch_one(&repository.pool)
        .await
        .unwrap();
        assert_eq!(row.try_get::<String, _>("status").unwrap(), "pending");
        assert!(row.try_get::<bool, _>("has_password").unwrap());
        assert!(!row.try_get::<bool, _>("has_totp").unwrap());
        assert!(!row.try_get::<bool, _>("has_recovery").unwrap());
        assert!(!row.try_get::<bool, _>("has_session").unwrap());

        sqlx::query("DELETE FROM audit_events WHERE target_id = $1")
            .bind(&user_id)
            .execute(&repository.pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM admin_users WHERE id = $1")
            .bind(&user_id)
            .execute(&repository.pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn password_change_is_retry_safe_and_revokes_every_session() {
        let database_url = std::env::var("TEST_DATABASE_URL")
            .expect("TEST_DATABASE_URL is required for the PostgreSQL integration test");
        let repository =
            PostgresRepository::connect(&database_url, 2, std::time::Duration::from_secs(5))
                .await
                .expect("connect PostgreSQL");
        repository.migrate().await.expect("run migrations");
        let application = AdminApplication::new(repository.clone(), 24 * 60 * 60)
            .await
            .expect("initialize admin application");
        let keyring = Arc::new(AdminKeyring::ephemeral());
        let service = AdminAuthService::new(application.clone(), keyring.clone()).unwrap();
        let now = application.trusted_now().await.unwrap();
        let suffix = random_id("password_change_test");
        let user_id = format!("admin_{suffix}");
        let username = format!("password-{suffix}");
        let session_id = format!("session_{suffix}");
        let operation_id = format!("password-change-{suffix}");
        let old_password = "Unrelated-Volcano-72!Orbit";
        let new_password = "Distant-Cedar-94!River";
        let key_id = keyring.active_key_id().to_owned();
        let password_hash = hash_password(old_password, &keyring, &key_id).unwrap();
        let mut tx = repository.pool.begin().await.unwrap();
        sqlx::query(
            "INSERT INTO admin_users
             (id, username, display_name, status, created_at, updated_at)
             VALUES ($1, $2, 'Password change test', 'active', $3, $3)",
        )
        .bind(&user_id)
        .bind(&username)
        .bind(now)
        .execute(&mut *tx)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO admin_role_bindings
             (user_id, role, granted_by, reason, created_at)
             VALUES ($1, 'platform_owner', 'test', 'password lifecycle test', $2)",
        )
        .bind(&user_id)
        .bind(now)
        .execute(&mut *tx)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO admin_password_credentials
             (user_id, password_hash, key_id, changed_at) VALUES ($1, $2, $3, $4)",
        )
        .bind(&user_id)
        .bind(password_hash)
        .bind(&key_id)
        .bind(now)
        .execute(&mut *tx)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO admin_sessions
             (id, user_id, token_hash, csrf_hash, auth_time, elevated_until,
              last_seen_at, expires_at, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $5, $7, $5)",
        )
        .bind(&session_id)
        .bind(&user_id)
        .bind(sha256_hex(&format!("token-{suffix}")))
        .bind(sha256_hex(&format!("csrf-{suffix}")))
        .bind(now)
        .bind(now + 600)
        .bind(now + 3600)
        .execute(&mut *tx)
        .await
        .unwrap();
        tx.commit().await.unwrap();

        let mut context = MutationContext::new(
            crate::admin_app::AdminPrincipal {
                id: user_id.clone(),
                session_id: Some(session_id),
                source_ip: Some("127.0.0.1".to_owned()),
                user_agent_hash: Some(sha256_hex("password-change-test")),
                request_id: None,
            },
            "rotate the administrator password",
        )
        .unwrap();
        context.operation_id = Some(operation_id.clone());
        let changed = service
            .change_password(&user_id, new_password, 1, &context)
            .await
            .unwrap();
        let replay = service
            .change_password(&user_id, new_password, 1, &context)
            .await
            .unwrap();
        assert_eq!(changed.row_version, 2);
        assert_eq!(changed.row_version, replay.row_version);

        let row = sqlx::query(
            "SELECT p.password_hash, p.key_id,
                    EXISTS (
                        SELECT 1 FROM admin_sessions s
                        WHERE s.user_id = p.user_id AND s.revoked_at IS NULL
                    ) AS has_active_session
             FROM admin_password_credentials p WHERE p.user_id = $1",
        )
        .bind(&user_id)
        .fetch_one(&repository.pool)
        .await
        .unwrap();
        assert!(
            service
                .password_hashes
                .verify(
                    new_password,
                    row.try_get("password_hash").unwrap(),
                    keyring,
                    row.try_get("key_id").unwrap(),
                )
                .await
                .unwrap()
        );
        assert!(!row.try_get::<bool, _>("has_active_session").unwrap());
        let audits: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM audit_events
             WHERE event_type = 'admin_password_changed' AND operation_id = $1",
        )
        .bind(&operation_id)
        .fetch_one(&repository.pool)
        .await
        .unwrap();
        assert_eq!(audits, 1);
        assert!(matches!(
            service
                .change_password(&user_id, "Another-Secure-57!Forest", 1, &context)
                .await,
            Err(AdminAuthError::Conflict)
        ));

        sqlx::query("DELETE FROM admin_operations WHERE operation_id = $1")
            .bind(&operation_id)
            .execute(&repository.pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM audit_events WHERE target_id = $1")
            .bind(&user_id)
            .execute(&repository.pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM admin_users WHERE id = $1")
            .bind(&user_id)
            .execute(&repository.pool)
            .await
            .unwrap();
    }
}
