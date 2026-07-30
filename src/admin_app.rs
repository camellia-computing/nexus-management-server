use std::collections::BTreeMap;

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use sqlx::Row;
use thiserror::Error;

use crate::{
    admin_auth::AdminPermission,
    admin_operation::{self, AdminOperationClaim},
    config::time_max_forward_jump_seconds_from_env,
    contracts::{DeviceState, Plan},
    crypto::{
        activation_code_prefix, canonicalize_activation_code, generate_activation_code, random_id,
        sha256_hex,
    },
    domain::{
        Account, AccountState, ActivationCodeRecord, ActivationCodeStatus, AuditEventRecord,
        Device, License, LicenseStatus,
    },
    error::ApiError,
    plan_catalog::{
        CURRENT_PLAN_REVISION, TEAM_MAXIMUM_SEATS, TEAM_MINIMUM_SEATS, validate_purchased_seats,
    },
    store::{
        ActivationCodeBatchCommit, ActivationCodeDeliveryReceipt, AdminSecretDeliveryInsert,
        LicenseRepository, PostgresRepository, TimeAuthorityStatus,
    },
    time_authority::PersistentTimeAuthority,
};

const DEFAULT_PAGE_SIZE: u32 = 50;
const MAX_PAGE_SIZE: u32 = 100;

#[derive(Debug, Error)]
pub enum AdminAppError {
    #[error("{0}")]
    Validation(String),
    #[error("resource not found")]
    NotFound,
    #[error("resource version conflict")]
    VersionConflict,
    #[error("idempotency key conflicts with an earlier request")]
    IdempotencyConflict,
    #[error(
        "activation-code batch already committed; plaintext cannot be replayed; inspect and revoke the original batch before issuing a replacement"
    )]
    SecretReplayUnavailable,
    #[error("permission denied")]
    PermissionDenied,
    #[error("recent password and TOTP verification is required")]
    StepUpRequired,
    #[error("secret delivery could not be prepared")]
    SecretDelivery,
    #[error(transparent)]
    Service(#[from] ApiError),
    #[error(transparent)]
    Serialization(#[from] serde_json::Error),
}

pub type AdminAppResult<T> = Result<T, AdminAppError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct PageRequest {
    #[serde(default)]
    pub cursor: Option<String>,
    #[serde(default = "default_page_size")]
    pub page_size: u32,
    #[serde(default)]
    pub query: Option<String>,
}

impl Default for PageRequest {
    fn default() -> Self {
        Self {
            cursor: None,
            page_size: DEFAULT_PAGE_SIZE,
            query: None,
        }
    }
}

impl PageRequest {
    pub fn validate(mut self) -> AdminAppResult<Self> {
        if !(1..=MAX_PAGE_SIZE).contains(&self.page_size) {
            return Err(AdminAppError::Validation(format!(
                "pageSize must be between 1 and {MAX_PAGE_SIZE}"
            )));
        }
        self.cursor = self.cursor.and_then(non_empty);
        self.query = self.query.and_then(non_empty);
        if self.query.as_ref().is_some_and(|query| query.len() > 128) {
            return Err(AdminAppError::Validation(
                "query must not exceed 128 characters".to_owned(),
            ));
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Page<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Versioned<T> {
    #[serde(flatten)]
    pub value: T,
    pub row_version: i64,
}

#[derive(Debug, Clone)]
pub struct AdminPrincipal {
    pub id: String,
    pub session_id: Option<String>,
    pub source_ip: Option<String>,
    pub user_agent_hash: Option<String>,
    pub request_id: Option<String>,
}

impl AdminPrincipal {
    pub fn cli(actor: impl Into<String>) -> AdminAppResult<Self> {
        let id = actor.into().trim().to_owned();
        if id.is_empty() || id.len() > 128 {
            return Err(AdminAppError::Validation(
                "actor must contain 1 to 128 characters".to_owned(),
            ));
        }
        Ok(Self {
            id,
            session_id: None,
            source_ip: None,
            user_agent_hash: None,
            request_id: None,
        })
    }
}

#[derive(Debug, Clone)]
pub struct MutationContext {
    pub principal: AdminPrincipal,
    pub reason: String,
    pub operation_id: Option<String>,
    pub job_id: Option<String>,
}

impl MutationContext {
    pub fn new(principal: AdminPrincipal, reason: impl Into<String>) -> AdminAppResult<Self> {
        let reason = reason.into().trim().to_owned();
        if reason.is_empty() || reason.len() > 512 {
            return Err(AdminAppError::Validation(
                "reason must contain 1 to 512 characters".to_owned(),
            ));
        }
        Ok(Self {
            principal,
            reason,
            operation_id: None,
            job_id: None,
        })
    }
}

#[derive(Debug, Clone)]
pub struct NewLicense {
    pub id: String,
    pub account_id: String,
    pub plan: Plan,
    pub status: LicenseStatus,
    pub expires_at: Option<i64>,
    pub purchased_seats: u32,
}

pub(crate) fn validate_license_seats(plan: Plan, purchased_seats: u32) -> AdminAppResult<()> {
    validate_purchased_seats(plan, purchased_seats).map_err(|_| {
        AdminAppError::Validation(match plan {
            Plan::Team => format!(
                "Team purchasedSeats must be between {TEAM_MINIMUM_SEATS} and {TEAM_MAXIMUM_SEATS}"
            ),
            Plan::Free | Plan::Pro => {
                "purchasedSeats must be zero for Free and Pro licenses".to_owned()
            }
        })
    })
}

pub(crate) fn apply_license_plan(
    license: &mut License,
    plan: Plan,
    purchased_seats: Option<u32>,
) -> AdminAppResult<()> {
    let seats = match plan {
        Plan::Team => match purchased_seats {
            Some(seats) => seats,
            None if license.plan == Plan::Team => license.purchased_seats,
            None => {
                return Err(AdminAppError::Validation(
                    "purchasedSeats is required when changing to the Team plan".to_owned(),
                ));
            }
        },
        Plan::Free | Plan::Pro => {
            if purchased_seats.is_some_and(|seats| seats != 0) {
                return Err(AdminAppError::Validation(
                    "purchasedSeats must be omitted or zero for Free and Pro licenses".to_owned(),
                ));
            }
            0
        }
    };
    validate_license_seats(plan, seats)?;
    let changed = license.plan != plan
        || license.plan_revision != CURRENT_PLAN_REVISION
        || license.purchased_seats != seats;
    license.plan = plan;
    license.plan_revision = CURRENT_PLAN_REVISION;
    license.purchased_seats = seats;
    if changed {
        license.license_epoch = license.license_epoch.saturating_add(1);
        license.row_version = license.row_version.saturating_add(1);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActivationCodeExpiryKind {
    NoExpiry,
    Absolute(i64),
    RelativeSeconds(i64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActivationCodeExpiry(ActivationCodeExpiryKind);

impl ActivationCodeExpiry {
    pub fn fixed(expires_at: Option<i64>) -> Self {
        match expires_at {
            Some(expires_at) => Self(ActivationCodeExpiryKind::Absolute(expires_at)),
            None => Self(ActivationCodeExpiryKind::NoExpiry),
        }
    }

    pub fn relative_seconds(seconds: i64) -> AdminAppResult<Self> {
        if seconds <= 0 {
            return Err(AdminAppError::Validation(
                "activation-code relative expiry must be positive".to_owned(),
            ));
        }
        Ok(Self(ActivationCodeExpiryKind::RelativeSeconds(seconds)))
    }

    fn resolve(self, now: i64) -> AdminAppResult<Option<i64>> {
        match self.0 {
            ActivationCodeExpiryKind::NoExpiry => Ok(None),
            ActivationCodeExpiryKind::Absolute(expires_at) => Ok(Some(expires_at)),
            ActivationCodeExpiryKind::RelativeSeconds(seconds) => {
                now.checked_add(seconds).map(Some).ok_or_else(|| {
                    AdminAppError::Validation(
                        "activation-code relative expiry exceeds the supported time range"
                            .to_owned(),
                    )
                })
            }
        }
    }

    fn operation_value(self) -> Value {
        match self.0 {
            ActivationCodeExpiryKind::NoExpiry => json!({ "mode": "no_expiry" }),
            ActivationCodeExpiryKind::Absolute(expires_at) => {
                json!({ "mode": "absolute", "value": expires_at })
            }
            ActivationCodeExpiryKind::RelativeSeconds(seconds) => {
                json!({ "mode": "relative_seconds", "value": seconds })
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct ActivationCodeBatchRequest {
    pub account_id: String,
    pub license_id: String,
    pub count: u32,
    pub max_redemptions: u32,
    pub expiry: ActivationCodeExpiry,
    pub channel: Option<String>,
    pub note: Option<String>,
    pub operation_id: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IssuedActivationCode {
    pub code: String,
    pub code_prefix: String,
    pub code_hash: String,
    pub account_id: String,
    pub license_id: String,
    pub expires_at: Option<i64>,
    pub max_redemptions: u32,
    pub channel: Option<String>,
    pub issued_by: String,
}

#[derive(Debug, Clone)]
pub struct ActivationCodeDeliveryDraft {
    pub id: String,
    pub actor_id: String,
    pub session_id: String,
    pub claim_token_hash: String,
    pub expires_at: i64,
}

struct PreparedActivationCodeBatch {
    issued: Vec<IssuedActivationCode>,
    records: Vec<ActivationCodeRecord>,
    audits: Vec<AuditEventRecord>,
    request_hash: String,
    created_at: i64,
}

#[derive(Clone)]
pub struct AdminApplication {
    repository: PostgresRepository,
    persistent_time: PersistentTimeAuthority,
}

impl AdminApplication {
    pub async fn new(
        repository: PostgresRepository,
        time_max_forward_jump_seconds: i64,
    ) -> AdminAppResult<Self> {
        if time_max_forward_jump_seconds <= 0 {
            return Err(AdminAppError::Validation(
                "time authority maximum forward jump must be positive".to_owned(),
            ));
        }
        let observation = repository
            .observe_time_authority(None, time_max_forward_jump_seconds)
            .await?;
        if observation.status == TimeAuthorityStatus::ForwardJump {
            return Err(ApiError::TimeAuthorityUnavailable.into());
        }
        Ok(Self {
            repository,
            persistent_time: PersistentTimeAuthority::new(
                observation.trusted_unix,
                time_max_forward_jump_seconds,
            ),
        })
    }

    pub async fn from_environment(repository: PostgresRepository) -> AdminAppResult<Self> {
        Self::new(
            repository,
            time_max_forward_jump_seconds_from_env().map_err(|error| {
                AdminAppError::Validation(format!("invalid time authority configuration: {error}"))
            })?,
        )
        .await
    }

    pub fn repository(&self) -> &PostgresRepository {
        &self.repository
    }

    pub async fn trusted_now(&self) -> AdminAppResult<i64> {
        let observation = self
            .repository
            .observe_time_authority(
                Some(self.persistent_time.now()),
                self.persistent_time.max_forward_jump_seconds,
            )
            .await?;
        self.persistent_time.observe(observation.trusted_unix);
        if observation.status == TimeAuthorityStatus::ForwardJump {
            Err(ApiError::TimeAuthorityUnavailable.into())
        } else {
            Ok(observation.trusted_unix)
        }
    }

    async fn replay_operation<T: DeserializeOwned>(
        &self,
        operation: Option<&AdminOperationClaim>,
    ) -> AdminAppResult<Option<T>> {
        match operation {
            Some(operation) => admin_operation::replay(&self.repository.pool, operation).await,
            None => Ok(None),
        }
    }

    pub async fn accounts(&self, request: PageRequest) -> AdminAppResult<Page<Versioned<Account>>> {
        let request = request.validate()?;
        let limit = i64::from(request.page_size) + 1;
        let rows = sqlx::query(
            "SELECT document, row_version FROM accounts
             WHERE ($1::text IS NULL OR id > $1)
               AND ($2::text IS NULL OR lower(id) LIKE lower($2) || '%' OR
                    lower(coalesce(document ->> 'note', '')) LIKE lower($2) || '%')
             ORDER BY id ASC LIMIT $3",
        )
        .bind(request.cursor.as_deref())
        .bind(request.query.as_deref())
        .bind(limit)
        .fetch_all(&self.repository.pool)
        .await
        .map_err(|_| ApiError::Database)?;
        page_from_rows(rows, request.page_size, |value: &Account| value.id.clone())
    }

    pub async fn licenses(
        &self,
        account_id: Option<&str>,
        request: PageRequest,
    ) -> AdminAppResult<Page<Versioned<License>>> {
        let request = request.validate()?;
        let limit = i64::from(request.page_size) + 1;
        let rows = sqlx::query(
            "SELECT to_jsonb(licenses) - 'created_at' - 'updated_at' AS document, row_version
             FROM licenses
             WHERE ($1::text IS NULL OR id > $1)
               AND ($2::text IS NULL OR account_id = $2)
               AND ($3::text IS NULL OR lower(id) LIKE lower($3) || '%' OR
                    lower(account_id) LIKE lower($3) || '%')
             ORDER BY id ASC LIMIT $4",
        )
        .bind(request.cursor.as_deref())
        .bind(account_id)
        .bind(request.query.as_deref())
        .bind(limit)
        .fetch_all(&self.repository.pool)
        .await
        .map_err(|_| ApiError::Database)?;
        page_from_rows(rows, request.page_size, |value: &License| value.id.clone())
    }

    pub async fn devices(
        &self,
        account_id: Option<&str>,
        request: PageRequest,
    ) -> AdminAppResult<Page<Versioned<Device>>> {
        let request = request.validate()?;
        let limit = i64::from(request.page_size) + 1;
        let rows = sqlx::query(
            "SELECT document, row_version FROM devices
             WHERE ($1::text IS NULL OR device_id > $1)
               AND ($2::text IS NULL OR account_id = $2)
               AND ($3::text IS NULL OR lower(device_id) LIKE lower($3) || '%' OR
                    lower(account_id) LIKE lower($3) || '%' OR
                    lower(coalesce(document -> 'metadata' ->> 'display_name', '')) LIKE lower($3) || '%')
             ORDER BY device_id ASC LIMIT $4",
        )
        .bind(request.cursor.as_deref())
        .bind(account_id)
        .bind(request.query.as_deref())
        .bind(limit)
        .fetch_all(&self.repository.pool)
        .await
        .map_err(|_| ApiError::Database)?;
        page_from_rows(rows, request.page_size, |value: &Device| {
            value.metadata.device_id.clone()
        })
    }

    pub async fn activation_codes(
        &self,
        account_id: Option<&str>,
        status: Option<ActivationCodeStatus>,
        request: PageRequest,
    ) -> AdminAppResult<Page<Versioned<ActivationCodeRecord>>> {
        let request = request.validate()?;
        let limit = i64::from(request.page_size) + 1;
        let status = status.map(activation_code_status_name);
        let rows = sqlx::query(
            "SELECT document, row_version FROM activation_codes
             WHERE ($1::text IS NULL OR code_hash > $1)
               AND ($2::text IS NULL OR account_id = $2)
               AND ($3::text IS NULL OR status = $3)
               AND ($4::text IS NULL OR lower(code_prefix) LIKE lower($4) || '%' OR
                    lower(account_id) LIKE lower($4) || '%' OR lower(code_hash) = lower($4))
             ORDER BY code_hash ASC LIMIT $5",
        )
        .bind(request.cursor.as_deref())
        .bind(account_id)
        .bind(status)
        .bind(request.query.as_deref())
        .bind(limit)
        .fetch_all(&self.repository.pool)
        .await
        .map_err(|_| ApiError::Database)?;
        page_from_rows(rows, request.page_size, |value: &ActivationCodeRecord| {
            value.code_hash.clone()
        })
    }

    pub async fn account(&self, id: &str) -> AdminAppResult<Option<Versioned<Account>>> {
        versioned_document(
            sqlx::query("SELECT document, row_version FROM accounts WHERE id = $1")
                .bind(id)
                .fetch_optional(&self.repository.pool)
                .await
                .map_err(|_| ApiError::Database)?,
        )
    }

    pub async fn license(&self, id: &str) -> AdminAppResult<Option<Versioned<License>>> {
        let Some(row) = sqlx::query(
            "SELECT id, account_id, plan, plan_revision, status, expires_at,
                    license_epoch, purchased_seats, row_version FROM licenses WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.repository.pool)
        .await
        .map_err(|_| ApiError::Database)?
        else {
            return Ok(None);
        };
        let value = License {
            id: row.try_get("id").map_err(|_| ApiError::Database)?,
            account_id: row.try_get("account_id").map_err(|_| ApiError::Database)?,
            plan: parse_plan_db(
                row.try_get::<String, _>("plan")
                    .map_err(|_| ApiError::Database)?,
            )?,
            plan_revision: u32::try_from(
                row.try_get::<i32, _>("plan_revision")
                    .map_err(|_| ApiError::Database)?,
            )
            .map_err(|_| ApiError::Database)?,
            status: parse_license_status_db(
                row.try_get::<String, _>("status")
                    .map_err(|_| ApiError::Database)?,
            )?,
            expires_at: row.try_get("expires_at").map_err(|_| ApiError::Database)?,
            license_epoch: u64::try_from(
                row.try_get::<i64, _>("license_epoch")
                    .map_err(|_| ApiError::Database)?,
            )
            .map_err(|_| ApiError::Database)?,
            purchased_seats: u32::try_from(
                row.try_get::<i32, _>("purchased_seats")
                    .map_err(|_| ApiError::Database)?,
            )
            .map_err(|_| ApiError::Database)?,
            row_version: u64::try_from(
                row.try_get::<i64, _>("row_version")
                    .map_err(|_| ApiError::Database)?,
            )
            .map_err(|_| ApiError::Database)?,
        };
        Ok(Some(Versioned {
            row_version: i64::try_from(value.row_version).map_err(|_| ApiError::Database)?,
            value,
        }))
    }

    pub async fn create_account(
        &self,
        id: &str,
        note: Option<String>,
        context: &MutationContext,
    ) -> AdminAppResult<Account> {
        validate_identifier(id, "account id", 128)?;
        if note.as_ref().is_some_and(|note| note.len() > 1_024) {
            return Err(AdminAppError::Validation(
                "account note must not exceed 1024 characters".to_owned(),
            ));
        }
        let operation = admin_operation::prepare(
            "account.create",
            &json!({"accountId": id, "note": note}),
            context,
        )?;
        if let Some(replayed) = self.replay_operation(operation.as_ref()).await? {
            return Ok(replayed);
        }
        let now = self.trusted_now().await?;
        let mut account = Account::active(id, now);
        account.note = note;
        let audit = admin_audit("account_created", context, Some(id), None, None, now);
        self.repository
            .create_account_with_audit(
                account,
                audit,
                operation.as_ref(),
                context,
                AdminPermission::AccountWrite,
            )
            .await
    }

    pub async fn set_account_state(
        &self,
        id: &str,
        state: AccountState,
        expected_version: Option<i64>,
        context: &MutationContext,
    ) -> AdminAppResult<Account> {
        let operation = admin_operation::prepare(
            "account.set_state",
            &json!({
                "accountId": id,
                "state": state,
                "expectedVersion": expected_version,
            }),
            context,
        )?;
        if let Some(replayed) = self.replay_operation(operation.as_ref()).await? {
            return Ok(replayed);
        }
        let current = self.account(id).await?.ok_or(AdminAppError::NotFound)?;
        if expected_version.is_some_and(|version| version != current.row_version) {
            if let Some(replayed) = self.replay_operation(operation.as_ref()).await? {
                return Ok(replayed);
            }
            return Err(AdminAppError::VersionConflict);
        }
        let expected_document = serde_json::to_value(&current.value)?;
        let mut account = current.value;
        let changed = account.state != state;
        let now = self.trusted_now().await?;
        if changed {
            account.state = state;
            account.updated_at = now;
        }
        let audit = admin_audit("account_state_set", context, Some(id), None, None, now);
        let permission = if state == AccountState::Denylisted {
            AdminPermission::AccountDenylist
        } else {
            AdminPermission::AccountWrite
        };
        self.repository
            .update_account_with_audit(
                account,
                expected_document,
                changed && state != AccountState::Active,
                audit,
                operation.as_ref(),
                context,
                permission,
            )
            .await
    }

    pub async fn create_license(
        &self,
        request: NewLicense,
        context: &MutationContext,
    ) -> AdminAppResult<License> {
        validate_identifier(&request.id, "license id", 128)?;
        validate_license_seats(request.plan, request.purchased_seats)?;
        let operation = admin_operation::prepare(
            "license.create",
            &json!({
                "licenseId": request.id,
                "accountId": request.account_id,
                "plan": request.plan,
                "status": request.status,
                "expiresAt": request.expires_at,
                "purchasedSeats": request.purchased_seats,
            }),
            context,
        )?;
        if let Some(replayed) = self.replay_operation(operation.as_ref()).await? {
            return Ok(replayed);
        }
        if self
            .repository
            .account(&request.account_id)
            .await?
            .is_none()
        {
            return Err(AdminAppError::Validation(
                "account must exist before a license is created".to_owned(),
            ));
        }
        if self.repository.license(&request.id).await?.is_some() {
            if let Some(replayed) = self.replay_operation(operation.as_ref()).await? {
                return Ok(replayed);
            }
            return Err(AdminAppError::IdempotencyConflict);
        }
        let mut license = License::new(&request.account_id, request.plan);
        license.id = request.id;
        license.status = request.status;
        license.expires_at = request.expires_at;
        license.purchased_seats = request.purchased_seats;
        license
            .effective_policy()
            .map_err(|error| AdminAppError::Validation(error.to_string()))?;
        let now = self.trusted_now().await?;
        let audit = admin_audit(
            "license_created",
            context,
            Some(&license.account_id),
            Some(&license.id),
            None,
            now,
        );
        self.repository
            .upsert_license_with_audit(license, None, audit, operation.as_ref(), context)
            .await
    }

    pub async fn mutate_license(
        &self,
        id: &str,
        expected_version: Option<i64>,
        context: &MutationContext,
        operation_input: Value,
        mutate: impl FnOnce(&mut License) -> AdminAppResult<()>,
        event_type: &str,
    ) -> AdminAppResult<License> {
        let operation = admin_operation::prepare(
            event_type,
            &json!({
                "licenseId": id,
                "expectedVersion": expected_version,
                "input": operation_input,
            }),
            context,
        )?;
        if let Some(replayed) = self.replay_operation(operation.as_ref()).await? {
            return Ok(replayed);
        }
        let current = self.license(id).await?.ok_or(AdminAppError::NotFound)?;
        if expected_version.is_some_and(|version| version != current.row_version) {
            if let Some(replayed) = self.replay_operation(operation.as_ref()).await? {
                return Ok(replayed);
            }
            return Err(AdminAppError::VersionConflict);
        }
        let mut license = current.value;
        let before = serde_json::to_value(&license)?;
        mutate(&mut license)?;
        license
            .effective_policy()
            .map_err(|error| AdminAppError::Validation(error.to_string()))?;
        let audit = admin_audit(
            event_type,
            context,
            Some(&license.account_id),
            Some(&license.id),
            None,
            self.trusted_now().await?,
        );
        self.repository
            .upsert_license_with_audit(license, Some(before), audit, operation.as_ref(), context)
            .await
    }

    pub async fn set_device_state(
        &self,
        device_id: &str,
        state: DeviceState,
        expected_version: Option<i64>,
        context: &MutationContext,
    ) -> AdminAppResult<Device> {
        if matches!(state, DeviceState::Active | DeviceState::PendingActivation) {
            return Err(AdminAppError::Validation(
                "device activation requires the proof-of-possession flow".to_owned(),
            ));
        }
        let operation = admin_operation::prepare(
            "device.set_state",
            &json!({
                "deviceId": device_id,
                "state": state,
                "expectedVersion": expected_version,
            }),
            context,
        )?;
        if let Some(replayed) = self.replay_operation(operation.as_ref()).await? {
            return Ok(replayed);
        }
        let device = self
            .repository
            .device(device_id)
            .await?
            .ok_or(AdminAppError::NotFound)?;
        let now = self.trusted_now().await?;
        let audit = admin_audit(
            "device_state_set",
            context,
            Some(&device.account_id),
            Some(&device.license_id),
            Some(device_id),
            now,
        );
        self.repository
            .set_device_state_with_audit(
                device_id,
                state,
                expected_version,
                now,
                audit,
                operation.as_ref(),
                context,
                if matches!(state, DeviceState::Revoked | DeviceState::Suspicious) {
                    AdminPermission::DeviceSecurity
                } else {
                    AdminPermission::DeviceRemove
                },
            )
            .await?
            .ok_or(AdminAppError::VersionConflict)
    }

    pub async fn resolve_activation_code(
        &self,
        input: &str,
    ) -> AdminAppResult<ActivationCodeRecord> {
        let canonical = canonicalize_activation_code(input);
        let by_hash = if let Some(canonical) = canonical {
            self.repository
                .activation_code_by_hash(&sha256_hex(&canonical))
                .await?
        } else if is_sha256_hex(input) {
            self.repository.activation_code_by_hash(input).await?
        } else {
            self.repository
                .activation_code_by_hash(&sha256_hex(input))
                .await?
        };
        if let Some(record) = by_hash {
            return Ok(record);
        }
        if input.len() <= 16
            && let Some(record) = self.repository.activation_code_by_prefix(input).await?
        {
            return Ok(record);
        }
        Err(AdminAppError::NotFound)
    }

    pub async fn mutate_activation_code(
        &self,
        input: &str,
        expected_version: Option<i64>,
        context: &MutationContext,
        action: &str,
        max_redemptions: Option<u32>,
        expires_at: Option<i64>,
    ) -> AdminAppResult<ActivationCodeRecord> {
        let mut record = self.resolve_activation_code(input).await?;
        let operation = admin_operation::prepare(
            "activation_code.mutate",
            &json!({
                "codeHash": record.code_hash,
                "action": action,
                "maxRedemptions": max_redemptions,
                "expiresAt": expires_at,
                "expectedVersion": expected_version,
            }),
            context,
        )?;
        if let Some(replayed) = self.replay_operation(operation.as_ref()).await? {
            return Ok(replayed);
        }
        let expected = serde_json::to_value(&record)?;
        let now = self.trusted_now().await?;
        match action {
            "revoke" => {
                record.status = ActivationCodeStatus::Revoked;
                record.revoked_reason = Some(context.reason.clone());
                record.last_admin_reason = Some(context.reason.clone());
                record.updated_at = now;
            }
            "restore" => {
                if let Some(limit) = max_redemptions {
                    if !(1..=10_000).contains(&limit) {
                        return Err(AdminAppError::Validation(
                            "max redemptions must be between 1 and 10000".to_owned(),
                        ));
                    }
                    record.max_redemptions = limit;
                }
                record.restore_for_redemption(context.reason.clone(), now);
            }
            "expire" => {
                let expires_at = expires_at
                    .ok_or_else(|| AdminAppError::Validation("expiresAt is required".to_owned()))?;
                record.expires_at = Some(expires_at);
                record.last_admin_reason = Some(context.reason.clone());
                record.updated_at = now;
            }
            _ => {
                return Err(AdminAppError::Validation(
                    "unsupported activation code action".to_owned(),
                ));
            }
        }
        let audit = code_admin_audit(action, &record, context, now);
        let updated = self
            .repository
            .update_activation_code_with_audit(
                record,
                expected,
                expected_version,
                audit,
                operation.as_ref(),
                context,
            )
            .await?;
        updated.ok_or(AdminAppError::VersionConflict)
    }

    pub async fn issue_activation_codes(
        &self,
        request: ActivationCodeBatchRequest,
        context: &MutationContext,
    ) -> AdminAppResult<Vec<IssuedActivationCode>> {
        let operation_id = request.operation_id.clone();
        let request_hash = activation_code_batch_request_hash(&request, context)?;
        let operation = admin_operation::from_parts(
            &operation_id,
            "activation_code_issue",
            &request_hash,
            &context.principal.id,
            &context.reason,
        )?;
        if admin_operation::replay::<ActivationCodeBatchCommit>(&self.repository.pool, &operation)
            .await?
            .is_some()
        {
            return Err(AdminAppError::SecretReplayUnavailable);
        }
        let prepared = self.prepare_activation_code_batch(request, context).await?;
        let commit = self
            .repository
            .issue_activation_code_batch(
                &operation_id,
                &prepared.request_hash,
                context,
                &prepared.records,
                &prepared.audits,
            )
            .await?;
        if commit.replayed {
            return Err(AdminAppError::SecretReplayUnavailable);
        }
        Ok(prepared.issued)
    }

    pub async fn issue_activation_codes_for_delivery(
        &self,
        request: ActivationCodeBatchRequest,
        context: &MutationContext,
        draft: ActivationCodeDeliveryDraft,
        seal: impl FnOnce(&str, &[u8]) -> AdminAppResult<(String, Vec<u8>, Vec<u8>)>,
    ) -> AdminAppResult<ActivationCodeDeliveryReceipt> {
        if draft.actor_id != context.principal.id {
            return Err(AdminAppError::PermissionDenied);
        }
        let operation_id = request.operation_id.clone();
        let request_hash = activation_code_batch_request_hash(&request, context)?;
        let operation = admin_operation::from_parts(
            &operation_id,
            "activation_code_issue",
            &request_hash,
            &context.principal.id,
            &context.reason,
        )?;
        if let Some(commit) =
            admin_operation::replay::<ActivationCodeBatchCommit>(&self.repository.pool, &operation)
                .await?
        {
            return commit.delivery.ok_or(AdminAppError::SecretDelivery);
        }
        let prepared = self.prepare_activation_code_batch(request, context).await?;
        let plaintext = serde_json::to_vec(&prepared.issued)?;
        let (key_id, nonce, ciphertext) = seal(&draft.id, &plaintext)?;
        let delivery = AdminSecretDeliveryInsert {
            id: draft.id,
            actor_id: draft.actor_id,
            session_id: draft.session_id,
            purpose: "activation_code_batch".to_owned(),
            key_id,
            nonce,
            ciphertext,
            claim_token_hash: draft.claim_token_hash,
            expires_at: draft.expires_at,
            created_at: prepared.created_at,
        };
        let commit = self
            .repository
            .issue_activation_code_batch_with_delivery(
                &operation_id,
                &prepared.request_hash,
                context,
                &prepared.records,
                &prepared.audits,
                Some(&delivery),
            )
            .await?;
        commit.delivery.ok_or(AdminAppError::SecretDelivery)
    }

    async fn prepare_activation_code_batch(
        &self,
        request: ActivationCodeBatchRequest,
        context: &MutationContext,
    ) -> AdminAppResult<PreparedActivationCodeBatch> {
        if !(1..=1_000).contains(&request.count) {
            return Err(AdminAppError::Validation(
                "count must be between 1 and 1000".to_owned(),
            ));
        }
        if !(1..=10_000).contains(&request.max_redemptions) {
            return Err(AdminAppError::Validation(
                "max redemptions must be between 1 and 10000".to_owned(),
            ));
        }
        let license = self
            .repository
            .license(&request.license_id)
            .await?
            .ok_or(AdminAppError::NotFound)?;
        if license.account_id != request.account_id {
            return Err(AdminAppError::Validation(
                "license does not belong to the account".to_owned(),
            ));
        }
        let now = self.trusted_now().await?;
        let expires_at = request.expiry.resolve(now)?;
        let mut issued = Vec::with_capacity(request.count as usize);
        let mut records = Vec::with_capacity(request.count as usize);
        let mut audits = Vec::with_capacity(request.count as usize);
        for index in 0..request.count {
            let plaintext = generate_activation_code();
            let record = ActivationCodeRecord {
                code_hash: sha256_hex(&plaintext),
                code_prefix: activation_code_prefix(&plaintext)
                    .expect("generated activation codes are canonical"),
                account_id: request.account_id.clone(),
                license_id: Some(request.license_id.clone()),
                status: ActivationCodeStatus::Active,
                max_redemptions: request.max_redemptions,
                redeemed_count: 0,
                expires_at,
                consumed_at: None,
                consumed_device_id: None,
                last_redeemed_at: None,
                last_redeemed_device_id: None,
                created_at: now,
                updated_at: now,
                note: request.note.clone(),
                order_id: Some(format!("{}:{}", request.operation_id, index + 1)),
                channel: request.channel.clone(),
                issued_by: Some(context.principal.id.clone()),
                revoked_reason: None,
                last_admin_reason: Some(context.reason.clone()),
            };
            audits.push(code_admin_audit("issue", &record, context, now));
            issued.push(IssuedActivationCode {
                code: plaintext,
                code_prefix: record.code_prefix.clone(),
                code_hash: record.code_hash.clone(),
                account_id: record.account_id.clone(),
                license_id: request.license_id.clone(),
                expires_at: record.expires_at,
                max_redemptions: record.max_redemptions(),
                channel: record.channel.clone(),
                issued_by: context.principal.id.clone(),
            });
            records.push(record);
        }
        let request_hash = activation_code_batch_request_hash(&request, context)?;
        Ok(PreparedActivationCodeBatch {
            issued,
            records,
            audits,
            request_hash,
            created_at: now,
        })
    }
}

fn activation_code_batch_request_hash(
    request: &ActivationCodeBatchRequest,
    context: &MutationContext,
) -> AdminAppResult<String> {
    Ok(sha256_hex(&serde_json::to_string(&json!({
        "accountId": request.account_id,
        "licenseId": request.license_id,
        "count": request.count,
        "maxRedemptions": request.max_redemptions,
        "expiry": request.expiry.operation_value(),
        "channel": request.channel,
        "note": request.note,
        "actor": context.principal.id,
        "reason": context.reason,
    }))?))
}

fn page_from_rows<T: DeserializeOwned>(
    rows: Vec<sqlx::postgres::PgRow>,
    page_size: u32,
    cursor: impl Fn(&T) -> String,
) -> AdminAppResult<Page<Versioned<T>>> {
    let has_more = rows.len() > page_size as usize;
    let mut items = rows
        .into_iter()
        .take(page_size as usize)
        .map(|row| {
            let document: Value = row.try_get("document").map_err(|_| ApiError::Database)?;
            let value = serde_json::from_value(document)?;
            let row_version = row.try_get("row_version").map_err(|_| ApiError::Database)?;
            Ok(Versioned { value, row_version })
        })
        .collect::<AdminAppResult<Vec<_>>>()?;
    let next_cursor = has_more
        .then(|| items.last().map(|item| cursor(&item.value)))
        .flatten();
    Ok(Page {
        items: std::mem::take(&mut items),
        next_cursor,
    })
}

fn versioned_document<T: DeserializeOwned>(
    row: Option<sqlx::postgres::PgRow>,
) -> AdminAppResult<Option<Versioned<T>>> {
    row.map(|row| {
        let document = row.try_get("document").map_err(|_| ApiError::Database)?;
        let value = serde_json::from_value(document)?;
        let row_version = row.try_get("row_version").map_err(|_| ApiError::Database)?;
        Ok(Versioned { value, row_version })
    })
    .transpose()
}

fn admin_audit(
    event_type: &str,
    context: &MutationContext,
    account_id: Option<&str>,
    license_id: Option<&str>,
    device_id: Option<&str>,
    now: i64,
) -> AuditEventRecord {
    let mut metadata = BTreeMap::from([
        ("actor".to_owned(), context.principal.id.clone()),
        (
            "actor_type".to_owned(),
            actor_type(&context.principal).to_owned(),
        ),
        ("reason".to_owned(), context.reason.clone()),
    ]);
    if let Some(operation_id) = &context.operation_id {
        metadata.insert("operation_id".to_owned(), operation_id.clone());
    }
    if let Some(session_id) = &context.principal.session_id {
        metadata.insert("admin_session_id".to_owned(), session_id.clone());
    }
    if let Some(request_id) = &context.principal.request_id {
        metadata.insert("request_id".to_owned(), request_id.clone());
    }
    if let Some(source_ip) = &context.principal.source_ip {
        metadata.insert("source_ip".to_owned(), source_ip.clone());
    }
    if let Some(user_agent_hash) = &context.principal.user_agent_hash {
        metadata.insert("user_agent_hash".to_owned(), user_agent_hash.clone());
    }
    if let Some(job_id) = &context.job_id {
        metadata.insert("job_id".to_owned(), job_id.clone());
    }
    let (target_type, target_id) = if let Some(device_id) = device_id {
        ("device", device_id)
    } else if let Some(license_id) = license_id {
        ("license", license_id)
    } else if let Some(account_id) = account_id {
        ("account", account_id)
    } else {
        ("system", "control-plane")
    };
    metadata.insert("target_type".to_owned(), target_type.to_owned());
    metadata.insert("target_id".to_owned(), target_id.to_owned());
    AuditEventRecord {
        id: random_id("audit"),
        event_type: event_type.to_owned(),
        outcome: "succeeded".to_owned(),
        occurred_at: now,
        account_id: account_id.map(str::to_owned),
        license_id: license_id.map(str::to_owned),
        device_id: device_id.map(str::to_owned),
        reason_code: Some("admin_operation".to_owned()),
        metadata,
    }
}

fn code_admin_audit(
    action: &str,
    record: &ActivationCodeRecord,
    context: &MutationContext,
    now: i64,
) -> AuditEventRecord {
    let mut audit = admin_audit(
        &format!("activation_code_{action}"),
        context,
        Some(&record.account_id),
        record.license_id.as_deref(),
        None,
        now,
    );
    audit
        .metadata
        .insert("code_prefix".to_owned(), record.code_prefix.clone());
    audit.metadata.insert(
        "max_redemptions".to_owned(),
        record.max_redemptions().to_string(),
    );
    audit
}

fn actor_type(principal: &AdminPrincipal) -> &'static str {
    if principal.session_id.is_some() {
        "web"
    } else {
        "cli"
    }
}

fn validate_identifier(value: &str, name: &str, max_len: usize) -> AdminAppResult<()> {
    if value.is_empty()
        || value.len() > max_len
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(AdminAppError::Validation(format!(
            "{name} must contain 1 to {max_len} ASCII letters, digits, hyphens, underscores, dots, or colons"
        )));
    }
    Ok(())
}

fn non_empty(value: String) -> Option<String> {
    let value = value.trim().to_owned();
    (!value.is_empty()).then_some(value)
}

const fn default_page_size() -> u32 {
    DEFAULT_PAGE_SIZE
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn activation_code_status_name(status: ActivationCodeStatus) -> &'static str {
    match status {
        ActivationCodeStatus::Active => "active",
        ActivationCodeStatus::Consumed => "consumed",
        ActivationCodeStatus::Revoked => "revoked",
    }
}

fn parse_plan_db(value: String) -> AdminAppResult<Plan> {
    match value.as_str() {
        "free" => Ok(Plan::Free),
        "pro" => Ok(Plan::Pro),
        "team" => Ok(Plan::Team),
        _ => Err(AdminAppError::Service(ApiError::Database)),
    }
}

fn parse_license_status_db(value: String) -> AdminAppResult<LicenseStatus> {
    match value.as_str() {
        "active" => Ok(LicenseStatus::Active),
        "past_due" => Ok(LicenseStatus::PastDue),
        "canceled" => Ok(LicenseStatus::Canceled),
        _ => Err(AdminAppError::Service(ApiError::Database)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn operation_context(actor: &str, operation_id: &str) -> MutationContext {
        let mut context = MutationContext::new(
            AdminPrincipal::cli(actor).expect("valid test actor"),
            "verify retry-safe core mutation",
        )
        .expect("valid mutation context");
        context.operation_id = Some(operation_id.to_owned());
        context
    }

    #[test]
    fn page_request_rejects_unbounded_pages() {
        let error = PageRequest {
            page_size: 101,
            ..PageRequest::default()
        }
        .validate()
        .expect_err("page size should be rejected");
        assert!(matches!(error, AdminAppError::Validation(_)));
    }

    #[test]
    fn mutation_context_normalizes_reason() {
        let principal = AdminPrincipal::cli("operator").expect("principal");
        let context = MutationContext::new(principal, "  reviewed  ").expect("context");
        assert_eq!(context.reason, "reviewed");
    }

    #[test]
    fn plan_changes_keep_seats_and_versions_canonical() {
        let mut license = License {
            id: "license".to_owned(),
            account_id: "account".to_owned(),
            plan: Plan::Pro,
            plan_revision: CURRENT_PLAN_REVISION,
            status: LicenseStatus::Active,
            expires_at: None,
            license_epoch: 4,
            purchased_seats: 0,
            row_version: 7,
        };

        assert!(apply_license_plan(&mut license, Plan::Team, None).is_err());
        apply_license_plan(&mut license, Plan::Team, Some(3)).unwrap();
        assert_eq!((license.plan, license.purchased_seats), (Plan::Team, 3));
        assert_eq!((license.license_epoch, license.row_version), (5, 8));

        apply_license_plan(&mut license, Plan::Team, None).unwrap();
        assert_eq!((license.license_epoch, license.row_version), (5, 8));

        apply_license_plan(&mut license, Plan::Pro, None).unwrap();
        assert_eq!((license.plan, license.purchased_seats), (Plan::Pro, 0));
        assert_eq!((license.license_epoch, license.row_version), (6, 9));
        assert!(apply_license_plan(&mut license, Plan::Free, Some(3)).is_err());
    }

    #[test]
    fn activation_code_batch_idempotency_binds_expiry_policy_and_delivery_content() {
        let context = MutationContext::new(
            AdminPrincipal::cli("operator").unwrap(),
            "issue activation codes",
        )
        .unwrap();
        let request = ActivationCodeBatchRequest {
            account_id: "account".to_owned(),
            license_id: "license".to_owned(),
            count: 1,
            max_redemptions: 1,
            expiry: ActivationCodeExpiry::fixed(Some(2_000_000_000)),
            channel: Some("manual".to_owned()),
            note: Some("first order".to_owned()),
            operation_id: "operation".to_owned(),
        };
        let first = activation_code_batch_request_hash(&request, &context).unwrap();
        assert_eq!(request.expiry.resolve(1_000).unwrap(), Some(2_000_000_000));
        let relative_expiry = ActivationCodeExpiry::relative_seconds(30 * 24 * 60 * 60).unwrap();
        assert_eq!(relative_expiry.resolve(1_000).unwrap(), Some(2_593_000));
        assert!(relative_expiry.resolve(i64::MAX).is_err());
        let relative = activation_code_batch_request_hash(
            &ActivationCodeBatchRequest {
                expiry: relative_expiry,
                ..request.clone()
            },
            &context,
        )
        .unwrap();
        assert_ne!(first, relative);
        let changed = activation_code_batch_request_hash(
            &ActivationCodeBatchRequest {
                note: Some("another order".to_owned()),
                ..request
            },
            &context,
        )
        .unwrap();
        assert_ne!(first, changed);
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn admin_trusted_time_advances_while_database_clock_is_held_back() {
        let database_url = std::env::var("TEST_DATABASE_URL")
            .expect("TEST_DATABASE_URL is required for the PostgreSQL integration test");
        let repository =
            PostgresRepository::connect(&database_url, 2, std::time::Duration::from_secs(5))
                .await
                .expect("connect PostgreSQL");
        repository.migrate().await.expect("run migrations");
        let held_high_water: i64 = sqlx::query_scalar(
            "UPDATE service_time_authority
             SET high_water_unix =
                   floor(extract(epoch FROM clock_timestamp()))::BIGINT + 30,
                 last_database_unix =
                   floor(extract(epoch FROM clock_timestamp()))::BIGINT,
                 status = 'rollback_held'
             WHERE singleton = 1
             RETURNING high_water_unix",
        )
        .fetch_one(&repository.pool)
        .await
        .expect("hold database time behind the durable high-water mark");
        let application = AdminApplication::new(repository.clone(), 24 * 60 * 60)
            .await
            .expect("initialize Admin time authority during rollback");
        let first = application.trusted_now().await.expect("first trusted time");
        tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
        let advanced = application
            .trusted_now()
            .await
            .expect("monotonic trusted time");

        sqlx::query(
            "UPDATE service_time_authority
             SET high_water_unix = floor(extract(epoch FROM clock_timestamp()))::BIGINT,
                 last_database_unix = floor(extract(epoch FROM clock_timestamp()))::BIGINT,
                 status = 'healthy'
             WHERE singleton = 1",
        )
        .execute(&repository.pool)
        .await
        .expect("restore test time authority");
        repository.pool.close().await;

        assert_eq!(first, held_high_water);
        assert!(
            advanced >= first.saturating_add(1),
            "Admin expirations must progress during a database clock rollback"
        );
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn core_admin_mutations_replay_the_committed_response() {
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
        let suffix = random_id("core_operation_test");
        let actor = format!("admin_{suffix}");
        let account_id = format!("account_{suffix}");
        let license_id = format!("license_{suffix}");

        let create_account_context = operation_context(&actor, &format!("create-account-{suffix}"));
        let created = application
            .create_account(
                &account_id,
                Some("idempotency integration test".to_owned()),
                &create_account_context,
            )
            .await
            .expect("create account");
        let replayed = application
            .create_account(
                &account_id,
                Some("idempotency integration test".to_owned()),
                &create_account_context,
            )
            .await
            .expect("replay account creation");
        assert_eq!(
            serde_json::to_value(created).unwrap(),
            serde_json::to_value(replayed).unwrap()
        );
        assert!(matches!(
            application
                .create_account(
                    &account_id,
                    Some("changed request".to_owned()),
                    &create_account_context,
                )
                .await,
            Err(AdminAppError::IdempotencyConflict)
        ));

        let license_context = operation_context(&actor, &format!("create-license-{suffix}"));
        let license_request = || NewLicense {
            id: license_id.clone(),
            account_id: account_id.clone(),
            plan: Plan::Team,
            status: LicenseStatus::Active,
            expires_at: None,
            purchased_seats: 8,
        };
        let license = application
            .create_license(license_request(), &license_context)
            .await
            .expect("create license");
        let license_replay = application
            .create_license(license_request(), &license_context)
            .await
            .expect("replay license creation");
        assert_eq!(license.id, license_replay.id);

        let code_operation_id = format!("issue-code-{suffix}");
        let code_context = operation_context(&actor, &code_operation_id);
        let code_request = || ActivationCodeBatchRequest {
            account_id: account_id.clone(),
            license_id: license_id.clone(),
            count: 1,
            max_redemptions: 1,
            expiry: ActivationCodeExpiry::relative_seconds(30 * 24 * 60 * 60).unwrap(),
            channel: Some("integration_test".to_owned()),
            note: None,
            operation_id: code_operation_id.clone(),
        };
        let issued = application
            .issue_activation_codes(code_request(), &code_context)
            .await
            .expect("issue activation-code batch");
        assert_eq!(issued.len(), 1);
        assert!(matches!(
            application
                .issue_activation_codes(code_request(), &code_context)
                .await,
            Err(AdminAppError::SecretReplayUnavailable)
        ));
        let issued_records: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM activation_codes WHERE document ->> 'order_id' = $1",
        )
        .bind(format!("{code_operation_id}:1"))
        .fetch_one(&repository.pool)
        .await
        .expect("count activation-code operation records");
        assert_eq!(issued_records, 1);

        let now = application.trusted_now().await.expect("trusted time");
        let device_id = uuid::Uuid::new_v4().to_string();
        repository
            .upsert_device(Device {
                account_id: account_id.clone(),
                license_id: license_id.clone(),
                metadata: crate::contracts::DeviceRegistrationMetadata {
                    device_id: device_id.clone(),
                    public_key_pem: "admin-operation-test-public-key".to_owned(),
                    public_key_thumbprint: format!("sha256:{suffix}"),
                    platform: "test".to_owned(),
                    app_version: "1.0.0".to_owned(),
                    display_name: Some("Admin operation test".to_owned()),
                },
                state: DeviceState::Active,
                pending_activation_code_hash: None,
                pending_activation_expires_at: None,
                created_at: now,
                last_seen_at: Some(now),
            })
            .await
            .expect("insert device");
        let device_version: i64 =
            sqlx::query_scalar("SELECT row_version FROM devices WHERE device_id = $1")
                .bind(&device_id)
                .fetch_one(&repository.pool)
                .await
                .expect("load device version");
        let device_context = operation_context(&actor, &format!("remove-device-{suffix}"));
        let removed = application
            .set_device_state(
                &device_id,
                DeviceState::Removed,
                Some(device_version),
                &device_context,
            )
            .await
            .expect("remove device");
        let removed_replay = application
            .set_device_state(
                &device_id,
                DeviceState::Removed,
                Some(device_version),
                &device_context,
            )
            .await
            .expect("replay device mutation");
        assert_eq!(removed.last_seen_at, removed_replay.last_seen_at);

        let code_hash = sha256_hex(&format!("activation-code-{suffix}"));
        repository
            .upsert_activation_code(ActivationCodeRecord {
                code_hash: code_hash.clone(),
                code_prefix: format!("CN-{}", &suffix[..8]),
                account_id: account_id.clone(),
                license_id: Some(license_id.clone()),
                status: ActivationCodeStatus::Active,
                max_redemptions: 1,
                redeemed_count: 0,
                expires_at: None,
                consumed_at: None,
                consumed_device_id: None,
                last_redeemed_at: None,
                last_redeemed_device_id: None,
                created_at: now,
                updated_at: now,
                note: None,
                order_id: Some(format!("test-order-{suffix}")),
                channel: Some("integration_test".to_owned()),
                issued_by: Some(actor.clone()),
                revoked_reason: None,
                last_admin_reason: None,
            })
            .await
            .expect("insert activation code");
        let code_version: i64 =
            sqlx::query_scalar("SELECT row_version FROM activation_codes WHERE code_hash = $1")
                .bind(&code_hash)
                .fetch_one(&repository.pool)
                .await
                .expect("load activation code version");
        let code_context = operation_context(&actor, &format!("revoke-code-{suffix}"));
        let revoked = application
            .mutate_activation_code(
                &code_hash,
                Some(code_version),
                &code_context,
                "revoke",
                None,
                None,
            )
            .await
            .expect("revoke activation code");
        let revoked_replay = application
            .mutate_activation_code(
                &code_hash,
                Some(code_version),
                &code_context,
                "revoke",
                None,
                None,
            )
            .await
            .expect("replay activation code mutation");
        assert_eq!(revoked.updated_at, revoked_replay.updated_at);

        let license_mutation_context =
            operation_context(&actor, &format!("set-license-status-{suffix}"));
        let past_due = application
            .mutate_license(
                &license_id,
                Some(i64::try_from(license.row_version).unwrap()),
                &license_mutation_context,
                json!({"status": "past_due"}),
                |license| {
                    license.status = LicenseStatus::PastDue;
                    license.license_epoch = license.license_epoch.saturating_add(1);
                    license.row_version = license.row_version.saturating_add(1);
                    Ok(())
                },
                "license_status_set",
            )
            .await
            .expect("set license status");
        let past_due_replay = application
            .mutate_license(
                &license_id,
                Some(i64::try_from(license.row_version).unwrap()),
                &license_mutation_context,
                json!({"status": "past_due"}),
                |_| panic!("replayed mutation must not execute"),
                "license_status_set",
            )
            .await
            .expect("replay license mutation after row version changed");
        assert_eq!(past_due.row_version, past_due_replay.row_version);

        let account_version = application
            .account(&account_id)
            .await
            .unwrap()
            .unwrap()
            .row_version;
        let account_state_context =
            operation_context(&actor, &format!("set-account-state-{suffix}"));
        let suspended = application
            .set_account_state(
                &account_id,
                AccountState::Suspended,
                Some(account_version),
                &account_state_context,
            )
            .await
            .expect("suspend account");
        let suspended_replay = application
            .set_account_state(
                &account_id,
                AccountState::Suspended,
                Some(account_version),
                &account_state_context,
            )
            .await
            .expect("replay account mutation after row version changed");
        assert_eq!(suspended.updated_at, suspended_replay.updated_at);

        let operation_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM admin_operations
             WHERE operation_id = ANY($1)",
        )
        .bind(vec![
            create_account_context.operation_id.unwrap(),
            account_state_context.operation_id.unwrap(),
            license_context.operation_id.unwrap(),
            license_mutation_context.operation_id.unwrap(),
            device_context.operation_id.unwrap(),
            code_context.operation_id.unwrap(),
        ])
        .fetch_one(&repository.pool)
        .await
        .expect("count committed operations");
        assert_eq!(operation_count, 6);
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn admin_mutation_rechecks_revoked_role_in_the_commit_transaction() {
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
        let suffix = random_id("admin_commit_auth_test");
        let actor_id = format!("admin_{suffix}");
        let session_id = format!("session_{suffix}");
        let account_id = format!("account_{suffix}");
        let operation_id = format!("create-account-{suffix}");
        let now = application.trusted_now().await.expect("trusted time");
        let mut setup = repository.pool.begin().await.expect("begin fixture");
        sqlx::query(
            "INSERT INTO admin_users
             (id, username, display_name, status, created_at, updated_at)
             VALUES ($1, $2, 'Commit authorization test', 'active', $3, $3)",
        )
        .bind(&actor_id)
        .bind(format!("commit-{}", &sha256_hex(&suffix)[..16]))
        .bind(now)
        .execute(&mut *setup)
        .await
        .expect("insert administrator");
        sqlx::query(
            "INSERT INTO admin_password_credentials
             (user_id, password_hash, key_id, changed_at)
             VALUES ($1, 'test-only-hash', 'test-only-key', $2)",
        )
        .bind(&actor_id)
        .bind(now)
        .execute(&mut *setup)
        .await
        .expect("insert password credential");
        sqlx::query(
            "INSERT INTO admin_role_bindings
             (user_id, role, granted_by, reason, created_at)
             VALUES ($1, 'licensing_admin', 'test', 'commit authorization test', $2)",
        )
        .bind(&actor_id)
        .bind(now)
        .execute(&mut *setup)
        .await
        .expect("insert role");
        sqlx::query(
            "INSERT INTO admin_sessions
             (id, user_id, token_hash, csrf_hash, auth_time, elevated_until,
              last_seen_at, expires_at, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $5, $6, $5)",
        )
        .bind(&session_id)
        .bind(&actor_id)
        .bind(sha256_hex(&format!("token-{suffix}")))
        .bind(sha256_hex(&format!("csrf-{suffix}")))
        .bind(now)
        .bind(now.saturating_add(3_600))
        .execute(&mut *setup)
        .await
        .expect("insert session");
        setup.commit().await.expect("commit fixture");

        // Model request authentication caching the role before a concurrent revocation.
        let initially_authorized: bool = sqlx::query_scalar(
            "SELECT EXISTS (
                 SELECT 1 FROM admin_role_bindings
                 WHERE user_id = $1 AND role = 'licensing_admin'
             )",
        )
        .bind(&actor_id)
        .fetch_one(&repository.pool)
        .await
        .expect("read initial role");
        assert!(initially_authorized);
        sqlx::query("DELETE FROM admin_role_bindings WHERE user_id = $1")
            .bind(&actor_id)
            .execute(&repository.pool)
            .await
            .expect("revoke role after request authentication");

        let mut context = MutationContext::new(
            AdminPrincipal {
                id: actor_id.clone(),
                session_id: Some(session_id),
                source_ip: Some("127.0.0.1".to_owned()),
                user_agent_hash: None,
                request_id: None,
            },
            "verify final transaction authorization",
        )
        .expect("mutation context");
        context.operation_id = Some(operation_id.clone());
        assert!(matches!(
            application
                .create_account(&account_id, None, &context)
                .await,
            Err(AdminAppError::PermissionDenied)
        ));
        let account_exists: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM accounts WHERE id = $1)")
                .bind(&account_id)
                .fetch_one(&repository.pool)
                .await
                .expect("check denied account");
        let operation_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (
                 SELECT 1 FROM admin_operations WHERE operation_id = $1
             )",
        )
        .bind(&operation_id)
        .fetch_one(&repository.pool)
        .await
        .expect("check denied operation");
        assert!(!account_exists);
        assert!(!operation_exists);

        sqlx::query("DELETE FROM admin_users WHERE id = $1")
            .bind(&actor_id)
            .execute(&repository.pool)
            .await
            .expect("delete administrator fixture");
        repository.pool.close().await;
    }
}
