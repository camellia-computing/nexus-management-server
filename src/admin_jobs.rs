use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::Row;
use thiserror::Error;

use crate::{
    admin_app::{
        AdminAppError, AdminApplication, AdminPrincipal, MutationContext, Page, PageRequest,
    },
    admin_auth::{AdminKeyring, AdminPermission, authorize_admin_mutation},
    admin_operation,
    admin_storage::{
        EvidenceScanner, ObjectStorageConfig, ObjectStorageError, ObjectStorageService,
        StagingReconciliation, StoredObjectStatus,
    },
    config::{Environment, database_pool_config_from_env, time_max_forward_jump_seconds_from_env},
    contracts::DeviceState,
    crypto::{random_id, sha256_hex, stable_log_reference},
    domain::{AccountState, AuditEventRecord, LicenseStatus},
    error::ApiError,
    metrics::{BackgroundOutcome, MetricsServer, RuntimeMetrics, RuntimeRole},
    runtime_task::{join_required_task, supervise_required_task},
    store::{LicenseRepository, PostgresRepository},
};

const PREVIEW_TTL_SECONDS: i64 = 10 * 60;
const JOB_LEASE_SECONDS: i64 = 60;
const JOB_HEARTBEAT_SECONDS: u64 = 20;
const WORKER_DEPENDENCY_CHECK_SECONDS: i64 = 10;
const WORKER_CLEANUP_INTERVAL_SECONDS: i64 = 60;
const OVERDUE_INVOICE_BATCH_SIZE: i64 = 100;
const SECRET_CLEANUP_BATCH_SIZE: i64 = 100;
const MAX_TARGETS: usize = 10_000;
const MAX_ATTEMPTS: i32 = 3;

#[derive(Debug, Error)]
pub enum AdminJobError {
    #[error("invalid bulk operation: {0}")]
    Validation(String),
    #[error("bulk preview or job not found")]
    NotFound,
    #[error("bulk preview expired or was already consumed")]
    PreviewUnavailable,
    #[error("bulk operation conflicts with an earlier idempotent request")]
    Conflict,
    #[error("bulk operation permission denied")]
    PermissionDenied,
    #[error(transparent)]
    Application(#[from] AdminAppError),
    #[error(transparent)]
    Service(#[from] ApiError),
}

pub type AdminJobResult<T> = Result<T, AdminJobError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BulkJobKind {
    AccountSetState,
    LicenseSetStatus,
    ActivationCodeRevoke,
    ActivationCodeExpire,
    DeviceSetState,
}

impl BulkJobKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AccountSetState => "account_set_state",
            Self::LicenseSetStatus => "license_set_status",
            Self::ActivationCodeRevoke => "activation_code_revoke",
            Self::ActivationCodeExpire => "activation_code_expire",
            Self::DeviceSetState => "device_set_state",
        }
    }

    fn parse(value: &str) -> AdminJobResult<Self> {
        match value {
            "account_set_state" => Ok(Self::AccountSetState),
            "license_set_status" => Ok(Self::LicenseSetStatus),
            "activation_code_revoke" => Ok(Self::ActivationCodeRevoke),
            "activation_code_expire" => Ok(Self::ActivationCodeExpire),
            "device_set_state" => Ok(Self::DeviceSetState),
            _ => Err(AdminJobError::Validation("unknown job kind".to_owned())),
        }
    }

    pub const fn is_high_risk(self) -> bool {
        matches!(
            self,
            Self::AccountSetState | Self::LicenseSetStatus | Self::DeviceSetState
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreatePreview {
    pub kind: BulkJobKind,
    pub target_ids: Vec<String>,
    #[serde(default)]
    pub parameters: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkTarget {
    pub id: String,
    pub row_version: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkPreview {
    pub id: String,
    pub kind: BulkJobKind,
    pub parameters: Value,
    pub targets: Vec<BulkTarget>,
    pub expires_at: i64,
    pub high_risk: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BulkJobStatus {
    Queued,
    Running,
    CancelRequested,
    Succeeded,
    PartialFailed,
    Failed,
    Canceled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkJob {
    pub id: String,
    pub kind: BulkJobKind,
    pub status: BulkJobStatus,
    pub actor_id: String,
    pub reason: String,
    pub parameters: Value,
    pub total_items: i32,
    pub completed_items: i32,
    pub failed_items: i32,
    pub created_at: i64,
    pub started_at: Option<i64>,
    pub finished_at: Option<i64>,
}

#[derive(Clone)]
pub struct AdminJobService {
    repository: PostgresRepository,
    application: AdminApplication,
}

struct JobLeaseHeartbeat {
    lost: Arc<AtomicBool>,
    task: tokio::task::JoinHandle<()>,
}

impl JobLeaseHeartbeat {
    fn lost(&self) -> bool {
        self.lost.load(Ordering::Acquire)
    }
}

impl Drop for JobLeaseHeartbeat {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl AdminJobService {
    pub fn new(application: AdminApplication) -> Self {
        Self {
            repository: application.repository().clone(),
            application,
        }
    }

    pub async fn create_preview(
        &self,
        actor_id: &str,
        session_id: &str,
        request: CreatePreview,
    ) -> AdminJobResult<BulkPreview> {
        validate_parameters(request.kind, &request.parameters)?;
        let target_ids = request
            .target_ids
            .into_iter()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
            .collect::<BTreeSet<_>>();
        if target_ids.is_empty() || target_ids.len() > MAX_TARGETS {
            return Err(AdminJobError::Validation(format!(
                "targetIds must contain 1 to {MAX_TARGETS} unique values"
            )));
        }
        let target_ids = target_ids.into_iter().collect::<Vec<_>>();
        let targets = self.versions(request.kind, &target_ids).await?;
        if targets.len() != target_ids.len() {
            return Err(AdminJobError::NotFound);
        }
        let now = self.application.trusted_now().await?;
        let preview = BulkPreview {
            id: random_id("bulk_preview"),
            kind: request.kind,
            parameters: request.parameters,
            targets,
            expires_at: now.saturating_add(PREVIEW_TTL_SECONDS),
            high_risk: request.kind.is_high_risk(),
        };
        let canonical = serde_json::to_string(&json!({
            "actorId": actor_id,
            "kind": preview.kind,
            "parameters": preview.parameters,
            "targets": preview.targets,
        }))
        .map_err(|_| ApiError::Internal)?;
        let context = MutationContext::new(
            AdminPrincipal {
                id: actor_id.to_owned(),
                session_id: Some(session_id.to_owned()),
                source_ip: None,
                user_agent_hash: None,
                request_id: None,
            },
            "create bulk-operation preview",
        )?;
        let mut tx = self
            .repository
            .pool
            .begin()
            .await
            .map_err(|_| ApiError::Database)?;
        authorize_admin_mutation(&mut tx, &context, AdminPermission::JobManage, false, now)
            .await
            .map_err(AdminAppError::from)?;
        authorize_admin_mutation(
            &mut tx,
            &context,
            required_admin_permission(preview.kind, &preview.parameters)?,
            false,
            now,
        )
        .await
        .map_err(AdminAppError::from)?;
        sqlx::query(
            "INSERT INTO admin_bulk_previews
             (id, actor_id, kind, parameters, targets, target_count,
              request_hash, expires_at, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(&preview.id)
        .bind(actor_id)
        .bind(preview.kind.as_str())
        .bind(&preview.parameters)
        .bind(serde_json::to_value(&preview.targets).map_err(|_| ApiError::Internal)?)
        .bind(i32::try_from(preview.targets.len()).map_err(|_| ApiError::Internal)?)
        .bind(sha256_hex(&canonical))
        .bind(preview.expires_at)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        tx.commit().await.map_err(|_| ApiError::Database)?;
        Ok(preview)
    }

    pub async fn create_job(
        &self,
        actor_id: &str,
        session_id: &str,
        preview_id: &str,
        reason: &str,
        idempotency_key: &str,
    ) -> AdminJobResult<BulkJob> {
        let reason = reason.trim();
        if reason.is_empty() || reason.chars().count() > 512 {
            return Err(AdminJobError::Validation(
                "reason must contain 1 to 512 characters".to_owned(),
            ));
        }
        if idempotency_key.is_empty() || idempotency_key.len() > 128 {
            return Err(AdminJobError::Validation(
                "idempotency key must contain 1 to 128 characters".to_owned(),
            ));
        }
        let mut context = MutationContext::new(
            AdminPrincipal {
                id: actor_id.to_owned(),
                session_id: Some(session_id.to_owned()),
                source_ip: None,
                user_agent_hash: None,
                request_id: None,
            },
            reason,
        )?;
        context.operation_id = Some(idempotency_key.to_owned());
        let now = self.application.trusted_now().await?;
        let mut tx = self
            .repository
            .pool
            .begin()
            .await
            .map_err(|_| ApiError::Database)?;
        authorize_admin_mutation(&mut tx, &context, AdminPermission::JobManage, true, now)
            .await
            .map_err(AdminAppError::from)?;
        let preview = sqlx::query(
            "SELECT kind, parameters, targets, target_count, request_hash, consumed_at, expires_at
             FROM admin_bulk_previews
             WHERE id = $1 AND actor_id = $2
             FOR UPDATE",
        )
        .bind(preview_id)
        .bind(actor_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?
        .ok_or(AdminJobError::PreviewUnavailable)?;
        let kind = BulkJobKind::parse(
            &preview
                .try_get::<String, _>("kind")
                .map_err(|_| ApiError::Database)?,
        )?;
        let parameters: Value = preview
            .try_get("parameters")
            .map_err(|_| ApiError::Database)?;
        authorize_admin_mutation(
            &mut tx,
            &context,
            required_admin_permission(kind, &parameters)?,
            true,
            now,
        )
        .await
        .map_err(AdminAppError::from)?;
        let targets: Vec<BulkTarget> =
            serde_json::from_value(preview.try_get("targets").map_err(|_| ApiError::Database)?)
                .map_err(|_| ApiError::Database)?;
        let request_hash = sha256_hex(
            &serde_json::to_string(&json!({
                "previewHash": preview.try_get::<String, _>("request_hash").map_err(|_| ApiError::Database)?,
                "reason": reason,
            }))
            .map_err(|_| ApiError::Internal)?,
        );
        if let Some(existing) = sqlx::query(
            "SELECT id, request_hash FROM admin_bulk_jobs
             WHERE actor_id = $1 AND idempotency_key = $2",
        )
        .bind(actor_id)
        .bind(idempotency_key)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?
        {
            let existing_hash: String = existing
                .try_get("request_hash")
                .map_err(|_| ApiError::Database)?;
            if existing_hash != request_hash {
                return Err(AdminJobError::Conflict);
            }
            let id: String = existing.try_get("id").map_err(|_| ApiError::Database)?;
            tx.rollback().await.map_err(|_| ApiError::Database)?;
            return self.job(&id).await;
        }
        let consumed_at: Option<i64> = preview
            .try_get("consumed_at")
            .map_err(|_| ApiError::Database)?;
        let expires_at: i64 = preview
            .try_get("expires_at")
            .map_err(|_| ApiError::Database)?;
        if consumed_at.is_some() || expires_at <= now {
            return Err(AdminJobError::PreviewUnavailable);
        }
        let job_id = random_id("bulk_job");
        sqlx::query(
            "INSERT INTO admin_bulk_jobs
             (id, kind, status, actor_id, session_id, reason, idempotency_key,
              request_hash, parameters, total_items, created_at)
             VALUES ($1, $2, 'queued', $3, $4, $5, $6, $7, $8, $9, $10)",
        )
        .bind(&job_id)
        .bind(kind.as_str())
        .bind(actor_id)
        .bind(session_id)
        .bind(reason)
        .bind(idempotency_key)
        .bind(&request_hash)
        .bind(&parameters)
        .bind(
            preview
                .try_get::<i32, _>("target_count")
                .map_err(|_| ApiError::Database)?,
        )
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        for (ordinal, target) in targets.iter().enumerate() {
            sqlx::query(
                "INSERT INTO admin_bulk_job_items
                 (job_id, ordinal, target_type, target_id, expected_version, status)
                 VALUES ($1, $2, $3, $4, $5, 'pending')",
            )
            .bind(&job_id)
            .bind(i32::try_from(ordinal).map_err(|_| ApiError::Internal)?)
            .bind(target_type(kind))
            .bind(&target.id)
            .bind(target.row_version)
            .execute(&mut *tx)
            .await
            .map_err(|_| ApiError::Database)?;
        }
        sqlx::query("UPDATE admin_bulk_previews SET consumed_at = $2 WHERE id = $1")
            .bind(preview_id)
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(|_| ApiError::Database)?;
        tx.commit().await.map_err(|_| ApiError::Database)?;
        self.job(&job_id).await
    }

    pub async fn jobs(&self, request: PageRequest) -> AdminJobResult<Page<BulkJob>> {
        let request = request.validate()?;
        let rows = sqlx::query(
            "SELECT id, kind, status, actor_id, reason, parameters, total_items,
                    completed_items, failed_items, created_at, started_at, finished_at
             FROM admin_bulk_jobs
             WHERE ($1::text IS NULL OR id > $1)
             ORDER BY id ASC LIMIT $2",
        )
        .bind(request.cursor.as_deref())
        .bind(i64::from(request.page_size) + 1)
        .fetch_all(&self.repository.pool)
        .await
        .map_err(|_| ApiError::Database)?;
        let has_more = rows.len() > request.page_size as usize;
        let items = rows
            .into_iter()
            .take(request.page_size as usize)
            .map(row_job)
            .collect::<AdminJobResult<Vec<_>>>()?;
        let next_cursor = has_more
            .then(|| items.last().map(|job| job.id.clone()))
            .flatten();
        Ok(Page { items, next_cursor })
    }

    pub async fn job(&self, id: &str) -> AdminJobResult<BulkJob> {
        sqlx::query(
            "SELECT id, kind, status, actor_id, reason, parameters, total_items,
                    completed_items, failed_items, created_at, started_at, finished_at
             FROM admin_bulk_jobs WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.repository.pool)
        .await
        .map_err(|_| ApiError::Database)?
        .map(row_job)
        .transpose()?
        .ok_or(AdminJobError::NotFound)
    }

    pub async fn cancel(&self, id: &str, context: &MutationContext) -> AdminJobResult<BulkJob> {
        let operation =
            admin_operation::prepare("bulk_job.cancel", &json!({"jobId": id}), context)?
                .ok_or_else(|| {
                    AdminJobError::Validation("idempotency key is required".to_owned())
                })?;
        if let Some(response) = admin_operation::replay(&self.repository.pool, &operation).await? {
            return Ok(response);
        }
        let now = self.application.trusted_now().await?;
        let mut tx = self
            .repository
            .pool
            .begin()
            .await
            .map_err(|_| ApiError::Database)?;
        authorize_admin_mutation(&mut tx, context, AdminPermission::JobManage, false, now)
            .await
            .map_err(AdminAppError::from)?;
        if let Some(response) =
            admin_operation::claim_prepared::<BulkJob>(&mut tx, &operation).await?
        {
            tx.commit().await.map_err(|_| ApiError::Database)?;
            return Ok(response);
        }
        let status = sqlx::query_scalar::<_, String>(
            "SELECT status FROM admin_bulk_jobs WHERE id = $1 FOR UPDATE",
        )
        .bind(id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?
        .ok_or(AdminJobError::NotFound)?;
        match status.as_str() {
            "queued" => {
                sqlx::query(
                    "UPDATE admin_bulk_job_items
                     SET status = 'canceled', finished_at = $2
                     WHERE job_id = $1 AND status = 'pending'",
                )
                .bind(id)
                .bind(now)
                .execute(&mut *tx)
                .await
                .map_err(|_| ApiError::Database)?;
                sqlx::query(
                    "UPDATE admin_bulk_jobs
                     SET status = 'canceled', finished_at = $2,
                         lease_owner = NULL, lease_expires_at = NULL
                     WHERE id = $1",
                )
                .bind(id)
                .bind(now)
                .execute(&mut *tx)
                .await
                .map_err(|_| ApiError::Database)?;
            }
            "running" => {
                sqlx::query("UPDATE admin_bulk_jobs SET status = 'cancel_requested' WHERE id = $1")
                    .bind(id)
                    .execute(&mut *tx)
                    .await
                    .map_err(|_| ApiError::Database)?;
            }
            "cancel_requested" | "canceled" => {}
            _ => return Err(AdminJobError::Conflict),
        }
        let job = sqlx::query(
            "SELECT id, kind, status, actor_id, reason, parameters, total_items,
                    completed_items, failed_items, created_at, started_at, finished_at
             FROM admin_bulk_jobs WHERE id = $1",
        )
        .bind(id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        let job = row_job(job)?;
        insert_job_cancellation_audit(&mut tx, id, context, now).await?;
        admin_operation::finish_prepared(&mut tx, &job, &operation).await?;
        tx.commit().await.map_err(|_| ApiError::Database)?;
        Ok(job)
    }

    async fn versions(
        &self,
        kind: BulkJobKind,
        target_ids: &[String],
    ) -> AdminJobResult<Vec<BulkTarget>> {
        let rows = match kind {
            BulkJobKind::AccountSetState => {
                sqlx::query("SELECT id, row_version FROM accounts WHERE id = ANY($1)")
                    .bind(target_ids)
                    .fetch_all(&self.repository.pool)
                    .await
            }
            BulkJobKind::LicenseSetStatus => {
                sqlx::query("SELECT id, row_version FROM licenses WHERE id = ANY($1)")
                    .bind(target_ids)
                    .fetch_all(&self.repository.pool)
                    .await
            }
            BulkJobKind::ActivationCodeRevoke | BulkJobKind::ActivationCodeExpire => sqlx::query(
                "SELECT code_hash AS id, row_version FROM activation_codes WHERE code_hash = ANY($1)",
            )
            .bind(target_ids)
            .fetch_all(&self.repository.pool)
            .await,
            BulkJobKind::DeviceSetState => sqlx::query(
                "SELECT device_id AS id, row_version FROM devices WHERE device_id = ANY($1)",
            )
            .bind(target_ids)
            .fetch_all(&self.repository.pool)
            .await,
        }
        .map_err(|_| ApiError::Database)?;
        let mut targets = rows
            .into_iter()
            .map(|row| {
                Ok(BulkTarget {
                    id: row.try_get("id").map_err(|_| ApiError::Database)?,
                    row_version: row.try_get("row_version").map_err(|_| ApiError::Database)?,
                })
            })
            .collect::<AdminJobResult<Vec<_>>>()?;
        targets.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(targets)
    }

    pub async fn run_once(&self, worker_id: &str) -> AdminJobResult<bool> {
        let now = self.application.trusted_now().await?;
        let row = sqlx::query(
            "UPDATE admin_bulk_jobs SET
                 status = CASE WHEN status = 'cancel_requested' THEN status ELSE 'running' END,
                 lease_owner = $1, lease_expires_at = $2,
                 lease_generation = lease_generation + 1,
                 started_at = coalesce(started_at, $3)
             WHERE id = (
                 SELECT id FROM admin_bulk_jobs
                 WHERE status = 'queued'
                    OR (
                        status = 'running'
                        AND (lease_expires_at IS NULL OR lease_expires_at < $3)
                    )
                    OR (
                        status = 'cancel_requested'
                        AND (lease_owner IS NULL OR lease_expires_at IS NULL OR lease_expires_at < $3)
                    )
                 ORDER BY created_at ASC
                 FOR UPDATE SKIP LOCKED LIMIT 1
             )
             RETURNING id, kind, status, actor_id, reason, parameters, lease_generation",
        )
        .bind(worker_id)
        .bind(now.saturating_add(JOB_LEASE_SECONDS))
        .bind(now)
        .fetch_optional(&self.repository.pool)
        .await
        .map_err(|_| ApiError::Database)?;
        let Some(job) = row else {
            return Ok(false);
        };
        let job_id: String = job.try_get("id").map_err(|_| ApiError::Database)?;
        let kind = BulkJobKind::parse(
            &job.try_get::<String, _>("kind")
                .map_err(|_| ApiError::Database)?,
        )?;
        let actor_id: String = job.try_get("actor_id").map_err(|_| ApiError::Database)?;
        let reason: String = job.try_get("reason").map_err(|_| ApiError::Database)?;
        let parameters: Value = job.try_get("parameters").map_err(|_| ApiError::Database)?;
        let lease_generation: i64 = job
            .try_get("lease_generation")
            .map_err(|_| ApiError::Database)?;
        self.requeue_stale_running_items(&job_id, worker_id, lease_generation)
            .await?;
        let heartbeat =
            self.start_lease_heartbeat(job_id.clone(), worker_id.to_owned(), lease_generation);
        if self
            .cancel_requested(&job_id, worker_id, lease_generation)
            .await?
        {
            self.cancel_pending_items(&job_id, worker_id, lease_generation)
                .await?;
            self.finish_job(&job_id, worker_id, lease_generation)
                .await?;
            return Ok(true);
        }
        if !self
            .actor_still_authorized(&actor_id, kind, &parameters)
            .await?
        {
            self.fail_remaining(
                &job_id,
                worker_id,
                lease_generation,
                "actor_permission_revoked",
            )
            .await?;
            self.finish_job(&job_id, worker_id, lease_generation)
                .await?;
            return Ok(true);
        }
        let items = sqlx::query(
            "SELECT ordinal, target_id, expected_version, attempts
             FROM admin_bulk_job_items
             WHERE job_id = $1 AND status = 'pending'
             ORDER BY ordinal ASC LIMIT 100",
        )
        .bind(&job_id)
        .fetch_all(&self.repository.pool)
        .await
        .map_err(|_| ApiError::Database)?;
        for item in items {
            if heartbeat.lost()
                || !self
                    .owns_lease(&job_id, worker_id, lease_generation)
                    .await?
            {
                return Err(AdminJobError::Conflict);
            }
            if self
                .cancel_requested(&job_id, worker_id, lease_generation)
                .await?
            {
                self.cancel_pending_items(&job_id, worker_id, lease_generation)
                    .await?;
                self.finish_job(&job_id, worker_id, lease_generation)
                    .await?;
                return Ok(true);
            }
            let ordinal: i32 = item.try_get("ordinal").map_err(|_| ApiError::Database)?;
            let target_id: String = item.try_get("target_id").map_err(|_| ApiError::Database)?;
            let expected_version: i64 = item
                .try_get("expected_version")
                .map_err(|_| ApiError::Database)?;
            let attempts: i32 = item.try_get("attempts").map_err(|_| ApiError::Database)?;
            let claimed = sqlx::query(
                "UPDATE admin_bulk_job_items
                 SET status = 'running', attempts = attempts + 1, started_at = $3,
                     lease_generation = $5, error_code = NULL, finished_at = NULL
                 WHERE job_id = $1 AND ordinal = $2 AND status = 'pending'
                   AND EXISTS (
                     SELECT 1 FROM admin_bulk_jobs
                     WHERE id = $1 AND lease_owner = $4
                       AND lease_generation = $5
                       AND status IN ('running', 'cancel_requested')
                       AND lease_expires_at > $3
                   )",
            )
            .bind(&job_id)
            .bind(ordinal)
            .bind(self.application.trusted_now().await?)
            .bind(worker_id)
            .bind(lease_generation)
            .execute(&self.repository.pool)
            .await
            .map_err(|_| ApiError::Database)?
            .rows_affected();
            if claimed != 1 {
                return Err(AdminJobError::Conflict);
            }
            let result = self
                .execute_item(
                    &self.application,
                    kind,
                    &job_id,
                    &actor_id,
                    &reason,
                    &parameters,
                    &target_id,
                    expected_version,
                    ordinal,
                )
                .await;
            let (status, error_code) = match result {
                Ok(()) => ("succeeded", None),
                Err(error) if attempts + 1 < MAX_ATTEMPTS && transient(&error) => {
                    ("pending", Some("transient_retry".to_owned()))
                }
                Err(error) => ("failed", Some(job_error_code(&error).to_owned())),
            };
            let updated = sqlx::query(
                "UPDATE admin_bulk_job_items
                 SET status = $3, error_code = $4,
                     finished_at = CASE WHEN $3 = 'pending' THEN NULL ELSE $5 END
                 WHERE job_id = $1 AND ordinal = $2 AND status = 'running'
                   AND lease_generation = $7
                   AND EXISTS (
                     SELECT 1 FROM admin_bulk_jobs
                     WHERE id = $1 AND lease_owner = $6
                       AND lease_generation = $7
                       AND status IN ('running', 'cancel_requested')
                   )",
            )
            .bind(&job_id)
            .bind(ordinal)
            .bind(status)
            .bind(error_code)
            .bind(self.application.trusted_now().await?)
            .bind(worker_id)
            .bind(lease_generation)
            .execute(&self.repository.pool)
            .await
            .map_err(|_| ApiError::Database)?
            .rows_affected();
            if updated != 1 || heartbeat.lost() {
                return Err(AdminJobError::Conflict);
            }
        }
        if self
            .cancel_requested(&job_id, worker_id, lease_generation)
            .await?
        {
            self.cancel_pending_items(&job_id, worker_id, lease_generation)
                .await?;
            self.finish_job(&job_id, worker_id, lease_generation)
                .await?;
            return Ok(true);
        }
        self.refresh_job_counts(&job_id, worker_id, lease_generation)
            .await?;
        Ok(true)
    }

    fn start_lease_heartbeat(
        &self,
        job_id: String,
        worker_id: String,
        lease_generation: i64,
    ) -> JobLeaseHeartbeat {
        let pool = self.repository.pool.clone();
        let application = self.application.clone();
        let lost = Arc::new(AtomicBool::new(false));
        let heartbeat_lost = lost.clone();
        let task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(JOB_HEARTBEAT_SECONDS));
            loop {
                interval.tick().await;
                let now = match application.trusted_now().await {
                    Ok(now) => now,
                    Err(error) => {
                        tracing::error!(%error, "admin job lease heartbeat lost trusted time");
                        heartbeat_lost.store(true, Ordering::Release);
                        break;
                    }
                };
                let renewed = sqlx::query(
                    "UPDATE admin_bulk_jobs SET lease_expires_at = $3
                     WHERE id = $1 AND lease_owner = $2
                       AND lease_generation = $4
                       AND status IN ('running', 'cancel_requested')",
                )
                .bind(&job_id)
                .bind(&worker_id)
                .bind(now.saturating_add(JOB_LEASE_SECONDS))
                .bind(lease_generation)
                .execute(&pool)
                .await;
                if !matches!(renewed, Ok(result) if result.rows_affected() == 1) {
                    heartbeat_lost.store(true, Ordering::Release);
                    break;
                }
            }
        });
        JobLeaseHeartbeat { lost, task }
    }

    async fn requeue_stale_running_items(
        &self,
        job_id: &str,
        worker_id: &str,
        lease_generation: i64,
    ) -> AdminJobResult<()> {
        sqlx::query(
            "UPDATE admin_bulk_job_items
             SET status = 'pending', error_code = NULL, started_at = NULL, finished_at = NULL
             WHERE job_id = $1 AND status = 'running'
               AND lease_generation < $3
               AND EXISTS (
                 SELECT 1 FROM admin_bulk_jobs
                 WHERE id = $1 AND lease_owner = $2 AND lease_generation = $3
               )",
        )
        .bind(job_id)
        .bind(worker_id)
        .bind(lease_generation)
        .execute(&self.repository.pool)
        .await
        .map_err(|_| ApiError::Database)?;
        Ok(())
    }

    async fn owns_lease(
        &self,
        job_id: &str,
        worker_id: &str,
        lease_generation: i64,
    ) -> AdminJobResult<bool> {
        sqlx::query_scalar(
            "SELECT EXISTS (
               SELECT 1 FROM admin_bulk_jobs
               WHERE id = $1 AND lease_owner = $2
                 AND lease_generation = $4
                 AND status IN ('running', 'cancel_requested')
                 AND lease_expires_at > $3
             )",
        )
        .bind(job_id)
        .bind(worker_id)
        .bind(self.application.trusted_now().await?)
        .bind(lease_generation)
        .fetch_one(&self.repository.pool)
        .await
        .map_err(|_| ApiError::Database.into())
    }

    async fn cancel_requested(
        &self,
        job_id: &str,
        worker_id: &str,
        lease_generation: i64,
    ) -> AdminJobResult<bool> {
        sqlx::query_scalar(
            "SELECT EXISTS (
               SELECT 1 FROM admin_bulk_jobs
               WHERE id = $1 AND lease_owner = $2 AND lease_generation = $3
                 AND status = 'cancel_requested'
             )",
        )
        .bind(job_id)
        .bind(worker_id)
        .bind(lease_generation)
        .fetch_one(&self.repository.pool)
        .await
        .map_err(|_| ApiError::Database.into())
    }

    #[allow(clippy::too_many_arguments)]
    async fn execute_item(
        &self,
        application: &AdminApplication,
        kind: BulkJobKind,
        job_id: &str,
        actor_id: &str,
        reason: &str,
        parameters: &Value,
        target_id: &str,
        expected_version: i64,
        ordinal: i32,
    ) -> AdminJobResult<()> {
        let mut context = MutationContext::new(AdminPrincipal::cli(actor_id)?, reason)?;
        context.operation_id = Some(format!("{job_id}:{ordinal}"));
        context.job_id = Some(job_id.to_owned());
        match kind {
            BulkJobKind::AccountSetState => {
                let state = parse_account_state(parameter_string(parameters, "state")?)?;
                application
                    .set_account_state(target_id, state, Some(expected_version), &context)
                    .await?;
            }
            BulkJobKind::LicenseSetStatus => {
                let status = parse_license_status(parameter_string(parameters, "status")?)?;
                application
                    .mutate_license(
                        target_id,
                        Some(expected_version),
                        &context,
                        json!({"status": status}),
                        move |license| {
                            if license.status != status {
                                license.status = status;
                                license.license_epoch = license.license_epoch.saturating_add(1);
                                license.row_version = license.row_version.saturating_add(1);
                            }
                            Ok(())
                        },
                        "license_status_set",
                    )
                    .await?;
            }
            BulkJobKind::ActivationCodeRevoke => {
                application
                    .mutate_activation_code(
                        target_id,
                        Some(expected_version),
                        &context,
                        "revoke",
                        None,
                        None,
                    )
                    .await?;
            }
            BulkJobKind::ActivationCodeExpire => {
                let expires_at = parameters
                    .get("expiresAt")
                    .and_then(Value::as_i64)
                    .ok_or_else(|| {
                        AdminJobError::Validation("expiresAt must be Unix seconds".to_owned())
                    })?;
                application
                    .mutate_activation_code(
                        target_id,
                        Some(expected_version),
                        &context,
                        "expire",
                        None,
                        Some(expires_at),
                    )
                    .await?;
            }
            BulkJobKind::DeviceSetState => {
                let state = parse_device_state(parameter_string(parameters, "state")?)?;
                application
                    .set_device_state(target_id, state, Some(expected_version), &context)
                    .await?;
            }
        }
        Ok(())
    }

    async fn actor_still_authorized(
        &self,
        actor_id: &str,
        kind: BulkJobKind,
        parameters: &Value,
    ) -> AdminJobResult<bool> {
        let active: bool = sqlx::query_scalar(
            "SELECT EXISTS (
                SELECT 1 FROM admin_users u
                JOIN admin_role_bindings r ON r.user_id = u.id
                WHERE u.id = $1 AND u.status = 'active'
                  AND r.role = ANY($2)
             )",
        )
        .bind(actor_id)
        .bind(authorized_roles(kind, parameters)?)
        .fetch_one(&self.repository.pool)
        .await
        .map_err(|_| ApiError::Database)?;
        Ok(active)
    }

    async fn cancel_pending_items(
        &self,
        job_id: &str,
        worker_id: &str,
        lease_generation: i64,
    ) -> AdminJobResult<()> {
        sqlx::query(
            "UPDATE admin_bulk_job_items SET status = 'canceled', finished_at = $2
             WHERE job_id = $1 AND status = 'pending'
               AND EXISTS (
                 SELECT 1 FROM admin_bulk_jobs
                 WHERE id = $1 AND lease_owner = $3 AND lease_generation = $4
               )",
        )
        .bind(job_id)
        .bind(self.application.trusted_now().await?)
        .bind(worker_id)
        .bind(lease_generation)
        .execute(&self.repository.pool)
        .await
        .map_err(|_| ApiError::Database)?;
        Ok(())
    }

    async fn fail_remaining(
        &self,
        job_id: &str,
        worker_id: &str,
        lease_generation: i64,
        code: &str,
    ) -> AdminJobResult<()> {
        sqlx::query(
            "UPDATE admin_bulk_job_items
             SET status = 'failed', error_code = $2, finished_at = $3
             WHERE job_id = $1 AND status IN ('pending', 'running')
               AND EXISTS (
                 SELECT 1 FROM admin_bulk_jobs
                 WHERE id = $1 AND lease_owner = $4 AND lease_generation = $5
               )",
        )
        .bind(job_id)
        .bind(code)
        .bind(self.application.trusted_now().await?)
        .bind(worker_id)
        .bind(lease_generation)
        .execute(&self.repository.pool)
        .await
        .map_err(|_| ApiError::Database)?;
        Ok(())
    }

    async fn refresh_job_counts(
        &self,
        job_id: &str,
        worker_id: &str,
        lease_generation: i64,
    ) -> AdminJobResult<()> {
        let row = sqlx::query(
            "SELECT
                count(*) FILTER (WHERE status = 'succeeded')::int AS completed,
                count(*) FILTER (WHERE status = 'failed')::int AS failed,
                count(*) FILTER (WHERE status = 'canceled')::int AS canceled,
                count(*) FILTER (WHERE status IN ('pending', 'running'))::int AS remaining
             FROM admin_bulk_job_items WHERE job_id = $1",
        )
        .bind(job_id)
        .fetch_one(&self.repository.pool)
        .await
        .map_err(|_| ApiError::Database)?;
        let completed: i32 = row.try_get("completed").map_err(|_| ApiError::Database)?;
        let failed: i32 = row.try_get("failed").map_err(|_| ApiError::Database)?;
        let canceled: i32 = row.try_get("canceled").map_err(|_| ApiError::Database)?;
        let remaining: i32 = row.try_get("remaining").map_err(|_| ApiError::Database)?;
        let status = if remaining > 0 {
            "running"
        } else if canceled > 0 {
            "canceled"
        } else if failed == 0 {
            "succeeded"
        } else if completed == 0 {
            "failed"
        } else {
            "partial_failed"
        };
        let now = self.application.trusted_now().await?;
        let updated = sqlx::query(
            "UPDATE admin_bulk_jobs SET completed_items = $3, failed_items = $4,
                 status = CASE
                   WHEN status = 'cancel_requested' AND $6 > 0 THEN status
                   WHEN status = 'cancel_requested' THEN 'canceled'
                   WHEN $6 > 0 THEN 'queued'
                   ELSE $5
                 END,
                 lease_expires_at = NULL,
                 lease_owner = NULL,
                 finished_at = CASE WHEN $6 = 0 THEN $2 ELSE NULL END
             WHERE id = $1 AND lease_owner = $7 AND lease_generation = $8",
        )
        .bind(job_id)
        .bind(now)
        .bind(completed)
        .bind(failed)
        .bind(status)
        .bind(remaining)
        .bind(worker_id)
        .bind(lease_generation)
        .execute(&self.repository.pool)
        .await
        .map_err(|_| ApiError::Database)?
        .rows_affected();
        if updated != 1 {
            return Err(AdminJobError::Conflict);
        }
        Ok(())
    }

    async fn finish_job(
        &self,
        job_id: &str,
        worker_id: &str,
        lease_generation: i64,
    ) -> AdminJobResult<()> {
        self.refresh_job_counts(job_id, worker_id, lease_generation)
            .await
    }
}

async fn insert_job_cancellation_audit(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    job_id: &str,
    context: &MutationContext,
    now: i64,
) -> AdminJobResult<()> {
    let audit = AuditEventRecord {
        id: random_id("audit"),
        event_type: "admin_bulk_job_cancel_requested".to_owned(),
        outcome: "succeeded".to_owned(),
        occurred_at: now,
        account_id: None,
        license_id: None,
        device_id: None,
        reason_code: None,
        metadata: BTreeMap::from([
            ("actor".to_owned(), context.principal.id.clone()),
            ("reason".to_owned(), context.reason.clone()),
            ("job_id".to_owned(), job_id.to_owned()),
            (
                "operation_id".to_owned(),
                context.operation_id.clone().unwrap_or_default(),
            ),
        ]),
    };
    sqlx::query(
        "INSERT INTO audit_events
         (id, event_type, outcome, occurred_at, account_id, license_id, device_id,
          reason_code, metadata, document)
         VALUES ($1, $2, $3, $4, NULL, NULL, NULL, NULL, $5, $6)",
    )
    .bind(&audit.id)
    .bind(&audit.event_type)
    .bind(&audit.outcome)
    .bind(audit.occurred_at)
    .bind(serde_json::to_value(&audit.metadata).map_err(|_| ApiError::Internal)?)
    .bind(serde_json::to_value(&audit).map_err(|_| ApiError::Internal)?)
    .execute(&mut **tx)
    .await
    .map_err(|_| ApiError::Database)?;
    Ok(())
}

pub async fn run_admin_worker() -> Result<(), Box<dyn std::error::Error>> {
    let environment = Environment::from_env()?;
    let runtime_metrics = RuntimeMetrics::new(RuntimeRole::AdminWorker);
    let database_url = env::var("DATABASE_URL")?;
    let database_pool = database_pool_config_from_env()?;
    let repository = PostgresRepository::connect(
        &database_url,
        database_pool.max_connections,
        database_pool.acquire_timeout,
    )
    .await?;
    if let Err(error) = repository.readiness_check().await {
        runtime_metrics.record_readiness(false);
        return Err(error.into());
    }
    crate::admin_http::admin_schema_ready(&repository).await?;
    let application = AdminApplication::new(
        repository.clone(),
        time_max_forward_jump_seconds_from_env()?,
    )
    .await?;
    let keyring = match env::var("CAMELLIA_NEXUS_ADMIN_KEYRING_PATH") {
        Ok(path) if !path.trim().is_empty() => Arc::new(AdminKeyring::load(PathBuf::from(path))?),
        _ if environment == Environment::Production => {
            return Err(
                "CAMELLIA_NEXUS_ADMIN_KEYRING_PATH is required for admin-worker in production"
                    .into(),
            );
        }
        _ => Arc::new(AdminKeyring::ephemeral()),
    };
    keyring.worker_readiness_check(&repository).await?;
    let storage = ObjectStorageService::new(
        application.clone(),
        keyring.clone(),
        ObjectStorageConfig::from_env()?,
    )?;
    storage.readiness_check().await?;
    let scanner = EvidenceScanner::from_env(environment == Environment::Production)?;
    scanner.readiness_check().await?;
    runtime_metrics.record_readiness(true);
    let jobs = AdminJobService::new(application.clone());
    let worker_id = random_id("admin_worker");
    let mut next_invoice_advance = 0_i64;
    let mut next_secret_purge = 0_i64;
    let mut next_storage_maintenance = 0_i64;
    let mut next_dependency_check = application
        .trusted_now()
        .await?
        .saturating_add(WORKER_DEPENDENCY_CHECK_SECONDS);
    let mut dependencies_ready = true;
    let metrics_server = MetricsServer::from_env(
        environment,
        RuntimeRole::AdminWorker,
        runtime_metrics.clone(),
    )
    .await?;
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
    let metrics_task = metrics_server.map(|server| {
        let task = tokio::spawn(server.serve(shutdown_rx.clone()));
        tokio::spawn(supervise_required_task(
            "admin-worker metrics listener",
            task,
            shutdown_tx.clone(),
            shutdown_rx.clone(),
        ))
    });
    let signal_tx = shutdown_tx.clone();
    let signal_task = tokio::spawn(async move {
        worker_shutdown_signal().await;
        let _ = signal_tx.send(true);
    });
    tracing::info!(
        worker_ref = %stable_log_reference(&worker_id),
        "Camellia Nexus admin worker started"
    );
    loop {
        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow() {
                    break;
                }
            },
            result = jobs.run_once(&worker_id) => {
                let followup = async {
                let now = match application.trusted_now().await {
                    Ok(now) => now,
                    Err(error) => {
                        runtime_metrics.record_readiness(false);
                        runtime_metrics.record_background_iteration(BackgroundOutcome::Error);
                        tracing::error!(%error, "admin worker cleanup skipped because trusted time is unavailable");
                        tokio::time::sleep(Duration::from_secs(2)).await;
                        return;
                    }
                };
                let mut cleanup_failed = false;
                if now >= next_dependency_check {
                    dependencies_ready = true;
                    if let Err(error) = keyring
                        .worker_readiness_check(application.repository())
                        .await
                    {
                        dependencies_ready = false;
                        tracing::error!(%error, "admin worker keyring readiness check failed");
                    }
                    if let Err(error) = scanner.readiness_check().await {
                        dependencies_ready = false;
                        tracing::error!(%error, "admin worker malware-scanner readiness check failed");
                    }
                    if let Err(error) = storage.readiness_check().await {
                        dependencies_ready = false;
                        tracing::error!(%error, "admin worker object-storage readiness check failed");
                    }
                    next_dependency_check =
                        now.saturating_add(WORKER_DEPENDENCY_CHECK_SECONDS);
                }
                if now >= next_invoice_advance {
                    match advance_overdue_invoices(application.repository(), now).await {
                        Ok(advanced) => {
                            next_invoice_advance = next_overdue_invoice_check(now, advanced);
                            if advanced > 0 {
                                tracing::info!(advanced, "overdue invoices advanced by trusted-time worker");
                            }
                        }
                        Err(error) => {
                            cleanup_failed = true;
                            next_invoice_advance =
                                now.saturating_add(WORKER_CLEANUP_INTERVAL_SECONDS);
                            tracing::error!(%error, "overdue invoice transition failed");
                        }
                    }
                }
                if now >= next_secret_purge {
                    let mut purge_failed = false;
                    let mut purged_deliveries = 0;
                    let mut purged_enrollment_states = 0;
                    match purge_secret_deliveries(application.repository(), now).await {
                        Ok(purged) => {
                            purged_deliveries = purged;
                            if purged > 0 {
                                tracing::info!(purged, "expired admin secret deliveries purged");
                            }
                        }
                        Err(error) => {
                            cleanup_failed = true;
                            purge_failed = true;
                            tracing::error!(%error, "admin secret delivery purge failed");
                        }
                    }
                    match purge_enrollment_states(application.repository(), now).await {
                        Ok(purged) => {
                            purged_enrollment_states = purged;
                            if purged > 0 {
                                tracing::info!(purged, "expired administrator enrollment secrets purged");
                            }
                        }
                        Err(error) => {
                            cleanup_failed = true;
                            purge_failed = true;
                            tracing::error!(%error, "administrator enrollment secret purge failed");
                        }
                    }
                    next_secret_purge = next_secret_purge_check(
                        now,
                        purge_failed,
                        purged_deliveries,
                        purged_enrollment_states,
                    );
                }
                if now >= next_storage_maintenance {
                    if let Err(error) = retry_payment_evidence(application.repository(), &storage, &scanner, now).await {
                        cleanup_failed = true;
                        tracing::error!(%error, "payment evidence retry failed");
                    }
                    if let Err(error) = purge_stale_objects(application.repository(), &storage, now).await {
                        cleanup_failed = true;
                        tracing::error!(%error, "stale object cleanup failed");
                    }
                    next_storage_maintenance =
                        now.saturating_add(WORKER_CLEANUP_INTERVAL_SECONDS);
                }
                let iteration_ready = result.is_ok() && !cleanup_failed && dependencies_ready;
                runtime_metrics.record_readiness(iteration_ready);
                match result {
                    Ok(true) => runtime_metrics.record_background_iteration(if iteration_ready {
                        BackgroundOutcome::Success
                    } else {
                        BackgroundOutcome::Error
                    }),
                    Ok(false) => {
                        runtime_metrics.record_background_iteration(if iteration_ready {
                            BackgroundOutcome::Idle
                        } else {
                            BackgroundOutcome::Error
                        });
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                    Err(error) => {
                        runtime_metrics.record_background_iteration(BackgroundOutcome::Error);
                        tracing::error!(%error, "admin worker iteration failed");
                        tokio::time::sleep(Duration::from_secs(2)).await;
                    }
                }
                };
                if complete_before_shutdown(&mut shutdown_rx, followup)
                    .await
                    .is_none()
                {
                    break;
                }
            }
        }
    }
    runtime_metrics.record_readiness(false);
    let _ = shutdown_tx.send(true);
    signal_task.abort();
    let _ = signal_task.await;
    let metrics_result = match metrics_task {
        Some(task) => join_required_task("admin-worker metrics supervisor", task).await,
        None => Ok(()),
    };
    metrics_result?;
    Ok(())
}

async fn complete_before_shutdown<T>(
    shutdown: &mut tokio::sync::watch::Receiver<bool>,
    operation: impl std::future::Future<Output = T>,
) -> Option<T> {
    if *shutdown.borrow() {
        return None;
    }
    tokio::pin!(operation);
    loop {
        tokio::select! {
            result = &mut operation => return Some(result),
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return None;
                }
            }
        }
    }
}

async fn advance_overdue_invoices(
    repository: &PostgresRepository,
    now: i64,
) -> Result<u64, ApiError> {
    let mut tx = repository
        .pool
        .begin()
        .await
        .map_err(|_| ApiError::Database)?;
    let rows = sqlx::query(
        "WITH candidates AS (
             SELECT id FROM billing_invoices
             WHERE status = 'open' AND due_at <= $1
             ORDER BY due_at, id
             FOR UPDATE SKIP LOCKED
             LIMIT $2
         )
         UPDATE billing_invoices AS invoices
         SET status = 'overdue', updated_at = $1, row_version = row_version + 1
         FROM candidates
         WHERE invoices.id = candidates.id
         RETURNING invoices.id, invoices.account_id, invoices.license_id",
    )
    .bind(now)
    .bind(OVERDUE_INVOICE_BATCH_SIZE)
    .fetch_all(&mut *tx)
    .await
    .map_err(|_| ApiError::Database)?;
    for row in &rows {
        let invoice_id: String = row.try_get("id").map_err(|_| ApiError::Database)?;
        let account_id: String = row.try_get("account_id").map_err(|_| ApiError::Database)?;
        let license_id: String = row.try_get("license_id").map_err(|_| ApiError::Database)?;
        let audit = AuditEventRecord {
            id: random_id("audit"),
            event_type: "billing_invoice_overdue".to_owned(),
            outcome: "succeeded".to_owned(),
            occurred_at: now,
            account_id: Some(account_id.clone()),
            license_id: Some(license_id.clone()),
            device_id: None,
            reason_code: Some("trusted_due_at_elapsed".to_owned()),
            metadata: BTreeMap::from([("invoice_id".to_owned(), invoice_id)]),
        };
        sqlx::query(
            "INSERT INTO audit_events
             (id, event_type, outcome, occurred_at, account_id, license_id, device_id,
              reason_code, metadata, document)
             VALUES ($1, $2, $3, $4, $5, $6, NULL, $7, $8, $9)",
        )
        .bind(&audit.id)
        .bind(&audit.event_type)
        .bind(&audit.outcome)
        .bind(audit.occurred_at)
        .bind(&account_id)
        .bind(&license_id)
        .bind(audit.reason_code.as_deref())
        .bind(serde_json::to_value(&audit.metadata).map_err(|_| ApiError::Internal)?)
        .bind(serde_json::to_value(&audit).map_err(|_| ApiError::Internal)?)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
    }
    tx.commit().await.map_err(|_| ApiError::Database)?;
    Ok(rows.len() as u64)
}

fn next_overdue_invoice_check(now: i64, advanced: u64) -> i64 {
    if advanced >= OVERDUE_INVOICE_BATCH_SIZE as u64 {
        now
    } else {
        now.saturating_add(WORKER_CLEANUP_INTERVAL_SECONDS)
    }
}

fn next_secret_purge_check(
    now: i64,
    failed: bool,
    purged_deliveries: u64,
    purged_enrollment_states: u64,
) -> i64 {
    if !failed
        && (purged_deliveries >= SECRET_CLEANUP_BATCH_SIZE as u64
            || purged_enrollment_states >= SECRET_CLEANUP_BATCH_SIZE as u64)
    {
        now
    } else {
        now.saturating_add(WORKER_CLEANUP_INTERVAL_SECONDS)
    }
}

pub(crate) async fn purge_secret_deliveries(
    repository: &PostgresRepository,
    now: i64,
) -> Result<u64, ApiError> {
    Ok(sqlx::query(
        "WITH candidates AS (
             SELECT id FROM admin_secret_deliveries
             WHERE expires_at <= $1 OR acknowledged_at IS NOT NULL
             ORDER BY (acknowledged_at IS NULL),
                      COALESCE(acknowledged_at, expires_at), id
             FOR UPDATE SKIP LOCKED
             LIMIT $2
         )
         DELETE FROM admin_secret_deliveries AS deliveries
         USING candidates
         WHERE deliveries.id = candidates.id",
    )
    .bind(now)
    .bind(SECRET_CLEANUP_BATCH_SIZE)
    .execute(&repository.pool)
    .await
    .map_err(|_| ApiError::Database)?
    .rows_affected())
}

pub(crate) async fn purge_enrollment_states(
    repository: &PostgresRepository,
    now: i64,
) -> Result<u64, ApiError> {
    Ok(sqlx::query(
        "WITH candidates AS (
             SELECT states.token_hash
             FROM admin_enrollment_states AS states
             JOIN admin_enrollment_tokens AS tokens
               ON tokens.token_hash = states.token_hash
             WHERE tokens.expires_at <= $1 OR tokens.consumed_at IS NOT NULL
             ORDER BY (tokens.consumed_at IS NULL),
                      COALESCE(tokens.consumed_at, tokens.expires_at), states.token_hash
             FOR UPDATE OF tokens, states SKIP LOCKED
             LIMIT $2
         )
         DELETE FROM admin_enrollment_states AS states
         USING candidates
         WHERE states.token_hash = candidates.token_hash",
    )
    .bind(now)
    .bind(SECRET_CLEANUP_BATCH_SIZE)
    .execute(&repository.pool)
    .await
    .map_err(|_| ApiError::Database)?
    .rows_affected())
}

async fn retry_payment_evidence(
    repository: &PostgresRepository,
    storage: &ObjectStorageService,
    scanner: &EvidenceScanner,
    now: i64,
) -> Result<(), String> {
    let rows = sqlx::query(
        "SELECT id, object_id FROM payment_evidence_attachments
         WHERE scan_status = 'failed' ORDER BY created_at LIMIT 10",
    )
    .fetch_all(&repository.pool)
    .await
    .map_err(|_| "database unavailable while loading failed evidence".to_owned())?;
    for row in rows {
        let evidence_id: String = row
            .try_get("id")
            .map_err(|_| "invalid evidence row".to_owned())?;
        let object_id: String = row
            .try_get("object_id")
            .map_err(|_| "invalid evidence object row".to_owned())?;
        let (_, content) = storage
            .get_for_scan(&object_id)
            .await
            .map_err(|error| error.to_string())?;
        let (scan_status, object_status) = match scanner.scan(&content).await {
            Ok(()) => ("clean", StoredObjectStatus::Ready),
            Err(ObjectStorageError::MalwareDetected) => ("rejected", StoredObjectStatus::Rejected),
            Err(ObjectStorageError::ScannerUnavailable) => continue,
            Err(error) => return Err(error.to_string()),
        };
        let mut tx = repository
            .pool
            .begin()
            .await
            .map_err(|_| "database unavailable while beginning evidence update".to_owned())?;
        let updated = sqlx::query(
            "UPDATE payment_evidence_attachments
             SET scan_status = $2, scanned_at = $3 WHERE id = $1 AND scan_status = 'failed'",
        )
        .bind(&evidence_id)
        .bind(scan_status)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|_| "database unavailable while updating evidence".to_owned())?
        .rows_affected();
        if updated != 1 {
            tx.rollback()
                .await
                .map_err(|_| "database unavailable while releasing evidence update".to_owned())?;
            continue;
        }
        storage
            .set_status_in_transaction(&mut tx, &object_id, object_status, now)
            .await
            .map_err(|error| error.to_string())?;
        tx.commit()
            .await
            .map_err(|_| "database unavailable while committing evidence update".to_owned())?;
        tracing::info!(
            evidence_ref = %stable_log_reference(&evidence_id),
            object_ref = %stable_log_reference(&object_id),
            scan_status,
            "payment evidence rescanned"
        );
    }
    Ok(())
}

pub(crate) async fn purge_stale_objects(
    repository: &PostgresRepository,
    storage: &ObjectStorageService,
    now: i64,
) -> Result<(), String> {
    let rows = sqlx::query(
        "SELECT objects.id, objects.status FROM stored_objects AS objects
         WHERE objects.updated_at < $1 AND (
             objects.status IN ('staging', 'deleting')
             OR (
                 objects.namespace = 'payment_evidence'
                 AND NOT EXISTS (
                     SELECT 1 FROM payment_evidence_attachments AS evidence
                     WHERE evidence.object_id = objects.id
                 )
             )
         )
         ORDER BY updated_at LIMIT 25",
    )
    .bind(now.saturating_sub(60 * 60))
    .fetch_all(&repository.pool)
    .await
    .map_err(|_| "database unavailable while loading stale objects".to_owned())?;
    for row in rows {
        let id: String = row
            .try_get("id")
            .map_err(|_| "invalid stale object row".to_owned())?;
        let status: String = row
            .try_get("status")
            .map_err(|_| "invalid stale object status".to_owned())?;
        if status == StoredObjectStatus::Staging.as_str() {
            match storage
                .reconcile_staging(&id, now)
                .await
                .map_err(|error| error.to_string())?
            {
                StagingReconciliation::Finalized => {
                    tracing::info!(
                        object_ref = %stable_log_reference(&id),
                        "staged stored object finalized"
                    );
                }
                StagingReconciliation::Removed => {
                    tracing::info!(
                        object_ref = %stable_log_reference(&id),
                        "invalid staged stored object removed"
                    );
                }
                StagingReconciliation::Unchanged => {}
            }
        } else {
            storage
                .delete(&id)
                .await
                .map_err(|error| error.to_string())?;
            tracing::info!(
                object_ref = %stable_log_reference(&id),
                "stale stored object removed"
            );
        }
    }
    Ok(())
}

async fn worker_shutdown_signal() {
    #[cfg(unix)]
    {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut terminate) => tokio::select! {
                _ = tokio::signal::ctrl_c() => {},
                _ = terminate.recv() => {},
            },
            Err(error) => {
                tracing::warn!(%error, "SIGTERM handler is unavailable; waiting for Ctrl-C");
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

fn row_job(row: sqlx::postgres::PgRow) -> AdminJobResult<BulkJob> {
    Ok(BulkJob {
        id: row.try_get("id").map_err(|_| ApiError::Database)?,
        kind: BulkJobKind::parse(
            &row.try_get::<String, _>("kind")
                .map_err(|_| ApiError::Database)?,
        )?,
        status: parse_job_status(
            &row.try_get::<String, _>("status")
                .map_err(|_| ApiError::Database)?,
        )?,
        actor_id: row.try_get("actor_id").map_err(|_| ApiError::Database)?,
        reason: row.try_get("reason").map_err(|_| ApiError::Database)?,
        parameters: row.try_get("parameters").map_err(|_| ApiError::Database)?,
        total_items: row.try_get("total_items").map_err(|_| ApiError::Database)?,
        completed_items: row
            .try_get("completed_items")
            .map_err(|_| ApiError::Database)?,
        failed_items: row
            .try_get("failed_items")
            .map_err(|_| ApiError::Database)?,
        created_at: row.try_get("created_at").map_err(|_| ApiError::Database)?,
        started_at: row.try_get("started_at").map_err(|_| ApiError::Database)?,
        finished_at: row.try_get("finished_at").map_err(|_| ApiError::Database)?,
    })
}

fn parse_job_status(value: &str) -> AdminJobResult<BulkJobStatus> {
    match value {
        "queued" => Ok(BulkJobStatus::Queued),
        "running" => Ok(BulkJobStatus::Running),
        "cancel_requested" => Ok(BulkJobStatus::CancelRequested),
        "succeeded" => Ok(BulkJobStatus::Succeeded),
        "partial_failed" => Ok(BulkJobStatus::PartialFailed),
        "failed" => Ok(BulkJobStatus::Failed),
        "canceled" => Ok(BulkJobStatus::Canceled),
        _ => Err(ApiError::Database.into()),
    }
}

fn validate_parameters(kind: BulkJobKind, parameters: &Value) -> AdminJobResult<()> {
    if !parameters.is_object() {
        return Err(AdminJobError::Validation(
            "parameters must be an object".to_owned(),
        ));
    }
    match kind {
        BulkJobKind::AccountSetState => {
            parse_account_state(parameter_string(parameters, "state")?)?;
        }
        BulkJobKind::LicenseSetStatus => {
            parse_license_status(parameter_string(parameters, "status")?)?;
        }
        BulkJobKind::ActivationCodeRevoke => {
            if parameters
                .as_object()
                .is_some_and(|value| !value.is_empty())
            {
                return Err(AdminJobError::Validation(
                    "activation_code_revoke accepts no parameters".to_owned(),
                ));
            }
        }
        BulkJobKind::ActivationCodeExpire => {
            if parameters
                .get("expiresAt")
                .and_then(Value::as_i64)
                .is_none()
            {
                return Err(AdminJobError::Validation(
                    "expiresAt must be Unix seconds".to_owned(),
                ));
            }
        }
        BulkJobKind::DeviceSetState => {
            parse_device_state(parameter_string(parameters, "state")?)?;
        }
    }
    Ok(())
}

fn parameter_string<'a>(parameters: &'a Value, key: &str) -> AdminJobResult<&'a str> {
    parameters
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| AdminJobError::Validation(format!("{key} must be a string")))
}

fn parse_account_state(value: &str) -> AdminJobResult<AccountState> {
    match value {
        "active" => Ok(AccountState::Active),
        "suspended" => Ok(AccountState::Suspended),
        "denylisted" => Ok(AccountState::Denylisted),
        _ => Err(AdminJobError::Validation(
            "invalid account state".to_owned(),
        )),
    }
}

fn parse_license_status(value: &str) -> AdminJobResult<LicenseStatus> {
    match value {
        "active" => Ok(LicenseStatus::Active),
        "past_due" => Ok(LicenseStatus::PastDue),
        "canceled" => Ok(LicenseStatus::Canceled),
        _ => Err(AdminJobError::Validation(
            "invalid license status".to_owned(),
        )),
    }
}

fn parse_device_state(value: &str) -> AdminJobResult<DeviceState> {
    match value {
        "removed" => Ok(DeviceState::Removed),
        "revoked" => Ok(DeviceState::Revoked),
        "suspicious" => Ok(DeviceState::Suspicious),
        _ => Err(AdminJobError::Validation("invalid device state".to_owned())),
    }
}

fn target_type(kind: BulkJobKind) -> &'static str {
    match kind {
        BulkJobKind::AccountSetState => "account",
        BulkJobKind::LicenseSetStatus => "license",
        BulkJobKind::ActivationCodeRevoke | BulkJobKind::ActivationCodeExpire => "activation_code",
        BulkJobKind::DeviceSetState => "device",
    }
}

pub(crate) fn required_admin_permission(
    kind: BulkJobKind,
    parameters: &Value,
) -> AdminJobResult<AdminPermission> {
    match kind {
        BulkJobKind::AccountSetState => Ok(
            match parse_account_state(parameter_string(parameters, "state")?)? {
                AccountState::Active | AccountState::Suspended => AdminPermission::AccountWrite,
                AccountState::Denylisted => AdminPermission::AccountDenylist,
            },
        ),
        BulkJobKind::LicenseSetStatus => Ok(AdminPermission::LicenseWrite),
        BulkJobKind::ActivationCodeRevoke | BulkJobKind::ActivationCodeExpire => {
            Ok(AdminPermission::CodeWrite)
        }
        BulkJobKind::DeviceSetState => Ok(
            match parse_device_state(parameter_string(parameters, "state")?)? {
                DeviceState::Removed => AdminPermission::DeviceRemove,
                DeviceState::Revoked | DeviceState::Suspicious => AdminPermission::DeviceSecurity,
                DeviceState::PendingActivation | DeviceState::Active => {
                    return Err(AdminJobError::Validation("invalid device state".to_owned()));
                }
            },
        ),
    }
}

fn authorized_roles(kind: BulkJobKind, parameters: &Value) -> AdminJobResult<Vec<&'static str>> {
    let roles = match kind {
        BulkJobKind::AccountSetState => {
            match parse_account_state(parameter_string(parameters, "state")?)? {
                AccountState::Active | AccountState::Suspended => {
                    vec!["platform_owner", "licensing_admin"]
                }
                AccountState::Denylisted => vec!["platform_owner", "security_admin"],
            }
        }
        BulkJobKind::LicenseSetStatus => vec!["platform_owner", "licensing_admin"],
        BulkJobKind::ActivationCodeRevoke | BulkJobKind::ActivationCodeExpire => {
            vec!["platform_owner", "licensing_admin"]
        }
        BulkJobKind::DeviceSetState => {
            match parse_device_state(parameter_string(parameters, "state")?)? {
                DeviceState::Removed => vec!["platform_owner", "licensing_admin"],
                DeviceState::Revoked | DeviceState::Suspicious => {
                    vec!["platform_owner", "security_admin"]
                }
                DeviceState::PendingActivation | DeviceState::Active => {
                    return Err(AdminJobError::Validation("invalid device state".to_owned()));
                }
            }
        }
    };
    Ok(roles)
}

fn transient(error: &AdminJobError) -> bool {
    matches!(
        error,
        AdminJobError::Service(ApiError::Database | ApiError::TimeAuthorityUnavailable)
            | AdminJobError::Application(AdminAppError::Service(
                ApiError::Database | ApiError::TimeAuthorityUnavailable
            ))
    )
}

fn job_error_code(error: &AdminJobError) -> &'static str {
    match error {
        AdminJobError::NotFound => "target_not_found",
        AdminJobError::Application(AdminAppError::VersionConflict) => "target_version_conflict",
        AdminJobError::Validation(_) => "validation_failed",
        AdminJobError::PermissionDenied => "permission_denied",
        AdminJobError::Service(ApiError::TimeAuthorityUnavailable)
        | AdminJobError::Application(AdminAppError::Service(ApiError::TimeAuthorityUnavailable)) => {
            "time_authority_unavailable"
        }
        _ => "operation_failed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn cancellation_is_idempotent_and_active_leases_cannot_be_stolen() {
        let database_url = std::env::var("TEST_DATABASE_URL")
            .expect("TEST_DATABASE_URL is required for the PostgreSQL integration test");
        let repository = PostgresRepository::connect(&database_url, 2, Duration::from_secs(5))
            .await
            .expect("connect PostgreSQL");
        repository.migrate().await.expect("run migrations");
        let suffix = random_id("job_test");
        let actor_id = format!("admin_{suffix}");
        let session_id = format!("session_{suffix}");
        let target_id = format!("account_{suffix}");
        let queued_id = format!("queued_{suffix}");
        let leased_id = format!("leased_{suffix}");
        let application = AdminApplication::new(repository.clone(), 24 * 60 * 60)
            .await
            .expect("initialize admin application");
        let now = application.trusted_now().await.expect("trusted time");
        sqlx::query(
            "INSERT INTO admin_users
             (id, username, display_name, status, created_at, updated_at)
             VALUES ($1, $2, 'Job test', 'active', $3, $3)",
        )
        .bind(&actor_id)
        .bind(format!("job-test-{suffix}"))
        .bind(now)
        .execute(&repository.pool)
        .await
        .expect("insert admin user");
        sqlx::query(
            "INSERT INTO admin_password_credentials
             (user_id, password_hash, key_id, changed_at)
             VALUES ($1, 'test-only-hash', 'test-only-key', $2)",
        )
        .bind(&actor_id)
        .bind(now)
        .execute(&repository.pool)
        .await
        .expect("insert admin password credential");
        sqlx::query(
            "INSERT INTO admin_role_bindings
             (user_id, role, granted_by, reason, created_at)
             VALUES ($1, 'licensing_admin', 'test', 'bulk authorization test', $2)",
        )
        .bind(&actor_id)
        .bind(now)
        .execute(&repository.pool)
        .await
        .expect("insert admin role");
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
        .execute(&repository.pool)
        .await
        .expect("insert admin session");
        sqlx::query(
            "INSERT INTO accounts (id, document)
             VALUES ($1, jsonb_build_object('created_at', $2::BIGINT))",
        )
        .bind(&target_id)
        .bind(now)
        .execute(&repository.pool)
        .await
        .expect("insert bulk target");
        for (id, status, owner, expiry) in [
            (&queued_id, "queued", None, None),
            (
                &leased_id,
                "cancel_requested",
                Some("worker-a"),
                Some(now.saturating_add(3_600)),
            ),
        ] {
            sqlx::query(
                "INSERT INTO admin_bulk_jobs
                 (id, kind, status, actor_id, reason, idempotency_key, request_hash,
                  parameters, total_items, lease_owner, lease_expires_at, created_at)
                 VALUES ($1, 'account_set_state', $2, $3, 'test', $1,
                         repeat('0', 64), '{\"state\":\"active\"}'::jsonb, 1, $4, $5, $6)",
            )
            .bind(id)
            .bind(status)
            .bind(&actor_id)
            .bind(owner)
            .bind(expiry)
            .bind(now)
            .execute(&repository.pool)
            .await
            .expect("insert admin job");
            sqlx::query(
                "INSERT INTO admin_bulk_job_items
                 (job_id, ordinal, target_type, target_id, expected_version, status)
                 VALUES ($1, 0, 'account', $2, 1, 'pending')",
            )
            .bind(id)
            .bind(format!("target_{suffix}"))
            .execute(&repository.pool)
            .await
            .expect("insert admin job item");
        }

        let jobs = AdminJobService::new(application);
        let preview = jobs
            .create_preview(
                &actor_id,
                &session_id,
                CreatePreview {
                    kind: BulkJobKind::AccountSetState,
                    target_ids: vec![target_id.clone()],
                    parameters: json!({"state": "active"}),
                },
            )
            .await
            .expect("create replay preview");
        let replay_key = format!("replay-{suffix}");
        let first = jobs
            .create_job(
                &actor_id,
                &session_id,
                &preview.id,
                "idempotent replay test",
                &replay_key,
            )
            .await
            .expect("create replay job");
        let replay = jobs
            .create_job(
                &actor_id,
                &session_id,
                &preview.id,
                "idempotent replay test",
                &replay_key,
            )
            .await
            .expect("replay consumed preview");
        assert_eq!(replay.id, first.id);
        assert!(matches!(
            jobs.create_job(
                &actor_id,
                &session_id,
                &preview.id,
                "changed replay payload",
                &replay_key,
            )
            .await,
            Err(AdminJobError::Conflict)
        ));
        sqlx::query("DELETE FROM admin_bulk_jobs WHERE id = $1")
            .bind(&first.id)
            .execute(&repository.pool)
            .await
            .expect("delete replay job");
        let mut cancel_context = MutationContext::new(
            AdminPrincipal::cli(&actor_id).unwrap(),
            "cancel integration test job",
        )
        .unwrap();
        cancel_context.operation_id = Some(format!("cancel-{suffix}"));
        assert!(matches!(
            jobs.cancel(&queued_id, &cancel_context)
                .await
                .expect("cancel queued job")
                .status,
            BulkJobStatus::Canceled
        ));
        assert!(matches!(
            jobs.cancel(&queued_id, &cancel_context)
                .await
                .expect("repeat cancellation")
                .status,
            BulkJobStatus::Canceled
        ));
        let pending: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM admin_bulk_job_items
             WHERE job_id = $1 AND status = 'pending'",
        )
        .bind(&queued_id)
        .fetch_one(&repository.pool)
        .await
        .expect("count pending items");
        assert_eq!(pending, 0);

        assert!(
            !jobs
                .run_once("worker-b")
                .await
                .expect("active lease must be skipped")
        );
        let lease_owner: Option<String> =
            sqlx::query_scalar("SELECT lease_owner FROM admin_bulk_jobs WHERE id = $1")
                .bind(&leased_id)
                .fetch_one(&repository.pool)
                .await
                .expect("load lease owner");
        assert_eq!(lease_owner.as_deref(), Some("worker-a"));

        sqlx::query("DELETE FROM admin_bulk_jobs WHERE actor_id = $1")
            .bind(&actor_id)
            .execute(&repository.pool)
            .await
            .expect("delete jobs");
        sqlx::query("DELETE FROM accounts WHERE id = $1")
            .bind(&target_id)
            .execute(&repository.pool)
            .await
            .expect("delete bulk target");
        sqlx::query("DELETE FROM admin_users WHERE id = $1")
            .bind(&actor_id)
            .execute(&repository.pool)
            .await
            .expect("delete admin user");
        repository.close().await;
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn expired_lease_reconciles_a_committed_item_without_reporting_failure() {
        let database_url = std::env::var("TEST_DATABASE_URL")
            .expect("TEST_DATABASE_URL is required for the PostgreSQL integration test");
        let repository = PostgresRepository::connect(&database_url, 4, Duration::from_secs(5))
            .await
            .expect("connect PostgreSQL");
        repository.migrate().await.expect("run migrations");
        let application = AdminApplication::new(repository.clone(), 24 * 60 * 60)
            .await
            .expect("initialize admin application");
        let now = application.trusted_now().await.expect("trusted time");
        let suffix = random_id("job_fence_test");
        let actor_id = format!("admin_{suffix}");
        let target_id = format!("account_{suffix}");
        let job_id = format!("job_{suffix}");
        let operation_id = format!("{job_id}:0");

        sqlx::query(
            "INSERT INTO admin_users
             (id, username, display_name, status, created_at, updated_at)
             VALUES ($1, $2, 'Lease fencing test', 'active', $3, $3)",
        )
        .bind(&actor_id)
        .bind(format!("lease-{suffix}"))
        .bind(now)
        .execute(&repository.pool)
        .await
        .expect("insert admin user");
        sqlx::query(
            "INSERT INTO admin_role_bindings
             (user_id, role, granted_by, reason, created_at)
             VALUES ($1, 'platform_owner', $1, 'lease fencing test', $2)",
        )
        .bind(&actor_id)
        .bind(now)
        .execute(&repository.pool)
        .await
        .expect("insert admin role");
        repository
            .upsert_account(crate::domain::Account::active(&target_id, now))
            .await
            .expect("insert account");

        let mut context = MutationContext::new(
            AdminPrincipal::cli(&actor_id).unwrap(),
            "lease fencing test",
        )
        .unwrap();
        context.operation_id = Some(operation_id.clone());
        context.job_id = Some(job_id.clone());
        application
            .set_account_state(&target_id, AccountState::Suspended, Some(1), &context)
            .await
            .expect("commit item business transaction before result persistence");

        sqlx::query(
            "INSERT INTO admin_bulk_jobs
             (id, kind, status, actor_id, reason, idempotency_key, request_hash,
              parameters, total_items, lease_owner, lease_expires_at, lease_generation,
              created_at, started_at)
             VALUES ($1, 'account_set_state', 'running', $2, 'lease fencing test', $1,
                     repeat('0', 64), '{\"state\":\"suspended\"}'::jsonb, 1, $3, $4, 1,
                     $5, $5)",
        )
        .bind(&job_id)
        .bind(&actor_id)
        .bind("reused-worker-id")
        .bind(now.saturating_sub(1))
        .bind(now.saturating_sub(120))
        .execute(&repository.pool)
        .await
        .expect("insert expired leased job");
        sqlx::query(
            "INSERT INTO admin_bulk_job_items
             (job_id, ordinal, target_type, target_id, expected_version, status,
              attempts, lease_generation, started_at)
             VALUES ($1, 0, 'account', $2, 1, 'running', 1, 1, $3)",
        )
        .bind(&job_id)
        .bind(&target_id)
        .bind(now.saturating_sub(120))
        .execute(&repository.pool)
        .await
        .expect("insert item left running after business commit");

        let jobs = AdminJobService::new(application);
        assert!(
            jobs.run_once("reused-worker-id")
                .await
                .expect("reconcile expired lease")
        );
        let (job_status, generation): (String, i64) =
            sqlx::query_as("SELECT status, lease_generation FROM admin_bulk_jobs WHERE id = $1")
                .bind(&job_id)
                .fetch_one(&repository.pool)
                .await
                .expect("load reconciled job");
        assert_eq!(job_status, "succeeded");
        assert_eq!(generation, 2);
        let (item_status, error_code): (String, Option<String>) = sqlx::query_as(
            "SELECT status, error_code FROM admin_bulk_job_items
             WHERE job_id = $1 AND ordinal = 0",
        )
        .bind(&job_id)
        .fetch_one(&repository.pool)
        .await
        .expect("load reconciled item");
        assert_eq!(item_status, "succeeded");
        assert_eq!(error_code, None);
        let operations: i64 =
            sqlx::query_scalar("SELECT count(*) FROM admin_operations WHERE operation_id = $1")
                .bind(&operation_id)
                .fetch_one(&repository.pool)
                .await
                .expect("count idempotent operations");
        assert_eq!(operations, 1);
        let successful_audits: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM audit_events
             WHERE event_type = 'account_state_set'
               AND metadata ->> 'job_id' = $1
               AND outcome = 'succeeded'",
        )
        .bind(&job_id)
        .fetch_one(&repository.pool)
        .await
        .expect("count business audits");
        assert_eq!(successful_audits, 1);

        sqlx::query("DELETE FROM admin_bulk_jobs WHERE id = $1")
            .bind(&job_id)
            .execute(&repository.pool)
            .await
            .expect("delete job");
        sqlx::query("DELETE FROM admin_operations WHERE operation_id = $1")
            .bind(&operation_id)
            .execute(&repository.pool)
            .await
            .expect("delete operation");
        sqlx::query("DELETE FROM accounts WHERE id = $1")
            .bind(&target_id)
            .execute(&repository.pool)
            .await
            .expect("delete account");
        sqlx::query("DELETE FROM admin_users WHERE id = $1")
            .bind(&actor_id)
            .execute(&repository.pool)
            .await
            .expect("delete admin user");
        repository.close().await;
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn secret_cleanup_is_bounded_and_drains_backlogs() {
        let database_url = std::env::var("TEST_DATABASE_URL")
            .expect("TEST_DATABASE_URL is required for the PostgreSQL integration test");
        let repository = PostgresRepository::connect(&database_url, 2, Duration::from_secs(5))
            .await
            .expect("connect PostgreSQL");
        repository.migrate().await.expect("run migrations");

        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let actor_id = format!("purge_actor_{suffix}");
        let session_id = format!("purge_session_{suffix}");
        let delivery_prefix = format!("purge_delivery_{suffix}_");
        let now = 2_000_000_000_i64;
        sqlx::query(
            "INSERT INTO admin_users
                (id, username, display_name, status, created_at, updated_at)
             VALUES ($1, $2, 'Purge test', 'active', $3, $3)",
        )
        .bind(&actor_id)
        .bind(format!("purge-{suffix}"))
        .bind(now - 60)
        .execute(&repository.pool)
        .await
        .expect("insert purge-test administrator");
        sqlx::query(
            "INSERT INTO admin_sessions
                (id, user_id, token_hash, csrf_hash, auth_time, elevated_until,
                 last_seen_at, expires_at, created_at)
             VALUES ($1, $2, $3, $4, $5, $5, $5, $6, $5)",
        )
        .bind(&session_id)
        .bind(&actor_id)
        .bind(sha256_hex(&format!("purge-session-token-{suffix}")))
        .bind(sha256_hex(&format!("purge-session-csrf-{suffix}")))
        .bind(now - 60)
        .bind(now + 60)
        .execute(&repository.pool)
        .await
        .expect("insert purge-test session");
        sqlx::query(
            "INSERT INTO admin_secret_deliveries
                (id, actor_id, session_id, purpose, key_id, nonce, ciphertext,
                 claim_token_hash, expires_at, created_at)
             SELECT $1 || series::TEXT, $2, $3, 'admin_enrollment', 'purge-test-key',
                    decode('00', 'hex'), decode('00', 'hex'),
                    md5($4 || series::TEXT) || md5($4 || series::TEXT), $5 - 1, $5 - 60
             FROM generate_series(1, $6::BIGINT) AS series",
        )
        .bind(&delivery_prefix)
        .bind(&actor_id)
        .bind(&session_id)
        .bind(format!("purge-delivery-claim-{suffix}-"))
        .bind(now)
        .bind(SECRET_CLEANUP_BATCH_SIZE + 1)
        .execute(&repository.pool)
        .await
        .expect("insert expired secret deliveries");
        sqlx::query(
            "INSERT INTO admin_enrollment_tokens
                (token_hash, user_id, purpose, created_by, reason, expires_at, created_at)
             SELECT md5($1 || series::TEXT) || md5($1 || series::TEXT), $2,
                    'enroll', $2, 'purge test', $3 - 1, $3 - 60
             FROM generate_series(1, $4::BIGINT) AS series",
        )
        .bind(format!("purge-enrollment-token-{suffix}-"))
        .bind(&actor_id)
        .bind(now)
        .bind(SECRET_CLEANUP_BATCH_SIZE + 1)
        .execute(&repository.pool)
        .await
        .expect("insert expired enrollment tokens");
        sqlx::query(
            "INSERT INTO admin_enrollment_states
                (token_hash, key_id, nonce, ciphertext, created_at)
             SELECT token_hash, 'purge-test-key', decode('00', 'hex'),
                    decode('00', 'hex'), $2 - 60
             FROM admin_enrollment_tokens WHERE user_id = $1",
        )
        .bind(&actor_id)
        .bind(now)
        .execute(&repository.pool)
        .await
        .expect("insert expired enrollment states");

        let mut blocker = repository.pool.begin().await.expect("begin purge blocker");
        let locked_delivery_id: String = sqlx::query_scalar(
            "SELECT id FROM admin_secret_deliveries
             WHERE actor_id = $1 ORDER BY id LIMIT 1 FOR UPDATE",
        )
        .bind(&actor_id)
        .fetch_one(&mut *blocker)
        .await
        .expect("lock one secret delivery");
        let locked_state_hash: String = sqlx::query_scalar(
            "SELECT states.token_hash
             FROM admin_enrollment_states AS states
             JOIN admin_enrollment_tokens AS tokens
               ON tokens.token_hash = states.token_hash
             WHERE tokens.user_id = $1
             ORDER BY states.token_hash LIMIT 1
             FOR UPDATE OF tokens, states",
        )
        .bind(&actor_id)
        .fetch_one(&mut *blocker)
        .await
        .expect("lock one enrollment state");
        let first_deliveries = purge_secret_deliveries(&repository, now)
            .await
            .expect("purge first secret-delivery batch");
        let first_states = purge_enrollment_states(&repository, now)
            .await
            .expect("purge first enrollment-state batch");
        let remaining_after_first: (i64, i64) = sqlx::query_as(
            "SELECT
                (SELECT count(*) FROM admin_secret_deliveries WHERE actor_id = $1),
                (SELECT count(*) FROM admin_enrollment_states s
                 JOIN admin_enrollment_tokens t ON t.token_hash = s.token_hash
                 WHERE t.user_id = $1)",
        )
        .bind(&actor_id)
        .fetch_one(&repository.pool)
        .await
        .expect("count first secret-cleanup batch");
        let remaining_ids: (String, String) = sqlx::query_as(
            "SELECT
                (SELECT id FROM admin_secret_deliveries WHERE actor_id = $1),
                (SELECT s.token_hash FROM admin_enrollment_states s
                 JOIN admin_enrollment_tokens t ON t.token_hash = s.token_hash
                 WHERE t.user_id = $1)",
        )
        .bind(&actor_id)
        .fetch_one(&repository.pool)
        .await
        .expect("load locked rows skipped by secret cleanup");
        blocker.commit().await.expect("release purge blocker");
        let second_deliveries = purge_secret_deliveries(&repository, now)
            .await
            .expect("purge final secret-delivery batch");
        let second_states = purge_enrollment_states(&repository, now)
            .await
            .expect("purge final enrollment-state batch");
        let remaining_after_second: (i64, i64) = sqlx::query_as(
            "SELECT
                (SELECT count(*) FROM admin_secret_deliveries WHERE actor_id = $1),
                (SELECT count(*) FROM admin_enrollment_states s
                 JOIN admin_enrollment_tokens t ON t.token_hash = s.token_hash
                 WHERE t.user_id = $1)",
        )
        .bind(&actor_id)
        .fetch_one(&repository.pool)
        .await
        .expect("count final secret-cleanup batch");

        sqlx::query("DELETE FROM admin_users WHERE id = $1")
            .bind(&actor_id)
            .execute(&repository.pool)
            .await
            .expect("delete purge-test administrator");
        repository.close().await;

        assert_eq!(
            (first_deliveries, first_states),
            (
                SECRET_CLEANUP_BATCH_SIZE as u64,
                SECRET_CLEANUP_BATCH_SIZE as u64
            )
        );
        assert_eq!(remaining_after_first, (1, 1));
        assert_eq!(remaining_ids, (locked_delivery_id, locked_state_hash));
        assert_eq!((second_deliveries, second_states), (1, 1));
        assert_eq!(remaining_after_second, (0, 0));
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn overdue_invoice_transition_is_bounded_versioned_and_audited() {
        let database_url = std::env::var("TEST_DATABASE_URL")
            .expect("TEST_DATABASE_URL is required for the PostgreSQL integration test");
        let repository = PostgresRepository::connect(&database_url, 2, Duration::from_secs(5))
            .await
            .expect("connect PostgreSQL");
        repository.migrate().await.expect("run migrations");

        let suffix = random_id("overdue_test");
        let account_id = format!("account_{suffix}");
        let license_id = format!("license_{suffix}");
        let offer_id = format!("offer_{suffix}");
        let invoice_prefix = format!("invoice_{suffix}_");
        let now = 2_000_000_000_i64;
        sqlx::query(
            "INSERT INTO accounts (id, document)
             VALUES ($1, jsonb_build_object('created_at', $2::BIGINT))",
        )
        .bind(&account_id)
        .bind(now)
        .execute(&repository.pool)
        .await
        .expect("insert overdue-test account");
        sqlx::query(
            "INSERT INTO licenses
                (id, account_id, plan, plan_revision, status, expires_at, license_epoch,
                 purchased_seats, row_version)
             VALUES ($1, $2, 'pro', 1, 'active', NULL, 1, 0, 1)",
        )
        .bind(&license_id)
        .bind(&account_id)
        .execute(&repository.pool)
        .await
        .expect("insert overdue-test license");
        sqlx::query(
            "INSERT INTO commercial_offers
                (id, plan, plan_revision, duration_days, currency, base_amount, seat_amount,
                 name_en, name_zh, active, created_at, updated_at)
             VALUES ($1, 'pro', 1, 365, 'USD', 99, NULL, 'Test', 'Test', true, $2, $2)",
        )
        .bind(&offer_id)
        .bind(now)
        .execute(&repository.pool)
        .await
        .expect("insert overdue-test offer");
        sqlx::query(
            "INSERT INTO billing_invoices
                (id, account_id, license_id, offer_id, plan, plan_revision, seats,
                 duration_days, currency, amount_due, payment_reference, status, due_at,
                 paid_at, created_at, updated_at)
             SELECT $1 || series::TEXT, $2, $3, $4, 'pro', 1, 0, 365, 'USD', 99,
                    $5 || series::TEXT, 'open', $6, NULL, $7, $7
             FROM generate_series(1, $8::BIGINT) AS series",
        )
        .bind(&invoice_prefix)
        .bind(&account_id)
        .bind(&license_id)
        .bind(&offer_id)
        .bind(format!("CNX-OVERDUE-{suffix}-"))
        .bind(now - 1)
        .bind(now - 60)
        .bind(OVERDUE_INVOICE_BATCH_SIZE + 1)
        .execute(&repository.pool)
        .await
        .expect("insert overdue-test invoices");

        let first_advanced = advance_overdue_invoices(&repository, now)
            .await
            .expect("advance first overdue invoice batch");
        let first_state: (i64, i64, i64) = sqlx::query_as(
            "SELECT count(*) FILTER (WHERE status = 'overdue'),
                    count(*) FILTER (WHERE status = 'open'),
                    count(*) FILTER (WHERE status = 'overdue' AND row_version = 2)
             FROM billing_invoices WHERE account_id = $1",
        )
        .bind(&account_id)
        .fetch_one(&repository.pool)
        .await
        .expect("load first overdue batch state");
        let first_audit_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM audit_events
             WHERE event_type = 'billing_invoice_overdue' AND account_id = $1",
        )
        .bind(&account_id)
        .fetch_one(&repository.pool)
        .await
        .expect("count first overdue audit batch");
        let second_advanced = advance_overdue_invoices(&repository, now)
            .await
            .expect("advance final overdue invoice batch");
        let final_state: (i64, i64, i64) = sqlx::query_as(
            "SELECT count(*) FILTER (WHERE status = 'overdue'),
                    count(*) FILTER (WHERE status = 'open'),
                    count(*) FILTER (WHERE status = 'overdue' AND row_version = 2)
             FROM billing_invoices WHERE account_id = $1",
        )
        .bind(&account_id)
        .fetch_one(&repository.pool)
        .await
        .expect("load final overdue batch state");
        let final_audit_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM audit_events
             WHERE event_type = 'billing_invoice_overdue' AND account_id = $1",
        )
        .bind(&account_id)
        .fetch_one(&repository.pool)
        .await
        .expect("count final overdue audit batch");

        sqlx::query(
            "DELETE FROM audit_events
             WHERE event_type = 'billing_invoice_overdue' AND account_id = $1",
        )
        .bind(&account_id)
        .execute(&repository.pool)
        .await
        .expect("delete overdue-test audit");
        sqlx::query("DELETE FROM billing_invoices WHERE account_id = $1")
            .bind(&account_id)
            .execute(&repository.pool)
            .await
            .expect("delete overdue-test invoices");
        sqlx::query("DELETE FROM commercial_offers WHERE id = $1")
            .bind(&offer_id)
            .execute(&repository.pool)
            .await
            .expect("delete overdue-test offer");
        sqlx::query("DELETE FROM licenses WHERE id = $1")
            .bind(&license_id)
            .execute(&repository.pool)
            .await
            .expect("delete overdue-test license");
        sqlx::query("DELETE FROM accounts WHERE id = $1")
            .bind(&account_id)
            .execute(&repository.pool)
            .await
            .expect("delete overdue-test account");
        repository.close().await;

        assert_eq!(first_advanced, OVERDUE_INVOICE_BATCH_SIZE as u64);
        assert_eq!(
            first_state,
            (OVERDUE_INVOICE_BATCH_SIZE, 1, OVERDUE_INVOICE_BATCH_SIZE)
        );
        assert_eq!(first_audit_count, OVERDUE_INVOICE_BATCH_SIZE);
        assert_eq!(second_advanced, 1);
        assert_eq!(
            final_state,
            (
                OVERDUE_INVOICE_BATCH_SIZE + 1,
                0,
                OVERDUE_INVOICE_BATCH_SIZE + 1
            )
        );
        assert_eq!(final_audit_count, OVERDUE_INVOICE_BATCH_SIZE + 1);
    }

    #[test]
    fn overdue_invoice_backlog_rechecks_immediately_only_after_a_full_batch() {
        let now = 2_000_000_000_i64;
        assert_eq!(
            next_overdue_invoice_check(now, OVERDUE_INVOICE_BATCH_SIZE as u64),
            now
        );
        assert_eq!(
            next_overdue_invoice_check(now, OVERDUE_INVOICE_BATCH_SIZE as u64 - 1),
            now + WORKER_CLEANUP_INTERVAL_SECONDS
        );
    }

    #[test]
    fn secret_backlog_rechecks_immediately_without_repeating_storage_maintenance() {
        let now = 2_000_000_000_i64;
        assert_eq!(
            next_secret_purge_check(now, false, SECRET_CLEANUP_BATCH_SIZE as u64, 0),
            now
        );
        assert_eq!(
            next_secret_purge_check(now, false, 0, SECRET_CLEANUP_BATCH_SIZE as u64),
            now
        );
        assert_eq!(
            next_secret_purge_check(now, false, SECRET_CLEANUP_BATCH_SIZE as u64 - 1, 0),
            now + WORKER_CLEANUP_INTERVAL_SECONDS
        );
        assert_eq!(
            next_secret_purge_check(now, true, SECRET_CLEANUP_BATCH_SIZE as u64, 0),
            now + WORKER_CLEANUP_INTERVAL_SECONDS
        );
    }

    #[test]
    fn previews_reject_unsafe_or_unknown_parameters() {
        assert!(
            validate_parameters(
                BulkJobKind::ActivationCodeRevoke,
                &json!({"unexpected": true})
            )
            .is_err()
        );
        assert!(
            validate_parameters(BulkJobKind::DeviceSetState, &json!({"state": "active"})).is_err()
        );
    }

    #[test]
    fn risky_jobs_are_explicit() {
        assert!(BulkJobKind::DeviceSetState.is_high_risk());
        assert!(!BulkJobKind::ActivationCodeRevoke.is_high_risk());
    }

    #[tokio::test]
    async fn worker_followup_is_canceled_when_shutdown_arrives() {
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let operation = async move {
            let _ = started_tx.send(());
            std::future::pending::<()>().await;
        };
        let signal = tokio::spawn(async move {
            started_rx.await.expect("worker followup starts");
            shutdown_tx.send(true).expect("request worker shutdown");
        });

        assert!(
            complete_before_shutdown(&mut shutdown_rx, operation)
                .await
                .is_none()
        );
        signal.await.expect("shutdown signal task");
    }

    #[tokio::test]
    async fn worker_followup_completes_without_shutdown() {
        let (_shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
        assert_eq!(
            complete_before_shutdown(&mut shutdown_rx, async { 7 }).await,
            Some(7)
        );
    }

    #[test]
    fn worker_role_checks_preserve_parameter_specific_permissions() {
        assert_eq!(
            authorized_roles(
                BulkJobKind::AccountSetState,
                &json!({"state": "denylisted"}),
            )
            .expect("denylist roles"),
            ["platform_owner", "security_admin"]
        );
        assert_eq!(
            authorized_roles(BulkJobKind::AccountSetState, &json!({"state": "active"}),)
                .expect("account writer roles"),
            ["platform_owner", "licensing_admin"]
        );
        assert_eq!(
            authorized_roles(BulkJobKind::DeviceSetState, &json!({"state": "removed"}),)
                .expect("device removal roles"),
            ["platform_owner", "licensing_admin"]
        );
        assert_eq!(
            authorized_roles(BulkJobKind::DeviceSetState, &json!({"state": "revoked"}),)
                .expect("device security roles"),
            ["platform_owner", "security_admin"]
        );
    }
}
