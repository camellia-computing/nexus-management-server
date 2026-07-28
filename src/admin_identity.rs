use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{Postgres, Row, Transaction};
use zeroize::Zeroizing;

use crate::{
    admin_app::{AdminAppError, AdminApplication, AdminPrincipal, MutationContext},
    admin_auth::{
        AdminAuthError, AdminAuthResult, AdminKeyring, AdminRole, AdminUser,
        insert_enrollment_token, normalize_username, validate_display_name,
    },
    admin_operation,
    crypto::{random_id, random_secret, sha256_hex},
    domain::AuditEventRecord,
    error::ApiError,
    store::PostgresRepository,
};

const ENROLLMENT_TTL_SECONDS: i64 = 10 * 60;
const IDENTITY_OPERATION_COMMAND_CREATE: &str = "admin.identity.create";
const IDENTITY_OPERATION_COMMAND_UPDATE: &str = "admin.identity.update";
const IDENTITY_OPERATION_COMMAND_DISABLE: &str = "admin.identity.disable";
const IDENTITY_OPERATION_COMMAND_RESET: &str = "admin.identity.reset";

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminUserPage {
    pub items: Vec<AdminUser>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminEnrollmentDelivery {
    pub id: String,
    pub claim_token: String,
    pub expires_at: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminEnrollmentProvisioning {
    pub user: AdminUser,
    pub delivery: AdminEnrollmentDelivery,
    pub acknowledgement_required: bool,
}

#[derive(Debug, Clone)]
pub struct NewAdminUser {
    pub username: String,
    pub display_name: String,
    pub roles: BTreeSet<AdminRole>,
}

#[derive(Debug, Clone)]
pub struct UpdateAdminUser {
    pub display_name: Option<String>,
    pub roles: Option<BTreeSet<AdminRole>>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct IdentityOperationResponse {
    user: AdminUser,
    delivery_id: Option<String>,
    delivery_expires_at: Option<i64>,
    secret_key_id: Option<String>,
}

#[derive(Clone)]
pub struct AdminIdentityService {
    repository: PostgresRepository,
    application: AdminApplication,
    keyring: Arc<AdminKeyring>,
}

impl AdminIdentityService {
    pub fn new(application: AdminApplication, keyring: Arc<AdminKeyring>) -> Self {
        Self {
            repository: application.repository().clone(),
            application,
            keyring,
        }
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

    pub async fn admin_users(
        &self,
        cursor: Option<&str>,
        query: Option<&str>,
        page_size: u32,
    ) -> AdminAuthResult<AdminUserPage> {
        if !(1..=100).contains(&page_size) {
            return Err(AdminAuthError::Validation(
                "page size must be between 1 and 100".to_owned(),
            ));
        }
        let cursor = cursor.map(normalize_username).transpose()?;
        let query = query
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| {
                if value.chars().count() > 128 {
                    Err(AdminAuthError::Validation(
                        "query must not exceed 128 characters".to_owned(),
                    ))
                } else {
                    Ok(format!("%{}%", value.to_ascii_lowercase()))
                }
            })
            .transpose()?;
        let rows = sqlx::query(
            "SELECT u.id, u.username, u.display_name, u.status, u.row_version,
                    coalesce(array_agg(r.role ORDER BY r.role)
                        FILTER (WHERE r.role IS NOT NULL), ARRAY[]::text[]) AS roles
             FROM admin_users u
             LEFT JOIN admin_role_bindings r ON r.user_id = u.id
             WHERE ($1::text IS NULL OR u.username > $1)
               AND ($2::text IS NULL OR lower(u.username) LIKE $2
                    OR lower(u.display_name) LIKE $2)
             GROUP BY u.id
             ORDER BY u.username
             LIMIT $3",
        )
        .bind(cursor)
        .bind(query)
        .bind(i64::from(page_size) + 1)
        .fetch_all(&self.repository.pool)
        .await
        .map_err(|_| ApiError::Database)?;
        let has_more = rows.len() > page_size as usize;
        let mut items = rows
            .into_iter()
            .take(page_size as usize)
            .map(admin_user_from_row)
            .collect::<AdminAuthResult<Vec<_>>>()?;
        let next_cursor = has_more
            .then(|| items.last().map(|user| user.username.clone()))
            .flatten();
        Ok(AdminUserPage {
            items: std::mem::take(&mut items),
            next_cursor,
        })
    }

    pub async fn create_admin_user(
        &self,
        request: NewAdminUser,
        context: &MutationContext,
    ) -> AdminAuthResult<AdminEnrollmentProvisioning> {
        let username = normalize_username(&request.username)?;
        validate_display_name(&request.display_name)?;
        validate_roles(&request.roles)?;
        let operation_id = admin_operation::operation_id(context)?;
        identity_session_id(context)?;
        let roles = request
            .roles
            .iter()
            .map(|role| role.as_str())
            .collect::<Vec<_>>();
        let request_hash = admin_operation::request_hash(&json!({
            "username": username,
            "displayName": request.display_name.trim(),
            "roles": roles,
        }))?;
        let now = self.trusted_now().await?;
        let mut tx = self
            .repository
            .pool
            .begin()
            .await
            .map_err(|_| ApiError::Database)?;
        lock_identity_mutations(&mut tx).await?;
        if let Some(response) = admin_operation::claim::<IdentityOperationResponse>(
            &mut tx,
            IDENTITY_OPERATION_COMMAND_CREATE,
            &request_hash,
            context,
        )
        .await?
        {
            tx.commit().await.map_err(|_| ApiError::Database)?;
            return self.provisioning_from_operation(response, operation_id, context);
        }
        let duplicate: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM admin_users WHERE username = $1)")
                .bind(&username)
                .fetch_one(&mut *tx)
                .await
                .map_err(|_| ApiError::Database)?;
        if duplicate {
            return Err(AdminAuthError::Conflict);
        }
        let user_id = random_id("admin");
        sqlx::query(
            "INSERT INTO admin_users
             (id, username, display_name, status, created_at, updated_at)
             VALUES ($1, $2, $3, 'pending', $4, $4)",
        )
        .bind(&user_id)
        .bind(&username)
        .bind(request.display_name.trim())
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        replace_roles(&mut tx, &user_id, &request.roles, context, now).await?;
        let secret_key_id = self.keyring.active_key_id().to_owned();
        let enrollment_token = Zeroizing::new(self.identity_secret(
            &secret_key_id,
            b"admin-enrollment-token",
            operation_id,
            context,
        )?);
        insert_enrollment_token(
            &mut tx,
            &sha256_hex(&enrollment_token),
            &user_id,
            "enroll",
            &context.principal.id,
            &context.reason,
            now,
        )
        .await?;
        let delivery = self
            .insert_identity_delivery(
                &mut tx,
                operation_id,
                context,
                &secret_key_id,
                &enrollment_token,
                now,
            )
            .await?;
        let user = admin_user_in_tx(&mut tx, &user_id).await?;
        insert_identity_audit(&mut tx, context, "admin_user_created", &user_id, now).await?;
        let response = IdentityOperationResponse {
            user: user.clone(),
            delivery_id: Some(delivery.id.clone()),
            delivery_expires_at: Some(delivery.expires_at),
            secret_key_id: Some(secret_key_id),
        };
        admin_operation::finish(&mut tx, &response, context).await?;
        tx.commit().await.map_err(|_| ApiError::Database)?;
        Ok(AdminEnrollmentProvisioning {
            user,
            delivery,
            acknowledgement_required: true,
        })
    }

    pub async fn recover_owner_offline(
        &self,
        username: &str,
        actor: &str,
        reason: &str,
        confirmation: &str,
    ) -> AdminAuthResult<String> {
        let username = normalize_username(username)?;
        if confirmation != username {
            return Err(AdminAuthError::Validation(
                "confirmation must exactly match the normalized username".to_owned(),
            ));
        }
        let context = MutationContext::new(AdminPrincipal::cli(actor)?, reason)?;
        let now = self.trusted_now().await?;
        let token = Zeroizing::new(random_secret());
        let mut tx = self
            .repository
            .pool
            .begin()
            .await
            .map_err(|_| ApiError::Database)?;
        lock_identity_mutations(&mut tx).await?;
        let row = sqlx::query(
            "SELECT u.id, u.status,
                    EXISTS (
                        SELECT 1 FROM admin_role_bindings r
                        WHERE r.user_id = u.id AND r.role = 'platform_owner'
                    ) AS is_owner,
                    EXISTS (
                        SELECT 1 FROM admin_password_credentials p WHERE p.user_id = u.id
                    ) AS has_password,
                    EXISTS (
                        SELECT 1 FROM admin_totp_credentials t WHERE t.user_id = u.id
                    ) AS has_totp
             FROM admin_users u WHERE u.username = $1 FOR UPDATE",
        )
        .bind(&username)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?
        .ok_or(AdminAuthError::NotFound)?;
        let user_id: String = row.try_get("id").map_err(|_| ApiError::Database)?;
        let status = row
            .try_get::<String, _>("status")
            .map_err(|_| ApiError::Database)?;
        let is_owner: bool = row.try_get("is_owner").map_err(|_| ApiError::Database)?;
        let has_password: bool = row
            .try_get("has_password")
            .map_err(|_| ApiError::Database)?;
        let has_totp: bool = row.try_get("has_totp").map_err(|_| ApiError::Database)?;
        let recoverable = status == "active" || (status == "pending" && !has_password && !has_totp);
        if !is_owner || !recoverable {
            return Err(AdminAuthError::PermissionDenied);
        }
        revoke_identity_material(&mut tx, &user_id, now, true).await?;
        sqlx::query(
            "UPDATE admin_users SET status = 'pending', row_version = row_version + 1,
             updated_at = $2 WHERE id = $1",
        )
        .bind(&user_id)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        insert_enrollment_token(
            &mut tx,
            &sha256_hex(token.as_str()),
            &user_id,
            "reset",
            &context.principal.id,
            &context.reason,
            now,
        )
        .await?;
        insert_identity_audit(
            &mut tx,
            &context,
            "admin_owner_offline_recovery_started",
            &user_id,
            now,
        )
        .await?;
        tx.commit().await.map_err(|_| ApiError::Database)?;
        Ok(token.to_string())
    }

    pub async fn update_admin_user(
        &self,
        user_id: &str,
        request: UpdateAdminUser,
        expected_version: i64,
        context: &MutationContext,
    ) -> AdminAuthResult<AdminUser> {
        if request.display_name.is_none() && request.roles.is_none() {
            return Err(AdminAuthError::Validation(
                "at least one administrator field must be supplied".to_owned(),
            ));
        }
        if let Some(display_name) = &request.display_name {
            validate_display_name(display_name)?;
        }
        if let Some(roles) = &request.roles {
            validate_roles(roles)?;
            if user_id == context.principal.id {
                return Err(AdminAuthError::Validation(
                    "administrators cannot change their own roles".to_owned(),
                ));
            }
        }
        let roles = request
            .roles
            .as_ref()
            .map(|roles| roles.iter().map(|role| role.as_str()).collect::<Vec<_>>());
        let request_hash = admin_operation::request_hash(&json!({
            "userId": user_id,
            "expectedVersion": expected_version,
            "displayName": request.display_name.as_deref().map(str::trim),
            "roles": roles,
        }))?;
        let now = self.trusted_now().await?;
        let mut tx = self
            .repository
            .pool
            .begin()
            .await
            .map_err(|_| ApiError::Database)?;
        lock_identity_mutations(&mut tx).await?;
        if let Some(response) = admin_operation::claim::<IdentityOperationResponse>(
            &mut tx,
            IDENTITY_OPERATION_COMMAND_UPDATE,
            &request_hash,
            context,
        )
        .await?
        {
            tx.commit().await.map_err(|_| ApiError::Database)?;
            return Ok(response.user);
        }
        let current = admin_user_for_update(&mut tx, user_id).await?;
        if current.row_version != expected_version {
            return Err(AdminAuthError::VersionConflict);
        }
        if let Some(roles) = &request.roles {
            protect_last_owner(&mut tx, &current, roles).await?;
            if *roles != current.roles {
                replace_roles(&mut tx, user_id, roles, context, now).await?;
            }
        }
        let display_name = request
            .display_name
            .as_deref()
            .map(str::trim)
            .unwrap_or(&current.display_name);
        let changed = display_name != current.display_name
            || request
                .roles
                .as_ref()
                .is_some_and(|roles| *roles != current.roles);
        if changed {
            sqlx::query(
                "UPDATE admin_users SET display_name = $2, row_version = row_version + 1,
                 updated_at = $3 WHERE id = $1",
            )
            .bind(user_id)
            .bind(display_name)
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(|_| ApiError::Database)?;
        }
        let user = admin_user_in_tx(&mut tx, user_id).await?;
        insert_identity_audit(&mut tx, context, "admin_user_updated", user_id, now).await?;
        let response = IdentityOperationResponse::user_only(user.clone());
        admin_operation::finish(&mut tx, &response, context).await?;
        tx.commit().await.map_err(|_| ApiError::Database)?;
        Ok(user)
    }

    pub async fn disable_admin_user(
        &self,
        user_id: &str,
        expected_version: i64,
        context: &MutationContext,
    ) -> AdminAuthResult<AdminUser> {
        if user_id == context.principal.id {
            return Err(AdminAuthError::Validation(
                "administrators cannot disable their own identity".to_owned(),
            ));
        }
        let request_hash = admin_operation::request_hash(&json!({
            "userId": user_id,
            "expectedVersion": expected_version,
        }))?;
        let now = self.trusted_now().await?;
        let mut tx = self
            .repository
            .pool
            .begin()
            .await
            .map_err(|_| ApiError::Database)?;
        lock_identity_mutations(&mut tx).await?;
        if let Some(response) = admin_operation::claim::<IdentityOperationResponse>(
            &mut tx,
            IDENTITY_OPERATION_COMMAND_DISABLE,
            &request_hash,
            context,
        )
        .await?
        {
            tx.commit().await.map_err(|_| ApiError::Database)?;
            return Ok(response.user);
        }
        let current = admin_user_for_update(&mut tx, user_id).await?;
        if current.row_version != expected_version {
            return Err(AdminAuthError::VersionConflict);
        }
        protect_last_owner(&mut tx, &current, &BTreeSet::new()).await?;
        if current.status != "disabled" {
            sqlx::query(
                "UPDATE admin_users SET status = 'disabled', row_version = row_version + 1,
                 updated_at = $2 WHERE id = $1",
            )
            .bind(user_id)
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(|_| ApiError::Database)?;
        }
        revoke_identity_material(&mut tx, user_id, now, false).await?;
        let user = admin_user_in_tx(&mut tx, user_id).await?;
        insert_identity_audit(&mut tx, context, "admin_user_disabled", user_id, now).await?;
        let response = IdentityOperationResponse::user_only(user.clone());
        admin_operation::finish(&mut tx, &response, context).await?;
        tx.commit().await.map_err(|_| ApiError::Database)?;
        Ok(user)
    }

    pub async fn reset_admin_enrollment(
        &self,
        user_id: &str,
        expected_version: i64,
        context: &MutationContext,
    ) -> AdminAuthResult<AdminEnrollmentProvisioning> {
        if user_id == context.principal.id {
            return Err(AdminAuthError::Validation(
                "administrators cannot reset their own identity".to_owned(),
            ));
        }
        let operation_id = admin_operation::operation_id(context)?;
        identity_session_id(context)?;
        let request_hash = admin_operation::request_hash(&json!({
            "userId": user_id,
            "expectedVersion": expected_version,
        }))?;
        let now = self.trusted_now().await?;
        let mut tx = self
            .repository
            .pool
            .begin()
            .await
            .map_err(|_| ApiError::Database)?;
        lock_identity_mutations(&mut tx).await?;
        if let Some(response) = admin_operation::claim::<IdentityOperationResponse>(
            &mut tx,
            IDENTITY_OPERATION_COMMAND_RESET,
            &request_hash,
            context,
        )
        .await?
        {
            tx.commit().await.map_err(|_| ApiError::Database)?;
            return self.provisioning_from_operation(response, operation_id, context);
        }
        let current = admin_user_for_update(&mut tx, user_id).await?;
        if current.row_version != expected_version {
            return Err(AdminAuthError::VersionConflict);
        }
        protect_last_owner(&mut tx, &current, &BTreeSet::new()).await?;
        revoke_identity_material(&mut tx, user_id, now, true).await?;
        sqlx::query(
            "UPDATE admin_users SET status = 'pending', row_version = row_version + 1,
             updated_at = $2 WHERE id = $1",
        )
        .bind(user_id)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        let secret_key_id = self.keyring.active_key_id().to_owned();
        let enrollment_token = Zeroizing::new(self.identity_secret(
            &secret_key_id,
            b"admin-enrollment-token",
            operation_id,
            context,
        )?);
        insert_enrollment_token(
            &mut tx,
            &sha256_hex(&enrollment_token),
            user_id,
            "reset",
            &context.principal.id,
            &context.reason,
            now,
        )
        .await?;
        let delivery = self
            .insert_identity_delivery(
                &mut tx,
                operation_id,
                context,
                &secret_key_id,
                &enrollment_token,
                now,
            )
            .await?;
        let user = admin_user_in_tx(&mut tx, user_id).await?;
        insert_identity_audit(&mut tx, context, "admin_enrollment_reset", user_id, now).await?;
        let response = IdentityOperationResponse {
            user: user.clone(),
            delivery_id: Some(delivery.id.clone()),
            delivery_expires_at: Some(delivery.expires_at),
            secret_key_id: Some(secret_key_id),
        };
        admin_operation::finish(&mut tx, &response, context).await?;
        tx.commit().await.map_err(|_| ApiError::Database)?;
        Ok(AdminEnrollmentProvisioning {
            user,
            delivery,
            acknowledgement_required: true,
        })
    }

    fn provisioning_from_operation(
        &self,
        response: IdentityOperationResponse,
        operation_id: &str,
        context: &MutationContext,
    ) -> AdminAuthResult<AdminEnrollmentProvisioning> {
        let secret_key_id = response.secret_key_id.ok_or(AdminAuthError::Conflict)?;
        let id = response.delivery_id.ok_or(AdminAuthError::Conflict)?;
        let expires_at = response
            .delivery_expires_at
            .ok_or(AdminAuthError::Conflict)?;
        let claim_token = self.identity_secret(
            &secret_key_id,
            b"admin-delivery-claim",
            operation_id,
            context,
        )?;
        Ok(AdminEnrollmentProvisioning {
            user: response.user,
            delivery: AdminEnrollmentDelivery {
                id,
                claim_token,
                expires_at,
            },
            acknowledgement_required: true,
        })
    }

    fn identity_secret(
        &self,
        key_id: &str,
        label: &[u8],
        operation_id: &str,
        context: &MutationContext,
    ) -> AdminAuthResult<String> {
        self.keyring.deterministic_secret(
            key_id,
            label,
            &[
                operation_id,
                &context.principal.id,
                identity_session_id(context)?,
            ],
        )
    }

    async fn insert_identity_delivery(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        operation_id: &str,
        context: &MutationContext,
        secret_key_id: &str,
        enrollment_token: &str,
        now: i64,
    ) -> AdminAuthResult<AdminEnrollmentDelivery> {
        let id = random_id("delivery");
        let claim_token = self.identity_secret(
            secret_key_id,
            b"admin-delivery-claim",
            operation_id,
            context,
        )?;
        let plaintext = Zeroizing::new(
            serde_json::to_vec(&json!({"enrollmentToken": enrollment_token}))
                .map_err(|_| ApiError::Internal)?,
        );
        let (key_id, nonce, ciphertext) =
            self.keyring
                .seal(b"code-delivery", id.as_bytes(), plaintext.as_ref())?;
        let expires_at = now.saturating_add(ENROLLMENT_TTL_SECONDS);
        sqlx::query(
            "INSERT INTO admin_secret_deliveries
             (id, actor_id, session_id, purpose, key_id, nonce, ciphertext,
              claim_token_hash, expires_at, created_at)
             VALUES ($1, $2, $3, 'admin_enrollment', $4, $5, $6, $7, $8, $9)",
        )
        .bind(&id)
        .bind(&context.principal.id)
        .bind(identity_session_id(context)?)
        .bind(key_id)
        .bind(nonce)
        .bind(ciphertext)
        .bind(sha256_hex(&claim_token))
        .bind(expires_at)
        .bind(now)
        .execute(&mut **tx)
        .await
        .map_err(|_| ApiError::Database)?;
        Ok(AdminEnrollmentDelivery {
            id,
            claim_token,
            expires_at,
        })
    }
}

impl IdentityOperationResponse {
    fn user_only(user: AdminUser) -> Self {
        Self {
            user,
            delivery_id: None,
            delivery_expires_at: None,
            secret_key_id: None,
        }
    }
}

fn validate_roles(roles: &BTreeSet<AdminRole>) -> AdminAuthResult<()> {
    if roles.is_empty() {
        Err(AdminAuthError::Validation(
            "at least one administrator role is required".to_owned(),
        ))
    } else {
        Ok(())
    }
}

fn identity_session_id(context: &MutationContext) -> AdminAuthResult<&str> {
    context
        .principal
        .session_id
        .as_deref()
        .filter(|value| !value.is_empty())
        .ok_or(AdminAuthError::PermissionDenied)
}

async fn lock_identity_mutations(tx: &mut Transaction<'_, Postgres>) -> AdminAuthResult<()> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext('camellia_admin_identity'))")
        .execute(&mut **tx)
        .await
        .map_err(|_| ApiError::Database)?;
    Ok(())
}

fn admin_user_from_row(row: sqlx::postgres::PgRow) -> AdminAuthResult<AdminUser> {
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

async fn admin_user_in_tx(
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
    admin_user_from_row(row)
}

async fn admin_user_for_update(
    tx: &mut Transaction<'_, Postgres>,
    user_id: &str,
) -> AdminAuthResult<AdminUser> {
    sqlx::query("SELECT id FROM admin_users WHERE id = $1 FOR UPDATE")
        .bind(user_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| ApiError::Database)?
        .ok_or(AdminAuthError::NotFound)?;
    admin_user_in_tx(tx, user_id).await
}

async fn replace_roles(
    tx: &mut Transaction<'_, Postgres>,
    user_id: &str,
    roles: &BTreeSet<AdminRole>,
    context: &MutationContext,
    now: i64,
) -> AdminAuthResult<()> {
    sqlx::query("DELETE FROM admin_role_bindings WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut **tx)
        .await
        .map_err(|_| ApiError::Database)?;
    for role in roles {
        sqlx::query(
            "INSERT INTO admin_role_bindings
             (user_id, role, granted_by, reason, created_at)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(user_id)
        .bind(role.as_str())
        .bind(&context.principal.id)
        .bind(&context.reason)
        .bind(now)
        .execute(&mut **tx)
        .await
        .map_err(|_| ApiError::Database)?;
    }
    Ok(())
}

async fn protect_last_owner(
    tx: &mut Transaction<'_, Postgres>,
    current: &AdminUser,
    replacement_roles: &BTreeSet<AdminRole>,
) -> AdminAuthResult<()> {
    if current.status != "active"
        || !current.roles.contains(&AdminRole::PlatformOwner)
        || replacement_roles.contains(&AdminRole::PlatformOwner)
    {
        return Ok(());
    }
    let other_active_owners: i64 = sqlx::query_scalar(
        "SELECT count(*)
         FROM admin_users u
         JOIN admin_role_bindings r ON r.user_id = u.id
         WHERE u.status = 'active' AND r.role = 'platform_owner' AND u.id <> $1",
    )
    .bind(&current.id)
    .fetch_one(&mut **tx)
    .await
    .map_err(|_| ApiError::Database)?;
    if other_active_owners == 0 {
        Err(AdminAuthError::Validation(
            "the last active Platform Owner cannot be removed, disabled, or reset".to_owned(),
        ))
    } else {
        Ok(())
    }
}

async fn revoke_identity_material(
    tx: &mut Transaction<'_, Postgres>,
    user_id: &str,
    now: i64,
    clear_credentials: bool,
) -> AdminAuthResult<()> {
    sqlx::query(
        "UPDATE admin_sessions SET revoked_at = $2
         WHERE user_id = $1 AND revoked_at IS NULL",
    )
    .bind(user_id)
    .bind(now)
    .execute(&mut **tx)
    .await
    .map_err(|_| ApiError::Database)?;
    sqlx::query(
        "DELETE FROM admin_enrollment_states s
         USING admin_enrollment_tokens t
         WHERE s.token_hash = t.token_hash AND t.user_id = $1",
    )
    .bind(user_id)
    .execute(&mut **tx)
    .await
    .map_err(|_| ApiError::Database)?;
    sqlx::query(
        "UPDATE admin_enrollment_tokens SET consumed_at = $2
         WHERE user_id = $1 AND consumed_at IS NULL",
    )
    .bind(user_id)
    .bind(now)
    .execute(&mut **tx)
    .await
    .map_err(|_| ApiError::Database)?;
    if clear_credentials {
        sqlx::query("DELETE FROM admin_password_credentials WHERE user_id = $1")
            .bind(user_id)
            .execute(&mut **tx)
            .await
            .map_err(|_| ApiError::Database)?;
        sqlx::query("DELETE FROM admin_totp_credentials WHERE user_id = $1")
            .bind(user_id)
            .execute(&mut **tx)
            .await
            .map_err(|_| ApiError::Database)?;
        sqlx::query("DELETE FROM admin_recovery_codes WHERE user_id = $1")
            .bind(user_id)
            .execute(&mut **tx)
            .await
            .map_err(|_| ApiError::Database)?;
    }
    Ok(())
}

async fn insert_identity_audit(
    tx: &mut Transaction<'_, Postgres>,
    context: &MutationContext,
    event_type: &str,
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
        reason_code: Some("admin_identity".to_owned()),
        metadata,
    };
    sqlx::query(
        "INSERT INTO audit_events
         (id, event_type, outcome, occurred_at, reason_code, metadata, document,
          actor_type, actor_id, admin_session_id, request_id, source_ip, user_agent_hash,
          target_type, target_id, operation_id)
         VALUES ($1, $2, 'succeeded', $3, 'admin_identity', $4, $5,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn administrator_roles_cannot_be_empty() {
        assert!(validate_roles(&BTreeSet::new()).is_err());
        assert!(validate_roles(&BTreeSet::from([AdminRole::Auditor])).is_ok());
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn administrator_creation_is_atomic_and_retry_safe() {
        let database_url = std::env::var("TEST_DATABASE_URL")
            .expect("TEST_DATABASE_URL is required for the PostgreSQL integration test");
        let repository =
            PostgresRepository::connect(&database_url, 2, std::time::Duration::from_secs(5))
                .await
                .expect("connect PostgreSQL");
        repository.migrate().await.expect("run migrations");
        let application = AdminApplication::new(repository.clone(), 24 * 60 * 60);
        let keyring = Arc::new(AdminKeyring::ephemeral());
        let service = AdminIdentityService::new(application.clone(), keyring);
        let now = application.trusted_now().await.unwrap();
        let suffix = random_id("identity_test");
        let actor_id = format!("admin_actor_{suffix}");
        let session_id = format!("admin_session_{suffix}");
        let operation_id = format!("identity-create-{suffix}");
        sqlx::query(
            "INSERT INTO admin_users
             (id, username, display_name, status, created_at, updated_at)
             VALUES ($1, $2, 'Identity test owner', 'active', $3, $3)",
        )
        .bind(&actor_id)
        .bind(format!("owner-{suffix}"))
        .bind(now)
        .execute(&repository.pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO admin_role_bindings
             (user_id, role, granted_by, reason, created_at)
             VALUES ($1, 'platform_owner', 'test', 'identity lifecycle test', $2)",
        )
        .bind(&actor_id)
        .bind(now)
        .execute(&repository.pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO admin_sessions
             (id, user_id, token_hash, csrf_hash, auth_time, elevated_until,
              last_seen_at, expires_at, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $5, $7, $5)",
        )
        .bind(&session_id)
        .bind(&actor_id)
        .bind(sha256_hex(&format!("token-{suffix}")))
        .bind(sha256_hex(&format!("csrf-{suffix}")))
        .bind(now)
        .bind(now + 600)
        .bind(now + 3600)
        .execute(&repository.pool)
        .await
        .unwrap();
        let mut context = MutationContext::new(
            crate::admin_app::AdminPrincipal {
                id: actor_id.clone(),
                session_id: Some(session_id),
                source_ip: Some("127.0.0.1".to_owned()),
                user_agent_hash: Some(sha256_hex("integration-test")),
                request_id: None,
            },
            "provision test security administrator",
        )
        .unwrap();
        context.operation_id = Some(operation_id.clone());
        let request = NewAdminUser {
            username: format!("security-{suffix}"),
            display_name: "Security administrator".to_owned(),
            roles: BTreeSet::from([AdminRole::SecurityAdmin]),
        };
        let first = service
            .create_admin_user(request.clone(), &context)
            .await
            .unwrap();
        let retry = service.create_admin_user(request, &context).await.unwrap();
        assert_eq!(first.user.id, retry.user.id);
        assert_eq!(first.delivery.id, retry.delivery.id);
        assert_eq!(first.delivery.claim_token, retry.delivery.claim_token);
        let users: i64 = sqlx::query_scalar("SELECT count(*) FROM admin_users WHERE id = $1")
            .bind(&first.user.id)
            .fetch_one(&repository.pool)
            .await
            .unwrap();
        let audits: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM audit_events
             WHERE event_type = 'admin_user_created' AND operation_id = $1",
        )
        .bind(&operation_id)
        .fetch_one(&repository.pool)
        .await
        .unwrap();
        assert_eq!(users, 1);
        assert_eq!(audits, 1);

        sqlx::query("DELETE FROM audit_events WHERE operation_id = $1")
            .bind(&operation_id)
            .execute(&repository.pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM admin_operations WHERE operation_id = $1")
            .bind(&operation_id)
            .execute(&repository.pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM admin_users WHERE id = ANY($1)")
            .bind(vec![first.user.id, actor_id])
            .execute(&repository.pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn offline_owner_recovery_requires_exact_confirmation_and_clears_factors() {
        let database_url = std::env::var("TEST_DATABASE_URL")
            .expect("TEST_DATABASE_URL is required for the PostgreSQL integration test");
        let repository =
            PostgresRepository::connect(&database_url, 2, std::time::Duration::from_secs(5))
                .await
                .expect("connect PostgreSQL");
        repository.migrate().await.expect("run migrations");
        let application = AdminApplication::new(repository.clone(), 24 * 60 * 60);
        let keyring = Arc::new(AdminKeyring::ephemeral());
        let key_id = keyring.active_key_id().to_owned();
        let service = AdminIdentityService::new(application.clone(), keyring);
        let now = application.trusted_now().await.unwrap();
        let suffix = random_id("owner_recovery_test");
        let user_id = format!("admin_{suffix}");
        let username = format!("owner-{suffix}");
        let session_id = format!("session_{suffix}");
        let mut tx = repository.pool.begin().await.unwrap();
        sqlx::query(
            "INSERT INTO admin_users
             (id, username, display_name, status, created_at, updated_at)
             VALUES ($1, $2, 'Offline recovery owner', 'active', $3, $3)",
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
             VALUES ($1, 'platform_owner', 'test', 'offline recovery test', $2)",
        )
        .bind(&user_id)
        .bind(now)
        .execute(&mut *tx)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO admin_password_credentials
             (user_id, password_hash, key_id, changed_at)
             VALUES ($1, 'test-password-hash', $2, $3)",
        )
        .bind(&user_id)
        .bind(key_id)
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

        assert!(matches!(
            service
                .recover_owner_offline(
                    &username,
                    "offline-operator",
                    "restore control-plane access",
                    "wrong-owner",
                )
                .await,
            Err(AdminAuthError::Validation(_))
        ));
        assert!(matches!(
            service
                .recover_owner_offline(
                    &username,
                    "offline-operator",
                    "restore control-plane access",
                    &format!(" {username}"),
                )
                .await,
            Err(AdminAuthError::Validation(_))
        ));
        let first_token = service
            .recover_owner_offline(
                &username,
                "offline-operator",
                "restore control-plane access",
                &username,
            )
            .await
            .unwrap();
        let replacement_token = service
            .recover_owner_offline(
                &username,
                "offline-operator",
                "replace an undelivered recovery token",
                &username,
            )
            .await
            .unwrap();
        assert_ne!(first_token, replacement_token);
        let row = sqlx::query(
            "SELECT u.status, u.row_version,
                    EXISTS (SELECT 1 FROM admin_role_bindings r
                            WHERE r.user_id = u.id AND r.role = 'platform_owner') AS is_owner,
                    EXISTS (SELECT 1 FROM admin_password_credentials p
                            WHERE p.user_id = u.id) AS has_password,
                    EXISTS (SELECT 1 FROM admin_sessions s
                            WHERE s.user_id = u.id AND s.revoked_at IS NULL) AS has_session,
                    EXISTS (SELECT 1 FROM admin_enrollment_tokens t
                            WHERE t.user_id = u.id AND t.token_hash = $2
                              AND t.purpose = 'reset' AND t.expires_at = t.created_at + 600
                              AND t.consumed_at IS NOT NULL) AS replaced_token_consumed,
                    EXISTS (SELECT 1 FROM admin_enrollment_tokens t
                            WHERE t.user_id = u.id AND t.token_hash = $3
                              AND t.purpose = 'reset' AND t.expires_at = t.created_at + 600
                              AND t.consumed_at IS NULL) AS has_reset_token
             FROM admin_users u WHERE u.id = $1",
        )
        .bind(&user_id)
        .bind(sha256_hex(&first_token))
        .bind(sha256_hex(&replacement_token))
        .fetch_one(&repository.pool)
        .await
        .unwrap();
        assert_eq!(row.try_get::<String, _>("status").unwrap(), "pending");
        assert_eq!(row.try_get::<i64, _>("row_version").unwrap(), 3);
        assert!(row.try_get::<bool, _>("is_owner").unwrap());
        assert!(!row.try_get::<bool, _>("has_password").unwrap());
        assert!(!row.try_get::<bool, _>("has_session").unwrap());
        assert!(row.try_get::<bool, _>("replaced_token_consumed").unwrap());
        assert!(row.try_get::<bool, _>("has_reset_token").unwrap());
        let audit: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM audit_events
             WHERE event_type = 'admin_owner_offline_recovery_started'
               AND target_id = $1 AND actor_id = 'offline-operator'",
        )
        .bind(&user_id)
        .fetch_one(&repository.pool)
        .await
        .unwrap();
        assert_eq!(audit, 2);

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
