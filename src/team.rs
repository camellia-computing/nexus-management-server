use std::{collections::BTreeMap, sync::Arc};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Row, Transaction, postgres::PgRow};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::{
    contracts::Plan,
    crypto::{random_id, random_secret, sha256_hex},
    domain::AuditEventRecord,
    error::{ApiError, Result},
    plan_catalog::effective_policy,
    store::PostgresRepository,
    workspace::WorkspaceKeyring,
};

const INVITATION_TTL_SECONDS: i64 = 7 * 24 * 60 * 60;
const DEVICE_ENROLLMENT_TTL_SECONDS: i64 = 15 * 60;
const MAX_DEVICES_PER_MEMBER: i64 = 3;
const DEFAULT_MEMBER_PAGE_SIZE: u32 = 100;
const MAX_MEMBER_PAGE_SIZE: u32 = 200;
const MAX_TEAM_OPERATION_RESPONSE_PLAINTEXT_BYTES: usize = 128 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceRole {
    Owner,
    Admin,
    Billing,
    Operator,
    Viewer,
    Auditor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceMemberStatus {
    Invited,
    Active,
    Suspended,
    Removed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceMember {
    pub id: String,
    pub email: String,
    pub display_name: String,
    pub role: WorkspaceRole,
    pub status: WorkspaceMemberStatus,
    pub bound_device_count: u32,
    pub row_version: u64,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TeamProfile {
    pub enabled: bool,
    pub member: Option<WorkspaceMember>,
    pub permissions: Vec<String>,
    pub member_limit: u32,
    pub member_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TeamMemberPageRequest {
    pub cursor: Option<String>,
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TeamMemberPage {
    pub members: Vec<WorkspaceMember>,
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TeamMemberCursor {
    created_at: i64,
    member_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateTeamInvitation {
    pub operation_id: String,
    pub email: String,
    pub display_name: String,
    pub role: WorkspaceRole,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TeamInvitation {
    pub id: String,
    pub member: WorkspaceMember,
    pub invitation_token: String,
    pub expires_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AcceptTeamInvitation {
    pub operation_id: String,
    pub invitation_token: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateWorkspaceMember {
    pub operation_id: String,
    pub role: WorkspaceRole,
    pub status: WorkspaceMemberStatus,
    pub row_version: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemberDeviceEnrollment {
    pub id: String,
    pub member_id: String,
    pub enrollment_token: String,
    pub expires_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AcceptMemberDeviceEnrollment {
    pub operation_id: String,
    pub enrollment_token: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TeamOperationRequest {
    pub operation_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TeamOperationStatusResponse {
    pub committed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransferWorkspaceOwnership {
    pub operation_id: String,
    pub new_owner_member_id: String,
    pub owner_row_version: u64,
    pub new_owner_row_version: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LeaveWorkspace {
    pub operation_id: String,
    pub member_id: String,
    pub row_version: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OwnershipTransferResult {
    pub previous_owner: WorkspaceMember,
    pub new_owner: WorkspaceMember,
}

#[async_trait]
pub trait TeamRepository: Send + Sync + 'static {
    async fn profile(&self, account_id: &str, device_id: &str, now: i64) -> Result<TeamProfile>;
    async fn can_read_billing(&self, account_id: &str, device_id: &str) -> Result<bool>;
    async fn can_manage_billing(&self, account_id: &str, device_id: &str) -> Result<bool>;
    async fn members(
        &self,
        account_id: &str,
        device_id: &str,
        request: TeamMemberPageRequest,
    ) -> Result<TeamMemberPage>;
    async fn create_invitation(
        &self,
        account_id: &str,
        device_id: &str,
        requester_session_hash: &str,
        request: CreateTeamInvitation,
        now: i64,
    ) -> Result<TeamInvitation>;
    async fn accept_invitation(
        &self,
        account_id: &str,
        device_id: &str,
        requester_session_hash: &str,
        request: AcceptTeamInvitation,
        now: i64,
    ) -> Result<TeamProfile>;
    async fn update_member(
        &self,
        account_id: &str,
        device_id: &str,
        requester_session_hash: &str,
        member_id: &str,
        request: UpdateWorkspaceMember,
        now: i64,
    ) -> Result<WorkspaceMember>;
    async fn create_device_enrollment(
        &self,
        account_id: &str,
        device_id: &str,
        requester_session_hash: &str,
        request: TeamOperationRequest,
        now: i64,
    ) -> Result<MemberDeviceEnrollment>;
    async fn create_member_device_enrollment(
        &self,
        account_id: &str,
        device_id: &str,
        requester_session_hash: &str,
        member_id: &str,
        request: TeamOperationRequest,
        now: i64,
    ) -> Result<MemberDeviceEnrollment>;
    async fn accept_device_enrollment(
        &self,
        account_id: &str,
        device_id: &str,
        requester_session_hash: &str,
        request: AcceptMemberDeviceEnrollment,
        now: i64,
    ) -> Result<TeamProfile>;
    async fn leave_workspace(
        &self,
        account_id: &str,
        device_id: &str,
        requester_session_hash: &str,
        request: LeaveWorkspace,
        now: i64,
    ) -> Result<()>;
    async fn transfer_ownership(
        &self,
        account_id: &str,
        device_id: &str,
        requester_session_hash: &str,
        request: TransferWorkspaceOwnership,
        now: i64,
    ) -> Result<(WorkspaceMember, WorkspaceMember)>;
    async fn operation_committed_for_device(
        &self,
        account_id: &str,
        device_id: &str,
        operation_id: &str,
    ) -> Result<bool>;
    async fn leave_operation_status(
        &self,
        account_id: &str,
        requester_session_hash: &str,
        requester_device_id: &str,
        operation_id: &str,
        member_id: &str,
        row_version: u64,
    ) -> Result<bool>;
}

#[derive(Clone)]
pub struct PostgresTeamRepository {
    pool: PgPool,
    keyring: Arc<WorkspaceKeyring>,
}

impl PostgresTeamRepository {
    pub fn new(repository: &PostgresRepository, keyring: impl Into<Arc<WorkspaceKeyring>>) -> Self {
        Self {
            pool: repository.pool.clone(),
            keyring: keyring.into(),
        }
    }
}

#[async_trait]
impl TeamRepository for PostgresTeamRepository {
    async fn profile(&self, account_id: &str, device_id: &str, now: i64) -> Result<TeamProfile> {
        let (plan, member_limit) = account_plan(&self.pool, account_id).await?;
        let member = member_for_device(&self.pool, account_id, device_id).await?;
        let member_count = occupied_member_count(&self.pool, account_id, now).await?;
        Ok(TeamProfile {
            enabled: plan == Plan::Team,
            permissions: member
                .as_ref()
                .filter(|member| member.status == WorkspaceMemberStatus::Active)
                .map(|member| permissions(member.role))
                .unwrap_or_default(),
            member,
            member_limit,
            member_count,
        })
    }

    async fn can_read_billing(&self, account_id: &str, device_id: &str) -> Result<bool> {
        billing_access(
            &self.pool,
            account_id,
            device_id,
            &[
                WorkspaceRole::Owner,
                WorkspaceRole::Admin,
                WorkspaceRole::Billing,
            ],
        )
        .await
    }

    async fn can_manage_billing(&self, account_id: &str, device_id: &str) -> Result<bool> {
        billing_access(
            &self.pool,
            account_id,
            device_id,
            &[WorkspaceRole::Owner, WorkspaceRole::Billing],
        )
        .await
    }

    async fn members(
        &self,
        account_id: &str,
        device_id: &str,
        request: TeamMemberPageRequest,
    ) -> Result<TeamMemberPage> {
        require_role(
            &self.pool,
            account_id,
            device_id,
            &[
                WorkspaceRole::Owner,
                WorkspaceRole::Admin,
                WorkspaceRole::Operator,
                WorkspaceRole::Viewer,
                WorkspaceRole::Auditor,
            ],
        )
        .await?;
        let limit = member_page_limit(request.limit)?;
        let cursor = request
            .cursor
            .as_deref()
            .map(decode_member_cursor)
            .transpose()?;
        let rows = sqlx::query(
            "SELECT members.id, members.email, members.display_name, members.role, members.status,
                    members.row_version, members.created_at, members.updated_at,
                    (SELECT COUNT(*) FROM device_member_bindings AS bindings
                     WHERE bindings.account_id = members.account_id
                       AND bindings.member_id = members.id) AS bound_device_count
             FROM workspace_members AS members WHERE members.account_id = $1
               AND ($2::BIGINT IS NULL OR (created_at, id) > ($2, $3))
             ORDER BY created_at, id LIMIT $4",
        )
        .bind(account_id)
        .bind(cursor.as_ref().map(|value| value.created_at))
        .bind(cursor.as_ref().map(|value| value.member_id.as_str()))
        .bind(i64::from(limit.saturating_add(1)))
        .fetch_all(&self.pool)
        .await
        .map_err(|_| ApiError::Database)?;
        let has_more = rows.len() > limit as usize;
        let members = rows
            .into_iter()
            .take(limit as usize)
            .map(row_member)
            .collect::<Result<Vec<_>>>()?;
        let next_cursor = if has_more {
            members
                .last()
                .map(|member| {
                    encode_member_cursor(&TeamMemberCursor {
                        created_at: member.created_at,
                        member_id: member.id.clone(),
                    })
                })
                .transpose()?
        } else {
            None
        };
        Ok(TeamMemberPage {
            members,
            next_cursor,
            has_more,
        })
    }

    async fn create_invitation(
        &self,
        account_id: &str,
        device_id: &str,
        requester_session_hash: &str,
        request: CreateTeamInvitation,
        now: i64,
    ) -> Result<TeamInvitation> {
        validate_team_operation_identity(&request.operation_id, requester_session_hash)?;
        if request.role == WorkspaceRole::Owner {
            return Err(ApiError::InvalidRequest);
        }
        let email = normalized_email(&request.email)?;
        let display_name = bounded(&request.display_name, 160)?;
        let operation_id = request.operation_id;
        let request_hash = team_operation_request_hash(
            "create_invitation",
            &[
                email.as_bytes(),
                display_name.as_bytes(),
                role_name(request.role).as_bytes(),
            ],
        );
        let mut tx = self.pool.begin().await.map_err(|_| ApiError::Database)?;
        let actor = require_role_tx(
            &mut tx,
            account_id,
            device_id,
            &[WorkspaceRole::Owner, WorkspaceRole::Admin],
            now,
        )
        .await?;
        if request.role == WorkspaceRole::Admin && actor.role != WorkspaceRole::Owner {
            return Err(ApiError::PermissionDenied);
        }
        if let Some(response) = claim_team_operation::<TeamInvitation>(
            &mut tx,
            self.keyring.as_ref(),
            account_id,
            device_id,
            &operation_id,
            "create_invitation",
            &request_hash,
        )
        .await?
        {
            tx.commit().await.map_err(|_| ApiError::Database)?;
            return Ok(response);
        }
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 7112026))")
            .bind(account_id)
            .execute(&mut *tx)
            .await
            .map_err(|_| ApiError::Database)?;
        let (plan, member_limit) = account_plan_tx(&mut tx, account_id).await?;
        if plan != Plan::Team {
            return Err(ApiError::PermissionDenied);
        }
        let existing_member: Option<(String, String, String, String)> = sqlx::query_as(
            "SELECT id, status, display_name, role FROM workspace_members
             WHERE account_id = $1 AND email = $2 FOR UPDATE",
        )
        .bind(account_id)
        .bind(&email)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        let existing_member_id = existing_member.as_ref().map(|(id, _, _, _)| id.as_str());
        let occupied_other: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM workspace_members AS members
             WHERE members.account_id = $1 AND (
               members.status IN ('active', 'suspended')
               OR (members.status = 'invited' AND EXISTS (
                 SELECT 1 FROM team_invitations AS invitations
                 WHERE invitations.member_id = members.id
                   AND invitations.accepted_at IS NULL
                   AND invitations.revoked_at IS NULL
                   AND invitations.expires_at > $2
               ))
             ) AND ($3::TEXT IS NULL OR members.id <> $3)",
        )
        .bind(account_id)
        .bind(now)
        .bind(existing_member_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        if occupied_other >= i64::from(member_limit) {
            return Err(ApiError::ActivationLimitReached);
        }
        let member_id = if let Some((member_id, status, _, _)) = existing_member {
            if status == "active" {
                return Err(ApiError::InvalidRequest);
            }
            if status == "suspended" {
                return Err(ApiError::InvalidRequest);
            }
            sqlx::query(
                "UPDATE team_invitations SET revoked_at = COALESCE(revoked_at, $2)
                 WHERE member_id = $1 AND revoked_at IS NULL",
            )
            .bind(&member_id)
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(|_| ApiError::Database)?;
            let affected = sqlx::query(
                "UPDATE workspace_members
                 SET display_name = $2, role = $3, status = 'invited',
                     row_version = row_version + 1, updated_at = $4
                 WHERE id = $1 AND status IN ('invited', 'removed')",
            )
            .bind(&member_id)
            .bind(&display_name)
            .bind(role_name(request.role))
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(|_| ApiError::Database)?
            .rows_affected();
            if affected != 1 {
                return Err(ApiError::InvalidRequest);
            }
            member_id
        } else {
            let member_id = random_id("member");
            sqlx::query(
                "INSERT INTO workspace_members
                    (id, account_id, email, display_name, role, status, row_version, created_at, updated_at)
                 VALUES ($1, $2, $3, $4, $5, 'invited', 1, $6, $6)",
            )
            .bind(&member_id)
            .bind(account_id)
            .bind(&email)
            .bind(&display_name)
            .bind(role_name(request.role))
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(|_| ApiError::InvalidRequest)?;
            member_id
        };
        let invitation_id = random_id("team_invite");
        let invitation_token = random_secret();
        let expires_at = now.saturating_add(INVITATION_TTL_SECONDS);
        sqlx::query(
            "INSERT INTO team_invitations
                (id, account_id, member_id, token_hash, invited_by_member_id,
                 expires_at, accepted_at, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(&invitation_id)
        .bind(account_id)
        .bind(&member_id)
        .bind(sha256_hex(&invitation_token))
        .bind(&actor.id)
        .bind(expires_at)
        .bind(Option::<i64>::None)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        insert_team_audit(
            &mut tx,
            "team_invitation_created",
            account_id,
            device_id,
            now,
            BTreeMap::from([
                ("member_id".into(), member_id.clone()),
                ("operation_id".into(), operation_id.clone()),
                ("role".into(), role_name(request.role).into()),
            ]),
        )
        .await?;
        let member = sqlx::query(
            "SELECT members.id, members.email, members.display_name, members.role, members.status,
                    members.row_version, members.created_at, members.updated_at,
                    (SELECT COUNT(*) FROM device_member_bindings AS bindings
                     WHERE bindings.account_id = members.account_id
                       AND bindings.member_id = members.id) AS bound_device_count
             FROM workspace_members AS members WHERE members.id = $1",
        )
        .bind(&member_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)
        .and_then(row_member)?;
        let response = TeamInvitation {
            id: invitation_id,
            member,
            invitation_token,
            expires_at,
        };
        finish_team_operation(
            &mut tx,
            self.keyring.as_ref(),
            account_id,
            device_id,
            requester_session_hash,
            &operation_id,
            "create_invitation",
            &request_hash,
            &response,
            now,
        )
        .await?;
        tx.commit().await.map_err(|_| ApiError::Database)?;
        Ok(response)
    }

    async fn accept_invitation(
        &self,
        account_id: &str,
        device_id: &str,
        requester_session_hash: &str,
        request: AcceptTeamInvitation,
        now: i64,
    ) -> Result<TeamProfile> {
        validate_team_operation_identity(&request.operation_id, requester_session_hash)?;
        let invitation_token = request.invitation_token.trim().to_owned();
        if invitation_token.len() < 32 || invitation_token.len() > 256 {
            return Err(ApiError::TeamInvitationInvalid);
        }
        let operation_id = request.operation_id;
        let token_hash = sha256_hex(&invitation_token);
        let request_hash =
            team_operation_request_hash("accept_invitation", &[token_hash.as_bytes()]);
        let mut tx = self.pool.begin().await.map_err(|_| ApiError::Database)?;
        if let Some(response) = claim_team_operation::<TeamProfile>(
            &mut tx,
            self.keyring.as_ref(),
            account_id,
            device_id,
            &operation_id,
            "accept_invitation",
            &request_hash,
        )
        .await?
        {
            tx.commit().await.map_err(|_| ApiError::Database)?;
            return Ok(response);
        }
        require_team_device_authority_tx(&mut tx, account_id, device_id, now).await?;
        let row = sqlx::query(
            "SELECT invitations.id AS invitation_id, members.id, members.email, members.display_name,
                    members.role, members.status, members.row_version, members.created_at,
                    members.updated_at, invitations.expires_at, invitations.accepted_at,
                    invitations.revoked_at,
                    (SELECT COUNT(*) FROM device_member_bindings AS bindings
                     WHERE bindings.account_id = members.account_id
                       AND bindings.member_id = members.id) AS bound_device_count
             FROM team_invitations AS invitations
             JOIN workspace_members AS members ON members.id = invitations.member_id
             WHERE invitations.account_id = $1 AND invitations.token_hash = $2
             FOR UPDATE OF invitations, members",
        )
        .bind(account_id)
        .bind(&token_hash)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        let Some(row) = row else {
            insert_team_audit_outcome(
                &mut tx,
                "team_invitation_accept_denied",
                "denied",
                account_id,
                device_id,
                Some("invitation_not_found"),
                now,
                BTreeMap::new(),
            )
            .await?;
            tx.commit().await.map_err(|_| ApiError::Database)?;
            return Err(ApiError::TeamInvitationInvalid);
        };
        let expires_at: i64 = row.try_get("expires_at").map_err(|_| ApiError::Database)?;
        let accepted_at: Option<i64> =
            row.try_get("accepted_at").map_err(|_| ApiError::Database)?;
        let revoked_at: Option<i64> = row.try_get("revoked_at").map_err(|_| ApiError::Database)?;
        let invitation_id: String = row
            .try_get("invitation_id")
            .map_err(|_| ApiError::Database)?;
        let member = row_member(row)?;
        if member.status == WorkspaceMemberStatus::Suspended {
            insert_team_audit_outcome(
                &mut tx,
                "team_invitation_accept_denied",
                "denied",
                account_id,
                device_id,
                Some("member_suspended"),
                now,
                BTreeMap::from([
                    ("invitation_id".into(), invitation_id.clone()),
                    ("member_id".into(), member.id.clone()),
                ]),
            )
            .await?;
            tx.commit().await.map_err(|_| ApiError::Database)?;
            return Err(ApiError::PermissionDenied);
        }
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 7142026))")
            .bind(device_id)
            .execute(&mut *tx)
            .await
            .map_err(|_| ApiError::Database)?;
        let existing_binding: Option<String> = sqlx::query_scalar(
            "SELECT member_id FROM device_member_bindings
             WHERE account_id = $1 AND device_id = $2 FOR UPDATE",
        )
        .bind(account_id)
        .bind(device_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        if accepted_at.is_some() && existing_binding.as_deref() == Some(member.id.as_str()) {
            let response = profile_tx(&mut tx, account_id, device_id, now).await?;
            finish_team_operation(
                &mut tx,
                self.keyring.as_ref(),
                account_id,
                device_id,
                requester_session_hash,
                &operation_id,
                "accept_invitation",
                &request_hash,
                &response,
                now,
            )
            .await?;
            tx.commit().await.map_err(|_| ApiError::Database)?;
            return Ok(response);
        }
        if expires_at <= now || revoked_at.is_some() {
            let reason = if revoked_at.is_some() {
                "invitation_revoked"
            } else {
                "invitation_expired"
            };
            insert_team_audit_outcome(
                &mut tx,
                "team_invitation_accept_denied",
                "denied",
                account_id,
                device_id,
                Some(reason),
                now,
                BTreeMap::from([("invitation_id".into(), invitation_id.clone())]),
            )
            .await?;
            tx.commit().await.map_err(|_| ApiError::Database)?;
            return Err(ApiError::TeamInvitationInvalid);
        }
        if existing_binding
            .as_deref()
            .is_some_and(|id| id != member.id)
        {
            insert_team_audit_outcome(
                &mut tx,
                "team_invitation_accept_denied",
                "denied",
                account_id,
                device_id,
                Some("device_bound_to_other_member"),
                now,
                BTreeMap::from([
                    ("invitation_id".into(), invitation_id.clone()),
                    ("member_id".into(), member.id.clone()),
                ]),
            )
            .await?;
            tx.commit().await.map_err(|_| ApiError::Database)?;
            return Err(ApiError::PermissionDenied);
        }
        if accepted_at.is_some() {
            insert_team_audit_outcome(
                &mut tx,
                "team_invitation_accept_denied",
                "denied",
                account_id,
                device_id,
                Some("invitation_already_consumed"),
                now,
                BTreeMap::from([
                    ("invitation_id".into(), invitation_id.clone()),
                    ("member_id".into(), member.id.clone()),
                ]),
            )
            .await?;
            tx.commit().await.map_err(|_| ApiError::Database)?;
            return Err(ApiError::TeamInvitationInvalid);
        }
        if member.status != WorkspaceMemberStatus::Invited {
            insert_team_audit_outcome(
                &mut tx,
                "team_invitation_accept_denied",
                "denied",
                account_id,
                device_id,
                Some("member_not_invited"),
                now,
                BTreeMap::from([
                    ("invitation_id".into(), invitation_id.clone()),
                    ("member_id".into(), member.id.clone()),
                ]),
            )
            .await?;
            tx.commit().await.map_err(|_| ApiError::Database)?;
            return Err(ApiError::TeamInvitationInvalid);
        }
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 7132026))")
            .bind(&member.id)
            .execute(&mut *tx)
            .await
            .map_err(|_| ApiError::Database)?;
        let bound_devices: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM device_member_bindings
             WHERE account_id = $1 AND member_id = $2",
        )
        .bind(account_id)
        .bind(&member.id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        if bound_devices >= MAX_DEVICES_PER_MEMBER {
            insert_team_audit_outcome(
                &mut tx,
                "team_invitation_accept_denied",
                "denied",
                account_id,
                device_id,
                Some("member_device_limit_reached"),
                now,
                BTreeMap::from([
                    ("invitation_id".into(), invitation_id.clone()),
                    ("member_id".into(), member.id.clone()),
                ]),
            )
            .await?;
            tx.commit().await.map_err(|_| ApiError::Database)?;
            return Err(ApiError::ActivationLimitReached);
        }
        sqlx::query(
            "INSERT INTO device_member_bindings (account_id, device_id, member_id, bound_at)
             VALUES ($1, $2, $3, $4)",
        )
        .bind(account_id)
        .bind(device_id)
        .bind(&member.id)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        sqlx::query(
            "UPDATE workspace_members
             SET status = 'active', row_version = row_version + 1, updated_at = $2
             WHERE id = $1 AND status = 'invited'",
        )
        .bind(&member.id)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        sqlx::query("UPDATE team_invitations SET accepted_at = $2 WHERE id = $1")
            .bind(invitation_id)
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(|_| ApiError::Database)?;
        insert_team_audit(
            &mut tx,
            "team_invitation_accepted",
            account_id,
            device_id,
            now,
            BTreeMap::from([
                ("member_id".into(), member.id),
                ("operation_id".into(), operation_id.clone()),
            ]),
        )
        .await?;
        let response = profile_tx(&mut tx, account_id, device_id, now).await?;
        finish_team_operation(
            &mut tx,
            self.keyring.as_ref(),
            account_id,
            device_id,
            requester_session_hash,
            &operation_id,
            "accept_invitation",
            &request_hash,
            &response,
            now,
        )
        .await?;
        tx.commit().await.map_err(|_| ApiError::Database)?;
        Ok(response)
    }

    async fn update_member(
        &self,
        account_id: &str,
        device_id: &str,
        requester_session_hash: &str,
        member_id: &str,
        request: UpdateWorkspaceMember,
        now: i64,
    ) -> Result<WorkspaceMember> {
        validate_team_operation_identity(&request.operation_id, requester_session_hash)?;
        if request.role == WorkspaceRole::Owner
            || request.status == WorkspaceMemberStatus::Invited
            || request.row_version == 0
        {
            return Err(ApiError::InvalidRequest);
        }
        let operation_id = request.operation_id;
        let request_hash = team_operation_request_hash(
            "update_member",
            &[
                member_id.as_bytes(),
                role_name(request.role).as_bytes(),
                member_status_name(request.status).as_bytes(),
                request.row_version.to_string().as_bytes(),
            ],
        );
        let mut tx = self.pool.begin().await.map_err(|_| ApiError::Database)?;
        let actor = require_role_tx(
            &mut tx,
            account_id,
            device_id,
            &[WorkspaceRole::Owner, WorkspaceRole::Admin],
            now,
        )
        .await?;
        if let Some(response) = claim_team_operation::<WorkspaceMember>(
            &mut tx,
            self.keyring.as_ref(),
            account_id,
            device_id,
            &operation_id,
            "update_member",
            &request_hash,
        )
        .await?
        {
            tx.commit().await.map_err(|_| ApiError::Database)?;
            return Ok(response);
        }
        let target_row = sqlx::query(
            "SELECT members.id, members.email, members.display_name, members.role, members.status,
                    members.row_version, members.created_at, members.updated_at,
                    (SELECT COUNT(*) FROM device_member_bindings AS bindings
                     WHERE bindings.account_id = members.account_id
                       AND bindings.member_id = members.id) AS bound_device_count
             FROM workspace_members AS members
             WHERE members.account_id = $1 AND members.id = $2 FOR UPDATE",
        )
        .bind(account_id)
        .bind(member_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?
        .ok_or(ApiError::InvalidRequest)?;
        let target = row_member(target_row)?;
        if !valid_member_update_transition(target.role, target.status, request.role, request.status)
            || target.role == WorkspaceRole::Owner
            || target.id == actor.id
            || (actor.role == WorkspaceRole::Admin && target.role == WorkspaceRole::Admin)
            || (request.role == WorkspaceRole::Admin && actor.role != WorkspaceRole::Owner)
        {
            return Err(ApiError::PermissionDenied);
        }
        let affected = sqlx::query(
            "UPDATE workspace_members
             SET role = $3, status = $4, row_version = row_version + 1, updated_at = $5
             WHERE account_id = $1 AND id = $2 AND row_version = $6",
        )
        .bind(account_id)
        .bind(member_id)
        .bind(role_name(request.role))
        .bind(member_status_name(request.status))
        .bind(now)
        .bind(i64::try_from(request.row_version).map_err(|_| ApiError::InvalidRequest)?)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?
        .rows_affected();
        if affected != 1 {
            return Err(ApiError::WorkspaceVersionConflict);
        }
        if request.status == WorkspaceMemberStatus::Suspended {
            sqlx::query(
                "UPDATE refresh_sessions SET active = false,
                     document = jsonb_set(document, '{active}', 'false'::jsonb, true),
                     updated_at = to_timestamp($2)
                 WHERE device_id IN (
                     SELECT device_id FROM device_member_bindings WHERE member_id = $1
                 ) AND active",
            )
            .bind(member_id)
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(|_| ApiError::Database)?;
        }
        if request.status == WorkspaceMemberStatus::Removed {
            revoke_member_access(&mut tx, member_id, now).await?;
        }
        insert_team_audit(
            &mut tx,
            "team_member_updated",
            account_id,
            device_id,
            now,
            BTreeMap::from([
                ("member_id".into(), member_id.to_owned()),
                ("operation_id".into(), operation_id.clone()),
                ("role".into(), role_name(request.role).into()),
                ("status".into(), member_status_name(request.status).into()),
            ]),
        )
        .await?;
        let response = WorkspaceMember {
            role: request.role,
            status: request.status,
            row_version: request.row_version.saturating_add(1),
            updated_at: now,
            ..target
        };
        finish_team_operation(
            &mut tx,
            self.keyring.as_ref(),
            account_id,
            device_id,
            requester_session_hash,
            &operation_id,
            "update_member",
            &request_hash,
            &response,
            now,
        )
        .await?;
        tx.commit().await.map_err(|_| ApiError::Database)?;
        Ok(response)
    }

    async fn create_device_enrollment(
        &self,
        account_id: &str,
        device_id: &str,
        requester_session_hash: &str,
        request: TeamOperationRequest,
        now: i64,
    ) -> Result<MemberDeviceEnrollment> {
        validate_team_operation_identity(&request.operation_id, requester_session_hash)?;
        let operation_id = request.operation_id;
        let mut tx = self.pool.begin().await.map_err(|_| ApiError::Database)?;
        let member = require_role_tx(
            &mut tx,
            account_id,
            device_id,
            &[
                WorkspaceRole::Owner,
                WorkspaceRole::Admin,
                WorkspaceRole::Billing,
                WorkspaceRole::Operator,
                WorkspaceRole::Viewer,
                WorkspaceRole::Auditor,
            ],
            now,
        )
        .await?;
        let request_hash =
            team_operation_request_hash("create_device_enrollment", &[member.id.as_bytes()]);
        if let Some(response) = claim_team_operation::<MemberDeviceEnrollment>(
            &mut tx,
            self.keyring.as_ref(),
            account_id,
            device_id,
            &operation_id,
            "create_device_enrollment",
            &request_hash,
        )
        .await?
        {
            tx.commit().await.map_err(|_| ApiError::Database)?;
            return Ok(response);
        }
        let enrollment =
            issue_member_device_enrollment(&mut tx, account_id, device_id, &member, now).await?;
        insert_team_audit(
            &mut tx,
            "team_member_device_enrollment_created",
            account_id,
            device_id,
            now,
            BTreeMap::from([
                ("member_id".into(), member.id),
                ("operation_id".into(), operation_id.clone()),
            ]),
        )
        .await?;
        finish_team_operation(
            &mut tx,
            self.keyring.as_ref(),
            account_id,
            device_id,
            requester_session_hash,
            &operation_id,
            "create_device_enrollment",
            &request_hash,
            &enrollment,
            now,
        )
        .await?;
        tx.commit().await.map_err(|_| ApiError::Database)?;
        Ok(enrollment)
    }

    async fn create_member_device_enrollment(
        &self,
        account_id: &str,
        device_id: &str,
        requester_session_hash: &str,
        member_id: &str,
        request: TeamOperationRequest,
        now: i64,
    ) -> Result<MemberDeviceEnrollment> {
        validate_team_operation_identity(&request.operation_id, requester_session_hash)?;
        if !valid_member_id(member_id) {
            return Err(ApiError::InvalidRequest);
        }
        let operation_id = request.operation_id;
        let request_hash =
            team_operation_request_hash("create_member_device_enrollment", &[member_id.as_bytes()]);
        let mut tx = self.pool.begin().await.map_err(|_| ApiError::Database)?;
        let actor = require_role_tx(
            &mut tx,
            account_id,
            device_id,
            &[WorkspaceRole::Owner, WorkspaceRole::Admin],
            now,
        )
        .await?;
        if let Some(response) = claim_team_operation::<MemberDeviceEnrollment>(
            &mut tx,
            self.keyring.as_ref(),
            account_id,
            device_id,
            &operation_id,
            "create_member_device_enrollment",
            &request_hash,
        )
        .await?
        {
            tx.commit().await.map_err(|_| ApiError::Database)?;
            return Ok(response);
        }
        let row = sqlx::query(
            "SELECT members.id, members.email, members.display_name, members.role, members.status,
                    members.row_version, members.created_at, members.updated_at,
                    (SELECT COUNT(*) FROM device_member_bindings AS bindings
                     WHERE bindings.account_id = members.account_id
                       AND bindings.member_id = members.id) AS bound_device_count
             FROM workspace_members AS members
             WHERE members.account_id = $1 AND members.id = $2 FOR UPDATE",
        )
        .bind(account_id)
        .bind(member_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?
        .ok_or(ApiError::InvalidRequest)?;
        let member = row_member(row)?;
        if member.status != WorkspaceMemberStatus::Active
            || member.bound_device_count != 0
            || (member.role == WorkspaceRole::Owner && actor.role != WorkspaceRole::Owner)
        {
            return Err(ApiError::PermissionDenied);
        }
        let enrollment =
            issue_member_device_enrollment(&mut tx, account_id, device_id, &member, now).await?;
        insert_team_audit(
            &mut tx,
            "team_member_device_recovery_created",
            account_id,
            device_id,
            now,
            BTreeMap::from([
                ("member_id".into(), member.id),
                ("operation_id".into(), operation_id.clone()),
            ]),
        )
        .await?;
        finish_team_operation(
            &mut tx,
            self.keyring.as_ref(),
            account_id,
            device_id,
            requester_session_hash,
            &operation_id,
            "create_member_device_enrollment",
            &request_hash,
            &enrollment,
            now,
        )
        .await?;
        tx.commit().await.map_err(|_| ApiError::Database)?;
        Ok(enrollment)
    }

    async fn accept_device_enrollment(
        &self,
        account_id: &str,
        device_id: &str,
        requester_session_hash: &str,
        request: AcceptMemberDeviceEnrollment,
        now: i64,
    ) -> Result<TeamProfile> {
        validate_team_operation_identity(&request.operation_id, requester_session_hash)?;
        let enrollment_token = request.enrollment_token.trim().to_owned();
        if enrollment_token.len() < 32 || enrollment_token.len() > 256 {
            return Err(ApiError::TeamDeviceEnrollmentInvalid);
        }
        let operation_id = request.operation_id;
        let token_hash = sha256_hex(&enrollment_token);
        let request_hash =
            team_operation_request_hash("accept_device_enrollment", &[token_hash.as_bytes()]);
        let mut tx = self.pool.begin().await.map_err(|_| ApiError::Database)?;
        if let Some(response) = claim_team_operation::<TeamProfile>(
            &mut tx,
            self.keyring.as_ref(),
            account_id,
            device_id,
            &operation_id,
            "accept_device_enrollment",
            &request_hash,
        )
        .await?
        {
            tx.commit().await.map_err(|_| ApiError::Database)?;
            return Ok(response);
        }
        require_team_device_authority_tx(&mut tx, account_id, device_id, now).await?;
        let row: Option<(String, String, i64, Option<i64>, Option<i64>)> = sqlx::query_as(
            "SELECT id, member_id, expires_at, consumed_at, revoked_at
             FROM member_device_enrollments
             WHERE account_id = $1 AND token_hash = $2 FOR UPDATE",
        )
        .bind(account_id)
        .bind(&token_hash)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        let Some((enrollment_id, member_id, expires_at, consumed_at, revoked_at)) = row else {
            insert_team_audit_outcome(
                &mut tx,
                "team_member_device_enrollment_accept_denied",
                "denied",
                account_id,
                device_id,
                Some("device_enrollment_not_found"),
                now,
                BTreeMap::new(),
            )
            .await?;
            tx.commit().await.map_err(|_| ApiError::Database)?;
            return Err(ApiError::TeamDeviceEnrollmentInvalid);
        };
        let member_status: Option<String> = sqlx::query_scalar(
            "SELECT status FROM workspace_members
             WHERE account_id = $1 AND id = $2 FOR SHARE",
        )
        .bind(account_id)
        .bind(&member_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        if member_status.as_deref() != Some("active") {
            insert_team_audit_outcome(
                &mut tx,
                "team_member_device_enrollment_accept_denied",
                "denied",
                account_id,
                device_id,
                Some("member_not_active"),
                now,
                BTreeMap::from([
                    ("enrollment_id".into(), enrollment_id.clone()),
                    ("member_id".into(), member_id.clone()),
                ]),
            )
            .await?;
            tx.commit().await.map_err(|_| ApiError::Database)?;
            return Err(ApiError::PermissionDenied);
        }
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 7142026))")
            .bind(device_id)
            .execute(&mut *tx)
            .await
            .map_err(|_| ApiError::Database)?;
        let existing_binding: Option<String> = sqlx::query_scalar(
            "SELECT member_id FROM device_member_bindings
             WHERE account_id = $1 AND device_id = $2 FOR UPDATE",
        )
        .bind(account_id)
        .bind(device_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        if consumed_at.is_some() && existing_binding.as_deref() == Some(member_id.as_str()) {
            let response = profile_tx(&mut tx, account_id, device_id, now).await?;
            finish_team_operation(
                &mut tx,
                self.keyring.as_ref(),
                account_id,
                device_id,
                requester_session_hash,
                &operation_id,
                "accept_device_enrollment",
                &request_hash,
                &response,
                now,
            )
            .await?;
            tx.commit().await.map_err(|_| ApiError::Database)?;
            return Ok(response);
        }
        if expires_at <= now || revoked_at.is_some() {
            let reason = if revoked_at.is_some() {
                "device_enrollment_revoked"
            } else {
                "device_enrollment_expired"
            };
            insert_team_audit_outcome(
                &mut tx,
                "team_member_device_enrollment_accept_denied",
                "denied",
                account_id,
                device_id,
                Some(reason),
                now,
                BTreeMap::from([("enrollment_id".into(), enrollment_id.clone())]),
            )
            .await?;
            tx.commit().await.map_err(|_| ApiError::Database)?;
            return Err(ApiError::TeamDeviceEnrollmentInvalid);
        }
        if consumed_at.is_some() {
            insert_team_audit_outcome(
                &mut tx,
                "team_member_device_enrollment_accept_denied",
                "denied",
                account_id,
                device_id,
                Some("device_enrollment_already_consumed"),
                now,
                BTreeMap::from([
                    ("enrollment_id".into(), enrollment_id.clone()),
                    ("member_id".into(), member_id.clone()),
                ]),
            )
            .await?;
            tx.commit().await.map_err(|_| ApiError::Database)?;
            return Err(ApiError::TeamDeviceEnrollmentInvalid);
        }
        if existing_binding.is_some() {
            insert_team_audit_outcome(
                &mut tx,
                "team_member_device_enrollment_accept_denied",
                "denied",
                account_id,
                device_id,
                Some("device_already_bound"),
                now,
                BTreeMap::from([
                    ("enrollment_id".into(), enrollment_id.clone()),
                    ("member_id".into(), member_id.clone()),
                ]),
            )
            .await?;
            tx.commit().await.map_err(|_| ApiError::Database)?;
            return Err(ApiError::PermissionDenied);
        }
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 7132026))")
            .bind(&member_id)
            .execute(&mut *tx)
            .await
            .map_err(|_| ApiError::Database)?;
        let bound_devices: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM device_member_bindings
             WHERE account_id = $1 AND member_id = $2",
        )
        .bind(account_id)
        .bind(&member_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        if bound_devices >= MAX_DEVICES_PER_MEMBER {
            insert_team_audit_outcome(
                &mut tx,
                "team_member_device_enrollment_accept_denied",
                "denied",
                account_id,
                device_id,
                Some("member_device_limit_reached"),
                now,
                BTreeMap::from([
                    ("enrollment_id".into(), enrollment_id.clone()),
                    ("member_id".into(), member_id.clone()),
                ]),
            )
            .await?;
            tx.commit().await.map_err(|_| ApiError::Database)?;
            return Err(ApiError::ActivationLimitReached);
        }
        sqlx::query(
            "INSERT INTO device_member_bindings (account_id, device_id, member_id, bound_at)
             VALUES ($1, $2, $3, $4)",
        )
        .bind(account_id)
        .bind(device_id)
        .bind(&member_id)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        let consumed = sqlx::query(
            "UPDATE member_device_enrollments SET consumed_at = $2
             WHERE id = $1 AND consumed_at IS NULL AND revoked_at IS NULL",
        )
        .bind(&enrollment_id)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?
        .rows_affected();
        if consumed != 1 {
            return Err(ApiError::Database);
        }
        insert_team_audit(
            &mut tx,
            "team_member_device_enrollment_consumed",
            account_id,
            device_id,
            now,
            BTreeMap::from([
                ("member_id".into(), member_id),
                ("operation_id".into(), operation_id.clone()),
            ]),
        )
        .await?;
        let response = profile_tx(&mut tx, account_id, device_id, now).await?;
        finish_team_operation(
            &mut tx,
            self.keyring.as_ref(),
            account_id,
            device_id,
            requester_session_hash,
            &operation_id,
            "accept_device_enrollment",
            &request_hash,
            &response,
            now,
        )
        .await?;
        tx.commit().await.map_err(|_| ApiError::Database)?;
        Ok(response)
    }

    async fn leave_workspace(
        &self,
        account_id: &str,
        device_id: &str,
        requester_session_hash: &str,
        request: LeaveWorkspace,
        now: i64,
    ) -> Result<()> {
        validate_team_operation_identity(&request.operation_id, requester_session_hash)?;
        if !valid_member_id(&request.member_id) || request.row_version == 0 {
            return Err(ApiError::InvalidRequest);
        }
        let operation_id = request.operation_id;
        let request_hash = team_operation_request_hash(
            "leave_workspace",
            &[
                request.member_id.as_bytes(),
                request.row_version.to_string().as_bytes(),
            ],
        );
        let mut tx = self.pool.begin().await.map_err(|_| ApiError::Database)?;
        if let Some(()) = claim_team_operation::<()>(
            &mut tx,
            self.keyring.as_ref(),
            account_id,
            device_id,
            &operation_id,
            "leave_workspace",
            &request_hash,
        )
        .await?
        {
            tx.commit().await.map_err(|_| ApiError::Database)?;
            return Ok(());
        }
        let member = require_role_tx(
            &mut tx,
            account_id,
            device_id,
            &[
                WorkspaceRole::Owner,
                WorkspaceRole::Admin,
                WorkspaceRole::Billing,
                WorkspaceRole::Operator,
                WorkspaceRole::Viewer,
                WorkspaceRole::Auditor,
            ],
            now,
        )
        .await?;
        if member.role == WorkspaceRole::Owner {
            return Err(ApiError::PermissionDenied);
        }
        if member.id != request.member_id {
            return Err(ApiError::PermissionDenied);
        }
        let affected = sqlx::query(
            "UPDATE workspace_members SET status = 'removed', row_version = row_version + 1,
                 updated_at = $3 WHERE account_id = $1 AND id = $2 AND row_version = $4",
        )
        .bind(account_id)
        .bind(&member.id)
        .bind(now)
        .bind(i64::try_from(request.row_version).map_err(|_| ApiError::InvalidRequest)?)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?
        .rows_affected();
        if affected != 1 {
            return Err(ApiError::WorkspaceVersionConflict);
        }
        revoke_member_access(&mut tx, &member.id, now).await?;
        insert_team_audit(
            &mut tx,
            "team_member_left",
            account_id,
            device_id,
            now,
            BTreeMap::from([
                ("member_id".into(), member.id),
                ("operation_id".into(), operation_id.clone()),
            ]),
        )
        .await?;
        finish_team_operation(
            &mut tx,
            self.keyring.as_ref(),
            account_id,
            device_id,
            requester_session_hash,
            &operation_id,
            "leave_workspace",
            &request_hash,
            &(),
            now,
        )
        .await?;
        tx.commit().await.map_err(|_| ApiError::Database)
    }

    async fn transfer_ownership(
        &self,
        account_id: &str,
        device_id: &str,
        requester_session_hash: &str,
        request: TransferWorkspaceOwnership,
        now: i64,
    ) -> Result<(WorkspaceMember, WorkspaceMember)> {
        validate_team_operation_identity(&request.operation_id, requester_session_hash)?;
        if request.owner_row_version == 0 || request.new_owner_row_version == 0 {
            return Err(ApiError::InvalidRequest);
        }
        let operation_id = request.operation_id;
        let request_hash = team_operation_request_hash(
            "transfer_ownership",
            &[
                request.new_owner_member_id.as_bytes(),
                request.owner_row_version.to_string().as_bytes(),
                request.new_owner_row_version.to_string().as_bytes(),
            ],
        );
        let mut tx = self.pool.begin().await.map_err(|_| ApiError::Database)?;
        if let Some(response) = claim_team_operation::<(WorkspaceMember, WorkspaceMember)>(
            &mut tx,
            self.keyring.as_ref(),
            account_id,
            device_id,
            &operation_id,
            "transfer_ownership",
            &request_hash,
        )
        .await?
        {
            tx.commit().await.map_err(|_| ApiError::Database)?;
            return Ok(response);
        }
        // Serialize ownership changes before taking member-row locks. Distinct operation IDs may
        // target different Admin rows, and allowing both transactions to share-lock the current
        // Owner before upgrading that lock would otherwise permit an avoidable deadlock.
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 7182026))")
            .bind(account_id)
            .execute(&mut *tx)
            .await
            .map_err(|_| ApiError::Database)?;
        let owner = require_role_tx(
            &mut tx,
            account_id,
            device_id,
            &[WorkspaceRole::Owner, WorkspaceRole::Admin],
            now,
        )
        .await?;
        if owner.role != WorkspaceRole::Owner {
            return Err(ApiError::PermissionDenied);
        }
        if owner.id == request.new_owner_member_id {
            return Err(ApiError::InvalidRequest);
        }
        let target_row = sqlx::query(
            "SELECT members.id, members.email, members.display_name, members.role, members.status,
                    members.row_version, members.created_at, members.updated_at,
                    (SELECT COUNT(*) FROM device_member_bindings AS bindings
                     WHERE bindings.account_id = members.account_id
                       AND bindings.member_id = members.id) AS bound_device_count
             FROM workspace_members AS members
             WHERE members.account_id = $1 AND members.id = $2 FOR UPDATE",
        )
        .bind(account_id)
        .bind(&request.new_owner_member_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?
        .ok_or(ApiError::InvalidRequest)?;
        let target = row_member(target_row)?;
        if target.role != WorkspaceRole::Admin || target.status != WorkspaceMemberStatus::Active {
            return Err(ApiError::PermissionDenied);
        }
        let owner_row_version =
            i64::try_from(request.owner_row_version).map_err(|_| ApiError::InvalidRequest)?;
        let target_row_version =
            i64::try_from(request.new_owner_row_version).map_err(|_| ApiError::InvalidRequest)?;
        // PostgreSQL enforces the partial one-Owner index row by row, so a CASE update can promote
        // the Admin before it demotes the current Owner and fail with a transient duplicate. The
        // two statements remain atomic inside this transaction: readers keep seeing the committed
        // Owner, while any failed promotion rolls the demotion back.
        let owner_affected = sqlx::query(
            "UPDATE workspace_members
             SET role = 'admin', row_version = row_version + 1, updated_at = $3
             WHERE account_id = $1 AND id = $2 AND role = 'owner' AND status = 'active'
               AND row_version = $4",
        )
        .bind(account_id)
        .bind(&owner.id)
        .bind(now)
        .bind(owner_row_version)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?
        .rows_affected();
        if owner_affected != 1 {
            return Err(ApiError::WorkspaceVersionConflict);
        }
        let target_affected = sqlx::query(
            "UPDATE workspace_members
             SET role = 'owner', row_version = row_version + 1, updated_at = $3
             WHERE account_id = $1 AND id = $2 AND role = 'admin' AND status = 'active'
               AND row_version = $4",
        )
        .bind(account_id)
        .bind(&target.id)
        .bind(now)
        .bind(target_row_version)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?
        .rows_affected();
        if target_affected != 1 {
            return Err(ApiError::WorkspaceVersionConflict);
        }
        insert_team_audit(
            &mut tx,
            "team_ownership_transferred",
            account_id,
            device_id,
            now,
            BTreeMap::from([
                ("previous_owner_member_id".into(), owner.id.clone()),
                ("new_owner_member_id".into(), target.id.clone()),
                ("operation_id".into(), operation_id.clone()),
            ]),
        )
        .await?;
        let response = (
            WorkspaceMember {
                role: WorkspaceRole::Admin,
                row_version: owner.row_version.saturating_add(1),
                updated_at: now,
                ..owner
            },
            WorkspaceMember {
                role: WorkspaceRole::Owner,
                row_version: target.row_version.saturating_add(1),
                updated_at: now,
                ..target
            },
        );
        finish_team_operation(
            &mut tx,
            self.keyring.as_ref(),
            account_id,
            device_id,
            requester_session_hash,
            &operation_id,
            "transfer_ownership",
            &request_hash,
            &response,
            now,
        )
        .await?;
        tx.commit().await.map_err(|_| ApiError::Database)?;
        Ok(response)
    }

    async fn operation_committed_for_device(
        &self,
        account_id: &str,
        device_id: &str,
        operation_id: &str,
    ) -> Result<bool> {
        validate_team_operation_id(operation_id)?;
        let requester_device_id: Option<String> = sqlx::query_scalar(
            "SELECT requester_device_id FROM team_operations
             WHERE account_id = $1 AND operation_id = $2",
        )
        .bind(account_id)
        .bind(operation_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| ApiError::Database)?;
        let Some(requester_device_id) = requester_device_id else {
            return Ok(false);
        };
        if requester_device_id != device_id {
            return Err(ApiError::IdempotencyConflict);
        }
        Ok(true)
    }

    async fn leave_operation_status(
        &self,
        account_id: &str,
        requester_session_hash: &str,
        requester_device_id: &str,
        operation_id: &str,
        member_id: &str,
        row_version: u64,
    ) -> Result<bool> {
        validate_team_operation_identity(operation_id, requester_session_hash)?;
        if !valid_member_id(member_id) || row_version == 0 {
            return Err(ApiError::InvalidRequest);
        }
        let request_hash = team_operation_request_hash(
            "leave_workspace",
            &[member_id.as_bytes(), row_version.to_string().as_bytes()],
        );
        let row: Option<(String, String, String, String)> = sqlx::query_as(
            "SELECT requester_session_hash, requester_device_id, command, request_hash
             FROM team_operations WHERE account_id = $1 AND operation_id = $2",
        )
        .bind(account_id)
        .bind(operation_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| ApiError::Database)?;
        let Some((stored_session_hash, stored_device_id, stored_command, stored_request_hash)) =
            row
        else {
            return Ok(false);
        };
        if stored_device_id != requester_device_id
            || stored_command != "leave_workspace"
            || stored_request_hash.len() != request_hash.len()
            || !bool::from(
                stored_request_hash
                    .as_bytes()
                    .ct_eq(request_hash.as_bytes()),
            )
            || stored_session_hash.len() != requester_session_hash.len()
            || !bool::from(
                stored_session_hash
                    .as_bytes()
                    .ct_eq(requester_session_hash.as_bytes()),
            )
        {
            return Err(ApiError::IdempotencyConflict);
        }
        Ok(true)
    }
}

async fn profile_tx(
    tx: &mut Transaction<'_, Postgres>,
    account_id: &str,
    device_id: &str,
    now: i64,
) -> Result<TeamProfile> {
    let row = sqlx::query(
        "SELECT plan, plan_revision, purchased_seats FROM licenses WHERE account_id = $1",
    )
    .bind(account_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| ApiError::Database)?
    .ok_or(ApiError::LicenseUnavailable)?;
    let (plan, member_limit) = policy_from_row(&row)?;
    let member = sqlx::query(
        "SELECT members.id, members.email, members.display_name, members.role, members.status,
                members.row_version, members.created_at, members.updated_at,
                (SELECT COUNT(*) FROM device_member_bindings AS member_bindings
                 WHERE member_bindings.account_id = members.account_id
                   AND member_bindings.member_id = members.id) AS bound_device_count
         FROM device_member_bindings AS bindings
         JOIN workspace_members AS members ON members.id = bindings.member_id
         WHERE bindings.account_id = $2 AND bindings.device_id = $1
           AND members.account_id = $2",
    )
    .bind(device_id)
    .bind(account_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| ApiError::Database)?
    .map(row_member)
    .transpose()?;
    let member_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM workspace_members AS members
         WHERE members.account_id = $1 AND (
             members.status IN ('active', 'suspended')
             OR (members.status = 'invited' AND EXISTS (
                 SELECT 1 FROM team_invitations AS invitations
                 WHERE invitations.member_id = members.id
                   AND invitations.accepted_at IS NULL
                   AND invitations.revoked_at IS NULL
                   AND invitations.expires_at > $2
             ))
         )",
    )
    .bind(account_id)
    .bind(now)
    .fetch_one(&mut **tx)
    .await
    .map_err(|_| ApiError::Database)?;
    Ok(TeamProfile {
        enabled: plan == Plan::Team,
        permissions: member
            .as_ref()
            .filter(|member| member.status == WorkspaceMemberStatus::Active)
            .map(|member| permissions(member.role))
            .unwrap_or_default(),
        member,
        member_limit,
        member_count: u32::try_from(member_count).map_err(|_| ApiError::Database)?,
    })
}

fn validate_team_operation_identity(operation_id: &str, session_hash: &str) -> Result<()> {
    validate_team_operation_id(operation_id)?;
    if session_hash.len() != 64
        || !session_hash
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(ApiError::InvalidRequest);
    }
    Ok(())
}

fn validate_team_operation_id(value: &str) -> Result<()> {
    let parsed = uuid::Uuid::parse_str(value).map_err(|_| ApiError::InvalidRequest)?;
    if parsed.get_version() != Some(uuid::Version::Random)
        || parsed.get_variant() != uuid::Variant::RFC4122
        || parsed.hyphenated().to_string() != value
    {
        return Err(ApiError::InvalidRequest);
    }
    Ok(())
}

fn team_operation_request_hash(command: &str, fields: &[&[u8]]) -> String {
    let mut digest = Sha256::new();
    update_team_operation_hash_field(&mut digest, b"camellia-nexus-team-operation-request-v1");
    update_team_operation_hash_field(&mut digest, command.as_bytes());
    for field in fields {
        update_team_operation_hash_field(&mut digest, field);
    }
    digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn update_team_operation_hash_field(digest: &mut Sha256, value: &[u8]) {
    digest.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    digest.update(value);
}

fn team_operation_response_aad(
    account_id: &str,
    device_id: &str,
    operation_id: &str,
    command: &str,
    request_hash: &str,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    update_team_operation_hash_field(&mut digest, b"camellia-nexus-team-operation-response-v1");
    for field in [
        account_id.as_bytes(),
        device_id.as_bytes(),
        operation_id.as_bytes(),
        command.as_bytes(),
        request_hash.as_bytes(),
    ] {
        update_team_operation_hash_field(&mut digest, field);
    }
    digest.finalize().into()
}

async fn claim_team_operation<T: DeserializeOwned>(
    tx: &mut Transaction<'_, Postgres>,
    keyring: &WorkspaceKeyring,
    account_id: &str,
    device_id: &str,
    operation_id: &str,
    command: &str,
    request_hash: &str,
) -> Result<Option<T>> {
    let lock_key = format!("{account_id}:{operation_id}");
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 7172026))")
        .bind(lock_key)
        .execute(&mut **tx)
        .await
        .map_err(|_| ApiError::Database)?;
    let row = sqlx::query(
        "SELECT requester_device_id, command, request_hash, response_key_id,
                response_nonce, response_ciphertext
         FROM team_operations WHERE account_id = $1 AND operation_id = $2 FOR UPDATE",
    )
    .bind(account_id)
    .bind(operation_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| ApiError::Database)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let stored_device_id: String = row
        .try_get("requester_device_id")
        .map_err(|_| ApiError::Database)?;
    let stored_command: String = row.try_get("command").map_err(|_| ApiError::Database)?;
    let stored_hash: String = row
        .try_get("request_hash")
        .map_err(|_| ApiError::Database)?;
    if stored_device_id != device_id
        || stored_command != command
        || stored_hash.len() != request_hash.len()
        || !bool::from(stored_hash.as_bytes().ct_eq(request_hash.as_bytes()))
    {
        return Err(ApiError::IdempotencyConflict);
    }
    let aad =
        team_operation_response_aad(account_id, device_id, operation_id, command, request_hash);
    let plaintext = Zeroizing::new(
        keyring.open_team_operation_response(
            &row.try_get::<String, _>("response_key_id")
                .map_err(|_| ApiError::Database)?,
            &row.try_get::<Vec<u8>, _>("response_nonce")
                .map_err(|_| ApiError::Database)?,
            &row.try_get::<Vec<u8>, _>("response_ciphertext")
                .map_err(|_| ApiError::Database)?,
            &aad,
        )?,
    );
    serde_json::from_slice(plaintext.as_slice())
        .map(Some)
        .map_err(|_| ApiError::WorkspaceIntegrity)
}

#[allow(clippy::too_many_arguments)]
async fn finish_team_operation<T: Serialize>(
    tx: &mut Transaction<'_, Postgres>,
    keyring: &WorkspaceKeyring,
    account_id: &str,
    device_id: &str,
    requester_session_hash: &str,
    operation_id: &str,
    command: &str,
    request_hash: &str,
    response: &T,
    now: i64,
) -> Result<()> {
    let plaintext =
        Zeroizing::new(serde_json::to_vec(response).map_err(|_| ApiError::WorkspaceIntegrity)?);
    if plaintext.len() > MAX_TEAM_OPERATION_RESPONSE_PLAINTEXT_BYTES {
        return Err(ApiError::WorkspaceIntegrity);
    }
    let aad =
        team_operation_response_aad(account_id, device_id, operation_id, command, request_hash);
    let (response_key_id, response_nonce, response_ciphertext) =
        keyring.seal_team_operation_response(&aad, plaintext.as_slice())?;
    sqlx::query(
        "INSERT INTO team_operations
            (account_id, operation_id, requester_session_hash, requester_device_id,
             command, request_hash, response_key_id, response_nonce, response_ciphertext,
             created_at, completed_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $10)",
    )
    .bind(account_id)
    .bind(operation_id)
    .bind(requester_session_hash)
    .bind(device_id)
    .bind(command)
    .bind(request_hash)
    .bind(response_key_id)
    .bind(response_nonce)
    .bind(response_ciphertext)
    .bind(now)
    .execute(&mut **tx)
    .await
    .map_err(|_| ApiError::Database)?;
    Ok(())
}

async fn billing_access(
    pool: &sqlx::PgPool,
    account_id: &str,
    device_id: &str,
    allowed: &[WorkspaceRole],
) -> Result<bool> {
    let (plan, _) = account_plan(pool, account_id).await?;
    if plan != Plan::Team {
        return Ok(true);
    }
    Ok(member_for_device(pool, account_id, device_id)
        .await?
        .is_some_and(|member| {
            member.status == WorkspaceMemberStatus::Active && allowed.contains(&member.role)
        }))
}

async fn account_plan(pool: &sqlx::PgPool, account_id: &str) -> Result<(Plan, u32)> {
    let row = sqlx::query(
        "SELECT plan, plan_revision, purchased_seats FROM licenses WHERE account_id = $1",
    )
    .bind(account_id)
    .fetch_optional(pool)
    .await
    .map_err(|_| ApiError::Database)?
    .ok_or(ApiError::LicenseUnavailable)?;
    policy_from_row(&row)
}

async fn account_plan_tx(
    tx: &mut Transaction<'_, Postgres>,
    account_id: &str,
) -> Result<(Plan, u32)> {
    let row = sqlx::query(
        "SELECT plan, plan_revision, purchased_seats FROM licenses
         WHERE account_id = $1 FOR SHARE",
    )
    .bind(account_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| ApiError::Database)?
    .ok_or(ApiError::LicenseUnavailable)?;
    policy_from_row(&row)
}

fn policy_from_row(row: &PgRow) -> Result<(Plan, u32)> {
    let plan = match row.try_get::<String, _>("plan").as_deref() {
        Ok("free") => Plan::Free,
        Ok("pro") => Plan::Pro,
        Ok("team") => Plan::Team,
        _ => return Err(ApiError::Database),
    };
    let revision = row
        .try_get::<i32, _>("plan_revision")
        .ok()
        .and_then(|value| u32::try_from(value).ok())
        .ok_or(ApiError::Database)?;
    let seats = row
        .try_get::<i32, _>("purchased_seats")
        .ok()
        .and_then(|value| u32::try_from(value).ok())
        .ok_or(ApiError::Database)?;
    Ok((plan, effective_policy(plan, revision, seats)?.member_limit))
}

async fn member_for_device(
    pool: &sqlx::PgPool,
    account_id: &str,
    device_id: &str,
) -> Result<Option<WorkspaceMember>> {
    let row = sqlx::query(
        "SELECT members.id, members.email, members.display_name, members.role, members.status,
                members.row_version, members.created_at, members.updated_at,
                (SELECT COUNT(*) FROM device_member_bindings AS member_bindings
                 WHERE member_bindings.account_id = members.account_id
                   AND member_bindings.member_id = members.id) AS bound_device_count
         FROM device_member_bindings AS bindings
         JOIN workspace_members AS members ON members.id = bindings.member_id
         WHERE bindings.account_id = $2 AND bindings.device_id = $1
           AND members.account_id = $2",
    )
    .bind(device_id)
    .bind(account_id)
    .fetch_optional(pool)
    .await
    .map_err(|_| ApiError::Database)?;
    row.map(row_member).transpose()
}

async fn occupied_member_count(pool: &sqlx::PgPool, account_id: &str, now: i64) -> Result<u32> {
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM workspace_members AS members
         WHERE members.account_id = $1 AND (
             members.status IN ('active', 'suspended')
             OR (members.status = 'invited' AND EXISTS (
                 SELECT 1 FROM team_invitations AS invitations
                 WHERE invitations.member_id = members.id
                   AND invitations.accepted_at IS NULL
                   AND invitations.revoked_at IS NULL
                   AND invitations.expires_at > $2
             ))
         )",
    )
    .bind(account_id)
    .bind(now)
    .fetch_one(pool)
    .await
    .map_err(|_| ApiError::Database)?;
    u32::try_from(count).map_err(|_| ApiError::Database)
}

async fn require_role(
    pool: &sqlx::PgPool,
    account_id: &str,
    device_id: &str,
    allowed: &[WorkspaceRole],
) -> Result<WorkspaceMember> {
    let member = member_for_device(pool, account_id, device_id)
        .await?
        .ok_or(ApiError::PermissionDenied)?;
    if member.status != WorkspaceMemberStatus::Active || !allowed.contains(&member.role) {
        return Err(ApiError::PermissionDenied);
    }
    Ok(member)
}

async fn require_role_tx(
    tx: &mut Transaction<'_, Postgres>,
    account_id: &str,
    device_id: &str,
    allowed: &[WorkspaceRole],
    now: i64,
) -> Result<WorkspaceMember> {
    let row = sqlx::query(
        "SELECT members.id, members.email, members.display_name, members.role, members.status,
                members.row_version, members.created_at, members.updated_at,
                devices.state AS device_state,
                COALESCE(accounts.document ->> 'state', 'active') AS account_state,
                licenses.plan, licenses.plan_revision, licenses.status AS license_status,
                licenses.expires_at, licenses.purchased_seats,
                (SELECT COUNT(*) FROM device_member_bindings AS member_bindings
                 WHERE member_bindings.account_id = members.account_id
                   AND member_bindings.member_id = members.id) AS bound_device_count
         FROM device_member_bindings AS bindings
         JOIN workspace_members AS members ON members.id = bindings.member_id
         JOIN devices ON devices.account_id = bindings.account_id
           AND devices.device_id = bindings.device_id
         JOIN accounts ON accounts.id = devices.account_id
         JOIN licenses ON licenses.id = devices.license_id
           AND licenses.account_id = devices.account_id
         WHERE bindings.account_id = $2 AND bindings.device_id = $1
           AND members.account_id = $2
         FOR SHARE OF members, devices, accounts, licenses",
    )
    .bind(device_id)
    .bind(account_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| ApiError::Database)?
    .ok_or(ApiError::PermissionDenied)?;
    require_team_authority_row(&row, now)?;
    let member = row_member(row)?;
    if member.status != WorkspaceMemberStatus::Active || !allowed.contains(&member.role) {
        return Err(ApiError::PermissionDenied);
    }
    Ok(member)
}

async fn require_team_device_authority_tx(
    tx: &mut Transaction<'_, Postgres>,
    account_id: &str,
    device_id: &str,
    now: i64,
) -> Result<()> {
    let row = sqlx::query(
        "SELECT devices.state AS device_state,
                COALESCE(accounts.document ->> 'state', 'active') AS account_state,
                licenses.plan, licenses.plan_revision, licenses.status AS license_status,
                licenses.expires_at, licenses.purchased_seats
         FROM devices
         JOIN accounts ON accounts.id = devices.account_id
         JOIN licenses ON licenses.id = devices.license_id
           AND licenses.account_id = devices.account_id
         WHERE devices.account_id = $1 AND devices.device_id = $2
         FOR SHARE OF devices, accounts, licenses",
    )
    .bind(account_id)
    .bind(device_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| ApiError::Database)?
    .ok_or(ApiError::PermissionDenied)?;
    require_team_authority_row(&row, now)
}

fn require_team_authority_row(row: &PgRow, now: i64) -> Result<()> {
    if row
        .try_get::<String, _>("device_state")
        .map_err(|_| ApiError::Database)?
        != "active"
    {
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
    if policy_from_row(row)?.0 != Plan::Team {
        return Err(ApiError::CapabilityDenied);
    }
    let expires_at: Option<i64> = row.try_get("expires_at").map_err(|_| ApiError::Database)?;
    match row
        .try_get::<String, _>("license_status")
        .map_err(|_| ApiError::Database)?
        .as_str()
    {
        "active" if expires_at.is_none_or(|expires_at| expires_at > now) => Ok(()),
        "past_due" | "canceled" if expires_at.is_some_and(|expires_at| expires_at > now) => Ok(()),
        "past_due" => Err(ApiError::LicensePastDue),
        "canceled" => Err(ApiError::LicenseCanceled),
        "active" => Err(ApiError::LicenseExpired),
        _ => Err(ApiError::Database),
    }
}

fn row_member(row: PgRow) -> Result<WorkspaceMember> {
    Ok(WorkspaceMember {
        id: row.try_get("id").map_err(|_| ApiError::Database)?,
        email: row.try_get("email").map_err(|_| ApiError::Database)?,
        display_name: row
            .try_get("display_name")
            .map_err(|_| ApiError::Database)?,
        role: parse_role(
            &row.try_get::<String, _>("role")
                .map_err(|_| ApiError::Database)?,
        )?,
        status: parse_status(
            &row.try_get::<String, _>("status")
                .map_err(|_| ApiError::Database)?,
        )?,
        bound_device_count: row
            .try_get::<i64, _>("bound_device_count")
            .ok()
            .and_then(|value| u32::try_from(value).ok())
            .unwrap_or(0),
        row_version: row
            .try_get::<i64, _>("row_version")
            .ok()
            .and_then(|value| u64::try_from(value).ok())
            .ok_or(ApiError::Database)?,
        created_at: row.try_get("created_at").map_err(|_| ApiError::Database)?,
        updated_at: row.try_get("updated_at").map_err(|_| ApiError::Database)?,
    })
}

async fn issue_member_device_enrollment(
    tx: &mut Transaction<'_, Postgres>,
    account_id: &str,
    device_id: &str,
    member: &WorkspaceMember,
    now: i64,
) -> Result<MemberDeviceEnrollment> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 7132026))")
        .bind(&member.id)
        .execute(&mut **tx)
        .await
        .map_err(|_| ApiError::Database)?;
    let bound_devices: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM device_member_bindings
         WHERE account_id = $1 AND member_id = $2",
    )
    .bind(account_id)
    .bind(&member.id)
    .fetch_one(&mut **tx)
    .await
    .map_err(|_| ApiError::Database)?;
    if bound_devices >= MAX_DEVICES_PER_MEMBER {
        return Err(ApiError::ActivationLimitReached);
    }
    sqlx::query(
        "UPDATE member_device_enrollments SET revoked_at = COALESCE(revoked_at, $2)
         WHERE member_id = $1 AND consumed_at IS NULL AND revoked_at IS NULL",
    )
    .bind(&member.id)
    .bind(now)
    .execute(&mut **tx)
    .await
    .map_err(|_| ApiError::Database)?;
    let id = random_id("member_enrollment");
    let enrollment_token = random_secret();
    let expires_at = now.saturating_add(DEVICE_ENROLLMENT_TTL_SECONDS);
    sqlx::query(
        "INSERT INTO member_device_enrollments
            (id, account_id, member_id, token_hash, created_by_device_id,
             expires_at, consumed_at, revoked_at, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, NULL, NULL, $7)",
    )
    .bind(&id)
    .bind(account_id)
    .bind(&member.id)
    .bind(sha256_hex(&enrollment_token))
    .bind(device_id)
    .bind(expires_at)
    .bind(now)
    .execute(&mut **tx)
    .await
    .map_err(|_| ApiError::Database)?;
    Ok(MemberDeviceEnrollment {
        id,
        member_id: member.id.clone(),
        enrollment_token,
        expires_at,
    })
}

fn role_permissions(role: WorkspaceRole) -> &'static [&'static str] {
    match role {
        WorkspaceRole::Owner => &[
            "team.read",
            "team.manage",
            "team.transfer_ownership",
            "billing.read",
            "billing.manage",
            "shared.read",
            "shared.write",
            "shared.publish",
            "shared.purge",
            "sync.read",
            "sync.write",
            "remote.read",
            "alerts.read",
            "alerts.history.read",
            "alerts.manage",
            "alerts.ack",
            "audit.read",
            "audit.export",
            "webhooks.read",
            "webhooks.manage",
        ],
        WorkspaceRole::Admin => &[
            "team.read",
            "team.manage",
            "billing.read",
            "shared.read",
            "shared.write",
            "shared.publish",
            "sync.read",
            "sync.write",
            "remote.read",
            "alerts.read",
            "alerts.history.read",
            "alerts.manage",
            "alerts.ack",
            "audit.read",
            "audit.export",
            "webhooks.read",
            "webhooks.manage",
        ],
        WorkspaceRole::Billing => &["billing.read", "billing.manage"],
        WorkspaceRole::Operator => &[
            "team.read",
            "shared.read",
            "shared.write",
            "sync.read",
            "sync.write",
            "remote.read",
            "alerts.read",
            "alerts.ack",
        ],
        WorkspaceRole::Viewer => &[
            "team.read",
            "shared.read",
            "sync.read",
            "remote.read",
            "alerts.read",
        ],
        WorkspaceRole::Auditor => &[
            "team.read",
            "alerts.history.read",
            "audit.read",
            "audit.export",
            "webhooks.delivery.read",
        ],
    }
}

fn valid_member_update_transition(
    current_role: WorkspaceRole,
    current_status: WorkspaceMemberStatus,
    requested_role: WorkspaceRole,
    requested_status: WorkspaceMemberStatus,
) -> bool {
    if current_role == requested_role && current_status == requested_status {
        return false;
    }
    match (current_status, requested_status) {
        (WorkspaceMemberStatus::Invited, WorkspaceMemberStatus::Removed) => {
            requested_role == current_role
        }
        (
            WorkspaceMemberStatus::Active | WorkspaceMemberStatus::Suspended,
            WorkspaceMemberStatus::Active | WorkspaceMemberStatus::Suspended,
        ) => true,
        (
            WorkspaceMemberStatus::Active | WorkspaceMemberStatus::Suspended,
            WorkspaceMemberStatus::Removed,
        ) => requested_role == current_role,
        _ => false,
    }
}

pub(crate) fn workspace_role_has_permission(role: &str, permission: &str) -> bool {
    parse_role(role)
        .ok()
        .is_some_and(|role| role_permissions(role).contains(&permission))
}

fn permissions(role: WorkspaceRole) -> Vec<String> {
    role_permissions(role)
        .iter()
        .map(|value| (*value).to_owned())
        .collect()
}

fn member_page_limit(value: Option<u32>) -> Result<u32> {
    let value = value.unwrap_or(DEFAULT_MEMBER_PAGE_SIZE);
    if value == 0 || value > MAX_MEMBER_PAGE_SIZE {
        Err(ApiError::InvalidRequest)
    } else {
        Ok(value)
    }
}

fn encode_member_cursor(cursor: &TeamMemberCursor) -> Result<String> {
    serde_json::to_vec(cursor)
        .map(|bytes| URL_SAFE_NO_PAD.encode(bytes))
        .map_err(|_| ApiError::Internal)
}

fn decode_member_cursor(value: &str) -> Result<TeamMemberCursor> {
    if value.is_empty() || value.len() > 512 {
        return Err(ApiError::InvalidRequest);
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| ApiError::InvalidRequest)?;
    let cursor: TeamMemberCursor =
        serde_json::from_slice(&bytes).map_err(|_| ApiError::InvalidRequest)?;
    if cursor.created_at < 0
        || !cursor.member_id.starts_with("member_")
        || cursor.member_id.len() > 128
        || !cursor
            .member_id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(ApiError::InvalidRequest);
    }
    Ok(cursor)
}

fn normalized_email(value: &str) -> Result<String> {
    let email = value.trim().to_ascii_lowercase();
    let mut parts = email.split('@');
    let local = parts.next().unwrap_or_default();
    let domain = parts.next().unwrap_or_default();
    if email.len() > 254
        || local.is_empty()
        || domain.is_empty()
        || parts.next().is_some()
        || !domain.contains('.')
        || email.chars().any(char::is_control)
    {
        return Err(ApiError::InvalidRequest);
    }
    Ok(email)
}

fn bounded(value: &str, max: usize) -> Result<String> {
    let value = value.trim();
    if value.is_empty() || value.len() > max || value.chars().any(char::is_control) {
        Err(ApiError::InvalidRequest)
    } else {
        Ok(value.to_owned())
    }
}

fn valid_member_id(value: &str) -> bool {
    value.starts_with("member_")
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn role_name(role: WorkspaceRole) -> &'static str {
    match role {
        WorkspaceRole::Owner => "owner",
        WorkspaceRole::Admin => "admin",
        WorkspaceRole::Billing => "billing",
        WorkspaceRole::Operator => "operator",
        WorkspaceRole::Viewer => "viewer",
        WorkspaceRole::Auditor => "auditor",
    }
}

fn member_status_name(status: WorkspaceMemberStatus) -> &'static str {
    match status {
        WorkspaceMemberStatus::Invited => "invited",
        WorkspaceMemberStatus::Active => "active",
        WorkspaceMemberStatus::Suspended => "suspended",
        WorkspaceMemberStatus::Removed => "removed",
    }
}

fn parse_role(value: &str) -> Result<WorkspaceRole> {
    match value {
        "owner" => Ok(WorkspaceRole::Owner),
        "admin" => Ok(WorkspaceRole::Admin),
        "billing" => Ok(WorkspaceRole::Billing),
        "operator" => Ok(WorkspaceRole::Operator),
        "viewer" => Ok(WorkspaceRole::Viewer),
        "auditor" => Ok(WorkspaceRole::Auditor),
        _ => Err(ApiError::Database),
    }
}

fn parse_status(value: &str) -> Result<WorkspaceMemberStatus> {
    match value {
        "invited" => Ok(WorkspaceMemberStatus::Invited),
        "active" => Ok(WorkspaceMemberStatus::Active),
        "suspended" => Ok(WorkspaceMemberStatus::Suspended),
        "removed" => Ok(WorkspaceMemberStatus::Removed),
        _ => Err(ApiError::Database),
    }
}

pub(crate) async fn revoke_member_access(
    tx: &mut Transaction<'_, Postgres>,
    member_id: &str,
    now: i64,
) -> Result<()> {
    sqlx::query(
        "UPDATE refresh_sessions SET active = false,
             document = jsonb_set(document, '{active}', 'false'::jsonb, true),
             updated_at = to_timestamp($2)
         WHERE device_id IN (
             SELECT device_id FROM device_member_bindings WHERE member_id = $1
         ) AND active",
    )
    .bind(member_id)
    .bind(now)
    .execute(&mut **tx)
    .await
    .map_err(|_| ApiError::Database)?;
    sqlx::query(
        "UPDATE devices
         SET state = 'removed',
             document = jsonb_set(
                 jsonb_set(document, '{state}', '\"removed\"'::jsonb, true),
                 '{last_seen_at}', to_jsonb($2::BIGINT), true
             ),
             updated_at = to_timestamp($2)
         WHERE device_id IN (
             SELECT device_id FROM device_member_bindings WHERE member_id = $1
         )",
    )
    .bind(member_id)
    .bind(now)
    .execute(&mut **tx)
    .await
    .map_err(|_| ApiError::Database)?;
    sqlx::query("DELETE FROM device_member_bindings WHERE member_id = $1")
        .bind(member_id)
        .execute(&mut **tx)
        .await
        .map_err(|_| ApiError::Database)?;
    sqlx::query(
        "UPDATE team_invitations SET revoked_at = COALESCE(revoked_at, $2)
         WHERE member_id = $1 AND accepted_at IS NULL AND revoked_at IS NULL",
    )
    .bind(member_id)
    .bind(now)
    .execute(&mut **tx)
    .await
    .map_err(|_| ApiError::Database)?;
    sqlx::query(
        "UPDATE member_device_enrollments SET revoked_at = COALESCE(revoked_at, $2)
         WHERE member_id = $1 AND consumed_at IS NULL AND revoked_at IS NULL",
    )
    .bind(member_id)
    .bind(now)
    .execute(&mut **tx)
    .await
    .map_err(|_| ApiError::Database)?;
    Ok(())
}

async fn insert_team_audit(
    tx: &mut Transaction<'_, Postgres>,
    event_type: &str,
    account_id: &str,
    device_id: &str,
    now: i64,
    metadata: BTreeMap<String, String>,
) -> Result<()> {
    insert_team_audit_outcome(
        tx,
        event_type,
        "succeeded",
        account_id,
        device_id,
        None,
        now,
        metadata,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn insert_team_audit_outcome(
    tx: &mut Transaction<'_, Postgres>,
    event_type: &str,
    outcome: &str,
    account_id: &str,
    device_id: &str,
    reason_code: Option<&str>,
    now: i64,
    metadata: BTreeMap<String, String>,
) -> Result<()> {
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
             reason_code, metadata, document)
         VALUES ($1, $2, $3, $4, $5, NULL, $6, $7, $8, $9)",
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        contracts::{DeviceRegistrationMetadata, DeviceState, Plan},
        domain::{
            Account, AuditEventRecord, Device, License, RefreshSessionProofState,
            RefreshSessionRecord,
        },
        store::LicenseRepository,
    };

    #[test]
    fn permissions_are_fixed_and_least_privilege() {
        let owner = permissions(WorkspaceRole::Owner);
        let admin = permissions(WorkspaceRole::Admin);
        let billing = permissions(WorkspaceRole::Billing);
        let operator = permissions(WorkspaceRole::Operator);
        let viewer = permissions(WorkspaceRole::Viewer);
        let auditor = permissions(WorkspaceRole::Auditor);

        assert!(owner.iter().any(|permission| permission == "shared.purge"));
        assert!(
            owner
                .iter()
                .any(|permission| permission == "team.transfer_ownership")
        );
        assert!(
            !admin
                .iter()
                .any(|permission| permission == "billing.manage")
        );
        assert!(!admin.iter().any(|permission| permission == "shared.purge"));
        assert_eq!(billing, ["billing.read", "billing.manage"]);
        assert!(
            operator
                .iter()
                .any(|permission| permission == "shared.write")
        );
        assert!(operator.iter().any(|permission| permission == "alerts.ack"));
        assert!(
            !operator
                .iter()
                .any(|permission| permission == "alerts.manage")
        );
        assert!(viewer.iter().any(|permission| permission == "shared.read"));
        assert!(!viewer.iter().any(|permission| permission == "shared.write"));
        assert!(
            auditor
                .iter()
                .any(|permission| permission == "audit.export")
        );
        assert!(
            auditor
                .iter()
                .any(|permission| permission == "webhooks.delivery.read")
        );
        assert!(
            !auditor
                .iter()
                .any(|permission| permission == "webhooks.read")
        );
    }

    #[test]
    fn invitation_identity_is_normalized_and_bounded() {
        assert_eq!(
            normalized_email(" USER@Example.COM ").unwrap(),
            "user@example.com"
        );
        assert!(normalized_email("not-an-email").is_err());
        assert!(normalized_email("user@localhost").is_err());
    }

    #[test]
    fn team_operation_identity_and_request_hash_are_canonical_and_bound_to_every_field() {
        let operation_id = uuid::Uuid::new_v4().to_string();
        let session_hash = sha256_hex("team-operation-session");
        assert!(validate_team_operation_identity(&operation_id, &session_hash).is_ok());
        assert!(validate_team_operation_id(&operation_id.to_uppercase()).is_err());
        assert!(validate_team_operation_id("00000000-0000-1000-8000-000000000000").is_err());
        assert!(validate_team_operation_identity(&operation_id, "not-a-session-hash").is_err());

        let first = team_operation_request_hash("update_member", &[b"member-a", b"viewer", b"1"]);
        let retry = team_operation_request_hash("update_member", &[b"member-a", b"viewer", b"1"]);
        let changed_member =
            team_operation_request_hash("update_member", &[b"member-b", b"viewer", b"1"]);
        let changed_role =
            team_operation_request_hash("update_member", &[b"member-a", b"operator", b"1"]);
        let changed_version =
            team_operation_request_hash("update_member", &[b"member-a", b"viewer", b"2"]);
        assert_eq!(first, retry);
        assert_ne!(first, changed_member);
        assert_ne!(first, changed_role);
        assert_ne!(first, changed_version);
    }

    #[test]
    fn prelaunch_baseline_stores_only_encrypted_bounded_team_responses() {
        let migration = include_str!("../migrations/0001_prelaunch_baseline.sql");
        let team_operations = migration
            .split_once("CREATE TABLE team_operations")
            .expect("team operations table must be present")
            .1
            .split_once(";\n")
            .expect("team operations table must be terminated")
            .0;
        assert!(team_operations.contains("response_key_id TEXT NOT NULL"));
        assert!(team_operations.contains("response_nonce BYTEA NOT NULL"));
        assert!(team_operations.contains("response_ciphertext BYTEA NOT NULL"));
        assert!(
            team_operations.contains("octet_length(response_ciphertext) BETWEEN 17 AND 131088")
        );
        assert!(team_operations.contains("requester_session_hash TEXT NOT NULL"));
        assert!(!team_operations.contains("invitation_token"));
        assert!(!team_operations.contains("enrollment_token"));
    }

    #[test]
    fn member_page_cursor_is_canonical_and_bounded() {
        let expected = TeamMemberCursor {
            created_at: 1_700_000_000,
            member_id: "member_0123456789abcdef0123456789abcdef".to_owned(),
        };
        let encoded = encode_member_cursor(&expected).unwrap();
        assert_eq!(decode_member_cursor(&encoded).unwrap(), expected);
        assert!(decode_member_cursor("").is_err());
        assert!(decode_member_cursor("not-base64!").is_err());
        assert_eq!(member_page_limit(None).unwrap(), DEFAULT_MEMBER_PAGE_SIZE);
        assert_eq!(member_page_limit(Some(MAX_MEMBER_PAGE_SIZE)).unwrap(), 200);
        assert!(member_page_limit(Some(0)).is_err());
        assert!(member_page_limit(Some(MAX_MEMBER_PAGE_SIZE + 1)).is_err());
    }

    #[test]
    fn member_removal_is_explicit_and_pending_invitations_can_only_be_revoked() {
        assert!(valid_member_update_transition(
            WorkspaceRole::Operator,
            WorkspaceMemberStatus::Invited,
            WorkspaceRole::Operator,
            WorkspaceMemberStatus::Removed,
        ));
        assert!(!valid_member_update_transition(
            WorkspaceRole::Operator,
            WorkspaceMemberStatus::Invited,
            WorkspaceRole::Operator,
            WorkspaceMemberStatus::Active,
        ));
        assert!(valid_member_update_transition(
            WorkspaceRole::Operator,
            WorkspaceMemberStatus::Active,
            WorkspaceRole::Operator,
            WorkspaceMemberStatus::Removed,
        ));
        assert!(!valid_member_update_transition(
            WorkspaceRole::Operator,
            WorkspaceMemberStatus::Active,
            WorkspaceRole::Viewer,
            WorkspaceMemberStatus::Removed,
        ));
        assert!(!valid_member_update_transition(
            WorkspaceRole::Operator,
            WorkspaceMemberStatus::Removed,
            WorkspaceRole::Operator,
            WorkspaceMemberStatus::Active,
        ));
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn final_team_authorization_rechecks_account_and_license_state() {
        let database_url = std::env::var("TEST_DATABASE_URL")
            .expect("TEST_DATABASE_URL is required for the PostgreSQL integration test");
        let repository =
            PostgresRepository::connect(&database_url, 2, std::time::Duration::from_secs(5))
                .await
                .expect("connect PostgreSQL");
        repository.migrate().await.expect("run migrations");

        let suffix = random_id("team_authority_test");
        let account_id = format!("account_{suffix}");
        let device_id = uuid::Uuid::new_v4().to_string();
        let now = 1_800_000_000;
        let active_account = Account::active(&account_id, now);
        let team_license = License::new(&account_id, Plan::Team);
        repository
            .upsert_account(active_account.clone())
            .await
            .expect("create account");
        repository
            .upsert_license(team_license.clone())
            .await
            .expect("create Team license");
        repository
            .upsert_device(Device {
                account_id: account_id.clone(),
                license_id: team_license.id.clone(),
                metadata: DeviceRegistrationMetadata {
                    device_id: device_id.clone(),
                    public_key_pem: "team-authority-test-public-key".to_owned(),
                    public_key_thumbprint: format!("sha256:{device_id}"),
                    platform: "test".to_owned(),
                    app_version: "1.0.0".to_owned(),
                    display_name: Some("Team authority test".to_owned()),
                },
                state: DeviceState::Active,
                pending_activation_code_hash: None,
                pending_activation_expires_at: None,
                created_at: now,
                last_seen_at: Some(now),
            })
            .await
            .expect("create active device and owner binding");

        let mut suspended_account = active_account.clone();
        suspended_account.state = crate::domain::AccountState::Suspended;
        repository
            .upsert_account(suspended_account)
            .await
            .expect("suspend account between outer authorization and final transaction");
        let mut tx = repository.pool.begin().await.expect("begin account check");
        assert!(matches!(
            require_role_tx(
                &mut tx,
                &account_id,
                &device_id,
                &[WorkspaceRole::Owner, WorkspaceRole::Admin],
                now,
            )
            .await,
            Err(ApiError::AccountSuspended)
        ));
        assert!(matches!(
            require_team_device_authority_tx(&mut tx, &account_id, &device_id, now).await,
            Err(ApiError::AccountSuspended)
        ));
        tx.rollback().await.expect("rollback account check");

        repository
            .upsert_account(active_account)
            .await
            .expect("restore active account");
        let mut free_license = team_license;
        free_license.set_plan(Plan::Free);
        free_license.license_epoch += 1;
        free_license.row_version += 1;
        repository
            .upsert_license(free_license)
            .await
            .expect("downgrade license between outer authorization and final transaction");
        let mut tx = repository.pool.begin().await.expect("begin license check");
        assert!(matches!(
            require_role_tx(
                &mut tx,
                &account_id,
                &device_id,
                &[WorkspaceRole::Owner, WorkspaceRole::Admin],
                now,
            )
            .await,
            Err(ApiError::CapabilityDenied)
        ));
        assert!(matches!(
            require_team_device_authority_tx(&mut tx, &account_id, &device_id, now).await,
            Err(ApiError::CapabilityDenied)
        ));
        tx.rollback().await.expect("rollback license check");

        sqlx::query("DELETE FROM accounts WHERE id = $1")
            .bind(&account_id)
            .execute(&repository.pool)
            .await
            .expect("clean up authority fixture");
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn member_pagination_and_removal_recovery_are_exercised() {
        let database_url = std::env::var("TEST_DATABASE_URL")
            .expect("TEST_DATABASE_URL is required for the PostgreSQL integration test");
        let repository =
            PostgresRepository::connect(&database_url, 2, std::time::Duration::from_secs(5))
                .await
                .expect("connect PostgreSQL");
        repository.migrate().await.expect("run migrations");
        let team_repository =
            PostgresTeamRepository::new(&repository, WorkspaceKeyring::ephemeral_for_development());

        let suffix = random_id("team_repository_test");
        let account_id = format!("account_{suffix}");
        let license = License::new(&account_id, Plan::Team);
        let owner_device_id = uuid::Uuid::new_v4().to_string();
        let removed_device_id = uuid::Uuid::new_v4().to_string();
        let now = 1_800_000_000;
        repository
            .upsert_account(Account::active(&account_id, now))
            .await
            .expect("create account");
        repository
            .upsert_license(license.clone())
            .await
            .expect("create Team license");
        for device_id in [&owner_device_id, &removed_device_id] {
            repository
                .upsert_device(Device {
                    account_id: account_id.clone(),
                    license_id: license.id.clone(),
                    metadata: DeviceRegistrationMetadata {
                        device_id: device_id.clone(),
                        public_key_pem: "team-test-public-key".to_owned(),
                        public_key_thumbprint: format!("sha256:{device_id}"),
                        platform: "test".to_owned(),
                        app_version: "1.0.0".to_owned(),
                        display_name: Some("Team repository test".to_owned()),
                    },
                    state: DeviceState::Active,
                    pending_activation_code_hash: None,
                    pending_activation_expires_at: None,
                    created_at: now,
                    last_seen_at: Some(now),
                })
                .await
                .expect("create device");
        }

        let owner_id: String = sqlx::query_scalar(
            "SELECT id FROM workspace_members WHERE account_id = $1 AND role = 'owner'",
        )
        .bind(&account_id)
        .fetch_one(&repository.pool)
        .await
        .expect("load bootstrapped workspace owner");
        let removable_id = random_id("member");
        let transfer_target_id = random_id("member");
        let member_fixtures = [
            (1, removable_id.clone(), "viewer", "active"),
            (2, random_id("member"), "operator", "suspended"),
            (3, random_id("member"), "auditor", "removed"),
            (4, transfer_target_id.clone(), "admin", "active"),
        ];
        for (offset, member_id, role, status) in &member_fixtures {
            sqlx::query(
                "INSERT INTO workspace_members
                    (id, account_id, email, display_name, role, status, row_version,
                     created_at, updated_at)
                 VALUES ($1, $2, $3, $4, $5, $6, 1, $7, $7)",
            )
            .bind(member_id)
            .bind(&account_id)
            .bind(format!("{member_id}@example.test"))
            .bind(format!("Member {offset}"))
            .bind(role)
            .bind(status)
            .bind(now + offset)
            .execute(&repository.pool)
            .await
            .expect("insert workspace member");
        }
        let owner_binding: String =
            sqlx::query_scalar("SELECT member_id FROM device_member_bindings WHERE device_id = $1")
                .bind(&owner_device_id)
                .fetch_one(&repository.pool)
                .await
                .expect("load bootstrapped owner device binding");
        assert_eq!(owner_binding, owner_id);
        sqlx::query(
            "INSERT INTO device_member_bindings (account_id, device_id, member_id, bound_at)
             VALUES ($1, $2, $3, $4)",
        )
        .bind(&account_id)
        .bind(&removed_device_id)
        .bind(&removable_id)
        .bind(now)
        .execute(&repository.pool)
        .await
        .expect("bind member devices");

        let first = team_repository
            .members(
                &account_id,
                &owner_device_id,
                TeamMemberPageRequest {
                    cursor: None,
                    limit: Some(2),
                },
            )
            .await
            .expect("load first member page");
        assert_eq!(first.members.len(), 2);
        assert!(first.has_more);
        let second = team_repository
            .members(
                &account_id,
                &owner_device_id,
                TeamMemberPageRequest {
                    cursor: first.next_cursor,
                    limit: Some(2),
                },
            )
            .await
            .expect("load second member page");
        assert_eq!(second.members.len(), 2);
        assert!(second.has_more);
        let third = team_repository
            .members(
                &account_id,
                &owner_device_id,
                TeamMemberPageRequest {
                    cursor: second.next_cursor,
                    limit: Some(2),
                },
            )
            .await
            .expect("load final member page");
        assert_eq!(third.members.len(), 1);
        assert!(!third.has_more);
        assert!(third.next_cursor.is_none());

        let token_hash = sha256_hex(&random_id("team_session"));
        repository
            .insert_session(RefreshSessionRecord {
                token_hash: token_hash.clone(),
                account_id: account_id.clone(),
                device_id: removed_device_id.clone(),
                family_id: random_id("team_session_family"),
                family_created_at: now,
                absolute_expires_at: now + 86_400,
                active: true,
                expires_at: now + 3_600,
                rotated_to_hash: None,
                rotated_at: None,
                pending_activation_code_hash: None,
                activation_verified_at: Some(now),
                activation_confirmation_consumed: false,
                proof_state: RefreshSessionProofState::DeviceProven,
            })
            .await
            .expect("create member session");
        let removal_operation_id = uuid::Uuid::new_v4().to_string();
        let removal_audit = AuditEventRecord {
            id: random_id("audit"),
            event_type: "device_removed".to_owned(),
            outcome: "succeeded".to_owned(),
            occurred_at: now + 5,
            account_id: Some(account_id.clone()),
            license_id: Some(license.id.clone()),
            device_id: Some(removed_device_id.clone()),
            reason_code: None,
            metadata: BTreeMap::from([
                ("target_device_id".to_owned(), removed_device_id.clone()),
                ("operation_id".to_owned(), removal_operation_id.clone()),
            ]),
        };
        assert!(
            repository
                .remove_device_with_audit(
                    &token_hash,
                    &removed_device_id,
                    &removed_device_id,
                    &removal_operation_id,
                    now + 5,
                    removal_audit,
                )
                .await
                .expect("remove the member device")
        );
        assert!(
            repository
                .device_removal_replayed(
                    &account_id,
                    &token_hash,
                    &removed_device_id,
                    &removed_device_id,
                    &removal_operation_id,
                )
                .await
                .expect("query committed removal")
        );
        let removed_binding_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM device_member_bindings
             WHERE account_id = $1 AND device_id = $2",
        )
        .bind(&account_id)
        .bind(&removed_device_id)
        .fetch_one(&repository.pool)
        .await
        .expect("read binding after device removal");
        assert_eq!(removed_binding_count, 0);

        repository
            .set_device_state(&removed_device_id, DeviceState::Active, now + 7)
            .await
            .expect("simulate device reactivation");
        let reactivated_binding_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM device_member_bindings
             WHERE account_id = $1 AND device_id = $2",
        )
        .bind(&account_id)
        .bind(&removed_device_id)
        .fetch_one(&repository.pool)
        .await
        .expect("read binding after reactivation");
        assert_eq!(
            reactivated_binding_count, 0,
            "reactivation must not resurrect the previous member binding"
        );
        let owner_session_hash = sha256_hex("team-owner-session");
        let recovery = team_repository
            .create_member_device_enrollment(
                &account_id,
                &owner_device_id,
                &owner_session_hash,
                &removable_id,
                TeamOperationRequest {
                    operation_id: uuid::Uuid::new_v4().to_string(),
                },
                now + 8,
            )
            .await
            .expect("create zero-device member recovery");
        let recovered = team_repository
            .accept_device_enrollment(
                &account_id,
                &removed_device_id,
                &token_hash,
                AcceptMemberDeviceEnrollment {
                    operation_id: uuid::Uuid::new_v4().to_string(),
                    enrollment_token: recovery.enrollment_token,
                },
                now + 9,
            )
            .await
            .expect("explicitly rebind the reactivated device");
        let recovered_member = recovered.member.expect("recovered member");
        assert_eq!(recovered_member.id, removable_id);
        assert_eq!(recovered_member.bound_device_count, 1);

        let mut tx = repository.pool.begin().await.expect("begin removal");
        sqlx::query("UPDATE workspace_members SET status = 'removed' WHERE id = $1")
            .bind(&removable_id)
            .execute(&mut *tx)
            .await
            .expect("mark member removed");
        revoke_member_access(&mut tx, &removable_id, now + 10)
            .await
            .expect("revoke member access");
        tx.commit().await.expect("commit member removal");
        let session_active: bool =
            sqlx::query_scalar("SELECT active FROM refresh_sessions WHERE token_hash = $1")
                .bind(&token_hash)
                .fetch_one(&repository.pool)
                .await
                .expect("read revoked session");
        let device_state: String =
            sqlx::query_scalar("SELECT state FROM devices WHERE device_id = $1")
                .bind(&removed_device_id)
                .fetch_one(&repository.pool)
                .await
                .expect("read removed device");
        let binding_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM device_member_bindings WHERE member_id = $1")
                .bind(&removable_id)
                .fetch_one(&repository.pool)
                .await
                .expect("read removed bindings");
        assert!(!session_active);
        assert_eq!(device_state, "removed");
        assert_eq!(binding_count, 0);

        let (owner_row_version, target_row_version): (i64, i64) = sqlx::query_as(
            "SELECT
                (SELECT row_version FROM workspace_members WHERE id = $1),
                (SELECT row_version FROM workspace_members WHERE id = $2)",
        )
        .bind(&owner_id)
        .bind(&transfer_target_id)
        .fetch_one(&repository.pool)
        .await
        .expect("load ownership transfer row versions");
        let transfer_operation_id = uuid::Uuid::new_v4().to_string();
        let transfer_request = TransferWorkspaceOwnership {
            operation_id: transfer_operation_id.clone(),
            new_owner_member_id: transfer_target_id.clone(),
            owner_row_version: u64::try_from(owner_row_version).expect("owner row version"),
            new_owner_row_version: u64::try_from(target_row_version).expect("target row version"),
        };
        let (first_transfer, concurrent_transfer) = tokio::join!(
            team_repository.transfer_ownership(
                &account_id,
                &owner_device_id,
                &owner_session_hash,
                transfer_request.clone(),
                now + 11,
            ),
            team_repository.transfer_ownership(
                &account_id,
                &owner_device_id,
                &owner_session_hash,
                transfer_request,
                now + 11,
            ),
        );
        let first_transfer = first_transfer.expect("first ownership transfer commits");
        let concurrent_transfer = concurrent_transfer
            .expect("concurrent identical ownership transfer replays the committed response");
        assert_eq!(first_transfer, concurrent_transfer);
        assert_eq!(first_transfer.0.role, WorkspaceRole::Admin);
        assert_eq!(first_transfer.1.role, WorkspaceRole::Owner);
        let transfer_audit_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_events
             WHERE account_id = $1 AND event_type = 'team_ownership_transferred'
               AND metadata ->> 'operation_id' = $2",
        )
        .bind(&account_id)
        .bind(&transfer_operation_id)
        .fetch_one(&repository.pool)
        .await
        .expect("count concurrent ownership-transfer audit events");
        assert_eq!(transfer_audit_count, 1);
        let committed_owner_ids: Vec<String> = sqlx::query_scalar(
            "SELECT id FROM workspace_members
             WHERE account_id = $1 AND role = 'owner' ORDER BY id",
        )
        .bind(&account_id)
        .fetch_all(&repository.pool)
        .await
        .expect("read the committed workspace Owner");
        assert_eq!(committed_owner_ids, vec![transfer_target_id]);

        sqlx::query("DELETE FROM accounts WHERE id = $1")
            .bind(&account_id)
            .execute(&repository.pool)
            .await
            .expect("clean up Team repository test");
        repository.close().await;
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn team_token_acceptance_is_idempotent_and_denials_are_audited() {
        let database_url = std::env::var("TEST_DATABASE_URL")
            .expect("TEST_DATABASE_URL is required for the PostgreSQL integration test");
        let repository =
            PostgresRepository::connect(&database_url, 2, std::time::Duration::from_secs(5))
                .await
                .expect("connect PostgreSQL");
        repository.migrate().await.expect("run migrations");
        let team_repository =
            PostgresTeamRepository::new(&repository, WorkspaceKeyring::ephemeral_for_development());

        let suffix = random_id("team_invitation_replay_test");
        let account_id = format!("account_{suffix}");
        let license = License::new(&account_id, Plan::Team);
        let owner_device_id = uuid::Uuid::new_v4().to_string();
        let accepted_device_id = uuid::Uuid::new_v4().to_string();
        let replay_device_id = uuid::Uuid::new_v4().to_string();
        let invalid_token_device_id = uuid::Uuid::new_v4().to_string();
        let now = 1_900_000_000;
        let owner_session_hash = sha256_hex(&format!("team-replay-owner-session-{suffix}"));
        let accepted_session_hash = sha256_hex(&format!("team-replay-accepted-session-{suffix}"));
        let replay_session_hash =
            sha256_hex(&format!("team-replay-additional-device-session-{suffix}"));
        repository
            .upsert_account(Account::active(&account_id, now))
            .await
            .expect("create account");
        repository
            .upsert_license(license.clone())
            .await
            .expect("create Team license");
        for device_id in [
            &owner_device_id,
            &accepted_device_id,
            &replay_device_id,
            &invalid_token_device_id,
        ] {
            repository
                .upsert_device(Device {
                    account_id: account_id.clone(),
                    license_id: license.id.clone(),
                    metadata: DeviceRegistrationMetadata {
                        device_id: device_id.clone(),
                        public_key_pem: "team-invitation-test-public-key".to_owned(),
                        public_key_thumbprint: format!("sha256:{device_id}"),
                        platform: "test".to_owned(),
                        app_version: "1.0.0".to_owned(),
                        display_name: Some("Team invitation test".to_owned()),
                    },
                    state: DeviceState::Active,
                    pending_activation_code_hash: None,
                    pending_activation_expires_at: None,
                    created_at: now,
                    last_seen_at: Some(now),
                })
                .await
                .expect("create device");
        }

        let invalid_token_session_hash =
            sha256_hex(&format!("team-invalid-token-session-{suffix}"));
        repository
            .insert_session(RefreshSessionRecord {
                token_hash: invalid_token_session_hash.clone(),
                account_id: account_id.clone(),
                device_id: invalid_token_device_id.clone(),
                family_id: random_id("team_invalid_token_session_family"),
                family_created_at: now,
                absolute_expires_at: now + 86_400,
                active: true,
                expires_at: now + 3_600,
                rotated_to_hash: None,
                rotated_at: None,
                pending_activation_code_hash: None,
                activation_verified_at: Some(now),
                activation_confirmation_consumed: false,
                proof_state: RefreshSessionProofState::DeviceProven,
            })
            .await
            .expect("create invalid-token device session");
        assert!(matches!(
            team_repository
                .accept_invitation(
                    &account_id,
                    &invalid_token_device_id,
                    &invalid_token_session_hash,
                    AcceptTeamInvitation {
                        operation_id: uuid::Uuid::new_v4().to_string(),
                        invitation_token: "device-enrollment-token-used-in-invitation-field-123456"
                            .to_owned(),
                    },
                    now + 1,
                )
                .await,
            Err(ApiError::TeamInvitationInvalid)
        ));
        assert!(matches!(
            team_repository
                .accept_device_enrollment(
                    &account_id,
                    &invalid_token_device_id,
                    &invalid_token_session_hash,
                    AcceptMemberDeviceEnrollment {
                        operation_id: uuid::Uuid::new_v4().to_string(),
                        enrollment_token: "invitation-token-used-in-device-enrollment-field-123456"
                            .to_owned(),
                    },
                    now + 1,
                )
                .await,
            Err(ApiError::TeamDeviceEnrollmentInvalid)
        ));
        let invalid_token_session_active: bool =
            sqlx::query_scalar("SELECT active FROM refresh_sessions WHERE token_hash = $1")
                .bind(&invalid_token_session_hash)
                .fetch_one(&repository.pool)
                .await
                .expect("read invalid-token device session");
        assert!(invalid_token_session_active);
        let wrong_enrollment_kind_denial: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_events
             WHERE account_id = $1 AND device_id = $2
               AND event_type = 'team_member_device_enrollment_accept_denied'
               AND outcome = 'denied' AND reason_code = 'device_enrollment_not_found'",
        )
        .bind(&account_id)
        .bind(&invalid_token_device_id)
        .fetch_one(&repository.pool)
        .await
        .expect("load wrong-kind device-enrollment denial audit");
        assert_eq!(wrong_enrollment_kind_denial, 1);

        let create_invitation_operation_id = uuid::Uuid::new_v4().to_string();
        let create_invitation_request = CreateTeamInvitation {
            operation_id: create_invitation_operation_id.clone(),
            email: format!("invite-{suffix}@example.test"),
            display_name: "Invitation replay member".to_owned(),
            role: WorkspaceRole::Viewer,
        };
        let invitation = team_repository
            .create_invitation(
                &account_id,
                &owner_device_id,
                &owner_session_hash,
                create_invitation_request.clone(),
                now + 1,
            )
            .await
            .expect("create invitation");
        let invitation_replay = team_repository
            .create_invitation(
                &account_id,
                &owner_device_id,
                &owner_session_hash,
                create_invitation_request,
                now + 2,
            )
            .await
            .expect("replay invitation creation");
        assert_eq!(invitation_replay, invitation);
        let stored_response: (String, Vec<u8>, Vec<u8>) = sqlx::query_as(
            "SELECT response_key_id, response_nonce, response_ciphertext
             FROM team_operations WHERE account_id = $1 AND operation_id = $2",
        )
        .bind(&account_id)
        .bind(&create_invitation_operation_id)
        .fetch_one(&repository.pool)
        .await
        .expect("load encrypted invitation operation response");
        assert!(!stored_response.0.is_empty());
        assert_eq!(stored_response.1.len(), 24);
        assert!(stored_response.2.len() > invitation.invitation_token.len());
        assert!(
            !stored_response
                .2
                .windows(invitation.invitation_token.len())
                .any(|window| window == invitation.invitation_token.as_bytes()),
            "one-time invitation token must not be stored in plaintext",
        );
        assert!(matches!(
            team_repository
                .create_invitation(
                    &account_id,
                    &owner_device_id,
                    &owner_session_hash,
                    CreateTeamInvitation {
                        operation_id: create_invitation_operation_id.clone(),
                        email: format!("invite-{suffix}@example.test"),
                        display_name: "Changed replay content".to_owned(),
                        role: WorkspaceRole::Viewer,
                    },
                    now + 2,
                )
                .await,
            Err(ApiError::IdempotencyConflict)
        ));
        assert!(matches!(
            team_repository
                .leave_operation_status(
                    &account_id,
                    &owner_session_hash,
                    &owner_device_id,
                    &create_invitation_operation_id,
                    &invitation.member.id,
                    invitation.member.row_version,
                )
                .await,
            Err(ApiError::IdempotencyConflict)
        ));
        assert!(matches!(
            team_repository
                .operation_committed_for_device(
                    &account_id,
                    &accepted_device_id,
                    &create_invitation_operation_id,
                )
                .await,
            Err(ApiError::IdempotencyConflict)
        ));
        let invitation_expires_at = invitation.expires_at;
        let invitation_token = invitation.invitation_token.clone();
        let request = AcceptTeamInvitation {
            operation_id: uuid::Uuid::new_v4().to_string(),
            invitation_token: invitation_token.clone(),
        };
        let accepted = team_repository
            .accept_invitation(
                &account_id,
                &accepted_device_id,
                &accepted_session_hash,
                request.clone(),
                now + 2,
            )
            .await
            .expect("accept invitation");
        assert_eq!(
            accepted.member.map(|member| member.id),
            Some(invitation.member.id.clone())
        );
        team_repository
            .accept_invitation(
                &account_id,
                &accepted_device_id,
                &accepted_session_hash,
                request,
                now + 3,
            )
            .await
            .expect("same operation replays its encrypted response");
        team_repository
            .accept_invitation(
                &account_id,
                &accepted_device_id,
                &accepted_session_hash,
                AcceptTeamInvitation {
                    operation_id: uuid::Uuid::new_v4().to_string(),
                    invitation_token: invitation_token.clone(),
                },
                now + 3,
            )
            .await
            .expect("same-device token replay is idempotent");
        assert!(matches!(
            team_repository
                .accept_invitation(
                    &account_id,
                    &replay_device_id,
                    &replay_session_hash,
                    AcceptTeamInvitation {
                        operation_id: uuid::Uuid::new_v4().to_string(),
                        invitation_token: invitation_token.clone(),
                    },
                    now + 4,
                )
                .await,
            Err(ApiError::TeamInvitationInvalid)
        ));
        team_repository
            .accept_invitation(
                &account_id,
                &accepted_device_id,
                &accepted_session_hash,
                AcceptTeamInvitation {
                    operation_id: uuid::Uuid::new_v4().to_string(),
                    invitation_token,
                },
                invitation_expires_at + 1,
            )
            .await
            .expect("same-device invitation replay survives token expiry");

        let denial: (i64, Option<String>) = sqlx::query_as(
            "SELECT COUNT(*), MIN(reason_code)
             FROM audit_events
             WHERE account_id = $1 AND device_id = $2
               AND event_type = 'team_invitation_accept_denied' AND outcome = 'denied'",
        )
        .bind(&account_id)
        .bind(&replay_device_id)
        .fetch_one(&repository.pool)
        .await
        .expect("load invitation denial audit");
        assert_eq!(denial, (1, Some("invitation_already_consumed".to_owned())));

        let create_enrollment_request = TeamOperationRequest {
            operation_id: uuid::Uuid::new_v4().to_string(),
        };
        let enrollment = team_repository
            .create_device_enrollment(
                &account_id,
                &accepted_device_id,
                &accepted_session_hash,
                create_enrollment_request.clone(),
                now + 5,
            )
            .await
            .expect("create additional-device enrollment");
        let enrollment_replay = team_repository
            .create_device_enrollment(
                &account_id,
                &accepted_device_id,
                &accepted_session_hash,
                create_enrollment_request,
                now + 6,
            )
            .await
            .expect("replay additional-device enrollment creation");
        assert_eq!(enrollment_replay, enrollment);
        let enrollment_expires_at = enrollment.expires_at;
        let enrollment_token = enrollment.enrollment_token.clone();
        let enrollment_request = AcceptMemberDeviceEnrollment {
            operation_id: uuid::Uuid::new_v4().to_string(),
            enrollment_token: enrollment_token.clone(),
        };
        let enrolled = team_repository
            .accept_device_enrollment(
                &account_id,
                &replay_device_id,
                &replay_session_hash,
                enrollment_request.clone(),
                now + 6,
            )
            .await
            .expect("accept additional-device enrollment");
        assert_eq!(
            enrolled.member.map(|member| member.id),
            Some(invitation.member.id.clone())
        );
        team_repository
            .accept_device_enrollment(
                &account_id,
                &replay_device_id,
                &replay_session_hash,
                enrollment_request,
                now + 7,
            )
            .await
            .expect("same enrollment operation replays its encrypted response");
        team_repository
            .accept_device_enrollment(
                &account_id,
                &replay_device_id,
                &replay_session_hash,
                AcceptMemberDeviceEnrollment {
                    operation_id: uuid::Uuid::new_v4().to_string(),
                    enrollment_token: enrollment_token.clone(),
                },
                now + 7,
            )
            .await
            .expect("same-device enrollment token replay is idempotent");
        assert!(matches!(
            team_repository
                .accept_device_enrollment(
                    &account_id,
                    &invalid_token_device_id,
                    &invalid_token_session_hash,
                    AcceptMemberDeviceEnrollment {
                        operation_id: uuid::Uuid::new_v4().to_string(),
                        enrollment_token: enrollment_token.clone(),
                    },
                    now + 8,
                )
                .await,
            Err(ApiError::TeamDeviceEnrollmentInvalid)
        ));
        let consumed_enrollment_denial: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_events
             WHERE account_id = $1 AND device_id = $2
               AND event_type = 'team_member_device_enrollment_accept_denied'
               AND outcome = 'denied'
               AND reason_code = 'device_enrollment_already_consumed'",
        )
        .bind(&account_id)
        .bind(&invalid_token_device_id)
        .fetch_one(&repository.pool)
        .await
        .expect("load consumed device-enrollment denial audit");
        assert_eq!(consumed_enrollment_denial, 1);
        team_repository
            .accept_device_enrollment(
                &account_id,
                &replay_device_id,
                &replay_session_hash,
                AcceptMemberDeviceEnrollment {
                    operation_id: uuid::Uuid::new_v4().to_string(),
                    enrollment_token,
                },
                enrollment_expires_at + 1,
            )
            .await
            .expect("same-device enrollment replay survives token expiry");

        let leaving_member = team_repository
            .profile(&account_id, &accepted_device_id, now + 9)
            .await
            .expect("load member before leaving")
            .member
            .expect("accepted device remains bound");
        let leave_operation_id = uuid::Uuid::new_v4().to_string();
        let leave_request = LeaveWorkspace {
            operation_id: leave_operation_id.clone(),
            member_id: leaving_member.id.clone(),
            row_version: leaving_member.row_version,
        };
        let (first_leave, concurrent_leave) = tokio::join!(
            team_repository.leave_workspace(
                &account_id,
                &accepted_device_id,
                &accepted_session_hash,
                leave_request.clone(),
                now + 9,
            ),
            team_repository.leave_workspace(
                &account_id,
                &accepted_device_id,
                &accepted_session_hash,
                leave_request,
                now + 9,
            ),
        );
        first_leave.expect("first leave workspace transaction commits");
        concurrent_leave.expect("concurrent identical leave replays the committed response");
        let leave_audit_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_events
             WHERE account_id = $1 AND event_type = 'team_member_left'
               AND metadata ->> 'operation_id' = $2",
        )
        .bind(&account_id)
        .bind(&leave_operation_id)
        .fetch_one(&repository.pool)
        .await
        .expect("count concurrent leave audit events");
        assert_eq!(leave_audit_count, 1);
        assert!(
            team_repository
                .leave_operation_status(
                    &account_id,
                    &accepted_session_hash,
                    &accepted_device_id,
                    &leave_operation_id,
                    &leaving_member.id,
                    leaving_member.row_version,
                )
                .await
                .expect("revoked original session identity can recover leave status")
        );
        assert!(matches!(
            team_repository
                .leave_operation_status(
                    &account_id,
                    &owner_session_hash,
                    &accepted_device_id,
                    &leave_operation_id,
                    &leaving_member.id,
                    leaving_member.row_version,
                )
                .await,
            Err(ApiError::IdempotencyConflict)
        ));
        assert!(matches!(
            team_repository
                .leave_operation_status(
                    &account_id,
                    &accepted_session_hash,
                    &accepted_device_id,
                    &leave_operation_id,
                    "member_wrong",
                    leaving_member.row_version,
                )
                .await,
            Err(ApiError::IdempotencyConflict)
        ));
        assert!(matches!(
            team_repository
                .leave_operation_status(
                    &account_id,
                    &accepted_session_hash,
                    &accepted_device_id,
                    &leave_operation_id,
                    &leaving_member.id,
                    leaving_member.row_version + 1,
                )
                .await,
            Err(ApiError::IdempotencyConflict)
        ));
        assert!(
            team_repository
                .profile(&account_id, &accepted_device_id, now + 9)
                .await
                .expect("load profile after leaving")
                .member
                .is_none()
        );

        let invalid_invitation = team_repository
            .create_invitation(
                &account_id,
                &owner_device_id,
                &owner_session_hash,
                CreateTeamInvitation {
                    operation_id: uuid::Uuid::new_v4().to_string(),
                    email: format!("invalid-{suffix}@example.test"),
                    display_name: "Invalid-state invitation member".to_owned(),
                    role: WorkspaceRole::Viewer,
                },
                now + 9,
            )
            .await
            .expect("create invalid-state invitation");
        sqlx::query("UPDATE workspace_members SET status = 'removed' WHERE id = $1")
            .bind(&invalid_invitation.member.id)
            .execute(&repository.pool)
            .await
            .expect("simulate an inconsistent invitation member state");
        assert!(matches!(
            team_repository
                .accept_invitation(
                    &account_id,
                    &invalid_token_device_id,
                    &invalid_token_session_hash,
                    AcceptTeamInvitation {
                        operation_id: uuid::Uuid::new_v4().to_string(),
                        invitation_token: invalid_invitation.invitation_token,
                    },
                    now + 10,
                )
                .await,
            Err(ApiError::TeamInvitationInvalid)
        ));
        let invalid_state_denial: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_events
             WHERE account_id = $1 AND device_id = $2
               AND event_type = 'team_invitation_accept_denied' AND outcome = 'denied'
               AND reason_code = 'member_not_invited'",
        )
        .bind(&account_id)
        .bind(&invalid_token_device_id)
        .fetch_one(&repository.pool)
        .await
        .expect("load invalid member-state denial audit");
        assert_eq!(invalid_state_denial, 1);

        sqlx::query("DELETE FROM audit_events WHERE account_id = $1")
            .bind(&account_id)
            .execute(&repository.pool)
            .await
            .expect("delete test audits");
        sqlx::query("DELETE FROM accounts WHERE id = $1")
            .bind(&account_id)
            .execute(&repository.pool)
            .await
            .expect("clean up invitation replay test");
        repository.close().await;
    }
}
