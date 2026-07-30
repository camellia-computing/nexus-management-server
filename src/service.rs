use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicI64, Ordering},
    },
};

use semver::Version;
use sha2::Digest;
use url::Url;

use crate::{
    billing::{
        BillingSummary, CommercialRepository, CustomerPaymentSubmission, ManualPaymentClaim,
    },
    config::canonical_client_version,
    contracts::{
        ActivationProofClaims, ActivationVerificationRequest, ActivationVerificationResponse,
        Capability, ChallengeRequest, ClientVersionPolicy, DeviceActivationConfirmationResponse,
        DeviceChallenge, DeviceProof, DeviceRegistrationRequest, DeviceRegistrationResponse,
        DeviceRemovalRequest, DeviceRemovalStatusResponse, DeviceState, EntitlementClaims,
        EntitlementRefreshRequest, EntitlementRefreshResponse, EntitlementStatusRequest,
        EntitlementStatusResponse, LicenseStanding, Plan, RefreshSession, RegisteredDevice,
        RegisteredDevicePage, RegisteredDevicePageRequest, SessionRecoveryChallengeRequest,
        SessionRecoveryRequest, SessionRecoveryResponse,
    },
    crypto::{
        EntitlementSigner, canonicalize_activation_code, pkce_s256_challenge, random_id,
        random_secret, sha256_hex, verify_device_proof,
    },
    domain::{
        AUTHORIZATION_RESULT_RETRY_SECONDS, Account, ActivationCodeRecord, ActivationCodeStatus,
        AuditEventRecord, AuthorizationCodeRedemption, Device, License, LicenseStatus,
        RefreshSessionProofState, RefreshSessionRecord, StoredAuthorizationCode, StoredChallenge,
    },
    error::{ApiError, Result},
    store::{LicenseRepository, TimeAuthorityStatus},
    team::{
        AcceptMemberDeviceEnrollment, AcceptTeamInvitation, CreateTeamInvitation, LeaveWorkspace,
        MemberDeviceEnrollment, OwnershipTransferResult, TeamInvitation, TeamOperationRequest,
        TeamOperationStatusResponse, TeamProfile, TeamRepository, TransferWorkspaceOwnership,
        UpdateWorkspaceMember, WorkspaceMember,
    },
    time_authority::PersistentTimeAuthority,
    webhooks::{
        CreateWebhookEndpoint, DeleteWebhookEndpoint, PostgresWebhookRepository,
        RotateWebhookSecret, UpdateWebhookEndpoint, WebhookCleanupReport, WebhookDeletion,
        WebhookDeliverySummary, WebhookEndpoint, WebhookSecretResult, WebhookTimeAuthority,
        canonical_webhook_endpoint_id,
    },
    workspace::{
        ALERTS_ACK_SCOPE, ALERTS_MANAGE_SCOPE, ALERTS_READ_SCOPE, AUDIT_EXPORT_SCOPE,
        AUDIT_READ_SCOPE, AdvanceWorkspaceCheckpoint, CreateSharedConfiguration,
        CreateWorkspaceAlertRule, PublishSharedConfiguration, ReviseSharedConfiguration,
        SHARED_PUBLISH_SCOPE, SHARED_PURGE_SCOPE, SHARED_READ_SCOPE, SHARED_WRITE_SCOPE,
        SYNC_READ_SCOPE, SYNC_WRITE_SCOPE, SharedConfigurationContent,
        SharedConfigurationContentRequest, SharedConfigurationPage, SharedConfigurationPageRequest,
        UpdateWorkspaceAlertRule, VersionedWorkspaceMutation, WorkspaceAlertRulePage,
        WorkspaceAlertRulePageRequest, WorkspaceAuditEventTypes, WorkspaceAuditExport,
        WorkspaceAuditPage, WorkspaceAuditPageRequest, WorkspaceDeviceCheckpoint,
        WorkspaceIncidentPage, WorkspaceIncidentPageRequest, WorkspaceMutationReceipt,
        WorkspaceRepository, WorkspaceSyncFeed, WorkspaceSyncFeedRequest,
    },
};

const CHALLENGE_TTL_SECONDS: i64 = 60;
const AUTHORIZATION_CODE_TTL_SECONDS: i64 = 5 * 60;
const PENDING_ACTIVATION_TTL_SECONDS: i64 = 30 * 60;
const REFRESH_SESSION_IDLE_TTL_SECONDS: i64 = 7 * 24 * 60 * 60;
const REFRESH_SESSION_ABSOLUTE_TTL_SECONDS: i64 = 30 * 24 * 60 * 60;
const ENTITLEMENT_TTL_SECONDS: i64 = 6 * 60 * 60;
const ENTITLEMENT_REFRESH_AFTER_SECONDS: i64 = 4 * 60 * 60;
const OAUTH_AUTHORIZATION_SCOPE: &str = "camellia.nexus.license";
const MAX_OAUTH_CLIENT_ID_BYTES: usize = 128;
const MAX_OAUTH_REDIRECT_URI_BYTES: usize = 2 * 1024;
const MAX_OAUTH_SCOPE_BYTES: usize = 64;
const MAX_OAUTH_STATE_BYTES: usize = 128;
const MAX_OAUTH_CODE_CHALLENGE_BYTES: usize = 128;
const MAX_ACTIVATION_CODE_INPUT_BYTES: usize = 256;
const DEFAULT_SCOPE: &str = "entitlement:refresh";
const ENTITLEMENT_STATUS_SCOPE: &str = "entitlement:status";
const ACTIVATION_VERIFY_SCOPE: &str = "activation:verify";
const SESSION_RECOVERY_SCOPE: &str = "session:recover";
const DEVICE_LIST_SCOPE: &str = "device:list";
const BILLING_SUMMARY_SCOPE: &str = "billing:summary";
const BILLING_PAYMENT_SCOPE: &str = "billing:payment:submit";
const TEAM_PROFILE_SCOPE: &str = "team:profile";
const TEAM_MEMBERS_SCOPE: &str = "team:members";
const TEAM_INVITATION_CREATE_SCOPE: &str = "team:invitation:create";
const TEAM_INVITATION_ACCEPT_SCOPE: &str = "team:invitation:accept";
const TEAM_DEVICE_ENROLLMENT_CREATE_SCOPE: &str = "team:device-enrollment:create";
const TEAM_DEVICE_ENROLLMENT_ACCEPT_SCOPE: &str = "team:device-enrollment:accept";
const TEAM_LEAVE_SCOPE: &str = "team:leave";
const TEAM_OWNERSHIP_TRANSFER_SCOPE: &str = "team:ownership:transfer";
const WEBHOOK_LIST_SCOPE: &str = "workspace:webhooks:list";
const WEBHOOK_CREATE_SCOPE: &str = "workspace:webhooks:create";
const WEBHOOK_DELIVERIES_SCOPE: &str = "workspace:webhooks:deliveries";
const DUMMY_DEVICE_PUBLIC_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----\n\
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfM3fUmH4Ow73tI6EajPc8KXQYE2H\n\
1aoMYXO0vuSsFqEzj2ZOLXDf1DxMz6cxmQauKhE9Y1CwcDTPT3fG9T9/Gw==\n\
-----END PUBLIC KEY-----\n";
const RATE_LIMIT_WINDOW_SHORT_SECONDS: i64 = 10 * 60;
const RATE_LIMIT_WINDOW_LONG_SECONDS: i64 = 60 * 60;
const ANONYMOUS_GLOBAL_RATE_LIMIT: u32 = 60_000;
const ANONYMOUS_AUDIT_SAMPLE_SECONDS: i64 = 60;
const DEVICE_LAST_SEEN_WRITE_INTERVAL_SECONDS: i64 = 5 * 60;
const DEFAULT_DEVICE_PAGE_SIZE: u32 = 50;
const MAX_DEVICE_PAGE_SIZE: u32 = 100;

struct AuditRecord<'a> {
    event_type: &'static str,
    outcome: &'static str,
    account_id: Option<&'a str>,
    license_id: Option<&'a str>,
    device_id: Option<&'a str>,
    reason_code: Option<&'a str>,
    metadata: BTreeMap<String, String>,
}

#[derive(Clone)]
pub struct LicenseService {
    repository: Arc<dyn LicenseRepository>,
    commercial_repository: Option<Arc<dyn CommercialRepository>>,
    team_repository: Option<Arc<dyn TeamRepository>>,
    workspace_repository: Option<Arc<WorkspaceRepository>>,
    webhook_repository: Option<Arc<PostgresWebhookRepository>>,
    signer: EntitlementSigner,
    issuer: String,
    audience: String,
    authorization: AuthorizationPolicy,
    clock: Arc<dyn Clock>,
    persistent_time: Option<PersistentTimeAuthority>,
    client_version_policy: ClientVersionPolicy,
    minimum_client_version: Version,
}

#[derive(Debug, Clone)]
pub struct AuthorizationPolicy {
    client_id: String,
    redirect_uris: BTreeSet<String>,
    activation_codes: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthAuthorizationRequest {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub state: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
}

impl AuthorizationPolicy {
    pub fn new(
        client_id: impl Into<String>,
        redirect_uris: impl IntoIterator<Item = String>,
        activation_codes: impl IntoIterator<Item = (String, String)>,
    ) -> Result<Self> {
        let client_id = client_id.into();
        if client_id.trim() != client_id
            || client_id.is_empty()
            || client_id.len() > MAX_OAUTH_CLIENT_ID_BYTES
            || !client_id.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(ApiError::InvalidRequest);
        }
        let redirect_uris = redirect_uris
            .into_iter()
            .map(|uri| uri.trim().to_owned())
            .filter(|uri| !uri.is_empty())
            .collect::<BTreeSet<_>>();
        if redirect_uris.is_empty()
            || redirect_uris
                .iter()
                .any(|uri| uri.len() > MAX_OAUTH_REDIRECT_URI_BYTES || !valid_redirect_uri(uri))
        {
            return Err(ApiError::InvalidRequest);
        }
        let activation_codes = activation_codes
            .into_iter()
            .map(|(code, account_id)| (code.trim().to_owned(), account_id.trim().to_owned()))
            .filter(|(code, account_id)| !code.is_empty() && !account_id.is_empty())
            .collect::<BTreeMap<_, _>>();
        if activation_codes.iter().any(|(code, account_id)| {
            !(8..=MAX_ACTIVATION_CODE_INPUT_BYTES).contains(&code.len())
                || account_id.len() > 128
                || account_id.chars().any(char::is_control)
        }) {
            return Err(ApiError::InvalidRequest);
        }
        Ok(Self {
            client_id,
            redirect_uris,
            activation_codes,
        })
    }

    pub fn development() -> Self {
        Self::new(
            "camellia-nexus-desktop",
            vec!["camellia-nexus://auth/callback".to_owned()],
            vec![("dev-activation-code".to_owned(), "acct_local".to_owned())],
        )
        .expect("development authorization policy")
    }

    fn validate_authorization_request(&self, request: &OAuthAuthorizationRequest) -> Result<()> {
        if request.response_type.len() > 16
            || request.client_id.len() > MAX_OAUTH_CLIENT_ID_BYTES
            || request.redirect_uri.len() > MAX_OAUTH_REDIRECT_URI_BYTES
            || request.scope.len() > MAX_OAUTH_SCOPE_BYTES
            || request.state.len() > MAX_OAUTH_STATE_BYTES
            || request.code_challenge.len() > MAX_OAUTH_CODE_CHALLENGE_BYTES
            || request.code_challenge_method.len() > 16
            || request.response_type != "code"
            || request.client_id != self.client_id
            || request.scope != OAUTH_AUTHORIZATION_SCOPE
            || request.code_challenge_method != "S256"
            || !valid_oauth_state(&request.state)
            || !valid_pkce_s256_challenge(&request.code_challenge)
            || !self.is_allowed_redirect_uri(&request.redirect_uri)
        {
            return Err(ApiError::InvalidRequest);
        }
        Ok(())
    }

    fn is_allowed_redirect_uri(&self, redirect_uri: &str) -> bool {
        self.redirect_uris.contains(redirect_uri)
            || is_loopback_authorization_callback(redirect_uri)
    }

    fn fallback_account_for_activation_code(&self, activation_code: &str) -> Option<String> {
        self.activation_codes.get(activation_code.trim()).cloned()
    }
}

struct ActivationGrant {
    account_id: String,
    license_id: Option<String>,
    activation_code_hash: Option<String>,
}

pub trait Clock: Send + Sync + 'static {
    fn now(&self) -> i64;
}

#[derive(Clone, Default)]
pub struct SystemClock {
    last_seen: Arc<AtomicI64>,
    rollback_reported: Arc<AtomicBool>,
}

impl Clock for SystemClock {
    fn now(&self) -> i64 {
        let wall_clock = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_secs().min(i64::MAX as u64) as i64)
            .unwrap_or(0);
        let previous = self.last_seen.fetch_max(wall_clock, Ordering::AcqRel);
        if previous > wall_clock {
            if !self.rollback_reported.swap(true, Ordering::AcqRel) {
                tracing::error!(
                    previous_unix = previous,
                    wall_clock_unix = wall_clock,
                    "system clock moved backwards; holding license time at its last observed value"
                );
            }
            previous
        } else {
            self.rollback_reported.store(false, Ordering::Release);
            wall_clock
        }
    }
}

impl LicenseService {
    pub async fn readiness_check(&self) -> Result<()> {
        self.repository.readiness_check().await?;
        if let Some(repository) = &self.workspace_repository {
            repository.readiness_check().await?;
        }
        if let Some(repository) = &self.webhook_repository {
            repository.readiness_check().await.map_err(ApiError::from)?;
        }
        self.trusted_now().await.map(|_| ())
    }

    pub async fn shutdown(&self) {
        self.repository.close().await;
    }

    pub fn validate_authorization_request(
        &self,
        request: &OAuthAuthorizationRequest,
    ) -> Result<()> {
        self.authorization.validate_authorization_request(request)
    }

    pub async fn cleanup_expired(&self, batch_size: u32) -> Result<crate::store::CleanupReport> {
        let now = self.trusted_now().await?;
        self.repository.cleanup_expired(now, batch_size).await
    }

    pub async fn cleanup_webhooks(&self, batch_size: u32) -> Result<Option<WebhookCleanupReport>> {
        let Some(repository) = &self.webhook_repository else {
            return Ok(None);
        };
        let now = self.trusted_now().await?;
        repository
            .cleanup_expired(now, batch_size)
            .await
            .map(Some)
            .map_err(ApiError::from)
    }

    pub async fn with_authoritative_time_and_authorization(
        repository: Arc<dyn LicenseRepository>,
        signer: EntitlementSigner,
        issuer: impl Into<String>,
        audience: impl Into<String>,
        max_forward_jump_seconds: i64,
        client_version_policy: ClientVersionPolicy,
        authorization: AuthorizationPolicy,
    ) -> Result<Self> {
        if max_forward_jump_seconds <= 0 {
            return Err(ApiError::InvalidRequest);
        }
        let observation = repository
            .observe_time_authority(None, max_forward_jump_seconds)
            .await?;
        match observation.status {
            TimeAuthorityStatus::ForwardJump => tracing::error!(
                trusted_unix = observation.trusted_unix,
                database_unix = observation.database_unix,
                max_forward_jump_seconds,
                "license service initialized with time authority fail-closed"
            ),
            TimeAuthorityStatus::RollbackHeld => tracing::warn!(
                trusted_unix = observation.trusted_unix,
                database_unix = observation.database_unix,
                "license service initialized while holding a persistent time rollback"
            ),
            TimeAuthorityStatus::Healthy => {}
        }
        client_version_policy.validate()?;
        let minimum_client_version =
            canonical_client_version(&client_version_policy.minimum_version)?;
        Ok(Self {
            repository,
            commercial_repository: None,
            team_repository: None,
            workspace_repository: None,
            webhook_repository: None,
            signer,
            issuer: issuer.into(),
            audience: audience.into(),
            authorization,
            clock: Arc::new(SystemClock::default()),
            persistent_time: Some(PersistentTimeAuthority::new(
                observation.trusted_unix,
                max_forward_jump_seconds,
            )),
            client_version_policy,
            minimum_client_version,
        })
    }

    pub fn new(
        repository: Arc<dyn LicenseRepository>,
        signer: EntitlementSigner,
        issuer: impl Into<String>,
        audience: impl Into<String>,
    ) -> Self {
        Self::with_authorization(
            repository,
            signer,
            issuer,
            audience,
            AuthorizationPolicy::development(),
        )
    }

    pub fn with_authorization(
        repository: Arc<dyn LicenseRepository>,
        signer: EntitlementSigner,
        issuer: impl Into<String>,
        audience: impl Into<String>,
        authorization: AuthorizationPolicy,
    ) -> Self {
        Self::with_clock_and_authorization(
            repository,
            signer,
            issuer,
            audience,
            Arc::new(SystemClock::default()),
            authorization,
        )
    }

    pub fn with_clock(
        repository: Arc<dyn LicenseRepository>,
        signer: EntitlementSigner,
        issuer: impl Into<String>,
        audience: impl Into<String>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self::with_clock_and_authorization(
            repository,
            signer,
            issuer,
            audience,
            clock,
            AuthorizationPolicy::development(),
        )
    }

    pub fn with_clock_and_authorization(
        repository: Arc<dyn LicenseRepository>,
        signer: EntitlementSigner,
        issuer: impl Into<String>,
        audience: impl Into<String>,
        clock: Arc<dyn Clock>,
        authorization: AuthorizationPolicy,
    ) -> Self {
        let client_version_policy = ClientVersionPolicy::development_default();
        let minimum_client_version =
            canonical_client_version(&client_version_policy.minimum_version)
                .expect("the built-in development client-version policy must be valid");
        Self {
            repository,
            commercial_repository: None,
            team_repository: None,
            workspace_repository: None,
            webhook_repository: None,
            signer,
            issuer: issuer.into(),
            audience: audience.into(),
            authorization,
            clock,
            persistent_time: None,
            client_version_policy,
            minimum_client_version,
        }
    }

    pub fn with_clock_authorization_and_client_version_policy(
        repository: Arc<dyn LicenseRepository>,
        signer: EntitlementSigner,
        issuer: impl Into<String>,
        audience: impl Into<String>,
        clock: Arc<dyn Clock>,
        authorization: AuthorizationPolicy,
        client_version_policy: ClientVersionPolicy,
    ) -> Result<Self> {
        client_version_policy.validate()?;
        let minimum_client_version =
            canonical_client_version(&client_version_policy.minimum_version)?;
        Ok(Self {
            repository,
            commercial_repository: None,
            team_repository: None,
            workspace_repository: None,
            webhook_repository: None,
            signer,
            issuer: issuer.into(),
            audience: audience.into(),
            authorization,
            clock,
            persistent_time: None,
            client_version_policy,
            minimum_client_version,
        })
    }

    pub fn with_commercial_repository(mut self, repository: Arc<dyn CommercialRepository>) -> Self {
        self.commercial_repository = Some(repository);
        self
    }

    pub fn with_team_repository(mut self, repository: Arc<dyn TeamRepository>) -> Self {
        self.team_repository = Some(repository);
        self
    }

    pub fn with_workspace_repository(mut self, repository: Arc<WorkspaceRepository>) -> Self {
        self.workspace_repository = Some(repository);
        self
    }

    pub fn with_webhook_repository(mut self, repository: Arc<PostgresWebhookRepository>) -> Self {
        self.webhook_repository = Some(repository);
        self
    }

    pub async fn shared_configurations_authenticated(
        &self,
        session: &RefreshSession,
        proof: &DeviceProof,
        request: SharedConfigurationPageRequest,
    ) -> Result<SharedConfigurationPage> {
        let (repository, session, now) = self
            .authorize_workspace_request(
                session,
                proof,
                SHARED_READ_SCOPE,
                Capability::SharedConfigurations,
            )
            .await?;
        repository
            .shared_configurations(&session.account_id, &session.device_id, request, now)
            .await
    }

    pub async fn shared_configuration_content_authenticated(
        &self,
        session: &RefreshSession,
        proof: &DeviceProof,
        document_id: &str,
        request: SharedConfigurationContentRequest,
    ) -> Result<SharedConfigurationContent> {
        let (repository, session, now) = self
            .authorize_workspace_request(
                session,
                proof,
                SHARED_READ_SCOPE,
                Capability::SharedConfigurations,
            )
            .await?;
        repository
            .shared_configuration_content(
                &session.account_id,
                &session.device_id,
                document_id,
                request,
                now,
            )
            .await
    }

    pub async fn create_shared_configuration_authenticated(
        &self,
        session: &RefreshSession,
        proof: &DeviceProof,
        request: CreateSharedConfiguration,
    ) -> Result<WorkspaceMutationReceipt> {
        let (repository, session, now) = self
            .authorize_workspace_request(
                session,
                proof,
                SHARED_WRITE_SCOPE,
                Capability::SharedConfigurations,
            )
            .await?;
        repository
            .create_shared_configuration(&session.account_id, &session.device_id, request, now)
            .await
    }

    pub async fn revise_shared_configuration_authenticated(
        &self,
        session: &RefreshSession,
        proof: &DeviceProof,
        document_id: &str,
        request: ReviseSharedConfiguration,
    ) -> Result<WorkspaceMutationReceipt> {
        let (repository, session, now) = self
            .authorize_workspace_request(
                session,
                proof,
                SHARED_WRITE_SCOPE,
                Capability::SharedConfigurations,
            )
            .await?;
        repository
            .revise_shared_configuration(
                &session.account_id,
                &session.device_id,
                document_id,
                request,
                now,
            )
            .await
    }

    pub async fn publish_shared_configuration_authenticated(
        &self,
        session: &RefreshSession,
        proof: &DeviceProof,
        document_id: &str,
        request: PublishSharedConfiguration,
    ) -> Result<WorkspaceMutationReceipt> {
        let (repository, session, now) = self
            .authorize_workspace_request(
                session,
                proof,
                SHARED_PUBLISH_SCOPE,
                Capability::SharedConfigurations,
            )
            .await?;
        repository
            .publish_shared_configuration(
                &session.account_id,
                &session.device_id,
                document_id,
                request,
                now,
            )
            .await
    }

    pub async fn delete_shared_configuration_authenticated(
        &self,
        session: &RefreshSession,
        proof: &DeviceProof,
        document_id: &str,
        request: VersionedWorkspaceMutation,
    ) -> Result<WorkspaceMutationReceipt> {
        let (repository, session, now) = self
            .authorize_workspace_request(
                session,
                proof,
                SHARED_WRITE_SCOPE,
                Capability::SharedConfigurations,
            )
            .await?;
        repository
            .delete_shared_configuration(
                &session.account_id,
                &session.device_id,
                document_id,
                request,
                now,
            )
            .await
    }

    pub async fn restore_shared_configuration_authenticated(
        &self,
        session: &RefreshSession,
        proof: &DeviceProof,
        document_id: &str,
        request: VersionedWorkspaceMutation,
    ) -> Result<WorkspaceMutationReceipt> {
        let (repository, session, now) = self
            .authorize_workspace_request(
                session,
                proof,
                SHARED_WRITE_SCOPE,
                Capability::SharedConfigurations,
            )
            .await?;
        repository
            .restore_shared_configuration(
                &session.account_id,
                &session.device_id,
                document_id,
                request,
                now,
            )
            .await
    }

    pub async fn purge_shared_configuration_authenticated(
        &self,
        session: &RefreshSession,
        proof: &DeviceProof,
        document_id: &str,
        request: VersionedWorkspaceMutation,
    ) -> Result<WorkspaceMutationReceipt> {
        let (repository, session, now) = self
            .authorize_workspace_request(
                session,
                proof,
                SHARED_PURGE_SCOPE,
                Capability::SharedConfigurations,
            )
            .await?;
        repository
            .purge_shared_configuration(
                &session.account_id,
                &session.device_id,
                document_id,
                request,
                now,
            )
            .await
    }

    pub async fn workspace_sync_feed_authenticated(
        &self,
        session: &RefreshSession,
        proof: &DeviceProof,
        request: WorkspaceSyncFeedRequest,
    ) -> Result<WorkspaceSyncFeed> {
        let (repository, session, now) = self
            .authorize_workspace_request(session, proof, SYNC_READ_SCOPE, Capability::CloudSync)
            .await?;
        repository
            .sync_feed(&session.account_id, &session.device_id, request, now)
            .await
    }

    pub async fn workspace_device_checkpoint_authenticated(
        &self,
        session: &RefreshSession,
        proof: &DeviceProof,
    ) -> Result<Option<WorkspaceDeviceCheckpoint>> {
        let (repository, session, now) = self
            .authorize_workspace_request(session, proof, SYNC_READ_SCOPE, Capability::CloudSync)
            .await?;
        repository
            .device_checkpoint(&session.account_id, &session.device_id, now)
            .await
    }

    pub async fn advance_workspace_checkpoint_authenticated(
        &self,
        session: &RefreshSession,
        proof: &DeviceProof,
        request: AdvanceWorkspaceCheckpoint,
    ) -> Result<WorkspaceMutationReceipt> {
        let (repository, session, now) = self
            .authorize_workspace_request(session, proof, SYNC_WRITE_SCOPE, Capability::CloudSync)
            .await?;
        repository
            .advance_device_checkpoint(&session.account_id, &session.device_id, request, now)
            .await
    }

    pub async fn workspace_alert_rules_authenticated(
        &self,
        session: &RefreshSession,
        proof: &DeviceProof,
        request: WorkspaceAlertRulePageRequest,
    ) -> Result<WorkspaceAlertRulePage> {
        let (repository, session, now) = self
            .authorize_workspace_request(session, proof, ALERTS_READ_SCOPE, Capability::Alerts)
            .await?;
        repository
            .alert_rules(&session.account_id, &session.device_id, request, now)
            .await
    }

    pub async fn create_workspace_alert_rule_authenticated(
        &self,
        session: &RefreshSession,
        proof: &DeviceProof,
        request: CreateWorkspaceAlertRule,
    ) -> Result<WorkspaceMutationReceipt> {
        let (repository, session, now) = self
            .authorize_workspace_request(session, proof, ALERTS_MANAGE_SCOPE, Capability::Alerts)
            .await?;
        repository
            .create_alert_rule(&session.account_id, &session.device_id, request, now)
            .await
    }

    pub async fn update_workspace_alert_rule_authenticated(
        &self,
        session: &RefreshSession,
        proof: &DeviceProof,
        rule_id: &str,
        request: UpdateWorkspaceAlertRule,
    ) -> Result<WorkspaceMutationReceipt> {
        let (repository, session, now) = self
            .authorize_workspace_request(session, proof, ALERTS_MANAGE_SCOPE, Capability::Alerts)
            .await?;
        repository
            .update_alert_rule(
                &session.account_id,
                &session.device_id,
                rule_id,
                request,
                now,
            )
            .await
    }

    pub async fn delete_workspace_alert_rule_authenticated(
        &self,
        session: &RefreshSession,
        proof: &DeviceProof,
        rule_id: &str,
        request: VersionedWorkspaceMutation,
    ) -> Result<WorkspaceMutationReceipt> {
        let (repository, session, now) = self
            .authorize_workspace_request(session, proof, ALERTS_MANAGE_SCOPE, Capability::Alerts)
            .await?;
        repository
            .delete_alert_rule(
                &session.account_id,
                &session.device_id,
                rule_id,
                request,
                now,
            )
            .await
    }

    pub async fn workspace_alert_incidents_authenticated(
        &self,
        session: &RefreshSession,
        proof: &DeviceProof,
        request: WorkspaceIncidentPageRequest,
    ) -> Result<WorkspaceIncidentPage> {
        let (repository, session, now) = self
            .authorize_workspace_request(session, proof, ALERTS_READ_SCOPE, Capability::Alerts)
            .await?;
        repository
            .alert_incidents(&session.account_id, &session.device_id, request, now)
            .await
    }

    pub async fn acknowledge_workspace_incident_authenticated(
        &self,
        session: &RefreshSession,
        proof: &DeviceProof,
        incident_id: &str,
        request: VersionedWorkspaceMutation,
    ) -> Result<WorkspaceMutationReceipt> {
        let (repository, session, now) = self
            .authorize_workspace_request(session, proof, ALERTS_ACK_SCOPE, Capability::Alerts)
            .await?;
        repository
            .acknowledge_incident(
                &session.account_id,
                &session.device_id,
                incident_id,
                request,
                now,
            )
            .await
    }

    pub async fn resolve_workspace_incident_authenticated(
        &self,
        session: &RefreshSession,
        proof: &DeviceProof,
        incident_id: &str,
        request: VersionedWorkspaceMutation,
    ) -> Result<WorkspaceMutationReceipt> {
        let (repository, session, now) = self
            .authorize_workspace_request(session, proof, ALERTS_MANAGE_SCOPE, Capability::Alerts)
            .await?;
        repository
            .resolve_incident(
                &session.account_id,
                &session.device_id,
                incident_id,
                request,
                now,
            )
            .await
    }

    pub async fn workspace_audit_page_authenticated(
        &self,
        session: &RefreshSession,
        proof: &DeviceProof,
        request: WorkspaceAuditPageRequest,
    ) -> Result<WorkspaceAuditPage> {
        let (repository, session, now) = self
            .authorize_workspace_request(session, proof, AUDIT_READ_SCOPE, Capability::AuditLog)
            .await?;
        repository
            .audit_page(&session.account_id, &session.device_id, request, now)
            .await
    }

    pub async fn workspace_audit_event_types_authenticated(
        &self,
        session: &RefreshSession,
        proof: &DeviceProof,
    ) -> Result<WorkspaceAuditEventTypes> {
        let (repository, session, now) = self
            .authorize_workspace_request(session, proof, AUDIT_READ_SCOPE, Capability::AuditLog)
            .await?;
        repository
            .audit_event_types(&session.account_id, &session.device_id, now)
            .await
    }

    pub async fn workspace_audit_export_authenticated(
        &self,
        session: &RefreshSession,
        proof: &DeviceProof,
        request: WorkspaceAuditPageRequest,
    ) -> Result<WorkspaceAuditExport> {
        let (repository, session, now) = self
            .authorize_workspace_request(session, proof, AUDIT_EXPORT_SCOPE, Capability::AuditLog)
            .await?;
        repository
            .audit_export(&session.account_id, &session.device_id, request, now)
            .await
    }

    pub async fn workspace_webhook_endpoints_authenticated(
        &self,
        session: &RefreshSession,
        proof: &DeviceProof,
    ) -> Result<Vec<WebhookEndpoint>> {
        let (repository, session, now) = self
            .authorize_webhook_request(session, proof, WEBHOOK_LIST_SCOPE)
            .await?;
        repository
            .list_endpoints(&session.account_id, &session.device_id, now)
            .await
            .map_err(ApiError::from)
    }

    pub async fn create_workspace_webhook_endpoint_authenticated(
        &self,
        session: &RefreshSession,
        proof: &DeviceProof,
        request: CreateWebhookEndpoint,
    ) -> Result<WebhookSecretResult> {
        let (repository, session, now) = self
            .authorize_webhook_request(session, proof, WEBHOOK_CREATE_SCOPE)
            .await?;
        repository
            .create_endpoint(&session.account_id, &session.device_id, request, now)
            .await
            .map_err(ApiError::from)
    }

    pub async fn update_workspace_webhook_endpoint_authenticated(
        &self,
        session: &RefreshSession,
        proof: &DeviceProof,
        endpoint_id: &str,
        request: UpdateWebhookEndpoint,
    ) -> Result<WebhookEndpoint> {
        let endpoint_id = canonical_webhook_endpoint_id(endpoint_id).map_err(ApiError::from)?;
        let scope = format!("workspace:webhooks:update:{endpoint_id}");
        let (repository, session, now) = self
            .authorize_webhook_request(session, proof, &scope)
            .await?;
        repository
            .update_endpoint(
                &session.account_id,
                &session.device_id,
                &endpoint_id,
                request,
                now,
            )
            .await
            .map_err(ApiError::from)
    }

    pub async fn rotate_workspace_webhook_secret_authenticated(
        &self,
        session: &RefreshSession,
        proof: &DeviceProof,
        endpoint_id: &str,
        request: RotateWebhookSecret,
    ) -> Result<WebhookSecretResult> {
        let endpoint_id = canonical_webhook_endpoint_id(endpoint_id).map_err(ApiError::from)?;
        let scope = format!("workspace:webhooks:rotate:{endpoint_id}");
        let (repository, session, now) = self
            .authorize_webhook_request(session, proof, &scope)
            .await?;
        repository
            .rotate_endpoint_secret(
                &session.account_id,
                &session.device_id,
                &endpoint_id,
                request,
                now,
            )
            .await
            .map_err(ApiError::from)
    }

    pub async fn delete_workspace_webhook_endpoint_authenticated(
        &self,
        session: &RefreshSession,
        proof: &DeviceProof,
        endpoint_id: &str,
        request: DeleteWebhookEndpoint,
    ) -> Result<WebhookDeletion> {
        let endpoint_id = canonical_webhook_endpoint_id(endpoint_id).map_err(ApiError::from)?;
        let scope = format!("workspace:webhooks:delete:{endpoint_id}");
        let (repository, session, now) = self
            .authorize_webhook_request(session, proof, &scope)
            .await?;
        repository
            .delete_endpoint(
                &session.account_id,
                &session.device_id,
                &endpoint_id,
                request,
                now,
            )
            .await
            .map_err(ApiError::from)
    }

    pub async fn workspace_webhook_deliveries_authenticated(
        &self,
        session: &RefreshSession,
        proof: &DeviceProof,
        endpoint_id: Option<&str>,
        limit: u16,
    ) -> Result<Vec<WebhookDeliverySummary>> {
        let endpoint_id = endpoint_id
            .map(canonical_webhook_endpoint_id)
            .transpose()
            .map_err(ApiError::from)?;
        let scope = endpoint_id.as_ref().map_or_else(
            || WEBHOOK_DELIVERIES_SCOPE.to_owned(),
            |endpoint_id| format!("{WEBHOOK_DELIVERIES_SCOPE}:{endpoint_id}"),
        );
        let (repository, session, now) = self
            .authorize_webhook_request(session, proof, &scope)
            .await?;
        repository
            .list_deliveries(
                &session.account_id,
                &session.device_id,
                endpoint_id.as_deref(),
                limit,
                now,
            )
            .await
            .map_err(ApiError::from)
    }

    pub async fn customer_billing_summary_authenticated(
        &self,
        session: &RefreshSession,
        proof: &DeviceProof,
    ) -> Result<BillingSummary> {
        let now = self.trusted_now().await?;
        let (session, _) = self
            .authorize_sensitive_request(session, proof, BILLING_SUMMARY_SCOPE, now)
            .await?;
        self.require_billing_read_access(&session).await?;
        self.commercial_repository
            .as_ref()
            .ok_or(ApiError::LicenseUnavailable)?
            .customer_billing_summary(&session.account_id, now)
            .await
    }

    pub async fn submit_customer_payment_authenticated(
        &self,
        session: &RefreshSession,
        proof: &DeviceProof,
        submission: CustomerPaymentSubmission,
    ) -> Result<ManualPaymentClaim> {
        let now = self.trusted_now().await?;
        let (session, _) = self
            .authorize_sensitive_request(session, proof, BILLING_PAYMENT_SCOPE, now)
            .await?;
        self.require_billing_manage_access(&session).await?;
        self.enforce_rate_limit(
            now,
            "manual_payment_submission",
            &session.account_id,
            10,
            RATE_LIMIT_WINDOW_LONG_SECONDS,
            AuditRecord {
                event_type: "rate_limit_denied",
                outcome: "denied",
                account_id: Some(&session.account_id),
                license_id: None,
                device_id: Some(&session.device_id),
                reason_code: None,
                metadata: BTreeMap::new(),
            },
        )
        .await?;
        self.commercial_repository
            .as_ref()
            .ok_or(ApiError::LicenseUnavailable)?
            .submit_customer_payment(
                &session.account_id,
                &format!("device:{}", session.device_id),
                submission,
                now,
            )
            .await
    }

    pub async fn team_profile_authenticated(
        &self,
        session: &RefreshSession,
        proof: &DeviceProof,
    ) -> Result<TeamProfile> {
        let now = self.trusted_now().await?;
        let (session, device) = self
            .authorize_sensitive_request(session, proof, TEAM_PROFILE_SCOPE, now)
            .await?;
        self.require_team_access(&device, now).await?;
        self.team_repository
            .as_ref()
            .ok_or(ApiError::LicenseUnavailable)?
            .profile(&session.account_id, &session.device_id, now)
            .await
    }

    pub async fn team_leave_operation_status(
        &self,
        session: &RefreshSession,
        operation_id: &str,
        member_id: &str,
        row_version: u64,
    ) -> Result<TeamOperationStatusResponse> {
        if session.0.len() < 24
            || !valid_operation_id(operation_id)
            || row_version == 0
            || !member_id.starts_with("member_")
            || member_id.len() > 128
            || !member_id
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err(ApiError::InvalidRequest);
        }
        let requester_session_hash = sha256_hex(&session.0);
        let previous_session = self
            .repository
            .session_by_hash(&requester_session_hash)
            .await?
            .ok_or(ApiError::AuthorizationRequired)?;
        let committed = self
            .team_repository
            .as_ref()
            .ok_or(ApiError::LicenseUnavailable)?
            .leave_operation_status(
                &previous_session.account_id,
                &requester_session_hash,
                &previous_session.device_id,
                operation_id,
                member_id,
                row_version,
            )
            .await?;
        Ok(TeamOperationStatusResponse { committed })
    }

    pub async fn team_members_authenticated(
        &self,
        session: &RefreshSession,
        proof: &DeviceProof,
        request: crate::team::TeamMemberPageRequest,
    ) -> Result<crate::team::TeamMemberPage> {
        let now = self.trusted_now().await?;
        let (session, device) = self
            .authorize_sensitive_request(session, proof, TEAM_MEMBERS_SCOPE, now)
            .await?;
        self.require_team_access(&device, now).await?;
        self.team_repository
            .as_ref()
            .ok_or(ApiError::LicenseUnavailable)?
            .members(&session.account_id, &session.device_id, request)
            .await
    }

    pub async fn create_team_invitation_authenticated(
        &self,
        session: &RefreshSession,
        proof: &DeviceProof,
        request: CreateTeamInvitation,
    ) -> Result<TeamInvitation> {
        let now = self.trusted_now().await?;
        let (session, device) = self
            .authorize_sensitive_request(session, proof, TEAM_INVITATION_CREATE_SCOPE, now)
            .await?;
        self.require_team_access(&device, now).await?;
        let repository = self
            .team_repository
            .as_ref()
            .ok_or(ApiError::LicenseUnavailable)?;
        if !repository
            .operation_committed_for_device(
                &session.account_id,
                &session.device_id,
                &request.operation_id,
            )
            .await?
        {
            self.enforce_rate_limit(
                now,
                "team_invitation",
                &session.account_id,
                20,
                RATE_LIMIT_WINDOW_LONG_SECONDS,
                AuditRecord {
                    event_type: "rate_limit_denied",
                    outcome: "denied",
                    account_id: Some(&session.account_id),
                    license_id: None,
                    device_id: Some(&session.device_id),
                    reason_code: None,
                    metadata: BTreeMap::new(),
                },
            )
            .await?;
        }
        repository
            .create_invitation(
                &session.account_id,
                &session.device_id,
                &session.token_hash,
                request,
                now,
            )
            .await
    }

    pub async fn accept_team_invitation_authenticated(
        &self,
        session: &RefreshSession,
        proof: &DeviceProof,
        request: AcceptTeamInvitation,
    ) -> Result<TeamProfile> {
        let now = self.trusted_now().await?;
        let (session, device) = self
            .authorize_sensitive_request(session, proof, TEAM_INVITATION_ACCEPT_SCOPE, now)
            .await?;
        self.require_team_access(&device, now).await?;
        let repository = self
            .team_repository
            .as_ref()
            .ok_or(ApiError::LicenseUnavailable)?;
        if !repository
            .operation_committed_for_device(
                &session.account_id,
                &session.device_id,
                &request.operation_id,
            )
            .await?
        {
            self.enforce_rate_limit(
                now,
                "team_invitation_accept",
                &session.device_id,
                10,
                RATE_LIMIT_WINDOW_LONG_SECONDS,
                AuditRecord {
                    event_type: "rate_limit_denied",
                    outcome: "denied",
                    account_id: Some(&session.account_id),
                    license_id: None,
                    device_id: Some(&session.device_id),
                    reason_code: None,
                    metadata: BTreeMap::new(),
                },
            )
            .await?;
        }
        repository
            .accept_invitation(
                &session.account_id,
                &session.device_id,
                &session.token_hash,
                request,
                now,
            )
            .await
    }

    pub async fn update_team_member_authenticated(
        &self,
        session: &RefreshSession,
        proof: &DeviceProof,
        member_id: &str,
        request: UpdateWorkspaceMember,
    ) -> Result<WorkspaceMember> {
        let now = self.trusted_now().await?;
        let scope = team_member_update_scope(member_id)?;
        let (session, device) = self
            .authorize_sensitive_request(session, proof, &scope, now)
            .await?;
        self.require_team_access(&device, now).await?;
        self.team_repository
            .as_ref()
            .ok_or(ApiError::LicenseUnavailable)?
            .update_member(
                &session.account_id,
                &session.device_id,
                &session.token_hash,
                member_id,
                request,
                now,
            )
            .await
    }

    pub async fn create_team_device_enrollment_authenticated(
        &self,
        session: &RefreshSession,
        proof: &DeviceProof,
        request: TeamOperationRequest,
    ) -> Result<MemberDeviceEnrollment> {
        let now = self.trusted_now().await?;
        let (session, device) = self
            .authorize_sensitive_request(session, proof, TEAM_DEVICE_ENROLLMENT_CREATE_SCOPE, now)
            .await?;
        self.require_team_access(&device, now).await?;
        let repository = self
            .team_repository
            .as_ref()
            .ok_or(ApiError::LicenseUnavailable)?;
        if !repository
            .operation_committed_for_device(
                &session.account_id,
                &session.device_id,
                &request.operation_id,
            )
            .await?
        {
            self.enforce_rate_limit(
                now,
                "team_device_enrollment",
                &session.account_id,
                10,
                RATE_LIMIT_WINDOW_LONG_SECONDS,
                AuditRecord {
                    event_type: "rate_limit_denied",
                    outcome: "denied",
                    account_id: Some(&session.account_id),
                    license_id: None,
                    device_id: Some(&session.device_id),
                    reason_code: None,
                    metadata: BTreeMap::new(),
                },
            )
            .await?;
        }
        repository
            .create_device_enrollment(
                &session.account_id,
                &session.device_id,
                &session.token_hash,
                request,
                now,
            )
            .await
    }

    pub async fn create_team_member_device_enrollment_authenticated(
        &self,
        session: &RefreshSession,
        proof: &DeviceProof,
        member_id: &str,
        request: TeamOperationRequest,
    ) -> Result<MemberDeviceEnrollment> {
        let now = self.trusted_now().await?;
        let scope = team_member_device_enrollment_scope(member_id)?;
        let (session, device) = self
            .authorize_sensitive_request(session, proof, &scope, now)
            .await?;
        self.require_team_access(&device, now).await?;
        let repository = self
            .team_repository
            .as_ref()
            .ok_or(ApiError::LicenseUnavailable)?;
        if !repository
            .operation_committed_for_device(
                &session.account_id,
                &session.device_id,
                &request.operation_id,
            )
            .await?
        {
            self.enforce_rate_limit(
                now,
                "team_member_device_enrollment",
                &session.account_id,
                10,
                RATE_LIMIT_WINDOW_LONG_SECONDS,
                AuditRecord {
                    event_type: "rate_limit_denied",
                    outcome: "denied",
                    account_id: Some(&session.account_id),
                    license_id: None,
                    device_id: Some(&session.device_id),
                    reason_code: None,
                    metadata: BTreeMap::new(),
                },
            )
            .await?;
        }
        repository
            .create_member_device_enrollment(
                &session.account_id,
                &session.device_id,
                &session.token_hash,
                member_id,
                request,
                now,
            )
            .await
    }

    pub async fn accept_team_device_enrollment_authenticated(
        &self,
        session: &RefreshSession,
        proof: &DeviceProof,
        request: AcceptMemberDeviceEnrollment,
    ) -> Result<TeamProfile> {
        let now = self.trusted_now().await?;
        let (session, device) = self
            .authorize_sensitive_request(session, proof, TEAM_DEVICE_ENROLLMENT_ACCEPT_SCOPE, now)
            .await?;
        self.require_team_access(&device, now).await?;
        let repository = self
            .team_repository
            .as_ref()
            .ok_or(ApiError::LicenseUnavailable)?;
        if !repository
            .operation_committed_for_device(
                &session.account_id,
                &session.device_id,
                &request.operation_id,
            )
            .await?
        {
            self.enforce_rate_limit(
                now,
                "team_device_enrollment_accept",
                &session.device_id,
                10,
                RATE_LIMIT_WINDOW_LONG_SECONDS,
                AuditRecord {
                    event_type: "rate_limit_denied",
                    outcome: "denied",
                    account_id: Some(&session.account_id),
                    license_id: None,
                    device_id: Some(&session.device_id),
                    reason_code: None,
                    metadata: BTreeMap::new(),
                },
            )
            .await?;
        }
        repository
            .accept_device_enrollment(
                &session.account_id,
                &session.device_id,
                &session.token_hash,
                request,
                now,
            )
            .await
    }

    pub async fn leave_team_workspace_authenticated(
        &self,
        session: &RefreshSession,
        proof: &DeviceProof,
        request: LeaveWorkspace,
    ) -> Result<()> {
        let now = self.trusted_now().await?;
        let (session, device) = self
            .authorize_sensitive_request(session, proof, TEAM_LEAVE_SCOPE, now)
            .await?;
        self.require_team_access(&device, now).await?;
        self.team_repository
            .as_ref()
            .ok_or(ApiError::LicenseUnavailable)?
            .leave_workspace(
                &session.account_id,
                &session.device_id,
                &session.token_hash,
                request,
                now,
            )
            .await
    }

    pub async fn transfer_team_ownership_authenticated(
        &self,
        session: &RefreshSession,
        proof: &DeviceProof,
        request: TransferWorkspaceOwnership,
    ) -> Result<OwnershipTransferResult> {
        let now = self.trusted_now().await?;
        let scope = normalize_scope(&format!(
            "{TEAM_OWNERSHIP_TRANSFER_SCOPE}:{}",
            request.new_owner_member_id
        ))?;
        let (session, device) = self
            .authorize_sensitive_request(session, proof, &scope, now)
            .await?;
        self.require_team_access(&device, now).await?;
        let (previous_owner, new_owner) = self
            .team_repository
            .as_ref()
            .ok_or(ApiError::LicenseUnavailable)?
            .transfer_ownership(
                &session.account_id,
                &session.device_id,
                &session.token_hash,
                request,
                now,
            )
            .await?;
        Ok(OwnershipTransferResult {
            previous_owner,
            new_owner,
        })
    }

    async fn require_billing_read_access(&self, session: &RefreshSessionRecord) -> Result<()> {
        let allowed = self
            .team_repository
            .as_ref()
            .ok_or(ApiError::LicenseUnavailable)?
            .can_read_billing(&session.account_id, &session.device_id)
            .await?;
        if allowed {
            Ok(())
        } else {
            Err(ApiError::PermissionDenied)
        }
    }

    async fn require_billing_manage_access(&self, session: &RefreshSessionRecord) -> Result<()> {
        let allowed = self
            .team_repository
            .as_ref()
            .ok_or(ApiError::LicenseUnavailable)?
            .can_manage_billing(&session.account_id, &session.device_id)
            .await?;
        if allowed {
            Ok(())
        } else {
            Err(ApiError::PermissionDenied)
        }
    }

    async fn require_team_access(&self, device: &Device, now: i64) -> Result<()> {
        self.require_capability_access(device, now, Capability::TeamAdministration)
            .await
    }

    async fn require_capability_access(
        &self,
        device: &Device,
        now: i64,
        capability: Capability,
    ) -> Result<()> {
        let license = self
            .repository
            .license(&device.license_id)
            .await?
            .ok_or(ApiError::LicenseUnavailable)?;
        ensure_license_active(&license, now)?;
        if license
            .effective_policy()?
            .capabilities
            .contains(&capability)
        {
            Ok(())
        } else {
            Err(ApiError::CapabilityDenied)
        }
    }

    async fn authorize_workspace_request(
        &self,
        session: &RefreshSession,
        proof: &DeviceProof,
        scope: &str,
        capability: Capability,
    ) -> Result<(Arc<WorkspaceRepository>, RefreshSessionRecord, i64)> {
        let now = self.trusted_now().await?;
        let (session, device) = self
            .authorize_sensitive_request(session, proof, scope, now)
            .await?;
        self.require_capability_access(&device, now, capability)
            .await?;
        let repository = self
            .workspace_repository
            .as_ref()
            .cloned()
            .ok_or(ApiError::CapabilityDenied)?;
        Ok((repository, session, now))
    }

    async fn authorize_webhook_request(
        &self,
        session: &RefreshSession,
        proof: &DeviceProof,
        scope: &str,
    ) -> Result<(Arc<PostgresWebhookRepository>, RefreshSessionRecord, i64)> {
        let now = self.trusted_now().await?;
        let (session, device) = self
            .authorize_sensitive_request(session, proof, scope, now)
            .await?;
        self.require_capability_access(&device, now, Capability::Webhooks)
            .await?;
        let repository = self
            .webhook_repository
            .as_ref()
            .cloned()
            .ok_or(ApiError::CapabilityDenied)?;
        Ok((repository, session, now))
    }

    async fn authorize_sensitive_request(
        &self,
        session: &RefreshSession,
        proof: &DeviceProof,
        expected_scope: &str,
        now: i64,
    ) -> Result<(RefreshSessionRecord, Device)> {
        let session = self.authorize_session(session, now, false).await?;
        Self::require_proven_session(&session)?;
        if session.device_id != proof.device_id {
            return Err(ApiError::AuthorizationRequired);
        }
        let device = self.require_active_device(&session.device_id).await?;
        let stored = self
            .repository
            .consume_challenge(&proof.challenge_id, &device.metadata.device_id, now)
            .await?;
        let challenge = DeviceChallenge {
            challenge_id: stored.challenge_id,
            nonce: stored.nonce,
            requested_scope: stored.requested_scope,
            issued_at: stored.issued_at,
            expires_at: stored.expires_at,
        };
        if challenge.requested_scope != expected_scope {
            return Err(ApiError::InvalidChallenge);
        }
        verify_device_proof(
            &device.metadata.public_key_pem,
            &challenge,
            proof,
            &device.metadata.device_id,
            now,
        )?;
        self.enforce_verified_client_version(&device, &proof.app_version, now)
            .await?;
        Ok((session, device))
    }

    async fn trusted_now(&self) -> Result<i64> {
        let Some(authority) = &self.persistent_time else {
            return Ok(self.clock.now());
        };
        let observation = self
            .repository
            .observe_time_authority(Some(authority.now()), authority.max_forward_jump_seconds)
            .await?;
        authority.observe(observation.trusted_unix);
        if observation.status == TimeAuthorityStatus::ForwardJump {
            Err(ApiError::TimeAuthorityUnavailable)
        } else {
            Ok(observation.trusted_unix)
        }
    }

    async fn enforce_rate_limit(
        &self,
        now: i64,
        scope: &'static str,
        key: &str,
        max_count: u32,
        window_seconds: i64,
        audit: AuditRecord<'_>,
    ) -> Result<()> {
        if self
            .repository
            .consume_rate_limit(scope, &sha256_hex(key), now, max_count, window_seconds)
            .await?
        {
            return Ok(());
        }
        tracing::warn!(
            rate_limit_scope = scope,
            account_id = audit.account_id.unwrap_or(""),
            license_id = audit.license_id.unwrap_or(""),
            device_id = audit.device_id.unwrap_or(""),
            "license service rate limit denied request"
        );
        let audit_key = format!("{scope}:{key}");
        let persist_denial = self
            .repository
            .consume_rate_limit(
                "rate_limit_denial_audit",
                &sha256_hex(&audit_key),
                now,
                1,
                window_seconds,
            )
            .await
            .unwrap_or(false);
        if persist_denial {
            let mut metadata = audit.metadata;
            metadata.insert("rate_limit_scope".to_owned(), scope.to_owned());
            metadata.insert("window_seconds".to_owned(), window_seconds.to_string());
            metadata.insert("max_count".to_owned(), max_count.to_string());
            self.record_audit(
                now,
                AuditRecord {
                    event_type: "rate_limit_denied",
                    outcome: "denied",
                    account_id: audit.account_id,
                    license_id: audit.license_id,
                    device_id: audit.device_id,
                    reason_code: Some(scope),
                    metadata,
                },
            )
            .await;
        }
        Err(ApiError::TooManyRequests)
    }

    async fn record_audit(&self, now: i64, record: AuditRecord<'_>) {
        let event = Self::audit_event(now, record);
        Self::log_audit(&event);
        if let Err(error) = self.repository.insert_audit_event(event).await {
            tracing::warn!(%error, "could not persist license audit event");
        }
    }

    async fn record_anonymous_audit_sample(&self, now: i64, record: AuditRecord<'_>) {
        let key = format!(
            "{}:{}",
            record.event_type,
            record.reason_code.unwrap_or("unspecified")
        );
        let should_persist = self
            .repository
            .consume_rate_limit(
                "anonymous_audit_sample",
                &sha256_hex(&key),
                now,
                1,
                ANONYMOUS_AUDIT_SAMPLE_SECONDS,
            )
            .await
            .unwrap_or(false);
        if should_persist {
            self.record_audit(now, record).await;
        } else {
            tracing::debug!(
                audit_event = record.event_type,
                reason_code = record.reason_code.unwrap_or(""),
                "suppressed repeated anonymous denial audit"
            );
        }
    }

    async fn touch_device_last_seen(&self, device_id: &str, now: i64) {
        if let Err(error) = self
            .repository
            .touch_device_last_seen(device_id, now, DEVICE_LAST_SEEN_WRITE_INTERVAL_SECONDS)
            .await
        {
            tracing::warn!(%error, %device_id, "could not update device last-seen time");
        }
    }

    fn enforce_client_version(&self, app_version: &str, now: i64) -> Result<()> {
        let version = canonical_client_version(app_version)?;
        self.enforce_parsed_client_version(&version, now)
    }

    fn enforce_parsed_client_version(&self, version: &Version, now: i64) -> Result<()> {
        if now >= self.client_version_policy.enforce_after && version < &self.minimum_client_version
        {
            Err(ApiError::ClientUpgradeRequired(
                self.client_version_policy.clone(),
            ))
        } else {
            Ok(())
        }
    }

    async fn record_verified_client_version(
        &self,
        device: &Device,
        app_version: &str,
        now: i64,
    ) -> Result<Version> {
        let version = canonical_client_version(app_version)?;
        self.repository
            .update_device_client_metadata(&device.metadata.device_id, app_version, now)
            .await?;
        Ok(version)
    }

    async fn enforce_verified_client_version(
        &self,
        device: &Device,
        app_version: &str,
        now: i64,
    ) -> Result<Version> {
        let version = self
            .record_verified_client_version(device, app_version, now)
            .await?;
        let result = self.enforce_parsed_client_version(&version, now);
        if let Err(error) = result {
            self.record_audit(
                now,
                AuditRecord {
                    event_type: "client_version_denied",
                    outcome: "denied",
                    account_id: Some(&device.account_id),
                    license_id: Some(&device.license_id),
                    device_id: Some(&device.metadata.device_id),
                    reason_code: Some(error.code()),
                    metadata: BTreeMap::from([
                        ("app_version".to_owned(), app_version.to_owned()),
                        (
                            "minimum_version".to_owned(),
                            self.client_version_policy.minimum_version.clone(),
                        ),
                        (
                            "recommended_version".to_owned(),
                            self.client_version_policy.recommended_version.clone(),
                        ),
                        (
                            "enforce_after".to_owned(),
                            self.client_version_policy.enforce_after.to_string(),
                        ),
                    ]),
                },
            )
            .await;
            return Err(error);
        }
        Ok(version)
    }

    async fn enforce_recorded_client_version(&self, device: &Device, now: i64) -> Result<()> {
        if let Err(error) = self.enforce_client_version(&device.metadata.app_version, now) {
            self.record_audit(
                now,
                AuditRecord {
                    event_type: "client_version_denied",
                    outcome: "denied",
                    account_id: Some(&device.account_id),
                    license_id: Some(&device.license_id),
                    device_id: Some(&device.metadata.device_id),
                    reason_code: Some(error.code()),
                    metadata: BTreeMap::from([(
                        "app_version".to_owned(),
                        device.metadata.app_version.clone(),
                    )]),
                },
            )
            .await;
            return Err(error);
        }
        Ok(())
    }

    fn audit_event(now: i64, record: AuditRecord<'_>) -> AuditEventRecord {
        AuditEventRecord {
            id: random_id("audit"),
            event_type: record.event_type.to_owned(),
            outcome: record.outcome.to_owned(),
            occurred_at: now,
            account_id: record.account_id.map(str::to_owned),
            license_id: record.license_id.map(str::to_owned),
            device_id: record.device_id.map(str::to_owned),
            reason_code: record.reason_code.map(str::to_owned),
            metadata: record.metadata,
        }
    }

    fn log_audit(event: &AuditEventRecord) {
        tracing::info!(
            audit_event = %event.event_type,
            outcome = %event.outcome,
            account_id = event.account_id.as_deref().unwrap_or(""),
            license_id = event.license_id.as_deref().unwrap_or(""),
            device_id = event.device_id.as_deref().unwrap_or(""),
            reason_code = event.reason_code.as_deref().unwrap_or(""),
            "license audit event"
        );
    }

    pub async fn create_authorization_redirect(
        &self,
        activation_code: &str,
        request: OAuthAuthorizationRequest,
    ) -> Result<String> {
        let now = self.trusted_now().await?;
        self.enforce_rate_limit(
            now,
            "authorization_code_global",
            "global",
            ANONYMOUS_GLOBAL_RATE_LIMIT,
            RATE_LIMIT_WINDOW_SHORT_SECONDS,
            AuditRecord {
                event_type: "rate_limit_denied",
                outcome: "denied",
                account_id: None,
                license_id: None,
                device_id: None,
                reason_code: None,
                metadata: BTreeMap::new(),
            },
        )
        .await?;
        if let Err(error) = self
            .authorization
            .validate_authorization_request(&request)
            .and_then(|_| {
                (activation_code.len() <= MAX_ACTIVATION_CODE_INPUT_BYTES)
                    .then_some(())
                    .ok_or(ApiError::InvalidRequest)
            })
        {
            self.record_anonymous_audit_sample(
                now,
                AuditRecord {
                    event_type: "authorization_code_denied",
                    outcome: "denied",
                    account_id: None,
                    license_id: None,
                    device_id: None,
                    reason_code: Some(error.code()),
                    metadata: authorization_request_metadata(&request),
                },
            )
            .await;
            return Err(error);
        }
        let activation_hash = sha256_hex(
            &canonicalize_activation_code(activation_code)
                .unwrap_or_else(|| activation_code.trim().to_owned()),
        );
        self.enforce_rate_limit(
            now,
            "authorization_code",
            &activation_hash,
            20,
            RATE_LIMIT_WINDOW_SHORT_SECONDS,
            AuditRecord {
                event_type: "rate_limit_denied",
                outcome: "denied",
                account_id: None,
                license_id: None,
                device_id: None,
                reason_code: None,
                metadata: BTreeMap::new(),
            },
        )
        .await?;
        let grant = self.activation_grant(activation_code, now).await?;
        let code = random_secret();
        let stored_code = StoredAuthorizationCode {
            code_hash: sha256_hex(&code),
            account_id: grant.account_id.clone(),
            license_id: grant.license_id.clone(),
            activation_code_hash: grant.activation_code_hash.clone(),
            code_challenge: request.code_challenge.clone(),
            redirect_uri: request.redirect_uri.clone(),
            expires_at: now + AUTHORIZATION_CODE_TTL_SECONDS,
            consumed: false,
            consumed_at: None,
            consumed_device_id: None,
            consumed_key_thumbprint: None,
        };
        let success_audit = Self::audit_event(
            now,
            AuditRecord {
                event_type: "authorization_code_issued",
                outcome: "succeeded",
                account_id: Some(&grant.account_id),
                license_id: grant.license_id.as_deref(),
                device_id: None,
                reason_code: None,
                metadata: BTreeMap::new(),
            },
        );
        self.repository
            .insert_authorization_code_with_audit(stored_code, success_audit.clone())
            .await?;
        let mut redirect =
            Url::parse(&request.redirect_uri).map_err(|_| ApiError::InvalidRequest)?;
        redirect
            .query_pairs_mut()
            .append_pair("code", &code)
            .append_pair("state", &request.state);
        tracing::info!(account_id = %grant.account_id, "authorization code issued");
        Self::log_audit(&success_audit);
        Ok(redirect.to_string())
    }

    pub async fn register_device(
        &self,
        request: DeviceRegistrationRequest,
    ) -> Result<DeviceRegistrationResponse> {
        let now = self.trusted_now().await?;
        self.enforce_rate_limit(
            now,
            "device_registration_global",
            "global",
            ANONYMOUS_GLOBAL_RATE_LIMIT,
            RATE_LIMIT_WINDOW_SHORT_SECONDS,
            AuditRecord {
                event_type: "rate_limit_denied",
                outcome: "denied",
                account_id: None,
                license_id: None,
                device_id: None,
                reason_code: None,
                metadata: BTreeMap::new(),
            },
        )
        .await?;
        if let Err(error) = validate_registration_request(&request) {
            self.record_anonymous_audit_sample(
                now,
                AuditRecord {
                    event_type: "device_registration_denied",
                    outcome: "denied",
                    account_id: None,
                    license_id: None,
                    device_id: non_empty_str(&request.device.device_id),
                    reason_code: Some(error.code()),
                    metadata: registration_metadata(&request),
                },
            )
            .await;
            return Err(error);
        }
        if let Err(error) = self.enforce_client_version(&request.device.app_version, now) {
            self.record_anonymous_audit_sample(
                now,
                AuditRecord {
                    event_type: "device_registration_denied",
                    outcome: "denied",
                    account_id: None,
                    license_id: None,
                    device_id: Some(&request.device.device_id),
                    reason_code: Some(error.code()),
                    metadata: registration_metadata(&request),
                },
            )
            .await;
            return Err(error);
        }
        self.enforce_rate_limit(
            now,
            "device_registration",
            &request.device.device_id,
            30,
            RATE_LIMIT_WINDOW_LONG_SECONDS,
            AuditRecord {
                event_type: "rate_limit_denied",
                outcome: "denied",
                account_id: None,
                license_id: None,
                device_id: Some(&request.device.device_id),
                reason_code: None,
                metadata: BTreeMap::from([(
                    "platform".to_owned(),
                    request.device.platform.clone(),
                )]),
            },
        )
        .await?;
        let (authorization, authorization_redemption) =
            match self.validate_authorization_code(&request, now).await {
                Ok(authorization) => authorization,
                Err(error) => {
                    self.record_anonymous_audit_sample(
                        now,
                        AuditRecord {
                            event_type: "device_registration_denied",
                            outcome: "denied",
                            account_id: None,
                            license_id: None,
                            device_id: Some(&request.device.device_id),
                            reason_code: Some("authorization_code_invalid"),
                            metadata: registration_metadata(&request),
                        },
                    )
                    .await;
                    return Err(error);
                }
            };
        let pending_activation_code_hash = authorization.activation_code_hash.clone();
        if let Some(activation_code_hash) = &pending_activation_code_hash {
            let Some(activation) = self
                .repository
                .activation_code_by_hash(activation_code_hash)
                .await?
            else {
                self.record_audit(
                    now,
                    AuditRecord {
                        event_type: "device_registration_denied",
                        outcome: "denied",
                        account_id: Some(&authorization.account_id),
                        license_id: authorization.license_id.as_deref(),
                        device_id: Some(&request.device.device_id),
                        reason_code: Some(ApiError::ActivationCodeInvalid.code()),
                        metadata: registration_metadata(&request),
                    },
                )
                .await;
                return Err(ApiError::ActivationCodeInvalid);
            };
            let activation_error = if activation.account_id != authorization.account_id
                || activation.license_id != authorization.license_id
            {
                Some(ApiError::ActivationCodeInvalid)
            } else if !activation.is_usable(now) {
                Some(activation_code_error(&activation, now))
            } else {
                None
            };
            if let Some(error) = activation_error {
                let mut metadata = registration_metadata(&request);
                metadata.extend(activation_code_metadata(&activation, now));
                self.record_audit(
                    now,
                    AuditRecord {
                        event_type: "device_registration_denied",
                        outcome: "denied",
                        account_id: Some(&authorization.account_id),
                        license_id: authorization.license_id.as_deref(),
                        device_id: Some(&request.device.device_id),
                        reason_code: Some(error.code()),
                        metadata,
                    },
                )
                .await;
                return Err(error);
            }
        }
        let account = match self.repository.account(&authorization.account_id).await? {
            Some(account) => {
                if let Err(error) = ensure_account_active(&account) {
                    self.record_audit(
                        now,
                        AuditRecord {
                            event_type: "device_registration_denied",
                            outcome: "denied",
                            account_id: Some(&authorization.account_id),
                            license_id: authorization.license_id.as_deref(),
                            device_id: Some(&request.device.device_id),
                            reason_code: Some(error.code()),
                            metadata: registration_metadata(&request),
                        },
                    )
                    .await;
                    return Err(error);
                }
                account
            }
            None => {
                let account = Account::active(authorization.account_id.clone(), now);
                self.repository.upsert_account(account.clone()).await?;
                account
            }
        };
        let license = match &authorization.license_id {
            Some(license_id) => self
                .repository
                .license(license_id)
                .await?
                .ok_or(ApiError::LicenseUnavailable)?,
            None => match self.repository.license_for_account(&account.id).await? {
                Some(license) => license,
                None => {
                    let license = License::default_pro(account.id.clone(), now);
                    self.repository.upsert_license(license.clone()).await?;
                    license
                }
            },
        };
        if let Err(error) = ensure_license_active(&license, now) {
            self.record_audit(
                now,
                AuditRecord {
                    event_type: "device_registration_denied",
                    outcome: "denied",
                    account_id: Some(&account.id),
                    license_id: Some(&license.id),
                    device_id: Some(&request.device.device_id),
                    reason_code: Some(error.code()),
                    metadata: registration_metadata(&request),
                },
            )
            .await;
            return Err(error);
        }
        for attempt in 0..2 {
            match self
                .register_device_attempt(
                    &request,
                    &account,
                    &license,
                    pending_activation_code_hash.clone(),
                    &authorization_redemption,
                    now,
                )
                .await
            {
                Err(ApiError::DeviceStateDenied(_)) if attempt == 0 => continue,
                Err(error) => {
                    if matches!(&error, ApiError::ActivationLimitReached) {
                        tracing::warn!(
                            account_id = %account.id,
                            license_id = %license.id,
                            max_devices = license.effective_policy()?.device_limit,
                            "device registration denied by activation limit"
                        );
                    }
                    self.record_audit(
                        now,
                        AuditRecord {
                            event_type: "device_registration_denied",
                            outcome: "denied",
                            account_id: Some(&account.id),
                            license_id: Some(&license.id),
                            device_id: Some(&request.device.device_id),
                            reason_code: Some(error.code()),
                            metadata: registration_metadata(&request),
                        },
                    )
                    .await;
                    return Err(error);
                }
                Ok(response) => return Ok(response),
            }
        }
        unreachable!("device registration attempts are bounded")
    }

    async fn register_device_attempt(
        &self,
        request: &DeviceRegistrationRequest,
        account: &Account,
        license: &License,
        pending_activation_code_hash: Option<String>,
        authorization: &AuthorizationCodeRedemption,
        now: i64,
    ) -> Result<DeviceRegistrationResponse> {
        let existing_device = self.repository.device(&request.device.device_id).await?;
        if let Some(existing) = &existing_device {
            if existing.account_id != account.id
                || existing.license_id != license.id
                || existing.metadata.public_key_thumbprint != request.device.public_key_thumbprint
            {
                return Err(ApiError::DeviceDenied);
            }
            match existing.state {
                DeviceState::Active => {
                    let mut device = existing.clone();
                    device.metadata.platform = request.device.platform.trim().to_owned();
                    device.metadata.app_version = request.device.app_version.clone();
                    device.metadata.display_name = request
                        .device
                        .display_name
                        .as_deref()
                        .map(str::trim)
                        .map(str::to_owned);
                    device.last_seen_at = Some(now);
                    let (refresh_session, session_record) = Self::new_session_record(
                        &account.id,
                        &device.metadata.device_id,
                        None,
                        RefreshSessionProofState::Unproven,
                        now,
                    );
                    let audit = Self::audit_event(
                        now,
                        AuditRecord {
                            event_type: "device_session_issued",
                            outcome: "succeeded",
                            account_id: Some(&account.id),
                            license_id: Some(&license.id),
                            device_id: Some(&device.metadata.device_id),
                            reason_code: Some("already_active"),
                            metadata: BTreeMap::new(),
                        },
                    );
                    self.repository
                        .register_device_session_with_audit(
                            device,
                            session_record,
                            Some(DeviceState::Active),
                            authorization.clone(),
                            now,
                            audit.clone(),
                        )
                        .await?;
                    tracing::info!(
                        account_id = %account.id,
                        device_id = %existing.metadata.device_id,
                        platform = %existing.metadata.platform,
                        "active device session issued"
                    );
                    Self::log_audit(&audit);
                    return Ok(DeviceRegistrationResponse {
                        device_state: DeviceState::Active,
                        refresh_session,
                        server_unix: now,
                    });
                }
                DeviceState::PendingActivation | DeviceState::Removed => {}
                DeviceState::Revoked | DeviceState::Suspicious => {
                    return Err(ApiError::DeviceStateDenied(existing.state));
                }
            }
        }

        let device_state = if pending_activation_code_hash.is_some() {
            DeviceState::PendingActivation
        } else {
            DeviceState::Active
        };
        let device = Device {
            account_id: account.id.clone(),
            license_id: license.id.clone(),
            metadata: normalized_registration_metadata(&request.device),
            state: device_state,
            pending_activation_code_hash: pending_activation_code_hash.clone(),
            pending_activation_expires_at: pending_activation_code_hash
                .as_ref()
                .map(|_| now + PENDING_ACTIVATION_TTL_SECONDS),
            created_at: existing_device
                .as_ref()
                .map_or(now, |device| device.created_at),
            last_seen_at: Some(now),
        };
        let (refresh_session, session_record) = Self::new_session_record(
            &account.id,
            &device.metadata.device_id,
            pending_activation_code_hash,
            RefreshSessionProofState::Unproven,
            now,
        );
        let audit = Self::audit_event(
            now,
            AuditRecord {
                event_type: "device_registered",
                outcome: "succeeded",
                account_id: Some(&account.id),
                license_id: Some(&license.id),
                device_id: Some(&device.metadata.device_id),
                reason_code: None,
                metadata: BTreeMap::from([
                    ("platform".to_owned(), device.metadata.platform.clone()),
                    ("device_state".to_owned(), format!("{:?}", device.state)),
                ]),
            },
        );
        self.repository
            .register_device_session_with_audit(
                device.clone(),
                session_record,
                existing_device.as_ref().map(|device| device.state),
                authorization.clone(),
                now,
                audit.clone(),
            )
            .await?;
        tracing::info!(
            account_id = %account.id,
            device_id = %device.metadata.device_id,
            platform = %device.metadata.platform,
            device_state = ?device.state,
            "device registered"
        );
        Self::log_audit(&audit);
        Ok(DeviceRegistrationResponse {
            device_state: device.state,
            refresh_session,
            server_unix: now,
        })
    }

    pub async fn confirm_activation(
        &self,
        session: &RefreshSession,
    ) -> Result<DeviceActivationConfirmationResponse> {
        let now = self.trusted_now().await?;
        let session_record = self.authorize_session(session, now, false).await?;
        Self::require_proven_session(&session_record)?;
        self.enforce_rate_limit(
            now,
            "activation_confirm",
            &session_record.device_id,
            30,
            RATE_LIMIT_WINDOW_SHORT_SECONDS,
            AuditRecord {
                event_type: "rate_limit_denied",
                outcome: "denied",
                account_id: Some(&session_record.account_id),
                license_id: None,
                device_id: Some(&session_record.device_id),
                reason_code: None,
                metadata: BTreeMap::new(),
            },
        )
        .await?;
        let device = self
            .require_refreshable_device(&session_record.device_id, now)
            .await?;
        self.enforce_recorded_client_version(&device, now).await?;
        if session_record
            .activation_verified_at
            .is_none_or(|verified_at| verified_at + AUTHORIZATION_CODE_TTL_SECONDS <= now)
            || (device.state != DeviceState::Active
                && session_record.activation_confirmation_consumed)
        {
            self.record_audit(
                now,
                AuditRecord {
                    event_type: "device_activation_denied",
                    outcome: "denied",
                    account_id: Some(&device.account_id),
                    license_id: Some(&device.license_id),
                    device_id: Some(&device.metadata.device_id),
                    reason_code: Some("activation_proof_required"),
                    metadata: BTreeMap::new(),
                },
            )
            .await;
            return Err(ApiError::AuthorizationRequired);
        }
        let activation_code_hash = if device.state == DeviceState::Active {
            None
        } else {
            match device
                .pending_activation_code_hash
                .clone()
                .or_else(|| session_record.pending_activation_code_hash.clone())
            {
                Some(hash) => Some(hash),
                None => {
                    self.record_audit(
                        now,
                        AuditRecord {
                            event_type: "device_activation_denied",
                            outcome: "denied",
                            account_id: Some(&device.account_id),
                            license_id: Some(&device.license_id),
                            device_id: Some(&device.metadata.device_id),
                            reason_code: Some("activation_code_missing"),
                            metadata: BTreeMap::new(),
                        },
                    )
                    .await;
                    return Err(ApiError::AuthorizationRequired);
                }
            }
        };
        if device.state != DeviceState::Active
            && device
                .pending_activation_expires_at
                .is_none_or(|expires_at| expires_at <= now)
        {
            self.record_audit(
                now,
                AuditRecord {
                    event_type: "device_activation_denied",
                    outcome: "denied",
                    account_id: Some(&device.account_id),
                    license_id: Some(&device.license_id),
                    device_id: Some(&device.metadata.device_id),
                    reason_code: Some("pending_activation_expired"),
                    metadata: BTreeMap::new(),
                },
            )
            .await;
            return Err(ApiError::ActivationPendingExpired);
        }
        let license = self
            .repository
            .license(&device.license_id)
            .await?
            .ok_or(ApiError::LicenseUnavailable)?;
        if let Err(error) = ensure_license_active(&license, now) {
            self.record_audit(
                now,
                AuditRecord {
                    event_type: "device_activation_denied",
                    outcome: "denied",
                    account_id: Some(&device.account_id),
                    license_id: Some(&device.license_id),
                    device_id: Some(&device.metadata.device_id),
                    reason_code: Some(error.code()),
                    metadata: BTreeMap::new(),
                },
            )
            .await;
            return Err(error);
        }
        let success_audit = Self::audit_event(
            now,
            AuditRecord {
                event_type: "device_activation_confirmed",
                outcome: "succeeded",
                account_id: Some(&device.account_id),
                license_id: Some(&device.license_id),
                device_id: Some(&device.metadata.device_id),
                reason_code: (device.state == DeviceState::Active).then_some("already_active"),
                metadata: if device.state == DeviceState::Active {
                    BTreeMap::from([("idempotent".to_owned(), "true".to_owned())])
                } else {
                    BTreeMap::new()
                },
            },
        );
        let device = match self
            .repository
            .confirm_device_activation(
                &session_record.token_hash,
                &device.metadata.device_id,
                activation_code_hash.as_deref(),
                now,
                success_audit.clone(),
            )
            .await
        {
            Ok(device) => device,
            Err(error) => {
                self.record_audit(
                    now,
                    AuditRecord {
                        event_type: "device_activation_denied",
                        outcome: "denied",
                        account_id: Some(&device.account_id),
                        license_id: Some(&device.license_id),
                        device_id: Some(&device.metadata.device_id),
                        reason_code: Some(error.code()),
                        metadata: BTreeMap::new(),
                    },
                )
                .await;
                return Err(error);
            }
        };
        tracing::info!(
            account_id = %device.account_id,
            device_id = %device.metadata.device_id,
            "device activation confirmed"
        );
        Self::log_audit(&success_audit);
        Ok(DeviceActivationConfirmationResponse {
            device_state: DeviceState::Active,
            server_unix: now,
        })
    }

    pub async fn verify_activation(
        &self,
        session: &RefreshSession,
        request: ActivationVerificationRequest,
    ) -> Result<ActivationVerificationResponse> {
        let now = self.trusted_now().await?;
        let session_record = self.authorize_session(session, now, true).await?;
        self.enforce_rate_limit(
            now,
            "activation_verify",
            &session_record.device_id,
            60,
            RATE_LIMIT_WINDOW_SHORT_SECONDS,
            AuditRecord {
                event_type: "rate_limit_denied",
                outcome: "denied",
                account_id: Some(&session_record.account_id),
                license_id: None,
                device_id: Some(&session_record.device_id),
                reason_code: None,
                metadata: BTreeMap::new(),
            },
        )
        .await?;
        if session_record.device_id != request.proof.device_id {
            return Err(ApiError::AuthorizationRequired);
        }
        let device = self
            .require_refreshable_device(&session_record.device_id, now)
            .await?;
        let stored_challenge = self
            .repository
            .consume_challenge(&request.proof.challenge_id, &device.metadata.device_id, now)
            .await?;
        let challenge = DeviceChallenge {
            challenge_id: stored_challenge.challenge_id,
            nonce: stored_challenge.nonce,
            requested_scope: stored_challenge.requested_scope,
            issued_at: stored_challenge.issued_at,
            expires_at: stored_challenge.expires_at,
        };
        if challenge.requested_scope != ACTIVATION_VERIFY_SCOPE {
            return Err(ApiError::InvalidChallenge);
        }
        verify_device_proof(
            &device.metadata.public_key_pem,
            &challenge,
            &request.proof,
            &device.metadata.device_id,
            now,
        )?;
        self.enforce_verified_client_version(&device, &request.proof.app_version, now)
            .await?;
        let license = self
            .repository
            .license(&device.license_id)
            .await?
            .ok_or(ApiError::LicenseUnavailable)?;
        ensure_license_active(&license, now)?;
        let claims = self.activation_verification_claims(&license, &device, now);
        let activation = self.signer.sign(&claims)?;
        let success_audit = Self::audit_event(
            now,
            AuditRecord {
                event_type: "activation_proof_issued",
                outcome: "succeeded",
                account_id: Some(&device.account_id),
                license_id: Some(&license.id),
                device_id: Some(&device.metadata.device_id),
                reason_code: None,
                metadata: BTreeMap::from([("token_id".to_owned(), claims.token_id.clone())]),
            },
        );
        let rotated = self
            .rotate_session(&session_record, now, true, success_audit.clone())
            .await?;
        tracing::info!(
            account_id = %device.account_id,
            device_id = %device.metadata.device_id,
            license_id = %license.id,
            token_id = %claims.token_id,
            device_state = ?device.state,
            "activation proof issued"
        );
        Self::log_audit(&success_audit);
        Ok(ActivationVerificationResponse {
            activation: crate::contracts::SecretValue(activation),
            rotated_refresh_session: rotated,
            server_unix: now,
            device_state: device.state,
        })
    }

    pub async fn issue_challenge(
        &self,
        session: &RefreshSession,
        request: ChallengeRequest,
    ) -> Result<DeviceChallenge> {
        let now = self.trusted_now().await?;
        let session = self.authorize_session(session, now, true).await?;
        self.enforce_rate_limit(
            now,
            "challenge",
            &session.device_id,
            120,
            RATE_LIMIT_WINDOW_SHORT_SECONDS,
            AuditRecord {
                event_type: "rate_limit_denied",
                outcome: "denied",
                account_id: Some(&session.account_id),
                license_id: None,
                device_id: Some(&session.device_id),
                reason_code: None,
                metadata: BTreeMap::from([(
                    "requested_scope".to_owned(),
                    request.requested_scope.clone(),
                )]),
            },
        )
        .await?;
        if session.device_id != request.device_id {
            return Err(ApiError::AuthorizationRequired);
        }
        let device = self
            .require_refreshable_device(&session.device_id, now)
            .await?;
        let requested_scope = normalize_scope(&request.requested_scope)?;
        if device.state == DeviceState::PendingActivation
            && requested_scope != ACTIVATION_VERIFY_SCOPE
        {
            tracing::warn!(
                device_id = %device.metadata.device_id,
                requested_scope = %requested_scope,
                "pending activation device requested a non-activation challenge"
            );
            self.record_audit(
                now,
                AuditRecord {
                    event_type: "challenge_denied",
                    outcome: "denied",
                    account_id: Some(&device.account_id),
                    license_id: Some(&device.license_id),
                    device_id: Some(&device.metadata.device_id),
                    reason_code: Some("pending_activation_scope_denied"),
                    metadata: BTreeMap::from([("requested_scope".to_owned(), requested_scope)]),
                },
            )
            .await;
            return Err(ApiError::DeviceStateDenied(DeviceState::PendingActivation));
        }
        let challenge = DeviceChallenge {
            challenge_id: random_id("challenge"),
            nonce: random_secret(),
            requested_scope,
            issued_at: now,
            expires_at: now + CHALLENGE_TTL_SECONDS,
        };
        let device_id = device.metadata.device_id.clone();
        self.repository
            .insert_challenge(StoredChallenge {
                challenge_id: challenge.challenge_id.clone(),
                nonce: challenge.nonce.clone(),
                device_id: device_id.clone(),
                requested_scope: challenge.requested_scope.clone(),
                issued_at: challenge.issued_at,
                expires_at: challenge.expires_at,
                consumed: false,
            })
            .await?;
        tracing::debug!(
            device_id = %device_id,
            challenge_id = %challenge.challenge_id,
            "device challenge issued"
        );
        self.record_audit(
            now,
            AuditRecord {
                event_type: "challenge_issued",
                outcome: "succeeded",
                account_id: Some(&device.account_id),
                license_id: Some(&device.license_id),
                device_id: Some(&device_id),
                reason_code: None,
                metadata: BTreeMap::from([(
                    "requested_scope".to_owned(),
                    challenge.requested_scope.clone(),
                )]),
            },
        )
        .await;
        Ok(challenge)
    }

    pub async fn refresh_entitlement(
        &self,
        session: &RefreshSession,
        request: EntitlementRefreshRequest,
    ) -> Result<EntitlementRefreshResponse> {
        let now = self.trusted_now().await?;
        let session_record = self.authorize_session(session, now, true).await?;
        self.enforce_rate_limit(
            now,
            "entitlement_refresh",
            &session_record.device_id,
            60,
            RATE_LIMIT_WINDOW_SHORT_SECONDS,
            AuditRecord {
                event_type: "rate_limit_denied",
                outcome: "denied",
                account_id: Some(&session_record.account_id),
                license_id: None,
                device_id: Some(&session_record.device_id),
                reason_code: None,
                metadata: BTreeMap::new(),
            },
        )
        .await?;
        if session_record.device_id != request.proof.device_id {
            return Err(ApiError::AuthorizationRequired);
        }
        let device = self
            .require_active_device(&session_record.device_id)
            .await?;
        let stored_challenge = self
            .repository
            .consume_challenge(&request.proof.challenge_id, &device.metadata.device_id, now)
            .await?;
        let challenge = DeviceChallenge {
            challenge_id: stored_challenge.challenge_id,
            nonce: stored_challenge.nonce,
            requested_scope: stored_challenge.requested_scope,
            issued_at: stored_challenge.issued_at,
            expires_at: stored_challenge.expires_at,
        };
        if challenge.requested_scope != DEFAULT_SCOPE {
            return Err(ApiError::InvalidChallenge);
        }
        verify_device_proof(
            &device.metadata.public_key_pem,
            &challenge,
            &request.proof,
            &device.metadata.device_id,
            now,
        )?;
        let client_version = self
            .enforce_verified_client_version(&device, &request.proof.app_version, now)
            .await?;
        let license = self
            .repository
            .license(&device.license_id)
            .await?
            .ok_or(ApiError::LicenseUnavailable)?;
        ensure_license_active(&license, now)?;
        let claims = self
            .entitlement_claims(&license, &device, &client_version, now)
            .await?;
        let entitlement = self.signer.sign(&claims)?;
        let success_audit = Self::audit_event(
            now,
            AuditRecord {
                event_type: "entitlement_refreshed",
                outcome: "succeeded",
                account_id: Some(&device.account_id),
                license_id: Some(&license.id),
                device_id: Some(&device.metadata.device_id),
                reason_code: None,
                metadata: BTreeMap::from([("token_id".to_owned(), claims.token_id.clone())]),
            },
        );
        let rotated = self
            .rotate_session(&session_record, now, false, success_audit.clone())
            .await?;
        tracing::info!(
            account_id = %device.account_id,
            device_id = %device.metadata.device_id,
            license_id = %license.id,
            token_id = %claims.token_id,
            "entitlement refreshed"
        );
        Self::log_audit(&success_audit);
        Ok(EntitlementRefreshResponse {
            entitlement: crate::contracts::SecretValue(entitlement),
            rotated_refresh_session: rotated,
            server_unix: now,
            device_state: device.state,
        })
    }

    pub async fn issue_session_recovery_challenge(
        &self,
        request: SessionRecoveryChallengeRequest,
    ) -> Result<DeviceChallenge> {
        let now = self.trusted_now().await?;
        let device_id = request.device_id.trim();
        self.enforce_rate_limit(
            now,
            "session_recovery_challenge_global",
            "global",
            ANONYMOUS_GLOBAL_RATE_LIMIT,
            RATE_LIMIT_WINDOW_SHORT_SECONDS,
            AuditRecord {
                event_type: "rate_limit_denied",
                outcome: "denied",
                account_id: None,
                license_id: None,
                device_id: None,
                reason_code: None,
                metadata: BTreeMap::new(),
            },
        )
        .await?;
        if !valid_device_id(device_id) {
            self.record_anonymous_audit_sample(
                now,
                AuditRecord {
                    event_type: "session_recovery_challenge_denied",
                    outcome: "denied",
                    account_id: None,
                    license_id: None,
                    device_id: None,
                    reason_code: Some(ApiError::InvalidRequest.code()),
                    metadata: BTreeMap::from([("device_id_valid".to_owned(), "false".to_owned())]),
                },
            )
            .await;
            return Err(ApiError::InvalidRequest);
        }
        let challenge = DeviceChallenge {
            challenge_id: random_id("challenge"),
            nonce: random_secret(),
            requested_scope: SESSION_RECOVERY_SCOPE.to_owned(),
            issued_at: now,
            expires_at: now + CHALLENGE_TTL_SECONDS,
        };
        let device = self.repository.device(device_id).await?;
        self.repository
            .insert_challenge(StoredChallenge {
                challenge_id: challenge.challenge_id.clone(),
                nonce: challenge.nonce.clone(),
                device_id: device_id.to_owned(),
                requested_scope: challenge.requested_scope.clone(),
                issued_at: challenge.issued_at,
                expires_at: challenge.expires_at,
                consumed: false,
            })
            .await?;
        if let Some(device) = device {
            tracing::debug!(
                device_id = %device.metadata.device_id,
                device_state = ?device.state,
                challenge_id = %challenge.challenge_id,
                "session recovery challenge issued for an existing device"
            );
            self.record_anonymous_audit_sample(
                now,
                AuditRecord {
                    event_type: "session_recovery_challenge_issued",
                    outcome: "succeeded",
                    account_id: Some(&device.account_id),
                    license_id: Some(&device.license_id),
                    device_id: Some(&device.metadata.device_id),
                    reason_code: Some("device_record_present"),
                    metadata: BTreeMap::from([
                        (
                            "requested_scope".to_owned(),
                            challenge.requested_scope.clone(),
                        ),
                        ("device_state".to_owned(), format!("{:?}", device.state)),
                    ]),
                },
            )
            .await;
        } else {
            tracing::debug!(
                device_id_hash = %sha256_hex(device_id),
                challenge_id = %challenge.challenge_id,
                "persisted synthetic session recovery challenge issued for an unknown device"
            );
            self.record_anonymous_audit_sample(
                now,
                AuditRecord {
                    event_type: "session_recovery_challenge_issued",
                    outcome: "succeeded",
                    account_id: None,
                    license_id: None,
                    device_id: None,
                    reason_code: Some("synthetic_unknown_device"),
                    metadata: BTreeMap::from([(
                        "requested_scope".to_owned(),
                        challenge.requested_scope.clone(),
                    )]),
                },
            )
            .await;
        }
        Ok(challenge)
    }

    pub async fn recover_session(
        &self,
        request: SessionRecoveryRequest,
    ) -> Result<SessionRecoveryResponse> {
        let now = self.trusted_now().await?;
        let device_id = request.proof.device_id.trim();
        self.enforce_rate_limit(
            now,
            "session_recovery_global",
            "global",
            ANONYMOUS_GLOBAL_RATE_LIMIT,
            RATE_LIMIT_WINDOW_SHORT_SECONDS,
            AuditRecord {
                event_type: "rate_limit_denied",
                outcome: "denied",
                account_id: None,
                license_id: None,
                device_id: None,
                reason_code: None,
                metadata: BTreeMap::new(),
            },
        )
        .await?;
        if !valid_device_id(device_id) {
            self.record_anonymous_audit_sample(
                now,
                AuditRecord {
                    event_type: "session_recovery_denied",
                    outcome: "denied",
                    account_id: None,
                    license_id: None,
                    device_id: None,
                    reason_code: Some(ApiError::InvalidRequest.code()),
                    metadata: BTreeMap::from([("device_id_valid".to_owned(), "false".to_owned())]),
                },
            )
            .await;
            return Err(ApiError::InvalidRequest);
        }
        let stored_challenge = match self
            .repository
            .consume_challenge(&request.proof.challenge_id, device_id, now)
            .await
        {
            Ok(challenge) => challenge,
            Err(ApiError::InvalidChallenge) => {
                self.audit_unverified_recovery_denial(
                    now,
                    device_id,
                    &request.proof.challenge_id,
                    "challenge_invalid",
                )
                .await;
                return Err(ApiError::InvalidChallenge);
            }
            Err(ApiError::ChallengeReplay) => {
                self.audit_unverified_recovery_denial(
                    now,
                    device_id,
                    &request.proof.challenge_id,
                    "challenge_replayed",
                )
                .await;
                return Err(ApiError::InvalidChallenge);
            }
            Err(error) => return Err(error),
        };
        let challenge = DeviceChallenge {
            challenge_id: stored_challenge.challenge_id,
            nonce: stored_challenge.nonce,
            requested_scope: stored_challenge.requested_scope,
            issued_at: stored_challenge.issued_at,
            expires_at: stored_challenge.expires_at,
        };
        if challenge.requested_scope != SESSION_RECOVERY_SCOPE {
            self.audit_unverified_recovery_denial(
                now,
                device_id,
                &challenge.challenge_id,
                "challenge_scope_mismatch",
            )
            .await;
            return Err(ApiError::InvalidChallenge);
        }
        let challenge_device = self.repository.device(device_id).await?;
        let verification_key = challenge_device
            .as_ref()
            .map_or(DUMMY_DEVICE_PUBLIC_KEY_PEM, |device| {
                device.metadata.public_key_pem.as_str()
            });
        let proof_result =
            verify_device_proof(verification_key, &challenge, &request.proof, device_id, now);
        if challenge_device.is_none() || proof_result.is_err() {
            let reason = if challenge_device.is_none() {
                "device_record_missing"
            } else if matches!(proof_result, Err(ApiError::InvalidRequest)) {
                "device_public_key_invalid"
            } else {
                "device_proof_invalid"
            };
            self.audit_unverified_recovery_denial(now, device_id, &challenge.challenge_id, reason)
                .await;
            return Err(ApiError::InvalidChallenge);
        }
        let challenge_device = challenge_device.ok_or(ApiError::InvalidChallenge)?;
        self.enforce_rate_limit(
            now,
            "session_recovery",
            device_id,
            20,
            RATE_LIMIT_WINDOW_LONG_SECONDS,
            AuditRecord {
                event_type: "rate_limit_denied",
                outcome: "denied",
                account_id: Some(&challenge_device.account_id),
                license_id: Some(&challenge_device.license_id),
                device_id: Some(&challenge_device.metadata.device_id),
                reason_code: None,
                metadata: BTreeMap::new(),
            },
        )
        .await?;
        self.enforce_verified_client_version(&challenge_device, &request.proof.app_version, now)
            .await?;
        let device = match self.require_refreshable_device(device_id, now).await {
            Ok(device) => device,
            Err(error) => {
                self.audit_verified_recovery_denial(now, &challenge_device, &error)
                    .await;
                return Err(error);
            }
        };
        let license = match self.repository.license(&device.license_id).await? {
            Some(license) => license,
            None => {
                let error = ApiError::LicenseUnavailable;
                self.audit_verified_recovery_denial(now, &device, &error)
                    .await;
                return Err(error);
            }
        };
        if let Err(error) = ensure_license_active(&license, now) {
            self.audit_verified_recovery_denial(now, &device, &error)
                .await;
            return Err(error);
        }
        let success_audit = Self::audit_event(
            now,
            AuditRecord {
                event_type: "session_recovered",
                outcome: "succeeded",
                account_id: Some(&device.account_id),
                license_id: Some(&license.id),
                device_id: Some(&device.metadata.device_id),
                reason_code: Some("device_proof"),
                metadata: BTreeMap::new(),
            },
        );
        let refresh_session = match self
            .create_proven_session(
                &device.account_id,
                &device.metadata.device_id,
                device.pending_activation_code_hash.clone(),
                now,
                success_audit.clone(),
            )
            .await
        {
            Ok(session) => session,
            Err(error) => {
                self.audit_verified_recovery_denial(now, &device, &error)
                    .await;
                return Err(error);
            }
        };
        tracing::info!(
            account_id = %device.account_id,
            device_id = %device.metadata.device_id,
            license_id = %license.id,
            "license session recovered with device proof"
        );
        Self::log_audit(&success_audit);
        Ok(SessionRecoveryResponse {
            refresh_session,
            server_unix: now,
            device_state: device.state,
        })
    }

    async fn audit_unverified_recovery_denial(
        &self,
        now: i64,
        device_id: &str,
        challenge_id: &str,
        reason_code: &'static str,
    ) {
        tracing::warn!(
            device_id_hash = %sha256_hex(device_id),
            challenge_id_hash = %sha256_hex(challenge_id),
            reason_code,
            "unverified session recovery request denied"
        );
        self.record_anonymous_audit_sample(
            now,
            AuditRecord {
                event_type: "session_recovery_denied",
                outcome: "denied",
                account_id: None,
                license_id: None,
                device_id: None,
                reason_code: Some(reason_code),
                metadata: BTreeMap::from([
                    ("proof_verified".to_owned(), "false".to_owned()),
                    ("challenge_id_hash".to_owned(), sha256_hex(challenge_id)),
                ]),
            },
        )
        .await;
    }

    async fn audit_verified_recovery_denial(&self, now: i64, device: &Device, error: &ApiError) {
        self.record_audit(
            now,
            AuditRecord {
                event_type: "session_recovery_denied",
                outcome: "denied",
                account_id: Some(&device.account_id),
                license_id: Some(&device.license_id),
                device_id: Some(&device.metadata.device_id),
                reason_code: Some(error.code()),
                metadata: BTreeMap::from([("proof_verified".to_owned(), "true".to_owned())]),
            },
        )
        .await;
    }

    pub async fn entitlement_status(
        &self,
        session: &RefreshSession,
        request: EntitlementStatusRequest,
    ) -> Result<EntitlementStatusResponse> {
        let now = self.trusted_now().await?;
        let session = self.authorize_session(session, now, false).await?;
        Self::require_proven_session(&session)?;
        self.enforce_rate_limit(
            now,
            "entitlement_status",
            &session.device_id,
            120,
            RATE_LIMIT_WINDOW_SHORT_SECONDS,
            AuditRecord {
                event_type: "rate_limit_denied",
                outcome: "denied",
                account_id: Some(&session.account_id),
                license_id: None,
                device_id: Some(&session.device_id),
                reason_code: None,
                metadata: BTreeMap::new(),
            },
        )
        .await?;
        let stored_challenge = self
            .repository
            .consume_challenge(&request.proof.challenge_id, &session.device_id, now)
            .await?;
        let challenge = DeviceChallenge {
            challenge_id: stored_challenge.challenge_id,
            nonce: stored_challenge.nonce,
            requested_scope: stored_challenge.requested_scope,
            issued_at: stored_challenge.issued_at,
            expires_at: stored_challenge.expires_at,
        };
        if challenge.requested_scope != ENTITLEMENT_STATUS_SCOPE {
            return Err(ApiError::InvalidChallenge);
        }
        let challenge_device = self.repository.device(&session.device_id).await?;
        let verification_key = challenge_device
            .as_ref()
            .map_or(DUMMY_DEVICE_PUBLIC_KEY_PEM, |device| {
                device.metadata.public_key_pem.as_str()
            });
        let proof_result = verify_device_proof(
            verification_key,
            &challenge,
            &request.proof,
            &session.device_id,
            now,
        );
        if challenge_device.is_none() || proof_result.is_err() {
            return Err(ApiError::InvalidChallenge);
        }
        let device = match self.require_active_device(&session.device_id).await {
            Ok(device) => device,
            Err(error) => {
                self.record_audit(
                    now,
                    AuditRecord {
                        event_type: "entitlement_status_denied",
                        outcome: "denied",
                        account_id: Some(&session.account_id),
                        license_id: None,
                        device_id: Some(&session.device_id),
                        reason_code: Some(error.code()),
                        metadata: BTreeMap::new(),
                    },
                )
                .await;
                return Err(error);
            }
        };
        self.enforce_verified_client_version(&device, &request.proof.app_version, now)
            .await?;
        let license = self
            .repository
            .license(&device.license_id)
            .await?
            .ok_or(ApiError::LicenseUnavailable)?;
        if let Err(error) = ensure_license_active(&license, now) {
            self.record_audit(
                now,
                AuditRecord {
                    event_type: "entitlement_status_denied",
                    outcome: "denied",
                    account_id: Some(&device.account_id),
                    license_id: Some(&license.id),
                    device_id: Some(&device.metadata.device_id),
                    reason_code: Some(error.code()),
                    metadata: BTreeMap::from([
                        ("license_status".to_owned(), format!("{:?}", license.status)),
                        (
                            "license_expired".to_owned(),
                            license
                                .expires_at
                                .is_some_and(|expires_at| expires_at <= now)
                                .to_string(),
                        ),
                    ]),
                },
            )
            .await;
            return Err(error);
        }
        Ok(EntitlementStatusResponse {
            device_state: device.state,
            license_epoch: license.license_epoch,
        })
    }

    #[cfg(test)]
    async fn list_devices(
        &self,
        session: &RefreshSession,
        request: RegisteredDevicePageRequest,
    ) -> Result<RegisteredDevicePage> {
        let now = self.trusted_now().await?;
        let (cursor, page_size) = normalize_device_page(request)?;
        let session = self.authorize_session(session, now, false).await?;
        Self::require_proven_session(&session)?;
        let current = self.require_active_device(&session.device_id).await?;
        self.list_devices_authorized(&session, &current, cursor, page_size, now)
            .await
    }

    pub async fn list_devices_authenticated(
        &self,
        session: &RefreshSession,
        proof: &DeviceProof,
        request: RegisteredDevicePageRequest,
    ) -> Result<RegisteredDevicePage> {
        let (cursor, page_size) = normalize_device_page(request)?;
        let now = self.trusted_now().await?;
        let (session, current) = self
            .authorize_sensitive_request(session, proof, DEVICE_LIST_SCOPE, now)
            .await?;
        self.list_devices_authorized(&session, &current, cursor, page_size, now)
            .await
    }

    async fn list_devices_authorized(
        &self,
        session: &RefreshSessionRecord,
        current: &Device,
        cursor: Option<String>,
        page_size: u32,
        now: i64,
    ) -> Result<RegisteredDevicePage> {
        self.enforce_rate_limit(
            now,
            "device_list",
            &session.device_id,
            120,
            RATE_LIMIT_WINDOW_SHORT_SECONDS,
            AuditRecord {
                event_type: "rate_limit_denied",
                outcome: "denied",
                account_id: Some(&session.account_id),
                license_id: None,
                device_id: Some(&session.device_id),
                reason_code: None,
                metadata: BTreeMap::new(),
            },
        )
        .await?;
        self.touch_device_last_seen(&current.metadata.device_id, now)
            .await;
        let mut devices = self
            .repository
            .devices_for_license_page(
                &current.license_id,
                cursor.as_deref(),
                page_size.saturating_add(1),
            )
            .await?;
        let has_more = devices.len() > page_size as usize;
        devices.truncate(page_size as usize);
        let next_cursor = if has_more {
            devices
                .last()
                .map(|device| device.metadata.device_id.clone())
        } else {
            None
        };
        Ok(RegisteredDevicePage {
            devices: devices
                .into_iter()
                .map(|device| RegisteredDevice {
                    device_id: device.metadata.device_id,
                    display_name: device.metadata.display_name,
                    platform: device.metadata.platform,
                    state: device.state,
                    last_seen_at: device.last_seen_at,
                })
                .collect(),
            next_cursor,
        })
    }

    pub async fn remove_device(
        &self,
        session: &RefreshSession,
        device_id: &str,
        request: DeviceRemovalRequest,
    ) -> Result<()> {
        let now = self.trusted_now().await?;
        if !valid_device_id(device_id.trim()) || !valid_operation_id(&request.operation_id) {
            return Err(ApiError::InvalidRequest);
        }
        let requester_session_hash = sha256_hex(&session.0);
        if let Some(previous_session) = self
            .repository
            .session_by_hash(&requester_session_hash)
            .await?
            && self
                .repository
                .device_removal_replayed(
                    &previous_session.account_id,
                    &requester_session_hash,
                    &previous_session.device_id,
                    device_id,
                    &request.operation_id,
                )
                .await?
        {
            return Ok(());
        }
        let session = self.authorize_session(session, now, false).await?;
        Self::require_proven_session(&session)?;
        self.enforce_rate_limit(
            now,
            "device_remove",
            &session.device_id,
            20,
            RATE_LIMIT_WINDOW_LONG_SECONDS,
            AuditRecord {
                event_type: "rate_limit_denied",
                outcome: "denied",
                account_id: Some(&session.account_id),
                license_id: None,
                device_id: Some(&session.device_id),
                reason_code: None,
                metadata: BTreeMap::from([
                    ("target_device_id".to_owned(), device_id.to_owned()),
                    ("operation_id".to_owned(), request.operation_id.clone()),
                ]),
            },
        )
        .await?;
        let current = self.require_active_device(&session.device_id).await?;
        let stored_challenge = self
            .repository
            .consume_challenge(
                &request.proof.challenge_id,
                &current.metadata.device_id,
                now,
            )
            .await?;
        let challenge = DeviceChallenge {
            challenge_id: stored_challenge.challenge_id,
            nonce: stored_challenge.nonce,
            requested_scope: stored_challenge.requested_scope,
            issued_at: stored_challenge.issued_at,
            expires_at: stored_challenge.expires_at,
        };
        if challenge.requested_scope != device_removal_scope(device_id) {
            return Err(ApiError::InvalidChallenge);
        }
        verify_device_proof(
            &current.metadata.public_key_pem,
            &challenge,
            &request.proof,
            &current.metadata.device_id,
            now,
        )?;
        self.record_verified_client_version(&current, &request.proof.app_version, now)
            .await?;
        let target = self
            .repository
            .device(device_id)
            .await?
            .ok_or(ApiError::DeviceDenied)?;
        if target.account_id != current.account_id || target.license_id != current.license_id {
            tracing::warn!(
                requester_device_id = %current.metadata.device_id,
                target_device_id = %device_id,
                "cross-license device removal denied"
            );
            self.record_audit(
                now,
                AuditRecord {
                    event_type: "device_removal_denied",
                    outcome: "denied",
                    account_id: Some(&current.account_id),
                    license_id: Some(&current.license_id),
                    device_id: Some(&current.metadata.device_id),
                    reason_code: Some("cross_license_device"),
                    metadata: BTreeMap::from([(
                        "target_device_id".to_owned(),
                        device_id.to_owned(),
                    )]),
                },
            )
            .await;
            return Err(ApiError::DeviceDenied);
        }
        let audit = Self::audit_event(
            now,
            AuditRecord {
                event_type: "device_removed",
                outcome: "succeeded",
                account_id: Some(&current.account_id),
                license_id: Some(&current.license_id),
                device_id: Some(&current.metadata.device_id),
                reason_code: None,
                metadata: BTreeMap::from([
                    ("target_device_id".to_owned(), device_id.to_owned()),
                    ("operation_id".to_owned(), request.operation_id.clone()),
                ]),
            },
        );
        let removed = self
            .repository
            .remove_device_with_audit(
                &session.token_hash,
                &current.metadata.device_id,
                device_id,
                &request.operation_id,
                now,
                audit.clone(),
            )
            .await?;
        if removed {
            tracing::info!(
                requester_device_id = %current.metadata.device_id,
                target_device_id = %device_id,
                "device removed"
            );
            Self::log_audit(&audit);
        } else {
            tracing::debug!(
                requester_device_id = %current.metadata.device_id,
                target_device_id = %device_id,
                "device was already removed"
            );
        }
        Ok(())
    }

    pub async fn device_removal_status(
        &self,
        session: &RefreshSession,
        device_id: &str,
        operation_id: &str,
    ) -> Result<DeviceRemovalStatusResponse> {
        if session.0.len() < 24
            || !valid_device_id(device_id.trim())
            || !valid_operation_id(operation_id)
        {
            return Err(ApiError::InvalidRequest);
        }
        let requester_session_hash = sha256_hex(&session.0);
        let previous_session = self
            .repository
            .session_by_hash(&requester_session_hash)
            .await?
            .ok_or(ApiError::AuthorizationRequired)?;
        let committed = self
            .repository
            .device_removal_replayed(
                &previous_session.account_id,
                &requester_session_hash,
                &previous_session.device_id,
                device_id,
                operation_id,
            )
            .await?;
        Ok(DeviceRemovalStatusResponse { committed })
    }

    pub async fn logout(&self, session: RefreshSession) -> Result<()> {
        let now = self.trusted_now().await?;
        if session.0.len() < 24 {
            self.enforce_anonymous_logout_limit(now).await?;
            self.record_audit(
                now,
                AuditRecord {
                    event_type: "session_logout",
                    outcome: "denied",
                    account_id: None,
                    license_id: None,
                    device_id: None,
                    reason_code: Some("invalid_session"),
                    metadata: BTreeMap::new(),
                },
            )
            .await;
            return Ok(());
        }
        let token_hash = sha256_hex(&session.0);
        let session_record = self.repository.session_by_hash(&token_hash).await?;
        match session_record {
            Some(record)
                if record.active && record.expires_at > now && record.absolute_expires_at > now =>
            {
                let audit = Self::audit_event(
                    now,
                    AuditRecord {
                        event_type: "session_logout",
                        outcome: "succeeded",
                        account_id: Some(&record.account_id),
                        license_id: None,
                        device_id: Some(&record.device_id),
                        reason_code: Some("device_sessions_revoked"),
                        metadata: BTreeMap::from([(
                            "family_id".to_owned(),
                            record.family_id.clone(),
                        )]),
                    },
                );
                let Some(record) = self
                    .repository
                    .logout_device_sessions_with_audit(&token_hash, now, audit.clone())
                    .await?
                else {
                    self.audit_absent_logout(now).await;
                    return Ok(());
                };
                tracing::info!(
                    account_id = %record.account_id,
                    device_id = %record.device_id,
                    active = record.active,
                    "license session logged out"
                );
                Self::log_audit(&audit);
            }
            Some(_) => {
                self.enforce_anonymous_logout_limit(now).await?;
                self.audit_absent_logout(now).await;
            }
            None => {
                self.enforce_anonymous_logout_limit(now).await?;
                self.audit_absent_logout(now).await;
            }
        }
        Ok(())
    }

    async fn enforce_anonymous_logout_limit(&self, now: i64) -> Result<()> {
        self.enforce_rate_limit(
            now,
            "session_logout_global",
            "global",
            3_000,
            RATE_LIMIT_WINDOW_SHORT_SECONDS,
            AuditRecord {
                event_type: "rate_limit_denied",
                outcome: "denied",
                account_id: None,
                license_id: None,
                device_id: None,
                reason_code: None,
                metadata: BTreeMap::new(),
            },
        )
        .await
    }

    async fn audit_absent_logout(&self, now: i64) {
        self.record_audit(
            now,
            AuditRecord {
                event_type: "session_logout",
                outcome: "succeeded",
                account_id: None,
                license_id: None,
                device_id: None,
                reason_code: Some("already_absent"),
                metadata: BTreeMap::from([("idempotent".to_owned(), "true".to_owned())]),
            },
        )
        .await;
    }

    async fn validate_authorization_code(
        &self,
        request: &DeviceRegistrationRequest,
        now: i64,
    ) -> Result<(StoredAuthorizationCode, AuthorizationCodeRedemption)> {
        let verifier = request.pkce_verifier.expose();
        let challenge = pkce_s256_challenge(verifier);
        let redemption = AuthorizationCodeRedemption {
            code_hash: sha256_hex(request.authorization_code.expose()),
            code_challenge: challenge,
            redirect_uri: request.redirect_uri.clone(),
        };
        let code = self
            .repository
            .authorization_code_by_hash(&redemption.code_hash)
            .await?
            .ok_or(ApiError::AuthorizationRequired)?;
        if code.code_challenge != redemption.code_challenge
            || code.redirect_uri != redemption.redirect_uri
            || (!code.consumed && code.expires_at <= now)
            || (code.consumed
                && !(code.consumed_at.is_some_and(|consumed_at| {
                    consumed_at.saturating_add(AUTHORIZATION_RESULT_RETRY_SECONDS) >= now
                }) && code.consumed_device_id.as_deref()
                    == Some(request.device.device_id.as_str())
                    && code.consumed_key_thumbprint.as_deref()
                        == Some(request.device.public_key_thumbprint.as_str())))
        {
            return Err(ApiError::AuthorizationRequired);
        }
        Ok((code, redemption))
    }

    async fn activation_grant(&self, activation_code: &str, now: i64) -> Result<ActivationGrant> {
        let trimmed = activation_code.trim();
        let canonical = canonicalize_activation_code(trimmed);
        let code_hash = sha256_hex(canonical.as_deref().unwrap_or(trimmed));
        if let Some(record) = self.repository.activation_code_by_hash(&code_hash).await? {
            if !record.is_usable(now) {
                let error = activation_code_error(&record, now);
                self.record_audit(
                    now,
                    AuditRecord {
                        event_type: "authorization_code_denied",
                        outcome: "denied",
                        account_id: Some(&record.account_id),
                        license_id: record.license_id.as_deref(),
                        device_id: None,
                        reason_code: Some(error.code()),
                        metadata: activation_code_metadata(&record, now),
                    },
                )
                .await;
                return Err(error);
            }
            let account = self
                .repository
                .account(&record.account_id)
                .await?
                .ok_or(ApiError::LicenseUnavailable)?;
            ensure_account_active(&account)?;
            if let Some(license_id) = &record.license_id {
                let license = self
                    .repository
                    .license(license_id)
                    .await?
                    .ok_or(ApiError::LicenseUnavailable)?;
                ensure_license_active(&license, now)?;
            }
            return Ok(ActivationGrant {
                account_id: record.account_id,
                license_id: record.license_id,
                activation_code_hash: Some(code_hash),
            });
        }
        let Some(account_id) = self
            .authorization
            .fallback_account_for_activation_code(trimmed)
        else {
            self.record_anonymous_audit_sample(
                now,
                AuditRecord {
                    event_type: "authorization_code_denied",
                    outcome: "denied",
                    account_id: None,
                    license_id: None,
                    device_id: None,
                    reason_code: Some("activation_code_unknown"),
                    metadata: BTreeMap::new(),
                },
            )
            .await;
            return Err(ApiError::ActivationCodeInvalid);
        };
        Ok(ActivationGrant {
            account_id,
            license_id: None,
            activation_code_hash: None,
        })
    }

    async fn create_proven_session(
        &self,
        account_id: &str,
        device_id: &str,
        pending_activation_code_hash: Option<String>,
        now: i64,
        audit: AuditEventRecord,
    ) -> Result<RefreshSession> {
        let (session, record) = Self::new_session_record(
            account_id,
            device_id,
            pending_activation_code_hash,
            RefreshSessionProofState::DeviceProven,
            now,
        );
        self.repository
            .replace_device_sessions_with_audit(record, now, audit)
            .await?;
        Ok(session)
    }

    fn new_session_record(
        account_id: &str,
        device_id: &str,
        pending_activation_code_hash: Option<String>,
        proof_state: RefreshSessionProofState,
        now: i64,
    ) -> (RefreshSession, RefreshSessionRecord) {
        let session = RefreshSession(random_secret());
        let record = RefreshSessionRecord {
            token_hash: sha256_hex(&session.0),
            account_id: account_id.to_owned(),
            device_id: device_id.to_owned(),
            family_id: random_id("session_family"),
            family_created_at: now,
            absolute_expires_at: now + REFRESH_SESSION_ABSOLUTE_TTL_SECONDS,
            active: true,
            expires_at: now + REFRESH_SESSION_IDLE_TTL_SECONDS,
            rotated_to_hash: None,
            rotated_at: None,
            pending_activation_code_hash,
            activation_verified_at: None,
            activation_confirmation_consumed: false,
            proof_state,
        };
        (session, record)
    }

    async fn rotate_session(
        &self,
        previous: &RefreshSessionRecord,
        now: i64,
        activation_verified: bool,
        audit: AuditEventRecord,
    ) -> Result<RefreshSession> {
        let rotated = RefreshSession(random_secret());
        if let Err(error) = self
            .repository
            .rotate_session_with_audit(
                &previous.token_hash,
                RefreshSessionRecord {
                    token_hash: sha256_hex(&rotated.0),
                    account_id: previous.account_id.clone(),
                    device_id: previous.device_id.clone(),
                    family_id: previous.family_id.clone(),
                    family_created_at: previous.family_created_at,
                    absolute_expires_at: previous.absolute_expires_at,
                    active: true,
                    expires_at: now
                        .saturating_add(REFRESH_SESSION_IDLE_TTL_SECONDS)
                        .min(previous.absolute_expires_at),
                    rotated_to_hash: None,
                    rotated_at: None,
                    pending_activation_code_hash: previous.pending_activation_code_hash.clone(),
                    activation_verified_at: activation_verified.then_some(now),
                    activation_confirmation_consumed: false,
                    proof_state: RefreshSessionProofState::DeviceProven,
                },
                now,
                audit,
            )
            .await
        {
            if matches!(error, ApiError::RefreshSessionReused) {
                self.record_audit(
                    now,
                    AuditRecord {
                        event_type: "refresh_session_reuse_detected",
                        outcome: "denied",
                        account_id: Some(&previous.account_id),
                        license_id: None,
                        device_id: Some(&previous.device_id),
                        reason_code: Some("concurrent_session_reuse"),
                        metadata: BTreeMap::from([(
                            "family_id".to_owned(),
                            previous.family_id.clone(),
                        )]),
                    },
                )
                .await;
            }
            return Err(error);
        }
        Ok(rotated)
    }

    async fn authorize_session(
        &self,
        session: &RefreshSession,
        now: i64,
        allow_rotation_retry: bool,
    ) -> Result<RefreshSessionRecord> {
        if session.0.len() < 24 {
            return Err(ApiError::AuthorizationRequired);
        }
        let hash = sha256_hex(&session.0);
        let record = self
            .repository
            .session_by_hash(&hash)
            .await?
            .ok_or(ApiError::AuthorizationRequired)?;
        if !record.active {
            if record.rotated_to_hash.is_some() {
                if allow_rotation_retry && self.rotation_retry_is_safe(&record, now).await? {
                    let mut retry = record;
                    retry.active = true;
                    tracing::info!(
                        device_id = %retry.device_id,
                        family_id = %retry.family_id,
                        "accepting a device-proven refresh retry inside the rotation grace window"
                    );
                    return Ok(retry);
                }
                self.repository
                    .revoke_session_family(&record.family_id)
                    .await?;
                tracing::warn!(
                    device_id = %record.device_id,
                    family_id = %record.family_id,
                    "refresh session reuse detected; session family revoked"
                );
                self.record_audit(
                    now,
                    AuditRecord {
                        event_type: "refresh_session_reuse_detected",
                        outcome: "denied",
                        account_id: Some(&record.account_id),
                        license_id: None,
                        device_id: Some(&record.device_id),
                        reason_code: Some("rotated_session_reuse"),
                        metadata: BTreeMap::from([(
                            "family_id".to_owned(),
                            record.family_id.clone(),
                        )]),
                    },
                )
                .await;
                return Err(ApiError::RefreshSessionReused);
            }
            let denial = match self.repository.account(&record.account_id).await? {
                Some(account) => ensure_account_active(&account).err(),
                None => None,
            }
            .unwrap_or(ApiError::AuthorizationRequired);
            let reason_code = match &denial {
                ApiError::AuthorizationRequired => "session_inactive",
                _ => denial.code(),
            };
            self.record_audit(
                now,
                AuditRecord {
                    event_type: "session_authorization_denied",
                    outcome: "denied",
                    account_id: Some(&record.account_id),
                    license_id: None,
                    device_id: Some(&record.device_id),
                    reason_code: Some(reason_code),
                    metadata: BTreeMap::from([("family_id".to_owned(), record.family_id.clone())]),
                },
            )
            .await;
            return Err(denial);
        }
        if record.expires_at <= now || record.absolute_expires_at <= now {
            self.record_audit(
                now,
                AuditRecord {
                    event_type: "session_authorization_denied",
                    outcome: "denied",
                    account_id: Some(&record.account_id),
                    license_id: None,
                    device_id: Some(&record.device_id),
                    reason_code: Some("session_expired"),
                    metadata: BTreeMap::from([
                        ("family_id".to_owned(), record.family_id.clone()),
                        ("expires_at".to_owned(), record.expires_at.to_string()),
                    ]),
                },
            )
            .await;
            return Err(ApiError::AuthorizationRequired);
        }
        Ok(record)
    }

    async fn rotation_retry_is_safe(
        &self,
        previous: &RefreshSessionRecord,
        now: i64,
    ) -> Result<bool> {
        const ROTATION_RETRY_GRACE_SECONDS: i64 = 60;
        let Some(rotated_at) = previous.rotated_at else {
            return Ok(false);
        };
        let Some(successor_hash) = previous.rotated_to_hash.as_deref() else {
            return Ok(false);
        };
        if rotated_at.saturating_add(ROTATION_RETRY_GRACE_SECONDS) < now {
            return Ok(false);
        }
        let Some(successor) = self.repository.session_by_hash(successor_hash).await? else {
            return Ok(false);
        };
        Ok(successor.active
            && successor.expires_at > now
            && successor.absolute_expires_at > now
            && successor.rotated_to_hash.is_none()
            && successor.family_id == previous.family_id
            && successor.device_id == previous.device_id)
    }

    fn require_proven_session(session: &RefreshSessionRecord) -> Result<()> {
        if session.proof_state == RefreshSessionProofState::DeviceProven {
            Ok(())
        } else {
            Err(ApiError::AuthorizationRequired)
        }
    }

    async fn require_refreshable_device(&self, device_id: &str, now: i64) -> Result<Device> {
        let device = self
            .repository
            .device(device_id)
            .await?
            .ok_or(ApiError::DeviceDenied)?;
        let account = self
            .repository
            .account(&device.account_id)
            .await?
            .ok_or(ApiError::DeviceDenied)?;
        ensure_account_active(&account)?;
        match device.state {
            DeviceState::Active => Ok(device),
            DeviceState::PendingActivation
                if device
                    .pending_activation_expires_at
                    .is_some_and(|expires_at| expires_at > now) =>
            {
                Ok(device)
            }
            DeviceState::PendingActivation => Err(ApiError::ActivationPendingExpired),
            DeviceState::Removed | DeviceState::Revoked | DeviceState::Suspicious => {
                Err(ApiError::DeviceStateDenied(device.state))
            }
        }
    }

    async fn require_active_device(&self, device_id: &str) -> Result<Device> {
        let device = self
            .repository
            .device(device_id)
            .await?
            .ok_or(ApiError::DeviceDenied)?;
        let account = self
            .repository
            .account(&device.account_id)
            .await?
            .ok_or(ApiError::DeviceDenied)?;
        ensure_account_active(&account)?;
        if device.state != DeviceState::Active {
            return Err(ApiError::DeviceStateDenied(device.state));
        }
        Ok(device)
    }

    fn activation_verification_claims(
        &self,
        license: &License,
        device: &Device,
        now: i64,
    ) -> ActivationProofClaims {
        ActivationProofClaims {
            iss: self.issuer.clone(),
            aud: activation_audience(&self.audience),
            sub: license.account_id.clone(),
            license_id: license.id.clone(),
            device_id: device.metadata.device_id.clone(),
            device_key_thumbprint: device.metadata.public_key_thumbprint.clone(),
            license_epoch: license.license_epoch,
            purpose: "activation_verify".to_owned(),
            issued_at: now,
            expires_at: now + AUTHORIZATION_CODE_TTL_SECONDS,
            token_id: random_id("activation"),
            key_id: self.signer.key_id().to_owned(),
        }
    }

    async fn entitlement_claims(
        &self,
        license: &License,
        device: &Device,
        client_version: &Version,
        now: i64,
    ) -> Result<EntitlementClaims> {
        let enforcement_cap = (client_version < &self.minimum_client_version
            && now < self.client_version_policy.enforce_after)
            .then_some(self.client_version_policy.enforce_after);
        let cap = |value: i64| {
            let value = license
                .expires_at
                .map_or(value, |expires_at| value.min(expires_at));
            enforcement_cap.map_or(value, |enforce_after| value.min(enforce_after))
        };
        let policy = license.effective_policy()?;
        let mut workspace_permissions = Vec::new();
        if license.plan == Plan::Team
            && let Some(team_repository) = &self.team_repository
        {
            let profile = team_repository
                .profile(&license.account_id, &device.metadata.device_id, now)
                .await?;
            if profile.enabled {
                workspace_permissions = profile.permissions;
                workspace_permissions.sort();
                workspace_permissions.dedup();
            }
        }
        let mut capabilities = policy.capabilities.clone();
        if license.plan == Plan::Team {
            capabilities
                .retain(|capability| team_capability_allowed(*capability, &workspace_permissions));
        }
        Ok(EntitlementClaims {
            schema_version: 3,
            iss: self.issuer.clone(),
            aud: self.audience.clone(),
            sub: license.account_id.clone(),
            license_id: license.id.clone(),
            device_id: device.metadata.device_id.clone(),
            device_key_thumbprint: device.metadata.public_key_thumbprint.clone(),
            plan: license.plan,
            plan_revision: license.plan_revision,
            policy_hash: policy.policy_hash(),
            license_status: match license.status {
                LicenseStatus::Active => LicenseStanding::Active,
                LicenseStatus::PastDue => LicenseStanding::PastDue,
                LicenseStatus::Canceled => LicenseStanding::Canceled,
            },
            capabilities,
            workspace_permissions,
            limits: policy.limits,
            license_expires_at: license.expires_at,
            license_epoch: license.license_epoch,
            device_limit: policy.device_limit,
            member_limit: policy.member_limit,
            client_version_policy: self.client_version_policy.clone(),
            issued_at: now,
            refresh_after: cap(now.saturating_add(ENTITLEMENT_REFRESH_AFTER_SECONDS)),
            expires_at: cap(now.saturating_add(ENTITLEMENT_TTL_SECONDS)),
            offline_access_ends_at: cap(now.saturating_add(24 * 60 * 60)),
            token_id: random_id("lease"),
            key_id: self.signer.key_id().to_owned(),
        })
    }
}

#[async_trait::async_trait]
impl WebhookTimeAuthority for LicenseService {
    async fn trusted_now(&self) -> crate::webhooks::WebhookResult<i64> {
        LicenseService::trusted_now(self).await.map_err(|error| {
            if matches!(error, ApiError::TimeAuthorityUnavailable) {
                crate::webhooks::WebhookError::TimeAuthorityUnavailable
            } else {
                crate::webhooks::WebhookError::Database
            }
        })
    }
}

fn validate_registration_request(request: &DeviceRegistrationRequest) -> Result<()> {
    let platform = request.device.platform.trim();
    let app_version = request.device.app_version.trim();
    let display_name_valid = request.device.display_name.as_ref().is_none_or(|name| {
        let name = name.trim();
        !name.is_empty() && name.len() <= 128 && !name.chars().any(char::is_control)
    });
    if !valid_device_id(request.device.device_id.trim())
        || platform.is_empty()
        || platform.len() > 64
        || app_version.is_empty()
        || app_version.len() > 64
        || canonical_client_version(&request.device.app_version).is_err()
        || !display_name_valid
        || request.device.public_key_pem.len() > 8 * 1024
        || request.device.public_key_thumbprint.len() > 128
        || validate_device_public_key(
            &request.device.public_key_pem,
            &request.device.public_key_thumbprint,
        )
        .is_err()
        || !(24..=4 * 1024).contains(&request.authorization_code.expose().len())
        || !valid_pkce_verifier(request.pkce_verifier.expose())
        || request.redirect_uri.len() > 2 * 1024
        || !valid_redirect_uri(&request.redirect_uri)
    {
        return Err(ApiError::InvalidRequest);
    }
    Ok(())
}

fn activation_code_error(record: &ActivationCodeRecord, now: i64) -> ApiError {
    if record.status == ActivationCodeStatus::Revoked {
        ApiError::ActivationCodeRevoked
    } else if record.is_expired(now) {
        ApiError::ActivationCodeExpired
    } else if record.status == ActivationCodeStatus::Consumed || record.remaining_redemptions() == 0
    {
        ApiError::ActivationCodeConsumed
    } else {
        ApiError::ActivationCodeInvalid
    }
}

fn normalized_registration_metadata(
    metadata: &crate::contracts::DeviceRegistrationMetadata,
) -> crate::contracts::DeviceRegistrationMetadata {
    let mut normalized = metadata.clone();
    normalized.platform = metadata.platform.trim().to_owned();
    normalized.display_name = metadata
        .display_name
        .as_deref()
        .map(str::trim)
        .map(str::to_owned);
    normalized
}

fn activation_code_metadata(record: &ActivationCodeRecord, now: i64) -> BTreeMap<String, String> {
    BTreeMap::from([
        (
            "activation_code_status".to_owned(),
            match record.status {
                ActivationCodeStatus::Active => "active",
                ActivationCodeStatus::Consumed => "consumed",
                ActivationCodeStatus::Revoked => "revoked",
            }
            .to_owned(),
        ),
        (
            "activation_code_expired".to_owned(),
            record.is_expired(now).to_string(),
        ),
        (
            "activation_code_max_redemptions".to_owned(),
            record.max_redemptions().to_string(),
        ),
        (
            "activation_code_redeemed_count".to_owned(),
            record.redeemed_count.to_string(),
        ),
        (
            "activation_code_remaining_redemptions".to_owned(),
            record.remaining_redemptions().to_string(),
        ),
    ])
}

fn authorization_request_metadata(request: &OAuthAuthorizationRequest) -> BTreeMap<String, String> {
    BTreeMap::from([
        (
            "response_type".to_owned(),
            bounded_metadata_value(&request.response_type),
        ),
        (
            "client_id".to_owned(),
            bounded_metadata_value(&request.client_id),
        ),
        (
            "redirect_uri_scheme".to_owned(),
            Url::parse(&request.redirect_uri)
                .map(|url| bounded_metadata_value(url.scheme()))
                .unwrap_or_else(|_| "invalid".to_owned()),
        ),
        ("scope".to_owned(), bounded_metadata_value(&request.scope)),
        (
            "code_challenge_method".to_owned(),
            bounded_metadata_value(&request.code_challenge_method),
        ),
    ])
}

fn registration_metadata(request: &DeviceRegistrationRequest) -> BTreeMap<String, String> {
    let mut metadata = BTreeMap::from([
        (
            "platform".to_owned(),
            bounded_metadata_value(&request.device.platform),
        ),
        (
            "app_version".to_owned(),
            bounded_metadata_value(&request.device.app_version),
        ),
    ]);
    if let Some(display_name) = &request.device.display_name {
        metadata.insert(
            "display_name_present".to_owned(),
            (!display_name.trim().is_empty()).to_string(),
        );
    }
    metadata
}

fn non_empty_str(value: &str) -> Option<&str> {
    let value = value.trim();
    (!value.is_empty()).then_some(value)
}

fn bounded_metadata_value(value: &str) -> String {
    const MAX_METADATA_VALUE_CHARS: usize = 128;
    let trimmed = value.trim();
    if trimmed.chars().count() <= MAX_METADATA_VALUE_CHARS {
        return trimmed.to_owned();
    }
    let mut truncated = trimmed
        .chars()
        .take(MAX_METADATA_VALUE_CHARS)
        .collect::<String>();
    truncated.push('…');
    truncated
}

fn valid_pkce_verifier(value: &str) -> bool {
    (43..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
}

fn valid_pkce_s256_challenge(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn valid_oauth_state(value: &str) -> bool {
    (32..=MAX_OAUTH_STATE_BYTES).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
}

fn validate_device_public_key(public_key_pem: &str, expected_thumbprint: &str) -> Result<()> {
    use p256::{
        ecdsa::VerifyingKey,
        pkcs8::{DecodePublicKey, EncodePublicKey},
    };

    if !expected_thumbprint.starts_with("sha256:") {
        return Err(ApiError::InvalidRequest);
    }
    let key =
        VerifyingKey::from_public_key_pem(public_key_pem).map_err(|_| ApiError::InvalidRequest)?;
    let public_der = key
        .to_public_key_der()
        .map_err(|_| ApiError::InvalidRequest)?;
    let thumbprint = format!(
        "sha256:{}",
        sha2::Sha256::digest(public_der.as_ref())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    if thumbprint != expected_thumbprint {
        return Err(ApiError::InvalidRequest);
    }
    Ok(())
}

pub(crate) fn valid_redirect_uri(value: &str) -> bool {
    let Ok(url) = Url::parse(value) else {
        return false;
    };
    (url.scheme() == "camellia-nexus"
        && url.host_str() == Some("auth")
        && url.port().is_none()
        && url.path() == "/callback"
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none())
        || is_loopback_authorization_callback(value)
}

pub(crate) fn is_loopback_authorization_callback(value: &str) -> bool {
    let Ok(url) = Url::parse(value) else {
        return false;
    };
    url.scheme() == "http"
        && url.host_str() == Some("127.0.0.1")
        && url.port().is_some()
        && url.path() == "/auth/callback"
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
}

fn ensure_license_active(license: &License, now: i64) -> Result<()> {
    match license.status {
        LicenseStatus::Active if license.expires_at.is_none_or(|expires_at| expires_at > now) => {
            Ok(())
        }
        LicenseStatus::PastDue | LicenseStatus::Canceled
            if license
                .expires_at
                .is_some_and(|expires_at| expires_at > now) =>
        {
            Ok(())
        }
        LicenseStatus::PastDue => Err(ApiError::LicensePastDue),
        LicenseStatus::Canceled => Err(ApiError::LicenseCanceled),
        LicenseStatus::Active => Err(ApiError::LicenseExpired),
    }
}

fn ensure_account_active(account: &Account) -> Result<()> {
    match account.state {
        crate::domain::AccountState::Active => Ok(()),
        crate::domain::AccountState::Suspended => Err(ApiError::AccountSuspended),
        crate::domain::AccountState::Denylisted => Err(ApiError::AccountDenylisted),
    }
}

fn team_capability_allowed(capability: Capability, permissions: &[String]) -> bool {
    let has_any = |required: &[&str]| {
        required
            .iter()
            .any(|required| permissions.iter().any(|permission| permission == required))
    };
    match capability {
        Capability::SharedConfigurations => {
            has_any(&["shared.read", "shared.write", "shared.publish"])
        }
        Capability::CloudSync => has_any(&["sync.read", "sync.write"]),
        Capability::RemoteDashboard => has_any(&["remote.read"]),
        Capability::Alerts => has_any(&[
            "alerts.read",
            "alerts.history.read",
            "alerts.manage",
            "alerts.ack",
        ]),
        Capability::AuditLog => has_any(&["audit.read", "audit.export"]),
        Capability::Webhooks => {
            has_any(&["webhooks.read", "webhooks.manage", "webhooks.delivery.read"])
        }
        Capability::TeamAdministration => has_any(&["team.manage", "team.transfer_ownership"]),
        Capability::ManagedConfigSources
        | Capability::AdvancedDiagnostics
        | Capability::ManagedProgramPackages => true,
    }
}

fn device_removal_scope(device_id: &str) -> String {
    format!("device:remove:{device_id}")
}

fn valid_operation_id(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|parsed| {
        parsed.get_version() == Some(uuid::Version::Random)
            && parsed.get_variant() == uuid::Variant::RFC4122
            && parsed.hyphenated().to_string() == value
    })
}

fn team_member_update_scope(member_id: &str) -> Result<String> {
    normalize_scope(&format!("team:member:update:{member_id}"))
}

fn team_member_device_enrollment_scope(member_id: &str) -> Result<String> {
    normalize_scope(&format!("team:member:device-enrollment:create:{member_id}"))
}

fn normalize_scope(scope: &str) -> Result<String> {
    let scope = scope.trim();
    let scope = if scope.is_empty() {
        DEFAULT_SCOPE
    } else {
        scope
    };
    if scope.len() > 256
        || !scope
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'-' | b'_' | b'.'))
    {
        Err(ApiError::InvalidRequest)
    } else {
        Ok(scope.to_owned())
    }
}

fn valid_device_id(device_id: &str) -> bool {
    uuid::Uuid::parse_str(device_id)
        .is_ok_and(|parsed| parsed.hyphenated().to_string() == device_id)
}

fn normalize_device_page(request: RegisteredDevicePageRequest) -> Result<(Option<String>, u32)> {
    let cursor = request
        .cursor
        .as_deref()
        .map(normalize_device_cursor)
        .transpose()?;
    let page_size = request.page_size.unwrap_or(DEFAULT_DEVICE_PAGE_SIZE);
    if !(1..=MAX_DEVICE_PAGE_SIZE).contains(&page_size) {
        return Err(ApiError::InvalidRequest);
    }
    Ok((cursor, page_size))
}

fn normalize_device_cursor(cursor: &str) -> Result<String> {
    if valid_device_id(cursor) {
        Ok(cursor.to_owned())
    } else {
        Err(ApiError::InvalidRequest)
    }
}

fn activation_audience(audience: &str) -> String {
    format!("{audience}:activation")
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::{Arc, Mutex};

    use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
    use p256::{
        ecdsa::SigningKey,
        elliptic_curve::Generate,
        pkcs8::{EncodePublicKey, LineEnding},
    };
    use sha2::Digest;

    use super::*;
    use crate::{
        contracts::{
            ActivationProofClaims, ActivationVerificationRequest, DeviceRegistrationMetadata,
            DeviceRemovalRequest, EntitlementRefreshRequest, Plan, SecretValue,
            SessionRecoveryChallengeRequest, SessionRecoveryRequest,
        },
        crypto::{EntitlementSigner, sign_device_challenge},
        domain::{ActivationCodeRecord, ActivationCodeStatus},
        store::MemoryRepository,
    };

    pub const TEST_ACTIVATION_CODE: &str = "test-activation-code";
    pub const TEST_PKCE_VERIFIER: &str = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG";

    fn test_signing_key() -> SigningKey {
        SigningKey::try_generate().expect("test signing key entropy")
    }

    #[derive(Default)]
    struct TestClock(Mutex<i64>);

    impl TestClock {
        fn new(now: i64) -> Self {
            Self(Mutex::new(now))
        }

        fn set(&self, now: i64) {
            *self.0.lock().unwrap() = now;
        }
    }

    impl Clock for TestClock {
        fn now(&self) -> i64 {
            *self.0.lock().unwrap()
        }
    }

    fn fixture_with_repository() -> (LicenseService, MemoryRepository, SigningKey, String) {
        let repository = MemoryRepository::default();
        let entitlement_key = test_signing_key();
        let signer = EntitlementSigner::from_signing_key("entitlement-test", &entitlement_key);
        let public_pem = entitlement_key
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .expect("public");
        let authorization = AuthorizationPolicy::new(
            "camellia-nexus-desktop",
            vec!["camellia-nexus://auth/callback".to_owned()],
            vec![(TEST_ACTIVATION_CODE.to_owned(), "acct_test".to_owned())],
        )
        .expect("authorization policy");
        let service = LicenseService::with_clock_and_authorization(
            Arc::new(repository.clone()),
            signer,
            "https://license.test",
            "camellia-nexus-desktop",
            Arc::new(TestClock::new(1_000)),
            authorization,
        );
        (service, repository, entitlement_key, public_pem)
    }

    fn fixture_with_client_version_policy(
        now: i64,
        client_version_policy: ClientVersionPolicy,
    ) -> (
        LicenseService,
        MemoryRepository,
        SigningKey,
        String,
        Arc<TestClock>,
    ) {
        let repository = MemoryRepository::default();
        let entitlement_key = test_signing_key();
        let signer = EntitlementSigner::from_signing_key("entitlement-test", &entitlement_key);
        let public_pem = entitlement_key
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .expect("public");
        let authorization = AuthorizationPolicy::new(
            "camellia-nexus-desktop",
            vec!["camellia-nexus://auth/callback".to_owned()],
            vec![(TEST_ACTIVATION_CODE.to_owned(), "acct_test".to_owned())],
        )
        .expect("authorization policy");
        let clock = Arc::new(TestClock::new(now));
        let service = LicenseService::with_clock_authorization_and_client_version_policy(
            Arc::new(repository.clone()),
            signer,
            "https://license.test",
            "camellia-nexus-desktop",
            clock.clone(),
            authorization,
            client_version_policy,
        )
        .expect("client-version policy fixture");
        (service, repository, entitlement_key, public_pem, clock)
    }

    pub fn fixture() -> (LicenseService, SigningKey, String) {
        let (service, _, entitlement_key, public_pem) = fixture_with_repository();
        (service, entitlement_key, public_pem)
    }

    pub async fn register(
        service: &LicenseService,
    ) -> (RefreshSession, SigningKey, String, String) {
        register_result(service).await.expect("register")
    }

    async fn activate_registered_device(
        service: &LicenseService,
        session: &RefreshSession,
        device_key: &SigningKey,
        device_id: &str,
    ) -> RefreshSession {
        let challenge = service
            .issue_challenge(
                session,
                ChallengeRequest {
                    device_id: device_id.to_owned(),
                    requested_scope: ACTIVATION_VERIFY_SCOPE.into(),
                },
            )
            .await
            .expect("activation challenge");
        let proof = sign_device_challenge(device_key, &challenge, device_id, "1.0.0");
        let verified = service
            .verify_activation(session, ActivationVerificationRequest { proof })
            .await
            .expect("activation verification");
        service
            .confirm_activation(&verified.rotated_refresh_session)
            .await
            .expect("activation confirmation");
        verified.rotated_refresh_session
    }

    async fn refresh_entitlement_claims(
        service: &LicenseService,
        session: &RefreshSession,
        device_key: &SigningKey,
        device_id: &str,
        public_pem: &str,
    ) -> (EntitlementClaims, RefreshSession) {
        let challenge = service
            .issue_challenge(
                session,
                ChallengeRequest {
                    device_id: device_id.to_owned(),
                    requested_scope: DEFAULT_SCOPE.into(),
                },
            )
            .await
            .expect("refresh challenge");
        let proof = sign_device_challenge(device_key, &challenge, device_id, "1.0.0");
        let response = service
            .refresh_entitlement(session, EntitlementRefreshRequest { proof })
            .await
            .expect("refresh");
        let claims = decode_claims(response.entitlement.expose(), public_pem);
        (claims, response.rotated_refresh_session)
    }

    async fn entitlement_status_with_version(
        service: &LicenseService,
        session: &RefreshSession,
        device_key: &SigningKey,
        device_id: &str,
        app_version: &str,
    ) -> Result<EntitlementStatusResponse> {
        let challenge = service
            .issue_challenge(
                session,
                ChallengeRequest {
                    device_id: device_id.to_owned(),
                    requested_scope: ENTITLEMENT_STATUS_SCOPE.into(),
                },
            )
            .await?;
        let proof = sign_device_challenge(device_key, &challenge, device_id, app_version);
        service
            .entitlement_status(session, EntitlementStatusRequest { proof })
            .await
    }

    fn invalid_status_request(device_id: &str) -> EntitlementStatusRequest {
        EntitlementStatusRequest {
            proof: crate::contracts::DeviceProof {
                challenge_id: "unused".into(),
                device_id: device_id.to_owned(),
                app_version: "1.0.0".into(),
                requested_scope: ENTITLEMENT_STATUS_SCOPE.into(),
                issued_at: 0,
                signature: "unused".into(),
            },
        }
    }

    fn decode_claims<T: serde::de::DeserializeOwned>(token: &str, public_pem: &str) -> T {
        let mut validation = Validation::new(Algorithm::ES256);
        validation.validate_exp = false;
        validation.validate_aud = false;
        crate::es256_provider::ensure_installed();
        decode::<T>(
            token,
            &DecodingKey::from_ec_pem(public_pem.as_bytes()).expect("decoding"),
            &validation,
        )
        .expect("claims")
        .claims
    }

    async fn issue_authorization_code(service: &LicenseService, verifier: &str) -> String {
        issue_authorization_code_for(service, TEST_ACTIVATION_CODE, verifier).await
    }

    async fn issue_authorization_code_for(
        service: &LicenseService,
        activation_code: &str,
        verifier: &str,
    ) -> String {
        let redirect = service
            .create_authorization_redirect(activation_code, oauth_request(verifier))
            .await
            .expect("authorization redirect");
        let url = Url::parse(&redirect).expect("redirect url");
        url.query_pairs()
            .find_map(|(name, value)| (name == "code").then(|| value.into_owned()))
            .expect("code")
    }

    fn activation_code_record(
        code: &str,
        account_id: &str,
        license_id: &str,
        now: i64,
        max_redemptions: u32,
    ) -> ActivationCodeRecord {
        ActivationCodeRecord {
            code_hash: sha256_hex(code),
            code_prefix: code.chars().take(16).collect(),
            account_id: account_id.to_owned(),
            license_id: Some(license_id.to_owned()),
            status: ActivationCodeStatus::Active,
            max_redemptions,
            redeemed_count: 0,
            expires_at: None,
            consumed_at: None,
            consumed_device_id: None,
            last_redeemed_at: None,
            last_redeemed_device_id: None,
            created_at: now,
            updated_at: now,
            note: None,
            order_id: None,
            channel: Some("test".to_owned()),
            issued_by: Some("test-suite".to_owned()),
            revoked_reason: None,
            last_admin_reason: Some("test fixture".to_owned()),
        }
    }

    async fn register_database_device(
        service: &LicenseService,
        activation_code: &str,
        device_key: &SigningKey,
        device_id: &str,
    ) -> Result<DeviceRegistrationResponse> {
        let public_key_pem = device_key
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .expect("device public");
        let public_der = device_key
            .verifying_key()
            .to_public_key_der()
            .expect("device der");
        let thumbprint = format!(
            "sha256:{}",
            sha2::Sha256::digest(public_der.as_ref())
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        );
        let authorization_code =
            issue_authorization_code_for(service, activation_code, TEST_PKCE_VERIFIER).await;
        service
            .register_device(DeviceRegistrationRequest {
                device: DeviceRegistrationMetadata {
                    device_id: device_id.to_owned(),
                    public_key_pem,
                    public_key_thumbprint: thumbprint,
                    platform: "test".to_owned(),
                    app_version: "1.0.0".to_owned(),
                    display_name: Some("Database activation test".to_owned()),
                },
                authorization_code: SecretValue(authorization_code),
                pkce_verifier: SecretValue(TEST_PKCE_VERIFIER.to_owned()),
                redirect_uri: "camellia-nexus://auth/callback".to_owned(),
            })
            .await
    }

    fn oauth_request(verifier: &str) -> OAuthAuthorizationRequest {
        OAuthAuthorizationRequest {
            response_type: "code".into(),
            client_id: "camellia-nexus-desktop".into(),
            redirect_uri: "camellia-nexus://auth/callback".into(),
            scope: "camellia.nexus.license".into(),
            state: "0123456789abcdef0123456789abcdef".into(),
            code_challenge: pkce_s256_challenge(verifier),
            code_challenge_method: "S256".into(),
        }
    }

    #[test]
    fn oauth_authorization_request_validation_is_exact_and_bounded() {
        let policy = AuthorizationPolicy::development();
        let valid = oauth_request(TEST_PKCE_VERIFIER);
        assert!(policy.validate_authorization_request(&valid).is_ok());

        let invalid_requests = [
            OAuthAuthorizationRequest {
                scope: String::new(),
                ..valid.clone()
            },
            OAuthAuthorizationRequest {
                scope: "openid offline_access camellia.nexus.license".into(),
                ..valid.clone()
            },
            OAuthAuthorizationRequest {
                scope: "camellia.nexus.license camellia.nexus.license".into(),
                ..valid.clone()
            },
            OAuthAuthorizationRequest {
                scope: " camellia.nexus.license".into(),
                ..valid.clone()
            },
            OAuthAuthorizationRequest {
                response_type: "a".repeat(17),
                ..valid.clone()
            },
            OAuthAuthorizationRequest {
                client_id: "a".repeat(MAX_OAUTH_CLIENT_ID_BYTES + 1),
                ..valid.clone()
            },
            OAuthAuthorizationRequest {
                scope: "a".repeat(MAX_OAUTH_SCOPE_BYTES + 1),
                ..valid.clone()
            },
            OAuthAuthorizationRequest {
                state: "a".repeat(31),
                ..valid.clone()
            },
            OAuthAuthorizationRequest {
                state: "a".repeat(129),
                ..valid.clone()
            },
            OAuthAuthorizationRequest {
                state: format!("{}+", "a".repeat(31)),
                ..valid.clone()
            },
            OAuthAuthorizationRequest {
                code_challenge: "a".repeat(42),
                ..valid.clone()
            },
            OAuthAuthorizationRequest {
                code_challenge: "a".repeat(44),
                ..valid.clone()
            },
            OAuthAuthorizationRequest {
                code_challenge: format!("{}=", "a".repeat(42)),
                ..valid.clone()
            },
            OAuthAuthorizationRequest {
                code_challenge: format!("{}+", "a".repeat(42)),
                ..valid.clone()
            },
            OAuthAuthorizationRequest {
                redirect_uri: " camellia-nexus://auth/callback".into(),
                ..valid.clone()
            },
            OAuthAuthorizationRequest {
                redirect_uri: "camellia-nexus://auth/other".into(),
                ..valid.clone()
            },
            OAuthAuthorizationRequest {
                redirect_uri: "http://127.0.0.1/auth/callback".into(),
                ..valid.clone()
            },
            OAuthAuthorizationRequest {
                redirect_uri: "http://localhost:49152/auth/callback".into(),
                ..valid.clone()
            },
            OAuthAuthorizationRequest {
                redirect_uri: "http://[::1]:49152/auth/callback".into(),
                ..valid.clone()
            },
            OAuthAuthorizationRequest {
                redirect_uri: "a".repeat(MAX_OAUTH_REDIRECT_URI_BYTES + 1),
                ..valid.clone()
            },
            OAuthAuthorizationRequest {
                code_challenge_method: "S256 ".into(),
                ..valid.clone()
            },
            OAuthAuthorizationRequest {
                code_challenge_method: "a".repeat(17),
                ..valid.clone()
            },
        ];
        for request in invalid_requests {
            assert!(
                matches!(
                    policy.validate_authorization_request(&request),
                    Err(ApiError::InvalidRequest)
                ),
                "request must be rejected: {request:?}"
            );
        }
    }

    async fn register_result(
        service: &LicenseService,
    ) -> Result<(RefreshSession, SigningKey, String, String)> {
        let device_key = test_signing_key();
        let device_id = uuid::Uuid::new_v4().to_string();
        let authorization_code = issue_authorization_code(service, TEST_PKCE_VERIFIER).await;
        let request = registration_request(
            &device_key,
            &device_id,
            authorization_code,
            "1.0.0",
            "test",
            Some("test"),
        );
        let thumbprint = request.device.public_key_thumbprint.clone();
        let response = service.register_device(request).await?;
        Ok((response.refresh_session, device_key, device_id, thumbprint))
    }

    fn registration_request(
        device_key: &SigningKey,
        device_id: &str,
        authorization_code: String,
        app_version: &str,
        platform: &str,
        display_name: Option<&str>,
    ) -> DeviceRegistrationRequest {
        let public_key_pem = device_key
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .expect("device public");
        let public_der = device_key.verifying_key().to_public_key_der().expect("der");
        let thumbprint = format!(
            "sha256:{}",
            sha2::Sha256::digest(public_der.as_ref())
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        );
        DeviceRegistrationRequest {
            device: DeviceRegistrationMetadata {
                device_id: device_id.to_owned(),
                public_key_pem,
                public_key_thumbprint: thumbprint,
                platform: platform.to_owned(),
                app_version: app_version.to_owned(),
                display_name: display_name.map(str::to_owned),
            },
            authorization_code: SecretValue(authorization_code),
            pkce_verifier: SecretValue(TEST_PKCE_VERIFIER.into()),
            redirect_uri: "camellia-nexus://auth/callback".into(),
        }
    }

    #[tokio::test]
    async fn refreshes_entitlement_and_rotates_session() {
        let (service, _entitlement_key, public_pem) = fixture();
        let (session, device_key, device_id, thumbprint) = register(&service).await;
        let session = activate_registered_device(&service, &session, &device_key, &device_id).await;
        let challenge = service
            .issue_challenge(
                &session,
                ChallengeRequest {
                    device_id: device_id.clone(),
                    requested_scope: DEFAULT_SCOPE.into(),
                },
            )
            .await
            .expect("challenge");
        let proof = sign_device_challenge(&device_key, &challenge, &device_id, "1.0.0");
        let response = service
            .refresh_entitlement(&session, EntitlementRefreshRequest { proof })
            .await
            .expect("refresh");
        assert_ne!(
            session.0.as_str(),
            response.rotated_refresh_session.0.as_str()
        );
        let header = decode_header(response.entitlement.expose()).expect("header");
        assert_eq!(header.alg, Algorithm::ES256);
        assert_eq!(header.kid.as_deref(), Some("entitlement-test"));
        let claims: EntitlementClaims = decode_claims(response.entitlement.expose(), &public_pem);
        assert_eq!(claims.plan, Plan::Pro);
        assert_eq!(claims.device_id, device_id);
        assert_eq!(claims.device_key_thumbprint, thumbprint);
    }

    #[tokio::test]
    async fn entitlement_policy_caps_the_transition_and_enforces_before_rotation() {
        let policy = ClientVersionPolicy {
            minimum_version: "2.0.0".into(),
            recommended_version: "2.1.0".into(),
            enforce_after: 1_100,
        };
        let (service, repository, _, public_pem, clock) =
            fixture_with_client_version_policy(1_000, policy.clone());
        let (session, device_key, device_id, _) = register(&service).await;
        let session = activate_registered_device(&service, &session, &device_key, &device_id).await;
        let challenge = service
            .issue_challenge(
                &session,
                ChallengeRequest {
                    device_id: device_id.clone(),
                    requested_scope: DEFAULT_SCOPE.into(),
                },
            )
            .await
            .expect("noncanonical-version challenge");
        let proof = sign_device_challenge(&device_key, &challenge, &device_id, "1.0");
        assert!(matches!(
            service
                .refresh_entitlement(&session, EntitlementRefreshRequest { proof })
                .await,
            Err(ApiError::InvalidRequest)
        ));
        let (claims, session) =
            refresh_entitlement_claims(&service, &session, &device_key, &device_id, &public_pem)
                .await;
        assert_eq!(claims.client_version_policy, policy);
        assert_eq!(claims.refresh_after, 1_100);
        assert_eq!(claims.expires_at, 1_100);

        let challenge = service
            .issue_challenge(
                &session,
                ChallengeRequest {
                    device_id: device_id.clone(),
                    requested_scope: DEFAULT_SCOPE.into(),
                },
            )
            .await
            .expect("supported-client challenge before enforcement");
        let proof = sign_device_challenge(&device_key, &challenge, &device_id, "2.0.0");
        let response = service
            .refresh_entitlement(&session, EntitlementRefreshRequest { proof })
            .await
            .expect("supported client is not capped by a future enforcement boundary");
        let supported_claims: EntitlementClaims =
            decode_claims(response.entitlement.expose(), &public_pem);
        assert!(supported_claims.refresh_after > policy.enforce_after);
        assert!(supported_claims.expires_at > policy.enforce_after);
        let session = response.rotated_refresh_session;

        clock.set(1_100);
        let challenge = service
            .issue_challenge(
                &session,
                ChallengeRequest {
                    device_id: device_id.clone(),
                    requested_scope: DEFAULT_SCOPE.into(),
                },
            )
            .await
            .expect("outdated-client challenge");
        let proof = sign_device_challenge(&device_key, &challenge, &device_id, "1.0.0");
        assert!(matches!(
            service
                .refresh_entitlement(&session, EntitlementRefreshRequest { proof })
                .await,
            Err(ApiError::ClientUpgradeRequired(ref returned)) if returned == &policy
        ));

        let challenge = service
            .issue_challenge(
                &session,
                ChallengeRequest {
                    device_id: device_id.clone(),
                    requested_scope: DEFAULT_SCOPE.into(),
                },
            )
            .await
            .expect("supported-client retry challenge");
        let proof = sign_device_challenge(&device_key, &challenge, &device_id, "2.0.0");
        service
            .refresh_entitlement(&session, EntitlementRefreshRequest { proof })
            .await
            .expect("the rejected refresh did not rotate the session");
        let device = repository
            .device(&device_id)
            .await
            .unwrap()
            .expect("registered device");
        assert_eq!(device.metadata.app_version, "2.0.0");
        assert_eq!(device.last_seen_at, Some(1_100));
    }

    #[tokio::test]
    async fn registration_version_gate_preserves_the_code_and_refreshes_mutable_metadata() {
        let policy = ClientVersionPolicy {
            minimum_version: "2.0.0".into(),
            recommended_version: "2.1.0".into(),
            enforce_after: 0,
        };
        let (service, repository, _, _, _) =
            fixture_with_client_version_policy(1_000, policy.clone());
        let device_key = test_signing_key();
        let device_id = uuid::Uuid::new_v4().to_string();
        let authorization_code = issue_authorization_code(&service, TEST_PKCE_VERIFIER).await;
        let mut request = registration_request(
            &device_key,
            &device_id,
            authorization_code,
            "1.0.0",
            "Linux",
            Some("Original"),
        );
        assert!(matches!(
            service.register_device(request.clone()).await,
            Err(ApiError::ClientUpgradeRequired(ref returned)) if returned == &policy
        ));
        request.device.app_version = "2.0".into();
        assert!(matches!(
            service.register_device(request.clone()).await,
            Err(ApiError::InvalidRequest)
        ));
        request.device.app_version = "2.0.0".into();
        service
            .register_device(request.clone())
            .await
            .expect("policy denials did not consume the authorization code");
        let original_key = request.device.public_key_pem.clone();

        request.authorization_code =
            SecretValue(issue_authorization_code(&service, TEST_PKCE_VERIFIER).await);
        request.device.app_version = "2.1.0".into();
        request.device.platform = " Windows ".into();
        request.device.display_name = Some(" Laptop ".into());
        service
            .register_device(request)
            .await
            .expect("active-device login refreshes mutable metadata");
        let device = repository
            .device(&device_id)
            .await
            .unwrap()
            .expect("registered device");
        assert_eq!(device.metadata.public_key_pem, original_key);
        assert_eq!(device.metadata.app_version, "2.1.0");
        assert_eq!(device.metadata.platform, "Windows");
        assert_eq!(device.metadata.display_name.as_deref(), Some("Laptop"));
    }

    #[tokio::test]
    async fn activation_confirmation_rechecks_version_at_the_enforcement_boundary() {
        let policy = ClientVersionPolicy {
            minimum_version: "2.0.0".into(),
            recommended_version: "2.0.0".into(),
            enforce_after: 1_100,
        };
        let (service, repository, _, _, clock) =
            fixture_with_client_version_policy(1_000, policy.clone());
        repository
            .upsert_account(Account::active("policy-confirm", 1_000))
            .await
            .unwrap();
        let license = License::default_pro("policy-confirm", 1_000);
        repository.upsert_license(license.clone()).await.unwrap();
        let activation_code = "policy-confirm-activation";
        repository
            .upsert_activation_code(activation_code_record(
                activation_code,
                "policy-confirm",
                &license.id,
                1_000,
                1,
            ))
            .await
            .unwrap();
        let device_key = test_signing_key();
        let device_id = uuid::Uuid::new_v4().to_string();
        let registered =
            register_database_device(&service, activation_code, &device_key, &device_id)
                .await
                .expect("pre-enforcement registration");
        let challenge = service
            .issue_challenge(
                &registered.refresh_session,
                ChallengeRequest {
                    device_id: device_id.clone(),
                    requested_scope: ACTIVATION_VERIFY_SCOPE.into(),
                },
            )
            .await
            .unwrap();
        let proof = sign_device_challenge(&device_key, &challenge, &device_id, "1.0.0");
        let verified = service
            .verify_activation(
                &registered.refresh_session,
                ActivationVerificationRequest { proof },
            )
            .await
            .expect("pre-enforcement activation proof");

        clock.set(1_100);
        assert!(matches!(
            service
                .confirm_activation(&verified.rotated_refresh_session)
                .await,
            Err(ApiError::ClientUpgradeRequired(ref returned)) if returned == &policy
        ));
        assert_eq!(
            repository
                .activation_code_by_hash(&sha256_hex(activation_code))
                .await
                .unwrap()
                .unwrap()
                .redeemed_count,
            0
        );

        let challenge = service
            .issue_challenge(
                &verified.rotated_refresh_session,
                ChallengeRequest {
                    device_id: device_id.clone(),
                    requested_scope: ACTIVATION_VERIFY_SCOPE.into(),
                },
            )
            .await
            .unwrap();
        let proof = sign_device_challenge(&device_key, &challenge, &device_id, "2.0.0");
        let upgraded = service
            .verify_activation(
                &verified.rotated_refresh_session,
                ActivationVerificationRequest { proof },
            )
            .await
            .expect("supported activation proof");
        service
            .confirm_activation(&upgraded.rotated_refresh_session)
            .await
            .expect("supported client consumes activation grant");
        assert_eq!(
            repository
                .activation_code_by_hash(&sha256_hex(activation_code))
                .await
                .unwrap()
                .unwrap()
                .redeemed_count,
            1
        );
    }

    #[tokio::test]
    async fn license_expiry_caps_entitlement_lease_and_blocks_refresh_after_expiry() {
        let (service, repository, _entitlement_key, public_pem) = fixture_with_repository();
        let (session, device_key, device_id, _) = register(&service).await;
        let session = activate_registered_device(&service, &session, &device_key, &device_id).await;

        let mut license = service
            .repository
            .license("lic_acct_test")
            .await
            .unwrap()
            .expect("license");
        license.expires_at = Some(1_200);
        service
            .repository
            .upsert_license(license.clone())
            .await
            .unwrap();

        let (claims, session) =
            refresh_entitlement_claims(&service, &session, &device_key, &device_id, &public_pem)
                .await;
        assert_eq!(claims.license_expires_at, Some(1_200));
        assert_eq!(claims.refresh_after, 1_200);
        assert_eq!(claims.expires_at, 1_200);

        license.expires_at = Some(1_000);
        service.repository.upsert_license(license).await.unwrap();
        assert!(matches!(
            entitlement_status_with_version(&service, &session, &device_key, &device_id, "1.0.0",)
                .await,
            Err(ApiError::LicenseExpired)
        ));
        assert!(repository.audit_events().unwrap().iter().any(|event| {
            event.event_type == "entitlement_status_denied"
                && event.reason_code.as_deref() == Some("license_expired")
                && event.device_id.as_deref() == Some(device_id.as_str())
        }));
        let challenge = service
            .issue_challenge(
                &session,
                ChallengeRequest {
                    device_id: device_id.clone(),
                    requested_scope: DEFAULT_SCOPE.into(),
                },
            )
            .await
            .expect("refresh challenge");
        let proof = sign_device_challenge(&device_key, &challenge, &device_id, "1.0.0");
        assert!(matches!(
            service
                .refresh_entitlement(&session, EntitlementRefreshRequest { proof })
                .await,
            Err(ApiError::LicenseExpired)
        ));
    }

    #[tokio::test]
    async fn repository_rate_limiter_enforces_fixed_windows() {
        let repository = MemoryRepository::default();
        assert!(
            repository
                .consume_rate_limit("challenge", "device", 1_000, 2, 60)
                .await
                .unwrap()
        );
        assert!(
            repository
                .consume_rate_limit("challenge", "device", 1_001, 2, 60)
                .await
                .unwrap()
        );
        assert!(
            !repository
                .consume_rate_limit("challenge", "device", 1_002, 2, 60)
                .await
                .unwrap()
        );
        assert!(
            repository
                .consume_rate_limit("challenge", "device", 1_061, 2, 60)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn repository_rate_limiter_keeps_scopes_and_keys_independent() {
        let repository = MemoryRepository::default();
        assert!(
            repository
                .consume_rate_limit("authorization_code_global", "global", 1_000, 1, 60)
                .await
                .unwrap()
        );
        assert!(
            !repository
                .consume_rate_limit("authorization_code_global", "global", 1_001, 1, 60)
                .await
                .unwrap()
        );
        assert!(
            repository
                .consume_rate_limit("authorization_code", "code-a", 1_001, 1, 60)
                .await
                .unwrap()
        );
        assert!(
            repository
                .consume_rate_limit("authorization_code", "code-b", 1_001, 1, 60)
                .await
                .unwrap()
        );
    }

    #[test]
    fn system_clock_never_moves_behind_its_last_observation() {
        let clock = SystemClock::default();
        clock.last_seen.store(i64::MAX - 1, Ordering::Release);
        assert_eq!(clock.now(), i64::MAX - 1);
        assert_eq!(clock.now(), i64::MAX - 1);
    }

    #[test]
    fn persistent_time_observation_does_not_double_count_elapsed_time() {
        let authority = PersistentTimeAuthority::new(1_000, 60);
        assert_eq!(authority.now_at_elapsed(1), 1_001);

        authority.observe(1_002);
        assert_eq!(authority.now_at_elapsed(1), 1_002);
        assert_eq!(authority.now_at_elapsed(2), 1_002);
        assert_eq!(authority.now_at_elapsed(3), 1_003);

        authority.observe(1_001);
        assert_eq!(authority.now_at_elapsed(2), 1_002);
    }

    #[tokio::test]
    async fn audits_denied_authorization_code_attempts() {
        let (service, repository, _, _) = fixture_with_repository();
        assert!(matches!(
            service
                .create_authorization_redirect(
                    "wrong-activation-code",
                    oauth_request(TEST_PKCE_VERIFIER),
                )
                .await,
            Err(ApiError::ActivationCodeInvalid)
        ));
        assert!(matches!(
            service
                .create_authorization_redirect(
                    "another-wrong-activation-code",
                    oauth_request(TEST_PKCE_VERIFIER),
                )
                .await,
            Err(ApiError::ActivationCodeInvalid)
        ));
        let events = repository.audit_events().expect("audit events");
        assert_eq!(
            events
                .iter()
                .filter(|event| {
                    event.event_type == "authorization_code_denied"
                        && event.outcome == "denied"
                        && event.reason_code.as_deref() == Some("activation_code_unknown")
                })
                .count(),
            1,
            "repeated anonymous failures in one sample window must not grow audit storage",
        );
    }

    #[tokio::test]
    async fn audits_logout_session_end() {
        let (service, repository, _, _) = fixture_with_repository();
        let (session, _, device_id, _) = register(&service).await;
        service.logout(session).await.expect("logout");
        let events = repository.audit_events().expect("audit events");
        assert!(events.iter().any(|event| {
            event.event_type == "session_logout"
                && event.outcome == "succeeded"
                && event.device_id.as_deref() == Some(device_id.as_str())
                && event.reason_code.as_deref() == Some("device_sessions_revoked")
        }));
    }

    #[tokio::test]
    async fn a_new_login_replaces_every_existing_session_for_the_device() {
        let (service, repository, _, _) = fixture_with_repository();
        let (first, device_key, device_id, _) = register(&service).await;
        let second =
            register_database_device(&service, TEST_ACTIVATION_CODE, &device_key, &device_id)
                .await
                .expect("repeat device login")
                .refresh_session;

        let first = repository
            .session_by_hash(&sha256_hex(&first.0))
            .await
            .unwrap()
            .expect("first session");
        let second = repository
            .session_by_hash(&sha256_hex(&second.0))
            .await
            .unwrap()
            .expect("replacement session");
        assert!(!first.active);
        assert!(second.active);
        assert_ne!(first.family_id, second.family_id);
    }

    #[tokio::test]
    async fn unproven_login_cannot_interrupt_a_proven_device_session() {
        let (service, repository, _, _) = fixture_with_repository();
        let (initial, device_key, device_id, _) = register(&service).await;
        let proven = activate_registered_device(&service, &initial, &device_key, &device_id).await;

        let replacement =
            register_database_device(&service, TEST_ACTIVATION_CODE, &device_key, &device_id)
                .await
                .expect("unproven replacement");
        assert!(
            repository
                .session_by_hash(&sha256_hex(&proven.0))
                .await
                .unwrap()
                .unwrap()
                .active
        );

        let replacement = activate_registered_device(
            &service,
            &replacement.refresh_session,
            &device_key,
            &device_id,
        )
        .await;
        assert!(
            !repository
                .session_by_hash(&sha256_hex(&proven.0))
                .await
                .unwrap()
                .unwrap()
                .active
        );
        assert!(
            repository
                .session_by_hash(&sha256_hex(&replacement.0))
                .await
                .unwrap()
                .unwrap()
                .active
        );
    }

    #[tokio::test]
    async fn stale_session_logout_does_not_revoke_a_replacement_session() {
        let (service, repository, _, _) = fixture_with_repository();
        let (initial, device_key, device_id, _) = register(&service).await;
        let stale = activate_registered_device(&service, &initial, &device_key, &device_id).await;
        let replacement =
            register_database_device(&service, TEST_ACTIVATION_CODE, &device_key, &device_id)
                .await
                .expect("replacement registration");
        let replacement = activate_registered_device(
            &service,
            &replacement.refresh_session,
            &device_key,
            &device_id,
        )
        .await;

        service
            .logout(stale)
            .await
            .expect("stale logout is idempotent");

        assert!(
            repository
                .session_by_hash(&sha256_hex(&replacement.0))
                .await
                .unwrap()
                .unwrap()
                .active
        );
    }

    #[tokio::test]
    async fn logout_revokes_all_session_families_for_the_device() {
        let (service, repository, _, _) = fixture_with_repository();
        let (session, _, device_id, _) = register(&service).await;
        let sibling_token = "sibling-session-token-that-is-long-enough";
        repository
            .insert_session(RefreshSessionRecord {
                token_hash: sha256_hex(sibling_token),
                account_id: "acct_test".to_owned(),
                device_id: device_id.clone(),
                family_id: "sibling-family".to_owned(),
                family_created_at: 1_000,
                absolute_expires_at: 3_000,
                active: true,
                expires_at: 2_000,
                rotated_to_hash: None,
                rotated_at: None,
                pending_activation_code_hash: None,
                activation_verified_at: None,
                activation_confirmation_consumed: false,
                proof_state: RefreshSessionProofState::DeviceProven,
            })
            .await
            .unwrap();

        service.logout(session).await.expect("logout");

        assert!(
            !repository
                .session_by_hash(&sha256_hex(sibling_token))
                .await
                .unwrap()
                .unwrap()
                .active
        );
    }

    #[tokio::test]
    async fn removed_device_can_reactivate_but_revoked_and_suspicious_devices_cannot() {
        let repository = MemoryRepository::default();
        let entitlement_key = test_signing_key();
        let signer = EntitlementSigner::from_signing_key("entitlement-test", &entitlement_key);
        let service = LicenseService::with_clock_and_authorization(
            Arc::new(repository.clone()),
            signer,
            "https://license.test",
            "camellia-nexus-desktop",
            Arc::new(TestClock::new(1_000)),
            AuthorizationPolicy::new(
                "camellia-nexus-desktop",
                vec!["camellia-nexus://auth/callback".to_owned()],
                Vec::<(String, String)>::new(),
            )
            .unwrap(),
        );
        let account_id = "acct_reactivation";
        repository
            .upsert_account(Account::active(account_id, 1_000))
            .await
            .unwrap();
        let license = License::default_pro(account_id, 1_000);
        repository.upsert_license(license.clone()).await.unwrap();
        let device_key = test_signing_key();
        let device_id = uuid::Uuid::new_v4().to_string();

        for code in ["database-code-first", "database-code-second"] {
            repository
                .upsert_activation_code(activation_code_record(
                    code,
                    account_id,
                    &license.id,
                    1_000,
                    1,
                ))
                .await
                .unwrap();
        }
        let registered =
            register_database_device(&service, "database-code-first", &device_key, &device_id)
                .await
                .unwrap();
        assert!(matches!(
            service
                .confirm_activation(&registered.refresh_session)
                .await,
            Err(ApiError::AuthorizationRequired)
        ));
        let active_session = activate_registered_device(
            &service,
            &registered.refresh_session,
            &device_key,
            &device_id,
        )
        .await;
        let removal_scope = device_removal_scope(&device_id);
        let removal_challenge = service
            .issue_challenge(
                &active_session,
                ChallengeRequest {
                    device_id: device_id.clone(),
                    requested_scope: removal_scope,
                },
            )
            .await
            .unwrap();
        let removal_proof =
            sign_device_challenge(&device_key, &removal_challenge, &device_id, "1.0.0");
        service
            .remove_device(
                &active_session,
                &device_id,
                DeviceRemovalRequest {
                    proof: removal_proof,
                    operation_id: uuid::Uuid::new_v4().to_string(),
                },
            )
            .await
            .unwrap();
        assert!(matches!(
            service
                .entitlement_status(&active_session, invalid_status_request(&device_id))
                .await,
            Err(ApiError::AuthorizationRequired)
        ));

        let registered =
            register_database_device(&service, "database-code-second", &device_key, &device_id)
                .await
                .unwrap();
        assert_eq!(registered.device_state, DeviceState::PendingActivation);
        let active_session = activate_registered_device(
            &service,
            &registered.refresh_session,
            &device_key,
            &device_id,
        )
        .await;
        assert_eq!(
            entitlement_status_with_version(
                &service,
                &active_session,
                &device_key,
                &device_id,
                "1.0.0",
            )
            .await
            .unwrap()
            .device_state,
            DeviceState::Active
        );

        for (state, code) in [
            (DeviceState::Revoked, "database-code-revoked"),
            (DeviceState::Suspicious, "database-code-suspicious"),
        ] {
            repository
                .set_device_state(&device_id, state, 1_000)
                .await
                .unwrap();
            repository
                .upsert_activation_code(activation_code_record(
                    code,
                    account_id,
                    &license.id,
                    1_000,
                    1,
                ))
                .await
                .unwrap();
            assert!(matches!(
                register_database_device(&service, code, &device_key, &device_id).await,
                Err(ApiError::DeviceStateDenied(actual)) if actual == state
            ));
        }
    }

    #[tokio::test]
    async fn user_removal_cannot_downgrade_revoked_or_suspicious_devices() {
        for denied_state in [DeviceState::Revoked, DeviceState::Suspicious] {
            let (service, repository, _, _) = fixture_with_repository();
            let (requester_session, requester_key, requester_id, _) = register(&service).await;
            let requester_session = activate_registered_device(
                &service,
                &requester_session,
                &requester_key,
                &requester_id,
            )
            .await;
            let (target_session, target_key, target_id, _) = register(&service).await;
            let _target_session =
                activate_registered_device(&service, &target_session, &target_key, &target_id)
                    .await;
            repository
                .set_device_state(&target_id, denied_state, 1_001)
                .await
                .unwrap();

            let challenge = service
                .issue_challenge(
                    &requester_session,
                    ChallengeRequest {
                        device_id: requester_id.clone(),
                        requested_scope: device_removal_scope(&target_id),
                    },
                )
                .await
                .unwrap();
            let proof = sign_device_challenge(&requester_key, &challenge, &requester_id, "1.0.0");
            assert!(matches!(
                service
                    .remove_device(
                        &requester_session,
                        &target_id,
                        DeviceRemovalRequest {
                            proof,
                            operation_id: uuid::Uuid::new_v4().to_string(),
                        },
                    )
                    .await,
                Err(ApiError::DeviceStateDenied(state)) if state == denied_state
            ));
            assert_eq!(
                repository.device(&target_id).await.unwrap().unwrap().state,
                denied_state
            );
        }
    }

    #[tokio::test]
    async fn minimum_version_policy_does_not_block_device_removal_safety_action() {
        let policy = ClientVersionPolicy {
            minimum_version: "2.0.0".into(),
            recommended_version: "2.0.0".into(),
            enforce_after: 1_100,
        };
        let (service, repository, _, _, clock) = fixture_with_client_version_policy(1_000, policy);
        let (session, device_key, device_id, _) = register(&service).await;
        let session = activate_registered_device(&service, &session, &device_key, &device_id).await;
        clock.set(1_100);

        let challenge = service
            .issue_challenge(
                &session,
                ChallengeRequest {
                    device_id: device_id.clone(),
                    requested_scope: device_removal_scope(&device_id),
                },
            )
            .await
            .expect("an outdated client can request a safety challenge");
        let proof = sign_device_challenge(&device_key, &challenge, &device_id, "1.0.0");
        let operation_id = uuid::Uuid::new_v4().to_string();
        let removal = DeviceRemovalRequest {
            proof,
            operation_id: operation_id.clone(),
        };
        service
            .remove_device(&session, &device_id, removal.clone())
            .await
            .expect("minimum-version enforcement must not prevent revocation");
        assert!(
            service
                .device_removal_status(&session, &device_id, &operation_id)
                .await
                .expect("removed session may query its exact committed operation")
                .committed
        );
        service
            .remove_device(&session, &device_id, removal)
            .await
            .expect("an exact retry remains successful after self-removal revoked the session");

        let removed = repository.device(&device_id).await.unwrap().unwrap();
        assert_eq!(removed.state, DeviceState::Removed);
        assert_eq!(removed.metadata.app_version, "1.0.0");
        assert_eq!(removed.last_seen_at, Some(1_100));
    }

    #[tokio::test]
    async fn entitlement_status_requires_a_dedicated_single_use_device_proof() {
        let (service, _, _) = fixture();
        let (session, device_key, device_id, _) = register(&service).await;
        let session = activate_registered_device(&service, &session, &device_key, &device_id).await;
        let challenge = service
            .issue_challenge(
                &session,
                ChallengeRequest {
                    device_id: device_id.clone(),
                    requested_scope: DEFAULT_SCOPE.into(),
                },
            )
            .await
            .expect("wrong-scope challenge");
        let proof = sign_device_challenge(&device_key, &challenge, &device_id, "1.0.0");
        let request = EntitlementStatusRequest {
            proof: proof.clone(),
        };

        assert!(matches!(
            service.entitlement_status(&session, request).await,
            Err(ApiError::InvalidChallenge)
        ));
        assert!(matches!(
            service
                .entitlement_status(&session, EntitlementStatusRequest { proof })
                .await,
            Err(ApiError::ChallengeReplay)
        ));
    }

    #[tokio::test]
    async fn entitlement_status_enforces_the_current_proven_build_without_rotating_the_session() {
        let policy = ClientVersionPolicy {
            minimum_version: "2.0.0".into(),
            recommended_version: "2.0.0".into(),
            enforce_after: 1_100,
        };
        let (service, repository, _, _, clock) = fixture_with_client_version_policy(1_000, policy);
        let (session, device_key, device_id, _) = register(&service).await;
        let session = activate_registered_device(&service, &session, &device_key, &device_id).await;
        clock.set(1_100);

        entitlement_status_with_version(&service, &session, &device_key, &device_id, "2.0.0")
            .await
            .expect("current supported build");
        assert_eq!(
            repository
                .device(&device_id)
                .await
                .unwrap()
                .unwrap()
                .metadata
                .app_version,
            "2.0.0"
        );

        assert!(matches!(
            entitlement_status_with_version(&service, &session, &device_key, &device_id, "1.0.0",)
                .await,
            Err(ApiError::ClientUpgradeRequired(_))
        ));
        assert_eq!(
            repository
                .device(&device_id)
                .await
                .unwrap()
                .unwrap()
                .metadata
                .app_version,
            "1.0.0"
        );

        entitlement_status_with_version(&service, &session, &device_key, &device_id, "2.0.0")
            .await
            .expect("upgrade-required response must not invalidate the session");
    }

    #[tokio::test]
    async fn device_listing_and_removal_are_scoped_to_the_current_license() {
        let (service, repository, _, _) = fixture_with_repository();
        let (requester_session, requester_key, requester_id, _) = register(&service).await;
        let requester_session =
            activate_registered_device(&service, &requester_session, &requester_key, &requester_id)
                .await;
        let mut other_license = License::default_pro("acct_test", 1_000);
        other_license.id = "lic_other".to_owned();
        repository
            .upsert_license(other_license.clone())
            .await
            .unwrap();
        let target_id = uuid::Uuid::new_v4().to_string();
        let target_key = test_signing_key();
        let public_key_pem = target_key
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .unwrap();
        let public_der = target_key.verifying_key().to_public_key_der().unwrap();
        repository
            .upsert_device(Device {
                account_id: "acct_test".to_owned(),
                license_id: other_license.id,
                metadata: DeviceRegistrationMetadata {
                    device_id: target_id.clone(),
                    public_key_pem,
                    public_key_thumbprint: format!(
                        "sha256:{}",
                        sha2::Sha256::digest(public_der.as_ref())
                            .iter()
                            .map(|byte| format!("{byte:02x}"))
                            .collect::<String>()
                    ),
                    platform: "test".to_owned(),
                    app_version: "1.0.0".to_owned(),
                    display_name: Some("Other license".to_owned()),
                },
                state: DeviceState::Active,
                pending_activation_code_hash: None,
                pending_activation_expires_at: None,
                created_at: 1_000,
                last_seen_at: Some(1_000),
            })
            .await
            .unwrap();

        assert!(
            service
                .list_devices(&requester_session, RegisteredDevicePageRequest::default())
                .await
                .unwrap()
                .devices
                .iter()
                .all(|device| device.device_id != target_id)
        );
        let challenge = service
            .issue_challenge(
                &requester_session,
                ChallengeRequest {
                    device_id: requester_id.clone(),
                    requested_scope: device_removal_scope(&target_id),
                },
            )
            .await
            .unwrap();
        let proof = sign_device_challenge(&requester_key, &challenge, &requester_id, "1.0.0");
        assert!(matches!(
            service
                .remove_device(
                    &requester_session,
                    &target_id,
                    DeviceRemovalRequest {
                        proof,
                        operation_id: uuid::Uuid::new_v4().to_string(),
                    },
                )
                .await,
            Err(ApiError::DeviceDenied)
        ));

        let requester = repository
            .device(&requester_id)
            .await
            .unwrap()
            .expect("requester device");
        let removable_id = uuid::Uuid::new_v4().to_string();
        let mut removable = requester;
        removable.metadata.device_id = removable_id.clone();
        removable.metadata.public_key_thumbprint = format!("sha256:{removable_id}");
        removable.metadata.display_name = Some("Removable device".to_owned());
        repository.upsert_device(removable).await.unwrap();

        let operation_id = uuid::Uuid::new_v4().to_string();
        for attempt in 0..2 {
            let challenge = service
                .issue_challenge(
                    &requester_session,
                    ChallengeRequest {
                        device_id: requester_id.clone(),
                        requested_scope: device_removal_scope(&removable_id),
                    },
                )
                .await
                .unwrap();
            let proof = sign_device_challenge(&requester_key, &challenge, &requester_id, "1.0.0");
            service
                .remove_device(
                    &requester_session,
                    &removable_id,
                    DeviceRemovalRequest {
                        proof,
                        operation_id: operation_id.clone(),
                    },
                )
                .await
                .unwrap();
            let removal_audits = repository
                .audit_events()
                .unwrap()
                .into_iter()
                .filter(|event| {
                    event.event_type == "device_removed"
                        && event.metadata.get("target_device_id") == Some(&removable_id)
                })
                .count();
            assert_eq!(
                removal_audits, 1,
                "attempt {attempt} must not duplicate audit"
            );
        }
        assert!(
            service
                .list_devices(&requester_session, RegisteredDevicePageRequest::default())
                .await
                .unwrap()
                .devices
                .iter()
                .all(|device| device.device_id != removable_id)
        );
        assert!(
            service
                .device_removal_status(&requester_session, &removable_id, &operation_id)
                .await
                .unwrap()
                .committed
        );
        assert!(matches!(
            service
                .device_removal_status(
                    &requester_session,
                    &uuid::Uuid::new_v4().to_string(),
                    &operation_id,
                )
                .await,
            Err(ApiError::IdempotencyConflict)
        ));
    }

    #[tokio::test]
    async fn team_apis_require_the_team_plan_capability() {
        let (service, _, _, _) = fixture_with_repository();
        let (session, device_key, device_id, _) = register(&service).await;
        let session = activate_registered_device(&service, &session, &device_key, &device_id).await;
        let challenge = service
            .issue_challenge(
                &session,
                ChallengeRequest {
                    device_id: device_id.clone(),
                    requested_scope: TEAM_PROFILE_SCOPE.to_owned(),
                },
            )
            .await
            .unwrap();
        let proof = sign_device_challenge(&device_key, &challenge, &device_id, "1.0.0");

        assert!(matches!(
            service.team_profile_authenticated(&session, &proof).await,
            Err(ApiError::CapabilityDenied)
        ));
    }

    #[tokio::test]
    async fn device_listing_uses_stable_license_scoped_cursor_pages() {
        let (service, repository, _, _) = fixture_with_repository();
        let (session, device_key, requester_id, _) = register(&service).await;
        let session =
            activate_registered_device(&service, &session, &device_key, &requester_id).await;
        let requester = repository
            .device(&requester_id)
            .await
            .unwrap()
            .expect("requester device");
        let mut expected = vec![requester_id];

        for suffix in 1..=4 {
            let device_id = format!("00000000-0000-4000-8000-{suffix:012}");
            expected.push(device_id.clone());
            let mut device = requester.clone();
            device.metadata.device_id = device_id.clone();
            device.metadata.public_key_thumbprint = format!("sha256:{device_id}");
            device.metadata.display_name = Some(format!("Page device {suffix}"));
            repository.upsert_device(device).await.unwrap();
        }
        let mut other_license = License::default_pro("acct_test", 1_000);
        other_license.id = "lic_page_other".to_owned();
        repository
            .upsert_license(other_license.clone())
            .await
            .unwrap();
        let mut other_device = requester.clone();
        other_device.license_id = other_license.id;
        other_device.metadata.device_id = "ffffffff-ffff-4fff-8fff-ffffffffffff".to_owned();
        other_device.metadata.public_key_thumbprint = "sha256:other-license".to_owned();
        repository.upsert_device(other_device).await.unwrap();

        expected.sort();
        let first = service
            .list_devices(
                &session,
                RegisteredDevicePageRequest {
                    cursor: None,
                    page_size: Some(2),
                },
            )
            .await
            .unwrap();
        assert_eq!(
            first
                .devices
                .iter()
                .map(|device| device.device_id.as_str())
                .collect::<Vec<_>>(),
            expected[..2]
        );
        assert_eq!(first.next_cursor.as_deref(), Some(expected[1].as_str()));

        let second = service
            .list_devices(
                &session,
                RegisteredDevicePageRequest {
                    cursor: first.next_cursor,
                    page_size: Some(2),
                },
            )
            .await
            .unwrap();
        assert_eq!(
            second
                .devices
                .iter()
                .map(|device| device.device_id.as_str())
                .collect::<Vec<_>>(),
            expected[2..4]
        );
        assert_eq!(second.next_cursor.as_deref(), Some(expected[3].as_str()));

        let final_page = service
            .list_devices(
                &session,
                RegisteredDevicePageRequest {
                    cursor: second.next_cursor,
                    page_size: Some(2),
                },
            )
            .await
            .unwrap();
        assert_eq!(
            final_page
                .devices
                .iter()
                .map(|device| device.device_id.as_str())
                .collect::<Vec<_>>(),
            expected[4..]
        );
        assert!(final_page.next_cursor.is_none());
    }

    #[tokio::test]
    async fn device_listing_rejects_noncanonical_cursors_and_invalid_page_sizes() {
        let (service, _, _, _) = fixture_with_repository();
        let (session, device_key, device_id, _) = register(&service).await;
        let session = activate_registered_device(&service, &session, &device_key, &device_id).await;

        assert!(
            service
                .list_devices(
                    &session,
                    RegisteredDevicePageRequest {
                        cursor: None,
                        page_size: Some(MAX_DEVICE_PAGE_SIZE),
                    },
                )
                .await
                .is_ok()
        );

        for request in [
            RegisteredDevicePageRequest {
                cursor: Some("AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA".to_owned()),
                page_size: None,
            },
            RegisteredDevicePageRequest {
                cursor: Some("not-a-device-id".to_owned()),
                page_size: None,
            },
            RegisteredDevicePageRequest {
                cursor: None,
                page_size: Some(0),
            },
            RegisteredDevicePageRequest {
                cursor: None,
                page_size: Some(MAX_DEVICE_PAGE_SIZE + 1),
            },
        ] {
            assert!(matches!(
                service.list_devices(&session, request).await,
                Err(ApiError::InvalidRequest)
            ));
        }
    }

    #[tokio::test]
    async fn device_listing_defaults_to_fifty_items() {
        let (service, repository, _, _) = fixture_with_repository();
        let (session, device_key, requester_id, _) = register(&service).await;
        let session =
            activate_registered_device(&service, &session, &device_key, &requester_id).await;
        let requester = repository
            .device(&requester_id)
            .await
            .unwrap()
            .expect("requester device");
        for suffix in 1..=50 {
            let device_id = format!("00000000-0000-4000-8000-{suffix:012}");
            let mut device = requester.clone();
            device.metadata.device_id = device_id.clone();
            device.metadata.public_key_thumbprint = format!("sha256:{device_id}");
            repository.upsert_device(device).await.unwrap();
        }

        let first = service
            .list_devices(&session, RegisteredDevicePageRequest::default())
            .await
            .unwrap();
        assert_eq!(first.devices.len(), DEFAULT_DEVICE_PAGE_SIZE as usize);
        let second = service
            .list_devices(
                &session,
                RegisteredDevicePageRequest {
                    cursor: first.next_cursor,
                    page_size: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(second.devices.len(), 1);
        assert!(second.next_cursor.is_none());
    }

    #[tokio::test]
    async fn activation_code_redemption_limit_is_enforced_across_devices() {
        let repository = MemoryRepository::default();
        let entitlement_key = test_signing_key();
        let service = LicenseService::with_clock_and_authorization(
            Arc::new(repository.clone()),
            EntitlementSigner::from_signing_key("entitlement-test", &entitlement_key),
            "https://license.test",
            "camellia-nexus-desktop",
            Arc::new(TestClock::new(1_000)),
            AuthorizationPolicy::new(
                "camellia-nexus-desktop",
                vec!["camellia-nexus://auth/callback".to_owned()],
                Vec::<(String, String)>::new(),
            )
            .unwrap(),
        );
        let account_id = "acct_redemption_limit";
        repository
            .upsert_account(Account::active(account_id, 1_000))
            .await
            .unwrap();
        let license = License::default_pro(account_id, 1_000);
        repository.upsert_license(license.clone()).await.unwrap();
        let code = "database-code-two-redemptions";
        let code_hash = sha256_hex(code);
        repository
            .upsert_activation_code(activation_code_record(
                code,
                account_id,
                &license.id,
                1_000,
                2,
            ))
            .await
            .unwrap();

        for expected_count in 1..=2 {
            let device_key = test_signing_key();
            let device_id = uuid::Uuid::new_v4().to_string();
            let registered = register_database_device(&service, code, &device_key, &device_id)
                .await
                .unwrap();
            activate_registered_device(
                &service,
                &registered.refresh_session,
                &device_key,
                &device_id,
            )
            .await;
            let record = repository
                .activation_code_by_hash(&code_hash)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(record.redeemed_count, expected_count);
            assert_eq!(
                record.status,
                if expected_count == 2 {
                    ActivationCodeStatus::Consumed
                } else {
                    ActivationCodeStatus::Active
                }
            );
        }
        assert!(matches!(
            service
                .create_authorization_redirect(code, oauth_request(TEST_PKCE_VERIFIER))
                .await,
            Err(ApiError::ActivationCodeConsumed)
        ));
    }

    #[tokio::test]
    async fn refresh_entitlement_rejects_wrong_challenge_scope() {
        let (service, _, _) = fixture();
        let (session, device_key, device_id, _) = register(&service).await;
        let challenge = service
            .issue_challenge(
                &session,
                ChallengeRequest {
                    device_id: device_id.clone(),
                    requested_scope: "activation:verify".into(),
                },
            )
            .await
            .expect("challenge");
        let proof = sign_device_challenge(&device_key, &challenge, &device_id, "1.0.0");
        let error = service
            .refresh_entitlement(&session, EntitlementRefreshRequest { proof })
            .await
            .expect_err("wrong challenge scope");
        assert!(matches!(error, ApiError::InvalidChallenge));
    }

    #[tokio::test]
    async fn rejects_arbitrary_authorization_code() {
        let (service, repository, _, _) = fixture_with_repository();
        let device_key = test_signing_key();
        let public_key_pem = device_key
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .expect("device public");
        let public_der = device_key.verifying_key().to_public_key_der().expect("der");
        let thumbprint = format!(
            "sha256:{}",
            sha2::Sha256::digest(public_der.as_ref())
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        );
        let result = service
            .register_device(DeviceRegistrationRequest {
                device: DeviceRegistrationMetadata {
                    device_id: uuid::Uuid::new_v4().to_string(),
                    public_key_pem,
                    public_key_thumbprint: thumbprint,
                    platform: "test".into(),
                    app_version: "1.0.0".into(),
                    display_name: None,
                },
                authorization_code: SecretValue("arbitrary-authorization-code-that-is-long".into()),
                pkce_verifier: SecretValue(TEST_PKCE_VERIFIER.into()),
                redirect_uri: "camellia-nexus://auth/callback".into(),
            })
            .await;
        assert!(matches!(result, Err(ApiError::AuthorizationRequired)));
        let events = repository.audit_events().expect("audit events");
        assert!(events.iter().any(|event| {
            event.event_type == "device_registration_denied"
                && event.outcome == "denied"
                && event.reason_code.as_deref() == Some("authorization_code_invalid")
        }));
    }

    #[tokio::test]
    async fn rejects_pkce_mismatch() {
        let (service, _, _) = fixture();
        let code = issue_authorization_code(&service, TEST_PKCE_VERIFIER).await;
        let device_key = test_signing_key();
        let public_key_pem = device_key
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .expect("device public");
        let public_der = device_key.verifying_key().to_public_key_der().expect("der");
        let thumbprint = format!(
            "sha256:{}",
            sha2::Sha256::digest(public_der.as_ref())
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        );
        let result = service
            .register_device(DeviceRegistrationRequest {
                device: DeviceRegistrationMetadata {
                    device_id: uuid::Uuid::new_v4().to_string(),
                    public_key_pem,
                    public_key_thumbprint: thumbprint,
                    platform: "test".into(),
                    app_version: "1.0.0".into(),
                    display_name: None,
                },
                authorization_code: SecretValue(code),
                pkce_verifier: SecretValue("abcdefghijklmnopqrstuvwxyz0123456789ABCDEFH".into()),
                redirect_uri: "camellia-nexus://auth/callback".into(),
            })
            .await;
        assert!(matches!(result, Err(ApiError::AuthorizationRequired)));
    }

    #[tokio::test]
    async fn inactive_session_preserves_terminal_account_denial() {
        let (service, repository, _, _) = fixture_with_repository();
        let (session, _, device_id, _) = register(&service).await;
        repository
            .revoke_sessions_for_device(&device_id)
            .await
            .expect("revoke fixture session");

        assert!(matches!(
            service.authorize_session(&session, 1_000, false).await,
            Err(ApiError::AuthorizationRequired)
        ));

        let mut account = repository
            .account("acct_test")
            .await
            .expect("account query")
            .expect("account");
        account.state = crate::domain::AccountState::Suspended;
        repository
            .upsert_account(account)
            .await
            .expect("suspend account");
        assert!(matches!(
            service.authorize_session(&session, 1_000, false).await,
            Err(ApiError::AccountSuspended)
        ));

        let mut account = repository
            .account("acct_test")
            .await
            .expect("account query")
            .expect("account");
        account.state = crate::domain::AccountState::Denylisted;
        repository
            .upsert_account(account)
            .await
            .expect("denylist account");
        assert!(matches!(
            service.authorize_session(&session, 1_000, false).await,
            Err(ApiError::AccountDenylisted)
        ));

        let reason_codes = repository
            .audit_events()
            .expect("audit events")
            .into_iter()
            .filter(|event| event.event_type == "session_authorization_denied")
            .filter_map(|event| event.reason_code)
            .collect::<Vec<_>>();
        assert_eq!(
            reason_codes,
            [
                "session_inactive",
                "account_suspended",
                "account_denylisted"
            ]
        );
    }

    #[tokio::test]
    async fn reused_rotated_session_revokes_family() {
        let (service, _, _) = fixture();
        let (session, device_key, device_id, _) = register(&service).await;
        let challenge = service
            .issue_challenge(
                &session,
                ChallengeRequest {
                    device_id: device_id.clone(),
                    requested_scope: "entitlement:refresh".into(),
                },
            )
            .await
            .unwrap();
        let proof = sign_device_challenge(&device_key, &challenge, &device_id, "1.0.0");
        let refreshed = service
            .refresh_entitlement(&session, EntitlementRefreshRequest { proof })
            .await
            .unwrap();
        assert!(matches!(
            service
                .entitlement_status(&session, invalid_status_request(&device_id))
                .await,
            Err(ApiError::RefreshSessionReused)
        ));
        assert!(matches!(
            service
                .entitlement_status(
                    &refreshed.rotated_refresh_session,
                    invalid_status_request(&device_id),
                )
                .await,
            Err(ApiError::AuthorizationRequired)
        ));
    }

    #[tokio::test]
    async fn removed_device_returns_removed_error_code() {
        let (service, repository, _, _) = fixture_with_repository();
        let (session, device_key, device_id, _) = register(&service).await;
        let session = activate_registered_device(&service, &session, &device_key, &device_id).await;
        let challenge = service
            .issue_challenge(
                &session,
                ChallengeRequest {
                    device_id: device_id.clone(),
                    requested_scope: ENTITLEMENT_STATUS_SCOPE.into(),
                },
            )
            .await
            .expect("status challenge");
        let proof = sign_device_challenge(&device_key, &challenge, &device_id, "1.0.0");
        repository
            .set_device_state(&device_id, DeviceState::Removed, 1_001)
            .await
            .expect("remove device");
        assert!(matches!(
            service
                .entitlement_status(&session, invalid_status_request(&device_id))
                .await,
            Err(ApiError::InvalidChallenge)
        ));
        assert!(matches!(
            service
                .entitlement_status(&session, EntitlementStatusRequest { proof })
                .await,
            Err(ApiError::DeviceStateDenied(DeviceState::Removed))
        ));
    }

    #[tokio::test]
    async fn challenge_is_single_use() {
        let (service, _, _) = fixture();
        let (session, device_key, device_id, _) = register(&service).await;
        let challenge = service
            .issue_challenge(
                &session,
                ChallengeRequest {
                    device_id: device_id.clone(),
                    requested_scope: "entitlement:refresh".into(),
                },
            )
            .await
            .unwrap();
        let proof = sign_device_challenge(&device_key, &challenge, &device_id, "1.0.0");
        service
            .refresh_entitlement(
                &session,
                EntitlementRefreshRequest {
                    proof: proof.clone(),
                },
            )
            .await
            .unwrap();
        assert!(matches!(
            service
                .refresh_entitlement(&session, EntitlementRefreshRequest { proof })
                .await,
            Err(ApiError::ChallengeReplay
                | ApiError::RefreshSessionReused
                | ApiError::AuthorizationRequired)
        ));
    }

    #[tokio::test]
    async fn device_proof_recovers_a_proven_refresh_session_after_logout() {
        let (service, repository, _, public_pem) = fixture_with_repository();
        let (session, device_key, device_id, _) = register(&service).await;
        let session = activate_registered_device(&service, &session, &device_key, &device_id).await;
        service.logout(session).await.expect("logout");

        let challenge = service
            .issue_session_recovery_challenge(SessionRecoveryChallengeRequest {
                device_id: device_id.clone(),
            })
            .await
            .expect("recovery challenge");
        assert_eq!(challenge.requested_scope, SESSION_RECOVERY_SCOPE);
        let proof = sign_device_challenge(&device_key, &challenge, &device_id, "1.0.0");
        let recovered = service
            .recover_session(SessionRecoveryRequest { proof })
            .await
            .expect("recover session");
        assert_eq!(recovered.device_state, DeviceState::Active);

        let record = repository
            .session_by_hash(&sha256_hex(&recovered.refresh_session.0))
            .await
            .expect("session query")
            .expect("recovered session");
        assert_eq!(record.proof_state, RefreshSessionProofState::DeviceProven);
        assert_eq!(record.family_created_at, 1_000);
        assert_eq!(
            record.absolute_expires_at,
            1_000 + REFRESH_SESSION_ABSOLUTE_TTL_SECONDS
        );
        assert_eq!(record.expires_at, 1_000 + REFRESH_SESSION_IDLE_TTL_SECONDS);

        let (claims, _) = refresh_entitlement_claims(
            &service,
            &recovered.refresh_session,
            &device_key,
            &device_id,
            &public_pem,
        )
        .await;
        assert_eq!(claims.device_id, device_id);
        assert!(repository.audit_events().unwrap().iter().any(|event| {
            event.event_type == "session_recovered"
                && event.device_id.as_deref() == Some(device_id.as_str())
                && event.reason_code.as_deref() == Some("device_proof")
        }));
    }

    #[tokio::test]
    async fn pending_device_proof_recovers_activation_after_a_lost_rotated_session() {
        let (service, repository, _, _) = fixture_with_repository();
        repository
            .upsert_account(Account::active("acct_test", 1_000))
            .await
            .unwrap();
        repository
            .upsert_license(License::default_pro("acct_test", 1_000))
            .await
            .unwrap();
        let activation_code = "pending-recovery-activation-code";
        repository
            .upsert_activation_code(activation_code_record(
                activation_code,
                "acct_test",
                "lic_acct_test",
                1_000,
                1,
            ))
            .await
            .unwrap();
        let device_key = test_signing_key();
        let device_id = uuid::Uuid::new_v4().to_string();
        let registered =
            register_database_device(&service, activation_code, &device_key, &device_id)
                .await
                .expect("register pending device");
        let session = registered.refresh_session;
        assert_eq!(registered.device_state, DeviceState::PendingActivation);
        repository
            .revoke_sessions_for_device(&device_id)
            .await
            .expect("simulate lost session family");

        let challenge = service
            .issue_session_recovery_challenge(SessionRecoveryChallengeRequest {
                device_id: device_id.clone(),
            })
            .await
            .expect("pending recovery challenge");
        let proof = sign_device_challenge(&device_key, &challenge, &device_id, "1.0.0");
        let recovered = service
            .recover_session(SessionRecoveryRequest { proof })
            .await
            .expect("recover pending activation session");
        assert_eq!(recovered.device_state, DeviceState::PendingActivation);
        let recovered_record = repository
            .session_by_hash(&sha256_hex(&recovered.refresh_session.0))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            recovered_record.proof_state,
            RefreshSessionProofState::DeviceProven
        );

        let active = activate_registered_device(
            &service,
            &recovered.refresh_session,
            &device_key,
            &device_id,
        )
        .await;
        assert_eq!(
            entitlement_status_with_version(&service, &active, &device_key, &device_id, "1.0.0",)
                .await
                .unwrap()
                .device_state,
            DeviceState::Active
        );
        assert_ne!(session.0, active.0);
    }

    #[tokio::test]
    async fn session_recovery_replaces_an_existing_session_for_the_same_device() {
        let (service, repository, _, _) = fixture_with_repository();
        let (session, device_key, device_id, _) = register(&service).await;
        let existing =
            activate_registered_device(&service, &session, &device_key, &device_id).await;
        entitlement_status_with_version(&service, &existing, &device_key, &device_id, "1.0.0")
            .await
            .expect("existing session starts active");

        let challenge = service
            .issue_session_recovery_challenge(SessionRecoveryChallengeRequest {
                device_id: device_id.clone(),
            })
            .await
            .expect("recovery challenge");
        let proof = sign_device_challenge(&device_key, &challenge, &device_id, "1.0.0");
        let recovered = service
            .recover_session(SessionRecoveryRequest { proof })
            .await
            .expect("recover session");

        let existing_record = repository
            .session_by_hash(&sha256_hex(&existing.0))
            .await
            .expect("existing session query")
            .expect("existing session retained for replay detection");
        let recovered_record = repository
            .session_by_hash(&sha256_hex(&recovered.refresh_session.0))
            .await
            .expect("recovered session query")
            .expect("recovered session");
        assert!(!existing_record.active);
        assert!(recovered_record.active);
        assert_ne!(existing_record.family_id, recovered_record.family_id);
        assert!(matches!(
            service
                .entitlement_status(&existing, invalid_status_request(&device_id))
                .await,
            Err(ApiError::AuthorizationRequired)
        ));
        entitlement_status_with_version(
            &service,
            &recovered.refresh_session,
            &device_key,
            &device_id,
            "1.0.0",
        )
        .await
        .expect("replacement session remains authorized");
    }

    #[tokio::test]
    async fn recovery_challenge_is_scope_bound_and_consumed_before_signature_verification() {
        let (service, _, _) = fixture();
        let (session, device_key, device_id, _) = register(&service).await;
        let wrong_scope = service
            .issue_challenge(
                &session,
                ChallengeRequest {
                    device_id: device_id.clone(),
                    requested_scope: DEFAULT_SCOPE.into(),
                },
            )
            .await
            .expect("entitlement challenge");
        let proof = sign_device_challenge(&device_key, &wrong_scope, &device_id, "1.0.0");
        assert!(matches!(
            service
                .recover_session(SessionRecoveryRequest { proof })
                .await,
            Err(ApiError::InvalidChallenge)
        ));

        let challenge = service
            .issue_session_recovery_challenge(SessionRecoveryChallengeRequest {
                device_id: device_id.clone(),
            })
            .await
            .expect("recovery challenge");
        let attacker_key = test_signing_key();
        let invalid_proof = sign_device_challenge(&attacker_key, &challenge, &device_id, "1.0.0");
        assert!(matches!(
            service
                .recover_session(SessionRecoveryRequest {
                    proof: invalid_proof
                })
                .await,
            Err(ApiError::InvalidChallenge)
        ));
        let valid_proof = sign_device_challenge(&device_key, &challenge, &device_id, "1.0.0");
        assert!(matches!(
            service
                .recover_session(SessionRecoveryRequest { proof: valid_proof })
                .await,
            Err(ApiError::InvalidChallenge)
        ));
    }

    #[tokio::test]
    async fn session_recovery_reveals_business_state_only_after_device_proof() {
        let (service, repository, _, _) = fixture_with_repository();
        let (_, device_key, device_id, _) = register(&service).await;
        repository
            .set_device_state(&device_id, DeviceState::Removed, 1_000)
            .await
            .expect("remove device");
        let challenge = service
            .issue_session_recovery_challenge(SessionRecoveryChallengeRequest {
                device_id: device_id.clone(),
            })
            .await
            .expect("removed device receives an indistinguishable challenge");
        let proof = sign_device_challenge(&device_key, &challenge, &device_id, "1.0.0");
        assert!(matches!(
            service
                .recover_session(SessionRecoveryRequest { proof })
                .await,
            Err(ApiError::DeviceStateDenied(DeviceState::Removed))
        ));

        repository
            .set_device_state(&device_id, DeviceState::Active, 1_000)
            .await
            .expect("reactivate fixture");
        let mut license = repository
            .license("lic_acct_test")
            .await
            .expect("license query")
            .expect("license");
        license.status = LicenseStatus::Canceled;
        repository
            .upsert_license(license)
            .await
            .expect("cancel license");
        let challenge = service
            .issue_session_recovery_challenge(SessionRecoveryChallengeRequest {
                device_id: device_id.clone(),
            })
            .await
            .expect("canceled license receives an indistinguishable challenge");
        let proof = sign_device_challenge(&device_key, &challenge, &device_id, "1.0.0");
        assert!(matches!(
            service
                .recover_session(SessionRecoveryRequest { proof })
                .await,
            Err(ApiError::LicenseCanceled)
        ));

        let mut license = repository
            .license("lic_acct_test")
            .await
            .expect("license query")
            .expect("license");
        license.status = LicenseStatus::Active;
        repository
            .upsert_license(license)
            .await
            .expect("restore license");
        let mut account = repository
            .account("acct_test")
            .await
            .expect("account query")
            .expect("account");
        account.state = crate::domain::AccountState::Suspended;
        repository
            .upsert_account(account)
            .await
            .expect("suspend account");
        let challenge = service
            .issue_session_recovery_challenge(SessionRecoveryChallengeRequest {
                device_id: device_id.clone(),
            })
            .await
            .expect("suspended account receives an indistinguishable challenge");
        let proof = sign_device_challenge(&device_key, &challenge, &device_id, "1.0.0");
        assert!(matches!(
            service
                .recover_session(SessionRecoveryRequest { proof })
                .await,
            Err(ApiError::AccountSuspended)
        ));
    }

    #[tokio::test]
    async fn synthetic_recovery_challenge_does_not_authenticate_an_unknown_device() {
        let (service, repository, _, _) = fixture_with_repository();
        let device_id = uuid::Uuid::new_v4().to_string();
        let challenge = service
            .issue_session_recovery_challenge(SessionRecoveryChallengeRequest {
                device_id: device_id.clone(),
            })
            .await
            .expect("unknown UUID receives a synthetic challenge");
        assert_eq!(challenge.requested_scope, SESSION_RECOVERY_SCOPE);
        let attacker_key = test_signing_key();
        let proof = sign_device_challenge(&attacker_key, &challenge, &device_id, "1.0.0");
        assert!(matches!(
            service
                .recover_session(SessionRecoveryRequest {
                    proof: proof.clone(),
                })
                .await,
            Err(ApiError::InvalidChallenge)
        ));
        assert!(matches!(
            repository
                .consume_challenge(&challenge.challenge_id, &device_id, 1_000)
                .await,
            Err(ApiError::ChallengeReplay)
        ));
        assert!(matches!(
            service
                .recover_session(SessionRecoveryRequest { proof })
                .await,
            Err(ApiError::InvalidChallenge)
        ));
    }

    #[tokio::test]
    async fn malformed_recovery_subjects_are_sampled_after_global_admission() {
        let (service, repository, _, _) = fixture_with_repository();
        for _ in 0..2 {
            assert!(matches!(
                service
                    .issue_session_recovery_challenge(SessionRecoveryChallengeRequest {
                        device_id: "not-a-canonical-uuid".to_owned(),
                    })
                    .await,
                Err(ApiError::InvalidRequest)
            ));
            assert!(matches!(
                service
                    .recover_session(SessionRecoveryRequest {
                        proof: crate::contracts::DeviceProof {
                            challenge_id: "malformed".to_owned(),
                            device_id: "not-a-canonical-uuid".to_owned(),
                            app_version: "1.0.0".to_owned(),
                            requested_scope: SESSION_RECOVERY_SCOPE.to_owned(),
                            issued_at: 1_000,
                            signature: "malformed".to_owned(),
                        },
                    })
                    .await,
                Err(ApiError::InvalidRequest)
            ));
        }

        let events = repository.audit_events().unwrap();
        assert_eq!(
            events
                .iter()
                .filter(|event| event.event_type == "session_recovery_challenge_denied")
                .count(),
            1
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| {
                    event.event_type == "session_recovery_denied"
                        && event.reason_code.as_deref() == Some("invalid_request")
                })
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn invalid_proofs_cannot_exhaust_a_device_recovery_rate_limit() {
        let (service, _, _) = fixture();
        let (_, device_key, device_id, _) = register(&service).await;
        let attacker_key = test_signing_key();
        for _ in 0..25 {
            let challenge = service
                .issue_session_recovery_challenge(SessionRecoveryChallengeRequest {
                    device_id: device_id.clone(),
                })
                .await
                .expect("challenge before invalid proof");
            let proof = sign_device_challenge(&attacker_key, &challenge, &device_id, "1.0.0");
            assert!(matches!(
                service
                    .recover_session(SessionRecoveryRequest { proof })
                    .await,
                Err(ApiError::InvalidChallenge)
            ));
        }

        let challenge = service
            .issue_session_recovery_challenge(SessionRecoveryChallengeRequest {
                device_id: device_id.clone(),
            })
            .await
            .expect("legitimate recovery challenge");
        let proof = sign_device_challenge(&device_key, &challenge, &device_id, "1.0.0");
        service
            .recover_session(SessionRecoveryRequest { proof })
            .await
            .expect("invalid anonymous proofs did not consume the device bucket");
    }

    #[tokio::test]
    async fn concurrent_recovery_proof_consumption_succeeds_once() {
        let (service, _, _) = fixture();
        let (_, device_key, device_id, _) = register(&service).await;
        let challenge = service
            .issue_session_recovery_challenge(SessionRecoveryChallengeRequest {
                device_id: device_id.clone(),
            })
            .await
            .expect("recovery challenge");
        let proof = sign_device_challenge(&device_key, &challenge, &device_id, "1.0.0");
        let (first, second) = tokio::join!(
            service.recover_session(SessionRecoveryRequest {
                proof: proof.clone()
            }),
            service.recover_session(SessionRecoveryRequest { proof }),
        );
        assert_eq!(
            [&first, &second].into_iter().filter(|r| r.is_ok()).count(),
            1
        );
        assert_eq!(
            [&first, &second]
                .into_iter()
                .filter(|r| matches!(r, Err(ApiError::InvalidChallenge)))
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn enforces_device_limit() {
        let (service, _, _) = fixture();
        let _ = register(&service).await;
        let _ = register(&service).await;
        let _ = register(&service).await;
        assert!(matches!(
            register_result(&service).await,
            Err(ApiError::ActivationLimitReached)
        ));
    }

    #[tokio::test]
    async fn concurrent_device_registrations_cannot_oversubscribe_the_license() {
        let (service, _, _) = fixture();
        let (first, second, third, fourth) = tokio::join!(
            register_result(&service),
            register_result(&service),
            register_result(&service),
            register_result(&service),
        );
        let results = [first, second, third, fourth];
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 3);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(ApiError::ActivationLimitReached)))
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn expired_pending_activation_is_reported_as_terminal() {
        let (service, repository, _, _) = fixture_with_repository();
        let account = Account::active("pending-expired", 1_000);
        repository.upsert_account(account.clone()).await.unwrap();
        let license = License::default_pro(&account.id, 1_000);
        repository.upsert_license(license.clone()).await.unwrap();
        let device_id = uuid::Uuid::new_v4().to_string();
        let device_key = test_signing_key();
        let public_key_pem = device_key
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .expect("device public key");
        repository
            .upsert_device(Device {
                account_id: account.id,
                license_id: license.id,
                metadata: DeviceRegistrationMetadata {
                    device_id: device_id.clone(),
                    public_key_pem,
                    public_key_thumbprint: "unused-thumbprint".into(),
                    platform: "test".into(),
                    app_version: "1.0.0".into(),
                    display_name: None,
                },
                state: DeviceState::PendingActivation,
                pending_activation_code_hash: Some("activation-code".into()),
                pending_activation_expires_at: Some(1_000),
                created_at: 900,
                last_seen_at: Some(900),
            })
            .await
            .unwrap();

        let challenge = service
            .issue_session_recovery_challenge(SessionRecoveryChallengeRequest {
                device_id: device_id.clone(),
            })
            .await
            .expect("expired pending device receives an indistinguishable challenge");
        let proof = sign_device_challenge(&device_key, &challenge, &device_id, "1.0.0");
        assert!(matches!(
            service
                .recover_session(SessionRecoveryRequest { proof })
                .await,
            Err(ApiError::ActivationPendingExpired)
        ));
    }

    #[tokio::test]
    async fn authorization_result_retry_window_cannot_be_extended_by_retries() {
        let repository = MemoryRepository::default();
        let entitlement_key = test_signing_key();
        let signer = EntitlementSigner::from_signing_key("entitlement-test", &entitlement_key);
        let authorization = AuthorizationPolicy::new(
            "camellia-nexus-desktop",
            vec!["camellia-nexus://auth/callback".to_owned()],
            vec![(TEST_ACTIVATION_CODE.to_owned(), "acct_test".to_owned())],
        )
        .expect("authorization policy");
        let clock = Arc::new(TestClock::new(1_000));
        let service = LicenseService::with_clock_and_authorization(
            Arc::new(repository.clone()),
            signer,
            "https://license.test",
            "camellia-nexus-desktop",
            clock.clone(),
            authorization,
        );
        let authorization_code = issue_authorization_code(&service, TEST_PKCE_VERIFIER).await;
        let authorization_code_hash = sha256_hex(&authorization_code);
        let device_key = test_signing_key();
        let public_key_pem = device_key
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .expect("device public");
        let public_der = device_key.verifying_key().to_public_key_der().expect("der");
        let thumbprint = format!(
            "sha256:{}",
            sha2::Sha256::digest(public_der.as_ref())
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        );
        let request = DeviceRegistrationRequest {
            device: DeviceRegistrationMetadata {
                device_id: uuid::Uuid::new_v4().to_string(),
                public_key_pem,
                public_key_thumbprint: thumbprint,
                platform: "test".into(),
                app_version: "1.0.0".into(),
                display_name: Some("retry-window-test".into()),
            },
            authorization_code: SecretValue(authorization_code),
            pkce_verifier: SecretValue(TEST_PKCE_VERIFIER.into()),
            redirect_uri: "camellia-nexus://auth/callback".into(),
        };

        service
            .register_device(request.clone())
            .await
            .expect("initial registration");
        assert_eq!(
            repository
                .authorization_code_by_hash(&authorization_code_hash)
                .await
                .unwrap()
                .unwrap()
                .consumed_at,
            Some(1_000)
        );

        clock.set(1_000 + AUTHORIZATION_RESULT_RETRY_SECONDS);
        service
            .register_device(request.clone())
            .await
            .expect("retry at the original boundary");
        assert_eq!(
            repository
                .authorization_code_by_hash(&authorization_code_hash)
                .await
                .unwrap()
                .unwrap()
                .consumed_at,
            Some(1_000),
            "a successful retry must not slide the retry window"
        );

        clock.set(1_001 + AUTHORIZATION_RESULT_RETRY_SECONDS);
        assert!(matches!(
            service.register_device(request).await,
            Err(ApiError::AuthorizationRequired)
        ));
    }

    #[tokio::test]
    async fn database_activation_code_is_consumed_only_after_confirmation() {
        let repository = MemoryRepository::default();
        let entitlement_key = test_signing_key();
        let signer = EntitlementSigner::from_signing_key("entitlement-test", &entitlement_key);
        let public_pem = entitlement_key
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .expect("public");
        let authorization = AuthorizationPolicy::new(
            "camellia-nexus-desktop",
            vec!["camellia-nexus://auth/callback".to_owned()],
            Vec::<(String, String)>::new(),
        )
        .expect("authorization policy");
        let service = LicenseService::with_clock_and_authorization(
            Arc::new(repository.clone()),
            signer,
            "https://license.test",
            "camellia-nexus-desktop",
            Arc::new(TestClock::new(1_000)),
            authorization,
        );
        let account_id = "acct_database_code";
        repository
            .upsert_account(Account::active(account_id, 1_000))
            .await
            .unwrap();
        let license = License::default_pro(account_id, 1_000);
        repository.upsert_license(license.clone()).await.unwrap();
        let mut second_license = License::default_pro(account_id, 1_001);
        second_license.id = "lic_second_for_same_account".into();
        second_license.license_epoch = 99;
        repository.upsert_license(second_license).await.unwrap();
        let activation_code = "database-activation-code";
        let activation_code_hash = sha256_hex(activation_code);
        repository
            .upsert_activation_code(ActivationCodeRecord {
                code_hash: activation_code_hash.clone(),
                code_prefix: activation_code.chars().take(10).collect(),
                account_id: account_id.to_owned(),
                license_id: Some(license.id.clone()),
                status: ActivationCodeStatus::Active,
                max_redemptions: 1,
                redeemed_count: 0,
                expires_at: None,
                consumed_at: None,
                consumed_device_id: None,
                last_redeemed_at: None,
                last_redeemed_device_id: None,
                created_at: 1_000,
                updated_at: 1_000,
                note: None,
                order_id: None,
                channel: None,
                issued_by: None,
                revoked_reason: None,
                last_admin_reason: None,
            })
            .await
            .unwrap();

        let code =
            issue_authorization_code_for(&service, activation_code, TEST_PKCE_VERIFIER).await;
        let device_key = test_signing_key();
        let public_key_pem = device_key
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .expect("device public");
        let public_der = device_key.verifying_key().to_public_key_der().expect("der");
        let thumbprint = format!(
            "sha256:{}",
            sha2::Sha256::digest(public_der.as_ref())
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        );
        let device_id = uuid::Uuid::new_v4().to_string();
        let registered = service
            .register_device(DeviceRegistrationRequest {
                device: DeviceRegistrationMetadata {
                    device_id: device_id.clone(),
                    public_key_pem,
                    public_key_thumbprint: thumbprint,
                    platform: "test".into(),
                    app_version: "1.0.0".into(),
                    display_name: None,
                },
                authorization_code: SecretValue(code),
                pkce_verifier: SecretValue(TEST_PKCE_VERIFIER.into()),
                redirect_uri: "camellia-nexus://auth/callback".into(),
            })
            .await
            .unwrap();
        assert_eq!(registered.device_state, DeviceState::PendingActivation);
        assert!(matches!(
            service
                .confirm_activation(&registered.refresh_session)
                .await,
            Err(ApiError::AuthorizationRequired)
        ));
        assert_eq!(
            repository
                .activation_code_by_hash(&activation_code_hash)
                .await
                .unwrap()
                .unwrap()
                .status,
            ActivationCodeStatus::Active
        );

        assert!(matches!(
            service
                .issue_challenge(
                    &registered.refresh_session,
                    ChallengeRequest {
                        device_id: device_id.clone(),
                        requested_scope: "entitlement:refresh".into(),
                    },
                )
                .await,
            Err(ApiError::DeviceStateDenied(DeviceState::PendingActivation))
        ));

        let challenge = service
            .issue_challenge(
                &registered.refresh_session,
                ChallengeRequest {
                    device_id: device_id.clone(),
                    requested_scope: "activation:verify".into(),
                },
            )
            .await
            .expect("activation challenge");
        let proof = sign_device_challenge(&device_key, &challenge, &device_id, "1.0.0");
        let verified = service
            .verify_activation(
                &registered.refresh_session,
                ActivationVerificationRequest { proof },
            )
            .await
            .expect("activation verify");
        assert_eq!(verified.device_state, DeviceState::PendingActivation);
        let activation_claims: ActivationProofClaims =
            decode_claims(verified.activation.expose(), &public_pem);
        assert_eq!(activation_claims.license_id, license.id);
        assert_eq!(activation_claims.license_epoch, license.license_epoch);
        assert_eq!(
            repository
                .activation_code_by_hash(&activation_code_hash)
                .await
                .unwrap()
                .unwrap()
                .status,
            ActivationCodeStatus::Active
        );

        let confirmed = service
            .confirm_activation(&verified.rotated_refresh_session)
            .await
            .expect("confirm");
        assert_eq!(confirmed.device_state, DeviceState::Active);
        let consumed = repository
            .activation_code_by_hash(&activation_code_hash)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(consumed.status, ActivationCodeStatus::Consumed);
        assert_eq!(consumed.redeemed_count, 1);
        assert_eq!(
            consumed.consumed_device_id.as_deref(),
            Some(device_id.as_str())
        );
        let confirmed_again = service
            .confirm_activation(&verified.rotated_refresh_session)
            .await
            .expect("confirm again");
        assert_eq!(confirmed_again.device_state, DeviceState::Active);
        let events = repository.audit_events().expect("audit events");
        assert!(events.iter().any(|event| {
            event.event_type == "device_activation_confirmed"
                && event.outcome == "succeeded"
                && event.device_id.as_deref() == Some(device_id.as_str())
                && event.reason_code.as_deref() == Some("already_active")
                && event.metadata.get("idempotent").map(String::as_str) == Some("true")
        }));

        let challenge = service
            .issue_challenge(
                &verified.rotated_refresh_session,
                ChallengeRequest {
                    device_id: device_id.clone(),
                    requested_scope: "entitlement:refresh".into(),
                },
            )
            .await
            .expect("refresh challenge");
        let proof = sign_device_challenge(&device_key, &challenge, &device_id, "1.0.0");
        let refreshed = service
            .refresh_entitlement(
                &verified.rotated_refresh_session,
                EntitlementRefreshRequest { proof },
            )
            .await
            .expect("refresh");
        let entitlement_claims: EntitlementClaims =
            decode_claims(refreshed.entitlement.expose(), &public_pem);
        assert_eq!(entitlement_claims.license_id, license.id);
        assert_eq!(entitlement_claims.license_epoch, license.license_epoch);
        assert_eq!(entitlement_claims.schema_version, 3);
        assert!(entitlement_claims.workspace_permissions.is_empty());
    }

    #[test]
    fn team_entitlement_capabilities_are_trimmed_by_signed_role_permissions() {
        let operator = vec![
            "shared.read".to_owned(),
            "shared.write".to_owned(),
            "sync.read".to_owned(),
            "sync.write".to_owned(),
            "remote.read".to_owned(),
            "alerts.read".to_owned(),
            "alerts.ack".to_owned(),
            "team.read".to_owned(),
        ];
        assert!(team_capability_allowed(
            Capability::SharedConfigurations,
            &operator
        ));
        assert!(team_capability_allowed(Capability::CloudSync, &operator));
        assert!(team_capability_allowed(
            Capability::RemoteDashboard,
            &operator
        ));
        assert!(team_capability_allowed(Capability::Alerts, &operator));
        assert!(!team_capability_allowed(
            Capability::TeamAdministration,
            &operator
        ));
        assert!(!team_capability_allowed(Capability::AuditLog, &operator));

        let auditor = vec![
            "team.read".to_owned(),
            "alerts.history.read".to_owned(),
            "audit.read".to_owned(),
            "audit.export".to_owned(),
        ];
        assert!(team_capability_allowed(Capability::Alerts, &auditor));
        assert!(team_capability_allowed(Capability::AuditLog, &auditor));
        assert!(!team_capability_allowed(
            Capability::SharedConfigurations,
            &auditor
        ));
        assert!(!team_capability_allowed(
            Capability::TeamAdministration,
            &auditor
        ));

        assert!(team_capability_allowed(
            Capability::ManagedConfigSources,
            &[]
        ));
        assert!(!team_capability_allowed(Capability::Webhooks, &[]));
    }
}
