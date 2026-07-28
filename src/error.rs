use axum::{
    Json,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use thiserror::Error;

use crate::contracts::{ClientVersionPolicy, DeviceState, ErrorResponse};

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("authorization required")]
    AuthorizationRequired,
    #[error("activation code is invalid")]
    ActivationCodeInvalid,
    #[error("activation code has expired")]
    ActivationCodeExpired,
    #[error("activation code has already been used")]
    ActivationCodeConsumed,
    #[error("activation code has been revoked")]
    ActivationCodeRevoked,
    #[error("activation limit reached")]
    ActivationLimitReached,
    #[error("pending activation has expired")]
    ActivationPendingExpired,
    #[error("device denied")]
    DeviceDenied,
    #[error("device denied: {0:?}")]
    DeviceStateDenied(DeviceState),
    #[error("invalid challenge")]
    InvalidChallenge,
    #[error("challenge replay")]
    ChallengeReplay,
    #[error("refresh token reuse")]
    RefreshSessionReused,
    #[error("invalid request")]
    InvalidRequest,
    #[error("Team invitation token is invalid")]
    TeamInvitationInvalid,
    #[error("Team device enrollment token is invalid")]
    TeamDeviceEnrollmentInvalid,
    #[error("idempotency key conflicts with an earlier request")]
    IdempotencyConflict,
    #[error("workspace version conflict")]
    WorkspaceVersionConflict,
    #[error("workspace plaintext quota exceeded")]
    WorkspaceQuotaExceeded,
    #[error("workspace document limit reached")]
    WorkspaceDocumentLimitReached,
    #[error("workspace alert-rule limit reached")]
    WorkspaceAlertRuleLimitReached,
    #[error("workspace resource not found")]
    WorkspaceNotFound,
    #[error("workspace deleted-resource retention period is still active")]
    WorkspaceRetentionActive,
    #[error("workspace ciphertext integrity check failed")]
    WorkspaceIntegrity,
    #[error("workspace encryption key unavailable")]
    WorkspaceKeyUnavailable,
    #[error("webhook endpoint URL is invalid")]
    WebhookInvalidUrl,
    #[error("webhook endpoint limit reached")]
    WebhookEndpointLimitReached,
    #[error("webhook endpoint not found")]
    WebhookNotFound,
    #[error("webhook encryption key unavailable")]
    WebhookKeyUnavailable,
    #[error("workspace permission denied")]
    PermissionDenied,
    #[error("license capability is not available")]
    CapabilityDenied,
    #[error("client upgrade required")]
    ClientUpgradeRequired(ClientVersionPolicy),
    #[error("too many requests")]
    TooManyRequests,
    #[error("license unavailable")]
    LicenseUnavailable,
    #[error("account suspended")]
    AccountSuspended,
    #[error("account denylisted")]
    AccountDenylisted,
    #[error("license payment past due")]
    LicensePastDue,
    #[error("license canceled")]
    LicenseCanceled,
    #[error("license expired")]
    LicenseExpired,
    #[error("signing key unavailable")]
    SigningKeyUnavailable,
    #[error("time authority unavailable")]
    TimeAuthorityUnavailable,
    #[error("database operation failed")]
    Database,
    #[error("database schema is not ready")]
    DatabaseSchemaNotReady,
    #[error("internal error")]
    Internal,
}

impl ApiError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::AuthorizationRequired => "authorization_required",
            Self::ActivationCodeInvalid => "activation_code_invalid",
            Self::ActivationCodeExpired => "activation_code_expired",
            Self::ActivationCodeConsumed => "activation_code_consumed",
            Self::ActivationCodeRevoked => "activation_code_revoked",
            Self::ActivationLimitReached => "activation_limit",
            Self::ActivationPendingExpired => "activation_pending_expired",
            Self::DeviceDenied => "device_denied",
            Self::DeviceStateDenied(DeviceState::Removed) => "device_removed",
            Self::DeviceStateDenied(DeviceState::Revoked) => "device_revoked",
            Self::DeviceStateDenied(DeviceState::Suspicious) => "device_suspicious",
            Self::DeviceStateDenied(DeviceState::PendingActivation) => "device_activation_pending",
            Self::DeviceStateDenied(DeviceState::Active) => "device_state_conflict",
            Self::InvalidChallenge => "invalid_challenge",
            Self::ChallengeReplay => "challenge_replay",
            Self::RefreshSessionReused => "refresh_token_reuse",
            Self::InvalidRequest => "invalid_request",
            Self::TeamInvitationInvalid => "team_invitation_invalid",
            Self::TeamDeviceEnrollmentInvalid => "team_device_enrollment_invalid",
            Self::IdempotencyConflict => "idempotency_conflict",
            Self::WorkspaceVersionConflict => "workspace_version_conflict",
            Self::WorkspaceQuotaExceeded => "workspace_quota_exceeded",
            Self::WorkspaceDocumentLimitReached => "workspace_document_limit_reached",
            Self::WorkspaceAlertRuleLimitReached => "workspace_alert_rule_limit_reached",
            Self::WorkspaceNotFound => "workspace_not_found",
            Self::WorkspaceRetentionActive => "workspace_retention_active",
            Self::WorkspaceIntegrity => "workspace_integrity_failed",
            Self::WorkspaceKeyUnavailable => "workspace_key_unavailable",
            Self::WebhookInvalidUrl => "webhook_invalid_url",
            Self::WebhookEndpointLimitReached => "webhook_endpoint_limit",
            Self::WebhookNotFound => "webhook_not_found",
            Self::WebhookKeyUnavailable => "webhook_keyring_unavailable",
            Self::PermissionDenied => "permission_denied",
            Self::CapabilityDenied => "capability_denied",
            Self::ClientUpgradeRequired(_) => "client_upgrade_required",
            Self::TooManyRequests => "too_many_requests",
            Self::LicenseUnavailable => "license_unavailable",
            Self::AccountSuspended => "account_suspended",
            Self::AccountDenylisted => "account_denylisted",
            Self::LicensePastDue => "license_past_due",
            Self::LicenseCanceled => "license_canceled",
            Self::LicenseExpired => "license_expired",
            Self::SigningKeyUnavailable => "signing_key_unavailable",
            Self::TimeAuthorityUnavailable => "time_authority_unavailable",
            Self::Database => "database",
            Self::DatabaseSchemaNotReady => "database_schema_not_ready",
            Self::Internal => "internal",
        }
    }

    fn status(&self) -> StatusCode {
        match self {
            Self::AuthorizationRequired
            | Self::ActivationCodeInvalid
            | Self::ActivationCodeExpired
            | Self::ActivationCodeConsumed
            | Self::ActivationCodeRevoked => StatusCode::UNAUTHORIZED,
            Self::ActivationLimitReached
            | Self::ActivationPendingExpired
            | Self::IdempotencyConflict => StatusCode::CONFLICT,
            Self::DeviceDenied
            | Self::DeviceStateDenied(_)
            | Self::AccountSuspended
            | Self::AccountDenylisted
            | Self::PermissionDenied
            | Self::CapabilityDenied => StatusCode::FORBIDDEN,
            Self::WorkspaceVersionConflict => StatusCode::CONFLICT,
            Self::WorkspaceQuotaExceeded
            | Self::WorkspaceDocumentLimitReached
            | Self::WorkspaceAlertRuleLimitReached
            | Self::WorkspaceRetentionActive
            | Self::WebhookEndpointLimitReached => StatusCode::CONFLICT,
            Self::WorkspaceNotFound | Self::WebhookNotFound => StatusCode::NOT_FOUND,
            Self::InvalidChallenge
            | Self::ChallengeReplay
            | Self::InvalidRequest
            | Self::TeamInvitationInvalid
            | Self::TeamDeviceEnrollmentInvalid
            | Self::WebhookInvalidUrl => StatusCode::BAD_REQUEST,
            Self::ClientUpgradeRequired(_) => StatusCode::UPGRADE_REQUIRED,
            Self::TooManyRequests => StatusCode::TOO_MANY_REQUESTS,
            Self::RefreshSessionReused => StatusCode::UNAUTHORIZED,
            Self::LicenseUnavailable
            | Self::LicensePastDue
            | Self::LicenseCanceled
            | Self::LicenseExpired => StatusCode::PAYMENT_REQUIRED,
            Self::TimeAuthorityUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            Self::WorkspaceKeyUnavailable | Self::WebhookKeyUnavailable => {
                StatusCode::SERVICE_UNAVAILABLE
            }
            Self::SigningKeyUnavailable
            | Self::WorkspaceIntegrity
            | Self::Database
            | Self::DatabaseSchemaNotReady
            | Self::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl From<crate::webhooks::WebhookError> for ApiError {
    fn from(error: crate::webhooks::WebhookError) -> Self {
        use crate::webhooks::WebhookError;

        match error {
            WebhookError::InvalidRequest => Self::InvalidRequest,
            WebhookError::InvalidUrl => Self::WebhookInvalidUrl,
            WebhookError::PermissionDenied => Self::PermissionDenied,
            WebhookError::CapabilityDenied => Self::CapabilityDenied,
            WebhookError::AccountSuspended => Self::AccountSuspended,
            WebhookError::AccountDenylisted => Self::AccountDenylisted,
            WebhookError::LicenseUnavailable => Self::LicenseUnavailable,
            WebhookError::LicensePastDue => Self::LicensePastDue,
            WebhookError::LicenseCanceled => Self::LicenseCanceled,
            WebhookError::LicenseExpired => Self::LicenseExpired,
            WebhookError::NotFound => Self::WebhookNotFound,
            WebhookError::EndpointLimitReached => Self::WebhookEndpointLimitReached,
            WebhookError::VersionConflict => Self::WorkspaceVersionConflict,
            WebhookError::IdempotencyConflict => Self::IdempotencyConflict,
            WebhookError::KeyringUnavailable => Self::WebhookKeyUnavailable,
            WebhookError::TimeAuthorityUnavailable => Self::TimeAuthorityUnavailable,
            WebhookError::Database => Self::Database,
            WebhookError::DatabaseSchemaNotReady => Self::DatabaseSchemaNotReady,
            WebhookError::Serialization
            | WebhookError::DnsRejected
            | WebhookError::LeaseLost
            | WebhookError::InvalidDispatcherConfiguration
            | WebhookError::UnexpectedDispatcherExit
            | WebhookError::WorkerTaskPanicked => Self::Internal,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status();
        if status.is_server_error() {
            tracing::error!(
                error_code = self.code(),
                status = status.as_u16(),
                "api error response"
            );
        } else {
            tracing::debug!(
                error_code = self.code(),
                status = status.as_u16(),
                "api error response"
            );
        }
        let body = ErrorResponse {
            code: self.code(),
            message: match &self {
                Self::AuthorizationRequired => "Authentication is required.",
                Self::ActivationCodeInvalid => "The activation code is invalid.",
                Self::ActivationCodeExpired => "The activation code has expired.",
                Self::ActivationCodeConsumed => "The activation code has already been used.",
                Self::ActivationCodeRevoked => "The activation code has been revoked.",
                Self::ActivationLimitReached => "The active device limit has been reached.",
                Self::ActivationPendingExpired => {
                    "The pending device activation has expired. Start authorization again."
                }
                Self::CapabilityDenied => {
                    "The current license plan does not include this capability."
                }
                Self::DeviceStateDenied(DeviceState::PendingActivation) => {
                    "This device still needs to complete activation."
                }
                Self::DeviceDenied | Self::DeviceStateDenied(_) => {
                    "This device is not allowed to refresh entitlements."
                }
                Self::InvalidChallenge => "The device challenge is invalid or expired.",
                Self::ChallengeReplay => "The device challenge has already been used.",
                Self::RefreshSessionReused => "The refresh session was reused after rotation.",
                Self::InvalidRequest => "The request is invalid.",
                Self::TeamInvitationInvalid => {
                    "The Team invitation token is invalid, expired, or no longer available."
                }
                Self::TeamDeviceEnrollmentInvalid => {
                    "The Team device enrollment token is invalid, expired, or no longer available."
                }
                Self::IdempotencyConflict => {
                    "The operation ID was already used for a different request."
                }
                Self::WorkspaceVersionConflict => {
                    "The workspace changed. Reload it before retrying this action."
                }
                Self::WorkspaceQuotaExceeded => {
                    "The workspace's 2 GiB configuration history quota has been reached."
                }
                Self::WorkspaceDocumentLimitReached => {
                    "The workspace's 200 active shared-configuration limit has been reached."
                }
                Self::WorkspaceAlertRuleLimitReached => {
                    "The workspace's 50 active alert-rule limit has been reached."
                }
                Self::WorkspaceNotFound => "The requested workspace resource does not exist.",
                Self::WorkspaceRetentionActive => {
                    "The deleted configuration is still within its 30-day recovery period."
                }
                Self::WorkspaceIntegrity => {
                    "The stored workspace configuration failed its integrity check."
                }
                Self::WorkspaceKeyUnavailable => "The workspace encryption keyring is unavailable.",
                Self::WebhookInvalidUrl => {
                    "The webhook endpoint must be a public HTTPS URL without embedded credentials."
                }
                Self::WebhookEndpointLimitReached => {
                    "The workspace's webhook endpoint limit has been reached."
                }
                Self::WebhookNotFound => "The requested webhook endpoint does not exist.",
                Self::WebhookKeyUnavailable => "The webhook encryption keyring is unavailable.",
                Self::PermissionDenied => "This workspace role does not allow that action.",
                Self::ClientUpgradeRequired(_) => {
                    "This Camellia Nexus client version is no longer supported. Upgrade to continue."
                }
                Self::TooManyRequests => "Too many requests. Try again later.",
                Self::LicenseUnavailable => "No active license is available.",
                Self::AccountSuspended => "This license account is suspended.",
                Self::AccountDenylisted => "This license account is disabled.",
                Self::LicensePastDue => "The license payment is past due.",
                Self::LicenseCanceled => "The license has been canceled.",
                Self::LicenseExpired => "The license has expired.",
                Self::SigningKeyUnavailable => "The entitlement signing key is unavailable.",
                Self::TimeAuthorityUnavailable => {
                    "The license time authority is unavailable. Try again later."
                }
                Self::Database => "The license database is unavailable.",
                Self::DatabaseSchemaNotReady => {
                    "The license database schema is not ready. Apply the required migrations."
                }
                Self::Internal => "The license service encountered an internal error.",
            },
            client_version_policy: match &self {
                Self::ClientUpgradeRequired(policy) => Some(policy.clone()),
                _ => None,
            },
        };
        let mut response = (status, Json(body)).into_response();
        if status == StatusCode::TOO_MANY_REQUESTS {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("60"));
        }
        response
    }
}

pub type Result<T> = std::result::Result<T, ApiError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn team_token_failures_are_recoverable_business_errors() {
        for (error, code) in [
            (ApiError::TeamInvitationInvalid, "team_invitation_invalid"),
            (
                ApiError::TeamDeviceEnrollmentInvalid,
                "team_device_enrollment_invalid",
            ),
        ] {
            assert_eq!(error.code(), code);
            assert_eq!(error.status(), StatusCode::BAD_REQUEST);
        }
        assert_eq!(
            ApiError::AuthorizationRequired.status(),
            StatusCode::UNAUTHORIZED
        );
    }
}
