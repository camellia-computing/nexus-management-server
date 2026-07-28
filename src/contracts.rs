use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Plan {
    Free,
    Pro,
    Team,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LicenseStanding {
    Active,
    PastDue,
    Canceled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    ManagedConfigSources,
    AdvancedDiagnostics,
    CloudSync,
    RemoteDashboard,
    Alerts,
    SharedConfigurations,
    TeamAdministration,
    AuditLog,
    Webhooks,
    ManagedProgramPackages,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NumericLimit {
    MaxPrograms,
    MaxConfigSourcesPerProgram,
    MaxTeamMembers,
    MaxRemoteMonitors,
    MaxSharedPrograms,
    MaxWebhookEndpoints,
    MaxWorkspaceStorageBytes,
    MaxAlertRules,
    MaxAuditExportEvents,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceState {
    PendingActivation,
    Active,
    Removed,
    Revoked,
    Suspicious,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceRegistrationMetadata {
    pub device_id: String,
    pub public_key_pem: String,
    pub public_key_thumbprint: String,
    pub platform: String,
    pub app_version: String,
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceChallenge {
    pub challenge_id: String,
    pub nonce: String,
    pub requested_scope: String,
    pub issued_at: i64,
    pub expires_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceProof {
    pub challenge_id: String,
    pub device_id: String,
    pub app_version: String,
    pub requested_scope: String,
    pub issued_at: i64,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceRegistrationRequest {
    pub device: DeviceRegistrationMetadata,
    pub authorization_code: SecretValue,
    pub pkce_verifier: SecretValue,
    pub redirect_uri: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceRegistrationResponse {
    pub device_state: DeviceState,
    pub refresh_session: RefreshSession,
    pub server_unix: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceActivationConfirmationResponse {
    pub device_state: DeviceState,
    pub server_unix: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChallengeRequest {
    pub device_id: String,
    pub requested_scope: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionRecoveryChallengeRequest {
    pub device_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionRecoveryRequest {
    pub proof: DeviceProof,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionRecoveryResponse {
    pub refresh_session: RefreshSession,
    pub server_unix: i64,
    pub device_state: DeviceState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceRemovalRequest {
    pub proof: DeviceProof,
    pub operation_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceRemovalStatusResponse {
    pub committed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EntitlementRefreshRequest {
    pub proof: DeviceProof,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EntitlementStatusRequest {
    pub proof: DeviceProof,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivationVerificationRequest {
    pub proof: DeviceProof,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivationVerificationResponse {
    pub activation: SecretValue,
    pub rotated_refresh_session: RefreshSession,
    pub server_unix: i64,
    pub device_state: DeviceState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EntitlementRefreshResponse {
    pub entitlement: SecretValue,
    pub rotated_refresh_session: RefreshSession,
    pub server_unix: i64,
    pub device_state: DeviceState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EntitlementStatusResponse {
    pub device_state: DeviceState,
    pub license_epoch: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisteredDevice {
    pub device_id: String,
    pub display_name: Option<String>,
    pub platform: String,
    pub state: DeviceState,
    pub last_seen_at: Option<i64>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegisteredDevicePageRequest {
    pub cursor: Option<String>,
    pub page_size: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisteredDevicePage {
    pub devices: Vec<RegisteredDevice>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientVersionPolicy {
    pub minimum_version: String,
    pub recommended_version: String,
    pub enforce_after: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EntitlementClaims {
    pub schema_version: u32,
    pub iss: String,
    pub aud: String,
    pub sub: String,
    pub license_id: String,
    pub device_id: String,
    pub device_key_thumbprint: String,
    pub plan: Plan,
    pub plan_revision: u32,
    pub policy_hash: String,
    pub license_status: LicenseStanding,
    pub capabilities: Vec<Capability>,
    pub workspace_permissions: Vec<String>,
    pub limits: BTreeMap<NumericLimit, u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license_expires_at: Option<i64>,
    pub license_epoch: u64,
    pub device_limit: u32,
    pub member_limit: u32,
    pub offline_access_ends_at: i64,
    pub client_version_policy: ClientVersionPolicy,
    #[serde(rename = "iat")]
    pub issued_at: i64,
    pub refresh_after: i64,
    #[serde(rename = "exp")]
    pub expires_at: i64,
    pub token_id: String,
    pub key_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivationProofClaims {
    pub iss: String,
    pub aud: String,
    pub sub: String,
    pub license_id: String,
    pub device_id: String,
    pub device_key_thumbprint: String,
    pub license_epoch: u64,
    pub purpose: String,
    #[serde(rename = "iat")]
    pub issued_at: i64,
    #[serde(rename = "exp")]
    pub expires_at: i64,
    pub token_id: String,
    pub key_id: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RefreshSession(pub String);

impl std::fmt::Debug for RefreshSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RefreshSession([REDACTED])")
    }
}

impl Drop for RefreshSession {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretValue(pub String);

impl SecretValue {
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for SecretValue {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SecretValue([REDACTED])")
    }
}

impl Drop for SecretValue {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorResponse {
    pub code: &'static str,
    pub message: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_version_policy: Option<ClientVersionPolicy>,
}
