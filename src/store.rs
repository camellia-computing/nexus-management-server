use std::{
    collections::{BTreeMap, HashMap},
    path::Path,
    str::FromStr,
    sync::{Arc, RwLock},
    time::Duration,
};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sqlx::{
    PgPool, Postgres, Row, Transaction,
    postgres::{PgConnectOptions, PgPoolOptions, PgRow},
};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    admin_app::{AdminAppError, AdminAppResult, MutationContext},
    admin_auth::{AdminPermission, authorize_admin_mutation},
    admin_operation::{self, AdminOperationClaim},
    config::DatabaseConnectionConfig,
    contracts::{DeviceState, Plan},
    crypto::stable_log_reference,
    domain::{
        AUTHORIZATION_RESULT_RETRY_SECONDS, Account, AccountState, ActivationCodeRecord,
        ActivationCodeStatus, AuditEventRecord, AuthorizationCodeRedemption, Device, License,
        LicenseStatus, RefreshSessionProofState, RefreshSessionRecord, StoredAuthorizationCode,
        StoredChallenge,
    },
    error::{ApiError, Result},
};

#[async_trait]
pub trait LicenseRepository: Send + Sync + 'static {
    async fn readiness_check(&self) -> Result<()>;
    async fn observe_time_authority(
        &self,
        logical_unix: Option<i64>,
        max_forward_jump_seconds: i64,
    ) -> Result<TimeAuthorityObservation>;
    async fn close(&self);
    async fn cleanup_expired(&self, now: i64, batch_size: u32) -> Result<CleanupReport>;
    async fn consume_rate_limit(
        &self,
        scope: &str,
        key_hash: &str,
        now: i64,
        max_count: u32,
        window_seconds: i64,
    ) -> Result<bool>;
    async fn upsert_account(&self, account: Account) -> Result<()>;
    async fn account(&self, account_id: &str) -> Result<Option<Account>>;
    async fn upsert_license(&self, license: License) -> Result<()>;
    async fn license(&self, license_id: &str) -> Result<Option<License>>;
    async fn license_for_account(&self, account_id: &str) -> Result<Option<License>>;
    async fn upsert_device(&self, device: Device) -> Result<()>;
    async fn register_device_session_with_audit(
        &self,
        device: Device,
        session: RefreshSessionRecord,
        expected_device_state: Option<DeviceState>,
        authorization: AuthorizationCodeRedemption,
        now: i64,
        audit: AuditEventRecord,
    ) -> Result<()>;
    async fn device(&self, device_id: &str) -> Result<Option<Device>>;
    async fn devices_for_license_page(
        &self,
        license_id: &str,
        after_device_id: Option<&str>,
        limit: u32,
    ) -> Result<Vec<Device>>;
    async fn set_device_state(&self, device_id: &str, state: DeviceState, now: i64) -> Result<()>;
    async fn touch_device_last_seen(
        &self,
        device_id: &str,
        now: i64,
        minimum_interval_seconds: i64,
    ) -> Result<()>;
    async fn update_device_client_metadata(
        &self,
        device_id: &str,
        app_version: &str,
        now: i64,
    ) -> Result<()>;
    async fn insert_session(&self, session: RefreshSessionRecord) -> Result<()>;
    async fn replace_device_sessions_with_audit(
        &self,
        session: RefreshSessionRecord,
        now: i64,
        audit: AuditEventRecord,
    ) -> Result<()>;
    async fn session_by_hash(&self, token_hash: &str) -> Result<Option<RefreshSessionRecord>>;
    async fn rotate_session_with_audit(
        &self,
        old_hash: &str,
        new_session: RefreshSessionRecord,
        now: i64,
        audit: AuditEventRecord,
    ) -> Result<()>;
    async fn revoke_session_family(&self, family_id: &str) -> Result<()>;
    async fn revoke_sessions_for_device(&self, device_id: &str) -> Result<()>;
    async fn device_removal_replayed(
        &self,
        account_id: &str,
        requester_session_hash: &str,
        requester_device_id: &str,
        target_device_id: &str,
        operation_id: &str,
    ) -> Result<bool>;
    async fn remove_device_with_audit(
        &self,
        requester_session_hash: &str,
        requester_device_id: &str,
        target_device_id: &str,
        operation_id: &str,
        now: i64,
        audit: AuditEventRecord,
    ) -> Result<bool>;
    async fn logout_device_sessions_with_audit(
        &self,
        token_hash: &str,
        now: i64,
        audit: AuditEventRecord,
    ) -> Result<Option<RefreshSessionRecord>>;
    async fn insert_challenge(&self, challenge: StoredChallenge) -> Result<()>;
    async fn consume_challenge(
        &self,
        challenge_id: &str,
        device_id: &str,
        now: i64,
    ) -> Result<StoredChallenge>;
    async fn insert_authorization_code_with_audit(
        &self,
        code: StoredAuthorizationCode,
        audit: AuditEventRecord,
    ) -> Result<()>;
    async fn authorization_code_by_hash(
        &self,
        code_hash: &str,
    ) -> Result<Option<StoredAuthorizationCode>>;
    async fn upsert_activation_code(&self, code: ActivationCodeRecord) -> Result<()>;
    async fn activation_code_by_hash(
        &self,
        code_hash: &str,
    ) -> Result<Option<ActivationCodeRecord>>;
    async fn confirm_device_activation(
        &self,
        session_token_hash: &str,
        device_id: &str,
        activation_code_hash: Option<&str>,
        now: i64,
        audit: AuditEventRecord,
    ) -> Result<Device>;
    async fn insert_audit_event(&self, event: AuditEventRecord) -> Result<()>;
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CleanupReport {
    pub challenges: u64,
    pub authorization_codes: u64,
    pub refresh_sessions: u64,
    pub rate_limit_buckets: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeAuthorityStatus {
    Healthy,
    RollbackHeld,
    ForwardJump,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeAuthorityObservation {
    pub trusted_unix: i64,
    pub database_unix: i64,
    pub previous_high_water_unix: i64,
    pub status: TimeAuthorityStatus,
}

const ONLINE_ARTIFACT_RETENTION_SECONDS: i64 = 60 * 60;
const SESSION_REPLAY_RETENTION_SECONDS: i64 = 7 * 24 * 60 * 60;
const RATE_LIMIT_RETENTION_SECONDS: i64 = 2 * 60 * 60;
const PUBLIC_OPERATION_RETENTION_SECONDS: i64 = 37 * 24 * 60 * 60;
const CHALLENGE_INSERT_PRUNE_BATCH_SIZE: i64 = 128;

#[derive(Clone, Default)]
pub struct MemoryRepository {
    inner: Arc<RwLock<MemoryState>>,
}

#[derive(Default)]
struct MemoryState {
    accounts: HashMap<String, Account>,
    licenses: HashMap<String, License>,
    devices: HashMap<String, Device>,
    sessions: HashMap<String, RefreshSessionRecord>,
    challenges: HashMap<String, StoredChallenge>,
    authorization_codes: HashMap<String, StoredAuthorizationCode>,
    activation_codes: HashMap<String, ActivationCodeRecord>,
    audit_events: Vec<AuditEventRecord>,
    device_removal_operations: HashMap<(String, String), (String, String, String, i64)>,
    rate_limit_buckets: HashMap<(String, String), MemoryRateLimitBucket>,
    time_high_water_unix: i64,
}

#[derive(Debug, Clone)]
struct MemoryRateLimitBucket {
    window_started_at: i64,
    count: u32,
}

fn validate_session_replacement(
    state: &MemoryState,
    session: &RefreshSessionRecord,
    now: i64,
) -> Result<()> {
    let device = state
        .devices
        .get(&session.device_id)
        .ok_or(ApiError::DeviceDenied)?;
    validate_session_binding(state, device, session, now)
}

fn validate_session_binding(
    state: &MemoryState,
    device: &Device,
    session: &RefreshSessionRecord,
    now: i64,
) -> Result<()> {
    if !session.active
        || session.expires_at <= now
        || session.absolute_expires_at <= now
        || session.family_created_at > now
        || session.expires_at > session.absolute_expires_at
        || session.device_id != device.metadata.device_id
    {
        return Err(ApiError::InvalidRequest);
    }
    if device.account_id != session.account_id {
        return Err(ApiError::DeviceDenied);
    }
    ensure_session_device_state(device, session.proof_state)?;
    ensure_account_is_active(
        state
            .accounts
            .get(&device.account_id)
            .ok_or(ApiError::DeviceDenied)?,
    )?;
    let license = state
        .licenses
        .get(&device.license_id)
        .ok_or(ApiError::LicenseUnavailable)?;
    if license.account_id != device.account_id {
        return Err(ApiError::LicenseUnavailable);
    }
    ensure_license_is_usable(license, now)
}

fn ensure_session_device_state(device: &Device, proof: RefreshSessionProofState) -> Result<()> {
    match (proof, device.state) {
        (
            RefreshSessionProofState::DeviceProven,
            DeviceState::Active | DeviceState::PendingActivation,
        )
        | (
            RefreshSessionProofState::Unproven,
            DeviceState::Active | DeviceState::PendingActivation,
        ) => Ok(()),
        _ => Err(ApiError::DeviceStateDenied(device.state)),
    }
}

fn ensure_active_proven_session(
    session: &RefreshSessionRecord,
    requester: &Device,
    now: i64,
) -> Result<()> {
    if !session.active
        || session.expires_at <= now
        || session.absolute_expires_at <= now
        || session.device_id != requester.metadata.device_id
        || session.account_id != requester.account_id
        || session.proof_state != RefreshSessionProofState::DeviceProven
    {
        return Err(ApiError::AuthorizationRequired);
    }
    Ok(())
}

fn ensure_account_is_active(account: &Account) -> Result<()> {
    match account.state {
        AccountState::Active => Ok(()),
        AccountState::Suspended => Err(ApiError::AccountSuspended),
        AccountState::Denylisted => Err(ApiError::AccountDenylisted),
    }
}

fn ensure_license_is_usable(license: &License, now: i64) -> Result<()> {
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

fn validate_device_removal_audit(
    audit: &AuditEventRecord,
    requester: &Device,
    target_device_id: &str,
) -> Result<()> {
    if audit.event_type != "device_removed"
        || audit.outcome != "succeeded"
        || audit.account_id.as_deref() != Some(requester.account_id.as_str())
        || audit.license_id.as_deref() != Some(requester.license_id.as_str())
        || audit.device_id.as_deref() != Some(requester.metadata.device_id.as_str())
        || audit.metadata.get("target_device_id").map(String::as_str) != Some(target_device_id)
    {
        return Err(ApiError::InvalidRequest);
    }
    Ok(())
}

fn validate_device_registration_audit(audit: &AuditEventRecord, device: &Device) -> Result<()> {
    if !matches!(
        audit.event_type.as_str(),
        "device_registered" | "device_session_issued"
    ) || audit.outcome != "succeeded"
        || audit.account_id.as_deref() != Some(device.account_id.as_str())
        || audit.license_id.as_deref() != Some(device.license_id.as_str())
        || audit.device_id.as_deref() != Some(device.metadata.device_id.as_str())
    {
        return Err(ApiError::InvalidRequest);
    }
    Ok(())
}

fn device_occupies_activation_slot(device: &Device, now: i64) -> bool {
    device.state == DeviceState::Active
        || (device.state == DeviceState::PendingActivation
            && device
                .pending_activation_expires_at
                .is_some_and(|expires_at| expires_at > now))
}

fn validate_initial_registration_bundle(
    device: &Device,
    session: &RefreshSessionRecord,
    expected_device_state: Option<DeviceState>,
    now: i64,
    audit: &AuditEventRecord,
) -> Result<()> {
    validate_device_registration_audit(audit, device)?;
    if session.proof_state != RefreshSessionProofState::Unproven
        || session.rotated_to_hash.is_some()
        || session.rotated_at.is_some()
        || session.activation_verified_at.is_some()
        || session.activation_confirmation_consumed
    {
        return Err(ApiError::InvalidRequest);
    }
    match device.state {
        DeviceState::PendingActivation
            if device.pending_activation_code_hash.is_some()
                && device.pending_activation_code_hash == session.pending_activation_code_hash
                && device
                    .pending_activation_expires_at
                    .is_some_and(|expires_at| expires_at > now) => {}
        DeviceState::Active
            if device.pending_activation_code_hash.is_none()
                && device.pending_activation_expires_at.is_none()
                && session.pending_activation_code_hash.is_none() => {}
        _ => return Err(ApiError::InvalidRequest),
    }
    match expected_device_state {
        Some(DeviceState::Active)
            if device.state == DeviceState::Active
                && audit.event_type == "device_session_issued"
                && audit.reason_code.as_deref() == Some("already_active") => {}
        None | Some(DeviceState::PendingActivation | DeviceState::Removed)
            if audit.event_type == "device_registered" => {}
        _ => return Err(ApiError::InvalidRequest),
    }
    Ok(())
}

fn ensure_expected_device_state(
    actual: Option<&Device>,
    expected: Option<DeviceState>,
) -> Result<()> {
    if actual.map(|device| device.state) == expected {
        return Ok(());
    }
    Err(ApiError::DeviceStateDenied(
        actual.map_or(DeviceState::Removed, |device| device.state),
    ))
}

fn validate_authorization_redemption(
    code: &StoredAuthorizationCode,
    redemption: &AuthorizationCodeRedemption,
    device: &Device,
    pending_activation_code_hash: Option<&str>,
    now: i64,
) -> Result<()> {
    if code.code_hash != redemption.code_hash
        || code.code_challenge != redemption.code_challenge
        || code.redirect_uri != redemption.redirect_uri
        || code.account_id != device.account_id
        || (device.state == DeviceState::PendingActivation
            && code.activation_code_hash.as_deref() != pending_activation_code_hash)
        || code
            .license_id
            .as_ref()
            .is_some_and(|license_id| license_id != &device.license_id)
    {
        return Err(ApiError::AuthorizationRequired);
    }
    if !code.consumed {
        return if code.expires_at > now {
            Ok(())
        } else {
            Err(ApiError::AuthorizationRequired)
        };
    }
    if code.consumed_at.is_some_and(|consumed_at| {
        consumed_at.saturating_add(AUTHORIZATION_RESULT_RETRY_SECONDS) >= now
    }) && code.consumed_device_id.as_deref() == Some(device.metadata.device_id.as_str())
        && code.consumed_key_thumbprint.as_deref()
            == Some(device.metadata.public_key_thumbprint.as_str())
    {
        Ok(())
    } else {
        Err(ApiError::AuthorizationRequired)
    }
}

fn validate_logout_audit(audit: &AuditEventRecord, session: &RefreshSessionRecord) -> Result<()> {
    if audit.event_type != "session_logout"
        || audit.outcome != "succeeded"
        || audit.account_id.as_deref() != Some(session.account_id.as_str())
        || audit.license_id.is_some()
        || audit.device_id.as_deref() != Some(session.device_id.as_str())
    {
        return Err(ApiError::InvalidRequest);
    }
    Ok(())
}

fn validate_activation_confirmation_audit(audit: &AuditEventRecord, device: &Device) -> Result<()> {
    if audit.event_type != "device_activation_confirmed"
        || audit.outcome != "succeeded"
        || audit.account_id.as_deref() != Some(device.account_id.as_str())
        || audit.license_id.as_deref() != Some(device.license_id.as_str())
        || audit.device_id.as_deref() != Some(device.metadata.device_id.as_str())
    {
        return Err(ApiError::InvalidRequest);
    }
    Ok(())
}

fn validate_authorization_code_audit(
    audit: &AuditEventRecord,
    code: &StoredAuthorizationCode,
) -> Result<()> {
    if audit.event_type != "authorization_code_issued"
        || audit.outcome != "succeeded"
        || audit.account_id.as_deref() != Some(code.account_id.as_str())
        || audit.license_id.as_deref() != code.license_id.as_deref()
        || audit.device_id.is_some()
    {
        return Err(ApiError::InvalidRequest);
    }
    Ok(())
}

fn validate_session_success_audit(
    audit: &AuditEventRecord,
    event_type: &str,
    session: &RefreshSessionRecord,
    device: &Device,
    now: i64,
) -> Result<()> {
    if audit.event_type != event_type
        || audit.outcome != "succeeded"
        || audit.occurred_at != now
        || audit.account_id.as_deref() != Some(session.account_id.as_str())
        || audit.license_id.as_deref() != Some(device.license_id.as_str())
        || audit.device_id.as_deref() != Some(session.device_id.as_str())
        || session.account_id != device.account_id
        || session.device_id != device.metadata.device_id
    {
        return Err(ApiError::InvalidRequest);
    }
    match event_type {
        "activation_proof_issued" | "entitlement_refreshed"
            if audit
                .metadata
                .get("token_id")
                .is_some_and(|token_id| !token_id.is_empty()) => {}
        "session_recovered" if audit.reason_code.as_deref() == Some("device_proof") => {}
        _ => return Err(ApiError::InvalidRequest),
    }
    Ok(())
}

fn contains_audit_id(events: &[AuditEventRecord], audit: &AuditEventRecord) -> bool {
    events.iter().any(|existing| existing.id == audit.id)
}

#[async_trait]
impl LicenseRepository for MemoryRepository {
    async fn readiness_check(&self) -> Result<()> {
        drop(self.read()?);
        Ok(())
    }

    async fn observe_time_authority(
        &self,
        logical_unix: Option<i64>,
        max_forward_jump_seconds: i64,
    ) -> Result<TimeAuthorityObservation> {
        if max_forward_jump_seconds <= 0 {
            return Err(ApiError::InvalidRequest);
        }
        let observed = logical_unix
            .unwrap_or_else(crate::time_format::unix_now)
            .max(0);
        let mut state = self.write()?;
        let previous = state.time_high_water_unix;
        state.time_high_water_unix = previous.max(observed);
        Ok(TimeAuthorityObservation {
            trusted_unix: state.time_high_water_unix,
            database_unix: observed,
            previous_high_water_unix: previous,
            status: TimeAuthorityStatus::Healthy,
        })
    }

    async fn close(&self) {}

    async fn cleanup_expired(&self, now: i64, batch_size: u32) -> Result<CleanupReport> {
        let mut guard = self.write()?;
        let limit = batch_size.max(1) as usize;
        let challenge_ids = guard
            .challenges
            .iter()
            .filter(|(_, value)| {
                value
                    .expires_at
                    .saturating_add(ONLINE_ARTIFACT_RETENTION_SECONDS)
                    <= now
            })
            .map(|(key, _)| key.clone())
            .take(limit)
            .collect::<Vec<_>>();
        for key in &challenge_ids {
            guard.challenges.remove(key);
        }
        let authorization_ids = guard
            .authorization_codes
            .iter()
            .filter(|(_, value)| {
                value
                    .expires_at
                    .saturating_add(ONLINE_ARTIFACT_RETENTION_SECONDS)
                    <= now
            })
            .map(|(key, _)| key.clone())
            .take(limit)
            .collect::<Vec<_>>();
        for key in &authorization_ids {
            guard.authorization_codes.remove(key);
        }
        let session_ids = guard
            .sessions
            .iter()
            .filter(|(_, value)| {
                value
                    .absolute_expires_at
                    .saturating_add(SESSION_REPLAY_RETENTION_SECONDS)
                    <= now
            })
            .map(|(key, _)| key.clone())
            .take(limit)
            .collect::<Vec<_>>();
        for key in &session_ids {
            guard.sessions.remove(key);
        }
        guard
            .device_removal_operations
            .retain(|_, (_, _, _, created_at)| {
                created_at.saturating_add(PUBLIC_OPERATION_RETENTION_SECONDS) > now
            });
        let rate_limit_ids = guard
            .rate_limit_buckets
            .iter()
            .filter(|(_, value)| {
                value
                    .window_started_at
                    .saturating_add(RATE_LIMIT_RETENTION_SECONDS)
                    <= now
            })
            .map(|(key, _)| key.clone())
            .take(limit)
            .collect::<Vec<_>>();
        for key in &rate_limit_ids {
            guard.rate_limit_buckets.remove(key);
        }
        Ok(CleanupReport {
            challenges: challenge_ids.len() as u64,
            authorization_codes: authorization_ids.len() as u64,
            refresh_sessions: session_ids.len() as u64,
            rate_limit_buckets: rate_limit_ids.len() as u64,
        })
    }

    async fn consume_rate_limit(
        &self,
        scope: &str,
        key_hash: &str,
        now: i64,
        max_count: u32,
        window_seconds: i64,
    ) -> Result<bool> {
        if scope.is_empty() || key_hash.is_empty() || max_count == 0 || window_seconds <= 0 {
            return Err(ApiError::InvalidRequest);
        }
        let now = now.max(0);
        let mut guard = self.write()?;
        let bucket = guard
            .rate_limit_buckets
            .entry((scope.to_owned(), key_hash.to_owned()))
            .or_insert(MemoryRateLimitBucket {
                window_started_at: now,
                count: 0,
            });
        if now.saturating_sub(bucket.window_started_at) >= window_seconds {
            bucket.window_started_at = now;
            bucket.count = 0;
        }
        if bucket.count >= max_count {
            return Ok(false);
        }
        bucket.count = bucket.count.saturating_add(1);
        Ok(true)
    }

    async fn upsert_account(&self, account: Account) -> Result<()> {
        self.write()?.accounts.insert(account.id.clone(), account);
        Ok(())
    }

    async fn account(&self, account_id: &str) -> Result<Option<Account>> {
        Ok(self.read()?.accounts.get(account_id).cloned())
    }

    async fn upsert_license(&self, license: License) -> Result<()> {
        self.write()?.licenses.insert(license.id.clone(), license);
        Ok(())
    }

    async fn license(&self, license_id: &str) -> Result<Option<License>> {
        Ok(self.read()?.licenses.get(license_id).cloned())
    }

    async fn license_for_account(&self, account_id: &str) -> Result<Option<License>> {
        Ok(self
            .read()?
            .licenses
            .values()
            .find(|license| license.account_id == account_id)
            .cloned())
    }

    async fn upsert_device(&self, device: Device) -> Result<()> {
        let mut guard = self.write()?;
        let license = guard
            .licenses
            .get(&device.license_id)
            .ok_or(ApiError::LicenseUnavailable)?;
        if device.state == DeviceState::PendingActivation {
            let now = device.last_seen_at.unwrap_or(device.created_at);
            let occupied = guard
                .devices
                .values()
                .filter(|existing| {
                    existing.license_id == device.license_id
                        && existing.metadata.device_id != device.metadata.device_id
                        && (existing.state == DeviceState::Active
                            || (existing.state == DeviceState::PendingActivation
                                && existing
                                    .pending_activation_expires_at
                                    .is_some_and(|expires_at| expires_at > now)))
                })
                .count();
            if occupied >= license.effective_policy()?.device_limit as usize {
                return Err(ApiError::ActivationLimitReached);
            }
        }
        if let Some(existing) = guard.devices.get(&device.metadata.device_id) {
            if existing.account_id != device.account_id
                || existing.license_id != device.license_id
                || existing.metadata.public_key_thumbprint != device.metadata.public_key_thumbprint
            {
                return Err(ApiError::DeviceDenied);
            }
            if matches!(
                existing.state,
                DeviceState::Revoked | DeviceState::Suspicious
            ) {
                return Err(ApiError::DeviceStateDenied(existing.state));
            }
        }
        guard
            .devices
            .insert(device.metadata.device_id.clone(), device);
        Ok(())
    }

    async fn register_device_session_with_audit(
        &self,
        device: Device,
        session: RefreshSessionRecord,
        expected_device_state: Option<DeviceState>,
        authorization: AuthorizationCodeRedemption,
        now: i64,
        audit: AuditEventRecord,
    ) -> Result<()> {
        let mut guard = self.write()?;
        validate_initial_registration_bundle(
            &device,
            &session,
            expected_device_state,
            now,
            &audit,
        )?;
        let authorization_code = guard
            .authorization_codes
            .get(&authorization.code_hash)
            .cloned()
            .ok_or(ApiError::AuthorizationRequired)?;
        validate_authorization_redemption(
            &authorization_code,
            &authorization,
            &device,
            session.pending_activation_code_hash.as_deref(),
            now,
        )?;
        validate_session_binding(&guard, &device, &session, now)?;
        let existing = guard.devices.get(&device.metadata.device_id).cloned();
        ensure_expected_device_state(existing.as_ref(), expected_device_state)?;
        if let Some(existing) = &existing {
            if existing.account_id != device.account_id
                || existing.license_id != device.license_id
                || existing.metadata.public_key_thumbprint != device.metadata.public_key_thumbprint
            {
                return Err(ApiError::DeviceDenied);
            }
            if matches!(
                existing.state,
                DeviceState::Revoked | DeviceState::Suspicious
            ) {
                return Err(ApiError::DeviceStateDenied(existing.state));
            }
        }
        if let Some(activation_code_hash) = session.pending_activation_code_hash.as_deref() {
            let code = guard
                .activation_codes
                .get(activation_code_hash)
                .ok_or(ApiError::ActivationCodeInvalid)?;
            if code.account_id != device.account_id
                || code
                    .license_id
                    .as_ref()
                    .is_some_and(|license_id| license_id != &device.license_id)
            {
                return Err(ApiError::ActivationCodeInvalid);
            }
            if !code.is_usable(now) {
                return Err(activation_code_error(code, now));
            }
        }
        let license = guard
            .licenses
            .get(&device.license_id)
            .ok_or(ApiError::LicenseUnavailable)?;
        let previously_occupied = existing
            .as_ref()
            .is_some_and(|existing| device_occupies_activation_slot(existing, now));
        if device_occupies_activation_slot(&device, now) && !previously_occupied {
            let occupied = guard
                .devices
                .values()
                .filter(|existing| {
                    existing.license_id == device.license_id
                        && existing.metadata.device_id != device.metadata.device_id
                        && (existing.state == DeviceState::Active
                            || (existing.state == DeviceState::PendingActivation
                                && existing
                                    .pending_activation_expires_at
                                    .is_some_and(|expires_at| expires_at > now)))
                })
                .count();
            if occupied >= license.effective_policy()?.device_limit as usize {
                return Err(ApiError::ActivationLimitReached);
            }
        }
        if guard.sessions.contains_key(&session.token_hash)
            || guard
                .audit_events
                .iter()
                .any(|existing| existing.id == audit.id)
        {
            return Err(ApiError::InvalidRequest);
        }

        let device_id = device.metadata.device_id.clone();
        let authorization_code = guard
            .authorization_codes
            .get_mut(&authorization.code_hash)
            .ok_or(ApiError::AuthorizationRequired)?;
        if !authorization_code.consumed {
            authorization_code.consumed = true;
            authorization_code.consumed_at = Some(now);
            authorization_code.consumed_device_id = Some(device_id.clone());
            authorization_code.consumed_key_thumbprint =
                Some(device.metadata.public_key_thumbprint.clone());
        }
        guard.devices.insert(device_id.clone(), device);
        for existing in guard.sessions.values_mut() {
            if existing.device_id == device_id
                && (session.proof_state == RefreshSessionProofState::DeviceProven
                    || existing.proof_state == RefreshSessionProofState::Unproven)
            {
                existing.active = false;
            }
        }
        guard.sessions.insert(session.token_hash.clone(), session);
        guard.audit_events.push(audit);
        Ok(())
    }

    async fn device(&self, device_id: &str) -> Result<Option<Device>> {
        Ok(self.read()?.devices.get(device_id).cloned())
    }

    async fn devices_for_license_page(
        &self,
        license_id: &str,
        after_device_id: Option<&str>,
        limit: u32,
    ) -> Result<Vec<Device>> {
        let mut devices = self
            .read()?
            .devices
            .values()
            .filter(|device| {
                device.license_id == license_id
                    && device.state != DeviceState::Removed
                    && after_device_id
                        .is_none_or(|cursor| device.metadata.device_id.as_str() > cursor)
            })
            .cloned()
            .collect::<Vec<_>>();
        devices.sort_by(|left, right| left.metadata.device_id.cmp(&right.metadata.device_id));
        devices.truncate(limit as usize);
        Ok(devices)
    }

    async fn set_device_state(&self, device_id: &str, state: DeviceState, now: i64) -> Result<()> {
        let mut guard = self.write()?;
        let device = guard
            .devices
            .get_mut(device_id)
            .ok_or(ApiError::DeviceDenied)?;
        device.state = state;
        device.last_seen_at = Some(now);
        Ok(())
    }

    async fn touch_device_last_seen(
        &self,
        device_id: &str,
        now: i64,
        minimum_interval_seconds: i64,
    ) -> Result<()> {
        let mut guard = self.write()?;
        let device = guard
            .devices
            .get_mut(device_id)
            .ok_or(ApiError::DeviceDenied)?;
        if device.last_seen_at.is_none_or(|last_seen_at| {
            last_seen_at.saturating_add(minimum_interval_seconds.max(0)) <= now
        }) {
            device.last_seen_at = Some(now);
        }
        Ok(())
    }

    async fn update_device_client_metadata(
        &self,
        device_id: &str,
        app_version: &str,
        now: i64,
    ) -> Result<()> {
        let mut guard = self.write()?;
        let device = guard
            .devices
            .get_mut(device_id)
            .ok_or(ApiError::DeviceDenied)?;
        if device.last_seen_at.is_none_or(|seen| seen <= now) {
            device.metadata.app_version = app_version.to_owned();
            device.last_seen_at = Some(now);
        }
        Ok(())
    }

    async fn insert_session(&self, session: RefreshSessionRecord) -> Result<()> {
        self.write()?
            .sessions
            .insert(session.token_hash.clone(), session);
        Ok(())
    }

    async fn replace_device_sessions_with_audit(
        &self,
        session: RefreshSessionRecord,
        now: i64,
        audit: AuditEventRecord,
    ) -> Result<()> {
        let mut guard = self.write()?;
        validate_session_replacement(&guard, &session, now)?;
        let device = guard
            .devices
            .get(&session.device_id)
            .ok_or(ApiError::DeviceDenied)?;
        validate_session_success_audit(&audit, "session_recovered", &session, device, now)?;
        if guard.sessions.contains_key(&session.token_hash)
            || contains_audit_id(&guard.audit_events, &audit)
        {
            return Err(ApiError::InvalidRequest);
        }
        for existing in guard.sessions.values_mut() {
            if existing.device_id == session.device_id
                && (session.proof_state == RefreshSessionProofState::DeviceProven
                    || existing.proof_state == RefreshSessionProofState::Unproven)
            {
                existing.active = false;
            }
        }
        guard.sessions.insert(session.token_hash.clone(), session);
        guard.audit_events.push(audit);
        Ok(())
    }

    async fn session_by_hash(&self, token_hash: &str) -> Result<Option<RefreshSessionRecord>> {
        Ok(self.read()?.sessions.get(token_hash).cloned())
    }

    async fn rotate_session_with_audit(
        &self,
        old_hash: &str,
        new_session: RefreshSessionRecord,
        now: i64,
        audit: AuditEventRecord,
    ) -> Result<()> {
        let mut guard = self.write()?;
        let previous = guard
            .sessions
            .get(old_hash)
            .cloned()
            .ok_or(ApiError::AuthorizationRequired)?;
        let retry_successor = if !previous.active
            && previous
                .rotated_at
                .is_some_and(|rotated_at| rotated_at.saturating_add(60) >= now)
        {
            previous
                .rotated_to_hash
                .as_ref()
                .and_then(|hash| guard.sessions.get(hash))
                .filter(|successor| {
                    successor.active
                        && successor.expires_at > now
                        && successor.absolute_expires_at > now
                        && successor.rotated_to_hash.is_none()
                        && successor.family_id == previous.family_id
                        && successor.device_id == previous.device_id
                })
                .map(|successor| successor.token_hash.clone())
        } else {
            None
        };
        if (!previous.active && retry_successor.is_none())
            || previous.expires_at <= now
            || previous.absolute_expires_at <= now
        {
            for session in guard.sessions.values_mut() {
                if session.family_id == previous.family_id {
                    session.active = false;
                }
            }
            return Err(if previous.active {
                ApiError::AuthorizationRequired
            } else {
                ApiError::RefreshSessionReused
            });
        }
        if new_session.family_id != previous.family_id
            || new_session.account_id != previous.account_id
            || new_session.device_id != previous.device_id
            || new_session.family_created_at != previous.family_created_at
            || new_session.absolute_expires_at != previous.absolute_expires_at
            || new_session.expires_at > previous.absolute_expires_at
            || new_session.proof_state != RefreshSessionProofState::DeviceProven
        {
            return Err(ApiError::InvalidRequest);
        }
        let device = guard
            .devices
            .get(&previous.device_id)
            .ok_or(ApiError::DeviceDenied)?;
        let event_type = if new_session.activation_verified_at == Some(now) {
            "activation_proof_issued"
        } else if new_session.activation_verified_at.is_none() {
            "entitlement_refreshed"
        } else {
            return Err(ApiError::InvalidRequest);
        };
        validate_session_success_audit(&audit, event_type, &previous, device, now)?;
        if guard.sessions.contains_key(&new_session.token_hash)
            || contains_audit_id(&guard.audit_events, &audit)
        {
            return Err(ApiError::InvalidRequest);
        }
        if previous.proof_state == RefreshSessionProofState::Unproven
            && new_session.proof_state == RefreshSessionProofState::DeviceProven
        {
            for session in guard.sessions.values_mut() {
                if session.device_id == previous.device_id && session.token_hash != old_hash {
                    session.active = false;
                }
            }
        }
        let old = guard
            .sessions
            .get_mut(old_hash)
            .ok_or(ApiError::AuthorizationRequired)?;
        old.active = false;
        old.rotated_to_hash = Some(new_session.token_hash.clone());
        old.rotated_at = Some(now);
        if let Some(successor_hash) = retry_successor
            && let Some(successor) = guard.sessions.get_mut(&successor_hash)
        {
            successor.active = false;
        }
        guard
            .sessions
            .insert(new_session.token_hash.clone(), new_session);
        guard.audit_events.push(audit);
        Ok(())
    }

    async fn revoke_session_family(&self, family_id: &str) -> Result<()> {
        for session in self.write()?.sessions.values_mut() {
            if session.family_id == family_id {
                session.active = false;
            }
        }
        Ok(())
    }

    async fn revoke_sessions_for_device(&self, device_id: &str) -> Result<()> {
        for session in self.write()?.sessions.values_mut() {
            if session.device_id == device_id {
                session.active = false;
            }
        }
        Ok(())
    }

    async fn device_removal_replayed(
        &self,
        account_id: &str,
        requester_session_hash: &str,
        requester_device_id: &str,
        target_device_id: &str,
        operation_id: &str,
    ) -> Result<bool> {
        let guard = self.read()?;
        let Some((stored_session_hash, stored_requester, stored_target, _)) = guard
            .device_removal_operations
            .get(&(account_id.to_owned(), operation_id.to_owned()))
        else {
            return Ok(false);
        };
        if stored_session_hash != requester_session_hash
            || stored_requester != requester_device_id
            || stored_target != target_device_id
        {
            return Err(ApiError::IdempotencyConflict);
        }
        Ok(true)
    }

    async fn remove_device_with_audit(
        &self,
        requester_session_hash: &str,
        requester_device_id: &str,
        target_device_id: &str,
        operation_id: &str,
        now: i64,
        audit: AuditEventRecord,
    ) -> Result<bool> {
        let mut guard = self.write()?;
        let requester = guard
            .devices
            .get(requester_device_id)
            .cloned()
            .ok_or(ApiError::DeviceDenied)?;
        let target = guard
            .devices
            .get(target_device_id)
            .cloned()
            .ok_or(ApiError::DeviceDenied)?;
        let requester_session = guard
            .sessions
            .get(requester_session_hash)
            .ok_or(ApiError::AuthorizationRequired)?;
        let operation_key = (requester.account_id.clone(), operation_id.to_owned());
        if let Some((stored_session_hash, stored_requester, stored_target, _)) =
            guard.device_removal_operations.get(&operation_key)
        {
            if stored_session_hash != requester_session_hash
                || stored_requester != requester_device_id
                || stored_target != target_device_id
            {
                return Err(ApiError::IdempotencyConflict);
            }
            return Ok(false);
        }
        ensure_active_proven_session(requester_session, &requester, now)?;
        ensure_account_is_active(
            guard
                .accounts
                .get(&requester.account_id)
                .ok_or(ApiError::DeviceDenied)?,
        )?;
        if requester.state != DeviceState::Active {
            return Err(ApiError::DeviceStateDenied(requester.state));
        }
        if target.account_id != requester.account_id || target.license_id != requester.license_id {
            return Err(ApiError::DeviceDenied);
        }
        if matches!(target.state, DeviceState::Revoked | DeviceState::Suspicious) {
            return Err(ApiError::DeviceStateDenied(target.state));
        }
        validate_device_removal_audit(&audit, &requester, target_device_id)?;
        if target.state == DeviceState::Removed {
            guard.device_removal_operations.insert(
                operation_key,
                (
                    requester_session_hash.to_owned(),
                    requester_device_id.to_owned(),
                    target_device_id.to_owned(),
                    now,
                ),
            );
            return Ok(false);
        }

        let target = guard
            .devices
            .get_mut(target_device_id)
            .ok_or(ApiError::DeviceDenied)?;
        target.state = DeviceState::Removed;
        target.last_seen_at = Some(now);
        for session in guard.sessions.values_mut() {
            if session.device_id == target_device_id {
                session.active = false;
            }
        }
        guard.audit_events.push(audit);
        guard.device_removal_operations.insert(
            operation_key,
            (
                requester_session_hash.to_owned(),
                requester_device_id.to_owned(),
                target_device_id.to_owned(),
                now,
            ),
        );
        Ok(true)
    }

    async fn logout_device_sessions_with_audit(
        &self,
        token_hash: &str,
        now: i64,
        audit: AuditEventRecord,
    ) -> Result<Option<RefreshSessionRecord>> {
        let mut guard = self.write()?;
        let Some(record) = guard.sessions.get(token_hash).cloned() else {
            return Ok(None);
        };
        if !record.active || record.expires_at <= now || record.absolute_expires_at <= now {
            return Ok(None);
        }
        validate_logout_audit(&audit, &record)?;
        for session in guard.sessions.values_mut() {
            if session.device_id == record.device_id {
                session.active = false;
            }
        }
        guard.audit_events.push(audit);
        Ok(Some(record))
    }

    async fn insert_challenge(&self, challenge: StoredChallenge) -> Result<()> {
        let mut guard = self.write()?;
        guard
            .challenges
            .retain(|_, existing| existing.expires_at > challenge.issued_at);
        guard
            .challenges
            .insert(challenge.challenge_id.clone(), challenge);
        Ok(())
    }

    async fn consume_challenge(
        &self,
        challenge_id: &str,
        device_id: &str,
        now: i64,
    ) -> Result<StoredChallenge> {
        let mut guard = self.write()?;
        let challenge = guard
            .challenges
            .get_mut(challenge_id)
            .ok_or(ApiError::InvalidChallenge)?;
        if challenge.device_id != device_id || challenge.expires_at <= now {
            return Err(ApiError::InvalidChallenge);
        }
        if challenge.consumed {
            return Err(ApiError::ChallengeReplay);
        }
        challenge.consumed = true;
        Ok(challenge.clone())
    }

    async fn insert_authorization_code_with_audit(
        &self,
        code: StoredAuthorizationCode,
        audit: AuditEventRecord,
    ) -> Result<()> {
        let mut guard = self.write()?;
        validate_authorization_code_audit(&audit, &code)?;
        if guard.authorization_codes.contains_key(&code.code_hash)
            || contains_audit_id(&guard.audit_events, &audit)
        {
            return Err(ApiError::InvalidRequest);
        }
        guard
            .authorization_codes
            .insert(code.code_hash.clone(), code);
        guard.audit_events.push(audit);
        Ok(())
    }

    async fn authorization_code_by_hash(
        &self,
        code_hash: &str,
    ) -> Result<Option<StoredAuthorizationCode>> {
        Ok(self.read()?.authorization_codes.get(code_hash).cloned())
    }

    async fn upsert_activation_code(&self, code: ActivationCodeRecord) -> Result<()> {
        self.write()?
            .activation_codes
            .insert(code.code_hash.clone(), code);
        Ok(())
    }

    async fn activation_code_by_hash(
        &self,
        code_hash: &str,
    ) -> Result<Option<ActivationCodeRecord>> {
        Ok(self.read()?.activation_codes.get(code_hash).cloned())
    }

    async fn confirm_device_activation(
        &self,
        session_token_hash: &str,
        device_id: &str,
        activation_code_hash: Option<&str>,
        now: i64,
        audit: AuditEventRecord,
    ) -> Result<Device> {
        let mut guard = self.write()?;
        let confirmation = guard
            .sessions
            .get(session_token_hash)
            .cloned()
            .ok_or(ApiError::AuthorizationRequired)?;
        if !confirmation.active
            || confirmation.expires_at <= now
            || confirmation.absolute_expires_at <= now
            || confirmation.proof_state != RefreshSessionProofState::DeviceProven
            || confirmation.device_id != device_id
            || confirmation
                .activation_verified_at
                .is_none_or(|verified_at| verified_at + 5 * 60 <= now)
        {
            return Err(ApiError::AuthorizationRequired);
        }
        let current = guard
            .devices
            .get(device_id)
            .cloned()
            .ok_or(ApiError::DeviceDenied)?;
        ensure_account_is_active(
            guard
                .accounts
                .get(&current.account_id)
                .ok_or(ApiError::DeviceDenied)?,
        )?;
        let license = guard
            .licenses
            .get(&current.license_id)
            .ok_or(ApiError::LicenseUnavailable)?;
        if license.account_id != current.account_id {
            return Err(ApiError::LicenseUnavailable);
        }
        ensure_license_is_usable(license, now)?;
        let max_devices = license.effective_policy()?.device_limit;
        validate_activation_confirmation_audit(&audit, &current)?;
        if current.state == DeviceState::Active {
            guard.audit_events.push(audit);
            return Ok(current);
        }
        let activation_code_hash = activation_code_hash.ok_or(ApiError::AuthorizationRequired)?;
        if confirmation.pending_activation_code_hash.as_deref() != Some(activation_code_hash) {
            return Err(ApiError::AuthorizationRequired);
        }
        if confirmation.activation_confirmation_consumed {
            return Err(ApiError::AuthorizationRequired);
        }
        if current.state != DeviceState::PendingActivation
            || current.pending_activation_code_hash.as_deref() != Some(activation_code_hash)
            || current
                .pending_activation_expires_at
                .is_none_or(|expires_at| expires_at <= now)
        {
            return Err(ApiError::AuthorizationRequired);
        }
        let active_count = guard
            .devices
            .values()
            .filter(|device| {
                device.license_id == current.license_id && device.state == DeviceState::Active
            })
            .count();
        if active_count >= max_devices as usize {
            return Err(ApiError::ActivationLimitReached);
        }
        let code = guard
            .activation_codes
            .get_mut(activation_code_hash)
            .ok_or(ApiError::ActivationCodeInvalid)?;
        if code.account_id != current.account_id
            || code
                .license_id
                .as_ref()
                .is_some_and(|license_id| license_id != &current.license_id)
        {
            return Err(ApiError::ActivationCodeInvalid);
        }
        if !code.is_usable(now) {
            return Err(activation_code_error(code, now));
        }
        code.record_redemption(device_id, now);
        let confirmation = guard
            .sessions
            .get_mut(session_token_hash)
            .ok_or(ApiError::AuthorizationRequired)?;
        confirmation.activation_confirmation_consumed = true;
        let device = guard
            .devices
            .get_mut(device_id)
            .ok_or(ApiError::DeviceDenied)?;
        device.state = DeviceState::Active;
        device.pending_activation_code_hash = None;
        device.pending_activation_expires_at = None;
        device.last_seen_at = Some(now);
        let device = device.clone();
        guard.audit_events.push(audit);
        Ok(device)
    }

    async fn insert_audit_event(&self, event: AuditEventRecord) -> Result<()> {
        let mut guard = self.write()?;
        if contains_audit_id(&guard.audit_events, &event) {
            return Err(ApiError::InvalidRequest);
        }
        guard.audit_events.push(event);
        Ok(())
    }
}

impl MemoryRepository {
    #[cfg(test)]
    pub fn audit_events(&self) -> Result<Vec<AuditEventRecord>> {
        Ok(self.read()?.audit_events.clone())
    }

    fn read(&self) -> Result<std::sync::RwLockReadGuard<'_, MemoryState>> {
        self.inner.read().map_err(|_| ApiError::Internal)
    }

    fn write(&self) -> Result<std::sync::RwLockWriteGuard<'_, MemoryState>> {
        self.inner.write().map_err(|_| ApiError::Internal)
    }
}

#[derive(Clone)]
pub struct PostgresRepository {
    pub(crate) pool: PgPool,
}

pub struct AdminSecretDeliveryInsert {
    pub id: String,
    pub actor_id: String,
    pub session_id: String,
    pub purpose: String,
    pub key_id: String,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub claim_token_hash: String,
    pub expires_at: i64,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivationCodeDeliveryReceipt {
    pub delivery_id: String,
    pub delivery_expires_at: i64,
    pub secret_key_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivationCodeBatchCommit {
    pub delivery: Option<ActivationCodeDeliveryReceipt>,
    #[serde(skip)]
    pub replayed: bool,
}

impl PostgresRepository {
    pub async fn connect_config(
        database: &DatabaseConnectionConfig,
        max_connections: u32,
        acquire_timeout: Duration,
    ) -> Result<Self> {
        let mut options = PgConnectOptions::from_str(&database.database_url)
            .map_err(|error| database_error("postgres_connect_options", error))?;
        if let Some(path) = &database.password_file {
            let password = read_database_password(path)?;
            options = options.password(&password);
        }
        let pool = PgPoolOptions::new()
            .max_connections(max_connections)
            .acquire_timeout(acquire_timeout)
            .connect_with(options)
            .await
            .map_err(|error| database_error("postgres_connect", error))?;
        Ok(Self { pool })
    }

    pub async fn connect(
        database_url: &str,
        max_connections: u32,
        acquire_timeout: Duration,
    ) -> Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(max_connections)
            .acquire_timeout(acquire_timeout)
            .connect(database_url)
            .await
            .map_err(|error| database_error("postgres_connect", error))?;
        Ok(Self { pool })
    }

    pub async fn migrate(&self) -> Result<()> {
        sqlx::migrate!("./migrations")
            .run(&self.pool)
            .await
            .map_err(|error| database_error("postgres_migrate", error))
    }

    pub async fn accounts(&self) -> Result<Vec<Account>> {
        let rows = sqlx::query("SELECT document FROM accounts ORDER BY id ASC")
            .fetch_all(&self.pool)
            .await
            .map_err(|_| ApiError::Database)?;
        rows.into_iter().map(row_document).collect()
    }

    pub async fn create_account_with_audit(
        &self,
        account: Account,
        audit: AuditEventRecord,
        operation: Option<&AdminOperationClaim>,
        context: &MutationContext,
        permission: AdminPermission,
    ) -> AdminAppResult<Account> {
        if audit.account_id.as_deref() != Some(account.id.as_str()) {
            return Err(ApiError::InvalidRequest.into());
        }
        let mut tx = self.pool.begin().await.map_err(|_| ApiError::Database)?;
        authorize_admin_mutation(&mut tx, context, permission, false, audit.occurred_at).await?;
        if let Some(operation) = operation
            && let Some(response) =
                admin_operation::claim_prepared::<Account>(&mut tx, operation).await?
        {
            tx.commit().await.map_err(|_| ApiError::Database)?;
            return Ok(response);
        }
        sqlx::query(
            "INSERT INTO accounts (id, document, created_at, updated_at)
             VALUES ($1, $2, to_timestamp($3), to_timestamp($3))",
        )
        .bind(&account.id)
        .bind(json(&account)?)
        .bind(audit.occurred_at)
        .execute(&mut *tx)
        .await
        .map_err(|error| admin_conflict_or_database("admin_account_create", error))?;
        insert_audit_event_transaction(&mut tx, &audit).await?;
        if let Some(operation) = operation {
            admin_operation::finish_prepared(&mut tx, &account, operation).await?;
        }
        tx.commit().await.map_err(|_| ApiError::Database)?;
        Ok(account)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn update_account_with_audit(
        &self,
        account: Account,
        expected_document: serde_json::Value,
        revoke_sessions: bool,
        audit: AuditEventRecord,
        operation: Option<&AdminOperationClaim>,
        context: &MutationContext,
        permission: AdminPermission,
    ) -> AdminAppResult<Account> {
        if audit.account_id.as_deref() != Some(account.id.as_str()) {
            return Err(ApiError::InvalidRequest.into());
        }
        let mut tx = self.pool.begin().await.map_err(|_| ApiError::Database)?;
        authorize_admin_mutation(&mut tx, context, permission, false, audit.occurred_at).await?;
        if let Some(operation) = operation
            && let Some(response) =
                admin_operation::claim_prepared::<Account>(&mut tx, operation).await?
        {
            tx.commit().await.map_err(|_| ApiError::Database)?;
            return Ok(response);
        }
        let device_ids: Vec<String> = sqlx::query_scalar(
            "SELECT device_id FROM devices WHERE account_id = $1 ORDER BY device_id",
        )
        .bind(&account.id)
        .fetch_all(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        for device_id in &device_ids {
            lock_device(&mut tx, device_id).await?;
        }
        let updated = sqlx::query(
            "UPDATE accounts
             SET document = $2, row_version = row_version + 1, updated_at = to_timestamp($4)
             WHERE id = $1 AND document = $3",
        )
        .bind(&account.id)
        .bind(json(&account)?)
        .bind(expected_document)
        .bind(audit.occurred_at)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?
        .rows_affected();
        if updated != 1 {
            return Err(AdminAppError::VersionConflict);
        }
        if revoke_sessions {
            sqlx::query(
                "UPDATE refresh_sessions
                 SET active = false,
                     document = jsonb_set(document, '{active}', 'false'::jsonb, true),
                     updated_at = to_timestamp($2)
                 WHERE device_id IN (
                     SELECT device_id FROM devices WHERE account_id = $1
                 )",
            )
            .bind(&account.id)
            .bind(audit.occurred_at)
            .execute(&mut *tx)
            .await
            .map_err(|_| ApiError::Database)?;
        }
        insert_audit_event_transaction(&mut tx, &audit).await?;
        if let Some(operation) = operation {
            admin_operation::finish_prepared(&mut tx, &account, operation).await?;
        }
        tx.commit().await.map_err(|_| ApiError::Database)?;
        Ok(account)
    }

    pub async fn licenses(&self, account_id: Option<&str>) -> Result<Vec<License>> {
        let rows = if let Some(account_id) = account_id {
            sqlx::query(
                "SELECT id, account_id, plan, plan_revision, status, expires_at,
                        license_epoch, purchased_seats, row_version
                 FROM licenses WHERE account_id = $1 ORDER BY id ASC",
            )
            .bind(account_id)
            .fetch_all(&self.pool)
            .await
        } else {
            sqlx::query(
                "SELECT id, account_id, plan, plan_revision, status, expires_at,
                        license_epoch, purchased_seats, row_version
                 FROM licenses ORDER BY account_id ASC, id ASC",
            )
            .fetch_all(&self.pool)
            .await
        }
        .map_err(|_| ApiError::Database)?;
        rows.into_iter().map(row_license).collect()
    }

    pub async fn upsert_license_with_audit(
        &self,
        license: License,
        expected_document: Option<serde_json::Value>,
        audit: AuditEventRecord,
        operation: Option<&AdminOperationClaim>,
        context: &MutationContext,
    ) -> AdminAppResult<License> {
        if audit.account_id.as_deref() != Some(license.account_id.as_str())
            || audit.license_id.as_deref() != Some(license.id.as_str())
        {
            return Err(ApiError::InvalidRequest.into());
        }
        let previous = expected_document
            .as_ref()
            .and_then(|document| serde_json::from_value::<License>(document.clone()).ok());
        let revoke_sessions = previous.as_ref().is_some_and(|previous| {
            previous.status != LicenseStatus::Canceled && license.status == LicenseStatus::Canceled
        });
        let mut tx = self.pool.begin().await.map_err(|_| ApiError::Database)?;
        authorize_admin_mutation(
            &mut tx,
            context,
            AdminPermission::LicenseWrite,
            false,
            audit.occurred_at,
        )
        .await?;
        if let Some(operation) = operation
            && let Some(response) =
                admin_operation::claim_prepared::<License>(&mut tx, operation).await?
        {
            tx.commit().await.map_err(|_| ApiError::Database)?;
            return Ok(response);
        }
        lock_license(&mut tx, &license.id).await?;
        let device_ids: Vec<String> = sqlx::query_scalar(
            "SELECT device_id FROM devices WHERE license_id = $1 ORDER BY device_id",
        )
        .bind(&license.id)
        .fetch_all(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        for device_id in &device_ids {
            lock_device(&mut tx, device_id).await?;
        }
        let updated = if let Some(expected_document) = expected_document {
            let expected: License =
                serde_json::from_value(expected_document).map_err(|_| ApiError::InvalidRequest)?;
            sqlx::query(
                "UPDATE licenses
                 SET account_id = $2, plan = $3, plan_revision = $4, status = $5,
                     expires_at = $6, license_epoch = $7, purchased_seats = $8,
                     row_version = $9, updated_at = to_timestamp($11)
                 WHERE id = $1 AND row_version = $10",
            )
            .bind(&license.id)
            .bind(&license.account_id)
            .bind(plan_name(license.plan))
            .bind(i32::try_from(license.plan_revision).map_err(|_| ApiError::InvalidRequest)?)
            .bind(license_status_name(license.status))
            .bind(license.expires_at)
            .bind(i64::try_from(license.license_epoch).map_err(|_| ApiError::InvalidRequest)?)
            .bind(i32::try_from(license.purchased_seats).map_err(|_| ApiError::InvalidRequest)?)
            .bind(i64::try_from(license.row_version).map_err(|_| ApiError::InvalidRequest)?)
            .bind(i64::try_from(expected.row_version).map_err(|_| ApiError::InvalidRequest)?)
            .bind(audit.occurred_at)
            .execute(&mut *tx)
            .await
            .map_err(|_| ApiError::Database)?
            .rows_affected()
        } else {
            sqlx::query(
                "INSERT INTO licenses
                    (id, account_id, plan, plan_revision, status, expires_at,
                     license_epoch, purchased_seats, row_version, created_at, updated_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9,
                         to_timestamp($10), to_timestamp($10))",
            )
            .bind(&license.id)
            .bind(&license.account_id)
            .bind(plan_name(license.plan))
            .bind(i32::try_from(license.plan_revision).map_err(|_| ApiError::InvalidRequest)?)
            .bind(license_status_name(license.status))
            .bind(license.expires_at)
            .bind(i64::try_from(license.license_epoch).map_err(|_| ApiError::InvalidRequest)?)
            .bind(i32::try_from(license.purchased_seats).map_err(|_| ApiError::InvalidRequest)?)
            .bind(i64::try_from(license.row_version).map_err(|_| ApiError::InvalidRequest)?)
            .bind(audit.occurred_at)
            .execute(&mut *tx)
            .await
            .map_err(|error| admin_conflict_or_database("admin_license_create", error))?
            .rows_affected()
        };
        if updated != 1 {
            return Err(AdminAppError::VersionConflict);
        }
        if revoke_sessions {
            sqlx::query(
                "UPDATE refresh_sessions
                 SET active = false,
                     document = jsonb_set(document, '{active}', 'false'::jsonb, true),
                     updated_at = to_timestamp($2)
                 WHERE device_id IN (
                     SELECT device_id FROM devices WHERE license_id = $1
                 )",
            )
            .bind(&license.id)
            .bind(audit.occurred_at)
            .execute(&mut *tx)
            .await
            .map_err(|_| ApiError::Database)?;
        }
        insert_audit_event_transaction(&mut tx, &audit).await?;
        if let Some(operation) = operation {
            admin_operation::finish_prepared(&mut tx, &license, operation).await?;
        }
        tx.commit().await.map_err(|_| ApiError::Database)?;
        Ok(license)
    }

    pub async fn activation_codes(
        &self,
        account_id: Option<&str>,
        status: Option<ActivationCodeStatus>,
    ) -> Result<Vec<ActivationCodeRecord>> {
        let rows = if let Some(account_id) = account_id {
            sqlx::query(
                "SELECT document FROM activation_codes WHERE account_id = $1 ORDER BY created_at DESC",
            )
            .bind(account_id)
            .fetch_all(&self.pool)
            .await
        } else {
            sqlx::query("SELECT document FROM activation_codes ORDER BY created_at DESC")
                .fetch_all(&self.pool)
                .await
        }
        .map_err(|_| ApiError::Database)?;
        let mut codes = rows
            .into_iter()
            .map(row_document)
            .collect::<Result<Vec<ActivationCodeRecord>>>()?;
        if let Some(status) = status {
            codes.retain(|code| code.status == status);
        }
        Ok(codes)
    }

    pub async fn activation_code_by_prefix(
        &self,
        prefix: &str,
    ) -> Result<Option<ActivationCodeRecord>> {
        let rows = sqlx::query(
            "SELECT document FROM activation_codes WHERE code_prefix = $1 ORDER BY created_at DESC LIMIT 2",
        )
        .bind(prefix)
        .fetch_all(&self.pool)
        .await
        .map_err(|_| ApiError::Database)?;
        if rows.len() != 1 {
            return Ok(None);
        }
        row_document(rows.into_iter().next().expect("one row")).map(Some)
    }

    pub async fn update_activation_code_with_audit(
        &self,
        code: ActivationCodeRecord,
        expected_document: serde_json::Value,
        expected_version: Option<i64>,
        audit: AuditEventRecord,
        operation: Option<&AdminOperationClaim>,
        context: &MutationContext,
    ) -> AdminAppResult<Option<ActivationCodeRecord>> {
        if audit.account_id.as_deref() != Some(code.account_id.as_str())
            || audit.license_id.as_deref() != code.license_id.as_deref()
        {
            return Err(ApiError::InvalidRequest.into());
        }
        let mut tx = self.pool.begin().await.map_err(|_| ApiError::Database)?;
        authorize_admin_mutation(
            &mut tx,
            context,
            AdminPermission::CodeWrite,
            false,
            audit.occurred_at,
        )
        .await?;
        if let Some(operation) = operation
            && let Some(response) =
                admin_operation::claim_prepared::<ActivationCodeRecord>(&mut tx, operation).await?
        {
            tx.commit().await.map_err(|_| ApiError::Database)?;
            return Ok(Some(response));
        }
        let updated = sqlx::query(
            "UPDATE activation_codes
             SET account_id = $2, license_id = $3, status = $4, expires_at = $5,
                 consumed = $6, consumed_at = $7, consumed_device_id = $8,
                 document = $9, row_version = row_version + 1,
                 updated_at = to_timestamp($12)
             WHERE code_hash = $1 AND document = $10
               AND ($11::bigint IS NULL OR row_version = $11)",
        )
        .bind(&code.code_hash)
        .bind(&code.account_id)
        .bind(&code.license_id)
        .bind(activation_code_status(&code.status))
        .bind(code.expires_at)
        .bind(code.status == ActivationCodeStatus::Consumed)
        .bind(code.consumed_at)
        .bind(&code.consumed_device_id)
        .bind(json(&code)?)
        .bind(expected_document)
        .bind(expected_version)
        .bind(audit.occurred_at)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?
        .rows_affected();
        if updated != 1 {
            return Ok(None);
        }
        insert_audit_event_transaction(&mut tx, &audit).await?;
        if let Some(operation) = operation {
            admin_operation::finish_prepared(&mut tx, &code, operation).await?;
        }
        tx.commit().await.map_err(|_| ApiError::Database)?;
        Ok(Some(code))
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn issue_activation_code_batch(
        &self,
        operation_id: &str,
        request_hash: &str,
        context: &MutationContext,
        records: &[ActivationCodeRecord],
        audits: &[AuditEventRecord],
    ) -> AdminAppResult<ActivationCodeBatchCommit> {
        self.issue_activation_code_batch_with_delivery(
            operation_id,
            request_hash,
            context,
            records,
            audits,
            None,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn issue_activation_code_batch_with_delivery(
        &self,
        operation_id: &str,
        request_hash: &str,
        context: &MutationContext,
        records: &[ActivationCodeRecord],
        audits: &[AuditEventRecord],
        delivery: Option<&AdminSecretDeliveryInsert>,
    ) -> AdminAppResult<ActivationCodeBatchCommit> {
        let actor = context.principal.id.as_str();
        let reason = context.reason.as_str();
        if operation_id.trim().is_empty()
            || request_hash.len() != 64
            || actor.trim().is_empty()
            || reason.trim().is_empty()
            || records.is_empty()
            || records.len() != audits.len()
            || records.iter().zip(audits).any(|(record, audit)| {
                audit.account_id.as_deref() != Some(record.account_id.as_str())
                    || audit.license_id.as_deref() != record.license_id.as_deref()
                    || audit.metadata.get("actor").map(String::as_str) != Some(actor)
                    || audit.metadata.get("operation_id").map(String::as_str) != Some(operation_id)
            })
        {
            return Err(ApiError::InvalidRequest.into());
        }
        let operation = admin_operation::from_parts(
            operation_id,
            "activation_code_issue",
            request_hash,
            actor,
            reason,
        )?;
        let mut tx = self.pool.begin().await.map_err(|_| ApiError::Database)?;
        authorize_admin_mutation(
            &mut tx,
            context,
            AdminPermission::CodeIssue,
            false,
            audits[0].occurred_at,
        )
        .await?;
        if let Some(mut response) =
            admin_operation::claim_prepared::<ActivationCodeBatchCommit>(&mut tx, &operation)
                .await?
        {
            response.replayed = true;
            tx.commit().await.map_err(|_| ApiError::Database)?;
            return Ok(response);
        }
        for (record, audit) in records.iter().zip(audits) {
            sqlx::query(
                "INSERT INTO activation_codes
                 (code_hash, code_prefix, account_id, license_id, status, expires_at, consumed,
                  consumed_at, consumed_device_id, document)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
            )
            .bind(&record.code_hash)
            .bind(&record.code_prefix)
            .bind(&record.account_id)
            .bind(&record.license_id)
            .bind(activation_code_status(&record.status))
            .bind(record.expires_at)
            .bind(false)
            .bind(record.consumed_at)
            .bind(&record.consumed_device_id)
            .bind(json(record)?)
            .execute(&mut *tx)
            .await
            .map_err(|_| ApiError::Database)?;
            insert_audit_event_transaction(&mut tx, audit).await?;
        }
        if let Some(delivery) = delivery {
            if delivery.actor_id != actor
                || delivery.purpose != "activation_code_batch"
                || delivery.created_at <= 0
                || delivery.expires_at <= delivery.created_at
                || delivery.claim_token_hash.len() != 64
                || delivery.ciphertext.is_empty()
            {
                return Err(ApiError::InvalidRequest.into());
            }
            sqlx::query(
                "INSERT INTO admin_secret_deliveries
                 (id, actor_id, session_id, purpose, key_id, nonce, ciphertext,
                  claim_token_hash, expires_at, created_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
            )
            .bind(&delivery.id)
            .bind(&delivery.actor_id)
            .bind(&delivery.session_id)
            .bind(&delivery.purpose)
            .bind(&delivery.key_id)
            .bind(&delivery.nonce)
            .bind(&delivery.ciphertext)
            .bind(&delivery.claim_token_hash)
            .bind(delivery.expires_at)
            .bind(delivery.created_at)
            .execute(&mut *tx)
            .await
            .map_err(|_| ApiError::Database)?;
        }
        let response = ActivationCodeBatchCommit {
            delivery: delivery.map(|delivery| ActivationCodeDeliveryReceipt {
                delivery_id: delivery.id.clone(),
                delivery_expires_at: delivery.expires_at,
                secret_key_id: delivery.key_id.clone(),
            }),
            replayed: false,
        };
        admin_operation::finish_prepared(&mut tx, &response, &operation).await?;
        tx.commit().await.map_err(|_| ApiError::Database)?;
        Ok(response)
    }

    pub async fn devices(&self, account_id: Option<&str>) -> Result<Vec<Device>> {
        let rows = if let Some(account_id) = account_id {
            sqlx::query("SELECT document FROM devices WHERE account_id = $1 ORDER BY device_id ASC")
                .bind(account_id)
                .fetch_all(&self.pool)
                .await
        } else {
            sqlx::query("SELECT document FROM devices ORDER BY account_id ASC, device_id ASC")
                .fetch_all(&self.pool)
                .await
        }
        .map_err(|_| ApiError::Database)?;
        rows.into_iter().map(row_document).collect()
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn set_device_state_with_audit(
        &self,
        device_id: &str,
        state: DeviceState,
        expected_version: Option<i64>,
        now: i64,
        audit: AuditEventRecord,
        operation: Option<&AdminOperationClaim>,
        context: &MutationContext,
        permission: AdminPermission,
    ) -> AdminAppResult<Option<Device>> {
        let mut tx = self.pool.begin().await.map_err(|_| ApiError::Database)?;
        authorize_admin_mutation(&mut tx, context, permission, false, now).await?;
        if let Some(operation) = operation
            && let Some(response) =
                admin_operation::claim_prepared::<Device>(&mut tx, operation).await?
        {
            tx.commit().await.map_err(|_| ApiError::Database)?;
            return Ok(Some(response));
        }
        lock_device(&mut tx, device_id).await?;
        let row = sqlx::query(
            "SELECT document, row_version FROM devices WHERE device_id = $1 FOR UPDATE",
        )
        .bind(device_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?
        .ok_or(ApiError::DeviceDenied)?;
        let row_version: i64 = row.try_get("row_version").map_err(|_| ApiError::Database)?;
        if expected_version.is_some_and(|expected| expected != row_version) {
            return Ok(None);
        }
        let mut device: Device = row_document(row)?;
        if audit.account_id.as_deref() != Some(device.account_id.as_str())
            || audit.license_id.as_deref() != Some(device.license_id.as_str())
            || audit.device_id.as_deref() != Some(device_id)
        {
            return Err(ApiError::InvalidRequest.into());
        }
        device.state = state;
        device.last_seen_at = Some(now);
        sqlx::query(
            "UPDATE devices
             SET state = $2, document = $3, row_version = row_version + 1,
                 updated_at = to_timestamp($4)
             WHERE device_id = $1",
        )
        .bind(device_id)
        .bind(device_state(&state))
        .bind(json(&device)?)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        sqlx::query(
            "UPDATE refresh_sessions
             SET active = false,
                 document = jsonb_set(document, '{active}', 'false'::jsonb, true),
                 updated_at = to_timestamp($2)
             WHERE device_id = $1",
        )
        .bind(device_id)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        if state != DeviceState::Active {
            sqlx::query(
                "DELETE FROM device_member_bindings
                 WHERE account_id = $1 AND device_id = $2",
            )
            .bind(&device.account_id)
            .bind(device_id)
            .execute(&mut *tx)
            .await
            .map_err(|_| ApiError::Database)?;
        }
        insert_audit_event_transaction(&mut tx, &audit).await?;
        if let Some(operation) = operation {
            admin_operation::finish_prepared(&mut tx, &device, operation).await?;
        }
        tx.commit().await.map_err(|_| ApiError::Database)?;
        Ok(Some(device))
    }

    pub async fn audit_events(
        &self,
        account_id: Option<&str>,
        limit: i64,
    ) -> Result<Vec<AuditEventRecord>> {
        let limit = limit.clamp(1, 500);
        let rows = if let Some(account_id) = account_id {
            sqlx::query(
                "SELECT id, event_type, outcome, occurred_at, account_id, license_id,
                        device_id, reason_code, metadata
                 FROM audit_events
                 WHERE account_id = $1
                 ORDER BY occurred_at DESC, id DESC
                 LIMIT $2",
            )
            .bind(account_id)
            .bind(limit)
            .fetch_all(&self.pool)
            .await
        } else {
            sqlx::query(
                "SELECT id, event_type, outcome, occurred_at, account_id, license_id,
                        device_id, reason_code, metadata
                 FROM audit_events
                 ORDER BY occurred_at DESC, id DESC
                 LIMIT $1",
            )
            .bind(limit)
            .fetch_all(&self.pool)
            .await
        }
        .map_err(|error| database_error("postgres_audit_events_list", error))?;
        rows.into_iter().map(row_audit_event).collect()
    }
}

fn read_database_password(path: &Path) -> Result<Zeroizing<String>> {
    let bytes = crate::secret_file::read_secret_file(path)
        .map_err(|_| database_password_error("unreadable_or_invalid_file"))?;
    let mut password = match String::from_utf8(bytes.to_vec()) {
        Ok(password) => Zeroizing::new(password),
        Err(error) => {
            let mut invalid_bytes = error.into_bytes();
            invalid_bytes.zeroize();
            return Err(database_password_error("invalid_utf8"));
        }
    };
    if password.ends_with('\n') {
        password.pop();
        if password.ends_with('\r') {
            password.pop();
        }
    }
    if password.is_empty()
        || password
            .chars()
            .any(|character| matches!(character, '\0' | '\r' | '\n'))
    {
        return Err(database_password_error("empty_or_multiline_value"));
    }
    Ok(password)
}

fn database_password_error(reason: &'static str) -> ApiError {
    tracing::error!(
        stage = "database_password_file",
        error_kind = "configuration",
        reason,
        "database password file is invalid"
    );
    ApiError::Database
}

#[async_trait]
impl LicenseRepository for PostgresRepository {
    async fn readiness_check(&self) -> Result<()> {
        // `information_schema` hides columns the current role cannot read. Use
        // PostgreSQL's metadata catalog so schema readiness remains independent
        // from each runtime role's intentionally narrower data privileges.
        let row = sqlx::query(
            "SELECT
                to_regclass('public.accounts') IS NOT NULL
                AND to_regclass('public.licenses') IS NOT NULL
                AND to_regclass('public.devices') IS NOT NULL
                AND to_regclass('public.refresh_sessions') IS NOT NULL
                AND to_regclass('public.device_challenges') IS NOT NULL
                AND to_regclass('public.authorization_codes') IS NOT NULL
                AND to_regclass('public.activation_codes') IS NOT NULL
                AND to_regclass('public.audit_events') IS NOT NULL
                AND to_regclass('public.admin_operations') IS NOT NULL
                AND to_regclass('public.rate_limit_buckets') IS NOT NULL
                AND to_regclass('public.service_time_authority') IS NOT NULL
                AND to_regclass('public.commercial_offers') IS NOT NULL
                AND to_regclass('public.manual_payment_methods') IS NOT NULL
                AND to_regclass('public.billing_invoices') IS NOT NULL
                AND to_regclass('public.manual_payment_claims') IS NOT NULL
                AND to_regclass('public.payment_evidence_attachments') IS NOT NULL
                AND to_regclass('public.workspace_members') IS NOT NULL
                AND to_regclass('public.team_invitations') IS NOT NULL
                AND to_regclass('public.device_member_bindings') IS NOT NULL
                AND to_regclass('public.device_removal_operations') IS NOT NULL
                AND to_regclass('public.team_operations') IS NOT NULL
                AND to_regprocedure('public.ensure_workspace_owner_for_account()') IS NOT NULL
                AND to_regprocedure('public.bind_first_workspace_device_to_owner()') IS NOT NULL
                AND to_regprocedure('public.require_active_team_device_binding()') IS NOT NULL
                AND to_regprocedure('public.remove_inactive_team_device_binding()') IS NOT NULL
                AND EXISTS (
                    SELECT 1 FROM pg_trigger
                    WHERE tgname = 'accounts_workspace_owner_after_insert' AND NOT tgisinternal
                )
                AND EXISTS (
                    SELECT 1 FROM pg_trigger
                    WHERE tgname = 'devices_workspace_owner_after_insert'
                      AND NOT tgisinternal
                      AND pg_get_triggerdef(oid) LIKE '%INSERT OR UPDATE OF state%'
                )
                AND EXISTS (
                    SELECT 1 FROM pg_attribute
                    WHERE attrelid = to_regclass('public.device_member_bindings')
                      AND attname = 'account_id'
                      AND attnum > 0
                      AND NOT attisdropped
                      AND attnotnull
                )
                AND EXISTS (
                    SELECT 1 FROM pg_trigger
                    WHERE tgname = 'device_member_bindings_active_device_before_write'
                      AND NOT tgisinternal
                )
                AND EXISTS (
                    SELECT 1 FROM pg_trigger
                    WHERE tgname = 'devices_remove_inactive_team_binding_after_update'
                      AND NOT tgisinternal
                )
                AND to_regclass('public.licenses_one_per_account_idx') IS NOT NULL
                AND to_regprocedure(
                    'public.observe_service_time_authority(bigint,bigint)'
                ) IS NOT NULL
                AND EXISTS (
                    SELECT 1 FROM pg_attribute
                    WHERE attrelid = to_regclass('public.licenses')
                      AND attname = 'plan_revision'
                      AND attnum > 0
                      AND NOT attisdropped
                      AND attnotnull
                )
                AND EXISTS (
                    SELECT 1 FROM pg_attribute
                    WHERE attrelid = to_regclass('public.licenses')
                      AND attname = 'purchased_seats'
                      AND attnum > 0
                      AND NOT attisdropped
                      AND attnotnull
                )
                AND NOT EXISTS (
                    SELECT 1 FROM pg_attribute
                    WHERE attrelid = to_regclass('public.licenses')
                      AND attname = 'document'
                      AND attnum > 0
                      AND NOT attisdropped
                )
                AND EXISTS (
                    SELECT 1 FROM pg_attribute
                    WHERE attrelid = to_regclass('public.refresh_sessions')
                      AND attname = 'device_id'
                      AND attnum > 0
                      AND NOT attisdropped
                      AND attnotnull
                )
                AND EXISTS (
                    SELECT 1 FROM pg_attribute
                    WHERE attrelid = to_regclass('public.refresh_sessions')
                      AND attname = 'proof_state'
                      AND attnum > 0
                      AND NOT attisdropped
                      AND attnotnull
                )
                AND to_regclass(
                    'public.refresh_sessions_one_active_proven_per_device_idx'
                ) IS NOT NULL
                AND to_regclass('public.devices_license_device_id_idx') IS NOT NULL
                AND to_regclass(
                    'public.device_challenges_subject_expiry_idx'
                ) IS NOT NULL
                AS schema_ready",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|error| database_error("postgres_readiness_schema", error))?;
        let schema_ready = row
            .try_get::<bool, _>("schema_ready")
            .map_err(|error| database_error("postgres_readiness_schema_decode", error))?;
        if !schema_ready {
            tracing::error!(
                recovery = "apply all PostgreSQL migrations before starting the production service",
                "postgres database schema is not ready"
            );
            return Err(ApiError::DatabaseSchemaNotReady);
        }

        let time_authority_ready = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (
                SELECT 1 FROM service_time_authority WHERE singleton = 1
            )",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|error| database_error("postgres_readiness_time_authority", error))?;
        if !time_authority_ready {
            tracing::error!(
                recovery =
                    "apply all PostgreSQL migrations or restore the time-authority singleton",
                "postgres time-authority state is not ready"
            );
            return Err(ApiError::DatabaseSchemaNotReady);
        }

        Ok(())
    }

    async fn observe_time_authority(
        &self,
        logical_unix: Option<i64>,
        max_forward_jump_seconds: i64,
    ) -> Result<TimeAuthorityObservation> {
        if max_forward_jump_seconds <= 0 || logical_unix.is_some_and(|value| value < 0) {
            return Err(ApiError::InvalidRequest);
        }
        let row = sqlx::query(
            "SELECT trusted_unix,
                    database_unix,
                    previous_high_water_unix,
                    authority_status,
                    status_changed
             FROM observe_service_time_authority($1, $2)",
        )
        .bind(logical_unix)
        .bind(max_forward_jump_seconds)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| ApiError::Database)?
        .ok_or(ApiError::Database)?;
        let trusted_unix = row
            .try_get::<i64, _>("trusted_unix")
            .map_err(|_| ApiError::Database)?;
        let database_unix = row
            .try_get::<i64, _>("database_unix")
            .map_err(|_| ApiError::Database)?;
        let previous_high_water_unix = row
            .try_get::<i64, _>("previous_high_water_unix")
            .map_err(|_| ApiError::Database)?;
        let status_name = row
            .try_get::<String, _>("authority_status")
            .map_err(|_| ApiError::Database)?;
        let status_changed = row
            .try_get::<bool, _>("status_changed")
            .map_err(|_| ApiError::Database)?;
        let status = time_authority_status_from_name(&status_name)?;

        match (status, status_changed) {
            (TimeAuthorityStatus::ForwardJump, true) => tracing::error!(
                previous_high_water_unix,
                database_unix,
                max_forward_jump_seconds,
                "database clock jumped beyond the configured safety limit; license operations are fail-closed"
            ),
            (TimeAuthorityStatus::RollbackHeld, true) => tracing::warn!(
                previous_high_water_unix,
                database_unix,
                "database clock moved backwards; persistent license time remains monotonic"
            ),
            (TimeAuthorityStatus::Healthy, true) => tracing::info!(
                trusted_unix,
                database_unix,
                "license time authority recovered"
            ),
            _ => {}
        }

        Ok(TimeAuthorityObservation {
            trusted_unix,
            database_unix,
            previous_high_water_unix,
            status,
        })
    }

    async fn close(&self) {
        self.pool.close().await;
    }

    async fn cleanup_expired(&self, now: i64, batch_size: u32) -> Result<CleanupReport> {
        let artifact_cutoff = now.saturating_sub(ONLINE_ARTIFACT_RETENTION_SECONDS);
        let session_cutoff = now.saturating_sub(SESSION_REPLAY_RETENTION_SECONDS);
        let batch_size = i64::from(batch_size.max(1));
        let challenges = sqlx::query(
            "DELETE FROM device_challenges
             WHERE challenge_id IN (
                 SELECT challenge_id FROM device_challenges
                 WHERE expires_at <= $1 ORDER BY expires_at ASC LIMIT $2
             )",
        )
        .bind(artifact_cutoff)
        .bind(batch_size)
        .execute(&self.pool)
        .await
        .map_err(|_| ApiError::Database)?
        .rows_affected();
        let authorization_codes = sqlx::query(
            "DELETE FROM authorization_codes
             WHERE code_hash IN (
                 SELECT code_hash FROM authorization_codes
                 WHERE expires_at <= $1 ORDER BY expires_at ASC LIMIT $2
             )",
        )
        .bind(artifact_cutoff)
        .bind(batch_size)
        .execute(&self.pool)
        .await
        .map_err(|_| ApiError::Database)?
        .rows_affected();
        let refresh_sessions = sqlx::query(
            "DELETE FROM refresh_sessions
             WHERE token_hash IN (
                 SELECT token_hash FROM refresh_sessions
                 WHERE (document ->> 'absolute_expires_at')::bigint <= $1
                 ORDER BY (document ->> 'absolute_expires_at')::bigint ASC
                 LIMIT $2
             )",
        )
        .bind(session_cutoff)
        .bind(batch_size)
        .execute(&self.pool)
        .await
        .map_err(|_| ApiError::Database)?
        .rows_affected();
        let rate_limit_cutoff = now.saturating_sub(RATE_LIMIT_RETENTION_SECONDS);
        let rate_limit_buckets = sqlx::query(
            "DELETE FROM rate_limit_buckets
             WHERE (scope, bucket_key) IN (
                 SELECT scope, bucket_key FROM rate_limit_buckets
                 WHERE window_started_at <= $1
                 ORDER BY window_started_at ASC LIMIT $2
             )",
        )
        .bind(rate_limit_cutoff)
        .bind(batch_size)
        .execute(&self.pool)
        .await
        .map_err(|_| ApiError::Database)?
        .rows_affected();
        let operation_cutoff = now.saturating_sub(PUBLIC_OPERATION_RETENTION_SECONDS);
        sqlx::query(
            "DELETE FROM device_removal_operations
             WHERE (account_id, operation_id) IN (
                 SELECT account_id, operation_id FROM device_removal_operations
                 WHERE created_at <= $1 ORDER BY created_at ASC LIMIT $2
             )",
        )
        .bind(operation_cutoff)
        .bind(batch_size)
        .execute(&self.pool)
        .await
        .map_err(|_| ApiError::Database)?;
        sqlx::query(
            "DELETE FROM team_operations
             WHERE (account_id, operation_id) IN (
                 SELECT account_id, operation_id FROM team_operations
                 WHERE completed_at <= $1 ORDER BY completed_at ASC LIMIT $2
             )",
        )
        .bind(operation_cutoff)
        .bind(batch_size)
        .execute(&self.pool)
        .await
        .map_err(|_| ApiError::Database)?;
        Ok(CleanupReport {
            challenges,
            authorization_codes,
            refresh_sessions,
            rate_limit_buckets,
        })
    }

    async fn consume_rate_limit(
        &self,
        scope: &str,
        key_hash: &str,
        now: i64,
        max_count: u32,
        window_seconds: i64,
    ) -> Result<bool> {
        if scope.is_empty() || key_hash.is_empty() || max_count == 0 || window_seconds <= 0 {
            return Err(ApiError::InvalidRequest);
        }
        let row = sqlx::query(
            "INSERT INTO rate_limit_buckets
                 (scope, bucket_key, window_started_at, request_count)
             VALUES ($1, $2, $3, 1)
             ON CONFLICT (scope, bucket_key) DO UPDATE
             SET window_started_at = CASE
                     WHEN $3 - rate_limit_buckets.window_started_at >= $5 THEN $3
                     ELSE rate_limit_buckets.window_started_at
                 END,
                 request_count = CASE
                     WHEN $3 - rate_limit_buckets.window_started_at >= $5 THEN 1
                     ELSE rate_limit_buckets.request_count + 1
                 END,
                 updated_at = now()
             WHERE $3 - rate_limit_buckets.window_started_at >= $5
                OR rate_limit_buckets.request_count < $4
             RETURNING request_count",
        )
        .bind(scope)
        .bind(key_hash)
        .bind(now.max(0))
        .bind(i64::from(max_count))
        .bind(window_seconds)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| ApiError::Database)?;
        Ok(row.is_some())
    }

    async fn upsert_account(&self, account: Account) -> Result<()> {
        sqlx::query(
            "INSERT INTO accounts (id, document) VALUES ($1, $2)
             ON CONFLICT (id) DO UPDATE SET document = EXCLUDED.document, updated_at = now()",
        )
        .bind(&account.id)
        .bind(json(&account)?)
        .execute(&self.pool)
        .await
        .map_err(|_| ApiError::Database)?;
        Ok(())
    }

    async fn account(&self, account_id: &str) -> Result<Option<Account>> {
        let row = sqlx::query("SELECT document FROM accounts WHERE id = $1")
            .bind(account_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|_| ApiError::Database)?;
        row.map(row_document).transpose()
    }

    async fn upsert_license(&self, license: License) -> Result<()> {
        sqlx::query(
            "INSERT INTO licenses
                (id, account_id, plan, plan_revision, status, expires_at,
                 license_epoch, purchased_seats, row_version)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
             ON CONFLICT (id) DO UPDATE
             SET account_id = EXCLUDED.account_id,
                 plan = EXCLUDED.plan,
                 plan_revision = EXCLUDED.plan_revision,
                 status = EXCLUDED.status,
                 expires_at = EXCLUDED.expires_at,
                 license_epoch = EXCLUDED.license_epoch,
                 purchased_seats = EXCLUDED.purchased_seats,
                 row_version = EXCLUDED.row_version,
                 updated_at = now()",
        )
        .bind(&license.id)
        .bind(&license.account_id)
        .bind(plan_name(license.plan))
        .bind(i32::try_from(license.plan_revision).map_err(|_| ApiError::InvalidRequest)?)
        .bind(license_status_name(license.status))
        .bind(license.expires_at)
        .bind(i64::try_from(license.license_epoch).map_err(|_| ApiError::InvalidRequest)?)
        .bind(i32::try_from(license.purchased_seats).map_err(|_| ApiError::InvalidRequest)?)
        .bind(i64::try_from(license.row_version).map_err(|_| ApiError::InvalidRequest)?)
        .execute(&self.pool)
        .await
        .map_err(|_| ApiError::Database)?;
        Ok(())
    }

    async fn license(&self, license_id: &str) -> Result<Option<License>> {
        let row = sqlx::query(
            "SELECT id, account_id, plan, plan_revision, status, expires_at,
                    license_epoch, purchased_seats, row_version
             FROM licenses WHERE id = $1",
        )
        .bind(license_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| ApiError::Database)?;
        row.map(row_license).transpose()
    }

    async fn license_for_account(&self, account_id: &str) -> Result<Option<License>> {
        let row = sqlx::query(
            "SELECT id, account_id, plan, plan_revision, status, expires_at,
                    license_epoch, purchased_seats, row_version
             FROM licenses WHERE account_id = $1",
        )
        .bind(account_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| ApiError::Database)?;
        row.map(row_license).transpose()
    }

    async fn upsert_device(&self, device: Device) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(|_| ApiError::Database)?;
        lock_license(&mut tx, &device.license_id).await?;
        lock_device(&mut tx, &device.metadata.device_id).await?;
        let account = account_for_share(&mut tx, &device.account_id).await?;
        ensure_account_is_active(&account)?;
        let license = license_for_share(&mut tx, &device.license_id).await?;
        if license.account_id != device.account_id {
            return Err(ApiError::LicenseUnavailable);
        }
        ensure_license_is_usable(&license, device.last_seen_at.unwrap_or(device.created_at))?;
        if device.state == DeviceState::PendingActivation {
            let now = device.last_seen_at.unwrap_or(device.created_at);
            let occupied: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM devices
                 WHERE license_id = $1 AND device_id <> $2
                   AND (
                       state = 'active'
                       OR (
                           state = 'pending_activation'
                           AND (document ->> 'pending_activation_expires_at')::BIGINT > $3
                       )
                   )",
            )
            .bind(&device.license_id)
            .bind(&device.metadata.device_id)
            .bind(now)
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| ApiError::Database)?;
            if occupied >= i64::from(license.effective_policy()?.device_limit) {
                return Err(ApiError::ActivationLimitReached);
            }
        }
        let updated = sqlx::query(
            "INSERT INTO devices (device_id, account_id, license_id, state, document)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (device_id) DO UPDATE
             SET account_id = EXCLUDED.account_id,
                 license_id = EXCLUDED.license_id,
                 state = EXCLUDED.state,
                 document = EXCLUDED.document,
                 updated_at = now()
             WHERE devices.account_id = EXCLUDED.account_id
               AND devices.license_id = EXCLUDED.license_id
               AND devices.document #>> '{metadata,publicKeyThumbprint}' = $6
               AND devices.state NOT IN ('revoked', 'suspicious')",
        )
        .bind(&device.metadata.device_id)
        .bind(&device.account_id)
        .bind(&device.license_id)
        .bind(device_state(&device.state))
        .bind(json(&device)?)
        .bind(&device.metadata.public_key_thumbprint)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?
        .rows_affected();
        if updated != 1 {
            let existing = device_for_update(&mut tx, &device.metadata.device_id).await?;
            return Err(
                if matches!(
                    existing.state,
                    DeviceState::Revoked | DeviceState::Suspicious
                ) {
                    ApiError::DeviceStateDenied(existing.state)
                } else {
                    ApiError::DeviceDenied
                },
            );
        }
        tx.commit().await.map_err(|_| ApiError::Database)
    }

    async fn register_device_session_with_audit(
        &self,
        device: Device,
        session: RefreshSessionRecord,
        expected_device_state: Option<DeviceState>,
        authorization: AuthorizationCodeRedemption,
        now: i64,
        audit: AuditEventRecord,
    ) -> Result<()> {
        validate_initial_registration_bundle(
            &device,
            &session,
            expected_device_state,
            now,
            &audit,
        )?;
        if !session.active
            || session.expires_at <= now
            || session.absolute_expires_at <= now
            || session.family_created_at > now
            || session.expires_at > session.absolute_expires_at
            || session.device_id != device.metadata.device_id
            || session.account_id != device.account_id
        {
            return Err(ApiError::InvalidRequest);
        }
        ensure_session_device_state(&device, session.proof_state)?;

        let mut tx = self.pool.begin().await.map_err(|_| ApiError::Database)?;
        lock_license(&mut tx, &device.license_id).await?;
        lock_device(&mut tx, &device.metadata.device_id).await?;
        let existing = sqlx::query("SELECT document FROM devices WHERE device_id = $1 FOR UPDATE")
            .bind(&device.metadata.device_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|_| ApiError::Database)?
            .map(row_document)
            .transpose()?;
        ensure_expected_device_state(existing.as_ref(), expected_device_state)?;
        if let Some(existing) = &existing {
            if existing.account_id != device.account_id
                || existing.license_id != device.license_id
                || existing.metadata.public_key_thumbprint != device.metadata.public_key_thumbprint
            {
                return Err(ApiError::DeviceDenied);
            }
            if matches!(
                existing.state,
                DeviceState::Revoked | DeviceState::Suspicious
            ) {
                return Err(ApiError::DeviceStateDenied(existing.state));
            }
        }
        let account = account_for_share(&mut tx, &device.account_id).await?;
        ensure_account_is_active(&account)?;
        let license = license_for_share(&mut tx, &device.license_id).await?;
        if license.account_id != device.account_id {
            return Err(ApiError::LicenseUnavailable);
        }
        ensure_license_is_usable(&license, now)?;
        let row =
            sqlx::query("SELECT document FROM authorization_codes WHERE code_hash = $1 FOR UPDATE")
                .bind(&authorization.code_hash)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|_| ApiError::Database)?
                .ok_or(ApiError::AuthorizationRequired)?;
        let mut authorization_code: StoredAuthorizationCode = row_document(row)?;
        validate_authorization_redemption(
            &authorization_code,
            &authorization,
            &device,
            session.pending_activation_code_hash.as_deref(),
            now,
        )?;
        if let Some(activation_code_hash) = session.pending_activation_code_hash.as_deref() {
            let row =
                sqlx::query("SELECT document FROM activation_codes WHERE code_hash = $1 FOR SHARE")
                    .bind(activation_code_hash)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(|_| ApiError::Database)?
                    .ok_or(ApiError::ActivationCodeInvalid)?;
            let code: ActivationCodeRecord = row_document(row)?;
            if code.account_id != device.account_id
                || code
                    .license_id
                    .as_ref()
                    .is_some_and(|license_id| license_id != &device.license_id)
            {
                return Err(ApiError::ActivationCodeInvalid);
            }
            if !code.is_usable(now) {
                return Err(activation_code_error(&code, now));
            }
        }
        let previously_occupied = existing
            .as_ref()
            .is_some_and(|existing| device_occupies_activation_slot(existing, now));
        if device_occupies_activation_slot(&device, now) && !previously_occupied {
            let occupied: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM devices
                 WHERE license_id = $1 AND device_id <> $2
                   AND (
                       state = 'active'
                       OR (
                           state = 'pending_activation'
                           AND (document ->> 'pending_activation_expires_at')::BIGINT > $3
                       )
                   )",
            )
            .bind(&device.license_id)
            .bind(&device.metadata.device_id)
            .bind(now)
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| ApiError::Database)?;
            if occupied >= i64::from(license.effective_policy()?.device_limit) {
                return Err(ApiError::ActivationLimitReached);
            }
        }
        let updated = sqlx::query(
            "INSERT INTO devices (device_id, account_id, license_id, state, document)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (device_id) DO UPDATE
             SET account_id = EXCLUDED.account_id,
                 license_id = EXCLUDED.license_id,
                 state = EXCLUDED.state,
                 document = EXCLUDED.document,
                 updated_at = now()
             WHERE devices.account_id = EXCLUDED.account_id
               AND devices.license_id = EXCLUDED.license_id
               AND devices.document #>> '{metadata,publicKeyThumbprint}' = $6
               AND devices.state NOT IN ('revoked', 'suspicious')",
        )
        .bind(&device.metadata.device_id)
        .bind(&device.account_id)
        .bind(&device.license_id)
        .bind(device_state(&device.state))
        .bind(json(&device)?)
        .bind(&device.metadata.public_key_thumbprint)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?
        .rows_affected();
        if updated != 1 {
            let existing = device_for_update(&mut tx, &device.metadata.device_id).await?;
            return Err(
                if matches!(
                    existing.state,
                    DeviceState::Revoked | DeviceState::Suspicious
                ) {
                    ApiError::DeviceStateDenied(existing.state)
                } else {
                    ApiError::DeviceDenied
                },
            );
        }
        sqlx::query(
            "UPDATE refresh_sessions
             SET active = false,
                 document = jsonb_set(document, '{active}', 'false'::jsonb, true),
                 updated_at = now()
             WHERE device_id = $1
               AND ($2 = 'device_proven' OR proof_state = 'unproven')",
        )
        .bind(&session.device_id)
        .bind(session_proof_state(session.proof_state))
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        sqlx::query(
            "INSERT INTO refresh_sessions
             (token_hash, device_id, family_id, proof_state, active, expires_at, document)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(&session.token_hash)
        .bind(&session.device_id)
        .bind(&session.family_id)
        .bind(session_proof_state(session.proof_state))
        .bind(session.active)
        .bind(session.expires_at)
        .bind(json(&session)?)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        if !authorization_code.consumed {
            authorization_code.consumed = true;
            authorization_code.consumed_at = Some(now);
            authorization_code.consumed_device_id = Some(device.metadata.device_id.clone());
            authorization_code.consumed_key_thumbprint =
                Some(device.metadata.public_key_thumbprint.clone());
        }
        sqlx::query(
            "UPDATE authorization_codes
             SET consumed = true, document = $2, updated_at = now()
             WHERE code_hash = $1",
        )
        .bind(&authorization.code_hash)
        .bind(json(&authorization_code)?)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        insert_audit_event_transaction(&mut tx, &audit).await?;
        tx.commit().await.map_err(|_| ApiError::Database)
    }

    async fn device(&self, device_id: &str) -> Result<Option<Device>> {
        let row = sqlx::query("SELECT document FROM devices WHERE device_id = $1")
            .bind(device_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|_| ApiError::Database)?;
        row.map(row_document).transpose()
    }

    async fn devices_for_license_page(
        &self,
        license_id: &str,
        after_device_id: Option<&str>,
        limit: u32,
    ) -> Result<Vec<Device>> {
        let rows = if let Some(after_device_id) = after_device_id {
            sqlx::query(
                "SELECT document FROM devices
                 WHERE license_id = $1
                   AND state <> 'removed'
                   AND device_id COLLATE \"C\" > $2::TEXT COLLATE \"C\"
                 ORDER BY device_id COLLATE \"C\" ASC
                 LIMIT $3",
            )
            .bind(license_id)
            .bind(after_device_id)
            .bind(i64::from(limit))
            .fetch_all(&self.pool)
            .await
        } else {
            sqlx::query(
                "SELECT document FROM devices
                 WHERE license_id = $1
                   AND state <> 'removed'
                 ORDER BY device_id COLLATE \"C\" ASC
                 LIMIT $2",
            )
            .bind(license_id)
            .bind(i64::from(limit))
            .fetch_all(&self.pool)
            .await
        }
        .map_err(|_| ApiError::Database)?;
        rows.into_iter().map(row_document).collect()
    }

    async fn set_device_state(&self, device_id: &str, state: DeviceState, now: i64) -> Result<()> {
        let mut device = self
            .device(device_id)
            .await?
            .ok_or(ApiError::DeviceDenied)?;
        device.state = state;
        device.last_seen_at = Some(now);
        sqlx::query(
            "UPDATE devices SET state = $2, document = $3, updated_at = now() WHERE device_id = $1",
        )
        .bind(device_id)
        .bind(device_state(&state))
        .bind(json(&device)?)
        .execute(&self.pool)
        .await
        .map_err(|_| ApiError::Database)?;
        Ok(())
    }

    async fn touch_device_last_seen(
        &self,
        device_id: &str,
        now: i64,
        minimum_interval_seconds: i64,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE devices
             SET document = jsonb_set(document, '{last_seen_at}', to_jsonb($2::BIGINT), true),
                 updated_at = now()
             WHERE device_id = $1
               AND COALESCE((document ->> 'last_seen_at')::BIGINT, 0) <= $3",
        )
        .bind(device_id)
        .bind(now)
        .bind(now.saturating_sub(minimum_interval_seconds.max(0)))
        .execute(&self.pool)
        .await
        .map_err(|_| ApiError::Database)?;
        Ok(())
    }

    async fn update_device_client_metadata(
        &self,
        device_id: &str,
        app_version: &str,
        now: i64,
    ) -> Result<()> {
        let updated = sqlx::query(
            "UPDATE devices
             SET document = jsonb_set(
                     jsonb_set(
                         document,
                         '{metadata,appVersion}',
                         CASE
                             WHEN COALESCE((document ->> 'last_seen_at')::BIGINT, 0) <= $3
                             THEN to_jsonb($2::TEXT)
                             ELSE document #> '{metadata,appVersion}'
                         END,
                         true
                     ),
                     '{last_seen_at}',
                     to_jsonb(GREATEST(COALESCE((document ->> 'last_seen_at')::BIGINT, $3), $3)),
                     true
                 ),
                 updated_at = now()
             WHERE device_id = $1",
        )
        .bind(device_id)
        .bind(app_version)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|_| ApiError::Database)?
        .rows_affected();
        if updated == 1 {
            Ok(())
        } else {
            Err(ApiError::DeviceDenied)
        }
    }

    async fn insert_session(&self, session: RefreshSessionRecord) -> Result<()> {
        sqlx::query(
            "INSERT INTO refresh_sessions
             (token_hash, device_id, family_id, proof_state, active, expires_at, document)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(&session.token_hash)
        .bind(&session.device_id)
        .bind(&session.family_id)
        .bind(session_proof_state(session.proof_state))
        .bind(session.active)
        .bind(session.expires_at)
        .bind(json(&session)?)
        .execute(&self.pool)
        .await
        .map_err(|_| ApiError::Database)?;
        Ok(())
    }

    async fn replace_device_sessions_with_audit(
        &self,
        session: RefreshSessionRecord,
        now: i64,
        audit: AuditEventRecord,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(|_| ApiError::Database)?;
        lock_device(&mut tx, &session.device_id).await?;
        let device = device_for_update(&mut tx, &session.device_id).await?;
        if device.account_id != session.account_id {
            return Err(ApiError::DeviceDenied);
        }
        ensure_session_device_state(&device, session.proof_state)?;
        let account = account_for_share(&mut tx, &device.account_id).await?;
        ensure_account_is_active(&account)?;
        let license = license_for_share(&mut tx, &device.license_id).await?;
        if license.account_id != device.account_id {
            return Err(ApiError::LicenseUnavailable);
        }
        ensure_license_is_usable(&license, now)?;
        validate_session_success_audit(&audit, "session_recovered", &session, &device, now)?;
        sqlx::query(
            "UPDATE refresh_sessions
             SET active = false,
                 document = jsonb_set(document, '{active}', 'false'::jsonb, true),
                 updated_at = now()
             WHERE device_id = $1
               AND ($2 = 'device_proven' OR proof_state = 'unproven')",
        )
        .bind(&session.device_id)
        .bind(session_proof_state(session.proof_state))
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        sqlx::query(
            "INSERT INTO refresh_sessions
             (token_hash, device_id, family_id, proof_state, active, expires_at, document)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(&session.token_hash)
        .bind(&session.device_id)
        .bind(&session.family_id)
        .bind(session_proof_state(session.proof_state))
        .bind(session.active)
        .bind(session.expires_at)
        .bind(json(&session)?)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        insert_audit_event_transaction(&mut tx, &audit).await?;
        tx.commit().await.map_err(|_| ApiError::Database)
    }

    async fn session_by_hash(&self, token_hash: &str) -> Result<Option<RefreshSessionRecord>> {
        let row = sqlx::query(
            "SELECT document, family_id, active, expires_at
             FROM refresh_sessions WHERE token_hash = $1",
        )
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| ApiError::Database)?;
        row.map(|row| {
            let family_id = row
                .try_get::<String, _>("family_id")
                .map_err(|_| ApiError::Database)?;
            let active = row
                .try_get::<bool, _>("active")
                .map_err(|_| ApiError::Database)?;
            let expires_at = row
                .try_get::<i64, _>("expires_at")
                .map_err(|_| ApiError::Database)?;
            let mut session: RefreshSessionRecord = row_document(row)?;
            session.family_id = family_id;
            session.active = active;
            session.expires_at = expires_at;
            Ok(session)
        })
        .transpose()
    }

    async fn rotate_session_with_audit(
        &self,
        old_hash: &str,
        new_session: RefreshSessionRecord,
        now: i64,
        audit: AuditEventRecord,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(|_| ApiError::Database)?;
        let initial = session_in_transaction(&mut tx, old_hash)
            .await?
            .ok_or(ApiError::AuthorizationRequired)?;
        lock_device(&mut tx, &initial.device_id).await?;
        let mut previous = session_for_update(&mut tx, old_hash)
            .await?
            .ok_or(ApiError::AuthorizationRequired)?;
        let retry_successor = if !previous.active
            && previous
                .rotated_at
                .is_some_and(|rotated_at| rotated_at.saturating_add(60) >= now)
        {
            if let Some(successor_hash) = previous.rotated_to_hash.as_deref() {
                session_for_update(&mut tx, successor_hash)
                    .await?
                    .filter(|successor| {
                        successor.active
                            && successor.expires_at > now
                            && successor.absolute_expires_at > now
                            && successor.rotated_to_hash.is_none()
                            && successor.family_id == previous.family_id
                            && successor.device_id == previous.device_id
                    })
            } else {
                None
            }
        } else {
            None
        };
        if (!previous.active && retry_successor.is_none())
            || previous.expires_at <= now
            || previous.absolute_expires_at <= now
        {
            sqlx::query(
                "UPDATE refresh_sessions
                 SET active = false,
                     document = jsonb_set(document, '{active}', 'false'::jsonb, true),
                     updated_at = now()
                 WHERE family_id = $1",
            )
            .bind(&previous.family_id)
            .execute(&mut *tx)
            .await
            .map_err(|_| ApiError::Database)?;
            tx.commit().await.map_err(|_| ApiError::Database)?;
            return Err(if previous.active {
                ApiError::AuthorizationRequired
            } else {
                ApiError::RefreshSessionReused
            });
        }
        if initial.device_id != previous.device_id {
            return Err(ApiError::AuthorizationRequired);
        }
        if new_session.family_id != previous.family_id
            || new_session.account_id != previous.account_id
            || new_session.device_id != previous.device_id
            || new_session.family_created_at != previous.family_created_at
            || new_session.absolute_expires_at != previous.absolute_expires_at
            || new_session.expires_at > previous.absolute_expires_at
            || new_session.proof_state != RefreshSessionProofState::DeviceProven
        {
            return Err(ApiError::InvalidRequest);
        }
        let device = device_for_update(&mut tx, &previous.device_id).await?;
        let event_type = if new_session.activation_verified_at == Some(now) {
            "activation_proof_issued"
        } else if new_session.activation_verified_at.is_none() {
            "entitlement_refreshed"
        } else {
            return Err(ApiError::InvalidRequest);
        };
        validate_session_success_audit(&audit, event_type, &previous, &device, now)?;
        if previous.proof_state == RefreshSessionProofState::Unproven
            && new_session.proof_state == RefreshSessionProofState::DeviceProven
        {
            sqlx::query(
                "UPDATE refresh_sessions
                 SET active = false,
                     document = jsonb_set(document, '{active}', 'false'::jsonb, true),
                     updated_at = now()
                 WHERE device_id = $1 AND token_hash <> $2",
            )
            .bind(&previous.device_id)
            .bind(old_hash)
            .execute(&mut *tx)
            .await
            .map_err(|_| ApiError::Database)?;
        }
        previous.active = false;
        previous.rotated_to_hash = Some(new_session.token_hash.clone());
        previous.rotated_at = Some(now);
        if let Some(successor) = retry_successor {
            sqlx::query(
                "UPDATE refresh_sessions
                 SET active = false,
                     document = jsonb_set(document, '{active}', 'false'::jsonb, true),
                     updated_at = now()
                 WHERE token_hash = $1",
            )
            .bind(&successor.token_hash)
            .execute(&mut *tx)
            .await
            .map_err(|_| ApiError::Database)?;
        }
        sqlx::query(
            "UPDATE refresh_sessions
             SET active = false, document = $2, updated_at = now()
             WHERE token_hash = $1",
        )
        .bind(old_hash)
        .bind(json(&previous)?)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        sqlx::query(
            "INSERT INTO refresh_sessions
             (token_hash, device_id, family_id, proof_state, active, expires_at, document)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(&new_session.token_hash)
        .bind(&new_session.device_id)
        .bind(&new_session.family_id)
        .bind(session_proof_state(new_session.proof_state))
        .bind(new_session.active)
        .bind(new_session.expires_at)
        .bind(json(&new_session)?)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        insert_audit_event_transaction(&mut tx, &audit).await?;
        tx.commit().await.map_err(|_| ApiError::Database)
    }

    async fn revoke_session_family(&self, family_id: &str) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(|_| ApiError::Database)?;
        let device_id: Option<String> = sqlx::query_scalar(
            "SELECT device_id FROM refresh_sessions
             WHERE family_id = $1 LIMIT 1",
        )
        .bind(family_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        let Some(device_id) = device_id else {
            tx.commit().await.map_err(|_| ApiError::Database)?;
            return Ok(());
        };
        lock_device(&mut tx, &device_id).await?;
        sqlx::query(
            "UPDATE refresh_sessions
             SET active = false,
                 document = jsonb_set(document, '{active}', 'false'::jsonb, true),
                 updated_at = now()
             WHERE family_id = $1",
        )
        .bind(family_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        tx.commit().await.map_err(|_| ApiError::Database)
    }

    async fn revoke_sessions_for_device(&self, device_id: &str) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(|_| ApiError::Database)?;
        lock_device(&mut tx, device_id).await?;
        sqlx::query(
            "UPDATE refresh_sessions
             SET active = false,
                 document = jsonb_set(document, '{active}', 'false'::jsonb, true),
                 updated_at = now()
             WHERE device_id = $1",
        )
        .bind(device_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        tx.commit().await.map_err(|_| ApiError::Database)
    }

    async fn device_removal_replayed(
        &self,
        account_id: &str,
        requester_session_hash: &str,
        requester_device_id: &str,
        target_device_id: &str,
        operation_id: &str,
    ) -> Result<bool> {
        let row: Option<(String, String, String)> = sqlx::query_as(
            "SELECT requester_session_hash, requester_device_id, target_device_id
             FROM device_removal_operations
             WHERE account_id = $1 AND operation_id = $2",
        )
        .bind(account_id)
        .bind(operation_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| ApiError::Database)?;
        let Some((stored_session_hash, stored_requester, stored_target)) = row else {
            return Ok(false);
        };
        if stored_session_hash != requester_session_hash
            || stored_requester != requester_device_id
            || stored_target != target_device_id
        {
            return Err(ApiError::IdempotencyConflict);
        }
        Ok(true)
    }

    async fn remove_device_with_audit(
        &self,
        requester_session_hash: &str,
        requester_device_id: &str,
        target_device_id: &str,
        operation_id: &str,
        now: i64,
        audit: AuditEventRecord,
    ) -> Result<bool> {
        let mut tx = self.pool.begin().await.map_err(|_| ApiError::Database)?;
        let initial_session = session_in_transaction(&mut tx, requester_session_hash)
            .await?
            .ok_or(ApiError::AuthorizationRequired)?;
        if initial_session.device_id != requester_device_id {
            return Err(ApiError::AuthorizationRequired);
        }
        let operation_lock = format!("{}:{operation_id}", initial_session.account_id);
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 7162026))")
            .bind(operation_lock)
            .execute(&mut *tx)
            .await
            .map_err(|_| ApiError::Database)?;
        let existing_operation: Option<(String, String, String)> = sqlx::query_as(
            "SELECT requester_session_hash, requester_device_id, target_device_id
             FROM device_removal_operations
             WHERE account_id = $1 AND operation_id = $2 FOR UPDATE",
        )
        .bind(&initial_session.account_id)
        .bind(operation_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        if let Some((stored_session_hash, stored_requester, stored_target)) = existing_operation {
            if stored_session_hash != requester_session_hash
                || stored_requester != requester_device_id
                || stored_target != target_device_id
            {
                return Err(ApiError::IdempotencyConflict);
            }
            tx.commit().await.map_err(|_| ApiError::Database)?;
            return Ok(false);
        }
        lock_devices(&mut tx, requester_device_id, target_device_id).await?;
        let requester = device_for_update(&mut tx, requester_device_id).await?;
        let mut target = if requester_device_id == target_device_id {
            requester.clone()
        } else {
            device_for_update(&mut tx, target_device_id).await?
        };
        let requester_session = session_for_update(&mut tx, requester_session_hash)
            .await?
            .ok_or(ApiError::AuthorizationRequired)?;
        ensure_active_proven_session(&requester_session, &requester, now)?;
        let account = account_for_share(&mut tx, &requester.account_id).await?;
        ensure_account_is_active(&account)?;
        if requester.state != DeviceState::Active {
            return Err(ApiError::DeviceStateDenied(requester.state));
        }
        if target.account_id != requester.account_id || target.license_id != requester.license_id {
            return Err(ApiError::DeviceDenied);
        }
        if matches!(target.state, DeviceState::Revoked | DeviceState::Suspicious) {
            return Err(ApiError::DeviceStateDenied(target.state));
        }
        let plan: String = sqlx::query_scalar("SELECT plan FROM licenses WHERE id = $1 FOR SHARE")
            .bind(&requester.license_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| ApiError::Database)?;
        if plan == "team" {
            let requester_member: Option<(String, String, String)> = sqlx::query_as(
                "SELECT members.id, members.role, members.status
                 FROM device_member_bindings AS bindings
                 JOIN workspace_members AS members
                   ON members.account_id = bindings.account_id
                  AND members.id = bindings.member_id
                 WHERE bindings.account_id = $1 AND bindings.device_id = $2
                 FOR SHARE OF members",
            )
            .bind(&requester.account_id)
            .bind(requester_device_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|_| ApiError::Database)?;
            let target_member: Option<(String, String, String)> = sqlx::query_as(
                "SELECT members.id, members.role, members.status
                 FROM device_member_bindings AS bindings
                 JOIN workspace_members AS members
                   ON members.account_id = bindings.account_id
                  AND members.id = bindings.member_id
                 WHERE bindings.account_id = $1 AND bindings.device_id = $2
                 FOR SHARE OF members",
            )
            .bind(&requester.account_id)
            .bind(target_device_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|_| ApiError::Database)?;
            if requester_device_id != target_device_id {
                let (requester_member_id, requester_role, requester_status) = requester_member
                    .as_ref()
                    .ok_or(ApiError::PermissionDenied)?;
                if requester_status != "active" {
                    return Err(ApiError::PermissionDenied);
                }
                let same_member = target_member
                    .as_ref()
                    .is_some_and(|(target_member_id, _, _)| {
                        target_member_id == requester_member_id
                    });
                let target_is_owner = target_member
                    .as_ref()
                    .is_some_and(|(_, role, _)| role == "owner");
                if !same_member
                    && requester_role != "owner"
                    && !(requester_role == "admin" && !target_is_owner)
                {
                    return Err(ApiError::PermissionDenied);
                }
            }
            if target_member
                .as_ref()
                .is_some_and(|(_, role, status)| role == "owner" && status == "active")
            {
                let owner_active_devices: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*)
                     FROM device_member_bindings AS bindings
                     JOIN workspace_members AS members
                       ON members.account_id = bindings.account_id
                      AND members.id = bindings.member_id
                     JOIN devices
                       ON devices.account_id = bindings.account_id
                      AND devices.device_id = bindings.device_id
                     WHERE bindings.account_id = $1
                       AND members.role = 'owner' AND members.status = 'active'
                       AND devices.state = 'active'",
                )
                .bind(&requester.account_id)
                .fetch_one(&mut *tx)
                .await
                .map_err(|_| ApiError::Database)?;
                if owner_active_devices <= 1 {
                    return Err(ApiError::PermissionDenied);
                }
            }
        }
        validate_device_removal_audit(&audit, &requester, target_device_id)?;
        if target.state == DeviceState::Removed {
            sqlx::query(
                "DELETE FROM device_member_bindings
                 WHERE account_id = $1 AND device_id = $2",
            )
            .bind(&requester.account_id)
            .bind(target_device_id)
            .execute(&mut *tx)
            .await
            .map_err(|_| ApiError::Database)?;
            insert_device_removal_operation(
                &mut tx,
                &requester.account_id,
                requester_session_hash,
                requester_device_id,
                target_device_id,
                operation_id,
                now,
            )
            .await?;
            tx.commit().await.map_err(|_| ApiError::Database)?;
            return Ok(false);
        }

        target.state = DeviceState::Removed;
        target.last_seen_at = Some(now);
        sqlx::query(
            "UPDATE devices SET state = 'removed', document = $2, updated_at = now()
             WHERE device_id = $1",
        )
        .bind(target_device_id)
        .bind(json(&target)?)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        revoke_device_sessions_transaction(&mut tx, target_device_id).await?;
        sqlx::query(
            "DELETE FROM device_member_bindings
             WHERE account_id = $1 AND device_id = $2",
        )
        .bind(&requester.account_id)
        .bind(target_device_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        insert_audit_event_transaction(&mut tx, &audit).await?;
        insert_device_removal_operation(
            &mut tx,
            &requester.account_id,
            requester_session_hash,
            requester_device_id,
            target_device_id,
            operation_id,
            now,
        )
        .await?;
        tx.commit().await.map_err(|_| ApiError::Database)?;
        Ok(true)
    }

    async fn logout_device_sessions_with_audit(
        &self,
        token_hash: &str,
        now: i64,
        audit: AuditEventRecord,
    ) -> Result<Option<RefreshSessionRecord>> {
        let mut tx = self.pool.begin().await.map_err(|_| ApiError::Database)?;
        let Some(initial) = session_in_transaction(&mut tx, token_hash).await? else {
            return Ok(None);
        };
        lock_device(&mut tx, &initial.device_id).await?;
        let Some(record) = session_for_update(&mut tx, token_hash).await? else {
            return Ok(None);
        };
        if !record.active || record.expires_at <= now || record.absolute_expires_at <= now {
            tx.commit().await.map_err(|_| ApiError::Database)?;
            return Ok(None);
        }
        validate_logout_audit(&audit, &record)?;
        revoke_device_sessions_transaction(&mut tx, &record.device_id).await?;
        insert_audit_event_transaction(&mut tx, &audit).await?;
        tx.commit().await.map_err(|_| ApiError::Database)?;
        Ok(Some(record))
    }

    async fn insert_challenge(&self, challenge: StoredChallenge) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(|_| ApiError::Database)?;
        sqlx::query(
            "DELETE FROM device_challenges
             WHERE challenge_id IN (
                 SELECT challenge_id FROM device_challenges
                 WHERE expires_at <= $1 ORDER BY expires_at ASC LIMIT $2
             )",
        )
        .bind(challenge.issued_at)
        .bind(CHALLENGE_INSERT_PRUNE_BATCH_SIZE)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        sqlx::query(
            "INSERT INTO device_challenges
             (challenge_id, device_id, expires_at, consumed, document)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(&challenge.challenge_id)
        .bind(&challenge.device_id)
        .bind(challenge.expires_at)
        .bind(challenge.consumed)
        .bind(json(&challenge)?)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        tx.commit().await.map_err(|_| ApiError::Database)
    }

    async fn consume_challenge(
        &self,
        challenge_id: &str,
        device_id: &str,
        now: i64,
    ) -> Result<StoredChallenge> {
        let mut tx = self.pool.begin().await.map_err(|_| ApiError::Database)?;
        let row = sqlx::query(
            "SELECT document FROM device_challenges
             WHERE challenge_id = $1 AND device_id = $2 FOR UPDATE",
        )
        .bind(challenge_id)
        .bind(device_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?
        .ok_or(ApiError::InvalidChallenge)?;
        let mut challenge: StoredChallenge = row_document(row)?;
        if challenge.expires_at <= now {
            return Err(ApiError::InvalidChallenge);
        }
        if challenge.consumed {
            return Err(ApiError::ChallengeReplay);
        }
        challenge.consumed = true;
        sqlx::query(
            "UPDATE device_challenges
             SET consumed = true, document = $2, updated_at = now()
             WHERE challenge_id = $1",
        )
        .bind(challenge_id)
        .bind(json(&challenge)?)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        tx.commit().await.map_err(|_| ApiError::Database)?;
        Ok(challenge)
    }

    async fn insert_authorization_code_with_audit(
        &self,
        code: StoredAuthorizationCode,
        audit: AuditEventRecord,
    ) -> Result<()> {
        validate_authorization_code_audit(&audit, &code)?;
        let mut tx = self.pool.begin().await.map_err(|_| ApiError::Database)?;
        sqlx::query(
            "INSERT INTO authorization_codes
             (code_hash, account_id, license_id, activation_code_hash, expires_at, consumed, document)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(&code.code_hash)
        .bind(&code.account_id)
        .bind(&code.license_id)
        .bind(&code.activation_code_hash)
        .bind(code.expires_at)
        .bind(code.consumed)
        .bind(json(&code)?)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        insert_audit_event_transaction(&mut tx, &audit).await?;
        tx.commit().await.map_err(|_| ApiError::Database)
    }

    async fn authorization_code_by_hash(
        &self,
        code_hash: &str,
    ) -> Result<Option<StoredAuthorizationCode>> {
        let row = sqlx::query("SELECT document FROM authorization_codes WHERE code_hash = $1")
            .bind(code_hash)
            .fetch_optional(&self.pool)
            .await
            .map_err(|_| ApiError::Database)?;
        row.map(row_document).transpose()
    }

    async fn upsert_activation_code(&self, code: ActivationCodeRecord) -> Result<()> {
        sqlx::query(
            "INSERT INTO activation_codes
             (code_hash, code_prefix, account_id, license_id, status, expires_at, consumed,
              consumed_at, consumed_device_id, document)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
             ON CONFLICT (code_hash) DO UPDATE
             SET code_prefix = EXCLUDED.code_prefix,
                 account_id = EXCLUDED.account_id,
                 license_id = EXCLUDED.license_id,
                 status = EXCLUDED.status,
                 expires_at = EXCLUDED.expires_at,
                 consumed = EXCLUDED.consumed,
                 consumed_at = EXCLUDED.consumed_at,
                 consumed_device_id = EXCLUDED.consumed_device_id,
                 document = EXCLUDED.document,
                 updated_at = now()",
        )
        .bind(&code.code_hash)
        .bind(&code.code_prefix)
        .bind(&code.account_id)
        .bind(&code.license_id)
        .bind(activation_code_status(&code.status))
        .bind(code.expires_at)
        .bind(code.status == ActivationCodeStatus::Consumed)
        .bind(code.consumed_at)
        .bind(&code.consumed_device_id)
        .bind(json(&code)?)
        .execute(&self.pool)
        .await
        .map_err(|_| ApiError::Database)?;
        Ok(())
    }

    async fn activation_code_by_hash(
        &self,
        code_hash: &str,
    ) -> Result<Option<ActivationCodeRecord>> {
        let row = sqlx::query("SELECT document FROM activation_codes WHERE code_hash = $1")
            .bind(code_hash)
            .fetch_optional(&self.pool)
            .await
            .map_err(|_| ApiError::Database)?;
        row.map(row_document).transpose()
    }

    async fn confirm_device_activation(
        &self,
        session_token_hash: &str,
        device_id: &str,
        activation_code_hash: Option<&str>,
        now: i64,
        audit: AuditEventRecord,
    ) -> Result<Device> {
        let mut tx = self.pool.begin().await.map_err(|_| ApiError::Database)?;
        let initial = session_in_transaction(&mut tx, session_token_hash)
            .await?
            .ok_or(ApiError::AuthorizationRequired)?;
        if initial.device_id != device_id {
            return Err(ApiError::AuthorizationRequired);
        }
        let initial_device = device_in_transaction(&mut tx, device_id).await?;
        lock_license(&mut tx, &initial_device.license_id).await?;
        lock_device(&mut tx, device_id).await?;
        let mut confirmation = session_for_update(&mut tx, session_token_hash)
            .await?
            .ok_or(ApiError::AuthorizationRequired)?;
        if initial.device_id != confirmation.device_id {
            return Err(ApiError::AuthorizationRequired);
        }
        if !confirmation.active
            || confirmation.expires_at <= now
            || confirmation.absolute_expires_at <= now
            || confirmation.proof_state != RefreshSessionProofState::DeviceProven
            || confirmation.device_id != device_id
            || confirmation
                .activation_verified_at
                .is_none_or(|verified_at| verified_at + 5 * 60 <= now)
        {
            return Err(ApiError::AuthorizationRequired);
        }
        let rows = sqlx::query(
            "SELECT document FROM devices
             WHERE license_id = (SELECT license_id FROM devices WHERE device_id = $1)
             ORDER BY device_id
             FOR UPDATE",
        )
        .bind(device_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        let mut current = None;
        let mut active_count = 0usize;
        for row in rows {
            let device: Device = row_document(row)?;
            if device.state == DeviceState::Active {
                active_count += 1;
            }
            if device.metadata.device_id == device_id {
                current = Some(device);
            }
        }
        let mut device = current.ok_or(ApiError::DeviceDenied)?;
        let account = account_for_share(&mut tx, &device.account_id).await?;
        ensure_account_is_active(&account)?;
        let license = license_for_share(&mut tx, &device.license_id).await?;
        if license.account_id != device.account_id {
            return Err(ApiError::LicenseUnavailable);
        }
        ensure_license_is_usable(&license, now)?;
        let max_devices = license.effective_policy()?.device_limit;
        validate_activation_confirmation_audit(&audit, &device)?;
        if device.state == DeviceState::Active {
            insert_audit_event_transaction(&mut tx, &audit).await?;
            tx.commit().await.map_err(|_| ApiError::Database)?;
            return Ok(device);
        }
        let activation_code_hash = activation_code_hash.ok_or(ApiError::AuthorizationRequired)?;
        if confirmation.pending_activation_code_hash.as_deref() != Some(activation_code_hash) {
            return Err(ApiError::AuthorizationRequired);
        }
        if confirmation.activation_confirmation_consumed {
            return Err(ApiError::AuthorizationRequired);
        }
        if device.state != DeviceState::PendingActivation
            || device.pending_activation_code_hash.as_deref() != Some(activation_code_hash)
            || device
                .pending_activation_expires_at
                .is_none_or(|expires_at| expires_at <= now)
        {
            return Err(ApiError::AuthorizationRequired);
        }
        if active_count >= max_devices as usize {
            return Err(ApiError::ActivationLimitReached);
        }
        let row =
            sqlx::query("SELECT document FROM activation_codes WHERE code_hash = $1 FOR UPDATE")
                .bind(activation_code_hash)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|_| ApiError::Database)?
                .ok_or(ApiError::ActivationCodeInvalid)?;
        let mut code: ActivationCodeRecord = row_document(row)?;
        if code.account_id != device.account_id
            || code
                .license_id
                .as_ref()
                .is_some_and(|license_id| license_id != &device.license_id)
        {
            return Err(ApiError::ActivationCodeInvalid);
        }
        if !code.is_usable(now) {
            return Err(activation_code_error(&code, now));
        }
        code.record_redemption(device_id, now);
        confirmation.activation_confirmation_consumed = true;
        sqlx::query(
            "UPDATE refresh_sessions SET document = $2, updated_at = now()
             WHERE token_hash = $1",
        )
        .bind(session_token_hash)
        .bind(json(&confirmation)?)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        sqlx::query(
            "UPDATE activation_codes
             SET status = $2, consumed = $3, consumed_at = $4,
                 consumed_device_id = $5, document = $6, updated_at = now()
             WHERE code_hash = $1",
        )
        .bind(activation_code_hash)
        .bind(activation_code_status(&code.status))
        .bind(code.status == ActivationCodeStatus::Consumed)
        .bind(code.consumed_at)
        .bind(&code.consumed_device_id)
        .bind(json(&code)?)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        device.state = DeviceState::Active;
        device.pending_activation_code_hash = None;
        device.pending_activation_expires_at = None;
        device.last_seen_at = Some(now);
        sqlx::query(
            "UPDATE devices SET state = 'active', document = $2, updated_at = now() WHERE device_id = $1",
        )
        .bind(device_id)
        .bind(json(&device)?)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?;
        insert_audit_event_transaction(&mut tx, &audit).await?;
        tx.commit().await.map_err(|_| ApiError::Database)?;
        Ok(device)
    }

    async fn insert_audit_event(&self, event: AuditEventRecord) -> Result<()> {
        sqlx::query(
            "INSERT INTO audit_events
             (id, event_type, outcome, occurred_at, account_id, license_id, device_id,
              reason_code, metadata, document, actor_type, actor_id, admin_session_id,
              request_id, source_ip, user_agent_hash, target_type, target_id, operation_id, job_id)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
                     $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)",
        )
        .bind(&event.id)
        .bind(&event.event_type)
        .bind(&event.outcome)
        .bind(event.occurred_at)
        .bind(&event.account_id)
        .bind(&event.license_id)
        .bind(&event.device_id)
        .bind(&event.reason_code)
        .bind(json(&event.metadata)?)
        .bind(json(&event)?)
        .bind(event.metadata.get("actor_type"))
        .bind(event.metadata.get("actor"))
        .bind(event.metadata.get("admin_session_id"))
        .bind(event.metadata.get("request_id"))
        .bind(event.metadata.get("source_ip"))
        .bind(event.metadata.get("user_agent_hash"))
        .bind(event.metadata.get("target_type"))
        .bind(event.metadata.get("target_id"))
        .bind(event.metadata.get("operation_id"))
        .bind(event.metadata.get("job_id"))
        .execute(&self.pool)
        .await
        .map_err(|_| ApiError::Database)?;
        Ok(())
    }
}

async fn insert_audit_event_transaction(
    tx: &mut Transaction<'_, Postgres>,
    audit: &AuditEventRecord,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO audit_events
         (id, event_type, outcome, occurred_at, account_id, license_id, device_id,
          reason_code, metadata, document, actor_type, actor_id, admin_session_id,
          request_id, source_ip, user_agent_hash, target_type, target_id, operation_id, job_id)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
                 $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)",
    )
    .bind(&audit.id)
    .bind(&audit.event_type)
    .bind(&audit.outcome)
    .bind(audit.occurred_at)
    .bind(&audit.account_id)
    .bind(&audit.license_id)
    .bind(&audit.device_id)
    .bind(&audit.reason_code)
    .bind(json(&audit.metadata)?)
    .bind(json(audit)?)
    .bind(audit.metadata.get("actor_type"))
    .bind(audit.metadata.get("actor"))
    .bind(audit.metadata.get("admin_session_id"))
    .bind(audit.metadata.get("request_id"))
    .bind(audit.metadata.get("source_ip"))
    .bind(audit.metadata.get("user_agent_hash"))
    .bind(audit.metadata.get("target_type"))
    .bind(audit.metadata.get("target_id"))
    .bind(audit.metadata.get("operation_id"))
    .bind(audit.metadata.get("job_id"))
    .execute(&mut **tx)
    .await
    .map_err(|_| ApiError::Database)?;
    Ok(())
}

async fn lock_device(tx: &mut Transaction<'_, Postgres>, device_id: &str) -> Result<()> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!("device:{device_id}"))
        .execute(&mut **tx)
        .await
        .map_err(|_| ApiError::Database)?;
    Ok(())
}

async fn lock_license(tx: &mut Transaction<'_, Postgres>, license_id: &str) -> Result<()> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!("license:{license_id}"))
        .execute(&mut **tx)
        .await
        .map_err(|_| ApiError::Database)?;
    Ok(())
}

async fn lock_devices(tx: &mut Transaction<'_, Postgres>, first: &str, second: &str) -> Result<()> {
    if first <= second {
        lock_device(tx, first).await?;
        if first != second {
            lock_device(tx, second).await?;
        }
    } else {
        lock_device(tx, second).await?;
        lock_device(tx, first).await?;
    }
    Ok(())
}

async fn device_for_update(tx: &mut Transaction<'_, Postgres>, device_id: &str) -> Result<Device> {
    let row = sqlx::query("SELECT document FROM devices WHERE device_id = $1 FOR UPDATE")
        .bind(device_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| ApiError::Database)?
        .ok_or(ApiError::DeviceDenied)?;
    row_document(row)
}

async fn device_in_transaction(
    tx: &mut Transaction<'_, Postgres>,
    device_id: &str,
) -> Result<Device> {
    let row = sqlx::query("SELECT document FROM devices WHERE device_id = $1")
        .bind(device_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| ApiError::Database)?
        .ok_or(ApiError::DeviceDenied)?;
    row_document(row)
}

async fn account_for_share(
    tx: &mut Transaction<'_, Postgres>,
    account_id: &str,
) -> Result<Account> {
    let row = sqlx::query("SELECT document FROM accounts WHERE id = $1 FOR SHARE")
        .bind(account_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| ApiError::Database)?
        .ok_or(ApiError::DeviceDenied)?;
    row_document(row)
}

async fn license_for_share(
    tx: &mut Transaction<'_, Postgres>,
    license_id: &str,
) -> Result<License> {
    let row = sqlx::query(
        "SELECT id, account_id, plan, plan_revision, status, expires_at,
                license_epoch, purchased_seats, row_version
         FROM licenses WHERE id = $1 FOR SHARE",
    )
    .bind(license_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| ApiError::Database)?
    .ok_or(ApiError::LicenseUnavailable)?;
    row_license(row)
}

fn row_license(row: PgRow) -> Result<License> {
    let plan = match row
        .try_get::<String, _>("plan")
        .map_err(|_| ApiError::Database)?
        .as_str()
    {
        "free" => Plan::Free,
        "pro" => Plan::Pro,
        "team" => Plan::Team,
        _ => return Err(ApiError::Database),
    };
    let status = match row
        .try_get::<String, _>("status")
        .map_err(|_| ApiError::Database)?
        .as_str()
    {
        "active" => LicenseStatus::Active,
        "past_due" => LicenseStatus::PastDue,
        "canceled" => LicenseStatus::Canceled,
        _ => return Err(ApiError::Database),
    };
    Ok(License {
        id: row.try_get("id").map_err(|_| ApiError::Database)?,
        account_id: row.try_get("account_id").map_err(|_| ApiError::Database)?,
        plan,
        plan_revision: u32::try_from(
            row.try_get::<i32, _>("plan_revision")
                .map_err(|_| ApiError::Database)?,
        )
        .map_err(|_| ApiError::Database)?,
        status,
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
    })
}

const fn plan_name(plan: Plan) -> &'static str {
    match plan {
        Plan::Free => "free",
        Plan::Pro => "pro",
        Plan::Team => "team",
    }
}

const fn license_status_name(status: LicenseStatus) -> &'static str {
    match status {
        LicenseStatus::Active => "active",
        LicenseStatus::PastDue => "past_due",
        LicenseStatus::Canceled => "canceled",
    }
}

async fn session_in_transaction(
    tx: &mut Transaction<'_, Postgres>,
    token_hash: &str,
) -> Result<Option<RefreshSessionRecord>> {
    let row = sqlx::query(
        "SELECT document, family_id, active, expires_at
         FROM refresh_sessions WHERE token_hash = $1",
    )
    .bind(token_hash)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| ApiError::Database)?;
    row.map(session_record).transpose()
}

async fn session_for_update(
    tx: &mut Transaction<'_, Postgres>,
    token_hash: &str,
) -> Result<Option<RefreshSessionRecord>> {
    let row = sqlx::query(
        "SELECT document, family_id, active, expires_at
         FROM refresh_sessions WHERE token_hash = $1 FOR UPDATE",
    )
    .bind(token_hash)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| ApiError::Database)?;
    row.map(session_record).transpose()
}

fn session_record(row: PgRow) -> Result<RefreshSessionRecord> {
    let family_id = row
        .try_get::<String, _>("family_id")
        .map_err(|_| ApiError::Database)?;
    let active = row
        .try_get::<bool, _>("active")
        .map_err(|_| ApiError::Database)?;
    let expires_at = row
        .try_get::<i64, _>("expires_at")
        .map_err(|_| ApiError::Database)?;
    let mut session: RefreshSessionRecord = row_document(row)?;
    session.family_id = family_id;
    session.active = active;
    session.expires_at = expires_at;
    Ok(session)
}

async fn revoke_device_sessions_transaction(
    tx: &mut Transaction<'_, Postgres>,
    device_id: &str,
) -> Result<()> {
    sqlx::query(
        "UPDATE refresh_sessions
         SET active = false,
             document = jsonb_set(document, '{active}', 'false'::jsonb, true),
             updated_at = now()
         WHERE device_id = $1",
    )
    .bind(device_id)
    .execute(&mut **tx)
    .await
    .map_err(|_| ApiError::Database)?;
    Ok(())
}

async fn insert_device_removal_operation(
    tx: &mut Transaction<'_, Postgres>,
    account_id: &str,
    requester_session_hash: &str,
    requester_device_id: &str,
    target_device_id: &str,
    operation_id: &str,
    now: i64,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO device_removal_operations
            (account_id, operation_id, requester_session_hash, requester_device_id,
             target_device_id, created_at)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(account_id)
    .bind(operation_id)
    .bind(requester_session_hash)
    .bind(requester_device_id)
    .bind(target_device_id)
    .bind(now)
    .execute(&mut **tx)
    .await
    .map_err(|_| ApiError::Database)?;
    Ok(())
}

fn json<T: serde::Serialize>(value: &T) -> Result<serde_json::Value> {
    serde_json::to_value(value).map_err(|_| ApiError::Internal)
}

fn from_json<T: serde::de::DeserializeOwned>(value: serde_json::Value) -> Result<T> {
    serde_json::from_value(value).map_err(|_| ApiError::Database)
}

fn database_error(
    stage: &'static str,
    error: impl std::fmt::Display + std::fmt::Debug,
) -> ApiError {
    let error = error.to_string();
    if error.contains("was previously applied but has been modified") {
        tracing::error!(
            stage,
            error_kind = "database",
            error = %error,
            recovery = "restore consistency between the runtime artifact and database migration history, then deliver schema changes through a new migration",
            "database migration checksum mismatch"
        );
    } else {
        tracing::error!(
            stage,
            error_kind = "database",
            error = %error,
            "database operation failed"
        );
    }
    ApiError::Database
}

fn admin_conflict_or_database(stage: &'static str, error: sqlx::Error) -> AdminAppError {
    if error
        .as_database_error()
        .is_some_and(sqlx::error::DatabaseError::is_unique_violation)
    {
        AdminAppError::IdempotencyConflict
    } else {
        AdminAppError::Service(database_error(stage, error))
    }
}

fn row_document<T: serde::de::DeserializeOwned>(row: PgRow) -> Result<T> {
    let document = row
        .try_get::<serde_json::Value, _>("document")
        .map_err(|_| ApiError::Database)?;
    from_json(document)
}

fn row_audit_event(row: PgRow) -> Result<AuditEventRecord> {
    let id: String = row
        .try_get("id")
        .map_err(|error| database_error("postgres_audit_event_decode", error))?;
    let metadata = row
        .try_get::<serde_json::Value, _>("metadata")
        .map_err(|error| database_error("postgres_audit_event_decode", error))?;
    if !metadata.is_object() {
        tracing::warn!(
            audit_event_ref = %stable_log_reference(&id),
            "audit metadata is not an object; returning the normalized event without metadata"
        );
    }
    Ok(AuditEventRecord {
        id,
        event_type: row
            .try_get("event_type")
            .map_err(|error| database_error("postgres_audit_event_decode", error))?,
        outcome: row
            .try_get("outcome")
            .map_err(|error| database_error("postgres_audit_event_decode", error))?,
        occurred_at: row
            .try_get("occurred_at")
            .map_err(|error| database_error("postgres_audit_event_decode", error))?,
        account_id: row
            .try_get("account_id")
            .map_err(|error| database_error("postgres_audit_event_decode", error))?,
        license_id: row
            .try_get("license_id")
            .map_err(|error| database_error("postgres_audit_event_decode", error))?,
        device_id: row
            .try_get("device_id")
            .map_err(|error| database_error("postgres_audit_event_decode", error))?,
        reason_code: row
            .try_get("reason_code")
            .map_err(|error| database_error("postgres_audit_event_decode", error))?,
        metadata: audit_metadata(metadata),
    })
}

fn audit_metadata(value: serde_json::Value) -> BTreeMap<String, String> {
    let serde_json::Value::Object(entries) = value else {
        return BTreeMap::new();
    };
    entries
        .into_iter()
        .filter_map(|(key, value)| match value {
            serde_json::Value::Null => None,
            serde_json::Value::String(value) => Some((key, value)),
            value => Some((key, value.to_string())),
        })
        .collect()
}

fn device_state(state: &DeviceState) -> &'static str {
    match state {
        DeviceState::PendingActivation => "pending_activation",
        DeviceState::Active => "active",
        DeviceState::Removed => "removed",
        DeviceState::Revoked => "revoked",
        DeviceState::Suspicious => "suspicious",
    }
}

fn session_proof_state(state: RefreshSessionProofState) -> &'static str {
    match state {
        RefreshSessionProofState::Unproven => "unproven",
        RefreshSessionProofState::DeviceProven => "device_proven",
    }
}

fn activation_code_status(status: &ActivationCodeStatus) -> &'static str {
    match status {
        ActivationCodeStatus::Active => "active",
        ActivationCodeStatus::Consumed => "consumed",
        ActivationCodeStatus::Revoked => "revoked",
    }
}

fn time_authority_status_from_name(status: &str) -> Result<TimeAuthorityStatus> {
    match status {
        "healthy" => Ok(TimeAuthorityStatus::Healthy),
        "rollback_held" => Ok(TimeAuthorityStatus::RollbackHeld),
        "forward_jump" => Ok(TimeAuthorityStatus::ForwardJump),
        _ => Err(ApiError::Database),
    }
}

fn activation_code_error(code: &ActivationCodeRecord, now: i64) -> ApiError {
    if code.status == ActivationCodeStatus::Revoked {
        ApiError::ActivationCodeRevoked
    } else if code.is_expired(now) {
        ApiError::ActivationCodeExpired
    } else if code.status == ActivationCodeStatus::Consumed || code.remaining_redemptions() == 0 {
        ApiError::ActivationCodeConsumed
    } else {
        ApiError::ActivationCodeInvalid
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;

    use super::*;
    use crate::contracts::DeviceRegistrationMetadata;

    #[test]
    fn database_password_file_normalizes_one_line_ending_without_exposing_content() {
        let path = std::env::temp_dir().join("camellia-database-password-boundary-test");
        fs::write(&path, b"password-value\r\n").expect("write password fixture");
        let password = read_database_password(&path).expect("read password fixture");
        assert_eq!(&*password, "password-value");
        fs::remove_file(path).expect("remove password fixture");
    }

    #[test]
    fn database_password_file_rejects_empty_and_multiline_values() {
        for bytes in [
            b"".as_slice(),
            b"line-one\nline-two".as_slice(),
            b"bad\0value".as_slice(),
            b"bad\xffvalue".as_slice(),
        ] {
            let path = std::env::temp_dir().join("camellia-invalid-database-password-test");
            fs::write(&path, bytes).expect("write invalid password fixture");
            assert!(read_database_password(&path).is_err());
            fs::remove_file(path).expect("remove invalid password fixture");
        }
    }

    #[test]
    fn audit_metadata_preserves_values_without_failing_on_nullable_legacy_fields() {
        let metadata = audit_metadata(serde_json::json!({
            "actor": "anonymous",
            "attempt": 3,
            "flags": ["rate_limited", "unknown_user"],
            "target_id": null
        }));

        assert_eq!(metadata.get("actor").map(String::as_str), Some("anonymous"));
        assert_eq!(metadata.get("attempt").map(String::as_str), Some("3"));
        assert_eq!(
            metadata.get("flags").map(String::as_str),
            Some("[\"rate_limited\",\"unknown_user\"]")
        );
        assert!(!metadata.contains_key("target_id"));
    }

    #[test]
    fn audit_metadata_ignores_non_object_storage_without_hiding_the_event() {
        assert!(audit_metadata(serde_json::json!(["invalid"])).is_empty());
    }

    #[tokio::test]
    async fn memory_time_authority_never_moves_backwards() {
        let repository = MemoryRepository::default();
        let first = repository
            .observe_time_authority(Some(2_000), 60)
            .await
            .unwrap();
        let rollback = repository
            .observe_time_authority(Some(1_000), 60)
            .await
            .unwrap();

        assert_eq!(first.trusted_unix, 2_000);
        assert_eq!(rollback.previous_high_water_unix, 2_000);
        assert_eq!(rollback.trusted_unix, 2_000);
    }

    async fn rotation_repository() -> MemoryRepository {
        let repository = MemoryRepository::default();
        repository
            .upsert_account(Account::active("account", 1_000))
            .await
            .unwrap();
        repository
            .upsert_license(License::default_pro("account", 1_000))
            .await
            .unwrap();
        repository
            .upsert_device(Device {
                account_id: "account".into(),
                license_id: "lic_account".into(),
                metadata: DeviceRegistrationMetadata {
                    device_id: "device".into(),
                    public_key_pem: "public-key".into(),
                    public_key_thumbprint: "thumbprint".into(),
                    platform: "test".into(),
                    app_version: "1.0.0".into(),
                    display_name: None,
                },
                state: DeviceState::Active,
                pending_activation_code_hash: None,
                pending_activation_expires_at: None,
                created_at: 1_000,
                last_seen_at: Some(1_000),
            })
            .await
            .unwrap();
        repository
    }

    fn rotation_audit(id: &str, now: i64) -> AuditEventRecord {
        AuditEventRecord {
            id: id.to_owned(),
            event_type: "entitlement_refreshed".into(),
            outcome: "succeeded".into(),
            occurred_at: now,
            account_id: Some("account".into()),
            license_id: Some("lic_account".into()),
            device_id: Some("device".into()),
            reason_code: None,
            metadata: BTreeMap::from([("token_id".into(), format!("lease_{id}"))]),
        }
    }

    fn recovery_audit(id: &str, now: i64) -> AuditEventRecord {
        AuditEventRecord {
            id: id.to_owned(),
            event_type: "session_recovered".into(),
            outcome: "succeeded".into(),
            occurred_at: now,
            account_id: Some("account".into()),
            license_id: Some("lic_account".into()),
            device_id: Some("device".into()),
            reason_code: Some("device_proof".into()),
            metadata: BTreeMap::new(),
        }
    }

    fn session(token_hash: &str, family_id: &str) -> RefreshSessionRecord {
        RefreshSessionRecord {
            token_hash: token_hash.to_owned(),
            account_id: "account".to_owned(),
            device_id: "device".to_owned(),
            family_id: family_id.to_owned(),
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
        }
    }

    #[tokio::test]
    async fn concurrent_rotation_retry_keeps_only_the_latest_unobserved_successor() {
        let repository = rotation_repository().await;
        repository
            .insert_session(session("parent", "family"))
            .await
            .unwrap();

        let first_repository = repository.clone();
        let second_repository = repository.clone();
        let first = tokio::spawn(async move {
            first_repository
                .rotate_session_with_audit(
                    "parent",
                    session("first", "family"),
                    1_000,
                    rotation_audit("first-audit", 1_000),
                )
                .await
        });
        let second = tokio::spawn(async move {
            second_repository
                .rotate_session_with_audit(
                    "parent",
                    session("second", "family"),
                    1_000,
                    rotation_audit("second-audit", 1_000),
                )
                .await
        });
        let first = first.await.unwrap();
        let second = second.await.unwrap();

        assert!(first.is_ok());
        assert!(second.is_ok());
        assert!(
            !repository
                .session_by_hash("parent")
                .await
                .unwrap()
                .unwrap()
                .active
        );
        let first_active = repository
            .session_by_hash("first")
            .await
            .unwrap()
            .is_some_and(|session| session.active);
        let second_active = repository
            .session_by_hash("second")
            .await
            .unwrap()
            .is_some_and(|session| session.active);
        assert_ne!(first_active, second_active);
    }

    #[tokio::test]
    async fn rotation_rolls_back_when_success_audit_cannot_be_inserted() {
        let repository = rotation_repository().await;
        repository
            .insert_session(session("parent", "family"))
            .await
            .unwrap();
        let audit = rotation_audit("duplicate-audit", 1_000);
        repository.insert_audit_event(audit.clone()).await.unwrap();

        assert!(matches!(
            repository
                .rotate_session_with_audit("parent", session("child", "family"), 1_000, audit,)
                .await,
            Err(ApiError::InvalidRequest)
        ));
        assert!(
            repository
                .session_by_hash("parent")
                .await
                .unwrap()
                .unwrap()
                .active
        );
        assert!(repository.session_by_hash("child").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn recovery_rolls_back_when_success_audit_cannot_be_inserted() {
        let repository = rotation_repository().await;
        repository
            .insert_session(session("previous", "previous-family"))
            .await
            .unwrap();
        let audit = recovery_audit("duplicate-recovery-audit", 1_000);
        repository.insert_audit_event(audit.clone()).await.unwrap();

        assert!(matches!(
            repository
                .replace_device_sessions_with_audit(
                    session("recovery", "recovery-family"),
                    1_000,
                    audit,
                )
                .await,
            Err(ApiError::InvalidRequest)
        ));
        assert!(
            repository
                .session_by_hash("previous")
                .await
                .unwrap()
                .unwrap()
                .active
        );
        assert!(
            repository
                .session_by_hash("recovery")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn authorization_code_rolls_back_when_success_audit_cannot_be_inserted() {
        let repository = MemoryRepository::default();
        let code = StoredAuthorizationCode {
            code_hash: "authorization-code".into(),
            account_id: "account".into(),
            license_id: Some("license".into()),
            activation_code_hash: Some("activation".into()),
            code_challenge: "challenge".into(),
            redirect_uri: "http://127.0.0.1/callback".into(),
            expires_at: 2_000,
            consumed: false,
            consumed_at: None,
            consumed_device_id: None,
            consumed_key_thumbprint: None,
        };
        let audit = AuditEventRecord {
            id: "duplicate-authorization-audit".into(),
            event_type: "authorization_code_issued".into(),
            outcome: "succeeded".into(),
            occurred_at: 1_000,
            account_id: Some("account".into()),
            license_id: Some("license".into()),
            device_id: None,
            reason_code: None,
            metadata: BTreeMap::new(),
        };
        repository.insert_audit_event(audit.clone()).await.unwrap();

        assert!(matches!(
            repository
                .insert_authorization_code_with_audit(code, audit)
                .await,
            Err(ApiError::InvalidRequest)
        ));
        assert!(
            repository
                .authorization_code_by_hash("authorization-code")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn device_session_revocation_is_immediate() {
        let repository = rotation_repository().await;
        repository
            .insert_session(session("session", "family"))
            .await
            .unwrap();
        repository
            .revoke_sessions_for_device("device")
            .await
            .unwrap();
        assert!(
            !repository
                .session_by_hash("session")
                .await
                .unwrap()
                .unwrap()
                .active
        );
    }

    #[tokio::test]
    async fn device_last_seen_updates_are_throttled_and_monotonic() {
        let repository = MemoryRepository::default();
        let device_id = uuid::Uuid::new_v4().to_string();
        repository.write().unwrap().devices.insert(
            device_id.clone(),
            Device {
                account_id: "account".into(),
                license_id: "license".into(),
                metadata: DeviceRegistrationMetadata {
                    device_id: device_id.clone(),
                    public_key_pem: "public-key".into(),
                    public_key_thumbprint: "thumbprint".into(),
                    platform: "test".into(),
                    app_version: "1.0.0".into(),
                    display_name: None,
                },
                state: DeviceState::Active,
                pending_activation_code_hash: None,
                pending_activation_expires_at: None,
                created_at: 900,
                last_seen_at: Some(1_000),
            },
        );

        repository
            .touch_device_last_seen(&device_id, 1_299, 300)
            .await
            .unwrap();
        assert_eq!(
            repository
                .device(&device_id)
                .await
                .unwrap()
                .unwrap()
                .last_seen_at,
            Some(1_000)
        );

        repository
            .touch_device_last_seen(&device_id, 1_300, 300)
            .await
            .unwrap();
        repository
            .touch_device_last_seen(&device_id, 1_200, 300)
            .await
            .unwrap();
        assert_eq!(
            repository
                .device(&device_id)
                .await
                .unwrap()
                .unwrap()
                .last_seen_at,
            Some(1_300),
            "delayed requests must not move last-seen time backwards"
        );

        repository
            .update_device_client_metadata(&device_id, "2.0.0", 1_400)
            .await
            .unwrap();
        repository
            .update_device_client_metadata(&device_id, "1.5.0", 1_350)
            .await
            .unwrap();
        let device = repository.device(&device_id).await.unwrap().unwrap();
        assert_eq!(device.metadata.app_version, "2.0.0");
        assert_eq!(device.last_seen_at, Some(1_400));
    }

    #[tokio::test]
    async fn memory_device_pages_filter_by_license_before_applying_the_limit() {
        let repository = MemoryRepository::default();
        let make_device = |license_id: &str, device_id: &str| Device {
            account_id: "account".to_owned(),
            license_id: license_id.to_owned(),
            metadata: DeviceRegistrationMetadata {
                device_id: device_id.to_owned(),
                public_key_pem: "public-key".to_owned(),
                public_key_thumbprint: format!("sha256:{device_id}"),
                platform: "test".to_owned(),
                app_version: "1.0.0".to_owned(),
                display_name: None,
            },
            state: DeviceState::Active,
            pending_activation_code_hash: None,
            pending_activation_expires_at: None,
            created_at: 1_000,
            last_seen_at: Some(1_000),
        };
        {
            let mut guard = repository.write().unwrap();
            for (license_id, device_id) in [
                ("other-license", "00000000-0000-4000-8000-000000000000"),
                ("license", "00000000-0000-4000-8000-000000000001"),
                ("license", "00000000-0000-4000-8000-000000000002"),
                ("license", "00000000-0000-4000-8000-000000000003"),
            ] {
                guard
                    .devices
                    .insert(device_id.to_owned(), make_device(license_id, device_id));
            }
        }

        let first = repository
            .devices_for_license_page("license", None, 2)
            .await
            .unwrap();
        assert_eq!(
            first
                .iter()
                .map(|device| device.metadata.device_id.as_str())
                .collect::<Vec<_>>(),
            [
                "00000000-0000-4000-8000-000000000001",
                "00000000-0000-4000-8000-000000000002",
            ]
        );
        let second = repository
            .devices_for_license_page("license", Some("00000000-0000-4000-8000-000000000002"), 2)
            .await
            .unwrap();
        assert_eq!(second.len(), 1);
        assert_eq!(
            second[0].metadata.device_id,
            "00000000-0000-4000-8000-000000000003"
        );
    }

    #[tokio::test]
    async fn cleanup_preserves_session_family_until_replay_detection_window_closes() {
        let repository = rotation_repository().await;
        repository
            .insert_session(session("parent", "family"))
            .await
            .unwrap();
        repository
            .rotate_session_with_audit(
                "parent",
                session("child", "family"),
                1_000,
                rotation_audit("child-audit", 1_000),
            )
            .await
            .unwrap();

        let cleanup_boundary = 3_000 + SESSION_REPLAY_RETENTION_SECONDS;
        let report = repository
            .cleanup_expired(cleanup_boundary - 1, 10)
            .await
            .unwrap();
        assert_eq!(report.refresh_sessions, 0);
        assert!(
            repository
                .session_by_hash("parent")
                .await
                .unwrap()
                .is_some()
        );
        assert!(repository.session_by_hash("child").await.unwrap().is_some());

        assert!(matches!(
            repository
                .rotate_session_with_audit(
                    "parent",
                    session("replay", "family"),
                    2_000,
                    rotation_audit("replay-audit", 2_000),
                )
                .await,
            Err(ApiError::RefreshSessionReused)
        ));
        assert!(
            !repository
                .session_by_hash("child")
                .await
                .unwrap()
                .unwrap()
                .active
        );

        let report = repository
            .cleanup_expired(cleanup_boundary, 10)
            .await
            .unwrap();
        assert_eq!(report.refresh_sessions, 2);
        assert!(
            repository
                .session_by_hash("parent")
                .await
                .unwrap()
                .is_none()
        );
        assert!(repository.session_by_hash("child").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn cleanup_removes_only_stale_rate_limit_buckets() {
        let repository = MemoryRepository::default();
        assert!(
            repository
                .consume_rate_limit("scope", "old", 1_000, 1, 60)
                .await
                .unwrap()
        );
        assert!(
            repository
                .consume_rate_limit("scope", "current", 8_180, 1, 60)
                .await
                .unwrap()
        );

        let report = repository.cleanup_expired(8_200, 10).await.unwrap();
        assert_eq!(report.rate_limit_buckets, 1);
        assert!(
            !repository
                .consume_rate_limit("scope", "current", 8_201, 1, 60)
                .await
                .unwrap()
        );
        assert!(
            repository
                .consume_rate_limit("scope", "old", 8_201, 1, 60)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn challenge_insertion_prunes_expired_synthetic_state() {
        let repository = MemoryRepository::default();
        for (challenge_id, issued_at, expires_at) in
            [("expired", 1_000, 1_060), ("current", 1_060, 1_120)]
        {
            repository
                .insert_challenge(StoredChallenge {
                    challenge_id: challenge_id.to_owned(),
                    nonce: format!("nonce-{challenge_id}"),
                    device_id: uuid::Uuid::new_v4().to_string(),
                    requested_scope: "session:recover".to_owned(),
                    issued_at,
                    expires_at,
                    consumed: false,
                })
                .await
                .unwrap();
        }

        let guard = repository.read().unwrap();
        assert_eq!(guard.challenges.len(), 1);
        assert!(guard.challenges.contains_key("current"));
    }
}
