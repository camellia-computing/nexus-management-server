use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{
    contracts::{DeviceRegistrationMetadata, DeviceState, Plan},
    error::Result,
    plan_catalog::{CURRENT_PLAN_REVISION, EffectivePlanPolicy, effective_policy},
};

pub const AUTHORIZATION_RESULT_RETRY_SECONDS: i64 = 10 * 60;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub id: String,
    #[serde(default)]
    pub state: AccountState,
    #[serde(default)]
    pub note: Option<String>,
    #[serde(default)]
    pub created_at: i64,
    #[serde(default)]
    pub updated_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AccountState {
    #[default]
    Active,
    Suspended,
    Denylisted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct License {
    pub id: String,
    pub account_id: String,
    pub plan: Plan,
    pub plan_revision: u32,
    pub status: LicenseStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    pub license_epoch: u64,
    pub purchased_seats: u32,
    pub row_version: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LicenseStatus {
    Active,
    PastDue,
    Canceled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub account_id: String,
    pub license_id: String,
    pub metadata: DeviceRegistrationMetadata,
    pub state: DeviceState,
    #[serde(default)]
    pub pending_activation_code_hash: Option<String>,
    #[serde(default)]
    pub pending_activation_expires_at: Option<i64>,
    pub created_at: i64,
    pub last_seen_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshSessionRecord {
    pub token_hash: String,
    pub account_id: String,
    pub device_id: String,
    pub family_id: String,
    pub family_created_at: i64,
    pub absolute_expires_at: i64,
    pub active: bool,
    pub expires_at: i64,
    pub rotated_to_hash: Option<String>,
    #[serde(default)]
    pub rotated_at: Option<i64>,
    #[serde(default)]
    pub pending_activation_code_hash: Option<String>,
    #[serde(default)]
    pub activation_verified_at: Option<i64>,
    #[serde(default)]
    pub activation_confirmation_consumed: bool,
    #[serde(default)]
    pub proof_state: RefreshSessionProofState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RefreshSessionProofState {
    #[default]
    Unproven,
    DeviceProven,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredChallenge {
    pub challenge_id: String,
    pub nonce: String,
    pub device_id: String,
    pub requested_scope: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub consumed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredAuthorizationCode {
    pub code_hash: String,
    pub account_id: String,
    pub license_id: Option<String>,
    pub activation_code_hash: Option<String>,
    pub code_challenge: String,
    pub redirect_uri: String,
    pub expires_at: i64,
    pub consumed: bool,
    #[serde(default)]
    pub consumed_at: Option<i64>,
    #[serde(default)]
    pub consumed_device_id: Option<String>,
    #[serde(default)]
    pub consumed_key_thumbprint: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AuthorizationCodeRedemption {
    pub code_hash: String,
    pub code_challenge: String,
    pub redirect_uri: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivationCodeRecord {
    pub code_hash: String,
    pub code_prefix: String,
    pub account_id: String,
    pub license_id: Option<String>,
    pub status: ActivationCodeStatus,
    #[serde(default = "default_activation_code_max_redemptions")]
    pub max_redemptions: u32,
    #[serde(default)]
    pub redeemed_count: u32,
    pub expires_at: Option<i64>,
    pub consumed_at: Option<i64>,
    pub consumed_device_id: Option<String>,
    #[serde(default)]
    pub last_redeemed_at: Option<i64>,
    #[serde(default)]
    pub last_redeemed_device_id: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    pub note: Option<String>,
    pub order_id: Option<String>,
    #[serde(default)]
    pub channel: Option<String>,
    #[serde(default)]
    pub issued_by: Option<String>,
    #[serde(default)]
    pub revoked_reason: Option<String>,
    #[serde(default)]
    pub last_admin_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEventRecord {
    pub id: String,
    pub event_type: String,
    pub outcome: String,
    pub occurred_at: i64,
    pub account_id: Option<String>,
    pub license_id: Option<String>,
    pub device_id: Option<String>,
    pub reason_code: Option<String>,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ActivationCodeStatus {
    #[default]
    Active,
    Consumed,
    Revoked,
}

impl Account {
    pub fn active(id: impl Into<String>, now: i64) -> Self {
        Self {
            id: id.into(),
            state: AccountState::Active,
            note: None,
            created_at: now,
            updated_at: now,
        }
    }

    pub fn is_active(&self) -> bool {
        self.state == AccountState::Active
    }
}

impl ActivationCodeRecord {
    pub fn is_usable(&self, now: i64) -> bool {
        self.status == ActivationCodeStatus::Active
            && self.expires_at.is_none_or(|expires_at| expires_at > now)
            && self.remaining_redemptions() > 0
    }

    pub fn is_expired(&self, now: i64) -> bool {
        self.expires_at.is_some_and(|expires_at| expires_at <= now)
    }

    pub fn max_redemptions(&self) -> u32 {
        self.max_redemptions.max(1)
    }

    pub fn remaining_redemptions(&self) -> u32 {
        self.max_redemptions().saturating_sub(self.redeemed_count)
    }

    pub fn redeemed_by_last_device(&self, device_id: &str) -> bool {
        self.last_redeemed_device_id.as_deref() == Some(device_id)
    }

    pub fn record_redemption(&mut self, device_id: &str, now: i64) {
        self.redeemed_count = self
            .redeemed_count
            .saturating_add(1)
            .min(self.max_redemptions());
        self.last_redeemed_at = Some(now);
        self.last_redeemed_device_id = Some(device_id.to_owned());
        if self.remaining_redemptions() == 0 {
            self.status = ActivationCodeStatus::Consumed;
            self.consumed_at = Some(now);
            self.consumed_device_id = Some(device_id.to_owned());
        }
        self.updated_at = now;
    }

    pub fn restore_for_redemption(&mut self, reason: String, now: i64) {
        self.status = ActivationCodeStatus::Active;
        self.redeemed_count = 0;
        self.consumed_at = None;
        self.consumed_device_id = None;
        self.last_redeemed_at = None;
        self.last_redeemed_device_id = None;
        self.revoked_reason = None;
        self.last_admin_reason = Some(reason);
        self.updated_at = now;
    }
}

fn default_activation_code_max_redemptions() -> u32 {
    1
}

impl License {
    pub fn new(account_id: impl Into<String>, plan: Plan) -> Self {
        let account_id = account_id.into();
        let purchased_seats = if plan == Plan::Team { 3 } else { 0 };
        Self {
            id: format!("lic_{account_id}"),
            account_id,
            plan,
            plan_revision: CURRENT_PLAN_REVISION,
            status: LicenseStatus::Active,
            expires_at: None,
            license_epoch: 1,
            purchased_seats,
            row_version: 1,
        }
    }

    pub fn default_free(account_id: impl Into<String>, _now: i64) -> Self {
        Self::new(account_id, Plan::Free)
    }

    pub fn default_pro(account_id: impl Into<String>, _now: i64) -> Self {
        Self::new(account_id, Plan::Pro)
    }

    pub fn effective_policy(&self) -> Result<EffectivePlanPolicy> {
        effective_policy(self.plan, self.plan_revision, self.purchased_seats)
    }

    pub fn set_plan(&mut self, plan: Plan) {
        self.plan = plan;
        self.plan_revision = CURRENT_PLAN_REVISION;
        self.purchased_seats = if plan == Plan::Team {
            self.purchased_seats.max(3)
        } else {
            0
        };
    }
}
