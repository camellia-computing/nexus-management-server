use serde::{Deserialize, Serialize};

use crate::{
    admin_app::{Page, Versioned},
    admin_auth::AdminUser,
    admin_storage::ObjectStorageStatus,
    contracts::{DeviceState, Plan},
    domain::{
        Account, AccountState, ActivationCodeRecord, ActivationCodeStatus, AuditEventRecord,
        Device, License, LicenseStatus,
    },
    team::{WorkspaceMemberStatus, WorkspaceRole},
};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdminItems<T> {
    pub items: Vec<T>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdminSessionInfo {
    pub user: AdminUser,
    pub permissions: Vec<String>,
    pub expires_at: i64,
    pub elevated_until: i64,
    pub server_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdminDashboard {
    pub generated_at: i64,
    pub accounts: i64,
    pub active_licenses: i64,
    pub active_devices: i64,
    pub risky_devices: i64,
    pub pending_payments: i64,
    pub open_invoices: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdminSystemStatus {
    pub status: AdminReadiness,
    pub version: String,
    pub server_unix: i64,
    pub started_at: i64,
    pub admin_origin: String,
    pub database: AdminReadiness,
    pub time_authority: AdminReadiness,
    pub object_storage: ObjectStorageStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdminReadiness {
    Ready,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdminTeamWorkspace {
    pub account_id: String,
    pub license_id: String,
    pub purchased_seats: i32,
    pub occupied_members: i64,
    pub active_members: i64,
    pub member_count: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdminTeamMember {
    pub id: String,
    pub email: String,
    pub display_name: String,
    pub role: WorkspaceRole,
    pub status: WorkspaceMemberStatus,
    pub row_version: i64,
    pub created_at: i64,
    pub updated_at: i64,
    pub profile_pending: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdminTeamInvitation {
    pub id: String,
    pub member_id: String,
    pub email: String,
    pub display_name: String,
    pub role: WorkspaceRole,
    pub expires_at: i64,
    pub accepted_at: Option<i64>,
    pub revoked_at: Option<i64>,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdminPaymentEvidence {
    pub id: String,
    pub object_id: String,
    pub original_name: String,
    pub media_type: String,
    pub byte_length: i64,
    pub sha256: String,
    pub scan_status: String,
    pub created_at: i64,
    pub scanned_at: Option<i64>,
}

/// HTTP-only representation of an administration page. Domain documents retain their
/// persistence-oriented serde representation; every value crossing the Admin HTTP boundary is
/// converted to an explicit camelCase wire type instead.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdminPage<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdminAccount {
    pub id: String,
    pub state: AccountState,
    pub note: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    pub row_version: i64,
}

impl AdminAccount {
    pub fn new(value: Account, row_version: i64) -> Self {
        Self {
            id: value.id,
            state: value.state,
            note: value.note,
            created_at: value.created_at,
            updated_at: value.updated_at,
            row_version,
        }
    }
}

impl From<Versioned<Account>> for AdminAccount {
    fn from(value: Versioned<Account>) -> Self {
        Self::new(value.value, value.row_version)
    }
}

impl From<Page<Versioned<Account>>> for AdminPage<AdminAccount> {
    fn from(value: Page<Versioned<Account>>) -> Self {
        Self {
            items: value.items.into_iter().map(AdminAccount::from).collect(),
            next_cursor: value.next_cursor,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdminLicense {
    pub id: String,
    pub account_id: String,
    pub plan: Plan,
    pub plan_revision: u32,
    pub status: LicenseStatus,
    pub expires_at: Option<i64>,
    pub license_epoch: u64,
    pub purchased_seats: u32,
    pub row_version: i64,
}

impl AdminLicense {
    pub fn new(value: License, row_version: i64) -> Self {
        Self {
            id: value.id,
            account_id: value.account_id,
            plan: value.plan,
            plan_revision: value.plan_revision,
            status: value.status,
            expires_at: value.expires_at,
            license_epoch: value.license_epoch,
            purchased_seats: value.purchased_seats,
            row_version,
        }
    }
}

impl From<Versioned<License>> for AdminLicense {
    fn from(value: Versioned<License>) -> Self {
        debug_assert_eq!(
            u64::try_from(value.row_version).ok(),
            Some(value.value.row_version),
            "license document and relational row versions must agree"
        );
        Self::new(value.value, value.row_version)
    }
}

impl From<Page<Versioned<License>>> for AdminPage<AdminLicense> {
    fn from(value: Page<Versioned<License>>) -> Self {
        Self {
            items: value.items.into_iter().map(AdminLicense::from).collect(),
            next_cursor: value.next_cursor,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdminDevice {
    pub device_id: String,
    pub account_id: String,
    pub license_id: String,
    pub public_key_thumbprint: String,
    pub platform: String,
    pub app_version: String,
    pub display_name: Option<String>,
    pub state: DeviceState,
    pub pending_activation_expires_at: Option<i64>,
    pub created_at: i64,
    pub last_seen_at: Option<i64>,
    pub row_version: i64,
}

impl AdminDevice {
    pub fn new(value: Device, row_version: i64) -> Self {
        Self {
            device_id: value.metadata.device_id,
            account_id: value.account_id,
            license_id: value.license_id,
            public_key_thumbprint: value.metadata.public_key_thumbprint,
            platform: value.metadata.platform,
            app_version: value.metadata.app_version,
            display_name: value.metadata.display_name,
            state: value.state,
            pending_activation_expires_at: value.pending_activation_expires_at,
            created_at: value.created_at,
            last_seen_at: value.last_seen_at,
            row_version,
        }
    }
}

impl From<Versioned<Device>> for AdminDevice {
    fn from(value: Versioned<Device>) -> Self {
        Self::new(value.value, value.row_version)
    }
}

impl From<Page<Versioned<Device>>> for AdminPage<AdminDevice> {
    fn from(value: Page<Versioned<Device>>) -> Self {
        Self {
            items: value.items.into_iter().map(AdminDevice::from).collect(),
            next_cursor: value.next_cursor,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdminActivationCode {
    pub code_hash: String,
    pub code_prefix: String,
    pub account_id: String,
    pub license_id: Option<String>,
    pub status: ActivationCodeStatus,
    pub max_redemptions: u32,
    pub redeemed_count: u32,
    pub expires_at: Option<i64>,
    pub consumed_at: Option<i64>,
    pub consumed_device_id: Option<String>,
    pub last_redeemed_at: Option<i64>,
    pub last_redeemed_device_id: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    pub note: Option<String>,
    pub order_id: Option<String>,
    pub channel: Option<String>,
    pub issued_by: Option<String>,
    pub revoked_reason: Option<String>,
    pub last_admin_reason: Option<String>,
    pub row_version: i64,
}

impl AdminActivationCode {
    pub fn new(value: ActivationCodeRecord, row_version: i64) -> Self {
        Self {
            code_hash: value.code_hash,
            code_prefix: value.code_prefix,
            account_id: value.account_id,
            license_id: value.license_id,
            status: value.status,
            max_redemptions: value.max_redemptions,
            redeemed_count: value.redeemed_count,
            expires_at: value.expires_at,
            consumed_at: value.consumed_at,
            consumed_device_id: value.consumed_device_id,
            last_redeemed_at: value.last_redeemed_at,
            last_redeemed_device_id: value.last_redeemed_device_id,
            created_at: value.created_at,
            updated_at: value.updated_at,
            note: value.note,
            order_id: value.order_id,
            channel: value.channel,
            issued_by: value.issued_by,
            revoked_reason: value.revoked_reason,
            last_admin_reason: value.last_admin_reason,
            row_version,
        }
    }
}

impl From<Versioned<ActivationCodeRecord>> for AdminActivationCode {
    fn from(value: Versioned<ActivationCodeRecord>) -> Self {
        Self::new(value.value, value.row_version)
    }
}

impl From<Page<Versioned<ActivationCodeRecord>>> for AdminPage<AdminActivationCode> {
    fn from(value: Page<Versioned<ActivationCodeRecord>>) -> Self {
        Self {
            items: value
                .items
                .into_iter()
                .map(AdminActivationCode::from)
                .collect(),
            next_cursor: value.next_cursor,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdminAuditEvent {
    pub id: String,
    pub event_type: String,
    pub outcome: String,
    pub occurred_at: i64,
    pub account_id: Option<String>,
    pub license_id: Option<String>,
    pub device_id: Option<String>,
    pub reason_code: Option<String>,
    pub metadata: std::collections::BTreeMap<String, String>,
}

impl From<AuditEventRecord> for AdminAuditEvent {
    fn from(value: AuditEventRecord) -> Self {
        Self {
            id: value.id,
            event_type: value.event_type,
            outcome: value.outcome,
            occurred_at: value.occurred_at,
            account_id: value.account_id,
            license_id: value.license_id,
            device_id: value.device_id,
            reason_code: value.reason_code,
            metadata: value.metadata,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use serde_json::Value;

    use super::*;
    use crate::{
        admin_auth::AdminRole,
        admin_storage::{ObjectBackend, ObjectStorageStatus},
        contracts::DeviceRegistrationMetadata,
    };

    fn golden() -> Value {
        serde_json::from_str(include_str!("../admin-ui/tests/fixtures/admin-wire.json"))
            .expect("admin wire golden must be valid JSON")
    }

    #[test]
    fn provider_wire_contract_matches_shared_admin_ui_golden() {
        let expected = golden();
        let account = Account {
            id: "acct_golden".to_owned(),
            state: AccountState::Active,
            note: Some("Golden customer".to_owned()),
            created_at: 1_700_000_000,
            updated_at: 1_700_000_100,
        };
        let accounts: AdminPage<AdminAccount> = Page {
            items: vec![Versioned {
                value: account,
                row_version: 7,
            }],
            next_cursor: Some("acct_next".to_owned()),
        }
        .into();
        assert_eq!(
            serde_json::to_value(accounts).expect("serialize accounts"),
            expected["accounts"]
        );

        let license = License {
            id: "lic_golden".to_owned(),
            account_id: "acct_golden".to_owned(),
            plan: Plan::Team,
            plan_revision: crate::plan_catalog::CURRENT_PLAN_REVISION,
            status: LicenseStatus::Active,
            expires_at: None,
            license_epoch: 4,
            purchased_seats: 12,
            row_version: 11,
        };
        let licenses: AdminPage<AdminLicense> = Page {
            items: vec![Versioned {
                value: license,
                row_version: 11,
            }],
            next_cursor: None,
        }
        .into();
        assert_eq!(
            serde_json::to_value(licenses).expect("serialize licenses"),
            expected["licenses"]
        );

        let code = ActivationCodeRecord {
            code_hash: "a".repeat(64),
            code_prefix: "CNX1-GOLDEN".to_owned(),
            account_id: "acct_golden".to_owned(),
            license_id: Some("lic_golden".to_owned()),
            status: ActivationCodeStatus::Active,
            max_redemptions: 3,
            redeemed_count: 1,
            expires_at: Some(1_800_000_000),
            consumed_at: None,
            consumed_device_id: None,
            last_redeemed_at: Some(1_700_000_200),
            last_redeemed_device_id: Some("00000000-0000-4000-8000-000000000001".to_owned()),
            created_at: 1_700_000_000,
            updated_at: 1_700_000_200,
            note: Some("Golden batch".to_owned()),
            order_id: Some("order_golden".to_owned()),
            channel: Some("contract_test".to_owned()),
            issued_by: Some("admin_golden".to_owned()),
            revoked_reason: None,
            last_admin_reason: None,
        };
        let activation_codes: AdminPage<AdminActivationCode> = Page {
            items: vec![Versioned {
                value: code,
                row_version: 5,
            }],
            next_cursor: None,
        }
        .into();
        assert_eq!(
            serde_json::to_value(activation_codes).expect("serialize activation codes"),
            expected["activationCodes"]
        );

        let device = Device {
            account_id: "acct_golden".to_owned(),
            license_id: "lic_golden".to_owned(),
            metadata: DeviceRegistrationMetadata {
                device_id: "00000000-0000-4000-8000-000000000001".to_owned(),
                public_key_pem: "not part of the Admin wire response".to_owned(),
                public_key_thumbprint: "sha256:golden".to_owned(),
                platform: "windows".to_owned(),
                app_version: "1.0.0".to_owned(),
                display_name: Some("Golden laptop".to_owned()),
            },
            state: DeviceState::Active,
            pending_activation_code_hash: Some("not part of the Admin wire response".to_owned()),
            pending_activation_expires_at: None,
            created_at: 1_700_000_000,
            last_seen_at: Some(1_700_000_300),
        };
        let devices: AdminPage<AdminDevice> = Page {
            items: vec![Versioned {
                value: device,
                row_version: 9,
            }],
            next_cursor: None,
        }
        .into();
        assert_eq!(
            serde_json::to_value(devices).expect("serialize devices"),
            expected["devices"]
        );

        let audit = AdminAuditEvent::from(AuditEventRecord {
            id: "audit_golden".to_owned(),
            event_type: "license_status_set".to_owned(),
            outcome: "succeeded".to_owned(),
            occurred_at: 1_700_000_400,
            account_id: Some("acct_golden".to_owned()),
            license_id: Some("lic_golden".to_owned()),
            device_id: None,
            reason_code: None,
            metadata: BTreeMap::from([("actor".to_owned(), "admin_golden".to_owned())]),
        });
        assert_eq!(
            serde_json::to_value(vec![audit]).expect("serialize audit events"),
            expected["auditEvents"]
        );

        let dashboard = AdminDashboard {
            generated_at: 1_700_000_500,
            accounts: 42,
            active_licenses: 31,
            active_devices: 57,
            risky_devices: 2,
            pending_payments: 3,
            open_invoices: 4,
        };
        assert_eq!(
            serde_json::to_value(dashboard).expect("serialize dashboard"),
            expected["dashboard"]
        );

        let session_info = AdminSessionInfo {
            user: AdminUser {
                id: "admin_golden".to_owned(),
                username: "operator".to_owned(),
                display_name: "Golden Operator".to_owned(),
                status: "active".to_owned(),
                roles: BTreeSet::from([AdminRole::PlatformOwner]),
                row_version: 7,
            },
            permissions: vec!["system.read".to_owned()],
            expires_at: 1_700_003_600,
            elevated_until: 1_700_000_600,
            server_version: "1.0.1".to_owned(),
        };
        assert_eq!(
            serde_json::to_value(session_info).expect("serialize Admin session"),
            expected["sessionInfo"]
        );

        let system_status = AdminSystemStatus {
            status: AdminReadiness::Ready,
            version: "1.0.1".to_owned(),
            server_unix: 1_700_000_500,
            started_at: 1_700_000_000,
            admin_origin: "https://admin.example.test".to_owned(),
            database: AdminReadiness::Ready,
            time_authority: AdminReadiness::Ready,
            object_storage: ObjectStorageStatus {
                backend: ObjectBackend::Database,
                object_count: 8,
                stored_bytes: 4_096,
                hard_limit_bytes: 1_048_576,
                usage_ratio: 0.003_906_25,
            },
        };
        assert_eq!(
            serde_json::to_value(system_status).expect("serialize system status"),
            expected["systemStatus"]
        );

        let team_workspaces = AdminPage {
            items: vec![AdminTeamWorkspace {
                account_id: "acct_golden".to_owned(),
                license_id: "lic_golden".to_owned(),
                purchased_seats: 12,
                occupied_members: 5,
                active_members: 4,
                member_count: 6,
            }],
            next_cursor: Some("lic_next".to_owned()),
        };
        assert_eq!(
            serde_json::to_value(team_workspaces).expect("serialize Team workspaces"),
            expected["teamWorkspaces"]
        );

        let team_members = AdminPage {
            items: vec![AdminTeamMember {
                id: "member_golden".to_owned(),
                email: "owner@example.test".to_owned(),
                display_name: "Golden Owner".to_owned(),
                role: WorkspaceRole::Owner,
                status: WorkspaceMemberStatus::Active,
                row_version: 3,
                created_at: 1_700_000_000,
                updated_at: 1_700_000_400,
                profile_pending: false,
            }],
            next_cursor: None,
        };
        assert_eq!(
            serde_json::to_value(team_members).expect("serialize Team members"),
            expected["teamMembers"]
        );

        let team_invitations = AdminPage {
            items: vec![AdminTeamInvitation {
                id: "team_invite_golden".to_owned(),
                member_id: "member_invited".to_owned(),
                email: "viewer@example.test".to_owned(),
                display_name: "Golden Viewer".to_owned(),
                role: WorkspaceRole::Viewer,
                expires_at: 1_700_604_800,
                accepted_at: None,
                revoked_at: None,
                created_at: 1_700_000_000,
            }],
            next_cursor: None,
        };
        assert_eq!(
            serde_json::to_value(team_invitations).expect("serialize Team invitations"),
            expected["teamInvitations"]
        );

        let payment_evidence = AdminItems {
            items: vec![AdminPaymentEvidence {
                id: "evidence_golden".to_owned(),
                object_id: "object_golden".to_owned(),
                original_name: "receipt.pdf".to_owned(),
                media_type: "application/pdf".to_owned(),
                byte_length: 4_096,
                sha256: "b".repeat(64),
                scan_status: "clean".to_owned(),
                created_at: 1_700_000_300,
                scanned_at: Some(1_700_000_310),
            }],
        };
        assert_eq!(
            serde_json::to_value(payment_evidence).expect("serialize payment evidence"),
            expected["paymentEvidence"]
        );
    }

    #[test]
    fn persistence_and_admin_wire_serde_remain_separate() {
        let license = License {
            id: "lic_golden".to_owned(),
            account_id: "acct_golden".to_owned(),
            plan: Plan::Pro,
            plan_revision: crate::plan_catalog::CURRENT_PLAN_REVISION,
            status: LicenseStatus::Active,
            expires_at: None,
            license_epoch: 1,
            purchased_seats: 0,
            row_version: 3,
        };
        let persistence = serde_json::to_value(&license).expect("serialize persistence document");
        assert_eq!(persistence["account_id"], "acct_golden");
        assert_eq!(persistence["row_version"], 3);
        assert!(persistence.get("accountId").is_none());

        let wire = serde_json::to_value(AdminLicense::new(license, 3))
            .expect("serialize Admin wire response");
        assert_eq!(wire["accountId"], "acct_golden");
        assert_eq!(wire["rowVersion"], 3);
        assert!(wire.get("account_id").is_none());
        assert!(wire.get("row_version").is_none());
    }
}
