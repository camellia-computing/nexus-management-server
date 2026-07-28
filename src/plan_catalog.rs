use std::collections::BTreeMap;

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{
    contracts::{Capability, NumericLimit, Plan},
    error::{ApiError, Result},
};

pub const CURRENT_PLAN_REVISION: u32 = 2;
pub const TEAM_MINIMUM_SEATS: u32 = 3;
pub const TEAM_MAXIMUM_SEATS: u32 = 10_000;
pub const TEAM_DEVICES_PER_SEAT: u32 = 3;
pub const TEAM_WORKSPACE_STORAGE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
pub const TEAM_MAX_ALERT_RULES: u64 = 50;
pub const TEAM_MAX_AUDIT_EXPORT_EVENTS: u64 = 5_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EffectivePlanPolicy {
    pub plan: Plan,
    pub revision: u32,
    pub capabilities: Vec<Capability>,
    pub limits: BTreeMap<NumericLimit, u64>,
    pub device_limit: u32,
    pub member_limit: u32,
}

impl EffectivePlanPolicy {
    pub fn policy_hash(&self) -> String {
        let canonical = serde_json::to_vec(self).expect("plan policy is serializable");
        Sha256::digest(canonical)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
}

pub fn effective_policy(
    plan: Plan,
    revision: u32,
    purchased_seats: u32,
) -> Result<EffectivePlanPolicy> {
    if revision != CURRENT_PLAN_REVISION {
        return Err(ApiError::InvalidRequest);
    }
    validate_purchased_seats(plan, purchased_seats)?;

    let policy = match plan {
        Plan::Free => EffectivePlanPolicy {
            plan,
            revision,
            capabilities: vec![],
            limits: limits(PlanLimitValues {
                max_programs: 5,
                max_members: 1,
                ..PlanLimitValues::default()
            }),
            device_limit: 1,
            member_limit: 1,
        },
        Plan::Pro => EffectivePlanPolicy {
            plan,
            revision,
            capabilities: vec![
                Capability::ManagedConfigSources,
                Capability::AdvancedDiagnostics,
                Capability::RemoteDashboard,
                Capability::ManagedProgramPackages,
            ],
            limits: limits(PlanLimitValues {
                max_programs: 50,
                max_sources: 20,
                max_members: 1,
                max_monitors: 3,
                ..PlanLimitValues::default()
            }),
            device_limit: 3,
            member_limit: 1,
        },
        Plan::Team => EffectivePlanPolicy {
            plan,
            revision,
            capabilities: vec![
                Capability::ManagedConfigSources,
                Capability::AdvancedDiagnostics,
                Capability::RemoteDashboard,
                Capability::ManagedProgramPackages,
                Capability::CloudSync,
                Capability::SharedConfigurations,
                Capability::TeamAdministration,
                Capability::Alerts,
                Capability::AuditLog,
                Capability::Webhooks,
            ],
            limits: limits(PlanLimitValues {
                max_programs: 50,
                max_sources: 50,
                max_members: purchased_seats,
                max_monitors: 20,
                max_shared_programs: 200,
                max_webhooks: 5,
                max_workspace_storage_bytes: TEAM_WORKSPACE_STORAGE_BYTES,
                max_alert_rules: TEAM_MAX_ALERT_RULES,
                max_audit_export_events: TEAM_MAX_AUDIT_EXPORT_EVENTS,
            }),
            device_limit: purchased_seats.saturating_mul(TEAM_DEVICES_PER_SEAT),
            member_limit: purchased_seats,
        },
    };

    Ok(policy)
}

pub fn validate_purchased_seats(plan: Plan, purchased_seats: u32) -> Result<()> {
    match plan {
        Plan::Team if (TEAM_MINIMUM_SEATS..=TEAM_MAXIMUM_SEATS).contains(&purchased_seats) => {
            Ok(())
        }
        Plan::Team => Err(ApiError::InvalidRequest),
        Plan::Free | Plan::Pro if purchased_seats == 0 => Ok(()),
        Plan::Free | Plan::Pro => Err(ApiError::InvalidRequest),
    }
}

#[derive(Default)]
struct PlanLimitValues {
    max_programs: u64,
    max_sources: u64,
    max_members: u32,
    max_monitors: u64,
    max_shared_programs: u64,
    max_webhooks: u64,
    max_workspace_storage_bytes: u64,
    max_alert_rules: u64,
    max_audit_export_events: u64,
}

fn limits(values: PlanLimitValues) -> BTreeMap<NumericLimit, u64> {
    BTreeMap::from([
        (NumericLimit::MaxPrograms, values.max_programs),
        (NumericLimit::MaxConfigSourcesPerProgram, values.max_sources),
        (NumericLimit::MaxTeamMembers, u64::from(values.max_members)),
        (NumericLimit::MaxRemoteMonitors, values.max_monitors),
        (NumericLimit::MaxSharedPrograms, values.max_shared_programs),
        (NumericLimit::MaxWebhookEndpoints, values.max_webhooks),
        (
            NumericLimit::MaxWorkspaceStorageBytes,
            values.max_workspace_storage_bytes,
        ),
        (NumericLimit::MaxAlertRules, values.max_alert_rules),
        (
            NumericLimit::MaxAuditExportEvents,
            values.max_audit_export_events,
        ),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_is_complete_and_deterministic() {
        let free = effective_policy(Plan::Free, CURRENT_PLAN_REVISION, 0).unwrap();
        let pro = effective_policy(Plan::Pro, CURRENT_PLAN_REVISION, 0).unwrap();
        let team = effective_policy(Plan::Team, CURRENT_PLAN_REVISION, 3).unwrap();

        assert_eq!(free.device_limit, 1);
        assert_eq!(free.limits[&NumericLimit::MaxPrograms], 5);
        assert!(free.capabilities.is_empty());
        assert_eq!(pro.device_limit, 3);
        assert_eq!(pro.limits[&NumericLimit::MaxConfigSourcesPerProgram], 20);
        assert_eq!(team.device_limit, 9);
        assert_eq!(team.member_limit, 3);
        assert_eq!(team.limits[&NumericLimit::MaxSharedPrograms], 200);
        assert_eq!(
            team.limits[&NumericLimit::MaxWorkspaceStorageBytes],
            TEAM_WORKSPACE_STORAGE_BYTES
        );
        assert_eq!(team.limits[&NumericLimit::MaxAlertRules], 50);
        assert_eq!(team.limits[&NumericLimit::MaxAuditExportEvents], 5_000);
        assert_eq!(team.policy_hash(), team.policy_hash());
    }

    #[test]
    fn team_requires_three_seats_and_unknown_revisions_fail_closed() {
        assert_eq!(CURRENT_PLAN_REVISION, 2);
        assert!(effective_policy(Plan::Team, CURRENT_PLAN_REVISION, 2).is_err());
        assert!(effective_policy(Plan::Pro, CURRENT_PLAN_REVISION + 1, 0).is_err());
    }

    #[test]
    fn seat_quantity_is_canonical_for_every_plan() {
        assert!(validate_purchased_seats(Plan::Free, 0).is_ok());
        assert!(validate_purchased_seats(Plan::Pro, 0).is_ok());
        assert!(validate_purchased_seats(Plan::Free, 3).is_err());
        assert!(validate_purchased_seats(Plan::Team, 2).is_err());
        assert!(validate_purchased_seats(Plan::Team, 3).is_ok());
        assert!(validate_purchased_seats(Plan::Team, TEAM_MAXIMUM_SEATS).is_ok());
        assert!(validate_purchased_seats(Plan::Team, TEAM_MAXIMUM_SEATS + 1).is_err());
    }
}
