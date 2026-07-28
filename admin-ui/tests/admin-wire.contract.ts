import type {
  AccountState,
  ActivationCodeActionRequest,
  ActivationCodeStatus,
  AdminAccount,
  AdminActivationCode,
  AdminAuditEvent,
  AdminDashboard,
  AdminDevice,
  AdminItems,
  AdminLicense,
  AdminPage,
  AdminPaymentEvidence,
  AdminSystemStatus,
  AdminTeamInvitation,
  AdminTeamMember,
  AdminTeamWorkspace,
  CreateAccountRequest,
  CreateLicenseRequest,
  DeviceState,
  IssueActivationCodesRequest,
  LicensePlan,
  LicenseStatus,
  TeamMemberRole,
  TeamMemberStatus
} from '../src/lib/admin-contracts';
import type { SessionInfo } from '../src/lib/api';
import golden from './fixtures/admin-wire.json';

function oneOf<T extends string>(value: string, accepted: readonly T[]): T {
  if (!accepted.includes(value as T)) throw new Error(`unknown contract enum value: ${value}`);
  return value as T;
}

const accounts: AdminPage<AdminAccount> = {
  ...golden.accounts,
  items: golden.accounts.items.map((item) => ({
    ...item,
    state: oneOf<AccountState>(item.state, ['active', 'suspended', 'denylisted'])
  }))
};

const licenses: AdminPage<AdminLicense> = {
  ...golden.licenses,
  items: golden.licenses.items.map((item) => ({
    ...item,
    plan: oneOf<LicensePlan>(item.plan, ['free', 'pro', 'team']),
    status: oneOf<LicenseStatus>(item.status, ['active', 'past_due', 'canceled'])
  }))
};

const activationCodes: AdminPage<AdminActivationCode> = {
  ...golden.activationCodes,
  items: golden.activationCodes.items.map((item) => ({
    ...item,
    status: oneOf<ActivationCodeStatus>(item.status, ['active', 'consumed', 'revoked'])
  }))
};

const devices: AdminPage<AdminDevice> = {
  ...golden.devices,
  items: golden.devices.items.map((item) => ({
    ...item,
    state: oneOf<DeviceState>(item.state, [
      'active',
      'pending_activation',
      'removed',
      'revoked',
      'suspicious'
    ])
  }))
};

const auditEvents: AdminAuditEvent[] = golden.auditEvents;
const dashboard: AdminDashboard = golden.dashboard;
const sessionInfo: SessionInfo = golden.sessionInfo;
const systemStatus: AdminSystemStatus = {
  ...golden.systemStatus,
  status: oneOf<AdminSystemStatus['status']>(golden.systemStatus.status, ['ready']),
  database: oneOf<AdminSystemStatus['database']>(golden.systemStatus.database, ['ready']),
  timeAuthority: oneOf<AdminSystemStatus['timeAuthority']>(golden.systemStatus.timeAuthority, [
    'ready'
  ]),
  objectStorage: {
    ...golden.systemStatus.objectStorage,
    backend: oneOf<AdminSystemStatus['objectStorage']['backend']>(
      golden.systemStatus.objectStorage.backend,
      ['filesystem', 'database', 's3']
    )
  }
};
const teamWorkspaces: AdminPage<AdminTeamWorkspace> = golden.teamWorkspaces;
const teamMembers: AdminPage<AdminTeamMember> = {
  ...golden.teamMembers,
  items: golden.teamMembers.items.map((item) => ({
    ...item,
    role: oneOf<TeamMemberRole>(item.role, [
      'owner',
      'admin',
      'billing',
      'operator',
      'viewer',
      'auditor'
    ]),
    status: oneOf<TeamMemberStatus>(item.status, ['invited', 'active', 'suspended', 'removed'])
  }))
};
const teamInvitations: AdminPage<AdminTeamInvitation> = {
  ...golden.teamInvitations,
  items: golden.teamInvitations.items.map((item) => ({
    ...item,
    role: oneOf<TeamMemberRole>(item.role, [
      'owner',
      'admin',
      'billing',
      'operator',
      'viewer',
      'auditor'
    ])
  }))
};
const paymentEvidence: AdminItems<AdminPaymentEvidence> = golden.paymentEvidence;
const createAccountRequest: CreateAccountRequest = golden.createAccountRequest;
const createLicenseRequest: CreateLicenseRequest = {
  ...golden.createLicenseRequest,
  plan: oneOf<LicensePlan>(golden.createLicenseRequest.plan, ['free', 'pro', 'team']),
  status: oneOf<LicenseStatus>(golden.createLicenseRequest.status, [
    'active',
    'past_due',
    'canceled'
  ])
};
const issueActivationCodesRequest: IssueActivationCodesRequest = golden.issueActivationCodesRequest;
const activationCodeExpireRequest: ActivationCodeActionRequest = golden.activationCodeExpireRequest;

// These references keep every provider fixture in the TypeScript consumer program. `svelte-check`
// fails if a server field is renamed, nested again, or changes type.
void [
  accounts,
  licenses,
  activationCodes,
  devices,
  auditEvents,
  dashboard,
  sessionInfo,
  systemStatus,
  teamWorkspaces,
  teamMembers,
  teamInvitations,
  paymentEvidence,
  createAccountRequest,
  createLicenseRequest,
  issueActivationCodesRequest,
  activationCodeExpireRequest
];
