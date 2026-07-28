export type AccountState = 'active' | 'suspended' | 'denylisted';
export type LicensePlan = 'free' | 'pro' | 'team';
export type LicenseStatus = 'active' | 'past_due' | 'canceled';
export type ActivationCodeStatus = 'active' | 'consumed' | 'revoked';
export type DeviceState = 'active' | 'pending_activation' | 'removed' | 'revoked' | 'suspicious';

export interface AdminPage<T> {
  items: T[];
  nextCursor: string | null;
}

export interface AdminItems<T> {
  items: T[];
}

export interface AdminAccount extends Record<string, unknown> {
  id: string;
  state: AccountState;
  note: string | null;
  createdAt: number;
  updatedAt: number;
  rowVersion: number;
}

export interface AdminLicense extends Record<string, unknown> {
  id: string;
  accountId: string;
  plan: LicensePlan;
  planRevision: number;
  status: LicenseStatus;
  expiresAt: number | null;
  licenseEpoch: number;
  purchasedSeats: number;
  rowVersion: number;
}

export interface AdminActivationCode extends Record<string, unknown> {
  codeHash: string;
  codePrefix: string;
  accountId: string;
  licenseId: string | null;
  status: ActivationCodeStatus;
  maxRedemptions: number;
  redeemedCount: number;
  expiresAt: number | null;
  consumedAt: number | null;
  consumedDeviceId: string | null;
  lastRedeemedAt: number | null;
  lastRedeemedDeviceId: string | null;
  createdAt: number;
  updatedAt: number;
  note: string | null;
  orderId: string | null;
  channel: string | null;
  issuedBy: string | null;
  revokedReason: string | null;
  lastAdminReason: string | null;
  rowVersion: number;
}

export interface AdminDevice extends Record<string, unknown> {
  deviceId: string;
  accountId: string;
  licenseId: string;
  publicKeyThumbprint: string;
  platform: string;
  appVersion: string;
  displayName: string | null;
  state: DeviceState;
  pendingActivationExpiresAt: number | null;
  createdAt: number;
  lastSeenAt: number | null;
  rowVersion: number;
}

export interface AdminAuditEvent extends Record<string, unknown> {
  id: string;
  eventType: string;
  outcome: string;
  occurredAt: number;
  accountId: string | null;
  licenseId: string | null;
  deviceId: string | null;
  reasonCode: string | null;
  metadata: Record<string, string>;
}

export interface AdminBulkJob extends Record<string, unknown> {
  id: string;
  kind: string;
  status: string;
  actorId: string;
  reason: string;
  parameters: unknown;
  totalItems: number;
  completedItems: number;
  failedItems: number;
  createdAt: number;
  startedAt: number | null;
  finishedAt: number | null;
}

export type AdminVersionedResource =
  AdminAccount | AdminLicense | AdminActivationCode | AdminDevice;

export interface CreateAccountRequest {
  id: string;
  note: string | null;
  reason: string;
}

export interface CreateLicenseRequest {
  id: string;
  accountId: string;
  plan: LicensePlan;
  status: LicenseStatus;
  expiresAt: string | null;
  purchasedSeats: number;
  reason: string;
}

export interface IssueActivationCodesRequest {
  accountId: string;
  licenseId: string;
  count: number;
  maxRedemptions: number;
  expiresAt: string | null;
  channel: string | null;
  note: string | null;
  reason: string;
}

export interface ActivationCodeActionRequest {
  reason: string;
  maxRedemptions: number | null;
  /** Expiry expression accepted by the server: Unix seconds encoded as text, RFC3339 or date. */
  expiresAt: string | null;
}

export interface SecretDeliveryTicket {
  id: string;
  claimToken: string;
  expiresAt: number;
}

export interface ActivationCodeDeliveryResponse {
  delivery: SecretDeliveryTicket;
  count: number;
  acknowledgementRequired: boolean;
}

export interface DeliveredActivationCode {
  code: string;
}

export interface AdminBulkJobPreview {
  id: string;
  expiresAt?: number;
}

export interface AdminDashboard {
  generatedAt: number;
  accounts: number;
  activeLicenses: number;
  activeDevices: number;
  riskyDevices: number;
  pendingPayments: number;
  openInvoices: number;
}

export interface ObjectStorageStatus {
  backend: 'filesystem' | 'database' | 's3';
  objectCount: number;
  storedBytes: number;
  hardLimitBytes: number;
  usageRatio: number;
}

export interface AdminSystemStatus {
  status: 'ready';
  version: string;
  serverUnix: number;
  startedAt: number;
  adminOrigin: string;
  database: 'ready';
  timeAuthority: 'ready';
  objectStorage: ObjectStorageStatus;
}

export interface AdminPaymentEvidence {
  id: string;
  objectId: string;
  originalName: string;
  mediaType: string;
  byteLength: number;
  sha256: string;
  scanStatus: string;
  createdAt: number;
  scannedAt: number | null;
}

export interface AdminTeamWorkspace extends Record<string, unknown> {
  accountId: string;
  licenseId: string;
  purchasedSeats: number;
  occupiedMembers: number;
  activeMembers: number;
  memberCount: number;
}

export type TeamMemberRole = 'owner' | 'admin' | 'billing' | 'operator' | 'viewer' | 'auditor';
export type TeamMemberStatus = 'invited' | 'active' | 'suspended' | 'removed';

export interface AdminTeamMember {
  id: string;
  email: string;
  displayName: string;
  role: TeamMemberRole;
  status: TeamMemberStatus;
  rowVersion: number;
  createdAt: number;
  updatedAt: number;
  profilePending: boolean;
}

export interface AdminTeamInvitation {
  id: string;
  memberId: string;
  email: string;
  displayName: string;
  role: TeamMemberRole;
  expiresAt: number;
  acceptedAt: number | null;
  revokedAt: number | null;
  createdAt: number;
}

export interface TeamInvitationDeliveryResponse {
  delivery: SecretDeliveryTicket;
  acknowledgementRequired: boolean;
}

export interface TeamInvitationSecret {
  invitationToken: string;
}
