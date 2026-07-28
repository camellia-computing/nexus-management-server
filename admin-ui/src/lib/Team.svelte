<script lang="ts">
  import { ArrowRight, Plus, RefreshCw, UsersRound, X } from '@lucide/svelte';
  import { onMount } from 'svelte';
  import { api, ApiError, isVersionConflict, MutationAttempt } from './api';
  import type {
    AdminPage,
    AdminTeamInvitation,
    AdminTeamMember,
    AdminTeamWorkspace,
    TeamInvitationDeliveryResponse,
    TeamInvitationSecret
  } from './admin-contracts';
  import { focusTrap } from './actions/focusTrap';
  import { teamRoleLabel } from './domainLabels';
  import { copy, defineCopy, locale, localeTag } from './i18n';
  import { setResourceIntent } from './resourceIntent';
  import ResourceTable from './ResourceTable.svelte';

  let {
    permissions,
    onNavigate
  }: {
    permissions: string[];
    onNavigate: (id: string) => void;
  } = $props();

  type Page<T> = Partial<AdminPage<T>>;
  type Workspace = AdminTeamWorkspace;
  type Member = AdminTeamMember;
  type Invitation = AdminTeamInvitation;

  const messages = defineCopy(
    {
      title: 'Team 工作区',
      description: '管理组织席位、成员角色与待接受邀请。',
      createInvitation: '创建邀请',
      operations: '团队运营',
      heroTitle: '让成员权限与商业席位保持一致',
      heroDetail: '所有成员变更都受版本校验、原因记录和完整审计保护。',
      viewMatrix: '查看权限矩阵',
      workspaces: '工作区',
      workspaceDetail: 'Team 套餐下的组织与席位使用情况',
      refresh: '刷新 Team 工作区',
      account: '账户',
      license: '授权',
      purchasedSeats: '购买席位',
      occupiedSeats: '占用席位',
      activeMembers: '活跃成员',
      memberRecords: '成员记录',
      loading: '正在加载…',
      loadMoreWorkspaces: '加载更多工作区',
      inviteMember: '邀请工作区成员',
      tokenOnce: '邀请令牌仅显示一次',
      tokenDetail: '请通过可信渠道发送给受邀成员；它不能替代设备激活码。',
      activationRequired: '设备必须先完成授权激活',
      activationDetail:
        '接收邀请的设备需要先使用属于同一 Team 授权的一次性激活码，再输入邀请令牌绑定成员身份。',
      issueActivationCode: '前往签发激活码',
      copyToken: '复制邀请令牌',
      copied: '邀请令牌已复制',
      copyFailed: '无法复制，请手动选择邀请令牌',
      acknowledging: '正在确认…',
      acknowledge: '已安全保存并销毁交付',
      teamAccount: 'Team 账户',
      memberRole: '成员角色',
      memberStatus: '成员状态',
      email: '邮箱',
      displayName: '显示名称',
      reason: '操作原因',
      cancel: '取消',
      processing: '正在处理…',
      retryToken: '重试领取邀请令牌',
      changeReason: '变更原因',
      reasonPlaceholder: '成员更新、所有权转移、移除和邀请撤销将使用此审计原因',
      members: '成员',
      roleFor: '{name} 的角色',
      statusFor: '{name} 的状态',
      save: '保存',
      discardChanges: '撤销更改',
      transferOwner: '转让所有权',
      remove: '移除',
      loadMoreMembers: '加载更多成员',
      invitations: '邀请',
      expires: '到期：',
      revoke: '撤销',
      loadMoreInvitations: '加载更多邀请记录',
      closeWorkspace: '关闭工作区管理',
      close: '关闭',
      transferTitle: '确认转让工作区所有权',
      soleOwner: '{name} 将成为唯一所有者',
      transferDetail: '当前所有者会降级为管理员。此操作要求近期二次验证并写入审计日志。',
      transferring: '正在转让…',
      confirmTransfer: '确认转让',
      removeTitle: '确认移除工作区成员',
      cancelRemoval: '取消移除成员',
      losesAccess: '{name} 将立即失去 Team 访问权限',
      removeDetail:
        '所有刷新会话、设备绑定和未使用令牌会在同一事务中撤销。重新加入必须签发新邀请。',
      removing: '正在移除…',
      confirmRemoval: '确认移除',
      matrixTitle: '成员权限矩阵',
      invitationEyebrow: 'Team / 邀请',
      workspaceEyebrow: 'Team / 工作区',
      ownerEyebrow: 'Team / 所有者',
      ownershipEyebrow: 'Team / 所有权',
      removalEyebrow: 'Team / 移除成员',
      permissionsEyebrow: 'Team / 权限',
      ownerPermissions:
        '成员治理和所有权转移、账单读写、共享配置发布与清除、同步、告警、审计导出及 Webhook 管理',
      adminPermissions:
        '日常成员管理、账单只读、共享配置与发布、同步、告警、审计和 Webhook；不能转移所有权、修改同级管理员或提交付款',
      billingPermissions: '只负责账单读取和付款凭证提交，不具有成员及云工作区权限',
      operatorPermissions:
        '读取成员与共享配置，可编辑草稿和同步，可读取并确认告警；不能发布或管理成员',
      auditorPermissions:
        '只读成员、告警历史、审计与导出及 Webhook 投递元数据；不可查看 Webhook 密钥或正文',
      viewerPermissions: '只读成员、共享配置、同步状态与当前告警',
      done: '完成',
      workspaceLoadFailed: '工作区加载失败',
      workspaceMembersFailed: '工作区成员加载失败',
      membersFailed: '成员加载失败',
      invitationsFailed: '邀请加载失败',
      inviteFailed: '邀请失败',
      acknowledgeFailed: '交付确认失败',
      updateFailed: '成员更新失败',
      transferFailed: '所有权转移失败',
      revokeFailed: '撤销失败',
      missingDelivery: '服务端未返回邀请交付凭据',
      claimPending: '邀请已创建，但令牌尚未成功领取。请使用同一交付凭据重试，避免生成重复邀请。',
      active: '活跃',
      suspended: '已暂停',
      invited: '待接受',
      removed: '已移除',
      noMembers: '此工作区暂无成员记录',
      noInvitations: '此工作区暂无待接受邀请',
      noWorkspaces: '暂无 Team 工作区。请先为账户配置有效的 Team 授权和席位。',
      completeOwnerProfile: '完善所有者资料',
      ownerProfileTitle: '完善首位所有者资料',
      ownerProfileDetail: '占位资料仅用于初始化。请填写真实的联系邮箱与显示名称。',
      ownerProfileFailed: '所有者资料更新失败',
      workspaceChanged: '工作区已在其他会话中更新。已加载最新状态，请复核后重试。',
      emailInvalid: '请输入有效的邮箱地址。',
      displayNameInvalid: '显示名称必须包含 1–160 个字符。',
      complete: '完成资料'
    },
    {
      title: 'Team workspaces',
      description: 'Manage organization seats, member roles, and pending invitations.',
      createInvitation: 'Create invitation',
      operations: 'Team operations',
      heroTitle: 'Keep member permissions aligned with commercial seats',
      heroDetail:
        'Every membership change is protected by version checks, recorded reasons, and a complete audit trail.',
      viewMatrix: 'View permission matrix',
      workspaces: 'Workspaces',
      workspaceDetail: 'Organizations and seat usage under Team plans',
      refresh: 'Refresh Team workspaces',
      account: 'Account',
      license: 'License',
      purchasedSeats: 'Purchased seats',
      occupiedSeats: 'Occupied seats',
      activeMembers: 'Active members',
      memberRecords: 'Member records',
      loading: 'Loading…',
      loadMoreWorkspaces: 'Load more workspaces',
      inviteMember: 'Invite workspace member',
      tokenOnce: 'Invitation token is shown only once',
      tokenDetail:
        'Send it through a trusted channel; it does not replace a device activation code.',
      activationRequired: 'The device must be license-activated first',
      activationDetail:
        'The invited device must first redeem a one-use activation code for the same Team license, then enter the invitation token to bind its member identity.',
      issueActivationCode: 'Issue activation code',
      copyToken: 'Copy invitation token',
      copied: 'Invitation token copied',
      copyFailed: 'Copy failed; select the invitation token manually',
      acknowledging: 'Acknowledging…',
      acknowledge: 'Stored securely; destroy delivery',
      teamAccount: 'Team account',
      memberRole: 'Member role',
      memberStatus: 'Member status',
      email: 'Email',
      displayName: 'Display name',
      reason: 'Operation reason',
      cancel: 'Cancel',
      processing: 'Processing…',
      retryToken: 'Retry invitation-token claim',
      changeReason: 'Change reason',
      reasonPlaceholder:
        'Member updates, ownership transfers, removals, and invitation revocations use this audit reason',
      members: 'Members',
      roleFor: '{name} role',
      statusFor: '{name} status',
      save: 'Save',
      discardChanges: 'Discard changes',
      transferOwner: 'Transfer Owner',
      remove: 'Remove',
      loadMoreMembers: 'Load more members',
      invitations: 'Invitations',
      expires: 'Expires: ',
      revoke: 'Revoke',
      loadMoreInvitations: 'Load more invitation records',
      closeWorkspace: 'Close workspace management',
      close: 'Close',
      transferTitle: 'Confirm workspace ownership transfer',
      soleOwner: '{name} will become the sole Owner',
      transferDetail:
        'The current Owner becomes an Admin. This action requires recent step-up authentication and is written to the audit log.',
      transferring: 'Transferring…',
      confirmTransfer: 'Confirm transfer',
      removeTitle: 'Confirm workspace-member removal',
      cancelRemoval: 'Cancel member removal',
      losesAccess: '{name} will immediately lose Team access',
      removeDetail:
        'All refresh sessions, device bindings, and unused tokens are revoked in the same transaction. Rejoining requires a new invitation.',
      removing: 'Removing…',
      confirmRemoval: 'Confirm removal',
      matrixTitle: 'Member permission matrix',
      invitationEyebrow: 'Team / Invitation',
      workspaceEyebrow: 'Team / Workspace',
      ownerEyebrow: 'Team / Owner',
      ownershipEyebrow: 'Team / Ownership',
      removalEyebrow: 'Team / Member removal',
      permissionsEyebrow: 'Team / Permissions',
      ownerPermissions:
        'Member governance and ownership transfer; billing read/write; shared-configuration publishing and purge; sync, alerts, audit export, and Webhook management',
      adminPermissions:
        'Routine member management, billing read, shared configurations and publishing, sync, alerts, audit, and Webhooks; cannot transfer ownership, modify peer Admins, or submit payments',
      billingPermissions:
        'Billing read and payment evidence submission only; no member or cloud-workspace permissions',
      operatorPermissions:
        'Read members and shared configurations, edit drafts and sync, and read or acknowledge alerts; cannot publish or manage members',
      auditorPermissions:
        'Read-only members, alert history, audit/export, and Webhook delivery metadata; cannot view Webhook secrets or bodies',
      viewerPermissions: 'Read-only members, shared configurations, sync state, and current alerts',
      done: 'Done',
      workspaceLoadFailed: 'Workspaces failed to load',
      workspaceMembersFailed: 'Workspace membership failed to load',
      membersFailed: 'Members failed to load',
      invitationsFailed: 'Invitations failed to load',
      inviteFailed: 'Invitation failed',
      acknowledgeFailed: 'Delivery acknowledgement failed',
      updateFailed: 'Member update failed',
      transferFailed: 'Ownership transfer failed',
      revokeFailed: 'Revocation failed',
      missingDelivery: 'The server did not return invitation-delivery credentials',
      claimPending:
        'The invitation was created, but its token has not been claimed. Retry with the same delivery credentials to avoid creating a duplicate invitation.',
      active: 'Active',
      suspended: 'Suspended',
      invited: 'Invited',
      removed: 'Removed',
      noMembers: 'This workspace has no member records',
      noInvitations: 'This workspace has no pending invitations',
      noWorkspaces:
        'No Team workspaces are available. Configure an account with an active Team license and seats first.',
      completeOwnerProfile: 'Complete Owner profile',
      ownerProfileTitle: 'Complete the primary Owner profile',
      ownerProfileDetail:
        'The placeholder exists only for initialization. Enter the real contact email and display name.',
      ownerProfileFailed: 'Owner profile update failed',
      workspaceChanged:
        'This workspace changed in another session. The latest state is loaded; review it before retrying.',
      emailInvalid: 'Enter a valid email address.',
      displayNameInvalid: 'The display name must contain 1–160 characters.',
      complete: 'Complete profile'
    }
  );

  let rows = $state<Workspace[]>([]);
  let workspaceNextCursor = $state<string | null>(null);
  let members = $state<Member[]>([]);
  let memberDrafts = $state<Record<string, Pick<Member, 'role' | 'status'>>>({});
  let memberNextCursor = $state<string | null>(null);
  let invitations = $state<Invitation[]>([]);
  let invitationNextCursor = $state<string | null>(null);
  let loading = $state(true);
  let loadingMore = $state(false);
  let loadingWorkspacePage = $state(false);
  let creating = $state(false);
  let saving = $state(false);
  let error = $state('');
  let fieldErrors = $state<Record<string, string>>({});
  let delivery = $state<TeamInvitationDeliveryResponse['delivery'] | null>(null);
  let copyStatus = $state('');
  let invitationToken = $state('');
  let form = $state({ accountId: '', email: '', displayName: '', role: 'viewer', reason: '' });
  let selectedWorkspace = $state<Workspace | null>(null);
  let manageReason = $state('');
  let ownershipTarget = $state<Member | null>(null);
  let removalTarget = $state<Member | null>(null);
  let ownerProfileTarget = $state<Member | null>(null);
  let ownerProfileEmail = $state('');
  let ownerProfileName = $state('');
  let ownerProfileReason = $state('');
  let showMatrix = $state(false);
  const invitationAttempt = new MutationAttempt();
  const manageAttempt = new MutationAttempt();
  const ownerProfileAttempt = new MutationAttempt();
  let permissionSet = $derived(new Set(permissions));
  let canWrite = $derived(permissionSet.has('team.write'));
  let canIssueCode = $derived(permissionSet.has('code.issue'));
  let loadGeneration = 0;
  let workspaceGeneration = 0;
  let workspaceColumns = $derived([
    { key: 'accountId', label: messages[$locale].account, type: 'mono' as const },
    { key: 'licenseId', label: messages[$locale].license, type: 'mono' as const },
    { key: 'purchasedSeats', label: messages[$locale].purchasedSeats, type: 'number' as const },
    { key: 'occupiedMembers', label: messages[$locale].occupiedSeats, type: 'number' as const },
    { key: 'activeMembers', label: messages[$locale].activeMembers, type: 'number' as const },
    { key: 'memberCount', label: messages[$locale].memberRecords, type: 'number' as const }
  ]);
  const validEmail = (value: string) =>
    value.length <= 254 && /^[^\s@]+@[^\s@]+$/.test(value.trim());
  let createValid = $derived(
    Boolean(
      form.accountId && validEmail(form.email) && form.displayName.trim() && form.reason.trim()
    )
  );
  let pendingInvitations = $derived(
    invitations.filter((item) => !item.acceptedAt && !item.revokedAt)
  );

  const message = (value: unknown, fallback: string) =>
    value instanceof Error ? value.message : fallback;
  const pagePath = (path: string, cursor?: string | null) => {
    const parameters = new URLSearchParams({ pageSize: '100' });
    if (cursor) parameters.set('cursor', cursor);
    return `${path}?${parameters}`;
  };
  const mergeById = <T extends { id: string }>(current: T[], incoming: T[]) => {
    const merged = new Map(current.map((item) => [item.id, item]));
    for (const item of incoming) merged.set(item.id, item);
    return [...merged.values()];
  };
  const draftFor = (member: Member) =>
    memberDrafts[member.id] ?? {
      role: member.role,
      status: member.status
    };
  const memberEditable = (member: Member) =>
    canWrite &&
    member.role !== 'owner' &&
    member.status !== 'invited' &&
    member.status !== 'removed';
  const memberChanged = (member: Member) => {
    const draft = draftFor(member);
    return draft.role !== member.role || draft.status !== member.status;
  };
  function replaceMemberDrafts(nextMembers: Member[]) {
    memberDrafts = Object.fromEntries(
      nextMembers.map((member) => [member.id, { role: member.role, status: member.status }])
    );
  }
  function appendMemberDrafts(nextMembers: Member[]) {
    const next = { ...memberDrafts };
    for (const member of nextMembers) {
      next[member.id] ??= { role: member.role, status: member.status };
    }
    memberDrafts = next;
  }
  function updateMemberDraft(
    member: Member,
    field: 'role' | 'status',
    value: Member['role'] | Member['status']
  ) {
    const draft = draftFor(member);
    memberDrafts = { ...memberDrafts, [member.id]: { ...draft, [field]: value } };
    manageAttempt.succeeded();
  }
  function resetMemberDraft(member: Member) {
    memberDrafts = {
      ...memberDrafts,
      [member.id]: { role: member.role, status: member.status }
    };
    manageAttempt.succeeded();
  }

  async function load(append = false) {
    if ((append && !workspaceNextCursor) || loadingMore) return;
    const requestedCursor = append ? workspaceNextCursor : null;
    const current = append ? loadGeneration : ++loadGeneration;
    if (append) loadingMore = true;
    else loading = true;
    error = '';
    try {
      const data = await api<Page<Workspace>>(pagePath('/team-workspaces', requestedCursor));
      if (current !== loadGeneration) return;
      if (append) {
        const merged = new Map(rows.map((item) => [item.accountId, item]));
        for (const item of data.items ?? []) merged.set(item.accountId, item);
        rows = [...merged.values()];
      } else {
        rows = data.items ?? [];
      }
      workspaceNextCursor = data.nextCursor ?? null;
      if (!form.accountId && rows[0]) form.accountId = String(rows[0].accountId);
    } catch (value) {
      if (current === loadGeneration) error = message(value, messages[$locale].workspaceLoadFailed);
    } finally {
      if (append) loadingMore = false;
      else if (current === loadGeneration) loading = false;
    }
  }

  async function openWorkspace(row: Workspace) {
    const current = ++workspaceGeneration;
    selectedWorkspace = row;
    ownershipTarget = null;
    removalTarget = null;
    ownerProfileTarget = null;
    manageReason = '';
    error = '';
    members = [];
    invitations = [];
    memberNextCursor = null;
    invitationNextCursor = null;
    const account = String(row.accountId);
    loadingWorkspacePage = true;
    try {
      const [memberPage, invitationPage] = await Promise.all([
        api<Page<Member>>(pagePath(`/team-workspaces/${account}/members`)),
        api<Page<Invitation>>(pagePath(`/team-workspaces/${account}/invitations`))
      ]);
      if (current !== workspaceGeneration || String(selectedWorkspace?.accountId) !== account)
        return;
      members = memberPage.items ?? [];
      replaceMemberDrafts(members);
      memberNextCursor = memberPage.nextCursor ?? null;
      invitations = invitationPage.items ?? [];
      invitationNextCursor = invitationPage.nextCursor ?? null;
    } catch (value) {
      if (current === workspaceGeneration)
        error = message(value, messages[$locale].workspaceMembersFailed);
    } finally {
      if (current === workspaceGeneration) loadingWorkspacePage = false;
    }
  }

  async function loadMoreMembers() {
    if (!selectedWorkspace || !memberNextCursor || loadingWorkspacePage) return;
    const account = String(selectedWorkspace.accountId);
    const cursor = memberNextCursor;
    const current = workspaceGeneration;
    loadingWorkspacePage = true;
    try {
      const page = await api<Page<Member>>(pagePath(`/team-workspaces/${account}/members`, cursor));
      if (current !== workspaceGeneration || String(selectedWorkspace?.accountId) !== account)
        return;
      members = mergeById(members, page.items ?? []);
      appendMemberDrafts(page.items ?? []);
      memberNextCursor = page.nextCursor ?? null;
    } catch (value) {
      if (current === workspaceGeneration) error = message(value, messages[$locale].membersFailed);
    } finally {
      if (current === workspaceGeneration) loadingWorkspacePage = false;
    }
  }

  async function loadMoreInvitations() {
    if (!selectedWorkspace || !invitationNextCursor || loadingWorkspacePage) return;
    const account = String(selectedWorkspace.accountId);
    const cursor = invitationNextCursor;
    const current = workspaceGeneration;
    loadingWorkspacePage = true;
    try {
      const page = await api<Page<Invitation>>(
        pagePath(`/team-workspaces/${account}/invitations`, cursor)
      );
      if (current !== workspaceGeneration || String(selectedWorkspace?.accountId) !== account)
        return;
      invitations = mergeById(invitations, page.items ?? []);
      invitationNextCursor = page.nextCursor ?? null;
    } catch (value) {
      if (current === workspaceGeneration)
        error = message(value, messages[$locale].invitationsFailed);
    } finally {
      if (current === workspaceGeneration) loadingWorkspacePage = false;
    }
  }

  async function invite() {
    if (saving || (!delivery && !createValid)) return;
    saving = true;
    error = '';
    fieldErrors = {};
    try {
      if (!delivery) {
        const body = JSON.stringify({
          email: form.email,
          displayName: form.displayName,
          role: form.role,
          reason: form.reason
        });
        const path = `/team-workspaces/${form.accountId}/invitations`;
        const result = await api<TeamInvitationDeliveryResponse>(path, {
          method: 'POST',
          mutation: true,
          operationId: invitationAttempt.operationId(`${path}:${body}`),
          body
        });
        delivery = result.delivery;
        invitationAttempt.succeeded();
      }
      const ticket = delivery;
      if (!ticket) throw new Error(messages[$locale].missingDelivery);
      const secret = await api<TeamInvitationSecret>(`/secret-deliveries/${ticket.id}/claim`, {
        method: 'POST',
        csrf: true,
        body: JSON.stringify({ claimToken: ticket.claimToken })
      });
      invitationToken = secret.invitationToken;
    } catch (value) {
      if (!delivery) invitationAttempt.failed(value);
      if (value instanceof ApiError && value.field) {
        fieldErrors = {
          [value.field]:
            value.field === 'email'
              ? messages[$locale].emailInvalid
              : value.field === 'displayName'
                ? messages[$locale].displayNameInvalid
                : value.message
        };
      } else {
        error = message(value, messages[$locale].inviteFailed);
      }
    } finally {
      saving = false;
    }
  }

  async function acknowledge() {
    const ticket = delivery;
    if (!ticket || saving) return;
    saving = true;
    error = '';
    try {
      await api(`/secret-deliveries/${ticket.id}/acknowledge`, {
        method: 'POST',
        csrf: true,
        body: JSON.stringify({ claimToken: ticket.claimToken })
      });
      creating = false;
      delivery = null;
      invitationToken = '';
      copyStatus = '';
      invitationAttempt.succeeded();
      await load();
    } catch (value) {
      error = message(value, messages[$locale].acknowledgeFailed);
    } finally {
      saving = false;
    }
  }

  async function reloadWorkspaceAfterVersionConflict(value: unknown) {
    if (!isVersionConflict(value) || !selectedWorkspace) return false;
    const workspace = selectedWorkspace;
    ownershipTarget = null;
    removalTarget = null;
    ownerProfileTarget = null;
    await openWorkspace(workspace);
    error = messages[$locale].workspaceChanged;
    return true;
  }

  async function updateMember(member: Member, status?: Member['status']) {
    if (!selectedWorkspace || !manageReason) return false;
    const draft = status ? { role: member.role, status } : draftFor(member);
    if (!status && !memberChanged(member)) return false;
    const path = `/team-workspaces/${selectedWorkspace.accountId}/members/${member.id}/actions/update`;
    const body = JSON.stringify({ role: draft.role, status: draft.status, reason: manageReason });
    const fingerprint = `${path}:${member.rowVersion}:${body}`;
    saving = true;
    error = '';
    try {
      await api(path, {
        method: 'POST',
        mutation: true,
        operationId: manageAttempt.operationId(fingerprint),
        headers: { 'if-match': String(member.rowVersion) },
        body
      });
      manageAttempt.succeeded();
      await openWorkspace(selectedWorkspace);
      return true;
    } catch (value) {
      manageAttempt.failed(value);
      if (!(await reloadWorkspaceAfterVersionConflict(value)))
        error = message(value, messages[$locale].updateFailed);
      return false;
    } finally {
      saving = false;
    }
  }

  async function removeMember() {
    const target = removalTarget;
    if (!target) return;
    if (await updateMember(target, 'removed')) removalTarget = null;
  }

  async function transferOwnership() {
    if (!selectedWorkspace || !ownershipTarget || !manageReason) return;
    const target = ownershipTarget;
    const path = `/team-workspaces/${selectedWorkspace.accountId}/members/${target.id}/actions/transfer-ownership`;
    const body = JSON.stringify({ reason: manageReason });
    saving = true;
    error = '';
    try {
      await api(path, {
        method: 'POST',
        mutation: true,
        operationId: manageAttempt.operationId(`${path}:${target.rowVersion}:${body}`),
        headers: { 'if-match': String(target.rowVersion) },
        body
      });
      manageAttempt.succeeded();
      ownershipTarget = null;
      await openWorkspace(selectedWorkspace);
    } catch (value) {
      manageAttempt.failed(value);
      if (!(await reloadWorkspaceAfterVersionConflict(value)))
        error = message(value, messages[$locale].transferFailed);
    } finally {
      saving = false;
    }
  }

  async function revokeInvitation(invitation: Invitation) {
    if (!selectedWorkspace || !manageReason) return;
    const path = `/team-workspaces/${selectedWorkspace.accountId}/invitations/${invitation.id}/actions/revoke`;
    const body = JSON.stringify({ reason: manageReason });
    saving = true;
    error = '';
    try {
      await api(path, {
        method: 'POST',
        mutation: true,
        operationId: manageAttempt.operationId(`${path}:${body}`),
        body
      });
      manageAttempt.succeeded();
      await openWorkspace(selectedWorkspace);
    } catch (value) {
      manageAttempt.failed(value);
      error = message(value, messages[$locale].revokeFailed);
    } finally {
      saving = false;
    }
  }

  function openOwnerProfile(member: Member) {
    ownerProfileTarget = member;
    ownerProfileEmail = '';
    ownerProfileName = '';
    ownerProfileReason = '';
    error = '';
    fieldErrors = {};
    ownerProfileAttempt.succeeded();
  }

  async function completeOwnerProfile() {
    const target = ownerProfileTarget;
    if (
      !selectedWorkspace ||
      !target ||
      !ownerProfileEmail.trim() ||
      !ownerProfileName.trim() ||
      !ownerProfileReason.trim() ||
      saving
    )
      return;
    const path = `/team-workspaces/${selectedWorkspace.accountId}/members/${target.id}/actions/complete-owner-profile`;
    const body = JSON.stringify({
      email: ownerProfileEmail.trim(),
      displayName: ownerProfileName.trim(),
      reason: ownerProfileReason.trim()
    });
    saving = true;
    error = '';
    fieldErrors = {};
    try {
      await api<AdminTeamMember>(path, {
        method: 'POST',
        mutation: true,
        operationId: ownerProfileAttempt.operationId(`${path}:${target.rowVersion}:${body}`),
        headers: { 'if-match': String(target.rowVersion) },
        body
      });
      ownerProfileAttempt.succeeded();
      ownerProfileTarget = null;
      await openWorkspace(selectedWorkspace);
    } catch (value) {
      ownerProfileAttempt.failed(value);
      const reloaded = await reloadWorkspaceAfterVersionConflict(value);
      if (!reloaded && value instanceof ApiError && value.field) {
        fieldErrors = {
          [value.field]:
            value.field === 'email'
              ? messages[$locale].emailInvalid
              : value.field === 'displayName'
                ? messages[$locale].displayNameInvalid
                : value.message
        };
      } else if (!reloaded) {
        error = message(value, messages[$locale].ownerProfileFailed);
      }
    } finally {
      saving = false;
    }
  }

  function openInvitation() {
    creating = true;
    error = '';
    fieldErrors = {};
    delivery = null;
    invitationToken = '';
    copyStatus = '';
    form = {
      accountId: String(rows[0]?.accountId ?? ''),
      email: '',
      displayName: '',
      role: 'viewer',
      reason: ''
    };
    invitationAttempt.succeeded();
  }

  function closeInvitation() {
    if (!delivery && !saving) creating = false;
  }

  function closeWorkspace() {
    if (saving) return;
    workspaceGeneration++;
    selectedWorkspace = null;
    memberDrafts = {};
    ownershipTarget = null;
    removalTarget = null;
    ownerProfileTarget = null;
  }

  async function copyInvitationToken() {
    try {
      await navigator.clipboard.writeText(invitationToken);
      copyStatus = messages[$locale].copied;
    } catch {
      copyStatus = messages[$locale].copyFailed;
    }
  }

  onMount(() => {
    void load();
  });
</script>

<div class="page-heading">
  <div>
    <span class="breadcrumb">{copy[$locale].console} / {messages[$locale].title}</span>
    <h1>{messages[$locale].title}</h1>
    <p>{messages[$locale].description}</p>
  </div>
  {#if canWrite}<button class="primary" onclick={openInvitation} disabled={!rows.length}
      ><Plus size={17} />{messages[$locale].createInvitation}</button
    >{/if}
</div>

<section class="team-hero">
  <div>
    <span><UsersRound size={24} /></span>
    <div>
      <small>{messages[$locale].operations.toUpperCase()}</small>
      <h2>{messages[$locale].heroTitle}</h2>
      <p>{messages[$locale].heroDetail}</p>
    </div>
  </div>
  <button onclick={() => (showMatrix = true)}
    >{messages[$locale].viewMatrix} <ArrowRight size={16} /></button
  >
</section>

<section class="panel resource-panel">
  <div class="panel-head padded">
    <div>
      <h2>{messages[$locale].workspaces}</h2>
      <p>{messages[$locale].workspaceDetail}</p>
    </div>
    <button
      class="icon-button"
      aria-label={messages[$locale].refresh}
      onclick={() => void load()}
      disabled={loading}><RefreshCw class={loading ? 'spin' : ''} size={18} /></button
    >
  </div>
  {#if error && !creating && !selectedWorkspace}<div class="inline-error" role="alert">
      <span>{error}</span><button onclick={() => void load()}>{messages[$locale].refresh}</button>
    </div>{/if}
  <ResourceTable
    columns={workspaceColumns}
    {rows}
    {loading}
    onSelect={(row) => void openWorkspace(row as Workspace)}
  />
  {#if !loading && !rows.length && !error}<p class="resource-empty-guidance">
      {messages[$locale].noWorkspaces}
    </p>{/if}
  {#if workspaceNextCursor}<div class="table-load-more">
      <button disabled={loadingMore} onclick={() => void load(true)}
        >{loadingMore ? messages[$locale].loading : messages[$locale].loadMoreWorkspaces}</button
      >
    </div>{/if}
</section>

{#if creating}
  <div class="modal-layer" role="presentation">
    <button
      class="modal-scrim"
      aria-label={messages[$locale].close}
      onclick={closeInvitation}
      disabled={Boolean(delivery) || saving}
    ></button>
    <div
      use:focusTrap={{
        onEscape: delivery || saving ? undefined : closeInvitation,
        initialFocus: invitationToken ? '.copy-all' : 'select, input'
      }}
      class="modal-card"
      role="dialog"
      aria-modal="true"
      aria-labelledby="team-invitation-title"
      aria-busy={saving}
    >
      <header>
        <div>
          <span class="eyebrow">{messages[$locale].invitationEyebrow}</span>
          <h2 id="team-invitation-title">{messages[$locale].inviteMember}</h2>
        </div>
        <button
          class="icon-button modal-close"
          disabled={Boolean(delivery) || saving}
          onclick={closeInvitation}
          aria-label={messages[$locale].close}><X size={18} /></button
        >
      </header>
      {#if error}<div class="form-error" role="alert">{error}</div>{/if}
      {#if copyStatus}<p class="sr-only" role="status">{copyStatus}</p>{/if}
      {#if invitationToken}
        <div class="secret-warning">
          <strong>{messages[$locale].tokenOnce}</strong><span>{messages[$locale].tokenDetail}</span>
        </div>
        <div class="code-delivery"><code>{invitationToken}</code></div>
        <button class="secondary copy-all" onclick={() => void copyInvitationToken()}
          >{messages[$locale].copyToken}</button
        >
        <footer>
          <button class="primary" disabled={saving} onclick={() => void acknowledge()}
            >{saving ? messages[$locale].acknowledging : messages[$locale].acknowledge}</button
          >
        </footer>
      {:else if delivery}
        <div class="secret-warning">
          <strong>{messages[$locale].retryToken}</strong><span
            >{messages[$locale].claimPending}</span
          >
        </div>
        <footer>
          <button class="primary" onclick={() => void invite()} disabled={saving}
            >{saving ? messages[$locale].processing : messages[$locale].retryToken}</button
          >
        </footer>
      {:else}
        <div class="secret-warning activation-prerequisite">
          <strong>{messages[$locale].activationRequired}</strong><span
            >{messages[$locale].activationDetail}</span
          >
          {#if canIssueCode}<button
              type="button"
              class="text-button"
              onclick={() => {
                const workspace = rows.find((row) => String(row.accountId) === form.accountId);
                if (workspace)
                  setResourceIntent({
                    resource: 'codes',
                    accountId: form.accountId,
                    licenseId: String(workspace.licenseId)
                  });
                creating = false;
                onNavigate('codes');
              }}>{messages[$locale].issueActivationCode}<ArrowRight size={15} /></button
            >{/if}
        </div>
        <div class="form-grid">
          <label
            >{messages[$locale].teamAccount}<select
              data-option-align="start"
              bind:value={form.accountId}
              >{#each rows as row}<option value={String(row.accountId)}
                  >{String(row.accountId)}</option
                >{/each}</select
            ></label
          >
          <label
            >{messages[$locale].memberRole}<select data-option-align="center" bind:value={form.role}
              ><option value="admin">{teamRoleLabel('admin', $locale)}</option><option
                value="billing">{teamRoleLabel('billing', $locale)}</option
              ><option value="operator">{teamRoleLabel('operator', $locale)}</option><option
                value="auditor">{teamRoleLabel('auditor', $locale)}</option
              ><option value="viewer">{teamRoleLabel('viewer', $locale)}</option></select
            ></label
          >
          <label
            >{messages[$locale].email}<input
              type="email"
              maxlength="254"
              autocomplete="off"
              bind:value={form.email}
              aria-invalid={Boolean(fieldErrors.email)}
              aria-describedby={fieldErrors.email ? 'invitation-email-error' : undefined}
              oninput={() => (fieldErrors = {})}
              required
            />{#if fieldErrors.email}<small
                id="invitation-email-error"
                class="field-error"
                role="alert">{fieldErrors.email}</small
              >{/if}</label
          >
          <label
            >{messages[$locale].displayName}<input
              maxlength="160"
              autocomplete="off"
              bind:value={form.displayName}
              aria-invalid={Boolean(fieldErrors.displayName)}
              aria-describedby={fieldErrors.displayName
                ? 'invitation-display-name-error'
                : undefined}
              oninput={() => (fieldErrors = {})}
              required
            />{#if fieldErrors.displayName}<small
                id="invitation-display-name-error"
                class="field-error"
                role="alert">{fieldErrors.displayName}</small
              >{/if}</label
          >
          <label class="wide"
            >{messages[$locale].reason}<textarea maxlength="1000" bind:value={form.reason} required
            ></textarea></label
          >
        </div>
        <footer>
          <button class="secondary" onclick={closeInvitation} disabled={saving}
            >{messages[$locale].cancel}</button
          ><button class="primary" onclick={() => void invite()} disabled={saving || !createValid}
            >{saving ? messages[$locale].processing : messages[$locale].createInvitation}</button
          >
        </footer>
      {/if}
    </div>
  </div>
{/if}

{#if selectedWorkspace && !ownershipTarget && !removalTarget && !ownerProfileTarget}
  <div class="modal-layer" role="presentation">
    <button
      class="modal-scrim"
      aria-label={messages[$locale].closeWorkspace}
      onclick={closeWorkspace}
      disabled={saving}
    ></button>
    <div
      use:focusTrap={{ onEscape: saving ? undefined : closeWorkspace, initialFocus: 'textarea' }}
      class="modal-card workspace-modal"
      role="dialog"
      aria-modal="true"
      aria-labelledby="team-workspace-title"
      aria-busy={loadingWorkspacePage || saving}
    >
      <header>
        <div>
          <span class="eyebrow">{messages[$locale].workspaceEyebrow}</span>
          <h2 id="team-workspace-title">{String(selectedWorkspace.accountId)}</h2>
        </div>
        <button
          class="icon-button modal-close"
          aria-label={messages[$locale].closeWorkspace}
          onclick={closeWorkspace}
          disabled={saving}><X size={18} /></button
        >
      </header>
      {#if error}<div class="form-error" role="alert">{error}</div>{/if}
      {#if canWrite}<label class="standalone-label"
          >{messages[$locale].changeReason}<textarea
            maxlength="1000"
            bind:value={manageReason}
            placeholder={messages[$locale].reasonPlaceholder}></textarea></label
        >{/if}
      <h3>{messages[$locale].members}</h3>
      <div class="member-list">
        {#each members as member (member.id)}
          <article class="member-row">
            <span class="member-identity"
              ><strong title={member.displayName}>{member.displayName}</strong><small
                title={member.email}>{member.email}</small
              ></span
            >
            {#if memberEditable(member)}
              <div class="member-fields">
                <label
                  ><span>{messages[$locale].memberRole}</span><select
                    data-option-align="center"
                    aria-label={messages[$locale].roleFor.replace('{name}', member.displayName)}
                    value={draftFor(member).role}
                    disabled={saving}
                    onchange={(event) =>
                      updateMemberDraft(
                        member,
                        'role',
                        event.currentTarget.value as Member['role']
                      )}
                  >
                    <option value="admin">{teamRoleLabel('admin', $locale)}</option><option
                      value="billing">{teamRoleLabel('billing', $locale)}</option
                    ><option value="operator">{teamRoleLabel('operator', $locale)}</option><option
                      value="auditor">{teamRoleLabel('auditor', $locale)}</option
                    ><option value="viewer">{teamRoleLabel('viewer', $locale)}</option>
                  </select></label
                >
                <label
                  ><span>{messages[$locale].memberStatus}</span><select
                    data-option-align="center"
                    aria-label={messages[$locale].statusFor.replace('{name}', member.displayName)}
                    value={draftFor(member).status}
                    disabled={saving}
                    onchange={(event) =>
                      updateMemberDraft(
                        member,
                        'status',
                        event.currentTarget.value as Member['status']
                      )}
                  >
                    <option value="active">{messages[$locale].active}</option><option
                      value="suspended">{messages[$locale].suspended}</option
                    >
                  </select></label
                >
              </div>
            {:else}
              <div class="member-readonly-fields" aria-label={messages[$locale].memberStatus}>
                <span>{teamRoleLabel(member.role, $locale)}</span><span
                  class={`member-status ${member.status}`}>{messages[$locale][member.status]}</span
                >
              </div>
            {/if}
            {#if canWrite}<div class="member-actions">
                {#if memberEditable(member)}<button
                    onclick={() => void updateMember(member)}
                    disabled={saving || !manageReason.trim() || !memberChanged(member)}
                    >{messages[$locale].save}</button
                  ><button
                    onclick={() => resetMemberDraft(member)}
                    disabled={saving || !memberChanged(member)}
                    >{messages[$locale].discardChanges}</button
                  >{/if}
                {#if member.profilePending}<button
                    onclick={() => openOwnerProfile(member)}
                    disabled={saving}>{messages[$locale].completeOwnerProfile}</button
                  >{/if}
                {#if member.role === 'admin' && member.status === 'active'}<button
                    class="transfer-button"
                    onclick={() => (ownershipTarget = member)}
                    disabled={saving || !manageReason.trim() || memberChanged(member)}
                    >{messages[$locale].transferOwner}</button
                  >{/if}
                {#if member.role !== 'owner' && (member.status === 'active' || member.status === 'suspended')}<button
                    class="revoke-button"
                    onclick={() => (removalTarget = member)}
                    disabled={saving || !manageReason.trim() || memberChanged(member)}
                    >{messages[$locale].remove}</button
                  >{/if}
              </div>{/if}
          </article>
        {:else}
          <p class="compact-empty">
            {loadingWorkspacePage ? messages[$locale].loading : messages[$locale].noMembers}
          </p>
        {/each}
      </div>
      {#if memberNextCursor}<div class="table-load-more">
          <button disabled={loadingWorkspacePage} onclick={() => void loadMoreMembers()}
            >{loadingWorkspacePage
              ? messages[$locale].loading
              : messages[$locale].loadMoreMembers}</button
          >
        </div>{/if}
      <h3>{messages[$locale].invitations}</h3>
      <div class="member-list invitation-list">
        {#each pendingInvitations as invitation (invitation.id)}
          <article class="invitation-row">
            <span class="member-identity"
              ><strong>{invitation.email}</strong><small
                >{messages[$locale].expires}
                {new Date(invitation.expiresAt * 1000).toLocaleString(localeTag($locale))}</small
              ></span
            >
            <div class="member-readonly-fields">
              <span>{teamRoleLabel(invitation.role, $locale)}</span><span
                class="member-status invited">{messages[$locale].invited}</span
              >
            </div>
            {#if canWrite}<div class="member-actions">
                <button
                  class="revoke-button"
                  onclick={() => void revokeInvitation(invitation)}
                  disabled={saving || !manageReason.trim()}>{messages[$locale].revoke}</button
                >
              </div>{/if}
          </article>
        {:else}
          <p class="compact-empty">
            {loadingWorkspacePage ? messages[$locale].loading : messages[$locale].noInvitations}
          </p>
        {/each}
      </div>
      {#if invitationNextCursor}<div class="table-load-more">
          <button disabled={loadingWorkspacePage} onclick={() => void loadMoreInvitations()}
            >{loadingWorkspacePage
              ? messages[$locale].loading
              : messages[$locale].loadMoreInvitations}</button
          >
        </div>{/if}
    </div>
  </div>
{/if}

{#if ownerProfileTarget}
  <div class="modal-layer" role="presentation">
    <button
      class="modal-scrim"
      aria-label={messages[$locale].cancel}
      onclick={() => {
        if (!saving) ownerProfileTarget = null;
      }}
      disabled={saving}
    ></button>
    <div
      use:focusTrap={{
        onEscape: saving ? undefined : () => (ownerProfileTarget = null),
        initialFocus: 'input'
      }}
      class="modal-card"
      role="dialog"
      aria-modal="true"
      aria-labelledby="owner-profile-title"
      aria-busy={saving}
    >
      <header>
        <div>
          <span class="eyebrow">{messages[$locale].ownerEyebrow}</span>
          <h2 id="owner-profile-title">{messages[$locale].ownerProfileTitle}</h2>
        </div>
        <button
          class="icon-button modal-close"
          onclick={() => (ownerProfileTarget = null)}
          disabled={saving}
          aria-label={messages[$locale].cancel}><X size={18} /></button
        >
      </header>
      {#if error}<div class="form-error" role="alert">{error}</div>{/if}
      <p class="modal-detail">{messages[$locale].ownerProfileDetail}</p>
      <div class="form-grid">
        <label
          >{messages[$locale].email}<input
            type="email"
            maxlength="254"
            autocomplete="off"
            bind:value={ownerProfileEmail}
            aria-invalid={Boolean(fieldErrors.email)}
            aria-describedby={fieldErrors.email ? 'owner-email-error' : undefined}
            oninput={() => (fieldErrors = {})}
            required
          />{#if fieldErrors.email}<small id="owner-email-error" class="field-error" role="alert"
              >{fieldErrors.email}</small
            >{/if}</label
        >
        <label
          >{messages[$locale].displayName}<input
            maxlength="160"
            autocomplete="off"
            bind:value={ownerProfileName}
            aria-invalid={Boolean(fieldErrors.displayName)}
            aria-describedby={fieldErrors.displayName ? 'owner-name-error' : undefined}
            oninput={() => (fieldErrors = {})}
            required
          />{#if fieldErrors.displayName}<small
              id="owner-name-error"
              class="field-error"
              role="alert">{fieldErrors.displayName}</small
            >{/if}</label
        >
        <label class="wide"
          >{messages[$locale].reason}<textarea
            maxlength="512"
            bind:value={ownerProfileReason}
            required></textarea></label
        >
      </div>
      <footer>
        <button class="secondary" onclick={() => (ownerProfileTarget = null)} disabled={saving}
          >{messages[$locale].cancel}</button
        ><button
          class="primary"
          onclick={() => void completeOwnerProfile()}
          disabled={saving ||
            !validEmail(ownerProfileEmail) ||
            !ownerProfileName.trim() ||
            !ownerProfileReason.trim()}
          >{saving ? messages[$locale].processing : messages[$locale].complete}</button
        >
      </footer>
    </div>
  </div>
{/if}

{#if ownershipTarget}
  <div class="modal-layer" role="presentation">
    <button
      class="modal-scrim"
      aria-label={messages[$locale].cancel}
      onclick={() => {
        if (!saving) ownershipTarget = null;
      }}
      disabled={saving}
    ></button>
    <div
      use:focusTrap={{
        onEscape: saving ? undefined : () => (ownershipTarget = null),
        initialFocus: '.danger-action'
      }}
      class="modal-card"
      role="alertdialog"
      aria-modal="true"
      aria-labelledby="ownership-title"
      aria-busy={saving}
    >
      <header>
        <div>
          <span class="eyebrow">{messages[$locale].ownershipEyebrow}</span>
          <h2 id="ownership-title">{messages[$locale].transferTitle}</h2>
        </div>
        <button
          class="icon-button modal-close"
          onclick={() => (ownershipTarget = null)}
          disabled={saving}
          aria-label={messages[$locale].cancel}><X size={18} /></button
        >
      </header>
      {#if error}<div class="form-error" role="alert">{error}</div>{/if}
      <div class="secret-warning">
        <strong>{messages[$locale].soleOwner.replace('{name}', ownershipTarget.displayName)}</strong
        ><span>{messages[$locale].transferDetail}</span>
      </div>
      <footer>
        <button class="secondary" onclick={() => (ownershipTarget = null)} disabled={saving}
          >{messages[$locale].cancel}</button
        ><button
          class="primary danger-action"
          onclick={() => void transferOwnership()}
          disabled={saving}
          >{saving ? messages[$locale].transferring : messages[$locale].confirmTransfer}</button
        >
      </footer>
    </div>
  </div>
{/if}

{#if removalTarget}
  <div class="modal-layer" role="presentation">
    <button
      class="modal-scrim"
      aria-label={messages[$locale].cancelRemoval}
      onclick={() => {
        if (!saving) removalTarget = null;
      }}
      disabled={saving}
    ></button>
    <div
      use:focusTrap={{
        onEscape: saving ? undefined : () => (removalTarget = null),
        initialFocus: '.danger-action'
      }}
      class="modal-card"
      role="alertdialog"
      aria-modal="true"
      aria-labelledby="removal-title"
      aria-busy={saving}
    >
      <header>
        <div>
          <span class="eyebrow">{messages[$locale].removalEyebrow}</span>
          <h2 id="removal-title">{messages[$locale].removeTitle}</h2>
        </div>
        <button
          class="icon-button modal-close"
          aria-label={messages[$locale].cancelRemoval}
          onclick={() => (removalTarget = null)}
          disabled={saving}><X size={18} /></button
        >
      </header>
      {#if error}<div class="form-error" role="alert">{error}</div>{/if}
      <div class="secret-warning">
        <strong>{messages[$locale].losesAccess.replace('{name}', removalTarget.displayName)}</strong
        ><span>{messages[$locale].removeDetail}</span>
      </div>
      <footer>
        <button class="secondary" onclick={() => (removalTarget = null)} disabled={saving}
          >{messages[$locale].cancel}</button
        ><button class="primary danger-action" onclick={() => void removeMember()} disabled={saving}
          >{saving ? messages[$locale].removing : messages[$locale].confirmRemoval}</button
        >
      </footer>
    </div>
  </div>
{/if}

{#if showMatrix}
  <div class="modal-layer" role="presentation">
    <button
      class="modal-scrim"
      aria-label={messages[$locale].close}
      onclick={() => (showMatrix = false)}
    ></button>
    <div
      use:focusTrap={{ onEscape: () => (showMatrix = false), initialFocus: 'footer button' }}
      class="modal-card role-matrix"
      role="dialog"
      aria-modal="true"
      aria-labelledby="role-matrix-title"
    >
      <header>
        <div>
          <span class="eyebrow">{messages[$locale].permissionsEyebrow}</span>
          <h2 id="role-matrix-title">{messages[$locale].matrixTitle}</h2>
        </div>
        <button
          class="icon-button modal-close"
          onclick={() => (showMatrix = false)}
          aria-label={messages[$locale].close}><X size={18} /></button
        >
      </header>
      <div class="matrix-list">
        <div>
          <strong>{teamRoleLabel('owner', $locale)}</strong><span
            >{messages[$locale].ownerPermissions}</span
          >
        </div>
        <div>
          <strong>{teamRoleLabel('admin', $locale)}</strong><span
            >{messages[$locale].adminPermissions}</span
          >
        </div>
        <div>
          <strong>{teamRoleLabel('billing', $locale)}</strong><span
            >{messages[$locale].billingPermissions}</span
          >
        </div>
        <div>
          <strong>{teamRoleLabel('operator', $locale)}</strong><span
            >{messages[$locale].operatorPermissions}</span
          >
        </div>
        <div>
          <strong>{teamRoleLabel('auditor', $locale)}</strong><span
            >{messages[$locale].auditorPermissions}</span
          >
        </div>
        <div>
          <strong>{teamRoleLabel('viewer', $locale)}</strong><span
            >{messages[$locale].viewerPermissions}</span
          >
        </div>
      </div>
      <footer>
        <button class="primary" onclick={() => (showMatrix = false)}
          >{messages[$locale].done}</button
        >
      </footer>
    </div>
  </div>
{/if}
