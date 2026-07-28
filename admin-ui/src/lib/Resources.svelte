<script lang="ts">
  import { untrack } from 'svelte';
  import { Download, Plus, RefreshCw, Search, X } from '@lucide/svelte';
  import { api, ApiError, isVersionConflict, MutationAttempt } from './api';
  import type {
    ActivationCodeActionRequest,
    ActivationCodeDeliveryResponse,
    AdminAuditEvent,
    AdminBulkJob,
    AdminBulkJobPreview,
    AdminPage,
    AdminVersionedResource,
    CreateAccountRequest,
    CreateLicenseRequest,
    DeliveredActivationCode,
    IssueActivationCodesRequest
  } from './admin-contracts';
  import { focusTrap } from './actions/focusTrap';
  import { actionLabel, planLabel, statusLabel } from './domainLabels';
  import { copy, defineCopy, locale } from './i18n';
  import ResourceCombobox from './ResourceCombobox.svelte';
  import FilterSelect from './FilterSelect.svelte';
  import { takeResourceIntent } from './resourceIntent';
  import ResourceTable from './ResourceTable.svelte';
  let { resource, permissions }: { resource: string; permissions: string[] } = $props();
  let rows = $state<Record<string, unknown>[]>([]);
  let loading = $state(true);
  let query = $state('');
  let error = $state('');
  let creating = $state(false);
  let saving = $state(false);
  let formError = $state('');
  let fieldErrors = $state<Record<string, string>>({});
  let form = $state<Record<string, string>>({});
  let deliveredCodes = $state<DeliveredActivationCode[]>([]);
  let delivery = $state<ActivationCodeDeliveryResponse['delivery'] | null>(null);
  let selected = $state<Record<string, unknown> | null>(null);
  let actionValue = $state('');
  let actionReason = $state('');
  let licenseAction = $state<'status' | 'plan' | 'expiry'>('status');
  let licensePlan = $state('pro');
  let licenseSeats = $state('0');
  let licenseExpiry = $state('none');
  const createAttempt = new MutationAttempt();
  const actionAttempt = new MutationAttempt();
  let actionExpiresAt = $state<string | null>(null);
  let jobPreview = $state<{ fingerprint: string; id: string } | null>(null);
  let jobExpiresAt = $state<number | null>(null);
  let statusFilter = $state('all');
  let cursor = $state<string | null>(null);
  let nextCursor = $state<string | null>(null);
  let cursorHistory = $state<string[]>([]);
  const messages = defineCopy(
    {
      accountsDescription: '管理客户身份、使用状态和商业关系。',
      licensesDescription: '套餐、席位、有效期与授权状态的统一视图。',
      codesDescription: '签发、追踪与撤销一次性或多次使用的激活码。',
      devicesDescription: '查看设备状态、风险信号和最近活动。',
      jobsDescription: '可恢复、可取消并逐项审计的批量操作。',
      auditDescription: '不可变的安全、授权与商业操作轨迹。',
      id: 'ID',
      accountId: '账户 ID',
      account: '账户',
      licenseId: '授权 ID',
      license: '授权',
      state: '状态',
      status: '状态',
      note: '备注',
      createdAt: '创建时间',
      expiresAt: '到期时间',
      plan: '套餐',
      codePrefix: '代码前缀',
      redeemed: '已兑换',
      deviceId: '设备 ID',
      platform: '平台',
      lastSeen: '最近活动',
      jobId: '任务 ID',
      operationType: '操作类型',
      totalItems: '总项数',
      completed: '已完成',
      time: '时间',
      event: '事件',
      outcome: '结果',
      cause: '原因',
      syncFailed: '同步失败',
      operationFailed: '操作失败',
      missingVersion: '资源响应缺少 rowVersion，请刷新后重试',
      resourceChanged: '资源已在其他会话中更新。已加载最新状态，请复核后重试。',
      showing: '当前显示 {count} 条记录',
      issueCodes: '签发激活码',
      createJob: '创建批量任务',
      createResource: '新建{name}',
      onlyOnce: '仅显示一次',
      deliveryWarning: '请立即复制并安全保存。确认后服务端会销毁交付密文。',
      copyCodes: '复制全部激活码',
      copiedCodes: '激活码已复制',
      copyFailed: '无法复制，请手动选择激活码',
      acknowledge: '我已安全保存并销毁交付',
      optional: '可选',
      seats: 'Team 席位',
      expiry: '到期时间',
      issueCount: '签发数量',
      redemptionLimit: '每码兑换上限',
      channel: '渠道',
      targetState: '目标状态',
      targetIds: '目标 ID（每行一个）',
      reasonPlaceholder: '说明业务依据，内容将写入审计日志',
      submitting: '正在提交…',
      confirmCreate: '确认创建',
      accountState: '账户状态',
      licenseState: '授权状态',
      licenseAction: '授权变更项目',
      licensePlan: '授权套餐',
      licenseExpiry: '授权到期时间',
      changeStatus: '商业状态',
      changePlan: '套餐与席位',
      changeExpiry: '到期时间',
      deviceState: '设备状态',
      codeAction: '激活码操作',
      cancelJob: '请求取消批量任务',
      cancelJobDetail: '已开始的单项可能完成，尚未执行的单项将被取消。',
      actionReasonPlaceholder: '说明业务或安全依据',
      selectAction: '请选择允许的状态变更',
      confirmCancel: '确认取消',
      apply: '应用变更',
      create: '创建',
      manage: '管理',
      refresh: '刷新',
      close: '关闭',
      cancel: '取消',
      allStatuses: '全部状态',
      filterStatus: '按状态筛选',
      previous: '上一页',
      next: '下一页',
      dateOrNone: '2027-01-01 或 none',
      durationOrNone: '+30d 或 none',
      accountSetState: '变更账户状态',
      licenseSetStatus: '变更授权状态',
      revokeCodes: '撤销激活码',
      expireCodes: '立即过期激活码',
      deviceSetState: '变更设备状态'
    },
    {
      accountsDescription: 'Manage customer identity, account state, and commercial relationships.',
      licensesDescription: 'A unified view of plans, seats, expiry, and license standing.',
      codesDescription: 'Issue, track, and revoke single-use or multi-use activation codes.',
      devicesDescription: 'Review device state, risk signals, and recent activity.',
      jobsDescription: 'Recoverable, cancelable bulk operations with item-level audit records.',
      auditDescription: 'Immutable security, licensing, and commercial operation history.',
      id: 'ID',
      accountId: 'Account ID',
      account: 'Account',
      licenseId: 'License ID',
      license: 'License',
      state: 'State',
      status: 'Status',
      note: 'Note',
      createdAt: 'Created at',
      expiresAt: 'Expires at',
      plan: 'Plan',
      codePrefix: 'Code prefix',
      redeemed: 'Redeemed',
      deviceId: 'Device ID',
      platform: 'Platform',
      lastSeen: 'Last activity',
      jobId: 'Job ID',
      operationType: 'Operation type',
      totalItems: 'Total items',
      completed: 'Completed',
      time: 'Time',
      event: 'Event',
      outcome: 'Outcome',
      cause: 'Reason',
      syncFailed: 'Synchronization failed',
      operationFailed: 'Operation failed',
      missingVersion: 'The resource response is missing rowVersion; refresh and try again',
      resourceChanged:
        'This resource changed in another session. The latest state is loaded; review it before retrying.',
      showing: 'Showing {count} records',
      issueCodes: 'Issue activation codes',
      createJob: 'Create bulk job',
      createResource: 'Create {name}',
      onlyOnce: 'Shown only once',
      deliveryWarning:
        'Copy and store these values now. Acknowledgement destroys the encrypted server delivery.',
      copyCodes: 'Copy all activation codes',
      copiedCodes: 'Activation codes copied',
      copyFailed: 'Copy failed; select the activation codes manually',
      acknowledge: 'Stored securely; destroy delivery',
      optional: 'Optional',
      seats: 'Team seats',
      expiry: 'Expiry',
      issueCount: 'Number to issue',
      redemptionLimit: 'Redemptions per code',
      channel: 'Channel',
      targetState: 'Target state',
      targetIds: 'Target IDs (one per line)',
      reasonPlaceholder: 'Explain the business basis; this is written to the audit log',
      submitting: 'Submitting…',
      confirmCreate: 'Confirm creation',
      accountState: 'Account state',
      licenseState: 'License status',
      licenseAction: 'License change',
      licensePlan: 'License plan',
      licenseExpiry: 'License expiry',
      changeStatus: 'Commercial status',
      changePlan: 'Plan and seats',
      changeExpiry: 'Expiry',
      deviceState: 'Device state',
      codeAction: 'Activation-code action',
      cancelJob: 'Request bulk-job cancellation',
      cancelJobDetail: 'Items already running may finish; items not yet started will be canceled.',
      actionReasonPlaceholder: 'Explain the business or security basis',
      selectAction: 'Select an allowed state change',
      confirmCancel: 'Confirm cancellation',
      apply: 'Apply change',
      create: 'Create',
      manage: 'Manage',
      refresh: 'Refresh',
      close: 'Close',
      cancel: 'Cancel',
      allStatuses: 'All statuses',
      filterStatus: 'Filter by status',
      previous: 'Previous',
      next: 'Next',
      dateOrNone: '2027-01-01 or none',
      durationOrNone: '+30d or none',
      accountSetState: 'Set account state',
      licenseSetStatus: 'Set license status',
      revokeCodes: 'Revoke activation codes',
      expireCodes: 'Expire activation codes now',
      deviceSetState: 'Set device state'
    }
  );
  let config = $derived<
    Record<
      string,
      {
        endpoint: string;
        description: string;
        columns: {
          key: string;
          label: string;
          type?: 'status' | 'time' | 'mono' | 'plan' | 'job-kind' | 'enabled' | 'number';
          align?: 'start' | 'center' | 'end';
        }[];
      }
    >
  >({
    accounts: {
      endpoint: '/accounts',
      description: messages[$locale].accountsDescription,
      columns: [
        { key: 'id', label: messages[$locale].accountId, type: 'mono' },
        { key: 'state', label: messages[$locale].state, type: 'status' },
        { key: 'note', label: messages[$locale].note },
        { key: 'createdAt', label: messages[$locale].createdAt, type: 'time' }
      ]
    },
    licenses: {
      endpoint: '/licenses',
      description: messages[$locale].licensesDescription,
      columns: [
        { key: 'id', label: messages[$locale].licenseId, type: 'mono' },
        { key: 'accountId', label: messages[$locale].account, type: 'mono' },
        { key: 'plan', label: messages[$locale].plan, type: 'plan' },
        { key: 'status', label: messages[$locale].status, type: 'status' },
        { key: 'expiresAt', label: messages[$locale].expiresAt, type: 'time' }
      ]
    },
    codes: {
      endpoint: '/activation-codes',
      description: messages[$locale].codesDescription,
      columns: [
        { key: 'codePrefix', label: messages[$locale].codePrefix, type: 'mono' },
        { key: 'accountId', label: messages[$locale].account, type: 'mono' },
        { key: 'status', label: messages[$locale].status, type: 'status' },
        { key: 'redeemedCount', label: messages[$locale].redeemed, type: 'number' },
        { key: 'expiresAt', label: messages[$locale].expiresAt, type: 'time' }
      ]
    },
    devices: {
      endpoint: '/devices',
      description: messages[$locale].devicesDescription,
      columns: [
        { key: 'deviceId', label: messages[$locale].deviceId, type: 'mono' },
        { key: 'accountId', label: messages[$locale].account, type: 'mono' },
        { key: 'state', label: messages[$locale].state, type: 'status' },
        { key: 'platform', label: messages[$locale].platform, align: 'center' },
        { key: 'lastSeenAt', label: messages[$locale].lastSeen, type: 'time' }
      ]
    },
    jobs: {
      endpoint: '/bulk-jobs',
      description: messages[$locale].jobsDescription,
      columns: [
        { key: 'id', label: messages[$locale].jobId, type: 'mono' },
        { key: 'kind', label: messages[$locale].operationType, type: 'job-kind' },
        { key: 'status', label: messages[$locale].status, type: 'status' },
        { key: 'totalItems', label: messages[$locale].totalItems, type: 'number' },
        { key: 'completedItems', label: messages[$locale].completed, type: 'number' },
        { key: 'createdAt', label: messages[$locale].createdAt, type: 'time' }
      ]
    },
    audit: {
      endpoint: '/audit-events',
      description: messages[$locale].auditDescription,
      columns: [
        { key: 'occurredAt', label: messages[$locale].time, type: 'time' },
        { key: 'eventType', label: messages[$locale].event },
        { key: 'outcome', label: messages[$locale].outcome, type: 'status' },
        { key: 'accountId', label: messages[$locale].account, type: 'mono' },
        { key: 'reasonCode', label: messages[$locale].cause }
      ]
    }
  });
  let loadGeneration = 0;
  let copyStatus = $state('');
  let current = $derived(config[resource]);
  let title = $derived((copy[$locale] as Record<string, string>)[resource] ?? resource);
  let statusOptions = $derived([
    ...new Set(
      rows.map((row) => String(row.status ?? row.state ?? row.outcome ?? '')).filter(Boolean)
    )
  ]);
  let filterOptions = $derived([
    { value: 'all', label: copy[$locale].allStatuses },
    ...statusOptions.map((status) => ({ value: status, label: statusLabel(status, $locale) }))
  ]);
  let filtered = $derived(
    rows.filter(
      (row) =>
        (!query || JSON.stringify(row).toLowerCase().includes(query.toLowerCase())) &&
        (statusFilter === 'all' || String(row.status ?? row.state ?? row.outcome) === statusFilter)
    )
  );
  let permissionSet = $derived(new Set(permissions));
  let canCreate = $derived(
    (resource === 'accounts' && permissionSet.has('account.write')) ||
      (resource === 'licenses' && permissionSet.has('license.write')) ||
      (resource === 'codes' && permissionSet.has('code.issue')) ||
      (resource === 'jobs' && permissionSet.has('job.manage'))
  );
  let canManage = $derived(
    (resource === 'accounts' &&
      (permissionSet.has('account.write') || permissionSet.has('account.denylist'))) ||
      (resource === 'licenses' && permissionSet.has('license.write')) ||
      (resource === 'codes' && permissionSet.has('code.write')) ||
      (resource === 'devices' &&
        (permissionSet.has('device.remove') || permissionSet.has('device.security'))) ||
      (resource === 'jobs' && permissionSet.has('job.manage'))
  );
  let createValid = $derived.by(() => {
    if (!form.reason?.trim()) return false;
    if (resource === 'accounts') return Boolean(form.id?.trim());
    if (resource === 'licenses') {
      const seats = Number(form.seats);
      return (
        Boolean(form.id?.trim() && form.accountId?.trim()) &&
        Number.isInteger(seats) &&
        (form.plan === 'team' ? seats >= 3 && seats <= 10000 : seats === 0)
      );
    }
    if (resource === 'codes') {
      const count = Number(form.count);
      const maximum = Number(form.maxRedemptions);
      return (
        Boolean(form.accountId?.trim() && form.licenseId?.trim()) &&
        Number.isInteger(count) &&
        count >= 1 &&
        count <= 1000 &&
        Number.isInteger(maximum) &&
        maximum >= 1 &&
        maximum <= 10000
      );
    }
    if (resource === 'jobs') return Boolean(form.kind && form.targetIds?.trim());
    return false;
  });
  let actionValid = $derived.by(() => {
    if (!actionReason.trim()) return false;
    if (resource === 'accounts')
      return (
        (permissionSet.has('account.write') && ['active', 'suspended'].includes(actionValue)) ||
        (permissionSet.has('account.denylist') && actionValue === 'denylisted')
      );
    if (resource === 'devices')
      return (
        (permissionSet.has('device.remove') && actionValue === 'removed') ||
        (permissionSet.has('device.security') && ['revoked', 'suspicious'].includes(actionValue))
      );
    if (resource !== 'licenses') return true;
    if (licenseAction === 'expiry') return Boolean(licenseExpiry.trim());
    if (licenseAction === 'plan' && licensePlan === 'team') {
      const seats = Number(licenseSeats);
      return Number.isInteger(seats) && seats >= 3 && seats <= 10000;
    }
    return true;
  });
  async function load(requestedCursor: string | null = cursor): Promise<boolean> {
    const generation = ++loadGeneration;
    const requestedResource = resource;
    const requestedConfig = current;
    loading = true;
    error = '';
    try {
      if (resource === 'audit') {
        const value = await api<AdminAuditEvent[]>(requestedConfig.endpoint);
        if (generation !== loadGeneration || resource !== requestedResource) return false;
        rows = value;
        nextCursor = null;
        cursor = null;
      } else {
        const query = `?pageSize=50${requestedCursor ? `&cursor=${encodeURIComponent(requestedCursor)}` : ''}`;
        if (resource === 'jobs') {
          const data = await api<AdminPage<AdminBulkJob>>(requestedConfig.endpoint + query);
          if (generation !== loadGeneration || resource !== requestedResource) return false;
          rows = data.items;
          nextCursor = data.nextCursor;
        } else {
          const data = await api<AdminPage<AdminVersionedResource>>(
            requestedConfig.endpoint + query
          );
          if (generation !== loadGeneration || resource !== requestedResource) return false;
          rows = data.items;
          nextCursor = data.nextCursor;
        }
        cursor = requestedCursor;
      }
      return true;
    } catch (reason) {
      if (generation === loadGeneration && resource === requestedResource) {
        error = reason instanceof Error ? reason.message : messages[$locale].syncFailed;
      }
      return false;
    } finally {
      if (generation === loadGeneration && resource === requestedResource) loading = false;
    }
  }
  function openCreate() {
    form = {
      id: '',
      note: '',
      accountId: '',
      licenseId: '',
      status: 'active',
      plan: 'pro',
      seats: '0',
      count: '1',
      maxRedemptions: '1',
      expiresAt: '',
      channel: '',
      reason: '',
      kind: 'account_set_state',
      targetIds: '',
      bulkValue: 'suspended'
    };
    formError = '';
    fieldErrors = {};
    copyStatus = '';
    deliveredCodes = [];
    delivery = null;
    jobPreview = null;
    jobExpiresAt = null;
    createAttempt.succeeded();
    creating = true;
  }
  async function submit() {
    saving = true;
    formError = '';
    fieldErrors = {};
    try {
      const createFingerprint = `${resource}:${JSON.stringify(form)}`;
      if (resource === 'accounts') {
        const request: CreateAccountRequest = {
          id: form.id,
          note: form.note || null,
          reason: form.reason
        };
        await api('/accounts', {
          method: 'POST',
          mutation: true,
          operationId: createAttempt.operationId(createFingerprint),
          body: JSON.stringify(request)
        });
      }
      if (resource === 'licenses') {
        const request: CreateLicenseRequest = {
          id: form.id,
          accountId: form.accountId,
          plan: form.plan as CreateLicenseRequest['plan'],
          status: form.status as CreateLicenseRequest['status'],
          expiresAt: form.expiresAt || null,
          purchasedSeats: Number(form.seats || 0),
          reason: form.reason
        };
        await api('/licenses', {
          method: 'POST',
          mutation: true,
          operationId: createAttempt.operationId(createFingerprint),
          body: JSON.stringify(request)
        });
      }
      if (resource === 'codes') {
        if (!delivery) {
          const request: IssueActivationCodesRequest = {
            accountId: form.accountId,
            licenseId: form.licenseId,
            count: Number(form.count),
            maxRedemptions: Number(form.maxRedemptions),
            expiresAt: form.expiresAt || null,
            channel: form.channel || null,
            note: form.note || null,
            reason: form.reason
          };
          const result = await api<ActivationCodeDeliveryResponse>('/activation-codes', {
            method: 'POST',
            mutation: true,
            operationId: createAttempt.operationId(createFingerprint),
            body: JSON.stringify(request)
          });
          delivery = result.delivery;
        }
        deliveredCodes = await api<DeliveredActivationCode[]>(
          `/secret-deliveries/${delivery.id}/claim`,
          { method: 'POST', csrf: true, body: JSON.stringify({ claimToken: delivery.claimToken }) }
        );
        return;
      }
      if (resource === 'jobs') {
        const targetIds = form.targetIds
          .split(/[\n,]/)
          .map((value) => value.trim())
          .filter(Boolean);
        let parameters: Record<string, unknown> = {};
        if (form.kind === 'account_set_state') parameters = { state: form.bulkValue };
        if (form.kind === 'license_set_status') parameters = { status: form.bulkValue };
        if (form.kind === 'activation_code_expire') {
          jobExpiresAt ??= Math.floor(Date.now() / 1000);
          parameters = { expiresAt: jobExpiresAt };
        } else jobExpiresAt = null;
        if (form.kind === 'device_set_state') parameters = { state: form.bulkValue };
        const previewFingerprint = JSON.stringify({ kind: form.kind, targetIds, parameters });
        if (!jobPreview || jobPreview.fingerprint !== previewFingerprint) {
          const preview = await api<AdminBulkJobPreview>('/bulk-jobs/previews', {
            method: 'POST',
            csrf: true,
            body: previewFingerprint
          });
          jobPreview = { fingerprint: previewFingerprint, id: preview.id };
        }
        const body = JSON.stringify({ previewId: jobPreview.id, reason: form.reason });
        await api('/bulk-jobs', {
          method: 'POST',
          mutation: true,
          operationId: createAttempt.operationId(`jobs:${previewFingerprint}:${body}`),
          body
        });
      }
      createAttempt.succeeded();
      creating = false;
      await load();
    } catch (reason) {
      if (!delivery) {
        const ambiguous = createAttempt.failed(reason);
        if (resource === 'jobs' && !ambiguous) jobPreview = null;
      }
      if (reason instanceof ApiError && reason.field) {
        fieldErrors = { [reason.field]: reason.message };
      } else {
        formError = reason instanceof Error ? reason.message : messages[$locale].operationFailed;
      }
    } finally {
      saving = false;
    }
  }
  async function acknowledge() {
    if (!delivery || saving) return;
    saving = true;
    formError = '';
    try {
      await api(`/secret-deliveries/${delivery.id}/acknowledge`, {
        method: 'POST',
        csrf: true,
        body: JSON.stringify({ claimToken: delivery.claimToken })
      });
      creating = false;
      deliveredCodes = [];
      delivery = null;
      copyStatus = '';
      createAttempt.succeeded();
      await load();
    } catch (reason) {
      formError = reason instanceof Error ? reason.message : messages[$locale].operationFailed;
    } finally {
      saving = false;
    }
  }
  function manage(row: Record<string, unknown>) {
    selected = row;
    actionReason = '';
    actionAttempt.succeeded();
    actionExpiresAt = null;
    licenseAction = 'status';
    licensePlan = String(row.plan ?? 'pro');
    licenseSeats = String(row.purchasedSeats ?? (row.plan === 'team' ? 3 : 0));
    licenseExpiry = row.expiresAt == null ? 'none' : String(row.expiresAt);
    formError = '';
    fieldErrors = {};
    actionValue =
      resource === 'accounts' || resource === 'devices'
        ? ''
        : resource === 'licenses'
          ? String(row.status)
          : resource === 'codes'
            ? 'revoke'
            : 'cancel';
  }
  async function applyAction() {
    if (!selected) return;
    saving = true;
    formError = '';
    fieldErrors = {};
    try {
      const headers: Record<string, string> = {};
      const rowVersion = typeof selected.rowVersion === 'number' ? selected.rowVersion : null;
      if (resource !== 'jobs' && rowVersion === null)
        throw new Error(messages[$locale].missingVersion);
      if (rowVersion !== null) headers['if-match'] = `"${rowVersion}"`;
      if (resource === 'codes' && actionValue === 'expire')
        actionExpiresAt ??= String(Math.floor(Date.now() / 1000));
      else actionExpiresAt = null;
      const codeActionBody: ActivationCodeActionRequest = {
        reason: actionReason,
        maxRedemptions: null,
        expiresAt: actionExpiresAt
      };
      const licenseActionBody =
        licenseAction === 'plan'
          ? {
              plan: licensePlan,
              purchasedSeats: licensePlan === 'team' ? Number(licenseSeats) : null,
              reason: actionReason
            }
          : licenseAction === 'expiry'
            ? { expiresAt: licenseExpiry.trim(), reason: actionReason }
            : { status: actionValue, reason: actionReason };
      const actionBody =
        resource === 'accounts'
          ? { state: actionValue, reason: actionReason }
          : resource === 'licenses'
            ? licenseActionBody
            : resource === 'devices'
              ? { state: actionValue, reason: actionReason }
              : resource === 'codes'
                ? codeActionBody
                : { reason: actionReason };
      const actionFingerprint = `${resource}:${String(selected.id ?? selected.deviceId ?? selected.codeHash)}:${actionValue}:${headers['if-match'] ?? ''}:${JSON.stringify(actionBody)}`;
      const actionOperationId = actionAttempt.operationId(actionFingerprint);
      if (resource === 'accounts')
        await api(`/accounts/${selected.id}/actions/set-state`, {
          method: 'POST',
          mutation: true,
          operationId: actionOperationId,
          headers,
          body: JSON.stringify({ state: actionValue, reason: actionReason })
        });
      if (resource === 'licenses')
        await api(`/licenses/${selected.id}/actions/set-${licenseAction}`, {
          method: 'POST',
          mutation: true,
          operationId: actionOperationId,
          headers,
          body: JSON.stringify(licenseActionBody)
        });
      if (resource === 'devices')
        await api(`/devices/${selected.deviceId}/actions/set-state`, {
          method: 'POST',
          mutation: true,
          operationId: actionOperationId,
          headers,
          body: JSON.stringify({ state: actionValue, reason: actionReason })
        });
      if (resource === 'codes')
        await api(`/activation-codes/${selected.codeHash}/actions/${actionValue}`, {
          method: 'POST',
          mutation: true,
          operationId: actionOperationId,
          headers,
          body: JSON.stringify(codeActionBody)
        });
      if (resource === 'jobs')
        await api(`/bulk-jobs/${selected.id}/actions/cancel`, {
          method: 'POST',
          mutation: true,
          operationId: actionOperationId,
          body: JSON.stringify({ reason: actionReason })
        });
      actionAttempt.succeeded();
      selected = null;
      await load();
    } catch (reason) {
      actionAttempt.failed(reason);
      if (isVersionConflict(reason)) {
        const staleKey = selected
          ? String(selected.id ?? selected.deviceId ?? selected.codeHash ?? '')
          : '';
        if (!staleKey) {
          selected = null;
          error = messages[$locale].resourceChanged;
        } else if (await load()) {
          const latest = rows.find(
            (row) => String(row.id ?? row.deviceId ?? row.codeHash ?? '') === staleKey
          );
          if (latest) {
            manage(latest);
            formError = messages[$locale].resourceChanged;
          } else {
            selected = null;
            error = messages[$locale].resourceChanged;
          }
        } else {
          selected = null;
        }
      } else if (reason instanceof ApiError && reason.field) {
        fieldErrors = { [reason.field]: reason.message };
      } else {
        formError = reason instanceof Error ? reason.message : messages[$locale].operationFailed;
      }
    } finally {
      saving = false;
    }
  }
  function exportData() {
    const blob = new Blob([JSON.stringify(filtered, null, 2)], { type: 'application/json' });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = `camellia-${resource}-${new Date().toISOString().slice(0, 10)}.json`;
    link.click();
    URL.revokeObjectURL(link.href);
  }
  async function nextPage() {
    if (!nextCursor || loading) return;
    const previous = cursor ?? '';
    const target = nextCursor;
    if (await load(target)) cursorHistory = [...cursorHistory, previous];
  }
  async function previousPage() {
    const previous = cursorHistory.at(-1);
    if (previous === undefined || loading) return;
    if (await load(previous || null)) cursorHistory = cursorHistory.slice(0, -1);
  }
  async function copyDeliveredCodes() {
    try {
      await navigator.clipboard.writeText(deliveredCodes.map((item) => item.code).join('\n'));
      copyStatus = messages[$locale].copiedCodes;
    } catch {
      copyStatus = messages[$locale].copyFailed;
    }
  }
  function closeCreate() {
    if (!delivery && !saving) creating = false;
  }
  function closeSelected() {
    if (!saving) selected = null;
  }
  $effect(() => {
    resource;
    cursor = null;
    cursorHistory = [];
    loadGeneration++;
    untrack(() => {
      const intent = takeResourceIntent(resource);
      if (intent) {
        openCreate();
        form.accountId = intent.accountId;
        form.licenseId = intent.licenseId;
      }
      void load(null);
    });
  });
</script>

<div class="page-heading">
  <div>
    <span class="breadcrumb">{copy[$locale].console} / {title}</span>
    <h1>{title}</h1>
    <p>{current.description}</p>
  </div>
  <div class="heading-actions">
    <button class="secondary" onclick={exportData} disabled={!filtered.length}
      ><Download size={17} />{copy[$locale].export}</button
    >{#if canCreate}<button class="primary" onclick={openCreate}
        ><Plus size={17} />{copy[$locale].create}</button
      >{/if}
  </div>
</div>
<section class="panel resource-panel">
  <div class="resource-toolbar">
    <div class="search-field">
      <Search size={17} /><input bind:value={query} placeholder="{copy[$locale].search} {title}…" />
    </div>
    <div class="toolbar-actions">
      <FilterSelect
        bind:value={statusFilter}
        options={filterOptions}
        label={messages[$locale].filterStatus}
      /><button
        class="icon-button"
        onclick={() => load()}
        aria-label={messages[$locale].refresh}
        disabled={loading}><RefreshCw class={loading ? 'spin' : ''} size={18} /></button
      >
    </div>
  </div>
  {#if error}<div class="inline-error">
      <span>{error}</span><button onclick={() => void load()}>{copy[$locale].retry}</button>
    </div>{/if}
  <ResourceTable
    columns={current.columns}
    rows={filtered}
    {loading}
    onSelect={canManage ? manage : undefined}
  />
  <footer class="table-footer">
    <span>{messages[$locale].showing.replace('{count}', String(filtered.length))}</span
    >{#if resource !== 'audit'}<div>
        <button onclick={previousPage} disabled={!cursorHistory.length || loading}
          >{copy[$locale].previous}</button
        ><button class="current" aria-current="page">{cursorHistory.length + 1}</button><button
          onclick={nextPage}
          disabled={!nextCursor || loading}>{copy[$locale].next}</button
        >
      </div>{/if}
  </footer>
</section>

{#if creating}
  <div class="modal-layer" role="presentation">
    <button
      class="modal-scrim"
      aria-label={messages[$locale].close}
      onclick={closeCreate}
      disabled={Boolean(delivery) || saving}
    ></button>
    <div
      use:focusTrap={{
        onEscape: delivery || saving ? undefined : closeCreate,
        initialFocus: deliveredCodes.length ? '.copy-all' : 'input, select'
      }}
      class="modal-card"
      role="dialog"
      aria-modal="true"
      aria-labelledby="create-resource-title"
    >
      <header>
        <div>
          <span class="eyebrow"
            >{messages[$locale].create.toUpperCase()} / {title.toUpperCase()}</span
          >
          <h2 id="create-resource-title">
            {resource === 'codes'
              ? messages[$locale].issueCodes
              : resource === 'jobs'
                ? messages[$locale].createJob
                : messages[$locale].createResource.replace('{name}', title)}
          </h2>
        </div>
        <button
          onclick={closeCreate}
          disabled={Boolean(delivery) || saving}
          class="icon-button modal-close"
          aria-label={messages[$locale].close}><X size={18} /></button
        >
      </header>
      {#if formError}<div class="form-error" role="alert">{formError}</div>{/if}
      {#if copyStatus}<p class="sr-only" role="status">{copyStatus}</p>{/if}
      {#if deliveredCodes.length}
        <div class="secret-warning">
          <strong>{messages[$locale].onlyOnce}</strong><span
            >{messages[$locale].deliveryWarning}</span
          >
        </div>
        <div class="code-delivery">
          {#each deliveredCodes as item}<code>{item.code}</code>{/each}
        </div>
        <button class="secondary copy-all" onclick={copyDeliveredCodes}
          >{messages[$locale].copyCodes}</button
        >
        <footer>
          <button class="primary" onclick={acknowledge} disabled={saving}
            >{messages[$locale].acknowledge}</button
          >
        </footer>
      {:else}
        <div class="form-grid">
          {#if resource === 'accounts'}<label
              >{messages[$locale].accountId}<input
                bind:value={form.id}
                placeholder="acct_customer_001"
                required
              /></label
            ><label
              >{messages[$locale].note}<input
                bind:value={form.note}
                placeholder={messages[$locale].optional}
              /></label
            >{/if}
          {#if resource === 'licenses'}<label
              >{messages[$locale].licenseId}<input
                bind:value={form.id}
                placeholder="lic_customer_001"
                required
              /></label
            ><label
              >{messages[$locale].accountId}<ResourceCombobox
                kind="account"
                bind:value={form.accountId}
                placeholder="acct_customer_001"
              /></label
            ><label
              >{messages[$locale].plan}<select
                data-option-align="center"
                bind:value={form.plan}
                onchange={() => (form.seats = form.plan === 'team' ? '3' : '0')}
                ><option value="free">{planLabel('free', $locale)}</option><option value="pro"
                  >{planLabel('pro', $locale)}</option
                ><option value="team">{planLabel('team', $locale)}</option></select
              ></label
            ><label
              >{messages[$locale].status}<select data-option-align="center" bind:value={form.status}
                ><option value="active">{statusLabel('active', $locale)}</option><option
                  value="past_due">{statusLabel('past_due', $locale)}</option
                ><option value="canceled">{statusLabel('canceled', $locale)}</option></select
              ></label
            >{#if form.plan === 'team'}<label
                >{messages[$locale].seats}<input
                  type="number"
                  min="3"
                  max="10000"
                  bind:value={form.seats}
                  aria-invalid={Boolean(fieldErrors.purchasedSeats)}
                  aria-describedby={fieldErrors.purchasedSeats ? 'license-seats-error' : undefined}
                  oninput={() => (fieldErrors = {})}
                />{#if fieldErrors.purchasedSeats}<small
                    id="license-seats-error"
                    class="field-error"
                    role="alert">{fieldErrors.purchasedSeats}</small
                  >{/if}</label
              >{/if}<label
              >{messages[$locale].expiry}<input
                bind:value={form.expiresAt}
                placeholder={messages[$locale].dateOrNone}
              /></label
            >{/if}
          {#if resource === 'codes'}<label
              >{messages[$locale].accountId}<ResourceCombobox
                kind="account"
                bind:value={form.accountId}
                placeholder="acct_customer_001"
              /></label
            ><label
              >{messages[$locale].licenseId}<ResourceCombobox
                kind="license"
                accountId={form.accountId}
                bind:value={form.licenseId}
                placeholder="lic_customer_001"
              /></label
            ><label
              >{messages[$locale].issueCount}<input
                type="number"
                min="1"
                max="1000"
                bind:value={form.count}
              /></label
            ><label
              >{messages[$locale].redemptionLimit}<input
                type="number"
                min="1"
                max="10000"
                bind:value={form.maxRedemptions}
              /></label
            ><label
              >{messages[$locale].expiry}<input
                bind:value={form.expiresAt}
                placeholder={messages[$locale].durationOrNone}
              /></label
            ><label
              >{messages[$locale].channel}<input
                bind:value={form.channel}
                placeholder="manual"
              /></label
            >{/if}
          {#if resource === 'jobs'}<label
              >{messages[$locale].operationType}<select
                data-option-align="center"
                bind:value={form.kind}
                onchange={() =>
                  (form.bulkValue =
                    form.kind === 'device_set_state'
                      ? 'removed'
                      : form.kind === 'license_set_status'
                        ? 'past_due'
                        : 'suspended')}
                ><option value="account_set_state">{messages[$locale].accountSetState}</option
                ><option value="license_set_status">{messages[$locale].licenseSetStatus}</option
                ><option value="activation_code_revoke">{messages[$locale].revokeCodes}</option
                ><option value="activation_code_expire">{messages[$locale].expireCodes}</option
                ><option value="device_set_state">{messages[$locale].deviceSetState}</option
                ></select
              ></label
            >{#if !form.kind.startsWith('activation_code')}<label
                >{messages[$locale].targetState}<select
                  data-option-align="center"
                  bind:value={form.bulkValue}
                  >{#if form.kind === 'account_set_state'}<option value="active"
                      >{statusLabel('active', $locale)}</option
                    ><option value="suspended">{statusLabel('suspended', $locale)}</option><option
                      value="denylisted">{statusLabel('denylisted', $locale)}</option
                    >{:else if form.kind === 'license_set_status'}<option value="active"
                      >{statusLabel('active', $locale)}</option
                    ><option value="past_due">{statusLabel('past_due', $locale)}</option><option
                      value="canceled">{statusLabel('canceled', $locale)}</option
                    >{:else}<option value="removed">{statusLabel('removed', $locale)}</option
                    ><option value="revoked">{statusLabel('revoked', $locale)}</option><option
                      value="suspicious">{statusLabel('suspicious', $locale)}</option
                    >{/if}</select
                ></label
              >{/if}<label class="wide"
              >{messages[$locale].targetIds}<textarea
                bind:value={form.targetIds}
                placeholder="acct_001\nacct_002"></textarea></label
            >{/if}
          <label class="wide"
            >{copy[$locale].reason}<textarea
              bind:value={form.reason}
              placeholder={messages[$locale].reasonPlaceholder}></textarea></label
          >
        </div>
        <footer>
          <button class="secondary" onclick={closeCreate} disabled={saving}
            >{copy[$locale].cancel}</button
          ><button class="primary" onclick={submit} disabled={saving || !createValid}
            >{saving ? messages[$locale].submitting : messages[$locale].confirmCreate}</button
          >
        </footer>
      {/if}
    </div>
  </div>
{/if}
{#if selected}
  <div class="modal-layer">
    <button
      class="modal-scrim"
      aria-label={messages[$locale].close}
      onclick={closeSelected}
      disabled={saving}
    ></button>
    <div
      use:focusTrap={{
        onEscape: saving ? undefined : closeSelected,
        initialFocus: 'select, textarea'
      }}
      class="modal-card manage-card"
      role="dialog"
      aria-modal="true"
      aria-labelledby="manage-resource-title"
    >
      <header>
        <div>
          <span class="eyebrow"
            >{messages[$locale].manage.toUpperCase()} / {title.toUpperCase()}</span
          >
          <h2 id="manage-resource-title">
            {String(selected.id ?? selected.deviceId ?? selected.codePrefix)}
          </h2>
        </div>
        <button
          class="icon-button modal-close"
          onclick={closeSelected}
          disabled={saving}
          aria-label={messages[$locale].close}><X size={18} /></button
        >
      </header>
      {#if formError}<div class="form-error" role="alert">{formError}</div>{/if}
      {#if resource === 'accounts'}<label class="standalone-label"
          >{messages[$locale].accountState}<select
            data-option-align="center"
            bind:value={actionValue}
            ><option value="" disabled>{messages[$locale].selectAction}</option
            >{#if permissionSet.has('account.write')}<option value="active"
                >{statusLabel('active', $locale)}</option
              ><option value="suspended">{statusLabel('suspended', $locale)}</option
              >{/if}{#if permissionSet.has('account.denylist')}<option value="denylisted"
                >{statusLabel('denylisted', $locale)}</option
              >{/if}</select
          ></label
        >{/if}
      {#if resource === 'licenses'}<div class="form-grid manage-license-grid">
          <label
            >{messages[$locale].licenseAction}<select
              data-option-align="center"
              bind:value={licenseAction}
              ><option value="status">{messages[$locale].changeStatus}</option><option value="plan"
                >{messages[$locale].changePlan}</option
              ><option value="expiry">{messages[$locale].changeExpiry}</option></select
            ></label
          >{#if licenseAction === 'status'}<label
              >{messages[$locale].licenseState}<select
                data-option-align="center"
                bind:value={actionValue}
                ><option value="active">{statusLabel('active', $locale)}</option><option
                  value="past_due">{statusLabel('past_due', $locale)}</option
                ><option value="canceled">{statusLabel('canceled', $locale)}</option></select
              ></label
            >{:else if licenseAction === 'plan'}<label
              >{messages[$locale].licensePlan}<select
                data-option-align="center"
                bind:value={licensePlan}
                onchange={() => (licenseSeats = licensePlan === 'team' ? '3' : '0')}
                ><option value="free">{planLabel('free', $locale)}</option><option value="pro"
                  >{planLabel('pro', $locale)}</option
                ><option value="team">{planLabel('team', $locale)}</option></select
              ></label
            >{#if licensePlan === 'team'}<label
                >{messages[$locale].seats}<input
                  type="number"
                  min="3"
                  max="10000"
                  bind:value={licenseSeats}
                  aria-invalid={Boolean(fieldErrors.purchasedSeats)}
                  aria-describedby={fieldErrors.purchasedSeats
                    ? 'manage-license-seats-error'
                    : undefined}
                  oninput={() => (fieldErrors = {})}
                />{#if fieldErrors.purchasedSeats}<small
                    id="manage-license-seats-error"
                    class="field-error"
                    role="alert">{fieldErrors.purchasedSeats}</small
                  >{/if}</label
              >{/if}{:else}<label
              >{messages[$locale].licenseExpiry}<input
                bind:value={licenseExpiry}
                placeholder={messages[$locale].dateOrNone}
              /></label
            >{/if}
        </div>{/if}
      {#if resource === 'devices'}<label class="standalone-label"
          >{messages[$locale].deviceState}<select
            data-option-align="center"
            bind:value={actionValue}
            ><option value="" disabled>{messages[$locale].selectAction}</option
            >{#if permissionSet.has('device.remove')}<option value="removed"
                >{statusLabel('removed', $locale)}</option
              >{/if}{#if permissionSet.has('device.security')}<option value="revoked"
                >{statusLabel('revoked', $locale)}</option
              ><option value="suspicious">{statusLabel('suspicious', $locale)}</option>{/if}</select
          ></label
        >{/if}
      {#if resource === 'codes'}<label class="standalone-label"
          >{messages[$locale].codeAction}<select data-option-align="center" bind:value={actionValue}
            ><option value="revoke">{actionLabel('revoke', $locale)}</option><option value="expire"
              >{actionLabel('expire', $locale)}</option
            ><option value="restore">{actionLabel('restore', $locale)}</option></select
          ></label
        >{/if}
      {#if resource === 'jobs'}<div class="secret-warning">
          <strong>{messages[$locale].cancelJob}</strong><span
            >{messages[$locale].cancelJobDetail}</span
          >
        </div>{/if}<label class="standalone-label"
        >{copy[$locale].reason}<textarea
          bind:value={actionReason}
          placeholder={messages[$locale].actionReasonPlaceholder}></textarea></label
      >
      <footer>
        <button class="secondary" onclick={closeSelected} disabled={saving}
          >{copy[$locale].close}</button
        ><button
          class="primary danger-action"
          onclick={applyAction}
          disabled={saving || !actionValid}
          >{saving
            ? messages[$locale].submitting
            : resource === 'jobs'
              ? messages[$locale].confirmCancel
              : messages[$locale].apply}</button
        >
      </footer>
    </div>
  </div>
{/if}
