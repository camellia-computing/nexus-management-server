<script lang="ts">
  import { onMount } from 'svelte';
  import {
    Copy,
    KeyRound,
    MoreHorizontal,
    Plus,
    RefreshCw,
    RotateCcw,
    ShieldCheck,
    UserRound,
    UserX,
    X
  } from '@lucide/svelte';
  import {
    api,
    isVersionConflict,
    MutationAttempt,
    type AdminEnrollmentProvisioning,
    type AdminUser,
    type AdminUserPage
  } from './api';
  import { focusTrap } from './actions/focusTrap';
  import { adminRoleLabel } from './domainLabels';
  import { defineCopy, locale } from './i18n';
  import StatusBadge from './StatusBadge.svelte';

  let { currentUser }: { currentUser: AdminUser } = $props();
  const messages = defineCopy(
    {
      breadcrumb: '控制台 / 安全',
      title: '管理员身份',
      description: '管理控制面角色、登记状态与凭据重置。',
      refresh: '刷新',
      add: '添加管理员',
      search: '搜索管理员',
      searchPlaceholder: '搜索用户名或显示名称',
      identities: '个身份',
      loading: '正在同步管理员身份…',
      empty: '没有符合条件的管理员',
      edit: '编辑管理员',
      reset: '重置凭据',
      disable: '禁用管理员',
      loadMore: '加载更多',
      identityControl: '身份控制',
      username: '用户名',
      displayName: '显示名称',
      roles: '控制面角色',
      changeReason: '变更原因',
      reasonPlaceholder: '记录业务或安全原因',
      saving: '正在保存…',
      save: '保存',
      cancel: '取消',
      close: '关闭',
      securityAction: '安全操作',
      resetTitle: '重置管理员凭据',
      disableDetail: '将立即撤销 {name} 的全部会话并禁止登录。',
      resetDetail: '将立即撤销 {name} 的会话、密码、TOTP 与恢复码，并签发新的十分钟登记令牌。',
      actionReason: '操作原因',
      actionReasonPlaceholder: '说明执行此安全操作的原因',
      executing: '正在执行…',
      confirm: '确认操作',
      delivery: '一次性交付',
      deliveryTitle: '安全交付登记令牌',
      deliveryDetail: '请通过独立安全通道交给该管理员。令牌十分钟后失效，确认交付后密文会被销毁。',
      claiming: '正在领取安全内容…',
      retry: '重试',
      copyToken: '复制登记令牌',
      acknowledge: '已安全保存并销毁服务端副本',
      copied: '登记令牌已复制',
      copyFailed: '无法复制，请手动选择登记令牌',
      listFailed: '管理员列表加载失败',
      saveFailed: '管理员保存失败',
      actionFailed: '管理员操作失败',
      identityChanged: '管理员身份已在其他会话中更新。已加载最新状态，请复核后重试。',
      claimFailed: '登记令牌领取失败',
      acknowledgeFailed: '安全确认失败',
      ownerRole: '全部控制面权限与管理员身份管理',
      licensingRole: '账户、授权、设备、激活码与 Team 运营',
      securityRole: '安全处置、审计导出与风险设备管理',
      billingRole: '账单、付款、商业方案与审核',
      supportRole: '面向客户支持的受限日常操作',
      auditorRole: '只读业务视图与审计导出'
    },
    {
      breadcrumb: 'Console / Security',
      title: 'Administrator identities',
      description: 'Manage control-plane roles, enrollment state, and credential resets.',
      refresh: 'Refresh',
      add: 'Add administrator',
      search: 'Search administrators',
      searchPlaceholder: 'Search username or display name',
      identities: 'identities',
      loading: 'Synchronizing administrator identities…',
      empty: 'No matching administrators',
      edit: 'Edit administrator',
      reset: 'Reset credentials',
      disable: 'Disable administrator',
      loadMore: 'Load more',
      identityControl: 'Identity control',
      username: 'Username',
      displayName: 'Display name',
      roles: 'Control-plane roles',
      changeReason: 'Change reason',
      reasonPlaceholder: 'Record the business or security reason',
      saving: 'Saving…',
      save: 'Save',
      cancel: 'Cancel',
      close: 'Close',
      securityAction: 'Security action',
      resetTitle: 'Reset administrator credentials',
      disableDetail: 'Immediately revoke every session for {name} and prevent sign-in.',
      resetDetail:
        'Immediately revoke the sessions, password, TOTP, and recovery codes for {name}, then issue a new ten-minute enrollment token.',
      actionReason: 'Action reason',
      actionReasonPlaceholder: 'Explain the reason for this security action',
      executing: 'Working…',
      confirm: 'Confirm action',
      delivery: 'One-time delivery',
      deliveryTitle: 'Deliver enrollment token securely',
      deliveryDetail:
        'Send this token through an independent secure channel. It expires in ten minutes and its encrypted server copy is destroyed after acknowledgement.',
      claiming: 'Retrieving secure content…',
      retry: 'Retry',
      copyToken: 'Copy enrollment token',
      acknowledge: 'Stored securely; destroy the server copy',
      copied: 'Enrollment token copied',
      copyFailed: 'Copy failed; select the enrollment token manually',
      listFailed: 'Administrator list failed to load',
      saveFailed: 'Administrator could not be saved',
      actionFailed: 'Administrator action failed',
      identityChanged:
        'This administrator changed in another session. The latest state is loaded; review it before retrying.',
      claimFailed: 'Enrollment token could not be claimed',
      acknowledgeFailed: 'Secure acknowledgement failed',
      ownerRole: 'All control-plane permissions and administrator identity management',
      licensingRole: 'Accounts, licenses, devices, activation codes, and Team operations',
      securityRole: 'Security response, audit export, and risky-device management',
      billingRole: 'Billing, payments, commercial offers, and reviews',
      supportRole: 'Restricted customer-support operations',
      auditorRole: 'Read-only business views and audit export'
    }
  );
  let roleOptions = $derived([
    ['platform_owner', adminRoleLabel('platform_owner', $locale), messages[$locale].ownerRole],
    [
      'licensing_admin',
      adminRoleLabel('licensing_admin', $locale),
      messages[$locale].licensingRole
    ],
    ['security_admin', adminRoleLabel('security_admin', $locale), messages[$locale].securityRole],
    ['billing_admin', adminRoleLabel('billing_admin', $locale), messages[$locale].billingRole],
    [
      'support_operator',
      adminRoleLabel('support_operator', $locale),
      messages[$locale].supportRole
    ],
    ['auditor', adminRoleLabel('auditor', $locale), messages[$locale].auditorRole]
  ] as const);

  let users = $state<AdminUser[]>([]);
  let nextCursor = $state<string | undefined>();
  let loading = $state(true);
  let saving = $state(false);
  let error = $state('');
  let query = $state('');
  let editor = $state<AdminUser | 'create' | null>(null);
  let username = $state('');
  let displayName = $state('');
  let roles = $state<string[]>([]);
  let reason = $state('');
  let action = $state<{ kind: 'disable' | 'reset'; user: AdminUser } | null>(null);
  const editorAttempt = new MutationAttempt();
  const actionAttempt = new MutationAttempt();
  let provisioning = $state<AdminEnrollmentProvisioning | null>(null);
  let enrollmentToken = $state('');
  let deliveryError = $state('');
  let deliveryBusy = $state(false);
  let deliveryStatus = $state('');

  async function load(append = false) {
    loading = true;
    error = '';
    const params = new URLSearchParams({ pageSize: '100' });
    if (append && nextCursor) params.set('cursor', nextCursor);
    if (query.trim()) params.set('query', query.trim());
    try {
      const page = await api<AdminUserPage>(`/admin-users?${params}`);
      users = append ? [...users, ...page.items] : page.items;
      nextCursor = page.nextCursor;
    } catch (cause) {
      error = cause instanceof Error ? cause.message : messages[$locale].listFailed;
    } finally {
      loading = false;
    }
  }

  function openCreate() {
    error = '';
    editor = 'create';
    username = '';
    displayName = '';
    roles = ['support_operator'];
    reason = '';
    editorAttempt.succeeded();
  }

  function openEdit(user: AdminUser) {
    error = '';
    editor = user;
    username = user.username;
    displayName = user.displayName;
    roles = [...user.roles];
    reason = '';
    editorAttempt.succeeded();
  }

  async function save() {
    if (!editor || !displayName.trim() || roles.length === 0 || !reason.trim()) return;
    saving = true;
    error = '';
    const body = JSON.stringify(
      editor === 'create'
        ? { username, displayName, roles, reason }
        : { displayName, roles, reason }
    );
    const path = editor === 'create' ? '/admin-users' : `/admin-users/${editor.id}`;
    const operationId = editorAttempt.operationId(
      `${path}:${editor === 'create' ? '' : editor.rowVersion}:${body}`
    );
    try {
      if (editor === 'create') {
        const result = await api<AdminEnrollmentProvisioning>('/admin-users', {
          method: 'POST',
          mutation: true,
          operationId,
          body
        });
        editorAttempt.succeeded();
        editor = null;
        await load();
        await reveal(result);
      } else {
        await api<AdminUser>(`/admin-users/${editor.id}`, {
          method: 'PATCH',
          mutation: true,
          operationId,
          headers: { 'if-match': `"${editor.rowVersion}"` },
          body
        });
        editorAttempt.succeeded();
        editor = null;
        await load();
      }
    } catch (cause) {
      editorAttempt.failed(cause);
      if (isVersionConflict(cause)) {
        editor = null;
        await load();
        error = messages[$locale].identityChanged;
      } else {
        error = cause instanceof Error ? cause.message : messages[$locale].saveFailed;
      }
    } finally {
      saving = false;
    }
  }

  async function runAction() {
    if (!action || !reason.trim()) return;
    saving = true;
    error = '';
    const selected = action;
    const path = selected.kind === 'disable' ? 'disable' : 'reset-enrollment';
    const body = JSON.stringify({ reason });
    const operationId = actionAttempt.operationId(
      `${selected.user.id}:${path}:${selected.user.rowVersion}:${body}`
    );
    try {
      const result = await api<AdminUser | AdminEnrollmentProvisioning>(
        `/admin-users/${selected.user.id}/actions/${path}`,
        {
          method: 'POST',
          mutation: true,
          operationId,
          headers: { 'if-match': `"${selected.user.rowVersion}"` },
          body
        }
      );
      actionAttempt.succeeded();
      action = null;
      await load();
      if (selected.kind === 'reset') await reveal(result as AdminEnrollmentProvisioning);
    } catch (cause) {
      actionAttempt.failed(cause);
      if (isVersionConflict(cause)) {
        action = null;
        await load();
        error = messages[$locale].identityChanged;
      } else {
        error = cause instanceof Error ? cause.message : messages[$locale].actionFailed;
      }
    } finally {
      saving = false;
    }
  }

  async function reveal(value: AdminEnrollmentProvisioning) {
    provisioning = value;
    enrollmentToken = '';
    deliveryError = '';
    deliveryStatus = '';
    deliveryBusy = true;
    try {
      const secret = await api<{ enrollmentToken: string }>(
        `/secret-deliveries/${value.delivery.id}/claim`,
        {
          method: 'POST',
          csrf: true,
          body: JSON.stringify({ claimToken: value.delivery.claimToken })
        }
      );
      enrollmentToken = secret.enrollmentToken;
    } catch (cause) {
      deliveryError = cause instanceof Error ? cause.message : messages[$locale].claimFailed;
    } finally {
      deliveryBusy = false;
    }
  }

  async function acknowledgeDelivery() {
    if (!provisioning || !enrollmentToken) return;
    deliveryBusy = true;
    try {
      await api(`/secret-deliveries/${provisioning.delivery.id}/acknowledge`, {
        method: 'POST',
        csrf: true,
        body: JSON.stringify({ claimToken: provisioning.delivery.claimToken })
      });
      enrollmentToken = '';
      provisioning = null;
    } catch (cause) {
      deliveryError = cause instanceof Error ? cause.message : messages[$locale].acknowledgeFailed;
    } finally {
      deliveryBusy = false;
    }
  }

  function beginAction(kind: 'disable' | 'reset', user: AdminUser) {
    error = '';
    action = { kind, user };
    reason = '';
    actionAttempt.succeeded();
  }

  async function copyEnrollmentToken() {
    try {
      await navigator.clipboard.writeText(enrollmentToken);
      deliveryStatus = messages[$locale].copied;
    } catch {
      deliveryStatus = messages[$locale].copyFailed;
    }
  }

  onMount(() => {
    void load();
  });
</script>

<div class="page-heading">
  <div>
    <span class="breadcrumb">{messages[$locale].breadcrumb}</span>
    <h1>{messages[$locale].title}</h1>
    <p>{messages[$locale].description}</p>
  </div>
  <div class="heading-actions">
    <button class="secondary" onclick={() => load()} disabled={loading}
      ><RefreshCw class={loading ? 'spin' : ''} size={17} />{messages[$locale].refresh}</button
    ><button class="primary" onclick={openCreate}><Plus size={17} />{messages[$locale].add}</button>
  </div>
</div>

<section class="panel identity-panel">
  <div class="identity-toolbar">
    <label
      ><span class="sr-only">{messages[$locale].search}</span><input
        bind:value={query}
        onkeydown={(event) => event.key === 'Enter' && load()}
        placeholder={messages[$locale].searchPlaceholder}
      /></label
    ><small>{users.length} {messages[$locale].identities}</small>
  </div>
  {#if error}<div class="inline-error" role="alert">
      {error}<button onclick={() => (error = '')}>{messages[$locale].close}</button>
    </div>{/if}
  {#if loading && users.length === 0}<div class="identity-empty">{messages[$locale].loading}</div>
  {:else if users.length === 0}<div class="identity-empty">{messages[$locale].empty}</div>
  {:else}<div class="identity-list">
      {#each users as user (user.id)}
        <article>
          <span class="identity-avatar"><UserRound size={19} /></span>
          <div class="identity-name">
            <strong>{user.displayName}</strong><small>@{user.username}</small>
          </div>
          <div class="identity-roles">
            {#each user.roles as role}<span
                >{roleOptions.find(([id]) => id === role)?.[1] ?? role}</span
              >{/each}
          </div>
          <StatusBadge value={user.status} />
          <div class="identity-actions">
            <button
              title={messages[$locale].edit}
              aria-label={`${messages[$locale].edit}: ${user.displayName}`}
              onclick={() => openEdit(user)}><MoreHorizontal size={18} /></button
            >
            <button
              title={messages[$locale].reset}
              aria-label={`${messages[$locale].reset}: ${user.displayName}`}
              disabled={user.id === currentUser.id}
              onclick={() => beginAction('reset', user)}><RotateCcw size={16} /></button
            >
            <button
              class="danger-icon"
              title={messages[$locale].disable}
              aria-label={`${messages[$locale].disable}: ${user.displayName}`}
              disabled={user.id === currentUser.id || user.status === 'disabled'}
              onclick={() => beginAction('disable', user)}><UserX size={16} /></button
            >
          </div>
        </article>
      {/each}
    </div>{/if}
  {#if nextCursor}<button class="load-more" disabled={loading} onclick={() => load(true)}
      >{messages[$locale].loadMore}</button
    >{/if}
</section>

{#if editor}
  <div class="modal-layer">
    <button
      class="modal-scrim"
      aria-label={messages[$locale].close}
      onclick={() => {
        if (!saving) editor = null;
      }}
      disabled={saving}
    ></button>
    <div
      use:focusTrap={{
        onEscape: saving ? undefined : () => (editor = null),
        initialFocus: 'input:not([disabled])'
      }}
      class="modal-card identity-editor"
      role="dialog"
      aria-modal="true"
      aria-labelledby="identity-editor-title"
    >
      <header>
        <div>
          <span class="eyebrow"
            ><ShieldCheck size={14} /> {messages[$locale].identityControl.toUpperCase()}</span
          >
          <h2 id="identity-editor-title">
            {editor === 'create' ? messages[$locale].add : messages[$locale].edit}
          </h2>
        </div>
        <button
          class="icon-button modal-close"
          aria-label={messages[$locale].close}
          disabled={saving}
          onclick={() => (editor = null)}><X size={17} /></button
        >
      </header>
      {#if error}<div class="form-error" role="alert">{error}</div>{/if}
      <div class="form-grid">
        <label
          >{messages[$locale].username}<input
            bind:value={username}
            disabled={editor !== 'create'}
            autocomplete="off"
            placeholder="operator.name"
          /></label
        >
        <label
          >{messages[$locale].displayName}<input
            bind:value={displayName}
            autocomplete="off"
          /></label
        >
      </div>
      <fieldset class="role-picker">
        <legend>{messages[$locale].roles}</legend
        >{#each roleOptions as [id, label, description]}<label
            ><input type="checkbox" value={id} bind:group={roles} /><span
              ><strong>{label}</strong><small>{description}</small></span
            ></label
          >{/each}
      </fieldset>
      <label class="standalone-label"
        >{messages[$locale].changeReason}<textarea
          bind:value={reason}
          placeholder={messages[$locale].reasonPlaceholder}></textarea></label
      >
      <footer>
        <button class="secondary" disabled={saving} onclick={() => (editor = null)}
          >{messages[$locale].cancel}</button
        ><button
          class="primary"
          disabled={saving ||
            !displayName.trim() ||
            roles.length === 0 ||
            !reason.trim() ||
            (editor === 'create' && !username.trim())}
          onclick={save}>{saving ? messages[$locale].saving : messages[$locale].save}</button
        >
      </footer>
    </div>
  </div>
{/if}

{#if action}
  <div class="modal-layer">
    <button
      class="modal-scrim"
      aria-label={messages[$locale].close}
      onclick={() => {
        if (!saving) action = null;
      }}
      disabled={saving}
    ></button>
    <div
      use:focusTrap={{
        onEscape: saving ? undefined : () => (action = null),
        initialFocus: 'textarea'
      }}
      class="modal-card identity-confirm"
      role="alertdialog"
      aria-modal="true"
    >
      <header>
        <div>
          <span class="eyebrow"
            ><KeyRound size={14} /> {messages[$locale].securityAction.toUpperCase()}</span
          >
          <h2>
            {action.kind === 'disable' ? messages[$locale].disable : messages[$locale].resetTitle}
          </h2>
        </div>
        <button
          class="icon-button modal-close"
          aria-label={messages[$locale].close}
          disabled={saving}
          onclick={() => (action = null)}><X size={17} /></button
        >
      </header>
      {#if error}<div class="form-error" role="alert">{error}</div>{/if}
      <p>
        {(action.kind === 'disable'
          ? messages[$locale].disableDetail
          : messages[$locale].resetDetail
        ).replace('{name}', action.user.displayName)}
      </p>
      <label class="standalone-label"
        >{messages[$locale].actionReason}<textarea
          bind:value={reason}
          placeholder={messages[$locale].actionReasonPlaceholder}></textarea></label
      >
      <footer>
        <button class="secondary" disabled={saving} onclick={() => (action = null)}
          >{messages[$locale].cancel}</button
        ><button class="primary" disabled={saving || !reason.trim()} onclick={runAction}
          >{saving ? messages[$locale].executing : messages[$locale].confirm}</button
        >
      </footer>
    </div>
  </div>
{/if}

{#if provisioning}
  <div class="modal-layer">
    <div class="modal-scrim"></div>
    <div
      use:focusTrap={{
        initialFocus: deliveryError ? '.inline-error button' : '.delivery-secret button'
      }}
      class="modal-card enrollment-delivery"
      role="dialog"
      aria-modal="true"
      aria-labelledby="delivery-title"
    >
      <header>
        <div>
          <span class="eyebrow"
            ><ShieldCheck size={14} /> {messages[$locale].delivery.toUpperCase()}</span
          >
          <h2 id="delivery-title">{messages[$locale].deliveryTitle}</h2>
        </div>
      </header>
      <div class="delivery-user">
        <span class="identity-avatar"><UserRound size={18} /></span>
        <div>
          <strong>{provisioning.user.displayName}</strong><small
            >@{provisioning.user.username}</small
          >
        </div>
      </div>
      <p>{messages[$locale].deliveryDetail}</p>
      {#if deliveryStatus}<p class="sr-only" role="status">{deliveryStatus}</p>{/if}
      {#if deliveryBusy}<div class="identity-empty">
          {messages[$locale].claiming}
        </div>{:else if deliveryError}<div class="inline-error" role="alert">
          {deliveryError}<button onclick={() => provisioning && reveal(provisioning)}
            >{messages[$locale].retry}</button
          >
        </div>{:else}<div class="delivery-secret">
          <code>{enrollmentToken}</code><button
            aria-label={messages[$locale].copyToken}
            onclick={copyEnrollmentToken}><Copy size={17} /></button
          >
        </div>{/if}
      <footer>
        <button
          class="primary"
          disabled={deliveryBusy || !enrollmentToken}
          onclick={acknowledgeDelivery}>{messages[$locale].acknowledge}</button
        >
      </footer>
    </div>
  </div>
{/if}
