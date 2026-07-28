<script lang="ts">
  import { Search } from '@lucide/svelte';
  import { onMount } from 'svelte';

  import Administrators from '$lib/Administrators.svelte';
  import AccountSettingsDialog from '$lib/AccountSettingsDialog.svelte';
  import Billing from '$lib/Billing.svelte';
  import Dashboard from '$lib/Dashboard.svelte';
  import Enrollment from '$lib/Enrollment.svelte';
  import Login from '$lib/Login.svelte';
  import Resources from '$lib/Resources.svelte';
  import Sidebar from '$lib/Sidebar.svelte';
  import StepUpDialog from '$lib/StepUpDialog.svelte';
  import SystemPage from '$lib/SystemPage.svelte';
  import Team from '$lib/Team.svelte';
  import Topbar from '$lib/Topbar.svelte';
  import { focusTrap } from '$lib/actions/focusTrap';
  import {
    ApiError,
    api,
    setAuthenticationFailureHandler,
    setStepUpHandler,
    type AdminUser,
    type RecoveryEnrollment,
    type SessionInfo
  } from '$lib/api';
  import { copy, defineCopy, locale } from '$lib/i18n';
  import { readPreference, writePreference } from '$lib/preferences';

  const messages = defineCopy(
    {
      establishing: '正在建立安全会话…',
      controlPlane: 'Camellia Nexus 控制面',
      secureSession: '安全会话',
      secureSessionUntil: '会话最晚结束于',
      closeSearch: '关闭导航搜索',
      navigationSearch: '导航搜索',
      searchPlaceholder: '搜索控制台功能…',
      noMatches: '没有匹配的功能'
    },
    {
      establishing: 'Establishing a secure session…',
      controlPlane: 'Camellia Nexus Control Plane',
      secureSession: 'Secure session',
      secureSessionUntil: 'Session ends by',
      closeSearch: 'Close navigation search',
      navigationSearch: 'Navigation search',
      searchPlaceholder: 'Search console features…',
      noMatches: 'No matching features'
    }
  );

  const SESSION_ACTIVITY_CHECK_MS = 60_000;
  const SESSION_KEEPALIVE_AFTER_MS = 5 * 60_000;
  const SESSION_RECENT_ACTIVITY_MS = 10 * 60_000;

  const resources = new Set(['accounts', 'licenses', 'codes', 'devices', 'jobs', 'audit']);
  const destinationPermission: Record<string, string | undefined> = {
    overview: undefined,
    accounts: 'account.read',
    licenses: 'license.read',
    codes: 'code.read',
    devices: 'device.read',
    team: 'team.read',
    billing: 'billing.read',
    jobs: 'job.manage',
    audit: 'audit.read',
    administrators: 'identity.manage',
    system: 'system.read'
  };

  let user = $state<AdminUser | null>(null);
  let checking = $state(true);
  let active = $state('overview');
  let permissions = $state<string[]>([]);
  let serverVersion = $state('');
  let sessionExpiresAt = $state(0);
  let enrolling = $state(false);
  let recoveryEnrollment = $state<RecoveryEnrollment | null>(null);
  let commandOpen = $state(false);
  let commandQuery = $state('');
  let stepUpOpen = $state(false);
  let stepUpPromise: Promise<void> | null = null;
  let stepUpResolve: (() => void) | null = null;
  let stepUpReject: ((reason: Error) => void) | null = null;
  let collapsed = $state(readPreference('admin-sidebar') === 'collapsed');
  let mobileOpen = $state(false);
  let accountSettings = $state<'profile' | 'password' | null>(null);
  let lastSessionCheckAt = 0;
  let lastInteractionAt = 0;
  let sessionCheckActive = false;

  function navigate(id: string) {
    active = Object.hasOwn(destinationPermission, id) ? id : 'overview';
    mobileOpen = false;
    location.hash = active === 'overview' ? '' : active;
  }

  function openSearch() {
    commandQuery = '';
    commandOpen = true;
    requestAnimationFrame(() =>
      document.querySelector<HTMLInputElement>('.command-input input')?.focus()
    );
  }

  function syncHash() {
    const requested = location.hash.slice(1);
    active = requested && Object.hasOwn(destinationPermission, requested) ? requested : 'overview';
  }

  function requestStepUp(): Promise<void> {
    if (stepUpPromise) return stepUpPromise;
    stepUpOpen = true;
    stepUpPromise = new Promise<void>((resolve, reject) => {
      stepUpResolve = resolve;
      stepUpReject = reject;
    });
    return stepUpPromise;
  }

  function clearStepUp() {
    stepUpOpen = false;
    stepUpPromise = null;
    stepUpResolve = null;
    stepUpReject = null;
  }

  function completeStepUp() {
    const resolve = stepUpResolve;
    clearStepUp();
    resolve?.();
  }

  function cancelStepUp(reason: Error) {
    const reject = stepUpReject;
    clearStepUp();
    reject?.(reason);
  }

  function clearSession() {
    if (stepUpPromise) cancelStepUp(new Error('Authentication is no longer valid'));
    user = null;
    permissions = [];
    serverVersion = '';
    sessionExpiresAt = 0;
    enrolling = false;
    recoveryEnrollment = null;
    accountSettings = null;
  }

  function applySession(value: SessionInfo) {
    user = value.user;
    permissions = value.permissions;
    serverVersion = value.serverVersion;
    sessionExpiresAt = value.expiresAt;
    lastSessionCheckAt = Date.now();
  }

  async function refreshSession(fallback?: AdminUser) {
    try {
      const value = await api<SessionInfo>('/auth/me');
      applySession(value);
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) {
        clearSession();
        return;
      }
      user = fallback ?? null;
      permissions = [];
      serverVersion = '';
      sessionExpiresAt = 0;
    }
  }

  async function keepActiveSession() {
    if (!user || sessionCheckActive) return;
    sessionCheckActive = true;
    try {
      applySession(await api<SessionInfo>('/auth/me'));
    } catch {
      // A 401 clears the session through the shared API handler. Transient
      // failures leave the current view intact and retry on later activity.
    } finally {
      sessionCheckActive = false;
    }
  }

  function noteInteraction() {
    lastInteractionAt = Date.now();
  }

  function formattedSessionExpiry() {
    return sessionExpiresAt
      ? new Date(sessionExpiresAt * 1000).toLocaleString($locale === 'zh' ? 'zh-CN' : 'en-US', {
          month: 'short',
          day: 'numeric',
          hour: '2-digit',
          minute: '2-digit'
        })
      : '';
  }

  onMount(() => {
    setStepUpHandler(requestStepUp);
    setAuthenticationFailureHandler(clearSession);
    syncHash();
    addEventListener('hashchange', syncHash);
    void refreshSession().finally(() => (checking = false));
    const onInteraction = () => noteInteraction();
    const onVisibility = () => {
      if (document.visibilityState !== 'visible') return;
      noteInteraction();
      if (Date.now() - lastSessionCheckAt >= SESSION_KEEPALIVE_AFTER_MS) {
        void keepActiveSession();
      }
    };
    addEventListener('pointerdown', onInteraction, { capture: true, passive: true });
    addEventListener('keydown', onInteraction, { capture: true });
    addEventListener('wheel', onInteraction, { capture: true, passive: true });
    addEventListener('focus', onVisibility);
    document.addEventListener('visibilitychange', onVisibility);
    const sessionTimer = window.setInterval(() => {
      const now = Date.now();
      if (
        document.visibilityState === 'visible' &&
        lastInteractionAt >= lastSessionCheckAt &&
        now - lastSessionCheckAt >= SESSION_KEEPALIVE_AFTER_MS &&
        now - lastInteractionAt <= SESSION_RECENT_ACTIVITY_MS
      ) {
        void keepActiveSession();
      }
    }, SESSION_ACTIVITY_CHECK_MS);

    return () => {
      setStepUpHandler();
      setAuthenticationFailureHandler();
      removeEventListener('hashchange', syncHash);
      removeEventListener('pointerdown', onInteraction, { capture: true });
      removeEventListener('keydown', onInteraction, { capture: true });
      removeEventListener('wheel', onInteraction, { capture: true });
      removeEventListener('focus', onVisibility);
      document.removeEventListener('visibilitychange', onVisibility);
      clearInterval(sessionTimer);
      if (stepUpPromise) cancelStepUp(new Error('The administration view was closed'));
    };
  });

  function toggleSidebar() {
    collapsed = !collapsed;
    writePreference('admin-sidebar', collapsed ? 'collapsed' : 'expanded');
  }

  async function logout() {
    try {
      await api('/auth/logout', { method: 'POST', mutation: true });
    } finally {
      clearSession();
    }
  }

  let activeTitle = $derived((copy[$locale] as Record<string, string>)[active] ?? active);
  let canManageIdentity = $derived(permissions.includes('identity.manage'));
  let destinations = $derived(
    Object.keys(destinationPermission).filter(
      (id) => !destinationPermission[id] || permissions.includes(destinationPermission[id])
    )
  );
  let matchingDestinations = $derived(
    destinations.filter((id) =>
      `${id} ${(copy[$locale] as Record<string, string>)[id]}`
        .toLowerCase()
        .includes(commandQuery.toLowerCase())
    )
  );

  $effect(() => {
    if (user && !destinations.includes(active)) navigate('overview');
  });
</script>

<svelte:window
  onkeydown={(event) => {
    if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
      event.preventDefault();
      openSearch();
    }
    if (event.key === 'Escape') commandOpen = false;
  }}
/>

<svelte:head>
  <title>Camellia Console</title>
  <meta name="description" content="Camellia Nexus licensing administration console" />
</svelte:head>

{#if checking}
  <main class="boot-screen">
    <div class="boot-mark"><span></span><span></span><span></span></div>
    <strong>Camellia Console</strong>
    <small>{messages[$locale].establishing}</small>
  </main>
{:else if !user}
  {#if enrolling}
    <Enrollment
      recovery={recoveryEnrollment}
      onComplete={(value) => {
        void refreshSession(value);
        recoveryEnrollment = null;
      }}
      onBack={() => {
        enrolling = false;
        recoveryEnrollment = null;
      }}
    />
  {:else}
    <Login
      onSuccess={(value) => void refreshSession(value)}
      onEnroll={() => {
        recoveryEnrollment = null;
        enrolling = true;
      }}
      onRecover={(value) => {
        recoveryEnrollment = value;
        enrolling = true;
      }}
    />
  {/if}
{:else}
  <div class:sidebar-collapsed={collapsed} class="app-shell">
    <Sidebar
      {active}
      {collapsed}
      {mobileOpen}
      {destinations}
      onNavigate={navigate}
      onSearch={openSearch}
      onCollapse={toggleSidebar}
      onClose={() => (mobileOpen = false)}
    />
    <div class="app-main">
      <Topbar
        {user}
        title={activeTitle}
        onMenu={() => (mobileOpen = true)}
        onSearch={openSearch}
        onLogout={logout}
        onEditProfile={() => (accountSettings = 'profile')}
        onChangePassword={() => (accountSettings = 'password')}
      />
      <main class="content">
        {#if active === 'overview'}
          <Dashboard onNavigate={navigate} />
        {:else if resources.has(active)}
          <Resources resource={active} {permissions} />
        {:else if active === 'billing'}
          <Billing {permissions} />
        {:else if active === 'team'}
          <Team {permissions} onNavigate={navigate} />
        {:else if active === 'administrators' && canManageIdentity}
          <Administrators currentUser={user} />
        {:else if active === 'system'}
          <SystemPage />
        {/if}
      </main>
      <footer class="app-footer">
        <span>{messages[$locale].controlPlane}</span>
        <span
          >{serverVersion ? `v${serverVersion}` : '—'} · <i></i>
          {sessionExpiresAt
            ? `${messages[$locale].secureSessionUntil} ${formattedSessionExpiry()}`
            : messages[$locale].secureSession}</span
        >
      </footer>
    </div>
  </div>

  {#if commandOpen}
    <div class="modal-layer command-layer">
      <button
        class="modal-scrim"
        aria-label={messages[$locale].closeSearch}
        onclick={() => (commandOpen = false)}
      ></button>
      <div
        use:focusTrap={{ onEscape: () => (commandOpen = false), initialFocus: 'input' }}
        class="command-card"
        role="dialog"
        aria-modal="true"
        aria-label={messages[$locale].navigationSearch}
      >
        <div class="command-input">
          <Search size={19} />
          <input
            bind:value={commandQuery}
            aria-label={messages[$locale].navigationSearch}
            placeholder={messages[$locale].searchPlaceholder}
          />
        </div>
        <div class="command-results">
          {#each matchingDestinations as id}
            <button
              onclick={() => {
                navigate(id);
                commandOpen = false;
              }}
            >
              <span>{(copy[$locale] as Record<string, string>)[id]}</span>
              <small>{id}</small>
            </button>
          {:else}
            <p>{messages[$locale].noMatches}</p>
          {/each}
        </div>
      </div>
    </div>
  {/if}

  {#if stepUpOpen}
    <StepUpDialog onComplete={completeStepUp} onCancel={cancelStepUp} />
  {/if}
  {#if accountSettings}
    <AccountSettingsDialog
      {user}
      mode={accountSettings}
      onCancel={() => (accountSettings = null)}
      onProfileSaved={(updated) => {
        user = updated;
        accountSettings = null;
      }}
      onUserRefreshed={(updated) => (user = updated)}
      onPasswordChanged={clearSession}
    />
  {/if}
{/if}
