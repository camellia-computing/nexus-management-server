<script lang="ts">
  import { KeyRound, UserRound, X } from '@lucide/svelte';
  import {
    api,
    ApiError,
    isVersionConflict,
    MutationAttempt,
    type AdminUser,
    type SessionInfo
  } from './api';
  import { focusTrap } from './actions/focusTrap';
  import { defineCopy, locale } from './i18n';

  let {
    user,
    mode,
    onCancel,
    onProfileSaved,
    onUserRefreshed,
    onPasswordChanged
  }: {
    user: AdminUser;
    mode: 'profile' | 'password';
    onCancel: () => void;
    onProfileSaved: (user: AdminUser) => void;
    onUserRefreshed: (user: AdminUser) => void;
    onPasswordChanged: () => void;
  } = $props();

  const messages = defineCopy(
    {
      profileTitle: '个人资料',
      passwordTitle: '修改密码',
      eyebrow: '管理员 / 账户',
      username: '登录用户名',
      immutableUsername: '用户名是稳定的登录与审计标识，创建后不可修改。',
      displayName: '显示名称',
      newPassword: '新密码',
      confirmPassword: '确认新密码',
      passwordHint: '使用 14–128 个字符，不得包含用户名或常见密码。',
      passwordInvalid: '新密码不符合要求，或与当前密码相同。',
      reason: '操作原因',
      profileReason: '说明显示名称调整原因',
      passwordReason: '说明密码轮换原因',
      mismatch: '两次输入的新密码不一致',
      failed: '无法保存账户设置',
      stale: '账户资料已在其他会话中更新。已加载最新状态，请复核后重试。',
      cancel: '取消',
      saving: '正在保存…',
      save: '保存资料',
      change: '修改密码',
      close: '关闭账户设置'
    },
    {
      profileTitle: 'Profile',
      passwordTitle: 'Change password',
      eyebrow: 'Admin / Account',
      username: 'Sign-in username',
      immutableUsername:
        'The username is a stable sign-in and audit identifier and cannot be changed after creation.',
      displayName: 'Display name',
      newPassword: 'New password',
      confirmPassword: 'Confirm new password',
      passwordHint: 'Use 14–128 characters without the username or common passwords.',
      passwordInvalid: 'The new password is invalid or matches the current password.',
      reason: 'Operation reason',
      profileReason: 'Explain the display-name change',
      passwordReason: 'Explain the credential rotation',
      mismatch: 'The new passwords do not match',
      failed: 'The account settings could not be saved',
      stale:
        'Your account changed in another session. The latest state is loaded; review it before retrying.',
      cancel: 'Cancel',
      saving: 'Saving…',
      save: 'Save profile',
      change: 'Change password',
      close: 'Close account settings'
    }
  );

  const attempt = new MutationAttempt();
  let displayName = $state('');
  let password = $state('');
  let confirmation = $state('');
  let reason = $state('');
  let busy = $state(false);
  let error = $state('');
  let passwordError = $state('');
  let passwordMismatch = $derived(Boolean(confirmation) && password !== confirmation);
  let valid = $derived(
    Boolean(reason.trim()) &&
      (mode === 'profile'
        ? Boolean(displayName.trim()) && displayName.trim() !== user.displayName
        : password.length >= 14 && confirmation.length >= 14 && password === confirmation)
  );
  let initialized = false;

  $effect(() => {
    if (!initialized) {
      displayName = user.displayName;
      initialized = true;
    }
  });

  async function reloadAfterVersionConflict(cause: unknown) {
    if (!isVersionConflict(cause)) return false;
    attempt.succeeded();
    try {
      const session = await api<SessionInfo>('/auth/me');
      onUserRefreshed(session.user);
      displayName = session.user.displayName;
      reason = '';
      error = messages[$locale].stale;
    } catch (reloadCause) {
      error = reloadCause instanceof Error ? reloadCause.message : messages[$locale].failed;
    }
    return true;
  }

  async function submit() {
    if (busy || !valid) return;
    if (mode === 'password' && password !== confirmation) {
      error = messages[$locale].mismatch;
      return;
    }
    busy = true;
    error = '';
    passwordError = '';
    if (mode === 'profile') {
      const body = JSON.stringify({ displayName: displayName.trim(), reason: reason.trim() });
      const path = `/admin-users/${user.id}`;
      try {
        const updated = await api<AdminUser>(path, {
          method: 'PATCH',
          mutation: true,
          operationId: attempt.operationId(`${path}:${user.rowVersion}:${body}`),
          headers: { 'if-match': String(user.rowVersion) },
          body
        });
        attempt.succeeded();
        onProfileSaved(updated);
      } catch (cause) {
        attempt.failed(cause);
        if (!(await reloadAfterVersionConflict(cause)))
          error = cause instanceof Error ? cause.message : messages[$locale].failed;
      } finally {
        busy = false;
      }
      return;
    }
    const body = JSON.stringify({ newPassword: password, reason: reason.trim() });
    try {
      await api('/auth/password', {
        method: 'POST',
        mutation: true,
        operationId: attempt.operationId(`/auth/password:${user.rowVersion}:${reason.trim()}`),
        headers: { 'if-match': String(user.rowVersion) },
        body
      });
      attempt.succeeded();
      password = '';
      confirmation = '';
      onPasswordChanged();
    } catch (cause) {
      attempt.failed(cause);
      if (await reloadAfterVersionConflict(cause)) {
        passwordError = '';
      } else if (cause instanceof ApiError && cause.field === 'newPassword') {
        passwordError = messages[$locale].passwordInvalid;
      } else {
        error = cause instanceof Error ? cause.message : messages[$locale].failed;
      }
    } finally {
      busy = false;
    }
  }
</script>

<div class="modal-layer account-settings-layer">
  <button
    class="modal-scrim"
    aria-label={messages[$locale].close}
    onclick={onCancel}
    disabled={busy}
  ></button>
  <div
    use:focusTrap={{ onEscape: busy ? undefined : onCancel, initialFocus: 'input' }}
    class="modal-card account-settings-card"
    role="dialog"
    aria-modal="true"
    aria-labelledby="account-settings-title"
    aria-busy={busy}
  >
    <header>
      <div>
        <span class="eyebrow"
          >{#if mode === 'profile'}<UserRound size={15} />{:else}<KeyRound size={15} />{/if}
          {messages[$locale].eyebrow}</span
        >
        <h2 id="account-settings-title">
          {mode === 'profile' ? messages[$locale].profileTitle : messages[$locale].passwordTitle}
        </h2>
      </div>
      <button
        class="icon-button modal-close"
        aria-label={messages[$locale].close}
        onclick={onCancel}
        disabled={busy}><X size={18} /></button
      >
    </header>
    {#if error}<div class="form-error" role="alert">{error}</div>{/if}
    <div class="form-grid">
      {#if mode === 'profile'}
        <label
          >{messages[$locale].username}<input value={user.username} disabled /><small
            >{messages[$locale].immutableUsername}</small
          ></label
        >
        <label
          >{messages[$locale].displayName}<input
            bind:value={displayName}
            maxlength="128"
            autocomplete="name"
            required
          /></label
        >
      {:else}
        <label
          >{messages[$locale].newPassword}<input
            type="password"
            bind:value={password}
            oninput={() => {
              attempt.succeeded();
              passwordError = '';
            }}
            minlength="14"
            maxlength="128"
            autocomplete="new-password"
            aria-invalid={Boolean(passwordError)}
            aria-describedby={passwordError
              ? 'new-password-hint new-password-error'
              : 'new-password-hint'}
          /><small id="new-password-hint">{messages[$locale].passwordHint}</small
          >{#if passwordError}<small id="new-password-error" class="field-error" role="alert"
              >{passwordError}</small
            >{/if}</label
        >
        <label
          >{messages[$locale].confirmPassword}<input
            type="password"
            bind:value={confirmation}
            oninput={() => {
              attempt.succeeded();
              passwordError = '';
            }}
            minlength="14"
            maxlength="128"
            autocomplete="new-password"
            aria-invalid={passwordMismatch}
            aria-describedby={passwordMismatch ? 'confirm-password-error' : undefined}
          />{#if passwordMismatch}<small
              class="field-error"
              role="alert"
              id="confirm-password-error">{messages[$locale].mismatch}</small
            >{/if}</label
        >
      {/if}
      <label class="wide"
        >{messages[$locale].reason}<textarea
          bind:value={reason}
          maxlength="512"
          placeholder={mode === 'profile'
            ? messages[$locale].profileReason
            : messages[$locale].passwordReason}
          required></textarea></label
      >
    </div>
    <footer>
      <button class="secondary" onclick={onCancel} disabled={busy}
        >{messages[$locale].cancel}</button
      ><button class="primary" onclick={submit} disabled={busy || !valid}
        >{busy
          ? messages[$locale].saving
          : mode === 'profile'
            ? messages[$locale].save
            : messages[$locale].change}</button
      >
    </footer>
  </div>
</div>
