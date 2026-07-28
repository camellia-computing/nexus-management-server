<script lang="ts">
  import {
    ArrowRight,
    Eye,
    EyeOff,
    KeyRound,
    Languages,
    LockKeyhole,
    ShieldCheck
  } from '@lucide/svelte';
  import BrandMark from './BrandMark.svelte';
  import { beginRecovery, login, type AdminUser, type RecoveryEnrollment } from './api';
  import { defineCopy, locale, setLocale } from './i18n';

  let {
    onSuccess,
    onEnroll,
    onRecover
  }: {
    onSuccess: (user: AdminUser) => void;
    onEnroll: () => void;
    onRecover: (value: RecoveryEnrollment) => void;
  } = $props();
  const messages = defineCopy(
    {
      privatePlane: '私有控制面',
      storyTitle: '让授权运营\n保持清晰、可信。',
      storyDetail:
        '从账户、授权和设备，到 Team 与人工付款审核，所有关键操作都在一个可审计的工作空间完成。',
      securityEnabled: '安全边界已启用',
      securityDetail: '独立监听 · TOTP · 完整审计',
      welcome: '欢迎回来',
      subtitle: '使用管理员凭据进入 Camellia Console',
      account: '管理员账户',
      password: '密码',
      recoveryCode: '一次性恢复码',
      totp: '双重验证码',
      verifying: '正在验证…',
      resetTotp: '验证并重置 TOTP',
      secureLogin: '安全登录',
      returnLogin: '返回密码与 TOTP 登录',
      useRecovery: '无法使用身份验证器？使用恢复码',
      firstDeploy: '首次部署？登记平台管理员',
      sessionNote: '会话仅在此浏览器中生效。敏感操作需要近期双重验证。',
      loginFailed: '登录失败',
      showPassword: '显示密码',
      hidePassword: '隐藏密码',
      switchLanguage: 'Switch to English'
    },
    {
      privatePlane: 'Private control plane',
      storyTitle: 'Keep licensing operations\nclear and trustworthy.',
      storyDetail:
        'Manage accounts, entitlements, devices, Team access, and manual payment reviews in one auditable workspace.',
      securityEnabled: 'Security boundary enabled',
      securityDetail: 'Dedicated listener · TOTP · Complete audit trail',
      welcome: 'Welcome back',
      subtitle: 'Use your administrator credentials to enter Camellia Console',
      account: 'Administrator account',
      password: 'Password',
      recoveryCode: 'One-time recovery code',
      totp: 'Two-factor code',
      verifying: 'Verifying…',
      resetTotp: 'Verify and reset TOTP',
      secureLogin: 'Sign in securely',
      returnLogin: 'Return to password and TOTP',
      useRecovery: 'Authenticator unavailable? Use a recovery code',
      firstDeploy: 'First deployment? Enroll a platform administrator',
      sessionNote:
        'This session is valid only in this browser. Sensitive actions require recent two-factor verification.',
      loginFailed: 'Sign-in failed',
      showPassword: 'Show password',
      hidePassword: 'Hide password',
      switchLanguage: '切换到简体中文'
    }
  );
  let username = $state('');
  let password = $state('');
  let totp = $state('');
  let recoveryCode = $state('');
  let recovering = $state(false);
  let visible = $state(false);
  let busy = $state(false);
  let error = $state('');

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    if (busy) return;
    busy = true;
    error = '';
    try {
      if (recovering) onRecover(await beginRecovery(username, password, recoveryCode));
      else onSuccess((await login(username, password, totp)).user);
    } catch (reason) {
      error = reason instanceof Error ? reason.message : messages[$locale].loginFailed;
    } finally {
      busy = false;
    }
  }
</script>

<main class="auth-page">
  <section class="auth-story">
    <div class="auth-brand">
      <BrandMark /><span><strong>Camellia</strong><small>Console</small></span>
    </div>
    <div class="story-copy">
      <span class="eyebrow"
        ><ShieldCheck size={16} /> {messages[$locale].privatePlane.toUpperCase()}</span
      >
      <h1>
        {#each messages[$locale].storyTitle.split('\n') as line}{line}<br />{/each}
      </h1>
      <p>{messages[$locale].storyDetail}</p>
    </div>
    <div class="story-metric">
      <i></i>
      <div>
        <strong>{messages[$locale].securityEnabled}</strong><span
          >{messages[$locale].securityDetail}</span
        >
      </div>
    </div>
  </section>
  <section class="auth-form-wrap">
    <form class="auth-card" onsubmit={submit} aria-busy={busy}>
      <button
        class="auth-language"
        type="button"
        onclick={() => setLocale($locale === 'zh' ? 'en' : 'zh')}
        aria-label={messages[$locale].switchLanguage}
        ><Languages size={16} />{$locale === 'zh' ? 'English' : '简体中文'}</button
      >
      <div class="auth-icon"><LockKeyhole size={23} /></div>
      <h2>{messages[$locale].welcome}</h2>
      <p>{messages[$locale].subtitle}</p>
      {#if error}<div class="form-error" role="alert">{error}</div>{/if}
      <label
        >{messages[$locale].account}<input
          autocomplete="username"
          bind:value={username}
          placeholder="operator"
          required
        /></label
      >
      <label
        >{messages[$locale].password}
        <div class="password-field">
          <input
            type={visible ? 'text' : 'password'}
            autocomplete="current-password"
            bind:value={password}
            required
          /><button
            type="button"
            onclick={() => (visible = !visible)}
            aria-label={visible ? messages[$locale].hidePassword : messages[$locale].showPassword}
            >{#if visible}<EyeOff size={18} />{:else}<Eye size={18} />{/if}</button
          >
        </div></label
      >
      {#if recovering}
        <label
          >{messages[$locale].recoveryCode}
          <div class="totp-field">
            <KeyRound size={17} /><input
              autocomplete="one-time-code"
              bind:value={recoveryCode}
              placeholder="CNXR-…"
              required
            />
          </div></label
        >
      {:else}
        <label
          >{messages[$locale].totp}
          <div class="totp-field">
            <KeyRound size={17} /><input
              inputmode="numeric"
              autocomplete="one-time-code"
              minlength="6"
              maxlength="8"
              bind:value={totp}
              placeholder="000 000"
              required
            />
          </div></label
        >
      {/if}
      <button class="primary auth-submit" disabled={busy}
        >{busy
          ? messages[$locale].verifying
          : recovering
            ? messages[$locale].resetTotp
            : messages[$locale].secureLogin}<ArrowRight size={18} /></button
      >
      <button
        class="enrollment-link"
        type="button"
        onclick={() => {
          recovering = !recovering;
          error = '';
        }}>{recovering ? messages[$locale].returnLogin : messages[$locale].useRecovery}</button
      >
      <button class="enrollment-link" type="button" onclick={onEnroll}
        >{messages[$locale].firstDeploy}</button
      >
      <small class="auth-note">{messages[$locale].sessionNote}</small>
    </form>
  </section>
</main>
