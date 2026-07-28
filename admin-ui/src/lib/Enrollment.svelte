<script lang="ts">
  import {
    ArrowLeft,
    ArrowRight,
    CheckCircle2,
    Copy,
    Download,
    KeyRound,
    Languages,
    ShieldCheck
  } from '@lucide/svelte';
  import { api, type AdminUser, type EnrollmentChallenge, type RecoveryEnrollment } from './api';
  import BrandMark from './BrandMark.svelte';
  import { defineCopy, locale, setLocale } from './i18n';

  interface EnrollmentResult {
    user: AdminUser;
    expiresAt: number;
    recoveryCodes: string[];
  }

  let {
    onComplete,
    onBack,
    recovery = null
  }: {
    onComplete: (user: AdminUser) => void;
    onBack: () => void;
    recovery?: RecoveryEnrollment | null;
  } = $props();
  const messages = defineCopy(
    {
      back: '返回登录',
      secureEnrollment: '安全登记',
      title: '登记平台管理员',
      intro: '登记令牌仅在引导后十分钟内有效。完成后必须使用密码与 TOTP 登录。',
      tokenInvalid: '登记令牌无效',
      mismatch: '两次输入的密码不一致',
      failed: '登记失败',
      created: '管理员已创建',
      codesOnce: '恢复码只显示这一次',
      codesDetail: '将恢复码存放在密码管理器或离线安全位置。每个恢复码只能使用一次。',
      copyAll: '复制全部',
      download: '下载文本',
      acknowledged: '我已经将恢复码保存到安全位置',
      enter: '进入管理控制台',
      bootstrapToken: '引导令牌',
      bootstrapPlaceholder: '粘贴 operator bootstrap 输出的登记令牌',
      validating: '正在验证…',
      validateToken: '验证令牌',
      authenticatorDetail: '在身份验证器中添加上述密钥，然后输入当前验证码。密钥不会再次显示。',
      password: '设置密码',
      passwordHint: '使用 14–128 个字符，且不要包含用户名或常见密码。',
      confirmPassword: '确认密码',
      totp: '当前 TOTP 验证码',
      creating: '正在创建…',
      finish: '完成安全登记',
      copySecret: '复制 TOTP 密钥',
      recoveryCodesLabel: '管理员恢复码',
      totpSecret: 'TOTP 密钥',
      recoveryFileTitle: 'Camellia Nexus 管理员恢复码',
      copied: '已复制',
      copyFailed: '无法复制，请手动选择内容',
      switchLanguage: 'Switch to English'
    },
    {
      back: 'Back to sign in',
      secureEnrollment: 'Secure enrollment',
      title: 'Enroll a platform administrator',
      intro:
        'The enrollment token is valid for ten minutes after bootstrap. Password and TOTP are required afterward.',
      tokenInvalid: 'The enrollment token is invalid',
      mismatch: 'The passwords do not match',
      failed: 'Enrollment failed',
      created: 'Administrator created',
      codesOnce: 'Recovery codes are shown only once',
      codesDetail:
        'Store the recovery codes in a password manager or another secure offline location. Each code can be used only once.',
      copyAll: 'Copy all',
      download: 'Download text',
      acknowledged: 'I have stored the recovery codes securely',
      enter: 'Enter the admin console',
      bootstrapToken: 'Bootstrap token',
      bootstrapPlaceholder: 'Paste the enrollment token from operator bootstrap',
      validating: 'Validating…',
      validateToken: 'Validate token',
      authenticatorDetail:
        'Add the secret to an authenticator and enter the current code. The secret will not be shown again.',
      password: 'Set password',
      passwordHint: 'Use 14–128 characters and do not include the username or common passwords.',
      confirmPassword: 'Confirm password',
      totp: 'Current TOTP code',
      creating: 'Creating…',
      finish: 'Complete secure enrollment',
      copySecret: 'Copy TOTP secret',
      recoveryCodesLabel: 'Administrator recovery codes',
      totpSecret: 'TOTP secret',
      recoveryFileTitle: 'Camellia Nexus administrator recovery codes',
      copied: 'Copied',
      copyFailed: 'Copy failed; select the value manually',
      switchLanguage: '切换到简体中文'
    }
  );
  let token = $state('');
  let password = $state('');
  let confirm = $state('');
  let totp = $state('');
  let busy = $state(false);
  let error = $state('');
  let status = $state('');
  let challenge = $state<EnrollmentChallenge | null>(null);
  let result = $state<EnrollmentResult | null>(null);
  let recoveryAcknowledged = $state(false);
  let recoveryInitialized = false;

  $effect(() => {
    if (!recoveryInitialized && recovery) {
      token = recovery.token;
      challenge = recovery.challenge;
      recoveryInitialized = true;
    }
  });

  async function begin() {
    if (busy) return;
    busy = true;
    error = '';
    try {
      challenge = await api<EnrollmentChallenge>('/auth/enrollment', {
        method: 'POST',
        body: JSON.stringify({ token })
      });
    } catch (cause) {
      error = cause instanceof Error ? cause.message : messages[$locale].tokenInvalid;
    } finally {
      busy = false;
    }
  }

  async function complete() {
    if (busy) return;
    if (password !== confirm) {
      error = messages[$locale].mismatch;
      return;
    }
    busy = true;
    error = '';
    try {
      result = await api<EnrollmentResult>('/auth/enrollment/complete', {
        method: 'POST',
        body: JSON.stringify({ token, password, totp })
      });
      password = '';
      confirm = '';
      totp = '';
    } catch (cause) {
      error = cause instanceof Error ? cause.message : messages[$locale].failed;
    } finally {
      busy = false;
    }
  }

  async function copyText(value: string) {
    try {
      await navigator.clipboard.writeText(value);
      status = messages[$locale].copied;
    } catch {
      status = messages[$locale].copyFailed;
    }
  }

  function downloadRecoveryCodes() {
    if (!result) return;
    const blob = new Blob(
      [`${messages[$locale].recoveryFileTitle}\n\n${result.recoveryCodes.join('\n')}\n`],
      { type: 'text/plain;charset=utf-8' }
    );
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = 'camellia-nexus-admin-recovery-codes.txt';
    anchor.click();
    URL.revokeObjectURL(url);
  }
</script>

<main class="enrollment-page">
  <header>
    <button onclick={onBack}><ArrowLeft size={18} />{messages[$locale].back}</button>
    <div>
      <BrandMark compact /><strong>Camellia Console</strong><button
        class="auth-language"
        onclick={() => setLocale($locale === 'zh' ? 'en' : 'zh')}
        aria-label={messages[$locale].switchLanguage}
        ><Languages size={16} />{$locale === 'zh' ? 'English' : '简体中文'}</button
      >
    </div>
  </header>
  <section class="enrollment-card" aria-busy={busy}>
    <span class="eyebrow"
      ><ShieldCheck size={15} /> {messages[$locale].secureEnrollment.toUpperCase()}</span
    >
    <h1>{messages[$locale].title}</h1>
    <p>{messages[$locale].intro}</p>
    {#if error}<div class="form-error" role="alert">{error}</div>{/if}
    {#if status}<p class="sr-only" role="status">{status}</p>{/if}
    {#if result}
      <div class="enrollment-step recovery-step">
        <div class="step-ok">
          <CheckCircle2 size={18} /><span
            ><strong>{messages[$locale].created}</strong><small>{messages[$locale].codesOnce}</small
            ></span
          >
        </div>
        <p>{messages[$locale].codesDetail}</p>
        <div class="recovery-code-list" aria-label={messages[$locale].recoveryCodesLabel}>
          {#each result.recoveryCodes as code}<code>{code}</code>{/each}
        </div>
        <div class="recovery-actions">
          <button type="button" onclick={() => copyText(result!.recoveryCodes.join('\n'))}
            ><Copy size={16} />{messages[$locale].copyAll}</button
          ><button type="button" onclick={downloadRecoveryCodes}
            ><Download size={16} />{messages[$locale].download}</button
          >
        </div>
        <label class="recovery-confirm"
          ><input type="checkbox" bind:checked={recoveryAcknowledged} /><span
            >{messages[$locale].acknowledged}</span
          ></label
        >
        <button
          class="primary enrollment-submit"
          onclick={() => onComplete(result!.user)}
          disabled={!recoveryAcknowledged}>{messages[$locale].enter}<ArrowRight size={18} /></button
        >
      </div>
    {:else if !challenge}
      <label
        >{messages[$locale].bootstrapToken}<textarea
          bind:value={token}
          placeholder={messages[$locale].bootstrapPlaceholder}
          autocomplete="off"></textarea></label
      ><button class="primary enrollment-submit" onclick={begin} disabled={busy || !token.trim()}
        >{busy ? messages[$locale].validating : messages[$locale].validateToken}<ArrowRight
          size={18}
        /></button
      >
    {:else}
      <div class="enrollment-step">
        <div class="step-ok">
          <CheckCircle2 size={18} /><span
            ><strong>{challenge.displayName}</strong><small>{challenge.username}</small></span
          >
        </div>
        <div class="secret-box">
          <small>{messages[$locale].totpSecret}</small><code>{challenge.totpSecret}</code><button
            onclick={() => copyText(challenge!.totpSecret)}
            aria-label={messages[$locale].copySecret}><Copy size={16} /></button
          >
        </div>
        <p>{messages[$locale].authenticatorDetail}</p>
      </div>
      <div class="enrollment-fields">
        <label
          >{messages[$locale].password}<input
            type="password"
            bind:value={password}
            autocomplete="new-password"
            minlength="14"
            maxlength="128"
            aria-describedby="password-requirements"
          /><small id="password-requirements">{messages[$locale].passwordHint}</small></label
        ><label
          >{messages[$locale].confirmPassword}<input
            type="password"
            bind:value={confirm}
            autocomplete="new-password"
            minlength="14"
            maxlength="128"
          /></label
        ><label
          >{messages[$locale].totp}
          <div class="totp-field">
            <KeyRound size={17} /><input
              bind:value={totp}
              inputmode="numeric"
              autocomplete="one-time-code"
              minlength="6"
              maxlength="6"
            />
          </div></label
        >
      </div>
      <button
        class="primary enrollment-submit"
        onclick={complete}
        disabled={busy || password.length < 14 || password !== confirm || totp.length !== 6}
        >{busy ? messages[$locale].creating : messages[$locale].finish}<ArrowRight
          size={18}
        /></button
      >
    {/if}
  </section>
</main>
