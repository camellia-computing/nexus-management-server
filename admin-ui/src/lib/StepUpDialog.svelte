<script lang="ts">
  import { KeyRound, ShieldCheck } from '@lucide/svelte';
  import { stepUp } from './api';
  import { focusTrap } from './actions/focusTrap';
  import { defineCopy, locale } from './i18n';

  let { onComplete, onCancel }: { onComplete: () => void; onCancel: (reason: Error) => void } =
    $props();
  const messages = defineCopy(
    {
      securityCheck: '安全确认',
      title: '重新确认管理员身份',
      detail: '此操作会改变安全或商业状态。请输入密码与当前 TOTP 验证码后，原操作将自动重试一次。',
      password: '管理员密码',
      totp: '当前 TOTP 验证码',
      cancel: '取消',
      verifying: '正在验证…',
      continue: '验证并继续',
      failed: '重新验证失败'
    },
    {
      securityCheck: 'Security check',
      title: 'Confirm administrator identity',
      detail:
        'This action changes security or commercial state. Enter your password and current TOTP code; the original action will then retry once.',
      password: 'Administrator password',
      totp: 'Current TOTP code',
      cancel: 'Cancel',
      verifying: 'Verifying…',
      continue: 'Verify and continue',
      failed: 'Re-authentication failed'
    }
  );
  let password = $state('');
  let totp = $state('');
  let busy = $state(false);
  let error = $state('');

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    if (busy) return;
    busy = true;
    error = '';
    try {
      await stepUp(password, totp);
      password = '';
      totp = '';
      onComplete();
    } catch (cause) {
      error = cause instanceof Error ? cause.message : messages[$locale].failed;
    } finally {
      busy = false;
    }
  }

  function cancel() {
    if (!busy) onCancel(new Error('Administrator step-up authentication was canceled'));
  }
</script>

<div class="modal-layer step-up-layer" role="presentation">
  <button class="modal-scrim" aria-label={messages[$locale].cancel} onclick={cancel} disabled={busy}
  ></button>
  <div
    use:focusTrap={{ onEscape: busy ? undefined : cancel, initialFocus: 'input' }}
    class="modal-card step-up-card"
    role="dialog"
    aria-modal="true"
    aria-labelledby="step-up-title"
    aria-describedby="step-up-description"
  >
    <form onsubmit={submit} aria-busy={busy}>
      <header>
        <div>
          <span class="eyebrow"
            ><ShieldCheck size={14} /> {messages[$locale].securityCheck.toUpperCase()}</span
          >
          <h2 id="step-up-title">{messages[$locale].title}</h2>
        </div>
      </header>
      <p id="step-up-description">{messages[$locale].detail}</p>
      {#if error}<div class="form-error" role="alert">{error}</div>{/if}
      <label
        >{messages[$locale].password}<input
          type="password"
          bind:value={password}
          autocomplete="current-password"
          required
        /></label
      >
      <label
        >{messages[$locale].totp}
        <div class="totp-field">
          <KeyRound size={17} /><input
            bind:value={totp}
            inputmode="numeric"
            autocomplete="one-time-code"
            minlength="6"
            maxlength="6"
            required
          />
        </div></label
      >
      <footer>
        <button type="button" class="secondary" onclick={cancel} disabled={busy}
          >{messages[$locale].cancel}</button
        ><button class="primary" disabled={busy || !password || totp.length !== 6}
          >{busy ? messages[$locale].verifying : messages[$locale].continue}</button
        >
      </footer>
    </form>
  </div>
</div>
