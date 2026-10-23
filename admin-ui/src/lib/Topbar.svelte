<script lang="ts">
  import {
    Check,
    KeyRound,
    Languages,
    Menu,
    Moon,
    Search,
    Sun,
    Monitor,
    Type,
    UserRound
  } from '@lucide/svelte';
  import { adminRoleLabel } from './domainLabels';
  import { onMount } from 'svelte';
  import { copy, defineCopy, locale, setLocale } from './i18n';
  import type { AdminUser } from './api';
  import { readPreference, writePreference } from './preferences';

  let {
    user,
    title,
    onMenu,
    onSearch,
    onLogout,
    onEditProfile,
    onChangePassword
  }: {
    user: AdminUser;
    title: string;
    onMenu: () => void;
    onSearch: () => void;
    onLogout: () => void;
    onEditProfile: () => void;
    onChangePassword: () => void;
  } = $props();
  const messages = defineCopy(
    {
      openNavigation: '打开导航',
      console: '控制台',
      secureSession: '安全会话有效',
      appearanceLabel: '外观与语言',
      userMenu: '管理员菜单',
      signedInAs: '登录账户',
      editProfile: '个人资料',
      changePassword: '修改密码'
    },
    {
      openNavigation: 'Open navigation',
      console: 'Console',
      secureSession: 'Secure session',
      appearanceLabel: 'Appearance and language',
      userMenu: 'Administrator menu',
      signedInAs: 'Signed in as',
      editProfile: 'Profile',
      changePassword: 'Change password'
    }
  );
  type Theme = 'light' | 'dark' | 'system';
  type FontSize = 'standard' | 'large' | 'extra-large';
  const storedTheme = readPreference('admin-theme');
  const storedFontSize = readPreference('admin-font-size');
  let menu = $state<'theme' | 'user' | null>(null);
  let theme = $state<Theme>(
    storedTheme === 'light' || storedTheme === 'dark' ? storedTheme : 'system'
  );
  let fontSize = $state<FontSize>(
    storedFontSize === 'large' || storedFontSize === 'extra-large' ? storedFontSize : 'standard'
  );
  let themeWrap = $state<HTMLDivElement | null>(null);
  let userWrap = $state<HTMLDivElement | null>(null);
  let themeButton = $state<HTMLButtonElement | null>(null);
  let userButton = $state<HTMLButtonElement | null>(null);

  function closeMenu(restoreFocus = false) {
    const trigger = menu === 'theme' ? themeButton : menu === 'user' ? userButton : null;
    menu = null;
    if (restoreFocus) requestAnimationFrame(() => trigger?.focus());
  }

  function toggleMenu(next: 'theme' | 'user') {
    if (menu === next) {
      closeMenu(true);
      return;
    }
    menu = next;
    requestAnimationFrame(() => {
      const wrap = next === 'theme' ? themeWrap : userWrap;
      wrap?.querySelector<HTMLButtonElement>('[role^="menuitem"]')?.focus();
    });
  }

  function handleMenuKeydown(event: KeyboardEvent) {
    if (!menu || !['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key)) return;
    const wrap = menu === 'theme' ? themeWrap : userWrap;
    const items = [...(wrap?.querySelectorAll<HTMLButtonElement>('[role^="menuitem"]') ?? [])];
    if (!items.length) return;
    event.preventDefault();
    const current = items.indexOf(document.activeElement as HTMLButtonElement);
    const next =
      event.key === 'Home'
        ? 0
        : event.key === 'End'
          ? items.length - 1
          : event.key === 'ArrowDown'
            ? (current + 1 + items.length) % items.length
            : (current - 1 + items.length) % items.length;
    items[next]?.focus();
  }

  function setTheme(value: Theme) {
    theme = value;
    writePreference('admin-theme', value);
    document.documentElement.dataset.theme = value;
    closeMenu(true);
  }

  function setFontSize(value: FontSize) {
    fontSize = value;
    writePreference('admin-font-size', value);
    document.documentElement.dataset.fontSize = value;
    closeMenu(true);
  }

  function openAccountSettings(action: () => void) {
    menu = null;
    userButton?.focus({ preventScroll: true });
    action();
  }

  function closeAfterFocusLeaves(event: FocusEvent, expected: 'theme' | 'user') {
    if (menu !== expected) return;
    const wrap = expected === 'theme' ? themeWrap : userWrap;
    if (!(event.relatedTarget instanceof Node) || !wrap?.contains(event.relatedTarget)) closeMenu();
  }

  onMount(() => {
    const closeOnOutsidePointer = (event: PointerEvent) => {
      if (!menu) return;
      const target = event.target;
      if (!(target instanceof Node)) return;
      const activeWrap = menu === 'theme' ? themeWrap : userWrap;
      if (!activeWrap?.contains(target)) closeMenu();
    };
    document.addEventListener('pointerdown', closeOnOutsidePointer, true);
    return () => document.removeEventListener('pointerdown', closeOnOutsidePointer, true);
  });
</script>

<svelte:window
  onkeydown={(event) => {
    if (event.key === 'Escape' && menu) {
      event.preventDefault();
      closeMenu(true);
    }
  }}
/>

<header class="topbar">
  <div class="topbar-title">
    <button
      class="icon-button nav-trigger"
      onclick={onMenu}
      aria-label={messages[$locale].openNavigation}><Menu size={21} /></button
    >
    <div><span>{messages[$locale].console}</span><strong>{title}</strong></div>
  </div>
  <div class="topbar-actions">
    <button class="command-search" onclick={onSearch}
      ><Search size={18} strokeWidth={2} /><span>{copy[$locale].search}</span><kbd>⌘/Ctrl K</kbd
      ></button
    >
    <div class="health-pill"><i></i><span>{messages[$locale].secureSession}</span></div>
    <div
      class="popover-wrap"
      bind:this={themeWrap}
      onfocusout={(event) => closeAfterFocusLeaves(event, 'theme')}
    >
      <button
        bind:this={themeButton}
        class="icon-button"
        onclick={() => toggleMenu('theme')}
        aria-label={messages[$locale].appearanceLabel}
        aria-haspopup="menu"
        aria-expanded={menu === 'theme'}
      >
        {#if theme === 'dark'}<Moon size={19} />{:else if theme === 'light'}<Sun
            size={19}
          />{:else}<Monitor size={19} />{/if}
      </button>
      {#if menu === 'theme'}
        <div class="popover compact-menu" role="menu" tabindex="-1" onkeydown={handleMenuKeydown}>
          <small>{copy[$locale].appearance}</small>
          <button
            role="menuitemradio"
            aria-checked={theme === 'system'}
            onclick={() => setTheme('system')}
            ><Monitor size={16} /><span>{copy[$locale].systemTheme}</span><i class="menu-check"
              >{#if theme === 'system'}<Check size={15} />{/if}</i
            ></button
          >
          <button
            role="menuitemradio"
            aria-checked={theme === 'light'}
            onclick={() => setTheme('light')}
            ><Sun size={16} /><span>{copy[$locale].light}</span><i class="menu-check"
              >{#if theme === 'light'}<Check size={15} />{/if}</i
            ></button
          >
          <button
            role="menuitemradio"
            aria-checked={theme === 'dark'}
            onclick={() => setTheme('dark')}
            ><Moon size={16} /><span>{copy[$locale].dark}</span><i class="menu-check"
              >{#if theme === 'dark'}<Check size={15} />{/if}</i
            ></button
          >
          <hr />
          <small>{copy[$locale].fontSize}</small>
          <button
            role="menuitemradio"
            aria-checked={fontSize === 'standard'}
            onclick={() => setFontSize('standard')}
            ><Type size={16} /><span>{copy[$locale].standardFont}</span><i class="menu-check"
              >{#if fontSize === 'standard'}<Check size={15} />{/if}</i
            ></button
          >
          <button
            role="menuitemradio"
            aria-checked={fontSize === 'large'}
            onclick={() => setFontSize('large')}
            ><Type size={18} /><span>{copy[$locale].largeFont}</span><i class="menu-check"
              >{#if fontSize === 'large'}<Check size={15} />{/if}</i
            ></button
          >
          <button
            role="menuitemradio"
            aria-checked={fontSize === 'extra-large'}
            onclick={() => setFontSize('extra-large')}
            ><Type size={20} /><span>{copy[$locale].extraLargeFont}</span><i class="menu-check"
              >{#if fontSize === 'extra-large'}<Check size={15} />{/if}</i
            ></button
          >
          <hr />
          <button
            role="menuitem"
            onclick={() => {
              setLocale($locale === 'zh' ? 'en' : 'zh');
              closeMenu(true);
            }}
            ><Languages size={16} /><span>{$locale === 'zh' ? 'English' : '简体中文'}</span><i
              class="menu-check"
            ></i></button
          >
        </div>
      {/if}
    </div>
    <div
      class="popover-wrap"
      bind:this={userWrap}
      onfocusout={(event) => closeAfterFocusLeaves(event, 'user')}
    >
      <button
        bind:this={userButton}
        class="user-button"
        onclick={() => toggleMenu('user')}
        title={messages[$locale].userMenu}
        aria-haspopup="menu"
        aria-expanded={menu === 'user'}
      >
        <span aria-hidden="true">{user.displayName.slice(0, 1).toUpperCase()}</span>
        <div>
          <strong>{user.displayName}</strong><small
            >{adminRoleLabel(user.roles[0] ?? '', $locale)}</small
          >
        </div>
      </button>
      {#if menu === 'user'}
        <div class="popover user-menu" role="menu" tabindex="-1" onkeydown={handleMenuKeydown}>
          <div class="user-identity">
            <UserRound size={18} /><span
              ><strong>{user.username}</strong><small
                >{messages[$locale].signedInAs} · {user.id}</small
              ></span
            >
          </div>
          <button role="menuitem" onclick={() => openAccountSettings(onEditProfile)}
            ><UserRound size={16} /><span>{messages[$locale].editProfile}</span></button
          >
          <button role="menuitem" onclick={() => openAccountSettings(onChangePassword)}
            ><KeyRound size={16} /><span>{messages[$locale].changePassword}</span></button
          >
          <hr />
          <button
            role="menuitem"
            onclick={() => {
              closeMenu();
              onLogout();
            }}><span>{copy[$locale].signOut}</span></button
          >
        </div>
      {/if}
    </div>
  </div>
</header>
