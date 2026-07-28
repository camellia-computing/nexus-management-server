<script lang="ts">
  import {
    Activity,
    BookOpenCheck,
    Building2,
    ChevronLeft,
    ChevronRight,
    CreditCard,
    Gauge,
    KeyRound,
    Laptop,
    ListChecks,
    PanelLeftClose,
    Search,
    ShieldCheck,
    UserCog,
    UsersRound,
    X
  } from '@lucide/svelte';
  import BrandMark from './BrandMark.svelte';
  import { copy, defineCopy, locale } from './i18n';

  let {
    active,
    collapsed,
    mobileOpen,
    destinations,
    onNavigate,
    onSearch,
    onCollapse,
    onClose
  }: {
    active: string;
    collapsed: boolean;
    mobileOpen: boolean;
    destinations: string[];
    onNavigate: (id: string) => void;
    onSearch: () => void;
    onCollapse: () => void;
    onClose: () => void;
  } = $props();

  const items = [
    ['overview', Gauge],
    ['accounts', Building2],
    ['licenses', ShieldCheck],
    ['codes', KeyRound],
    ['devices', Laptop],
    ['team', UsersRound],
    ['billing', CreditCard],
    ['jobs', ListChecks],
    ['audit', BookOpenCheck],
    ['administrators', UserCog],
    ['system', Activity]
  ] as const;
  const messages = defineCopy(
    {
      closeNavigation: '关闭导航',
      searchNavigation: '搜索导航',
      primaryNavigation: '主导航',
      collapseSidebar: '收起侧栏',
      expandSidebar: '展开侧栏'
    },
    {
      closeNavigation: 'Close navigation',
      searchNavigation: 'Search navigation',
      primaryNavigation: 'Primary navigation',
      collapseSidebar: 'Collapse sidebar',
      expandSidebar: 'Expand sidebar'
    }
  );
</script>

{#if mobileOpen}<button
    class="scrim"
    aria-label={messages[$locale].closeNavigation}
    onclick={onClose}
  ></button>{/if}
<aside class:collapsed class:mobile-open={mobileOpen} class="sidebar">
  <div class="sidebar-head">
    <button class="brand" onclick={() => onNavigate('overview')} aria-label="Camellia Console">
      <BrandMark compact={collapsed} />
      {#if !collapsed}
        <span><strong>Camellia</strong><small>Console</small></span>
      {/if}
    </button>
    <button
      class="icon-button mobile-only"
      onclick={onClose}
      aria-label={messages[$locale].closeNavigation}><X size={19} /></button
    >
  </div>

  <div class="nav-search">
    <button onclick={onSearch} aria-label={messages[$locale].searchNavigation}>
      <Search size={18} /><span>{copy[$locale].search}</span><kbd>⌘/Ctrl K</kbd>
    </button>
  </div>

  <nav aria-label={messages[$locale].primaryNavigation}>
    {#each items as [id, Icon]}
      {#if destinations.includes(id)}
        <button
          class:active={active === id}
          title={collapsed ? copy[$locale][id] : undefined}
          onclick={() => onNavigate(id)}
        >
          <Icon size={19} strokeWidth={1.9} />
          <span>{copy[$locale][id]}</span>
        </button>
      {/if}
    {/each}
  </nav>

  <div class="sidebar-foot">
    {#if !collapsed}
      <div class="security-chip"><ShieldCheck size={15} /><span>{copy[$locale].secure}</span></div>
    {/if}
    <button
      class="collapse-button"
      onclick={onCollapse}
      aria-label={collapsed ? messages[$locale].expandSidebar : messages[$locale].collapseSidebar}
    >
      {#if collapsed}<ChevronRight size={18} />{:else}<PanelLeftClose size={18} /><span
          >{messages[$locale].collapseSidebar}</span
        ><ChevronLeft size={15} />{/if}
    </button>
  </div>
</aside>
