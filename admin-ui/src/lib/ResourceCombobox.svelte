<script lang="ts">
  import { Search } from '@lucide/svelte';
  import { onDestroy, untrack } from 'svelte';
  import { api } from './api';
  import type { AdminAccount, AdminLicense, AdminPage } from './admin-contracts';
  import { planLabel, statusLabel } from './domainLabels';
  import { defineCopy, locale } from './i18n';

  let {
    kind,
    value = $bindable(),
    accountId = '',
    disabled = false,
    placeholder = ''
  }: {
    kind: 'account' | 'license';
    value: string;
    accountId?: string;
    disabled?: boolean;
    placeholder?: string;
  } = $props();

  const messages = defineCopy(
    {
      loading: '正在搜索…',
      empty: '没有匹配项；仍可使用手工输入值',
      failed: '无法加载建议；仍可手工输入',
      suggestions: '资源建议'
    },
    {
      loading: 'Searching…',
      empty: 'No matches; the manually entered value remains available',
      failed: 'Suggestions unavailable; enter the value manually',
      suggestions: 'Resource suggestions'
    }
  );

  type ResourceOption = {
    id: string;
    accountId?: string;
    plan?: string;
    status: string;
  };

  let options = $state<ResourceOption[]>([]);
  let open = $state(false);
  let loading = $state(false);
  let failed = $state(false);
  let activeIndex = $state(-1);
  let generation = 0;
  let debounce: number | undefined;
  let closeTimer: number | undefined;
  let observedAccountId = '';
  let observedAccountInitialized = false;
  let listboxId = $derived(`resource-${kind}-options`);

  function schedule() {
    open = true;
    activeIndex = -1;
    if (closeTimer) {
      clearTimeout(closeTimer);
      closeTimer = undefined;
    }
    if (debounce) clearTimeout(debounce);
    debounce = window.setTimeout(() => void load(), 250);
  }

  async function load() {
    const current = ++generation;
    loading = true;
    failed = false;
    const parameters = new URLSearchParams({ pageSize: '50' });
    if (value.trim()) parameters.set('query', value.trim());
    if (kind === 'license' && accountId.trim()) parameters.set('account', accountId.trim());
    try {
      if (kind === 'account') {
        const page = await api<AdminPage<AdminAccount>>(`/accounts?${parameters}`);
        if (current !== generation) return;
        options = page.items.map((item) => ({ id: item.id, status: item.state }));
      } else {
        const page = await api<AdminPage<AdminLicense>>(`/licenses?${parameters}`);
        if (current !== generation) return;
        options = page.items.map((item) => ({
          id: item.id,
          accountId: item.accountId,
          plan: item.plan,
          status: item.status
        }));
      }
    } catch {
      if (current === generation) {
        options = [];
        failed = true;
      }
    } finally {
      if (current === generation) loading = false;
    }
  }

  function select(option: { id: string }) {
    value = option.id;
    open = false;
    activeIndex = -1;
  }

  function optionDetail(option: ResourceOption) {
    const status = statusLabel(option.status, $locale);
    return option.plan
      ? `${option.accountId} · ${planLabel(option.plan, $locale)} · ${status}`
      : status;
  }

  function keydown(event: KeyboardEvent) {
    if (event.key === 'ArrowDown') {
      event.preventDefault();
      if (!open) {
        open = true;
        void load();
      } else if (options.length) activeIndex = Math.min(options.length - 1, activeIndex + 1);
    } else if (event.key === 'ArrowUp' && open) {
      event.preventDefault();
      if (options.length) activeIndex = Math.max(0, activeIndex - 1);
    } else if (event.key === 'Enter' && open && activeIndex >= 0) {
      event.preventDefault();
      select(options[activeIndex]);
    } else if (event.key === 'Escape' && open) {
      event.preventDefault();
      open = false;
    }
  }

  function closeAfterFocus() {
    if (closeTimer) clearTimeout(closeTimer);
    closeTimer = window.setTimeout(() => {
      open = false;
      closeTimer = undefined;
    }, 100);
  }

  onDestroy(() => {
    generation++;
    if (debounce) clearTimeout(debounce);
    if (closeTimer) clearTimeout(closeTimer);
  });

  $effect(() => {
    const nextAccountId = accountId;
    untrack(() => {
      if (observedAccountInitialized && kind === 'license' && observedAccountId !== nextAccountId)
        value = '';
      observedAccountId = nextAccountId;
      observedAccountInitialized = true;
      generation++;
      options = [];
      activeIndex = -1;
      if (open) schedule();
    });
  });
</script>

<div class="resource-combobox">
  <div class="resource-combobox-input">
    <Search size={16} aria-hidden="true" />
    <input
      bind:value
      {placeholder}
      {disabled}
      role="combobox"
      aria-autocomplete="list"
      aria-expanded={open}
      aria-controls={listboxId}
      aria-activedescendant={activeIndex >= 0 ? `${listboxId}-${activeIndex}` : undefined}
      autocomplete="off"
      onfocus={() => {
        if (closeTimer) {
          clearTimeout(closeTimer);
          closeTimer = undefined;
        }
        open = true;
        void load();
      }}
      onblur={closeAfterFocus}
      oninput={schedule}
      onkeydown={keydown}
    />
  </div>
  {#if open}
    <div
      class="resource-combobox-options"
      id={listboxId}
      role="listbox"
      aria-label={messages[$locale].suggestions}
    >
      {#if loading}
        <p role="status">{messages[$locale].loading}</p>
      {:else if failed}
        <p role="status">{messages[$locale].failed}</p>
      {:else if options.length}
        {#each options as option, index (option.id)}
          <button
            id={`${listboxId}-${index}`}
            type="button"
            role="option"
            aria-selected={index === activeIndex}
            class:active={index === activeIndex}
            onmousedown={(event) => event.preventDefault()}
            onclick={() => select(option)}
          >
            <strong>{option.id}</strong><small>{optionDetail(option)}</small>
          </button>
        {/each}
      {:else}
        <p role="status">{messages[$locale].empty}</p>
      {/if}
    </div>
  {/if}
</div>
