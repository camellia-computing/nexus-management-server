<script lang="ts">
  import { ChevronRight, Inbox } from '@lucide/svelte';
  import { enabledLabel, jobKindLabel, planLabel } from './domainLabels';
  import StatusBadge from './StatusBadge.svelte';
  import { copy, locale, localeTag } from './i18n';

  type Column = {
    key: string;
    label: string;
    type?: 'status' | 'time' | 'mono' | 'plan' | 'job-kind' | 'enabled' | 'number';
    align?: 'start' | 'center' | 'end';
  };
  let {
    columns,
    rows,
    loading = false,
    onSelect
  }: {
    columns: Column[];
    rows: Record<string, unknown>[];
    loading?: boolean;
    onSelect?: (row: Record<string, unknown>) => void;
  } = $props();
  const display = (value: unknown, type?: string) => {
    if (value === null || value === undefined || value === '') return '—';
    if (type === 'time' && typeof value === 'number')
      return new Date(value * 1000).toLocaleString(localeTag($locale));
    if (type === 'plan') return planLabel(String(value), $locale);
    if (type === 'job-kind') return jobKindLabel(String(value), $locale);
    if (type === 'enabled') return enabledLabel(value, $locale);
    if (typeof value === 'object') return JSON.stringify(value);
    return String(value);
  };
  const alignment = (column: Column) =>
    column.align ??
    (column.type &&
    ['status', 'time', 'plan', 'job-kind', 'enabled', 'number'].includes(column.type)
      ? 'center'
      : 'start');
</script>

<div class="table-shell">
  <table>
    <thead
      ><tr
        >{#each columns as column}<th
            class:cell-center={alignment(column) === 'center'}
            class:cell-end={alignment(column) === 'end'}>{column.label}</th
          >{/each}{#if onSelect}<th class="cell-end"
            ><span class="sr-only">{copy[$locale].manage}</span></th
          >{/if}</tr
      ></thead
    >
    <tbody>
      {#if loading}
        {#each Array(6) as _}<tr class="skeleton-row"
            >{#each columns as _}<td><span></span></td>{/each}{#if onSelect}<td></td>{/if}</tr
          >{/each}
      {:else}
        {#each rows as row}
          <tr>
            {#each columns as column}
              <td
                class:mono={column.type === 'mono'}
                class:cell-center={alignment(column) === 'center'}
                class:cell-end={alignment(column) === 'end'}
              >
                {#if column.type === 'status'}<StatusBadge
                    value={display(row[column.key])}
                  />{:else}{display(row[column.key], column.type)}{/if}
              </td>
            {/each}
            {#if onSelect}<td class="row-action"
                ><button aria-label={copy[$locale].manage} onclick={() => onSelect?.(row)}
                  ><span>{copy[$locale].manage}</span><ChevronRight size={15} /></button
                ></td
              >{/if}
          </tr>
        {/each}
      {/if}
    </tbody>
  </table>
  {#if !loading && rows.length === 0}
    <div class="empty-state">
      <span><Inbox size={24} /></span><strong>{copy[$locale].empty}</strong><small
        >{copy[$locale].emptyHint}</small
      >
    </div>
  {/if}
</div>
