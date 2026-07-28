<script lang="ts">
  import { ChevronDown, Filter } from '@lucide/svelte';

  type Option = {
    value: string;
    label: string;
  };

  let {
    value = $bindable(),
    options,
    label,
    disabled = false
  }: {
    value: string;
    options: readonly Option[];
    label: string;
    disabled?: boolean;
  } = $props();
</script>

<label class="filter-select">
  <Filter size={16} aria-hidden="true" />
  <span class="filter-select-value">
    {#each options as option}<span aria-hidden="true">{option.label}</span>{/each}
    <select bind:value aria-label={label} data-option-align="center" {disabled}>
      {#each options as option}<option value={option.value}>{option.label}</option>{/each}
    </select>
  </span>
  <ChevronDown size={14} aria-hidden="true" />
</label>
