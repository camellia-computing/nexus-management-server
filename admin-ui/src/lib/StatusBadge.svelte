<script lang="ts">
  import { statusLabel } from './domainLabels';
  import { locale } from './i18n';
  let { value }: { value: string } = $props();
  const good = [
    'active',
    'ready',
    'succeeded',
    'verified',
    'paid',
    'clean',
    'delivered',
    'resolved'
  ];
  const warn = [
    'pending',
    'pending_activation',
    'suspended',
    'past_due',
    'submitted',
    'under_review',
    'needs_information',
    'open',
    'overdue',
    'queued',
    'running',
    'invited',
    'cancel_requested',
    'quarantined',
    'retry',
    'in_flight',
    'acknowledged'
  ];
  const bad = [
    'disabled',
    'revoked',
    'rejected',
    'failed',
    'partial_failed',
    'denied',
    'denylisted',
    'suspicious',
    'dead'
  ];
  let label = $derived(statusLabel(value, $locale));
</script>

<span
  class:good={good.includes(value)}
  class:warn={warn.includes(value)}
  class:bad={bad.includes(value)}
  class="status-badge"><i></i>{label}</span
>
