<script lang="ts">
  import { onMount } from 'svelte';
  import {
    AlertCircle,
    CheckCircle2,
    Clock3,
    CreditCard,
    Plus,
    RefreshCw,
    Search,
    X
  } from '@lucide/svelte';
  import { api, ApiError, isVersionConflict, MutationAttempt } from './api';
  import type {
    AdminDashboard,
    AdminItems,
    AdminPage,
    AdminPaymentEvidence
  } from './admin-contracts';
  import { focusTrap } from './actions/focusTrap';
  import { planLabel, statusLabel } from './domainLabels';
  import { defineCopy, locale } from './i18n';
  import ResourceCombobox from './ResourceCombobox.svelte';
  import ResourceTable from './ResourceTable.svelte';

  let { permissions }: { permissions: string[] } = $props();

  type BillingTab = 'claims' | 'invoices' | 'offers' | 'methods';
  type Column = {
    key: string;
    label: string;
    type?: 'status' | 'time' | 'mono' | 'plan' | 'job-kind' | 'enabled' | 'number';
    align?: 'start' | 'center' | 'end';
  };
  type BillingConfig = { endpoint: string; columns: Column[] };
  type PaymentClaim = Record<string, unknown> & {
    id: string;
    rowVersion: number;
    invoiceId: string;
    paidAmount: string;
    paidAsset: string;
    externalTransactionId: string;
    status: string;
    createdAt: number;
  };
  type CommercialOffer = {
    id: string;
    rowVersion: number;
    plan: 'pro' | 'team';
    planRevision: number;
    durationDays: number;
    currency: string;
    baseAmount: string;
    seatAmount: string | null;
    nameEn: string;
    nameZh: string;
    active: boolean;
  };

  const messages = defineCopy(
    {
      breadcrumb: '控制台 / 商业运营',
      title: '账单与付款',
      description: '支持人工付款渠道的报价、账单、证据与审核闭环。',
      newInvoice: '新建账单',
      claims: '付款审核',
      invoices: '账单',
      offers: '商业报价',
      methods: '收款方式',
      paymentClaim: '付款声明',
      invoice: '账单',
      amount: '金额',
      asset: '资产',
      status: '状态',
      submittedAt: '提交时间',
      invoiceId: '账单 ID',
      account: '账户',
      accountId: '账户 ID',
      plan: '套餐',
      amountDue: '应付金额',
      dueAt: '到期时间',
      offerId: '报价 ID',
      offer: '商业报价',
      selectOffer: '请选择已启用的报价',
      loadingOffers: '正在加载报价…',
      noOffers: '暂无已启用的商业报价，请先创建报价。',
      offersFailed: '商业报价加载失败',
      retryOffers: '重新加载报价',
      duration: '有效天数',
      currency: '币种',
      baseAmount: '基础价格',
      enabled: '启用',
      methodId: '方式 ID',
      name: '名称',
      settlementAsset: '结算资产',
      destination: '收款信息',
      pendingReview: '等待审核',
      visibleRecords: '当前视图记录',
      openInvoices: '开放账单',
      followUp: '需运营跟进',
      search: '搜索账单、账户或交易号…',
      refresh: '刷新',
      loadFailed: '账单数据加载失败',
      createTitle: '新建商业账单',
      licenseId: '授权 ID',
      seats: 'Team 席位',
      seatsHint: 'Team 报价必须购买 3 至 10,000 席。',
      seatsInvalid: 'Team 席位必须为 3 至 10,000 的整数。',
      priceSummary: '价格摘要',
      basePrice: '基础价格',
      seatPrice: '每席价格',
      perSeatUnit: '席',
      estimatedTotal: '预计应付',
      days: '天',
      paymentDue: '付款截止',
      reason: '操作原因',
      cancel: '取消',
      creating: '正在创建…',
      createInvoice: '创建账单',
      createFailed: '创建失败',
      paymentReview: '付款审核',
      paidAmount: '付款金额',
      transactionId: '外部交易号',
      evidence: '付款证据',
      noEvidence: '尚未上传证据',
      addEvidence: '补充证据',
      upload: '上传并扫描',
      decision: '审核决定',
      approve: '批准',
      reject: '拒绝',
      requestInfo: '要求补充信息',
      override: '允许金额或资产不完全匹配（仅平台所有者）',
      reviewReason: '审核原因',
      invoiceEyebrow: '账单 / 商业账单',
      claimEyebrow: '付款 / 审核',
      close: '关闭',
      processing: '正在处理…',
      submitReview: '提交审核',
      evidenceFailed: '证据加载失败',
      uploadFailed: '上传失败',
      reviewFailed: '审核失败',
      reviewComplete: '该付款声明已结束审核，仅保留证据与结果供查阅。',
      reviewChanged: '该付款声明已被其他会话更新。已载入最新状态，请核对后重新操作。',
      reviewMissing: '该付款声明已更新且不再出现在当前列表中。已刷新列表，请从最新记录重新进入。',
      reviewReloadFailed:
        '该付款声明已被其他会话更新，但最新状态载入失败。请关闭窗口并刷新列表后重试。'
    },
    {
      breadcrumb: 'Console / Commercial operations',
      title: 'Billing and payments',
      description:
        'Complete manual-payment workflows across offers, invoices, evidence, and review.',
      newInvoice: 'New invoice',
      claims: 'Payment review',
      invoices: 'Invoices',
      offers: 'Commercial offers',
      methods: 'Payment methods',
      paymentClaim: 'Payment claim',
      invoice: 'Invoice',
      amount: 'Amount',
      asset: 'Asset',
      status: 'Status',
      submittedAt: 'Submitted at',
      invoiceId: 'Invoice ID',
      account: 'Account',
      accountId: 'Account ID',
      plan: 'Plan',
      amountDue: 'Amount due',
      dueAt: 'Due at',
      offerId: 'Offer ID',
      offer: 'Commercial offer',
      selectOffer: 'Select an active offer',
      loadingOffers: 'Loading offers…',
      noOffers: 'No active commercial offers are available. Create an offer first.',
      offersFailed: 'Commercial offers failed to load',
      retryOffers: 'Reload offers',
      duration: 'Duration in days',
      currency: 'Currency',
      baseAmount: 'Base amount',
      enabled: 'Enabled',
      methodId: 'Method ID',
      name: 'Name',
      settlementAsset: 'Settlement asset',
      destination: 'Payment destination',
      pendingReview: 'Awaiting review',
      visibleRecords: 'Records in this view',
      openInvoices: 'Open invoices',
      followUp: 'Requires follow-up',
      search: 'Search invoices, accounts, or transaction IDs…',
      refresh: 'Refresh',
      loadFailed: 'Billing data failed to load',
      createTitle: 'Create commercial invoice',
      licenseId: 'License ID',
      seats: 'Team seats',
      seatsHint: 'Team offers require between 3 and 10,000 purchased seats.',
      seatsInvalid: 'Team seats must be an integer between 3 and 10,000.',
      priceSummary: 'Price summary',
      basePrice: 'Base price',
      seatPrice: 'Per-seat price',
      perSeatUnit: 'seat',
      estimatedTotal: 'Estimated amount due',
      days: 'days',
      paymentDue: 'Payment due',
      reason: 'Operation reason',
      cancel: 'Cancel',
      creating: 'Creating…',
      createInvoice: 'Create invoice',
      createFailed: 'Invoice creation failed',
      paymentReview: 'Payment review',
      paidAmount: 'Paid amount',
      transactionId: 'External transaction ID',
      evidence: 'Payment evidence',
      noEvidence: 'No evidence uploaded',
      addEvidence: 'Add evidence',
      upload: 'Upload and scan',
      decision: 'Review decision',
      approve: 'Approve',
      reject: 'Reject',
      requestInfo: 'Request information',
      override: 'Allow amount or asset mismatch (Platform Owner only)',
      reviewReason: 'Review reason',
      invoiceEyebrow: 'Billing / Invoice',
      claimEyebrow: 'Payment / Review',
      close: 'Close',
      processing: 'Processing…',
      submitReview: 'Submit review',
      evidenceFailed: 'Evidence failed to load',
      uploadFailed: 'Upload failed',
      reviewFailed: 'Review failed',
      reviewComplete:
        'This payment claim is final. Its evidence and result remain available for reference.',
      reviewChanged:
        'This payment claim changed in another session. The latest state has been loaded; review it before retrying.',
      reviewMissing:
        'This payment claim changed and no longer appears in the current list. The list has been refreshed; reopen the latest record.',
      reviewReloadFailed:
        'This payment claim changed in another session, but its latest state could not be loaded. Close this dialog, refresh the list, and try again.'
    }
  );

  let tab = $state<BillingTab>('claims');
  let rows = $state<Record<string, unknown>[]>([]);
  let loading = $state(true);
  let query = $state('');
  let dashboard = $state<Partial<AdminDashboard>>({});
  let creating = $state(false);
  let saving = $state(false);
  let loadError = $state('');
  let dialogError = $state('');
  let invoiceFieldErrors = $state<Record<string, string>>({});
  let activeOffers = $state<CommercialOffer[]>([]);
  let offersLoading = $state(false);
  let offersError = $state('');
  let form = $state({
    id: '',
    accountId: '',
    licenseId: '',
    offerId: '',
    seats: '0',
    dueAt: '+7d',
    reason: ''
  });
  let selected = $state<PaymentClaim | null>(null);
  let decision = $state('approve');
  let reviewReason = $state('');
  let overrideAmount = $state(false);
  let evidence = $state<AdminPaymentEvidence[]>([]);
  let evidenceFile = $state<File | null>(null);
  let loadGeneration = 0;
  let claimLoadGeneration = 0;
  let offerLoadGeneration = 0;
  const invoiceAttempt = new MutationAttempt();
  const reviewAttempt = new MutationAttempt();
  const evidenceAttempt = new MutationAttempt();
  let permissionSet = $derived(new Set(permissions));
  let canWrite = $derived(permissionSet.has('billing.write'));
  let canReview = $derived(permissionSet.has('billing.review'));
  let canOverride = $derived(permissionSet.has('billing.override'));
  let selectedOffer = $derived(activeOffers.find((offer) => offer.id === form.offerId) ?? null);
  let claimReviewable = $derived(
    selected !== null &&
      ['submitted', 'under_review', 'needs_information'].includes(selected.status)
  );
  let tabs: { id: BillingTab; label: string }[] = $derived([
    { id: 'claims', label: messages[$locale].claims },
    { id: 'invoices', label: messages[$locale].invoices },
    { id: 'offers', label: messages[$locale].offers },
    { id: 'methods', label: messages[$locale].methods }
  ]);
  let configs = $derived<Record<BillingTab, BillingConfig>>({
    claims: {
      endpoint: '/billing/payment-claims',
      columns: [
        { key: 'id', label: messages[$locale].paymentClaim, type: 'mono' },
        { key: 'invoiceId', label: messages[$locale].invoice, type: 'mono' },
        { key: 'paidAmount', label: messages[$locale].amount, type: 'number' },
        { key: 'paidAsset', label: messages[$locale].asset, align: 'center' },
        { key: 'status', label: messages[$locale].status, type: 'status' },
        { key: 'createdAt', label: messages[$locale].submittedAt, type: 'time' }
      ]
    },
    invoices: {
      endpoint: '/billing/invoices',
      columns: [
        { key: 'id', label: messages[$locale].invoiceId, type: 'mono' },
        { key: 'accountId', label: messages[$locale].account, type: 'mono' },
        { key: 'plan', label: messages[$locale].plan, type: 'plan' },
        { key: 'amountDue', label: messages[$locale].amountDue, type: 'number' },
        { key: 'status', label: messages[$locale].status, type: 'status' },
        { key: 'dueAt', label: messages[$locale].dueAt, type: 'time' }
      ]
    },
    offers: {
      endpoint: '/billing/offers',
      columns: [
        { key: 'id', label: messages[$locale].offerId, type: 'mono' },
        { key: 'plan', label: messages[$locale].plan, type: 'plan' },
        { key: 'durationDays', label: messages[$locale].duration, type: 'number' },
        { key: 'currency', label: messages[$locale].currency, align: 'center' },
        { key: 'baseAmount', label: messages[$locale].baseAmount, type: 'number' },
        { key: 'active', label: messages[$locale].enabled, type: 'enabled' }
      ]
    },
    methods: {
      endpoint: '/billing/payment-methods',
      columns: [
        { key: 'id', label: messages[$locale].methodId, type: 'mono' },
        { key: 'nameZh', label: messages[$locale].name },
        { key: 'settlementAsset', label: messages[$locale].settlementAsset },
        { key: 'destinationHint', label: messages[$locale].destination },
        { key: 'active', label: messages[$locale].enabled, type: 'enabled' }
      ]
    }
  });
  let filteredRows = $derived(
    rows.filter((row) => !query || JSON.stringify(row).toLowerCase().includes(query.toLowerCase()))
  );
  let invoiceValid = $derived(
    Boolean(
      form.id.trim() &&
      form.accountId.trim() &&
      form.licenseId.trim() &&
      selectedOffer !== null &&
      form.dueAt.trim() &&
      form.reason.trim()
    ) &&
      Number.isInteger(Number(form.seats)) &&
      (selectedOffer?.plan === 'team'
        ? Number(form.seats) >= 3 && Number(form.seats) <= 10_000
        : Number(form.seats) === 0)
  );

  function decimalUnits(value: string) {
    const match = /^(\d+)(?:\.(\d{0,8}))?$/.exec(value);
    if (!match) return null;
    return BigInt(match[1]) * 100_000_000n + BigInt((match[2] ?? '').padEnd(8, '0'));
  }

  function formatUnits(value: bigint) {
    const whole = value / 100_000_000n;
    let fraction = (value % 100_000_000n).toString().padStart(8, '0');
    while (fraction.length > 2 && fraction.endsWith('0')) fraction = fraction.slice(0, -1);
    return `${whole}.${fraction}`;
  }

  function money(value: string, currency: string) {
    const units = decimalUnits(value);
    return `${currency} ${units === null ? value : formatUnits(units)}`;
  }

  function offerTotal(offer: CommercialOffer, seats: number) {
    const base = decimalUnits(offer.baseAmount);
    const perSeat = decimalUnits(offer.seatAmount ?? '0');
    if (base === null || perSeat === null) return money(offer.baseAmount, offer.currency);
    if (!Number.isSafeInteger(seats) || seats < 0 || seats > 10_000) return `${offer.currency} —`;
    return `${offer.currency} ${formatUnits(base + perSeat * BigInt(seats))}`;
  }

  function offerName(offer: CommercialOffer) {
    return $locale === 'zh' ? offer.nameZh : offer.nameEn;
  }

  function offerOption(offer: CommercialOffer) {
    const price =
      offer.plan === 'team' && offer.seatAmount
        ? `${money(offer.baseAmount, offer.currency)} + ${money(offer.seatAmount, offer.currency)}/${messages[$locale].perSeatUnit}`
        : money(offer.baseAmount, offer.currency);
    return `${offerName(offer)} · ${planLabel(offer.plan, $locale)} · ${offer.durationDays} ${messages[$locale].days} · ${price}`;
  }

  async function loadActiveOffers() {
    const generation = ++offerLoadGeneration;
    offersLoading = true;
    offersError = '';
    try {
      const offers = await api<CommercialOffer[]>('/billing/offers?activeOnly=true');
      if (generation !== offerLoadGeneration || !creating) return;
      activeOffers = offers.filter((offer) => offer.active);
      if (!activeOffers.some((offer) => offer.id === form.offerId)) form.offerId = '';
    } catch (cause) {
      if (generation === offerLoadGeneration && creating) {
        activeOffers = [];
        offersError = cause instanceof Error ? cause.message : messages[$locale].offersFailed;
      }
    } finally {
      if (generation === offerLoadGeneration) offersLoading = false;
    }
  }

  function changeOffer(offerId: string) {
    form.offerId = offerId;
    invoiceFieldErrors = {};
    const offer = activeOffers.find((item) => item.id === offerId);
    if (offer?.plan === 'team') {
      const seats = Number(form.seats);
      if (!Number.isInteger(seats) || seats < 3 || seats > 10_000) form.seats = '3';
    } else {
      form.seats = '0';
    }
  }

  async function load(requestedTab: BillingTab = tab) {
    const generation = ++loadGeneration;
    loading = true;
    loadError = '';
    try {
      const data = await api<AdminPage<Record<string, unknown>> | Record<string, unknown>[]>(
        configs[requestedTab].endpoint
      );
      if (generation !== loadGeneration || requestedTab !== tab) return false;
      rows = Array.isArray(data) ? data : data.items;
      return true;
    } catch (cause) {
      if (generation === loadGeneration && requestedTab === tab)
        loadError = cause instanceof Error ? cause.message : messages[$locale].loadFailed;
      return false;
    } finally {
      if (generation === loadGeneration && requestedTab === tab) loading = false;
    }
  }

  function selectTab(value: BillingTab) {
    if (tab === value) return;
    tab = value;
    query = '';
    rows = [];
    void load(value);
  }

  function openInvoice() {
    form = {
      id: '',
      accountId: '',
      licenseId: '',
      offerId: '',
      seats: '0',
      dueAt: '+7d',
      reason: ''
    };
    dialogError = '';
    invoiceFieldErrors = {};
    activeOffers = [];
    offersError = '';
    invoiceAttempt.succeeded();
    creating = true;
    void loadActiveOffers();
  }

  async function createInvoice() {
    if (saving || !invoiceValid) return;
    saving = true;
    dialogError = '';
    invoiceFieldErrors = {};
    const body = JSON.stringify({ ...form, seats: Number(form.seats) });
    try {
      await api('/billing/invoices', {
        method: 'POST',
        mutation: true,
        operationId: invoiceAttempt.operationId(`/billing/invoices:${body}`),
        body
      });
      invoiceAttempt.succeeded();
      creating = false;
      tab = 'invoices';
      rows = [];
      await load('invoices');
    } catch (cause) {
      invoiceAttempt.failed(cause);
      if (cause instanceof ApiError && cause.field) {
        invoiceFieldErrors = {
          [cause.field]: cause.field === 'seats' ? messages[$locale].seatsInvalid : cause.message
        };
      } else {
        dialogError = cause instanceof Error ? cause.message : messages[$locale].createFailed;
      }
    } finally {
      saving = false;
    }
  }

  async function openClaim(row: Record<string, unknown>, resetReview = selected?.id !== row.id) {
    const claim = row as PaymentClaim;
    const generation = ++claimLoadGeneration;
    if (selected?.id !== claim.id) {
      reviewAttempt.succeeded();
      evidenceAttempt.succeeded();
      evidenceFile = null;
    }
    selected = claim;
    evidence = [];
    if (resetReview) {
      decision = 'approve';
      overrideAmount = false;
      reviewReason = '';
    }
    dialogError = '';
    try {
      const data = await api<AdminItems<AdminPaymentEvidence>>(
        `/billing/payment-claims/${claim.id}/evidence`
      );
      if (generation === claimLoadGeneration && selected?.id === claim.id) evidence = data.items;
      return true;
    } catch (cause) {
      if (generation === claimLoadGeneration && selected?.id === claim.id)
        dialogError = cause instanceof Error ? cause.message : messages[$locale].evidenceFailed;
      return false;
    }
  }

  function closeClaim() {
    if (saving) return;
    selected = null;
    claimLoadGeneration++;
  }

  async function uploadEvidence() {
    if (!selected || !evidenceFile || !reviewReason.trim() || saving) return;
    const claim = selected;
    const file = evidenceFile;
    saving = true;
    dialogError = '';
    try {
      const digest = Array.from(
        new Uint8Array(await crypto.subtle.digest('SHA-256', await file.arrayBuffer())),
        (byte) => byte.toString(16).padStart(2, '0')
      ).join('');
      const fingerprint = `${claim.id}:${reviewReason}:${file.name}:${file.size}:${file.type}:${digest}`;
      const body = new FormData();
      body.append('file', file);
      await api(`/billing/payment-claims/${claim.id}/evidence`, {
        method: 'POST',
        mutation: true,
        operationId: evidenceAttempt.operationId(fingerprint),
        reason: reviewReason,
        body
      });
      evidenceAttempt.succeeded();
      evidenceFile = null;
      await openClaim(claim);
    } catch (cause) {
      evidenceAttempt.failed(cause);
      dialogError = cause instanceof Error ? cause.message : messages[$locale].uploadFailed;
    } finally {
      saving = false;
    }
  }

  async function review() {
    if (!selected || !reviewReason.trim() || saving) return;
    const claim = selected;
    saving = true;
    dialogError = '';
    const body = JSON.stringify({
      decision,
      allowAmountOverride: overrideAmount,
      reason: reviewReason
    });
    try {
      await api(`/billing/payment-claims/${claim.id}/actions/review`, {
        method: 'POST',
        mutation: true,
        operationId: reviewAttempt.operationId(`${claim.id}:${claim.rowVersion}:${body}`),
        headers: { 'if-match': `"${claim.rowVersion}"` },
        body
      });
      reviewAttempt.succeeded();
      selected = null;
      claimLoadGeneration++;
      await load();
    } catch (cause) {
      reviewAttempt.failed(cause);
      if (isVersionConflict(cause)) {
        if (await load('claims')) {
          const latest = rows.find((row) => row.id === claim.id) as PaymentClaim | undefined;
          if (latest) {
            const evidenceLoaded = await openClaim(latest, true);
            dialogError = evidenceLoaded
              ? messages[$locale].reviewChanged
              : `${messages[$locale].reviewChanged} ${messages[$locale].evidenceFailed}.`;
          } else {
            selected = null;
            claimLoadGeneration++;
            loadError = messages[$locale].reviewMissing;
          }
        } else {
          dialogError = messages[$locale].reviewReloadFailed;
        }
      } else {
        dialogError = cause instanceof Error ? cause.message : messages[$locale].reviewFailed;
      }
    } finally {
      saving = false;
    }
  }

  async function loadDashboard() {
    try {
      dashboard = await api<AdminDashboard>('/dashboard');
    } catch {
      dashboard = {};
    }
  }

  onMount(() => {
    void Promise.all([load(), loadDashboard()]);
  });
</script>

<div class="page-heading">
  <div>
    <span class="breadcrumb">{messages[$locale].breadcrumb}</span>
    <h1>{messages[$locale].title}</h1>
    <p>{messages[$locale].description}</p>
  </div>
  {#if canWrite}<button class="primary" onclick={openInvoice}
      ><Plus size={17} />{messages[$locale].newInvoice}</button
    >{/if}
</div>
<section class="billing-summary">
  <article>
    <span class="amber"><Clock3 size={19} /></span>
    <div>
      <small>{messages[$locale].pendingReview}</small><strong
        >{dashboard.pendingPayments ?? '—'}</strong
      >
    </div>
  </article>
  <article>
    <span class="green"><CheckCircle2 size={19} /></span>
    <div>
      <small>{messages[$locale].visibleRecords}</small><strong>{loading ? '—' : rows.length}</strong
      >
    </div>
  </article>
  <article>
    <span class="blue"><CreditCard size={19} /></span>
    <div>
      <small>{messages[$locale].openInvoices}</small><strong>{dashboard.openInvoices ?? '—'}</strong
      >
    </div>
  </article>
  <article>
    <span class="red"><AlertCircle size={19} /></span>
    <div>
      <small>{messages[$locale].followUp}</small><strong
        >{(dashboard.pendingPayments ?? 0) + (dashboard.openInvoices ?? 0)}</strong
      >
    </div>
  </article>
</section>
<section class="panel resource-panel">
  <div class="tab-bar" role="tablist">
    {#each tabs as item}<button
        role="tab"
        aria-selected={tab === item.id}
        class:active={tab === item.id}
        onclick={() => selectTab(item.id)}
        >{item.label}{#if item.id === 'claims' && dashboard.pendingPayments}<i
            >{dashboard.pendingPayments}</i
          >{/if}</button
      >{/each}
  </div>
  <div class="resource-toolbar">
    <div class="search-field">
      <Search size={17} /><input bind:value={query} placeholder={messages[$locale].search} />
    </div>
    <button
      class="icon-button"
      onclick={() => load()}
      disabled={loading}
      aria-label={messages[$locale].refresh}
      ><RefreshCw size={18} class={loading ? 'spin' : ''} /></button
    >
  </div>
  {#if loadError}<div class="inline-error" role="alert">
      <span>{loadError}</span><button onclick={() => load()}>{messages[$locale].refresh}</button>
    </div>{/if}<ResourceTable
    columns={configs[tab].columns}
    rows={filteredRows}
    {loading}
    onSelect={tab === 'claims' && canReview ? openClaim : undefined}
  />
</section>

{#if creating}
  <div class="modal-layer">
    <button
      class="modal-scrim"
      aria-label={messages[$locale].close}
      onclick={() => {
        if (!saving) creating = false;
      }}
      disabled={saving}
    ></button>
    <div
      use:focusTrap={{
        onEscape: saving ? undefined : () => (creating = false),
        initialFocus: 'input'
      }}
      class="modal-card"
      role="dialog"
      aria-modal="true"
      aria-labelledby="invoice-title"
    >
      <header>
        <div>
          <span class="eyebrow">{messages[$locale].invoiceEyebrow}</span>
          <h2 id="invoice-title">{messages[$locale].createTitle}</h2>
        </div>
        <button
          aria-label={messages[$locale].close}
          disabled={saving}
          class="icon-button modal-close"
          onclick={() => (creating = false)}><X size={18} /></button
        >
      </header>
      {#if dialogError}<div class="form-error" role="alert">{dialogError}</div>{/if}
      <div class="form-grid">
        <label
          >{messages[$locale].invoiceId}<input
            bind:value={form.id}
            placeholder="invoice_2026_001"
          /></label
        ><label
          >{messages[$locale].accountId}<ResourceCombobox
            kind="account"
            bind:value={form.accountId}
            placeholder="acct_customer_001"
          /></label
        ><label
          >{messages[$locale].licenseId}<ResourceCombobox
            kind="license"
            accountId={form.accountId}
            bind:value={form.licenseId}
            placeholder="lic_customer_001"
          /></label
        ><label class="wide"
          >{messages[$locale].offer}<select
            data-option-align="start"
            value={form.offerId}
            disabled={offersLoading || !activeOffers.length}
            onchange={(event) => changeOffer(event.currentTarget.value)}
          >
            <option value=""
              >{offersLoading
                ? messages[$locale].loadingOffers
                : messages[$locale].selectOffer}</option
            >
            {#each activeOffers as offer (offer.id)}<option value={offer.id}
                >{offerOption(offer)}</option
              >{/each}
          </select>
          {#if !offersLoading && !offersError && !activeOffers.length}<small class="field-help"
              >{messages[$locale].noOffers}</small
            >{/if}</label
        >
        {#if offersError}<div class="offer-load-error wide" role="alert">
            <span>{offersError || messages[$locale].offersFailed}</span><button
              type="button"
              onclick={() => void loadActiveOffers()}
              disabled={offersLoading}>{messages[$locale].retryOffers}</button
            >
          </div>{/if}
        {#if selectedOffer?.plan === 'team'}<label
            >{messages[$locale].seats}<input
              type="number"
              min="3"
              max="10000"
              step="1"
              bind:value={form.seats}
              aria-invalid={Boolean(invoiceFieldErrors.seats)}
              aria-describedby={invoiceFieldErrors.seats
                ? 'invoice-seats-error'
                : 'invoice-seats-help'}
              oninput={() => (invoiceFieldErrors = {})}
            />{#if invoiceFieldErrors.seats}<small
                id="invoice-seats-error"
                class="field-error"
                role="alert">{invoiceFieldErrors.seats}</small
              >{:else}<small id="invoice-seats-help" class="field-help"
                >{messages[$locale].seatsHint}</small
              >{/if}</label
          >{/if}<label class:wide={selectedOffer?.plan !== 'team'}
          >{messages[$locale].paymentDue}<input bind:value={form.dueAt} placeholder="+7d" /></label
        >
        {#if selectedOffer}<section class="invoice-offer-summary wide" aria-live="polite">
            <header>
              <strong>{messages[$locale].priceSummary}</strong><span
                >{offerName(selectedOffer)} · {planLabel(selectedOffer.plan, $locale)}</span
              >
            </header>
            <dl>
              <div>
                <dt>{messages[$locale].basePrice}</dt>
                <dd>{money(selectedOffer.baseAmount, selectedOffer.currency)}</dd>
              </div>
              {#if selectedOffer.plan === 'team'}<div>
                  <dt>{messages[$locale].seatPrice}</dt>
                  <dd>{money(selectedOffer.seatAmount ?? '0', selectedOffer.currency)}</dd>
                </div>{/if}
              <div class="total">
                <dt>{messages[$locale].estimatedTotal}</dt>
                <dd>{offerTotal(selectedOffer, Number(form.seats))}</dd>
              </div>
            </dl>
            <small
              ><code>{selectedOffer.id}</code> · {selectedOffer.durationDays}
              {messages[$locale].days}</small
            >
          </section>{/if}
        <label class="wide"
          >{messages[$locale].reason}<textarea bind:value={form.reason}></textarea></label
        >
      </div>
      <footer>
        <button class="secondary" disabled={saving} onclick={() => (creating = false)}
          >{messages[$locale].cancel}</button
        ><button class="primary" onclick={createInvoice} disabled={saving || !invoiceValid}
          >{saving ? messages[$locale].creating : messages[$locale].createInvoice}</button
        >
      </footer>
    </div>
  </div>
{/if}

{#if selected}
  <div class="modal-layer">
    <button
      class="modal-scrim"
      aria-label={messages[$locale].close}
      onclick={closeClaim}
      disabled={saving}
    ></button>
    <div
      use:focusTrap={{
        onEscape: saving ? undefined : closeClaim,
        initialFocus: 'input[type="file"], select'
      }}
      class="modal-card"
      role="dialog"
      aria-modal="true"
      aria-labelledby="claim-title"
    >
      <header>
        <div>
          <span class="eyebrow">{messages[$locale].claimEyebrow}</span>
          <h2 id="claim-title">{selected.id}</h2>
        </div>
        <button
          aria-label={messages[$locale].close}
          disabled={saving}
          onclick={closeClaim}
          class="icon-button modal-close"><X size={18} /></button
        >
      </header>
      {#if dialogError}<div class="form-error" role="alert">{dialogError}</div>{/if}
      <div class="claim-summary">
        <span
          ><small>{messages[$locale].paidAmount}</small><strong
            >{selected.paidAmount} {selected.paidAsset}</strong
          ></span
        ><span
          ><small>{messages[$locale].transactionId}</small><strong
            >{selected.externalTransactionId}</strong
          ></span
        >
      </div>
      <div class="evidence-list">
        <strong>{messages[$locale].evidence}</strong
        >{#if evidence.length}{#each evidence as item}<div>
              <span>{item.originalName}</span><small
                >{statusLabel(item.scanStatus, $locale)} · {(item.byteLength / 1024).toFixed(1)} KiB</small
              >
            </div>{/each}{:else}<small>{messages[$locale].noEvidence}</small>{/if}
      </div>
      {#if claimReviewable && canWrite}<label class="evidence-upload"
          >{messages[$locale].addEvidence}<input
            type="file"
            accept="image/png,image/jpeg,application/pdf"
            onchange={(event) => {
              evidenceFile = event.currentTarget.files?.[0] ?? null;
              evidenceAttempt.succeeded();
            }}
          /></label
        >{/if}{#if claimReviewable && canWrite && evidenceFile}<button
          class="secondary upload-button"
          onclick={uploadEvidence}
          disabled={saving || !reviewReason.trim()}>{messages[$locale].upload}</button
        >{/if}{#if claimReviewable}<label class="standalone-label"
          >{messages[$locale].decision}<select
            data-option-align="center"
            bind:value={decision}
            onchange={() => {
              if (decision !== 'approve') overrideAmount = false;
            }}
            ><option value="approve">{messages[$locale].approve}</option><option value="reject"
              >{messages[$locale].reject}</option
            ><option value="request_information">{messages[$locale].requestInfo}</option></select
          ></label
        >{#if canOverride && decision === 'approve'}<label class="override-check"
            ><input type="checkbox" bind:checked={overrideAmount} />{messages[$locale]
              .override}</label
          >{/if}<label class="standalone-label"
          >{messages[$locale].reviewReason}<textarea bind:value={reviewReason}></textarea></label
        >{:else}<p class="review-complete">{messages[$locale].reviewComplete}</p>{/if}
      <footer>
        <button class="secondary" disabled={saving} onclick={closeClaim}
          >{messages[$locale].close}</button
        >{#if claimReviewable}<button
            class="primary"
            onclick={review}
            disabled={saving || !reviewReason.trim()}
            >{saving ? messages[$locale].processing : messages[$locale].submitReview}</button
          >{/if}
      </footer>
    </div>
  </div>
{/if}
