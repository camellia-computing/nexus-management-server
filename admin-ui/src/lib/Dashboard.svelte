<script lang="ts">
  import { onMount } from 'svelte';
  import {
    AlertTriangle,
    ArrowUpRight,
    Building2,
    CreditCard,
    Laptop,
    ReceiptText,
    ShieldCheck,
    Sparkles
  } from '@lucide/svelte';
  import { api } from './api';
  import type { AdminDashboard } from './admin-contracts';
  import { copy, defineCopy, locale, localeTag } from './i18n';

  let { onNavigate }: { onNavigate: (id: string) => void } = $props();
  const messages = defineCopy(
    {
      operationsCenter: '运营中心',
      description: '授权业务的实时脉搏、风险信号与待办事项。',
      syncFailed: '同步失败',
      synchronized: '数据已同步',
      synchronizing: '正在同步',
      lastSuccess: '上次成功',
      refresh: '点击重试',
      lessThanMinuteAgo: '不足 1 分钟前',
      minutesAgo: '{count} 分钟前',
      currentStatus: '当前状态',
      currentScale: '当前业务规模',
      scaleDetail: '来自控制面实时聚合，不包含推测数据',
      attentionOrder: '按风险与时效排序',
      paymentCount: '{count} 笔付款等待审核',
      paymentDetail: '进入付款审核队列',
      riskyCount: '{count} 台设备存在风险',
      riskyDetail: '已撤销或标记为可疑',
      invoiceCount: '{count} 张账单尚未结清',
      invoiceDetail: '查看开放或逾期账单',
      auditAndJobs: '审计与任务',
      auditDetail: '从不可变记录追踪控制面操作',
      viewAudit: '查看审计',
      auditTrail: '安全审计轨迹',
      auditTrailDetail: '检查授权、付款与管理员操作',
      bulkJobs: '批量任务',
      bulkJobsDetail: '查看进度、失败项与取消状态',
      teamWorkspace: 'Team 工作区',
      teamDetail: '核对席位、角色与邀请'
    },
    {
      operationsCenter: 'Operations center',
      description:
        'A live view of licensing operations, risk signals, and work requiring attention.',
      syncFailed: 'Sync failed',
      synchronized: 'Data synchronized',
      synchronizing: 'Synchronizing',
      lastSuccess: 'Last success',
      refresh: 'Click to retry',
      lessThanMinuteAgo: 'Less than 1 min ago',
      minutesAgo: '{count} min ago',
      currentStatus: 'Current status',
      currentScale: 'Current business scale',
      scaleDetail: 'Live control-plane aggregates with no estimated data',
      attentionOrder: 'Ordered by risk and urgency',
      paymentCount: '{count} payments awaiting review',
      paymentDetail: 'Open the payment review queue',
      riskyCount: '{count} devices require attention',
      riskyDetail: 'Revoked or marked suspicious',
      invoiceCount: '{count} invoices remain open',
      invoiceDetail: 'Review open and overdue invoices',
      auditAndJobs: 'Audit and jobs',
      auditDetail: 'Trace control-plane actions through immutable records',
      viewAudit: 'View audit',
      auditTrail: 'Security audit trail',
      auditTrailDetail: 'Review licensing, payment, and administrator actions',
      bulkJobs: 'Bulk jobs',
      bulkJobsDetail: 'Review progress, failures, and cancellations',
      teamWorkspace: 'Team workspaces',
      teamDetail: 'Review seats, roles, and invitations'
    }
  );
  const cards = [
    ['accounts', 'totalAccounts', Building2, 'blue'],
    ['activeLicenses', 'activeLicenses', ShieldCheck, 'violet'],
    ['activeDevices', 'activeDevices', Laptop, 'cyan'],
    ['pendingPayments', 'pendingPayments', CreditCard, 'amber']
  ] as const;

  let data = $state<Partial<AdminDashboard>>({});
  let loading = $state(true);
  let failed = $state(false);
  let generation = 0;
  let receivedAt = $state(0);
  let now = $state(Date.now());
  let largestMetric = $derived(Math.max(1, ...cards.map(([key]) => data[key] ?? 0)));
  const countText = (template: string, count: number) =>
    template.replace('{count}', count.toLocaleString(localeTag($locale)));

  function relativeSyncTime() {
    if (!receivedAt) return messages[$locale].refresh;
    const minutes = Math.floor(Math.max(0, now - receivedAt) / 60_000);
    return minutes < 1
      ? messages[$locale].lessThanMinuteAgo
      : messages[$locale].minutesAgo.replace('{count}', minutes.toLocaleString(localeTag($locale)));
  }

  function synchronizedAt() {
    const timestamp = data.generatedAt ? data.generatedAt * 1000 : receivedAt;
    if (!timestamp) return messages[$locale].refresh;
    return new Date(timestamp).toLocaleTimeString(localeTag($locale), {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    });
  }

  async function load() {
    if (loading && generation > 0) return;
    const current = ++generation;
    loading = true;
    try {
      const value = await api<AdminDashboard>('/dashboard');
      if (current === generation) {
        data = value;
        receivedAt = Date.now();
        now = receivedAt;
        failed = false;
      }
    } catch {
      if (current === generation) failed = true;
    } finally {
      if (current === generation) loading = false;
    }
  }

  onMount(() => {
    void load();
    const refreshTimer = window.setInterval(() => {
      if (document.visibilityState === 'visible') void load();
    }, 60_000);
    const clockTimer = window.setInterval(() => (now = Date.now()), 10_000);
    const onVisibility = () => {
      if (
        document.visibilityState === 'visible' &&
        receivedAt > 0 &&
        Date.now() - receivedAt >= 60_000
      )
        void load();
    };
    document.addEventListener('visibilitychange', onVisibility);
    return () => {
      generation++;
      clearInterval(refreshTimer);
      clearInterval(clockTimer);
      document.removeEventListener('visibilitychange', onVisibility);
    };
  });
</script>

<div class="page-heading hero-heading">
  <div>
    <span class="eyebrow"
      ><Sparkles size={15} /> {messages[$locale].operationsCenter.toUpperCase()}</span
    >
    <h1>{copy[$locale].overview}</h1>
    <p>{messages[$locale].description}</p>
  </div>
  <button
    class:failed
    class="sync-state"
    onclick={load}
    disabled={loading}
    title={data.generatedAt
      ? new Date(data.generatedAt * 1000).toLocaleString(localeTag($locale))
      : undefined}
  >
    <i></i><span
      >{loading
        ? messages[$locale].synchronizing
        : failed
          ? messages[$locale].syncFailed
          : messages[$locale].synchronized}</span
    ><strong
      >{failed && receivedAt
        ? `${messages[$locale].lastSuccess} · ${synchronizedAt()} · ${relativeSyncTime()}`
        : failed
          ? messages[$locale].refresh
          : `${messages[$locale].lastSuccess} · ${synchronizedAt()}`}</strong
    >
  </button>
</div>
<section class="metric-grid">
  {#each cards as [key, label, Icon, tone]}
    <article class="metric-card {tone}">
      <div class="metric-top">
        <span><Icon size={20} /></span><small>{messages[$locale].currentStatus}</small>
      </div>
      <strong>{loading ? '—' : (data[key] ?? 0).toLocaleString(localeTag($locale))}</strong>
      <p>{copy[$locale][label]}</p>
      <div class="spark-bars" aria-hidden="true">
        {#each [38, 55, 47, 68, 58, 81, 73, 92, 79, 96] as height}<i style={`height:${height}%`}
          ></i>{/each}
      </div>
    </article>
  {/each}
</section>
<section class="dashboard-grid">
  <article class="panel activity-panel">
    <div class="panel-head">
      <div>
        <h2>{messages[$locale].currentScale}</h2>
        <p>{messages[$locale].scaleDetail}</p>
      </div>
      <span class="live-label">{copy[$locale].live.toUpperCase()}</span>
    </div>
    <div class="scale-chart">
      {#each cards as [key, label, Icon, tone]}<div class="scale-row">
          <span class="scale-icon {tone}"><Icon size={17} /></span>
          <div>
            <header>
              <span>{copy[$locale][label]}</span><strong
                >{loading ? '—' : (data[key] ?? 0).toLocaleString(localeTag($locale))}</strong
              >
            </header>
            <i
              ><b
                style={`width:${loading ? 0 : Math.max(2, ((data[key] ?? 0) / largestMetric) * 100)}%`}
              ></b></i
            >
          </div>
        </div>{/each}
    </div>
  </article>
  <article class="panel attention-panel">
    <div class="panel-head">
      <div>
        <h2>{copy[$locale].needsAttention}</h2>
        <p>{messages[$locale].attentionOrder}</p>
      </div>
      <span class="count-badge"
        >{(data.pendingPayments ?? 0) + (data.openInvoices ?? 0) + (data.riskyDevices ?? 0)}</span
      >
    </div>
    <div class="attention-list">
      <button onclick={() => onNavigate('billing')}
        ><span class="attention-icon amber"><ReceiptText size={18} /></span>
        <div>
          <strong>{countText(messages[$locale].paymentCount, data.pendingPayments ?? 0)}</strong
          ><small>{messages[$locale].paymentDetail}</small>
        </div>
        <ArrowUpRight size={17} /></button
      ><button onclick={() => onNavigate('devices')}
        ><span class="attention-icon red"><AlertTriangle size={18} /></span>
        <div>
          <strong>{countText(messages[$locale].riskyCount, data.riskyDevices ?? 0)}</strong><small
            >{messages[$locale].riskyDetail}</small
          >
        </div>
        <ArrowUpRight size={17} /></button
      ><button onclick={() => onNavigate('billing')}
        ><span class="attention-icon blue"><CreditCard size={18} /></span>
        <div>
          <strong>{countText(messages[$locale].invoiceCount, data.openInvoices ?? 0)}</strong><small
            >{messages[$locale].invoiceDetail}</small
          >
        </div>
        <ArrowUpRight size={17} /></button
      >
    </div>
  </article>
  <article class="panel recent-panel">
    <div class="panel-head">
      <div>
        <h2>{messages[$locale].auditAndJobs}</h2>
        <p>{messages[$locale].auditDetail}</p>
      </div>
      <button class="text-button" onclick={() => onNavigate('audit')}
        >{messages[$locale].viewAudit} <ArrowUpRight size={15} /></button
      >
    </div>
    <div class="timeline">
      <button onclick={() => onNavigate('audit')}
        ><i class="green"></i><span
          ><strong>{messages[$locale].auditTrail}</strong><small
            >{messages[$locale].auditTrailDetail}</small
          ></span
        ><ArrowUpRight size={17} /></button
      ><button onclick={() => onNavigate('jobs')}
        ><i class="violet"></i><span
          ><strong>{messages[$locale].bulkJobs}</strong><small
            >{messages[$locale].bulkJobsDetail}</small
          ></span
        ><ArrowUpRight size={17} /></button
      ><button onclick={() => onNavigate('team')}
        ><i class="blue"></i><span
          ><strong>{messages[$locale].teamWorkspace}</strong><small
            >{messages[$locale].teamDetail}</small
          ></span
        ><ArrowUpRight size={17} /></button
      >
    </div>
  </article>
</section>
