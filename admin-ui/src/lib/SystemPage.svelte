<script lang="ts">
  import { onMount } from 'svelte';
  import {
    CheckCircle2,
    Clock3,
    Database,
    HardDrive,
    RefreshCw,
    Server,
    ShieldCheck
  } from '@lucide/svelte';
  import { api } from './api';
  import type { AdminSystemStatus } from './admin-contracts';
  import { defineCopy, locale, localeTag } from './i18n';

  const messages = defineCopy(
    {
      breadcrumb: '控制台 / 基础设施',
      title: '系统状态',
      description: '控制面依赖、可信时间与对象存储的运行状态。',
      recheck: '重新检查',
      checkFailed: '状态检查失败',
      unavailable: '无法确认控制面状态',
      checkingStatus: '正在检查控制面',
      checkingDetail: '正在验证数据库、可信时间与对象存储。',
      healthy: '控制面运行正常',
      healthyDetail: '最近一次检查未发现阻断运营的问题。',
      version: '版本',
      trustedTime: '可信时间',
      objectStorage: '对象存储',
      adminSession: '管理员会话',
      runtime: '运行信息',
      runtimeDetail: '用于部署检查与问题定位',
      adminOrigin: '管理端源',
      startedAt: '启动时间',
      serverTime: '服务端时间',
      storedObjects: '已存储对象',
      storageUsage: '存储使用',
      checking: '检查中',
      ready: '正常',
      filesystem: '文件系统',
      database: '数据库',
      s3: 'S3 对象存储'
    },
    {
      breadcrumb: 'Console / Infrastructure',
      title: 'System status',
      description: 'Runtime state of control-plane dependencies, trusted time, and object storage.',
      recheck: 'Check again',
      checkFailed: 'Status check failed',
      unavailable: 'Control-plane status unavailable',
      checkingStatus: 'Checking the control plane',
      checkingDetail: 'Verifying the database, trusted time, and object storage.',
      healthy: 'Control plane is healthy',
      healthyDetail: 'The latest check found no issues blocking operations.',
      version: 'Version',
      trustedTime: 'Trusted time',
      objectStorage: 'Object storage',
      adminSession: 'Administrator session',
      runtime: 'Runtime information',
      runtimeDetail: 'Deployment verification and troubleshooting details',
      adminOrigin: 'Admin origin',
      startedAt: 'Started at',
      serverTime: 'Server time',
      storedObjects: 'Stored objects',
      storageUsage: 'Storage usage',
      checking: 'Checking',
      ready: 'Ready',
      filesystem: 'Filesystem',
      database: 'Database',
      s3: 'S3 object storage'
    }
  );

  let data = $state<AdminSystemStatus | null>(null);
  let loading = $state(true);
  let error = $state('');
  let generation = 0;

  function readinessLabel(value: AdminSystemStatus['status'] | undefined) {
    return value === 'ready' ? messages[$locale].ready : messages[$locale].checking;
  }

  function storageLabel(value: AdminSystemStatus['objectStorage']['backend'] | undefined) {
    return value ? messages[$locale][value] : messages[$locale].checking;
  }

  async function load() {
    const current = ++generation;
    loading = true;
    error = '';
    try {
      const value = await api<AdminSystemStatus>('/system/status');
      if (current === generation) data = value;
    } catch (reason) {
      if (current === generation) {
        data = null;
        error = reason instanceof Error ? reason.message : messages[$locale].checkFailed;
      }
    } finally {
      if (current === generation) loading = false;
    }
  }

  onMount(() => {
    void load();
  });
</script>

<div class="page-heading">
  <div>
    <span class="breadcrumb">{messages[$locale].breadcrumb}</span>
    <h1>{messages[$locale].title}</h1>
    <p>{messages[$locale].description}</p>
  </div>
  <button class="secondary" onclick={load} disabled={loading}
    ><RefreshCw class={loading ? 'spin' : ''} size={17} />{messages[$locale].recheck}</button
  >
</div>
<section
  class:error={Boolean(error)}
  class:loading={loading && !error}
  class="system-banner"
  aria-busy={loading}
  aria-live="polite"
>
  <span
    >{#if error}<Server size={24} />{:else if loading}<Clock3 size={24} />{:else}<CheckCircle2
        size={24}
      />{/if}</span
  >
  <div>
    <h2>
      {error
        ? messages[$locale].unavailable
        : loading
          ? messages[$locale].checkingStatus
          : messages[$locale].healthy}
    </h2>
    <p>
      {error || (loading ? messages[$locale].checkingDetail : messages[$locale].healthyDetail)}
    </p>
  </div>
  <small>{messages[$locale].version} {data?.version ?? '—'}</small>
</section>
<section class="system-grid">
  <article class:pending={!data} class="panel system-card">
    <span><Database size={20} /></span>
    <div>
      <small>PostgreSQL</small><strong>{readinessLabel(data?.database)}</strong>
    </div>
    <i></i>
  </article>
  <article class:pending={!data} class="panel system-card">
    <span><Clock3 size={20} /></span>
    <div>
      <small>{messages[$locale].trustedTime}</small><strong
        >{readinessLabel(data?.timeAuthority)}</strong
      >
    </div>
    <i></i>
  </article>
  <article class:pending={!data} class="panel system-card">
    <span><HardDrive size={20} /></span>
    <div>
      <small>{messages[$locale].objectStorage}</small><strong
        >{storageLabel(data?.objectStorage.backend)}</strong
      >
    </div>
    <i></i>
  </article>
  <article class:pending={!data} class="panel system-card">
    <span><ShieldCheck size={20} /></span>
    <div>
      <small>{messages[$locale].adminSession}</small><strong>{readinessLabel(data?.status)}</strong>
    </div>
    <i></i>
  </article>
</section>
<section class="panel details-panel">
  <div class="panel-head">
    <div>
      <h2>{messages[$locale].runtime}</h2>
      <p>{messages[$locale].runtimeDetail}</p>
    </div>
  </div>
  <dl>
    <div>
      <dt>{messages[$locale].adminOrigin}</dt>
      <dd>{data?.adminOrigin ?? '—'}</dd>
    </div>
    <div>
      <dt>{messages[$locale].startedAt}</dt>
      <dd>
        {data?.startedAt ? new Date(data.startedAt * 1000).toLocaleString(localeTag($locale)) : '—'}
      </dd>
    </div>
    <div>
      <dt>{messages[$locale].serverTime}</dt>
      <dd>
        {data?.serverUnix
          ? new Date(data.serverUnix * 1000).toLocaleString(localeTag($locale))
          : '—'}
      </dd>
    </div>
    <div>
      <dt>{messages[$locale].storedObjects}</dt>
      <dd>{data?.objectStorage.objectCount ?? '—'}</dd>
    </div>
    <div>
      <dt>{messages[$locale].storageUsage}</dt>
      <dd>{data?.objectStorage ? `${(data.objectStorage.usageRatio * 100).toFixed(2)}%` : '—'}</dd>
    </div>
  </dl>
</section>
