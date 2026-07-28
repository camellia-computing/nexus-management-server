import { writable } from 'svelte/store';
import { readPreference, writePreference } from './preferences';

export type Locale = 'zh' | 'en';
const storedLocale = readPreference('admin-locale');
export const locale = writable<Locale>(storedLocale === 'en' ? 'en' : 'zh');

export const copy = {
  zh: {
    product: 'Camellia Console',
    console: '控制台',
    control: '授权与商业运营控制台',
    overview: '运营总览',
    accounts: '账户',
    licenses: '授权',
    codes: '激活码',
    devices: '设备',
    team: 'Team 工作区',
    billing: '账单与付款',
    jobs: '批量任务',
    audit: '审计',
    administrators: '管理员身份',
    system: '系统状态',
    search: '搜索',
    refresh: '刷新',
    create: '新建',
    signOut: '退出',
    appearance: '外观',
    language: '语言',
    fontSize: '字号',
    standardFont: '标准',
    largeFont: '大',
    extraLargeFont: '特大',
    light: '浅色',
    dark: '深色',
    systemTheme: '跟随系统',
    allHealthy: '所有核心服务正常',
    loading: '正在同步数据…',
    empty: '暂无符合条件的数据',
    retry: '重试',
    close: '关闭',
    reason: '操作原因',
    confirm: '确认操作',
    cancel: '取消',
    live: '实时',
    operator: '当前管理员',
    manage: '管理',
    export: '导出',
    save: '保存',
    remove: '移除',
    revoke: '撤销',
    done: '完成',
    previous: '上一页',
    next: '下一页',
    allStatuses: '全部状态',
    emptyHint: '调整筛选条件或刷新数据后重试',
    secure: '私有控制面',
    needsAttention: '需要处理',
    pendingPayments: '待审核付款',
    openInvoices: '未结账单',
    activeLicenses: '有效授权',
    activeDevices: '活跃设备',
    totalAccounts: '账户总数'
  },
  en: {
    product: 'Camellia Console',
    console: 'Console',
    control: 'Licensing & commercial operations',
    overview: 'Overview',
    accounts: 'Accounts',
    licenses: 'Licenses',
    codes: 'Activation codes',
    devices: 'Devices',
    team: 'Team workspaces',
    billing: 'Billing & payments',
    jobs: 'Bulk jobs',
    audit: 'Audit',
    administrators: 'Administrators',
    system: 'System status',
    search: 'Search',
    refresh: 'Refresh',
    create: 'Create',
    signOut: 'Sign out',
    appearance: 'Appearance',
    language: 'Language',
    fontSize: 'Text size',
    standardFont: 'Standard',
    largeFont: 'Large',
    extraLargeFont: 'Extra large',
    light: 'Light',
    dark: 'Dark',
    systemTheme: 'System',
    allHealthy: 'All core services healthy',
    loading: 'Synchronizing data…',
    empty: 'No matching records',
    retry: 'Retry',
    close: 'Close',
    reason: 'Operation reason',
    confirm: 'Confirm',
    cancel: 'Cancel',
    live: 'Live',
    operator: 'Signed in as',
    manage: 'Manage',
    export: 'Export',
    save: 'Save',
    remove: 'Remove',
    revoke: 'Revoke',
    done: 'Done',
    previous: 'Previous',
    next: 'Next',
    allStatuses: 'All statuses',
    emptyHint: 'Adjust the filters or refresh the data and try again',
    secure: 'Private control plane',
    needsAttention: 'Needs attention',
    pendingPayments: 'Payments to review',
    openInvoices: 'Open invoices',
    activeLicenses: 'Active licenses',
    activeDevices: 'Active devices',
    totalAccounts: 'Accounts'
  }
} as const;

export function setLocale(value: Locale) {
  writePreference('admin-locale', value);
  locale.set(value);
  document.documentElement.lang = value === 'zh' ? 'zh-CN' : 'en';
}

export function defineCopy<const Zh extends Record<string, string>>(
  zh: Zh,
  en: { [Key in keyof Zh]: string }
) {
  return { zh, en } as const;
}

export function localeTag(value: Locale): string {
  return value === 'zh' ? 'zh-CN' : 'en';
}
