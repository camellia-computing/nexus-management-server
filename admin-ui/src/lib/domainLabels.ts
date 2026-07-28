import type { Locale } from './i18n';

type Label = { zh: string; en: string };

const statuses: Record<string, Label> = {
  active: { zh: '有效', en: 'Active' },
  ready: { zh: '就绪', en: 'Ready' },
  succeeded: { zh: '成功', en: 'Succeeded' },
  verified: { zh: '已验证', en: 'Verified' },
  paid: { zh: '已付款', en: 'Paid' },
  clean: { zh: '安全', en: 'Clean' },
  pending: { zh: '待处理', en: 'Pending' },
  pending_activation: { zh: '待激活', en: 'Pending activation' },
  suspended: { zh: '已暂停', en: 'Suspended' },
  past_due: { zh: '逾期', en: 'Past due' },
  submitted: { zh: '已提交', en: 'Submitted' },
  under_review: { zh: '审核中', en: 'Under review' },
  needs_information: { zh: '待补充信息', en: 'Needs information' },
  open: { zh: '开放', en: 'Open' },
  overdue: { zh: '已逾期', en: 'Overdue' },
  queued: { zh: '排队中', en: 'Queued' },
  running: { zh: '运行中', en: 'Running' },
  invited: { zh: '已邀请', en: 'Invited' },
  cancel_requested: { zh: '取消中', en: 'Cancel requested' },
  disabled: { zh: '已禁用', en: 'Disabled' },
  revoked: { zh: '已撤销', en: 'Revoked' },
  rejected: { zh: '已拒绝', en: 'Rejected' },
  failed: { zh: '失败', en: 'Failed' },
  partial_failed: { zh: '部分失败', en: 'Partially failed' },
  denied: { zh: '已拒绝', en: 'Denied' },
  denylisted: { zh: '已封禁', en: 'Denylisted' },
  canceled: { zh: '已取消', en: 'Canceled' },
  removed: { zh: '已移除', en: 'Removed' },
  suspicious: { zh: '可疑', en: 'Suspicious' },
  consumed: { zh: '已使用', en: 'Consumed' },
  expired: { zh: '已过期', en: 'Expired' },
  withdrawn: { zh: '已撤回', en: 'Withdrawn' },
  void: { zh: '已作废', en: 'Void' },
  refunded: { zh: '已退款', en: 'Refunded' },
  quarantined: { zh: '已隔离', en: 'Quarantined' },
  retry: { zh: '等待重试', en: 'Retrying' },
  in_flight: { zh: '投递中', en: 'In flight' },
  delivered: { zh: '已投递', en: 'Delivered' },
  dead: { zh: '已终止', en: 'Dead' },
  acknowledged: { zh: '已确认', en: 'Acknowledged' },
  resolved: { zh: '已解决', en: 'Resolved' }
};

const plans: Record<string, Label> = {
  free: { zh: 'Free', en: 'Free' },
  pro: { zh: 'Pro', en: 'Pro' },
  team: { zh: 'Team', en: 'Team' }
};

const actions: Record<string, Label> = {
  revoke: { zh: '撤销', en: 'Revoke' },
  expire: { zh: '立即过期', en: 'Expire now' },
  restore: { zh: '恢复', en: 'Restore' }
};

const jobKinds: Record<string, Label> = {
  account_set_state: { zh: '变更账户状态', en: 'Set account state' },
  license_set_status: { zh: '变更授权状态', en: 'Set license status' },
  activation_code_revoke: { zh: '撤销激活码', en: 'Revoke activation codes' },
  activation_code_expire: { zh: '使激活码过期', en: 'Expire activation codes' },
  device_set_state: { zh: '变更设备状态', en: 'Set device state' }
};

const adminRoles: Record<string, Label> = {
  platform_owner: { zh: '平台所有者', en: 'Platform Owner' },
  licensing_admin: { zh: '授权管理员', en: 'Licensing Admin' },
  security_admin: { zh: '安全管理员', en: 'Security Admin' },
  billing_admin: { zh: '账单管理员', en: 'Billing Admin' },
  support_operator: { zh: '支持操作员', en: 'Support Operator' },
  auditor: { zh: '审计员', en: 'Auditor' }
};

const teamRoles: Record<string, Label> = {
  owner: { zh: '所有者', en: 'Owner' },
  admin: { zh: '管理员', en: 'Admin' },
  billing: { zh: '账单管理员', en: 'Billing' },
  operator: { zh: '操作员', en: 'Operator' },
  auditor: { zh: '审计员', en: 'Auditor' },
  viewer: { zh: '查看者', en: 'Viewer' }
};

const enabled: Record<string, Label> = {
  true: { zh: '已启用', en: 'Enabled' },
  false: { zh: '已停用', en: 'Disabled' }
};

function label(value: string, locale: Locale, dictionary: Record<string, Label>) {
  return dictionary[value]?.[locale] ?? value;
}

export function statusLabel(value: string, locale: Locale) {
  return label(value, locale, statuses);
}

export function planLabel(value: string, locale: Locale) {
  return label(value, locale, plans);
}

export function actionLabel(value: string, locale: Locale) {
  return label(value, locale, actions);
}

export function jobKindLabel(value: string, locale: Locale) {
  return label(value, locale, jobKinds);
}

export function adminRoleLabel(value: string, locale: Locale) {
  return label(value, locale, adminRoles);
}

export function teamRoleLabel(value: string, locale: Locale) {
  return label(value, locale, teamRoles);
}

export function enabledLabel(value: unknown, locale: Locale) {
  const key = value === true ? 'true' : value === false ? 'false' : String(value);
  return label(key, locale, enabled);
}
