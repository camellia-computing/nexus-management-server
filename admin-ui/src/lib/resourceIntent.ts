export interface ResourceIntent {
  resource: 'codes';
  accountId: string;
  licenseId: string;
}

let pending: ResourceIntent | null = null;

export function setResourceIntent(intent: ResourceIntent) {
  pending = intent;
}

export function takeResourceIntent(resource: string): ResourceIntent | null {
  if (pending?.resource !== resource) return null;
  const value = pending;
  pending = null;
  return value;
}
