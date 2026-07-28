export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
    public field?: string
  ) {
    super(message);
  }
}

export function isVersionConflict(error: unknown): error is ApiError {
  return error instanceof ApiError && error.code === 'admin_version_conflict';
}

function ambiguousMutationFailure(error: unknown): boolean {
  return (
    !(error instanceof ApiError) ||
    error.status === 408 ||
    error.status === 429 ||
    error.status >= 500
  );
}

/**
 * Owns the idempotency identity for one logical mutation. Callers supply a stable fingerprint
 * containing the endpoint, preconditions, reason and body. Network/overload failures retain the
 * identity; changing the payload or receiving a definitive 4xx creates a new attempt.
 */
export class MutationAttempt {
  #operationId = '';
  #fingerprint = '';

  operationId(fingerprint: string): string {
    if (!this.#operationId || this.#fingerprint !== fingerprint) {
      this.#operationId = crypto.randomUUID();
      this.#fingerprint = fingerprint;
    }
    return this.#operationId;
  }

  succeeded(): void {
    this.#operationId = '';
    this.#fingerprint = '';
  }

  failed(error: unknown): boolean {
    const ambiguous = ambiguousMutationFailure(error);
    if (!ambiguous) this.succeeded();
    return ambiguous;
  }
}

type StepUpHandler = () => Promise<void>;
const REQUEST_TIMEOUT_MS = 20_000;
let stepUpHandler: StepUpHandler | undefined;
let pendingStepUp: Promise<void> | undefined;
let authenticationFailureHandler: (() => void) | undefined;

export function setStepUpHandler(handler?: StepUpHandler) {
  stepUpHandler = handler;
}

export function setAuthenticationFailureHandler(handler?: () => void) {
  authenticationFailureHandler = handler;
}

async function requireStepUp() {
  if (!stepUpHandler)
    throw new ApiError(403, 'admin_step_up_required', 'Recent authentication is required');
  pendingStepUp ??= stepUpHandler().finally(() => {
    pendingStepUp = undefined;
  });
  await pendingStepUp;
}

function cookie(name: string): string | undefined {
  for (const item of document.cookie.split(';')) {
    const value = item.trim();
    const separator = value.indexOf('=');
    if (separator > 0 && value.slice(0, separator) === name) return value.slice(separator + 1);
  }
  return undefined;
}

function csrfToken(): string | undefined {
  const encoded = cookie('__Host-camellia_admin_csrf') ?? cookie('camellia_admin_csrf_development');
  if (!encoded) return undefined;
  try {
    return decodeURIComponent(encoded);
  } catch {
    return undefined;
  }
}

export interface ApiRequestInit extends RequestInit {
  mutation?: boolean;
  reason?: string;
  csrf?: boolean;
  operationId?: string;
}

export async function api<T>(path: string, init: ApiRequestInit = {}): Promise<T> {
  return request<T>(
    path,
    init,
    init.mutation ? (init.operationId ?? crypto.randomUUID()) : undefined,
    true
  );
}

async function request<T>(
  path: string,
  init: ApiRequestInit,
  operationId: string | undefined,
  allowStepUp: boolean
): Promise<T> {
  const { mutation, reason, csrf, operationId: _operationId, ...requestInit } = init;
  const headers = new Headers(init.headers);
  if (init.body && !(init.body instanceof FormData))
    headers.set('content-type', 'application/json');
  if (mutation) {
    headers.set('idempotency-key', operationId!);
  }
  if (mutation || csrf) {
    const csrf = csrfToken();
    if (csrf) headers.set('x-csrf-token', csrf);
  }
  if (reason) headers.set('x-admin-reason', reason);
  const timeout = AbortSignal.timeout(REQUEST_TIMEOUT_MS);
  const signal = requestInit.signal ? AbortSignal.any([requestInit.signal, timeout]) : timeout;
  let response: Response;
  try {
    response = await fetch(`/api/v1${path}`, {
      ...requestInit,
      headers,
      signal,
      credentials: 'same-origin'
    });
  } catch (error) {
    if (timeout.aborted && !requestInit.signal?.aborted) {
      throw new ApiError(408, 'request_timeout', 'The request timed out; retry the operation');
    }
    throw error;
  }
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    if (allowStepUp && body.code === 'admin_step_up_required') {
      await requireStepUp();
      return request<T>(path, init, operationId, false);
    }
    if (response.status === 401 && body.code === 'admin_authentication_required') {
      authenticationFailureHandler?.();
    }
    throw new ApiError(
      response.status,
      body.code ?? 'request_failed',
      body.message ?? response.statusText,
      typeof body.field === 'string' ? body.field : undefined
    );
  }
  if (response.status === 204) return undefined as T;
  return response.json() as Promise<T>;
}

export function stepUp(password: string, totp: string) {
  return api<{ elevatedUntil: number }>('/auth/step-up', {
    method: 'POST',
    csrf: true,
    body: JSON.stringify({ password, totp })
  });
}

export function login(username: string, password: string, totp: string) {
  return api<{ user: AdminUser; expiresAt: number }>('/auth/login', {
    method: 'POST',
    body: JSON.stringify({ username, password, totp })
  });
}

export interface EnrollmentChallenge {
  username: string;
  displayName: string;
  totpSecret: string;
  otpauthUri: string;
  expiresAt: number;
}

export interface RecoveryEnrollment {
  token: string;
  challenge: EnrollmentChallenge;
}

export function beginRecovery(username: string, password: string, recoveryCode: string) {
  return api<RecoveryEnrollment>('/auth/recovery', {
    method: 'POST',
    body: JSON.stringify({ username, password, recoveryCode })
  });
}

export interface AdminUser {
  id: string;
  username: string;
  displayName: string;
  roles: string[];
  status: string;
  rowVersion: number;
}

export interface AdminUserPage {
  items: AdminUser[];
  nextCursor?: string;
}

export interface SecretDeliveryTicket {
  id: string;
  claimToken: string;
  expiresAt: number;
}

export interface AdminEnrollmentProvisioning {
  user: AdminUser;
  delivery: SecretDeliveryTicket;
  acknowledgementRequired: boolean;
}

export interface SessionInfo {
  user: AdminUser;
  permissions: string[];
  expiresAt: number;
  elevatedUntil: number;
  serverVersion: string;
}
