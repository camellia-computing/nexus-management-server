import { createHmac, randomUUID } from 'node:crypto';
import AxeBuilder from '@axe-core/playwright';
import {
  expect,
  test,
  type APIResponse,
  type Browser,
  type Page,
  type Request
} from '@playwright/test';

const credentials = {
  baseUrl: requiredEnvironment('CAMELLIA_NEXUS_ADMIN_E2E_BASE_URL'),
  username: requiredEnvironment('CAMELLIA_NEXUS_ADMIN_E2E_USERNAME'),
  password: requiredEnvironment('CAMELLIA_NEXUS_ADMIN_E2E_PASSWORD'),
  totpSecret: requiredEnvironment('CAMELLIA_NEXUS_ADMIN_E2E_TOTP_SECRET'),
  displayName: requiredEnvironment('CAMELLIA_NEXUS_ADMIN_E2E_DISPLAY_NAME'),
  sessionCookieName: requiredEnvironment('CAMELLIA_NEXUS_ADMIN_E2E_SESSION_COOKIE_NAME'),
  sessionCookieValue: requiredEnvironment('CAMELLIA_NEXUS_ADMIN_E2E_SESSION_COOKIE_VALUE'),
  csrfCookieName: requiredEnvironment('CAMELLIA_NEXUS_ADMIN_E2E_CSRF_COOKIE_NAME'),
  csrfCookieValue: requiredEnvironment('CAMELLIA_NEXUS_ADMIN_E2E_CSRF_COOKIE_VALUE'),
  accountId: requiredEnvironment('CAMELLIA_NEXUS_ADMIN_E2E_ACCOUNT_ID'),
  licenseId: requiredEnvironment('CAMELLIA_NEXUS_ADMIN_E2E_LICENSE_ID'),
  billingOfferId: requiredEnvironment('CAMELLIA_NEXUS_ADMIN_E2E_BILLING_OFFER_ID'),
  paymentClaimId: requiredEnvironment('CAMELLIA_NEXUS_ADMIN_E2E_PAYMENT_CLAIM_ID'),
  evidencePath: requiredEnvironment('CAMELLIA_NEXUS_ADMIN_E2E_EVIDENCE_PATH')
};

const secretRedactionUrl = new URL(
  '/.well-known/camellia-admin-e2e-secret-redaction.css',
  credentials.baseUrl
).href;
const secretRedactionStyles = `
  .code-delivery code,
  .delivery-secret code,
  .secret-box code,
  .recovery-code-list code,
  .enrollment-card textarea,
  input[type="password"],
  input[autocomplete="current-password"],
  input[autocomplete="new-password"],
  input[autocomplete="one-time-code"] {
    filter: blur(8px) !important;
    user-select: none !important;
  }
`;
const secretRedactionPages = new WeakSet<Page>();

let lastOwnerTotpCounter = Number(
  requiredEnvironment('CAMELLIA_NEXUS_ADMIN_E2E_LAST_TOTP_COUNTER')
);
if (!Number.isSafeInteger(lastOwnerTotpCounter) || lastOwnerTotpCounter < 0) {
  throw new Error('CAMELLIA_NEXUS_ADMIN_E2E_LAST_TOTP_COUNTER must be a non-negative integer');
}

function requiredEnvironment(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required for live Admin UI tests`);
  return value;
}

function decodeBase32(value: string): Buffer {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const normalized = value.toUpperCase().replace(/=+$/u, '').replaceAll(/\s+/gu, '');
  let bits = '';
  for (const character of normalized) {
    const index = alphabet.indexOf(character);
    if (index < 0) throw new Error('The test TOTP secret is not valid Base32');
    bits += index.toString(2).padStart(5, '0');
  }
  return Buffer.from(
    Array.from({ length: Math.floor(bits.length / 8) }, (_, index) =>
      Number.parseInt(bits.slice(index * 8, index * 8 + 8), 2)
    )
  );
}

function totpForCounter(secret: string, counter: number): string {
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(BigInt(counter));
  const digest = createHmac('sha1', decodeBase32(secret)).update(message).digest();
  const offset = digest.at(-1)! & 0x0f;
  const value = (digest.readUInt32BE(offset) & 0x7fff_ffff) % 1_000_000;
  return value.toString().padStart(6, '0');
}

async function unusedOwnerTotp(): Promise<string> {
  let counter = Math.floor(Date.now() / 30_000);
  while (counter <= lastOwnerTotpCounter) {
    await new Promise((resolve) =>
      setTimeout(resolve, Math.min(500, 30_000 - (Date.now() % 30_000) + 50))
    );
    counter = Math.floor(Date.now() / 30_000);
  }
  lastOwnerTotpCounter = counter;
  return totpForCounter(credentials.totpSecret, counter);
}

async function installSecretRedaction(page: Page) {
  if (!secretRedactionPages.has(page)) {
    await page.route(secretRedactionUrl, (route) =>
      route.fulfill({
        status: 200,
        contentType: 'text/css; charset=utf-8',
        body: secretRedactionStyles
      })
    );
    secretRedactionPages.add(page);
  }
  await page.evaluate(
    (url) =>
      new Promise<void>((resolve, reject) => {
        const link = document.createElement('link');
        link.rel = 'stylesheet';
        link.href = url;
        link.addEventListener('load', () => resolve(), { once: true });
        link.addEventListener('error', () => reject(new Error('secret redaction failed to load')), {
          once: true
        });
        document.head.append(link);
      }),
    secretRedactionUrl
  );
}

async function signIn(page: Page, username: string, password: string, totp: string) {
  await page.goto('/');
  await installSecretRedaction(page);
  await expect(page.getByRole('heading', { name: 'Welcome back' })).toBeVisible();
  await page.getByLabel('Administrator account').fill(username);
  await page.getByLabel('Password', { exact: true }).fill(password);
  await page.getByLabel('Two-factor code').fill(totp);
  await page.getByRole('button', { name: 'Sign in securely' }).click();
  await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible();
}

async function establishExpiredSession(page: Page) {
  await page.context().addCookies([
    {
      name: credentials.sessionCookieName,
      value: credentials.sessionCookieValue,
      url: credentials.baseUrl,
      httpOnly: true,
      sameSite: 'Strict'
    },
    {
      name: credentials.csrfCookieName,
      value: credentials.csrfCookieValue,
      url: credentials.baseUrl,
      sameSite: 'Strict'
    }
  ]);
  await page.goto('/');
  await installSecretRedaction(page);
  await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible();
}

async function navigate(page: Page, destination: string, heading = destination) {
  await page.getByRole('button', { name: destination, exact: true }).click();
  await expect(page.getByRole('heading', { name: heading, exact: true })).toBeVisible();
}

async function expectNoHorizontalOverflow(page: Page) {
  const overflow = await page.evaluate(() => ({
    document: document.documentElement.scrollWidth - document.documentElement.clientWidth,
    body: document.body.scrollWidth - document.body.clientWidth
  }));
  expect(overflow.document).toBeLessThanOrEqual(1);
  expect(overflow.body).toBeLessThanOrEqual(1);
}

async function expectAccessible(page: Page) {
  const result = await new AxeBuilder({ page })
    .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'])
    .analyze();
  expect(
    result.violations.map(({ id, impact, nodes }) => ({
      id,
      impact,
      targets: nodes.map((node) => node.target)
    }))
  ).toEqual([]);
}

function isApiRequest(request: Request, method: string, path: string) {
  return request.method() === method && new URL(request.url()).pathname === `/api/v1${path}`;
}

async function adminRequest(
  page: Page,
  method: 'GET' | 'POST',
  path: string,
  data?: unknown,
  headers: Record<string, string> = {}
): Promise<APIResponse> {
  const requestHeaders: Record<string, string> = { ...headers };
  if (method !== 'GET') {
    const cookies = await page.context().cookies(credentials.baseUrl);
    const csrf = cookies.find((cookie) => cookie.name === credentials.csrfCookieName);
    if (!csrf) throw new Error('The Admin CSRF cookie is missing');
    requestHeaders.Origin = credentials.baseUrl;
    requestHeaders['X-CSRF-Token'] = csrf.value;
  }
  return page.request.fetch(`${credentials.baseUrl}/api/v1${path}`, {
    method,
    data,
    headers: requestHeaders
  });
}

async function expectDestroyedSecretDelivery(response: APIResponse) {
  expect(response.status()).toBe(404);
  expect(await response.json()).toMatchObject({ code: 'admin_secret_delivery_not_found' });
}

async function completeStepUp(page: Page) {
  const dialog = page.getByRole('dialog', { name: 'Confirm administrator identity' });
  await expect(dialog).toBeVisible();
  await dialog.getByLabel('Administrator password').fill(credentials.password);
  await dialog.getByLabel('Current TOTP code').fill(await unusedOwnerTotp());
  await dialog.getByRole('button', { name: 'Verify and continue' }).click();
  await expect(dialog).not.toBeVisible();
}

async function enrollRestrictedAdministrator(browser: Browser, token: string) {
  const context = await browser.newContext({ baseURL: credentials.baseUrl });
  const page = await context.newPage();
  await page.addInitScript(() => localStorage.setItem('admin-locale', 'en'));
  await page.goto('/');
  await installSecretRedaction(page);
  await page
    .getByRole('button', { name: 'First deployment? Enroll a platform administrator' })
    .click();
  await page.getByLabel('Bootstrap token').fill(token);
  await page.getByRole('button', { name: 'Validate token' }).click();
  const secret = (await page.locator('.secret-box code').textContent())?.trim();
  expect(secret).toBeTruthy();
  const password = 'Restricted-Console-47!River';
  await page.getByLabel('Set password').fill(password);
  await page.getByLabel('Confirm password').fill(password);
  await page
    .getByLabel('Current TOTP code')
    .fill(totpForCounter(secret!, Math.floor(Date.now() / 30_000)));
  await page.getByRole('button', { name: 'Complete secure enrollment' }).click();
  await page.getByLabel('I have stored the recovery codes securely').check();
  await page.getByRole('button', { name: 'Enter the admin console' }).click();
  await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Administrators', exact: true })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Accounts', exact: true })).toBeVisible();

  const denied = await adminRequest(
    page,
    'POST',
    '/accounts',
    { id: `forbidden_${Date.now()}`, note: null, reason: 'permission-boundary verification' },
    { 'Idempotency-Key': randomUUID() }
  );
  expect(denied.status()).toBe(403);
  await expectAccessible(page);
  await page.getByRole('button', { name: 'Administrator menu' }).click();
  await page.getByRole('menuitem', { name: 'Sign out', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Welcome back' })).toBeVisible();
  await context.close();
}

test('the final image supports complete real control-plane journeys', async ({ page, browser }) => {
  test.setTimeout(480_000);
  await page.addInitScript(() => localStorage.setItem('admin-locale', 'en'));
  await page.setViewportSize({ width: 1440, height: 900 });
  await establishExpiredSession(page);

  await expect(page.locator('.app-footer')).toContainText(/v\d+\.\d+\.\d+/u);
  await expectNoHorizontalOverflow(page);
  await expectAccessible(page);

  const liveAccountId = `${credentials.accountId}_live`;
  const liveLicenseId = `${credentials.licenseId}_live`;
  const accountOperationIds: string[] = [];
  const activationCodeOperationIds: string[] = [];
  page.on('request', (request) => {
    if (isApiRequest(request, 'POST', '/accounts')) {
      accountOperationIds.push(request.headers()['idempotency-key']);
    }
    if (isApiRequest(request, 'POST', '/activation-codes')) {
      activationCodeOperationIds.push(request.headers()['idempotency-key']);
    }
  });

  await navigate(page, 'Accounts');
  await page.getByRole('button', { name: 'Create' }).click();
  let dialog = page.getByRole('dialog', { name: 'Create Accounts' });
  await dialog.getByLabel('Account ID').fill(liveAccountId);
  await dialog.getByLabel('Note').fill('Created through the final-image Admin UI');
  await dialog.getByLabel('Reason').fill('verify the live account journey');
  await dialog.getByRole('button', { name: 'Confirm creation' }).click();
  await expect(dialog).not.toBeVisible();
  await expect(page.getByText(liveAccountId, { exact: true })).toBeVisible();
  expect(accountOperationIds).toHaveLength(1);

  await navigate(page, 'Licenses');
  await page.getByRole('button', { name: 'Create' }).click();
  dialog = page.getByRole('dialog', { name: 'Create Licenses' });
  await dialog.getByLabel('License ID').fill(liveLicenseId);
  await dialog.getByLabel('Account ID').fill(liveAccountId);
  await dialog.getByLabel('Plan').selectOption('team');
  await dialog.getByLabel('Team seats').fill('3');
  await dialog.getByLabel('Reason').fill('verify the live Team license journey');
  await dialog.getByRole('button', { name: 'Confirm creation' }).click();
  await expect(dialog).not.toBeVisible();
  await expect(page.getByText(liveLicenseId, { exact: true })).toBeVisible();

  await navigate(page, 'Activation codes');
  await page.getByRole('button', { name: 'Create' }).click();
  dialog = page.getByRole('dialog', { name: 'Issue activation codes' });
  await dialog.getByLabel('Account ID').fill(liveAccountId);
  await dialog.getByLabel('License ID').fill(liveLicenseId);
  await dialog.getByLabel('Channel').fill('live_admin_ui');
  await dialog.getByLabel('Reason').fill('deliver a real one-time activation code');
  const stepUpRequiredResponse = page.waitForResponse(
    (response) =>
      isApiRequest(response.request(), 'POST', '/activation-codes') && response.status() === 403
  );
  await dialog.getByRole('button', { name: 'Confirm creation' }).click();
  expect(await (await stepUpRequiredResponse).json()).toMatchObject({
    code: 'admin_step_up_required'
  });
  const codeDeliveryResponse = page.waitForResponse(
    (response) => isApiRequest(response.request(), 'POST', '/activation-codes') && response.ok(),
    { timeout: 45_000 }
  );
  await completeStepUp(page);
  const codeDelivery = (await (await codeDeliveryResponse).json()) as {
    delivery: { id: string; claimToken: string };
  };
  expect(activationCodeOperationIds).toHaveLength(2);
  expect(activationCodeOperationIds[0]).toBe(activationCodeOperationIds[1]);
  await expect(dialog.locator('.code-delivery code')).toHaveText(/^CNX1-/u);
  await dialog.getByRole('button', { name: 'Stored securely; destroy delivery' }).click();
  await expect(dialog).not.toBeVisible();
  const codeReplay = await adminRequest(
    page,
    'POST',
    `/secret-deliveries/${codeDelivery.delivery.id}/claim`,
    { claimToken: codeDelivery.delivery.claimToken }
  );
  await expectDestroyedSecretDelivery(codeReplay);

  await navigate(page, 'Team workspaces');
  await page.getByRole('button', { name: 'Create invitation' }).click();
  dialog = page.getByRole('dialog', { name: 'Invite workspace member' });
  await dialog.getByLabel('Team account').selectOption(liveAccountId);
  await dialog.getByLabel('Member role').selectOption('viewer');
  await dialog.getByLabel('Email').fill('live.member@example.invalid');
  await dialog.getByLabel('Display name').fill('Live member');
  await dialog.getByLabel('Operation reason').fill('verify the live Team invitation journey');
  const invitationDeliveryResponse = page.waitForResponse(
    (response) =>
      isApiRequest(response.request(), 'POST', `/team-workspaces/${liveAccountId}/invitations`) &&
      response.ok()
  );
  await dialog.getByRole('button', { name: 'Create invitation' }).click();
  const invitationDelivery = (await (await invitationDeliveryResponse).json()) as {
    delivery: { id: string; claimToken: string };
  };
  await expect(dialog.locator('.code-delivery code')).not.toBeEmpty();
  await dialog.getByRole('button', { name: 'Stored securely; destroy delivery' }).click();
  await expect(dialog).not.toBeVisible();
  const invitationReplay = await adminRequest(
    page,
    'POST',
    `/secret-deliveries/${invitationDelivery.delivery.id}/claim`,
    { claimToken: invitationDelivery.delivery.claimToken }
  );
  await expectDestroyedSecretDelivery(invitationReplay);

  await navigate(page, 'Accounts');
  const accountRow = page.locator('tr').filter({ hasText: liveAccountId });
  await accountRow.getByRole('button', { name: 'Manage' }).click();
  dialog = page.getByRole('dialog', { name: liveAccountId });
  const accountPage = await adminRequest(page, 'GET', '/accounts?pageSize=50');
  expect(accountPage.ok()).toBe(true);
  const account = (
    (await accountPage.json()) as { items: Array<{ id: string; rowVersion: number }> }
  ).items.find((item) => item.id === liveAccountId);
  expect(account).toBeTruthy();
  const secondPage = await page.context().newPage();
  const changed = await adminRequest(
    secondPage,
    'POST',
    `/accounts/${liveAccountId}/actions/set-state`,
    { state: 'suspended', reason: 'create a real optimistic-concurrency conflict' },
    { 'Idempotency-Key': randomUUID(), 'If-Match': `"${account!.rowVersion}"` }
  );
  expect(changed.ok()).toBe(true);
  await secondPage.close();
  await dialog.getByLabel('Account state').selectOption('suspended');
  await dialog.getByLabel('Reason').fill('submit the stale account version');
  await dialog.getByRole('button', { name: 'Apply change' }).click();
  await expect(dialog.getByText('This resource changed in another session')).toBeVisible();
  await dialog.locator('footer').getByRole('button', { name: 'Close', exact: true }).click();

  await navigate(page, 'Billing & payments', 'Billing and payments');
  await page.getByRole('button', { name: 'New invoice' }).click();
  dialog = page.getByRole('dialog', { name: 'Create commercial invoice' });
  const liveInvoiceId = `invoice_live_${Date.now()}`;
  await dialog.getByLabel('Invoice ID').fill(liveInvoiceId);
  await dialog.getByLabel('Account ID').fill(liveAccountId);
  await dialog.getByLabel('License ID').fill(liveLicenseId);
  await dialog.getByLabel('Commercial offer').selectOption(credentials.billingOfferId);
  await dialog.getByLabel('Team seats').fill('3');
  await dialog.getByLabel('Operation reason').fill('verify live invoice creation');
  await dialog.getByRole('button', { name: 'Create invoice' }).click();
  await expect(dialog).not.toBeVisible();
  const invoicePage = await adminRequest(page, 'GET', '/billing/invoices');
  expect(invoicePage.ok()).toBe(true);
  expect(
    ((await invoicePage.json()) as Array<{ id: string }>).some(
      (invoice) => invoice.id === liveInvoiceId
    )
  ).toBe(true);

  await page.getByRole('tab', { name: /^Payment review/u }).click();
  const claimRow = page.locator('tr').filter({ hasText: credentials.paymentClaimId });
  await expect(claimRow).toBeVisible();
  await claimRow.getByRole('button', { name: 'Manage' }).click();
  dialog = page.getByRole('dialog', { name: credentials.paymentClaimId });
  await dialog.getByLabel('Add evidence').setInputFiles(credentials.evidencePath);
  await dialog.getByLabel('Review reason').fill('ClamAV verified the clean synthetic PDF');
  await dialog.getByRole('button', { name: 'Upload and scan' }).click();
  await expect(dialog.getByText('runtime-clean-receipt.pdf')).toBeVisible();
  await expect(dialog.locator('.evidence-list')).toContainText('clean');
  await dialog.getByLabel('Review decision').selectOption('approve');
  await dialog.getByRole('button', { name: 'Submit review' }).click();
  await expect(dialog).not.toBeVisible();
  const reviewedClaims = await adminRequest(page, 'GET', '/billing/payment-claims');
  expect(reviewedClaims.ok()).toBe(true);
  const reviewedClaim = (
    (await reviewedClaims.json()) as Array<{
      id: string;
      status: string;
      reviewReason: string | null;
    }>
  ).find((claim) => claim.id === credentials.paymentClaimId);
  expect(reviewedClaim).toMatchObject({
    status: 'verified',
    reviewReason: 'ClamAV verified the clean synthetic PDF'
  });

  await navigate(page, 'Bulk jobs');
  await page.getByRole('button', { name: 'Create' }).click();
  dialog = page.getByRole('dialog', { name: 'Create bulk job' });
  await dialog.getByLabel('Operation type').selectOption('account_set_state');
  await dialog.getByLabel('Target state').selectOption('active');
  await dialog.getByLabel('Target IDs (one per line)').fill(liveAccountId);
  await dialog.getByLabel('Reason').fill('verify bounded preview, creation, and cancellation');
  const previewResponse = page.waitForResponse(
    (response) => isApiRequest(response.request(), 'POST', '/bulk-jobs/previews') && response.ok()
  );
  const jobResponse = page.waitForResponse(
    (response) => isApiRequest(response.request(), 'POST', '/bulk-jobs') && response.ok()
  );
  await dialog.getByRole('button', { name: 'Confirm creation' }).click();
  const preview = (await (await previewResponse).json()) as {
    targets: Array<{ id: string; rowVersion: number }>;
  };
  expect(preview.targets).toHaveLength(1);
  expect(preview.targets[0]).toMatchObject({ id: liveAccountId });
  expect(preview.targets[0].rowVersion).toBeGreaterThan(0);
  const job = (await (await jobResponse).json()) as { id: string };
  await expect(dialog).not.toBeVisible();
  const jobRow = page.locator('tr').filter({ hasText: job.id });
  await jobRow.getByRole('button', { name: 'Manage' }).click();
  dialog = page.getByRole('dialog', { name: job.id });
  await dialog.getByLabel('Reason').fill('cancel the synthetic live job before worker startup');
  await dialog.getByRole('button', { name: 'Confirm cancellation' }).click();
  await expect(dialog).not.toBeVisible();
  const canceledJob = await adminRequest(page, 'GET', `/bulk-jobs/${job.id}`);
  expect(canceledJob.ok()).toBe(true);
  expect(((await canceledJob.json()) as { status: string }).status).toBe('canceled');

  await navigate(page, 'Administrators', 'Administrator identities');
  await page.getByRole('button', { name: 'Add administrator' }).click();
  dialog = page.getByRole('dialog', { name: 'Add administrator' });
  const restrictedUsername = `support${Date.now()}`;
  await dialog.getByLabel('Username').fill(restrictedUsername);
  await dialog.getByLabel('Display name').fill('Live restricted support');
  await dialog.getByLabel('Change reason').fill('verify restricted control-plane permissions');
  await dialog.getByRole('button', { name: 'Save' }).click();
  const delivery = page.getByRole('dialog', { name: 'Deliver enrollment token securely' });
  const enrollmentToken = (await delivery.locator('.delivery-secret code').textContent())?.trim();
  expect(enrollmentToken).toBeTruthy();
  await enrollRestrictedAdministrator(browser, enrollmentToken!);
  await delivery.getByRole('button', { name: 'Stored securely; destroy the server copy' }).click();
  await expect(delivery).not.toBeVisible();

  for (const [destination, expectedText] of [
    ['Audit', 'live'],
    ['System status', 'Control plane is healthy']
  ] as const) {
    await navigate(page, destination);
    await expect(page.getByText(expectedText, { exact: false }).first()).toBeVisible();
    await expectNoHorizontalOverflow(page);
  }
  await expectAccessible(page);

  for (const viewport of [
    { width: 640, height: 900 },
    { width: 390, height: 844 }
  ]) {
    await page.setViewportSize(viewport);
    await expectNoHorizontalOverflow(page);
    await expect(page.getByRole('heading', { name: 'System status' })).toBeVisible();
  }

  await page.setViewportSize({ width: 1440, height: 900 });
  let administratorMenu = page.getByRole('button', { name: 'Administrator menu' });
  await administratorMenu.click();
  await page.getByRole('menuitem', { name: 'Profile' }).click();
  dialog = page.getByRole('dialog', { name: 'Profile' });
  await dialog.getByLabel('Display name').fill('Runtime Browser Verified');
  await dialog.getByLabel('Operation reason').fill('verify live profile maintenance');
  await dialog.getByRole('button', { name: 'Save profile' }).click();
  await expect(dialog).not.toBeVisible();

  const rotatedPassword = 'Rotated-Console-47!River';
  administratorMenu = page.getByRole('button', { name: 'Administrator menu' });
  await administratorMenu.click();
  await page.getByRole('menuitem', { name: 'Change password' }).click();
  dialog = page.getByRole('dialog', { name: 'Change password' });
  await dialog.getByRole('textbox', { name: /^New password\b/ }).fill(rotatedPassword);
  await dialog.getByRole('textbox', { name: /^Confirm new password\b/ }).fill(rotatedPassword);
  await dialog.getByLabel('Operation reason').fill('verify live credential rotation');
  await dialog.getByRole('button', { name: 'Change password' }).click();
  await expect(page.getByRole('heading', { name: 'Welcome back' })).toBeVisible();

  const postRotationTotp = await unusedOwnerTotp();
  await page.getByLabel('Administrator account').fill(credentials.username);
  await page.getByLabel('Password', { exact: true }).fill(credentials.password);
  await page.getByLabel('Two-factor code').fill(postRotationTotp);
  await page.getByRole('button', { name: 'Sign in securely' }).click();
  await expect(page.getByRole('alert')).toContainText('invalid administrator credentials');
  await signIn(page, credentials.username, rotatedPassword, postRotationTotp);
  administratorMenu = page.getByRole('button', { name: 'Administrator menu' });
  await expect(administratorMenu).toContainText('Runtime Browser Verified');
  await administratorMenu.click();
  await page.getByRole('menuitem', { name: 'Sign out', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Welcome back' })).toBeVisible();
});
