import { Buffer } from 'node:buffer';
import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Locator, type Page } from '@playwright/test';

type MockConsoleOptions = {
  user?: {
    id: string;
    username: string;
    displayName: string;
    status: string;
    roles: string[];
    rowVersion: number;
  };
  permissions?: string[];
  onSessionRequest?: () => void;
  sessionAvailable?: () => boolean;
};

const fullPermissions = [
  'identity.manage',
  'account.read',
  'account.write',
  'account.denylist',
  'license.read',
  'license.write',
  'code.read',
  'code.issue',
  'code.write',
  'device.read',
  'device.remove',
  'device.security',
  'team.read',
  'team.write',
  'billing.read',
  'billing.write',
  'billing.review',
  'billing.override',
  'job.manage',
  'audit.read',
  'audit.export',
  'system.read'
];

async function mockConsole(page: Page, authenticated: boolean, options: MockConsoleOptions = {}) {
  const user =
    options.user ??
    ({
      id: 'admin_01',
      username: 'operator',
      displayName: 'Operations',
      status: 'active',
      roles: ['platform_owner'],
      rowVersion: 3
    } as const);
  await page.route('**/api/v1/**', async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path.endsWith('/auth/me')) {
      options.onSessionRequest?.();
      const sessionAvailable = options.sessionAvailable?.() ?? authenticated;
      return route.fulfill(
        sessionAvailable
          ? {
              json: {
                user,
                permissions: options.permissions ?? fullPermissions,
                expiresAt: 1999999999,
                elevatedUntil: 1999990000,
                serverVersion: '1.0.1'
              }
            }
          : {
              status: 401,
              json: { code: 'admin_authentication_required', message: 'Authentication required' }
            }
      );
    }
    if (path.endsWith('/dashboard')) {
      return route.fulfill({
        json: {
          generatedAt: Math.floor(Date.now() / 1000),
          accounts: 1284,
          activeLicenses: 946,
          activeDevices: 2371,
          riskyDevices: 2,
          pendingPayments: 3,
          openInvoices: 12
        }
      });
    }
    if (path.endsWith('/system/status')) {
      return route.fulfill({
        json: {
          status: 'ready',
          version: '1.0.1',
          serverUnix: 1784422800,
          startedAt: 1784419200,
          adminOrigin: 'https://admin.example.test',
          database: 'ready',
          timeAuthority: 'ready',
          objectStorage: {
            backend: 'database',
            objectCount: 8,
            storedBytes: 4096,
            hardLimitBytes: 1048576,
            usageRatio: 0.00390625
          }
        }
      });
    }
    if (path.endsWith('/team-workspaces') && route.request().method() === 'GET') {
      return route.fulfill({
        json: {
          items: [
            {
              accountId: 'acct_team',
              licenseId: 'lic_team',
              purchasedSeats: 10,
              occupiedMembers: 2,
              activeMembers: 2,
              memberCount: 2
            }
          ],
          nextCursor: null
        }
      });
    }
    if (path.endsWith('/accounts') && route.request().method() === 'GET') {
      return route.fulfill({
        json: {
          items: [
            {
              id: 'acct_001',
              state: 'active',
              note: 'Production tenant',
              createdAt: 1783731600,
              updatedAt: 1783731600,
              rowVersion: 2
            }
          ],
          nextCursor: null
        }
      });
    }
    if (path.endsWith('/licenses') && route.request().method() === 'GET') {
      return route.fulfill({
        json: {
          items: [
            {
              id: 'lic_001',
              accountId: 'acct_001',
              plan: 'pro',
              planRevision: 2,
              status: 'active',
              expiresAt: null,
              licenseEpoch: 1,
              purchasedSeats: 0,
              rowVersion: 4
            }
          ],
          nextCursor: null
        }
      });
    }
    if (path.endsWith('/billing/offers') && route.request().method() === 'GET') {
      return route.fulfill({
        json: [
          {
            id: 'offer_001',
            rowVersion: 1,
            plan: 'team',
            planRevision: 2,
            durationDays: 365,
            currency: 'USD',
            baseAmount: '99.00',
            seatAmount: '20.00',
            nameEn: 'Team annual',
            nameZh: 'Team 年付',
            active: true,
            createdAt: 1900000000,
            updatedAt: 1900000000
          }
        ]
      });
    }
    if (path.endsWith('/admin-users') && route.request().method() === 'GET') {
      return route.fulfill({
        json: {
          items: [
            {
              id: 'admin_01',
              username: 'operator',
              displayName: 'Operations',
              status: 'active',
              roles: ['platform_owner'],
              rowVersion: 3
            },
            {
              id: 'admin_02',
              username: 'security',
              displayName: 'Security team',
              status: 'pending',
              roles: ['security_admin', 'auditor'],
              rowVersion: 1
            },
            {
              id: 'admin_03',
              username: 'billing',
              displayName: 'Billing operations',
              status: 'disabled',
              roles: ['billing_admin'],
              rowVersion: 7
            }
          ]
        }
      });
    }
    if (path.endsWith('/admin-users') && route.request().method() === 'POST') {
      return route.fulfill({
        json: {
          user: {
            id: 'admin_04',
            username: 'support',
            displayName: 'Support operator',
            status: 'pending',
            roles: ['support_operator'],
            rowVersion: 1
          },
          delivery: { id: 'delivery_01', claimToken: 'claim-token', expiresAt: 1999999999 },
          acknowledgementRequired: true
        }
      });
    }
    if (path.endsWith('/secret-deliveries/delivery_01/claim')) {
      return route.fulfill({ json: { enrollmentToken: 'one-time-enrollment-token' } });
    }
    if (path.endsWith('/secret-deliveries/delivery_01/acknowledge')) {
      return route.fulfill({ status: 204 });
    }
    return route.fulfill({ json: { items: [] } });
  });
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

async function expectIconCentered(button: Locator) {
  await expect(button).toBeVisible();
  const offset = await button.evaluate((element) => {
    const buttonBounds = element.getBoundingClientRect();
    const iconBounds = element.querySelector('svg')?.getBoundingClientRect();
    if (!iconBounds) return { x: Number.POSITIVE_INFINITY, y: Number.POSITIVE_INFINITY };
    return {
      x: Math.abs(
        buttonBounds.left + buttonBounds.width / 2 - (iconBounds.left + iconBounds.width / 2)
      ),
      y: Math.abs(
        buttonBounds.top + buttonBounds.height / 2 - (iconBounds.top + iconBounds.height / 2)
      )
    };
  });
  expect(offset.x).toBeLessThanOrEqual(1);
  expect(offset.y).toBeLessThanOrEqual(1);
}

test('login and authenticated overview meet the automated accessibility baseline', async ({
  page
}) => {
  await mockConsole(page, false);
  await page.goto('/');
  await expect(page.getByRole('heading', { name: '欢迎回来' })).toBeVisible();
  await expectAccessible(page);

  await page.unroute('**/api/v1/**');
  await mockConsole(page, true);
  await page.reload();
  await expect(page.getByRole('heading', { name: '运营总览' })).toBeVisible();
  await expectAccessible(page);

  await page.getByRole('button', { name: '审计', exact: true }).click();
  await expect(page.getByRole('heading', { name: '审计', exact: true })).toBeVisible();
  await expectAccessible(page);

  await page.evaluate(() => {
    localStorage.setItem('admin-theme', 'dark');
    document.documentElement.dataset.theme = 'dark';
  });
  await expectAccessible(page);

  await page.unroute('**/api/v1/**');
  await mockConsole(page, false);
  await page.reload();
  await expect(page.getByRole('heading', { name: '欢迎回来' })).toBeVisible();
  await expectAccessible(page);
});

test('login surface remains balanced on desktop and mobile', async ({ page }) => {
  await mockConsole(page, false);
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto('/');
  await expect(page.getByRole('heading', { name: '欢迎回来' })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(
    true
  );
  await page.screenshot({ path: 'test-results/login-desktop.png', fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  await page.reload();
  await expect(page.getByRole('heading', { name: '欢迎回来' })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(
    true
  );
  await page.screenshot({ path: 'test-results/login-mobile.png', fullPage: true });
  await page.getByRole('button', { name: '首次部署？登记平台管理员' }).click();
  await expect(page.getByRole('heading', { name: '登记平台管理员' })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(
    true
  );
});

test('persisted English is applied before the first UI renders', async ({ page }) => {
  await page.addInitScript(() => {
    localStorage.setItem('admin-locale', 'en');
    localStorage.setItem('admin-theme', 'dark');
    localStorage.setItem('admin-font-size', 'large');
  });
  await mockConsole(page, false);
  await page.goto('/');
  await expect(page.locator('html')).toHaveAttribute('lang', 'en');
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  await expect(page.locator('html')).toHaveAttribute('data-font-size', 'large');
  await expect(page.getByRole('heading', { name: 'Welcome back' })).toBeVisible();
  const visibleText = (await page.locator('body').innerText()).replace('简体中文', '');
  expect(visibleText).not.toMatch(/[一-龥]/);
});

test('the installable app shell caches only immutable public assets', async ({ page }) => {
  await mockConsole(page, false);
  await page.goto('/');
  await expect(page.getByRole('heading', { name: '欢迎回来' })).toBeVisible();

  const metadata = await page.evaluate(async () => {
    const response = await fetch('/manifest.webmanifest');
    const manifest = await response.json();
    const iconDimensions = await Promise.all(
      [
        ['/icons/camellia-console.v1-192.png', 192],
        ['/icons/camellia-console.v1-512.png', 512],
        ['/icons/camellia-console-maskable.v1-512.png', 512],
        ['/icons/camellia-console-apple.v1-180.png', 180]
      ].map(
        ([src, expected]) =>
          new Promise<{ src: string; expected: number; width: number; height: number }>(
            (resolve, reject) => {
              const image = new Image();
              image.onload = () =>
                resolve({
                  src: String(src),
                  expected: Number(expected),
                  width: image.width,
                  height: image.height
                });
              image.onerror = () => reject(new Error(`icon failed to load: ${src}`));
              image.src = String(src);
            }
          )
      )
    );
    return {
      contentType: response.headers.get('content-type'),
      manifest,
      manifestHref: document.querySelector<HTMLLinkElement>('link[rel="manifest"]')?.href,
      appleIcon: document.querySelector<HTMLLinkElement>('link[rel="apple-touch-icon"]')?.href,
      themeColors: [...document.querySelectorAll<HTMLMetaElement>('meta[name="theme-color"]')].map(
        (meta) => ({ color: meta.content, media: meta.media })
      ),
      iconDimensions
    };
  });
  expect(metadata.contentType).toContain('application/manifest+json');
  expect(metadata.manifest).toMatchObject({
    id: '/',
    name: 'Camellia Console',
    short_name: 'Camellia Console',
    start_url: '/',
    scope: '/',
    display: 'standalone'
  });
  expect(metadata.manifestHref).toBe('http://127.0.0.1:4178/manifest.webmanifest');
  expect(metadata.appleIcon).toBe('http://127.0.0.1:4178/icons/camellia-console-apple.v1-180.png');
  expect(metadata.themeColors).toEqual([
    { color: '#f4f7fb', media: '(prefers-color-scheme: light)' },
    { color: '#0d121b', media: '(prefers-color-scheme: dark)' }
  ]);
  expect(
    metadata.iconDimensions.every(
      (icon) => icon.width === icon.expected && icon.height === icon.expected
    )
  ).toBe(true);

  await expect
    .poll(() =>
      page.evaluate(async () => {
        const registration = await Promise.race([
          navigator.serviceWorker.ready,
          new Promise<null>((resolve) => setTimeout(() => resolve(null), 250))
        ]);
        return registration?.active?.state ?? null;
      })
    )
    .toBe('activated');
  await page.reload();
  await expect
    .poll(() => page.evaluate(() => Boolean(navigator.serviceWorker.controller)))
    .toBe(true);
  const cacheState = await page.evaluate(async () => {
    const registration = await navigator.serviceWorker.ready;
    await registration.update();
    const cacheNames = await caches.keys();
    const requests = (
      await Promise.all(cacheNames.map(async (name) => (await caches.open(name)).keys()))
    ).flat();
    return {
      cacheNames,
      paths: requests.map((request) => new URL(request.url).pathname)
    };
  });
  expect(cacheState.cacheNames).toHaveLength(1);
  expect(cacheState.cacheNames[0]).toMatch(/^camellia-console-shell-/);
  expect(cacheState.paths.length).toBeGreaterThan(5);
  expect(
    cacheState.paths.every(
      (path) =>
        path.startsWith('/_app/immutable/') || (path.startsWith('/icons/') && path.includes('.v1'))
    )
  ).toBe(true);
  expect(cacheState.paths.some((path) => path.includes('inter-latin-opsz-normal'))).toBe(true);
  expect(
    cacheState.paths.some(
      (path) =>
        path.startsWith('/api/v1') ||
        [
          '/',
          '/index.html',
          '/fallback.html',
          '/manifest.webmanifest',
          '/appearance-init.js'
        ].includes(path)
    )
  ).toBe(false);

  await page.unroute('**/api/v1/**');
  await page.context().setOffline(true);
  const offline = await page.evaluate(async () => {
    const result = async (path: string) =>
      fetch(`${path}${path.includes('?') ? '&' : '?'}offline-check=1`, {
        cache: 'no-store'
      }).then(
        () => 'response',
        () => 'failed'
      );
    const cache = await caches.open((await caches.keys())[0]);
    const cachedPath = new URL((await cache.keys())[0].url).pathname;
    return {
      cachedAsset: await fetch(cachedPath).then(
        () => 'response',
        () => 'failed'
      ),
      api: await result('/api/v1/auth/me'),
      navigation: await result('/'),
      manifest: await result('/manifest.webmanifest'),
      appearance: await result('/appearance-init.js')
    };
  });
  await page.context().setOffline(false);
  expect(offline).toEqual({
    cachedAsset: 'response',
    api: 'failed',
    navigation: 'failed',
    manifest: 'failed',
    appearance: 'failed'
  });
});

test('signing out after enrollment returns to sign in', async ({ page }) => {
  let sessionAvailable = false;
  await page.addInitScript(() => localStorage.setItem('admin-locale', 'en'));
  await mockConsole(page, false, { sessionAvailable: () => sessionAvailable });
  await page.route(/\/api\/v1\/auth\/enrollment$/, (route) =>
    route.fulfill({
      json: {
        username: 'support',
        displayName: 'Support operator',
        totpSecret: 'JBSWY3DPEHPK3PXP',
        otpauthUri: 'otpauth://totp/Camellia%20Nexus%3Asupport',
        expiresAt: 1999999999
      }
    })
  );
  await page.route('**/api/v1/auth/enrollment/complete', (route) => {
    sessionAvailable = true;
    return route.fulfill({
      json: {
        user: {
          id: 'admin_support',
          username: 'support',
          displayName: 'Support operator',
          status: 'active',
          roles: ['support_operator'],
          rowVersion: 1
        },
        expiresAt: 1999999999,
        recoveryCodes: ['CNX-RECOVERY-001']
      }
    });
  });
  await page.route('**/api/v1/auth/logout', (route) => {
    sessionAvailable = false;
    return route.fulfill({ status: 204 });
  });

  await page.goto('/');
  await page
    .getByRole('button', { name: 'First deployment? Enroll a platform administrator' })
    .click();
  await page.getByLabel('Bootstrap token').fill('enrollment-token');
  await page.getByRole('button', { name: 'Validate token' }).click();
  await expect(page.locator('.secret-box small')).toHaveText('TOTP secret');
  await expect(page.getByRole('button', { name: 'Copy TOTP secret' })).toBeVisible();
  await page.getByLabel('Set password').fill('Restricted-Console-47!River');
  await page.getByLabel('Confirm password').fill('Restricted-Console-47!River');
  await page.getByLabel('Current TOTP code').fill('123456');
  await page.getByRole('button', { name: 'Complete secure enrollment' }).click();
  await expect(page.getByLabel('Administrator recovery codes')).toContainText('CNX-RECOVERY-001');
  await page.getByLabel('I have stored the recovery codes securely').check();
  await page.getByRole('button', { name: 'Enter the admin console' }).click();
  await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible();

  await page.getByRole('button', { name: 'Administrator menu' }).click();
  await page.getByRole('menuitem', { name: 'Sign out', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Welcome back' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Enroll a platform administrator' })).toHaveCount(
    0
  );
});

test('authenticated English UI reports the running server version at compact width', async ({
  page
}) => {
  await page.addInitScript(() => localStorage.setItem('admin-locale', 'en'));
  await mockConsole(page, true);
  await page.setViewportSize({ width: 640, height: 900 });
  await page.goto('/#system');
  await expect(page.locator('html')).toHaveAttribute('lang', 'en');
  await expect(page.getByRole('heading', { name: 'System status' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Check again' })).toHaveCSS(
    'white-space',
    'nowrap'
  );
  await expect(page.getByText('Control plane is healthy')).toBeVisible();
  await expect(page.locator('.system-grid')).toContainText('Ready');
  await expect(page.locator('.system-grid')).toContainText('Database');
  await expect(page.locator('.system-grid')).not.toContainText('ready');
  await expect(page.locator('.app-footer')).toContainText('v1.0.1');
  await expect(page.locator('.app-footer')).toContainText('Session ends by');
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(
    true
  );
  await page.screenshot({ path: 'test-results/system-status-en-compact.png', fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  await page.reload();
  await expect(page.getByRole('heading', { name: 'System status' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Check again' })).toHaveCSS(
    'white-space',
    'nowrap'
  );
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(
    true
  );
  await page.screenshot({ path: 'test-results/system-status-en-mobile.png', fullPage: true });
});

test('recent visible activity keeps an idle session alive without keeping an unattended tab alive', async ({
  page
}) => {
  let sessionRequests = 0;
  let sessionAvailable = true;
  await page.clock.install({ time: new Date('2026-07-19T00:00:00Z') });
  await mockConsole(page, true, {
    onSessionRequest: () => {
      sessionRequests += 1;
    },
    sessionAvailable: () => sessionAvailable
  });
  await page.goto('/#system');
  await expect(page.getByRole('heading', { name: '系统状态' })).toBeVisible();
  await expect.poll(() => sessionRequests).toBe(1);
  await page.evaluate(() => dispatchEvent(new Event('focus')));
  await expect.poll(() => sessionRequests).toBe(1);
  await page.mouse.wheel(0, 120);

  await page.clock.fastForward(5 * 60_000 + 1_000);
  await expect.poll(() => sessionRequests).toBe(2);
  await expect(page.locator('.app-footer')).toContainText('会话最晚结束于');

  await page.clock.fastForward(10 * 60_000);
  await expect.poll(() => sessionRequests).toBe(2);

  sessionAvailable = false;
  await page.keyboard.press('Tab');
  await page.clock.fastForward(5 * 60_000 + 1_000);
  await expect(page.getByRole('heading', { name: '欢迎回来' })).toBeVisible();
});

test('system status localizes protocol values in Chinese', async ({ page }) => {
  await mockConsole(page, true);
  await page.goto('/#system');
  await expect(page.getByRole('heading', { name: '系统状态' })).toBeVisible();
  await expect(page.getByText('控制面运行正常')).toBeVisible();
  await expect(page.locator('.system-grid')).toContainText('正常');
  await expect(page.locator('.system-grid')).toContainText('数据库');
  await expect(page.locator('.system-grid')).not.toContainText('ready');
  await page.screenshot({ path: 'test-results/system-status-zh.png', fullPage: true });
});

test('refresh controls and status filters share stable geometry and localized labels', async ({
  page
}, testInfo) => {
  await mockConsole(page, true);
  await page.route(/\/api\/v1\/accounts(?:\?.*)?$/, (route) =>
    route.fulfill({
      json: {
        items: [
          { id: 'acct_active', state: 'active', rowVersion: 1 },
          { id: 'acct_suspended', state: 'suspended', rowVersion: 1 },
          { id: 'acct_denied', state: 'denylisted', rowVersion: 1 }
        ],
        nextCursor: null
      }
    })
  );
  await page.route(/\/api\/v1\/licenses(?:\?.*)?$/, (route) =>
    route.fulfill({
      json: {
        items: [
          { id: 'lic_due', accountId: 'acct_active', plan: 'pro', status: 'past_due' },
          { id: 'lic_canceled', accountId: 'acct_active', plan: 'team', status: 'canceled' }
        ],
        nextCursor: null
      }
    })
  );
  await page.route(/\/api\/v1\/devices(?:\?.*)?$/, (route) =>
    route.fulfill({
      json: {
        items: [
          { deviceId: 'device_pending', accountId: 'acct_active', state: 'pending_activation' },
          { deviceId: 'device_risky', accountId: 'acct_active', state: 'suspicious' }
        ],
        nextCursor: null
      }
    })
  );
  await page.route(/\/api\/v1\/bulk-jobs(?:\?.*)?$/, (route) =>
    route.fulfill({
      json: {
        items: [
          { id: 'job_partial', kind: 'account_set_state', status: 'partial_failed' },
          { id: 'job_cancel', kind: 'device_set_state', status: 'cancel_requested' }
        ],
        nextCursor: null
      }
    })
  );
  await page.route(/\/api\/v1\/audit-events(?:\?.*)?$/, (route) =>
    route.fulfill({
      json: [
        {
          id: 'audit_denied',
          eventType: 'team_invitation_accept_denied',
          outcome: 'denied',
          reasonCode: 'device_enrollment_not_found'
        },
        { id: 'audit_ok', eventType: 'admin_account_updated', outcome: 'succeeded' }
      ]
    })
  );

  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto('/#accounts');
  const filter = page.locator('.filter-select');
  const statusSelect = page.getByLabel('按状态筛选');
  await expect(statusSelect.locator('option')).toHaveText(['全部状态', '有效', '已暂停', '已封禁']);
  await expectIconCentered(page.locator('.toolbar-actions > .icon-button'));
  const filterGeometry = await filter.evaluate((element) => {
    const bounds = element.getBoundingClientRect();
    const select = element.querySelector('select')!.getBoundingClientRect();
    const icons = [...element.querySelectorAll('svg')].map((icon) => icon.getBoundingClientRect());
    return {
      width: bounds.width,
      height: bounds.height,
      textAlign: getComputedStyle(element.querySelector('select')!).textAlign,
      textAlignLast: getComputedStyle(element.querySelector('select')!).textAlignLast,
      selectHeight: select.height,
      leadingGap: select.left - icons[0].right,
      trailingGap: icons[1].left - select.right
    };
  });
  expect(filterGeometry.height).toBe(40);
  expect(Math.abs(filterGeometry.height - filterGeometry.selectHeight)).toBeLessThanOrEqual(2);
  expect(filterGeometry.width).toBeGreaterThanOrEqual(120);
  expect(filterGeometry.width).toBeLessThanOrEqual(260);
  expect(filterGeometry.textAlign).toBe('center');
  expect(filterGeometry.textAlignLast).toBe('center');
  expect(filterGeometry.leadingGap).toBeGreaterThanOrEqual(6);
  expect(filterGeometry.trailingGap).toBeGreaterThanOrEqual(6);
  const pickerGeometry = await statusSelect.evaluate((element) => {
    const select = element as HTMLSelectElement;
    const option = select.options[0];
    const selectStyle = getComputedStyle(select);
    const optionStyle = getComputedStyle(option);
    const checkmarkStyle = getComputedStyle(option, '::checkmark');
    const mirrorStyle = getComputedStyle(option, '::after');
    return {
      supportsBaseSelect: CSS.supports('appearance', 'base-select'),
      appearance: selectStyle.appearance,
      alignItems: selectStyle.alignItems,
      paddingTop: selectStyle.paddingTop,
      paddingBottom: selectStyle.paddingBottom,
      pickerAppearance: getComputedStyle(select, '::picker(select)').appearance,
      optionDisplay: optionStyle.display,
      checkmarkDisplay: checkmarkStyle.display,
      mirrorContent: mirrorStyle.content
    };
  });
  expect(pickerGeometry.supportsBaseSelect).toBe(true);
  expect(pickerGeometry.appearance).toBe('base-select');
  expect(pickerGeometry.alignItems).toBe('center');
  expect(pickerGeometry.paddingTop).toBe('0px');
  expect(pickerGeometry.paddingBottom).toBe('0px');
  expect(pickerGeometry.pickerAppearance).toBe('base-select');
  expect(pickerGeometry.optionDisplay).toBe('flex');
  expect(pickerGeometry.checkmarkDisplay).toBe('none');
  expect(pickerGeometry.mirrorContent).toBe('none');
  await statusSelect.click();
  await expect.poll(() => statusSelect.evaluate((element) => element.matches(':open'))).toBe(true);
  await page.screenshot({
    path: testInfo.outputPath('centered-filter-picker.png'),
    fullPage: true
  });
  await page.keyboard.press('Escape');
  await expect.poll(() => statusSelect.evaluate((element) => element.matches(':open'))).toBe(false);
  await statusSelect.selectOption('denylisted');
  await expect(page.locator('tbody')).toContainText('acct_denied');
  await expect(page.locator('tbody')).toContainText('已封禁');
  await statusSelect.selectOption('all');
  await expectAccessible(page);

  const cases = [
    ['/#licenses', '授权', ['全部状态', '逾期', '已取消'], 'lic_due'],
    ['/#devices', '设备', ['全部状态', '待激活', '可疑'], 'device_pending'],
    ['/#jobs', '批量任务', ['全部状态', '部分失败', '取消中'], 'job_partial'],
    ['/#audit', '审计', ['全部状态', '已拒绝', '成功'], 'team_invitation_accept_denied']
  ] as const;
  const widths = [filterGeometry.width];
  for (const [hash, destination, labels, rowId] of cases) {
    await page.goto(hash);
    await expect(page.getByRole('heading', { name: destination, exact: true })).toBeVisible();
    await expect(page.locator('tbody')).toContainText(rowId);
    await expect(page.getByLabel('按状态筛选').locator('option')).toHaveText([...labels]);
    widths.push((await page.locator('.filter-select').boundingBox())!.width);
  }
  expect(widths.every((width) => width >= 120 && width <= 260)).toBe(true);
  expect(Math.max(...widths) - Math.min(...widths)).toBeLessThanOrEqual(90);
  await expect(page.locator('tbody')).toContainText('team_invitation_accept_denied');

  const tableAlignment = await page.locator('table').evaluate((table) => ({
    time: getComputedStyle(table.querySelectorAll('td')[0]!).textAlign,
    event: getComputedStyle(table.querySelectorAll('td')[1]!).textAlign,
    outcome: getComputedStyle(table.querySelectorAll('td')[2]!).textAlign
  }));
  expect(tableAlignment).toEqual({ time: 'center', event: 'start', outcome: 'center' });

  await page.getByRole('button', { name: '账单与付款', exact: true }).click();
  await expect(page.getByRole('heading', { name: '账单与付款' })).toBeVisible();
  await expectIconCentered(page.locator('.resource-toolbar > .icon-button'));
  await page.getByRole('button', { name: 'Team 工作区', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Team 工作区' })).toBeVisible();
  await expectIconCentered(page.locator('.panel-head > .icon-button'));
  await page.getByRole('button', { name: '查看权限矩阵' }).click();
  const matrix = page.getByRole('dialog', { name: '成员权限矩阵' });
  await expect(matrix.locator('.eyebrow')).toHaveText('Team / 权限');
  await expect(matrix.locator('.matrix-list')).toContainText('所有者');
  await expect(matrix.locator('.matrix-list')).toContainText('操作员');
  await matrix.getByRole('button', { name: '完成' }).click();

  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto('/#accounts');
  await expect(page.getByRole('heading', { name: '账户', exact: true })).toBeVisible();
  const mobileLayout = await page.locator('.resource-toolbar').evaluate((element) => {
    const bounds = element.getBoundingClientRect();
    const select = element.querySelector<HTMLSelectElement>('.filter-select select')!;
    const controls = [...element.querySelectorAll<HTMLElement>('.filter-select, .icon-button')].map(
      (control) => control.getBoundingClientRect()
    );
    const table = document.querySelector<HTMLElement>('.table-shell');
    return {
      pageOverflow: document.documentElement.scrollWidth - window.innerWidth,
      toolbarOverflow: element.scrollWidth - element.clientWidth,
      controlsInside: controls.every(
        (control) => control.left >= bounds.left - 1 && control.right <= bounds.right + 1
      ),
      tableScrollable: Boolean(table && table.scrollWidth > table.clientWidth),
      selectAppearance: getComputedStyle(select).appearance,
      selectTextAlign: getComputedStyle(select).textAlign
    };
  });
  expect(mobileLayout.pageOverflow).toBeLessThanOrEqual(1);
  expect(mobileLayout.toolbarOverflow).toBeLessThanOrEqual(1);
  expect(mobileLayout.controlsInside).toBe(true);
  expect(mobileLayout.tableScrollable).toBe(true);
  expect(mobileLayout.selectAppearance).toBe('auto');
  expect(mobileLayout.selectTextAlign).toBe('start');

  await page.evaluate(() => localStorage.setItem('admin-locale', 'en'));
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto('/#accounts');
  await page.reload();
  await expect(page.getByRole('heading', { name: 'Accounts', exact: true })).toBeVisible();
  const compactEnglishWidth = (await page.locator('.filter-select').boundingBox())!.width;
  await page.goto('/#devices');
  const longestEnglishWidth = (await page.locator('.filter-select').boundingBox())!.width;
  expect(longestEnglishWidth).toBeGreaterThan(compactEnglishWidth);
});

test('English domain labels remain complete while wire values stay unchanged', async ({ page }) => {
  await page.addInitScript(() => localStorage.setItem('admin-locale', 'en'));
  await mockConsole(page, true);
  await page.route(/\/api\/v1\/accounts(?:\?.*)?$/, (route) =>
    route.fulfill({
      json: {
        items: [
          { id: 'acct_active', state: 'active', rowVersion: 1 },
          { id: 'acct_suspended', state: 'suspended', rowVersion: 1 },
          { id: 'acct_denied', state: 'denylisted', rowVersion: 1 }
        ],
        nextCursor: null
      }
    })
  );
  await page.goto('/#accounts');
  await expect(page.getByLabel('Filter by status').locator('option')).toHaveText([
    'All statuses',
    'Active',
    'Suspended',
    'Denylisted'
  ]);
  await expect(page.locator('.user-button small')).toHaveText('Platform Owner');
  await page.getByRole('button', { name: 'Administrators', exact: true }).click();
  const securityIdentity = page.locator('.identity-roles').filter({ hasText: 'Security Admin' });
  await expect(securityIdentity).toContainText('Security Admin');
  await expect(securityIdentity).toContainText('Auditor');
  await page.getByRole('button', { name: 'Add administrator' }).click();
  const editor = page.getByRole('dialog', { name: 'Add administrator' });
  await expect(editor.locator('.role-picker')).toContainText('Platform Owner');
  await expect(editor.locator('.role-picker')).toContainText('Support Operator');
  expect((await editor.innerText()).replace('Camellia', '')).not.toMatch(/[一-龥]/);
});

test('topbar menus handle long identities, outside clicks, checks, and keyboard navigation', async ({
  page
}) => {
  await mockConsole(page, true, {
    user: {
      id: `admin_${'c5231d1b04e9c498d4408e1ec4fe0a'.repeat(2)}`,
      username: 'primary.owner.with.a.long.audit.identifier',
      displayName: 'Primary owner responsible for global licensing operations',
      status: 'active',
      roles: ['platform_owner'],
      rowVersion: 3
    }
  });
  await page.setViewportSize({ width: 1024, height: 768 });
  await page.goto('/');
  await page.getByRole('button', { name: '管理员菜单' }).click();
  const userMenu = page.getByRole('menu');
  await expect(userMenu.getByRole('menuitem', { name: '个人资料' })).toBeFocused();
  expect(
    await userMenu.evaluate((element) => {
      const box = element.getBoundingClientRect();
      return (
        box.left >= 0 &&
        box.right <= window.innerWidth &&
        element.scrollWidth <= element.clientWidth
      );
    })
  ).toBe(true);
  await page.getByRole('heading', { name: '运营总览' }).click();
  await expect(userMenu).not.toBeVisible();

  await page.getByRole('button', { name: '外观与语言' }).click();
  const themeMenu = page.getByRole('menu');
  await expect(themeMenu.locator('.menu-check svg')).toHaveCount(2);
  await page.keyboard.press('ArrowDown');
  await expect(themeMenu.getByRole('menuitemradio', { name: '浅色' })).toBeFocused();
  await themeMenu.getByRole('menuitemradio', { name: '深色' }).click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  await page.getByRole('button', { name: '外观与语言' }).click();
  await page.getByRole('menuitemradio', { name: '特大' }).click();
  await expect(page.locator('html')).toHaveAttribute('data-font-size', 'extra-large');
  await expect
    .poll(() => page.locator('html').evaluate((element) => getComputedStyle(element).fontSize))
    .toBe('20px');
  await page.getByRole('button', { name: '外观与语言' }).click();
  await expect(page.getByRole('menu').locator('.menu-check svg')).toHaveCount(2);
  await page.keyboard.press('Escape');
  await expect(page.getByRole('button', { name: '外观与语言' })).toBeFocused();
});

test('font scale and localization remain usable at supported compact boundaries', async ({
  page
}) => {
  await page.addInitScript(() => {
    localStorage.setItem('admin-font-size', 'extra-large');
    localStorage.setItem('admin-locale', 'en');
  });
  await mockConsole(page, true, {
    user: {
      id: 'admin_compact',
      username: 'owner.with.long.audit.identifier',
      displayName: 'Global licensing operations owner',
      status: 'active',
      roles: ['platform_owner'],
      rowVersion: 1
    }
  });

  for (const viewport of [
    { width: 360, height: 640 },
    { width: 768, height: 1024 },
    { width: 1366, height: 768 }
  ]) {
    await page.setViewportSize(viewport);
    await page.goto('/#accounts');
    await expect(page.locator('html')).toHaveAttribute('data-font-size', 'extra-large');
    await expect(page.locator('html')).toHaveAttribute('lang', 'en');
    const geometry = await page.evaluate(() => ({
      overflow: document.documentElement.scrollWidth - window.innerWidth,
      rootFontSize: getComputedStyle(document.documentElement).fontSize,
      tableScrollable: (() => {
        const table = document.querySelector<HTMLElement>('.table-shell');
        return Boolean(table && table.scrollWidth > table.clientWidth);
      })()
    }));
    expect(geometry.overflow).toBeLessThanOrEqual(1);
    expect(geometry.rootFontSize).toBe('20px');
    if (viewport.width === 360) expect(geometry.tableScrollable).toBe(true);
  }

  await page.setViewportSize({ width: 320, height: 568 });
  await page.goto('/#accounts');
  expect(
    await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)
  ).toBeLessThanOrEqual(1);
  await expect(page.locator('.table-shell')).toBeVisible();
});

test('all text sizes persist and the self-hosted typography remains crisp and stable', async ({
  page
}) => {
  await mockConsole(page, true);
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto('/');

  for (const [label, value, pixels] of [
    ['标准', 'standard', '16px'],
    ['大', 'large', '18px'],
    ['特大', 'extra-large', '20px']
  ] as const) {
    await page.getByRole('button', { name: '外观与语言' }).click();
    await page.getByRole('menuitemradio', { name: label, exact: true }).click();
    await expect(page.locator('html')).toHaveAttribute('data-font-size', value);
    await expect
      .poll(() => page.locator('html').evaluate((element) => getComputedStyle(element).fontSize))
      .toBe(pixels);
    expect(await page.evaluate(() => localStorage.getItem('admin-font-size'))).toBe(value);
    await page.reload();
    await expect(page.locator('html')).toHaveAttribute('data-font-size', value);
  }

  await expect
    .poll(() =>
      page.evaluate(() =>
        performance
          .getEntriesByType('resource')
          .some((entry) => entry.name.includes('inter-latin-opsz-normal'))
      )
    )
    .toBe(true);
  const typography = await page.evaluate(async () => {
    await document.fonts.load('400 1rem "Inter Variable"', 'Camellia 0123456789');
    const bodyStyle = getComputedStyle(document.body);
    const measure = (text: string) => {
      const element = document.createElement('span');
      element.textContent = text;
      element.style.cssText =
        'position:absolute;visibility:hidden;font:400 1rem "Inter Variable";font-variant-numeric:tabular-nums';
      document.body.append(element);
      const width = element.getBoundingClientRect().width;
      element.remove();
      return width;
    };
    return {
      family: bodyStyle.fontFamily,
      synthesis: bodyStyle.fontSynthesis,
      numeric: bodyStyle.fontVariantNumeric,
      oneWidth: measure('11111111'),
      eightWidth: measure('88888888')
    };
  });
  expect(typography.family).toContain('Inter Variable');
  expect(typography.family).toContain('Noto Sans SC');
  expect(typography.family).toContain('PingFang SC');
  expect(typography.family).toContain('Microsoft YaHei UI');
  expect(typography.synthesis).toBe('none');
  expect(typography.numeric).toContain('tabular-nums');
  expect(Math.abs(typography.oneWidth - typography.eightWidth)).toBeLessThanOrEqual(0.1);
});

test('shell, toolbars and tables honor the supported viewport boundaries', async ({
  page
}, testInfo) => {
  await mockConsole(page, true);
  const widths = [360, 390, 430, 600, 601, 768, 960, 961, 1024, 1280, 1440, 1920];
  for (const width of widths) {
    await page.setViewportSize({ width, height: width <= 430 ? 640 : 900 });
    await page.goto('/#accounts');
    await expect(page.getByRole('heading', { name: '账户', exact: true })).toBeVisible();
    const layout = await page.evaluate(() => {
      const toolbar = document.querySelector<HTMLElement>('.resource-toolbar')!;
      const toolbarBounds = toolbar.getBoundingClientRect();
      const controls = [
        ...toolbar.querySelectorAll<HTMLElement>('.search-field, .filter-select, .icon-button')
      ].map((control) => control.getBoundingClientRect());
      const table = document.querySelector<HTMLElement>('.table-shell')!;
      return {
        documentOverflow: document.documentElement.scrollWidth - innerWidth,
        bodyOverflow: document.body.scrollWidth - innerWidth,
        toolbarOverflow: toolbar.scrollWidth - toolbar.clientWidth,
        toolbarDirection: getComputedStyle(toolbar).flexDirection,
        controlsInside: controls.every(
          (control) =>
            control.left >= toolbarBounds.left - 1 && control.right <= toolbarBounds.right + 1
        ),
        tableInside: table.getBoundingClientRect().right <= innerWidth + 1
      };
    });
    expect(layout.documentOverflow, `document overflow at ${width}px`).toBeLessThanOrEqual(1);
    expect(layout.bodyOverflow, `body overflow at ${width}px`).toBeLessThanOrEqual(1);
    expect(layout.toolbarOverflow, `toolbar overflow at ${width}px`).toBeLessThanOrEqual(1);
    expect(layout.controlsInside, `toolbar controls at ${width}px`).toBe(true);
    expect(layout.tableInside, `table scrollport at ${width}px`).toBe(true);
    if (width === 600) expect(layout.toolbarDirection).toBe('column');
    if (width === 601) expect(layout.toolbarDirection).toBe('row');
    if (width === 960) await expect(page.getByRole('button', { name: '打开导航' })).toBeVisible();
    if (width === 961) await expect(page.getByRole('button', { name: '打开导航' })).toBeHidden();
  }

  for (const [width, theme] of [
    [360, 'dark'],
    [768, 'light'],
    [1440, 'dark']
  ] as const) {
    await page.setViewportSize({ width, height: width === 360 ? 640 : 900 });
    await page.evaluate((nextTheme) => {
      localStorage.setItem('admin-theme', nextTheme);
      document.documentElement.dataset.theme = nextTheme;
    }, theme);
    for (const [hash, heading] of [
      ['#team', 'Team 工作区'],
      ['#billing', '账单与付款'],
      ['#administrators', '管理员身份'],
      ['#system', '系统状态']
    ] as const) {
      await page.goto(`/${hash}`);
      await expect(page.getByRole('heading', { name: heading, exact: true })).toBeVisible();
      expect(
        await page.evaluate(() => document.documentElement.scrollWidth - innerWidth),
        `${heading} overflow at ${width}px`
      ).toBeLessThanOrEqual(1);
    }
    await page.screenshot({
      path: testInfo.outputPath(`viewport-${width}-${theme}.png`),
      fullPage: true
    });
  }
});

test('long dialogs keep their title, close and confirmation actions reachable in low landscape', async ({
  page
}) => {
  await mockConsole(page, true);
  await page.setViewportSize({ width: 760, height: 360 });
  await page.goto('/#codes');
  await page.getByRole('button', { name: '新建' }).click();
  const dialog = page.getByRole('dialog');
  const card = dialog;
  const assertReachable = async () => {
    const layout = await card.evaluate((element) => {
      const bounds = element.getBoundingClientRect();
      const header = element.querySelector<HTMLElement>(':scope > header')!.getBoundingClientRect();
      const footer = element.querySelector<HTMLElement>(':scope > footer')!.getBoundingClientRect();
      return {
        top: bounds.top,
        bottom: bounds.bottom,
        scrollable: element.scrollHeight > element.clientHeight,
        headerVisible: header.top >= bounds.top - 1 && header.bottom <= bounds.bottom + 1,
        footerVisible: footer.top >= bounds.top - 1 && footer.bottom <= bounds.bottom + 1
      };
    });
    expect(layout.top).toBeGreaterThanOrEqual(0);
    expect(layout.bottom).toBeLessThanOrEqual(360);
    expect(layout.scrollable).toBe(true);
    expect(layout.headerVisible).toBe(true);
    expect(layout.footerVisible).toBe(true);
  };
  await assertReachable();
  await card.evaluate((element) => {
    element.scrollTop = element.scrollHeight / 2;
  });
  await assertReachable();
  await expect(dialog.getByRole('button', { name: '关闭' })).toBeInViewport();
  await expect(dialog.getByRole('button', { name: '确认创建' })).toBeInViewport();
});

test('self-service profile and password changes preserve audit and session boundaries', async ({
  page
}) => {
  await mockConsole(page, true);
  let profileRequest: Record<string, unknown> | undefined;
  const passwordOperations: string[] = [];
  let passwordAttempts = 0;
  await page.route('**/api/v1/admin-users/admin_01', async (route) => {
    profileRequest = route.request().postDataJSON();
    expect(route.request().headers()['if-match']).toBe('3');
    expect(route.request().headers()['idempotency-key']).toBeTruthy();
    return route.fulfill({
      json: {
        id: 'admin_01',
        username: 'operator',
        displayName: 'Primary operations',
        status: 'active',
        roles: ['platform_owner'],
        rowVersion: 4
      }
    });
  });
  await page.route('**/api/v1/auth/password', async (route) => {
    passwordOperations.push(route.request().headers()['idempotency-key']);
    expect(route.request().headers()['if-match']).toBe('4');
    passwordAttempts += 1;
    if (passwordAttempts === 1) {
      return route.fulfill({
        status: 422,
        json: {
          code: 'admin_password_invalid',
          field: 'newPassword',
          message: 'new password must differ from the current password'
        }
      });
    }
    return route.fulfill({ status: 204 });
  });

  await page.goto('/');
  await page.getByRole('button', { name: '管理员菜单' }).click();
  await page.getByRole('menuitem', { name: '个人资料' }).click();
  const profile = page.getByRole('dialog', { name: '个人资料' });
  await expect(profile.getByLabel('登录用户名')).toBeDisabled();
  await profile.getByLabel('显示名称').fill('Primary operations');
  await profile.getByLabel('操作原因').fill('align the operator display name');
  await profile.getByRole('button', { name: '保存资料' }).click();
  await expect(profile).not.toBeVisible();
  await expect(page.getByRole('button', { name: '管理员菜单' })).toBeFocused();
  expect(profileRequest).toEqual({
    displayName: 'Primary operations',
    reason: 'align the operator display name'
  });

  await page.getByRole('button', { name: '管理员菜单' }).click();
  await page.getByRole('menuitem', { name: '修改密码' }).click();
  const password = page.getByRole('dialog', { name: '修改密码' });
  await password.getByRole('textbox', { name: /^新密码 使用/ }).fill('Distant-Cedar-94!River');
  await password.getByRole('textbox', { name: /^确认新密码/ }).fill('Different-Cedar-94!River');
  await expect(password.getByText('两次输入的新密码不一致')).toBeVisible();
  await expect(password.getByRole('button', { name: '修改密码' })).toBeDisabled();
  await password.getByRole('textbox', { name: /^确认新密码/ }).fill('Distant-Cedar-94!River');
  await password.getByLabel('操作原因').fill('scheduled credential rotation');
  await password.getByRole('button', { name: '修改密码' }).click();
  await expect(password.getByText('新密码不符合要求，或与当前密码相同。')).toBeVisible();
  await password.getByRole('button', { name: '修改密码' }).click();
  await expect(page.getByRole('heading', { name: '欢迎回来' })).toBeVisible();
  expect(passwordOperations).toHaveLength(2);
  expect(passwordOperations[0]).not.toBe(passwordOperations[1]);
});

test('stale profile and resource versions reload authoritative state before retry', async ({
  page
}) => {
  await mockConsole(page, true);
  let sessionReads = 0;
  let accountChanged = false;
  await page.route('**/api/v1/auth/me', (route) => {
    sessionReads += 1;
    const refreshed = sessionReads > 1;
    return route.fulfill({
      json: {
        user: {
          id: 'admin_01',
          username: 'operator',
          displayName: refreshed ? 'Authoritative operations' : 'Operations',
          status: 'active',
          roles: ['platform_owner'],
          rowVersion: refreshed ? 4 : 3
        },
        permissions: fullPermissions,
        expiresAt: 1999999999,
        elevatedUntil: 1999990000,
        serverVersion: '1.0.1'
      }
    });
  });
  await page.route('**/api/v1/admin-users/admin_01', (route) =>
    route.fulfill({
      status: 412,
      json: { code: 'admin_version_conflict', message: 'resource version conflict' }
    })
  );
  await page.route(/\/api\/v1\/accounts(?:\?.*)?$/, (route) =>
    route.fulfill({
      json: {
        items: [
          {
            id: 'acct_001',
            state: accountChanged ? 'suspended' : 'active',
            note: 'Production tenant',
            createdAt: 1783731600,
            updatedAt: 1783731600,
            rowVersion: accountChanged ? 3 : 2
          }
        ],
        nextCursor: null
      }
    })
  );
  await page.route('**/api/v1/accounts/acct_001/actions/set-state', (route) => {
    accountChanged = true;
    return route.fulfill({
      status: 412,
      json: { code: 'admin_version_conflict', message: 'resource version conflict' }
    });
  });

  await page.goto('/');
  await page.getByRole('button', { name: '管理员菜单' }).click();
  await page.getByRole('menuitem', { name: '个人资料' }).click();
  let dialog = page.getByRole('dialog', { name: '个人资料' });
  await dialog.getByLabel('显示名称').fill('Stale local value');
  await dialog.getByLabel('操作原因').fill('test optimistic concurrency');
  await dialog.getByRole('button', { name: '保存资料' }).click();
  await expect(
    dialog.getByText('账户资料已在其他会话中更新。已加载最新状态，请复核后重试。')
  ).toBeVisible();
  await expect(dialog.getByLabel('显示名称')).toHaveValue('Authoritative operations');
  await expect(dialog.getByLabel('操作原因')).toHaveValue('');
  await dialog.locator('header button').click();

  await page.getByRole('button', { name: '账户', exact: true }).click();
  await page.getByRole('button', { name: '管理', exact: true }).click();
  dialog = page.getByRole('dialog');
  await dialog.getByLabel('账户状态').selectOption('suspended');
  await dialog.getByLabel('原因').fill('test optimistic concurrency');
  await dialog.getByRole('button', { name: '应用变更' }).click();
  await expect(
    dialog.getByText('资源已在其他会话中更新。已加载最新状态，请复核后重试。')
  ).toBeVisible();
  await expect(dialog.getByLabel('账户状态')).toHaveValue('');
  await expect(dialog.getByLabel('原因')).toHaveValue('');
});

test('resource selectors cascade and license plan changes keep Team seats conditional', async ({
  page
}) => {
  await mockConsole(page, true);
  let planRequest: Record<string, unknown> | undefined;
  await page.route('**/api/v1/licenses/lic_001/actions/set-plan', async (route) => {
    expect(route.request().headers()['if-match']).toBe('"4"');
    planRequest = route.request().postDataJSON();
    return route.fulfill({
      json: {
        id: 'lic_001',
        accountId: 'acct_001',
        plan: 'team',
        planRevision: 2,
        status: 'active',
        expiresAt: null,
        licenseEpoch: 2,
        purchasedSeats: 5,
        rowVersion: 5
      }
    });
  });

  await page.goto('/#codes');
  await page.getByRole('button', { name: '新建' }).click();
  const createCode = page.getByRole('dialog');
  await createCode.getByLabel('账户 ID').click();
  await createCode.getByRole('option', { name: /acct_001/ }).click();
  await createCode.getByLabel('授权 ID').click();
  await createCode.getByRole('option', { name: /lic_001/ }).click();
  await expect(createCode.getByLabel('授权 ID')).toHaveValue('lic_001');
  await createCode.getByLabel('账户 ID').fill('acct_other');
  await expect(createCode.getByLabel('授权 ID')).toHaveValue('');
  await createCode.getByRole('button', { name: '关闭' }).click();

  await page.getByRole('button', { name: '授权', exact: true }).click();
  await page.getByRole('button', { name: '管理', exact: true }).click();
  const manage = page.getByRole('dialog');
  await manage.getByLabel('授权变更项目').selectOption('plan');
  await manage.getByLabel('授权套餐').selectOption('team');
  await expect(manage.getByLabel('Team 席位')).toHaveAttribute('min', '3');
  await expect(manage.getByLabel('Team 席位')).toHaveAttribute('max', '10000');
  await manage.getByLabel('Team 席位').fill('5');
  await manage.getByLabel('操作原因').fill('approved Team upgrade');
  await manage.getByRole('button', { name: '应用变更' }).click();
  await expect(manage).not.toBeVisible();
  expect(planRequest).toEqual({
    plan: 'team',
    purchasedSeats: 5,
    reason: 'approved Team upgrade'
  });
});

test('dialog focus is contained and restored to its trigger', async ({ page }) => {
  await mockConsole(page, true);
  await page.goto('/#team');
  const trigger = page.getByRole('button', { name: '创建邀请' });
  await trigger.click();
  const dialog = page.getByRole('dialog', { name: '邀请工作区成员' });
  const selects = dialog.locator('select');
  await expect(selects.first()).toBeFocused();
  await expect(selects.first()).toHaveAttribute('data-option-align', 'start');
  await expect(selects.first()).toHaveCSS('text-align', 'start');
  await expect(selects.first()).toHaveCSS('appearance', 'base-select');
  await expect(selects.first()).toHaveCSS('align-items', 'center');
  await expect(selects.nth(1)).toHaveAttribute('data-option-align', 'center');
  await expect(selects.nth(1)).toHaveCSS('text-align', 'center');
  await expect(selects.nth(1)).toHaveCSS('appearance', 'base-select');
  const cancel = dialog.getByRole('button', { name: '取消' });
  await cancel.focus();
  await page.keyboard.press('Tab');
  await expect(dialog.locator('header button')).toBeFocused();
  await page.keyboard.press('Escape');
  await expect(dialog).not.toBeVisible();
  await expect(trigger).toBeFocused();
});

test('team invitation retries keep the same commercial operation', async ({ page }) => {
  await mockConsole(page, true);
  const operationIds: string[] = [];
  let attempts = 0;
  await page.route('**/api/v1/team-workspaces/acct_team/invitations', async (route) => {
    operationIds.push(route.request().headers()['idempotency-key']);
    attempts += 1;
    if (attempts === 1) return route.abort('connectionreset');
    return route.fulfill({
      json: {
        invitation: {
          id: 'invite_01',
          memberId: 'member_01',
          email: 'member@example.com',
          displayName: 'Member',
          role: 'viewer',
          expiresAt: 1999999999
        },
        delivery: { id: 'delivery_team', claimToken: 'team-claim-token', expiresAt: 1999999999 },
        acknowledgementRequired: true
      }
    });
  });
  await page.route('**/api/v1/secret-deliveries/delivery_team/claim', (route) =>
    route.fulfill({ json: { invitationToken: 'team-invitation-token' } })
  );
  await page.route('**/api/v1/secret-deliveries/delivery_team/acknowledge', (route) =>
    route.fulfill({ status: 204 })
  );
  await page.goto('/#team');
  await expect(page.getByRole('heading', { name: 'Team 工作区' })).toBeVisible();
  await page.getByRole('button', { name: '创建邀请' }).click();
  const dialog = page.getByRole('dialog');
  await dialog.getByLabel('邮箱').fill('member@example.com');
  await dialog.getByLabel('显示名称').fill('Member');
  await dialog.getByLabel('操作原因').fill('add licensed team member');
  await dialog.getByRole('button', { name: '创建邀请' }).click();
  await expect(dialog.locator('.form-error')).toBeVisible();
  await dialog.getByRole('button', { name: '创建邀请' }).click();
  await expect(dialog.getByText('team-invitation-token')).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(dialog).toBeVisible();
  await expect(dialog.locator('header button')).toBeDisabled();
  expect(operationIds).toHaveLength(2);
  expect(operationIds[0]).toBe(operationIds[1]);
  await dialog.getByRole('button', { name: '已安全保存并销毁交付' }).click();
  await expect(dialog).not.toBeVisible();
});

test('team ownership transfer is confirmed and retry safe', async ({ page }) => {
  await mockConsole(page, true);
  const operationIds: string[] = [];
  let attempts = 0;
  await page.route(/\/api\/v1\/team-workspaces\/acct_team\/members(?:\?.*)?$/, (route) =>
    route.fulfill({
      json: {
        items: [
          {
            id: 'member_owner',
            email: 'owner@example.com',
            displayName: 'Current owner',
            role: 'owner',
            status: 'active',
            rowVersion: 4,
            profilePending: false
          },
          {
            id: 'member_next',
            email: 'next@example.com',
            displayName: 'Next owner',
            role: 'admin',
            status: 'active',
            rowVersion: 7,
            profilePending: false
          },
          {
            id: 'member_suspended',
            email: 'suspended@example.com',
            displayName: 'Suspended admin',
            role: 'admin',
            status: 'suspended',
            rowVersion: 2,
            profilePending: false
          },
          {
            id: 'member_viewer',
            email: 'viewer@example.com',
            displayName: 'Active viewer',
            role: 'viewer',
            status: 'active',
            rowVersion: 1,
            profilePending: false
          }
        ]
      }
    })
  );
  await page.route(/\/api\/v1\/team-workspaces\/acct_team\/invitations(?:\?.*)?$/, (route) =>
    route.fulfill({ json: { items: [] } })
  );
  await page.route(
    '**/api/v1/team-workspaces/acct_team/members/member_next/actions/transfer-ownership',
    async (route) => {
      operationIds.push(route.request().headers()['idempotency-key']);
      expect(route.request().headers()['if-match']).toBe('7');
      expect(route.request().postDataJSON()).toEqual({ reason: 'approved succession' });
      attempts += 1;
      if (attempts === 1) return route.abort('connectionreset');
      return route.fulfill({
        json: {
          id: 'member_next',
          email: 'next@example.com',
          displayName: 'Next owner',
          role: 'owner',
          status: 'active',
          rowVersion: 8,
          profilePending: false,
          previousOwnerId: 'member_owner'
        }
      });
    }
  );
  await page.goto('/#team');
  await page.getByRole('button', { name: '管理', exact: true }).click();
  const workspace = page.getByRole('dialog');
  await workspace.getByLabel('变更原因').fill('approved succession');
  await expect(workspace.getByRole('button', { name: '转让所有权' })).toHaveCount(1);
  await workspace.getByRole('button', { name: '转让所有权' }).click();
  const confirmation = page.getByRole('alertdialog');
  await expect(confirmation.getByText('Next owner 将成为唯一所有者')).toBeVisible();
  await confirmation.getByRole('button', { name: '确认转让' }).click();
  await expect(confirmation.locator('.form-error')).toBeVisible();
  await confirmation.getByRole('button', { name: '确认转让' }).click();
  await expect(confirmation).not.toBeVisible();
  expect(operationIds).toHaveLength(2);
  expect(operationIds[0]).toBe(operationIds[1]);
});

test('Team member drafts require an explicit save and stay orderly across responsive states', async ({
  page
}, testInfo) => {
  await mockConsole(page, true);
  const longName = 'Production billing viewer with an exceptionally long operational identity';
  let updated = false;
  let submitted: Record<string, unknown> | undefined;
  await page.route(/\/api\/v1\/team-workspaces\/acct_team\/members(?:\?.*)?$/, (route) =>
    route.fulfill({
      json: {
        items: [
          {
            id: 'member_owner',
            email: 'owner@example.com',
            displayName: 'Current owner',
            role: 'owner',
            status: 'active',
            rowVersion: 4,
            profilePending: false
          },
          {
            id: 'member_long',
            email: 'billing.viewer.with.a.long.address@example.com',
            displayName: longName,
            role: updated ? 'operator' : 'viewer',
            status: updated ? 'suspended' : 'active',
            rowVersion: updated ? 6 : 5,
            profilePending: false
          }
        ],
        nextCursor: null
      }
    })
  );
  await page.route(/\/api\/v1\/team-workspaces\/acct_team\/invitations(?:\?.*)?$/, (route) =>
    route.fulfill({
      json: {
        items: [
          {
            id: 'invitation_long',
            memberId: 'member_invited',
            email: 'pending.member.with.a.long.address@example.com',
            displayName: 'Pending member',
            role: 'auditor',
            expiresAt: 1999999999,
            acceptedAt: null,
            revokedAt: null,
            createdAt: 1900000000
          }
        ],
        nextCursor: null
      }
    })
  );
  await page.route(
    '**/api/v1/team-workspaces/acct_team/members/member_long/actions/update',
    async (route) => {
      expect(route.request().headers()['if-match']).toBe('5');
      submitted = route.request().postDataJSON();
      updated = true;
      return route.fulfill({ json: { id: 'member_long', rowVersion: 6 } });
    }
  );

  await page.setViewportSize({ width: 1180, height: 900 });
  await page.goto('/#team');
  await page.getByRole('button', { name: '管理', exact: true }).click();
  const workspace = page.getByRole('dialog', { name: 'acct_team' });
  const member = workspace.locator('.member-row').filter({ hasText: longName });
  await expect(member).toBeVisible();
  await expect(member.getByRole('button', { name: '保存' })).toBeDisabled();
  await expect(member.getByRole('button', { name: '撤销更改' })).toBeDisabled();
  await expect(
    workspace.locator('.member-row').filter({ hasText: 'Current owner' }).locator('select')
  ).toHaveCount(0);
  await expect(workspace.locator('.invitation-row')).toContainText('审计员');
  await expect(workspace.locator('.invitation-row')).toContainText('待接受');

  await member.getByLabel(`${longName} 的角色`).selectOption('operator');
  await expect(member.getByRole('button', { name: '撤销更改' })).toBeEnabled();
  await member.getByRole('button', { name: '撤销更改' }).click();
  await expect(member.getByLabel(`${longName} 的角色`)).toHaveValue('viewer');
  await member.getByLabel(`${longName} 的角色`).selectOption('operator');
  await member.getByLabel(`${longName} 的状态`).selectOption('suspended');
  await expect(member.getByRole('button', { name: '保存' })).toBeDisabled();
  await workspace.getByLabel('变更原因').fill('align operational responsibilities');
  await expect(member.getByRole('button', { name: '保存' })).toBeEnabled();

  const wideLayout = await member.evaluate((element) => ({
    columns: getComputedStyle(element).gridTemplateColumns.split(' ').length,
    overflow: element.scrollWidth - element.clientWidth
  }));
  expect(wideLayout.columns).toBe(3);
  expect(wideLayout.overflow).toBeLessThanOrEqual(1);
  await member.screenshot({ path: testInfo.outputPath('team-member-wide.png') });
  await page.setViewportSize({ width: 700, height: 860 });
  const compactLayout = await member.evaluate((element) => ({
    columns: getComputedStyle(element).gridTemplateColumns.split(' ').length,
    overflow: element.scrollWidth - element.clientWidth,
    controls: [...element.querySelectorAll<HTMLElement>('button, select')].map((control) => {
      const bounds = control.getBoundingClientRect();
      const owner = element.getBoundingClientRect();
      return bounds.left >= owner.left - 1 && bounds.right <= owner.right + 1;
    })
  }));
  expect(compactLayout.columns).toBe(1);
  expect(compactLayout.overflow).toBeLessThanOrEqual(1);
  expect(compactLayout.controls.every(Boolean)).toBe(true);
  await member.screenshot({ path: testInfo.outputPath('team-member-compact.png') });

  await member.getByRole('button', { name: '保存' }).click();
  expect(submitted).toEqual({
    role: 'operator',
    status: 'suspended',
    reason: 'align operational responsibilities'
  });
  const refreshed = workspace.locator('.member-row').filter({ hasText: longName });
  await expect(refreshed.getByLabel(`${longName} 的角色`)).toHaveValue('operator');
  await expect(refreshed.getByLabel(`${longName} 的状态`)).toHaveValue('suspended');
  await expect(refreshed.getByRole('button', { name: '保存' })).toBeDisabled();
});

test('primary Team Owner placeholder is completed once with field validation', async ({ page }) => {
  await mockConsole(page, true);
  let completed = false;
  let submitted: Record<string, unknown> | undefined;
  await page.route(/\/api\/v1\/team-workspaces\/acct_team\/members(?:\?.*)?$/, (route) =>
    route.fulfill({
      json: {
        items: [
          {
            id: 'member_owner_8d9f1d2f0c6a4c2399f6f19268dc1040',
            email: completed
              ? 'owner@example.com'
              : 'owner+8d9f1d2f0c6a4c2399f6f19268dc1040@local.invalid',
            displayName: completed ? 'Primary owner' : 'acct_team',
            role: 'owner',
            status: 'active',
            rowVersion: completed ? 2 : 1,
            profilePending: !completed
          }
        ],
        nextCursor: null
      }
    })
  );
  await page.route(/\/api\/v1\/team-workspaces\/acct_team\/invitations(?:\?.*)?$/, (route) =>
    route.fulfill({ json: { items: [], nextCursor: null } })
  );
  await page.route('**/actions/complete-owner-profile', async (route) => {
    expect(route.request().headers()['if-match']).toBe('1');
    submitted = route.request().postDataJSON();
    completed = true;
    return route.fulfill({
      json: {
        id: 'member_owner_8d9f1d2f0c6a4c2399f6f19268dc1040',
        email: 'owner@example.com',
        displayName: 'Primary owner',
        role: 'owner',
        status: 'active',
        rowVersion: 2,
        profilePending: false
      }
    });
  });

  await page.goto('/#team');
  await page.getByRole('button', { name: '管理', exact: true }).click();
  await page.getByRole('button', { name: '完善所有者资料' }).click();
  const dialog = page.getByRole('dialog', { name: '完善首位所有者资料' });
  await dialog.getByLabel('邮箱').fill('invalid-address');
  await dialog.getByLabel('显示名称').fill('Primary owner');
  await dialog.getByLabel('操作原因').fill('replace the initialization placeholder');
  await expect(dialog.getByRole('button', { name: '完成资料' })).toBeDisabled();
  await dialog.getByLabel('邮箱').fill('owner@example.com');
  await dialog.getByRole('button', { name: '完成资料' }).click();
  await expect(dialog).not.toBeVisible();
  expect(submitted).toEqual({
    email: 'owner@example.com',
    displayName: 'Primary owner',
    reason: 'replace the initialization placeholder'
  });
  await expect(page.getByRole('button', { name: '完善所有者资料' })).toHaveCount(0);
});

test('read-only administrators can inspect resources without mutation controls', async ({
  page
}) => {
  await mockConsole(page, true, {
    permissions: [
      'account.read',
      'license.read',
      'code.read',
      'device.read',
      'team.read',
      'billing.read',
      'audit.read',
      'system.read'
    ]
  });
  await page.goto('/#accounts');
  await expect(page.getByRole('heading', { name: '账户', exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: '新建' })).toHaveCount(0);
  await expect(page.getByRole('button', { name: '管理', exact: true })).toHaveCount(0);

  await page.getByRole('button', { name: 'Team 工作区', exact: true }).click();
  await expect(page.getByRole('button', { name: '创建邀请' })).toHaveCount(0);
  await page.getByRole('button', { name: '管理', exact: true }).click();
  const workspace = page.getByRole('dialog');
  await expect(workspace.getByLabel('变更原因')).toHaveCount(0);
  await expect(workspace.getByRole('button', { name: '保存' })).toHaveCount(0);
});

test('scoped operators only receive state and billing controls they are authorized to use', async ({
  page
}) => {
  await mockConsole(page, true, {
    permissions: [
      'account.read',
      'account.denylist',
      'device.read',
      'device.security',
      'billing.read',
      'billing.review',
      'billing.override',
      'system.read'
    ]
  });
  await page.route(/\/api\/v1\/devices(?:\?.*)?$/, (route) =>
    route.fulfill({
      json: {
        items: [
          {
            deviceId: 'device_01',
            accountId: 'acct_001',
            state: 'active',
            platform: 'windows',
            lastSeenAt: 1900000000,
            rowVersion: 4
          }
        ],
        nextCursor: null
      }
    })
  );
  await page.route(/\/api\/v1\/billing\/payment-claims(?:\?.*)?$/, (route) =>
    route.fulfill({
      json: {
        items: [
          {
            id: 'claim_scoped',
            rowVersion: 1,
            invoiceId: 'invoice_scoped',
            paidAmount: '199.00',
            paidAsset: 'USD',
            externalTransactionId: 'bank-scoped-001',
            status: 'submitted',
            createdAt: 1900000000
          }
        ]
      }
    })
  );
  await page.route('**/api/v1/billing/payment-claims/claim_scoped/evidence', (route) =>
    route.fulfill({ json: { items: [] } })
  );

  await page.goto('/#accounts');
  await page.getByRole('button', { name: '管理', exact: true }).click();
  let dialog = page.getByRole('dialog');
  await expect(dialog.getByLabel('账户状态').locator('option')).toHaveText([
    '请选择允许的状态变更',
    '已封禁'
  ]);
  await dialog.locator('header button').click();

  await page.getByRole('button', { name: '设备', exact: true }).click();
  await page.getByRole('button', { name: '管理', exact: true }).click();
  dialog = page.getByRole('dialog');
  await expect(dialog.getByLabel('设备状态').locator('option')).toHaveText([
    '请选择允许的状态变更',
    '已撤销',
    '可疑'
  ]);
  await dialog.locator('header button').click();

  await page.getByRole('button', { name: '账单与付款', exact: true }).click();
  await expect(page.getByRole('button', { name: '新建账单' })).toHaveCount(0);
  await page.getByRole('button', { name: '管理', exact: true }).click();
  dialog = page.getByRole('dialog');
  await expect(dialog.getByLabel('补充证据')).toHaveCount(0);
  await expect(dialog.getByRole('checkbox', { name: /允许金额或资产不完全匹配/ })).toBeVisible();
  await dialog.getByLabel('审核决定').selectOption('reject');
  await expect(dialog.getByRole('checkbox', { name: /允许金额或资产不完全匹配/ })).toHaveCount(0);
});

test('Team control-plane pages append members and workspaces', async ({ page }) => {
  await mockConsole(page, true);
  await page.route('**/api/v1/team-workspaces*', async (route) => {
    const url = new URL(route.request().url());
    if (url.pathname !== '/api/v1/team-workspaces') return route.fallback();
    if (url.searchParams.get('cursor')) {
      return route.fulfill({
        json: {
          items: [
            {
              accountId: 'acct_team_next',
              licenseId: 'lic_team_next',
              purchasedSeats: 20,
              occupiedMembers: 4,
              activeMembers: 3,
              memberCount: 5
            }
          ],
          nextCursor: null
        }
      });
    }
    return route.fulfill({
      json: {
        items: [
          {
            accountId: 'acct_team',
            licenseId: 'lic_team',
            purchasedSeats: 10,
            occupiedMembers: 2,
            activeMembers: 2,
            memberCount: 2
          }
        ],
        nextCursor: 'lic_team'
      }
    });
  });
  await page.route('**/api/v1/team-workspaces/acct_team/members*', async (route) => {
    const cursor = new URL(route.request().url()).searchParams.get('cursor');
    if (cursor) {
      return route.fulfill({
        json: {
          items: [
            {
              id: 'member_viewer',
              email: 'viewer@example.com',
              displayName: 'Paged viewer',
              role: 'viewer',
              status: 'active',
              rowVersion: 2,
              profilePending: false
            }
          ],
          nextCursor: null
        }
      });
    }
    return route.fulfill({
      json: {
        items: [
          {
            id: 'member_owner',
            email: 'owner@example.com',
            displayName: 'Current owner',
            role: 'owner',
            status: 'active',
            rowVersion: 4,
            profilePending: false
          }
        ],
        nextCursor: 'member_owner'
      }
    });
  });
  await page.goto('/#team');
  await expect(page.getByText('acct_team_next')).toHaveCount(0);
  await page.getByRole('button', { name: '加载更多工作区' }).click();
  await expect(page.getByText('acct_team_next')).toBeVisible();
  await page.getByRole('button', { name: '管理', exact: true }).first().click();
  const workspace = page.getByRole('dialog');
  await expect(workspace.getByText('Paged viewer')).toHaveCount(0);
  await workspace.getByRole('button', { name: '加载更多成员' }).click();
  await expect(workspace.getByText('Paged viewer')).toBeVisible();
});

test('invoice retries preserve the original idempotency key', async ({ page }) => {
  await mockConsole(page, true);
  const operationIds: string[] = [];
  let attempts = 0;
  await page.route('**/api/v1/billing/invoices', async (route) => {
    if (route.request().method() !== 'POST') return route.fallback();
    operationIds.push(route.request().headers()['idempotency-key']);
    attempts += 1;
    if (attempts === 1) return route.abort('connectionreset');
    return route.fulfill({
      json: {
        id: 'invoice_retry',
        accountId: 'acct_001',
        licenseId: 'lic_001',
        offerId: 'offer_001',
        plan: 'team',
        planRevision: 2,
        seats: 5,
        durationDays: 365,
        currency: 'USD',
        amountDue: '199.00',
        paymentReference: 'CNX-RETRY',
        status: 'open',
        dueAt: 1999999999,
        paidAt: null,
        createdAt: 1900000000,
        updatedAt: 1900000000
      }
    });
  });
  await page.goto('/#billing');
  await page.getByRole('button', { name: '新建账单' }).click();
  const dialog = page.getByRole('dialog');
  await dialog.getByLabel('账单 ID').fill('invoice_retry');
  await dialog.getByLabel('账户 ID').fill('acct_001');
  await dialog.getByLabel('授权 ID').fill('lic_001');
  await dialog.getByLabel('商业报价').selectOption('offer_001');
  await dialog.getByRole('spinbutton', { name: /^Team 席位/ }).fill('5');
  await dialog.getByLabel('操作原因').fill('issue approved annual invoice');
  await dialog.getByRole('button', { name: '创建账单' }).click();
  await expect(dialog.locator('.form-error')).toBeVisible();
  await dialog.getByRole('button', { name: '创建账单' }).click();
  await expect(dialog).not.toBeVisible();
  expect(operationIds).toHaveLength(2);
  expect(operationIds[0]).toBe(operationIds[1]);
});

test('billing pages append opaque cursor results without repeating the first page', async ({
  page
}) => {
  await mockConsole(page, true);
  const requests: string[] = [];
  await page.route(/\/api\/v1\/billing\/payment-claims(?:\?.*)?$/, (route) => {
    const url = new URL(route.request().url());
    requests.push(url.search);
    const cursor = url.searchParams.get('cursor');
    return route.fulfill({
      json:
        cursor === 'opaque-claim-cursor'
          ? {
              items: [
                {
                  id: 'claim_page_2',
                  rowVersion: 1,
                  invoiceId: 'invoice_page_2',
                  paidAmount: '29.00',
                  paidAsset: 'USD',
                  externalTransactionId: 'bank-page-002',
                  status: 'submitted',
                  createdAt: 1899999999
                }
              ],
              nextCursor: null
            }
          : {
              items: [
                {
                  id: 'claim_page_1',
                  rowVersion: 1,
                  invoiceId: 'invoice_page_1',
                  paidAmount: '19.00',
                  paidAsset: 'USD',
                  externalTransactionId: 'bank-page-001',
                  status: 'submitted',
                  createdAt: 1900000000
                }
              ],
              nextCursor: 'opaque-claim-cursor'
            }
    });
  });

  await page.goto('/#billing');
  await expect(page.getByText('claim_page_1')).toBeVisible();
  await expect(page.getByText('claim_page_2')).toHaveCount(0);
  await page.getByRole('button', { name: '加载更多' }).click();
  await expect(page.getByText('claim_page_1')).toBeVisible();
  await expect(page.getByText('claim_page_2')).toBeVisible();
  await expect(page.getByRole('button', { name: '加载更多' })).toHaveCount(0);
  expect(requests).toHaveLength(2);
  expect(new URLSearchParams(requests[0]).get('pageSize')).toBe('50');
  expect(new URLSearchParams(requests[0]).has('cursor')).toBe(false);
  expect(new URLSearchParams(requests[1]).get('cursor')).toBe('opaque-claim-cursor');
});

test('invoice offer selection keeps plan seats, validation and responsive layout aligned', async ({
  page
}, testInfo) => {
  await mockConsole(page, true);
  await page.route(/\/api\/v1\/accounts\?.*$/, (route) =>
    route.fulfill({
      json: {
        items: [
          {
            id: 'acct_suggestion',
            state: 'suspended',
            note: null,
            createdAt: 1900000000,
            updatedAt: 1900000000,
            rowVersion: 1
          }
        ],
        nextCursor: null
      }
    })
  );
  await page.route(/\/api\/v1\/licenses\?.*$/, (route) =>
    route.fulfill({
      json: {
        items: [
          {
            id: 'lic_suggestion',
            accountId: 'acct_001',
            plan: 'team',
            status: 'past_due',
            expiresAt: null,
            purchasedSeats: 3,
            rowVersion: 1
          }
        ],
        nextCursor: null
      }
    })
  );
  await page.route('**/api/v1/billing/offers?activeOnly=true', (route) =>
    route.fulfill({
      json: [
        {
          id: 'offer_pro',
          rowVersion: 1,
          plan: 'pro',
          planRevision: 2,
          durationDays: 365,
          currency: 'USD',
          baseAmount: '99.00',
          seatAmount: null,
          nameEn: 'Pro annual',
          nameZh: '专业版年付',
          active: true
        },
        {
          id: 'offer_team',
          rowVersion: 1,
          plan: 'team',
          planRevision: 2,
          durationDays: 365,
          currency: 'USD',
          baseAmount: '99.00',
          seatAmount: '20.00',
          nameEn: 'Team annual',
          nameZh: 'Team 年付',
          active: true
        }
      ]
    })
  );
  let attempts = 0;
  let submitted: Record<string, unknown> | undefined;
  await page.route('**/api/v1/billing/invoices', async (route) => {
    if (route.request().method() !== 'POST') return route.fallback();
    attempts += 1;
    submitted = route.request().postDataJSON();
    if (attempts === 1) {
      return route.fulfill({
        status: 422,
        json: {
          code: 'admin_invoice_seats_invalid',
          field: 'seats',
          message: 'Team invoice seats must be between 3 and 10000'
        }
      });
    }
    return route.fulfill({ json: { id: 'invoice_plan_ui' } });
  });

  await page.setViewportSize({ width: 1024, height: 820 });
  await page.goto('/#billing');
  await page.getByRole('button', { name: '新建账单' }).click();
  const dialog = page.getByRole('dialog', { name: '新建商业账单' });
  const accountInput = dialog.getByRole('combobox', { name: '账户 ID' });
  await accountInput.focus();
  await expect(dialog.locator('.resource-combobox-options')).toContainText('已暂停');
  await accountInput.fill('acct_001');
  const licenseInput = dialog.getByRole('combobox', { name: '授权 ID' });
  await licenseInput.focus();
  await expect(dialog.locator('#resource-license-options')).toContainText('逾期');
  const offer = dialog.getByLabel('商业报价');
  await expect(offer.locator('option')).toHaveCount(3);
  await expect(offer).toHaveAttribute('data-option-align', 'start');
  await expect(offer).toHaveCSS('text-align', 'start');
  await expect(dialog.getByRole('spinbutton', { name: /^Team 席位/ })).toHaveCount(0);

  await offer.selectOption('offer_pro');
  await expect(dialog.getByRole('spinbutton', { name: /^Team 席位/ })).toHaveCount(0);
  await expect(dialog.locator('.invoice-offer-summary .total')).toContainText('USD 99.00');

  await offer.selectOption('offer_team');
  const seats = dialog.getByRole('spinbutton', { name: /^Team 席位/ });
  await expect(seats).toHaveValue('3');
  await expect(dialog.locator('.invoice-offer-summary .total')).toContainText('USD 159.00');
  const [seatBounds, dueBounds] = await Promise.all([
    seats.boundingBox(),
    dialog.getByLabel('付款截止').boundingBox()
  ]);
  expect(seatBounds && dueBounds && Math.abs(seatBounds.y - dueBounds.y)).toBeLessThanOrEqual(2);
  await dialog.screenshot({ path: testInfo.outputPath('invoice-team-wide.png') });
  await seats.fill('2');
  await expect(dialog.getByRole('button', { name: '创建账单' })).toBeDisabled();
  await seats.fill('3.5');
  await expect(dialog.locator('.invoice-offer-summary .total')).toContainText('USD —');
  await expect(dialog.getByRole('button', { name: '创建账单' })).toBeDisabled();
  await seats.fill('3');

  await dialog.getByLabel('账单 ID').fill('invoice_plan_ui');
  await dialog.getByLabel('账户 ID').fill('acct_001');
  await dialog.getByLabel('授权 ID').fill('lic_001');
  await dialog.getByLabel('操作原因').fill('approved Team annual order');

  await page.setViewportSize({ width: 390, height: 844 });
  expect(
    await dialog.evaluate((element) => {
      const bounds = element.getBoundingClientRect();
      const controls = [...element.querySelectorAll<HTMLElement>('input, select, textarea, button')]
        .filter((control) => control.offsetParent !== null)
        .map((control) => control.getBoundingClientRect());
      return (
        element.scrollWidth <= element.clientWidth + 1 &&
        controls.every(
          (control) => control.left >= bounds.left - 1 && control.right <= bounds.right + 1
        )
      );
    })
  ).toBe(true);
  await dialog.screenshot({ path: testInfo.outputPath('invoice-team-compact.png') });
  await dialog.evaluate((element) => element.scrollTo({ top: element.scrollHeight }));
  await expect(dialog.getByRole('button', { name: '创建账单' })).toBeVisible();
  await dialog.screenshot({ path: testInfo.outputPath('invoice-team-compact-actions.png') });

  await dialog.getByRole('button', { name: '创建账单' }).click();
  await expect(dialog.getByText('Team 席位必须为 3 至 10,000 的整数。')).toBeVisible();
  await dialog.getByRole('button', { name: '创建账单' }).click();
  await expect(dialog).not.toBeVisible();
  expect(submitted).toMatchObject({ offerId: 'offer_team', seats: 3 });
});

test('payment evidence retries preserve the upload operation', async ({ page }) => {
  await mockConsole(page, true);
  const operationIds: string[] = [];
  let attempts = 0;
  let uploaded = false;
  await page.route(/\/api\/v1\/billing\/payment-claims(?:\?.*)?$/, (route) =>
    route.fulfill({
      json: {
        items: [
          {
            id: 'claim_retry',
            rowVersion: 1,
            invoiceId: 'invoice_retry',
            paidAmount: '199.00',
            paidAsset: 'USD',
            externalTransactionId: 'bank-retry-001',
            status: 'submitted',
            createdAt: 1900000000
          }
        ]
      }
    })
  );
  await page.route('**/api/v1/billing/payment-claims/claim_retry/evidence', async (route) => {
    if (route.request().method() === 'GET') {
      return route.fulfill({
        json: {
          items: uploaded
            ? [
                {
                  id: 'evidence_retry',
                  originalName: 'receipt.png',
                  byteLength: 16,
                  scanStatus: 'clean'
                }
              ]
            : []
        }
      });
    }
    operationIds.push(route.request().headers()['idempotency-key']);
    attempts += 1;
    if (attempts === 1) return route.abort('connectionreset');
    uploaded = true;
    return route.fulfill({
      status: 201,
      json: {
        id: 'evidence_retry',
        claimId: 'claim_retry',
        scanStatus: 'clean',
        object: { id: 'object_retry', status: 'ready' }
      }
    });
  });
  await page.goto('/#billing');
  await page.getByRole('button', { name: '管理', exact: true }).click();
  const dialog = page.getByRole('dialog');
  await dialog.getByLabel('补充证据').setInputFiles({
    name: 'receipt.png',
    mimeType: 'image/png',
    buffer: Buffer.from('89504e470d0a1a0a', 'hex')
  });
  await dialog.getByLabel('审核原因').fill('verify manual payment receipt');
  await dialog.getByRole('button', { name: '上传并扫描' }).click();
  await expect(dialog.locator('.form-error')).toBeVisible();
  await dialog.getByRole('button', { name: '上传并扫描' }).click();
  await expect(dialog.getByText('receipt.png')).toBeVisible();
  await expect(dialog.locator('.evidence-list')).toContainText('安全');
  await expect(dialog.getByLabel('审核原因')).toHaveValue('verify manual payment receipt');
  expect(operationIds).toHaveLength(2);
  expect(operationIds[0]).toBe(operationIds[1]);
});

test('payment review reloads a stale claim and retries with its new row version', async ({
  page
}) => {
  await mockConsole(page, true);
  let claimLoads = 0;
  let evidenceLoads = 0;
  let reviewAttempts = 0;
  const operationIds: string[] = [];
  await page.route(/\/api\/v1\/billing\/payment-claims(?:\?.*)?$/, (route) => {
    claimLoads += 1;
    return route.fulfill({
      json: {
        items: [
          {
            id: 'claim_versioned',
            rowVersion: claimLoads === 1 ? 3 : 4,
            invoiceId: 'invoice_versioned',
            paidAmount: '99.00',
            paidAsset: 'USD',
            externalTransactionId: 'bank-versioned-001',
            status: claimLoads === 1 ? 'submitted' : 'needs_information',
            createdAt: 1900000000
          }
        ]
      }
    });
  });
  await page.route('**/api/v1/billing/payment-claims/claim_versioned/evidence', (route) => {
    evidenceLoads += 1;
    return route.fulfill({ json: { items: [] } });
  });
  await page.route(
    '**/api/v1/billing/payment-claims/claim_versioned/actions/review',
    async (route) => {
      reviewAttempts += 1;
      operationIds.push(route.request().headers()['idempotency-key']);
      expect(route.request().headers()['if-match']).toBe(reviewAttempts === 1 ? '"3"' : '"4"');
      if (reviewAttempts === 1) {
        return route.fulfill({
          status: 409,
          json: { code: 'admin_version_conflict', message: 'payment claim version conflict' }
        });
      }
      return route.fulfill({
        json: {
          id: 'claim_versioned',
          rowVersion: 5,
          status: 'verified'
        }
      });
    }
  );

  await page.goto('/#billing');
  await page.getByRole('button', { name: '管理', exact: true }).click();
  const dialog = page.getByRole('dialog');
  await dialog.getByLabel('审核原因').fill('verify the versioned payment claim');
  await dialog.getByRole('button', { name: '提交审核' }).click();
  await expect(dialog.getByText(/已被其他会话更新/)).toBeVisible();
  await expect(dialog.getByRole('button', { name: '提交审核' })).toBeDisabled();
  await dialog.getByLabel('审核原因').fill('recheck the latest payment claim');
  await dialog.getByRole('button', { name: '提交审核' }).click();
  await expect(dialog).not.toBeVisible();
  expect(evidenceLoads).toBe(2);
  expect(operationIds).toHaveLength(2);
  expect(operationIds[0]).not.toBe(operationIds[1]);
});

test('activation code delivery survives an ambiguous create response', async ({ page }) => {
  await mockConsole(page, true);
  const operationIds: string[] = [];
  let attempts = 0;
  await page.route('**/api/v1/activation-codes', async (route) => {
    if (route.request().method() !== 'POST') return route.fallback();
    operationIds.push(route.request().headers()['idempotency-key']);
    attempts += 1;
    if (attempts === 1) return route.abort('connectionreset');
    return route.fulfill({
      status: 201,
      json: {
        delivery: {
          id: 'delivery_codes',
          claimToken: 'deterministic-claim',
          expiresAt: 1999999999
        },
        count: 1,
        acknowledgementRequired: true
      }
    });
  });
  await page.route('**/api/v1/secret-deliveries/delivery_codes/claim', (route) =>
    route.fulfill({ json: [{ code: 'CNX-TEST-CODE' }] })
  );
  await page.goto('/#codes');
  await page.getByRole('button', { name: '新建' }).click();
  const dialog = page.getByRole('dialog');
  await dialog.getByLabel('账户 ID').fill('acct_001');
  await dialog.getByLabel('授权 ID').fill('lic_001');
  await dialog.getByLabel('操作原因').fill('issue customer activation code');
  await dialog.getByRole('button', { name: '确认创建' }).click();
  await expect(dialog.locator('.form-error')).toBeVisible();
  await dialog.getByRole('button', { name: '确认创建' }).click();
  await expect(dialog.getByText('CNX-TEST-CODE')).toBeVisible();
  expect(operationIds).toHaveLength(2);
  expect(operationIds[0]).toBe(operationIds[1]);
});

test('activation code expiry sends a stable concrete timestamp', async ({ page }) => {
  await mockConsole(page, true);
  const operationIds: string[] = [];
  const expiresAt: string[] = [];
  const codeHash = 'a'.repeat(64);
  let attempts = 0;
  await page.route('**/api/v1/activation-codes?*', (route) =>
    route.fulfill({
      json: {
        items: [
          {
            codeHash,
            codePrefix: 'CNX-EXP',
            accountId: 'acct_001',
            status: 'active',
            redeemedCount: 0,
            expiresAt: null,
            rowVersion: 2
          }
        ],
        nextCursor: null
      }
    })
  );
  await page.route(`**/api/v1/activation-codes/${codeHash}/actions/expire`, async (route) => {
    operationIds.push(route.request().headers()['idempotency-key']);
    expect(route.request().headers()['if-match']).toBe('"2"');
    expiresAt.push(route.request().postDataJSON().expiresAt);
    attempts += 1;
    if (attempts === 1) return route.abort('connectionreset');
    return route.fulfill({ status: 204 });
  });
  await page.goto('/#codes');
  await page.getByRole('button', { name: '管理', exact: true }).click();
  const dialog = page.getByRole('dialog');
  await dialog.getByLabel('激活码操作').selectOption('expire');
  await dialog.getByLabel('操作原因').fill('expire compromised delivery batch');
  await dialog.getByRole('button', { name: '应用变更' }).click();
  await expect(dialog.locator('.form-error')).toBeVisible();
  await dialog.getByRole('button', { name: '应用变更' }).click();
  await expect(dialog).not.toBeVisible();
  expect(operationIds[0]).toBe(operationIds[1]);
  expect(Number(expiresAt[0])).toBeGreaterThan(0);
  expect(expiresAt[0]).toBe(expiresAt[1]);
});

test('late payment evidence cannot replace the newly selected claim', async ({ page }) => {
  await mockConsole(page, true);
  await page.route(/\/api\/v1\/billing\/payment-claims(?:\?.*)?$/, (route) =>
    route.fulfill({
      json: {
        items: [
          {
            id: 'claim_a',
            rowVersion: 1,
            invoiceId: 'invoice_a',
            paidAmount: '10.00',
            paidAsset: 'USD',
            externalTransactionId: 'tx-a',
            status: 'submitted',
            createdAt: 2
          },
          {
            id: 'claim_b',
            rowVersion: 2,
            invoiceId: 'invoice_b',
            paidAmount: '20.00',
            paidAsset: 'USD',
            externalTransactionId: 'tx-b',
            status: 'verified',
            createdAt: 1
          }
        ]
      }
    })
  );
  await page.route('**/api/v1/billing/payment-claims/claim_a/evidence', async (route) => {
    await new Promise((resolve) => setTimeout(resolve, 300));
    return route.fulfill({
      json: {
        items: [
          { id: 'evidence_a', originalName: 'a-only.png', byteLength: 10, scanStatus: 'clean' }
        ]
      }
    });
  });
  await page.route('**/api/v1/billing/payment-claims/claim_b/evidence', (route) =>
    route.fulfill({
      json: {
        items: [
          { id: 'evidence_b', originalName: 'b-current.png', byteLength: 20, scanStatus: 'clean' }
        ]
      }
    })
  );
  await page.goto('/#billing');
  await page.getByRole('button', { name: '管理', exact: true }).nth(0).click();
  await page.getByRole('dialog').locator('header button').click();
  await page.getByRole('button', { name: '管理', exact: true }).nth(1).click();
  await expect(page.getByRole('dialog').getByText('b-current.png')).toBeVisible();
  await expect(page.getByRole('dialog').getByText(/该付款声明已结束审核/)).toBeVisible();
  await expect(page.getByRole('dialog').getByRole('button', { name: '提交审核' })).toHaveCount(0);
  await page.waitForTimeout(400);
  await expect(page.getByRole('dialog').getByText('a-only.png')).toHaveCount(0);
});

test('bulk job cancellation is reasoned and retry safe', async ({ page }) => {
  await mockConsole(page, true);
  const operationIds: string[] = [];
  let attempts = 0;
  await page.route('**/api/v1/bulk-jobs?*', (route) =>
    route.fulfill({
      json: {
        items: [
          {
            id: 'job_retry',
            kind: 'account_set_state',
            status: 'running',
            actorId: 'admin_01',
            reason: 'suspend affected tenants',
            parameters: { state: 'suspended' },
            totalItems: 4,
            completedItems: 1,
            failedItems: 0,
            createdAt: 1900000000,
            startedAt: 1900000001,
            finishedAt: null
          }
        ]
      }
    })
  );
  await page.route('**/api/v1/bulk-jobs/job_retry/actions/cancel', async (route) => {
    operationIds.push(route.request().headers()['idempotency-key']);
    expect(route.request().postDataJSON()).toEqual({ reason: 'stop incorrect bulk selection' });
    attempts += 1;
    if (attempts === 1) return route.abort('connectionreset');
    return route.fulfill({
      json: {
        id: 'job_retry',
        kind: 'account_set_state',
        status: 'cancel_requested',
        actorId: 'admin_01',
        reason: 'suspend affected tenants',
        parameters: { state: 'suspended' },
        totalItems: 4,
        completedItems: 1,
        failedItems: 0,
        createdAt: 1900000000,
        startedAt: 1900000001,
        finishedAt: null
      }
    });
  });
  await page.goto('/#jobs');
  await page.getByRole('button', { name: '管理', exact: true }).click();
  const dialog = page.getByRole('dialog');
  await dialog.getByLabel('操作原因').fill('stop incorrect bulk selection');
  await dialog.getByRole('button', { name: '确认取消' }).click();
  await expect(dialog.locator('.form-error')).toBeVisible();
  await dialog.getByRole('button', { name: '确认取消' }).click();
  await expect(dialog).not.toBeVisible();
  expect(operationIds).toHaveLength(2);
  expect(operationIds[0]).toBe(operationIds[1]);
});

test('administrator identity control remains readable across breakpoints', async ({ page }) => {
  await mockConsole(page, true);
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto('/#administrators');
  await expect(page.getByRole('heading', { name: '管理员身份' })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(
    true
  );
  await page.screenshot({ path: 'test-results/administrators-desktop.png', fullPage: true });
  await page.evaluate(() => {
    localStorage.setItem('admin-theme', 'dark');
    document.documentElement.dataset.theme = 'dark';
  });
  await page.screenshot({ path: 'test-results/administrators-dark.png', fullPage: true });
  await page.getByRole('button', { name: '添加管理员' }).click();
  await expect(page.getByRole('heading', { name: '添加管理员' })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(
    true
  );
  const editor = page.getByRole('dialog', { name: '添加管理员' });
  await editor.getByLabel('用户名').fill('support');
  await editor.getByLabel('显示名称').fill('Support operator');
  await editor.getByLabel('变更原因').fill('provision support coverage');
  await editor.getByRole('button', { name: '保存' }).click();
  await expect(page.getByRole('heading', { name: '安全交付登记令牌' })).toBeVisible();
  await expect(page.getByText('one-time-enrollment-token')).toBeVisible();
  await page.getByRole('button', { name: '已安全保存并销毁服务端副本' }).click();
  await expect(page.getByRole('heading', { name: '安全交付登记令牌' })).not.toBeVisible();
  await page.setViewportSize({ width: 390, height: 844 });
  await page.reload();
  await expect(page.getByRole('heading', { name: '管理员身份' })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(
    true
  );
  await page.screenshot({ path: 'test-results/administrators-mobile.png', fullPage: true });
});

test('dashboard is responsive in light and dark modes', async ({ page }) => {
  await mockConsole(page, true);
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.goto('/');
  await expect(page.getByRole('heading', { name: '运营总览' })).toBeVisible();
  const syncState = page.getByRole('button', { name: '数据已同步' });
  await expect(syncState).toContainText('上次成功');
  await expect(syncState).not.toContainText('刚刚');
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(
    true
  );
  await page.screenshot({ path: 'test-results/dashboard-light.png', fullPage: true });
  await page.evaluate(() => {
    localStorage.setItem('admin-theme', 'dark');
    document.documentElement.dataset.theme = 'dark';
  });
  await page.screenshot({ path: 'test-results/dashboard-dark.png', fullPage: true });
  await page.setViewportSize({ width: 768, height: 1024 });
  await page.reload();
  await expect(page.getByRole('heading', { name: '运营总览' })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(
    true
  );
  await page.screenshot({ path: 'test-results/dashboard-tablet.png', fullPage: true });
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.getByRole('button', { name: '账户', exact: true }).click();
  await expect(page.getByRole('heading', { name: '账户', exact: true })).toBeVisible();
  await page.getByRole('button', { name: '新建' }).click();
  await expect(page.getByRole('heading', { name: '新建账户' })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(
    true
  );
  await page.getByRole('dialog').getByRole('button', { name: '关闭' }).click();
  await page.getByRole('button', { name: '管理', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'acct_001' })).toBeVisible();
});
