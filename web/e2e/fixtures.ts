// Shared test fixture: installs the mock API and fails any test that logs a
// console error, throws an uncaught page error, or calls an endpoint the
// mock has no fixture for.

import { test as base, expect, type Page } from '@playwright/test';
import { MockApi } from './mock';

export interface Fixtures {
  api: MockApi;
  /** Console messages/page errors matching these are expected in this test. */
  allowConsole: (re: RegExp) => void;
}

export const test = base.extend<Fixtures>({
  api: async ({ page }, use) => {
    const api = new MockApi();
    await api.install(page);
    await use(api);
  },
  allowConsole: [
    async ({ page, api }, use) => {
      const allowed: RegExp[] = [];
      const errors: string[] = [];
      page.on('console', (m) => {
        if (m.type() !== 'error') return;
        const text = `${m.text()} ${m.location().url ?? ''}`;
        if (!allowed.some((re) => re.test(text))) errors.push(`console.error: ${text}`);
      });
      page.on('pageerror', (e) => {
        if (!allowed.some((re) => re.test(e.message))) errors.push(`pageerror: ${e.message}`);
      });
      await use((re) => allowed.push(re));
      expect(api.unhandled, 'requests with no mock fixture').toEqual([]);
      expect(errors, 'console errors / page errors').toEqual([]);
    },
    { auto: true }
  ]
});

export { expect };

/** Every page in the console, for the per-page sweeps. */
export const PAGES = [
  { path: '/', heading: 'Overview' },
  { path: '/secrets', heading: 'Secrets' },
  { path: '/secrets/payments', heading: /Payments/ },
  { path: '/secrets/payments/dev', heading: /Payments/ },
  { path: '/secrets/payments/dev?secret=STRIPE_KEY&tab=rotation', heading: /Payments/ },
  { path: '/parameters', heading: 'Parameters' },
  { path: '/kms', heading: /KMS/ },
  { path: '/certificates', heading: 'Certificates' },
  { path: '/iam', heading: /IAM|Identity/ },
  { path: '/workload-identity', heading: /Workload identity/i },
  { path: '/agents', heading: 'Agents' },
  { path: '/agents/agt_abcdefghijklmnopqrst', heading: 'claude-code' },
  { path: '/agents/agt_abcdefghijklmnopqrst?tab=grants', heading: 'claude-code' },
  { path: '/secrets/payments/dev?secret=STRIPE_KEY&tab=agents', heading: /Payments/ },
  { path: '/account', heading: 'My account' },
  { path: '/audit', heading: 'Audit log' },
  { path: '/approvals', heading: 'Approvals' },
  { path: '/admin', heading: 'Administration' },
  { path: '/admin?tab=notifications', heading: 'Administration' },
  { path: '/api-reference', heading: 'API reference' }
] as const;

/** Opens a console page and waits for its first heading. */
export async function open(page: Page, path: string) {
  await page.goto(`/app${path === '/' ? '/' : path}`);
  await expect(page.locator('main h1').first()).toBeVisible();
}
