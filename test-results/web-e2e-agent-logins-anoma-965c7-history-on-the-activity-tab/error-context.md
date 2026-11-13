# Instructions

- Following Playwright test failed.
- Explain why, be concise, respect Playwright best practices.
- Provide a snippet of code with the fix, if possible.

# Test info

- Name: web/e2e/agent-logins.spec.ts >> anomaly settings on the overview and history on the activity tab
- Location: web/e2e/agent-logins.spec.ts:75:1

# Error details

```
Error: page.goto: Protocol error (Page.navigate): Cannot navigate to invalid URL
Call log:
  - navigating to "/app/agents/agt_abcdefghijklmnopqrst", waiting until "load"

```

# Test source

```ts
  1  | // Shared test fixture: installs the mock API and fails any test that logs a
  2  | // console error, throws an uncaught page error, or calls an endpoint the
  3  | // mock has no fixture for.
  4  | 
  5  | import { test as base, expect, type Page } from '@playwright/test';
  6  | import { MockApi } from './mock';
  7  | 
  8  | export interface Fixtures {
  9  |   api: MockApi;
  10 |   /** Console messages/page errors matching these are expected in this test. */
  11 |   allowConsole: (re: RegExp) => void;
  12 | }
  13 | 
  14 | export const test = base.extend<Fixtures>({
  15 |   api: async ({ page }, use) => {
  16 |     const api = new MockApi();
  17 |     await api.install(page);
  18 |     await use(api);
  19 |   },
  20 |   allowConsole: [
  21 |     async ({ page, api }, use) => {
  22 |       const allowed: RegExp[] = [];
  23 |       const errors: string[] = [];
  24 |       page.on('console', (m) => {
  25 |         if (m.type() !== 'error') return;
  26 |         const text = `${m.text()} ${m.location().url ?? ''}`;
  27 |         if (!allowed.some((re) => re.test(text))) errors.push(`console.error: ${text}`);
  28 |       });
  29 |       page.on('pageerror', (e) => {
  30 |         if (!allowed.some((re) => re.test(e.message))) errors.push(`pageerror: ${e.message}`);
  31 |       });
  32 |       await use((re) => allowed.push(re));
  33 |       expect(api.unhandled, 'requests with no mock fixture').toEqual([]);
  34 |       expect(errors, 'console errors / page errors').toEqual([]);
  35 |     },
  36 |     { auto: true }
  37 |   ]
  38 | });
  39 | 
  40 | export { expect };
  41 | 
  42 | /** Every page in the console, for the per-page sweeps. */
  43 | export const PAGES = [
  44 |   { path: '/', heading: 'Overview' },
  45 |   { path: '/secrets', heading: 'Secrets' },
  46 |   { path: '/secrets/payments', heading: /Payments/ },
  47 |   { path: '/secrets/payments/dev', heading: /Payments/ },
  48 |   { path: '/secrets/payments/dev?secret=STRIPE_KEY&tab=rotation', heading: /Payments/ },
  49 |   { path: '/parameters', heading: 'Parameters' },
  50 |   { path: '/kms', heading: /KMS/ },
  51 |   { path: '/certificates', heading: 'Certificates' },
  52 |   { path: '/iam', heading: /IAM|Identity/ },
  53 |   { path: '/workload-identity', heading: /Workload identity/i },
  54 |   { path: '/agents', heading: 'Agents' },
  55 |   { path: '/agents/agt_abcdefghijklmnopqrst', heading: 'claude-code' },
  56 |   { path: '/agents/agt_abcdefghijklmnopqrst?tab=grants', heading: 'claude-code' },
  57 |   { path: '/agents/agt_abcdefghijklmnopqrst?tab=requests', heading: 'claude-code' },
  58 |   { path: '/agents/agt_abcdefghijklmnopqrst?tab=leases', heading: 'claude-code' },
  59 |   { path: '/secrets/payments/dev?secret=STRIPE_KEY&tab=agents', heading: /Payments/ },
  60 |   { path: '/account', heading: 'My account' },
  61 |   { path: '/audit', heading: 'Audit log' },
  62 |   { path: '/approvals', heading: 'Approvals' },
  63 |   { path: '/approvals?type=agent_access&id=aar_bbbbbbbbbbbbbbbb', heading: 'Approvals' },
  64 |   { path: '/admin', heading: 'Administration' },
  65 |   { path: '/admin?tab=notifications', heading: 'Administration' },
  66 |   { path: '/api-reference', heading: 'API reference' }
  67 | ] as const;
  68 | 
  69 | /** Opens a console page and waits for its first heading. */
  70 | export async function open(page: Page, path: string) {
> 71 |   await page.goto(`/app${path === '/' ? '/' : path}`);
     |              ^ Error: page.goto: Protocol error (Page.navigate): Cannot navigate to invalid URL
  72 |   await expect(page.locator('main h1').first()).toBeVisible();
  73 | }
  74 | 
```