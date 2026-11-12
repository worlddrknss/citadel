// Shared fixture for the live suite. Every test fails on console errors,
// uncaught page errors and any /v1 response with status >= 400 that the test
// didn't declare with expectStatus(). Helpers sign users in through the real
// API and run axe.

import AxeBuilder from '@axe-core/playwright';
import { test as base, expect, type APIRequestContext, type Browser, type Page } from '@playwright/test';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

export const BOOTSTRAP_TOKEN = process.env.CITADEL_LIVE_BOOTSTRAP_TOKEN ?? 'live-e2e-bootstrap-token-0123456789';

/** Data shared across the ordered spec files (they run in one worker). */
export const ORG = {
  organization: 'Live Org',
  account: 'production',
  admin: { username: 'alice', password: 'alice-correct-horse-1' },
  admin2: { username: 'bob', password: 'bob-correct-horse-22' },
  editor: { username: 'erin', password: 'erin-correct-horse-3' },
  viewer: { username: 'victor', password: 'victor-correct-horse' }
};

/** The account id is created by the bootstrap; later specs look it up. */
export async function accountId(request: APIRequestContext): Promise<string> {
  const res = await request.get('/v1/me');
  expect(res.ok(), 'signed in for accountId()').toBeTruthy();
  return (await res.json()).accountId;
}

interface Expected {
  status: number;
  url: RegExp;
}

export interface Fixtures {
  /** Declare a /v1 error response this test provokes on purpose. */
  expectStatus: (status: number, url: RegExp) => void;
  /** Console messages / page errors matching these are expected. */
  allowConsole: (re: RegExp) => void;
}

/**
 * Runs `fn` on the test's page and on every page of any context the test
 * opens with browser.newContext() (other users signed in side by side), so
 * their errors count too. Returns a function that stops watching.
 */
function onEveryPage(page: Page, browser: Browser, fn: (p: Page) => void): () => void {
  fn(page);
  const original = browser.newContext.bind(browser);
  browser.newContext = async (...args: Parameters<Browser['newContext']>) => {
    const ctx = await original(...args);
    ctx.on('page', fn);
    return ctx;
  };
  return () => {
    browser.newContext = original;
  };
}

export const test = base.extend<Fixtures>({
  expectStatus: [
    async ({ page, browser }, use) => {
      const expected: Expected[] = [];
      const seen: { status: number; method: string; url: string }[] = [];
      const stop = onEveryPage(page, browser, (p) =>
        p.on('response', (r) => {
          const url = r.url();
          if (!url.includes('/v1/') || r.status() < 400) return;
          seen.push({ status: r.status(), method: r.request().method(), url: url.replace(/^https?:\/\/[^/]+/, '') });
        })
      );
      await use((status, url) => expected.push({ status, url }));
      stop();
      const bad = seen
        .filter((r) => !expected.some((e) => e.status === r.status && e.url.test(r.url)))
        .map((r) => `${r.status} ${r.method} ${r.url}`);
      expect(bad, 'unexpected /v1 error responses').toEqual([]);
    },
    { auto: true }
  ],
  allowConsole: [
    async ({ page, browser }, use) => {
      const allowed: RegExp[] = [
        // Chrome logs every failed fetch; the response check above already
        // decides whether that status was expected.
        /Failed to load resource: the server responded with a status of/
      ];
      const errors: string[] = [];
      const stop = onEveryPage(page, browser, (p) => {
        p.on('console', (m) => {
          if (m.type() !== 'error') return;
          const text = `${m.text()} ${m.location().url ?? ''}`;
          if (!allowed.some((re) => re.test(text))) errors.push(`console.error: ${text}`);
        });
        p.on('pageerror', (e) => {
          if (!allowed.some((re) => re.test(e.message))) errors.push(`pageerror: ${e.message}`);
        });
      });
      await use((re) => allowed.push(re));
      stop();
      expect(errors, 'console errors / page errors').toEqual([]);
    },
    { auto: true }
  ]
});

export { expect };

// Session cookies by user+account, reused across tests: the server limits
// password sign-ins per IP (a burst of 20, then one per 3 s), which a full
// run would exceed. A cached session that has since been revoked (sign-out,
// session revocation, password change) is detected and replaced.
type Cookie = Awaited<ReturnType<ReturnType<Page['context']>['cookies']>>[number];
const sessions = new Map<string, Cookie[]>();

/**
 * Signs in through the API; the page's context shares the cookie. Pass
 * `fresh` for a new session (e.g. one a test is about to revoke).
 */
export async function signIn(page: Page, user: { username: string; password: string }, acct?: string, fresh = false) {
  const id = acct ?? lookupAccount();
  const key = `${id}/${user.username}`;
  const cached = fresh ? undefined : sessions.get(key);
  if (cached) {
    await page.context().clearCookies();
    await page.context().addCookies(cached);
    const me = await page.request.get('/v1/me');
    if (me.ok() && (await me.json()).username === user.username) return;
    sessions.delete(key);
    await page.context().clearCookies();
  }
  const res = await page.request.post('/v1/login', {
    data: { accountId: id, username: user.username, password: user.password },
    headers: { 'X-Citadel-Request': '1' }
  });
  expect(res.status(), `sign in as ${user.username}: ${await res.text()}`).toBe(200);
  if (!fresh) sessions.set(key, await page.context().cookies());
}

// The bootstrap spec writes the account id here for later spec files.
const STATE = join(dirname(fileURLToPath(import.meta.url)), '.run', 'state.json');

export function saveState(s: Record<string, unknown>) {
  mkdirSync(dirname(STATE), { recursive: true });
  writeFileSync(STATE, JSON.stringify({ ...loadState(), ...s }, null, 2));
}
export function loadState(): Record<string, string> {
  try {
    return JSON.parse(readFileSync(STATE, 'utf8'));
  } catch {
    return {};
  }
}
function lookupAccount(): string {
  const id = loadState().accountId;
  if (!id) throw new Error('no account id: run 01-bootstrap first');
  return id;
}

/** Opens a console page (path under /app) and waits for its heading. */
export async function open(page: Page, path: string) {
  await page.goto(`/app${path}`);
  await expect(page.locator('main h1').first()).toBeVisible();
}

/** Fails on serious or critical axe violations on the current page. */
export async function checkA11y(page: Page) {
  // Fading toasts and sliding panels read as low contrast mid-animation.
  await page.waitForFunction(() => document.getAnimations().every((a) => a.playState !== 'running'));
  const results = await new AxeBuilder({ page }).analyze();
  const bad = results.violations
    .filter((v) => v.impact === 'serious' || v.impact === 'critical')
    .map((v) => ({ id: v.id, help: v.help, nodes: v.nodes.slice(0, 5).map((n) => n.target.join(' ')) }));
  expect(bad, `axe violations on ${page.url()}`).toEqual([]);
}

/** Calls the /v1 API with the page's session cookie. */
export async function apiPost(page: Page, path: string, data: unknown) {
  const res = await page.request.post(path, { data, headers: { 'X-Citadel-Request': '1' } });
  expect(res.ok(), `POST ${path}: ${res.status()} ${await res.text()}`).toBeTruthy();
  return res.json();
}
