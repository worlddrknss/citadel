import { createHmac } from 'node:crypto';
import type { Page } from '@playwright/test';
import { ORG, apiPost, checkA11y, expect, loadState, open, signIn, test } from './fixtures';

// Two-step verification against the real server: enrol through the UI (the
// TOTP code is computed here from the secret the page shows), sign out, sign
// back in with a code, use a recovery code once, then the organization
// policy that forces enrolment, and an admin reset.

const MIA = { username: 'mia', password: 'mia-correct-horse-44' };
const NINA = { username: 'nina', password: 'nina-correct-horse-5' };

function base32(s: string): Buffer {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const c of s.replace(/[\s=]/g, '').toUpperCase()) bits += alphabet.indexOf(c).toString(2).padStart(5, '0');
  const out: number[] = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(out);
}

/** RFC 6238 TOTP, HMAC-SHA-256, 6 digits, 30 s steps. */
function totp(secret: string, step: number): string {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(step));
  const mac = createHmac('sha256', base32(secret)).update(msg).digest();
  const off = mac[mac.length - 1] & 0x0f;
  const bin = ((mac[off] & 0x7f) << 24) | (mac[off + 1] << 16) | (mac[off + 2] << 8) | mac[off + 3];
  return String(bin % 1_000_000).padStart(6, '0');
}
const stepNow = () => Math.floor(Date.now() / 30_000);

/** A code for a step later than `used` (codes are single-use per step). */
async function freshCode(page: Page, secret: string, used: number): Promise<{ code: string; step: number }> {
  while (stepNow() <= used) await page.waitForTimeout(1000);
  const step = stepNow();
  return { code: totp(secret, step), step };
}

async function createUser(page: Page, u: { username: string; password: string }) {
  const { accountId } = loadState();
  await apiPost(page, '/v1/admin/users', { username: u.username, displayName: u.username, role: 'viewer', password: u.password, accounts: [accountId] });
}

/** Enrols via the open MfaEnroll form; returns the secret and the step used. */
async function enrolOnPage(page: Page, scope: ReturnType<Page['locator']> | Page) {
  await expect(scope.getByRole('img', { name: /QR code/ })).toBeVisible();
  await scope.getByRole('button', { name: /Enter the key by hand/ }).click();
  const secret = (await scope.getByTestId('mfa-secret').textContent())!.replace(/\s+/g, '');
  expect(secret).toMatch(/^[A-Z2-7]{32}$/);
  const step = stepNow();
  await scope.getByLabel(/6-digit code/).fill(totp(secret, step));
  await scope.getByRole('button', { name: 'Turn on' }).click();
  const codes = scope.getByRole('list', { name: 'Recovery codes' }).getByRole('listitem');
  await expect(codes).toHaveCount(10);
  const recovery = (await codes.allTextContents()).map((c) => c.trim());
  await scope.getByLabel("I've saved my recovery codes").check();
  await scope.getByRole('button', { name: 'Finish' }).click();
  return { secret, step, recovery };
}

test('enrol → sign out → sign in with a code; recovery codes work once', async ({ page, browser, baseURL, expectStatus }) => {
  test.setTimeout(150_000);
  expectStatus(401, /\/v1\/login\/mfa$/);
  expectStatus(401, /\/v1\/me$/);
  await signIn(page, ORG.admin);
  await createUser(page, MIA);
  const { accountId } = loadState();

  const ctx = await browser.newContext({ baseURL });
  const p = await ctx.newPage();
  await signIn(p, MIA, undefined, true);
  await open(p, '/account');
  const panel = p.getByRole('region', { name: 'Security' });
  await panel.getByRole('button', { name: 'Set up' }).click();
  const dialog = p.getByRole('dialog', { name: 'Set up two-step verification' });
  await checkA11y(p);
  const { secret, step, recovery } = await enrolOnPage(p, dialog);
  await expect(panel.getByText(/10 recovery codes left/)).toBeVisible();

  // Sign out, then sign in through the form: password, then a code.
  await p.getByRole('button', { name: 'Account menu' }).click();
  await p.getByRole('menuitem', { name: 'Sign out' }).click();
  await expect(p.getByRole('heading', { name: 'Sign in' })).toBeVisible();
  await p.getByRole('textbox', { name: 'Account ID' }).fill(accountId);
  await p.getByLabel('Username').fill(MIA.username);
  await p.getByLabel('Password', { exact: true }).fill(MIA.password);
  await p.getByRole('button', { name: 'Sign in', exact: true }).click();
  await expect(p.getByRole('heading', { name: 'Enter your code' })).toBeVisible();
  await checkA11y(p);
  // The enrolment code's step is already used: a replay fails.
  await p.getByLabel('Authentication code').fill(totp(secret, step));
  await p.getByRole('button', { name: 'Verify' }).click();
  await expect(p.getByRole('alert')).toContainText(/invalid or already used/);
  const next = await freshCode(p, secret, step);
  await p.getByLabel('Authentication code').fill(next.code);
  await p.getByRole('button', { name: 'Verify' }).click();
  // Back in the console, on the page signed out from.
  await expect(p.getByRole('navigation', { name: 'Main' })).toBeVisible();
  await expect(p.getByRole('heading', { level: 1, name: 'My account' })).toBeVisible();

  // Recovery code through the API: once.
  const login = async () => {
    const r = await p.request.post('/v1/login', { data: { accountId, username: MIA.username, password: MIA.password }, headers: { 'X-Citadel-Request': '1' } });
    expect(r.status()).toBe(200);
    const body = await r.json();
    expect(body.mfaRequired).toBe(true);
    return body.mfaToken as string;
  };
  const use = (mfaToken: string, recoveryCode: string) =>
    p.request.post('/v1/login/mfa', { data: { mfaToken, recoveryCode }, headers: { 'X-Citadel-Request': '1' } });
  expect((await use(await login(), recovery[0])).status()).toBe(200);
  expect((await use(await login(), recovery[0])).status()).toBe(401);
  const status = await (await p.request.get('/v1/account/mfa')).json();
  expect(status).toMatchObject({ enabled: true, recoveryCodesLeft: 9, algorithm: 'SHA256' });
  await ctx.close();

  // The admin sees it and the audit log recorded it.
  const users = (await (await page.request.get('/v1/admin/users')).json()).users as { username: string; mfaEnabled?: boolean }[];
  expect(users.find((u) => u.username === MIA.username)?.mfaEnabled).toBe(true);
  const audit = await (await page.request.get('/v1/audit?limit=200')).text();
  for (const action of ['citadel.MFAEnroll', 'citadel.LoginMFA', 'citadel.MFARecoveryCodeUsed']) expect(audit).toContain(action);
});

test('requireMFA forces enrolment; an admin resets MFA', async ({ page, browser, baseURL, expectStatus }) => {
  test.setTimeout(120_000);
  expectStatus(401, /\/v1\/me$/); // the fresh context's first visit
  await signIn(page, ORG.admin);
  await createUser(page, NINA);
  const { accountId } = loadState();
  const settings = await (await page.request.get('/v1/admin/settings')).json();
  const { updatedAt: _a, updatedBy: _b, ...base } = settings;
  await apiPost(page, '/v1/admin/settings', { ...base, requireMFA: true });
  try {
    const ctx = await browser.newContext({ baseURL });
    const p = await ctx.newPage();
    await p.goto('/app/');
    await p.getByLabel('Account ID').fill(accountId);
    await p.getByLabel('Username').fill(NINA.username);
    await p.getByLabel('Password', { exact: true }).fill(NINA.password);
    await p.getByRole('button', { name: 'Sign in', exact: true }).click();
    await expect(p.getByRole('heading', { name: 'Set up two-step verification' })).toBeVisible();
    await expect(p.getByRole('navigation', { name: 'Main' })).toHaveCount(0);
    expect((await p.request.get('/v1/projects')).status()).toBe(403);
    await checkA11y(p);
    await enrolOnPage(p, p);
    await expect(p.getByRole('heading', { level: 1, name: 'Overview' })).toBeVisible();
    expect((await p.request.get('/v1/projects')).status()).toBe(200);

    // Admin reset with type-to-confirm: nina is signed out everywhere.
    await open(page, '/admin?tab=users');
    await page.getByRole('button', { name: `Reset two-step verification for ${NINA.username}` }).click();
    const dlg = page.getByRole('dialog', { name: new RegExp(`Reset two-step verification for ${NINA.username}`) });
    await dlg.getByRole('textbox').fill(NINA.username);
    await dlg.getByRole('button', { name: 'Reset MFA' }).click();
    await expect(page.getByText(`Reset two-step verification for ${NINA.username}`, { exact: true })).toBeVisible();
    expect((await p.request.get('/v1/me')).status()).toBe(401);
    await ctx.close();
  } finally {
    await apiPost(page, '/v1/admin/settings', { ...base, requireMFA: false });
  }
});
