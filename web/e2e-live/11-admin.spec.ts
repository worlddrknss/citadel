import { ORG, checkA11y, expect, loadState, open, signIn, test } from './fixtures';
import { startFakeOidc, type FakeOidc } from './fake-oidc';

// Administration: the platform admin (alice) versus an account admin (bob),
// organization settings, and a console SSO provider backed by a fake OIDC
// issuer, through to an actual SSO sign-in.

let idp: FakeOidc;
test.beforeAll(async () => {
  idp = await startFakeOidc();
});
test.afterAll(async () => {
  await idp?.close();
});

test('users and memberships list everyone with their roles', async ({ page }) => {
  await signIn(page, ORG.admin);
  await open(page, '/admin');
  const users = page.getByRole('table', { name: 'Users' });
  for (const u of ['alice', 'bob', 'erin', 'victor']) await expect(users.getByRole('row', { name: new RegExp(`\\b${u}\\b`) })).toBeVisible();
  await expect(users.getByRole('row', { name: /alice/ }).getByText('Platform admin')).toBeVisible();

  await page.getByRole('tab', { name: /Memberships/ }).click();
  const mem = page.getByRole('table', { name: 'Memberships' });
  await expect(mem.getByRole('row', { name: /victor.*production.*viewer/i })).toBeVisible();
  await page.waitForLoadState('networkidle');
  await checkA11y(page);

  await page.getByRole('tab', { name: /Accounts/ }).click();
  await expect(page.getByRole('button', { name: 'Create account' })).toBeVisible();
});

test('platform admin saves organization settings; account admin sees them read-only', async ({ page, browser, baseURL }) => {
  await signIn(page, ORG.admin);
  await open(page, '/admin?tab=settings');
  const idle = page.getByLabel('Idle timeout (minutes)');
  await expect(idle).toBeEditable();
  await idle.fill('45');
  await page.getByRole('button', { name: 'Save settings' }).click();
  await expect(page.getByText('Organization settings saved')).toBeVisible();
  await expect(page.getByText(/Last changed .* by alice/)).toBeVisible();
  await page.waitForLoadState('networkidle');
  await checkA11y(page);

  const ctx = await browser.newContext({ baseURL });
  const bob = await ctx.newPage();
  await signIn(bob, ORG.admin2);
  await open(bob, '/admin?tab=settings');
  await expect(bob.getByText('Only platform admins can change them.')).toBeVisible();
  await expect(bob.getByLabel('Idle timeout (minutes)')).toHaveValue('45');
  await expect(bob.getByLabel('Idle timeout (minutes)')).toBeDisabled();
  await expect(bob.getByRole('button', { name: 'Save settings' })).toHaveCount(0);
  // Accounts: no create or delete for an account admin.
  await bob.getByRole('tab', { name: /Accounts/ }).click();
  await expect(bob.getByRole('table', { name: 'Accounts' }).getByText('production')).toBeVisible();
  await expect(bob.getByRole('button', { name: 'Create account' })).toHaveCount(0);
  await expect(bob.getByRole('button', { name: /^Delete / })).toHaveCount(0);
  // Users: bob can't edit the platform admin.
  await bob.getByRole('tab', { name: /Users/ }).click();
  await expect(bob.getByRole('table', { name: 'Users' }).getByRole('row', { name: /\berin\b/ })).toBeVisible();
  await expect(bob.getByRole('button', { name: 'Edit alice' })).toHaveCount(0);
  await expect(bob.getByRole('button', { name: 'Edit erin' })).toBeVisible();
  await ctx.close();
});

test('SSO provider: create, test, sign in, edit to org-wide, delete', async ({ page, browser, baseURL, expectStatus }) => {
  const { accountId } = loadState();
  // The SSO users start signed out: the console's /v1/me probe says 401.
  expectStatus(401, /\/v1\/me$/);
  await signIn(page, ORG.admin);
  await open(page, '/admin?tab=settings');
  await page.getByRole('button', { name: 'Add provider' }).first().click();
  const dlg = page.getByRole('dialog', { name: 'Add sign-in provider' });
  await dlg.getByLabel('Name').fill('Fake IdP');
  await dlg.getByLabel('Issuer URL').fill(idp.issuer);
  await dlg.getByLabel('Client ID').fill(idp.clientId);
  await dlg.getByLabel('Client secret').fill(idp.clientSecret);
  await dlg.getByRole('button', { name: 'Add rule' }).click();
  await dlg.getByLabel('Group for rule 1').fill('citadel-editors');
  await expect(dlg.getByLabel('Account for rule 1')).toHaveValue(accountId);
  await dlg.getByLabel('Role for rule 1').selectOption('editor');
  await dlg.getByLabel(/Allowed email domains/).fill('example.com');
  await dlg.getByRole('switch').check();
  await dlg.getByRole('button', { name: 'Add provider' }).click();

  // The server's redirect URI, with the provider's id.
  const done = page.getByRole('dialog', { name: 'Fake IdP added' });
  const redirect = done.getByTestId('sso-redirect-uri');
  await expect(redirect).toHaveText(new RegExp(`^${baseURL}/v1/auth/oidc/sso-[0-9a-f]+/callback$`));
  await done.getByRole('button', { name: 'Done' }).click();

  const row = page.getByRole('row', { name: /Fake IdP/ });
  await expect(row).toBeVisible();
  await row.getByRole('button', { name: 'Test' }).click();
  await expect(page.getByText('Fake IdP: discovery OK')).toBeVisible();

  // Edit keeps the email domains (saving used to clear them).
  await row.getByRole('button', { name: 'Edit Fake IdP' }).click();
  const edit = page.getByRole('dialog', { name: 'Edit Fake IdP' });
  await expect(edit.getByLabel(/Allowed email domains/)).toHaveValue('example.com');
  await expect(edit.getByTestId('sso-redirect-uri').or(edit.getByText(/\/v1\/auth\/oidc\/sso-/))).toBeVisible();
  await edit.getByRole('button', { name: 'Cancel' }).click();

  // An actual SSO sign-in through the fake issuer, in a fresh browser.
  const ctx = await browser.newContext({ baseURL });
  const sso = await ctx.newPage();
  await sso.goto('/app/');
  await sso.getByRole('button', { name: 'Continue with Fake IdP' }).click();
  await expect(sso.getByRole('heading', { level: 1, name: 'Overview' })).toBeVisible();
  const me = await (await sso.request.get('/v1/me')).json();
  expect(me.role).toBe('editor');
  expect(me.accountId).toBe(accountId);
  // A user outside the allowed domains is refused.
  idp.user = { sub: 'u-2', email: 'mallory@evil.test', name: 'Mallory', groups: ['citadel-editors'] };
  const ctx2 = await browser.newContext({ baseURL });
  const bad = await ctx2.newPage();
  await bad.goto('/app/');
  await bad.getByRole('button', { name: 'Continue with Fake IdP' }).click();
  await expect(bad.getByRole('alert').filter({ hasText: /denied|groups|failed/i })).toBeVisible();
  await ctx.close();
  await ctx2.close();

  // Make it org-wide: account admins then can't manage it.
  await row.getByRole('button', { name: 'Edit Fake IdP' }).click();
  await edit.getByLabel('Account for rule 1').selectOption('*');
  await edit.getByRole('button', { name: 'Save changes' }).click();
  await expect(edit).toBeHidden();
  await expect(row.getByText(/org-wide/)).toBeVisible();
  const bctx = await browser.newContext({ baseURL });
  const bob = await bctx.newPage();
  await signIn(bob, ORG.admin2);
  await open(bob, '/admin?tab=settings');
  const bobRow = bob.getByRole('row', { name: /Fake IdP/ });
  await expect(bobRow.getByText('Platform admins manage this')).toBeVisible();
  await expect(bobRow.getByRole('button', { name: 'Edit Fake IdP' })).toHaveCount(0);
  await bctx.close();

  // Delete.
  await row.getByRole('button', { name: 'Delete Fake IdP' }).click();
  await page.getByLabel(/Type .* to confirm/).fill('Fake IdP');
  await page.getByRole('button', { name: 'Delete provider' }).click();
  await expect(page.getByText('Deleted Fake IdP')).toBeVisible();
  await expect(row).toHaveCount(0);
});
