import { BOOTSTRAP_TOKEN, ORG, checkA11y, expect, loadState, saveState, test } from './fixtures';

// First run: the server starts with no users and only accepts the setup
// token from KMS_BOOTSTRAP_TOKEN.

test('first-run bootstrap creates the organization and signs the admin in', async ({ page, expectStatus }) => {
  await page.goto('/app/');
  await expect(page.getByRole('heading', { name: 'Create your organization' })).toBeVisible();
  // The shell probes /v1/me before showing the first-run screen.
  expectStatus(401, /\/v1\/me$/);
  await checkA11y(page);

  // A wrong token is refused.
  expectStatus(401, /\/v1\/bootstrap$/);
  await page.getByLabel('Setup token').fill('not-the-right-token-000000');
  await page.getByLabel('Organization name').fill(ORG.organization);
  await page.getByLabel('First account name').fill(ORG.account);
  await page.getByLabel('Admin username').fill(ORG.admin.username);
  await page.getByLabel('Password', { exact: true }).fill(ORG.admin.password);
  await page.getByRole('button', { name: /Create/i }).click();
  await expect(page.getByRole('alert')).toBeVisible();

  await page.getByLabel('Setup token').fill(BOOTSTRAP_TOKEN);
  await page.getByRole('button', { name: /Create/i }).click();
  await expect(page.getByRole('heading', { name: `${ORG.organization} is ready` })).toBeVisible();
  const id = (await page.locator('.acct .mono').textContent())!.trim();
  expect(id).toMatch(/^\d{12}$/);
  saveState({ accountId: id });
  await page.getByRole('button', { name: 'Continue to console' }).click();
  await expect(page.getByRole('heading', { level: 1, name: 'Overview' })).toBeVisible();
  await page.waitForLoadState('networkidle');
  await checkA11y(page);
});

test('sign out and sign back in with the password', async ({ page, expectStatus }) => {
  const { accountId } = loadState();
  expectStatus(401, /\/v1\/me$/);
  await page.goto('/app/');
  await expect(page.getByRole('heading', { name: 'Sign in' })).toBeVisible();

  expectStatus(401, /\/v1\/login$/);
  await page.getByLabel('Account ID').fill(accountId);
  await page.getByLabel('Username').fill(ORG.admin.username);
  await page.getByLabel('Password', { exact: true }).fill('wrong-password-123');
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await expect(page.getByRole('alert')).toBeVisible();

  await page.getByLabel('Password', { exact: true }).fill(ORG.admin.password);
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await expect(page.getByRole('heading', { level: 1, name: 'Overview' })).toBeVisible();

  await page.getByRole('button', { name: 'Account menu' }).click();
  await page.getByRole('menuitem', { name: 'Sign out' }).click();
  await expect(page.getByRole('heading', { name: 'Sign in' })).toBeVisible();
});
