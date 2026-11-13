import { expect, open, test } from './fixtures';
import { AGENT_ID, TOTP_CODE } from './mock';

// Agents 2.4: login fields in the secret drawer (write-only seed, live code
// preview, SHA-1 refused), Add login, minted credential settings and grant
// scopes, and anomaly settings and history on the agent page.

test('a login credential shows its fields and a live TOTP preview', async ({ page, api, allowConsole }) => {
  allowConsole(/status of 400/);
  await open(page, '/secrets/payments/dev?secret=API_KEY&tab=agents');
  const profile = page.getByRole('article', { name: 'Usage profile shop-login' });
  await expect(profile.getByText('https://shop.example.com/admin')).toBeVisible();
  const login = profile.getByRole('form', { name: 'Login shop-login' });
  await expect(login.getByLabel('Username')).toHaveValue('admin@shop.example.com');
  await expect(login.getByLabel('Password')).toHaveValue('');
  await expect(login.getByText('Configured')).toBeVisible();

  await login.getByRole('button', { name: 'Show current code' }).click();
  await expect(login.getByLabel('Current code')).toHaveText(TOTP_CODE);
  await expect.poll(() => api.log.some((l) => l.includes('/v1/agents/credentials/login?name=shop-login&code=true'))).toBe(true);

  // A SHA-1 seed is refused with the FIPS explanation.
  await login.getByLabel('TOTP seed').fill('otpauth://totp/x?secret=JBSWY3DPEHPK3PXP');
  await login.getByRole('button', { name: 'Save login' }).click();
  await expect(login.getByRole('alert')).toContainText('FIPS 140-3');
  await login.getByLabel('TOTP seed').fill('otpauth://totp/x?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&algorithm=SHA256');
  await login.getByRole('button', { name: 'Save login' }).click();
  await expect.poll(() => api.log.filter((l) => l.startsWith('POST /v1/agents/credentials/login')).length).toBe(2);
  await expect(login.getByLabel('TOTP seed')).toHaveValue('');
});

test('Add login creates the secret, the login profile and the seed', async ({ page, api }) => {
  await open(page, '/agents');
  await page.getByRole('button', { name: 'Add login' }).click();
  const dlg = page.getByRole('dialog', { name: 'Add login' });
  await dlg.getByLabel('Credential name').fill('crm-login');
  await dlg.getByLabel('Project').fill('payments');
  await dlg.getByLabel('Environment').fill('dev');
  await dlg.getByLabel('Key', { exact: true }).fill('CRM_LOGIN');
  await dlg.getByLabel('Pages the login may be used on').fill('http://crm.example.com');
  await dlg.getByLabel('Username').fill('ops@example.com');
  await expect(dlg.getByText(/not an https:\/\/ URL pattern/)).toBeVisible();
  await dlg.getByLabel('Pages the login may be used on').fill('https://crm.example.com/login');
  await dlg.getByLabel('Password').fill('correct-horse');
  await dlg.getByLabel(/TOTP seed/).fill('otpauth://totp/x?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&algorithm=SHA512');
  await dlg.getByRole('button', { name: 'Add login' }).click();
  await expect(dlg).toBeHidden();
  const writes = api.log.filter((l) => l.startsWith('POST'));
  expect(writes.some((l) => l.startsWith('POST /v1/secrets'))).toBe(true);
  expect(writes.some((l) => l === 'POST /v1/agents/credentials')).toBe(true);
  expect(writes.some((l) => l.startsWith('POST /v1/agents/credentials/login'))).toBe(true);
});

test('minted credentials: GitHub App settings and a restricted grant', async ({ page, api }) => {
  await open(page, '/secrets/payments/dev?secret=STRIPE_KEY&tab=agents');
  await page.getByRole('button', { name: 'Make usable by agents' }).click();
  const dlg = page.getByRole('dialog', { name: 'Make usable by agents' });
  await dlg.getByLabel('How agents use it').selectOption('github_app');
  await dlg.getByLabel('App ID').fill('12345');
  await dlg.getByLabel('Installation ID').fill('678');
  await dlg.getByLabel('Default permissions').fill('contents=everything');
  await expect(dlg.getByText(/name=read\|write\|admin/)).toBeVisible();
  await dlg.getByLabel('Default permissions').fill('contents=read');
  await dlg.getByRole('button', { name: 'Save' }).click();
  await expect.poll(() => api.log.some((l) => l.startsWith('POST /v1/agents/credentials'))).toBe(true);

  await open(page, `/agents/${AGENT_ID}?tab=grants`);
  await page.getByRole('button', { name: /Grant a credential|New grant|Grant credential/ }).first().click();
  const grant = page.getByRole('dialog', { name: 'Grant a credential' });
  await grant.getByLabel('Credential', { exact: true }).selectOption('gh-app');
  await expect(grant.getByText(/Restrict the token/)).toBeVisible();
  await grant.getByLabel('Repositories').fill('api');
  await expect(grant.getByText(/Restrict the token/)).toBeHidden();
});

test('anomaly settings on the overview and history on the activity tab', async ({ page, api }) => {
  await open(page, `/agents/${AGENT_ID}`);
  await expect(page.getByText(/Learned from 412 uses/)).toBeVisible();
  await page.getByRole('checkbox', { name: /Suspend automatically/ }).check();
  await expect.poll(() => api.log.some((l) => l.startsWith('POST /v1/agents/anomaly-settings'))).toBe(true);

  await page.getByRole('tab', { name: 'Activity' }).click();
  const list = page.getByRole('region', { name: 'Anomalies' });
  await expect(list.getByText('New host')).toBeVisible();
  await expect(list.getByText('first use of host exfil.example.net')).toBeVisible();
  await expect(list.getByText('Suspended')).toBeVisible();
});
