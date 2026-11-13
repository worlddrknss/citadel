import { BASE } from './playwright.config';
import type { Page } from '@playwright/test';
import { ORG, checkA11y, expect, open, signIn, test } from './fixtures';

/** Waits for drawer/modal transitions, which axe would read mid-fade. */
async function settle(page: Page) {
  await page.waitForTimeout(300);
  await page.waitForFunction(() => document.getAnimations().every((a) => a.playState !== 'running'));
}

// Workload identity: Citadel's own OIDC issuer (KMS_PUBLIC_URL is set by
// start-server.sh) and per-account workload clients.

test('issuer is configured and the platform admin manages its signing key', async ({ page }) => {
  await signIn(page, ORG.admin);
  await open(page, '/workload-identity');
  const issuer = page.getByRole('region', { name: 'Issuer' });
  await expect(issuer.getByText('Configured', { exact: true })).toBeVisible();
  await expect(issuer.getByText(`${BASE}/oidc`, { exact: true })).toBeVisible();
  await expect(issuer.getByText(`${BASE}/v1/workload-identity/token`, { exact: true })).toBeVisible();
  await expect(issuer.getByText(/tokenType: "id_token"/)).toBeVisible();

  const key = page.getByRole('region', { name: 'Signing key' });
  await expect(key.getByRole('button', { name: 'Settings' })).toBeVisible();
  // No key until the first token or rotation; create one now.
  await key.getByRole('button', { name: 'Create signing key' }).click();
  await page.getByRole('dialog', { name: /Rotate the signing key/ }).getByRole('button', { name: 'Rotate key' }).click();
  await expect(key.getByText('ES256', { exact: false }).first()).toBeVisible();
  await expect(key.getByText('Active', { exact: true })).toBeVisible();

  await key.getByRole('button', { name: 'Settings' }).click();
  const dlg = page.getByRole('dialog', { name: 'Signing settings' });
  await expect(dlg.getByLabel('Algorithm')).toHaveValue('ES256');
  await dlg.getByLabel('Rotate every (days)').fill('30');
  await dlg.getByRole('button', { name: 'Save' }).click();
  await expect(dlg).toBeHidden();
  await expect(key.getByText(/Every 30 days/)).toBeVisible();
  await page.waitForLoadState('networkidle');
  await checkA11y(page);

  const info = await (await page.request.get('/v1/workload-identity/issuer')).json();
  expect(info).toMatchObject({ configured: true, algorithm: 'ES256', rotationDays: 30, tokenEndpoint: `${BASE}/v1/workload-identity/token` });
});

test('an account admin creates an access-key client but cannot manage the issuer', async ({ page }) => {
  // Axe reads the client drawer mid-animation otherwise.
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await signIn(page, ORG.admin2);
  await open(page, '/workload-identity');
  const key = page.getByRole('region', { name: 'Signing key' });
  await expect(key.getByText('Active', { exact: true })).toBeVisible();
  await expect(key.getByRole('button', { name: 'Settings' })).toHaveCount(0);
  await expect(key.getByRole('button', { name: /Rotate/ })).toHaveCount(0);

  await page.getByRole('button', { name: 'New client' }).first().click();
  const dlg = page.getByRole('dialog', { name: 'New workload client' });
  await dlg.getByLabel('Name').fill('ci-deployer');
  await dlg.getByLabel('Allowed audiences').fill('sts.amazonaws.com');
  // Kubernetes TokenReview isn't configured on the test server.
  await expect(dlg.getByText(/KMS_WORKLOAD_K8S_REVIEWER_TOKEN_FILE/)).toBeVisible();
  // Required: the server needs at least one member whose keys may ask.
  await dlg.getByRole('button', { name: 'Create client' }).click();
  await expect(dlg.getByText(/Name at least one user/)).toBeVisible();
  await dlg.getByLabel('Allowed users').fill(ORG.editor.username);
  await expect(dlg.getByLabel('Subject format')).toHaveValue('user:{username}');
  await dlg.getByLabel('Token lifetime').selectOption({ label: '1 hour' });
  await dlg.getByRole('button', { name: 'Create client' }).click();
  await expect(dlg).toBeHidden();

  const drawer = page.getByRole('dialog', { name: /ci-deployer/ });
  await expect(drawer).toBeVisible();
  await expect(drawer.getByText(ORG.editor.username, { exact: true })).toBeVisible();
  await expect(drawer.getByText(/citadel/).first()).toBeVisible();

  const { clients } = await (await page.request.get('/v1/workload-identity/clients')).json();
  expect(clients).toHaveLength(1);
  expect(clients[0]).toMatchObject({ name: 'ci-deployer', tokenTtlSeconds: 3600, auth: { method: 'access-key', allowedUsers: [ORG.editor.username] } });
  expect(clients[0].clientId).toMatch(/^wic-/);
  await settle(page);
  await checkA11y(page);
});

test('client names are unique per account', async ({ page }) => {
  await signIn(page, ORG.admin2);
  await open(page, '/workload-identity');
  await page.waitForLoadState('networkidle');
  await page.getByRole('button', { name: 'New client' }).first().click();
  const dlg = page.getByRole('dialog', { name: 'New workload client' });
  await dlg.getByLabel('Name').fill('CI-Deployer');
  await dlg.getByLabel('Allowed users').fill(ORG.editor.username);
  await dlg.getByRole('button', { name: 'Create client' }).click();
  const msg = 'A client named "CI-Deployer" already exists in this account. Choose another name.';
  await expect(dlg.getByText(msg)).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(dlg).toBeHidden();

  // The server refuses it too (409), even if the console's list were stale.
  const res = await page.request.post('/v1/workload-identity/clients', {
    data: { name: 'CI-Deployer', audiences: ['sts.amazonaws.com'], tokenTtlSeconds: 900, subjectFormat: 'user:{username}', auth: { method: 'access-key', allowedUsers: [ORG.editor.username] } },
    headers: { 'X-Citadel-Request': '1' }
  });
  expect(res.status()).toBe(409);
  expect(await res.json()).toMatchObject({ error: 'name_taken', message: msg });
});
