import { ORG, checkA11y, expect, open, signIn, test } from './fixtures';

// Private CA hierarchy, issuance with a generated key, revocation, and the
// built-in ACME server's issuance policy and EAB keys.

test('root CA, subordinate CA, issue with a generated key, revoke', async ({ page }) => {
  await signIn(page, ORG.admin);
  await open(page, '/certificates');
  await page.waitForLoadState('networkidle');

  // Root CA.
  await page.getByRole('button', { name: 'Create root CA' }).click();
  let dlg = page.getByRole('dialog', { name: 'New certificate authority' });
  await dlg.getByLabel('Common name').fill('Live Root CA');
  await dlg.getByRole('button', { name: /Create/ }).click();
  await expect(dlg).toBeHidden();
  // The new CA opens; a root can sign subordinates.
  let drawer = page.getByRole('dialog').filter({ hasText: 'Live Root CA' });
  await expect(drawer).toBeVisible();
  await drawer.getByRole('button', { name: 'New subordinate' }).click();
  dlg = page.getByRole('dialog', { name: 'New certificate authority' });
  await expect(dlg.getByLabel('Parent CA')).toContainText('Live Root CA');
  await dlg.getByLabel('Common name').fill('Live Issuing CA');
  await dlg.getByRole('button', { name: /Create/ }).click();
  await expect(dlg).toBeHidden();
  await expect(page.getByRole('button', { name: /Live Issuing CA/ }).first()).toBeVisible();

  // A subordinate can't sign further CAs, so its drawer offers no "New subordinate".
  drawer = page.getByRole('dialog').filter({ hasText: 'Live Issuing CA' });
  await expect(drawer.getByRole('button', { name: 'Issue from this CA' })).toBeVisible();
  await expect(drawer.getByRole('button', { name: 'New subordinate' })).toHaveCount(0);
  // The path length constraint shows in the drawer and the CA tree.
  await expect(drawer.getByTestId('ca-pathlen')).toHaveText(/^0 — issues end-entity certificates only/);
  const tree = page.getByRole('region', { name: 'CA hierarchy' });
  await expect(tree.getByRole('button', { name: /Live Issuing CA/ })).toContainText('pathLen: 0');
  await expect(tree.getByRole('button', { name: /Live Root CA/ })).toContainText('pathLen: unlimited');
  const { certificates } = await (await page.request.get('/v1/certificates')).json();
  const issuing = certificates.find((c: { subject: string }) => c.subject.includes('Live Issuing CA'));
  expect(issuing).toMatchObject({ isCA: true, pathLen: 0 });
  await checkA11y(page);
  await drawer.getByRole('button', { name: 'Issue from this CA' }).click();

  // Issue: starting from the CA skips the issuer step; generate the key in Citadel.
  dlg = page.getByRole('dialog', { name: 'Issue certificate' });
  await expect(dlg.getByText('From Live Issuing CA.')).toBeVisible();
  await dlg.getByLabel('Common name').fill('orders.live.example.com');
  await dlg.getByRole('button', { name: /Continue/ }).click();
  await dlg.getByRole('radio', { name: /Generate in Citadel/ }).check();
  await dlg.getByRole('button', { name: 'Issue certificate' }).click();
  const once = page.getByRole('dialog').filter({ hasText: "I've saved it somewhere safe" });
  await expect(once).toBeVisible();
  await expect(once.getByText('-----BEGIN PRIVATE KEY-----', { exact: false }).first()).toBeAttached();
  await once.getByLabel("I've saved it somewhere safe").check();
  await once.getByRole('button', { name: 'Done' }).click();

  // The new certificate opens; revoke it.
  const cert = page.getByRole('dialog').filter({ hasText: 'orders.live.example.com' });
  await expect(cert).toBeVisible();
  await expect(cert.getByText('Server TLS', { exact: false }).or(cert.getByText('server', { exact: true })).first()).toBeVisible();
  await cert.getByRole('button', { name: 'Revoke' }).click();
  dlg = page.getByRole('dialog', { name: 'Revoke this certificate?' });
  await dlg.getByLabel('Reason').selectOption('Superseded');
  await dlg.getByLabel(/to confirm/).fill('orders.live.example.com');
  await dlg.getByRole('button', { name: 'Revoke certificate' }).click();
  await expect(dlg).toBeHidden();

  await page.goto('/app/certificates?filter=revoked');
  await expect(page.getByRole('button', { name: 'orders.live.example.com', exact: true })).toBeVisible();
});

test('ACME server: issuance policy and an EAB key shown once', async ({ page, expectStatus }) => {
  await signIn(page, ORG.admin);
  await open(page, '/certificates?tab=acme');
  await expect(page.getByRole('heading', { name: 'Issuance policy' })).toBeVisible();
  await expect(page.getByTestId('acme-directory')).toHaveText(/^http:\/\/127\.0\.0\.1:\d+\/acme\/directory$/);
  // Nothing saved yet: every order would be refused; the automatic CA is the oldest active one.
  await expect(page.getByText('No names are allowed yet')).toBeVisible();
  // (Both CAs were created within the same second, so either may count as oldest.)
  await expect(page.getByTestId('acme-effective-ca')).toHaveText(/^Live (Root|Issuing) CA$/);
  await checkA11y(page);

  // Invalid input is reported from the server.
  expectStatus(400, /\/v1\/certificates\/acme\/settings$/);
  await page.getByLabel('Allowed domains').fill('*.bad.example.com');
  await page.getByRole('button', { name: 'Save policy' }).click();
  await expect(page.getByRole('alert')).toContainText('allowedDomains');

  await page.getByLabel('Issuing CA').selectOption({ label: 'Live Issuing CA' });
  await page.getByLabel('Allowed domains').fill('Live.Example.com\ninternal.example.com');
  await page.getByLabel(/Allowed IP ranges/).fill('10.1.2.3');
  await page.getByRole('button', { name: 'Save policy' }).click();
  await expect(page.getByText('ACME settings saved')).toBeVisible();
  // The server normalizes entries.
  await expect(page.getByLabel('Allowed domains')).toHaveValue('live.example.com\ninternal.example.com');
  await expect(page.getByLabel(/Allowed IP ranges/)).toHaveValue('10.1.2.3/32');
  await expect(page.getByTestId('acme-effective-ca')).toHaveText('Live Issuing CA');
  await expect(page.getByText('No names are allowed yet')).toHaveCount(0);

  const saved = await (await page.request.get('/v1/certificates/acme/settings')).json();
  expect(saved.allowedDomains).toEqual(['live.example.com', 'internal.example.com']);

  // EAB key: the HMAC key is shown once.
  await page.getByRole('button', { name: 'Create key' }).first().click();
  const dlg = page.getByRole('dialog', { name: 'Create EAB key' });
  await dlg.getByLabel('Label').fill('live cert-manager');
  await dlg.getByRole('button', { name: 'Create key' }).click();
  const once = page.getByRole('dialog', { name: 'EAB key created' });
  await expect(once.getByText('HMAC key', { exact: true })).toBeVisible();
  await once.getByLabel("I've saved it somewhere safe").check();
  await once.getByRole('button', { name: 'Done' }).click();
  await expect(page.getByRole('row', { name: /live cert-manager.*Unused/ })).toBeVisible();
  const keys = await (await page.request.get('/v1/certificates/acme/eab')).json();
  expect(keys.keys[0]).not.toHaveProperty('hmacKey');
});

// Let's Encrypt issuance is asynchronous: the request returns an order to
// poll. (Nothing here reaches a real ACME server.)
test("Let's Encrypt order endpoints answer without holding the request", async ({ page }) => {
  await signIn(page, ORG.editor);
  const post = (data: unknown) => page.request.post('/v1/certificates/letsencrypt/request', { data, headers: { 'X-Citadel-Request': '1' } });
  const wildcard = await post({ domains: '*.live.example.com' });
  expect(wildcard.status()).toBe(400);
  expect((await wildcard.json()).message).toMatch(/DNS-01/);
  expect((await post({ domains: ' ' })).status()).toBe(400);
  const missing = await page.request.get('/v1/certificates/letsencrypt/orders?id=does-not-exist');
  expect(missing.status()).toBe(404);
  const noId = await page.request.post('/v1/certificates/letsencrypt/dns/complete', { data: { orderId: 'nope' }, headers: { 'X-Citadel-Request': '1' } });
  expect(noId.status()).toBe(404);

  // The console checks the form before starting an order.
  await open(page, '/certificates?tab=letsencrypt');
  await page.getByLabel('Domains').fill('*.live.example.com');
  await page.getByRole('button', { name: 'Request certificate' }).click();
  await expect(page.getByText(/Wildcards need DNS-01/)).toBeVisible();
});

test('viewer sees the ACME policy read-only', async ({ page }) => {
  await signIn(page, ORG.viewer);
  await open(page, '/certificates?tab=acme');
  await expect(page.getByLabel('Allowed domains')).toBeDisabled();
  await expect(page.getByRole('button', { name: 'Save policy' })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Create key' })).toHaveCount(0);
});

test('full chain in the detail; delete a revoked certificate; disable, delete and restore a CA', async ({ page }) => {
  await signIn(page, ORG.admin);
  const { certificates } = await (await page.request.get('/v1/certificates')).json();
  type Row = { source: string; id: string; subject: string; commonName?: string };
  const revoked = (certificates as Row[]).find((c) => c.source === 'pca-cert' && c.commonName === 'orders.live.example.com');
  expect(revoked).toBeTruthy();

  // The detail carries the chain from the leaf to the root.
  const detail = await (await page.request.get(`/v1/certificates/detail?${new URLSearchParams({ source: 'pca-cert', id: revoked!.id })}`)).json();
  expect(detail.chain.map((c: { role: string }) => c.role)).toEqual(['leaf', 'intermediate', 'root']);
  expect(detail.chain[1].subject).toContain('Live Issuing CA');
  expect(detail.chain[2].subject).toContain('Live Root CA');
  await open(page, `/certificates?cert=pca-cert:${revoked!.id}&view=chain`);
  await expect(page.getByTestId('chain-cert')).toHaveCount(3);

  // A revoked certificate is deleted without typing its name.
  await open(page, '/certificates?filter=revoked');
  const row = page.locator('section.certs').getByRole('row', { name: /orders\.live\.example\.com/ });
  await row.getByRole('button', { name: 'More actions for orders.live.example.com' }).click();
  await page.getByRole('menuitem', { name: 'Delete' }).click();
  const confirm = page.getByRole('dialog', { name: 'Delete certificate?' });
  await expect(confirm.getByRole('textbox')).toHaveCount(0);
  await confirm.getByRole('button', { name: 'Delete' }).click();
  await expect(page.getByText('Certificate deleted')).toBeVisible();
  await expect(row).toHaveCount(0);

  // A CA: disable, delete with a 7-day window, restore.
  await open(page, '/certificates');
  await page.getByRole('button', { name: 'New CA' }).or(page.getByRole('button', { name: 'Create root CA' })).first().click();
  let dlg = page.getByRole('dialog', { name: 'New certificate authority' });
  await dlg.getByLabel('Common name').fill('Live Disposable CA');
  await dlg.getByRole('button', { name: /Create/ }).click();
  await expect(dlg).toBeHidden();
  const drawer = page.getByRole('dialog').filter({ hasText: 'Live Disposable CA' });
  await expect(drawer.getByTestId('ca-lifecycle')).toContainText('Disable the CA before deleting it.');
  await drawer.getByRole('button', { name: 'Disable' }).click();
  await expect(drawer.getByTestId('ca-lifecycle')).toContainText('It can be deleted');
  await drawer.getByRole('button', { name: 'Delete' }).click();
  dlg = page.getByRole('dialog', { name: 'Delete this certificate authority?' });
  await dlg.getByLabel('Restore window (days)').fill('7');
  await dlg.getByLabel(/to confirm/).fill('Live Disposable CA');
  await dlg.getByRole('button', { name: 'Delete CA' }).click();
  await expect(dlg).toBeHidden();
  await expect(drawer.getByTestId('ca-lifecycle')).toContainText(/It can be restored until .* \(7 days left\)/);
  await drawer.getByRole('button', { name: 'Restore' }).click();
  await expect(drawer.getByTestId('ca-lifecycle')).toContainText('It can be deleted');
  await expect(drawer.getByRole('button', { name: 'Enable' })).toBeVisible();
});
