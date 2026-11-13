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

test('viewer sees the ACME policy read-only', async ({ page }) => {
  await signIn(page, ORG.viewer);
  await open(page, '/certificates?tab=acme');
  await expect(page.getByLabel('Allowed domains')).toBeDisabled();
  await expect(page.getByRole('button', { name: 'Save policy' })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Create key' })).toHaveCount(0);
});
