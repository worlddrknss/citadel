// Imported ACM certificates in the certificates list and drawer, and the
// full chain to the root in the certificate detail (mocked API).

import { expect, open, test } from './fixtures';

const IMPORTED_ARN = 'arn:aws:acm:us-east-1:000000000000:certificate/imp1';

test('imported ACM certificates are listed read-only, with the chain to the root and delete', async ({ page, api }) => {
  await open(page, '/certificates');
  const table = page.locator('section.certs');
  const row = table.getByRole('row', { name: /legacy\.acme\.test/ });
  await expect(row).toContainText('Imported');
  await expect(row).toContainText('External Issuing CA');

  // The row menu offers no renew or revoke, only details and delete.
  await row.getByRole('button', { name: 'More actions for legacy.acme.test' }).click();
  const menu = page.getByRole('menu', { name: 'More actions for legacy.acme.test' });
  await expect(menu.getByRole('menuitem')).toHaveText(['View details', 'Delete']);
  await page.keyboard.press('Escape');

  await row.getByRole('button', { name: 'legacy.acme.test', exact: true }).click();
  const drawer = page.getByRole('dialog', { name: 'legacy.acme.test' });
  await expect(drawer.getByText('Imported', { exact: true })).toBeVisible();
  await expect(drawer.getByRole('button', { name: 'Renew' })).toHaveCount(0);
  await expect(drawer.getByRole('button', { name: 'Revoke' })).toHaveCount(0);

  await drawer.getByRole('tab', { name: 'Chain' }).click();
  const links = drawer.getByTestId('chain-cert');
  await expect(links).toHaveCount(3);
  await expect(links.nth(0)).toContainText('Leaf');
  await expect(links.nth(0)).toContainText('CN=legacy.acme.test');
  await expect(links.nth(1)).toContainText('Intermediate');
  await expect(links.nth(1)).toContainText('CN=External Issuing CA,O=Example');
  await expect(links.nth(2)).toContainText('Root');
  await expect(links.nth(2)).toContainText('(self-signed)');
  await expect(drawer.getByTestId('chain-incomplete')).toHaveCount(0);

  const download = page.waitForEvent('download');
  await links.nth(2).getByRole('button', { name: /Download root certificate/ }).click();
  expect((await download).suggestedFilename()).toBe('External_Root_CA.pem');

  await drawer.getByRole('button', { name: 'Delete' }).click();
  const confirmDlg = page.getByRole('dialog', { name: 'Delete imported certificate?' });
  await confirmDlg.getByRole('button', { name: 'Delete' }).click();
  await expect(page.getByText('Certificate deleted')).toBeVisible();
  expect(api.log).toContain(`DELETE /v1/certificates/acm?${new URLSearchParams({ arn: IMPORTED_ARN })}`);
});

test('a private CA certificate shows its chain up to the root CA', async ({ page }) => {
  await open(page, '/certificates?cert=pca-cert:cert-api-1&view=chain');
  const drawer = page.getByRole('dialog', { name: 'api.acme.test' });
  const links = drawer.getByTestId('chain-cert');
  await expect(links).toHaveCount(2);
  await expect(links.nth(0)).toContainText('Leaf');
  await expect(links.nth(1)).toContainText('Root');
  await expect(drawer.getByRole('button', { name: 'Renew' })).toBeVisible();
});
