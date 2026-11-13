// Deleting certificates and CAs, restoring CAs, and Let's Encrypt renewal
// status (mocked API).

import type { Request } from '@playwright/test';
import { expect, open, test } from './fixtures';

function bodies(page: import('@playwright/test').Page, path: string) {
  const out: Record<string, unknown>[] = [];
  page.on('request', (r: Request) => {
    if (r.method() === 'POST' && new URL(r.url()).pathname === path) out.push(r.postDataJSON());
  });
  return out;
}

test('deleting a valid certificate asks for its name', async ({ page, api }) => {
  await open(page, '/certificates');
  const row = page.locator('section.certs').getByRole('row', { name: /api\.acme\.test/ });
  await row.getByRole('button', { name: 'More actions for api.acme.test' }).click();
  await page.getByRole('menuitem', { name: 'Delete' }).click();
  const dlg = page.getByRole('dialog', { name: 'Delete certificate?' });
  await expect(dlg).toContainText('revokes it first');
  const confirm = dlg.getByRole('button', { name: 'Delete' });
  await expect(confirm).toBeDisabled();
  await dlg.getByRole('textbox').fill('api.acme.test');
  await confirm.click();
  await expect(page.getByText('Certificate revoked and deleted')).toBeVisible();
  expect(api.log).toContain('DELETE /v1/certificates?source=pca-cert&id=cert-api-1');
});

test('an active CA must be disabled before deletion; a disabled one is deleted with a restore window', async ({ page, api }) => {
  const deletes = bodies(page, '/v1/certificates/authorities/delete');
  const statuses = bodies(page, '/v1/certificates/authorities/status');
  await open(page, '/certificates?cert=pca-ca:ca-root-1');
  let drawer = page.getByRole('dialog', { name: 'Acme Root CA' });
  await expect(drawer.getByTestId('ca-lifecycle')).toContainText('Disable the CA before deleting it.');
  await expect(drawer.getByTestId('ca-lifecycle')).toContainText('1 certificate issued by this CA is still valid');
  await expect(drawer.getByRole('button', { name: 'Delete' })).toHaveCount(0);
  await drawer.getByRole('button', { name: 'Disable' }).click();
  await expect(page.getByText('Disabled Acme Root CA')).toBeVisible();
  expect(statuses).toEqual([{ caId: 'ca-root-1', status: 'DISABLED' }]);

  await open(page, '/certificates?cert=pca-ca:ca-old-1');
  drawer = page.getByRole('dialog', { name: 'Acme Old CA' });
  await expect(drawer.getByTestId('ca-lifecycle')).toContainText('It can be deleted');
  await expect(drawer.getByRole('button', { name: 'Enable' })).toBeVisible();
  await drawer.getByRole('button', { name: 'Delete' }).click();
  const dlg = page.getByRole('dialog', { name: 'Delete this certificate authority?' });
  await dlg.getByLabel('Restore window (days)').fill('7');
  const submit = dlg.getByRole('button', { name: 'Delete CA' });
  await expect(submit).toBeDisabled();
  await dlg.getByLabel(/to confirm/).fill('Acme Old CA');
  await submit.click();
  await expect(page.getByText('Deleted Acme Old CA; restorable for 7 days')).toBeVisible();
  expect(deletes).toEqual([{ caId: 'ca-old-1', permanentDeletionTimeInDays: 7 }]);
  expect(api.log.some((l) => l.startsWith('POST /v1/certificates/authorities/delete'))).toBe(true);
});

test('a deleted CA shows its restore window and can be restored', async ({ page }) => {
  const restores = bodies(page, '/v1/certificates/authorities/restore');
  await open(page, '/certificates?cert=pca-ca:ca-gone-1');
  const drawer = page.getByRole('dialog', { name: 'Acme Retired CA' });
  await expect(drawer.getByTestId('ca-lifecycle')).toContainText(/It can be restored until .* \(12 days left\)/);
  await drawer.getByRole('button', { name: 'Restore' }).click();
  await expect(page.getByText('Restored Acme Retired CA (disabled)')).toBeVisible();
  expect(restores).toEqual([{ caId: 'ca-gone-1' }]);
});

test("Let's Encrypt renewal status: auto-renew toggle for HTTP-01, manual notice for DNS-01", async ({ page }) => {
  const toggles = bodies(page, '/v1/certificates/letsencrypt/auto-renew');
  await open(page, '/certificates?cert=lets-encrypt:cert-www-1');
  let drawer = page.getByRole('dialog', { name: 'www.acme.test' });
  const panel = drawer.getByTestId('le-renewal');
  await expect(panel).toContainText('Auto-renew on');
  await expect(panel.getByTestId('le-next-renewal')).not.toBeEmpty();
  const box = panel.getByRole('checkbox', { name: 'Renew automatically (HTTP-01)' });
  await expect(box).toBeChecked();
  await box.uncheck();
  await expect(page.getByText('Automatic renewal off')).toBeVisible();
  expect(toggles).toEqual([{ certId: 'cert-www-1', autoRenew: false }]);

  await open(page, '/certificates?cert=lets-encrypt:cert-dns-1');
  drawer = page.getByRole('dialog', { name: 'dns.acme.test' });
  await expect(drawer.getByTestId('le-renewal')).toContainText('Manual renewal');
  await expect(drawer.getByTestId('le-renewal')).toContainText(/expires in (19|20) days/);
  await expect(drawer.getByRole('checkbox')).toHaveCount(0);
});
