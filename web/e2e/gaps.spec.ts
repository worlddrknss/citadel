import { expect, open, test } from './fixtures';

// 2.0.3 console changes against the mocked API: CA path length, workload
// client name conflicts, parameter name rules.

test('the CA tree and drawer show each CA path length', async ({ page }) => {
  await open(page, '/certificates');
  const tree = page.getByRole('region', { name: 'CA hierarchy' });
  await expect(tree.getByRole('button', { name: /Acme Root CA/ })).toContainText('pathLen: unlimited');
  const sub = tree.getByRole('button', { name: /Acme Issuing CA/ });
  await expect(sub).toContainText('pathLen: 0');
  await sub.click();
  await expect(page.getByTestId('ca-pathlen')).toHaveText(/^0 — issues end-entity certificates only/);
});

test('a duplicate workload client name shows the server conflict on the name field', async ({ page, allowConsole }) => {
  allowConsole(/status of 409/);
  await page.route('**/v1/workload-identity/clients', (route) =>
    route.request().method() === 'POST'
      ? route.fulfill({
          status: 409,
          json: { error: 'name_taken', message: 'A client named "fresh-name" already exists in this account. Choose another name.' }
        })
      : route.fallback()
  );
  await open(page, '/workload-identity');
  await page.getByRole('button', { name: 'New client' }).first().click();
  const dlg = page.getByRole('dialog', { name: 'New workload client' });
  await dlg.getByLabel('Name').fill('fresh-name');
  await dlg.getByRole('button', { name: 'Citadel access key' }).click();
  await dlg.getByLabel('Allowed users').fill('alice');
  await dlg.getByRole('button', { name: 'Create client' }).click();
  await expect(dlg.getByText('A client named "fresh-name" already exists in this account. Choose another name.')).toBeVisible();
  await expect(dlg).toBeVisible();
});

test('parameter names beginning with aws or ssm are refused before submitting', async ({ page, api }) => {
  await open(page, '/parameters');
  await page.getByRole('button', { name: 'Create parameter' }).first().click();
  const dlg = page.getByRole('dialog', { name: 'Create parameter' });
  await dlg.getByRole('textbox').first().fill('AWS-thing');
  await dlg.getByLabel('Value').fill('v');
  await dlg.getByRole('button', { name: 'Create parameter' }).click();
  await expect(dlg.getByText('Parameter names can\'t begin with "aws" or "ssm" (in any case).')).toBeVisible();
  expect(api.log.filter((l) => l.startsWith('POST /v1/parameters'))).toEqual([]);
});
