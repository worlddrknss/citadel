import { expect, open, test } from './fixtures';

test('roles list shows each role permissions', async ({ page }) => {
  await open(page, '/iam');
  await expect(page.getByRole('row', { name: /deploy/ })).toContainText('Read app/prod/');
  await expect(page.getByRole('row', { name: /audit-reader/ })).toContainText('Whole account');
});

test('a new role is limited to the secret paths entered', async ({ page }) => {
  await open(page, '/iam');
  await page.getByRole('button', { name: 'Create role' }).first().click();
  const dialog = page.getByRole('dialog');
  await dialog.getByLabel('Role name').fill('shop-prod');
  await dialog.getByLabel('Subjects').fill('repo:acme/shop:*');
  await expect(dialog.getByRole('button', { name: 'Secret paths' })).toHaveAttribute('aria-pressed', 'true');

  // No paths yet: the form refuses to save.
  await dialog.getByRole('button', { name: 'Create role' }).click();
  await expect(dialog).toContainText('Add at least one secret path');

  await dialog.getByLabel('Secrets this role can read').fill('shop/prod');
  const req = page.waitForRequest((r) => r.url().endsWith('/v1/iam/roles') && r.method() === 'POST');
  await dialog.getByRole('button', { name: 'Create role' }).click();
  const body = (await req).postDataJSON();
  expect(body.permissionsPolicy.Statement[0].Resource).toEqual(['arn:aws:secretsmanager:*:*:secret:shop/prod/*']);
  expect(body.permissionsPolicy.Statement[0].Action).toContain('secretsmanager:GetSecretValue');
});

test('editing a role can switch it to the whole account', async ({ page }) => {
  await open(page, '/iam');
  await page.getByRole('button', { name: 'Edit deploy' }).click();
  const dialog = page.getByRole('dialog');
  await expect(dialog.getByLabel('Secrets this role can read')).toHaveValue('app/prod/');
  await dialog.getByRole('button', { name: 'Whole account' }).click();
  await expect(dialog).toContainText('every secret, key and parameter');
  const req = page.waitForRequest((r) => r.url().endsWith('/v1/iam/roles/update'));
  await dialog.getByRole('button', { name: 'Save changes' }).click();
  expect((await req).postDataJSON().permissionsPolicy).toBeNull();
});
