import AxeBuilder from '@axe-core/playwright';
import { expect, open, test } from './fixtures';

// The API reference: reached from the help menu, renders the served OpenAPI
// document grouped by tag, expands schemas, and filters operations.

test('opens from the help menu and renders operations by tag', async ({ page }) => {
  await open(page, '/');
  await page.getByRole('button', { name: 'Help and docs' }).click();
  await page.getByRole('menuitem', { name: 'API reference' }).click();
  await expect(page).toHaveURL(/\/app\/api-reference$/);
  await expect(page.locator('main h1')).toHaveText('API reference');

  const sections = page.locator('main section h2');
  await expect(sections).toHaveText(['Secrets', 'KMS', 'Server']);
  await expect(page.getByText('4 operations', { exact: false })).toBeVisible();
});

test('expands an operation and its schemas', async ({ page }) => {
  await open(page, '/api-reference');
  const op = page.locator('details.op', { has: page.getByText('List the items in a folder') });
  await op.locator('summary').first().click();
  await expect(op.getByText('listSecrets')).toBeVisible();
  await expect(op.getByText('Viewer or above')).toBeVisible();
  await expect(op.getByRole('cell', { name: /project required/ })).toBeVisible();

  // The 200 response: SecretListing -> items: SecretItem[] -> nested fields.
  const box = op.locator('details.schemabox', { hasText: 'SecretListing' });
  await box.locator('summary').first().click();
  await expect(box.getByText('folders', { exact: true })).toBeVisible();
  await box.getByText('Fields of').first().click();
  await expect(box.getByText('updatedAt', { exact: true })).toBeVisible();
  await expect(box.getByText('string (date-time)')).toBeVisible();

  // The audit action of a write operation.
  const put = page.locator('details.op', { has: page.getByText('Create or update an item') });
  await put.locator('summary').first().press('Enter');
  await expect(put.getByText('citadel.PutItem')).toBeVisible();
  await expect(put.getByText('Approval required')).toBeVisible();
});

test('filters operations', async ({ page }) => {
  await open(page, '/api-reference');
  await page.getByRole('searchbox', { name: 'Filter operations' }).fill('encrypt');
  await expect(page.getByText('1 of 4 operations')).toBeVisible();
  await expect(page.locator('main section h2')).toHaveText(['KMS']);
  await page.getByRole('searchbox', { name: 'Filter operations' }).fill('no-such-thing');
  await expect(page.getByText('No matching operations')).toBeVisible();
});

test('has no serious or critical axe violations with an operation open', async ({ page }) => {
  await open(page, '/api-reference');
  const op = page.locator('details.op').first();
  await op.locator('summary').first().click();
  await op.locator('details.schemabox summary').first().click();
  const results = await new AxeBuilder({ page }).analyze();
  const bad = results.violations.filter((v) => v.impact === 'serious' || v.impact === 'critical').map((v) => ({ id: v.id, nodes: v.nodes.slice(0, 5).map((n) => n.target.join(' ')) }));
  expect(bad).toEqual([]);
});
