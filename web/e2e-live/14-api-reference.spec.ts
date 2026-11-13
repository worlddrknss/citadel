import { ORG, checkA11y, expect, open, signIn, test } from './fixtures';

// The API reference renders the server's real OpenAPI document, which is
// also served unauthenticated at /v1/openapi.yaml.

test('the spec is served without a session', async ({ request }) => {
  const res = await request.get('/v1/openapi.yaml');
  expect(res.status()).toBe(200);
  expect(res.headers()['content-type']).toContain('yaml');
  const text = await res.text();
  expect(text).toMatch(/^openapi: 3\.1/m);
  expect(text).toContain('/v1/secrets:');
});

test('API reference renders the real spec from the help menu', async ({ page }) => {
  await signIn(page, ORG.admin);
  await open(page, '/');
  await page.getByRole('button', { name: 'Help and docs' }).click();
  await page.getByRole('menuitem', { name: 'API reference' }).click();
  await expect(page.getByRole('heading', { level: 1, name: 'API reference' })).toBeVisible();

  await expect(page.getByRole('heading', { level: 2, name: 'Secrets' })).toBeVisible();
  await page.getByRole('searchbox', { name: 'Filter operations' }).fill('listSecrets');
  const op = page.locator('details.op').filter({ hasText: '/v1/secrets' }).first();
  await expect(op).toBeVisible();
  await op.locator('summary').first().click();
  await expect(op.getByText('listSecrets')).toBeVisible();
  await expect(op.locator('details.schemabox').first()).toBeVisible();
  await op.locator('details.schemabox summary').first().click();
  await checkA11y(page);

  await page.getByRole('searchbox', { name: 'Filter operations' }).fill('kmsEncrypt');
  await expect(page.locator('details.op').filter({ hasText: '/v1/kms/encrypt' })).toBeVisible();
});
