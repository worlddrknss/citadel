import { ORG, checkA11y, expect, open, signIn, test } from './fixtures';

// Parameter Store: create, edit (a new version), history with old values,
// labels, and SecureString reveal rules for viewers.

test('editor creates, edits and labels parameters', async ({ page }) => {
  await signIn(page, ORG.editor);
  await open(page, '/parameters');
  await page.waitForLoadState('networkidle');

  // String parameter.
  await page.getByRole('button', { name: 'Create parameter' }).first().click();
  let dlg = page.getByRole('dialog', { name: 'Create parameter' });
  await dlg.getByRole('textbox').first().fill('live/app/url');
  await dlg.getByLabel('Value').fill('https://v1.example.com');
  await dlg.getByLabel(/Description/).fill('Service URL');
  await dlg.getByRole('button', { name: 'Create parameter' }).click();
  await expect(dlg).toBeHidden();
  await expect(page.getByText('Created /live/app/url')).toBeVisible();

  // SecureString parameter with the default key.
  await page.getByRole('button', { name: 'Create parameter' }).first().click();
  dlg = page.getByRole('dialog', { name: 'Create parameter' });
  await dlg.getByRole('textbox').first().fill('live/app/token');
  await dlg.getByText('SecureString').click();
  await dlg.getByLabel('Value').fill('s3cret-token-value');
  await dlg.getByRole('button', { name: 'Create parameter' }).click();
  await expect(dlg).toBeHidden();

  // Open the String parameter and edit it.
  await page.goto('/app/parameters?p=%2Flive%2Fapp%2Furl');
  const panel = page.getByRole('complementary', { name: 'url' });
  await expect(panel).toBeVisible();
  await expect(panel.getByText('https://v1.example.com')).toBeVisible();
  await checkA11y(page);
  await panel.getByRole('button', { name: 'Edit', exact: true }).click();
  dlg = page.getByRole('dialog', { name: 'Edit parameter' });
  await expect(dlg.getByLabel('Value')).toHaveValue('https://v1.example.com');
  await dlg.getByLabel('Value').fill('https://v2.example.com');
  await dlg.getByRole('button', { name: 'Save new version' }).click();
  await expect(dlg).toBeHidden();
  await expect(page.getByText('as version 2')).toBeVisible();
  await expect(panel.getByText('v2', { exact: true }).first()).toBeVisible();

  // History shows both versions; the old value is readable.
  await panel.getByRole('tab', { name: /History/ }).click();
  const v1 = panel.locator('li').filter({ hasText: 'v1' });
  await v1.getByRole('button', { name: 'Show value' }).click();
  await expect(v1.getByText('https://v1.example.com')).toBeVisible();

  // Label v1, then remove it.
  await v1.getByRole('button', { name: 'Label' }).click();
  await v1.getByLabel('Labels for v1').fill('stable');
  await v1.getByRole('button', { name: 'Apply' }).click();
  await expect(v1.getByRole('button', { name: 'Remove label stable from version 1' })).toBeVisible();
  await v1.getByRole('button', { name: 'Remove label stable from version 1' }).click();
  await expect(v1.getByRole('button', { name: 'Remove label stable from version 1' })).toHaveCount(0);

  // A stale edit is refused with the version guard.
  const stale = await page.request.post('/v1/parameters/update', {
    data: { name: '/live/app/url', expectedVersion: 1, value: 'x' },
    headers: { 'X-Citadel-Request': '1' }
  });
  expect(stale.status()).toBe(409);
  expect((await stale.json()).error).toBe('version_conflict');
});

test('viewer cannot reveal SecureString values unless the account allows it', async ({ page }) => {
  await signIn(page, ORG.viewer);
  await open(page, '/parameters?p=%2Flive%2Fapp%2Ftoken');
  const panel = page.getByRole('complementary', { name: 'token' });
  await expect(panel.getByText(/Hidden/).first()).toBeVisible();
  await expect(panel.getByRole('button', { name: 'Reveal value' })).toHaveCount(0);
  // Plain String values stay readable.
  await page.goto('/app/parameters?p=%2Flive%2Fapp%2Furl');
  await expect(page.getByRole('complementary', { name: 'url' }).getByText('https://v2.example.com')).toBeVisible();
  await page.waitForLoadState('networkidle');
});

test('reserved, too deep and too long names are refused in the form and by the server', async ({ page }) => {
  await signIn(page, ORG.editor);
  await open(page, '/parameters');
  await page.waitForLoadState('networkidle');
  await page.getByRole('button', { name: 'Create parameter' }).first().click();
  const dlg = page.getByRole('dialog', { name: 'Create parameter' });
  const name = dlg.getByRole('textbox').first();
  await dlg.getByLabel('Value').fill('v');
  await name.fill('SSM-config');
  await dlg.getByRole('button', { name: 'Create parameter' }).click();
  await expect(dlg.getByText('Parameter names can\'t begin with "aws" or "ssm" (in any case).')).toBeVisible();
  await name.fill('a/'.repeat(15) + 'leaf');
  await expect(dlg.getByText('A parameter hierarchy can have a maximum of 15 levels.')).toBeVisible();
  await name.fill('n'.repeat(1000));
  await expect(dlg.getByText(/Parameter names can be at most \d+ characters/)).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(dlg).toBeHidden();

  // The server applies the same rules and wording.
  for (const [n, msg] of [
    ['/aws/x', 'Parameter names can\'t begin with "aws" or "ssm" (in any case).'],
    ['/a'.repeat(16), 'A parameter hierarchy can have a maximum of 15 levels.']
  ]) {
    const res = await page.request.post('/v1/parameters', {
      data: { name: n, type: 'String', value: 'v' },
      headers: { 'X-Citadel-Request': '1' }
    });
    expect(res.status()).toBe(400);
    expect((await res.json()).message).toBe(msg);
  }
});
