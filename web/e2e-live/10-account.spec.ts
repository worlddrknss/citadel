import { ORG, checkA11y, expect, open, signIn, test } from './fixtures';

// My account as the editor: profile, an access key whose secret is shown
// once, and signing out another session.

test('profile, access key shown once, sessions list and revoke', async ({ page, browser, baseURL }) => {
  // A second session for the same user, in its own browser context.
  const other = await browser.newContext({ baseURL, userAgent: 'Mozilla/5.0 (X11; Linux x86_64) Firefox/140.0' });
  const otherPage = await other.newPage();
  await signIn(otherPage, ORG.editor);

  await signIn(page, ORG.editor);
  await open(page, '/account');
  await expect(page.getByRole('heading', { level: 1, name: 'My account' })).toBeVisible();
  await page.waitForLoadState('networkidle');
  await checkA11y(page);

  // Profile.
  await page.getByRole('button', { name: 'Edit display name' }).click();
  await page.getByLabel('Display name').fill('Erin E. Editor');
  await page.getByRole('button', { name: 'Save', exact: true }).click();
  await expect(page.getByText('Display name updated')).toBeVisible();
  expect((await (await page.request.get('/v1/me')).json()).displayName).toBe('Erin E. Editor');

  // Access key: the secret appears once, then never again.
  await page.getByRole('button', { name: 'Create access key' }).click();
  const dlg = page.getByRole('dialog', { name: 'Access key created' });
  await expect(dlg).toBeVisible();
  const keyId = (await dlg.locator('code.val').first().textContent())!.trim();
  const secret = (await dlg.locator('code.val').nth(1).textContent())!.trim();
  expect(keyId).toMatch(/^AKIA[A-Z0-9]{12,}$/);
  expect(secret.length).toBeGreaterThanOrEqual(30);
  await expect(dlg.getByRole('button', { name: 'Done' })).toBeDisabled();
  await dlg.getByLabel("I've saved it somewhere safe").check();
  await dlg.getByRole('button', { name: 'Done' }).click();
  await expect(dlg).toBeHidden();
  const keysTable = page.getByRole('table', { name: 'Access keys' });
  await expect(keysTable.getByText(keyId)).toBeVisible();
  await expect(page.getByText(secret)).toHaveCount(0);
  const listed = await (await page.request.get('/v1/account/keys')).text();
  expect(listed).not.toContain(secret);

  // Sessions: this one plus the Firefox one; sign the other out.
  const sessions = page.getByRole('region', { name: 'Active sessions' }).or(page.locator('section[aria-labelledby="sess-title"]'));
  await expect(sessions.getByText(/Firefox/).first()).toBeVisible();
  await sessions.getByRole('button', { name: /^Sign out .*Firefox.* session$/ }).click();
  await page.getByRole('button', { name: 'Sign out session' }).click();
  await expect(page.getByText('Session signed out')).toBeVisible();
  await expect(sessions.getByText(/Firefox/)).toHaveCount(0);
  expect((await otherPage.request.get('/v1/me')).status()).toBe(401);
  await other.close();
});
