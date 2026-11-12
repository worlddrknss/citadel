import { ORG, checkA11y, expect, loadState, open, signIn, test } from './fixtures';

// The bootstrap admin (a platform admin) creates the people later specs use:
// a second admin, an editor and a viewer, all members of the first account.

test('admin creates users in the first account', async ({ page }) => {
  await signIn(page, ORG.admin);
  const { accountId } = loadState();
  await open(page, '/admin');
  await expect(page.getByRole('heading', { level: 1, name: 'Administration' })).toBeVisible();
  await page.waitForLoadState('networkidle');
  await checkA11y(page);

  const people = [
    { ...ORG.admin2, role: 'Admin', display: 'Bob Admin' },
    { ...ORG.editor, role: 'Editor', display: 'Erin Editor' },
    { ...ORG.viewer, role: 'Viewer', display: 'Victor Viewer' }
  ];
  for (const u of people) {
    await page.getByRole('button', { name: 'Create user' }).first().click();
    const dlg = page.getByRole('dialog', { name: 'Create user' });
    await dlg.getByLabel('Username').fill(u.username);
    await dlg.getByLabel('Display name').fill(u.display);
    await dlg.getByRole('radio', { name: new RegExp(`^${u.role}`) }).check();
    await dlg.getByLabel('Add to account').selectOption(accountId);
    await dlg.getByLabel('Initial password').fill(u.password);
    await dlg.getByRole('button', { name: 'Create user' }).click();
    await expect(dlg).toBeHidden();
    await expect(page.getByRole('row', { name: new RegExp(`\\b${u.username}\\b.*${u.role.toLowerCase()}`) })).toBeVisible();
  }

  // Each can sign in with the role they were given.
  for (const [u, role] of [
    [ORG.admin2, 'admin'],
    [ORG.editor, 'editor'],
    [ORG.viewer, 'viewer']
  ] as const) {
    const ctx = await page.context().browser()!.newContext({ baseURL: page.url() });
    const p = await ctx.newPage();
    await signIn(p, u);
    const me = await (await p.request.get('/v1/me')).json();
    expect(me.role).toBe(role);
    expect(me.platformAdmin).toBe(false);
    await ctx.close();
  }
});
