import { ORG, apiPost, checkA11y, expect, open, signIn, test } from './fixtures';

// The overview, the command palette and the notifications menu with real
// data, for an admin and a viewer.

test('overview, command palette and notifications with real data', async ({ page }) => {
  await signIn(page, ORG.admin);
  await apiPost(page, '/v1/projects', { slug: 'overview-demo', name: 'Overview demo' });
  await apiPost(page, '/v1/environments', { project: 'overview-demo', slug: 'dev', name: 'dev' });
  await apiPost(page, '/v1/secrets', { project: 'overview-demo', env: 'dev', path: '/', key: 'PALETTE_FINDS_ME', value: 'v1' });

  await open(page, '/');
  await expect(page.getByRole('heading', { level: 1, name: 'Overview' })).toBeVisible();
  await page.waitForLoadState('networkidle');
  // Real counts: at least the secret above and the account default key.
  const secretsCard = page.getByRole('link', { name: /Secrets/ }).filter({ hasText: /project/ });
  await expect(secretsCard).toContainText(/[1-9]\d*/);
  await expect(page.getByRole('link', { name: /KMS keys/ }).filter({ hasText: /enabled/ })).toContainText(/[1-9]\d* enabled/);
  await expect(page.getByRole('heading', { name: 'Recent activity' })).toBeVisible();
  // The setup checklist reads org data only an admin can see. It hides once
  // every step is done (the full suite does them all before this spec), so
  // only check that nothing on the page failed to load.
  await expect(page.getByText(/Couldn't load/)).toBeHidden();
  // The activity feed shows real actors.
  await expect(page.locator('.feed')).toContainText(ORG.admin.username);
  await checkA11y(page);

  // Command palette: Ctrl/Meta+K, find a page and a project.
  await page.keyboard.press('ControlOrMeta+k');
  const palette = page.getByRole('dialog', { name: 'Search Citadel' });
  await expect(palette).toBeVisible();
  const search = palette.getByRole('combobox');
  await search.fill('audit');
  await expect(palette.getByRole('option', { name: /^Audit log Governance/ })).toBeVisible();
  await search.fill('overview-demo');
  await expect(palette.getByRole('option', { name: /overview-demo \/ dev/ })).toBeVisible();
  await checkA11y(page);
  await palette.getByRole('option', { name: /overview-demo \/ dev/ }).click();
  await expect(page).toHaveURL(/\/app\/secrets\/overview-demo\/dev/);
  await expect(page.locator('main h1').first()).toBeVisible();

  // Inside an environment the palette searches its secrets too.
  await page.keyboard.press('ControlOrMeta+k');
  await search.fill('PALETTE_FINDS');
  await expect(palette.getByRole('option', { name: /PALETTE_FINDS_ME/ })).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(palette).toBeHidden();

  // Notifications menu opens.
  await page.getByRole('button', { name: /^Notifications/ }).click();
  const notif = page.getByRole('dialog', { name: /^Notifications, 0 items/ });
  await expect(notif.getByText("You're all caught up.")).toBeVisible();
  await checkA11y(page);
  await page.keyboard.press('Escape');
});

test('overview loads for a viewer without admin-only calls', async ({ page }) => {
  await signIn(page, ORG.viewer);
  await open(page, '/');
  await page.waitForLoadState('networkidle');
  await expect(page.getByRole('heading', { name: 'Recent activity' })).toBeVisible();
  await expect(page.getByText(/Finish setting up/)).toBeHidden();
  await checkA11y(page);
  await page.keyboard.press('ControlOrMeta+k');
  const palette = page.getByRole('dialog', { name: 'Search Citadel' });
  await palette.getByRole('combobox').fill('overview-demo');
  await expect(palette.getByRole('option', { name: /overview-demo \/ dev/ })).toBeVisible();
  await expect(palette.getByText(/Couldn't load/)).toBeHidden();
});
