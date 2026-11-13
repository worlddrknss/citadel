import type { Browser, Page } from '@playwright/test';
import { ORG, checkA11y, expect, open, signIn, test } from './fixtures';

// Secrets end to end: project → environments → folder → secret, reveal,
// versions and restore, and the viewersCanReveal account setting as seen by
// a viewer.

const PROJECT = 'payments';

async function asUser(browser: Browser, baseURL: string, user: { username: string; password: string }) {
  const ctx = await browser.newContext({ baseURL });
  const page = await ctx.newPage();
  await signIn(page, user);
  return { ctx, page };
}

async function addSecret(page: Page, key: string, value: string) {
  await page.getByRole('button', { name: 'Add secret' }).first().click();
  const dlg = page.getByRole('dialog', { name: 'Add secret' });
  await dlg.getByRole('textbox', { name: /^Key/ }).fill(key);
  await dlg.locator('#vv').fill(value);
  await dlg.getByRole('button', { name: 'Add secret' }).click();
  await expect(dlg).toBeHidden();
  await expect(page.getByRole('row', { name: new RegExp(key) })).toBeVisible();
}

test('admin creates a project, environments, a folder and secrets', async ({ page }) => {
  await signIn(page, ORG.admin);
  await open(page, '/secrets');
  await page.waitForLoadState('networkidle');
  await checkA11y(page);

  await page.getByRole('button', { name: 'New project' }).first().click();
  const pdlg = page.getByRole('dialog', { name: 'New project' });
  await pdlg.getByLabel('Slug').fill(PROJECT);
  await pdlg.getByLabel('Display name').fill('Payments');
  await pdlg.getByRole('button', { name: 'Create project' }).click();
  await expect(pdlg).toBeHidden();

  await open(page, `/secrets/${PROJECT}`);
  for (const env of ['dev', 'prod']) {
    await page.getByRole('button', { name: 'New environment' }).first().click();
    const edlg = page.getByRole('dialog', { name: 'New environment' });
    await edlg.getByLabel('Slug').fill(env);
    await edlg.getByRole('button', { name: 'Create environment' }).click();
    await expect(edlg).toBeHidden();
    await expect(page.getByRole('link', { name: new RegExp(`^${env}`, 'i') }).first()).toBeVisible();
  }
  await page.waitForLoadState('networkidle');
  await checkA11y(page);

  await open(page, `/secrets/${PROJECT}/dev`);
  await addSecret(page, 'DB_PASSWORD', 'dev-password-1');

  // A folder, with a key inside it.
  await page.getByRole('button', { name: 'Environment', exact: true }).click();
  await page.getByRole('menuitem', { name: 'New folder…' }).click();
  const fdlg = page.getByRole('dialog', { name: 'New folder' });
  await fdlg.getByLabel('Folder name').fill('database');
  await fdlg.getByRole('button', { name: 'Create folder' }).click();
  await expect(fdlg).toBeHidden();
  await page.getByRole('link', { name: /database/ }).first().click();
  await expect(page).toHaveURL(/path=%2Fdatabase|path=\/database/);
  await addSecret(page, 'HOST', 'db.internal');

  // prod gets a secret too (the approvals spec changes it).
  await open(page, `/secrets/${PROJECT}/prod`);
  await addSecret(page, 'API_KEY', 'prod-api-key-1');
  await page.waitForLoadState('networkidle');
  await checkA11y(page);
});

test('reveal, versions and restore', async ({ page }) => {
  await signIn(page, ORG.admin);
  await open(page, `/secrets/${PROJECT}/dev`);
  const row = page.getByRole('row', { name: /DB_PASSWORD/ });
  await row.getByRole('button', { name: 'Reveal value' }).click();
  await expect(row).toContainText('dev-password-1');

  // A second version.
  await row.getByRole('button', { name: /actions|More/i }).click();
  await page.getByRole('menuitem', { name: 'Edit value…' }).click();
  const vdlg = page.getByRole('dialog', { name: /New value for DB_PASSWORD/ });
  await vdlg.locator('#vv').fill('dev-password-2');
  await vdlg.getByRole('button', { name: 'Save new version' }).click();
  await expect(vdlg).toBeHidden();

  // Drawer: details show the keyed fingerprint; versions list v2 then v1.
  await page.getByRole('button', { name: 'Open details for DB_PASSWORD' }).click();
  const drawer = page.getByRole('complementary').filter({ hasText: 'DB_PASSWORD' }).last();
  await expect(drawer.getByText(/fingerprint/)).toBeVisible();
  await expect(drawer.getByText(/hmac:[0-9a-f]{12}/)).toBeVisible();
  await drawer.getByRole('tab', { name: /Versions/ }).click();
  // The Details tab also lists recent versions, so wait for the switch (a
  // URL navigation) before looking for v2, or both copies match.
  await expect(drawer.getByRole('tabpanel', { name: 'versions' })).toBeVisible();
  await expect(drawer.getByText('v2', { exact: true })).toBeVisible();
  await expect(drawer.getByText('v1', { exact: true })).toBeVisible();
  await checkA11y(page);
  await drawer.getByRole('button', { name: 'Restore version 1' }).click();
  await page.getByRole('dialog').getByRole('button', { name: 'Restore version' }).click();
  await expect(page.getByText(/v1 is current|Restored|now current/i).first()).toBeVisible();

  // The value is v1's again.
  const res = await page.request.get(`/v1/secrets/value?project=${PROJECT}&env=dev&path=%2F&key=DB_PASSWORD`);
  expect((await res.json()).value).toBe('dev-password-1');
});

test('viewersCanReveal: viewers see Reveal and Export only when allowed', async ({ page, browser, baseURL }) => {
  // Off by default: the viewer sees no Reveal or Export.
  const viewer = await asUser(browser, baseURL!, ORG.viewer);
  await open(viewer.page, `/secrets/${PROJECT}/dev`);
  const vrow = viewer.page.getByRole('row', { name: /DB_PASSWORD/ });
  await expect(vrow).toBeVisible();
  await expect(vrow.getByRole('button', { name: 'Reveal value' })).toHaveCount(0);
  await expect(viewer.page.getByRole('button', { name: /^Export/ })).toHaveCount(0);
  await viewer.page.waitForLoadState('networkidle');
  await checkA11y(viewer.page);

  // The admin turns it on from the Secrets settings.
  await signIn(page, ORG.admin);
  await open(page, '/secrets');
  await page.getByRole('button', { name: 'Settings' }).click();
  const sdlg = page.getByRole('dialog', { name: 'Secrets settings' });
  const box = sdlg.getByRole('checkbox', { name: /Viewers can reveal values/ });
  await expect(box).not.toBeChecked();
  await checkA11y(page);
  await box.check();
  await sdlg.getByRole('button', { name: 'Save settings' }).click();
  await expect(sdlg).toBeHidden();

  // Now the viewer can reveal.
  await viewer.page.reload();
  const vrow2 = viewer.page.getByRole('row', { name: /DB_PASSWORD/ });
  await vrow2.getByRole('button', { name: 'Reveal value' }).click();
  await expect(vrow2).toContainText('dev-password-1');
  await expect(viewer.page.getByRole('button', { name: /^Export/ })).toBeVisible();
  await viewer.ctx.close();

  // Back off, so later specs see the default.
  await page.getByRole('button', { name: 'Settings' }).click();
  await sdlg.getByRole('checkbox', { name: /Viewers can reveal values/ }).uncheck();
  await sdlg.getByRole('button', { name: 'Save settings' }).click();
  await expect(sdlg).toBeHidden();
});
