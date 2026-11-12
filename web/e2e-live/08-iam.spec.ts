import type { Page } from '@playwright/test';
import { ORG, checkA11y, expect, open, signIn, test } from './fixtures';

/** Waits for drawer/modal transitions, which axe would read mid-fade. */
async function settle(page: Page) {
  await page.waitForTimeout(300);
  await page.waitForFunction(() => document.getAnimations().every((a) => a.playState !== 'running'));
}

// IAM federation: an OIDC provider and roles consumed by STS, created and
// edited through the console against the real /v1/iam API.

const ISSUER = 'https://token.actions.githubusercontent.com';

test('admin adds and edits an OIDC provider', async ({ page, expectStatus }) => {
  await signIn(page, ORG.admin);
  await open(page, '/iam');
  await page.getByRole('tab', { name: /Identity providers/ }).click();
  await page.waitForLoadState('networkidle');
  await checkA11y(page);

  await page.getByRole('button', { name: 'Add provider' }).first().click();
  let dlg = page.getByRole('dialog', { name: 'Add identity provider' });
  await dlg.getByLabel('Issuer URL').fill(ISSUER);
  await dlg.getByLabel('Audiences').fill('sts.amazonaws.com');
  await dlg.getByRole('button', { name: 'Add provider' }).click();
  await expect(dlg).toBeHidden();
  await expect(page.getByRole('row', { name: ISSUER })).toBeVisible();

  // Registering the same issuer again is refused instead of overwriting it.
  expectStatus(409, /\/v1\/iam\/oidc-providers$/);
  await page.getByRole('button', { name: 'Add provider' }).first().click();
  dlg = page.getByRole('dialog', { name: 'Add identity provider' });
  await dlg.getByLabel('Issuer URL').fill(ISSUER);
  await dlg.getByLabel('Audiences').fill('other');
  await dlg.getByRole('button', { name: 'Add provider' }).click();
  await expect(dlg.getByRole('alert')).toContainText(/already registered/);
  await dlg.getByRole('button', { name: 'Cancel' }).click();

  await page.getByRole('button', { name: `Edit ${ISSUER}` }).click();
  dlg = page.getByRole('dialog', { name: 'Edit identity provider' });
  await dlg.getByLabel('Audiences').fill('sts.amazonaws.com, sts.citadel');
  await dlg.getByRole('button', { name: 'Save changes' }).click();
  await expect(dlg).toBeHidden();
  await expect(page.getByRole('row', { name: /sts\.citadel/ })).toBeVisible();
});

test('admin creates and edits a role trusting the provider', async ({ page }) => {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await signIn(page, ORG.admin);
  await open(page, '/iam');
  await page.getByRole('button', { name: 'Create role' }).first().click();
  let dlg = page.getByRole('dialog', { name: 'Create role' });
  await dlg.getByLabel('Role name').fill('gha-deploy');
  await dlg.getByLabel('Description').fill('GitHub Actions deploys');
  await dlg.getByLabel('Identity provider').selectOption(ISSUER);
  await dlg.getByLabel('Audiences').fill('sts.citadel');
  await dlg.getByLabel('Subjects').fill('repo:acme/app:ref:refs/heads/main');
  await dlg.getByRole('button', { name: 'Create role' }).click();
  await expect(dlg).toBeHidden();
  // The new role opens in its drawer.
  const drawer = page.getByRole('dialog', { name: 'gha-deploy' });
  await expect(drawer.getByText(ISSUER, { exact: true })).toBeVisible();
  await settle(page);
  await checkA11y(page);
  await drawer.getByRole('button', { name: 'Close panel' }).click();
  await expect(page.getByRole('row', { name: /gha-deploy/ })).toBeVisible();

  await page.getByRole('button', { name: 'Edit gha-deploy' }).click();
  dlg = page.getByRole('dialog', { name: 'Edit gha-deploy' });
  await dlg.getByLabel('Subjects').fill('repo:acme/app:*');
  await dlg.getByLabel('Description').fill('Any ref of acme/app');
  await dlg.getByRole('button', { name: 'Save changes' }).click();
  await expect(dlg).toBeHidden();

  const roles = await (await page.request.get('/v1/iam/roles')).json();
  const role = roles.roles.find((r: { roleName: string }) => r.roleName === 'gha-deploy');
  expect(role.description).toBe('Any ref of acme/app');
  expect(role.trust.subjects).toEqual(['repo:acme/app:*']);
  await page.waitForLoadState('networkidle');
  await checkA11y(page);
});

test('an editor sees IAM read-only', async ({ page }) => {
  await signIn(page, ORG.editor);
  await open(page, '/iam');
  await expect(page.getByRole('row', { name: /gha-deploy/ })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Create role' })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Edit gha-deploy' })).toHaveCount(0);
});
