import { ORG, checkA11y, expect, open, signIn, test } from './fixtures';

// Built-in rotation end to end: set up the random rotator from the secret
// drawer's Rotation tab, rotate once, and check the value changed, the
// history shows it, the old value is AWSPREVIOUS and every step is audited.

test('random rotator rotates a secret from the Rotation tab', async ({ page }) => {
  await signIn(page, ORG.admin);
  await open(page, '/secrets/payments/dev');

  await page.getByRole('button', { name: 'Add secret' }).first().click();
  const dlg = page.getByRole('dialog', { name: 'Add secret' });
  await dlg.getByRole('textbox', { name: /^Key/ }).fill('ROTATING_TOKEN');
  await dlg.locator('#vv').fill('before-rotation');
  await dlg.getByRole('button', { name: 'Add secret' }).click();
  await expect(dlg).toBeHidden();

  const row = page.getByRole('row', { name: /ROTATING_TOKEN/ });
  await row.getByRole('button', { name: 'Open details for ROTATING_TOKEN' }).click();
  await page.getByRole('tab', { name: 'Rotation' }).click();
  const panel = page.getByRole('tabpanel');
  await expect(panel.getByText('Off', { exact: true })).toBeVisible();
  await expect(panel.getByText('No rotations yet.')).toBeVisible();
  await page.waitForLoadState('networkidle');
  await checkA11y(page);

  await panel.getByRole('button', { name: 'Set up rotation' }).click();
  await panel.getByLabel('Password length').fill('48');
  await panel.getByRole('textbox', { name: /^Exclude characters/ }).fill('O0Il');
  await expect(panel.getByLabel('Rotate once now as well')).toBeChecked();
  await panel.getByRole('button', { name: 'Save rotation' }).click();

  // The rotation runs in the background; the tab polls until it's done.
  await expect(panel.getByText('Rotated', { exact: true })).toBeVisible({ timeout: 20_000 });
  await expect(panel.getByText('On', { exact: true })).toBeVisible();
  await expect(panel.getByText('Every 30 days')).toBeVisible();
  await checkA11y(page);

  const q = new URLSearchParams({ project: 'payments', env: 'dev', path: '/', key: 'ROTATING_TOKEN' });
  const status = await (await page.request.get(`/v1/secrets/rotation?${q}`)).json();
  expect(status).toMatchObject({ enabled: true, mode: 'builtin', status: 'succeeded', rotator: { type: 'random', config: { length: 48, excludeCharacters: 'O0Il' } } });
  expect(status.history).toHaveLength(1);
  const value = (await (await page.request.get(`/v1/secrets/value?${q}`)).json()).value as string;
  expect(value).toHaveLength(48);
  expect(value).not.toMatch(/[O0Il]/);
  const prevId = (await (await page.request.get(`/v1/secrets/versions?${q}`)).json()).versions.find((v: { stages?: string[] }) => v.stages?.includes('AWSPREVIOUS')).versionId;
  const prev = (await (await page.request.get(`/v1/secrets/value?${new URLSearchParams({ ...Object.fromEntries(q), versionId: prevId })}`)).json()).value;
  expect(prev).toBe('before-rotation');

  // Every step is in the audit log, as the rotation system actor.
  const audit = await (await page.request.get('/v1/audit?limit=200')).json();
  const events = (audit.events ?? audit.items ?? audit) as { action: string; actor: string }[];
  for (const step of ['createSecret', 'setSecret', 'testSecret', 'finishSecret']) {
    expect(events.some((e) => e.action === `secretsmanager.RotationStep.${step}` && e.actor === 'system:rotation')).toBe(true);
  }

  // Rotate now again from the drawer footer.
  await page.getByRole('button', { name: 'Rotate now' }).last().click();
  await page.getByRole('dialog').getByRole('button', { name: 'Rotate now' }).click();
  await expect(panel.getByText('Rotated', { exact: true })).toHaveCount(2, { timeout: 20_000 });

  // Turn it off; the configuration is kept.
  await panel.getByRole('button', { name: 'Turn off' }).click();
  await page.getByRole('dialog').getByRole('button', { name: 'Turn off rotation' }).click();
  await expect(panel.getByText('Off', { exact: true })).toBeVisible();
});
