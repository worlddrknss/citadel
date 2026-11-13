import { ORG, checkA11y, expect, open, signIn, test } from './fixtures';

// Notifications end to end against the real server: create a webhook and a
// Slack channel from Administration → Notifications, send a test, and watch
// the real delivery worker refuse a loopback destination (the SSRF guard)
// in the delivery log. Secrets are shown once and never returned again.

test('notification channels: create, test, delivery log, rotate, delete', async ({ page }) => {
  await signIn(page, ORG.admin);
  await open(page, '/admin?tab=notifications');
  await expect(page.getByText('No notification channels')).toBeVisible();
  await expect(page.getByText(/Email channels need SMTP settings/)).toBeVisible();
  await page.waitForLoadState('networkidle');
  await checkA11y(page);

  // A webhook pointing at loopback: accepted (it's a valid https URL), but
  // the delivery worker refuses to connect to it.
  await page.getByRole('button', { name: 'Add channel' }).first().click();
  const dlg = page.getByRole('dialog', { name: 'Add notification channel' });
  await dlg.getByLabel('Name').fill('loopback-hook');
  await dlg.getByLabel('Endpoint URL').fill('https://127.0.0.1:9/citadel');
  await expect(dlg.getByRole('checkbox', { name: /Kill switch used/ })).toBeChecked();
  await checkA11y(page);
  await dlg.getByRole('button', { name: 'Add channel' }).click();
  const once = page.getByRole('dialog', { name: 'loopback-hook created' });
  const secret = (await once.locator('code').innerText()).trim();
  expect(secret).toMatch(/^whsec_[0-9a-f]{64}$/);
  await once.getByLabel("I've saved it somewhere safe").check();
  await once.getByRole('button', { name: 'Done' }).click();

  const row = page.getByRole('row', { name: /loopback-hook/ });
  await expect(row).toContainText('https://127.0.0.1:9/citadel');
  await row.getByRole('button', { name: 'Actions for loopback-hook' }).click();
  await page.getByRole('menuitem', { name: 'Send test' }).click();
  const drawer = page.getByRole('dialog', { name: 'loopback-hook deliveries' });
  await expect(drawer.getByText('Retrying (1 failed)')).toBeVisible({ timeout: 20_000 });
  await expect(drawer.getByText(/destination address is not allowed/)).toBeVisible();
  await checkA11y(page);
  await drawer.getByRole('button', { name: 'Close' }).click();

  // The API never returns the secret again, and viewers can't read channels.
  const list = await (await page.request.get('/v1/notifications/channels')).json();
  expect(JSON.stringify(list)).not.toContain(secret);
  expect(list.channels[0]).toMatchObject({ name: 'loopback-hook', type: 'webhook', hasSigningSecret: true });

  // Slack: hooks.slack.com only; the URL is write-only.
  await page.getByRole('button', { name: 'Add channel' }).first().click();
  await dlg.getByLabel('Name').fill('ops-slack');
  await dlg.getByRole('radio', { name: /Slack/ }).check();
  await dlg.getByLabel('Incoming webhook URL').fill('https://hooks.slack.com.evil.example/services/x');
  await dlg.getByRole('button', { name: 'Add channel' }).click();
  await expect(dlg.getByText(/Paste the incoming webhook URL/)).toBeVisible();
  const slackURL = 'https://hooks.slack.com/services/TLIVE0001/BLIVE0001/liveSlackSecretPart01';
  await dlg.getByLabel('Incoming webhook URL').fill(slackURL);
  await dlg.getByRole('button', { name: 'Add channel' }).click();
  await expect(dlg).toBeHidden();
  const slackRow = page.getByRole('row', { name: /ops-slack/ });
  await expect(slackRow).toContainText('hooks.slack.com/services/TLIVE0001/BLIVE0001/…');
  const list2 = await (await page.request.get('/v1/notifications/channels')).json();
  expect(JSON.stringify(list2)).not.toContain('liveSlackSecretPart01');

  // Rotate the webhook's signing secret: a new one, shown once.
  await row.getByRole('button', { name: 'Actions for loopback-hook' }).click();
  await page.getByRole('menuitem', { name: 'Rotate signing secret' }).click();
  await page.getByRole('dialog').getByRole('button', { name: 'Rotate secret' }).click();
  const rotated = page.getByRole('dialog', { name: 'New signing secret for loopback-hook' });
  const secret2 = (await rotated.locator('code').innerText()).trim();
  expect(secret2).toMatch(/^whsec_/);
  expect(secret2).not.toBe(secret);
  await rotated.getByLabel("I've saved it somewhere safe").check();
  await rotated.getByRole('button', { name: 'Done' }).click();

  // Disable from the list.
  await slackRow.getByRole('switch', { name: 'ops-slack enabled' }).click();
  await expect(slackRow.getByText('Disabled')).toBeVisible();

  // Every change is audited.
  const audit = await (await page.request.get('/v1/audit?limit=200')).json();
  const events = (audit.events ?? audit.items ?? audit) as { action: string }[];
  for (const a of ['citadel.CreateNotificationChannel', 'citadel.TestNotificationChannel', 'citadel.RotateNotificationSigningSecret', 'citadel.UpdateNotificationChannel']) {
    expect(events.some((e) => e.action === a), a).toBe(true);
  }
  expect(JSON.stringify(audit)).not.toContain(secret2);

  // Delete both.
  for (const name of ['loopback-hook', 'ops-slack']) {
    await page.getByRole('row', { name: new RegExp(name) }).getByRole('button', { name: `Actions for ${name}` }).click();
    await page.getByRole('menuitem', { name: 'Delete' }).click();
    const del = page.getByRole('dialog', { name: `Delete ${name}?` });
    await del.getByRole('textbox').fill(name);
    await del.getByRole('button', { name: 'Delete channel' }).click();
    await expect(page.getByRole('row', { name: new RegExp(name) })).toHaveCount(0);
  }
  await expect(page.getByText('No notification channels')).toBeVisible();
});

test('only account admins manage notification channels', async ({ page }) => {
  await signIn(page, ORG.editor);
  const res = await page.request.get('/v1/notifications/channels');
  expect(res.status()).toBe(403);
});
