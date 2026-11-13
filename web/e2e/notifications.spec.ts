import { expect, open, test } from './fixtures';

// Administration → Notifications against the mocked API: list, create a
// webhook (signing secret shown once), edit events, send a test, read and
// retry from the delivery log, rotate the secret and delete.

test('manages notification channels', async ({ page, api }) => {
  await open(page, '/admin?tab=notifications');
  await expect(page.getByRole('tab', { name: 'Notifications' })).toHaveAttribute('aria-selected', 'true');
  const row = page.getByRole('row', { name: /security-oncall/ });
  await expect(row).toContainText('https://hooks.acme.test/citadel');
  await expect(row).toContainText('Agent suspended');
  await expect(page.getByText(/Email channels need SMTP settings/)).toBeVisible();

  // Create a webhook channel.
  await page.getByRole('button', { name: 'Add channel' }).first().click();
  const dlg = page.getByRole('dialog', { name: 'Add notification channel' });
  await expect(dlg.getByRole('radio', { name: /Email/ })).toBeDisabled();
  await dlg.getByLabel('Name').fill('pager');
  await dlg.getByLabel('Endpoint URL').fill('http://insecure.example.com');
  await dlg.getByRole('button', { name: 'Add channel' }).click();
  await expect(dlg.getByText(/Enter an https:\/\/ URL/)).toBeVisible();
  await dlg.getByLabel('Endpoint URL').fill('https://pager.example.com/hook');
  await dlg.getByRole('checkbox', { name: /Agent anomaly/ }).uncheck();
  await dlg.getByRole('button', { name: 'Add channel' }).click();
  const secret = page.getByRole('dialog', { name: 'pager created' });
  await expect(secret.getByText(/^whsec_mock/)).toBeVisible();
  await secret.getByLabel("I've saved it somewhere safe").check();
  await secret.getByRole('button', { name: 'Done' }).click();
  expect(api.log).toContain('POST /v1/notifications/channels');

  // Edit: the type is fixed.
  await row.getByRole('button', { name: 'Actions for security-oncall' }).click();
  await page.getByRole('menuitem', { name: 'Edit' }).click();
  const edit = page.getByRole('dialog', { name: 'Edit security-oncall' });
  await expect(edit.getByRole('radio', { name: /Webhook/ })).toBeDisabled();
  await edit.getByRole('checkbox', { name: /Agent approval requested/ }).check();
  await edit.getByRole('button', { name: 'Save changes' }).click();
  await expect(edit).toBeHidden();
  expect(api.log).toContain('POST /v1/notifications/channels/update');

  // Delivery log: statuses, error, retry and test.
  await row.getByRole('button', { name: 'Deliveries for security-oncall' }).click();
  const drawer = page.getByRole('dialog', { name: 'security-oncall deliveries' });
  await expect(drawer.getByText('Delivered', { exact: true })).toBeVisible();
  await expect(drawer.getByText('Failed', { exact: true })).toBeVisible();
  await expect(drawer.getByText('the destination returned HTTP 503')).toBeVisible();
  await drawer.getByRole('button', { name: 'Retry' }).click();
  await expect(page.getByText('Delivery queued again')).toBeVisible();
  expect(api.log).toContain('POST /v1/notifications/deliveries/retry');
  await drawer.getByRole('button', { name: 'Send test' }).click();
  expect(api.log).toContain('POST /v1/notifications/channels/test');
  await drawer.getByRole('button', { name: 'Close' }).click();

  // Rotate the signing secret.
  await row.getByRole('button', { name: 'Actions for security-oncall' }).click();
  await page.getByRole('menuitem', { name: 'Rotate signing secret' }).click();
  await page.getByRole('dialog').getByRole('button', { name: 'Rotate secret' }).click();
  const rotated = page.getByRole('dialog', { name: 'New signing secret for security-oncall' });
  await expect(rotated.getByText(/^whsec_rotated/)).toBeVisible();
  await rotated.getByLabel("I've saved it somewhere safe").check();
  await rotated.getByRole('button', { name: 'Done' }).click();

  // Delete (type to confirm).
  await row.getByRole('button', { name: 'Actions for security-oncall' }).click();
  await page.getByRole('menuitem', { name: 'Delete' }).click();
  const del = page.getByRole('dialog', { name: 'Delete security-oncall?' });
  await del.getByRole('textbox').fill('security-oncall');
  await del.getByRole('button', { name: 'Delete channel' }).click();
  await expect.poll(() => api.log.some((l) => l.startsWith('DELETE /v1/notifications/channels?id=nch_'))).toBe(true);
});
