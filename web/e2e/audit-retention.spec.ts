import { expect, open, test } from './fixtures';

// Administration → Audit (audit retention) and the pruning anchor on the
// Audit page, against the mocked API.

test('sets a retention after previewing what it prunes', async ({ page, api }) => {
  await open(page, '/admin?tab=audit');
  await expect(page.getByRole('tab', { name: 'Audit' })).toHaveAttribute('aria-selected', 'true');
  const card = page.getByRole('region', { name: 'Audit log retention' });
  await expect(card.getByText('Keep forever', { exact: true }).first()).toBeVisible();
  const stats = card.getByTestId('retention-stats');
  await expect(stats).toContainText('1,840');
  // Platform admin: the audit table's size and the last run.
  await expect(stats).toContainText('2.0 GB');
  await expect(stats).toContainText('321,000');
  await expect(card.getByTestId('retention-last-run')).toContainText('0 events pruned');
  await expect(card.getByRole('radio', { name: /Deployment default/ })).toBeChecked();

  await card.getByRole('radio', { name: /Delete events older than/ }).check();
  const input = card.getByLabel('Days to keep');
  await input.fill('3');
  await expect(card.getByText('Between 7 and 3,650 days.')).toBeVisible();
  await expect(card.getByRole('button', { name: 'Save retention' })).toBeDisabled();

  await input.fill('30');
  await expect(card.getByTestId('retention-preview')).toContainText('340 of 1,840 events are older than 30 days and would be deleted within the hour');
  expect(api.log).toContain('GET /v1/audit/retention/preview?days=30');

  await card.getByRole('button', { name: 'Save retention' }).click();
  const dlg = page.getByRole('alertdialog').or(page.getByRole('dialog'));
  await expect(dlg.getByText('Delete 340 audit events?')).toBeVisible();
  await dlg.getByRole('button', { name: 'Save and prune' }).click();
  await expect(page.getByText('Audit retention: 30 days')).toBeVisible();
  expect(api.retentionSaves).toEqual([30]);
  await expect(card.getByRole('button', { name: 'Save retention' })).toBeDisabled();
  await expect(card.getByText(/Last changed/)).toBeVisible();
});

test('keep forever saves without a prune warning; the default can be restored', async ({ page, api }) => {
  api.retentionDays = 90;
  await open(page, '/admin?tab=audit');
  const card = page.getByRole('region', { name: 'Audit log retention' });
  await expect(card.getByLabel('Days to keep')).toHaveValue('90');

  await card.getByRole('radio', { name: 'Keep forever', exact: true }).check();
  await expect(card.getByTestId('retention-preview')).toContainText('Nothing is deleted.');
  await card.getByRole('button', { name: 'Save retention' }).click();
  await expect(page.getByText('Audit retention: keep forever')).toBeVisible();

  await card.getByRole('radio', { name: /Deployment default/ }).check();
  await card.getByRole('button', { name: 'Save retention' }).click();
  await expect.poll(() => api.retentionSaves).toEqual([0, null]);
});

test('the audit page says where pruned history ends', async ({ page, api }) => {
  api.auditPruned = true;
  api.retentionDays = 30;
  await open(page, '/audit');
  const note = page.getByTestId('chain-anchor-note');
  await expect(note).toContainText('was pruned by the retention policy (224,999 events)');
  await expect(note).toContainText('chain position 224,999');
  await note.getByRole('link', { name: 'Retention settings' }).click();
  await expect(page).toHaveURL(/\/admin\?tab=audit/);
  await expect(page.getByRole('region', { name: 'Audit log retention' }).getByText(/History before .* was pruned/)).toBeVisible();
});
