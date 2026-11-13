import { ORG, checkA11y, expect, open, signIn, test } from './fixtures';

// Audit retention against the real server and PostgreSQL: the platform admin
// sees the account's log and the audit table's size, previews a retention
// (nothing in this fresh database is old enough to prune), saves it, and the
// change shows up in the audit log with its old and new value. Editors can't
// change it. Pruning itself (batches, anchors, verification after a prune)
// is covered by the Go store tests against PostgreSQL.

test('audit retention: preview, save, audited, and verification still passes', async ({ page }) => {
  await signIn(page, ORG.admin);
  await open(page, '/admin?tab=audit');
  const card = page.getByRole('region', { name: 'Audit log retention' });
  const stats = card.getByTestId('retention-stats');
  await expect(stats).toContainText('Events');
  // Platform admin: the deployment-wide table size from the catalog.
  await expect(stats).toContainText('Audit table on disk');
  await expect(stats).toContainText(/\d+(\.\d)? (KB|MB|GB)/);
  // KMS_AUDIT_RETENTION_DAYS is unset: the default keeps events forever.
  await expect(card.getByRole('radio', { name: /Deployment default \(keep forever\)/ })).toBeChecked();
  await page.waitForLoadState('networkidle');
  await checkA11y(page);

  await card.getByRole('radio', { name: /Delete events older than/ }).check();
  await card.getByLabel('Days to keep').fill('5');
  await expect(card.getByText(/Between 7 and 3,650 days/)).toBeVisible();
  await card.getByLabel('Days to keep').fill('30');
  await expect(card.getByTestId('retention-preview')).toContainText('No events are older than 30 days yet.');
  await card.getByRole('button', { name: 'Save retention' }).click();
  await expect(page.getByText('Audit retention: 30 days')).toBeVisible();

  const r = await (await page.request.get('/v1/audit/retention')).json();
  expect(r).toMatchObject({ retentionDays: 30, source: 'account', accountDays: 30, deploymentDays: 0, minDays: 7 });
  expect(r.anchor).toBeUndefined();
  expect(r.storage.tableBytes).toBeGreaterThan(0);

  // The change is audited with the old and new values.
  await expect
    .poll(async () => {
      const res = await page.request.get('/v1/audit/events?action=PutAuditRetention&result=success&limit=5');
      return (await res.json()).events?.[0]?.resource ?? '';
    })
    .toBe('audit-retention: default(forever) -> 30d');

  // Nothing was pruned, so the chain verifies from its first event, without an anchor.
  await open(page, '/audit');
  await page.getByRole('button', { name: 'Verify now' }).click();
  await expect(page.getByRole('status').filter({ hasText: /Chain verified through event #\d+/ }).first()).toBeVisible();
  await expect(page.getByTestId('chain-anchor-note')).toHaveCount(0);

  // Back to the deployment default (keep forever) through the API.
  const reset = await page.request.post('/v1/audit/retention', { data: { retentionDays: null }, headers: { 'X-Citadel-Request': '1' } });
  expect(reset.ok()).toBeTruthy();
  expect(await reset.json()).toMatchObject({ source: 'deployment', accountDays: null, retentionDays: 0 });
});

test('audit retention: editors can read it but not change or preview it', async ({ page }) => {
  await signIn(page, ORG.editor);
  const get = await page.request.get('/v1/audit/retention');
  expect(get.ok()).toBeTruthy();
  expect((await get.json()).storage).toBeUndefined();
  const set = await page.request.post('/v1/audit/retention', { data: { retentionDays: 7 }, headers: { 'X-Citadel-Request': '1' } });
  expect(set.status()).toBe(403);
  const preview = await page.request.get('/v1/audit/retention/preview?days=7');
  expect(preview.status()).toBe(403);
});
