import { readFileSync } from 'node:fs';
import { ORG, apiPost, checkA11y, expect, open, signIn, test } from './fixtures';

// The audit log records who did what under the authenticated identity, the
// hash chain verifies, and exports download (and are themselves audited).

test('audit log shows real actors, verifies the chain and exports CSV', async ({ page, browser, baseURL }) => {
  // Events by two different people.
  await signIn(page, ORG.admin);
  await apiPost(page, '/v1/projects', { slug: 'audit-demo', name: 'Audit demo' }).catch(() => undefined);
  await apiPost(page, '/v1/secrets', { project: 'audit-demo', env: 'dev', path: '/', key: 'API_TOKEN', value: 'audit-value-1' });
  const ctx = await browser.newContext({ baseURL });
  const erin = await ctx.newPage();
  await signIn(erin, ORG.editor);
  await apiPost(erin, '/v1/secrets', { project: 'audit-demo', env: 'dev', path: '/', key: 'API_TOKEN', value: 'audit-value-2' });
  await ctx.close();

  await open(page, '/audit');
  await expect(page.getByRole('heading', { level: 1, name: 'Audit log' })).toBeVisible();
  const table = page.getByRole('table').first();
  // Display names, not "ui", "anonymous" or the deployment's access key.
  await expect(table.getByText('Erin Editor').first()).toBeVisible();
  await expect(table.getByText(/alice/).first()).toBeVisible();
  await expect(table.getByText(/^anonymous$|^ui$/)).toHaveCount(0);
  await page.waitForLoadState('networkidle');
  await checkA11y(page);

  // The JSON view of an event uses the API's field names.
  await page.getByRole('button', { name: /^Expand event/ }).first().click();
  await expect(page.locator('[id^="ev-"]').first()).toContainText('"actorType"');

  // Verify the chain.
  await page.getByRole('button', { name: 'Verify now' }).click();
  await expect(page.getByRole('status').filter({ hasText: /Chain verified through event #\d+/ }).first()).toBeVisible();

  // The platform admin can re-walk the whole chain; a 2.0-only chain has no
  // pre-2.0 note.
  const fullCheck = page.waitForResponse((r) => r.url().includes('/v1/audit/verify?full=true') && r.request().method() === 'POST');
  await page.getByRole('button', { name: 'Full re-check' }).click();
  const fullBody = await (await fullCheck).json();
  expect(fullBody).toMatchObject({ status: 'verified', legacyLinkBreaks: 0, legacyEvents: 0 });
  await expect(page.getByText(/Full re-check: chain verified through event #\d+/)).toBeVisible();
  await expect(page.getByTestId('legacy-break-note')).toHaveCount(0);

  // Export CSV.
  const download = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Export matching events' }).click();
  await page.getByRole('menuitem', { name: 'CSV' }).click();
  const file = await download;
  const csv = readFileSync((await file.path())!, 'utf8');
  expect(csv.split('\n')[0]).toMatch(/actor/i);
  expect(csv).toContain('erin');

  // The export itself is audited.
  await expect
    .poll(async () => {
      const r = await page.request.get('/v1/audit/events?action=ExportAudit&limit=5');
      return (await r.json()).events?.length ?? 0;
    })
    .toBeGreaterThan(0);
});

test('users who are not platform admins get no full re-check', async ({ page }) => {
  await signIn(page, ORG.editor);
  await open(page, '/audit');
  await expect(page.getByRole('button', { name: 'Verify now' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Full re-check' })).toHaveCount(0);
  const res = await page.request.post('/v1/audit/verify?full=true', { headers: { 'X-Citadel-Request': '1' } });
  expect(res.status()).toBe(403);
});

test('write-ahead audit: a change records a pending attempt linked to its outcome', async ({ page }) => {
  await signIn(page, ORG.admin);
  await apiPost(page, '/v1/secrets', { project: 'audit-demo', env: 'dev', path: '/', key: 'WRITE_AHEAD', value: 'wa-value' });

  // The attempt (the route, result pending) and the handler's outcome share a correlation ID.
  const attempts = await (await page.request.get('/v1/audit/events?result=pending&action=POST%20%2Fv1%2Fsecrets&limit=1')).json();
  const attempt = attempts.events[0];
  expect(attempt).toMatchObject({ result: 'pending', action: 'POST /v1/secrets' });
  expect(attempt.correlationId).toMatch(/^[0-9a-f]{32}$/);
  const linked = await (await page.request.get(`/v1/audit/events?correlation=${attempt.correlationId}`)).json();
  expect(linked.events).toHaveLength(2);
  expect(linked.events[0]).toMatchObject({ result: 'success', correlationId: attempt.correlationId });

  // The console labels the attempt and jumps to its outcome.
  await open(page, '/audit?range=all&result=pending');
  await page.getByRole('button', { name: `Expand event ${attempt.id}` }).click();
  await page.getByRole('button', { name: 'Show outcome' }).click();
  await expect(page).toHaveURL(new RegExp(`correlation=${attempt.correlationId}`));
  await expect(page.getByText('Showing 1–2 of 2 matching events')).toBeVisible();

  // Reads write no attempt.
  const pendingTotal = async () => (await (await page.request.get('/v1/audit/events?result=pending&limit=1')).json()).total;
  const before = await pendingTotal();
  await page.request.get('/v1/secrets?project=audit-demo&env=dev');
  expect(await pendingTotal()).toBe(before);
});
