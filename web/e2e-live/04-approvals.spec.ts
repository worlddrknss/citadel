import type { Browser } from '@playwright/test';
import { ORG, checkA11y, expect, open, signIn, test } from './fixtures';

// Two-person rule on payments/prod (created by 03-secrets): an admin adds the
// policy, an editor's change becomes a change request, the requester can't
// approve it, and a second admin approves and applies it.

const PROJECT = 'payments';

async function asUser(browser: Browser, baseURL: string, user: { username: string; password: string }) {
  const ctx = await browser.newContext({ baseURL });
  const page = await ctx.newPage();
  await signIn(page, user);
  return { ctx, page };
}

test('approval policy on prod, editor change, second admin approves', async ({ page, browser, baseURL }) => {
  // Policy: one approval, editors may approve (the requester still can't).
  await signIn(page, ORG.admin);
  await open(page, '/approvals?policies=1');
  const pdlg = page.getByRole('dialog', { name: 'Approval policies' });
  await expect(pdlg).toBeVisible();
  await pdlg.getByLabel('Project').selectOption(PROJECT);
  await pdlg.getByLabel('Environment').selectOption('prod');
  await pdlg.getByLabel('Approvals').fill('1');
  await pdlg.getByRole('checkbox', { name: 'Editors can approve' }).check();
  await pdlg.getByRole('button', { name: 'Add policy' }).click();
  const prow = pdlg.getByRole('row', { name: /payments.*prod/ });
  await expect(prow).toContainText('Project');
  await expect(prow).toContainText(/admin or editor|editor or admin/);
  await checkA11y(page);
  const pol = await (await page.request.get('/v1/change-requests/policies')).json();
  expect(pol.policies).toContainEqual(expect.objectContaining({ project: PROJECT, env: 'prod', approvalsRequired: 1, source: 'project' }));

  // The editor's edit on prod opens a change request instead of writing.
  const erin = await asUser(browser, baseURL!, ORG.editor);
  await open(erin.page, `/secrets/${PROJECT}/prod`);
  const row = erin.page.getByRole('row', { name: /API_KEY/ });
  await row.getByRole('button', { name: /actions|More/i }).click();
  await erin.page.getByRole('menuitem', { name: /Edit value|Request change/ }).click();
  const vdlg = erin.page.getByRole('dialog', { name: /Request change to API_KEY/ });
  await vdlg.locator('#vv').fill('prod-api-key-2');
  await vdlg.getByRole('button', { name: 'Open change request' }).click();
  await expect(vdlg).toBeHidden();
  const cur = await (await erin.page.request.get(`/v1/secrets/value?project=${PROJECT}&env=prod&path=%2F&key=API_KEY`)).json();
  expect(cur.value).toBe('prod-api-key-1');

  // The requester sees why they can't approve, and only Withdraw.
  await open(erin.page, '/approvals?view=open');
  await erin.page.locator('a.item').first().click();
  await expect(erin.page.getByText(/can't approve your own/i).first()).toBeVisible();
  await expect(erin.page.getByRole('button', { name: /^Approve/ })).toHaveCount(0);
  await expect(erin.page.getByRole('button', { name: 'Withdraw request' })).toBeVisible();
  await expect(erin.page.getByText(/fingerprint hmac:[0-9a-f]{12}/).first()).toBeVisible();
  await erin.page.waitForLoadState('networkidle');
  await checkA11y(erin.page);
  await erin.ctx.close();

  // Bob (second admin) approves; the value is applied.
  const bob = await asUser(browser, baseURL!, ORG.admin2);
  await open(bob.page, '/approvals');
  await bob.page.locator('a.item').first().click();
  await expect(bob.page.getByRole('heading', { level: 2, name: /API_KEY|payments/ })).toBeVisible();
  await bob.page.getByRole('button', { name: 'Approve and apply' }).click();
  await bob.page.getByRole('dialog').getByRole('button', { name: 'Approve and apply' }).click();
  await expect(bob.page.getByText('Approved', { exact: true }).first()).toBeVisible();
  const after = await (await bob.page.request.get(`/v1/secrets/value?project=${PROJECT}&env=prod&path=%2F&key=API_KEY`)).json();
  expect(after.value).toBe('prod-api-key-2');
  await bob.ctx.close();
});
