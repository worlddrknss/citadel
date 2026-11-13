import { expect, open, test } from './fixtures';
import { ACCESS_REQUEST_ID, AGENT_ID, MFA_CODE, REVEAL_REQUEST_ID } from './mock';

// Agent access requests (2.3): the Approvals inbox lists them with change
// requests, deep links open one, approving picks a scope (and asks for an MFA
// code when required), denying needs a reason; the agent's Requests and
// Leases tabs; requireFederation; requiresApproval on grants.

const posted = (api: { log: string[] }, path: string) => api.log.some((l) => l.startsWith(`POST ${path}`));

test('the inbox lists agent requests and approves one once', async ({ page, api }) => {
  await open(page, '/approvals?view=open');
  const item = page.getByRole('link', { name: /claude-code: use stripe-api/ });
  await expect(item).toBeVisible();
  await item.click();
  await expect(page).toHaveURL(new RegExp(`type=agent_access&id=${ACCESS_REQUEST_ID}`));
  const panel = page.getByTestId('agent-request');
  await expect(panel.getByRole('heading', { name: /claude-code asks to use stripe-api/ })).toBeVisible();
  await expect(panel.getByText('run-42')).toBeVisible();

  await panel.getByRole('button', { name: 'Approve…' }).click();
  const dlg = page.getByRole('dialog', { name: /Approve claude-code's request/ });
  await expect(dlg.getByRole('radio', { name: /For this task/ })).toBeEnabled();
  await dlg.getByRole('radio', { name: /Once/ }).check();
  const req = page.waitForRequest((r) => r.url().endsWith('/v1/agents/access-requests/approve'));
  await dlg.getByRole('button', { name: 'Approve' }).click();
  const body = (await req).postDataJSON();
  expect(body).toMatchObject({ requestId: ACCESS_REQUEST_ID, scope: 'once', durationSeconds: 3600 });
  await expect(page.getByText(/Approved claude-code's access to stripe-api/)).toBeVisible();
});

test('a deep link opens a request; reveal without a grant is flagged; deny needs a reason', async ({ page, api }) => {
  await open(page, `/approvals?type=agent_access&id=${REVEAL_REQUEST_ID}`);
  const panel = page.getByTestId('agent-request');
  await expect(panel.getByRole('heading', { name: /reveal db-password/ })).toBeVisible();
  // The agent's reason is shown as text, never markup.
  await expect(panel.getByText('Run the <b>migration</b> locally')).toBeVisible();
  await expect(panel.getByText(/No grant: approving gives access/)).toBeVisible();

  await panel.getByRole('button', { name: 'Deny…' }).click();
  const dlg = page.getByRole('dialog', { name: /Deny claude-code's request/ });
  await expect(dlg.getByRole('button', { name: 'Deny' })).toBeDisabled();
  await dlg.getByLabel(/Reason/).fill('use the broker instead');
  await dlg.getByRole('button', { name: 'Deny' }).click();
  await expect.poll(() => posted(api, '/v1/agents/access-requests/deny')).toBe(true);
  await expect(page.getByText(/Denied claude-code's request/)).toBeVisible();
});

test('approving asks for an MFA code when the organization requires one', async ({ page, api, allowConsole }) => {
  api.approvalMfa = true;
  allowConsole(/status of 403/);
  await open(page, `/approvals?type=agent_access&id=${REVEAL_REQUEST_ID}`);
  await page.getByTestId('agent-request').getByRole('button', { name: 'Approve…' }).click();
  const dlg = page.getByRole('dialog', { name: /Approve claude-code's request/ });
  await expect(dlg.getByText(/hands the secret value/)).toBeVisible();
  await expect(dlg.getByRole('radio', { name: /For this task/ })).toBeDisabled();
  await dlg.getByRole('button', { name: 'Approve' }).click();
  await expect(dlg.getByLabel('Authentication code')).toBeVisible();
  await dlg.getByLabel('Authentication code').fill('000000');
  await dlg.getByRole('button', { name: 'Approve' }).click();
  await expect(dlg.getByText('That code is not valid. Try the current one.')).toBeVisible();
  await dlg.getByLabel('Authentication code').fill(MFA_CODE);
  await dlg.getByRole('button', { name: 'Approve' }).click();
  await expect(dlg).toBeHidden();
});

test('the type filter narrows the inbox to agent access', async ({ page }) => {
  await open(page, '/approvals?view=closed');
  await page.getByRole('group', { name: 'Request type' }).getByRole('button', { name: 'Agent access' }).click();
  await expect(page).toHaveURL(/kind=agent/);
  await expect(page.getByText(/triage-bot: use/)).toBeVisible();
  await expect(page.getByTestId('agent-request').getByText('ok for today')).toBeVisible();
});

test('agent detail lists requests and leases, and revokes a lease', async ({ page, api }) => {
  await open(page, `/agents/${AGENT_ID}?tab=requests`);
  const reqs = page.getByRole('table', { name: 'Access requests' });
  await expect(reqs.getByText('stripe-api')).toBeVisible();
  await reqs.getByRole('button', { name: 'Approve…' }).first().click();
  await expect(page.getByRole('dialog', { name: /Approve claude-code's request/ })).toBeVisible();
  await page.getByRole('dialog').getByRole('button', { name: 'Cancel' }).click();

  await page.getByRole('tab', { name: 'Leases' }).click();
  const leases = page.getByRole('table', { name: 'Leases' });
  await expect(leases.getByText('stripe-api')).toBeVisible();
  await expect(leases.getByText('∞')).toBeVisible();
  await page.getByLabel('Show ended leases').check();
  await expect(leases.getByText('Used', { exact: true })).toBeVisible();
  await leases.getByRole('button', { name: 'Revoke lease on stripe-api' }).click();
  await page.getByRole('dialog').getByRole('button', { name: 'Revoke lease' }).click();
  await expect.poll(() => posted(api, '/v1/agents/leases/revoke')).toBe(true);
  expect(api.log.some((l) => l.includes(`/v1/agents/leases?agentId=${AGENT_ID}&active=false`))).toBe(true);

});

test('require federation from the overview', async ({ page, api }) => {
  await open(page, `/agents/${AGENT_ID}`);
  const req = page.waitForRequest((r) => r.url().endsWith('/v1/agents/update'));
  await page.getByRole('checkbox', { name: /Require workload identity federation/ }).check();
  await page.getByRole('dialog').getByRole('button', { name: 'Require federation' }).click();
  expect((await req).postDataJSON()).toMatchObject({ agentId: AGENT_ID, requireFederation: true });
  await expect.poll(() => posted(api, '/v1/agents/update')).toBe(true);
});

test('grants can require approval with a lease length', async ({ page }) => {
  await open(page, `/agents/${AGENT_ID}?tab=grants`);
  await page.getByRole('button', { name: 'Edit grant stripe-api' }).click();
  const dlg = page.getByRole('dialog', { name: /Edit grant/ });
  await dlg.getByRole('checkbox', { name: /Requires approval/ }).check();
  await dlg.getByLabel('Lease length (minutes)').fill('30');
  const req = page.waitForRequest((r) => r.url().endsWith('/v1/agents/grants') && r.method() === 'POST');
  await dlg.getByRole('button', { name: 'Save grant' }).click();
  expect((await req).postDataJSON()).toMatchObject({ credential: 'stripe-api', requiresApproval: true, leaseTtlSeconds: 1800 });
});
