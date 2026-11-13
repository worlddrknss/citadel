import { request as pwRequest } from '@playwright/test';
import { BASE } from './playwright.config';
import { ORG, apiPost, checkA11y, expect, open, signIn, test } from './fixtures';

// Agent approvals end to end against the real server: a credential whose
// grant requires approval, the agent refused with approval_required and a
// request ID, an admin approving once in the console Approvals inbox, the
// agent using the lease once, and the second use refused again. Then an
// agent asking for access it has no grant for, denied with a reason.

const SECRET = 'live-approval-secret-value-4b8d';

test('approval flow: agent asks, admin approves once in the console, one use only', async ({ page }) => {
  await signIn(page, ORG.admin);
  await apiPost(page, '/v1/secrets', { project: 'payments', env: 'dev', key: 'APPROVAL_DEPLOY_KEY', value: SECRET });
  await apiPost(page, '/v1/agents/credentials', { name: 'live-deploy-key', project: 'payments', env: 'dev', key: 'APPROVAL_DEPLOY_KEY', kind: 'raw' });
  const agent = await apiPost(page, '/v1/agents', { name: 'live-approver-agent', description: 'approval e2e' });
  const agentId = agent.agentId as string;
  const { token } = await apiPost(page, '/v1/agents/tokens', { agentId, name: 'live', expiresInDays: 1 });
  await apiPost(page, '/v1/agents/grants', { agentId, credential: 'live-deploy-key', actions: ['reveal'], requiresApproval: true, leaseTtlSeconds: 1800 });

  const client = await pwRequest.newContext({ baseURL: BASE, extraHTTPHeaders: { Authorization: `Bearer ${token}`, 'X-Citadel-Task-Id': 'live-approval-1' } });
  const reveal = () => client.post('/v1/agent/credentials/reveal', { data: { credential: 'live-deploy-key' } });

  // Refused until approved, with a pending request the agent can poll.
  let res = await reveal();
  expect(res.status()).toBe(403);
  const refused = await res.json();
  expect(refused).toMatchObject({ error: 'approval_required', reason: 'approval_required' });
  const requestId = refused.requestId as string;
  expect(requestId).toMatch(/^aar_[a-z2-7]{16}$/);
  expect(JSON.stringify(refused)).not.toContain(SECRET);
  res = await client.get(`/v1/agent/access-requests/${requestId}`);
  expect(await res.json()).toMatchObject({ requestId, status: 'pending', origin: 'policy', credential: 'live-deploy-key', taskId: 'live-approval-1' });
  // Asking again while pending returns the same request.
  expect((await (await reveal()).json()).requestId).toBe(requestId);

  // The admin approves once from the Approvals inbox (the notification's deep link).
  await open(page, `/approvals?type=agent_access&id=${requestId}`);
  const panel = page.getByTestId('agent-request');
  await expect(panel.getByRole('heading', { name: /live-approver-agent/ })).toBeVisible();
  await expect(panel.getByText('live-approval-1')).toBeVisible();
  await page.waitForLoadState('networkidle');
  await checkA11y(page);
  await panel.getByRole('button', { name: 'Approve…' }).click();
  const dlg = page.getByRole('dialog', { name: /Approve live-approver-agent's request/ });
  await dlg.getByRole('radio', { name: /Once/ }).check();
  await dlg.getByRole('button', { name: 'Approve' }).click();
  await expect(dlg).toBeHidden();
  await expect(page.getByText(/Approved live-approver-agent's access to live-deploy-key/)).toBeVisible();

  // The agent sees the decision, uses the lease once...
  res = await client.get(`/v1/agent/access-requests/${requestId}`);
  const approved = await res.json();
  expect(approved).toMatchObject({ status: 'approved', scope: 'once', decidedBy: ORG.admin.username });
  const leaseId = approved.lease.leaseId as string;
  res = await reveal();
  expect(res.status()).toBe(200);
  const value = await res.json();
  expect(value).toMatchObject({ credential: 'live-deploy-key', value: SECRET, leaseId });

  // ...and the second use needs a new approval.
  res = await reveal();
  expect(res.status()).toBe(403);
  const again = await res.json();
  expect(again.reason).toBe('approval_required');
  expect(again.requestId).not.toBe(requestId);

  // The agent's Leases tab shows the used lease; Requests shows both requests.
  await open(page, `/agents/${agentId}?tab=leases`);
  await page.getByLabel(/Show ended leases/).check();
  await expect(page.getByText('live-deploy-key').first()).toBeVisible();
  await open(page, `/agents/${agentId}?tab=requests`);
  await expect(page.getByText(/Approved/).first()).toBeVisible();
  await page.waitForLoadState('networkidle');
  await checkA11y(page);

  // Access the agent has no grant for: asked explicitly, denied with a reason.
  res = await client.post('/v1/agent/access-requests', { data: { credential: 'live-unknown-cred', reason: 'live e2e: try something new', duration: '10m' } });
  expect(res.status()).toBe(201);
  const asked = await res.json();
  expect(asked).toMatchObject({ status: 'pending', origin: 'agent', durationSeconds: 600 });
  await open(page, `/approvals?type=agent_access&id=${asked.requestId}`);
  await panel.getByRole('button', { name: 'Deny…' }).click();
  const deny = page.getByRole('dialog', { name: /Deny live-approver-agent's request/ });
  await deny.getByLabel(/Reason/).fill('not for this agent');
  await deny.getByRole('button', { name: 'Deny' }).click();
  await expect(deny).toBeHidden();
  res = await client.get(`/v1/agent/access-requests/${asked.requestId}`);
  expect(await res.json()).toMatchObject({ status: 'denied', decisionComment: 'not for this agent' });

  // The audit log attributes the use to the lease; the secret never appears.
  const events = await page.request.get(`/v1/audit/events?agent=${agentId}&limit=200`);
  const text = await events.text();
  expect(text).toContain('citadel.ApproveAgentAccess');
  expect(text).toContain(`lease=${leaseId}`);
  expect(text).not.toContain(SECRET);
  await client.dispose();
});
