import { request as pwRequest } from '@playwright/test';
import { BASE } from './playwright.config';
import { ORG, apiPost, checkA11y, expect, open, signIn, test } from './fixtures';

// AI agents end to end against the real server: a usage profile on a secret
// (Agent access tab), an agent with a token shown once, a grant, the Agent
// API with that token (whoami, credentials without values), suspend /
// resume, the account kill switch, and the agent's activity in the audit
// log.

test('agent lifecycle: profile, token, grant, Agent API, suspend and kill switch', async ({ page }) => {
  await signIn(page, ORG.admin);
  await apiPost(page, '/v1/secrets', { project: 'payments', env: 'dev', key: 'AGENT_API_KEY', value: 'live-agent-secret-value' });

  // Usage profile from the secret drawer.
  await open(page, '/secrets/payments/dev?secret=AGENT_API_KEY&tab=agents');
  await page.getByRole('button', { name: 'Make usable by agents' }).click();
  const cred = page.getByRole('dialog', { name: 'Make usable by agents' });
  await cred.getByLabel('Credential name').fill('live-api');
  await cred.getByLabel(/Allowed hosts/).fill('api.example.com');
  await cred.getByRole('button', { name: 'Save' }).click();
  await expect(cred).toBeHidden();
  const profile = page.getByRole('article', { name: 'Usage profile live-api' });
  await expect(profile.getByText('api.example.com')).toBeVisible();
  await page.waitForLoadState('networkidle');
  await checkA11y(page);

  // A new agent, then a token (shown once).
  await open(page, '/agents');
  await page.getByRole('button', { name: 'New agent' }).first().click();
  await page.getByLabel('Name').fill('live-agent');
  await page.getByRole('button', { name: 'Create agent' }).click();
  await expect(page.locator('main h1').first()).toHaveText('live-agent');
  await page.getByRole('button', { name: 'New token' }).first().click();
  await page.getByRole('dialog', { name: 'New agent token' }).getByRole('button', { name: 'Create token' }).click();
  const once = page.getByRole('dialog', { name: 'Copy the agent token' });
  const token = ((await once.getByText(/^cagt_agt_/).textContent()) ?? '').trim();
  expect(token).toMatch(/^cagt_agt_[a-z2-7]{20}_[a-z2-7]{52}$/);
  await once.getByRole('checkbox').check();
  await once.getByRole('button', { name: 'Done' }).click();
  await expect(page.getByRole('table', { name: 'Agent tokens' }).getByText('Active')).toBeVisible();
  const agentId = token.slice(5, 29);

  // Grant the credential.
  await page.getByRole('tab', { name: /Grants/ }).click();
  await page.getByRole('button', { name: 'Grant credential' }).click();
  const grant = page.getByRole('dialog', { name: 'Grant a credential' });
  await grant.getByLabel('Uses per hour').fill('100');
  await grant.getByRole('button', { name: 'Grant' }).click();
  await expect(page.getByRole('table', { name: 'Grants' }).getByText('live-api')).toBeVisible();
  await page.waitForLoadState('networkidle');
  await checkA11y(page);

  // The Agent API, with the agent's own token.
  const agent = await pwRequest.newContext({ baseURL: BASE, extraHTTPHeaders: { Authorization: `Bearer ${token}`, 'X-Citadel-Task-Id': 'live-task-1' } });
  const who = await agent.get('/v1/agent/whoami');
  expect(who.status()).toBe(200);
  expect(await who.json()).toMatchObject({ agentId, name: 'live-agent', owner: ORG.admin.username, authMethod: 'token', taskId: 'live-task-1' });
  const list = await agent.get('/v1/agent/credentials');
  const body = await list.text();
  expect(list.status()).toBe(200);
  expect(JSON.parse(body).credentials).toEqual([expect.objectContaining({ name: 'live-api', usable: true, actions: ['use'] })]);
  expect(body).not.toContain('live-agent-secret-value');
  // An agent token is not a console credential.
  expect((await agent.get('/v1/agents')).status()).toBe(401);

  // Suspend from the row menu: the agent is refused; resume restores it.
  await open(page, '/agents');
  await page.getByRole('button', { name: 'Actions for live-agent' }).click();
  await page.getByRole('menuitem', { name: 'Suspend' }).click();
  await page.getByRole('dialog').getByRole('button', { name: 'Suspend agent' }).click();
  await expect(page.getByRole('row', { name: /live-agent/ }).getByText('Suspended')).toBeVisible();
  const refused = await agent.get('/v1/agent/whoami');
  expect(refused.status()).toBe(403);
  expect((await refused.json()).reason).toBe('agent_suspended');
  await page.getByRole('button', { name: 'Actions for live-agent' }).click();
  await page.getByRole('menuitem', { name: 'Resume' }).click();
  await expect(page.getByRole('row', { name: /live-agent/ }).getByText('Active')).toBeVisible();
  expect((await agent.get('/v1/agent/whoami')).status()).toBe(200);

  // The account kill switch.
  await open(page, '/admin?tab=settings');
  await page.getByLabel(/Reason/).fill('live drill');
  await page.getByRole('button', { name: 'Suspend all agents' }).click();
  await page.getByRole('dialog').getByRole('button', { name: 'Suspend all agents' }).click();
  await expect(page.getByRole('button', { name: 'Resume all agents' })).toBeVisible();
  const killed = await agent.get('/v1/agent/whoami');
  expect(killed.status()).toBe(403);
  expect((await killed.json()).reason).toBe('agents_suspended');
  await page.getByRole('button', { name: 'Resume all agents' }).click();
  await expect(page.getByRole('button', { name: 'Suspend all agents' })).toBeVisible();
  expect((await agent.get('/v1/agent/whoami')).status()).toBe(200);
  await agent.dispose();

  // The agent's activity: its requests, with the task ID, and console changes.
  await open(page, `/agents/${agentId}?tab=activity`);
  const activity = page.getByRole('table', { name: 'Agent activity' });
  await expect(activity.getByText('citadel.AgentWhoAmI').first()).toBeVisible();
  await expect(activity.getByText('live-task-1').first()).toBeVisible();
  await expect(activity.getByText('citadel.SuspendAgent').first()).toBeVisible();
  await page.waitForLoadState('networkidle');
  await checkA11y(page);
});
