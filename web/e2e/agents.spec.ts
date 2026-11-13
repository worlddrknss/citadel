import { expect, open, test } from './fixtures';
import { AGENT_ID, AGENT_TOKEN } from './mock';

// AI agents: the list with its row menu, the detail page (tokens shown once,
// federation, grants with reveal flagged as risky, activity), the secret
// drawer's Agent access tab and the account kill switch.

test('agents list shows status, owner and a row menu', async ({ page, api }) => {
  await open(page, '/agents');
  const table = page.getByRole('table', { name: 'Agents' });
  await expect(table.getByRole('link', { name: 'claude-code' })).toBeVisible();
  await expect(table.getByText('Suspended')).toBeVisible();

  await page.getByRole('button', { name: 'Actions for claude-code' }).click();
  await page.getByRole('menuitem', { name: 'Suspend' }).click();
  await page.getByRole('dialog').getByRole('button', { name: 'Suspend agent' }).click();
  await expect.poll(() => api.log.some((l) => l.startsWith('POST /v1/agents/suspend'))).toBe(true);

  await page.getByRole('button', { name: 'Actions for triage-bot' }).click();
  await expect(page.getByRole('menuitem', { name: 'Resume' })).toBeVisible();
});

test('creating an agent opens its tokens', async ({ page, api }) => {
  await open(page, '/agents');
  await page.getByRole('button', { name: 'New agent' }).first().click();
  await page.getByLabel('Name').fill('bad name');
  await expect(page.getByText(/Letters, digits/)).toBeVisible();
  await page.getByLabel('Name').fill('release-bot');
  await page.getByRole('button', { name: 'Create agent' }).click();
  await expect.poll(() => api.log.some((l) => l.startsWith('POST /v1/agents'))).toBe(true);
  await expect(page).toHaveURL(/\/agents\/agt_newnewnewnewnewnewne\?tab=tokens/);
});

test('a new token is shown once', async ({ page }) => {
  await open(page, `/agents/${AGENT_ID}?tab=tokens`);
  await expect(page.getByRole('table', { name: 'Agent tokens' }).getByText('laptop')).toBeVisible();
  await page.getByRole('button', { name: 'New token' }).first().click();
  await page.getByLabel('Name').fill('ci');
  await page.getByRole('button', { name: 'Create token' }).click();
  const dlg = page.getByRole('dialog', { name: 'Copy the agent token' });
  await expect(dlg).toBeVisible();
  await expect(dlg.getByText(AGENT_TOKEN)).toBeVisible();
});

test('grants flag reveal as risky and confirm granting it', async ({ page, api }) => {
  await open(page, `/agents/${AGENT_ID}?tab=grants`);
  const table = page.getByRole('table', { name: 'Grants' });
  await expect(table.getByText('stripe-api')).toBeVisible();
  await expect(table.getByText('Expired')).toBeVisible();
  await expect(table.getByText('reveal')).toBeVisible();

  await page.getByRole('button', { name: 'Edit grant stripe-api' }).click();
  const dlg = page.getByRole('dialog', { name: /Edit grant/ });
  await expect(dlg.getByText('Risky')).toBeVisible();
  await dlg.getByRole('checkbox', { name: /Reveal/ }).check();
  await dlg.getByRole('button', { name: 'Save grant' }).click();
  await expect(page.getByRole('dialog', { name: /reveal stripe-api/ })).toBeVisible();
  await page.getByRole('button', { name: 'Grant reveal' }).click();
  await expect.poll(() => api.log.some((l) => l.startsWith('POST /v1/agents/grants'))).toBe(true);
});

test('federation and activity tabs', async ({ page, api }) => {
  await open(page, `/agents/${AGENT_ID}?tab=federation`);
  await expect(page.getByText('repo:acme/payments:ref:refs/heads/main')).toBeVisible();
  await page.getByRole('tab', { name: 'Activity' }).click();
  await expect.poll(() => api.log.some((l) => l.includes(`/v1/audit/events?agent=${AGENT_ID}`))).toBe(true);
  await expect(page.getByRole('link', { name: 'Open in audit log' })).toHaveAttribute('href', new RegExp(`/audit\\?agent=${AGENT_ID}`));
});

test('the secret drawer lists agent usage profiles', async ({ page }) => {
  await open(page, '/secrets/payments/dev?secret=STRIPE_KEY&tab=agents');
  const profile = page.getByRole('article', { name: 'Usage profile stripe-api' });
  await expect(profile).toBeVisible();
  await expect(profile.getByText('api.stripe.com')).toBeVisible();
  await expect(profile.getByRole('link', { name: 'claude-code' })).toBeVisible();
  await page.getByRole('button', { name: 'Make usable by agents' }).click();
  await expect(page.getByRole('dialog', { name: 'Make usable by agents' })).toBeVisible();
});

test('admins can suspend every agent from Administration', async ({ page, api }) => {
  await open(page, '/admin?tab=settings');
  await page.getByLabel(/Reason/).fill('incident drill');
  await page.getByRole('button', { name: 'Suspend all agents' }).click();
  await page.getByRole('dialog').getByRole('button', { name: 'Suspend all agents' }).click();
  await expect(page.getByRole('button', { name: 'Resume all agents' })).toBeVisible();
  await expect.poll(() => api.log.some((l) => l.startsWith('POST /v1/agents/settings'))).toBe(true);
});

test('Agents is in the sidebar under Identity', async ({ page }) => {
  await open(page, '/');
  await page.getByRole('navigation', { name: 'Main' }).getByRole('link', { name: 'Agents' }).click();
  await expect(page.locator('main h1').first()).toHaveText('Agents');
});
