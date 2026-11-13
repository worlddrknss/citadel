import AxeBuilder from '@axe-core/playwright';
import { expect, open, test } from './fixtures';

// The in-console docs: built from docs/*.md, with a grouped nav, search,
// deep-linkable headings, an "On this page" contents, copy buttons, and
// readable without signing in. (The per-page sweeps in pages.spec.ts also
// run axe and the phone-width check on /docs pages.)

test('opens from the sidebar and navigates between docs', async ({ page }) => {
  await open(page, '/');
  await page.getByRole('navigation', { name: 'Main' }).getByRole('link', { name: 'Docs' }).click();
  await expect(page).toHaveURL(/\/app\/docs$/);
  await expect(page.locator('main h1')).toHaveText('Documentation');

  const nav = page.getByRole('navigation', { name: 'Docs pages' });
  await expect(nav.getByText('Getting started', { exact: true }).first()).toBeVisible();
  await nav.getByRole('link', { name: 'Connecting MCP clients' }).click();
  await expect(page).toHaveURL(/\/app\/docs\/agents-mcp$/);
  await expect(page.locator('main h1')).toHaveText('Connecting MCP clients to Citadel');
  await expect(nav.getByRole('link', { name: 'Connecting MCP clients' })).toHaveAttribute('aria-current', 'page');
  await expect(page).toHaveTitle('Connecting MCP clients to Citadel · Docs · Citadel');

  // A link between docs (agents.md#logins-for-browser-agents) stays in the console.
  await page.locator('article').getByRole('link', { name: 'agents.md' }).first().click();
  await expect(page).toHaveURL(/\/app\/docs\/agents(#.*)?$/);
  await expect(page.locator('main h1')).toHaveText('Credentials for AI agents');
});

test('deep links to a heading, with an On this page contents', async ({ page }) => {
  await page.goto('/app/docs/agents#minted-credentials');
  const heading = page.getByRole('heading', { level: 2, name: 'Minted credentials' });
  await expect(heading).toBeInViewport();
  await expect(heading).toHaveAttribute('id', 'minted-credentials');

  const toc = page.getByRole('navigation', { name: 'On this page' });
  await expect(toc.getByRole('link', { name: 'Anomaly alerts' })).toHaveAttribute('href', '#anomaly-alerts');
  await toc.getByRole('link', { name: 'Anomaly alerts' }).click();
  await expect(page).toHaveURL(/#anomaly-alerts$/);
  await expect(page.getByRole('heading', { level: 2, name: 'Anomaly alerts' })).toBeInViewport();
  await expect(toc.getByRole('link', { name: 'Anomaly alerts' })).toHaveAttribute('aria-current', 'location');
});

test('searches titles, headings and text', async ({ page }) => {
  await open(page, '/docs');
  const search = page.getByRole('searchbox', { name: 'Search the docs' });
  await search.fill('totp_sha1_unsupported');
  const results = page.getByRole('list', { name: 'Search results' });
  await expect(results.getByRole('link').first()).toBeVisible();
  await results.getByRole('link', { name: /Troubleshooting/ }).first().click();
  await expect(page).toHaveURL(/\/app\/docs\/getting-started-agents#troubleshooting$/);
  await expect(page.getByRole('heading', { level: 2, name: 'Troubleshooting' })).toBeInViewport();

  await search.fill('kill switch');
  await search.press('ArrowDown');
  await expect(results.getByRole('link').first()).toBeFocused();
  await search.fill('qwertyuiop');
  await expect(page.getByText('No matches.')).toBeVisible();
});

test('copies a code block', async ({ page, context }) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  await open(page, '/docs/getting-started-agents');
  const block = page.locator('.codeblock').first();
  await block.getByRole('button', { name: 'Copy code' }).click();
  await expect(block.getByRole('button', { name: 'Copied' })).toBeVisible();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(await block.locator('code').textContent());
});

test('is in the command palette', async ({ page }) => {
  await open(page, '/');
  await page.keyboard.press('ControlOrMeta+k');
  const palette = page.getByRole('dialog', { name: 'Search Citadel' });
  await palette.getByRole('combobox').fill('AI agents: step');
  await expect(palette.getByRole('option', { name: /AI agents: step by step/ }).first()).toBeVisible();
  await page.keyboard.press('Enter');
  await expect(page).toHaveURL(/\/app\/docs\/getting-started-agents$/);
});

test('Learn more links from the agent pages land on the guide', async ({ page }) => {
  await open(page, '/agents');
  await page.getByRole('link', { name: 'Learn more' }).click();
  await expect(page.locator('main h1')).toHaveText('Getting started with AI agents');

  await open(page, '/secrets/payments/dev?secret=STRIPE_KEY&tab=agents');
  await page.getByRole('link', { name: 'Learn more about usage profiles' }).click();
  await expect(page).toHaveURL(/\/docs\/getting-started-agents#step-3-make-a-secret-usable-by-agents$/);
  await expect(page.getByRole('heading', { level: 2, name: /Step 3: Make a secret usable by agents/ })).toBeInViewport();
});

test('works at phone width', async ({ page }) => {
  await page.setViewportSize({ width: 375, height: 812 });
  await open(page, '/docs/agents');
  await expect(page.getByRole('navigation', { name: 'Docs pages' })).toBeHidden();
  await page.getByText('Browse the docs').click();
  await page.getByRole('navigation', { name: 'Docs pages' }).getByRole('link', { name: 'Deployment' }).click();
  await expect(page.locator('main h1')).toHaveText('Deploying Citadel');
  await page.locator('summary', { hasText: 'On this page' }).click();
  await expect(page.locator('details.tocfold').getByRole('link', { name: 'First run' })).toBeVisible();
  const { scrollWidth, innerWidth } = await page.evaluate(() => ({ scrollWidth: document.scrollingElement!.scrollWidth, innerWidth: window.innerWidth }));
  expect(scrollWidth).toBeLessThanOrEqual(innerWidth);
});

test('is readable without signing in', async ({ page, api, allowConsole }) => {
  allowConsole(/status of 401/);
  api.signedIn = false;
  await page.goto('/app/docs/getting-started');
  await expect(page.locator('main h1')).toHaveText('Getting started');
  await expect(page.getByRole('link', { name: 'Sign in' })).toBeVisible();
  await expect(page.getByRole('navigation', { name: 'Main' })).toHaveCount(0);
  const results = await new AxeBuilder({ page }).analyze();
  expect(results.violations.filter((v) => v.impact === 'serious' || v.impact === 'critical').map((v) => v.id)).toEqual([]);

  // Other pages still need a session.
  await page.goto('/app/kms');
  await expect(page.getByRole('button', { name: 'Sign in' })).toBeVisible();
});
