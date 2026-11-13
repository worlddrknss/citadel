import { ORG, checkA11y, expect, open, signIn, test } from './fixtures';

// The in-console docs served by the real binary: the embedded console's
// index.html fallback serves deep links under /app/docs, the server's CSP
// allows the rendered pages (a violation would be a console error), and the
// docs are readable without a session.

test('docs pages, deep links and search in a signed-in session', async ({ page }) => {
  await signIn(page, ORG.admin);
  await open(page, '/agents');
  await page.getByRole('link', { name: 'Learn more' }).click();
  await expect(page.locator('main h1')).toHaveText('Getting started with AI agents');

  await page.goto('/app/docs/agents#minted-credentials');
  await expect(page.getByRole('heading', { level: 2, name: 'Minted credentials' })).toBeInViewport();
  await checkA11y(page);

  await page.getByRole('searchbox', { name: 'Search the docs' }).fill('approval_required');
  await page.getByRole('list', { name: 'Search results' }).getByRole('link').first().click();
  await expect(page).toHaveURL(/\/app\/docs\/[a-z-]+#/);

  // The API reference is one click away.
  await open(page, '/docs');
  await page.getByRole('navigation', { name: 'Docs pages' }).getByRole('link', { name: 'API reference' }).click();
  await expect(page.getByRole('heading', { level: 1, name: 'API reference' })).toBeVisible();
});

test('docs are public; the rest of the console still needs a session', async ({ browser, expectStatus }) => {
  expectStatus(401, /^\/v1\/me$/);
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  try {
    const res = await page.goto('/app/docs/getting-started-agents#troubleshooting');
    expect(res?.status()).toBe(200);
    await expect(page.locator('main h1')).toHaveText('Getting started with AI agents');
    await expect(page.getByRole('heading', { level: 2, name: 'Troubleshooting' })).toBeInViewport();
    await expect(page.getByRole('link', { name: 'Sign in' })).toBeVisible();
    await checkA11y(page);

    await page.goto('/app/agents');
    await expect(page.getByRole('button', { name: 'Sign in' })).toBeVisible();
    await expect(page.getByRole('navigation', { name: 'Main' })).toHaveCount(0);
  } finally {
    await ctx.close();
  }
});
