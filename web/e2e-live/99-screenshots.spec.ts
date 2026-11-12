import { mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ORG, apiPost, expect, open, signIn, test } from './fixtures';

// README screenshots, taken from the real server after the rest of the live
// suite has filled it with data. Runs only with CITADEL_SCREENSHOTS=1:
//
//   npm run screenshots
//
// Images are written to docs/images/ at the repository root.

const OUT = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'docs', 'images');

test.skip(!process.env.CITADEL_SCREENSHOTS, 'set CITADEL_SCREENSHOTS=1 to refresh the README screenshots');

test.use({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2 });

async function shoot(page: import('@playwright/test').Page, name: string, theme: 'light' | 'dark') {
  await page.evaluate((t) => document.documentElement.setAttribute('data-theme', t), theme);
  // Let toasts fade and panels settle before capturing.
  await page.waitForTimeout(400);
  await page.waitForFunction(() => document.getAnimations().every((a) => a.playState !== 'running'));
  await page.screenshot({ path: join(OUT, `${name}-${theme}.png`) });
}

test('README screenshots', async ({ page }) => {
  mkdirSync(OUT, { recursive: true });
  await signIn(page, ORG.admin);

  // A realistic-looking project for the secrets screenshot. Values are
  // placeholders; they stay masked in the capture.
  await apiPost(page, '/v1/projects', { slug: 'payments-api', name: 'Payments API' }).catch(() => undefined);
  for (const env of ['development', 'staging', 'production']) {
    await apiPost(page, '/v1/environments', { project: 'payments-api', slug: env, name: env }).catch(() => undefined);
  }
  for (const [key, value] of [
    ['DATABASE_URL', 'postgres://payments:placeholder@db.internal:5432/payments'],
    ['STRIPE_SECRET_KEY', 'sk_test_placeholder'],
    ['WEBHOOK_SIGNING_SECRET', 'whsec_placeholder'],
    ['REDIS_URL', 'redis://cache.internal:6379/0'],
    ['JWT_PRIVATE_KEY', 'placeholder-private-key'],
    ['SENTRY_DSN', 'https://placeholder@sentry.example.com/1']
  ]) {
    await apiPost(page, '/v1/secrets', { project: 'payments-api', env: 'production', path: '/', key, value }).catch(() => undefined);
  }

  await open(page, '/');
  await shoot(page, 'overview', 'light');

  await open(page, '/secrets/payments-api/production');
  await expect(page.getByText('DATABASE_URL').first()).toBeVisible();
  await shoot(page, 'secrets', 'dark');

  await open(page, '/kms');
  await shoot(page, 'kms', 'light');
});
