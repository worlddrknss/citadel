import type { Page } from '@playwright/test';
import { expect, open, test } from './fixtures';
import { me } from './mock';

const LEGACY_NOTE =
  "16 links in pre-2.0 history don't connect. This is consistent with concurrent writes in Citadel 1.x, which didn't lock the chain; events from 2.0 on are fully verified.";

/** Serves a verified chain whose pre-2.0 part has 16 links that don't connect. */
async function legacyChain(page: Page, full: string[]) {
  await page.route('**/v1/audit/verify**', (route) => {
    const url = new URL(route.request().url());
    if (route.request().method() === 'POST' && url.searchParams.get('full') === 'true') full.push('full');
    return route.fulfill({
      json: {
        status: 'verified',
        verifiedThrough: 316700,
        headHash: 'abcdef0123456789',
        checkedAt: new Date().toISOString(),
        totalEvents: 316700,
        legacyEvents: 316652,
        legacyLinkBreaks: 16,
        firstLegacyBreakSeq: 1174,
        firstLegacyBreakId: 1174
      }
    });
  });
}

test('legacy link breaks: verified with an amber note on the audit page and the overview', async ({ page }) => {
  const full: string[] = [];
  await legacyChain(page, full);
  await open(page, '/audit');
  await expect(page.getByText('Chain verified through event #316,700')).toBeVisible();
  await expect(page.getByTestId('legacy-break-note')).toHaveText(LEGACY_NOTE);

  // Platform admins can run a full re-check.
  await page.getByRole('button', { name: 'Full re-check' }).click();
  await expect(page.getByText(/Full re-check: chain verified through event #316,700/)).toBeVisible();
  expect(full).toEqual(['full']);

  await open(page, '/');
  await expect(page.getByTestId('overview-legacy-note')).toHaveText(LEGACY_NOTE);
});

test('the full re-check button is hidden from users who are not platform admins', async ({ page }) => {
  await page.route('**/v1/me', (route) => route.fulfill({ json: { ...me, role: 'admin', platformAdmin: false } }));
  await open(page, '/audit');
  await expect(page.getByRole('button', { name: 'Verify now' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Full re-check' })).toHaveCount(0);
});

// 2.0.3 console changes against the mocked API: CA path length, workload
// client name conflicts, parameter name rules.

test("Let's Encrypt HTTP-01 issuance runs in the background with progress", async ({ page }) => {
  const polls: string[] = [];
  await page.route('**/v1/certificates/letsencrypt/request', (route) =>
    route.fulfill({ status: 202, json: { requested: true, orderId: 'ord-1', status: 'processing', domains: 'www.acme.test' } })
  );
  await page.route('**/v1/certificates/letsencrypt/orders**', (route) => {
    polls.push(route.request().url());
    const step = polls.length;
    const json =
      step < 3
        ? { orderId: 'ord-1', kind: 'http-01', status: 'processing', domains: 'www.acme.test', progress: 'Validating www.acme.test (HTTP-01)' }
        : { orderId: 'ord-1', kind: 'http-01', status: 'issued', domains: 'www.acme.test', certId: 'cert-www-1' };
    return route.fulfill({ json });
  });
  await open(page, '/certificates?tab=letsencrypt');
  await page.getByLabel('Domains').fill('www.acme.test');
  await page.getByRole('button', { name: 'Request certificate' }).click();
  const progress = page.getByTestId('le-progress');
  await expect(progress).toBeVisible();
  await expect(page.getByTestId('le-progress-step')).toHaveText('Validating www.acme.test (HTTP-01)…');
  await expect(page.getByText('Issued a certificate for www.acme.test')).toBeVisible({ timeout: 15_000 });
  await expect(progress).toBeHidden();
  expect(polls.every((u) => u.includes('id=ord-1'))).toBe(true);
});

test("Let's Encrypt DNS-01: a failed validation shows the error and can be retried", async ({ page }) => {
  let completes = 0;
  await page.route('**/v1/certificates/letsencrypt/dns/begin', (route) =>
    route.fulfill({ json: { orderId: 'dns-1', records: [{ domain: 'acme.test', name: '_acme-challenge.acme.test', value: 'txt-value-1' }] } })
  );
  await page.route('**/v1/certificates/letsencrypt/dns/complete', (route) => {
    completes++;
    return route.fulfill({ status: 202, json: { orderId: 'dns-1', kind: 'dns-01', status: 'processing', domains: 'acme.test', progress: 'Starting validation' } });
  });
  await page.route('**/v1/certificates/letsencrypt/orders**', (route) =>
    route.fulfill({
      json:
        completes === 1
          ? { orderId: 'dns-1', kind: 'dns-01', status: 'failed', domains: 'acme.test', error: 'Validation failed: no TXT record found at _acme-challenge.acme.test' }
          : { orderId: 'dns-1', kind: 'dns-01', status: 'issued', domains: 'acme.test', certId: 'cert-www-1' }
    })
  );
  await open(page, '/certificates?tab=letsencrypt');
  await page.getByRole('button', { name: 'DNS-01 · manual' }).click();
  await page.getByLabel('Domains').fill('acme.test');
  await page.getByRole('button', { name: 'Get DNS records' }).click();
  await expect(page.getByText('txt-value-1')).toBeVisible();
  await page.getByRole('button', { name: 'Validate and issue' }).click();
  await expect(page.getByRole('alert').filter({ hasText: 'no TXT record found' })).toBeVisible();
  // The records stay up for a retry.
  await expect(page.getByText('txt-value-1')).toBeVisible();
  await page.getByRole('button', { name: 'Validate and issue' }).click();
  await expect(page.getByText('Issued a certificate for acme.test')).toBeVisible();
  expect(completes).toBe(2);
});

test('the CA tree and drawer show each CA path length', async ({ page }) => {
  await open(page, '/certificates');
  const tree = page.getByRole('region', { name: 'CA hierarchy' });
  await expect(tree.getByRole('button', { name: /Acme Root CA/ })).toContainText('pathLen: unlimited');
  const sub = tree.getByRole('button', { name: /Acme Issuing CA/ });
  await expect(sub).toContainText('pathLen: 0');
  await sub.click();
  await expect(page.getByTestId('ca-pathlen')).toHaveText(/^0 — issues end-entity certificates only/);
});

test('a duplicate workload client name shows the server conflict on the name field', async ({ page, allowConsole }) => {
  allowConsole(/status of 409/);
  await page.route('**/v1/workload-identity/clients', (route) =>
    route.request().method() === 'POST'
      ? route.fulfill({
          status: 409,
          json: { error: 'name_taken', message: 'A client named "fresh-name" already exists in this account. Choose another name.' }
        })
      : route.fallback()
  );
  await open(page, '/workload-identity');
  await page.getByRole('button', { name: 'New client' }).first().click();
  const dlg = page.getByRole('dialog', { name: 'New workload client' });
  await dlg.getByLabel('Name').fill('fresh-name');
  await dlg.getByRole('button', { name: 'Citadel access key' }).click();
  await dlg.getByLabel('Allowed users').fill('alice');
  await dlg.getByRole('button', { name: 'Create client' }).click();
  await expect(dlg.getByText('A client named "fresh-name" already exists in this account. Choose another name.')).toBeVisible();
  await expect(dlg).toBeVisible();
});

test('parameter names beginning with aws or ssm are refused before submitting', async ({ page, api }) => {
  await open(page, '/parameters');
  await page.getByRole('button', { name: 'Create parameter' }).first().click();
  const dlg = page.getByRole('dialog', { name: 'Create parameter' });
  await dlg.getByRole('textbox').first().fill('AWS-thing');
  await dlg.getByLabel('Value').fill('v');
  await dlg.getByRole('button', { name: 'Create parameter' }).click();
  await expect(dlg.getByText('Parameter names can\'t begin with "aws" or "ssm" (in any case).')).toBeVisible();
  expect(api.log.filter((l) => l.startsWith('POST /v1/parameters'))).toEqual([]);
});
