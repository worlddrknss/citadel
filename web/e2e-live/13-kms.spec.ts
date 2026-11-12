import { ORG, apiPost, checkA11y, expect, open, signIn, test } from './fixtures';
import type { Page } from '@playwright/test';

// KMS keys through the real UI: create (symmetric, RSA encryption, ECC
// signing), aliases, grants, rotation (scheduled and on demand), tags, the
// Try it panel, the deletion dialog's usage warning and ?key= deep links.

async function createKey(page: Page, usage: 'Encrypt / decrypt' | 'Sign / verify', spec: string, alias: string): Promise<string> {
  await page.getByRole('button', { name: 'Create key' }).first().click();
  const dlg = page.getByRole('dialog', { name: 'Create key' });
  await dlg.getByRole('radio', { name: new RegExp(usage.replace('/', '\\/')) }).check();
  await dlg.getByLabel('Key spec').selectOption(spec);
  await dlg.getByLabel(/^Alias/).fill(alias);
  await dlg.getByLabel(/^Description/).fill(`live e2e ${alias}`);
  await dlg.getByRole('button', { name: 'Create key' }).click();
  await expect(dlg).toBeHidden();
  // Creating opens the new key's panel and puts it in the URL.
  const panel = page.getByRole('complementary', { name: `alias/${alias}` });
  await expect(panel).toBeVisible();
  await expect(page).toHaveURL(/[?&]key=/);
  return new URL(page.url()).searchParams.get('key')!;
}

function panelTab(page: Page, name: string) {
  return page.getByRole('tablist', { name: 'Key detail' }).getByRole('tab', { name: new RegExp(`^${name}`) });
}

test.describe.configure({ mode: 'serial' });

test('KMS keys: create, aliases, grants, rotation, tags, try it, deletion', async ({ page }) => {
  await signIn(page, ORG.admin);
  await open(page, '/kms');
  await page.waitForLoadState('networkidle');
  await checkA11y(page);

  // The account's managed default key is listed and flagged.
  await expect(page.getByRole('button', { name: /^alias\/default/ })).toBeVisible();

  // ---- symmetric key: aliases, grants, rotation, tags, encrypt/decrypt ----
  const symId = await createKey(page, 'Encrypt / decrypt', 'SYMMETRIC_DEFAULT', 'live-sym');
  const panel = page.getByRole('complementary', { name: 'alias/live-sym' });
  await expect(panel.getByText('Citadel, FIPS 140 module')).toBeVisible();
  await expect(panel.getByRole('definition').filter({ hasText: /^Off/ })).toBeVisible();
  await checkA11y(page);

  // Try it: encrypt, hand the blob to decrypt, get the plaintext back.
  await panel.getByLabel('Plaintext').fill('hello from the live suite');
  await panel.getByRole('button', { name: 'Encrypt', exact: true }).last().click();
  await expect(panel.getByText('Ciphertext blob (base64)').last()).toBeVisible();
  await panel.getByRole('button', { name: 'Decrypt this' }).click();
  await panel.getByRole('button', { name: 'Decrypt', exact: true }).last().click();
  await expect(panel.locator('pre.out')).toHaveText('hello from the live suite');

  // Aliases.
  await panelTab(page, 'Aliases').click();
  await panel.getByLabel('New alias').fill('live-sym-second');
  await panel.getByRole('button', { name: 'Add alias' }).first().click();
  await expect(panel.getByText('alias/live-sym-second')).toBeVisible();
  await panel.getByRole('button', { name: 'Delete alias alias/live-sym-second' }).click();
  await page.getByRole('dialog').last().getByRole('button', { name: /Delete/ }).click();
  await expect(panel.getByText('alias/live-sym-second')).toBeHidden();

  // Grants: create (token shown once), then revoke.
  await panelTab(page, 'Grants').click();
  await panel.getByRole('button', { name: 'Create grant' }).click();
  const gdlg = page.getByRole('dialog', { name: 'Create grant' });
  await gdlg.getByLabel('Grantee principal').fill('arn:aws:iam::123456789012:role/live-app');
  await gdlg.getByRole('checkbox', { name: 'Encrypt', exact: true }).check();
  await gdlg.getByRole('checkbox', { name: 'Decrypt', exact: true }).check();
  await gdlg.getByLabel(/^Name/).fill('live-grant');
  await gdlg.getByRole('button', { name: 'Create grant' }).click();
  const done = page.getByRole('dialog', { name: 'Grant created' });
  await expect(done.getByText('Grant token', { exact: true })).toBeVisible();
  await done.getByRole('button', { name: 'Done' }).click();
  await expect(panel.getByText('arn:aws:iam::123456789012:role/live-app')).toBeVisible();
  await panel.getByRole('button', { name: 'Revoke' }).click();
  await page.getByRole('dialog').last().getByRole('button', { name: /Revoke/ }).click();
  await expect(panel.getByText('arn:aws:iam::123456789012:role/live-app')).toBeHidden();

  // Rotation: turn on, then rotate on demand; history shows it.
  await panelTab(page, 'Rotation').click();
  await panel.getByLabel('Rotation period (days)').fill('180');
  await panel.getByRole('button', { name: 'Turn on rotation' }).click();
  await expect(panel.getByText('Every 180 days')).toBeVisible();
  await panel.getByRole('button', { name: 'Rotate now' }).click();
  await page.getByRole('dialog').last().getByRole('button', { name: 'Rotate now' }).click();
  await expect(panel.getByText('On demand')).toBeVisible();
  await expect(page.getByRole('row', { name: /alias\/live-sym/ }).getByText('Every 180 days')).toBeVisible();

  // Tags.
  await panelTab(page, 'Tags').click();
  await panel.getByLabel('Key', { exact: true }).fill('team');
  await panel.getByLabel('Value', { exact: true }).fill('payments');
  await panel.getByRole('button', { name: 'Add tag' }).click();
  await expect(panel.getByText('team')).toBeVisible();
  await panel.getByRole('button', { name: 'Remove tag team' }).click();
  await page.getByRole('dialog').last().getByRole('button', { name: 'Remove tag' }).click();
  await expect(panel.getByRole('button', { name: 'Remove tag team' })).toBeHidden();

  // ---- RSA encryption key: encrypt/decrypt with RSAES-OAEP ---------------
  await createKey(page, 'Encrypt / decrypt', 'RSA_2048', 'live-rsa');
  const rsa = page.getByRole('complementary', { name: 'alias/live-rsa' });
  await expect(rsa.getByText('Public key', { exact: true })).toBeVisible();
  await rsa.getByLabel('Plaintext').fill('rsa secret');
  await rsa.getByRole('button', { name: 'Encrypt', exact: true }).last().click();
  await rsa.getByRole('button', { name: 'Decrypt this' }).click();
  await rsa.getByRole('button', { name: 'Decrypt', exact: true }).last().click();
  await expect(rsa.locator('pre.out')).toHaveText('rsa secret');
  await panelTab(page, 'Rotation').click();
  await expect(rsa.getByText(/symmetric keys only/)).toBeVisible();

  // ---- signing key: sign, then verify --------------------------------------
  await createKey(page, 'Sign / verify', 'ECC_NIST_P256', 'live-sign');
  const sig = page.getByRole('complementary', { name: 'alias/live-sign' });
  await sig.getByRole('textbox', { name: 'Message' }).fill('sign me');
  await sig.getByRole('button', { name: 'Sign', exact: true }).last().click();
  await expect(sig.getByText('Signature (base64)').last()).toBeVisible();
  await sig.getByRole('button', { name: 'Verify this' }).click();
  await sig.getByRole('button', { name: 'Verify', exact: true }).last().click();
  await expect(sig.getByText('Signature valid')).toBeVisible();

  // ---- deep link and deletion with the usage warning ----------------------
  // A SecureString parameter encrypted with the symmetric key.
  await apiPost(page, '/v1/parameters', { name: '/live/kms/used', type: 'SecureString', value: 'x', kmsKeyId: symId });
  await page.goto(`/app/kms?key=${symId}`);
  const deep = page.getByRole('complementary', { name: 'alias/live-sym' });
  await expect(deep).toBeVisible();
  await expect(deep.getByText(/1 SecureString parameter/)).toBeVisible();
  await deep.getByRole('button', { name: 'Schedule deletion' }).click();
  const del = page.getByRole('dialog', { name: 'Schedule deletion of this key?' });
  await expect(del.getByTestId('key-usage')).toHaveText(/0 secrets and 1 parameter still use it/);
  await checkA11y(page);
  await del.getByRole('textbox').fill('live-sym');
  await del.getByRole('button', { name: /Schedule deletion/ }).click();
  await expect(del).toBeHidden();
  await expect(deep.getByText('Pending deletion').first()).toBeVisible();
  await deep.getByRole('button', { name: 'Cancel deletion' }).click();
  await expect(deep.getByRole('button', { name: 'Enable' })).toBeVisible();
});

test('KMS keys: editors cannot schedule deletion, viewers cannot run crypto', async ({ page }) => {
  await signIn(page, ORG.editor);
  await open(page, '/kms');
  await page.getByRole('button', { name: /^alias\/live-rsa/ }).click();
  const panel = page.getByRole('complementary', { name: 'alias/live-rsa' });
  await expect(panel.getByRole('button', { name: 'Disable' })).toBeVisible();
  await expect(panel.getByRole('button', { name: 'Schedule deletion' })).toBeHidden();
  await expect(panel.getByRole('heading', { name: 'Try it' })).toBeVisible();

  await page.context().clearCookies();
  await signIn(page, ORG.viewer);
  await open(page, '/kms');
  await page.getByRole('button', { name: /^alias\/live-rsa/ }).click();
  const vpanel = page.getByRole('complementary', { name: 'alias/live-rsa' });
  await expect(vpanel.getByText('Public key', { exact: true })).toBeVisible();
  await expect(vpanel.getByRole('heading', { name: 'Try it' })).toBeHidden();
  await expect(page.getByRole('button', { name: 'Create key' })).toBeHidden();
});
