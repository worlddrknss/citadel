import { expect, open, test } from './fixtures';
import { ACCOUNT, MFA_CODE, mfaRecoveryCodes } from './mock';

const FAILED_401 = /status of 401/;

async function signIn(page: import('@playwright/test').Page) {
  await page.goto('/app/');
  await page.getByLabel('Account ID').fill(ACCOUNT);
  await page.getByLabel('Username').fill('alice');
  await page.getByLabel('Password', { exact: true }).fill('correct horse battery staple');
  await page.getByRole('button', { name: 'Sign in' }).click();
}

test.describe('two-step verification', () => {
  test('sign-in asks for a code after the password', async ({ page, api, allowConsole }) => {
    allowConsole(FAILED_401);
    api.signedIn = false;
    api.mfaLogin = true;
    await signIn(page);

    await expect(page.getByRole('heading', { name: 'Enter your code' })).toBeVisible();
    const code = page.getByLabel('Authentication code');
    await expect(code).toHaveAttribute('autocomplete', 'one-time-code');
    await expect(code).toHaveAttribute('inputmode', 'numeric');
    await expect(code).toBeFocused();

    await code.fill('000000');
    await page.getByRole('button', { name: 'Verify' }).click();
    await expect(page.getByRole('alert')).toContainText('invalid or already used code');
    await expect(page.locator('main h1')).toHaveCount(0);

    await code.fill(MFA_CODE);
    await page.getByRole('button', { name: 'Verify' }).click();
    await expect(page.locator('main h1')).toHaveText('Overview');
    expect(api.log).toContain('POST /v1/login/mfa');
  });

  test('a recovery code works instead of the app', async ({ page, api, allowConsole }) => {
    allowConsole(FAILED_401);
    api.signedIn = false;
    api.mfaLogin = true;
    await signIn(page);
    await page.getByRole('button', { name: 'Use a recovery code' }).click();
    await expect(page.getByRole('heading', { name: 'Use a recovery code' })).toBeVisible();
    await page.getByRole('textbox', { name: 'Recovery code' }).fill(mfaRecoveryCodes[0].toUpperCase());
    await page.getByRole('button', { name: 'Verify' }).click();
    await expect(page.locator('main h1')).toHaveText('Overview');
  });

  test('My account → Security enrols with a locally drawn QR code and shows recovery codes once', async ({ page, api, allowConsole }) => {
    allowConsole(/status of 400/); // the deliberately wrong code
    const external: string[] = [];
    page.on('request', (r) => {
      if (!r.url().startsWith('http://localhost')) external.push(r.url());
    });
    await open(page, '/account');
    const panel = page.getByRole('region', { name: 'Security' });
    await expect(panel.getByText('Off', { exact: true })).toBeVisible();
    await panel.getByRole('button', { name: 'Set up' }).click();

    const dialog = page.getByRole('dialog', { name: 'Set up two-step verification' });
    await expect(dialog.getByRole('img', { name: /QR code/ })).toBeVisible();
    await expect(dialog.getByText(/must support SHA-256/)).toBeVisible();
    await dialog.getByRole('button', { name: /Enter the key by hand/ }).click();
    await expect(dialog.getByTestId('mfa-secret')).toContainText('GEZD GNBV');

    await dialog.getByLabel(/6-digit code/).fill('111111');
    await dialog.getByRole('button', { name: 'Turn on' }).click();
    await expect(dialog.getByRole('alert')).toContainText('not valid');
    await dialog.getByLabel(/6-digit code/).fill(MFA_CODE);
    await dialog.getByRole('button', { name: 'Turn on' }).click();

    await expect(dialog.getByText(mfaRecoveryCodes[0])).toBeVisible();
    const download = page.waitForEvent('download');
    await dialog.getByRole('button', { name: 'Download .txt' }).click();
    expect((await download).suggestedFilename()).toBe('citadel-recovery-codes.txt');
    await expect(dialog.getByRole('button', { name: 'Finish' })).toBeDisabled();
    await dialog.getByLabel("I've saved my recovery codes").check();
    await dialog.getByRole('button', { name: 'Finish' }).click();

    await expect(panel.getByText('On', { exact: true })).toBeVisible();
    await expect(panel.getByText(/10 recovery codes left/)).toBeVisible();
    expect(external, 'no request leaves the page (QR codes are local)').toEqual([]);
    expect(api.mfaEnabled).toBe(true);
  });

  test('turning it off needs the password and a code', async ({ page, api }) => {
    api.mfaEnabled = true;
    const posted: Record<string, unknown>[] = [];
    page.on('request', (r) => {
      if (r.url().endsWith('/v1/account/mfa/disable')) posted.push(r.postDataJSON());
    });
    await open(page, '/account');
    const panel = page.getByRole('region', { name: 'Security' });
    await panel.getByRole('button', { name: 'Turn off' }).click();
    const dialog = page.getByRole('dialog', { name: /Turn off two-step/ });
    await dialog.getByLabel('Current password').fill('pw-123456789');
    await dialog.getByLabel('Authentication code').fill(MFA_CODE);
    await dialog.getByRole('button', { name: 'Turn off' }).click();
    await expect(page.getByText('Two-step verification is off')).toBeVisible();
    expect(posted).toEqual([{ password: 'pw-123456789', code: MFA_CODE }]);
  });

  test('organization policy forces enrolment before the console', async ({ page, api }) => {
    api.mfaEnrollmentRequired = true;
    await page.goto('/app/');
    await expect(page.getByRole('heading', { name: 'Set up two-step verification' })).toBeVisible();
    await expect(page.getByRole('navigation', { name: 'Main' })).toHaveCount(0);
    // Nothing but the enrolment endpoints is called.
    expect(api.log.filter((l) => /change-requests|certificates|organization/.test(l))).toEqual([]);

    await page.getByLabel(/6-digit code/).fill(MFA_CODE);
    await page.getByRole('button', { name: 'Turn on' }).click();
    await page.getByLabel("I've saved my recovery codes").check();
    await page.getByRole('button', { name: 'Finish' }).click();
    await expect(page.locator('main h1')).toHaveText('Overview');
  });

  test('admins reset a user’s MFA with type-to-confirm; settings toggle requireMFA', async ({ page }) => {
    const posted: Record<string, unknown>[] = [];
    page.on('request', (r) => {
      if (r.method() === 'POST' && /\/v1\/admin\/(users\/mfa\/reset|settings)$/.test(r.url())) posted.push(r.postDataJSON());
    });
    await open(page, '/admin?tab=users');
    await expect(page.getByText('MFA', { exact: true })).toBeVisible();
    await page.getByRole('button', { name: 'Reset two-step verification for bob' }).click();
    const dialog = page.getByRole('dialog', { name: /Reset two-step verification for bob/ });
    const go = dialog.getByRole('button', { name: 'Reset MFA' });
    await expect(go).toBeDisabled();
    await dialog.getByRole('textbox').fill('bob');
    await go.click();
    await expect(page.getByText('Reset two-step verification for bob', { exact: true })).toBeVisible();
    expect(posted[0]).toEqual({ username: 'bob', confirm: 'bob' });

    await open(page, '/admin?tab=settings');
    await page.getByLabel('Require an authenticator app for password sign-in').check();
    await page.getByRole('button', { name: 'Save settings' }).click();
    await page.getByRole('dialog', { name: 'Require two-step verification?' }).getByRole('button', { name: 'Require it' }).click();
    await expect(page.getByText('Organization settings saved')).toBeVisible();
    expect(posted[1]).toMatchObject({ requireMFA: true });
  });
});
