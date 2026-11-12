import { expect, open, test } from './fixtures';
import { ACCOUNT } from './mock';

// A 401 is the point of these tests; Chromium logs each one as a failed load.
const FAILED_401 = /status of 401/;

test.describe('sign-in', () => {
  test('signs in from the sign-in screen to the console shell', async ({ page, api, allowConsole }) => {
    allowConsole(FAILED_401); // the initial /v1/me
    api.signedIn = false;
    await page.goto('/app/');
    await expect(page.getByRole('heading', { name: /sign in/i })).toBeVisible();
    await expect(page.locator('main h1')).toHaveCount(0);

    await page.getByLabel('Account ID').fill(ACCOUNT);
    await page.getByLabel('Username').fill('alice');
    await page.getByLabel('Password', { exact: true }).fill('correct horse battery staple');
    await page.getByRole('button', { name: 'Sign in' }).click();

    await expect(page.locator('main h1')).toHaveText('Overview');
    await expect(page.getByRole('navigation', { name: 'Main' })).toBeVisible();
    expect(api.log).toContain('POST /v1/login');
    // The account is remembered for next time.
    expect(await page.evaluate(() => localStorage.getItem('citadel-last-account'))).toBe(ACCOUNT);
  });

  test('a 401 mid-session returns to sign-in with the expired notice', async ({ page, api, allowConsole }) => {
    allowConsole(FAILED_401);
    await open(page, '/');
    await expect(page.getByText(/Your session expired/)).toHaveCount(0);

    api.expireSession();
    await page.getByRole('navigation', { name: 'Main' }).getByRole('link', { name: 'KMS keys' }).click();

    await expect(page.getByText(/Your session expired/)).toBeVisible();
    await expect(page.getByRole('button', { name: 'Sign in' })).toBeVisible();
    await expect(page.locator('main h1')).toHaveCount(0);
  });

  test('first run asks for the one-time setup token', async ({ page, api, allowConsole }) => {
    allowConsole(FAILED_401);
    api.signedIn = false;
    const posted: Record<string, unknown>[] = [];
    await page.route('**/v1/bootstrap', async (route) => {
      const req = route.request();
      if (req.method() === 'GET') return route.fulfill({ status: 200, json: { required: true } });
      const body = req.postDataJSON() as Record<string, unknown>;
      posted.push(body);
      if (body.bootstrapToken !== 'tok-from-the-log') {
        return route.fulfill({ status: 401, json: { error: 'invalid_bootstrap_token', message: 'The bootstrap token is missing or wrong.' } });
      }
      return route.fulfill({ status: 201, json: { accountId: ACCOUNT, organization: 'Acme', username: 'founder' } });
    });
    await page.goto('/app/');
    await expect(page.getByRole('heading', { name: 'Create your organization' })).toBeVisible();

    await page.getByLabel('Setup token').fill('wrong');
    await page.getByLabel('Organization name').fill('Acme');
    await page.getByLabel('First account name').fill('production');
    await page.getByLabel('Admin username').fill('founder');
    await page.getByLabel('Password', { exact: true }).fill('a-long-passphrase-here');
    await page.getByRole('button', { name: 'Create organization' }).click();
    await expect(page.getByRole('alert')).toContainText('bootstrap token is missing or wrong');

    await page.getByLabel('Setup token').fill('tok-from-the-log');
    await page.getByRole('button', { name: 'Create organization' }).click();
    await expect(page.getByRole('heading', { name: 'Acme is ready' })).toBeVisible();
    expect(posted.map((b) => b.bootstrapToken)).toEqual(['wrong', 'tok-from-the-log']);
  });

  test('a fresh visit without a session shows no expired notice', async ({ page, api, allowConsole }) => {
    allowConsole(FAILED_401);
    api.signedIn = false;
    await page.goto('/app/kms');
    await expect(page.getByRole('button', { name: 'Sign in' })).toBeVisible();
    await expect(page.getByText(/Your session expired/)).toHaveCount(0);
  });
});

test.describe('secrets', () => {
  test('project → environment → folder, reveal a value, open the drawer', async ({ page, api }) => {
    await open(page, '/secrets');
    await page.getByRole('link', { name: /^Payments/ }).first().click();
    await expect(page).toHaveURL(/\/app\/secrets\/payments$/);

    await page.getByRole('link', { name: /Development/ }).first().click();
    await expect(page).toHaveURL(/\/app\/secrets\/payments\/dev$/);
    await expect(page.getByRole('link', { name: /^db/ })).toBeVisible();

    await page.getByRole('link', { name: /^db/ }).click();
    await expect(page).toHaveURL(/[?&]path=%2Fdb(&|$)/);
    const row = page.getByRole('row', { name: /DB_PASSWORD/ });
    await expect(row).toBeVisible();

    // Reveal: the value is fetched only now, and shows with a countdown.
    expect(api.log.some((l) => l.startsWith('GET /v1/secrets/value'))).toBe(false);
    await row.getByRole('button', { name: 'Reveal value' }).click();
    await expect(row.getByText('value-of-DB_PASSWORD')).toBeVisible();
    await expect(row.getByText(/Hides in \d+ s/)).toBeVisible();
    expect(api.log).toContainEqual(expect.stringMatching(/^GET \/v1\/secrets\/value\?.*key=DB_PASSWORD/));
    await row.getByRole('button', { name: 'Hide value' }).click();
    await expect(row.getByText('value-of-DB_PASSWORD')).toHaveCount(0);

    // Drawer: URL-backed, so a refresh lands in the same place.
    await row.getByRole('button', { name: 'Open details for DB_PASSWORD' }).click();
    await expect(page).toHaveURL(/[?&]secret=DB_PASSWORD(&|$)/);
    const close = page.getByRole('button', { name: 'Close details' });
    await expect(close).toBeVisible();
    await page.reload();
    await expect(page.getByRole('button', { name: 'Close details' })).toBeVisible();
    await page.getByRole('button', { name: 'Close details' }).click();
    await expect(page).not.toHaveURL(/secret=/);
    await expect(page).toHaveURL(/path=%2Fdb/);

    // Back returns to the environment root.
    await page.goBack();
    await expect(page).not.toHaveURL(/path=/);
    await expect(page.getByRole('row', { name: /API_KEY/ })).toBeVisible();
  });
});

test.describe('KMS', () => {
  test('filter by status, open a key, schedule deletion only after typing its name', async ({ page, api }) => {
    await open(page, '/kms');
    const table = page.getByRole('table');
    await expect(table.getByText('alias/payments')).toBeVisible();

    const filters = page.getByRole('group', { name: 'Status filter' });
    await filters.getByRole('button', { name: /^Disabled/ }).click();
    await expect(page).toHaveURL(/[?&]status=disabled/);
    await expect(table.getByText('alias/release-signing')).toBeVisible();
    await expect(table.getByText('alias/payments')).toHaveCount(0);

    await filters.getByRole('button', { name: /^Pending deletion/ }).click();
    await expect(table.getByText('alias/legacy')).toBeVisible();
    await expect(table.getByText('alias/release-signing')).toHaveCount(0);

    await filters.getByRole('button', { name: /^Enabled/ }).click();
    await expect(table.getByText('alias/payments')).toBeVisible();
    await expect(table.getByText('alias/legacy')).toHaveCount(0);

    await table.getByRole('button', { name: /^alias\/payments/ }).click();
    await expect(page).toHaveURL(/[?&]key=2222bbbb-0000-4000-8000-000000000002/);
    await page.getByRole('button', { name: 'Schedule deletion' }).click();

    const dialog = page.getByRole('dialog', { name: 'Schedule deletion of this key?' });
    await expect(dialog).toBeVisible();
    // usedBy comes from the key detail, not the list.
    await expect(dialog.getByTestId('key-usage')).toHaveText(/3 secrets and 0 parameters still use it/);
    const confirm = dialog.getByRole('button', { name: 'Schedule deletion' });
    await expect(confirm).toBeDisabled();
    const input = dialog.getByRole('textbox');
    await input.fill('paymen');
    await expect(confirm).toBeDisabled();
    await input.fill('alias/payments-x');
    await expect(confirm).toBeDisabled();
    await input.fill('payments');
    await expect(confirm).toBeEnabled();
    await dialog.getByRole('combobox').selectOption('7');
    await confirm.click();

    await expect(dialog).toBeHidden();
    expect(api.log).toContain('POST /v1/kms/keys/schedule-deletion');
    await expect(page.getByText(/alias\/payments deletes on/)).toBeVisible();
  });
});

test.describe('shell', () => {
  test('⌘K / Ctrl+K opens the palette, finds a page and navigates', async ({ page }) => {
    await open(page, '/');
    await page.keyboard.press('ControlOrMeta+k');
    const palette = page.getByRole('dialog', { name: 'Search Citadel' });
    await expect(palette).toBeVisible();
    await palette.getByRole('combobox').fill('audit log');
    await expect(palette.getByRole('option', { name: /Audit log/ }).first()).toBeVisible();
    await page.keyboard.press('Enter');
    await expect(page).toHaveURL(/\/app\/audit$/);
    await expect(page.locator('main h1')).toHaveText('Audit log');
    await expect(palette).toBeHidden();
  });

  test('theme control switches data-theme and persists it', async ({ page }) => {
    await open(page, '/');
    const html = page.locator('html');
    await page.getByRole('button', { name: /^Account menu/ }).click();
    const theme = page.getByRole('group', { name: 'Theme' });
    await theme.getByRole('button', { name: 'Dark' }).click();
    await expect(html).toHaveAttribute('data-theme', 'dark');
    await theme.getByRole('button', { name: 'Light' }).click();
    await expect(html).toHaveAttribute('data-theme', 'light');

    await page.reload();
    await expect(page.locator('main h1')).toBeVisible();
    await expect(html).toHaveAttribute('data-theme', 'light');

    await page.getByRole('button', { name: /^Account menu/ }).click();
    await page.getByRole('group', { name: 'Theme' }).getByRole('button', { name: 'System' }).click();
    await expect(html).not.toHaveAttribute('data-theme', /.*/);
  });

  test('sign-in screen theme toggle cycles system → light → dark', async ({ page, api, allowConsole }) => {
    allowConsole(FAILED_401);
    api.signedIn = false;
    await page.goto('/app/');
    const html = page.locator('html');
    const toggle = page.getByRole('button', { name: /^Switch theme/ });
    await expect(toggle).toHaveAccessibleName(/now system/);
    await toggle.click();
    await expect(html).toHaveAttribute('data-theme', 'light');
    await toggle.click();
    await expect(html).toHaveAttribute('data-theme', 'dark');
    await toggle.click();
    await expect(html).not.toHaveAttribute('data-theme', /.*/);
  });
});
