import { expect, open, test } from './fixtures';

test('write-ahead audit: an attempt shows as pending and links to its outcome', async ({ page }) => {
  await open(page, '/audit');
  const attempt = page.getByRole('row').filter({ hasText: '#98' });
  await expect(attempt.getByText('Attempt')).toBeVisible();

  await attempt.getByRole('button', { name: 'Expand event 98' }).click();
  await expect(page.getByText('Recorded before the change ran (write-ahead audit).')).toBeVisible();
  await page.getByRole('button', { name: 'Show outcome' }).click();

  await expect(page).toHaveURL(/correlation=5f2a9c0d1e3b4a6f8091a2b3c4d5e6f7/);
  await expect(page.getByText(/correlation = 5f2a9c0d1e3b/)).toBeVisible();
  await expect(page.getByText('Showing 1–2 of 2 matching events')).toBeVisible();
  await expect(page.getByRole('row').filter({ hasText: '#99' })).toBeVisible();
});

test('write-ahead audit: the result filter offers pending attempts', async ({ page }) => {
  await open(page, '/audit');
  await page.getByRole('button', { name: /Result:/ }).click();
  await page.getByRole('menuitemradio', { name: 'Pending' }).click();
  await expect(page).toHaveURL(/result=pending/);
  await expect(page.getByText('Showing 1–1 of 1 matching events')).toBeVisible();
});
