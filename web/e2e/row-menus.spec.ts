import { expect, open, test } from './fixtures';
import { fixtures } from './mock';

// Row "more actions" menus open over everything: not clipped by the table's
// scroll box or the card around it, including on the last row, where the menu
// has to open upward. The check is that the browser hit-tests the menu item
// at its own centre, which fails when anything covers or clips it.

// Each list is trimmed to a single row: a one-row table is the short scroll
// box a menu used to spill out of and get clipped by.
type Row = Record<string, unknown>;
const pages: { path: string; rows: Row[]; keep: (rows: Row[]) => Row[] }[] = [
  {
    path: '/certificates',
    rows: fixtures.certificates as Row[],
    // CAs live in the CA tree, not the table: keep them and one certificate.
    keep: (rows) => [...rows.filter((r) => r.isCA), rows.find((r) => !r.isCA)!]
  },
  { path: '/kms', rows: fixtures.keys as Row[], keep: (rows) => rows.slice(0, 1) },
  {
    path: '/parameters',
    rows: fixtures.parameters as Row[],
    // A top-level parameter, so the root folder shows a single row.
    keep: (rows) => [rows.find((r) => !String(r.name).startsWith('/'))!]
  }
];

for (const p of pages) {
  test(`row menus on ${p.path} are fully visible with a single row`, async ({ page }) => {
    const saved = p.rows.slice();
    p.rows.splice(0, p.rows.length, ...p.keep(saved));
    try {
      await check(page, p.path);
    } finally {
      p.rows.splice(0, p.rows.length, ...saved);
    }
  });
}

async function check(page: import('@playwright/test').Page, path: string) {
  await open(page, path);
  await page.waitForLoadState('networkidle');
  const triggers = page.getByRole('button', { name: /^More actions for / });
  const count = await triggers.count();
  expect(count, 'rows with a menu').toBeGreaterThan(0);

  for (const index of [0, count - 1]) {
    await triggers.nth(index).click();
    const items = page.getByRole('menuitem');
    await expect(items.first()).toBeVisible();
    const n = await items.count();
    for (let i = 0; i < n; i++) {
      const item = items.nth(i);
      const box = await item.boundingBox();
      expect(box, `menu item ${i} has a box`).not.toBeNull();
      const vp = page.viewportSize()!;
      expect(box!.y).toBeGreaterThanOrEqual(0);
      expect(box!.y + box!.height).toBeLessThanOrEqual(vp.height);
      const hit = await item.evaluate((el) => {
        const r = el.getBoundingClientRect();
        const top = document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2);
        return !!top && (top === el || el.contains(top));
      });
      expect(hit, `menu item ${i} on row ${index} is not covered or clipped`).toBe(true);
    }
    await page.keyboard.press('Escape');
    await expect(items.first()).toBeHidden();
  }
}
