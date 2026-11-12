import AxeBuilder from '@axe-core/playwright';
import { PAGES, expect, open, test } from './fixtures';

// One pass per page: it loads with no console/page errors and no unmocked
// calls (checked by the fixture), passes axe with no serious or critical
// violations, and has no horizontal page scroll at phone width.

for (const p of PAGES) {
  test.describe(`page ${p.path}`, () => {
    test('loads without errors', async ({ page }) => {
      await open(page, p.path);
      await expect(page.locator('main h1').first()).toHaveText(p.heading);
      // Let follow-up requests (details, counts, polls) settle.
      await page.waitForLoadState('networkidle');
    });

    test('has no serious or critical axe violations', async ({ page }) => {
      await open(page, p.path);
      await page.waitForLoadState('networkidle');
      const results = await new AxeBuilder({ page }).analyze();
      const bad = results.violations
        .filter((v) => v.impact === 'serious' || v.impact === 'critical')
        .map((v) => ({
          id: v.id,
          impact: v.impact,
          help: v.help,
          nodes: v.nodes.slice(0, 5).map((n) => n.target.join(' '))
        }));
      expect(bad).toEqual([]);
    });

    test('fits a 375px-wide screen without horizontal scroll', async ({ page }) => {
      await page.setViewportSize({ width: 375, height: 812 });
      await open(page, p.path);
      await page.waitForLoadState('networkidle');
      const { scrollWidth, innerWidth } = await page.evaluate(() => ({
        scrollWidth: document.scrollingElement!.scrollWidth,
        innerWidth: window.innerWidth
      }));
      expect(scrollWidth).toBeLessThanOrEqual(innerWidth);
    });
  });
}
