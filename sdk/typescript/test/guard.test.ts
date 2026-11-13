import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { assertServerRuntime, isBrowserRuntime, SERVER_ONLY_MESSAGE } from '../src/guard.js';

describe('server-only guard', () => {
  it('detects a browser main thread', () => {
    expect(isBrowserRuntime({ window: {}, document: {} })).toBe(true);
    expect(() => assertServerRuntime({ window: {}, document: {} })).toThrow(SERVER_ONLY_MESSAGE);
  });

  it('allows Node, edge runtimes and jsdom on Node', () => {
    expect(isBrowserRuntime({ process: { versions: { node: '22.0.0' } } })).toBe(false);
    // Vercel Edge / Cloudflare Workers / Next.js middleware: no window or document.
    expect(isBrowserRuntime({ self: {}, fetch: () => {} })).toBe(false);
    expect(isBrowserRuntime({ window: {}, document: {}, process: { versions: { node: '22.0.0' } } })).toBe(false);
    expect(() => assertServerRuntime()).not.toThrow();
  });

  it('ships a browser entry that throws on import', async () => {
    await expect(import('../src/browser.js')).rejects.toThrow(/server-only/);
  });

  it('routes browser bundles to the throwing entry', async () => {
    const raw = readFileSync(new URL('../package.json', import.meta.url), 'utf8');
    const pkg = JSON.parse(raw) as { exports: Record<string, Record<string, unknown>> };
    const conditions = Object.keys(pkg.exports['.']!);
    // Server conditions must come before "browser": Next.js edge bundles match
    // both "edge-light" and "browser", and the first listed key wins.
    expect(conditions.indexOf('edge-light')).toBeLessThan(conditions.indexOf('browser'));
    expect(conditions.indexOf('node')).toBeLessThan(conditions.indexOf('browser'));
    expect(JSON.stringify(pkg.exports['.']!['browser'])).toContain('browser.js');
  });
});
