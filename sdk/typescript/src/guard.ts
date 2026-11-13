/** Message used whenever the SDK is loaded where secrets could leak. */
export const SERVER_ONLY_MESSAGE =
  '@worlddrknss/citadel is server-only: it holds a Citadel access key and returns secret values, ' +
  'which must never reach a browser bundle. Import it only from server code (Next.js route handlers, ' +
  'server components, server actions, middleware, or Node scripts), and add `import "server-only"` ' +
  'to the modules that use it so a client import fails the build.';

/**
 * Reports whether g looks like a browser main thread: a DOM `window` and
 * `document` and no Node.js. Edge runtimes (Vercel Edge, Cloudflare Workers,
 * Next.js middleware) have neither `window` nor `document`, so they pass;
 * jsdom-style test environments run on Node, so they pass too.
 */
export function isBrowserRuntime(g: Record<string, unknown> = globalThis as unknown as Record<string, unknown>): boolean {
  const hasDOM = typeof g['window'] !== 'undefined' && typeof g['document'] !== 'undefined';
  if (!hasDOM) return false;
  const proc = g['process'] as { versions?: { node?: unknown } } | undefined;
  const onNode = typeof proc?.versions?.node === 'string';
  return !onNode;
}

/**
 * Throws when called in a browser. Runs when the SDK module loads and again
 * in the Citadel constructor, so a client bundle that somehow skipped the
 * package's "browser" export still cannot construct a client.
 */
export function assertServerRuntime(g?: Record<string, unknown>): void {
  if (isBrowserRuntime(g)) {
    try {
      console.error(SERVER_ONLY_MESSAGE);
    } catch {
      // console may be unavailable; the throw below is what matters.
    }
    throw new Error(SERVER_ONLY_MESSAGE);
  }
}
