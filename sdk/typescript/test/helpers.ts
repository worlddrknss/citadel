import { Citadel, type CitadelOptions } from '../src/index.js';

export interface Recorded {
  url: URL;
  method: string;
  headers: Record<string, string>;
  body: unknown;
  init: RequestInit & { next?: unknown };
}

export type Handler = (req: Recorded) => Response | Promise<Response>;

export function json(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', ...headers } });
}

/** A fetch mock that records requests and answers from handler. */
export function mockFetch(handler: Handler) {
  const calls: Recorded[] = [];
  const fetchFn = (async (input: RequestInfo | URL, init: RequestInit = {}) => {
    const headers: Record<string, string> = {};
    new Headers(init.headers).forEach((v, k) => (headers[k] = v));
    const rec: Recorded = {
      url: new URL(String(input)),
      method: init.method ?? 'GET',
      headers,
      body: typeof init.body === 'string' ? JSON.parse(init.body) : undefined,
      init: init as Recorded['init'],
    };
    calls.push(rec);
    return handler(rec);
  }) as typeof fetch;
  return { fetch: fetchFn, calls };
}

export function client(handler: Handler, opts: CitadelOptions = {}) {
  const m = mockFetch(handler);
  const c = new Citadel({
    baseUrl: 'https://citadel.test/',
    accessKeyId: 'AKIATEST',
    secretAccessKey: 's3cret',
    retryBaseDelayMs: 1,
    retryMaxDelayMs: 5,
    fetch: m.fetch,
    ...opts,
  });
  return { c, calls: m.calls };
}
