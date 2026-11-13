// Helpers for page-local API modules (JSON calls go through req() in
// #lib/api). isNotImplemented() lets pages fall back to older endpoints on
// servers that don't have a newer one yet: unknown /v1 paths currently get
// redirected to the SPA's HTML shell, so req() fails parsing JSON
// (SyntaxError) or the server answers 404/405/501. rawRequest() is only for
// file downloads, where the body isn't JSON.

import { ApiError } from '#lib/api.ts';
import { session } from '#lib/stores/session.svelte.ts';

const TIMEOUT_MS = 30_000;

export function isNotImplemented(e: unknown): boolean {
  if (e instanceof SyntaxError) return true;
  return e instanceof ApiError && (e.code === 'not_implemented' || e.status === 404 || e.status === 405 || e.status === 501);
}

export async function rawRequest(path: string, init: RequestInit = {}): Promise<Response> {
  const timeout = new AbortController();
  const timer = setTimeout(() => timeout.abort(), TIMEOUT_MS);
  const signal = init.signal ? AbortSignal.any([init.signal, timeout.signal]) : timeout.signal;
  let res: Response;
  try {
    res = await fetch(path, {
      ...init,
      signal,
      credentials: 'same-origin',
      headers: {
        ...(init.body ? { 'Content-Type': 'application/json' } : {}),
        'X-Citadel-Request': '1',
        ...(init.headers ?? {})
      }
    });
  } catch (e) {
    if (timeout.signal.aborted) throw new ApiError(0, 'timeout', 'The server took too long to respond.');
    if (init.signal?.aborted) throw e;
    throw new ApiError(0, 'network', "Can't reach the Citadel server. Check your connection.");
  } finally {
    clearTimeout(timer);
  }
  const type = res.headers.get('content-type') ?? '';
  if (res.redirected || type.includes('text/html')) {
    throw new ApiError(404, 'not_implemented', 'This server does not support that feature yet.');
  }
  if (!res.ok) {
    let code = 'error';
    let message = res.statusText || 'Request failed';
    try {
      const body = await res.json();
      code = body.error ?? code;
      message = body.message ?? message;
    } catch {
      /* non-JSON error */
    }
    // Let the session store notice an expired session (it flips the console
    // back to the sign-in screen when /v1/me also says 401).
    if (res.status === 401 && session.status === 'signed-in') void session.refresh();
    throw new ApiError(res.status, code, message);
  }
  return res;
}

export const qs = (params: Record<string, string | number | undefined | null>) => {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== null && v !== '') p.set(k, String(v));
  const s = p.toString();
  return s ? `?${s}` : '';
};

/** Saves a Blob as a file via a temporary object URL. */
export function saveBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
