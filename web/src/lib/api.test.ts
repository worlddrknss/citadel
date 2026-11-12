import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiError, errorMessage, onUnauthorized, req } from './api';

const json = (status: number, body: unknown, statusText = '') =>
  new Response(body === undefined ? null : JSON.stringify(body), {
    status,
    statusText,
    headers: { 'Content-Type': 'application/json' }
  });

let fetchMock: ReturnType<typeof vi.fn>;
beforeEach(() => {
  fetchMock = vi.fn();
  vi.stubGlobal('fetch', fetchMock);
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

async function caught(p: Promise<unknown>): Promise<ApiError> {
  try {
    await p;
  } catch (e) {
    return e as ApiError;
  }
  throw new Error('expected a rejection');
}

describe('req', () => {
  it('sends JSON and the X-Citadel-Request header with same-origin credentials', async () => {
    fetchMock.mockResolvedValue(json(200, { ok: true }));
    await expect(req('/v1/thing', { method: 'POST', body: '{}', headers: { 'X-Extra': 'y' } })).resolves.toEqual({ ok: true });
    const [path, init] = fetchMock.mock.calls[0];
    expect(path).toBe('/v1/thing');
    expect(init.method).toBe('POST');
    expect(init.credentials).toBe('same-origin');
    expect(init.headers).toMatchObject({
      'Content-Type': 'application/json',
      'X-Citadel-Request': '1',
      'X-Extra': 'y'
    });
    expect(init.signal).toBeInstanceOf(AbortSignal);
  });

  it('returns undefined for 204', async () => {
    fetchMock.mockResolvedValue(new Response(null, { status: 204 }));
    await expect(req('/v1/x')).resolves.toBeUndefined();
  });

  it('turns an error body into ApiError(status, code, message)', async () => {
    fetchMock.mockResolvedValue(json(409, { error: 'conflict', message: 'Already exists.' }));
    const e = await caught(req('/v1/x'));
    expect(e).toBeInstanceOf(ApiError);
    expect([e.status, e.code, e.message]).toEqual([409, 'conflict', 'Already exists.']);
  });

  it('uses statusText for a non-JSON error body', async () => {
    fetchMock.mockResolvedValue(new Response('<html>', { status: 502, statusText: 'Bad Gateway' }));
    const e = await caught(req('/v1/x'));
    expect([e.status, e.code, e.message]).toEqual([502, 'error', 'Bad Gateway']);
  });

  it('explains a bare 404 as a missing feature, but keeps a coded 404 message', async () => {
    fetchMock.mockResolvedValueOnce(new Response('not found', { status: 404, statusText: 'Not Found' }));
    expect((await caught(req('/v1/new-thing'))).message).toBe('This feature is not available on this server yet.');
    fetchMock.mockResolvedValueOnce(json(404, { error: 'not_found', message: 'No such secret.' }));
    expect((await caught(req('/v1/secrets'))).message).toBe('No such secret.');
  });

  it('maps a fetch failure to a network ApiError', async () => {
    fetchMock.mockRejectedValue(new TypeError('Failed to fetch'));
    const e = await caught(req('/v1/x'));
    expect([e.status, e.code]).toEqual([0, 'network']);
    expect(e.message).toMatch(/reach the Citadel server/);
  });

  it('times out after 30 s', async () => {
    vi.useFakeTimers();
    fetchMock.mockImplementation(
      (_: string, init: RequestInit) =>
        new Promise((_, reject) => {
          init.signal!.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')));
        })
    );
    const p = caught(req('/v1/slow'));
    await vi.advanceTimersByTimeAsync(29_999);
    expect(fetchMock.mock.calls[0][1].signal.aborted).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    const e = await p;
    expect([e.status, e.code]).toEqual([0, 'timeout']);
  });

  it('rethrows the caller’s own abort untouched', async () => {
    const ctrl = new AbortController();
    fetchMock.mockImplementation(
      (_: string, init: RequestInit) =>
        new Promise((_, reject) => {
          init.signal!.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')));
        })
    );
    const p = caught(req('/v1/x', { signal: ctrl.signal }));
    ctrl.abort();
    const e = (await p) as unknown as DOMException;
    expect(e).not.toBeInstanceOf(ApiError);
    expect(e.name).toBe('AbortError');
    expect(errorMessage(e, 'fallback')).toBe('fallback');
  });

  it('tells 401 listeners, except for the login call itself', async () => {
    const listener = vi.fn();
    const off = onUnauthorized(listener);
    fetchMock.mockResolvedValue(json(401, { error: 'unauthorized', message: 'Session expired.' }));
    expect((await caught(req('/v1/secrets'))).status).toBe(401);
    expect(listener).toHaveBeenCalledTimes(1);
    await caught(req('/v1/login', { method: 'POST' }));
    expect(listener).toHaveBeenCalledTimes(1);
    off();
    await caught(req('/v1/secrets'));
    expect(listener).toHaveBeenCalledTimes(1);
  });

  it('does not call 401 listeners for 403', async () => {
    const listener = vi.fn();
    const off = onUnauthorized(listener);
    fetchMock.mockResolvedValue(json(403, { error: 'forbidden', message: 'No.' }));
    await caught(req('/v1/x'));
    expect(listener).not.toHaveBeenCalled();
    off();
  });
});

describe('errorMessage', () => {
  it('prefers the error message, else the fallback', () => {
    expect(errorMessage(new ApiError(500, 'x', 'Boom'))).toBe('Boom');
    expect(errorMessage(new ApiError(500, 'x', ''), 'fb')).toBe('fb');
    expect(errorMessage(new Error('plain'))).toBe('plain');
    expect(errorMessage('string', 'fb')).toBe('fb');
    expect(errorMessage(undefined)).toBe('Something went wrong.');
  });
});
