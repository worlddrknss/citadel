import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// The stores are module singletons; each test imports fresh copies.
beforeEach(() => {
  vi.resetModules();
});
afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe('toast', () => {
  it('each toast keeps its own timer, so a newer one is not cleared early', async () => {
    vi.useFakeTimers();
    const { toast } = await import('./toast.svelte');
    toast.success('first'); // 4 s
    vi.advanceTimersByTime(3000);
    toast.error('second'); // 8 s from now
    expect(toast.items.map((t) => t.message)).toEqual(['first', 'second']);
    vi.advanceTimersByTime(1000); // first expires
    expect(toast.items.map((t) => t.message)).toEqual(['second']);
    vi.advanceTimersByTime(6999);
    expect(toast.items.map((t) => t.message)).toEqual(['second']);
    vi.advanceTimersByTime(1);
    expect(toast.items).toEqual([]);
  });

  it('uses per-kind durations', async () => {
    vi.useFakeTimers();
    const { toast } = await import('./toast.svelte');
    toast.success('s');
    toast.info('i');
    toast.error('e');
    vi.advanceTimersByTime(4000);
    expect(toast.items.map((t) => t.kind)).toEqual(['info', 'error']);
    vi.advanceTimersByTime(1000);
    expect(toast.items.map((t) => t.kind)).toEqual(['error']);
    vi.advanceTimersByTime(3000);
    expect(toast.items).toEqual([]);
  });

  it('dismiss removes one toast and cancels its timer', async () => {
    vi.useFakeTimers();
    const { toast } = await import('./toast.svelte');
    const a = toast.info('a');
    toast.info('b');
    toast.dismiss(a);
    expect(toast.items.map((t) => t.message)).toEqual(['b']);
    expect(vi.getTimerCount()).toBe(1);
  });

  it('keeps at most five', async () => {
    vi.useFakeTimers();
    const { toast } = await import('./toast.svelte');
    for (let i = 1; i <= 7; i++) toast.info(`m${i}`);
    expect(toast.items.map((t) => t.message)).toEqual(['m3', 'm4', 'm5', 'm6', 'm7']);
  });

  it('error() accepts strings, errors and a fallback', async () => {
    const { toast } = await import('./toast.svelte');
    const { ApiError } = await import('$lib/api');
    toast.error('plain');
    toast.error(new ApiError(500, 'x', 'from api'));
    toast.error({}, 'fallback');
    expect(toast.items.map((t) => t.message)).toEqual(['plain', 'from api', 'fallback']);
  });
});

describe('confirm', () => {
  it('resolves with the settled answer and clears the pending dialog', async () => {
    const { confirm, confirmState } = await import('./confirm.svelte');
    const p = confirm({ title: 'Delete?', message: 'Sure?', danger: true });
    expect(confirmState.pending).toMatchObject({ title: 'Delete?', danger: true });
    confirmState.settle(true);
    await expect(p).resolves.toBe(true);
    expect(confirmState.pending).toBeNull();

    const q = confirm({ title: 'Again?', message: '' });
    confirmState.settle(false);
    await expect(q).resolves.toBe(false);
  });

  it('a new confirmation supersedes (declines) the open one', async () => {
    const { confirm, confirmState } = await import('./confirm.svelte');
    const first = confirm({ title: 'One', message: '' });
    const second = confirm({ title: 'Two', message: '' });
    await expect(first).resolves.toBe(false);
    expect(confirmState.pending?.title).toBe('Two');
    confirmState.settle(true);
    await expect(second).resolves.toBe(true);
  });

  it('settle with nothing pending is a no-op', async () => {
    const { confirmState } = await import('./confirm.svelte');
    expect(() => confirmState.settle(true)).not.toThrow();
  });
});

describe('session', () => {
  const me = { username: 'alice', displayName: 'Alice', role: 'editor', accountId: '000000000000', accounts: ['000000000000'] };
  const json = (status: number, body: unknown) =>
    new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

  async function load(fetchImpl: (path: string, init?: RequestInit) => Promise<Response>) {
    vi.stubGlobal('fetch', vi.fn(fetchImpl));
    const { session } = await import('./session.svelte');
    const api = await import('$lib/api');
    return { session, api };
  }

  it('starts loading, then signs in from /v1/me', async () => {
    const { session } = await load(async () => json(200, me));
    expect(session.status).toBe('loading');
    await session.refresh();
    expect(session.status).toBe('signed-in');
    expect(session.me?.username).toBe('alice');
    expect(session.expired).toBe(false);
  });

  it('401 from /v1/me is signed out (a fresh visit, not "expired")', async () => {
    const { session } = await load(async () => json(401, { error: 'unauthorized', message: 'Sign in.' }));
    await session.refresh();
    expect(session.status).toBe('signed-out');
    expect(session.expired).toBe(false);
    expect(session.me).toBeNull();
  });

  it('a network failure or 5xx is unreachable, not signed out', async () => {
    const { session } = await load(async () => {
      throw new TypeError('Failed to fetch');
    });
    await session.refresh();
    expect(session.status).toBe('unreachable');

    vi.resetModules();
    const again = await load(async () => json(503, { error: 'unavailable', message: 'Down.' }));
    await again.session.refresh();
    expect(again.session.status).toBe('unreachable');
  });

  it('a 401 on any call mid-session signs out and marks the session expired', async () => {
    let authed = true;
    const { session, api } = await load(async (path) =>
      authed || path === '/v1/me' ? json(200, me) : json(401, { error: 'unauthorized', message: 'Expired.' })
    );
    await session.refresh();
    authed = false;
    await expect(api.api.projects()).rejects.toMatchObject({ status: 401 });
    expect(session.status).toBe('signed-out');
    expect(session.expired).toBe(true);
    expect(session.me).toBeNull();
    // Signing in again clears the notice.
    await session.refresh();
    expect(session.expired).toBe(false);
  });

  it('a 401 while not signed in does not claim the session expired', async () => {
    const { session, api } = await load(async () => json(401, { error: 'unauthorized', message: 'x' }));
    await api.api.projects().catch(() => {});
    expect(session.status).toBe('signed-out');
    expect(session.expired).toBe(false);
  });

  it('signOut posts /v1/logout and signs out even if that fails', async () => {
    const calls: string[] = [];
    const { session } = await load(async (path) => {
      calls.push(path);
      if (path === '/v1/logout') throw new TypeError('offline');
      return json(200, me);
    });
    await session.refresh();
    await session.signOut();
    expect(calls).toContain('/v1/logout');
    expect(session.status).toBe('signed-out');
    expect(session.expired).toBe(false);
  });

  it('can() compares role rank', async () => {
    const { session } = await load(async () => json(200, me));
    expect(session.can('viewer')).toBe(true); // signed out counts as viewer
    expect(session.can('editor')).toBe(false);
    await session.refresh();
    expect(session.can('editor')).toBe(true);
    expect(session.can('admin')).toBe(false);
  });
});
