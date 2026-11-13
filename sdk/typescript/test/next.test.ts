import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { clearSecretsCache, loadSecrets } from '../src/index.js';
import { clock } from '../src/next.js';
import { client, json, type Recorded } from './helpers.js';

let now = 1_000_000;
const realNow = clock.now;

beforeEach(() => {
  clearSecretsCache();
  clock.now = () => now;
});

afterEach(() => {
  clock.now = realNow;
});

function folder(values: Record<string, string>, extra: { deleted?: string[] } = {}) {
  let reads = 0;
  const handler = (req: Recorded) => {
    if (req.url.pathname === '/v1/secrets') {
      const keys = [...Object.keys(values), ...(extra.deleted ?? [])];
      return json(200, {
        project: 'web',
        env: 'prod',
        path: '/',
        folders: ['nested'],
        shadowed: [],
        folderCounts: {},
        items: keys.map((key) => ({ key, project: 'web', env: 'prod', path: '/', arn: '', updatedAt: '', tags: [], ...(extra.deleted?.includes(key) ? { deletionDate: 'x' } : {}) })),
      });
    }
    reads++;
    const key = req.url.searchParams.get('key')!;
    return json(200, { key, versionId: 'v', resolved: false, value: values[key] });
  };
  return { handler, reads: () => reads };
}

describe('loadSecrets', () => {
  it('returns the folder as a record, skipping deleted items and filtering by prefix', async () => {
    const f = folder({ DB_URL: 'pg', API_TOKEN: 't', DB_USER: 'u' }, { deleted: ['DB_OLD'] });
    const { c, calls } = client(f.handler);
    expect(await loadSecrets({ client: c, project: 'web', env: 'prod' })).toEqual({ DB_URL: 'pg', API_TOKEN: 't', DB_USER: 'u' });
    clearSecretsCache();
    expect(await loadSecrets({ client: c, project: 'web', env: 'prod', prefix: 'DB_' })).toEqual({ DB_URL: 'pg', DB_USER: 'u' });
    expect(calls.some((r) => r.url.searchParams.get('key') === 'DB_OLD')).toBe(false);
  });

  it('caches within the TTL and shares concurrent loads', async () => {
    const f = folder({ A: '1', B: '2' });
    const { c, calls } = client(f.handler);
    const [x, y] = await Promise.all([
      loadSecrets({ client: c, project: 'web', env: 'prod', ttl: 1000 }),
      loadSecrets({ client: c, project: 'web', env: 'prod', ttl: 1000 }),
    ]);
    expect(x).toEqual(y);
    expect(calls).toHaveLength(3);
    now += 500;
    await loadSecrets({ client: c, project: 'web', env: 'prod', ttl: 1000 });
    expect(calls).toHaveLength(3);
  });

  it('serves stale values while revalidating in the background', async () => {
    const values: Record<string, string> = { A: 'old' };
    const f = folder(values);
    const { c } = client(f.handler);
    const opts = { client: c, project: 'web', env: 'prod', ttl: 1000, staleWhileRevalidate: 5000 };
    expect(await loadSecrets(opts)).toEqual({ A: 'old' });
    values.A = 'new';
    now += 2000;
    expect(await loadSecrets(opts)).toEqual({ A: 'old' });
    await new Promise((r) => setTimeout(r, 10));
    expect(await loadSecrets(opts)).toEqual({ A: 'new' });
    // Past ttl + swr the caller waits for fresh data.
    values.A = 'newest';
    now += 10_000;
    expect(await loadSecrets(opts)).toEqual({ A: 'newest' });
  });

  it('keeps serving stale data when a background refresh fails', async () => {
    let fail = false;
    const f = folder({ A: '1' });
    const { c } = client((req) => (fail ? json(500, { error: 'internal_error', message: 'x' }) : f.handler(req)), { maxRetries: 0 });
    const opts = { client: c, project: 'web', env: 'prod', ttl: 1000, staleWhileRevalidate: 5000 };
    await loadSecrets(opts);
    fail = true;
    now += 2000;
    expect(await loadSecrets(opts)).toEqual({ A: '1' });
    await new Promise((r) => setTimeout(r, 10));
    expect(await loadSecrets(opts)).toEqual({ A: '1' });
    now += 10_000;
    await expect(loadSecrets(opts)).rejects.toMatchObject({ code: 'internal_error' });
  });

  it('does not cache with ttl 0 and passes revalidate to fetch', async () => {
    const f = folder({ A: '1' });
    const { c, calls } = client(f.handler);
    await loadSecrets({ client: c, project: 'web', env: 'prod', ttl: 0, revalidate: 120, tags: ['citadel'] });
    await loadSecrets({ client: c, project: 'web', env: 'prod', ttl: 0 });
    expect(calls).toHaveLength(4);
    expect(calls[0]!.init.next).toEqual({ revalidate: 120, tags: ['citadel'] });
    expect(calls[1]!.init.next).toEqual({ revalidate: 120, tags: ['citadel'] });
    expect(calls[2]!.init.next).toBeUndefined();
  });

  it('injects into process.env without overwriting', async () => {
    const f = folder({ CITADEL_T_NEW: 'from-citadel', CITADEL_T_SET: 'from-citadel' });
    const { c } = client(f.handler);
    process.env.CITADEL_T_SET = 'already';
    try {
      await loadSecrets({ client: c, project: 'web', env: 'prod', inject: true });
      expect(process.env.CITADEL_T_NEW).toBe('from-citadel');
      expect(process.env.CITADEL_T_SET).toBe('already');
    } finally {
      delete process.env.CITADEL_T_NEW;
      delete process.env.CITADEL_T_SET;
    }
  });

  it('limits concurrency of value reads', async () => {
    const values = Object.fromEntries(Array.from({ length: 12 }, (_, i) => [`K${i}`, String(i)]));
    let inFlight = 0;
    let peak = 0;
    const f = folder(values);
    const { c } = client(async (req) => {
      if (req.url.pathname === '/v1/secrets/value') {
        inFlight++;
        peak = Math.max(peak, inFlight);
        await new Promise((r) => setTimeout(r, 2));
        inFlight--;
      }
      return f.handler(req);
    });
    const out = await loadSecrets({ client: c, project: 'web', env: 'prod', concurrency: 3 });
    expect(Object.keys(out)).toEqual(Object.keys(values));
    expect(peak).toBeLessThanOrEqual(3);
  });
});
