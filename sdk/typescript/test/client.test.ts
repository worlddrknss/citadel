import { describe, expect, it } from 'vitest';
import { Citadel, CitadelConnectionError, CitadelError, CitadelTimeoutError } from '../src/index.js';
import { backoffDelay, parseRetryAfter } from '../src/http.js';
import { client, json } from './helpers.js';

describe('Citadel client', () => {
  it('sends the bearer access key and builds query strings', async () => {
    const { c, calls } = client(() =>
      json(200, { project: 'web', env: 'prod', path: '/api', folders: [], items: [], shadowed: [], folderCounts: {} }),
    );
    const listing = await c.secrets.list({ project: 'web', env: 'prod', path: 'api' });
    expect(listing.path).toBe('/api');
    const req = calls[0]!;
    expect(req.method).toBe('GET');
    expect(req.url.pathname).toBe('/v1/secrets');
    expect(Object.fromEntries(req.url.searchParams)).toEqual({ project: 'web', env: 'prod', path: 'api' });
    expect(req.headers['authorization']).toBe('Bearer AKIATEST:s3cret');
    expect(req.init.redirect).toBe('manual');
  });

  it('puts, reads and deletes secrets with the documented shapes', async () => {
    const { c, calls } = client((req) => {
      if (req.method === 'POST') return json(200, { project: 'web', env: 'prod', path: '/', key: 'K', created: true });
      if (req.url.pathname === '/v1/secrets/value') return json(200, { key: 'K', versionId: 'v1', resolved: false, value: 'val' });
      if (req.url.pathname === '/v1/secrets/versions') return json(200, { key: 'K', versions: [{ versionId: 'v1', stages: ['AWSCURRENT'], createdAt: 'x', version: 1 }] });
      return json(200, { deleted: true, forced: true });
    });
    const put = await c.secrets.put({ project: 'web', env: 'prod', key: 'K', value: 'val' });
    expect(put.created).toBe(true);
    expect(calls[0]!.body).toEqual({ project: 'web', env: 'prod', path: '', key: 'K', value: 'val', kmsKeyId: '' });
    expect(calls[0]!.headers['content-type']).toBe('application/json');

    expect(await c.secrets.getValue({ project: 'web', env: 'prod', key: 'K', versionStage: 'AWSCURRENT' })).toBe('val');
    expect(calls[1]!.url.searchParams.get('versionStage')).toBe('AWSCURRENT');
    expect(calls[1]!.url.searchParams.has('resolve')).toBe(false);

    const versions = await c.secrets.versions({ project: 'web', env: 'prod', key: 'K' });
    expect(versions).toHaveLength(1);

    const del = await c.secrets.delete({ project: 'web', env: 'prod', key: 'K', force: true });
    expect(del.forced).toBe(true);
    expect(calls[3]!.method).toBe('DELETE');
    expect(calls[3]!.url.searchParams.get('force')).toBe('true');
  });

  it('base64-encodes KMS plaintext and decodes the result', async () => {
    const { c, calls } = client((req) => {
      if (req.url.pathname === '/v1/kms/encrypt') {
        return json(200, { keyId: 'k1', ciphertextBlob: 'Q0lQSEVS', encryptionAlgorithm: 'SYMMETRIC_DEFAULT' });
      }
      return json(200, { keyId: 'k1', plaintext: btoa('héllo'.normalize()), encryptionAlgorithm: 'SYMMETRIC_DEFAULT' });
    });
    const enc = await c.kms.encrypt({ keyId: 'alias/app', plaintext: 'hi', encryptionContext: { app: 'web' } });
    expect(enc.ciphertextBlob).toBe('Q0lQSEVS');
    expect(calls[0]!.body).toEqual({ keyId: 'alias/app', plaintext: 'aGk=', encryptionContext: { app: 'web' } });
    const dec = await c.kms.decrypt({ keyId: 'k1', ciphertextBlob: enc.ciphertextBlob });
    expect(dec.plaintext).toBeInstanceOf(Uint8Array);
    await c.kms.encrypt({ keyId: 'k1', plaintext: new Uint8Array([0, 255]) });
    expect((calls[2]!.body as { plaintext: string }).plaintext).toBe('AP8=');
  });

  it('wraps parameters, certificates and workload identity', async () => {
    const { c, calls } = client((req) => {
      switch (req.url.pathname) {
        case '/v1/parameters':
          return req.method === 'GET'
            ? json(200, { parameters: [{ name: '/a' }], limits: { nameMaxLength: 1, maxHierarchyLevels: 1 } })
            : json(200, { parameter: { name: '/a', version: 2 } });
        case '/v1/parameters/value':
          return json(200, { parameter: { name: '/a' }, value: 'v' });
        case '/v1/certificates':
          return json(200, { certificates: [{ id: 'c1' }] });
        case '/v1/certificates/issue/generate':
          return json(200, { certId: 'c2', certificatePem: 'C', chainPem: 'CH', privateKeyPem: 'K' });
        case '/v1/workload-identity/token':
          return json(200, { token: 'jwt', expiresAt: 'x', tokenType: 'id_token' });
      }
      return json(404, { error: 'not_found', message: 'nope' });
    });
    expect(await c.parameters.list()).toEqual([{ name: '/a' }]);
    expect((await c.parameters.put({ name: '/a', type: 'String', value: 'v', overwrite: true })).version).toBe(2);
    expect((await c.parameters.get('/a', { version: 1 })).value).toBe('v');
    expect(calls[2]!.url.searchParams.get('version')).toBe('1');
    expect(await c.certificates.list()).toEqual([{ id: 'c1' }]);
    expect((await c.certificates.issueGenerated({ caId: 'ca', commonName: 'x', keyAlgorithm: 'EC_prime256v1' })).privateKeyPem).toBe('K');
    const tok = await c.workloadIdentity.token({ clientId: 'ci', audience: 'aud' });
    expect(tok.token).toBe('jwt');
    expect(calls.at(-1)!.headers['authorization']).toBe('Bearer AKIATEST:s3cret');
  });

  it('throws CitadelError carrying the API error code', async () => {
    const { c } = client(() => json(409, { error: 'approval_required', message: 'changes require approval' }));
    const err = await c.secrets.put({ project: 'p', env: 'e', key: 'K', value: 'v' }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(CitadelError);
    expect(CitadelError.is(err, 'approval_required')).toBe(true);
    const e = err as CitadelError;
    expect(e.status).toBe(409);
    expect(e.code).toBe('approval_required');
    expect(e.message).toBe('changes require approval');
    expect(e.operation).toBe('POST /v1/secrets');
    expect(e.isNotFound).toBe(false);
  });

  it('falls back to a generic code for non-JSON errors', async () => {
    const { c } = client(() => new Response('<html>bad gateway</html>', { status: 404 }));
    const e = (await c.me().catch((x: unknown) => x)) as CitadelError;
    expect(e.code).toBe('http_404');
    expect(e.isNotFound).toBe(true);
  });

  it('retries 429 and 5xx with backoff, honouring Retry-After', async () => {
    let n = 0;
    const { c, calls } = client(() => {
      n++;
      if (n === 1) return json(429, { error: 'rate_limited', message: 'slow' }, { 'Retry-After': '0' });
      if (n === 2) return json(503, { error: 'unavailable', message: 'x' });
      return json(200, { projects: [] });
    });
    expect(await c.projects.list()).toEqual([]);
    expect(calls).toHaveLength(3);
  });

  it('gives up after maxRetries and reports attempts', async () => {
    const { c, calls } = client(() => json(500, { error: 'internal_error', message: 'boom' }), { maxRetries: 2 });
    const e = (await c.projects.list().catch((x: unknown) => x)) as CitadelError;
    expect(e.code).toBe('internal_error');
    expect(e.attempts).toBe(3);
    expect(calls).toHaveLength(3);
  });

  it('does not retry other 4xx', async () => {
    const { c, calls } = client(() => json(403, { error: 'forbidden', message: 'insufficient role' }));
    await expect(c.projects.list()).rejects.toMatchObject({ code: 'forbidden', status: 403 });
    expect(calls).toHaveLength(1);
  });

  it('retries network errors only for idempotent methods', async () => {
    let n = 0;
    const { c, calls } = client(() => {
      n++;
      if (n === 1) throw new TypeError('fetch failed');
      return json(200, { projects: [] });
    });
    await c.projects.list();
    expect(calls).toHaveLength(2);

    const post = client(() => {
      throw new TypeError('fetch failed');
    });
    const e = await post.c.secrets.put({ project: 'p', env: 'e', key: 'K', value: 'v' }).catch((x: unknown) => x);
    expect(e).toBeInstanceOf(CitadelConnectionError);
    expect(post.calls).toHaveLength(1);
  });

  it('times out each attempt with an AbortSignal', async () => {
    const hang = (_: unknown, init?: RequestInit) =>
      new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')));
      });
    const c = new Citadel({ baseUrl: 'https://citadel.test', timeoutMs: 20, maxRetries: 1, retryBaseDelayMs: 1, fetch: hang as typeof fetch });
    const e = (await c.projects.list().catch((x: unknown) => x)) as CitadelTimeoutError;
    expect(e).toBeInstanceOf(CitadelTimeoutError);
    expect(e.code).toBe('timeout');
    expect(e.attempts).toBe(2);
  });

  it('stops immediately when the caller aborts', async () => {
    const ac = new AbortController();
    let calls = 0;
    const c = new Citadel({
      baseUrl: 'https://citadel.test',
      fetch: ((_: unknown, init?: RequestInit) => {
        calls++;
        return new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')));
        });
      }) as typeof fetch,
    });
    const p = c.projects.list({ signal: ac.signal });
    ac.abort(new Error('user cancelled'));
    await expect(p).rejects.toThrow('user cancelled');
    expect(calls).toBe(1);
  });

  it('passes Next.js cache options to fetch', async () => {
    const { c, calls } = client(() => json(200, { projects: [] }));
    await c.projects.list({ next: { revalidate: 60, tags: ['secrets'] }, cache: 'force-cache' });
    expect(calls[0]!.init.next).toEqual({ revalidate: 60, tags: ['secrets'] });
    expect(calls[0]!.init.cache).toBe('force-cache');
  });

  it('validates its options', () => {
    expect(() => new Citadel({ baseUrl: '' })).toThrow(/baseUrl is required/);
    expect(() => new Citadel({ baseUrl: 'ftp://x' })).toThrow(/http/);
    expect(() => new Citadel({ baseUrl: 'https://x', accessKeyId: 'a' })).toThrow(/together/);
  });

  it('reads configuration from the environment', async () => {
    process.env.CITADEL_URL = 'https://env.test';
    process.env.CITADEL_ACCESS_KEY_ID = 'AKIAENV';
    process.env.CITADEL_SECRET_ACCESS_KEY = 'envsecret';
    try {
      let seen = '';
      const c = new Citadel({
        fetch: (async (input: RequestInfo | URL, init?: RequestInit) => {
          seen = `${String(input)} ${new Headers(init?.headers).get('authorization')}`;
          return json(200, { username: 'u' });
        }) as typeof fetch,
      });
      await c.me();
      expect(seen).toBe('https://env.test/v1/me Bearer AKIAENV:envsecret');
    } finally {
      delete process.env.CITADEL_URL;
      delete process.env.CITADEL_ACCESS_KEY_ID;
      delete process.env.CITADEL_SECRET_ACCESS_KEY;
    }
  });
});

describe('retry helpers', () => {
  it('parses Retry-After seconds and dates', () => {
    expect(parseRetryAfter('2')).toBe(2000);
    expect(parseRetryAfter(null)).toBeUndefined();
    expect(parseRetryAfter('garbage')).toBeUndefined();
    const now = Date.parse('2026-01-01T00:00:00Z');
    expect(parseRetryAfter('Thu, 01 Jan 2026 00:00:03 GMT', now)).toBe(3000);
  });

  it('grows the backoff exponentially with jitter and a cap', () => {
    const retry = { maxRetries: 5, baseDelayMs: 100, maxDelayMs: 1000 };
    expect(backoffDelay(1, retry, () => 0)).toBe(50);
    expect(backoffDelay(1, retry, () => 0.999)).toBeLessThanOrEqual(100);
    expect(backoffDelay(3, retry, () => 0)).toBe(200);
    expect(backoffDelay(10, retry, () => 0.999)).toBeLessThanOrEqual(1000);
  });
});
