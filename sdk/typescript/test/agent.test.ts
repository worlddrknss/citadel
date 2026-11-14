import { readFileSync } from 'node:fs';
import { inspect } from 'node:util';
import { afterEach, describe, expect, it } from 'vitest';
import { AgentHttpResult, CitadelAgent, CitadelError, VERSION, type CitadelAgentOptions } from '../src/index.js';
import { client, json, mockFetch, type Handler } from './helpers.js';

const TOKEN = 'cagt_agt_test_0123456789abcdef';

function agent(handler: Handler, opts: CitadelAgentOptions = {}) {
  const m = mockFetch(handler);
  const a = new CitadelAgent({
    baseUrl: 'https://citadel.test/',
    token: TOKEN,
    retryBaseDelayMs: 1,
    retryMaxDelayMs: 5,
    fetch: m.fetch,
    ...opts,
  });
  return { a, calls: m.calls };
}

const brokered = (over: Record<string, unknown> = {}) => ({
  status: 200,
  headers: { 'content-type': 'application/json' },
  body: '{"login":"octocat"}',
  bodyEncoding: 'text',
  truncated: false,
  redacted: false,
  ...over,
});

describe('CitadelAgent', () => {
  afterEach(() => {
    delete process.env.CITADEL_AGENT_TOKEN;
    delete process.env.CITADEL_URL;
  });

  it('sends the agent token, task and agent headers and a User-Agent', async () => {
    const { a, calls } = agent(() => json(200, { agentId: 'agt_1', name: 'coder', owner: 'alice', accountId: '1', status: 'active', authMethod: 'token' }), {
      taskId: 'run-7',
      agentId: 'agt_1',
    });
    const me = await a.whoami();
    expect(me.agentId).toBe('agt_1');
    const req = calls[0]!;
    expect(req.url.toString()).toBe('https://citadel.test/v1/agent/whoami');
    expect(req.headers['authorization']).toBe(`Bearer ${TOKEN}`);
    expect(req.headers['x-citadel-task-id']).toBe('run-7');
    expect(req.headers['x-citadel-agent-id']).toBe('agt_1');
    expect(req.headers['user-agent']).toBe(`citadel-ts/${VERSION}`);
  });

  it('reads the token and URL from the environment and never shows the token', () => {
    process.env.CITADEL_AGENT_TOKEN = TOKEN;
    process.env.CITADEL_URL = 'https://env.citadel.test';
    const a = new CitadelAgent({ fetch: mockFetch(() => json(200, {})).fetch });
    expect(a.baseUrl).toBe('https://env.citadel.test');
    expect(inspect(a, { depth: 10, showHidden: true })).not.toContain(TOKEN);
    expect(JSON.stringify(a)).not.toContain(TOKEN);
  });

  it('validates its options without echoing the token', () => {
    expect(() => new CitadelAgent({ baseUrl: 'https://c.test' })).toThrow(/token is required/);
    let msg = '';
    try {
      new CitadelAgent({ baseUrl: 'https://c.test', token: 'cagt_bad\ntoken' });
    } catch (e) {
      msg = (e as Error).message;
    }
    expect(msg).toMatch(/whitespace/);
    expect(msg).not.toContain('cagt_bad');
    expect(() => new CitadelAgent({ baseUrl: 'ftp://c.test', token: TOKEN })).toThrow(/http\(s\)/);
  });

  it('wraps every Agent API operation', async () => {
    const { a, calls } = agent((req) => {
      switch (req.url.pathname) {
        case '/v1/agent/credentials':
          return json(200, { credentials: [{ name: 'gh', usable: true }] });
        case '/v1/agent/credentials/reveal':
          return json(200, { credential: 'gh', kind: 'raw', value: 'v', leaseId: 'lease_1', leaseExpiresAt: '2026-01-01T00:00:00Z' });
        case '/v1/agent/totp':
          return json(200, { credential: 'site', code: '123456', secondsRemaining: 10 });
        case '/v1/agent/login':
          return json(200, { credential: 'site', username: 'u', password: 'p', urlPattern: 'https://example.com' });
        case '/v1/agent/access-requests':
          return json(201, { requestId: 'areq_1', status: 'pending' });
        case '/v1/agent/access-requests/areq%2F1':
          return json(200, { requestId: 'areq/1', status: 'approved' });
        case '/v1/agent/leases':
          return json(200, { leases: [{ leaseId: 'lease_1' }] });
        default:
          return json(404, { error: 'not_found', message: req.url.pathname });
      }
    });
    expect((await a.listCredentials())[0]!.name).toBe('gh');
    const revealed = await a.reveal('gh');
    expect(revealed.leaseId).toBe('lease_1');
    expect(revealed.leaseExpiresAt).toBe('2026-01-01T00:00:00Z');
    await a.reveal({ credential: 'gh', taskId: 't' });
    expect((await a.getTotpCode('site')).code).toBe('123456');
    expect((await a.getLogin({ credential: 'site', url: 'https://example.com/login' })).username).toBe('u');
    expect((await a.requestAccess({ credential: 'gh', reason: 'deploy', actions: ['reveal'], durationSeconds: 900 })).requestId).toBe('areq_1');
    expect((await a.getAccessRequest('areq/1')).status).toBe('approved');
    expect(await a.listLeases({ credential: 'gh' })).toHaveLength(1);

    const sent = calls.map((c) => `${c.method} ${c.url.pathname}${c.url.search}`);
    expect(sent).toEqual([
      'GET /v1/agent/credentials',
      'POST /v1/agent/credentials/reveal',
      'POST /v1/agent/credentials/reveal',
      'POST /v1/agent/totp',
      'POST /v1/agent/login',
      'POST /v1/agent/access-requests',
      'GET /v1/agent/access-requests/areq%2F1',
      'GET /v1/agent/leases?credential=gh',
    ]);
    expect(calls[1]!.body).toEqual({ credential: 'gh' });
    expect(calls[2]!.body).toEqual({ credential: 'gh', taskId: 't' });
    expect(calls[4]!.body).toEqual({ credential: 'site', url: 'https://example.com/login' });
    expect(calls[5]!.body).toEqual({ credential: 'gh', reason: 'deploy', actions: ['reveal'], durationSeconds: 900 });
  });

  it('encodes brokered request bodies and decodes responses', async () => {
    const { a, calls } = agent((req) => {
      const body = req.body as { url: string };
      if (body.url.endsWith('/bin')) return json(200, brokered({ body: 'AP8=', bodyEncoding: 'base64', redacted: true }));
      return json(200, brokered());
    });

    const res = await a.http({ credential: 'gh', url: 'https://api.github.com/user' });
    expect(res).toBeInstanceOf(AgentHttpResult);
    expect(res.ok).toBe(true);
    expect(res.json<{ login: string }>().login).toBe('octocat');
    expect(calls[0]!.body).toEqual({ credential: 'gh', method: 'GET', url: 'https://api.github.com/user', bodyEncoding: 'text' });

    await a.http({ credential: 'gh', method: 'POST', url: 'https://api.github.com/x', json: { a: 1 }, taskId: 'task-9' });
    expect(calls[1]!.body).toEqual({
      credential: 'gh',
      method: 'POST',
      url: 'https://api.github.com/x',
      body: '{"a":1}',
      bodyEncoding: 'text',
      headers: { 'Content-Type': 'application/json' },
      taskId: 'task-9',
    });

    await a.http({ credential: 'gh', method: 'POST', url: 'https://api.github.com/x', json: [1], headers: { 'content-type': 'application/vnd.x+json' } });
    expect((calls[2]!.body as { headers: unknown }).headers).toEqual({ 'content-type': 'application/vnd.x+json' });

    const bin = await a.http({ credential: 'gh', method: 'PUT', url: 'https://up.test/bin', body: new Uint8Array([0, 255]) });
    expect(calls[3]!.body).toMatchObject({ body: 'AP8=', bodyEncoding: 'base64' });
    expect(Array.from(bin.bytes())).toEqual([0, 255]);
    expect(bin.redacted).toBe(true);

    await a.http({ credential: 'gh', method: 'POST', url: 'https://up.test/t', body: 'plain' });
    expect(calls[4]!.body).toMatchObject({ body: 'plain', bodyEncoding: 'text' });

    await expect(a.http({ credential: 'gh', url: 'https://x.test', body: 'a', json: 1 })).rejects.toThrow(/body or json/);
  });

  it('treats an upstream error status as a successful brokered call', async () => {
    const { a } = agent(() => json(200, brokered({ status: 404, body: 'nope', headers: {} })));
    const res = await a.http({ credential: 'gh', url: 'https://api.github.com/missing' });
    expect(res.ok).toBe(false);
    expect(res.status).toBe(404);
    expect(res.text()).toBe('nope');
  });

  it('exposes reason and requestId on errors and waits for approval', async () => {
    let polls = 0;
    const { a } = agent((req) => {
      if (req.url.pathname === '/v1/agent/http') {
        return json(403, { error: 'approval_required', message: 'a person must approve this use', reason: 'approval_required', requestId: 'areq_9' });
      }
      polls++;
      return json(200, { requestId: 'areq_9', status: polls < 3 ? 'pending' : 'approved', lease: { leaseId: 'lease_9' } });
    });
    const err = (await a.http({ credential: 'gated', url: 'https://x.test' }).catch((e: unknown) => e)) as CitadelError;
    expect(CitadelError.is(err, 'approval_required')).toBe(true);
    expect(err.isApprovalRequired).toBe(true);
    expect(err.reason).toBe('approval_required');
    expect(err.requestId).toBe('areq_9');
    expect(err.attempts).toBe(1);

    const decided = await a.waitForAccess(err.requestId!, { intervalMs: 1 });
    expect(decided.status).toBe('approved');
    expect(polls).toBe(3);
  });

  it('stops waiting for approval when aborted', async () => {
    const { a } = agent(() => json(200, { requestId: 'r', status: 'pending' }));
    const ac = new AbortController();
    const p = a.waitForAccess('r', { intervalMs: 50, signal: ac.signal });
    setTimeout(() => ac.abort(new Error('give up')), 10);
    await expect(p).rejects.toThrow('give up');
  });

  it('keeps reason undefined for errors without one', async () => {
    const { a } = agent(() => json(401, { error: 'unauthorized', message: 'bad token' }));
    const err = (await a.whoami().catch((e: unknown) => e)) as CitadelError;
    expect(err.isUnauthorized).toBe(true);
    expect(err.reason).toBeUndefined();
    expect(err.requestId).toBeUndefined();
    expect(err.message).not.toContain(TOKEN);
  });
});

describe('retry safety', () => {
  const failing = (statuses: Array<[number, Record<string, string>?]>) => {
    let n = 0;
    return () => {
      const [status, headers] = statuses[n++] ?? [200];
      if (status === 200) return json(200, brokered());
      return json(status, { error: 'upstream_error', message: 'x', reason: 'upstream_timeout' }, headers);
    };
  };

  for (const status of [500, 502, 504]) {
    it(`never repeats a brokered call after ${status}`, async () => {
      const { a, calls } = agent(failing([[status], [status]]));
      const err = (await a.http({ credential: 'gh', method: 'POST', url: 'https://pay.test/charge', json: { amount: 1 } }).catch((e: unknown) => e)) as CitadelError;
      expect(err.status).toBe(status);
      expect(err.reason).toBe('upstream_timeout');
      expect(calls).toHaveLength(1);
    });
  }

  it('does not repeat reveal or access requests after an ambiguous failure', async () => {
    const r = agent(failing([[503]])); // no Retry-After: maybe a proxy
    await expect(r.a.reveal('gh')).rejects.toMatchObject({ status: 503 });
    expect(r.calls).toHaveLength(1);
    const q = agent(failing([[502]]));
    await expect(q.a.requestAccess({ credential: 'gh', reason: 'r' })).rejects.toMatchObject({ status: 502 });
    expect(q.calls).toHaveLength(1);
  });

  it('does not repeat a brokered call that timed out', async () => {
    const m = mockFetch(
      (req) =>
        new Promise<Response>((_resolve, reject) => {
          req.init.signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')));
        }),
    );
    const a = new CitadelAgent({ baseUrl: 'https://c.test', token: TOKEN, timeoutMs: 10, retryBaseDelayMs: 1, fetch: m.fetch });
    await expect(a.http({ credential: 'gh', url: 'https://x.test' })).rejects.toMatchObject({ code: 'timeout' });
    expect(m.calls).toHaveLength(1);
  });

  it('retries 429 and a busy broker (503 with Retry-After)', async () => {
    const { a, calls } = agent(failing([[429, { 'Retry-After': '0' }], [503, { 'Retry-After': '1' }]]));
    const res = await a.http({ credential: 'gh', method: 'POST', url: 'https://x.test', body: 'b' });
    expect(res.ok).toBe(true);
    expect(calls).toHaveLength(3);
  });

  it('retries ambiguous failures when the call opts in', async () => {
    const { a, calls } = agent(failing([[502], [504]]));
    const res = await a.http({ credential: 'gh', url: 'https://x.test' }, { retryNonIdempotent: true });
    expect(res.ok).toBe(true);
    expect(calls).toHaveLength(3);
  });

  it('still retries reads after 5xx', async () => {
    const { a, calls } = agent(failing([[502], [504], [500]]));
    await a.whoami();
    expect(calls).toHaveLength(4);
  });

  it('no longer retries non-idempotent native calls after a 500', async () => {
    const { c, calls } = client(() => json(500, { error: 'internal_error', message: 'boom' }));
    await expect(c.secrets.put({ project: 'p', env: 'e', key: 'K', value: 'v' })).rejects.toMatchObject({ status: 500 });
    expect(calls).toHaveLength(1);
  });
});

describe('VERSION', () => {
  it('matches package.json', () => {
    const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as { version: string };
    expect(VERSION).toBe(pkg.version);
  });
});
