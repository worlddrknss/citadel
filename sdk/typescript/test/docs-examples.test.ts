// The examples in docs/sdk-typescript.md, kept here so they are typechecked
// (`npm run lint`) and run against a mocked fetch (`npm test`). When you
// change an example in the docs, change it here too, and the other way round.
// Doc-only lines (`import 'server-only'`, JSX) are left out.
import { afterEach, describe, expect, it } from 'vitest';
import { Citadel, CitadelError, clearSecretsCache, loadSecrets, type components, type RequestOptions } from '../src/index.js';
import { json, mockFetch, type Handler } from './helpers.js';

type S = components['schemas'];

// ---- Configuration ----------------------------------------------------------

function configured(fetchImpl: typeof fetch): Citadel {
  return new Citadel({
    baseUrl: 'https://citadel.example.com',
    accessKeyId: process.env.CITADEL_ACCESS_KEY_ID ?? 'AKIAEXAMPLE',
    secretAccessKey: process.env.CITADEL_SECRET_ACCESS_KEY ?? 'example-secret',
    timeoutMs: 10_000, // per attempt (default 30 s; 0 disables)
    maxRetries: 3, // 429/5xx and network errors (default 3)
    retryBaseDelayMs: 1, // default 200 ms (shortened for the test)
    retryMaxDelayMs: 5, // default 10 s
    headers: { 'X-Request-Source': 'shop-web' },
    fetch: fetchImpl, // optional; defaults to the global fetch
  });
}

// ---- Reading secrets and parameters -------------------------------------------

async function readSecrets(citadel: Citadel) {
  const ref = { project: 'shop', env: 'prod', path: 'api', key: 'DATABASE_URL' };

  // The current value, as a string (throws `binary_value` for binary secrets).
  const databaseUrl = await citadel.secrets.getValue(ref);

  // The full response: version ID, and `resolve` expands ${...} references.
  const previous = await citadel.secrets.get({ ...ref, versionStage: 'AWSPREVIOUS' });

  // One folder: keys and metadata, never values.
  const listing = await citadel.secrets.list({ project: 'shop', env: 'prod', path: 'api' });
  const keys = listing.items.map((item) => item.key);

  // Parameter Store: SecureString values come back decrypted.
  const { value: region } = await citadel.parameters.get('/shop/prod/region');

  return { databaseUrl, previousVersion: previous.versionId, keys, region };
}

// ---- Next.js ----------------------------------------------------------------

// lib/citadel.ts
function makeAppCitadel(fetchImpl: typeof fetch) {
  // In the app: `export const citadel = new Citadel();` (reads CITADEL_URL,
  // CITADEL_ACCESS_KEY_ID, CITADEL_SECRET_ACCESS_KEY).
  return new Citadel({ baseUrl: 'https://citadel.example.com', accessKeyId: 'AKIAEXAMPLE', secretAccessKey: 'example-secret', fetch: fetchImpl });
}

// app/api/orders/route.ts
function makeRouteHandler(citadel: Citadel, upstream: typeof fetch) {
  return async function GET(): Promise<Response> {
    try {
      const apiKey = await citadel.secrets.getValue({ project: 'shop', env: 'prod', key: 'PAYMENTS_API_KEY' }, { cache: 'no-store' });
      const orders = await upstream('https://payments.example.com/orders', {
        headers: { Authorization: `Bearer ${apiKey}` },
      });
      return Response.json(await orders.json());
    } catch (err) {
      if (CitadelError.is(err, 'not_found')) {
        return new Response('payments are not configured', { status: 503 });
      }
      throw err;
    }
  };
}

// lib/secrets.ts
function appSecrets(client: Citadel) {
  return loadSecrets({
    client, // omit to build a client from the environment
    project: 'shop',
    env: process.env.NODE_ENV === 'production' ? 'prod' : 'dev',
    path: 'web',
    prefix: 'STRIPE_',
    ttl: 60_000,
    staleWhileRevalidate: 300_000,
  });
}

// app/checkout/page.tsx (server component), without the JSX
async function checkoutProps(client: Citadel) {
  const { STRIPE_PUBLISHABLE_KEY } = await appSecrets(client);
  return { publishableKey: STRIPE_PUBLISHABLE_KEY };
}

// next.config.mjs
async function nextConfig(client: Citadel) {
  await loadSecrets({ client, project: 'shop', env: 'prod', path: 'web', inject: true, ttl: 0 });
  return {};
}

// ---- KMS --------------------------------------------------------------------

async function kmsRoundTrip(citadel: Citadel) {
  const context = { tenant: '42' };
  const { ciphertextBlob } = await citadel.kms.encrypt({
    keyId: 'alias/payments', // key ID, key ARN, alias or alias ARN
    plaintext: 'card-token', // string (UTF-8) or Uint8Array, up to 4 KB
    encryptionContext: context,
  });
  // Store ciphertextBlob (base64). Decrypt needs the same encryption context.
  const plaintext = await citadel.kms.decryptText({ keyId: 'alias/payments', ciphertextBlob, encryptionContext: context });
  return { ciphertextBlob, plaintext };
}

// ---- Agent API --------------------------------------------------------------

// lib/citadel-agent.ts: typed wrappers for the Agent API, using the
// generated OpenAPI types. The token goes in each call's Authorization
// header, so no access key is needed.
function agentApi(token: string, client: Citadel = new Citadel()) {
  const authorization = `Bearer ${token}`;
  const get = <T>(path: string, query?: Record<string, string>, opts?: RequestOptions) =>
    client.request<T>({ method: 'GET', path, query, authorization }, opts);
  const post = <T>(path: string, body: unknown, opts?: RequestOptions) =>
    client.request<T>({ method: 'POST', path, body, authorization }, opts);
  return {
    whoami: (opts?: RequestOptions) => get<S['AgentWhoAmI']>('/v1/agent/whoami', undefined, opts),
    credentials: async (opts?: RequestOptions) => (await get<S['AgentUsableCredentialList']>('/v1/agent/credentials', undefined, opts)).credentials,
    http: (input: S['AgentHttpRequest'], opts?: RequestOptions) => post<S['AgentHttpResponse']>('/v1/agent/http', input, opts),
    reveal: (input: S['AgentRevealRequest'], opts?: RequestOptions) => post<S['AgentRevealResponse']>('/v1/agent/credentials/reveal', input, opts),
    login: (input: S['AgentLoginRequest'], opts?: RequestOptions) => post<S['AgentLogin']>('/v1/agent/login', input, opts),
    totp: (input: S['AgentTOTPRequest'], opts?: RequestOptions) => post<S['AgentTOTPCode']>('/v1/agent/totp', input, opts),
    requestAccess: (input: S['AgentAccessRequestInput'], opts?: RequestOptions) => post<S['AgentAccessRequest']>('/v1/agent/access-requests', input, opts),
    accessRequest: (id: string, opts?: RequestOptions) => get<S['AgentAccessRequest']>(`/v1/agent/access-requests/${encodeURIComponent(id)}`, undefined, opts),
    leases: async (credential?: string, opts?: RequestOptions) =>
      (await get<S['AgentLeaseList']>('/v1/agent/leases', credential ? { credential } : undefined, opts)).leases,
  };
}

async function agentBasics(agent: ReturnType<typeof agentApi>) {
  const me = await agent.whoami();
  const usable = (await agent.credentials()).filter((c) => c.usable).map((c) => c.name);

  // Brokered HTTP: Citadel injects the credential; the agent never sees it.
  const res = await agent.http(
    {
      credential: 'github-pat',
      method: 'GET',
      url: 'https://api.github.com/user/repos',
      headers: { Accept: 'application/vnd.github+json' },
      bodyEncoding: 'text',
      taskId: 'fix-issue-1234',
    },
    { maxRetries: 0 }, // don't repeat upstream side effects on a 502/504
  );
  const repos: unknown = res.bodyEncoding === 'text' ? JSON.parse(res.body) : null;
  return { agentId: me.agentId, usable, status: res.status, repos };
}

async function agentSecrets(agent: ReturnType<typeof agentApi>) {
  // Needs a grant with `reveal`. Prefer brokered use when you only call an API.
  const deployKey = await agent.reveal({ credential: 'deploy-key', taskId: 'release-42' });

  // Browser agents: a login for one page (`reveal`), and its TOTP code (`totp`).
  const login = await agent.login({ credential: 'acme-admin', url: 'https://admin.acme.example/login' });
  const { code, secondsRemaining } = await agent.totp({ credential: 'acme-admin' });

  return { value: deployKey.value, expiresAt: deployKey.expiresAt, username: login.username, code, secondsRemaining };
}

async function waitForAccess(agent: ReturnType<typeof agentApi>, sleep: (ms: number) => Promise<void>) {
  // Ask a person for access. Asking again while it is pending returns the
  // same request, which is also how to find the request behind an
  // `approval_required` error.
  let request = await agent.requestAccess({
    credential: 'deploy-key',
    actions: ['reveal'],
    reason: 'Tag the release; the pipeline needs the deploy key',
    duration: '15m',
    taskId: 'release-42',
  });
  while (request.status === 'pending') {
    await sleep(5_000);
    request = await agent.accessRequest(request.requestId);
  }
  if (request.status !== 'approved') {
    throw new Error(`access ${request.status}: ${request.decisionComment ?? ''}`);
  }
  const leases = await agent.leases('deploy-key');
  return { lease: request.lease?.leaseId, active: leases.length };
}

async function revealOrAsk(agent: ReturnType<typeof agentApi>) {
  try {
    return (await agent.reveal({ credential: 'deploy-key' })).value;
  } catch (err) {
    if (CitadelError.is(err, 'approval_required')) {
      const pending = await agent.requestAccess({ credential: 'deploy-key', actions: ['reveal'], reason: 'release' });
      return `waiting for ${pending.requestId}`;
    }
    if (CitadelError.is(err) && err.isForbidden) {
      // no_grant, host_not_allowed, agent_suspended...: err.message explains.
      return `refused: ${err.message}`;
    }
    throw err;
  }
}

// ---- Management -------------------------------------------------------------

async function manage(citadel: Citadel) {
  await citadel.projects.create({ slug: 'shop', name: 'Shop' });
  await citadel.environments.create({ project: 'shop', slug: 'prod' });
  await citadel.folders.create({ project: 'shop', env: 'prod', path: 'api' });
  await citadel.secrets.put({ project: 'shop', env: 'prod', path: 'api', key: 'DATABASE_URL', value: 'postgres://example' });
  const versions = await citadel.secrets.versions({ project: 'shop', env: 'prod', path: 'api', key: 'DATABASE_URL' });
  await citadel.parameters.put({ name: '/shop/prod/region', type: 'String', value: 'eu-west-1', overwrite: true });

  // Anything without a typed method: request() with the generated types.
  const { agents } = await citadel.request<S['AgentList']>({ method: 'GET', path: '/v1/agents' });
  return { versions: versions.length, agents: agents.map((a) => a.name) };
}

async function writeOrRequestChange(citadel: Citadel) {
  try {
    await citadel.secrets.put({ project: 'shop', env: 'prod', key: 'FEATURE_FLAG', value: 'on' });
    return 'written';
  } catch (err) {
    if (CitadelError.is(err, 'approval_required')) return 'needs a change request';
    if (CitadelError.is(err, 'rate_limited')) return `retry after ${err.retryAfterMs ?? 0} ms`;
    throw err;
  }
}

async function perCall(citadel: Citadel) {
  const ac = new AbortController();
  return citadel.secrets.list({ project: 'shop', env: 'prod' }, { signal: ac.signal, timeoutMs: 5_000, maxRetries: 0, cache: 'no-store' });
}

// ---- Tests ------------------------------------------------------------------

const listing = (keys: string[]) => ({
  project: 'shop',
  env: 'prod',
  path: '/web',
  folders: [],
  shadowed: [],
  folderCounts: {},
  items: keys.map((key) => ({ key, project: 'shop', env: 'prod', path: '/web', arn: '', updatedAt: '', tags: [] })),
});

const route: (routes: Record<string, (body: unknown, url: URL) => Response>) => Handler = (routes) => (req) => {
  const h = routes[`${req.method} ${req.url.pathname}`];
  return h ? h(req.body, req.url) : json(404, { error: 'not_found', message: `no mock for ${req.method} ${req.url.pathname}` });
};

afterEach(() => clearSecretsCache());

describe('docs/sdk-typescript.md examples', () => {
  it('configure a client and read secrets and parameters', async () => {
    const m = mockFetch(
      route({
        'GET /v1/secrets/value': (_b, url) => json(200, { key: 'DATABASE_URL', versionId: url.searchParams.get('versionStage') ? 'v1' : 'v2', resolved: false, value: 'postgres://x' }),
        'GET /v1/secrets': () => json(200, listing(['DATABASE_URL'])),
        'GET /v1/parameters/value': () => json(200, { name: '/shop/prod/region', type: 'String', version: 1, value: 'eu-west-1' }),
      }),
    );
    const out = await readSecrets(configured(m.fetch));
    expect(out).toEqual({ databaseUrl: 'postgres://x', previousVersion: 'v1', keys: ['DATABASE_URL'], region: 'eu-west-1' });
    expect(m.calls[0]!.headers['x-request-source']).toBe('shop-web');
  });

  it('serve a Next.js route handler, server component and config', async () => {
    const m = mockFetch(
      route({
        'GET /v1/secrets/value': (_b, url) =>
          url.searchParams.get('key') === 'PAYMENTS_API_KEY' ? json(404, { error: 'not_found', message: 'no such secret' }) : json(200, { key: 'k', versionId: 'v', resolved: false, value: 'pk_test' }),
        'GET /v1/secrets': () => json(200, listing(['STRIPE_PUBLISHABLE_KEY', 'OTHER'])),
      }),
    );
    const citadel = makeAppCitadel(m.fetch);
    const res = await makeRouteHandler(citadel, m.fetch)();
    expect(res.status).toBe(503);
    expect(await checkoutProps(citadel)).toEqual({ publishableKey: 'pk_test' });
    delete process.env.STRIPE_PUBLISHABLE_KEY;
    await nextConfig(citadel);
    expect(process.env.STRIPE_PUBLISHABLE_KEY).toBe('pk_test');
    delete process.env.STRIPE_PUBLISHABLE_KEY;
    delete process.env.OTHER;
  });

  it('encrypt and decrypt with KMS', async () => {
    const m = mockFetch(
      route({
        'POST /v1/kms/encrypt': (b) => json(200, { keyId: 'k1', ciphertextBlob: btoa(JSON.stringify(b)), encryptionAlgorithm: 'SYMMETRIC_DEFAULT' }),
        'POST /v1/kms/decrypt': (b) => {
          const original = JSON.parse(atob((b as { ciphertextBlob: string }).ciphertextBlob)) as { plaintext: string };
          return json(200, { keyId: 'k1', plaintext: original.plaintext, encryptionAlgorithm: 'SYMMETRIC_DEFAULT' });
        },
      }),
    );
    expect((await kmsRoundTrip(configured(m.fetch))).plaintext).toBe('card-token');
    expect(m.calls[0]!.body).toMatchObject({ keyId: 'alias/payments', encryptionContext: { tenant: '42' } });
  });

  it('call the Agent API with an agent token', async () => {
    let polls = 0;
    const lease = { leaseId: 'als_1', agentId: 'agt_1', credential: 'deploy-key', actions: ['reveal'], scope: 'duration', usesLeft: null, useCount: 0, expiresAt: '', createdAt: '', createdBy: 'alice', status: 'active' };
    const pending = { requestId: 'aar_1', credential: 'deploy-key', actions: ['reveal'], origin: 'agent', status: 'pending', createdAt: '', expiresAt: '' };
    const m = mockFetch(
      route({
        'GET /v1/agent/whoami': () => json(200, { agentId: 'agt_1', name: 'ci', owner: 'alice', accountId: 'a', status: 'active', authMethod: 'token' }),
        'GET /v1/agent/credentials': () =>
          json(200, { credentials: [{ name: 'github-pat', kind: 'http_header', description: '', allowedHosts: [], allowedMethods: [], allowedPathPrefixes: [], actions: ['use'], maxUsesPerHour: 0, requiresApproval: false, usable: true }] }),
        'POST /v1/agent/http': () => json(200, { status: 200, headers: {}, body: '[]', bodyEncoding: 'text', truncated: false, redacted: false }),
        'POST /v1/agent/credentials/reveal': () => json(200, { credential: 'deploy-key', kind: 'raw', value: 'k3y' }),
        'POST /v1/agent/login': () => json(200, { credential: 'acme-admin', username: 'bot', password: 'pw', urlPattern: 'https://admin.acme.example' }),
        'POST /v1/agent/totp': () => json(200, { credential: 'acme-admin', code: '123456', expiresAt: '', secondsRemaining: 20, digits: 6, period: 30, algorithm: 'SHA256' }),
        'POST /v1/agent/access-requests': () => json(201, pending),
        'GET /v1/agent/access-requests/aar_1': () => json(200, ++polls < 2 ? pending : { ...pending, status: 'approved', lease }),
        'GET /v1/agent/leases': () => json(200, { leases: [lease] }),
      }),
    );
    const agent = agentApi('cagt_example', new Citadel({ baseUrl: 'https://citadel.example.com', fetch: m.fetch }));
    expect(await agentBasics(agent)).toEqual({ agentId: 'agt_1', usable: ['github-pat'], status: 200, repos: [] });
    expect(m.calls.every((c) => c.headers['authorization'] === 'Bearer cagt_example')).toBe(true);
    expect((await agentSecrets(agent)).code).toBe('123456');
    expect(await waitForAccess(agent, async () => {})).toEqual({ lease: 'als_1', active: 1 });
    expect(m.calls.find((c) => c.url.pathname === '/v1/agent/leases')!.url.searchParams.get('credential')).toBe('deploy-key');
  });

  it('turn approval_required and refusals into decisions', async () => {
    let answer: Response = json(403, { error: 'approval_required', reason: 'approval_required', requestId: 'aar_9', message: 'a person must approve this use' });
    const m = mockFetch(
      route({
        'POST /v1/agent/credentials/reveal': () => answer,
        'POST /v1/agent/access-requests': () => json(200, { requestId: 'aar_9', credential: 'deploy-key', actions: ['reveal'], origin: 'policy', status: 'pending', createdAt: '', expiresAt: '' }),
      }),
    );
    const agent = agentApi('cagt_example', new Citadel({ baseUrl: 'https://citadel.example.com', fetch: m.fetch }));
    expect(await revealOrAsk(agent)).toBe('waiting for aar_9');
    answer = json(403, { error: 'forbidden', reason: 'no_grant', message: 'the agent has no grant for this credential' });
    expect(await revealOrAsk(agent)).toBe('refused: the agent has no grant for this credential');
  });

  it('manage projects, secrets and parameters, and call untyped operations', async () => {
    const m = mockFetch(
      route({
        'POST /v1/projects': () => json(201, {}),
        'POST /v1/environments': () => json(201, {}),
        'POST /v1/folders': () => json(201, {}),
        'POST /v1/secrets': () => json(200, { project: 'shop', env: 'prod', path: '/api', key: 'DATABASE_URL', created: true }),
        'GET /v1/secrets/versions': () => json(200, { key: 'DATABASE_URL', versions: [{ versionId: 'v1', stages: ['AWSCURRENT'], createdAt: '', version: 1 }] }),
        'POST /v1/parameters': () => json(200, { parameter: { name: '/shop/prod/region', type: 'String', tier: 'Standard', version: 1, description: '', lastModified: '' } }),
        'GET /v1/agents': () => json(200, { agents: [{ name: 'ci' }] }),
      }),
    );
    expect(await manage(configured(m.fetch))).toEqual({ versions: 1, agents: ['ci'] });
  });

  it('handle errors and per-call options', async () => {
    const m = mockFetch(
      route({
        'POST /v1/secrets': () => json(409, { error: 'approval_required', message: 'prod requires a change request' }),
        'GET /v1/secrets': () => json(200, listing([])),
      }),
    );
    const citadel = configured(m.fetch);
    expect(await writeOrRequestChange(citadel)).toBe('needs a change request');
    expect((await perCall(citadel)).items).toEqual([]);
    expect(m.calls[1]!.init.cache).toBe('no-store');
  });
});
