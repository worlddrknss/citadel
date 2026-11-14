// The examples in docs/sdk-typescript.md, kept here so they are typechecked
// (`npm run lint`) and run against a mocked fetch (`npm test`). When you
// change an example in the docs, change it here too, and the other way round.
// Doc-only lines (`import 'server-only'`, JSX) are left out.
import { afterEach, describe, expect, it } from 'vitest';
import { Citadel, CitadelAgent, CitadelError, clearSecretsCache, loadSecrets, type components } from '../src/index.js';
import { json, mockFetch, type Handler } from './helpers.js';

type S = components['schemas'];

// ---- Configuration ----------------------------------------------------------

function configured(fetchImpl: typeof fetch): Citadel {
  return new Citadel({
    baseUrl: 'https://citadel.example.com',
    accessKeyId: process.env.CITADEL_ACCESS_KEY_ID ?? 'AKIAEXAMPLE',
    secretAccessKey: process.env.CITADEL_SECRET_ACCESS_KEY ?? 'example-secret',
    timeoutMs: 10_000, // per attempt (default 30 s; 0 disables)
    maxRetries: 3, // see Errors, retries and timeouts (default 3)
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

// lib/citadel-agent.ts
function makeAgent(fetchImpl: typeof fetch) {
  // In the app: `export const agent = new CitadelAgent();` (reads CITADEL_URL
  // and CITADEL_AGENT_TOKEN).
  return new CitadelAgent({
    baseUrl: 'https://citadel.example.com',
    token: process.env.CITADEL_AGENT_TOKEN ?? 'cagt_example',
    taskId: 'fix-issue-1234', // optional: X-Citadel-Task-Id on every call
    fetch: fetchImpl,
  });
}

async function agentBasics(agent: CitadelAgent) {
  const me = await agent.whoami();
  const usable = (await agent.listCredentials()).filter((c) => c.usable).map((c) => c.name);

  // Brokered HTTP: Citadel injects the credential; the agent never sees it.
  const res = await agent.http({
    credential: 'github-pat',
    url: 'https://api.github.com/user/repos',
    headers: { Accept: 'application/vnd.github+json' },
  });
  const repos = res.ok ? res.json<unknown[]>() : [];

  // A JSON body (`json`), text (`body: string`) or bytes (`body: Uint8Array`).
  const issue = await agent.http({
    credential: 'github-pat',
    method: 'POST',
    url: 'https://api.github.com/repos/acme/app/issues',
    json: { title: 'Flaky test in CI' },
  });
  return { agentId: me.agentId, usable, status: res.status, repos, created: issue.status };
}

async function agentSecrets(agent: CitadelAgent) {
  // Needs a grant with `reveal`. Prefer brokered use when you only call an API.
  const deployKey = await agent.reveal({ credential: 'deploy-key', taskId: 'release-42' });

  // Browser agents: a login for one page (`reveal`), and its TOTP code (`totp`).
  const login = await agent.getLogin({ credential: 'acme-admin', url: 'https://admin.acme.example/login' });
  const { code, secondsRemaining } = await agent.getTotpCode('acme-admin');

  return { value: deployKey.value, expiresAt: deployKey.expiresAt, username: login.username, code, secondsRemaining };
}

async function askForAccess(agent: CitadelAgent) {
  // Ask a person for access, then wait for the decision (polls every 5 s by
  // default; pass `signal` to give up).
  const request = await agent.requestAccess({
    credential: 'deploy-key',
    actions: ['reveal'],
    reason: 'Tag the release; the pipeline needs the deploy key',
    duration: '15m',
    taskId: 'release-42',
  });
  const decided = await agent.waitForAccess(request.requestId, { intervalMs: 1 /* default 5000 */ });
  if (decided.status !== 'approved') {
    throw new Error(`access ${decided.status}: ${decided.decisionComment ?? ''}`);
  }
  const leases = await agent.listLeases({ credential: 'deploy-key' });
  return { lease: decided.lease?.leaseId, active: leases.length };
}

async function revealWithApproval(agent: CitadelAgent): Promise<string> {
  try {
    return (await agent.reveal('deploy-key')).value;
  } catch (err) {
    // A grant with requiresApproval: the error names the access request
    // Citadel opened. Wait for it, then retry under the lease.
    if (CitadelError.is(err, 'approval_required') && err.requestId) {
      const decided = await agent.waitForAccess(err.requestId, { intervalMs: 1 /* default 5000 */ });
      if (decided.status === 'approved') return (await agent.reveal('deploy-key')).value;
      return `not approved: ${decided.decisionComment ?? decided.status}`;
    }
    if (CitadelError.is(err) && err.isForbidden) {
      // err.reason: no_grant, action_not_granted, host_not_allowed, agent_suspended...
      return `refused: ${err.reason ?? err.code}`;
    }
    throw err;
  }
}

async function chargeOnce(agent: CitadelAgent) {
  // Not retried after a 502/504 or a timeout: the upstream may have acted.
  const once = await agent.http({ credential: 'payments', method: 'POST', url: 'https://pay.example.com/charges', json: { amount: 100 } });
  // An idempotent upstream call (an Idempotency-Key header): safe to retry.
  const retried = await agent.http(
    {
      credential: 'payments',
      method: 'POST',
      url: 'https://pay.example.com/charges',
      headers: { 'Idempotency-Key': 'order-42' },
      json: { amount: 100 },
    },
    { retryNonIdempotent: true },
  );
  return [once.status, retried.status];
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

  it('call the Agent API with CitadelAgent', async () => {
    let polls = 0;
    const lease = { leaseId: 'als_1', agentId: 'agt_1', credential: 'deploy-key', actions: ['reveal'], scope: 'duration', usesLeft: null, useCount: 0, expiresAt: '', createdAt: '', createdBy: 'alice', status: 'active' };
    const pending = { requestId: 'aar_1', credential: 'deploy-key', actions: ['reveal'], origin: 'agent', status: 'pending', createdAt: '', expiresAt: '' };
    const m = mockFetch(
      route({
        'GET /v1/agent/whoami': () => json(200, { agentId: 'agt_1', name: 'ci', owner: 'alice', accountId: 'a', status: 'active', authMethod: 'token' }),
        'GET /v1/agent/credentials': () =>
          json(200, { credentials: [{ name: 'github-pat', kind: 'http_header', description: '', allowedHosts: [], allowedMethods: [], allowedPathPrefixes: [], actions: ['use'], maxUsesPerHour: 0, requiresApproval: false, usable: true }] }),
        'POST /v1/agent/http': (b) =>
          json(200, { status: (b as { method: string }).method === 'POST' ? 201 : 200, headers: {}, body: '[]', bodyEncoding: 'text', truncated: false, redacted: false }),
        'POST /v1/agent/credentials/reveal': () => json(200, { credential: 'deploy-key', kind: 'raw', value: 'k3y' }),
        'POST /v1/agent/login': () => json(200, { credential: 'acme-admin', username: 'bot', password: 'pw', urlPattern: 'https://admin.acme.example' }),
        'POST /v1/agent/totp': () => json(200, { credential: 'acme-admin', code: '123456', expiresAt: '', secondsRemaining: 20, digits: 6, period: 30, algorithm: 'SHA256' }),
        'POST /v1/agent/access-requests': () => json(201, pending),
        'GET /v1/agent/access-requests/aar_1': () => json(200, ++polls < 2 ? pending : { ...pending, status: 'approved', lease }),
        'GET /v1/agent/leases': () => json(200, { leases: [lease] }),
      }),
    );
    const agent = makeAgent(m.fetch);
    expect(await agentBasics(agent)).toEqual({ agentId: 'agt_1', usable: ['github-pat'], status: 200, repos: [], created: 201 });
    expect(m.calls.every((c) => c.headers['authorization'] === 'Bearer cagt_example' && c.headers['x-citadel-task-id'] === 'fix-issue-1234')).toBe(true);
    expect(m.calls[3]!.body).toMatchObject({ method: 'POST', body: '{"title":"Flaky test in CI"}', headers: { 'Content-Type': 'application/json' } });
    expect((await agentSecrets(agent)).code).toBe('123456');
    expect(await askForAccess(agent)).toEqual({ lease: 'als_1', active: 1 });
    expect(m.calls.find((c) => c.url.pathname === '/v1/agent/leases')!.url.searchParams.get('credential')).toBe('deploy-key');
  });

  it('wait for approval and turn refusals into decisions', async () => {
    let reveals = 0;
    let answer: () => Response = () =>
      ++reveals === 1 ? json(403, { error: 'approval_required', reason: 'approval_required', requestId: 'aar_9', message: 'a person must approve this use' }) : json(200, { credential: 'deploy-key', kind: 'raw', value: 'k3y' });
    const m = mockFetch(
      route({
        'POST /v1/agent/credentials/reveal': () => answer(),
        'GET /v1/agent/access-requests/aar_9': () => json(200, { requestId: 'aar_9', credential: 'deploy-key', actions: ['reveal'], origin: 'policy', status: 'approved', createdAt: '', expiresAt: '' }),
      }),
    );
    const agent = makeAgent(m.fetch);
    expect(await revealWithApproval(agent)).toBe('k3y');
    expect(m.calls.map((c) => `${c.method} ${c.url.pathname}`)).toEqual(['POST /v1/agent/credentials/reveal', 'GET /v1/agent/access-requests/aar_9', 'POST /v1/agent/credentials/reveal']);
    answer = () => json(403, { error: 'forbidden', reason: 'no_grant', message: 'the agent has no grant for this credential' });
    expect(await revealWithApproval(agent)).toBe('refused: no_grant');
  });

  it('retry brokered calls only when asked', async () => {
    let n = 0;
    const m = mockFetch(() => (++n % 2 === 1 ? json(502, { error: 'upstream_error', reason: 'upstream_unreachable', message: 'x' }) : json(200, { status: 201, headers: {}, body: '', bodyEncoding: 'text', truncated: false, redacted: false })));
    const agent = new CitadelAgent({ baseUrl: 'https://citadel.example.com', token: 'cagt_example', retryBaseDelayMs: 1, fetch: m.fetch });
    await expect(chargeOnce(agent)).rejects.toMatchObject({ status: 502, reason: 'upstream_unreachable' });
    expect(m.calls).toHaveLength(1);
    n = 0;
    m.calls.length = 0;
    const retried = await agent.http({ credential: 'payments', method: 'POST', url: 'https://pay.example.com/charges', json: {} }, { retryNonIdempotent: true });
    expect(retried.status).toBe(201);
    expect(m.calls).toHaveLength(2);
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
