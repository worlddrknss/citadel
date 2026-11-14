// Integration tests against the real Go server (cmd/server).
//
// The first suite runs the in-memory store in insecure dev mode (no
// credentials needed). The second runs the memory store with a console user,
// signs in, mints an access key and uses bearer authentication. The third,
// enabled by CITADEL_SDK_TEST_DB_URL (an
// EMPTY PostgreSQL database), bootstraps a real deployment, mints an access
// key and drives the SDK with bearer authentication.
//
// Both build the server with `go build`; they are skipped when Go is not
// installed or CITADEL_SDK_SKIP_INTEGRATION=1.
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { Citadel, CitadelAgent, CitadelError, clearSecretsCache, loadSecrets } from '../src/index.js';
import { cleanupBuild, goAvailable, randomKeyB64, startServer, type RunningServer } from './server.js';

const hasGo = goAvailable();
const dbURL = process.env.CITADEL_SDK_TEST_DB_URL ?? '';

afterAll(() => cleanupBuild());

describe.skipIf(!hasGo)('integration: memory store (insecure dev)', () => {
  let server: RunningServer;
  let citadel: Citadel;

  beforeAll(async () => {
    server = await startServer({ KMS_INSECURE_DEV: 'true', KMS_MASTER_KEY_B64: randomKeyB64() });
    citadel = new Citadel({ baseUrl: server.url, maxRetries: 0 });
  });

  afterAll(async () => {
    await server?.stop();
  });

  it('manages the project hierarchy and secrets', async () => {
    await citadel.projects.create({ slug: 'web', name: 'Web' });
    await citadel.environments.create({ project: 'web', slug: 'prod' });
    await citadel.folders.create({ project: 'web', env: 'prod', path: 'api' });
    const projects = await citadel.projects.list();
    expect(projects.find((p) => p.slug === 'web')?.environments).toContain('prod');

    const put = await citadel.secrets.put({ project: 'web', env: 'prod', key: 'DATABASE_URL', value: 'postgres://db/one' });
    expect(put.created).toBe(true);
    await citadel.secrets.put({ project: 'web', env: 'prod', key: 'DATABASE_URL', value: 'postgres://db/two' });
    await citadel.secrets.put({ project: 'web', env: 'prod', path: 'api', key: 'TOKEN', value: 'tok' });

    const listing = await citadel.secrets.list({ project: 'web', env: 'prod' });
    expect(listing.folders).toContain('api');
    expect(listing.items.map((i) => i.key)).toEqual(['DATABASE_URL']);

    expect(await citadel.secrets.getValue({ project: 'web', env: 'prod', key: 'DATABASE_URL' })).toBe('postgres://db/two');
    expect(await citadel.secrets.getValue({ project: 'web', env: 'prod', path: 'api', key: 'TOKEN' })).toBe('tok');

    const versions = await citadel.secrets.versions({ project: 'web', env: 'prod', key: 'DATABASE_URL' });
    expect(versions).toHaveLength(2);
    const first = versions.find((v) => v.version === 1)!;
    const old = await citadel.secrets.get({ project: 'web', env: 'prod', key: 'DATABASE_URL', versionId: first.versionId });
    expect(old.value).toBe('postgres://db/one');

    const del = await citadel.secrets.delete({ project: 'web', env: 'prod', path: 'api', key: 'TOKEN' });
    expect(del.deleted).toBe(true);
    await citadel.secrets.restore({ project: 'web', env: 'prod', path: 'api', key: 'TOKEN' });
    expect(await citadel.secrets.getValue({ project: 'web', env: 'prod', path: 'api', key: 'TOKEN' })).toBe('tok');
  });

  it('reports API errors with their codes', async () => {
    const missing = await citadel.secrets.get({ project: 'web', env: 'prod', key: 'NOPE' }).catch((e: unknown) => e);
    expect(CitadelError.is(missing, 'not_found')).toBe(true);
    expect((missing as CitadelError).status).toBe(404);

    const bad = await citadel.secrets.list({ project: 'web', env: 'prod', path: 'bad segment!' }).catch((e: unknown) => e);
    expect(CitadelError.is(bad, 'invalid_request')).toBe(true);

    const badToken = new Citadel({ baseUrl: server.url, accessKeyId: 'AKIANOPE', secretAccessKey: 'nope', maxRetries: 0 });
    await expect(badToken.projects.list()).rejects.toMatchObject({ status: 401, code: 'unauthorized' });
  });

  it('loads a folder with loadSecrets', async () => {
    clearSecretsCache();
    await citadel.secrets.put({ project: 'web', env: 'prod', key: 'API_KEY', value: 'k' });
    const values = await loadSecrets({ client: citadel, project: 'web', env: 'prod' });
    expect(values).toEqual({ API_KEY: 'k', DATABASE_URL: 'postgres://db/two' });
    expect(await loadSecrets({ client: citadel, project: 'web', env: 'prod', path: '/api/', prefix: 'TO' })).toEqual({ TOKEN: 'tok' });
  });

  it('stores and reveals parameters', async () => {
    const p = await citadel.parameters.put({ name: '/web/prod/feature', type: 'SecureString', value: 'on' });
    expect(p.type).toBe('SecureString');
    await citadel.parameters.put({ name: '/web/prod/feature', type: 'SecureString', value: 'off', overwrite: true });
    expect((await citadel.parameters.get('/web/prod/feature')).value).toBe('off');
    expect((await citadel.parameters.get('/web/prod/feature', { version: 1 })).value).toBe('on');
    expect((await citadel.parameters.list()).map((x) => x.name)).toContain('/web/prod/feature');
    expect((await citadel.parameters.history('/web/prod/feature')).history.length).toBe(2);
    await citadel.parameters.delete('/web/prod/feature');
    await expect(citadel.parameters.get('/web/prod/feature')).rejects.toMatchObject({ status: 404 });
  });

  it('encrypts and decrypts with KMS', async () => {
    const keys = await citadel.kms.listKeys();
    expect(keys.length).toBeGreaterThan(0);
    const keyId = keys[0]!.keyId;
    const enc = await citadel.kms.encrypt({ keyId, plaintext: 'top secret ✓', encryptionContext: { app: 'web' } });
    expect(enc.ciphertextBlob).not.toContain('top secret');
    expect(await citadel.kms.decryptText({ keyId, ciphertextBlob: enc.ciphertextBlob, encryptionContext: { app: 'web' } })).toBe('top secret ✓');
    await expect(citadel.kms.decrypt({ keyId, ciphertextBlob: enc.ciphertextBlob, encryptionContext: { app: 'other' } })).rejects.toBeInstanceOf(CitadelError);
  });

  it('issues and lists certificates', async () => {
    const ca = await citadel.request<{ caId: string }>({
      method: 'POST',
      path: '/v1/certificates/authorities',
      body: { caType: 'ROOT', keyAlgorithm: 'EC_prime256v1', commonName: 'SDK Test Root' },
    });
    const cert = await citadel.certificates.issueGenerated({
      caId: ca.caId,
      commonName: 'app.internal',
      sans: ['app.internal'],
      keyAlgorithm: 'EC_prime256v1',
      validityDays: 30,
    });
    expect(cert.certificatePem).toContain('BEGIN CERTIFICATE');
    expect(cert.privateKeyPem).toContain('BEGIN PRIVATE KEY');
    const list = await citadel.certificates.list();
    expect(list.map((c) => c.id)).toEqual(expect.arrayContaining([ca.caId, cert.certId]));
  });

  it('surfaces workload identity errors', async () => {
    await expect(citadel.workloadIdentity.token({ clientId: 'unknown-client', audience: 'aud' })).rejects.toMatchObject({
      code: 'invalid_client',
    });
  });
});

describe.skipIf(!hasGo)('integration: memory store with bearer access keys', () => {
  let server: RunningServer;
  let citadel: Citadel;
  const password = 'sdk-memory-admin-password-123';

  beforeAll(async () => {
    server = await startServer({
      KMS_MASTER_KEY_B64: randomKeyB64(),
      KMS_ACCESS_KEY_ID: 'AKIASDKTSMEMORY00001',
      KMS_SECRET_ACCESS_KEY: 'sdk-ts-memory-secret-access-key-0123456789',
      KMS_UI_USERNAME: 'sdkadmin',
      KMS_UI_PASSWORD: password,
      KMS_UI_ACCOUNTS: '123456789012',
    });
    const login = await fetch(`${server.url}/v1/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Citadel-Request': '1' },
      body: JSON.stringify({ accountId: '123456789012', username: 'sdkadmin', password }),
    });
    if (!login.ok) throw new Error(`login failed (${login.status}): ${await login.text()}`);
    const cookie = (login.headers.get('set-cookie') ?? '').split(';')[0]!;
    const keyRes = await fetch(`${server.url}/v1/account/keys`, {
      method: 'POST',
      headers: { Cookie: cookie, 'X-Citadel-Request': '1' },
    });
    if (!keyRes.ok) throw new Error(`create access key failed (${keyRes.status}): ${await keyRes.text()}`);
    const key = (await keyRes.json()) as { accessKeyId: string; secretKey: string };
    citadel = new Citadel({ baseUrl: server.url, accessKeyId: key.accessKeyId, secretAccessKey: key.secretKey, maxRetries: 0 });
  });

  afterAll(async () => {
    await server?.stop();
  });

  it('authenticates with the access key and acts as its owner', async () => {
    const me = await citadel.me();
    expect(me.role).toBe('admin');
    await citadel.projects.create({ slug: 'mem' });
    await citadel.environments.create({ project: 'mem', slug: 'dev' });
    await citadel.secrets.put({ project: 'mem', env: 'dev', key: 'SECRET', value: 'v1' });
    expect(await loadSecrets({ client: citadel, project: 'mem', env: 'dev', ttl: 0 })).toEqual({ SECRET: 'v1' });
  });

  it('rejects a wrong secret', async () => {
    const id = (citadel.transport.authorization ?? '').slice('Bearer '.length).split(':')[0]!;
    const wrong = new Citadel({ baseUrl: server.url, accessKeyId: id, secretAccessKey: 'wrong-secret', maxRetries: 0 });
    await expect(wrong.me()).rejects.toMatchObject({ status: 401, code: 'unauthorized' });
  });

  it('drives the Agent API with CitadelAgent', async () => {
    const secret = 'sdk-ts-upstream-token-0123456789';
    // A local upstream, reachable through the credential's allowHttp and
    // allowedCidrs (the broker refuses loopback otherwise).
    const upstream = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on('data', (c: Buffer) => chunks.push(c));
      req.on('end', () => {
        if (req.headers.authorization !== `Bearer ${secret}`) {
          res.writeHead(401).end('no credential');
          return;
        }
        if (req.url === '/leak') {
          res.writeHead(200, { 'Content-Type': 'text/plain' }).end(`token=${secret}`);
          return;
        }
        res.writeHead(200, { 'Content-Type': 'application/json', 'X-Method': req.method ?? '' }).end(Buffer.concat(chunks));
      });
    });
    await new Promise<void>((resolve) => upstream.listen(0, '127.0.0.1', resolve));
    const host = `127.0.0.1:${(upstream.address() as AddressInfo).port}`;
    try {
      await citadel.projects.create({ slug: 'agents' });
      await citadel.environments.create({ project: 'agents', slug: 'dev' });
      await citadel.secrets.put({ project: 'agents', env: 'dev', key: 'API_TOKEN', value: secret });
      const a = await citadel.request<{ agentId: string }>({ method: 'POST', path: '/v1/agents', body: { name: 'sdk-ts' } });
      for (const name of ['upstream', 'gated']) {
        await citadel.request({
          method: 'POST',
          path: '/v1/agents/credentials',
          body: {
            name,
            project: 'agents',
            env: 'dev',
            key: 'API_TOKEN',
            kind: 'http_header',
            headerPrefix: 'Bearer ',
            allowedHosts: [host],
            allowedMethods: ['GET', 'POST'],
            allowHttp: true,
            allowedCidrs: ['127.0.0.1/32'],
          },
        });
      }
      await citadel.request({ method: 'POST', path: '/v1/agents/grants', body: { agentId: a.agentId, credential: 'upstream', actions: ['use', 'reveal'] } });
      await citadel.request({ method: 'POST', path: '/v1/agents/grants', body: { agentId: a.agentId, credential: 'gated', requiresApproval: true } });
      const tok = await citadel.request<{ token: string }>({ method: 'POST', path: '/v1/agents/tokens', body: { agentId: a.agentId, name: 'sdk', expiresInDays: 1 } });

      const agent = new CitadelAgent({ baseUrl: server.url, token: tok.token, taskId: 'sdk-ts-run' });
      const me = await agent.whoami();
      expect(me.agentId).toBe(a.agentId);
      expect(me.taskId).toBe('sdk-ts-run');
      const creds = await agent.listCredentials();
      expect(creds.map((c) => c.name).sort()).toEqual(['gated', 'upstream']);

      const res = await agent.http({ credential: 'upstream', method: 'POST', url: `http://${host}/echo`, json: { hello: 'world' } });
      expect(res.ok).toBe(true);
      expect(res.headers['X-Method']).toBe('POST');
      expect(res.json<{ hello: string }>()).toEqual({ hello: 'world' });
      const leak = await agent.http({ credential: 'upstream', url: `http://${host}/leak` });
      expect(leak.redacted).toBe(true);
      expect(leak.text()).not.toContain(secret);
      expect((await agent.reveal('upstream')).value).toBe(secret);

      const denied = (await agent.http({ credential: 'upstream', url: 'https://elsewhere.example.com/' }).catch((e: unknown) => e)) as CitadelError;
      expect(denied).toMatchObject({ status: 403, code: 'forbidden', reason: 'host_not_allowed' });

      const gated = (await agent.http({ credential: 'gated', url: `http://${host}/echo` }).catch((e: unknown) => e)) as CitadelError;
      expect(gated.isApprovalRequired).toBe(true);
      expect(gated.reason).toBe('approval_required');
      expect(gated.requestId).toBeTruthy();
      const pending = await agent.getAccessRequest(gated.requestId!);
      expect(pending).toMatchObject({ status: 'pending', credential: 'gated', origin: 'policy' });
      const asked = await agent.requestAccess({ credential: 'gated', reason: 'sdk test', durationSeconds: 600 });
      expect(asked.status).toBe('pending');
      expect(await agent.listLeases()).toEqual([]);
    } finally {
      await new Promise<void>((resolve) => upstream.close(() => resolve()));
    }
  });
});

describe.skipIf(!hasGo || !dbURL)('integration: PostgreSQL with bearer access keys', () => {
  let server: RunningServer;
  let citadel: Citadel;
  const bootstrapToken = 'sdk-ts-bootstrap-token-0123456789';

  beforeAll(async () => {
    server = await startServer({
      KMS_DB_URL: dbURL,
      KMS_BOOTSTRAP_TOKEN: bootstrapToken,
      KMS_WRAPPING_KEY_B64: randomKeyB64(),
    });
    const res = await fetch(`${server.url}/v1/bootstrap`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Citadel-Request': '1' },
      body: JSON.stringify({
        organizationName: 'SDK Test Org',
        accountName: 'sdk-test',
        username: 'sdkadmin',
        password: 'sdk-admin-password-123',
        bootstrapToken,
      }),
    });
    if (!res.ok) throw new Error(`bootstrap failed (${res.status}): ${await res.text()} (the database must be empty)`);
    const cookie = (res.headers.get('set-cookie') ?? '').split(';')[0]!;
    const keyRes = await fetch(`${server.url}/v1/account/keys`, {
      method: 'POST',
      headers: { Cookie: cookie, 'X-Citadel-Request': '1' },
    });
    if (!keyRes.ok) throw new Error(`create access key failed (${keyRes.status}): ${await keyRes.text()}`);
    const key = (await keyRes.json()) as { accessKeyId: string; secretKey: string };
    citadel = new Citadel({ baseUrl: server.url, accessKeyId: key.accessKeyId, secretAccessKey: key.secretKey, maxRetries: 0 });
  });

  afterAll(async () => {
    await server?.stop();
  });

  it('authenticates with the access key', async () => {
    const me = await citadel.me();
    expect(me.role).toBe('admin');
  });

  it('writes and reads secrets as the key owner', async () => {
    await citadel.projects.create({ slug: 'svc' });
    await citadel.environments.create({ project: 'svc', slug: 'staging' });
    await citadel.secrets.put({ project: 'svc', env: 'staging', key: 'SECRET', value: 'v1' });
    expect(await citadel.secrets.getValue({ project: 'svc', env: 'staging', key: 'SECRET' })).toBe('v1');
    expect(await loadSecrets({ client: citadel, project: 'svc', env: 'staging', ttl: 0 })).toEqual({ SECRET: 'v1' });
  });

  it('rejects a wrong secret', async () => {
    const id = (citadel.transport.authorization ?? '').slice('Bearer '.length).split(':')[0]!;
    const wrong = new Citadel({ baseUrl: server.url, accessKeyId: id, secretAccessKey: 'wrong-secret', maxRetries: 0 });
    await expect(wrong.me()).rejects.toMatchObject({ status: 401, code: 'unauthorized' });
  });
});
