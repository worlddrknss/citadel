import { execFileSync, spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { createServer, type IncomingMessage, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { dirname, resolve } from 'node:path';
import { createInterface } from 'node:readline';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { request as pwRequest } from '@playwright/test';
import { BASE } from './playwright.config';
import { ORG, apiPost, expect, signIn, test } from './fixtures';

// The agent broker and the MCP server end to end: the real server, an agent
// with a token and a grant, a local upstream API, the REST broker
// (POST /v1/agent/http) and the TypeScript SDK's MCP stdio bridge
// (`citadel mcp`) driving /mcp. The secret must reach the upstream and never
// the agent; every call is audited.

const SECRET = 'live-broker-secret-value-7f3a9c';
const SDK = resolve(dirname(fileURLToPath(import.meta.url)), '../../sdk/typescript');

interface Seen {
  authorization?: string;
  path?: string;
}

function startUpstream(seen: Seen): Promise<Server> {
  const srv = createServer((req: IncomingMessage, res) => {
    seen.authorization = req.headers.authorization;
    seen.path = req.url;
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Set-Cookie', 'upstream=1');
    // Echo the credential back: the broker must redact it.
    res.end(JSON.stringify({ ok: true, echoed: req.headers.authorization, b64: Buffer.from(SECRET).toString('base64') }));
  });
  return new Promise((done) => srv.listen(0, '127.0.0.1', () => done(srv)));
}

/** Runs the stdio bridge and exchanges newline-delimited JSON-RPC. */
class Bridge {
  private replies = new Map<number | string, (m: Record<string, unknown>) => void>();
  readonly proc;
  stderr = '';
  constructor(token: string) {
    this.proc = spawn(process.execPath, [resolve(SDK, 'dist/esm/cli.js'), 'mcp', '--url', BASE], {
      env: { ...process.env, CITADEL_AGENT_TOKEN: token, NODE_EXTRA_CA_CERTS: '' },
      stdio: ['pipe', 'pipe', 'pipe']
    });
    this.proc.stderr.on('data', (d: Buffer) => (this.stderr += d.toString()));
    createInterface({ input: this.proc.stdout }).on('line', (line) => {
      const msg = JSON.parse(line) as Record<string, unknown>;
      const done = this.replies.get(msg.id as number);
      if (done) {
        this.replies.delete(msg.id as number);
        done(msg);
      }
    });
  }
  send(msg: Record<string, unknown>) {
    this.proc.stdin.write(JSON.stringify(msg) + '\n');
  }
  call(id: number, method: string, params?: unknown): Promise<Record<string, unknown>> {
    const p = new Promise<Record<string, unknown>>((done) => this.replies.set(id, done));
    this.send({ jsonrpc: '2.0', id, method, ...(params === undefined ? {} : { params }) });
    return p;
  }
  close(): Promise<number | null> {
    const exited = new Promise<number | null>((done) => this.proc.on('exit', (code) => done(code)));
    this.proc.stdin.end();
    return exited;
  }
}

/** Builds the SDK unless dist/ has this version's files. */
function ensureSdkBuilt() {
  if (!existsSync(resolve(SDK, 'dist/esm/cli.js')) || !existsSync(resolve(SDK, 'dist/esm/agent.js'))) {
    execFileSync('npm', ['run', 'build'], { cwd: SDK, stdio: 'inherit' });
  }
}

test('agent broker: REST and the MCP stdio bridge against the real server', async ({ page }) => {
  ensureSdkBuilt();
  const seen: Seen = {};
  const upstream = await startUpstream(seen);
  const port = (upstream.address() as AddressInfo).port;
  const upstreamURL = `http://127.0.0.1:${port}`;

  try {
    await signIn(page, ORG.admin);
    await apiPost(page, '/v1/secrets', { project: 'payments', env: 'dev', key: 'BROKER_API_KEY', value: SECRET });
    await apiPost(page, '/v1/agents/credentials', {
      name: 'live-upstream', project: 'payments', env: 'dev', key: 'BROKER_API_KEY', kind: 'http_header',
      headerName: 'Authorization', headerPrefix: 'Bearer ',
      allowedHosts: [`127.0.0.1:${port}`], allowedMethods: ['GET', 'POST'], allowHttp: true, allowedCidrs: ['127.0.0.1/32']
    });
    const agent = await apiPost(page, '/v1/agents', { name: 'live-broker-agent', description: 'broker e2e' });
    const agentId = agent.agentId as string;
    const { token } = await apiPost(page, '/v1/agents/tokens', { agentId, name: 'e2e' });
    await apiPost(page, '/v1/agents/grants', { agentId, credential: 'live-upstream', actions: ['use'], maxUsesPerHour: 100 });

    // REST broker.
    const api = await pwRequest.newContext({ baseURL: BASE, extraHTTPHeaders: { Authorization: `Bearer ${token}` } });
    const res = await api.post('/v1/agent/http', { data: { credential: 'live-upstream', url: `${upstreamURL}/v1/items?page=2`, taskId: 'live-broker-1' } });
    const text = await res.text();
    expect(res.status(), text).toBe(200);
    expect(text).not.toContain(SECRET);
    const out = JSON.parse(text);
    expect(out).toMatchObject({ status: 200, redacted: true, truncated: false, bodyEncoding: 'text' });
    expect(JSON.parse(out.body)).toEqual({ ok: true, echoed: 'Bearer [REDACTED]', b64: '[REDACTED]' });
    expect(out.headers['Set-Cookie']).toBeUndefined();
    expect(seen.authorization).toBe(`Bearer ${SECRET}`);
    // Policy: another host, and a cookie instead of the token.
    const denied = await api.post('/v1/agent/http', { data: { credential: 'live-upstream', url: 'https://example.com/' } });
    expect(denied.status()).toBe(403);
    expect((await denied.json()).reason).toBe('host_not_allowed');
    const viaCookie = await page.request.post('/v1/agent/http', { data: { credential: 'live-upstream', url: `${upstreamURL}/` }, headers: { 'X-Citadel-Request': '1' } });
    expect(viaCookie.status()).toBe(401);
    // No reveal grant.
    const reveal = await api.post('/v1/agent/credentials/reveal', { data: { credential: 'live-upstream' } });
    expect(reveal.status()).toBe(403);
    await api.dispose();

    // MCP over the stdio bridge.
    const bridge = new Bridge(token);
    const init = await bridge.call(1, 'initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'live-e2e', version: '1' } });
    expect(init.result).toMatchObject({ protocolVersion: '2025-06-18', serverInfo: { name: 'citadel' } });
    bridge.send({ jsonrpc: '2.0', method: 'notifications/initialized' });
    const tools = await bridge.call(2, 'tools/list');
    const names = ((tools.result as { tools: { name: string }[] }).tools ?? []).map((t) => t.name);
    expect(names).toEqual(['list_credentials', 'http_request', 'request_access', 'get_lease']);
    const listed = await bridge.call(3, 'tools/call', { name: 'list_credentials', arguments: {} });
    expect(JSON.stringify(listed)).not.toContain(SECRET);
    expect((listed.result as { structuredContent: { credentials: { name: string }[] } }).structuredContent.credentials.map((c) => c.name)).toEqual(['live-upstream']);
    const called = await bridge.call(4, 'tools/call', { name: 'http_request', arguments: { credential: 'live-upstream', url: `${upstreamURL}/mcp-path?x=1`, taskId: 'live-mcp-1' } });
    expect(JSON.stringify(called)).not.toContain(SECRET);
    const result = called.result as { isError: boolean; structuredContent: { status: number; body: string; redacted: boolean } };
    expect(result.isError).toBe(false);
    expect(result.structuredContent).toMatchObject({ status: 200, redacted: true });
    expect(seen.path).toBe('/mcp-path?x=1');
    const refused = await bridge.call(5, 'tools/call', { name: 'http_request', arguments: { credential: 'live-upstream', url: 'https://example.com/' } });
    expect((refused.result as { isError: boolean }).isError).toBe(true);
    expect(JSON.stringify(refused.result)).toContain('host_not_allowed');
    expect(await bridge.close()).toBe(0);
    expect(bridge.stderr).not.toContain(token);

    // Audit: brokered calls with method, host, path (no query), status and
    // task ID; MCP session start and end; never the value.
    const audit = await page.request.get(`/v1/audit/events?agent=${agentId}&limit=200`);
    const auditText = await audit.text();
    expect(audit.ok()).toBeTruthy();
    expect(auditText).not.toContain(SECRET);
    const events = JSON.parse(auditText).events as { action: string; resource?: string; taskId?: string; result: string }[];
    const http = events.filter((e) => e.action === 'citadel.AgentHTTP');
    expect(http.some((e) => e.resource?.includes('via=mcp') && e.resource.includes('path=/mcp-path ') && !e.resource.includes('x=1'))).toBeTruthy();
    expect(http.some((e) => e.resource?.includes('via=api') && e.taskId === 'live-broker-1')).toBeTruthy();
    expect(events.some((e) => e.action === 'citadel.MCPInitialize')).toBeTruthy();
    expect(events.some((e) => e.action === 'citadel.MCPEndSession')).toBeTruthy();
  } finally {
    upstream.close();
  }
});

// The parts of the built SDK (dist/esm/index.js) this spec drives. Typed
// here so the web project doesn't typecheck the SDK's sources.
interface SdkError extends Error {
  status: number;
  code: string;
  reason?: string;
  requestId?: string;
  attempts: number;
}
interface HttpResult {
  ok: boolean;
  status: number;
  redacted: boolean;
  text(): string;
  json<T>(): T;
}
interface Agent {
  whoami(): Promise<{ agentId: string; taskId?: string }>;
  listCredentials(): Promise<{ name: string; usable: boolean; requiresApproval: boolean }[]>;
  http(input: { credential: string; url: string; method?: string; json?: unknown }): Promise<HttpResult>;
  reveal(credential: string): Promise<{ value: string }>;
  getAccessRequest(id: string): Promise<{ requestId: string; status: string; origin: string; lease?: { leaseId: string } }>;
  waitForAccess(id: string, opts: { intervalMs: number; signal?: AbortSignal }): Promise<{ status: string; lease?: { leaseId: string } }>;
  listLeases(input?: { credential?: string }): Promise<{ leaseId: string; credential: string; status: string }[]>;
}
interface Sdk {
  CitadelAgent: new (opts: { baseUrl: string; token: string; taskId?: string }) => Agent;
  VERSION: string;
}

test('agent broker: the TypeScript SDK (CitadelAgent) against the real server', async ({ page }) => {
  ensureSdkBuilt();
  const sdk = (await import(pathToFileURL(resolve(SDK, 'dist/esm/index.js')).href)) as Sdk;
  const seen: Seen = {};
  const upstream = await startUpstream(seen);
  const port = (upstream.address() as AddressInfo).port;
  const upstreamURL = `http://127.0.0.1:${port}`;

  try {
    await signIn(page, ORG.admin);
    await apiPost(page, '/v1/secrets', { project: 'payments', env: 'dev', key: 'SDK_BROKER_API_KEY', value: SECRET });
    for (const name of ['live-sdk-upstream', 'live-sdk-gated']) {
      await apiPost(page, '/v1/agents/credentials', {
        name, project: 'payments', env: 'dev', key: 'SDK_BROKER_API_KEY', kind: 'http_header',
        headerName: 'Authorization', headerPrefix: 'Bearer ',
        allowedHosts: [`127.0.0.1:${port}`], allowedMethods: ['GET', 'POST'], allowHttp: true, allowedCidrs: ['127.0.0.1/32']
      });
    }
    const created = await apiPost(page, '/v1/agents', { name: 'live-sdk-agent', description: 'TypeScript SDK e2e' });
    const agentId = created.agentId as string;
    const { token } = await apiPost(page, '/v1/agents/tokens', { agentId, name: 'sdk-e2e', expiresInDays: 1 });
    await apiPost(page, '/v1/agents/grants', { agentId, credential: 'live-sdk-upstream', actions: ['use'], maxUsesPerHour: 100 });
    await apiPost(page, '/v1/agents/grants', { agentId, credential: 'live-sdk-gated', actions: ['use'], requiresApproval: true, leaseTtlSeconds: 600 });

    const agent = new sdk.CitadelAgent({ baseUrl: BASE, token, taskId: 'live-sdk-1' });
    const me = await agent.whoami();
    expect(me).toMatchObject({ agentId, taskId: 'live-sdk-1' });
    const creds = await agent.listCredentials();
    expect(creds.map((c) => c.name).sort()).toEqual(['live-sdk-gated', 'live-sdk-upstream']);
    expect(creds.find((c) => c.name === 'live-sdk-gated')?.requiresApproval).toBe(true);

    // Brokered HTTP with a JSON body: the secret reaches the upstream, never the agent.
    const res = await agent.http({ credential: 'live-sdk-upstream', method: 'POST', url: `${upstreamURL}/v1/sdk?x=1`, json: { hello: 'world' } });
    expect(res.ok).toBe(true);
    expect(res.redacted).toBe(true);
    expect(res.text()).not.toContain(SECRET);
    expect(res.json<{ echoed: string }>().echoed).toBe('Bearer [REDACTED]');
    expect(seen.authorization).toBe(`Bearer ${SECRET}`);
    expect(seen.path).toBe('/v1/sdk?x=1');

    // Errors carry the stable reason.
    const denied = (await agent.http({ credential: 'live-sdk-upstream', url: 'https://example.com/' }).catch((e: unknown) => e)) as SdkError;
    expect(denied).toMatchObject({ status: 403, code: 'forbidden', reason: 'host_not_allowed', attempts: 1 });
    const noReveal = (await agent.reveal('live-sdk-upstream').catch((e: unknown) => e)) as SdkError;
    expect(noReveal).toMatchObject({ status: 403, reason: 'action_not_granted' });
    expect(JSON.stringify(noReveal)).not.toContain(token);

    // approval_required carries the request to wait for: no need to ask again.
    const gated = (await agent.http({ credential: 'live-sdk-gated', url: `${upstreamURL}/gated` }).catch((e: unknown) => e)) as SdkError;
    expect(gated).toMatchObject({ status: 403, code: 'approval_required', reason: 'approval_required' });
    const requestId = gated.requestId as string;
    expect(requestId).toMatch(/^aar_[a-z2-7]{16}$/);
    expect(await agent.getAccessRequest(requestId)).toMatchObject({ requestId, status: 'pending', origin: 'policy' });

    // A person approves once (here through the API); the agent's wait ends
    // and the retried call runs under the lease.
    const waiting = agent.waitForAccess(requestId, { intervalMs: 200, signal: AbortSignal.timeout(30_000) });
    await apiPost(page, '/v1/agents/access-requests/approve', { requestId, scope: 'once', comment: 'live sdk e2e' });
    const decided = await waiting;
    expect(decided.status).toBe('approved');
    const leaseId = decided.lease?.leaseId as string;
    expect(leaseId).toBeTruthy();
    expect((await agent.listLeases({ credential: 'live-sdk-gated' })).map((l) => l.leaseId)).toEqual([leaseId]);
    const viaLease = await agent.http({ credential: 'live-sdk-gated', url: `${upstreamURL}/gated` });
    expect(viaLease.ok).toBe(true);
    expect(seen.path).toBe('/gated');
    expect(await agent.listLeases({ credential: 'live-sdk-gated' })).toEqual([]);

    // The SDK's calls are audited with the task ID and the lease, never the value.
    const audit = await page.request.get(`/v1/audit/events?agent=${agentId}&limit=200`);
    const auditText = await audit.text();
    expect(audit.ok()).toBeTruthy();
    expect(auditText).not.toContain(SECRET);
    expect(auditText).not.toContain(token);
    const events = JSON.parse(auditText).events as { action: string; resource?: string; taskId?: string; result: string }[];
    const http = events.filter((e) => e.action === 'citadel.AgentHTTP');
    expect(http.some((e) => e.taskId === 'live-sdk-1' && e.result === 'success' && e.resource?.includes(`lease=${leaseId}`))).toBeTruthy();
  } finally {
    upstream.close();
  }
});
