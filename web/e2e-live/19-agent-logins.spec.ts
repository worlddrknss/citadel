import { execFileSync, spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { createServer, type IncomingMessage, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { dirname, resolve } from 'node:path';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import { request as pwRequest } from '@playwright/test';
import { BASE } from './playwright.config';
import { ORG, apiPost, expect, open, signIn, test } from './fixtures';

// Agents 2.4 end to end against the real server (FIPS mode):
//   - a login credential with a SHA-256 TOTP seed, used through the
//     TypeScript SDK's MCP stdio bridge (get_totp_code, get_login);
//   - a SHA-1 seed refused with the FIPS explanation;
//   - an oauth2_client_credentials credential minting a token from a local
//     fake token endpoint (loopback allowed through allowedCidrs), injected
//     into a brokered request and cached;
//   - the console's live TOTP preview in the secret drawer.

const SDK = resolve(dirname(fileURLToPath(import.meta.url)), '../../sdk/typescript');
const PASSWORD = 'live-login-password-9c1e';
const SEED = 'otpauth://totp/Shop:bot?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&algorithm=SHA256&digits=6&period=30';
const CLIENT_SECRET = 'live-oauth-client-secret-41f7';
const MINTED = 'live-minted-access-token-77aa';

class Bridge {
  private replies = new Map<number, (m: Record<string, unknown>) => void>();
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

function listen(handler: (req: IncomingMessage, body: string) => { status: number; json: unknown }): Promise<Server> {
  const srv = createServer((req, res) => {
    let body = '';
    req.on('data', (d: Buffer) => (body += d.toString()));
    req.on('end', () => {
      const out = handler(req, body);
      res.statusCode = out.status;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify(out.json));
    });
  });
  return new Promise((done) => srv.listen(0, '127.0.0.1', () => done(srv)));
}

const port = (s: Server) => (s.address() as AddressInfo).port;

test('login credentials over MCP, a minted OAuth token and the console TOTP preview', async ({ page, expectStatus }) => {
  expectStatus(400, /\/v1\/agents\/credentials\/login/);
  if (!existsSync(resolve(SDK, 'dist/esm/cli.js'))) {
    execFileSync('npm', ['run', 'build'], { cwd: SDK, stdio: 'inherit' });
  }
  let tokenCalls = 0;
  const tokenSrv = await listen((req) => {
    tokenCalls++;
    const ok = req.headers.authorization === `Basic ${Buffer.from(`live-client:${CLIENT_SECRET}`).toString('base64')}`;
    return ok ? { status: 200, json: { access_token: MINTED, token_type: 'Bearer', expires_in: 3600 } } : { status: 401, json: { error: 'invalid_client' } };
  });
  let seenAuth = '';
  const upstream = await listen((req) => {
    seenAuth = req.headers.authorization ?? '';
    return { status: 200, json: { ok: true } };
  });

  try {
    await signIn(page, ORG.admin);
    // A login with a SHA-256 seed; a SHA-1 seed is refused.
    await apiPost(page, '/v1/secrets', { project: 'payments', env: 'dev', key: 'SHOP_LOGIN', value: JSON.stringify({ username: 'bot@shop.example', password: PASSWORD }) });
    await apiPost(page, '/v1/agents/credentials', {
      name: 'live-shop-login', project: 'payments', env: 'dev', key: 'SHOP_LOGIN', kind: 'login',
      login: { urlPatterns: ['https://shop.example.com/login'] }
    });
    const sha1 = await page.request.post('/v1/agents/credentials/login', {
      data: { name: 'live-shop-login', totpSeed: 'otpauth://totp/x?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP' },
      headers: { 'X-Citadel-Request': '1' }
    });
    expect(sha1.status()).toBe(400);
    expect(await sha1.json()).toMatchObject({ error: 'totp_sha1_unsupported' });
    await apiPost(page, '/v1/agents/credentials/login', { name: 'live-shop-login', totpSeed: SEED });

    // An OAuth client minted against the local token endpoint.
    await apiPost(page, '/v1/secrets', { project: 'payments', env: 'dev', key: 'OAUTH_CLIENT', value: CLIENT_SECRET });
    await apiPost(page, '/v1/agents/credentials', {
      name: 'live-oauth', project: 'payments', env: 'dev', key: 'OAUTH_CLIENT', kind: 'oauth2_client_credentials',
      allowedHosts: [`127.0.0.1:${port(upstream)}`], allowHttp: true, allowedCidrs: ['127.0.0.1/32'],
      oauth2: { tokenUrl: `http://127.0.0.1:${port(tokenSrv)}/token`, clientId: 'live-client' }
    });

    const agent = await apiPost(page, '/v1/agents', { name: 'live-browser-agent', description: 'logins e2e' });
    const agentId = agent.agentId as string;
    const { token } = await apiPost(page, '/v1/agents/tokens', { agentId, name: 'e2e' });
    await apiPost(page, '/v1/agents/grants', { agentId, credential: 'live-shop-login', actions: ['totp', 'reveal'] });
    await apiPost(page, '/v1/agents/grants', { agentId, credential: 'live-oauth', actions: ['use', 'reveal'] });

    // MCP over the stdio bridge.
    const bridge = new Bridge(token);
    await bridge.call(1, 'initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'live-e2e', version: '1' } });
    bridge.send({ jsonrpc: '2.0', method: 'notifications/initialized' });
    const tools = await bridge.call(2, 'tools/list');
    const names = ((tools.result as { tools: { name: string }[] }).tools ?? []).map((t) => t.name);
    expect(names).toEqual(expect.arrayContaining(['get_totp_code', 'get_login', 'reveal_credential']));
    const code = await bridge.call(3, 'tools/call', { name: 'get_totp_code', arguments: { credential: 'live-shop-login', taskId: 'live-login-1' } });
    const codeOut = (code.result as { isError: boolean; structuredContent: { code: string; secondsRemaining: number; algorithm: string } });
    expect(codeOut.isError).toBe(false);
    expect(codeOut.structuredContent.code).toMatch(/^\d{6}$/);
    expect(codeOut.structuredContent.algorithm).toBe('SHA256');
    expect(JSON.stringify(code)).not.toContain('JBSWY3DP');
    const login = await bridge.call(4, 'tools/call', { name: 'get_login', arguments: { credential: 'live-shop-login', url: 'https://shop.example.com/login?next=/cart' } });
    expect((login.result as { structuredContent: { username: string; password: string } }).structuredContent).toMatchObject({ username: 'bot@shop.example', password: PASSWORD });
    const elsewhere = await bridge.call(5, 'tools/call', { name: 'get_login', arguments: { credential: 'live-shop-login', url: 'https://evil.example.com/login' } });
    expect((elsewhere.result as { isError: boolean }).isError).toBe(true);
    expect(JSON.stringify(elsewhere.result)).toContain('url_not_allowed');
    expect(JSON.stringify(elsewhere.result)).not.toContain(PASSWORD);
    expect(await bridge.close()).toBe(0);
    expect(bridge.stderr).not.toContain(token);

    // The minted OAuth token: injected into brokered requests, cached, and
    // revealed with its expiry, never the client secret.
    const api = await pwRequest.newContext({ baseURL: BASE, extraHTTPHeaders: { Authorization: `Bearer ${token}` } });
    for (let i = 0; i < 2; i++) {
      const res = await api.post('/v1/agent/http', { data: { credential: 'live-oauth', url: `http://127.0.0.1:${port(upstream)}/items` } });
      expect(res.status(), await res.text()).toBe(200);
    }
    expect(seenAuth).toBe(`Bearer ${MINTED}`);
    expect(tokenCalls).toBe(1);
    const revealed = await api.post('/v1/agent/credentials/reveal', { data: { credential: 'live-oauth' } });
    const rv = await revealed.json();
    expect(rv).toMatchObject({ kind: 'oauth2_client_credentials', value: MINTED });
    expect(rv.expiresAt).toBeTruthy();
    expect(JSON.stringify(rv)).not.toContain(CLIENT_SECRET);
    await api.dispose();

    // Audit: TOTP and logins recorded, never the values.
    const audit = await page.request.get(`/v1/audit/events?agent=${agentId}&limit=200`);
    const auditText = await audit.text();
    expect(auditText).not.toContain(PASSWORD);
    expect(auditText).not.toContain(MINTED);
    const events = JSON.parse(auditText).events as { action: string; resource?: string; taskId?: string; result: string }[];
    expect(events.some((e) => e.action === 'citadel.AgentTOTP' && e.taskId === 'live-login-1')).toBeTruthy();
    expect(events.some((e) => e.action === 'citadel.AgentGetLogin' && e.resource?.includes('host=shop.example.com path=/login ') && !e.resource.includes('next='))).toBeTruthy();

    // The console: login fields and the live code preview.
    await open(page, '/secrets/payments/dev?secret=SHOP_LOGIN&tab=agents');
    const form = page.getByRole('form', { name: 'Login live-shop-login' });
    await expect(form.getByLabel('Username')).toHaveValue('bot@shop.example');
    await expect(form.getByText('Configured')).toBeVisible();
    await form.getByRole('button', { name: 'Show current code' }).click();
    await expect(form.getByLabel('Current code')).toHaveText(/^\d{6}$/);
  } finally {
    tokenSrv.close();
    upstream.close();
  }
});
