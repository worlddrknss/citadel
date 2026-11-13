// Unit tests for the MCP stdio bridge against a fake Streamable HTTP server.
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { BridgeErrorCode, McpBridge } from '../src/mcp/bridge.js';
import { lines, mcpEndpoint, parseMcpArgs } from '../src/mcp/config.js';

const TOKEN = 'cagt_agent1_s3cr3t-token-value';

interface Seen {
  method: string;
  headers: IncomingMessage['headers'];
  body: unknown;
}

type Route = (msg: Record<string, unknown> | unknown[], res: ServerResponse, req: IncomingMessage) => void;

let server: Server;
let base: string;
let seen: Seen[];
let route: Route;

function sendJson(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}) {
  res.writeHead(status, { 'Content-Type': 'application/json', ...headers });
  res.end(JSON.stringify(body));
}

beforeEach(async () => {
  seen = [];
  route = (_m, res) => {
    res.writeHead(500);
    res.end();
  };
  server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      const text = Buffer.concat(chunks).toString('utf8');
      const body = text ? (JSON.parse(text) as Record<string, unknown>) : undefined;
      seen.push({ method: req.method ?? '', headers: req.headers, body });
      if (req.method === 'DELETE') {
        res.writeHead(204);
        res.end();
        return;
      }
      route(body as Record<string, unknown>, res, req);
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}/mcp`;
});

afterEach(async () => {
  server.closeAllConnections();
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

function bridge(endpoint = base) {
  const out: unknown[] = [];
  const raw: string[] = [];
  const logs: string[] = [];
  const b = new McpBridge({
    endpoint,
    token: TOKEN,
    write: (line) => {
      raw.push(line);
      out.push(JSON.parse(line));
    },
    log: (m) => logs.push(m),
  });
  return { b, out, raw, logs };
}

const init = { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 't', version: '1' } } };
const initResult = { jsonrpc: '2.0', id: 1, result: { protocolVersion: '2025-06-18', capabilities: { tools: {} }, serverInfo: { name: 'citadel', version: '2.2.0' } } };

/** A server that hands out a session on initialize and echoes tool lists. */
function standardRoutes(extra?: Route): Route {
  return (m, res, req) => {
    const msg = m as Record<string, unknown>;
    if (msg.method === 'initialize') return sendJson(res, 200, initResult, { 'Mcp-Session-Id': 'sess-123' });
    if (msg.id === undefined) {
      res.writeHead(202);
      return res.end();
    }
    if (extra) return extra(m, res, req);
    sendJson(res, 200, { jsonrpc: '2.0', id: msg.id, result: { tools: [] } });
  };
}

describe('McpBridge', () => {
  it('relays JSON replies and carries the session and protocol headers', async () => {
    route = standardRoutes();
    const { b, out, raw } = bridge();
    await b.handleLine(JSON.stringify(init));
    await b.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list' }));
    expect(out).toEqual([initResult, { jsonrpc: '2.0', id: 2, result: { tools: [] } }]);
    expect(raw.every((l) => !l.includes('\n'))).toBe(true);
    expect(b.session).toBe('sess-123');

    const [first, second] = seen;
    expect(first!.method).toBe('POST');
    expect(first!.headers.authorization).toBe(`Bearer ${TOKEN}`);
    expect(first!.headers.accept).toBe('application/json, text/event-stream');
    expect(first!.headers['content-type']).toBe('application/json');
    expect(first!.headers['mcp-session-id']).toBeUndefined();
    expect(second!.headers['mcp-session-id']).toBe('sess-123');
    expect(second!.headers['mcp-protocol-version']).toBe('2025-06-18');
    expect(second!.body).toEqual({ jsonrpc: '2.0', id: 2, method: 'tools/list' });
  });

  it('holds messages sent right after initialize until the session exists', async () => {
    route = (m, res, req) => {
      if ((m as Record<string, unknown>).method === 'initialize') {
        setTimeout(() => standardRoutes()(m, res, req), 50);
        return;
      }
      standardRoutes()(m, res, req);
    };
    const { b, out } = bridge();
    void b.handleLine(JSON.stringify(init));
    void b.handleLine(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }));
    void b.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list' }));
    await b.drain();
    expect(seen.map((s) => s.headers['mcp-session-id'])).toEqual([undefined, 'sess-123', 'sess-123']);
    expect(out).toHaveLength(2);
  });

  it('relays every event of an SSE reply stream', async () => {
    route = standardRoutes((m, res) => {
      const id = (m as Record<string, unknown>).id;
      res.writeHead(200, { 'Content-Type': 'text/event-stream; charset=utf-8' });
      res.write(': keep-alive\n\n');
      res.write('event: message\r\nid: 1\r\n');
      res.write('data: {"jsonrpc":"2.0","method":"notifications/progress",\r\n');
      res.write('data: "params":{"progress":1}}\r\n\r\n');
      setTimeout(() => {
        res.write(`data: ${JSON.stringify({ jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: 'ok\nline' }] } })}\n\n`);
        // The stream may stay open; the bridge stops once the request is answered.
      }, 20);
    });
    const { b, out, raw } = bridge();
    await b.handleLine(JSON.stringify(init));
    await b.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 'call-1', method: 'tools/call', params: { name: 'list_credentials' } }));
    expect(out.slice(1)).toEqual([
      { jsonrpc: '2.0', method: 'notifications/progress', params: { progress: 1 } },
      { jsonrpc: '2.0', id: 'call-1', result: { content: [{ type: 'text', text: 'ok\nline' }] } },
    ]);
    expect(raw.every((l) => !l.includes('\n'))).toBe(true);
  });

  it('handles an SSE stream whose last event has no trailing blank line', async () => {
    route = standardRoutes((m, res) => {
      res.writeHead(200, { 'Content-Type': 'text/event-stream' });
      res.end(`data: ${JSON.stringify({ jsonrpc: '2.0', id: (m as Record<string, unknown>).id, result: {} })}`);
    });
    const { b, out } = bridge();
    await b.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 5, method: 'ping' }));
    expect(out).toEqual([{ jsonrpc: '2.0', id: 5, result: {} }]);
  });

  it('writes nothing for notifications answered with 202', async () => {
    route = standardRoutes();
    const { b, out } = bridge();
    await b.handleLine(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/cancelled', params: { requestId: 3 } }));
    expect(out).toEqual([]);
    expect(seen).toHaveLength(1);
  });

  it('ignores blank lines and answers malformed ones with JSON-RPC errors', async () => {
    const { b, out } = bridge();
    await b.handleLine('   ');
    await b.handleLine('{not json');
    await b.handleLine('42');
    expect(seen).toHaveLength(0);
    expect(out).toEqual([
      { jsonrpc: '2.0', id: null, error: { code: BridgeErrorCode.parseError, message: expect.any(String) } },
      { jsonrpc: '2.0', id: null, error: { code: BridgeErrorCode.invalidRequest, message: expect.any(String) } },
    ]);
  });

  it('maps an unreachable server to an error for requests only', async () => {
    const { b, out, logs } = bridge('http://127.0.0.1:1/mcp');
    await b.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 7, method: 'tools/list' }));
    await b.handleLine(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }));
    expect(out).toEqual([{ jsonrpc: '2.0', id: 7, error: { code: BridgeErrorCode.transport, message: 'Cannot reach Citadel' } }]);
    expect(logs.length).toBeGreaterThan(0);
    expect(logs.join('\n')).not.toContain(TOKEN);
  });

  it('maps HTTP errors to JSON-RPC errors without leaking the body or token', async () => {
    route = (_m, res) => sendJson(res, 401, { error: 'unauthorized', message: `bad token ${TOKEN}` });
    const { b, out, raw, logs } = bridge();
    await b.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }));
    expect(out).toEqual([
      { jsonrpc: '2.0', id: 1, error: { code: BridgeErrorCode.transport, message: expect.stringContaining('401'), data: { httpStatus: 401 } } },
    ]);
    expect(raw.join('\n') + logs.join('\n')).not.toContain(TOKEN);
  });

  it('maps a 5xx with a non-JSON body to an error', async () => {
    route = (_m, res) => {
      res.writeHead(502, { 'Content-Type': 'text/html' });
      res.end('<h1>Bad gateway</h1>');
    };
    const { b, out } = bridge();
    await b.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'ping' }));
    expect(out).toEqual([{ jsonrpc: '2.0', id: 1, error: { code: BridgeErrorCode.transport, message: 'Citadel returned HTTP 502', data: { httpStatus: 502 } } }]);
  });

  it('passes through JSON-RPC errors sent with an HTTP error status', async () => {
    route = (m, res) => sendJson(res, 400, { jsonrpc: '2.0', id: (m as Record<string, unknown>).id, error: { code: -32602, message: 'Invalid params' } });
    const { b, out } = bridge();
    await b.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 9, method: 'tools/call', params: {} }));
    expect(out).toEqual([{ jsonrpc: '2.0', id: 9, error: { code: -32602, message: 'Invalid params' } }]);
  });

  it('reports an expired session (404) and forgets it', async () => {
    route = standardRoutes((_m, res) => sendJson(res, 404, { error: 'not_found' }));
    const { b, out } = bridge();
    await b.handleLine(JSON.stringify(init));
    await b.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list' }));
    expect(out[1]).toEqual({ jsonrpc: '2.0', id: 2, error: { code: BridgeErrorCode.sessionExpired, message: expect.any(String) } });
    expect(b.session).toBeUndefined();
  });

  it('answers a request the server left unanswered', async () => {
    route = (_m, res) => sendJson(res, 200, { unexpected: true });
    const { b, out } = bridge();
    await b.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 3, method: 'ping' }));
    expect(out).toEqual([{ jsonrpc: '2.0', id: 3, error: { code: BridgeErrorCode.transport, message: 'Citadel returned an incomplete response' } }]);
  });

  it('ends the session with DELETE on close', async () => {
    route = standardRoutes();
    const { b } = bridge();
    await b.handleLine(JSON.stringify(init));
    await b.close();
    const del = seen.find((s) => s.method === 'DELETE');
    expect(del?.headers['mcp-session-id']).toBe('sess-123');
    expect(del?.headers.authorization).toBe(`Bearer ${TOKEN}`);
    await b.close(); // idempotent
    expect(seen.filter((s) => s.method === 'DELETE')).toHaveLength(1);
  });

  it('sends no DELETE when no session was assigned', async () => {
    route = (m, res) => sendJson(res, 200, { ...initResult, id: (m as Record<string, unknown>).id });
    const { b } = bridge();
    await b.handleLine(JSON.stringify(init));
    await b.close();
    expect(seen.some((s) => s.method === 'DELETE')).toBe(false);
  });

  it('waits for in-flight requests before closing', async () => {
    route = standardRoutes((m, res) => {
      setTimeout(() => sendJson(res, 200, { jsonrpc: '2.0', id: (m as Record<string, unknown>).id, result: {} }), 50);
    });
    const { b, out } = bridge();
    await b.handleLine(JSON.stringify(init));
    void b.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'ping' }));
    await b.close();
    expect(out).toHaveLength(2);
    expect(seen.at(-1)!.method).toBe('DELETE');
  });
});

describe('parseMcpArgs', () => {
  const env = { CITADEL_URL: 'https://citadel.example.com', CITADEL_AGENT_TOKEN: TOKEN };

  it('reads the URL and token from the environment', () => {
    expect(parseMcpArgs([], env)).toEqual({
      kind: 'run',
      config: { endpoint: 'https://citadel.example.com/mcp', token: TOKEN, tokenEnv: 'CITADEL_AGENT_TOKEN' },
    });
  });

  it('accepts --url and --token-env in both forms', () => {
    const r = parseMcpArgs(['--url', 'https://other.example/', '--token-env=MY_TOKEN'], { MY_TOKEN: 'cagt_x_y' });
    expect(r).toEqual({ kind: 'run', config: { endpoint: 'https://other.example/mcp', token: 'cagt_x_y', tokenEnv: 'MY_TOKEN' } });
  });

  it('rejects a token on the command line and never echoes it', () => {
    const r = parseMcpArgs(['--token', TOKEN], env);
    expect(r.kind).toBe('error');
    expect(JSON.stringify(r)).not.toContain(TOKEN);
  });

  it('explains missing configuration', () => {
    expect(parseMcpArgs([], {})).toEqual({ kind: 'error', message: expect.stringContaining('CITADEL_URL') });
    expect(parseMcpArgs([], { CITADEL_URL: 'https://c.example' })).toEqual({ kind: 'error', message: expect.stringContaining('CITADEL_AGENT_TOKEN') });
    expect(parseMcpArgs(['--token-env', 'bad-name'], env).kind).toBe('error');
    expect(parseMcpArgs(['--url'], env).kind).toBe('error');
    expect(parseMcpArgs(['--bogus'], env).kind).toBe('error');
    expect(parseMcpArgs(['--help'], env)).toEqual({ kind: 'help' });
  });
});

describe('mcpEndpoint', () => {
  it('appends /mcp once and drops query and fragment', () => {
    expect(mcpEndpoint('https://c.example')).toBe('https://c.example/mcp');
    expect(mcpEndpoint('https://c.example/citadel/')).toBe('https://c.example/citadel/mcp');
    expect(mcpEndpoint('https://c.example/mcp')).toBe('https://c.example/mcp');
    expect(mcpEndpoint('https://c.example/?a=1#x')).toBe('https://c.example/mcp');
  });

  it('requires https except on loopback', () => {
    expect(mcpEndpoint('http://citadel.example.com')).toEqual({ error: expect.any(String) });
    expect(mcpEndpoint('http://localhost:8080')).toBe('http://localhost:8080/mcp');
    expect(mcpEndpoint('http://127.0.0.1:8080')).toBe('http://127.0.0.1:8080/mcp');
    expect(mcpEndpoint('http://[::1]:8080')).toBe('http://[::1]:8080/mcp');
    expect(mcpEndpoint('ftp://c.example')).toEqual({ error: expect.any(String) });
    expect(mcpEndpoint('https://user:pw@c.example')).toEqual({ error: expect.any(String) });
    expect(mcpEndpoint('not a url')).toEqual({ error: expect.any(String) });
  });
});

describe('lines', () => {
  it('splits chunks on newlines, across chunk and UTF-8 boundaries', async () => {
    const enc = new TextEncoder().encode('{"a":"é"}\r\n{"b":2}\n\n{"c":3}');
    async function* chunks() {
      for (let i = 0; i < enc.length; i += 3) yield enc.slice(i, i + 3);
    }
    const got: string[] = [];
    for await (const l of lines(chunks())) got.push(l);
    expect(got).toEqual(['{"a":"é"}', '{"b":2}', '', '{"c":3}']);
  });
});
