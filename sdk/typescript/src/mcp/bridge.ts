/**
 * MCP stdio bridge: forwards newline-delimited JSON-RPC 2.0 messages to
 * Citadel's MCP endpoint over Streamable HTTP and writes the replies back,
 * one JSON message per line.
 *
 * The bridge is runtime-agnostic (it needs only `fetch`, `TextDecoder` and
 * streams); `cli.ts` wires it to the process's stdin and stdout.
 */

/** A JSON-RPC 2.0 id. */
type Id = string | number | null;

/** One POST: the request ids still awaiting an answer. */
interface Exchange {
  pending: Set<Id>;
  isInit: boolean;
}

interface JsonRpcMessage {
  jsonrpc?: unknown;
  id?: Id;
  method?: unknown;
  result?: unknown;
  error?: unknown;
  params?: unknown;
}

/** JSON-RPC error codes the bridge produces itself. */
export const BridgeErrorCode = {
  /** The line on stdin was not valid JSON. */
  parseError: -32700,
  /** The message was not a JSON-RPC 2.0 object. */
  invalidRequest: -32600,
  /** Citadel could not be reached or answered with an HTTP error. */
  transport: -32000,
  /** Citadel no longer knows the MCP session; the client must reconnect. */
  sessionExpired: -32001,
} as const;

export interface BridgeOptions {
  /** The full MCP endpoint, e.g. `https://citadel.example.com/mcp`. */
  endpoint: string;
  /** The agent token (`cagt_...`). Sent only as the Bearer credential. */
  token: string;
  /** Writes one line of protocol output (the bridge appends no newline). */
  write: (line: string) => void | Promise<void>;
  /** Diagnostics; never receives the token. Defaults to discarding. */
  log?: (message: string) => void;
  /** Defaults to the global `fetch`. */
  fetch?: typeof fetch;
  /** Value of the User-Agent header. */
  userAgent?: string;
}

/** The headers the MCP spec defines for Streamable HTTP. */
const SESSION_HEADER = 'Mcp-Session-Id';
const PROTOCOL_HEADER = 'MCP-Protocol-Version';

export class McpBridge {
  private readonly endpoint: string;
  private readonly token: string;
  private readonly write: (line: string) => void | Promise<void>;
  private readonly log: (message: string) => void;
  private readonly fetchFn: typeof fetch;
  private readonly userAgent: string | undefined;
  private sessionId: string | undefined;
  private protocolVersion: string | undefined;
  /** Settles when the in-flight initialize exchange has finished. */
  private initializing: Promise<void> | undefined;
  private readonly inflight = new Set<Promise<void>>();
  private closed = false;

  constructor(opts: BridgeOptions) {
    this.endpoint = opts.endpoint;
    this.token = opts.token;
    this.write = opts.write;
    this.log = opts.log ?? (() => {});
    this.fetchFn = opts.fetch ?? globalThis.fetch.bind(globalThis);
    this.userAgent = opts.userAgent;
  }

  /** The session id Citadel assigned in its initialize response, if any. */
  get session(): string | undefined {
    return this.sessionId;
  }

  /**
   * Handles one line from stdin. Messages are forwarded concurrently, except
   * that everything after an `initialize` request waits for its response so
   * that it carries the session id. The returned promise settles when the
   * message has been answered; `drain()` waits for all of them.
   */
  handleLine(line: string): Promise<void> {
    const text = line.trim();
    if (text === '') return Promise.resolve();
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      return this.emit(errorResponse(null, BridgeErrorCode.parseError, 'Parse error: stdin line is not valid JSON'));
    }
    const messages = Array.isArray(parsed) ? parsed : [parsed];
    if (messages.length === 0 || !messages.every(isObject)) {
      return this.emit(errorResponse(null, BridgeErrorCode.invalidRequest, 'Invalid Request: expected a JSON-RPC 2.0 object'));
    }
    const isInit = messages.some((m) => (m as JsonRpcMessage).method === 'initialize');
    const before = this.initializing;
    const task = (async () => {
      if (before) await before;
      await this.forward(parsed, messages as JsonRpcMessage[]);
    })();
    if (isInit) this.initializing = task.catch(() => {});
    this.inflight.add(task);
    task.then(
      () => this.inflight.delete(task),
      () => this.inflight.delete(task),
    );
    return task;
  }

  /** Waits until every message received so far has been answered. */
  async drain(): Promise<void> {
    while (this.inflight.size > 0) {
      await Promise.allSettled([...this.inflight]);
    }
  }

  /**
   * Waits for in-flight messages, then ends the MCP session with an HTTP
   * DELETE (when Citadel assigned one). Failures are logged, not thrown.
   */
  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    await this.drain();
    if (!this.sessionId) return;
    try {
      const res = await this.fetchFn(this.endpoint, { method: 'DELETE', headers: this.headers(false) });
      // 405 means the server doesn't let clients end sessions; that's fine.
      if (!res.ok && res.status !== 405 && res.status !== 404) {
        this.log(`ending the MCP session failed: HTTP ${res.status}`);
      }
      await res.body?.cancel().catch(() => {});
    } catch (err) {
      this.log(`ending the MCP session failed: ${describe(err)}`);
    }
    this.sessionId = undefined;
  }

  private headers(withBody: boolean): Headers {
    const h = new Headers();
    h.set('Accept', 'application/json, text/event-stream');
    h.set('Authorization', `Bearer ${this.token}`);
    if (withBody) h.set('Content-Type', 'application/json');
    if (this.sessionId) h.set(SESSION_HEADER, this.sessionId);
    if (this.protocolVersion) h.set(PROTOCOL_HEADER, this.protocolVersion);
    if (this.userAgent) h.set('User-Agent', this.userAgent);
    return h;
  }

  private async forward(body: unknown, messages: JsonRpcMessage[]): Promise<void> {
    // Requests are the messages the client expects an answer to.
    const isInit = messages.some((m) => m.method === 'initialize');
    const ex: Exchange = { pending: new Set<Id>(messages.filter(isRequest).map((m) => m.id as Id)), isInit };
    const pending = ex.pending;
    const sentSession = this.sessionId;

    let res: Response;
    try {
      res = await this.fetchFn(this.endpoint, { method: 'POST', headers: this.headers(true), body: JSON.stringify(body) });
    } catch (err) {
      this.log(`cannot reach Citadel: ${describe(err)}`);
      await this.failAll(pending, BridgeErrorCode.transport, 'Cannot reach Citadel');
      return;
    }

    if (isInit && res.ok) {
      const sid = res.headers.get(SESSION_HEADER);
      if (sid) this.sessionId = sid;
    }

    if (res.status === 202 || res.status === 204) {
      await res.body?.cancel().catch(() => {});
      if (pending.size > 0) {
        this.log(`Citadel accepted a request without answering it (HTTP ${res.status})`);
        await this.failAll(pending, BridgeErrorCode.transport, 'Citadel returned no response');
      }
      return;
    }

    const type = (res.headers.get('Content-Type') ?? '').split(';')[0]!.trim().toLowerCase();

    if (!res.ok) {
      if (res.status === 404 && sentSession && !isInit) {
        // The spec says a 404 on a session means it has ended; the client
        // has to start over with a new initialize.
        this.sessionId = undefined;
        this.protocolVersion = undefined;
        await res.body?.cancel().catch(() => {});
        this.log('the MCP session has expired; the client must reconnect');
        await this.failAll(pending, BridgeErrorCode.sessionExpired, 'MCP session expired; restart the MCP client to reconnect');
        return;
      }
      // Citadel answers protocol errors as JSON-RPC error objects; pass those
      // through. Anything else becomes a transport error.
      if (type === 'application/json') {
        const replied = await this.relayJson(res, ex).catch(() => false);
        if (replied && pending.size === 0) return;
      } else {
        await res.body?.cancel().catch(() => {});
      }
      this.log(`Citadel returned HTTP ${res.status}`);
      await this.failAll(pending, BridgeErrorCode.transport, httpMessage(res.status), { httpStatus: res.status });
      return;
    }

    try {
      if (type === 'text/event-stream') {
        await this.relaySse(res, ex);
      } else if (type === 'application/json') {
        await this.relayJson(res, ex);
      } else {
        await res.body?.cancel().catch(() => {});
        this.log(`Citadel answered with an unexpected content type (HTTP ${res.status})`);
      }
    } catch (err) {
      this.log(`reading Citadel's response failed: ${describe(err)}`);
    }
    if (pending.size > 0) {
      await this.failAll(pending, BridgeErrorCode.transport, 'Citadel returned an incomplete response');
    }
  }

  /** Relays a JSON body. Returns whether it contained JSON-RPC messages. */
  private async relayJson(res: Response, ex: Exchange): Promise<boolean> {
    const text = await res.text();
    if (text.trim() === '') return false;
    const value = JSON.parse(text) as unknown;
    return this.relayValue(value, ex);
  }

  private async relayValue(value: unknown, ex: Exchange): Promise<boolean> {
    const items = Array.isArray(value) ? value : [value];
    if (items.length === 0 || !items.every((m) => isObject(m) && m.jsonrpc === '2.0')) return false;
    for (const m of items as JsonRpcMessage[]) this.observe(m, ex);
    await this.emit(value);
    return true;
  }

  /** Reads a `text/event-stream` body and relays each event's data. */
  private async relaySse(res: Response, ex: Exchange): Promise<void> {
    if (!res.body) return;
    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';
    let data: string[] = [];
    let event = '';
    const dispatch = async () => {
      const payload = data.join('\n');
      const kind = event;
      data = [];
      event = '';
      if (payload === '' || (kind !== '' && kind !== 'message')) return;
      let value: unknown;
      try {
        value = JSON.parse(payload);
      } catch {
        this.log('skipped a server-sent event that is not JSON');
        return;
      }
      if (!(await this.relayValue(value, ex))) this.log('skipped a server-sent event that is not JSON-RPC');
    };
    const onLine = async (line: string) => {
      if (line === '') return dispatch();
      if (line.startsWith(':')) return; // comment / keep-alive
      const colon = line.indexOf(':');
      const field = colon < 0 ? line : line.slice(0, colon);
      let val = colon < 0 ? '' : line.slice(colon + 1);
      if (val.startsWith(' ')) val = val.slice(1);
      if (field === 'data') data.push(val);
      else if (field === 'event') event = val;
      // "id" and "retry" only matter for resuming a stream; the bridge
      // doesn't resume, so they are ignored.
    };
    try {
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        let nl: number;
        while ((nl = buffer.search(/\r\n|\r|\n/)) >= 0) {
          const line = buffer.slice(0, nl);
          buffer = buffer.slice(nl + (buffer[nl] === '\r' && buffer[nl + 1] === '\n' ? 2 : 1));
          await onLine(line);
        }
        // The stream answers this POST; stop once every request is answered.
        if (ex.pending.size === 0) break;
      }
      buffer += decoder.decode();
      if (buffer !== '') await onLine(buffer);
      await dispatch();
    } finally {
      await reader.cancel().catch(() => {});
    }
  }

  /** Notes answered requests and the negotiated protocol version. */
  private observe(m: JsonRpcMessage, ex: Exchange) {
    if (m.method !== undefined || !('id' in m) || !ex.pending.has(m.id as Id)) return;
    ex.pending.delete(m.id as Id);
    const result = m.result as { protocolVersion?: unknown } | undefined;
    if (ex.isInit && isObject(result) && typeof result.protocolVersion === 'string') {
      this.protocolVersion = result.protocolVersion;
    }
  }

  private async failAll(pending: Set<Id>, code: number, message: string, data?: Record<string, unknown>) {
    for (const id of [...pending]) {
      pending.delete(id);
      await this.emit(errorResponse(id, code, message, data));
    }
  }

  private async emit(value: unknown): Promise<void> {
    // JSON.stringify never emits raw newlines, so this is exactly one line.
    await this.write(JSON.stringify(value));
  }
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function isRequest(m: JsonRpcMessage): boolean {
  return typeof m.method === 'string' && 'id' in m && m.id !== undefined && m.id !== null;
}

function errorResponse(id: Id, code: number, message: string, data?: Record<string, unknown>) {
  return { jsonrpc: '2.0', id, error: data ? { code, message, data } : { code, message } };
}

function httpMessage(status: number): string {
  switch (status) {
    case 401:
      return 'Citadel rejected the agent token (HTTP 401); check CITADEL_AGENT_TOKEN';
    case 403:
      return 'Citadel refused the request (HTTP 403)';
    case 429:
      return 'Citadel rate-limited the request (HTTP 429)';
    default:
      return `Citadel returned HTTP ${status}`;
  }
}

/** A short description of a fetch failure, without request details. */
function describe(err: unknown): string {
  if (err instanceof Error) {
    const cause = (err as { cause?: unknown }).cause;
    const code = isObject(cause) && typeof cause.code === 'string' ? ` (${cause.code})` : '';
    return `${err.name}: ${err.message}${code}`;
  }
  return 'unknown error';
}
