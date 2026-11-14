import { base64ToBytes, bytesToBase64, utf8Decode, utf8Encode } from './base64.js';
import { buildTransport, env, type TransportOptions } from './client.js';
import { assertServerRuntime } from './guard.js';
import { call, defaultSleep, type CallSpec, type RequestOptions, type TransportConfig } from './http.js';
import type {
  AgentAccessRequest,
  AgentAccessRequestInput,
  AgentHttpInput,
  AgentHttpRequestBody,
  AgentHttpResponseBody,
  AgentLease,
  AgentLogin,
  AgentRevealResult,
  AgentTotpCode,
  AgentUsableCredential,
  AgentWhoAmI,
} from './types.js';

/** Options for {@link CitadelAgent}. */
export interface CitadelAgentOptions extends TransportOptions {
  /**
   * The agent's token: a `cagt_...` token from the console, or a JWT from
   * an identity provider bound to the agent (workload federation).
   * Defaults to the `CITADEL_AGENT_TOKEN` environment variable. It is sent
   * only in the Authorization header and never appears in errors.
   */
  token?: string;
  /**
   * The agent's task or session ID, sent as `X-Citadel-Task-Id` on every
   * call and recorded on audit events (1-128 of letters, digits and
   * `-_.:/@#+=`). Task-scoped approvals are bound to it.
   */
  taskId?: string;
  /**
   * Names the agent (`X-Citadel-Agent-Id`) when a federated identity is
   * bound to more than one agent. Not needed with a `cagt_` token.
   */
  agentId?: string;
}

/** Options for {@link CitadelAgent.waitForAccess}. */
export interface WaitForAccessOptions extends RequestOptions {
  /** Delay between polls in milliseconds (default 5000). */
  intervalMs?: number;
}

/**
 * Client for Citadel's Agent API (`/v1/agent/*`), authenticated with an
 * agent token. Agents use credentials without holding them: {@link http}
 * has Citadel make the request with the credential injected.
 *
 * Server-only, like {@link Citadel}: it throws if constructed in a browser.
 *
 * ```ts
 * const agent = new CitadelAgent({ baseUrl: 'https://citadel.example.com', token: process.env.CITADEL_AGENT_TOKEN });
 * const res = await agent.http({ credential: 'github', url: 'https://api.github.com/user' });
 * const user = res.json<{ login: string }>();
 * ```
 *
 * Failures throw {@link CitadelError}: `code` is the API's error code and
 * `reason` the stable denial or failure reason (`no_grant`,
 * `host_not_allowed`, `upstream_timeout`, ...). A grant that requires
 * approval throws `approval_required` with `requestId`; pass it to
 * {@link waitForAccess} and retry once approved.
 *
 * Calls that may act (http, reveal, getTotpCode, getLogin, requestAccess
 * are POSTs) are retried only after 429 or 503 with Retry-After, which the
 * server answers before acting, never after a 5xx or timeout that may have
 * reached the upstream, unless the call sets `retryNonIdempotent: true`.
 */
export class CitadelAgent {
  readonly baseUrl: string;
  // Private, so the token never shows up when the client is logged or
  // inspected.
  readonly #transport: TransportConfig;

  constructor(options: CitadelAgentOptions = {}) {
    assertServerRuntime();
    const token = (options.token ?? env('CITADEL_AGENT_TOKEN') ?? '').trim();
    if (!token) {
      throw new TypeError('CitadelAgent: token is required (or set CITADEL_AGENT_TOKEN)');
    }
    if (/[\s\0-\x1f\x7f]/.test(token)) {
      throw new TypeError('CitadelAgent: token must not contain whitespace or control characters');
    }
    const headers: Record<string, string> = { ...options.headers };
    if (options.taskId) headers['X-Citadel-Task-Id'] = options.taskId;
    if (options.agentId) headers['X-Citadel-Agent-Id'] = options.agentId;
    this.#transport = buildTransport('CitadelAgent', { ...options, headers }, `Bearer ${token}`);
    this.baseUrl = this.#transport.baseUrl;
  }

  /** Low-level call to any Agent API operation; prefer the typed methods. */
  request<T>(spec: CallSpec, opts?: RequestOptions): Promise<T> {
    return call<T>(this.#transport, spec, opts);
  }

  /** The calling agent: ID, name, owner, account, status and how it authenticated. */
  whoami(opts?: RequestOptions): Promise<AgentWhoAmI> {
    return this.request<AgentWhoAmI>({ method: 'GET', path: '/v1/agent/whoami' }, opts);
  }

  /**
   * The credentials the agent has grants for, with what it may do with
   * each (`usable`, `reason`, allowed hosts and methods). Never values.
   */
  async listCredentials(opts?: RequestOptions): Promise<AgentUsableCredential[]> {
    return (await this.request<{ credentials: AgentUsableCredential[] }>({ method: 'GET', path: '/v1/agent/credentials' }, opts)).credentials;
  }

  /**
   * Brokered HTTP: Citadel performs the request with the credential
   * injected and returns the upstream's response, filtered and with the
   * secret redacted. An upstream error status is a successful call; check
   * `res.ok` or `res.status`.
   *
   * Not retried after a 5xx or timeout (the upstream may have acted)
   * unless `opts.retryNonIdempotent` is set.
   */
  async http(input: AgentHttpInput, opts?: RequestOptions): Promise<AgentHttpResult> {
    const res = await this.request<AgentHttpResponseBody>({ method: 'POST', path: '/v1/agent/http', body: encodeHttpInput(input) }, opts);
    return new AgentHttpResult(res);
  }

  /**
   * Reveals a credential's value (needs a grant with the `reveal` action,
   * or an approved lease). Prefer {@link http}. Minted credentials return a
   * short-lived token with `expiresAt`; a reveal under a lease returns
   * `leaseId` and `leaseExpiresAt`. Not retried after a 5xx or timeout.
   */
  reveal(credential: string | { credential: string; taskId?: string }, opts?: RequestOptions): Promise<AgentRevealResult> {
    const body = typeof credential === 'string' ? { credential } : credential;
    return this.request<AgentRevealResult>({ method: 'POST', path: '/v1/agent/credentials/reveal', body }, opts);
  }

  /** The current TOTP code of a login credential (needs the `totp` action). The seed never leaves Citadel. */
  getTotpCode(credential: string | { credential: string; taskId?: string }, opts?: RequestOptions): Promise<AgentTotpCode> {
    const body = typeof credential === 'string' ? { credential } : credential;
    return this.request<AgentTotpCode>({ method: 'POST', path: '/v1/agent/totp', body }, opts);
  }

  /**
   * A login credential's username and password for the page at `url`,
   * which must match one of the credential's URL patterns (needs the
   * `reveal` action).
   */
  getLogin(input: { credential: string; url: string; taskId?: string }, opts?: RequestOptions): Promise<AgentLogin> {
    return this.request<AgentLogin>({ method: 'POST', path: '/v1/agent/login', body: input }, opts);
  }

  /**
   * Asks a person for access to a credential, or returns the pending
   * request for the same credential, actions and task. `reason` is shown
   * to approvers. Not retried after a 5xx or timeout.
   */
  requestAccess(input: AgentAccessRequestInput, opts?: RequestOptions): Promise<AgentAccessRequest> {
    return this.request<AgentAccessRequest>({ method: 'POST', path: '/v1/agent/access-requests', body: input }, opts);
  }

  /** One of the agent's access requests: its status and, once approved, its lease. */
  getAccessRequest(requestId: string, opts?: RequestOptions): Promise<AgentAccessRequest> {
    return this.request<AgentAccessRequest>({ method: 'GET', path: `/v1/agent/access-requests/${encodeURIComponent(requestId)}` }, opts);
  }

  /**
   * Polls an access request until it is decided and returns it: check
   * `status` (`approved`, or `denied`, `expired`, `cancelled` with
   * `decisionComment`). Stop waiting with `signal`.
   */
  async waitForAccess(requestId: string, options: WaitForAccessOptions = {}): Promise<AgentAccessRequest> {
    const { intervalMs = 5000, ...opts } = options;
    for (;;) {
      const req = await this.getAccessRequest(requestId, opts);
      if (req.status !== 'pending') return req;
      await defaultSleep(intervalMs, opts.signal);
    }
  }

  /** The agent's active leases, optionally for one credential. */
  async listLeases(input: { credential?: string } = {}, opts?: RequestOptions): Promise<AgentLease[]> {
    return (await this.request<{ leases: AgentLease[] }>({ method: 'GET', path: '/v1/agent/leases', query: { credential: input.credential } }, opts)).leases;
  }
}

/** A brokered response from {@link CitadelAgent.http}. */
export class AgentHttpResult implements AgentHttpResponseBody {
  /** The upstream's HTTP status. */
  readonly status: number;
  /** Response headers (multiple values joined with ", "), without Set-Cookie and credential headers. */
  readonly headers: Record<string, string>;
  /** The body as sent by Citadel: text, or base64 when `bodyEncoding` is base64. */
  readonly body: string;
  readonly bodyEncoding: 'text' | 'base64';
  /** The body was cut at 5 MiB. */
  readonly truncated: boolean;
  /** Occurrences of the secret were replaced with `[REDACTED]`. */
  readonly redacted: boolean;

  constructor(res: AgentHttpResponseBody) {
    this.status = res.status;
    this.headers = res.headers ?? {};
    this.body = res.body ?? '';
    this.bodyEncoding = res.bodyEncoding;
    this.truncated = res.truncated;
    this.redacted = res.redacted;
  }

  /** True for a 2xx upstream status. */
  get ok(): boolean {
    return this.status >= 200 && this.status < 300;
  }

  /** The decoded body bytes. */
  bytes(): Uint8Array {
    return this.bodyEncoding === 'base64' ? base64ToBytes(this.body) : utf8Encode(this.body);
  }

  /** The body as text (base64 bodies are decoded as UTF-8). */
  text(): string {
    return this.bodyEncoding === 'base64' ? utf8Decode(base64ToBytes(this.body)) : this.body;
  }

  /** The body parsed as JSON. */
  json<T = unknown>(): T {
    return JSON.parse(this.text()) as T;
  }
}

/** Builds the wire request, encoding the body and setting `bodyEncoding`. */
export function encodeHttpInput(input: AgentHttpInput): AgentHttpRequestBody {
  const out: AgentHttpRequestBody = { credential: input.credential, method: input.method ?? 'GET', url: input.url, bodyEncoding: 'text' };
  if (input.taskId) out.taskId = input.taskId;
  let headers = input.headers ? { ...input.headers } : undefined;
  if (input.json !== undefined) {
    if (input.body !== undefined) throw new TypeError('CitadelAgent.http: set body or json, not both');
    out.body = JSON.stringify(input.json);
    out.bodyEncoding = 'text';
    if (!headers || !Object.keys(headers).some((k) => k.toLowerCase() === 'content-type')) {
      headers = { ...headers, 'Content-Type': 'application/json' };
    }
  } else if (typeof input.body === 'string') {
    out.body = input.body;
    out.bodyEncoding = 'text';
  } else if (input.body !== undefined) {
    const bytes = input.body instanceof Uint8Array ? input.body : new Uint8Array(input.body);
    out.body = bytesToBase64(bytes);
    out.bodyEncoding = 'base64';
  }
  if (headers) out.headers = headers;
  return out;
}
