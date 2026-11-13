import { CitadelConnectionError, CitadelError, CitadelTimeoutError } from './errors.js';

/** Next.js data cache options, passed through to `fetch` as `next`. */
export interface NextFetchOptions {
  /** Seconds to cache the response in the Next.js data cache, or false to opt out. */
  revalidate?: number | false;
  /** Cache tags for `revalidateTag`. */
  tags?: string[];
}

/** Per-call options accepted by every client method. */
export interface RequestOptions {
  /** Aborts the call (and any pending retry) when signalled. */
  signal?: AbortSignal;
  /** Per-attempt timeout in milliseconds; overrides the client default. */
  timeoutMs?: number;
  /** Maximum retries for this call; overrides the client default. */
  maxRetries?: number;
  /**
   * Also retry this call after a 500, 502, 504, a timeout or a network
   * failure when it is not idempotent (POST). Off by default: those
   * failures can come after the server, or the upstream behind the Agent
   * API's broker, already acted, so a retry could repeat a side effect
   * (a payment, a message, a deploy). Set it only for calls you know are
   * safe to repeat. 429 and 503 with Retry-After, which Citadel answers
   * before acting, are retried either way.
   */
  retryNonIdempotent?: boolean;
  /**
   * Next.js `fetch` cache options. Ignored by other runtimes. Responses
   * that carry secret values are only cached server-side by Next.js; they
   * never reach the browser.
   */
  next?: NextFetchOptions;
  /** Standard `fetch` cache mode, e.g. `no-store`. */
  cache?: RequestCache;
}

/**
 * Retry policy. 429 and 503 with Retry-After are retried for every method;
 * 500, 502, 503 without Retry-After, 504, timeouts and network failures only
 * for idempotent methods (GET, HEAD, PUT, DELETE) unless the call sets
 * {@link RequestOptions.retryNonIdempotent}.
 */
export interface RetryOptions {
  /** Retries after the first attempt (default 3; 0 disables retries). */
  maxRetries: number;
  /** First backoff delay in milliseconds (default 200). */
  baseDelayMs: number;
  /** Cap for any single backoff delay, including Retry-After (default 10000). */
  maxDelayMs: number;
}

export interface TransportConfig {
  baseUrl: string;
  authorization: string | undefined;
  timeoutMs: number;
  retry: RetryOptions;
  fetch: typeof fetch;
  headers: Record<string, string>;
  /** Injected for tests: waits ms milliseconds. */
  sleep?: (ms: number, signal?: AbortSignal) => Promise<void>;
  /** Injected for tests: returns a value in [0, 1). */
  random?: () => number;
}

export interface CallSpec {
  method: 'GET' | 'POST' | 'DELETE';
  path: string;
  query?: Record<string, string | number | boolean | undefined>;
  body?: unknown;
  /** false sends no Authorization header (workload identity token exchange). */
  auth?: boolean;
  /** Overrides the Authorization header for this call. */
  authorization?: string;
}

const IDEMPOTENT = new Set(['GET', 'DELETE', 'HEAD', 'PUT']);

/**
 * Reports whether a failed response may be retried. Citadel answers 429
 * (rate limits) and 503 with Retry-After (a busy broker) before acting, so
 * those are safe for every method. A 500, 502, 504 or a bare 503 (from a
 * proxy, say) can follow a request that took effect; for example the Agent
 * API's broker answers 502 or 504 when the upstream failed or timed out,
 * possibly after it acted. Those are retried only when repeatable.
 */
export function retryableStatus(status: number, repeatable: boolean, hasRetryAfter: boolean): boolean {
  switch (status) {
    case 429:
      return true;
    case 503:
      return repeatable || hasRetryAfter;
    case 500:
    case 502:
    case 504:
      return repeatable;
    default:
      return false;
  }
}

/** Default per-attempt timeout: 30 seconds. */
export const DEFAULT_TIMEOUT_MS = 30_000;

export function defaultSleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(abortReason(signal));
      return;
    }
    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort);
      resolve();
    }, ms);
    const onAbort = () => {
      clearTimeout(timer);
      reject(abortReason(signal!));
    };
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}

function abortReason(signal: AbortSignal): unknown {
  if (signal.reason !== undefined) return signal.reason;
  const err = new Error('The operation was aborted');
  err.name = 'AbortError';
  return err;
}

/**
 * Parses a Retry-After header (delta-seconds or an HTTP date) into
 * milliseconds. Returns undefined when absent or unparseable.
 */
export function parseRetryAfter(value: string | null, now: number = Date.now()): number | undefined {
  if (!value) return undefined;
  const trimmed = value.trim();
  if (/^\d+(\.\d+)?$/.test(trimmed)) return Math.round(Number(trimmed) * 1000);
  const date = Date.parse(trimmed);
  if (Number.isNaN(date)) return undefined;
  return Math.max(0, date - now);
}

/** Full-jitter exponential backoff for retry number attempt (1-based). */
export function backoffDelay(attempt: number, retry: RetryOptions, random: () => number = Math.random): number {
  const exp = Math.min(retry.maxDelayMs, retry.baseDelayMs * 2 ** (attempt - 1));
  return Math.round(exp / 2 + random() * (exp / 2));
}

function buildURL(baseUrl: string, path: string, query: CallSpec['query']): string {
  const url = new URL(baseUrl.replace(/\/+$/, '') + path);
  if (query) {
    for (const [k, v] of Object.entries(query)) {
      if (v === undefined || v === '') continue;
      url.searchParams.set(k, String(v));
    }
  }
  return url.toString();
}

/** Performs one API call with timeouts, retries and typed errors. */
export async function call<T>(cfg: TransportConfig, spec: CallSpec, opts: RequestOptions = {}): Promise<T> {
  const url = buildURL(cfg.baseUrl, spec.path, spec.query);
  const operation = `${spec.method} ${spec.path}`;
  const maxRetries = Math.max(0, opts.maxRetries ?? cfg.retry.maxRetries);
  const timeoutMs = opts.timeoutMs ?? cfg.timeoutMs;
  const sleep = cfg.sleep ?? defaultSleep;
  const random = cfg.random ?? Math.random;
  const repeatable = IDEMPOTENT.has(spec.method) || opts.retryNonIdempotent === true;

  const headers: Record<string, string> = { Accept: 'application/json', ...cfg.headers };
  const authorization = spec.authorization ?? (spec.auth === false ? undefined : cfg.authorization);
  if (authorization) headers['Authorization'] = authorization;
  let body: string | undefined;
  if (spec.body !== undefined) {
    headers['Content-Type'] = 'application/json';
    body = JSON.stringify(spec.body);
  }

  for (let attempt = 1; ; attempt++) {
    if (opts.signal?.aborted) throw abortReason(opts.signal);
    const controller = new AbortController();
    let timedOut = false;
    const timer =
      timeoutMs > 0
        ? setTimeout(() => {
            timedOut = true;
            controller.abort();
          }, timeoutMs)
        : undefined;
    const onUserAbort = () => controller.abort(opts.signal?.reason);
    opts.signal?.addEventListener('abort', onUserAbort, { once: true });

    const init: RequestInit & { next?: NextFetchOptions } = {
      method: spec.method,
      headers,
      body,
      signal: controller.signal,
      redirect: 'manual',
    };
    if (opts.cache) init.cache = opts.cache;
    if (opts.next) init.next = opts.next;

    let res: Response;
    try {
      res = await cfg.fetch(url, init);
    } catch (err) {
      clearTimeout(timer);
      opts.signal?.removeEventListener('abort', onUserAbort);
      if (opts.signal?.aborted) throw abortReason(opts.signal);
      const failure = timedOut
        ? new CitadelTimeoutError({ status: 0, code: 'timeout', message: `${operation} timed out after ${timeoutMs}ms`, operation, attempts: attempt, cause: err })
        : new CitadelConnectionError({ status: 0, code: 'connection_error', message: `${operation} failed: ${errorText(err)}`, operation, attempts: attempt, cause: err });
      // Without a response we can't know whether the server applied the
      // request, so only idempotent methods are retried.
      if (attempt <= maxRetries && repeatable) {
        await sleep(backoffDelay(attempt, cfg.retry, random), opts.signal);
        continue;
      }
      throw failure;
    }

    let text: string;
    try {
      text = await res.text();
    } catch (err) {
      clearTimeout(timer);
      opts.signal?.removeEventListener('abort', onUserAbort);
      if (opts.signal?.aborted) throw abortReason(opts.signal);
      if (timedOut) {
        throw new CitadelTimeoutError({ status: res.status, code: 'timeout', message: `${operation} timed out after ${timeoutMs}ms`, operation, attempts: attempt, cause: err });
      }
      throw new CitadelConnectionError({ status: res.status, code: 'connection_error', message: `${operation}: reading the response failed`, operation, attempts: attempt, cause: err });
    }
    clearTimeout(timer);
    opts.signal?.removeEventListener('abort', onUserAbort);

    if (res.ok) {
      if (text === '') return undefined as T;
      try {
        return JSON.parse(text) as T;
      } catch (err) {
        throw new CitadelError({ status: res.status, code: 'invalid_response', message: `${operation}: response is not JSON`, operation, attempts: attempt, cause: err });
      }
    }

    const retryAfterHeader = res.headers.get('Retry-After');
    const retryAfterMs = parseRetryAfter(retryAfterHeader);
    if (attempt <= maxRetries && retryableStatus(res.status, repeatable, retryAfterHeader !== null && retryAfterHeader.trim() !== '')) {
      const delay = Math.min(cfg.retry.maxDelayMs, retryAfterMs ?? backoffDelay(attempt, cfg.retry, random));
      await sleep(delay, opts.signal);
      continue;
    }
    throw errorFromResponse(res.status, text, operation, attempt, retryAfterMs);
  }
}

function errorText(err: unknown): string {
  if (err instanceof Error) {
    const cause = (err as Error & { cause?: unknown }).cause;
    if (cause instanceof Error && cause.message) return `${err.message} (${cause.message})`;
    return err.message;
  }
  return String(err);
}

/** Builds a CitadelError from a non-2xx response body. */
export function errorFromResponse(status: number, text: string, operation: string, attempts: number, retryAfterMs?: number): CitadelError {
  let code = `http_${status}`;
  let message = `${operation} failed with HTTP ${status}`;
  let reason: string | undefined;
  let requestId: string | undefined;
  try {
    const parsed = JSON.parse(text) as { error?: unknown; message?: unknown; error_description?: unknown; reason?: unknown; requestId?: unknown };
    if (typeof parsed.error === 'string' && parsed.error) code = parsed.error;
    if (typeof parsed.message === 'string' && parsed.message) message = parsed.message;
    else if (typeof parsed.error_description === 'string' && parsed.error_description) message = parsed.error_description;
    if (typeof parsed.reason === 'string' && parsed.reason) reason = parsed.reason;
    if (typeof parsed.requestId === 'string' && parsed.requestId) requestId = parsed.requestId;
  } catch {
    // Not JSON (a proxy error page, say): keep the generic code and message.
  }
  return new CitadelError({ status, code, message, operation, attempts, retryAfterMs, reason, requestId });
}
