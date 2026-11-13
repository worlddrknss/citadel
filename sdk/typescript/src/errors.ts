/**
 * Error raised for every failed Citadel call.
 *
 * `status` is the HTTP status (0 when no response arrived), `code` is the
 * stable machine-readable code from the API's `{ error, message }` body
 * (for example `not_found`, `forbidden`, `approval_required`,
 * `reveal_forbidden`, `rate_limited`), and `message` is the human-readable
 * explanation. Branch on `code`, never on `message`.
 */
export class CitadelError extends Error {
  override readonly name: string = 'CitadelError';
  /** HTTP status, or 0 when the request never got a response. */
  readonly status: number;
  /** Stable error code from the API (`error` field), e.g. `not_found`. */
  readonly code: string;
  /** HTTP method and path of the failed request, e.g. `GET /v1/secrets`. */
  readonly operation: string;
  /** Number of attempts made, including retries. */
  readonly attempts: number;
  /** Retry-After hint from the server, in milliseconds, when present. */
  readonly retryAfterMs: number | undefined;

  constructor(init: {
    status: number;
    code: string;
    message: string;
    operation?: string;
    attempts?: number;
    retryAfterMs?: number;
    cause?: unknown;
  }) {
    super(init.message, init.cause === undefined ? undefined : { cause: init.cause });
    this.status = init.status;
    this.code = init.code;
    this.operation = init.operation ?? '';
    this.attempts = init.attempts ?? 1;
    this.retryAfterMs = init.retryAfterMs;
  }

  /** True when the resource does not exist (HTTP 404). */
  get isNotFound(): boolean {
    return this.status === 404;
  }

  /** True when the caller is not authenticated (HTTP 401). */
  get isUnauthorized(): boolean {
    return this.status === 401;
  }

  /** True when the caller lacks the role or setting needed (HTTP 403). */
  get isForbidden(): boolean {
    return this.status === 403;
  }

  /**
   * Reports whether err is a CitadelError, optionally with the given code.
   * Works across bundles and module copies, unlike `instanceof`.
   */
  static is(err: unknown, code?: string): err is CitadelError {
    if (!(err instanceof Error)) return false;
    const e = err as Partial<CitadelError>;
    if (typeof e.status !== 'number' || typeof e.code !== 'string') return false;
    return code === undefined || e.code === code;
  }
}

/** The request could not reach Citadel (DNS, connection refused, reset). */
export class CitadelConnectionError extends CitadelError {
  override readonly name: string = 'CitadelConnectionError';
}

/** The request did not complete within the configured timeout. */
export class CitadelTimeoutError extends CitadelError {
  override readonly name: string = 'CitadelTimeoutError';
}
