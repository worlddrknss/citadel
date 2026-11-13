import { base64ToBytes, bytesToBase64, utf8Decode, utf8Encode } from './base64.js';
import { CitadelError } from './errors.js';
import { assertServerRuntime } from './guard.js';
import { call, DEFAULT_TIMEOUT_MS, type CallSpec, type RequestOptions, type RetryOptions, type TransportConfig } from './http.js';
import type {
  CertificateSummary,
  CreatedAccessKey,
  DecryptInput,
  DecryptResult,
  DeleteSecretInput,
  DeleteSecretResult,
  EncryptInput,
  EncryptResult,
  FolderRef,
  GeneratedCertificate,
  GetSecretInput,
  IssueCertificateInput,
  IssueCertificateResult,
  IssueGeneratedCertificateInput,
  KmsDecryptResponse,
  KmsEncryptResponse,
  KmsKey,
  Me,
  Parameter,
  ParameterHistory,
  ParameterList,
  ParameterValue,
  Project,
  PutParameterInput,
  PutSecretInput,
  PutSecretResult,
  SecretListing,
  SecretRef,
  SecretValue,
  SecretVersion,
  SecretVersionList,
  WorkloadToken,
  WorkloadTokenInput,
} from './types.js';

/** Options for {@link Citadel}. */
export interface CitadelOptions {
  /**
   * Citadel's base URL, e.g. `https://citadel.example.com`. Defaults to the
   * `CITADEL_URL` environment variable.
   */
  baseUrl?: string;
  /** Access key ID. Defaults to `CITADEL_ACCESS_KEY_ID`. */
  accessKeyId?: string;
  /** Access key secret. Defaults to `CITADEL_SECRET_ACCESS_KEY`. */
  secretAccessKey?: string;
  /** Per-attempt timeout in milliseconds (default 30000; 0 disables). */
  timeoutMs?: number;
  /** Retries after the first attempt for 429/5xx and network errors (default 3). */
  maxRetries?: number;
  /** First backoff delay in milliseconds (default 200). */
  retryBaseDelayMs?: number;
  /** Maximum single backoff delay, including Retry-After, in ms (default 10000). */
  retryMaxDelayMs?: number;
  /** A fetch implementation; defaults to the global fetch. */
  fetch?: typeof fetch;
  /** Extra headers sent with every request. */
  headers?: Record<string, string>;
}

function env(name: string): string | undefined {
  try {
    const value = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process?.env?.[name];
    return value && value.trim() !== '' ? value.trim() : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Client for Citadel's native /v1 API.
 *
 * Server-only: it holds an access key and returns secret values. It throws
 * if constructed in a browser.
 *
 * ```ts
 * const citadel = new Citadel({
 *   baseUrl: 'https://citadel.example.com',
 *   accessKeyId: process.env.CITADEL_ACCESS_KEY_ID,
 *   secretAccessKey: process.env.CITADEL_SECRET_ACCESS_KEY,
 * });
 * const db = await citadel.secrets.getValue({ project: 'web', env: 'prod', key: 'DATABASE_URL' });
 * ```
 *
 * Every method accepts {@link RequestOptions} as its last argument (abort
 * signal, timeout, retries, Next.js `next: { revalidate }`). Failures throw
 * {@link CitadelError}, whose `code` is the API's stable error code.
 */
export class Citadel {
  readonly baseUrl: string;
  /** @internal */
  readonly transport: TransportConfig;

  constructor(options: CitadelOptions = {}) {
    assertServerRuntime();
    const baseUrl = (options.baseUrl ?? env('CITADEL_URL') ?? '').trim();
    if (!baseUrl) {
      throw new TypeError('Citadel: baseUrl is required (or set CITADEL_URL)');
    }
    let parsed: URL;
    try {
      parsed = new URL(baseUrl);
    } catch {
      throw new TypeError(`Citadel: baseUrl is not a valid URL: ${baseUrl}`);
    }
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
      throw new TypeError('Citadel: baseUrl must be an http(s) URL');
    }
    this.baseUrl = trimSlashes(baseUrl, false, true);

    const accessKeyId = options.accessKeyId ?? env('CITADEL_ACCESS_KEY_ID');
    const secretAccessKey = options.secretAccessKey ?? env('CITADEL_SECRET_ACCESS_KEY');
    if (Boolean(accessKeyId) !== Boolean(secretAccessKey)) {
      throw new TypeError('Citadel: accessKeyId and secretAccessKey must be set together');
    }
    if (accessKeyId?.includes(':')) {
      throw new TypeError('Citadel: accessKeyId must not contain ":"');
    }
    const fetchImpl = options.fetch ?? (globalThis.fetch as typeof fetch | undefined);
    if (typeof fetchImpl !== 'function') {
      throw new TypeError('Citadel: no global fetch; use Node 18+ or pass options.fetch');
    }
    const retry: RetryOptions = {
      maxRetries: options.maxRetries ?? 3,
      baseDelayMs: options.retryBaseDelayMs ?? 200,
      maxDelayMs: options.retryMaxDelayMs ?? 10_000,
    };
    this.transport = {
      baseUrl: this.baseUrl,
      authorization: accessKeyId ? `Bearer ${accessKeyId}:${secretAccessKey}` : undefined,
      timeoutMs: options.timeoutMs ?? DEFAULT_TIMEOUT_MS,
      retry,
      // Bind so runtimes that require fetch's `this` to be the global work.
      fetch: (input, init) => fetchImpl.call(globalThis, input, init),
      headers: { ...options.headers },
    };
  }

  /** Low-level call to any /v1 operation; prefer the typed methods. */
  request<T>(spec: CallSpec, opts?: RequestOptions): Promise<T> {
    return call<T>(this.transport, spec, opts);
  }

  /** The caller's identity: username, role and account. */
  me(opts?: RequestOptions): Promise<Me> {
    return this.request<Me>({ method: 'GET', path: '/v1/me' }, opts);
  }

  /** Projects in the caller's account, with their environments. */
  readonly projects = {
    list: async (opts?: RequestOptions): Promise<Project[]> =>
      (await this.request<{ projects: Project[] }>({ method: 'GET', path: '/v1/projects' }, opts)).projects,
    create: (input: { slug: string; name?: string }, opts?: RequestOptions): Promise<void> =>
      this.request<unknown>({ method: 'POST', path: '/v1/projects', body: input }, opts).then(() => undefined),
    /** Deletes an empty project (the server refuses one that holds secrets). */
    delete: (project: string, opts?: RequestOptions): Promise<void> =>
      this.request<unknown>({ method: 'DELETE', path: '/v1/projects', query: { project } }, opts).then(() => undefined),
  };

  /** Environments inside a project. */
  readonly environments = {
    create: (input: { project: string; slug: string; name?: string }, opts?: RequestOptions): Promise<void> =>
      this.request<unknown>({ method: 'POST', path: '/v1/environments', body: input }, opts).then(() => undefined),
    delete: (input: { project: string; env: string }, opts?: RequestOptions): Promise<void> =>
      this.request<unknown>({ method: 'DELETE', path: '/v1/environments', query: { ...input } }, opts).then(() => undefined),
  };

  /** Folders inside an environment. */
  readonly folders = {
    create: (input: FolderRef & { path: string }, opts?: RequestOptions): Promise<void> =>
      this.request<unknown>({ method: 'POST', path: '/v1/folders', body: input }, opts).then(() => undefined),
    delete: (input: FolderRef & { path: string }, opts?: RequestOptions): Promise<void> =>
      this.request<unknown>({ method: 'DELETE', path: '/v1/folders', query: { ...input } }, opts).then(() => undefined),
  };

  /** Secrets addressed as project / environment / folder / key. */
  readonly secrets = {
    /**
     * Lists one folder: its items (no values) and sub-folders. The API returns
     * the whole folder in one response; there is no pagination.
     */
    list: (ref: FolderRef, opts?: RequestOptions): Promise<SecretListing> =>
      this.request<SecretListing>({ method: 'GET', path: '/v1/secrets', query: folderQuery(ref) }, opts),
    /**
     * Reads a secret's value (an audited reveal). Viewers can read values only
     * where the account allows it; otherwise this throws `reveal_forbidden`.
     */
    get: (input: GetSecretInput, opts?: RequestOptions): Promise<SecretValue> =>
      this.request<SecretValue>(
        {
          method: 'GET',
          path: '/v1/secrets/value',
          query: {
            ...secretQuery(input),
            versionId: input.versionId,
            versionStage: input.versionStage,
            resolve: input.resolve ? 'true' : undefined,
          },
        },
        opts,
      ),
    /** Reads a secret's string value. Throws if the secret holds binary data. */
    getValue: async (input: GetSecretInput, opts?: RequestOptions): Promise<string> => {
      const v = await this.secrets.get(input, opts);
      if (typeof v.value !== 'string') {
        throw new CitadelError({ status: 200, code: 'binary_value', message: `secret ${input.key} holds a binary value`, operation: 'GET /v1/secrets/value' });
      }
      return v.value;
    },
    /**
     * Creates or updates a secret (a new version each time). Throws
     * `approval_required` (409) where the environment requires a change request.
     */
    put: (input: PutSecretInput, opts?: RequestOptions): Promise<PutSecretResult> =>
      this.request<PutSecretResult>(
        {
          method: 'POST',
          path: '/v1/secrets',
          body: { project: input.project, env: input.env, path: input.path ?? '', key: input.key, value: input.value, kmsKeyId: input.kmsKeyId ?? '' },
        },
        opts,
      ),
    /** Schedules deletion (restorable during the recovery window) or deletes now with force. */
    delete: (input: DeleteSecretInput, opts?: RequestOptions): Promise<DeleteSecretResult> =>
      this.request<DeleteSecretResult>(
        {
          method: 'DELETE',
          path: '/v1/secrets',
          query: { ...secretQuery(input), force: input.force ? 'true' : undefined, recoveryWindowDays: input.recoveryWindowDays },
        },
        opts,
      ),
    /** Cancels a pending deletion. */
    restore: (ref: SecretRef, opts?: RequestOptions): Promise<void> =>
      this.request<unknown>({ method: 'POST', path: '/v1/secrets/restore', query: secretQuery(ref) }, opts).then(() => undefined),
    /** A secret's versions, newest first, without values. */
    versions: async (ref: SecretRef, opts?: RequestOptions): Promise<SecretVersion[]> =>
      (await this.request<SecretVersionList>({ method: 'GET', path: '/v1/secrets/versions', query: secretQuery(ref) }, opts)).versions,
  };

  /** Parameter Store parameters (String, StringList, SecureString). */
  readonly parameters = {
    /**
     * Every parameter in the account. String and StringList values are
     * included; SecureString values need {@link Citadel.parameters.get}.
     */
    list: async (opts?: RequestOptions): Promise<Parameter[]> =>
      (await this.request<ParameterList>({ method: 'GET', path: '/v1/parameters' }, opts)).parameters,
    /** A parameter with its (decrypted) value, optionally at a given version. */
    get: (name: string, options: { version?: number } & RequestOptions = {}): Promise<ParameterValue> => {
      const { version, ...opts } = options;
      return this.request<ParameterValue>({ method: 'GET', path: '/v1/parameters/value', query: { name, version } }, opts);
    },
    /** Creates a parameter, or a new version of it with `overwrite: true`. */
    put: async (input: PutParameterInput, opts?: RequestOptions): Promise<Parameter> =>
      (await this.request<{ parameter: Parameter }>({ method: 'POST', path: '/v1/parameters', body: input }, opts)).parameter,
    /** Deletes a parameter and its history. */
    delete: (name: string, opts?: RequestOptions): Promise<void> =>
      this.request<unknown>({ method: 'DELETE', path: '/v1/parameters', query: { name } }, opts).then(() => undefined),
    /** A parameter's version history. */
    history: (name: string, opts?: RequestOptions): Promise<ParameterHistory> =>
      this.request<ParameterHistory>({ method: 'GET', path: '/v1/parameters/history', query: { name } }, opts),
  };

  /** KMS keys and envelope cryptography. */
  readonly kms = {
    /** Keys visible to the caller, with their aliases. */
    listKeys: async (opts?: RequestOptions): Promise<KmsKey[]> =>
      (await this.request<{ keys: KmsKey[] }>({ method: 'GET', path: '/v1/kms/keys' }, opts)).keys,
    /** Encrypts up to 4 KB under a symmetric or RSA key. Needs the editor role. */
    encrypt: async (input: EncryptInput, opts?: RequestOptions): Promise<EncryptResult> => {
      const bytes = typeof input.plaintext === 'string' ? utf8Encode(input.plaintext) : input.plaintext;
      const res = await this.request<KmsEncryptResponse>(
        {
          method: 'POST',
          path: '/v1/kms/encrypt',
          body: {
            keyId: input.keyId,
            plaintext: bytesToBase64(bytes),
            encryptionContext: input.encryptionContext,
            encryptionAlgorithm: input.encryptionAlgorithm,
          },
        },
        opts,
      );
      return { keyId: res.keyId, ciphertextBlob: res.ciphertextBlob, encryptionAlgorithm: res.encryptionAlgorithm };
    },
    /** Decrypts a ciphertext from encrypt. Needs the editor role. */
    decrypt: async (input: DecryptInput, opts?: RequestOptions): Promise<DecryptResult> => {
      const res = await this.request<KmsDecryptResponse>(
        {
          method: 'POST',
          path: '/v1/kms/decrypt',
          body: {
            keyId: input.keyId,
            ciphertextBlob: input.ciphertextBlob,
            encryptionContext: input.encryptionContext,
            encryptionAlgorithm: input.encryptionAlgorithm,
          },
        },
        opts,
      );
      return { keyId: res.keyId, plaintext: base64ToBytes(res.plaintext), encryptionAlgorithm: res.encryptionAlgorithm };
    },
    /** Decrypts and decodes the plaintext as UTF-8. */
    decryptText: async (input: DecryptInput, opts?: RequestOptions): Promise<string> =>
      utf8Decode((await this.kms.decrypt(input, opts)).plaintext),
  };

  /** Private CA and Let's Encrypt certificates. */
  readonly certificates = {
    /** CAs, the certificates they issued, and Let's Encrypt certificates. */
    list: async (opts?: RequestOptions): Promise<CertificateSummary[]> =>
      (await this.request<{ certificates: CertificateSummary[] }>({ method: 'GET', path: '/v1/certificates' }, opts)).certificates,
    /** Signs a CSR with a private CA (`caArn` takes a CA ID or ARN). */
    issue: (input: IssueCertificateInput, opts?: RequestOptions): Promise<IssueCertificateResult> =>
      this.request<IssueCertificateResult>({ method: 'POST', path: '/v1/certificates/issue', body: input }, opts),
    /**
     * Generates a key pair in Citadel and issues a certificate for it. The
     * private key is returned once and never stored.
     */
    issueGenerated: (input: IssueGeneratedCertificateInput, opts?: RequestOptions): Promise<GeneratedCertificate> =>
      this.request<GeneratedCertificate>({ method: 'POST', path: '/v1/certificates/issue/generate', body: input }, opts),
  };

  /** Workload identity: short-lived OIDC ID tokens for registered clients. */
  readonly workloadIdentity = {
    /**
     * Exchanges a credential for a signed ID token. Access-key clients
     * authenticate with this client's access key; Kubernetes clients pass
     * `kubernetesToken` (a projected service account token).
     */
    token: (input: WorkloadTokenInput, opts?: RequestOptions): Promise<WorkloadToken> =>
      this.request<WorkloadToken>({ method: 'POST', path: '/v1/workload-identity/token', body: input }, opts),
  };

  /** The caller's own access keys. */
  readonly accessKeys = {
    /** Mints an access key for the caller; the secret is returned only once. */
    create: (opts?: RequestOptions): Promise<CreatedAccessKey> =>
      this.request<CreatedAccessKey>({ method: 'POST', path: '/v1/account/keys' }, opts),
  };
}

function folderQuery(ref: FolderRef): Record<string, string | undefined> {
  return { project: ref.project, env: ref.env, path: ref.path };
}

function secretQuery(ref: SecretRef): Record<string, string | undefined> {
  return { ...folderQuery(ref), key: ref.key };
}

/**
 * Removes leading and/or trailing '/' characters with a linear scan. (A regex
 * like /\/+$/ backtracks quadratically on long runs of slashes.)
 */
export function trimSlashes(value: string, leading: boolean, trailing: boolean): string {
  let start = 0;
  let end = value.length;
  if (leading) while (start < end && value.charCodeAt(start) === 47) start++;
  if (trailing) while (end > start && value.charCodeAt(end - 1) === 47) end--;
  return value.slice(start, end);
}

