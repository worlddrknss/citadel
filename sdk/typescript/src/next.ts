import { Citadel, trimSlashes } from './client.js';
import type { RequestOptions } from './http.js';
import type { FolderRef } from './types.js';

/** Options for {@link loadSecrets}. */
export interface LoadSecretsOptions extends FolderRef {
  /** Only keys starting with this prefix (kept as-is in the result). */
  prefix?: string;
  /** Client to use; defaults to one built from CITADEL_URL, CITADEL_ACCESS_KEY_ID and CITADEL_SECRET_ACCESS_KEY. */
  client?: Citadel;
  /** How long a loaded folder stays fresh in memory, in ms (default 60000; 0 disables the cache). */
  ttl?: number;
  /**
   * How long after `ttl` a stale result may still be served while it is
   * refreshed in the background, in ms (default 300000). A failed refresh
   * keeps serving the stale result until this window ends.
   */
  staleWhileRevalidate?: number;
  /**
   * Next.js data-cache lifetime in seconds, passed to fetch as
   * `next: { revalidate }`. Ignored outside Next.js.
   */
  revalidate?: number | false;
  /** Next.js cache tags (`next: { tags }`) for on-demand `revalidateTag`. */
  tags?: string[];
  /** Also set `process.env[KEY]` for every key that is not already set. */
  inject?: boolean;
  /** Maximum concurrent value reads (default 8). */
  concurrency?: number;
  /** Aborts loading. */
  signal?: AbortSignal;
}

interface CacheEntry {
  value: Record<string, string>;
  fetchedAt: number;
  pending?: Promise<Record<string, string>>;
}

const cache = new Map<string, CacheEntry>();
let defaultClient: Citadel | undefined;

/** Clock used by the cache (tests replace it). @internal */
export const clock = { now: (): number => Date.now() };

/** Empties the loadSecrets in-memory cache. */
export function clearSecretsCache(): void {
  cache.clear();
}

/**
 * Loads every secret in one folder as a `{ KEY: value }` record.
 *
 * Built for Next.js (route handlers, server components, server actions,
 * `next.config.js`) but works in any server runtime. Results are cached in
 * memory per process with a TTL and stale-while-revalidate, concurrent calls
 * for the same folder share one load, and `inject: true` copies the keys into
 * `process.env` without overwriting variables that are already set.
 *
 * Sub-folders are not included; call once per folder. Items scheduled for
 * deletion and binary values are skipped.
 *
 * ```ts
 * import 'server-only';
 * import { loadSecrets } from '@worlddrknss/citadel';
 *
 * const secrets = await loadSecrets({ project: 'web', env: 'prod', ttl: 60_000 });
 * ```
 */
export async function loadSecrets(options: LoadSecretsOptions): Promise<Record<string, string>> {
  const client = options.client ?? (defaultClient ??= new Citadel());
  const ttl = Math.max(0, options.ttl ?? 60_000);
  const swr = Math.max(0, options.staleWhileRevalidate ?? 300_000);
  const key = cacheKey(client, options);

  let result: Record<string, string>;
  if (ttl === 0) {
    result = await fetchFolder(client, options);
  } else {
    const now = clock.now();
    const entry = cache.get(key);
    const age = entry ? now - entry.fetchedAt : Infinity;
    if (entry && age < ttl) {
      result = entry.value;
    } else if (entry && age < ttl + swr) {
      result = entry.value;
      if (!entry.pending) {
        entry.pending = fetchFolder(client, { ...options, signal: undefined });
        entry.pending.then(
          (value) => cache.set(key, { value, fetchedAt: clock.now() }),
          () => {
            // Keep serving the stale value; the next call retries.
            const current = cache.get(key);
            if (current) delete current.pending;
          },
        );
      }
    } else if (entry?.pending) {
      result = await entry.pending;
    } else {
      const pending = fetchFolder(client, options);
      if (entry) {
        entry.pending = pending;
      } else {
        cache.set(key, { value: {}, fetchedAt: -Infinity, pending });
      }
      try {
        result = await pending;
        cache.set(key, { value: result, fetchedAt: clock.now() });
      } catch (err) {
        const current = cache.get(key);
        if (current?.pending === pending) {
          if (current.fetchedAt === -Infinity) cache.delete(key);
          else delete current.pending;
        }
        throw err;
      }
    }
  }

  if (options.inject) injectEnv(result);
  return { ...result };
}

function cacheKey(client: Citadel, o: LoadSecretsOptions): string {
  const auth = client.transport.authorization?.split(':')[0] ?? '';
  return JSON.stringify([client.baseUrl, auth, o.project, o.env, normalizePath(o.path), o.prefix ?? '']);
}

function normalizePath(path: string | undefined): string {
  return trimSlashes(path ?? '', true, true);
}

async function fetchFolder(client: Citadel, o: LoadSecretsOptions): Promise<Record<string, string>> {
  const req: RequestOptions = { signal: o.signal };
  if (o.revalidate !== undefined || o.tags) {
    req.next = {};
    if (o.revalidate !== undefined) req.next.revalidate = o.revalidate;
    if (o.tags) req.next.tags = o.tags;
  }
  const ref = { project: o.project, env: o.env, path: normalizePath(o.path) };
  const listing = await client.secrets.list(ref, req);
  const keys = listing.items
    .filter((it) => !it.deletionDate)
    .map((it) => it.key)
    .filter((k) => !o.prefix || k.startsWith(o.prefix));

  const out: Record<string, string> = {};
  const limit = Math.max(1, o.concurrency ?? 8);
  let next = 0;
  const worker = async () => {
    while (next < keys.length) {
      const k = keys[next++]!;
      const v = await client.secrets.get({ ...ref, key: k }, req);
      if (typeof v.value === 'string') out[k] = v.value;
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, keys.length) }, worker));
  // Stable key order regardless of completion order.
  const sorted: Record<string, string> = {};
  for (const k of keys) if (k in out) sorted[k] = out[k]!;
  return sorted;
}

function injectEnv(values: Record<string, string>): void {
  const env = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process?.env;
  if (!env) return;
  for (const [k, v] of Object.entries(values)) {
    if (env[k] === undefined) env[k] = v;
  }
}
