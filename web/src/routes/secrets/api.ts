// Secrets-area client additions. Everything that already exists goes through
// `api` from $lib/api; this file adds:
//   - optional response fields the pages read when the backend provides them
//     (they degrade to "—" or are hidden when absent), and
//   - calls for endpoints this area needs that the backend doesn't have yet.
// Each new contract is documented on its function. Errors use the standard
// `{error, message}` body and surface as ApiError.

import {
  api,
  ApiError,
  req,
  type Item,
  type ItemDetail,
  type ItemVersion,
  type ListResult,
  type Project,
  type SecretTag
} from '$lib/api';
import { envTier, type Tier } from './lib';

/** A row of GET /v1/secrets, plus optional fields the backend may add. */
export interface SecretRow extends Item {
  /** 1-based ordinal of the current version (v7 = seventh version). */
  version?: number;
  /** Who wrote the current version (username or principal ARN). */
  updatedBy?: string;
  /** Tags, so the list can be filtered by tag without a detail call each. */
  tags?: SecretTag[];
}

export interface SecretList extends ListResult {
  items: SecretRow[];
  /** Number of secrets at or below each child folder, keyed by folder name. */
  folderCounts?: Record<string, number>;
}

export interface ProjectInfo extends Project {
  /** Display name set via /v1/projects/rename. */
  name?: string;
  description?: string;
  /** Number of live secrets in each environment (recursive), keyed by env slug. */
  environmentCounts?: Record<string, number>;
}

export interface VersionInfo extends ItemVersion {
  /** Who wrote this version. */
  createdBy?: string;
}

export interface SecretDetail extends ItemDetail {
  /** Character length of the current value, without revealing it. */
  valueLength?: number;
  /** e.g. "sha256:3f9a…c41e" — a truncated hash of the current value. */
  fingerprint?: string;
  updatedBy?: string;
}

/**
 * Whether value changes in an environment need approval. Shared with the
 * Approvals page, which owns the contract:
 *   GET  /v1/change-requests/policies   (viewer)
 *     200 { policies: [{ project, env, approvalsRequired: number, approverRoles: string[] }] }
 *   POST /v1/change-requests/policies   (admin)
 *     body { project, env, approvalsRequired }   — 0 removes the policy
 *     200 { saved: true }
 *
 * While an environment has approvalsRequired > 0 the console sends value
 * writes through POST /v1/change-requests instead of writing directly, and the
 * server should refuse direct writes there (POST /v1/secrets,
 * /v1/secrets/versions/promote, bulk copy/move into it) with
 * 409 { error: "approval_required" }. A requester may not approve their own
 * request.
 */
export interface EnvPolicy {
  project: string;
  env: string;
  requireApproval: boolean;
  minApprovals: number;
  approverRoles: string[];
  /** From the environment's name (dev/staging/prod…), for its color. */
  tier: Tier;
}

export function defaultPolicy(project: string, env: string): EnvPolicy {
  return { project, env, requireApproval: false, minApprovals: 0, approverRoles: [], tier: envTier(env) };
}

const qs = (p: Record<string, string>) => new URLSearchParams(p).toString();

export const secretsApi = {
  list: (project: string, env: string, path: string) => api.list(project, env, path) as Promise<SecretList>,
  projects: async () => (await api.projects()).projects as ProjectInfo[],
  detail: (project: string, env: string, path: string, key: string) =>
    api.secretDetail(project, env, path, key) as Promise<SecretDetail>,
  versions: async (project: string, env: string, path: string, key: string) =>
    (await api.versions(project, env, path, key)).versions as VersionInfo[],

  /** Current value as text (binary values are reported, not shown). */
  async revealValue(project: string, env: string, path: string, key: string): Promise<string> {
    const r = await api.reveal(project, env, path, key);
    return r.value ?? '(binary value — not shown)';
  },

  /**
   * The value of a specific, possibly non-current version. The existing
   * reveal endpoint already accepts it:
   *   GET /v1/secrets/value?project&env&path&key&versionId=<id>   (viewer;
   *   audit citadel.RevealItem) → { key, versionId, value? , binaryValue? }
   */
  async revealVersion(project: string, env: string, path: string, key: string, versionId: string): Promise<string> {
    const r = await req<{ value?: string; binaryValue?: string }>(
      `/v1/secrets/value?${qs({ project, env, path, key, versionId })}`
    );
    return r.value ?? '(binary value — not shown)';
  },

  /** Approval policies for a project's environments, keyed by env. Empty when the backend has none. */
  async envPolicies(project: string): Promise<Record<string, EnvPolicy>> {
    let res: { policies?: { project: string; env: string; approvalsRequired: number; approverRoles?: string[] }[] };
    try {
      res = await req('/v1/change-requests/policies');
    } catch (e) {
      if (e instanceof ApiError && (e.status === 404 || e.status === 405)) return {};
      throw e;
    }
    const out: Record<string, EnvPolicy> = {};
    for (const p of res.policies ?? []) {
      if (p.project !== project) continue;
      out[p.env] = {
        project,
        env: p.env,
        requireApproval: p.approvalsRequired > 0,
        minApprovals: p.approvalsRequired,
        approverRoles: p.approverRoles ?? [],
        tier: envTier(p.env)
      };
    }
    return out;
  },

  savePolicy: (body: { project: string; env: string; approvalsRequired: number }) =>
    req<{ saved: boolean }>('/v1/change-requests/policies', { method: 'POST', body: JSON.stringify(body) }),

  /**
   * NEW CONTRACT — extends POST /v1/secrets/bulk (editor) with two actions:
   *   { project, env, path, keys: string[], action: "copy",
   *     targetEnv: string, targetPath: string, overwrite: boolean }
   *     Copies each key's current value (and tags, description and KMS key)
   *     to targetEnv/targetPath. Existing keys are skipped (reported in
   *     `failed`) unless overwrite. If the target environment requires
   *     approval, a change request is opened per key instead and its id is
   *     returned in `changeRequests`. Audit citadel.BulkCopy.
   *   { project, env, path, keys: string[], action: "move", targetPath: string }
   *     Moves keys to another folder of the same environment, keeping version
   *     history, tags and policy. 409 approval_required if the environment
   *     requires approval. Audit citadel.BulkMove.
   *   200 { applied: number, failed: string[], changeRequests?: string[] }
   */
  bulkCopy: (body: {
    project: string;
    env: string;
    path: string;
    keys: string[];
    targetEnv: string;
    targetPath: string;
    overwrite: boolean;
  }) =>
    req<{ applied: number; failed: string[]; changeRequests?: string[] }>('/v1/secrets/bulk', {
      method: 'POST',
      body: JSON.stringify({ ...body, action: 'copy' })
    }),

  bulkMove: (body: { project: string; env: string; path: string; keys: string[]; targetPath: string }) =>
    req<{ applied: number; failed: string[] }>('/v1/secrets/bulk', {
      method: 'POST',
      body: JSON.stringify({ ...body, action: 'move' })
    })
};

/** Who a resource policy lets read or write, parsed from its JSON. */
export interface AccessEntry {
  principal: string;
  access: 'Read' | 'Write' | 'Read · Write' | 'Full';
  deny: boolean;
}

export function parsePolicyAccess(doc: string): AccessEntry[] {
  if (!doc?.trim()) return [];
  let parsed: { Statement?: unknown };
  try {
    parsed = JSON.parse(doc);
  } catch {
    return [];
  }
  const stmts = Array.isArray(parsed.Statement) ? parsed.Statement : parsed.Statement ? [parsed.Statement] : [];
  const out = new Map<string, { read: boolean; write: boolean; full: boolean; deny: boolean }>();
  for (const raw of stmts as Record<string, unknown>[]) {
    const effect = String(raw.Effect ?? 'Allow');
    const actions = ([] as unknown[]).concat(raw.Action ?? []).map(String);
    const p = raw.Principal as unknown;
    let principals: string[] = [];
    if (p === '*') principals = ['*'];
    else if (p && typeof p === 'object') {
      for (const v of Object.values(p as Record<string, unknown>)) principals.push(...([] as unknown[]).concat(v).map(String));
    }
    const full = actions.some((a) => a === '*' || a === 'secretsmanager:*');
    const read = full || actions.some((a) => /GetSecretValue|DescribeSecret|secretsmanager:Get|secretsmanager:List/i.test(a));
    const write = full || actions.some((a) => /PutSecretValue|UpdateSecret|DeleteSecret|RotateSecret|secretsmanager:Put/i.test(a));
    for (const pr of principals) {
      const cur = out.get(pr) ?? { read: false, write: false, full: false, deny: false };
      if (effect === 'Deny') cur.deny = true;
      else {
        cur.read ||= read;
        cur.write ||= write;
        cur.full ||= full;
      }
      out.set(pr, cur);
    }
  }
  return [...out.entries()].map(([principal, a]) => ({
    principal: shortPrincipal(principal),
    deny: a.deny && !a.read && !a.write,
    access: a.full ? 'Full' : a.read && a.write ? 'Read · Write' : a.write ? 'Write' : 'Read'
  }));
}

function shortPrincipal(arn: string): string {
  if (arn === '*') return 'Anyone (*)';
  const m = arn.match(/^arn:[^:]+:(?:iam|sts)::\d+:(.+)$/);
  return m ? m[1] : arn;
}
