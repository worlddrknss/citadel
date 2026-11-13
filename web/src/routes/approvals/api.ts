// Approvals calls beyond #lib/api's list/create/approve/reject. Contracts are
// documented on each call; values never travel except through the explicit,
// audited reveal call.

import { ApiError, req, type ChangeRequest } from '#lib/api.ts';
import { qs } from '../http';

export interface ValueFingerprint {
  /**
   * Keyed fingerprint of the value, "hmac:<12 hex>": an HMAC under a
   * per-deployment key, comparable with the secret detail's fingerprint but
   * not brute-forceable offline. It is not a hash of the value.
   */
  fingerprint?: string;
  /** Older servers: the same keyed HMAC as bare hex (the name is historical). */
  sha256?: string;
  /** Length in characters. */
  length: number;
  /** Version the value is (previous) or will become (proposed), e.g. "v8". */
  version?: string;
}

export interface ChangeItem {
  key: string;
  path: string;
  change: 'added' | 'modified' | 'deleted';
  previous?: ValueFingerprint;
  proposed?: ValueFingerprint;
}

export interface ApprovalPolicySummary {
  name: string;
  approvalsRequired: number;
  approverRoles: string[];
}

export interface ChangeRequestDetail extends ChangeRequest {
  title?: string;
  comment?: string;
  requesterDisplayName?: string;
  requesterRole?: string;
  decisionComment?: string;
  changes: ChangeItem[];
  policy?: ApprovalPolicySummary;
  approvals?: { username: string; decidedAt: string; comment?: string }[];
  /** Server's answer to "may the caller approve this?" (requester never may). */
  canApprove: boolean;
  cannotApproveReason?: string;
  /** Approvers, and the requester withdrawing, may reject a pending request. */
  canReject?: boolean;
}

/** GET /v1/change-requests rows; pending rows carry their approval state. */
export interface ChangeRequestRow extends ChangeRequest {
  title?: string;
  approvals?: number;
  approvalsRequired?: number;
  approverRoles?: string[];
  /** Whether the caller may approve (pending rows only). */
  canApprove?: boolean;
}

/** POST /v1/change-requests/approve response. */
export interface ApproveResult {
  id: string;
  approvals: number;
  approvalsRequired: number;
  approved: boolean;
  /** False while more approvals are needed. */
  applied: boolean;
  status: string;
}

export interface ApprovalPolicy {
  project: string;
  env: string;
  approvalsRequired: number;
  approverRoles: string[];
  /**
   * "project": set for this project/environment, removable here.
   * "organization": from the organization's approval environments
   * (Administration → Organization settings); not removable per project.
   */
  source?: 'project' | 'organization';
}

/** The server accepts 0–10 approvals per policy. */
export const MAX_APPROVALS = 10;

/** Retries without `comment` on servers whose strict decoder rejects it. */
async function decide<T>(kind: 'approve' | 'reject', id: string, comment: string): Promise<T> {
  const path = `/v1/change-requests/${kind}`;
  const body = comment ? { id, comment } : { id };
  try {
    return await req<T>(path, { method: 'POST', body: JSON.stringify(body) });
  } catch (e) {
    if (comment && e instanceof ApiError && e.status === 400 && /unknown field/i.test(e.message)) {
      return await req<T>(path, { method: 'POST', body: JSON.stringify({ id }) });
    }
    throw e;
  }
}

export const approvalsApi = {
  /** GET /v1/change-requests — viewer. */
  list: async () => (await req<{ changeRequests: ChangeRequestRow[] }>('/v1/change-requests')).changeRequests,
  /** GET /v1/change-requests/detail?id= — viewer. */
  detail: (id: string) => req<ChangeRequestDetail>(`/v1/change-requests/detail${qs({ id })}`),
  /** GET /v1/change-requests/values?id= — editor; audited as citadel.RevealChangeRequest. */
  values: (id: string) =>
    req<{ changes: { key: string; previousValue?: string; proposedValue?: string }[] }>(
      `/v1/change-requests/values${qs({ id })}`
    ),
  /** POST /v1/change-requests/approve {id, comment?}. */
  approve: (id: string, comment: string) => decide<ApproveResult>('approve', id, comment),
  /** POST /v1/change-requests/reject {id, comment}. */
  reject: (id: string, comment: string) => decide<{ rejected: boolean; id: string }>('reject', id, comment),
  /** GET /v1/change-requests/policies — viewer. */
  policies: () => req<{ policies: ApprovalPolicy[] }>('/v1/change-requests/policies'),
  /**
   * POST /v1/change-requests/policies — admin. approvalsRequired 0 removes the
   * project policy. approverRoles ⊆ {admin, editor}; empty means admin. The
   * server replaces the whole policy, so always send the roles.
   */
  savePolicy: (p: { project: string; env: string; approvalsRequired: number; approverRoles: string[] }) =>
    req<{ saved: boolean }>('/v1/change-requests/policies', { method: 'POST', body: JSON.stringify(p) })
};

/** The keyed fingerprint as "hmac:<hex>" ('' when the server sent none). */
export function fingerprintOf(f?: ValueFingerprint): string {
  if (!f) return '';
  if (f.fingerprint) return f.fingerprint;
  return f.sha256 ? `hmac:${f.sha256.replace(/^(sha256|hmac):/, '')}` : '';
}

export function fingerprint(f?: ValueFingerprint): string {
  if (!f) return '—';
  const fp = fingerprintOf(f);
  return `${fp ? `fingerprint ${fp}` : 'no fingerprint'} · ${f.length} chars`;
}

/** "CR-1a2b3c"-style display id; server ids are "cr-<12 hex>". */
export function shortId(id: string): string {
  const bare = id.replace(/^cr-/i, '');
  if (/^\d+$/.test(bare)) return `CR-${bare}`;
  return `CR-${bare.length > 6 ? bare.slice(0, 6) : bare}`;
}

/** Whether an approver role list lets `role` approve (admin ≥ editor). */
export function roleMayApprove(role: string | undefined, approverRoles: string[] | undefined): boolean {
  const rank: Record<string, number> = { viewer: 1, editor: 2, admin: 3 };
  const roles = approverRoles?.length ? approverRoles : ['admin'];
  return roles.some((r) => (rank[role ?? ''] ?? 0) >= (rank[r] ?? 99));
}

export function envTone(env: string): 'danger' | 'warning' | 'info' | 'neutral' {
  const e = env.toLowerCase();
  if (e.startsWith('prod')) return 'danger';
  if (e.startsWith('stag') || e === 'uat' || e.startsWith('pre')) return 'warning';
  if (e.startsWith('dev') || e === 'test' || e === 'qa') return 'info';
  return 'neutral';
}
