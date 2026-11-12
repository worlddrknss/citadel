// Approvals calls beyond $lib/api's list/create/approve/reject. Contracts are
// documented on each call; values never travel except through the explicit,
// audited reveal call.

import { ApiError, req, type ChangeRequest } from '$lib/api';
import { qs } from '../http';

export interface ValueFingerprint {
  /** Lowercase hex SHA-256 of the UTF-8 value. */
  sha256: string;
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
}

export interface ApprovalPolicy {
  project: string;
  env: string;
  approvalsRequired: number;
  approverRoles: string[];
}

/** Retries without `comment` on servers whose strict decoder rejects it. */
async function decide(kind: 'approve' | 'reject', id: string, comment: string) {
  const path = `/v1/change-requests/${kind}`;
  const body = comment ? { id, comment } : { id };
  try {
    return await req<unknown>(path, { method: 'POST', body: JSON.stringify(body) });
  } catch (e) {
    if (comment && e instanceof ApiError && e.status === 400 && /unknown field/i.test(e.message)) {
      return await req<unknown>(path, { method: 'POST', body: JSON.stringify({ id }) });
    }
    throw e;
  }
}

export const approvalsApi = {
  /** GET /v1/change-requests/detail?id= — viewer. */
  detail: (id: string) => req<ChangeRequestDetail>(`/v1/change-requests/detail${qs({ id })}`),
  /** GET /v1/change-requests/values?id= — editor; audited as citadel.RevealChangeRequest. */
  values: (id: string) =>
    req<{ changes: { key: string; previousValue?: string; proposedValue?: string }[] }>(
      `/v1/change-requests/values${qs({ id })}`
    ),
  /** POST /v1/change-requests/approve {id, comment?}. */
  approve: (id: string, comment: string) => decide('approve', id, comment),
  /** POST /v1/change-requests/reject {id, comment}. */
  reject: (id: string, comment: string) => decide('reject', id, comment),
  /** GET /v1/change-requests/policies — viewer. */
  policies: () => req<{ policies: ApprovalPolicy[] }>('/v1/change-requests/policies'),
  /** POST /v1/change-requests/policies — admin. approvalsRequired 0 removes the policy. */
  savePolicy: (p: { project: string; env: string; approvalsRequired: number }) =>
    req<{ saved: boolean }>('/v1/change-requests/policies', { method: 'POST', body: JSON.stringify(p) })
};

export function fingerprint(f?: ValueFingerprint): string {
  if (!f) return '—';
  const h = f.sha256.replace(/^sha256:/, '');
  return `sha256:${h.slice(0, 4)}…${h.slice(-4)} · ${f.length} chars`;
}

/** "CR-1042"-style display id for long ids. */
export function shortId(id: string): string {
  return /^\d+$/.test(id) ? `CR-${id}` : id.length > 10 ? `CR-${id.slice(0, 6)}` : id;
}

export function envTone(env: string): 'danger' | 'warning' | 'info' | 'neutral' {
  const e = env.toLowerCase();
  if (e.startsWith('prod')) return 'danger';
  if (e.startsWith('stag') || e === 'uat' || e.startsWith('pre')) return 'warning';
  if (e.startsWith('dev') || e === 'test' || e === 'qa') return 'info';
  return 'neutral';
}
