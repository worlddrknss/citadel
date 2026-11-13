// Client for AI agents: principals that use credentials without holding
// them. Shapes follow internal/server/routes_agents.go.

import { req, type AuditEvent } from '#lib/api.ts';

export type AgentStatus = 'active' | 'suspended' | 'revoked';
export type CredentialKind = 'http_header' | 'http_basic' | 'http_query' | 'login' | 'raw';
export type GrantAction = 'use' | 'reveal' | 'totp';

export interface Agent {
  agentId: string;
  name: string;
  description: string;
  owner: string;
  status: AgentStatus;
  labels: Record<string, string>;
  createdAt: string;
  createdBy?: string;
  updatedAt: string;
  lastUsedAt?: string;
  statusChangedAt?: string;
  statusChangedBy?: string;
  statusReason?: string;
  grantCount: number;
  activeTokenCount: number;
  bindingCount: number;
  /** Agent tokens are refused; the agent authenticates with workload identity federation only. */
  requireFederation?: boolean;
  canManage: boolean;
}

export interface AgentSettings {
  agentsSuspended: boolean;
  suspendedAt?: string;
  suspendedBy?: string;
  reason?: string;
}

export interface AgentToken {
  tokenId: string;
  name: string;
  prefix: string;
  status: 'active' | 'expired' | 'revoked';
  createdAt: string;
  createdBy?: string;
  expiresAt?: string;
  revokedAt?: string;
  revokedBy?: string;
  lastUsedAt?: string;
}

export interface AgentBinding {
  bindingId: string;
  issuer: string;
  subject: string;
  audience: string;
  description: string;
  createdAt: string;
  createdBy?: string;
}

export interface GrantWindow {
  start: string;
  end: string;
  days: string[];
  timezone: string;
}

export interface AgentGrant {
  grantId: string;
  agentId: string;
  agentName?: string;
  credential: string;
  actions: GrantAction[];
  notBefore?: string;
  notAfter?: string;
  window: GrantWindow | null;
  maxUsesPerHour: number;
  requiresApproval: boolean | null;
  leaseTtlSeconds: number | null;
  createdAt: string;
  updatedAt: string;
  usableNow: boolean;
  reason?: string;
}

export interface AgentDetail {
  agent: Agent;
  tokens: AgentToken[];
  bindings: AgentBinding[];
  grants: AgentGrant[];
}

export interface AgentCredential {
  name: string;
  secretName: string;
  project?: string;
  env?: string;
  path?: string;
  key?: string;
  kind: CredentialKind;
  description: string;
  allowedHosts: string[];
  allowedMethods: string[];
  allowedPathPrefixes: string[];
  headerName?: string;
  headerPrefix?: string;
  queryParam?: string;
  allowHttp: boolean;
  allowedCidrs: string[];
  createdAt: string;
  updatedAt: string;
  updatedBy?: string;
  grants: { grantId: string; agentId: string; agentName: string; actions: GrantAction[] }[];
}

export interface CredentialInput {
  name: string;
  secret?: string;
  project?: string;
  env?: string;
  path?: string;
  key?: string;
  kind: CredentialKind;
  description?: string;
  allowedHosts?: string[];
  allowedMethods?: string[];
  allowedPathPrefixes?: string[];
  headerName?: string;
  headerPrefix?: string;
  queryParam?: string;
  allowHttp?: boolean;
  allowedCidrs?: string[];
}

export interface GrantInput {
  agentId: string;
  credential: string;
  actions: GrantAction[];
  notBefore?: string;
  notAfter?: string;
  window?: GrantWindow | null;
  maxUsesPerHour?: number;
  requiresApproval?: boolean;
  /** 0 (not set) or 60..86400. */
  leaseTtlSeconds?: number;
}

// ---- access requests and leases (2.3), routes_agent_access.go ----------------

export type AccessRequestStatus = 'pending' | 'approved' | 'denied' | 'expired' | 'cancelled';
export type LeaseScope = 'once' | 'duration' | 'task';
export type LeaseStatus = 'active' | 'expired' | 'used' | 'ended';

export interface AgentLease {
  leaseId: string;
  agentId: string;
  agentName?: string;
  credential: string;
  actions: GrantAction[];
  scope: LeaseScope;
  taskId?: string;
  /** null: unlimited uses until expiry. */
  usesLeft: number | null;
  useCount: number;
  expiresAt: string;
  createdAt: string;
  /** The approver, or "policy" for a lease opened by a grant's lease TTL. */
  createdBy: string;
  requestId?: string;
  status: LeaseStatus;
  lastUsedAt?: string;
  endedAt?: string;
  endedBy?: string;
  endedReason?: string;
  canRevoke?: boolean;
}

export interface AccessRequest {
  requestId: string;
  credential: string;
  actions: GrantAction[];
  /** The agent's own words: untrusted, render as text. */
  reason?: string;
  taskId?: string;
  durationSeconds?: number;
  origin: 'policy' | 'agent';
  status: AccessRequestStatus;
  createdAt: string;
  expiresAt: string;
  decidedAt?: string;
  decidedBy?: string;
  decisionComment?: string;
  scope?: LeaseScope;
  agentId: string;
  agentName: string;
  agentOwner: string;
  agentStatus: string;
  leaseId?: string;
  /** '' / absent when no credential has the requested name. */
  credentialKind?: CredentialKind | '';
  /** null: the agent has no grant for the credential. */
  grant: { actions: GrantAction[]; requiresApproval: boolean; leaseTtlSeconds?: number; notAfter?: string } | null;
  maxDurationSeconds: number;
  canDecide: boolean;
  cannotDecideReason?: string;
  mfaRequired?: boolean;
}

export interface ApproveInput {
  requestId: string;
  scope: LeaseScope;
  durationSeconds?: number;
  comment?: string;
  mfaCode?: string;
  recoveryCode?: string;
}

const qs = (p: Record<string, string>) => new URLSearchParams(p).toString();
const post = <T>(path: string, body: unknown) => req<T>(path, { method: 'POST', body: JSON.stringify(body) });

export const agentsApi = {
  list: () => req<{ agents: Agent[]; settings: AgentSettings; canCreate: boolean }>('/v1/agents'),
  detail: (agentId: string) => req<AgentDetail>(`/v1/agents/detail?${qs({ agentId })}`),
  create: (body: { name: string; description?: string; owner?: string; labels?: Record<string, string>; requireFederation?: boolean }) =>
    post<Agent>('/v1/agents', body),
  update: (body: { agentId: string; name: string; description?: string; owner?: string; labels?: Record<string, string>; requireFederation?: boolean }) =>
    post<Agent>('/v1/agents/update', body),
  remove: (agentId: string) => req<{ deleted: boolean }>(`/v1/agents?${qs({ agentId })}`, { method: 'DELETE' }),
  suspend: (agentId: string, reason = '') => post<Agent>('/v1/agents/suspend', { agentId, reason }),
  resume: (agentId: string) => post<Agent>('/v1/agents/resume', { agentId }),
  revoke: (agentId: string, reason = '') => post<Agent>('/v1/agents/revoke', { agentId, reason }),

  createToken: (agentId: string, name: string, expiresInDays: number) =>
    post<{ token: string; tokenInfo: AgentToken }>('/v1/agents/tokens', { agentId, name, expiresInDays }),
  revokeToken: (agentId: string, tokenId: string) => post<{ revoked: boolean }>('/v1/agents/tokens/revoke', { agentId, tokenId }),

  createBinding: (body: { agentId: string; issuer: string; subject: string; audience: string; description?: string }) =>
    post<AgentBinding>('/v1/agents/bindings', body),
  deleteBinding: (agentId: string, bindingId: string) =>
    req<{ deleted: boolean }>(`/v1/agents/bindings?${qs({ agentId, bindingId })}`, { method: 'DELETE' }),

  putGrant: (body: GrantInput) => post<AgentGrant>('/v1/agents/grants', body),
  deleteGrant: (agentId: string, grantId: string) =>
    req<{ deleted: boolean }>(`/v1/agents/grants?${qs({ agentId, grantId })}`, { method: 'DELETE' }),

  credentials: (filter?: { project: string; env: string; path: string; key: string }) =>
    req<{ credentials: AgentCredential[]; canEdit: boolean }>(`/v1/agents/credentials${filter ? `?${qs(filter)}` : ''}`),
  createCredential: (body: CredentialInput) => post<AgentCredential>('/v1/agents/credentials', body),
  updateCredential: (body: CredentialInput) => post<AgentCredential>('/v1/agents/credentials/update', body),
  deleteCredential: (name: string) => req<{ deleted: boolean }>(`/v1/agents/credentials?${qs({ name })}`, { method: 'DELETE' }),

  /** Access requests, newest first: one agent's or the account's; pending only by default. */
  accessRequests: async (opts: { agentId?: string; status?: 'pending' | 'all' } = {}) =>
    (
      await req<{ requests: AccessRequest[] }>(
        `/v1/agents/access-requests?${qs({ ...(opts.agentId ? { agentId: opts.agentId } : {}), status: opts.status ?? 'pending' })}`
      )
    ).requests ?? [],
  approveAccess: (body: ApproveInput) => post<{ request: AccessRequest; lease: AgentLease }>('/v1/agents/access-requests/approve', body),
  denyAccess: (requestId: string, comment: string) => post<{ request: AccessRequest }>('/v1/agents/access-requests/deny', { requestId, comment }),
  leases: async (opts: { agentId?: string; active?: boolean } = {}) =>
    (
      await req<{ leases: AgentLease[] }>(
        `/v1/agents/leases?${qs({ ...(opts.agentId ? { agentId: opts.agentId } : {}), ...(opts.active === false ? { active: 'false' } : {}) })}`
      )
    ).leases ?? [],
  revokeLease: (leaseId: string, reason = '') => post<AgentLease>('/v1/agents/leases/revoke', { leaseId, reason }),

  settings: () => req<AgentSettings>('/v1/agents/settings'),
  saveSettings: (agentsSuspended: boolean, reason = '') => post<AgentSettings>('/v1/agents/settings', { agentsSuspended, reason }),

  /** The agent's activity: what it did and console changes to it, newest first. */
  activity: async (agentId: string): Promise<AuditEvent[]> =>
    (await req<{ events: AuditEvent[] }>(`/v1/audit/events?${qs({ agent: agentId, limit: '200' })}`)).events ?? []
};

// Field rules, mirroring routes_agents.go.
export const AGENT_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
export const CREDENTIAL_NAME_RE = /^[a-z0-9][a-z0-9._-]{0,62}$/;
export const HOST_RE = /^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(:[0-9]{1,5})?$/;
export const HHMM_RE = /^([01][0-9]|2[0-3]):[0-5][0-9]$/;
export const HTTP_METHODS = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'] as const;
export const WEEKDAYS = ['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun'] as const;

export const KIND_LABELS: Record<CredentialKind, string> = {
  http_header: 'HTTP header',
  http_basic: 'HTTP basic auth',
  http_query: 'Query parameter',
  login: 'Website login',
  raw: 'Raw value'
};

export const KIND_HINTS: Record<CredentialKind, string> = {
  http_header: 'Citadel adds the value as a request header (Authorization: Bearer … by default).',
  http_basic: 'The secret is JSON {"username", "password"}; Citadel sends it as HTTP basic auth.',
  http_query: 'Citadel adds the value as a query parameter.',
  login: 'The secret is JSON {"username", "password", "totpSeed"?, "url"} for browser agents.',
  raw: 'An opaque value agents can only get through an explicit reveal grant.'
};

export const isHttpKind = (k: CredentialKind) => k === 'http_header' || k === 'http_basic' || k === 'http_query';

export const STATUS_TONE: Record<AgentStatus, 'success' | 'warning' | 'danger'> = { active: 'success', suspended: 'warning', revoked: 'danger' };
export const STATUS_LABEL: Record<AgentStatus, string> = { active: 'Active', suspended: 'Suspended', revoked: 'Revoked' };

export const REASON_LABELS: Record<string, string> = {
  not_yet_valid: 'Not valid yet',
  grant_expired: 'Expired',
  outside_window: 'Outside its time window',
  credential_unavailable: 'Secret missing'
};

/** Validates a usage profile form; '' when valid. */
export function validateCredential(c: CredentialInput): string {
  if (!CREDENTIAL_NAME_RE.test(c.name)) return 'Name: 1-63 lowercase letters, digits, dots, dashes or underscores.';
  const hosts = c.allowedHosts ?? [];
  if (isHttpKind(c.kind) && hosts.length === 0) return 'Add at least one allowed host.';
  for (const h of hosts) {
    if (!HOST_RE.test(h)) return `"${h}" is not a host name (api.example.com or *.example.com).`;
    if (h.startsWith('*.') && !h.slice(2).includes('.')) return `"${h}" is too broad; use at least *.example.com.`;
  }
  for (const p of c.allowedPathPrefixes ?? []) if (!p.startsWith('/')) return `Path prefixes start with / ("${p}").`;
  if (c.kind === 'http_query' && !/^[A-Za-z0-9._~-]{1,64}$/.test(c.queryParam ?? '')) return 'Name the query parameter.';
  return '';
}

/** Validates a grant form; '' when valid. */
export function validateGrant(g: GrantInput, kind: CredentialKind | undefined): string {
  if (!g.credential) return 'Choose a credential.';
  if (g.actions.length === 0) return 'Choose at least one action.';
  if (g.actions.includes('totp') && kind !== 'login') return 'TOTP codes are only for website logins.';
  if (g.actions.includes('use') && kind === 'raw') return 'Raw values can only be revealed.';
  if (g.notBefore && g.notAfter && new Date(g.notAfter) <= new Date(g.notBefore)) return '"Until" must be after "from".';
  if (g.window && (g.window.start || g.window.end)) {
    if (!HHMM_RE.test(g.window.start) || !HHMM_RE.test(g.window.end)) return 'Times are HH:MM.';
  }
  if ((g.maxUsesPerHour ?? 0) < 0 || (g.maxUsesPerHour ?? 0) > 100000) return 'Uses per hour: 0 (unlimited) to 100000.';
  const ttl = g.leaseTtlSeconds ?? 0;
  if (ttl !== 0 && (ttl < 60 || ttl > 86400)) return 'Lease length: 1 minute to 24 hours.';
  return '';
}

/** One-line summary of a grant's limits. */
export function grantLimits(g: Pick<AgentGrant, 'window' | 'maxUsesPerHour' | 'notAfter'> & Partial<Pick<AgentGrant, 'requiresApproval' | 'leaseTtlSeconds'>>): string {
  const parts: string[] = [];
  if (g.requiresApproval) parts.push('needs approval');
  if (g.leaseTtlSeconds) parts.push(`leases ${formatDuration(g.leaseTtlSeconds)}`);
  if (g.window?.start) parts.push(`${g.window.start}–${g.window.end}${g.window.timezone ? ` ${g.window.timezone}` : ' UTC'}`);
  if (g.window?.days?.length) parts.push(g.window.days.join(', '));
  if (g.maxUsesPerHour) parts.push(`${g.maxUsesPerHour}/hour`);
  if (g.notAfter) parts.push(`until ${new Date(g.notAfter).toLocaleDateString(undefined, { dateStyle: 'medium' })}`);
  return parts.join(' · ') || 'No limits';
}

/** Splits a comma/newline separated list. */
export const splitList = (v: string) =>
  v
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter(Boolean);

/** "1h 30m", "45m", "2h", "90s". */
export function formatDuration(seconds: number): string {
  if (!seconds || seconds < 0) return '0m';
  if (seconds < 60) return `${seconds}s`;
  const h = Math.floor(seconds / 3600);
  const m = Math.round((seconds % 3600) / 60);
  if (h && m) return `${h}h ${m}m`;
  return h ? `${h}h` : `${m}m`;
}

/** The approval's default lease length: what the agent asked for, or an hour, never above the cap. */
export function defaultApprovalSeconds(r: Pick<AccessRequest, 'durationSeconds' | 'maxDurationSeconds'>): number {
  return Math.max(0, Math.min(r.durationSeconds || 3600, r.maxDurationSeconds));
}

/** Validates an approval form; '' when valid. */
export function validateApproval(a: ApproveInput, r: Pick<AccessRequest, 'taskId' | 'maxDurationSeconds' | 'mfaRequired'>): string {
  if (a.scope === 'task' && !r.taskId) return 'This request has no task ID.';
  const d = a.durationSeconds ?? 0;
  if (r.maxDurationSeconds < 60) return "The agent's grant ends in less than a minute.";
  if (d < 60 || d > r.maxDurationSeconds) return `Length: 1 minute to ${formatDuration(r.maxDurationSeconds)}.`;
  if (r.mfaRequired && !(a.mfaCode ?? '').trim() && !(a.recoveryCode ?? '').trim()) return 'Enter a code from your authenticator app.';
  return '';
}

export const ACCESS_STATUS: Record<AccessRequestStatus, { label: string; tone: 'neutral' | 'success' | 'warning' | 'danger' | 'info' }> = {
  pending: { label: 'Pending', tone: 'info' },
  approved: { label: 'Approved', tone: 'success' },
  denied: { label: 'Denied', tone: 'danger' },
  expired: { label: 'Expired', tone: 'neutral' },
  cancelled: { label: 'Cancelled', tone: 'neutral' }
};

export const LEASE_STATUS: Record<LeaseStatus, { label: string; tone: 'neutral' | 'success' | 'warning' | 'danger' }> = {
  active: { label: 'Active', tone: 'success' },
  expired: { label: 'Expired', tone: 'neutral' },
  used: { label: 'Used', tone: 'neutral' },
  ended: { label: 'Revoked', tone: 'warning' }
};

export const SCOPE_LABELS: Record<LeaseScope, string> = { once: 'Once', duration: 'For a time', task: 'For the task' };

/** "in 42 min", "in 3 h", "in 2 days", or "expired" for a time in the past. */
export function timeLeft(iso: string, now = new Date()): string {
  const s = Math.round((Date.parse(iso) - now.getTime()) / 1000);
  if (Number.isNaN(s)) return iso;
  if (s <= 0) return 'expired';
  if (s < 3600) return `in ${Math.max(1, Math.round(s / 60))} min`;
  if (s < 2 * 86400) return `in ${Math.round(s / 3600)} h`;
  return `in ${Math.round(s / 86400)} days`;
}
