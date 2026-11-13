// Audit log calls: server-side filtered paging, chain verification, export
// and SIEM streaming. Falls back to the legacy GET /v1/audit (latest 500,
// filtered here) when the server doesn't have the paged endpoint yet.

import { api, req } from '#lib/api.ts';
import { isNotImplemented, qs, rawRequest } from '../http';

export type ResultFilter = '' | 'success' | 'denied' | 'error' | 'pending';

export interface AuditFilters {
  /** ISO-8601 instants, inclusive. */
  from?: string;
  to?: string;
  actor?: string;
  action?: string;
  result?: ResultFilter;
  resource?: string;
  /** Exact correlation ID: a write-ahead attempt and its outcomes. */
  correlation?: string;
  /** Exact agent ID: events made by or about one AI agent. */
  agent?: string;
}

export interface AuditRow {
  id: number;
  createdAt: string;
  actor: string;
  /** console | access-key | sts | acme | system… (how the actor authenticated). */
  actorType?: string;
  actorDisplayName?: string;
  /** The access key used, for SigV4 calls. */
  accessKeyId?: string;
  action: string;
  resource?: string;
  keyId?: string;
  result: string;
  errorType?: string;
  sourceIp?: string;
  userAgent?: string;
  /** Position in the hash chain (gapless); `id` may have gaps. */
  chainSeq?: number;
  prevHash?: string;
  hash?: string;
  /** Server recomputed this event's hash and it matched. */
  hashValid?: boolean;
  /**
   * Links a write-ahead attempt (result "pending", written before the change)
   * to its outcome events.
   */
  correlationId?: string;
  /** The AI agent the event concerns, its owner and the agent's task ID. */
  agentId?: string;
  agentOwner?: string;
  taskId?: string;
}

export interface AuditPage {
  events: AuditRow[];
  total: number;
  limit: number;
  offset: number;
  /** True when served by the legacy endpoint (latest 500, filtered client-side). */
  legacy?: boolean;
}

export interface ChainStatus {
  status: 'verified' | 'broken' | 'never';
  /** Event IDs (not chain positions). */
  verifiedThrough?: number;
  headHash?: string;
  checkedAt?: string;
  brokenAt?: number;
  totalEvents?: number;
  /** Pre-2.0 (hash version 1) events in the chain. */
  legacyEvents?: number;
  /**
   * Links among pre-2.0 events that don't connect. Citadel 1.x appended
   * without locking the chain, so concurrent requests could link to the same
   * event; these don't make the chain broken.
   */
  legacyLinkBreaks?: number;
  /** Chain position and event ID of the first such link. */
  firstLegacyBreakSeq?: number;
  firstLegacyBreakId?: number;
  /** Where the chain starts after retention pruning. */
  anchor?: ChainAnchor;
}

/**
 * The authenticated start of the chain after retention pruning: every event
 * up to and including `chainSeq` was deleted on purpose.
 */
export interface ChainAnchor {
  chainSeq: number;
  eventId: number;
  hash: string;
  /** Timestamp of the last pruned event; everything older is gone. */
  prunedBefore: string;
  prunedEvents: number;
  updatedAt: string;
}

/** GET /v1/audit/retention. */
export interface Retention {
  /** In force; 0 keeps events forever. */
  retentionDays: number;
  source: 'account' | 'deployment';
  /** The account's override; null uses the deployment default. */
  accountDays: number | null;
  deploymentDays: number;
  minDays: number;
  maxDays: number;
  updatedBy?: string;
  updatedAt?: string;
  /** SIEM streaming is on: events are pruned only once delivered. */
  streamHeld: boolean;
  events: number;
  oldestEvent?: string;
  anchor?: ChainAnchor;
  /** Platform admins only; deployment-wide. */
  storage?: { tableBytes: number; tableRowsEstimate: number };
  /** Platform admins only; deployment-wide. */
  lastRun?: { startedAt?: string; finishedAt?: string; prunedEvents: number; error?: string };
}

export interface RetentionPreview {
  retentionDays: number;
  cutoff?: string;
  prunableEvents: number;
  events: number;
  oldestEvent?: string;
}

/** "Keep forever" or "90 days". */
export function retentionLabel(days: number): string {
  if (days <= 0) return 'Keep forever';
  return days === 1 ? '1 day' : `${days.toLocaleString()} days`;
}

/** "1.9 GB" (binary units, one decimal from MB up); "—" when unknown. */
export function formatBytes(n: number | undefined): string {
  if (n == null || n < 0) return '—';
  const units = ['bytes', 'KB', 'MB', 'GB', 'TB'];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return i === 0 ? `${v} bytes` : `${v.toFixed(i >= 2 ? 1 : 0)} ${units[i]}`;
}

/** The note shown when the chain starts at a pruning anchor. */
export function anchorNote(a: ChainAnchor | null | undefined, fmt: (iso: string) => string = (s) => new Date(s).toLocaleString()): string {
  if (!a) return '';
  const n = a.prunedEvents;
  return `History before ${fmt(a.prunedBefore)} was pruned by the retention policy (${n.toLocaleString()} ${n === 1 ? 'event' : 'events'}). Verification starts at the signed anchor, chain position ${a.chainSeq.toLocaleString()}.`;
}

/** The amber note shown when pre-2.0 history has links that don't connect. */
export function legacyBreakNote(c: Pick<ChainStatus, 'legacyLinkBreaks'> | null | undefined): string {
  const n = c?.legacyLinkBreaks ?? 0;
  if (n <= 0) return '';
  return `${n.toLocaleString()} ${n === 1 ? "link in pre-2.0 history doesn't" : "links in pre-2.0 history don't"} connect. This is consistent with concurrent writes in Citadel 1.x, which didn't lock the chain; events from 2.0 on are fully verified.`;
}

export interface StreamConfig {
  enabled: boolean;
  url: string;
  format: 'json' | 'cef';
  hasToken: boolean;
}

export function resultKind(r: Pick<AuditRow, 'result' | 'errorType'>): 'success' | 'denied' | 'error' | 'pending' {
  const v = (r.result || '').toLowerCase();
  if (v === 'ok' || v === 'success') return 'success';
  if (v === 'pending') return 'pending';
  if (v === 'denied' || /denied|forbidden|unauthori[sz]ed/i.test(r.errorType ?? '')) return 'denied';
  return 'error';
}

function matches(e: AuditRow, f: AuditFilters): boolean {
  const t = Date.parse(e.createdAt);
  if (f.from && t < Date.parse(f.from)) return false;
  if (f.to && t > Date.parse(f.to)) return false;
  const has = (hay: string | undefined, needle?: string) =>
    !needle || (hay ?? '').toLowerCase().includes(needle.toLowerCase());
  if (!has(`${e.actor} ${e.actorDisplayName ?? ''}`, f.actor)) return false;
  if (!has(e.action, f.action)) return false;
  if (!has(`${e.resource ?? ''} ${e.keyId ?? ''}`, f.resource)) return false;
  if (f.result && resultKind(e) !== f.result) return false;
  if (f.correlation && e.correlationId !== f.correlation) return false;
  if (f.agent && e.agentId !== f.agent) return false;
  return true;
}

async function legacy(f: AuditFilters): Promise<AuditRow[]> {
  const { events } = await api.audit();
  return events.map((e) => ({ ...e, resource: e.keyId })).filter((e) => matches(e, f));
}

export const auditApi = {
  /**
   * GET /v1/audit/events?from&to&actor&action&result&resource&limit&offset — viewer.
   * Newest first. Text filters are case-insensitive "contains".
   */
  async list(f: AuditFilters, limit: number, offset: number): Promise<AuditPage> {
    try {
      return await req<AuditPage>(`/v1/audit/events${qs({ ...f, limit, offset })}`);
    } catch (e) {
      if (!isNotImplemented(e)) throw e;
      const rows = await legacy(f);
      return { events: rows.slice(offset, offset + limit), total: rows.length, limit, offset, legacy: true };
    }
  },
  /** GET /v1/audit/verify — viewer. Last verification result. */
  chainStatus: () => req<ChainStatus>('/v1/audit/verify'),
  /** POST /v1/audit/verify — viewer. Re-walks the chain now and returns the result. */
  verify: () => req<ChainStatus>('/v1/audit/verify', { method: 'POST' }),
  /**
   * POST /v1/audit/verify?full=true — platform admins. Re-walks the whole
   * chain from the first event instead of continuing from the last checkpoint.
   */
  verifyFull: () => req<ChainStatus>('/v1/audit/verify?full=true', { method: 'POST' }),
  /**
   * GET /v1/audit/export?format=csv|json&<filters> — viewer; audited as
   * citadel.ExportAudit. Falls back to exporting the legacy listing here.
   */
  async export(format: 'csv' | 'json', f: AuditFilters): Promise<Blob> {
    try {
      const res = await rawRequest(`/v1/audit/export${qs({ ...f, format })}`);
      return await res.blob();
    } catch (e) {
      if (!isNotImplemented(e)) throw e;
      const rows = await legacy(f);
      return format === 'json'
        ? new Blob([JSON.stringify(rows, null, 2)], { type: 'application/json' })
        : new Blob([toCsv(rows)], { type: 'text/csv' });
    }
  },
  /** GET /v1/audit/stream — viewer. */
  stream: () => req<StreamConfig>('/v1/audit/stream'),
  /** POST /v1/audit/stream — admin. Omit token to keep the stored one. */
  saveStream: (body: { enabled: boolean; url: string; format: 'json' | 'cef'; token?: string }) =>
    req<StreamConfig>('/v1/audit/stream', { method: 'POST', body: JSON.stringify(body) }),
  /** POST /v1/audit/stream/test — admin. Sends one synthetic event. */
  testStream: () => req<{ delivered: boolean; status?: number }>('/v1/audit/stream/test', { method: 'POST' }),
  /** GET /v1/audit/retention — viewer. */
  retention: () => req<Retention>('/v1/audit/retention'),
  /**
   * POST /v1/audit/retention — admin. Days (0 keeps events forever), or null
   * for the deployment default. Audited.
   */
  saveRetention: (retentionDays: number | null) =>
    req<Retention>('/v1/audit/retention', { method: 'POST', body: JSON.stringify({ retentionDays }) }),
  /** GET /v1/audit/retention/preview?days=N — admin. */
  previewRetention: (days: number) => req<RetentionPreview>(`/v1/audit/retention/preview${qs({ days })}`)
};

const CSV_COLS: (keyof AuditRow)[] = ['id', 'createdAt', 'actor', 'action', 'resource', 'result', 'errorType', 'sourceIp', 'prevHash', 'hash', 'correlationId'];

/** CSV for the legacy export fallback. Exported for tests. */
export function toCsv(rows: AuditRow[]): string {
  const cell = (v: unknown) => {
    const s = v == null ? '' : String(v);
    // Quote everything; neutralise spreadsheet formula injection.
    const safe = /^[=+\-@\t\r]/.test(s) ? `'${s}` : s;
    return `"${safe.replace(/"/g, '""')}"`;
  };
  return [CSV_COLS.join(','), ...rows.map((r) => CSV_COLS.map((c) => cell(r[c])).join(','))].join('\r\n');
}
