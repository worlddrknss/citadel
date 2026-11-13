// Audit log calls: server-side filtered paging, chain verification, export
// and SIEM streaming. Falls back to the legacy GET /v1/audit (latest 500,
// filtered here) when the server doesn't have the paged endpoint yet.

import { api, req } from '#lib/api.ts';
import { isNotImplemented, qs, rawRequest } from '../http';

export type ResultFilter = '' | 'success' | 'denied' | 'error';

export interface AuditFilters {
  /** ISO-8601 instants, inclusive. */
  from?: string;
  to?: string;
  actor?: string;
  action?: string;
  result?: ResultFilter;
  resource?: string;
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
}

export interface StreamConfig {
  enabled: boolean;
  url: string;
  format: 'json' | 'cef';
  hasToken: boolean;
}

export function resultKind(r: Pick<AuditRow, 'result' | 'errorType'>): 'success' | 'denied' | 'error' {
  const v = (r.result || '').toLowerCase();
  if (v === 'ok' || v === 'success') return 'success';
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
  testStream: () => req<{ delivered: boolean; status?: number }>('/v1/audit/stream/test', { method: 'POST' })
};

const CSV_COLS: (keyof AuditRow)[] = ['id', 'createdAt', 'actor', 'action', 'resource', 'result', 'errorType', 'sourceIp', 'prevHash', 'hash'];

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
