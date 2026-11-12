// Page-local Parameter Store client: calls $lib/api doesn't have yet (real
// edit, reading an old version, removing labels) and display helpers.

import type { Parameter, ParameterTier, ParameterType } from '$lib/api';
import { req } from '../kms/api';

const qs = (p: Record<string, string>) => new URLSearchParams(p).toString();

/** List items may carry the plaintext of String/StringList values (never SecureString). */
export type Param = Parameter & { value?: string };

export const params = {
  /**
   * Edits an existing parameter in place and creates a new version. Omitting
   * `value` keeps the current value (re-encrypting it if the type or KMS key
   * changes). `expectedVersion` guards against overwriting someone else's
   * edit: the server answers 409 `version_conflict` when it no longer matches.
   */
  update: (body: {
    name: string;
    expectedVersion: number;
    type?: ParameterType;
    value?: string;
    description?: string;
    kmsKeyId?: string;
    tier?: ParameterTier;
  }) => req<{ parameter: Parameter }>('/v1/parameters/update', { method: 'POST', body: JSON.stringify(body) }),

  /** Value of a specific version (decrypted for SecureString). */
  revealVersion: (name: string, version: number) =>
    req<{ parameter: Parameter; value: string }>(`/v1/parameters/value?${qs({ name, version: String(version) })}`),

  /** Account setting: may viewers decrypt SecureString values? (editors always can) */
  revealSettings: () => req<{ viewersCanReveal: boolean }>('/v1/secrets/settings'),

  unlabel: (name: string, version: number, labels: string[]) =>
    req<{ name: string; removed: string[] }>(
      `/v1/parameters/label?${qs({ name, version: String(version), labels: labels.join(',') })}`,
      { method: 'DELETE' }
    )
};

export const TYPES: ParameterType[] = ['String', 'StringList', 'SecureString'];

export const TYPE_TONE: Record<ParameterType, 'neutral' | 'info' | 'warning'> = {
  String: 'neutral',
  StringList: 'info',
  SecureString: 'warning'
};

/** "/app/prod/db/url" → ["app", "prod", "db", "url"] */
export const segments = (path: string) => path.split('/').filter(Boolean);

/** Normalized folder prefix with leading and trailing slash ("/" at root). */
export const prefixOf = (path: string) => {
  const s = segments(path);
  return s.length ? `/${s.join('/')}/` : '/';
};

export const leaf = (name: string) => name.slice(name.lastIndexOf('/') + 1);
export const parentPath = (name: string) => {
  const i = name.lastIndexOf('/');
  return i > 0 ? name.slice(0, i) : '/';
};

export function validateName(full: string): string {
  if (!full || full === '/') return 'Enter a name.';
  if (full.length > 1011) return 'Names can be at most 1011 characters.';
  if (!/^[A-Za-z0-9_.\-/]+$/.test(full)) return 'Use letters, numbers, and _ . - / only.';
  if (full.includes('//')) return "Names can't contain empty path segments (//).";
  if (full.endsWith('/')) return "Names can't end with /.";
  const lower = full.replace(/^\//, '').toLowerCase();
  if (lower.startsWith('aws') || lower.startsWith('ssm')) return 'Names can\'t start with "aws" or "ssm".';
  if (segments(full).length > 15) return 'A hierarchy can be at most 15 levels deep.';
  return '';
}

export function valueLimit(tier: ParameterTier): number {
  return tier === 'Advanced' ? 8192 : 4096;
}

export function byteLength(s: string): number {
  return new TextEncoder().encode(s).length;
}

export function fmtDateTime(ts?: string): string {
  if (!ts) return '—';
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return ts;
  return d.toLocaleString(undefined, { month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit' });
}

/** "2 h ago" for recent times, a date otherwise. */
export function fmtRelative(ts?: string): string {
  if (!ts) return '—';
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return ts;
  const s = (Date.now() - d.getTime()) / 1000;
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  if (s < 7 * 86400) return `${Math.floor(s / 86400)} d ago`;
  return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: d.getFullYear() === new Date().getFullYear() ? undefined : 'numeric' });
}
