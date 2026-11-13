// Pure helpers shared by the certificate page components.

import type { CertRow } from './api';

export type Tone = 'neutral' | 'success' | 'warning' | 'danger' | 'info';

const DAY = 86_400_000;

/** The CN out of an RFC 4514-ish subject DN ("CN=x,O=y" or "/CN=x/O=y"). */
export function cnOf(dn?: string): string {
  if (!dn) return '';
  const m = dn.match(/(?:^|[,/]\s*)CN=([^,/]+)/i);
  return (m ? m[1] : dn).trim();
}

export function firstDomain(domains?: string): string {
  return (domains ?? '').split(/[\s,]+/).filter(Boolean)[0] ?? '';
}

export function isRevoked(c: { status?: string }): boolean {
  return (c.status ?? '').toUpperCase() === 'REVOKED';
}

export function daysLeft(notAfter?: string, now = Date.now()): number | null {
  if (!notAfter) return null;
  const t = Date.parse(notAfter);
  return isNaN(t) ? null : Math.floor((t - now) / DAY);
}

export function lifetimeDays(notBefore?: string, notAfter?: string): number | null {
  if (!notBefore || !notAfter) return null;
  const a = Date.parse(notBefore);
  const b = Date.parse(notAfter);
  if (isNaN(a) || isNaN(b) || b <= a) return null;
  return Math.max(1, Math.round((b - a) / DAY));
}

export interface CertStatus {
  label: string;
  tone: Tone;
  icon: 'alert-triangle' | 'clock' | 'check-circle' | 'x' | 'alert-circle';
}

/** Display status: revoked, expired, expiring (≤14 d danger, ≤30 d warning) or valid. */
export function certStatus(c: CertRow): CertStatus {
  if (isRevoked(c)) return { label: 'Revoked', tone: 'neutral', icon: 'x' };
  const left = daysLeft(c.notAfter);
  if (left === null) return { label: titleCase(c.status || 'Unknown'), tone: 'neutral', icon: 'alert-circle' };
  if (left < 0) return { label: 'Expired', tone: 'danger', icon: 'alert-circle' };
  if (left <= 14) return { label: 'Expires soon', tone: 'danger', icon: 'alert-triangle' };
  if (left <= 30) return { label: 'Expiring', tone: 'warning', icon: 'clock' };
  return { label: 'Valid', tone: 'success', icon: 'check-circle' };
}

export function isExpiring(c: CertRow): boolean {
  if (isRevoked(c)) return false;
  const left = daysLeft(c.notAfter);
  return left !== null && left <= 30;
}

export function titleCase(s: string): string {
  return s.toLowerCase().replace(/(^|[\s_])(\w)/g, (_, p, ch) => (p ? ' ' : '') + ch.toUpperCase());
}

export function fmtDate(s?: string): string {
  if (!s) return '—';
  const d = new Date(s);
  return isNaN(d.getTime()) ? s : d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}

export function fmtDateTime(s?: string): string {
  if (!s) return '—';
  const d = new Date(s);
  return isNaN(d.getTime()) ? s : d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}

export function yearOf(s?: string): string {
  if (!s) return '';
  const d = new Date(s);
  return isNaN(d.getTime()) ? '' : String(d.getFullYear());
}

/** Human key algorithm names in the style of the mockup (RSA_4096, ECC_NIST_P384). */
export function keyAlgLabel(k?: string): string {
  if (!k) return '';
  const map: Record<string, string> = {
    EC_prime256v1: 'ECC_NIST_P256',
    EC_secp384r1: 'ECC_NIST_P384'
  };
  return map[k] ?? k;
}

/**
 * A CA's basic-constraints path length for display. pathLen is how many CAs
 * may follow it in a chain; the server omits it when there is no limit.
 */
export function pathLenLabel(c: { isCA?: boolean; pathLen?: number }): string {
  if (!c.isCA) return '';
  if (c.pathLen === undefined || c.pathLen === null) return 'pathLen: unlimited';
  return `pathLen: ${c.pathLen}`;
}

/** Longer wording for the details panel. */
export function pathLenDescription(pathLen?: number): string {
  if (pathLen === undefined || pathLen === null) return 'Unlimited — subordinate CAs may be created below it';
  if (pathLen === 0) return '0 — issues end-entity certificates only, no subordinate CAs';
  return `${pathLen} — up to ${pathLen} more CA level${pathLen === 1 ? '' : 's'} below it`;
}

/** Certificates imported through ACM ImportCertificate. */
export const SOURCE_IMPORTED = 'acm-imported';

export function isImported(c: { source?: string }): boolean {
  return c.source === SOURCE_IMPORTED;
}

/** The Source badge of a certificate row. */
export function sourceLabel(source?: string): string {
  switch (source) {
    case 'lets-encrypt':
      return 'ACME';
    case SOURCE_IMPORTED:
      return 'Imported';
    case 'pca-ca':
    case 'pca-cert':
      return 'Private CA';
    default:
      return source ? titleCase(source) : '—';
  }
}

/** Renew and revoke apply only to certificates a Citadel CA issued. */
export function canRenewOrRevoke(c: { source?: string; status?: string }): boolean {
  return c.source === 'pca-cert' && !isRevoked(c);
}

/** Label of a chain element's position. */
export function chainRoleLabel(role: string): string {
  return role === 'leaf' ? 'Leaf' : role === 'root' ? 'Root' : 'Intermediate';
}

/**
 * Whether a chain ends at a self-signed root. When it doesn't, Citadel does
 * not hold the remaining issuers.
 */
export function chainComplete(chain?: { selfSigned: boolean }[]): boolean {
  return !!chain?.length && chain[chain.length - 1].selfSigned;
}

export function rowKey(c: { source: string; id: string }): string {
  return `${c.source}:${c.id}`;
}

export function downloadText(filename: string, text: string, type = 'application/x-pem-file') {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function safeFileName(s: string): string {
  return s.replace(/[^a-zA-Z0-9._-]+/g, '_').replace(/^_+|_+$/g, '') || 'certificate';
}

export const REVOKE_REASONS: { value: string; label: string }[] = [
  { value: 'Unspecified', label: 'Unspecified' },
  { value: 'KeyCompromise', label: 'Key compromise' },
  { value: 'CACompromise', label: 'CA compromise' },
  { value: 'AffiliationChanged', label: 'Affiliation changed' },
  { value: 'Superseded', label: 'Superseded' },
  { value: 'CessationOfOperation', label: 'Cessation of operation' },
  { value: 'PrivilegeWithdrawn', label: 'Privilege withdrawn' },
  { value: 'AACompromise', label: 'Attribute authority compromise' }
];

export const KEY_ALGORITHMS: { value: string; label: string }[] = [
  { value: 'EC_prime256v1', label: 'ECDSA P-256' },
  { value: 'EC_secp384r1', label: 'ECDSA P-384' },
  { value: 'RSA_2048', label: 'RSA 2048' },
  { value: 'RSA_3072', label: 'RSA 3072' },
  { value: 'RSA_4096', label: 'RSA 4096' }
];

export type Filter = 'all' | 'expiring' | 'revoked';
export type SortKey = 'name' | 'left';
