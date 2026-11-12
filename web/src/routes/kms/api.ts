// Page-local KMS client: the calls the console needs that $lib/api doesn't
// have yet (grants, rotation, tags, and the "Try it" crypto operations), plus
// display helpers shared by the KMS components. The contracts are documented
// next to each call; the server implements them under /v1/kms.

import type { KMSKey, KMSKeyDetail } from '$lib/api';

// Transport (timeouts, CSRF header, 401 handling) is the shared one.
export { req } from '$lib/api';
import { req } from '$lib/api';

const qs = (p: Record<string, string>) => new URLSearchParams(p).toString();
const post = <T>(path: string, body: unknown) => req<T>(path, { method: 'POST', body: JSON.stringify(body) });

// ---- Types the server adds to existing responses (optional until shipped) --

/** Fields the list/detail endpoints should add; read defensively. */
export interface KeyExtras {
  /** True for the immutable per-account default key (alias/default). */
  managed?: boolean;
  rotation?: { enabled: boolean; rotationPeriodDays?: number };
  /** Detail response only: how many secrets and parameters use this key. */
  usedBy?: { secrets: number; parameters: number };
  origin?: string;
}
export type Key = KMSKey & KeyExtras;
export type KeyDetail = KMSKeyDetail & KeyExtras;

export interface Tag {
  key: string;
  value: string;
}

export interface RotationEvent {
  rotatedAt: string;
  kind: 'automatic' | 'on-demand';
  keyMaterialId?: string;
}

export interface RotationStatus {
  keyId: string;
  supported: boolean;
  enabled: boolean;
  rotationPeriodDays: number;
  lastRotatedAt?: string;
  nextRotationAt?: string;
  history: RotationEvent[];
}

export const kms = {
  createGrant: (body: {
    keyId: string;
    granteePrincipal: string;
    operations: string[];
    retiringPrincipal?: string;
    name?: string;
  }) => post<{ grantId: string; grantToken: string }>('/v1/kms/grants', body),
  revokeGrant: (keyId: string, grantId: string) =>
    req<{ revoked: boolean }>(`/v1/kms/grants?${qs({ keyId, grantId })}`, { method: 'DELETE' }),

  rotation: (keyId: string) => req<RotationStatus>(`/v1/kms/keys/rotation?${qs({ keyId })}`),
  setRotation: (keyId: string, enabled: boolean, rotationPeriodDays?: number) =>
    post<RotationStatus>('/v1/kms/keys/rotation', { keyId, enabled, rotationPeriodDays }),
  /** Rotates a symmetric key's material now; returns the new rotation status. */
  rotateNow: (keyId: string) => post<RotationStatus>('/v1/kms/keys/rotate', { keyId }),

  tags: (keyId: string) => req<{ keyId: string; tags: Tag[] }>(`/v1/kms/keys/tags?${qs({ keyId })}`),
  tag: (keyId: string, tags: Tag[]) => post<{ tagged: boolean }>('/v1/kms/keys/tags', { keyId, tags }),
  untag: (keyId: string, tagKey: string) =>
    req<{ untagged: boolean }>(`/v1/kms/keys/tags?${qs({ keyId, tagKey })}`, { method: 'DELETE' }),

  encrypt: (body: {
    keyId: string;
    plaintext: string;
    encryptionContext?: Record<string, string>;
    encryptionAlgorithm: string;
  }) => post<{ keyId: string; ciphertextBlob: string; encryptionAlgorithm: string }>('/v1/kms/encrypt', body),
  decrypt: (body: {
    keyId: string;
    ciphertextBlob: string;
    encryptionContext?: Record<string, string>;
    encryptionAlgorithm: string;
  }) => post<{ keyId: string; plaintext: string; encryptionAlgorithm: string }>('/v1/kms/decrypt', body),
  sign: (body: { keyId: string; message: string; messageType: 'RAW' | 'DIGEST'; signingAlgorithm: string }) =>
    post<{ keyId: string; signature: string; signingAlgorithm: string }>('/v1/kms/sign', body),
  verify: (body: {
    keyId: string;
    message: string;
    messageType: 'RAW' | 'DIGEST';
    signature: string;
    signingAlgorithm: string;
  }) => post<{ keyId: string; signatureValid: boolean; signingAlgorithm: string }>('/v1/kms/verify', body)
};

// ---- FIPS 140-3 approved algorithms --------------------------------------

export const SYMMETRIC = 'SYMMETRIC_DEFAULT';
export const USAGE_LABEL: Record<string, string> = {
  ENCRYPT_DECRYPT: 'Encrypt / decrypt',
  SIGN_VERIFY: 'Sign / verify'
};

/** Key specs offered when creating a key, per usage. */
export const SPECS: Record<string, { value: string; label: string; hint: string }[]> = {
  ENCRYPT_DECRYPT: [
    { value: 'SYMMETRIC_DEFAULT', label: 'Symmetric (AES-256-GCM)', hint: 'Recommended. Fast, the key never leaves Citadel.' },
    { value: 'RSA_2048', label: 'RSA 2048', hint: 'Asymmetric. RSAES-OAEP with SHA-256.' },
    { value: 'RSA_3072', label: 'RSA 3072', hint: 'Asymmetric. RSAES-OAEP with SHA-256.' },
    { value: 'RSA_4096', label: 'RSA 4096', hint: 'Asymmetric. RSAES-OAEP with SHA-256.' }
  ],
  SIGN_VERIFY: [
    { value: 'ECC_NIST_P256', label: 'ECC NIST P-256', hint: 'ECDSA with SHA-256.' },
    { value: 'ECC_NIST_P384', label: 'ECC NIST P-384', hint: 'ECDSA with SHA-384.' },
    { value: 'RSA_2048', label: 'RSA 2048', hint: 'RSASSA-PSS or PKCS #1 v1.5 with SHA-2.' },
    { value: 'RSA_3072', label: 'RSA 3072', hint: 'RSASSA-PSS or PKCS #1 v1.5 with SHA-2.' },
    { value: 'RSA_4096', label: 'RSA 4096', hint: 'RSASSA-PSS or PKCS #1 v1.5 with SHA-2.' }
  ]
};

const APPROVED_SIGNING = [
  'RSASSA_PSS_SHA_256',
  'RSASSA_PSS_SHA_384',
  'RSASSA_PSS_SHA_512',
  'RSASSA_PKCS1_V1_5_SHA_256',
  'RSASSA_PKCS1_V1_5_SHA_384',
  'RSASSA_PKCS1_V1_5_SHA_512',
  'ECDSA_SHA_256',
  'ECDSA_SHA_384'
];

export function encryptionAlgorithms(d: KMSKeyDetail): string[] {
  if (d.keySpec === SYMMETRIC) return [SYMMETRIC];
  return ['RSAES_OAEP_SHA_256'];
}

export function signingAlgorithms(d: KMSKeyDetail): string[] {
  const fromServer = (d.signingAlgorithms ?? []).filter((a) => APPROVED_SIGNING.includes(a));
  if (fromServer.length) return fromServer;
  if (d.keySpec === 'ECC_NIST_P256') return ['ECDSA_SHA_256'];
  if (d.keySpec === 'ECC_NIST_P384') return ['ECDSA_SHA_384'];
  return APPROVED_SIGNING.filter((a) => a.startsWith('RSASSA'));
}

/**
 * Grant operations the server accepts for a key's type (kms_grants.go):
 * data keys only come from symmetric keys, and RSA encryption keys can hand
 * out their public key.
 */
export function grantOperations(usage: string, spec: string): string[] {
  const common = ['DescribeKey', 'CreateGrant', 'RetireGrant'];
  if (usage === 'SIGN_VERIFY') return ['Sign', 'Verify', 'GetPublicKey', ...common];
  if (spec !== SYMMETRIC) return ['Encrypt', 'Decrypt', 'ReEncryptFrom', 'ReEncryptTo', 'GetPublicKey', ...common];
  return ['Encrypt', 'Decrypt', 'GenerateDataKey', 'GenerateDataKeyWithoutPlaintext', 'ReEncryptFrom', 'ReEncryptTo', ...common];
}

/** Human label for a key's origin as the server reports it. */
export function originLabel(origin?: string): string {
  switch (origin) {
    case undefined:
    case '':
    case 'AWS_KMS':
      return 'Citadel, FIPS 140 module';
    case 'EXTERNAL':
      return 'Imported key material';
    default:
      return origin;
  }
}

// ---- Display helpers ------------------------------------------------------

export type Status = 'Enabled' | 'Disabled' | 'Pending deletion';

export function statusOf(k: { enabled: boolean; deletionDate?: string }): Status {
  if (k.deletionDate) return 'Pending deletion';
  return k.enabled ? 'Enabled' : 'Disabled';
}

export const DEFAULT_ALIAS = 'alias/default';

export function isManaged(k: Key | KeyDetail): boolean {
  return k.managed ?? k.aliases.includes(DEFAULT_ALIAS);
}

/** The alias shown as a key's name: the default alias first, then A–Z. */
export function primaryAlias(k: { aliases: string[] }): string | undefined {
  if (k.aliases.includes(DEFAULT_ALIAS)) return DEFAULT_ALIAS;
  return [...k.aliases].sort()[0];
}

export const shortId = (id: string) => (id.length > 14 ? `${id.slice(0, 8)}…${id.slice(-4)}` : id);

export function fmtDate(ts?: string, withYear = true): string {
  if (!ts) return '—';
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return ts;
  return d.toLocaleDateString(undefined, withYear ? { month: 'short', day: 'numeric', year: 'numeric' } : { month: 'short', day: 'numeric' });
}

export function fmtDateTime(ts?: string): string {
  if (!ts) return '—';
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return ts;
  return d.toLocaleString(undefined, { month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit' });
}

export function rotationLabel(k: Key): string {
  if (k.deletionDate) return '—';
  if (k.keySpec !== SYMMETRIC) return 'Not supported';
  if (!k.rotation) return '—';
  if (!k.rotation.enabled) return 'Off';
  return periodLabel(k.rotation.rotationPeriodDays ?? 365);
}

export function periodLabel(days: number): string {
  if (days === 365) return 'Yearly';
  if (days % 365 === 0) return `Every ${days / 365} years`;
  if (days === 90) return 'Every 90 days';
  return `Every ${days} days`;
}

// UTF-8 safe base64 for the Try it panel.
export function toB64(text: string): string {
  const bytes = new TextEncoder().encode(text);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

/** Decodes base64 to text, or returns null when it isn't valid UTF-8. */
export function fromB64(b64: string): string | null {
  try {
    const bin = atob(b64);
    const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
}

/** Parses "a=b, c=d" or a JSON object into an encryption context. */
export function parseContext(text: string): Record<string, string> | undefined {
  const t = text.trim();
  if (!t) return undefined;
  if (t.startsWith('{')) {
    const obj = JSON.parse(t);
    if (typeof obj !== 'object' || obj === null || Array.isArray(obj)) throw new Error('Encryption context must be a JSON object.');
    return Object.fromEntries(Object.entries(obj).map(([k, v]) => [k, String(v)]));
  }
  const out: Record<string, string> = {};
  for (const part of t.split(',')) {
    const p = part.trim();
    if (!p) continue;
    const i = p.indexOf('=');
    if (i <= 0) throw new Error(`"${p}" isn't key=value.`);
    out[p.slice(0, i).trim()] = p.slice(i + 1).trim();
  }
  return out;
}
