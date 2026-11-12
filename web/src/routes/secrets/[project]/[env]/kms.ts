import type { KMSKey } from '$lib/api';

/** "payments-prod · 1a2b3c4d…" — the first alias reads better than a key ID. */
export function kmsLabel(k: KMSKey): string {
  const alias = (k.aliases ?? []).find((a) => a && a.trim());
  if (alias) return `${alias.replace(/^alias\//, '')} · ${k.keyId.slice(0, 8)}…`;
  return k.keyId;
}

/** Finds the key a detail's kmsKeyId refers to (it may be an ID, an ARN or an alias). */
export function findKms(keys: KMSKey[], ref: string): KMSKey | undefined {
  if (!ref) return undefined;
  return keys.find(
    (k) => k.keyId === ref || k.arn === ref || (k.aliases ?? []).includes(ref) || ref.endsWith(`:key/${k.keyId}`)
  );
}

/** Display name for a key reference: its alias when known, else the raw reference. */
export function kmsDisplay(keys: KMSKey[], ref: string): string {
  if (!ref) return 'Account default key';
  const k = findKms(keys, ref);
  const alias = k?.aliases?.find((a) => a && a.trim());
  return alias ?? k?.keyId ?? ref;
}
