// Role permissions policies: what a role's temporary credentials may do.
// The server validates and enforces them (internal/server/role_policy.go);
// these helpers build the common "read secrets under these paths" policy
// and recognise it again so the editor can show it as a form.

import type { PermissionsPolicy, PolicyStatement } from '#lib/api.ts';

export type { PermissionsPolicy, PolicyStatement };

// What ESO, the AWS SDKs and the CLI need to find and read secrets.
export const READ_SECRET_ACTIONS = [
  'secretsmanager:GetSecretValue',
  'secretsmanager:DescribeSecret',
  'secretsmanager:ListSecrets',
  'secretsmanager:BatchGetSecretValue'
];

const SECRET_ARN_PREFIX = 'arn:aws:secretsmanager:*:*:secret:';

/** Normalises a path prefix: trimmed, no leading slash, ends with "/". */
export function normalizePrefix(p: string): string {
  let s = p.trim().replace(/^\/+/, '');
  if (s.endsWith('*')) s = s.slice(0, -1);
  if (s && !s.endsWith('/')) s += '/';
  return s;
}

/** Splits the textarea into normalised, de-duplicated path prefixes. */
export function parsePrefixes(text: string): string[] {
  const out: string[] = [];
  for (const line of text.split(/[\n,]/)) {
    const p = normalizePrefix(line);
    if (p && !out.includes(p)) out.push(p);
  }
  return out;
}

export function prefixError(prefixes: string[]): string {
  if (prefixes.length === 0) return 'Add at least one secret path, for example shop/prod/.';
  const bad = prefixes.find((p) => /[*?\s]/.test(p.slice(0, -1)));
  if (bad) return `"${bad}" can't contain spaces or wildcards; use a plain path such as shop/prod/.`;
  return '';
}

/** The policy that lets a role find and read secrets under the prefixes. */
export function readPathsPolicy(prefixes: string[]): PermissionsPolicy {
  return {
    Version: '2012-10-17',
    Statement: [
      {
        Sid: 'ReadSecrets',
        Effect: 'Allow',
        Action: [...READ_SECRET_ACTIONS],
        Resource: prefixes.map((p) => `${SECRET_ARN_PREFIX}${p}*`)
      }
    ]
  };
}

const asList = <T,>(v: T | T[]): T[] => (Array.isArray(v) ? v : [v]);

/**
 * Returns the path prefixes when policy is exactly a readPathsPolicy (in any
 * order), so the editor can show it as a form; null for anything else.
 */
export function prefixesFromPolicy(policy: PermissionsPolicy | null | undefined): string[] | null {
  if (!policy) return null;
  const stmts = asList<PolicyStatement>(policy.Statement);
  if (stmts.length !== 1) return null;
  const st = stmts[0];
  if (st.Effect !== 'Allow') return null;
  const actions = asList(st.Action);
  if (actions.length !== READ_SECRET_ACTIONS.length || !READ_SECRET_ACTIONS.every((a) => actions.includes(a))) return null;
  const out: string[] = [];
  for (const r of asList(st.Resource)) {
    if (!r.startsWith(SECRET_ARN_PREFIX) || !r.endsWith('/*')) return null;
    const p = r.slice(SECRET_ARN_PREFIX.length, -1);
    if (!p || /[*?]/.test(p)) return null;
    out.push(p);
  }
  return out.length ? out : null;
}

export function policyToJson(policy: PermissionsPolicy): string {
  return JSON.stringify(policy, null, 2);
}

/** Parses the JSON editor. The server does the full validation on save. */
export function parsePolicyJson(text: string): { policy?: PermissionsPolicy; error?: string } {
  let v: unknown;
  try {
    v = JSON.parse(text);
  } catch (e) {
    return { error: `Not valid JSON: ${(e as Error).message}` };
  }
  if (!v || typeof v !== 'object' || Array.isArray(v)) return { error: 'The policy must be a JSON object.' };
  const st = (v as { Statement?: unknown }).Statement;
  if (!st || (Array.isArray(st) && st.length === 0)) return { error: 'The policy needs at least one Statement.' };
  return { policy: v as PermissionsPolicy };
}

/** A short description of a role's permissions for lists and headers. */
export function permissionsSummary(policy: PermissionsPolicy | null | undefined): { label: string; restricted: boolean } {
  if (!policy) return { label: 'Whole account', restricted: false };
  const prefixes = prefixesFromPolicy(policy);
  if (prefixes) return { label: prefixes.length === 1 ? `Read ${prefixes[0]}` : `Read ${prefixes.length} paths`, restricted: true };
  return { label: 'Custom policy', restricted: true };
}
