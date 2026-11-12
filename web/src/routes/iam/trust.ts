// Trust policy validation and rendering for the IAM page. The server stores
// the native shape ({type, providerUrl, audiences, subjects} or
// {type, principals}); the editor shows and validates exactly that JSON.

import type { OIDCProvider, Role, TrustPolicy } from '$lib/api';

export interface TrustErrors {
  json?: string;
  type?: string;
  providerUrl?: string;
  audiences?: string;
  subjects?: string;
  principals?: string;
}

const norm = (u: string) => u.trim().replace(/\/+$/, '');

export function splitList(s: string): string[] {
  return s
    .split(/[\n,]+/)
    .map((v) => v.trim())
    .filter(Boolean);
}

/** Field-level problems; empty object means valid. */
export function validateTrust(t: TrustPolicy, providers: OIDCProvider[]): TrustErrors {
  const e: TrustErrors = {};
  if (t.type === 'oidc') {
    const url = norm(t.providerUrl ?? '');
    const p = providers.find((x) => norm(x.url) === url);
    if (!url) e.providerUrl = 'Choose the identity provider whose tokens this role accepts.';
    else if (!/^https:\/\//.test(url)) e.providerUrl = 'The issuer must be an https:// URL.';
    else if (!p) e.providerUrl = 'No identity provider is registered for this issuer. Add it on the Identity providers tab first.';
    const auds = t.audiences ?? [];
    if (auds.length === 0) e.audiences = 'Add at least one audience (the token’s aud claim).';
    else if (p) {
      const unknown = auds.filter((a) => !p.clientIds.includes(a));
      if (unknown.length) e.audiences = `Not an audience of this provider: ${unknown.join(', ')}. Allowed: ${p.clientIds.join(', ')}.`;
    }
    const subs = t.subjects ?? [];
    if (subs.length === 0) e.subjects = 'Add at least one subject. Use a trailing * to match a prefix.';
    else {
      const bad = subs.find((s) => s.indexOf('*') !== -1 && s.indexOf('*') !== s.length - 1);
      if (bad) e.subjects = `“${bad}”: * is only allowed at the end.`;
      else if (subs.includes('*')) e.subjects = 'A bare * trusts every token from this issuer. Narrow it to a prefix.';
    }
    if (t.principals?.length) e.principals = 'principals only applies to account trust.';
  } else if (t.type === 'account') {
    const pr = t.principals ?? [];
    if (pr.length === 0) e.principals = 'Add at least one 12-digit account ID.';
    else {
      const bad = pr.find((x) => !/^\d{12}$/.test(x));
      if (bad) e.principals = `“${bad}” isn't a 12-digit account ID.`;
    }
  } else {
    e.type = 'type must be "oidc" or "account".';
  }
  return e;
}

export function hasErrors(e: TrustErrors): boolean {
  return Object.values(e).some(Boolean);
}

/** The native JSON document shown in the editor. */
export function trustToJson(t: TrustPolicy): string {
  const doc =
    t.type === 'oidc'
      ? { type: 'oidc', providerUrl: t.providerUrl ?? '', audiences: t.audiences ?? [], subjects: t.subjects ?? [] }
      : { type: 'account', principals: t.principals ?? [] };
  return JSON.stringify(doc, null, 2);
}

export function parseTrustJson(text: string): { trust?: TrustPolicy; error?: string } {
  let v: unknown;
  try {
    v = JSON.parse(text);
  } catch (e) {
    return { error: `Invalid JSON: ${(e as Error).message}` };
  }
  if (!v || typeof v !== 'object' || Array.isArray(v)) return { error: 'The trust policy must be a JSON object.' };
  const o = v as Record<string, unknown>;
  const allowed = new Set(['type', 'providerUrl', 'audiences', 'subjects', 'principals']);
  const extra = Object.keys(o).filter((k) => !allowed.has(k));
  if (extra.length) return { error: `Unknown field${extra.length > 1 ? 's' : ''}: ${extra.join(', ')}.` };
  const list = (k: string): string[] | undefined | null => {
    const x = o[k];
    if (x === undefined) return undefined;
    if (!Array.isArray(x) || x.some((i) => typeof i !== 'string')) return null;
    return (x as string[]).map((s) => s.trim()).filter(Boolean);
  };
  for (const k of ['audiences', 'subjects', 'principals']) {
    if (list(k) === null) return { error: `${k} must be an array of strings.` };
  }
  if (o.providerUrl !== undefined && typeof o.providerUrl !== 'string') return { error: 'providerUrl must be a string.' };
  return {
    trust: {
      type: o.type as TrustPolicy['type'],
      providerUrl: o.providerUrl as string | undefined,
      audiences: list('audiences') ?? undefined,
      subjects: list('subjects') ?? undefined,
      principals: list('principals') ?? undefined
    }
  };
}

export function sessionLabel(secs: number): string {
  if (secs % 3600 === 0) return `${secs / 3600} h`;
  return `${Math.round(secs / 60)} min`;
}

export function fmtDate(s?: string): string {
  if (!s) return '—';
  const d = new Date(s);
  return isNaN(d.getTime()) ? s : d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}

/** Ready-to-run examples for assuming a role. */
export function usage(role: Role, origin: string): { id: string; label: string; code: string }[] {
  const session = role.roleName.toLowerCase().replace(/[^a-z0-9_=,.@-]/g, '-').slice(0, 40) || 'session';
  if (role.trust.type === 'oidc') {
    const aud = role.trust.audiences?.[0] ?? 'sts.citadel';
    return [
      {
        id: 'cli',
        label: 'AWS CLI',
        code: `aws sts assume-role-with-web-identity \\
  --endpoint-url ${origin} \\
  --role-arn ${role.roleArn} \\
  --role-session-name ${session} \\
  --duration-seconds ${role.maxSessionSeconds} \\
  --web-identity-token "$(cat /var/run/secrets/citadel/token)"`
      },
      {
        id: 'env',
        label: 'SDK environment',
        code: `# Any AWS SDK picks these up and refreshes credentials on its own.
AWS_ENDPOINT_URL_STS=${origin}
AWS_ROLE_ARN=${role.roleArn}
AWS_WEB_IDENTITY_TOKEN_FILE=/var/run/secrets/citadel/token
AWS_ROLE_SESSION_NAME=${session}
AWS_REGION=us-east-1`
      },
      {
        id: 'k8s',
        label: 'Kubernetes',
        code: `# Pod spec: project a service-account token with the role's audience.
volumes:
  - name: citadel-token
    projected:
      sources:
        - serviceAccountToken:
            audience: ${aud}
            expirationSeconds: 3600
            path: token
containers:
  - name: app
    env:
      - { name: AWS_ENDPOINT_URL_STS, value: "${origin}" }
      - { name: AWS_ROLE_ARN, value: "${role.roleArn}" }
      - { name: AWS_WEB_IDENTITY_TOKEN_FILE, value: /var/run/secrets/citadel/token }
    volumeMounts:
      - { name: citadel-token, mountPath: /var/run/secrets/citadel, readOnly: true }`
      }
    ];
  }
  return [
    {
      id: 'cli',
      label: 'AWS CLI',
      code: `# Run with access keys from one of the trusted accounts.
aws sts assume-role \\
  --endpoint-url ${origin} \\
  --role-arn ${role.roleArn} \\
  --role-session-name ${session} \\
  --duration-seconds ${role.maxSessionSeconds}`
    },
    {
      id: 'env',
      label: 'AWS config profile',
      code: `# ~/.aws/config
[profile ${session}]
role_arn = ${role.roleArn}
source_profile = default
duration_seconds = ${role.maxSessionSeconds}
endpoint_url = ${origin}`
    }
  ];
}
