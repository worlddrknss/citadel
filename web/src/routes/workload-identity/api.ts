// Client for Citadel as a workload identity provider: an OIDC issuer that
// mints ID tokens for machines, signed by Citadel KMS keys. All endpoints are
// new; the contracts are documented in the console redesign report.

import { req, api, type AuditEvent } from '$lib/api';

export type SigningAlg = 'ES256' | 'ES384' | 'RS256' | 'PS256';

export interface SigningKey {
  kid: string;
  kmsKeyId: string;
  kmsAlias?: string;
  algorithm: SigningAlg;
  activatedAt: string;
}

export interface RetiredKey {
  kid: string;
  kmsKeyId: string;
  algorithm: SigningAlg;
  retiredAt: string;
  /** When it drops out of the JWKS (retiredAt + max token TTL + grace). */
  unpublishAt: string;
}

export interface IssuerInfo {
  issuer: string;
  discoveryUrl: string;
  jwksUrl: string;
  tokenEndpoint: string;
  signingKey: SigningKey | null;
  previousKeys: RetiredKey[];
  rotationDays: number;
  nextRotationAt?: string;
}

export type ClientAuth =
  | { method: 'access-key'; allowedUsers: string[] }
  | { method: 'k8s-token-review'; apiServer: string; caPem?: string; serviceAccounts: string[]; reviewAudience?: string };

export interface WorkloadClient {
  clientId: string;
  name: string;
  audiences: string[];
  tokenTtlSeconds: number;
  subjectFormat: string;
  auth: ClientAuth;
  createdAt: string;
  updatedAt: string;
  lastIssuedAt?: string;
}

export type ClientInput = Pick<WorkloadClient, 'name' | 'audiences' | 'tokenTtlSeconds' | 'subjectFormat' | 'auth'>;

const qs = (p: Record<string, string>) => new URLSearchParams(p).toString();

export const wiApi = {
  issuer: () => req<IssuerInfo>('/v1/workload-identity/issuer'),
  saveIssuerSettings: (body: { algorithm: SigningAlg; rotationDays: number }) =>
    req<IssuerInfo>('/v1/workload-identity/issuer/settings', { method: 'POST', body: JSON.stringify(body) }),
  rotate: () => req<IssuerInfo>('/v1/workload-identity/issuer/rotate', { method: 'POST' }),

  clients: () => req<{ clients: WorkloadClient[] }>('/v1/workload-identity/clients'),
  createClient: (body: ClientInput) =>
    req<{ clientId: string }>('/v1/workload-identity/clients', { method: 'POST', body: JSON.stringify(body) }),
  updateClient: (clientId: string, body: ClientInput) =>
    req<{ clientId: string; updated: boolean }>('/v1/workload-identity/clients/update', {
      method: 'POST',
      body: JSON.stringify({ clientId, ...body })
    }),
  deleteClient: (clientId: string) =>
    req<{ deleted: boolean }>(`/v1/workload-identity/clients?${qs({ clientId })}`, { method: 'DELETE' }),

  /** Token issuance events from the audit log. */
  tokenEvents: async (): Promise<AuditEvent[]> => {
    const { events } = await api.audit();
    return (events ?? []).filter((e) => TOKEN_ACTIONS.has(e.action));
  }
};

export const TOKEN_ACTIONS = new Set(['citadel.IssueWorkloadToken', 'workload-identity.IssueToken']);

export const ALGS: { value: SigningAlg; label: string; kms: string }[] = [
  { value: 'ES256', label: 'ES256 · ECDSA P-256 / SHA-256', kms: 'ECC_NIST_P256' },
  { value: 'ES384', label: 'ES384 · ECDSA P-384 / SHA-384', kms: 'ECC_NIST_P384' },
  { value: 'RS256', label: 'RS256 · RSA PKCS#1 v1.5 / SHA-256', kms: 'RSA_3072' },
  { value: 'PS256', label: 'PS256 · RSA-PSS / SHA-256', kms: 'RSA_3072' }
];

export const SUBJECT_PRESETS: { value: string; label: string; for: ClientAuth['method'] | 'any' }[] = [
  { value: 'system:serviceaccount:{namespace}:{serviceAccount}', label: 'Kubernetes service account', for: 'k8s-token-review' },
  { value: 'user:{username}', label: 'Access key owner', for: 'access-key' },
  { value: 'client:{clientId}', label: 'Client ID', for: 'any' },
  { value: 'account:{accountId}:client:{name}', label: 'Account and client name', for: 'any' }
];

export const PLACEHOLDERS: Record<ClientAuth['method'], string[]> = {
  'access-key': ['{clientId}', '{name}', '{accountId}', '{username}', '{accessKeyId}'],
  'k8s-token-review': ['{clientId}', '{name}', '{accountId}', '{namespace}', '{serviceAccount}', '{podName}']
};

export function ttlLabel(s: number): string {
  if (s % 3600 === 0) return `${s / 3600} h`;
  return `${Math.round(s / 60)} min`;
}

export function fmtDateTime(s?: string): string {
  if (!s) return '—';
  const d = new Date(s);
  return isNaN(d.getTime()) ? s : d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}

export function fmtDate(s?: string): string {
  if (!s) return '—';
  const d = new Date(s);
  return isNaN(d.getTime()) ? s : d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}

/** Copy-paste examples for one client. */
export function usage(c: WorkloadClient, info: IssuerInfo | null, origin: string): { id: string; label: string; code: string }[] {
  const tokenUrl = info?.tokenEndpoint || `${origin}/v1/workload-identity/token`;
  const issuer = info?.issuer || `${origin}/oidc`;
  const aud = c.audiences[0] ?? 'sts.amazonaws.com';
  const fetch =
    c.auth.method === 'access-key'
      ? `# Sign the request with a Citadel access key (SigV4).
TOKEN=$(curl -sf "${tokenUrl}" \\
  --aws-sigv4 "aws:amz:us-east-1:citadel" \\
  --user "$AWS_ACCESS_KEY_ID:$AWS_SECRET_ACCESS_KEY" \\
  -H 'Content-Type: application/json' \\
  -d '{"clientId":"${c.clientId}","audience":"${aud}"}' | jq -r .token)`
      : `# Inside the pod: trade the projected service-account token.
SA_TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
TOKEN=$(curl -sf "${tokenUrl}" \\
  -H 'Content-Type: application/json' \\
  -d "{\\"clientId\\":\\"${c.clientId}\\",\\"audience\\":\\"${aud}\\",\\"kubernetesToken\\":\\"$SA_TOKEN\\"}" | jq -r .token)`;
  return [
    { id: 'curl', label: 'curl', code: fetch },
    {
      id: 'aws',
      label: 'AWS CLI',
      code: `${fetch}
echo "$TOKEN" > /tmp/citadel-id-token

# Register ${issuer} as an IAM OIDC provider (audience ${aud})
# in the target AWS account, then:
aws sts assume-role-with-web-identity \\
  --role-arn arn:aws:iam::123456789012:role/<role-trusting-citadel> \\
  --role-session-name ${c.name.toLowerCase().replace(/[^a-z0-9_=,.@-]/g, '-').slice(0, 40) || 'workload'} \\
  --web-identity-token "$TOKEN"`
    },
    {
      id: 'env',
      label: 'SDK environment',
      code: `# Refresh /tmp/citadel-id-token before it expires (TTL ${ttlLabel(c.tokenTtlSeconds)}).
AWS_ROLE_ARN=arn:aws:iam::123456789012:role/<role-trusting-citadel>
AWS_WEB_IDENTITY_TOKEN_FILE=/tmp/citadel-id-token
AWS_ROLE_SESSION_NAME=${c.name.toLowerCase().replace(/[^a-z0-9_=,.@-]/g, '-').slice(0, 40) || 'workload'}`
    }
  ];
}
