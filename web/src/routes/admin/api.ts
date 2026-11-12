// Page-local client for administration features the shared $lib/api client
// lacks: per-account membership roles, organization settings and console SSO.
// Contracts are documented in the console redesign report.

import { req, type AdminUser } from '$lib/api';

export type RoleName = 'viewer' | 'editor' | 'admin';

/** GET /v1/admin/users rows; `memberships` is the extended contract. */
export interface UserRow extends AdminUser {
  memberships?: { accountId: string; role: RoleName }[];
}

export interface OrgSettings {
  approvalEnvironments: string[];
  approvalMinApprovers: number;
  sessionIdleMinutes: number;
  sessionMaxHours: number;
  updatedAt?: string;
  updatedBy?: string;
}

export interface RoleMapping {
  group: string;
  /** Account the rule grants membership in; "*" = every account. */
  accountId: string;
  role: RoleName;
}

export interface SsoProvider {
  id: string;
  name: string;
  issuer: string;
  clientId: string;
  /** The secret is write-only; the server only says whether one is stored. */
  clientSecretSet: boolean;
  scopes: string[];
  groupClaim: string;
  roleMappings: RoleMapping[];
  defaultRole: RoleName | 'none';
  enabled: boolean;
  redirectUri: string;
  createdAt: string;
  updatedAt: string;
}

export type SsoInput = Omit<SsoProvider, 'id' | 'clientSecretSet' | 'redirectUri' | 'createdAt' | 'updatedAt'> & {
  /** Omit to keep the stored secret on update. */
  clientSecret?: string;
};

export const adminApi = {
  settings: () => req<OrgSettings>('/v1/admin/settings'),
  saveSettings: (s: Omit<OrgSettings, 'updatedAt' | 'updatedBy'>) =>
    req<OrgSettings>('/v1/admin/settings', { method: 'POST', body: JSON.stringify(s) }),

  ssoProviders: () => req<{ providers: SsoProvider[] }>('/v1/admin/sso/providers'),
  createSso: (p: SsoInput) => req<{ id: string; redirectUri: string }>('/v1/admin/sso/providers', { method: 'POST', body: JSON.stringify(p) }),
  updateSso: (id: string, p: SsoInput) =>
    req<{ id: string; updated: boolean }>('/v1/admin/sso/providers/update', { method: 'POST', body: JSON.stringify({ id, ...p }) }),
  deleteSso: (id: string) => req<{ deleted: boolean }>(`/v1/admin/sso/providers?${new URLSearchParams({ id })}`, { method: 'DELETE' }),
  testSso: (id: string) =>
    req<{ ok: boolean; message?: string; authorizationEndpoint?: string }>('/v1/admin/sso/providers/test', {
      method: 'POST',
      body: JSON.stringify({ id })
    })
};

export const ROLES: { value: RoleName; label: string; hint: string }[] = [
  { value: 'viewer', label: 'Viewer', hint: 'Read metadata; reveal nothing it is not granted' },
  { value: 'editor', label: 'Editor', hint: 'Create and change secrets, keys and certificates' },
  { value: 'admin', label: 'Admin', hint: 'Everything, including users, accounts and settings' }
];

export function roleTone(r?: string): 'info' | 'success' | 'neutral' {
  return r === 'admin' ? 'info' : r === 'editor' ? 'success' : 'neutral';
}

export function fmtDate(s?: string): string {
  if (!s) return '—';
  const d = new Date(s);
  return isNaN(d.getTime()) ? s : d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}
