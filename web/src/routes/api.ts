// Client calls used by the app shell and the Overview page that $lib/api
// doesn't have yet. Each documents the backend contract it expects; callers
// treat isNotImplemented() errors as "feature not available on this server".

import { req, type Me } from '$lib/api';

export interface ServerInfo {
  /** Server started with GODEBUG=fips140=on/only. */
  fips: boolean;
  version?: string;
  sessionIdleMinutes?: number;
  sessionMaxHours?: number;
}

export interface OrgAccount {
  accountId: string;
  name: string;
  /** The caller's role in that account. */
  role?: string;
}

export interface Organization {
  organization: { name: string };
  accounts: OrgAccount[];
}

export interface SecretsSummary {
  total: number;
  projects: number;
  environments: number;
}

export const shellApi = {
  /** GET /v1/server/info — unauthenticated. */
  serverInfo: () => req<ServerInfo>('/v1/server/info'),
  /** GET /v1/me/organization — viewer. The caller's org name and the accounts they can use. */
  organization: () => req<Organization>('/v1/me/organization'),
  /** POST /v1/session/account — viewer. Re-scopes the current session to another of the caller's accounts. */
  switchAccount: (accountId: string) =>
    req<Me>('/v1/session/account', { method: 'POST', body: JSON.stringify({ accountId }) }),
  /** GET /v1/secrets/summary — viewer. Counts across the caller's account. */
  secretsSummary: () => req<SecretsSummary>('/v1/secrets/summary')
};
