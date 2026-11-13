// Page-local client for self-service features the shared #lib/api client
// lacks (profile edits and sign-in sessions). Contracts are documented in
// the console redesign report.

import { req } from '#lib/api.ts';

export interface SignInSession {
  id: string;
  current: boolean;
  createdAt: string;
  lastSeenAt: string;
  expiresAt: string;
  ip?: string;
  userAgent?: string;
  accountId?: string;
  method?: 'password' | 'sso';
}

export const accountApi = {
  updateProfile: (displayName: string) =>
    req<{ username: string; displayName: string }>('/v1/account/profile', {
      method: 'POST',
      body: JSON.stringify({ displayName })
    }),
  sessions: () => req<{ sessions: SignInSession[] }>('/v1/account/sessions'),
  revokeSession: (id: string) =>
    req<{ revoked: boolean }>(`/v1/account/sessions?${new URLSearchParams({ id })}`, { method: 'DELETE' }),
  revokeOtherSessions: () => req<{ revoked: number }>('/v1/account/sessions/revoke-others', { method: 'POST' })
};

/** "Firefox on macOS" from a user-agent string; good enough for a list. */
export function describeAgent(ua?: string): string {
  if (!ua) return 'Unknown device';
  const browser = /Edg\//.test(ua)
    ? 'Edge'
    : /Firefox\//.test(ua)
      ? 'Firefox'
      : /Chrome\//.test(ua)
        ? 'Chrome'
        : /Safari\//.test(ua)
          ? 'Safari'
          : /curl|aws-cli|Go-http|python/i.test(ua)
            ? ua.split(/[ /]/)[0]
            : 'Browser';
  const os = /Windows/.test(ua)
    ? 'Windows'
    : /iPhone|iPad/.test(ua)
      ? 'iOS'
      : /Mac OS X|Macintosh/.test(ua)
        ? 'macOS'
        : /Android/.test(ua)
          ? 'Android'
          : /Linux/.test(ua)
            ? 'Linux'
            : '';
  return os ? `${browser} on ${os}` : browser;
}

export function relTime(s?: string): string {
  if (!s) return '—';
  const t = Date.parse(s);
  if (isNaN(t)) return s;
  const diff = (Date.now() - t) / 1000;
  const fmt = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' });
  const abs = Math.abs(diff);
  if (abs < 60) return 'just now';
  if (abs < 3600) return fmt.format(-Math.round(diff / 60), 'minute');
  if (abs < 86400) return fmt.format(-Math.round(diff / 3600), 'hour');
  if (abs < 86400 * 30) return fmt.format(-Math.round(diff / 86400), 'day');
  return new Date(t).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}
