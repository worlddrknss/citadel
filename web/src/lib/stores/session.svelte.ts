// The signed-in user, shared by the whole console. Pages read `session.me`
// instead of each fetching /v1/me, and use `can()` to hide actions the role
// can't perform.

import { api, onUnauthorized, type Me } from '$lib/api';

export type Role = 'viewer' | 'editor' | 'admin';
type Status = 'loading' | 'signed-in' | 'signed-out' | 'unreachable';

const rank: Record<Role, number> = { viewer: 1, editor: 2, admin: 3 };

function createSession() {
  let me = $state<Me | null>(null);
  let status = $state<Status>('loading');
  let expired = $state(false);

  async function refresh() {
    try {
      me = await api.me();
      status = 'signed-in';
      expired = false;
    } catch (e) {
      me = null;
      // Only a 401 means "sign in"; anything else is the server being down,
      // which deserves a different screen than a login form.
      status = (e as { status?: number })?.status === 401 ? 'signed-out' : 'unreachable';
    }
  }

  onUnauthorized(() => {
    if (status === 'signed-in') expired = true;
    me = null;
    status = 'signed-out';
  });

  return {
    get me() {
      return me;
    },
    get status() {
      return status;
    },
    /** True when the session ended under the user (vs. a fresh visit). */
    get expired() {
      return expired;
    },
    refresh,
    /** Whether the current user's role is at least `role`. */
    can(role: Role): boolean {
      const r = (me?.role ?? 'viewer') as Role;
      return (rank[r] ?? 1) >= rank[role];
    },
    async signOut() {
      try {
        await api.logout();
      } catch {
        /* the session is being discarded either way */
      }
      me = null;
      expired = false;
      status = 'signed-out';
    }
  };
}

export const session = createSession();
