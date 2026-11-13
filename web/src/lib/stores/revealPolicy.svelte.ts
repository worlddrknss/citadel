// Whether the signed-in user may read secret and SecureString values.
// Editors and admins always may; viewers only while the account's
// viewersCanReveal setting (GET /v1/secrets/settings) is on. The server
// enforces it (403 reveal_forbidden); pages use this to hide Reveal/Export
// instead of offering buttons that fail.

import { req } from '#lib/api.ts';
import { session } from './session.svelte';

function createRevealPolicy() {
  let viewersCanReveal = $state<boolean | null>(null);
  let loadedFor = '';

  async function load(force = false) {
    const key = `${session.me?.accountId ?? ''}:${session.me?.username ?? ''}`;
    if (!force && key === loadedFor && viewersCanReveal !== null) return;
    loadedFor = key;
    try {
      viewersCanReveal = !!(await req<{ viewersCanReveal: boolean }>('/v1/secrets/settings')).viewersCanReveal;
    } catch {
      // Older servers have no setting and let viewers reveal.
      viewersCanReveal = true;
    }
  }

  return {
    /** null until loaded. */
    get viewersCanReveal() {
      return viewersCanReveal;
    },
    /** Whether the current user may reveal values (false while loading, for viewers). */
    get canReveal() {
      return session.can('editor') || viewersCanReveal === true;
    },
    load,
    set(v: boolean) {
      viewersCanReveal = v;
    }
  };
}

export const revealPolicy = createRevealPolicy();
