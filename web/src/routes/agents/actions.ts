// Suspend / resume / revoke / delete with the same confirmations on the
// list page and the detail page.

import type { MenuItem } from '#lib/components/ActionMenu.svelte';
import { confirm } from '#lib/stores/confirm.svelte.ts';
import { toast } from '#lib/stores/toast.svelte.ts';
import { agentsApi, type Agent } from './api';

export async function suspendAgent(a: Agent): Promise<boolean> {
  const ok = await confirm({
    title: `Suspend ${a.name}?`,
    message: 'Every request the agent makes is refused until you resume it. Its tokens, bindings and grants are kept.',
    confirmLabel: 'Suspend agent',
    danger: true
  });
  if (!ok) return false;
  try {
    await agentsApi.suspend(a.agentId);
    toast.success(`Suspended ${a.name}`);
    return true;
  } catch (e) {
    toast.error(e, 'Could not suspend the agent');
    return false;
  }
}

export async function resumeAgent(a: Agent): Promise<boolean> {
  try {
    await agentsApi.resume(a.agentId);
    toast.success(`Resumed ${a.name}`);
    return true;
  } catch (e) {
    toast.error(e, 'Could not resume the agent');
    return false;
  }
}

export async function revokeAgent(a: Agent): Promise<boolean> {
  const ok = await confirm({
    title: `Revoke ${a.name}?`,
    message: 'Revoking is permanent: all of its tokens stop working and it can never be resumed. Its audit history is kept.',
    confirmLabel: 'Revoke agent',
    danger: true,
    typeToConfirm: a.name
  });
  if (!ok) return false;
  try {
    await agentsApi.revoke(a.agentId);
    toast.success(`Revoked ${a.name}`);
    return true;
  } catch (e) {
    toast.error(e, 'Could not revoke the agent');
    return false;
  }
}

export async function deleteAgent(a: Agent): Promise<boolean> {
  const ok = await confirm({
    title: `Delete ${a.name}?`,
    message: 'The agent, its tokens, bindings and grants are removed. Its audit history is kept.',
    confirmLabel: 'Delete agent',
    danger: true,
    typeToConfirm: a.name
  });
  if (!ok) return false;
  try {
    await agentsApi.remove(a.agentId);
    toast.success(`Deleted ${a.name}`);
    return true;
  } catch (e) {
    toast.error(e, 'Could not delete the agent');
    return false;
  }
}

/** Row/detail menu items for an agent the caller may manage. */
export function agentMenu(a: Agent, done: (deleted?: boolean) => void): MenuItem[] {
  const run = (fn: (a: Agent) => Promise<boolean>, deleted = false) => async () => {
    if (await fn(a)) done(deleted);
  };
  const items: MenuItem[] = [];
  if (a.status === 'active') items.push({ label: 'Suspend', icon: 'clock', onselect: run(suspendAgent) });
  if (a.status === 'suspended') items.push({ label: 'Resume', icon: 'play', onselect: run(resumeAgent) });
  if (a.status !== 'revoked') items.push({ label: 'Revoke', icon: 'x-circle', danger: true, onselect: run(revokeAgent) });
  items.push({ label: 'Delete', icon: 'trash', danger: true, onselect: run(deleteAgent, true) });
  return items;
}
