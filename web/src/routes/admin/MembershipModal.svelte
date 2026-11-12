<!-- Add a user to an account, or change the role of an existing membership. -->
<script lang="ts">
  import { untrack } from 'svelte';
  import Modal from '$lib/components/Modal.svelte';
  import Icon from '$lib/components/Icon.svelte';
  import { api, errorMessage, type Account } from '$lib/api';
  import { toast } from '$lib/stores/toast.svelte';
  import { ROLES, type RoleName, type UserRow } from './api';

  let {
    open = $bindable(false),
    users,
    accounts,
    preset = null,
    onsaved
  }: {
    open?: boolean;
    users: UserRow[];
    accounts: Account[];
    /** Editing an existing membership, or prefilled user/account. */
    preset?: { username?: string; accountId?: string; role?: RoleName; editing?: boolean } | null;
    onsaved: () => void;
  } = $props();

  let username = $state('');
  let accountId = $state('');
  let role = $state<RoleName>('viewer');
  let busy = $state(false);
  let error = $state('');

  $effect(() => {
    if (open)
      untrack(() => {
        username = preset?.username ?? '';
        accountId = preset?.accountId ?? '';
        role = preset?.role ?? 'viewer';
        error = '';
      });
  });

  const editing = $derived(!!preset?.editing);
  const already = $derived(
    !editing && !!username && !!accountId && !!users.find((u) => u.username === username)?.accounts?.includes(accountId)
  );

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    if (!username || !accountId) {
      error = 'Choose a user and an account.';
      return;
    }
    busy = true;
    error = '';
    try {
      await api.assignUserAccount(username, accountId, role);
      toast.success(editing ? `${username} is now ${role} in ${accountId}` : `Added ${username} to ${accountId}`);
      open = false;
      onsaved();
    } catch (err) {
      error = errorMessage(err, 'Could not save the membership.');
    } finally {
      busy = false;
    }
  }
</script>

<Modal bind:open title={editing ? 'Change membership role' : 'Add membership'} description="The role applies only inside this account." size="sm">
  <form id="mem-form" class="form" onsubmit={submit} novalidate>
    <div class="field">
      <label class="field-label" for="m-user">User</label>
      <select id="m-user" class="select" bind:value={username} disabled={editing || !!preset?.username}>
        <option value="" disabled>Choose a user…</option>
        {#each users as u (u.username)}<option value={u.username}>{u.displayName && u.displayName !== u.username ? `${u.displayName} (${u.username})` : u.username}</option>{/each}
      </select>
    </div>
    <div class="field">
      <label class="field-label" for="m-acct">Account</label>
      <select id="m-acct" class="select" bind:value={accountId} disabled={editing || !!preset?.accountId}>
        <option value="" disabled>Choose an account…</option>
        {#each accounts as a (a.accountId)}<option value={a.accountId}>{a.name} ({a.accountId})</option>{/each}
      </select>
      {#if already}<span class="field-hint">Already a member; saving changes their role.</span>{/if}
    </div>
    <div class="field">
      <label class="field-label" for="m-role">Role in this account</label>
      <select id="m-role" class="select" bind:value={role}>
        {#each ROLES as r (r.value)}<option value={r.value}>{r.label} · {r.hint}</option>{/each}
      </select>
    </div>
    {#if error}
      <div class="callout callout-danger" role="alert"><Icon name="alert-circle" size={16} /><span>{error}</span></div>
    {/if}
  </form>
  {#snippet footer()}
    <button type="button" class="btn btn-ghost" onclick={() => (open = false)}>Cancel</button>
    <button type="submit" form="mem-form" class="btn btn-primary" disabled={busy}>{busy ? 'Saving…' : editing ? 'Save role' : 'Add membership'}</button>
  {/snippet}
</Modal>

<style>
  .form {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
  }
  .form :global(.field + .field) {
    margin-top: 0;
  }
</style>
