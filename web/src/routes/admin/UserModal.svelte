<!-- Create a user, or edit one's display name, role or password. -->
<script lang="ts">
  import { untrack } from 'svelte';
  import Modal from '$lib/components/Modal.svelte';
  import Icon from '$lib/components/Icon.svelte';
  import { api, errorMessage, type Account } from '$lib/api';
  import { toast } from '$lib/stores/toast.svelte';
  import { session } from '$lib/stores/session.svelte';
  import { ROLES, type RoleName, type UserRow } from './api';

  let {
    open = $bindable(false),
    user = null,
    accounts,
    users,
    onsaved
  }: { open?: boolean; user?: UserRow | null; accounts: Account[]; users: UserRow[]; onsaved: () => void } = $props();

  let username = $state('');
  let displayName = $state('');
  let role = $state<RoleName>('viewer');
  let password = $state('');
  let initialAccount = $state('');
  let platformAdmin = $state(false);
  let touched = $state(false);
  let busy = $state(false);
  let error = $state('');

  $effect(() => {
    if (open)
      untrack(() => {
        username = user?.username ?? '';
        displayName = user?.displayName ?? '';
        role = (user?.role as RoleName) ?? 'viewer';
        password = '';
        // Account admins create people straight into their own account.
        initialAccount = isPlatform ? '' : (session.me?.accountId ?? '');
        platformAdmin = !!user?.platformAdmin;
        touched = false;
        error = '';
      });
  });

  const isPlatform = $derived(session.platformAdmin);
  const isSelf = $derived(!!user && user.username === session.me?.username);
  // Only platform admins set a user's default role; account admins grant a
  // role in their account (a membership) when creating, and change it on the
  // Memberships tab. The server ignores the default role otherwise.
  const showRole = $derived(isPlatform || !user);

  const usernameError = $derived(
    user ? '' : !/^[a-zA-Z0-9._@-]{2,64}$/.test(username.trim()) ? "Use 2–64 letters, numbers, '.', '_', '-' or '@'." : users.some((u) => u.username.toLowerCase() === username.trim().toLowerCase()) ? 'That username is taken.' : ''
  );
  const passwordError = $derived(!user && !password ? 'Set an initial password.' : password && password.length < 8 ? 'Use at least 8 characters.' : '');

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    touched = true;
    if (usernameError || passwordError) return;
    busy = true;
    error = '';
    try {
      const name = user?.username ?? username.trim();
      await api.upsertUser({
        username: name,
        displayName: displayName.trim(),
        role,
        password: password || undefined,
        accounts: !user && initialAccount ? [initialAccount] : undefined,
        ...(isPlatform && !isSelf ? { platformAdmin } : {})
      });
      if (!user && initialAccount) await api.assignUserAccount(name, initialAccount, role);
      toast.success(user ? `Saved ${name}` : `Created ${name}`);
      open = false;
      onsaved();
    } catch (err) {
      error = errorMessage(err, 'Could not save the user.');
    } finally {
      busy = false;
    }
  }
</script>

<Modal bind:open title={user ? `Edit ${user.username}` : 'Create user'} description={user ? undefined : 'A console sign-in. Share the initial password out of band; they can change it from My account.'} size="md">
  <form id="user-form" class="form" onsubmit={submit} novalidate>
    <!-- Keeps password managers from offering the admin's own credentials. -->
    <input type="text" name="username" autocomplete="off" value={user?.username ?? username} readonly hidden />
    <div class="field-row">
      <div class="field">
        <label class="field-label" for="u-name">Username</label>
        <input id="u-name" class="input mono" bind:value={username} disabled={!!user} autocomplete="off" spellcheck="false" aria-invalid={touched && !!usernameError} />
        {#if touched && usernameError}<span class="field-error">{usernameError}</span>{/if}
      </div>
      <div class="field">
        <label class="field-label" for="u-dn">Display name</label>
        <input id="u-dn" class="input" bind:value={displayName} autocomplete="off" placeholder="Ana López" />
      </div>
    </div>
    {#if showRole}
    <fieldset class="field" disabled={isSelf}>
      <legend class="field-label">{isPlatform ? 'Default role' : 'Role in this account'}</legend>
      <div class="roles">
        {#each ROLES as r (r.value)}
          <label class="choice" class:on={role === r.value}>
            <input type="radio" name="u-role" value={r.value} bind:group={role} />
            <span><span class="ctitle">{r.label}</span><span class="muted csub">{r.hint}</span></span>
          </label>
        {/each}
      </div>
      {#if isSelf}
        <span class="field-hint">You can't change your own role.</span>
      {:else}
        <span class="field-hint">Each account membership can override this on the Memberships tab.</span>
      {/if}
    </fieldset>
    {/if}
    {#if isPlatform && !isSelf}
      <label class="choice pa">
        <input type="checkbox" bind:checked={platformAdmin} />
        <span><span class="ctitle">Platform admin</span><span class="muted csub">Manages every account, org settings, the workload identity issuer and org-wide SSO.</span></span>
      </label>
    {/if}
    {#if !user && accounts.length && isPlatform}
      <div class="field">
        <label class="field-label" for="u-acct">Add to account <span class="subtle">(optional)</span></label>
        <select id="u-acct" class="select" bind:value={initialAccount}>
          <option value="">None for now</option>
          {#each accounts as a (a.accountId)}<option value={a.accountId}>{a.name} ({a.accountId})</option>{/each}
        </select>
      </div>
    {/if}
    <div class="field">
      <label class="field-label" for="u-pw">{user ? 'Reset password' : 'Initial password'}</label>
      <input id="u-pw" class="input" type="password" bind:value={password} autocomplete="new-password" placeholder={user ? 'Leave blank to keep the current password' : ''} aria-invalid={touched && !!passwordError} />
      {#if touched && passwordError}<span class="field-error">{passwordError}</span>{:else}<span class="field-hint">At least 8 characters.</span>{/if}
    </div>
    {#if error}
      <div class="callout callout-danger" role="alert"><Icon name="alert-circle" size={16} /><span>{error}</span></div>
    {/if}
  </form>
  {#snippet footer()}
    <button type="button" class="btn btn-ghost" onclick={() => (open = false)}>Cancel</button>
    <button type="submit" form="user-form" class="btn btn-primary" disabled={busy}>{busy ? 'Saving…' : user ? 'Save changes' : 'Create user'}</button>
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
  fieldset {
    margin: 0;
    padding: 0;
    border: 0;
  }
  legend {
    padding: 0;
    margin-bottom: 6px;
  }
  .roles {
    display: grid;
    gap: 6px;
  }
  .choice {
    display: flex;
    gap: 10px;
    padding: 10px 12px;
    border: 1px solid var(--border-strong);
    border-radius: var(--radius-md);
    cursor: pointer;
  }
  .choice.on {
    border-color: var(--accent);
    background: var(--accent-soft);
  }
  .choice:focus-within {
    box-shadow: var(--focus-ring);
  }
  .choice input {
    margin-top: 2px;
  }
  .choice > span {
    display: flex;
    flex-direction: column;
  }
  .ctitle {
    font-weight: 600;
  }
  .csub {
    font-size: 12px;
  }
</style>
