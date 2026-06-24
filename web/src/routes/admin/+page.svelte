<script lang="ts">
  import { onMount } from 'svelte';
  import { api, ApiError, type Me, type AdminUser, type Account } from '$lib/api';

  let me: Me | null = $state(null);
  let users: AdminUser[] = $state([]);
  let accounts: Account[] = $state([]);
  let flash = $state('');
  let flashOk = $state(true);
  let loaded = $state(false);

  // User form
  let uUsername = $state('');
  let uDisplayName = $state('');
  let uRole = $state('viewer');
  let uPassword = $state('');
  let savingUser = $state(false);

  // Account form
  let aName = $state('');
  let creatingAccount = $state(false);

  // Assignment form
  let asgUsername = $state('');
  let asgAccount = $state('');
  let asgRole = $state('viewer');

  const isAdmin = $derived(me?.role === 'admin');

  function notify(msg: string, ok = true) {
    flash = msg;
    flashOk = ok;
    setTimeout(() => (flash = ''), 5000);
  }

  async function load() {
    try {
      me = await api.me();
    } catch (e) {
      if (e instanceof ApiError) notify(e.message, false);
      return;
    }
    if (me?.role !== 'admin') {
      loaded = true;
      return;
    }
    try {
      users = (await api.users()).users;
      accounts = (await api.accounts()).accounts;
    } catch (e) {
      if (e instanceof ApiError) notify(e.message, false);
    } finally {
      loaded = true;
    }
  }

  async function saveUser() {
    if (!uUsername.trim()) {
      notify('username is required', false);
      return;
    }
    savingUser = true;
    try {
      const res = await api.upsertUser({
        username: uUsername.trim(),
        displayName: uDisplayName.trim(),
        role: uRole,
        password: uPassword || undefined
      });
      notify(res.created ? `Created user ${res.username}` : `Updated user ${res.username}`);
      uUsername = '';
      uDisplayName = '';
      uPassword = '';
      users = (await api.users()).users;
    } catch (e) {
      if (e instanceof ApiError) notify(e.message, false);
    } finally {
      savingUser = false;
    }
  }

  function editUser(u: AdminUser) {
    uUsername = u.username;
    uDisplayName = u.displayName;
    uRole = u.role;
    uPassword = '';
  }

  async function deleteUser(u: AdminUser) {
    if (!confirm(`Delete user ${u.username}?`)) return;
    try {
      await api.deleteUser(u.username);
      notify(`Deleted ${u.username}`);
      users = (await api.users()).users;
    } catch (e) {
      if (e instanceof ApiError) notify(e.message, false);
    }
  }

  async function createAccount() {
    if (!aName.trim()) {
      notify('account name is required', false);
      return;
    }
    creatingAccount = true;
    try {
      const res = await api.createAccount(aName.trim());
      notify(`Created account ${res.accountId}`);
      aName = '';
      accounts = (await api.accounts()).accounts;
    } catch (e) {
      if (e instanceof ApiError) notify(e.message, false);
    } finally {
      creatingAccount = false;
    }
  }

  async function deleteAccount(a: Account) {
    if (!confirm(`Delete account ${a.name} (${a.accountId})?`)) return;
    try {
      await api.deleteAccount(a.accountId);
      notify(`Deleted ${a.accountId}`);
      accounts = (await api.accounts()).accounts;
    } catch (e) {
      if (e instanceof ApiError) notify(e.message, false);
    }
  }

  async function assign() {
    if (!asgUsername.trim() || !asgAccount) {
      notify('username and account are required', false);
      return;
    }
    try {
      await api.assignUserAccount(asgUsername.trim(), asgAccount, asgRole);
      notify(`Assigned ${asgUsername} to ${asgAccount}`);
      asgUsername = '';
    } catch (e) {
      if (e instanceof ApiError) notify(e.message, false);
    }
  }

  onMount(load);
</script>

<div class="ph">
  <h1 class="ph-title">Master Administration</h1>
  <p class="ph-sub">Deployment-level management of users, accounts (organizations), and role assignments.</p>
</div>

{#if flash}
  <div class="flash {flashOk ? 'ok' : 'err'}">{flash}</div>
{/if}

{#if loaded && !isAdmin}
  <div class="card">
    <div class="empty">Administrator role required to manage the deployment.</div>
  </div>
{:else if isAdmin}
  <div class="card">
    <h3 style="margin-top:0">Users</h3>
    {#if users.length === 0}
      <div class="empty">No users yet.</div>
    {:else}
      <table>
        <thead>
          <tr><th>Username</th><th>Display name</th><th>Role</th><th>Accounts</th><th></th></tr>
        </thead>
        <tbody>
          {#each users as u}
            <tr>
              <td class="mono">{u.username}</td>
              <td>{u.displayName || '—'}</td>
              <td><span class="badge">{u.role}</span></td>
              <td>
                {#if u.accounts && u.accounts.length}
                  {#each u.accounts as a}<span class="badge mono">{a}</span> {/each}
                {:else}—{/if}
              </td>
              <td>
                <button class="btn btn-sm" onclick={() => editUser(u)}>Edit</button>
                <button class="btn btn-sm btn-d" onclick={() => deleteUser(u)}>Delete</button>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
  </div>

  <div class="card" style="margin-top:1.25rem">
    <h3 style="margin-top:0">Create / update user</h3>
    <div class="toolbar" style="margin-bottom:0">
      <div class="field">
        <label for="uu">Username</label>
        <input id="uu" class="mono" bind:value={uUsername} />
      </div>
      <div class="field" style="flex:1">
        <label for="ud">Display name</label>
        <input id="ud" bind:value={uDisplayName} />
      </div>
      <div class="field">
        <label for="ur">Role</label>
        <select id="ur" bind:value={uRole}>
          <option value="viewer">viewer</option>
          <option value="editor">editor</option>
          <option value="admin">admin</option>
        </select>
      </div>
      <div class="field">
        <label for="up">Password</label>
        <input id="up" type="password" placeholder="(unchanged)" bind:value={uPassword} />
      </div>
      <div class="field" style="align-self:flex-end">
        <button class="btn btn-p" onclick={saveUser} disabled={savingUser}>
          {savingUser ? 'Saving…' : 'Save user'}
        </button>
      </div>
    </div>
  </div>

  <div class="card" style="margin-top:1.25rem">
    <h3 style="margin-top:0">Accounts</h3>
    {#if accounts.length === 0}
      <div class="empty">No accounts yet.</div>
    {:else}
      <table>
        <thead><tr><th>Account ID</th><th>Name</th><th>Created</th><th></th></tr></thead>
        <tbody>
          {#each accounts as a}
            <tr>
              <td class="mono">{a.accountId}</td>
              <td>{a.name}</td>
              <td class="muted">{a.createdAt}</td>
              <td><button class="btn btn-sm btn-d" onclick={() => deleteAccount(a)}>Delete</button></td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
    <div class="toolbar" style="margin:0.75rem 0 0">
      <div class="field" style="flex:1">
        <label for="an">New account name</label>
        <input id="an" bind:value={aName} />
      </div>
      <div class="field" style="align-self:flex-end">
        <button class="btn btn-p" onclick={createAccount} disabled={creatingAccount}>
          {creatingAccount ? 'Creating…' : 'Create account'}
        </button>
      </div>
    </div>
  </div>

  <div class="card" style="margin-top:1.25rem">
    <h3 style="margin-top:0">Assign user to account</h3>
    <div class="toolbar" style="margin-bottom:0">
      <div class="field" style="flex:1">
        <label for="au">Username</label>
        <input id="au" class="mono" bind:value={asgUsername} />
      </div>
      <div class="field">
        <label for="aa">Account</label>
        <select id="aa" bind:value={asgAccount}>
          <option value="">(select)</option>
          {#each accounts as a}
            <option value={a.accountId}>{a.name} ({a.accountId})</option>
          {/each}
        </select>
      </div>
      <div class="field">
        <label for="ar">Role</label>
        <select id="ar" bind:value={asgRole}>
          <option value="viewer">viewer</option>
          <option value="editor">editor</option>
          <option value="admin">admin</option>
        </select>
      </div>
      <div class="field" style="align-self:flex-end">
        <button class="btn btn-p" onclick={assign}>Assign</button>
      </div>
    </div>
  </div>
{/if}
