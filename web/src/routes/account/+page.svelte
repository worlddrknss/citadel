<script lang="ts">
  import { onMount } from 'svelte';
  import { api, ApiError, type Me, type AccessKey } from '$lib/api';

  let me: Me | null = $state(null);
  let keys: AccessKey[] = $state([]);
  let flash = $state('');
  let flashOk = $state(true);

  // Newly created key secret (shown once)
  let newSecret: { accessKeyId: string; secretKey: string } | null = $state(null);

  // Password form
  let currentPassword = $state('');
  let newPassword = $state('');
  let confirmPassword = $state('');
  let changing = $state(false);

  function notify(msg: string, ok = true) {
    flash = msg;
    flashOk = ok;
    setTimeout(() => (flash = ''), 5000);
  }

  async function load() {
    try {
      me = await api.me();
      keys = (await api.accessKeys()).accessKeys;
    } catch (e) {
      if (e instanceof ApiError) notify(e.message, false);
    }
  }

  async function createKey() {
    try {
      newSecret = await api.createAccessKey();
      notify('Access key created — copy the secret now, it will not be shown again');
      keys = (await api.accessKeys()).accessKeys;
    } catch (e) {
      if (e instanceof ApiError) notify(e.message, false);
    }
  }

  async function deleteKey(k: AccessKey) {
    if (!confirm(`Delete access key ${k.accessKeyId}?`)) return;
    try {
      await api.deleteAccessKey(k.accessKeyId);
      notify(`Deleted ${k.accessKeyId}`);
      if (newSecret?.accessKeyId === k.accessKeyId) newSecret = null;
      keys = (await api.accessKeys()).accessKeys;
    } catch (e) {
      if (e instanceof ApiError) notify(e.message, false);
    }
  }

  async function toggleKey(k: AccessKey) {
    const next = k.status === 'Active' ? 'Inactive' : 'Active';
    try {
      await api.setAccessKeyStatus(k.accessKeyId, next);
      notify(`${k.accessKeyId} → ${next}`);
      keys = (await api.accessKeys()).accessKeys;
    } catch (e) {
      if (e instanceof ApiError) notify(e.message, false);
    }
  }

  async function changePassword() {
    if (newPassword !== confirmPassword) {
      notify('passwords do not match', false);
      return;
    }
    if (newPassword.length < 8) {
      notify('new password must be at least 8 characters', false);
      return;
    }
    changing = true;
    try {
      await api.changePassword(currentPassword, newPassword);
      notify('Password updated');
      currentPassword = '';
      newPassword = '';
      confirmPassword = '';
    } catch (e) {
      if (e instanceof ApiError) notify(e.message, false);
    } finally {
      changing = false;
    }
  }

  onMount(load);
</script>

<div class="ph">
  <h1 class="ph-title">My Account</h1>
  <p class="ph-sub">Profile, access keys for machine identities, and password management.</p>
</div>

{#if flash}
  <div class="flash {flashOk ? 'ok' : 'err'}">{flash}</div>
{/if}

<div class="card">
  <h3 style="margin-top:0">Profile</h3>
  {#if !me}
    <div class="empty">Loading…</div>
  {:else}
    <table>
      <tbody>
        <tr><th>Username</th><td class="mono">{me.username}</td></tr>
        <tr><th>Display name</th><td>{me.displayName}</td></tr>
        <tr><th>Role</th><td><span class="badge">{me.role}</span></td></tr>
        <tr><th>Active account</th><td class="mono">{me.accountId || '—'}</td></tr>
        <tr>
          <th>Accounts</th>
          <td>
            {#if me.accounts && me.accounts.length}
              {#each me.accounts as a}<span class="badge mono">{a}</span> {/each}
            {:else}
              —
            {/if}
          </td>
        </tr>
      </tbody>
    </table>
  {/if}
</div>

<div class="card" style="margin-top:1.25rem">
  <div class="toolbar" style="justify-content:space-between;align-items:center;margin-bottom:0.75rem">
    <h3 style="margin:0">Access keys</h3>
    <button class="btn btn-p" onclick={createKey}>Create access key</button>
  </div>

  {#if newSecret}
    <div class="flash ok">
      <strong>New access key — copy now:</strong>
      <div class="mono" style="margin-top:0.5rem">
        ID: {newSecret.accessKeyId}<br />
        Secret: {newSecret.secretKey}
      </div>
    </div>
  {/if}

  {#if keys.length === 0}
    <div class="empty">No access keys. A maximum of two active keys per account is allowed.</div>
  {:else}
    <table>
      <thead>
        <tr>
          <th>Access key ID</th>
          <th>Status</th>
          <th>Created</th>
          <th>Last used</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        {#each keys as k}
          <tr>
            <td class="mono">{k.accessKeyId}</td>
            <td><span class="badge">{k.status}</span></td>
            <td class="muted">{new Date(k.createdAt).toLocaleString()}</td>
            <td class="muted">{k.lastUsedAt ? new Date(k.lastUsedAt).toLocaleString() : 'never'}</td>
            <td>
              <button class="btn btn-sm" onclick={() => toggleKey(k)}>
                {k.status === 'Active' ? 'Deactivate' : 'Activate'}
              </button>
              <button class="btn btn-sm btn-d" onclick={() => deleteKey(k)}>Delete</button>
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
</div>

<div class="card" style="margin-top:1.25rem">
  <h3 style="margin-top:0">Change password</h3>
  <div class="toolbar" style="margin-bottom:0">
    <div class="field">
      <label for="cp">Current password</label>
      <input id="cp" type="password" bind:value={currentPassword} />
    </div>
    <div class="field">
      <label for="np">New password</label>
      <input id="np" type="password" bind:value={newPassword} />
    </div>
    <div class="field">
      <label for="cf">Confirm</label>
      <input id="cf" type="password" bind:value={confirmPassword} />
    </div>
    <div class="field" style="align-self:flex-end">
      <button class="btn btn-p" onclick={changePassword} disabled={changing}>
        {changing ? 'Updating…' : 'Update password'}
      </button>
    </div>
  </div>
</div>
