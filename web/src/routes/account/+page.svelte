<script lang="ts">
  import { onMount } from 'svelte';
  import { api, ApiError, type Me } from '$lib/api';

  let me: Me | null = $state(null);
  let error = $state('');

  onMount(async () => {
    try {
      me = await api.me();
    } catch (e) {
      error = e instanceof ApiError ? e.message : 'Failed to load account';
    }
  });
</script>

<div class="card">
  <h2>My Account</h2>
  {#if error}
    <p class="flash err">{error}</p>
  {:else if !me}
    <p class="muted">Loading…</p>
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
    <p class="muted" style="margin-top: 16px;">
      Manage your password and access keys from the
      <a href="/account/profile">profile</a> and
      <a href="/account/keys">access keys</a> pages.
    </p>
  {/if}
</div>
