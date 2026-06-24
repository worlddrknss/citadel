<script lang="ts">
  import { onMount } from 'svelte';
  import { api, ApiError, type Me } from '$lib/api';

  let me: Me | null = $state(null);
  let error = $state('');

  onMount(async () => {
    try {
      me = await api.me();
    } catch (e) {
      error = e instanceof ApiError ? e.message : 'Failed to load';
    }
  });

  const adminLinks = [
    { href: '/admin', label: 'Overview', desc: 'Deployment master settings' },
    { href: '/admin/users', label: 'Users', desc: 'Manage user identities' },
    { href: '/admin/rbac', label: 'RBAC', desc: 'Roles and access policies' },
    { href: '/admin/accounts', label: 'Accounts', desc: 'Tenant organizations' },
    { href: '/admin/settings', label: 'Settings', desc: 'Master deployment settings' }
  ];
</script>

<div class="card">
  <h2>Master Administration</h2>
  {#if error}
    <p class="flash err">{error}</p>
  {:else if me && me.role !== 'admin'}
    <div class="empty">
      <p class="muted">Administrator role required to manage the deployment.</p>
    </div>
  {:else}
    <p class="muted">Deployment-level administration. These management consoles open the secured admin pages.</p>
    <table>
      <thead><tr><th>Console</th><th>Description</th></tr></thead>
      <tbody>
        {#each adminLinks as l}
          <tr>
            <td><a href={l.href}>{l.label}</a></td>
            <td class="muted">{l.desc}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
</div>
