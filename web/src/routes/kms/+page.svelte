<script lang="ts">
  import { onMount } from 'svelte';
  import { api, ApiError, type KMSKey } from '$lib/api';

  let keys: KMSKey[] = $state([]);
  let loading = $state(true);
  let error = $state('');

  onMount(async () => {
    try {
      keys = (await api.kmsKeys()).keys;
    } catch (e) {
      error = e instanceof ApiError ? e.message : 'Failed to load keys';
    } finally {
      loading = false;
    }
  });
</script>

<div class="card">
  <h2>Customer Master Keys</h2>
  <p class="muted">Symmetric and asymmetric keys managed by the Citadel KMS service.</p>

  {#if loading}
    <p class="muted">Loading…</p>
  {:else if error}
    <p class="flash err">{error}</p>
  {:else if keys.length === 0}
    <div class="empty"><p class="muted">No KMS keys yet.</p></div>
  {:else}
    <table>
      <thead>
        <tr>
          <th>Key ID</th>
          <th>Description</th>
          <th>Spec</th>
          <th>Usage</th>
          <th>Status</th>
          <th>Created</th>
        </tr>
      </thead>
      <tbody>
        {#each keys as k}
          <tr>
            <td class="mono">{k.keyId}</td>
            <td>{k.description || '—'}</td>
            <td>{k.keySpec || '—'}</td>
            <td>{k.keyUsage || '—'}</td>
            <td>
              {#if k.deletionDate}
                <span class="badge">Pending deletion</span>
              {:else if k.enabled}
                <span class="badge">Enabled</span>
              {:else}
                <span class="badge">Disabled</span>
              {/if}
            </td>
            <td>{new Date(k.createdAt).toLocaleString()}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
</div>
