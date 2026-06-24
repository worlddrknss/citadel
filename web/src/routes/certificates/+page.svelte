<script lang="ts">
  import { onMount } from 'svelte';
  import { api, ApiError, type Certificate } from '$lib/api';

  let certs: Certificate[] = $state([]);
  let loading = $state(true);
  let error = $state('');

  const sourceLabel: Record<string, string> = {
    'pca-ca': 'Private CA',
    'pca-cert': 'Issued (PCA)',
    'lets-encrypt': "Let's Encrypt"
  };

  onMount(async () => {
    try {
      certs = (await api.certificates()).certificates;
    } catch (e) {
      error = e instanceof ApiError ? e.message : 'Failed to load certificates';
    } finally {
      loading = false;
    }
  });
</script>

<div class="card">
  <h2>Certificates</h2>
  <p class="muted">Private CA hierarchy, issued certificates, and ACME / Let's Encrypt certificates.</p>

  {#if loading}
    <p class="muted">Loading…</p>
  {:else if error}
    <p class="flash err">{error}</p>
  {:else if certs.length === 0}
    <div class="empty"><p class="muted">No certificates yet.</p></div>
  {:else}
    <table>
      <thead>
        <tr>
          <th>Source</th>
          <th>ID</th>
          <th>Subject / Serial</th>
          <th>Status</th>
          <th>Not After</th>
        </tr>
      </thead>
      <tbody>
        {#each certs as c}
          <tr>
            <td>{sourceLabel[c.source] ?? c.source}</td>
            <td class="mono">{c.id}</td>
            <td>{c.subject || '—'}</td>
            <td><span class="badge">{c.status || '—'}</span></td>
            <td>{c.notAfter ? new Date(c.notAfter).toLocaleDateString() : '—'}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
</div>
