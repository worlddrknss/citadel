<script lang="ts">
  import { onMount } from 'svelte';
  import { api, ApiError, type AuditEvent } from '$lib/api';

  let events: AuditEvent[] = $state([]);
  let loading = $state(true);
  let error = $state('');
  let filter = $state('');

  const shown = $derived(
    filter
      ? events.filter((e) =>
          (e.action + ' ' + e.actor + ' ' + (e.keyId ?? '') + ' ' + e.result)
            .toLowerCase()
            .includes(filter.toLowerCase())
        )
      : events
  );

  onMount(async () => {
    try {
      events = (await api.audit()).events;
    } catch (e) {
      error = e instanceof ApiError ? e.message : 'Failed to load audit log';
    } finally {
      loading = false;
    }
  });
</script>

<div class="card">
  <h2>Audit Log</h2>
  <p class="muted">Tamper-evident, hash-chained record of every KMS, Secrets, and certificate action.</p>

  <input placeholder="Filter by action, actor, key…" bind:value={filter} style="width: 320px;" />

  {#if loading}
    <p class="muted">Loading…</p>
  {:else if error}
    <p class="flash err">{error}</p>
  {:else if shown.length === 0}
    <div class="empty"><p class="muted">No matching audit events.</p></div>
  {:else}
    <table>
      <thead>
        <tr>
          <th>Time</th>
          <th>Action</th>
          <th>Result</th>
          <th>Key</th>
          <th>Actor</th>
        </tr>
      </thead>
      <tbody>
        {#each shown as e}
          <tr>
            <td>{new Date(e.createdAt).toLocaleString()}</td>
            <td class="mono">{e.action}</td>
            <td>
              <span class="badge">{e.result}{e.errorType ? ` · ${e.errorType}` : ''}</span>
            </td>
            <td class="mono">{e.keyId || '—'}</td>
            <td>{e.actor || '—'}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
</div>
