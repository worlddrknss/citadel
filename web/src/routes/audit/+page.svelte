<script lang="ts">
  import { onMount } from 'svelte';
  import { api, ApiError, type AuditEvent } from '$lib/api';

  let events: AuditEvent[] = $state([]);
  let loading = $state(true);
  let error = $state('');
  let filter = $state('');

  const pageSize = 25;
  let pageNum = $state(1);

  const shown = $derived(
    filter
      ? events.filter((e) =>
          (e.action + ' ' + e.actor + ' ' + (e.keyId ?? '') + ' ' + e.result)
            .toLowerCase()
            .includes(filter.toLowerCase())
        )
      : events
  );

  const pageCount = $derived(Math.max(1, Math.ceil(shown.length / pageSize)));
  const clampedPage = $derived(Math.min(pageNum, pageCount));
  const paged = $derived(shown.slice((clampedPage - 1) * pageSize, clampedPage * pageSize));
  const rangeStart = $derived(shown.length === 0 ? 0 : (clampedPage - 1) * pageSize + 1);
  const rangeEnd = $derived(Math.min(clampedPage * pageSize, shown.length));

  function resetPage() {
    pageNum = 1;
  }

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

  <input placeholder="Filter by action, actor, key…" bind:value={filter} oninput={resetPage} style="width: 320px;" />

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
        {#each paged as e}
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

    <div class="pager">
      <span class="muted small">Showing {rangeStart}–{rangeEnd} of {shown.length}</span>
      <div class="pager-act">
        <button class="btn btn-sm" disabled={clampedPage <= 1} onclick={() => (pageNum = 1)}>« First</button>
        <button class="btn btn-sm" disabled={clampedPage <= 1} onclick={() => (pageNum = clampedPage - 1)}>‹ Prev</button>
        <span class="small">Page {clampedPage} of {pageCount}</span>
        <button class="btn btn-sm" disabled={clampedPage >= pageCount} onclick={() => (pageNum = clampedPage + 1)}>Next ›</button>
        <button class="btn btn-sm" disabled={clampedPage >= pageCount} onclick={() => (pageNum = pageCount)}>Last »</button>
      </div>
    </div>
  {/if}
</div>

<style>
  .pager {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 1rem;
    margin-top: 1rem;
    flex-wrap: wrap;
  }
  .pager-act {
    display: flex;
    align-items: center;
    gap: 0.4rem;
  }
  .small {
    font-size: 0.82rem;
  }
</style>
