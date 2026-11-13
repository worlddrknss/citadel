<!-- "Who can read this": principals granted by the secret's resource policy,
     plus account admins, who can always manage it. -->
<script lang="ts">
  import Icon from '#lib/components/Icon.svelte';
  import { parsePolicyAccess } from '../../api';

  let { policy }: { policy: string } = $props();

  const entries = $derived(parsePolicyAccess(policy));
</script>

<ul class="list">
  {#each entries as e (e.principal)}
    <li>
      <span class="subtle ic"><Icon name="shield" size={14} /></span>
      <span class="mono who">{e.principal}</span>
      {#if e.deny}
        <span class="badge badge-danger">Denied</span>
      {:else}
        <span class="badge" class:badge-info={e.access === 'Read · Write'} class:badge-warning={e.access === 'Full'}>{e.access}</span>
      {/if}
    </li>
  {/each}
  <li>
    <span class="subtle ic"><Icon name="users" size={14} /></span>
    <span class="who">Admins and editors in this account</span>
    <span class="badge">Full</span>
  </li>
</ul>
{#if entries.length === 0}
  <p class="subtle small note">No resource policy grants other principals access.</p>
{/if}

<style>
  .list {
    margin: 0;
    padding: 0;
    list-style: none;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
  }
  .list li {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 10px var(--space-3);
    border-bottom: 1px solid var(--border);
  }
  .list li:last-child {
    border-bottom: none;
  }
  .ic {
    display: inline-flex;
  }
  .who {
    flex: 1;
    min-width: 0;
    overflow-wrap: anywhere;
  }
  .note {
    margin: var(--space-2) 0 0;
  }
</style>
