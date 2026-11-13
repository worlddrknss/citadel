<!--
  The secret drawer's Agent access tab: usage profiles that let AI agents
  use this secret without seeing it, and which agents are granted each one.
-->
<script lang="ts">
  import { untrack } from 'svelte';
  import { base } from '#lib/paths.ts';
  import Badge from '#lib/components/Badge.svelte';
  import Icon from '#lib/components/Icon.svelte';
  import { errorMessage } from '#lib/api.ts';
  import { confirm } from '#lib/stores/confirm.svelte.ts';
  import { toast } from '#lib/stores/toast.svelte.ts';
  import CredentialModal from '../../../agents/CredentialModal.svelte';
  import { agentsApi, KIND_LABELS, type AgentCredential } from '../../../agents/api';

  let {
    coord,
    canEdit,
    deleted
  }: {
    coord: { project: string; env: string; path: string; key: string };
    canEdit: boolean;
    deleted: boolean;
  } = $props();

  let creds = $state<AgentCredential[]>([]);
  let loading = $state(true);
  let error = $state('');
  let modalOpen = $state(false);
  let editing = $state<AgentCredential | null>(null);

  async function load() {
    error = '';
    try {
      creds = (await agentsApi.credentials(coord)).credentials ?? [];
    } catch (e) {
      error = errorMessage(e, 'Could not load agent access.');
    } finally {
      loading = false;
    }
  }

  $effect(() => {
    void coord.project;
    void coord.env;
    void coord.path;
    void coord.key;
    untrack(() => {
      loading = true;
      load();
    });
  });

  function add() {
    editing = null;
    modalOpen = true;
  }
  function edit(c: AgentCredential) {
    editing = c;
    modalOpen = true;
  }
  async function remove(c: AgentCredential) {
    const ok = await confirm({
      title: `Stop agents using ${c.name}?`,
      message: c.grants.length ? 'Remove the agents\' grants first.' : 'The usage profile is deleted. The secret itself is unchanged.',
      confirmLabel: 'Delete profile',
      danger: true
    });
    if (!ok) return;
    try {
      await agentsApi.deleteCredential(c.name);
      toast.success(`Deleted ${c.name}`);
      await load();
    } catch (e) {
      toast.error(e, 'Could not delete the usage profile');
    }
  }
</script>

{#if loading && creds.length === 0}
  <div class="skel" aria-busy="true" aria-label="Loading agent access">
    <span class="skeleton"></span><span class="skeleton"></span>
  </div>
{:else if error}
  <div class="callout callout-danger" role="alert">
    <Icon name="alert-circle" size={16} />
    <span class="grow">{error}</span>
    <button type="button" class="btn btn-ghost btn-sm" onclick={() => load()}>Retry</button>
  </div>
{:else}
  <div class="wrap">
    <p class="muted small intro">
      A usage profile lets <a href="{base}/agents">agents</a> use this secret without holding it: Citadel injects it into requests to the hosts listed, and agents only ever see the profile's name.
    </p>
    {#each creds as c (c.name)}
      <article class="cred" aria-label="Usage profile {c.name}">
        <div class="cred-head">
          <span class="mono strong">{c.name}</span>
          <span class="badge">{KIND_LABELS[c.kind]}</span>
          {#if canEdit && !deleted}
            <span class="acts">
              <button type="button" class="btn-icon" aria-label="Edit {c.name}" title="Edit" onclick={() => edit(c)}><Icon name="edit" size={14} /></button>
              <button type="button" class="btn-icon danger" aria-label="Delete {c.name}" title="Delete" onclick={() => remove(c)}><Icon name="trash" size={14} /></button>
            </span>
          {/if}
        </div>
        {#if c.description}<p class="small muted desc">{c.description}</p>{/if}
        <dl class="kv small">
          {#if c.allowedHosts.length}
            <dt>Hosts</dt>
            <dd><span class="chips">{#each c.allowedHosts as h (h)}<span class="badge mono">{h}</span>{/each}</span></dd>
          {/if}
          {#if c.allowedMethods.length}
            <dt>Methods</dt>
            <dd class="mono">{c.allowedMethods.join(' ')}</dd>
          {/if}
          {#if c.kind === 'http_header'}
            <dt>Injected as</dt>
            <dd class="mono">{c.headerName}: {c.headerPrefix}••••</dd>
          {:else if c.kind === 'http_query'}
            <dt>Injected as</dt>
            <dd class="mono">?{c.queryParam}=••••</dd>
          {/if}
          {#if c.allowedPathPrefixes.length}
            <dt>Paths</dt>
            <dd class="mono">{c.allowedPathPrefixes.join(', ')}</dd>
          {/if}
          <dt>Agents</dt>
          <dd>
            {#if c.grants.length}
              <ul class="grants">
                {#each c.grants as g (g.grantId)}
                  <li>
                    <a class="row-link" href="{base}/agents/{encodeURIComponent(g.agentId)}?tab=grants">{g.agentName || g.agentId}</a>
                    {#each g.actions as a (a)}
                      {#if a === 'reveal'}<Badge tone="danger" dot={false}>reveal</Badge>{:else}<span class="badge">{a}</span>{/if}
                    {/each}
                  </li>
                {/each}
              </ul>
            {:else}<span class="subtle">None yet. Grant it from an agent's Grants tab.</span>{/if}
          </dd>
        </dl>
      </article>
    {:else}
      <div class="empty">
        <Icon name="bot" size={20} />
        <span class="muted small">No agent can use this secret.</span>
      </div>
    {/each}
    {#if canEdit && !deleted}
      <div><button type="button" class="btn btn-secondary btn-sm" onclick={add}><Icon name="plus" size={14} />Make usable by agents</button></div>
    {/if}
  </div>
{/if}

<CredentialModal bind:open={modalOpen} {coord} credential={editing} onsaved={load} />

<style>
  .wrap {
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
  }
  .intro {
    margin: 0;
  }
  .intro a {
    text-decoration: underline;
  }
  .cred {
    padding: var(--space-3);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: var(--surface-sunken);
  }
  .cred-head {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    flex-wrap: wrap;
  }
  .acts {
    margin-left: auto;
    display: inline-flex;
    gap: 2px;
  }
  .desc {
    margin: var(--space-1) 0 0;
  }
  .kv {
    margin-top: var(--space-2);
    grid-template-columns: 90px minmax(0, 1fr);
  }
  .chips {
    display: inline-flex;
    flex-wrap: wrap;
    gap: 4px;
  }
  .grants {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 4px;
  }
  .grants li {
    display: flex;
    align-items: center;
    gap: 6px;
    flex-wrap: wrap;
  }
  .empty {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    padding: var(--space-3);
    border: 1px dashed var(--border);
    border-radius: var(--radius-md);
    color: var(--text-subtle);
  }
  .skel {
    display: flex;
    flex-direction: column;
    gap: 10px;
  }
  .skel .skeleton {
    height: 14px;
  }
  .grow {
    flex: 1;
  }
  .danger:hover:not(:disabled) {
    color: var(--danger);
    background: var(--danger-soft);
  }
</style>
