<script lang="ts">
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import { base } from '#lib/paths.ts';
  import PageHeader from '#lib/components/PageHeader.svelte';
  import DataTable, { type Column } from '#lib/components/DataTable.svelte';
  import EmptyState from '#lib/components/EmptyState.svelte';
  import Badge from '#lib/components/Badge.svelte';
  import Modal from '#lib/components/Modal.svelte';
  import Icon from '#lib/components/Icon.svelte';
  import ActionMenu from '#lib/components/ActionMenu.svelte';
  import { errorMessage } from '#lib/api.ts';
  import { session } from '#lib/stores/session.svelte.ts';
  import { toast } from '#lib/stores/toast.svelte.ts';
  import { relTime, fullTime } from '../time';
  import { agentMenu } from './actions';
  import AddLoginModal from './AddLoginModal.svelte';
  import { DOC_LINKS } from '#lib/docs-links.ts';
  import { agentsApi, AGENT_NAME_RE, STATUS_LABEL, STATUS_TONE, type Agent, type AgentSettings } from './api';

  let agents = $state<Agent[]>([]);
  let settings = $state<AgentSettings | null>(null);
  let canCreate = $state(false);
  let loading = $state(true);
  let loadError = $state('');
  let query = $state('');

  async function load() {
    loadError = '';
    try {
      const r = await agentsApi.list();
      agents = r.agents ?? [];
      settings = r.settings;
      canCreate = r.canCreate;
    } catch (e) {
      loadError = errorMessage(e, 'Could not load agents.');
    } finally {
      loading = false;
    }
  }
  onMount(load);

  let addLoginOpen = $state(false);

  // ---- new agent -----------------------------------------------------------
  let createOpen = $state(false);
  let name = $state('');
  let description = $state('');
  let owner = $state('');
  let creating = $state(false);
  let createError = $state('');
  const nameError = $derived(name && !AGENT_NAME_RE.test(name) ? 'Letters, digits, dots, dashes or underscores; up to 64.' : '');

  function openCreate() {
    name = description = owner = createError = '';
    createOpen = true;
  }
  async function create(e: SubmitEvent) {
    e.preventDefault();
    if (!name || nameError) return;
    creating = true;
    createError = '';
    try {
      const a = await agentsApi.create({ name: name.trim(), description: description.trim(), owner: owner.trim() || undefined });
      toast.success(`Created ${a.name}`);
      createOpen = false;
      await goto(`${base}/agents/${encodeURIComponent(a.agentId)}?tab=tokens`);
    } catch (err) {
      createError = errorMessage(err, 'Could not create the agent.');
    } finally {
      creating = false;
    }
  }

  const cols: Column<Agent>[] = [
    { id: 'name', label: 'Agent', sort: (a) => a.name.toLowerCase() },
    { id: 'status', label: 'Status', sort: (a) => a.status },
    { id: 'owner', label: 'Owner', sort: (a) => a.owner, hideOnMobile: true },
    { id: 'last', label: 'Last used', sort: (a) => a.lastUsedAt ?? '', hideOnMobile: true },
    { id: 'grants', label: 'Grants', sort: (a) => a.grantCount, hideOnMobile: true },
    { id: 'tokens', label: 'Tokens', sort: (a) => a.activeTokenCount, hideOnMobile: true },
    { id: 'act', label: '', align: 'end', width: '56px' }
  ];
  const href = (a: Agent) => `${base}/agents/${encodeURIComponent(a.agentId)}`;
</script>

<PageHeader
  title="Agents"
  description="AI agents use credentials without holding them: Citadel injects secrets into the requests they make, within the hosts, times and limits you grant. Every use is audited."
>
  {#snippet actions()}
    <a class="btn btn-ghost" href="{base}{DOC_LINKS.agentsGuide}"><Icon name="book" size={16} />Learn more</a>
    {#if canCreate}
      <button type="button" class="btn btn-secondary" onclick={() => (addLoginOpen = true)}><Icon name="key" size={16} />Add login</button>
      <button type="button" class="btn btn-primary" onclick={openCreate}><Icon name="plus" size={16} />New agent</button>
    {/if}
  {/snippet}
</PageHeader>

{#if settings?.agentsSuspended}
  <div class="callout callout-danger kill" role="status">
    <Icon name="alert-triangle" size={16} />
    <span class="grow">
      <strong>All agents in this account are suspended.</strong>
      Every agent request is refused{settings.suspendedBy ? ` (switched on by ${settings.suspendedBy}${settings.suspendedAt ? `, ${relTime(settings.suspendedAt)}` : ''})` : ''}.{#if settings.reason}
        Reason: {settings.reason}{/if}
    </span>
    {#if session.can('admin')}<a class="btn btn-secondary btn-sm" href="{base}/admin?tab=settings">Manage</a>{/if}
  </div>
{/if}

{#if loadError}
  <div class="callout callout-danger err" role="alert">
    <Icon name="alert-circle" size={16} /><span>{loadError}</span>
    <button type="button" class="btn btn-ghost btn-sm push" onclick={load}>Retry</button>
  </div>
{/if}

<DataTable caption="Agents" rows={agents} columns={cols} key={(a) => a.agentId} {loading} searchable={(a) => `${a.name} ${a.agentId} ${a.owner} ${a.description}`} searchPlaceholder="Search agents" bind:query>
  {#snippet row(a)}
    <td>
      <a class="row-link strong" href={href(a)}>{a.name}</a>
      <span class="mono subtle sub">{a.agentId}</span>
    </td>
    <td>
      <Badge tone={STATUS_TONE[a.status]}>{STATUS_LABEL[a.status]}</Badge>
    </td>
    <td class="hide-sm">{a.owner}</td>
    <td class="subtle hide-sm">{#if a.lastUsedAt}<span title={fullTime(a.lastUsedAt)}>{relTime(a.lastUsedAt)}</span>{:else}Never{/if}</td>
    <td class="num hide-sm">{a.grantCount}</td>
    <td class="num hide-sm">{a.activeTokenCount}</td>
    <td class="end">
      {#if a.canManage}
        <ActionMenu label="Actions for {a.name}" items={agentMenu(a, load)} />
      {/if}
    </td>
  {/snippet}
  {#snippet empty()}
    <EmptyState icon="bot" title="No agents yet" description="Create an agent for each AI tool or workflow, give it a token, then grant it the credentials it may use.">
      {#if canCreate}<button type="button" class="btn btn-primary btn-sm" onclick={openCreate}><Icon name="plus" size={14} />New agent</button>{/if}
    </EmptyState>
  {/snippet}
</DataTable>

<AddLoginModal bind:open={addLoginOpen} />

<Modal bind:open={createOpen} title="New agent" description="An agent authenticates with its own tokens or workload identity, never with console sessions or access keys." size="sm">
  <form id="agent-form" class="form" onsubmit={create} novalidate>
    {#if createError}<div class="callout callout-danger" role="alert"><Icon name="alert-circle" size={16} /><span>{createError}</span></div>{/if}
    <div class="field">
      <label class="field-label" for="ag-name">Name</label>
      <input id="ag-name" class="input mono" bind:value={name} placeholder="claude-code" autocomplete="off" spellcheck="false" aria-invalid={!!nameError} />
      {#if nameError}<span class="field-error">{nameError}</span>{/if}
    </div>
    <div class="field">
      <label class="field-label" for="ag-desc">Description <span class="subtle">(optional)</span></label>
      <input id="ag-desc" class="input" bind:value={description} placeholder="What the agent does" />
    </div>
    {#if session.can('admin')}
      <div class="field">
        <label class="field-label" for="ag-owner">Owner <span class="subtle">(optional)</span></label>
        <input id="ag-owner" class="input" bind:value={owner} placeholder={session.me?.username ?? ''} autocomplete="off" />
        <span class="field-hint">The person accountable for the agent; they can manage it. Defaults to you.</span>
      </div>
    {/if}
  </form>
  {#snippet footer()}
    <button type="button" class="btn btn-ghost" onclick={() => (createOpen = false)}>Cancel</button>
    <button type="submit" form="agent-form" class="btn btn-primary" disabled={creating || !name || !!nameError}>{creating ? 'Creating…' : 'Create agent'}</button>
  {/snippet}
</Modal>

<style>
  .kill {
    margin-bottom: var(--space-5);
    align-items: center;
  }
  .err {
    margin-bottom: var(--space-4);
    align-items: center;
  }
  .push {
    margin-left: auto;
  }
  .grow {
    flex: 1;
    min-width: 0;
  }
  .sub {
    display: block;
    font-size: 12.5px;
  }
  .form {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
  }
  .form .field + .field {
    margin-top: 0;
  }
  @media (max-width: 720px) {
    .hide-sm {
      display: none;
    }
  }
</style>
