<script lang="ts">
  import { onMount } from 'svelte';
  import PageHeader from '#lib/components/PageHeader.svelte';
  import Tabs from '#lib/components/Tabs.svelte';
  import DataTable, { type Column } from '#lib/components/DataTable.svelte';
  import EmptyState from '#lib/components/EmptyState.svelte';
  import Badge from '#lib/components/Badge.svelte';
  import Icon from '#lib/components/Icon.svelte';
  import { api, errorMessage, type OIDCProvider, type Role } from '#lib/api.ts';
  import { session } from '#lib/stores/session.svelte.ts';
  import { toast } from '#lib/stores/toast.svelte.ts';
  import { confirm } from '#lib/stores/confirm.svelte.ts';
  import { param, setParams } from '#lib/url.ts';
  import RoleEditor from './RoleEditor.svelte';
  import RoleDrawer from './RoleDrawer.svelte';
  import ProviderModal from './ProviderModal.svelte';
  import { sessionLabel, fmtDate } from './trust';

  let providers = $state<OIDCProvider[]>([]);
  let roles = $state<Role[]>([]);
  let loading = $state(true);
  let loadError = $state('');

  async function load() {
    loading = true;
    loadError = '';
    try {
      const [p, r] = await Promise.all([api.oidcProviders(), api.roles()]);
      providers = p.providers ?? [];
      roles = r.roles ?? [];
    } catch (e) {
      loadError = errorMessage(e, 'Could not load identity federation settings.');
    } finally {
      loading = false;
    }
  }
  onMount(load);

  const canEdit = $derived(session.can('admin'));
  const tab = $derived(param('tab', 'roles'));
  const q = $derived(param('q'));
  const selectedName = $derived(param('role'));
  const selected = $derived(roles.find((r) => r.roleName === selectedName) ?? null);

  let tabValue = $state('roles');
  let query = $state('');
  $effect(() => {
    tabValue = tab;
  });
  $effect(() => {
    query = q;
  });
  $effect(() => {
    if (query !== q) setParams({ q: query });
  });

  let drawerOpen = $state(false);
  $effect(() => {
    drawerOpen = !!selected;
  });

  const rolesUsing = (p: OIDCProvider) => roles.filter((r) => r.trust.type === 'oidc' && r.trust.providerUrl?.replace(/\/+$/, '') === p.url.replace(/\/+$/, ''));

  // Dialogs
  let editorOpen = $state(false);
  let editing = $state<Role | null>(null);
  let providerOpen = $state(false);
  let editingProvider = $state<OIDCProvider | null>(null);

  function createRole() {
    editing = null;
    editorOpen = true;
  }
  function editRole(r: Role) {
    editing = r;
    editorOpen = true;
  }
  function addProvider() {
    editingProvider = null;
    providerOpen = true;
  }
  function editProvider(p: OIDCProvider) {
    editingProvider = p;
    providerOpen = true;
  }

  async function deleteRole(r: Role) {
    const ok = await confirm({
      title: `Delete ${r.roleName}?`,
      message: 'Workloads that assume this role lose access when their current credentials expire. This cannot be undone.',
      confirmLabel: 'Delete role',
      danger: true,
      typeToConfirm: r.roleName
    });
    if (!ok) return;
    try {
      await api.deleteRole(r.roleName);
      toast.success(`Deleted ${r.roleName}`);
      if (selectedName === r.roleName) setParams({ role: null });
      await load();
    } catch (e) {
      toast.error(e, 'Could not delete the role');
    }
  }

  async function deleteProvider(p: OIDCProvider) {
    const using = rolesUsing(p);
    const ok = await confirm({
      title: 'Delete identity provider?',
      message: using.length
        ? `${using.length} role${using.length > 1 ? 's' : ''} (${using.map((r) => r.roleName).join(', ')}) trust ${p.url}. They will stop accepting its tokens.`
        : `Tokens from ${p.url} will no longer be accepted.`,
      confirmLabel: 'Delete provider',
      danger: true,
      typeToConfirm: using.length ? new URL(p.url).host : undefined
    });
    if (!ok) return;
    try {
      await api.deleteOIDCProvider(p.providerArn);
      toast.success('Identity provider deleted');
      await load();
    } catch (e) {
      toast.error(e, 'Could not delete the provider');
    }
  }

  const roleCols: Column<Role>[] = [
    { id: 'name', label: 'Role', sort: (r) => r.roleName },
    { id: 'trust', label: 'Trusted principal', sort: (r) => r.trust.type },
    { id: 'cond', label: 'Conditions', hideOnMobile: true },
    { id: 'max', label: 'Max session', sort: (r) => r.maxSessionSeconds, hideOnMobile: true },
    { id: 'updated', label: 'Updated', sort: (r) => r.updatedAt, hideOnMobile: true },
    { id: 'act', label: '', align: 'end', width: '96px' }
  ];
  const provCols: Column<OIDCProvider>[] = [
    { id: 'url', label: 'Issuer', sort: (p) => p.url },
    { id: 'aud', label: 'Audiences' },
    { id: 'roles', label: 'Roles', sort: (p) => rolesUsing(p).length, hideOnMobile: true },
    { id: 'created', label: 'Added', sort: (p) => p.createdAt, hideOnMobile: true },
    { id: 'act', label: '', align: 'end', width: '96px' }
  ];
</script>

<PageHeader
  title="Identity federation"
  description="OIDC identity providers and roles for Citadel STS. Workloads trade a token they already have for short-lived credentials, so they need no static access keys."
>
  {#snippet actions()}
    {#if canEdit}
      <button type="button" class="btn btn-secondary" onclick={addProvider}><Icon name="plus" size={16} />Add provider</button>
      <button type="button" class="btn btn-primary" onclick={createRole}><Icon name="plus" size={16} />Create role</button>
    {/if}
  {/snippet}
</PageHeader>

<div class="tabs-row">
  <Tabs
    label="Identity federation sections"
    tabs={[
      { id: 'roles', label: 'Roles', count: loading ? undefined : roles.length },
      { id: 'providers', label: 'Identity providers', count: loading ? undefined : providers.length }
    ]}
    bind:active={tabValue}
    onchange={(t) => setParams({ tab: t === 'roles' ? null : t, q: null })}
  />
</div>

{#if loadError}
  <div class="callout callout-danger err" role="alert">
    <Icon name="alert-circle" size={16} /><span>{loadError}</span>
    <button type="button" class="btn btn-ghost btn-sm push" onclick={load}>Retry</button>
  </div>
{/if}

{#if tab === 'providers'}
  <DataTable
    caption="Identity providers"
    rows={providers}
    columns={provCols}
    key={(p) => p.providerArn}
    {loading}
    searchable={(p) => `${p.url} ${p.clientIds.join(' ')}`}
    searchPlaceholder="Search issuers and audiences"
    bind:query
  >
    {#snippet row(p)}
      {@const n = rolesUsing(p).length}
      <td><span class="mono strong">{p.url}</span><span class="mono subtle sub">{p.providerArn}</span></td>
      <td><span class="chips">{#each p.clientIds as c (c)}<span class="badge mono">{c}</span>{/each}</span></td>
      <td class="hide-sm">
        {#if n}
          <button type="button" class="row-link" onclick={() => setParams({ tab: null, q: p.url })}>{n} role{n > 1 ? 's' : ''}</button>
        {:else}<span class="subtle">None</span>{/if}
      </td>
      <td class="subtle hide-sm">{fmtDate(p.createdAt)}</td>
      <td class="end">
        {#if canEdit}
          <span class="cell-actions">
            <button type="button" class="btn-icon" aria-label="Edit {p.url}" title="Edit" onclick={() => editProvider(p)}><Icon name="edit" size={14} /></button>
            <button type="button" class="btn-icon danger" aria-label="Delete {p.url}" title="Delete" onclick={() => deleteProvider(p)}><Icon name="trash" size={14} /></button>
          </span>
        {/if}
      </td>
    {/snippet}
    {#snippet empty()}
      <EmptyState icon="shield" title="No identity providers" description="Register the OIDC issuer of a Kubernetes cluster, CI system or IdP, then create roles that trust it.">
        {#if canEdit}<button type="button" class="btn btn-primary btn-sm" onclick={addProvider}><Icon name="plus" size={14} />Add provider</button>{/if}
      </EmptyState>
    {/snippet}
  </DataTable>
{:else}
  <DataTable
    caption="Roles"
    rows={roles}
    columns={roleCols}
    key={(r) => r.roleName}
    {loading}
    searchable={(r) => `${r.roleName} ${r.description} ${r.trust.providerUrl ?? ''} ${(r.trust.subjects ?? []).join(' ')} ${(r.trust.principals ?? []).join(' ')}`}
    searchPlaceholder="Search roles, issuers, subjects"
    bind:query
  >
    {#snippet row(r)}
      <td>
        <button type="button" class="row-link mono" onclick={() => setParams({ role: r.roleName }, { push: true })}>{r.roleName}</button>
        {#if r.description}<span class="muted sub">{r.description}</span>{/if}
      </td>
      <td>
        {#if r.trust.type === 'oidc'}
          <Badge tone="info" dot={false}>OIDC</Badge> <span class="mono small">{r.trust.providerUrl?.replace(/^https:\/\//, '')}</span>
        {:else}
          <Badge dot={false}>Accounts</Badge>
        {/if}
      </td>
      <td class="hide-sm">
        <span class="chips">
          {#each (r.trust.type === 'oidc' ? r.trust.subjects : r.trust.principals)?.slice(0, 2) ?? [] as s (s)}<span class="badge mono">{s}</span>{/each}
          {#if ((r.trust.type === 'oidc' ? r.trust.subjects : r.trust.principals)?.length ?? 0) > 2}
            <span class="subtle small">+{((r.trust.type === 'oidc' ? r.trust.subjects : r.trust.principals)?.length ?? 0) - 2}</span>
          {/if}
        </span>
      </td>
      <td class="num hide-sm">{sessionLabel(r.maxSessionSeconds)}</td>
      <td class="subtle hide-sm">{fmtDate(r.updatedAt)}</td>
      <td class="end">
        {#if canEdit}
          <span class="cell-actions">
            <button type="button" class="btn-icon" aria-label="Edit {r.roleName}" title="Edit" onclick={() => editRole(r)}><Icon name="edit" size={14} /></button>
            <button type="button" class="btn-icon danger" aria-label="Delete {r.roleName}" title="Delete" onclick={() => deleteRole(r)}><Icon name="trash" size={14} /></button>
          </span>
        {/if}
      </td>
    {/snippet}
    {#snippet empty()}
      <EmptyState icon="users" title="No roles yet" description="A role says which tokens may be exchanged for credentials, and for how long.">
        {#if canEdit}<button type="button" class="btn btn-primary btn-sm" onclick={createRole}><Icon name="plus" size={14} />Create role</button>{/if}
      </EmptyState>
    {/snippet}
  </DataTable>
{/if}

<RoleDrawer
  bind:open={drawerOpen}
  role={selected}
  {canEdit}
  onclose={() => setParams({ role: null })}
  onedit={editRole}
  ondelete={deleteRole}
/>
<RoleEditor bind:open={editorOpen} role={editing} {providers} onsaved={(name) => load().then(() => setParams({ role: name, tab: null }))} />
<ProviderModal bind:open={providerOpen} provider={editingProvider} onsaved={load} />

<style>
  .tabs-row {
    margin: calc(-1 * var(--space-2)) 0 var(--space-5);
  }
  .err {
    margin-bottom: var(--space-4);
    align-items: center;
  }
  .push {
    margin-left: auto;
  }
  .strong {
    font-weight: 500;
  }
  .sub {
    display: block;
    font-size: 12.5px;
    max-width: 48ch;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .chips {
    display: inline-flex;
    flex-wrap: wrap;
    gap: 4px;
    align-items: center;
  }
  .chips .badge {
    font-size: 12.5px;
  }
  .danger:hover:not(:disabled) {
    color: var(--danger);
    background: var(--danger-soft);
  }
  @media (max-width: 720px) {
    .hide-sm {
      display: none;
    }
  }
</style>
