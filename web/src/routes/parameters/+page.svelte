<script lang="ts">
  import { onMount, untrack } from 'svelte';
  import { base } from '$app/paths';
  import { api, errorMessage, type KMSKey } from '$lib/api';
  import { param as urlParam, setParams } from '$lib/url';
  import { session } from '$lib/stores/session.svelte';
  import { toast } from '$lib/stores/toast.svelte';
  import { confirm } from '$lib/stores/confirm.svelte';
  import PageHeader from '$lib/components/PageHeader.svelte';
  import DataTable, { type Column } from '$lib/components/DataTable.svelte';
  import EmptyState from '$lib/components/EmptyState.svelte';
  import Badge from '$lib/components/Badge.svelte';
  import Icon from '$lib/components/Icon.svelte';
  import SecretValue from '$lib/components/SecretValue.svelte';
  import ActionMenu, { type MenuItem } from '../kms/ActionMenu.svelte';
  import InlineValue from './InlineValue.svelte';
  import ParamPanel from './ParamPanel.svelte';
  import ParamForm from './ParamForm.svelte';
  import { TYPES, TYPE_TONE, segments, prefixOf, leaf, fmtRelative, fmtDateTime, type Param } from './api';

  const canEdit = $derived(session.can('editor'));

  let all = $state<Param[]>([]);
  let loading = $state(true);
  let loadError = $state('');
  let kmsKeys = $state<KMSKey[]>([]);

  // ---- URL state ------------------------------------------------------------
  const path = $derived(urlParam('path', '/'));
  const prefix = $derived(prefixOf(path));
  const crumbs = $derived(segments(path));
  const typeFilter = $derived(urlParam('type'));
  const selectedName = $derived(urlParam('p'));
  let query = $state(urlParam('q'));
  let tab = $state(urlParam('tab', 'overview'));

  $effect(() => {
    setParams({ q: query.trim() || null });
  });
  $effect(() => {
    if (selectedName) setParams({ tab: tab === 'overview' ? null : tab });
  });

  const hrefFor = (p: string) => {
    const s = segments(p);
    return s.length ? `${base}/parameters?path=${encodeURIComponent('/' + s.join('/'))}` : `${base}/parameters`;
  };

  function openParam(name: string, nextTab = 'overview') {
    tab = nextTab;
    setParams({ p: name, tab: nextTab === 'overview' ? null : nextTab });
  }
  function closeParam() {
    const n = selectedName;
    setParams({ p: null, tab: null });
    requestAnimationFrame(() => document.querySelector<HTMLElement>(`[data-param-open="${CSS.escape(n)}"]`)?.focus());
  }

  // ---- Data -----------------------------------------------------------------
  async function load() {
    loadError = '';
    try {
      all = (await api.parameters()).parameters as Param[];
    } catch (e) {
      loadError = errorMessage(e);
    } finally {
      loading = false;
    }
  }
  async function loadKeys() {
    try {
      kmsKeys = (await api.kmsKeys()).keys;
    } catch {
      kmsKeys = [];
    }
  }
  onMount(() => {
    load();
    loadKeys();
  });

  const selected = $derived(all.find((p) => p.name === selectedName));
  // Show a parameter's own folder when it's opened from a link (once per
  // selection, so browsing other folders with the panel open still works).
  const selectedLoaded = $derived(selected?.name ?? '');
  $effect(() => {
    const n = selectedLoaded;
    if (!n) return;
    untrack(() => {
      if (query.trim() || typeFilter || n.startsWith(prefix)) return;
      const i = n.lastIndexOf('/');
      setParams({ path: i > 0 ? n.slice(0, i) : null });
    });
  });

  type Row =
    | { kind: 'folder'; id: string; name: string; count: number }
    | { kind: 'param'; id: string; p: Param; rel: string };

  const under = $derived(all.filter((p) => p.name.startsWith(prefix) || (prefix === '/' && !p.name.startsWith('/'))));
  const relName = (p: Param) => (p.name.startsWith(prefix) ? p.name.slice(prefix.length) : p.name);

  const typeCounts = $derived(
    Object.fromEntries([['', under.length], ...TYPES.map((t) => [t, under.filter((p) => p.type === t).length])]) as Record<string, number>
  );

  const rows = $derived.by((): Row[] => {
    const searching = query.trim() !== '';
    const ofType = under.filter((p) => !typeFilter || p.type === typeFilter);
    if (searching || typeFilter) {
      // Search and type filters look through every level below this folder.
      return ofType.map((p) => ({ kind: 'param', id: p.name, p, rel: relName(p) }));
    }
    const folders = new Map<string, number>();
    const out: Row[] = [];
    for (const p of ofType) {
      const rel = relName(p);
      const slash = rel.indexOf('/');
      if (slash > 0) {
        const f = rel.slice(0, slash);
        folders.set(f, (folders.get(f) ?? 0) + 1);
      } else {
        out.push({ kind: 'param', id: p.name, p, rel });
      }
    }
    const folderRows: Row[] = [...folders.entries()].map(([name, count]) => ({ kind: 'folder', id: `${prefix}${name}/`, name, count }));
    return [...folderRows, ...out];
  });
  const folderCount = $derived(rows.filter((r) => r.kind === 'folder').length);
  const paramCount = $derived(rows.length - folderCount);

  // Folders always sort first.
  const sortName = (r: Row) => (r.kind === 'folder' ? `0${r.name}` : `1${r.rel}`);
  const columns: Column<Row>[] = [
    { id: 'name', label: 'Name', sort: sortName },
    { id: 'type', label: 'Type', sort: (r) => (r.kind === 'folder' ? '' : r.p.type) },
    { id: 'value', label: 'Value' },
    { id: 'version', label: 'Version', sort: (r) => (r.kind === 'folder' ? -1 : r.p.version), hideOnMobile: true },
    { id: 'modified', label: 'Last modified', sort: (r) => (r.kind === 'folder' ? null : new Date(r.p.lastModified)), hideOnMobile: true },
    { id: 'actions', label: '', width: '48px', align: 'end' }
  ];
  let sortBy = $state('name');
  let sortDir = $state<'asc' | 'desc'>('asc');

  // ---- Actions --------------------------------------------------------------
  let formOpen = $state(false);
  let editing = $state<Param | null>(null);

  function startCreate() {
    editing = null;
    formOpen = true;
  }
  function startEdit(p: Param) {
    editing = p;
    formOpen = true;
  }
  async function saved(name: string) {
    await load();
    openParam(name);
  }

  async function remove(p: Param) {
    const ok = await confirm({
      title: `Delete ${p.name}?`,
      message: `The parameter and all ${p.version} version${p.version === 1 ? '' : 's'} of its history are deleted permanently. Anything that reads it will start failing.`,
      confirmLabel: 'Delete parameter',
      danger: true,
      typeToConfirm: leaf(p.name)
    });
    if (!ok) return;
    try {
      await api.deleteParameter(p.name);
      toast.success(`Deleted ${p.name}`);
      if (selectedName === p.name) setParams({ p: null, tab: null });
      await load();
    } catch (e) {
      toast.error(e);
    }
  }

  async function copy(text: string, what: string) {
    try {
      await navigator.clipboard.writeText(text);
      toast.success(`Copied ${what}`);
    } catch (e) {
      toast.error(e, 'Copy failed');
    }
  }

  function rowMenu(p: Param): MenuItem[] {
    const items: MenuItem[] = [
      { label: 'View details', icon: 'eye', onselect: () => openParam(p.name) },
      { label: 'Version history', icon: 'history', onselect: () => openParam(p.name, 'history') },
      { label: 'Copy name', icon: 'copy', onselect: () => copy(p.name, 'name') }
    ];
    if (canEdit) {
      items.push({ label: 'Edit', icon: 'edit', onselect: () => startEdit(p) });
      items.push({ label: 'Delete', icon: 'trash', danger: true, onselect: () => remove(p) });
    }
    return items;
  }
</script>

<svelte:head><title>Parameters · Citadel</title></svelte:head>

<PageHeader
  title="Parameters"
  description="Hierarchical configuration and secrets{session.me ? ` for ${session.me.accountId}` : ''}. Compatible with the AWS Systems Manager Parameter Store API."
>
  {#snippet actions()}
    {#if canEdit}
      <button type="button" class="btn btn-primary" onclick={startCreate}><Icon name="plus" size={16} />Create parameter</button>
    {/if}
  {/snippet}
</PageHeader>

<div class="layout">
  <div class="main-col">
    <div class="pathbar">
      <span class="crumb-box">
        <Icon name="folder" size={14} />
        <nav aria-label="Folder">
          <ol class="crumbs mono">
            <li>
              {#if crumbs.length}<a href={hrefFor('/')}>/</a>{:else}<span aria-current="page">/</span>{/if}
            </li>
            {#each crumbs as seg, i (i)}
              <li aria-hidden="true" class="sep">›</li>
              <li>
                {#if i < crumbs.length - 1}
                  <a href={hrefFor(crumbs.slice(0, i + 1).join('/'))}>{seg}</a>
                {:else}
                  <span aria-current="page">{seg}</span>
                {/if}
              </li>
            {/each}
          </ol>
        </nav>
      </span>
      {#if crumbs.length}
        <a class="btn btn-ghost btn-sm" href={hrefFor(crumbs.slice(0, -1).join('/'))}><Icon name="arrow-up" size={14} />Up one level</a>
      {/if}
    </div>

    {#if loadError}
      <div class="callout callout-danger" role="alert">
        <Icon name="alert-circle" size={16} />
        <span class="grow">Couldn't load parameters. {loadError}</span>
        <button type="button" class="btn btn-ghost btn-sm" onclick={() => { loading = true; load(); }}>Retry</button>
      </div>
    {/if}

    <DataTable
      {rows}
      {columns}
      key={(r) => r.id}
      {loading}
      caption="Parameters in {prefix}"
      searchable={(r) => (r.kind === 'folder' ? r.name : `${r.p.name} ${r.p.description}`)}
      searchPlaceholder="Search this folder and below"
      bind:query
      bind:sortBy
      bind:sortDir
      selected={selectedName ? [selectedName] : []}
    >
      {#snippet toolbar()}
        <div class="seg" role="group" aria-label="Type filter">
          <button type="button" aria-pressed={!typeFilter} onclick={() => setParams({ type: null })}>All<span class="count">{typeCounts[''] ?? 0}</span></button>
          {#each TYPES as t (t)}
            <button type="button" aria-pressed={typeFilter === t} onclick={() => setParams({ type: t })}>{t}<span class="count">{typeCounts[t] ?? 0}</span></button>
          {/each}
        </div>
      {/snippet}

      {#snippet row(r)}
        {#if r.kind === 'folder'}
          <td colspan="5">
            <a class="folder" href={hrefFor(prefix + r.name)}>
              <Icon name="folder" size={16} /><span class="mono">{r.name}/</span>
              <span class="subtle small">{r.count} parameter{r.count === 1 ? '' : 's'}</span>
            </a>
          </td>
          <td class="end"></td>
        {:else}
          {@const p = r.p}
          <td>
            <button type="button" class="row-link mono name" data-param-open={p.name} onclick={() => openParam(p.name)}>{r.rel}</button>
            {#if p.description}<span class="subtle desc">{p.description}</span>{/if}
          </td>
          <td>
            <Badge tone={TYPE_TONE[p.type]} dot={false}>{#if p.type === 'SecureString'}<Icon name="lock" size={12} />{/if}{p.type}</Badge>
          </td>
          <td class="value">
            {#key `${p.name}:${p.version}`}
              {#if p.type === 'SecureString'}
                <SecretValue load={async () => (await api.revealParameter(p.name)).value} />
              {:else}
                <InlineValue auto list={p.type === 'StringList'} initial={p.value} load={async () => (await api.revealParameter(p.name)).value} />
              {/if}
            {/key}
          </td>
          <td class="hide-sm"><span class="mono subtle">v{p.version}</span></td>
          <td class="subtle hide-sm nowrap" title={fmtDateTime(p.lastModified)}>{fmtRelative(p.lastModified)}</td>
          <td class="end"><ActionMenu label="More actions for {p.name}" items={rowMenu(p)} /></td>
        {/if}
      {/snippet}

      {#snippet empty()}
        {#if all.length === 0}
          <EmptyState icon="sliders" title="No parameters yet" description="Store configuration as String or StringList, and secrets as SecureString encrypted with KMS.">
            {#if canEdit}<button type="button" class="btn btn-primary btn-sm" onclick={startCreate}><Icon name="plus" size={14} />Create parameter</button>{/if}
          </EmptyState>
        {:else}
          <EmptyState icon="folder" title={typeFilter ? `No ${typeFilter} parameters in ${prefix}` : `Nothing in ${prefix}`} description="Create a parameter here, or go back up a level.">
            {#if typeFilter}<button type="button" class="btn btn-secondary btn-sm" onclick={() => setParams({ type: null })}>Show all types</button>{/if}
            {#if canEdit}<button type="button" class="btn btn-primary btn-sm" onclick={startCreate}><Icon name="plus" size={14} />Create parameter</button>{/if}
          </EmptyState>
        {/if}
      {/snippet}
    </DataTable>

    {#if !loading && rows.length > 0}
      <div class="table-foot">
        <span>
          {paramCount} parameter{paramCount === 1 ? '' : 's'}{folderCount ? ` and ${folderCount} folder${folderCount === 1 ? '' : 's'}` : ''}
          in <span class="mono">{prefix}</span>{query.trim() || typeFilter ? ' and below' : ''}
        </span>
        <span class="note"><Icon name="shield-check" size={14} />SecureString values hide after 30 s and every reveal is logged</span>
      </div>
    {/if}
  </div>

  {#if selected}
    <ParamPanel
      param={selected}
      {kmsKeys}
      bind:tab
      {canEdit}
      onclose={closeParam}
      onedit={() => startEdit(selected)}
      ondelete={() => remove(selected)}
    />
  {:else if selectedName && !loading && !loadError}
    <aside class="missing card" aria-live="polite">
      <EmptyState icon="alert-circle" title="Parameter not found" description="{selectedName} doesn't exist or was deleted.">
        <button type="button" class="btn btn-secondary btn-sm" onclick={() => setParams({ p: null, tab: null })}>Close</button>
      </EmptyState>
    </aside>
  {/if}
</div>

<ParamForm bind:open={formOpen} {editing} {prefix} {kmsKeys} onsaved={saved} />

<style>
  .layout {
    display: flex;
    flex-wrap: wrap;
    align-items: flex-start;
    gap: var(--space-5);
  }
  .main-col {
    flex: 999 1 560px;
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
  }
  .grow {
    flex: 1;
  }
  .pathbar {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--space-2);
  }
  .crumb-box {
    display: inline-flex;
    align-items: center;
    gap: var(--space-2);
    min-height: var(--ctl-h);
    max-width: 100%;
    padding: 0 10px;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: var(--surface-hover);
    color: var(--text-subtle);
  }
  .crumbs {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 4px;
    margin: 0;
    padding: 0;
    list-style: none;
    font-size: var(--text-sm);
  }
  .crumbs a {
    color: var(--text-muted);
  }
  .crumbs [aria-current] {
    color: var(--text);
  }
  .sep {
    color: var(--text-subtle);
  }
  .folder {
    display: inline-flex;
    align-items: center;
    gap: var(--space-2);
    color: var(--text);
  }
  .folder :global(svg) {
    color: var(--text-subtle);
  }
  .name {
    font-weight: 500;
    overflow-wrap: anywhere;
  }
  .desc {
    display: block;
    max-width: 320px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    font-size: var(--text-xs);
  }
  .value {
    max-width: 380px;
  }
  @media (max-width: 720px) {
    .hide-sm {
      display: none;
    }
  }
  .table-foot {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: var(--space-2);
    padding: 0 var(--space-1);
    color: var(--text-subtle);
    font-size: var(--text-sm);
  }
  .note {
    display: inline-flex;
    align-items: center;
    gap: 6px;
  }
  .missing {
    flex: 1 1 400px;
    max-width: 480px;
    padding: var(--space-8) var(--space-4);
  }
  /* Segmented control (DesignSystem "seg"). */
  .seg {
    display: inline-flex;
    flex-wrap: wrap;
    gap: 2px;
    padding: 3px;
    border-radius: var(--radius-md);
    background: var(--surface-pressed);
  }
  .seg button {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    height: 28px;
    padding: 0 10px;
    border: 0;
    border-radius: var(--radius-sm);
    background: transparent;
    color: var(--text-muted);
    font: 500 var(--text-sm) / 1 var(--font-sans);
    white-space: nowrap;
    cursor: pointer;
  }
  .seg button[aria-pressed='true'] {
    background: var(--surface);
    color: var(--text);
    box-shadow: var(--shadow-xs);
  }
  .count {
    padding: 0 6px;
    border-radius: 999px;
    background: var(--surface-pressed);
    color: var(--text-muted);
    font: 500 var(--text-xs) / 16px var(--font-sans);
    font-variant-numeric: tabular-nums;
  }
  .seg button[aria-pressed='true'] .count {
    background: var(--surface-hover);
  }
</style>
