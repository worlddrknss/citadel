<script lang="ts">
  import { onMount } from 'svelte';
  import { base } from '#lib/paths.ts';
  import { api } from '#lib/api.ts';
  import DataTable, { type Column } from '#lib/components/DataTable.svelte';
  import EmptyState from '#lib/components/EmptyState.svelte';
  import Icon from '#lib/components/Icon.svelte';
  import Modal from '#lib/components/Modal.svelte';
  import PageHeader from '#lib/components/PageHeader.svelte';
  import { confirm } from '#lib/stores/confirm.svelte.ts';
  import { session } from '#lib/stores/session.svelte.ts';
  import { toast } from '#lib/stores/toast.svelte.ts';
  import { revealPolicy } from '#lib/stores/revealPolicy.svelte.ts';
  import { param, setParams } from '#lib/url.ts';
  import { secretsApi, type ProjectInfo, type SecretSettings } from './api';
  import { envLabel, envTier, sortEnvs, tierTone } from './lib';

  let projects = $state<ProjectInfo[]>([]);
  let loading = $state(true);
  let loadError = $state('');

  let query = $state(param('q'));
  let sortBy = $state(param('sort', 'project'));
  let sortDir = $state<'asc' | 'desc'>(param('dir') === 'desc' ? 'desc' : 'asc');
  $effect(() => {
    setParams({ q: query, sort: sortBy === 'project' ? null : sortBy, dir: sortDir === 'asc' ? null : sortDir });
  });

  // Create / rename dialog
  let formOpen = $state(false);
  let formMode = $state<'create' | 'rename'>('create');
  let formSlug = $state('');
  let formName = $state('');
  let formBusy = $state(false);
  const slugOk = $derived(/^[A-Za-z0-9_.-]+$/.test(formSlug.trim()));

  const canEdit = $derived(session.can('editor'));
  const isAdmin = $derived(session.can('admin'));

  // Account secrets settings (admin): whether viewers may read values.
  let settingsOpen = $state(false);
  let settings = $state<SecretSettings | null>(null);
  let settingsReveal = $state(false);
  let settingsBusy = $state(false);
  let settingsError = $state('');
  async function openSettings() {
    settingsError = '';
    settingsOpen = true;
    try {
      settings = await secretsApi.settings();
      settingsReveal = settings.viewersCanReveal;
    } catch (e) {
      settingsError = e instanceof Error ? e.message : 'Could not load the settings';
    }
  }
  async function saveSettings(e: SubmitEvent) {
    e.preventDefault();
    settingsBusy = true;
    try {
      settings = await secretsApi.saveSettings({ viewersCanReveal: settingsReveal });
      revealPolicy.set(settings.viewersCanReveal);
      toast.success(settings.viewersCanReveal ? 'Viewers can now reveal values' : 'Viewers can no longer reveal values');
      settingsOpen = false;
    } catch (err) {
      toast.error(err, 'Could not save the settings');
    } finally {
      settingsBusy = false;
    }
  }

  const columns: Column<ProjectInfo>[] = [
    { id: 'project', label: 'Project', sort: (p) => p.name || p.slug },
    { id: 'envs', label: 'Environments' },
    { id: 'secrets', label: 'Secrets', sort: (p) => totalSecrets(p), align: 'end', width: '110px', hideOnMobile: true },
    { id: 'actions', label: '', width: '1%' }
  ];

  function totalSecrets(p: ProjectInfo): number | null {
    if (!p.environmentCounts) return null;
    return Object.values(p.environmentCounts).reduce((a, b) => a + b, 0);
  }

  function projectHref(slug: string) {
    return `${base}/secrets/${encodeURIComponent(slug)}`;
  }

  async function load() {
    loading = true;
    loadError = '';
    try {
      projects = await secretsApi.projects();
    } catch (e) {
      loadError = e instanceof Error ? e.message : 'Could not load projects.';
      toast.error(e, 'Could not load projects');
    } finally {
      loading = false;
    }
  }

  function openCreate() {
    formMode = 'create';
    formSlug = '';
    formName = '';
    formOpen = true;
  }

  function openRename(p: ProjectInfo) {
    formMode = 'rename';
    formSlug = p.slug;
    formName = p.name || p.slug;
    formOpen = true;
  }

  async function submitForm(e: SubmitEvent) {
    e.preventDefault();
    const slug = formSlug.trim();
    const name = formName.trim() || slug;
    if (formMode === 'create' && !slugOk) return;
    formBusy = true;
    try {
      if (formMode === 'create') {
        await api.createProject(slug, name);
        toast.success(`Created project ${slug}`);
      } else {
        await api.renameProject(slug, name);
        toast.success(`Renamed ${slug} to “${name}”`);
      }
      formOpen = false;
      await load();
    } catch (err) {
      toast.error(err, formMode === 'create' ? 'Could not create project' : 'Could not rename project');
    } finally {
      formBusy = false;
    }
  }

  async function deleteProject(p: ProjectInfo) {
    const ok = await confirm({
      title: `Delete project ${p.slug}?`,
      message:
        'This removes the project and its empty environments and folders. It is refused while any secret still exists under it.',
      confirmLabel: 'Delete project',
      danger: true,
      typeToConfirm: p.slug
    });
    if (!ok) return;
    try {
      await api.deleteProject(p.slug);
      toast.success(`Deleted project ${p.slug}`);
      await load();
    } catch (e) {
      toast.error(e, 'Could not delete project');
    }
  }

  onMount(load);
</script>

<svelte:head><title>Secrets · Citadel</title></svelte:head>

<PageHeader
  title="Secrets"
  description="Projects group secrets by environment and folder. Every item stays readable through the AWS Secrets Manager API for External Secrets and SDK clients."
>
  {#snippet actions()}
    {#if isAdmin}
      <button type="button" class="btn btn-secondary" onclick={openSettings}>
        <Icon name="settings" size={16} />Settings
      </button>
    {/if}
    {#if canEdit}
      <button type="button" class="btn btn-primary" onclick={openCreate}>
        <Icon name="plus" size={16} />New project
      </button>
    {/if}
  {/snippet}
</PageHeader>

{#if loadError && !loading && projects.length === 0}
  <div class="callout callout-danger" role="alert">
    <Icon name="alert-circle" size={16} />
    <div class="grow">
      <strong>Couldn't load projects.</strong>
      <span class="muted">{loadError}</span>
    </div>
    <button type="button" class="btn btn-secondary btn-sm" onclick={load}>Try again</button>
  </div>
{:else}
  <DataTable
    rows={projects}
    {columns}
    key={(p) => p.slug}
    {loading}
    searchable={(p) => `${p.slug} ${p.name ?? ''} ${p.environments.join(' ')}`}
    searchPlaceholder="Filter projects or environments"
    bind:query
    bind:sortBy
    bind:sortDir
    caption="Secret projects"
  >
    {#snippet row(p)}
      <td>
        <a class="proj" href={projectHref(p.slug)}>
          <span class="proj-icon" aria-hidden="true"><Icon name="folder" size={16} /></span>
          <span class="proj-text">
            <span class="proj-name">{p.name || p.slug}</span>
            {#if p.name && p.name !== p.slug}<span class="mono subtle small">{p.slug}</span>{/if}
          </span>
        </a>
      </td>
      <td>
        {#if p.environments.length === 0}
          <span class="subtle">No environments</span>
        {:else}
          <span class="envs">
            {#each sortEnvs(p.environments) as env (env)}
              <a
                class="badge badge-{tierTone[envTier(env)]} env-chip"
                href="{projectHref(p.slug)}/{encodeURIComponent(env)}"
              >
                <span class="badge-dot" aria-hidden="true"></span>{envLabel(env)}
                {#if p.environmentCounts?.[env] !== undefined}
                  <span class="num env-count">{p.environmentCounts[env]}</span>
                {/if}
              </a>
            {/each}
          </span>
        {/if}
      </td>
      <td class="end num hide-mobile">{totalSecrets(p) ?? '—'}</td>
      <td class="end">
        <span class="cell-actions">
          {#if canEdit}
            <button type="button" class="btn btn-ghost btn-sm" onclick={() => openRename(p)}>
              <Icon name="edit" size={14} />Rename
            </button>
            <button
              type="button"
              class="btn-icon"
              aria-label="Delete project {p.slug}"
              title="Delete project"
              onclick={() => deleteProject(p)}
            >
              <Icon name="trash" size={14} />
            </button>
          {/if}
          <a class="btn-icon" href={projectHref(p.slug)} aria-label="Open {p.slug}" title="Open">
            <Icon name="chevron-right" size={16} />
          </a>
        </span>
      </td>
    {/snippet}
    {#snippet empty()}
      <EmptyState
        icon="lock"
        title="No projects yet"
        description="Create a project, then add environments such as dev, staging and prod to hold its secrets."
      >
        {#if canEdit}
          <button type="button" class="btn btn-primary" onclick={openCreate}>
            <Icon name="plus" size={16} />New project
          </button>
        {/if}
      </EmptyState>
    {/snippet}
  </DataTable>
{/if}

<Modal
  bind:open={formOpen}
  title={formMode === 'create' ? 'New project' : `Rename ${formSlug}`}
  description={formMode === 'create'
    ? 'The slug is part of every secret name (project/env/folder/KEY) and cannot change later.'
    : 'Changes the display name only. Secret names keep the slug.'}
  size="sm"
>
  <form id="project-form" class="form" onsubmit={submitForm}>
    {#if formMode === 'create'}
      <label class="field">
        <span class="field-label">Slug</span>
        <!-- svelte-ignore a11y_autofocus -->
        <input
          class="input mono"
          bind:value={formSlug}
          placeholder="payments-api"
          autocomplete="off"
          spellcheck="false"
          autofocus
          aria-invalid={formSlug.trim() !== '' && !slugOk}
          aria-describedby="slug-hint"
        />
        <span id="slug-hint" class={formSlug.trim() && !slugOk ? 'field-error' : 'field-hint'}>
          Letters, digits, dots, dashes and underscores.
        </span>
      </label>
    {/if}
    <label class="field">
      <span class="field-label">Display name</span>
      <input class="input" bind:value={formName} placeholder={formSlug || 'Payments API'} autocomplete="off" />
    </label>
  </form>
  {#snippet footer()}
    <button type="button" class="btn btn-secondary" onclick={() => (formOpen = false)}>Cancel</button>
    <button
      type="submit"
      form="project-form"
      class="btn btn-primary"
      disabled={formBusy || (formMode === 'create' && !slugOk)}
    >
      {formMode === 'create' ? 'Create project' : 'Save name'}
    </button>
  {/snippet}
</Modal>

<Modal bind:open={settingsOpen} title="Secrets settings" description="Applies to every project in this account." size="sm">
  <form id="secrets-settings-form" class="form" onsubmit={saveSettings}>
    {#if settingsError}
      <div class="callout callout-danger" role="alert"><Icon name="alert-circle" size={16} /><span>{settingsError}</span></div>
    {:else if !settings}
      <span class="skeleton" style:width="100%" style:height="40px"></span>
    {:else}
      <label class="check-row">
        <input type="checkbox" bind:checked={settingsReveal} />
        <span>
          <span class="field-label">Viewers can reveal values</span>
          <span class="field-hint block">
            When off, viewers see names, metadata and fingerprints only: revealing, version values and .env export need the
            editor role. Every reveal is logged either way.
          </span>
        </span>
      </label>
      {#if settings.updatedBy}
        <p class="subtle small">Last changed by {settings.updatedBy}{settings.updatedAt ? ` · ${new Date(settings.updatedAt).toLocaleString()}` : ''}</p>
      {/if}
    {/if}
  </form>
  {#snippet footer()}
    <button type="button" class="btn btn-secondary" onclick={() => (settingsOpen = false)}>Cancel</button>
    <button type="submit" form="secrets-settings-form" class="btn btn-primary" disabled={settingsBusy || !settings}>Save settings</button>
  {/snippet}
</Modal>

<style>
  .check-row {
    display: flex;
    gap: 10px;
    align-items: flex-start;
  }
  .check-row input {
    margin-top: 3px;
  }
  .grow {
    flex: 1;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .proj {
    display: inline-flex;
    align-items: center;
    gap: var(--space-3);
    color: var(--text);
    font-weight: 500;
  }
  .proj:hover {
    text-decoration: none;
  }
  .proj:hover .proj-name {
    color: var(--accent-text);
    text-decoration: underline;
  }
  .proj-icon {
    display: inline-grid;
    place-items: center;
    width: 28px;
    height: 28px;
    border-radius: var(--radius-md);
    background: var(--surface-sunken);
    color: var(--text-subtle);
    flex-shrink: 0;
  }
  .proj-text {
    display: flex;
    flex-direction: column;
    min-width: 0;
  }
  .envs {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
  }
  .env-chip:hover {
    text-decoration: none;
    filter: brightness(0.97);
  }
  .env-count {
    opacity: 0.8;
  }
  .form {
    display: flex;
    flex-direction: column;
  }
  @media (max-width: 720px) {
    .hide-mobile {
      display: none;
    }
  }
</style>
