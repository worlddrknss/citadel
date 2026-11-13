<script lang="ts">
  import { untrack } from 'svelte';
  import { goto } from '$app/navigation';
  import { base } from '#lib/paths.ts';
  import { page } from '$app/state';
  import { api } from '#lib/api.ts';
  import DataTable, { type Column } from '#lib/components/DataTable.svelte';
  import EmptyState from '#lib/components/EmptyState.svelte';
  import Icon from '#lib/components/Icon.svelte';
  import Modal from '#lib/components/Modal.svelte';
  import PageHeader from '#lib/components/PageHeader.svelte';
  import { confirm } from '#lib/stores/confirm.svelte.ts';
  import { session } from '#lib/stores/session.svelte.ts';
  import { toast } from '#lib/stores/toast.svelte.ts';
  import { defaultPolicy, secretsApi, type EnvPolicy, type ProjectInfo } from '../api';
  import { envLabel, envTier, sortEnvs, tierTone, type Tier } from '../lib';

  const project = $derived(page.params.project ?? '');

  let info = $state<ProjectInfo | null>(null);
  let notFound = $state(false);
  let loading = $state(true);
  let loadError = $state('');
  let policies = $state<Record<string, EnvPolicy>>({});

  const canEdit = $derived(session.can('editor'));
  const isAdmin = $derived(session.can('admin'));
  const envs = $derived(sortEnvs(info?.environments ?? []));
  const projectHref = $derived(`${base}/secrets/${encodeURIComponent(project)}`);

  interface EnvRow {
    slug: string;
    tier: Tier;
    count?: number;
    policy?: EnvPolicy;
  }
  const rows = $derived<EnvRow[]>(
    envs.map((slug) => ({
      slug,
      tier: envTier(slug, policies[slug]?.tier),
      count: info?.environmentCounts?.[slug],
      policy: policies[slug]
    }))
  );

  const columns: Column<EnvRow>[] = [
    { id: 'env', label: 'Environment' },
    { id: 'tier', label: 'Tier', hideOnMobile: true },
    { id: 'policy', label: 'Changes' },
    { id: 'count', label: 'Secrets', align: 'end', width: '100px', hideOnMobile: true },
    { id: 'actions', label: '', width: '1%' }
  ];

  async function load() {
    loading = true;
    loadError = '';
    try {
      const all = await secretsApi.projects();
      info = all.find((p) => p.slug === project) ?? null;
      notFound = !info;
      if (info) {
        try {
          policies = await secretsApi.envPolicies(project);
        } catch {
          policies = {};
        }
      }
    } catch (e) {
      loadError = e instanceof Error ? e.message : 'Could not load the project.';
      toast.error(e, 'Could not load the project');
    } finally {
      loading = false;
    }
  }

  $effect(() => {
    void project;
    untrack(load);
  });

  // ---- Name dialog (create env / rename env / rename project) -------------
  type NameMode = 'create-env' | 'rename-env' | 'rename-project';
  let nameOpen = $state(false);
  let nameMode = $state<NameMode>('create-env');
  let nameSlug = $state('');
  let nameValue = $state('');
  let nameBusy = $state(false);
  const slugOk = $derived(/^[A-Za-z0-9_.-]+$/.test(nameSlug.trim()));

  function openName(mode: NameMode, slug = '', value = '') {
    nameMode = mode;
    nameSlug = slug;
    nameValue = value;
    nameOpen = true;
  }

  const nameTitle = $derived(
    nameMode === 'create-env'
      ? 'New environment'
      : nameMode === 'rename-env'
        ? `Rename ${nameSlug}`
        : `Rename ${project}`
  );

  async function submitName(e: SubmitEvent) {
    e.preventDefault();
    if (nameMode === 'create-env' && !slugOk) return;
    nameBusy = true;
    const slug = nameSlug.trim();
    const value = nameValue.trim() || slug;
    try {
      if (nameMode === 'create-env') {
        await api.createEnvironment(project, slug, value);
        toast.success(`Created environment ${slug}`);
      } else if (nameMode === 'rename-env') {
        await api.renameEnvironment(project, slug, value);
        toast.success(`Renamed environment ${slug}`);
      } else {
        await api.renameProject(project, nameValue.trim() || project);
        toast.success(`Renamed project ${project}`);
      }
      nameOpen = false;
      await load();
    } catch (err) {
      toast.error(err, 'Could not save');
    } finally {
      nameBusy = false;
    }
  }

  // ---- Policy dialog --------------------------------------------------------
  let policyOpen = $state(false);
  let policyEnv = $state('');
  let policyRequire = $state(false);
  let policyMin = $state(1);
  let policyEditors = $state(false);
  let policySource = $state<'project' | 'organization' | undefined>(undefined);
  let policyBusy = $state(false);
  const MAX_APPROVALS = 10;

  function openPolicy(r: EnvRow) {
    policyEnv = r.slug;
    policyRequire = r.policy?.requireApproval ?? false;
    policyMin = Math.max(1, r.policy?.minApprovals ?? 1);
    policyEditors = r.policy?.approverRoles?.includes('editor') ?? false;
    policySource = r.policy?.source;
    policyOpen = true;
  }

  async function submitPolicy(e: SubmitEvent) {
    e.preventDefault();
    policyBusy = true;
    try {
      const approvalsRequired = policyRequire ? Math.min(MAX_APPROVALS, Math.max(1, Math.round(policyMin))) : 0;
      const approverRoles = policyEditors ? ['admin', 'editor'] : ['admin'];
      await secretsApi.savePolicy({ project, env: policyEnv, approvalsRequired, approverRoles });
      // Re-read: removing a project policy can leave an organization one in force.
      try {
        policies = await secretsApi.envPolicies(project);
      } catch {
        policies = {
          ...policies,
          [policyEnv]: {
            ...(policies[policyEnv] ?? defaultPolicy(project, policyEnv)),
            requireApproval: approvalsRequired > 0,
            minApprovals: approvalsRequired,
            approverRoles
          }
        };
      }
      const now = policies[policyEnv];
      if (!policyRequire && now?.requireApproval && now.source === 'organization') {
        toast.info(`${policyEnv} still needs approval: it's an organization approval environment (Administration → Organization settings).`);
      } else {
        toast.success(`Saved change policy for ${policyEnv}`);
      }
      policyOpen = false;
    } catch (err) {
      toast.error(err, 'Could not save the policy');
    } finally {
      policyBusy = false;
    }
  }

  // ---- Deletes --------------------------------------------------------------
  async function deleteEnv(slug: string) {
    const ok = await confirm({
      title: `Delete environment ${slug}?`,
      message: 'This removes the environment and its empty folders. It is refused while any secret still exists under it.',
      confirmLabel: 'Delete environment',
      danger: true,
      typeToConfirm: slug
    });
    if (!ok) return;
    try {
      await api.deleteEnvironment(project, slug);
      toast.success(`Deleted environment ${slug}`);
      await load();
    } catch (e) {
      toast.error(e, 'Could not delete environment');
    }
  }

  async function deleteProject() {
    const ok = await confirm({
      title: `Delete project ${project}?`,
      message:
        'This removes the project and its empty environments and folders. It is refused while any secret still exists under it.',
      confirmLabel: 'Delete project',
      danger: true,
      typeToConfirm: project
    });
    if (!ok) return;
    try {
      await api.deleteProject(project);
      toast.success(`Deleted project ${project}`);
      goto(`${base}/secrets`);
    } catch (e) {
      toast.error(e, 'Could not delete project');
    }
  }

  const description = $derived.by(() => {
    const parts: string[] = [];
    if (info?.description) parts.push(info.description);
    parts.push(`${envs.length} environment${envs.length === 1 ? '' : 's'}`);
    const total = info?.environmentCounts
      ? Object.values(info.environmentCounts).reduce((a, b) => a + b, 0)
      : undefined;
    if (total !== undefined) parts.push(`${total} secret${total === 1 ? '' : 's'}`);
    return parts.join(' · ');
  });
</script>

<svelte:head><title>{info?.name || project} · Secrets · Citadel</title></svelte:head>

<PageHeader
  title={info?.name || project}
  description={loading && !info ? undefined : description}
  crumbs={[{ label: 'Secrets', href: `${base}/secrets` }, { label: info?.name || project }]}
>
  {#snippet actions()}
    {#if canEdit && info}
      <button type="button" class="btn btn-ghost" onclick={() => openName('rename-project', project, info?.name || project)}>
        <Icon name="edit" size={16} />Rename
      </button>
      <button type="button" class="btn btn-danger-ghost" onclick={deleteProject}>
        <Icon name="trash" size={16} />Delete project
      </button>
      <button type="button" class="btn btn-primary" onclick={() => openName('create-env')}>
        <Icon name="plus" size={16} />New environment
      </button>
    {/if}
  {/snippet}
</PageHeader>

{#if loadError && !loading && !info}
  <div class="callout callout-danger" role="alert">
    <Icon name="alert-circle" size={16} />
    <div class="grow"><strong>Couldn't load this project.</strong> <span class="muted">{loadError}</span></div>
    <button type="button" class="btn btn-secondary btn-sm" onclick={load}>Try again</button>
  </div>
{:else if notFound && !loading}
  <div class="card card-flush">
    <div class="pad">
      <EmptyState icon="folder" title="Project not found" description="It may have been deleted or renamed, or it belongs to another account.">
        <a class="btn btn-secondary" href="{base}/secrets"><Icon name="chevron-left" size={16} />All projects</a>
      </EmptyState>
    </div>
  </div>
{:else}
  <DataTable rows={rows} {columns} key={(r) => r.slug} {loading} caption="Environments in {project}">
    {#snippet row(r)}
      <td>
        <a class="env" href="{projectHref}/{encodeURIComponent(r.slug)}">
          <span class="swatch swatch-{tierTone[r.tier]}" aria-hidden="true"></span>
          <span class="env-text">
            <span class="env-name">{envLabel(r.slug)}</span>
            {#if envLabel(r.slug) !== r.slug}<span class="mono subtle small">{r.slug}</span>{/if}
          </span>
        </a>
      </td>
      <td class="hide-mobile">
        <span class="badge badge-{tierTone[r.tier]}">{r.tier === 'other' ? 'Unclassified' : r.tier}</span>
      </td>
      <td>
        {#if r.policy?.requireApproval}
          <span class="policy"><Icon name="lock" size={14} />Needs {r.policy.minApprovals} approval{r.policy.minApprovals === 1 ? '' : 's'}{#if r.policy.source === 'organization'}<span class="subtle small"> · org-wide</span>{/if}</span>
        {:else}
          <span class="subtle">Direct edits</span>
        {/if}
      </td>
      <td class="end num hide-mobile">{r.count ?? '—'}</td>
      <td class="end">
        <span class="cell-actions">
          {#if isAdmin}
            <button type="button" class="btn btn-ghost btn-sm" onclick={() => openPolicy(r)}>
              <Icon name="shield" size={14} />Policy
            </button>
          {/if}
          {#if canEdit}
            <button
              type="button"
              class="btn-icon"
              aria-label="Rename environment {r.slug}"
              title="Rename"
              onclick={() => openName('rename-env', r.slug, r.slug)}
            >
              <Icon name="edit" size={14} />
            </button>
            <button
              type="button"
              class="btn-icon"
              aria-label="Delete environment {r.slug}"
              title="Delete"
              onclick={() => deleteEnv(r.slug)}
            >
              <Icon name="trash" size={14} />
            </button>
          {/if}
          <a class="btn-icon" href="{projectHref}/{encodeURIComponent(r.slug)}" aria-label="Open {r.slug}" title="Open">
            <Icon name="chevron-right" size={16} />
          </a>
        </span>
      </td>
    {/snippet}
    {#snippet empty()}
      <EmptyState
        icon="grid"
        title="No environments yet"
        description="Environments such as dev, staging and prod each hold their own copy of the project's secrets."
      >
        {#if canEdit}
          <button type="button" class="btn btn-primary" onclick={() => openName('create-env')}>
            <Icon name="plus" size={16} />New environment
          </button>
        {/if}
      </EmptyState>
    {/snippet}
  </DataTable>
{/if}

<Modal
  bind:open={nameOpen}
  title={nameTitle}
  description={nameMode === 'create-env'
    ? 'The slug becomes part of every secret name in this environment and cannot change later.'
    : 'Changes the display name only; secret names keep the slug.'}
  size="sm"
>
  <form id="name-form" class="form" onsubmit={submitName}>
    {#if nameMode === 'create-env'}
      <label class="field">
        <span class="field-label">Slug</span>
        <!-- svelte-ignore a11y_autofocus -->
        <input
          class="input mono"
          bind:value={nameSlug}
          placeholder="staging"
          autocomplete="off"
          spellcheck="false"
          autofocus
          aria-invalid={nameSlug.trim() !== '' && !slugOk}
        />
        <span class={nameSlug.trim() && !slugOk ? 'field-error' : 'field-hint'}>
          Letters, digits, dots, dashes and underscores. Names like dev, staging and prod pick their color automatically.
        </span>
      </label>
    {/if}
    <label class="field">
      <span class="field-label">Display name</span>
      <input class="input" bind:value={nameValue} placeholder={nameSlug || project} autocomplete="off" />
    </label>
  </form>
  {#snippet footer()}
    <button type="button" class="btn btn-secondary" onclick={() => (nameOpen = false)}>Cancel</button>
    <button type="submit" form="name-form" class="btn btn-primary" disabled={nameBusy || (nameMode === 'create-env' && !slugOk)}>
      {nameMode === 'create-env' ? 'Create environment' : 'Save name'}
    </button>
  {/snippet}
</Modal>

<Modal
  bind:open={policyOpen}
  title="Change policy · {policyEnv}"
  description="Controls how edits to secret values in this environment are applied."
  size="sm"
>
  <form id="policy-form" class="form" onsubmit={submitPolicy}>
    <label class="check first">
      <input type="checkbox" bind:checked={policyRequire} />
      <span>
        <span class="field-label">Require approval for changes</span>
        <span class="field-hint block">Saves open a change request; someone other than the requester must approve it.</span>
      </span>
    </label>
    {#if policyRequire}
      <label class="field">
        <span class="field-label">Approvals needed</span>
        <input class="input num" type="number" min="1" max={MAX_APPROVALS} bind:value={policyMin} />
      </label>
      <label class="check">
        <input type="checkbox" bind:checked={policyEditors} />
        <span>
          <span class="field-label">Editors can approve</span>
          <span class="field-hint block">Otherwise only admins approve. The requester never can.</span>
        </span>
      </label>
    {/if}
    {#if policySource === 'organization'}
      <div class="callout callout-info">
        <Icon name="info" size={16} />
        <span>
          This environment needs approval organization-wide (Administration → Organization settings). Saving here sets a
          project policy that overrides it; turning approval off here doesn't remove the organization rule.
        </span>
      </div>
    {/if}
  </form>
  {#snippet footer()}
    <button type="button" class="btn btn-secondary" onclick={() => (policyOpen = false)}>Cancel</button>
    <button type="submit" form="policy-form" class="btn btn-primary" disabled={policyBusy}>Save policy</button>
  {/snippet}
</Modal>

<style>
  .grow {
    flex: 1;
  }
  .pad {
    padding: var(--space-10) var(--space-5);
  }
  .env {
    display: inline-flex;
    align-items: center;
    gap: var(--space-3);
    color: var(--text);
    font-weight: 500;
  }
  .env:hover {
    text-decoration: none;
  }
  .env:hover .env-name {
    color: var(--accent-text);
    text-decoration: underline;
  }
  .env-text {
    display: flex;
    flex-direction: column;
  }
  .swatch {
    width: 8px;
    height: 8px;
    border-radius: 2px;
    flex-shrink: 0;
    background: var(--text-subtle);
  }
  .swatch-info {
    background: var(--info);
  }
  .swatch-warning {
    background: var(--warning);
  }
  .swatch-danger {
    background: var(--danger);
  }
  .badge {
    text-transform: capitalize;
  }
  .policy {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    color: var(--warning);
    font-weight: 500;
  }
  .form {
    display: flex;
    flex-direction: column;
  }
  .check {
    display: flex;
    gap: var(--space-3);
    align-items: flex-start;
    margin-top: var(--space-4);
    cursor: pointer;
  }
  .check.first {
    margin-top: 0;
  }
  .check input {
    margin-top: 2px;
  }
  .block {
    display: block;
    margin-top: 2px;
  }
  @media (max-width: 720px) {
    .hide-mobile {
      display: none;
    }
  }
</style>
