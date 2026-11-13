<script lang="ts">
  import { tick, untrack } from 'svelte';
  import { goto } from '$app/navigation';
  import { base } from '#lib/paths.ts';
  import { page } from '$app/state';
  import { api, type ChangeRequest, type KMSKey } from '#lib/api.ts';
  import EmptyState from '#lib/components/EmptyState.svelte';
  import Icon from '#lib/components/Icon.svelte';
  import PageHeader from '#lib/components/PageHeader.svelte';
  import { confirm } from '#lib/stores/confirm.svelte.ts';
  import { session } from '#lib/stores/session.svelte.ts';
  import { revealPolicy } from '#lib/stores/revealPolicy.svelte.ts';
  import { toast } from '#lib/stores/toast.svelte.ts';
  import { param, setParams } from '#lib/url.ts';
  import { defaultPolicy, secretsApi, type EnvPolicy, type ProjectInfo, type SecretList, type SecretRow } from '../../api';
  import { envLabel, envTier, joinPath, normPath, sortEnvs, type Tier } from '../../lib';
  import BulkBar from './BulkBar.svelte';
  import CopyMoveModal from './CopyMoveModal.svelte';
  import DeleteModal from './DeleteModal.svelte';
  import { toDotenv } from './dotenv';
  import EnvTabs from './EnvTabs.svelte';
  import FolderCrumb from './FolderCrumb.svelte';
  import ImportModal from './ImportModal.svelte';
  import Menu, { type MenuItem } from './Menu.svelte';
  import NameModal from './NameModal.svelte';
  import RekeyModal from './RekeyModal.svelte';
  import SecretDrawer, { type DrawerTab } from './SecretDrawer.svelte';
  import SecretsTable, { type SortKey } from './SecretsTable.svelte';
  import TagModal from './TagModal.svelte';
  import ValueModal from './ValueModal.svelte';

  // ---- Route + URL state ----------------------------------------------------
  const project = $derived(page.params.project ?? '');
  const env = $derived(page.params.env ?? '');
  const path = $derived(normPath(param('path', '/')));
  const openKey = $derived(param('secret'));
  const drawerTab = $derived<DrawerTab>(
    (['details', 'versions', 'rotation', 'access'] as const).find((t) => t === param('tab')) ?? 'details'
  );

  let query = $state(param('q'));
  let sortBy = $state<SortKey>(param('sort') === 'updated' ? 'updated' : 'key');
  let sortDir = $state<'asc' | 'desc'>(param('dir') === 'desc' ? 'desc' : 'asc');
  $effect(() => {
    setParams({ q: query, sort: sortBy === 'key' ? null : sortBy, dir: sortDir === 'asc' ? null : sortDir });
  });

  const canEdit = $derived(session.can('editor'));
  // Viewers read values only while the account allows it (the server
  // refuses otherwise), so hide Reveal and Export instead of failing.
  const canReveal = $derived(revealPolicy.canReveal);
  $effect(() => {
    void session.me;
    void revealPolicy.load();
  });

  // ---- Data -------------------------------------------------------------------
  let list = $state<SecretList | null>(null);
  let listLoading = $state(true);
  let listError = $state('');
  let projects = $state<ProjectInfo[]>([]);
  let policies = $state<Record<string, EnvPolicy>>({});
  let kmsKeys = $state<KMSKey[]>([]);
  let changeRequests = $state<ChangeRequest[]>([]);
  let selected = $state<string[]>([]);
  let drawerReload = $state(0);

  const info = $derived(projects.find((p) => p.slug === project));
  const envs = $derived(sortEnvs(info?.environments.includes(env) || !info ? (info?.environments ?? [env]) : [...info.environments, env]));
  const policy = $derived<EnvPolicy>(
    policies[env] ?? defaultPolicy(project, env)
  );
  const requireApproval = $derived(policy.requireApproval);
  const minApprovals = $derived(Math.max(1, policy.minApprovals || 1));
  const tier = $derived(policy.tier);
  const tiers = $derived(Object.fromEntries(envs.map((e) => [e, envTier(e, policies[e]?.tier)])) as Record<string, Tier>);
  const approvalEnvs = $derived(new Set(Object.values(policies).filter((p) => p.requireApproval).map((p) => p.env)));
  const nextEnv = $derived.by(() => {
    const others = envs.filter((e) => e !== env);
    const i = envs.indexOf(env);
    return envs[i + 1] && envs[i + 1] !== env ? envs[i + 1] : (others[0] ?? '');
  });

  const pending = $derived(
    changeRequests.filter((cr) => cr.status === 'pending' && cr.project === project && cr.env === env)
  );
  const pendingKeys = $derived(new Set(pending.filter((cr) => normPath(cr.path) === path).map((cr) => cr.key)));

  async function loadList() {
    if (!project || !env) return;
    listLoading = true;
    listError = '';
    const at = path;
    try {
      const res = await secretsApi.list(project, env, at);
      if (at !== path) return;
      list = res;
      selected = selected.filter((k) => res.items.some((i) => i.key === k));
    } catch (e) {
      listError = e instanceof Error ? e.message : 'Could not load secrets.';
      list = null;
    } finally {
      listLoading = false;
    }
  }

  async function loadContext() {
    const [ps, crs] = await Promise.allSettled([secretsApi.projects(), api.changeRequests()]);
    if (ps.status === 'fulfilled') projects = ps.value;
    else toast.error(ps.reason, 'Could not load projects');
    changeRequests = crs.status === 'fulfilled' ? crs.value.changeRequests : [];
    try {
      policies = await secretsApi.envPolicies(project);
    } catch {
      policies = {};
    }
  }

  async function loadKms() {
    try {
      kmsKeys = (await api.kmsKeys()).keys.filter((k) => k.enabled && !k.deletionDate);
    } catch {
      kmsKeys = [];
    }
  }

  // Project or environment changed: reset view state and load its context.
  $effect(() => {
    void project;
    void env;
    untrack(() => {
      selected = [];
      query = param('q');
      loadContext();
    });
  });
  $effect(() => {
    untrack(loadKms);
  });
  // Folder (or environment) changed: load the listing.
  $effect(() => {
    void project;
    void env;
    void path;
    untrack(() => {
      selected = [];
      loadList();
    });
  });

  async function refreshAll() {
    await Promise.all([loadList(), loadContext()]);
    drawerReload++;
  }

  // ---- Filtering and sorting -------------------------------------------------
  function matches(r: SecretRow, q: string) {
    if (r.key.toLowerCase().includes(q)) return true;
    return (r.tags ?? []).some((t) => `${t.key}=${t.value}`.toLowerCase().includes(q));
  }

  const q = $derived(query.trim().toLowerCase());
  const rows = $derived.by(() => {
    const items = (list?.items ?? []).filter((r) => !q || matches(r, q));
    const dir = sortDir === 'asc' ? 1 : -1;
    return [...items].sort((a, b) =>
      sortBy === 'updated'
        ? (new Date(a.updatedAt).getTime() - new Date(b.updatedAt).getTime()) * dir
        : a.key.localeCompare(b.key, undefined, { numeric: true, sensitivity: 'base' }) * dir
    );
  });
  const folders = $derived.by(() => {
    const fs = (list?.folders ?? []).filter((f) => !q || f.toLowerCase().includes(q));
    return [...fs].sort((a, b) => a.localeCompare(b) * (sortBy === 'key' && sortDir === 'desc' ? -1 : 1));
  });
  const existingKeys = $derived((list?.items ?? []).map((i) => i.key));
  const selectedRows = $derived((list?.items ?? []).filter((i) => selected.includes(i.key)));
  const selectedActive = $derived(selectedRows.filter((r) => !r.deletionDate).map((r) => r.key));
  const selectedDeleted = $derived(selectedRows.filter((r) => r.deletionDate).map((r) => r.key));
  const shadowed = $derived(list?.shadowed ?? []);

  // ---- Navigation -----------------------------------------------------------
  function urlWith(updates: Record<string, string | null>): string {
    const u = new URL(page.url.href);
    for (const [k, v] of Object.entries(updates)) {
      if (v === null || v === '') u.searchParams.delete(k);
      else u.searchParams.set(k, v);
    }
    return u.pathname + u.search;
  }

  const folderUrl = (p: string) => urlWith({ path: p === '/' ? null : p, secret: null, tab: null, q: null });

  function goFolder(p: string) {
    query = '';
    setParams({ path: p === '/' ? null : p, secret: null, tab: null, q: null }, { push: true });
  }

  function openSecret(r: SecretRow | string) {
    setParams({ secret: typeof r === 'string' ? r : r.key, tab: null });
  }

  async function closeDrawer() {
    const key = openKey;
    await setParams({ secret: null, tab: null });
    await tick();
    document.querySelector<HTMLButtonElement>(`[data-secret-key="${CSS.escape(key)}"]`)?.focus();
  }

  const crumbs = $derived.by(() => {
    const segs = path.split('/').filter(Boolean);
    const envHref = `${base}/secrets/${encodeURIComponent(project)}/${encodeURIComponent(env)}`;
    return [
      { label: 'Secrets', href: `${base}/secrets` },
      { label: info?.name || project, href: `${base}/secrets/${encodeURIComponent(project)}` },
      { label: envLabel(env), href: envHref },
      ...segs.map((s, i) => ({ label: s, href: `${envHref}?path=${encodeURIComponent('/' + segs.slice(0, i + 1).join('/'))}` }))
    ];
  });

  // ---- Single-secret actions -------------------------------------------------
  let valueOpen = $state(false);
  let valueMode = $state<'create' | 'edit'>('create');
  let valueKey = $state('');

  function addSecret() {
    valueMode = 'create';
    valueKey = '';
    valueOpen = true;
  }

  function editSecret(key: string) {
    valueMode = 'edit';
    valueKey = key;
    valueOpen = true;
  }

  async function onValueSaved(r: { key: string; changeRequest: boolean }) {
    await refreshAll();
    if (!r.changeRequest && valueMode === 'create') openSecret(r.key);
  }

  const reveal = (r: SecretRow) => secretsApi.revealValue(project, env, path, r.key);

  let deleteOpen = $state(false);
  let deleteKeys = $state<string[]>([]);

  function askDelete(keys: string[]) {
    deleteKeys = keys;
    deleteOpen = true;
  }

  async function scheduleDelete(days: number) {
    const keys = deleteKeys;
    try {
      if (keys.length === 1) {
        await api.remove(project, env, path, keys[0], { recoveryWindowDays: days });
        toast.success(`${keys[0]} is scheduled for deletion in ${days} days`);
      } else {
        const res = await api.bulkSecrets({ project, env, path, keys, action: 'delete', recoveryWindowDays: days });
        reportBulk(res, 'Scheduled', 'for deletion');
      }
      selected = selected.filter((k) => !keys.includes(k));
      await refreshAll();
    } catch (e) {
      toast.error(e, 'Could not schedule deletion');
    }
  }

  async function forceDelete(keys: string[]) {
    if (!keys.length) return;
    const one = keys.length === 1;
    const ok = await confirm({
      title: one ? `Force delete ${keys[0]} now?` : `Force delete ${keys.length} secrets now?`,
      message:
        'This skips the recovery window. The value is removed from External Secrets and SDK clients immediately and cannot be restored.',
      confirmLabel: 'Force delete',
      danger: true,
      typeToConfirm: one ? keys[0] : `force delete ${keys.length} secrets`
    });
    if (!ok) return;
    try {
      if (one) {
        await api.remove(project, env, path, keys[0], { force: true });
        toast.success(`Deleted ${keys[0]} permanently`);
      } else {
        const res = await api.bulkSecrets({ project, env, path, keys, action: 'delete', force: true });
        reportBulk(res, 'Deleted', 'permanently');
      }
      selected = selected.filter((k) => !keys.includes(k));
      if (keys.includes(openKey)) await setParams({ secret: null, tab: null });
      await refreshAll();
    } catch (e) {
      toast.error(e, 'Could not delete');
    }
  }

  async function restore(key: string) {
    try {
      await api.restore(project, env, path, key);
      toast.success(`Restored ${key}`);
      await refreshAll();
    } catch (e) {
      toast.error(e, 'Could not restore');
    }
  }

  function drawerDelete(key: string) {
    const row = list?.items.find((i) => i.key === key);
    if (row?.deletionDate) forceDelete([key]);
    else askDelete([key]);
  }

  function menuFor(r: SecretRow): MenuItem[] {
    const items: MenuItem[] = [
      { label: 'View details', icon: 'list', onclick: () => openSecret(r) },
      { label: 'Version history', icon: 'history', onclick: () => setParams({ secret: r.key, tab: 'versions' }) },
      { label: 'Copy ARN', icon: 'copy', onclick: () => copyText(r.arn, 'ARN copied') }
    ];
    if (!canEdit) return items;
    if (r.deletionDate) {
      // The server refuses restores where changes need approval.
      if (!requireApproval) items.push({ label: 'Restore', icon: 'history', divider: true, onclick: () => restore(r.key) });
      items.push({ label: 'Force delete…', icon: 'alert-triangle', danger: true, divider: requireApproval, onclick: () => forceDelete([r.key]) });
    } else {
      items.push(
        {
          label: requireApproval ? 'Request change…' : 'Edit value…',
          icon: requireApproval ? 'git-pull-request' : 'edit',
          divider: true,
          onclick: () => editSecret(r.key)
        },
        { label: 'Delete…', icon: 'trash', danger: true, divider: true, onclick: () => askDelete([r.key]) },
        { label: 'Force delete…', icon: 'alert-triangle', danger: true, onclick: () => forceDelete([r.key]) }
      );
    }
    return items;
  }

  async function copyText(text: string, msg: string) {
    try {
      await navigator.clipboard.writeText(text);
      toast.success(msg);
    } catch (e) {
      toast.error(e, 'Copy failed');
    }
  }

  // ---- Bulk -------------------------------------------------------------------
  function reportBulk(res: { applied: number; failed: string[] }, verb: string, tail: string) {
    const n = res.applied;
    if (res.failed.length) toast.error(`${verb} ${n} ${tail}; ${res.failed.length} failed: ${res.failed.slice(0, 4).join(', ')}`);
    else toast.success(`${verb} ${n} secret${n === 1 ? '' : 's'} ${tail}`);
  }

  async function bulkRestore() {
    const keys = selectedDeleted;
    const ok = await confirm({
      title: `Restore ${keys.length} secret${keys.length === 1 ? '' : 's'}?`,
      message: 'They leave the deletion schedule and External Secrets clients receive them again.',
      confirmLabel: 'Restore'
    });
    if (!ok) return;
    try {
      const res = await api.bulkSecrets({ project, env, path, keys, action: 'restore' });
      reportBulk(res, 'Restored', '');
      await refreshAll();
    } catch (e) {
      toast.error(e, 'Could not restore');
    }
  }

  let copyOpen = $state(false);
  let copyMode = $state<'copy' | 'move'>('copy');

  function openCopy(mode: 'copy' | 'move') {
    copyMode = mode;
    copyOpen = true;
  }

  async function submitCopy(r: { targetEnv: string; targetPath: string; overwrite: boolean }): Promise<boolean> {
    const keys = selectedActive;
    try {
      if (copyMode === 'copy') {
        const res = await secretsApi.bulkCopy({ project, env, path, keys, ...r });
        if (res.changeRequests?.length) toast.success(`Opened ${res.changeRequests.length} change request${res.changeRequests.length === 1 ? '' : 's'} in ${envLabel(r.targetEnv)}`);
        else reportBulk(res, 'Copied', `to ${envLabel(r.targetEnv)}`);
      } else {
        const res = await secretsApi.bulkMove({ project, env, path, keys, targetPath: r.targetPath });
        reportBulk(res, 'Moved', `to ${r.targetPath}`);
      }
      selected = [];
      await refreshAll();
      return true;
    } catch (e) {
      toast.error(e, copyMode === 'copy' ? 'Could not copy' : 'Could not move');
      return false;
    }
  }

  let tagOpen = $state(false);
  async function submitTag(tag: { key: string; value: string }): Promise<boolean> {
    const keys = selectedActive;
    const results = await Promise.allSettled(keys.map((k) => api.tagSecret(project, env, path, k, [tag])));
    const failed = keys.filter((_, i) => results[i].status === 'rejected');
    reportBulk({ applied: keys.length - failed.length, failed }, 'Tagged', `with ${tag.key}=${tag.value}`);
    await refreshAll();
    return failed.length === 0;
  }

  // ---- Export -------------------------------------------------------------------
  let exporting = $state(false);
  async function exportEnv() {
    const targets = (selectedActive.length ? selectedRows : (list?.items ?? [])).filter((r) => !r.deletionDate);
    if (!targets.length) {
      toast.info('There are no active secrets to export here.');
      return;
    }
    const ok = await confirm({
      title: `Export ${targets.length} secret${targets.length === 1 ? '' : 's'} as .env?`,
      message:
        'Each value is revealed (every reveal is logged) and saved to a file on this device. Treat the file as a secret and delete it when you are done.',
      confirmLabel: 'Export'
    });
    if (!ok) return;
    exporting = true;
    try {
      const out: { key: string; value: string }[] = [];
      for (let i = 0; i < targets.length; i += 4) {
        const batch = targets.slice(i, i + 4);
        const values = await Promise.all(batch.map((r) => secretsApi.revealValue(project, env, path, r.key)));
        batch.forEach((r, j) => out.push({ key: r.key, value: values[j] }));
      }
      const blob = new Blob([toDotenv(out)], { type: 'text/plain' });
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = `${project}-${env}${path === '/' ? '' : path.replace(/\//g, '-')}.env`;
      a.click();
      setTimeout(() => URL.revokeObjectURL(a.href), 1000);
      toast.success(`Exported ${out.length} secret${out.length === 1 ? '' : 's'}`);
    } catch (e) {
      toast.error(e, 'Export failed');
    } finally {
      exporting = false;
    }
  }

  // ---- Structure: folders, environments --------------------------------------
  let importOpen = $state(false);
  let rekeyOpen = $state(false);
  let folderOpen = $state(false);
  let envOpen = $state(false);

  async function createFolder(name: string): Promise<boolean> {
    try {
      await api.createFolder(project, env, joinPath(path, name).replace(/^\//, ''));
      toast.success(`Created folder ${name}`);
      await loadList();
      return true;
    } catch (e) {
      toast.error(e, 'Could not create folder');
      return false;
    }
  }

  async function deleteFolder(name: string) {
    const ok = await confirm({
      title: `Delete folder ${name}?`,
      message: 'Removes the folder and any empty folders inside it. It is refused while any secret exists at or below it.',
      confirmLabel: 'Delete folder',
      danger: true
    });
    if (!ok) return;
    try {
      await api.deleteFolder(project, env, joinPath(path, name));
      toast.success(`Deleted folder ${name}`);
      await loadList();
    } catch (e) {
      toast.error(e, 'Could not delete folder');
    }
  }

  async function createEnv(name: string): Promise<boolean> {
    try {
      await api.createEnvironment(project, name, name);
      toast.success(`Created environment ${name}`);
      await goto(`${base}/secrets/${encodeURIComponent(project)}/${encodeURIComponent(name)}`);
      return true;
    } catch (e) {
      toast.error(e, 'Could not create environment');
      return false;
    }
  }

  async function deleteEnv() {
    const ok = await confirm({
      title: `Delete environment ${env}?`,
      message: 'Removes the environment and its empty folders. It is refused while any secret still exists in it.',
      confirmLabel: 'Delete environment',
      danger: true,
      typeToConfirm: env
    });
    if (!ok) return;
    try {
      await api.deleteEnvironment(project, env);
      toast.success(`Deleted environment ${env}`);
      await goto(`${base}/secrets/${encodeURIComponent(project)}`);
    } catch (e) {
      toast.error(e, 'Could not delete environment');
    }
  }

  async function removeShadowing() {
    const ok = await confirm({
      title: 'Delete the object shadowing this folder?',
      message:
        'A secret is stored under this folder’s own name. Anything reading the folder receives that frozen object instead of a live view of the keys below, so keys added since are silently missing. Deleting it restores the live view. The keys in this folder are not touched.',
      confirmLabel: 'Delete shadowing object',
      danger: true,
      typeToConfirm: `${project}/${env}${path === '/' ? '' : path}`
    });
    if (!ok) return;
    try {
      await api.removeShadowing(project, env, path, { force: true });
      toast.success('Deleted the shadowing object; the folder now serves a live view');
      await loadList();
    } catch (e) {
      toast.error(e, 'Could not delete the shadowing object');
    }
  }

  const envMenu = $derived<MenuItem[]>([
    { label: 'New folder…', icon: 'folder', onclick: () => (folderOpen = true) },
    { label: 'Re-encrypt with another KMS key…', icon: 'key', onclick: () => (rekeyOpen = true) },
    { label: 'Delete environment…', icon: 'trash', danger: true, divider: true, onclick: deleteEnv }
  ]);

  const description = $derived.by(() => {
    const parts: string[] = [];
    if (info?.description) parts.push(info.description);
    const n = info?.environments.length ?? 0;
    if (n) parts.push(`${n} environment${n === 1 ? '' : 's'}`);
    if (requireApproval) parts.push(`changes need ${minApprovals} approval${minApprovals === 1 ? '' : 's'}`);
    return parts.join(' · ') || undefined;
  });
  const location = $derived(`${project}/${env}${path === '/' ? '' : path}`);
</script>

<svelte:head><title>{envLabel(env)} · {info?.name || project} · Secrets · Citadel</title></svelte:head>

{#if tier === 'production' || requireApproval}
  <div class="ribbon" class:ribbon-danger={tier === 'production'} role="note">
    <Icon name="lock" size={14} />
    <strong>{tier === 'production' ? 'Production' : envLabel(env)}</strong>
    <span>
      {#if requireApproval}
        Edits here open a change request and need {minApprovals === 1 ? 'one approval' : `${minApprovals} approvals`} from someone other than you.
      {:else}
        Changes here apply to live workloads immediately.
      {/if}
    </span>
    <a href="{base}/approvals">{requireApproval ? 'View policy' : 'Approvals'}</a>
  </div>
{/if}

<div class="page">
  <PageHeader title={info?.name || project} {description} {crumbs}>
    {#snippet actions()}
      {#if canEdit}
        <Menu label="Environment actions" text="Environment" icon="sliders" buttonClass="btn btn-ghost" items={envMenu} />
      {/if}
      <a class="btn btn-ghost" href="{base}/secrets/{encodeURIComponent(project)}"><Icon name="settings" size={16} />Project settings</a>
    {/snippet}
  </PageHeader>

  <EnvTabs {project} {envs} current={env} {tiers} counts={info?.environmentCounts} canAdd={canEdit} onadd={() => (envOpen = true)} />

  {#if pending.length}
    <div class="callout callout-info">
      <Icon name="git-pull-request" size={16} />
      <span class="grow">
        {pending.length} change request{pending.length === 1 ? ' is' : 's are'} waiting for approval in {envLabel(env)}.
      </span>
      <a class="btn btn-secondary btn-sm" href="{base}/approvals">Review</a>
    </div>
  {/if}

  {#each shadowed as sh (sh.arn)}
    <div class="callout callout-warning" role="alert">
      <Icon name="alert-triangle" size={16} />
      <div class="grow">
        <strong>An object is shadowing this folder.</strong>
        <span>
          A secret is stored under the folder’s own name (<code>{location}</code>) instead of under a key in it.
          Anything reading the folder, External Secrets included, gets that frozen copy, so keys added since are missing.
          Last changed {new Date(sh.updatedAt).toLocaleString()}. The {existingKeys.length} key{existingKeys.length === 1 ? '' : 's'} here are not affected.
        </span>
      </div>
      {#if canEdit}
        <button type="button" class="btn btn-danger btn-sm" onclick={removeShadowing}>Delete shadowing object</button>
      {/if}
    </div>
  {/each}

  <div class="split">
    <div class="main-col">
      <div class="toolbar-row">
        <div class="tb-left">
          <FolderCrumb {path} href={folderUrl} onnavigate={goFolder} />
          <label class="search">
            <span class="search-ic" aria-hidden="true"><Icon name="search" size={16} /></span>
            <span class="sr-only">Filter secrets by key or tag</span>
            <input class="input" type="search" placeholder="Filter by key or tag" bind:value={query} />
          </label>
        </div>
        <div class="tb-right">
          {#if canEdit}
            <button type="button" class="btn btn-secondary" onclick={() => (importOpen = true)}>
              <Icon name="upload" size={16} />Import .env
            </button>
          {/if}
          {#if canReveal}
            <button type="button" class="btn btn-secondary" disabled={exporting || !list?.items.length} onclick={exportEnv}>
              <Icon name="download" size={16} />{exporting ? 'Exporting…' : selectedActive.length ? `Export ${selectedActive.length}` : 'Export'}
            </button>
          {/if}
          {#if canEdit}
            <button type="button" class="btn btn-primary" onclick={addSecret}>
              <Icon name="plus" size={16} />Add secret
            </button>
          {/if}
        </div>
      </div>

      {#if canEdit && selected.length > 0}
        <BulkBar
          count={selected.length}
          copyLabel={nextEnv ? `Copy to ${envLabel(nextEnv).toLowerCase()}` : 'Copy to…'}
          canMove={!requireApproval}
          moveHint={requireApproval ? 'Moves are not available where changes need approval' : undefined}
          deletedCount={requireApproval ? 0 : selectedDeleted.length}
          activeCount={selectedActive.length}
          oncopy={() => openCopy('copy')}
          onmove={() => openCopy('move')}
          ontag={() => (tagOpen = true)}
          onrestore={bulkRestore}
          ondelete={() => askDelete(selectedActive)}
          onforce={() => forceDelete(selected)}
          onclear={() => (selected = [])}
        />
      {/if}

      {#if listError && !listLoading}
        <div class="callout callout-danger" role="alert">
          <Icon name="alert-circle" size={16} />
          <div class="grow"><strong>Couldn't load {location}.</strong> <span class="muted">{listError}</span></div>
          <button type="button" class="btn btn-secondary btn-sm" onclick={loadList}>Try again</button>
        </div>
      {:else}
        <SecretsTable
          {rows}
          {folders}
          folderCounts={list?.folderCounts}
          loading={listLoading}
          selectable={canEdit}
          bind:selected
          activeKey={openKey}
          {pendingKeys}
          bind:sortBy
          bind:sortDir
          caption="Secrets in {project}, {envLabel(env)}, folder {path}"
          folderHref={(f) => folderUrl(joinPath(path, f))}
          onopenfolder={(f) => goFolder(joinPath(path, f))}
          ondeletefolder={canEdit ? deleteFolder : undefined}
          onopen={openSecret}
          {reveal}
          {canReveal}
          {menuFor}
        >
          {#snippet empty()}
            {#if q}
              <div class="nomatch">
                <p class="muted">Nothing here matches “{query}”.</p>
                <button type="button" class="btn btn-ghost btn-sm" onclick={() => (query = '')}>Clear filter</button>
              </div>
            {:else}
              <EmptyState
                icon="lock"
                title={path === '/' ? `No secrets in ${envLabel(env)} yet` : 'This folder is empty'}
                description={canEdit
                  ? 'Add a secret, import a .env file, or create a folder to organize keys.'
                  : 'Nothing has been stored here yet.'}
              >
                {#if canEdit}
                  <button type="button" class="btn btn-primary" onclick={addSecret}><Icon name="plus" size={16} />Add secret</button>
                  <button type="button" class="btn btn-secondary" onclick={() => (importOpen = true)}><Icon name="upload" size={16} />Import .env</button>
                  <button type="button" class="btn btn-ghost" onclick={() => (folderOpen = true)}><Icon name="folder" size={16} />New folder</button>
                {/if}
              </EmptyState>
            {/if}
          {/snippet}
          {#snippet footer()}
            <span>
              {rows.length} secret{rows.length === 1 ? '' : 's'}{folders.length ? ` and ${folders.length} folder${folders.length === 1 ? '' : 's'}` : ''}
              in <span class="mono">{path}</span>{q ? ' matching the filter' : ''}
            </span>
            <span class="foot-note"><Icon name="shield-check" size={14} />Revealed values hide after 30 s and every reveal is logged</span>
          {/snippet}
        </SecretsTable>
      {/if}
    </div>

    {#if openKey}
      <SecretDrawer
        {project}
        {env}
        {path}
        secretKey={openKey}
        {kmsKeys}
        {requireApproval}
        {minApprovals}
        {canEdit}
        {canReveal}
        reloadToken={drawerReload}
        tab={drawerTab}
        ontab={(t) => setParams({ tab: t === 'details' ? null : t })}
        onclose={closeDrawer}
        onchanged={() => {
          loadList();
          loadContext();
        }}
        onedit={editSecret}
        ondelete={drawerDelete}
        onrestore={restore}
      />
    {/if}
  </div>
</div>

<ValueModal
  bind:open={valueOpen}
  mode={valueMode}
  {project}
  {env}
  {path}
  initialKey={valueKey}
  {kmsKeys}
  {existingKeys}
  {requireApproval}
  {minApprovals}
  onsaved={onValueSaved}
/>
<DeleteModal bind:open={deleteOpen} keys={deleteKeys} onconfirm={scheduleDelete} onforce={() => forceDelete(deleteKeys)} />
<ImportModal bind:open={importOpen} {project} {env} {path} {existingKeys} {requireApproval} ondone={refreshAll} />
<CopyMoveModal
  bind:open={copyOpen}
  mode={copyMode}
  keys={selectedActive}
  {env}
  {envs}
  defaultTarget={nextEnv}
  {path}
  {approvalEnvs}
  onsubmit={submitCopy}
/>
<TagModal bind:open={tagOpen} count={selectedActive.length} onsubmit={submitTag} />
<RekeyModal bind:open={rekeyOpen} {project} {env} {kmsKeys} ondone={refreshAll} />
<NameModal
  bind:open={folderOpen}
  title="New folder"
  description="Folders group keys; External Secrets can read a whole folder as one JSON object."
  label="Folder name"
  placeholder="database"
  submitLabel="Create folder"
  prefix={`${path === '/' ? '' : path}/`}
  onsubmit={createFolder}
/>
<NameModal
  bind:open={envOpen}
  title="Add environment"
  description="Names like dev, staging and prod get their color automatically."
  label="Environment slug"
  placeholder="staging"
  submitLabel="Create environment"
  onsubmit={createEnv}
/>

<style>
  .ribbon {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 10px;
    margin: calc(-1 * var(--pad-page)) calc(-1 * var(--pad-page)) var(--space-6);
    padding: var(--space-2) var(--pad-page);
    border-bottom: 1px solid var(--border);
    background: var(--warning-soft);
    color: var(--warning);
    font-size: var(--text-sm);
  }
  .ribbon-danger {
    background: var(--danger-soft);
    color: var(--danger);
  }
  .ribbon strong {
    font-weight: 600;
  }
  .ribbon a {
    margin-left: auto;
    color: inherit;
    font-weight: 500;
    text-decoration: underline;
  }
  .page {
    display: flex;
    flex-direction: column;
    gap: var(--space-5);
  }
  .page :global(.ph) {
    margin-bottom: 0;
  }
  .grow {
    flex: 1;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .split {
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
  .toolbar-row {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: var(--space-2);
  }
  .tb-left {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: var(--space-2);
    flex: 1 1 320px;
    min-width: 0;
  }
  .tb-right {
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-2);
  }
  .search {
    position: relative;
    display: flex;
    align-items: center;
    flex: 1 1 220px;
    max-width: 360px;
  }
  .search-ic {
    position: absolute;
    left: 10px;
    display: inline-flex;
    color: var(--text-subtle);
    pointer-events: none;
  }
  .search .input {
    padding-left: 34px;
  }
  .nomatch {
    text-align: center;
  }
  .nomatch p {
    margin: 0 0 var(--space-2);
  }
  .foot-note {
    display: inline-flex;
    align-items: center;
    gap: 6px;
  }
  @media (max-width: 720px) {
    .search {
      max-width: none;
    }
    .tb-right {
      width: 100%;
    }
  }
</style>
