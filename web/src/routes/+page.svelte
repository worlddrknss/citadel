<script lang="ts">
  import { onMount } from 'svelte';
  import {
    api,
    ApiError,
    type Project,
    type Item,
    type ItemDetail,
    type ItemVersion,
    type KMSKey
  } from '$lib/api';

  let projects: Project[] = $state([]);
  let project = $state('');
  let env = $state('');
  let path = $state('/');

  let folders: string[] = $state([]);
  let items: Item[] = $state([]);
  let revealed: Record<string, string> = $state({});
  let selected: Record<string, boolean> = $state({});

  let kmsKeys: KMSKey[] = $state([]);

  let flash = $state('');
  let flashOk = $state(true);
  let loading = $state(false);

  // New-secret form
  let newKey = $state('');
  let newValue = $state('');
  let newKms = $state('');

  // Structure creation
  let newProjectSlug = $state('');
  let newEnvSlug = $state('');
  let newFolderName = $state('');

  // Detail drawer
  let detail: ItemDetail | null = $state(null);
  let detailKey = $state('');
  let detailTab: 'overview' | 'versions' | 'tags' | 'policy' | 'rotation' = $state('overview');
  let versions: ItemVersion[] = $state([]);
  let metaDescription = $state('');
  let metaKms = $state('');
  let newVersionValue = $state('');
  let tagKey = $state('');
  let tagValue = $state('');
  let policyDoc = $state('');
  let rotLambda = $state('');
  let rotDays = $state('30');
  let rotImmediate = $state(false);

  // Confirm modal (avoids native confirm per UX guidelines)
  let confirmOpen = $state(false);
  let confirmTitle = $state('');
  let confirmBody = $state('');
  let confirmLabel = $state('Confirm');
  let confirmDanger = $state(true);
  let confirmAction: (() => Promise<void>) | null = $state(null);

  // Prompt modal (avoids native prompt per UX guidelines)
  let promptOpen = $state(false);
  let promptTitle = $state('');
  let promptLabel = $state('');
  let promptValue = $state('');
  let promptAction: ((value: string) => Promise<void>) | null = $state(null);

  const envs = $derived(projects.find((p) => p.slug === project)?.environments ?? []);
  const selectedKeys = $derived(items.filter((it) => selected[it.key]).map((it) => it.key));
  const crumbSegs = $derived(path.split('/').filter(Boolean));

  function notify(msg: string, ok = true) {
    flash = msg;
    flashOk = ok;
    setTimeout(() => (flash = ''), 4000);
  }

  function err(e: unknown) {
    if (e instanceof ApiError) notify(e.message, false);
    else notify('Unexpected error', false);
  }

  // prettyJSON pretty-prints a JSON string with 2-space indentation. If the
  // input is not valid JSON it is returned unchanged so the user can still fix
  // it by hand.
  function prettyJSON(raw: string): string {
    const trimmed = (raw ?? '').trim();
    if (!trimmed) return '';
    try {
      return JSON.stringify(JSON.parse(trimmed), null, 2);
    } catch {
      return raw;
    }
  }

  function formatPolicy() {
    const next = prettyJSON(policyDoc);
    if (next === policyDoc) {
      if (policyDoc.trim()) notify('Policy is not valid JSON', false);
      return;
    }
    policyDoc = next;
  }

  function askConfirm(opts: {
    title: string;
    body: string;
    label?: string;
    danger?: boolean;
    action: () => Promise<void>;
  }) {
    confirmTitle = opts.title;
    confirmBody = opts.body;
    confirmLabel = opts.label ?? 'Confirm';
    confirmDanger = opts.danger ?? true;
    confirmAction = opts.action;
    confirmOpen = true;
  }

  async function runConfirm() {
    const action = confirmAction;
    confirmOpen = false;
    if (action) await action();
    confirmAction = null;
  }

  function askPrompt(opts: {
    title: string;
    label: string;
    value?: string;
    action: (value: string) => Promise<void>;
  }) {
    promptTitle = opts.title;
    promptLabel = opts.label;
    promptValue = opts.value ?? '';
    promptAction = opts.action;
    promptOpen = true;
  }

  async function runPrompt() {
    const action = promptAction;
    const value = promptValue;
    promptOpen = false;
    if (action) await action(value);
    promptAction = null;
  }

  async function loadProjects() {
    try {
      const res = await api.projects();
      projects = res.projects;
      if (!project && projects.length) {
        project = projects[0].slug;
        env = projects[0].environments[0] ?? '';
      }
    } catch (e) {
      err(e);
    }
  }

  async function loadKms() {
    try {
      kmsKeys = (await api.kmsKeys()).keys.filter((k) => k.enabled);
    } catch {
      kmsKeys = [];
    }
  }

  async function loadItems() {
    if (!project || !env) {
      items = [];
      folders = [];
      return;
    }
    loading = true;
    try {
      const res = await api.list(project, env, path);
      items = res.items;
      folders = res.folders;
      revealed = {};
      selected = {};
    } catch (e) {
      err(e);
    } finally {
      loading = false;
    }
  }

  async function reveal(it: Item) {
    try {
      const res = await api.reveal(it.project, it.env, it.path, it.key);
      revealed = { ...revealed, [it.key]: res.value ?? '(binary)' };
    } catch (e) {
      err(e);
    }
  }

  function hide(key: string) {
    const next = { ...revealed };
    delete next[key];
    revealed = next;
  }

  async function addSecret() {
    if (!project || !env || !newKey.trim()) {
      notify('project, env and key are required', false);
      return;
    }
    try {
      const res = await api.put({
        project,
        env,
        path,
        key: newKey.trim(),
        value: newValue,
        kmsKeyId: newKms || undefined
      });
      notify(res.created ? `Created ${newKey}` : `Updated ${newKey}`);
      newKey = '';
      newValue = '';
      await loadItems();
    } catch (e) {
      err(e);
    }
  }

  function scheduleDelete(it: Item) {
    askConfirm({
      title: `Schedule deletion of ${it.key}?`,
      body: 'The item enters a 30-day recovery window and can be restored before it is purged. External Secrets clients stop receiving it immediately.',
      label: 'Schedule deletion',
      action: async () => {
        try {
          await api.remove(it.project, it.env, it.path, it.key, { recoveryWindowDays: 30 });
          notify(`Scheduled ${it.key} for deletion`);
          if (detailKey === it.key) closeDetail();
          await loadItems();
        } catch (e) {
          err(e);
        }
      }
    });
  }

  function forceDelete(it: Item) {
    askConfirm({
      title: `Force delete ${it.key} now?`,
      body: 'This bypasses the recovery window. The value is removed from External Secrets immediately and cannot be restored from the UI.',
      label: 'Force delete now',
      action: async () => {
        try {
          await api.remove(it.project, it.env, it.path, it.key, { force: true });
          notify(`Force deleted ${it.key}`);
          if (detailKey === it.key) closeDetail();
          await loadItems();
        } catch (e) {
          err(e);
        }
      }
    });
  }

  async function restore(it: Item) {
    try {
      await api.restore(it.project, it.env, it.path, it.key);
      notify(`Restored ${it.key}`);
      await loadItems();
      if (detailKey === it.key) await loadDetail(it);
    } catch (e) {
      err(e);
    }
  }

  function openFolder(name: string) {
    closeDetail();
    path = path === '/' ? `/${name}` : `${path}/${name}`;
    loadItems();
  }

  function crumbTo(idx: number) {
    closeDetail();
    const segs = path.split('/').filter(Boolean);
    path = idx < 0 ? '/' : '/' + segs.slice(0, idx + 1).join('/');
    loadItems();
  }

  // ---- structure creation --------------------------------------------------
  async function createProject() {
    const slug = newProjectSlug.trim();
    if (!slug) return;
    try {
      await api.createProject(slug, slug);
      notify(`Created project ${slug}`);
      newProjectSlug = '';
      await loadProjects();
      project = slug;
    } catch (e) {
      err(e);
    }
  }

  async function createEnvironment() {
    const slug = newEnvSlug.trim();
    if (!project || !slug) {
      notify('select a project and enter an environment name', false);
      return;
    }
    try {
      await api.createEnvironment(project, slug, slug);
      notify(`Created environment ${slug}`);
      newEnvSlug = '';
      await loadProjects();
      env = slug;
    } catch (e) {
      err(e);
    }
  }

  async function createFolder() {
    const name = newFolderName.trim();
    if (!project || !env || !name) {
      notify('select project/env and enter a folder name', false);
      return;
    }
    const full = path === '/' ? name : `${path.replace(/^\//, '')}/${name}`;
    try {
      await api.createFolder(project, env, full);
      notify(`Created folder ${name}`);
      newFolderName = '';
      await loadItems();
    } catch (e) {
      err(e);
    }
  }

  // ---- structure management ------------------------------------------------
  function renameProject() {
    if (!project) return;
    askPrompt({
      title: `Rename project "${project}"`,
      label: 'Display name',
      value: project,
      action: async (name) => {
        try {
          await api.renameProject(project, name.trim());
          notify(`Renamed project ${project}`);
          await loadProjects();
        } catch (e) {
          err(e);
        }
      }
    });
  }

  function deleteProject() {
    if (!project) return;
    askConfirm({
      title: `Delete project "${project}"?`,
      body: 'This removes the project and its empty environments/folders. It is refused while any secret still exists under it.',
      label: 'Delete project',
      action: async () => {
        try {
          await api.deleteProject(project);
          notify(`Deleted project ${project}`);
          project = '';
          env = '';
          await loadProjects();
        } catch (e) {
          err(e);
        }
      }
    });
  }

  function renameEnvironment() {
    if (!project || !env) return;
    askPrompt({
      title: `Rename environment "${env}"`,
      label: 'Display name',
      value: env,
      action: async (name) => {
        try {
          await api.renameEnvironment(project, env, name.trim());
          notify(`Renamed environment ${env}`);
          await loadProjects();
        } catch (e) {
          err(e);
        }
      }
    });
  }

  function deleteEnvironment() {
    if (!project || !env) return;
    askConfirm({
      title: `Delete environment "${env}"?`,
      body: 'This removes the environment and its empty folders. It is refused while any secret still exists under it.',
      label: 'Delete environment',
      action: async () => {
        try {
          await api.deleteEnvironment(project, env);
          notify(`Deleted environment ${env}`);
          env = '';
          await loadProjects();
        } catch (e) {
          err(e);
        }
      }
    });
  }

  function deleteFolder(name: string) {
    const full = path === '/' ? `/${name}` : `${path}/${name}`;
    askConfirm({
      title: `Delete folder "${name}"?`,
      body: 'This removes the folder and any nested empty folders. It is refused while any secret still exists at or below it.',
      label: 'Delete folder',
      action: async () => {
        try {
          await api.deleteFolder(project, env, full);
          notify(`Deleted folder ${name}`);
          await loadItems();
        } catch (e) {
          err(e);
        }
      }
    });
  }

  // ---- detail drawer -------------------------------------------------------
  async function openDetail(it: Item) {
    detailKey = it.key;
    detailTab = 'overview';
    await loadDetail(it);
  }

  async function loadDetail(it: Item) {
    try {
      const d = await api.secretDetail(it.project, it.env, it.path, it.key);
      detail = d;
      metaDescription = d.description;
      metaKms = d.kmsKeyId;
      policyDoc = prettyJSON(d.policyDocument);
      rotLambda = d.rotation.lambdaArn ?? '';
      rotDays = String(d.rotation.afterDays || 30);
      versions = [];
    } catch (e) {
      err(e);
      detail = null;
      detailKey = '';
    }
  }

  function closeDetail() {
    detail = null;
    detailKey = '';
    versions = [];
  }

  function detailCoord() {
    if (!detail) return null;
    return { project: detail.project, env: detail.env, path: detail.path, key: detail.key };
  }

  function detailAsItem(): Item | null {
    if (!detail) return null;
    return {
      project: detail.project,
      env: detail.env,
      path: detail.path,
      key: detail.key,
      arn: detail.arn,
      updatedAt: detail.updatedAt,
      deletionDate: detail.deletionDate
    };
  }

  async function loadVersions() {
    if (!detail) return;
    try {
      const res = await api.versions(detail.project, detail.env, detail.path, detail.key);
      versions = res.versions;
    } catch (e) {
      err(e);
    }
  }

  async function reloadDetail() {
    const it = detailAsItem();
    if (it) await loadDetail(it);
  }

  async function saveMetadata() {
    const c = detailCoord();
    if (!c) return;
    try {
      await api.updateSecretMetadata({ ...c, description: metaDescription, kmsKeyId: metaKms });
      notify('Saved metadata');
      await reloadDetail();
    } catch (e) {
      err(e);
    }
  }

  async function storeNewVersion() {
    const c = detailCoord();
    if (!c) return;
    try {
      await api.put({ ...c, value: newVersionValue });
      notify('Stored new version');
      newVersionValue = '';
      await reloadDetail();
      if (detailTab === 'versions') await loadVersions();
    } catch (e) {
      err(e);
    }
  }

  async function promote(versionId: string) {
    const c = detailCoord();
    if (!c) return;
    try {
      await api.promoteVersion(c.project, c.env, c.path, c.key, versionId);
      notify('Promoted version to current');
      await loadVersions();
      await reloadDetail();
    } catch (e) {
      err(e);
    }
  }

  async function addTag() {
    const c = detailCoord();
    if (!c || !tagKey.trim()) return;
    try {
      await api.tagSecret(c.project, c.env, c.path, c.key, [
        { key: tagKey.trim(), value: tagValue }
      ]);
      notify('Saved tag');
      tagKey = '';
      tagValue = '';
      await reloadDetail();
    } catch (e) {
      err(e);
    }
  }

  async function removeTag(key: string) {
    const c = detailCoord();
    if (!c) return;
    try {
      await api.untagSecret(c.project, c.env, c.path, c.key, key);
      notify('Removed tag');
      await reloadDetail();
    } catch (e) {
      err(e);
    }
  }

  async function savePolicy() {
    const c = detailCoord();
    if (!c) return;
    try {
      await api.putSecretPolicy(c.project, c.env, c.path, c.key, policyDoc);
      notify('Saved resource policy');
      await reloadDetail();
    } catch (e) {
      err(e);
    }
  }

  async function saveRotation() {
    const c = detailCoord();
    if (!c) return;
    try {
      await api.configureRotation({
        ...c,
        lambdaArn: rotLambda.trim(),
        afterDays: parseInt(rotDays, 10) || 30,
        rotateImmediately: rotImmediate
      });
      notify('Saved rotation config');
      rotImmediate = false;
      await reloadDetail();
    } catch (e) {
      err(e);
    }
  }

  async function cancelRotation() {
    const c = detailCoord();
    if (!c) return;
    try {
      await api.cancelRotation(c.project, c.env, c.path, c.key);
      notify('Cancelled rotation');
      await reloadDetail();
    } catch (e) {
      err(e);
    }
  }

  // ---- bulk ----------------------------------------------------------------
  function bulkDelete() {
    const keys = selectedKeys;
    if (!keys.length) return;
    askConfirm({
      title: `Schedule ${keys.length} item(s) for deletion?`,
      body: 'Each selected item enters a 30-day recovery window and can be restored before purge.',
      label: 'Schedule deletion',
      action: async () => {
        try {
          const res = await api.bulkSecrets({
            project,
            env,
            path,
            keys,
            action: 'delete',
            recoveryWindowDays: 30
          });
          notify(
            `Scheduled ${res.applied} item(s); ${res.failed.length} failed`,
            res.failed.length === 0
          );
          await loadItems();
        } catch (e) {
          err(e);
        }
      }
    });
  }

  async function bulkRestore() {
    const keys = selectedKeys;
    if (!keys.length) return;
    try {
      const res = await api.bulkSecrets({ project, env, path, keys, action: 'restore' });
      notify(
        `Restored ${res.applied} item(s); ${res.failed.length} failed`,
        res.failed.length === 0
      );
      await loadItems();
    } catch (e) {
      err(e);
    }
  }

  $effect(() => {
    // Reload whenever project/env changes.
    void project;
    void env;
    path = '/';
    closeDetail();
    loadItems();
  });

  onMount(() => {
    loadProjects();
    loadKms();
  });
</script>

<div class="ph">
  <h1 class="ph-title">Secrets</h1>
  <p class="ph-sub">
    Organize secrets by project, environment, and folder. Items remain readable through
    the AWS Secrets Manager API for ESO and SDK clients.
  </p>
</div>

{#if flash}
  <div class="flash {flashOk ? 'ok' : 'err'}">{flash}</div>
{/if}

<div class="card">
  <div class="toolbar">
    <div class="field">
      <label for="project">Project</label>
      <select id="project" bind:value={project}>
        {#each projects as p}
          <option value={p.slug}>{p.slug}</option>
        {/each}
        {#if projects.length === 0}
          <option value="">(none yet)</option>
        {/if}
      </select>
    </div>
    <div class="field">
      <label for="env">Environment</label>
      <select id="env" bind:value={env}>
        {#each envs as e}
          <option value={e}>{e}</option>
        {/each}
        {#if envs.length === 0}
          <option value="">(none)</option>
        {/if}
      </select>
    </div>
    <div class="manage-act">
      {#if project}
        <button class="btn btn-sm" onclick={renameProject} title="Rename project">Edit project</button>
        <button class="btn btn-sm btn-d" onclick={deleteProject} title="Delete project">Delete project</button>
      {/if}
      {#if project && env}
        <button class="btn btn-sm" onclick={renameEnvironment} title="Rename environment">Edit env</button>
        <button class="btn btn-sm btn-d" onclick={deleteEnvironment} title="Delete environment">Delete env</button>
      {/if}
    </div>
  </div>

  <!-- structure creation -->
  <div class="toolbar struct">
    <div class="field">
      <label for="np">New project</label>
      <input id="np" placeholder="prod" bind:value={newProjectSlug} />
    </div>
    <button class="btn btn-sm" onclick={createProject}>+ Project</button>
    <div class="field">
      <label for="ne">New environment</label>
      <input id="ne" placeholder="staging" bind:value={newEnvSlug} />
    </div>
    <button class="btn btn-sm" onclick={createEnvironment}>+ Environment</button>
    <div class="field">
      <label for="nf">New folder (here)</label>
      <input id="nf" placeholder="database" bind:value={newFolderName} />
    </div>
    <button class="btn btn-sm" onclick={createFolder}>+ Folder</button>
  </div>

  <div class="crumbs" style="margin-bottom:0.75rem">
    <span onclick={() => crumbTo(-1)} role="button" tabindex="0" onkeydown={() => {}}
      >{project || '—'}/{env || '—'}</span
    >
    {#each crumbSegs as seg, i}
      / <span onclick={() => crumbTo(i)} role="button" tabindex="0" onkeydown={() => {}}>{seg}</span>
    {/each}
  </div>

  {#if selectedKeys.length > 0}
    <div class="bulkbar">
      <span class="muted">{selectedKeys.length} selected</span>
      <button class="btn btn-sm btn-d" onclick={bulkDelete}>Schedule deletion</button>
      <button class="btn btn-sm" onclick={bulkRestore}>Restore</button>
    </div>
  {/if}

  {#if loading}
    <div class="empty">Loading…</div>
  {:else}
    <table>
      <thead>
        <tr>
          <th style="width:28px"></th>
          <th>Key</th>
          <th>Value</th>
          <th>Status</th>
          <th>Updated</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        {#each folders as f}
          <tr>
            <td></td>
            <td>
              <button class="btn btn-sm" onclick={() => openFolder(f)}>📁 {f}/</button>
            </td>
            <td class="muted">folder</td>
            <td></td>
            <td></td>
            <td>
              <div class="rowact">
                <button class="btn btn-sm btn-d" onclick={() => deleteFolder(f)}>Delete</button>
              </div>
            </td>
          </tr>
        {/each}
        {#each items as it}
          <tr class:rowsel={detailKey === it.key}>
            <td>
              <input type="checkbox" class="chk" bind:checked={selected[it.key]} />
            </td>
            <td class="mono">
              <button class="linklike" onclick={() => openDetail(it)}>{it.key}</button>
            </td>
            <td class="mono">
              {#if it.deletionDate}
                <span class="muted">— unavailable —</span>
              {:else if revealed[it.key] !== undefined}
                {revealed[it.key]}
                <button class="btn btn-sm" onclick={() => hide(it.key)}>Hide</button>
              {:else}
                <span class="muted">••••••••</span>
                <button class="btn btn-sm" onclick={() => reveal(it)}>Reveal</button>
              {/if}
            </td>
            <td>
              {#if it.deletionDate}
                <span class="badge warn">scheduled deletion</span>
              {:else}
                <span class="badge ok">active</span>
              {/if}
            </td>
            <td class="muted">{it.updatedAt?.replace('T', ' ').replace('Z', '')}</td>
            <td>
              <div class="rowact">
                <button class="btn btn-sm" onclick={() => openDetail(it)}>Details</button>
                {#if it.deletionDate}
                  <button class="btn btn-sm" onclick={() => restore(it)}>Restore</button>
                {:else}
                  <button class="btn btn-sm btn-d" onclick={() => scheduleDelete(it)}>Delete</button>
                {/if}
              </div>
            </td>
          </tr>
        {/each}
        {#if folders.length === 0 && items.length === 0}
          <tr><td colspan="6" class="empty">No secrets at this path yet.</td></tr>
        {/if}
      </tbody>
    </table>
  {/if}
</div>

<div class="card" style="margin-top:1.25rem">
  <h3 style="margin-top:0">Add / update secret</h3>
  <div class="toolbar" style="margin-bottom:0">
    <div class="field">
      <label for="nk">Key</label>
      <input id="nk" class="mono" placeholder="DB_PASSWORD" bind:value={newKey} />
    </div>
    <div class="field" style="flex:1">
      <label for="nv">Value</label>
      <input id="nv" class="mono" placeholder="••••••" bind:value={newValue} />
    </div>
    <div class="field">
      <label for="nkms">KMS key (optional)</label>
      <select id="nkms" bind:value={newKms}>
        <option value="">default</option>
        {#each kmsKeys as k}
          <option value={k.keyId}>{k.keyId}</option>
        {/each}
      </select>
    </div>
    <button class="btn btn-p" onclick={addSecret}>Save</button>
  </div>
</div>

<!-- detail drawer -->
{#if detail}
  <div
    class="drawer-scrim"
    role="button"
    tabindex="0"
    aria-label="Close details"
    onclick={closeDetail}
    onkeydown={(e) => e.key === 'Escape' && closeDetail()}
  ></div>
  <aside class="drawer">
    <div class="drawer-head">
      <div>
        <div class="mono drawer-title">{detail.key}</div>
        <div class="muted small">
          {detail.project}/{detail.env}{detail.path === '/' ? '' : detail.path}
        </div>
      </div>
      <button class="btn btn-sm" onclick={closeDetail}>✕</button>
    </div>

    <div class="kv">
      <div class="kv-row"><span class="kv-l">ARN</span><span class="kv-v mono">{detail.arn}</span></div>
      <div class="kv-row">
        <span class="kv-l">Status</span>
        <span class="kv-v">
          {#if detail.deletionDate}
            <span class="badge warn">scheduled deletion</span>
            <span class="muted small">
              {detail.deletionDate.replace('T', ' ').replace('Z', '')}</span
            >
          {:else}
            <span class="badge ok">active</span>
          {/if}
        </span>
      </div>
      <div class="kv-row">
        <span class="kv-l">Current version</span><span class="kv-v mono small"
          >{detail.currentVersionId}</span
        >
      </div>
      <div class="kv-row">
        <span class="kv-l">KMS key</span><span class="kv-v mono small">{detail.kmsKeyId || 'default'}</span>
      </div>
      <div class="kv-row">
        <span class="kv-l">Updated</span><span class="kv-v small"
          >{detail.updatedAt.replace('T', ' ').replace('Z', '')}</span
        >
      </div>
    </div>

    {#if detail.deletionDate}
      <button
        class="btn btn-sm"
        style="margin:0.5rem 0"
        onclick={() => detailAsItem() && restore(detailAsItem()!)}>Restore secret</button
      >
    {/if}

    <div class="tabs">
      <button class="tab" class:active={detailTab === 'overview'} onclick={() => (detailTab = 'overview')}
        >Overview</button
      >
      <button
        class="tab"
        class:active={detailTab === 'versions'}
        onclick={() => {
          detailTab = 'versions';
          loadVersions();
        }}>Versions</button
      >
      <button class="tab" class:active={detailTab === 'tags'} onclick={() => (detailTab = 'tags')}
        >Tags</button
      >
      <button class="tab" class:active={detailTab === 'policy'} onclick={() => (detailTab = 'policy')}
        >Policy</button
      >
      <button
        class="tab"
        class:active={detailTab === 'rotation'}
        onclick={() => (detailTab = 'rotation')}>Rotation</button
      >
    </div>

    {#if detailTab === 'overview'}
      <div class="tab-body">
        <div class="field block">
          <label for="md">Description</label>
          <input id="md" bind:value={metaDescription} />
        </div>
        <div class="field block">
          <label for="mk">KMS key</label>
          <select id="mk" bind:value={metaKms}>
            <option value="">default</option>
            {#each kmsKeys as k}
              <option value={k.keyId}>{k.keyId}</option>
            {/each}
          </select>
        </div>
        <button class="btn btn-p btn-sm" onclick={saveMetadata}>Save metadata</button>

        <hr />
        <div class="field block">
          <label for="nvv">Store new version (secret value)</label>
          <textarea
            id="nvv"
            class="mono"
            rows="3"
            placeholder={'{"password":"new-value"}'}
            bind:value={newVersionValue}
          ></textarea>
        </div>
        <button class="btn btn-p btn-sm" onclick={storeNewVersion}>Store new version</button>
      </div>
    {:else if detailTab === 'versions'}
      <div class="tab-body">
        <table>
          <thead><tr><th>Version</th><th>Stages</th><th>Created</th><th></th></tr></thead>
          <tbody>
            {#each versions as v}
              <tr>
                <td class="mono small">{v.versionId.slice(0, 12)}…</td>
                <td>
                  {#each v.stages as st}<span class="badge">{st}</span> {/each}
                </td>
                <td class="muted small">{v.createdAt.replace('T', ' ').replace('Z', '')}</td>
                <td>
                  {#if !v.stages.includes('AWSCURRENT')}
                    <button class="btn btn-sm" onclick={() => promote(v.versionId)}>Promote</button>
                  {/if}
                </td>
              </tr>
            {/each}
            {#if versions.length === 0}
              <tr><td colspan="4" class="empty">No versions loaded.</td></tr>
            {/if}
          </tbody>
        </table>
      </div>
    {:else if detailTab === 'tags'}
      <div class="tab-body">
        <table>
          <thead><tr><th>Key</th><th>Value</th><th></th></tr></thead>
          <tbody>
            {#each detail.tags as t}
              <tr>
                <td class="mono small">{t.key}</td>
                <td class="small">{t.value}</td>
                <td><button class="btn btn-sm btn-d" onclick={() => removeTag(t.key)}>Remove</button></td>
              </tr>
            {/each}
            {#if detail.tags.length === 0}
              <tr><td colspan="3" class="empty">No tags.</td></tr>
            {/if}
          </tbody>
        </table>
        <hr />
        <div class="toolbar" style="margin-bottom:0">
          <div class="field">
            <label for="tk">Key</label><input id="tk" bind:value={tagKey} placeholder="environment" />
          </div>
          <div class="field">
            <label for="tv">Value</label><input id="tv" bind:value={tagValue} placeholder="production" />
          </div>
          <button class="btn btn-p btn-sm" onclick={addTag}>Save tag</button>
        </div>
      </div>
    {:else if detailTab === 'policy'}
      <div class="tab-body">
        <div class="field block">
          <label for="pol">Resource policy (JSON)</label>
          <textarea id="pol" class="mono" rows="14" spellcheck="false" bind:value={policyDoc}></textarea>
        </div>
        <div class="rowact">
          <button class="btn btn-p btn-sm" onclick={savePolicy}>Save policy</button>
          <button class="btn btn-sm" onclick={formatPolicy}>Format JSON</button>
        </div>
      </div>
    {:else if detailTab === 'rotation'}
      <div class="tab-body">
        {#if detail.rotation.enabled}
          <div class="kv-row">
            <span class="kv-l">Rotation</span><span class="kv-v"><span class="badge ok">enabled</span></span>
          </div>
          {#if detail.rotation.nextRotationDate}
            <div class="kv-row">
              <span class="kv-l">Next</span><span class="kv-v small"
                >{detail.rotation.nextRotationDate.replace('T', ' ').replace('Z', '')}</span
              >
            </div>
          {/if}
          <button class="btn btn-sm btn-d" style="margin:0.5rem 0" onclick={cancelRotation}
            >Cancel rotation</button
          >
          <hr />
        {/if}
        <div class="field block">
          <label for="rl">Rotation Lambda ARN</label>
          <input id="rl" class="mono" placeholder="arn:aws:lambda:…" bind:value={rotLambda} />
        </div>
        <div class="field block">
          <label for="rd">Automatically after (days)</label>
          <input id="rd" bind:value={rotDays} />
        </div>
        <label class="chkline"
          ><input type="checkbox" bind:checked={rotImmediate} /> Rotate immediately (create AWSPENDING now)</label
        >
        <button class="btn btn-p btn-sm" onclick={saveRotation}>Save rotation config</button>
      </div>
    {/if}
  </aside>
{/if}

<!-- confirm modal -->
{#if confirmOpen}
  <div class="modal-scrim" role="presentation" onclick={() => (confirmOpen = false)}></div>
  <div class="modal" role="dialog" aria-modal="true">
    <h3 style="margin-top:0">{confirmTitle}</h3>
    <p class="muted">{confirmBody}</p>
    <div class="modal-act">
      <button class="btn" onclick={() => (confirmOpen = false)}>Cancel</button>
      <button class="btn {confirmDanger ? 'btn-d' : 'btn-p'}" onclick={runConfirm}>{confirmLabel}</button>
    </div>
  </div>
{/if}

<!-- prompt modal -->
{#if promptOpen}
  <div class="modal-scrim" role="presentation" onclick={() => (promptOpen = false)}></div>
  <div class="modal" role="dialog" aria-modal="true">
    <h3 style="margin-top:0">{promptTitle}</h3>
    <div class="field block">
      <label for="prompt-input">{promptLabel}</label>
      <!-- svelte-ignore a11y_autofocus -->
      <input
        id="prompt-input"
        bind:value={promptValue}
        autofocus
        onkeydown={(e) => e.key === 'Enter' && runPrompt()}
      />
    </div>
    <div class="modal-act">
      <button class="btn" onclick={() => (promptOpen = false)}>Cancel</button>
      <button class="btn btn-p" onclick={runPrompt}>Save</button>
    </div>
  </div>
{/if}

<style>
  .struct {
    border-top: 1px dashed var(--c-border);
    border-bottom: 1px dashed var(--c-border);
    padding: 0.75rem 0;
    margin-bottom: 0.75rem;
  }
  .struct .field input {
    min-width: 130px;
  }
  .manage-act {
    display: flex;
    align-items: flex-end;
    gap: 0.4rem;
    flex-wrap: wrap;
    margin-left: auto;
  }
  .bulkbar {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    margin-bottom: 0.5rem;
  }
  .badge.ok {
    background: #e7f6ec;
    color: var(--c-ok);
  }
  .badge.warn {
    background: #fef3c7;
    color: #b45309;
  }
  .linklike {
    background: none;
    border: none;
    color: var(--c-blue);
    cursor: pointer;
    padding: 0;
    font: inherit;
  }
  .linklike:hover {
    text-decoration: underline;
  }
  .rowsel {
    background: #f3f8fd;
  }
  .rowact {
    white-space: nowrap;
    display: flex;
    gap: 0.35rem;
  }
  .chk {
    min-width: auto;
  }
  .small {
    font-size: 0.8rem;
  }

  .drawer-scrim {
    position: fixed;
    inset: 0;
    background: rgba(15, 20, 30, 0.35);
    z-index: 40;
    border: none;
  }
  .drawer {
    position: fixed;
    top: 0;
    right: 0;
    height: 100vh;
    width: min(560px, 92vw);
    background: var(--c-surface);
    border-left: 1px solid var(--c-border);
    box-shadow: -8px 0 24px rgba(15, 20, 30, 0.12);
    z-index: 41;
    padding: 1.25rem;
    overflow-y: auto;
  }
  .drawer-head {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    margin-bottom: 1rem;
  }
  .drawer-title {
    font-size: 1.1rem;
    font-weight: 700;
  }
  .kv {
    border: 1px solid var(--c-border);
    border-radius: var(--radius);
    padding: 0.5rem 0.75rem;
  }
  .kv-row {
    display: flex;
    gap: 0.75rem;
    padding: 0.3rem 0;
    border-bottom: 1px solid var(--c-border);
  }
  .kv-row:last-child {
    border-bottom: none;
  }
  .kv-l {
    width: 130px;
    color: var(--c-muted);
    font-size: 0.78rem;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    flex-shrink: 0;
  }
  .kv-v {
    word-break: break-all;
    flex: 1;
  }
  .tabs {
    display: flex;
    gap: 0.25rem;
    border-bottom: 1px solid var(--c-border);
    margin: 1rem 0 0.75rem;
    flex-wrap: wrap;
  }
  .tab {
    background: none;
    border: none;
    border-bottom: 2px solid transparent;
    padding: 0.5rem 0.7rem;
    cursor: pointer;
    color: var(--c-muted);
    font: inherit;
  }
  .tab.active {
    color: var(--c-text);
    border-bottom-color: var(--c-blue);
    font-weight: 600;
  }
  .tab-body {
    padding-top: 0.25rem;
  }
  .field.block {
    display: block;
    margin-bottom: 0.75rem;
  }
  .field.block input,
  .field.block select,
  .field.block textarea {
    width: 100%;
  }
  textarea {
    font: inherit;
    padding: 0.45rem 0.6rem;
    border: 1px solid var(--c-border);
    border-radius: 6px;
    width: 100%;
    resize: vertical;
  }
  .chkline {
    display: flex;
    align-items: center;
    gap: 0.4rem;
    font-size: 0.85rem;
    margin-bottom: 0.75rem;
  }
  .chkline input {
    min-width: auto;
  }
  hr {
    border: none;
    border-top: 1px solid var(--c-border);
    margin: 1rem 0;
  }

  .modal-scrim {
    position: fixed;
    inset: 0;
    background: rgba(15, 20, 30, 0.35);
    z-index: 50;
  }
  .modal {
    position: fixed;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    background: var(--c-surface);
    border: 1px solid var(--c-border);
    border-radius: var(--radius);
    padding: 1.25rem;
    width: min(460px, 92vw);
    z-index: 51;
    box-shadow: 0 12px 32px rgba(15, 20, 30, 0.2);
  }
  .modal-act {
    display: flex;
    justify-content: flex-end;
    gap: 0.5rem;
    margin-top: 1rem;
  }
</style>
