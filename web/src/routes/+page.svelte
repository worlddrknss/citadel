<script lang="ts">
  import { onMount } from 'svelte';
  import { api, ApiError, type Project, type Item } from '$lib/api';

  let projects: Project[] = $state([]);
  let project = $state('');
  let env = $state('');
  let path = $state('/');

  let folders: string[] = $state([]);
  let items: Item[] = $state([]);
  let revealed: Record<string, string> = $state({});

  let flash = $state('');
  let flashOk = $state(true);
  let loading = $state(false);

  // New-secret form
  let newKey = $state('');
  let newValue = $state('');

  const envs = $derived(projects.find((p) => p.slug === project)?.environments ?? []);

  function notify(msg: string, ok = true) {
    flash = msg;
    flashOk = ok;
    setTimeout(() => (flash = ''), 4000);
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
      if (e instanceof ApiError) notify(e.message, false);
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
    } catch (e) {
      if (e instanceof ApiError) notify(e.message, false);
    } finally {
      loading = false;
    }
  }

  async function reveal(it: Item) {
    try {
      const res = await api.reveal(it.project, it.env, it.path, it.key);
      revealed = { ...revealed, [it.key]: res.value ?? '(binary)' };
    } catch (e) {
      if (e instanceof ApiError) notify(e.message, false);
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
      const res = await api.put({ project, env, path, key: newKey.trim(), value: newValue });
      notify(res.created ? `Created ${newKey}` : `Updated ${newKey}`);
      newKey = '';
      newValue = '';
      await loadItems();
    } catch (e) {
      if (e instanceof ApiError) notify(e.message, false);
    }
  }

  async function removeSecret(it: Item) {
    if (!confirm(`Delete ${it.key}?`)) return;
    try {
      await api.remove(it.project, it.env, it.path, it.key);
      notify(`Deleted ${it.key}`);
      await loadItems();
    } catch (e) {
      if (e instanceof ApiError) notify(e.message, false);
    }
  }

  function openFolder(name: string) {
    path = path === '/' ? `/${name}` : `${path}/${name}`;
    loadItems();
  }

  function crumbTo(idx: number) {
    const segs = path.split('/').filter(Boolean);
    path = idx < 0 ? '/' : '/' + segs.slice(0, idx + 1).join('/');
    loadItems();
  }

  $effect(() => {
    // Reload whenever project/env changes.
    void project;
    void env;
    path = '/';
    loadItems();
  });

  onMount(loadProjects);

  const crumbSegs = $derived(path.split('/').filter(Boolean));
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
    <div class="field" style="flex:1">
      <label for="newproj">Or create a new path</label>
      <input
        id="newproj"
        placeholder="project (type then add a key below)"
        bind:value={project}
      />
    </div>
  </div>

  <div class="crumbs" style="margin-bottom:0.75rem">
    <span onclick={() => crumbTo(-1)} role="button" tabindex="0" onkeydown={() => {}}
      >{project || '—'}/{env || '—'}</span
    >
    {#each crumbSegs as seg, i}
      / <span onclick={() => crumbTo(i)} role="button" tabindex="0" onkeydown={() => {}}>{seg}</span>
    {/each}
  </div>

  {#if loading}
    <div class="empty">Loading…</div>
  {:else}
    <table>
      <thead>
        <tr>
          <th>Key</th>
          <th>Value</th>
          <th>Updated</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        {#each folders as f}
          <tr>
            <td>
              <button class="btn btn-sm" onclick={() => openFolder(f)}>📁 {f}/</button>
            </td>
            <td class="muted">folder</td>
            <td></td>
            <td></td>
          </tr>
        {/each}
        {#each items as it}
          <tr>
            <td class="mono">{it.key}</td>
            <td class="mono">
              {#if revealed[it.key] !== undefined}
                {revealed[it.key]}
                <button class="btn btn-sm" onclick={() => hide(it.key)}>Hide</button>
              {:else}
                <span class="muted">••••••••</span>
                <button class="btn btn-sm" onclick={() => reveal(it)}>Reveal</button>
              {/if}
            </td>
            <td class="muted">{it.updatedAt?.replace('T', ' ').replace('Z', '')}</td>
            <td>
              <button class="btn btn-sm btn-d" onclick={() => removeSecret(it)}>Delete</button>
            </td>
          </tr>
        {/each}
        {#if folders.length === 0 && items.length === 0}
          <tr><td colspan="4" class="empty">No secrets at this path yet.</td></tr>
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
    <button class="btn btn-p" onclick={addSecret}>Save</button>
  </div>
</div>
