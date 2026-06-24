<script lang="ts">
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import { base } from '$app/paths';
  import { page } from '$app/stores';
  import { api, ApiError, type Project } from '$lib/api';

  const project = $derived($page.params.project ?? '');

  let projects: Project[] = $state([]);
  let loading = $state(true);
  let flash = $state('');
  let flashOk = $state(true);

  let newEnvSlug = $state('');

  // Confirm modal
  let confirmOpen = $state(false);
  let confirmTitle = $state('');
  let confirmBody = $state('');
  let confirmLabel = $state('Confirm');
  let confirmAction: (() => Promise<void>) | null = $state(null);

  // Prompt modal
  let promptOpen = $state(false);
  let promptTitle = $state('');
  let promptLabel = $state('');
  let promptValue = $state('');
  let promptAction: ((value: string) => Promise<void>) | null = $state(null);

  const current = $derived(projects.find((p) => p.slug === project));
  const envs = $derived(current?.environments ?? []);

  function notify(msg: string, ok = true) {
    flash = msg;
    flashOk = ok;
    setTimeout(() => (flash = ''), 4000);
  }

  function err(e: unknown) {
    if (e instanceof ApiError) notify(e.message, false);
    else notify('Unexpected error', false);
  }

  function askConfirm(opts: { title: string; body: string; label?: string; action: () => Promise<void> }) {
    confirmTitle = opts.title;
    confirmBody = opts.body;
    confirmLabel = opts.label ?? 'Confirm';
    confirmAction = opts.action;
    confirmOpen = true;
  }

  async function runConfirm() {
    const action = confirmAction;
    confirmOpen = false;
    if (action) await action();
    confirmAction = null;
  }

  function askPrompt(opts: { title: string; label: string; value?: string; action: (v: string) => Promise<void> }) {
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

  async function load() {
    loading = true;
    try {
      projects = (await api.projects()).projects;
    } catch (e) {
      err(e);
    } finally {
      loading = false;
    }
  }

  async function createEnvironment() {
    const slug = newEnvSlug.trim();
    if (!slug) {
      notify('enter an environment name', false);
      return;
    }
    try {
      await api.createEnvironment(project, slug, slug);
      notify(`Created environment ${slug}`);
      newEnvSlug = '';
      await load();
    } catch (e) {
      err(e);
    }
  }

  function renameProject() {
    askPrompt({
      title: `Rename project "${project}"`,
      label: 'Display name',
      value: project,
      action: async (name) => {
        try {
          await api.renameProject(project, name.trim());
          notify(`Renamed project ${project}`);
          await load();
        } catch (e) {
          err(e);
        }
      }
    });
  }

  function deleteProject() {
    askConfirm({
      title: `Delete project "${project}"?`,
      body: 'This removes the project and its empty environments/folders. It is refused while any secret still exists under it.',
      label: 'Delete project',
      action: async () => {
        try {
          await api.deleteProject(project);
          notify(`Deleted project ${project}`);
          goto(`${base}/`);
        } catch (e) {
          err(e);
        }
      }
    });
  }

  function renameEnvironment(envSlug: string) {
    askPrompt({
      title: `Rename environment "${envSlug}"`,
      label: 'Display name',
      value: envSlug,
      action: async (name) => {
        try {
          await api.renameEnvironment(project, envSlug, name.trim());
          notify(`Renamed environment ${envSlug}`);
          await load();
        } catch (e) {
          err(e);
        }
      }
    });
  }

  function deleteEnvironment(envSlug: string) {
    askConfirm({
      title: `Delete environment "${envSlug}"?`,
      body: 'This removes the environment and its empty folders. It is refused while any secret still exists under it.',
      label: 'Delete environment',
      action: async () => {
        try {
          await api.deleteEnvironment(project, envSlug);
          notify(`Deleted environment ${envSlug}`);
          await load();
        } catch (e) {
          err(e);
        }
      }
    });
  }

  function openEnv(envSlug: string) {
    goto(`${base}/secrets/${encodeURIComponent(project)}/${encodeURIComponent(envSlug)}`);
  }

  onMount(load);
</script>

<div class="crumbs" style="margin-bottom:0.5rem">
  <a href={`${base}/`}>Projects</a>
  / <span class="cur">{project}</span>
</div>

<div class="ph">
  <h1 class="ph-title">{project}</h1>
  <p class="ph-sub">Environments in this project. Open one to manage its folders and secrets.</p>
</div>

{#if flash}
  <div class="flash {flashOk ? 'ok' : 'err'}">{flash}</div>
{/if}

<div class="card">
  <div class="toolbar" style="margin-bottom:0; align-items:flex-end">
    <h3 style="margin:0; flex:1">Environments</h3>
    <button class="btn btn-sm" onclick={renameProject}>Rename project</button>
    <button class="btn btn-sm btn-d" onclick={deleteProject}>Delete project</button>
  </div>
</div>

<div class="card" style="margin-top:1.25rem">
  {#if loading}
    <div class="empty">Loading…</div>
  {:else if !current}
    <div class="empty">Project not found.</div>
  {:else if envs.length === 0}
    <div class="empty">No environments yet. Create one below.</div>
  {:else}
    <table>
      <thead>
        <tr><th>Environment</th><th></th></tr>
      </thead>
      <tbody>
        {#each envs as e}
          <tr>
            <td><button class="linklike" onclick={() => openEnv(e)}>{e}</button></td>
            <td>
              <div class="rowact">
                <button class="btn btn-sm" onclick={() => openEnv(e)}>Open</button>
                <button class="btn btn-sm" onclick={() => renameEnvironment(e)}>Rename</button>
                <button class="btn btn-sm btn-d" onclick={() => deleteEnvironment(e)}>Delete</button>
              </div>
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
</div>

<div class="card" style="margin-top:1.25rem">
  <h3 style="margin-top:0">Create environment</h3>
  <div class="toolbar" style="margin-bottom:0; align-items:flex-end">
    <div class="field" style="flex:1">
      <label for="ne">Name</label>
      <input id="ne" placeholder="staging" bind:value={newEnvSlug} />
    </div>
    <button class="btn btn-p" onclick={createEnvironment}>+ Environment</button>
  </div>
</div>

<!-- confirm modal -->
{#if confirmOpen}
  <div class="modal-scrim" role="presentation" onclick={() => (confirmOpen = false)}></div>
  <div class="modal" role="dialog" aria-modal="true">
    <h3 style="margin-top:0">{confirmTitle}</h3>
    <p class="muted">{confirmBody}</p>
    <div class="modal-act">
      <button class="btn" onclick={() => (confirmOpen = false)}>Cancel</button>
      <button class="btn btn-d" onclick={runConfirm}>{confirmLabel}</button>
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
  .crumbs a {
    color: var(--c-blue);
    text-decoration: none;
  }
  .crumbs a:hover {
    text-decoration: underline;
  }
  .crumbs .cur {
    color: var(--c-text);
    font-weight: 600;
  }
  .linklike {
    background: none;
    border: none;
    color: var(--c-blue);
    cursor: pointer;
    padding: 0;
    font: inherit;
    font-weight: 600;
  }
  .linklike:hover {
    text-decoration: underline;
  }
  .rowact {
    white-space: nowrap;
    display: flex;
    gap: 0.35rem;
    justify-content: flex-end;
  }
  .field.block {
    display: block;
    margin-bottom: 0.75rem;
  }
  .field.block input {
    width: 100%;
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
