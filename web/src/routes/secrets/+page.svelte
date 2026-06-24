<script lang="ts">
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import { base } from '$app/paths';
  import { api, ApiError, type Project } from '$lib/api';

  let projects: Project[] = $state([]);
  let loading = $state(true);
  let flash = $state('');
  let flashOk = $state(true);

  let newProjectSlug = $state('');

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

  async function createProject() {
    const slug = newProjectSlug.trim();
    if (!slug) {
      notify('enter a project name', false);
      return;
    }
    try {
      await api.createProject(slug, slug);
      notify(`Created project ${slug}`);
      newProjectSlug = '';
      await load();
    } catch (e) {
      err(e);
    }
  }

  function renameProject(slug: string) {
    askPrompt({
      title: `Rename project "${slug}"`,
      label: 'Display name',
      value: slug,
      action: async (name) => {
        try {
          await api.renameProject(slug, name.trim());
          notify(`Renamed project ${slug}`);
          await load();
        } catch (e) {
          err(e);
        }
      }
    });
  }

  function deleteProject(slug: string) {
    askConfirm({
      title: `Delete project "${slug}"?`,
      body: 'This removes the project and its empty environments/folders. It is refused while any secret still exists under it.',
      label: 'Delete project',
      action: async () => {
        try {
          await api.deleteProject(slug);
          notify(`Deleted project ${slug}`);
          await load();
        } catch (e) {
          err(e);
        }
      }
    });
  }

  function openProject(slug: string) {
    goto(`${base}/secrets/${encodeURIComponent(slug)}`);
  }

  onMount(load);
</script>

<div class="ph">
  <h1 class="ph-title">Secrets</h1>
  <p class="ph-sub">
    Organize secrets by project, environment, and folder. Items remain readable through the
    AWS Secrets Manager API for ESO and SDK clients.
  </p>
</div>

{#if flash}
  <div class="flash {flashOk ? 'ok' : 'err'}">{flash}</div>
{/if}

<div class="card">
  <div class="toolbar" style="margin-bottom:0; align-items:flex-end">
    <h3 style="margin:0; flex:1">Projects</h3>
    <div class="field">
      <label for="np">New project</label>
      <input id="np" placeholder="prod" bind:value={newProjectSlug} onkeydown={(e) => e.key === 'Enter' && createProject()} />
    </div>
    <button class="btn btn-p" onclick={createProject}>+ Project</button>
  </div>
</div>

<div class="card" style="margin-top:1.25rem">
  {#if loading}
    <div class="empty">Loading…</div>
  {:else if projects.length === 0}
    <div class="empty">No projects yet. Create one above.</div>
  {:else}
    <table>
      <thead>
        <tr><th>Project</th><th>Environments</th><th></th></tr>
      </thead>
      <tbody>
        {#each projects as p}
          <tr>
            <td><button class="linklike" onclick={() => openProject(p.slug)}>{p.slug}</button></td>
            <td>
              {#if p.environments.length === 0}
                <span class="muted">none</span>
              {:else}
                {#each p.environments as e}
                  <span class="badge env">{e}</span>
                {/each}
              {/if}
            </td>
            <td>
              <div class="rowact">
                <button class="btn btn-sm" onclick={() => openProject(p.slug)}>Open</button>
                <button class="btn btn-sm" onclick={() => renameProject(p.slug)}>Rename</button>
                <button class="btn btn-sm btn-d" onclick={() => deleteProject(p.slug)}>Delete</button>
              </div>
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
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
  .badge.env {
    margin-right: 0.3rem;
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
