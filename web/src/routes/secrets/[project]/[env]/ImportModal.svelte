<!--
  Import a .env file into the current folder: paste or pick a file, review
  which keys are new or updated, then write them (or open change requests in
  environments that require approval).
-->
<script lang="ts">
  import { api } from '$lib/api';
  import Icon from '$lib/components/Icon.svelte';
  import Modal from '$lib/components/Modal.svelte';
  import { toast } from '$lib/stores/toast.svelte';
  import { parseDotenv } from './dotenv';
  import SecretInput from './SecretInput.svelte';

  let {
    open = $bindable(false),
    project,
    env,
    path,
    existingKeys,
    requireApproval,
    ondone
  }: {
    open?: boolean;
    project: string;
    env: string;
    path: string;
    existingKeys: string[];
    requireApproval: boolean;
    ondone: () => void;
  } = $props();

  let text = $state('');
  let skipExisting = $state(false);
  let busy = $state(false);
  let done = $state(0);
  let fileInput = $state<HTMLInputElement>();

  $effect(() => {
    if (open) {
      text = '';
      skipExisting = false;
      done = 0;
    }
  });

  const parsed = $derived(parseDotenv(text));
  const valid = $derived(parsed.entries.filter((e) => /^[A-Za-z0-9_.-]+$/.test(e.key)));
  const invalid = $derived(parsed.entries.filter((e) => !/^[A-Za-z0-9_.-]+$/.test(e.key)));
  const toWrite = $derived(valid.filter((e) => !(skipExisting && existingKeys.includes(e.key))));
  const updates = $derived(valid.filter((e) => existingKeys.includes(e.key)).length);

  async function pickFile(e: Event) {
    const f = (e.currentTarget as HTMLInputElement).files?.[0];
    if (!f) return;
    if (f.size > 1024 * 1024) {
      toast.error('That file is larger than 1 MB.');
      return;
    }
    text = await f.text();
  }

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    if (!toWrite.length) return;
    busy = true;
    done = 0;
    const failed: string[] = [];
    for (const entry of toWrite) {
      try {
        if (requireApproval) await api.createChangeRequest({ project, env, path, key: entry.key, value: entry.value });
        else await api.put({ project, env, path, key: entry.key, value: entry.value });
      } catch {
        failed.push(entry.key);
      }
      done++;
    }
    busy = false;
    const ok = toWrite.length - failed.length;
    const verb = requireApproval ? 'Opened change requests for' : 'Imported';
    if (failed.length) toast.error(`${verb} ${ok} of ${toWrite.length}. Failed: ${failed.slice(0, 5).join(', ')}${failed.length > 5 ? '…' : ''}`);
    else toast.success(`${verb} ${ok} secret${ok === 1 ? '' : 's'}`);
    text = '';
    open = false;
    ondone();
  }
</script>

<Modal
  bind:open
  title="Import .env"
  description="Adds each KEY=VALUE line to {path === '/' ? 'the environment root' : path} as a secret."
  size="md"
>
  <form id="import-form" class="form" onsubmit={submit}>
    {#if requireApproval}
      <div class="callout callout-warning">
        <Icon name="lock" size={16} />
        <span>This environment requires approval: each key opens its own change request.</span>
      </div>
    {/if}
    <div class="field">
      <div class="label-row">
        <label class="field-label" for="import-text">Contents</label>
        <button type="button" class="btn btn-ghost btn-sm" onclick={() => fileInput?.click()}>
          <Icon name="upload" size={14} />Choose file…
        </button>
        <input bind:this={fileInput} class="sr-only" type="file" accept=".env,text/plain,*/*" tabindex="-1" onchange={pickFile} />
      </div>
      <SecretInput id="import-text" bind:value={text} rows={8} placeholder={'DATABASE_URL=postgres://…\nSTRIPE_KEY="sk_live_…"'} />
    </div>
    {#if text.trim()}
      <div class="summary" aria-live="polite">
        <span><strong class="num">{valid.length}</strong> key{valid.length === 1 ? '' : 's'} found</span>
        {#if updates}<span class="badge badge-warning">{updates} already exist</span>{/if}
        {#if invalid.length}<span class="badge badge-danger" title={invalid.map((e) => e.key).join(', ')}>{invalid.length} invalid key name{invalid.length === 1 ? '' : 's'} skipped</span>{/if}
        {#if parsed.errors.length}<span class="badge badge-danger">Lines {parsed.errors.slice(0, 5).join(', ')} unreadable</span>{/if}
      </div>
      {#if valid.length}
        <ul class="keys mono">
          {#each valid as e (e.line)}
            <li>
              <span>{e.key}</span>
              {#if existingKeys.includes(e.key)}
                <span class="subtle small">{skipExisting ? 'skip' : 'new version'}</span>
              {:else}
                <span class="small new">new</span>
              {/if}
            </li>
          {/each}
        </ul>
      {/if}
      {#if updates}
        <label class="check">
          <input type="checkbox" bind:checked={skipExisting} />
          <span>Skip keys that already exist</span>
        </label>
      {/if}
    {/if}
  </form>
  {#snippet footer()}
    {#if busy}<span class="subtle small progress num">{done} / {toWrite.length}</span>{/if}
    <button type="button" class="btn btn-secondary" onclick={() => (open = false)} disabled={busy}>Cancel</button>
    <button type="submit" form="import-form" class="btn btn-primary" disabled={busy || toWrite.length === 0}>
      {requireApproval ? `Request ${toWrite.length}` : `Import ${toWrite.length}`}
    </button>
  {/snippet}
</Modal>

<style>
  .form {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
  }
  .label-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
  }
  .summary {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--space-2);
    font-size: var(--text-sm);
  }
  .keys {
    margin: 0;
    padding: var(--space-1) 0;
    list-style: none;
    max-height: 180px;
    overflow: auto;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    font-size: var(--text-sm);
  }
  .keys li {
    display: flex;
    justify-content: space-between;
    gap: var(--space-3);
    padding: 4px var(--space-3);
  }
  .new {
    color: var(--success);
  }
  .check {
    display: flex;
    gap: var(--space-2);
    align-items: center;
    font-size: var(--text-sm);
    cursor: pointer;
  }
  .progress {
    margin-right: auto;
  }
</style>
