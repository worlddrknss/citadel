<!-- Copy selected secrets to another environment, or move them to another
     folder of this one. -->
<script lang="ts">
  import Icon from '#lib/components/Icon.svelte';
  import Modal from '#lib/components/Modal.svelte';
  import { envLabel, normPath } from '../../lib';

  let {
    open = $bindable(false),
    mode,
    keys,
    env,
    envs,
    defaultTarget,
    path,
    approvalEnvs,
    onsubmit
  }: {
    open?: boolean;
    mode: 'copy' | 'move';
    keys: string[];
    env: string;
    envs: string[];
    defaultTarget: string;
    path: string;
    /** Environments where writes become change requests. */
    approvalEnvs: Set<string>;
    onsubmit: (r: { targetEnv: string; targetPath: string; overwrite: boolean }) => Promise<boolean>;
  } = $props();

  let targetEnv = $state('');
  let targetPath = $state('/');
  let overwrite = $state(false);
  let busy = $state(false);

  $effect(() => {
    if (open) {
      targetEnv = mode === 'copy' ? defaultTarget : env;
      targetPath = path;
      overwrite = false;
    }
  });

  const norm = $derived(normPath(targetPath));
  const pathOk = $derived(norm.split('/').filter(Boolean).every((s) => /^[A-Za-z0-9_.-]+$/.test(s)));
  const same = $derived(mode === 'move' && norm === path);
  const blocked = $derived(!pathOk || same || (mode === 'copy' && !targetEnv));

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    if (blocked) return;
    busy = true;
    try {
      if (await onsubmit({ targetEnv, targetPath: norm, overwrite })) open = false;
    } finally {
      busy = false;
    }
  }
</script>

<Modal
  bind:open
  title={mode === 'copy' ? `Copy ${keys.length} secret${keys.length === 1 ? '' : 's'}` : `Move ${keys.length} secret${keys.length === 1 ? '' : 's'}`}
  description={mode === 'copy'
    ? 'Copies the current value, tags, description and KMS key. Version history stays here.'
    : 'Moves keys with their version history, tags and policy. Clients reading the old names stop finding them.'}
  size="sm"
>
  <form id="cm-form" onsubmit={submit}>
    {#if mode === 'copy'}
      <label class="field">
        <span class="field-label">Target environment</span>
        <select class="select" bind:value={targetEnv}>
          {#each envs.filter((e) => e !== env) as e (e)}
            <option value={e}>{envLabel(e)}{envLabel(e) !== e ? ` (${e})` : ''}</option>
          {/each}
        </select>
      </label>
    {/if}
    <label class="field">
      <span class="field-label">Target folder</span>
      <input class="input mono" bind:value={targetPath} placeholder="/" autocomplete="off" spellcheck="false" aria-invalid={!pathOk} />
      <span class={pathOk ? 'field-hint' : 'field-error'}>
        {#if !pathOk}Folder names use letters, digits, dots, dashes and underscores.{:else if same}Choose a different folder.{:else}Missing folders are created.{/if}
      </span>
    </label>
    {#if mode === 'copy'}
      <label class="check">
        <input type="checkbox" bind:checked={overwrite} />
        <span>Overwrite keys that already exist there (adds a new version)</span>
      </label>
      {#if approvalEnvs.has(targetEnv)}
        <div class="callout callout-warning">
          <Icon name="lock" size={16} />
          <span>{envLabel(targetEnv)} requires approval, so each key opens a change request there instead of being written.</span>
        </div>
      {/if}
    {/if}
  </form>
  {#snippet footer()}
    <button type="button" class="btn btn-secondary" onclick={() => (open = false)}>Cancel</button>
    <button type="submit" form="cm-form" class="btn btn-primary" disabled={busy || blocked}>
      {mode === 'copy' ? `Copy to ${envLabel(targetEnv || '…')}` : 'Move'}
    </button>
  {/snippet}
</Modal>

<style>
  .check {
    display: flex;
    align-items: flex-start;
    gap: var(--space-2);
    margin-top: var(--space-4);
    font-size: var(--text-sm);
    cursor: pointer;
  }
  .check input {
    margin-top: 2px;
  }
  .callout {
    margin-top: var(--space-4);
  }
</style>
