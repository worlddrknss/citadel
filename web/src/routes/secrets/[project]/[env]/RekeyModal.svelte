<!-- Re-encrypt every secret in the environment under another KMS key. -->
<script lang="ts">
  import { api, type KMSKey } from '$lib/api';
  import Modal from '$lib/components/Modal.svelte';
  import { toast } from '$lib/stores/toast.svelte';
  import { kmsLabel } from './kms';

  let {
    open = $bindable(false),
    project,
    env,
    kmsKeys,
    ondone
  }: {
    open?: boolean;
    project: string;
    env: string;
    kmsKeys: KMSKey[];
    ondone: () => void;
  } = $props();

  let target = $state('');
  let busy = $state(false);

  $effect(() => {
    if (open) target = '';
  });

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    if (!target) return;
    busy = true;
    try {
      const res = await api.rekeySecret({ project, env, kmsKeyId: target });
      if (res.failed.length) toast.error(`Re-encrypted ${res.rekeyed}; ${res.failed.length} failed: ${res.failed.slice(0, 3).join(', ')}`);
      else toast.success(`Re-encrypted ${res.rekeyed} secret${res.rekeyed === 1 ? '' : 's'}`);
      open = false;
      ondone();
    } catch (err) {
      toast.error(err, 'Could not re-encrypt');
    } finally {
      busy = false;
    }
  }
</script>

<Modal
  bind:open
  title="Re-encrypt with another KMS key"
  description="Every active secret in {project}/{env} gets a new version sealed with the selected key. Values don't change, and clients keep reading the latest version."
  size="sm"
>
  <form id="rekey-form" onsubmit={submit}>
    <label class="field">
      <span class="field-label">KMS key</span>
      <select class="select" bind:value={target} required>
        <option value="" disabled>Select a key…</option>
        {#each kmsKeys as k (k.keyId)}
          <option value={k.keyId}>{kmsLabel(k)}</option>
        {/each}
      </select>
      {#if kmsKeys.length === 0}
        <span class="field-hint">No enabled symmetric keys found. Create one under KMS keys first.</span>
      {/if}
    </label>
  </form>
  {#snippet footer()}
    <button type="button" class="btn btn-secondary" onclick={() => (open = false)} disabled={busy}>Cancel</button>
    <button type="submit" form="rekey-form" class="btn btn-primary" disabled={busy || !target}>
      {busy ? 'Re-encrypting…' : 'Re-encrypt'}
    </button>
  {/snippet}
</Modal>
