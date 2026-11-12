<!-- Inline editor for a secret's description and KMS key. -->
<script lang="ts">
  import { api, type KMSKey } from '$lib/api';
  import { toast } from '$lib/stores/toast.svelte';
  import type { SecretDetail } from '../../api';
  import { findKms, kmsLabel } from './kms';

  let {
    detail,
    kmsKeys,
    oncancel,
    onsaved
  }: {
    detail: SecretDetail;
    kmsKeys: KMSKey[];
    oncancel: () => void;
    onsaved: () => void;
  } = $props();

  let description = $state('');
  let kms = $state('');
  let busy = $state(false);

  $effect.pre(() => {
    description = detail.description ?? '';
    kms = findKms(kmsKeys, detail.kmsKeyId)?.keyId ?? detail.kmsKeyId ?? '';
  });

  const knownKms = $derived(!kms || kmsKeys.some((k) => k.keyId === kms));

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    busy = true;
    try {
      await api.updateSecretMetadata({
        project: detail.project,
        env: detail.env,
        path: detail.path,
        key: detail.key,
        description: description.trim(),
        kmsKeyId: kms
      });
      toast.success('Saved details');
      onsaved();
    } catch (err) {
      toast.error(err, 'Could not save details');
    } finally {
      busy = false;
    }
  }
</script>

<form class="inline-form" onsubmit={submit}>
  <label class="field">
    <span class="field-label">Description</span>
    <textarea class="textarea" rows="2" bind:value={description} placeholder="What uses this secret?"></textarea>
  </label>
  <label class="field">
    <span class="field-label">KMS key</span>
    <select class="select" bind:value={kms}>
      <option value="">Account default</option>
      {#if !knownKms}<option value={kms}>{kms}</option>{/if}
      {#each kmsKeys as k (k.keyId)}
        <option value={k.keyId}>{kmsLabel(k)}</option>
      {/each}
    </select>
    <span class="field-hint">New versions are encrypted with this key. To re-encrypt existing versions, use “Re-encrypt” on the environment.</span>
  </label>
  <div class="actions">
    <button type="button" class="btn btn-ghost btn-sm" onclick={oncancel}>Cancel</button>
    <button type="submit" class="btn btn-primary btn-sm" disabled={busy}>Save details</button>
  </div>
</form>

<style>
  .inline-form {
    display: flex;
    flex-direction: column;
    padding: var(--space-3);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: var(--surface-hover);
  }
  .textarea {
    min-height: 56px;
    font-family: var(--font-sans);
  }
  .actions {
    display: flex;
    justify-content: flex-end;
    gap: var(--space-2);
    margin-top: var(--space-3);
  }
</style>
