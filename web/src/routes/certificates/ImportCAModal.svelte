<!-- Import an externally generated CA certificate with its private key. -->
<script lang="ts">
  import Modal from '#lib/components/Modal.svelte';
  import Icon from '#lib/components/Icon.svelte';
  import { api, errorMessage } from '#lib/api.ts';
  import { toast } from '#lib/stores/toast.svelte.ts';

  let { open = $bindable(false), onimported }: { open?: boolean; onimported: (caId: string) => void } = $props();

  let description = $state('');
  let certPem = $state('');
  let keyPem = $state('');
  let busy = $state(false);
  let error = $state('');
  let touched = $state(false);

  $effect(() => {
    if (!open) return;
    description = '';
    certPem = '';
    keyPem = '';
    error = '';
    touched = false;
  });

  const certError = $derived(/-----BEGIN CERTIFICATE-----/.test(certPem) ? '' : 'Paste the CA certificate in PEM form.');
  const keyError = $derived(/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(keyPem) ? '' : 'Paste the matching private key in PEM form.');

  async function readFile(e: Event, set: (v: string) => void) {
    const f = (e.currentTarget as HTMLInputElement).files?.[0];
    if (f) set(await f.text());
  }

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    touched = true;
    if (certError || keyError) return;
    busy = true;
    error = '';
    try {
      const r = await api.importCA({ caCertPem: certPem.trim(), caKeyPem: keyPem.trim(), description: description.trim() });
      toast.success('CA imported');
      keyPem = '';
      open = false;
      onimported(r.caId);
    } catch (err) {
      error = errorMessage(err, 'Could not import the CA.');
    } finally {
      busy = false;
    }
  }
</script>

<Modal bind:open title="Import certificate authority" description="Bring an existing CA into Citadel so it can issue certificates. The key is moved into KMS." size="lg">
  <form id="import-form" class="form" onsubmit={submit} novalidate>
    <div class="field">
      <label class="field-label" for="im-desc">Description <span class="subtle">(optional)</span></label>
      <input id="im-desc" class="input" bind:value={description} placeholder="Corporate issuing CA" autocomplete="off" />
    </div>
    <div class="field">
      <div class="lrow">
        <label class="field-label" for="im-cert">CA certificate (PEM)</label>
        <label class="btn btn-ghost btn-sm file"><Icon name="upload" size={14} />From file<input type="file" accept=".pem,.crt,.cer" class="sr-only" onchange={(e) => readFile(e, (v) => (certPem = v))} /></label>
      </div>
      <textarea id="im-cert" class="textarea mono" rows="6" bind:value={certPem} spellcheck="false" placeholder="-----BEGIN CERTIFICATE-----" aria-invalid={touched && !!certError}></textarea>
      {#if touched && certError}<span class="field-error">{certError}</span>{:else}<span class="field-hint">Must have basicConstraints CA:TRUE.</span>{/if}
    </div>
    <div class="field">
      <div class="lrow">
        <label class="field-label" for="im-key">Private key (PEM)</label>
        <label class="btn btn-ghost btn-sm file"><Icon name="upload" size={14} />From file<input type="file" accept=".pem,.key" class="sr-only" onchange={(e) => readFile(e, (v) => (keyPem = v))} /></label>
      </div>
      <textarea id="im-key" class="textarea mono" rows="6" bind:value={keyPem} spellcheck="false" autocomplete="off" placeholder="-----BEGIN PRIVATE KEY-----" aria-invalid={touched && !!keyError}></textarea>
      {#if touched && keyError}<span class="field-error">{keyError}</span>{:else}<span class="field-hint">Must match the certificate's public key. It is never shown again.</span>{/if}
    </div>
    {#if error}
      <div class="callout callout-danger" role="alert"><Icon name="alert-circle" size={16} /><span>{error}</span></div>
    {/if}
  </form>
  {#snippet footer()}
    <button type="button" class="btn btn-ghost" onclick={() => (open = false)}>Cancel</button>
    <button type="submit" form="import-form" class="btn btn-primary" disabled={busy}>{busy ? 'Importing…' : 'Import CA'}</button>
  {/snippet}
</Modal>

<style>
  .form {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
  }
  .form .field + .field {
    margin-top: 0;
  }
  .lrow {
    display: flex;
    align-items: center;
    justify-content: space-between;
  }
  .file:focus-within {
    box-shadow: var(--focus-ring);
  }
</style>
