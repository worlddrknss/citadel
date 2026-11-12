<!-- Renew: re-issue from the same CA with the stored CSR, a new serial and a
     fresh validity window. -->
<script lang="ts">
  import { untrack } from 'svelte';
  import Modal from '$lib/components/Modal.svelte';
  import Icon from '$lib/components/Icon.svelte';
  import { api, errorMessage } from '$lib/api';
  import { toast } from '$lib/stores/toast.svelte';
  import type { CertRow } from './api';
  import { lifetimeDays } from './certs';

  let {
    open = $bindable(false),
    cert,
    name,
    ondone
  }: {
    open?: boolean;
    cert: CertRow | null;
    name: string;
    ondone: () => void;
  } = $props();

  let days = $state(90);
  let busy = $state(false);
  let error = $state('');

  $effect(() => {
    if (open)
      untrack(() => {
        days = (cert && lifetimeDays(cert.notBefore, cert.notAfter)) || 90;
        error = '';
      });
  });

  const invalid = $derived(!Number.isInteger(days) || days < 1 || days > 3650);

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    if (!cert || invalid) return;
    busy = true;
    error = '';
    try {
      await api.renewCert(cert.id, String(days));
      toast.success(`Renewed ${name}`);
      open = false;
      ondone();
    } catch (err) {
      error = errorMessage(err, 'Could not renew the certificate.');
    } finally {
      busy = false;
    }
  }
</script>

<Modal bind:open title="Renew certificate" description="Re-issues {name} from the same CA with its stored CSR, a new serial and a fresh validity window." size="sm">
  <form id="renew-form" class="form" onsubmit={submit}>
    <div class="field">
      <label class="field-label" for="rn-days">Validity (days)</label>
      <input id="rn-days" class="input num" type="number" min="1" max="3650" bind:value={days} aria-invalid={invalid} aria-describedby="rn-hint" />
      {#if invalid}
        <span class="field-error" id="rn-hint">Enter a whole number of days between 1 and 3650.</span>
      {:else}
        <span class="field-hint" id="rn-hint">Defaults to the current certificate's lifetime. The old certificate stays valid until it expires.</span>
      {/if}
    </div>
    {#if error}
      <div class="callout callout-danger" role="alert"><Icon name="alert-circle" size={16} /><span>{error}</span></div>
    {/if}
  </form>
  {#snippet footer()}
    <button type="button" class="btn btn-ghost" onclick={() => (open = false)}>Cancel</button>
    <button type="submit" form="renew-form" class="btn btn-primary" disabled={invalid || busy}>{busy ? 'Renewing…' : 'Renew'}</button>
  {/snippet}
</Modal>

<style>
  .form {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
  }
</style>
