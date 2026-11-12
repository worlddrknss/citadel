<!-- Revoke a certificate: pick a CRL reason and type the common name to
     confirm. Revocation is permanent. -->
<script lang="ts">
  import Modal from '$lib/components/Modal.svelte';
  import Icon from '$lib/components/Icon.svelte';
  import { api, errorMessage } from '$lib/api';
  import { toast } from '$lib/stores/toast.svelte';
  import type { CertRow } from './api';
  import { REVOKE_REASONS } from './certs';

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

  let reason = $state('Unspecified');
  let typed = $state('');
  let busy = $state(false);
  let error = $state('');

  $effect(() => {
    if (open) {
      reason = 'Unspecified';
      typed = '';
      error = '';
    }
  });

  const blocked = $derived(typed.trim() !== name);

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    if (!cert || blocked) return;
    busy = true;
    error = '';
    try {
      await api.revokeCert(cert.id, reason);
      toast.success(`Revoked ${name}`);
      open = false;
      ondone();
    } catch (err) {
      error = errorMessage(err, 'Could not revoke the certificate.');
    } finally {
      busy = false;
    }
  }
</script>

<Modal bind:open title="Revoke this certificate?" size="sm">
  <form id="revoke-form" class="form" onsubmit={submit}>
    <div class="lead">
      <span class="warn" aria-hidden="true"><Icon name="alert-triangle" size={18} /></span>
      <p class="muted">
        <span class="mono strong">{name}</span> is added to its CA's revocation list and stops being trusted. This can't be undone.
      </p>
    </div>
    <div class="field">
      <label class="field-label" for="rv-reason">Reason</label>
      <select id="rv-reason" class="select" bind:value={reason}>
        {#each REVOKE_REASONS as r (r.value)}<option value={r.value}>{r.label}</option>{/each}
      </select>
      <span class="field-hint">Published in the CRL. Use “Key compromise” if the private key may have leaked.</span>
    </div>
    <div class="field">
      <label class="field-label" for="rv-confirm">Type <span class="mono strong">{name}</span> to confirm</label>
      <input id="rv-confirm" class="input mono" bind:value={typed} autocomplete="off" spellcheck="false" />
      <span class="field-hint">The button turns on when the name matches.</span>
    </div>
    {#if error}
      <div class="callout callout-danger" role="alert"><Icon name="alert-circle" size={16} /><span>{error}</span></div>
    {/if}
  </form>
  {#snippet footer()}
    <button type="button" class="btn btn-ghost" onclick={() => (open = false)}>Cancel</button>
    <button type="submit" form="revoke-form" class="btn btn-danger" disabled={blocked || busy}>
      {busy ? 'Revoking…' : 'Revoke certificate'}
    </button>
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
  .lead {
    display: flex;
    gap: 12px;
    align-items: flex-start;
  }
  .lead p {
    margin: 0;
  }
  .warn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    flex: none;
    width: 36px;
    height: 36px;
    border-radius: 10px;
    background: var(--danger-soft);
    color: var(--danger);
  }
  .strong {
    color: var(--text);
    font-weight: 600;
    overflow-wrap: anywhere;
  }
</style>
