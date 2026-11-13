<!-- Delete a disabled CA (AWS PCA semantics): pick how long it stays
     restorable (7–30 days) and type its name to confirm. -->
<script lang="ts">
  import Modal from '#lib/components/Modal.svelte';
  import Icon from '#lib/components/Icon.svelte';
  import { errorMessage } from '#lib/api.ts';
  import { toast } from '#lib/stores/toast.svelte.ts';
  import { certApi, type CertRow } from './api';
  import { CA_DELETION_DAYS, caDeleteBlocker } from './certs';

  let {
    open = $bindable(false),
    ca,
    name,
    ondone
  }: {
    open?: boolean;
    ca: CertRow | null;
    name: string;
    ondone: () => void;
  } = $props();

  let days = $state<number>(CA_DELETION_DAYS.default);
  let typed = $state('');
  let busy = $state(false);
  let error = $state('');

  $effect(() => {
    if (open) {
      days = CA_DELETION_DAYS.default;
      typed = '';
      error = '';
    }
  });

  const blocker = $derived(ca ? caDeleteBlocker(ca) : null);
  const validDays = $derived(Number.isInteger(days) && days >= CA_DELETION_DAYS.min && days <= CA_DELETION_DAYS.max);
  const blocked = $derived(!!blocker || !validDays || typed.trim() !== name);

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    if (!ca || blocked) return;
    busy = true;
    error = '';
    try {
      await certApi.deleteCA(ca.id, days);
      toast.success(`Deleted ${name}; restorable for ${days} days`);
      open = false;
      ondone();
    } catch (err) {
      error = errorMessage(err, 'Could not delete the certificate authority.');
    } finally {
      busy = false;
    }
  }
</script>

<Modal bind:open title="Delete this certificate authority?" size="sm">
  <form id="delete-ca-form" class="form" onsubmit={submit}>
    <div class="lead">
      <span class="warn" aria-hidden="true"><Icon name="alert-triangle" size={18} /></span>
      <p class="muted">
        <span class="mono strong">{name}</span> stops being usable at once. You can restore it until the restore window ends; after that
        it is removed permanently with the certificates it issued.
      </p>
    </div>
    {#if blocker}
      <div class="callout callout-warning" role="alert" data-testid="ca-delete-blocker"><Icon name="alert-triangle" size={16} /><span>{blocker}</span></div>
    {:else}
      <div class="field">
        <label class="field-label" for="dca-days">Restore window (days)</label>
        <input
          id="dca-days"
          class="input num"
          type="number"
          min={CA_DELETION_DAYS.min}
          max={CA_DELETION_DAYS.max}
          step="1"
          bind:value={days}
          aria-invalid={!validDays}
        />
        <span class="field-hint">Between {CA_DELETION_DAYS.min} and {CA_DELETION_DAYS.max} days. The default is {CA_DELETION_DAYS.default}.</span>
      </div>
      <div class="field">
        <label class="field-label" for="dca-confirm">Type <span class="mono strong">{name}</span> to confirm</label>
        <input id="dca-confirm" class="input mono" bind:value={typed} autocomplete="off" spellcheck="false" />
      </div>
    {/if}
    {#if error}
      <div class="callout callout-danger" role="alert"><Icon name="alert-circle" size={16} /><span>{error}</span></div>
    {/if}
  </form>
  {#snippet footer()}
    <button type="button" class="btn btn-ghost" onclick={() => (open = false)}>Cancel</button>
    <button type="submit" form="delete-ca-form" class="btn btn-danger" disabled={blocked || busy}>
      {busy ? 'Deleting…' : 'Delete CA'}
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
  .num {
    max-width: 120px;
  }
</style>
