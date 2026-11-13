<!--
  Schedule deletion with a recovery window of 7–30 days. Deleting several
  secrets at once also requires typing a confirmation phrase. Force delete is
  offered separately underneath and runs its own type-the-key confirmation.
-->
<script lang="ts">
  import Icon from '#lib/components/Icon.svelte';
  import Modal from '#lib/components/Modal.svelte';

  let {
    open = $bindable(false),
    keys,
    onconfirm,
    onforce
  }: {
    open?: boolean;
    keys: string[];
    onconfirm: (days: number) => Promise<void>;
    onforce: () => void;
  } = $props();

  let days = $state(30);
  let typed = $state('');
  let busy = $state(false);

  $effect(() => {
    if (open) {
      days = 30;
      typed = '';
    }
  });

  const bulk = $derived(keys.length > 1);
  const phrase = $derived(`delete ${keys.length} secrets`);
  const daysOk = $derived(Number.isInteger(days) && days >= 7 && days <= 30);
  const purgeOn = $derived(
    daysOk ? new Date(Date.now() + days * 86400_000).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' }) : ''
  );
  const blocked = $derived(!daysOk || (bulk && typed.trim() !== phrase));

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    if (blocked) return;
    busy = true;
    try {
      await onconfirm(days);
      open = false;
    } finally {
      busy = false;
    }
  }

  function force() {
    open = false;
    onforce();
  }
</script>

<Modal
  bind:open
  title={bulk ? `Schedule ${keys.length} secrets for deletion?` : `Schedule ${keys[0] ?? ''} for deletion?`}
  description="External Secrets clients stop receiving {bulk ? 'them' : 'it'} immediately. Until the window ends {bulk
    ? 'they'
    : 'it'} can be restored."
  size="sm"
>
  <form id="delete-form" class="form" onsubmit={submit}>
    {#if bulk}
      <ul class="keys mono">
        {#each keys.slice(0, 6) as k (k)}<li>{k}</li>{/each}
        {#if keys.length > 6}<li class="subtle">and {keys.length - 6} more</li>{/if}
      </ul>
    {/if}
    <label class="field">
      <span class="field-label">Recovery window</span>
      <span class="days">
        <input class="input num" type="number" min="7" max="30" step="1" bind:value={days} aria-invalid={!daysOk} aria-describedby="days-hint" />
        <span class="muted">days</span>
      </span>
      <span id="days-hint" class={daysOk ? 'field-hint' : 'field-error'}>
        {daysOk ? `Purged permanently on ${purgeOn}.` : 'Choose between 7 and 30 days.'}
      </span>
    </label>
    {#if bulk}
      <label class="field">
        <span class="field-label">Type <code>{phrase}</code> to confirm</span>
        <input class="input mono" bind:value={typed} autocomplete="off" spellcheck="false" />
      </label>
    {/if}
    <div class="force">
      <div>
        <strong>Skip the recovery window?</strong>
        <p class="subtle small">Force delete removes {bulk ? 'them' : 'it'} now. It can't be undone.</p>
      </div>
      <button type="button" class="btn btn-danger-ghost btn-sm" onclick={force}>
        <Icon name="alert-triangle" size={14} />Force delete…
      </button>
    </div>
  </form>
  {#snippet footer()}
    <button type="button" class="btn btn-secondary" onclick={() => (open = false)}>Cancel</button>
    <button type="submit" form="delete-form" class="btn btn-danger" disabled={busy || blocked}>
      <Icon name="trash" size={16} />Schedule deletion
    </button>
  {/snippet}
</Modal>

<style>
  .form {
    display: flex;
    flex-direction: column;
  }
  .keys {
    margin: 0 0 var(--space-4);
    padding: var(--space-2) var(--space-3);
    list-style: none;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: var(--surface-sunken);
    font-size: var(--text-sm);
    max-height: 160px;
    overflow: auto;
  }
  .days {
    display: flex;
    align-items: center;
    gap: var(--space-2);
  }
  .days .input {
    width: 96px;
  }
  .force {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--space-3);
    margin-top: var(--space-5);
    padding-top: var(--space-4);
    border-top: 1px solid var(--border);
  }
  .force p {
    margin: 2px 0 0;
  }
</style>
