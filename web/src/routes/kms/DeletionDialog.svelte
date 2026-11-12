<!--
  Schedule key deletion: pick a 7–30 day waiting period and type the key's
  alias (or ID) to confirm. Irreversible once the period ends.
-->
<script lang="ts">
  import { errorMessage } from '$lib/api';
  import Modal from '$lib/components/Modal.svelte';
  import Icon from '$lib/components/Icon.svelte';
  import { primaryAlias, fmtDate, type Key } from './api';

  let {
    open = $bindable(false),
    target,
    onconfirm
  }: {
    open?: boolean;
    target: Key | null;
    onconfirm: (days: number) => Promise<void>;
  } = $props();

  let days = $state(30);
  let typed = $state('');
  let busy = $state(false);
  let error = $state('');
  const uid = Math.random().toString(36).slice(2, 8);

  const alias = $derived(target ? primaryAlias(target) : undefined);
  /** What must be typed: the alias without its prefix, else the key ID. */
  const phrase = $derived(alias ? alias.replace(/^alias\//, '') : (target?.keyId ?? ''));
  const when = $derived(fmtDate(new Date(Date.now() + days * 86_400_000).toISOString()));
  const matches = $derived(typed.trim() === phrase || (!!target && typed.trim() === target.keyId));

  $effect(() => {
    if (open) {
      days = 30;
      typed = '';
      error = '';
    }
  });

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    if (!matches || busy) return;
    busy = true;
    error = '';
    try {
      await onconfirm(days);
      open = false;
    } catch (err) {
      error = errorMessage(err);
    } finally {
      busy = false;
    }
  }
</script>

<Modal bind:open title="Schedule deletion of this key?" size="sm">
  {#if target}
    <form id="del-form-{uid}" class="del" onsubmit={submit}>
      <div class="lead">
        <span class="tile" aria-hidden="true"><Icon name="alert-triangle" size={18} /></span>
        <p class="muted">
          After the {days}-day waiting period, data encrypted with
          <span class="mono strong">{alias ?? target.keyId}</span> can never be decrypted.
          {#if target.usedBy && target.usedBy.secrets + target.usedBy.parameters > 0}
            <strong class="danger">{target.usedBy.secrets} secret{target.usedBy.secrets === 1 ? '' : 's'} and {target.usedBy.parameters} parameter{target.usedBy.parameters === 1 ? '' : 's'} still use it.</strong>
          {/if}
          The key is disabled while it waits, and you can cancel any time before then.
        </p>
      </div>
      <label class="field">
        <span class="field-label">Waiting period</span>
        <select class="select" bind:value={days}>
          {#each Array.from({ length: 24 }, (_, i) => i + 7) as d (d)}
            <option value={d}>{d} days{d === 30 ? ' (default)' : d === 7 ? ' (minimum)' : ''}</option>
          {/each}
        </select>
        <span class="field-hint">Deletes on {when}.</span>
      </label>
      <label class="field">
        <span class="field-label">Type <span class="mono strong">{phrase}</span> to confirm</span>
        <input id="del-in-{uid}" class="input mono" bind:value={typed} autocomplete="off" spellcheck="false" />
        <span class="field-hint">The button turns on when the name matches.</span>
      </label>
      {#if error}<p class="field-error" role="alert">{error}</p>{/if}
    </form>
  {/if}
  {#snippet footer()}
    <button type="button" class="btn btn-ghost" onclick={() => (open = false)}>Cancel</button>
    <button type="submit" form="del-form-{uid}" class="btn btn-danger" disabled={!matches || busy}>
      {busy ? 'Scheduling…' : 'Schedule deletion'}
    </button>
  {/snippet}
</Modal>

<style>
  .del {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
  }
  .del .field + .field {
    margin-top: 0;
  }
  .lead {
    display: flex;
    gap: var(--space-3);
    align-items: flex-start;
  }
  .lead p {
    margin: 0;
    line-height: 1.5;
  }
  .tile {
    display: inline-grid;
    place-items: center;
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
  }
  .danger {
    color: var(--danger);
    font-weight: 500;
  }
</style>
