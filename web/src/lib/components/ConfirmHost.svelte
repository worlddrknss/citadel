<script lang="ts">
  import { confirmState } from '$lib/stores/confirm.svelte';
  import Modal from './Modal.svelte';

  let typed = $state('');
  const p = $derived(confirmState.pending);
  const blocked = $derived(!!p?.typeToConfirm && typed !== p.typeToConfirm);

  $effect(() => {
    // Reset the typed text whenever a new confirmation opens.
    if (p) typed = '';
  });

  function submit(e: SubmitEvent) {
    e.preventDefault();
    if (!blocked) confirmState.settle(true);
  }
</script>

{#if p}
  <Modal open={true} title={p.title} size="sm" onclose={() => confirmState.settle(false)}>
    <form id="confirm-form" onsubmit={submit}>
      <p class="msg">{p.message}</p>
      {#if p.typeToConfirm}
        <label class="field">
          <span class="field-label">Type <code>{p.typeToConfirm}</code> to confirm</span>
          <!-- svelte-ignore a11y_autofocus -->
          <input class="input mono" bind:value={typed} autocomplete="off" spellcheck="false" autofocus />
        </label>
      {/if}
    </form>
    {#snippet footer()}
      <button type="button" class="btn btn-secondary" onclick={() => confirmState.settle(false)}>Cancel</button>
      <button
        type="submit"
        form="confirm-form"
        class="btn {p.danger ? 'btn-danger' : 'btn-primary'}"
        disabled={blocked}
      >
        {p.confirmLabel ?? 'Confirm'}
      </button>
    {/snippet}
  </Modal>
{/if}

<style>
  .msg {
    margin: 0 0 var(--space-4);
    color: var(--text-muted);
    line-height: 1.5;
    white-space: pre-line;
  }
</style>
