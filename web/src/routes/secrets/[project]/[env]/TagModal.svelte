<!-- Add (or overwrite) one tag on several secrets. -->
<script lang="ts">
  import Modal from '$lib/components/Modal.svelte';

  let {
    open = $bindable(false),
    count,
    onsubmit
  }: {
    open?: boolean;
    count: number;
    onsubmit: (tag: { key: string; value: string }) => Promise<boolean>;
  } = $props();

  let key = $state('');
  let value = $state('');
  let busy = $state(false);

  $effect(() => {
    if (open) {
      key = '';
      value = '';
    }
  });

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    if (!key.trim()) return;
    busy = true;
    try {
      if (await onsubmit({ key: key.trim(), value: value.trim() })) open = false;
    } finally {
      busy = false;
    }
  }
</script>

<Modal bind:open title="Add tag to {count} secret{count === 1 ? '' : 's'}" description="A tag with the same key is replaced." size="sm">
  <form id="tag-form" class="row" onsubmit={submit}>
    <label class="field">
      <span class="field-label">Key</span>
      <!-- svelte-ignore a11y_autofocus -->
      <input class="input mono" bind:value={key} placeholder="team" autocomplete="off" spellcheck="false" autofocus />
    </label>
    <label class="field">
      <span class="field-label">Value</span>
      <input class="input mono" bind:value placeholder="payments" autocomplete="off" spellcheck="false" />
    </label>
  </form>
  {#snippet footer()}
    <button type="button" class="btn btn-secondary" onclick={() => (open = false)}>Cancel</button>
    <button type="submit" form="tag-form" class="btn btn-primary" disabled={busy || !key.trim()}>Add tag</button>
  {/snippet}
</Modal>

<style>
  .row {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: var(--space-3);
  }
  .row :global(.field + .field) {
    margin-top: 0;
  }
</style>
