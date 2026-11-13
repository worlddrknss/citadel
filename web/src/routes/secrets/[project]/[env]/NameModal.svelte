<!-- One-field dialog for naming a new folder or environment. -->
<script lang="ts">
  import Modal from '#lib/components/Modal.svelte';

  let {
    open = $bindable(false),
    title,
    description,
    label,
    placeholder,
    submitLabel,
    prefix,
    onsubmit
  }: {
    open?: boolean;
    title: string;
    description?: string;
    label: string;
    placeholder: string;
    submitLabel: string;
    /** Read-only text shown before the input, e.g. the parent folder. */
    prefix?: string;
    onsubmit: (name: string) => Promise<boolean>;
  } = $props();

  let name = $state('');
  let busy = $state(false);
  const formId = `name-${Math.random().toString(36).slice(2, 9)}`;
  const ok = $derived(/^[A-Za-z0-9_.-]+$/.test(name.trim()));

  $effect(() => {
    if (open) name = '';
  });

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    if (!ok) return;
    busy = true;
    try {
      if (await onsubmit(name.trim())) open = false;
    } finally {
      busy = false;
    }
  }
</script>

<Modal bind:open {title} {description} size="sm">
  <form id={formId} onsubmit={submit}>
    <label class="field">
      <span class="field-label">{label}</span>
      <span class="row">
        {#if prefix}<span class="mono subtle prefix">{prefix}</span>{/if}
        <!-- svelte-ignore a11y_autofocus -->
        <input
          class="input mono"
          bind:value={name}
          {placeholder}
          autocomplete="off"
          spellcheck="false"
          autofocus
          aria-invalid={name.trim() !== '' && !ok}
        />
      </span>
      <span class={name.trim() && !ok ? 'field-error' : 'field-hint'}>Letters, digits, dots, dashes and underscores.</span>
    </label>
  </form>
  {#snippet footer()}
    <button type="button" class="btn btn-secondary" onclick={() => (open = false)}>Cancel</button>
    <button type="submit" form={formId} class="btn btn-primary" disabled={busy || !ok}>{submitLabel}</button>
  {/snippet}
</Modal>

<style>
  .row {
    display: flex;
    align-items: center;
    gap: var(--space-2);
  }
  .prefix {
    white-space: nowrap;
    max-width: 45%;
    overflow: hidden;
    text-overflow: ellipsis;
  }
</style>
