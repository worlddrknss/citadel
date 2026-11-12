<!--
  Dialog built on the native <dialog> element: showModal() gives a real focus
  trap, Esc to close, an inert background and focus restore on close, which
  the hand-rolled div modals never had.
-->
<script lang="ts">
  import type { Snippet } from 'svelte';
  import Icon from './Icon.svelte';

  let {
    open = $bindable(false),
    title,
    description,
    size = 'md',
    onclose,
    children,
    footer
  }: {
    open?: boolean;
    title: string;
    description?: string;
    size?: 'sm' | 'md' | 'lg';
    onclose?: () => void;
    children: Snippet;
    footer?: Snippet;
  } = $props();

  let dialog = $state<HTMLDialogElement>();
  const titleId = `dlg-${Math.random().toString(36).slice(2, 9)}`;

  $effect(() => {
    if (!dialog) return;
    if (open && !dialog.open) dialog.showModal();
    if (!open && dialog.open) dialog.close();
  });

  function handleClose() {
    open = false;
    onclose?.();
  }

  // A click on the backdrop lands on the <dialog> itself, not its contents.
  function handleClick(e: MouseEvent) {
    if (e.target === dialog) handleClose();
  }
</script>

<dialog
  bind:this={dialog}
  class="modal modal-{size}"
  aria-labelledby={titleId}
  onclose={handleClose}
  onclick={handleClick}
>
  {#if open}
    <div class="modal-body">
      <header class="modal-head">
        <div>
          <h2 id={titleId}>{title}</h2>
          {#if description}<p class="modal-desc">{description}</p>{/if}
        </div>
        <button type="button" class="btn-icon" aria-label="Close" onclick={handleClose}>
          <Icon name="x" />
        </button>
      </header>
      <div class="modal-content">{@render children()}</div>
      {#if footer}<footer class="modal-foot">{@render footer()}</footer>{/if}
    </div>
  {/if}
</dialog>

<style>
  .modal {
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    background: var(--surface);
    color: var(--text);
    padding: 0;
    width: min(calc(100vw - 32px), var(--w));
    max-height: min(calc(100dvh - 32px), 860px);
    box-shadow: var(--shadow-lg);
  }
  .modal-sm { --w: 420px; }
  .modal-md { --w: 560px; }
  .modal-lg { --w: 820px; }
  .modal::backdrop {
    background: var(--overlay);
    backdrop-filter: blur(2px);
  }
  .modal-body {
    display: flex;
    flex-direction: column;
    max-height: inherit;
  }
  .modal-head {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: var(--space-4);
    padding: var(--space-5) var(--space-5) var(--space-3);
  }
  h2 {
    margin: 0;
    font-size: var(--text-lg);
    font-weight: 600;
  }
  .modal-desc {
    margin: var(--space-1) 0 0;
    color: var(--text-muted);
    font-size: var(--text-sm);
  }
  .modal-content {
    padding: var(--space-2) var(--space-5) var(--space-5);
    overflow: auto;
  }
  .modal-foot {
    display: flex;
    justify-content: flex-end;
    flex-wrap: wrap;
    gap: var(--space-2);
    padding: var(--space-4) var(--space-5);
    border-top: 1px solid var(--border);
  }
</style>
