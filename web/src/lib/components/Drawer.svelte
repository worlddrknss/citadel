<!--
  Side panel for item details. Like Modal it uses <dialog>.showModal(), so
  it traps focus, closes on Esc and restores focus; on phones it fills the
  screen.
-->
<script lang="ts">
  import type { Snippet } from 'svelte';
  import Icon from './Icon.svelte';

  let {
    open = $bindable(false),
    title,
    subtitle,
    width = 560,
    onclose,
    actions,
    children
  }: {
    open?: boolean;
    title: string;
    subtitle?: string;
    width?: number;
    onclose?: () => void;
    /** Buttons shown in the header, next to Close. */
    actions?: Snippet;
    children: Snippet;
  } = $props();

  let dialog = $state<HTMLDialogElement>();
  const titleId = `drw-${Math.random().toString(36).slice(2, 9)}`;

  $effect(() => {
    if (!dialog) return;
    if (open && !dialog.open) dialog.showModal();
    if (!open && dialog.open) dialog.close();
  });

  function handleClose() {
    open = false;
    onclose?.();
  }
</script>

<dialog
  bind:this={dialog}
  class="drawer"
  style="--drawer-w: {width}px"
  aria-labelledby={titleId}
  onclose={handleClose}
  onclick={(e) => e.target === dialog && handleClose()}
>
  {#if open}
    <div class="drawer-panel">
      <header class="drawer-head">
        <div class="drawer-titles">
          <h2 id={titleId}>{title}</h2>
          {#if subtitle}<p class="mono drawer-sub">{subtitle}</p>{/if}
        </div>
        <div class="drawer-actions">
          {@render actions?.()}
          <button type="button" class="btn-icon" aria-label="Close panel" onclick={handleClose}>
            <Icon name="x" />
          </button>
        </div>
      </header>
      <div class="drawer-body">{@render children()}</div>
    </div>
  {/if}
</dialog>

<style>
  .drawer {
    margin: 0 0 0 auto;
    height: 100dvh;
    max-height: 100dvh;
    width: min(100vw, var(--drawer-w));
    max-width: 100vw;
    padding: 0;
    border: none;
    border-left: 1px solid var(--border);
    background: var(--surface);
    color: var(--text);
    box-shadow: var(--shadow-lg);
  }
  .drawer[open] {
    animation: drawer-in 180ms ease-out;
  }
  .drawer::backdrop {
    background: var(--overlay);
  }
  .drawer-panel {
    display: flex;
    flex-direction: column;
    height: 100%;
  }
  .drawer-head {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: var(--space-3);
    padding: var(--space-5);
    border-bottom: 1px solid var(--border);
  }
  .drawer-titles {
    min-width: 0;
  }
  h2 {
    margin: 0;
    font-size: var(--text-lg);
    font-weight: 600;
    overflow-wrap: anywhere;
  }
  .drawer-sub {
    margin: var(--space-1) 0 0;
    color: var(--text-muted);
    font-size: var(--text-xs);
    overflow-wrap: anywhere;
  }
  .drawer-actions {
    display: flex;
    gap: var(--space-1);
    flex-shrink: 0;
  }
  .drawer-body {
    flex: 1;
    overflow: auto;
    padding: var(--space-5);
  }
  @keyframes drawer-in {
    from { transform: translateX(24px); opacity: 0; }
  }
  @media (prefers-reduced-motion: reduce) {
    .drawer[open] { animation: none; }
  }
</style>
