<!-- Inverted bar shown while secrets are selected (board: "2 selected | Copy
     to staging · Move to folder · Add tag … Delete ×"). -->
<script lang="ts">
  import Icon from '$lib/components/Icon.svelte';

  let {
    count,
    copyLabel,
    canMove,
    moveHint,
    deletedCount,
    activeCount,
    oncopy,
    onmove,
    ontag,
    onrestore,
    ondelete,
    onforce,
    onclear
  }: {
    count: number;
    copyLabel: string;
    canMove: boolean;
    moveHint?: string;
    deletedCount: number;
    activeCount: number;
    oncopy: () => void;
    onmove: () => void;
    ontag: () => void;
    onrestore: () => void;
    ondelete: () => void;
    onforce: () => void;
    onclear: () => void;
  } = $props();
</script>

<div class="bulk" role="region" aria-label="Bulk actions">
  <span class="count" aria-live="polite">{count} selected</span>
  <span class="bar" aria-hidden="true">|</span>
  <button type="button" class="btn btn-ghost btn-sm" disabled={activeCount === 0} onclick={oncopy}>
    <Icon name="copy" size={14} />{copyLabel}
  </button>
  <button type="button" class="btn btn-ghost btn-sm" disabled={!canMove || activeCount === 0} title={moveHint} onclick={onmove}>
    <Icon name="folder" size={14} />Move to folder
  </button>
  <button type="button" class="btn btn-ghost btn-sm" disabled={activeCount === 0} onclick={ontag}>
    <Icon name="tag" size={14} />Add tag
  </button>
  <span class="right">
    {#if deletedCount > 0}
      <button type="button" class="btn btn-ghost btn-sm" onclick={onrestore}>
        <Icon name="history" size={14} />Restore {deletedCount}
      </button>
    {/if}
    {#if activeCount > 0}
      <button type="button" class="btn btn-ghost btn-sm" onclick={ondelete}>
        <Icon name="trash" size={14} />Delete
      </button>
    {/if}
    <button type="button" class="btn btn-ghost btn-sm danger" onclick={onforce}>
      <Icon name="alert-triangle" size={14} />Force delete
    </button>
    <button type="button" class="btn btn-ghost btn-sm icon-only" aria-label="Clear selection" title="Clear selection" onclick={onclear}>
      <Icon name="x" size={14} />
    </button>
  </span>
</div>

<style>
  .bulk {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: var(--space-2);
    padding: 6px var(--space-2) 6px 14px;
    border-radius: var(--radius-md);
    background: var(--text);
    color: var(--bg);
  }
  .count {
    font-weight: 500;
  }
  .bar {
    opacity: 0.4;
  }
  .btn {
    background: transparent;
    border-color: transparent;
    color: var(--bg);
  }
  .btn:hover:not(:disabled) {
    background: color-mix(in srgb, var(--bg) 14%, transparent);
  }
  .btn:focus-visible {
    outline: 2px solid var(--bg);
    outline-offset: 1px;
  }
  .danger {
    color: var(--danger-soft);
  }
  .right {
    display: inline-flex;
    flex-wrap: wrap;
    gap: var(--space-1);
    margin-left: auto;
  }
  .icon-only {
    width: 28px;
    padding: 0;
  }
</style>
