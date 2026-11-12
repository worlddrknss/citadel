<!--
  ARIA tablist: arrow keys move between tabs, Home/End jump, and only the
  active tab is in the tab order (roving tabindex).
-->
<script lang="ts">
  let {
    tabs,
    active = $bindable(),
    label,
    onchange
  }: {
    tabs: { id: string; label: string; count?: number }[];
    active: string;
    label: string;
    onchange?: (id: string) => void;
  } = $props();

  const baseId = `tabs-${Math.random().toString(36).slice(2, 9)}`;
  let buttons: HTMLButtonElement[] = $state([]);

  function select(id: string) {
    active = id;
    onchange?.(id);
  }

  function onkeydown(e: KeyboardEvent, i: number) {
    let next = -1;
    if (e.key === 'ArrowRight') next = (i + 1) % tabs.length;
    else if (e.key === 'ArrowLeft') next = (i - 1 + tabs.length) % tabs.length;
    else if (e.key === 'Home') next = 0;
    else if (e.key === 'End') next = tabs.length - 1;
    if (next < 0) return;
    e.preventDefault();
    select(tabs[next].id);
    buttons[next]?.focus();
  }

  export function panelId(id: string) {
    return `${baseId}-panel-${id}`;
  }
</script>

<div class="tabs" role="tablist" aria-label={label}>
  {#each tabs as t, i (t.id)}
    <button
      bind:this={buttons[i]}
      type="button"
      role="tab"
      id="{baseId}-tab-{t.id}"
      class="tab"
      aria-selected={active === t.id}
      tabindex={active === t.id ? 0 : -1}
      onclick={() => select(t.id)}
      onkeydown={(e) => onkeydown(e, i)}
    >
      {t.label}
      {#if t.count !== undefined}<span class="tab-count">{t.count}</span>{/if}
    </button>
  {/each}
</div>

<style>
  .tabs {
    display: flex;
    gap: var(--space-1);
    border-bottom: 1px solid var(--border);
    overflow-x: auto;
    scrollbar-width: none;
  }
  .tab {
    position: relative;
    display: inline-flex;
    align-items: center;
    gap: var(--space-2);
    padding: var(--space-2) var(--space-3);
    min-height: 40px;
    border: none;
    background: none;
    color: var(--text-muted);
    font: inherit;
    font-size: var(--text-sm);
    font-weight: 500;
    white-space: nowrap;
    cursor: pointer;
    border-radius: var(--radius-sm) var(--radius-sm) 0 0;
  }
  .tab:hover {
    color: var(--text);
  }
  .tab[aria-selected='true'] {
    color: var(--text);
  }
  .tab[aria-selected='true']::after {
    content: '';
    position: absolute;
    left: var(--space-2);
    right: var(--space-2);
    bottom: -1px;
    height: 2px;
    border-radius: 2px;
    background: var(--accent);
  }
  .tab-count {
    padding: 0 6px;
    border-radius: 999px;
    background: var(--surface-sunken);
    color: var(--text-muted);
    font-size: var(--text-xs);
    font-variant-numeric: tabular-nums;
  }
</style>
