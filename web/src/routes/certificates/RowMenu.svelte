<!--
  Row "more actions" menu: a menu button with arrow-key navigation, Esc to
  close and focus return. Page-local until #lib has a shared menu.
-->
<script lang="ts" module>
  import type { IconName } from '#lib/components/Icon.svelte';

  export interface MenuItem {
    label: string;
    icon?: IconName;
    danger?: boolean;
    onselect: () => void;
  }
</script>

<script lang="ts">
  import Icon from '#lib/components/Icon.svelte';

  let { items, label }: { items: MenuItem[]; label: string } = $props();

  let open = $state(false);
  let root = $state<HTMLDivElement>();
  let trigger = $state<HTMLButtonElement>();
  let list = $state<HTMLDivElement>();
  let up = $state(false);

  function focusItem(i: number) {
    const els = list?.querySelectorAll<HTMLButtonElement>('[role="menuitem"]');
    if (!els?.length) return;
    els[(i + els.length) % els.length].focus();
  }

  async function toggle() {
    open = !open;
    if (open) {
      const r = trigger?.getBoundingClientRect();
      up = !!r && window.innerHeight - r.bottom < 40 + items.length * 36;
      queueMicrotask(() => focusItem(0));
    }
  }

  function close(returnFocus = true) {
    open = false;
    if (returnFocus) trigger?.focus();
  }

  function onkeydown(e: KeyboardEvent) {
    const els = Array.from(list?.querySelectorAll<HTMLButtonElement>('[role="menuitem"]') ?? []);
    const i = els.indexOf(document.activeElement as HTMLButtonElement);
    if (e.key === 'Escape') {
      e.preventDefault();
      close();
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      focusItem(i + 1);
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      focusItem(i - 1);
    } else if (e.key === 'Home') {
      e.preventDefault();
      focusItem(0);
    } else if (e.key === 'End') {
      e.preventDefault();
      focusItem(els.length - 1);
    } else if (e.key === 'Tab') close(false);
  }

  $effect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (root && !root.contains(e.target as Node)) close(false);
    };
    document.addEventListener('mousedown', onDoc);
    return () => document.removeEventListener('mousedown', onDoc);
  });
</script>

<div class="menu" bind:this={root}>
  <button
    bind:this={trigger}
    type="button"
    class="btn btn-ghost btn-sm btn-icon"
    aria-haspopup="menu"
    aria-expanded={open}
    aria-label={label}
    onclick={(e) => {
      e.stopPropagation();
      toggle();
    }}
  >
    <Icon name="more" size={14} />
  </button>
  {#if open}
    <!-- svelte-ignore a11y_interactive_supports_focus -->
    <div class="list" class:up role="menu" tabindex="-1" aria-label={label} bind:this={list} {onkeydown}>
      {#each items as it (it.label)}
        <button
          type="button"
          role="menuitem"
          class:danger={it.danger}
          onclick={(e) => {
            e.stopPropagation();
            close();
            it.onselect();
          }}
        >
          {#if it.icon}<Icon name={it.icon} size={14} />{/if}
          {it.label}
        </button>
      {/each}
    </div>
  {/if}
</div>

<style>
  .menu {
    position: relative;
    display: inline-flex;
  }
  .list {
    position: absolute;
    right: 0;
    top: calc(100% + 4px);
    z-index: 20;
    min-width: 180px;
    padding: 4px;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: var(--surface);
    box-shadow: var(--shadow-lg);
    display: flex;
    flex-direction: column;
  }
  .list.up {
    top: auto;
    bottom: calc(100% + 4px);
  }
  [role='menuitem'] {
    display: flex;
    align-items: center;
    gap: 8px;
    height: 32px;
    padding: 0 10px;
    border: 0;
    border-radius: var(--radius-sm);
    background: none;
    color: var(--text);
    font: inherit;
    font-size: var(--text-sm);
    text-align: start;
    white-space: nowrap;
    cursor: pointer;
  }
  [role='menuitem']:hover,
  [role='menuitem']:focus-visible {
    background: var(--surface-hover);
    outline: none;
  }
  [role='menuitem'].danger {
    color: var(--danger);
  }
  [role='menuitem'].danger:hover,
  [role='menuitem'].danger:focus-visible {
    background: var(--danger-soft);
  }
</style>
