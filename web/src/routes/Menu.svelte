<!--
  Disclosure menu: a trigger button plus a popover. Closes on outside click,
  Escape (focus returns to the trigger) and after choosing an item. Arrow
  keys move between [role=menuitem] / [role=menuitemradio] elements.
  Page-local to the shell; candidate for #lib/components.
-->
<script lang="ts">
  import type { Snippet } from 'svelte';

  let {
    label,
    trigger,
    children,
    align = 'start',
    width = 260,
    triggerClass = 'btn btn-ghost',
    open = $bindable(false),
    role = 'menu',
    labelTrigger = true
  }: {
    /** Accessible name for the trigger (and the popover). */
    label: string;
    /**
     * false: the trigger is named by its own content (add sr-only text to it)
     * rather than `label`, so the name includes the visible text (WCAG 2.5.3).
     */
    labelTrigger?: boolean;
    trigger: Snippet;
    children: Snippet<[() => void]>;
    align?: 'start' | 'end';
    width?: number;
    triggerClass?: string;
    open?: boolean;
    /** "dialog" for popovers with form controls instead of menu items. */
    role?: 'menu' | 'dialog';
  } = $props();

  let root = $state<HTMLElement>();
  let btn = $state<HTMLButtonElement>();
  let pop = $state<HTMLElement>();

  function close(refocus = false) {
    open = false;
    if (refocus) btn?.focus();
  }

  function items(): HTMLElement[] {
    return pop ? Array.from(pop.querySelectorAll<HTMLElement>('[role^="menuitem"]:not([disabled])')) : [];
  }

  async function toggle() {
    open = !open;
    if (open && role === 'menu') {
      await Promise.resolve();
      requestAnimationFrame(() => items()[0]?.focus());
    }
  }

  function onkeydown(e: KeyboardEvent) {
    if (!open) return;
    if (e.key === 'Escape') {
      e.stopPropagation();
      close(true);
      return;
    }
    if (role !== 'menu') return;
    const list = items();
    if (!list.length) return;
    const i = list.indexOf(document.activeElement as HTMLElement);
    let next = -1;
    if (e.key === 'ArrowDown') next = (i + 1) % list.length;
    else if (e.key === 'ArrowUp') next = (i - 1 + list.length) % list.length;
    else if (e.key === 'Home') next = 0;
    else if (e.key === 'End') next = list.length - 1;
    if (next >= 0) {
      e.preventDefault();
      list[next].focus();
    }
  }

  $effect(() => {
    if (!open) return;
    const onDoc = (e: PointerEvent) => {
      if (root && !root.contains(e.target as Node)) close();
    };
    document.addEventListener('pointerdown', onDoc, true);
    return () => document.removeEventListener('pointerdown', onDoc, true);
  });
</script>

<!-- svelte-ignore a11y_no_static_element_interactions -->
<div class="menu-root" bind:this={root} {onkeydown}>
  <button
    bind:this={btn}
    type="button"
    class={triggerClass}
    aria-haspopup={role === 'menu' ? 'menu' : 'dialog'}
    aria-expanded={open}
    aria-label={labelTrigger ? label : undefined}
    onclick={toggle}
  >
    {@render trigger()}
  </button>
  {#if open}
    <div bind:this={pop} class="pop pop-{align}" style:width="min({width}px, calc(100vw - 32px))" {role} aria-label={label}>
      {@render children(() => close(true))}
    </div>
  {/if}
</div>

<style>
  .menu-root {
    position: relative;
    display: inline-flex;
  }
  .pop {
    position: absolute;
    top: calc(100% + 6px);
    z-index: 70;
    display: flex;
    flex-direction: column;
    padding: 4px;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: var(--surface-raised);
    box-shadow: var(--shadow-lg);
  }
  .pop-start {
    left: 0;
  }
  .pop-end {
    right: 0;
  }
  .pop :global([role^='menuitem']) {
    display: flex;
    align-items: center;
    gap: 10px;
    width: 100%;
    min-height: 34px;
    padding: 6px 10px;
    border: none;
    border-radius: var(--radius-sm);
    background: none;
    color: var(--text);
    font: inherit;
    font-size: var(--text-base);
    text-align: start;
    text-decoration: none;
    cursor: pointer;
  }
  .pop :global([role^='menuitem']:hover),
  .pop :global([role^='menuitem']:focus-visible) {
    background: var(--surface-hover);
    outline: none;
    text-decoration: none;
  }
  .pop :global([role^='menuitem'] svg) {
    color: var(--text-subtle);
  }
  .pop :global(.menu-sep) {
    height: 1px;
    margin: 4px -4px;
    background: var(--border);
  }
  .pop :global(.menu-head) {
    display: flex;
    flex-direction: column;
    gap: 2px;
    padding: 8px 10px;
  }
  .pop :global(.menu-label) {
    padding: 6px 10px 2px;
    font-size: var(--text-xs);
    font-weight: 600;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    color: var(--text-subtle);
  }
</style>
