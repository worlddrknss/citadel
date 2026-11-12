<!--
  Action menu (button + popover, ARIA menu pattern). The popover is fixed-
  positioned from the trigger so it isn't clipped by a scrolling table.
  Arrow keys move, Esc closes and returns focus to the trigger.
  Page-local because $lib has no menu component yet.
-->
<script lang="ts" module>
  import type { IconName } from '$lib/components/Icon.svelte';
  export interface MenuItem {
    label: string;
    icon?: IconName;
    onclick?: () => void;
    danger?: boolean;
    disabled?: boolean;
    /** Draws a separator above this item. */
    divider?: boolean;
    hint?: string;
  }
</script>

<script lang="ts">
  import { tick } from 'svelte';
  import Icon from '$lib/components/Icon.svelte';

  let {
    items,
    label,
    text,
    icon = 'more',
    buttonClass = 'btn btn-ghost btn-sm btn-icon-only'
  }: {
    items: MenuItem[];
    /** Accessible name of the trigger. */
    label: string;
    /** Visible trigger text; omit for an icon-only trigger. */
    text?: string;
    icon?: IconName;
    buttonClass?: string;
  } = $props();

  let open = $state(false);
  let trigger = $state<HTMLButtonElement>();
  let menu = $state<HTMLDivElement>();
  let pos = $state({ top: 0, left: 0 });
  const id = `menu-${Math.random().toString(36).slice(2, 9)}`;

  function place() {
    if (!trigger) return;
    const r = trigger.getBoundingClientRect();
    const w = menu?.offsetWidth ?? 220;
    const h = menu?.offsetHeight ?? 200;
    let left = r.right - w;
    if (left < 8) left = Math.min(r.left, window.innerWidth - w - 8);
    let top = r.bottom + 4;
    if (top + h > window.innerHeight - 8) top = Math.max(8, r.top - h - 4);
    pos = { top, left };
  }

  async function show(focusLast = false) {
    open = true;
    await tick();
    place();
    const els = buttons();
    (focusLast ? els[els.length - 1] : els[0])?.focus();
  }

  function hide(refocus = true) {
    open = false;
    if (refocus) trigger?.focus();
  }

  function buttons(): HTMLButtonElement[] {
    return menu ? [...menu.querySelectorAll<HTMLButtonElement>('button[role="menuitem"]:not(:disabled)')] : [];
  }

  function onTriggerKey(e: KeyboardEvent) {
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      show(e.key === 'ArrowUp');
    }
  }

  function onMenuKey(e: KeyboardEvent) {
    const els = buttons();
    const i = els.indexOf(document.activeElement as HTMLButtonElement);
    if (e.key === 'Escape') {
      e.preventDefault();
      e.stopPropagation();
      hide();
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      els[(i + 1) % els.length]?.focus();
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      els[(i - 1 + els.length) % els.length]?.focus();
    } else if (e.key === 'Home') {
      e.preventDefault();
      els[0]?.focus();
    } else if (e.key === 'End') {
      e.preventDefault();
      els[els.length - 1]?.focus();
    } else if (e.key === 'Tab') {
      hide(false);
    }
  }

  function choose(item: MenuItem) {
    hide();
    item.onclick?.();
  }

  function onWindowPointer(e: PointerEvent) {
    if (!open) return;
    const t = e.target as Node;
    if (menu?.contains(t) || trigger?.contains(t)) return;
    hide(false);
  }
</script>

<svelte:window
  onpointerdown={onWindowPointer}
  onresize={() => open && hide(false)}
  onscrollcapture={() => open && place()}
/>

<button
  bind:this={trigger}
  type="button"
  class={buttonClass}
  aria-label={text ? undefined : label}
  aria-haspopup="menu"
  aria-expanded={open}
  aria-controls={open ? id : undefined}
  title={text ? undefined : label}
  onclick={() => (open ? hide() : show())}
  onkeydown={onTriggerKey}
>
  <Icon name={icon} size={14} />
  {#if text}<span>{text}</span><Icon name="chevron-down" size={12} />{/if}
</button>

{#if open}
  <div
    bind:this={menu}
    {id}
    class="menu"
    role="menu"
    aria-label={label}
    tabindex="-1"
    style:top="{pos.top}px"
    style:left="{pos.left}px"
    onkeydown={onMenuKey}
  >
    {#each items as item, i (i)}
      {#if item.divider}<div class="sep" role="separator"></div>{/if}
      <button
        type="button"
        role="menuitem"
        class="item"
        class:danger={item.danger}
        disabled={item.disabled}
        title={item.hint}
        onclick={() => choose(item)}
      >
        {#if item.icon}<Icon name={item.icon} size={14} />{/if}
        <span>{item.label}</span>
      </button>
    {/each}
  </div>
{/if}

<style>
  .btn-icon-only {
    width: 28px;
    padding: 0;
  }
  .menu {
    position: fixed;
    z-index: 70;
    min-width: 200px;
    max-width: calc(100vw - 16px);
    padding: var(--space-1);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: var(--surface-raised);
    box-shadow: var(--shadow-lg);
  }
  .item {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    width: 100%;
    min-height: 32px;
    padding: 0 var(--space-2);
    border: none;
    border-radius: var(--radius-sm);
    background: none;
    color: var(--text);
    font: inherit;
    font-size: var(--text-sm);
    text-align: start;
    white-space: nowrap;
    cursor: pointer;
  }
  .item:hover:not(:disabled),
  .item:focus-visible {
    background: var(--surface-hover);
    outline: none;
  }
  .item:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }
  .item.danger {
    color: var(--danger);
  }
  .item.danger:hover:not(:disabled),
  .item.danger:focus-visible {
    background: var(--danger-soft);
  }
  .sep {
    height: 1px;
    margin: var(--space-1) 0;
    background: var(--border);
  }
  @media (max-width: 720px) {
    .btn-icon-only {
      width: 36px;
      height: 36px;
    }
    .item {
      min-height: 40px;
    }
  }
</style>
