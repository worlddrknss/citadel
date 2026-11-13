<!--
  Menu button: a trigger with aria-haspopup="menu" and a popup of menu items.
  Arrow keys move, Home/End jump, Esc closes and returns focus to the trigger.
  The popup is position: fixed so a table's scroll box or a card can't clip
  it; it opens upward when there isn't room below, and follows the trigger
  when any ancestor scrolls.
-->
<script lang="ts" module>
  import type { IconName } from '#lib/components/Icon.svelte';
  export interface MenuItem {
    label: string;
    icon?: IconName;
    danger?: boolean;
    disabled?: boolean;
    /** Renders the item as menuitemradio with this checked state. */
    checked?: boolean;
    onselect: () => void;
  }
</script>

<script lang="ts">
  import type { Snippet } from 'svelte';
  import { tick } from 'svelte';
  import Icon from '#lib/components/Icon.svelte';

  let {
    items,
    label,
    triggerClass = 'btn btn-ghost btn-sm btn-icon-sm',
    align = 'end',
    children
  }: {
    items: MenuItem[];
    /** Accessible name of the trigger. */
    label: string;
    triggerClass?: string;
    align?: 'start' | 'end';
    /** Trigger content; defaults to a "more" icon. */
    children?: Snippet;
  } = $props();

  let open = $state(false);
  let trigger = $state<HTMLButtonElement>();
  let menu = $state<HTMLDivElement>();
  let pos = $state<{ top?: number; bottom?: number; left: number; right: number }>({ top: 0, left: 0, right: 0 });
  const id = `menu-${Math.random().toString(36).slice(2, 9)}`;

  function place() {
    if (!trigger) return;
    const r = trigger.getBoundingClientRect();
    // Estimated height until the menu has rendered; measured after.
    const height = menu?.offsetHeight ?? 16 + items.length * 34;
    const below = window.innerHeight - r.bottom;
    const up = below < height + 8 && r.top > below;
    pos = up
      ? { bottom: window.innerHeight - r.top + 4, left: r.left, right: window.innerWidth - r.right }
      : { top: r.bottom + 4, left: r.left, right: window.innerWidth - r.right };
  }

  // Follow the trigger when the page or any scroll box around it scrolls.
  $effect(() => {
    if (!open) return;
    const onScroll = () => place();
    document.addEventListener('scroll', onScroll, true);
    return () => document.removeEventListener('scroll', onScroll, true);
  });

  async function show(focus: 'first' | 'last' = 'first') {
    place();
    open = true;
    await tick();
    place(); // now with the measured height
    const els = itemEls();
    (focus === 'first' ? els[0] : els[els.length - 1])?.focus();
  }

  function hide(returnFocus = true) {
    open = false;
    if (returnFocus) trigger?.focus();
  }

  function itemEls(): HTMLButtonElement[] {
    return menu ? [...menu.querySelectorAll<HTMLButtonElement>('button:not(:disabled)')] : [];
  }

  function onTriggerKey(e: KeyboardEvent) {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      show('first');
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      show('last');
    }
  }

  function onMenuKey(e: KeyboardEvent) {
    const els = itemEls();
    const i = els.indexOf(document.activeElement as HTMLButtonElement);
    let next = -1;
    if (e.key === 'ArrowDown') next = (i + 1) % els.length;
    else if (e.key === 'ArrowUp') next = (i - 1 + els.length) % els.length;
    else if (e.key === 'Home') next = 0;
    else if (e.key === 'End') next = els.length - 1;
    else if (e.key === 'Escape') {
      e.preventDefault();
      e.stopPropagation();
      hide();
      return;
    } else if (e.key === 'Tab') {
      hide(false);
      return;
    }
    if (next >= 0) {
      e.preventDefault();
      els[next]?.focus();
    }
  }

  function choose(item: MenuItem) {
    hide();
    item.onselect();
  }

  function onWindowPointer(e: PointerEvent) {
    if (!open) return;
    const t = e.target as Node;
    if (menu?.contains(t) || trigger?.contains(t)) return;
    hide(false);
  }
</script>

<svelte:window onpointerdown={onWindowPointer} onresize={() => open && hide(false)} />

<button
  bind:this={trigger}
  type="button"
  class={triggerClass}
  aria-haspopup="menu"
  aria-expanded={open}
  aria-controls={open ? id : undefined}
  aria-label={children ? undefined : label}
  title={children ? undefined : label}
  onclick={() => (open ? hide() : show())}
  onkeydown={onTriggerKey}
>
  {#if children}{@render children()}{:else}<Icon name="more" size={14} />{/if}
</button>

{#if open}
  <!-- svelte-ignore a11y_interactive_supports_focus -->
  <div
    bind:this={menu}
    {id}
    class="menu"
    role="menu"
    aria-label={label}
    style:top={pos.top !== undefined ? `${pos.top}px` : undefined}
    style:bottom={pos.bottom !== undefined ? `${pos.bottom}px` : undefined}
    style:left={align === 'start' ? `${pos.left}px` : undefined}
    style:right={align === 'end' ? `${pos.right}px` : undefined}
    onkeydown={onMenuKey}
  >
    {#each items as item (item.label)}
      <button
        type="button"
        role={item.checked === undefined ? 'menuitem' : 'menuitemradio'}
        aria-checked={item.checked}
        class="menu-item"
        class:danger={item.danger}
        disabled={item.disabled}
        tabindex="-1"
        onclick={() => choose(item)}
      >
        {#if item.checked !== undefined}
          <span class="menu-check" aria-hidden="true">{#if item.checked}<Icon name="check" size={14} />{/if}</span>
        {:else if item.icon}
          <Icon name={item.icon} size={14} />
        {/if}
        {item.label}
      </button>
    {/each}
  </div>
{/if}

<style>
  :global(.btn-icon-sm) {
    width: 28px;
    padding: 0;
  }
  .menu {
    position: fixed;
    z-index: 60;
    min-width: 180px;
    max-width: min(320px, calc(100vw - 32px));
    padding: 4px;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: var(--surface);
    box-shadow: var(--shadow-lg);
    display: flex;
    flex-direction: column;
  }
  .menu-item {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    min-height: 32px;
    padding: 0 var(--space-3) 0 var(--space-2);
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
  .menu-item:hover:not(:disabled),
  .menu-item:focus-visible {
    background: var(--surface-hover);
    outline: none;
  }
  .menu-item:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }
  .menu-item.danger {
    color: var(--danger);
  }
  .menu-item.danger:hover:not(:disabled),
  .menu-item.danger:focus-visible {
    background: var(--danger-soft);
  }
  .menu-check {
    display: inline-grid;
    place-items: center;
    width: 14px;
  }
</style>
