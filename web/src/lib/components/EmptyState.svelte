<script lang="ts">
  import type { Snippet } from 'svelte';
  import Icon, { type IconName } from './Icon.svelte';

  let {
    icon,
    title,
    description,
    children
  }: {
    icon: IconName;
    title: string;
    description?: string;
    /** Call-to-action buttons. */
    children?: Snippet;
  } = $props();
</script>

<div class="empty">
  <div class="empty-icon"><Icon name={icon} size={22} /></div>
  <h3>{title}</h3>
  {#if description}<p>{description}</p>{/if}
  {#if children}<div class="empty-actions">{@render children()}</div>{/if}
</div>

<style>
  .empty {
    display: flex;
    flex-direction: column;
    align-items: center;
    text-align: center;
    gap: var(--space-2);
    max-width: 420px;
    margin: 0 auto;
  }
  .empty-icon {
    display: grid;
    place-items: center;
    width: 44px;
    height: 44px;
    margin-bottom: var(--space-1);
    border-radius: var(--radius-md);
    background: var(--accent-soft);
    color: var(--accent);
  }
  h3 {
    margin: 0;
    font-size: var(--text-md);
    font-weight: 600;
  }
  p {
    margin: 0;
    color: var(--text-muted);
    font-size: var(--text-sm);
    line-height: 1.5;
  }
  .empty-actions {
    display: flex;
    flex-wrap: wrap;
    justify-content: center;
    gap: var(--space-2);
    margin-top: var(--space-3);
  }
</style>
