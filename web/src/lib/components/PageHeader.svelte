<script lang="ts">
  import type { Snippet } from 'svelte';
  import Icon from './Icon.svelte';

  let {
    title,
    description,
    crumbs = [],
    actions
  }: {
    title: string;
    description?: string;
    /** Breadcrumb trail above the title; the last crumb is the current page. */
    crumbs?: { label: string; href?: string }[];
    actions?: Snippet;
  } = $props();
</script>

<header class="ph">
  {#if crumbs.length}
    <nav aria-label="Breadcrumb">
      <ol class="crumbs">
        {#each crumbs as c, i (i)}
          <li>
            {#if c.href && i < crumbs.length - 1}
              <a href={c.href}>{c.label}</a>
            {:else}
              <span aria-current={i === crumbs.length - 1 ? 'page' : undefined}>{c.label}</span>
            {/if}
            {#if i < crumbs.length - 1}<Icon name="chevron-right" size={12} />{/if}
          </li>
        {/each}
      </ol>
    </nav>
  {/if}
  <div class="ph-row">
    <div class="ph-text">
      <h1>{title}</h1>
      {#if description}<p>{description}</p>{/if}
    </div>
    {#if actions}<div class="ph-actions">{@render actions()}</div>{/if}
  </div>
</header>

<style>
  .ph {
    margin-bottom: var(--space-6);
  }
  .crumbs {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--space-1);
    margin: 0 0 var(--space-2);
    padding: 0;
    list-style: none;
    font-size: var(--text-sm);
    color: var(--text-muted);
  }
  .crumbs li {
    display: inline-flex;
    align-items: center;
    gap: var(--space-1);
  }
  .crumbs a {
    color: var(--text-muted);
    text-decoration: none;
  }
  .crumbs a:hover {
    color: var(--text);
    text-decoration: underline;
  }
  .crumbs [aria-current] {
    color: var(--text);
  }
  .ph-row {
    display: flex;
    flex-wrap: wrap;
    align-items: flex-end;
    justify-content: space-between;
    gap: var(--space-4);
  }
  .ph-text {
    min-width: 0;
  }
  h1 {
    margin: 0;
    font-size: var(--text-2xl);
    font-weight: 600;
    letter-spacing: -0.01em;
  }
  p {
    margin: var(--space-1) 0 0;
    color: var(--text-muted);
    font-size: var(--text-sm);
    max-width: 68ch;
  }
  .ph-actions {
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-2);
  }
</style>
