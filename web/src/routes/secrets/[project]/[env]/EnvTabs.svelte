<!--
  Environment switcher styled as the board's tab row: a tone swatch per tier
  (dev info, staging warning, prod danger), live secret counts when the
  backend reports them, and "Add environment" for editors. Each tab is a link,
  since switching environments is navigation.
-->
<script lang="ts">
  import { base } from '$app/paths';
  import Icon from '$lib/components/Icon.svelte';
  import { envLabel, tierTone, type Tier } from '../../lib';

  let {
    project,
    envs,
    current,
    tiers,
    counts,
    canAdd,
    onadd
  }: {
    project: string;
    envs: string[];
    current: string;
    tiers: Record<string, Tier>;
    counts?: Record<string, number>;
    canAdd: boolean;
    onadd: () => void;
  } = $props();
</script>

<nav class="tabs" aria-label="Environment">
  {#each envs as env (env)}
    <a
      class="tab"
      href="{base}/secrets/{encodeURIComponent(project)}/{encodeURIComponent(env)}"
      aria-current={env === current ? 'page' : undefined}
    >
      <span class="swatch swatch-{tierTone[tiers[env] ?? 'other']}" aria-hidden="true"></span>
      {envLabel(env)}
      {#if counts?.[env] !== undefined}
        <span class="count num" aria-label="{counts[env]} secrets">{counts[env]}</span>
      {/if}
    </a>
  {/each}
  {#if canAdd}
    <button type="button" class="tab tab-add" onclick={onadd}>
      <Icon name="plus" size={14} /><span>Add environment</span>
    </button>
  {/if}
</nav>

<style>
  .tabs {
    display: flex;
    gap: var(--space-6);
    border-bottom: 1px solid var(--border);
    overflow-x: auto;
    scrollbar-width: none;
  }
  .tab {
    display: inline-flex;
    align-items: center;
    gap: var(--space-2);
    height: 40px;
    padding: 0 2px;
    margin-bottom: -1px;
    border: none;
    border-bottom: 2px solid transparent;
    background: none;
    color: var(--text-muted);
    font: inherit;
    font-size: var(--text-base);
    font-weight: 500;
    white-space: nowrap;
    cursor: pointer;
    text-decoration: none;
  }
  .tab:hover {
    color: var(--text);
    text-decoration: none;
  }
  .tab[aria-current='page'] {
    color: var(--text);
    border-bottom-color: var(--accent);
  }
  .tab-add {
    color: var(--text-subtle);
  }
  .swatch {
    width: 8px;
    height: 8px;
    border-radius: 2px;
    background: var(--text-subtle);
    flex-shrink: 0;
  }
  .swatch-info {
    background: var(--info);
  }
  .swatch-warning {
    background: var(--warning);
  }
  .swatch-danger {
    background: var(--danger);
  }
  .count {
    padding: 0 6px;
    border-radius: 999px;
    background: var(--surface-pressed);
    color: var(--text-muted);
    font-size: var(--text-xs);
    line-height: 16px;
  }
</style>
