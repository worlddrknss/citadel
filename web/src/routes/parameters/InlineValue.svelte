<!--
  A non-secret value shown inline (String / StringList). Loads on mount when
  `auto` is set, otherwise on demand.
-->
<script lang="ts">
  import { onMount } from 'svelte';
  import { errorMessage } from '#lib/api.ts';
  import CopyButton from '#lib/components/CopyButton.svelte';
  import Icon from '#lib/components/Icon.svelte';

  let {
    load,
    initial,
    auto = false,
    list = false
  }: {
    load: () => Promise<string>;
    initial?: string;
    auto?: boolean;
    /** StringList: render the comma-separated items as chips. */
    list?: boolean;
  } = $props();

  let value = $state<string | null>(null);
  let loading = $state(false);
  let error = $state('');

  $effect(() => {
    if (initial !== undefined) value = initial;
  });

  async function fetchValue() {
    loading = true;
    error = '';
    try {
      value = await load();
    } catch (e) {
      error = errorMessage(e);
    } finally {
      loading = false;
    }
  }

  onMount(() => {
    if (auto && value === null) fetchValue();
  });
</script>

<span class="iv">
  {#if value !== null}
    {#if list && value.includes(',')}
      <span class="chips">
        {#each value.split(',') as item, i (i)}<code class="chip">{item}</code>{/each}
      </span>
    {:else}
      <code class="val" title={value}>{value === '' ? '(empty)' : value}</code>
    {/if}
    <CopyButton value={value} label="Copy value" />
  {:else if loading}
    <span class="skeleton sk" aria-label="Loading value"></span>
  {:else if error}
    <span class="err small" title={error}><Icon name="alert-circle" size={12} />Couldn't load</span>
    <button type="button" class="btn btn-ghost btn-sm" onclick={fetchValue}>Retry</button>
  {:else}
    <button type="button" class="btn btn-ghost btn-sm" onclick={fetchValue}><Icon name="eye" size={14} />Show value</button>
  {/if}
</span>

<style>
  .iv {
    display: inline-flex;
    align-items: center;
    gap: var(--space-1);
    min-width: 0;
    max-width: 100%;
  }
  .val {
    min-width: 0;
    max-width: 360px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .chips {
    display: inline-flex;
    flex-wrap: wrap;
    gap: 4px;
    min-width: 0;
    max-width: 360px;
  }
  .chip {
    white-space: nowrap;
  }
  .sk {
    width: 120px;
    height: 12px;
  }
  .err {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    color: var(--danger);
  }
</style>
