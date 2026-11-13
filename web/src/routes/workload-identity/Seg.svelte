<!--
  Segmented control (toggle-button group) from the Verdigris design system.
  Page-local until a shared version exists in $lib/components.
-->
<script lang="ts" generics="V extends string">
  let {
    options,
    value = $bindable(),
    label,
    onchange
  }: {
    options: { value: V; label: string; count?: number }[];
    value: V;
    label: string;
    onchange?: (v: V) => void;
  } = $props();
</script>

<div class="seg" role="group" aria-label={label}>
  {#each options as o (o.value)}
    <button
      type="button"
      aria-pressed={value === o.value}
      onclick={() => {
        value = o.value;
        onchange?.(o.value);
      }}
    >
      {o.label}
      {#if o.count !== undefined}<span class="count num">{o.count}</span>{/if}
    </button>
  {/each}
</div>

<style>
  .seg {
    display: inline-flex;
    flex-wrap: wrap;
    gap: 2px;
    padding: 3px;
    border-radius: var(--radius-md);
    background: var(--surface-pressed);
  }
  .seg button {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    height: 28px;
    padding: 0 10px;
    border: 0;
    border-radius: var(--radius-sm);
    background: transparent;
    color: var(--text-muted);
    font: inherit;
    font-size: 13.5px;
    font-weight: 500;
    white-space: nowrap;
    cursor: pointer;
  }
  .seg button:hover {
    color: var(--text);
  }
  .seg button[aria-pressed='true'] {
    background: var(--surface);
    color: var(--text);
    box-shadow: var(--shadow-xs);
  }
  .count {
    padding: 0 6px;
    border-radius: 999px;
    background: var(--surface-pressed);
    color: var(--text-muted);
    font-size: var(--text-xs);
    line-height: 16px;
  }
  @media (max-width: 820px) {
    .seg button {
      height: 36px;
    }
  }
</style>
