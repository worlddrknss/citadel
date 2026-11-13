<!--
  A masked secret. The value is fetched only when revealed or copied, hides
  itself again after `hideAfter` seconds, and copies clear the clipboard.
-->
<script lang="ts">
  import { onDestroy } from 'svelte';
  import { toast } from '#lib/stores/toast.svelte.ts';
  import CopyButton from './CopyButton.svelte';
  import Icon from './Icon.svelte';

  let {
    load,
    hideAfter = 30
  }: {
    load: () => Promise<string>;
    hideAfter?: number;
  } = $props();

  let value = $state<string | null>(null);
  let loading = $state(false);
  let remaining = $state(0);
  let timer: ReturnType<typeof setInterval> | undefined;

  async function fetchValue(): Promise<string> {
    if (value !== null) return value;
    return await load();
  }

  async function toggle() {
    if (value !== null) {
      hide();
      return;
    }
    loading = true;
    try {
      value = await load();
      remaining = hideAfter;
      timer = setInterval(() => {
        remaining -= 1;
        if (remaining <= 0) hide();
      }, 1000);
    } catch (e) {
      toast.error(e, 'Could not reveal value');
    } finally {
      loading = false;
    }
  }

  function hide() {
    clearInterval(timer);
    value = null;
  }

  onDestroy(() => clearInterval(timer));
</script>

<span class="secret">
  {#if value !== null}
    <code class="secret-value">{value}</code>
    <span class="badge badge-warning secret-timer" aria-live="off">Hides in {remaining} s</span>
  {:else}
    <span class="secret-mask" aria-label="Hidden value">••••••••••••</span>
  {/if}
  <span class="secret-actions">
    <button
      type="button"
      class="btn-icon"
      aria-label={value !== null ? 'Hide value' : 'Reveal value'}
      title={value !== null ? 'Hide' : 'Reveal'}
      disabled={loading}
      onclick={toggle}
    >
      <Icon name={value !== null ? 'eye-off' : 'eye'} size={14} />
    </button>
    <CopyButton value={fetchValue} label="Copy value" clearAfter={30} />
  </span>
</span>

<style>
  .secret {
    display: inline-flex;
    align-items: center;
    gap: var(--space-2);
    min-width: 0;
    max-width: 100%;
  }
  .secret-value {
    font-family: var(--font-mono);
    font-size: var(--text-sm);
    padding: 2px 6px;
    border-radius: var(--radius-sm);
    background: var(--warning-soft);
    color: var(--text);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    min-width: 0;
  }
  .secret-timer {
    flex-shrink: 0;
    font-variant-numeric: tabular-nums;
  }
  .secret-mask {
    color: var(--text-subtle);
    letter-spacing: 1px;
    font-family: var(--font-mono);
  }
  .secret-actions {
    display: inline-flex;
    flex-shrink: 0;
  }
</style>
