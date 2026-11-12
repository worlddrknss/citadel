<script lang="ts">
  import { toast } from '$lib/stores/toast.svelte';
  import Icon from './Icon.svelte';

  const icons = { success: 'check-circle', error: 'alert-circle', info: 'info' } as const;
</script>

<!-- Polite live region: screen readers announce messages without stealing focus. -->
<div class="toaster" role="status" aria-live="polite">
  {#each toast.items as t (t.id)}
    <div class="toast toast-{t.kind}">
      <Icon name={icons[t.kind]} />
      <span class="toast-msg">{t.message}</span>
      <button type="button" class="btn-icon" aria-label="Dismiss" onclick={() => toast.dismiss(t.id)}>
        <Icon name="x" size={14} />
      </button>
    </div>
  {/each}
</div>

<style>
  .toaster {
    position: fixed;
    right: var(--space-4);
    bottom: var(--space-4);
    z-index: 100;
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
    width: min(400px, calc(100vw - 32px));
    pointer-events: none;
  }
  .toast {
    pointer-events: auto;
    display: flex;
    align-items: flex-start;
    gap: var(--space-3);
    padding: var(--space-3) var(--space-3) var(--space-3) var(--space-4);
    border-radius: var(--radius-md);
    border: 1px solid var(--border);
    background: var(--surface-raised);
    color: var(--text);
    box-shadow: var(--shadow-lg);
    font-size: var(--text-sm);
    animation: toast-in 160ms ease-out;
  }
  .toast-msg {
    flex: 1;
    line-height: 1.45;
    padding-top: 1px;
  }
  .toast-success :global(svg:first-child) { color: var(--success); }
  .toast-error :global(svg:first-child) { color: var(--danger); }
  .toast-info :global(svg:first-child) { color: var(--accent); }
  @keyframes toast-in {
    from { transform: translateY(8px); opacity: 0; }
  }
  @media (prefers-reduced-motion: reduce) {
    .toast { animation: none; }
  }
</style>
