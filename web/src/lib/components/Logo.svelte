<script lang="ts">
  let { compact = false }: { compact?: boolean } = $props();
</script>

<span class="logo">
  <svg width="28" height="28" viewBox="0 0 32 32" aria-hidden="true">
    <rect width="32" height="32" rx="8" fill="var(--accent)" />
    <path
      d="M9 24V13l2.5-1.5V9l2.5 1.5L16 7l2 3.5L20.5 9v2.5L23 13v11"
      fill="none"
      stroke="var(--accent-contrast)"
      stroke-width="2"
      stroke-linejoin="round"
    />
    <path d="M14 24v-4a2 2 0 0 1 4 0v4" fill="none" stroke="var(--accent-contrast)" stroke-width="2" />
  </svg>
  {#if !compact}<span class="logo-text">Citadel</span>{/if}
</span>

<style>
  .logo {
    display: inline-flex;
    align-items: center;
    gap: 10px;
  }
  .logo-text {
    font-size: var(--text-md);
    font-weight: 650;
    letter-spacing: -0.01em;
    color: var(--text);
  }
</style>
