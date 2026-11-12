<!-- Citadel mark + wordmark. "ink" (sidebar) uses the text color as the tile;
     "accent" (sign-in) uses the brand accent. -->
<script lang="ts">
  let {
    compact = false,
    tone = 'ink',
    size = 'md'
  }: { compact?: boolean; tone?: 'ink' | 'accent'; size?: 'md' | 'lg' } = $props();
</script>

<span class="logo logo-{size}">
  <span class="tile tile-{tone}" aria-hidden="true">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">
      <path d="M5 3.5h3v2h2.5v-2h3v2H16v-2h3V11c0 5-3 8.6-7 10-4-1.4-7-5-7-10z" />
      <circle cx="12" cy="11.5" r="1.8" />
      <path d="M12 13.3V16" />
    </svg>
  </span>
  {#if !compact}<span class="word">Citadel</span>{/if}
</span>

<style>
  .logo {
    display: inline-flex;
    align-items: center;
    gap: 10px;
    color: var(--text);
  }
  .tile {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 28px;
    height: 28px;
    border-radius: 8px;
    flex: none;
  }
  .tile svg {
    width: 18px;
    height: 18px;
  }
  .tile-ink {
    background: var(--text);
    color: var(--bg);
  }
  .tile-accent {
    background: var(--accent);
    color: var(--accent-contrast);
  }
  .logo-lg .tile {
    width: 32px;
    height: 32px;
    border-radius: 9px;
  }
  .logo-lg .tile svg {
    width: 20px;
    height: 20px;
  }
  .word {
    font: 600 16px/1 var(--font-display);
    letter-spacing: -0.01em;
  }
  .logo-lg .word {
    font-size: 18px;
  }
</style>
