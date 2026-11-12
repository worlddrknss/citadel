<!-- Status pill. Tone sets color; the text always states the status too, so
     it never relies on color alone. -->
<script lang="ts">
  import type { Snippet } from 'svelte';

  let {
    tone = 'neutral',
    dot = true,
    children
  }: {
    tone?: 'neutral' | 'success' | 'warning' | 'danger' | 'info';
    dot?: boolean;
    children: Snippet;
  } = $props();
</script>

<span class="badge badge-{tone}">
  {#if dot}<span class="badge-dot" aria-hidden="true"></span>{/if}
  {@render children()}
</span>
