<!--
  A QR code drawn as an inline SVG from a locally computed module matrix
  (uqr). Always dark on white, whatever the theme: scanners need contrast.
-->
<script lang="ts">
  import { qrPath } from '../mfa.ts';

  let { value, label, size = 196 }: { value: string; label: string; size?: number } = $props();
  const qr = $derived(qrPath(value));
</script>

<svg class="qr" role="img" aria-label={label} width={size} height={size} viewBox="0 0 {qr.size} {qr.size}" shape-rendering="crispEdges">
  <rect width={qr.size} height={qr.size} fill="#fff" />
  <path d={qr.d} fill="#000" />
</svg>

<style>
  .qr {
    display: block;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
  }
</style>
