<!-- Key state as icon + text + color, never color alone. -->
<script lang="ts">
  import Badge from '#lib/components/Badge.svelte';
  import Icon from '#lib/components/Icon.svelte';
  import type { Status } from './api';

  let { status }: { status: Status } = $props();
</script>

{#if status === 'Enabled'}
  <Badge tone="success" dot={false}><Icon name="check-circle" size={12} />Enabled</Badge>
{:else if status === 'Pending deletion'}
  <Badge tone="danger" dot={false}><Icon name="clock" size={12} />Pending deletion</Badge>
{:else}
  <!-- No hollow "circle" icon in the shared set; the badge dot stands in. -->
  <Badge tone="neutral">Disabled</Badge>
{/if}
