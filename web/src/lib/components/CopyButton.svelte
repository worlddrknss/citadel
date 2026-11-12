<script lang="ts">
  import { toast } from '$lib/stores/toast.svelte';
  import Icon from './Icon.svelte';

  let {
    value,
    label = 'Copy',
    /** Clears the clipboard after this many seconds if it still holds the value. */
    clearAfter
  }: {
    value: string | (() => Promise<string> | string);
    label?: string;
    clearAfter?: number;
  } = $props();

  let copied = $state(false);

  async function copy() {
    try {
      const text = typeof value === 'function' ? await value() : value;
      await navigator.clipboard.writeText(text);
      copied = true;
      setTimeout(() => (copied = false), 1500);
      if (clearAfter) {
        setTimeout(async () => {
          try {
            if ((await navigator.clipboard.readText()) === text) await navigator.clipboard.writeText('');
          } catch {
            /* reading the clipboard needs permission; best effort */
          }
        }, clearAfter * 1000);
      }
    } catch (e) {
      toast.error(e, 'Copy failed');
    }
  }
</script>

<button type="button" class="btn-icon" aria-label={copied ? 'Copied' : label} title={copied ? 'Copied' : label} onclick={copy}>
  <Icon name={copied ? 'check' : 'copy'} size={14} />
</button>
