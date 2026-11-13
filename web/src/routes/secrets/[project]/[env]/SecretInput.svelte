<!--
  Multiline secret value input, masked until the user chooses to show it.
  Browsers that support -webkit-text-security draw discs; others blur the
  text instead, so the value is never shown in the clear by default.
-->
<script lang="ts">
  import Icon from '$lib/components/Icon.svelte';

  let {
    value = $bindable(''),
    id,
    rows = 4,
    placeholder = '',
    describedby,
    autofocus = false
  }: {
    value?: string;
    id: string;
    rows?: number;
    placeholder?: string;
    describedby?: string;
    autofocus?: boolean;
  } = $props();

  let shown = $state(false);
  let el = $state<HTMLTextAreaElement>();

  $effect(() => {
    if (autofocus) el?.focus();
  });
</script>

<div class="wrap">
  <textarea
    bind:this={el}
    {id}
    class="textarea mono"
    class:masked={!shown}
    {rows}
    {placeholder}
    bind:value
    autocomplete="off"
    autocapitalize="off"
    spellcheck="false"
    data-1p-ignore
    data-lpignore="true"
    aria-describedby={describedby}
  ></textarea>
  <div class="bar">
    <span class="subtle small num">{value.length} character{value.length === 1 ? '' : 's'}{value.includes('\n') ? ` · ${value.split('\n').length} lines` : ''}</span>
    <button type="button" class="btn btn-ghost btn-sm" aria-pressed={shown} aria-controls={id} onclick={() => (shown = !shown)}>
      <Icon name={shown ? 'eye-off' : 'eye'} size={14} />{shown ? 'Hide' : 'Show'}
    </button>
  </div>
</div>

<style>
  .wrap {
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
  }
  .textarea {
    font-family: var(--font-mono);
    font-size: 13.5px;
    white-space: pre;
    overflow-wrap: normal;
    overflow-x: auto;
  }
  .masked {
    -webkit-text-security: disc;
  }
  @supports not (-webkit-text-security: disc) {
    .masked {
      color: transparent;
      text-shadow: 0 0 7px var(--text);
    }
  }
  .bar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--space-2);
  }
</style>
