<!--
  Shows secret material the server returns exactly once (a generated private
  key, an EAB HMAC key). The dialog only closes after the user confirms they
  saved it; values are copyable and downloadable.
-->
<script lang="ts" module>
  export interface SecretField {
    label: string;
    value: string;
    /** Render in a scrolling block (PEM) rather than one line. */
    multiline?: boolean;
    /** Offer a download under this file name. */
    filename?: string;
    /** True for the secret parts; they get the warning styling. */
    secret?: boolean;
  }
</script>

<script lang="ts">
  import Modal from '$lib/components/Modal.svelte';
  import CopyButton from '$lib/components/CopyButton.svelte';
  import Icon from '$lib/components/Icon.svelte';
  import { toast } from '$lib/stores/toast.svelte';
  import { downloadText } from './certs';


  let {
    open = $bindable(false),
    title,
    description,
    fields,
    ondone
  }: {
    open?: boolean;
    title: string;
    description: string;
    fields: SecretField[];
    ondone?: () => void;
  } = $props();

  let saved = $state(false);
  $effect(() => {
    if (open) saved = false;
  });

  function onclose() {
    if (!saved) {
      // Esc or the close button: keep the secret on screen until acknowledged.
      toast.info("Confirm you've saved it first — it can't be shown again.");
      queueMicrotask(() => (open = true));
      return;
    }
    ondone?.();
  }

  function done() {
    open = false;
    ondone?.();
  }
</script>

<Modal bind:open {title} {description} size="md" {onclose}>
  <div class="once">
    <div class="callout callout-warning" role="note">
      <Icon name="alert-triangle" size={16} />
      <span>This is the only time Citadel shows this. Store it in a secret manager before closing.</span>
    </div>
    {#each fields as f (f.label)}
      <div class="field">
        <div class="row">
          <span class="field-label">{f.label}</span>
          <span class="tools">
            <CopyButton value={f.value} label="Copy {f.label}" clearAfter={f.secret ? 60 : undefined} />
            {#if f.filename}
              <button
                type="button"
                class="btn-icon"
                aria-label="Download {f.label}"
                title="Download"
                onclick={() => downloadText(f.filename!, f.value)}
              >
                <Icon name="download" size={14} />
              </button>
            {/if}
          </span>
        </div>
        {#if f.multiline}
          <pre class="val" class:secret={f.secret}>{f.value}</pre>
        {:else}
          <code class="val one" class:secret={f.secret}>{f.value}</code>
        {/if}
      </div>
    {/each}
    <label class="ack">
      <input type="checkbox" bind:checked={saved} />
      <span>I've saved it somewhere safe</span>
    </label>
  </div>
  {#snippet footer()}
    <button type="button" class="btn btn-primary" disabled={!saved} onclick={done}>Done</button>
  {/snippet}
</Modal>

<style>
  .once {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
  }
  .field + .field {
    margin-top: 0;
  }
  .row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--space-2);
  }
  .tools {
    display: inline-flex;
  }
  .val {
    margin: 0;
    max-height: 220px;
    overflow: auto;
    font-size: 12px;
    white-space: pre;
  }
  .val.one {
    display: block;
    padding: 8px 10px;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    overflow-wrap: anywhere;
    white-space: normal;
  }
  .val.secret {
    border-color: var(--warning);
  }
  .ack {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    font-weight: 500;
    cursor: pointer;
  }
</style>
