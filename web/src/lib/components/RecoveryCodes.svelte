<!--
  One-time display of MFA recovery codes with copy, download and an
  "I've saved them" acknowledgement that gates `ondone`.
-->
<script lang="ts">
  import Icon from './Icon.svelte';
  import CopyButton from './CopyButton.svelte';
  import { recoveryCodesText } from '../mfa.ts';

  let { codes, username, ondone, doneLabel = 'Done' }: { codes: string[]; username: string; ondone: () => void; doneLabel?: string } = $props();
  let saved = $state(false);
  const text = $derived(recoveryCodesText(codes, username));

  function download() {
    const url = URL.createObjectURL(new Blob([text], { type: 'text/plain' }));
    const a = document.createElement('a');
    a.href = url;
    a.download = 'citadel-recovery-codes.txt';
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
</script>

<div class="rc">
  <div class="callout callout-warning" role="note">
    <Icon name="alert-triangle" size={16} />
    <span>Save these recovery codes now. Each one signs you in once if you lose your authenticator, and Citadel won't show them again.</span>
  </div>
  <ol class="codes mono" aria-label="Recovery codes">
    {#each codes as c (c)}<li>{c}</li>{/each}
  </ol>
  <div class="tools">
    <CopyButton value={codes.join('\n')} label="Copy recovery codes" clearAfter={60} />
    <span class="subtle small">Copy</span>
    <button type="button" class="btn btn-secondary btn-sm" onclick={download}><Icon name="download" size={14} />Download .txt</button>
  </div>
  <label class="ack">
    <input type="checkbox" bind:checked={saved} />
    <span>I've saved my recovery codes</span>
  </label>
  <div class="end">
    <button type="button" class="btn btn-primary" disabled={!saved} onclick={ondone}>{doneLabel}</button>
  </div>
</div>

<style>
  .rc {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
  }
  .callout {
    margin: 0;
  }
  .codes {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
    gap: 6px 16px;
    margin: 0;
    padding: 12px 16px 12px 36px;
    border: 1px solid var(--warning);
    border-radius: var(--radius-md);
    font-size: 14px;
  }
  .tools {
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .tools .btn {
    margin-left: auto;
  }
  .ack {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    font-weight: 500;
    cursor: pointer;
  }
  .end {
    display: flex;
    justify-content: flex-end;
  }
</style>
