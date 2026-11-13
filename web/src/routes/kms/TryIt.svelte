<!--
  "Try it": run Encrypt/Decrypt (or Sign/Verify for signing keys) against the
  selected key, as the signed-in user. Only FIPS-approved algorithms are
  offered.
-->
<script lang="ts">
  import Icon from '#lib/components/Icon.svelte';
  import Badge from '#lib/components/Badge.svelte';
  import CopyButton from '#lib/components/CopyButton.svelte';
  import { errorMessage } from '#lib/api.ts';
  import {
    kms,
    encryptionAlgorithms,
    signingAlgorithms,
    toB64,
    fromB64,
    parseContext,
    SYMMETRIC,
    type KeyDetail
  } from './api';

  let { detail }: { detail: KeyDetail } = $props();

  const keyId = $derived(detail.keyId);
  const signing = $derived(detail.keyUsage === 'SIGN_VERIFY');
  const symmetric = $derived(detail.keySpec === SYMMETRIC);
  const ops = $derived(signing ? (['Sign', 'Verify'] as const) : (['Encrypt', 'Decrypt'] as const));
  const usable = $derived(detail.enabled && !detail.deletionDate);
  const uid = Math.random().toString(36).slice(2, 8);

  type Op = 'Encrypt' | 'Decrypt' | 'Sign' | 'Verify';
  let op = $state<Op>('Encrypt');
  let input = $state('');
  let context = $state('');
  let signature = $state('');
  let digest = $state(false);
  let algorithm = $state('');
  let busy = $state(false);
  let error = $state('');
  let result = $state<{ kind: 'blob' | 'text' | 'binary' | 'valid' | 'invalid'; value: string; label: string } | null>(null);

  const algorithms = $derived(signing ? signingAlgorithms(detail) : encryptionAlgorithms(detail));

  // Reset whenever another key is selected (not when the same key reloads).
  $effect(() => {
    void keyId;
    op = signing ? 'Sign' : 'Encrypt';
    input = '';
    context = '';
    signature = '';
    digest = false;
    result = null;
    error = '';
  });
  $effect(() => {
    if (!algorithms.includes(algorithm)) algorithm = algorithms[0];
  });

  function pick(next: Op) {
    if (next === op) return;
    op = next;
    result = null;
    error = '';
  }

  const inputLabel = $derived(
    op === 'Encrypt' ? 'Plaintext' : op === 'Decrypt' ? 'Ciphertext blob (base64)' : digest ? 'Message digest (base64)' : 'Message'
  );

  async function run(e: SubmitEvent) {
    e.preventDefault();
    if (busy || !input.trim()) return;
    busy = true;
    error = '';
    result = null;
    try {
      const encryptionContext = symmetric && !signing ? parseContext(context) : undefined;
      if (op === 'Encrypt') {
        const r = await kms.encrypt({ keyId: detail.keyId, plaintext: toB64(input), encryptionContext, encryptionAlgorithm: algorithm });
        result = { kind: 'blob', value: r.ciphertextBlob, label: 'Ciphertext blob (base64)' };
      } else if (op === 'Decrypt') {
        const r = await kms.decrypt({
          keyId: detail.keyId,
          ciphertextBlob: input.trim(),
          encryptionContext,
          encryptionAlgorithm: algorithm
        });
        const text = fromB64(r.plaintext);
        result = text === null
          ? { kind: 'binary', value: r.plaintext, label: 'Plaintext (binary, base64)' }
          : { kind: 'text', value: text, label: 'Plaintext' };
      } else if (op === 'Sign') {
        const r = await kms.sign({
          keyId: detail.keyId,
          message: digest ? input.trim() : toB64(input),
          messageType: digest ? 'DIGEST' : 'RAW',
          signingAlgorithm: algorithm
        });
        result = { kind: 'blob', value: r.signature, label: 'Signature (base64)' };
      } else {
        const r = await kms.verify({
          keyId: detail.keyId,
          message: digest ? input.trim() : toB64(input),
          messageType: digest ? 'DIGEST' : 'RAW',
          signature: signature.trim(),
          signingAlgorithm: algorithm
        });
        result = { kind: r.signatureValid ? 'valid' : 'invalid', value: '', label: 'Result' };
      }
    } catch (err) {
      error = errorMessage(err);
    } finally {
      busy = false;
    }
  }

  /** Hand the output to the inverse operation. */
  function carry() {
    if (!result) return;
    if (op === 'Encrypt') {
      const blob = result.value;
      pick('Decrypt');
      input = blob;
    } else if (op === 'Sign') {
      const sig = result.value;
      pick('Verify');
      signature = sig;
    }
  }
</script>

<section class="try" aria-labelledby="try-{uid}">
  <div class="try-head">
    <h3 id="try-{uid}"><Icon name="activity" size={14} />Try it</h3>
    <div class="seg" role="group" aria-label="Operation">
      {#each ops as o (o)}
        <button type="button" aria-pressed={op === o} onclick={() => pick(o)}>{o}</button>
      {/each}
    </div>
  </div>
  <form class="try-body" onsubmit={run}>
    {#if !usable}
      <div class="callout callout-warning" role="note">
        <Icon name="alert-triangle" size={16} />
        <span>This key is {detail.deletionDate ? 'pending deletion' : 'disabled'}, so cryptographic operations are refused.</span>
      </div>
    {/if}
    <label class="field">
      <span class="field-label">{inputLabel}</span>
      <textarea class="textarea mono" rows="2" bind:value={input} spellcheck="false" autocomplete="off"
        placeholder={op === 'Encrypt' ? 'hello from the staging smoke test' : op === 'Decrypt' ? 'AQICAH…' : ''}></textarea>
    </label>
    {#if op === 'Verify'}
      <label class="field">
        <span class="field-label">Signature (base64)</span>
        <textarea class="textarea mono" rows="2" bind:value={signature} spellcheck="false" autocomplete="off"></textarea>
      </label>
    {/if}
    {#if signing}
      <div class="try-row">
        <label class="field grow">
          <span class="field-label">Signing algorithm</span>
          <select class="select mono" bind:value={algorithm}>
            {#each algorithms as a (a)}<option value={a}>{a}</option>{/each}
          </select>
        </label>
        <label class="check">
          <input type="checkbox" bind:checked={digest} />
          <span>Message is a pre-computed digest</span>
        </label>
      </div>
    {:else if symmetric}
      <label class="field">
        <span class="field-label">Encryption context <span class="subtle opt">(optional)</span></span>
        <input class="input mono" bind:value={context} placeholder="service=payments-api" spellcheck="false" autocomplete="off" />
        <span class="field-hint">Comma-separated key=value pairs, or a JSON object. Decrypt needs the same context.</span>
      </label>
    {:else}
      <p class="field-hint algo">Algorithm <span class="mono">{algorithm}</span></p>
    {/if}
    <div class="try-run">
      <button type="submit" class="btn btn-primary btn-sm" disabled={busy || !usable || !input.trim() || (op === 'Verify' && !signature.trim())}>
        <Icon name={op === 'Encrypt' ? 'lock' : op === 'Decrypt' ? 'key' : op === 'Sign' ? 'edit' : 'shield-check'} size={14} />
        {busy ? `${op === 'Sign' ? 'Signing' : op === 'Verify' ? 'Verifying' : op + 'ing'}…` : op}
      </button>
      <span class="field-hint">Runs as you. The call is written to the audit log.</span>
    </div>
    <div aria-live="polite">
      {#if error}
        <div class="callout callout-danger" role="alert"><Icon name="alert-circle" size={16} /><span>{error}</span></div>
      {:else if result}
        {#if result.kind === 'valid' || result.kind === 'invalid'}
          <div class="verdict">
            {#if result.kind === 'valid'}
              <Badge tone="success" dot={false}><Icon name="check-circle" size={12} />Signature valid</Badge>
            {:else}
              <Badge tone="danger" dot={false}><Icon name="alert-circle" size={12} />Signature invalid</Badge>
            {/if}
            <span class="subtle small mono">{algorithm}</span>
          </div>
        {:else}
          <div class="field">
            <span class="out-head">
              <span class="field-label">{result.label}</span>
              <span class="out-actions">
                {#if op === 'Encrypt' || op === 'Sign'}
                  <button type="button" class="btn btn-ghost btn-sm" onclick={carry}>
                    {op === 'Encrypt' ? 'Decrypt this' : 'Verify this'}
                  </button>
                {/if}
                <CopyButton value={result.value} label="Copy {result.label.toLowerCase()}" clearAfter={result.kind === 'blob' ? undefined : 60} />
              </span>
            </span>
            <pre class="out">{result.value}</pre>
          </div>
        {/if}
      {/if}
    </div>
  </form>
</section>

<style>
  .try {
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    overflow: hidden;
  }
  .try-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--space-2);
    flex-wrap: wrap;
    padding: 10px var(--space-3);
    background: var(--surface-hover);
    border-bottom: 1px solid var(--border);
  }
  h3 {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    margin: 0;
    font: 600 var(--text-base) / 20px var(--font-sans);
  }
  h3 :global(svg) {
    color: var(--accent);
  }
  .try-body {
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
    padding: var(--space-3);
  }
  .try-body .field + .field {
    margin-top: 0;
  }
  .textarea {
    min-height: 0;
  }
  .opt {
    font-weight: 400;
  }
  .algo {
    margin: 0;
  }
  .try-row {
    display: flex;
    flex-wrap: wrap;
    align-items: flex-end;
    gap: var(--space-3);
  }
  .grow {
    flex: 1 1 200px;
  }
  .check {
    display: inline-flex;
    align-items: center;
    gap: var(--space-2);
    min-height: var(--ctl-h);
    font-size: var(--text-sm);
  }
  .try-run {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    flex-wrap: wrap;
  }
  .out-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--space-2);
  }
  .out-actions {
    display: inline-flex;
    align-items: center;
    gap: 2px;
  }
  .out {
    white-space: pre-wrap;
    word-break: break-all;
    max-height: 200px;
  }
  .verdict {
    display: flex;
    align-items: center;
    gap: var(--space-2);
  }
  /* Segmented control (DesignSystem "seg"). */
  .seg {
    display: inline-flex;
    flex-wrap: wrap;
    gap: 2px;
    padding: 3px;
    border-radius: var(--radius-md);
    background: var(--surface-pressed);
  }
  .seg button {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    height: 28px;
    padding: 0 10px;
    border: 0;
    border-radius: var(--radius-sm);
    background: transparent;
    color: var(--text-muted);
    font: 500 var(--text-sm) / 1 var(--font-sans);
    cursor: pointer;
  }
  .seg button[aria-pressed='true'] {
    background: var(--surface);
    color: var(--text);
    box-shadow: var(--shadow-xs);
  }
</style>
