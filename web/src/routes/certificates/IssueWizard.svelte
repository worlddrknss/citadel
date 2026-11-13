<!-- Three-step "Issue certificate" dialog: issuer, subject & names, key &
     validity. The key is either generated inside Citadel (returned once) or
     comes from a pasted CSR. -->
<script lang="ts" module>
  export interface IssueResult {
    certId?: string;
    generated?: { certificatePem: string; chainPem: string; privateKeyPem: string; commonName: string };
  }
</script>

<script lang="ts">
  import { untrack } from 'svelte';
  import Modal from '#lib/components/Modal.svelte';
  import Icon from '#lib/components/Icon.svelte';
  import { toast } from '#lib/stores/toast.svelte.ts';
  import { errorMessage } from '#lib/api.ts';
  import { certApi, type CertRow, type KeyAlgorithm, type Template } from './api';
  import { cnOf, keyAlgLabel, yearOf, KEY_ALGORITHMS } from './certs';


  let {
    open = $bindable(false),
    cas,
    initialCaId = '',
    oncomplete
  }: {
    open?: boolean;
    cas: CertRow[];
    initialCaId?: string;
    oncomplete: (r: IssueResult) => void;
  } = $props();

  const steps = ['Issuer', 'Subject & names', 'Key & validity'];
  let step = $state(0);
  let caId = $state('');
  let cn = $state('');
  let sans = $state<string[]>([]);
  let sanDraft = $state('');
  let template = $state<Template>('server');
  let keyMode = $state<'generate' | 'csr'>('generate');
  let keyAlg = $state<KeyAlgorithm>('EC_prime256v1');
  let csr = $state('');
  let validity = $state(90);
  let busy = $state(false);
  let error = $state('');
  let touched = $state(false);

  const activeCas = $derived(cas.filter((c) => (c.status ?? '').toUpperCase() === 'ACTIVE' || !c.status));
  const ca = $derived(cas.find((c) => c.id === caId));

  // Reset each time the dialog opens.
  $effect(() => {
    if (open) untrack(reset);
  });
  function reset() {
    step = 0;
    caId = initialCaId || activeCas[0]?.id || '';
    cn = '';
    sans = [];
    sanDraft = '';
    template = 'server';
    keyMode = 'generate';
    keyAlg = 'EC_prime256v1';
    csr = '';
    validity = 90;
    error = '';
    touched = false;
    if (initialCaId) step = 1;
  }

  const NAME_RE = /^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/i;
  const IP_RE = /^(\d{1,3}\.){3}\d{1,3}$|^[0-9a-f:]+:[0-9a-f:]*$/i;
  const EMAIL_RE = /^[^\s@]+@[^\s@]+$/;
  const validName = (s: string) => NAME_RE.test(s) || IP_RE.test(s) || EMAIL_RE.test(s);

  // The server takes any common name up to 64 characters (client
  // certificates often use a service or user name); only names that are
  // valid SANs are copied into the SAN list.
  const cnError = $derived(
    !cn.trim()
      ? 'A common name is required.'
      : cn.trim().length > 64
        ? 'Use at most 64 characters.'
        : /[\u0000-\u001f\u007f]/.test(cn)
          ? 'Remove control characters.'
          : ''
  );
  const sanError = $derived(sanDraft.trim() && !validName(sanDraft.trim()) ? `“${sanDraft.trim()}” isn't a DNS name, IP address or email.` : '');
  const validityError = $derived(
    !Number.isInteger(validity) || validity < 1 || validity > 3650 ? 'Enter a whole number of days between 1 and 3650.' : ''
  );
  const csrError = $derived(
    keyMode === 'csr' && !/-----BEGIN (NEW )?CERTIFICATE REQUEST-----/.test(csr) ? 'Paste a PEM-encoded CSR (BEGIN CERTIFICATE REQUEST).' : ''
  );

  function addSan(raw: string) {
    for (const tok of raw.split(/[\s,;]+/).map((t) => t.trim()).filter(Boolean)) {
      if (!validName(tok)) {
        sanDraft = tok;
        return;
      }
      if (!sans.includes(tok)) sans = [...sans, tok];
    }
    sanDraft = '';
  }

  function onSanKey(e: KeyboardEvent) {
    if (e.key === 'Enter' || e.key === ',') {
      e.preventDefault();
      addSan(sanDraft);
    } else if (e.key === 'Backspace' && !sanDraft && sans.length) {
      sans = sans.slice(0, -1);
    }
  }

  // The CN is always the first SAN, as the hint promises.
  const allSans = $derived(cn.trim() && validName(cn.trim()) ? [cn.trim(), ...sans.filter((s) => s !== cn.trim())] : sans);

  function next() {
    touched = true;
    if (step === 0 && !caId) return;
    if (step === 1) {
      if (sanDraft.trim()) addSan(sanDraft);
      if (cnError || sanError) return;
    }
    touched = false;
    step++;
  }

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    if (step < 2) {
      next();
      return;
    }
    touched = true;
    if (validityError || csrError) return;
    busy = true;
    error = '';
    try {
      if (keyMode === 'generate') {
        const r = await certApi.issueWithGeneratedKey({
          caId,
          commonName: cn.trim(),
          sans: allSans,
          template,
          keyAlgorithm: keyAlg,
          validityDays: validity
        });
        open = false;
        oncomplete({ certId: r.certId, generated: { ...r, commonName: cn.trim() } });
      } else {
        const r = await certApi.issueFromCsr({
          caId,
          csrPem: csr.trim(),
          validityDays: validity,
          commonName: cn.trim(),
          sans: allSans,
          template
        });
        toast.success(`Issued ${cn.trim()}`);
        open = false;
        oncomplete({ certId: r.certId });
      }
    } catch (err) {
      error = errorMessage(err, 'Could not issue the certificate.');
    } finally {
      busy = false;
    }
  }

  const description = $derived(
    step === 0 ? `Step 1 of 3.` : `From ${cnOf(ca?.subject) || 'the selected CA'}. Step ${step + 1} of 3.`
  );
</script>

<Modal bind:open title="Issue certificate" {description} size="md">
  <form id="issue-form" onsubmit={submit} novalidate>
    <ol class="steps">
      {#each steps as label, i (label)}
        <li aria-current={i === step ? 'step' : undefined} class:done={i < step} class:todo={i > step}>
          <span class="dot">{#if i < step}<Icon name="check" size={12} />{:else}{i + 1}{/if}</span>
          <span>{label}</span>
        </li>
      {/each}
    </ol>

    <div class="body">
      {#if step === 0}
        <fieldset>
          <legend class="field-label">Issuing CA</legend>
          {#if activeCas.length === 0}
            <p class="muted small">There's no active private CA. Create one first, or request a public certificate from Let's Encrypt.</p>
          {:else}
            <div class="choices">
              {#each activeCas as c (c.id)}
                <label class="choice" class:on={caId === c.id}>
                  <input type="radio" name="ca" value={c.id} bind:group={caId} />
                  <span class="ctext">
                    <span class="ctitle">{cnOf(c.subject) || c.id}</span>
                    <span class="muted csub">
                      {c.caType === 'SUBORDINATE' ? 'Subordinate' : 'Root'}{c.keyAlgorithm ? ` · ${keyAlgLabel(c.keyAlgorithm)}` : ''}{yearOf(c.notAfter) ? ` · valid to ${yearOf(c.notAfter)}` : ''}
                    </span>
                  </span>
                </label>
              {/each}
            </div>
          {/if}
        </fieldset>
      {:else if step === 1}
        <div class="field">
          <label class="field-label" for="iw-cn">Common name</label>
          <!-- svelte-ignore a11y_autofocus -->
          <input
            id="iw-cn"
            class="input mono"
            bind:value={cn}
            autocomplete="off"
            spellcheck="false"
            placeholder="orders.internal.example.com"
            aria-invalid={touched && !!cnError}
            aria-describedby="iw-cn-hint"
            autofocus
          />
          {#if touched && cnError}
            <span class="field-error" id="iw-cn-hint">{cnError}</span>
          {:else}
            <span class="field-hint" id="iw-cn-hint">Usually the primary DNS name, which is also added as the first SAN. With a CSR it replaces the CSR's common name.</span>
          {/if}
        </div>
        <div class="field">
          <label class="field-label" for="iw-san">Subject alternative names</label>
          <div class="chips" class:invalid={!!sanError}>
            {#each allSans as s (s)}
              <span class="badge chip mono">
                {s}
                {#if s !== cn.trim()}
                  <button type="button" class="btn-icon x" aria-label="Remove {s}" onclick={() => (sans = sans.filter((v) => v !== s))}>
                    <Icon name="x" size={10} />
                  </button>
                {/if}
              </span>
            {/each}
            <input
              id="iw-san"
              class="mono chip-input"
              placeholder="Add DNS name or IP"
              bind:value={sanDraft}
              onkeydown={onSanKey}
              onblur={() => sanDraft.trim() && addSan(sanDraft)}
              autocomplete="off"
              spellcheck="false"
              aria-invalid={!!sanError}
              aria-describedby="iw-san-hint"
            />
          </div>
          {#if sanError}
            <span class="field-error" id="iw-san-hint">{sanError}</span>
          {:else}
            <span class="field-hint" id="iw-san-hint">Press Enter or comma to add. DNS names, IP addresses and email addresses are accepted.</span>
          {/if}
        </div>
        <fieldset>
          <legend class="field-label">Template</legend>
          <div class="choices">
            <label class="choice" class:on={template === 'server'}>
              <input type="radio" name="tpl" value="server" bind:group={template} />
              <span class="ctext"><span class="ctitle">Server TLS</span><span class="muted csub">serverAuth · for HTTPS endpoints</span></span>
            </label>
            <label class="choice" class:on={template === 'client'}>
              <input type="radio" name="tpl" value="client" bind:group={template} />
              <span class="ctext"><span class="ctitle">Client mTLS</span><span class="muted csub">clientAuth · for service identity</span></span>
            </label>
          </div>
        </fieldset>
      {:else}
        <fieldset>
          <legend class="field-label">Private key</legend>
          <div class="choices">
            <label class="choice" class:on={keyMode === 'generate'}>
              <input type="radio" name="km" value="generate" bind:group={keyMode} />
              <span class="ctext"><span class="ctitle">Generate in Citadel</span><span class="muted csub">Key and CSR made server-side. The key is shown once.</span></span>
            </label>
            <label class="choice" class:on={keyMode === 'csr'}>
              <input type="radio" name="km" value="csr" bind:group={keyMode} />
              <span class="ctext"><span class="ctitle">Paste a CSR</span><span class="muted csub">The key never leaves your machine.</span></span>
            </label>
          </div>
        </fieldset>
        {#if keyMode === 'generate'}
          <div class="field">
            <label class="field-label" for="iw-alg">Key algorithm</label>
            <select id="iw-alg" class="select" bind:value={keyAlg}>
              {#each KEY_ALGORITHMS as k (k.value)}<option value={k.value}>{k.label}</option>{/each}
            </select>
            <span class="field-hint">FIPS-approved curves and RSA sizes only.</span>
          </div>
        {:else}
          <div class="field">
            <label class="field-label" for="iw-csr">Certificate signing request (PEM)</label>
            <textarea
              id="iw-csr"
              class="textarea mono"
              rows="7"
              bind:value={csr}
              spellcheck="false"
              placeholder="-----BEGIN CERTIFICATE REQUEST-----"
              aria-invalid={touched && !!csrError}
              aria-describedby="iw-csr-hint"
            ></textarea>
            {#if touched && csrError}
              <span class="field-error" id="iw-csr-hint">{csrError}</span>
            {:else}
              <span class="field-hint" id="iw-csr-hint">The common name and SANs above replace the ones in the CSR.</span>
            {/if}
          </div>
        {/if}
        <div class="field">
          <label class="field-label" for="iw-days">Validity (days)</label>
          <input
            id="iw-days"
            class="input num"
            type="number"
            min="1"
            max="3650"
            bind:value={validity}
            aria-invalid={touched && !!validityError}
            aria-describedby="iw-days-hint"
          />
          {#if touched && validityError}
            <span class="field-error" id="iw-days-hint">{validityError}</span>
          {:else}
            <span class="field-hint" id="iw-days-hint">Short lifetimes limit the damage of a leaked key. 90 days is a good default.</span>
          {/if}
        </div>
      {/if}

      {#if error}
        <div class="callout callout-danger" role="alert"><Icon name="alert-circle" size={16} /><span>{error}</span></div>
      {/if}
    </div>
  </form>

  {#snippet footer()}
    <button type="button" class="btn btn-ghost" onclick={() => (open = false)}>Cancel</button>
    <span class="spacer"></span>
    {#if step > 0}
      <button type="button" class="btn btn-secondary" onclick={() => step--} disabled={busy}>
        <Icon name="chevron-left" size={14} />Back
      </button>
    {/if}
    <button type="submit" form="issue-form" class="btn btn-primary" disabled={busy || (step === 0 && !caId)}>
      {#if step < 2}Continue<Icon name="chevron-right" size={14} />{:else}{busy ? 'Issuing…' : 'Issue certificate'}{/if}
    </button>
  {/snippet}
</Modal>

<style>
  .steps {
    display: flex;
    flex-wrap: wrap;
    gap: 12px;
    margin: 0 calc(-1 * var(--space-5));
    padding: 0 var(--space-5) var(--space-4);
    list-style: none;
    border-bottom: 1px solid var(--border);
  }
  .steps li {
    display: flex;
    align-items: center;
    gap: 8px;
    flex: 1 1 auto;
    font-weight: 600;
    color: var(--text);
  }
  .steps li.done {
    font-weight: 500;
  }
  .steps li.todo {
    font-weight: 500;
    color: var(--text-subtle);
  }
  .dot {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 22px;
    height: 22px;
    border-radius: 50%;
    border: 2px solid var(--accent);
    color: var(--accent);
    font-size: 12px;
    font-weight: 600;
  }
  .done .dot {
    border: 0;
    background: var(--accent);
    color: var(--accent-contrast);
  }
  .todo .dot {
    border: 1.5px solid var(--border-strong);
    color: var(--text-subtle);
  }
  .body {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
    padding-top: var(--space-5);
  }
  .body .field + .field {
    margin-top: 0;
  }
  fieldset {
    margin: 0;
    padding: 0;
    border: 0;
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  legend {
    padding: 0;
    margin-bottom: 8px;
  }
  .choices {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(min(240px, 100%), 1fr));
    gap: 8px;
  }
  .choice {
    display: flex;
    gap: 10px;
    padding: 12px;
    border: 1px solid var(--border-strong);
    border-radius: var(--radius-md);
    cursor: pointer;
  }
  .choice.on {
    border: 1.5px solid var(--accent);
    background: var(--accent-soft);
  }
  .choice:focus-within {
    box-shadow: var(--focus-ring);
  }
  .choice input {
    margin-top: 2px;
  }
  .ctext {
    display: flex;
    flex-direction: column;
    gap: 2px;
    min-width: 0;
  }
  .ctitle {
    font-weight: 600;
  }
  .csub {
    font-size: 13px;
    line-height: 16px;
  }
  .chips {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    align-items: center;
    min-height: var(--ctl-h);
    padding: 4px 6px;
    border: 1px solid var(--border-strong);
    border-radius: var(--radius-md);
    background: var(--surface);
  }
  .chips:focus-within {
    border-color: var(--accent);
    box-shadow: var(--focus-ring);
  }
  .chips.invalid {
    border-color: var(--danger);
  }
  .chip {
    font-size: 12.5px;
    padding-right: 2px;
  }
  .chip .x {
    width: 18px;
    height: 18px;
  }
  .chip-input {
    flex: 1 1 140px;
    min-width: 0;
    height: 26px;
    border: 0;
    outline: none;
    background: transparent;
    color: var(--text);
    font-size: 13.5px;
  }
  .spacer {
    flex: 1 1 auto;
  }
</style>
