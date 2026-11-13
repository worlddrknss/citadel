<!-- New private CA: a root, or a subordinate signed by an existing CA. -->
<script lang="ts">
  import { untrack } from 'svelte';
  import Modal from '#lib/components/Modal.svelte';
  import Icon from '#lib/components/Icon.svelte';
  import { errorMessage } from '#lib/api.ts';
  import { toast } from '#lib/stores/toast.svelte.ts';
  import Seg from './Seg.svelte';
  import { certApi, type CertRow, type KeyAlgorithm } from './api';
  import { cnOf, KEY_ALGORITHMS } from './certs';

  let {
    open = $bindable(false),
    cas,
    initialParent = '',
    oncreated
  }: {
    open?: boolean;
    cas: CertRow[];
    initialParent?: string;
    oncreated: (caId: string) => void;
  } = $props();

  let caType = $state<'ROOT' | 'SUBORDINATE'>('ROOT');
  let parent = $state('');
  let cn = $state('');
  let org = $state('');
  let country = $state('');
  let keyAlg = $state<KeyAlgorithm>('EC_secp384r1');
  let busy = $state(false);
  let error = $state('');
  let touched = $state(false);

  // Subordinates are created with pathLen 0 and can't sign further CAs, so
  // only active roots can be parents.
  const parents = $derived(
    cas.filter((c) => ((c.status ?? '').toUpperCase() === 'ACTIVE' || !c.status) && (c.caType ?? '').toUpperCase() !== 'SUBORDINATE')
  );

  $effect(() => {
    if (open) untrack(reset);
  });
  function reset() {
    caType = initialParent ? 'SUBORDINATE' : 'ROOT';
    parent = initialParent || parents[0]?.id || '';
    cn = '';
    org = '';
    country = '';
    keyAlg = 'EC_secp384r1';
    error = '';
    touched = false;
  }

  const cnError = $derived(cn.trim() ? '' : 'A common name is required.');
  const countryError = $derived(country.trim() && !/^[A-Za-z]{2}$/.test(country.trim()) ? 'Use a two-letter ISO country code.' : '');
  const parentError = $derived(caType === 'SUBORDINATE' && !parent ? 'Choose the CA that signs this one.' : '');

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    touched = true;
    if (cnError || countryError || parentError) return;
    busy = true;
    error = '';
    try {
      const r = await certApi.createCA({
        caType,
        keyAlgorithm: keyAlg,
        commonName: cn.trim(),
        organization: org.trim(),
        country: country.trim().toUpperCase(),
        parentCaId: caType === 'SUBORDINATE' ? parent : undefined
      });
      toast.success(`Created ${cn.trim()}`);
      open = false;
      oncreated(r.caId);
    } catch (err) {
      error = errorMessage(err, 'Could not create the CA.');
    } finally {
      busy = false;
    }
  }
</script>

<Modal bind:open title="New certificate authority" description="The signing key is generated in Citadel KMS and never leaves it." size="md">
  <form id="ca-form" class="form" onsubmit={submit} novalidate>
    <div class="field">
      <span class="field-label" id="ca-type-l">Type</span>
      <Seg
        label="CA type"
        bind:value={caType}
        options={[
          { value: 'ROOT', label: 'Root CA' },
          { value: 'SUBORDINATE', label: 'Subordinate CA', count: undefined }
        ]}
      />
      <span class="field-hint">
        {caType === 'ROOT'
          ? 'Self-signed trust anchor. Keep roots offline in practice and issue from subordinates.'
          : 'Signed by a parent CA. Issue leaf certificates from subordinates so a root never signs workloads directly.'}
      </span>
    </div>
    {#if caType === 'SUBORDINATE'}
      <div class="field">
        <label class="field-label" for="ca-parent">Parent CA</label>
        {#if parents.length === 0}
          <p class="callout"><Icon name="info" size={16} /><span>Create a root CA first; a subordinate needs a parent to sign it.</span></p>
        {:else}
          <select id="ca-parent" class="select" bind:value={parent} aria-invalid={touched && !!parentError}>
            {#each parents as p (p.id)}
              <option value={p.id}>{cnOf(p.subject) || p.id} ({p.caType === 'SUBORDINATE' ? 'subordinate' : 'root'})</option>
            {/each}
          </select>
        {/if}
        {#if touched && parentError}<span class="field-error">{parentError}</span>{/if}
      </div>
    {/if}
    <div class="field">
      <label class="field-label" for="ca-cn">Common name</label>
      <input id="ca-cn" class="input" bind:value={cn} placeholder="Internal Services CA" autocomplete="off" aria-invalid={touched && !!cnError} />
      {#if touched && cnError}<span class="field-error">{cnError}</span>{/if}
    </div>
    <div class="field-row">
      <div class="field">
        <label class="field-label" for="ca-org">Organization <span class="subtle">(optional)</span></label>
        <input id="ca-org" class="input" bind:value={org} autocomplete="organization" />
      </div>
      <div class="field">
        <label class="field-label" for="ca-c">Country <span class="subtle">(optional)</span></label>
        <input id="ca-c" class="input" bind:value={country} maxlength="2" placeholder="US" autocomplete="country" aria-invalid={!!countryError} />
        {#if countryError}<span class="field-error">{countryError}</span>{/if}
      </div>
    </div>
    <div class="field">
      <label class="field-label" for="ca-alg">Key algorithm</label>
      <select id="ca-alg" class="select" bind:value={keyAlg}>
        {#each KEY_ALGORITHMS as k (k.value)}<option value={k.value}>{k.label}</option>{/each}
      </select>
    </div>
    {#if error}
      <div class="callout callout-danger" role="alert"><Icon name="alert-circle" size={16} /><span>{error}</span></div>
    {/if}
  </form>
  {#snippet footer()}
    <button type="button" class="btn btn-ghost" onclick={() => (open = false)}>Cancel</button>
    <button type="submit" form="ca-form" class="btn btn-primary" disabled={busy || (caType === 'SUBORDINATE' && parents.length === 0)}>
      {busy ? 'Creating…' : 'Create CA'}
    </button>
  {/snippet}
</Modal>

<style>
  .form {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
  }
  .form .field + .field {
    margin-top: 0;
  }
  .form p {
    margin: 0;
  }
</style>
