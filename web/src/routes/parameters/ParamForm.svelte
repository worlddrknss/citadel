<!-- Create or edit a parameter. Edit is a real in-place update with a version guard. -->
<script lang="ts">
  import { api, ApiError, errorMessage, type KMSKey, type ParameterTier, type ParameterType } from '#lib/api.ts';
  import Modal from '#lib/components/Modal.svelte';
  import Icon from '#lib/components/Icon.svelte';
  import { toast } from '#lib/stores/toast.svelte.ts';
  import { params, TYPES, validateName, valueLimit, byteLength, leaf, type Param } from './api';

  let {
    open = $bindable(false),
    editing,
    prefix,
    kmsKeys,
    onsaved
  }: {
    open?: boolean;
    /** The parameter being edited; null creates a new one. */
    editing: Param | null;
    /** Folder new parameters are created in. */
    prefix: string;
    kmsKeys: KMSKey[];
    onsaved: (name: string) => void;
  } = $props();

  let name = $state('');
  let type = $state<ParameterType>('String');
  let value = $state('');
  let keepValue = $state(false);
  let valueLoading = $state(false);
  let kmsKeyId = $state('');
  let tier = $state<ParameterTier>('Standard');
  let description = $state('');
  let busy = $state(false);
  let error = $state('');
  let touched = $state(false);
  const uid = Math.random().toString(36).slice(2, 8);

  const isEdit = $derived(!!editing);
  const fullName = $derived(isEdit ? editing!.name : `${prefix}${name.trim().replace(/^\/+/, '')}`);
  const nameError = $derived(isEdit ? '' : validateName(fullName));
  const limit = $derived(valueLimit(tier));
  const bytes = $derived(byteLength(value));
  const valueError = $derived(
    keepValue ? '' : bytes > limit ? `Too long for the ${tier} tier (${bytes} of ${limit} bytes).` : ''
  );
  const keyOptions = $derived(
    kmsKeys.filter((k) => k.enabled && !k.deletionDate && k.keyUsage === 'ENCRYPT_DECRYPT' && k.keySpec === 'SYMMETRIC_DEFAULT')
  );

  function keyLabel(k: KMSKey) {
    const alias = [...k.aliases].sort()[0];
    return alias ? `${alias} · ${k.keyId.slice(0, 8)}…` : k.keyId;
  }

  $effect(() => {
    if (!open) return;
    const p = editing;
    error = '';
    touched = false;
    busy = false;
    if (p) {
      name = leaf(p.name);
      type = p.type;
      tier = p.tier;
      description = p.description;
      kmsKeyId = p.kmsKeyId ?? '';
      // SecureString values aren't revealed just to open the form.
      keepValue = p.type === 'SecureString';
      value = '';
      if (p.type !== 'SecureString') {
        if (p.value !== undefined) value = p.value;
        else loadValue(p.name);
      }
    } else {
      name = '';
      type = 'String';
      tier = 'Standard';
      description = '';
      kmsKeyId = '';
      keepValue = false;
      value = '';
    }
  });

  async function loadValue(n: string) {
    valueLoading = true;
    try {
      value = (await api.revealParameter(n)).value;
    } catch (e) {
      error = `Couldn't load the current value: ${errorMessage(e)}`;
    } finally {
      valueLoading = false;
    }
  }

  async function save(e: SubmitEvent) {
    e.preventDefault();
    touched = true;
    if (busy || nameError || valueError || valueLoading) return;
    busy = true;
    error = '';
    try {
      const kms = type === 'SecureString' ? kmsKeyId || undefined : undefined;
      if (editing) {
        // On edit an omitted kmsKeyId keeps the current key; "" switches a
        // SecureString back to the account default key.
        const editKms = type !== 'SecureString' ? undefined : kmsKeyId !== (editing.kmsKeyId ?? '') ? kmsKeyId : undefined;
        await params.update({
          name: editing.name,
          expectedVersion: editing.version,
          type,
          value: keepValue ? undefined : value,
          description: description.trim(),
          kmsKeyId: editKms,
          tier
        });
        toast.success(`Saved ${editing.name} as version ${editing.version + 1}`);
        open = false;
        onsaved(editing.name);
      } else {
        await api.putParameter({
          name: fullName,
          type,
          value,
          kmsKeyId: kms,
          tier,
          description: description.trim() || undefined,
          overwrite: false
        });
        toast.success(`Created ${fullName}`);
        open = false;
        onsaved(fullName);
      }
    } catch (err) {
      if (err instanceof ApiError && err.status === 409) {
        error = editing
          ? 'Someone saved a newer version since you opened this form. Close it and reopen to edit the latest version.'
          : 'A parameter with this name already exists. Open it and choose Edit to change it.';
      } else {
        error = errorMessage(err);
      }
    } finally {
      busy = false;
    }
  }
</script>

<Modal bind:open title={isEdit ? 'Edit parameter' : 'Create parameter'} description={isEdit ? `Saving creates version ${(editing?.version ?? 0) + 1}. Earlier versions stay in the history.` : undefined}>
  <form id="pf-{uid}" class="form" onsubmit={save} novalidate>
    <label class="field">
      <span class="field-label">Name</span>
      {#if isEdit}
        <input class="input mono" value={editing?.name} readonly aria-readonly="true" />
      {:else}
        <span class="name-row">
          <span class="prefix mono" title={prefix}>{prefix}</span>
          <input
            class="input mono"
            bind:value={name}
            placeholder="db/url"
            autocomplete="off"
            spellcheck="false"
            aria-invalid={touched && !!nameError}
            aria-describedby="pf-name-{uid}"
          />
        </span>
        <span id="pf-name-{uid}" class={touched && nameError ? 'field-error' : 'field-hint'}>
          {touched && nameError ? nameError : 'Use / to nest it in folders, for example db/url.'}
        </span>
      {/if}
    </label>

    <fieldset class="field">
      <legend class="field-label">Type</legend>
      <div class="seg" role="radiogroup" aria-label="Type">
        {#each TYPES as t (t)}
          <label class="seg-opt" class:on={type === t}>
            <input type="radio" class="sr-only" name="type-{uid}" value={t} checked={type === t} onchange={() => (type = t)} />
            {#if t === 'SecureString'}<Icon name="lock" size={12} />{/if}{t}
          </label>
        {/each}
      </div>
      <span class="field-hint">
        {type === 'String' ? 'Plain text, readable by anyone with access to the parameter.' : type === 'StringList' ? 'Comma-separated values, for example a,b,c.' : 'Encrypted with a KMS key. Values are masked and every reveal is logged.'}
      </span>
    </fieldset>

    {#if type === 'SecureString'}
      <label class="field">
        <span class="field-label">KMS key</span>
        <select class="select mono" bind:value={kmsKeyId}>
          <option value="">alias/default (account default key)</option>
          {#each keyOptions as k (k.keyId)}
            {#if !k.aliases.includes('alias/default')}<option value={k.keyId}>{keyLabel(k)}</option>{/if}
          {/each}
        </select>
        <span class="field-hint">Only enabled symmetric keys are listed.</span>
      </label>
    {/if}

    <div class="field">
      <span class="value-head">
        <label class="field-label" for="pf-val-{uid}">Value</label>
        {#if isEdit && editing?.type === 'SecureString'}
          <label class="check small"><input type="checkbox" bind:checked={keepValue} />Keep the current value</label>
        {/if}
      </span>
      {#if keepValue}
        <p class="kept subtle small"><Icon name="lock" size={12} />The current encrypted value is kept{type !== editing?.type || (kmsKeyId || '') !== (editing?.kmsKeyId ?? '') ? ' and re-encrypted' : ''}.</p>
      {:else if valueLoading}
        <span class="skeleton sk" aria-label="Loading current value"></span>
      {:else}
        <textarea
          id="pf-val-{uid}"
          class="textarea mono"
          rows="4"
          bind:value={value}
          spellcheck="false"
          autocomplete="off"
          placeholder={type === 'StringList' ? 'a,b,c' : ''}
          aria-invalid={!!valueError}
          aria-describedby="pf-val-hint-{uid}"
        ></textarea>
        <span id="pf-val-hint-{uid}" class={valueError ? 'field-error' : 'field-hint num'}>{valueError || `${bytes} of ${limit} bytes`}</span>
      {/if}
    </div>

    <div class="row">
      <label class="field">
        <span class="field-label">Tier</span>
        <select class="select" bind:value={tier} disabled={isEdit && editing?.tier === 'Advanced'}>
          <option value="Standard">Standard (4 KB)</option>
          <option value="Advanced">Advanced (8 KB)</option>
        </select>
        {#if isEdit && editing?.tier === 'Advanced'}<span class="field-hint">Advanced parameters can't move back to Standard.</span>{/if}
      </label>
      <label class="field">
        <span class="field-label">Description <span class="subtle opt">(optional)</span></span>
        <input class="input" bind:value={description} maxlength="1024" />
      </label>
    </div>

    {#if error}<div class="callout callout-danger" role="alert"><Icon name="alert-circle" size={16} /><span>{error}</span></div>{/if}
  </form>
  {#snippet footer()}
    <button type="button" class="btn btn-ghost" onclick={() => (open = false)}>Cancel</button>
    <button type="submit" form="pf-{uid}" class="btn btn-primary" disabled={busy || valueLoading}>
      {busy ? 'Saving…' : isEdit ? 'Save new version' : 'Create parameter'}
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
  fieldset {
    margin: 0;
    padding: 0;
    border: 0;
  }
  .name-row {
    display: flex;
    align-items: stretch;
    min-width: 0;
  }
  .prefix {
    display: inline-flex;
    align-items: center;
    max-width: 45%;
    padding: 0 var(--space-2);
    border: 1px solid var(--border-strong);
    border-right: 0;
    border-radius: var(--radius-md) 0 0 var(--radius-md);
    background: var(--surface-hover);
    color: var(--text-muted);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    direction: rtl;
  }
  .name-row .input {
    border-radius: 0 var(--radius-md) var(--radius-md) 0;
  }
  .seg {
    display: inline-flex;
    flex-wrap: wrap;
    gap: 2px;
    padding: 3px;
    border-radius: var(--radius-md);
    background: var(--surface-pressed);
    align-self: flex-start;
  }
  .seg-opt {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    height: 28px;
    padding: 0 10px;
    border-radius: var(--radius-sm);
    color: var(--text-muted);
    font: 500 var(--text-sm) / 1 var(--font-sans);
    cursor: pointer;
  }
  .seg-opt.on {
    background: var(--surface);
    color: var(--text);
    box-shadow: var(--shadow-xs);
  }
  .seg-opt:focus-within {
    box-shadow: var(--focus-ring);
  }
  .value-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--space-2);
  }
  .check {
    display: inline-flex;
    align-items: center;
    gap: var(--space-2);
    font-weight: 400;
  }
  .kept {
    display: flex;
    align-items: center;
    gap: 6px;
    margin: 0;
    padding: var(--space-3);
    border: 1px dashed var(--border-strong);
    border-radius: var(--radius-md);
  }
  .sk {
    display: block;
    height: 96px;
    width: 100%;
  }
  .row {
    display: grid;
    grid-template-columns: minmax(0, 1fr) minmax(0, 2fr);
    gap: var(--space-4);
  }
  @media (max-width: 520px) {
    .row {
      grid-template-columns: minmax(0, 1fr);
    }
  }
  .opt {
    font-weight: 400;
  }
</style>
