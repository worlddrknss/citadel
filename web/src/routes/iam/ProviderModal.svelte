<!-- Register an OIDC issuer, or edit the audiences (client IDs) of one. -->
<script lang="ts">
  import { untrack } from 'svelte';
  import Modal from '$lib/components/Modal.svelte';
  import Icon from '$lib/components/Icon.svelte';
  import { api, errorMessage, type OIDCProvider } from '$lib/api';
  import { toast } from '$lib/stores/toast.svelte';
  import { iamApi } from './api';
  import { splitList } from './trust';

  let {
    open = $bindable(false),
    provider = null,
    onsaved
  }: { open?: boolean; provider?: OIDCProvider | null; onsaved: () => void } = $props();

  let url = $state('');
  let auds = $state('');
  let touched = $state(false);
  let busy = $state(false);
  let error = $state('');

  $effect(() => {
    if (open)
      untrack(() => {
        url = provider?.url ?? '';
        auds = provider?.clientIds.join(', ') ?? '';
        touched = false;
        error = '';
      });
  });

  const urlError = $derived(!/^https:\/\/[^\s/]+(\/\S*)?$/.test(url.trim()) ? 'Enter the https:// issuer URL exactly as it appears in the token’s iss claim.' : '');
  const audError = $derived(splitList(auds).length === 0 ? 'Add at least one audience.' : '');

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    touched = true;
    if ((!provider && urlError) || audError) return;
    busy = true;
    error = '';
    try {
      if (provider) {
        await iamApi.updateOIDCProvider(provider.providerArn, splitList(auds));
        toast.success('Provider updated');
      } else {
        await api.createOIDCProvider(url.trim(), splitList(auds));
        toast.success('Identity provider added');
      }
      open = false;
      onsaved();
    } catch (err) {
      error = errorMessage(err, 'Could not save the provider.');
    } finally {
      busy = false;
    }
  }
</script>

<Modal
  bind:open
  title={provider ? 'Edit identity provider' : 'Add identity provider'}
  description="An OIDC issuer (a Kubernetes cluster, GitHub Actions, GitLab, your IdP) whose tokens can be exchanged for credentials."
  size="md"
>
  <form id="prov-form" class="form" onsubmit={submit} novalidate>
    <div class="field">
      <label class="field-label" for="p-url">Issuer URL</label>
      <input
        id="p-url"
        class="input mono"
        bind:value={url}
        disabled={!!provider}
        placeholder="https://token.actions.githubusercontent.com"
        autocomplete="off"
        spellcheck="false"
        aria-invalid={touched && !provider && !!urlError}
      />
      {#if touched && !provider && urlError}
        <span class="field-error">{urlError}</span>
      {:else}
        <span class="field-hint">{provider ? "The issuer can't change. Delete and re-add the provider to use another one." : 'Citadel fetches signing keys from <issuer>/.well-known/openid-configuration.'}</span>
      {/if}
    </div>
    <div class="field">
      <label class="field-label" for="p-aud">Audiences</label>
      <input id="p-aud" class="input mono" bind:value={auds} placeholder="sts.citadel" autocomplete="off" spellcheck="false" aria-invalid={touched && !!audError} />
      {#if touched && audError}<span class="field-error">{audError}</span>{:else}<span class="field-hint">Comma-separated client IDs accepted in the token's <code>aud</code> claim.</span>{/if}
    </div>
    {#if error}
      <div class="callout callout-danger" role="alert"><Icon name="alert-circle" size={16} /><span>{error}</span></div>
    {/if}
  </form>
  {#snippet footer()}
    <button type="button" class="btn btn-ghost" onclick={() => (open = false)}>Cancel</button>
    <button type="submit" form="prov-form" class="btn btn-primary" disabled={busy}>{busy ? 'Saving…' : provider ? 'Save changes' : 'Add provider'}</button>
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
</style>
