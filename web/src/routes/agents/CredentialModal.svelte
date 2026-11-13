<!--
  Usage profile editor: makes a secret usable by agents and says how (kind,
  injection) and where (hosts, methods, paths, network).
-->
<script lang="ts">
  import Modal from '#lib/components/Modal.svelte';
  import Icon from '#lib/components/Icon.svelte';
  import { errorMessage } from '#lib/api.ts';
  import { toast } from '#lib/stores/toast.svelte.ts';
  import {
    agentsApi,
    isHttpKind,
    splitList,
    validateCredential,
    HTTP_METHODS,
    KIND_HINTS,
    KIND_LABELS,
    type AgentCredential,
    type CredentialInput,
    type CredentialKind
  } from './api';

  let {
    open = $bindable(false),
    coord,
    credential,
    onsaved
  }: {
    open?: boolean;
    /** The secret the profile is for. */
    coord: { project: string; env: string; path: string; key: string };
    /** The profile being edited; null for a new one. */
    credential: AgentCredential | null;
    onsaved: () => void;
  } = $props();

  const kinds: CredentialKind[] = ['http_header', 'http_basic', 'http_query', 'login', 'raw'];
  const uid = Math.random().toString(36).slice(2, 8);

  let name = $state('');
  let kind = $state<CredentialKind>('http_header');
  let description = $state('');
  let hosts = $state('');
  let methods = $state<string[]>(['GET']);
  let paths = $state('');
  let headerName = $state('Authorization');
  let headerPrefix = $state('Bearer ');
  let queryParam = $state('');
  let allowHttp = $state(false);
  let cidrs = $state('');
  let saving = $state(false);
  let saveError = $state('');

  $effect(() => {
    if (!open) return;
    const c = credential;
    name = c?.name ?? coord.key.toLowerCase().replace(/[^a-z0-9._-]+/g, '-').replace(/^[^a-z0-9]+/, '').slice(0, 63);
    kind = c?.kind ?? 'http_header';
    description = c?.description ?? '';
    hosts = (c?.allowedHosts ?? []).join('\n');
    methods = c ? [...c.allowedMethods] : ['GET'];
    paths = (c?.allowedPathPrefixes ?? []).join('\n');
    headerName = c?.headerName ?? 'Authorization';
    headerPrefix = c ? (c.headerPrefix ?? '') : 'Bearer ';
    queryParam = c?.queryParam ?? '';
    allowHttp = c?.allowHttp ?? false;
    cidrs = (c?.allowedCidrs ?? []).join('\n');
    saveError = '';
  });

  const input = $derived<CredentialInput>({
    name: name.trim(),
    ...(credential ? {} : { project: coord.project, env: coord.env, path: coord.path, key: coord.key }),
    kind,
    description: description.trim(),
    allowedHosts: splitList(hosts.toLowerCase()),
    allowedMethods: isHttpKind(kind) ? methods : [],
    allowedPathPrefixes: splitList(paths),
    headerName: kind === 'http_header' ? headerName.trim() : '',
    headerPrefix: kind === 'http_header' ? headerPrefix : '',
    queryParam: kind === 'http_query' ? queryParam.trim() : '',
    allowHttp: isHttpKind(kind) && allowHttp,
    allowedCidrs: splitList(cidrs)
  });
  const formError = $derived(validateCredential(input));

  function toggleMethod(m: string, on: boolean) {
    methods = on ? [...methods, m] : methods.filter((x) => x !== m);
  }

  async function save(e: SubmitEvent) {
    e.preventDefault();
    if (saving || formError) return;
    saving = true;
    saveError = '';
    try {
      if (credential) await agentsApi.updateCredential(input);
      else await agentsApi.createCredential(input);
      toast.success(credential ? 'Usage profile saved' : `Agents can now be granted ${input.name}`);
      open = false;
      onsaved();
    } catch (err) {
      saveError = errorMessage(err, 'Could not save the usage profile.');
    } finally {
      saving = false;
    }
  }
</script>

<Modal bind:open title={credential ? `Edit ${credential.name}` : 'Make usable by agents'} description="Agents refer to the credential by name. Citadel only ever sends it where this profile allows." size="md">
  <form id="cred-form-{uid}" class="form" onsubmit={save} novalidate>
    {#if saveError}<div class="callout callout-danger" role="alert"><Icon name="alert-circle" size={16} /><span>{saveError}</span></div>{/if}
    <div class="field">
      <label class="field-label" for="cr-name-{uid}">Credential name</label>
      <input id="cr-name-{uid}" class="input mono" bind:value={name} disabled={!!credential} spellcheck="false" placeholder="github-pat" />
    </div>
    <div class="field">
      <label class="field-label" for="cr-kind-{uid}">How agents use it</label>
      <select id="cr-kind-{uid}" class="select" bind:value={kind}>
        {#each kinds as k (k)}<option value={k}>{KIND_LABELS[k]}</option>{/each}
      </select>
      <span class="field-hint">{KIND_HINTS[kind]}</span>
    </div>
    {#if kind === 'http_header'}
      <div class="row2">
        <div class="field">
          <label class="field-label" for="cr-hn-{uid}">Header</label>
          <input id="cr-hn-{uid}" class="input mono" bind:value={headerName} spellcheck="false" />
        </div>
        <div class="field">
          <label class="field-label" for="cr-hp-{uid}">Value prefix</label>
          <input id="cr-hp-{uid}" class="input mono" bind:value={headerPrefix} spellcheck="false" placeholder="none" />
        </div>
      </div>
    {:else if kind === 'http_query'}
      <div class="field">
        <label class="field-label" for="cr-qp-{uid}">Query parameter</label>
        <input id="cr-qp-{uid}" class="input mono" bind:value={queryParam} spellcheck="false" placeholder="api_key" />
      </div>
    {/if}
    <div class="field">
      <label class="field-label" for="cr-hosts-{uid}">Allowed hosts{isHttpKind(kind) ? '' : ' (optional)'}</label>
      <textarea id="cr-hosts-{uid}" class="input mono" rows="2" bind:value={hosts} spellcheck="false" placeholder="api.github.com&#10;*.example.com"></textarea>
      <span class="field-hint">One per line. Exact hosts or *.example.com; add :port for a non-default port.</span>
    </div>
    {#if isHttpKind(kind)}
      <fieldset class="field plain">
        <legend class="field-label">Allowed methods</legend>
        <div class="methods">
          {#each HTTP_METHODS as m (m)}
            <label class="check-inline"><input type="checkbox" checked={methods.includes(m)} onchange={(e) => toggleMethod(m, e.currentTarget.checked)} /><span class="mono">{m}</span></label>
          {/each}
        </div>
      </fieldset>
      <div class="field">
        <label class="field-label" for="cr-paths-{uid}">Path prefixes <span class="subtle">(optional)</span></label>
        <textarea id="cr-paths-{uid}" class="input mono" rows="2" bind:value={paths} spellcheck="false" placeholder="/repos/acme/"></textarea>
      </div>
      <details class="adv">
        <summary>Network</summary>
        <label class="check-inline"><input type="checkbox" bind:checked={allowHttp} /><span>Allow plain http:// (otherwise https only)</span></label>
        <div class="field">
          <label class="field-label" for="cr-cidr-{uid}">Private networks allowed <span class="subtle">(optional)</span></label>
          <textarea id="cr-cidr-{uid}" class="input mono" rows="2" bind:value={cidrs} spellcheck="false" placeholder="10.20.0.0/16"></textarea>
          <span class="field-hint">Loopback, link-local, private and metadata addresses are refused unless listed here.</span>
        </div>
      </details>
    {/if}
    <div class="field">
      <label class="field-label" for="cr-desc-{uid}">Description <span class="subtle">(optional; agents see it)</span></label>
      <input id="cr-desc-{uid}" class="input" bind:value={description} placeholder="GitHub API for the acme org" />
    </div>
    {#if formError && name}<span class="field-error" role="status">{formError}</span>{/if}
  </form>
  {#snippet footer()}
    <button type="button" class="btn btn-ghost" onclick={() => (open = false)}>Cancel</button>
    <button type="submit" form="cred-form-{uid}" class="btn btn-primary" disabled={saving || !!formError}>{saving ? 'Saving…' : 'Save'}</button>
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
  .row2 {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: var(--space-3);
  }
  .row2 .field + .field {
    margin-top: 0;
  }
  .plain {
    border: 0;
    margin: 0;
    padding: 0;
    min-width: 0;
  }
  .methods {
    display: flex;
    flex-wrap: wrap;
    gap: 6px 14px;
  }
  .check-inline {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-size: var(--text-base);
  }
  .adv {
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
  }
  .adv summary {
    cursor: pointer;
    font-weight: 600;
    font-size: var(--text-sm);
    margin-bottom: var(--space-2);
  }
  .adv .field {
    margin-top: var(--space-3);
  }
  @media (max-width: 560px) {
    .row2 {
      grid-template-columns: minmax(0, 1fr);
    }
  }
</style>
