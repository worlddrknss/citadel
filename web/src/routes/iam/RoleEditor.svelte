<!-- Create or edit a role. The trust policy can be edited as a form or as
     its JSON document; both are validated against the registered providers. -->
<script lang="ts">
  import { untrack } from 'svelte';
  import Modal from '$lib/components/Modal.svelte';
  import Icon from '$lib/components/Icon.svelte';
  import { api, errorMessage, type OIDCProvider, type Role, type TrustPolicy } from '$lib/api';
  import { toast } from '$lib/stores/toast.svelte';
  import Seg from './Seg.svelte';
  import { iamApi } from './api';
  import { validateTrust, hasErrors, trustToJson, parseTrustJson, splitList, type TrustErrors } from './trust';

  let {
    open = $bindable(false),
    role = null,
    providers,
    onsaved
  }: {
    open?: boolean;
    role?: Role | null;
    providers: OIDCProvider[];
    onsaved: (roleName: string) => void;
  } = $props();

  const SESSIONS = [
    { v: 900, l: '15 minutes' },
    { v: 3600, l: '1 hour' },
    { v: 7200, l: '2 hours' },
    { v: 14400, l: '4 hours' },
    { v: 28800, l: '8 hours' },
    { v: 43200, l: '12 hours' }
  ];

  let name = $state('');
  let description = $state('');
  let maxSession = $state(3600);
  let mode = $state<'form' | 'json'>('form');
  let type = $state<'oidc' | 'account'>('oidc');
  let providerUrl = $state('');
  let audiences = $state('');
  let subjects = $state('');
  let principals = $state('');
  let json = $state('');
  let touched = $state(false);
  let busy = $state(false);
  let error = $state('');

  $effect(() => {
    if (open) untrack(reset);
  });

  function reset() {
    const t: TrustPolicy = role?.trust ?? { type: 'oidc', providerUrl: providers[0]?.url ?? '', audiences: providers[0]?.clientIds ?? [], subjects: [] };
    name = role?.roleName ?? '';
    description = role?.description ?? '';
    maxSession = role?.maxSessionSeconds ?? 3600;
    mode = 'form';
    fromTrust(t);
    json = trustToJson(t);
    touched = false;
    error = '';
  }

  function fromTrust(t: TrustPolicy) {
    type = t.type === 'account' ? 'account' : 'oidc';
    providerUrl = t.providerUrl ?? '';
    audiences = (t.audiences ?? []).join(', ');
    subjects = (t.subjects ?? []).join('\n');
    principals = (t.principals ?? []).join(', ');
  }

  const formTrust = $derived<TrustPolicy>(
    type === 'oidc'
      ? { type, providerUrl, audiences: splitList(audiences), subjects: splitList(subjects) }
      : { type, principals: splitList(principals) }
  );
  const parsed = $derived(mode === 'json' ? parseTrustJson(json) : { trust: formTrust });
  const trust = $derived(parsed.trust);
  const errors = $derived<TrustErrors>(parsed.error ? { json: parsed.error } : trust ? validateTrust(trust, providers) : {});
  const nameError = $derived(!name.trim() ? 'A role name is required.' : !/^[A-Za-z0-9._-]{1,64}$/.test(name.trim()) ? "Use letters, numbers, '.', '_' and '-' (up to 64)." : '');
  const jsonErrorList = $derived(Object.entries(errors).filter(([, v]) => v).map(([k, v]) => (k === 'json' ? v : `${k}: ${v}`)));

  function switchMode(m: 'form' | 'json') {
    if (m === 'json') json = trustToJson(formTrust);
    else {
      const p = parseTrustJson(json);
      if (p.trust) fromTrust(p.trust);
      else {
        toast.error('Fix the JSON before switching back to the form.');
        mode = 'json';
        return;
      }
    }
    mode = m;
  }

  function onProvider() {
    // Default the audiences to the chosen provider's client IDs.
    const p = providers.find((x) => x.url === providerUrl);
    if (p && !audiences.trim()) audiences = p.clientIds.join(', ');
  }

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    touched = true;
    if ((!role && nameError) || !trust || hasErrors(errors)) return;
    busy = true;
    error = '';
    try {
      if (role) {
        await iamApi.updateRole({ roleName: role.roleName, description: description.trim(), trust, maxSessionSeconds: maxSession });
        toast.success(`Saved ${role.roleName}`);
      } else {
        await api.createRole({ roleName: name.trim(), description: description.trim(), trust, maxSessionSeconds: maxSession });
        toast.success(`Created ${name.trim()}`);
      }
      open = false;
      onsaved(role?.roleName ?? name.trim());
    } catch (err) {
      error = errorMessage(err, 'Could not save the role.');
    } finally {
      busy = false;
    }
  }

  const show = (k: keyof TrustErrors) => (touched || mode === 'json' ? errors[k] : '');
</script>

<Modal bind:open title={role ? `Edit ${role.roleName}` : 'Create role'} description="Workloads assume a role to get short-lived credentials. The trust policy decides who may." size="lg">
  <form id="role-form" class="form" onsubmit={submit} novalidate>
    <div class="field-row">
      <div class="field">
        <label class="field-label" for="r-name">Role name</label>
        <input
          id="r-name"
          class="input mono"
          bind:value={name}
          disabled={!!role}
          placeholder="payments-api"
          autocomplete="off"
          spellcheck="false"
          aria-invalid={touched && !role && !!nameError}
          aria-describedby="r-name-hint"
        />
        {#if touched && !role && nameError}
          <span class="field-error" id="r-name-hint">{nameError}</span>
        {:else}
          <span class="field-hint" id="r-name-hint">{role ? "A role's name can't change; it is part of the ARN." : 'Part of the role ARN.'}</span>
        {/if}
      </div>
      <div class="field">
        <label class="field-label" for="r-max">Maximum session</label>
        <select id="r-max" class="select" bind:value={maxSession}>
          {#each SESSIONS as s (s.v)}<option value={s.v}>{s.l}</option>{/each}
          {#if !SESSIONS.some((s) => s.v === maxSession)}<option value={maxSession}>{Math.round(maxSession / 60)} minutes</option>{/if}
        </select>
        <span class="field-hint">Longest lifetime of credentials from this role.</span>
      </div>
    </div>
    <div class="field">
      <label class="field-label" for="r-desc">Description <span class="subtle">(optional)</span></label>
      <input id="r-desc" class="input" bind:value={description} placeholder="Read payment secrets from the prod cluster" autocomplete="off" />
    </div>

    <section class="trust" aria-labelledby="trust-title">
      <div class="trust-head">
        <h3 id="trust-title">Trust policy</h3>
        <Seg label="Editor" bind:value={mode} onchange={switchMode} options={[{ value: 'form', label: 'Form' }, { value: 'json', label: 'JSON' }]} />
      </div>
      <div class="trust-body">
        {#if mode === 'json'}
          <div class="field">
            <label class="field-label" for="r-json">Policy document</label>
            <textarea
              id="r-json"
              class="textarea mono code"
              rows="12"
              spellcheck="false"
              bind:value={json}
              aria-invalid={jsonErrorList.length > 0}
              aria-describedby="r-json-status"
            ></textarea>
            <div id="r-json-status" aria-live="polite">
              {#if jsonErrorList.length}
                <ul class="errs">
                  {#each jsonErrorList as m (m)}<li class="field-error"><Icon name="alert-circle" size={12} />{m}</li>{/each}
                </ul>
              {:else}
                <span class="ok small"><Icon name="check-circle" size={12} />Valid trust policy</span>
              {/if}
            </div>
            <span class="field-hint">
              Shape: <code>{'{"type":"oidc","providerUrl","audiences":[],"subjects":[]}'}</code> or <code>{'{"type":"account","principals":[]}'}</code>.
            </span>
          </div>
        {:else}
          <div class="field">
            <span class="field-label">Trusted principal</span>
            <Seg
              label="Trust type"
              bind:value={type}
              options={[
                { value: 'oidc', label: 'Web identity (OIDC)' },
                { value: 'account', label: 'Citadel accounts' }
              ]}
            />
          </div>
          {#if type === 'oidc'}
            {#if providers.length === 0}
              <div class="callout callout-warning"><Icon name="alert-triangle" size={16} /><span>No identity providers yet. Add one on the Identity providers tab, then create the role.</span></div>
            {/if}
            <div class="field">
              <label class="field-label" for="r-prov">Identity provider</label>
              <select id="r-prov" class="select mono" bind:value={providerUrl} onchange={onProvider} aria-invalid={!!show('providerUrl')}>
                <option value="" disabled>Choose a provider…</option>
                {#each providers as p (p.providerArn)}<option value={p.url}>{p.url}</option>{/each}
                {#if providerUrl && !providers.some((p) => p.url === providerUrl)}<option value={providerUrl}>{providerUrl} (not registered)</option>{/if}
              </select>
              {#if show('providerUrl')}<span class="field-error">{show('providerUrl')}</span>{/if}
            </div>
            <div class="field">
              <label class="field-label" for="r-aud">Audiences</label>
              <input id="r-aud" class="input mono" bind:value={audiences} placeholder="sts.citadel" autocomplete="off" spellcheck="false" aria-invalid={!!show('audiences')} />
              {#if show('audiences')}<span class="field-error">{show('audiences')}</span>{:else}<span class="field-hint">Comma-separated. The token's <code>aud</code> must match one.</span>{/if}
            </div>
            <div class="field">
              <label class="field-label" for="r-sub">Subjects</label>
              <textarea id="r-sub" class="textarea mono" rows="3" bind:value={subjects} placeholder="system:serviceaccount:payments:api" spellcheck="false" aria-invalid={!!show('subjects')}></textarea>
              {#if show('subjects')}<span class="field-error">{show('subjects')}</span>{:else}<span class="field-hint">One per line. The token's <code>sub</code> must match one; a trailing <code>*</code> matches a prefix.</span>{/if}
            </div>
          {:else}
            <div class="field">
              <label class="field-label" for="r-prin">Account IDs</label>
              <input id="r-prin" class="input mono" bind:value={principals} placeholder="123456789012" autocomplete="off" inputmode="numeric" aria-invalid={!!show('principals')} />
              {#if show('principals')}<span class="field-error">{show('principals')}</span>{:else}<span class="field-hint">Comma-separated. Callers signed with access keys from these accounts may assume the role.</span>{/if}
            </div>
          {/if}
        {/if}
      </div>
    </section>

    {#if error}
      <div class="callout callout-danger" role="alert"><Icon name="alert-circle" size={16} /><span>{error}</span></div>
    {/if}
  </form>
  {#snippet footer()}
    <button type="button" class="btn btn-ghost" onclick={() => (open = false)}>Cancel</button>
    <button type="submit" form="role-form" class="btn btn-primary" disabled={busy}>{busy ? 'Saving…' : role ? 'Save changes' : 'Create role'}</button>
  {/snippet}
</Modal>

<style>
  .form {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
  }
  .form :global(.field + .field) {
    margin-top: 0;
  }
  .trust {
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    overflow: hidden;
  }
  .trust-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    flex-wrap: wrap;
    padding: 8px 12px;
    background: var(--surface-hover);
    border-bottom: 1px solid var(--border);
  }
  .trust-head h3 {
    margin: 0;
    font-size: var(--text-base);
    font-weight: 600;
  }
  .trust-body {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
    padding: 12px;
  }
  .code {
    font-size: 12px;
    background: var(--surface-sunken);
  }
  .errs {
    margin: 0;
    padding: 0;
    list-style: none;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .errs li,
  .ok {
    display: flex;
    gap: 4px;
    align-items: flex-start;
  }
  .ok {
    color: var(--success);
    align-items: center;
  }
</style>
