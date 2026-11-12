<!-- Create or edit a workload client: who may get tokens, for which
     audiences, how long they live and what their subject looks like. -->
<script lang="ts">
  import { untrack } from 'svelte';
  import Modal from '$lib/components/Modal.svelte';
  import Icon from '$lib/components/Icon.svelte';
  import { errorMessage } from '$lib/api';
  import { toast } from '$lib/stores/toast.svelte';
  import Seg from './Seg.svelte';
  import { wiApi, SUBJECT_PRESETS, PLACEHOLDERS, type ClientAuth, type ClientInput, type WorkloadClient } from './api';

  let {
    open = $bindable(false),
    client = null,
    existing,
    onsaved
  }: { open?: boolean; client?: WorkloadClient | null; existing: WorkloadClient[]; onsaved: (clientId: string) => void } = $props();

  const TTLS = [
    { v: 300, l: '5 minutes' },
    { v: 900, l: '15 minutes' },
    { v: 3600, l: '1 hour' },
    { v: 14400, l: '4 hours' },
    { v: 43200, l: '12 hours' }
  ];

  let name = $state('');
  let audiences = $state('');
  let ttl = $state(900);
  let method = $state<ClientAuth['method']>('k8s-token-review');
  let allowedUsers = $state('');
  let apiServer = $state('');
  let caPem = $state('');
  let serviceAccounts = $state('');
  let reviewAudience = $state('');
  let subjectFormat = $state('');
  let touched = $state(false);
  let busy = $state(false);
  let error = $state('');

  $effect(() => {
    if (open) untrack(reset);
  });

  function reset() {
    name = client?.name ?? '';
    audiences = client?.audiences.join(', ') ?? 'sts.amazonaws.com';
    ttl = client?.tokenTtlSeconds ?? 900;
    const a = client?.auth;
    method = a?.method ?? 'k8s-token-review';
    allowedUsers = a?.method === 'access-key' ? a.allowedUsers.join(', ') : '';
    apiServer = a?.method === 'k8s-token-review' ? a.apiServer : '';
    caPem = a?.method === 'k8s-token-review' ? (a.caPem ?? '') : '';
    serviceAccounts = a?.method === 'k8s-token-review' ? a.serviceAccounts.join('\n') : '';
    reviewAudience = a?.method === 'k8s-token-review' ? (a.reviewAudience ?? '') : '';
    subjectFormat = client?.subjectFormat ?? 'system:serviceaccount:{namespace}:{serviceAccount}';
    touched = false;
    error = '';
  }

  const list = (s: string) => s.split(/[\n,]+/).map((v) => v.trim()).filter(Boolean);
  const placeholders = $derived(PLACEHOLDERS[method]);
  const usedPlaceholders = $derived(subjectFormat.match(/\{[a-zA-Z]+\}/g) ?? []);
  const sampleValues = $derived<Record<string, string>>({
    '{clientId}': client?.clientId ?? 'wc_8f2a91',
    '{name}': name.trim() || 'orders-api',
    '{accountId}': '123456789012',
    '{username}': 'ci-bot',
    '{accessKeyId}': 'AKIACITADELEXAMPLE',
    '{namespace}': 'payments',
    '{serviceAccount}': 'orders-api',
    '{podName}': 'orders-api-7d9f8-x2k4p'
  });
  const preview = $derived(subjectFormat.replace(/\{[a-zA-Z]+\}/g, (m) => sampleValues[m] ?? m));

  const errs = $derived({
    name: !/^[a-z0-9][a-z0-9-]{1,62}$/.test(name.trim())
      ? 'Use 2–63 lowercase letters, numbers and dashes.'
      : existing.some((c) => c.name === name.trim() && c.clientId !== client?.clientId)
        ? 'Another client already uses this name.'
        : '',
    audiences: list(audiences).length === 0 ? 'Add at least one audience.' : '',
    subject: !subjectFormat.trim()
      ? 'Set a subject format.'
      : usedPlaceholders.find((p) => !placeholders.includes(p))
        ? `${usedPlaceholders.find((p) => !placeholders.includes(p))} isn't available with this authentication method.`
        : '',
    apiServer: method === 'k8s-token-review' && !/^https:\/\/\S+$/.test(apiServer.trim()) ? 'Enter the cluster API server https:// URL.' : '',
    serviceAccounts:
      method === 'k8s-token-review'
        ? list(serviceAccounts).length === 0
          ? 'Allow at least one namespace:serviceaccount.'
          : list(serviceAccounts).find((s) => !/^[a-z0-9*][a-z0-9.*-]*:[a-z0-9*][a-z0-9.*-]*$/.test(s))
            ? `“${list(serviceAccounts).find((s) => !/^[a-z0-9*][a-z0-9.*-]*:[a-z0-9*][a-z0-9.*-]*$/.test(s))}” should look like namespace:serviceaccount.`
            : ''
        : '',
    caPem: method === 'k8s-token-review' && caPem.trim() && !/-----BEGIN CERTIFICATE-----/.test(caPem) ? 'Paste the CA certificate in PEM form, or leave it empty.' : ''
  });
  const invalid = $derived(Object.values(errs).some(Boolean));
  const show = (k: keyof typeof errs) => (touched ? errs[k] : '');

  function onMethod(m: ClientAuth['method']) {
    // Swap the default subject format when it no longer fits the method.
    const preset = SUBJECT_PRESETS.find((p) => p.for === m);
    if (preset && SUBJECT_PRESETS.some((p) => p.value === subjectFormat && p.for !== 'any' && p.for !== m)) subjectFormat = preset.value;
  }

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    touched = true;
    if (invalid) return;
    const auth: ClientAuth =
      method === 'access-key'
        ? { method, allowedUsers: list(allowedUsers) }
        : {
            method,
            apiServer: apiServer.trim(),
            serviceAccounts: list(serviceAccounts),
            ...(caPem.trim() ? { caPem: caPem.trim() } : {}),
            ...(reviewAudience.trim() ? { reviewAudience: reviewAudience.trim() } : {})
          };
    const body: ClientInput = { name: name.trim(), audiences: list(audiences), tokenTtlSeconds: ttl, subjectFormat: subjectFormat.trim(), auth };
    busy = true;
    error = '';
    try {
      let id = client?.clientId ?? '';
      if (client) await wiApi.updateClient(client.clientId, body);
      else id = (await wiApi.createClient(body)).clientId;
      toast.success(client ? `Saved ${body.name}` : `Created ${body.name}`);
      open = false;
      onsaved(id);
    } catch (err) {
      error = errorMessage(err, 'Could not save the client.');
    } finally {
      busy = false;
    }
  }
</script>

<Modal bind:open title={client ? `Edit ${client.name}` : 'New workload client'} description="A client is one kind of workload that may ask Citadel for ID tokens." size="lg">
  <form id="wc-form" class="form" onsubmit={submit} novalidate>
    <div class="field-row">
      <div class="field">
        <label class="field-label" for="wc-name">Name</label>
        <input id="wc-name" class="input mono" bind:value={name} placeholder="orders-api" autocomplete="off" spellcheck="false" aria-invalid={!!show('name')} />
        {#if show('name')}<span class="field-error">{show('name')}</span>{/if}
      </div>
      <div class="field">
        <label class="field-label" for="wc-ttl">Token lifetime</label>
        <select id="wc-ttl" class="select" bind:value={ttl}>
          {#each TTLS as t (t.v)}<option value={t.v}>{t.l}</option>{/each}
          {#if !TTLS.some((t) => t.v === ttl)}<option value={ttl}>{Math.round(ttl / 60)} minutes</option>{/if}
        </select>
        <span class="field-hint">Short-lived tokens limit what a leak can do.</span>
      </div>
    </div>
    <div class="field">
      <label class="field-label" for="wc-aud">Allowed audiences</label>
      <input id="wc-aud" class="input mono" bind:value={audiences} autocomplete="off" spellcheck="false" aria-invalid={!!show('audiences')} />
      {#if show('audiences')}<span class="field-error">{show('audiences')}</span>{:else}<span class="field-hint">Comma-separated <code>aud</code> values the workload may request, e.g. <code>sts.amazonaws.com</code> or your API's URL.</span>{/if}
    </div>

    <section class="box" aria-labelledby="wc-auth-title">
      <div class="box-head">
        <h3 id="wc-auth-title">How the workload proves who it is</h3>
        <Seg
          label="Authentication method"
          bind:value={method}
          onchange={onMethod}
          options={[
            { value: 'k8s-token-review', label: 'Kubernetes service account' },
            { value: 'access-key', label: 'Citadel access key' }
          ]}
        />
      </div>
      <div class="box-body">
        {#if method === 'k8s-token-review'}
          <p class="muted small">The pod sends its projected service-account token. Citadel checks it with the cluster's TokenReview API.</p>
          <div class="field">
            <label class="field-label" for="wc-api">API server URL</label>
            <input id="wc-api" class="input mono" bind:value={apiServer} placeholder="https://k8s.prod.internal:6443" autocomplete="off" spellcheck="false" aria-invalid={!!show('apiServer')} />
            {#if show('apiServer')}<span class="field-error">{show('apiServer')}</span>{/if}
          </div>
          <div class="field">
            <label class="field-label" for="wc-sa">Allowed service accounts</label>
            <textarea id="wc-sa" class="textarea mono" rows="3" bind:value={serviceAccounts} placeholder={'payments:orders-api\nbatch:*'} spellcheck="false" aria-invalid={!!show('serviceAccounts')}></textarea>
            {#if show('serviceAccounts')}<span class="field-error">{show('serviceAccounts')}</span>{:else}<span class="field-hint">One <code>namespace:serviceaccount</code> per line; <code>*</code> matches any.</span>{/if}
          </div>
          <div class="field-row">
            <div class="field">
              <label class="field-label" for="wc-ra">Token review audience <span class="subtle">(optional)</span></label>
              <input id="wc-ra" class="input mono" bind:value={reviewAudience} placeholder="citadel" autocomplete="off" spellcheck="false" />
              <span class="field-hint">Require the pod token to be minted for this audience.</span>
            </div>
            <div class="field">
              <label class="field-label" for="wc-ca">Cluster CA <span class="subtle">(optional)</span></label>
              <textarea id="wc-ca" class="textarea mono" rows="2" bind:value={caPem} placeholder="-----BEGIN CERTIFICATE-----" spellcheck="false" aria-invalid={!!show('caPem')}></textarea>
              {#if show('caPem')}<span class="field-error">{show('caPem')}</span>{:else}<span class="field-hint">Needed when the API server uses a private CA.</span>{/if}
            </div>
          </div>
        {:else}
          <p class="muted small">The workload signs the token request (SigV4) with a Citadel access key from this account.</p>
          <div class="field">
            <label class="field-label" for="wc-users">Allowed users <span class="subtle">(optional)</span></label>
            <input id="wc-users" class="input mono" bind:value={allowedUsers} placeholder="ci-bot, deployer" autocomplete="off" spellcheck="false" />
            <span class="field-hint">Comma-separated usernames whose keys may request tokens. Empty allows any active key in this account.</span>
          </div>
        {/if}
      </div>
    </section>

    <div class="field">
      <label class="field-label" for="wc-sub">Subject format</label>
      <div class="subject">
        <input id="wc-sub" class="input mono" bind:value={subjectFormat} autocomplete="off" spellcheck="false" aria-invalid={!!show('subject')} aria-describedby="wc-sub-hint" />
        <label class="sr-only" for="wc-preset">Subject presets</label>
        <select id="wc-preset" class="select preset" value="" onchange={(e) => { if (e.currentTarget.value) subjectFormat = e.currentTarget.value; e.currentTarget.value = ''; }}>
          <option value="">Presets…</option>
          {#each SUBJECT_PRESETS.filter((p) => p.for === 'any' || p.for === method) as p (p.value)}<option value={p.value}>{p.label}</option>{/each}
        </select>
      </div>
      <span id="wc-sub-hint">
        {#if show('subject')}
          <span class="field-error">{show('subject')}</span>
        {:else}
          <span class="field-hint">Placeholders: {#each placeholders as p, i (p)}<code>{p}</code>{i < placeholders.length - 1 ? ' ' : ''}{/each}. Example: <code>{preview}</code></span>
        {/if}
      </span>
    </div>

    {#if error}
      <div class="callout callout-danger" role="alert"><Icon name="alert-circle" size={16} /><span>{error}</span></div>
    {/if}
  </form>
  {#snippet footer()}
    <button type="button" class="btn btn-ghost" onclick={() => (open = false)}>Cancel</button>
    <button type="submit" form="wc-form" class="btn btn-primary" disabled={busy}>{busy ? 'Saving…' : client ? 'Save changes' : 'Create client'}</button>
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
  .box {
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    overflow: hidden;
  }
  .box-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 8px;
    padding: 8px 12px;
    background: var(--surface-hover);
    border-bottom: 1px solid var(--border);
  }
  .box-head h3 {
    margin: 0;
    font-size: var(--text-base);
    font-weight: 600;
  }
  .box-body {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
    padding: 12px;
  }
  .box-body p {
    margin: 0;
  }
  .subject {
    display: flex;
    gap: 8px;
  }
  .preset {
    width: auto;
    flex: none;
  }
</style>
