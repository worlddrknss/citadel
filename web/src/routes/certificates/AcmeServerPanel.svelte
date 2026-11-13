<!-- Citadel's built-in RFC 8555 ACME server: where clients point, which
     names they may request and which CA signs them (the issuance policy;
     with none saved every order is refused), how to configure common
     clients, and External Account Binding keys. -->
<script lang="ts">
  import Icon from '#lib/components/Icon.svelte';
  import Badge from '#lib/components/Badge.svelte';
  import Modal from '#lib/components/Modal.svelte';
  import CopyButton from '#lib/components/CopyButton.svelte';
  import EmptyState from '#lib/components/EmptyState.svelte';
  import Seg from './Seg.svelte';
  import OnceSecret from './OnceSecret.svelte';
  import { errorMessage } from '#lib/api.ts';
  import { toast } from '#lib/stores/toast.svelte.ts';
  import { confirm } from '#lib/stores/confirm.svelte.ts';
  import { certApi, type AcmeSettings, type EabKey } from './api';
  import { fmtDateTime } from './certs';

  interface CaOption {
    id: string;
    name: string;
    status: string;
  }

  let { accountId, canManage, cas = [] }: { accountId: string; canManage: boolean; cas?: CaOption[] } = $props();

  // ---- issuance policy -----------------------------------------------------
  let settings = $state<AcmeSettings | null>(null);
  let settingsError = $state('');
  let issuingCaId = $state('');
  let domainsText = $state('');
  let ipsText = $state('');
  let cidrsText = $state('');
  let saving = $state(false);
  let saveError = $state('');

  const lines = (t: string) =>
    t
      .split(/[\s,]+/)
      .map((x) => x.trim())
      .filter(Boolean);

  function fill(s: AcmeSettings) {
    settings = s;
    issuingCaId = s.issuingCaId ?? '';
    domainsText = (s.allowedDomains ?? []).join('\n');
    ipsText = (s.allowedIpRanges ?? []).join('\n');
    cidrsText = (s.validationAllowedCidrs ?? []).join('\n');
  }

  async function loadSettings() {
    settingsError = '';
    try {
      fill(await certApi.acmeSettings());
    } catch (e) {
      settingsError = errorMessage(e, 'Could not load the ACME settings.');
    }
  }

  const dirty = $derived(
    !!settings &&
      (issuingCaId !== (settings.issuingCaId ?? '') ||
        lines(domainsText).join() !== (settings.allowedDomains ?? []).join() ||
        lines(ipsText).join() !== (settings.allowedIpRanges ?? []).join() ||
        lines(cidrsText).join() !== (settings.validationAllowedCidrs ?? []).join())
  );

  async function saveSettings(e: SubmitEvent) {
    e.preventDefault();
    saving = true;
    saveError = '';
    try {
      fill(
        await certApi.saveAcmeSettings({
          issuingCaId,
          allowedDomains: lines(domainsText),
          allowedIpRanges: lines(ipsText),
          validationAllowedCidrs: lines(cidrsText)
        })
      );
      toast.success('ACME settings saved');
    } catch (err) {
      saveError = errorMessage(err, 'Could not save the ACME settings.');
    } finally {
      saving = false;
    }
  }

  const activeCas = $derived(cas.filter((c) => (c.status ?? '').toUpperCase() === 'ACTIVE'));
  const caLabel = (id?: string) => {
    if (!id) return '';
    const c = cas.find((x) => x.id === id);
    return c ? c.name : id;
  };
  const nothingAllowed = $derived(!!settings && !settings.allowedDomains?.length && !settings.allowedIpRanges?.length);

  const directory = $derived(settings?.directoryUrl ?? '');
  const host = $derived(directory.replace(/^https?:\/\//, '').replace(/\/.*$/, ''));
  const shown = $derived(directory || 'https://citadel.example.com/acme/directory');

  let client = $state<'certbot' | 'acmesh' | 'certmanager'>('certbot');
  const snippets = $derived({
    certbot: `certbot certonly --standalone \\
  --server ${shown} \\
  --eab-kid "<KID>" --eab-hmac-key "<HMAC_KEY>" \\
  -d orders.internal.example.com`,
    acmesh: `acme.sh --register-account --server ${shown} \\
  --eab-kid "<KID>" --eab-hmac-key "<HMAC_KEY>"
acme.sh --issue --server ${shown} \\
  --standalone -d orders.internal.example.com`,
    certmanager: `apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: citadel
spec:
  acme:
    server: ${shown}
    privateKeySecretRef:
      name: citadel-acme-account
    externalAccountBinding:
      keyID: "<KID>"
      keySecretRef:
        name: citadel-eab
        key: secret
    solvers:
      - http01:
          ingress:
            ingressClassName: nginx`
  }[client]);

  let keys = $state<EabKey[]>([]);
  let loading = $state(true);
  let loadError = $state('');

  async function load() {
    loading = true;
    loadError = '';
    try {
      keys = (await certApi.eabKeys()).keys ?? [];
    } catch (e) {
      loadError = errorMessage(e, 'Could not load EAB keys.');
    } finally {
      loading = false;
    }
  }
  $effect(() => {
    void accountId;
    load();
    loadSettings();
  });

  // Create
  let createOpen = $state(false);
  let label = $state('');
  let creating = $state(false);
  let createError = $state('');
  let secret = $state<{ kid: string; hmacKey: string } | null>(null);
  let secretOpen = $state(false);

  function openCreate() {
    label = '';
    createError = '';
    createOpen = true;
  }

  async function create(e: SubmitEvent) {
    e.preventDefault();
    if (!label.trim()) {
      createError = 'Give the key a label so you can tell it apart later.';
      return;
    }
    creating = true;
    createError = '';
    try {
      const r = await certApi.createEabKey(label.trim());
      createOpen = false;
      secret = { kid: r.kid, hmacKey: r.hmacKey };
      secretOpen = true;
      load();
    } catch (err) {
      createError = errorMessage(err, 'Could not create the key.');
    } finally {
      creating = false;
    }
  }

  async function revoke(k: EabKey) {
    const ok = await confirm({
      title: `Revoke ${k.label || k.kid}?`,
      message:
        k.status === 'bound'
          ? 'The ACME account bound to this key can no longer order certificates. Certificates already issued stay valid.'
          : 'Nobody will be able to register an ACME account with this key.',
      confirmLabel: 'Revoke key',
      danger: true,
      typeToConfirm: k.status === 'bound' ? k.kid : undefined
    });
    if (!ok) return;
    try {
      await certApi.revokeEabKey(k.kid);
      toast.success('EAB key revoked');
      load();
    } catch (e) {
      toast.error(e, 'Could not revoke the key');
    }
  }

  const tone = { unused: 'info', bound: 'success', revoked: 'neutral' } as const;
  const statusLabel = { unused: 'Unused', bound: 'Bound', revoked: 'Revoked' } as const;
</script>

<div class="stack">
  <section class="card" aria-labelledby="acme-title">
    <div class="card-head">
      <h2 id="acme-title">Built-in ACME server</h2>
      <span class="badge">RFC 8555</span>
    </div>
    <div class="card-pad intro">
      <p class="muted">
        Any ACME client (certbot, acme.sh, cert-manager, Caddy, Traefik) can get certificates from your private CA by pointing at Citadel instead
        of Let's Encrypt. Clients prove control of each name with HTTP-01, then Citadel signs the order with the default private CA.
      </p>
      {#if settingsError}
        <div class="callout callout-danger" role="alert">
          <Icon name="alert-circle" size={16} /><span>{settingsError}</span>
          <button type="button" class="btn btn-ghost btn-sm push" onclick={loadSettings}>Retry</button>
        </div>
      {:else if settings && !settings.enabled}
        <div class="callout callout-warning" role="status">
          <Icon name="alert-triangle" size={16} />
          <span>The ACME server is off on this deployment: set <span class="mono">KMS_PUBLIC_URL</span> to the address clients use to reach Citadel, then restart it.</span>
        </div>
      {:else if settings}
        <div class="field">
          <span class="field-label">Directory URL</span>
          <div class="urlbox">
            <code class="mono" data-testid="acme-directory">{directory}</code>
            <CopyButton value={directory} label="Copy directory URL" />
          </div>
          <span class="field-hint">Clients must trust your root CA, and reach <span class="mono">{host}</span> over HTTPS.</span>
        </div>
      {/if}
      <div class="field">
        <div class="snip-head">
          <span class="field-label">Client setup</span>
          <Seg
            label="ACME client"
            bind:value={client}
            options={[
              { value: 'certbot', label: 'certbot' },
              { value: 'acmesh', label: 'acme.sh' },
              { value: 'certmanager', label: 'cert-manager' }
            ]}
          />
        </div>
        <div class="code">
          <pre>{snippets}</pre>
          <span class="copy"><CopyButton value={snippets} label="Copy snippet" /></span>
        </div>
        <span class="field-hint">Replace <span class="mono">&lt;KID&gt;</span> and <span class="mono">&lt;HMAC_KEY&gt;</span> with an External Account Binding key from below.</span>
      </div>
    </div>
  </section>

  {#if settings}
    <section class="card" aria-labelledby="acme-policy-title">
      <div class="card-head">
        <div>
          <h2 id="acme-policy-title">Issuance policy</h2>
          <p class="subtle small sub">What ACME clients in <span class="mono">{accountId || 'this account'}</span> may request, and which CA signs it.</p>
        </div>
        <Badge tone={settings.enabled ? 'success' : 'neutral'}>{settings.enabled ? 'Enabled' : 'Off'}</Badge>
      </div>
      <form class="card-pad policy" onsubmit={saveSettings} novalidate>
        {#if nothingAllowed}
          <div class="callout callout-warning" role="status">
            <Icon name="alert-triangle" size={16} />
            <span>No names are allowed yet, so every order is refused. Add the domains (or IP ranges) your clients may request.</span>
          </div>
        {/if}
        <div class="field">
          <label class="field-label" for="acme-ca">Issuing CA</label>
          <select id="acme-ca" class="select" bind:value={issuingCaId} disabled={!canManage}>
            <option value="">Automatic (oldest active CA)</option>
            {#each activeCas as c (c.id)}<option value={c.id}>{c.name}</option>{/each}
            {#if issuingCaId && !activeCas.some((c) => c.id === issuingCaId)}<option value={issuingCaId}>{caLabel(issuingCaId)}</option>{/if}
          </select>
          {#if settings.effectiveIssuingCaId}
            <span class="field-hint">Orders are signed by <span class="strong" data-testid="acme-effective-ca">{caLabel(settings.effectiveIssuingCaId)}</span>.</span>
          {:else}
            <span class="field-error">No active CA can sign ACME orders. Create or activate a CA first.</span>
          {/if}
        </div>
        <div class="field">
          <label class="field-label" for="acme-domains">Allowed domains</label>
          <textarea id="acme-domains" class="textarea mono" rows="3" bind:value={domainsText} disabled={!canManage} placeholder="internal.example.com" spellcheck="false"></textarea>
          <span class="field-hint">One per line. Each domain also allows its subdomains; wildcards aren't needed.</span>
        </div>
        <div class="field-row">
          <div class="field">
            <label class="field-label" for="acme-ips">Allowed IP ranges <span class="subtle">(optional)</span></label>
            <textarea id="acme-ips" class="textarea mono" rows="2" bind:value={ipsText} disabled={!canManage} placeholder="10.0.0.0/8" spellcheck="false"></textarea>
            <span class="field-hint">IP addresses clients may put in certificates. CIDRs or single IPs.</span>
          </div>
          <div class="field">
            <label class="field-label" for="acme-cidrs">Validation exemptions <span class="subtle">(optional)</span></label>
            <textarea id="acme-cidrs" class="textarea mono" rows="2" bind:value={cidrsText} disabled={!canManage} placeholder="127.0.0.1/32" spellcheck="false"></textarea>
            <span class="field-hint">Addresses Citadel may connect to for HTTP-01 even though they are loopback, link-local or private.</span>
          </div>
        </div>
        {#if saveError}
          <div class="callout callout-danger" role="alert"><Icon name="alert-circle" size={16} /><span>{saveError}</span></div>
        {/if}
        <div class="policy-foot">
          <span class="subtle small">{settings.updatedAt ? `Updated ${fmtDateTime(settings.updatedAt)}${settings.updatedBy ? ` by ${settings.updatedBy}` : ''}` : 'Not configured yet'}</span>
          {#if canManage}
            <button type="submit" class="btn btn-primary btn-sm" disabled={saving || !dirty}>{saving ? 'Saving…' : 'Save policy'}</button>
          {/if}
        </div>
      </form>
    </section>
  {/if}

  <section class="card" aria-labelledby="eab-title">
    <div class="card-head">
      <div>
        <h2 id="eab-title">External Account Binding keys</h2>
        <p class="subtle small sub">Each key registers one ACME account in <span class="mono">{accountId || 'this account'}</span>. Revoke it to cut that client off.</p>
      </div>
      {#if canManage}
        <button type="button" class="btn btn-secondary btn-sm" onclick={openCreate}><Icon name="plus" size={14} />Create key</button>
      {/if}
    </div>
    {#if loadError}
      <div class="card-pad">
        <div class="callout callout-danger" role="alert">
          <Icon name="alert-circle" size={16} /><span>{loadError}</span>
          <button type="button" class="btn btn-ghost btn-sm push" onclick={load}>Retry</button>
        </div>
      </div>
    {:else if !loading && keys.length === 0}
      <div class="card-pad">
        <EmptyState icon="key" title="No EAB keys" description="Create one per client or cluster. The HMAC key is shown once, when you create it.">
          {#if canManage}<button type="button" class="btn btn-primary btn-sm" onclick={openCreate}><Icon name="plus" size={14} />Create key</button>{/if}
        </EmptyState>
      </div>
    {:else}
      <div class="scroll">
        <table class="table">
          <caption class="sr-only">External Account Binding keys</caption>
          <thead>
            <tr>
              <th scope="col">Label</th>
              <th scope="col">Key ID</th>
              <th scope="col">Status</th>
              <th scope="col">ACME account</th>
              <th scope="col">Created</th>
              <th scope="col" class="end"><span class="sr-only">Actions</span></th>
            </tr>
          </thead>
          <tbody>
            {#if loading && keys.length === 0}
              {#each Array(3) as _, i (i)}<tr>{#each Array(6) as __, j (j)}<td><span class="skeleton sk"></span></td>{/each}</tr>{/each}
            {:else}
              {#each keys as k (k.kid)}
                <tr>
                  <td class="strong">{k.label || '—'}</td>
                  <td><span class="cell"><span class="mono">{k.kid}</span><CopyButton value={k.kid} label="Copy key ID" /></span></td>
                  <td><Badge tone={tone[k.status] ?? 'neutral'} dot={false}>{statusLabel[k.status] ?? k.status}</Badge></td>
                  <td class="mono subtle">{k.acmeAccountId ?? '—'}</td>
                  <td class="subtle">{fmtDateTime(k.createdAt)}{k.createdBy ? ` · ${k.createdBy}` : ''}</td>
                  <td class="end">
                    {#if canManage && k.status !== 'revoked'}
                      <button type="button" class="btn btn-danger-ghost btn-sm" onclick={() => revoke(k)} aria-label="Revoke {k.label || k.kid}">Revoke</button>
                    {/if}
                  </td>
                </tr>
              {/each}
            {/if}
          </tbody>
        </table>
      </div>
    {/if}
  </section>
</div>

<Modal bind:open={createOpen} title="Create EAB key" description="Give it a label that says which client or cluster will use it." size="sm">
  <form id="eab-form" onsubmit={create} novalidate>
    <div class="field">
      <label class="field-label" for="eab-label">Label</label>
      <input id="eab-label" class="input" bind:value={label} placeholder="prod-eu cert-manager" autocomplete="off" maxlength="128" aria-invalid={!!createError} />
      {#if createError}<span class="field-error">{createError}</span>{/if}
    </div>
  </form>
  {#snippet footer()}
    <button type="button" class="btn btn-ghost" onclick={() => (createOpen = false)}>Cancel</button>
    <button type="submit" form="eab-form" class="btn btn-primary" disabled={creating}>{creating ? 'Creating…' : 'Create key'}</button>
  {/snippet}
</Modal>

{#if secret}
  <OnceSecret
    bind:open={secretOpen}
    title="EAB key created"
    description="Configure your ACME client with both values. The HMAC key can't be retrieved later."
    fields={[
      { label: 'Key ID (kid)', value: secret.kid },
      { label: 'HMAC key', value: secret.hmacKey, secret: true }
    ]}
    ondone={() => (secret = null)}
  />
{/if}

<style>
  .card-head h2 {
    font-family: var(--font-sans);
    font-size: var(--text-md);
    letter-spacing: 0;
  }
  .sub {
    margin: 2px 0 0;
  }
  .intro {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
  }
  .intro p {
    margin: 0;
    max-width: 80ch;
  }
  .intro .field + .field {
    margin-top: 0;
  }
  .urlbox {
    display: flex;
    align-items: center;
    gap: 4px;
    padding: 6px 6px 6px 12px;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: var(--surface-sunken);
    max-width: 640px;
  }
  .urlbox code {
    flex: 1;
    padding: 0;
    background: none;
    overflow-wrap: anywhere;
  }
  .snip-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    flex-wrap: wrap;
  }
  .code {
    position: relative;
  }
  .code pre {
    padding-right: 44px;
    white-space: pre;
  }
  .copy {
    position: absolute;
    top: 6px;
    right: 6px;
  }
  .scroll {
    overflow-x: auto;
  }
  .table {
    min-width: 720px;
  }
  .table td {
    white-space: nowrap;
  }
  .strong {
    font-weight: 500;
  }
  .cell {
    display: inline-flex;
    align-items: center;
    gap: 4px;
  }
  .sk {
    display: block;
    height: 12px;
    width: 70%;
  }
  .end {
    text-align: end;
  }
  .push {
    margin-left: auto;
  }
  .policy {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
  }
  .policy .field + .field {
    margin-top: 0;
  }
  .policy textarea {
    max-width: 640px;
  }
  .policy select {
    max-width: 420px;
  }
  .policy-foot {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    flex-wrap: wrap;
  }
</style>
