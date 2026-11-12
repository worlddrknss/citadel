<!-- Citadel's built-in RFC 8555 ACME server: where clients point, how to
     configure common clients, and External Account Binding keys. -->
<script lang="ts">
  import Icon from '$lib/components/Icon.svelte';
  import Badge from '$lib/components/Badge.svelte';
  import Modal from '$lib/components/Modal.svelte';
  import CopyButton from '$lib/components/CopyButton.svelte';
  import EmptyState from '$lib/components/EmptyState.svelte';
  import Seg from './Seg.svelte';
  import OnceSecret from './OnceSecret.svelte';
  import { errorMessage } from '$lib/api';
  import { toast } from '$lib/stores/toast.svelte';
  import { confirm } from '$lib/stores/confirm.svelte';
  import { certApi, type EabKey } from './api';
  import { fmtDateTime } from './certs';

  let { accountId, canManage }: { accountId: string; canManage: boolean } = $props();

  const origin = typeof location !== 'undefined' ? location.origin : '';
  const directory = `${origin}/acme/directory`;
  const host = origin.replace(/^https?:\/\//, '');

  let client = $state<'certbot' | 'acmesh' | 'certmanager'>('certbot');
  const snippets = $derived({
    certbot: `certbot certonly --standalone \\
  --server ${directory} \\
  --eab-kid "<KID>" --eab-hmac-key "<HMAC_KEY>" \\
  -d orders.internal.example.com`,
    acmesh: `acme.sh --register-account --server ${directory} \\
  --eab-kid "<KID>" --eab-hmac-key "<HMAC_KEY>"
acme.sh --issue --server ${directory} \\
  --standalone -d orders.internal.example.com`,
    certmanager: `apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: citadel
spec:
  acme:
    server: ${directory}
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
      <div class="field">
        <span class="field-label">Directory URL</span>
        <div class="urlbox">
          <code class="mono">{directory}</code>
          <CopyButton value={directory} label="Copy directory URL" />
        </div>
        <span class="field-hint">Clients must trust your root CA, and reach <span class="mono">{host}</span> over HTTPS.</span>
      </div>
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
      <input id="eab-label" class="input" bind:value={label} placeholder="prod-eu cert-manager" autocomplete="off" maxlength="64" aria-invalid={!!createError} />
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
</style>
