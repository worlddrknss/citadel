<!-- Detail drawer for a CA, an issued certificate or a Let's Encrypt
     certificate: metadata, PEM and chain with copy/download, and the
     renew / revoke / CRL actions that apply to it. -->
<script lang="ts">
  import Drawer from '$lib/components/Drawer.svelte';
  import Tabs from '$lib/components/Tabs.svelte';
  import Badge from '$lib/components/Badge.svelte';
  import CopyButton from '$lib/components/CopyButton.svelte';
  import Icon from '$lib/components/Icon.svelte';
  import { api, errorMessage } from '$lib/api';
  import { certApi, type CertRow, type CertificateDetail } from './api';
  import { certStatus, cnOf, fmtDateTime, keyAlgLabel, titleCase, downloadText, safeFileName, isRevoked, firstDomain } from './certs';

  let {
    open = $bindable(false),
    row,
    tab = 'overview',
    caName,
    canIssue,
    canAdmin,
    ontab,
    onclose,
    onrenew,
    onrevoke,
    onissuefrom,
    onsubordinate
  }: {
    open?: boolean;
    row: CertRow | null;
    tab?: string;
    caName: (id?: string) => string;
    canIssue: boolean;
    canAdmin: boolean;
    ontab: (t: string) => void;
    onclose: () => void;
    onrenew: (c: CertRow) => void;
    onrevoke: (c: CertRow) => void;
    onissuefrom: (ca: CertRow) => void;
    onsubordinate: (ca: CertRow) => void;
  } = $props();

  let detail = $state<CertificateDetail | null>(null);
  let loading = $state(false);
  let error = $state('');
  let activeTab = $state('overview');

  $effect(() => {
    activeTab = tab || 'overview';
  });

  let loadedFor = '';
  $effect(() => {
    const r = row;
    if (!open || !r) return;
    const k = `${r.source}:${r.id}:${r.status}`;
    if (k === loadedFor) return;
    loadedFor = k;
    load(r);
  });

  async function load(r: CertRow) {
    loading = true;
    error = '';
    detail = null;
    try {
      detail = await certApi.detail(r.source, r.id);
    } catch (e) {
      error = errorMessage(e, 'Could not load the certificate.');
    } finally {
      loading = false;
    }
  }

  const isCA = $derived(row?.source === 'pca-ca');
  const name = $derived(
    row
      ? row.source === 'pca-ca'
        ? cnOf(row.subject) || row.id
        : row.source === 'lets-encrypt'
          ? firstDomain(row.subject) || row.id
          : row.commonName || cnOf(detail?.subject) || row.id
      : ''
  );
  const st = $derived(row && !isCA ? certStatus(row) : null);
  const tabs = $derived([
    { id: 'overview', label: 'Overview' },
    ...(detail?.pem ? [{ id: 'pem', label: 'PEM' }] : []),
    ...(detail?.chainPem && !isCA ? [{ id: 'chain', label: 'Chain' }] : [])
  ]);
  const fullChain = $derived(detail?.pem ? [detail.pem.trim(), detail.chainPem?.trim()].filter(Boolean).join('\n') + '\n' : '');
  const crlHref = $derived(row && isCA ? api.crlUrl(row.id) : '');
  const file = $derived(safeFileName(name));
</script>

<Drawer bind:open title={name} subtitle={row?.id} width={560} {onclose}>
  {#snippet actions()}
    {#if detail?.pem}
      <button
        type="button"
        class="btn-icon"
        aria-label="Download certificate"
        title="Download certificate"
        onclick={() => downloadText(`${file}.pem`, detail!.pem!)}
      >
        <Icon name="download" size={16} />
      </button>
    {/if}
  {/snippet}

  {#if row}
    <div class="wrap">
      <div class="badges">
        {#if isCA}
          <Badge tone="info" dot={false}>{row.caType === 'SUBORDINATE' ? 'Subordinate CA' : 'Root CA'}</Badge>
          <Badge tone={(row.status ?? '').toUpperCase() === 'ACTIVE' ? 'success' : 'neutral'} dot={false}>{titleCase(row.status || 'Unknown')}</Badge>
        {:else if st}
          <Badge tone={st.tone} dot={false}><Icon name={st.icon} size={12} />{st.label}</Badge>
          <span class="badge outline">{row.source === 'lets-encrypt' ? 'ACME' : 'Private CA'}</span>
        {/if}
      </div>

      <Tabs
        label="Certificate detail"
        tabs={tabs}
        bind:active={activeTab}
        onchange={(t) => ontab(t)}
      />

      {#if loading}
        <div class="sk" aria-busy="true" aria-label="Loading certificate">
          {#each Array(6) as _, i (i)}<span class="skeleton" style:width="{50 + ((i * 13) % 40)}%"></span>{/each}
        </div>
      {:else if error}
        <div class="callout callout-danger" role="alert">
          <Icon name="alert-circle" size={16} />
          <span>{error}</span>
          <button type="button" class="btn btn-ghost btn-sm retry" onclick={() => row && load(row)}>Retry</button>
        </div>
      {:else if detail}
        {#if activeTab === 'pem' && detail.pem}
          <div class="pemhead">
            <span class="field-label">Certificate</span>
            <span class="tools">
              <CopyButton value={detail.pem} label="Copy certificate PEM" />
              <button type="button" class="btn btn-ghost btn-sm" onclick={() => downloadText(`${file}.pem`, detail!.pem!)}>
                <Icon name="download" size={14} />Download .pem
              </button>
            </span>
          </div>
          <pre class="pem">{detail.pem}</pre>
        {:else if activeTab === 'chain' && detail.chainPem}
          <div class="pemhead">
            <span class="field-label">Issuer chain</span>
            <span class="tools">
              <CopyButton value={detail.chainPem} label="Copy chain PEM" />
              <button type="button" class="btn btn-ghost btn-sm" onclick={() => downloadText(`${file}-chain.pem`, detail!.chainPem!)}>
                <Icon name="download" size={14} />Chain
              </button>
              <button type="button" class="btn btn-ghost btn-sm" onclick={() => downloadText(`${file}-fullchain.pem`, fullChain)}>
                <Icon name="download" size={14} />Full chain
              </button>
            </span>
          </div>
          <pre class="pem">{detail.chainPem}</pre>
          <p class="subtle small">Full chain = this certificate followed by its issuer, the order most servers expect.</p>
        {:else}
          <dl class="kv">
            <dt>Subject</dt>
            <dd class="mono">{detail.subject || '—'}</dd>
            {#if !isCA}
              <dt>Issuer</dt>
              <dd>{row.source === 'lets-encrypt' ? "Let's Encrypt" : caName(row.issuerCaId) || detail.issuer || '—'}</dd>
            {:else if row.parentCaId}
              <dt>Parent CA</dt>
              <dd>{caName(row.parentCaId)}</dd>
            {/if}
            <dt>Serial</dt>
            <dd class="mono">{detail.serial || '—'}</dd>
            {#if detail.sans?.length}
              <dt>SANs</dt>
              <dd><span class="sans">{#each detail.sans as s (s)}<span class="badge mono">{s}</span>{/each}</span></dd>
            {:else if detail.domains}
              <dt>Domains</dt>
              <dd class="mono">{detail.domains}</dd>
            {/if}
            <dt>Valid from</dt>
            <dd>{fmtDateTime(detail.notBefore)}</dd>
            <dt>Valid to</dt>
            <dd>{fmtDateTime(detail.notAfter)}</dd>
            {#if detail.keyAlgorithm}
              <dt>Key</dt>
              <dd class="mono">{keyAlgLabel(detail.keyAlgorithm)}</dd>
            {/if}
            {#if detail.signatureAlgorithm}
              <dt>Signature</dt>
              <dd class="mono">{detail.signatureAlgorithm}</dd>
            {/if}
            {#if detail.template}
              <dt>Template</dt>
              <dd>{detail.template}</dd>
            {/if}
            {#if detail.kmsKeyId}
              <dt>KMS key</dt>
              <dd class="mono">{detail.kmsKeyId}</dd>
            {/if}
            {#if detail.revokedAt}
              <dt>Revoked</dt>
              <dd>{fmtDateTime(detail.revokedAt)}{detail.revocationReason ? ` · ${detail.revocationReason}` : ''}</dd>
            {/if}
            <dt>ID</dt>
            <dd class="idrow"><span class="mono">{detail.id}</span><CopyButton value={detail.id} label="Copy ID" /></dd>
          </dl>

          {#if isCA}
            <section class="crl" aria-labelledby="crl-title">
              <h3 id="crl-title">Revocation list</h3>
              <p class="muted small">Relying parties fetch the CRL from this public URL. It updates whenever a certificate from this CA is revoked.</p>
              <div class="crlrow">
                <a class="mono crlurl" href={crlHref} target="_blank" rel="noopener">{crlHref}</a>
                <CopyButton value={() => new URL(crlHref, location.origin).toString()} label="Copy CRL URL" />
                <a class="btn btn-secondary btn-sm" href={crlHref} download><Icon name="download" size={14} />Download CRL</a>
              </div>
            </section>
          {/if}
        {/if}
      {/if}
    </div>

    <div class="foot">
      {#if isCA}
        {#if canIssue && (row.status ?? '').toUpperCase() === 'ACTIVE'}
          <button type="button" class="btn btn-primary btn-sm" onclick={() => onissuefrom(row)}><Icon name="plus" size={14} />Issue from this CA</button>
        {/if}
        {#if canAdmin}
          <button type="button" class="btn btn-secondary btn-sm" onclick={() => onsubordinate(row)}><Icon name="git-pull-request" size={14} />New subordinate</button>
        {/if}
      {:else if row.source === 'pca-cert' && !isRevoked(row)}
        {#if canIssue}
          <button type="button" class="btn btn-secondary btn-sm" onclick={() => onrenew(row)}><Icon name="refresh" size={14} />Renew</button>
        {/if}
        {#if canAdmin}
          <button type="button" class="btn btn-danger-ghost btn-sm end" onclick={() => onrevoke(row)}><Icon name="x" size={14} />Revoke</button>
        {/if}
      {:else if row.source === 'lets-encrypt'}
        <span class="subtle small">Renew Let's Encrypt certificates by requesting the same domains again.</span>
      {/if}
    </div>
  {/if}
</Drawer>

<style>
  .wrap {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
    padding-bottom: var(--space-4);
  }
  .badges {
    display: flex;
    gap: 6px;
    flex-wrap: wrap;
  }
  .badge.outline {
    background: transparent;
    color: var(--text-muted);
    box-shadow: inset 0 0 0 1px var(--border-strong);
    font-size: 11.5px;
  }
  .sk {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }
  .sk .skeleton {
    height: 12px;
  }
  .retry {
    margin-left: auto;
  }
  .kv {
    grid-template-columns: 120px minmax(0, 1fr);
  }
  .sans {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
  }
  .sans .badge {
    font-size: 11.5px;
  }
  .idrow {
    display: flex;
    align-items: center;
    gap: 4px;
  }
  .pemhead {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--space-2);
    flex-wrap: wrap;
  }
  .tools {
    display: inline-flex;
    align-items: center;
    gap: 2px;
    flex-wrap: wrap;
  }
  .pem {
    font-size: 11.5px;
    max-height: 420px;
    white-space: pre;
  }
  .crl {
    display: flex;
    flex-direction: column;
    gap: 8px;
    padding: var(--space-4);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
  }
  .crl h3 {
    margin: 0;
    font-size: var(--text-base);
  }
  .crl p {
    margin: 0;
  }
  .crlrow {
    display: flex;
    align-items: center;
    gap: 6px;
    flex-wrap: wrap;
  }
  .crlurl {
    overflow-wrap: anywhere;
    font-size: 12px;
  }
  .foot {
    position: sticky;
    bottom: calc(-1 * var(--space-5));
    margin: 0 calc(-1 * var(--space-5)) calc(-1 * var(--space-5));
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
    align-items: center;
    padding: 12px var(--space-5);
    border-top: 1px solid var(--border);
    background: var(--surface-hover);
  }
  .foot:empty {
    display: none;
  }
  .end {
    margin-left: auto;
  }
  @media (max-width: 820px) {
    .kv {
      grid-template-columns: minmax(0, 1fr);
    }
  }
</style>
