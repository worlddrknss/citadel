<!-- Detail drawer for a CA, an issued certificate, a Let's Encrypt
     certificate or one imported through ACM: metadata, PEM, the full chain
     to the root with per-certificate downloads, and the renew / revoke /
     delete / CRL actions that apply to it. -->
<script lang="ts">
  import Drawer from '#lib/components/Drawer.svelte';
  import Tabs from '#lib/components/Tabs.svelte';
  import Badge from '#lib/components/Badge.svelte';
  import CopyButton from '#lib/components/CopyButton.svelte';
  import Icon from '#lib/components/Icon.svelte';
  import { api, errorMessage } from '#lib/api.ts';
  import { certApi, type CertRow, type CertificateDetail } from './api';
  import { certStatus, cnOf, fmtDateTime, keyAlgLabel, titleCase, downloadText, safeFileName, isRevoked, isImported, canRenewOrRevoke, sourceLabel, chainRoleLabel, chainComplete, firstDomain, pathLenDescription } from './certs';

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
    ondelete,
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
    ondelete: (c: CertRow) => void;
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
          : row.commonName || cnOf(detail?.subject) || (isImported(row) ? row.subject : '') || row.id
      : ''
  );
  const st = $derived(row && !isCA ? certStatus(row) : null);
  const tabs = $derived([
    { id: 'overview', label: 'Overview' },
    ...(detail?.pem ? [{ id: 'pem', label: 'PEM' }] : []),
    ...((detail?.chain?.length ?? 0) > 1 || (detail?.chainPem && !isCA) ? [{ id: 'chain', label: 'Chain' }] : [])
  ]);
  const fullChain = $derived(
    detail?.chain?.length
      ? detail.chain.map((c) => c.pem.trim()).join('\n') + '\n'
      : detail?.pem
        ? [detail.pem.trim(), detail.chainPem?.trim()].filter(Boolean).join('\n') + '\n'
        : ''
  );
  /** The issuer chain without this certificate. */
  const issuerChain = $derived(
    detail?.chain && detail.chain.length > 1 ? detail.chain.slice(1).map((c) => c.pem.trim()).join('\n') + '\n' : detail?.chainPem ?? ''
  );
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
          <span class="badge outline">{sourceLabel(row.source)}</span>
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
        {:else if activeTab === 'chain' && (detail.chain?.length || detail.chainPem)}
          <div class="pemhead">
            <span class="field-label">Chain to the root</span>
            <span class="tools">
              {#if issuerChain}
                <CopyButton value={issuerChain} label="Copy issuer chain PEM" />
                <button type="button" class="btn btn-ghost btn-sm" onclick={() => downloadText(`${file}-chain.pem`, issuerChain)}>
                  <Icon name="download" size={14} />Chain
                </button>
              {/if}
              <button type="button" class="btn btn-ghost btn-sm" onclick={() => downloadText(`${file}-fullchain.pem`, fullChain)}>
                <Icon name="download" size={14} />Full chain
              </button>
            </span>
          </div>
          {#if detail.chain?.length}
            <ol class="chain" aria-label="Certificate chain, leaf to root">
              {#each detail.chain as c, i (i)}
                <li class="link" data-testid="chain-cert">
                  <div class="linkhead">
                    <Badge tone={c.role === 'root' ? 'info' : c.role === 'leaf' ? 'success' : 'neutral'} dot={false}>{chainRoleLabel(c.role)}</Badge>
                    <span class="mono linkname">{cnOf(c.subject) || c.subject}</span>
                    <button
                      type="button"
                      class="btn btn-ghost btn-sm push"
                      aria-label="Download {chainRoleLabel(c.role).toLowerCase()} certificate {cnOf(c.subject) || c.subject}"
                      onclick={() => downloadText(`${safeFileName(cnOf(c.subject) || c.subject)}.pem`, c.pem)}
                    >
                      <Icon name="download" size={14} />.pem
                    </button>
                  </div>
                  <dl class="kv chainkv">
                    <dt>Subject</dt>
                    <dd class="mono">{c.subject}</dd>
                    <dt>Issuer</dt>
                    <dd class="mono">{c.issuer}{c.selfSigned ? ' (self-signed)' : ''}</dd>
                    <dt>Valid</dt>
                    <dd>{fmtDateTime(c.notBefore)} – {fmtDateTime(c.notAfter)}</dd>
                    <dt>Serial</dt>
                    <dd class="mono">{c.serial}</dd>
                  </dl>
                </li>
              {/each}
            </ol>
            {#if !chainComplete(detail.chain)}
              <p class="subtle small" data-testid="chain-incomplete">
                Citadel doesn't hold the issuer of the last certificate, so the chain stops there.
              </p>
            {/if}
          {:else if detail.chainPem}
            <pre class="pem">{detail.chainPem}</pre>
          {/if}
          <p class="subtle small">Full chain = this certificate followed by its issuers, the order most servers expect.</p>
        {:else}
          <dl class="kv">
            <dt>Subject</dt>
            <dd class="mono">{detail.subject || '—'}</dd>
            {#if !isCA}
              <dt>Issuer</dt>
              <dd>{row.source === 'lets-encrypt' ? "Let's Encrypt" : (!isImported(row) && caName(row.issuerCaId)) || detail.issuer || '—'}</dd>
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
            {#if isCA}
              <dt>Path length</dt>
              <dd data-testid="ca-pathlen">{pathLenDescription(detail.pathLen)}</dd>
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
        <!-- The server gives subordinates pathLen 0, so only active roots can sign CAs. -->
        {#if canAdmin && (row.status ?? '').toUpperCase() === 'ACTIVE' && (row.caType ?? '').toUpperCase() !== 'SUBORDINATE'}
          <button type="button" class="btn btn-secondary btn-sm" onclick={() => onsubordinate(row)}><Icon name="git-pull-request" size={14} />New subordinate</button>
        {/if}
      {:else if canRenewOrRevoke(row)}
        {#if canIssue}
          <button type="button" class="btn btn-secondary btn-sm" onclick={() => onrenew(row)}><Icon name="refresh" size={14} />Renew</button>
        {/if}
        {#if canAdmin}
          <button type="button" class="btn btn-danger-ghost btn-sm end" onclick={() => onrevoke(row)}><Icon name="x" size={14} />Revoke</button>
        {/if}
      {:else if row.source === 'lets-encrypt'}
        <span class="subtle small">Renew Let's Encrypt certificates by requesting the same domains again.</span>
      {:else if isImported(row)}
        <span class="subtle small">Imported through ACM. Replace it with ACM ImportCertificate.</span>
        {#if canAdmin}
          <button type="button" class="btn btn-danger-ghost btn-sm end" onclick={() => ondelete(row)}><Icon name="trash" size={14} />Delete</button>
        {/if}
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
    font-size: 12.5px;
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
    font-size: 12.5px;
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
    font-size: 12.5px;
    max-height: 420px;
    white-space: pre;
  }
  .chain {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
  }
  .link {
    position: relative;
    padding: var(--space-3) var(--space-4);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
  }
  .link + .link::before {
    content: '';
    position: absolute;
    left: var(--space-5);
    top: calc(-1 * var(--space-3) - 1px);
    height: var(--space-3);
    border-left: 1px solid var(--border-strong);
  }
  .linkhead {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 6px;
  }
  .linkname {
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    font-size: 13px;
  }
  .push {
    margin-left: auto;
  }
  .chainkv {
    grid-template-columns: 70px minmax(0, 1fr);
    font-size: 13px;
  }
  .chainkv dd {
    overflow-wrap: anywhere;
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
    font-size: 13px;
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
