<script lang="ts">
  import { onMount } from 'svelte';
  import { api, ApiError, type Certificate, type CertificateDetail } from '$lib/api';

  let certs: Certificate[] = $state([]);
  let loading = $state(true);
  let flash = $state('');
  let flashOk = $state(true);

  // Detail drawer
  let detail: CertificateDetail | null = $state(null);
  let detailTab = $state('overview');

  const sourceLabel: Record<string, string> = {
    'pca-ca': 'Private CA',
    'pca-cert': 'Issued (PCA)',
    'lets-encrypt': "Let's Encrypt"
  };

  // Create-CA form
  let caCommonName = $state('');
  let caOrg = $state('');
  let caCountry = $state('');
  let caType = $state('ROOT');
  let caKeyAlg = $state('RSA_2048');
  let creatingCA = $state(false);

  // Issue-cert form
  let issueCaArn = $state('');
  let csrPem = $state('');
  let validityDays = $state('365');
  let sanNames = $state('');
  let issuing = $state(false);

  const cas = $derived(certs.filter((c) => c.source === 'pca-ca'));

  // CA hierarchy: each CA grouped with the certificates it has issued.
  const caGroups = $derived(
    cas.map((ca) => ({
      ca,
      issued: certs.filter((c) => c.source === 'pca-cert' && c.issuerCaId === ca.id)
    }))
  );
  // pca-cert rows whose issuing CA is not present in the listing.
  const orphanCerts = $derived(
    certs.filter((c) => c.source === 'pca-cert' && !cas.some((ca) => ca.id === c.issuerCaId))
  );
  const otherCerts = $derived(certs.filter((c) => c.source === 'lets-encrypt'));

  let expanded = $state<Record<string, boolean>>({});
  function toggleCA(id: string) {
    expanded = { ...expanded, [id]: !expanded[id] };
  }

  // In-app revoke confirmation (no native confirm()).
  let confirmCert: Certificate | null = $state(null);
  let confirmReason = $state('Unspecified');
  let revoking = $state(false);
  const revokeReasons = [
    'Unspecified',
    'KeyCompromise',
    'CACompromise',
    'AffiliationChanged',
    'Superseded',
    'CessationOfOperation',
    'PrivilegeWithdrawn'
  ];

  function fmtType(t?: string): string {
    return t === 'SUBORDINATE' ? 'Subordinate' : t === 'ROOT' ? 'Root' : t || '—';
  }

  function notify(msg: string, ok = true) {
    flash = msg;
    flashOk = ok;
    setTimeout(() => (flash = ''), 5000);
  }

  async function load() {
    loading = true;
    try {
      certs = (await api.certificates()).certificates;
    } catch (e) {
      if (e instanceof ApiError) notify(e.message, false);
    } finally {
      loading = false;
    }
  }

  async function createCA() {
    if (!caCommonName.trim()) {
      notify('common name is required', false);
      return;
    }
    creatingCA = true;
    try {
      const res = await api.createCA({
        caType,
        keyAlgorithm: caKeyAlg,
        commonName: caCommonName.trim(),
        organization: caOrg.trim(),
        country: caCountry.trim()
      });
      notify(`Created CA ${res.caId}`);
      caCommonName = '';
      caOrg = '';
      caCountry = '';
      await load();
    } catch (e) {
      if (e instanceof ApiError) notify(e.message, false);
    } finally {
      creatingCA = false;
    }
  }

  async function issueCert() {
    if (!issueCaArn || !csrPem.trim()) {
      notify('CA and CSR are required', false);
      return;
    }
    issuing = true;
    try {
      await api.issueCert({ caArn: issueCaArn, csrPem: csrPem.trim(), validityDays, sanNames: sanNames.trim() });
      notify('Certificate issued');
      csrPem = '';
      sanNames = '';
      await load();
    } catch (e) {
      if (e instanceof ApiError) notify(e.message, false);
    } finally {
      issuing = false;
    }
  }

  function askRevoke(c: Certificate) {
    confirmReason = 'Unspecified';
    confirmCert = c;
  }

  async function confirmRevoke() {
    if (!confirmCert) return;
    revoking = true;
    try {
      await api.revokeCert(confirmCert.id, confirmReason);
      notify(`Revoked ${confirmCert.id}`);
      confirmCert = null;
      await load();
    } catch (e) {
      if (e instanceof ApiError) notify(e.message, false);
    } finally {
      revoking = false;
    }
  }

  // ---- detail drawer -------------------------------------------------------
  async function openDetail(c: Certificate) {
    detailTab = 'overview';
    detail = null;
    try {
      detail = await api.certificateDetail(c.source, c.id);
    } catch (e) {
      if (e instanceof ApiError) notify(e.message, false);
    }
  }

  function closeDetail() {
    detail = null;
  }

  async function copyText(text: string) {
    try {
      await navigator.clipboard.writeText(text);
      notify('Copied to clipboard');
    } catch {
      notify('Copy failed', false);
    }
  }

  function downloadText(filename: string, text: string) {
    const blob = new Blob([text], { type: 'application/x-pem-file' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  }

  function fmtDate(s?: string): string {
    return s ? s.replace('T', ' ').replace('Z', '') : '—';
  }

  onMount(load);
</script>

<div class="ph">
  <h1 class="ph-title">Certificate Authority</h1>
  <p class="ph-sub">Manage your private CA hierarchy, issue and revoke certificates, and publish revocation lists.</p>
</div>

{#if flash}
  <div class="flash {flashOk ? 'ok' : 'err'}">{flash}</div>
{/if}

<div class="card">
  <h3 style="margin-top:0">Certificate authorities</h3>
  {#if loading}
    <div class="empty">Loading…</div>
  {:else if caGroups.length === 0}
    <div class="empty">No certificate authorities yet. Create one below to start issuing certificates.</div>
  {:else}
    <div class="ca-list">
      {#each caGroups as g}
        <div class="ca-node">
          <div class="ca-head">
            <button class="ca-toggle" onclick={() => toggleCA(g.ca.id)} aria-label="Toggle issued certificates">
              <span class="caret" class:open={expanded[g.ca.id]}>▸</span>
            </button>
            <div class="ca-main">
              <button class="linklike ca-name" onclick={() => openDetail(g.ca)}>{g.ca.subject || g.ca.id}</button>
              <div class="ca-meta">
                <span class="badge">{fmtType(g.ca.caType)}</span>
                <span class="badge">{g.ca.status || '—'}</span>
                <span class="muted small">{g.issued.length} issued</span>
                {#if g.ca.notAfter}
                  <span class="muted small">expires {new Date(g.ca.notAfter).toLocaleDateString()}</span>
                {/if}
              </div>
            </div>
            <div class="ca-act">
              <a class="btn btn-sm" href={api.crlUrl(g.ca.id)} target="_blank" rel="noopener" download>Download CRL</a>
            </div>
          </div>
          {#if expanded[g.ca.id]}
            <div class="ca-children">
              {#if g.issued.length === 0}
                <div class="empty small">No certificates issued by this CA.</div>
              {:else}
                <table>
                  <thead>
                    <tr>
                      <th>Certificate</th>
                      <th>Serial</th>
                      <th>Status</th>
                      <th>Not after</th>
                      <th></th>
                    </tr>
                  </thead>
                  <tbody>
                    {#each g.issued as c}
                      <tr class:rowsel={detail?.id === c.id}>
                        <td class="mono">
                          <button class="linklike" onclick={() => openDetail(c)}>{c.id}</button>
                        </td>
                        <td class="mono small">{c.subject || '—'}</td>
                        <td><span class="badge">{c.status || '—'}</span></td>
                        <td class="muted">{c.notAfter ? new Date(c.notAfter).toLocaleDateString() : '—'}</td>
                        <td>
                          {#if c.status !== 'REVOKED'}
                            <button class="btn btn-sm btn-d" onclick={() => askRevoke(c)}>Revoke</button>
                          {/if}
                        </td>
                      </tr>
                    {/each}
                  </tbody>
                </table>
              {/if}
            </div>
          {/if}
        </div>
      {/each}
    </div>
  {/if}
</div>

{#if orphanCerts.length > 0}
  <div class="card" style="margin-top:1.25rem">
    <h3 style="margin-top:0">Issued certificates (CA unavailable)</h3>
    <table>
      <thead>
        <tr>
          <th>Certificate</th>
          <th>Serial</th>
          <th>Status</th>
          <th>Not after</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        {#each orphanCerts as c}
          <tr class:rowsel={detail?.id === c.id}>
            <td class="mono"><button class="linklike" onclick={() => openDetail(c)}>{c.id}</button></td>
            <td class="mono small">{c.subject || '—'}</td>
            <td><span class="badge">{c.status || '—'}</span></td>
            <td class="muted">{c.notAfter ? new Date(c.notAfter).toLocaleDateString() : '—'}</td>
            <td>
              {#if c.status !== 'REVOKED'}
                <button class="btn btn-sm btn-d" onclick={() => askRevoke(c)}>Revoke</button>
              {/if}
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
{/if}

{#if otherCerts.length > 0}
  <div class="card" style="margin-top:1.25rem">
    <h3 style="margin-top:0">ACME / Let's Encrypt certificates</h3>
    <table>
      <thead>
        <tr>
          <th>ID</th>
          <th>Subject</th>
          <th>Status</th>
          <th>Not after</th>
        </tr>
      </thead>
      <tbody>
        {#each otherCerts as c}
          <tr class:rowsel={detail?.id === c.id}>
            <td class="mono"><button class="linklike" onclick={() => openDetail(c)}>{c.id}</button></td>
            <td>{c.subject || '—'}</td>
            <td><span class="badge">{c.status || '—'}</span></td>
            <td class="muted">{c.notAfter ? new Date(c.notAfter).toLocaleDateString() : '—'}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
{/if}

<div class="card" style="margin-top:1.25rem">
  <h3 style="margin-top:0">Create private CA</h3>
  <div class="toolbar">
    <div class="field" style="flex:1">
      <label for="cn">Common name</label>
      <input id="cn" placeholder="Example Root CA" bind:value={caCommonName} />
    </div>
    <div class="field">
      <label for="org">Organization</label>
      <input id="org" placeholder="Example Inc" bind:value={caOrg} />
    </div>
    <div class="field" style="width:5rem">
      <label for="cc">Country</label>
      <input id="cc" placeholder="US" bind:value={caCountry} />
    </div>
  </div>
  <div class="toolbar" style="margin-bottom:0">
    <div class="field">
      <label for="ct">Type</label>
      <select id="ct" bind:value={caType}>
        <option value="ROOT">ROOT</option>
        <option value="SUBORDINATE">SUBORDINATE</option>
      </select>
    </div>
    <div class="field">
      <label for="ka">Key algorithm</label>
      <select id="ka" bind:value={caKeyAlg}>
        <option value="RSA_2048">RSA_2048</option>
        <option value="RSA_3072">RSA_3072</option>
        <option value="RSA_4096">RSA_4096</option>
        <option value="EC_prime256v1">EC_prime256v1</option>
        <option value="EC_secp384r1">EC_secp384r1</option>
      </select>
    </div>
    <div class="field" style="align-self:flex-end">
      <button class="btn btn-p" onclick={createCA} disabled={creatingCA}>
        {creatingCA ? 'Creating…' : 'Create CA'}
      </button>
    </div>
  </div>
</div>

<div class="card" style="margin-top:1.25rem">
  <h3 style="margin-top:0">Issue certificate</h3>
  <div class="toolbar">
    <div class="field" style="flex:1">
      <label for="ica">Issuing CA</label>
      <select id="ica" bind:value={issueCaArn}>
        <option value="">(select a CA)</option>
        {#each cas as ca}
          <option value={ca.id}>{ca.subject}</option>
        {/each}
      </select>
    </div>
    <div class="field" style="width:8rem">
      <label for="vd">Validity (days)</label>
      <input id="vd" bind:value={validityDays} />
    </div>
  </div>
  <div class="field" style="margin-bottom:0.75rem">
    <label for="csr">CSR (PEM)</label>
    <textarea id="csr" class="mono" rows="6" placeholder="-----BEGIN CERTIFICATE REQUEST-----" bind:value={csrPem}></textarea>
  </div>
  <div class="toolbar" style="margin-bottom:0">
    <div class="field" style="flex:1">
      <label for="san">SAN names (optional, comma/space separated)</label>
      <input id="san" placeholder="example.com www.example.com" bind:value={sanNames} />
    </div>
    <div class="field" style="align-self:flex-end">
      <button class="btn btn-p" onclick={issueCert} disabled={issuing}>
        {issuing ? 'Issuing…' : 'Issue certificate'}
      </button>
    </div>
  </div>
</div>

<!-- revoke confirmation modal -->
{#if confirmCert}
  <div
    class="modal-scrim"
    role="button"
    tabindex="0"
    aria-label="Cancel"
    onclick={() => (confirmCert = null)}
    onkeydown={(e) => e.key === 'Escape' && (confirmCert = null)}
  ></div>
  <div class="modal" role="dialog" aria-modal="true" aria-label="Revoke certificate">
    <h3 style="margin-top:0">Revoke certificate</h3>
    <p class="muted small">
      This permanently revokes <span class="mono">{confirmCert.id}</span> and adds it to the CA's revocation list. This cannot be undone.
    </p>
    <div class="field" style="margin-bottom:1rem">
      <label for="rr">Revocation reason</label>
      <select id="rr" bind:value={confirmReason}>
        {#each revokeReasons as r}
          <option value={r}>{r}</option>
        {/each}
      </select>
    </div>
    <div class="row-act" style="justify-content:flex-end">
      <button class="btn btn-sm" onclick={() => (confirmCert = null)} disabled={revoking}>Cancel</button>
      <button class="btn btn-sm btn-d" onclick={confirmRevoke} disabled={revoking}>
        {revoking ? 'Revoking…' : 'Revoke'}
      </button>
    </div>
  </div>
{/if}

<!-- detail drawer -->
{#if detail}
  <div
    class="drawer-scrim"
    role="button"
    tabindex="0"
    aria-label="Close details"
    onclick={closeDetail}
    onkeydown={(e) => e.key === 'Escape' && closeDetail()}
  ></div>
  <aside class="drawer">
    <div class="drawer-head">
      <div>
        <div class="mono drawer-title">{detail.subject || detail.id}</div>
        <div class="muted small">{sourceLabel[detail.source] ?? detail.source}</div>
      </div>
      <button class="btn btn-sm" onclick={closeDetail}>✕</button>
    </div>

    <div class="tabs">
      <button class="tab" class:active={detailTab === 'overview'} onclick={() => (detailTab = 'overview')}
        >Overview</button
      >
      {#if detail.pem}
        <button class="tab" class:active={detailTab === 'pem'} onclick={() => (detailTab = 'pem')}
          >PEM</button
        >
      {/if}
      {#if detail.chainPem}
        <button class="tab" class:active={detailTab === 'chain'} onclick={() => (detailTab = 'chain')}
          >Chain</button
        >
      {/if}
    </div>

    {#if detailTab === 'overview'}
      <div class="tab-body">
        <div class="kv">
          <div class="kv-row"><span class="kv-l">ID</span><span class="kv-v mono small">{detail.id}</span></div>
          <div class="kv-row">
            <span class="kv-l">Status</span>
            <span class="kv-v"><span class="badge">{detail.status || '—'}</span></span>
          </div>
          <div class="kv-row"><span class="kv-l">Subject</span><span class="kv-v small">{detail.subject || '—'}</span></div>
          <div class="kv-row"><span class="kv-l">Issuer</span><span class="kv-v small">{detail.issuer || '—'}</span></div>
          <div class="kv-row"><span class="kv-l">Serial</span><span class="kv-v mono small">{detail.serial || '—'}</span></div>
          <div class="kv-row"><span class="kv-l">Not before</span><span class="kv-v small">{fmtDate(detail.notBefore)}</span></div>
          <div class="kv-row"><span class="kv-l">Not after</span><span class="kv-v small">{fmtDate(detail.notAfter)}</span></div>
          {#if detail.keyAlgorithm}
            <div class="kv-row"><span class="kv-l">Key alg</span><span class="kv-v small">{detail.keyAlgorithm}</span></div>
          {/if}
          {#if detail.signatureAlgorithm}
            <div class="kv-row"><span class="kv-l">Sig alg</span><span class="kv-v small">{detail.signatureAlgorithm}</span></div>
          {/if}
          <div class="kv-row"><span class="kv-l">CA</span><span class="kv-v small">{detail.isCA ? 'yes' : 'no'}</span></div>
          {#if detail.caType}
            <div class="kv-row"><span class="kv-l">CA type</span><span class="kv-v small">{detail.caType}</span></div>
          {/if}
          {#if detail.template}
            <div class="kv-row"><span class="kv-l">Template</span><span class="kv-v small">{detail.template}</span></div>
          {/if}
          {#if detail.kmsKeyId}
            <div class="kv-row"><span class="kv-l">KMS key</span><span class="kv-v mono small">{detail.kmsKeyId}</span></div>
          {/if}
          {#if detail.domains}
            <div class="kv-row"><span class="kv-l">Domains</span><span class="kv-v small">{detail.domains}</span></div>
          {/if}
          {#if detail.sans && detail.sans.length}
            <div class="kv-row"><span class="kv-l">SANs</span><span class="kv-v small">{detail.sans.join(', ')}</span></div>
          {/if}
          {#if detail.revokedAt}
            <div class="kv-row"><span class="kv-l">Revoked</span><span class="kv-v small">{fmtDate(detail.revokedAt)}</span></div>
          {/if}
          {#if detail.revocationReason}
            <div class="kv-row"><span class="kv-l">Reason</span><span class="kv-v small">{detail.revocationReason}</span></div>
          {/if}
        </div>
      </div>
    {:else if detailTab === 'pem' && detail.pem}
      <div class="tab-body">
        <pre class="pem">{detail.pem}</pre>
        <div class="row-act">
          <button class="btn btn-sm" onclick={() => copyText(detail!.pem!)}>Copy</button>
          <button class="btn btn-sm" onclick={() => downloadText(`${detail!.id}.pem`, detail!.pem!)}
            >Download .pem</button
          >
        </div>
      </div>
    {:else if detailTab === 'chain' && detail.chainPem}
      <div class="tab-body">
        <pre class="pem">{detail.chainPem}</pre>
        <div class="row-act">
          <button class="btn btn-sm" onclick={() => copyText(detail!.chainPem!)}>Copy</button>
          <button
            class="btn btn-sm"
            onclick={() => downloadText(`${detail!.id}-chain.pem`, detail!.chainPem!)}
            >Download chain</button
          >
        </div>
      </div>
    {/if}
  </aside>
{/if}

<style>
  textarea {
    width: 100%;
    box-sizing: border-box;
    resize: vertical;
  }
  .linklike {
    background: none;
    border: none;
    padding: 0;
    color: var(--c-blue);
    cursor: pointer;
    font: inherit;
  }
  .rowsel {
    background: rgba(43, 108, 176, 0.06);
  }
  .small {
    font-size: 0.82rem;
  }
  .drawer-scrim {
    position: fixed;
    inset: 0;
    background: rgba(15, 20, 30, 0.35);
    z-index: 40;
    border: none;
  }
  .drawer {
    position: fixed;
    top: 0;
    right: 0;
    height: 100vh;
    width: min(560px, 92vw);
    background: var(--c-surface);
    border-left: 1px solid var(--c-border);
    box-shadow: -8px 0 24px rgba(15, 20, 30, 0.12);
    z-index: 41;
    padding: 1.25rem;
    overflow-y: auto;
  }
  .drawer-head {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    margin-bottom: 1rem;
  }
  .drawer-title {
    font-size: 1.1rem;
    font-weight: 700;
  }
  .kv {
    border: 1px solid var(--c-border);
    border-radius: var(--radius);
    padding: 0.5rem 0.75rem;
  }
  .kv-row {
    display: flex;
    gap: 0.75rem;
    padding: 0.3rem 0;
    border-bottom: 1px solid var(--c-border);
  }
  .kv-row:last-child {
    border-bottom: none;
  }
  .kv-l {
    width: 110px;
    color: var(--c-muted);
    font-size: 0.78rem;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    flex-shrink: 0;
  }
  .kv-v {
    word-break: break-all;
    flex: 1;
  }
  .tabs {
    display: flex;
    gap: 0.25rem;
    border-bottom: 1px solid var(--c-border);
    margin: 1rem 0 0.75rem;
    flex-wrap: wrap;
  }
  .tab {
    background: none;
    border: none;
    border-bottom: 2px solid transparent;
    padding: 0.5rem 0.7rem;
    cursor: pointer;
    color: var(--c-muted);
    font: inherit;
  }
  .tab.active {
    color: var(--c-text);
    border-bottom-color: var(--c-blue);
    font-weight: 600;
  }
  .tab-body {
    padding-top: 0.25rem;
  }
  .row-act {
    display: flex;
    gap: 0.5rem;
    flex-wrap: wrap;
  }
  .pem {
    background: var(--c-surface);
    border: 1px solid var(--c-border);
    border-radius: var(--radius);
    padding: 0.6rem;
    font-size: 0.74rem;
    white-space: pre-wrap;
    word-break: break-all;
    max-height: 360px;
    overflow-y: auto;
    margin: 0 0 0.6rem;
  }
  .ca-list {
    display: flex;
    flex-direction: column;
    gap: 0.6rem;
  }
  .ca-node {
    border: 1px solid var(--c-border);
    border-radius: var(--radius);
    overflow: hidden;
  }
  .ca-head {
    display: flex;
    align-items: center;
    gap: 0.6rem;
    padding: 0.6rem 0.75rem;
  }
  .ca-toggle {
    background: none;
    border: none;
    cursor: pointer;
    padding: 0;
    color: var(--c-muted);
    flex-shrink: 0;
  }
  .caret {
    display: inline-block;
    transition: transform 0.12s ease;
  }
  .caret.open {
    transform: rotate(90deg);
  }
  .ca-main {
    flex: 1;
    min-width: 0;
  }
  .ca-name {
    font-weight: 600;
    display: block;
    margin-bottom: 0.2rem;
  }
  .ca-meta {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    flex-wrap: wrap;
  }
  .ca-act {
    flex-shrink: 0;
  }
  .ca-children {
    border-top: 1px solid var(--c-border);
    padding: 0.5rem 0.75rem;
    background: rgba(43, 108, 176, 0.03);
  }
  .modal-scrim {
    position: fixed;
    inset: 0;
    background: rgba(15, 20, 30, 0.35);
    z-index: 50;
    border: none;
  }
  .modal {
    position: fixed;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    width: min(440px, 92vw);
    background: var(--c-surface);
    border: 1px solid var(--c-border);
    border-radius: var(--radius);
    box-shadow: 0 12px 32px rgba(15, 20, 30, 0.18);
    z-index: 51;
    padding: 1.25rem;
  }
</style>
