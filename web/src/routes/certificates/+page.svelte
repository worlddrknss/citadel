<script lang="ts">
  import { onMount } from 'svelte';
  import PageHeader from '$lib/components/PageHeader.svelte';
  import Tabs from '$lib/components/Tabs.svelte';
  import Icon from '$lib/components/Icon.svelte';
  import { errorMessage } from '$lib/api';
  import { api } from '$lib/api';
  import { session } from '$lib/stores/session.svelte';
  import { param, setParams } from '$lib/url';
  import { certApi, type CertRow } from './api';
  import { cnOf, firstDomain, rowKey, safeFileName, type Filter, type SortKey } from './certs';
  import CATree from './CATree.svelte';
  import CertTable from './CertTable.svelte';
  import CertDrawer from './CertDrawer.svelte';
  import IssueWizard, { type IssueResult } from './IssueWizard.svelte';
  import RevokeModal from './RevokeModal.svelte';
  import RenewModal from './RenewModal.svelte';
  import CreateCAModal from './CreateCAModal.svelte';
  import ImportCAModal from './ImportCAModal.svelte';
  import LetsEncryptPanel from './LetsEncryptPanel.svelte';
  import AcmeServerPanel from './AcmeServerPanel.svelte';
  import OnceSecret from './OnceSecret.svelte';

  // ---- data ----------------------------------------------------------------
  let rows = $state<CertRow[]>([]);
  let loading = $state(true);
  let loadError = $state('');
  /** CN / serial / revocation date filled from the detail endpoint while the
   *  list endpoint doesn't return them for issued certificates. */
  let extra = $state<Record<string, { commonName?: string; serial?: string; revokedAt?: string }>>({});
  let le = $state<{ environment: string; directoryUrl: string; contactEmail: string } | null>(null);
  let leError = $state('');

  let generation = 0;
  async function load() {
    const gen = ++generation;
    loading = true;
    loadError = '';
    try {
      const r = await certApi.list();
      if (gen !== generation) return;
      rows = r.certificates ?? [];
      enrich(gen);
    } catch (e) {
      if (gen === generation) loadError = errorMessage(e, 'Could not load certificates.');
    } finally {
      if (gen === generation) loading = false;
    }
  }

  async function enrich(gen: number) {
    const todo = rows.filter((c) => c.source === 'pca-cert' && !c.commonName && !extra[rowKey(c)]);
    let i = 0;
    const worker = async () => {
      while (i < todo.length && gen === generation) {
        const c = todo[i++];
        try {
          const d = await certApi.detail(c.source, c.id);
          if (gen !== generation) return;
          extra[rowKey(c)] = { commonName: cnOf(d.subject) || d.sans?.[0], serial: d.serial, revokedAt: d.revokedAt };
        } catch {
          /* the row keeps showing its serial */
        }
      }
    };
    await Promise.all([worker(), worker(), worker(), worker()]);
  }

  async function loadLE() {
    leError = '';
    try {
      le = await api.letsEncryptSettings();
    } catch (e) {
      leError = errorMessage(e, "Could not load Let's Encrypt settings.");
    }
  }

  onMount(() => {
    load();
    loadLE();
  });

  // ---- derived -------------------------------------------------------------
  const merged = $derived(rows.map((c) => ({ ...c, ...(extra[rowKey(c)] ?? {}), ...pick(c) })));
  function pick(c: CertRow) {
    // Fields the server sent win over enrichment.
    const o: Partial<CertRow> = {};
    if (c.commonName) o.commonName = c.commonName;
    if (c.revokedAt) o.revokedAt = c.revokedAt;
    return o;
  }
  const cas = $derived(merged.filter((c) => c.source === 'pca-ca'));
  const leaves = $derived(merged.filter((c) => c.source !== 'pca-ca'));

  function caName(id?: string): string {
    if (!id) return '';
    const ca = cas.find((c) => c.id === id);
    return ca ? cnOf(ca.subject) || ca.id : id;
  }
  function nameOf(c: CertRow): string {
    if (c.source === 'pca-ca') return cnOf(c.subject) || c.id;
    if (c.source === 'lets-encrypt') return firstDomain(c.subject) || c.id;
    if (c.commonName) return c.commonName;
    const serial = c.serial || c.subject;
    return serial ? `serial ${serial.length > 16 ? serial.slice(0, 16) + '…' : serial}` : c.id;
  }
  function issuerOf(c: CertRow): string {
    return c.source === 'lets-encrypt' ? "Let's Encrypt" : caName(c.issuerCaId) || '—';
  }

  // ---- URL state -----------------------------------------------------------
  const tab = $derived(param('tab', 'overview'));
  const filter = $derived(param('filter', 'all') as Filter);
  const sort = $derived(param('sort', 'left') as SortKey);
  const dir = $derived(param('dir', 'asc') as 'asc' | 'desc');
  const selectedKey = $derived(param('cert'));
  const drawerTab = $derived(param('view', 'overview'));
  const selected = $derived(merged.find((c) => rowKey(c) === selectedKey) ?? null);

  let tabValue = $state('overview');
  $effect(() => {
    tabValue = tab;
  });

  let drawerOpen = $state(false);
  $effect(() => {
    drawerOpen = !!selectedKey && (!!selected || loading);
  });

  function openCert(c: CertRow) {
    setParams({ cert: rowKey(c), view: null }, { push: true });
  }
  function closeDrawer() {
    setParams({ cert: null, view: null });
  }

  // ---- roles ---------------------------------------------------------------
  const canIssue = $derived(session.can('editor'));
  const canAdmin = $derived(session.can('admin'));

  // ---- dialogs -------------------------------------------------------------
  let issueOpen = $state(false);
  let issueCa = $state('');
  let caOpen = $state(false);
  let caParent = $state('');
  let importOpen = $state(false);
  let revokeOpen = $state(false);
  let renewOpen = $state(false);
  let target = $state<CertRow | null>(null);
  let generated = $state<NonNullable<IssueResult['generated']> | null>(null);
  let generatedOpen = $state(false);
  let afterGenerated: string | undefined;

  function issue(caId = '') {
    issueCa = caId;
    issueOpen = true;
  }
  function newCA(parent = '') {
    caParent = parent;
    caOpen = true;
  }
  function askRevoke(c: CertRow) {
    target = c;
    revokeOpen = true;
  }
  function askRenew(c: CertRow) {
    target = c;
    renewOpen = true;
  }

  async function issued(r: IssueResult) {
    await load();
    if (r.generated) {
      generated = r.generated;
      generatedOpen = true;
      afterGenerated = r.certId;
    } else if (r.certId) {
      setParams({ cert: `pca-cert:${r.certId}`, tab: null }, { push: true });
    }
  }
  function generatedDone() {
    generated = null;
    if (afterGenerated) setParams({ cert: `pca-cert:${afterGenerated}`, tab: null }, { push: true });
    afterGenerated = undefined;
  }
</script>

<PageHeader title="Certificates" description="Private CA hierarchy and public certificates from Let's Encrypt, in one place.">
  {#snippet actions()}
    {#if canAdmin}
      <button type="button" class="btn btn-secondary" onclick={() => (importOpen = true)}><Icon name="upload" size={16} />Import</button>
    {/if}
    {#if canIssue}
      <button type="button" class="btn btn-primary" onclick={() => issue()}><Icon name="plus" size={16} />Issue certificate</button>
    {/if}
  {/snippet}
</PageHeader>

<div class="tabs-row">
  <Tabs
    label="Certificate sections"
    tabs={[
      { id: 'overview', label: 'Overview' },
      { id: 'letsencrypt', label: "Let's Encrypt" },
      { id: 'acme', label: 'ACME server' }
    ]}
    bind:active={tabValue}
    onchange={(t) => setParams({ tab: t === 'overview' ? null : t })}
  />
</div>

{#if loadError && tab === 'overview'}
  <div class="callout callout-danger err" role="alert">
    <Icon name="alert-circle" size={16} />
    <span>{loadError}</span>
    <button type="button" class="btn btn-ghost btn-sm push" onclick={load}>Retry</button>
  </div>
{/if}

{#if tab === 'letsencrypt'}
  <LetsEncryptPanel
    settings={le}
    settingsError={leError}
    canRequest={canIssue}
    canConfigure={canAdmin}
    onsaved={loadLE}
    onissued={async (id) => {
      await load();
      if (id) setParams({ tab: null, cert: `lets-encrypt:${id}` }, { push: true });
    }}
  />
{:else if tab === 'acme'}
  <AcmeServerPanel
    accountId={session.me?.accountId ?? ''}
    canManage={canAdmin}
    cas={cas.map((c) => ({ id: c.id, name: nameOf(c), status: c.status }))}
  />
{:else}
  <div class="layout">
    <CATree
      {cas}
      {loading}
      selected={selectedKey}
      canCreate={canAdmin}
      le={le ? { environment: le.environment, contactEmail: le.contactEmail } : null}
      onselect={openCert}
      onnew={() => newCA()}
      onle={() => setParams({ tab: 'letsencrypt' })}
    />
    <CertTable
      rows={leaves}
      {loading}
      {filter}
      {sort}
      {dir}
      selected={selectedKey}
      {nameOf}
      {issuerOf}
      {canIssue}
      canRevoke={canAdmin}
      onfilter={(f) => setParams({ filter: f === 'all' ? null : f })}
      onsort={(k, d) => setParams({ sort: k === 'left' ? null : k, dir: d === 'asc' ? null : d })}
      onopen={openCert}
      onrenew={askRenew}
      onrevoke={askRevoke}
      onissue={() => issue()}
    />
  </div>
{/if}

<CertDrawer
  bind:open={drawerOpen}
  row={selected}
  tab={drawerTab}
  {caName}
  {canIssue}
  {canAdmin}
  ontab={(t) => setParams({ view: t === 'overview' ? null : t })}
  onclose={closeDrawer}
  onrenew={askRenew}
  onrevoke={askRevoke}
  onissuefrom={(ca) => issue(ca.id)}
  onsubordinate={(ca) => newCA(ca.id)}
/>

<IssueWizard bind:open={issueOpen} {cas} initialCaId={issueCa} oncomplete={issued} />
<CreateCAModal bind:open={caOpen} {cas} initialParent={caParent} oncreated={(id) => load().then(() => setParams({ cert: `pca-ca:${id}`, tab: null }))} />
<ImportCAModal bind:open={importOpen} onimported={(id) => load().then(() => setParams({ cert: `pca-ca:${id}`, tab: null }))} />
<RevokeModal bind:open={revokeOpen} cert={target} name={target ? nameOf(target) : ''} ondone={load} />
<RenewModal bind:open={renewOpen} cert={target} name={target ? nameOf(target) : ''} ondone={load} />

{#if generated}
  <OnceSecret
    bind:open={generatedOpen}
    title="Certificate issued"
    description="Citadel generated the key pair for {generated.commonName}. The private key isn't stored; download it now."
    fields={[
      { label: 'Private key', value: generated.privateKeyPem, multiline: true, secret: true, filename: `${safeFileName(generated.commonName)}.key` },
      { label: 'Certificate', value: generated.certificatePem, multiline: true, filename: `${safeFileName(generated.commonName)}.pem` },
      ...(generated.chainPem
        ? [{ label: 'Issuer chain', value: generated.chainPem, multiline: true, filename: `${safeFileName(generated.commonName)}-chain.pem` }]
        : [])
    ]}
    ondone={generatedDone}
  />
{/if}

<style>
  .tabs-row {
    margin: calc(-1 * var(--space-2)) 0 var(--space-5);
  }
  .layout {
    display: flex;
    gap: 20px;
    flex-wrap: wrap;
    align-items: flex-start;
  }
  .err {
    margin-bottom: var(--space-4);
    align-items: center;
  }
  .push {
    margin-left: auto;
  }
</style>
