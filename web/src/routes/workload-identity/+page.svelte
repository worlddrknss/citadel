<script lang="ts">
  import { onMount } from 'svelte';
  import PageHeader from '$lib/components/PageHeader.svelte';
  import Tabs from '$lib/components/Tabs.svelte';
  import DataTable, { type Column } from '$lib/components/DataTable.svelte';
  import EmptyState from '$lib/components/EmptyState.svelte';
  import Badge from '$lib/components/Badge.svelte';
  import CopyButton from '$lib/components/CopyButton.svelte';
  import Modal from '$lib/components/Modal.svelte';
  import Icon from '$lib/components/Icon.svelte';
  import { errorMessage, type AuditEvent } from '$lib/api';
  import { session } from '$lib/stores/session.svelte';
  import { toast } from '$lib/stores/toast.svelte';
  import { confirm } from '$lib/stores/confirm.svelte';
  import { param, setParams } from '$lib/url';
  import Seg from './Seg.svelte';
  import ClientEditor from './ClientEditor.svelte';
  import ClientDrawer from './ClientDrawer.svelte';
  import { wiApi, ALGS, issued, ttlLabel, fmtDate, fmtDateTime, type IssuerInfo, type SigningAlg, type WorkloadClient } from './api';

  // Clients are per account (account admins); the issuer and its signing
  // key are shared by the whole organization (platform admins only).
  const canEdit = $derived(session.can('admin'));
  const canManageIssuer = $derived(session.platformAdmin);
  const origin = typeof location !== 'undefined' ? location.origin : '';

  // ---- issuer --------------------------------------------------------------
  let info = $state<IssuerInfo | null>(null);
  let infoError = $state('');
  async function loadIssuer() {
    infoError = '';
    try {
      info = await wiApi.issuer();
    } catch (e) {
      infoError = errorMessage(e, 'Could not load the issuer configuration.');
    }
  }
  // Empty until the server answers; empty for good when KMS_PUBLIC_URL is unset.
  const configured = $derived(info?.configured ?? true);
  const urls = $derived(
    info?.configured
      ? [
          { l: 'Issuer URL', v: info.issuer, h: 'The iss claim. Register this URL as an OIDC provider wherever tokens are verified.' },
          { l: 'Discovery document', v: info.discoveryUrl, h: '' },
          { l: 'JWKS', v: info.jwksUrl, h: 'Public keys verifiers use to check token signatures.' },
          { l: 'Token endpoint', v: info.tokenEndpoint, h: 'Workloads POST {clientId, audience} here and get {token, expiresAt, tokenType: "id_token"}.' }
        ]
      : []
  );

  let rotating = $state(false);
  async function rotate() {
    const ok = await confirm({
      title: 'Rotate the signing key now?',
      message: 'Citadel creates a new KMS key and signs new tokens with it. The current key stays in the JWKS until every token it signed has expired, so verifiers keep working.',
      confirmLabel: 'Rotate key'
    });
    if (!ok) return;
    rotating = true;
    try {
      info = await wiApi.rotate();
      toast.success('Signing key rotated');
    } catch (e) {
      toast.error(e, 'Could not rotate the key');
    } finally {
      rotating = false;
    }
  }

  let settingsOpen = $state(false);
  let alg = $state<SigningAlg>('ES256');
  let rotationDays = $state(90);
  let savingSettings = $state(false);
  function openSettings() {
    alg = info?.algorithm ?? info?.signingKey?.algorithm ?? 'ES256';
    rotationDays = info?.rotationDays ?? 90;
    settingsOpen = true;
  }
  const rotationError = $derived(!Number.isInteger(rotationDays) || rotationDays < 7 || rotationDays > 365 ? 'Between 7 and 365 days.' : '');
  async function saveSettings(e: SubmitEvent) {
    e.preventDefault();
    if (rotationError) return;
    savingSettings = true;
    try {
      info = await wiApi.saveIssuerSettings({ algorithm: alg, rotationDays });
      toast.success('Signing settings saved');
      settingsOpen = false;
    } catch (err) {
      toast.error(err, 'Could not save signing settings');
    } finally {
      savingSettings = false;
    }
  }

  // ---- clients -------------------------------------------------------------
  let clients = $state<WorkloadClient[]>([]);
  let clientsLoading = $state(true);
  let clientsError = $state('');
  async function loadClients() {
    clientsLoading = true;
    clientsError = '';
    try {
      clients = (await wiApi.clients()).clients ?? [];
    } catch (e) {
      clientsError = errorMessage(e, 'Could not load workload clients.');
    } finally {
      clientsLoading = false;
    }
  }

  // ---- audit ---------------------------------------------------------------
  let events = $state<AuditEvent[]>([]);
  let eventsLoading = $state(false);
  let eventsError = $state('');
  let eventsLoaded = false;
  async function loadEvents() {
    eventsLoading = true;
    eventsLoaded = true;
    eventsError = '';
    try {
      events = await wiApi.tokenEvents();
    } catch (e) {
      eventsError = errorMessage(e, 'Could not load the audit log.');
    } finally {
      eventsLoading = false;
    }
  }

  onMount(() => {
    loadIssuer();
    loadClients();
  });

  // ---- URL state -----------------------------------------------------------
  const tab = $derived(param('tab', 'clients'));
  const selectedId = $derived(param('client'));
  const auditClient = $derived(param('auditClient'));
  const auditResult = $derived(param('result', 'all') as 'all' | 'ok' | 'error');
  const selected = $derived(clients.find((c) => c.clientId === selectedId) ?? null);
  let tabValue = $state('clients');
  $effect(() => {
    tabValue = tab;
  });
  $effect(() => {
    if (tab === 'audit' && !eventsLoaded && !eventsLoading) loadEvents();
  });
  let drawerOpen = $state(false);
  $effect(() => {
    drawerOpen = !!selected;
  });
  let resultValue = $state<'all' | 'ok' | 'error'>('all');
  $effect(() => {
    resultValue = auditResult;
  });

  const clientName = (id?: string) => clients.find((c) => c.clientId === id)?.name ?? id ?? '—';
  const filteredEvents = $derived(
    events.filter(
      (e) => (!auditClient || e.keyId === auditClient) && (auditResult === 'all' || (auditResult === 'ok' ? issued(e) : !issued(e)))
    )
  );

  // ---- client dialogs ------------------------------------------------------
  let editorOpen = $state(false);
  let editing = $state<WorkloadClient | null>(null);
  function newClient() {
    editing = null;
    editorOpen = true;
  }
  function editClient(c: WorkloadClient) {
    editing = c;
    editorOpen = true;
  }
  async function deleteClient(c: WorkloadClient) {
    const ok = await confirm({
      title: `Delete ${c.name}?`,
      message: 'Workloads using this client can no longer get tokens. Tokens already issued stay valid until they expire.',
      confirmLabel: 'Delete client',
      danger: true,
      typeToConfirm: c.name
    });
    if (!ok) return;
    try {
      await wiApi.deleteClient(c.clientId);
      toast.success(`Deleted ${c.name}`);
      if (selectedId === c.clientId) setParams({ client: null });
      loadClients();
    } catch (e) {
      toast.error(e, 'Could not delete the client');
    }
  }

  let query = $state('');
  const cols: Column<WorkloadClient>[] = [
    { id: 'name', label: 'Client', sort: (c) => c.name },
    { id: 'auth', label: 'Authenticates with', sort: (c) => c.auth.method },
    { id: 'aud', label: 'Audiences', hideOnMobile: true },
    { id: 'ttl', label: 'Token TTL', sort: (c) => c.tokenTtlSeconds, hideOnMobile: true },
    { id: 'last', label: 'Last token', sort: (c) => c.lastIssuedAt ?? '', hideOnMobile: true },
    { id: 'act', label: '', align: 'end', width: '96px' }
  ];
  const auditCols: Column<AuditEvent>[] = [
    { id: 'time', label: 'Time', sort: (e) => e.createdAt },
    { id: 'client', label: 'Client', sort: (e) => clientName(e.keyId) },
    { id: 'actor', label: 'Caller', sort: (e) => e.actor },
    { id: 'result', label: 'Result', sort: (e) => e.result }
  ];
</script>

<PageHeader
  title="Workload identity"
  description="Citadel as an OIDC issuer for machines. CI jobs, pods and services get short-lived ID tokens signed by a Citadel KMS key, and trade them for cloud credentials."
>
  {#snippet actions()}
    {#if canEdit}
      <button type="button" class="btn btn-primary" onclick={newClient}><Icon name="plus" size={16} />New client</button>
    {/if}
  {/snippet}
</PageHeader>

<div class="top">
  <section class="card" aria-labelledby="iss-title">
    <div class="card-head">
      <h2 id="iss-title">Issuer</h2>
      {#if info}
        {#if info.configured}<Badge tone="success" dot={false}>Configured</Badge>{:else}<Badge tone="warning" dot={false}>Not configured</Badge>{/if}
      {/if}
    </div>
    <div class="card-pad urls">
      {#if !configured}
        <div class="callout callout-warning" role="status">
          <Icon name="alert-triangle" size={16} />
          <span>The issuer needs the server's public URL. Set <code class="mono">KMS_PUBLIC_URL</code> and restart Citadel; until then no workload tokens are issued.</span>
        </div>
      {:else if !info}
        <div class="sk" aria-busy="true"><span class="skeleton"></span><span class="skeleton"></span><span class="skeleton"></span></div>
      {/if}
      {#each urls as u (u.l)}
        <div class="field">
          <span class="field-label">{u.l}</span>
          <div class="urlbox">
            <code class="mono">{u.v}</code>
            <CopyButton value={u.v} label="Copy {u.l}" />
            <a class="btn-icon" href={u.v} target="_blank" rel="noopener" aria-label="Open {u.l}" title="Open"><Icon name="external-link" size={14} /></a>
          </div>
          {#if u.h}<span class="field-hint">{u.h}</span>{/if}
        </div>
      {/each}
    </div>
  </section>

  <section class="card" aria-labelledby="key-title">
    <div class="card-head">
      <h2 id="key-title">Signing key</h2>
      {#if canManageIssuer && info?.configured}
        <span class="head-actions">
          <button type="button" class="btn btn-ghost btn-sm" onclick={openSettings}><Icon name="settings" size={14} />Settings</button>
          <button type="button" class="btn btn-secondary btn-sm" onclick={rotate} disabled={rotating}><Icon name="rotate" size={14} />{rotating ? 'Rotating…' : 'Rotate now'}</button>
        </span>
      {/if}
    </div>
    <div class="card-pad">
      {#if infoError}
        <div class="callout callout-danger" role="alert"><Icon name="alert-circle" size={16} /><span>{infoError}</span><button type="button" class="btn btn-ghost btn-sm push" onclick={loadIssuer}>Retry</button></div>
      {:else if !info}
        <div class="sk" aria-busy="true"><span class="skeleton"></span><span class="skeleton"></span><span class="skeleton"></span></div>
      {:else if !info.signingKey}
        <EmptyState icon="key" title="No signing key yet" description="Citadel creates a {info.algorithm} key in KMS the first time a token is requested{canManageIssuer ? ', or when you rotate' : ''}.">
          {#if canManageIssuer && info.configured}<button type="button" class="btn btn-primary btn-sm" onclick={rotate}><Icon name="key" size={14} />Create signing key</button>{/if}
        </EmptyState>
      {:else}
        <dl class="kv">
          <dt>Status</dt>
          <dd><Badge tone="success" dot={false}><Icon name="check-circle" size={12} />Active</Badge></dd>
          <dt>Algorithm</dt>
          <dd class="mono">
            {info.signingKey.algorithm} <span class="subtle">({ALGS.find((a) => a.value === info?.signingKey?.algorithm)?.kms ?? ''})</span>
            {#if info.algorithm !== info.signingKey.algorithm}<span class="subtle small">· {info.algorithm} from the next rotation</span>{/if}
          </dd>
          <dt>KMS key</dt>
          <dd class="idrow"><span class="mono">{info.signingKey.kmsKeyId}</span><CopyButton value={info.signingKey.kmsKeyId} label="Copy KMS key ID" /></dd>
          <dt>Key ID (kid)</dt>
          <dd class="mono">{info.signingKey.kid}</dd>
          <dt>Rotation</dt>
          <dd>Every {info.rotationDays} days · active since {fmtDate(info.signingKey.activatedAt)}{info.nextRotationAt ? ` · next ${fmtDate(info.nextRotationAt)}` : ''}</dd>
        </dl>
        {#if info.previousKeys.length}
          <div class="prev">
            <span class="label">Still published in the JWKS</span>
            <ul>
              {#each info.previousKeys as k (k.kid)}
                <li>
                  <span class="mono">{k.kid}</span>
                  <span class="badge">{k.algorithm}</span>
                  <span class="subtle small">retired {fmtDate(k.retiredAt)} · removed {fmtDate(k.unpublishAt)}</span>
                </li>
              {/each}
            </ul>
          </div>
        {/if}
      {/if}
    </div>
  </section>
</div>

<div class="tabs-row">
  <Tabs
    label="Workload identity sections"
    tabs={[
      { id: 'clients', label: 'Workload clients', count: clientsLoading ? undefined : clients.length },
      { id: 'audit', label: 'Token issuance' }
    ]}
    bind:active={tabValue}
    onchange={(t) => setParams({ tab: t === 'clients' ? null : t })}
  />
</div>

{#if tab === 'audit'}
  {#if eventsError}
    <div class="callout callout-danger err" role="alert"><Icon name="alert-circle" size={16} /><span>{eventsError}</span><button type="button" class="btn btn-ghost btn-sm push" onclick={loadEvents}>Retry</button></div>
  {/if}
  <DataTable caption="Token issuance events" rows={filteredEvents} columns={auditCols} key={(e) => String(e.id)} loading={eventsLoading} sortBy="time" sortDir="desc" pageSize={50}>
    {#snippet toolbar()}
      <label class="sr-only" for="au-client">Client</label>
      <select id="au-client" class="select inline" value={auditClient} onchange={(e) => setParams({ auditClient: e.currentTarget.value })}>
        <option value="">All clients</option>
        {#each clients as c (c.clientId)}<option value={c.clientId}>{c.name}</option>{/each}
      </select>
      <Seg
        label="Result"
        bind:value={resultValue}
        onchange={(v) => setParams({ result: v === 'all' ? null : v })}
        options={[
          { value: 'all', label: 'All' },
          { value: 'ok', label: 'Issued' },
          { value: 'error', label: 'Denied' }
        ]}
      />
      <button type="button" class="btn btn-ghost btn-sm" onclick={loadEvents} aria-label="Refresh"><Icon name="refresh" size={14} /></button>
    {/snippet}
    {#snippet row(e)}
      <td class="nowrap">{fmtDateTime(e.createdAt)}</td>
      <td>{#if e.keyId}<button type="button" class="row-link" onclick={() => setParams({ client: e.keyId, tab: null }, { push: true })}>{clientName(e.keyId)}</button>{:else}—{/if}</td>
      <td class="mono small">{e.actor}</td>
      <td>
        {#if issued(e)}<Badge tone="success" dot={false}>Issued</Badge>{:else}<Badge tone="danger" dot={false}>{e.errorType || 'Denied'}</Badge>{/if}
      </td>
    {/snippet}
    {#snippet empty()}
      <EmptyState icon="activity" title="No tokens issued yet" description="Every token request, issued or denied, is recorded in the audit log and shows up here." />
    {/snippet}
  </DataTable>
{:else}
  {#if clientsError}
    <div class="callout callout-danger err" role="alert"><Icon name="alert-circle" size={16} /><span>{clientsError}</span><button type="button" class="btn btn-ghost btn-sm push" onclick={loadClients}>Retry</button></div>
  {/if}
  <DataTable caption="Workload clients" rows={clients} columns={cols} key={(c) => c.clientId} loading={clientsLoading} searchable={(c) => `${c.name} ${c.clientId} ${c.audiences.join(' ')}`} searchPlaceholder="Search clients" bind:query>
    {#snippet row(c)}
      <td>
        <button type="button" class="row-link mono" onclick={() => setParams({ client: c.clientId }, { push: true })}>{c.name}</button>
        <span class="mono subtle sub">{c.clientId}</span>
      </td>
      <td>
        {#if c.auth.method === 'access-key'}
          <span class="badge">Access key</span>
        {:else}
          <span class="badge">Kubernetes</span> <span class="subtle small">{c.auth.serviceAccounts.length} service account{c.auth.serviceAccounts.length === 1 ? '' : 's'}</span>
        {/if}
      </td>
      <td class="hide-sm"><span class="chips">{#each c.audiences.slice(0, 2) as a (a)}<span class="badge mono">{a}</span>{/each}{#if c.audiences.length > 2}<span class="subtle small">+{c.audiences.length - 2}</span>{/if}</span></td>
      <td class="num hide-sm">{ttlLabel(c.tokenTtlSeconds)}</td>
      <td class="subtle hide-sm">{c.lastIssuedAt ? fmtDateTime(c.lastIssuedAt) : 'Never'}</td>
      <td class="end">
        {#if canEdit}
          <span class="cell-actions">
            <button type="button" class="btn-icon" aria-label="Edit {c.name}" title="Edit" onclick={() => editClient(c)}><Icon name="edit" size={14} /></button>
            <button type="button" class="btn-icon danger" aria-label="Delete {c.name}" title="Delete" onclick={() => deleteClient(c)}><Icon name="trash" size={14} /></button>
          </span>
        {/if}
      </td>
    {/snippet}
    {#snippet empty()}
      <EmptyState icon="key" title="No workload clients" description="Create a client for each kind of workload, then point it at the token endpoint to get ID tokens.">
        {#if canEdit}<button type="button" class="btn btn-primary btn-sm" onclick={newClient}><Icon name="plus" size={14} />New client</button>{/if}
      </EmptyState>
    {/snippet}
  </DataTable>
{/if}

<ClientDrawer
  bind:open={drawerOpen}
  client={selected}
  {info}
  {canEdit}
  onclose={() => setParams({ client: null })}
  onedit={editClient}
  ondelete={deleteClient}
  onaudit={(c) => setParams({ client: null, tab: 'audit', auditClient: c.clientId })}
/>
<ClientEditor bind:open={editorOpen} client={editing} existing={clients} k8sAvailable={info?.k8sTokenReview ?? false} onsaved={(id) => loadClients().then(() => setParams({ client: id, tab: null }))} />

<Modal bind:open={settingsOpen} title="Signing settings" description="Changing the algorithm rotates to a new signing key right away. The rotation period applies from the current key's activation." size="sm">
  <form id="sig-form" class="form" onsubmit={saveSettings} novalidate>
    <div class="field">
      <label class="field-label" for="sig-alg">Algorithm</label>
      <select id="sig-alg" class="select" bind:value={alg}>
        {#each ALGS as a (a.value)}<option value={a.value}>{a.label}</option>{/each}
      </select>
      <span class="field-hint">FIPS-approved only. ES256 is widely supported and compact.</span>
    </div>
    <div class="field">
      <label class="field-label" for="sig-rot">Rotate every (days)</label>
      <input id="sig-rot" class="input num" type="number" min="7" max="365" bind:value={rotationDays} aria-invalid={!!rotationError} />
      {#if rotationError}<span class="field-error">{rotationError}</span>{/if}
    </div>
  </form>
  {#snippet footer()}
    <button type="button" class="btn btn-ghost" onclick={() => (settingsOpen = false)}>Cancel</button>
    <button type="submit" form="sig-form" class="btn btn-primary" disabled={savingSettings}>{savingSettings ? 'Saving…' : 'Save'}</button>
  {/snippet}
</Modal>

<style>
  .top {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(min(420px, 100%), 1fr));
    gap: 20px;
    align-items: start;
    margin-bottom: var(--space-6);
  }
  .card-head h2 {
    font-family: var(--font-sans);
    font-size: var(--text-md);
    letter-spacing: 0;
  }
  .head-actions {
    display: inline-flex;
    gap: 6px;
  }
  .urls {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
  }
  .urls .field + .field {
    margin-top: 0;
  }
  .urlbox {
    display: flex;
    align-items: center;
    gap: 2px;
    padding: 4px 4px 4px 12px;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: var(--surface-sunken);
  }
  .urlbox code {
    flex: 1;
    min-width: 0;
    padding: 0;
    background: none;
    overflow-wrap: anywhere;
  }
  .sk {
    display: flex;
    flex-direction: column;
    gap: 10px;
  }
  .sk .skeleton {
    height: 14px;
  }
  .kv {
    grid-template-columns: 110px minmax(0, 1fr);
  }
  .idrow {
    display: flex;
    align-items: center;
    gap: 4px;
  }
  .prev {
    margin-top: var(--space-4);
    padding-top: var(--space-4);
    border-top: 1px solid var(--border);
  }
  .prev ul {
    list-style: none;
    margin: 8px 0 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .prev li {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 8px;
  }
  .label {
    font-size: var(--text-xs);
    font-weight: 600;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    color: var(--text-subtle);
  }
  .tabs-row {
    margin-bottom: var(--space-5);
  }
  .err {
    margin-bottom: var(--space-4);
    align-items: center;
  }
  .push {
    margin-left: auto;
  }
  .sub {
    display: block;
    font-size: 12.5px;
  }
  .chips {
    display: inline-flex;
    flex-wrap: wrap;
    gap: 4px;
    align-items: center;
  }
  .chips .badge {
    font-size: 12.5px;
  }
  .select.inline {
    width: auto;
  }
  .form {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
  }
  .form .field + .field {
    margin-top: 0;
  }
  .danger:hover:not(:disabled) {
    color: var(--danger);
    background: var(--danger-soft);
  }
  @media (max-width: 720px) {
    .hide-sm {
      display: none;
    }
    .kv {
      grid-template-columns: minmax(0, 1fr);
    }
  }
</style>
