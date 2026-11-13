<script lang="ts">
  import { goto } from '$app/navigation';
  import { page } from '$app/state';
  import { base } from '#lib/paths.ts';
  import PageHeader from '#lib/components/PageHeader.svelte';
  import Tabs from '#lib/components/Tabs.svelte';
  import DataTable, { type Column } from '#lib/components/DataTable.svelte';
  import EmptyState from '#lib/components/EmptyState.svelte';
  import Badge from '#lib/components/Badge.svelte';
  import CopyButton from '#lib/components/CopyButton.svelte';
  import Modal from '#lib/components/Modal.svelte';
  import Icon from '#lib/components/Icon.svelte';
  import ActionMenu from '#lib/components/ActionMenu.svelte';
  import { errorMessage, type AuditEvent } from '#lib/api.ts';
  import { confirm } from '#lib/stores/confirm.svelte.ts';
  import { toast } from '#lib/stores/toast.svelte.ts';
  import { param, setParams } from '#lib/url.ts';
  import OnceSecret from '../../account/OnceSecret.svelte';
  import { fullTime, relTime } from '../../time';
  import { agentMenu } from '../actions';
  import GrantModal from './GrantModal.svelte';
  import AccessDecisionModal from '../AccessDecisionModal.svelte';
  import {
    ACCESS_STATUS,
    LEASE_STATUS,
    SCOPE_LABELS,
    agentsApi,
    formatDuration,
    grantLimits,
    timeLeft,
    type AccessRequest,
    type AgentLease,
    REASON_LABELS,
    STATUS_LABEL,
    STATUS_TONE,
    type AgentBinding,
    type AgentCredential,
    type AgentDetail,
    type AgentGrant,
    type AgentToken
  } from '../api';

  const agentId = $derived(page.params.agent ?? '');
  let detail = $state<AgentDetail | null>(null);
  let loading = $state(true);
  let loadError = $state('');
  let credentials = $state<AgentCredential[]>([]);

  async function load() {
    loadError = '';
    try {
      detail = await agentsApi.detail(agentId);
    } catch (e) {
      loadError = errorMessage(e, 'Could not load the agent.');
    } finally {
      loading = false;
    }
  }
  async function loadCredentials() {
    try {
      credentials = (await agentsApi.credentials()).credentials ?? [];
    } catch {
      credentials = [];
    }
  }
  $effect(() => {
    void agentId;
    loading = true;
    detail = null;
    load();
  });

  const agent = $derived(detail?.agent ?? null);
  const manage = $derived(!!agent?.canManage && agent.status !== 'revoked');

  const TABS = ['overview', 'tokens', 'federation', 'grants', 'requests', 'leases', 'activity'] as const;
  type Tab = (typeof TABS)[number];
  const tab = $derived<Tab>(TABS.find((t) => t === param('tab')) ?? 'overview');
  let tabValue = $state<string>('overview');
  $effect(() => {
    tabValue = tab;
  });

  // ---- activity ------------------------------------------------------------
  let events = $state<AuditEvent[]>([]);
  let eventsLoading = $state(false);
  let eventsError = $state('');
  async function loadEvents() {
    eventsLoading = true;
    eventsError = '';
    try {
      events = await agentsApi.activity(agentId);
    } catch (e) {
      eventsError = errorMessage(e, 'Could not load the activity.');
    } finally {
      eventsLoading = false;
    }
  }
  $effect(() => {
    if (tab === 'activity') loadEvents();
    if (tab === 'grants' && manage) loadCredentials();
    if (tab === 'requests') loadRequests();
    if (tab === 'leases') loadLeases();
  });

  // ---- access requests (2.3) ----------------------------------------------
  let requests = $state<AccessRequest[]>([]);
  let requestsLoading = $state(false);
  let requestsError = $state('');
  async function loadRequests() {
    requestsLoading = true;
    requestsError = '';
    try {
      requests = await agentsApi.accessRequests({ agentId, status: 'all' });
    } catch (e) {
      requestsError = errorMessage(e, 'Could not load the access requests.');
    } finally {
      requestsLoading = false;
    }
  }
  let decideOpen = $state(false);
  let decideMode = $state<'approve' | 'deny'>('approve');
  let deciding = $state<AccessRequest | null>(null);
  function decide(r: AccessRequest, mode: 'approve' | 'deny') {
    deciding = r;
    decideMode = mode;
    decideOpen = true;
  }
  async function decided() {
    window.dispatchEvent(new CustomEvent('citadel:approvals-changed'));
    await loadRequests();
  }

  // ---- leases --------------------------------------------------------------
  let leases = $state<AgentLease[]>([]);
  let leasesLoading = $state(false);
  let leasesError = $state('');
  let showEnded = $state(false);
  async function loadLeases() {
    leasesLoading = true;
    leasesError = '';
    try {
      leases = await agentsApi.leases({ agentId, active: !showEnded });
    } catch (e) {
      leasesError = errorMessage(e, 'Could not load the leases.');
    } finally {
      leasesLoading = false;
    }
  }
  async function revokeLease(l: AgentLease) {
    const ok = await confirm({
      title: `Revoke the lease on ${l.credential}?`,
      message: `${agent?.name ?? 'The agent'} can no longer ${l.actions.join(' or ')} ${l.credential} under this lease. It can ask again.`,
      confirmLabel: 'Revoke lease',
      danger: true
    });
    if (!ok) return;
    try {
      await agentsApi.revokeLease(l.leaseId, 'revoked in the console');
      toast.success('Lease revoked');
      await loadLeases();
    } catch (e) {
      toast.error(e, 'Could not revoke the lease');
    }
  }

  // ---- federation requirement ----------------------------------------------
  let fedSaving = $state(false);
  async function setRequireFederation(on: boolean) {
    if (!agent || fedSaving) return;
    if (on && agent.activeTokenCount > 0) {
      const ok = await confirm({
        title: 'Require workload identity federation?',
        message: `${agent.name}'s ${agent.activeTokenCount} active token${agent.activeTokenCount === 1 ? '' : 's'} will be refused from the next request. It must authenticate with a federation binding.`,
        confirmLabel: 'Require federation',
        danger: true
      });
      if (!ok) return;
    }
    fedSaving = true;
    try {
      await agentsApi.update({ agentId, name: agent.name, description: agent.description, owner: agent.owner, labels: agent.labels, requireFederation: on });
      toast.success(on ? 'Agent tokens are now refused' : 'Agent tokens are accepted again');
      await load();
    } catch (e) {
      toast.error(e, 'Could not change the setting');
    } finally {
      fedSaving = false;
    }
  }

  // ---- tokens --------------------------------------------------------------
  let tokenOpen = $state(false);
  let tokenName = $state('');
  let tokenDays = $state(90);
  let tokenSaving = $state(false);
  let issued = $state('');
  let issuedOpen = $state(false);
  async function createToken(e: SubmitEvent) {
    e.preventDefault();
    if (tokenSaving) return;
    tokenSaving = true;
    try {
      const r = await agentsApi.createToken(agentId, tokenName.trim(), Number(tokenDays) || 0);
      tokenOpen = false;
      issued = r.token;
      issuedOpen = true;
      await load();
    } catch (err) {
      toast.error(err, 'Could not create the token');
    } finally {
      tokenSaving = false;
    }
  }
  async function revokeToken(t: AgentToken) {
    const ok = await confirm({
      title: `Revoke token ${t.name || t.prefix}?`,
      message: 'Anything using this token is refused from the next request.',
      confirmLabel: 'Revoke token',
      danger: true
    });
    if (!ok) return;
    try {
      await agentsApi.revokeToken(agentId, t.tokenId);
      toast.success('Token revoked');
      await load();
    } catch (e) {
      toast.error(e, 'Could not revoke the token');
    }
  }

  // ---- bindings ------------------------------------------------------------
  let bindOpen = $state(false);
  let bIssuer = $state('');
  let bSubject = $state('');
  let bAudience = $state('');
  let bDesc = $state('');
  let bSaving = $state(false);
  let bError = $state('');
  function openBinding() {
    bIssuer = typeof location !== 'undefined' ? `${location.origin}/oidc` : '';
    bSubject = bAudience = bDesc = bError = '';
    bindOpen = true;
  }
  async function createBinding(e: SubmitEvent) {
    e.preventDefault();
    if (bSaving) return;
    bSaving = true;
    bError = '';
    try {
      await agentsApi.createBinding({ agentId, issuer: bIssuer.trim(), subject: bSubject.trim(), audience: bAudience.trim(), description: bDesc.trim() });
      toast.success('Binding added');
      bindOpen = false;
      await load();
    } catch (err) {
      bError = errorMessage(err, 'Could not add the binding.');
    } finally {
      bSaving = false;
    }
  }
  async function deleteBinding(b: AgentBinding) {
    const ok = await confirm({ title: 'Remove this binding?', message: `Tokens for ${b.subject} no longer authenticate as this agent.`, confirmLabel: 'Remove binding', danger: true });
    if (!ok) return;
    try {
      await agentsApi.deleteBinding(agentId, b.bindingId);
      toast.success('Binding removed');
      await load();
    } catch (e) {
      toast.error(e, 'Could not remove the binding');
    }
  }

  // ---- grants --------------------------------------------------------------
  let grantOpen = $state(false);
  let editingGrant = $state<AgentGrant | null>(null);
  function openGrant(g: AgentGrant | null) {
    editingGrant = g;
    grantOpen = true;
  }
  async function deleteGrant(g: AgentGrant) {
    const ok = await confirm({ title: `Remove access to ${g.credential}?`, message: 'The agent can no longer use this credential.', confirmLabel: 'Remove grant', danger: true });
    if (!ok) return;
    try {
      await agentsApi.deleteGrant(agentId, g.grantId);
      toast.success('Grant removed');
      await load();
    } catch (e) {
      toast.error(e, 'Could not remove the grant');
    }
  }

  // ---- edit ----------------------------------------------------------------
  let editOpen = $state(false);
  let eName = $state('');
  let eDesc = $state('');
  let eOwner = $state('');
  let eSaving = $state(false);
  let eError = $state('');
  function openEdit() {
    if (!agent) return;
    eName = agent.name;
    eDesc = agent.description;
    eOwner = agent.owner;
    eError = '';
    editOpen = true;
  }
  async function saveEdit(e: SubmitEvent) {
    e.preventDefault();
    if (!agent || eSaving) return;
    eSaving = true;
    eError = '';
    try {
      await agentsApi.update({ agentId, name: eName.trim(), description: eDesc.trim(), owner: eOwner.trim(), labels: agent.labels });
      toast.success('Agent updated');
      editOpen = false;
      await load();
    } catch (err) {
      eError = errorMessage(err, 'Could not update the agent.');
    } finally {
      eSaving = false;
    }
  }

  const tokenCols: Column<AgentToken>[] = [
    { id: 'name', label: 'Token', sort: (t) => t.name },
    { id: 'status', label: 'Status', sort: (t) => t.status },
    { id: 'expires', label: 'Expires', sort: (t) => t.expiresAt ?? '9', hideOnMobile: true },
    { id: 'last', label: 'Last used', sort: (t) => t.lastUsedAt ?? '', hideOnMobile: true },
    { id: 'act', label: '', align: 'end', width: '56px' }
  ];
  const bindingCols: Column<AgentBinding>[] = [
    { id: 'subject', label: 'Subject', sort: (b) => b.subject },
    { id: 'issuer', label: 'Issuer', sort: (b) => b.issuer, hideOnMobile: true },
    { id: 'aud', label: 'Audience', sort: (b) => b.audience, hideOnMobile: true },
    { id: 'act', label: '', align: 'end', width: '56px' }
  ];
  const grantCols: Column<AgentGrant>[] = [
    { id: 'cred', label: 'Credential', sort: (g) => g.credential },
    { id: 'actions', label: 'Actions' },
    { id: 'limits', label: 'Limits', hideOnMobile: true },
    { id: 'state', label: 'Now', sort: (g) => (g.usableNow ? 0 : 1), hideOnMobile: true },
    { id: 'act', label: '', align: 'end', width: '96px' }
  ];
  const requestCols: Column<AccessRequest>[] = [
    { id: 'time', label: 'Asked', sort: (r) => r.createdAt },
    { id: 'cred', label: 'Credential', sort: (r) => r.credential },
    { id: 'reason', label: 'Reason', hideOnMobile: true },
    { id: 'status', label: 'Status', sort: (r) => r.status },
    { id: 'act', label: '', align: 'end', width: '180px' }
  ];
  const leaseCols: Column<AgentLease>[] = [
    { id: 'cred', label: 'Credential', sort: (l) => l.credential },
    { id: 'scope', label: 'Scope', sort: (l) => l.scope },
    { id: 'uses', label: 'Uses left', sort: (l) => l.usesLeft ?? Infinity, hideOnMobile: true },
    { id: 'expires', label: 'Expires', sort: (l) => l.expiresAt },
    { id: 'by', label: 'Created by', sort: (l) => l.createdBy, hideOnMobile: true },
    { id: 'last', label: 'Last used', sort: (l) => l.lastUsedAt ?? '', hideOnMobile: true },
    { id: 'act', label: '', align: 'end', width: '56px' }
  ];
  const eventCols: Column<AuditEvent>[] = [
    { id: 'time', label: 'Time', sort: (e) => e.createdAt },
    { id: 'action', label: 'Action', sort: (e) => e.action },
    { id: 'by', label: 'By', sort: (e) => e.actor, hideOnMobile: true },
    { id: 'task', label: 'Task', sort: (e) => e.taskId ?? '', hideOnMobile: true },
    { id: 'result', label: 'Result', sort: (e) => e.result }
  ];
  const resultTone = (r: string) => (r === 'success' || r === 'ok' ? 'success' : r === 'denied' ? 'danger' : r === 'pending' ? 'neutral' : 'warning');
</script>

<a class="back subtle small" href="{base}/agents"><Icon name="chevron-left" size={14} />Agents</a>

{#if loadError && !detail}
  <PageHeader title="Agent" />
  <div class="callout callout-danger" role="alert">
    <Icon name="alert-circle" size={16} /><span>{loadError}</span>
    <button type="button" class="btn btn-ghost btn-sm push" onclick={load}>Retry</button>
  </div>
{:else if !agent}
  <PageHeader title="Agent" />
  <div class="sk" aria-busy="true"><span class="skeleton"></span><span class="skeleton"></span><span class="skeleton"></span></div>
{:else}
  <PageHeader title={agent.name} description={agent.description || 'No description'}>
    {#snippet actions()}
      {#if manage}
        <button type="button" class="btn btn-secondary" onclick={openEdit}><Icon name="edit" size={16} />Edit</button>
      {/if}
      {#if agent?.canManage}
        <ActionMenu label="Actions for {agent.name}" triggerClass="btn btn-secondary btn-icon-sm" items={agentMenu(agent, (deleted) => (deleted ? goto(`${base}/agents`) : load()))} />
      {/if}
    {/snippet}
  </PageHeader>

  <div class="summary">
    <Badge tone={STATUS_TONE[agent.status]}>{STATUS_LABEL[agent.status]}</Badge>
    <span class="idrow"><span class="mono subtle">{agent.agentId}</span><CopyButton value={agent.agentId} label="Copy agent ID" /></span>
    <span class="subtle">Owner <strong>{agent.owner}</strong></span>
    <span class="subtle">Last used {agent.lastUsedAt ? relTime(agent.lastUsedAt) : 'never'}</span>
  </div>

  {#if agent.status !== 'active'}
    <div class="callout {agent.status === 'revoked' ? 'callout-danger' : 'callout-warning'} note" role="status">
      <Icon name="alert-triangle" size={16} />
      <span>
        {agent.status === 'revoked' ? 'Revoked' : 'Suspended'}{agent.statusChangedBy ? ` by ${agent.statusChangedBy}` : ''}{agent.statusChangedAt ? `, ${relTime(agent.statusChangedAt)}` : ''}.
        {agent.statusReason ? `Reason: ${agent.statusReason}.` : ''}
        {agent.status === 'revoked' ? 'Revoking is permanent.' : 'Every request it makes is refused until it is resumed.'}
      </span>
    </div>
  {/if}

  <div class="tabs-row">
    <Tabs
      label="Agent sections"
      tabs={[
        { id: 'overview', label: 'Overview' },
        { id: 'tokens', label: 'Tokens', count: detail?.tokens.length },
        { id: 'federation', label: 'Federation', count: detail?.bindings.length },
        { id: 'grants', label: 'Grants', count: detail?.grants.length },
        { id: 'requests', label: 'Requests' },
        { id: 'leases', label: 'Leases' },
        { id: 'activity', label: 'Activity' }
      ]}
      bind:active={tabValue}
      onchange={(t) => setParams({ tab: t === 'overview' ? null : t })}
    />
  </div>

  {#if tab === 'overview'}
    <section class="card card-pad">
      <dl class="kv">
        <dt>Status</dt>
        <dd><Badge tone={STATUS_TONE[agent.status]}>{STATUS_LABEL[agent.status]}</Badge></dd>
        <dt>Owner</dt>
        <dd>{agent.owner}</dd>
        <dt>Created</dt>
        <dd><span title={fullTime(agent.createdAt)}>{relTime(agent.createdAt)}</span>{agent.createdBy ? ` by ${agent.createdBy}` : ''}</dd>
        <dt>Last used</dt>
        <dd>{agent.lastUsedAt ? fullTime(agent.lastUsedAt) : 'Never'}</dd>
        <dt>Active tokens</dt>
        <dd>{agent.activeTokenCount}</dd>
        <dt>Federation bindings</dt>
        <dd>{agent.bindingCount}</dd>
        <dt>Grants</dt>
        <dd>{agent.grantCount}</dd>
        <dt>Authentication</dt>
        <dd>
          <label class="check">
            <input type="checkbox" checked={!!agent.requireFederation} disabled={!manage || fedSaving} onchange={(e) => setRequireFederation(e.currentTarget.checked)} />
            <span>Require workload identity federation <span class="subtle small block">Agent tokens are refused; the agent authenticates only with a federation binding.</span></span>
          </label>
        </dd>
        {#if Object.keys(agent.labels).length}
          <dt>Labels</dt>
          <dd><span class="chips">{#each Object.entries(agent.labels) as [k, v] (k)}<span class="badge mono">{k}{v ? `=${v}` : ''}</span>{/each}</span></dd>
        {/if}
      </dl>
      <div class="usage">
        <span class="label">Use it</span>
        <p class="muted small">Agents call the Agent API with their token (<span class="mono">Authorization: Bearer cagt_…</span>). Send <span class="mono">X-Citadel-Task-Id</span> to tie requests to a task in the audit log.</p>
        <pre class="code mono small">curl -H "Authorization: Bearer $CITADEL_AGENT_TOKEN" \
  {typeof location !== 'undefined' ? location.origin : ''}/v1/agent/credentials</pre>
      </div>
    </section>
  {:else if tab === 'tokens'}
    {#if agent.requireFederation}
      <div class="callout callout-info note" role="note"><Icon name="info" size={16} /><span>This agent requires workload identity federation: its tokens are refused and no new ones can be issued. Turn it off on the Overview tab to use tokens.</span></div>
    {/if}
    <DataTable caption="Agent tokens" rows={detail?.tokens ?? []} columns={tokenCols} key={(t) => t.tokenId} {loading} sortBy="expires">
      {#snippet toolbar()}
        {#if manage}<button type="button" class="btn btn-primary btn-sm" disabled={agent?.requireFederation} onclick={() => { tokenName = ''; tokenDays = 90; tokenOpen = true; }}><Icon name="plus" size={14} />New token</button>{/if}
      {/snippet}
      {#snippet row(t)}
        <td><span class="strong">{t.name || 'Unnamed'}</span><span class="mono subtle sub">{t.prefix}…</span></td>
        <td><Badge tone={t.status === 'active' ? 'success' : t.status === 'expired' ? 'warning' : 'danger'}>{t.status === 'active' ? 'Active' : t.status === 'expired' ? 'Expired' : 'Revoked'}</Badge></td>
        <td class="subtle hide-sm">{t.expiresAt ? fullTime(t.expiresAt) : 'Never'}</td>
        <td class="subtle hide-sm">{t.lastUsedAt ? relTime(t.lastUsedAt) : 'Never'}</td>
        <td class="end">
          {#if agent?.canManage && t.status === 'active'}
            <button type="button" class="btn-icon danger" aria-label="Revoke token {t.name || t.prefix}" title="Revoke" onclick={() => revokeToken(t)}><Icon name="x-circle" size={14} /></button>
          {/if}
        </td>
      {/snippet}
      {#snippet empty()}
        <EmptyState icon="key" title="No tokens" description="Issue a token and give it to the agent's MCP client or SDK. It is shown once; Citadel keeps only a hash.">
          {#if manage && !agent?.requireFederation}<button type="button" class="btn btn-primary btn-sm" onclick={() => (tokenOpen = true)}><Icon name="plus" size={14} />New token</button>{/if}
        </EmptyState>
      {/snippet}
    </DataTable>
  {:else if tab === 'federation'}
    <p class="muted small intro">Instead of a long-lived token, the agent can present a workload identity token (Citadel's own issuer, or an OIDC provider registered under IAM, such as GitHub Actions) whose issuer, subject and audience match a binding.</p>
    <DataTable caption="Federation bindings" rows={detail?.bindings ?? []} columns={bindingCols} key={(b) => b.bindingId} {loading}>
      {#snippet toolbar()}
        {#if manage}<button type="button" class="btn btn-primary btn-sm" onclick={openBinding}><Icon name="plus" size={14} />Add binding</button>{/if}
      {/snippet}
      {#snippet row(b)}
        <td><span class="mono">{b.subject}</span>{#if b.description}<span class="subtle sub">{b.description}</span>{/if}</td>
        <td class="mono small hide-sm">{b.issuer}</td>
        <td class="mono small hide-sm">{b.audience}</td>
        <td class="end">
          {#if manage}<button type="button" class="btn-icon danger" aria-label="Remove binding {b.subject}" title="Remove" onclick={() => deleteBinding(b)}><Icon name="trash" size={14} /></button>{/if}
        </td>
      {/snippet}
      {#snippet empty()}
        <EmptyState icon="link" title="No bindings" description="Bind a CI job or Kubernetes service account so it can act as this agent without a stored token." />
      {/snippet}
    </DataTable>
  {:else if tab === 'grants'}
    <DataTable caption="Grants" rows={detail?.grants ?? []} columns={grantCols} key={(g) => g.grantId} {loading}>
      {#snippet toolbar()}
        {#if manage}<button type="button" class="btn btn-primary btn-sm" onclick={() => openGrant(null)} disabled={credentials.length === 0} title={credentials.length === 0 ? 'Add an agent usage profile to a secret first' : undefined}><Icon name="plus" size={14} />Grant credential</button>{/if}
      {/snippet}
      {#snippet row(g)}
        <td class="mono">{g.credential}</td>
        <td>
          <span class="chips">
            {#each g.actions as a (a)}
              {#if a === 'reveal'}<Badge tone="danger" dot={false}><Icon name="eye" size={12} />reveal</Badge>{:else}<span class="badge">{a}</span>{/if}
            {/each}
          </span>
        </td>
        <td class="subtle small hide-sm">{grantLimits(g)}</td>
        <td class="hide-sm">{#if g.usableNow}<Badge tone="success" dot={false}>Usable</Badge>{:else}<Badge tone="warning" dot={false}>{REASON_LABELS[g.reason ?? ''] ?? g.reason}</Badge>{/if}</td>
        <td class="end">
          {#if manage}
            <span class="cell-actions">
              <button type="button" class="btn-icon" aria-label="Edit grant {g.credential}" title="Edit" onclick={() => openGrant(g)}><Icon name="edit" size={14} /></button>
              <button type="button" class="btn-icon danger" aria-label="Remove grant {g.credential}" title="Remove" onclick={() => deleteGrant(g)}><Icon name="trash" size={14} /></button>
            </span>
          {/if}
        </td>
      {/snippet}
      {#snippet empty()}
        <EmptyState icon="lock" title="No grants" description="The agent can't use any credential yet. Grant one; prefer use over reveal so the agent never holds the secret." />
      {/snippet}
    </DataTable>
  {:else if tab === 'requests'}
    <p class="muted small intro">The agent asks for access when a grant needs approval for each use, or when it wants a credential it wasn't granted. Approving opens a lease: once, for a time, or for one task.</p>
    {#if requestsError}
      <div class="callout callout-danger err" role="alert"><Icon name="alert-circle" size={16} /><span>{requestsError}</span><button type="button" class="btn btn-ghost btn-sm push" onclick={loadRequests}>Retry</button></div>
    {/if}
    <DataTable caption="Access requests" rows={requests} columns={requestCols} key={(r) => r.requestId} loading={requestsLoading} sortBy="time" sortDir="desc">
      {#snippet toolbar()}
        <button type="button" class="btn btn-ghost btn-sm" onclick={loadRequests} aria-label="Refresh"><Icon name="refresh" size={14} /></button>
      {/snippet}
      {#snippet row(r)}
        <td class="nowrap"><span title={fullTime(r.createdAt)}>{relTime(r.createdAt)}</span></td>
        <td>
          <span class="mono">{r.credential}</span>
          <span class="chips sub">
            {#each r.actions as a (a)}
              {#if a === 'reveal'}<Badge tone="danger" dot={false}><Icon name="eye" size={12} />reveal</Badge>{:else}<span class="badge">{a}</span>{/if}
            {/each}
            {#if r.taskId}<span class="subtle small mono">task {r.taskId}</span>{/if}
          </span>
        </td>
        <td class="small hide-sm"><span class="reason">{r.reason || (r.origin === 'policy' ? 'Grant needs approval' : '')}</span></td>
        <td>
          <Badge tone={ACCESS_STATUS[r.status].tone} dot={false}>{ACCESS_STATUS[r.status].label}</Badge>
          <span class="subtle small sub">
            {#if r.status === 'pending'}expires {timeLeft(r.expiresAt)}{:else if r.decidedBy}{r.decidedBy}{r.scope ? ` · ${SCOPE_LABELS[r.scope].toLowerCase()}` : ''}{#if r.decisionComment} · {r.decisionComment}{/if}{/if}
          </span>
        </td>
        <td class="end">
          {#if r.status === 'pending' && r.canDecide}
            <span class="cell-actions">
              <button type="button" class="btn btn-primary btn-sm" onclick={() => decide(r, 'approve')}>Approve…</button>
              <button type="button" class="btn btn-danger-ghost btn-sm" onclick={() => decide(r, 'deny')}>Deny…</button>
            </span>
          {:else if r.status === 'pending' && r.cannotDecideReason}
            <span class="subtle small" title={r.cannotDecideReason}><Icon name="lock" size={12} /></span>
          {/if}
        </td>
      {/snippet}
      {#snippet empty()}
        <EmptyState icon="git-pull-request" title="No access requests" description="Requests appear when the agent uses a grant that needs approval, or asks for a credential." />
      {/snippet}
    </DataTable>
  {:else if tab === 'leases'}
    <p class="muted small intro">Leases are time-boxed access from an approval or a grant's lease length. They end when they expire or are used up, when revoked, and when the agent is suspended.</p>
    {#if leasesError}
      <div class="callout callout-danger err" role="alert"><Icon name="alert-circle" size={16} /><span>{leasesError}</span><button type="button" class="btn btn-ghost btn-sm push" onclick={loadLeases}>Retry</button></div>
    {/if}
    <DataTable caption="Leases" rows={leases} columns={leaseCols} key={(l) => l.leaseId} loading={leasesLoading} sortBy="expires">
      {#snippet toolbar()}
        <label class="check small"><input type="checkbox" bind:checked={showEnded} />Show ended leases</label>
        <button type="button" class="btn btn-ghost btn-sm" onclick={loadLeases} aria-label="Refresh"><Icon name="refresh" size={14} /></button>
      {/snippet}
      {#snippet row(l)}
        <td>
          <span class="mono">{l.credential}</span>
          <span class="chips sub">
            {#each l.actions as a (a)}
              {#if a === 'reveal'}<Badge tone="danger" dot={false}><Icon name="eye" size={12} />reveal</Badge>{:else}<span class="badge">{a}</span>{/if}
            {/each}
            {#if l.status !== 'active'}<Badge tone={LEASE_STATUS[l.status].tone} dot={false}>{LEASE_STATUS[l.status].label}</Badge>{/if}
          </span>
        </td>
        <td>{SCOPE_LABELS[l.scope]}{#if l.taskId}<span class="mono subtle sub">{l.taskId}</span>{/if}</td>
        <td class="hide-sm">{l.usesLeft === null ? '∞' : l.usesLeft}<span class="subtle small"> · used {l.useCount}</span></td>
        <td class="nowrap"><span title={fullTime(l.expiresAt)}>{l.status === 'active' ? timeLeft(l.expiresAt) : fullTime(l.expiresAt)}</span></td>
        <td class="small hide-sm">{l.createdBy === 'policy' ? 'Grant lease length' : l.createdBy}</td>
        <td class="subtle hide-sm">{l.lastUsedAt ? relTime(l.lastUsedAt) : 'Never'}</td>
        <td class="end">
          {#if l.canRevoke}
            <button type="button" class="btn-icon danger" aria-label="Revoke lease on {l.credential}" title="Revoke" onclick={() => revokeLease(l)}><Icon name="x-circle" size={14} /></button>
          {/if}
        </td>
      {/snippet}
      {#snippet empty()}
        <EmptyState icon="clock" title={showEnded ? 'No leases' : 'No active leases'} description="Approving an access request, or a grant with a lease length, opens a lease." />
      {/snippet}
    </DataTable>
  {:else}
    {#if eventsError}
      <div class="callout callout-danger err" role="alert"><Icon name="alert-circle" size={16} /><span>{eventsError}</span><button type="button" class="btn btn-ghost btn-sm push" onclick={loadEvents}>Retry</button></div>
    {/if}
    <DataTable caption="Agent activity" rows={events} columns={eventCols} key={(e) => String(e.id)} loading={eventsLoading} sortBy="time" sortDir="desc" pageSize={50}>
      {#snippet toolbar()}
        <a class="btn btn-ghost btn-sm" href="{base}/audit?agent={encodeURIComponent(agentId)}"><Icon name="list" size={14} />Open in audit log</a>
        <button type="button" class="btn btn-ghost btn-sm" onclick={loadEvents} aria-label="Refresh"><Icon name="refresh" size={14} /></button>
      {/snippet}
      {#snippet row(e)}
        <td class="nowrap"><span title={fullTime(e.createdAt)}>{relTime(e.createdAt)}</span></td>
        <td class="mono small">{e.action}</td>
        <td class="small hide-sm">{e.actorType === 'agent' ? 'Agent' : e.actorDisplayName || e.actor}</td>
        <td class="mono small hide-sm">{e.taskId ?? ''}</td>
        <td><Badge tone={resultTone(e.result)} dot={false}>{e.errorType || e.result}</Badge></td>
      {/snippet}
      {#snippet empty()}
        <EmptyState icon="activity" title="No activity yet" description="Requests the agent makes, refusals, and console changes to it appear here." />
      {/snippet}
    </DataTable>
  {/if}

  <GrantModal bind:open={grantOpen} {agentId} agentName={agent.name} grant={editingGrant} {credentials} onsaved={load} />
  <AccessDecisionModal bind:open={decideOpen} request={deciding} mode={decideMode} ondone={decided} />
{/if}

<Modal bind:open={tokenOpen} title="New agent token" description="The token is shown once. Store it in the agent's secret configuration (for example CITADEL_AGENT_TOKEN)." size="sm">
  <form id="token-form" class="form" onsubmit={createToken} novalidate>
    <div class="field">
      <label class="field-label" for="tk-name">Name <span class="subtle">(optional)</span></label>
      <input id="tk-name" class="input" bind:value={tokenName} placeholder="laptop, ci, …" maxlength="64" />
    </div>
    <div class="field">
      <label class="field-label" for="tk-days">Expires after</label>
      <select id="tk-days" class="select" bind:value={tokenDays}>
        <option value={7}>7 days</option>
        <option value={30}>30 days</option>
        <option value={90}>90 days</option>
        <option value={365}>1 year</option>
        <option value={0}>Never</option>
      </select>
    </div>
  </form>
  {#snippet footer()}
    <button type="button" class="btn btn-ghost" onclick={() => (tokenOpen = false)}>Cancel</button>
    <button type="submit" form="token-form" class="btn btn-primary" disabled={tokenSaving}>{tokenSaving ? 'Creating…' : 'Create token'}</button>
  {/snippet}
</Modal>

<OnceSecret
  bind:open={issuedOpen}
  title="Copy the agent token"
  description="This is the only time Citadel shows it. Anyone with the token can act as this agent until it expires or is revoked."
  fields={[{ label: 'Agent token', value: issued, secret: true, filename: `${agent?.name ?? 'agent'}.token` }]}
  ondone={() => (issued = '')}
/>

<Modal bind:open={bindOpen} title="Add federation binding" description="A token whose iss, sub and aud claims all match exactly authenticates as this agent." size="md">
  <form id="bind-form" class="form" onsubmit={createBinding} novalidate>
    {#if bError}<div class="callout callout-danger" role="alert"><Icon name="alert-circle" size={16} /><span>{bError}</span></div>{/if}
    <div class="field">
      <label class="field-label" for="bd-iss">Issuer</label>
      <input id="bd-iss" class="input mono" bind:value={bIssuer} placeholder="https://token.actions.githubusercontent.com" spellcheck="false" />
      <span class="field-hint">Citadel's workload identity issuer, or an OIDC provider registered under IAM in this account.</span>
    </div>
    <div class="field">
      <label class="field-label" for="bd-sub">Subject</label>
      <input id="bd-sub" class="input mono" bind:value={bSubject} placeholder="repo:acme/app:ref:refs/heads/main" spellcheck="false" />
    </div>
    <div class="field">
      <label class="field-label" for="bd-aud">Audience</label>
      <input id="bd-aud" class="input mono" bind:value={bAudience} placeholder="citadel" spellcheck="false" />
    </div>
    <div class="field">
      <label class="field-label" for="bd-desc">Description <span class="subtle">(optional)</span></label>
      <input id="bd-desc" class="input" bind:value={bDesc} />
    </div>
  </form>
  {#snippet footer()}
    <button type="button" class="btn btn-ghost" onclick={() => (bindOpen = false)}>Cancel</button>
    <button type="submit" form="bind-form" class="btn btn-primary" disabled={bSaving || !bIssuer || !bSubject || !bAudience}>{bSaving ? 'Adding…' : 'Add binding'}</button>
  {/snippet}
</Modal>

<Modal bind:open={editOpen} title="Edit agent" size="sm">
  <form id="edit-form" class="form" onsubmit={saveEdit} novalidate>
    {#if eError}<div class="callout callout-danger" role="alert"><Icon name="alert-circle" size={16} /><span>{eError}</span></div>{/if}
    <div class="field">
      <label class="field-label" for="ed-name">Name</label>
      <input id="ed-name" class="input mono" bind:value={eName} spellcheck="false" />
    </div>
    <div class="field">
      <label class="field-label" for="ed-desc">Description</label>
      <input id="ed-desc" class="input" bind:value={eDesc} />
    </div>
    <div class="field">
      <label class="field-label" for="ed-owner">Owner</label>
      <input id="ed-owner" class="input" bind:value={eOwner} autocomplete="off" />
      <span class="field-hint">Only account admins can hand an agent to someone else.</span>
    </div>
  </form>
  {#snippet footer()}
    <button type="button" class="btn btn-ghost" onclick={() => (editOpen = false)}>Cancel</button>
    <button type="submit" form="edit-form" class="btn btn-primary" disabled={eSaving || !eName}>{eSaving ? 'Saving…' : 'Save'}</button>
  {/snippet}
</Modal>

<style>
  .back {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    margin-bottom: var(--space-2);
    text-decoration: none;
  }
  .summary {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--space-2) var(--space-4);
    margin-bottom: var(--space-5);
  }
  .idrow {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    min-width: 0;
    overflow-wrap: anywhere;
  }
  .note {
    margin-bottom: var(--space-5);
  }
  .tabs-row {
    margin-bottom: var(--space-5);
  }
  .intro {
    margin: 0 0 var(--space-4);
    max-width: 70ch;
  }
  .err {
    margin-bottom: var(--space-4);
    align-items: center;
  }
  .push {
    margin-left: auto;
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
    grid-template-columns: 170px minmax(0, 1fr);
  }
  .chips {
    display: inline-flex;
    flex-wrap: wrap;
    gap: 4px;
    align-items: center;
  }
  .sub {
    display: block;
    font-size: 12.5px;
    overflow-wrap: anywhere;
  }
  .check {
    display: inline-flex;
    gap: 8px;
    align-items: flex-start;
  }
  .check input {
    margin-top: 3px;
  }
  .block {
    display: block;
  }
  .reason {
    white-space: pre-wrap;
    overflow-wrap: anywhere;
  }
  .usage {
    margin-top: var(--space-5);
    padding-top: var(--space-4);
    border-top: 1px solid var(--border);
  }
  .label {
    font-size: var(--text-xs);
    font-weight: 600;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    color: var(--text-subtle);
  }
  .code {
    margin: var(--space-2) 0 0;
    padding: var(--space-3);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: var(--surface-sunken);
    overflow-x: auto;
    white-space: pre;
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
