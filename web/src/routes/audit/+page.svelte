<script lang="ts">
  import { onMount } from 'svelte';
  import { errorMessage } from '$lib/api';
  import { session } from '$lib/stores/session.svelte';
  import { toast } from '$lib/stores/toast.svelte';
  import { param, setParams } from '$lib/url';
  import Icon from '$lib/components/Icon.svelte';
  import PageHeader from '$lib/components/PageHeader.svelte';
  import EmptyState from '$lib/components/EmptyState.svelte';
  import Menu from '../Menu.svelte';
  import { isNotImplemented, saveBlob } from '../http';
  import { fullTime, initials, relTime, utcStamp } from '../time';
  import StreamModal from './StreamModal.svelte';
  import { auditApi, resultKind, type AuditFilters, type AuditPage, type AuditRow, type ChainStatus, type ResultFilter } from './api';

  const PAGE_SIZE = 50;

  // ---- URL state -----------------------------------------------------------
  const PRESETS = [
    { id: '24h', label: 'Last 24 hours', ms: 86_400_000 },
    { id: '7d', label: 'Last 7 days', ms: 7 * 86_400_000 },
    { id: '30d', label: 'Last 30 days', ms: 30 * 86_400_000 },
    { id: '90d', label: 'Last 90 days', ms: 90 * 86_400_000 },
    { id: 'all', label: 'All time', ms: 0 }
  ];
  const RESULTS: { id: ResultFilter; label: string }[] = [
    { id: '', label: 'any' },
    { id: 'success', label: 'Success' },
    { id: 'denied', label: 'Denied' },
    { id: 'error', label: 'Error' }
  ];

  const range = $derived(param('range', '7d'));
  const fromDay = $derived(param('from'));
  const toDay = $derived(param('to'));
  const actor = $derived(param('actor'));
  const action = $derived(param('action'));
  const result = $derived(param('result') as ResultFilter);
  const resource = $derived(param('resource'));
  const pageNum = $derived(Math.max(1, Number(param('page', '1')) || 1));
  const openId = $derived(param('event'));

  function localDay(s: string, end = false): string | undefined {
    if (!/^\d{4}-\d{2}-\d{2}$/.test(s)) return undefined;
    const [y, m, d] = s.split('-').map(Number);
    const dt = end ? new Date(y, m - 1, d, 23, 59, 59, 999) : new Date(y, m - 1, d);
    return dt.toISOString();
  }

  const filters = $derived.by<AuditFilters>(() => {
    let from: string | undefined;
    let to: string | undefined;
    if (range === 'custom') {
      from = localDay(fromDay);
      to = localDay(toDay, true);
    } else {
      const p = PRESETS.find((x) => x.id === range) ?? PRESETS[1];
      // Round to the minute so the derived value is stable between renders.
      if (p.ms) from = new Date(Math.floor((Date.now() - p.ms) / 60_000) * 60_000).toISOString();
    }
    return { from, to, actor, action, result: RESULTS.some((r) => r.id === result) ? result : '', resource };
  });

  const rangeLabel = $derived.by(() => {
    const fmt = (d: Date, year = false) => d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', ...(year ? { year: 'numeric' } : {}) });
    if (range === 'all') return 'All time';
    if (range === '24h') return 'Last 24 hours';
    const from = filters.from ? new Date(filters.from) : null;
    const to = filters.to ? new Date(filters.to) : new Date();
    return from ? `${fmt(from)} – ${fmt(to, true)}` : `Until ${fmt(to, true)}`;
  });

  // ---- data ---------------------------------------------------------------
  let data = $state<AuditPage | null>(null);
  let loading = $state(true);
  let error = $state('');
  let seq = 0;

  async function load() {
    const my = ++seq;
    loading = true;
    error = '';
    try {
      const res = await auditApi.list(filters, PAGE_SIZE, (pageNum - 1) * PAGE_SIZE);
      if (my !== seq) return;
      data = res;
    } catch (e) {
      if (my !== seq) return;
      error = errorMessage(e, "Couldn't load the audit log");
    } finally {
      if (my === seq) loading = false;
    }
  }

  const loadKey = $derived(JSON.stringify([range, fromDay, toDay, actor, action, result, resource, pageNum]));
  $effect(() => {
    void loadKey;
    void load();
  });

  const rangeStart = $derived(data && data.total ? data.offset + 1 : 0);
  const rangeEnd = $derived(data ? data.offset + data.events.length : 0);
  const hasFilters = $derived(!!(actor || action || result || resource));

  // ---- chain verification -------------------------------------------------
  let chain = $state<ChainStatus | null>(null);
  let chainState = $state<'loading' | 'ok' | 'unavailable' | 'error'>('loading');
  let chainError = $state('');
  let verifying = $state(false);

  async function loadChain() {
    chainState = 'loading';
    try {
      chain = await auditApi.chainStatus();
      chainState = 'ok';
    } catch (e) {
      chainState = isNotImplemented(e) ? 'unavailable' : 'error';
      chainError = errorMessage(e, "Couldn't check the chain");
    }
  }
  async function verifyNow() {
    verifying = true;
    try {
      chain = await auditApi.verify();
      chainState = 'ok';
      if (chain.status === 'verified') toast.success(`Chain verified through event #${(chain.verifiedThrough ?? 0).toLocaleString()}`);
      else if (chain.status === 'broken') toast.error(`Chain broken at event #${(chain.brokenAt ?? 0).toLocaleString()}`);
    } catch (e) {
      toast.error(e, 'Verification failed');
    } finally {
      verifying = false;
    }
  }
  onMount(loadChain);
  const shortHash = (h?: string) => (h ? `${h.slice(0, 6)}…${h.slice(-4)}` : '');

  // ---- filters ------------------------------------------------------------
  function setFilter(updates: Record<string, string | null>) {
    setParams({ ...updates, page: null, event: null });
  }
  let actorDraft = $state('');
  let actionDraft = $state('');
  let fromDraft = $state('');
  let toDraft = $state('');
  let resourceDraft = $state('');
  $effect(() => {
    resourceDraft = resource;
  });
  let resourceTimer: ReturnType<typeof setTimeout> | undefined;
  function onResourceInput() {
    clearTimeout(resourceTimer);
    resourceTimer = setTimeout(() => setFilter({ resource: resourceDraft.trim() || null }), 350);
  }
  const actionSuggestions = $derived([...new Set((data?.events ?? []).map((e) => e.action))].sort().slice(0, 30));

  // ---- rows ---------------------------------------------------------------
  function toggle(id: number) {
    setParams({ event: openId === String(id) ? null : String(id) });
  }

  function eventJson(e: AuditRow): string {
    const out: Record<string, unknown> = { id: e.id, time: e.createdAt, actor: e.actor, action: e.action };
    if (e.resource) out.resource = e.resource;
    if (e.keyId) out.kmsKeyId = e.keyId;
    out.result = e.result;
    if (e.errorType) out.errorType = e.errorType;
    if (e.sourceIp) out.sourceIp = e.sourceIp;
    if (e.prevHash) out.prevHash = e.prevHash;
    if (e.hash) out.hash = e.hash;
    return JSON.stringify(out, null, 2);
  }

  type Tok = { t: 'k' | 's' | 'n' | 'p'; v: string };
  function tokens(json: string): Tok[] {
    const out: Tok[] = [];
    const re = /("(?:\\.|[^"\\])*")(\s*:)?|\b(?:true|false|null)\b|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/g;
    let last = 0;
    for (const m of json.matchAll(re)) {
      const i = m.index ?? 0;
      if (i > last) out.push({ t: 'p', v: json.slice(last, i) });
      if (m[1] && m[2]) {
        out.push({ t: 'k', v: m[1] });
        out.push({ t: 'p', v: m[2] });
      } else out.push({ t: m[1] ? 's' : 'n', v: m[0] });
      last = i + m[0].length;
    }
    if (last < json.length) out.push({ t: 'p', v: json.slice(last) });
    return out;
  }

  async function copyJson(e: AuditRow) {
    try {
      await navigator.clipboard.writeText(eventJson(e));
      toast.success(`Copied event #${e.id}`);
    } catch (err) {
      toast.error(err, 'Copy failed');
    }
  }

  // ---- export -------------------------------------------------------------
  let exporting = $state(false);
  async function doExport(format: 'csv' | 'json', close: () => void) {
    close();
    exporting = true;
    try {
      const blob = await auditApi.export(format, filters);
      const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
      saveBlob(blob, `citadel-audit-${stamp}.${format}`);
      toast.success(`Exported audit log as ${format.toUpperCase()}`);
    } catch (e) {
      toast.error(e, 'Export failed');
    } finally {
      exporting = false;
    }
  }

  let streamOpen = $state(false);
  const resultTone = { success: 'success', denied: 'danger', error: 'warning' } as const;
</script>

<PageHeader title="Audit log" description="Append-only record of every API call and console action in account {session.me?.accountId ?? ''}.">
  {#snippet actions()}
    <button type="button" class="btn btn-ghost" onclick={() => (streamOpen = true)}><Icon name="external-link" />Stream to SIEM</button>
  {/snippet}
</PageHeader>

{#if chainState === 'loading'}
  <div class="banner banner-neutral" aria-busy="true"><span class="skeleton" style:width="20px" style:height="20px"></span><span class="skeleton" style:width="50%" style:height="14px"></span></div>
{:else if chainState === 'ok' && chain}
  <div class="banner banner-{chain.status === 'verified' ? 'success' : chain.status === 'broken' ? 'danger' : 'neutral'}" role="status">
    <Icon name={chain.status === 'broken' ? 'alert-triangle' : 'shield-check'} size={20} />
    <div class="banner-text">
      {#if chain.status === 'verified'}
        <strong>Chain verified through event #{(chain.verifiedThrough ?? 0).toLocaleString()}</strong>
      {:else if chain.status === 'broken'}
        <strong>Chain broken at event #{(chain.brokenAt ?? 0).toLocaleString()}</strong>
      {:else}
        <strong>The chain hasn't been verified yet</strong>
      {/if}
      <span>
        {chain.status === 'broken'
          ? 'That event or the one before it was edited or deleted after it was written. Export the log and investigate before trusting later events.'
          : 'Every event hashes the one before it, so an edited or deleted row breaks the chain.'}
        {#if chain.checkedAt}Last check <time datetime={chain.checkedAt} title={fullTime(chain.checkedAt)}>{relTime(chain.checkedAt)}</time>{/if}{#if chain.headHash}
          · head <span class="mono">{shortHash(chain.headHash)}</span>{/if}
      </span>
    </div>
    <button type="button" class="btn btn-secondary btn-sm" onclick={verifyNow} disabled={verifying}>
      <Icon name="rotate" size={14} />{verifying ? 'Verifying…' : 'Verify now'}
    </button>
  </div>
{:else if chainState === 'unavailable'}
  <div class="banner banner-neutral" role="status">
    <Icon name="link" size={20} />
    <div class="banner-text">
      <strong>Events are hash-chained</strong>
      <span>Every event hashes the one before it. This server can't run a chain check from the console yet.</span>
    </div>
  </div>
{:else}
  <div class="banner banner-danger" role="alert">
    <Icon name="alert-circle" size={20} />
    <div class="banner-text"><strong>Couldn't check the chain</strong><span>{chainError}</span></div>
    <button type="button" class="btn btn-secondary btn-sm" onclick={loadChain}><Icon name="refresh" size={14} />Retry</button>
  </div>
{/if}

<div class="filters">
  <Menu label="Date range: {rangeLabel}" triggerClass="btn btn-secondary" width={280} role="dialog">
    {#snippet trigger()}<Icon name="calendar" />{rangeLabel}<Icon name="chevron-down" size={14} />{/snippet}
    {#snippet children(close)}
      <div class="menu-label">Range</div>
      {#each PRESETS as p (p.id)}
        <button type="button" role="menuitemradio" aria-checked={range === p.id} onclick={() => { setFilter({ range: p.id === '7d' ? null : p.id, from: null, to: null }); close(); }}>
          <span class="grow">{p.label}</span>{#if range === p.id}<Icon name="check" />{/if}
        </button>
      {/each}
      <div class="menu-sep"></div>
      <form class="pop-form" onsubmit={(e) => { e.preventDefault(); setFilter({ range: 'custom', from: fromDraft || null, to: toDraft || null }); close(); }}>
        <div class="menu-label">Custom (your time zone)</div>
        <div class="pair">
          <label class="field"><span class="field-label">From</span><input class="input" type="date" bind:value={fromDraft} max={toDraft || undefined} /></label>
          <label class="field"><span class="field-label">To</span><input class="input" type="date" bind:value={toDraft} min={fromDraft || undefined} /></label>
        </div>
        <button type="submit" class="btn btn-primary btn-sm" disabled={!fromDraft && !toDraft}>Apply</button>
      </form>
    {/snippet}
  </Menu>

  <Menu label="Filter by actor" labelTrigger={false} triggerClass="btn btn-secondary" width={280} role="dialog">
    {#snippet trigger()}<Icon name="user" />Actor: {actor || 'anyone'}<Icon name="chevron-down" size={14} />{/snippet}
    {#snippet children(close)}
      <form class="pop-form" onsubmit={(e) => { e.preventDefault(); setFilter({ actor: actorDraft.trim() || null }); close(); }}>
        <label class="field"><span class="field-label">Actor contains</span><input class="input" bind:value={actorDraft} placeholder="Username, role or ARN" /></label>
        <div class="row-end">
          {#if actor}<button type="button" class="btn btn-ghost btn-sm" onclick={() => { setFilter({ actor: null }); close(); }}>Anyone</button>{/if}
          <button type="submit" class="btn btn-primary btn-sm">Apply</button>
        </div>
      </form>
    {/snippet}
  </Menu>

  <Menu label="Filter by action" labelTrigger={false} triggerClass="btn btn-secondary" width={300} role="dialog">
    {#snippet trigger()}Action: <span class:mono={!!action}>{action || 'any'}</span><Icon name="chevron-down" size={14} />{/snippet}
    {#snippet children(close)}
      <form class="pop-form" onsubmit={(e) => { e.preventDefault(); setFilter({ action: actionDraft.trim() || null }); close(); }}>
        <label class="field"><span class="field-label">Action contains</span><input class="input mono" bind:value={actionDraft} list="audit-actions" placeholder="e.g. Decrypt or citadel.PutItem" /></label>
        <datalist id="audit-actions">{#each actionSuggestions as a (a)}<option value={a}></option>{/each}</datalist>
        <div class="row-end">
          {#if action}<button type="button" class="btn btn-ghost btn-sm" onclick={() => { setFilter({ action: null }); close(); }}>Any</button>{/if}
          <button type="submit" class="btn btn-primary btn-sm">Apply</button>
        </div>
      </form>
    {/snippet}
  </Menu>

  <Menu label="Filter by result" labelTrigger={false} triggerClass="btn btn-secondary" width={200}>
    {#snippet trigger()}Result: {RESULTS.find((r) => r.id === result)?.label ?? 'any'}<Icon name="chevron-down" size={14} />{/snippet}
    {#snippet children(close)}
      {#each RESULTS as r (r.id)}
        <button type="button" role="menuitemradio" aria-checked={result === r.id} onclick={() => { setFilter({ result: r.id || null }); close(); }}>
          <span class="grow">{r.id ? r.label : 'Any result'}</span>{#if result === r.id}<Icon name="check" />{/if}
        </button>
      {/each}
    {/snippet}
  </Menu>

  <div class="res-search">
    <Icon name="search" />
    <label for="res" class="sr-only">Resource contains</label>
    <input id="res" class="input mono" type="search" placeholder="Resource ARN or name" bind:value={resourceDraft} oninput={onResourceInput} />
  </div>

  <span class="export">
    <Menu label="Export matching events" triggerClass="btn btn-secondary" align="end" width={200}>
      {#snippet trigger()}<Icon name="download" />{exporting ? 'Exporting…' : 'Export'}<Icon name="chevron-down" size={14} />{/snippet}
      {#snippet children(close)}
        <button type="button" role="menuitem" onclick={() => doExport('csv', close)}><Icon name="file" />CSV</button>
        <button type="button" role="menuitem" onclick={() => doExport('json', close)}><Icon name="file" />JSON</button>
      {/snippet}
    </Menu>
  </span>
</div>

{#if hasFilters}
  <div class="chips">
    <span class="subtle small">Filters:</span>
    {#if actor}<span class="badge chip">actor ~ {actor}<button type="button" class="chip-x" aria-label="Remove filter: actor" onclick={() => setFilter({ actor: null })}><Icon name="x" size={10} /></button></span>{/if}
    {#if action}<span class="badge chip mono">action ~ {action}<button type="button" class="chip-x" aria-label="Remove filter: action" onclick={() => setFilter({ action: null })}><Icon name="x" size={10} /></button></span>{/if}
    {#if result}<span class="badge chip">Result is {RESULTS.find((r) => r.id === result)?.label}<button type="button" class="chip-x" aria-label="Remove filter: result" onclick={() => setFilter({ result: null })}><Icon name="x" size={10} /></button></span>{/if}
    {#if resource}<span class="badge chip mono">resource ~ {resource}<button type="button" class="chip-x" aria-label="Remove filter: resource" onclick={() => setFilter({ resource: null })}><Icon name="x" size={10} /></button></span>{/if}
    <button type="button" class="btn btn-ghost btn-sm" onclick={() => setFilter({ actor: null, action: null, result: null, resource: null })}>Clear all</button>
  </div>
{/if}

{#if data?.legacy}
  <div class="callout callout-info"><Icon name="info" /><span>This server returns only its latest 500 events, so filters and export cover those. Upgrade the server for full history.</span></div>
{/if}

<div class="card card-flush tbl-card">
  {#if error}
    <div class="state" role="alert">
      <span class="err"><Icon name="alert-circle" />{error}</span>
      <button type="button" class="btn btn-secondary btn-sm" onclick={load}><Icon name="refresh" size={14} />Retry</button>
    </div>
  {:else if !loading && data && !data.events.length}
    <div class="state">
      {#if hasFilters || range !== 'all'}
        <EmptyState icon="filter" title="No matching events" description="Nothing in this range matches the filters. Widen the date range or clear filters.">
          <button type="button" class="btn btn-secondary" onclick={() => setFilter({ actor: null, action: null, result: null, resource: null, range: 'all', from: null, to: null })}>Show all events</button>
        </EmptyState>
      {:else}
        <EmptyState icon="activity" title="No audit events yet" description="API calls and console actions are recorded here as they happen." />
      {/if}
    </div>
  {:else}
    <div class="scroll">
      <table class="table" aria-busy={loading}>
        <caption class="sr-only">Audit events, newest first</caption>
        <thead>
          <tr>
            <th scope="col" class="w-exp"><span class="sr-only">Expand</span></th>
            <th scope="col">Event</th>
            <th scope="col" aria-sort="descending">Time (UTC)</th>
            <th scope="col">Actor</th>
            <th scope="col">Action</th>
            <th scope="col">Resource</th>
            <th scope="col">Result</th>
            <th scope="col">Source IP</th>
          </tr>
        </thead>
        <tbody>
          {#if loading && !data}
            {#each Array(8) as _, i (i)}
              <tr>{#each Array(8) as __, j (j)}<td><span class="skeleton" style:width={j === 0 ? '20px' : '70%'} style:height="12px"></span></td>{/each}</tr>
            {/each}
          {:else if data}
            {#each data.events as e (e.id)}
              {@const open = openId === String(e.id)}
              {@const kind = resultKind(e)}
              <tr class:selected={open} class:dim={loading}>
                <td class="w-exp">
                  <button type="button" class="btn btn-ghost btn-sm btn-icon" aria-expanded={open} aria-controls="ev-{e.id}" aria-label="{open ? 'Collapse' : 'Expand'} event {e.id}" onclick={() => toggle(e.id)}>
                    <Icon name={open ? 'chevron-down' : 'chevron-right'} size={14} />
                  </button>
                </td>
                <td class="mono subtle">#{e.id.toLocaleString()}</td>
                <td class="mono sm" title={fullTime(e.createdAt)}>{utcStamp(e.createdAt)}</td>
                <td><span class="who"><span class="avatar" aria-hidden="true">{initials(e.actorDisplayName || e.actor || '?')}</span>{e.actorDisplayName || e.actor || '—'}</span></td>
                <td class="mono sm">{e.action}</td>
                <td class="mono sm res" title={e.resource || e.keyId}>{e.resource || e.keyId || '—'}</td>
                <td>
                  <span class="badge badge-{resultTone[kind]}">
                    <Icon name={kind === 'success' ? 'check-circle' : kind === 'denied' ? 'x' : 'alert-triangle'} size={12} />
                    {kind === 'success' ? 'Success' : kind === 'denied' ? 'Denied' : e.errorType || 'Error'}
                  </span>
                </td>
                <td class="mono subtle sm">{e.sourceIp || '—'}</td>
              </tr>
              {#if open}
                {@const json = eventJson(e)}
                <tr class="detail" id="ev-{e.id}">
                  <td colspan="8">
                    <div class="detail-in">
                      <div class="detail-head">
                        <span class="label">Event JSON</span>
                        {#if e.hashValid === true}
                          <span class="badge badge-success mini"><Icon name="link" size={12} />Hash matches</span>
                        {:else if e.hashValid === false}
                          <span class="badge badge-danger mini"><Icon name="alert-triangle" size={12} />Hash mismatch</span>
                        {/if}
                        <span class="detail-actions">
                          <button type="button" class="btn btn-ghost btn-sm" onclick={() => copyJson(e)}><Icon name="copy" size={14} />Copy JSON</button>
                          {#if e.actor}<button type="button" class="btn btn-ghost btn-sm" onclick={() => setFilter({ actor: e.actor })}><Icon name="filter" size={14} />Filter by actor</button>{/if}
                        </span>
                      </div>
                      <pre class="code">{#each tokens(json) as t, ti (ti)}{#if t.t === 'p'}{t.v}{:else}<span class="tok-{t.t}">{t.v}</span>{/if}{/each}</pre>
                    </div>
                  </td>
                </tr>
              {/if}
            {/each}
          {/if}
        </tbody>
      </table>
    </div>
    <div class="pager">
      <span class="subtle small" aria-live="polite">
        {#if data}Showing {rangeStart.toLocaleString()}–{rangeEnd.toLocaleString()} of {data.total.toLocaleString()} matching events{:else}Loading…{/if}
      </span>
      <nav aria-label="Pagination" class="pager-nav">
        <button type="button" class="btn btn-secondary btn-sm" disabled={pageNum <= 1 || loading} onclick={() => setParams({ page: pageNum - 1 > 1 ? String(pageNum - 1) : null, event: null })}><Icon name="chevron-left" size={14} />Previous</button>
        <button type="button" class="btn btn-secondary btn-sm" disabled={!data || rangeEnd >= data.total || loading} onclick={() => setParams({ page: String(pageNum + 1), event: null })}>Next<Icon name="chevron-right" size={14} /></button>
      </nav>
    </div>
  {/if}
</div>

<StreamModal bind:open={streamOpen} />

<style>
  .grow {
    flex: 1;
  }
  .label {
    font-size: var(--text-xs);
    font-weight: 600;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    color: var(--text-subtle);
  }

  .banner {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 12px;
    padding: 12px 16px;
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
  }
  .banner-success {
    background: var(--success-soft);
    color: var(--success);
  }
  .banner-danger {
    background: var(--danger-soft);
    color: var(--danger);
  }
  .banner-neutral {
    background: var(--surface-hover);
    color: var(--text-muted);
  }
  .banner-text {
    display: flex;
    flex: 1 1 320px;
    flex-direction: column;
    gap: 2px;
    min-width: 0;
  }
  .banner-text strong {
    font-weight: 600;
  }
  .banner-text span {
    color: var(--text-muted);
    font-size: 12.5px;
  }
  .banner-neutral .banner-text strong {
    color: var(--text);
  }

  .filters {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 8px;
  }
  .filters :global(.btn > svg:last-child) {
    color: var(--text-subtle);
  }
  .res-search {
    position: relative;
    display: flex;
    flex: 1 1 220px;
    align-items: center;
    max-width: 320px;
    color: var(--text-subtle);
  }
  .res-search > :global(svg) {
    position: absolute;
    left: 10px;
  }
  .res-search .input {
    padding-left: 34px;
  }
  .export {
    display: flex;
    margin-left: auto;
  }
  .pop-form {
    display: flex;
    flex-direction: column;
    gap: 10px;
    padding: 6px 10px 10px;
  }
  .pop-form .menu-label {
    padding: 0;
  }
  .pop-form .field + .field {
    margin-top: 0;
  }
  .pair {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 8px;
  }
  .row-end {
    display: flex;
    justify-content: flex-end;
    gap: 6px;
  }
  .pop-form > .btn {
    align-self: flex-end;
  }

  .chips {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 6px;
  }
  .chip {
    padding-right: 2px;
  }
  .chip.mono {
    font-size: 11.5px;
  }
  .chip-x {
    display: inline-grid;
    place-items: center;
    width: 18px;
    height: 18px;
    padding: 0;
    border: none;
    border-radius: 50%;
    background: transparent;
    color: inherit;
    cursor: pointer;
  }
  .chip-x:hover {
    background: var(--surface-pressed);
  }

  .tbl-card {
    overflow: hidden;
  }
  .scroll {
    overflow-x: auto;
  }
  .table {
    min-width: 1040px;
  }
  .table td {
    white-space: nowrap;
  }
  .w-exp {
    width: 40px;
    padding-right: 0;
  }
  .sm {
    font-size: 12px;
  }
  .res {
    max-width: 320px;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .dim td {
    opacity: 0.6;
  }
  .who {
    display: inline-flex;
    align-items: center;
    gap: 8px;
  }
  .avatar {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    flex: none;
    width: 24px;
    height: 24px;
    border-radius: 50%;
    background: var(--accent-soft);
    color: var(--accent-text);
    font-size: 10px;
    font-weight: 600;
  }
  .detail td {
    height: auto;
    padding: 0 16px 14px 56px;
    white-space: normal;
    background: var(--surface-hover);
  }
  .table tbody tr.detail:hover td {
    background: var(--surface-hover);
  }
  .detail-in {
    display: flex;
    flex-direction: column;
    gap: 8px;
    padding-top: 4px;
  }
  .detail-head {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 8px;
  }
  .mini {
    height: 20px;
    font-size: 11px;
  }
  .detail-actions {
    display: flex;
    gap: 6px;
    margin-left: auto;
  }
  .code {
    padding: 14px 16px;
    font-size: 12px;
    line-height: 19px;
    white-space: pre;
    overflow-x: auto;
  }
  .tok-k {
    color: var(--info);
  }
  .tok-s {
    color: var(--success);
  }
  .tok-n {
    color: var(--warning);
  }
  .state {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: center;
    gap: 12px;
    padding: 40px 16px;
  }
  .err {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    color: var(--danger);
  }
  .pager {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    padding: 10px 16px;
    border-top: 1px solid var(--border);
  }
  .pager-nav {
    display: flex;
    gap: 6px;
  }
  @media (max-width: 820px) {
    .export {
      margin-left: 0;
    }
    .res-search {
      max-width: none;
    }
  }
</style>
