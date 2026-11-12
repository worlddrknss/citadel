<script lang="ts">
  import { onMount } from 'svelte';
  import { base } from '$app/paths';
  import { api, errorMessage } from '$lib/api';
  import { param, setParams } from '$lib/url';
  import { session } from '$lib/stores/session.svelte';
  import { toast } from '$lib/stores/toast.svelte';
  import { confirm } from '$lib/stores/confirm.svelte';
  import PageHeader from '$lib/components/PageHeader.svelte';
  import DataTable, { type Column } from '$lib/components/DataTable.svelte';
  import EmptyState from '$lib/components/EmptyState.svelte';
  import Modal from '$lib/components/Modal.svelte';
  import Icon from '$lib/components/Icon.svelte';
  import CopyButton from '$lib/components/CopyButton.svelte';
  import ActionMenu, { type MenuItem } from './ActionMenu.svelte';
  import StatusBadge from './StatusBadge.svelte';
  import KeyPanel from './KeyPanel.svelte';
  import DeletionDialog from './DeletionDialog.svelte';
  import {
    statusOf,
    isManaged,
    primaryAlias,
    shortId,
    fmtDate,
    rotationLabel,
    USAGE_LABEL,
    SPECS,
    type Key,
    type Status
  } from './api';

  const canEdit = $derived(session.can('editor'));

  let keys = $state<Key[]>([]);
  let loading = $state(true);
  let loadError = $state('');

  // ---- URL state ------------------------------------------------------------
  const STATUS_FILTERS: { id: string; label: string; match?: Status }[] = [
    { id: 'all', label: 'All' },
    { id: 'enabled', label: 'Enabled', match: 'Enabled' },
    { id: 'disabled', label: 'Disabled', match: 'Disabled' },
    { id: 'pending', label: 'Pending deletion', match: 'Pending deletion' }
  ];
  const statusFilter = $derived(param('status', 'all'));
  const specFilter = $derived(param('spec'));
  const usageFilter = $derived(param('usage'));
  const selectedId = $derived(param('key'));
  let query = $state(param('q'));
  let tab = $state(param('tab', 'overview'));

  $effect(() => {
    setParams({ q: query.trim() || null });
  });
  $effect(() => {
    if (selectedId) setParams({ tab: tab === 'overview' ? null : tab });
  });

  function openKey(id: string, nextTab = 'overview') {
    tab = nextTab;
    setParams({ key: id, tab: nextTab === 'overview' ? null : nextTab });
  }
  function closeKey() {
    const id = selectedId;
    setParams({ key: null, tab: null });
    // Return focus to the row that opened the panel.
    requestAnimationFrame(() => document.querySelector<HTMLElement>(`[data-key-open="${CSS.escape(id)}"]`)?.focus());
  }

  // ---- Data -----------------------------------------------------------------
  async function load() {
    loadError = '';
    try {
      keys = (await api.kmsKeys()).keys as Key[];
    } catch (e) {
      loadError = errorMessage(e);
    } finally {
      loading = false;
    }
  }
  onMount(load);

  let panel = $state<{ refresh: () => void }>();
  function reloadAll() {
    load();
    panel?.refresh();
  }

  const counts = $derived(
    Object.fromEntries(
      STATUS_FILTERS.map((f) => [f.id, f.match ? keys.filter((k) => statusOf(k) === f.match).length : keys.length])
    ) as Record<string, number>
  );
  const specs = $derived([...new Set(keys.map((k) => k.keySpec))].sort());

  const rows = $derived(
    keys.filter((k) => {
      const f = STATUS_FILTERS.find((s) => s.id === statusFilter);
      if (f?.match && statusOf(k) !== f.match) return false;
      if (specFilter && k.keySpec !== specFilter) return false;
      if (usageFilter && k.keyUsage !== usageFilter) return false;
      return true;
    })
  );

  const columns: Column<Key>[] = [
    { id: 'alias', label: 'Alias / key ID', sort: (k) => primaryAlias(k) ?? `\uffff${k.keyId}` },
    { id: 'spec', label: 'Key spec', sort: (k) => k.keySpec },
    { id: 'usage', label: 'Usage', sort: (k) => k.keyUsage, hideOnMobile: true },
    { id: 'status', label: 'Status', sort: (k) => statusOf(k) },
    { id: 'rotation', label: 'Rotation', hideOnMobile: true },
    { id: 'created', label: 'Created', sort: (k) => new Date(k.createdAt), hideOnMobile: true },
    { id: 'actions', label: '', width: '48px', align: 'end' }
  ];
  let sortBy = $state('alias');
  let sortDir = $state<'asc' | 'desc'>('asc');

  // ---- Actions --------------------------------------------------------------
  async function toggle(k: Key) {
    const name = primaryAlias(k) ?? k.keyId;
    if (k.enabled) {
      const ok = await confirm({
        title: `Disable ${name}?`,
        message:
          'Encrypt, decrypt and every other operation with this key fail until you enable it again. Secrets and parameters encrypted with it become unreadable meanwhile.',
        confirmLabel: 'Disable key',
        danger: true
      });
      if (!ok) return;
    }
    try {
      await api.setKmsKeyEnabled(k.keyId, !k.enabled);
      toast.success(`${k.enabled ? 'Disabled' : 'Enabled'} ${name}`);
      reloadAll();
    } catch (e) {
      toast.error(e);
    }
  }

  let deleting = $state<Key | null>(null);
  let deleteOpen = $state(false);
  function askDelete(k: Key) {
    deleting = k;
    deleteOpen = true;
  }
  async function scheduleDeletion(days: number) {
    if (!deleting) return;
    const k = deleting;
    const res = await api.scheduleKmsKeyDeletion(k.keyId, days);
    toast.success(`${primaryAlias(k) ?? k.keyId} deletes on ${fmtDate(res.deletionDate)}`);
    reloadAll();
  }

  async function cancelDeletion(k: Key) {
    try {
      await api.cancelKmsKeyDeletion(k.keyId);
      toast.success(`Kept ${primaryAlias(k) ?? k.keyId}. It's disabled; enable it to use it again.`);
      reloadAll();
    } catch (e) {
      toast.error(e);
    }
  }

  async function copy(text: string, what: string) {
    try {
      await navigator.clipboard.writeText(text);
      toast.success(`Copied ${what}`);
    } catch (e) {
      toast.error(e, 'Copy failed');
    }
  }

  function rowMenu(k: Key): MenuItem[] {
    const items: MenuItem[] = [
      { label: 'View details', icon: 'eye', onselect: () => openKey(k.keyId) },
      { label: 'Copy key ID', icon: 'copy', onselect: () => copy(k.keyId, 'key ID') },
      { label: 'Copy ARN', icon: 'copy', onselect: () => copy(k.arn, 'ARN') }
    ];
    if (!canEdit) return items;
    if (k.deletionDate) {
      items.push({ label: 'Cancel deletion', icon: 'rotate', onselect: () => cancelDeletion(k) });
      return items;
    }
    items.push({ label: 'Add alias', icon: 'plus', onselect: () => openKey(k.keyId, 'aliases') });
    if (!isManaged(k)) {
      items.push({ label: k.enabled ? 'Disable' : 'Enable', icon: k.enabled ? 'eye-off' : 'check-circle', onselect: () => toggle(k) });
      items.push({ label: 'Schedule deletion', icon: 'trash', danger: true, onselect: () => askDelete(k) });
    }
    return items;
  }

  const filterLabel = (v: string, any: string, fmt: (v: string) => string = (x) => x) => (v ? fmt(v) : any);

  // ---- Create key -----------------------------------------------------------
  let createOpen = $state(false);
  let cDescription = $state('');
  let cUsage = $state('ENCRYPT_DECRYPT');
  let cSpec = $state('SYMMETRIC_DEFAULT');
  let cAlias = $state('');
  let creating = $state(false);
  let createError = $state('');
  const specChoice = $derived(SPECS[cUsage].find((s) => s.value === cSpec));

  function startCreate() {
    cDescription = '';
    cUsage = 'ENCRYPT_DECRYPT';
    cSpec = 'SYMMETRIC_DEFAULT';
    cAlias = '';
    createError = '';
    createOpen = true;
  }
  function pickUsage(u: string) {
    cUsage = u;
    cSpec = SPECS[u][0].value;
  }
  const aliasError = $derived.by(() => {
    const t = cAlias.trim();
    if (!t) return '';
    const full = t.startsWith('alias/') ? t : `alias/${t}`;
    if (!/^alias\/[A-Za-z0-9/_-]{1,250}$/.test(full)) return 'Use letters, numbers, /, _ and - after "alias/".';
    if (full === 'alias/default' || full.startsWith('alias/aws/')) return 'That alias is reserved.';
    return '';
  });

  async function createKey(e: SubmitEvent) {
    e.preventDefault();
    if (creating || aliasError) return;
    creating = true;
    createError = '';
    try {
      const res = await api.createKmsKey({ description: cDescription.trim(), keyUsage: cUsage, keySpec: cSpec });
      const t = cAlias.trim();
      if (t) {
        const full = t.startsWith('alias/') ? t : `alias/${t}`;
        try {
          await api.createKmsAlias(res.keyId, full);
        } catch (err) {
          toast.error(`Key created, but the alias failed: ${errorMessage(err)}`);
        }
      }
      toast.success(`Created key ${shortId(res.keyId)}`);
      createOpen = false;
      await load();
      openKey(res.keyId);
    } catch (err) {
      createError = errorMessage(err);
    } finally {
      creating = false;
    }
  }

  // ---- API endpoint ---------------------------------------------------------
  let endpointOpen = $state(false);
  const endpoint = $derived(typeof window === 'undefined' ? '' : window.location.origin);
</script>

<svelte:head><title>KMS keys · Citadel</title></svelte:head>

<PageHeader
  title="KMS keys"
  description="Customer managed keys{session.me ? ` for ${session.me.accountId}` : ''}. Compatible with the AWS KMS API and SDKs."
>
  {#snippet actions()}
    <button type="button" class="btn btn-ghost" onclick={() => (endpointOpen = true)}><Icon name="external-link" size={16} />API endpoint</button>
    {#if canEdit}
      <button type="button" class="btn btn-primary" onclick={startCreate}><Icon name="plus" size={16} />Create key</button>
    {/if}
  {/snippet}
</PageHeader>

<div class="layout">
  <div class="main-col">
    {#if loadError}
      <div class="callout callout-danger" role="alert">
        <Icon name="alert-circle" size={16} />
        <span class="grow">Couldn't load keys. {loadError}</span>
        <button type="button" class="btn btn-ghost btn-sm" onclick={() => { loading = true; load(); }}>Retry</button>
      </div>
    {/if}

    <DataTable
      {rows}
      {columns}
      key={(k) => k.keyId}
      {loading}
      caption="KMS keys"
      searchable={(k) => [k.keyId, k.arn, k.description, ...k.aliases].join(' ')}
      searchPlaceholder="Alias, key ID or ARN"
      bind:query
      bind:sortBy
      bind:sortDir
      selected={selectedId ? [selectedId] : []}
    >
      {#snippet toolbar()}
        <div class="seg" role="group" aria-label="Status filter">
          {#each STATUS_FILTERS as f (f.id)}
            <button type="button" aria-pressed={statusFilter === f.id} onclick={() => setParams({ status: f.id === 'all' ? null : f.id })}>
              {f.label}<span class="count">{counts[f.id] ?? 0}</span>
            </button>
          {/each}
        </div>
        <ActionMenu
          label="Filter by key spec"
          triggerClass="btn btn-secondary"
          items={[
            { label: 'Any key spec', checked: !specFilter, onselect: () => setParams({ spec: null }) },
            ...specs.map((s) => ({ label: s, checked: specFilter === s, onselect: () => setParams({ spec: s }) }))
          ]}
        >
          <Icon name="filter" size={16} />Key spec: <span class:mono={!!specFilter}>{filterLabel(specFilter, 'any')}</span><Icon name="chevron-down" size={14} />
        </ActionMenu>
        <ActionMenu
          label="Filter by usage"
          triggerClass="btn btn-secondary"
          items={[
            { label: 'Any usage', checked: !usageFilter, onselect: () => setParams({ usage: null }) },
            ...Object.entries(USAGE_LABEL).map(([v, l]) => ({ label: l, checked: usageFilter === v, onselect: () => setParams({ usage: v }) }))
          ]}
        >
          Usage: {filterLabel(usageFilter, 'any', (v) => USAGE_LABEL[v] ?? v)}<Icon name="chevron-down" size={14} />
        </ActionMenu>
      {/snippet}

      {#snippet row(k)}
        {@const alias = primaryAlias(k)}
        {@const status = statusOf(k)}
        <td>
          <button type="button" class="key-open" data-key-open={k.keyId} onclick={() => openKey(k.keyId)}
            aria-label="Open {alias ?? k.keyId}">
            <span class="mono key-name">
              {alias ?? k.keyId}
              {#if isManaged(k)}<span class="managed" title="Account default key"><Icon name="lock" size={12} /><span class="sr-only">(account default key)</span></span>{/if}
            </span>
            <span class="mono subtle key-sub">{alias ? shortId(k.keyId) : k.description || shortId(k.keyId)}</span>
          </button>
        </td>
        <td class="mono spec">{k.keySpec}</td>
        <td class="hide-sm nowrap">{USAGE_LABEL[k.keyUsage] ?? k.keyUsage}</td>
        <td class="nowrap">
          <StatusBadge {status} />
          {#if k.deletionDate}<span class="subtle deletes">deletes {fmtDate(k.deletionDate, false)}</span>{/if}
        </td>
        <td class="muted hide-sm nowrap">{rotationLabel(k)}</td>
        <td class="subtle hide-sm nowrap">{fmtDate(k.createdAt)}</td>
        <td class="end"><ActionMenu label="More actions for {alias ?? k.keyId}" items={rowMenu(k)} /></td>
      {/snippet}

      {#snippet empty()}
        <EmptyState icon="key" title="No KMS keys yet" description="Create a key to encrypt secrets and parameters, or to sign tokens. Keys never leave the FIPS 140 module.">
          {#if canEdit}
            <button type="button" class="btn btn-primary btn-sm" onclick={startCreate}><Icon name="plus" size={14} />Create key</button>
          {/if}
        </EmptyState>
      {/snippet}
    </DataTable>

    {#if !loading && keys.length > 0}
      <div class="table-foot">
        <span>{rows.length === keys.length ? `${keys.length} key${keys.length === 1 ? '' : 's'}` : `${rows.length} of ${keys.length} keys`}</span>
        <span class="fips"><Icon name="shield-check" size={14} />All keys are generated inside the FIPS 140 module</span>
      </div>
    {/if}
  </div>

  {#if selectedId}
    <KeyPanel
      bind:this={panel}
      keyId={selectedId}
      {keys}
      bind:tab
      {canEdit}
      onclose={closeKey}
      onchanged={load}
      ontoggle={toggle}
      onschedule={askDelete}
      oncancel={cancelDeletion}
    />
  {/if}
</div>

<DeletionDialog bind:open={deleteOpen} target={deleting} onconfirm={scheduleDeletion} />

<Modal bind:open={createOpen} title="Create key" description="The key material is generated inside the FIPS 140 module and never leaves it.">
  <form id="create-key" class="form" onsubmit={createKey}>
    <fieldset class="field">
      <legend class="field-label">Usage</legend>
      <div class="choices">
        {#each Object.entries(USAGE_LABEL) as [v, l] (v)}
          <label class="choice" class:on={cUsage === v}>
            <input type="radio" name="usage" value={v} checked={cUsage === v} onchange={() => pickUsage(v)} />
            <span class="choice-text">
              <span class="choice-title">{l}</span>
              <span class="subtle small">{v === 'ENCRYPT_DECRYPT' ? 'Protect secrets, parameters and data keys.' : 'Sign tokens and verify signatures.'}</span>
            </span>
          </label>
        {/each}
      </div>
    </fieldset>
    <label class="field">
      <span class="field-label">Key spec</span>
      <select class="select" bind:value={cSpec}>
        {#each SPECS[cUsage] as s (s.value)}<option value={s.value}>{s.label} · {s.value}</option>{/each}
      </select>
      {#if specChoice}<span class="field-hint">{specChoice.hint}</span>{/if}
    </label>
    <label class="field">
      <span class="field-label">Alias <span class="subtle opt">(optional)</span></span>
      <input class="input mono" bind:value={cAlias} placeholder="alias/payments-prod" autocomplete="off" spellcheck="false" aria-invalid={!!aliasError} />
      <span class={aliasError ? 'field-error' : 'field-hint'}>{aliasError || 'A stable name applications can use instead of the key ID.'}</span>
    </label>
    <label class="field">
      <span class="field-label">Description <span class="subtle opt">(optional)</span></span>
      <input class="input" bind:value={cDescription} maxlength="8192" placeholder="Encrypts payment secrets in production" />
    </label>
    <div class="callout callout-info" role="note">
      <Icon name="shield-check" size={16} />
      <span>FIPS 140-3 mode: only approved algorithms are offered (AES-256-GCM; RSA 2048+ and ECDSA P-256/P-384 with SHA-2; RSAES-OAEP-SHA-256).</span>
    </div>
    {#if createError}<p class="field-error" role="alert">{createError}</p>{/if}
  </form>
  {#snippet footer()}
    <button type="button" class="btn btn-ghost" onclick={() => (createOpen = false)}>Cancel</button>
    <button type="submit" form="create-key" class="btn btn-primary" disabled={creating || !!aliasError}>{creating ? 'Creating…' : 'Create key'}</button>
  {/snippet}
</Modal>

<Modal bind:open={endpointOpen} title="API endpoint" description="Point any AWS SDK or the AWS CLI at Citadel to use these keys." size="sm">
  <div class="form">
    <div class="field">
      <span class="field-label">Endpoint URL</span>
      <span class="endpoint"><code>{endpoint}</code><CopyButton value={endpoint} label="Copy endpoint URL" /></span>
    </div>
    <div class="field">
      <span class="field-label">AWS CLI</span>
      <pre class="snippet">aws kms list-keys --endpoint-url {endpoint}</pre>
    </div>
    <p class="field-hint">Authenticate with an access key from My account. Every call is written to the audit log.</p>
  </div>
  {#snippet footer()}
    <a class="btn btn-secondary" href="{base}/account">Access keys</a>
    <button type="button" class="btn btn-primary" onclick={() => (endpointOpen = false)}>Done</button>
  {/snippet}
</Modal>

<style>
  .layout {
    display: flex;
    flex-wrap: wrap;
    align-items: flex-start;
    gap: var(--space-5);
  }
  .main-col {
    flex: 999 1 560px;
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
  }
  .grow {
    flex: 1;
  }
  .key-open {
    display: flex;
    flex-direction: column;
    gap: 2px;
    padding: 0;
    border: 0;
    background: none;
    color: var(--text);
    font: inherit;
    text-align: start;
    cursor: pointer;
  }
  .key-open:hover .key-name {
    color: var(--accent-text);
    text-decoration: underline;
  }
  .key-name {
    white-space: nowrap;
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-weight: 500;
  }
  .managed {
    display: inline-flex;
    color: var(--info);
  }
  .key-sub {
    font-size: 11.5px;
    max-width: 280px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .spec {
    font-size: var(--text-sm);
  }
  .deletes {
    margin-left: var(--space-2);
    font-size: var(--text-sm);
  }
  @media (max-width: 720px) {
    .hide-sm {
      display: none;
    }
  }
  .table-foot {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: var(--space-2);
    padding: 0 var(--space-1);
    color: var(--text-subtle);
    font-size: var(--text-sm);
  }
  .fips {
    display: inline-flex;
    align-items: center;
    gap: 6px;
  }
  /* Segmented control (DesignSystem "seg"). */
  .seg {
    display: inline-flex;
    flex-wrap: wrap;
    gap: 2px;
    padding: 3px;
    border-radius: var(--radius-md);
    background: var(--surface-pressed);
  }
  .seg button {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    height: 28px;
    padding: 0 10px;
    border: 0;
    border-radius: var(--radius-sm);
    background: transparent;
    color: var(--text-muted);
    font: 500 var(--text-sm) / 1 var(--font-sans);
    white-space: nowrap;
    cursor: pointer;
  }
  .seg button[aria-pressed='true'] {
    background: var(--surface);
    color: var(--text);
    box-shadow: var(--shadow-xs);
  }
  .count {
    padding: 0 6px;
    border-radius: 999px;
    background: var(--surface-pressed);
    color: var(--text-muted);
    font: 500 var(--text-xs) / 16px var(--font-sans);
    font-variant-numeric: tabular-nums;
  }
  .seg button[aria-pressed='true'] .count {
    background: var(--surface-hover);
  }
  .form {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
  }
  .form .field + .field {
    margin-top: 0;
  }
  fieldset {
    margin: 0;
    padding: 0;
    border: 0;
  }
  .choices {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: var(--space-2);
  }
  .choice {
    display: flex;
    align-items: flex-start;
    gap: var(--space-2);
    padding: var(--space-3);
    border: 1px solid var(--border-strong);
    border-radius: var(--radius-md);
    cursor: pointer;
  }
  .choice.on {
    border-color: var(--accent);
    background: var(--accent-soft);
  }
  .choice input {
    margin-top: 2px;
  }
  .choice-text {
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .choice-title {
    font-weight: 500;
  }
  .opt {
    font-weight: 400;
  }
  .endpoint {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    min-width: 0;
  }
  .endpoint code {
    overflow-wrap: anywhere;
  }
  .snippet {
    white-space: pre-wrap;
    word-break: break-all;
  }
</style>
