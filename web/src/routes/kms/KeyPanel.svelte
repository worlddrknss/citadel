<!--
  Key detail panel. Docks beside the table on wide screens and stacks under it
  on narrow ones, as in the KMS board.
-->
<script lang="ts">
  import { tick } from 'svelte';
  import { api, errorMessage } from '#lib/api.ts';
  import { session } from '#lib/stores/session.svelte.ts';
  import Icon from '#lib/components/Icon.svelte';
  import Badge from '#lib/components/Badge.svelte';
  import Tabs from '#lib/components/Tabs.svelte';
  import CopyButton from '#lib/components/CopyButton.svelte';
  import StatusBadge from './StatusBadge.svelte';
  import TryIt from './TryIt.svelte';
  import PolicyEditor from './PolicyEditor.svelte';
  import GrantsTab from './GrantsTab.svelte';
  import RotationTab from './RotationTab.svelte';
  import AliasesTab from './AliasesTab.svelte';
  import TagsEditor from './TagsEditor.svelte';
  import {
    kms,
    statusOf,
    isManaged,
    primaryAlias,
    fmtDate,
    rotationLabel,
    originLabel,
    encryptionAlgorithms,
    signingAlgorithms,
    USAGE_LABEL,
    type Key,
    type KeyDetail,
    type Tag
  } from './api';

  let {
    keyId,
    keys,
    tab = $bindable('overview'),
    canEdit,
    onclose,
    onchanged,
    ontoggle,
    onschedule,
    oncancel
  }: {
    keyId: string;
    keys: Key[];
    tab?: string;
    canEdit: boolean;
    onclose: () => void;
    /** The key changed; reload the list. */
    onchanged: () => void;
    ontoggle: (k: Key) => void;
    onschedule: (k: Key) => void;
    oncancel: (k: Key) => void;
  } = $props();

  // Scheduling and cancelling deletion are admin-only on the server.
  const canAdmin = $derived(session.can('admin'));
  let detail = $state<KeyDetail | null>(null);
  let loading = $state(true);
  let error = $state('');
  let tags = $state<Tag[]>([]);
  let tagsLoading = $state(false);
  let tagsError = $state('');
  let heading = $state<HTMLHeadingElement>();
  let panel = $state<HTMLElement>();
  let aliasesTab = $state<{ focusAdd: () => void }>();

  const listKey = $derived(keys.find((k) => k.keyId === keyId));

  async function load(id: string, quiet = false) {
    if (!quiet) loading = true;
    error = '';
    try {
      const d = await api.kmsKeyDetail(id);
      if (id !== keyId) return;
      detail = d as KeyDetail;
    } catch (e) {
      if (id === keyId) error = errorMessage(e);
    } finally {
      if (id === keyId) loading = false;
    }
  }

  async function loadTags(id: string) {
    tagsLoading = true;
    tagsError = '';
    try {
      const r = await kms.tags(id);
      if (id === keyId) tags = r.tags ?? [];
    } catch (e) {
      if (id === keyId) tagsError = errorMessage(e);
    } finally {
      tagsLoading = false;
    }
  }

  $effect(() => {
    const id = keyId;
    detail = null;
    tags = [];
    load(id);
    loadTags(id);
    tick().then(() => {
      heading?.focus({ preventScroll: true });
      if (panel && window.matchMedia('(max-width: 1100px)').matches) panel.scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
  });

  export function refresh() {
    load(keyId, true);
  }

  function changed() {
    load(keyId, true);
    onchanged();
  }

  const title = $derived(detail ? (primaryAlias(detail) ?? detail.keyId) : (listKey ? (primaryAlias(listKey) ?? listKey.keyId) : keyId));
  const managed = $derived(detail ? isManaged(detail) : listKey ? isManaged(listKey) : false);
  const status = $derived(detail ? statusOf(detail) : listKey ? statusOf(listKey) : 'Enabled');
  const asKey = $derived((detail ? { ...listKey, ...detail } : listKey) as Key | undefined);

  const tabs = $derived([
    { id: 'overview', label: 'Overview' },
    { id: 'aliases', label: 'Aliases', count: detail?.aliases.length },
    { id: 'policy', label: 'Policy' },
    { id: 'grants', label: 'Grants', count: detail?.grants.length },
    { id: 'rotation', label: 'Rotation' },
    { id: 'tags', label: 'Tags', count: tagsLoading || tagsError ? undefined : tags.length }
  ]);

  async function addAlias() {
    tab = 'aliases';
    await tick();
    aliasesTab?.focusAdd();
  }

  function downloadPem(pem: string) {
    const url = URL.createObjectURL(new Blob([pem], { type: 'application/x-pem-file' }));
    const a = document.createElement('a');
    a.href = url;
    a.download = `${keyId}-public.pem`;
    a.click();
    URL.revokeObjectURL(url);
  }

  function onkeydown(e: KeyboardEvent) {
    if (e.key === 'Escape' && !e.defaultPrevented) {
      e.preventDefault();
      onclose();
    }
  }
</script>

<!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
<aside class="panel" aria-labelledby="kd-title" bind:this={panel} {onkeydown}>
  <div class="head">
    <span class="tile" aria-hidden="true"><Icon name="key" size={18} /></span>
    <div class="titles">
      <h2 id="kd-title" class="mono" tabindex="-1" bind:this={heading}>{title}</h2>
      <div class="badges">
        <StatusBadge {status} />
        {#if detail || listKey}<span class="outline mono">{(detail ?? listKey)?.keySpec}</span>{/if}
        {#if managed}<Badge tone="info" dot={false}><Icon name="lock" size={12} />Account default</Badge>{/if}
      </div>
    </div>
    {#if detail}<CopyButton value={detail.arn} label="Copy ARN" />{/if}
    <button type="button" class="btn-icon" aria-label="Close key details" title="Close" onclick={onclose}><Icon name="x" size={16} /></button>
  </div>

  <div class="tabs-wrap"><Tabs {tabs} bind:active={tab} label="Key detail" /></div>

  <div class="body" role="tabpanel" aria-label={tabs.find((t) => t.id === tab)?.label}>
    {#if loading && !detail}
      <div class="skel" aria-busy="true" aria-label="Loading key">
        {#each Array(6) as _, i (i)}<span class="skeleton" style:width="{60 + ((i * 13) % 35)}%"></span>{/each}
      </div>
    {:else if error}
      <div class="callout callout-danger" role="alert">
        <Icon name="alert-circle" size={16} />
        <span class="grow">{error}</span>
        <button type="button" class="btn btn-ghost btn-sm" onclick={() => load(keyId)}>Retry</button>
      </div>
    {:else if detail}
      {#if tab === 'overview'}
        {#if managed}
          <div class="callout callout-info" role="note">
            <Icon name="lock" size={16} />
            <span>This is the account's managed default key, reached through <span class="mono">alias/default</span>. Citadel uses it when no key is chosen. It can't be disabled, deleted or re-aliased.</span>
          </div>
        {/if}
        {#if detail.deletionDate}
          <div class="callout callout-danger" role="note">
            <Icon name="clock" size={16} />
            <span>Scheduled for deletion on <strong>{fmtDate(detail.deletionDate)}</strong>. After that, data encrypted with this key can never be decrypted.{canEdit ? ' Cancel the deletion to keep it.' : ''}</span>
          </div>
        {/if}
        <dl class="kv dl">
          <dt>Key ID</dt>
          <dd class="with-copy"><span class="mono id">{detail.keyId}</span><CopyButton value={detail.keyId} label="Copy key ID" /></dd>
          <dt>ARN</dt>
          <dd class="mono id">{detail.arn}</dd>
          {#if detail.description}<dt>Description</dt><dd>{detail.description}</dd>{/if}
          <dt>Usage</dt>
          <dd>{USAGE_LABEL[detail.keyUsage] ?? detail.keyUsage}</dd>
          <dt>Algorithms</dt>
          <dd class="mono id">{(detail.keyUsage === 'SIGN_VERIFY' ? signingAlgorithms(detail) : encryptionAlgorithms(detail)).join(', ')}</dd>
          <dt>Origin</dt>
          <dd>{originLabel(detail.origin)}</dd>
          <dt>Rotation</dt>
          <dd>
            {asKey ? rotationLabel(asKey) : '—'}
            <button type="button" class="linklike small" onclick={() => (tab = 'rotation')}>Details</button>
          </dd>
          {#if detail.usedBy}
            <dt>Used by</dt>
            <dd>{detail.usedBy.secrets} secret{detail.usedBy.secrets === 1 ? '' : 's'}, {detail.usedBy.parameters} SecureString parameter{detail.usedBy.parameters === 1 ? '' : 's'}</dd>
          {/if}
          <dt>Created</dt>
          <dd>{fmtDate(detail.createdAt)}</dd>
          <dt>State</dt>
          <dd class="mono id">{detail.keyState}</dd>
        </dl>

        {#if detail.publicKeyPem}
          <div class="field">
            <span class="pem-head">
              <span class="field-label">Public key</span>
              <span class="pem-acts">
                <CopyButton value={detail.publicKeyPem} label="Copy public key" />
                <button type="button" class="btn-icon" aria-label="Download public key (.pem)" title="Download .pem" onclick={() => downloadPem(detail!.publicKeyPem!)}>
                  <Icon name="download" size={14} />
                </button>
              </span>
            </span>
            <pre class="pem">{detail.publicKeyPem}</pre>
          </div>
        {/if}

        {#if canEdit}<TryIt {detail} />{/if}
      {:else if tab === 'aliases'}
        <AliasesTab bind:this={aliasesTab} {detail} {keys} {canEdit} onchanged={changed} />
      {:else if tab === 'policy'}
        <PolicyEditor {detail} {canEdit} onsaved={() => load(keyId, true)} />
      {:else if tab === 'grants'}
        <GrantsTab {detail} {canEdit} onchanged={() => load(keyId, true)} />
      {:else if tab === 'rotation'}
        <RotationTab {detail} canEdit={canEdit && !detail.deletionDate} onchanged={onchanged} />
      {:else if tab === 'tags'}
        <TagsEditor
          {tags}
          loading={tagsLoading}
          error={tagsError}
          {canEdit}
          resource="this key"
          onadd={async (k, v) => {
            await kms.tag(keyId, [{ key: k, value: v }]);
            await loadTags(keyId);
          }}
          onremove={async (k) => {
            await kms.untag(keyId, k);
            await loadTags(keyId);
          }}
        />
      {/if}
    {/if}
  </div>

  {#if canEdit && asKey && detail}
    <div class="foot">
      {#if detail.deletionDate}
        {#if canAdmin}
          <button type="button" class="btn btn-secondary btn-sm" onclick={() => oncancel(asKey)}><Icon name="rotate" size={14} />Cancel deletion</button>
        {:else}
          <span class="subtle small">An admin can cancel the deletion.</span>
        {/if}
      {:else}
        <button type="button" class="btn btn-secondary btn-sm" onclick={addAlias}><Icon name="plus" size={14} />Add alias</button>
        {#if managed}
          <span class="subtle small managed-note"><Icon name="lock" size={12} />Managed keys can't be disabled or deleted</span>
        {:else}
          <button type="button" class="btn btn-secondary btn-sm" onclick={() => ontoggle(asKey)}>{detail.enabled ? 'Disable' : 'Enable'}</button>
          {#if canAdmin}
            <button type="button" class="btn btn-danger-ghost btn-sm push" onclick={() => onschedule(asKey)}><Icon name="trash" size={14} />Schedule deletion</button>
          {/if}
        {/if}
      {/if}
    </div>
  {/if}
</aside>

<style>
  .panel {
    flex: 1 1 420px;
    max-width: 500px;
    min-width: 0;
    align-self: flex-start;
    display: flex;
    flex-direction: column;
    overflow: hidden;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    box-shadow: var(--shadow-lg);
  }
  @media (max-width: 1100px) {
    .panel {
      max-width: none;
      flex-basis: 100%;
    }
  }
  .head {
    display: flex;
    align-items: flex-start;
    gap: var(--space-3);
    padding: var(--space-4) var(--space-4) 0;
  }
  .tile {
    display: inline-grid;
    place-items: center;
    flex: none;
    width: 36px;
    height: 36px;
    border-radius: var(--radius-md);
    background: var(--accent-soft);
    color: var(--accent-text);
  }
  .titles {
    display: flex;
    flex-direction: column;
    gap: 4px;
    flex: 1 1 auto;
    min-width: 0;
  }
  h2 {
    margin: 0;
    font-family: var(--font-mono);
    font-size: var(--text-lg);
    font-weight: 600;
    letter-spacing: -0.01em;
    overflow-wrap: anywhere;
  }
  h2:focus {
    outline: none;
  }
  .badges {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
  }
  .outline {
    display: inline-flex;
    align-items: center;
    height: 22px;
    padding: 0 8px;
    border-radius: 999px;
    box-shadow: inset 0 0 0 1px var(--border-strong);
    color: var(--text-muted);
    font-size: 12.5px;
    font-weight: 500;
  }
  .tabs-wrap {
    margin-top: var(--space-3);
    padding: 0 var(--space-2);
  }
  .body {
    display: flex;
    flex-direction: column;
    gap: var(--space-5);
    padding: var(--space-4);
    min-width: 0;
  }
  .skel {
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
  }
  .skel .skeleton {
    height: 14px;
  }
  .grow {
    flex: 1;
  }
  .dl {
    grid-template-columns: 120px minmax(0, 1fr);
    gap: 10px var(--space-4);
    align-items: baseline;
  }
  @media (max-width: 480px) {
    .dl {
      grid-template-columns: minmax(0, 1fr);
      gap: 2px 0;
    }
    .dl dd {
      margin-bottom: var(--space-2);
    }
  }
  .with-copy {
    display: flex;
    align-items: center;
    gap: 4px;
  }
  .id {
    font-size: var(--text-sm);
    overflow-wrap: anywhere;
  }
  .linklike {
    margin-left: var(--space-2);
  }
  .pem-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
  }
  .pem-acts {
    display: inline-flex;
  }
  .pem {
    font-size: 12px;
    white-space: pre-wrap;
    word-break: break-all;
    max-height: 220px;
  }
  .foot {
    margin-top: auto;
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--space-2);
    padding: var(--space-3) var(--space-4);
    border-top: 1px solid var(--border);
    background: var(--surface-hover);
  }
  .push {
    margin-left: auto;
  }
  .managed-note {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    margin-left: auto;
  }
</style>
