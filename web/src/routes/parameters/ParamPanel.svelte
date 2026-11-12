<!-- Parameter detail panel: overview, version history with labels, tags. -->
<script lang="ts">
  import { tick } from 'svelte';
  import { base } from '$app/paths';
  import { api, errorMessage, type KMSKey, type ParameterHistoryEntry, type ParameterTag } from '$lib/api';
  import Icon from '$lib/components/Icon.svelte';
  import Badge from '$lib/components/Badge.svelte';
  import Tabs from '$lib/components/Tabs.svelte';
  import CopyButton from '$lib/components/CopyButton.svelte';
  import SecretValue from '$lib/components/SecretValue.svelte';
  import { toast } from '$lib/stores/toast.svelte';
  import TagsEditor from '../kms/TagsEditor.svelte';
  import InlineValue from './InlineValue.svelte';
  import { params, leaf, parentPath, fmtDateTime, TYPE_TONE, type Param } from './api';

  let {
    param,
    kmsKeys,
    tab = $bindable('overview'),
    canEdit,
    onclose,
    onedit,
    ondelete
  }: {
    param: Param;
    kmsKeys: KMSKey[];
    tab?: string;
    canEdit: boolean;
    onclose: () => void;
    onedit: () => void;
    ondelete: () => void;
  } = $props();

  let history = $state<ParameterHistoryEntry[]>([]);
  let historyLoading = $state(true);
  let historyError = $state('');
  let tags = $state<ParameterTag[]>([]);
  let tagsLoading = $state(true);
  let tagsError = $state('');
  let heading = $state<HTMLHeadingElement>();
  let panel = $state<HTMLElement>();

  // Label editing
  let labeling = $state<number | null>(null);
  let labelText = $state('');
  let labelBusy = $state(false);
  let labelError = $state('');

  const name = $derived(param.name);
  const version = $derived(param.version);
  const secure = $derived(param.type === 'SecureString');
  const sorted = $derived([...history].sort((a, b) => b.version - a.version));
  const currentLabels = $derived(history.find((h) => h.version === param.version)?.labels ?? []);
  const kmsKey = $derived(kmsKeys.find((k) => k.keyId === param.kmsKeyId || k.arn === param.kmsKeyId || k.aliases.includes(param.kmsKeyId ?? '')));

  async function loadHistory(n: string) {
    historyLoading = true;
    historyError = '';
    try {
      const r = await api.parameterHistory(n);
      if (n === name) history = r.history ?? [];
    } catch (e) {
      if (n === name) historyError = errorMessage(e);
    } finally {
      historyLoading = false;
    }
  }

  async function loadTags(n: string) {
    tagsLoading = true;
    tagsError = '';
    try {
      const r = await api.parameterTags(n);
      if (n === name) tags = r.tags ?? [];
    } catch (e) {
      if (n === name) tagsError = errorMessage(e);
    } finally {
      tagsLoading = false;
    }
  }

  // Reload when another parameter is selected or a new version is saved.
  $effect(() => {
    const n = name;
    void version;
    labeling = null;
    loadHistory(n);
  });
  $effect(() => {
    const n = name;
    tags = [];
    loadTags(n);
    tick().then(() => {
      heading?.focus({ preventScroll: true });
      if (panel && window.matchMedia('(max-width: 1100px)').matches) panel.scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
  });

  const tabs = $derived([
    { id: 'overview', label: 'Overview' },
    { id: 'history', label: 'History', count: historyLoading ? undefined : history.length },
    { id: 'tags', label: 'Tags', count: tagsLoading || tagsError ? undefined : tags.length }
  ]);

  function startLabel(v: number) {
    labeling = v;
    labelText = '';
    labelError = '';
  }

  async function applyLabels(e: SubmitEvent) {
    e.preventDefault();
    if (labeling === null || labelBusy) return;
    const labels = labelText.split(',').map((s) => s.trim()).filter(Boolean);
    if (labels.length === 0) {
      labelError = 'Enter at least one label.';
      return;
    }
    const bad = labels.find((l) => !/^[A-Za-z0-9_.-]{1,100}$/.test(l) || /^(aws|ssm)/i.test(l) || /^\d/.test(l));
    if (bad) {
      labelError = `"${bad}" isn't a valid label. Use letters, numbers, _ . - and don't start with a digit, aws or ssm.`;
      return;
    }
    labelBusy = true;
    labelError = '';
    try {
      await api.labelParameterVersion(name, labeling, labels);
      toast.success(`Labeled version ${labeling}: ${labels.join(', ')}`);
      labeling = null;
      await loadHistory(name);
    } catch (err) {
      labelError = errorMessage(err);
    } finally {
      labelBusy = false;
    }
  }

  async function removeLabel(v: number, label: string) {
    try {
      await params.unlabel(name, v, [label]);
      toast.success(`Removed label ${label} from version ${v}`);
      await loadHistory(name);
    } catch (e) {
      toast.error(e);
    }
  }

  function onkeydown(e: KeyboardEvent) {
    if (e.key === 'Escape' && !e.defaultPrevented) {
      e.preventDefault();
      onclose();
    }
  }
</script>

<!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
<aside class="panel" aria-labelledby="pd-title" bind:this={panel} {onkeydown}>
  <div class="head">
    <div class="titles">
      <span class="mono subtle path">{parentPath(param.name)}</span>
      <h2 id="pd-title" class="mono" tabindex="-1" bind:this={heading}>{leaf(param.name)}</h2>
      <div class="badges">
        <Badge tone={TYPE_TONE[param.type]} dot={false}>{#if secure}<Icon name="lock" size={12} />{/if}{param.type}</Badge>
        <span class="outline mono">v{param.version}</span>
        {#if param.tier === 'Advanced'}<span class="outline">Advanced</span>{/if}
        {#each currentLabels as l (l)}<Badge tone="info" dot={false}><Icon name="tag" size={12} />{l}</Badge>{/each}
      </div>
    </div>
    <CopyButton value={param.name} label="Copy parameter name" />
    <button type="button" class="btn-icon" aria-label="Close parameter details" title="Close" onclick={onclose}><Icon name="x" size={16} /></button>
  </div>

  <div class="tabs-wrap"><Tabs {tabs} bind:active={tab} label="Parameter detail" /></div>

  <div class="body" role="tabpanel" aria-label={tabs.find((t) => t.id === tab)?.label}>
    {#if tab === 'overview'}
      <div class="value-box">
        <span class="label">Current value</span>
        <div class="value-row">
          {#key `${param.name}:${param.version}`}
            {#if secure}
              <SecretValue load={async () => (await api.revealParameter(param.name)).value} />
            {:else}
              <InlineValue auto list={param.type === 'StringList'} initial={param.value} load={async () => (await api.revealParameter(param.name)).value} />
            {/if}
          {/key}
        </div>
        {#if secure}<span class="field-hint">Revealed values hide after 30 s and every reveal is logged.</span>{/if}
      </div>
      <dl class="kv dl">
        <dt>Name</dt>
        <dd class="mono id">{param.name}</dd>
        <dt>Type</dt>
        <dd>{param.type}</dd>
        <dt>Tier</dt>
        <dd>{param.tier}</dd>
        <dt>Version</dt>
        <dd class="num">{param.version}</dd>
        {#if secure}
          <dt>Encrypted with</dt>
          <dd>
            {#if param.kmsKeyId}
              <a class="mono key-link" href="{base}/kms?key={encodeURIComponent(kmsKey?.keyId ?? param.kmsKeyId)}">
                <Icon name="key" size={14} />{kmsKey ? ([...kmsKey.aliases].sort()[0] ?? kmsKey.keyId) : param.kmsKeyId}
              </a>
            {:else}
              <span class="mono">alias/default</span>
            {/if}
          </dd>
        {/if}
        <dt>Description</dt>
        <dd>{param.description || '—'}</dd>
        <dt>Last modified</dt>
        <dd>{fmtDateTime(param.lastModified)}</dd>
      </dl>
    {:else if tab === 'history'}
      {#if historyLoading && history.length === 0}
        <div class="skel" aria-busy="true" aria-label="Loading history">
          <span class="skeleton"></span><span class="skeleton"></span><span class="skeleton"></span>
        </div>
      {:else if historyError}
        <div class="callout callout-danger" role="alert">
          <Icon name="alert-circle" size={16} /><span class="grow">{historyError}</span>
          <button type="button" class="btn btn-ghost btn-sm" onclick={() => loadHistory(name)}>Retry</button>
        </div>
      {:else if sorted.length === 0}
        <p class="subtle small">No history recorded.</p>
      {:else}
        <ol class="timeline">
          {#each sorted as h (h.version)}
            <li>
              <span class="rail" aria-hidden="true"><span class="dot" class:current={h.version === param.version}></span><span class="line-v"></span></span>
              <div class="entry">
                <div class="entry-top">
                  <span class="mono strong">v{h.version}</span>
                  {#if h.version === param.version}<Badge tone="success" dot={false}>Current</Badge>{/if}
                  {#if h.type !== param.type}<span class="outline">{h.type}</span>{/if}
                  {#each h.labels as l (l)}
                    <span class="label-chip">
                      <Icon name="tag" size={12} />{l}
                      {#if canEdit}
                        <button type="button" class="chip-x" aria-label="Remove label {l} from version {h.version}" onclick={() => removeLabel(h.version, l)}>
                          <Icon name="x" size={12} />
                        </button>
                      {/if}
                    </span>
                  {/each}
                  {#if canEdit && labeling !== h.version}
                    <button type="button" class="btn btn-ghost btn-sm push" onclick={() => startLabel(h.version)}><Icon name="tag" size={14} />Label</button>
                  {/if}
                </div>
                <span class="subtle small">{fmtDateTime(h.modifiedAt)}{h.description ? ` · ${h.description}` : ''}</span>
                <div class="hist-val">
                  {#if h.type === 'SecureString'}
                    <SecretValue load={async () => (await params.revealVersion(name, h.version)).value} />
                  {:else}
                    <InlineValue list={h.type === 'StringList'} load={async () => (await params.revealVersion(name, h.version)).value} />
                  {/if}
                </div>
                {#if labeling === h.version}
                  <form class="label-form" onsubmit={applyLabels}>
                    <label class="field grow">
                      <span class="field-label">Labels for v{h.version}</span>
                      <!-- svelte-ignore a11y_autofocus -->
                      <input class="input mono" bind:value={labelText} placeholder="stable, release-42" autocomplete="off" autofocus
                        aria-invalid={!!labelError} />
                      <span class={labelError ? 'field-error' : 'field-hint'}>{labelError || 'Comma-separated. A label moves here if another version has it.'}</span>
                    </label>
                    <span class="label-btns">
                      <button type="button" class="btn btn-ghost btn-sm" onclick={() => (labeling = null)}>Cancel</button>
                      <button type="submit" class="btn btn-primary btn-sm" disabled={labelBusy}>{labelBusy ? 'Saving…' : 'Apply'}</button>
                    </span>
                  </form>
                {/if}
              </div>
            </li>
          {/each}
        </ol>
      {/if}
    {:else if tab === 'tags'}
      <TagsEditor
        {tags}
        loading={tagsLoading}
        error={tagsError}
        {canEdit}
        resource="this parameter"
        onadd={async (k, v) => {
          await api.tagParameter(name, { [k]: v });
          await loadTags(name);
        }}
        onremove={async (k) => {
          await api.untagParameter(name, [k]);
          await loadTags(name);
        }}
      />
    {/if}
  </div>

  {#if canEdit}
    <div class="foot">
      <button type="button" class="btn btn-primary btn-sm" onclick={onedit}><Icon name="edit" size={14} />Edit</button>
      <button type="button" class="btn btn-danger-ghost btn-sm push" onclick={ondelete}><Icon name="trash" size={14} />Delete</button>
    </div>
  {/if}
</aside>

<style>
  .panel {
    flex: 1 1 400px;
    max-width: 480px;
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
  .titles {
    display: flex;
    flex-direction: column;
    gap: 4px;
    flex: 1 1 auto;
    min-width: 0;
  }
  .path {
    font-size: var(--text-sm);
    overflow-wrap: anywhere;
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
    margin-top: 2px;
  }
  .outline {
    display: inline-flex;
    align-items: center;
    height: 22px;
    padding: 0 8px;
    border-radius: 999px;
    box-shadow: inset 0 0 0 1px var(--border-strong);
    color: var(--text-muted);
    font-size: 11.5px;
    font-weight: 500;
  }
  .tabs-wrap {
    margin-top: var(--space-2);
    padding: 0 var(--space-2);
  }
  .body {
    display: flex;
    flex-direction: column;
    gap: var(--space-5);
    padding: var(--space-4);
    min-width: 0;
  }
  .label {
    font: 600 var(--text-xs) / 16px var(--font-sans);
    letter-spacing: 0.06em;
    text-transform: uppercase;
    color: var(--text-subtle);
  }
  .value-box {
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
  }
  .value-row {
    display: flex;
    align-items: center;
    min-height: 40px;
    padding: 4px 6px 4px var(--space-3);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: var(--surface-hover);
    min-width: 0;
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
  .id {
    font-size: var(--text-sm);
    overflow-wrap: anywhere;
  }
  .key-link {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    overflow-wrap: anywhere;
  }
  .skel {
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
  }
  .skel .skeleton {
    height: 32px;
    width: 100%;
  }
  .grow {
    flex: 1;
  }
  .timeline {
    list-style: none;
    margin: 0;
    padding: 0;
  }
  .timeline li {
    display: grid;
    grid-template-columns: 16px minmax(0, 1fr);
    gap: var(--space-3);
  }
  .rail {
    display: flex;
    flex-direction: column;
    align-items: center;
  }
  .dot {
    width: 10px;
    height: 10px;
    margin-top: 9px;
    border-radius: 50%;
    background: var(--surface-pressed);
    border: 2px solid var(--surface);
    box-shadow: 0 0 0 1px var(--border-strong);
  }
  .dot.current {
    background: var(--accent);
  }
  .line-v {
    flex: 1;
    width: 1px;
    background: var(--border);
  }
  .timeline li:last-child .line-v {
    display: none;
  }
  .entry {
    display: flex;
    flex-direction: column;
    gap: 4px;
    padding-bottom: var(--space-4);
    min-width: 0;
  }
  .entry-top {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 6px;
    min-height: 28px;
  }
  .strong {
    font-weight: 500;
  }
  .push {
    margin-left: auto;
  }
  .label-chip {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    height: 22px;
    padding: 0 4px 0 8px;
    border-radius: 999px;
    background: var(--info-soft);
    color: var(--info);
    font-size: var(--text-sm);
    font-weight: 500;
  }
  .chip-x {
    display: inline-grid;
    place-items: center;
    width: 18px;
    height: 18px;
    padding: 0;
    border: 0;
    border-radius: 50%;
    background: none;
    color: inherit;
    cursor: pointer;
  }
  .chip-x:hover {
    background: var(--surface);
  }
  .hist-val {
    min-width: 0;
  }
  .label-form {
    display: flex;
    flex-wrap: wrap;
    align-items: flex-start;
    gap: var(--space-2);
    margin-top: var(--space-2);
    padding: var(--space-3);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: var(--surface-hover);
  }
  .label-btns {
    display: flex;
    gap: var(--space-2);
    margin-top: 22px;
  }
  .foot {
    margin-top: auto;
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-2);
    padding: var(--space-3) var(--space-4);
    border-top: 1px solid var(--border);
    background: var(--surface-hover);
  }
</style>
