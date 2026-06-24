<script lang="ts">
  import { onMount } from 'svelte';
  import {
    api,
    ApiError,
    type Parameter,
    type ParameterType,
    type ParameterTier,
    type ParameterHistoryEntry,
    type ParameterTag,
    type KMSKey
  } from '$lib/api';

  let params: Parameter[] = $state([]);
  let kmsKeys: KMSKey[] = $state([]);
  let loading = $state(false);

  // Current folder path as segments, e.g. ["app", "prod"]. Root is [].
  let pathSegs: string[] = $state([]);

  let flash = $state('');
  let flashOk = $state(true);

  // Reveal cache: parameter name -> decrypted value.
  let revealed: Record<string, string> = $state({});

  // New-parameter form.
  let newName = $state('');
  let newType: ParameterType = $state('String');
  let newValue = $state('');
  let newTier: ParameterTier = $state('Standard');
  let newKms = $state('');
  let newDescription = $state('');
  let overwrite = $state(false);

  // Detail drawer.
  let detail: Parameter | null = $state(null);
  let detailTab: 'history' | 'tags' = $state('history');
  let history: ParameterHistoryEntry[] = $state([]);
  let tags: ParameterTag[] = $state([]);
  let tagKey = $state('');
  let tagValue = $state('');
  let labelVersion = $state('');
  let labelText = $state('');

  // Confirm modal (avoids native confirm per UX guidelines).
  let confirmOpen = $state(false);
  let confirmTitle = $state('');
  let confirmBody = $state('');
  let confirmLabel = $state('Confirm');
  let confirmAction: (() => Promise<void>) | null = $state(null);

  const prefix = $derived(pathSegs.length ? '/' + pathSegs.join('/') + '/' : '/');

  // Subfolders directly under the current path.
  const subfolders = $derived.by(() => {
    const set = new Set<string>();
    for (const p of params) {
      if (!p.name.startsWith(prefix)) continue;
      const rest = p.name.slice(prefix.length);
      const slash = rest.indexOf('/');
      if (slash > 0) set.add(rest.slice(0, slash));
    }
    return [...set].sort();
  });

  // Parameters directly at the current path (no further nesting).
  const currentParams = $derived(
    params
      .filter((p) => p.name.startsWith(prefix) && !p.name.slice(prefix.length).includes('/'))
      .sort((a, b) => a.name.localeCompare(b.name))
  );

  function leaf(name: string): string {
    const i = name.lastIndexOf('/');
    return i >= 0 ? name.slice(i + 1) : name;
  }

  function notify(msg: string, ok = true) {
    flash = msg;
    flashOk = ok;
    setTimeout(() => (flash = ''), 4000);
  }

  function err(e: unknown) {
    if (e instanceof ApiError) notify(e.message, false);
    else notify('Unexpected error', false);
  }

  function kmsLabel(k: KMSKey): string {
    const alias = (k.aliases ?? []).find((a) => a && a.trim());
    if (alias) {
      const name = alias.replace(/^alias\//, '');
      return `${name} · ${k.keyId.slice(0, 8)}…`;
    }
    return k.keyId;
  }

  function openFolder(name: string) {
    pathSegs = [...pathSegs, name];
  }

  function crumbTo(idx: number) {
    pathSegs = pathSegs.slice(0, idx);
  }

  async function loadParams() {
    loading = true;
    try {
      params = (await api.parameters()).parameters;
    } catch (e) {
      err(e);
    } finally {
      loading = false;
    }
  }

  async function loadKms() {
    try {
      kmsKeys = (await api.kmsKeys()).keys.filter((k) => k.enabled);
    } catch {
      kmsKeys = [];
    }
  }

  async function addParameter() {
    const rel = newName.trim();
    if (!rel) {
      notify('Name is required', false);
      return;
    }
    const fullName = (prefix + rel).replace(/\/+/g, '/');
    try {
      await api.putParameter({
        name: fullName,
        type: newType,
        value: newValue,
        kmsKeyId: newType === 'SecureString' ? newKms || undefined : undefined,
        tier: newTier,
        description: newDescription.trim() || undefined,
        overwrite
      });
      notify(`Saved ${fullName}`);
      newName = '';
      newValue = '';
      newDescription = '';
      overwrite = false;
      await loadParams();
    } catch (e) {
      err(e);
    }
  }

  async function reveal(p: Parameter) {
    try {
      const res = await api.revealParameter(p.name);
      revealed = { ...revealed, [p.name]: res.value };
    } catch (e) {
      err(e);
    }
  }

  function hide(name: string) {
    const next = { ...revealed };
    delete next[name];
    revealed = next;
  }

  function askDelete(p: Parameter) {
    confirmTitle = 'Delete parameter';
    confirmBody = `Permanently delete ${p.name} and its full version history? This cannot be undone.`;
    confirmLabel = 'Delete';
    confirmAction = async () => {
      try {
        await api.deleteParameter(p.name);
        notify(`Deleted ${p.name}`);
        if (detail?.name === p.name) closeDetail();
        await loadParams();
      } catch (e) {
        err(e);
      }
    };
    confirmOpen = true;
  }

  async function runConfirm() {
    const action = confirmAction;
    confirmOpen = false;
    if (action) await action();
    confirmAction = null;
  }

  async function openDetail(p: Parameter, tab: 'history' | 'tags' = 'history') {
    detail = p;
    detailTab = tab;
    await refreshDetail();
  }

  async function refreshDetail() {
    if (!detail) return;
    try {
      [history, tags] = await Promise.all([
        api.parameterHistory(detail.name).then((r) => r.history),
        api.parameterTags(detail.name).then((r) => r.tags)
      ]);
    } catch (e) {
      err(e);
    }
  }

  function closeDetail() {
    detail = null;
    history = [];
    tags = [];
  }

  async function addTag() {
    if (!detail || !tagKey.trim()) return;
    try {
      await api.tagParameter(detail.name, { [tagKey.trim()]: tagValue });
      tagKey = '';
      tagValue = '';
      await refreshDetail();
    } catch (e) {
      err(e);
    }
  }

  async function removeTag(key: string) {
    if (!detail) return;
    try {
      await api.untagParameter(detail.name, [key]);
      await refreshDetail();
    } catch (e) {
      err(e);
    }
  }

  async function applyLabel() {
    if (!detail) return;
    const v = parseInt(labelVersion, 10);
    const labels = labelText
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    if (!v || labels.length === 0) {
      notify('Provide a version and at least one label', false);
      return;
    }
    try {
      await api.labelParameterVersion(detail.name, v, labels);
      labelText = '';
      await refreshDetail();
      notify('Labels applied');
    } catch (e) {
      err(e);
    }
  }

  function fmt(ts: string): string {
    if (!ts) return '—';
    const d = new Date(ts);
    return Number.isNaN(d.getTime()) ? ts : d.toLocaleString();
  }

  onMount(() => {
    loadParams();
    loadKms();
  });
</script>

{#if flash}
  <div class="flash {flashOk ? 'ok' : 'err'}">{flash}</div>
{/if}

<div class="ph">
  <h1 class="ph-title">Parameter Store</h1>
  <p class="ph-sub">Hierarchical configuration and secrets, encrypted at rest with KMS.</p>
</div>

<div class="crumbs">
  <span onclick={() => crumbTo(0)} role="button" tabindex="0" onkeydown={(e) => e.key === 'Enter' && crumbTo(0)}>
    /
  </span>
  {#each pathSegs as seg, i}
    <span
      onclick={() => crumbTo(i + 1)}
      role="button"
      tabindex="0"
      onkeydown={(e) => e.key === 'Enter' && crumbTo(i + 1)}>{seg}</span
    >
  {/each}
</div>

<div class="grid">
  <div class="card">
    <h3 style="margin-top:0">Parameters</h3>
    {#if loading}
      <div class="empty">Loading…</div>
    {:else if subfolders.length === 0 && currentParams.length === 0}
      <div class="empty">No parameters at this path.</div>
    {:else}
      <table class="table">
        <thead>
          <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Tier</th>
            <th>Version</th>
            <th>Value</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {#each subfolders as f}
            <tr>
              <td>
                <button class="link-btn" onclick={() => openFolder(f)}>📁 {f}/</button>
              </td>
              <td class="muted" colspan="5">folder</td>
            </tr>
          {/each}
          {#each currentParams as p}
            <tr>
              <td class="mono">{leaf(p.name)}</td>
              <td><span class="badge">{p.type}</span></td>
              <td class="muted">{p.tier}</td>
              <td class="muted">v{p.version}</td>
              <td class="mono">
                {#if revealed[p.name] !== undefined}
                  <code>{revealed[p.name]}</code>
                  <button class="btn btn-sm" onclick={() => hide(p.name)}>Hide</button>
                {:else}
                  <button class="btn btn-sm" onclick={() => reveal(p)}>Reveal</button>
                {/if}
              </td>
              <td style="white-space:nowrap">
                <button class="btn btn-sm" onclick={() => openDetail(p)}>Details</button>
                <button class="btn btn-sm btn-d" onclick={() => askDelete(p)}>Delete</button>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
  </div>

  <div class="card">
    <h3 style="margin-top:0">Add parameter</h3>
    <p class="muted" style="margin-top:0">Created under <code>{prefix}</code></p>
    <div class="field">
      <label for="np-name">Name</label>
      <input id="np-name" class="mono" placeholder="db/password" bind:value={newName} />
    </div>
    <div class="field">
      <label for="np-type">Type</label>
      <select id="np-type" bind:value={newType}>
        <option value="String">String</option>
        <option value="StringList">StringList</option>
        <option value="SecureString">SecureString</option>
      </select>
    </div>
    {#if newType === 'SecureString'}
      <div class="field">
        <label for="np-kms">KMS key (defaults to account default)</label>
        <select id="np-kms" bind:value={newKms}>
          <option value="">Default key</option>
          {#each kmsKeys as k}
            <option value={k.keyId}>{kmsLabel(k)}</option>
          {/each}
        </select>
      </div>
    {/if}
    <div class="field">
      <label for="np-value">Value</label>
      {#if newType === 'StringList'}
        <input id="np-value" class="mono" placeholder="a,b,c" bind:value={newValue} />
      {:else}
        <input id="np-value" class="mono" bind:value={newValue} />
      {/if}
    </div>
    <div class="field">
      <label for="np-tier">Tier</label>
      <select id="np-tier" bind:value={newTier}>
        <option value="Standard">Standard</option>
        <option value="Advanced">Advanced</option>
      </select>
    </div>
    <div class="field">
      <label for="np-desc">Description</label>
      <input id="np-desc" bind:value={newDescription} />
    </div>
    <label class="check">
      <input type="checkbox" bind:checked={overwrite} /> Overwrite if it already exists
    </label>
    <button class="btn btn-p" style="margin-top:0.75rem" onclick={addParameter}>Save parameter</button>
  </div>
</div>

{#if detail}
  <div class="drawer-back" onclick={closeDetail} role="presentation"></div>
  <aside class="drawer">
    <div class="drawer-head">
      <div>
        <div class="mono" style="font-weight:600">{detail.name}</div>
        <div class="muted">{detail.type} · {detail.tier} · v{detail.version}</div>
      </div>
      <button class="btn" onclick={closeDetail}>Close</button>
    </div>
    <div class="tabs">
      <button class="tab" class:active={detailTab === 'history'} onclick={() => (detailTab = 'history')}>
        History
      </button>
      <button class="tab" class:active={detailTab === 'tags'} onclick={() => (detailTab = 'tags')}>
        Tags
      </button>
    </div>

    {#if detailTab === 'history'}
      <table class="table">
        <thead>
          <tr><th>Version</th><th>Type</th><th>Labels</th><th>Modified</th></tr>
        </thead>
        <tbody>
          {#each history as h}
            <tr>
              <td>v{h.version}</td>
              <td>{h.type}</td>
              <td>
                {#each h.labels as l}<span class="badge">{l}</span>{/each}
              </td>
              <td class="muted">{fmt(h.modifiedAt)}</td>
            </tr>
          {/each}
        </tbody>
      </table>
      <div class="card" style="margin-top:1rem">
        <h4 style="margin-top:0">Label a version</h4>
        <div class="field">
          <label for="lbl-ver">Version</label>
          <input id="lbl-ver" class="mono" placeholder={String(detail.version)} bind:value={labelVersion} />
        </div>
        <div class="field">
          <label for="lbl-txt">Labels (comma-separated)</label>
          <input id="lbl-txt" placeholder="stable, release-1" bind:value={labelText} />
        </div>
        <button class="btn btn-p" onclick={applyLabel}>Apply labels</button>
      </div>
    {:else}
      {#if tags.length === 0}
        <div class="empty">No tags.</div>
      {:else}
        <table class="table">
          <thead><tr><th>Key</th><th>Value</th><th></th></tr></thead>
          <tbody>
            {#each tags as t}
              <tr>
                <td class="mono">{t.key}</td>
                <td>{t.value}</td>
                <td><button class="btn btn-sm btn-d" onclick={() => removeTag(t.key)}>Remove</button></td>
              </tr>
            {/each}
          </tbody>
        </table>
      {/if}
      <div class="card" style="margin-top:1rem">
        <h4 style="margin-top:0">Add tag</h4>
        <div class="field">
          <label for="tg-key">Key</label>
          <input id="tg-key" bind:value={tagKey} />
        </div>
        <div class="field">
          <label for="tg-val">Value</label>
          <input id="tg-val" bind:value={tagValue} />
        </div>
        <button class="btn btn-p" onclick={addTag}>Add tag</button>
      </div>
    {/if}
  </aside>
{/if}

{#if confirmOpen}
  <div class="modal-back" role="presentation" onclick={() => (confirmOpen = false)}></div>
  <div class="modal">
    <h3 style="margin-top:0">{confirmTitle}</h3>
    <p>{confirmBody}</p>
    <div class="modal-actions">
      <button class="btn" onclick={() => (confirmOpen = false)}>Cancel</button>
      <button class="btn btn-d" onclick={runConfirm}>{confirmLabel}</button>
    </div>
  </div>
{/if}

<style>
  .crumbs {
    margin-bottom: 0.85rem;
  }
  .grid {
    display: grid;
    grid-template-columns: 2fr 1fr;
    gap: 1.25rem;
    align-items: start;
  }
  @media (max-width: 900px) {
    .grid {
      grid-template-columns: 1fr;
    }
  }
  .field :global(input),
  .field :global(select) {
    width: 100%;
    min-width: 0;
  }
  .link-btn {
    background: none;
    border: none;
    color: var(--c-blue);
    cursor: pointer;
    padding: 0;
    font: inherit;
  }
  .check {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.85rem;
    color: var(--c-muted);
  }
  .check :global(input) {
    min-width: 0;
  }
  .drawer-back,
  .modal-back {
    position: fixed;
    inset: 0;
    background: rgba(15, 20, 30, 0.35);
    z-index: 40;
  }
  .drawer {
    position: fixed;
    top: 0;
    right: 0;
    bottom: 0;
    width: min(560px, 92vw);
    background: var(--c-surface);
    border-left: 1px solid var(--c-border);
    box-shadow: -8px 0 24px rgba(15, 20, 30, 0.12);
    padding: 1.25rem;
    overflow-y: auto;
    z-index: 41;
  }
  .drawer-head {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    margin-bottom: 1rem;
  }
  .tabs {
    display: flex;
    gap: 0.25rem;
    margin-bottom: 1rem;
    border-bottom: 1px solid var(--c-border);
  }
  .tab {
    background: none;
    border: none;
    border-bottom: 2px solid transparent;
    color: var(--c-muted);
    padding: 0.5rem 0.7rem;
    cursor: pointer;
    font: inherit;
  }
  .tab.active {
    color: var(--c-text);
    border-bottom-color: var(--c-blue);
    font-weight: 600;
  }
  .modal {
    position: fixed;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    background: var(--c-surface);
    border: 1px solid var(--c-border);
    border-radius: var(--radius);
    box-shadow: 0 12px 32px rgba(15, 20, 30, 0.18);
    padding: 1.25rem;
    width: min(440px, 92vw);
    z-index: 42;
  }
  .modal-actions {
    display: flex;
    justify-content: flex-end;
    gap: 0.5rem;
    margin-top: 1rem;
  }
  .badge + .badge {
    margin-left: 0.25rem;
  }
</style>
