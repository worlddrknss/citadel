<script lang="ts">
  import { onMount } from 'svelte';
  import { api, ApiError, type KMSKey, type KMSKeyDetail } from '$lib/api';

  let keys: KMSKey[] = $state([]);
  let loading = $state(true);
  let flash = $state('');
  let flashOk = $state(true);

  // Detail drawer
  let detail: KMSKeyDetail | null = $state(null);
  let detailTab = $state('overview');
  let policyText = $state('');
  let savingPolicy = $state(false);

  // Alias management
  let aliasInput = $state('');
  let addingAlias = $state(false);

  // Confirm modal
  let confirmOpen = $state(false);
  let confirmTitle = $state('');
  let confirmBody = $state('');
  let confirmLabel = $state('Confirm');
  let confirmAction: (() => Promise<void>) | null = $state(null);
  let description = $state('');
  let keyUsage = $state('ENCRYPT_DECRYPT');
  let keySpec = $state('SYMMETRIC_DEFAULT');
  let creating = $state(false);

  const specsFor = $derived(
    keyUsage === 'SIGN_VERIFY'
      ? ['RSA_2048', 'RSA_3072', 'RSA_4096', 'ECC_NIST_P256', 'ECC_NIST_P384']
      : ['SYMMETRIC_DEFAULT', 'RSA_2048', 'RSA_3072', 'RSA_4096']
  );

  function notify(msg: string, ok = true) {
    flash = msg;
    flashOk = ok;
    setTimeout(() => (flash = ''), 4000);
  }

  async function load() {
    loading = true;
    try {
      keys = (await api.kmsKeys()).keys;
    } catch (e) {
      if (e instanceof ApiError) notify(e.message, false);
    } finally {
      loading = false;
    }
  }

  async function createKey() {
    if (creating) return;
    creating = true;
    try {
      const res = await api.createKmsKey({ description, keyUsage, keySpec });
      notify(`Created key ${res.keyId}`);
      description = '';
      await load();
    } catch (e) {
      if (e instanceof ApiError) notify(e.message, false);
    } finally {
      creating = false;
    }
  }

  async function toggle(k: KMSKey) {
    try {
      await api.setKmsKeyEnabled(k.keyId, !k.enabled);
      notify(`${k.enabled ? 'Disabled' : 'Enabled'} ${k.keyId}`);
      await load();
    } catch (e) {
      if (e instanceof ApiError) notify(e.message, false);
    }
  }

  async function scheduleDeletion(k: KMSKey) {
    if (!confirm(`Schedule ${k.keyId} for deletion in 30 days?`)) return;
    try {
      await api.scheduleKmsKeyDeletion(k.keyId, 30);
      notify(`Scheduled ${k.keyId} for deletion`);
      await load();
    } catch (e) {
      if (e instanceof ApiError) notify(e.message, false);
    }
  }

  async function cancelDeletion(k: KMSKey) {
    try {
      await api.cancelKmsKeyDeletion(k.keyId);
      notify(`Cancelled deletion of ${k.keyId}`);
      await load();
    } catch (e) {
      if (e instanceof ApiError) notify(e.message, false);
    }
  }

  // ---- detail drawer -------------------------------------------------------
  function prettyJSON(s: string): string {
    if (!s) return s;
    try {
      return JSON.stringify(JSON.parse(s), null, 2);
    } catch {
      return s;
    }
  }

  async function openDetail(k: KMSKey) {
    detailTab = 'overview';
    detail = null;
    try {
      const d = await api.kmsKeyDetail(k.keyId);
      detail = d;
      policyText = prettyJSON(d.policyDocument || '');
    } catch (e) {
      if (e instanceof ApiError) notify(e.message, false);
    }
  }

  function closeDetail() {
    detail = null;
  }

  async function refreshDetail() {
    if (!detail) return;
    try {
      const d = await api.kmsKeyDetail(detail.keyId);
      detail = d;
      policyText = prettyJSON(d.policyDocument || '');
    } catch (e) {
      if (e instanceof ApiError) notify(e.message, false);
    }
  }

  function formatPolicy() {
    policyText = prettyJSON(policyText);
  }

  async function savePolicy() {
    if (!detail || savingPolicy) return;
    savingPolicy = true;
    try {
      await api.putKmsKeyPolicy(detail.keyId, policyText);
      notify(`Saved key policy for ${detail.keyId}`);
      await openDetail(detail);
    } catch (e) {
      if (e instanceof ApiError) notify(e.message, false);
    } finally {
      savingPolicy = false;
    }
  }

  function askConfirm(opts: { title: string; body: string; label?: string; action: () => Promise<void> }) {
    confirmTitle = opts.title;
    confirmBody = opts.body;
    confirmLabel = opts.label ?? 'Confirm';
    confirmAction = opts.action;
    confirmOpen = true;
  }

  async function runConfirm() {
    const action = confirmAction;
    confirmOpen = false;
    if (action) await action();
    confirmAction = null;
  }

  async function addAlias() {
    if (!detail || addingAlias) return;
    const name = aliasInput.trim();
    if (!name) {
      notify('Enter an alias name', false);
      return;
    }
    addingAlias = true;
    try {
      const res = await api.createKmsAlias(detail.keyId, name);
      notify(`Added ${res.aliasName}`);
      aliasInput = '';
      await refreshDetail();
    } catch (e) {
      if (e instanceof ApiError) notify(e.message, false);
    } finally {
      addingAlias = false;
    }
  }

  function deleteAlias(aliasName: string) {
    if (!detail) return;
    askConfirm({
      title: `Delete alias "${aliasName}"?`,
      body: 'The alias will be removed. The underlying key is not affected.',
      label: 'Delete alias',
      action: async () => {
        try {
          await api.deleteKmsAlias(aliasName);
          notify(`Deleted ${aliasName}`);
          await refreshDetail();
        } catch (e) {
          if (e instanceof ApiError) notify(e.message, false);
        }
      }
    });
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
    const blob = new Blob([text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  }

  onMount(load);
</script>

<div class="ph">
  <h1 class="ph-title">Key Management Service</h1>
  <p class="ph-sub">Symmetric and asymmetric keys managed by the Citadel KMS service.</p>
</div>

{#if flash}
  <div class="flash {flashOk ? 'ok' : 'err'}">{flash}</div>
{/if}

<div class="card">
  <h3 style="margin-top:0">Customer Master Keys</h3>
  {#if loading}
    <div class="empty">Loading…</div>
  {:else if keys.length === 0}
    <div class="empty">No KMS keys yet.</div>
  {:else}
    <table>
      <thead>
        <tr>
          <th>Key ID</th>
          <th>Description</th>
          <th>Spec</th>
          <th>Usage</th>
          <th>Status</th>
          <th>Created</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        {#each keys as k}
          <tr class:rowsel={detail?.keyId === k.keyId}>
            <td class="mono">
              <button class="linklike" onclick={() => openDetail(k)}>{k.keyId}</button>
            </td>
            <td>{k.description || '—'}</td>
            <td>{k.keySpec || '—'}</td>
            <td>{k.keyUsage || '—'}</td>
            <td>
              {#if k.deletionDate}
                <span class="badge">Pending deletion</span>
              {:else if k.enabled}
                <span class="badge">Enabled</span>
              {:else}
                <span class="badge">Disabled</span>
              {/if}
            </td>
            <td class="muted">{new Date(k.createdAt).toLocaleString()}</td>
            <td>
              {#if k.deletionDate}
                <button class="btn btn-sm" onclick={() => cancelDeletion(k)}>Cancel deletion</button>
              {:else}
                <button class="btn btn-sm" onclick={() => toggle(k)}>
                  {k.enabled ? 'Disable' : 'Enable'}
                </button>
                <button class="btn btn-sm btn-d" onclick={() => scheduleDeletion(k)}>Delete</button>
              {/if}
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
</div>

<div class="card" style="margin-top:1.25rem">
  <h3 style="margin-top:0">Create key</h3>
  <div class="toolbar" style="margin-bottom:0">
    <div class="field" style="flex:1">
      <label for="kd">Description</label>
      <input id="kd" placeholder="payments signing key" bind:value={description} />
    </div>
    <div class="field">
      <label for="ku">Usage</label>
      <select id="ku" bind:value={keyUsage}>
        <option value="ENCRYPT_DECRYPT">ENCRYPT_DECRYPT</option>
        <option value="SIGN_VERIFY">SIGN_VERIFY</option>
      </select>
    </div>
    <div class="field">
      <label for="ks">Spec</label>
      <select id="ks" bind:value={keySpec}>
        {#each specsFor as s}
          <option value={s}>{s}</option>
        {/each}
      </select>
    </div>
    <div class="field" style="align-self:flex-end">
      <button class="btn btn-p" onclick={createKey} disabled={creating}>
        {creating ? 'Creating…' : 'Create key'}
      </button>
    </div>
  </div>
</div>

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
        <div class="mono drawer-title">{detail.keyId}</div>
        <div class="muted small">{detail.description || '—'}</div>
      </div>
      <button class="btn btn-sm" onclick={closeDetail}>✕</button>
    </div>

    <div class="kv">
      <div class="kv-row"><span class="kv-l">ARN</span><span class="kv-v mono small">{detail.arn}</span></div>
      <div class="kv-row">
        <span class="kv-l">State</span>
        <span class="kv-v">
          {#if detail.deletionDate}
            <span class="badge warn">pending deletion</span>
            <span class="muted small">{detail.deletionDate.replace('T', ' ').replace('Z', '')}</span>
          {:else if detail.enabled}
            <span class="badge ok">enabled</span>
          {:else}
            <span class="badge">disabled</span>
          {/if}
          <span class="muted small"> · {detail.keyState}</span>
        </span>
      </div>
      <div class="kv-row"><span class="kv-l">Usage</span><span class="kv-v">{detail.keyUsage}</span></div>
      <div class="kv-row"><span class="kv-l">Spec</span><span class="kv-v">{detail.keySpec}</span></div>
      <div class="kv-row">
        <span class="kv-l">Created</span>
        <span class="kv-v small">{detail.createdAt.replace('T', ' ').replace('Z', '')}</span>
      </div>
    </div>

    <div class="tabs">
      <button class="tab" class:active={detailTab === 'overview'} onclick={() => (detailTab = 'overview')}
        >Overview</button
      >
      <button class="tab" class:active={detailTab === 'policy'} onclick={() => (detailTab = 'policy')}
        >Key policy</button
      >
      <button class="tab" class:active={detailTab === 'grants'} onclick={() => (detailTab = 'grants')}
        >Grants</button
      >
      <button class="tab" class:active={detailTab === 'aliases'} onclick={() => (detailTab = 'aliases')}
        >Aliases</button
      >
      {#if detail.publicKeyPem}
        <button class="tab" class:active={detailTab === 'pubkey'} onclick={() => (detailTab = 'pubkey')}
          >Public key</button
        >
      {/if}
    </div>

    {#if detailTab === 'overview'}
      <div class="tab-body">
        <div class="kv">
          <div class="kv-row">
            <span class="kv-l">Encryption</span>
            <span class="kv-v small">{(detail.encryptionAlgorithms || []).join(', ') || '—'}</span>
          </div>
          <div class="kv-row">
            <span class="kv-l">Signing</span>
            <span class="kv-v small">{(detail.signingAlgorithms || []).join(', ') || '—'}</span>
          </div>
          <div class="kv-row">
            <span class="kv-l">Aliases</span>
            <span class="kv-v small">{detail.aliases.length}</span>
          </div>
          <div class="kv-row">
            <span class="kv-l">Grants</span>
            <span class="kv-v small">{detail.grants.length}</span>
          </div>
        </div>
      </div>
    {:else if detailTab === 'policy'}
      <div class="tab-body">
        <div class="field block">
          <label for="kpol">Key policy document</label>
          <textarea id="kpol" class="mono" rows="16" bind:value={policyText}></textarea>
        </div>
        <div class="row-act">
          <button class="btn btn-sm" onclick={formatPolicy}>Format JSON</button>
          <button class="btn btn-p btn-sm" onclick={savePolicy} disabled={savingPolicy}>
            {savingPolicy ? 'Saving…' : 'Save policy'}
          </button>
        </div>
      </div>
    {:else if detailTab === 'grants'}
      <div class="tab-body">
        {#if detail.grants.length === 0}
          <div class="empty">No grants.</div>
        {:else}
          {#each detail.grants as g}
            <div class="kv" style="margin-bottom:0.6rem">
              <div class="kv-row"><span class="kv-l">Grant ID</span><span class="kv-v mono small">{g.grantId}</span></div>
              {#if g.name}
                <div class="kv-row"><span class="kv-l">Name</span><span class="kv-v small">{g.name}</span></div>
              {/if}
              <div class="kv-row"><span class="kv-l">Grantee</span><span class="kv-v mono small">{g.granteePrincipal}</span></div>
              {#if g.retiringPrincipal}
                <div class="kv-row"><span class="kv-l">Retiring</span><span class="kv-v mono small">{g.retiringPrincipal}</span></div>
              {/if}
              <div class="kv-row"><span class="kv-l">Operations</span><span class="kv-v small">{g.operations.join(', ')}</span></div>
              <div class="kv-row"><span class="kv-l">Created</span><span class="kv-v small">{g.createdAt.replace('T', ' ').replace('Z', '')}</span></div>
            </div>
          {/each}
        {/if}
      </div>
    {:else if detailTab === 'aliases'}
      <div class="tab-body">
        <div class="alias-add">
          <input
            placeholder="alias/my-key"
            bind:value={aliasInput}
            onkeydown={(e) => e.key === 'Enter' && addAlias()}
          />
          <button class="btn btn-p btn-sm" onclick={addAlias} disabled={addingAlias}>
            {addingAlias ? 'Adding…' : 'Add alias'}
          </button>
        </div>
        <p class="muted small" style="margin:0.25rem 0 0.75rem">
          The <code>alias/</code> prefix is added automatically if omitted.
        </p>
        {#if detail.aliases.length === 0}
          <div class="empty">No aliases.</div>
        {:else}
          <ul class="plain alias-list">
            {#each detail.aliases as a}
              <li>
                <span class="mono small">{a}</span>
                <button class="btn btn-sm btn-d" onclick={() => deleteAlias(a)}>Delete</button>
              </li>
            {/each}
          </ul>
        {/if}
      </div>
    {:else if detailTab === 'pubkey' && detail.publicKeyPem}
      <div class="tab-body">
        <pre class="pem">{detail.publicKeyPem}</pre>
        <div class="row-act">
          <button class="btn btn-sm" onclick={() => copyText(detail!.publicKeyPem!)}>Copy</button>
          <button
            class="btn btn-sm"
            onclick={() => downloadText(`${detail!.keyId}-public.pem`, detail!.publicKeyPem!)}
            >Download .pem</button
          >
        </div>
      </div>
    {/if}
  </aside>
{/if}

<!-- confirm modal -->
{#if confirmOpen}
  <div class="modal-scrim" role="presentation" onclick={() => (confirmOpen = false)}></div>
  <div class="modal" role="dialog" aria-modal="true">
    <h3 style="margin-top:0">{confirmTitle}</h3>
    <p class="muted">{confirmBody}</p>
    <div class="modal-act">
      <button class="btn" onclick={() => (confirmOpen = false)}>Cancel</button>
      <button class="btn btn-d" onclick={runConfirm}>{confirmLabel}</button>
    </div>
  </div>
{/if}

<style>
  .linklike {
    background: none;
    border: none;
    padding: 0;
    color: var(--c-blue);
    cursor: pointer;
    font: inherit;
  }
  .alias-add {
    display: flex;
    gap: 0.5rem;
  }
  .alias-add input {
    flex: 1;
  }
  .alias-list {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 0.4rem;
  }
  .alias-list li {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 0.5rem;
    padding: 0.4rem 0.5rem;
    border: 1px solid var(--c-border);
    border-radius: var(--radius);
  }
  .modal-scrim {
    position: fixed;
    inset: 0;
    background: rgba(15, 20, 30, 0.35);
    z-index: 50;
  }
  .modal {
    position: fixed;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    background: var(--c-surface);
    border: 1px solid var(--c-border);
    border-radius: var(--radius);
    padding: 1.25rem;
    width: min(460px, 92vw);
    z-index: 51;
    box-shadow: 0 12px 32px rgba(15, 20, 30, 0.2);
  }
  .modal-act {
    display: flex;
    justify-content: flex-end;
    gap: 0.5rem;
    margin-top: 1rem;
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
    width: 130px;
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
  .field.block {
    display: block;
    margin-bottom: 0.75rem;
  }
  .field.block textarea {
    width: 100%;
  }
  textarea {
    font: inherit;
    padding: 0.45rem 0.6rem;
    border: 1px solid var(--c-border);
    border-radius: 6px;
    width: 100%;
    resize: vertical;
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
    max-height: 320px;
    overflow-y: auto;
    margin: 0 0 0.6rem;
  }
  ul.plain {
    list-style: none;
    margin: 0;
    padding: 0;
  }
  ul.plain li {
    padding: 0.3rem 0;
    border-bottom: 1px solid var(--c-border);
  }
</style>
