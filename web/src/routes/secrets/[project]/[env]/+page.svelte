<script lang="ts">
  import { onMount, untrack } from 'svelte';
  import { goto } from '$app/navigation';
  import { base } from '$app/paths';
  import { page } from '$app/stores';
  import {
    api,
    ApiError,
    type Item,
    type ItemDetail,
    type ItemVersion,
    type KMSKey
  } from '$lib/api';

  const project = $derived($page.params.project ?? '');
  const env = $derived($page.params.env ?? '');

  let path = $state('/');
  let folders: string[] = $state([]);
  let items: Item[] = $state([]);
  let revealed: Record<string, string> = $state({});
  let selected: Record<string, boolean> = $state({});

  let kmsKeys: KMSKey[] = $state([]);

  let flash = $state('');
  let flashOk = $state(true);
  let loading = $state(false);

  // New-secret form
  let newKey = $state('');
  let newValue = $state('');
  let newKms = $state('');

  // Structure creation
  let newFolderName = $state('');

  // Detail drawer
  let detail: ItemDetail | null = $state(null);
  let detailKey = $state('');
  let detailTab: 'overview' | 'versions' | 'tags' | 'policy' | 'rotation' = $state('overview');
  let versions: ItemVersion[] = $state([]);
  let metaDescription = $state('');
  let metaKms = $state('');
  let newVersionValue = $state('');
  let tagKey = $state('');
  let tagValue = $state('');
  let policyDoc = $state('');
  let rotLambda = $state('');
  let rotDays = $state('30');
  let rotImmediate = $state(false);

  // Confirm modal (avoids native confirm per UX guidelines)
  let confirmOpen = $state(false);
  let confirmTitle = $state('');
  let confirmBody = $state('');
  let confirmLabel = $state('Confirm');
  let confirmDanger = $state(true);
  let confirmAction: (() => Promise<void>) | null = $state(null);

  const selectedKeys = $derived(items.filter((it) => selected[it.key]).map((it) => it.key));
  const crumbSegs = $derived(path.split('/').filter(Boolean));

  function notify(msg: string, ok = true) {
    flash = msg;
    flashOk = ok;
    setTimeout(() => (flash = ''), 4000);
  }

  function err(e: unknown) {
    if (e instanceof ApiError) notify(e.message, false);
    else notify('Unexpected error', false);
  }

  function prettyJSON(raw: string): string {
    const trimmed = (raw ?? '').trim();
    if (!trimmed) return '';
    try {
      return JSON.stringify(JSON.parse(trimmed), null, 2);
    } catch {
      return raw;
    }
  }

  function formatPolicy() {
    const next = prettyJSON(policyDoc);
    if (next === policyDoc) {
      if (policyDoc.trim()) notify('Policy is not valid JSON', false);
      return;
    }
    policyDoc = next;
  }

  function askConfirm(opts: {
    title: string;
    body: string;
    label?: string;
    danger?: boolean;
    action: () => Promise<void>;
  }) {
    confirmTitle = opts.title;
    confirmBody = opts.body;
    confirmLabel = opts.label ?? 'Confirm';
    confirmDanger = opts.danger ?? true;
    confirmAction = opts.action;
    confirmOpen = true;
  }

  async function runConfirm() {
    const action = confirmAction;
    confirmOpen = false;
    if (action) await action();
    confirmAction = null;
  }

  async function loadKms() {
    try {
      kmsKeys = (await api.kmsKeys()).keys.filter((k) => k.enabled);
    } catch {
      kmsKeys = [];
    }
  }

  async function loadItems() {
    if (!project || !env) {
      items = [];
      folders = [];
      return;
    }
    loading = true;
    try {
      const res = await api.list(project, env, path);
      items = res.items;
      folders = res.folders;
      revealed = {};
      selected = {};
    } catch (e) {
      err(e);
    } finally {
      loading = false;
    }
  }

  async function reveal(it: Item) {
    try {
      const res = await api.reveal(it.project, it.env, it.path, it.key);
      revealed = { ...revealed, [it.key]: res.value ?? '(binary)' };
    } catch (e) {
      err(e);
    }
  }

  function hide(key: string) {
    const next = { ...revealed };
    delete next[key];
    revealed = next;
  }

  async function addSecret() {
    if (!project || !env || !newKey.trim()) {
      notify('key is required', false);
      return;
    }
    try {
      const res = await api.put({
        project,
        env,
        path,
        key: newKey.trim(),
        value: newValue,
        kmsKeyId: newKms || undefined
      });
      notify(res.created ? `Created ${newKey}` : `Updated ${newKey}`);
      newKey = '';
      newValue = '';
      await loadItems();
    } catch (e) {
      err(e);
    }
  }

  function scheduleDelete(it: Item) {
    askConfirm({
      title: `Schedule deletion of ${it.key}?`,
      body: 'The item enters a 30-day recovery window and can be restored before it is purged. External Secrets clients stop receiving it immediately.',
      label: 'Schedule deletion',
      action: async () => {
        try {
          await api.remove(it.project, it.env, it.path, it.key, { recoveryWindowDays: 30 });
          notify(`Scheduled ${it.key} for deletion`);
          if (detailKey === it.key) closeDetail();
          await loadItems();
        } catch (e) {
          err(e);
        }
      }
    });
  }

  function forceDelete(it: Item) {
    askConfirm({
      title: `Force delete ${it.key} now?`,
      body: 'This bypasses the recovery window. The value is removed from External Secrets immediately and cannot be restored from the UI.',
      label: 'Force delete now',
      action: async () => {
        try {
          await api.remove(it.project, it.env, it.path, it.key, { force: true });
          notify(`Force deleted ${it.key}`);
          if (detailKey === it.key) closeDetail();
          await loadItems();
        } catch (e) {
          err(e);
        }
      }
    });
  }

  async function restore(it: Item) {
    try {
      await api.restore(it.project, it.env, it.path, it.key);
      notify(`Restored ${it.key}`);
      await loadItems();
      if (detailKey === it.key) await loadDetail(it);
    } catch (e) {
      err(e);
    }
  }

  function openFolder(name: string) {
    closeDetail();
    path = path === '/' ? `/${name}` : `${path}/${name}`;
    loadItems();
  }

  function crumbTo(idx: number) {
    closeDetail();
    const segs = path.split('/').filter(Boolean);
    path = idx < 0 ? '/' : '/' + segs.slice(0, idx + 1).join('/');
    loadItems();
  }

  async function createFolder() {
    const name = newFolderName.trim();
    if (!project || !env || !name) {
      notify('enter a folder name', false);
      return;
    }
    const full = path === '/' ? name : `${path.replace(/^\//, '')}/${name}`;
    try {
      await api.createFolder(project, env, full);
      notify(`Created folder ${name}`);
      newFolderName = '';
      await loadItems();
    } catch (e) {
      err(e);
    }
  }

  function deleteFolder(name: string) {
    const full = path === '/' ? `/${name}` : `${path}/${name}`;
    askConfirm({
      title: `Delete folder "${name}"?`,
      body: 'This removes the folder and any nested empty folders. It is refused while any secret still exists at or below it.',
      label: 'Delete folder',
      action: async () => {
        try {
          await api.deleteFolder(project, env, full);
          notify(`Deleted folder ${name}`);
          await loadItems();
        } catch (e) {
          err(e);
        }
      }
    });
  }

  function deleteEnvironment() {
    if (!project || !env) return;
    askConfirm({
      title: `Delete environment "${env}"?`,
      body: 'This removes the environment and its empty folders. It is refused while any secret still exists under it.',
      label: 'Delete environment',
      action: async () => {
        try {
          await api.deleteEnvironment(project, env);
          notify(`Deleted environment ${env}`);
          goto(`${base}/secrets/${encodeURIComponent(project)}`);
        } catch (e) {
          err(e);
        }
      }
    });
  }

  // ---- detail drawer -------------------------------------------------------
  async function openDetail(it: Item) {
    detailKey = it.key;
    detailTab = 'overview';
    await loadDetail(it);
  }

  async function loadDetail(it: Item) {
    try {
      const d = await api.secretDetail(it.project, it.env, it.path, it.key);
      detail = d;
      metaDescription = d.description;
      metaKms = d.kmsKeyId;
      policyDoc = prettyJSON(d.policyDocument);
      rotLambda = d.rotation.lambdaArn ?? '';
      rotDays = String(d.rotation.afterDays || 30);
      versions = [];
    } catch (e) {
      err(e);
      detail = null;
      detailKey = '';
    }
  }

  function closeDetail() {
    detail = null;
    detailKey = '';
    versions = [];
  }

  function detailCoord() {
    if (!detail) return null;
    return { project: detail.project, env: detail.env, path: detail.path, key: detail.key };
  }

  function detailAsItem(): Item | null {
    if (!detail) return null;
    return {
      project: detail.project,
      env: detail.env,
      path: detail.path,
      key: detail.key,
      arn: detail.arn,
      updatedAt: detail.updatedAt,
      deletionDate: detail.deletionDate
    };
  }

  async function loadVersions() {
    if (!detail) return;
    try {
      const res = await api.versions(detail.project, detail.env, detail.path, detail.key);
      versions = res.versions;
    } catch (e) {
      err(e);
    }
  }

  async function reloadDetail() {
    const it = detailAsItem();
    if (it) await loadDetail(it);
  }

  async function saveMetadata() {
    const c = detailCoord();
    if (!c) return;
    try {
      await api.updateSecretMetadata({ ...c, description: metaDescription, kmsKeyId: metaKms });
      notify('Saved metadata');
      await reloadDetail();
    } catch (e) {
      err(e);
    }
  }

  async function storeNewVersion() {
    const c = detailCoord();
    if (!c) return;
    try {
      await api.put({ ...c, value: newVersionValue });
      notify('Stored new version');
      newVersionValue = '';
      await reloadDetail();
      if (detailTab === 'versions') await loadVersions();
    } catch (e) {
      err(e);
    }
  }

  async function promote(versionId: string) {
    const c = detailCoord();
    if (!c) return;
    try {
      await api.promoteVersion(c.project, c.env, c.path, c.key, versionId);
      notify('Promoted version to current');
      await loadVersions();
      await reloadDetail();
    } catch (e) {
      err(e);
    }
  }

  async function addTag() {
    const c = detailCoord();
    if (!c || !tagKey.trim()) return;
    try {
      await api.tagSecret(c.project, c.env, c.path, c.key, [
        { key: tagKey.trim(), value: tagValue }
      ]);
      notify('Saved tag');
      tagKey = '';
      tagValue = '';
      await reloadDetail();
    } catch (e) {
      err(e);
    }
  }

  async function removeTag(key: string) {
    const c = detailCoord();
    if (!c) return;
    try {
      await api.untagSecret(c.project, c.env, c.path, c.key, key);
      notify('Removed tag');
      await reloadDetail();
    } catch (e) {
      err(e);
    }
  }

  async function savePolicy() {
    const c = detailCoord();
    if (!c) return;
    try {
      await api.putSecretPolicy(c.project, c.env, c.path, c.key, policyDoc);
      notify('Saved resource policy');
      await reloadDetail();
    } catch (e) {
      err(e);
    }
  }

  async function saveRotation() {
    const c = detailCoord();
    if (!c) return;
    try {
      await api.configureRotation({
        ...c,
        lambdaArn: rotLambda.trim(),
        afterDays: parseInt(rotDays, 10) || 30,
        rotateImmediately: rotImmediate
      });
      notify('Saved rotation config');
      rotImmediate = false;
      await reloadDetail();
    } catch (e) {
      err(e);
    }
  }

  async function cancelRotation() {
    const c = detailCoord();
    if (!c) return;
    try {
      await api.cancelRotation(c.project, c.env, c.path, c.key);
      notify('Cancelled rotation');
      await reloadDetail();
    } catch (e) {
      err(e);
    }
  }

  // ---- bulk ----------------------------------------------------------------
  function bulkDelete() {
    const keys = selectedKeys;
    if (!keys.length) return;
    askConfirm({
      title: `Schedule ${keys.length} item(s) for deletion?`,
      body: 'Each selected item enters a 30-day recovery window and can be restored before purge.',
      label: 'Schedule deletion',
      action: async () => {
        try {
          const res = await api.bulkSecrets({
            project,
            env,
            path,
            keys,
            action: 'delete',
            recoveryWindowDays: 30
          });
          notify(
            `Scheduled ${res.applied} item(s); ${res.failed.length} failed`,
            res.failed.length === 0
          );
          await loadItems();
        } catch (e) {
          err(e);
        }
      }
    });
  }

  async function bulkRestore() {
    const keys = selectedKeys;
    if (!keys.length) return;
    try {
      const res = await api.bulkSecrets({ project, env, path, keys, action: 'restore' });
      notify(
        `Restored ${res.applied} item(s); ${res.failed.length} failed`,
        res.failed.length === 0
      );
      await loadItems();
    } catch (e) {
      err(e);
    }
  }

  function bulkForceDelete() {
    const keys = selectedKeys;
    if (!keys.length) return;
    askConfirm({
      title: `Force delete ${keys.length} item(s) now?`,
      body: 'This bypasses the recovery window. The values are removed from External Secrets immediately and cannot be restored from the UI.',
      label: 'Force delete now',
      action: async () => {
        try {
          const res = await api.bulkSecrets({ project, env, path, keys, action: 'delete', force: true });
          notify(
            `Force deleted ${res.applied} item(s); ${res.failed.length} failed`,
            res.failed.length === 0
          );
          await loadItems();
        } catch (e) {
          err(e);
        }
      }
    });
  }

  $effect(() => {
    // Reload whenever the env route changes. Only project/env are tracked as
    // dependencies; the body is untracked so navigating into a folder (which
    // updates `path` and calls loadItems) does not retrigger this reset.
    void project;
    void env;
    untrack(() => {
      path = '/';
      closeDetail();
      loadItems();
    });
  });

  onMount(loadKms);
</script>

<div class="crumbs" style="margin-bottom:0.5rem">
  <a href={`${base}/`}>Projects</a>
  / <a href={`${base}/secrets/${encodeURIComponent(project)}`}>{project}</a>
  / <span class="cur">{env}</span>
</div>

<div class="ph">
  <h1 class="ph-title">{project} / {env}</h1>
  <p class="ph-sub">
    Browse folders and secrets in this environment. Items remain readable through the
    AWS Secrets Manager API for ESO and SDK clients.
  </p>
</div>

{#if flash}
  <div class="flash {flashOk ? 'ok' : 'err'}">{flash}</div>
{/if}

<div class="card">
  <div class="toolbar" style="align-items:flex-end">
    <div class="field" style="flex:1">
      <label for="nf">New folder (here)</label>
      <input id="nf" placeholder="database" bind:value={newFolderName} />
    </div>
    <button class="btn btn-sm" onclick={createFolder}>+ Folder</button>
    <button class="btn btn-sm btn-d" onclick={deleteEnvironment}>Delete environment</button>
  </div>

  <div class="crumbs" style="margin:0.75rem 0 0">
    <span onclick={() => crumbTo(-1)} role="button" tabindex="0" onkeydown={() => {}}
      >{project}/{env}</span
    >
    {#each crumbSegs as seg, i}
      / <span onclick={() => crumbTo(i)} role="button" tabindex="0" onkeydown={() => {}}>{seg}</span>
    {/each}
  </div>
</div>

<div class="card" style="margin-top:1.25rem">
  {#if selectedKeys.length > 0}
    <div class="bulkbar">
      <span class="muted">{selectedKeys.length} selected</span>
      <button class="btn btn-sm btn-d" onclick={bulkDelete}>Schedule deletion</button>
      <button class="btn btn-sm" onclick={bulkRestore}>Restore</button>
      <button class="btn btn-sm btn-d" onclick={bulkForceDelete}>Force delete</button>
    </div>
  {/if}

  {#if loading}
    <div class="empty">Loading…</div>
  {:else}
    <table>
      <thead>
        <tr>
          <th style="width:28px"></th>
          <th>Key</th>
          <th>Value</th>
          <th>Status</th>
          <th>Updated</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        {#each folders as f}
          <tr>
            <td></td>
            <td>
              <button class="btn btn-sm" onclick={() => openFolder(f)}>📁 {f}/</button>
            </td>
            <td class="muted">folder</td>
            <td></td>
            <td></td>
            <td>
              <div class="rowact">
                <button class="btn btn-sm btn-d" onclick={() => deleteFolder(f)}>Delete</button>
              </div>
            </td>
          </tr>
        {/each}
        {#each items as it}
          <tr class:rowsel={detailKey === it.key}>
            <td>
              <input type="checkbox" class="chk" bind:checked={selected[it.key]} />
            </td>
            <td class="mono">
              <button class="linklike" onclick={() => openDetail(it)}>{it.key}</button>
            </td>
            <td class="mono">
              {#if it.deletionDate}
                <span class="muted">— unavailable —</span>
              {:else if revealed[it.key] !== undefined}
                {revealed[it.key]}
                <button class="btn btn-sm" onclick={() => hide(it.key)}>Hide</button>
              {:else}
                <span class="muted">••••••••</span>
                <button class="btn btn-sm" onclick={() => reveal(it)}>Reveal</button>
              {/if}
            </td>
            <td>
              {#if it.deletionDate}
                <span class="badge warn">scheduled deletion</span>
              {:else}
                <span class="badge ok">active</span>
              {/if}
            </td>
            <td class="muted">{it.updatedAt?.replace('T', ' ').replace('Z', '')}</td>
            <td>
              <div class="rowact">
                <button class="btn btn-sm" onclick={() => openDetail(it)}>Details</button>
                {#if it.deletionDate}
                  <button class="btn btn-sm" onclick={() => restore(it)}>Restore</button>
                  <button class="btn btn-sm btn-d" onclick={() => forceDelete(it)}>Force delete</button>
                {:else}
                  <button class="btn btn-sm btn-d" onclick={() => scheduleDelete(it)}>Delete</button>
                  <button class="btn btn-sm btn-d" onclick={() => forceDelete(it)}>Force delete</button>
                {/if}
              </div>
            </td>
          </tr>
        {/each}
        {#if folders.length === 0 && items.length === 0}
          <tr><td colspan="6" class="empty">No secrets at this path yet.</td></tr>
        {/if}
      </tbody>
    </table>
  {/if}
</div>

<div class="card" style="margin-top:1.25rem">
  <h3 style="margin-top:0">Add / update secret</h3>
  <div class="toolbar" style="margin-bottom:0">
    <div class="field">
      <label for="nk">Key</label>
      <input id="nk" class="mono" placeholder="DB_PASSWORD" bind:value={newKey} />
    </div>
    <div class="field" style="flex:1">
      <label for="nv">Value</label>
      <input id="nv" class="mono" placeholder="••••••" bind:value={newValue} />
    </div>
    <div class="field">
      <label for="nkms">KMS key (optional)</label>
      <select id="nkms" bind:value={newKms}>
        <option value="">default</option>
        {#each kmsKeys as k}
          <option value={k.keyId}>{k.keyId}</option>
        {/each}
      </select>
    </div>
    <button class="btn btn-p" onclick={addSecret}>Save</button>
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
        <div class="mono drawer-title">{detail.key}</div>
        <div class="muted small">
          {detail.project}/{detail.env}{detail.path === '/' ? '' : detail.path}
        </div>
      </div>
      <button class="btn btn-sm" onclick={closeDetail}>✕</button>
    </div>

    <div class="kv">
      <div class="kv-row"><span class="kv-l">ARN</span><span class="kv-v mono">{detail.arn}</span></div>
      <div class="kv-row">
        <span class="kv-l">Status</span>
        <span class="kv-v">
          {#if detail.deletionDate}
            <span class="badge warn">scheduled deletion</span>
            <span class="muted small">
              {detail.deletionDate.replace('T', ' ').replace('Z', '')}</span
            >
          {:else}
            <span class="badge ok">active</span>
          {/if}
        </span>
      </div>
      <div class="kv-row">
        <span class="kv-l">Current version</span><span class="kv-v mono small"
          >{detail.currentVersionId}</span
        >
      </div>
      <div class="kv-row">
        <span class="kv-l">KMS key</span><span class="kv-v mono small">{detail.kmsKeyId || 'default'}</span>
      </div>
      <div class="kv-row">
        <span class="kv-l">Updated</span><span class="kv-v small"
          >{detail.updatedAt.replace('T', ' ').replace('Z', '')}</span
        >
      </div>
    </div>

    {#if detail.deletionDate}
      <div class="rowact" style="margin:0.5rem 0">
        <button class="btn btn-sm" onclick={() => detailAsItem() && restore(detailAsItem()!)}
          >Restore secret</button
        >
        <button class="btn btn-sm btn-d" onclick={() => detailAsItem() && forceDelete(detailAsItem()!)}
          >Force delete</button
        >
      </div>
    {:else}
      <div class="rowact" style="margin:0.5rem 0">
        <button class="btn btn-sm btn-d" onclick={() => detailAsItem() && scheduleDelete(detailAsItem()!)}
          >Schedule deletion</button
        >
        <button class="btn btn-sm btn-d" onclick={() => detailAsItem() && forceDelete(detailAsItem()!)}
          >Force delete</button
        >
      </div>
    {/if}

    <div class="tabs">
      <button class="tab" class:active={detailTab === 'overview'} onclick={() => (detailTab = 'overview')}
        >Overview</button
      >
      <button
        class="tab"
        class:active={detailTab === 'versions'}
        onclick={() => {
          detailTab = 'versions';
          loadVersions();
        }}>Versions</button
      >
      <button class="tab" class:active={detailTab === 'tags'} onclick={() => (detailTab = 'tags')}
        >Tags</button
      >
      <button class="tab" class:active={detailTab === 'policy'} onclick={() => (detailTab = 'policy')}
        >Policy</button
      >
      <button
        class="tab"
        class:active={detailTab === 'rotation'}
        onclick={() => (detailTab = 'rotation')}>Rotation</button
      >
    </div>

    {#if detailTab === 'overview'}
      <div class="tab-body">
        <div class="field block">
          <label for="md">Description</label>
          <input id="md" bind:value={metaDescription} />
        </div>
        <div class="field block">
          <label for="mk">KMS key</label>
          <select id="mk" bind:value={metaKms}>
            <option value="">default</option>
            {#each kmsKeys as k}
              <option value={k.keyId}>{k.keyId}</option>
            {/each}
          </select>
        </div>
        <button class="btn btn-p btn-sm" onclick={saveMetadata}>Save metadata</button>

        <hr />
        <div class="field block">
          <label for="nvv">Store new version (secret value)</label>
          <textarea
            id="nvv"
            class="mono"
            rows="3"
            placeholder={'{"password":"new-value"}'}
            bind:value={newVersionValue}
          ></textarea>
        </div>
        <button class="btn btn-p btn-sm" onclick={storeNewVersion}>Store new version</button>
      </div>
    {:else if detailTab === 'versions'}
      <div class="tab-body">
        <table>
          <thead><tr><th>Version</th><th>Stages</th><th>Created</th><th></th></tr></thead>
          <tbody>
            {#each versions as v}
              <tr>
                <td class="mono small">{v.versionId.slice(0, 12)}…</td>
                <td>
                  {#each v.stages as st}<span class="badge">{st}</span> {/each}
                </td>
                <td class="muted small">{v.createdAt.replace('T', ' ').replace('Z', '')}</td>
                <td>
                  {#if !v.stages.includes('AWSCURRENT')}
                    <button class="btn btn-sm" onclick={() => promote(v.versionId)}>Promote</button>
                  {/if}
                </td>
              </tr>
            {/each}
            {#if versions.length === 0}
              <tr><td colspan="4" class="empty">No versions loaded.</td></tr>
            {/if}
          </tbody>
        </table>
      </div>
    {:else if detailTab === 'tags'}
      <div class="tab-body">
        <table>
          <thead><tr><th>Key</th><th>Value</th><th></th></tr></thead>
          <tbody>
            {#each detail.tags as t}
              <tr>
                <td class="mono small">{t.key}</td>
                <td class="small">{t.value}</td>
                <td><button class="btn btn-sm btn-d" onclick={() => removeTag(t.key)}>Remove</button></td>
              </tr>
            {/each}
            {#if detail.tags.length === 0}
              <tr><td colspan="3" class="empty">No tags.</td></tr>
            {/if}
          </tbody>
        </table>
        <hr />
        <div class="toolbar" style="margin-bottom:0">
          <div class="field">
            <label for="tk">Key</label><input id="tk" bind:value={tagKey} placeholder="environment" />
          </div>
          <div class="field">
            <label for="tv">Value</label><input id="tv" bind:value={tagValue} placeholder="production" />
          </div>
          <button class="btn btn-p btn-sm" onclick={addTag}>Save tag</button>
        </div>
      </div>
    {:else if detailTab === 'policy'}
      <div class="tab-body">
        <div class="field block">
          <label for="pol">Resource policy (JSON)</label>
          <textarea id="pol" class="mono" rows="14" spellcheck="false" bind:value={policyDoc}></textarea>
        </div>
        <div class="rowact">
          <button class="btn btn-p btn-sm" onclick={savePolicy}>Save policy</button>
          <button class="btn btn-sm" onclick={formatPolicy}>Format JSON</button>
        </div>
      </div>
    {:else if detailTab === 'rotation'}
      <div class="tab-body">
        {#if detail.rotation.enabled}
          <div class="kv-row">
            <span class="kv-l">Rotation</span><span class="kv-v"><span class="badge ok">enabled</span></span>
          </div>
          {#if detail.rotation.nextRotationDate}
            <div class="kv-row">
              <span class="kv-l">Next</span><span class="kv-v small"
                >{detail.rotation.nextRotationDate.replace('T', ' ').replace('Z', '')}</span
              >
            </div>
          {/if}
          <button class="btn btn-sm btn-d" style="margin:0.5rem 0" onclick={cancelRotation}
            >Cancel rotation</button
          >
          <hr />
        {/if}
        <div class="field block">
          <label for="rl">Rotation Lambda ARN</label>
          <input id="rl" class="mono" placeholder="arn:aws:lambda:…" bind:value={rotLambda} />
        </div>
        <div class="field block">
          <label for="rd">Automatically after (days)</label>
          <input id="rd" bind:value={rotDays} />
        </div>
        <label class="chkline"
          ><input type="checkbox" bind:checked={rotImmediate} /> Rotate immediately (create AWSPENDING now)</label
        >
        <button class="btn btn-p btn-sm" onclick={saveRotation}>Save rotation config</button>
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
      <button class="btn {confirmDanger ? 'btn-d' : 'btn-p'}" onclick={runConfirm}>{confirmLabel}</button>
    </div>
  </div>
{/if}

<style>
  .crumbs a {
    color: var(--c-blue);
    text-decoration: none;
  }
  .crumbs a:hover {
    text-decoration: underline;
  }
  .crumbs .cur {
    color: var(--c-text);
    font-weight: 600;
  }
  .bulkbar {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    margin-bottom: 0.5rem;
  }
  .badge.ok {
    background: #e7f6ec;
    color: var(--c-ok);
  }
  .badge.warn {
    background: #fef3c7;
    color: #b45309;
  }
  .linklike {
    background: none;
    border: none;
    color: var(--c-blue);
    cursor: pointer;
    padding: 0;
    font: inherit;
  }
  .linklike:hover {
    text-decoration: underline;
  }
  .rowsel {
    background: #f3f8fd;
  }
  .rowact {
    white-space: nowrap;
    display: flex;
    gap: 0.35rem;
  }
  .chk {
    min-width: auto;
  }
  .small {
    font-size: 0.8rem;
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
  .field.block input,
  .field.block select,
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
  .chkline {
    display: flex;
    align-items: center;
    gap: 0.4rem;
    font-size: 0.85rem;
    margin-bottom: 0.75rem;
  }
  .chkline input {
    min-width: auto;
  }
  hr {
    border: none;
    border-top: 1px solid var(--c-border);
    margin: 1rem 0;
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
</style>
