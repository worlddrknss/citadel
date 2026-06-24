<script lang="ts">
  import { onMount } from 'svelte';
  import { api, ApiError, type KMSKey } from '$lib/api';

  let keys: KMSKey[] = $state([]);
  let loading = $state(true);
  let flash = $state('');
  let flashOk = $state(true);

  // Create-key form
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
          <tr>
            <td class="mono">{k.keyId}</td>
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
