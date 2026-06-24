<script lang="ts">
  import { onMount } from 'svelte';
  import { api, ApiError, type Certificate } from '$lib/api';

  let certs: Certificate[] = $state([]);
  let loading = $state(true);
  let flash = $state('');
  let flashOk = $state(true);

  const sourceLabel: Record<string, string> = {
    'pca-ca': 'Private CA',
    'pca-cert': 'Issued (PCA)',
    'lets-encrypt': "Let's Encrypt"
  };

  // Create-CA form
  let caCommonName = $state('');
  let caOrg = $state('');
  let caCountry = $state('');
  let caType = $state('ROOT');
  let caKeyAlg = $state('RSA_2048');
  let creatingCA = $state(false);

  // Issue-cert form
  let issueCaArn = $state('');
  let csrPem = $state('');
  let validityDays = $state('365');
  let sanNames = $state('');
  let issuing = $state(false);

  const cas = $derived(certs.filter((c) => c.source === 'pca-ca'));

  function notify(msg: string, ok = true) {
    flash = msg;
    flashOk = ok;
    setTimeout(() => (flash = ''), 5000);
  }

  async function load() {
    loading = true;
    try {
      certs = (await api.certificates()).certificates;
    } catch (e) {
      if (e instanceof ApiError) notify(e.message, false);
    } finally {
      loading = false;
    }
  }

  async function createCA() {
    if (!caCommonName.trim()) {
      notify('common name is required', false);
      return;
    }
    creatingCA = true;
    try {
      const res = await api.createCA({
        caType,
        keyAlgorithm: caKeyAlg,
        commonName: caCommonName.trim(),
        organization: caOrg.trim(),
        country: caCountry.trim()
      });
      notify(`Created CA ${res.caId}`);
      caCommonName = '';
      caOrg = '';
      caCountry = '';
      await load();
    } catch (e) {
      if (e instanceof ApiError) notify(e.message, false);
    } finally {
      creatingCA = false;
    }
  }

  async function issueCert() {
    if (!issueCaArn || !csrPem.trim()) {
      notify('CA and CSR are required', false);
      return;
    }
    issuing = true;
    try {
      await api.issueCert({ caArn: issueCaArn, csrPem: csrPem.trim(), validityDays, sanNames: sanNames.trim() });
      notify('Certificate issued');
      csrPem = '';
      sanNames = '';
      await load();
    } catch (e) {
      if (e instanceof ApiError) notify(e.message, false);
    } finally {
      issuing = false;
    }
  }

  async function revoke(c: Certificate) {
    if (!confirm(`Revoke certificate ${c.id}?`)) return;
    try {
      await api.revokeCert(c.id, 'Unspecified');
      notify(`Revoked ${c.id}`);
      await load();
    } catch (e) {
      if (e instanceof ApiError) notify(e.message, false);
    }
  }

  onMount(load);
</script>

<div class="ph">
  <h1 class="ph-title">Certificate Management</h1>
  <p class="ph-sub">Private CA hierarchy, issued certificates, and ACME / Let's Encrypt certificates.</p>
</div>

{#if flash}
  <div class="flash {flashOk ? 'ok' : 'err'}">{flash}</div>
{/if}

<div class="card">
  <h3 style="margin-top:0">Certificates</h3>
  {#if loading}
    <div class="empty">Loading…</div>
  {:else if certs.length === 0}
    <div class="empty">No certificates yet.</div>
  {:else}
    <table>
      <thead>
        <tr>
          <th>Source</th>
          <th>ID</th>
          <th>Subject / Serial</th>
          <th>Status</th>
          <th>Not After</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        {#each certs as c}
          <tr>
            <td>{sourceLabel[c.source] ?? c.source}</td>
            <td class="mono">{c.id}</td>
            <td>{c.subject || '—'}</td>
            <td><span class="badge">{c.status || '—'}</span></td>
            <td class="muted">{c.notAfter ? new Date(c.notAfter).toLocaleDateString() : '—'}</td>
            <td>
              {#if c.source === 'pca-cert' && c.status !== 'REVOKED'}
                <button class="btn btn-sm btn-d" onclick={() => revoke(c)}>Revoke</button>
              {/if}
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
</div>

<div class="card" style="margin-top:1.25rem">
  <h3 style="margin-top:0">Create private CA</h3>
  <div class="toolbar">
    <div class="field" style="flex:1">
      <label for="cn">Common name</label>
      <input id="cn" placeholder="Example Root CA" bind:value={caCommonName} />
    </div>
    <div class="field">
      <label for="org">Organization</label>
      <input id="org" placeholder="Example Inc" bind:value={caOrg} />
    </div>
    <div class="field" style="width:5rem">
      <label for="cc">Country</label>
      <input id="cc" placeholder="US" bind:value={caCountry} />
    </div>
  </div>
  <div class="toolbar" style="margin-bottom:0">
    <div class="field">
      <label for="ct">Type</label>
      <select id="ct" bind:value={caType}>
        <option value="ROOT">ROOT</option>
        <option value="SUBORDINATE">SUBORDINATE</option>
      </select>
    </div>
    <div class="field">
      <label for="ka">Key algorithm</label>
      <select id="ka" bind:value={caKeyAlg}>
        <option value="RSA_2048">RSA_2048</option>
        <option value="RSA_3072">RSA_3072</option>
        <option value="RSA_4096">RSA_4096</option>
        <option value="EC_prime256v1">EC_prime256v1</option>
        <option value="EC_secp384r1">EC_secp384r1</option>
      </select>
    </div>
    <div class="field" style="align-self:flex-end">
      <button class="btn btn-p" onclick={createCA} disabled={creatingCA}>
        {creatingCA ? 'Creating…' : 'Create CA'}
      </button>
    </div>
  </div>
</div>

<div class="card" style="margin-top:1.25rem">
  <h3 style="margin-top:0">Issue certificate</h3>
  <div class="toolbar">
    <div class="field" style="flex:1">
      <label for="ica">Issuing CA</label>
      <select id="ica" bind:value={issueCaArn}>
        <option value="">(select a CA)</option>
        {#each cas as ca}
          <option value={ca.id}>{ca.subject}</option>
        {/each}
      </select>
    </div>
    <div class="field" style="width:8rem">
      <label for="vd">Validity (days)</label>
      <input id="vd" bind:value={validityDays} />
    </div>
  </div>
  <div class="field" style="margin-bottom:0.75rem">
    <label for="csr">CSR (PEM)</label>
    <textarea id="csr" class="mono" rows="6" placeholder="-----BEGIN CERTIFICATE REQUEST-----" bind:value={csrPem}></textarea>
  </div>
  <div class="toolbar" style="margin-bottom:0">
    <div class="field" style="flex:1">
      <label for="san">SAN names (optional, comma/space separated)</label>
      <input id="san" placeholder="example.com www.example.com" bind:value={sanNames} />
    </div>
    <div class="field" style="align-self:flex-end">
      <button class="btn btn-p" onclick={issueCert} disabled={issuing}>
        {issuing ? 'Issuing…' : 'Issue certificate'}
      </button>
    </div>
  </div>
</div>

<style>
  textarea {
    width: 100%;
    box-sizing: border-box;
    resize: vertical;
  }
</style>
