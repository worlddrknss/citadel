<script lang="ts">
  import { onMount } from 'svelte';
  import { api, ApiError, type OIDCProvider, type Role, type TrustType } from '$lib/api';

  let providers: OIDCProvider[] = $state([]);
  let roles: Role[] = $state([]);
  let loading = $state(false);

  let flash = $state('');
  let flashOk = $state(true);

  // Add-provider modal.
  let providerOpen = $state(false);
  let pUrl = $state('');
  let pAudiences = $state('');

  // Create-role modal.
  let roleOpen = $state(false);
  let rName = $state('');
  let rDescription = $state('');
  let rType: TrustType = $state('oidc');
  let rProvider = $state('');
  let rAudiences = $state('');
  let rSubjects = $state('');
  let rPrincipals = $state('');
  let rMaxSession = $state(3600);

  // Confirm modal (avoids native confirm per UX guidelines).
  let confirmOpen = $state(false);
  let confirmTitle = $state('');
  let confirmBody = $state('');
  let confirmLabel = $state('Delete');
  let confirmAction: (() => Promise<void>) | null = $state(null);

  function notify(msg: string, ok = true) {
    flash = msg;
    flashOk = ok;
    setTimeout(() => (flash = ''), 5000);
  }

  function err(e: unknown) {
    if (e instanceof ApiError) notify(e.message, false);
    else notify('Unexpected error', false);
  }

  function splitList(s: string): string[] {
    return s
      .split(',')
      .map((v) => v.trim())
      .filter(Boolean);
  }

  function fmt(ts: string): string {
    if (!ts) return '—';
    const d = new Date(ts);
    return isNaN(d.getTime()) ? ts : d.toLocaleString();
  }

  async function load() {
    loading = true;
    try {
      providers = (await api.oidcProviders()).providers;
      roles = (await api.roles()).roles;
    } catch (e) {
      err(e);
    } finally {
      loading = false;
    }
  }

  function openProvider() {
    pUrl = '';
    pAudiences = '';
    providerOpen = true;
  }

  async function addProvider() {
    const auds = splitList(pAudiences);
    if (!pUrl.trim() || auds.length === 0) {
      notify('Issuer URL and at least one audience are required', false);
      return;
    }
    try {
      await api.createOIDCProvider(pUrl.trim(), auds);
      notify('Identity provider added');
      providerOpen = false;
      await load();
    } catch (e) {
      err(e);
    }
  }

  function openRole() {
    rName = '';
    rDescription = '';
    rType = 'oidc';
    rProvider = providers[0]?.url ?? '';
    rAudiences = providers[0]?.clientIds?.join(', ') ?? '';
    rSubjects = '';
    rPrincipals = '';
    rMaxSession = 3600;
    roleOpen = true;
  }

  async function addRole() {
    if (!rName.trim()) {
      notify('Role name is required', false);
      return;
    }
    const trust =
      rType === 'oidc'
        ? {
            type: 'oidc' as TrustType,
            providerUrl: rProvider.trim(),
            audiences: splitList(rAudiences),
            subjects: splitList(rSubjects)
          }
        : { type: 'account' as TrustType, principals: splitList(rPrincipals) };
    try {
      await api.createRole({
        roleName: rName.trim(),
        description: rDescription.trim(),
        trust,
        maxSessionSeconds: Number(rMaxSession) || 3600
      });
      notify('Role created');
      roleOpen = false;
      await load();
    } catch (e) {
      err(e);
    }
  }

  function confirmDeleteProvider(p: OIDCProvider) {
    confirmTitle = 'Delete identity provider';
    confirmBody = `Remove ${p.url}? Roles that trust this provider will stop working.`;
    confirmLabel = 'Delete provider';
    confirmAction = async () => {
      await api.deleteOIDCProvider(p.providerArn);
      notify('Identity provider deleted');
      await load();
    };
    confirmOpen = true;
  }

  function confirmDeleteRole(role: Role) {
    confirmTitle = 'Delete role';
    confirmBody = `Delete role ${role.roleName}? Workloads assuming it will lose access.`;
    confirmLabel = 'Delete role';
    confirmAction = async () => {
      await api.deleteRole(role.roleName);
      notify('Role deleted');
      await load();
    };
    confirmOpen = true;
  }

  async function runConfirm() {
    if (!confirmAction) return;
    try {
      await confirmAction();
    } catch (e) {
      err(e);
    } finally {
      confirmOpen = false;
      confirmAction = null;
    }
  }

  onMount(load);
</script>

<div class="ph">
  <h1 class="ph-title">Identity &amp; Access</h1>
  <p class="ph-sub">
    OIDC identity providers and IAM roles for the Security Token Service. Workloads exchange a
    web-identity token for short-lived credentials via <code>AssumeRoleWithWebIdentity</code> — no
    static access keys required.
  </p>
</div>

{#if flash}
  <div class="flash {flashOk ? 'ok' : 'err'}">{flash}</div>
{/if}

<div class="card">
  <div class="card-head">
    <h3 style="margin:0">Identity providers</h3>
    <button class="btn btn-p btn-sm" onclick={openProvider}>Add provider</button>
  </div>
  {#if loading}
    <div class="empty">Loading…</div>
  {:else if providers.length === 0}
    <div class="empty">No identity providers registered.</div>
  {:else}
    <table class="table">
      <thead>
        <tr><th>Issuer URL</th><th>Audiences</th><th>Created</th><th></th></tr>
      </thead>
      <tbody>
        {#each providers as p}
          <tr>
            <td class="mono">{p.url}</td>
            <td>
              {#each p.clientIds as c}<span class="badge mono">{c}</span> {/each}
            </td>
            <td class="muted">{fmt(p.createdAt)}</td>
            <td>
              <button class="btn btn-sm btn-d" onclick={() => confirmDeleteProvider(p)}>Delete</button>
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
</div>

<div class="card" style="margin-top:1rem">
  <div class="card-head">
    <h3 style="margin:0">Roles</h3>
    <button class="btn btn-p btn-sm" onclick={openRole}>Create role</button>
  </div>
  {#if loading}
    <div class="empty">Loading…</div>
  {:else if roles.length === 0}
    <div class="empty">No roles defined.</div>
  {:else}
    <table class="table">
      <thead>
        <tr><th>Role</th><th>Trust</th><th>Conditions</th><th>Max session</th><th></th></tr>
      </thead>
      <tbody>
        {#each roles as role}
          <tr>
            <td>
              <div class="mono">{role.roleName}</div>
              {#if role.description}<div class="muted">{role.description}</div>{/if}
              <div class="muted mono" style="font-size:0.75rem">{role.roleArn}</div>
            </td>
            <td><span class="badge">{role.trust.type}</span></td>
            <td class="mono" style="font-size:0.8rem">
              {#if role.trust.type === 'oidc'}
                <div>{role.trust.providerUrl}</div>
                {#each role.trust.subjects ?? [] as s}<span class="badge">{s}</span> {/each}
              {:else}
                {#each role.trust.principals ?? [] as pr}<span class="badge">{pr}</span> {/each}
              {/if}
            </td>
            <td class="muted">{Math.round(role.maxSessionSeconds / 60)} min</td>
            <td>
              <button class="btn btn-sm btn-d" onclick={() => confirmDeleteRole(role)}>Delete</button>
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
</div>

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

{#if providerOpen}
  <div class="modal-back" role="presentation" onclick={() => (providerOpen = false)}></div>
  <div class="modal">
    <h3 style="margin-top:0">Add identity provider</h3>
    <p class="muted" style="margin-top:0">
      Register an OIDC issuer (e.g. a Kubernetes cluster) whose tokens may be exchanged for
      credentials.
    </p>
    <div class="field">
      <label for="p-url">Issuer URL</label>
      <input id="p-url" class="mono" placeholder="https://oidc.my-cluster.example" bind:value={pUrl} />
    </div>
    <div class="field">
      <label for="p-aud">Audiences (comma-separated)</label>
      <input id="p-aud" class="mono" placeholder="sts.citadel.local" bind:value={pAudiences} />
    </div>
    <div class="modal-actions">
      <button class="btn" onclick={() => (providerOpen = false)}>Cancel</button>
      <button class="btn btn-p" onclick={addProvider}>Add provider</button>
    </div>
  </div>
{/if}

{#if roleOpen}
  <div class="modal-back" role="presentation" onclick={() => (roleOpen = false)}></div>
  <div class="modal modal-lg">
    <h3 style="margin-top:0">Create role</h3>
    <div class="field">
      <label for="r-name">Role name</label>
      <input id="r-name" class="mono" placeholder="varaperformance-secrets" bind:value={rName} />
    </div>
    <div class="field">
      <label for="r-desc">Description</label>
      <input id="r-desc" bind:value={rDescription} />
    </div>
    <div class="field">
      <label for="r-type">Trust type</label>
      <select id="r-type" bind:value={rType}>
        <option value="oidc">Web identity (OIDC)</option>
        <option value="account">Account principal</option>
      </select>
    </div>
    {#if rType === 'oidc'}
      <div class="field">
        <label for="r-prov">Identity provider</label>
        <select id="r-prov" bind:value={rProvider}>
          {#each providers as p}
            <option value={p.url}>{p.url}</option>
          {/each}
        </select>
      </div>
      <div class="field">
        <label for="r-aud">Audiences (comma-separated)</label>
        <input id="r-aud" class="mono" bind:value={rAudiences} />
      </div>
      <div class="field">
        <label for="r-sub">Subjects (comma-separated, trailing * allowed)</label>
        <input
          id="r-sub"
          class="mono"
          placeholder="system:serviceaccount:app:secrets"
          bind:value={rSubjects}
        />
      </div>
    {:else}
      <div class="field">
        <label for="r-prin">Principal account IDs (comma-separated)</label>
        <input id="r-prin" class="mono" placeholder="123456789012" bind:value={rPrincipals} />
      </div>
    {/if}
    <div class="field">
      <label for="r-max">Max session (seconds)</label>
      <input id="r-max" class="mono" type="number" min="900" max="43200" bind:value={rMaxSession} />
    </div>
    <div class="modal-actions">
      <button class="btn" onclick={() => (roleOpen = false)}>Cancel</button>
      <button class="btn btn-p" onclick={addRole}>Create role</button>
    </div>
  </div>
{/if}

<style>
  .card-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 0.75rem;
  }
  .field :global(input),
  .field :global(select) {
    width: 100%;
    min-width: 0;
  }
</style>
