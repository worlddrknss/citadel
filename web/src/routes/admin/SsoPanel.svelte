<!-- Console single sign-on: OIDC providers users can sign in with. -->
<script lang="ts">
  import { onMount } from 'svelte';
  import Icon from '$lib/components/Icon.svelte';
  import Badge from '$lib/components/Badge.svelte';
  import EmptyState from '$lib/components/EmptyState.svelte';
  import { errorMessage, type Account } from '$lib/api';
  import { toast } from '$lib/stores/toast.svelte';
  import { confirm } from '$lib/stores/confirm.svelte';
  import SsoEditor from './SsoEditor.svelte';
  import { session } from '$lib/stores/session.svelte';
  import { adminApi, fmtDate, ssoOrgWide, type SsoProvider } from './api';

  let { accounts }: { accounts: Account[] } = $props();

  // Account admins see the providers of their account, but the server only
  // lets platform admins change ones whose rules reach other accounts.
  const canManage = (p: SsoProvider) => session.platformAdmin || (p.accountId === session.me?.accountId && !ssoOrgWide(p));
  const accountLabel = (id: string) => accounts.find((a) => a.accountId === id)?.name ?? id;

  let providers = $state<SsoProvider[]>([]);
  let loading = $state(true);
  let loadError = $state('');
  let editorOpen = $state(false);
  let editing = $state<SsoProvider | null>(null);
  let testing = $state('');

  async function load() {
    loading = true;
    loadError = '';
    try {
      providers = (await adminApi.ssoProviders()).providers ?? [];
    } catch (e) {
      loadError = errorMessage(e, 'Could not load sign-in providers.');
    } finally {
      loading = false;
    }
  }
  onMount(load);

  function add() {
    editing = null;
    editorOpen = true;
  }
  function edit(p: SsoProvider) {
    editing = p;
    editorOpen = true;
  }

  async function test(p: SsoProvider) {
    testing = p.id;
    try {
      const r = await adminApi.testSso(p.id);
      if (r.ok) toast.success(`${p.name}: discovery OK`);
      else toast.error(r.message || `${p.name}: discovery failed`);
    } catch (e) {
      toast.error(e, 'Test failed');
    } finally {
      testing = '';
    }
  }

  async function setEnabled(p: SsoProvider, enabled: boolean) {
    if (!enabled) {
      const ok = await confirm({
        title: `Disable ${p.name}?`,
        message: 'Users who only sign in with this provider will not be able to reach the console. Existing sessions stay active until they expire.',
        confirmLabel: 'Disable',
        danger: true
      });
      if (!ok) return;
    }
    try {
      await adminApi.updateSso(p.id, {
        name: p.name,
        issuer: p.issuer,
        clientId: p.clientId,
        scopes: p.scopes,
        groupClaim: p.groupClaim,
        roleMappings: p.roleMappings,
        defaultRole: p.defaultRole,
        // The server replaces the whole provider: omitting this would clear it.
        allowedEmailDomains: p.allowedEmailDomains ?? [],
        enabled
      });
      toast.success(`${p.name} ${enabled ? 'enabled' : 'disabled'}`);
      load();
    } catch (e) {
      toast.error(e, 'Could not update the provider');
    }
  }

  async function remove(p: SsoProvider) {
    const ok = await confirm({
      title: `Delete ${p.name}?`,
      message: 'Its configuration and client secret are removed. Users who sign in with it lose console access.',
      confirmLabel: 'Delete provider',
      danger: true,
      typeToConfirm: p.name
    });
    if (!ok) return;
    try {
      await adminApi.deleteSso(p.id);
      toast.success(`Deleted ${p.name}`);
      load();
    } catch (e) {
      toast.error(e, 'Could not delete the provider');
    }
  }
</script>

<section class="card" aria-labelledby="sso-title">
  <div class="card-head">
    <div>
      <h2 id="sso-title">Single sign-on</h2>
      <p class="subtle small sub">OpenID Connect providers for console sign-in. Password sign-in keeps working for local users.</p>
    </div>
    <button type="button" class="btn btn-secondary btn-sm" onclick={add}><Icon name="plus" size={14} />Add provider</button>
  </div>
  {#if loadError}
    <div class="card-pad"><div class="callout callout-danger" role="alert"><Icon name="alert-circle" size={16} /><span>{loadError}</span><button type="button" class="btn btn-ghost btn-sm push" onclick={load}>Retry</button></div></div>
  {:else if !loading && providers.length === 0}
    <div class="card-pad">
      <EmptyState icon="shield" title="No sign-in providers" description="Connect Okta, Entra ID, Google Workspace, Keycloak or any OIDC provider, and map its groups to Citadel roles.">
        <button type="button" class="btn btn-primary btn-sm" onclick={add}><Icon name="plus" size={14} />Add provider</button>
      </EmptyState>
    </div>
  {:else}
    <div class="scroll">
      <table class="table">
        <caption class="sr-only">Sign-in providers</caption>
        <thead><tr><th scope="col">Provider</th><th scope="col">Client ID</th><th scope="col">Role mapping</th><th scope="col">Status</th><th scope="col">Updated</th><th scope="col" class="end"><span class="sr-only">Actions</span></th></tr></thead>
        <tbody>
          {#if loading && providers.length === 0}
            {#each Array(2) as _, i (i)}<tr>{#each Array(6) as __, j (j)}<td><span class="skeleton sk"></span></td>{/each}</tr>{/each}
          {:else}
            {#each providers as p (p.id)}
              <tr>
                <td><span class="strong">{p.name}</span><span class="mono subtle sub2">{p.issuer}</span>{#if p.accountId}<span class="subtle sub2">Home account: {accountLabel(p.accountId)}{ssoOrgWide(p) ? ' · org-wide' : ''}</span>{/if}</td>
                <td class="mono">{p.clientId}</td>
                <td class="muted">
                  {p.roleMappings.length} rule{p.roleMappings.length === 1 ? '' : 's'} · default {p.defaultRole === 'none' ? 'no access' : p.defaultRole}
                </td>
                <td>
                  <label class="switch">
                    <input type="checkbox" role="switch" checked={p.enabled} disabled={!canManage(p)} onchange={(e) => { const on = e.currentTarget.checked; e.currentTarget.checked = p.enabled; setEnabled(p, on); }} aria-label="{p.name} enabled" />
                    <Badge tone={p.enabled ? 'success' : 'neutral'} dot={false}>{p.enabled ? 'Enabled' : 'Disabled'}</Badge>
                  </label>
                </td>
                <td class="subtle">{fmtDate(p.updatedAt)}</td>
                <td class="end">
                  {#if canManage(p)}
                    <span class="cell-actions">
                      <button type="button" class="btn btn-ghost btn-sm" onclick={() => test(p)} disabled={testing === p.id}>{testing === p.id ? 'Testing…' : 'Test'}</button>
                      <button type="button" class="btn-icon" aria-label="Edit {p.name}" title="Edit" onclick={() => edit(p)}><Icon name="edit" size={14} /></button>
                      <button type="button" class="btn-icon danger" aria-label="Delete {p.name}" title="Delete" onclick={() => remove(p)}><Icon name="trash" size={14} /></button>
                    </span>
                  {:else}
                    <span class="subtle small">Platform admins manage this</span>
                  {/if}
                </td>
              </tr>
            {/each}
          {/if}
        </tbody>
      </table>
    </div>
  {/if}
</section>

<SsoEditor bind:open={editorOpen} provider={editing} {accounts} onsaved={load} />

<style>
  .card-head h2 {
    font-family: var(--font-sans);
    font-size: var(--text-md);
    letter-spacing: 0;
  }
  .sub {
    margin: 2px 0 0;
  }
  .sub2 {
    display: block;
    font-size: 12.5px;
  }
  .scroll {
    overflow-x: auto;
  }
  .table {
    min-width: 760px;
  }
  .table td {
    white-space: nowrap;
  }
  .strong {
    font-weight: 500;
  }
  .switch {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    cursor: pointer;
  }
  .end {
    text-align: end;
  }
  .sk {
    display: block;
    height: 12px;
    width: 70%;
  }
  .push {
    margin-left: auto;
  }
  .danger:hover:not(:disabled) {
    color: var(--danger);
    background: var(--danger-soft);
  }
</style>
