<!-- Create or edit an OIDC sign-in provider for the console. The client
     secret is write-only: blank on edit keeps the stored one. -->
<script lang="ts">
  import { untrack } from 'svelte';
  import Modal from '#lib/components/Modal.svelte';
  import Icon from '#lib/components/Icon.svelte';
  import CopyButton from '#lib/components/CopyButton.svelte';
  import { errorMessage, type Account } from '#lib/api.ts';
  import { toast } from '#lib/stores/toast.svelte.ts';
  import { session } from '#lib/stores/session.svelte.ts';
  import { adminApi, ROLES, type RoleMapping, type RoleName, type SsoProvider } from './api';

  let {
    open = $bindable(false),
    provider = null,
    accounts,
    onsaved
  }: { open?: boolean; provider?: SsoProvider | null; accounts: Account[]; onsaved: () => void } = $props();

  let name = $state('');
  let issuer = $state('');
  let clientId = $state('');
  let clientSecret = $state('');
  let replaceSecret = $state(false);
  let scopes = $state('');
  let groupClaim = $state('');
  let mappings = $state<RoleMapping[]>([]);
  let defaultRole = $state<RoleName | 'none'>('none');
  let enabled = $state(true);
  let emailDomains = $state('');
  /** Set after a create: the server's redirect URI to register at the IdP. */
  let created = $state<{ name: string; redirectUri: string } | null>(null);
  let touched = $state(false);
  let busy = $state(false);
  let error = $state('');

  $effect(() => {
    if (open)
      untrack(() => {
        name = provider?.name ?? '';
        issuer = provider?.issuer ?? '';
        clientId = provider?.clientId ?? '';
        clientSecret = '';
        replaceSecret = !provider?.clientSecretSet;
        scopes = (provider?.scopes ?? ['openid', 'email', 'profile', 'groups']).join(' ');
        groupClaim = provider?.groupClaim ?? 'groups';
        mappings = (provider?.roleMappings ?? []).map((m) => ({ ...m }));
        defaultRole = provider?.defaultRole ?? 'none';
        enabled = provider?.enabled ?? false;
        emailDomains = (provider?.allowedEmailDomains ?? []).join(' ');
        created = null;
        touched = false;
        error = '';
      });
  });

  const scopeList = $derived(scopes.split(/[\s,]+/).filter(Boolean));
  const domainList = $derived(emailDomains.split(/[\s,]+/).map((d) => d.trim().toLowerCase()).filter(Boolean));
  // The provider grants its default role in its home account (the current
  // account when creating). Account admins may only map roles there.
  const homeAccount = $derived(provider?.accountId || session.me?.accountId || '');
  const ruleAccounts = $derived(session.platformAdmin ? accounts : accounts.filter((a) => a.accountId === homeAccount));
  const homeName = $derived(accounts.find((a) => a.accountId === homeAccount)?.name ?? homeAccount);
  const errs = $derived({
    name: name.trim() ? '' : 'Give the provider a name users will see on the sign-in button.',
    issuer: /^https?:\/\/[^\s/?#]+([/][^\s?#]*)?$/.test(issuer.trim()) ? '' : 'Enter the issuer URL (https://…), exactly as your identity provider publishes it.',
    clientId: clientId.trim() ? '' : 'Enter the client ID from your identity provider.',
    clientSecret: replaceSecret && !clientSecret ? 'Enter the client secret.' : '',
    scopes: scopeList.includes('openid') ? '' : 'Scopes must include openid.',
    groupClaim: mappings.length && !groupClaim.trim() ? 'Required when you map groups to roles.' : '',
    mappings: mappings.some((m) => !m.group.trim()) ? 'Every rule needs a group name.' : '',
    domains: domainList.every((d) => /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/.test(d)) ? '' : 'Enter domains like example.com, separated by spaces.'
  });
  const invalid = $derived(Object.values(errs).some(Boolean));

  function addRule() {
    mappings = [...mappings, { group: '', accountId: homeAccount || '*', role: 'viewer' }];
  }

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    touched = true;
    if (invalid) return;
    busy = true;
    error = '';
    const body = {
      name: name.trim(),
      // Sent as typed: it must match the discovery document's issuer exactly,
      // trailing slash included (Auth0's has one).
      issuer: issuer.trim(),
      clientId: clientId.trim(),
      ...(replaceSecret ? { clientSecret } : {}),
      scopes: scopeList,
      groupClaim: groupClaim.trim(),
      roleMappings: mappings.map((m) => ({ ...m, group: m.group.trim() })),
      defaultRole,
      allowedEmailDomains: domainList,
      enabled
    };
    try {
      clientSecret = '';
      if (provider) {
        await adminApi.updateSso(provider.id, body);
        toast.success(`Saved ${body.name}`);
        open = false;
      } else {
        // Keep the dialog open on the redirect URI the server will accept.
        const res = await adminApi.createSso(body);
        toast.success(`Added ${body.name}`);
        created = { name: body.name, redirectUri: res.redirectUri };
      }
      onsaved();
    } catch (err) {
      error = errorMessage(err, 'Could not save the provider.');
    } finally {
      busy = false;
    }
  }

  const show = (k: keyof typeof errs) => (touched ? errs[k] : '');
</script>

<Modal bind:open title={created ? `${created.name} added` : provider ? `Edit ${provider.name}` : 'Add sign-in provider'} description="Users sign in to the console with your OpenID Connect identity provider." size="lg">
  {#if created}
    <div class="form">
      <div class="field">
        <span class="field-label">Redirect URI</span>
        {#if created.redirectUri}
          <div class="cb"><code class="mono" data-testid="sso-redirect-uri">{created.redirectUri}</code><CopyButton value={created.redirectUri} label="Copy redirect URI" /></div>
          <span class="field-hint">Register this as an allowed redirect (callback) URL in your identity provider, then enable the provider.</span>
        {:else}
          <span class="field-hint">Set KMS_PUBLIC_URL on the server to get a redirect URI.</span>
        {/if}
      </div>
    </div>
  {:else}
  <form id="sso-form" class="form" onsubmit={submit} novalidate>
    <div class="field-row">
      <div class="field">
        <label class="field-label" for="sso-name">Name</label>
        <input id="sso-name" class="input" bind:value={name} placeholder="Okta" autocomplete="off" aria-invalid={!!show('name')} />
        {#if show('name')}<span class="field-error">{show('name')}</span>{:else}<span class="field-hint">Shown as “Sign in with …”.</span>{/if}
      </div>
      <div class="field">
        <label class="field-label" for="sso-iss">Issuer URL</label>
        <input id="sso-iss" class="input mono" bind:value={issuer} placeholder="https://example.okta.com" autocomplete="off" spellcheck="false" aria-invalid={!!show('issuer')} />
        {#if show('issuer')}<span class="field-error">{show('issuer')}</span>{/if}
      </div>
    </div>
    <div class="field-row">
      <div class="field">
        <label class="field-label" for="sso-cid">Client ID</label>
        <input id="sso-cid" class="input mono" bind:value={clientId} autocomplete="off" spellcheck="false" aria-invalid={!!show('clientId')} />
        {#if show('clientId')}<span class="field-error">{show('clientId')}</span>{/if}
      </div>
      <div class="field">
        <label class="field-label" for="sso-secret">Client secret</label>
        {#if replaceSecret}
          <input id="sso-secret" class="input mono" type="password" bind:value={clientSecret} autocomplete="new-password" spellcheck="false" aria-invalid={!!show('clientSecret')} />
          {#if show('clientSecret')}<span class="field-error">{show('clientSecret')}</span>{:else}<span class="field-hint">Write-only. Citadel stores it encrypted and never shows it again.</span>{/if}
        {:else}
          <div class="secret-set">
            <span class="mono subtle">•••••••••••• stored</span>
            <button type="button" class="btn btn-ghost btn-sm" onclick={() => (replaceSecret = true)}>Replace</button>
          </div>
        {/if}
      </div>
    </div>
    <div class="field">
      <span class="field-label">Redirect URI</span>
      {#if provider?.redirectUri}
        <div class="cb"><code class="mono">{provider.redirectUri}</code><CopyButton value={provider.redirectUri} label="Copy redirect URI" /></div>
        <span class="field-hint">Register this as an allowed redirect (callback) URL in your identity provider.</span>
      {:else if provider}
        <span class="field-hint">Set KMS_PUBLIC_URL on the server to get a redirect URI.</span>
      {:else}
        <span class="field-hint">Shown after you add the provider: it includes the provider's ID.</span>
      {/if}
    </div>
    <div class="field-row">
      <div class="field">
        <label class="field-label" for="sso-scopes">Scopes</label>
        <input id="sso-scopes" class="input mono" bind:value={scopes} autocomplete="off" spellcheck="false" aria-invalid={!!show('scopes')} />
        {#if show('scopes')}<span class="field-error">{show('scopes')}</span>{:else}<span class="field-hint">Space-separated.</span>{/if}
      </div>
      <div class="field">
        <label class="field-label" for="sso-gc">Group claim</label>
        <input id="sso-gc" class="input mono" bind:value={groupClaim} placeholder="groups" autocomplete="off" spellcheck="false" aria-invalid={!!show('groupClaim')} />
        {#if show('groupClaim')}<span class="field-error">{show('groupClaim')}</span>{:else}<span class="field-hint">ID-token claim that lists the user's groups.</span>{/if}
      </div>
    </div>

    <section class="rules" aria-labelledby="rules-title">
      <div class="rules-head">
        <h3 id="rules-title">Group → role mapping</h3>
        <button type="button" class="btn btn-ghost btn-sm" onclick={addRule}><Icon name="plus" size={14} />Add rule</button>
      </div>
      {#if mappings.length === 0}
        <p class="subtle small none">No rules. Everyone who signs in gets the default role below.</p>
      {:else}
        <ul>
          {#each mappings as m, i (i)}
            <li>
              <label class="sr-only" for="rg-{i}">Group for rule {i + 1}</label>
              <input id="rg-{i}" class="input mono" bind:value={m.group} placeholder="platform-admins" autocomplete="off" spellcheck="false" aria-invalid={touched && !m.group.trim()} />
              <label class="sr-only" for="ra-{i}">Account for rule {i + 1}</label>
              <select id="ra-{i}" class="select" bind:value={m.accountId}>
                {#if session.platformAdmin}<option value="*">All accounts</option>{/if}
                {#each ruleAccounts as a (a.accountId)}<option value={a.accountId}>{a.name}</option>{/each}
                {#if !ruleAccounts.some((a) => a.accountId === m.accountId) && !(session.platformAdmin && m.accountId === '*')}<option value={m.accountId}>{m.accountId === '*' ? 'All accounts' : m.accountId}</option>{/if}
              </select>
              <label class="sr-only" for="rr-{i}">Role for rule {i + 1}</label>
              <select id="rr-{i}" class="select" bind:value={m.role}>
                {#each ROLES as r (r.value)}<option value={r.value}>{r.label}</option>{/each}
              </select>
              <button type="button" class="btn-icon" aria-label="Remove rule {i + 1}" onclick={() => (mappings = mappings.filter((_, j) => j !== i))}><Icon name="trash" size={14} /></button>
            </li>
          {/each}
        </ul>
        {#if show('mappings')}<p class="field-error none">{show('mappings')}</p>{/if}
        <p class="subtle small none">When a user matches several rules for one account, the highest role wins.</p>
      {/if}
    </section>

    <div class="field-row">
      <div class="field">
        <label class="field-label" for="sso-def">Default role</label>
        <select id="sso-def" class="select" bind:value={defaultRole}>
          <option value="none">No access (must match a rule)</option>
          <option value="viewer">Viewer in {homeName}</option>
          <option value="editor">Editor in {homeName}</option>
          <option value="admin">Admin in {homeName}</option>
        </select>
        {#if defaultRole === 'admin'}
          <span class="field-hint warn">Everyone your identity provider lets in becomes an admin. Prefer a group rule.</span>
        {:else}
          <span class="field-hint">For users who match no rule. The home account is {homeName}.</span>
        {/if}
      </div>
      <label class="toggle">
        <input type="checkbox" role="switch" bind:checked={enabled} />
        <span><span class="field-label">Enabled</span><span class="field-hint">Show this provider on the sign-in screen.</span></span>
      </label>
    </div>

    <div class="field">
      <label class="field-label" for="sso-domains">Allowed email domains <span class="subtle">(optional)</span></label>
      <input id="sso-domains" class="input mono" bind:value={emailDomains} placeholder="example.com" autocomplete="off" spellcheck="false" aria-invalid={!!show('domains')} />
      {#if show('domains')}<span class="field-error">{show('domains')}</span>{:else}<span class="field-hint">Space-separated. Only users whose verified email is in one of these domains can sign in. Empty allows any.</span>{/if}
    </div>

    {#if error}
      <div class="callout callout-danger" role="alert"><Icon name="alert-circle" size={16} /><span>{error}</span></div>
    {/if}
  </form>
  {/if}
  {#snippet footer()}
    {#if created}
      <button type="button" class="btn btn-primary" onclick={() => (open = false)}>Done</button>
    {:else}
      <button type="button" class="btn btn-ghost" onclick={() => (open = false)}>Cancel</button>
      <button type="submit" form="sso-form" class="btn btn-primary" disabled={busy}>{busy ? 'Saving…' : provider ? 'Save changes' : 'Add provider'}</button>
    {/if}
  {/snippet}
</Modal>

<style>
  .form {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
  }
  .form :global(.field + .field) {
    margin-top: 0;
  }
  .secret-set,
  .cb {
    display: flex;
    align-items: center;
    gap: 6px;
    min-height: var(--ctl-h);
  }
  .cb code {
    overflow-wrap: anywhere;
  }
  .rules {
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    overflow: hidden;
  }
  .rules-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 8px 12px;
    background: var(--surface-hover);
    border-bottom: 1px solid var(--border);
  }
  .rules-head h3 {
    margin: 0;
    font-size: var(--text-base);
    font-weight: 600;
  }
  .rules ul {
    list-style: none;
    margin: 0;
    padding: 12px 12px 0;
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  .rules li {
    display: grid;
    grid-template-columns: minmax(0, 2fr) minmax(0, 1.5fr) minmax(0, 1fr) auto;
    gap: 8px;
    align-items: center;
  }
  @media (max-width: 640px) {
    .rules li {
      grid-template-columns: minmax(0, 1fr) auto;
    }
  }
  .none {
    margin: 0;
    padding: 12px;
  }
  .toggle {
    display: flex;
    gap: 10px;
    align-items: flex-start;
    padding-top: 22px;
    cursor: pointer;
  }
.warn {
    color: var(--warning);
  }
  .toggle > span {
    display: flex;
    flex-direction: column;
  }
</style>
