<script lang="ts">
  import { onMount } from 'svelte';
  import PageHeader from '$lib/components/PageHeader.svelte';
  import Badge from '$lib/components/Badge.svelte';
  import EmptyState from '$lib/components/EmptyState.svelte';
  import CopyButton from '$lib/components/CopyButton.svelte';
  import Icon from '$lib/components/Icon.svelte';
  import { api, errorMessage, type AccessKey } from '$lib/api';
  import { session } from '$lib/stores/session.svelte';
  import { toast } from '$lib/stores/toast.svelte';
  import { confirm } from '$lib/stores/confirm.svelte';
  import OnceSecret from './OnceSecret.svelte';
  import { accountApi, describeAgent, relTime, type SignInSession } from './api';

  const MAX_KEYS = 2;
  const me = $derived(session.me);
  const initials = $derived(
    (me?.displayName || me?.username || '?')
      .split(/\s+/)
      .map((p) => p[0])
      .join('')
      .slice(0, 2)
      .toUpperCase()
  );

  // ---- profile -------------------------------------------------------------
  let displayName = $state('');
  let editingName = $state(false);
  let savingName = $state(false);

  function startEditName() {
    displayName = me?.displayName ?? '';
    editingName = true;
  }

  async function saveName(e: SubmitEvent) {
    e.preventDefault();
    if (!displayName.trim()) return;
    savingName = true;
    try {
      await accountApi.updateProfile(displayName.trim());
      await session.refresh();
      toast.success('Display name updated');
      editingName = false;
    } catch (err) {
      toast.error(err, 'Could not update your name');
    } finally {
      savingName = false;
    }
  }

  // ---- password ------------------------------------------------------------
  let current = $state('');
  let next = $state('');
  let confirmPw = $state('');
  let pwTouched = $state(false);
  let changing = $state(false);
  let pwError = $state('');

  const nextError = $derived(
    next.length < 8 ? 'Use at least 8 characters.' : next === current ? 'Choose a password different from the current one.' : ''
  );
  const confirmError = $derived(confirmPw !== next ? "Passwords don't match." : '');

  async function changePassword(e: SubmitEvent) {
    e.preventDefault();
    pwTouched = true;
    if (!current || nextError || confirmError) return;
    changing = true;
    pwError = '';
    try {
      await api.changePassword(current, next);
      toast.success('Password changed');
      current = next = confirmPw = '';
      pwTouched = false;
    } catch (err) {
      pwError = errorMessage(err, 'Could not change your password.');
    } finally {
      changing = false;
    }
  }

  // ---- access keys ---------------------------------------------------------
  let keys = $state<AccessKey[]>([]);
  let keysLoading = $state(true);
  let keysError = $state('');
  let creating = $state(false);
  let created = $state<{ accessKeyId: string; secretKey: string } | null>(null);
  let createdOpen = $state(false);

  async function loadKeys() {
    keysLoading = true;
    keysError = '';
    try {
      keys = (await api.accessKeys()).accessKeys ?? [];
    } catch (e) {
      keysError = errorMessage(e, 'Could not load access keys.');
    } finally {
      keysLoading = false;
    }
  }

  async function createKey() {
    creating = true;
    try {
      created = await api.createAccessKey();
      createdOpen = true;
      loadKeys();
    } catch (e) {
      toast.error(e, 'Could not create an access key');
    } finally {
      creating = false;
    }
  }

  async function toggleKey(k: AccessKey) {
    const active = k.status === 'Active';
    if (active) {
      const ok = await confirm({
        title: `Deactivate ${k.accessKeyId}?`,
        message: 'Requests signed with this key start failing right away. You can activate it again later.',
        confirmLabel: 'Deactivate'
      });
      if (!ok) return;
    }
    try {
      await api.setAccessKeyStatus(k.accessKeyId, active ? 'Inactive' : 'Active');
      toast.success(`${k.accessKeyId} ${active ? 'deactivated' : 'activated'}`);
      loadKeys();
    } catch (e) {
      toast.error(e, 'Could not change the key status');
    }
  }

  async function deleteKey(k: AccessKey) {
    const ok = await confirm({
      title: 'Delete access key?',
      message:
        k.status === 'Active'
          ? 'This key is still active. Anything using it stops working immediately, and the key cannot be recovered.'
          : 'The key is permanently deleted and cannot be recovered.',
      confirmLabel: 'Delete key',
      danger: true,
      typeToConfirm: k.accessKeyId
    });
    if (!ok) return;
    try {
      await api.deleteAccessKey(k.accessKeyId);
      toast.success(`Deleted ${k.accessKeyId}`);
      loadKeys();
    } catch (e) {
      toast.error(e, 'Could not delete the key');
    }
  }

  const keySnippet = $derived(
    created
      ? `export AWS_ACCESS_KEY_ID=${created.accessKeyId}
export AWS_SECRET_ACCESS_KEY=${created.secretKey}
export AWS_ENDPOINT_URL=${typeof location !== 'undefined' ? location.origin : ''}`
      : ''
  );

  // ---- sessions ------------------------------------------------------------
  let sessions = $state<SignInSession[]>([]);
  let sessLoading = $state(true);
  let sessError = $state('');

  async function loadSessions() {
    sessLoading = true;
    sessError = '';
    try {
      const r = await accountApi.sessions();
      sessions = (r.sessions ?? []).sort((a, b) => Number(b.current) - Number(a.current) || b.lastSeenAt.localeCompare(a.lastSeenAt));
    } catch (e) {
      sessError = errorMessage(e, 'Could not load your sessions.');
    } finally {
      sessLoading = false;
    }
  }

  async function revoke(s: SignInSession) {
    const ok = await confirm({
      title: 'Sign out this session?',
      message: `${describeAgent(s.userAgent)}${s.ip ? ` (${s.ip})` : ''} will be signed out and must sign in again.`,
      confirmLabel: 'Sign out session',
      danger: true
    });
    if (!ok) return;
    try {
      await accountApi.revokeSession(s.id);
      toast.success('Session signed out');
      loadSessions();
    } catch (e) {
      toast.error(e, 'Could not sign out the session');
    }
  }

  async function revokeOthers() {
    const ok = await confirm({
      title: 'Sign out everywhere else?',
      message: 'Every session except this one is signed out. Access keys are not affected.',
      confirmLabel: 'Sign out others',
      danger: true
    });
    if (!ok) return;
    try {
      const r = await accountApi.revokeOtherSessions();
      toast.success(`Signed out ${r.revoked} session${r.revoked === 1 ? '' : 's'}`);
      loadSessions();
    } catch (e) {
      toast.error(e, 'Could not sign out other sessions');
    }
  }

  onMount(() => {
    loadKeys();
    loadSessions();
  });

  const fmt = (s?: string) =>
    s ? new Date(s).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }) : '—';
  const roleTone = (r?: string) => (r === 'admin' ? 'info' : r === 'editor' ? 'success' : 'neutral') as 'info' | 'success' | 'neutral';
</script>

<PageHeader title="My account" description="Your profile, password, API access keys and signed-in sessions." />

<div class="grid">
  <section class="card" aria-labelledby="profile-title">
    <div class="card-head"><h2 id="profile-title">Profile</h2></div>
    <div class="card-pad">
      {#if !me}
        <div class="sk" aria-busy="true"><span class="skeleton"></span><span class="skeleton"></span><span class="skeleton"></span></div>
      {:else}
        <div class="who">
          <span class="avatar" aria-hidden="true">{initials}</span>
          <div class="who-txt">
            {#if editingName}
              <form class="name-form" onsubmit={saveName}>
                <label class="sr-only" for="dn">Display name</label>
                <!-- svelte-ignore a11y_autofocus -->
                <input id="dn" class="input" bind:value={displayName} autocomplete="name" maxlength="80" autofocus required />
                <button type="submit" class="btn btn-primary btn-sm" disabled={savingName || !displayName.trim()}>{savingName ? 'Saving…' : 'Save'}</button>
                <button type="button" class="btn btn-ghost btn-sm" onclick={() => (editingName = false)}>Cancel</button>
              </form>
            {:else}
              <span class="name">
                {me.displayName || me.username}
                <button type="button" class="btn-icon" aria-label="Edit display name" title="Edit display name" onclick={startEditName}><Icon name="edit" size={14} /></button>
              </span>
            {/if}
            <span class="mono subtle small">{me.username}</span>
          </div>
        </div>
        <dl class="kv">
          <dt>Role</dt>
          <dd><Badge tone={roleTone(me.role)} dot={false}>{me.role}</Badge></dd>
          <dt>Current account</dt>
          <dd class="idrow"><span class="mono">{me.accountId || '—'}</span>{#if me.accountId}<CopyButton value={me.accountId} label="Copy account ID" />{/if}</dd>
          <dt>Member of</dt>
          <dd>
            {#if me.accounts?.length}
              <span class="chips">{#each me.accounts as a (a)}<span class="badge mono">{a}</span>{/each}</span>
            {:else}—{/if}
          </dd>
        </dl>
        <p class="subtle small">Your role and account memberships are managed by an administrator.</p>
      {/if}
    </div>
  </section>

  <section class="card" aria-labelledby="pw-title">
    <div class="card-head"><h2 id="pw-title">Password</h2></div>
    <form class="card-pad pw" onsubmit={changePassword} novalidate>
      <!-- Lets password managers associate the new password with this account. -->
      <input type="text" name="username" autocomplete="username" value={me?.username ?? ''} readonly hidden />
      <div class="field">
        <label class="field-label" for="pw-cur">Current password</label>
        <input id="pw-cur" name="current-password" class="input" type="password" autocomplete="current-password" bind:value={current} aria-invalid={pwTouched && !current} required />
        {#if pwTouched && !current}<span class="field-error">Enter your current password.</span>{/if}
      </div>
      <div class="field">
        <label class="field-label" for="pw-new">New password</label>
        <input id="pw-new" name="new-password" class="input" type="password" autocomplete="new-password" minlength="8" bind:value={next} aria-invalid={pwTouched && !!nextError} aria-describedby="pw-new-hint" required />
        {#if pwTouched && nextError}
          <span class="field-error" id="pw-new-hint">{nextError}</span>
        {:else}
          <span class="field-hint" id="pw-new-hint">At least 8 characters; longer is stronger. A passphrase of several words works well.</span>
        {/if}
      </div>
      <div class="field">
        <label class="field-label" for="pw-conf">Confirm new password</label>
        <input id="pw-conf" name="confirm-password" class="input" type="password" autocomplete="new-password" bind:value={confirmPw} aria-invalid={pwTouched && !!confirmError} required />
        {#if pwTouched && confirmError}<span class="field-error">{confirmError}</span>{/if}
      </div>
      {#if pwError}
        <div class="callout callout-danger" role="alert"><Icon name="alert-circle" size={16} /><span>{pwError}</span></div>
      {/if}
      <div class="actions"><button type="submit" class="btn btn-primary" disabled={changing}>{changing ? 'Changing…' : 'Change password'}</button></div>
    </form>
  </section>
</div>

<section class="card block" aria-labelledby="keys-title">
  <div class="card-head">
    <div>
      <h2 id="keys-title">Access keys</h2>
      <p class="subtle small sub">For the AWS CLI and SDKs. You can have up to {MAX_KEYS}, so you can rotate without downtime.</p>
    </div>
    <button type="button" class="btn btn-secondary btn-sm" onclick={createKey} disabled={creating || keysLoading || keys.length >= MAX_KEYS} title={keys.length >= MAX_KEYS ? `You already have ${MAX_KEYS} keys. Delete one to create another.` : undefined}>
      <Icon name="plus" size={14} />{creating ? 'Creating…' : 'Create access key'}
    </button>
  </div>
  {#if keysError}
    <div class="card-pad"><div class="callout callout-danger" role="alert"><Icon name="alert-circle" size={16} /><span>{keysError}</span><button type="button" class="btn btn-ghost btn-sm push" onclick={loadKeys}>Retry</button></div></div>
  {:else if !keysLoading && keys.length === 0}
    <div class="card-pad">
      <EmptyState icon="key" title="No access keys" description="Create one to call the Citadel API from scripts. For workloads, prefer a role with identity federation: no long-lived secret to leak." />
    </div>
  {:else}
    <div class="scroll">
      <table class="table">
        <caption class="sr-only">Access keys</caption>
        <thead><tr><th scope="col">Access key ID</th><th scope="col">Status</th><th scope="col">Created</th><th scope="col">Last used</th><th scope="col" class="end"><span class="sr-only">Actions</span></th></tr></thead>
        <tbody>
          {#if keysLoading && keys.length === 0}
            {#each Array(2) as _, i (i)}<tr>{#each Array(5) as __, j (j)}<td><span class="skeleton cell-sk"></span></td>{/each}</tr>{/each}
          {:else}
            {#each keys as k (k.accessKeyId)}
              <tr>
                <td><span class="idrow"><span class="mono strong">{k.accessKeyId}</span><CopyButton value={k.accessKeyId} label="Copy access key ID" /></span></td>
                <td>
                  {#if k.status === 'Active'}<Badge tone="success" dot={false}><Icon name="check-circle" size={12} />Active</Badge>{:else}<Badge dot={false}>Inactive</Badge>{/if}
                </td>
                <td class="subtle">{fmt(k.createdAt)}</td>
                <td class="subtle">{k.lastUsedAt ? relTime(k.lastUsedAt) : 'Never'}</td>
                <td class="end">
                  <span class="cell-actions">
                    <button type="button" class="btn btn-ghost btn-sm" onclick={() => toggleKey(k)}>{k.status === 'Active' ? 'Deactivate' : 'Activate'}</button>
                    <button type="button" class="btn btn-danger-ghost btn-sm" onclick={() => deleteKey(k)} aria-label="Delete {k.accessKeyId}"><Icon name="trash" size={14} /></button>
                  </span>
                </td>
              </tr>
            {/each}
          {/if}
        </tbody>
      </table>
    </div>
  {/if}
</section>

<section class="card block" aria-labelledby="sess-title">
  <div class="card-head">
    <div>
      <h2 id="sess-title">Active sessions</h2>
      <p class="subtle small sub">Browsers signed in to the console as you.</p>
    </div>
    {#if sessions.filter((s) => !s.current).length > 0}
      <button type="button" class="btn btn-danger-ghost btn-sm" onclick={revokeOthers}><Icon name="log-out" size={14} />Sign out other sessions</button>
    {/if}
  </div>
  {#if sessError}
    <div class="card-pad"><div class="callout callout-danger" role="alert"><Icon name="alert-circle" size={16} /><span>{sessError}</span><button type="button" class="btn btn-ghost btn-sm push" onclick={loadSessions}>Retry</button></div></div>
  {:else}
    <ul class="sessions" aria-busy={sessLoading}>
      {#if sessLoading && sessions.length === 0}
        {#each Array(2) as _, i (i)}<li><span class="skeleton cell-sk"></span></li>{/each}
      {:else}
        {#each sessions as s (s.id)}
          <li>
            <span class="dev" aria-hidden="true"><Icon name="monitor" size={16} /></span>
            <span class="s-txt">
              <span class="s-name">
                {describeAgent(s.userAgent)}
                {#if s.current}<Badge tone="success" dot={false}>This device</Badge>{/if}
                {#if s.method === 'sso'}<span class="badge">SSO</span>{/if}
              </span>
              <span class="subtle small">
                {s.ip ?? 'Unknown IP'} · signed in {relTime(s.createdAt)} · active {relTime(s.lastSeenAt)}{s.accountId ? ` · ${s.accountId}` : ''}
              </span>
            </span>
            {#if !s.current}
              <button type="button" class="btn btn-ghost btn-sm" onclick={() => revoke(s)} aria-label="Sign out {describeAgent(s.userAgent)} session">Sign out</button>
            {/if}
          </li>
        {:else}
          <li class="subtle">No sessions to show.</li>
        {/each}
      {/if}
    </ul>
  {/if}
</section>

{#if created}
  <OnceSecret
    bind:open={createdOpen}
    title="Access key created"
    description="Use these credentials with the AWS CLI or any AWS SDK pointed at Citadel."
    fields={[
      { label: 'Access key ID', value: created.accessKeyId },
      { label: 'Secret access key', value: created.secretKey, secret: true },
      { label: 'Shell environment', value: keySnippet, multiline: true, secret: true, filename: 'citadel-credentials.env' }
    ]}
    ondone={() => (created = null)}
  />
{/if}

<style>
  .grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(min(380px, 100%), 1fr));
    gap: 20px;
    align-items: start;
  }
  .block {
    margin-top: 20px;
    overflow: hidden;
  }
  .card-head h2 {
    font-family: var(--font-sans);
    font-size: var(--text-md);
    letter-spacing: 0;
  }
  .sub {
    margin: 2px 0 0;
  }
  .sk {
    display: flex;
    flex-direction: column;
    gap: 10px;
  }
  .sk .skeleton {
    height: 14px;
  }
  .who {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: var(--space-4);
  }
  .avatar {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    flex: none;
    width: 44px;
    height: 44px;
    border-radius: 50%;
    background: var(--accent-soft);
    color: var(--accent-text);
    font-weight: 600;
  }
  .who-txt {
    display: flex;
    flex-direction: column;
    min-width: 0;
    flex: 1;
  }
  .name {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    font-size: var(--text-md);
    font-weight: 600;
  }
  .name-form {
    display: flex;
    gap: 6px;
    flex-wrap: wrap;
  }
  .name-form .input {
    flex: 1 1 180px;
    width: auto;
  }
  .kv {
    grid-template-columns: 130px minmax(0, 1fr);
  }
  .idrow {
    display: inline-flex;
    align-items: center;
    gap: 4px;
  }
  .chips {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
  }
  .card-pad > p {
    margin: var(--space-4) 0 0;
  }
  .pw {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
  }
  .pw .field + .field {
    margin-top: 0;
  }
  .actions {
    display: flex;
    justify-content: flex-end;
  }
  .scroll {
    overflow-x: auto;
  }
  .table {
    min-width: 640px;
  }
  .strong {
    font-weight: 500;
  }
  .end {
    text-align: end;
  }
  .cell-sk {
    display: block;
    height: 12px;
    width: 60%;
  }
  .push {
    margin-left: auto;
  }
  .sessions {
    list-style: none;
    margin: 0;
    padding: 0;
  }
  .sessions li {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 12px var(--space-5);
    border-top: 1px solid var(--border);
  }
  .sessions li:first-child {
    border-top: 0;
  }
  .dev {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    flex: none;
    width: 32px;
    height: 32px;
    border-radius: var(--radius-md);
    background: var(--surface-pressed);
    color: var(--text-muted);
  }
  .s-txt {
    display: flex;
    flex-direction: column;
    flex: 1;
    min-width: 0;
  }
  .s-name {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
    font-weight: 500;
  }
  @media (max-width: 820px) {
    .kv {
      grid-template-columns: minmax(0, 1fr);
    }
  }
</style>
