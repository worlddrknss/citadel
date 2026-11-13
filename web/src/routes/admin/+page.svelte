<script lang="ts">
  import PageHeader from '#lib/components/PageHeader.svelte';
  import Tabs from '#lib/components/Tabs.svelte';
  import DataTable, { type Column } from '#lib/components/DataTable.svelte';
  import EmptyState from '#lib/components/EmptyState.svelte';
  import Badge from '#lib/components/Badge.svelte';
  import CopyButton from '#lib/components/CopyButton.svelte';
  import Modal from '#lib/components/Modal.svelte';
  import Icon from '#lib/components/Icon.svelte';
  import { api, errorMessage, type Account } from '#lib/api.ts';
  import { session } from '#lib/stores/session.svelte.ts';
  import { toast } from '#lib/stores/toast.svelte.ts';
  import { confirm } from '#lib/stores/confirm.svelte.ts';
  import { mfaApi } from '#lib/mfa.ts';
  import { param, setParams } from '#lib/url.ts';
  import UserModal from './UserModal.svelte';
  import MembershipModal from './MembershipModal.svelte';
  import SettingsPanel from './SettingsPanel.svelte';
  import SsoPanel from './SsoPanel.svelte';
  import AgentsKillSwitch from './AgentsKillSwitch.svelte';
  import NotificationsPanel from './NotificationsPanel.svelte';
  import { roleTone, fmtDate, type RoleName, type UserRow } from './api';

  const isAdmin = $derived(session.can('admin'));
  // Account admins manage their current account only; platform admins
  // manage accounts, org settings and every user (the server enforces this).
  const isPlatform = $derived(session.platformAdmin);
  const me = $derived(session.me);

  let users = $state<UserRow[]>([]);
  let accounts = $state<Account[]>([]);
  let loading = $state(true);
  let loadError = $state('');
  let started = false;

  async function load() {
    loading = true;
    loadError = '';
    try {
      const [u, a] = await Promise.all([api.users(), api.accounts()]);
      users = u.users ?? [];
      accounts = a.accounts ?? [];
    } catch (e) {
      loadError = errorMessage(e, 'Could not load users and accounts.');
    } finally {
      loading = false;
    }
  }
  $effect(() => {
    if (isAdmin && !started) {
      started = true;
      load();
    }
  });

  const tab = $derived(param('tab', 'users'));
  let tabValue = $state('users');
  $effect(() => {
    tabValue = tab;
  });
  let query = $state('');

  const accountName = (id: string) => accounts.find((a) => a.accountId === id)?.name ?? id;
  /** Accounts the signed-in admin may add members to. */
  const manageableAccounts = $derived(isPlatform ? accounts : accounts.filter((a) => a.accountId === me?.accountId));
  /** Mirrors the server: account admins can't touch platform admins or people in other accounts. */
  const canManageUser = (u: UserRow) =>
    isPlatform || (!u.platformAdmin && (u.accounts ?? []).length > 0 && (u.accounts ?? []).every((a) => a === me?.accountId));
  const canManageAccount = (id: string) => isPlatform || id === me?.accountId;

  interface Membership {
    username: string;
    displayName: string;
    accountId: string;
    role: RoleName | '';
  }
  const memberships = $derived<Membership[]>(
    users.flatMap((u) => {
      const roles = new Map((u.memberships ?? []).map((m) => [m.accountId, m.role]));
      const ids = new Set([...(u.accounts ?? []), ...roles.keys()]);
      return [...ids].map((accountId) => ({ username: u.username, displayName: u.displayName, accountId, role: roles.get(accountId) ?? '' }));
    })
  );
  const memberCount = (id: string) => memberships.filter((m) => m.accountId === id).length;

  // ---- users ---------------------------------------------------------------
  let userOpen = $state(false);
  let editingUser = $state<UserRow | null>(null);

  async function deleteUser(u: UserRow) {
    const ok = await confirm({
      title: `Delete ${u.username}?`,
      message: `They lose console access to ${u.accounts?.length ?? 0} account(s) immediately. Their access keys are deleted too. This cannot be undone.`,
      confirmLabel: 'Delete user',
      danger: true,
      typeToConfirm: u.username
    });
    if (!ok) return;
    try {
      await api.deleteUser(u.username);
      toast.success(`Deleted ${u.username}`);
      await load();
    } catch (e) {
      toast.error(e, 'Could not delete the user');
    }
  }

  async function resetMfa(u: UserRow) {
    const ok = await confirm({
      title: `Reset two-step verification for ${u.username}?`,
      message: `Their authenticator app and recovery codes stop working and they are signed out everywhere. They sign in with their password next time${requireMfaHint}.`,
      confirmLabel: 'Reset MFA',
      danger: true,
      typeToConfirm: u.username
    });
    if (!ok) return;
    try {
      await mfaApi.adminReset(u.username);
      toast.success(`Reset two-step verification for ${u.username}`);
      await load();
    } catch (e) {
      toast.error(e, 'Could not reset two-step verification');
    }
  }
  const requireMfaHint = ' (and set it up again if your organization requires it)';

  // ---- accounts ------------------------------------------------------------
  let accountOpen = $state(false);
  let accountName_ = $state('');
  let accountBusy = $state(false);
  let accountError = $state('');

  async function createAccount(e: SubmitEvent) {
    e.preventDefault();
    if (!accountName_.trim()) {
      accountError = 'Give the account a name.';
      return;
    }
    accountBusy = true;
    accountError = '';
    try {
      const r = await api.createAccount(accountName_.trim());
      toast.success(`Created ${accountName_.trim()} (${r.accountId})`);
      accountOpen = false;
      await load();
    } catch (err) {
      accountError = errorMessage(err, 'Could not create the account.');
    } finally {
      accountBusy = false;
    }
  }

  async function deleteAccount(a: Account) {
    const ok = await confirm({
      title: `Delete ${a.name}?`,
      message: `Every secret, parameter, key, certificate and role in ${a.accountId} is permanently destroyed, and ${memberCount(a.accountId)} member(s) lose access. This cannot be undone.`,
      confirmLabel: 'Delete account',
      danger: true,
      typeToConfirm: a.accountId
    });
    if (!ok) return;
    try {
      await api.deleteAccount(a.accountId);
      toast.success(`Deleted ${a.name}`);
      await load();
    } catch (e) {
      toast.error(e, 'Could not delete the account');
    }
  }

  // ---- memberships ---------------------------------------------------------
  let memOpen = $state(false);
  let memPreset = $state<{ username?: string; accountId?: string; role?: RoleName; editing?: boolean } | null>(null);

  function addMembership(preset: { username?: string; accountId?: string } | null = null) {
    memPreset = preset;
    memOpen = true;
  }

  async function removeMembership(m: Membership) {
    const self = m.username === me?.username && m.accountId === me?.accountId;
    const ok = await confirm({
      title: `Remove ${m.username} from ${accountName(m.accountId)}?`,
      message: self
        ? 'This is the account you are signed in to. You will lose access to it when your session ends.'
        : 'They lose access to this account at their next request. Their access keys for it stop working.',
      confirmLabel: 'Remove',
      danger: true
    });
    if (!ok) return;
    try {
      await api.removeUserAccount(m.username, m.accountId);
      toast.success(`Removed ${m.username} from ${accountName(m.accountId)}`);
      await load();
    } catch (e) {
      toast.error(e, 'Could not remove the membership');
    }
  }

  const userCols: Column<UserRow>[] = [
    { id: 'user', label: 'User', sort: (u) => u.displayName || u.username },
    { id: 'role', label: 'Default role', sort: (u) => u.role },
    { id: 'accounts', label: 'Accounts', sort: (u) => u.accounts?.length ?? 0, hideOnMobile: true },
    { id: 'act', label: '', align: 'end', width: '96px' }
  ];
  const accountCols: Column<Account>[] = [
    { id: 'name', label: 'Account', sort: (a) => a.name },
    { id: 'id', label: 'Account ID', sort: (a) => a.accountId },
    { id: 'members', label: 'Members', sort: (a) => memberCount(a.accountId), hideOnMobile: true },
    { id: 'created', label: 'Created', sort: (a) => a.createdAt, hideOnMobile: true },
    { id: 'act', label: '', align: 'end', width: '64px' }
  ];
  const memCols: Column<Membership>[] = [
    { id: 'user', label: 'User', sort: (m) => m.username },
    { id: 'account', label: 'Account', sort: (m) => accountName(m.accountId) },
    { id: 'role', label: 'Role in account', sort: (m) => m.role },
    { id: 'act', label: '', align: 'end', width: '120px' }
  ];
</script>

<PageHeader title="Administration" description="Users, accounts and who can reach what, plus organization-wide security settings.">
  {#snippet actions()}
    {#if isAdmin}
      {#if tab === 'users'}
        <button type="button" class="btn btn-primary" onclick={() => { editingUser = null; userOpen = true; }}><Icon name="plus" size={16} />Create user</button>
      {:else if tab === 'accounts' && isPlatform}
        <button type="button" class="btn btn-primary" onclick={() => { accountName_ = ''; accountError = ''; accountOpen = true; }}><Icon name="plus" size={16} />Create account</button>
      {:else if tab === 'memberships'}
        <button type="button" class="btn btn-primary" onclick={() => addMembership()}><Icon name="plus" size={16} />Add membership</button>
      {/if}
    {/if}
  {/snippet}
</PageHeader>

{#if session.status === 'signed-in' && !isAdmin}
  <div class="card card-pad">
    <EmptyState icon="lock" title="Administrators only" description="Ask an administrator if you need a user created, an account added or a role changed." />
  </div>
{:else}
  <div class="tabs-row">
    <Tabs
      label="Administration sections"
      tabs={[
        { id: 'users', label: 'Users', count: loading ? undefined : users.length },
        { id: 'accounts', label: 'Accounts', count: loading ? undefined : accounts.length },
        { id: 'memberships', label: 'Memberships', count: loading ? undefined : memberships.length },
        { id: 'settings', label: 'Settings' },
        { id: 'notifications', label: 'Notifications' }
      ]}
      bind:active={tabValue}
      onchange={(t) => {
        query = '';
        setParams({ tab: t === 'users' ? null : t });
      }}
    />
  </div>

  {#if loadError && tab !== 'settings' && tab !== 'notifications'}
    <div class="callout callout-danger err" role="alert">
      <Icon name="alert-circle" size={16} /><span>{loadError}</span>
      <button type="button" class="btn btn-ghost btn-sm push" onclick={load}>Retry</button>
    </div>
  {/if}

  {#if tab === 'accounts'}
    <DataTable caption="Accounts" rows={accounts} columns={accountCols} key={(a) => a.accountId} {loading} searchable={(a) => `${a.name} ${a.accountId}`} searchPlaceholder="Search accounts" bind:query>
      {#snippet row(a)}
        <td>
          <span class="strong">{a.name}</span>
          {#if a.accountId === me?.accountId}<Badge tone="success" dot={false}>Current</Badge>{/if}
        </td>
        <td><span class="idrow"><span class="mono">{a.accountId}</span><CopyButton value={a.accountId} label="Copy account ID" /></span></td>
        <td class="hide-sm">
          <button type="button" class="row-link" onclick={() => { query = a.accountId; setParams({ tab: 'memberships' }); }}>{memberCount(a.accountId)} member{memberCount(a.accountId) === 1 ? '' : 's'}</button>
        </td>
        <td class="subtle hide-sm">{fmtDate(a.createdAt)}</td>
        <td class="end">
          {#if isPlatform}
            <button
              type="button"
              class="btn-icon danger"
              aria-label="Delete {a.name}"
              title={a.accountId === me?.accountId ? "You can't delete the account you're signed in to" : 'Delete'}
              disabled={a.accountId === me?.accountId}
              onclick={() => deleteAccount(a)}
            >
              <Icon name="trash" size={14} />
            </button>
          {/if}
        </td>
      {/snippet}
      {#snippet empty()}
        <EmptyState icon="building" title="No accounts" description="Accounts isolate secrets, keys and certificates, like separate AWS accounts." />
      {/snippet}
    </DataTable>
  {:else if tab === 'memberships'}
    <DataTable
      caption="Memberships"
      rows={memberships}
      columns={memCols}
      key={(m) => `${m.username}@${m.accountId}`}
      {loading}
      searchable={(m) => `${m.username} ${m.displayName} ${m.accountId} ${accountName(m.accountId)} ${m.role}`}
      searchPlaceholder="Search by user, account or role"
      bind:query
    >
      {#snippet row(m)}
        <td><span class="strong">{m.displayName || m.username}</span>{#if m.displayName && m.displayName !== m.username}<span class="mono subtle sub">{m.username}</span>{/if}</td>
        <td><span class="strong">{accountName(m.accountId)}</span><span class="mono subtle sub">{m.accountId}</span></td>
        <td>{#if m.role}<Badge tone={roleTone(m.role)} dot={false}>{m.role}</Badge>{:else}<span class="subtle small">Default role</span>{/if}</td>
        <td class="end">
          {#if canManageAccount(m.accountId)}
            <span class="cell-actions">
              <button type="button" class="btn btn-ghost btn-sm" onclick={() => { memPreset = { username: m.username, accountId: m.accountId, role: m.role || 'viewer', editing: true }; memOpen = true; }}>Change role</button>
              <button type="button" class="btn-icon danger" aria-label="Remove {m.username} from {accountName(m.accountId)}" title="Remove" onclick={() => removeMembership(m)}><Icon name="x" size={14} /></button>
            </span>
          {/if}
        </td>
      {/snippet}
      {#snippet empty()}
        <EmptyState icon="users" title="No memberships" description="Add users to accounts so they can sign in to them.">
          <button type="button" class="btn btn-primary btn-sm" onclick={() => addMembership()}><Icon name="plus" size={14} />Add membership</button>
        </EmptyState>
      {/snippet}
    </DataTable>
  {:else if tab === 'notifications'}
    <NotificationsPanel />
  {:else if tab === 'settings'}
    <div class="stack">
      <SettingsPanel />
      <SsoPanel {accounts} />
      <AgentsKillSwitch />
    </div>
  {:else}
    <DataTable caption="Users" rows={users} columns={userCols} key={(u) => u.username} {loading} searchable={(u) => `${u.username} ${u.displayName} ${u.role}`} searchPlaceholder="Search users" bind:query>
      {#snippet row(u)}
        <td>
          <span class="who">
            <span class="avatar" aria-hidden="true">{(u.displayName || u.username).split(/\s+/).map((p) => p[0]).join('').slice(0, 2).toUpperCase()}</span>
            <span><span class="strong">{u.displayName || u.username}</span>{#if u.username === me?.username}<span class="subtle small"> (you)</span>{/if}<span class="mono subtle sub">{u.username}</span></span>
          </span>
        </td>
        <td><Badge tone={roleTone(u.role)} dot={false}>{u.role}</Badge>{#if u.platformAdmin}<Badge tone="info" dot={false}>Platform admin</Badge>{/if}{#if u.mfaEnabled}<Badge tone="success" dot={false}><Icon name="shield-check" size={12} />MFA</Badge>{/if}</td>
        <td class="hide-sm">
          <span class="chips">
            {#each (u.accounts ?? []).slice(0, 3) as a (a)}<span class="badge">{accountName(a)}</span>{/each}
            {#if (u.accounts?.length ?? 0) > 3}<span class="subtle small">+{(u.accounts?.length ?? 0) - 3}</span>{/if}
            <button type="button" class="btn btn-ghost btn-sm" onclick={() => addMembership({ username: u.username })} aria-label="Add {u.username} to an account"><Icon name="plus" size={12} /></button>
          </span>
        </td>
        <td class="end">
          {#if canManageUser(u)}
            <span class="cell-actions">
              <button type="button" class="btn-icon" aria-label="Edit {u.username}" title="Edit" onclick={() => { editingUser = u; userOpen = true; }}><Icon name="edit" size={14} /></button>
              {#if u.mfaEnabled && u.username !== me?.username}
                <button type="button" class="btn-icon" aria-label="Reset two-step verification for {u.username}" title="Reset MFA" onclick={() => resetMfa(u)}><Icon name="shield" size={14} /></button>
              {/if}
              <button type="button" class="btn-icon danger" aria-label="Delete {u.username}" title={u.username === me?.username ? "You can't delete yourself" : 'Delete'} disabled={u.username === me?.username} onclick={() => deleteUser(u)}><Icon name="trash" size={14} /></button>
            </span>
          {/if}
        </td>
      {/snippet}
      {#snippet empty()}
        <EmptyState icon="user" title="No users" description="Create console users, then add them to accounts." />
      {/snippet}
    </DataTable>
  {/if}
{/if}

<UserModal bind:open={userOpen} user={editingUser} accounts={manageableAccounts} {users} onsaved={load} />
<MembershipModal bind:open={memOpen} {users} accounts={manageableAccounts} preset={memPreset} onsaved={load} />

<Modal bind:open={accountOpen} title="Create account" description="A new isolated account with its own default KMS key." size="sm">
  <form id="acct-form" onsubmit={createAccount} novalidate>
    <div class="field">
      <label class="field-label" for="acct-name">Name</label>
      <input id="acct-name" class="input" bind:value={accountName_} placeholder="payments-prod" autocomplete="off" aria-invalid={!!accountError} />
      {#if accountError}<span class="field-error">{accountError}</span>{:else}<span class="field-hint">Citadel assigns the 12-digit account ID.</span>{/if}
    </div>
  </form>
  {#snippet footer()}
    <button type="button" class="btn btn-ghost" onclick={() => (accountOpen = false)}>Cancel</button>
    <button type="submit" form="acct-form" class="btn btn-primary" disabled={accountBusy}>{accountBusy ? 'Creating…' : 'Create account'}</button>
  {/snippet}
</Modal>

<style>
  .tabs-row {
    margin: calc(-1 * var(--space-2)) 0 var(--space-5);
  }
  .err {
    margin-bottom: var(--space-4);
    align-items: center;
  }
  .push {
    margin-left: auto;
  }
  .strong {
    font-weight: 500;
  }
  .sub {
    display: block;
    font-size: 12.5px;
  }
  .idrow {
    display: inline-flex;
    align-items: center;
    gap: 4px;
  }
  .who {
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .avatar {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    flex: none;
    width: 28px;
    height: 28px;
    border-radius: 50%;
    background: var(--accent-soft);
    color: var(--accent-text);
    font-size: 12px;
    font-weight: 600;
  }
  .chips {
    display: inline-flex;
    flex-wrap: wrap;
    gap: 4px;
    align-items: center;
  }
  .danger:hover:not(:disabled) {
    color: var(--danger);
    background: var(--danger-soft);
  }
  @media (max-width: 720px) {
    .hide-sm {
      display: none;
    }
  }
</style>
