<script lang="ts">
  import '$lib/styles.css';
  import { base } from '$app/paths';
  import { page } from '$app/state';
  import { afterNavigate, goto } from '$app/navigation';
  import { onMount } from 'svelte';
  import { api, type Certificate, type ChangeRequest } from '$lib/api';
  import { session, type Role } from '$lib/stores/session.svelte';
  import { toast } from '$lib/stores/toast.svelte';
  import Icon, { type IconName } from '$lib/components/Icon.svelte';
  import Logo from '$lib/components/Logo.svelte';
  import Modal from '$lib/components/Modal.svelte';
  import Toaster from '$lib/components/Toaster.svelte';
  import ConfirmHost from '$lib/components/ConfirmHost.svelte';
  import LoginScreen from '$lib/components/LoginScreen.svelte';
  import CommandPalette from './CommandPalette.svelte';
  import Menu from './Menu.svelte';
  import { density } from './prefs.svelte';
  import { shellApi, type Organization } from './api';
  import { isNotImplemented } from './http';
  import { envTone } from './approvals/api';
  import { daysUntil } from './time';

  let { children } = $props();

  const DOCS = 'https://github.com/worlddrknss/citadel/tree/main/docs';
  const SECURITY = 'https://github.com/worlddrknss/citadel/blob/main/SECURITY.md';

  interface NavItem {
    href: string;
    label: string;
    icon: IconName;
    minRole?: Role;
    /** Query param that must match for this item to be current. */
    tab?: string;
  }

  const groups: { label: string; items: NavItem[] }[] = [
    { label: '', items: [{ href: '/', label: 'Overview', icon: 'grid' }] },
    {
      label: 'Store',
      items: [
        { href: '/secrets', label: 'Secrets', icon: 'lock' },
        { href: '/parameters', label: 'Parameters', icon: 'sliders' },
        { href: '/kms', label: 'KMS keys', icon: 'key' },
        { href: '/certificates', label: 'Certificates', icon: 'award' }
      ]
    },
    {
      label: 'Identity',
      items: [
        { href: '/iam', label: 'IAM', icon: 'users' },
        { href: '/workload-identity', label: 'Workload identity', icon: 'shield' },
        { href: '/account', label: 'Access keys', icon: 'command', tab: 'keys' }
      ]
    },
    {
      label: 'Governance',
      items: [
        { href: '/audit', label: 'Audit log', icon: 'list' },
        { href: '/approvals', label: 'Approvals', icon: 'git-pull-request' }
      ]
    }
  ];

  const path = $derived(page.url.pathname.slice(base.length) || '/');
  const tab = $derived(page.url.searchParams.get('tab') ?? '');
  function isActive(item: NavItem) {
    const onPath = item.href === '/' ? path === '/' : path === item.href || path.startsWith(item.href + '/');
    return onPath && (!item.tab || tab === item.tab);
  }
  const settingsHref = $derived(session.can('admin') ? '/admin' : '/account');
  const settingsActive = $derived(
    session.can('admin') ? path.startsWith('/admin') : path.startsWith('/account') && tab !== 'keys'
  );
  const navHref = (item: NavItem) => `${base}${item.href}${item.tab ? `?tab=${item.tab}` : ''}`;

  // Palette targets: every page, including the ones in menus.
  const paletteNav = $derived([
    ...groups.flatMap((g) => g.items.map((i) => ({ href: i.tab ? `${i.href}?tab=${i.tab}` : i.href, label: i.label, icon: i.icon, group: g.label || undefined }))),
    { href: '/account', label: 'My account', icon: 'user' as IconName, group: 'Settings' },
    ...(session.can('admin') ? [{ href: '/admin', label: 'Administration', icon: 'building' as IconName, group: 'Settings' }] : [])
  ]);

  // Environment-aware search: inside /secrets/[project]/[env] the palette
  // offers that environment as a scope and the top bar shows its tier.
  const scope = $derived(
    page.params.project && page.params.env ? { project: page.params.project, env: page.params.env } : null
  );

  // ---- shell data ---------------------------------------------------------
  let org = $state<Organization | null>(null);
  let fips = $state(false);
  let pending = $state<ChangeRequest[]>([]);
  let expiring = $state<Certificate[]>([]);
  let lastPoll = 0;

  const me = $derived(session.me);
  const forMe = $derived(pending.filter((c) => c.status === 'pending' && c.requester !== me?.username));
  const currentAccount = $derived(org?.accounts.find((a) => a.accountId === me?.accountId));
  const orgName = $derived(org?.organization.name || 'Citadel');
  const orgInitials = $derived(initialsOf(orgName));
  const notifCount = $derived((session.can('admin') ? forMe.length : 0) + expiring.length);

  function initialsOf(s: string) {
    return (
      s
        .split(/[\s._-]+/)
        .filter(Boolean)
        .map((p) => p[0])
        .join('')
        .slice(0, 2)
        .toUpperCase() || '?'
    );
  }
  const userInitials = $derived(initialsOf(me?.displayName || me?.username || '?'));

  async function loadShell() {
    const [o, info] = await Promise.allSettled([shellApi.organization(), shellApi.serverInfo()]);
    org = o.status === 'fulfilled' ? o.value : null;
    fips = info.status === 'fulfilled' ? !!info.value.fips : false;
  }

  async function poll(force = false) {
    if (session.status !== 'signed-in') return;
    if (!force && Date.now() - lastPoll < 30_000) return;
    lastPoll = Date.now();
    const [cr, certs] = await Promise.allSettled([api.changeRequests(), api.certificates()]);
    if (cr.status === 'fulfilled') pending = cr.value.changeRequests.filter((c) => c.status === 'pending');
    if (certs.status === 'fulfilled') {
      const soon = Date.now() + 30 * 86_400_000;
      expiring = certs.value.certificates
        .filter((c) => c.notAfter && !/revoked/i.test(c.status) && Date.parse(c.notAfter) <= soon && Date.parse(c.notAfter) > Date.now())
        .sort((a, b) => Date.parse(a.notAfter!) - Date.parse(b.notAfter!));
    }
  }

  let shellFor = '';
  $effect(() => {
    const key = session.status === 'signed-in' ? `${me?.username}@${me?.accountId}` : '';
    if (key && key !== shellFor) {
      shellFor = key;
      void loadShell();
      void poll(true);
    }
    if (!key) shellFor = '';
  });

  afterNavigate(() => void poll());

  onMount(() => {
    session.refresh();
    const onChanged = () => void poll(true);
    window.addEventListener('citadel:approvals-changed', onChanged);
    return () => window.removeEventListener('citadel:approvals-changed', onChanged);
  });

  // ---- palette ------------------------------------------------------------
  let paletteOpen = $state(false);
  let paletteInitial = $state('');
  function openPalette(initial = '') {
    paletteInitial = initial;
    paletteOpen = true;
  }
  function onWindowKey(e: KeyboardEvent) {
    if (session.status !== 'signed-in') return;
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
      e.preventDefault();
      if (paletteOpen) paletteOpen = false;
      else openPalette();
      return;
    }
    const t = e.target as HTMLElement;
    const typing = t.closest('input, textarea, select, [contenteditable="true"], dialog');
    if (e.key === '/' && !typing && !e.metaKey && !e.ctrlKey && !e.altKey) {
      e.preventDefault();
      openPalette();
    }
  }
  const isMac = typeof navigator !== 'undefined' && /mac|iphone|ipad/i.test(navigator.platform || navigator.userAgent);

  // ---- account switching ----------------------------------------------------
  async function switchAccount(accountId: string, close: () => void) {
    close();
    if (accountId === me?.accountId) return;
    try {
      await shellApi.switchAccount(accountId);
      await session.refresh();
      toast.success(`Switched to account ${accountId}`);
      goto(`${base}/`);
    } catch (e) {
      if (isNotImplemented(e)) {
        // Older servers scope a session to one account: sign in again.
        try {
          localStorage.setItem('citadel-last-account', accountId);
        } catch {
          /* ignore */
        }
        await session.signOut();
        toast.info(`Sign in to account ${accountId} to switch.`);
      } else toast.error(e, 'Could not switch account');
    }
  }
  const accountList = $derived(
    org?.accounts.length ? org.accounts : (me?.accounts ?? []).map((id) => ({ accountId: id, name: '', role: undefined }))
  );

  // ---- theme (menu control; mirrors ThemeToggle's storage) -------------------
  type Theme = 'system' | 'light' | 'dark';
  let theme = $state<Theme>('system');
  onMount(() => {
    try {
      const t = localStorage.getItem('citadel-theme');
      theme = t === 'light' || t === 'dark' ? t : 'system';
    } catch {
      /* ignore */
    }
  });
  function setTheme(t: Theme) {
    theme = t;
    const root = document.documentElement;
    if (t === 'system') root.removeAttribute('data-theme');
    else root.setAttribute('data-theme', t);
    try {
      if (t === 'system') localStorage.removeItem('citadel-theme');
      else localStorage.setItem('citadel-theme', t);
    } catch {
      /* ignore */
    }
  }

  let shortcutsOpen = $state(false);

</script>

<svelte:head>
  <title>Citadel</title>
</svelte:head>

<svelte:window onkeydown={onWindowKey} />

{#if session.status === 'loading'}
  <div class="boot" aria-busy="true" aria-label="Loading Citadel">
    <Logo compact />
  </div>
{:else if session.status === 'unreachable'}
  <main class="boot">
    <div class="boot-msg">
      <Icon name="alert-triangle" size={22} />
      <h1>Can't reach Citadel</h1>
      <p class="muted">The server didn't respond. It may be restarting.</p>
      <button class="btn btn-secondary" onclick={() => session.refresh()}>
        <Icon name="refresh" /> Try again
      </button>
    </div>
  </main>
{:else if session.status === 'signed-out'}
  <LoginScreen />
{:else}
  <a class="skip" href="#main">Skip to content</a>
  <div class="shell">
    <aside class="side" aria-label="Primary">
      <a href="{base}/" class="brand" aria-label="Citadel home"><Logo /></a>
      <nav class="navgroups" aria-label="Main">
        {#each groups as g (g.label)}
          {@const items = g.items.filter((i) => !i.minRole || session.can(i.minRole))}
          {#if items.length}
            <div class="navgroup">
              {#if g.label}<div class="grouplabel">{g.label}</div>{/if}
              {#each items as item (item.href + (item.tab ?? ''))}
                <a class="navi" href={navHref(item)} aria-current={isActive(item) ? 'page' : undefined}>
                  <Icon name={item.icon} />
                  <span>{item.label}</span>
                  {#if item.href === '/approvals' && session.can('admin') && forMe.length}
                    <span class="count" aria-label="{forMe.length} pending">{forMe.length}</span>
                  {/if}
                </a>
              {/each}
            </div>
          {/if}
        {/each}
      </nav>
      <div class="sidefoot">
        <a class="navi" href="{base}{settingsHref}" aria-current={settingsActive ? 'page' : undefined}>
          <Icon name="settings" /><span>Settings</span>
        </a>
        {#if fips}
          <div class="fips">
            <Icon name="shield-check" />
            <div>
              <span class="fips-t">FIPS 140 mode</span>
              <span class="subtle">Approved algorithms only</span>
            </div>
          </div>
        {/if}
      </div>
    </aside>

    <div class="col">
      <header class="topbar">
        <Menu label="Switch organization or account" labelTrigger={false} triggerClass="btn btn-ghost orgbtn" width={300}>
          {#snippet trigger()}
            <span class="sr-only">Switch organization or account. Current:</span>
            <span class="orgmark" aria-hidden="true">{orgInitials}</span>
            <span class="orgtext">
              <span class="orgname">{orgName}</span>
              <span class="mono subtle orgacct">{currentAccount?.name ? `${currentAccount.name} · ` : ''}{me?.accountId || '—'}</span>
            </span>
            <Icon name="arrow-up-down" size={14} />
          {/snippet}
          {#snippet children(close)}
            <div class="menu-label">Accounts in {orgName}</div>
            {#each accountList as a (a.accountId)}
              <button type="button" role="menuitemradio" aria-checked={a.accountId === me?.accountId} onclick={() => switchAccount(a.accountId, close)}>
                <span class="acct">
                  <span>{a.name || 'Account'}</span>
                  <span class="mono subtle small">{a.accountId}{a.role ? ` · ${a.role}` : ''}</span>
                </span>
                {#if a.accountId === me?.accountId}<Icon name="check" />{/if}
              </button>
            {:else}
              <p class="menu-head subtle small">No other accounts.</p>
            {/each}
            {#if session.can('admin')}
              <div class="menu-sep"></div>
              <a role="menuitem" href="{base}/admin" onclick={close}><Icon name="building" />Manage accounts</a>
            {/if}
          {/snippet}
        </Menu>

        <div class="search" role="search">
          <button type="button" class="searchbox" aria-haspopup="dialog" aria-keyshortcuts={isMac ? 'Meta+K' : 'Control+K'} onclick={() => openPalette()}>
            <Icon name="search" />
            <span class="ph">{scope ? `Search ${scope.project} / ${scope.env}, keys, ARNs…` : 'Search secrets, keys, ARNs, people…'}</span>
            <span class="sk">
              {#if scope}<span class="badge badge-{envTone(scope.env)} envchip hide-sm">{scope.env}</span>{/if}
              <kbd>{isMac ? '⌘K' : 'Ctrl K'}</kbd>
            </span>
          </button>
        </div>

        <div class="tools">
          <Menu label="Help and docs" triggerClass="btn btn-ghost btn-icon tool" align="end" width={240}>
            {#snippet trigger()}<Icon name="info" />{/snippet}
            {#snippet children(close)}
              <a role="menuitem" href={DOCS} target="_blank" rel="noopener noreferrer" onclick={close}><Icon name="file" />Documentation<Icon name="external-link" size={12} /></a>
              <button type="button" role="menuitem" onclick={() => { close(); shortcutsOpen = true; }}><Icon name="command" />Keyboard shortcuts</button>
              <a role="menuitem" href={SECURITY} target="_blank" rel="noopener noreferrer" onclick={close}><Icon name="shield" />Report a security issue<Icon name="external-link" size={12} /></a>
            {/snippet}
          </Menu>

          <Menu label="Notifications, {notifCount} {notifCount === 1 ? 'item' : 'items'}" triggerClass="btn btn-ghost btn-icon tool bell" align="end" width={340}>
            {#snippet trigger()}
              <Icon name="alert-circle" />
              {#if notifCount}<span class="dot" aria-hidden="true"></span>{/if}
            {/snippet}
            {#snippet children(close)}
              <div class="menu-label">Notifications</div>
              {#if session.can('admin')}
                {#each forMe.slice(0, 5) as c (c.id)}
                  <a role="menuitem" href="{base}/approvals?cr={encodeURIComponent(c.id)}" onclick={close}>
                    <Icon name="git-pull-request" />
                    <span class="acct"><span>Review change to <span class="mono">{c.key}</span></span><span class="subtle small">{c.requester} · {c.project} / {c.env}</span></span>
                  </a>
                {/each}
              {/if}
              {#each expiring.slice(0, 5) as c (c.source + c.id)}
                {@const d = daysUntil(c.notAfter!)}
                <a role="menuitem" href="{base}/certificates?cert={encodeURIComponent(c.id)}&source={encodeURIComponent(c.source)}" onclick={close}>
                  <Icon name="award" />
                  <span class="acct"><span class="mono">{c.subject || c.id}</span><span class="small" class:warn={d > 9} class:danger={d <= 9}>Expires {d <= 0 ? 'today' : d === 1 ? 'tomorrow' : `in ${d} days`}</span></span>
                </a>
              {/each}
              {#if !notifCount}
                <p class="menu-head subtle small">You're all caught up.</p>
              {/if}
            {/snippet}
          </Menu>

          <Menu label="Account menu" labelTrigger={false} triggerClass="btn btn-ghost userbtn" align="end" width={280} role="dialog">
            {#snippet trigger()}
              <span class="sr-only">Account menu:</span>
              <span class="avatar" aria-hidden="true">{userInitials}</span>
              <span class="usertext hide-sm">
                <span class="username">{me?.displayName || me?.username}</span>
                <span class="subtle userrole">{me?.role}</span>
              </span>
              <Icon name="chevron-down" size={14} />
            {/snippet}
            {#snippet children(close)}
              <div class="menu-head">
                <strong>{me?.displayName || me?.username}</strong>
                <span class="subtle small">{me?.username} · <span class="cap">{me?.role}</span> · <span class="mono">{me?.accountId}</span></span>
              </div>
              <div class="menu-sep"></div>
              <a role="menuitem" href="{base}/account" onclick={close}><Icon name="user" />My account</a>
              <a role="menuitem" href="{base}/account?tab=keys" onclick={close}><Icon name="command" />Access keys</a>
              {#if session.can('admin')}
                <a role="menuitem" href="{base}/admin" onclick={close}><Icon name="building" />Administration</a>
              {/if}
              <div class="menu-sep"></div>
              <div class="pref">
                <span class="small muted" id="pref-theme">Theme</span>
                <div class="seg" role="group" aria-labelledby="pref-theme">
                  {#each ['system', 'light', 'dark'] as const as t (t)}
                    <button type="button" aria-pressed={theme === t} onclick={() => setTheme(t)}>{t[0].toUpperCase() + t.slice(1)}</button>
                  {/each}
                </div>
              </div>
              <div class="pref">
                <span class="small muted" id="pref-density">Density</span>
                <div class="seg" role="group" aria-labelledby="pref-density">
                  {#each ['comfortable', 'compact'] as const as d (d)}
                    <button type="button" aria-pressed={density.value === d} onclick={() => density.set(d)}>{d[0].toUpperCase() + d.slice(1)}</button>
                  {/each}
                </div>
              </div>
              <div class="menu-sep"></div>
              <button type="button" role="menuitem" onclick={() => { close(); session.signOut(); }}><Icon name="log-out" />Sign out</button>
            {/snippet}
          </Menu>
        </div>
      </header>

      <main id="main" class="content" tabindex="-1">
        {@render children()}
      </main>
    </div>
  </div>

  <CommandPalette bind:open={paletteOpen} nav={paletteNav} {scope} initial={paletteInitial} />

  <Modal bind:open={shortcutsOpen} title="Keyboard shortcuts" size="sm">
    <dl class="kv shortcuts">
      <dt><kbd>{isMac ? '⌘' : 'Ctrl'}</kbd> <kbd>K</kbd></dt>
      <dd>Open search</dd>
      <dt><kbd>/</kbd></dt>
      <dd>Open search (when not typing)</dd>
      <dt><kbd>↑</kbd> <kbd>↓</kbd> <kbd>↵</kbd></dt>
      <dd>Move through and open results</dd>
      <dt><kbd>Esc</kbd></dt>
      <dd>Close search, menus and dialogs</dd>
    </dl>
  </Modal>
{/if}

<Toaster />
<ConfirmHost />

<style>
  .boot {
    min-height: 100dvh;
    display: grid;
    place-items: center;
    padding: var(--space-4);
  }
  .boot-msg {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: var(--space-2);
    text-align: center;
    color: var(--warning);
  }
  .boot-msg h1 {
    margin: var(--space-2) 0 0;
    font-size: var(--text-xl);
    color: var(--text);
  }
  .boot-msg p {
    margin: 0 0 var(--space-3);
  }

  .skip {
    position: absolute;
    left: -9999px;
    top: var(--space-2);
    z-index: 200;
    padding: var(--space-2) var(--space-3);
    border-radius: var(--radius-md);
    background: var(--accent);
    color: var(--accent-contrast);
  }
  .skip:focus {
    left: var(--space-2);
  }

  .shell {
    min-height: 100dvh;
    display: flex;
    flex-wrap: wrap;
    align-items: stretch;
  }

  /* ---- sidebar ---- */
  .side {
    flex: 0 0 var(--sidebar-w);
    max-width: var(--sidebar-w);
    position: sticky;
    top: 0;
    height: 100dvh;
    overflow-y: auto;
    display: flex;
    flex-direction: column;
    gap: 20px;
    padding: 16px 12px;
    border-right: 1px solid var(--border);
    background: var(--sidebar);
  }
  .brand {
    display: flex;
    align-items: center;
    height: 32px;
    padding: 0 6px;
    color: var(--text);
  }
  .brand:hover {
    text-decoration: none;
  }
  .navgroups {
    display: flex;
    flex-direction: column;
    gap: 18px;
  }
  .navgroup {
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .grouplabel {
    margin-bottom: 4px;
    padding: 0 10px;
    font-size: var(--text-xs);
    font-weight: 600;
    line-height: 16px;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    color: var(--text-subtle);
  }
  .navi {
    display: flex;
    align-items: center;
    gap: 10px;
    height: 34px;
    padding: 0 10px;
    border-radius: var(--radius-md);
    color: var(--text-muted);
    font-size: var(--text-base);
    font-weight: 500;
    white-space: nowrap;
  }
  .navi:hover {
    background: var(--surface-pressed);
    color: var(--text);
    text-decoration: none;
  }
  .navi:focus-visible {
    outline: none;
    box-shadow: var(--focus-ring);
  }
  .navi[aria-current='page'] {
    background: var(--surface);
    color: var(--text);
    box-shadow: var(--shadow-xs), inset 0 0 0 1px var(--border);
  }
  .navi[aria-current='page'] :global(svg) {
    color: var(--accent);
  }
  .count {
    margin-left: auto;
    padding: 0 6px;
    border-radius: 999px;
    background: var(--accent-soft);
    color: var(--accent-text);
    font-size: var(--text-xs);
    font-weight: 500;
    line-height: 16px;
  }
  .sidefoot {
    margin-top: auto;
    display: flex;
    flex-direction: column;
    gap: 10px;
  }
  .fips {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 10px;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: var(--surface);
  }
  .fips > :global(svg) {
    color: var(--accent);
  }
  .fips div {
    display: flex;
    flex-direction: column;
    min-width: 0;
  }
  .fips-t {
    font-size: var(--text-sm);
    font-weight: 500;
    line-height: 16px;
  }
  .fips .subtle {
    font-size: 11.5px;
    line-height: 16px;
  }

  /* ---- top bar ---- */
  .col {
    flex: 999 1 560px;
    min-width: 0;
    display: flex;
    flex-direction: column;
  }
  .topbar {
    position: sticky;
    top: 0;
    z-index: 30;
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 12px;
    min-height: var(--topbar-h);
    padding: 10px var(--pad-page);
    border-bottom: 1px solid var(--border);
    background: var(--surface);
  }
  :global(.orgbtn) {
    gap: 10px !important;
    padding: 0 8px !important;
    height: auto !important;
    min-height: var(--ctl-h);
  }
  :global(.orgbtn > svg) {
    color: var(--text-subtle);
  }
  .orgmark {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 22px;
    height: 22px;
    border-radius: 6px;
    background: var(--accent-soft);
    color: var(--accent-text);
    font-size: 11px;
    font-weight: 700;
  }
  .orgtext {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: 2px;
  }
  .orgname {
    color: var(--text);
    font-size: var(--text-base);
    font-weight: 600;
    line-height: 1;
  }
  .orgacct {
    font-size: 11px;
    line-height: 1;
  }
  .acct {
    display: flex;
    flex-direction: column;
    flex: 1;
    min-width: 0;
    line-height: 1.35;
  }
  .search {
    flex: 1 1 280px;
    max-width: 560px;
    margin: 0 auto;
  }
  .searchbox {
    display: flex;
    align-items: center;
    gap: 8px;
    width: 100%;
    height: var(--ctl-h);
    padding: 0 8px 0 10px;
    border: 1px solid var(--border-strong);
    border-radius: var(--radius-md);
    background: var(--surface-hover);
    color: var(--text-subtle);
    font: inherit;
    font-size: var(--text-base);
    text-align: start;
    cursor: text;
  }
  .searchbox:hover {
    border-color: var(--text-subtle);
  }
  .searchbox:focus-visible {
    outline: none;
    border-color: var(--accent);
    box-shadow: var(--focus-ring);
  }
  .ph {
    flex: 1;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .sk {
    display: flex;
    align-items: center;
    gap: 6px;
  }
  .envchip {
    height: 20px;
    font-size: 11px;
  }
  .tools {
    display: flex;
    align-items: center;
    gap: 4px;
  }
  :global(.tool) {
    width: var(--ctl-h) !important;
    height: var(--ctl-h) !important;
    border-radius: var(--radius-md) !important;
    position: relative;
  }
  :global(.bell) .dot {
    position: absolute;
    top: 8px;
    right: 8px;
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: var(--danger);
    box-shadow: 0 0 0 2px var(--surface);
  }
  :global(.userbtn) {
    gap: 8px !important;
    margin-left: 4px;
    padding: 0 6px 0 4px !important;
  }
  :global(.userbtn > svg) {
    color: var(--text-subtle);
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
    font-size: 11px;
    font-weight: 600;
  }
  .usertext {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: 2px;
  }
  .username {
    color: var(--text);
    font-size: var(--text-base);
    font-weight: 500;
    line-height: 1;
  }
  .userrole {
    font-size: 11px;
    line-height: 1;
    text-transform: capitalize;
  }
  .cap {
    text-transform: capitalize;
  }
  .warn {
    color: var(--warning);
  }
  .danger {
    color: var(--danger);
  }
  .pref {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    padding: 6px 10px;
  }
  .seg {
    display: inline-flex;
    gap: 2px;
    padding: 3px;
    border-radius: var(--radius-md);
    background: var(--surface-pressed);
  }
  .seg button {
    height: 26px;
    padding: 0 8px;
    border: none;
    border-radius: var(--radius-sm);
    background: transparent;
    color: var(--text-muted);
    font: inherit;
    font-size: var(--text-sm);
    font-weight: 500;
    cursor: pointer;
  }
  .seg button[aria-pressed='true'] {
    background: var(--surface);
    color: var(--text);
    box-shadow: var(--shadow-xs);
  }
  .shortcuts {
    grid-template-columns: max-content 1fr;
    align-items: center;
  }

  .content {
    flex: 1 1 auto;
    display: flex;
    flex-direction: column;
    gap: 20px;
    width: 100%;
    max-width: 1440px;
    margin: 0 auto;
    padding: 24px var(--pad-page) 48px;
    outline: none;
  }
  /* The main column spaces page sections with its gap (as in the mockups),
     so PageHeader's own bottom margin would double it. */
  .content > :global(.ph) {
    margin-bottom: 0;
  }

  /* Narrow screens (mockup): the sidebar becomes a top strip whose nav
     scrolls sideways; group labels, the footer and secondary text hide. */
  @media (max-width: 820px) {
    .side {
      flex-basis: 100%;
      max-width: none;
      position: static;
      height: auto;
      gap: 8px;
      padding: 10px 12px;
      border-right: 0;
      border-bottom: 1px solid var(--border);
    }
    .navgroups {
      flex-direction: row;
      gap: 4px;
      overflow-x: auto;
      scrollbar-width: none;
    }
    .navgroup {
      flex-direction: row;
    }
    .grouplabel,
    .sidefoot,
    .hide-sm {
      display: none;
    }
    .topbar {
      position: static;
    }
    .search {
      order: 3;
      flex-basis: 100%;
      max-width: none;
    }
    .tools {
      margin-left: auto;
    }
  }
</style>
