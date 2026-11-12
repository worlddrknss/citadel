<script lang="ts">
  import '$lib/styles.css';
  import { base } from '$app/paths';
  import { page } from '$app/state';
  import { afterNavigate } from '$app/navigation';
  import { onMount } from 'svelte';
  import { session, type Role } from '$lib/stores/session.svelte';
  import Icon, { type IconName } from '$lib/components/Icon.svelte';
  import Logo from '$lib/components/Logo.svelte';
  import ThemeToggle from '$lib/components/ThemeToggle.svelte';
  import Toaster from '$lib/components/Toaster.svelte';
  import ConfirmHost from '$lib/components/ConfirmHost.svelte';
  import LoginScreen from '$lib/components/LoginScreen.svelte';

  let { children } = $props();

  interface NavItem {
    href: string;
    label: string;
    icon: IconName;
    minRole?: Role;
  }

  const groups: { label: string; items: NavItem[] }[] = [
    {
      label: '',
      items: [{ href: '/', label: 'Overview', icon: 'grid' }]
    },
    {
      label: 'Secrets',
      items: [
        { href: '/secrets', label: 'Secrets', icon: 'lock' },
        { href: '/parameters', label: 'Parameters', icon: 'sliders' }
      ]
    },
    {
      label: 'Cryptography',
      items: [
        { href: '/kms', label: 'KMS keys', icon: 'key' },
        { href: '/certificates', label: 'Certificates', icon: 'award' }
      ]
    },
    {
      label: 'Access',
      items: [
        { href: '/iam', label: 'Identity federation', icon: 'users' },
        { href: '/approvals', label: 'Approvals', icon: 'git-pull-request' },
        { href: '/audit', label: 'Audit log', icon: 'activity' }
      ]
    },
    {
      label: 'Organization',
      items: [
        { href: '/account', label: 'My account', icon: 'user' },
        { href: '/admin', label: 'Administration', icon: 'building', minRole: 'admin' }
      ]
    }
  ];

  let navOpen = $state(false);
  afterNavigate(() => (navOpen = false));

  const path = $derived(page.url.pathname.slice(base.length) || '/');
  function isActive(href: string) {
    return href === '/' ? path === '/' : path === href || path.startsWith(href + '/');
  }

  onMount(() => session.refresh());

  const initials = $derived(
    (session.me?.displayName || session.me?.username || '?')
      .split(/\s+/)
      .map((p) => p[0])
      .join('')
      .slice(0, 2)
      .toUpperCase()
  );
</script>

<svelte:head>
  <title>Citadel</title>
</svelte:head>

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
  <div class="shell" class:nav-open={navOpen}>
    <aside class="sidebar" aria-label="Primary">
      <div class="sidebar-head">
        <a href="{base}/" class="brand-link" aria-label="Citadel overview"><Logo /></a>
        <button class="btn-icon nav-close" aria-label="Close menu" onclick={() => (navOpen = false)}>
          <Icon name="x" />
        </button>
      </div>
      <nav class="nav">
        {#each groups as g (g.label)}
          {@const items = g.items.filter((i) => !i.minRole || session.can(i.minRole))}
          {#if items.length}
            <div class="nav-group">
              {#if g.label}<div class="nav-label">{g.label}</div>{/if}
              <ul>
                {#each items as item (item.href)}
                  <li>
                    <a
                      class="nav-link"
                      href="{base}{item.href}"
                      aria-current={isActive(item.href) ? 'page' : undefined}
                    >
                      <Icon name={item.icon} />
                      <span>{item.label}</span>
                    </a>
                  </li>
                {/each}
              </ul>
            </div>
          {/if}
        {/each}
      </nav>
      <div class="sidebar-foot">
        <div class="org">
          <Icon name="building" size={14} />
          <div class="org-text">
            <span class="subtle small">Account</span>
            <span class="mono small">{session.me?.accountId || '—'}</span>
          </div>
        </div>
      </div>
    </aside>
    <button class="scrim" aria-label="Close menu" tabindex="-1" onclick={() => (navOpen = false)}></button>

    <div class="main">
      <header class="topbar">
        <button class="btn-icon nav-toggle" aria-label="Open menu" aria-expanded={navOpen} onclick={() => (navOpen = true)}>
          <Icon name="menu" />
        </button>
        <div class="topbar-spacer"></div>
        <ThemeToggle />
        <details class="usermenu">
          <summary aria-label="Account menu">
            <span class="avatar" aria-hidden="true">{initials}</span>
            <span class="user-text">
              <span class="user-name">{session.me?.displayName || session.me?.username}</span>
              <span class="user-role subtle">{session.me?.role}</span>
            </span>
            <Icon name="chevron-down" size={14} />
          </summary>
          <div class="menu" role="menu">
            <a role="menuitem" href="{base}/account"><Icon name="user" /> My account</a>
            <button role="menuitem" type="button" onclick={() => session.signOut()}>
              <Icon name="log-out" /> Sign out
            </button>
          </div>
        </details>
      </header>
      <main id="main" class="content" tabindex="-1">
        {@render children()}
      </main>
    </div>
  </div>
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
    display: grid;
    grid-template-columns: var(--sidebar-w) minmax(0, 1fr);
    min-height: 100dvh;
  }

  .sidebar {
    position: sticky;
    top: 0;
    height: 100dvh;
    display: flex;
    flex-direction: column;
    border-right: 1px solid var(--border);
    background: var(--sidebar);
  }
  .sidebar-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    height: var(--topbar-h);
    padding: 0 var(--space-4);
  }
  .brand-link:hover {
    text-decoration: none;
  }
  .nav-close {
    display: none;
  }
  .nav {
    flex: 1;
    overflow-y: auto;
    padding: var(--space-2) var(--space-3);
  }
  .nav-group + .nav-group {
    margin-top: var(--space-4);
  }
  .nav-label {
    padding: 0 var(--space-2) var(--space-1);
    color: var(--text-subtle);
    font-size: var(--text-xs);
    font-weight: 600;
    letter-spacing: 0.04em;
    text-transform: uppercase;
  }
  .nav ul {
    margin: 0;
    padding: 0;
    list-style: none;
  }
  .nav-link {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    height: 34px;
    padding: 0 var(--space-2);
    border-radius: var(--radius-sm);
    color: var(--text-muted);
    font-size: var(--text-sm);
    font-weight: 500;
  }
  .nav-link:hover {
    background: var(--surface-hover);
    color: var(--text);
    text-decoration: none;
  }
  .nav-link[aria-current='page'] {
    background: var(--surface);
    color: var(--text);
    box-shadow: var(--shadow-xs), inset 0 0 0 1px var(--border);
  }
  .nav-link[aria-current='page'] :global(svg) {
    color: var(--accent);
  }
  .sidebar-foot {
    padding: var(--space-3);
    border-top: 1px solid var(--border);
  }
  .org {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    padding: var(--space-2);
    color: var(--text-subtle);
  }
  .org-text {
    display: flex;
    flex-direction: column;
    line-height: 1.3;
    color: var(--text);
  }

  .scrim {
    display: none;
  }

  .main {
    display: flex;
    flex-direction: column;
    min-width: 0;
  }
  .topbar {
    position: sticky;
    top: 0;
    z-index: 20;
    display: flex;
    align-items: center;
    gap: var(--space-2);
    height: var(--topbar-h);
    padding: 0 var(--space-6);
    border-bottom: 1px solid var(--border);
    background: var(--surface);
  }
  .nav-toggle {
    display: none;
  }
  .topbar-spacer {
    flex: 1;
  }

  .usermenu {
    position: relative;
  }
  .usermenu summary {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    padding: 4px var(--space-2) 4px 4px;
    border-radius: var(--radius-md);
    cursor: pointer;
    list-style: none;
    color: var(--text-muted);
  }
  .usermenu summary::-webkit-details-marker {
    display: none;
  }
  .usermenu summary:hover {
    background: var(--surface-hover);
  }
  .avatar {
    display: grid;
    place-items: center;
    width: 30px;
    height: 30px;
    border-radius: 50%;
    background: var(--accent-soft);
    color: var(--accent-text);
    font-size: var(--text-xs);
    font-weight: 600;
  }
  .user-text {
    display: flex;
    flex-direction: column;
    line-height: 1.2;
  }
  .user-name {
    color: var(--text);
    font-size: var(--text-sm);
    font-weight: 500;
  }
  .user-role {
    font-size: var(--text-xs);
    text-transform: capitalize;
  }
  .menu {
    position: absolute;
    right: 0;
    top: calc(100% + 6px);
    min-width: 200px;
    padding: var(--space-1);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: var(--surface-raised);
    box-shadow: var(--shadow-lg);
  }
  .menu a,
  .menu button {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    width: 100%;
    padding: var(--space-2) var(--space-3);
    border: none;
    border-radius: var(--radius-sm);
    background: none;
    color: var(--text);
    font: inherit;
    font-size: var(--text-sm);
    text-align: start;
    cursor: pointer;
  }
  .menu a:hover,
  .menu button:hover {
    background: var(--surface-hover);
    text-decoration: none;
  }

  .content {
    width: 100%;
    max-width: var(--content-max);
    margin: 0 auto;
    padding: var(--pad-page) var(--pad-page) var(--space-12);
    outline: none;
  }

  @media (max-width: 960px) {
    .shell {
      grid-template-columns: minmax(0, 1fr);
    }
    .sidebar {
      position: fixed;
      inset: 0 auto 0 0;
      z-index: 60;
      width: min(85vw, 300px);
      transform: translateX(-100%);
      transition: transform 180ms ease-out;
      box-shadow: var(--shadow-lg);
    }
    .nav-open .sidebar {
      transform: none;
    }
    .nav-open .scrim {
      display: block;
      position: fixed;
      inset: 0;
      z-index: 50;
      border: none;
      background: var(--overlay);
    }
    .nav-close,
    .nav-toggle {
      display: inline-grid;
    }
    .topbar {
      padding: 0 var(--space-4);
    }
    .user-text {
      display: none;
    }
  }
  @media (prefers-reduced-motion: reduce) {
    .sidebar {
      transition: none;
    }
  }
</style>
