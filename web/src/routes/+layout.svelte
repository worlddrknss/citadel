<script lang="ts">
  import '$lib/styles.css';
  import { base } from '$app/paths';
  import { page } from '$app/stores';
  import { onMount } from 'svelte';
  import { api, ApiError, type Me } from '$lib/api';

  let me: Me | null = $state(null);
  let authError = $state(false);
  let ready = $state(false);

  // Login form
  let loginAccount = $state('');
  let loginUsername = $state('');
  let loginPassword = $state('');
  let loginError = $state('');
  let loggingIn = $state(false);

  async function refreshMe() {
    try {
      me = await api.me();
      authError = false;
    } catch {
      me = null;
      authError = true;
    } finally {
      ready = true;
    }
  }

  async function doLogin(e: Event) {
    e.preventDefault();
    loginError = '';
    loggingIn = true;
    try {
      await api.login(loginAccount.trim(), loginUsername.trim(), loginPassword);
      loginPassword = '';
      await refreshMe();
    } catch (err) {
      loginError = err instanceof ApiError ? err.message : 'Sign in failed';
    } finally {
      loggingIn = false;
    }
  }

  async function doLogout(e: Event) {
    e.preventDefault();
    try {
      await api.logout();
    } catch {
      /* ignore */
    }
    await refreshMe();
  }

  onMount(refreshMe);

  let { children } = $props();

  const nav = [
    { href: '/', label: 'Dashboard', icon: 'dashboard', section: 'Services' },
    { href: '/secrets', label: 'Secrets', icon: 'secrets', section: 'Services' },
    { href: '/kms', label: 'KMS', icon: 'kms', section: 'Services' },
    { href: '/certificates', label: 'Certificates', icon: 'certificate', section: 'Services' },
    { href: '/audit', label: 'Audit', icon: 'audit', section: 'Services' },
    { href: '/account', label: 'Account', icon: 'account', section: 'Account' },
    { href: '/admin', label: 'Master Admin', icon: 'admin', section: 'Administration' }
  ];

  const sections = ['Services', 'Account', 'Administration'];

  const currentPath = $derived($page.url.pathname.replace(base, '') || '/');

  function isActive(href: string): boolean {
    if (href === '/') return currentPath === '/';
    if (href === '/secrets') return currentPath.startsWith('/secrets');
    return currentPath === href || currentPath.startsWith(href + '/');
  }

  const titles: Record<string, string> = {
    '/': 'Dashboard',
    '/secrets': 'Secrets Management',
    '/kms': 'Key Management Service',
    '/certificates': 'Certificate Management',
    '/audit': 'Audit Log',
    '/account': 'My Account',
    '/admin': 'Master Administration'
  };

  const pageTitle = $derived(
    titles[currentPath] ??
      (Object.entries(titles).find(([h]) => h !== '/' && currentPath.startsWith(h))?.[1] ??
        'Citadel')
  );
</script>

{#snippet icon(name: string)}
  <svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
    {#if name === 'dashboard'}
      <rect x="3" y="3" width="7" height="9" rx="1" /><rect x="14" y="3" width="7" height="5" rx="1" /><rect x="14" y="12" width="7" height="9" rx="1" /><rect x="3" y="16" width="7" height="5" rx="1" />
    {:else if name === 'secrets'}
      <rect x="4" y="10" width="16" height="11" rx="2" /><path d="M8 10V7a4 4 0 0 1 8 0v3" /><circle cx="12" cy="15.5" r="1.4" />
    {:else if name === 'kms'}
      <circle cx="8" cy="12" r="4" /><path d="M11.5 12H21" /><path d="M17 12v3" /><path d="M20 12v2.5" />
    {:else if name === 'certificate'}
      <rect x="4" y="4" width="16" height="13" rx="2" /><path d="M8 9h8" /><path d="M8 12h5" /><circle cx="9" cy="18.5" r="2" /><path d="M9 20.5 7.5 23l1.5-1 1.5 1L9 20.5" />
    {:else if name === 'audit'}
      <path d="M9 4h6l4 4v12a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1V5a1 1 0 0 1 1-1Z" /><path d="M14 4v4h4" /><path d="M8 13h6" /><path d="M8 16h4" />
    {:else if name === 'account'}
      <circle cx="12" cy="8" r="4" /><path d="M4 21a8 8 0 0 1 16 0" />
    {:else if name === 'admin'}
      <circle cx="12" cy="12" r="3" /><path d="M12 2v3M12 19v3M2 12h3M19 12h3M4.9 4.9l2.1 2.1M17 17l2.1 2.1M19.1 4.9 17 7M7 17l-2.1 2.1" />
    {/if}
  </svg>
{/snippet}

{#if !ready}
  <div class="shell" style="grid-template-columns: 1fr;">
    <div class="empty">Loading…</div>
  </div>
{:else if authError}
  <div class="login-wrap">
    <form class="card login-card" onsubmit={doLogin}>
      <div class="brand" style="font-size:1.5rem;margin-bottom:0.5rem">🏰 Citadel</div>
      <p class="muted" style="margin-top:0">Sign in to the control plane.</p>
      {#if loginError}
        <div class="flash err">{loginError}</div>
      {/if}
      <div class="field" style="margin-bottom:0.75rem">
        <label for="li-acct">Account ID</label>
        <input id="li-acct" class="mono" bind:value={loginAccount} autocomplete="organization" />
      </div>
      <div class="field" style="margin-bottom:0.75rem">
        <label for="li-user">Username</label>
        <input id="li-user" bind:value={loginUsername} autocomplete="username" />
      </div>
      <div class="field" style="margin-bottom:1rem">
        <label for="li-pass">Password</label>
        <input id="li-pass" type="password" bind:value={loginPassword} autocomplete="current-password" />
      </div>
      <button class="btn btn-p" type="submit" disabled={loggingIn} style="width:100%">
        {loggingIn ? 'Signing in…' : 'Sign in'}
      </button>
    </form>
  </div>
{:else}
  <div class="shell">
    <aside class="sidebar">
      <div class="brand">
        <svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
          <path d="M4 21V9l2-1V5l2 1 2-3 2 3 2-1v3l2 1v12" /><path d="M4 21h16" /><path d="M10 21v-4a2 2 0 0 1 4 0v4" />
        </svg>
        <span>Citadel</span>
      </div>
      {#each sections as section}
        <div class="sb-section">
          <div class="sb-label">{section}</div>
          {#each nav.filter((n) => n.section === section) as n}
            <a class="sb-link" class:active={isActive(n.href)} href="{base}{n.href === '/' ? '/' : n.href}">
              {@render icon(n.icon)}
              <span>{n.label}</span>
            </a>
          {/each}
        </div>
      {/each}
    </aside>
    <div class="main">
      <header class="topbar">
        <strong>{pageTitle}</strong>
        <span class="user">
          {#if me}
            {me.displayName} · <span class="badge">{me.role}</span>
            {#if me.accountId}<span class="mono"> · {me.accountId}</span>{/if}
          {/if}
          · <a href="{base}/" onclick={doLogout}>Sign out</a>
        </span>
      </header>
      <main class="content">
        {@render children()}
      </main>
    </div>
  </div>
{/if}

<style>
  .login-wrap {
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 1rem;
  }
  .login-card {
    width: 100%;
    max-width: 360px;
  }
  .ico {
    width: 18px;
    height: 18px;
    flex: none;
  }
</style>

