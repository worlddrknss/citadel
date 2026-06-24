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
    { href: '/', label: '� Dashboard', section: 'Services' },
    { href: '/secrets', label: '�🔑 Secrets', section: 'Services' },
    { href: '/kms', label: '🗝 KMS', section: 'Services' },
    { href: '/certificates', label: '📜 Certificates', section: 'Services' },
    { href: '/audit', label: '📋 Audit', section: 'Services' },
    { href: '/account', label: '🪪 Account', section: 'Account' },
    { href: '/admin', label: '⚙️ Master Admin', section: 'Administration' }
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
      <div class="brand">🏰 Citadel</div>
      {#each sections as section}
        <div class="sb-section">
          <div class="sb-label">{section}</div>
          {#each nav.filter((n) => n.section === section) as n}
            <a class="sb-link" class:active={isActive(n.href)} href="{base}{n.href === '/' ? '/' : n.href}">
              {n.label}
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
</style>

