<script lang="ts">
  import '$lib/styles.css';
  import { base } from '$app/paths';
  import { page } from '$app/stores';
  import { onMount } from 'svelte';
  import { api, type Me } from '$lib/api';

  let me: Me | null = $state(null);
  let authError = $state(false);

  onMount(async () => {
    try {
      me = await api.me();
    } catch {
      authError = true;
    }
  });

  let { children } = $props();

  const nav = [
    { href: '/', label: '🔑 Secrets', section: 'Services' },
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
    return currentPath === href || currentPath.startsWith(href + '/');
  }

  const titles: Record<string, string> = {
    '/': 'Secrets Management',
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

{#if authError}
  <div class="shell" style="grid-template-columns: 1fr;">
    <div class="empty">
      <h2>Sign in required</h2>
      <p class="muted">Your Citadel session has expired or you are not signed in.</p>
      <p><a class="btn btn-p" href="/login">Go to sign in</a></p>
    </div>
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
          · <a href="/logout">Sign out</a>
        </span>
      </header>
      <main class="content">
        {@render children()}
      </main>
    </div>
  </div>
{/if}

