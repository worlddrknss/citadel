<script lang="ts">
  import '$lib/styles.css';
  import { base } from '$app/paths';
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
      <div class="sb-section">
        <div class="sb-label">Services</div>
        <a class="sb-link active" href="{base}/">🔑 Secrets</a>
        <a class="sb-link" href="/secrets">🗝 KMS</a>
        <a class="sb-link" href="/certificates">📜 Certificates</a>
        <a class="sb-link" href="/audit">📋 Audit</a>
      </div>
      <div class="sb-section">
        <div class="sb-label">Account</div>
        <a class="sb-link" href="/account/profile">🪪 Profile</a>
        <a class="sb-link" href="/account/keys">🔐 Access Keys</a>
      </div>
      <div class="sb-section">
        <div class="sb-label">Administration</div>
        <a class="sb-link" href="/admin">⚙️ Master Admin</a>
      </div>
    </aside>
    <div class="main">
      <header class="topbar">
        <strong>Secrets Management</strong>
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
