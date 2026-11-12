<script lang="ts">
  import { api, errorMessage } from '$lib/api';
  import { session } from '$lib/stores/session.svelte';
  import Icon from './Icon.svelte';
  import Logo from './Logo.svelte';

  let accountId = $state('');
  let username = $state('');
  let password = $state('');
  let error = $state('');
  let busy = $state(false);

  // Remember the account ID (not the user) so returning users type less.
  $effect(() => {
    try {
      accountId = localStorage.getItem('citadel-last-account') ?? '';
    } catch {
      /* ignore */
    }
  });

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    error = '';
    busy = true;
    try {
      await api.login(accountId.trim(), username.trim(), password);
      password = '';
      try {
        localStorage.setItem('citadel-last-account', accountId.trim());
      } catch {
        /* ignore */
      }
      await session.refresh();
    } catch (err) {
      error = errorMessage(err, 'Sign in failed');
    } finally {
      busy = false;
    }
  }
</script>

<main class="auth">
  <div class="auth-panel">
    <div class="auth-brand"><Logo /></div>
    <h1>Sign in to Citadel</h1>
    <p class="muted">Keys, secrets and certificates for your organization.</p>

    {#if session.expired}
      <div class="callout callout-warning" role="alert">
        <Icon name="clock" />
        <span>Your session expired. Sign in again to pick up where you left off.</span>
      </div>
    {/if}
    {#if error}
      <div class="callout callout-danger" role="alert">
        <Icon name="alert-circle" />
        <span>{error}</span>
      </div>
    {/if}

    <form onsubmit={submit} class="auth-form">
      <label class="field">
        <span class="field-label">Account ID</span>
        <input
          class="input mono"
          bind:value={accountId}
          autocomplete="organization"
          inputmode="numeric"
          placeholder="123456789012"
          required
        />
      </label>
      <label class="field">
        <span class="field-label">Username</span>
        <input class="input" bind:value={username} autocomplete="username" required />
      </label>
      <label class="field">
        <span class="field-label">Password</span>
        <input class="input" type="password" bind:value={password} autocomplete="current-password" required />
      </label>
      <button class="btn btn-primary btn-lg btn-block" type="submit" disabled={busy}>
        {busy ? 'Signing in…' : 'Sign in'}
      </button>
    </form>
  </div>
</main>

<style>
  .auth {
    min-height: 100dvh;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: var(--space-5);
    padding: var(--space-4);
    background:
      radial-gradient(1200px 500px at 50% -10%, var(--accent-soft), transparent 70%),
      var(--bg);
  }
  .auth-panel {
    width: 100%;
    max-width: 400px;
    padding: var(--space-8);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    background: var(--surface);
    box-shadow: var(--shadow-md);
  }
  .auth-brand {
    margin-bottom: var(--space-6);
  }
  h1 {
    margin: 0;
    font-size: var(--text-xl);
    font-weight: 600;
    letter-spacing: -0.01em;
  }
  .auth-panel > p {
    margin: var(--space-1) 0 var(--space-5);
    font-size: var(--text-sm);
  }
  .callout {
    margin-bottom: var(--space-4);
  }
  .auth-form {
    display: flex;
    flex-direction: column;
  }
  .auth-form button {
    margin-top: var(--space-6);
  }
</style>
