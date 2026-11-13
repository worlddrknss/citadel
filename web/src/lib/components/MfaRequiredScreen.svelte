<!--
  Shown instead of the console when the session is restricted: the
  organization requires multi-factor authentication and this user has not
  set it up. Only enrolment (and signing out) is possible until it's done.
-->
<script lang="ts">
  import { session } from '../stores/session.svelte.ts';
  import Icon from './Icon.svelte';
  import Logo from './Logo.svelte';
  import ThemeToggle from './ThemeToggle.svelte';
  import MfaEnroll from './MfaEnroll.svelte';

  async function done() {
    // The server swapped the restricted session for a full one.
    await session.refresh();
  }
</script>

<div class="wrap">
  <header class="top">
    <Logo />
    <span class="spacer"></span>
    <ThemeToggle />
    <button type="button" class="btn btn-ghost btn-sm" onclick={() => session.signOut()}><Icon name="log-out" size={14} />Sign out</button>
  </header>
  <main class="card card-flush panel" aria-labelledby="mfa-req-title">
    <div class="head">
      <span class="label"><Icon name="shield-check" size={14} />Required by your organization</span>
      <h1 id="mfa-req-title">Set up two-step verification</h1>
      <p class="muted">Before you continue, {session.me?.displayName || session.me?.username}, add an authenticator app. You'll enter a code from it each time you sign in with your password.</p>
    </div>
    <MfaEnroll username={session.me?.username ?? ''} ondone={done} />
  </main>
</div>

<style>
  .wrap {
    min-height: 100dvh;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 32px;
    padding: 24px 16px 48px;
    background: var(--bg);
  }
  .top {
    width: 100%;
    max-width: 960px;
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .spacer {
    flex: 1;
  }
  .panel {
    width: 100%;
    max-width: 520px;
    padding: 28px;
    display: flex;
    flex-direction: column;
    gap: 20px;
  }
  .head {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .head h1 {
    margin: 0;
    font: 600 24px/28px var(--font-display);
    letter-spacing: -0.01em;
  }
  .head p {
    margin: 0;
  }
  .label {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-size: var(--text-xs);
    font-weight: 600;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    color: var(--accent-text);
  }
</style>
