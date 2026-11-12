<!--
  Sign-in screen: password sign-in, external OIDC sign-in and the first-run
  "Create your organization" flow. SSO and first-run only appear when the
  server says they're available, so this works against servers that don't
  have those endpoints yet.

  Contracts (all unauthenticated):
    GET  /v1/auth/providers          → { providers: [{ id, name, type: "oidc" }] }
    GET  /v1/auth/oidc/{id}/start    → 302 to the IdP (browser navigation)
    GET  /v1/auth/oidc/{id}/callback → sets session cookie, 302 to returnTo
                                        or /app/?sso_error=<code>
    GET  /v1/bootstrap               → { required: boolean }
    POST /v1/bootstrap               → { accountId, organization, username }
                                        (body includes the one-time bootstrapToken
                                        printed in the server log; 401
                                        invalid_bootstrap_token when wrong)
    GET  /v1/server/info             → { fips, sessionIdleMinutes?, ... }
-->
<script lang="ts">
  import { onMount } from 'svelte';
  import { api, ApiError, errorMessage } from '$lib/api';
  import { session } from '$lib/stores/session.svelte';
  import Icon from './Icon.svelte';
  import Logo from './Logo.svelte';
  import ThemeToggle from './ThemeToggle.svelte';
  import CopyButton from './CopyButton.svelte';

  interface Provider {
    id: string;
    name: string;
    type: 'oidc';
  }

  const DOCS = 'https://github.com/worlddrknss/citadel/tree/main/docs';
  const SECURITY = 'https://github.com/worlddrknss/citadel/blob/main/SECURITY.md';

  // Unauthenticated GET that resolves to null when the server doesn't have
  // the endpoint (unknown /v1 paths redirect to the SPA's HTML).
  async function optional<T>(path: string): Promise<T | null> {
    try {
      const res = await fetch(path, { credentials: 'same-origin', headers: { Accept: 'application/json' } });
      if (!res.ok || res.redirected || !(res.headers.get('content-type') ?? '').includes('json')) return null;
      return (await res.json()) as T;
    } catch {
      return null;
    }
  }

  let providers = $state<Provider[]>([]);
  let bootstrapRequired = $state(false);
  let fips = $state(false);
  let idleMinutes = $state<number | null>(null);
  let ready = $state(false);

  // Sign in
  let accountId = $state('');
  let username = $state('');
  let password = $state('');
  let showPassword = $state(false);
  let forgotOpen = $state(false);
  let error = $state('');
  let busy = $state(false);

  // First run
  let step = $state<1 | 2>(1);
  let orgName = $state('');
  let accountName = $state('');
  let adminUser = $state('');
  let adminPassword = $state('');
  let bootstrapToken = $state('');
  let frError = $state('');
  let frBusy = $state(false);
  let created = $state<{ accountId: string; organization: string; username: string } | null>(null);

  const SSO_ERRORS: Record<string, string> = {
    access_denied: 'Your identity provider denied the sign-in.',
    no_role: 'You signed in, but none of your groups map to a Citadel role. Ask an admin to grant access.',
    state_mismatch: 'The sign-in link expired or was opened in another browser. Try again.',
    provider_error: "The identity provider didn't complete the sign-in. Try again."
  };

  onMount(async () => {
    try {
      accountId = localStorage.getItem('citadel-last-account') ?? '';
    } catch {
      /* ignore */
    }
    const url = new URL(location.href);
    const ssoErr = url.searchParams.get('sso_error');
    if (ssoErr) {
      error = SSO_ERRORS[ssoErr] ?? 'Single sign-on failed. Try again or use a password.';
      url.searchParams.delete('sso_error');
      history.replaceState(history.state, '', url);
    }
    const [p, b, info] = await Promise.all([
      optional<{ providers: Provider[] }>('/v1/auth/providers'),
      optional<{ required: boolean }>('/v1/bootstrap'),
      optional<{ fips: boolean; sessionIdleMinutes?: number }>('/v1/server/info')
    ]);
    providers = (p?.providers ?? []).filter((x) => x && x.id && x.type === 'oidc');
    bootstrapRequired = !!b?.required;
    fips = !!info?.fips;
    idleMinutes = info?.sessionIdleMinutes ?? null;
    ready = true;
  });

  function startSso(p: Provider) {
    const returnTo = location.pathname + location.search;
    location.assign(`/v1/auth/oidc/${encodeURIComponent(p.id)}/start?returnTo=${encodeURIComponent(returnTo)}`);
  }

  function remember(id: string) {
    try {
      localStorage.setItem('citadel-last-account', id);
    } catch {
      /* ignore */
    }
  }

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    error = '';
    busy = true;
    try {
      await api.login(accountId.trim(), username.trim(), password);
      password = '';
      remember(accountId.trim());
      await session.refresh();
    } catch (err) {
      error = errorMessage(err, 'Sign in failed');
    } finally {
      busy = false;
    }
  }

  // Rough strength: length dominates, variety helps.
  const strength = $derived.by(() => {
    const pw = adminPassword;
    const variety = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((r) => r.test(pw)).length;
    let s = 0;
    if (pw.length >= 8) s++;
    if (pw.length >= 12) s++;
    if (pw.length >= 16) s++;
    if (pw.length >= 12 && (variety >= 3 || pw.length >= 20)) s++;
    return s;
  });
  const strengthLabel = $derived(['Too short', 'Weak', 'Fair', 'Good', 'Strong'][strength]);
  const MIN_PW = 12;

  async function bootstrap(e: SubmitEvent) {
    e.preventDefault();
    frError = '';
    if (adminPassword.length < MIN_PW) {
      frError = `Use at least ${MIN_PW} characters for the admin password.`;
      return;
    }
    frBusy = true;
    try {
      const res = await fetch('/v1/bootstrap', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', 'X-Citadel-Request': '1' },
        body: JSON.stringify({
          organizationName: orgName.trim(),
          accountName: accountName.trim(),
          username: adminUser.trim(),
          password: adminPassword,
          bootstrapToken: bootstrapToken.trim()
        })
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) {
        if (res.status === 409) bootstrapRequired = false;
        throw new ApiError(res.status, body.error ?? 'error', body.message ?? 'Could not create the organization.');
      }
      created = { accountId: body.accountId, organization: body.organization ?? orgName.trim(), username: body.username ?? adminUser.trim() };
      remember(created.accountId);
      accountId = created.accountId;
      username = created.username;
      adminPassword = '';
      bootstrapToken = '';
      step = 2;
    } catch (err) {
      frError = errorMessage(err, 'Could not create the organization.');
    } finally {
      frBusy = false;
    }
  }

  async function finish() {
    await session.refresh();
    // No session cookie from bootstrap: fall back to the sign-in form, prefilled.
    if (session.status !== 'signed-in') bootstrapRequired = false;
  }
</script>

<div class="auth">
  <section class="brand" aria-label="About Citadel">
    <Logo tone="accent" size="lg" />
    <div class="pitch">
      <h1>Keys, secrets and certificates on infrastructure you control.</h1>
      <p>One control plane that speaks the AWS KMS, Secrets Manager, SSM and ACM PCA APIs, so your existing SDKs and Terraform work unchanged.</p>
    </div>
    <ul class="points">
      {#if fips}
        <li>
          <span class="pi"><Icon name="shield-check" /></span>
          <div><strong>FIPS 140 mode</strong><span>Approved algorithms only, enforced by the runtime.</span></div>
        </li>
      {/if}
      <li>
        <span class="pi"><Icon name="link" /></span>
        <div><strong>Tamper-evident audit</strong><span>Every event is hash-chained to the one before it.</span></div>
      </li>
      <li>
        <span class="pi"><Icon name="git-pull-request" /></span>
        <div><strong>Two-person rule</strong><span>Production changes wait for a second approver.</span></div>
      </li>
    </ul>
    <p class="mono foot">Self-hosted · open source</p>
  </section>

  <main class="side">
    <div class="top">
      <a class="btn btn-ghost" href={DOCS} target="_blank" rel="noopener noreferrer">Docs <Icon name="external-link" size={14} /></a>
      <ThemeToggle />
    </div>

    <div class="cards">
      {#if !ready}
        <div class="card card-flush panel" aria-busy="true" aria-label="Loading sign-in options">
          <span class="skeleton" style:width="40%" style:height="28px"></span>
          <span class="skeleton" style:width="70%" style:height="16px"></span>
          <span class="skeleton" style:width="100%" style:height="var(--ctl-h)"></span>
          <span class="skeleton" style:width="100%" style:height="var(--ctl-h)"></span>
          <span class="skeleton" style:width="100%" style:height="40px"></span>
        </div>
      {:else if bootstrapRequired}
        <section class="card card-flush firstrun" aria-labelledby="fr-title">
          <div class="fr-banner"><Icon name="info" size={14} />First run: no organization exists on this server yet</div>
          {#if step === 1}
            <form class="fr-body" onsubmit={bootstrap}>
              <div class="head">
                <span class="label">Step 1 of 2</span>
                <h2 id="fr-title">Create your organization</h2>
                <p class="muted">You become its first admin. You can add accounts and people next.</p>
              </div>
              {#if frError}
                <div class="callout callout-danger" role="alert"><Icon name="alert-circle" /><span>{frError}</span></div>
              {/if}
              <label class="field">
                <span class="field-label">Setup token</span>
                <input class="input mono" bind:value={bootstrapToken} required autocomplete="off" spellcheck="false" aria-describedby="token-hint" />
                <span class="field-hint" id="token-hint">One-time token printed in the server log at startup (or the value of KMS_BOOTSTRAP_TOKEN). It proves you run this server.</span>
              </label>
              <label class="field">
                <span class="field-label">Organization name</span>
                <input class="input" bind:value={orgName} required maxlength="100" autocomplete="organization" />
              </label>
              <label class="field">
                <span class="field-label">First account name</span>
                <input class="input mono" bind:value={accountName} required maxlength="64" pattern="[a-z0-9][a-z0-9\-]*" title="Lowercase letters, digits and dashes" />
                <span class="field-hint">Gets a 12-digit account ID. Most teams make one account per environment tier.</span>
              </label>
              <div class="pair">
                <label class="field">
                  <span class="field-label">Admin username</span>
                  <input class="input" bind:value={adminUser} required autocomplete="username" />
                </label>
                <label class="field">
                  <span class="field-label">Password</span>
                  <input class="input" type="password" bind:value={adminPassword} required minlength={MIN_PW} autocomplete="new-password" aria-describedby="pw-strength" />
                </label>
              </div>
              <div class="meter-wrap">
                <div class="meter" role="meter" aria-label="Password strength: {strengthLabel}" aria-valuemin="0" aria-valuemax="4" aria-valuenow={strength}>
                  {#each [1, 2, 3, 4] as i (i)}<span class:on={strength >= i} class:weak={strength < 3}></span>{/each}
                </div>
                <span class="field-hint" id="pw-strength">{adminPassword ? `${strengthLabel} · ${adminPassword.length} characters` : `At least ${MIN_PW} characters. A long passphrase beats symbols.`}</span>
              </div>
              {#if fips}
                <div class="note">
                  <Icon name="shield-check" />
                  <span><strong>FIPS 140 mode is on.</strong> <span class="muted">This server was started with it, so passwords are hashed with PBKDF2-SHA256.</span></span>
                </div>
              {/if}
              <button type="submit" class="btn btn-primary btn-tall" disabled={frBusy}>
                {frBusy ? 'Creating…' : 'Create organization'}{#if !frBusy}<Icon name="chevron-right" size={14} />{/if}
              </button>
            </form>
          {:else if created}
            <div class="fr-body">
              <div class="head">
                <span class="label">Step 2 of 2</span>
                <h2 id="fr-title">{created.organization} is ready</h2>
                <p class="muted">Keep the account ID: you and your teammates sign in with it.</p>
              </div>
              <dl class="kv">
                <dt>Account ID</dt>
                <dd class="acct"><span class="mono">{created.accountId}</span><CopyButton value={created.accountId} label="Copy account ID" /></dd>
                <dt>Admin</dt>
                <dd>{created.username}</dd>
              </dl>
              <button type="button" class="btn btn-primary btn-tall" onclick={finish}>Continue to console<Icon name="chevron-right" size={14} /></button>
            </div>
          {/if}
        </section>
      {:else}
        <section class="card card-flush panel" aria-labelledby="si-title">
          <div class="head">
            <h2 id="si-title">Sign in</h2>
            <p class="muted">Use the account ID your admin gave you.</p>
          </div>

          {#if session.expired}
            <div class="callout callout-warning" role="alert">
              <Icon name="clock" /><span>Your session expired. Sign in again to pick up where you left off.</span>
            </div>
          {/if}
          {#if error}
            <div class="callout callout-danger" role="alert"><Icon name="alert-circle" /><span>{error}</span></div>
          {/if}

          {#if providers.length}
            <div class="sso">
              {#each providers as p (p.id)}
                <button type="button" class="btn btn-secondary btn-tall" onclick={() => startSso(p)}>
                  <Icon name="link" />
                  {providers.length === 1 ? 'Continue with SSO (OIDC)' : `Continue with ${p.name}`}
                </button>
              {/each}
            </div>
            <div class="divider" aria-hidden="true"><span></span><span class="subtle">or with a password</span><span></span></div>
          {/if}

          <form class="form" onsubmit={submit}>
            <label class="field">
              <span class="field-label">Account ID</span>
              <input class="input mono" bind:value={accountId} inputmode="numeric" autocomplete="organization" placeholder="12-digit account ID" required />
            </label>
            <label class="field">
              <span class="field-label">Username</span>
              <input class="input" bind:value={username} autocomplete="username" required />
            </label>
            <div class="field">
              <span class="pw-row">
                <label for="pw" class="field-label">Password</label>
                <button type="button" class="linkish" aria-expanded={forgotOpen} onclick={() => (forgotOpen = !forgotOpen)}>Forgot password?</button>
              </span>
              <div class="pw">
                <input id="pw" class="input" type={showPassword ? 'text' : 'password'} bind:value={password} autocomplete="current-password" required />
                <button type="button" class="btn btn-ghost btn-sm btn-icon" aria-label={showPassword ? 'Hide password' : 'Show password'} aria-pressed={showPassword} onclick={() => (showPassword = !showPassword)}>
                  <Icon name={showPassword ? 'eye-off' : 'eye'} />
                </button>
              </div>
              {#if forgotOpen}
                <span class="field-hint" role="status">Citadel doesn't send reset emails. Ask an admin to set a new password for you in Administration → People{providers.length ? ', or sign in with SSO' : ''}.</span>
              {/if}
            </div>
            <button type="submit" class="btn btn-primary btn-tall" disabled={busy}>{busy ? 'Signing in…' : 'Sign in'}</button>
          </form>
          {#if idleMinutes}
            <p class="subtle small center">
              Sessions expire after {idleMinutes % 60 === 0 ? `${idleMinutes / 60} hour${idleMinutes === 60 ? '' : 's'}` : `${idleMinutes} minutes`} of inactivity.
            </p>
          {/if}
        </section>
      {/if}
    </div>

    <p class="subtle small center">
      Citadel · <a href="/healthz" target="_blank" rel="noopener">Status</a> · <a href={SECURITY} target="_blank" rel="noopener noreferrer">Security</a>
    </p>
  </main>
</div>

<style>
  .auth {
    min-height: 100dvh;
    display: flex;
    flex-wrap: wrap;
    align-items: stretch;
    background: var(--bg);
  }

  /* The brand panel is always dark, whatever the page theme. styles.css only
     defines the dark palette on :root, so its values are mirrored here. */
  .brand {
    --bg: #0b0f0d;
    --border: #242c29;
    --border-strong: #34403b;
    --text: #e6ece9;
    --text-muted: #a9b5b0;
    --text-subtle: #8c9994;
    --accent: #3dcca5;
    --accent-contrast: #03201a;
    color-scheme: dark;
    flex: 1 1 440px;
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: 40px;
    padding: 40px clamp(20px, 5vw, 64px);
    overflow: hidden;
    background-color: var(--bg);
    background-image:
      linear-gradient(var(--border) 1px, transparent 1px),
      linear-gradient(90deg, var(--border) 1px, transparent 1px);
    background-size: 48px 48px;
    background-position: -1px -1px;
    color: var(--text);
  }
  .pitch {
    display: flex;
    flex-direction: column;
    gap: 16px;
    max-width: 520px;
    margin-top: auto;
  }
  .pitch h1 {
    margin: 0;
    font: 600 clamp(28px, 3.4vw, 40px) / 1.15 var(--font-display);
    letter-spacing: -0.02em;
    text-wrap: balance;
  }
  .pitch p {
    margin: 0;
    max-width: 460px;
    color: var(--text-muted);
    font-size: 15px;
    line-height: 24px;
  }
  .points {
    display: flex;
    flex-direction: column;
    gap: 18px;
    max-width: 460px;
    margin: 0;
    padding: 0;
    list-style: none;
  }
  .points li {
    display: flex;
    gap: 12px;
  }
  .points div {
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .points strong {
    font-weight: 600;
  }
  .points div span {
    color: var(--text-muted);
    font-size: 13px;
  }
  .pi {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    flex: none;
    width: 32px;
    height: 32px;
    border: 1px solid var(--border-strong);
    border-radius: 8px;
    color: var(--accent);
  }
  .foot {
    margin: auto 0 0;
    color: var(--text-subtle);
    font-size: 12px;
  }

  .side {
    flex: 999 1 560px;
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: 24px;
    padding: 40px clamp(16px, 4vw, 56px);
  }
  .top {
    display: flex;
    justify-content: flex-end;
    align-items: center;
    gap: 8px;
  }
  .cards {
    flex: 1 1 auto;
    display: flex;
    flex-wrap: wrap;
    justify-content: center;
    align-items: flex-start;
    gap: 24px;
    padding-top: 24px;
  }
  .panel {
    width: 100%;
    max-width: 420px;
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
  .head h2 {
    margin: 0;
    font: 600 22px/28px var(--font-display);
    letter-spacing: -0.01em;
  }
  .head p {
    margin: 0;
  }
  .label {
    font-size: var(--text-xs);
    font-weight: 600;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    color: var(--text-subtle);
  }
  .callout {
    margin: 0;
  }
  .sso {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  .btn-tall {
    width: 100%;
    height: 40px;
  }
  .divider {
    display: flex;
    align-items: center;
    gap: 12px;
    font-size: var(--text-sm);
  }
  .divider span:first-child,
  .divider span:last-child {
    flex: 1;
    height: 1px;
    background: var(--border);
  }
  .form {
    display: flex;
    flex-direction: column;
    gap: 14px;
  }
  .form .field + .field,
  .fr-body .field + .field {
    margin-top: 0;
  }
  .form button[type='submit'] {
    margin-top: 4px;
  }
  .pw-row {
    display: flex;
    justify-content: space-between;
    align-items: baseline;
  }
  .linkish {
    padding: 0;
    border: none;
    background: none;
    color: var(--accent-text);
    font: inherit;
    font-size: 12.5px;
    cursor: pointer;
  }
  .linkish:hover {
    text-decoration: underline;
  }
  .pw {
    position: relative;
    display: flex;
    align-items: center;
  }
  .pw .input {
    padding-right: 44px;
  }
  .pw .btn {
    position: absolute;
    right: 4px;
  }
  .center {
    margin: 0;
    text-align: center;
  }

  .firstrun {
    width: 100%;
    max-width: 420px;
    overflow: hidden;
  }
  .fr-banner {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 12px 28px;
    background: var(--accent-soft);
    color: var(--accent-text);
    font-size: 12.5px;
    font-weight: 500;
  }
  .fr-body {
    display: flex;
    flex-direction: column;
    gap: 18px;
    padding: 24px 28px 28px;
  }
  .pair {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(min(160px, 100%), 1fr));
    gap: 12px;
  }
  .meter-wrap {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .meter {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 4px;
  }
  .meter span {
    height: 4px;
    border-radius: 2px;
    background: var(--surface-pressed);
  }
  .meter span.on {
    background: var(--accent);
  }
  .meter span.on.weak {
    background: var(--warning);
  }
  .note {
    display: flex;
    align-items: flex-start;
    gap: 10px;
    padding: 10px 12px;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: var(--surface-hover);
    font-size: 12.5px;
  }
  .note > :global(svg) {
    margin-top: 2px;
    color: var(--accent);
  }
  .acct {
    display: flex;
    align-items: center;
    gap: 8px;
  }
</style>
