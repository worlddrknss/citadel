<!--
  TOTP enrolment: starts an enrolment, shows the QR code (rendered here, from
  the otpauth URI, never by an external service) and the secret for manual
  entry, confirms with a code, then shows the one-time recovery codes.
  `ondone` receives the confirm response (with `me` when a restricted
  session was upgraded).
-->
<script lang="ts">
  import { onMount } from 'svelte';
  import type { Me } from '../api.ts';
  import { errorMessage } from '../api.ts';
  import { mfaApi, cleanOtp, isOtp, groupSecret, type MfaEnrollment } from '../mfa.ts';
  import Icon from './Icon.svelte';
  import CopyButton from './CopyButton.svelte';
  import QrCode from './QrCode.svelte';
  import RecoveryCodes from './RecoveryCodes.svelte';

  let {
    username,
    ondone,
    oncancel
  }: {
    username: string;
    ondone: (r: { me?: Me }) => void;
    oncancel?: () => void;
  } = $props();

  let enrollment = $state<MfaEnrollment | null>(null);
  let startError = $state('');
  let code = $state('');
  let error = $state('');
  let busy = $state(false);
  let showSecret = $state(false);
  let result = $state<{ recoveryCodes: string[]; me?: Me } | null>(null);

  async function start() {
    startError = '';
    try {
      enrollment = await mfaApi.start();
    } catch (e) {
      startError = errorMessage(e, 'Could not start setting up multi-factor authentication.');
    }
  }
  onMount(start);

  async function confirm(e: SubmitEvent) {
    e.preventDefault();
    if (!isOtp(code)) {
      error = 'Enter the 6-digit code from your authenticator app.';
      return;
    }
    error = '';
    busy = true;
    try {
      const r = await mfaApi.confirm(cleanOtp(code));
      result = { recoveryCodes: r.recoveryCodes, me: r.me };
      enrollment = null;
    } catch (err) {
      error = errorMessage(err, 'That code did not work. Try the next one.');
      code = '';
    } finally {
      busy = false;
    }
  }
</script>

{#if result}
  <RecoveryCodes codes={result.recoveryCodes} {username} doneLabel="Finish" ondone={() => ondone({ me: result?.me })} />
{:else if startError}
  <div class="callout callout-danger" role="alert">
    <Icon name="alert-circle" size={16} /><span>{startError}</span>
    <button type="button" class="btn btn-ghost btn-sm push" onclick={start}>Retry</button>
  </div>
{:else if !enrollment}
  <div class="sk" aria-busy="true" aria-label="Preparing"><span class="skeleton qr-sk"></span><span class="skeleton"></span></div>
{:else}
  <form class="enroll" onsubmit={confirm} novalidate>
    <ol class="steps">
      <li>
        <strong>Scan this QR code with your authenticator app.</strong>
        <span class="muted small">The app must support SHA-256 codes: 1Password, Authy and Microsoft Authenticator do.</span>
      </li>
    </ol>
    <div class="qr-row">
      <QrCode value={enrollment.otpauthUri} label="QR code for your authenticator app" />
      <div class="manual">
        <button type="button" class="linkish" aria-expanded={showSecret} onclick={() => (showSecret = !showSecret)}>Can't scan it? Enter the key by hand</button>
        {#if showSecret}
          <dl class="kv small">
            <dt>Account</dt><dd class="mono">{enrollment.issuer}: {enrollment.account}</dd>
            <dt>Key</dt>
            <dd class="secret"><code class="mono" data-testid="mfa-secret">{groupSecret(enrollment.secret)}</code><CopyButton value={enrollment.secret} label="Copy key" clearAfter={60} /></dd>
            <dt>Type</dt><dd>Time-based, {enrollment.algorithm}, {enrollment.digits} digits, {enrollment.period}s</dd>
          </dl>
        {/if}
      </div>
    </div>
    <div class="field">
      <label class="field-label" for="mfa-enroll-code">2. Enter the 6-digit code it shows</label>
      <input
        id="mfa-enroll-code"
        class="input mono otp"
        bind:value={code}
        inputmode="numeric"
        autocomplete="one-time-code"
        maxlength="7"
        pattern="[0-9 ]*"
        aria-invalid={!!error}
        required
      />
      {#if error}<span class="field-error" role="alert">{error}</span>{/if}
    </div>
    <div class="actions">
      {#if oncancel}<button type="button" class="btn btn-ghost" onclick={oncancel}>Cancel</button>{/if}
      <button type="submit" class="btn btn-primary" disabled={busy}>{busy ? 'Verifying…' : 'Turn on'}</button>
    </div>
  </form>
{/if}

<style>
  .enroll {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
  }
  .steps {
    margin: 0;
    padding: 0;
    list-style: none;
  }
  .steps li {
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .steps strong::before {
    content: '1. ';
  }
  .qr-row {
    display: flex;
    flex-wrap: wrap;
    align-items: flex-start;
    gap: var(--space-4);
  }
  .manual {
    flex: 1 1 200px;
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  .kv {
    margin: 0;
  }
  .secret {
    display: flex;
    align-items: center;
    gap: 4px;
    overflow-wrap: anywhere;
  }
  .otp {
    max-width: 160px;
    letter-spacing: 0.2em;
    font-size: 16px;
  }
  .actions {
    display: flex;
    justify-content: flex-end;
    gap: 8px;
  }
  .linkish {
    align-self: flex-start;
    padding: 0;
    border: none;
    background: none;
    color: var(--accent-text);
    font: inherit;
    font-size: 13.5px;
    cursor: pointer;
  }
  .linkish:hover {
    text-decoration: underline;
  }
  .sk {
    display: flex;
    flex-direction: column;
    gap: 10px;
  }
  .sk .skeleton {
    height: 14px;
  }
  .sk .qr-sk {
    width: 196px;
    height: 196px;
  }
  .push {
    margin-left: auto;
  }
</style>
