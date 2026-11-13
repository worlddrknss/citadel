<!--
  My account → Security: two-step verification (TOTP) status, enrolment,
  recovery-code regeneration and turning it off. Turning off and
  regenerating need the current password plus a code.
-->
<script lang="ts">
  import { onMount } from 'svelte';
  import Badge from '#lib/components/Badge.svelte';
  import Icon from '#lib/components/Icon.svelte';
  import Modal from '#lib/components/Modal.svelte';
  import MfaEnroll from '#lib/components/MfaEnroll.svelte';
  import RecoveryCodes from '#lib/components/RecoveryCodes.svelte';
  import { errorMessage } from '#lib/api.ts';
  import { mfaApi, cleanOtp, isOtp, type MfaStatus } from '#lib/mfa.ts';
  import { session } from '#lib/stores/session.svelte.ts';
  import { toast } from '#lib/stores/toast.svelte.ts';

  let { sso = false }: { sso?: boolean } = $props();

  let status = $state<MfaStatus | null>(null);
  let loadError = $state('');

  async function load() {
    loadError = '';
    try {
      status = await mfaApi.status();
    } catch (e) {
      loadError = errorMessage(e, 'Could not load two-step verification status.');
    }
  }
  onMount(load);

  // Enrolment
  let enrollOpen = $state(false);
  let enrollKey = $state(0);
  function startEnroll() {
    enrollKey++;
    enrollOpen = true;
  }
  async function enrolled() {
    enrollOpen = false;
    toast.success('Two-step verification is on');
    await load();
  }

  // Re-authenticated actions
  let action = $state<'disable' | 'regenerate' | null>(null);
  let password = $state('');
  let code = $state('');
  let useRecovery = $state(false);
  let actionError = $state('');
  let busy = $state(false);
  let actionOpen = $state(false);
  let newCodes = $state<string[] | null>(null);
  let codesOpen = $state(false);

  function openAction(a: 'disable' | 'regenerate') {
    action = a;
    actionOpen = true;
    password = '';
    code = '';
    useRecovery = false;
    actionError = '';
  }

  async function submitAction(e: SubmitEvent) {
    e.preventDefault();
    if (!password) {
      actionError = 'Enter your current password.';
      return;
    }
    if (!useRecovery && !isOtp(code)) {
      actionError = 'Enter the 6-digit code from your authenticator app.';
      return;
    }
    actionError = '';
    busy = true;
    const factor = useRecovery ? { recoveryCode: code.trim() } : { code: cleanOtp(code) };
    try {
      if (action === 'disable') {
        await mfaApi.disable(password, factor);
        actionOpen = false;
        toast.success('Two-step verification is off');
      } else {
        const r = await mfaApi.regenerate(password, factor);
        actionOpen = false;
        newCodes = r.recoveryCodes;
        codesOpen = true;
      }
      await load();
    } catch (err) {
      actionError = errorMessage(err, 'Could not verify');
    } finally {
      busy = false;
      password = '';
    }
  }

  function keepCodesOpen() {
    if (!newCodes) return;
    // Esc or the close button: keep the codes on screen until acknowledged.
    toast.info("Confirm you've saved them first — they can't be shown again.");
    queueMicrotask(() => (codesOpen = true));
  }
  function codesSaved() {
    newCodes = null;
    codesOpen = false;
  }

  const fmt = (s?: string) => (s ? new Date(s).toLocaleDateString(undefined, { dateStyle: 'medium' }) : '');
</script>

<section class="card block" aria-labelledby="sec-title">
  <div class="card-head">
    <div>
      <h2 id="sec-title">Security</h2>
      <p class="subtle small sub">Two-step verification asks for a code from your authenticator app after your password.</p>
    </div>
  </div>
  <div class="card-pad">
    {#if sso}
      <p class="muted">You signed in with single sign-on; your identity provider handles two-step verification for that. The settings below apply when you sign in with a password.</p>
    {/if}
    {#if loadError}
      <div class="callout callout-danger" role="alert"><Icon name="alert-circle" size={16} /><span>{loadError}</span><button type="button" class="btn btn-ghost btn-sm push" onclick={load}>Retry</button></div>
    {:else if !status}
      <div class="sk" aria-busy="true"><span class="skeleton"></span><span class="skeleton"></span></div>
    {:else}
      <div class="row">
        <span class="ic" aria-hidden="true"><Icon name="shield-check" size={18} /></span>
        <div class="txt">
          <span class="name">
            Authenticator app
            {#if status.enabled}<Badge tone="success" dot={false} >On</Badge>{:else}<Badge dot={false}>Off</Badge>{/if}
            {#if status.required}<span class="badge">Required by your organization</span>{/if}
          </span>
          <span class="subtle small">
            {#if status.enabled}
              Turned on {fmt(status.enabledAt)} · {status.recoveryCodesLeft} recovery code{status.recoveryCodesLeft === 1 ? '' : 's'} left
            {:else}
              Time-based codes ({status.algorithm}, {status.digits} digits). Your app must support SHA-256: 1Password, Authy and Microsoft Authenticator do.
            {/if}
          </span>
        </div>
        <div class="acts">
          {#if status.enabled}
            <button type="button" class="btn btn-secondary btn-sm" onclick={() => openAction('regenerate')}><Icon name="refresh" size={14} />New recovery codes</button>
            {#if !status.required}
              <button type="button" class="btn btn-danger-ghost btn-sm" onclick={() => openAction('disable')}>Turn off</button>
            {/if}
          {:else}
            <button type="button" class="btn btn-primary btn-sm" onclick={startEnroll}>Set up</button>
          {/if}
        </div>
      </div>
      {#if status.enabled && status.recoveryCodesLeft <= 2}
        <div class="callout callout-warning" role="note"><Icon name="alert-triangle" size={16} /><span>You're running out of recovery codes. Create new ones so you can still get in if you lose your device.</span></div>
      {/if}
    {/if}
  </div>
</section>

<Modal bind:open={enrollOpen} title="Set up two-step verification" description="Link an authenticator app to your Citadel account." size="md">
  {#key enrollKey}
    {#if enrollOpen}
      <MfaEnroll username={session.me?.username ?? ''} ondone={enrolled} oncancel={() => (enrollOpen = false)} />
    {/if}
  {/key}
</Modal>

<Modal
  bind:open={actionOpen}
  title={action === 'disable' ? 'Turn off two-step verification?' : 'Create new recovery codes?'}
  description={action === 'disable' ? 'Your password alone will sign you in again.' : 'Your current recovery codes stop working.'}
  size="sm"
>
  <form id="mfa-reauth" class="reauth" onsubmit={submitAction} novalidate>
    <input type="text" name="username" autocomplete="username" value={session.me?.username ?? ''} readonly hidden />
    <div class="field">
      <label class="field-label" for="mfa-pw">Current password</label>
      <input id="mfa-pw" class="input" type="password" autocomplete="current-password" bind:value={password} required />
    </div>
    <div class="field">
      <label class="field-label" for="mfa-code">{useRecovery ? 'Recovery code' : 'Authentication code'}</label>
      {#if useRecovery}
        <input id="mfa-code" class="input mono" autocomplete="off" spellcheck="false" bind:value={code} required />
      {:else}
        <input id="mfa-code" class="input mono" inputmode="numeric" autocomplete="one-time-code" maxlength="7" bind:value={code} required />
      {/if}
      <button type="button" class="linkish" onclick={() => { useRecovery = !useRecovery; code = ''; }}>{useRecovery ? 'Use your authenticator app' : 'Use a recovery code'}</button>
    </div>
    {#if actionError}
      <div class="callout callout-danger" role="alert"><Icon name="alert-circle" size={16} /><span>{actionError}</span></div>
    {/if}
  </form>
  {#snippet footer()}
    <button type="button" class="btn btn-ghost" onclick={() => (actionOpen = false)}>Cancel</button>
    <button type="submit" form="mfa-reauth" class="btn {action === 'disable' ? 'btn-danger' : 'btn-primary'}" disabled={busy}>
      {busy ? 'Verifying…' : action === 'disable' ? 'Turn off' : 'Create new codes'}
    </button>
  {/snippet}
</Modal>

<Modal bind:open={codesOpen} title="New recovery codes" size="md" onclose={keepCodesOpen}>
  {#if newCodes}
    <RecoveryCodes codes={newCodes} username={session.me?.username ?? ''} ondone={codesSaved} />
  {/if}
</Modal>

<style>
  .block {
    margin-top: 20px;
  }
  .sub {
    margin: 2px 0 0;
  }
  .card-pad {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
  }
  .card-pad > p {
    margin: 0;
  }
  .row {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 12px;
  }
  .ic {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 36px;
    height: 36px;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    color: var(--accent);
  }
  .txt {
    flex: 1 1 260px;
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .name {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 6px;
    font-weight: 600;
  }
  .acts {
    display: flex;
    gap: 8px;
  }
  .callout {
    margin: 0;
  }
  .sk {
    display: flex;
    flex-direction: column;
    gap: 10px;
  }
  .sk .skeleton {
    height: 14px;
  }
  .push {
    margin-left: auto;
  }
  .reauth {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
  }
  .reauth .field + .field {
    margin-top: 0;
  }
  .linkish {
    align-self: flex-start;
    margin-top: 4px;
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
</style>
