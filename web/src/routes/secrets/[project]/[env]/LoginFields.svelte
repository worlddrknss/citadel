<!--
  A login credential's fields in the Agent access tab: username, password
  and TOTP seed. The password and seed are write-only (the server never
  returns them); editors who may reveal values see a live preview of the
  current one-time code.
-->
<script lang="ts">
  import { onDestroy, untrack } from 'svelte';
  import Badge from '#lib/components/Badge.svelte';
  import Icon from '#lib/components/Icon.svelte';
  import { errorMessage } from '#lib/api.ts';
  import { toast } from '#lib/stores/toast.svelte.ts';
  import { agentsApi, codeSecondsLeft, type LoginInput, type LoginState, type TotpCode } from '../../../agents/api';

  let { name, canEdit }: { name: string; canEdit: boolean } = $props();

  const uid = Math.random().toString(36).slice(2, 8);
  let info = $state<LoginState | null>(null);
  let loadError = $state('');
  let username = $state('');
  let password = $state('');
  let seed = $state('');
  let saving = $state(false);
  let saveError = $state('');

  let code = $state<TotpCode | null>(null);
  let now = $state(Date.now());
  let timer: ReturnType<typeof setInterval> | undefined;
  let fetching = false;

  async function load() {
    loadError = '';
    try {
      info = await agentsApi.login(name);
      username = info.username;
    } catch (e) {
      loadError = errorMessage(e, 'Could not load the login.');
    }
  }
  $effect(() => {
    void name;
    untrack(() => {
      stopPreview();
      load();
    });
  });

  async function refreshCode() {
    if (fetching) return;
    fetching = true;
    try {
      const s = await agentsApi.login(name, true);
      code = s.totp ?? null;
      if (!code) stopPreview();
    } catch (e) {
      toast.error(e, 'Could not get the code');
      stopPreview();
    } finally {
      fetching = false;
    }
  }
  function startPreview() {
    refreshCode();
    timer = setInterval(() => {
      now = Date.now();
      if (code && codeSecondsLeft(code.expiresAt, now) === 0) refreshCode();
    }, 1000);
  }
  function stopPreview() {
    if (timer) clearInterval(timer);
    timer = undefined;
    code = null;
  }
  onDestroy(stopPreview);

  const secondsLeft = $derived(code ? codeSecondsLeft(code.expiresAt, now) : 0);

  async function save(e: SubmitEvent) {
    e.preventDefault();
    if (saving || !info) return;
    const body: LoginInput = { name };
    if (username.trim() !== info.username) body.username = username.trim();
    if (password) body.password = password;
    if (seed.trim()) body.totpSeed = seed.trim();
    if (Object.keys(body).length === 1) return;
    saving = true;
    saveError = '';
    try {
      info = await agentsApi.putLogin(body);
      password = '';
      seed = '';
      toast.success('Login saved');
    } catch (err) {
      saveError = errorMessage(err, 'Could not save the login.');
    } finally {
      saving = false;
    }
  }

  async function removeSeed() {
    saving = true;
    saveError = '';
    try {
      info = await agentsApi.putLogin({ name, clearTotpSeed: true });
      stopPreview();
      toast.success('TOTP seed removed');
    } catch (err) {
      saveError = errorMessage(err, 'Could not remove the seed.');
    } finally {
      saving = false;
    }
  }
</script>

{#if loadError}
  <p class="small subtle">{loadError}</p>
{:else if info}
  <form class="login" aria-label="Login {name}" onsubmit={save} novalidate>
    {#if saveError}<div class="callout callout-danger" role="alert"><Icon name="alert-circle" size={16} /><span>{saveError}</span></div>{/if}
    <div class="row2">
      <div class="field">
        <label class="field-label" for="lg-user-{uid}">Username</label>
        <input id="lg-user-{uid}" class="input" bind:value={username} disabled={!canEdit} autocomplete="off" spellcheck="false" />
      </div>
      <div class="field">
        <label class="field-label" for="lg-pass-{uid}">Password</label>
        <input id="lg-pass-{uid}" class="input" type="password" bind:value={password} disabled={!canEdit} autocomplete="new-password" placeholder={info.hasPassword ? 'Set (type to replace)' : 'Not set'} />
      </div>
    </div>
    <div class="field">
      <span class="field-label" id="lg-totp-label-{uid}">TOTP seed</span>
      <div class="seed-row">
        {#if !info.hasTotpSeed}
          <span class="badge">Not set</span>
        {:else if info.totpStatus === 'ok'}
          <Badge tone="success">Configured</Badge>
        {:else}
          <Badge tone="danger">{info.totpStatus === 'sha1_unsupported' ? 'SHA-1: unusable' : 'Unusable'}</Badge>
        {/if}
        {#if canEdit && info.hasTotpSeed}
          <button type="button" class="btn btn-ghost btn-sm" onclick={removeSeed} disabled={saving}>Remove</button>
        {/if}
      </div>
      {#if info.totpMessage}<span class="field-hint warn">{info.totpMessage}</span>{/if}
      {#if canEdit}
        <input
          id="lg-seed-{uid}"
          class="input mono"
          type="password"
          aria-labelledby="lg-totp-label-{uid}"
          bind:value={seed}
          autocomplete="off"
          spellcheck="false"
          placeholder={info.hasTotpSeed ? 'Paste a new otpauth:// URI or seed to replace it' : 'otpauth://totp/… or a base32 seed'}
        />
        <span class="field-hint">Write-only: Citadel never shows it again. SHA-1 seeds can't be used (FIPS 140-3 mode).</span>
      {/if}
    </div>
    {#if info.hasTotpSeed && info.totpStatus === 'ok' && canEdit}
      <div class="preview" aria-live="polite">
        {#if code}
          <span class="code mono" aria-label="Current code">{code.code}</span>
          <span class="small muted">{secondsLeft}s left</span>
          <span class="bar" aria-hidden="true"><span style="width: {(secondsLeft / (code.period || 30)) * 100}%"></span></span>
          <button type="button" class="btn btn-ghost btn-sm" onclick={stopPreview}>Hide</button>
        {:else}
          <button type="button" class="btn btn-ghost btn-sm" onclick={startPreview}><Icon name="eye" size={14} />Show current code</button>
        {/if}
      </div>
    {/if}
    {#if canEdit}
      <div><button type="submit" class="btn btn-secondary btn-sm" disabled={saving}>{saving ? 'Saving…' : 'Save login'}</button></div>
    {/if}
  </form>
{/if}

<style>
  .login {
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
    margin-top: var(--space-3);
    padding-top: var(--space-3);
    border-top: 1px solid var(--border);
  }
  .login .field + .field {
    margin-top: 0;
  }
  .row2 {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: var(--space-3);
  }
  .seed-row {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    margin-bottom: var(--space-1);
  }
  .warn {
    color: var(--warning);
  }
  .preview {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    flex-wrap: wrap;
  }
  .code {
    font-size: var(--text-lg);
    font-weight: 600;
    letter-spacing: 0.12em;
  }
  .bar {
    flex: 0 0 80px;
    height: 4px;
    border-radius: 2px;
    background: var(--border);
    overflow: hidden;
  }
  .bar span {
    display: block;
    height: 100%;
    background: var(--accent);
    transition: width 1s linear;
  }
  @media (max-width: 560px) {
    .row2 {
      grid-template-columns: minmax(0, 1fr);
    }
  }
</style>
