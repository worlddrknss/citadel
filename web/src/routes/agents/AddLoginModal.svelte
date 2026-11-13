<!--
  "Add login": stores a website login as a secret and makes it usable by
  browser agents in one step (the secret, its login usage profile, and the
  TOTP seed, which is validated by the server and never shown again).
-->
<script lang="ts">
  import Modal from '#lib/components/Modal.svelte';
  import Icon from '#lib/components/Icon.svelte';
  import { errorMessage, req } from '#lib/api.ts';
  import { toast } from '#lib/stores/toast.svelte.ts';
  import { agentsApi, splitList, validateCredential, type CredentialInput } from './api';

  let { open = $bindable(false), onsaved }: { open?: boolean; onsaved?: () => void } = $props();

  const uid = Math.random().toString(36).slice(2, 8);
  let name = $state('');
  let project = $state('');
  let env = $state('');
  let path = $state('');
  let key = $state('');
  let pages = $state('');
  let username = $state('');
  let password = $state('');
  let seed = $state('');
  let description = $state('');
  let saving = $state(false);
  let saveError = $state('');
  // Set once the secret and profile exist and only the seed failed.
  let created = $state(false);

  $effect(() => {
    if (!open) return;
    name = project = env = path = key = pages = username = password = seed = description = saveError = '';
    created = false;
  });

  const SEG = /^[A-Za-z0-9_.-]+$/;
  const input = $derived<CredentialInput>({
    name: name.trim(),
    project: project.trim(),
    env: env.trim(),
    path: path.trim(),
    key: key.trim(),
    kind: 'login',
    description: description.trim(),
    login: { urlPatterns: splitList(pages) }
  });
  const formError = $derived(
    created
      ? ''
      : !SEG.test(project.trim()) || !SEG.test(env.trim()) || !SEG.test(key.trim())
        ? 'Name the secret: project, environment and key.'
        : !username.trim()
          ? 'Enter the username.'
          : validateCredential(input)
  );

  async function save(e: SubmitEvent) {
    e.preventDefault();
    if (saving || formError) return;
    saving = true;
    saveError = '';
    try {
      if (!created) {
        await req('/v1/secrets', {
          method: 'POST',
          body: JSON.stringify({ project: input.project, env: input.env, path: input.path || '/', key: input.key, value: JSON.stringify({ username: username.trim(), password }) })
        });
        await agentsApi.createCredential(input);
        created = true;
      }
      if (seed.trim()) await agentsApi.putLogin({ name: input.name, totpSeed: seed.trim() });
      toast.success(`Added login ${input.name}`);
      open = false;
      onsaved?.();
    } catch (err) {
      saveError = created
        ? `The login was created, but the TOTP seed was refused: ${errorMessage(err, 'unknown error')} Fix the seed and save again, or close and add it later from the secret's Agent access tab.`
        : errorMessage(err, 'Could not add the login.');
    } finally {
      saving = false;
    }
  }
</script>

<Modal bind:open title="Add login" description="A website login for browser agents. Agents get one-time codes, and the username and password only on the pages you list." size="md">
  <form id="login-form-{uid}" class="form" onsubmit={save} novalidate>
    {#if saveError}<div class="callout callout-danger" role="alert"><Icon name="alert-circle" size={16} /><span>{saveError}</span></div>{/if}
    <div class="field">
      <label class="field-label" for="al-name-{uid}">Credential name</label>
      <input id="al-name-{uid}" class="input mono" bind:value={name} disabled={created} spellcheck="false" placeholder="crm-login" />
    </div>
    <fieldset class="field plain">
      <legend class="field-label">Store it as the secret</legend>
      <div class="row4">
        <input class="input mono" aria-label="Project" bind:value={project} disabled={created} placeholder="project" spellcheck="false" />
        <input class="input mono" aria-label="Environment" bind:value={env} disabled={created} placeholder="env" spellcheck="false" />
        <input class="input mono" aria-label="Folder (optional)" bind:value={path} disabled={created} placeholder="folder (optional)" spellcheck="false" />
        <input class="input mono" aria-label="Key" bind:value={key} disabled={created} placeholder="KEY" spellcheck="false" />
      </div>
    </fieldset>
    <div class="field">
      <label class="field-label" for="al-pages-{uid}">Pages the login may be used on</label>
      <textarea id="al-pages-{uid}" class="input mono" rows="2" bind:value={pages} disabled={created} spellcheck="false" placeholder="https://crm.example.com/login"></textarea>
      <span class="field-hint">One per line: https://host[:port][/path], the host optionally *.example.com.</span>
    </div>
    <div class="row2">
      <div class="field">
        <label class="field-label" for="al-user-{uid}">Username</label>
        <input id="al-user-{uid}" class="input" bind:value={username} disabled={created} autocomplete="off" spellcheck="false" />
      </div>
      <div class="field">
        <label class="field-label" for="al-pass-{uid}">Password</label>
        <input id="al-pass-{uid}" class="input" type="password" bind:value={password} disabled={created} autocomplete="new-password" />
      </div>
    </div>
    <div class="field">
      <label class="field-label" for="al-seed-{uid}">TOTP seed <span class="subtle">(optional)</span></label>
      <input id="al-seed-{uid}" class="input mono" type="password" bind:value={seed} autocomplete="off" spellcheck="false" placeholder="otpauth://totp/…" />
      <span class="field-hint">The otpauth:// URI from the site's QR code, with SHA-256 or SHA-512. SHA-1 seeds can't be used: Citadel runs in FIPS 140-3 mode.</span>
    </div>
    <div class="field">
      <label class="field-label" for="al-desc-{uid}">Description <span class="subtle">(optional; agents see it)</span></label>
      <input id="al-desc-{uid}" class="input" bind:value={description} disabled={created} />
    </div>
    {#if formError && name}<span class="field-error" role="status">{formError}</span>{/if}
  </form>
  {#snippet footer()}
    <button type="button" class="btn btn-ghost" onclick={() => (open = false)}>{created ? 'Close' : 'Cancel'}</button>
    <button type="submit" form="login-form-{uid}" class="btn btn-primary" disabled={saving || !!formError}>{saving ? 'Saving…' : created ? 'Save seed' : 'Add login'}</button>
  {/snippet}
</Modal>

<style>
  .form {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
  }
  .form .field + .field {
    margin-top: 0;
  }
  .plain {
    border: 0;
    margin: 0;
    padding: 0;
    min-width: 0;
  }
  .row2 {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: var(--space-3);
  }
  .row4 {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: var(--space-2);
  }
  @media (max-width: 560px) {
    .row2,
    .row4 {
      grid-template-columns: minmax(0, 1fr);
    }
  }
</style>
