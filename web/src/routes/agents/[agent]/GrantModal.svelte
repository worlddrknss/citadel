<!--
  Grant editor: which credential, which actions (reveal is flagged as risky
  and confirmed), validity dates, a time-of-day window and an hourly limit.
-->
<script lang="ts">
  import Modal from '#lib/components/Modal.svelte';
  import Icon from '#lib/components/Icon.svelte';
  import { errorMessage } from '#lib/api.ts';
  import { confirm } from '#lib/stores/confirm.svelte.ts';
  import { toast } from '#lib/stores/toast.svelte.ts';
  import { agentsApi, validateGrant, KIND_LABELS, WEEKDAYS, type AgentCredential, type AgentGrant, type GrantAction, type GrantInput } from '../api';

  let {
    open = $bindable(false),
    agentId,
    agentName,
    grant,
    credentials,
    onsaved
  }: {
    open?: boolean;
    agentId: string;
    agentName: string;
    /** The grant being edited; null for a new one. */
    grant: AgentGrant | null;
    credentials: AgentCredential[];
    onsaved: () => void;
  } = $props();

  let credential = $state('');
  let actions = $state<GrantAction[]>(['use']);
  let notBefore = $state('');
  let notAfter = $state('');
  let windowOn = $state(false);
  let start = $state('09:00');
  let end = $state('17:00');
  let days = $state<string[]>([]);
  let timezone = $state('');
  let maxUses = $state(0);
  let saving = $state(false);
  let saveError = $state('');
  const uid = Math.random().toString(36).slice(2, 8);

  const localTz = typeof Intl !== 'undefined' ? Intl.DateTimeFormat().resolvedOptions().timeZone : 'UTC';
  /** ISO -> value for <input type="datetime-local">. */
  const toLocal = (iso?: string) => {
    if (!iso) return '';
    const d = new Date(iso);
    const pad = (n: number) => String(n).padStart(2, '0');
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
  };
  const toISO = (v: string) => (v ? new Date(v).toISOString().replace(/\.\d{3}Z$/, 'Z') : undefined);

  $effect(() => {
    if (!open) return;
    credential = grant?.credential ?? credentials.find((c) => c.kind !== 'raw')?.name ?? credentials[0]?.name ?? '';
    actions = grant ? [...grant.actions] : ['use'];
    notBefore = toLocal(grant?.notBefore);
    notAfter = toLocal(grant?.notAfter);
    windowOn = !!grant?.window;
    start = grant?.window?.start || '09:00';
    end = grant?.window?.end || '17:00';
    days = grant?.window?.days ? [...grant.window.days] : [];
    timezone = grant?.window?.timezone || localTz;
    maxUses = grant?.maxUsesPerHour ?? 0;
    saveError = '';
  });

  const kind = $derived(credentials.find((c) => c.name === credential)?.kind);
  const input = $derived<GrantInput>({
    agentId,
    credential,
    actions,
    notBefore: toISO(notBefore),
    notAfter: toISO(notAfter),
    window: windowOn ? { start, end, days, timezone } : null,
    maxUsesPerHour: Number(maxUses) || 0
  });
  const formError = $derived(validateGrant(input, kind));

  function toggle(a: GrantAction, on: boolean) {
    actions = on ? [...new Set([...actions, a])] : actions.filter((x) => x !== a);
  }
  function toggleDay(d: string, on: boolean) {
    days = on ? [...days, d] : days.filter((x) => x !== d);
  }

  async function save(e: SubmitEvent) {
    e.preventDefault();
    if (saving || formError) return;
    if (actions.includes('reveal') && !grant?.actions.includes('reveal')) {
      const ok = await confirm({
        title: `Let ${agentName} reveal ${credential}?`,
        message: 'Reveal hands the secret value to the agent. A value in an agent\'s context can leak through prompt injection, logs or its output. Prefer "use", where Citadel injects the credential and the agent never sees it.',
        confirmLabel: 'Grant reveal',
        danger: true
      });
      if (!ok) return;
    }
    saving = true;
    saveError = '';
    try {
      await agentsApi.putGrant(input);
      toast.success(grant ? 'Grant updated' : `Granted ${credential}`);
      open = false;
      onsaved();
    } catch (err) {
      saveError = errorMessage(err, 'Could not save the grant.');
    } finally {
      saving = false;
    }
  }
</script>

<Modal bind:open title={grant ? `Edit grant: ${grant.credential}` : 'Grant a credential'} description="What {agentName} may do with the credential, and when." size="md">
  <form id="grant-form-{uid}" class="form" onsubmit={save} novalidate>
    {#if saveError}<div class="callout callout-danger" role="alert"><Icon name="alert-circle" size={16} /><span>{saveError}</span></div>{/if}
    <div class="field">
      <label class="field-label" for="gr-cred-{uid}">Credential</label>
      <select id="gr-cred-{uid}" class="select" bind:value={credential} disabled={!!grant}>
        {#each credentials as c (c.name)}
          <option value={c.name}>{c.name} · {KIND_LABELS[c.kind]}</option>
        {/each}
      </select>
      <span class="field-hint">Credentials are usage profiles on secrets: open a secret and use its Agent access tab to add one.</span>
    </div>

    <fieldset class="field plain">
      <legend class="field-label">Actions</legend>
      <label class="check">
        <input type="checkbox" checked={actions.includes('use')} onchange={(e) => toggle('use', e.currentTarget.checked)} />
        <span><strong>Use</strong> <span class="muted">Citadel injects the credential into requests the agent makes; the agent never sees it.</span></span>
      </label>
      <label class="check risky">
        <input type="checkbox" checked={actions.includes('reveal')} onchange={(e) => toggle('reveal', e.currentTarget.checked)} />
        <span>
          <strong>Reveal</strong> <span class="badge badge-danger">Risky</span>
          <span class="muted">Returns the value to the agent. Only for tools that can't work through Citadel.</span>
        </span>
      </label>
      {#if kind === 'login'}
        <label class="check">
          <input type="checkbox" checked={actions.includes('totp')} onchange={(e) => toggle('totp', e.currentTarget.checked)} />
          <span><strong>TOTP codes</strong> <span class="muted">Current one-time codes for the login, never the seed.</span></span>
        </label>
      {/if}
    </fieldset>

    <div class="row2">
      <div class="field">
        <label class="field-label" for="gr-nbf-{uid}">From <span class="subtle">(optional)</span></label>
        <input id="gr-nbf-{uid}" class="input" type="datetime-local" bind:value={notBefore} />
      </div>
      <div class="field">
        <label class="field-label" for="gr-naf-{uid}">Until <span class="subtle">(optional)</span></label>
        <input id="gr-naf-{uid}" class="input" type="datetime-local" bind:value={notAfter} />
      </div>
    </div>

    <label class="check">
      <input type="checkbox" bind:checked={windowOn} />
      <span><strong>Only at certain times</strong></span>
    </label>
    {#if windowOn}
      <div class="window">
        <div class="row3">
          <div class="field">
            <label class="field-label" for="gr-start-{uid}">From</label>
            <input id="gr-start-{uid}" class="input mono" type="time" bind:value={start} />
          </div>
          <div class="field">
            <label class="field-label" for="gr-end-{uid}">To</label>
            <input id="gr-end-{uid}" class="input mono" type="time" bind:value={end} />
          </div>
          <div class="field">
            <label class="field-label" for="gr-tz-{uid}">Time zone</label>
            <input id="gr-tz-{uid}" class="input" bind:value={timezone} placeholder="UTC" spellcheck="false" />
          </div>
        </div>
        <fieldset class="field plain">
          <legend class="field-label">Days <span class="subtle">(none = every day)</span></legend>
          <div class="days">
            {#each WEEKDAYS as d (d)}
              <label class="day" class:on={days.includes(d)}>
                <input type="checkbox" checked={days.includes(d)} onchange={(e) => toggleDay(d, e.currentTarget.checked)} />{d}
              </label>
            {/each}
          </div>
          <span class="field-hint">An end before the start runs past midnight.</span>
        </fieldset>
      </div>
    {/if}

    <div class="field">
      <label class="field-label" for="gr-max-{uid}">Uses per hour</label>
      <input id="gr-max-{uid}" class="input num" type="number" min="0" max="100000" bind:value={maxUses} />
      <span class="field-hint">0 means no limit. Counted across all replicas.</span>
    </div>
    {#if formError && credential}<span class="field-error" role="status">{formError}</span>{/if}
  </form>
  {#snippet footer()}
    <button type="button" class="btn btn-ghost" onclick={() => (open = false)}>Cancel</button>
    <button type="submit" form="grant-form-{uid}" class="btn btn-primary" disabled={saving || !!formError}>{saving ? 'Saving…' : grant ? 'Save grant' : 'Grant'}</button>
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
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
  }
  .check {
    display: flex;
    gap: 10px;
    align-items: flex-start;
    font-size: var(--text-base);
  }
  .check input {
    margin-top: 3px;
  }
  .check .muted {
    display: block;
    font-size: var(--text-sm);
  }
  .risky {
    padding: 8px 10px;
    border: 1px solid var(--danger);
    border-radius: var(--radius-md);
    background: var(--danger-soft);
  }
  .row2,
  .row3 {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: var(--space-3);
  }
  .row3 {
    grid-template-columns: repeat(3, minmax(0, 1fr));
  }
  .row2 .field + .field,
  .row3 .field + .field {
    margin-top: 0;
  }
  .window {
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
    padding-left: 26px;
  }
  .days {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
  }
  .day {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 4px 10px;
    border: 1px solid var(--border);
    border-radius: 999px;
    font-size: var(--text-sm);
    text-transform: capitalize;
    cursor: pointer;
  }
  .day.on {
    border-color: var(--accent);
    background: var(--accent-soft);
  }
  .day input {
    position: absolute;
    opacity: 0;
    width: 1px;
    height: 1px;
  }
  @media (max-width: 560px) {
    .row2,
    .row3 {
      grid-template-columns: minmax(0, 1fr);
    }
  }
</style>
