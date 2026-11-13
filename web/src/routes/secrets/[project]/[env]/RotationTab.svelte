<!--
  The secret drawer's Rotation tab: state of the built-in rotator (or a
  Lambda schedule, which Citadel records but can't run), its settings
  (rotator type with per-type options, schedule and window), rotate now,
  turning it off, and the history of attempts.
-->
<script lang="ts">
  import { onDestroy, untrack } from 'svelte';
  import Badge from '#lib/components/Badge.svelte';
  import Icon from '#lib/components/Icon.svelte';
  import { errorMessage } from '#lib/api.ts';
  import { confirm } from '#lib/stores/confirm.svelte.ts';
  import { toast } from '#lib/stores/toast.svelte.ts';
  import OnceSecret from '../../../account/OnceSecret.svelte';
  import { fullDate, relTime } from '../../lib';
  import {
    ROTATOR_LABELS,
    STEP_LABELS,
    defaultForm,
    formFromStatus,
    requestFromForm,
    rotationApi,
    scheduleLabel,
    statusBadge,
    validateForm,
    type Coord,
    type RotationForm,
    type RotationStatus,
    type RotatorType
  } from '../../rotation';

  let {
    coord,
    canEdit,
    deleted,
    requireApproval,
    onchanged
  }: {
    coord: Coord;
    canEdit: boolean;
    deleted: boolean;
    requireApproval: boolean;
    onchanged: () => void;
  } = $props();

  let status = $state<RotationStatus | null>(null);
  let loading = $state(true);
  let error = $state('');
  let busy = $state(false);
  let editing = $state(false);
  let form = $state<RotationForm>(defaultForm());
  let rotateAfterSave = $state(false);
  let signingSecret = $state('');
  let signingOpen = $state(false);
  let poll: ReturnType<typeof setTimeout> | undefined;
  const uid = Math.random().toString(36).slice(2, 8);

  const formError = $derived(validateForm(form));
  const badge = $derived(status ? statusBadge(status) : null);
  const builtin = $derived(status?.mode === 'builtin');
  const editable = $derived(canEdit && !deleted && !requireApproval);

  async function load(quiet = false) {
    if (!quiet) loading = true;
    error = '';
    try {
      const s = await rotationApi.status(coord);
      status = s;
      if (!editing) form = formFromStatus(s);
      if (s.status === 'running') schedulePoll();
    } catch (e) {
      error = errorMessage(e);
    } finally {
      loading = false;
    }
  }

  function schedulePoll(tries = 30) {
    clearTimeout(poll);
    if (tries <= 0) return;
    poll = setTimeout(async () => {
      const before = status?.history.length ?? 0;
      await load(true);
      if (status && (status.status === 'running' || status.history.length === before)) schedulePoll(tries - 1);
      else onchanged();
    }, 1000);
  }
  onDestroy(() => clearTimeout(poll));

  $effect(() => {
    void coord.project;
    void coord.env;
    void coord.path;
    void coord.key;
    untrack(() => {
      editing = false;
      status = null;
      load();
    });
  });

  function startEdit() {
    form = formFromStatus(status);
    rotateAfterSave = !builtin;
    editing = true;
  }

  async function save(e: SubmitEvent) {
    e.preventDefault();
    if (busy || formError) return;
    busy = true;
    try {
      const res = await rotationApi.configure(requestFromForm(coord, form, rotateAfterSave));
      toast.success(res.versionId ? 'Saved rotation and started a rotation' : 'Saved rotation');
      editing = false;
      if (res.signingSecret) {
        signingSecret = res.signingSecret;
        signingOpen = true;
      }
      await load(true);
      if (res.versionId) schedulePoll();
      onchanged();
    } catch (err) {
      toast.error(err, 'Could not save rotation');
    } finally {
      busy = false;
    }
  }

  async function rotateNow() {
    if (busy) return;
    const ok = await confirm({
      title: `Rotate ${coord.key} now?`,
      message: 'Runs the rotator once: a new value is created as AWSPENDING, set and tested, then becomes AWSCURRENT. The old value stays as AWSPREVIOUS.',
      confirmLabel: 'Rotate now'
    });
    if (!ok) return;
    busy = true;
    try {
      await rotationApi.rotateNow(coord);
      toast.success(`Rotation started for ${coord.key}`);
      await load(true);
      schedulePoll();
    } catch (e) {
      toast.error(e, 'Could not start rotation');
    } finally {
      busy = false;
    }
  }

  async function turnOff() {
    const ok = await confirm({
      title: `Turn off rotation for ${coord.key}?`,
      message: 'The value stops rotating on a schedule. The current value is kept, and so is the rotator configuration.',
      confirmLabel: 'Turn off rotation',
      danger: true
    });
    if (!ok) return;
    busy = true;
    try {
      await rotationApi.turnOff(coord);
      toast.success('Rotation turned off');
      editing = false;
      await load(true);
      onchanged();
    } catch (e) {
      toast.error(e, 'Could not turn off rotation');
    } finally {
      busy = false;
    }
  }

  async function regenerate() {
    const ok = await confirm({
      title: 'Replace the signing secret?',
      message: 'The webhook must be updated with the new secret before the next rotation; requests signed with the old one stop being sent.',
      confirmLabel: 'Replace secret'
    });
    if (!ok) return;
    busy = true;
    try {
      signingSecret = (await rotationApi.regenerateSigningSecret(coord)).signingSecret;
      signingOpen = true;
    } catch (e) {
      toast.error(e, 'Could not replace the signing secret');
    } finally {
      busy = false;
    }
  }

  const types: RotatorType[] = ['random', 'postgresql', 'webhook'];
  const typeHints: Record<RotatorType, string> = {
    random: 'Generates a new random value (or one field of a JSON secret). Nothing outside Citadel is changed.',
    postgresql: "Changes a database user's password. The secret is JSON: engine, host, port, username, password, dbname.",
    webhook: 'POSTs each step, signed with HMAC-SHA256, to your https endpoint, which rotates the value anywhere.'
  };
</script>

{#if loading && !status}
  <div class="skel" aria-busy="true" aria-label="Loading rotation">
    <span class="skeleton"></span><span class="skeleton"></span><span class="skeleton short"></span>
  </div>
{:else if error || !status}
  <div class="callout callout-danger" role="alert">
    <Icon name="alert-circle" size={16} />
    <span class="grow">{error || 'Could not load rotation.'}</span>
    <button type="button" class="btn btn-ghost btn-sm" onclick={() => load()}>Retry</button>
  </div>
{:else}
  <div class="rot">
    <div class="state">
      <span class="label">Automatic rotation</span>
      <span class="line">
        {#if badge}<Badge tone={badge.tone}>{badge.text}</Badge>{/if}
        {#if status.enabled}<span class="muted">{scheduleLabel(status.schedule)}</span>{/if}
      </span>
    </div>

    {#if status.mode === 'lambda'}
      <div class="callout callout-info" role="note">
        <Icon name="info" size={16} />
        <span>
          This schedule names a Lambda function, which can't run in Citadel, so the value only changes when someone rotates it.
          Choose a built-in rotator to rotate automatically.
        </span>
      </div>
    {/if}

    {#if status.enabled && (status.status === 'retrying' || status.status === 'failed') && status.lastError}
      <div class="callout callout-danger" role="alert">
        <Icon name="alert-triangle" size={16} />
        <div class="grow col">
          <strong>Rotation failed at {STEP_LABELS[status.lastStep ?? ''] ?? status.lastStep}.</strong>
          <span class="mono small">{status.lastError}</span>
          <span class="small">
            {status.status === 'retrying' ? `Attempt ${status.attempts ?? 1} of 5.` : 'Retries are used up.'}
            {#if status.nextAttemptAt}Next attempt {relTime(status.nextAttemptAt)}.{/if}
            The new value is kept as AWSPENDING, so the retry continues where it stopped.
          </span>
        </div>
      </div>
    {/if}

    <dl class="kv">
      <dt>Rotator</dt>
      <dd>
        {#if status.rotator}
          {ROTATOR_LABELS[status.rotator.type]}
          {#if status.rotator.configSecret}<span class="subtle small"> · config from <span class="mono">{status.rotator.configSecret}</span></span>{/if}
          {#if status.rotator.type === 'webhook' && status.rotator.config?.url}<span class="mono subtle small url">{status.rotator.config.url}</span>{/if}
        {:else if status.mode === 'lambda'}
          <span class="mono small">{status.lambdaArn?.split(':').pop()}</span>
        {:else}<span class="subtle">None</span>{/if}
      </dd>
      <dt>Last rotated</dt>
      <dd>{status.lastRotatedDate ? fullDate(status.lastRotatedDate) : 'Never'}</dd>
      <dt>Next rotation</dt>
      <dd>
        {#if status.enabled && status.nextRotationDate}
          {fullDate(status.nextRotationDate)}{#if status.windowEnd}<span class="subtle small"> – {fullDate(status.windowEnd)}</span>{/if}
        {:else}—{/if}
      </dd>
      {#if status.pendingVersionId}
        <dt>Pending</dt>
        <dd><span class="mono small" title={status.pendingVersionId}>{status.pendingVersionId.slice(0, 13)}…</span> <span class="subtle small">AWSPENDING</span></dd>
      {/if}
    </dl>

    {#if canEdit && requireApproval && !deleted}
      <p class="subtle small note"><Icon name="lock" size={12} />Built-in rotation is off where changes need approval: a rotator would change values without review.</p>
    {/if}

    {#if editable && !editing}
      <div class="btns">
        <button type="button" class="btn btn-primary btn-sm" onclick={startEdit} disabled={busy}>
          <Icon name={builtin ? 'edit' : 'rotate'} size={14} />{builtin ? 'Edit rotation' : 'Set up rotation'}
        </button>
        {#if builtin && status.enabled}
          <button type="button" class="btn btn-secondary btn-sm" onclick={rotateNow} disabled={busy || status.status === 'running'}>Rotate now</button>
        {/if}
        {#if builtin && status.rotator?.type === 'webhook' && !status.rotator.configSecret && status.enabled}
          <button type="button" class="btn btn-ghost btn-sm" onclick={regenerate} disabled={busy}>Replace signing secret</button>
        {/if}
        {#if status.enabled}
          <button type="button" class="btn btn-danger-ghost btn-sm end" onclick={turnOff} disabled={busy}>Turn off</button>
        {/if}
      </div>
    {/if}

    {#if editing}
      <form class="inline-form" onsubmit={save} aria-label="Rotation settings">
        <fieldset class="types">
          <legend class="field-label">Rotator</legend>
          <div class="seg" role="radiogroup" aria-label="Rotator">
            {#each types as t (t)}
              <label class="seg-opt" class:on={form.type === t}>
                <input type="radio" name="rt-{uid}" value={t} bind:group={form.type} />{ROTATOR_LABELS[t]}
              </label>
            {/each}
          </div>
          <span class="field-hint">{typeHints[form.type]}</span>
        </fieldset>

        {#if form.type === 'webhook'}
          <label class="field">
            <span class="field-label">Webhook URL</span>
            <input class="input mono" bind:value={form.url} placeholder="https://rotate.example.com/hooks/citadel" spellcheck="false" />
            <span class="field-hint">Each step is POSTed with X-Citadel-Timestamp and X-Citadel-Signature (v1=HMAC-SHA256 of "timestamp.body"). Loopback, link-local and metadata addresses are refused, and redirects aren't followed.</span>
          </label>
        {:else}
          <div class="row2">
            <label class="field">
              <span class="field-label">Password length</span>
              <input class="input num" type="number" min="8" max="4096" bind:value={form.length} />
            </label>
            <label class="field">
              <span class="field-label">Exclude characters</span>
              <input class="input mono" bind:value={form.excludeCharacters} spellcheck="false" placeholder="none" />
            </label>
          </div>
          <label class="check">
            <input type="checkbox" bind:checked={form.excludePunctuation} />
            <span>Letters and digits only</span>
          </label>
        {/if}

        {#if form.type === 'random'}
          <label class="field">
            <span class="field-label">JSON field (optional)</span>
            <input class="input mono" bind:value={form.jsonKey} placeholder="password" spellcheck="false" />
            <span class="field-hint">Rotate one field of a JSON secret and keep the rest. Leave empty to replace the whole value.</span>
          </label>
        {/if}

        {#if form.type === 'postgresql'}
          <label class="field">
            <span class="field-label">Strategy</span>
            <select class="input" bind:value={form.strategy}>
              <option value="">Automatic (alternating when an admin secret is known)</option>
              <option value="single-user">Single user: the user changes its own password</option>
              <option value="alternating-users">Alternating users: an admin switches between user and user_clone</option>
            </select>
          </label>
          {#if form.strategy !== 'single-user'}
            <label class="field">
              <span class="field-label">Admin secret ARN</span>
              <input class="input mono" bind:value={form.adminSecretArn} placeholder="arn:aws:secretsmanager:…:secret:db/admin" spellcheck="false" />
              <span class="field-hint">Same account. Leave empty to use the secret's own masterarn field.</span>
            </label>
          {/if}
        {/if}

        <div class="row2">
          <label class="field">
            <span class="field-label">Schedule</span>
            <select class="input" bind:value={form.scheduleKind}>
              <option value="days">Every N days</option>
              <option value="hours">Every N hours</option>
              <option value="cron">On a cron schedule</option>
            </select>
          </label>
          {#if form.scheduleKind === 'days'}
            <label class="field">
              <span class="field-label">Rotate every (days)</span>
              <input class="input num" type="number" min="1" max="1000" bind:value={form.days} />
            </label>
          {:else if form.scheduleKind === 'hours'}
            <label class="field">
              <span class="field-label">Rotate every (hours)</span>
              <input class="input num" type="number" min="4" max="23" bind:value={form.hours} />
            </label>
          {/if}
        </div>
        {#if form.scheduleKind === 'cron'}
          <label class="field">
            <span class="field-label">Cron expression</span>
            <input class="input mono" bind:value={form.cron} spellcheck="false" />
            <span class="field-hint">AWS syntax, UTC: cron(Minutes Hours Day-of-month Month Day-of-week Year), with ? in one day field.</span>
          </label>
        {/if}
        <label class="field">
          <span class="field-label">Window (hours)</span>
          <input class="input num" type="number" min="0" max="24" bind:value={form.windowHours} aria-describedby="win-{uid}" />
          <span id="win-{uid}" class="field-hint">0 uses AWS's default: the rest of the UTC day, or one hour for hourly schedules. Rotation starts when the window opens.</span>
        </label>
        <label class="check">
          <input type="checkbox" bind:checked={rotateAfterSave} />
          <span>Rotate once now as well</span>
        </label>
        {#if formError}<span class="field-error" role="alert">{formError}</span>{/if}
        <div class="actions">
          <button type="button" class="btn btn-ghost btn-sm" onclick={() => (editing = false)}>Cancel</button>
          <button type="submit" class="btn btn-primary btn-sm" disabled={busy || !!formError}>Save rotation</button>
        </div>
      </form>
    {/if}

    <div class="hist">
      <span class="label">Rotation history</span>
      {#if status.history.length === 0}
        <p class="subtle small">No rotations yet.</p>
      {:else}
        <ol class="timeline">
          {#each status.history as h, i (h.startedAt + h.versionId + i)}
            <li>
              <span class="rail" aria-hidden="true"><span class="dot" class:ok={h.status === 'succeeded'} class:bad={h.status === 'failed'}></span><span class="line-v"></span></span>
              <div class="entry">
                <span class="entry-top">
                  <span>{fullDate(h.finishedAt)}</span>
                  <Badge tone={h.status === 'succeeded' ? 'success' : 'danger'} dot={false}>{h.status === 'succeeded' ? 'Rotated' : `Failed at ${STEP_LABELS[h.step] ?? h.step}`}</Badge>
                  <Badge tone="neutral" dot={false}>{h.trigger === 'schedule' ? 'Scheduled' : h.trigger === 'retry' ? 'Retry' : 'On demand'}</Badge>
                </span>
                <span class="mono subtle small" title={h.versionId}>{h.versionId.slice(0, 13)}…</span>
                {#if h.error}<span class="mono small err">{h.error}</span>{/if}
              </div>
            </li>
          {/each}
        </ol>
      {/if}
    </div>
  </div>
{/if}

{#if signingSecret}
  <OnceSecret
    bind:open={signingOpen}
    title="Webhook signing secret"
    description="Configure your webhook with this secret to verify X-Citadel-Signature. It is shown only once."
    fields={[{ label: 'Signing secret', value: signingSecret, secret: true }]}
    ondone={() => (signingSecret = '')}
  />
{/if}

<style>
  .skel {
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
  }
  .skel .skeleton {
    height: 14px;
    width: 80%;
  }
  .skel .short {
    width: 40%;
  }
  .grow {
    flex: 1;
  }
  .col {
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .rot {
    display: flex;
    flex-direction: column;
    gap: var(--space-5);
  }
  .label {
    font: 600 var(--text-xs) / 16px var(--font-sans);
    letter-spacing: 0.06em;
    text-transform: uppercase;
    color: var(--text-subtle);
  }
  .state {
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
  }
  .line {
    display: inline-flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--space-2);
  }
  .kv {
    grid-template-columns: 120px minmax(0, 1fr);
    align-items: baseline;
    gap: 10px var(--space-4);
  }
  .url {
    display: block;
    overflow-wrap: anywhere;
  }
  .note {
    display: flex;
    align-items: center;
    gap: 6px;
    margin: 0;
  }
  .btns {
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-2);
  }
  .end {
    margin-left: auto;
  }
  .inline-form {
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
    padding: var(--space-3);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: var(--surface-hover);
  }
  .types {
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
    margin: 0;
    padding: 0;
    border: 0;
    min-width: 0;
  }
  .seg {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
    padding: 3px;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: var(--surface);
  }
  .seg-opt {
    flex: 1 1 auto;
    display: inline-flex;
    justify-content: center;
    align-items: center;
    padding: 5px 10px;
    border-radius: calc(var(--radius-md) - 2px);
    font-size: var(--text-sm);
    color: var(--text-muted);
    cursor: pointer;
    white-space: nowrap;
  }
  .seg-opt input {
    position: absolute;
    opacity: 0;
    pointer-events: none;
  }
  .seg-opt.on {
    background: var(--accent-soft);
    color: var(--text);
    font-weight: 600;
  }
  .seg-opt:has(input:focus-visible) {
    outline: 2px solid var(--focus-ring);
    outline-offset: 1px;
  }
  .row2 {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: var(--space-3);
  }
  .num {
    width: 100%;
  }
  .check {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    font-size: var(--text-sm);
    cursor: pointer;
  }
  .actions {
    display: flex;
    justify-content: flex-end;
    gap: var(--space-2);
  }
  .hist {
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
  }
  .hist p {
    margin: 0;
  }
  .timeline {
    list-style: none;
    margin: 0;
    padding: 0;
  }
  .timeline li {
    display: grid;
    grid-template-columns: 16px minmax(0, 1fr);
    gap: var(--space-3);
  }
  .rail {
    display: flex;
    flex-direction: column;
    align-items: center;
  }
  .dot {
    width: 10px;
    height: 10px;
    margin-top: 5px;
    border-radius: 50%;
    background: var(--surface-pressed);
    border: 2px solid var(--surface);
    box-shadow: 0 0 0 1px var(--border-strong);
  }
  .dot.ok {
    background: var(--accent);
  }
  .dot.bad {
    background: var(--danger);
  }
  .line-v {
    flex: 1;
    width: 1px;
    background: var(--border);
  }
  .timeline li:last-child .line-v {
    display: none;
  }
  .entry {
    display: flex;
    flex-direction: column;
    gap: 2px;
    padding-bottom: 14px;
    min-width: 0;
  }
  .entry-top {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--space-2);
  }
  .err {
    overflow-wrap: anywhere;
    color: var(--danger);
  }
  @media (max-width: 720px) {
    .kv {
      grid-template-columns: minmax(0, 1fr);
      gap: 2px 0;
    }
    .row2 {
      grid-template-columns: minmax(0, 1fr);
    }
  }
</style>
