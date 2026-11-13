<!--
  Audit log retention for the current account: the deployment default, keep
  forever, or a number of days. Shows the log's size and a live preview of
  what a new retention would prune before it is saved. Platform admins also
  see the audit table's size on disk and the last retention run.
-->
<script lang="ts">
  import { onMount } from 'svelte';
  import Badge from '#lib/components/Badge.svelte';
  import Icon from '#lib/components/Icon.svelte';
  import { errorMessage } from '#lib/api.ts';
  import { base } from '#lib/paths.ts';
  import { confirm } from '#lib/stores/confirm.svelte.ts';
  import { session } from '#lib/stores/session.svelte.ts';
  import { toast } from '#lib/stores/toast.svelte.ts';
  import { fullTime, relTime } from '../time';
  import { anchorNote, auditApi, formatBytes, retentionLabel, type Retention, type RetentionPreview } from '../audit/api';

  type Mode = 'default' | 'forever' | 'days';

  let saved = $state<Retention | null>(null);
  let loadError = $state('');
  let mode = $state<Mode>('default');
  let days = $state(90);
  let saving = $state(false);
  let preview = $state<RetentionPreview | null>(null);
  let previewState = $state<'idle' | 'loading' | 'error'>('idle');

  function reset(r: Retention) {
    saved = r;
    if (r.accountDays == null) mode = 'default';
    else if (r.accountDays === 0) mode = 'forever';
    else {
      mode = 'days';
      days = r.accountDays;
    }
  }

  async function load() {
    loadError = '';
    try {
      reset(await auditApi.retention());
    } catch (e) {
      loadError = errorMessage(e, 'Could not load the audit retention.');
    }
  }
  onMount(load);

  const minDays = $derived(saved?.minDays ?? 7);
  const maxDays = $derived(saved?.maxDays ?? 3650);
  const daysError = $derived(
    mode === 'days' && (!Number.isInteger(days) || days < minDays || days > maxDays) ? `Between ${minDays} and ${maxDays.toLocaleString()} days.` : ''
  );
  /** The value to save: null = deployment default. */
  const chosen = $derived<number | null>(mode === 'default' ? null : mode === 'forever' ? 0 : days);
  /** The retention that would be in force. */
  const effective = $derived(chosen ?? saved?.deploymentDays ?? 0);
  const dirty = $derived(!!saved && chosen !== saved.accountDays);

  // Preview what the retention in the form would prune, debounced.
  let timer: ReturnType<typeof setTimeout> | undefined;
  let seq = 0;
  $effect(() => {
    const d = effective;
    const valid = !daysError && !!saved;
    clearTimeout(timer);
    if (!valid || d <= 0) {
      preview = null;
      previewState = 'idle';
      return;
    }
    previewState = 'loading';
    const mine = ++seq;
    timer = setTimeout(async () => {
      try {
        const p = await auditApi.previewRetention(d);
        if (mine === seq) {
          preview = p;
          previewState = 'idle';
        }
      } catch {
        if (mine === seq) previewState = 'error';
      }
    }, 300);
    return () => clearTimeout(timer);
  });

  async function save(e: SubmitEvent) {
    e.preventDefault();
    if (!saved || daysError || !dirty) return;
    const prunes = preview && effective > 0 ? preview.prunableEvents : 0;
    if (prunes > 0) {
      const ok = await confirm({
        title: `Delete ${prunes.toLocaleString()} audit ${prunes === 1 ? 'event' : 'events'}?`,
        message: `Events older than ${retentionLabel(effective).toLowerCase()} are permanently deleted within the hour, oldest first. The chain stays verifiable from a signed anchor, but the deleted events can't be recovered. Export or stream them first if you need a copy.`,
        confirmLabel: 'Save and prune',
        danger: true
      });
      if (!ok) return;
    }
    saving = true;
    try {
      reset(await auditApi.saveRetention(chosen));
      toast.success(`Audit retention: ${retentionLabel(saved?.retentionDays ?? 0).toLowerCase()}`);
    } catch (err) {
      toast.error(err, 'Could not save the audit retention');
    } finally {
      saving = false;
    }
  }
</script>

<section class="card" aria-labelledby="ret-title">
  <div class="card-head">
    <div>
      <h2 id="ret-title">Audit log retention</h2>
      <p class="subtle small sub">
        How long this account keeps audit events.
        {#if saved?.updatedAt}Last changed {relTime(saved.updatedAt)}{saved.updatedBy ? ` by ${saved.updatedBy}` : ''}.{/if}
      </p>
    </div>
    {#if saved}
      <Badge tone={saved.retentionDays > 0 ? 'info' : 'neutral'} dot={false}>{retentionLabel(saved.retentionDays)}</Badge>
    {/if}
  </div>
  {#if loadError}
    <div class="card-pad"><div class="callout callout-danger" role="alert"><Icon name="alert-circle" size={16} /><span>{loadError}</span><button type="button" class="btn btn-ghost btn-sm push" onclick={load}>Retry</button></div></div>
  {:else if !saved}
    <div class="card-pad sk" aria-busy="true"><span class="skeleton"></span><span class="skeleton"></span><span class="skeleton"></span></div>
  {:else}
    <dl class="stats card-pad" data-testid="retention-stats">
      <div><dt>Events</dt><dd>{saved.events.toLocaleString()}</dd></div>
      <div><dt>Oldest event</dt><dd>{#if saved.oldestEvent}<time datetime={saved.oldestEvent} title={fullTime(saved.oldestEvent)}>{relTime(saved.oldestEvent)}</time>{:else}—{/if}</dd></div>
      {#if saved.storage}
        <div><dt>Audit table on disk</dt><dd title="All accounts, with indexes">{formatBytes(saved.storage.tableBytes)}</dd></div>
        <div><dt>Rows (estimate)</dt><dd title="All accounts">{saved.storage.tableRowsEstimate >= 0 ? saved.storage.tableRowsEstimate.toLocaleString() : '—'}</dd></div>
      {/if}
      {#if saved.anchor}
        <div><dt>Pruned so far</dt><dd>{saved.anchor.prunedEvents.toLocaleString()}</dd></div>
      {/if}
    </dl>
    {#if saved.anchor}
      <div class="card-pad tight"><div class="callout callout-info" role="note"><Icon name="clock" size={16} /><span>{anchorNote(saved.anchor, fullTime)}</span></div></div>
    {/if}
    {#if saved.lastRun}
      <p class="card-pad tight subtle small run" data-testid="retention-last-run">
        Last retention run (all accounts): {saved.lastRun.finishedAt ? relTime(saved.lastRun.finishedAt) : 'running'}, {saved.lastRun.prunedEvents.toLocaleString()} events pruned{#if saved.lastRun.error}. <span class="err-text">{saved.lastRun.error}</span>{/if}
      </p>
    {/if}

    <form onsubmit={save} novalidate>
      <div class="group">
        <div class="gtext">
          <h3>Keep events</h3>
          <p class="muted small">
            Older events are deleted by an hourly job, oldest first, in small batches. Verification continues from a signed anchor, so pruning doesn't break the
            chain. <a href="{base}/audit">Audit log</a>
          </p>
        </div>
        <div class="gbody">
          <fieldset class="choices">
            <legend class="sr-only">Retention</legend>
            <label class="radio">
              <input type="radio" name="ret-mode" value="default" bind:group={mode} />
              <span>Deployment default <span class="subtle">({retentionLabel(saved.deploymentDays).toLowerCase()})</span></span>
            </label>
            <label class="radio">
              <input type="radio" name="ret-mode" value="forever" bind:group={mode} />
              <span>Keep forever</span>
            </label>
            <label class="radio">
              <input type="radio" name="ret-mode" value="days" bind:group={mode} />
              <span>Delete events older than a number of days</span>
            </label>
          </fieldset>
          {#if mode === 'days'}
            <div class="field">
              <label class="field-label" for="ret-days">Days to keep</label>
              <input id="ret-days" class="input num" type="number" min={minDays} max={maxDays} bind:value={days} aria-invalid={!!daysError} />
              {#if daysError}<span class="field-error">{daysError}</span>{:else}<span class="field-hint">At least {minDays} days.</span>{/if}
            </div>
          {/if}
          <div class="preview" aria-live="polite" data-testid="retention-preview">
            {#if effective <= 0}
              <span class="subtle small">Nothing is deleted.</span>
            {:else if daysError}
              <span></span>
            {:else if previewState === 'loading' && !preview}
              <span class="subtle small">Counting…</span>
            {:else if previewState === 'error'}
              <span class="subtle small">Couldn't count the events this would delete.</span>
            {:else if preview}
              {#if preview.prunableEvents > 0}
                <span class="small"><strong>{preview.prunableEvents.toLocaleString()}</strong> of {preview.events.toLocaleString()} events are older than {retentionLabel(effective).toLowerCase()}{dirty ? ' and would be deleted within the hour' : ''}.</span>
              {:else}
                <span class="subtle small">No events are older than {retentionLabel(effective).toLowerCase()} yet.</span>
              {/if}
            {/if}
          </div>
          {#if saved.streamHeld}
            <p class="subtle small note"><Icon name="external-link" size={12} /> SIEM streaming is on: events are deleted only after they have been delivered.</p>
          {:else if effective > 0}
            <p class="subtle small note">Need a copy? Turn on <a href="{base}/audit">streaming to a SIEM</a> or export the log on a schedule first.</p>
          {/if}
        </div>
      </div>
      {#if session.can('admin')}
        <div class="foot">
          {#if dirty}<span class="subtle small">Unsaved changes</span>{/if}
          <button type="button" class="btn btn-ghost" disabled={!dirty || saving} onclick={() => saved && reset(saved)}>Discard</button>
          <button type="submit" class="btn btn-primary" disabled={!dirty || saving || !!daysError}>{saving ? 'Saving…' : 'Save retention'}</button>
        </div>
      {/if}
    </form>
  {/if}
</section>

<style>
  .card-head h2 {
    font-family: var(--font-sans);
    font-size: var(--text-md);
    letter-spacing: 0;
  }
  .sub {
    margin: 2px 0 0;
  }
  .push {
    margin-left: auto;
  }
  .sk {
    display: flex;
    flex-direction: column;
    gap: 10px;
  }
  .sk .skeleton {
    height: 14px;
  }
  .stats {
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-4) var(--space-6);
    margin: 0;
    border-bottom: 1px solid var(--border);
  }
  .stats dt {
    font-size: var(--text-xs);
    font-weight: 600;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    color: var(--text-subtle);
  }
  .stats dd {
    margin: 2px 0 0;
    font-size: var(--text-md);
    font-variant-numeric: tabular-nums;
  }
  .tight {
    padding-bottom: 0;
  }
  .run {
    margin: 0;
  }
  .err-text {
    color: var(--danger);
  }
  .group {
    display: grid;
    grid-template-columns: minmax(0, 1fr) minmax(0, 2fr);
    gap: var(--space-5);
    padding: var(--space-5);
    border-bottom: 1px solid var(--border);
  }
  @media (max-width: 820px) {
    .group {
      grid-template-columns: minmax(0, 1fr);
      gap: var(--space-3);
    }
  }
  .gtext h3 {
    margin: 0 0 4px;
    font-size: var(--text-base);
    font-weight: 600;
  }
  .gtext p {
    margin: 0;
  }
  .gbody {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
  }
  .choices {
    margin: 0;
    padding: 0;
    border: 0;
    display: flex;
    flex-direction: column;
    gap: 10px;
  }
  .radio {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    cursor: pointer;
  }
  .field {
    margin: 0;
  }
  .num {
    max-width: 140px;
  }
  .preview {
    min-height: 20px;
  }
  .note {
    margin: 0;
    display: inline-flex;
    align-items: center;
    gap: 6px;
    flex-wrap: wrap;
  }
  .foot {
    display: flex;
    align-items: center;
    justify-content: flex-end;
    gap: 8px;
    padding: 12px var(--space-5);
    background: var(--surface-hover);
    border-radius: 0 0 var(--radius-lg) var(--radius-lg);
  }
</style>
