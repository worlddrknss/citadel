<!-- Create a notification channel, or edit one's name, destination and events. -->
<script lang="ts">
  import { untrack } from 'svelte';
  import Modal from '#lib/components/Modal.svelte';
  import Icon from '#lib/components/Icon.svelte';
  import { errorMessage } from '#lib/api.ts';
  import { toast } from '#lib/stores/toast.svelte.ts';
  import {
    CHANNEL_TYPES,
    isHTTPSURL,
    isSlackURL,
    notificationsApi,
    parseRecipients,
    type ChannelInput,
    type ChannelType,
    type NotificationChannel,
    type NotificationEventType,
    type SavedChannel
  } from './notifications';

  let {
    open = $bindable(false),
    channel = null,
    events,
    emailAvailable,
    onsaved
  }: {
    open?: boolean;
    channel?: NotificationChannel | null;
    events: NotificationEventType[];
    emailAvailable: boolean;
    onsaved: (r: SavedChannel, created: boolean) => void;
  } = $props();

  let name = $state('');
  let type = $state<ChannelType>('webhook');
  let url = $state('');
  let recipients = $state('');
  let selected = $state<string[]>([]);
  let enabled = $state(true);
  let touched = $state(false);
  let busy = $state(false);
  let error = $state('');

  $effect(() => {
    if (open)
      untrack(() => {
        name = channel?.name ?? '';
        type = channel?.type ?? 'webhook';
        // A Slack URL is write-only: leave it blank to keep the saved one.
        url = channel?.type === 'webhook' ? (channel.url ?? '') : '';
        recipients = (channel?.recipients ?? []).join('\n');
        selected = channel ? [...channel.events] : subscribable.map((e) => e.type);
        enabled = channel?.enabled ?? true;
        touched = false;
        error = '';
      });
  });

  /** The test event is always delivered, so it isn't offered. */
  const subscribable = $derived(events.filter((e) => e.type !== 'test'));
  const keepSlackURL = $derived(!!channel && channel.type === 'slack' && !url.trim());

  const nameError = $derived(!name.trim() ? 'Give the channel a name.' : !/^[\p{L}\p{N} ._-]{1,64}$/u.test(name.trim()) ? "Use up to 64 letters, numbers, spaces, '.', '_' or '-'." : '');
  const targetError = $derived.by(() => {
    if (type === 'webhook') return isHTTPSURL(url) ? '' : 'Enter an https:// URL without credentials.';
    if (type === 'slack') return keepSlackURL || isSlackURL(url) ? '' : 'Paste the incoming webhook URL from Slack (https://hooks.slack.com/…).';
    const list = parseRecipients(recipients);
    if (!list.length) return 'Add at least one email address.';
    if (list.length > 20) return 'At most 20 recipients.';
    const bad = list.find((r) => !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(r));
    return bad ? `${bad} is not an email address.` : '';
  });

  function toggle(t: string, on: boolean) {
    selected = on ? [...selected.filter((s) => s !== t), t] : selected.filter((s) => s !== t);
  }

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    touched = true;
    if (nameError || targetError) return;
    busy = true;
    error = '';
    // Keep the catalog's order.
    const evs = subscribable.map((x) => x.type).filter((t) => selected.includes(t));
    try {
      let r: SavedChannel;
      if (channel) {
        const body: Partial<Omit<ChannelInput, 'type'>> = { name: name.trim(), enabled, events: evs };
        if (type === 'webhook' || (type === 'slack' && !keepSlackURL)) body.url = url.trim();
        if (type === 'email') body.recipients = parseRecipients(recipients);
        r = await notificationsApi.update(channel.id, body);
        toast.success(`Saved ${r.channel.name}`);
      } else {
        const body: ChannelInput = { name: name.trim(), type, enabled, events: evs };
        if (type === 'email') body.recipients = parseRecipients(recipients);
        else body.url = url.trim();
        r = await notificationsApi.create(body);
        toast.success(`Created ${r.channel.name}`);
      }
      open = false;
      onsaved(r, !channel);
    } catch (err) {
      error = errorMessage(err, 'Could not save the channel.');
    } finally {
      busy = false;
    }
  }
</script>

<Modal
  bind:open
  title={channel ? `Edit ${channel.name}` : 'Add notification channel'}
  description={channel ? undefined : 'Where Citadel tells you about agent approvals, suspensions, anomalies and kill-switch use.'}
  size="md"
>
  <form id="channel-form" class="form" onsubmit={submit} novalidate>
    <div class="field">
      <label class="field-label" for="ch-name">Name</label>
      <input id="ch-name" class="input" bind:value={name} autocomplete="off" placeholder="security-oncall" aria-invalid={touched && !!nameError} />
      {#if touched && nameError}<span class="field-error">{nameError}</span>{/if}
    </div>

    <fieldset class="field" disabled={!!channel}>
      <legend class="field-label">Type</legend>
      <div class="choices">
        {#each CHANNEL_TYPES as t (t.value)}
          {@const off = t.value === 'email' && !emailAvailable && channel?.type !== 'email'}
          <label class="choice" class:on={type === t.value} class:off>
            <input type="radio" name="ch-type" value={t.value} bind:group={type} disabled={off} />
            <span><span class="ctitle">{t.label}</span><span class="muted csub">{off ? 'Needs SMTP settings on the server (KMS_SMTP_HOST).' : t.hint}</span></span>
          </label>
        {/each}
      </div>
      {#if channel}<span class="field-hint">A channel's type can't change. Create another channel instead.</span>{/if}
    </fieldset>

    {#if type === 'webhook'}
      <div class="field">
        <label class="field-label" for="ch-url">Endpoint URL</label>
        <input id="ch-url" class="input mono" type="url" bind:value={url} placeholder="https://hooks.example.com/citadel" autocomplete="off" spellcheck="false" aria-invalid={touched && !!targetError} />
        {#if touched && targetError}<span class="field-error">{targetError}</span>{:else}<span class="field-hint">HTTPS only. Each request is signed with the channel's secret (X-Citadel-Signature).</span>{/if}
      </div>
    {:else if type === 'slack'}
      <div class="field">
        <label class="field-label" for="ch-url">Incoming webhook URL</label>
        <input
          id="ch-url"
          class="input mono"
          type="password"
          bind:value={url}
          placeholder={channel?.type === 'slack' ? 'Saved. Leave blank to keep it.' : 'https://hooks.slack.com/services/…'}
          autocomplete="off"
          spellcheck="false"
          aria-invalid={touched && !!targetError}
        />
        {#if touched && targetError}<span class="field-error">{targetError}</span>{:else}<span class="field-hint">The URL is a credential: Citadel stores it encrypted and never shows it again.</span>{/if}
      </div>
    {:else}
      <div class="field">
        <label class="field-label" for="ch-rcpt">Recipients</label>
        <textarea id="ch-rcpt" class="textarea mono" rows="3" bind:value={recipients} placeholder="security@example.com" spellcheck="false" aria-invalid={touched && !!targetError}></textarea>
        {#if touched && targetError}<span class="field-error">{targetError}</span>{:else}<span class="field-hint">One address per line, up to 20.</span>{/if}
      </div>
    {/if}

    <fieldset class="field">
      <legend class="field-label">Events</legend>
      <div class="events">
        {#each subscribable as ev (ev.type)}
          <label class="choice" class:on={selected.includes(ev.type)}>
            <input type="checkbox" checked={selected.includes(ev.type)} onchange={(e) => toggle(ev.type, e.currentTarget.checked)} />
            <span>
              <span class="ctitle">{ev.title}{#if ev.severity === 'critical'}<span class="sev">Critical</span>{/if}</span>
              <span class="muted csub">{ev.description}</span>
              <span class="mono subtle csub">{ev.type}</span>
            </span>
          </label>
        {/each}
      </div>
      <span class="field-hint">Test notifications are always delivered.</span>
    </fieldset>

    <label class="check">
      <input type="checkbox" bind:checked={enabled} />
      <span>Enabled</span>
    </label>

    {#if error}
      <div class="callout callout-danger" role="alert"><Icon name="alert-circle" size={16} /><span>{error}</span></div>
    {/if}
  </form>
  {#snippet footer()}
    <button type="button" class="btn btn-ghost" onclick={() => (open = false)}>Cancel</button>
    <button type="submit" form="channel-form" class="btn btn-primary" disabled={busy}>{busy ? 'Saving…' : channel ? 'Save changes' : 'Add channel'}</button>
  {/snippet}
</Modal>

<style>
  .form {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
  }
  .form :global(.field + .field) {
    margin-top: 0;
  }
  fieldset {
    margin: 0;
    padding: 0;
    border: 0;
  }
  legend {
    padding: 0;
    margin-bottom: 6px;
  }
  .choices {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 6px;
  }
  .events {
    display: grid;
    gap: 6px;
  }
  .choice {
    display: flex;
    gap: 10px;
    padding: 10px 12px;
    border: 1px solid var(--border-strong);
    border-radius: var(--radius-md);
    cursor: pointer;
  }
  .choice.on {
    border-color: var(--accent);
    background: var(--accent-soft);
  }
  .choice.off {
    cursor: not-allowed;
    opacity: 0.7;
  }
  .choice:focus-within {
    box-shadow: var(--focus-ring);
  }
  .choice input {
    margin-top: 2px;
  }
  .choice > span {
    display: flex;
    flex-direction: column;
    min-width: 0;
  }
  .ctitle {
    font-weight: 600;
  }
  .csub {
    font-size: 13px;
  }
  .sev {
    margin-left: 6px;
    font-size: 11px;
    font-weight: 600;
    color: var(--danger);
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }
  .check {
    display: flex;
    align-items: center;
    gap: 8px;
    font-weight: 500;
  }
  @media (max-width: 640px) {
    .choices {
      grid-template-columns: 1fr;
    }
  }
</style>
