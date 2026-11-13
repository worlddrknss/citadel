<!-- A notification channel's delivery log: every event queued for it, its
     attempts and outcome. Polls while deliveries are still pending. -->
<script lang="ts">
  import Drawer from '#lib/components/Drawer.svelte';
  import Badge from '#lib/components/Badge.svelte';
  import EmptyState from '#lib/components/EmptyState.svelte';
  import Icon from '#lib/components/Icon.svelte';
  import { errorMessage } from '#lib/api.ts';
  import { toast } from '#lib/stores/toast.svelte.ts';
  import { fullTime, relTime } from '../time';
  import { deliveryState, notificationsApi, typeLabel, channelTarget, type NotificationChannel, type NotificationDelivery } from './notifications';

  let { open = $bindable(false), channel }: { open?: boolean; channel: NotificationChannel | null } = $props();

  let rows = $state<NotificationDelivery[]>([]);
  let loading = $state(false);
  let error = $state('');
  let testing = $state(false);
  let expanded = $state<number | null>(null);

  async function load(quiet = false) {
    if (!channel) return;
    if (!quiet) loading = true;
    try {
      rows = (await notificationsApi.deliveries(channel.id)).deliveries ?? [];
      error = '';
    } catch (e) {
      error = errorMessage(e, 'Could not load the delivery log.');
    } finally {
      loading = false;
    }
  }

  $effect(() => {
    if (open && channel) {
      rows = [];
      expanded = null;
      void load();
    }
  });

  // Refresh every few seconds while something is still in flight.
  const pending = $derived(rows.some((r) => r.status === 'pending'));
  $effect(() => {
    if (!open || !pending) return;
    const t = setInterval(() => void load(true), 3000);
    return () => clearInterval(t);
  });

  async function sendTest() {
    if (!channel) return;
    testing = true;
    try {
      await notificationsApi.test(channel.id);
      toast.success('Test notification queued');
      await load(true);
    } catch (e) {
      toast.error(e, 'Could not send a test');
    } finally {
      testing = false;
    }
  }

  async function retry(d: NotificationDelivery) {
    try {
      await notificationsApi.retry(d.id);
      toast.success('Delivery queued again');
      await load(true);
    } catch (e) {
      toast.error(e, 'Could not retry the delivery');
    }
  }
</script>

<Drawer bind:open title={channel ? `${channel.name} deliveries` : 'Deliveries'} subtitle={channel ? `${typeLabel(channel.type)} · ${channelTarget(channel)}` : undefined} width={640}>
  {#snippet actions()}
    <button type="button" class="btn btn-ghost btn-sm" onclick={() => load()} disabled={loading}><Icon name="refresh" size={14} />Refresh</button>
    <button type="button" class="btn btn-secondary btn-sm" onclick={sendTest} disabled={testing}><Icon name="bell" size={14} />{testing ? 'Sending…' : 'Send test'}</button>
  {/snippet}
  {#if error}
    <div class="callout callout-danger" role="alert"><Icon name="alert-circle" size={16} /><span>{error}</span></div>
  {:else if loading && rows.length === 0}
    <div class="stack-sm" aria-busy="true">
      {#each Array(3) as _, i (i)}<span class="skeleton" style:height="44px"></span>{/each}
    </div>
  {:else if rows.length === 0}
    <EmptyState icon="bell" title="No deliveries yet" description="Events this channel subscribes to appear here as they are sent. Send a test to check the channel works." />
  {:else}
    <ul class="log" aria-label="Deliveries">
      {#each rows as d (d.id)}
        {@const st = deliveryState(d)}
        <li class="entry">
          <div class="row">
            <span class="what">
              <span class="mono strong">{d.eventType}</span>
              <span class="subtle small" title={fullTime(d.createdAt)}>{relTime(d.createdAt)}</span>
            </span>
            <Badge tone={st.tone}>{st.label}</Badge>
          </div>
          <div class="meta subtle small">
            <span>{d.attempts} attempt{d.attempts === 1 ? '' : 's'}</span>
            {#if d.statusCode}<span>HTTP {d.statusCode}</span>{/if}
            {#if d.deliveredAt}<span title={fullTime(d.deliveredAt)}>delivered {relTime(d.deliveredAt)}</span>{/if}
            {#if d.status === 'pending' && d.attempts > 0 && d.nextAttemptAt}<span title={fullTime(d.nextAttemptAt)}>next try at {new Date(d.nextAttemptAt).toLocaleTimeString()}</span>{/if}
            <span class="mono">{d.eventId}</span>
          </div>
          {#if d.lastError && d.status !== 'delivered'}
            <p class="err small">{d.lastError}</p>
          {/if}
          <div class="acts">
            <button type="button" class="btn btn-ghost btn-sm" aria-expanded={expanded === d.id} onclick={() => (expanded = expanded === d.id ? null : d.id)}>
              {expanded === d.id ? 'Hide payload' : 'Show payload'}
            </button>
            {#if d.status === 'dead'}
              <button type="button" class="btn btn-secondary btn-sm" onclick={() => retry(d)}><Icon name="rotate" size={14} />Retry</button>
            {/if}
          </div>
          {#if expanded === d.id}
            <pre class="payload mono">{JSON.stringify(d.data, null, 2)}</pre>
          {/if}
        </li>
      {/each}
    </ul>
  {/if}
</Drawer>

<style>
  .stack-sm {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  .log {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  .entry {
    padding: 10px 12px;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
  }
  .row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
  }
  .what {
    display: flex;
    align-items: baseline;
    gap: 8px;
    min-width: 0;
  }
  .strong {
    font-weight: 500;
  }
  .meta {
    display: flex;
    flex-wrap: wrap;
    gap: 4px 12px;
    margin-top: 4px;
  }
  .err {
    margin: 6px 0 0;
    color: var(--danger);
    overflow-wrap: anywhere;
  }
  .acts {
    display: flex;
    gap: 6px;
    margin-top: 6px;
  }
  .payload {
    margin: 6px 0 0;
    padding: 8px 10px;
    max-height: 240px;
    overflow: auto;
    font-size: 12.5px;
    background: var(--surface-sunken);
    border-radius: var(--radius-sm);
    white-space: pre-wrap;
    overflow-wrap: anywhere;
  }
</style>
