<!--
  Anomaly alerts for one agent (2.4). view="settings" (Overview tab): alerts
  and auto-suspend switches and what the baseline has learned.
  view="list" (Activity tab): the anomalies Citadel detected.
-->
<script lang="ts">
  import { untrack } from 'svelte';
  import Badge from '#lib/components/Badge.svelte';
  import Icon from '#lib/components/Icon.svelte';
  import { errorMessage } from '#lib/api.ts';
  import { toast } from '#lib/stores/toast.svelte.ts';
  import { fullTime, relTime } from '../../time';
  import { agentsApi, ANOMALY_LABELS, type AgentAnomalies } from '../api';

  let { agentId, view, manage }: { agentId: string; view: 'settings' | 'list'; manage: boolean } = $props();

  let data = $state<AgentAnomalies | null>(null);
  let error = $state('');
  let saving = $state(false);

  async function load() {
    error = '';
    try {
      data = await agentsApi.anomalies(agentId);
    } catch (e) {
      error = errorMessage(e, 'Could not load anomalies.');
    }
  }
  $effect(() => {
    void agentId;
    untrack(load);
  });

  async function save(change: { alertsEnabled?: boolean; autoSuspend?: boolean }) {
    if (!data) return;
    saving = true;
    try {
      data.settings = await agentsApi.saveAnomalySettings(agentId, { ...data.settings, ...change });
      toast.success('Anomaly settings saved');
    } catch (e) {
      toast.error(e, 'Could not save the settings');
    } finally {
      saving = false;
    }
  }

  const hours = $derived(
    data?.baseline.activeHours.length ? `${data.baseline.activeHours.map((h) => String(h).padStart(2, '0')).join(', ')} UTC` : 'none yet'
  );
</script>

{#if error}
  <div class="callout callout-danger" role="alert"><Icon name="alert-circle" size={16} /><span>{error}</span></div>
{:else if data && view === 'settings'}
  <div class="anomaly-settings">
    <span class="label">Anomaly alerts</span>
    <label class="check">
      <input type="checkbox" checked={data.settings.alertsEnabled} disabled={!manage || saving} onchange={(e) => save({ alertsEnabled: e.currentTarget.checked })} />
      <span>Send alerts <span class="subtle small block">Notify the channels subscribed to agent.anomaly on a new host, off-hours use, a rate spike or repeated denials.</span></span>
    </label>
    <label class="check">
      <input type="checkbox" checked={data.settings.autoSuspend} disabled={!manage || saving} onchange={(e) => save({ autoSuspend: e.currentTarget.checked })} />
      <span>Suspend automatically <span class="subtle small block">Suspend the agent when an anomaly is detected. Resume it once you've looked.</span></span>
    </label>
    <p class="small muted baseline">
      {#if data.baseline.established}
        Learned from {data.baseline.events} uses in the last {data.baseline.windowDays} days: {data.baseline.hosts.length} hosts, active hours {hours}, about {data.baseline.meanPerHour.toFixed(1)} uses an hour.
      {:else}
        Still learning ({data.baseline.events} uses so far). New-host and off-hours alerts start after 20 uses over more than two days; rate spikes and repeated denials are watched from the start.
      {/if}
    </p>
  </div>
{:else if data && view === 'list'}
  <section class="card anomalies" aria-label="Anomalies">
    <div class="head">
      <span class="label">Anomalies</span>
      <span class="small muted">{data.anomalies.length ? `${data.anomalies.length} detected` : 'None detected'}</span>
    </div>
    {#if data.anomalies.length}
      <ul>
        {#each data.anomalies as a (a.anomalyId)}
          <li>
            <Badge tone="warning" dot={false}>{ANOMALY_LABELS[a.kind] ?? a.kind}</Badge>
            <span class="small grow">{a.detail}</span>
            {#if a.suspended}<Badge tone="danger" dot={false}>Suspended</Badge>{/if}
            <span class="small subtle nowrap" title={fullTime(a.detectedAt)}>{relTime(a.detectedAt)}</span>
          </li>
        {/each}
      </ul>
    {/if}
  </section>
{/if}

<style>
  .anomaly-settings {
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
    margin-top: var(--space-4);
    padding-top: var(--space-4);
    border-top: 1px solid var(--border);
  }
  .check {
    display: flex;
    align-items: flex-start;
    gap: var(--space-2);
  }
  .block {
    display: block;
  }
  .baseline {
    margin: 0;
  }
  .anomalies {
    padding: var(--space-3) var(--space-4);
    margin-bottom: var(--space-4);
  }
  .head {
    display: flex;
    align-items: baseline;
    gap: var(--space-3);
  }
  ul {
    list-style: none;
    margin: var(--space-2) 0 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
  }
  li {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    flex-wrap: wrap;
  }
  .grow {
    flex: 1;
    min-width: 0;
  }
  .nowrap {
    white-space: nowrap;
  }
</style>
