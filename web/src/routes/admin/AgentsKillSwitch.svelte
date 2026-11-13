<!--
  Account-wide agent kill switch: while on, every AI agent request in the
  current account is refused. Each agent's own status is kept.
-->
<script lang="ts">
  import { onMount } from 'svelte';
  import { base } from '#lib/paths.ts';
  import Badge from '#lib/components/Badge.svelte';
  import Icon from '#lib/components/Icon.svelte';
  import { errorMessage } from '#lib/api.ts';
  import { confirm } from '#lib/stores/confirm.svelte.ts';
  import { toast } from '#lib/stores/toast.svelte.ts';
  import { relTime } from '../time';
  import { agentsApi, type AgentSettings } from '../agents/api';

  let settings = $state<AgentSettings | null>(null);
  let loadError = $state('');
  let reason = $state('');
  let busy = $state(false);

  async function load() {
    loadError = '';
    try {
      settings = await agentsApi.settings();
    } catch (e) {
      loadError = errorMessage(e, 'Could not load the agent kill switch.');
    }
  }
  onMount(load);

  async function suspendAll() {
    const ok = await confirm({
      title: 'Suspend every agent in this account?',
      message: 'All agent requests are refused immediately, whatever their grants. Agents keep their own status, so turning this off restores things as they were.',
      confirmLabel: 'Suspend all agents',
      danger: true
    });
    if (!ok) return;
    busy = true;
    try {
      settings = await agentsApi.saveSettings(true, reason.trim());
      reason = '';
      toast.success('All agents suspended');
    } catch (e) {
      toast.error(e, 'Could not suspend agents');
    } finally {
      busy = false;
    }
  }

  async function resumeAll() {
    busy = true;
    try {
      settings = await agentsApi.saveSettings(false);
      toast.success('Agents resumed');
    } catch (e) {
      toast.error(e, 'Could not resume agents');
    } finally {
      busy = false;
    }
  }
</script>

<section class="card" aria-labelledby="ks-title">
  <div class="card-head">
    <div>
      <h2 id="ks-title">AI agents</h2>
      <p class="subtle small sub">Kill switch for every <a href="{base}/agents">agent</a> in this account.</p>
    </div>
    {#if settings}
      {#if settings.agentsSuspended}<Badge tone="danger">All suspended</Badge>{:else}<Badge tone="success">Running</Badge>{/if}
    {/if}
  </div>
  <div class="card-pad">
    {#if loadError}
      <div class="callout callout-danger" role="alert"><Icon name="alert-circle" size={16} /><span>{loadError}</span><button type="button" class="btn btn-ghost btn-sm push" onclick={load}>Retry</button></div>
    {:else if !settings}
      <div class="sk" aria-busy="true"><span class="skeleton"></span><span class="skeleton"></span></div>
    {:else if settings.agentsSuspended}
      <div class="callout callout-danger" role="status">
        <Icon name="alert-triangle" size={16} />
        <span>
          Every agent request is refused{settings.suspendedBy ? `. Switched on by ${settings.suspendedBy}` : ''}{settings.suspendedAt ? `, ${relTime(settings.suspendedAt)}` : ''}.
          {#if settings.reason}Reason: {settings.reason}{/if}
        </span>
      </div>
      <div class="btns"><button type="button" class="btn btn-primary btn-sm" onclick={resumeAll} disabled={busy}><Icon name="play" size={14} />Resume all agents</button></div>
    {:else}
      <p class="muted small first">Use this in an incident: it stops every agent at once without touching their tokens or grants.</p>
      <div class="row">
        <div class="field grow">
          <label class="field-label" for="ks-reason">Reason <span class="subtle">(optional, audited)</span></label>
          <input id="ks-reason" class="input" bind:value={reason} maxlength="256" placeholder="Suspected prompt injection" />
        </div>
        <button type="button" class="btn btn-danger btn-sm" onclick={suspendAll} disabled={busy}><Icon name="x-circle" size={14} />Suspend all agents</button>
      </div>
    {/if}
  </div>
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
  .first {
    margin: 0 0 var(--space-3);
  }
  .row {
    display: flex;
    align-items: flex-end;
    gap: var(--space-3);
    flex-wrap: wrap;
  }
  .grow {
    flex: 1 1 240px;
    margin: 0;
  }
  .btns {
    margin-top: var(--space-3);
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
</style>
