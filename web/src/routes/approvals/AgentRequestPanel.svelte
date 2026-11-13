<!--
  An agent access request in the Approvals inbox: who asks, for what, why
  (the agent's own words, shown as plain text), whether it has a grant, and
  the decision. Approve and Deny open the shared AccessDecisionModal.
-->
<script lang="ts">
  import { base } from '#lib/paths.ts';
  import Icon from '#lib/components/Icon.svelte';
  import Badge from '#lib/components/Badge.svelte';
  import { session } from '#lib/stores/session.svelte.ts';
  import { fullTime, initials, relTime } from '../time';
  import AccessDecisionModal from '../agents/AccessDecisionModal.svelte';
  import { ACCESS_STATUS, KIND_LABELS, SCOPE_LABELS, formatDuration, timeLeft, type AccessRequest } from '../agents/api';

  let { request, ondecided }: { request: AccessRequest; ondecided: () => void } = $props();

  const me = $derived(session.me);
  let mode = $state<'approve' | 'deny'>('approve');
  let decideOpen = $state(false);
  function decide(m: 'approve' | 'deny') {
    mode = m;
    decideOpen = true;
  }
  const st = $derived(ACCESS_STATUS[request.status] ?? ACCESS_STATUS.pending);
  const pending = $derived(request.status === 'pending');
</script>

<div class="card card-flush pad-lg stack" data-testid="agent-request">
  <div class="d-head">
    <div class="d-tags">
      <span class="mono subtle">{request.requestId}</span>
      <Badge tone={st.tone} dot={false}>{st.label}</Badge>
      <span class="badge mini">Agent access</span>
    </div>
    <h2 id="cr-title">{request.agentName || request.agentId} asks to {request.actions.join(' and ')} <span class="mono">{request.credential}</span></h2>
    <p class="muted who">
      <span class="avatar" aria-hidden="true"><Icon name="bot" size={13} /></span>
      <span>
        <a href="{base}/agents/{request.agentId}">{request.agentName || request.agentId}</a>
        (owner {request.agentOwner === me?.username ? 'you' : request.agentOwner}) ·
        {request.origin === 'policy' ? 'its grant needs approval for each use' : 'it asked for access'} ·
        <time datetime={request.createdAt} title={fullTime(request.createdAt)}>{relTime(request.createdAt)}</time>
      </span>
    </p>
  </div>

  <dl class="kv">
    <dt>Credential</dt>
    <dd><span class="mono">{request.credential}</span>{#if request.credentialKind}<span class="subtle"> · {KIND_LABELS[request.credentialKind]}</span>{:else}<span class="subtle"> · no credential has this name</span>{/if}</dd>
    <dt>Actions</dt>
    <dd>
      <span class="chips">
        {#each request.actions as a (a)}
          {#if a === 'reveal'}<Badge tone="danger" dot={false}><Icon name="eye" size={12} />reveal</Badge>{:else}<span class="badge">{a}</span>{/if}
        {/each}
      </span>
    </dd>
    <dt>Reason</dt>
    <dd class="reason">{request.reason || (request.origin === 'policy' ? 'Used a credential whose grant requires approval.' : '—')}</dd>
    {#if request.taskId}
      <dt>Task</dt>
      <dd class="mono">{request.taskId}</dd>
    {/if}
    {#if request.durationSeconds}
      <dt>Asked for</dt>
      <dd>{formatDuration(request.durationSeconds)}</dd>
    {/if}
    <dt>Grant</dt>
    <dd>
      {#if request.grant}
        {request.grant.actions.join(', ')}{request.grant.requiresApproval ? ' · needs approval' : ''}{request.grant.leaseTtlSeconds ? ` · leases up to ${formatDuration(request.grant.leaseTtlSeconds)}` : ''}
      {:else}
        <span class="warn"><Icon name="alert-triangle" size={14} />No grant: approving gives access the agent was never granted.</span>
      {/if}
    </dd>
    {#if pending}
      <dt>Expires</dt>
      <dd><time datetime={request.expiresAt} title={fullTime(request.expiresAt)}>{timeLeft(request.expiresAt)}</time> if nobody decides</dd>
    {/if}
  </dl>

  {#if !pending && request.decidedBy}
    <div class="cmt">
      <span class="avatar" aria-hidden="true">{initials(request.decidedBy)}</span>
      <div class="cmt-body">
        <span><strong>{request.decidedBy === me?.username ? 'You' : request.decidedBy}</strong> <span class="subtle small">{st.label.toLowerCase()}{request.scope ? ` · ${SCOPE_LABELS[request.scope].toLowerCase()}` : ''}{request.decidedAt ? ` · ${relTime(request.decidedAt)}` : ''}</span></span>
        {#if request.decisionComment}<p>{request.decisionComment}</p>{/if}
      </div>
    </div>
  {/if}

  {#if pending}
    {#if request.canDecide}
      <div class="actions">
        <button type="button" class="btn btn-primary" onclick={() => decide('approve')}><Icon name="check" />Approve…</button>
        <button type="button" class="btn btn-danger-ghost" onclick={() => decide('deny')}><Icon name="x" />Deny…</button>
        {#if request.mfaRequired}<span class="field-hint push"><Icon name="lock" size={12} />Approving asks for an MFA code.</span>{/if}
      </div>
    {:else}
      <p class="subtle small lock" data-testid="cannot-approve"><Icon name="lock" size={14} />{request.cannotDecideReason || "You can't decide this request."}</p>
    {/if}
  {/if}
</div>

<AccessDecisionModal bind:open={decideOpen} {request} {mode} ondone={ondecided} />

<style>
  .pad-lg {
    padding: 20px;
  }
  .stack {
    display: flex;
    flex-direction: column;
    gap: 14px;
  }
  .d-head {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .d-tags {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 8px;
  }
  .d-head h2 {
    margin: 0;
    font: 600 22px/28px var(--font-display);
    letter-spacing: -0.01em;
    overflow-wrap: anywhere;
  }
  .who {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 8px;
    margin: 0;
  }
  .avatar {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    flex: none;
    width: 24px;
    height: 24px;
    border-radius: 50%;
    background: var(--accent-soft);
    color: var(--accent-text);
    font-size: 11px;
    font-weight: 600;
  }
  .mini {
    height: 20px;
    font-size: 12px;
  }
  .kv {
    grid-template-columns: 120px minmax(0, 1fr);
  }
  .reason {
    white-space: pre-wrap;
    overflow-wrap: anywhere;
  }
  .chips {
    display: inline-flex;
    flex-wrap: wrap;
    gap: 4px;
    align-items: center;
  }
  .warn {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    color: var(--warning);
  }
  .cmt {
    display: flex;
    gap: 10px;
  }
  .cmt-body {
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .cmt-body p {
    margin: 0;
    white-space: pre-wrap;
  }
  .actions {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 8px;
  }
  .push {
    margin-left: auto;
    display: inline-flex;
    align-items: center;
    gap: 4px;
  }
  .lock {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    margin: 0;
  }
  @media (max-width: 720px) {
    .kv {
      grid-template-columns: minmax(0, 1fr);
    }
  }
</style>
