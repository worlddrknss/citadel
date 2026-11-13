<!--
  Approve or deny an agent's access request. Approving picks the lease's
  scope (once, for a time, or for the request's task) and length, capped by
  the server's maxDurationSeconds, and asks for an MFA code when the
  organization requires one. Denying needs a reason the agent will see.
  Used by the Approvals inbox and the agent's Requests tab.
-->
<script lang="ts">
  import Modal from '#lib/components/Modal.svelte';
  import Icon from '#lib/components/Icon.svelte';
  import { ApiError, errorMessage } from '#lib/api.ts';
  import { toast } from '#lib/stores/toast.svelte.ts';
  import {
    agentsApi,
    defaultApprovalSeconds,
    formatDuration,
    validateApproval,
    type AccessRequest,
    type ApproveInput,
    type LeaseScope
  } from './api';

  let {
    open = $bindable(false),
    request,
    mode,
    ondone
  }: {
    open?: boolean;
    request: AccessRequest | null;
    mode: 'approve' | 'deny';
    /** Called with the decided request after a successful decision. */
    ondone: (r: AccessRequest) => void;
  } = $props();

  const uid = Math.random().toString(36).slice(2, 8);
  let scope = $state<LeaseScope>('once');
  let minutes = $state(60);
  let comment = $state('');
  let mfaCode = $state('');
  let useRecovery = $state(false);
  let needMfa = $state(false);
  let saving = $state(false);
  let saveError = $state('');
  let mfaError = $state('');

  $effect(() => {
    if (!open || !request) return;
    scope = 'once';
    minutes = Math.max(1, Math.round(defaultApprovalSeconds(request) / 60));
    comment = mfaCode = saveError = mfaError = '';
    useRecovery = false;
    needMfa = !!request.mfaRequired;
  });

  const maxMinutes = $derived(request ? Math.floor(request.maxDurationSeconds / 60) : 0);
  const input = $derived<ApproveInput>({
    requestId: request?.requestId ?? '',
    scope,
    durationSeconds: Math.round(Number(minutes) * 60) || 0,
    comment: comment.trim() || undefined,
    ...(needMfa ? (useRecovery ? { recoveryCode: mfaCode.trim() } : { mfaCode: mfaCode.trim() }) : {})
  });
  const formError = $derived(
    !request ? '' : mode === 'deny' ? (comment.trim() ? '' : 'Say why, so the agent and its owner know.') : validateApproval(input, { ...request, mfaRequired: needMfa })
  );

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    if (!request || saving || formError) return;
    saving = true;
    saveError = mfaError = '';
    try {
      const res = mode === 'approve' ? await agentsApi.approveAccess(input) : await agentsApi.denyAccess(request.requestId, comment.trim());
      toast.success(mode === 'approve' ? `Approved ${request.agentName}'s access to ${request.credential}` : `Denied ${request.agentName}'s request`);
      open = false;
      ondone(res.request);
    } catch (err) {
      if (err instanceof ApiError && (err.code === 'mfa_required' || err.code === 'invalid_mfa_code')) {
        needMfa = true;
        mfaError = err.code === 'invalid_mfa_code' ? 'That code is not valid. Try the current one.' : err.message;
      } else {
        saveError = errorMessage(err, mode === 'approve' ? 'Could not approve the request.' : 'Could not deny the request.');
      }
    } finally {
      saving = false;
    }
  }
</script>

<Modal
  bind:open
  title={mode === 'approve' ? `Approve ${request?.agentName ?? 'agent'}'s request` : `Deny ${request?.agentName ?? 'agent'}'s request`}
  description={request ? `${request.actions.join(', ')} · ${request.credential}` : undefined}
  size="md"
>
  {#if request}
    <form id="decide-form-{uid}" class="form" onsubmit={submit} novalidate>
      {#if saveError}<div class="callout callout-danger" role="alert"><Icon name="alert-circle" size={16} /><span>{saveError}</span></div>{/if}
      {#if mode === 'approve'}
        {#if request.actions.includes('reveal')}
          <div class="callout callout-danger" role="note">
            <Icon name="eye" size={16} /><span>This hands the secret value to the agent. A value in an agent's context can leak through prompt injection, logs or its output.</span>
          </div>
        {/if}
        {#if !request.grant}
          <div class="callout callout-warning" role="note">
            <Icon name="alert-triangle" size={16} /><span>{request.agentName} has no grant for {request.credential}: approving gives access it was never granted.</span>
          </div>
        {/if}
        <fieldset class="field plain">
          <legend class="field-label">Allow</legend>
          <label class="check">
            <input type="radio" name="scope-{uid}" value="once" bind:group={scope} />
            <span><strong>Once</strong> <span class="muted">One use, then the agent has to ask again.</span></span>
          </label>
          <label class="check">
            <input type="radio" name="scope-{uid}" value="duration" bind:group={scope} />
            <span><strong>For a time</strong> <span class="muted">Every use until the lease expires.</span></span>
          </label>
          <label class="check" class:disabled={!request.taskId}>
            <input type="radio" name="scope-{uid}" value="task" bind:group={scope} disabled={!request.taskId} />
            <span>
              <strong>For this task</strong>
              <span class="muted">{request.taskId ? `Only requests from task ${request.taskId}, until the lease expires.` : 'The agent sent no task ID.'}</span>
            </span>
          </label>
        </fieldset>
        <div class="field">
          <label class="field-label" for="dc-min-{uid}">{scope === 'once' ? 'Usable within (minutes)' : 'Lease length (minutes)'}</label>
          <input id="dc-min-{uid}" class="input num" type="number" min="1" max={maxMinutes} bind:value={minutes} />
          <span class="field-hint">
            At most {formatDuration(request.maxDurationSeconds)}{request.grant?.leaseTtlSeconds ? " (the grant's lease length)" : ''}.{#if request.durationSeconds} The agent asked for {formatDuration(request.durationSeconds)}.{/if}
          </span>
        </div>
      {/if}
      <div class="field">
        <label class="field-label" for="dc-cmt-{uid}">{mode === 'deny' ? 'Reason' : 'Comment'} <span class="subtle">{mode === 'deny' ? '(the agent sees it)' : '(optional)'}</span></label>
        <textarea id="dc-cmt-{uid}" class="textarea" rows="3" maxlength="512" bind:value={comment}></textarea>
      </div>
      {#if mode === 'approve' && needMfa}
        <div class="field">
          <label class="field-label" for="dc-mfa-{uid}">{useRecovery ? 'Recovery code' : 'Authentication code'}</label>
          <input
            id="dc-mfa-{uid}"
            class="input mono"
            bind:value={mfaCode}
            autocomplete="one-time-code"
            inputmode={useRecovery ? 'text' : 'numeric'}
            aria-invalid={!!mfaError}
            aria-describedby={mfaError ? `dc-mfa-err-${uid}` : undefined}
          />
          {#if mfaError}<span class="field-error" id="dc-mfa-err-{uid}">{mfaError}</span>{/if}
          <span class="field-hint">Your organization requires a current code to approve agent access. <button type="button" class="linkbtn" onclick={() => (useRecovery = !useRecovery)}>{useRecovery ? 'Use an authenticator code' : 'Use a recovery code'}</button></span>
        </div>
      {/if}
      {#if formError && (mode === 'approve' || comment)}<span class="field-error" role="status">{formError}</span>{/if}
    </form>
  {/if}
  {#snippet footer()}
    <button type="button" class="btn btn-ghost" onclick={() => (open = false)}>Cancel</button>
    {#if mode === 'approve'}
      <button type="submit" form="decide-form-{uid}" class="btn btn-primary" disabled={saving || !!formError}><Icon name="check" size={16} />{saving ? 'Approving…' : 'Approve'}</button>
    {:else}
      <button type="submit" form="decide-form-{uid}" class="btn btn-danger" disabled={saving || !!formError}><Icon name="x" size={16} />{saving ? 'Denying…' : 'Deny'}</button>
    {/if}
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
  .check.disabled {
    opacity: 0.6;
  }
  .linkbtn {
    padding: 0;
    border: 0;
    background: none;
    color: var(--accent-text);
    font: inherit;
    cursor: pointer;
    text-decoration: underline;
  }
</style>
