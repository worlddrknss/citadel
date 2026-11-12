<!-- Grants on a key: list, create (modal) and revoke. -->
<script lang="ts">
  import Icon from '$lib/components/Icon.svelte';
  import Modal from '$lib/components/Modal.svelte';
  import CopyButton from '$lib/components/CopyButton.svelte';
  import { toast } from '$lib/stores/toast.svelte';
  import { confirm } from '$lib/stores/confirm.svelte';
  import { errorMessage } from '$lib/api';
  import { kms, grantOperations, fmtDate, type KeyDetail } from './api';

  let { detail, canEdit, onchanged }: { detail: KeyDetail; canEdit: boolean; onchanged: () => void } = $props();

  let open = $state(false);
  let grantee = $state('');
  let retiring = $state('');
  let name = $state('');
  let ops = $state<string[]>([]);
  let busy = $state(false);
  let formError = $state('');
  let token = $state<{ grantId: string; grantToken: string } | null>(null);

  const available = $derived(grantOperations(detail.keyUsage, detail.keySpec));

  function startCreate() {
    grantee = '';
    retiring = '';
    name = '';
    ops = detail.keyUsage === 'SIGN_VERIFY' ? ['Sign', 'Verify'] : ['Encrypt', 'Decrypt'];
    formError = '';
    token = null;
    open = true;
  }

  function toggleOp(op: string) {
    ops = ops.includes(op) ? ops.filter((o) => o !== op) : [...ops, op];
  }

  async function create(e: SubmitEvent) {
    e.preventDefault();
    if (busy) return;
    if (!grantee.trim()) {
      formError = 'Enter the principal that receives the grant.';
      return;
    }
    if (ops.length === 0) {
      formError = 'Pick at least one operation.';
      return;
    }
    busy = true;
    formError = '';
    try {
      token = await kms.createGrant({
        keyId: detail.keyId,
        granteePrincipal: grantee.trim(),
        operations: ops,
        retiringPrincipal: retiring.trim() || undefined,
        name: name.trim() || undefined
      });
      toast.success('Created grant');
      onchanged();
    } catch (err) {
      formError = errorMessage(err);
    } finally {
      busy = false;
    }
  }

  async function revoke(grantId: string, label: string) {
    const ok = await confirm({
      title: 'Revoke this grant?',
      message: `${label} loses the permissions this grant gave it on this key right away. This can't be undone; you'd have to create a new grant.`,
      confirmLabel: 'Revoke grant',
      danger: true
    });
    if (!ok) return;
    try {
      await kms.revokeGrant(detail.keyId, grantId);
      toast.success('Revoked grant');
      onchanged();
    } catch (e) {
      toast.error(e);
    }
  }
</script>

<div class="grants">
  <div class="bar">
    <p class="subtle small">Grants give a principal temporary use of this key without changing the key policy.</p>
    {#if canEdit}
      <button type="button" class="btn btn-secondary btn-sm" onclick={startCreate}><Icon name="plus" size={14} />Create grant</button>
    {/if}
  </div>

  {#if detail.grants.length === 0}
    <div class="none">
      <p class="muted">No grants on this key.</p>
    </div>
  {:else}
    <ul class="list">
      {#each detail.grants as g (g.grantId)}
        <li>
          <div class="row">
            <div class="who">
              <span class="mono strong">{g.granteePrincipal}</span>
              <span class="subtle small">{g.name ? `${g.name} · ` : ''}created {fmtDate(g.createdAt)}</span>
            </div>
            {#if canEdit}
              <button type="button" class="btn btn-danger-ghost btn-sm" onclick={() => revoke(g.grantId, g.granteePrincipal)}>Revoke</button>
            {/if}
          </div>
          <div class="ops">
            {#each g.operations as o (o)}<span class="chip mono">{o}</span>{/each}
          </div>
          <dl class="kv meta">
            <dt>Grant ID</dt>
            <dd class="mono">{g.grantId}</dd>
            {#if g.retiringPrincipal}
              <dt>Retiring principal</dt>
              <dd class="mono">{g.retiringPrincipal}</dd>
            {/if}
          </dl>
        </li>
      {/each}
    </ul>
  {/if}
</div>

<Modal bind:open title={token ? 'Grant created' : 'Create grant'} description={token ? undefined : 'Lets a principal use this key for the operations you pick.'}>
  {#if token}
    <div class="stack-sm">
      <div class="callout callout-warning" role="note">
        <Icon name="alert-triangle" size={16} />
        <span>Copy the grant token now if the grantee needs to use the grant before it propagates. It isn't shown again.</span>
      </div>
      <div class="field">
        <span class="field-label">Grant ID</span>
        <span class="tok"><code>{token.grantId}</code><CopyButton value={token.grantId} label="Copy grant ID" /></span>
      </div>
      <div class="field">
        <span class="field-label">Grant token</span>
        <span class="tok"><code class="wrap">{token.grantToken}</code><CopyButton value={token.grantToken} label="Copy grant token" clearAfter={60} /></span>
      </div>
    </div>
  {:else}
    <form id="grant-form" class="stack-sm" onsubmit={create}>
      <label class="field">
        <span class="field-label">Grantee principal</span>
        <input class="input mono" bind:value={grantee} placeholder="arn:aws:iam::123456789012:role/payments-api" autocomplete="off" spellcheck="false" />
        <span class="field-hint">A role or user ARN.</span>
      </label>
      <fieldset class="field">
        <legend class="field-label">Operations</legend>
        <div class="op-grid">
          {#each available as o (o)}
            <label class="check"><input type="checkbox" checked={ops.includes(o)} onchange={() => toggleOp(o)} /><span class="mono">{o}</span></label>
          {/each}
        </div>
      </fieldset>
      <label class="field">
        <span class="field-label">Retiring principal <span class="subtle opt">(optional)</span></span>
        <input class="input mono" bind:value={retiring} autocomplete="off" spellcheck="false" />
      </label>
      <label class="field">
        <span class="field-label">Name <span class="subtle opt">(optional)</span></span>
        <input class="input" bind:value={name} maxlength="256" autocomplete="off" />
      </label>
      {#if formError}<p class="field-error" role="alert">{formError}</p>{/if}
    </form>
  {/if}
  {#snippet footer()}
    {#if token}
      <button type="button" class="btn btn-primary" onclick={() => (open = false)}>Done</button>
    {:else}
      <button type="button" class="btn btn-ghost" onclick={() => (open = false)}>Cancel</button>
      <button type="submit" form="grant-form" class="btn btn-primary" disabled={busy}>{busy ? 'Creating…' : 'Create grant'}</button>
    {/if}
  {/snippet}
</Modal>

<style>
  .grants {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
  }
  .bar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--space-3);
    flex-wrap: wrap;
  }
  .bar p {
    margin: 0;
    flex: 1 1 200px;
  }
  .none {
    padding: var(--space-6) var(--space-4);
    border: 1px dashed var(--border-strong);
    border-radius: var(--radius-md);
    text-align: center;
  }
  .none p {
    margin: 0;
  }
  .list {
    list-style: none;
    margin: 0;
    padding: 0;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
  }
  .list > li {
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
    padding: var(--space-3);
    border-bottom: 1px solid var(--border);
  }
  .list > li:last-child {
    border-bottom: none;
  }
  .row {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: var(--space-2);
  }
  .who {
    display: flex;
    flex-direction: column;
    gap: 2px;
    min-width: 0;
  }
  .strong {
    font-weight: 500;
    overflow-wrap: anywhere;
  }
  .ops {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
  }
  .chip {
    display: inline-flex;
    align-items: center;
    height: 20px;
    padding: 0 6px;
    border-radius: 999px;
    box-shadow: inset 0 0 0 1px var(--border-strong);
    color: var(--text-muted);
    font-size: 11px;
  }
  .meta {
    font-size: var(--text-xs);
  }
  .stack-sm {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
  }
  .stack-sm .field + .field {
    margin-top: 0;
  }
  fieldset {
    margin: 0;
    padding: 0;
    border: 0;
  }
  .op-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
    gap: var(--space-2);
  }
  .check {
    display: inline-flex;
    align-items: center;
    gap: var(--space-2);
    font-size: var(--text-sm);
  }
  .opt {
    font-weight: 400;
  }
  .tok {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    min-width: 0;
  }
  .tok code {
    min-width: 0;
    overflow-wrap: anywhere;
  }
  .wrap {
    word-break: break-all;
  }
</style>
