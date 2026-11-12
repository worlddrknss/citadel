<!-- Workload client detail: configuration and copy-paste usage. -->
<script lang="ts">
  import Drawer from '$lib/components/Drawer.svelte';
  import Badge from '$lib/components/Badge.svelte';
  import CopyButton from '$lib/components/CopyButton.svelte';
  import Icon from '$lib/components/Icon.svelte';
  import Seg from './Seg.svelte';
  import { usage, ttlLabel, fmtDateTime, type IssuerInfo, type WorkloadClient } from './api';

  let {
    open = $bindable(false),
    client,
    info,
    canEdit,
    onclose,
    onedit,
    ondelete,
    onaudit
  }: {
    open?: boolean;
    client: WorkloadClient | null;
    info: IssuerInfo | null;
    canEdit: boolean;
    onclose: () => void;
    onedit: (c: WorkloadClient) => void;
    ondelete: (c: WorkloadClient) => void;
    onaudit: (c: WorkloadClient) => void;
  } = $props();

  const origin = typeof location !== 'undefined' ? location.origin : '';
  const examples = $derived(client ? usage(client, info, origin) : []);
  let ex = $state('curl');
  const current = $derived(examples.find((e) => e.id === ex) ?? examples[0]);
</script>

<Drawer bind:open title={client?.name ?? ''} subtitle={client?.clientId} width={620} {onclose}>
  {#snippet actions()}
    {#if client}<CopyButton value={client.clientId} label="Copy client ID" />{/if}
  {/snippet}
  {#if client}
    <div class="wrap">
      <div class="badges">
        <Badge tone="info" dot={false}>{client.auth.method === 'access-key' ? 'Access key' : 'Kubernetes'}</Badge>
        <span class="badge outline">TTL {ttlLabel(client.tokenTtlSeconds)}</span>
      </div>
      <dl class="kv">
        <dt>Audiences</dt>
        <dd><span class="chips">{#each client.audiences as a (a)}<span class="badge mono">{a}</span>{/each}</span></dd>
        <dt>Subject</dt>
        <dd class="mono">{client.subjectFormat}</dd>
        {#if client.auth.method === 'k8s-token-review'}
          <dt>API server</dt>
          <dd class="mono">{client.auth.apiServer}</dd>
          <dt>Service accounts</dt>
          <dd><span class="chips">{#each client.auth.serviceAccounts as s (s)}<span class="badge mono">{s}</span>{/each}</span></dd>
          <dt>Review audience</dt>
          <dd class="mono">{client.auth.reviewAudience}</dd>
          <dt>Cluster CA</dt>
          <dd>{client.auth.caPem ? 'Custom CA' : 'System trust store'}</dd>
        {:else}
          <dt>Allowed users</dt>
          <dd><span class="chips">{#each client.auth.allowedUsers as u (u)}<span class="badge mono">{u}</span>{/each}</span></dd>
        {/if}
        <dt>Last token</dt>
        <dd>{client.lastIssuedAt ? fmtDateTime(client.lastIssuedAt) : 'Never'} <button type="button" class="row-link small" onclick={() => onaudit(client)}>View history</button></dd>
        <dt>Updated</dt>
        <dd>{fmtDateTime(client.updatedAt)}</dd>
      </dl>

      <section class="box" aria-labelledby="use-title">
        <div class="box-head">
          <h3 id="use-title"><Icon name="command" size={14} />Get a token</h3>
          <Seg label="Example" bind:value={ex} options={examples.map((e) => ({ value: e.id, label: e.label }))} />
        </div>
        {#if current}
          <div class="snip">
            <pre class="code">{current.code}</pre>
            <span class="copy"><CopyButton value={current.code} label="Copy example" /></span>
          </div>
        {/if}
        <p class="subtle small note">
          Tokens are JWTs signed with {info?.signingKey?.algorithm ?? 'the active key'} and verifiable with the issuer's JWKS. Claims: <code>iss</code>, <code>sub</code>, <code>aud</code>, <code>iat</code>, <code>nbf</code>, <code>exp</code>, <code>jti</code>, and a <code>citadel</code> object with <code>account</code>, <code>client_id</code>, <code>auth_method</code> and the workload's attributes.
        </p>
      </section>
    </div>
    {#if canEdit}
      <div class="foot">
        <button type="button" class="btn btn-secondary btn-sm" onclick={() => onedit(client)}><Icon name="edit" size={14} />Edit</button>
        <button type="button" class="btn btn-danger-ghost btn-sm end" onclick={() => ondelete(client)}><Icon name="trash" size={14} />Delete client</button>
      </div>
    {/if}
  {/if}
</Drawer>

<style>
  .wrap {
    display: flex;
    flex-direction: column;
    gap: var(--space-5);
    padding-bottom: var(--space-4);
  }
  .badges,
  .chips {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
  }
  .chips .badge {
    font-size: 11.5px;
  }
  .badge.outline {
    background: transparent;
    color: var(--text-muted);
    box-shadow: inset 0 0 0 1px var(--border-strong);
  }
  .kv {
    grid-template-columns: 130px minmax(0, 1fr);
  }
  .box {
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    overflow: hidden;
  }
  .box-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 8px;
    padding: 8px 12px;
    background: var(--surface-hover);
    border-bottom: 1px solid var(--border);
  }
  .box-head h3 {
    display: flex;
    align-items: center;
    gap: 8px;
    margin: 0;
    font-size: var(--text-base);
    font-weight: 600;
  }
  .snip {
    position: relative;
  }
  .code {
    margin: 12px;
    padding-right: 44px;
    font-size: 12px;
    white-space: pre;
  }
  .copy {
    position: absolute;
    top: 18px;
    right: 18px;
  }
  .note {
    margin: 0 12px 12px;
  }
  .foot {
    position: sticky;
    bottom: calc(-1 * var(--space-5));
    margin: 0 calc(-1 * var(--space-5)) calc(-1 * var(--space-5));
    display: flex;
    gap: 8px;
    padding: 12px var(--space-5);
    border-top: 1px solid var(--border);
    background: var(--surface-hover);
  }
  .end {
    margin-left: auto;
  }
  @media (max-width: 820px) {
    .kv {
      grid-template-columns: minmax(0, 1fr);
    }
  }
</style>
