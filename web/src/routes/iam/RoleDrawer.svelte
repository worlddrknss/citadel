<!-- Role detail: trust summary, the policy document, and copy-paste examples
     for assuming the role. -->
<script lang="ts">
  import Drawer from '$lib/components/Drawer.svelte';
  import Badge from '$lib/components/Badge.svelte';
  import CopyButton from '$lib/components/CopyButton.svelte';
  import Icon from '$lib/components/Icon.svelte';
  import type { Role } from '$lib/api';
  import Seg from './Seg.svelte';
  import { trustToJson, usage, sessionLabel, fmtDate } from './trust';

  let {
    open = $bindable(false),
    role,
    canEdit,
    onclose,
    onedit,
    ondelete
  }: {
    open?: boolean;
    role: Role | null;
    canEdit: boolean;
    onclose: () => void;
    onedit: (r: Role) => void;
    ondelete: (r: Role) => void;
  } = $props();

  const origin = typeof location !== 'undefined' ? location.origin : '';
  const examples = $derived(role ? usage(role, origin) : []);
  let ex = $state('cli');
  $effect(() => {
    if (examples.length && !examples.some((e) => e.id === ex)) ex = examples[0].id;
  });
  const current = $derived(examples.find((e) => e.id === ex) ?? examples[0]);
  const doc = $derived(role ? trustToJson(role.trust) : '');
</script>

<Drawer bind:open title={role?.roleName ?? ''} subtitle={role?.roleArn} width={600} {onclose}>
  {#snippet actions()}
    {#if role}<CopyButton value={role.roleArn} label="Copy role ARN" />{/if}
  {/snippet}
  {#if role}
    <div class="wrap">
      <div class="badges">
        <Badge tone="info" dot={false}>{role.trust.type === 'oidc' ? 'Web identity' : 'Account trust'}</Badge>
        <span class="badge outline">Max session {sessionLabel(role.maxSessionSeconds)}</span>
      </div>
      {#if role.description}<p class="muted">{role.description}</p>{/if}

      <dl class="kv">
        {#if role.trust.type === 'oidc'}
          <dt>Provider</dt>
          <dd class="mono">{role.trust.providerUrl}</dd>
          <dt>Audiences</dt>
          <dd><span class="chips">{#each role.trust.audiences ?? [] as a (a)}<span class="badge mono">{a}</span>{/each}</span></dd>
          <dt>Subjects</dt>
          <dd><span class="chips">{#each role.trust.subjects ?? [] as s (s)}<span class="badge mono">{s}</span>{/each}</span></dd>
        {:else}
          <dt>Accounts</dt>
          <dd><span class="chips">{#each role.trust.principals ?? [] as p (p)}<span class="badge mono">{p}</span>{/each}</span></dd>
        {/if}
        <dt>Created</dt>
        <dd>{fmtDate(role.createdAt)}</dd>
        <dt>Updated</dt>
        <dd>{fmtDate(role.updatedAt)}</dd>
      </dl>

      <section class="box" aria-labelledby="tp-title">
        <div class="box-head">
          <h3 id="tp-title">Trust policy</h3>
          <CopyButton value={doc} label="Copy trust policy" />
        </div>
        <!-- svelte-ignore a11y_no_noninteractive_tabindex (scrollable code must be keyboard-reachable) -->
        <pre class="code" tabindex="0" aria-label="Trust policy document">{doc}</pre>
      </section>

      <section class="box" aria-labelledby="use-title">
        <div class="box-head">
          <h3 id="use-title"><Icon name="command" size={14} />Use this role</h3>
          <Seg label="Example" bind:value={ex} options={examples.map((e) => ({ value: e.id, label: e.label }))} />
        </div>
        {#if current}
          <div class="snip">
            <!-- svelte-ignore a11y_no_noninteractive_tabindex (scrollable code must be keyboard-reachable) -->
            <pre class="code" tabindex="0" aria-label="{current.label} example">{current.code}</pre>
            <span class="copy"><CopyButton value={current.code} label="Copy example" /></span>
          </div>
        {/if}
        <p class="subtle small note">
          {#if role.trust.type === 'oidc'}
            Calls <code>AssumeRoleWithWebIdentity</code>, which needs no Citadel credentials: the OIDC token is the proof. The token's <code>aud</code> and <code>sub</code> must match the trust policy above.
          {:else}
            Calls <code>AssumeRole</code> signed with an access key from a trusted account.
          {/if}
        </p>
      </section>
    </div>
    {#if canEdit}
      <div class="foot">
        <button type="button" class="btn btn-secondary btn-sm" onclick={() => onedit(role)}><Icon name="edit" size={14} />Edit</button>
        <button type="button" class="btn btn-danger-ghost btn-sm end" onclick={() => ondelete(role)}><Icon name="trash" size={14} />Delete role</button>
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
  .wrap > p {
    margin: 0;
  }
  .badges,
  .chips {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
  }
  .badge.outline {
    background: transparent;
    color: var(--text-muted);
    box-shadow: inset 0 0 0 1px var(--border-strong);
  }
  .chips .badge {
    font-size: 12.5px;
  }
  .kv {
    grid-template-columns: 110px minmax(0, 1fr);
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
    gap: 8px;
    flex-wrap: wrap;
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
  .code {
    margin: 12px;
    font-size: 13px;
    white-space: pre;
  }
  .snip {
    position: relative;
  }
  .snip .code {
    padding-right: 44px;
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
