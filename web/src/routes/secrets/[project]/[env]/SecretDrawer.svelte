<!--
  Secret detail panel from the board, shown beside the table (it wraps below
  on narrow screens). Tabs: Details (value, ARN, KMS key, rotation,
  description, tags, recent versions, who can read), Versions (full timeline
  with per-version values and restore), Access (principals + resource policy).
  It is an inline panel rather than the shared modal Drawer because the board
  keeps the table usable next to it.
-->
<script lang="ts" module>
  export type DrawerTab = 'details' | 'versions' | 'access';
</script>

<script lang="ts">
  import { tick, untrack } from 'svelte';
  import { base } from '$app/paths';
  import { api, type KMSKey } from '$lib/api';
  import CopyButton from '$lib/components/CopyButton.svelte';
  import Icon from '$lib/components/Icon.svelte';
  import SecretValue from '$lib/components/SecretValue.svelte';
  import Tabs from '$lib/components/Tabs.svelte';
  import { confirm } from '$lib/stores/confirm.svelte';
  import { toast } from '$lib/stores/toast.svelte';
  import { secretsApi, type SecretDetail } from '../../api';
  import { fullDate, shortDate } from '../../lib';
  import AccessList from './AccessList.svelte';
  import { findKms, kmsDisplay } from './kms';
  import MetadataForm from './MetadataForm.svelte';
  import PolicyEditor from './PolicyEditor.svelte';
  import RotationForm from './RotationForm.svelte';
  import TagEditor from './TagEditor.svelte';
  import VersionsTimeline, { numberVersions, type NumberedVersion } from './VersionsTimeline.svelte';


  let {
    project,
    env,
    path,
    secretKey,
    kmsKeys,
    requireApproval,
    minApprovals,
    canEdit,
    reloadToken,
    tab,
    ontab,
    onclose,
    onchanged,
    onedit,
    ondelete,
    onrestore
  }: {
    project: string;
    env: string;
    path: string;
    secretKey: string;
    kmsKeys: KMSKey[];
    requireApproval: boolean;
    minApprovals: number;
    canEdit: boolean;
    /** Bump to make the panel reload after a change made elsewhere. */
    reloadToken: number;
    tab: DrawerTab;
    ontab: (t: DrawerTab) => void;
    onclose: () => void;
    onchanged: () => void;
    onedit: (key: string) => void;
    ondelete: (key: string) => void;
    onrestore: (key: string) => void;
  } = $props();

  let detail = $state<SecretDetail | null>(null);
  let versions = $state<NumberedVersion[]>([]);
  let loading = $state(true);
  let error = $state('');
  let busy = $state(false);
  let editMeta = $state(false);
  let editRotation = $state(false);
  let editTags = $state(false);
  let heading = $state<HTMLHeadingElement>();
  let panel = $state<HTMLElement>();

  const crumb = $derived([project, env, ...path.split('/').filter(Boolean)].join(' / '));
  const deleted = $derived(!!detail?.deletionDate);
  const kmsKey = $derived(detail ? findKms(kmsKeys, detail.kmsKeyId) : undefined);
  const current = $derived(versions.find((v) => v.stages.includes('AWSCURRENT')));

  async function load(quiet = false) {
    if (!quiet) loading = true;
    error = '';
    const [d, vs] = await Promise.allSettled([
      secretsApi.detail(project, env, path, secretKey),
      secretsApi.versions(project, env, path, secretKey)
    ]);
    if (d.status === 'fulfilled') detail = d.value;
    else {
      detail = null;
      error = d.reason instanceof Error ? d.reason.message : 'Could not load this secret.';
    }
    versions = vs.status === 'fulfilled' ? numberVersions(vs.value) : [];
    loading = false;
  }

  // Reload when the selected secret changes or the page asks for it.
  $effect(() => {
    void project;
    void env;
    void path;
    void secretKey;
    void reloadToken;
    untrack(() => {
      editMeta = editRotation = editTags = false;
      load(!!detail && detail.key === secretKey);
    });
  });

  // Move focus to the panel when a different secret opens, and bring it into
  // view when it has wrapped below the table.
  $effect(() => {
    void secretKey;
    tick().then(() => {
      heading?.focus({ preventScroll: true });
      if (panel && window.matchMedia('(max-width: 1100px)').matches) panel.scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
  });

  async function refresh() {
    await load(true);
    onchanged();
  }

  async function rotateNow() {
    if (!detail) return;
    const ok = await confirm({
      title: `Rotate ${detail.key} now?`,
      message: `Runs the rotation Lambda once. It creates a new version and moves AWSCURRENT to it when the Lambda finishes.`,
      confirmLabel: 'Rotate now'
    });
    if (!ok || !detail.rotation.lambdaArn) return;
    busy = true;
    try {
      await api.configureRotation({
        project: detail.project,
        env: detail.env,
        path: detail.path,
        key: detail.key,
        lambdaArn: detail.rotation.lambdaArn,
        afterDays: detail.rotation.afterDays || 30,
        rotateImmediately: true
      });
      toast.success(`Rotation started for ${detail.key}`);
      await refresh();
    } catch (e) {
      toast.error(e, 'Could not start rotation');
    } finally {
      busy = false;
    }
  }

  async function restoreVersion(v: NumberedVersion) {
    if (!detail) return;
    const ok = await confirm({
      title: requireApproval ? `Request restore of v${v.ordinal}?` : `Make v${v.ordinal} current?`,
      message: requireApproval
        ? `Opens a change request that sets ${detail.key} back to the value of v${v.ordinal}. It applies once approved.`
        : `AWSCURRENT moves to v${v.ordinal}. Clients get its value on their next refresh; you can restore the current version the same way.`,
      confirmLabel: requireApproval ? 'Open change request' : 'Restore version'
    });
    if (!ok) return;
    busy = true;
    try {
      if (requireApproval) {
        const value = await secretsApi.revealVersion(project, env, path, secretKey, v.versionId);
        await api.createChangeRequest({ project, env, path, key: secretKey, value });
        toast.success(`Opened a change request to restore v${v.ordinal}`);
        onchanged();
      } else {
        await api.promoteVersion(project, env, path, secretKey, v.versionId);
        toast.success(`v${v.ordinal} is now current`);
        await refresh();
      }
    } catch (e) {
      toast.error(e, 'Could not restore that version');
    } finally {
      busy = false;
    }
  }

  function onkeydown(e: KeyboardEvent) {
    if (e.key === 'Escape' && !(e.target instanceof HTMLTextAreaElement) && !(e.target instanceof HTMLInputElement)) {
      e.preventDefault();
      onclose();
    }
  }

  const tabs = $derived([
    { id: 'details', label: 'Details' },
    { id: 'versions', label: 'Versions', count: versions.length || undefined },
    { id: 'access', label: 'Access' }
  ]);
  const coord = $derived({ project, env, path, key: secretKey });
</script>

<!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
<aside class="panel" aria-labelledby="dr-title" bind:this={panel} {onkeydown}>
  <header class="head">
    <div class="titles">
      <span class="mono subtle small">{crumb}</span>
      <h2 id="dr-title" class="mono" tabindex="-1" bind:this={heading}>{secretKey}</h2>
    </div>
    <CopyButton value={() => window.location.href} label="Copy link to this secret" />
    <button type="button" class="btn-icon" aria-label="Close details" title="Close" onclick={onclose}>
      <Icon name="x" size={16} />
    </button>
  </header>

  <div class="tabs-wrap">
    <Tabs {tabs} active={tab} label="Secret detail" onchange={(id) => ontab(id as DrawerTab)} />
  </div>

  <div class="body" role="tabpanel" aria-label={tab}>
    {#if loading && !detail}
      <div class="sk-stack" aria-busy="true" aria-label="Loading">
        <span class="skeleton sk" style:width="40%"></span>
        <span class="skeleton sk tall"></span>
        <span class="skeleton sk" style:width="80%"></span>
        <span class="skeleton sk" style:width="65%"></span>
        <span class="skeleton sk" style:width="72%"></span>
      </div>
    {:else if error || !detail}
      <div class="callout callout-danger" role="alert">
        <Icon name="alert-circle" size={16} />
        <div class="grow">
          <strong>Couldn't load {secretKey}.</strong>
          <span class="muted">{error}</span>
        </div>
        <button type="button" class="btn btn-secondary btn-sm" onclick={() => load()}>Retry</button>
      </div>
    {:else if tab === 'details'}
      {#if deleted}
        <div class="callout callout-warning">
          <Icon name="clock" size={16} />
          <div class="grow">
            <strong>Scheduled for deletion on {fullDate(detail.deletionDate)}.</strong>
            <span>Clients no longer receive it. Restore it to read or change the value.</span>
          </div>
          {#if canEdit}
            <button type="button" class="btn btn-secondary btn-sm" onclick={() => onrestore(secretKey)}>Restore</button>
          {/if}
        </div>
      {:else}
        <section class="sec">
          <span class="label">Current value</span>
          <div class="valbox">
            <SecretValue load={() => secretsApi.revealValue(project, env, path, secretKey)} hideAfter={30} />
          </div>
          <span class="field-hint">
            {#if detail.valueLength !== undefined}{detail.valueLength} characters{/if}
            {#if detail.fingerprint}{detail.valueLength !== undefined ? ' · ' : ''}fingerprint <span class="mono">{detail.fingerprint}</span>{/if}
            {#if detail.valueLength === undefined && !detail.fingerprint}Hidden until revealed. Every reveal is logged.{/if}
          </span>
        </section>
      {/if}

      <dl class="kv">
        <dt>ARN</dt>
        <dd class="arn"><span class="mono small">{detail.arn}</span><CopyButton value={detail.arn} label="Copy ARN" /></dd>
        <dt>Encrypted with</dt>
        <dd>
          <span class="row-between">
            {#if kmsKey}
              <a class="mono kms" href="{base}/kms?key={encodeURIComponent(kmsKey.keyId)}"><Icon name="key" size={14} />{kmsDisplay(kmsKeys, detail.kmsKeyId)}</a>
            {:else}
              <span class="mono kms"><Icon name="key" size={14} />{kmsDisplay(kmsKeys, detail.kmsKeyId)}</span>
            {/if}
            {#if canEdit && !editMeta}
              <button type="button" class="btn btn-ghost btn-sm" onclick={() => (editMeta = true)}>Edit</button>
            {/if}
          </span>
        </dd>
        <dt>Rotation</dt>
        <dd>
          <span class="row-between">
            <span class="rot">
              <span class="inline">
                {#if detail.rotation.enabled}
                  <span class="badge badge-success"><span class="badge-dot" aria-hidden="true"></span>On</span>
                  {#if detail.rotation.afterDays}Every {detail.rotation.afterDays} days{/if}
                {:else}
                  <span class="badge"><span class="badge-dot" aria-hidden="true"></span>Off</span>
                {/if}
              </span>
              {#if detail.rotation.enabled}
                <span class="subtle small">
                  {detail.rotation.nextRotationDate ? `Next on ${shortDate(detail.rotation.nextRotationDate)}` : 'Next date pending'}
                  {#if detail.rotation.lambdaArn} · <span class="mono">{detail.rotation.lambdaArn.split(':').pop()}</span>{/if}
                </span>
              {/if}
            </span>
            {#if canEdit && !editRotation}
              <button type="button" class="btn btn-ghost btn-sm" onclick={() => (editRotation = true)}>
                {detail.rotation.enabled ? 'Edit' : 'Set up'}
              </button>
            {/if}
          </span>
        </dd>
        <dt>Description</dt>
        <dd>{#if detail.description && !detail.description.startsWith('citadel:')}{detail.description}{:else}<span class="subtle">No description</span>{/if}</dd>
        <dt>Version</dt>
        <dd>
          {#if current}<span class="mono">v{current.ordinal}</span> · {/if}<span class="mono subtle small" title={detail.currentVersionId}>{detail.currentVersionId.slice(0, 13)}…</span>
        </dd>
        <dt>Updated</dt>
        <dd>{fullDate(detail.updatedAt)}{#if detail.updatedBy} · {detail.updatedBy}{/if}</dd>
        <dt>Created</dt>
        <dd>{fullDate(detail.createdAt)}</dd>
      </dl>

      {#if editMeta}
        <MetadataForm {detail} {kmsKeys} oncancel={() => (editMeta = false)} onsaved={() => { editMeta = false; refresh(); }} />
      {/if}
      {#if editRotation}
        <RotationForm {detail} oncancel={() => (editRotation = false)} onsaved={() => { editRotation = false; refresh(); }} />
      {/if}

      <section class="sec">
        <div class="row-between">
          <span class="label">Tags</span>
          {#if canEdit}
            <button type="button" class="btn btn-ghost btn-sm" aria-pressed={editTags} onclick={() => (editTags = !editTags)}>
              {editTags ? 'Done' : 'Edit'}
            </button>
          {/if}
        </div>
        <TagEditor {coord} tags={detail.tags} editing={editTags} onchanged={refresh} />
      </section>

      {#if versions.length}
        <section class="sec">
          <div class="row-between">
            <span class="label">Recent versions</span>
            <button type="button" class="linkbtn" onclick={() => ontab('versions')}>All {versions.length}</button>
          </div>
          <VersionsTimeline
            {versions}
            limit={3}
            canRestore={canEdit && !deleted}
            {requireApproval}
            disabled={busy}
            reveal={(id) => secretsApi.revealVersion(project, env, path, secretKey, id)}
            onrestore={restoreVersion}
          />
        </section>
      {/if}

      <section class="sec">
        <span class="label">Who can read this</span>
        <AccessList policy={detail.policyDocument} />
      </section>
    {:else if tab === 'versions'}
      {#if versions.length === 0}
        <p class="subtle">No versions found.</p>
      {:else}
        <p class="subtle small intro">
          Reveal any version to compare it. Restoring moves AWSCURRENT{requireApproval ? ' through a change request' : ''}; nothing is deleted.
        </p>
        <VersionsTimeline
          {versions}
          showValues={!deleted}
          canRestore={canEdit && !deleted}
          {requireApproval}
          disabled={busy}
          reveal={(id) => secretsApi.revealVersion(project, env, path, secretKey, id)}
          onrestore={restoreVersion}
        />
      {/if}
    {:else}
      <section class="sec">
        <span class="label">Who can read this</span>
        <AccessList policy={detail.policyDocument} />
      </section>
      <PolicyEditor {coord} policy={detail.policyDocument} {canEdit} onsaved={refresh} />
    {/if}
  </div>

  {#if canEdit && detail}
    <footer class="foot">
      {#if deleted}
        <button type="button" class="btn btn-primary btn-sm" onclick={() => onrestore(secretKey)}>
          <Icon name="history" size={14} />Restore secret
        </button>
      {:else}
        <button type="button" class="btn btn-primary btn-sm" onclick={() => onedit(secretKey)}>
          <Icon name={requireApproval ? 'git-pull-request' : 'edit'} size={14} />{requireApproval ? 'Request change' : 'Edit value'}
        </button>
        <button
          type="button"
          class="btn btn-secondary btn-sm"
          disabled={busy || !detail.rotation.enabled || !detail.rotation.lambdaArn}
          title={detail.rotation.enabled ? undefined : 'Set up rotation first'}
          onclick={rotateNow}
        >
          <Icon name="rotate" size={14} />Rotate now
        </button>
      {/if}
      <button type="button" class="btn btn-danger-ghost btn-sm end" onclick={() => ondelete(secretKey)}>
        <Icon name="trash" size={14} />{deleted ? 'Force delete' : 'Delete'}
      </button>
    </footer>
  {/if}
  {#if requireApproval && canEdit && !deleted}
    <p class="approval subtle small">
      <Icon name="lock" size={12} />Value changes need {minApprovals} approval{minApprovals === 1 ? '' : 's'}.
    </p>
  {/if}
</aside>

<style>
  .panel {
    flex: 1 1 400px;
    max-width: 460px;
    min-width: 0;
    align-self: flex-start;
    display: flex;
    flex-direction: column;
    overflow: hidden;
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    background: var(--surface);
    box-shadow: var(--shadow-lg);
    scroll-margin-top: var(--space-4);
  }
  .head {
    display: flex;
    align-items: flex-start;
    gap: var(--space-2);
    padding: var(--space-4) var(--space-4) 0;
  }
  .titles {
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
    flex: 1;
    min-width: 0;
  }
  .titles .small {
    overflow-wrap: anywhere;
  }
  h2 {
    margin: 0;
    font-family: var(--font-mono);
    font-size: var(--text-lg);
    font-weight: 600;
    letter-spacing: -0.01em;
    overflow-wrap: anywhere;
    outline: none;
  }
  .tabs-wrap {
    margin-top: var(--space-2);
    padding: 0 var(--space-4);
  }
  .body {
    display: flex;
    flex-direction: column;
    gap: var(--space-5);
    padding: var(--space-4);
  }
  .sec {
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
  }
  .label {
    color: var(--text-subtle);
    font-size: var(--text-xs);
    font-weight: 600;
    letter-spacing: 0.06em;
    text-transform: uppercase;
  }
  .valbox {
    display: flex;
    align-items: center;
    min-height: 40px;
    padding: 4px 6px 4px 12px;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: var(--surface-hover);
    overflow: hidden;
  }
  .kv {
    grid-template-columns: 120px minmax(0, 1fr);
    align-items: baseline;
    gap: 10px var(--space-4);
  }
  .arn {
    display: flex;
    align-items: flex-start;
    gap: var(--space-1);
  }
  .arn .mono {
    overflow-wrap: anywhere;
  }
  .kms {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    overflow-wrap: anywhere;
  }
  .row-between {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--space-2);
  }
  .rot {
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .inline {
    display: inline-flex;
    align-items: center;
    gap: var(--space-2);
  }
  .linkbtn {
    padding: 0;
    border: none;
    background: none;
    color: var(--accent-text);
    font: inherit;
    font-size: var(--text-sm);
    cursor: pointer;
  }
  .linkbtn:hover {
    text-decoration: underline;
  }
  .intro {
    margin: 0;
  }
  .grow {
    flex: 1;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .sk-stack {
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
  }
  .sk {
    height: 12px;
  }
  .sk.tall {
    height: 40px;
    width: 100%;
  }
  .foot {
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-2);
    margin-top: auto;
    padding: var(--space-3) var(--space-4);
    border-top: 1px solid var(--border);
    background: var(--surface-hover);
  }
  .end {
    margin-left: auto;
  }
  .approval {
    display: flex;
    align-items: center;
    gap: 6px;
    margin: 0;
    padding: 0 var(--space-4) var(--space-3);
    background: var(--surface-hover);
  }
  @media (max-width: 1100px) {
    .panel {
      max-width: none;
      flex-basis: 100%;
    }
  }
  @media (max-width: 720px) {
    .kv {
      grid-template-columns: minmax(0, 1fr);
      gap: 2px 0;
    }
    .kv :global(dd) {
      margin-bottom: var(--space-2);
    }
  }
</style>
