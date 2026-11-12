<!--
  Add a secret or store a new value for one. In environments that require
  approval the same form opens a change request instead of writing.
-->
<script lang="ts">
  import { api, ApiError, type KMSKey } from '$lib/api';
  import Icon from '$lib/components/Icon.svelte';
  import Modal from '$lib/components/Modal.svelte';
  import { toast } from '$lib/stores/toast.svelte';
  import { secretsApi } from '../../api';
  import { kmsLabel } from './kms';
  import SecretInput from './SecretInput.svelte';

  let {
    open = $bindable(false),
    mode,
    project,
    env,
    path,
    initialKey = '',
    kmsKeys,
    existingKeys,
    requireApproval,
    minApprovals,
    onsaved
  }: {
    open?: boolean;
    mode: 'create' | 'edit';
    project: string;
    env: string;
    path: string;
    initialKey?: string;
    kmsKeys: KMSKey[];
    existingKeys: string[];
    requireApproval: boolean;
    minApprovals: number;
    onsaved: (r: { key: string; changeRequest: boolean; created: boolean }) => void;
  } = $props();

  let key = $state('');
  let value = $state('');
  let kms = $state('');
  let busy = $state(false);
  let loadingCurrent = $state(false);

  $effect(() => {
    if (open) {
      key = initialKey;
      value = '';
      kms = '';
    }
  });

  const keyOk = $derived(/^[A-Za-z0-9_.-]+$/.test(key.trim()));
  const overwrites = $derived(mode === 'create' && existingKeys.includes(key.trim()));
  const location = $derived(`${project}/${env}${path === '/' ? '' : path}`);

  const title = $derived(
    mode === 'create'
      ? requireApproval
        ? 'Request a new secret'
        : 'Add secret'
      : requireApproval
        ? `Request change to ${initialKey}`
        : `New value for ${initialKey}`
  );

  async function loadCurrent() {
    loadingCurrent = true;
    try {
      value = await secretsApi.revealValue(project, env, path, initialKey);
    } catch (e) {
      toast.error(e, 'Could not load the current value');
    } finally {
      loadingCurrent = false;
    }
  }

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    if (!keyOk) return;
    busy = true;
    const k = key.trim();
    try {
      if (requireApproval) {
        await api.createChangeRequest({ project, env, path, key: k, value });
        toast.success(`Opened a change request for ${k}. It applies once approved.`);
        onsaved({ key: k, changeRequest: true, created: false });
      } else {
        try {
          const res = await api.put({ project, env, path, key: k, value, kmsKeyId: kms || undefined });
          toast.success(res.created ? `Created ${k}` : `Stored a new version of ${k}`);
          onsaved({ key: k, changeRequest: false, created: res.created });
        } catch (err) {
          // The environment needs approval although the console didn't know
          // (policy added meanwhile, or the policy list failed to load):
          // send the same value through a change request instead.
          if (!(err instanceof ApiError && err.code === 'approval_required')) throw err;
          await api.createChangeRequest({ project, env, path, key: k, value });
          toast.success(`${env} needs approval, so this opened a change request for ${k}. It applies once approved.`);
          onsaved({ key: k, changeRequest: true, created: false });
        }
      }
      value = '';
      open = false;
    } catch (err) {
      toast.error(err, requireApproval ? 'Could not open the change request' : 'Could not save the secret');
    } finally {
      busy = false;
    }
  }
</script>

<Modal bind:open {title} description="In {location}" size="md">
  <form id="value-form" class="form" onsubmit={submit}>
    {#if requireApproval}
      <div class="callout callout-warning">
        <Icon name="lock" size={16} />
        <span>
          This environment requires approval. Saving opens a change request that needs
          {minApprovals} approval{minApprovals === 1 ? '' : 's'} from someone other than you; nothing changes until then.
        </span>
      </div>
    {/if}
    {#if mode === 'create'}
      <label class="field">
        <span class="field-label">Key</span>
        <!-- svelte-ignore a11y_autofocus -->
        <input
          class="input mono"
          bind:value={key}
          placeholder="DATABASE_PASSWORD"
          autocomplete="off"
          spellcheck="false"
          autofocus
          aria-invalid={key.trim() !== '' && !keyOk}
          aria-describedby="vk-hint"
        />
        {#if key.trim() && !keyOk}
          <span id="vk-hint" class="field-error">Use letters, digits, dots, dashes and underscores.</span>
        {:else if overwrites}
          <span id="vk-hint" class="field-hint warn">{key.trim()} already exists here; saving stores a new version of it.</span>
        {:else}
          <span id="vk-hint" class="field-hint">Letters, digits, dots, dashes and underscores.</span>
        {/if}
      </label>
    {/if}
    <div class="field">
      <div class="label-row">
        <label class="field-label" for="vv">Value</label>
        {#if mode === 'edit'}
          <button type="button" class="btn btn-ghost btn-sm" disabled={loadingCurrent} onclick={loadCurrent}>
            <Icon name="download" size={14} />Load current value
          </button>
        {/if}
      </div>
      <SecretInput id="vv" bind:value rows={5} placeholder={'s3cr3t or {"user":"app","password":"…"}'} describedby="vv-hint" autofocus={mode === 'edit'} />
      <span id="vv-hint" class="field-hint">
        Hidden while you type. JSON objects are served to External Secrets as-is; each save creates a new version.
      </span>
    </div>
    {#if mode === 'create' && !requireApproval}
      <label class="field">
        <span class="field-label">KMS key</span>
        <select class="select" bind:value={kms}>
          <option value="">Account default</option>
          {#each kmsKeys as k (k.keyId)}
            <option value={k.keyId}>{kmsLabel(k)}</option>
          {/each}
        </select>
        <span class="field-hint">Encrypts this secret's values. You can re-encrypt under another key later.</span>
      </label>
    {/if}
  </form>
  {#snippet footer()}
    <button type="button" class="btn btn-secondary" onclick={() => (open = false)}>Cancel</button>
    <button type="submit" form="value-form" class="btn btn-primary" disabled={busy || !keyOk}>
      {#if requireApproval}
        <Icon name="git-pull-request" size={16} />Open change request
      {:else}
        {mode === 'create' ? 'Add secret' : 'Save new version'}
      {/if}
    </button>
  {/snippet}
</Modal>

<style>
  .form {
    display: flex;
    flex-direction: column;
  }
  .form > .callout {
    margin-bottom: var(--space-4);
  }
  .label-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--space-2);
  }
  .warn {
    color: var(--warning);
  }
</style>
