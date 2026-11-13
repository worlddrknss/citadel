<!--
  Key/value tag list with add and remove. Used by the KMS key panel and by
  Parameters; a candidate for #lib/components.
-->
<script lang="ts">
  import Icon from '#lib/components/Icon.svelte';
  import { confirm } from '#lib/stores/confirm.svelte.ts';
  import { toast } from '#lib/stores/toast.svelte.ts';

  let {
    tags,
    loading = false,
    error = '',
    canEdit,
    resource,
    onadd,
    onremove
  }: {
    tags: { key: string; value: string }[];
    loading?: boolean;
    error?: string;
    canEdit: boolean;
    /** Name of the tagged resource, for messages. */
    resource: string;
    onadd: (key: string, value: string) => Promise<void>;
    onremove: (key: string) => Promise<void>;
  } = $props();

  let key = $state('');
  let value = $state('');
  let busy = $state(false);
  const uid = Math.random().toString(36).slice(2, 8);
  const exists = $derived(tags.some((t) => t.key === key.trim()));

  async function add(e: SubmitEvent) {
    e.preventDefault();
    const k = key.trim();
    if (!k || busy) return;
    busy = true;
    try {
      await onadd(k, value);
      toast.success(`${exists ? 'Updated' : 'Added'} tag ${k}`);
      key = '';
      value = '';
    } catch (err) {
      toast.error(err);
    } finally {
      busy = false;
    }
  }

  async function remove(k: string) {
    const ok = await confirm({
      title: `Remove tag "${k}"?`,
      message: `The tag is removed from ${resource}. Policies that match on it stop matching.`,
      confirmLabel: 'Remove tag',
      danger: true
    });
    if (!ok) return;
    try {
      await onremove(k);
      toast.success(`Removed tag ${k}`);
    } catch (err) {
      toast.error(err);
    }
  }
</script>

<div class="tags">
  {#if loading && tags.length === 0}
    <div class="tag-skel" aria-busy="true" aria-label="Loading tags">
      <span class="skeleton"></span><span class="skeleton"></span>
    </div>
  {:else if error}
    <div class="callout callout-danger" role="alert"><Icon name="alert-circle" size={16} /><span>{error}</span></div>
  {:else if tags.length === 0}
    <p class="subtle small none">No tags yet. Tags help you find keys and scope access in policies.</p>
  {:else}
    <ul class="tag-list">
      {#each tags as t (t.key)}
        <li>
          <span class="mono tag-k">{t.key}</span>
          <span class="mono tag-v">{t.value || '—'}</span>
          {#if canEdit}
            <button type="button" class="btn-icon" aria-label="Remove tag {t.key}" title="Remove" onclick={() => remove(t.key)}>
              <Icon name="x" size={14} />
            </button>
          {/if}
        </li>
      {/each}
    </ul>
  {/if}

  {#if canEdit}
    <form class="tag-add" onsubmit={add}>
      <label class="field">
        <span class="field-label">Key</span>
        <input id="tk-{uid}" class="input mono" bind:value={key} maxlength="128" placeholder="team" autocomplete="off" />
      </label>
      <label class="field">
        <span class="field-label">Value</span>
        <input class="input mono" bind:value={value} maxlength="256" placeholder="payments" autocomplete="off" />
      </label>
      <button type="submit" class="btn btn-secondary" disabled={!key.trim() || busy}>
        <Icon name={exists ? 'edit' : 'plus'} size={14} />{exists ? 'Update' : 'Add tag'}
      </button>
    </form>
  {/if}
</div>

<style>
  .tags {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
  }
  .none {
    margin: 0;
  }
  .tag-skel {
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
  }
  .tag-skel .skeleton {
    height: 28px;
    width: 100%;
  }
  .tag-list {
    list-style: none;
    margin: 0;
    padding: 0;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
  }
  .tag-list li {
    display: grid;
    grid-template-columns: minmax(0, 2fr) minmax(0, 3fr) 32px;
    align-items: center;
    gap: var(--space-3);
    min-height: 40px;
    padding: 4px var(--space-2) 4px var(--space-3);
    border-bottom: 1px solid var(--border);
  }
  .tag-list li:last-child {
    border-bottom: none;
  }
  .tag-k {
    font-weight: 500;
    overflow-wrap: anywhere;
  }
  .tag-v {
    color: var(--text-muted);
    overflow-wrap: anywhere;
  }
  .tag-add {
    display: grid;
    grid-template-columns: minmax(0, 1fr) minmax(0, 1fr) auto;
    gap: var(--space-2);
    align-items: end;
  }
  .tag-add .field + .field {
    margin-top: 0;
  }
  @media (max-width: 480px) {
    .tag-add {
      grid-template-columns: minmax(0, 1fr);
    }
  }
</style>
