<!-- Tags as key=value chips; editors can remove chips and add new tags. -->
<script lang="ts">
  import { api, type SecretTag } from '$lib/api';
  import Icon from '$lib/components/Icon.svelte';
  import { toast } from '$lib/stores/toast.svelte';

  let {
    coord,
    tags,
    editing,
    onchanged
  }: {
    coord: { project: string; env: string; path: string; key: string };
    tags: SecretTag[];
    editing: boolean;
    onchanged: () => void;
  } = $props();

  let k = $state('');
  let v = $state('');
  let busy = $state(false);

  async function add(e: SubmitEvent) {
    e.preventDefault();
    if (!k.trim()) return;
    busy = true;
    try {
      await api.tagSecret(coord.project, coord.env, coord.path, coord.key, [{ key: k.trim(), value: v.trim() }]);
      toast.success(`Tagged ${k.trim()}=${v.trim()}`);
      k = '';
      v = '';
      onchanged();
    } catch (err) {
      toast.error(err, 'Could not add tag');
    } finally {
      busy = false;
    }
  }

  async function remove(tagKey: string) {
    busy = true;
    try {
      await api.untagSecret(coord.project, coord.env, coord.path, coord.key, tagKey);
      toast.success(`Removed tag ${tagKey}`);
      onchanged();
    } catch (err) {
      toast.error(err, 'Could not remove tag');
    } finally {
      busy = false;
    }
  }
</script>

{#if tags.length}
  <ul class="chips">
    {#each tags as t (t.key)}
      <li class="chip mono">
        {t.key}={t.value}
        {#if editing}
          <button type="button" class="x" aria-label="Remove tag {t.key}" disabled={busy} onclick={() => remove(t.key)}>
            <Icon name="x" size={12} />
          </button>
        {/if}
      </li>
    {/each}
  </ul>
{:else if !editing}
  <p class="subtle small none">No tags</p>
{/if}

{#if editing}
  <form class="add" onsubmit={add}>
    <label class="sr-only" for="tag-k">Tag key</label>
    <input id="tag-k" class="input mono" bind:value={k} placeholder="key" autocomplete="off" spellcheck="false" />
    <label class="sr-only" for="tag-v">Tag value</label>
    <input id="tag-v" class="input mono" bind:value={v} placeholder="value" autocomplete="off" spellcheck="false" />
    <button type="submit" class="btn btn-secondary btn-sm" disabled={busy || !k.trim()}>
      <Icon name="plus" size={14} />Add
    </button>
  </form>
{/if}

<style>
  .chips {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    margin: 0;
    padding: 0;
    list-style: none;
  }
  .chip {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    height: 22px;
    padding: 0 8px;
    border-radius: 999px;
    box-shadow: inset 0 0 0 1px var(--border-strong);
    color: var(--text-muted);
    font-size: 11.5px;
  }
  .x {
    display: inline-grid;
    place-items: center;
    width: 16px;
    height: 16px;
    margin-right: -4px;
    padding: 0;
    border: none;
    border-radius: 50%;
    background: none;
    color: inherit;
    cursor: pointer;
  }
  .x:hover {
    background: var(--surface-pressed);
    color: var(--text);
  }
  .none {
    margin: 0;
  }
  .add {
    display: grid;
    grid-template-columns: minmax(0, 1fr) minmax(0, 1fr) auto;
    gap: var(--space-2);
    margin-top: var(--space-2);
  }
  .add .input {
    min-height: 28px;
    height: 28px;
  }
</style>
