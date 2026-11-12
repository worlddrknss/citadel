<!-- Aliases of a key: add, move to another key (update), delete. alias/default is immutable. -->
<script lang="ts">
  import { api, errorMessage } from '$lib/api';
  import Icon from '$lib/components/Icon.svelte';
  import Badge from '$lib/components/Badge.svelte';
  import Modal from '$lib/components/Modal.svelte';
  import { toast } from '$lib/stores/toast.svelte';
  import { confirm } from '$lib/stores/confirm.svelte';
  import { DEFAULT_ALIAS, primaryAlias, shortId, statusOf, type Key, type KeyDetail } from './api';

  let {
    detail,
    keys,
    canEdit,
    onchanged
  }: { detail: KeyDetail; keys: Key[]; canEdit: boolean; onchanged: () => void } = $props();

  let input = $state<HTMLInputElement>();
  let name = $state('');
  let busy = $state(false);
  let addError = $state('');
  const uid = Math.random().toString(36).slice(2, 8);

  // Move dialog
  let moveOpen = $state(false);
  let moving = $state('');
  let target = $state('');
  let moveBusy = $state(false);
  let moveError = $state('');

  const targets = $derived(
    keys.filter((k) => k.keyId !== detail.keyId && !k.deletionDate && k.keyUsage === detail.keyUsage)
  );

  export function focusAdd() {
    input?.focus();
  }

  function normalize(raw: string): string {
    const t = raw.trim();
    return t.startsWith('alias/') ? t : `alias/${t}`;
  }

  function validate(full: string): string {
    if (!/^alias\/[A-Za-z0-9/_-]{1,250}$/.test(full)) return 'Use letters, numbers, /, _ and - after "alias/".';
    if (full === DEFAULT_ALIAS) return 'alias/default is reserved for the account default key.';
    if (full.startsWith('alias/aws/')) return 'The alias/aws/ prefix is reserved.';
    if (detail.aliases.includes(full)) return 'This key already has that alias.';
    return '';
  }

  async function add(e: SubmitEvent) {
    e.preventDefault();
    if (busy || !name.trim()) return;
    const full = normalize(name);
    addError = validate(full);
    if (addError) return;
    busy = true;
    try {
      await api.createKmsAlias(detail.keyId, full);
      toast.success(`Added ${full}`);
      name = '';
      onchanged();
    } catch (err) {
      addError = errorMessage(err);
    } finally {
      busy = false;
    }
  }

  function startMove(alias: string) {
    moving = alias;
    target = targets[0]?.keyId ?? '';
    moveError = '';
    moveOpen = true;
  }

  async function move(e: SubmitEvent) {
    e.preventDefault();
    if (!target || moveBusy) return;
    moveBusy = true;
    moveError = '';
    try {
      await api.updateKmsAlias(target, moving);
      toast.success(`Moved ${moving} to ${shortId(target)}`);
      moveOpen = false;
      onchanged();
    } catch (err) {
      moveError = errorMessage(err);
    } finally {
      moveBusy = false;
    }
  }

  async function remove(alias: string) {
    const ok = await confirm({
      title: `Delete ${alias}?`,
      message: 'Applications that refer to the key by this alias stop working. The key itself and its data are not affected.',
      confirmLabel: 'Delete alias',
      danger: true
    });
    if (!ok) return;
    try {
      await api.deleteKmsAlias(alias);
      toast.success(`Deleted ${alias}`);
      onchanged();
    } catch (err) {
      toast.error(err);
    }
  }

  function keyLabel(k: Key) {
    const a = primaryAlias(k);
    return `${a ?? k.keyId}${a ? ` · ${shortId(k.keyId)}` : ''}${statusOf(k) === 'Disabled' ? ' (disabled)' : ''}`;
  }
</script>

<div class="aliases">
  {#if detail.aliases.length === 0}
    <p class="subtle small none">No aliases. An alias gives applications a stable name, so you can swap the key behind it.</p>
  {:else}
    <ul class="list">
      {#each [...detail.aliases].sort() as a (a)}
        <li>
          <span class="mono name">{a}</span>
          {#if a === DEFAULT_ALIAS}
            <Badge tone="info" dot={false}><Icon name="lock" size={12} />Managed</Badge>
          {:else if canEdit}
            <span class="acts">
              <button type="button" class="btn btn-ghost btn-sm" onclick={() => startMove(a)} disabled={targets.length === 0}
                title={targets.length === 0 ? 'No other key with the same usage' : undefined}>Move</button>
              <button type="button" class="btn-icon" aria-label="Delete alias {a}" title="Delete" onclick={() => remove(a)}>
                <Icon name="trash" size={14} />
              </button>
            </span>
          {/if}
        </li>
      {/each}
    </ul>
  {/if}

  {#if canEdit}
    <form class="add" onsubmit={add} novalidate>
      <label class="field grow">
        <span class="field-label">New alias</span>
        <input
          bind:this={input}
          id="al-{uid}"
          class="input mono"
          bind:value={name}
          placeholder="alias/payments-prod"
          autocomplete="off"
          spellcheck="false"
          aria-invalid={!!addError}
          aria-describedby="al-msg-{uid}"
          oninput={() => (addError = '')}
        />
        <span id="al-msg-{uid}" class={addError ? 'field-error' : 'field-hint'}>
          {addError || 'The alias/ prefix is added if you leave it out.'}
        </span>
      </label>
      <button type="submit" class="btn btn-secondary" disabled={busy || !name.trim()}>
        <Icon name="plus" size={14} />{busy ? 'Adding…' : 'Add alias'}
      </button>
    </form>
  {/if}
</div>

<Modal bind:open={moveOpen} title="Move alias" description="Point {moving} at a different key. Callers using the alias switch to that key immediately." size="sm">
  <form id="move-form" onsubmit={move}>
    <label class="field">
      <span class="field-label">Target key</span>
      <select class="select mono" bind:value={target}>
        {#each targets as k (k.keyId)}<option value={k.keyId}>{keyLabel(k)}</option>{/each}
      </select>
      <span class="field-hint">Only keys with the same usage are listed. Data encrypted under the old key still needs the old key to decrypt.</span>
    </label>
    {#if moveError}<p class="field-error" role="alert">{moveError}</p>{/if}
  </form>
  {#snippet footer()}
    <button type="button" class="btn btn-ghost" onclick={() => (moveOpen = false)}>Cancel</button>
    <button type="submit" form="move-form" class="btn btn-primary" disabled={!target || moveBusy}>{moveBusy ? 'Moving…' : 'Move alias'}</button>
  {/snippet}
</Modal>

<style>
  .aliases {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
  }
  .none {
    margin: 0;
  }
  .list {
    list-style: none;
    margin: 0;
    padding: 0;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
  }
  .list li {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    min-height: 44px;
    padding: 4px var(--space-2) 4px var(--space-3);
    border-bottom: 1px solid var(--border);
  }
  .list li:last-child {
    border-bottom: none;
  }
  .name {
    flex: 1;
    min-width: 0;
    overflow-wrap: anywhere;
    font-weight: 500;
  }
  .acts {
    display: inline-flex;
    align-items: center;
    gap: 2px;
  }
  .add {
    display: flex;
    align-items: flex-start;
    gap: var(--space-2);
    flex-wrap: wrap;
  }
  .add .btn {
    margin-top: 22px;
  }
  .grow {
    flex: 1 1 220px;
  }
</style>
