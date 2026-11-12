<!--
  The board's secrets table: folder rows pinned on top, then secrets with a
  masked value (reveal + copy via SecretValue), version, author and age.
  Page-local rather than DataTable because the board needs non-selectable
  folder rows pinned above sorted secrets, an "open in drawer" row state and
  a footer inside the card, which DataTable doesn't model.
-->
<script lang="ts" module>
  export type SortKey = 'key' | 'updated';
</script>

<script lang="ts">
  import type { Snippet } from 'svelte';
  import Icon from '$lib/components/Icon.svelte';
  import SecretValue from '$lib/components/SecretValue.svelte';
  import type { SecretRow } from '../../api';
  import { fullDate, initials, relTime, shortDate } from '../../lib';
  import Menu, { type MenuItem } from './Menu.svelte';


  let {
    rows,
    folders,
    folderCounts,
    loading,
    selectable,
    selected = $bindable<string[]>([]),
    activeKey,
    pendingKeys,
    sortBy = $bindable<SortKey>('key'),
    sortDir = $bindable<'asc' | 'desc'>('asc'),
    caption,
    folderHref,
    onopenfolder,
    ondeletefolder,
    onopen,
    reveal,
    canReveal = true,
    menuFor,
    empty,
    footer
  }: {
    rows: SecretRow[];
    folders: string[];
    folderCounts?: Record<string, number>;
    loading: boolean;
    selectable: boolean;
    selected?: string[];
    activeKey: string;
    pendingKeys: Set<string>;
    sortBy?: SortKey;
    sortDir?: 'asc' | 'desc';
    caption: string;
    folderHref: (name: string) => string;
    onopenfolder: (name: string) => void;
    ondeletefolder?: (name: string) => void;
    onopen: (row: SecretRow) => void;
    reveal: (row: SecretRow) => Promise<string>;
    /** False hides Reveal (viewers while viewersCanReveal is off). */
    canReveal?: boolean;
    menuFor: (row: SecretRow) => MenuItem[];
    empty: Snippet;
    footer: Snippet;
  } = $props();

  const selectableKeys = $derived(rows.map((r) => r.key));
  const allSelected = $derived(selectableKeys.length > 0 && selectableKeys.every((k) => selected.includes(k)));
  const someSelected = $derived(!allSelected && selectableKeys.some((k) => selected.includes(k)));
  const cols = $derived(selectable ? 7 : 6);

  function toggleAll() {
    selected = allSelected
      ? selected.filter((k) => !selectableKeys.includes(k))
      : [...new Set([...selected, ...selectableKeys])];
  }

  function toggle(k: string) {
    selected = selected.includes(k) ? selected.filter((x) => x !== k) : [...selected, k];
  }

  function sort(by: SortKey) {
    if (sortBy === by) sortDir = sortDir === 'asc' ? 'desc' : 'asc';
    else {
      sortBy = by;
      sortDir = by === 'updated' ? 'desc' : 'asc';
    }
  }

  function ariaSort(by: SortKey) {
    if (sortBy !== by) return 'none';
    return sortDir === 'asc' ? 'ascending' : 'descending';
  }

  function folderClick(e: MouseEvent, name: string) {
    if (e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return;
    e.preventDefault();
    onopenfolder(name);
  }
</script>

<div class="card card-flush tbl-card">
  <div class="scroll">
    <table class="table">
      <caption class="sr-only">{caption}</caption>
      <thead>
        <tr>
          {#if selectable}
            <th scope="col" class="chk">
              <input
                type="checkbox"
                aria-label="Select all secrets in folder"
                checked={allSelected}
                indeterminate={someSelected}
                disabled={selectableKeys.length === 0}
                onchange={toggleAll}
              />
            </th>
          {/if}
          <th scope="col" aria-sort={ariaSort('key')}>
            <button type="button" class="sort" onclick={() => sort('key')}>
              Key<Icon name={sortBy === 'key' ? (sortDir === 'asc' ? 'chevron-up' : 'chevron-down') : 'arrow-up-down'} size={12} />
            </button>
          </th>
          <th scope="col">Value</th>
          <th scope="col">Version</th>
          <th scope="col">Updated by</th>
          <th scope="col" aria-sort={ariaSort('updated')}>
            <button type="button" class="sort" onclick={() => sort('updated')}>
              Updated<Icon name={sortBy === 'updated' ? (sortDir === 'asc' ? 'chevron-up' : 'chevron-down') : 'arrow-up-down'} size={12} />
            </button>
          </th>
          <th scope="col" class="act"><span class="sr-only">Actions</span></th>
        </tr>
      </thead>
      <tbody>
        {#if loading && rows.length === 0 && folders.length === 0}
          {#each Array(5) as _, i (i)}
            <tr aria-hidden="true">
              {#if selectable}<td class="chk"></td>{/if}
              <td><span class="skeleton sk" style:width="{140 + ((i * 37) % 80)}px"></span></td>
              <td><span class="skeleton sk" style:width="120px"></span></td>
              <td><span class="skeleton sk" style:width="24px"></span></td>
              <td><span class="skeleton sk" style:width="100px"></span></td>
              <td><span class="skeleton sk" style:width="60px"></span></td>
              <td></td>
            </tr>
          {/each}
        {:else}
          {#each folders as f (f)}
            <tr class="folder">
              {#if selectable}<td class="chk"></td>{/if}
              <td colspan="5">
                <a class="folder-link" href={folderHref(f)} onclick={(e) => folderClick(e, f)}>
                  <span class="subtle ic"><Icon name="folder" size={16} /></span>
                  <span class="mono">{f}/</span>
                  {#if folderCounts?.[f] !== undefined}
                    <span class="subtle small">{folderCounts[f]} secret{folderCounts[f] === 1 ? '' : 's'}</span>
                  {/if}
                </a>
              </td>
              <td class="act">
                {#if ondeletefolder}
                  <button
                    type="button"
                    class="btn btn-ghost btn-sm icon-only"
                    aria-label="Delete folder {f}"
                    title="Delete folder"
                    onclick={() => ondeletefolder?.(f)}
                  >
                    <Icon name="trash" size={14} />
                  </button>
                {/if}
              </td>
            </tr>
          {/each}
          {#each rows as r (r.key)}
            {@const checked = selected.includes(r.key)}
            <tr class:sel={checked || activeKey === r.key} class:deleted={!!r.deletionDate}>
              {#if selectable}
                <td class="chk">
                  <input type="checkbox" aria-label="Select {r.key}" {checked} onchange={() => toggle(r.key)} />
                </td>
              {/if}
              <td>
                <span class="key-cell">
                  <button
                    type="button"
                    class="key mono"
                    data-secret-key={r.key}
                    aria-label="Open details for {r.key}"
                    aria-expanded={activeKey === r.key}
                    onclick={() => onopen(r)}
                  >{r.key}</button>
                  {#if r.deletionDate}
                    <span class="badge badge-warning tiny" title="Scheduled for deletion on {fullDate(r.deletionDate)}">
                      <Icon name="clock" size={12} />Deletes {shortDate(r.deletionDate)}
                    </span>
                  {/if}
                  {#if pendingKeys.has(r.key)}
                    <span class="badge badge-info tiny" title="A change request for this key is waiting for approval">
                      <Icon name="git-pull-request" size={12} />Change pending
                    </span>
                  {/if}
                </span>
              </td>
              <td class="val">
                {#if r.deletionDate}
                  <span class="subtle small">Unavailable until restored</span>
                {:else if canReveal}
                  <SecretValue load={() => reveal(r)} hideAfter={30} />
                {:else}
                  <span class="subtle small" title="Your role can't reveal values in this account">Hidden</span>
                {/if}
              </td>
              <td><span class="mono subtle">{r.version ? `v${r.version}` : '—'}</span></td>
              <td>
                {#if r.updatedBy}
                  <span class="who"><span class="avatar" aria-hidden="true">{initials(r.updatedBy)}</span><span class="who-name">{r.updatedBy}</span></span>
                {:else}
                  <span class="subtle">—</span>
                {/if}
              </td>
              <td class="subtle nowrap"><time datetime={r.updatedAt} title={fullDate(r.updatedAt)}>{relTime(r.updatedAt)}</time></td>
              <td class="act">
                <Menu label="More actions for {r.key}" items={menuFor(r)} />
              </td>
            </tr>
          {/each}
        {/if}
      </tbody>
    </table>
    {#if !loading && rows.length === 0 && folders.length === 0}
      <div class="empty-wrap">{@render empty()}</div>
    {/if}
  </div>
  <div class="foot">{@render footer()}</div>
</div>

<style>
  .tbl-card {
    overflow: hidden;
    box-shadow: none;
  }
  .scroll {
    overflow-x: auto;
  }
  .table {
    min-width: 820px;
  }
  .table th,
  .table td {
    padding-left: var(--space-3);
    padding-right: var(--space-3);
    white-space: nowrap;
  }
  .chk {
    width: 44px;
  }
  .act {
    width: 48px;
    text-align: end;
  }
  .sort {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 0;
    border: none;
    background: none;
    color: inherit;
    font: inherit;
    letter-spacing: inherit;
    text-transform: inherit;
    cursor: pointer;
  }
  .sort:hover {
    color: var(--text);
  }
  .sk {
    height: 12px;
  }
  .folder-link {
    display: inline-flex;
    align-items: center;
    gap: var(--space-2);
    color: var(--text);
  }
  .folder-link:hover .mono {
    color: var(--accent-text);
    text-decoration: underline;
  }
  .folder-link:hover {
    text-decoration: none;
  }
  .ic {
    display: inline-flex;
  }
  .key-cell {
    display: inline-flex;
    align-items: center;
    gap: var(--space-2);
  }
  .key {
    padding: 0;
    border: none;
    background: none;
    color: var(--text);
    font-family: var(--font-mono);
    font-size: 13.5px;
    font-weight: 500;
    cursor: pointer;
    text-align: start;
  }
  .key:hover {
    color: var(--accent-text);
    text-decoration: underline;
  }
  .deleted .key {
    color: var(--text-muted);
    text-decoration: line-through;
  }
  .tiny {
    height: 20px;
    font-size: var(--text-xs);
    gap: 4px;
  }
  .val {
    max-width: 320px;
  }
  .who {
    display: inline-flex;
    align-items: center;
    gap: var(--space-2);
    max-width: 200px;
  }
  .who-name {
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .avatar {
    display: inline-grid;
    place-items: center;
    width: 24px;
    height: 24px;
    border-radius: 50%;
    background: var(--accent-soft);
    color: var(--accent-text);
    font-size: 11px;
    font-weight: 600;
    flex-shrink: 0;
  }
  .icon-only {
    width: 28px;
    padding: 0;
  }
  .empty-wrap {
    padding: var(--space-10) var(--space-5);
  }
  .foot {
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: var(--space-2);
    padding: 10px var(--space-4);
    border-top: 1px solid var(--border);
    color: var(--text-subtle);
    font-size: var(--text-sm);
  }
  @media (max-width: 720px) {
    .icon-only {
      width: 36px;
      height: 36px;
    }
  }
</style>
