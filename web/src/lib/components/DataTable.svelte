<!--
  List table with search, sortable columns, pagination, optional row
  selection, and loading/empty states. Pages describe columns and render
  each row's cells through the `row` snippet.

  Search and sort state can be bound so a page can keep them in the URL.
-->
<script lang="ts" module>
export interface Column<R> {
  id: string;
  label: string;
  /** Value used for sorting; columns without one aren't sortable. */
  sort?: (row: R) => string | number | Date | null | undefined;
  align?: 'start' | 'end';
  /** CSS width, e.g. "160px" or "30%". */
  width?: string;
  /** Hide on narrow screens. */
  hideOnMobile?: boolean;
}
</script>

<script lang="ts" generics="T">
  import type { Snippet } from 'svelte';
  import Icon from './Icon.svelte';


  let {
    rows,
    columns,
    key,
    row,
    loading = false,
    searchable,
    searchPlaceholder = 'Search…',
    query = $bindable(''),
    sortBy = $bindable(''),
    sortDir = $bindable<'asc' | 'desc'>('asc'),
    pageSize = 25,
    selectable = false,
    selected = $bindable<string[]>([]),
    empty,
    toolbar,
    bulk,
    caption
  }: {
    rows: T[];
    columns: Column<T>[];
    key: (row: T) => string;
    row: Snippet<[T]>;
    loading?: boolean;
    /** Text a row is searched by. Omit to hide the search box. */
    searchable?: (row: T) => string;
    searchPlaceholder?: string;
    query?: string;
    sortBy?: string;
    sortDir?: 'asc' | 'desc';
    pageSize?: number;
    selectable?: boolean;
    selected?: string[];
    /** Shown when there are no rows at all (not when a search matches nothing). */
    empty?: Snippet;
    /** Extra controls to the right of the search box (filters, buttons). */
    toolbar?: Snippet;
    /** Actions shown while rows are selected. */
    bulk?: Snippet<[string[]]>;
    caption: string;
  } = $props();

  let page = $state(0);

  const filtered = $derived.by(() => {
    const q = query.trim().toLowerCase();
    let out = q && searchable ? rows.filter((r) => searchable(r).toLowerCase().includes(q)) : rows;
    const col = columns.find((c) => c.id === sortBy);
    if (col?.sort) {
      const get = col.sort;
      const dir = sortDir === 'asc' ? 1 : -1;
      out = [...out].sort((a, b) => {
        const va = get(a);
        const vb = get(b);
        if (va == null && vb == null) return 0;
        if (va == null) return 1;
        if (vb == null) return -1;
        if (va instanceof Date && vb instanceof Date) return (va.getTime() - vb.getTime()) * dir;
        if (typeof va === 'number' && typeof vb === 'number') return (va - vb) * dir;
        return String(va).localeCompare(String(vb), undefined, { numeric: true, sensitivity: 'base' }) * dir;
      });
    }
    return out;
  });

  const pageCount = $derived(Math.max(1, Math.ceil(filtered.length / pageSize)));
  const visible = $derived(filtered.slice(page * pageSize, page * pageSize + pageSize));

  $effect(() => {
    // Back to the first page whenever the result set changes shape.
    void query;
    void sortBy;
    void sortDir;
    page = 0;
  });
  $effect(() => {
    if (page > pageCount - 1) page = pageCount - 1;
  });

  function toggleSort(col: Column<T>) {
    if (!col.sort) return;
    if (sortBy === col.id) sortDir = sortDir === 'asc' ? 'desc' : 'asc';
    else {
      sortBy = col.id;
      sortDir = 'asc';
    }
  }

  const visibleKeys = $derived(visible.map(key));
  const allVisibleSelected = $derived(visibleKeys.length > 0 && visibleKeys.every((k) => selected.includes(k)));

  function toggleAll() {
    if (allVisibleSelected) selected = selected.filter((k) => !visibleKeys.includes(k));
    else selected = [...new Set([...selected, ...visibleKeys])];
  }

  function toggleOne(k: string) {
    selected = selected.includes(k) ? selected.filter((x) => x !== k) : [...selected, k];
  }

  function ariaSort(col: Column<T>): 'ascending' | 'descending' | 'none' | undefined {
    if (!col.sort) return undefined;
    if (sortBy !== col.id) return 'none';
    return sortDir === 'asc' ? 'ascending' : 'descending';
  }
</script>

<div class="dt">
  {#if searchable || toolbar}
    <div class="dt-toolbar">
      {#if searchable}
        <label class="dt-search">
          <Icon name="search" size={14} />
          <span class="sr-only">Search</span>
          <input type="search" class="dt-search-input" placeholder={searchPlaceholder} bind:value={query} />
        </label>
      {/if}
      <div class="dt-tools">{@render toolbar?.()}</div>
    </div>
  {/if}

  {#if selectable && selected.length > 0 && bulk}
    <div class="dt-bulk" role="region" aria-label="Bulk actions">
      <span><strong>{selected.length}</strong> selected</span>
      <div class="dt-bulk-actions">{@render bulk(selected)}</div>
      <button type="button" class="btn btn-ghost btn-sm" onclick={() => (selected = [])}>Clear</button>
    </div>
  {/if}

  <div class="dt-scroll">
    <table class="table">
      <caption class="sr-only">{caption}</caption>
      <thead>
        <tr>
          {#if selectable}
            <th class="dt-check" scope="col">
              <input type="checkbox" aria-label="Select all on this page" checked={allVisibleSelected} onchange={toggleAll} />
            </th>
          {/if}
          {#each columns as col (col.id)}
            <th
              scope="col"
              style:width={col.width}
              class:end={col.align === 'end'}
              class:hide-mobile={col.hideOnMobile}
              aria-sort={ariaSort(col)}
            >
              {#if col.sort}
                <button type="button" class="dt-sort" onclick={() => toggleSort(col)}>
                  {col.label}
                  <Icon
                    name={sortBy === col.id ? (sortDir === 'asc' ? 'arrow-up' : 'arrow-down') : 'arrow-up-down'}
                    size={12}
                  />
                </button>
              {:else}
                {col.label}
              {/if}
            </th>
          {/each}
        </tr>
      </thead>
      <tbody>
        {#if loading && rows.length === 0}
          {#each Array(5) as _, i (i)}
            <tr class="dt-skel">
              {#if selectable}<td></td>{/if}
              {#each columns as col (col.id)}
                <td class:hide-mobile={col.hideOnMobile}><span class="skeleton"></span></td>
              {/each}
            </tr>
          {/each}
        {:else}
          {#each visible as r (key(r))}
            {@const k = key(r)}
            <tr class:selected={selected.includes(k)}>
              {#if selectable}
                <td class="dt-check">
                  <input type="checkbox" aria-label="Select row" checked={selected.includes(k)} onchange={() => toggleOne(k)} />
                </td>
              {/if}
              {@render row(r)}
            </tr>
          {/each}
        {/if}
      </tbody>
    </table>

    {#if !loading && rows.length === 0 && empty}
      <div class="dt-empty">{@render empty()}</div>
    {:else if !loading && rows.length > 0 && filtered.length === 0}
      <div class="dt-empty dt-nomatch">
        <p>Nothing matches “{query}”.</p>
        <button type="button" class="btn btn-ghost btn-sm" onclick={() => (query = '')}>Clear search</button>
      </div>
    {/if}
  </div>

  {#if filtered.length > pageSize}
    <nav class="dt-pager" aria-label="Pagination">
      <span class="dt-range">
        {page * pageSize + 1}–{Math.min(filtered.length, (page + 1) * pageSize)} of {filtered.length}
      </span>
      <button type="button" class="btn-icon" aria-label="Previous page" disabled={page === 0} onclick={() => page--}>
        <Icon name="chevron-left" />
      </button>
      <button type="button" class="btn-icon" aria-label="Next page" disabled={page >= pageCount - 1} onclick={() => page++}>
        <Icon name="chevron-right" />
      </button>
    </nav>
  {/if}
</div>

<style>
  .dt {
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
    min-width: 0;
  }
  .dt-toolbar {
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-2);
    align-items: center;
  }
  .dt-search {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    flex: 1 1 240px;
    max-width: 420px;
    height: 36px;
    padding: 0 var(--space-3);
    border: 1px solid var(--border-strong);
    border-radius: var(--radius-md);
    background: var(--surface);
    color: var(--text-muted);
  }
  .dt-search:focus-within {
    border-color: var(--accent);
    box-shadow: var(--focus-ring);
  }
  .dt-search-input {
    flex: 1;
    min-width: 0;
    border: none;
    outline: none;
    background: transparent;
    color: var(--text);
    font: inherit;
    font-size: var(--text-sm);
  }
  .dt-tools {
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-2);
    margin-left: auto;
  }
  .dt-bulk {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--space-3);
    padding: var(--space-2) var(--space-3);
    border-radius: var(--radius-md);
    background: var(--accent-soft);
    color: var(--text);
    font-size: var(--text-sm);
  }
  .dt-bulk-actions {
    display: flex;
    gap: var(--space-2);
    margin-left: auto;
  }
  .dt-scroll {
    overflow-x: auto;
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    background: var(--surface);
  }
  .dt-check {
    width: 40px;
  }
  .dt-sort {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 0;
    border: none;
    background: none;
    color: inherit;
    font: inherit;
    cursor: pointer;
  }
  .dt-sort:hover {
    color: var(--text);
  }
  th.end,
  th.end .dt-sort {
    text-align: end;
    justify-content: flex-end;
  }
  .dt-empty {
    padding: var(--space-8) var(--space-5);
    text-align: center;
  }
  .dt-nomatch p {
    margin: 0 0 var(--space-2);
    color: var(--text-muted);
  }
  .dt-skel .skeleton {
    display: block;
    height: 12px;
    width: 70%;
  }
  .dt-pager {
    display: flex;
    align-items: center;
    justify-content: flex-end;
    gap: var(--space-1);
  }
  .dt-range {
    margin-right: var(--space-2);
    color: var(--text-muted);
    font-size: var(--text-sm);
    font-variant-numeric: tabular-nums;
  }
  @media (max-width: 720px) {
    .hide-mobile {
      display: none;
    }
  }
</style>
