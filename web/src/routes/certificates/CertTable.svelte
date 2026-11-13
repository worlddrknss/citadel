<!-- Certificates card: leaf certificates from every private CA, from
     Let's Encrypt and imported through ACM, with a lifetime-remaining bar. -->
<script lang="ts">
  import Icon from '#lib/components/Icon.svelte';
  import Badge from '#lib/components/Badge.svelte';
  import EmptyState from '#lib/components/EmptyState.svelte';
  import Seg from './Seg.svelte';
  import RowMenu, { type MenuItem } from './RowMenu.svelte';
  import type { CertRow } from './api';
  import { certStatus, daysLeft, lifetimeDays, isRevoked, isExpiring, isImported, canRenewOrRevoke, sourceLabel, fmtDate, rowKey, type Filter, type SortKey } from './certs';


  let {
    rows,
    loading,
    filter,
    sort,
    dir,
    selected,
    nameOf,
    issuerOf,
    canIssue,
    canRevoke,
    onfilter,
    onsort,
    onopen,
    onrenew,
    onrevoke,
    ondelete,
    onissue
  }: {
    rows: CertRow[];
    loading: boolean;
    filter: Filter;
    sort: SortKey;
    dir: 'asc' | 'desc';
    selected: string;
    nameOf: (c: CertRow) => string;
    issuerOf: (c: CertRow) => string;
    canIssue: boolean;
    canRevoke: boolean;
    onfilter: (f: Filter) => void;
    onsort: (k: SortKey, d: 'asc' | 'desc') => void;
    onopen: (c: CertRow) => void;
    onrenew: (c: CertRow) => void;
    onrevoke: (c: CertRow) => void;
    ondelete: (c: CertRow) => void;
    onissue: () => void;
  } = $props();

  const counts = $derived({
    all: rows.length,
    expiring: rows.filter(isExpiring).length,
    revoked: rows.filter(isRevoked).length
  });

  const visible = $derived.by(() => {
    let out = rows;
    if (filter === 'expiring') out = out.filter(isExpiring);
    else if (filter === 'revoked') out = out.filter(isRevoked);
    const m = dir === 'asc' ? 1 : -1;
    return [...out].sort((a, b) => {
      if (sort === 'name') return nameOf(a).localeCompare(nameOf(b), undefined, { numeric: true }) * m;
      // Revoked rows always sink below live ones when sorting by time left.
      const ra = isRevoked(a) ? 1 : 0;
      const rb = isRevoked(b) ? 1 : 0;
      if (ra !== rb) return ra - rb;
      return ((daysLeft(a.notAfter) ?? Infinity) - (daysLeft(b.notAfter) ?? Infinity)) * m;
    });
  });

  let filterValue = $state<Filter>('all');
  $effect(() => {
    filterValue = filter;
  });

  function sortBy(k: SortKey) {
    onsort(k, sort === k ? (dir === 'asc' ? 'desc' : 'asc') : 'asc');
  }

  function ariaSort(k: SortKey) {
    return sort === k ? (dir === 'asc' ? 'ascending' : 'descending') : 'none';
  }

  function menu(c: CertRow): MenuItem[] {
    const items: MenuItem[] = [{ label: 'View details', icon: 'file', onselect: () => onopen(c) }];
    if (canRenewOrRevoke(c) && canIssue) items.push({ label: 'Renew', icon: 'refresh', onselect: () => onrenew(c) });
    if (canRenewOrRevoke(c) && canRevoke) items.push({ label: 'Revoke', icon: 'x', danger: true, onselect: () => onrevoke(c) });
    // Imported certificates are read-only apart from deletion (an admin action, like revoke).
    if (isImported(c) && canRevoke) items.push({ label: 'Delete', icon: 'trash', danger: true, onselect: () => ondelete(c) });
    return items;
  }

  function barColor(tone: string) {
    return tone === 'danger' ? 'var(--danger)' : tone === 'warning' ? 'var(--warning)' : 'var(--accent)';
  }
</script>

<section class="card certs" aria-labelledby="ct-title">
  <div class="card-head">
    <h2 id="ct-title">Certificates</h2>
    <Seg
      label="Filter certificates"
      bind:value={filterValue}
      onchange={onfilter}
      options={[
        { value: 'all', label: 'All', count: counts.all },
        { value: 'expiring', label: 'Expiring', count: counts.expiring },
        { value: 'revoked', label: 'Revoked', count: counts.revoked }
      ]}
    />
  </div>

  {#if !loading && rows.length === 0}
    <div class="empty-wrap">
      <EmptyState
        icon="award"
        title="No certificates yet"
        description="Issue one from a private CA, or request a public certificate from Let's Encrypt."
      >
        {#if canIssue}
          <button type="button" class="btn btn-primary btn-sm" onclick={onissue}><Icon name="plus" size={14} />Issue certificate</button>
        {/if}
      </EmptyState>
    </div>
  {:else}
    <div class="scroll">
      <table class="table">
        <caption class="sr-only">Certificates</caption>
        <thead>
          <tr>
            <th scope="col" aria-sort={ariaSort('name')}>
              <button type="button" class="th-sort" onclick={() => sortBy('name')}>
                Common name
                <Icon name={sort === 'name' ? (dir === 'asc' ? 'arrow-up' : 'arrow-down') : 'arrow-up-down'} size={12} />
              </button>
            </th>
            <th scope="col">Issuer</th>
            <th scope="col">Source</th>
            <th scope="col">Status</th>
            <th scope="col" aria-sort={ariaSort('left')}>
              <button type="button" class="th-sort" onclick={() => sortBy('left')}>
                Time left
                <Icon name={sort === 'left' ? (dir === 'asc' ? 'arrow-up' : 'arrow-down') : 'arrow-up-down'} size={12} />
              </button>
            </th>
            <th scope="col" class="act"><span class="sr-only">Actions</span></th>
          </tr>
        </thead>
        <tbody>
          {#if loading && rows.length === 0}
            {#each Array(5) as _, i (i)}
              <tr>
                {#each Array(6) as __, j (j)}<td><span class="skeleton sk"></span></td>{/each}
              </tr>
            {/each}
          {:else}
            {#each visible as c (rowKey(c))}
              {@const st = certStatus(c)}
              {@const left = daysLeft(c.notAfter)}
              {@const life = lifetimeDays(c.notBefore, c.notAfter)}
              <tr class:selected={selected === rowKey(c)}>
                <td>
                  <button type="button" class="row-link mono cn" onclick={() => onopen(c)}>{nameOf(c)}</button>
                </td>
                <td class="muted">{issuerOf(c)}</td>
                <td><span class="badge outline">{sourceLabel(c.source)}</span></td>
                <td>
                  <Badge tone={st.tone} dot={false}><Icon name={st.icon} size={12} />{st.label}</Badge>
                </td>
                <td>
                  {#if isRevoked(c)}
                    <span class="subtle small">Revoked{c.revokedAt ? ` ${fmtDate(c.revokedAt)}` : ''}</span>
                  {:else if left === null}
                    <span class="subtle small">—</span>
                  {:else}
                    {@const pct = life ? Math.max(0, Math.min(100, (left / life) * 100)) : 0}
                    <div class="life">
                      <div
                        class="meter"
                        role="meter"
                        aria-label="Lifetime remaining"
                        aria-valuemin={0}
                        aria-valuemax={life ?? Math.max(left, 0)}
                        aria-valuenow={Math.max(left, 0)}
                      >
                        <div style:width="{pct}%" style:background={barColor(st.tone)}></div>
                      </div>
                      <span class="days num" class:danger={st.tone === 'danger'}>
                        {left < 0 ? `${-left} days ago` : `${left} day${left === 1 ? '' : 's'}`}
                      </span>
                    </div>
                  {/if}
                </td>
                <td class="act"><RowMenu label="More actions for {nameOf(c)}" items={menu(c)} /></td>
              </tr>
            {:else}
              <tr>
                <td colspan="6" class="nomatch">
                  <span class="muted">No {filter === 'revoked' ? 'revoked' : 'expiring'} certificates.</span>
                  <button type="button" class="btn btn-ghost btn-sm" onclick={() => onfilter('all')}>Show all</button>
                </td>
              </tr>
            {/each}
          {/if}
        </tbody>
      </table>
    </div>
  {/if}
</section>

<style>
  .certs {
    flex: 999 1 560px;
    min-width: 0;
    overflow: hidden;
  }
  .card-head {
    flex-wrap: wrap;
  }
  .card-head h2 {
    font-family: var(--font-sans);
    font-size: var(--text-md);
    letter-spacing: 0;
  }
  .scroll {
    overflow-x: auto;
  }
  .table {
    min-width: 780px;
  }
  .table td {
    white-space: nowrap;
  }
  .th-sort {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 0;
    border: 0;
    background: none;
    color: inherit;
    font: inherit;
    letter-spacing: inherit;
    text-transform: inherit;
    cursor: pointer;
  }
  .th-sort:hover {
    color: var(--text);
  }
  .cn {
    font-family: var(--font-mono);
    font-size: 13.5px;
  }
  .badge.outline {
    background: transparent;
    color: var(--text-muted);
    box-shadow: inset 0 0 0 1px var(--border-strong);
    font-size: 12.5px;
  }
  .life {
    display: flex;
    align-items: center;
    gap: 10px;
    min-width: 200px;
  }
  .meter {
    flex: 1 1 120px;
    height: 6px;
    border-radius: 999px;
    background: var(--surface-pressed);
    overflow: hidden;
  }
  .meter > div {
    height: 100%;
  }
  .days {
    min-width: 64px;
    font-size: 13.5px;
    font-weight: 500;
    color: var(--text-muted);
  }
  .days.danger {
    color: var(--danger);
  }
  .act {
    width: 48px;
    text-align: end;
  }
  .sk {
    display: block;
    height: 12px;
    width: 70%;
  }
  .nomatch {
    text-align: center;
    padding: var(--space-6);
  }
  .empty-wrap {
    padding: var(--space-8) var(--space-5);
  }
</style>
