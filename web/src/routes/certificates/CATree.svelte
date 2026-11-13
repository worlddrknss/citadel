<!-- CA hierarchy card: roots with their subordinates nested beneath, then the
     public issuer (Let's Encrypt). -->
<script lang="ts">
  import Icon from '$lib/components/Icon.svelte';
  import Badge from '$lib/components/Badge.svelte';
  import type { CertRow } from './api';
  import { cnOf, keyAlgLabel, yearOf, titleCase, rowKey } from './certs';

  let {
    cas,
    loading,
    selected,
    canCreate,
    le,
    onselect,
    onnew,
    onle
  }: {
    cas: CertRow[];
    loading: boolean;
    selected: string;
    canCreate: boolean;
    le: { environment: string; contactEmail: string } | null;
    onselect: (ca: CertRow) => void;
    onnew: () => void;
    onle: () => void;
  } = $props();

  interface Node {
    ca: CertRow;
    depth: number;
  }

  // Depth-first order so each subordinate renders right under its parent.
  const nodes = $derived.by(() => {
    const ids = new Set(cas.map((c) => c.id));
    const children = new Map<string, CertRow[]>();
    const roots: CertRow[] = [];
    for (const c of cas) {
      if (c.parentCaId && ids.has(c.parentCaId) && c.parentCaId !== c.id) {
        const list = children.get(c.parentCaId) ?? [];
        list.push(c);
        children.set(c.parentCaId, list);
      } else roots.push(c);
    }
    const byName = (a: CertRow, b: CertRow) => cnOf(a.subject).localeCompare(cnOf(b.subject));
    const out: Node[] = [];
    const seen = new Set<string>();
    const walk = (c: CertRow, depth: number) => {
      if (seen.has(c.id)) return;
      seen.add(c.id);
      out.push({ ca: c, depth });
      for (const k of (children.get(c.id) ?? []).sort(byName)) walk(k, depth + 1);
    };
    // Roots first, then CAs created as "subordinate" without a known parent.
    roots.sort((a, b) => Number(a.caType === 'SUBORDINATE') - Number(b.caType === 'SUBORDINATE') || byName(a, b));
    for (const r of roots) walk(r, 0);
    return out;
  });

  function statusTone(s?: string) {
    const u = (s ?? '').toUpperCase();
    if (u === 'ACTIVE') return 'success' as const;
    if (u === 'DISABLED' || u === 'EXPIRED' || u === 'DELETED') return 'danger' as const;
    return 'neutral' as const;
  }

  function meta(ca: CertRow): string {
    const parts = [ca.caType === 'SUBORDINATE' ? 'Subordinate' : 'Root'];
    const k = keyAlgLabel(ca.keyAlgorithm);
    if (k) parts.push(k);
    const y = yearOf(ca.notAfter);
    if (y) parts.push(`valid to ${y}`);
    return parts.join(' · ');
  }

  const envLabel: Record<string, string> = { production: 'Production', staging: 'Staging', custom: 'Custom directory' };
</script>

<section class="card tree" aria-labelledby="ca-title">
  <div class="card-head">
    <h2 id="ca-title">CA hierarchy</h2>
    {#if canCreate}
      <button type="button" class="btn btn-ghost btn-sm" onclick={onnew}><Icon name="plus" size={14} />New CA</button>
    {/if}
  </div>

  {#if loading && cas.length === 0}
    <ul class="nodes" aria-busy="true" aria-label="Loading certificate authorities">
      {#each [0, 1, 1] as d, i (i)}
        <li style:padding-left="{d * 24}px"><div class="node skel"><span class="skeleton sk-ic"></span><span class="skeleton sk-line"></span></div></li>
      {/each}
    </ul>
  {:else if nodes.length === 0}
    <div class="none">
      <p class="muted small">No private CAs yet. Create a root CA to start issuing internal certificates.</p>
      {#if canCreate}
        <button type="button" class="btn btn-secondary btn-sm" onclick={onnew}><Icon name="plus" size={14} />Create root CA</button>
      {/if}
    </div>
  {:else}
    <ul class="nodes">
      {#each nodes as n (n.ca.id)}
        <li style:padding-left="{n.depth * 24}px">
          {#if n.depth > 0}<span class="guide" aria-hidden="true" style:left="{n.depth * 24 - 14}px"></span>{/if}
          <button
            type="button"
            class="node"
            class:sel={selected === rowKey(n.ca)}
            aria-current={selected === rowKey(n.ca) ? 'true' : undefined}
            onclick={() => onselect(n.ca)}
          >
            <span class="ic" class:root={n.ca.caType !== 'SUBORDINATE'}>
              <Icon name={n.ca.caType === 'SUBORDINATE' ? 'git-pull-request' : 'shield-check'} size={14} />
            </span>
            <span class="txt">
              <span class="name">{cnOf(n.ca.subject) || n.ca.id}</span>
              <span class="subtle meta">{meta(n.ca)}</span>
            </span>
            <Badge tone={statusTone(n.ca.status)} dot={false}>{titleCase(n.ca.status || 'Unknown')}</Badge>
          </button>
        </li>
      {/each}
    </ul>
  {/if}

  <div class="public">
    <span class="label">Public issuers</span>
    <button type="button" class="pub" onclick={onle}>
      <span class="ic info"><Icon name="external-link" size={14} /></span>
      <span class="txt">
        <span class="name">Let's Encrypt (ACME)</span>
        <span class="subtle meta">
          {#if le}
            {envLabel[le.environment] ?? 'Staging'} · HTTP-01 or manual DNS-01{le.contactEmail ? ` · ${le.contactEmail}` : ''}
          {:else}
            Not configured
          {/if}
        </span>
      </span>
      {#if le}<Badge tone="info" dot={false}>Connected</Badge>{:else}<Badge dot={false}>Set up</Badge>{/if}
    </button>
  </div>
</section>

<style>
  .tree {
    flex: 1 1 340px;
    max-width: 420px;
    min-width: 0;
    align-self: flex-start;
    overflow: hidden;
  }
  .card-head h2 {
    font-family: var(--font-sans);
    font-size: var(--text-md);
    letter-spacing: 0;
  }
  .nodes {
    list-style: none;
    margin: 0;
    padding: 4px 16px 16px;
  }
  .nodes li {
    position: relative;
  }
  .guide {
    position: absolute;
    top: 0;
    width: 12px;
    height: 28px;
    border-left: 1px solid var(--border-strong);
    border-bottom: 1px solid var(--border-strong);
    border-bottom-left-radius: 6px;
  }
  .node,
  .pub {
    display: flex;
    align-items: center;
    gap: 10px;
    width: 100%;
    padding: 10px 12px;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: var(--surface);
    color: var(--text);
    font: inherit;
    text-align: start;
    cursor: pointer;
  }
  .node {
    margin-top: 8px;
  }
  .node:hover,
  .pub:hover {
    background: var(--surface-hover);
  }
  .node.sel {
    border-color: var(--accent);
    background: var(--accent-soft);
  }
  .node.skel {
    cursor: default;
  }
  .sk-ic {
    width: 28px;
    height: 28px;
    border-radius: 8px;
  }
  .sk-line {
    height: 12px;
    width: 60%;
  }
  .ic {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    flex: none;
    width: 28px;
    height: 28px;
    border-radius: 8px;
    background: var(--surface-pressed);
    color: var(--text-muted);
  }
  .ic.root {
    background: var(--accent-soft);
    color: var(--accent-text);
  }
  .ic.info {
    background: var(--info-soft);
    color: var(--info);
  }
  .txt {
    display: flex;
    flex-direction: column;
    flex: 1 1 auto;
    min-width: 0;
  }
  .name {
    font-weight: 600;
    font-size: 14px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .meta {
    font-size: 13px;
    line-height: 16px;
  }
  .none {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: 10px;
    padding: 16px;
  }
  .none p {
    margin: 0;
  }
  .public {
    display: flex;
    flex-direction: column;
    gap: 8px;
    padding: 12px 16px;
    border-top: 1px solid var(--border);
  }
  .pub {
    padding: 0;
    border: 0;
    background: none;
  }
  .pub:hover {
    background: none;
  }
  .pub:hover .name {
    color: var(--accent-text);
    text-decoration: underline;
  }
  .label {
    font-size: var(--text-xs);
    font-weight: 600;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    color: var(--text-subtle);
  }
  @media (max-width: 820px) {
    .tree {
      max-width: none;
    }
  }
</style>
