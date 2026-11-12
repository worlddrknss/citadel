<!--
  Version timeline from the board: a dot per version (accent for current),
  staging labels, author and time, and Restore for older versions. With
  `showValues` each version's value can be revealed and copied.
-->
<script lang="ts" module>
  import type { VersionInfo } from '../../api';
  export interface NumberedVersion extends VersionInfo {
    ordinal: number;
  }

  /**
   * Newest first. Uses the server's 1-based `version` ordinal when present
   * (timestamps have second resolution, so sorting by them can misorder
   * quick successive writes); older servers are numbered v1…vN by age.
   */
  export function numberVersions(vs: VersionInfo[]): NumberedVersion[] {
    if (vs.length && vs.every((v) => typeof v.version === 'number' && v.version > 0)) {
      return vs.map((v) => ({ ...v, ordinal: v.version as number })).sort((a, b) => b.ordinal - a.ordinal);
    }
    return [...vs]
      .sort((a, b) => new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime())
      .map((v, i) => ({ ...v, ordinal: i + 1 }))
      .reverse();
  }
</script>

<script lang="ts">
  import SecretValue from '$lib/components/SecretValue.svelte';
  import { fullDate } from '../../lib';

  let {
    versions,
    limit,
    showValues = false,
    canRestore,
    requireApproval,
    disabled = false,
    reveal,
    onrestore
  }: {
    versions: NumberedVersion[];
    limit?: number;
    showValues?: boolean;
    canRestore: boolean;
    requireApproval: boolean;
    disabled?: boolean;
    reveal: (versionId: string) => Promise<string>;
    onrestore: (v: NumberedVersion) => void;
  } = $props();

  const shown = $derived(limit ? versions.slice(0, limit) : versions);

  function stageClass(s: string) {
    if (s === 'AWSCURRENT') return 'stage-current';
    if (s === 'AWSPENDING') return 'badge-info';
    return '';
  }
</script>

<ol class="tl">
  {#each shown as v, i (v.versionId)}
    {@const current = v.stages.includes('AWSCURRENT')}
    <li class="item">
      <span class="rail" aria-hidden="true">
        <span class="dot" class:current></span>
        {#if i < shown.length - 1}<span class="line"></span>{/if}
      </span>
      <div class="body">
        <div class="head">
          <span class="mono ver" title={v.versionId}>v{v.ordinal}</span>
          {#each v.stages as s (s)}
            <span class="badge {stageClass(s)}">{s}</span>
          {/each}
          {#if canRestore && !current}
            <button
              type="button"
              class="btn btn-ghost btn-sm restore"
              {disabled}
              onclick={() => onrestore(v)}
              aria-label="{requireApproval ? 'Request restore of' : 'Restore'} version {v.ordinal}"
            >
              {requireApproval ? 'Request restore' : 'Restore'}
            </button>
          {/if}
        </div>
        <span class="subtle small">
          {v.createdBy ? `${v.createdBy} · ` : ''}<time datetime={v.createdAt}>{fullDate(v.createdAt)}</time>
        </span>
        {#if showValues}
          <div class="value">
            <SecretValue load={() => reveal(v.versionId)} hideAfter={30} />
          </div>
        {/if}
      </div>
    </li>
  {/each}
</ol>

<style>
  .tl {
    margin: 0;
    padding: 0;
    list-style: none;
  }
  .item {
    display: grid;
    grid-template-columns: 16px minmax(0, 1fr);
    gap: var(--space-3);
  }
  .rail {
    display: flex;
    flex-direction: column;
    align-items: center;
  }
  .dot {
    width: 10px;
    height: 10px;
    margin-top: 5px;
    border-radius: 50%;
    background: var(--surface-pressed);
    border: 2px solid var(--surface);
    box-shadow: 0 0 0 1px var(--border-strong);
    flex-shrink: 0;
  }
  .dot.current {
    background: var(--accent);
  }
  .line {
    flex: 1;
    width: 1px;
    background: var(--border);
  }
  .body {
    display: flex;
    flex-direction: column;
    gap: 2px;
    padding-bottom: 14px;
    min-width: 0;
  }
  .head {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: var(--space-2);
  }
  .ver {
    font-weight: 500;
  }
  .stage-current {
    background: var(--accent-soft);
    color: var(--accent-text);
  }
  .restore {
    margin-left: auto;
  }
  .value {
    margin-top: var(--space-1);
    padding: 4px 4px 4px 10px;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: var(--surface-hover);
    max-width: 100%;
    overflow: hidden;
  }
</style>
