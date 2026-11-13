<!-- Folder path control from the board's toolbar: "/ › stripe › …" with
     each ancestor a link. Paths live in the URL (`?path=`). -->
<script lang="ts">
  import Icon from '#lib/components/Icon.svelte';

  let {
    path,
    href,
    onnavigate
  }: {
    path: string;
    /** URL for a folder path, so links work with middle-click and copy. */
    href: (path: string) => string;
    onnavigate: (path: string) => void;
  } = $props();

  const segs = $derived(path.split('/').filter(Boolean));

  function go(e: MouseEvent, to: string) {
    if (e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return;
    e.preventDefault();
    onnavigate(to);
  }
</script>

<div class="crumb">
  <span class="ic" aria-hidden="true"><Icon name="folder" size={14} /></span>
  <nav aria-label="Folder">
    <ol class="mono">
      <li>
        {#if segs.length === 0}
          <span aria-current="page" class="cur">/</span>
        {:else}
          <a href={href('/')} onclick={(e) => go(e, '/')} aria-label="Environment root">/</a>
        {/if}
      </li>
      {#each segs as seg, i (i)}
        {@const to = '/' + segs.slice(0, i + 1).join('/')}
        <li aria-hidden="true" class="sep">›</li>
        <li>
          {#if i === segs.length - 1}
            <span aria-current="page" class="cur">{seg}</span>
          {:else}
            <a href={href(to)} onclick={(e) => go(e, to)}>{seg}</a>
          {/if}
        </li>
      {/each}
    </ol>
  </nav>
</div>

<style>
  .crumb {
    display: flex;
    align-items: center;
    gap: var(--space-1);
    height: var(--ctl-h);
    padding: 0 10px;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: var(--surface-hover);
    min-width: 0;
    max-width: 100%;
    overflow-x: auto;
    scrollbar-width: none;
  }
  .ic {
    display: inline-flex;
    color: var(--text-subtle);
  }
  ol {
    display: flex;
    align-items: center;
    gap: var(--space-1);
    margin: 0;
    padding: 0;
    list-style: none;
    white-space: nowrap;
  }
  a {
    color: var(--text-muted);
  }
  a:hover {
    color: var(--text);
  }
  .cur {
    color: var(--text);
  }
  .sep {
    color: var(--text-subtle);
  }
</style>
