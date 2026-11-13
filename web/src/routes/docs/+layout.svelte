<!--
  Docs layout: a searchable, grouped nav of the repository's docs/*.md next
  to the page. On narrow screens the nav folds into a disclosure.
-->
<script lang="ts">
  import { page } from '$app/state';
  import { afterNavigate } from '$app/navigation';
  import { base } from '#lib/paths.ts';
  import Icon from '#lib/components/Icon.svelte';
  import { DOCS_NAV, allSections } from './content';
  import { isDoc } from './nav';
  import { searchDocs } from './markdown';

  let { children } = $props();

  let query = $state('');
  let navOpen = $state(false);

  const current = $derived(decodeURIComponent(page.url.pathname.slice(`${base}/docs`.length).replace(/^\/|\/$/g, '')));
  const hits = $derived(query.trim() ? searchDocs(allSections(), query) : []);
  const hitHref = (h: (typeof hits)[number]) => `${base}/docs/${h.section.slug}${h.section.id ? `#${h.section.id}` : ''}`;

  afterNavigate(() => {
    navOpen = false;
  });

  function onSearchKey(e: KeyboardEvent) {
    if (e.key === 'Escape' && query) {
      e.stopPropagation();
      query = '';
    } else if (e.key === 'ArrowDown' && hits.length) {
      e.preventDefault();
      document.querySelector<HTMLAnchorElement>('.hits a')?.focus();
    }
  }
  function onHitsKey(e: KeyboardEvent) {
    const links = [...document.querySelectorAll<HTMLAnchorElement>('.hits a')];
    const i = links.indexOf(document.activeElement as HTMLAnchorElement);
    if (e.key === 'ArrowDown' && i < links.length - 1) {
      e.preventDefault();
      links[i + 1].focus();
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (i > 0) links[i - 1].focus();
      else document.getElementById('docs-search')?.focus();
    }
  }
</script>

<div class="docs">
  <aside class="docnav" aria-label="Documentation">
    <label class="search">
      <span class="sr-only">Search the docs</span>
      <Icon name="search" />
      <input id="docs-search" class="input" type="search" bind:value={query} onkeydown={onSearchKey} placeholder="Search the docs" autocomplete="off" spellcheck="false" />
    </label>

    {#if query.trim()}
      <p class="sr-only" role="status" aria-live="polite">{hits.length ? `${hits.length} results` : 'No results'}</p>
      {#if hits.length}
        <ul class="hits" aria-label="Search results">
          {#each hits as h (h.section.slug + h.section.id)}
            <li>
              <a href={hitHref(h)} onkeydown={onHitsKey} onclick={() => (query = '')}>
                <span class="hit-title">{h.section.heading}</span>
                {#if h.section.depth > 1}<span class="hit-doc subtle">{h.section.docTitle}</span>{/if}
                {#if h.in === 'text' && h.snippet}<span class="hit-snip muted">{h.snippet}</span>{/if}
              </a>
            </li>
          {/each}
        </ul>
      {:else}
        <p class="nohits subtle small">No matches. Try a different word, or an error reason such as <span class="mono">no_grant</span>.</p>
      {/if}
    {:else}
      <details class="navfold" bind:open={navOpen}>
        <summary><Icon name="menu" size={16} />Browse the docs</summary>
      </details>
      <nav class="groups" class:open={navOpen} aria-label="Docs pages">
        <a class="item home" href="{base}/docs" aria-current={current === '' ? 'page' : undefined}><Icon name="book" size={16} />Overview</a>
        {#each DOCS_NAV as g (g.label)}
          <div class="group">
            <div class="glabel">{g.label}</div>
            <ul>
              {#each g.items as item (isDoc(item) ? item.slug : item.href)}
                <li>
                  {#if isDoc(item)}
                    <a class="item" href="{base}/docs/{item.slug}" aria-current={current === item.slug ? 'page' : undefined}>{item.label}</a>
                  {:else}
                    <a class="item" href="{base}{item.href}">{item.label}<Icon name="chevron-right" size={12} /></a>
                  {/if}
                </li>
              {/each}
            </ul>
          </div>
        {/each}
      </nav>
    {/if}
  </aside>

  <div class="docmain">
    {@render children()}
  </div>
</div>

<style>
  .docs {
    display: grid;
    grid-template-columns: 236px minmax(0, 1fr);
    gap: var(--space-10);
    align-items: start;
  }
  .docnav {
    position: sticky;
    top: calc(var(--topbar-h) + var(--space-6));
    max-height: calc(100dvh - var(--topbar-h) - var(--space-12));
    overflow-y: auto;
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
    padding-right: var(--space-1);
  }
  .search {
    position: relative;
    display: block;
  }
  .search :global(svg) {
    position: absolute;
    left: 10px;
    top: 50%;
    transform: translateY(-50%);
    color: var(--text-subtle);
    pointer-events: none;
  }
  .search .input {
    width: 100%;
    padding-left: 32px;
  }
  .navfold {
    display: none;
  }
  .groups {
    display: flex;
    flex-direction: column;
    gap: var(--space-5);
  }
  .group ul,
  .hits {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .glabel {
    margin-bottom: var(--space-1);
    padding: 0 10px;
    font-size: var(--text-xs);
    font-weight: 600;
    line-height: 16px;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    color: var(--text-subtle);
  }
  .item {
    display: flex;
    align-items: center;
    gap: 8px;
    min-height: 32px;
    padding: 5px 10px;
    border-radius: var(--radius-md);
    color: var(--text-muted);
    font-size: var(--text-base);
    line-height: 1.35;
  }
  .item :global(svg) {
    flex: none;
    color: var(--text-subtle);
  }
  .item:hover {
    background: var(--surface-pressed);
    color: var(--text);
    text-decoration: none;
  }
  .item[aria-current='page'] {
    background: var(--surface);
    color: var(--text);
    font-weight: 500;
    box-shadow: var(--shadow-xs), inset 0 0 0 1px var(--border);
  }
  .item[aria-current='page'] :global(svg) {
    color: var(--accent);
  }
  .hits a {
    display: flex;
    flex-direction: column;
    gap: 2px;
    padding: 8px 10px;
    border-radius: var(--radius-md);
    color: var(--text);
  }
  .hits a:hover,
  .hits a:focus-visible {
    background: var(--surface-pressed);
    text-decoration: none;
  }
  .hit-title {
    font-weight: 500;
    line-height: 1.35;
  }
  .hit-doc,
  .hit-snip {
    font-size: var(--text-sm);
    line-height: 1.4;
  }
  .hit-snip {
    overflow-wrap: anywhere;
  }
  .nohits {
    margin: 0;
    padding: 0 10px;
  }
  .docmain {
    min-width: 0;
  }

  @media (max-width: 1000px) {
    .docs {
      grid-template-columns: minmax(0, 1fr);
      gap: var(--space-5);
    }
    .docnav {
      position: static;
      max-height: none;
      overflow: visible;
      padding: 0;
    }
    .navfold {
      display: block;
    }
    .navfold summary {
      display: flex;
      align-items: center;
      gap: 8px;
      height: var(--ctl-h);
      padding: 0 var(--space-3);
      border: 1px solid var(--border);
      border-radius: var(--radius-md);
      background: var(--surface);
      font-weight: 500;
      cursor: pointer;
    }
    .groups:not(.open) {
      display: none;
    }
  }
</style>
