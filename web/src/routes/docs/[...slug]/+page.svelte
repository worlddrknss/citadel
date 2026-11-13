<!--
  A docs page rendered from docs/<slug>.md, with an "On this page" table of
  contents that follows the reader; /docs itself is the docs home.
-->
<script lang="ts">
  import { page } from '$app/state';
  import { base } from '#lib/paths.ts';
  import Icon from '#lib/components/Icon.svelte';
  import EmptyState from '#lib/components/EmptyState.svelte';
  import { toast } from '#lib/stores/toast.svelte.ts';
  import { DOCS_NAV, ORDER, getDoc, summaryOf } from '../content';
  import { isDoc } from '../nav';
  import { REPO_URL } from '../markdown';

  const slug = $derived((page.params.slug ?? '').replace(/\/$/, ''));
  const doc = $derived(slug ? getDoc(slug) : null);
  const toc = $derived(doc ? doc.headings.filter((h) => h.depth === 2 || h.depth === 3) : []);
  const idx = $derived(ORDER.indexOf(slug));
  const label = (s: string) => DOCS_NAV.flatMap((g) => g.items).find((i) => isDoc(i) && i.slug === s)?.label ?? s;
  const prev = $derived(idx > 0 ? ORDER[idx - 1] : null);
  const next = $derived(idx >= 0 && idx < ORDER.length - 1 ? ORDER[idx + 1] : null);

  let article = $state<HTMLElement>();
  let activeId = $state('');

  // A deep link opened directly (/docs/x#heading): the page renders after the
  // session check, too late for the browser's own jump, so jump once here.
  let jumped = '';
  $effect(() => {
    void doc;
    if (!article || !location.hash || jumped === location.href) return;
    jumped = location.href;
    document.getElementById(decodeURIComponent(location.hash.slice(1)))?.scrollIntoView();
  });

  // Highlight the section being read: the last heading above the top third.
  $effect(() => {
    void doc;
    if (!article || typeof IntersectionObserver === 'undefined') return;
    const hs = [...article.querySelectorAll<HTMLElement>('h2[id], h3[id]')];
    activeId = '';
    const visible = new Set<string>();
    const io = new IntersectionObserver(
      (entries) => {
        for (const e of entries) {
          if (e.isIntersecting) visible.add(e.target.id);
          else visible.delete(e.target.id);
        }
        const first = hs.find((h) => visible.has(h.id));
        if (first) activeId = first.id;
        else {
          const above = hs.filter((h) => h.getBoundingClientRect().top < 0);
          if (above.length) activeId = above[above.length - 1].id;
        }
      },
      { rootMargin: '-64px 0px -60% 0px' }
    );
    hs.forEach((h) => io.observe(h));
    return () => io.disconnect();
  });

  async function onArticleClick(e: MouseEvent) {
    const btn = (e.target as HTMLElement).closest<HTMLButtonElement>('button[data-copy]');
    if (!btn) return;
    const code = btn.closest('.codeblock')?.querySelector('code')?.textContent ?? '';
    try {
      await navigator.clipboard.writeText(code);
      const span = btn.querySelector('span');
      btn.setAttribute('aria-label', 'Copied');
      if (span) span.textContent = 'Copied';
      setTimeout(() => {
        btn.setAttribute('aria-label', 'Copy code');
        if (span) span.textContent = 'Copy';
      }, 1500);
    } catch (err) {
      toast.error(err, 'Copy failed');
    }
  }
</script>

<svelte:head>
  <title>{doc ? `${doc.title} · Docs · Citadel` : 'Docs · Citadel'}</title>
</svelte:head>

{#if !slug}
  <div class="home">
    <header class="homehead">
      <h1>Documentation</h1>
      <p class="lede">Guides and reference for running Citadel and using it from apps, pipelines and AI agents. These pages ship with this Citadel, so they match the version you are running.</p>
      <div class="starts">
        <a class="btn btn-primary" href="{base}/docs/getting-started"><Icon name="play" size={14} />Get started</a>
        <a class="btn btn-secondary" href="{base}/docs/getting-started-agents"><Icon name="bot" size={14} />Set up an AI agent</a>
      </div>
    </header>
    {#each DOCS_NAV as g (g.label)}
      <section class="hgroup" aria-labelledby="g-{g.label.replace(/\W+/g, '-')}">
        <h2 id="g-{g.label.replace(/\W+/g, '-')}">{g.label}</h2>
        <ul class="cards">
          {#each g.items as item (isDoc(item) ? item.slug : item.href)}
            <li>
              <a class="cardlink card" href={isDoc(item) ? `${base}/docs/${item.slug}` : `${base}${item.href}`}>
                <span class="ctitle">{item.label}<Icon name="chevron-right" size={14} /></span>
                <span class="csum muted">{isDoc(item) ? summaryOf(item.slug) : 'Every /v1 operation, rendered from the OpenAPI document this server serves.'}</span>
              </a>
            </li>
          {/each}
        </ul>
      </section>
    {/each}
  </div>
{:else if !doc}
  <h1 class="sr-only">Page not found</h1>
  <div class="card card-pad">
    <EmptyState icon="file" title="No such page" description="This docs page doesn't exist in this version of Citadel.">
      <a class="btn btn-secondary btn-sm" href="{base}/docs">All docs</a>
    </EmptyState>
  </div>
{:else}
  <div class="page">
    <div class="readcol">
      {#if toc.length}
        <details class="tocfold">
          <summary>On this page</summary>
          <ul class="toclist">
            {#each toc as h (h.id)}
              <li class:sub={h.depth === 3}><a href="#{h.id}">{h.text}</a></li>
            {/each}
          </ul>
        </details>
      {/if}
      <!-- Delegated clicks on the code blocks' copy buttons. -->
      <!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_noninteractive_element_interactions -->
      <article class="prose" bind:this={article} onclick={onArticleClick}>
        <!-- Rendered from the repository's own Markdown and sanitized with DOMPurify (markdown.ts). -->
        {@html doc.html}
      </article>
      <footer class="docfoot">
        <nav class="pager" aria-label="Previous and next page">
          {#if prev}<a class="card pg" href="{base}/docs/{prev}"><span class="subtle small">Previous</span><span class="pgt"><Icon name="chevron-left" size={14} />{label(prev)}</span></a>{:else}<span></span>{/if}
          {#if next}<a class="card pg nextpg" href="{base}/docs/{next}"><span class="subtle small">Next</span><span class="pgt">{label(next)}<Icon name="chevron-right" size={14} /></span></a>{/if}
        </nav>
        <a class="small src" href="{REPO_URL}/blob/main/docs/{slug}.md" target="_blank" rel="noopener noreferrer">View this page's source on GitHub<Icon name="external-link" size={12} /></a>
      </footer>
    </div>
    {#if toc.length}
      <nav class="toc" aria-label="On this page">
        <div class="toclabel">On this page</div>
        <ul class="toclist">
          {#each toc as h (h.id)}
            <li class:sub={h.depth === 3}><a href="#{h.id}" aria-current={activeId === h.id ? 'location' : undefined}>{h.text}</a></li>
          {/each}
        </ul>
      </nav>
    {/if}
  </div>
{/if}

<style>
  /* ---- home ---- */
  .home {
    display: flex;
    flex-direction: column;
    gap: var(--space-8);
    max-width: 980px;
  }
  .homehead h1 {
    margin: 0 0 var(--space-2);
    font-size: var(--text-3xl);
    line-height: 1.15;
  }
  .lede {
    margin: 0 0 var(--space-4);
    max-width: 68ch;
    color: var(--text-muted);
    font-size: var(--text-md);
    line-height: 1.6;
  }
  .starts {
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-2);
  }
  .hgroup h2 {
    margin: 0 0 var(--space-3);
    font-size: var(--text-lg);
  }
  .cards {
    list-style: none;
    margin: 0;
    padding: 0;
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
    gap: var(--space-3);
  }
  .cardlink {
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
    height: 100%;
    padding: var(--space-4);
    color: var(--text);
  }
  .cardlink:hover {
    text-decoration: none;
    border-color: var(--border-strong);
    box-shadow: var(--shadow-sm);
  }
  .ctitle {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--space-2);
    font-weight: 600;
  }
  .ctitle :global(svg) {
    color: var(--text-subtle);
  }
  .csum {
    font-size: var(--text-sm);
    line-height: 1.5;
  }

  /* ---- page ---- */
  .page {
    display: grid;
    grid-template-columns: minmax(0, 760px) 208px;
    gap: var(--space-10);
    align-items: start;
  }
  .readcol {
    min-width: 0;
  }
  .toc {
    position: sticky;
    top: calc(var(--topbar-h) + var(--space-6));
    max-height: calc(100dvh - var(--topbar-h) - var(--space-12));
    overflow-y: auto;
  }
  .toclabel {
    margin-bottom: var(--space-2);
    font-size: var(--text-xs);
    font-weight: 600;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    color: var(--text-subtle);
  }
  .toclist {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .toclist a {
    display: block;
    padding: 3px 0 3px 10px;
    border-left: 2px solid var(--border);
    color: var(--text-muted);
    font-size: var(--text-sm);
    line-height: 1.4;
  }
  .toclist .sub a {
    padding-left: 22px;
  }
  .toclist a:hover {
    color: var(--text);
    text-decoration: none;
  }
  .toclist a[aria-current='location'] {
    border-left-color: var(--accent);
    color: var(--accent-text);
    font-weight: 500;
  }
  .tocfold {
    display: none;
    margin-bottom: var(--space-5);
    padding: var(--space-2) var(--space-3);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: var(--surface);
  }
  .tocfold summary {
    cursor: pointer;
    font-weight: 500;
  }
  .tocfold .toclist {
    margin-top: var(--space-2);
  }
  .docfoot {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
    margin-top: var(--space-12);
    padding-top: var(--space-6);
    border-top: 1px solid var(--border);
  }
  .pager {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: var(--space-3);
  }
  .pg {
    display: flex;
    flex-direction: column;
    gap: 2px;
    padding: var(--space-3) var(--space-4);
    color: var(--text);
  }
  .pg:hover {
    text-decoration: none;
    border-color: var(--border-strong);
  }
  .nextpg {
    grid-column: 2;
    text-align: end;
    align-items: flex-end;
  }
  .pgt {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    font-weight: 500;
  }
  .src {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    align-self: flex-start;
    color: var(--text-subtle);
  }

  /* ---- long-form typography ---- */
  .prose {
    color: var(--text);
    font-size: var(--text-md);
    line-height: 1.7;
    overflow-wrap: break-word;
  }
  .prose :global(h1) {
    margin: 0 0 var(--space-5);
    font-size: var(--text-3xl);
    line-height: 1.15;
  }
  .prose :global(h2) {
    margin: var(--space-12) 0 var(--space-3);
    padding-top: var(--space-2);
    font-size: var(--text-xl);
    line-height: 1.3;
  }
  .prose :global(h3) {
    margin: var(--space-8) 0 var(--space-2);
    font-size: var(--text-lg);
    line-height: 1.4;
  }
  .prose :global(h4) {
    margin: var(--space-6) 0 var(--space-2);
    font-size: var(--text-md);
  }
  .prose :global(:is(h1, h2, h3, h4)) {
    scroll-margin-top: calc(var(--topbar-h) + var(--space-4));
  }
  .prose :global(.anchor) {
    margin-left: 8px;
    color: var(--text-subtle);
    font-weight: 400;
    opacity: 0;
    text-decoration: none;
  }
  .prose :global(:is(h2, h3, h4):hover .anchor),
  .prose :global(.anchor:focus-visible) {
    opacity: 1;
  }
  .prose :global(p),
  .prose :global(ul),
  .prose :global(ol) {
    margin: 0 0 var(--space-4);
  }
  .prose :global(ul),
  .prose :global(ol) {
    padding-left: 1.4em;
  }
  .prose :global(li + li),
  .prose :global(li > ul),
  .prose :global(li > ol) {
    margin-top: var(--space-1);
  }
  .prose :global(li > p) {
    margin-bottom: var(--space-2);
  }
  .prose :global(a) {
    color: var(--accent-text);
    text-decoration: underline;
    text-decoration-color: color-mix(in srgb, var(--accent-text) 40%, transparent);
    text-underline-offset: 2px;
  }
  .prose :global(a:hover) {
    text-decoration-color: currentColor;
  }
  .prose :global(strong) {
    font-weight: 600;
  }
  .prose :global(code) {
    font-size: 0.86em;
    overflow-wrap: anywhere;
  }
  .prose :global(blockquote) {
    margin: 0 0 var(--space-4);
    padding: var(--space-3) var(--space-4);
    border: 1px solid var(--border);
    border-left: 3px solid var(--warning);
    border-radius: var(--radius-md);
    background: var(--warning-soft);
  }
  .prose :global(blockquote > :last-child) {
    margin-bottom: 0;
  }
  .prose :global(hr) {
    margin: var(--space-8) 0;
  }
  .prose :global(img) {
    max-width: 100%;
    height: auto;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
  }
  .prose :global(.tablewrap) {
    margin: 0 0 var(--space-5);
    overflow-x: auto;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: var(--surface);
  }
  .prose :global(table) {
    width: 100%;
    border-collapse: collapse;
    font-size: var(--text-sm);
    line-height: 1.55;
  }
  .prose :global(th),
  .prose :global(td) {
    padding: 8px 12px;
    border-bottom: 1px solid var(--border);
    text-align: start;
    vertical-align: top;
  }
  .prose :global(th) {
    background: var(--surface-hover);
    color: var(--text-muted);
    font-weight: 600;
    white-space: nowrap;
  }
  /* Names in a table's first column (kinds, reasons, settings) stay whole. */
  .prose :global(td:first-child code) {
    white-space: nowrap;
    overflow-wrap: normal;
  }
  .prose :global(tr:last-child td) {
    border-bottom: 0;
  }
  .prose :global(.codeblock) {
    margin: 0 0 var(--space-5);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: var(--surface-sunken);
    overflow: hidden;
  }
  .prose :global(.codebar) {
    display: flex;
    align-items: center;
    justify-content: space-between;
    min-height: 32px;
    padding: 0 6px 0 12px;
    border-bottom: 1px solid var(--border);
    background: var(--surface-hover);
  }
  .prose :global(.lang) {
    color: var(--text-subtle);
    font-family: var(--font-mono);
    font-size: var(--text-xs);
  }
  .prose :global(.copy) {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    height: 26px;
    padding: 0 8px;
    border: 0;
    border-radius: var(--radius-sm);
    background: transparent;
    color: var(--text-muted);
    font: inherit;
    font-size: var(--text-xs);
    font-weight: 500;
    cursor: pointer;
  }
  .prose :global(.copy:hover) {
    background: var(--surface-pressed);
    color: var(--text);
  }
  .prose :global(.copy:focus-visible) {
    outline: none;
    box-shadow: var(--focus-ring);
  }
  .prose :global(.codeblock pre) {
    border: 0;
    border-radius: 0;
    font-size: 13px;
  }
  .prose :global(pre code) {
    padding: 0;
    background: none;
    font-size: inherit;
    overflow-wrap: normal;
  }

  @media (max-width: 1240px) {
    .page {
      grid-template-columns: minmax(0, 1fr);
    }
    .toc {
      display: none;
    }
    .tocfold {
      display: block;
    }
  }
  @media (max-width: 560px) {
    .prose :global(h1),
    .homehead h1 {
      font-size: var(--text-2xl);
    }
    .pager {
      grid-template-columns: 1fr;
    }
    .nextpg {
      grid-column: 1;
    }
  }
</style>
