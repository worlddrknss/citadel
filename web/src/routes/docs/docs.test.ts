import { describe, expect, it } from 'vitest';
import { DOC_LINKS } from '#lib/docs-links.ts';
import { plainText, renderDoc, resolveImage, resolveLink, searchDocs, sectionsOf, slugger, slugify, type RenderContext } from './markdown';
import { NAV_DOCS, navFor } from './nav';
import { DOCS_NAV, ORDER, SOURCES, allSections, getDoc, summaryOf } from './content';

const ctx = (slug = 'agents', extra: Partial<RenderContext> = {}): RenderContext => ({
  slug,
  known: new Set(['agents', 'agents-mcp', 'notifications', 'design/agent-credentials']),
  base: '/app',
  images: { 'docs/images/overview-light.png': '/app/_app/immutable/assets/overview-light.abc.png' },
  ...extra
});

describe('slugs', () => {
  it('match GitHub heading anchors', () => {
    expect(slugify('Approvals and leases')).toBe('approvals-and-leases');
    expect(slugify('Using a credential: brokered HTTP')).toBe('using-a-credential-brokered-http');
    expect(slugify('Step 3: Make a secret usable by agents')).toBe('step-3-make-a-secret-usable-by-agents');
    expect(slugify('Secrets & keys')).toBe('secrets--keys');
    expect(slugify('no_grant reasons')).toBe('no_grant-reasons');
  });
  it('dedupe like GitHub', () => {
    const next = slugger();
    expect([next('HTTP direct'), next('stdio bridge'), next('HTTP direct'), next('HTTP direct')]).toEqual(['http-direct', 'stdio-bridge', 'http-direct-1', 'http-direct-2']);
  });
  it('strip inline Markdown for plain text', () => {
    expect(plainText('The `reason` **field** and [docs](x.md)')).toBe('The reason field and docs');
    expect(plainText('`no_grant` stays')).toBe('no_grant stays');
    expect(plainText('at `https://<your-citadel>/mcp`.')).toBe('at https://<your-citadel>/mcp.');
  });
});

describe('links', () => {
  it('rewrite links between docs to console routes, keeping anchors', () => {
    expect(resolveLink('agents-mcp.md', ctx())).toEqual({ href: '/app/docs/agents-mcp', external: false });
    expect(resolveLink('agents.md#approvals-and-leases', ctx('agents-mcp'))).toEqual({ href: '/app/docs/agents#approvals-and-leases', external: false });
    expect(resolveLink('./notifications.md', ctx())).toEqual({ href: '/app/docs/notifications', external: false });
    expect(resolveLink('design/agent-credentials.md', ctx())).toEqual({ href: '/app/docs/design/agent-credentials', external: false });
    expect(resolveLink('../agents.md#x', ctx('design/agent-credentials'))).toEqual({ href: '/app/docs/agents#x', external: false });
  });
  it('send the OpenAPI document to the API reference page', () => {
    expect(resolveLink('openapi.yaml', ctx())).toEqual({ href: '/app/api-reference', external: false });
  });
  it('send other repository files to GitHub', () => {
    expect(resolveLink('../SECURITY.md', ctx())).toEqual({ href: 'https://github.com/worlddrknss/citadel/blob/main/SECURITY.md', external: true });
    expect(resolveLink('unknown.md#a', ctx())).toEqual({ href: 'https://github.com/worlddrknss/citadel/blob/main/docs/unknown.md#a', external: true });
    expect(resolveLink('../../../etc/passwd', ctx()).href).toBe('https://github.com/worlddrknss/citadel');
  });
  it('keep anchors, absolute paths and URLs', () => {
    expect(resolveLink('#minted-credentials', ctx())).toEqual({ href: '#minted-credentials', external: false });
    expect(resolveLink('/v1/openapi.yaml', ctx())).toEqual({ href: '/v1/openapi.yaml', external: false });
    expect(resolveLink('https://modelcontextprotocol.io', ctx())).toEqual({ href: 'https://modelcontextprotocol.io', external: true });
    expect(resolveLink('mailto:a@example.com', ctx()).external).toBe(false);
  });
  it('serve images under docs/images and drop others (CSP allows same-origin only)', () => {
    expect(resolveImage('images/overview-light.png', ctx())).toBe('/app/_app/immutable/assets/overview-light.abc.png');
    expect(resolveImage('../images/overview-light.png', ctx('design/agent-credentials'))).toBe('/app/_app/immutable/assets/overview-light.abc.png');
    expect(resolveImage('https://example.com/x.png', ctx())).toBeNull();
    expect(resolveImage('images/missing.png', ctx())).toBeNull();
  });
});

describe('renderDoc', () => {
  const md = [
    '# Title here',
    '',
    'See [MCP](agents-mcp.md#claude-code) and [the site](https://example.com).',
    '',
    '## First `section`',
    '',
    '```bash',
    'echo "<hi>"',
    '```',
    '',
    '### Sub',
    '',
    '| A | B |',
    '|---|---|',
    '| 1 | 2 |',
    '',
    '## First section',
    '',
    '![shot](images/overview-light.png) <script>alert(1)</script> <img src=x onerror="alert(1)">',
    ''
  ].join('\n');
  const doc = renderDoc(md, ctx());

  it('collects the title and headings with unique IDs', () => {
    expect(doc.title).toBe('Title here');
    expect(doc.headings.map((h) => [h.depth, h.id])).toEqual([
      [1, 'title-here'],
      [2, 'first-section'],
      [3, 'sub'],
      [2, 'first-section-1']
    ]);
    expect(doc.html).toContain('<h2 id="first-section">First <code>section</code><a class="anchor" href="#first-section"');
  });
  it('rewrites links and marks external ones', () => {
    expect(doc.html).toContain('href="/app/docs/agents-mcp#claude-code"');
    expect(doc.html).toMatch(/href="https:\/\/example.com" target="_blank" rel="noopener noreferrer"/);
  });
  it('wraps code blocks with a copy button and escapes them', () => {
    expect(doc.html).toContain('<div class="codeblock">');
    expect(doc.html).toContain('data-copy');
    expect(doc.html).toContain('<span class="lang">bash</span>');
    expect(doc.html).toContain('echo "&lt;hi&gt;"');
  });
  it('wraps tables so they scroll', () => {
    // Focusable, so a table that scrolls sideways can be scrolled from the keyboard.
    expect(doc.html).toContain('<div class="tablewrap" tabindex="0"><table>');
    expect(doc.html).toContain('<pre tabindex="0">');
  });
  it('sanitizes the output', () => {
    expect(doc.html).not.toContain('<script');
    expect(doc.html).not.toContain('onerror');
    expect(doc.html).toContain('src="/app/_app/immutable/assets/overview-light.abc.png"');
  });
});

describe('search', () => {
  const sections = [
    ...sectionsOf('guide', '# Getting started with AI agents\n\nIntro.\n\n## Troubleshooting\n\n| `no_grant` | The agent has no grant. |\n\n## Step 4: Grant the credential\n\nUse or reveal.'),
    ...sectionsOf('agents', '# Credentials for AI agents\n\n## Grant scopes\n\nNarrow tokens.\n\n## Revealing a credential\n\nSee `no_grant` too.')
  ];
  it('splits docs into sections with heading IDs', () => {
    expect(sections.map((s) => [s.slug, s.id, s.depth])).toEqual([
      ['guide', '', 1],
      ['guide', 'troubleshooting', 2],
      ['guide', 'step-4-grant-the-credential', 2],
      ['agents', '', 1],
      ['agents', 'grant-scopes', 2],
      ['agents', 'revealing-a-credential', 2]
    ]);
    expect(sections[1].text).toContain('no_grant');
    expect(sections[1].docTitle).toBe('Getting started with AI agents');
  });
  it('ranks titles over headings over text, in nav order', () => {
    expect(searchDocs(sections, 'agents').slice(0, 2).map((h) => h.in)).toEqual(['title', 'title']);
    const grant = searchDocs(sections, 'grant');
    expect(grant[0].in).toBe('heading');
    expect(grant.map((h) => h.section.id)).toEqual(['step-4-grant-the-credential', 'grant-scopes', 'troubleshooting', 'revealing-a-credential']);
  });
  it('matches every term, and finds error reasons in text with a snippet', () => {
    const hits = searchDocs(sections, 'no_grant');
    expect(hits.map((h) => h.section.id)).toEqual(['troubleshooting', 'revealing-a-credential']);
    expect(hits[0].snippet).toContain('no_grant');
    expect(searchDocs(sections, 'grant zebra')).toEqual([]);
    expect(searchDocs(sections, '   ')).toEqual([]);
  });
});

describe('the bundled docs', () => {
  it('include every docs/*.md and put each in the nav', () => {
    expect(Object.keys(SOURCES)).toEqual(expect.arrayContaining(['getting-started', 'getting-started-agents', 'agents', 'agents-mcp', 'design/agent-credentials']));
    expect(new Set(ORDER)).toEqual(new Set(Object.keys(SOURCES)));
    for (const d of NAV_DOCS) expect(SOURCES[d.slug], d.slug).toBeDefined();
    expect(DOCS_NAV.map((g) => g.label)).toEqual(['Getting started', 'Agents', 'Secrets & keys', 'Operations', 'Reference', 'Design notes']);
  });
  it('lists docs the manifest misses under Reference or Design notes', () => {
    const nav = navFor([...NAV_DOCS.map((d) => d.slug), 'new-thing', 'design/other'], { 'new-thing': 'New thing' });
    expect(nav.find((g) => g.label === 'Reference')?.items.at(-1)).toEqual({ slug: 'new-thing', label: 'New thing' });
    expect(nav.find((g) => g.label === 'Design notes')?.items.at(-1)).toEqual({ slug: 'design/other', label: 'design/other' });
  });
  it('render, and every link between docs points at a page and heading that exist', () => {
    const ids = new Map(Object.keys(SOURCES).map((s) => [s, new Set(getDoc(s)!.headings.map((h) => h.id))]));
    for (const slug of Object.keys(SOURCES)) {
      const doc = getDoc(slug)!;
      expect(doc.title, slug).not.toBe('');
      for (const m of doc.html.matchAll(/href="([^"]+)"/g)) {
        const href = m[1];
        const internal = /^\/app\/docs\/([^#]+)(?:#(.*))?$/.exec(href);
        if (internal) {
          expect(ids.has(internal[1]), `${slug} → ${href}`).toBe(true);
          if (internal[2]) expect(ids.get(internal[1])!.has(internal[2]), `${slug} → ${href}`).toBe(true);
        } else if (href.startsWith('#')) {
          expect(ids.get(slug)!.has(href.slice(1)), `${slug} → ${href}`).toBe(true);
        }
      }
    }
  });
  it('have the anchors the console links to', () => {
    for (const link of Object.values(DOC_LINKS)) {
      const [path, anchor] = link.replace(/^\/docs\//, '').split('#');
      const doc = getDoc(path);
      expect(doc, link).not.toBeNull();
      if (anchor) expect(doc!.headings.map((h) => h.id), link).toContain(anchor);
    }
  });
  it('find error reasons and have summaries', () => {
    expect(searchDocs(allSections(), 'totp_sha1_unsupported').some((h) => h.section.slug === 'getting-started-agents')).toBe(true);
    expect(summaryOf('getting-started-agents')).toMatch(/^This guide takes you/);
  });
});
