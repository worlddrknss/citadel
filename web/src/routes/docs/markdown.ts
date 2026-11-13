// Markdown rendering for the in-console docs: GitHub-style heading IDs,
// links between docs rewritten to console routes, images from docs/images,
// code blocks with a copy button, and a sanitized result.
//
// The source of truth is docs/*.md in the repository, so links are written
// for GitHub (`agents-mcp.md#x`, `../SECURITY.md`) and rewritten here.

import DOMPurify from 'dompurify';
import { Marked, type Token, type Tokens } from 'marked';

export const REPO_URL = 'https://github.com/worlddrknss/citadel';
const REPO_BLOB = `${REPO_URL}/blob/main/`;

export interface Heading {
  depth: number;
  /** Plain text, for the table of contents and search. */
  text: string;
  id: string;
}

export interface RenderedDoc {
  html: string;
  title: string;
  headings: Heading[];
}

export interface RenderContext {
  /** The doc being rendered, e.g. `agents` or `design/agent-credentials`. */
  slug: string;
  /** Slugs of every doc that has a console page. */
  known: ReadonlySet<string>;
  /** The console's base path (`/app`). */
  base: string;
  /** Repository paths (`docs/images/x.png`) to served URLs. */
  images?: Readonly<Record<string, string>>;
}

const escapeHtml = (s: string) =>
  s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');

/** Inline Markdown to plain text: code spans, emphasis and links lose their syntax. */
export function plainText(md: string): string {
  return md
    .replace(/!\[([^\]]*)\]\([^)]*\)/g, '$1')
    .replace(/\[([^\]]*)\]\([^)]*\)/g, '$1')
    .replace(/`([^`]*)`/g, '$1')
    .replace(/(\*\*|__)(.+?)\1/g, '$2')
    .replace(/(^|[\s(])[*_]([^*_\s][^*_]*?)[*_](?=$|[\s).,:;!?])/g, '$1$2')
    .replace(/\s+/g, ' ')
    .trim();
}

/** GitHub's heading anchor: lowercase, punctuation dropped, spaces to dashes. */
export function slugify(text: string): string {
  return text
    .toLowerCase()
    .replace(/[^\p{L}\p{N}\s_-]/gu, '')
    .trim()
    .replace(/\s/g, '-');
}

/** Hands out unique IDs the way GitHub does: `x`, `x-1`, `x-2`. */
export function slugger() {
  const seen = new Map<string, number>();
  return (text: string) => {
    const s = slugify(text) || 'section';
    const n = seen.get(s);
    seen.set(s, (n ?? -1) + 1);
    return n === undefined ? s : `${s}-${n + 1}`;
  };
}

/** Joins and normalizes repository paths (`docs` + `../SECURITY.md`). */
function joinPath(dir: string, rel: string): string | null {
  const out = dir ? dir.split('/') : [];
  for (const seg of rel.split('/')) {
    if (seg === '' || seg === '.') continue;
    if (seg === '..') {
      if (!out.length) return null;
      out.pop();
    } else out.push(seg);
  }
  return out.join('/');
}

function docDir(slug: string) {
  const i = slug.lastIndexOf('/');
  return i < 0 ? 'docs' : `docs/${slug.slice(0, i)}`;
}

export interface ResolvedLink {
  href: string;
  external: boolean;
}

/**
 * Where a link in a doc goes in the console. Other docs become /docs routes
 * (keeping the anchor), the OpenAPI document the API reference page, other
 * repository files their GitHub page; absolute URLs and anchors are kept.
 */
export function resolveLink(href: string, ctx: RenderContext): ResolvedLink {
  if (/^[a-z][a-z0-9+.-]*:/i.test(href)) return { href, external: /^https?:/i.test(href) };
  if (href.startsWith('#') || href.startsWith('/')) return { href, external: false };
  const hashAt = href.indexOf('#');
  const path = hashAt < 0 ? href : href.slice(0, hashAt);
  const hash = hashAt < 0 ? '' : href.slice(hashAt);
  const repoPath = joinPath(docDir(ctx.slug), path);
  if (repoPath === null) return { href: REPO_URL, external: true };
  if (repoPath.startsWith('docs/') && repoPath.endsWith('.md')) {
    const slug = repoPath.slice('docs/'.length, -'.md'.length);
    if (ctx.known.has(slug)) return { href: `${ctx.base}/docs/${slug}${hash}`, external: false };
  }
  if (repoPath === 'docs/openapi.yaml') return { href: `${ctx.base}/api-reference`, external: false };
  return { href: `${REPO_BLOB}${repoPath}${hash}`, external: true };
}

/** The served URL of an image under docs/, or null (CSP allows only same-origin images). */
export function resolveImage(src: string, ctx: RenderContext): string | null {
  if (/^data:image\//i.test(src)) return src;
  if (/^[a-z][a-z0-9+.-]*:/i.test(src) || src.startsWith('/')) return null;
  const repoPath = joinPath(docDir(ctx.slug), src.split('#')[0]);
  return (repoPath && ctx.images?.[repoPath]) || null;
}

const COPY_ICON =
  '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M20 9h-9a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h9a2 2 0 0 0 2-2v-9a2 2 0 0 0-2-2ZM5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>';

/** Renders one doc to sanitized HTML with its title and headings. */
export function renderDoc(md: string, ctx: RenderContext): RenderedDoc {
  const nextId = slugger();
  const headings: Heading[] = [];
  let title = '';

  const marked = new Marked({
    gfm: true,
    renderer: {
      heading({ tokens, depth, text }: Tokens.Heading) {
        const plain = plainText(text);
        const id = nextId(plain);
        headings.push({ depth, text: plain, id });
        if (depth === 1 && !title) title = plain;
        const inner = this.parser.parseInline(tokens);
        if (depth === 1) return `<h1 id="${id}">${inner}</h1>\n`;
        return `<h${depth} id="${id}">${inner}<a class="anchor" href="#${id}" aria-label="Link to ${escapeHtml(plain)}">#</a></h${depth}>\n`;
      },
      link({ href, title: linkTitle, tokens }: Tokens.Link) {
        const r = resolveLink(href, ctx);
        const t = linkTitle ? ` title="${escapeHtml(linkTitle)}"` : '';
        const ext = r.external ? ' target="_blank" rel="noopener noreferrer"' : '';
        return `<a href="${escapeHtml(r.href)}"${t}${ext}>${this.parser.parseInline(tokens)}</a>`;
      },
      image({ href, text }: Tokens.Image) {
        const src = resolveImage(href, ctx);
        if (!src) return escapeHtml(text);
        return `<img src="${escapeHtml(src)}" alt="${escapeHtml(text)}" loading="lazy" />`;
      },
      code({ text, lang }: Tokens.Code) {
        const language = (lang ?? '').split(/\s/)[0];
        const label = language ? `<span class="lang">${escapeHtml(language)}</span>` : '<span class="lang"></span>';
        const cls = language ? ` class="language-${escapeHtml(language)}"` : '';
        return (
          `<div class="codeblock">` +
          `<div class="codebar">${label}<button type="button" class="copy" data-copy aria-label="Copy code">${COPY_ICON}<span>Copy</span></button></div>` +
          // Focusable, so a code block that scrolls sideways can be scrolled from the keyboard.
          `<pre tabindex="0"><code${cls}>${escapeHtml(text)}</code></pre></div>\n`
        );
      },
      table(token: Tokens.Table) {
        // The default table, wrapped so wide tables scroll on their own
        // instead of widening the page.
        const head = token.header.map((c) => cell(this.parser.parseInline(c.tokens), 'th', c.align)).join('');
        const body = token.rows.map((r) => `<tr>${r.map((c) => cell(this.parser.parseInline(c.tokens), 'td', c.align)).join('')}</tr>`).join('\n');
        return `<div class="tablewrap"><table><thead><tr>${head}</tr></thead>${body ? `<tbody>${body}</tbody>` : ''}</table></div>\n`;
      }
    }
  });

  const raw = marked.parse(md, { async: false });
  const html = DOMPurify.sanitize(raw, { ADD_ATTR: ['target'], FORBID_TAGS: ['style', 'form', 'input'] });
  return { html, title, headings };
}

function cell(content: string, tag: 'th' | 'td', align: 'center' | 'left' | 'right' | null) {
  const a = align ? ` style="text-align:${align}"` : '';
  return `<${tag}${tag === 'th' ? ' scope="col"' : ''}${a}>${content}</${tag}>`;
}

// ---- search -----------------------------------------------------------------

export interface Section {
  slug: string;
  docTitle: string;
  /** The heading's ID; '' for the part before the first subheading. */
  id: string;
  heading: string;
  depth: number;
  /** Plain text of the section, for matching and snippets. */
  text: string;
}

function tokenText(t: Token): string {
  switch (t.type) {
    case 'code':
      return t.text;
    case 'table':
      return [...t.header.map((c: Tokens.TableCell) => c.text), ...t.rows.flat().map((c: Tokens.TableCell) => c.text)].join(' ');
    case 'list':
      return t.items.map((i: Tokens.ListItem) => i.text).join(' ');
    case 'space':
    case 'hr':
      return '';
    default:
      return 'text' in t && typeof t.text === 'string' ? t.text : t.raw;
  }
}

/** Splits a doc into sections at its headings (with the same IDs as renderDoc). */
export function sectionsOf(slug: string, md: string): Section[] {
  const nextId = slugger();
  const tokens = new Marked({ gfm: true }).lexer(md);
  const out: Section[] = [];
  let docTitle = '';
  let cur: Section | null = null;
  for (const t of tokens) {
    if (t.type === 'heading') {
      const text = plainText((t as Tokens.Heading).text);
      const id = nextId(text);
      if (t.depth === 1 && !docTitle) {
        docTitle = text;
        cur = { slug, docTitle, id: '', heading: text, depth: 1, text: '' };
      } else {
        cur = { slug, docTitle, id, heading: text, depth: t.depth, text: '' };
      }
      out.push(cur);
    } else if (cur) {
      cur.text += ' ' + plainText(tokenText(t));
    } else {
      cur = { slug, docTitle: slug, id: '', heading: slug, depth: 1, text: plainText(tokenText(t)) };
      out.push(cur);
    }
  }
  for (const s of out) {
    s.docTitle = docTitle || s.docTitle;
    s.text = s.text.trim();
  }
  return out;
}

export interface SearchHit {
  section: Section;
  /** Where the match is: the doc title, a heading, or the section's text. */
  in: 'title' | 'heading' | 'text';
  snippet: string;
  score: number;
}

const terms = (q: string) => q.toLowerCase().split(/\s+/).filter(Boolean);

function snippetAround(text: string, term: string, width = 120): string {
  const i = text.toLowerCase().indexOf(term);
  if (i < 0) return text.slice(0, width);
  const start = Math.max(0, i - Math.floor(width / 3));
  const s = text.slice(start, start + width).trim();
  return `${start > 0 ? '…' : ''}${s}${start + width < text.length ? '…' : ''}`;
}

/**
 * Client-side search over doc titles, headings and text. Every term must
 * match; titles rank above headings, headings above text, and earlier docs
 * (in nav order) break ties.
 */
export function searchDocs(sections: Section[], query: string, limit = 20): SearchHit[] {
  const ts = terms(query);
  if (!ts.length) return [];
  const all = (s: string) => {
    const l = s.toLowerCase();
    return ts.every((t) => l.includes(t));
  };
  const hits: SearchHit[] = [];
  sections.forEach((s, order) => {
    let hit: Omit<SearchHit, 'section'> | null = null;
    const exact = s.heading.toLowerCase() === query.trim().toLowerCase();
    if (s.depth === 1 && all(s.heading)) hit = { in: 'title', snippet: s.text.slice(0, 120), score: 400 + (exact ? 50 : 0) };
    else if (all(s.heading)) hit = { in: 'heading', snippet: s.text.slice(0, 120), score: 300 + (exact ? 50 : 0) - s.depth };
    else if (all(`${s.heading} ${s.text}`)) hit = { in: 'text', snippet: snippetAround(s.text, ts[0]), score: 100 };
    if (hit) hits.push({ section: s, ...hit, score: hit.score - order / 10_000 });
  });
  return hits.sort((a, b) => b.score - a.score).slice(0, limit);
}
