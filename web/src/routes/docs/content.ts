// The repository's docs/*.md, bundled at build time so the docs ship inside
// the console and work offline and self-hosted. Only the /docs route imports
// this module, so the Markdown stays out of the rest of the console.

import { base } from '#lib/paths.ts';
import { renderDoc, sectionsOf, type RenderedDoc, type Section } from './markdown';
import { navFor, isDoc, type NavGroup } from './nav';

const files = import.meta.glob('../../../../docs/**/*.md', { query: '?raw', import: 'default', eager: true }) as Record<string, string>;
const imageFiles = import.meta.glob('../../../../docs/images/*.{png,jpg,jpeg,gif,svg,webp}', { query: '?url', import: 'default', eager: true }) as Record<
  string,
  string
>;

const toRepoPath = (p: string) => p.slice(p.indexOf('docs/'));

/** Markdown source by slug (`agents`, `design/agent-credentials`). */
export const SOURCES: Record<string, string> = Object.fromEntries(
  Object.entries(files).map(([p, md]) => [toRepoPath(p).slice('docs/'.length, -'.md'.length), md])
);

const IMAGES: Record<string, string> = Object.fromEntries(Object.entries(imageFiles).map(([p, url]) => [toRepoPath(p), url]));
const KNOWN = new Set(Object.keys(SOURCES));

const firstHeading = (md: string) => /^#\s+(.+)$/m.exec(md)?.[1].trim() ?? '';
const TITLES: Record<string, string> = Object.fromEntries(Object.entries(SOURCES).map(([s, md]) => [s, firstHeading(md)]));

export const DOCS_NAV: NavGroup[] = navFor(KNOWN, TITLES);
/** Docs in nav order, for previous/next links and search ranking. */
export const ORDER: string[] = DOCS_NAV.flatMap((g) => g.items.filter(isDoc).map((d) => d.slug));

const cache = new Map<string, RenderedDoc>();
export function getDoc(slug: string): RenderedDoc | null {
  const md = SOURCES[slug];
  if (md === undefined) return null;
  let doc = cache.get(slug);
  if (!doc) {
    doc = renderDoc(md, { slug, known: KNOWN, base, images: IMAGES });
    cache.set(slug, doc);
  }
  return doc;
}

let sections: Section[] | null = null;
/** Every doc's sections, in nav order, for search. */
export function allSections(): Section[] {
  sections ??= ORDER.flatMap((slug) => sectionsOf(slug, SOURCES[slug]));
  return sections;
}

/** The first sentence after the title, as plain text, for the docs home. */
export function summaryOf(slug: string): string {
  const s = allSections().find((x) => x.slug === slug && x.depth === 1);
  const t = s?.text ?? '';
  const end = /[.:](\s|$)/g;
  end.lastIndex = 40;
  const m = end.exec(t);
  const first = m ? t.slice(0, m.index) + '.' : t;
  return first.length > 200 ? `${first.slice(0, 197).trimEnd()}…` : first;
}
