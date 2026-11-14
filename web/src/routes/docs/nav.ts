// The docs navigation: which docs/*.md pages appear in which group, in
// order. Kept free of the Markdown itself so the shell (sidebar, command
// palette) can import it without pulling every doc into its bundle.

export interface NavDoc {
  /** Path under docs/ without `.md`, also the route: /docs/<slug>. */
  slug: string;
  label: string;
}

export interface NavLink {
  /** A console route outside the docs. */
  href: string;
  label: string;
}

export interface NavGroup {
  label: string;
  items: (NavDoc | NavLink)[];
}

export const NAV: NavGroup[] = [
  {
    label: 'Getting started',
    items: [
      { slug: 'getting-started', label: 'Getting started' },
      { slug: 'getting-started-agents', label: 'AI agents: step by step' }
    ]
  },
  {
    label: 'Agents',
    items: [
      { slug: 'agents', label: 'Agent credentials' },
      { slug: 'agents-mcp', label: 'Connecting MCP clients' }
    ]
  },
  {
    label: 'SDKs',
    items: [
      { slug: 'sdks', label: 'Choosing an SDK' },
      { slug: 'sdk-typescript', label: 'TypeScript SDK' },
      { slug: 'sdk-go', label: 'Go SDK' }
    ]
  },
  {
    label: 'Secrets & keys',
    items: [
      { slug: 'rotation', label: 'Secret rotation' },
      { slug: 'aws-compatibility', label: 'AWS compatibility' }
    ]
  },
  {
    label: 'Operations',
    items: [
      { slug: 'deployment', label: 'Deployment' },
      { slug: 'configuration', label: 'Configuration' },
      { slug: 'notifications', label: 'Notifications' },
      { slug: 'audit', label: 'Audit log and retention' }
    ]
  },
  {
    label: 'Reference',
    items: [
      { slug: 'security-model', label: 'Security model' },
      { href: '/api-reference', label: 'API reference' }
    ]
  },
  {
    label: 'Design notes',
    items: [{ slug: 'design/agent-credentials', label: 'Agent credentials design' }]
  }
];

export const isDoc = (i: NavDoc | NavLink): i is NavDoc => 'slug' in i;

/** Every doc in the manifest, in nav order. */
export const NAV_DOCS: NavDoc[] = NAV.flatMap((g) => g.items.filter(isDoc));

/**
 * The manifest plus any doc it doesn't list (so a new docs/*.md file still
 * shows up): top-level docs go under Reference, docs/design/* under Design
 * notes.
 */
export function navFor(slugs: Iterable<string>, titles: Record<string, string> = {}): NavGroup[] {
  const listed = new Set(NAV_DOCS.map((d) => d.slug));
  const present = new Set(slugs);
  const extra = [...present].filter((s) => !listed.has(s)).sort();
  return NAV.map((g) => {
    const items = g.items.filter((i) => !isDoc(i) || present.has(i.slug));
    const add = extra.filter((s) => (g.label === 'Design notes' ? s.startsWith('design/') : g.label === 'Reference' && !s.startsWith('design/')));
    return { label: g.label, items: [...items, ...add.map((slug) => ({ slug, label: titles[slug] ?? slug }))] };
  }).filter((g) => g.items.length);
}
