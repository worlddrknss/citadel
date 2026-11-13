<!--
  ⌘K command palette. Searches navigation, projects/environments, KMS keys
  and aliases, certificates, parameters, people (admins) and — when the
  current page is inside an environment — that environment's top-level
  secrets. Enter navigates. Sources load in parallel and fail independently.
-->
<script lang="ts" module>
  import type { IconName } from '#lib/components/Icon.svelte';

  export interface PaletteNav {
    href: string;
    label: string;
    icon: IconName;
    group?: string;
  }

  interface Entry {
    id: string;
    group: string;
    label: string;
    sub?: string;
    icon: IconName;
    href: string;
    hay: string;
    boost?: number;
  }

  // Cached across openings for a minute so reopening is instant.
  let cache: { at: number; entries: Entry[]; failed: string[] } | null = null;
  let scopeCache: { key: string; entries: Entry[] } | null = null;
</script>

<script lang="ts">
  import { goto } from '$app/navigation';
  import { base } from '#lib/paths.ts';
  import { api } from '#lib/api.ts';
  import Icon from '#lib/components/Icon.svelte';
  import { session } from '#lib/stores/session.svelte.ts';

  let {
    open = $bindable(false),
    nav,
    scope = null,
    initial = ''
  }: {
    open?: boolean;
    nav: PaletteNav[];
    scope?: { project: string; env: string } | null;
    initial?: string;
  } = $props();

  let dialog = $state<HTMLDialogElement>();
  let input = $state<HTMLInputElement>();
  let query = $state('');
  let active = $state(0);
  let loading = $state(false);
  let entries = $state<Entry[]>([]);
  let scoped = $state<Entry[]>([]);
  let failed = $state<string[]>([]);
  let scopeOnly = $state(false);

  const enc = encodeURIComponent;

  $effect(() => {
    if (!dialog) return;
    if (open && !dialog.open) {
      query = initial;
      active = 0;
      scopeOnly = false;
      dialog.showModal();
      requestAnimationFrame(() => input?.focus());
      void load();
    }
    if (!open && dialog.open) dialog.close();
  });

  async function load() {
    if (cache && Date.now() - cache.at < 60_000) {
      entries = cache.entries;
      failed = cache.failed;
    } else {
      loading = true;
      const isAdmin = session.can('admin');
      const [p, k, c, prm, u] = await Promise.allSettled([
        api.projects(),
        api.kmsKeys(),
        api.certificates(),
        api.parameters(),
        isAdmin ? api.users() : Promise.resolve({ users: [] })
      ]);
      const out: Entry[] = [];
      const bad: string[] = [];
      if (p.status === 'fulfilled') {
        for (const pr of p.value.projects) {
          out.push({ id: `p:${pr.slug}`, group: 'Projects', label: pr.slug, sub: `${pr.environments.length} environments`, icon: 'folder', href: `${base}/secrets/${enc(pr.slug)}`, hay: pr.slug });
          for (const env of pr.environments)
            out.push({ id: `e:${pr.slug}/${env}`, group: 'Projects', label: `${pr.slug} / ${env}`, sub: 'Environment', icon: 'lock', href: `${base}/secrets/${enc(pr.slug)}/${enc(env)}`, hay: `${pr.slug} ${env}` });
        }
      } else bad.push('projects');
      if (k.status === 'fulfilled') {
        for (const key of k.value.keys) {
          const sub = [key.description, key.keySpec, key.enabled ? '' : 'disabled'].filter(Boolean).join(' · ');
          out.push({ id: `k:${key.keyId}`, group: 'KMS keys', label: key.aliases[0] ?? key.keyId, sub: key.aliases[0] ? `${key.keyId}${sub ? ' · ' + sub : ''}` : sub, icon: 'key', href: `${base}/kms?key=${enc(key.keyId)}`, hay: `${key.keyId} ${key.arn} ${key.description} ${key.aliases.join(' ')}` });
          for (const a of key.aliases.slice(1))
            out.push({ id: `a:${a}`, group: 'KMS keys', label: a, sub: `Alias of ${key.keyId}`, icon: 'tag', href: `${base}/kms?key=${enc(key.keyId)}`, hay: `${a} ${key.keyId}` });
        }
      } else bad.push('KMS keys');
      if (c.status === 'fulfilled') {
        for (const cert of c.value.certificates)
          out.push({ id: `c:${cert.source}:${cert.id}`, group: 'Certificates', label: cert.subject || cert.id, sub: [cert.status, cert.notAfter ? `expires ${new Date(cert.notAfter).toLocaleDateString()}` : ''].filter(Boolean).join(' · '), icon: 'award', href: `${base}/certificates?cert=${enc(cert.id)}&source=${enc(cert.source)}`, hay: `${cert.subject} ${cert.id}` });
      } else bad.push('certificates');
      if (prm.status === 'fulfilled') {
        for (const pa of prm.value.parameters)
          out.push({ id: `s:${pa.name}`, group: 'Parameters', label: pa.name, sub: `${pa.type} · v${pa.version}`, icon: 'sliders', href: `${base}/parameters?name=${enc(pa.name)}`, hay: `${pa.name} ${pa.description}` });
      } else bad.push('parameters');
      if (u.status === 'fulfilled') {
        for (const us of u.value.users)
          out.push({ id: `u:${us.username}`, group: 'People', label: us.displayName || us.username, sub: `${us.username} · ${us.role}`, icon: 'user', href: `${base}/admin?user=${enc(us.username)}`, hay: `${us.username} ${us.displayName}` });
      }
      cache = { at: Date.now(), entries: out, failed: bad };
      entries = out;
      failed = bad;
      loading = false;
    }
    if (scope) {
      const key = `${scope.project}/${scope.env}`;
      if (scopeCache?.key === key) scoped = scopeCache.entries;
      else {
        scoped = [];
        try {
          const { project, env } = scope;
          const res = await api.list(project, env, '');
          const list: Entry[] = [
            ...res.folders.map((f) => ({ id: `f:${key}/${f}`, group: `In ${env}`, label: `${f}/`, sub: `${project} / ${env}`, icon: 'folder' as IconName, href: `${base}/secrets/${enc(project)}/${enc(env)}?path=${enc(f)}`, hay: f, boost: 2 })),
            ...res.items.map((it) => ({ id: `i:${key}/${it.key}`, group: `In ${env}`, label: it.key, sub: `${project} / ${env}`, icon: 'lock' as IconName, href: `${base}/secrets/${enc(project)}/${enc(env)}?key=${enc(it.key)}`, hay: `${it.key} ${it.arn}`, boost: 2 }))
          ];
          scopeCache = { key, entries: list };
          scoped = list;
        } catch {
          failed = [...failed, `${scope.env} secrets`];
        }
      }
    } else scoped = [];
  }

  const navEntries = $derived<Entry[]>(
    nav.map((n) => ({ id: `n:${n.href}`, group: 'Go to', label: n.label, sub: n.group, icon: n.icon, href: `${base}${n.href}`, hay: `${n.label} ${n.group ?? ''}` }))
  );

  const MAX_PER_GROUP = 6;

  const results = $derived.by(() => {
    const q = query.trim().toLowerCase();
    const tokens = q.split(/\s+/).filter(Boolean);
    const all = scopeOnly ? scoped : [...scoped, ...navEntries, ...entries];
    let picked: { e: Entry; score: number }[];
    if (!tokens.length) {
      picked = (scopeOnly ? scoped : [...scoped.slice(0, 5), ...navEntries]).map((e) => ({ e, score: 0 }));
    } else {
      picked = [];
      for (const e of all) {
        const label = e.label.toLowerCase();
        const hay = `${label} ${e.hay.toLowerCase()} ${(e.sub ?? '').toLowerCase()}`;
        if (!tokens.every((t) => hay.includes(t))) continue;
        let score = (e.boost ?? 0) + (label === q ? 10 : label.startsWith(q) ? 6 : label.includes(q) ? 3 : 0);
        if (scope && hay.includes(scope.project.toLowerCase()) && hay.includes(scope.env.toLowerCase())) score += 1;
        picked.push({ e, score });
      }
      picked.sort((a, b) => b.score - a.score);
    }
    // Group, keeping the best group first, and cap each group.
    const groups = new Map<string, Entry[]>();
    for (const { e } of picked) {
      const g = groups.get(e.group) ?? [];
      if (g.length < MAX_PER_GROUP) g.push(e);
      groups.set(e.group, g);
    }
    return [...groups.entries()].map(([name, items]) => ({ name, items }));
  });

  const flat = $derived(results.flatMap((g) => g.items));

  $effect(() => {
    void query;
    void scopeOnly;
    active = 0;
  });

  function choose(e: Entry | undefined) {
    if (!e) return;
    open = false;
    goto(e.href);
  }

  function onkeydown(e: KeyboardEvent) {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      active = flat.length ? (active + 1) % flat.length : 0;
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      active = flat.length ? (active - 1 + flat.length) % flat.length : 0;
    } else if (e.key === 'Enter') {
      e.preventDefault();
      choose(flat[active]);
    } else if (e.key === 'Backspace' && !query && scopeOnly) {
      scopeOnly = false;
    }
  }

  $effect(() => {
    const el = document.getElementById(`pal-opt-${active}`);
    el?.scrollIntoView({ block: 'nearest' });
  });

  function onclick(e: MouseEvent) {
    if (e.target === dialog) open = false;
  }
</script>

<dialog bind:this={dialog} class="palette" aria-label="Search Citadel" onclose={() => (open = false)} {onclick}>
  <div class="box">
    <div class="bar">
      <Icon name="search" />
      {#if scope}
        <button type="button" class="chip" aria-pressed={scopeOnly} title="Search only this environment" onclick={() => { scopeOnly = !scopeOnly; input?.focus(); }}>
          {scope.project} / {scope.env}{#if scopeOnly}<Icon name="x" size={12} />{/if}
        </button>
      {/if}
      <input
        bind:this={input}
        bind:value={query}
        {onkeydown}
        type="text"
        role="combobox"
        aria-expanded="true"
        aria-controls="pal-list"
        aria-activedescendant={flat.length ? `pal-opt-${active}` : undefined}
        aria-autocomplete="list"
        aria-label="Search secrets, keys, certificates, parameters and pages"
        placeholder={scopeOnly && scope ? `Search ${scope.env}…` : 'Search secrets, keys, ARNs, people…'}
        autocomplete="off"
        spellcheck="false"
      />
      <kbd>Esc</kbd>
    </div>
    <div class="list" id="pal-list" role="listbox" aria-label="Results">
      {#each results as g (g.name)}
        <div role="group" aria-label={g.name}>
          <div class="group" aria-hidden="true">{g.name}</div>
          {#each g.items as e (e.id)}
            {@const i = flat.indexOf(e)}
            <!-- svelte-ignore a11y_click_events_have_key_events -->
            <div
              id="pal-opt-{i}"
              role="option"
              tabindex="-1"
              aria-selected={i === active}
              class="opt"
              onmousemove={() => (active = i)}
              onclick={() => choose(e)}
            >
              <span class="oi"><Icon name={e.icon} size={14} /></span>
              <span class="ot"><span class="ol">{e.label}</span>{#if e.sub}<span class="os">{e.sub}</span>{/if}</span>
              {#if i === active}<Icon name="chevron-right" size={14} />{/if}
            </div>
          {/each}
        </div>
      {/each}
      {#if loading}
        <div class="state" role="status"><span class="skeleton" style:width="60%" style:height="12px"></span><span class="sr-only">Loading results</span></div>
      {:else if !flat.length}
        <div class="state" role="status">No matches for “{query}”.</div>
      {/if}
    </div>
    <div class="foot">
      <span><kbd>↑</kbd><kbd>↓</kbd> to move</span>
      <span><kbd>↵</kbd> to open</span>
      {#if failed.length}<span class="warn" role="status"><Icon name="alert-triangle" size={12} />Couldn't load {failed.join(', ')}</span>{/if}
    </div>
  </div>
</dialog>

<style>
  .palette {
    width: min(640px, calc(100vw - 32px));
    max-height: min(560px, calc(100dvh - 96px));
    margin: 12vh auto auto;
    padding: 0;
    border: 1px solid var(--border);
    border-radius: var(--radius-xl);
    background: var(--surface-raised);
    color: var(--text);
    box-shadow: var(--shadow-lg);
    overflow: hidden;
  }
  .palette::backdrop {
    background: var(--overlay);
  }
  .box {
    display: flex;
    flex-direction: column;
    max-height: inherit;
  }
  .bar {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 0 14px;
    border-bottom: 1px solid var(--border);
    color: var(--text-subtle);
  }
  .bar input {
    flex: 1;
    min-width: 0;
    height: 52px;
    border: none;
    background: transparent;
    color: var(--text);
    font: inherit;
    font-size: var(--text-md);
    outline: none;
  }
  .chip {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    height: 24px;
    padding: 0 8px;
    border: 1px solid var(--border-strong);
    border-radius: 999px;
    background: var(--surface-hover);
    color: var(--text-muted);
    font: 500 13px/1 var(--font-mono);
    white-space: nowrap;
    cursor: pointer;
  }
  .chip[aria-pressed='true'] {
    border-color: transparent;
    background: var(--accent-soft);
    color: var(--accent-text);
  }
  .list {
    flex: 1;
    overflow-y: auto;
    padding: 6px;
  }
  .group {
    padding: 8px 10px 4px;
    font-size: var(--text-xs);
    font-weight: 600;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    color: var(--text-subtle);
  }
  .opt {
    display: flex;
    align-items: center;
    gap: 10px;
    min-height: 40px;
    padding: 6px 10px;
    border-radius: var(--radius-md);
    color: var(--text-subtle);
    cursor: pointer;
  }
  .opt[aria-selected='true'] {
    background: var(--accent-soft);
  }
  .oi {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    flex: none;
    width: 26px;
    height: 26px;
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    background: var(--surface);
    color: var(--text-muted);
  }
  .ot {
    display: flex;
    flex-direction: column;
    flex: 1;
    min-width: 0;
  }
  .ol,
  .os {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .ol {
    color: var(--text);
    font-weight: 500;
  }
  .os {
    font-size: var(--text-sm);
    color: var(--text-subtle);
  }
  .state {
    padding: 20px 12px;
    color: var(--text-muted);
    text-align: center;
  }
  .foot {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 14px;
    padding: 8px 14px;
    border-top: 1px solid var(--border);
    background: var(--surface-hover);
    color: var(--text-subtle);
    font-size: var(--text-sm);
  }
  .foot kbd + kbd {
    margin-left: 2px;
  }
  .warn {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    margin-left: auto;
    color: var(--warning);
  }
</style>
