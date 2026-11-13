<script lang="ts">
  import SchemaView from './SchemaView.svelte';
  import { expandable, isObj, refName, str, strList, typeLabel, type Schema } from './spec';

  let {
    schema,
    components,
    seen = []
  }: {
    schema: Schema;
    components: Record<string, Schema>;
    /** Component names already open above this one (cycle guard). */
    seen?: string[];
  } = $props();

  const ref = $derived(refName(schema.$ref));
  const target = $derived<Schema | null>(ref ? (components[ref] ?? null) : schema);
  const cyclic = $derived(ref !== '' && seen.includes(ref));
  const path = $derived(ref ? [...seen, ref] : seen);
  const fields = $derived(target && isObj(target.properties) ? Object.entries(target.properties).filter(([, v]) => isObj(v)) as [string, Schema][] : []);
  const required = $derived(new Set(target ? strList(target.required) : []));
  const items = $derived(target && isObj(target.items) ? target.items : null);
  const extra = $derived(target && isObj(target.additionalProperties) ? target.additionalProperties : null);
  const variants = $derived.by(() => {
    if (!target) return null;
    for (const k of ['oneOf', 'anyOf', 'allOf'] as const) {
      const v = target[k];
      if (Array.isArray(v)) return { kind: k === 'allOf' ? 'All of' : k === 'oneOf' ? 'One of' : 'Any of', list: v.filter(isObj) as Schema[] };
    }
    return null;
  });
</script>

{#snippet meta(s: Schema)}
  {#if Array.isArray(s.enum)}
    <span class="enum">one of {#each s.enum as e, i (i)}<code>{String(e)}</code>{i < s.enum.length - 1 ? ' ' : ''}{/each}</span>
  {/if}
  {#if s.default !== undefined}<span class="enum">default <code>{String(s.default)}</code></span>{/if}
  {#if str(s.description)}<span class="desc">{str(s.description)}</span>{/if}
{/snippet}

{#if cyclic}
  <p class="subtle small">Recursive reference to <code>{ref}</code> (shown above).</p>
{:else if !target}
  <p class="subtle small">Unknown schema <code>{ref}</code>.</p>
{:else}
  <div class="schema">
    {#if ref && str(target.description)}<p class="desc top">{str(target.description)}</p>{/if}
    {#if fields.length}
      <ul class="props">
        {#each fields as [name, p] (name)}
          <li>
            <div class="prop-head">
              <code class="pname">{name}</code>
              <span class="ptype mono">{typeLabel(p)}</span>
              {#if required.has(name)}<span class="req">required</span>{/if}
            </div>
            {@render meta(p)}
            {#if expandable(p, components)}
              <details class="nested">
                <summary>Fields of <span class="mono">{typeLabel(p)}</span></summary>
                <SchemaView schema={p} {components} seen={path} />
              </details>
            {/if}
          </li>
        {/each}
      </ul>
    {:else if items}
      <p class="small">Array of <span class="mono">{typeLabel(items)}</span></p>
      {@render meta(items)}
      {#if expandable(items, components)}<SchemaView schema={items} {components} seen={path} />{/if}
    {:else if variants}
      <p class="small">{variants.kind}:</p>
      <ul class="props">
        {#each variants.list as v, i (i)}
          <li>
            <span class="ptype mono">{typeLabel(v)}</span>
            {#if expandable(v, components)}<SchemaView schema={v} {components} seen={path} />{:else}{@render meta(v)}{/if}
          </li>
        {/each}
      </ul>
    {:else if !extra}
      <p class="small"><span class="mono">{typeLabel(target)}</span></p>
      {@render meta(target)}
    {/if}
    {#if extra}
      <p class="small">Map of string to <span class="mono">{typeLabel(extra)}</span></p>
      {#if expandable(extra, components)}<SchemaView schema={extra} {components} seen={path} />{/if}
    {/if}
  </div>
{/if}

<style>
  .schema {
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
    min-width: 0;
  }
  .props {
    list-style: none;
    margin: 0;
    padding: 0;
    border-left: 2px solid var(--border);
  }
  .props > li {
    display: flex;
    flex-direction: column;
    gap: 2px;
    padding: var(--space-2) 0 var(--space-2) var(--space-3);
    border-bottom: 1px solid var(--border);
    min-width: 0;
  }
  .props > li:last-child {
    border-bottom: none;
  }
  .prop-head {
    display: flex;
    flex-wrap: wrap;
    align-items: baseline;
    gap: var(--space-2);
  }
  .pname {
    font-family: var(--font-mono);
    font-weight: 600;
    font-size: var(--text-sm);
    overflow-wrap: anywhere;
  }
  .ptype {
    color: var(--accent-text);
    font-size: var(--text-xs);
    overflow-wrap: anywhere;
  }
  .req {
    color: var(--danger);
    font-size: var(--text-xs);
    font-weight: 500;
  }
  .desc {
    color: var(--text-muted);
    font-size: var(--text-sm);
    line-height: 1.5;
    white-space: pre-line;
  }
  .desc.top {
    margin: 0;
  }
  .enum {
    color: var(--text-subtle);
    font-size: var(--text-xs);
    overflow-wrap: anywhere;
  }
  code {
    font-family: var(--font-mono);
    font-size: 0.95em;
  }
  .enum code {
    background: var(--surface-sunken);
    border-radius: var(--radius-xs);
    padding: 0 4px;
  }
  .small {
    margin: 0;
  }
  .nested {
    margin-top: var(--space-1);
  }
  .nested > summary {
    cursor: pointer;
    color: var(--accent-text);
    font-size: var(--text-xs);
    font-weight: 500;
    width: fit-content;
    border-radius: var(--radius-xs);
  }
  .nested > summary:focus-visible {
    outline: none;
    box-shadow: var(--focus-ring);
  }
  .nested[open] > summary {
    margin-bottom: var(--space-2);
  }
</style>
