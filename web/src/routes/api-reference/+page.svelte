<script lang="ts">
  import { onMount } from 'svelte';
  import { errorMessage } from '#lib/api.ts';
  import Icon from '#lib/components/Icon.svelte';
  import PageHeader from '#lib/components/PageHeader.svelte';
  import EmptyState from '#lib/components/EmptyState.svelte';
  import { base } from '#lib/paths.ts';
  import { rawRequest } from '../http';
  import SchemaView from './SchemaView.svelte';
  import { expandable, filterGroups, parseSpec, typeLabel, type ApiSpec, type Operation } from './spec';

  const SPEC_URL = '/v1/openapi.yaml';

  let spec = $state<ApiSpec | null>(null);
  let loadState = $state<'loading' | 'ok' | 'error'>('loading');
  let loadError = $state('');
  let filter = $state('');

  const groups = $derived(spec ? filterGroups(spec.groups, filter) : []);
  const shown = $derived(groups.reduce((n, g) => n + g.operations.length, 0));

  async function load() {
    loadState = 'loading';
    try {
      const res = await rawRequest(SPEC_URL);
      spec = parseSpec(await res.text());
      loadState = 'ok';
    } catch (e) {
      loadError = errorMessage(e);
      loadState = 'error';
    }
  }

  onMount(load);

  const methodTone: Record<string, string> = { GET: 'info', POST: 'success', PUT: 'warning', PATCH: 'warning', DELETE: 'danger' };
  const slug = (s: string) => s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
  const opAnchor = (op: Operation) => `op-${slug(op.id || `${op.method}-${op.path}`)}`;
  const roleText: Record<string, string> = {
    public: 'No authentication',
    viewer: 'Viewer or above',
    editor: 'Editor or above',
    admin: 'Account admin',
    'platform-admin': 'Platform admin',
    session: 'Any signed-in caller',
    agent: 'Agent token only'
  };
</script>

<svelte:head><title>API reference · Citadel</title></svelte:head>

<PageHeader title="API reference" description="The native /v1 API used by this console and the SDKs. Authenticate with the console session cookie or a bearer access key.">
  {#snippet actions()}
    <a class="btn btn-secondary" href={SPEC_URL} download="citadel-openapi.yaml"><Icon name="download" />OpenAPI YAML</a>
  {/snippet}
</PageHeader>

{#if loadState === 'loading'}
  <div class="card card-pad" aria-busy="true">
    <span class="skeleton" style="width: 40%; height: 14px"></span>
    <span class="sr-only">Loading the API reference…</span>
  </div>
{:else if loadState === 'error'}
  <div class="card card-pad">
    <EmptyState icon="alert-circle" title="Couldn't load the API reference" description={loadError}>
      <button type="button" class="btn btn-secondary" onclick={load}><Icon name="refresh" />Try again</button>
    </EmptyState>
  </div>
{:else if spec}
  <div class="intro card card-pad">
    <div class="auth">
      <h2>Authentication</h2>
      <p>
        Machine clients send <code>Authorization: Bearer &lt;accessKeyId&gt;:&lt;secret&gt;</code> using an access key from <a href="{base}/account?tab=keys">My account</a>; a key acts with its owner's role in the key's account. Browser sessions use the session cookie, and every state-changing request made with the cookie must also send <code>X-Citadel-Request: 1</code>.
      </p>
      <p>Errors are JSON: <code>{'{"error": "<code>", "message": "<text>"}'}</code>.</p>
    </div>
    <div class="ver subtle small">{spec.title}{spec.version ? ` · version ${spec.version}` : ''} · {spec.operationCount} operations</div>
  </div>

  <div class="toolbar">
    <label class="search">
      <span class="sr-only">Filter operations</span>
      <Icon name="search" />
      <input class="input" type="search" bind:value={filter} placeholder="Filter by path, operation, tag, role or audit action" autocomplete="off" />
    </label>
    <span class="subtle small" role="status" aria-live="polite">{filter ? `${shown} of ${spec.operationCount} operations` : ''}</span>
  </div>

  {#if !filter}
    <nav class="tagnav" aria-label="API sections">
      {#each spec.groups as g (g.name)}
        <a href="#tag-{slug(g.name)}">{g.name}<span class="count">{g.operations.length}</span></a>
      {/each}
    </nav>
  {/if}

  {#if groups.length === 0}
    <div class="card card-pad">
      <EmptyState icon="search" title="No matching operations" description="Try a different path, operation ID or tag." />
    </div>
  {/if}

  {#each groups as g (g.name)}
    <section class="group" id="tag-{slug(g.name)}" aria-labelledby="tag-{slug(g.name)}-h">
      <h2 id="tag-{slug(g.name)}-h">{g.name}</h2>
      {#if g.description}<p class="gdesc">{g.description}</p>{/if}
      <div class="ops card">
        {#each g.operations as op (op.method + op.path)}
          <details class="op" id={opAnchor(op)}>
            <summary>
              <span class="badge badge-{methodTone[op.method] ?? 'info'} method">{op.method}</span>
              <span class="path mono">{op.path}</span>
              <span class="sum">{op.summary}</span>
              <Icon name="chevron-down" size={14} />
            </summary>
            <div class="body">
              <dl class="kv facts">
                {#if op.id}<dt>Operation</dt><dd class="mono">{op.id}</dd>{/if}
                <dt>Access</dt>
                <dd>{roleText[op.role] ?? (op.role || (op.authenticated ? 'Authenticated' : 'No authentication'))}</dd>
                {#if op.audit.length}
                  <dt>Audit action</dt>
                  <dd>{#each op.audit as a, i (a)}<code>{a}</code>{i < op.audit.length - 1 ? ', ' : ''}{/each}</dd>
                {/if}
              </dl>
              {#if op.description}<p class="odesc">{op.description}</p>{/if}

              {#if op.parameters.length}
                <h3>Parameters</h3>
                <div class="tablewrap">
                  <table class="table">
                    <thead><tr><th scope="col">Name</th><th scope="col">In</th><th scope="col">Type</th><th scope="col">Description</th></tr></thead>
                    <tbody>
                      {#each op.parameters as p (p.in + p.name)}
                        <tr>
                          <td><code>{p.name}</code>{#if p.required}{" "}<span class="req">required</span>{/if}</td>
                          <td>{p.in}</td>
                          <td class="mono small">{typeLabel(p.schema)}{#if p.schema && Array.isArray(p.schema.enum)}: {p.schema.enum.join(' | ')}{/if}</td>
                          <td>{p.description}</td>
                        </tr>
                      {/each}
                    </tbody>
                  </table>
                </div>
              {/if}

              {#if op.requestBody.length}
                <h3>Request body{op.requestBody[0].required ? '' : ' (optional)'}</h3>
                {#each op.requestBody as b (b.contentType)}
                  <details class="schemabox">
                    <summary><span class="mono">{b.contentType}</span> · <span class="mono">{typeLabel(b.schema)}</span></summary>
                    {#if b.schema}<SchemaView schema={b.schema} components={spec.schemas} />{/if}
                  </details>
                {/each}
              {/if}

              {#if op.responses.length}
                <h3>Responses</h3>
                <ul class="responses">
                  {#each op.responses as r (r.status)}
                    <li>
                      <div class="rhead">
                        <span class="badge badge-{r.status.startsWith('2') ? 'success' : r.status.startsWith('3') ? 'info' : r.status.startsWith('4') ? 'warning' : 'danger'} mono">{r.status}</span>
                        <span>{r.description}</span>
                      </div>
                      {#each r.bodies as b (b.contentType)}
                        {#if b.schema && expandable(b.schema, spec.schemas)}
                          <details class="schemabox">
                            <summary><span class="mono">{b.contentType}</span> · <span class="mono">{typeLabel(b.schema)}</span></summary>
                            <SchemaView schema={b.schema} components={spec.schemas} />
                          </details>
                        {:else if b.schema}
                          <p class="subtle small"><span class="mono">{b.contentType}</span> · <span class="mono">{typeLabel(b.schema)}</span></p>
                        {/if}
                      {/each}
                    </li>
                  {/each}
                </ul>
              {/if}
            </div>
          </details>
        {/each}
      </div>
    </section>
  {/each}
{/if}

<style>
  .intro {
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
    margin-bottom: var(--space-4);
  }
  .intro h2 {
    font-family: var(--font-display);
    font-size: var(--text-lg);
    margin: 0 0 var(--space-2);
  }
  .intro p {
    margin: 0 0 var(--space-2);
    color: var(--text-muted);
    line-height: 1.55;
  }
  code {
    font-family: var(--font-mono);
    font-size: 0.9em;
    overflow-wrap: anywhere;
  }
  .toolbar {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--space-3);
    margin-bottom: var(--space-3);
  }
  .search {
    position: relative;
    flex: 1 1 320px;
    max-width: 560px;
    min-width: 0;
  }
  .search :global(svg) {
    position: absolute;
    left: 10px;
    top: 50%;
    transform: translateY(-50%);
    color: var(--text-subtle);
  }
  .search .input {
    width: 100%;
    padding-left: 32px;
  }
  .tagnav {
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-2);
    margin-bottom: var(--space-5);
  }
  .tagnav a {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 4px 10px;
    border: 1px solid var(--border);
    border-radius: 999px;
    background: var(--surface);
    color: var(--text);
    font-size: var(--text-sm);
    text-decoration: none;
  }
  .tagnav a:hover {
    border-color: var(--border-strong);
    background: var(--surface-hover);
  }
  .tagnav a:focus-visible {
    outline: none;
    box-shadow: var(--focus-ring);
  }
  .count {
    color: var(--text-subtle);
    font-size: var(--text-xs);
  }
  .group {
    margin-bottom: var(--space-6);
    scroll-margin-top: calc(var(--topbar-h) + var(--space-4));
  }
  .group h2 {
    font-family: var(--font-display);
    font-size: var(--text-xl);
    margin: 0 0 var(--space-2);
  }
  .gdesc {
    margin: 0 0 var(--space-3);
    color: var(--text-muted);
  }
  .ops {
    overflow: hidden;
  }
  .op {
    border-bottom: 1px solid var(--border);
    scroll-margin-top: calc(var(--topbar-h) + var(--space-4));
  }
  .op:last-child {
    border-bottom: none;
  }
  .op > summary {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: var(--space-2) var(--space-3);
    min-height: var(--row-h);
    padding: var(--space-2) var(--space-4);
    cursor: pointer;
    list-style: none;
  }
  .op > summary::-webkit-details-marker {
    display: none;
  }
  .op > summary:hover {
    background: var(--surface-hover);
  }
  .op > summary:focus-visible {
    outline: none;
    box-shadow: inset var(--focus-ring);
  }
  .op > summary > :global(svg) {
    margin-left: auto;
    color: var(--text-subtle);
    transition: transform 0.15s;
  }
  .op[open] > summary > :global(svg) {
    transform: rotate(180deg);
  }
  .method {
    min-width: 64px;
    justify-content: center;
    font-family: var(--font-mono);
    font-size: var(--text-xs);
    font-weight: 600;
  }
  .path {
    font-weight: 500;
    overflow-wrap: anywhere;
    min-width: 0;
  }
  .sum {
    color: var(--text-muted);
    font-size: var(--text-sm);
  }
  .body {
    padding: var(--space-2) var(--space-4) var(--space-4);
    border-top: 1px solid var(--border);
    background: var(--surface-sunken);
    min-width: 0;
  }
  .body h3 {
    font-size: var(--text-sm);
    font-weight: 600;
    margin: var(--space-4) 0 var(--space-2);
  }
  .facts {
    margin: var(--space-2) 0 0;
  }
  .odesc {
    margin: var(--space-3) 0 0;
    color: var(--text-muted);
    line-height: 1.55;
    white-space: pre-line;
  }
  .tablewrap {
    overflow-x: auto;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: var(--surface);
  }
  .req {
    color: var(--danger);
    font-size: var(--text-xs);
  }
  .schemabox {
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: var(--surface);
    padding: var(--space-2) var(--space-3);
    margin-top: var(--space-2);
    min-width: 0;
  }
  .schemabox > summary {
    cursor: pointer;
    font-size: var(--text-sm);
    border-radius: var(--radius-xs);
    overflow-wrap: anywhere;
  }
  .schemabox > summary:focus-visible {
    outline: none;
    box-shadow: var(--focus-ring);
  }
  .schemabox[open] > summary {
    margin-bottom: var(--space-2);
  }
  .responses {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
  }
  .rhead {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: var(--space-2);
    font-size: var(--text-sm);
  }
  @media (max-width: 640px) {
    .op > summary {
      padding: var(--space-2) var(--space-3);
    }
    .body {
      padding: var(--space-2) var(--space-3) var(--space-3);
    }
  }
</style>
