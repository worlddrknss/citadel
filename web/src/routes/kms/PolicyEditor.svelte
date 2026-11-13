<!-- Key policy JSON editor with live validation, format and reset. -->
<script lang="ts">
  import { api } from '#lib/api.ts';
  import Icon from '#lib/components/Icon.svelte';
  import { toast } from '#lib/stores/toast.svelte.ts';
  import { confirm } from '#lib/stores/confirm.svelte.ts';
  import type { KeyDetail } from './api';

  let { detail, canEdit, onsaved }: { detail: KeyDetail; canEdit: boolean; onsaved: () => void } = $props();

  function pretty(s: string): string {
    if (!s) return '';
    try {
      return JSON.stringify(JSON.parse(s), null, 2);
    } catch {
      return s;
    }
  }

  const original = $derived(pretty(detail.policyDocument || ''));
  let text = $state('');
  let saving = $state(false);
  const uid = Math.random().toString(36).slice(2, 8);

  $effect(() => {
    text = original;
  });

  function position(src: string, msg: string): string {
    const m = /position (\d+)/.exec(msg);
    if (!m) {
      const lc = /line (\d+) column (\d+)/.exec(msg);
      return lc ? ` (line ${lc[1]}, column ${lc[2]})` : '';
    }
    const before = src.slice(0, Number(m[1]));
    const line = before.split('\n').length;
    const col = before.length - before.lastIndexOf('\n');
    return ` (line ${line}, column ${col})`;
  }

  const problems = $derived.by((): string[] => {
    if (!text.trim()) return ['The policy is empty.'];
    let doc: unknown;
    try {
      doc = JSON.parse(text);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return [`Invalid JSON${position(text, msg)}: ${msg.replace(/^JSON\.parse: /, '')}`];
    }
    if (typeof doc !== 'object' || doc === null || Array.isArray(doc)) return ['The policy must be a JSON object.'];
    const out: string[] = [];
    const d = doc as Record<string, unknown>;
    if (d.Version !== '2012-10-17') out.push('"Version" should be "2012-10-17".');
    const st = Array.isArray(d.Statement) ? d.Statement : d.Statement ? [d.Statement] : [];
    if (st.length === 0) out.push('"Statement" needs at least one statement.');
    st.forEach((s, i) => {
      const n = `Statement ${i + 1}`;
      if (typeof s !== 'object' || s === null) {
        out.push(`${n} must be an object.`);
        return;
      }
      const o = s as Record<string, unknown>;
      if (o.Effect !== 'Allow' && o.Effect !== 'Deny') out.push(`${n}: "Effect" must be "Allow" or "Deny".`);
      if (!o.Action && !o.NotAction) out.push(`${n}: add "Action" or "NotAction".`);
      if (!o.Principal && !o.NotPrincipal) out.push(`${n}: key policies need a "Principal".`);
      if (!o.Resource && !o.NotResource) out.push(`${n}: add "Resource" (usually "*").`);
    });
    return out;
  });

  const dirty = $derived(text !== original);
  const valid = $derived(problems.length === 0);

  function format() {
    text = pretty(text);
  }

  async function save() {
    if (!valid || !dirty || saving) return;
    const ok = await confirm({
      title: 'Save key policy?',
      message:
        'The new policy replaces the current one immediately. A policy that removes your own access can lock everyone out of this key.',
      confirmLabel: 'Save policy'
    });
    if (!ok) return;
    saving = true;
    try {
      await api.putKmsKeyPolicy(detail.keyId, JSON.stringify(JSON.parse(text)));
      toast.success('Saved key policy');
      onsaved();
    } catch (e) {
      toast.error(e);
    } finally {
      saving = false;
    }
  }
</script>

<div class="policy">
  <div class="field">
    <span class="head">
      <label class="field-label" for="pol-{uid}">Key policy</label>
      {#if canEdit}
        <span class="tools">
          <button type="button" class="btn btn-ghost btn-sm" onclick={format} disabled={!text.trim()}>Format</button>
          <button type="button" class="btn btn-ghost btn-sm" onclick={() => (text = original)} disabled={!dirty}>Reset</button>
        </span>
      {/if}
    </span>
    <textarea
      id="pol-{uid}"
      class="textarea mono editor"
      rows="18"
      bind:value={text}
      readonly={!canEdit}
      spellcheck="false"
      autocomplete="off"
      aria-invalid={!valid}
      aria-describedby="pol-msg-{uid}"
    ></textarea>
    <div id="pol-msg-{uid}" aria-live="polite">
      {#if valid}
        <span class="ok small"><Icon name="check-circle" size={12} />Valid policy JSON</span>
      {:else}
        <ul class="errs">
          {#each problems as p (p)}<li class="field-error"><Icon name="alert-circle" size={12} />{p}</li>{/each}
        </ul>
      {/if}
    </div>
  </div>
  {#if canEdit}
    <div class="actions">
      <button type="button" class="btn btn-primary btn-sm" disabled={!valid || !dirty || saving} onclick={save}>
        {saving ? 'Saving…' : 'Save policy'}
      </button>
      {#if dirty}<span class="subtle small">Unsaved changes</span>{/if}
    </div>
  {/if}
</div>

<style>
  .policy {
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
  }
  .head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--space-2);
  }
  .tools {
    display: inline-flex;
    gap: 2px;
  }
  .editor {
    font-size: 13px;
    line-height: 19px;
    background: var(--surface-sunken);
    tab-size: 2;
    white-space: pre;
    overflow: auto;
  }
  .ok {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    color: var(--success);
  }
  .errs {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .errs li {
    display: flex;
    align-items: flex-start;
    gap: 4px;
  }
  .errs :global(svg) {
    margin-top: 2px;
  }
  .actions {
    display: flex;
    align-items: center;
    gap: var(--space-3);
  }
</style>
