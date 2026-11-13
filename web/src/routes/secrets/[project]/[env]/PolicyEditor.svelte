<!-- Resource policy JSON for a secret, with format and save for editors. -->
<script lang="ts">
  import { api } from '#lib/api.ts';
  import { toast } from '#lib/stores/toast.svelte.ts';

  let {
    coord,
    policy,
    canEdit,
    onsaved
  }: {
    coord: { project: string; env: string; path: string; key: string };
    policy: string;
    canEdit: boolean;
    onsaved: () => void;
  } = $props();

  let doc = $state('');
  let busy = $state(false);

  function pretty(raw: string): string {
    const t = (raw ?? '').trim();
    if (!t) return '';
    try {
      return JSON.stringify(JSON.parse(t), null, 2);
    } catch {
      return raw;
    }
  }

  $effect.pre(() => {
    doc = pretty(policy);
  });

  const jsonError = $derived.by(() => {
    if (!doc.trim()) return '';
    try {
      JSON.parse(doc);
      return '';
    } catch (e) {
      return e instanceof Error ? e.message : 'Invalid JSON';
    }
  });
  const dirty = $derived(doc.trim() !== pretty(policy).trim());

  async function save(e: SubmitEvent) {
    e.preventDefault();
    if (jsonError) return;
    busy = true;
    try {
      await api.putSecretPolicy(coord.project, coord.env, coord.path, coord.key, doc.trim());
      toast.success('Saved resource policy');
      onsaved();
    } catch (err) {
      toast.error(err, 'Could not save the policy');
    } finally {
      busy = false;
    }
  }
</script>

<form class="pe" onsubmit={save}>
  <label class="field">
    <span class="field-label">Resource policy</span>
    <textarea
      class="textarea mono"
      rows="12"
      spellcheck="false"
      bind:value={doc}
      readonly={!canEdit}
      placeholder={'{\n  "Version": "2012-10-17",\n  "Statement": []\n}'}
      aria-invalid={!!jsonError}
      aria-describedby="pol-hint"
    ></textarea>
    <span id="pol-hint" class={jsonError ? 'field-error' : 'field-hint'}>
      {jsonError || 'IAM-style JSON. Principals listed here can call Secrets Manager on this secret with their own credentials.'}
    </span>
  </label>
  {#if canEdit}
    <div class="actions">
      <button type="button" class="btn btn-ghost btn-sm" disabled={!!jsonError || !doc.trim()} onclick={() => (doc = pretty(doc))}>Format</button>
      <button type="button" class="btn btn-ghost btn-sm" disabled={!dirty} onclick={() => (doc = pretty(policy))}>Discard</button>
      <button type="submit" class="btn btn-primary btn-sm" disabled={busy || !!jsonError || !dirty}>Save policy</button>
    </div>
  {/if}
</form>

<style>
  .pe {
    display: flex;
    flex-direction: column;
  }
  .textarea {
    font-size: 13px;
    white-space: pre;
    overflow-x: auto;
  }
  .actions {
    display: flex;
    justify-content: flex-end;
    gap: var(--space-2);
    margin-top: var(--space-3);
  }
</style>
