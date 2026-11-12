<!-- Automatic key rotation: status, enable/disable with a period, history. -->
<script lang="ts">
  import Icon from '$lib/components/Icon.svelte';
  import Badge from '$lib/components/Badge.svelte';
  import { toast } from '$lib/stores/toast.svelte';
  import { confirm } from '$lib/stores/confirm.svelte';
  import { errorMessage } from '$lib/api';
  import { kms, fmtDate, fmtDateTime, periodLabel, SYMMETRIC, type KeyDetail, type RotationStatus } from './api';

  let { detail, canEdit, onchanged }: { detail: KeyDetail; canEdit: boolean; onchanged: () => void } = $props();

  const supported = $derived(detail.keySpec === SYMMETRIC);
  const keyId = $derived(detail.keyId);
  let status = $state<RotationStatus | null>(null);
  let loading = $state(false);
  let error = $state('');
  let period = $state(365);
  let busy = $state(false);
  const uid = Math.random().toString(36).slice(2, 8);
  const periodValid = $derived(Number.isInteger(period) && period >= 90 && period <= 2560);

  async function load(keyId: string) {
    loading = true;
    error = '';
    try {
      const s = await kms.rotation(keyId);
      if (keyId !== detail.keyId) return;
      status = s;
      period = s.rotationPeriodDays || 365;
    } catch (e) {
      error = errorMessage(e);
    } finally {
      loading = false;
    }
  }

  $effect(() => {
    status = null;
    if (supported) load(keyId);
  });

  async function rotateNow() {
    if (busy) return;
    const ok = await confirm({
      title: 'Rotate key material now?',
      message: 'New data is encrypted with fresh key material right away. Earlier key material is kept, so existing ciphertext still decrypts.',
      confirmLabel: 'Rotate now'
    });
    if (!ok) return;
    busy = true;
    try {
      status = await kms.rotateNow(detail.keyId);
      toast.success('Key material rotated');
      onchanged();
    } catch (e) {
      toast.error(e);
    } finally {
      busy = false;
    }
  }

  async function apply(enabled: boolean) {
    if (busy) return;
    if (enabled && !periodValid) return;
    if (!enabled) {
      const ok = await confirm({
        title: 'Turn off automatic rotation?',
        message: 'The current key material stays in use until you turn rotation back on. Existing ciphertext is unaffected.',
        confirmLabel: 'Turn off',
        danger: true
      });
      if (!ok) return;
    }
    busy = true;
    try {
      status = await kms.setRotation(detail.keyId, enabled, enabled ? period : undefined);
      toast.success(enabled ? `Rotation on · ${periodLabel(period).toLowerCase()}` : 'Rotation turned off');
      onchanged();
    } catch (e) {
      toast.error(e);
    } finally {
      busy = false;
    }
  }
</script>

{#if !supported}
  <div class="callout callout-info" role="note">
    <Icon name="info" size={16} />
    <span>Automatic rotation applies to symmetric keys only. To rotate an asymmetric key, create a new key and move its alias.</span>
  </div>
{:else if loading && !status}
  <div class="skel" aria-busy="true" aria-label="Loading rotation">
    <span class="skeleton"></span><span class="skeleton"></span><span class="skeleton short"></span>
  </div>
{:else if error}
  <div class="callout callout-danger" role="alert">
    <Icon name="alert-circle" size={16} />
    <span class="grow">{error}</span>
    <button type="button" class="btn btn-ghost btn-sm" onclick={() => load(detail.keyId)}>Retry</button>
  </div>
{:else if status}
  <div class="rot">
    <div class="state">
      <div class="state-text">
        <span class="label">Automatic rotation</span>
        {#if status.enabled}
          <span class="line"><Badge tone="success">On</Badge>{periodLabel(status.rotationPeriodDays)}</span>
        {:else}
          <span class="line"><Badge tone="neutral">Off</Badge><span class="muted">Key material never changes</span></span>
        {/if}
      </div>
    </div>
    <dl class="kv">
      <dt>Last rotated</dt>
      <dd>{status.lastRotatedAt ? fmtDate(status.lastRotatedAt) : 'Never'}</dd>
      <dt>Next rotation</dt>
      <dd>{status.enabled && status.nextRotationAt ? fmtDate(status.nextRotationAt) : '—'}</dd>
    </dl>

    {#if canEdit}
      <div class="ctl">
        <label class="field period">
          <span class="field-label">Rotation period (days)</span>
          <input
            id="rp-{uid}"
            class="input num"
            type="number"
            min="90"
            max="2560"
            step="1"
            bind:value={period}
            aria-invalid={!periodValid}
            aria-describedby="rp-hint-{uid}"
          />
          <span id="rp-hint-{uid}" class={periodValid ? 'field-hint' : 'field-error'}>Between 90 and 2560 days. 365 is yearly.</span>
        </label>
        <div class="ctl-btns">
          {#if status.enabled}
            <button type="button" class="btn btn-secondary btn-sm" disabled={busy || !periodValid || period === status.rotationPeriodDays} onclick={() => apply(true)}>
              Update period
            </button>
            <button type="button" class="btn btn-danger-ghost btn-sm" disabled={busy} onclick={() => apply(false)}>Turn off</button>
          {:else}
            <button type="button" class="btn btn-primary btn-sm" disabled={busy || !periodValid} onclick={() => apply(true)}>
              <Icon name="rotate" size={14} />Turn on rotation
            </button>
          {/if}
          <button type="button" class="btn btn-ghost btn-sm" disabled={busy || !detail.enabled} onclick={rotateNow}>Rotate now</button>
        </div>
      </div>
    {/if}

    <div class="hist">
      <span class="label">Rotation history</span>
      {#if status.history.length === 0}
        <p class="subtle small">No rotations yet. Old key material is kept, so earlier ciphertext still decrypts.</p>
      {:else}
        <ol class="timeline">
          {#each status.history as h, i (h.rotatedAt + i)}
            <li>
              <span class="rail" aria-hidden="true"><span class="dot" class:current={i === 0}></span><span class="line-v"></span></span>
              <div class="entry">
                <span class="entry-top">
                  <span>{fmtDateTime(h.rotatedAt)}</span>
                  <Badge tone={h.kind === 'automatic' ? 'neutral' : 'info'} dot={false}>{h.kind === 'automatic' ? 'Automatic' : 'On demand'}</Badge>
                  {#if i === 0}<Badge tone="success" dot={false}>Current</Badge>{/if}
                </span>
                {#if h.keyMaterialId}<span class="mono subtle small">{h.keyMaterialId}</span>{/if}
              </div>
            </li>
          {/each}
        </ol>
      {/if}
    </div>
  </div>
{/if}

<style>
  .skel {
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
  }
  .skel .skeleton {
    height: 14px;
    width: 80%;
  }
  .skel .short {
    width: 40%;
  }
  .grow {
    flex: 1;
  }
  .rot {
    display: flex;
    flex-direction: column;
    gap: var(--space-5);
  }
  .label {
    font: 600 var(--text-xs) / 16px var(--font-sans);
    letter-spacing: 0.06em;
    text-transform: uppercase;
    color: var(--text-subtle);
  }
  .state-text {
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
  }
  .line {
    display: inline-flex;
    align-items: center;
    gap: var(--space-2);
  }
  .ctl {
    display: flex;
    flex-wrap: wrap;
    align-items: flex-end;
    gap: var(--space-3);
    padding: var(--space-3);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: var(--surface-hover);
  }
  .period {
    flex: 1 1 180px;
  }
  .ctl-btns {
    display: flex;
    gap: var(--space-2);
    padding-bottom: 20px;
  }
  .hist {
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
  }
  .hist p {
    margin: 0;
  }
  .timeline {
    list-style: none;
    margin: 0;
    padding: 0;
  }
  .timeline li {
    display: grid;
    grid-template-columns: 16px minmax(0, 1fr);
    gap: var(--space-3);
  }
  .rail {
    display: flex;
    flex-direction: column;
    align-items: center;
  }
  .dot {
    width: 10px;
    height: 10px;
    margin-top: 5px;
    border-radius: 50%;
    background: var(--surface-pressed);
    border: 2px solid var(--surface);
    box-shadow: 0 0 0 1px var(--border-strong);
  }
  .dot.current {
    background: var(--accent);
  }
  .line-v {
    flex: 1;
    width: 1px;
    background: var(--border);
  }
  .timeline li:last-child .line-v {
    display: none;
  }
  .entry {
    display: flex;
    flex-direction: column;
    gap: 2px;
    padding-bottom: 14px;
    min-width: 0;
  }
  .entry-top {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--space-2);
  }
</style>
