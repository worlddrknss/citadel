<!-- Inline rotation settings: Lambda, schedule, optional immediate rotation,
     and turning rotation off. -->
<script lang="ts">
  import { api } from '#lib/api.ts';
  import Icon from '#lib/components/Icon.svelte';
  import { confirm } from '#lib/stores/confirm.svelte.ts';
  import { toast } from '#lib/stores/toast.svelte.ts';
  import type { SecretDetail } from '../../api';

  let {
    detail,
    oncancel,
    onsaved
  }: {
    detail: SecretDetail;
    oncancel: () => void;
    onsaved: () => void;
  } = $props();

  let lambda = $state('');
  let days = $state(30);
  let immediately = $state(false);
  let busy = $state(false);

  $effect.pre(() => {
    lambda = detail.rotation.lambdaArn ?? '';
    days = detail.rotation.afterDays || 30;
    immediately = false;
  });

  const lambdaOk = $derived(/^arn:[^:]+:lambda:/.test(lambda.trim()));
  const daysOk = $derived(Number.isInteger(days) && days >= 1 && days <= 1000);

  const coord = $derived({ project: detail.project, env: detail.env, path: detail.path, key: detail.key });

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    if (!lambdaOk || !daysOk) return;
    busy = true;
    try {
      await api.configureRotation({ ...coord, lambdaArn: lambda.trim(), afterDays: days, rotateImmediately: immediately });
      toast.success(immediately ? 'Saved rotation and started a rotation' : 'Saved rotation schedule');
      onsaved();
    } catch (err) {
      toast.error(err, 'Could not save rotation');
    } finally {
      busy = false;
    }
  }

  async function turnOff() {
    const ok = await confirm({
      title: `Turn off rotation for ${detail.key}?`,
      message: 'The value stops rotating on a schedule. The current value is kept.',
      confirmLabel: 'Turn off rotation',
      danger: true
    });
    if (!ok) return;
    busy = true;
    try {
      await api.cancelRotation(coord.project, coord.env, coord.path, coord.key);
      toast.success('Rotation turned off');
      onsaved();
    } catch (err) {
      toast.error(err, 'Could not turn off rotation');
    } finally {
      busy = false;
    }
  }
</script>

<form class="inline-form" onsubmit={submit}>
  <label class="field">
    <span class="field-label">Rotation Lambda ARN</span>
    <input class="input mono" bind:value={lambda} placeholder="arn:aws:lambda:us-east-1:123456789012:function:rotate" spellcheck="false" aria-invalid={lambda.trim() !== '' && !lambdaOk} />
  </label>
  <label class="field">
    <span class="field-label">Rotate every</span>
    <span class="days"><input class="input num" type="number" min="1" max="1000" bind:value={days} aria-invalid={!daysOk} /><span class="muted">days</span></span>
  </label>
  <label class="check">
    <input type="checkbox" bind:checked={immediately} />
    <span>Rotate once now as well (creates an AWSPENDING version)</span>
  </label>
  <div class="actions">
    {#if detail.rotation.enabled}
      <button type="button" class="btn btn-danger-ghost btn-sm off" onclick={turnOff} disabled={busy}>
        <Icon name="x" size={14} />Turn off
      </button>
    {/if}
    <button type="button" class="btn btn-ghost btn-sm" onclick={oncancel}>Cancel</button>
    <button type="submit" class="btn btn-primary btn-sm" disabled={busy || !lambdaOk || !daysOk}>Save rotation</button>
  </div>
</form>

<style>
  .inline-form {
    display: flex;
    flex-direction: column;
    padding: var(--space-3);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: var(--surface-hover);
  }
  .days {
    display: flex;
    align-items: center;
    gap: var(--space-2);
  }
  .days .input {
    width: 96px;
  }
  .check {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    margin-top: var(--space-3);
    font-size: var(--text-sm);
    cursor: pointer;
  }
  .actions {
    display: flex;
    justify-content: flex-end;
    flex-wrap: wrap;
    gap: var(--space-2);
    margin-top: var(--space-3);
  }
  .off {
    margin-right: auto;
  }
</style>
