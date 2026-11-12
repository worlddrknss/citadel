<!-- Organization settings: change approval policy and console session
     lifetimes. SSO lives in its own card below (SsoPanel). -->
<script lang="ts">
  import { onMount } from 'svelte';
  import Icon from '$lib/components/Icon.svelte';
  import { api, errorMessage } from '$lib/api';
  import { toast } from '$lib/stores/toast.svelte';
  import { confirm } from '$lib/stores/confirm.svelte';
  import { adminApi, fmtDate, type OrgSettings } from './api';

  let saved = $state<OrgSettings | null>(null);
  let form = $state<OrgSettings | null>(null);
  let envs = $state<string[]>([]);
  let loading = $state(true);
  let loadError = $state('');
  let saving = $state(false);

  async function load() {
    loading = true;
    loadError = '';
    try {
      const [s, p] = await Promise.all([adminApi.settings(), api.projects().catch(() => ({ projects: [] }))]);
      saved = s;
      form = { ...s, approvalEnvironments: [...(s.approvalEnvironments ?? [])] };
      const set = new Set<string>(['production', 'staging', 'development']);
      for (const pr of p.projects) for (const e of pr.environments) set.add(e);
      for (const e of s.approvalEnvironments ?? []) set.add(e);
      const order = ['production', 'staging', 'development'];
      envs = [...set].sort((a, b) => {
        const ia = order.indexOf(a);
        const ib = order.indexOf(b);
        return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib) || a.localeCompare(b);
      });
    } catch (e) {
      loadError = errorMessage(e, 'Could not load organization settings.');
    } finally {
      loading = false;
    }
  }
  onMount(load);

  const dirty = $derived(!!form && !!saved && JSON.stringify(strip(form)) !== JSON.stringify(strip(saved)));
  function strip(s: OrgSettings) {
    return {
      approvalEnvironments: [...s.approvalEnvironments].sort(),
      approvalMinApprovers: s.approvalMinApprovers,
      sessionIdleMinutes: s.sessionIdleMinutes,
      sessionMaxHours: s.sessionMaxHours
    };
  }

  const idleError = $derived(form && (!Number.isInteger(form.sessionIdleMinutes) || form.sessionIdleMinutes < 5 || form.sessionIdleMinutes > 1440) ? 'Between 5 and 1440 minutes.' : '');
  const maxError = $derived(
    form && (!Number.isInteger(form.sessionMaxHours) || form.sessionMaxHours < 1 || form.sessionMaxHours > 720)
      ? 'Between 1 and 720 hours.'
      : form && form.sessionMaxHours * 60 < form.sessionIdleMinutes
        ? 'Must be at least the idle timeout.'
        : ''
  );

  function toggleEnv(env: string, on: boolean) {
    if (!form) return;
    form.approvalEnvironments = on ? [...new Set([...form.approvalEnvironments, env])] : form.approvalEnvironments.filter((e) => e !== env);
  }

  async function save(e: SubmitEvent) {
    e.preventDefault();
    if (!form || idleError || maxError) return;
    const removed = (saved?.approvalEnvironments ?? []).filter((x) => !form!.approvalEnvironments.includes(x));
    if (removed.length) {
      const ok = await confirm({
        title: 'Stop requiring approval?',
        message: `Changes in ${removed.join(', ')} will apply immediately, without a second person reviewing them.`,
        confirmLabel: 'Remove approval',
        danger: true
      });
      if (!ok) return;
    }
    saving = true;
    try {
      const s = await adminApi.saveSettings(strip(form));
      saved = s;
      form = { ...s, approvalEnvironments: [...s.approvalEnvironments] };
      toast.success('Organization settings saved');
    } catch (err) {
      toast.error(err, 'Could not save settings');
    } finally {
      saving = false;
    }
  }
</script>

<section class="card" aria-labelledby="org-title">
  <div class="card-head">
    <div>
      <h2 id="org-title">Organization settings</h2>
      {#if saved?.updatedAt}<p class="subtle small sub">Last changed {fmtDate(saved.updatedAt)}{saved.updatedBy ? ` by ${saved.updatedBy}` : ''}</p>{/if}
    </div>
  </div>
  {#if loadError}
    <div class="card-pad"><div class="callout callout-danger" role="alert"><Icon name="alert-circle" size={16} /><span>{loadError}</span><button type="button" class="btn btn-ghost btn-sm push" onclick={load}>Retry</button></div></div>
  {:else if loading || !form}
    <div class="card-pad sk" aria-busy="true"><span class="skeleton"></span><span class="skeleton"></span><span class="skeleton"></span></div>
  {:else}
    <form onsubmit={save} novalidate>
      <div class="group">
        <div class="gtext">
          <h3>Change approvals</h3>
          <p class="muted small">Secret changes in these environments become change requests that another person must approve.</p>
        </div>
        <div class="gbody">
          <fieldset>
            <legend class="sr-only">Environments that require approval</legend>
            {#each envs as env (env)}
              <label class="check">
                <input type="checkbox" checked={form.approvalEnvironments.includes(env)} onchange={(e) => toggleEnv(env, e.currentTarget.checked)} />
                <span class="badge env env-{env}">{env}</span>
              </label>
            {/each}
          </fieldset>
          <div class="field-row">
            <div class="field">
              <label class="field-label" for="s-min">Approvals needed</label>
              <select id="s-min" class="select" bind:value={form.approvalMinApprovers}>
                {#each [1, 2, 3] as n (n)}<option value={n}>{n} approver{n > 1 ? 's' : ''}</option>{/each}
              </select>
            </div>
          </div>
          <p class="subtle small">Requesters can never approve their own changes.</p>
        </div>
      </div>

      <div class="group">
        <div class="gtext">
          <h3>Console sessions</h3>
          <p class="muted small">Applies to new sign-ins. Access keys and STS credentials have their own lifetimes.</p>
        </div>
        <div class="gbody">
          <div class="field-row">
            <div class="field">
              <label class="field-label" for="s-idle">Idle timeout (minutes)</label>
              <input id="s-idle" class="input num" type="number" min="5" max="1440" bind:value={form.sessionIdleMinutes} aria-invalid={!!idleError} />
              {#if idleError}<span class="field-error">{idleError}</span>{:else}<span class="field-hint">Sign out after this long without activity.</span>{/if}
            </div>
            <div class="field">
              <label class="field-label" for="s-max">Maximum session (hours)</label>
              <input id="s-max" class="input num" type="number" min="1" max="720" bind:value={form.sessionMaxHours} aria-invalid={!!maxError} />
              {#if maxError}<span class="field-error">{maxError}</span>{:else}<span class="field-hint">Sign in again after this long, active or not.</span>{/if}
            </div>
          </div>
        </div>
      </div>

      <div class="foot">
        {#if dirty}<span class="subtle small">Unsaved changes</span>{/if}
        <button type="button" class="btn btn-ghost" disabled={!dirty || saving} onclick={() => saved && (form = { ...saved, approvalEnvironments: [...saved.approvalEnvironments] })}>Discard</button>
        <button type="submit" class="btn btn-primary" disabled={!dirty || saving}>{saving ? 'Saving…' : 'Save settings'}</button>
      </div>
    </form>
  {/if}
</section>

<style>
  .card-head h2 {
    font-family: var(--font-sans);
    font-size: var(--text-md);
    letter-spacing: 0;
  }
  .sub {
    margin: 2px 0 0;
  }
  .sk {
    display: flex;
    flex-direction: column;
    gap: 10px;
  }
  .sk .skeleton {
    height: 14px;
  }
  .push {
    margin-left: auto;
  }
  .group {
    display: grid;
    grid-template-columns: minmax(0, 1fr) minmax(0, 2fr);
    gap: var(--space-5);
    padding: var(--space-5);
    border-bottom: 1px solid var(--border);
  }
  @media (max-width: 820px) {
    .group {
      grid-template-columns: minmax(0, 1fr);
      gap: var(--space-3);
    }
  }
  .gtext h3 {
    margin: 0 0 4px;
    font-size: var(--text-base);
    font-weight: 600;
  }
  .gtext p {
    margin: 0;
  }
  .gbody {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
  }
  fieldset {
    margin: 0;
    padding: 0;
    border: 0;
    display: flex;
    flex-wrap: wrap;
    gap: 8px 20px;
  }
  .check {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    cursor: pointer;
  }
  .env-production {
    background: var(--danger-soft);
    color: var(--danger);
  }
  .env-staging {
    background: var(--warning-soft);
    color: var(--warning);
  }
  .env-development {
    background: var(--info-soft);
    color: var(--info);
  }
  .foot {
    display: flex;
    align-items: center;
    justify-content: flex-end;
    gap: 8px;
    padding: 12px var(--space-5);
    background: var(--surface-hover);
    border-radius: 0 0 var(--radius-lg) var(--radius-lg);
  }
</style>
