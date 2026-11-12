<!-- Approval policies: which environments need how many approvals. -->
<script lang="ts">
  import { api, errorMessage, type Project } from '$lib/api';
  import { session } from '$lib/stores/session.svelte';
  import { toast } from '$lib/stores/toast.svelte';
  import { confirm } from '$lib/stores/confirm.svelte';
  import Icon from '$lib/components/Icon.svelte';
  import Badge from '$lib/components/Badge.svelte';
  import Modal from '$lib/components/Modal.svelte';
  import { isNotImplemented } from '../http';
  import { approvalsApi, envTone, type ApprovalPolicy } from './api';

  let { open = $bindable(false), onclose }: { open?: boolean; onclose?: () => void } = $props();

  let phase = $state<'loading' | 'ok' | 'unavailable' | 'error'>('loading');
  let error = $state('');
  let policies = $state<ApprovalPolicy[]>([]);
  let projects = $state<Project[]>([]);
  const canEdit = $derived(session.can('admin'));

  let project = $state('');
  let env = $state('');
  let required = $state(1);
  let saving = $state(false);

  const envs = $derived(projects.find((p) => p.slug === project)?.environments ?? []);

  $effect(() => {
    if (open) void load();
  });

  async function load() {
    phase = 'loading';
    const [p, pr] = await Promise.allSettled([approvalsApi.policies(), api.projects()]);
    if (pr.status === 'fulfilled') projects = pr.value.projects;
    if (p.status === 'fulfilled') {
      policies = p.value.policies;
      phase = 'ok';
    } else {
      phase = isNotImplemented(p.reason) ? 'unavailable' : 'error';
      error = errorMessage(p.reason);
    }
  }

  async function save(e: SubmitEvent) {
    e.preventDefault();
    if (!project || !env) return;
    saving = true;
    try {
      await approvalsApi.savePolicy({ project, env, approvalsRequired: required });
      toast.success(`${project} / ${env} now needs ${required} approval${required === 1 ? '' : 's'}`);
      project = '';
      env = '';
      required = 1;
      await load();
    } catch (err) {
      toast.error(err, 'Could not save the policy');
    } finally {
      saving = false;
    }
  }

  async function remove(p: ApprovalPolicy) {
    const ok = await confirm({
      title: 'Remove approval policy?',
      message: `Changes to ${p.project} / ${p.env} will apply without a second approver.`,
      confirmLabel: 'Remove policy',
      danger: true
    });
    if (!ok) return;
    try {
      await approvalsApi.savePolicy({ project: p.project, env: p.env, approvalsRequired: 0 });
      toast.success('Policy removed');
      await load();
    } catch (err) {
      toast.error(err, 'Could not remove the policy');
    }
  }
</script>

<Modal bind:open {onclose} title="Approval policies" description="Environments listed here need approvals before a change is applied. The requester can never approve their own change." size="lg">
  {#if phase === 'loading'}
    <div class="stack" aria-busy="true">
      {#each [0, 1, 2] as i (i)}<span class="skeleton" style:width="100%" style:height="20px"></span>{/each}
    </div>
  {:else if phase === 'unavailable'}
    <div class="callout callout-info">
      <Icon name="info" />
      <span>This server uses one built-in rule: every change request needs one admin's approval. Per-environment policies need a newer server.</span>
    </div>
  {:else if phase === 'error'}
    <div class="callout callout-danger" role="alert"><Icon name="alert-circle" /><span>{error}</span></div>
  {:else}
    <div class="stack">
      {#if policies.length}
        <div class="scroll">
          <table class="table">
            <thead><tr><th scope="col">Environment</th><th scope="col">Approvals</th><th scope="col">Who can approve</th>{#if canEdit}<th scope="col"><span class="sr-only">Actions</span></th>{/if}</tr></thead>
            <tbody>
              {#each policies as p (p.project + '/' + p.env)}
                <tr>
                  <td><span class="mono">{p.project}</span> / <Badge tone={envTone(p.env)} dot={false}>{p.env}</Badge></td>
                  <td class="num">{p.approvalsRequired}</td>
                  <td class="muted">{p.approverRoles.join(' or ')}, not the requester</td>
                  {#if canEdit}
                    <td class="end"><button type="button" class="btn btn-danger-ghost btn-sm" onclick={() => remove(p)}>Remove</button></td>
                  {/if}
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {:else}
        <p class="muted">No environment needs approval yet. Changes apply as soon as an editor saves them.</p>
      {/if}

      {#if canEdit}
        <form class="add" onsubmit={save}>
          <label class="field">
            <span class="field-label">Project</span>
            <select class="select" bind:value={project} onchange={() => (env = '')} required>
              <option value="" disabled>Choose…</option>
              {#each projects as p (p.slug)}<option value={p.slug}>{p.slug}</option>{/each}
            </select>
          </label>
          <label class="field">
            <span class="field-label">Environment</span>
            <select class="select" bind:value={env} required disabled={!project}>
              <option value="" disabled>Choose…</option>
              {#each envs as e (e)}<option value={e}>{e}</option>{/each}
            </select>
          </label>
          <label class="field narrow">
            <span class="field-label">Approvals</span>
            <input class="input" type="number" min="1" max="5" bind:value={required} required />
          </label>
          <button type="submit" class="btn btn-primary" disabled={saving || !project || !env}>{saving ? 'Saving…' : 'Add policy'}</button>
        </form>
      {/if}
    </div>
  {/if}
</Modal>

<style>
  .stack {
    display: flex;
    flex-direction: column;
    gap: 16px;
  }
  .scroll {
    overflow-x: auto;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
  }
  .add {
    display: flex;
    flex-wrap: wrap;
    align-items: flex-end;
    gap: 12px;
  }
  .add .field {
    flex: 1 1 160px;
  }
  .add .field + .field {
    margin-top: 0;
  }
  .add .narrow {
    flex: 0 1 100px;
  }
</style>
