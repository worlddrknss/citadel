<!-- SIEM streaming settings: an HTTPS endpoint that receives every audit event. -->
<script lang="ts">
  import { errorMessage } from '$lib/api';
  import { session } from '$lib/stores/session.svelte';
  import { toast } from '$lib/stores/toast.svelte';
  import Icon from '$lib/components/Icon.svelte';
  import Modal from '$lib/components/Modal.svelte';
  import { isNotImplemented } from '../http';
  import { auditApi } from './api';

  let { open = $bindable(false) }: { open?: boolean } = $props();

  let phase = $state<'loading' | 'ok' | 'unavailable' | 'error'>('loading');
  let error = $state('');
  let enabled = $state(false);
  let url = $state('');
  let format = $state<'json' | 'cef'>('json');
  let token = $state('');
  let hasToken = $state(false);
  let clearToken = $state(false);
  /** The saved configuration: the test sends to this, not to unsaved edits. */
  let saved = $state<{ enabled: boolean; url: string; format: 'json' | 'cef' } | null>(null);
  let saving = $state(false);
  let testing = $state(false);
  const canEdit = $derived(session.can('admin'));

  $effect(() => {
    if (open) void load();
  });

  async function load() {
    phase = 'loading';
    try {
      const c = await auditApi.stream();
      enabled = c.enabled;
      url = c.url;
      format = c.format;
      hasToken = c.hasToken;
      token = '';
      clearToken = false;
      saved = { enabled: c.enabled, url: c.url, format: c.format };
      phase = 'ok';
    } catch (e) {
      phase = isNotImplemented(e) ? 'unavailable' : 'error';
      error = errorMessage(e);
    }
  }

  async function save(e: SubmitEvent) {
    e.preventDefault();
    saving = true;
    try {
      // token: omitted keeps the stored one, "" clears it.
      const c = await auditApi.saveStream({ enabled, url: url.trim(), format, ...(token ? { token } : clearToken ? { token: '' } : {}) });
      hasToken = c.hasToken;
      token = '';
      clearToken = false;
      saved = { enabled: c.enabled, url: c.url, format: c.format };
      toast.success(enabled ? 'Audit streaming is on' : 'Audit streaming settings saved');
      open = false;
    } catch (err) {
      toast.error(err, 'Could not save streaming settings');
    } finally {
      saving = false;
    }
  }

  const dirty = $derived(!!saved && (saved.enabled !== enabled || saved.url !== url.trim() || saved.format !== format || !!token || clearToken));

  async function test() {
    testing = true;
    try {
      const r = await auditApi.testStream();
      if (r.delivered) toast.success('Test event delivered');
      else toast.error(`The endpoint didn't accept the test event${r.status ? ` (HTTP ${r.status})` : ''}`);
    } catch (err) {
      toast.error(err, 'Test failed');
    } finally {
      testing = false;
    }
  }
</script>

<Modal bind:open title="Stream to SIEM" description="Send every audit event to your SIEM as it is written." size="md">
  {#if phase === 'loading'}
    <div class="stack-sm" aria-busy="true">
      <span class="skeleton" style:width="40%" style:height="14px"></span>
      <span class="skeleton" style:width="100%" style:height="var(--ctl-h)"></span>
      <span class="skeleton" style:width="100%" style:height="var(--ctl-h)"></span>
    </div>
  {:else if phase === 'unavailable'}
    <div class="callout callout-info">
      <Icon name="info" />
      <span>This server can't stream audit events yet. Until it can, schedule an export from the Audit log (Export → JSON) and ship the file to your SIEM.</span>
    </div>
  {:else if phase === 'error'}
    <div class="callout callout-danger" role="alert"><Icon name="alert-circle" /><span>{error}</span></div>
  {:else}
    <form id="stream-form" class="stack-sm" onsubmit={save}>
      {#if !canEdit}
        <div class="callout"><Icon name="lock" /><span>Only admins can change streaming settings.</span></div>
      {/if}
      <label class="check">
        <input type="checkbox" bind:checked={enabled} disabled={!canEdit} />
        <span>Stream audit events</span>
      </label>
      <label class="field">
        <span class="field-label">Endpoint URL</span>
        <input class="input mono" type="url" bind:value={url} placeholder="https://siem.example.com/ingest" pattern="https://.*" required={enabled} disabled={!canEdit} />
        <span class="field-hint">HTTPS only. Events are POSTed in batches, oldest first, and retried until accepted.</span>
      </label>
      <label class="field">
        <span class="field-label">Format</span>
        <select class="select" bind:value={format} disabled={!canEdit}>
          <option value="json">JSON lines</option>
          <option value="cef">CEF (ArcSight, QRadar)</option>
        </select>
      </label>
      <label class="field">
        <span class="field-label">Bearer token</span>
        <input class="input" type="password" bind:value={token} autocomplete="off" placeholder={hasToken && !clearToken ? 'Saved. Leave blank to keep it.' : 'Optional'} disabled={!canEdit || clearToken} />
      </label>
      {#if hasToken && canEdit}
        <label class="check">
          <input type="checkbox" bind:checked={clearToken} onchange={() => (token = '')} />
          <span>Remove the saved token</span>
        </label>
      {/if}
    </form>
  {/if}
  {#snippet footer()}
    {#if phase === 'ok' && canEdit}
      <button type="button" class="btn btn-ghost" onclick={test} disabled={testing || !saved?.url || dirty} title={dirty ? 'Save first: the test uses the saved settings' : undefined}>{testing ? 'Sending…' : 'Send test event'}</button>
      <button type="submit" form="stream-form" class="btn btn-primary" disabled={saving}>{saving ? 'Saving…' : 'Save'}</button>
    {:else}
      <button type="button" class="btn btn-secondary" onclick={() => (open = false)}>Close</button>
    {/if}
  {/snippet}
</Modal>

<style>
  .stack-sm {
    display: flex;
    flex-direction: column;
    gap: 14px;
  }
  .stack-sm .field + .field {
    margin-top: 0;
  }
  .check {
    display: flex;
    align-items: center;
    gap: 8px;
    font-weight: 500;
  }
</style>
