<!-- Administration → Notifications: channels that receive agent approval,
     suspension, anomaly and kill-switch events, with their delivery logs. -->
<script lang="ts">
  import { onMount } from 'svelte';
  import DataTable, { type Column } from '#lib/components/DataTable.svelte';
  import EmptyState from '#lib/components/EmptyState.svelte';
  import Badge from '#lib/components/Badge.svelte';
  import Icon from '#lib/components/Icon.svelte';
  import ActionMenu from '#lib/components/ActionMenu.svelte';
  import { errorMessage } from '#lib/api.ts';
  import { toast } from '#lib/stores/toast.svelte.ts';
  import { confirm } from '#lib/stores/confirm.svelte.ts';
  import OnceSecret from '../account/OnceSecret.svelte';
  import ChannelModal from './ChannelModal.svelte';
  import DeliveryDrawer from './DeliveryDrawer.svelte';
  import { fmtDate } from './api';
  import { channelTarget, notificationsApi, typeLabel, type NotificationChannel, type NotificationEventType, type SavedChannel } from './notifications';

  let channels = $state<NotificationChannel[]>([]);
  let events = $state<NotificationEventType[]>([]);
  let emailAvailable = $state(false);
  let loading = $state(true);
  let loadError = $state('');
  let query = $state('');

  let editorOpen = $state(false);
  let editing = $state<NotificationChannel | null>(null);
  let logOpen = $state(false);
  let logChannel = $state<NotificationChannel | null>(null);
  let secretOpen = $state(false);
  let secret = $state({ title: '', value: '' });

  async function load() {
    loading = true;
    loadError = '';
    try {
      const r = await notificationsApi.channels();
      channels = r.channels ?? [];
      events = r.events ?? [];
      emailAvailable = r.emailAvailable;
    } catch (e) {
      loadError = errorMessage(e, 'Could not load notification channels.');
    } finally {
      loading = false;
    }
  }
  onMount(load);

  const eventTitle = (t: string) => events.find((e) => e.type === t)?.title ?? t;

  function add() {
    editing = null;
    editorOpen = true;
  }

  function saved(r: SavedChannel, created: boolean) {
    if (r.signingSecret) showSecret(created ? `${r.channel.name} created` : `New signing secret for ${r.channel.name}`, r.signingSecret);
    void load();
  }

  function showSecret(title: string, value: string) {
    secret = { title, value };
    secretOpen = true;
  }

  async function sendTest(c: NotificationChannel) {
    try {
      await notificationsApi.test(c.id);
      toast.success(`Test notification queued for ${c.name}`);
      logChannel = c;
      logOpen = true;
    } catch (e) {
      toast.error(e, 'Could not send a test');
    }
  }

  async function setEnabled(c: NotificationChannel, enabled: boolean) {
    try {
      await notificationsApi.update(c.id, { enabled });
      toast.success(`${c.name} ${enabled ? 'enabled' : 'disabled'}`);
      await load();
    } catch (e) {
      toast.error(e, 'Could not update the channel');
    }
  }

  async function rotate(c: NotificationChannel) {
    const ok = await confirm({
      title: `Rotate the signing secret for ${c.name}?`,
      message: 'Deliveries are signed with the new secret straight away. Update your receiver before the next event, or it will reject them.',
      confirmLabel: 'Rotate secret',
      danger: true
    });
    if (!ok) return;
    try {
      const r = await notificationsApi.rotateSecret(c.id);
      if (r.signingSecret) showSecret(`New signing secret for ${c.name}`, r.signingSecret);
      await load();
    } catch (e) {
      toast.error(e, 'Could not rotate the signing secret');
    }
  }

  async function remove(c: NotificationChannel) {
    const ok = await confirm({
      title: `Delete ${c.name}?`,
      message: 'It stops receiving notifications at once, and its delivery log is deleted. This cannot be undone.',
      confirmLabel: 'Delete channel',
      danger: true,
      typeToConfirm: c.name
    });
    if (!ok) return;
    try {
      await notificationsApi.remove(c.id);
      toast.success(`Deleted ${c.name}`);
      await load();
    } catch (e) {
      toast.error(e, 'Could not delete the channel');
    }
  }

  const cols: Column<NotificationChannel>[] = [
    { id: 'name', label: 'Channel', sort: (c) => c.name },
    { id: 'type', label: 'Type', sort: (c) => c.type, width: '110px' },
    { id: 'events', label: 'Events', sort: (c) => c.events.length, hideOnMobile: true },
    { id: 'status', label: 'Status', sort: (c) => (c.enabled ? 1 : 0), width: '140px' },
    { id: 'updated', label: 'Updated', sort: (c) => c.updatedAt, hideOnMobile: true },
    { id: 'act', label: '', align: 'end', width: '150px' }
  ];
</script>

{#if loadError}
  <div class="callout callout-danger err" role="alert">
    <Icon name="alert-circle" size={16} /><span>{loadError}</span>
    <button type="button" class="btn btn-ghost btn-sm push" onclick={load}>Retry</button>
  </div>
{/if}

{#if !loading && !emailAvailable}
  <div class="callout callout-info err" role="note">
    <Icon name="info" size={16} />
    <span>Email channels need SMTP settings on the server (<span class="mono">KMS_SMTP_HOST</span> and related settings). Webhook and Slack channels work without them.</span>
  </div>
{/if}

<DataTable caption="Notification channels" rows={channels} columns={cols} key={(c) => c.id} {loading} searchable={(c) => `${c.name} ${c.type} ${channelTarget(c)} ${c.events.join(' ')}`} searchPlaceholder="Search channels" bind:query>
  {#snippet toolbar()}
    <button type="button" class="btn btn-primary" onclick={add}><Icon name="plus" size={16} />Add channel</button>
  {/snippet}
  {#snippet row(c)}
    <td>
      <span class="strong">{c.name}</span>
      <span class="mono subtle sub" title={channelTarget(c)}>{channelTarget(c)}</span>
    </td>
    <td><span class="badge">{typeLabel(c.type)}</span></td>
    <td class="hide-sm">
      {#if c.events.length === 0}
        <span class="subtle small">Test only</span>
      {:else}
        <span class="chips">
          {#each c.events.slice(0, 2) as ev (ev)}<span class="badge" title={ev}>{eventTitle(ev)}</span>{/each}
          {#if c.events.length > 2}<span class="subtle small">+{c.events.length - 2}</span>{/if}
        </span>
      {/if}
    </td>
    <td>
      <label class="switch">
        <input
          type="checkbox"
          role="switch"
          checked={c.enabled}
          onchange={(e) => {
            const on = e.currentTarget.checked;
            e.currentTarget.checked = c.enabled;
            setEnabled(c, on);
          }}
          aria-label="{c.name} enabled"
        />
        <Badge tone={c.enabled ? 'success' : 'neutral'} dot={false}>{c.enabled ? 'Enabled' : 'Disabled'}</Badge>
      </label>
    </td>
    <td class="subtle hide-sm" title="by {c.updatedBy}">{fmtDate(c.updatedAt)}</td>
    <td class="end">
      <span class="cell-actions">
        <button type="button" class="btn btn-ghost btn-sm" onclick={() => { logChannel = c; logOpen = true; }} aria-label="Deliveries for {c.name}">Deliveries</button>
        <ActionMenu
          label="Actions for {c.name}"
          items={[
            { label: 'Send test', icon: 'bell', onselect: () => sendTest(c) },
            { label: 'Edit', icon: 'edit', onselect: () => { editing = c; editorOpen = true; } },
            ...(c.type === 'webhook' ? [{ label: 'Rotate signing secret', icon: 'key' as const, onselect: () => rotate(c) }] : []),
            { label: 'Delete', icon: 'trash', danger: true, onselect: () => remove(c) }
          ]}
        />
      </span>
    </td>
  {/snippet}
  {#snippet empty()}
    <EmptyState icon="bell" title="No notification channels" description="Send agent approval requests, suspensions, anomalies and kill-switch alerts to a webhook, Slack or email.">
      <button type="button" class="btn btn-primary btn-sm" onclick={add}><Icon name="plus" size={14} />Add channel</button>
    </EmptyState>
  {/snippet}
</DataTable>

<ChannelModal bind:open={editorOpen} channel={editing} {events} {emailAvailable} onsaved={saved} />
<DeliveryDrawer bind:open={logOpen} channel={logChannel} />
<OnceSecret
  bind:open={secretOpen}
  title={secret.title}
  description="Use it to verify the X-Citadel-Signature header on every delivery (see the notifications guide)."
  fields={[{ label: 'Signing secret', value: secret.value, secret: true }]}
/>

<style>
  .err {
    margin-bottom: var(--space-4);
    align-items: center;
  }
  .push {
    margin-left: auto;
  }
  .strong {
    font-weight: 500;
  }
  .sub {
    display: block;
    font-size: 12.5px;
    max-width: 360px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .chips {
    display: inline-flex;
    flex-wrap: wrap;
    gap: 4px;
    align-items: center;
  }
  .switch {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    cursor: pointer;
  }
  @media (max-width: 720px) {
    .hide-sm {
      display: none;
    }
  }
</style>
