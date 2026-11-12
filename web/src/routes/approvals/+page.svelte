<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { api, errorMessage, type ChangeRequest } from '$lib/api';
  import { session } from '$lib/stores/session.svelte';
  import { toast } from '$lib/stores/toast.svelte';
  import { confirm } from '$lib/stores/confirm.svelte';
  import { param, setParams } from '$lib/url';
  import Icon from '$lib/components/Icon.svelte';
  import Badge from '$lib/components/Badge.svelte';
  import PageHeader from '$lib/components/PageHeader.svelte';
  import EmptyState from '$lib/components/EmptyState.svelte';
  import { isNotImplemented } from '../http';
  import { fullTime, initials, relTime } from '../time';
  import PoliciesModal from './PoliciesModal.svelte';
  import { approvalsApi, envTone, fingerprint, shortId, type ChangeRequestDetail } from './api';

  type View = 'forme' | 'open' | 'closed';

  const me = $derived(session.me);
  const isAdmin = $derived(session.can('admin'));
  const view = $derived((param('view') || (isAdmin ? 'forme' : 'open')) as View);
  const selectedId = $derived(param('cr'));
  const policiesOpen = $derived(param('policies') === '1');

  // ---- list ---------------------------------------------------------------
  let list = $state<ChangeRequest[]>([]);
  let listState = $state<'loading' | 'ok' | 'error'>('loading');
  let listError = $state('');

  async function loadList() {
    if (listState !== 'ok') listState = 'loading';
    try {
      list = (await api.changeRequests()).changeRequests.sort((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt));
      listState = 'ok';
    } catch (e) {
      listError = errorMessage(e, "Couldn't load change requests");
      listState = 'error';
    }
  }
  onMount(loadList);

  const mine = (c: ChangeRequest) => c.requester === me?.username;
  const forMe = $derived(list.filter((c) => c.status === 'pending' && !mine(c) && isAdmin));
  const openList = $derived(list.filter((c) => c.status === 'pending'));
  const closed = $derived(list.filter((c) => c.status !== 'pending'));
  const shown = $derived(view === 'forme' ? forMe : view === 'open' ? openList : closed);

  // Select the first request in the view when nothing (valid) is selected.
  const current = $derived(list.find((c) => c.id === selectedId) ?? shown[0] ?? null);

  function status(c: ChangeRequest): { text: string; tone: 'accent' | 'neutral' | 'success' | 'danger' | 'info' } {
    if (c.status === 'approved') return { text: 'Approved', tone: 'success' };
    if (c.status === 'rejected') return { text: 'Rejected', tone: 'danger' };
    if (mine(c)) return { text: 'Waiting on others', tone: 'neutral' };
    if (isAdmin) return { text: 'Needs your review', tone: 'accent' };
    return { text: 'Open', tone: 'info' };
  }

  // ---- detail -------------------------------------------------------------
  let detail = $state<ChangeRequestDetail | null>(null);
  let detailState = $state<'idle' | 'loading' | 'ok' | 'error'>('idle');
  let detailError = $state('');
  let legacyDetail = $state(false);
  let comment = $state('');
  let busy = $state<'' | 'approve' | 'reject'>('');
  let seq = 0;

  async function loadDetail(c: ChangeRequest) {
    const my = ++seq;
    detailState = 'loading';
    try {
      const d = await approvalsApi.detail(c.id);
      if (my !== seq) return;
      detail = d;
      legacyDetail = false;
      detailState = 'ok';
    } catch (e) {
      if (my !== seq) return;
      if (isNotImplemented(e)) {
        // Older server: build what we can from the list entry.
        detail = {
          ...c,
          changes: [{ key: c.key, path: c.path, change: 'modified' }],
          canApprove: c.status === 'pending' && isAdmin && !mine(c),
          cannotApproveReason: mine(c) ? "You can't approve your own request" : !isAdmin ? 'Only admins can approve change requests' : undefined
        };
        legacyDetail = true;
        detailState = 'ok';
      } else {
        detailError = errorMessage(e, "Couldn't load this change request");
        detailState = 'error';
      }
    }
  }

  let lastLoaded = '';
  $effect(() => {
    const c = current;
    const key = c ? `${c.id}:${c.status}` : '';
    if (key === lastLoaded) return;
    lastLoaded = key;
    hideValues();
    comment = '';
    if (c) void loadDetail(c);
    else {
      detail = null;
      detailState = 'idle';
    }
  });

  const isMine = $derived(!!detail && detail.requester === me?.username);
  // The requester can never approve, whatever the server or role says.
  const canDecide = $derived(!!detail && detail.status === 'pending' && detail.canApprove && !isMine);
  const blockReason = $derived(
    !detail || detail.status !== 'pending'
      ? ''
      : isMine
        ? "You can't approve your own request"
        : !detail.canApprove
          ? (detail.cannotApproveReason ?? "You aren't an eligible approver for this change")
          : ''
  );
  const title = $derived.by(() => {
    if (!detail) return '';
    if (detail.title) return detail.title;
    const ch = detail.changes;
    if (ch.length === 1) return `${ch[0].change === 'added' ? 'Add' : ch[0].change === 'deleted' ? 'Delete' : 'Update'} ${ch[0].key}`;
    return `Change ${ch.length} secrets`;
  });
  const scopePath = $derived(detail ? [detail.project, detail.env, detail.path].filter(Boolean).join('/') : '');
  const approvals = $derived(detail?.approvals?.length ?? (detail?.status === 'approved' ? 1 : 0));
  const required = $derived(detail?.policy?.approvalsRequired ?? 1);
  const nextVersion = $derived(detail?.changes.find((c) => c.proposed?.version)?.proposed?.version);

  // ---- reveal -------------------------------------------------------------
  let values = $state<Record<string, { previousValue?: string; proposedValue?: string }> | null>(null);
  let revealing = $state(false);
  let hideTimer: ReturnType<typeof setTimeout> | undefined;
  function hideValues() {
    clearTimeout(hideTimer);
    values = null;
  }
  onDestroy(() => clearTimeout(hideTimer));

  async function reveal() {
    if (!detail) return;
    if (values) return hideValues();
    const ok = await confirm({
      title: 'Reveal values?',
      message: `The plaintext values in ${shortId(detail.id)} will be shown for 30 seconds. Revealing is written to the audit log.`,
      confirmLabel: 'Reveal values'
    });
    if (!ok) return;
    revealing = true;
    try {
      const r = await approvalsApi.values(detail.id);
      values = Object.fromEntries(r.changes.map((c) => [c.key, c]));
      hideTimer = setTimeout(hideValues, 30_000);
    } catch (e) {
      toast.error(isNotImplemented(e) ? "This server can't reveal change request values yet." : e, 'Could not reveal values');
    } finally {
      revealing = false;
    }
  }

  // ---- decide -------------------------------------------------------------
  function changed() {
    window.dispatchEvent(new CustomEvent('citadel:approvals-changed'));
  }

  async function approve() {
    if (!detail || !canDecide) return;
    const ok = await confirm({
      title: `Approve ${shortId(detail.id)}?`,
      message: `${detail.changes.length === 1 ? detail.changes[0].key : `${detail.changes.length} secrets`} in ${detail.project} / ${detail.env} will be written right away.`,
      confirmLabel: 'Approve and apply'
    });
    if (!ok) return;
    busy = 'approve';
    try {
      await approvalsApi.approve(detail.id, comment.trim());
      toast.success(`${shortId(detail.id)} approved and applied`);
      changed();
      await loadList();
    } catch (e) {
      toast.error(e, 'Could not approve');
    } finally {
      busy = '';
    }
  }

  let commentEl = $state<HTMLTextAreaElement>();
  let commentError = $state('');
  async function reject() {
    if (!detail || !canDecide) return;
    if (!comment.trim()) {
      commentError = 'Add a comment so the requester knows why.';
      commentEl?.focus();
      return;
    }
    const ok = await confirm({
      title: `Reject ${shortId(detail.id)}?`,
      message: 'The change is discarded. The requester sees your comment and can open a new request.',
      confirmLabel: 'Reject',
      danger: true
    });
    if (!ok) return;
    busy = 'reject';
    try {
      await approvalsApi.reject(detail.id, comment.trim());
      toast.success(`${shortId(detail.id)} rejected`);
      changed();
      await loadList();
    } catch (e) {
      toast.error(e, 'Could not reject');
    } finally {
      busy = '';
    }
  }

  function select(c: ChangeRequest, e: MouseEvent) {
    e.preventDefault();
    setParams({ cr: c.id });
  }

  const views: { id: View; label: string; count?: () => number }[] = [
    { id: 'forme', label: 'For me', count: () => forMe.length },
    { id: 'open', label: 'Open', count: () => openList.length },
    { id: 'closed', label: 'Closed' }
  ];
</script>

<PageHeader title="Approvals" description="Change requests for protected environments and keys. Every decision is written to the audit log.">
  {#snippet actions()}
    <button type="button" class="btn btn-secondary" onclick={() => setParams({ policies: '1' })}><Icon name="settings" />Approval policies</button>
  {/snippet}
</PageHeader>

<div class="layout">
  <section class="card card-flush inbox" aria-labelledby="ib-title">
    <div class="inbox-head">
      <h2 id="ib-title" class="sr-only">Change requests</h2>
      <div class="seg" role="group" aria-label="Inbox filter">
        {#each views.filter((v) => v.id !== 'forme' || isAdmin) as v (v.id)}
          <button type="button" aria-pressed={view === v.id} onclick={() => setParams({ view: v.id, cr: null })}>
            {v.label}{#if v.count && listState === 'ok'}<span class="count">{v.count()}</span>{/if}
          </button>
        {/each}
      </div>
    </div>
    {#if listState === 'loading'}
      <ul class="items" aria-busy="true" aria-label="Loading change requests">
        {#each [0, 1, 2] as i (i)}
          <li class="item"><span class="skeleton" style:width="30%" style:height="12px"></span><span class="skeleton" style:width="80%" style:height="16px"></span><span class="skeleton" style:width="50%" style:height="12px"></span></li>
        {/each}
      </ul>
    {:else if listState === 'error'}
      <div class="pad" role="alert">
        <p class="err"><Icon name="alert-circle" />{listError}</p>
        <button type="button" class="btn btn-secondary btn-sm" onclick={loadList}><Icon name="refresh" size={14} />Retry</button>
      </div>
    {:else if !shown.length}
      <div class="pad">
        <EmptyState
          icon={view === 'closed' ? 'history' : 'check-circle'}
          title={view === 'forme' ? 'Nothing needs your review' : view === 'open' ? 'No open change requests' : 'No closed change requests'}
          description={view === 'closed' ? 'Approved and rejected requests show up here.' : 'Edits to protected environments wait here for a second person.'}
        />
      </div>
    {:else}
      <ul class="items">
        {#each shown as c (c.id)}
          {@const s = status(c)}
          {@const sel = current?.id === c.id}
          <li>
            <a href="?{new URLSearchParams({ view, cr: c.id })}" class="item" class:sel aria-current={sel ? 'true' : undefined} onclick={(e) => select(c, e)}>
              <span class="item-top"><span class="mono subtle small">{shortId(c.id)}</span><time class="subtle small" datetime={c.createdAt} title={fullTime(c.createdAt)}>{relTime(c.createdAt)}</time></span>
              <span class="item-title">Update {c.key}</span>
              <span class="mono muted small">{c.project} / {c.env}</span>
              <span class="item-meta">
                <span class="avatar" aria-hidden="true">{initials(c.requester)}</span>
                <span class="muted small">{mine(c) ? 'You' : c.requester}</span>
                <span class="badge badge-{s.tone} push">{s.text}</span>
              </span>
              {#if c.status === 'pending' && mine(c)}
                <span class="subtle small lock"><Icon name="lock" size={12} />You can't approve your own request</span>
              {/if}
            </a>
          </li>
        {/each}
      </ul>
    {/if}
  </section>

  <section class="detail" aria-labelledby="cr-title" aria-busy={detailState === 'loading'}>
    {#if detailState === 'idle'}
      {#if listState === 'ok'}
        <div class="card card-flush pad-lg">
          <EmptyState icon="git-pull-request" title="Select a change request" description="Pick a request on the left to see what it changes." />
        </div>
      {/if}
    {:else if detailState === 'loading' && !detail}
      <div class="card card-flush pad-lg stack">
        <span class="skeleton" style:width="30%" style:height="14px"></span>
        <span class="skeleton" style:width="60%" style:height="24px"></span>
        <span class="skeleton" style:width="90%" style:height="14px"></span>
      </div>
    {:else if detailState === 'error'}
      <div class="card card-flush pad-lg" role="alert">
        <p class="err"><Icon name="alert-circle" />{detailError}</p>
        <button type="button" class="btn btn-secondary btn-sm" onclick={() => current && loadDetail(current)}><Icon name="refresh" size={14} />Retry</button>
      </div>
    {:else if detail}
      <div class="card card-flush pad-lg stack">
        <div class="d-head">
          <div class="d-tags">
            <span class="mono subtle">{shortId(detail.id)}</span>
            {#if detail.status === 'pending'}<Badge tone="info" dot={false}>Open</Badge>{:else if detail.status === 'approved'}<Badge tone="success" dot={false}>Approved</Badge>{:else}<Badge tone="danger" dot={false}>Rejected</Badge>{/if}
            <span class="badge badge-{envTone(detail.env)} mini">{detail.env}</span>
          </div>
          <h2 id="cr-title">{title}</h2>
          <p class="muted who">
            <span class="avatar" aria-hidden="true">{initials(detail.requesterDisplayName || detail.requester)}</span>
            <span>
              <strong>{isMine ? 'You' : detail.requesterDisplayName || detail.requester}</strong>{#if detail.requesterRole} ({detail.requesterRole}){/if}
              {isMine ? 'want' : 'wants'} to change {detail.changes.length} secret{detail.changes.length === 1 ? '' : 's'} in <span class="mono">{scopePath}</span> ·
              <time datetime={detail.createdAt} title={fullTime(detail.createdAt)}>{relTime(detail.createdAt)}</time>
            </span>
          </p>
        </div>
        <div class="policy">
          <span class="policy-icon"><Icon name="shield-check" size={18} /></span>
          <div class="policy-text">
            <strong>Policy: {detail.policy?.name ?? 'change requests'}</strong>
            <span class="muted small">
              Needs {required} approval{required === 1 ? '' : 's'} from {detail.policy?.approverRoles?.length ? `an ${detail.policy.approverRoles.join(' or ')}` : 'an admin'} who is not the requester. The requester can't approve their own change, even as an admin.
            </span>
          </div>
          <div class="policy-status">
            <span class="ps"><Icon name={approvals >= required ? 'check-circle' : 'circle'} size={14} /><span>Approvals: <strong>{approvals} of {required}</strong></span></span>
            {#if detail.status === 'pending'}
              {#if canDecide}
                <span class="ps ok"><Icon name="check-circle" size={14} /><span>You are eligible to approve</span></span>
              {:else}
                <span class="ps subtle"><Icon name="lock" size={14} /><span>{blockReason}</span></span>
              {/if}
            {:else if detail.decidedBy}
              <span class="ps subtle"><Icon name="user" size={14} /><span>{detail.status === 'approved' ? 'Approved' : 'Rejected'} by {detail.decidedBy === me?.username ? 'you' : detail.decidedBy}{#if detail.decidedAt} · {relTime(detail.decidedAt)}{/if}</span></span>
            {/if}
          </div>
        </div>
      </div>

      <div class="card card-flush">
        <div class="sec-head">
          <h3>Requested changes</h3>
          <span class="badge outline">{detail.changes.length} secret{detail.changes.length === 1 ? '' : 's'}</span>
        </div>
        <!-- Focusable so keyboard users can scroll the diff sideways (axe scrollable-region-focusable). -->
        <!-- svelte-ignore a11y_no_noninteractive_tabindex -->
        <div class="scroll" role="region" aria-label="Requested changes" tabindex="0">
          <table class="table diff">
            <thead><tr><th scope="col">Key</th><th scope="col">Change</th><th scope="col">Before</th><th scope="col">After</th></tr></thead>
            <tbody>
              {#each detail.changes as ch (ch.path + '/' + ch.key)}
                {@const v = values?.[ch.key]}
                <tr>
                  <td><span class="mono strong">{ch.key}</span>{#if ch.path}<span class="subtle small block mono">{ch.path}</span>{/if}</td>
                  <td>
                    <Badge tone={ch.change === 'added' ? 'success' : ch.change === 'deleted' ? 'danger' : 'warning'} dot={false}>{ch.change === 'added' ? 'Added' : ch.change === 'deleted' ? 'Deleted' : 'Modified'}</Badge>
                  </td>
                  <td>
                    <div class="cellcol">
                      {#if ch.change === 'added'}
                        <span class="subtle">—</span>
                      {:else}
                        <span class="mono del"><span aria-hidden="true">− </span><span class="sr-only">Before: </span>{v ? (v.previousValue ?? '—') : legacyDetail ? 'current value' : fingerprint(ch.previous)}</span>
                        {#if ch.previous?.version}<span class="subtle small">Current {ch.previous.version}</span>{/if}
                      {/if}
                    </div>
                  </td>
                  <td>
                    <div class="cellcol">
                      {#if ch.change === 'deleted'}
                        <span class="subtle">—</span>
                      {:else}
                        <span class="mono add"><span aria-hidden="true">+ </span><span class="sr-only">After: </span>{v ? (v.proposedValue ?? '—') : legacyDetail ? 'new value' : fingerprint(ch.proposed)}</span>
                        {#if ch.proposed?.version}<span class="subtle small">New version {ch.proposed.version}</span>{/if}
                      {/if}
                    </div>
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
        <div class="sec-foot">
          <Icon name={values ? 'eye' : 'eye-off'} size={14} />
          <span class="muted small">
            {#if legacyDetail}This server doesn't report value fingerprints yet.{:else if values}Values are visible for 30 seconds. This reveal was logged.{:else}Values are shown as fingerprints. Revealing them is logged.{/if}
          </span>
          {#if session.can('editor') && !legacyDetail}
            <button type="button" class="btn btn-secondary btn-sm push" onclick={reveal} disabled={revealing}>
              <Icon name={values ? 'eye-off' : 'eye'} size={14} />{values ? 'Hide values' : revealing ? 'Revealing…' : 'Reveal values'}
            </button>
          {/if}
        </div>
      </div>

      <div class="card card-flush pad stack">
        {#if detail.comment}
          <div class="cmt">
            <span class="avatar" aria-hidden="true">{initials(detail.requesterDisplayName || detail.requester)}</span>
            <div class="cmt-body">
              <span><strong>{detail.requesterDisplayName || detail.requester}</strong> <time class="subtle small" datetime={detail.createdAt}>{relTime(detail.createdAt)}</time></span>
              <p>{detail.comment}</p>
            </div>
          </div>
        {/if}
        {#each detail.approvals ?? [] as a (a.username + a.decidedAt)}
          {#if a.comment}
            <div class="cmt">
              <span class="avatar" aria-hidden="true">{initials(a.username)}</span>
              <div class="cmt-body"><span><strong>{a.username}</strong> <span class="subtle small">approved · {relTime(a.decidedAt)}</span></span><p>{a.comment}</p></div>
            </div>
          {/if}
        {/each}
        {#if detail.decisionComment && detail.status !== 'pending'}
          <div class="cmt">
            <span class="avatar" aria-hidden="true">{initials(detail.decidedBy ?? '?')}</span>
            <div class="cmt-body"><span><strong>{detail.decidedBy}</strong> <span class="subtle small">{detail.status} · {detail.decidedAt ? relTime(detail.decidedAt) : ''}</span></span><p>{detail.decisionComment}</p></div>
          </div>
        {/if}

        {#if detail.status === 'pending' && canDecide}
          <label class="field">
            <span class="field-label">Comment <span class="subtle normal">(required to reject)</span></span>
            <textarea bind:this={commentEl} class="textarea" rows="3" placeholder="Add context for the requester" bind:value={comment} oninput={() => (commentError = '')} aria-invalid={!!commentError} aria-describedby={commentError ? 'cmt-err' : undefined}></textarea>
            {#if commentError}<span class="field-error" id="cmt-err">{commentError}</span>{/if}
          </label>
          <div class="actions">
            <button type="button" class="btn btn-primary" onclick={approve} disabled={!!busy}><Icon name="check" />{busy === 'approve' ? 'Applying…' : 'Approve and apply'}</button>
            <button type="button" class="btn btn-danger-ghost" onclick={reject} disabled={!!busy}><Icon name="x" />{busy === 'reject' ? 'Rejecting…' : 'Reject'}</button>
            <span class="field-hint push">Approving applies the change right away{nextVersion ? ` as version ${nextVersion}` : ''}.</span>
          </div>
        {:else if detail.status === 'pending'}
          <p class="subtle small lock"><Icon name="lock" size={14} />{blockReason}. {isMine ? 'Another admin has to review it.' : ''}</p>
        {:else if !detail.decisionComment && !detail.comment}
          <p class="subtle small">No comments.</p>
        {/if}
      </div>
    {/if}
  </section>
</div>

<PoliciesModal open={policiesOpen} onclose={() => setParams({ policies: null })} />

<style>
  .layout {
    display: flex;
    flex-wrap: wrap;
    align-items: flex-start;
    gap: 20px;
  }
  .inbox {
    flex: 1 1 340px;
    max-width: 400px;
    min-width: 0;
    overflow: hidden;
  }
  .inbox-head {
    display: flex;
    flex-direction: column;
    gap: 10px;
    padding: 12px 14px;
    border-bottom: 1px solid var(--border);
  }
  .seg {
    display: inline-flex;
    flex-wrap: wrap;
    align-self: flex-start;
    gap: 2px;
    padding: 3px;
    border-radius: var(--radius-md);
    background: var(--surface-pressed);
  }
  .seg button {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    height: 28px;
    padding: 0 10px;
    border: none;
    border-radius: var(--radius-sm);
    background: transparent;
    color: var(--text-muted);
    font: inherit;
    font-size: 12.5px;
    font-weight: 500;
    cursor: pointer;
  }
  .seg button[aria-pressed='true'] {
    background: var(--surface);
    color: var(--text);
    box-shadow: var(--shadow-xs);
  }
  .count {
    padding: 0 6px;
    border-radius: 999px;
    background: var(--surface-pressed);
    color: var(--text-muted);
    font-size: var(--text-xs);
    line-height: 16px;
  }
  .seg button[aria-pressed='true'] .count {
    background: var(--surface-hover);
  }
  .items {
    margin: 0;
    padding: 0;
    list-style: none;
  }
  .item {
    display: flex;
    flex-direction: column;
    gap: 6px;
    padding: 12px 14px;
    border-bottom: 1px solid var(--border);
    color: var(--text);
  }
  li:last-child .item {
    border-bottom: none;
  }
  a.item:hover {
    background: var(--surface-hover);
    text-decoration: none;
  }
  a.item:focus-visible {
    outline: none;
    box-shadow: inset var(--focus-ring);
  }
  .item.sel,
  a.item.sel:hover {
    background: var(--accent-soft);
  }
  .item-top {
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .item-top time {
    margin-left: auto;
  }
  .item-title {
    font-weight: 600;
  }
  .item-meta {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 8px;
  }
  .push {
    margin-left: auto;
  }
  .lock {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    margin: 0;
  }
  .avatar {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    flex: none;
    width: 24px;
    height: 24px;
    border-radius: 50%;
    background: var(--accent-soft);
    color: var(--accent-text);
    font-size: 10px;
    font-weight: 600;
  }
  .badge-accent {
    background: var(--accent-soft);
    color: var(--accent-text);
  }
  .badge.outline {
    background: transparent;
    box-shadow: inset 0 0 0 1px var(--border-strong);
  }
  .mini {
    height: 20px;
    font-size: 11px;
  }
  .pad {
    padding: 16px;
  }
  .pad-lg {
    padding: 20px;
  }
  .stack {
    display: flex;
    flex-direction: column;
    gap: 14px;
  }
  .err {
    display: flex;
    align-items: center;
    gap: 6px;
    margin: 0 0 10px;
    color: var(--danger);
  }

  .detail {
    flex: 999 1 560px;
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: 16px;
  }
  .d-head {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .d-tags {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 8px;
  }
  .d-head h2 {
    margin: 0;
    font: 600 20px/28px var(--font-display);
    letter-spacing: -0.01em;
  }
  .who {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 8px;
    margin: 0;
  }
  .who strong {
    color: var(--text);
    font-weight: 600;
  }
  .policy {
    display: flex;
    flex-wrap: wrap;
    align-items: flex-start;
    gap: 12px;
    padding: 12px;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: var(--surface-hover);
  }
  .policy-icon {
    display: inline-flex;
    margin-top: 2px;
    color: var(--accent);
  }
  .policy-text {
    display: flex;
    flex: 1 1 260px;
    flex-direction: column;
    gap: 4px;
  }
  .policy-text strong {
    font-weight: 600;
  }
  .policy-status {
    display: flex;
    flex-direction: column;
    gap: 6px;
    min-width: 200px;
  }
  .ps {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 12.5px;
  }
  .ps.ok {
    color: var(--success);
  }
  .sec-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    padding: 14px 16px;
    border-bottom: 1px solid var(--border);
  }
  .sec-head h3 {
    margin: 0;
    font-size: 14px;
    font-weight: 600;
  }
  .scroll {
    overflow-x: auto;
  }
  .diff {
    min-width: 680px;
  }
  .diff td {
    white-space: nowrap;
  }
  .strong {
    font-weight: 500;
  }
  .block {
    display: block;
  }
  .cellcol {
    display: flex;
    flex-direction: column;
    gap: 2px;
    padding: 8px 0;
  }
  .del,
  .add {
    align-self: flex-start;
    max-width: 360px;
    padding: 2px 6px;
    border-radius: 4px;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .del {
    background: var(--danger-soft);
    color: var(--danger);
  }
  .add {
    background: var(--success-soft);
    color: var(--success);
  }
  .sec-foot {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 8px;
    padding: 10px 16px;
    border-top: 1px solid var(--border);
    background: var(--surface-hover);
    color: var(--text-subtle);
    border-radius: 0 0 var(--radius-lg) var(--radius-lg);
  }
  .cmt {
    display: flex;
    gap: 10px;
  }
  .cmt-body {
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .cmt-body strong {
    font-weight: 600;
  }
  .cmt-body p {
    margin: 0;
    white-space: pre-wrap;
  }
  .normal {
    font-weight: 400;
  }
  .actions {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 8px;
  }
  @media (max-width: 820px) {
    .inbox {
      max-width: none;
    }
  }
</style>
