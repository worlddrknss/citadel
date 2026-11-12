<script lang="ts">
  import { onMount } from 'svelte';
  import { base } from '$app/paths';
  import { api, errorMessage, type Certificate, type ChangeRequest, type KMSKey, type Project } from '$lib/api';
  import { session } from '$lib/stores/session.svelte';
  import Icon, { type IconName } from '$lib/components/Icon.svelte';
  import PageHeader from '$lib/components/PageHeader.svelte';
  import Menu from './Menu.svelte';
  import { shellApi } from './api';
  import { isNotImplemented } from './http';
  import { auditApi, resultKind, type AuditRow, type ChainStatus } from './audit/api';
  import { approvalsApi } from './approvals/api';
  import { daysUntil, fullTime, relTime } from './time';

  // Each card loads on its own: one failing source shows an error in that
  // card instead of blanking the page (the old Promise.all did).
  type Load<T> = { state: 'loading' } | { state: 'ok'; data: T } | { state: 'error'; error: string };
  const loading = { state: 'loading' } as const;

  let keys = $state<Load<KMSKey[]>>(loading);
  let projects = $state<Load<Project[]>>(loading);
  let secrets = $state<Load<{ total: number; partial: boolean }>>(loading);
  let certs = $state<Load<Certificate[]>>(loading);
  let crs = $state<Load<ChangeRequest[]>>(loading);
  let events = $state<Load<AuditRow[]>>(loading);
  let chain = $state<ChainStatus | null>(null);
  let orgName = $state('');
  let accountName = $state('');
  let setup = $state<{ users: number | null; oidc: number | null; prodPolicy: boolean | null }>({ users: null, oidc: null, prodPolicy: null });

  const me = $derived(session.me);
  const isAdmin = $derived(session.can('admin'));

  async function run<T>(fn: () => Promise<T>, set: (v: Load<T>) => void) {
    set(loading);
    try {
      set({ state: 'ok', data: await fn() });
    } catch (e) {
      set({ state: 'error', error: errorMessage(e, "Couldn't load") });
    }
  }

  async function countSecrets(ps: Project[]): Promise<{ total: number; partial: boolean }> {
    try {
      const s = await shellApi.secretsSummary();
      return { total: s.total, partial: false };
    } catch (e) {
      if (!isNotImplemented(e)) throw e;
    }
    // Older servers: count top-level items per environment (bounded).
    const envs = ps.flatMap((p) => p.environments.map((env) => [p.slug, env] as const)).slice(0, 24);
    const lists = await Promise.allSettled(envs.map(([p, env]) => api.list(p, env, '')));
    let total = 0;
    let partial = envs.length < ps.reduce((n, p) => n + p.environments.length, 0);
    for (const l of lists) {
      if (l.status === 'fulfilled') {
        total += l.value.items.length;
        if (l.value.folders.length) partial = true;
      } else partial = true;
    }
    return { total, partial };
  }

  const loadKeys = () => run(async () => (await api.kmsKeys()).keys, (v) => (keys = v));
  const loadCerts = () => run(async () => (await api.certificates()).certificates, (v) => (certs = v));
  const loadCrs = () => run(async () => (await api.changeRequests()).changeRequests, (v) => (crs = v));
  const loadEvents = () => run(async () => (await auditApi.list({}, 50, 0)).events, (v) => (events = v));
  async function loadProjects() {
    await run(async () => (await api.projects()).projects, (v) => (projects = v));
    const p = projects as Load<Project[]>;
    if (p.state === 'ok') {
      const ps = p.data;
      await run(() => countSecrets(ps), (v) => (secrets = v));
    } else if (p.state === 'error') secrets = { state: 'error', error: p.error };
  }

  async function loadSetup() {
    const [u, o, p, org] = await Promise.allSettled([
      api.users(),
      api.oidcProviders(),
      approvalsApi.policies(),
      shellApi.organization()
    ]);
    setup = {
      users: u.status === 'fulfilled' ? u.value.users.length : null,
      oidc: o.status === 'fulfilled' ? o.value.providers.length : null,
      prodPolicy: p.status === 'fulfilled' ? p.value.policies.some((x) => /^prod/i.test(x.env) && x.approvalsRequired > 0) : null
    };
    if (org.status === 'fulfilled') {
      orgName = org.value.organization.name;
      accountName = org.value.accounts.find((a) => a.accountId === me?.accountId)?.name ?? '';
    }
  }

  onMount(() => {
    void loadKeys();
    void loadProjects();
    void loadCerts();
    void loadCrs();
    void loadEvents();
    auditApi.chainStatus().then((c) => (chain = c), () => (chain = null));
    if (isAdmin) void loadSetup();
    else shellApi.organization().then((o) => {
      orgName = o.organization.name;
      accountName = o.accounts.find((a) => a.accountId === me?.accountId)?.name ?? '';
    }, () => {});
  });

  // ---- header -------------------------------------------------------------
  const greeting = $derived.by(() => {
    const h = new Date().getHours();
    const part = h < 12 ? 'morning' : h < 18 ? 'afternoon' : 'evening';
    const first = (me?.displayName || me?.username || '').split(/\s+/)[0];
    return `Good ${part}${first ? `, ${first}` : ''}. Here is what changed in ${accountName || me?.accountId || 'your account'} since yesterday.`;
  });

  // ---- stats --------------------------------------------------------------
  const keyStats = $derived.by(() => {
    if (keys.state !== 'ok') return null;
    const k = keys.data;
    return {
      total: k.length,
      enabled: k.filter((x) => x.enabled && !x.deletionDate).length,
      disabled: k.filter((x) => !x.enabled && !x.deletionDate).length,
      pending: k.filter((x) => !!x.deletionDate).length
    };
  });
  const envCount = $derived(projects.state === 'ok' ? projects.data.reduce((n, p) => n + p.environments.length, 0) : 0);

  const live = (c: Certificate) => !!c.notAfter && !/revoked/i.test(c.status);
  const expiringSoon = $derived(
    certs.state === 'ok'
      ? certs.data
          .filter((c) => live(c) && daysUntil(c.notAfter!) >= 0 && daysUntil(c.notAfter!) <= 30)
          .sort((a, b) => Date.parse(a.notAfter!) - Date.parse(b.notAfter!))
      : []
  );
  const pendingCrs = $derived(crs.state === 'ok' ? crs.data.filter((c) => c.status === 'pending') : []);
  const waitingOnMe = $derived(isAdmin ? pendingCrs.filter((c) => c.requester !== me?.username).length : 0);

  // ---- checklist ----------------------------------------------------------
  const dismissKey = $derived(`citadel-setup-dismissed:${me?.accountId ?? ''}`);
  let dismissed = $state(false);
  $effect(() => {
    try {
      dismissed = localStorage.getItem(dismissKey) === '1';
    } catch {
      dismissed = false;
    }
  });
  function dismiss() {
    dismissed = true;
    try {
      localStorage.setItem(dismissKey, '1');
    } catch {
      /* ignore */
    }
  }

  const steps = $derived([
    { done: true, title: 'Create your organization', detail: `${orgName || 'Your organization'} · account ${me?.accountId ?? ''}`, href: '/admin' },
    {
      done: keyStats ? keyStats.total > 0 : false,
      title: 'Create a KMS key',
      detail: keys.state === 'ok' && keys.data.length ? (keys.data[0].aliases[0] ?? keys.data[0].keyId) : 'Secrets are encrypted under a key you control',
      href: '/kms'
    },
    {
      done: secrets.state === 'ok' && secrets.data.total > 0,
      title: 'Add your first secret',
      detail: projects.state === 'ok' && projects.data.length ? `${projects.data.length} project${projects.data.length === 1 ? '' : 's'} so far` : 'Create a project and an environment, then a secret',
      href: '/secrets'
    },
    { done: (setup.users ?? 0) > 1, title: 'Invite a teammate', detail: 'Give editors and viewers their own sign-in', href: '/admin' },
    { done: (setup.oidc ?? 0) > 0, title: 'Connect an OIDC provider', detail: 'Let CI exchange tokens for short-lived credentials', href: '/iam' },
    { done: setup.prodPolicy === true, title: 'Require approvals for production', detail: 'Changes to prod secrets need a second person', href: '/approvals?policies=1' }
  ]);
  const doneCount = $derived(steps.filter((s) => s.done).length);
  const setupReady = $derived(keys.state !== 'loading' && secrets.state !== 'loading' && setup.users !== null);
  const showChecklist = $derived(isAdmin && !dismissed && setupReady && doneCount < steps.length);

  // ---- activity -----------------------------------------------------------
  let envFilter = $state('');
  const envOptions = $derived(projects.state === 'ok' ? [...new Set(projects.data.flatMap((p) => p.environments))].sort() : []);
  const recent = $derived.by(() => {
    if (events.state !== 'ok') return [];
    const re = envFilter ? new RegExp(`(^|[/:])${envFilter.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}([/:]|$)`, 'i') : null;
    return events.data.filter((e) => !re || re.test(e.resource ?? e.keyId ?? '')).slice(0, 6);
  });

  function describe(e: AuditRow): { verb: string; icon: IconName; danger: boolean } {
    const op = e.action.split(/[.:]/).pop() ?? e.action;
    const words = op.replace(/([a-z])([A-Z])/g, '$1 $2').toLowerCase();
    const kind = resultKind(e);
    let icon: IconName = 'activity';
    if (/reveal|getsecret|decrypt|value/i.test(op)) icon = 'eye';
    else if (/rotat|rekey/i.test(op)) icon = 'rotate';
    else if (/delete|remove|revoke/i.test(op)) icon = 'trash';
    else if (/cert|letsencrypt|\bca\b/i.test(op)) icon = 'award';
    else if (/parameter/i.test(op)) icon = 'sliders';
    else if (/changerequest/i.test(op)) icon = 'git-pull-request';
    else if (/key|alias|grant/i.test(op)) icon = 'key';
    else if (/user|account|login|assume/i.test(op)) icon = 'user';
    if (kind === 'denied') return { verb: `was denied · ${words}`, icon: 'x', danger: true };
    if (kind === 'error') return { verb: `failed · ${words}`, icon: 'alert-triangle', danger: true };
    return { verb: words, icon, danger: false };
  }

  // ---- expiry timeline ----------------------------------------------------
  const timeline = $derived(
    certs.state === 'ok'
      ? certs.data
          .filter((c) => live(c) && daysUntil(c.notAfter!) <= 90)
          .sort((a, b) => Date.parse(a.notAfter!) - Date.parse(b.notAfter!))
          .slice(0, 6)
          .map((c) => {
            const days = daysUntil(c.notAfter!);
            const tone = days <= 14 ? 'danger' : days <= 30 ? 'warning' : 'neutral';
            const pct = (Math.min(Math.max(days, 0), 90) / 90) * 100;
            const label = days < 0 ? `Expired ${-days} d ago` : days === 0 ? 'Today' : `${days} day${days === 1 ? '' : 's'}`;
            return { c, days, tone, pct, label };
          })
      : []
  );
  function issuer(c: Certificate) {
    if (c.source === 'lets-encrypt') return "Let's Encrypt";
    if (c.source === 'pca-ca') return `${c.caType ? c.caType.toLowerCase() + ' ' : ''}certificate authority`;
    return c.issuerCaId ? `Private CA ${c.issuerCaId.slice(0, 8)}` : 'Private CA';
  }
</script>

<PageHeader title="Overview" description={greeting}>
  {#snippet actions()}
    {#if isAdmin}<a class="btn btn-secondary" href="{base}/admin?invite=1"><Icon name="user" />Invite member</a>{/if}
    {#if session.can('editor')}<a class="btn btn-primary" href="{base}/secrets?new=1"><Icon name="plus" />New secret</a>{/if}
  {/snippet}
</PageHeader>

{#if showChecklist}
  <section class="card card-flush checklist" aria-labelledby="gs-title">
    <div class="cl-head">
      <div class="cl-text">
        <h2 id="gs-title">Finish setting up {orgName || 'Citadel'}</h2>
        <p class="muted">{doneCount} of {steps.length} steps done. Each step links to the screen where you do it.</p>
      </div>
      <div class="cl-progress">
        <div class="bar" role="progressbar" aria-label="Setup progress" aria-valuemin="0" aria-valuemax={steps.length} aria-valuenow={doneCount}>
          <div style:width="{(doneCount / steps.length) * 100}%"></div>
        </div>
        <span class="mono subtle small">{doneCount}/{steps.length}</span>
        <button type="button" class="btn btn-ghost btn-sm btn-icon" aria-label="Dismiss setup checklist" onclick={dismiss}><Icon name="x" size={14} /></button>
      </div>
    </div>
    <ul class="cl-list">
      {#each steps as s (s.title)}
        <li>
          {#if s.done}
            <span class="mark done" aria-hidden="true"><Icon name="check" size={12} /></span>
          {:else}
            <span class="mark" aria-hidden="true"></span>
          {/if}
          <div class="cl-item">
            <span class="cl-title" class:struck={s.done}>{s.title}<span class="sr-only">{s.done ? ' (done)' : ' (to do)'}</span></span>
            <span class="subtle small">{s.detail}</span>
          </div>
          {#if s.done}
            <span class="subtle small">Done</span>
          {:else}
            <a class="btn btn-secondary btn-sm" href="{base}{s.href}" aria-label="Start: {s.title}">Start<Icon name="chevron-right" size={14} /></a>
          {/if}
        </li>
      {/each}
    </ul>
  </section>
{/if}

<div class="stats">
  {#snippet stat(href: string, icon: IconName, label: string, value: string, detail: string, badge: { text: string; tone: string } | null)}
    <a {href} class="card card-flush stat">
      <span class="stat-top"><span class="stat-label"><Icon name={icon} />{label}</span>{#if badge}<span class="badge badge-{badge.tone}">{badge.text}</span>{/if}</span>
      <span class="stat-value num">{value}</span>
      <span class="muted stat-detail">{detail}</span>
    </a>
  {/snippet}
  {#snippet statState(icon: IconName, label: string, state: Load<unknown>, retry: () => void)}
    <div class="card card-flush stat" aria-busy={state.state === 'loading'}>
      <span class="stat-top"><span class="stat-label"><Icon name={icon} />{label}</span></span>
      {#if state.state === 'error'}
        <span class="stat-err" role="alert"><Icon name="alert-circle" size={14} />{state.error}</span>
        <button type="button" class="btn btn-secondary btn-sm retry" onclick={retry}><Icon name="refresh" size={14} />Retry</button>
      {:else}
        <span class="skeleton" style:width="56px" style:height="36px"></span>
        <span class="skeleton" style:width="80%" style:height="14px"></span>
      {/if}
    </div>
  {/snippet}

  {#if keys.state === 'ok' && keyStats}
    {@render stat(`${base}/kms`, 'key', 'KMS keys', String(keyStats.total), `${keyStats.enabled} enabled · ${keyStats.disabled} disabled · ${keyStats.pending} pending deletion`, null)}
  {:else}
    {@render statState('key', 'KMS keys', keys, loadKeys)}
  {/if}

  {#if secrets.state === 'ok' && projects.state === 'ok'}
    {@render stat(`${base}/secrets`, 'lock', 'Secrets', `${secrets.data.total}${secrets.data.partial ? '+' : ''}`, `${projects.data.length} project${projects.data.length === 1 ? '' : 's'} · ${envCount} environment${envCount === 1 ? '' : 's'}${secrets.data.partial ? ' · top-level count' : ''}`, null)}
  {:else}
    {@render statState('lock', 'Secrets', secrets.state === 'error' ? secrets : projects, loadProjects)}
  {/if}

  {#if certs.state === 'ok'}
    {@const next = expiringSoon[0]}
    {@render stat(
      `${base}/certificates`,
      'award',
      'Certificates expiring',
      String(expiringSoon.length),
      next ? `Within 30 days. Next: ${next.subject || next.id} in ${daysUntil(next.notAfter!)} day${daysUntil(next.notAfter!) === 1 ? '' : 's'}` : 'Nothing expires in the next 30 days.',
      expiringSoon.length ? { text: 'Action needed', tone: 'warning' } : null
    )}
  {:else}
    {@render statState('award', 'Certificates expiring', certs, loadCerts)}
  {/if}

  {#if crs.state === 'ok'}
    {@render stat(
      `${base}/approvals`,
      'git-pull-request',
      'Pending approvals',
      String(pendingCrs.length),
      isAdmin ? (waitingOnMe ? `${waitingOnMe} ${waitingOnMe === 1 ? 'is' : 'are'} waiting on you` : 'None waiting on you') : 'Admins review change requests',
      waitingOnMe ? { text: 'Your review', tone: 'accent' } : null
    )}
  {:else}
    {@render statState('git-pull-request', 'Pending approvals', crs, loadCrs)}
  {/if}
</div>

<div class="split">
  <section class="card card-flush activity" aria-labelledby="act-title">
    <div class="sec-head">
      <h2 id="act-title">Recent activity</h2>
      <Menu label="Filter activity by environment" labelTrigger={false} triggerClass="btn btn-ghost btn-sm" align="end" width={220}>
        {#snippet trigger()}<span class="sr-only">Filter activity by environment: </span>{envFilter || 'All environments'}<Icon name="chevron-down" size={14} />{/snippet}
        {#snippet children(close)}
          <button type="button" role="menuitemradio" aria-checked={!envFilter} onclick={() => { envFilter = ''; close(); }}>All environments{#if !envFilter}<Icon name="check" />{/if}</button>
          {#each envOptions as env (env)}
            <button type="button" role="menuitemradio" aria-checked={envFilter === env} onclick={() => { envFilter = env; close(); }}><span class="grow">{env}</span>{#if envFilter === env}<Icon name="check" />{/if}</button>
          {/each}
        {/snippet}
      </Menu>
    </div>
    {#if events.state === 'loading'}
      <ul class="feed" aria-busy="true" aria-label="Loading activity">
        {#each [0, 1, 2, 3] as i (i)}
          <li><span class="skeleton" style:width="28px" style:height="28px"></span><div class="feed-body"><span class="skeleton" style:width="60%" style:height="14px"></span><span class="skeleton" style:width="80%" style:height="12px"></span></div></li>
        {/each}
      </ul>
    {:else if events.state === 'error'}
      <div class="sec-state" role="alert">
        <Icon name="alert-circle" />
        <span>{events.error}</span>
        <button type="button" class="btn btn-secondary btn-sm" onclick={loadEvents}><Icon name="refresh" size={14} />Retry</button>
      </div>
    {:else if !recent.length}
      <div class="sec-state"><span class="muted">{envFilter ? `No recent activity in ${envFilter}.` : 'No activity yet. Actions in the console and API calls show up here.'}</span></div>
    {:else}
      <ul class="feed">
        {#each recent as e (e.id)}
          {@const d = describe(e)}
          <li>
            <span class="feed-icon" class:danger={d.danger}><Icon name={d.icon} size={14} /></span>
            <div class="feed-body">
              <p><strong>{e.actorDisplayName || e.actor || 'unknown'}</strong> <span class="muted">{d.verb}</span></p>
              <span class="mono feed-res">{e.resource || e.keyId || e.action}</span>
            </div>
            <time class="subtle small" datetime={e.createdAt} title={fullTime(e.createdAt)}>{relTime(e.createdAt)}</time>
          </li>
        {/each}
      </ul>
    {/if}
    <div class="sec-foot">
      {#if chain?.status === 'verified'}
        <span class="ok"><Icon name="shield-check" size={14} /></span>
        <span>Audit chain verified through event <span class="mono">#{(chain.verifiedThrough ?? 0).toLocaleString()}</span></span>
      {:else if chain?.status === 'broken'}
        <span class="danger"><Icon name="alert-triangle" size={14} /></span>
        <span class="danger">Audit chain broken at event <span class="mono">#{(chain.brokenAt ?? 0).toLocaleString()}</span></span>
      {:else}
        <span class="subtle"><Icon name="link" size={14} /></span>
        <span class="muted">Every audit event is hash-chained to the one before it.</span>
      {/if}
      <a href="{base}/audit" class="foot-link">Open audit log</a>
    </div>
  </section>

  <section class="card card-flush" aria-labelledby="exp-title">
    <div class="sec-head">
      <h2 id="exp-title">Expiring in the next 90 days</h2>
      <a href="{base}/certificates" class="foot-link">All certificates</a>
    </div>
    <div class="tl-row tl-head">
      <span class="label">Certificate</span>
      <div class="label tl-scale" aria-hidden="true"><span>Today</span><span>30 d</span><span>60 d</span><span>90 d</span></div>
    </div>
    {#if certs.state === 'loading'}
      <ul class="tl" aria-busy="true" aria-label="Loading certificates">
        {#each [0, 1, 2] as i (i)}<li class="tl-row"><span class="skeleton" style:width="70%" style:height="14px"></span><span class="skeleton" style:width="100%" style:height="6px"></span></li>{/each}
      </ul>
    {:else if certs.state === 'error'}
      <div class="sec-state" role="alert">
        <Icon name="alert-circle" /><span>{certs.error}</span>
        <button type="button" class="btn btn-secondary btn-sm" onclick={loadCerts}><Icon name="refresh" size={14} />Retry</button>
      </div>
    {:else if !timeline.length}
      <div class="sec-state"><span class="muted">No certificates expire in the next 90 days.</span></div>
    {:else}
      <ul class="tl">
        {#each timeline as t (t.c.source + t.c.id)}
          <li class="tl-row">
            <a class="tl-name" href="{base}/certificates?cert={encodeURIComponent(t.c.id)}&source={encodeURIComponent(t.c.source)}">
              <span class="mono ell">{t.c.subject || t.c.id}</span>
              <span class="subtle small">{issuer(t.c)}</span>
            </a>
            <div class="track tone-{t.tone}" role="img" aria-label="{t.c.subject || t.c.id}: {t.days < 0 ? t.label : `expires in ${t.label}`}" title={fullTime(t.c.notAfter!)}>
              <div class="rail"></div>
              <div class="fill" style:width="{t.pct}%"></div>
              <div class="knob" style:left="calc({t.pct}% - 5px)"></div>
              <span class="tl-label" style:left="calc({Math.min(t.pct, 72)}% + 10px)">{t.label}</span>
            </div>
          </li>
        {/each}
      </ul>
    {/if}
  </section>
</div>

<style>
  .label {
    font-size: var(--text-xs);
    font-weight: 600;
    line-height: 16px;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    color: var(--text-subtle);
  }
  .badge-accent {
    background: var(--accent-soft);
    color: var(--accent-text);
  }
  .danger {
    color: var(--danger);
  }
  .ok {
    color: var(--success);
  }
  .grow {
    flex: 1;
  }

  /* checklist */
  .checklist {
    overflow: hidden;
  }
  .cl-head {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 16px;
    padding: 16px;
  }
  .cl-text {
    display: flex;
    flex: 1 1 240px;
    flex-direction: column;
    gap: 4px;
  }
  .cl-text h2 {
    margin: 0;
    font: 600 15px/20px var(--font-sans);
    letter-spacing: 0;
  }
  .cl-text p {
    margin: 0;
    font-size: 12.5px;
  }
  .cl-progress {
    display: flex;
    align-items: center;
    gap: 12px;
  }
  .bar {
    width: 160px;
    height: 6px;
    border-radius: 999px;
    background: var(--surface-pressed);
    overflow: hidden;
  }
  .bar div {
    height: 100%;
    background: var(--accent);
  }
  .cl-list {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(min(420px, 100%), 1fr));
    margin: 0;
    padding: 0;
    list-style: none;
  }
  .cl-list li {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 10px 16px;
    border-top: 1px solid var(--border);
  }
  .mark {
    flex: none;
    width: 20px;
    height: 20px;
    border: 1.5px dashed var(--border-strong);
    border-radius: 50%;
  }
  .mark.done {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    border: none;
    background: var(--accent);
    color: var(--accent-contrast);
  }
  .cl-item {
    display: flex;
    flex: 1 1 auto;
    flex-direction: column;
    min-width: 0;
  }
  .cl-title {
    font-weight: 500;
  }
  .struck {
    color: var(--text-muted);
    text-decoration: line-through;
    text-decoration-color: var(--border-strong);
  }

  /* stats */
  .stats {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(min(230px, 100%), 1fr));
    gap: 16px;
  }
  .stat {
    display: flex;
    flex-direction: column;
    gap: 14px;
    padding: 16px;
    color: var(--text);
    box-shadow: var(--shadow-xs);
  }
  a.stat:hover {
    text-decoration: none;
    border-color: var(--border-strong);
    box-shadow: var(--shadow-sm);
  }
  a.stat:focus-visible {
    outline: none;
    box-shadow: var(--focus-ring);
  }
  .stat-top {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
  }
  .stat-label {
    display: flex;
    align-items: center;
    gap: 8px;
    color: var(--text-muted);
    font-weight: 500;
  }
  .stat-value {
    font: 600 30px/36px var(--font-display);
    letter-spacing: -0.02em;
  }
  .stat-detail {
    font-size: 12.5px;
    line-height: 18px;
  }
  .stat-err {
    display: flex;
    align-items: center;
    gap: 6px;
    color: var(--danger);
    font-size: 12.5px;
  }
  .retry {
    align-self: flex-start;
  }

  /* cards with lists */
  .split {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(min(460px, 100%), 1fr));
    gap: 16px;
    align-items: start;
  }
  .card {
    overflow: hidden;
  }
  .activity {
    display: flex;
    flex-direction: column;
    /* lets the environment menu escape the card */
    overflow: visible;
  }
  .sec-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    padding: 14px 16px;
  }
  .sec-head h2 {
    margin: 0;
    font: 600 14px/20px var(--font-sans);
    letter-spacing: 0;
  }
  .sec-state {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 8px;
    padding: 20px 16px;
    border-top: 1px solid var(--border);
  }
  .sec-state[role='alert'] {
    color: var(--danger);
  }
  .feed {
    margin: 0;
    padding: 0;
    list-style: none;
  }
  .feed li {
    display: flex;
    gap: 12px;
    padding: 12px 16px;
    border-top: 1px solid var(--border);
  }
  .feed-icon {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    flex: none;
    width: 28px;
    height: 28px;
    border: 1px solid var(--border);
    border-radius: 8px;
    background: var(--surface-hover);
    color: var(--text-muted);
  }
  .feed-icon.danger {
    color: var(--danger);
  }
  .feed-body {
    display: flex;
    flex: 1 1 auto;
    flex-direction: column;
    gap: 2px;
    min-width: 0;
  }
  .feed-body p {
    margin: 0;
    line-height: 18px;
  }
  .feed-body strong {
    font-weight: 600;
  }
  .feed-res,
  .ell {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .feed-res {
    color: var(--text-muted);
  }
  .feed time {
    white-space: nowrap;
  }
  .sec-foot {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 8px;
    margin-top: auto;
    padding: 12px 16px;
    border-top: 1px solid var(--border);
    background: var(--surface-hover);
    border-radius: 0 0 var(--radius-lg) var(--radius-lg);
    font-size: 12.5px;
  }
  .sec-foot > span:first-child {
    display: inline-flex;
  }
  .foot-link {
    margin-left: auto;
    font-size: 12.5px;
    font-weight: 500;
  }

  /* timeline */
  .tl {
    margin: 0;
    padding: 0;
    list-style: none;
  }
  .tl-row {
    display: grid;
    grid-template-columns: minmax(0, 1.1fr) minmax(0, 1.4fr);
    gap: 16px;
    align-items: center;
    padding: 10px 16px;
    border-top: 1px solid var(--border);
  }
  .tl-head {
    padding: 8px 16px;
    background: var(--surface-hover);
  }
  .tl-scale {
    display: flex;
    justify-content: space-between;
  }
  .tl-name {
    display: flex;
    flex-direction: column;
    min-width: 0;
    color: var(--text);
  }
  .tl-name:hover .mono {
    text-decoration: underline;
  }
  .tl-name:hover {
    text-decoration: none;
  }
  .track {
    position: relative;
    height: 24px;
    --tone: var(--text-subtle);
  }
  .tone-danger {
    --tone: var(--danger);
  }
  .tone-warning {
    --tone: var(--warning);
  }
  .rail,
  .fill {
    position: absolute;
    top: 11px;
    height: 2px;
    border-radius: 2px;
  }
  .rail {
    left: 0;
    right: 0;
    background: var(--surface-pressed);
  }
  .fill {
    left: 0;
    background: var(--tone);
  }
  .knob {
    position: absolute;
    top: 7px;
    width: 10px;
    height: 10px;
    border: 2px solid var(--tone);
    border-radius: 50%;
    background: var(--surface);
  }
  .tl-label {
    position: absolute;
    top: 2px;
    color: var(--tone);
    font-size: var(--text-sm);
    font-weight: 500;
    line-height: 20px;
    white-space: nowrap;
  }
</style>
