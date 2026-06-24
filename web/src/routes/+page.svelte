<script lang="ts">
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import { base } from '$app/paths';
  import {
    api,
    ApiError,
    type Project,
    type KMSKey,
    type Certificate,
    type AuditEvent
  } from '$lib/api';

  let loading = $state(true);
  let flash = $state('');

  let projects: Project[] = $state([]);
  let keys: KMSKey[] = $state([]);
  let certificates: Certificate[] = $state([]);
  let events: AuditEvent[] = $state([]);

  function notify(msg: string) {
    flash = msg;
    setTimeout(() => (flash = ''), 4000);
  }

  async function load() {
    loading = true;
    try {
      const [p, k, c, a] = await Promise.all([
        api.projects(),
        api.kmsKeys(),
        api.certificates(),
        api.audit()
      ]);
      projects = p.projects;
      keys = k.keys;
      certificates = c.certificates;
      events = a.events;
    } catch (e) {
      if (e instanceof ApiError) notify(e.message);
      else notify('Failed to load dashboard');
    } finally {
      loading = false;
    }
  }

  onMount(load);

  // ---- derived metrics -----------------------------------------------------
  const projectCount = $derived(projects.length);
  const envCount = $derived(projects.reduce((n, p) => n + p.environments.length, 0));
  const keyCount = $derived(keys.length);
  const certCount = $derived(certificates.length);

  const enabledKeys = $derived(keys.filter((k) => k.enabled && !k.deletionDate).length);
  const disabledKeys = $derived(keys.filter((k) => !k.enabled && !k.deletionDate).length);
  const pendingKeys = $derived(keys.filter((k) => !!k.deletionDate).length);

  type Slice = { label: string; value: number; color: string };

  const keySlices = $derived<Slice[]>(
    [
      { label: 'Enabled', value: enabledKeys, color: '#2f855a' },
      { label: 'Disabled', value: disabledKeys, color: '#b7791f' },
      { label: 'Pending deletion', value: pendingKeys, color: '#c53030' }
    ].filter((s) => s.value > 0)
  );

  // Key-usage split (encrypt vs sign).
  const usageCounts = $derived(
    keys.reduce(
      (acc, k) => {
        const u = (k.keyUsage || '').toUpperCase();
        if (u.includes('SIGN')) acc.sign += 1;
        else acc.encrypt += 1;
        return acc;
      },
      { encrypt: 0, sign: 0 }
    )
  );

  // Certificate status breakdown.
  const certStatus = $derived(() => {
    const m = new Map<string, number>();
    for (const c of certificates) {
      const s = (c.status || 'UNKNOWN').toUpperCase();
      m.set(s, (m.get(s) ?? 0) + 1);
    }
    return Array.from(m.entries()).map(([label, value]) => ({ label, value }));
  });

  // Certificates expiring within 30 days.
  const expiringSoon = $derived(
    certificates.filter((c) => {
      if (!c.notAfter) return false;
      const t = Date.parse(c.notAfter);
      if (Number.isNaN(t)) return false;
      const days = (t - Date.now()) / 86_400_000;
      return days >= 0 && days <= 30;
    }).length
  );

  // Audit activity over the last 7 days (oldest → newest).
  const auditSeries = $derived(() => {
    const days: { label: string; key: string; count: number }[] = [];
    const fmt = (d: Date) =>
      d.toLocaleDateString(undefined, { weekday: 'short' });
    for (let i = 6; i >= 0; i--) {
      const d = new Date();
      d.setHours(0, 0, 0, 0);
      d.setDate(d.getDate() - i);
      days.push({ label: fmt(d), key: d.toISOString().slice(0, 10), count: 0 });
    }
    const index = new Map(days.map((d) => [d.key, d]));
    for (const e of events) {
      if (!e.createdAt) continue;
      const k = e.createdAt.slice(0, 10);
      const bucket = index.get(k);
      if (bucket) bucket.count += 1;
    }
    return days;
  });

  const auditMax = $derived(Math.max(1, ...auditSeries().map((d) => d.count)));

  const failureCount = $derived(
    events.filter((e) => (e.result || '').toLowerCase() !== 'ok').length
  );

  const recentEvents = $derived(events.slice(0, 8));

  // ---- donut geometry ------------------------------------------------------
  function donutSegments(slices: Slice[]) {
    const total = slices.reduce((n, s) => n + s.value, 0) || 1;
    const r = 54;
    const c = 2 * Math.PI * r;
    let offset = 0;
    return slices.map((s) => {
      const frac = s.value / total;
      const seg = {
        color: s.color,
        dash: frac * c,
        gap: c - frac * c,
        offset: -offset * c
      };
      offset += frac;
      return seg;
    });
  }

  const keyDonut = $derived(donutSegments(keySlices));

  function go(path: string) {
    goto(`${base}${path}`);
  }

  function relTime(iso: string): string {
    const t = Date.parse(iso);
    if (Number.isNaN(t)) return iso;
    const s = Math.round((Date.now() - t) / 1000);
    if (s < 60) return `${s}s ago`;
    if (s < 3600) return `${Math.floor(s / 60)}m ago`;
    if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
    return `${Math.floor(s / 86400)}d ago`;
  }
</script>

<div class="ph">
  <h1 class="ph-title">Dashboard</h1>
  <p class="ph-sub">An overview of secrets, keys, certificates, and recent activity across Citadel.</p>
</div>

{#if flash}
  <div class="flash err">{flash}</div>
{/if}

{#if loading}
  <div class="card"><div class="empty">Loading dashboard…</div></div>
{:else}
  <!-- KPI cards -->
  <div class="kpis">
    <button class="kpi" onclick={() => go('/secrets')}>
      <span class="kpi-icon">🔑</span>
      <span class="kpi-num">{projectCount}</span>
      <span class="kpi-label">Projects</span>
      <span class="kpi-sub">{envCount} environment{envCount === 1 ? '' : 's'}</span>
    </button>
    <button class="kpi" onclick={() => go('/kms')}>
      <span class="kpi-icon">🗝</span>
      <span class="kpi-num">{keyCount}</span>
      <span class="kpi-label">KMS keys</span>
      <span class="kpi-sub">{enabledKeys} enabled</span>
    </button>
    <button class="kpi" onclick={() => go('/certificates')}>
      <span class="kpi-icon">📜</span>
      <span class="kpi-num">{certCount}</span>
      <span class="kpi-label">Certificates</span>
      <span class="kpi-sub" class:warn={expiringSoon > 0}>{expiringSoon} expiring ≤30d</span>
    </button>
    <button class="kpi" onclick={() => go('/audit')}>
      <span class="kpi-icon">📋</span>
      <span class="kpi-num">{events.length}</span>
      <span class="kpi-label">Audit events</span>
      <span class="kpi-sub" class:warn={failureCount > 0}>{failureCount} failure{failureCount === 1 ? '' : 's'}</span>
    </button>
  </div>

  <div class="grid">
    <!-- Audit activity bar chart -->
    <div class="card chart-card">
      <div class="chart-head">
        <h3>Activity (7 days)</h3>
        <span class="muted small">{events.length} total events</span>
      </div>
      <div class="bars">
        {#each auditSeries() as d}
          <div class="bar-col">
            <div class="bar-track">
              <div
                class="bar-fill"
                style="height:{Math.round((d.count / auditMax) * 100)}%"
                title="{d.count} events"
              ></div>
            </div>
            <span class="bar-num">{d.count}</span>
            <span class="bar-label">{d.label}</span>
          </div>
        {/each}
      </div>
    </div>

    <!-- KMS key status donut -->
    <div class="card chart-card">
      <div class="chart-head">
        <h3>Key status</h3>
        <span class="muted small">{keyCount} keys</span>
      </div>
      {#if keyCount === 0}
        <div class="empty">No KMS keys yet.</div>
      {:else}
        <div class="donut-wrap">
          <svg viewBox="0 0 140 140" class="donut" aria-hidden="true">
            <circle cx="70" cy="70" r="54" class="donut-bg" />
            {#each keyDonut as seg}
              <circle
                cx="70"
                cy="70"
                r="54"
                fill="none"
                stroke={seg.color}
                stroke-width="16"
                stroke-dasharray="{seg.dash} {seg.gap}"
                stroke-dashoffset={seg.offset}
                transform="rotate(-90 70 70)"
              />
            {/each}
            <text x="70" y="66" class="donut-num">{keyCount}</text>
            <text x="70" y="84" class="donut-cap">keys</text>
          </svg>
          <ul class="legend">
            {#each keySlices as s}
              <li><span class="dot" style="background:{s.color}"></span>{s.label}<b>{s.value}</b></li>
            {/each}
          </ul>
        </div>
      {/if}
    </div>

    <!-- Key usage split -->
    <div class="card chart-card">
      <div class="chart-head">
        <h3>Key usage</h3>
        <span class="muted small">encrypt vs sign</span>
      </div>
      {#if keyCount === 0}
        <div class="empty">No KMS keys yet.</div>
      {:else}
        {@const total = usageCounts.encrypt + usageCounts.sign || 1}
        <div class="meter">
          <div class="meter-row">
            <span class="meter-label">Encrypt / decrypt</span>
            <span class="meter-val">{usageCounts.encrypt}</span>
          </div>
          <div class="meter-track">
            <div class="meter-fill enc" style="width:{(usageCounts.encrypt / total) * 100}%"></div>
          </div>
          <div class="meter-row">
            <span class="meter-label">Sign / verify</span>
            <span class="meter-val">{usageCounts.sign}</span>
          </div>
          <div class="meter-track">
            <div class="meter-fill sig" style="width:{(usageCounts.sign / total) * 100}%"></div>
          </div>
        </div>
      {/if}
    </div>

    <!-- Certificate status -->
    <div class="card chart-card">
      <div class="chart-head">
        <h3>Certificates</h3>
        <span class="muted small">{certCount} total</span>
      </div>
      {#if certCount === 0}
        <div class="empty">No certificates yet.</div>
      {:else}
        {@const cmax = Math.max(1, ...certStatus().map((s) => s.value))}
        <div class="meter">
          {#each certStatus() as s}
            <div class="meter-row">
              <span class="meter-label">{s.label}</span>
              <span class="meter-val">{s.value}</span>
            </div>
            <div class="meter-track">
              <div class="meter-fill cert" style="width:{(s.value / cmax) * 100}%"></div>
            </div>
          {/each}
        </div>
      {/if}
    </div>

    <!-- Recent activity feed -->
    <div class="card chart-card span-2">
      <div class="chart-head">
        <h3>Recent activity</h3>
        <button class="btn btn-sm" onclick={() => go('/audit')}>View all</button>
      </div>
      {#if recentEvents.length === 0}
        <div class="empty">No recent activity.</div>
      {:else}
        <table class="feed">
          <tbody>
            {#each recentEvents as e}
              <tr>
                <td><span class="badge {(e.result || '').toLowerCase() === 'ok' ? 'ok' : 'bad'}">{e.result}</span></td>
                <td class="mono small">{e.action}</td>
                <td class="muted small">{e.actor}</td>
                <td class="muted small ta-r">{relTime(e.createdAt)}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      {/if}
    </div>
  </div>
{/if}

<style>
  .kpis {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 1rem;
    margin-bottom: 1.25rem;
  }
  .kpi {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: 0.15rem;
    background: var(--c-surface);
    border: 1px solid var(--c-border);
    border-radius: var(--radius);
    padding: 1rem 1.1rem;
    cursor: pointer;
    text-align: left;
    transition: border-color 0.15s, box-shadow 0.15s;
  }
  .kpi:hover {
    border-color: var(--c-blue);
    box-shadow: 0 4px 14px rgba(15, 20, 30, 0.08);
  }
  .kpi-icon {
    font-size: 1.3rem;
  }
  .kpi-num {
    font-size: 1.9rem;
    font-weight: 700;
    line-height: 1.1;
  }
  .kpi-label {
    font-weight: 600;
    color: var(--c-text);
  }
  .kpi-sub {
    font-size: 0.8rem;
    color: var(--c-muted);
  }
  .kpi-sub.warn {
    color: #c53030;
    font-weight: 600;
  }

  .grid {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 1.25rem;
  }
  .span-2 {
    grid-column: 1 / -1;
  }
  .chart-card {
    display: flex;
    flex-direction: column;
  }
  .chart-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 1rem;
  }
  .chart-head h3 {
    margin: 0;
  }
  .small {
    font-size: 0.82rem;
  }
  .ta-r {
    text-align: right;
  }

  /* bar chart */
  .bars {
    display: flex;
    align-items: flex-end;
    gap: 0.6rem;
    height: 180px;
  }
  .bar-col {
    flex: 1;
    display: flex;
    flex-direction: column;
    align-items: center;
    height: 100%;
  }
  .bar-track {
    flex: 1;
    width: 60%;
    display: flex;
    align-items: flex-end;
  }
  .bar-fill {
    width: 100%;
    min-height: 3px;
    background: linear-gradient(180deg, #4299e1, #2b6cb0);
    border-radius: 4px 4px 0 0;
    transition: height 0.3s;
  }
  .bar-num {
    font-size: 0.75rem;
    font-weight: 600;
    margin-top: 0.3rem;
  }
  .bar-label {
    font-size: 0.72rem;
    color: var(--c-muted);
  }

  /* donut */
  .donut-wrap {
    display: flex;
    align-items: center;
    gap: 1.25rem;
  }
  .donut {
    width: 150px;
    height: 150px;
    flex: none;
  }
  .donut-bg {
    fill: none;
    stroke: var(--c-border);
    stroke-width: 16;
  }
  .donut-num {
    font-size: 1.6rem;
    font-weight: 700;
    text-anchor: middle;
    fill: var(--c-text);
  }
  .donut-cap {
    font-size: 0.7rem;
    text-anchor: middle;
    fill: var(--c-muted);
  }
  .legend {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 0.4rem;
  }
  .legend li {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.86rem;
  }
  .legend b {
    margin-left: auto;
  }
  .dot {
    width: 0.7rem;
    height: 0.7rem;
    border-radius: 50%;
    display: inline-block;
  }

  /* meters */
  .meter {
    display: flex;
    flex-direction: column;
    gap: 0.35rem;
  }
  .meter-row {
    display: flex;
    justify-content: space-between;
    font-size: 0.84rem;
  }
  .meter-val {
    font-weight: 600;
  }
  .meter-track {
    height: 8px;
    background: var(--c-border);
    border-radius: 4px;
    overflow: hidden;
    margin-bottom: 0.4rem;
  }
  .meter-fill {
    height: 100%;
    border-radius: 4px;
  }
  .meter-fill.enc {
    background: #2b6cb0;
  }
  .meter-fill.sig {
    background: #6b46c1;
  }
  .meter-fill.cert {
    background: #2f855a;
  }

  /* feed */
  table.feed {
    width: 100%;
  }
  table.feed td {
    padding: 0.4rem 0.5rem;
    border-bottom: 1px solid var(--c-border);
  }
  .badge.ok {
    background: rgba(47, 133, 90, 0.12);
    color: #2f855a;
  }
  .badge.bad {
    background: rgba(197, 48, 48, 0.12);
    color: #c53030;
  }

  @media (max-width: 900px) {
    .kpis {
      grid-template-columns: repeat(2, 1fr);
    }
    .grid {
      grid-template-columns: 1fr;
    }
  }
</style>
