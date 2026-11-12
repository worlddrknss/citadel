// Date helpers shared by the shell, Overview, Audit and Approvals. Day math
// uses the viewer's local calendar days (the old dashboard bucketed by UTC
// date, so late-evening events landed on "tomorrow" west of Greenwich).

const DAY = 86_400_000;

function startOfLocalDay(d: Date): number {
  const c = new Date(d);
  c.setHours(0, 0, 0, 0);
  return c.getTime();
}

/** Whole local calendar days from today to `iso` (negative = past). */
export function daysUntil(iso: string, now = new Date()): number {
  return Math.round((startOfLocalDay(new Date(iso)) - startOfLocalDay(now)) / DAY);
}

/** "just now", "4 min ago", "3 h ago", "Yesterday", "Nov 10", "Nov 10, 2025". */
export function relTime(iso: string, now = new Date()): string {
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return iso;
  const s = Math.round((now.getTime() - t) / 1000);
  if (s < 45) return 'just now';
  if (s < 3600) return `${Math.max(1, Math.round(s / 60))} min ago`;
  const days = -daysUntil(iso, now);
  if (days === 0) return `${Math.round(s / 3600)} h ago`;
  if (days === 1) return 'Yesterday';
  const d = new Date(t);
  return d.toLocaleDateString(undefined, {
    month: 'short',
    day: 'numeric',
    ...(d.getFullYear() !== now.getFullYear() ? { year: 'numeric' } : {})
  });
}

/** Absolute local timestamp for title tooltips. */
export function fullTime(iso: string): string {
  const t = Date.parse(iso);
  return Number.isNaN(t) ? iso : new Date(t).toLocaleString();
}

/** "Nov 12, 13:04:51" in UTC, as the audit table shows. */
export function utcStamp(iso: string): string {
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return iso;
  return new Date(t).toLocaleString('en-US', {
    timeZone: 'UTC',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false
  });
}

export function initials(s: string): string {
  return (
    s
      .replace(/^[a-z]+\//i, '')
      .split(/[\s._@-]+/)
      .filter(Boolean)
      .map((p) => p[0])
      .join('')
      .slice(0, 2)
      .toUpperCase() || '?'
  );
}
