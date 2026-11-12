// Helpers shared by the three Secrets pages: environment tiers and tones,
// ordering, labels, and the compact time and initials formats the boards use.

export type Tier = 'development' | 'staging' | 'production' | 'other';
export type Tone = 'neutral' | 'success' | 'warning' | 'danger' | 'info';

const TIER_BY_SLUG: Record<string, Tier> = {
  dev: 'development',
  develop: 'development',
  development: 'development',
  local: 'development',
  test: 'development',
  sandbox: 'development',
  stg: 'staging',
  stage: 'staging',
  staging: 'staging',
  qa: 'staging',
  uat: 'staging',
  preprod: 'staging',
  'pre-prod': 'staging',
  prod: 'production',
  prd: 'production',
  production: 'production',
  live: 'production'
};

/** The tier an environment belongs to: its policy says so, else its name. */
export function envTier(slug: string, policyTier?: string | null): Tier {
  if (policyTier === 'development' || policyTier === 'staging' || policyTier === 'production') return policyTier;
  return TIER_BY_SLUG[slug.toLowerCase()] ?? 'other';
}

export const tierTone: Record<Tier, Tone> = {
  development: 'info',
  staging: 'warning',
  production: 'danger',
  other: 'neutral'
};

const TIER_ORDER: Record<Tier, number> = { development: 0, staging: 1, production: 2, other: 3 };

/** dev → staging → prod, then everything else alphabetically. */
export function sortEnvs(envs: string[]): string[] {
  return [...envs].sort((a, b) => TIER_ORDER[envTier(a)] - TIER_ORDER[envTier(b)] || a.localeCompare(b));
}

const LABELS: Record<string, string> = {
  dev: 'Development',
  development: 'Development',
  stg: 'Staging',
  staging: 'Staging',
  prod: 'Production',
  production: 'Production'
};

/** Display name for an environment slug ("prod" → "Production"). */
export function envLabel(slug: string): string {
  return LABELS[slug.toLowerCase()] ?? slug;
}

/** "2 h ago", "3 d ago", then a short date. */
export function relTime(iso?: string | null): string {
  if (!iso) return '—';
  const t = new Date(iso);
  if (Number.isNaN(t.getTime())) return '—';
  const s = Math.round((Date.now() - t.getTime()) / 1000);
  if (s < 0) return shortDate(iso);
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  if (s < 7 * 86400) return `${Math.floor(s / 86400)} d ago`;
  return shortDate(iso);
}

export function shortDate(iso?: string | null): string {
  if (!iso) return '—';
  const t = new Date(iso);
  if (Number.isNaN(t.getTime())) return '—';
  const sameYear = t.getFullYear() === new Date().getFullYear();
  return t.toLocaleDateString(undefined, { month: 'short', day: 'numeric', ...(sameYear ? {} : { year: 'numeric' }) });
}

export function fullDate(iso?: string | null): string {
  if (!iso) return '—';
  const t = new Date(iso);
  if (Number.isNaN(t.getTime())) return '—';
  return t.toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  });
}

/** Two-letter initials for an avatar ("svc/rotation" → "SR", "Priya Nair" → "PN"). */
export function initials(name?: string | null): string {
  if (!name) return '?';
  const parts = name.split(/[\s/._@-]+/).filter(Boolean);
  if (parts.length === 0) return '?';
  if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
  return (parts[0][0] + parts[1][0]).toUpperCase();
}

/** Joins a folder path and a child name: ("/", "db") → "/db". */
export function joinPath(path: string, name: string): string {
  const base = path === '/' || !path ? '' : path.replace(/\/+$/, '');
  return `${base}/${name}`;
}

/** Normalizes a folder path from the URL to "/" or "/a/b". */
export function normPath(raw: string): string {
  const segs = raw.split('/').filter(Boolean);
  return segs.length ? '/' + segs.join('/') : '/';
}
