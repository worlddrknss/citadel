// Built-in secret rotation: client for /v1/secrets/rotation and the helpers
// the drawer's Rotation tab uses (form state <-> request, labels).
//
//   GET  /v1/secrets/rotation?project&env&path&key (viewer) → RotationStatus
//   POST /v1/secrets/rotation (editor) { project, env, path, key,
//        rotator?: { type, config?, configSecret? } | lambdaArn,
//        afterDays? | scheduleExpression?, duration?, rotateImmediately }
//        → { configured, builtin, versionId?, signingSecret? (once) }
//   POST /v1/secrets/rotation/rotate (editor) → 202 { started, versionId }
//   POST /v1/secrets/rotation/signing-secret (editor) → { signingSecret }
//   DELETE /v1/secrets/rotation?project&env&path&key (editor) → { cancelled }

import { api, req } from '#lib/api.ts';

export type RotatorType = 'random' | 'postgresql' | 'webhook';

export interface RotatorConfig {
  length?: number;
  excludeCharacters?: string;
  excludeNumbers?: boolean;
  excludePunctuation?: boolean;
  excludeUppercase?: boolean;
  excludeLowercase?: boolean;
  includeSpace?: boolean;
  requireEachIncludedType?: boolean;
  jsonKey?: string;
  strategy?: '' | 'single-user' | 'alternating-users';
  adminSecretArn?: string;
  url?: string;
}

export interface RotationEvent {
  versionId: string;
  rotator: string;
  trigger: 'schedule' | 'immediate' | 'retry';
  status: 'succeeded' | 'failed';
  step: string;
  error?: string;
  startedAt: string;
  finishedAt: string;
}

export interface RotationStatus {
  enabled: boolean;
  mode: 'builtin' | 'lambda' | 'none';
  lambdaArn?: string;
  rotator?: { type: RotatorType; config?: RotatorConfig; configSecret?: string; hasSigningSecret?: boolean };
  schedule: { afterDays?: number; expression?: string; duration?: string };
  nextRotationDate?: string;
  windowEnd?: string;
  lastRotatedDate?: string;
  status: '' | 'running' | 'succeeded' | 'retrying' | 'failed';
  lastStep?: string;
  lastError?: string;
  attempts?: number;
  nextAttemptAt?: string;
  pendingVersionId?: string;
  due: boolean;
  history: RotationEvent[];
}

export interface Coord {
  project: string;
  env: string;
  path: string;
  key: string;
}

const qs = (p: Record<string, string>) => new URLSearchParams(p).toString();

export const rotationApi = {
  status: (c: Coord) => req<RotationStatus>(`/v1/secrets/rotation?${qs({ ...c })}`),
  configure: api.configureRotation,
  rotateNow: (c: Coord) =>
    req<{ started: boolean; versionId: string }>('/v1/secrets/rotation/rotate', { method: 'POST', body: JSON.stringify(c) }),
  regenerateSigningSecret: (c: Coord) =>
    req<{ signingSecret: string }>('/v1/secrets/rotation/signing-secret', { method: 'POST', body: JSON.stringify(c) }),
  turnOff: (c: Coord) => api.cancelRotation(c.project, c.env, c.path, c.key)
};

export const ROTATOR_LABELS: Record<RotatorType, string> = {
  random: 'Random value',
  postgresql: 'PostgreSQL user',
  webhook: 'Webhook'
};

/** How the schedule is entered in the form. */
export type ScheduleKind = 'days' | 'hours' | 'cron';

/** Editable form state for the Rotation tab. */
export interface RotationForm {
  type: RotatorType;
  scheduleKind: ScheduleKind;
  days: number;
  hours: number;
  cron: string;
  /** Window length in hours; 0 is AWS's default. */
  windowHours: number;
  length: number;
  excludePunctuation: boolean;
  excludeCharacters: string;
  jsonKey: string;
  strategy: '' | 'single-user' | 'alternating-users';
  adminSecretArn: string;
  url: string;
}

export function defaultForm(): RotationForm {
  return {
    type: 'random',
    scheduleKind: 'days',
    days: 30,
    hours: 12,
    cron: 'cron(0 4 ? * MON *)',
    windowHours: 0,
    length: 32,
    excludePunctuation: false,
    excludeCharacters: '',
    jsonKey: '',
    strategy: '',
    adminSecretArn: '',
    url: ''
  };
}

/** Form state from the server's status (defaults where unset). */
export function formFromStatus(s: RotationStatus | null): RotationForm {
  const f = defaultForm();
  if (!s) return f;
  if (s.rotator) {
    f.type = s.rotator.type;
    const c = s.rotator.config ?? {};
    f.length = c.length ?? 32;
    f.excludePunctuation = !!c.excludePunctuation;
    f.excludeCharacters = c.excludeCharacters ?? '';
    f.jsonKey = c.jsonKey ?? '';
    f.strategy = c.strategy ?? '';
    f.adminSecretArn = c.adminSecretArn ?? '';
    f.url = c.url ?? '';
  }
  const expr = s.schedule.expression ?? '';
  const rate = /^rate\((\d+) (day|days|hour|hours)\)$/.exec(expr);
  if (rate) {
    if (rate[2].startsWith('hour')) {
      f.scheduleKind = 'hours';
      f.hours = Number(rate[1]);
    } else f.days = Number(rate[1]);
  } else if (expr.startsWith('cron(')) {
    f.scheduleKind = 'cron';
    f.cron = expr;
  } else if (s.schedule.afterDays) f.days = s.schedule.afterDays;
  const d = /^(\d+)h$/.exec(s.schedule.duration ?? '');
  f.windowHours = d ? Number(d[1]) : 0;
  return f;
}

/** Client-side checks mirroring the server's; '' when valid. */
export function validateForm(f: RotationForm): string {
  if (f.scheduleKind === 'days' && !(Number.isInteger(f.days) && f.days >= 1 && f.days <= 1000)) return 'Rotate every 1 to 1000 days.';
  if (f.scheduleKind === 'hours' && !(Number.isInteger(f.hours) && f.hours >= 4 && f.hours <= 23)) return 'Rotate every 4 to 23 hours.';
  if (f.scheduleKind === 'cron' && !/^cron\(\S+( \S+){5}\)$/.test(f.cron.trim())) return 'A cron expression has six fields: cron(Minutes Hours Day-of-month Month Day-of-week Year).';
  if (!(Number.isInteger(f.windowHours) && f.windowHours >= 0 && f.windowHours <= 24)) return 'The window is 1 to 24 hours.';
  if (f.scheduleKind === 'hours' && f.windowHours > f.hours) return 'The window must not run into the next one.';
  if (f.type !== 'webhook' && !(Number.isInteger(f.length) && f.length >= 8 && f.length <= 4096)) return 'Passwords are 8 to 4096 characters.';
  if (f.type === 'webhook' && !/^https:\/\/[^\s/]+/i.test(f.url.trim())) return 'The webhook URL must start with https://.';
  if (f.type === 'postgresql' && f.strategy === 'alternating-users' && !f.adminSecretArn.trim())
    return 'Alternating users needs the admin secret ARN (or a masterarn field in the secret).';
  return '';
}

/** The POST /v1/secrets/rotation body for the form. */
export function requestFromForm(c: Coord, f: RotationForm, rotateImmediately: boolean) {
  const config: RotatorConfig = {};
  if (f.type === 'webhook') {
    config.url = f.url.trim();
  } else {
    if (f.length !== 32) config.length = f.length;
    if (f.excludePunctuation) config.excludePunctuation = true;
    if (f.excludeCharacters) config.excludeCharacters = f.excludeCharacters;
  }
  if (f.type === 'random' && f.jsonKey.trim()) config.jsonKey = f.jsonKey.trim();
  if (f.type === 'postgresql') {
    if (f.strategy) config.strategy = f.strategy;
    if (f.adminSecretArn.trim()) config.adminSecretArn = f.adminSecretArn.trim();
  }
  const body: Parameters<typeof api.configureRotation>[0] = {
    ...c,
    rotator: { type: f.type, config: config as Record<string, unknown> },
    rotateImmediately
  };
  if (f.scheduleKind === 'days') body.afterDays = f.days;
  else if (f.scheduleKind === 'hours') body.scheduleExpression = `rate(${f.hours} hours)`;
  else body.scheduleExpression = f.cron.trim();
  if (f.windowHours > 0) body.duration = `${f.windowHours}h`;
  return body;
}

/** "Every 30 days", "Every 6 hours", "cron(0 4 ? * MON *)" (+ window). */
export function scheduleLabel(s: RotationStatus['schedule']): string {
  let out = '';
  const expr = s.expression ?? '';
  const rate = /^rate\((\d+) (day|days|hour|hours)\)$/.exec(expr);
  if (rate) out = `Every ${rate[1]} ${rate[2].replace(/s$/, '')}${rate[1] === '1' ? '' : 's'}`;
  else if (expr) out = expr;
  else if (s.afterDays) out = `Every ${s.afterDays} day${s.afterDays === 1 ? '' : 's'}`;
  if (s.duration) out += ` · ${s.duration} window`;
  return out;
}

/** Badge tone and text for a rotation state. */
export function statusBadge(s: Pick<RotationStatus, 'status' | 'enabled' | 'mode' | 'due'>): { tone: 'success' | 'warning' | 'danger' | 'info' | 'neutral'; text: string } {
  if (!s.enabled) return { tone: 'neutral', text: 'Off' };
  if (s.mode === 'lambda') return { tone: s.due ? 'warning' : 'neutral', text: s.due ? 'Due · schedule only' : 'Schedule only' };
  switch (s.status) {
    case 'running':
      return { tone: 'info', text: 'Rotating' };
    case 'retrying':
      return { tone: 'danger', text: 'Retrying' };
    case 'failed':
      return { tone: 'danger', text: 'Failed' };
  }
  if (s.due) return { tone: 'warning', text: 'Due' };
  return { tone: 'success', text: 'On' };
}

export const STEP_LABELS: Record<string, string> = {
  configuration: 'Configuration',
  createSecret: 'Create',
  setSecret: 'Set',
  testSecret: 'Test',
  finishSecret: 'Finish'
};
