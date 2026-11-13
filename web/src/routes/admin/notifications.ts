// Notification channels (Administration → Notifications): signed webhooks,
// Slack incoming webhooks and email, the events they subscribe to, and their
// delivery log. API: /v1/notifications/* (account admins).

import { req } from '#lib/api.ts';

export type ChannelType = 'webhook' | 'slack' | 'email';
export type DeliveryStatus = 'pending' | 'delivered' | 'dead';

export interface NotificationEventType {
  type: string;
  title: string;
  description: string;
  severity: 'info' | 'warning' | 'critical';
}

export interface NotificationChannel {
  id: string;
  name: string;
  type: ChannelType;
  enabled: boolean;
  events: string[];
  /** Webhook URL (webhook channels). */
  url?: string;
  /** Slack URL without its secret part (slack channels). */
  urlHint?: string;
  /** Email channels. */
  recipients?: string[];
  hasSigningSecret: boolean;
  createdAt: string;
  createdBy: string;
  updatedAt: string;
  updatedBy: string;
}

export interface ChannelList {
  channels: NotificationChannel[];
  events: NotificationEventType[];
  emailAvailable: boolean;
}

export interface SavedChannel {
  channel: NotificationChannel;
  /** A webhook's signing secret: returned once, on create and rotate. */
  signingSecret?: string;
}

export interface ChannelInput {
  name: string;
  type: ChannelType;
  enabled: boolean;
  events: string[];
  url?: string;
  recipients?: string[];
}

export interface NotificationDelivery {
  id: number;
  channelId: string;
  eventId: string;
  eventType: string;
  status: DeliveryStatus;
  attempts: number;
  lastError?: string;
  statusCode?: number;
  createdAt: string;
  nextAttemptAt?: string;
  lastAttemptAt?: string;
  deliveredAt?: string;
  data: Record<string, unknown>;
}

const json = (body: unknown) => ({ method: 'POST', body: JSON.stringify(body) });

export const notificationsApi = {
  channels: () => req<ChannelList>('/v1/notifications/channels'),
  create: (c: ChannelInput) => req<SavedChannel>('/v1/notifications/channels', json(c)),
  /** Omitted members are kept; a Slack url is write-only (omit to keep). */
  update: (id: string, c: Partial<Omit<ChannelInput, 'type'>>) => req<SavedChannel>('/v1/notifications/channels/update', json({ id, ...c })),
  remove: (id: string) => req<{ deleted: boolean }>(`/v1/notifications/channels?${new URLSearchParams({ id })}`, { method: 'DELETE' }),
  test: (id: string) => req<{ queued: boolean; eventId: string }>('/v1/notifications/channels/test', json({ id })),
  rotateSecret: (id: string) => req<SavedChannel>('/v1/notifications/channels/signing-secret', json({ id })),
  deliveries: (channelId: string, limit = 50) =>
    req<{ deliveries: NotificationDelivery[] }>(`/v1/notifications/deliveries?${new URLSearchParams({ channelId, limit: String(limit) })}`),
  retry: (id: number) => req<{ requeued: boolean }>('/v1/notifications/deliveries/retry', json({ id }))
};

export const CHANNEL_TYPES: { value: ChannelType; label: string; hint: string }[] = [
  { value: 'webhook', label: 'Webhook', hint: 'POST signed JSON to any HTTPS endpoint.' },
  { value: 'slack', label: 'Slack', hint: 'Post to a Slack channel through an incoming webhook.' },
  { value: 'email', label: 'Email', hint: "Send through this server's SMTP settings." }
];

export function typeLabel(t: ChannelType): string {
  return CHANNEL_TYPES.find((c) => c.value === t)?.label ?? t;
}

/** Where a channel sends, for the list. */
export function channelTarget(c: NotificationChannel): string {
  switch (c.type) {
    case 'webhook':
      return c.url ?? '';
    case 'slack':
      return c.urlHint ?? 'hooks.slack.com';
    case 'email': {
      const r = c.recipients ?? [];
      return r.length <= 2 ? r.join(', ') : `${r.slice(0, 2).join(', ')} +${r.length - 2}`;
    }
  }
}

/** Splits a recipients textarea (commas, semicolons, whitespace, new lines). */
export function parseRecipients(text: string): string[] {
  const out: string[] = [];
  for (const part of text.split(/[\s,;]+/)) {
    const v = part.trim();
    if (v && !out.includes(v)) out.push(v);
  }
  return out;
}

export function isSlackURL(u: string): boolean {
  try {
    const url = new URL(u.trim());
    return url.protocol === 'https:' && url.hostname.toLowerCase() === 'hooks.slack.com' && !url.port && url.pathname.replace(/\//g, '') !== '';
  } catch {
    return false;
  }
}

export function isHTTPSURL(u: string): boolean {
  try {
    const url = new URL(u.trim());
    return url.protocol === 'https:' && !!url.hostname && !url.username && !url.password && !url.hash;
  } catch {
    return false;
  }
}

export function deliveryState(d: Pick<NotificationDelivery, 'status' | 'attempts'>): { label: string; tone: 'success' | 'warning' | 'danger' | 'neutral' } {
  if (d.status === 'delivered') return { label: 'Delivered', tone: 'success' };
  if (d.status === 'dead') return { label: 'Failed', tone: 'danger' };
  return d.attempts > 0 ? { label: `Retrying (${d.attempts} failed)`, tone: 'warning' } : { label: 'Queued', tone: 'neutral' };
}
