import { describe, expect, it } from 'vitest';
import { channelTarget, deliveryState, isHTTPSURL, isSlackURL, parseRecipients, type NotificationChannel } from './notifications';

const base: NotificationChannel = {
  id: 'nch_1',
  name: 'ops',
  type: 'webhook',
  enabled: true,
  events: [],
  hasSigningSecret: true,
  createdAt: '',
  createdBy: '',
  updatedAt: '',
  updatedBy: ''
};

describe('notifications helpers', () => {
  it('describes where a channel sends', () => {
    expect(channelTarget({ ...base, url: 'https://hooks.example.com/x' })).toBe('https://hooks.example.com/x');
    expect(channelTarget({ ...base, type: 'slack', urlHint: 'hooks.slack.com/services/T1/B1/…' })).toBe('hooks.slack.com/services/T1/B1/…');
    expect(channelTarget({ ...base, type: 'email', recipients: ['a@x.io'] })).toBe('a@x.io');
    expect(channelTarget({ ...base, type: 'email', recipients: ['a@x.io', 'b@x.io', 'c@x.io', 'd@x.io'] })).toBe('a@x.io, b@x.io +2');
  });

  it('parses recipients', () => {
    expect(parseRecipients(' a@x.io, b@x.io;\nc@x.io  a@x.io ')).toEqual(['a@x.io', 'b@x.io', 'c@x.io']);
    expect(parseRecipients('')).toEqual([]);
  });

  it('validates URLs like the server', () => {
    expect(isSlackURL('https://hooks.slack.com/services/T/B/x')).toBe(true);
    expect(isSlackURL('https://hooks.slack.com/')).toBe(false);
    expect(isSlackURL('https://hooks.slack.com.evil.io/x')).toBe(false);
    expect(isSlackURL('http://hooks.slack.com/x')).toBe(false);
    expect(isHTTPSURL('https://example.com/hook')).toBe(true);
    expect(isHTTPSURL('http://example.com/hook')).toBe(false);
    expect(isHTTPSURL('https://u:p@example.com/')).toBe(false);
    expect(isHTTPSURL('not a url')).toBe(false);
  });

  it('labels delivery states', () => {
    expect(deliveryState({ status: 'delivered', attempts: 1 })).toEqual({ label: 'Delivered', tone: 'success' });
    expect(deliveryState({ status: 'pending', attempts: 0 })).toEqual({ label: 'Queued', tone: 'neutral' });
    expect(deliveryState({ status: 'pending', attempts: 2 })).toEqual({ label: 'Retrying (2 failed)', tone: 'warning' });
    expect(deliveryState({ status: 'dead', attempts: 10 })).toEqual({ label: 'Failed', tone: 'danger' });
  });
});
