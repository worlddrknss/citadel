import { describe, expect, it } from 'vitest';
import {
  defaultApprovalSeconds,
  formatDuration,
  grantLimits,
  splitList,
  timeLeft,
  validateApproval,
  validateCredential,
  validateGrant,
  type CredentialInput,
  type GrantInput
} from './api';

const cred = (over: Partial<CredentialInput> = {}): CredentialInput => ({
  name: 'github-pat',
  kind: 'http_header',
  allowedHosts: ['api.github.com'],
  ...over
});

describe('validateCredential', () => {
  it('accepts a header profile', () => expect(validateCredential(cred())).toBe(''));
  it('needs hosts for HTTP kinds, not for raw', () => {
    expect(validateCredential(cred({ allowedHosts: [] }))).toMatch(/allowed host/);
    expect(validateCredential(cred({ kind: 'raw', allowedHosts: [] }))).toBe('');
  });
  it('rejects bad names, hosts and broad wildcards', () => {
    expect(validateCredential(cred({ name: 'GitHub' }))).toMatch(/Name/);
    expect(validateCredential(cred({ allowedHosts: ['https://api.github.com'] }))).toMatch(/not a host/);
    expect(validateCredential(cred({ allowedHosts: ['*.com'] }))).toMatch(/too broad/);
    expect(validateCredential(cred({ allowedHosts: ['*.example.com', 'api.example.com:8443'] }))).toBe('');
  });
  it('checks path prefixes and query parameters', () => {
    expect(validateCredential(cred({ allowedPathPrefixes: ['repos/'] }))).toMatch(/start with/);
    expect(validateCredential(cred({ kind: 'http_query', queryParam: '' }))).toMatch(/query parameter/);
    expect(validateCredential(cred({ kind: 'http_query', queryParam: 'api_key' }))).toBe('');
  });
});

describe('validateGrant', () => {
  const g = (over: Partial<GrantInput> = {}): GrantInput => ({ agentId: 'agt_x', credential: 'c', actions: ['use'], ...over });
  it('accepts use', () => expect(validateGrant(g(), 'http_header')).toBe(''));
  it('needs an action and matching kinds', () => {
    expect(validateGrant(g({ actions: [] }), 'http_header')).toMatch(/at least one/);
    expect(validateGrant(g({ actions: ['totp'] }), 'http_header')).toMatch(/TOTP/);
    expect(validateGrant(g({ actions: ['use'] }), 'raw')).toMatch(/revealed/);
    expect(validateGrant(g({ actions: ['reveal'] }), 'raw')).toBe('');
  });
  it('checks dates, windows and limits', () => {
    expect(validateGrant(g({ notBefore: '2026-02-01T00:00:00Z', notAfter: '2026-01-01T00:00:00Z' }), 'http_header')).toMatch(/after/);
    expect(validateGrant(g({ window: { start: '9:00', end: '17:00', days: [], timezone: '' } }), 'http_header')).toMatch(/HH:MM/);
    expect(validateGrant(g({ window: { start: '22:00', end: '06:00', days: ['mon'], timezone: 'UTC' } }), 'http_header')).toBe('');
    expect(validateGrant(g({ maxUsesPerHour: -1 }), 'http_header')).toMatch(/per hour/);
  });
});

describe('helpers', () => {
  it('summarises grant limits', () => {
    expect(grantLimits({ window: null, maxUsesPerHour: 0 })).toBe('No limits');
    expect(grantLimits({ window: { start: '09:00', end: '17:00', days: ['mon'], timezone: '' }, maxUsesPerHour: 30 })).toBe('09:00–17:00 UTC · mon · 30/hour');
  });
  it('splits lists', () => expect(splitList(' a.com,\nb.com  c.com ')).toEqual(['a.com', 'b.com', 'c.com']));
});

describe('approvals and leases', () => {
  it('checks the grant lease length', () => {
    const g: GrantInput = { agentId: 'agt_x', credential: 'c', actions: ['use'] };
    expect(validateGrant({ ...g, leaseTtlSeconds: 30 }, 'http_header')).toMatch(/Lease length/);
    expect(validateGrant({ ...g, leaseTtlSeconds: 90000 }, 'http_header')).toMatch(/Lease length/);
    expect(validateGrant({ ...g, leaseTtlSeconds: 0, requiresApproval: true }, 'http_header')).toBe('');
    expect(grantLimits({ window: null, maxUsesPerHour: 0, requiresApproval: true, leaseTtlSeconds: 900 })).toBe('needs approval · leases 15m');
  });
  it('formats durations and time left', () => {
    expect(formatDuration(45)).toBe('45s');
    expect(formatDuration(900)).toBe('15m');
    expect(formatDuration(5400)).toBe('1h 30m');
    expect(formatDuration(86400)).toBe('24h');
    const now = new Date('2026-11-13T10:00:00Z');
    expect(timeLeft('2026-11-13T10:40:00Z', now)).toBe('in 40 min');
    expect(timeLeft('2026-11-13T13:00:00Z', now)).toBe('in 3 h');
    expect(timeLeft('2026-11-13T09:00:00Z', now)).toBe('expired');
  });
  it('defaults an approval to the requested length, capped', () => {
    expect(defaultApprovalSeconds({ durationSeconds: 900, maxDurationSeconds: 86400 })).toBe(900);
    expect(defaultApprovalSeconds({ durationSeconds: 0, maxDurationSeconds: 86400 })).toBe(3600);
    expect(defaultApprovalSeconds({ durationSeconds: 7200, maxDurationSeconds: 600 })).toBe(600);
  });
  it('validates an approval', () => {
    const r = { taskId: '', maxDurationSeconds: 3600, mfaRequired: false };
    expect(validateApproval({ requestId: 'aar_x', scope: 'once', durationSeconds: 3600 }, r)).toBe('');
    expect(validateApproval({ requestId: 'aar_x', scope: 'task', durationSeconds: 600 }, r)).toMatch(/task ID/);
    expect(validateApproval({ requestId: 'aar_x', scope: 'duration', durationSeconds: 7200 }, r)).toMatch(/1 minute to 1h/);
    expect(validateApproval({ requestId: 'aar_x', scope: 'duration', durationSeconds: 30 }, r)).toMatch(/1 minute/);
    expect(validateApproval({ requestId: 'aar_x', scope: 'once', durationSeconds: 600 }, { ...r, mfaRequired: true })).toMatch(/code/);
    expect(validateApproval({ requestId: 'aar_x', scope: 'once', durationSeconds: 600, mfaCode: '123456' }, { ...r, mfaRequired: true })).toBe('');
    expect(validateApproval({ requestId: 'aar_x', scope: 'once', durationSeconds: 600 }, { ...r, maxDurationSeconds: 30 })).toMatch(/less than a minute/);
  });
});
