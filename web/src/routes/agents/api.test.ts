import { describe, expect, it } from 'vitest';
import { grantLimits, splitList, validateCredential, validateGrant, type CredentialInput, type GrantInput } from './api';

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
