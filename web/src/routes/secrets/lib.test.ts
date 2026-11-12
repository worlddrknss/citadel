import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { envLabel, envTier, fullDate, initials, joinPath, normPath, relTime, shortDate, sortEnvs, tierTone } from './lib';

describe('envTier', () => {
  it('infers the tier from common slugs, case-insensitively', () => {
    expect(envTier('dev')).toBe('development');
    expect(envTier('Sandbox')).toBe('development');
    expect(envTier('uat')).toBe('staging');
    expect(envTier('pre-prod')).toBe('staging');
    expect(envTier('PROD')).toBe('production');
    expect(envTier('live')).toBe('production');
    expect(envTier('perf')).toBe('other');
  });

  it('prefers the environment policy tier over the name', () => {
    expect(envTier('dev', 'production')).toBe('production');
    expect(envTier('perf', 'staging')).toBe('staging');
    expect(envTier('prod', 'bogus')).toBe('production');
    expect(envTier('prod', null)).toBe('production');
  });

  it('maps tiers to tones', () => {
    expect(tierTone[envTier('prod')]).toBe('danger');
    expect(tierTone[envTier('qa')]).toBe('warning');
    expect(tierTone[envTier('perf')]).toBe('neutral');
  });
});

describe('sortEnvs', () => {
  it('orders dev → staging → prod, then the rest alphabetically, without mutating', () => {
    const input = ['zeta', 'prod', 'alpha', 'staging', 'dev', 'qa', 'local'];
    expect(sortEnvs(input)).toEqual(['dev', 'local', 'qa', 'staging', 'prod', 'alpha', 'zeta']);
    expect(input[0]).toBe('zeta');
  });
});

describe('envLabel', () => {
  it('names well-known slugs and passes others through', () => {
    expect(envLabel('prod')).toBe('Production');
    expect(envLabel('STG')).toBe('Staging');
    expect(envLabel('perf-2')).toBe('perf-2');
  });
});

describe('relTime / dates', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-11-12T12:00:00Z'));
  });
  afterEach(() => vi.useRealTimers());

  it('formats elapsed time in coarse steps', () => {
    expect(relTime('2026-11-12T11:59:30Z')).toBe('just now');
    expect(relTime('2026-11-12T11:58:59Z')).toBe('1 min ago');
    expect(relTime('2026-11-12T09:00:00Z')).toBe('3 h ago');
    expect(relTime('2026-11-09T12:00:00Z')).toBe('3 d ago');
  });

  it('falls back to a short date for old or future times', () => {
    expect(relTime('2026-10-01T12:00:00Z')).toBe(shortDate('2026-10-01T12:00:00Z'));
    expect(relTime('2026-12-01T12:00:00Z')).toBe(shortDate('2026-12-01T12:00:00Z'));
    expect(shortDate('2026-10-01T12:00:00Z')).not.toMatch(/2026/);
    expect(shortDate('2024-10-01T12:00:00Z')).toMatch(/2024/);
  });

  it('shows an em dash for missing or invalid input', () => {
    for (const v of [undefined, null, '', 'garbage']) {
      expect(relTime(v)).toBe('—');
      expect(shortDate(v)).toBe('—');
      expect(fullDate(v)).toBe('—');
    }
  });
});

describe('initials', () => {
  it.each([
    ['svc/rotation', 'SR'],
    ['Priya Nair', 'PN'],
    ['alice', 'AL'],
    ['a', 'A'],
    ['', '?'],
    [null, '?'],
    ['//', '?']
  ])('%j → %s', (input, out) => {
    expect(initials(input)).toBe(out);
  });
});

describe('paths', () => {
  it('joinPath joins without doubling slashes', () => {
    expect(joinPath('/', 'db')).toBe('/db');
    expect(joinPath('', 'db')).toBe('/db');
    expect(joinPath('/app', 'db')).toBe('/app/db');
    expect(joinPath('/app//', 'db')).toBe('/app/db');
  });

  it('normPath collapses slashes and trims', () => {
    expect(normPath('')).toBe('/');
    expect(normPath('/')).toBe('/');
    expect(normPath('a/b')).toBe('/a/b');
    expect(normPath('//a///b/')).toBe('/a/b');
  });
});
