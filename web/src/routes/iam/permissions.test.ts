import { describe, expect, it } from 'vitest';
import {
  normalizePrefix,
  parsePrefixes,
  prefixError,
  readPathsPolicy,
  prefixesFromPolicy,
  parsePolicyJson,
  permissionsSummary,
  READ_SECRET_ACTIONS
} from './permissions';

describe('path prefixes', () => {
  it('normalises', () => {
    expect(normalizePrefix(' /shop/prod ')).toBe('shop/prod/');
    expect(normalizePrefix('shop/prod/*')).toBe('shop/prod/');
    expect(normalizePrefix('shop/prod/')).toBe('shop/prod/');
    expect(normalizePrefix('  ')).toBe('');
  });
  it('splits and de-duplicates', () => {
    expect(parsePrefixes('shop/prod\nshop/prod/\n\nblog/prod, api/x')).toEqual(['shop/prod/', 'blog/prod/', 'api/x/']);
  });
  it('validates', () => {
    expect(prefixError([])).toMatch(/at least one/);
    expect(prefixError(['sh*p/'])).toMatch(/wildcards/);
    expect(prefixError(['shop/prod/'])).toBe('');
  });
});

describe('read paths policy', () => {
  it('builds a scoped read policy', () => {
    const p = readPathsPolicy(['shop/prod/']);
    const st = Array.isArray(p.Statement) ? p.Statement[0] : p.Statement;
    expect(st.Effect).toBe('Allow');
    expect(st.Action).toEqual(READ_SECRET_ACTIONS);
    expect(st.Resource).toEqual(['arn:aws:secretsmanager:*:*:secret:shop/prod/*']);
  });
  it('round-trips', () => {
    expect(prefixesFromPolicy(readPathsPolicy(['a/prod/', 'b/prod/']))).toEqual(['a/prod/', 'b/prod/']);
  });
  it('does not recognise other policies', () => {
    expect(prefixesFromPolicy(null)).toBeNull();
    expect(prefixesFromPolicy({ Statement: { Effect: 'Allow', Action: '*', Resource: '*' } })).toBeNull();
    const extra = readPathsPolicy(['a/']);
    (extra.Statement as unknown[]).push({ Effect: 'Deny', Action: '*', Resource: '*' });
    expect(prefixesFromPolicy(extra)).toBeNull();
    expect(
      prefixesFromPolicy({ Statement: [{ Effect: 'Allow', Action: READ_SECRET_ACTIONS, Resource: 'arn:aws:secretsmanager:*:*:secret:*' }] })
    ).toBeNull();
  });
});

describe('JSON editor', () => {
  it('parses', () => {
    expect(parsePolicyJson('{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}').policy).toBeTruthy();
    expect(parsePolicyJson('nope').error).toMatch(/Not valid JSON/);
    expect(parsePolicyJson('[]').error).toMatch(/object/);
    expect(parsePolicyJson('{"Statement":[]}').error).toMatch(/Statement/);
  });
});

describe('summary', () => {
  it('describes', () => {
    expect(permissionsSummary(undefined)).toEqual({ label: 'Whole account', restricted: false });
    expect(permissionsSummary(readPathsPolicy(['shop/prod/'])).label).toBe('Read shop/prod/');
    expect(permissionsSummary(readPathsPolicy(['a/', 'b/'])).label).toBe('Read 2 paths');
    expect(permissionsSummary({ Statement: { Effect: 'Allow', Action: '*', Resource: '*' } }).label).toBe('Custom policy');
  });
});
