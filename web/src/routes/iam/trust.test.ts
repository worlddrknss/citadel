import { describe, expect, it } from 'vitest';
import type { OIDCProvider, Role, TrustPolicy } from '#lib/api.ts';
import { hasErrors, parseTrustJson, sessionLabel, splitList, trustToJson, usage, validateTrust } from './trust';

const providers: OIDCProvider[] = [
  {
    providerArn: 'arn:aws:iam::000000000000:oidc-provider/token.actions.githubusercontent.com',
    url: 'https://token.actions.githubusercontent.com/',
    clientIds: ['sts.amazonaws.com', 'citadel'],
    createdAt: '2026-01-01T00:00:00Z'
  }
];

const oidc = (over: Partial<TrustPolicy> = {}): TrustPolicy => ({
  type: 'oidc',
  providerUrl: 'https://token.actions.githubusercontent.com',
  audiences: ['sts.amazonaws.com'],
  subjects: ['repo:acme/app:ref:refs/heads/main'],
  ...over
});

describe('splitList', () => {
  it('splits on commas and newlines and drops blanks', () => {
    expect(splitList(' a, b\n\nc ,, ')).toEqual(['a', 'b', 'c']);
    expect(splitList('')).toEqual([]);
  });
});

describe('validateTrust (oidc)', () => {
  it('accepts a valid policy, matching the issuer regardless of a trailing slash', () => {
    const e = validateTrust(oidc(), providers);
    expect(e).toEqual({});
    expect(hasErrors(e)).toBe(false);
  });

  it('requires a registered https issuer', () => {
    expect(validateTrust(oidc({ providerUrl: '' }), providers).providerUrl).toMatch(/Choose/);
    expect(validateTrust(oidc({ providerUrl: 'http://token.actions.githubusercontent.com' }), providers).providerUrl).toMatch(/https/);
    expect(validateTrust(oidc({ providerUrl: 'https://other.example' }), providers).providerUrl).toMatch(/No identity provider/);
  });

  it('requires audiences known to the provider', () => {
    expect(validateTrust(oidc({ audiences: [] }), providers).audiences).toMatch(/at least one/);
    expect(validateTrust(oidc({ audiences: ['nope'] }), providers).audiences).toMatch(/Not an audience.*nope/);
  });

  it('only allows * at the end of a subject, and never alone', () => {
    expect(validateTrust(oidc({ subjects: ['repo:acme/*'] }), providers)).toEqual({});
    expect(validateTrust(oidc({ subjects: ['repo:*:main'] }), providers).subjects).toMatch(/only allowed at the end/);
    expect(validateTrust(oidc({ subjects: ['*'] }), providers).subjects).toMatch(/bare \*/);
    expect(validateTrust(oidc({ subjects: [] }), providers).subjects).toMatch(/at least one/);
  });

  it('rejects principals on an oidc policy', () => {
    expect(validateTrust(oidc({ principals: ['123456789012'] }), providers).principals).toBeTruthy();
  });
});

describe('validateTrust (account)', () => {
  it('requires 12-digit account IDs', () => {
    expect(validateTrust({ type: 'account', principals: ['123456789012'] }, [])).toEqual({});
    expect(validateTrust({ type: 'account', principals: [] }, []).principals).toMatch(/at least one/);
    expect(validateTrust({ type: 'account', principals: ['12345'] }, []).principals).toMatch(/12345/);
    expect(validateTrust({ type: 'account', principals: ['1234567890123'] }, []).principals).toBeTruthy();
  });

  it('rejects an unknown type', () => {
    expect(validateTrust({ type: 'saml' as never }, []).type).toBeTruthy();
  });
});

describe('trust JSON', () => {
  it('serializes only the fields for the type', () => {
    expect(JSON.parse(trustToJson(oidc({ principals: ['x'] })))).toEqual({
      type: 'oidc',
      providerUrl: 'https://token.actions.githubusercontent.com',
      audiences: ['sts.amazonaws.com'],
      subjects: ['repo:acme/app:ref:refs/heads/main']
    });
    expect(JSON.parse(trustToJson({ type: 'account', providerUrl: 'x' }))).toEqual({ type: 'account', principals: [] });
  });

  it('round-trips', () => {
    const t = oidc();
    expect(parseTrustJson(trustToJson(t)).trust).toEqual({ ...t, principals: undefined });
  });

  it('trims list entries and drops blanks', () => {
    expect(parseTrustJson('{"type":"account","principals":[" 123456789012 ",""]}').trust?.principals).toEqual(['123456789012']);
  });

  it.each([
    ['not json', /Invalid JSON/],
    ['[]', /JSON object/],
    ['null', /JSON object/],
    ['{"type":"oidc","extra":1}', /Unknown field: extra/],
    ['{"type":"oidc","a":1,"b":2}', /Unknown fields: a, b/],
    ['{"type":"oidc","audiences":"x"}', /audiences must be an array/],
    ['{"type":"oidc","subjects":[1]}', /subjects must be an array/],
    ['{"type":"oidc","providerUrl":5}', /providerUrl must be a string/]
  ])('rejects %s', (text, msg) => {
    expect(parseTrustJson(text).error).toMatch(msg);
  });
});

describe('sessionLabel', () => {
  it('uses hours when whole, else minutes', () => {
    expect(sessionLabel(3600)).toBe('1 h');
    expect(sessionLabel(43200)).toBe('12 h');
    expect(sessionLabel(5400)).toBe('90 min');
  });
});

describe('usage', () => {
  const role = (trust: TrustPolicy): Role => ({
    roleArn: 'arn:aws:iam::000000000000:role/Deploy Bot',
    roleName: 'Deploy Bot!',
    description: '',
    trust,
    maxSessionSeconds: 3600,
    createdAt: '',
    updatedAt: ''
  });

  it('builds web-identity examples for oidc roles with a sanitised session name', () => {
    const u = usage(role(oidc({ audiences: ['citadel'] })), 'https://citadel.example');
    expect(u.map((x) => x.id)).toEqual(['cli', 'env', 'k8s']);
    expect(u[0].code).toContain('assume-role-with-web-identity');
    expect(u[0].code).toContain('--role-session-name deploy-bot-');
    expect(u[2].code).toContain('audience: citadel');
  });

  it('builds assume-role examples for account roles', () => {
    const u = usage(role({ type: 'account', principals: ['123456789012'] }), 'https://c');
    expect(u.map((x) => x.id)).toEqual(['cli', 'env']);
    expect(u[0].code).toContain('aws sts assume-role \\');
  });
});
