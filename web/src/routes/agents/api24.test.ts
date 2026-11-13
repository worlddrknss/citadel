import { describe, expect, it } from 'vitest';
import { codeSecondsLeft, formatPermissions, isMintedKind, parsePermissions, validateCredential, validateScope, type AgentCredential } from './api';

const base = (over: Partial<AgentCredential>): AgentCredential => ({
  name: 'c',
  secretName: 'p/e/K',
  kind: 'github_app',
  description: '',
  allowedHosts: [],
  allowedMethods: [],
  allowedPathPrefixes: [],
  allowHttp: false,
  allowedCidrs: [],
  createdAt: '',
  updatedAt: '',
  grants: [],
  ...over
});

describe('login and minted credentials', () => {
  it('validates login URL patterns', () => {
    expect(validateCredential({ name: 'site', kind: 'login', login: { urlPatterns: [] } })).toMatch(/at least one page/);
    expect(validateCredential({ name: 'site', kind: 'login', login: { urlPatterns: ['http://x.example.com'] } })).toMatch(/https/);
    expect(validateCredential({ name: 'site', kind: 'login', login: { urlPatterns: ['https://*.example.com/login'] } })).toBe('');
  });

  it('validates minted settings', () => {
    expect(validateCredential({ name: 'aws', kind: 'aws_sts', awsSts: { roleArn: 'nope' } })).toMatch(/role ARN/);
    expect(validateCredential({ name: 'aws', kind: 'aws_sts', awsSts: { roleArn: 'arn:aws:iam::123456789012:role/agent' } })).toBe('');
    expect(validateCredential({ name: 'gh', kind: 'github_app', githubApp: { appId: '1', installationId: 0 } })).toMatch(/installation/);
    expect(validateCredential({ name: 'o', kind: 'oauth2_client_credentials', oauth2: { tokenUrl: '' } })).toMatch(/token endpoint/);
    expect(isMintedKind('github_app')).toBe(true);
    expect(isMintedKind('login')).toBe(false);
  });

  it('parses and formats GitHub permissions', () => {
    expect(parsePermissions('contents=read\npull_requests=write')).toEqual({ contents: 'read', pull_requests: 'write' });
    expect(parsePermissions('contents=all')).toBeNull();
    expect(parsePermissions('')).toEqual({});
    expect(formatPermissions({ contents: 'read' })).toBe('contents=read');
  });

  it('checks grant scopes against the credential', () => {
    const bare = base({ githubApp: { appId: '1', installationId: 2 } });
    expect(validateScope({}, bare)).toMatch(/Restrict/);
    expect(validateScope({ repositories: ['api'] }, bare)).toBe('');
    const withRepos = base({ githubApp: { appId: '1', installationId: 2, repositories: ['api'] } });
    expect(validateScope({}, withRepos)).toBe('');
    expect(validateScope({ repositories: ['web'] }, withRepos)).toMatch(/not one of/);
    const aws = base({ kind: 'aws_sts', awsSts: { roleArn: 'r', sessionPolicy: '{}' } });
    expect(validateScope({ sessionPolicy: '{}' }, aws)).toMatch(/already has/);
    const oauth = base({ kind: 'oauth2_client_credentials', oauth2: { tokenUrl: 'https://x', scopes: ['read'] } });
    expect(validateScope({ scopes: ['write'] }, oauth)).toMatch(/not one of/);
    expect(validateScope({ scopes: ['read'] }, oauth)).toBe('');
  });

  it('counts TOTP seconds left', () => {
    const now = Date.parse('2026-11-13T10:00:00Z');
    expect(codeSecondsLeft('2026-11-13T10:00:12Z', now)).toBe(12);
    expect(codeSecondsLeft('2026-11-13T09:59:00Z', now)).toBe(0);
  });
});
