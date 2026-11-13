import { describe, expect, it } from 'vitest';
import { canRenewOrRevoke, chainComplete, chainRoleLabel, isImported, pathLenDescription, pathLenLabel, sourceLabel } from './certs';

describe('certificate sources', () => {
  it('labels each source', () => {
    expect(sourceLabel('pca-cert')).toBe('Private CA');
    expect(sourceLabel('pca-ca')).toBe('Private CA');
    expect(sourceLabel('lets-encrypt')).toBe('ACME');
    expect(sourceLabel('acm-imported')).toBe('Imported');
    expect(sourceLabel(undefined)).toBe('—');
  });

  it('keeps imported certificates read-only apart from delete', () => {
    expect(isImported({ source: 'acm-imported' })).toBe(true);
    expect(isImported({ source: 'pca-cert' })).toBe(false);
    expect(canRenewOrRevoke({ source: 'acm-imported', status: 'ISSUED' })).toBe(false);
    expect(canRenewOrRevoke({ source: 'lets-encrypt', status: 'ISSUED' })).toBe(false);
    expect(canRenewOrRevoke({ source: 'pca-cert', status: 'ISSUED' })).toBe(true);
    expect(canRenewOrRevoke({ source: 'pca-cert', status: 'REVOKED' })).toBe(false);
  });
});

describe('certificate chain', () => {
  it('names positions', () => {
    expect(chainRoleLabel('leaf')).toBe('Leaf');
    expect(chainRoleLabel('intermediate')).toBe('Intermediate');
    expect(chainRoleLabel('root')).toBe('Root');
  });

  it('is complete only when it ends at a self-signed root', () => {
    expect(chainComplete(undefined)).toBe(false);
    expect(chainComplete([])).toBe(false);
    expect(chainComplete([{ selfSigned: false }, { selfSigned: true }])).toBe(true);
    expect(chainComplete([{ selfSigned: false }, { selfSigned: false }])).toBe(false);
  });
});

describe('pathLen display', () => {
  it('labels CAs only', () => {
    expect(pathLenLabel({ isCA: false, pathLen: 1 })).toBe('');
    expect(pathLenLabel({ isCA: true })).toBe('pathLen: unlimited');
    expect(pathLenLabel({ isCA: true, pathLen: 0 })).toBe('pathLen: 0');
    expect(pathLenLabel({ isCA: true, pathLen: 2 })).toBe('pathLen: 2');
  });

  it('describes the constraint', () => {
    expect(pathLenDescription()).toMatch(/^Unlimited/);
    expect(pathLenDescription(0)).toMatch(/end-entity certificates only/);
    expect(pathLenDescription(1)).toBe('1 — up to 1 more CA level below it');
    expect(pathLenDescription(3)).toBe('3 — up to 3 more CA levels below it');
  });
});
