import { describe, expect, it } from 'vitest';
import {
  caDeleteBlocker,
  canRenewOrRevoke,
  chainComplete,
  chainRoleLabel,
  deleteCertMessage,
  deleteNeedsTypeToConfirm,
  isImported,
  pathLenDescription,
  pathLenLabel,
  renewalSummary,
  restoreDaysLeft,
  sourceLabel
} from './certs';

const NOW = Date.parse('2026-06-01T00:00:00Z');
const inDays = (d: number) => new Date(NOW + d * 86_400_000).toISOString();

describe('deleting certificates', () => {
  it('asks for the name only while a certificate is still valid', () => {
    expect(deleteNeedsTypeToConfirm({ status: 'ISSUED', notAfter: inDays(10) }, NOW)).toBe(true);
    expect(deleteNeedsTypeToConfirm({ status: 'REVOKED', notAfter: inDays(10) }, NOW)).toBe(false);
    expect(deleteNeedsTypeToConfirm({ status: 'ISSUED', notAfter: inDays(-2) }, NOW)).toBe(false);
  });

  it('explains what happens per source', () => {
    expect(deleteCertMessage({ source: 'pca-cert', status: 'ISSUED', notAfter: inDays(5) }, 'a.test', NOW)).toMatch(/revokes it first/);
    expect(deleteCertMessage({ source: 'pca-cert', status: 'REVOKED', notAfter: inDays(5) }, 'a.test', NOW)).toMatch(/revocation list doesn't change/);
    expect(deleteCertMessage({ source: 'lets-encrypt', status: 'ISSUED', notAfter: inDays(5) }, 'a.test', NOW)).toMatch(/isn't revoked at Let's Encrypt/);
    expect(deleteCertMessage({ source: 'acm-imported', status: 'ISSUED', notAfter: inDays(5) }, 'a.test', NOW)).toMatch(/through ACM/);
  });
});

describe('deleting CAs', () => {
  it('needs a disabled CA with no valid certificates', () => {
    expect(caDeleteBlocker({ status: 'ACTIVE', outstanding: 0 })).toBe('Disable the CA before deleting it.');
    expect(caDeleteBlocker({ status: 'DISABLED', outstanding: 1 })).toBe('1 certificate issued by this CA is still valid. Revoke it before deleting the CA.');
    expect(caDeleteBlocker({ status: 'DISABLED', outstanding: 3 })).toMatch(/^3 certificates .* are still valid\. Revoke them/);
    expect(caDeleteBlocker({ status: 'DISABLED', outstanding: 0 })).toBeNull();
    expect(caDeleteBlocker({ status: 'EXPIRED' })).toBeNull();
    expect(caDeleteBlocker({ status: 'DELETED' })).toMatch(/already deleted/);
  });

  it('counts the restore window', () => {
    expect(restoreDaysLeft(undefined, NOW)).toBeNull();
    expect(restoreDaysLeft(inDays(6.5), NOW)).toBe(7);
    expect(restoreDaysLeft(inDays(-1), NOW)).toBe(0);
  });
});

describe("Let's Encrypt renewal", () => {
  it('summarises the renewal state', () => {
    expect(renewalSummary(undefined)).toBeNull();
    expect(renewalSummary({ kind: 'http-01', autoRenew: true, manual: false }, inDays(60), NOW)?.label).toBe('Auto-renew on');
    const failing = renewalSummary({ kind: 'http-01', autoRenew: true, manual: false, lastError: 'Validation failed' }, inDays(20), NOW);
    expect(failing).toEqual({ label: 'Renewal failing', tone: 'danger', detail: 'Validation failed' });
    const manual = renewalSummary({ kind: 'dns-01', autoRenew: false, manual: true }, inDays(12), NOW);
    expect(manual?.label).toBe('Manual renewal');
    expect(manual?.tone).toBe('warning');
    expect(manual?.detail).toMatch(/expires in 12 days/);
    expect(renewalSummary({ kind: 'http-01', autoRenew: false, manual: false }, inDays(90), NOW)?.label).toBe('Auto-renew off');
    expect(renewalSummary({ kind: 'http-01', autoRenew: true, manual: false, renewedBy: 'x' }, inDays(5), NOW)?.label).toBe('Renewed');
  });
});

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
