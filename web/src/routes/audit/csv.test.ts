import { describe, expect, it } from 'vitest';
import { resultKind, toCsv, type AuditRow } from './api';

const row = (over: Partial<AuditRow> = {}): AuditRow => ({
  id: 1,
  createdAt: '2026-11-12T13:04:51Z',
  actor: 'alice',
  action: 'secretsmanager.GetSecretValue',
  result: 'ok',
  ...over
});

/** Splits one CSV record of fully quoted cells (no embedded newlines). */
function cells(line: string): string[] {
  return [...line.matchAll(/"((?:[^"]|"")*)"/g)].map((m) => m[1].replace(/""/g, '"'));
}

describe('audit CSV export', () => {
  it('writes a header and quotes every cell, CRLF between records', () => {
    const csv = toCsv([row(), row({ id: 2 })]);
    const lines = csv.split('\r\n');
    expect(lines[0]).toBe('id,createdAt,actor,action,resource,result,errorType,sourceIp,prevHash,hash,correlationId');
    expect(lines).toHaveLength(3);
    expect(lines[1]).toBe('"1","2026-11-12T13:04:51Z","alice","secretsmanager.GetSecretValue","","ok","","","","",""');
  });

  it('doubles embedded quotes and keeps commas inside the cell', () => {
    const csv = toCsv([row({ actor: 'Bob "the builder", Jr' })]);
    expect(cells(csv.split('\r\n')[1])[2]).toBe('Bob "the builder", Jr');
  });

  it.each(['=HYPERLINK("http://evil","x")', '+1+1', '-2+3', '@SUM(A1)', '\t=1', '\r=1'])(
    'neutralises a formula-leading value %j',
    (v) => {
      const out = cells(toCsv([row({ actor: v, resource: v })]).split('\r\n')[1]);
      expect(out[2]).toBe(`'${v}`);
      expect(out[4]).toBe(`'${v}`);
    }
  );

  it('leaves values that merely contain those characters alone', () => {
    const out = cells(toCsv([row({ actor: 'a=b', resource: 'arn:aws:kms:us-east-1:1:key/a-b+c@d' })]).split('\r\n')[1]);
    expect(out[2]).toBe('a=b');
    expect(out[4]).toBe('arn:aws:kms:us-east-1:1:key/a-b+c@d');
  });

  it('writes missing values as empty cells', () => {
    const out = cells(toCsv([row({ errorType: undefined, sourceIp: undefined })]).split('\r\n')[1]);
    expect(out[6]).toBe('');
    expect(out[7]).toBe('');
  });
});

describe('resultKind', () => {
  it.each([
    [{ result: 'ok' }, 'success'],
    [{ result: 'Success' }, 'success'],
    [{ result: 'denied' }, 'denied'],
    [{ result: 'error', errorType: 'AccessDeniedException' }, 'denied'],
    [{ result: 'error', errorType: 'UnauthorizedOperation' }, 'denied'],
    [{ result: 'error', errorType: 'ThrottlingException' }, 'error'],
    [{ result: 'pending' }, 'pending'],
    [{ result: '' }, 'error']
  ] as const)('%j → %s', (r, kind) => {
    expect(resultKind(r)).toBe(kind);
  });
});
