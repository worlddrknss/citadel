import { describe, expect, it } from 'vitest';
import { parseDotenv, toDotenv } from './dotenv';

const values = (text: string) => Object.fromEntries(parseDotenv(text).entries.map((e) => [e.key, e.value]));

describe('parseDotenv', () => {
  it('reads plain KEY=VALUE lines with line numbers', () => {
    const r = parseDotenv('A=1\nB=two\n');
    expect(r.entries).toEqual([
      { key: 'A', value: '1', line: 1 },
      { key: 'B', value: 'two', line: 2 }
    ]);
    expect(r.errors).toEqual([]);
  });

  it('skips blank lines and # comments', () => {
    const r = parseDotenv('# heading\n\n   # indented comment\nA=1\n');
    expect(r.entries).toEqual([{ key: 'A', value: '1', line: 4 }]);
  });

  it('strips an export prefix', () => {
    expect(values('export A=1\nexport   B=2')).toEqual({ A: '1', B: '2' });
    // Not a prefix without the space.
    expect(values('exportC=3')).toEqual({ exportC: '3' });
  });

  it('trims around the key and the =', () => {
    expect(values('  A  =  hello  ')).toEqual({ A: 'hello' });
  });

  it('keeps everything after the first =', () => {
    expect(values('URL=postgres://u:p@h/db?sslmode=require&x=1')).toEqual({
      URL: 'postgres://u:p@h/db?sslmode=require&x=1'
    });
  });

  it('drops trailing " # comments" from unquoted values but keeps # inside a value', () => {
    expect(values('A=value # comment')).toEqual({ A: 'value' });
    expect(values('A=val#ue')).toEqual({ A: 'val#ue' });
    expect(values('A=#notacomment')).toEqual({ A: '#notacomment' });
  });

  it('treats "KEY= # comment" as an empty value, not the comment text', () => {
    expect(values('A= # comment')).toEqual({ A: '' });
    expect(values('A=\t# comment')).toEqual({ A: '' });
  });

  it('allows empty values', () => {
    expect(values('A=\nB=""\nC=\'\'')).toEqual({ A: '', B: '', C: '' });
  });

  it('single quotes are literal', () => {
    expect(values("A='a \\n b # c'")).toEqual({ A: 'a \\n b # c' });
    expect(values("A='x' # trailing")).toEqual({ A: 'x' });
  });

  it('double quotes process \\n \\t \\r \\" \\\\ escapes', () => {
    expect(values('A="l1\\nl2\\tt\\rr"')).toEqual({ A: 'l1\nl2\tt\rr' });
    expect(values('A="he said \\"hi\\""')).toEqual({ A: 'he said "hi"' });
    expect(values('A="back\\\\slash"')).toEqual({ A: 'back\\slash' });
    expect(values('A="ends with backslash\\\\"')).toEqual({ A: 'ends with backslash\\' });
    expect(values('A="literal \\\\n"')).toEqual({ A: 'literal \\n' });
  });

  it('double-quoted values keep # and spaces and ignore a trailing comment', () => {
    expect(values('A="  pad # not comment  " # comment')).toEqual({ A: '  pad # not comment  ' });
  });

  it('double-quoted values may span lines', () => {
    const r = parseDotenv('KEY="-----BEGIN-----\nabc\n-----END-----"\nNEXT=1');
    expect(r.entries).toEqual([
      { key: 'KEY', value: '-----BEGIN-----\nabc\n-----END-----', line: 1 },
      { key: 'NEXT', value: '1', line: 4 }
    ]);
  });

  it('an escaped quote does not end a multi-line value', () => {
    expect(values('A="x\\"\ny"')).toEqual({ A: 'x"\ny' });
  });

  it('reports unterminated quotes and lines without a key', () => {
    expect(parseDotenv("A='open").errors).toEqual([1]);
    expect(parseDotenv('A="open').errors).toEqual([1]);
    const r = parseDotenv('JUSTTEXT\n=value\nB=2');
    expect(r.errors).toEqual([1, 2]);
    expect(r.entries).toEqual([{ key: 'B', value: '2', line: 3 }]);
  });

  it('handles CRLF and CR line endings', () => {
    expect(values('A=1\r\nB="x"\r\nC=3\rD=4')).toEqual({ A: '1', B: 'x', C: '3', D: '4' });
  });

  it('ignores a UTF-8 byte order mark', () => {
    expect(values('﻿A=1')).toEqual({ A: '1' });
  });

  it('collapses duplicate keys: the last one wins, as when a shell sources the file', () => {
    const r = parseDotenv('A=first\nB=b\nA=second\n');
    expect(r.entries).toEqual([
      { key: 'B', value: 'b', line: 2 },
      { key: 'A', value: 'second', line: 3 }
    ]);
    expect(r.duplicates).toEqual(['A']);
  });
});

describe('toDotenv', () => {
  it('leaves simple values bare and ends with a newline', () => {
    expect(toDotenv([{ key: 'A', value: 'abc-123_./:@+' }, { key: 'B', value: '' }])).toBe('A=abc-123_./:@+\nB=\n');
  });

  it('quotes and escapes values that need it', () => {
    expect(toDotenv([{ key: 'A', value: 'has space' }])).toBe('A="has space"\n');
    expect(toDotenv([{ key: 'A', value: 'q"b\\n\nr\r' }])).toBe('A="q\\"b\\\\n\\nr\\r"\n');
    expect(toDotenv([{ key: 'A', value: '#hash' }])).toBe('A="#hash"\n');
  });

  it('round-trips through parseDotenv', () => {
    const tricky = [
      'plain',
      '',
      ' leading and trailing ',
      'with # hash',
      ' # looks like a comment',
      "single ' quote",
      'double " quote',
      'back\\slash',
      'trailing backslash\\',
      'multi\nline\nvalue',
      'cr\r\nlf',
      'tab\there',
      '$HOME ${VAR}',
      '=starts with equals',
      'unicode ✓ ünï'
    ];
    const entries = tricky.map((value, i) => ({ key: `K${i}`, value }));
    const parsed = parseDotenv(toDotenv(entries));
    expect(parsed.errors).toEqual([]);
    expect(parsed.entries.map(({ key, value }) => ({ key, value }))).toEqual(entries);
  });
});
