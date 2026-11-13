import { describe, expect, it } from 'vitest';
import { parseYaml, YamlError } from './yaml';

describe('parseYaml', () => {
  it('parses nested mappings and typed plain scalars', () => {
    const doc = parseYaml(`openapi: 3.1.0
info:
  title: Citadel API
  version: 2.1.0
count: 42
ratio: 0.5
on: true
off: false
nothing: null
tilde: ~
`);
    expect(doc).toEqual({
      openapi: '3.1.0',
      info: { title: 'Citadel API', version: '2.1.0' },
      count: 42,
      ratio: 0.5,
      on: true,
      off: false,
      nothing: null,
      tilde: null
    });
  });

  it('parses sequences of scalars and of mappings', () => {
    const doc = parseYaml(`parameters:
  - name: project
    in: query
    required: true
    schema:
      type: string
  - name: env
    in: query
list:
  - a
  - "b c"
same-indent:
- x
- y
`);
    expect(doc).toEqual({
      parameters: [
        { name: 'project', in: 'query', required: true, schema: { type: 'string' } },
        { name: 'env', in: 'query' }
      ],
      list: ['a', 'b c'],
      'same-indent': ['x', 'y']
    });
  });

  it('parses quoted keys and scalars', () => {
    const doc = parseYaml(`responses:
  "200":
    description: "OK: done # really"
  '404':
    $ref: "#/components/responses/NotFound"
single: 'it''s'
escaped: "line\\nnext \\"q\\""
`);
    expect(doc).toEqual({
      responses: {
        '200': { description: 'OK: done # really' },
        '404': { $ref: '#/components/responses/NotFound' }
      },
      single: "it's",
      escaped: 'line\nnext "q"'
    });
  });

  it('parses flow collections', () => {
    const doc = parseYaml(`tags: [Secrets]
enum: [viewer, editor, admin]
mixed: ["Let's Encrypt", 3, true]
empty: []
obj: {}
`);
    expect(doc).toEqual({
      tags: ['Secrets'],
      enum: ['viewer', 'editor', 'admin'],
      mixed: ["Let's Encrypt", 3, true],
      empty: [],
      obj: {}
    });
  });

  it('parses literal blocks with blank lines and chomping', () => {
    const doc = parseYaml(`a: |
  first line

  third: line # kept
b: |-
  stripped
c: after
`);
    expect(doc).toEqual({ a: 'first line\n\nthird: line # kept\n', b: 'stripped', c: 'after' });
  });

  it('ignores full-line comments and blank lines', () => {
    expect(parseYaml(`# header\n\na: 1\n  # indented comment\nb:\n  c: 2\n`)).toEqual({ a: 1, b: { c: 2 } });
  });

  it('returns null for an empty value or document', () => {
    expect(parseYaml('a:\nb: 1\n')).toEqual({ a: null, b: 1 });
    expect(parseYaml('')).toBeNull();
  });

  it('handles nested sequences inside sequence items', () => {
    const doc = parseYaml(`security:
  - sessionCookie: []
  - bearerAccessKey: []
oneOf:
  - type: object
    required: [a]
    properties:
      a:
        type: array
        items:
          type: string
`);
    expect(doc).toEqual({
      security: [{ sessionCookie: [] }, { bearerAccessKey: [] }],
      oneOf: [{ type: 'object', required: ['a'], properties: { a: { type: 'array', items: { type: 'string' } } } }]
    });
  });

  it('parses empty-mapping items, $ref items and type lists', () => {
    const doc = parseYaml(`security:
  - {}
  - bearerAccessKey: []
oneOf:
  - $ref: "#/components/schemas/A"
  - type: "null"
type: [integer, string]
note: |
  - a list-looking line

  stays text
`);
    expect(doc).toEqual({
      security: [{}, { bearerAccessKey: [] }],
      oneOf: [{ $ref: '#/components/schemas/A' }, { type: 'null' }],
      type: ['integer', 'string'],
      note: '- a list-looking line\n\nstays text\n'
    });
  });

  it('rejects unsupported syntax with a line number', () => {
    expect(() => parseYaml('a: &anchor 1\n')).toThrow(YamlError);
    expect(() => parseYaml('a: >\n  folded\n')).toThrow(/line 1/);
    expect(() => parseYaml('a: [[1]]\n')).toThrow(/nested/);
    expect(() => parseYaml('a: {b: 1}\n')).toThrow(/flow mappings/);
    expect(() => parseYaml('a: 1\na: 2\n')).toThrow(/duplicate/);
    expect(() => parseYaml('a: 1\n    b: 2\n')).toThrow(/indentation/);
  });
});
