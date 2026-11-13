import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { expandable, filterGroups, parseSpec, refName, typeLabel } from './spec';

const SAMPLE = `openapi: 3.1.0
info:
  title: Citadel API
  version: 2.1.0
security:
  - sessionCookie: []
  - bearerAccessKey: []
tags:
  - name: Secrets
    description: Items in folders
  - name: Server
paths:
  /v1/secrets:
    get:
      operationId: listSecrets
      tags: [Secrets]
      summary: List the items in a folder
      x-citadel-role: viewer
      parameters:
        - name: project
          in: query
          required: true
          schema:
            type: string
      responses:
        "200":
          description: The listing
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/SecretListing"
        "401":
          $ref: "#/components/responses/Unauthorized"
    post:
      operationId: putSecret
      tags: [Secrets]
      summary: Create or update an item
      x-citadel-role: editor
      x-citadel-audit: citadel.PutItem
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
      responses:
        "200":
          description: OK
  /v1/openapi.yaml:
    get:
      operationId: getOpenAPISpec
      tags: [Server]
      summary: This document
      x-citadel-role: public
      security: []
      responses:
        "200":
          description: The spec
components:
  schemas:
    Error:
      type: object
    SecretListing:
      type: object
      properties:
        items:
          type: array
          items:
            $ref: "#/components/schemas/SecretItem"
    SecretItem:
      type: object
      properties:
        key:
          type: string
        updatedAt:
          type: string
          format: date-time
  responses:
    Unauthorized:
      description: Not signed in
      content:
        application/json:
          schema:
            $ref: "#/components/schemas/Error"
`;

describe('parseSpec', () => {
  const spec = parseSpec(SAMPLE);

  it('groups operations by tag in the declared order', () => {
    expect(spec.groups.map((g) => g.name)).toEqual(['Secrets', 'Server']);
    expect(spec.groups[0].description).toBe('Items in folders');
    expect(spec.groups[0].operations.map((o) => o.id)).toEqual(['listSecrets', 'putSecret']);
    expect(spec.operationCount).toBe(3);
  });

  it('reads the Citadel extensions and security', () => {
    const [list, put] = spec.groups[0].operations;
    expect(list.role).toBe('viewer');
    expect(list.audit).toEqual([]);
    expect(put.audit).toEqual(['citadel.PutItem']);
    expect(put.requestBody[0]).toMatchObject({ contentType: 'application/json', required: true });
    expect(list.authenticated).toBe(true);
    expect(spec.groups[1].operations[0].authenticated).toBe(false);
  });

  it('resolves component responses', () => {
    const unauthorized = spec.groups[0].operations[0].responses.find((r) => r.status === '401')!;
    expect(unauthorized).toMatchObject({ ref: 'Unauthorized', description: 'Not signed in' });
    expect(unauthorized.bodies[0].schema).toEqual({ $ref: '#/components/schemas/Error' });
  });

  it('filters on every term', () => {
    expect(filterGroups(spec.groups, 'secrets put').flatMap((g) => g.operations.map((o) => o.id))).toEqual(['putSecret']);
    expect(filterGroups(spec.groups, 'citadel.PutItem')[0].operations).toHaveLength(1);
    expect(filterGroups(spec.groups, 'nothing-like-this')).toEqual([]);
    expect(filterGroups(spec.groups, '')).toHaveLength(2);
  });

  it('labels types and knows what can expand', () => {
    expect(refName('#/components/schemas/SecretItem')).toBe('SecretItem');
    expect(typeLabel({ $ref: '#/components/schemas/SecretItem' })).toBe('SecretItem');
    expect(typeLabel({ type: 'array', items: { $ref: '#/components/schemas/SecretItem' } })).toBe('SecretItem[]');
    expect(typeLabel({ type: 'string', format: 'date-time' })).toBe('string (date-time)');
    expect(typeLabel(null)).toBe('any');
    expect(expandable({ $ref: '#/components/schemas/SecretListing' }, spec.schemas)).toBe(true);
    expect(expandable({ type: 'string' }, spec.schemas)).toBe(false);
  });

  it('rejects a document without paths', () => {
    expect(() => parseSpec('openapi: 3.1.0\n')).toThrow();
  });
});

// The real document, once the repository has it: it must parse with the
// console's YAML subset parser and expose the operations the console uses.
const real = resolve(__dirname, '../../../../docs/openapi.yaml');
describe.runIf(existsSync(real))('docs/openapi.yaml', () => {
  it('parses and lists the core operations', () => {
    const spec = parseSpec(readFileSync(real, 'utf8'));
    const ids = spec.groups.flatMap((g) => g.operations.map((o) => o.id));
    expect(ids).toEqual(expect.arrayContaining(['listSecrets', 'putSecret', 'getSecretValue', 'getOpenAPISpec']));
    expect(new Set(ids).size).toBe(ids.length);
    for (const g of spec.groups) for (const o of g.operations) expect(o.role, `${o.method} ${o.path}`).not.toBe('');
  });
});
