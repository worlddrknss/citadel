// Turns the parsed OpenAPI document (docs/openapi.yaml, served at
// /v1/openapi.yaml) into what the API reference page renders: operations
// grouped by tag, $ref resolution and a text filter.

import { parseYaml, type YamlValue } from '#lib/yaml.ts';

export type Schema = { [key: string]: YamlValue };

export interface Parameter {
  name: string;
  in: string;
  required: boolean;
  description: string;
  schema: Schema | null;
}

export interface Body {
  contentType: string;
  schema: Schema | null;
}

export interface Response {
  status: string;
  description: string;
  /** The component response name when the response is a $ref. */
  ref: string;
  bodies: Body[];
}

export interface Operation {
  id: string;
  method: string;
  path: string;
  summary: string;
  description: string;
  tags: string[];
  role: string;
  audit: string[];
  /** False when the operation declares `security: []`. */
  authenticated: boolean;
  parameters: Parameter[];
  requestBody: (Body & { required: boolean })[];
  responses: Response[];
}

export interface TagGroup {
  name: string;
  description: string;
  operations: Operation[];
}

export interface ApiSpec {
  title: string;
  version: string;
  description: string;
  groups: TagGroup[];
  schemas: Record<string, Schema>;
  responses: Record<string, Schema>;
  operationCount: number;
}

const METHODS = ['get', 'post', 'put', 'patch', 'delete'] as const;

const isObj = (v: unknown): v is Schema => typeof v === 'object' && v !== null && !Array.isArray(v);
const str = (v: unknown): string => (typeof v === 'string' ? v : typeof v === 'number' ? String(v) : '');
const strList = (v: unknown): string[] => (Array.isArray(v) ? v.map(str).filter(Boolean) : str(v) ? [str(v)] : []);

/** The component name a "#/components/<kind>/<Name>" reference points at. */
export function refName(ref: unknown): string {
  const m = /^#\/components\/[^/]+\/(.+)$/.exec(str(ref));
  return m ? m[1] : '';
}

export function parseSpec(text: string): ApiSpec {
  const doc = parseYaml(text);
  if (!isObj(doc) || !isObj(doc.paths)) throw new Error('not an OpenAPI document');
  const info = isObj(doc.info) ? doc.info : {};
  const components = isObj(doc.components) ? doc.components : {};
  const schemas = (isObj(components.schemas) ? components.schemas : {}) as Record<string, Schema>;
  const compResponses = (isObj(components.responses) ? components.responses : {}) as Record<string, Schema>;
  const globalSecurity = Array.isArray(doc.security) ? doc.security : [];

  const ops: Operation[] = [];
  for (const [path, item] of Object.entries(doc.paths)) {
    if (!isObj(item)) continue;
    const shared = Array.isArray(item.parameters) ? item.parameters : [];
    for (const method of METHODS) {
      const op = item[method];
      if (!isObj(op)) continue;
      const security = Array.isArray(op.security) ? op.security : globalSecurity;
      ops.push({
        id: str(op.operationId),
        method: method.toUpperCase(),
        path,
        summary: str(op.summary),
        description: str(op.description).trim(),
        tags: strList(op.tags),
        role: str(op['x-citadel-role']),
        audit: strList(op['x-citadel-audit']),
        authenticated: security.length > 0,
        parameters: [...shared, ...(Array.isArray(op.parameters) ? op.parameters : [])].filter(isObj).map((p) => ({
          name: str(p.name),
          in: str(p.in),
          required: p.required === true,
          description: str(p.description).trim(),
          schema: isObj(p.schema) ? p.schema : null
        })),
        requestBody: isObj(op.requestBody) ? bodies(op.requestBody).map((b) => ({ ...b, required: (op.requestBody as Schema).required === true })) : [],
        responses: isObj(op.responses)
          ? Object.entries(op.responses)
              .filter(([, r]) => isObj(r))
              .map(([status, r]) => {
                const ref = refName((r as Schema).$ref);
                const resolved = ref && compResponses[ref] ? compResponses[ref] : (r as Schema);
                return { status, ref, description: str(resolved.description).trim(), bodies: bodies(resolved) };
              })
          : []
      });
    }
  }

  // Groups follow the document's tag order; tags it doesn't declare come
  // after, in order of first use, and untagged operations last.
  const declared = Array.isArray(doc.tags) ? doc.tags.filter(isObj) : [];
  const groups = new Map<string, TagGroup>();
  for (const t of declared) groups.set(str(t.name), { name: str(t.name), description: str(t.description).trim(), operations: [] });
  for (const op of ops) {
    const name = op.tags[0] ?? 'Other';
    if (!groups.has(name)) groups.set(name, { name, description: '', operations: [] });
    groups.get(name)!.operations.push(op);
  }
  return {
    title: str(info.title) || 'API',
    version: str(info.version),
    description: str(info.description).trim(),
    groups: [...groups.values()].filter((g) => g.operations.length > 0),
    schemas,
    responses: compResponses,
    operationCount: ops.length
  };
}

function bodies(holder: Schema): Body[] {
  if (!isObj(holder.content)) return [];
  return Object.entries(holder.content).map(([contentType, media]) => ({
    contentType,
    schema: isObj(media) && isObj(media.schema) ? media.schema : null
  }));
}

/** Whether op matches every whitespace-separated term of the filter. */
export function matches(op: Operation, filter: string): boolean {
  const terms = filter.toLowerCase().split(/\s+/).filter(Boolean);
  if (!terms.length) return true;
  const hay = [op.method, op.path, op.id, op.summary, op.description, op.role, ...op.tags, ...op.audit].join(' ').toLowerCase();
  return terms.every((t) => hay.includes(t));
}

export function filterGroups(groups: TagGroup[], filter: string): TagGroup[] {
  return groups.map((g) => ({ ...g, operations: g.operations.filter((o) => matches(o, filter)) })).filter((g) => g.operations.length > 0);
}

/** A short type label for a schema: "string (date-time)", "KmsKey[]", "object". */
export function typeLabel(schema: Schema | null | undefined): string {
  if (!schema) return 'any';
  const ref = refName(schema.$ref);
  if (ref) return ref;
  const t = Array.isArray(schema.type) ? schema.type.map(str).join(' | ') : str(schema.type);
  if (t === 'array') return `${typeLabel(isObj(schema.items) ? schema.items : null)}[]`;
  for (const k of ['oneOf', 'anyOf', 'allOf'] as const) {
    if (Array.isArray(schema[k])) return (schema[k] as YamlValue[]).map((s) => typeLabel(isObj(s) ? s : null)).join(k === 'allOf' ? ' & ' : ' | ');
  }
  if (!t && isObj(schema.properties)) return 'object';
  if (!t && isObj(schema.additionalProperties)) return 'object';
  const fmt = str(schema.format);
  return (t || 'any') + (fmt ? ` (${fmt})` : '');
}

/** Whether a schema has structure worth expanding. */
export function expandable(schema: Schema | null | undefined, components: Record<string, Schema>): boolean {
  if (!schema) return false;
  const ref = refName(schema.$ref);
  if (ref) return Boolean(components[ref]);
  if (isObj(schema.properties) && Object.keys(schema.properties).length) return true;
  if (isObj(schema.additionalProperties)) return true;
  if (isObj(schema.items)) return expandable(schema.items, components);
  return ['oneOf', 'anyOf', 'allOf'].some((k) => Array.isArray(schema[k]));
}

export { isObj, str, strList };
