// A small parser for the YAML subset Citadel's OpenAPI document is written in
// (docs/openapi.yaml), so the console can render the API reference without a
// YAML dependency. Supported: block mappings and sequences (2-space indents,
// `- key: value` items), plain, double-quoted and single-quoted scalars (plain
// ints, floats, booleans and null are typed), flow `[]`, `{}` and one-line
// lists of scalars like `[a, "b"]`, `|` / `|-` literal blocks, and full-line
// comments. Anchors, aliases, tags, `>` folding and multi-line flow
// collections are not supported and raise a YamlError.

export type YamlValue = string | number | boolean | null | YamlValue[] | { [key: string]: YamlValue };

export class YamlError extends Error {
  constructor(message: string, line: number) {
    super(`line ${line}: ${message}`);
    this.name = 'YamlError';
  }
}

interface Line {
  /** 1-based line number in the source. */
  no: number;
  indent: number;
  text: string;
}

export function parseYaml(src: string): YamlValue {
  const raw = src.replace(/\r\n?/g, '\n').split('\n');
  return new Parser(raw).parseDocument();
}

class Parser {
  private lines: (Line | null)[];
  private i = 0;

  constructor(private raw: string[]) {
    // Pre-scan: null marks lines that are blank or comments (they still
    // matter inside literal blocks, which read `raw` directly).
    this.lines = raw.map((t, idx) => {
      if (/^\s*$/.test(t) || /^\s*#/.test(t) || t === '---') return null;
      const m = /^( *)(.*)$/.exec(t)!;
      if (m[2].startsWith('\t')) throw new YamlError('tabs are not allowed for indentation', idx + 1);
      return { no: idx + 1, indent: m[1].length, text: m[2].replace(/\s+$/, '') };
    });
  }

  parseDocument(): YamlValue {
    const first = this.peek();
    if (!first) return null;
    const v = this.parseNode(first.indent);
    const rest = this.peek();
    if (rest) throw new YamlError('unexpected content', rest.no);
    return v;
  }

  /** Next significant line, skipping blanks and comments. */
  private peek(): Line | null {
    while (this.i < this.lines.length && this.lines[this.i] === null) this.i++;
    return this.i < this.lines.length ? this.lines[this.i] : null;
  }

  private parseNode(indent: number): YamlValue {
    const line = this.peek()!;
    return isSeqItem(line.text) ? this.parseSequence(indent) : this.parseMapping(indent);
  }

  private parseMapping(indent: number): YamlValue {
    const out: { [key: string]: YamlValue } = {};
    for (let line = this.peek(); line && line.indent === indent && !isSeqItem(line.text); line = this.peek()) {
      const { key, rest } = splitKey(line);
      if (Object.prototype.hasOwnProperty.call(out, key)) throw new YamlError(`duplicate key "${key}"`, line.no);
      this.i++;
      out[key] = this.parseValue(rest, indent, line, true);
    }
    const line = this.peek();
    if (line && line.indent > indent) throw new YamlError('bad indentation', line.no);
    return out;
  }

  private parseSequence(indent: number): YamlValue {
    const out: YamlValue[] = [];
    for (let line = this.peek(); line && line.indent === indent && isSeqItem(line.text); line = this.peek()) {
      const content = line.text === '-' ? '' : line.text.slice(2).replace(/^ +/, '');
      if (content !== '' && looksLikeKey(content)) {
        // `- key: value`: re-read the line as the first entry of a mapping
        // indented past the dash.
        const inner = line.indent + (line.text.length - content.length);
        this.lines[this.i] = { no: line.no, indent: inner, text: content };
        out.push(this.parseMapping(inner));
        continue;
      }
      this.i++;
      out.push(this.parseValue(content, indent, line, false));
    }
    const line = this.peek();
    if (line && line.indent > indent) throw new YamlError('bad indentation', line.no);
    return out;
  }

  /** The value after `key:` or `- `; empty means a nested block (or null). */
  private parseValue(rest: string, indent: number, line: Line, inMapping: boolean): YamlValue {
    if (rest === '') {
      const next = this.peek();
      if (next && next.indent > indent) return this.parseNode(next.indent);
      // A sequence may sit at its parent key's indentation.
      if (inMapping && next && next.indent === indent && isSeqItem(next.text)) return this.parseSequence(indent);
      return null;
    }
    if (rest === '|' || rest === '|-' || rest === '|+') return this.parseLiteral(rest, indent);
    if (rest.startsWith('>')) throw new YamlError('folded scalars (>) are not supported', line.no);
    return parseInline(rest, line.no);
  }

  private parseLiteral(header: string, indent: number): string {
    const body: string[] = [];
    let blockIndent = -1;
    let j = this.i;
    for (; j < this.raw.length; j++) {
      const t = this.raw[j];
      if (/^\s*$/.test(t)) {
        body.push('');
        continue;
      }
      const ind = /^ */.exec(t)![0].length;
      if (ind <= indent) break;
      if (blockIndent < 0) blockIndent = ind;
      if (ind < blockIndent) break;
      body.push(t.slice(blockIndent));
    }
    // Trailing blank lines belong to the chomping indicator, not to the
    // content; they also aren't consumed so the next node starts after them.
    let end = body.length;
    while (end > 0 && body[end - 1] === '') end--;
    const consumed = j - (body.length - end);
    this.i = consumed;
    const text = body.slice(0, end).join('\n');
    if (header === '|-') return text;
    if (header === '|+') return text + '\n'.repeat(body.length - end + 1);
    return text === '' ? '' : text + '\n';
  }
}

function isSeqItem(text: string): boolean {
  return text === '-' || text.startsWith('- ');
}

/** Whether a sequence item's content is `key: value` / `key:`. */
function looksLikeKey(content: string): boolean {
  if (content.startsWith('"') || content.startsWith("'")) {
    const end = quotedEnd(content);
    return end > 0 && /^:( |$)/.test(content.slice(end));
  }
  if (content.startsWith('[') || content.startsWith('{')) return false;
  return /^[^\s#][^:]*?:( |$)/.test(content);
}

function splitKey(line: Line): { key: string; rest: string } {
  const t = line.text;
  if (t.startsWith('"') || t.startsWith("'")) {
    const end = quotedEnd(t);
    if (end < 0 || !/^:( |$)/.test(t.slice(end))) throw new YamlError('expected "key: value"', line.no);
    return { key: String(parseQuoted(t.slice(0, end), line.no)), rest: t.slice(end + 1).trim() };
  }
  const m = /^([^:]+?):( +(.*))?$/.exec(t);
  if (!m) throw new YamlError('expected "key: value"', line.no);
  return { key: m[1], rest: (m[3] ?? '').trim() };
}

/** Index just past the closing quote of a quoted scalar at the start of s, or -1. */
function quotedEnd(s: string): number {
  const q = s[0];
  for (let k = 1; k < s.length; k++) {
    if (q === '"' && s[k] === '\\') {
      k++;
      continue;
    }
    if (s[k] === q) {
      if (q === "'" && s[k + 1] === "'") {
        k++;
        continue;
      }
      return k + 1;
    }
  }
  return -1;
}

function parseQuoted(s: string, no: number): string {
  if (s.startsWith("'")) return s.slice(1, -1).replace(/''/g, "'");
  try {
    return JSON.parse(s.replace(/\\\//g, '/')) as string;
  } catch {
    throw new YamlError('bad escape in double-quoted string', no);
  }
}

function parseInline(s: string, no: number): YamlValue {
  if (s.startsWith('"') || s.startsWith("'")) {
    const end = quotedEnd(s);
    if (end !== s.length) throw new YamlError('unterminated or trailing text after quoted string', no);
    return parseQuoted(s, no);
  }
  if (s === '{}') return {};
  if (s.startsWith('{')) throw new YamlError('only empty flow mappings ({}) are supported', no);
  if (s.startsWith('[')) {
    if (!s.endsWith(']')) throw new YamlError('flow sequences must close on the same line', no);
    const inner = s.slice(1, -1).trim();
    if (inner === '') return [];
    return splitFlow(inner, no).map((item) => {
      if (item.startsWith('[') || item.startsWith('{')) throw new YamlError('nested flow collections are not supported', no);
      return parseInline(item, no);
    });
  }
  if (/^[&*!%@`|>]/.test(s)) throw new YamlError(`unsupported YAML syntax "${s[0]}"`, no);
  return plainScalar(s);
}

function splitFlow(inner: string, no: number): string[] {
  const items: string[] = [];
  let k = 0;
  while (k < inner.length) {
    while (inner[k] === ' ') k++;
    let item: string;
    if (inner[k] === '"' || inner[k] === "'") {
      const end = quotedEnd(inner.slice(k));
      if (end < 0) throw new YamlError('unterminated string in flow sequence', no);
      item = inner.slice(k, k + end);
      k += end;
      while (inner[k] === ' ') k++;
      if (k < inner.length && inner[k] !== ',') throw new YamlError('expected "," in flow sequence', no);
    } else {
      const comma = inner.indexOf(',', k);
      const stop = comma < 0 ? inner.length : comma;
      item = inner.slice(k, stop).trim();
      k = stop;
    }
    if (item === '') throw new YamlError('empty item in flow sequence', no);
    items.push(item);
    k++; // past the comma
  }
  return items;
}

function plainScalar(s: string): YamlValue {
  if (s === 'null' || s === '~' || s === 'Null' || s === 'NULL') return null;
  if (s === 'true' || s === 'True' || s === 'TRUE') return true;
  if (s === 'false' || s === 'False' || s === 'FALSE') return false;
  if (/^[-+]?\d+$/.test(s)) return Number(s);
  if (/^[-+]?(\d+\.\d*|\.\d+)([eE][-+]?\d+)?$/.test(s)) return Number(s);
  return s;
}
