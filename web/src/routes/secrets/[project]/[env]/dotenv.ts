// Minimal .env reader/writer for Import .env / Export.

export interface EnvEntry {
  key: string;
  value: string;
  line: number;
}

/**
 * Parses KEY=VALUE lines. Supports `export ` prefixes, # comments, single
 * quotes (literal), double quotes (with \n, \t, \", \\ escapes, may span
 * lines) and unquoted values with trailing " # comments". A key that appears
 * more than once keeps its last value (as when a shell sources the file) and
 * is listed in `duplicates`.
 */
export function parseDotenv(text: string): { entries: EnvEntry[]; errors: number[]; duplicates: string[] } {
  const entries: EnvEntry[] = [];
  const errors: number[] = [];
  const lines = text.replace(/\r\n?/g, '\n').split('\n');
  for (let i = 0; i < lines.length; i++) {
    const lineNo = i + 1;
    let line = lines[i].trim();
    if (!line || line.startsWith('#')) continue;
    if (line.startsWith('export ')) line = line.slice(7).trimStart();
    const eq = line.indexOf('=');
    if (eq <= 0) {
      errors.push(lineNo);
      continue;
    }
    const key = line.slice(0, eq).trim();
    const raw = line.slice(eq + 1);
    const rest = raw.trimStart();
    let value: string;
    if (rest.startsWith('"')) {
      let body = rest.slice(1);
      // Keep reading lines until the closing unescaped quote.
      while (!/(^|[^\\])(\\\\)*"/.test(body) && i + 1 < lines.length) {
        i++;
        body += '\n' + lines[i];
      }
      const m = body.match(/^((?:[^"\\]|\\.)*)"/s);
      if (!m) {
        errors.push(lineNo);
        continue;
      }
      value = m[1].replace(/\\(.)/g, (_, c: string) => (c === 'n' ? '\n' : c === 't' ? '\t' : c === 'r' ? '\r' : c));
    } else if (rest.startsWith("'")) {
      const end = rest.indexOf("'", 1);
      if (end < 0) {
        errors.push(lineNo);
        continue;
      }
      value = rest.slice(1, end);
    } else {
      // Search before trimming so "KEY= # note" is empty, not "# note".
      const hash = raw.search(/\s#/);
      value = (hash >= 0 ? raw.slice(0, hash) : raw).trim();
    }
    entries.push({ key, value, line: lineNo });
  }
  const last = new Map(entries.map((e, i) => [e.key, i]));
  const duplicates = [...new Set(entries.filter((e, i) => last.get(e.key) !== i).map((e) => e.key))];
  return { entries: entries.filter((e, i) => last.get(e.key) === i), errors, duplicates };
}

/** Serializes entries, quoting values that need it. */
export function toDotenv(entries: { key: string; value: string }[]): string {
  return (
    entries
      .map(({ key, value }) => {
        if (/^[A-Za-z0-9_./:@+-]*$/.test(value)) return `${key}=${value}`;
        const esc = value.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n').replace(/\r/g, '\\r');
        return `${key}="${esc}"`;
      })
      .join('\n') + '\n'
  );
}
