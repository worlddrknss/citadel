/** Command-line and environment handling for `citadel mcp`. */

export const DEFAULT_TOKEN_ENV = 'CITADEL_AGENT_TOKEN';

export const USAGE = `Usage: citadel mcp [--url <url>] [--token-env <name>]

Bridges an MCP client that speaks stdio to Citadel's MCP endpoint
(<url>/mcp, Streamable HTTP). JSON-RPC messages are read from stdin and the
replies written to stdout, one per line; diagnostics go to stderr.

Options:
  --url <url>          Citadel's base URL (default: $CITADEL_URL)
  --token-env <name>   environment variable holding the agent token
                       (default: ${DEFAULT_TOKEN_ENV})
  -h, --help           show this help

Environment:
  CITADEL_URL          Citadel's base URL, e.g. https://citadel.example.com
  ${DEFAULT_TOKEN_ENV}  the agent token (cagt_...)
  CITADEL_CA_FILE      PEM file with an extra CA to trust (for a private CA);
                       passed to Node as NODE_EXTRA_CA_CERTS

The token is read only from the environment, never from the command line.`;

export interface BridgeConfig {
  /** The MCP endpoint, `<base>/mcp`. */
  endpoint: string;
  token: string;
  tokenEnv: string;
}

export type ParsedArgs =
  | { kind: 'help' }
  | { kind: 'error'; message: string }
  | { kind: 'run'; config: BridgeConfig };

/** A plausible environment variable name. */
const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;

/**
 * Parses the arguments after `mcp` and resolves the configuration from the
 * environment. Error messages never contain the token.
 */
export function parseMcpArgs(argv: readonly string[], env: Readonly<Record<string, string | undefined>>): ParsedArgs {
  let url: string | undefined;
  let tokenEnv = DEFAULT_TOKEN_ENV;
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    const eq = arg.indexOf('=');
    const name = arg.startsWith('--') && eq > 0 ? arg.slice(0, eq) : arg;
    const inline = arg.startsWith('--') && eq > 0 ? arg.slice(eq + 1) : undefined;
    const value = (): string | undefined => {
      if (inline !== undefined) return inline;
      const next = argv[i + 1];
      if (next === undefined || next.startsWith('--')) return undefined;
      i++;
      return next;
    };
    switch (name) {
      case '-h':
      case '--help':
        return { kind: 'help' };
      case '--url': {
        const v = value();
        if (!v) return { kind: 'error', message: '--url needs a value' };
        url = v;
        break;
      }
      case '--token-env': {
        const v = value();
        if (!v || !ENV_NAME.test(v)) return { kind: 'error', message: '--token-env needs an environment variable name' };
        tokenEnv = v;
        break;
      }
      case '--token':
        return {
          kind: 'error',
          message: `--token is not supported: command lines are visible to other processes. Put the token in ${DEFAULT_TOKEN_ENV} (or the variable named by --token-env)`,
        };
      default:
        return { kind: 'error', message: `unknown argument: ${name.startsWith('-') ? name : JSON.stringify(name)}` };
    }
  }

  url ??= env.CITADEL_URL;
  if (!url) return { kind: 'error', message: 'set CITADEL_URL or pass --url' };
  const endpoint = mcpEndpoint(url);
  if (typeof endpoint !== 'string') return { kind: 'error', message: endpoint.error };

  const token = env[tokenEnv]?.trim();
  if (!token) return { kind: 'error', message: `${tokenEnv} is not set; it must hold the agent token` };
  return { kind: 'run', config: { endpoint, token, tokenEnv } };
}

/**
 * Turns Citadel's base URL into its MCP endpoint. Plain http is accepted only
 * for loopback addresses, so the token never crosses a network unencrypted.
 */
export function mcpEndpoint(base: string): string | { error: string } {
  let u: URL;
  try {
    u = new URL(base);
  } catch {
    return { error: 'the Citadel URL is not a valid URL' };
  }
  if (u.username || u.password) return { error: 'the Citadel URL must not contain credentials' };
  if (u.protocol !== 'https:' && u.protocol !== 'http:') return { error: 'the Citadel URL must use https' };
  if (u.protocol === 'http:' && !isLoopback(u.hostname)) {
    return { error: 'the Citadel URL must use https (plain http is allowed only for localhost)' };
  }
  u.search = '';
  u.hash = '';
  let path = u.pathname.replace(/\/+$/, '');
  if (!path.endsWith('/mcp')) path += '/mcp';
  u.pathname = path;
  return u.toString();
}

function isLoopback(host: string): boolean {
  const h = host.replace(/^\[|\]$/g, '').toLowerCase();
  return h === 'localhost' || h.endsWith('.localhost') || h === '::1' || /^127\.\d+\.\d+\.\d+$/.test(h);
}

/** Splits a stream of text chunks into lines (without the line endings). */
export async function* lines(chunks: AsyncIterable<Uint8Array | string>): AsyncGenerator<string> {
  const decoder = new TextDecoder();
  let buffer = '';
  for await (const chunk of chunks) {
    buffer += typeof chunk === 'string' ? chunk : decoder.decode(chunk, { stream: true });
    let nl: number;
    while ((nl = buffer.indexOf('\n')) >= 0) {
      yield buffer.slice(0, nl).replace(/\r$/, '');
      buffer = buffer.slice(nl + 1);
    }
  }
  buffer += decoder.decode();
  if (buffer !== '') yield buffer.replace(/\r$/, '');
}
