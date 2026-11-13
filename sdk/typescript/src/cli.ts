#!/usr/bin/env node
/**
 * `citadel` command-line entry point (package.json "bin").
 *
 *   npx @worlddrknss/citadel mcp
 *
 * Only protocol messages go to stdout; everything else goes to stderr.
 */
import { McpBridge } from './mcp/bridge.js';
import { lines, parseMcpArgs, USAGE } from './mcp/config.js';
import { VERSION } from './version.js';

// The library is typed without Node's globals (it also runs on edge
// runtimes), so describe the little of `process` this file uses.
interface NodeStream {
  write(chunk: string, cb?: (err?: Error | null) => void): boolean;
}
interface NodeProcess {
  argv: string[];
  execArgv: string[];
  execPath: string;
  env: Record<string, string | undefined>;
  exitCode?: number;
  stdin: AsyncIterable<Uint8Array>;
  stdout: NodeStream;
  stderr: NodeStream;
  on(event: string, listener: (...args: unknown[]) => void): void;
  exit(code: number): never;
}
interface ChildProcess {
  on(event: 'exit', listener: (code: number | null, signal: string | null) => void): void;
  on(event: 'error', listener: (err: Error) => void): void;
  kill(signal: string): void;
}

const proc = (globalThis as unknown as { process: NodeProcess }).process;

function warn(message: string) {
  proc.stderr.write(`citadel: ${message}\n`);
}

/** Loads a Node built-in without needing Node's type declarations. */
function builtin<T>(name: string): Promise<T> {
  const specifier = `node:${name}`;
  return import(specifier) as Promise<T>;
}

function writeStdout(line: string): Promise<void> {
  return new Promise((resolve, reject) => {
    proc.stdout.write(`${line}\n`, (err) => (err ? reject(err) : resolve()));
  });
}

/**
 * Node reads NODE_EXTRA_CA_CERTS only at startup, so when CITADEL_CA_FILE
 * names a CA that isn't loaded yet, run this command again with it set. TLS
 * verification stays on; the CA is added to Node's trust store.
 */
async function reexecWithCa(caFile: string): Promise<boolean> {
  if (proc.env.NODE_EXTRA_CA_CERTS === caFile) return false;
  const fs = await builtin<{ accessSync(path: string): void }>('fs');
  try {
    fs.accessSync(caFile);
  } catch {
    warn('CITADEL_CA_FILE does not name a readable file');
    proc.exitCode = 2;
    return true;
  }
  const cp = await builtin<{
    spawn(cmd: string, args: string[], opts: { stdio: 'inherit'; env: Record<string, string | undefined> }): ChildProcess;
  }>('child_process');
  const child = cp.spawn(proc.execPath, [...proc.execArgv, ...proc.argv.slice(1)], {
    stdio: 'inherit',
    env: { ...proc.env, NODE_EXTRA_CA_CERTS: caFile },
  });
  for (const sig of ['SIGINT', 'SIGTERM', 'SIGHUP']) {
    proc.on(sig, () => child.kill(sig));
  }
  await new Promise<void>((resolve) => {
    child.on('error', (err) => {
      warn(`cannot start node: ${err.message}`);
      proc.exitCode = 1;
      resolve();
    });
    child.on('exit', (code, signal) => {
      proc.exitCode = code ?? (signal ? 1 : 0);
      resolve();
    });
  });
  return true;
}

async function runMcp(args: string[]) {
  const parsed = parseMcpArgs(args, proc.env);
  if (parsed.kind === 'help') {
    proc.stderr.write(`${USAGE}\n`);
    return;
  }
  if (parsed.kind === 'error') {
    warn(parsed.message);
    warn('run `citadel mcp --help` for usage');
    proc.exitCode = 2;
    return;
  }
  const caFile = proc.env.CITADEL_CA_FILE;
  if (caFile && (await reexecWithCa(caFile))) return;

  const bridge = new McpBridge({
    endpoint: parsed.config.endpoint,
    token: parsed.config.token,
    write: writeStdout,
    log: warn,
    userAgent: `citadel-mcp-bridge/${VERSION}`,
  });

  let stopping = false;
  const stop = async () => {
    if (stopping) return;
    stopping = true;
    await bridge.close();
  };
  for (const sig of ['SIGINT', 'SIGTERM', 'SIGHUP']) {
    proc.on(sig, () => {
      // Don't wait for stdin, which may never close.
      void stop().finally(() => proc.exit(0));
    });
  }

  for await (const line of lines(proc.stdin)) {
    if (stopping) break;
    // Not awaited: requests run concurrently (bridge orders initialize).
    bridge.handleLine(line).catch((err: unknown) => {
      warn(`cannot write to stdout: ${err instanceof Error ? err.message : 'unknown error'}`);
    });
  }
  // stdin closed: the client is gone. Answer what's in flight, end the session.
  await stop();
}

async function main() {
  const [command, ...rest] = proc.argv.slice(2);
  switch (command) {
    case 'mcp':
      await runMcp(rest);
      return;
    case undefined:
    case '-h':
    case '--help':
    case 'help':
      proc.stderr.write('Usage: citadel <command>\n\nCommands:\n  mcp   stdio bridge to Citadel\'s MCP server (citadel mcp --help)\n');
      if (command === undefined) proc.exitCode = 2;
      return;
    default:
      warn(`unknown command: ${JSON.stringify(command)}`);
      proc.exitCode = 2;
  }
}

main().catch((err: unknown) => {
  warn(`fatal: ${err instanceof Error ? err.message : 'unknown error'}`);
  proc.exitCode = 1;
});
