// Builds and runs the real Citadel server (cmd/server) for integration tests.
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, openSync, readFileSync, rmSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');

export function goAvailable(): boolean {
  if (process.env.CITADEL_SDK_SKIP_INTEGRATION === '1') return false;
  return spawnSync('go', ['version'], { stdio: 'ignore' }).status === 0;
}

let built: { dir: string; bin: string } | undefined;

function buildServer(): string {
  if (built) return built.bin;
  const dir = mkdtempSync(join(tmpdir(), 'citadel-sdk-ts-'));
  const bin = join(dir, process.platform === 'win32' ? 'citadel.exe' : 'citadel');
  const res = spawnSync('go', ['build', '-o', bin, './cmd/server'], {
    cwd: repoRoot,
    env: { ...process.env, GOFIPS140: 'latest' },
    encoding: 'utf8',
  });
  if (res.status !== 0) throw new Error(`go build failed:\n${res.stderr}`);
  built = { dir, bin };
  return bin;
}

function freePort(): Promise<number> {
  return new Promise((resolvePort, reject) => {
    const srv = createServer();
    srv.once('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const addr = srv.address();
      srv.close(() => (typeof addr === 'object' && addr ? resolvePort(addr.port) : reject(new Error('no port'))));
    });
  });
}

export interface RunningServer {
  url: string;
  stop(): Promise<void>;
  log(): string;
}

/** Starts a server with the given extra environment and waits until healthy. */
export async function startServer(extraEnv: Record<string, string>): Promise<RunningServer> {
  const bin = buildServer();
  const port = await freePort();
  const url = `http://127.0.0.1:${port}`;
  const logPath = join(built!.dir, `server-${port}.log`);
  const out = openSync(logPath, 'w');
  const env: Record<string, string> = {
    PATH: process.env.PATH ?? '',
    HOME: process.env.HOME ?? '',
    KMS_LISTEN_ADDR: `127.0.0.1:${port}`,
    KMS_PUBLIC_URL: url,
    KMS_UI_SECURE_COOKIES: 'false',
    KMS_LOG_FORMAT: 'text',
    GODEBUG: 'fips140=only',
    ...extraEnv,
  };
  const child: ChildProcess = spawn(bin, [], { env, stdio: ['ignore', out, out] });
  const log = () => {
    try {
      return readFileSync(logPath, 'utf8');
    } catch {
      return '';
    }
  };
  const deadline = Date.now() + 30_000;
  for (;;) {
    if (child.exitCode !== null) throw new Error(`citadel exited (${child.exitCode}):\n${log()}`);
    try {
      const res = await fetch(`${url}/healthz`);
      if (res.ok) break;
    } catch {
      // not listening yet
    }
    if (Date.now() > deadline) {
      child.kill();
      throw new Error(`citadel did not become healthy:\n${log()}`);
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  return {
    url,
    log,
    stop: () =>
      new Promise<void>((done) => {
        if (child.exitCode !== null) return done();
        child.once('exit', () => done());
        child.kill('SIGTERM');
      }),
  };
}

export function randomKeyB64(): string {
  return randomBytes(32).toString('base64');
}

export function cleanupBuild(): void {
  if (built) rmSync(built.dir, { recursive: true, force: true });
  built = undefined;
}
