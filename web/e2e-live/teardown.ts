import { execFileSync } from 'node:child_process';

// start-server.sh removes its database container when Playwright stops it;
// this is the backstop for a hard kill. A no-op in CI (service container).
export default function teardown() {
  if (process.env.CITADEL_LIVE_DB_URL) return;
  try {
    execFileSync('docker', ['rm', '-f', `citadel-e2e-live-pg-${process.env.CITADEL_LIVE_PG_PORT ?? 55508}`], { stdio: 'ignore' });
  } catch {
    /* already gone */
  }
}
