import { defineConfig, devices } from '@playwright/test';

// Live end-to-end suite: the real Go server (with the console embedded)
// against a fresh PostgreSQL. Nothing is mocked. The spec files run in order
// in one worker and build on each other's data, starting with the first-run
// bootstrap, so a run always needs an empty database (start-server.sh makes
// one). See e2e/ for the fast mocked suite.
export const PORT = Number(process.env.CITADEL_LIVE_PORT ?? 18508);
export const BASE = `http://127.0.0.1:${PORT}`;

export default defineConfig({
  testDir: '.',
  testMatch: /\d\d-.*\.spec\.ts$/,
  fullyParallel: false,
  workers: 1,
  forbidOnly: !!process.env.CI,
  retries: 0,
  timeout: 60_000,
  expect: { timeout: 10_000 },
  reporter: process.env.CI ? [['list'], ['html', { open: 'never', outputFolder: '../playwright-report-live' }]] : [['list']],
  outputDir: '../test-results-live',
  globalTeardown: './teardown.ts',
  use: {
    baseURL: BASE,
    trace: 'retain-on-failure',
    timezoneId: 'America/New_York',
    locale: 'en-US',
    acceptDownloads: true
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: './e2e-live/start-server.sh',
    cwd: '..',
    url: `${BASE}/v1/bootstrap`,
    reuseExistingServer: false,
    timeout: 600_000,
    stdout: process.env.CITADEL_LIVE_SERVER_LOG ? 'pipe' : 'ignore',
    stderr: process.env.CITADEL_LIVE_SERVER_LOG ? 'pipe' : 'ignore'
  }
});
