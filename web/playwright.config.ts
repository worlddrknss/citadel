import { defineConfig, devices } from '@playwright/test';

// Smoke tests against the built SPA served by `vite preview`. The Go server
// is not needed: every /v1 call is answered by route interception in
// e2e/mock.ts.
const PORT = Number(process.env.CITADEL_E2E_PORT ?? 4173);

export default defineConfig({
  testDir: 'e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: process.env.CI ? 2 : undefined,
  reporter: process.env.CI ? [['list'], ['html', { open: 'never' }]] : [['list']],
  use: {
    baseURL: `http://localhost:${PORT}`,
    trace: 'retain-on-failure',
    timezoneId: 'America/New_York',
    locale: 'en-US'
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: `npm run build && npm run preview -- --port ${PORT} --strictPort`,
    url: `http://localhost:${PORT}/app/`,
    reuseExistingServer: !process.env.CI,
    timeout: 180_000
  }
});
