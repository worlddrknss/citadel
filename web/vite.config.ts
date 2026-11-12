import { sveltekit } from '@sveltejs/kit/vite';
import { svelteTesting } from '@testing-library/svelte/vite';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  plugins: [sveltekit(), svelteTesting()],
  server: {
    // During development the SPA runs on Vite (:5173) and proxies API calls to
    // the Go server (:8080) so we keep a single-origin model in production.
    proxy: {
      '/v1': 'http://localhost:8080',
      '/api': 'http://localhost:8080',
      '/login': 'http://localhost:8080',
      '/logout': 'http://localhost:8080'
    }
  },
  test: {
    // A non-UTC default zone, so date code is exercised the way users see it.
    // Set here rather than in the npm script so it works on Windows too.
    env: { TZ: 'America/New_York' },
    include: ['src/**/*.test.ts'],
    environment: 'jsdom',
    setupFiles: ['./src/test-setup.ts'],
    // Separate processes, so a test can change process.env.TZ and have Date
    // follow it (worker threads don't re-read TZ).
    pool: 'forks'
  }
});
