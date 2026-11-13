import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import adapter from '@sveltejs/adapter-static';
import { sveltekit } from '@sveltejs/kit/vite';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';
import { svelteTesting } from '@testing-library/svelte/vite';
import { defineConfig } from 'vitest/config';

// app.html has one inline script (applies the saved theme before first
// paint). SvelteKit only hashes its own scripts, so hash this one here and
// add it to script-src; it stays correct whenever the script is edited.
const appHtml = readFileSync(new URL('./src/app.html', import.meta.url), 'utf8');
const themeScript = appHtml.match(/<script>([\s\S]*?)<\/script>/i)?.[1];
const themeHash: `sha256-${string}`[] = themeScript ? [`sha256-${createHash('sha256').update(themeScript).digest('base64')}`] : [];

export default defineConfig({
  plugins: [
    // SvelteKit 3 takes its configuration here (svelte.config.js is gone).
    sveltekit({
      preprocess: vitePreprocess(),
      // Static SPA: a single index.html fallback drives client-side routing.
      adapter: adapter({ fallback: 'index.html', strict: false }),
      // The Go server mounts the SPA under /app/.
      paths: { base: '/app' },
      // Emits a CSP <meta> with hashes of SvelteKit's inline bootstrap script.
      // The Go server also sends a matching header CSP (it hashes the inline
      // scripts of the page it serves) carrying frame-ancestors, which a meta
      // policy cannot. Svelte transitions inject styles, hence 'unsafe-inline'
      // for style-src only.
      csp: {
        mode: 'hash',
        directives: {
          'default-src': ['self'],
          'script-src': ['self', ...themeHash],
          'style-src': ['self', 'unsafe-inline'],
          'img-src': ['self', 'data:'],
          'font-src': ['self', 'data:'],
          'connect-src': ['self'],
          'object-src': ['none'],
          'base-uri': ['self'],
          'form-action': ['self']
        }
      }
    }),
    svelteTesting()
  ],
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
