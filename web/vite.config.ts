import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';

export default defineConfig({
  plugins: [sveltekit()],
  server: {
    // During development the SPA runs on Vite (:5173) and proxies API calls to
    // the Go server (:8080) so we keep a single-origin model in production.
    proxy: {
      '/v1': 'http://localhost:8080',
      '/api': 'http://localhost:8080',
      '/login': 'http://localhost:8080',
      '/logout': 'http://localhost:8080'
    }
  }
});
