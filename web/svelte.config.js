import adapter from '@sveltejs/adapter-static';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

/** @type {import('@sveltejs/kit').Config} */
const config = {
  preprocess: vitePreprocess(),
  kit: {
    // Static SPA: a single index.html fallback drives client-side routing.
    adapter: adapter({ fallback: 'index.html', strict: false }),
    // The Go server mounts the SPA under /app/.
    paths: { base: '/app' }
  }
};

export default config;
