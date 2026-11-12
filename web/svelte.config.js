import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import adapter from '@sveltejs/adapter-static';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

// app.html has one inline script (applies the saved theme before first
// paint). SvelteKit only hashes its own scripts, so hash this one here and
// add it to script-src; it stays correct whenever the script is edited.
const appHtml = readFileSync(new URL('./src/app.html', import.meta.url), 'utf8');
const themeScript = appHtml.match(/<script>([\s\S]*?)<\/script>/)?.[1];
const themeHash = themeScript ? [`sha256-${createHash('sha256').update(themeScript).digest('base64')}`] : [];

/** @type {import('@sveltejs/kit').Config} */
const config = {
  preprocess: vitePreprocess(),
  kit: {
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
  }
};

export default config;
