// The SPA's base path ('/app', no trailing slash). SvelteKit 3 dropped `base`
// from $app/paths in favour of resolve(); the console builds most links by
// prefixing `base`, so derive the same value from resolve() here.

import { resolve } from '$app/paths';

export const base = resolve('/').replace(/\/$/, '');
