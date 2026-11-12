// URL-backed view state: folder paths, selected items, tabs and filters live
// in the query string so a refresh or a shared link lands in the same place.

import { goto } from '$app/navigation';
import { page } from '$app/state';

/** Reads a query parameter (reactive when used inside $derived/markup). */
export function param(name: string, fallback = ''): string {
  return page.url.searchParams.get(name) ?? fallback;
}

/**
 * Updates query parameters in place. `null`, `undefined` and `''` remove a
 * parameter. History entries are replaced by default so filters and drawers
 * don't flood the back button; pass `push: true` for real navigation steps
 * such as entering a folder.
 */
export function setParams(updates: Record<string, string | null | undefined>, opts: { push?: boolean } = {}) {
  const url = new URL(page.url);
  for (const [k, v] of Object.entries(updates)) {
    if (v === null || v === undefined || v === '') url.searchParams.delete(k);
    else url.searchParams.set(k, v);
  }
  if (url.search === page.url.search) return;
  return goto(url, { replaceState: !opts.push, keepFocus: true, noScroll: true });
}
