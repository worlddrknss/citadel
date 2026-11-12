import { beforeEach, describe, expect, it, vi } from 'vitest';

const nav = vi.hoisted(() => ({
  page: { url: new URL('http://localhost/app/secrets?tab=all&q=db') },
  goto: vi.fn(async () => {})
}));

vi.mock('$app/navigation', () => ({ goto: nav.goto }));
vi.mock('$app/state', () => ({ page: nav.page }));

import { param, setParams } from './url';

beforeEach(() => {
  nav.page.url = new URL('http://localhost/app/secrets?tab=all&q=db');
  nav.goto.mockClear();
});

describe('param', () => {
  it('reads a query parameter or the fallback', () => {
    expect(param('tab')).toBe('all');
    expect(param('missing')).toBe('');
    expect(param('missing', 'x')).toBe('x');
  });
});

describe('setParams', () => {
  it('sets and removes parameters, replacing history by default', () => {
    setParams({ tab: 'keys', q: '', page: '2', gone: null, also: undefined });
    expect(nav.goto).toHaveBeenCalledTimes(1);
    const [url, opts] = nav.goto.mock.calls[0] as unknown as [URL, Record<string, boolean>];
    expect(url.pathname).toBe('/app/secrets');
    expect(Object.fromEntries(url.searchParams)).toEqual({ tab: 'keys', page: '2' });
    expect(opts).toEqual({ replaceState: true, keepFocus: true, noScroll: true });
  });

  it('pushes a history entry when asked', () => {
    setParams({ path: '/db' }, { push: true });
    const [url, opts] = nav.goto.mock.calls[0] as unknown as [URL, Record<string, boolean>];
    expect(url.searchParams.get('path')).toBe('/db');
    expect(opts.replaceState).toBe(false);
  });

  it('does nothing when the query would not change', () => {
    expect(setParams({ tab: 'all', missing: '' })).toBeUndefined();
    expect(nav.goto).not.toHaveBeenCalled();
  });

  it('does not mutate the current page URL', () => {
    setParams({ tab: 'other' });
    expect(nav.page.url.searchParams.get('tab')).toBe('all');
  });
});
