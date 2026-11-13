import { describe, expect, it } from 'vitest';
import type { LEOrder } from '#lib/api.ts';
import { waitForLEOrder } from './api';

const order = (status: LEOrder['status'], extra: Partial<LEOrder> = {}): LEOrder => ({
  orderId: 'o1',
  kind: 'http-01',
  status,
  domains: 'a.example.com',
  ...extra
});

/** A fake clock: sleep advances time instead of waiting. */
function clock() {
  let t = 0;
  return { now: () => t, sleep: async (ms: number) => void (t += ms) };
}

describe('waitForLEOrder', () => {
  it('reports progress until the order is issued', async () => {
    const states = [order('processing', { progress: 'Creating the order' }), order('processing', { progress: 'Validating' }), order('issued', { certId: 'c1' })];
    const seen: string[] = [];
    const final = await waitForLEOrder(async () => states.shift()!, 'o1', (o) => seen.push(o.progress ?? o.status), clock());
    expect(final).toMatchObject({ status: 'issued', certId: 'c1' });
    expect(seen).toEqual(['Creating the order', 'Validating', 'issued']);
  });

  it('returns a failed order with its error', async () => {
    const final = await waitForLEOrder(async () => order('failed', { error: 'Validation failed: 404' }), 'o1', () => {}, clock());
    expect(final).toMatchObject({ status: 'failed', error: 'Validation failed: 404' });
  });

  it('retries transient errors but gives up after five in a row', async () => {
    let calls = 0;
    const flaky = async () => {
      calls++;
      if (calls < 3) throw new Error('502');
      return order('issued');
    };
    expect(await waitForLEOrder(flaky, 'o1', () => {}, clock())).toMatchObject({ status: 'issued' });
    await expect(
      waitForLEOrder(async () => {
        throw new Error('down');
      }, 'o1', () => {}, clock())
    ).rejects.toThrow('down');
  });

  it('stops after the limit with a failed state', async () => {
    const final = await waitForLEOrder(async () => order('processing'), 'o1', () => {}, { ...clock(), intervalMs: 2000, limitMs: 10_000 });
    expect(final?.status).toBe('failed');
    expect(final?.error).toMatch(/taking longer than expected/);
  });

  it('stops quietly when aborted', async () => {
    const ac = new AbortController();
    const final = await waitForLEOrder(
      async () => {
        ac.abort();
        return order('processing');
      },
      'o1',
      () => {},
      { ...clock(), signal: ac.signal }
    );
    expect(final).toBeNull();
  });
});
