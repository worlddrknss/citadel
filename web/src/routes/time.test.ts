import { afterEach, describe, expect, it } from 'vitest';
import { daysUntil, fullTime, initials, relTime, utcStamp } from './time';

// Date follows process.env.TZ at runtime (tests run in forked processes), so
// each case pins the zone it is about.
const originalTZ = process.env.TZ;
function inTZ(tz: string) {
  process.env.TZ = tz;
}
afterEach(() => {
  if (originalTZ === undefined) delete process.env.TZ;
  else process.env.TZ = originalTZ;
});

const ZONES = [
  'UTC',
  'America/New_York',
  'America/Los_Angeles',
  'Europe/London',
  'America/Santiago', // DST switches at midnight: some days have no 00:00
  'Australia/Lord_Howe', // 30-minute DST shift
  'Asia/Kathmandu', // +05:45, no DST
  'Pacific/Chatham' // +12:45 / +13:45
];

describe('daysUntil', () => {
  describe.each(ZONES)('in %s', (tz) => {
    it('counts local calendar days for every day of a year (crossing both DST changes)', () => {
      inTZ(tz);
      const now = new Date(2026, 0, 1, 0, 15);
      for (let k = 0; k <= 400; k++) {
        const late = new Date(2026, 0, 1 + k, 23, 45);
        expect(daysUntil(late.toISOString(), now), `day +${k} late evening`).toBe(k);
        const past = new Date(2026, 0, 1 - k, 23, 45);
        expect(daysUntil(past.toISOString(), now), `day -${k}`).toBe(k === 0 ? 0 : -k);
      }
    });

    it('is 0 for any time later the same local day', () => {
      inTZ(tz);
      const now = new Date(2026, 5, 15, 0, 30);
      expect(daysUntil(new Date(2026, 5, 15, 23, 59).toISOString(), now)).toBe(0);
    });
  });

  it('spring-forward in New York: a 23-hour day still counts as one', () => {
    inTZ('America/New_York');
    // Sat Mar 7 23:30 EST → Mon Mar 9 00:30 EDT; Sunday Mar 8 is 23 h long.
    const now = new Date('2026-03-08T04:30:00Z');
    expect(daysUntil('2026-03-09T04:30:00Z', now)).toBe(2);
    // Same instants bucketed by UTC date would give 1.
  });

  it('fall-back in New York: a 25-hour day still counts as one', () => {
    inTZ('America/New_York');
    const now = new Date('2026-10-31T16:00:00Z'); // Sat Oct 31 12:00 EDT
    expect(daysUntil('2026-11-02T17:00:00Z', now)).toBe(2); // Mon Nov 2 12:00 EST
    expect(daysUntil('2026-11-02T04:59:00Z', now)).toBe(1); // Sun Nov 1 23:59 EST
  });

  it('west of Greenwich, a late-evening event is today, not tomorrow', () => {
    // 2026-11-12T07:00Z is Nov 11 23:00 in Los Angeles; 09:00Z is Nov 12 01:00.
    const now = new Date('2026-11-12T07:00:00Z');
    inTZ('America/Los_Angeles');
    expect(daysUntil('2026-11-12T09:00:00Z', now)).toBe(1);
    expect(daysUntil('2026-11-12T07:30:00Z', now)).toBe(0);
    inTZ('UTC');
    expect(daysUntil('2026-11-12T09:00:00Z', now)).toBe(0);
  });

  it('east of Greenwich, the day rolls over before UTC midnight', () => {
    inTZ('Asia/Tokyo');
    // Nov 13 01:00 JST vs Nov 12 23:00 JST.
    expect(daysUntil('2026-11-12T14:00:00Z', new Date('2026-11-12T16:00:00Z'))).toBe(-1);
  });
});

describe('relTime', () => {
  const now = new Date('2026-11-12T18:00:00Z');

  it('formats recent times', () => {
    inTZ('UTC');
    expect(relTime('2026-11-12T17:59:30Z', now)).toBe('just now');
    expect(relTime('2026-11-12T17:59:00Z', now)).toBe('1 min ago');
    expect(relTime('2026-11-12T17:56:00Z', now)).toBe('4 min ago');
    expect(relTime('2026-11-12T15:00:00Z', now)).toBe('3 h ago');
  });

  it('says Yesterday based on the local calendar', () => {
    const iso = '2026-11-12T06:00:00Z'; // 12 h earlier
    inTZ('UTC');
    expect(relTime(iso, now)).toBe('12 h ago');
    inTZ('America/Los_Angeles'); // Nov 11 22:00 vs Nov 12 10:00
    expect(relTime(iso, now)).toBe('Yesterday');
    inTZ('Asia/Tokyo'); // event Nov 12 23:00 JST, now Nov 13 01:00 JST
    expect(relTime('2026-11-12T14:00:00Z', new Date('2026-11-12T16:00:00Z'))).toBe('Yesterday');
  });

  it('shows a date, with the year only when it differs', () => {
    inTZ('UTC');
    const same = relTime('2026-11-01T12:00:00Z', now);
    expect(same).not.toMatch(/2026/);
    expect(same).toMatch(/1/);
    expect(relTime('2025-11-01T12:00:00Z', now)).toMatch(/2025/);
  });

  it('returns unparseable input unchanged', () => {
    expect(relTime('not a date', now)).toBe('not a date');
    expect(fullTime('nope')).toBe('nope');
  });
});

describe('utcStamp', () => {
  it('is the same in every zone', () => {
    for (const tz of ZONES) {
      inTZ(tz);
      expect(utcStamp('2026-11-12T13:04:51Z')).toBe('Nov 12, 13:04:51');
    }
  });

  it('shows midnight as 00, not 24', () => {
    expect(utcStamp('2026-11-12T00:04:05Z')).toBe('Nov 12, 00:04:05');
  });

  it('returns unparseable input unchanged', () => {
    expect(utcStamp('x')).toBe('x');
  });
});

describe('initials', () => {
  it.each([
    ['Priya Nair', 'PN'],
    ['svc/rotation-bot', 'RB'],
    ['jane.doe@example.com', 'JD'],
    ['admin', 'A'],
    ['', '?'],
    ['---', '?']
  ])('%s → %s', (input, out) => {
    expect(initials(input)).toBe(out);
  });
});
