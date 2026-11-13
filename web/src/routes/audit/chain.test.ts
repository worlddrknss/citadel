import { describe, expect, it } from 'vitest';
import { legacyBreakNote } from './api';

describe('legacyBreakNote', () => {
  it('is empty without legacy breaks', () => {
    expect(legacyBreakNote(null)).toBe('');
    expect(legacyBreakNote({})).toBe('');
    expect(legacyBreakNote({ legacyLinkBreaks: 0 })).toBe('');
  });

  it('explains the breaks', () => {
    expect(legacyBreakNote({ legacyLinkBreaks: 16 })).toBe(
      "16 links in pre-2.0 history don't connect. This is consistent with concurrent writes in Citadel 1.x, which didn't lock the chain; events from 2.0 on are fully verified."
    );
    expect(legacyBreakNote({ legacyLinkBreaks: 1 })).toMatch(/^1 link in pre-2.0 history doesn't connect\./);
  });
});
