import { describe, expect, it } from 'vitest';
import { anchorNote, formatBytes, retentionLabel } from './api';

describe('retentionLabel', () => {
  it('names forever and days', () => {
    expect(retentionLabel(0)).toBe('Keep forever');
    expect(retentionLabel(1)).toBe('1 day');
    expect(retentionLabel(90)).toBe('90 days');
  });
});

describe('formatBytes', () => {
  it('uses binary units', () => {
    expect(formatBytes(undefined)).toBe('—');
    expect(formatBytes(-1)).toBe('—');
    expect(formatBytes(512)).toBe('512 bytes');
    expect(formatBytes(2048)).toBe('2 KB');
    expect(formatBytes(224 * 1024 * 1024)).toBe('224.0 MB');
    expect(formatBytes(2.05 * 1024 ** 3)).toBe('2.0 GB');
  });
});

describe('anchorNote', () => {
  it('is empty without an anchor', () => {
    expect(anchorNote(null)).toBe('');
    expect(anchorNote(undefined)).toBe('');
  });
  it('says what was pruned and where verification starts', () => {
    const note = anchorNote(
      { chainSeq: 224999, eventId: 225010, hash: 'ab', prunedBefore: '2026-10-14T12:00:00Z', prunedEvents: 224999, updatedAt: '2026-11-13T12:00:00Z' },
      () => 'Oct 14'
    );
    expect(note).toBe(
      `History before Oct 14 was pruned by the retention policy (${(224999).toLocaleString()} events). Verification starts at the signed anchor, chain position ${(224999).toLocaleString()}.`
    );
    expect(anchorNote({ chainSeq: 1, eventId: 1, hash: '', prunedBefore: '2026-10-14T12:00:00Z', prunedEvents: 1, updatedAt: '' }, () => 'x')).toMatch(/\(1 event\)/);
  });
});
