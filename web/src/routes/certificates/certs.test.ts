import { describe, expect, it } from 'vitest';
import { pathLenDescription, pathLenLabel } from './certs';

describe('pathLen display', () => {
  it('labels CAs only', () => {
    expect(pathLenLabel({ isCA: false, pathLen: 1 })).toBe('');
    expect(pathLenLabel({ isCA: true })).toBe('pathLen: unlimited');
    expect(pathLenLabel({ isCA: true, pathLen: 0 })).toBe('pathLen: 0');
    expect(pathLenLabel({ isCA: true, pathLen: 2 })).toBe('pathLen: 2');
  });

  it('describes the constraint', () => {
    expect(pathLenDescription()).toMatch(/^Unlimited/);
    expect(pathLenDescription(0)).toMatch(/end-entity certificates only/);
    expect(pathLenDescription(1)).toBe('1 — up to 1 more CA level below it');
    expect(pathLenDescription(3)).toBe('3 — up to 3 more CA levels below it');
  });
});
