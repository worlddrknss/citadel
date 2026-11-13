import { describe, expect, it } from 'vitest';
import { validateName, NAME_MESSAGES, DEFAULT_LIMITS } from './api';

describe('validateName', () => {
  it('accepts ordinary names, including aws/ssm below the first level', () => {
    expect(validateName('/app/prod/db')).toBe('');
    expect(validateName('/app/aws/ssm')).toBe('');
    expect(validateName('/my-ssm')).toBe('');
  });

  it('rejects names beginning with aws or ssm in any case, with the server message', () => {
    for (const n of ['/aws/x', '/AWSkey', '/ssm', '/Ssm-config', 'awsKey']) {
      expect(validateName(n)).toBe(NAME_MESSAGES.reserved);
    }
  });

  it('rejects more than 15 levels', () => {
    expect(validateName('/a'.repeat(15))).toBe('');
    expect(validateName('/a'.repeat(16))).toBe(NAME_MESSAGES.hierarchy);
  });

  it('applies the per-account length limit from the server', () => {
    const limits = { nameMaxLength: 20, maxHierarchyLevels: 15 };
    expect(validateName('/' + 'n'.repeat(19), limits)).toBe('');
    expect(validateName('/' + 'n'.repeat(20), limits)).toBe(NAME_MESSAGES.tooLong(20));
    expect(validateName('/' + 'n'.repeat(DEFAULT_LIMITS.nameMaxLength))).toContain('1011');
  });
});
