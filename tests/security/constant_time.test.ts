import { describe, it, expect } from 'vitest';
import {
  constantTimeEqual,
  constantTimeCompareHex,
  constantTimeSelect,
} from '../../src/lib/security/constant_time.js';

describe('constantTimeEqual', () => {
  it('returns true for identical byte arrays', () => {
    const a = new Uint8Array([1, 2, 3, 4]);
    const b = new Uint8Array([1, 2, 3, 4]);
    expect(constantTimeEqual(a, b)).toBe(true);
  });

  it('returns false for arrays that differ in one byte', () => {
    const a = new Uint8Array([1, 2, 3, 4]);
    const b = new Uint8Array([1, 2, 3, 5]);
    expect(constantTimeEqual(a, b)).toBe(false);
  });

  it('returns false for arrays of different length', () => {
    const a = new Uint8Array([1, 2, 3]);
    const b = new Uint8Array([1, 2, 3, 4]);
    expect(constantTimeEqual(a, b)).toBe(false);
  });

  it('returns true for two empty arrays', () => {
    expect(constantTimeEqual(new Uint8Array([]), new Uint8Array([]))).toBe(true);
  });
});

describe('constantTimeCompareHex', () => {
  it('matches equal hex strings regardless of 0x prefix and case', () => {
    expect(constantTimeCompareHex('0xAB12', 'ab12')).toBe(true);
    expect(constantTimeCompareHex('ab12', '0xAB12')).toBe(true);
  });

  it('rejects differing hex strings', () => {
    expect(constantTimeCompareHex('0xab12', '0xab13')).toBe(false);
  });

  it('rejects hex strings of different length', () => {
    expect(constantTimeCompareHex('0xab', '0xab12')).toBe(false);
  });
});

describe('constantTimeSelect', () => {
  it('returns a when condition is true', () => {
    expect(constantTimeSelect(true, 10n, 20n)).toBe(10n);
  });

  it('returns b when condition is false', () => {
    expect(constantTimeSelect(false, 10n, 20n)).toBe(20n);
  });
});
