import { describe, it, expect } from 'vitest';
import { secureRandomBytes, randomBigInt, randomScalar } from '../../src/lib/security/secure_random.js';
import { CURVE_ORDER } from '../../src/lib/crypto/secp256k1.js';

describe('CSPRNG', () => {
  it('should generate random bytes', () => {
    const b1 = secureRandomBytes(32);
    const b2 = secureRandomBytes(32);
    expect(b1.length).toBe(32);
    expect(b2.length).toBe(32);
    // Very unlikely to be equal
    expect(Buffer.from(b1).toString('hex')).not.toBe(Buffer.from(b2).toString('hex'));
  });

  it('should reject invalid length', () => {
    expect(() => secureRandomBytes(0)).toThrow();
    expect(() => secureRandomBytes(70000)).toThrow();
  });

  it('should generate random scalar', () => {
    const s = randomScalar(CURVE_ORDER);
    expect(s > 0n && s < CURVE_ORDER).toBe(true);
  });

  it('should generate random bigint', () => {
    const max = 1000n;
    const r = randomBigInt(max);
    expect(r >= 0n && r < max).toBe(true);
  });
});
