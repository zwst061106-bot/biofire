/**
 * Cryptographically Secure Pseudo-Random Number Generator (CSPRNG)
 * Production-grade: NEVER falls back to Math.random() or Date.now().
 */

import { randomBytes as nodeRandomBytes } from 'node:crypto';

export class CSPRNGError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CSPRNGError';
  }
}

/**
 * Generate cryptographically secure random bytes.
 * Uses crypto.getRandomValues() in browsers and crypto.randomBytes() in Node.js.
 */
export function secureRandomBytes(length: number): Uint8Array {
  if (length <= 0 || length > 65536) {
    throw new CSPRNGError(`Invalid length: ${length}. Must be 1-65536.`);
  }

  const bytes = new Uint8Array(length);

  try {
    if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
      crypto.getRandomValues(bytes);
      return bytes;
    }
  } catch {
    // Continue to Node.js fallback
  }

  try {
    // Node.js
    const nodeBytes = nodeRandomBytes(length);
    bytes.set(nodeBytes);
    return bytes;
  } catch {
    throw new CSPRNGError(
      'FATAL: CSPRNG (crypto.getRandomValues or crypto.randomBytes) is not available. ' +
      'This environment is UNSAFE for cryptographic operations.'
    );
  }
}

/**
 * Generate a random bigint less than max using rejection sampling.
 * Ensures uniform distribution to avoid modulo bias.
 */
export function randomBigInt(max: bigint): bigint {
  if (max <= 0n) {
    throw new CSPRNGError('max must be positive');
  }

  const bitLength = max.toString(2).length;
  const byteLength = Math.ceil(bitLength / 8);
  // Add extra bytes to reduce bias from rejection sampling
  const extraBytes = 8;

  while (true) {
    const bytes = secureRandomBytes(byteLength + extraBytes);
    let result = 0n;
    for (const b of bytes) {
      result = (result << 8n) | BigInt(b);
    }
    if (result < max) {
      return result;
    }
    // Rejection sampling: if result >= max, try again
  }
}

/**
 * Generate a random bigint in range [min, max).
 */
export function randomBigIntRange(min: bigint, max: bigint): bigint {
  if (min >= max) {
    throw new CSPRNGError('min must be less than max');
  }
  return min + randomBigInt(max - min);
}

/**
 * Generate a random scalar for elliptic curve operations.
 * Ensures 1 <= result < curveOrder to avoid weak keys.
 */
export function randomScalar(curveOrder: bigint): bigint {
  if (curveOrder <= 1n) {
    throw new CSPRNGError('curveOrder must be > 1');
  }
  let scalar: bigint;
  do {
    scalar = randomBigInt(curveOrder);
  } while (scalar === 0n);
  return scalar;
}
