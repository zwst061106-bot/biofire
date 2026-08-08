/**
 * Constant-Time Comparison Utilities
 * Protects against timing side-channel attacks.
 */

/**
 * Compare two Uint8Arrays in constant time.
 * Returns true if equal, false otherwise.
 * Execution time depends only on array length, not on content.
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i];
  }
  return result === 0;
}

/**
 * Compare two hex strings in constant time.
 */
export function constantTimeCompareHex(a: string, b: string): boolean {
  const cleanA = a.startsWith('0x') ? a.slice(2) : a;
  const cleanB = b.startsWith('0x') ? b.slice(2) : b;
  if (cleanA.length !== cleanB.length) return false;

  const bufA = new TextEncoder().encode(cleanA.toLowerCase());
  const bufB = new TextEncoder().encode(cleanB.toLowerCase());
  return constantTimeEqual(bufA, bufB);
}

/**
 * Constant-time select: returns a if condition is true, b otherwise.
 * Prevents branch prediction leaks.
 */
export function constantTimeSelect(condition: boolean, a: bigint, b: bigint): bigint {
  const mask = BigInt(condition ? -1 : 0);
  return (a & mask) | (b & ~mask);
}
