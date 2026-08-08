/**
 * Production Paillier Homomorphic Encryption
 * Implements: Key generation, encryption, decryption, homomorphic addition,
 * and scalar multiplication with cryptographically secure primes.
 */

import { secureRandomBytes, randomBigInt } from '../security/secure_random';

export interface PaillierPublicKey {
  n: bigint;
  g: bigint;
  nSquared: bigint;
}

export interface PaillierPrivateKey {
  lambda: bigint;
  mu: bigint;
  p: bigint;
  q: bigint;
}

export interface PaillierKeyPair {
  publicKey: PaillierPublicKey;
  privateKey: PaillierPrivateKey;
}

// Small primes for trial division (first 100 primes)
const SMALL_PRIMES = [
  2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n, 41n, 43n, 47n,
  53n, 59n, 61n, 67n, 71n, 73n, 79n, 83n, 89n, 97n, 101n, 103n, 107n, 109n,
  113n, 127n, 131n, 137n, 139n, 149n, 151n, 157n, 163n, 167n, 173n, 179n,
  181n, 191n, 193n, 197n, 199n, 211n, 223n, 227n, 229n, 233n, 239n, 241n,
  251n, 257n, 263n, 269n, 271n, 277n, 281n, 283n, 293n, 307n, 311n, 313n,
  317n, 331n, 337n, 347n, 349n, 353n, 359n, 367n, 373n, 379n, 383n, 389n,
  397n, 401n, 409n, 419n, 421n, 431n, 433n, 439n, 443n, 449n, 457n, 461n,
  463n, 467n, 479n, 487n, 491n, 499n, 503n, 509n, 521n, 523n, 541n
];

/**
 * Generate Paillier keypair with secure large primes.
 * Default bitLength = 2048 (two 1024-bit primes).
 * Production recommendation: 3072-bit for long-term security.
 */
export function generatePaillierKeys(bitLength: number = 2048): PaillierKeyPair {
  if (bitLength < 1024) {
    throw new Error('Paillier bitLength must be at least 1024 for security');
  }

  const pBits = Math.floor(bitLength / 2);
  const p = generateSecurePrime(pBits);
  let q: bigint;
  do {
    q = generateSecurePrime(pBits);
  } while (q === p || gcd(p - 1n, q - 1n) !== 2n); // Ensure gcd(p-1, q-1) is small

  const n = p * q;
  const nSquared = n * n;
  const g = n + 1n; // Standard choice: g = n + 1
  const lambda = lcm(p - 1n, q - 1n);

  // mu = (L(g^lambda mod n²))⁻¹ mod n
  // where L(u) = (u - 1) / n
  const gLambda = modPow(g, lambda, nSquared);
  const l = (gLambda - 1n) / n;
  const mu = modInverse(l, n);

  return {
    publicKey: { n, g, nSquared },
    privateKey: { lambda, mu, p, q },
  };
}

/**
 * Encrypt plaintext m with Paillier public key.
 * c = g^m · r^n mod n²
 */
export function encryptPaillier(
  publicKey: PaillierPublicKey,
  plaintext: bigint
): bigint {
  const { n, g, nSquared } = publicKey;

  if (plaintext < 0n || plaintext >= n) {
    throw new Error(`Plaintext must be in [0, n-1]. Got: ${plaintext}`);
  }

  // Random r ∈ (1, n) with gcd(r, n) = 1
  let r: bigint;
  let attempts = 0;
  const maxAttempts = 1000;
  do {
    r = randomBigInt(n - 2n) + 2n;
    attempts++;
    if (attempts > maxAttempts) {
      throw new Error('Failed to find valid random r for Paillier encryption');
    }
  } while (gcd(r, n) !== 1n);

  const gm = modPow(g, plaintext, nSquared);
  const rn = modPow(r, n, nSquared);
  return (gm * rn) % nSquared;
}

/**
 * Decrypt ciphertext c with Paillier private key.
 * m = L(c^λ mod n²) · μ mod n
 */
export function decryptPaillier(
  privateKey: PaillierPrivateKey,
  publicKey: PaillierPublicKey,
  ciphertext: bigint
): bigint {
  const { lambda, mu } = privateKey;
  const { n, nSquared } = publicKey;

  if (ciphertext <= 0n || ciphertext >= nSquared) {
    throw new Error(`Ciphertext must be in (0, n²). Got: ${ciphertext}`);
  }

  const cLambda = modPow(ciphertext, lambda, nSquared);
  const l = (cLambda - 1n) / n;
  return (l * mu) % n;
}

/**
 * Homomorphic addition: E(m1) · E(m2) = E(m1 + m2 mod n)
 */
export function addEncrypted(
  publicKey: PaillierPublicKey,
  c1: bigint,
  c2: bigint
): bigint {
  return (c1 * c2) % publicKey.nSquared;
}

/**
 * Homomorphic scalar multiplication: E(m)^k = E(m · k mod n)
 */
export function multiplyEncryptedByScalar(
  publicKey: PaillierPublicKey,
  ciphertext: bigint,
  scalar: bigint
): bigint {
  return modPow(ciphertext, scalar, publicKey.nSquared);
}

// ======================
// MODULAR ARITHMETIC
// ======================

export function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  if (mod === 1n) return 0n;
  if (exp < 0n) {
    throw new Error('Negative exponents not supported in modPow');
  }
  let result = 1n;
  let b = ((base % mod) + mod) % mod;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) {
      result = (result * b) % mod;
    }
    b = (b * b) % mod;
    e >>= 1n;
  }
  return result;
}

export function modInverse(a: bigint, m: bigint): bigint {
  const [g, x] = extendedGcd(((a % m) + m) % m, m);
  if (g !== 1n) {
    throw new Error(`Modular inverse does not exist: gcd(${a}, ${m}) = ${g}`);
  }
  return ((x % m) + m) % m;
}

function extendedGcd(a: bigint, b: bigint): [bigint, bigint, bigint] {
  if (b === 0n) return [a, 1n, 0n];
  const [g, x1, y1] = extendedGcd(b, a % b);
  return [g, y1, x1 - (a / b) * y1];
}

export function gcd(a: bigint, b: bigint): bigint {
  a = a < 0n ? -a : a;
  b = b < 0n ? -b : b;
  while (b !== 0n) {
    const t = b;
    b = a % b;
    a = t;
  }
  return a;
}

function lcm(a: bigint, b: bigint): bigint {
  return (a * b) / gcd(a, b);
}

// ======================
// PRIME GENERATION
// ======================

function generateSecurePrime(bits: number): bigint {
  if (bits < 512) {
    throw new Error('Prime bits must be at least 512 for security');
  }

  while (true) {
    // Generate random odd candidate with exact bit length
    let candidate = randomBigInt(1n << BigInt(bits - 1)) | 1n | (1n << BigInt(bits - 1));

    // Trial division by small primes
    let divisible = false;
    for (const p of SMALL_PRIMES) {
      if (candidate % p === 0n) {
        divisible = true;
        break;
      }
    }
    if (divisible) continue;

    // Miller-Rabin primality test with 40 rounds (error probability < 2^-80)
    if (isProbablePrime(candidate, 40)) {
      return candidate;
    }
  }
}

function isProbablePrime(n: bigint, k: number): boolean {
  if (n < 2n) return false;
  if (n === 2n || n === 3n) return true;
  if (n % 2n === 0n) return false;

  // Write n-1 as 2^r · d
  let r = 0n;
  let d = n - 1n;
  while (d % 2n === 0n) {
    d /= 2n;
    r++;
  }

  for (let i = 0; i < k; i++) {
    const a = randomBigIntRange(2n, n - 2n);
    let x = modPow(a, d, n);
    if (x === 1n || x === n - 1n) continue;

    let composite = true;
    for (let j = 0; j < Number(r) - 1; j++) {
      x = modPow(x, 2n, n);
      if (x === n - 1n) {
        composite = false;
        break;
      }
    }
    if (composite) return false;
  }
  return true;
}
