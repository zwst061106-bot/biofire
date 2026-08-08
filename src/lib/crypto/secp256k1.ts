/**
 * Production secp256k1 Cryptography
 * Real elliptic curve operations using @noble/curves.
 */

import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { keccak_256 } from '@noble/hashes/sha3';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { randomScalar } from '../security/secure_random';

export const CURVE_ORDER = secp256k1.CURVE.n;

export interface Secp256k1KeyPair {
  privateKey: string;
  publicKey: string;
  publicKeyCompressed: string;
}

export interface Secp256k1Signature {
  r: string;
  s: string;
  v: number;
  rawSigHex: string;
}

/**
 * Generate a real secp256k1 keypair using CSPRNG.
 */
export function generateKeyPairSecp256k1(): Secp256k1KeyPair {
  const priv = secp256k1.utils.randomPrivateKey();
  const pub = secp256k1.getPublicKey(priv, false); // uncompressed
  const pubCompressed = secp256k1.getPublicKey(priv, true); // compressed

  return {
    privateKey: '0x' + bytesToHex(priv),
    publicKey: '0x' + bytesToHex(pub),
    publicKeyCompressed: '0x' + bytesToHex(pubCompressed),
  };
}

/**
 * Modular inverse modulo curve order (for signatures).
 */
export function modInverseOrder(k: bigint): bigint {
  const n = CURVE_ORDER;
  k = ((k % n) + n) % n;
  let t = 0n, newt = 1n;
  let r = n, newr = k;
  while (newr !== 0n) {
    const q = r / newr;
    [t, newt] = [newt, t - q * newt];
    [r, newr] = [newr, r - q * newr];
  }
  if (r > 1n) throw new Error('Not invertible');
  if (t < 0n) t += n;
  return t;
}

export function modN(x: bigint): bigint {
  const r = x % CURVE_ORDER;
  return r < 0n ? r + CURVE_ORDER : r;
}

/**
 * Generate partial threshold signature share.
 * R = k·G, r = x(R), s = k⁻¹(z + r·xᵢ) mod N
 */
export function generatePartialSignature(
  privateShare: bigint,
  messageHash: Uint8Array,
  nonce: bigint
): { r: bigint; s: bigint; R: Uint8Array } {
  const R = secp256k1.ProjectivePoint.BASE.multiply(nonce);
  const Rbytes = R.toRawBytes(false);
  const r = modN(R.x);
  const z = bytesToBigInt(messageHash);
  const kInv = modInverseOrder(nonce);
  const rx = modN(r * privateShare);
  const z_plus_rx = modN(z + rx);
  const s = modN(kInv * z_plus_rx);

  return { r, s, R: Rbytes };
}

/**
 * Sign a message with real secp256k1 ECDSA.
 */
export function signMessageSecp256k1(privateKeyHex: string, message: Uint8Array): Secp256k1Signature {
  const priv = hexToBytes(privateKeyHex.replace('0x', ''));
  const sig = secp256k1.sign(message, priv);
  const rawSigHex = '0x' + sig.r.toString(16).padStart(64, '0') + sig.s.toString(16).padStart(64, '0') + (sig.recovery! + 27).toString(16);
  return {
    r: '0x' + sig.r.toString(16).padStart(64, '0'),
    s: '0x' + sig.s.toString(16).padStart(64, '0'),
    v: sig.recovery!,
    rawSigHex,
  };
}

/**
 * Verify ECDSA signature.
 */
export function verifySignatureSecp256k1(
  publicKeyHex: string,
  message: Uint8Array,
  r: bigint,
  s: bigint
): boolean {
  try {
    const pub = hexToBytes(publicKeyHex.replace('0x', ''));
    const sig = new secp256k1.Signature(r, s);
    return secp256k1.verify(sig.toCompactRawBytes(), message, pub);
  } catch {
    return false;
  }
}

/**
 * Derive Ethereum address from public key using Keccak-256.
 */
export function deriveEthereumAddress(publicKeyHex: string): string {
  const pub = hexToBytes(publicKeyHex.replace('0x', ''));
  const pubNoPrefix = pub.length === 65 ? pub.slice(1) : pub;
  const hash = keccak_256(pubNoPrefix);
  const rawAddr = bytesToHex(hash.slice(-20));

  // EIP-55 checksum
  const hashOfAddr = bytesToHex(keccak_256(new TextEncoder().encode(rawAddr)));
  let checksummed = '0x';
  for (let i = 0; i < 40; i++) {
    checksummed += parseInt(hashOfAddr[i], 16) >= 8
      ? rawAddr[i].toUpperCase()
      : rawAddr[i].toLowerCase();
  }
  return checksummed;
}

/**
 * Validate Ethereum address format.
 */
export function isValidEthereumAddress(address: string): boolean {
  return /^0x[a-fA-F0-9]{40}$/.test(address);
}

/**
 * Validate Bitcoin address format.
 */
export function isValidBitcoinAddress(address: string): { valid: boolean; type?: string } {
  if (/^(bc1|tb1)[a-zA-Z0-9]{38,59}$/.test(address)) {
    return { valid: true, type: 'Bech32' };
  }
  if (/^[13m][a-km-zA-HJ-NP-Z1-9]{25,34}$/.test(address)) {
    return { valid: true, type: address.startsWith('3') ? 'P2SH' : 'Legacy P2PKH' };
  }
  return { valid: false };
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let hex = '0x';
  for (const b of bytes) hex += b.toString(16).padStart(2, '0');
  return BigInt(hex);
}

export { secp256k1, sha256, bytesToHex, hexToBytes };
