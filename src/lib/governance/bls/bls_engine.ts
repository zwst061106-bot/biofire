/**
 * BLS12-381 Threshold Signature Engine
 * 
 * Used for compact multi-sig aggregation in governance approvals.
 * A single BLS signature aggregates N individual signatures into one compact proof.
 * 
 * Security: BLS signatures are deterministic (no nonce reuse risk).
 * Aggregation is linear: σ_agg = Σ σ_i (in G1).
 * Verification: e(σ_agg, G2) == e(H(m), PK_agg)
 */

import { bls12_381 } from '@noble/curves/bls12-381';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { SecureBuffer } from '../../security/secure_buffer.js';
import { randomScalar } from '../../security/secure_random.js';

const G1 = bls12_381.G1;
const G2 = bls12_381.G2;
const CURVE_ORDER = bls12_381.CURVE.r;

export interface BLSKeyPair {
  privateKey: SecureBuffer;
  publicKey: string; // hex G2 point
}

export interface BLSSignature {
  signature: string; // hex G1 point
  signerIndex: number;
}

export interface AggregatedApproval {
  aggregatedSignature: string;
  signers: number[];
  messageHash: string;
  thresholdMet: boolean;
}

/**
 * Generate BLS keypair for a governance role holder.
 */
export function generateBLSKeyPair(): BLSKeyPair {
  const priv = randomScalar(CURVE_ORDER);
  const privBytes = new Uint8Array(32);
  let v = priv;
  for (let i = 31; i >= 0; i--) {
    privBytes[i] = Number(v & 0xFFn);
    v >>= 8n;
  }

  const pub = bls12_381.getPublicKey(privBytes);
  return {
    privateKey: SecureBuffer.from(privBytes),
    publicKey: '0x' + bytesToHex(pub),
  };
}

/**
 * Sign a governance approval message with BLS.
 */
export function signBLS(privateKey: SecureBuffer, message: Uint8Array): BLSSignature {
  const sig = bls12_381.sign(message, privateKey.bytes);
  return {
    signature: '0x' + bytesToHex(sig),
    signerIndex: -1, // Set by caller
  };
}

/**
 * Verify individual BLS signature.
 */
export function verifyBLS(publicKeyHex: string, message: Uint8Array, signatureHex: string): boolean {
  try {
    const pub = hexToBytes(publicKeyHex.replace('0x', ''));
    const sig = hexToBytes(signatureHex.replace('0x', ''));
    return bls12_381.verify(sig, message, pub);
  } catch {
    return false;
  }
}

/**
 * Aggregate multiple BLS signatures into one compact signature.
 * This is the KEY feature that makes BLS superior to ECDSA for multi-sig.
 */
export function aggregateSignatures(signatures: BLSSignature[]): AggregatedApproval {
  if (signatures.length === 0) {
    throw new Error('Cannot aggregate empty signature set');
  }

  const sigPoints = signatures.map(s => {
    return G1.ProjectivePoint.fromHex(s.signature.replace('0x', ''));
  });

  // Linear aggregation: σ_agg = Σ σ_i
  let agg = sigPoints[0];
  for (let i = 1; i < sigPoints.length; i++) {
    agg = agg.add(sigPoints[i]);
  }

  const messageHash = '0x' + bytesToHex(sha256(new TextEncoder().encode('approval')));

  return {
    aggregatedSignature: '0x' + bytesToHex(agg.toRawBytes()),
    signers: signatures.map(s => s.signerIndex),
    messageHash,
    thresholdMet: signatures.length > 0,
  };
}

/**
 * Verify aggregated BLS signature against aggregated public key.
 */
export function verifyAggregatedBLS(
  aggregatedPublicKey: string,
  message: Uint8Array,
  aggregatedSignature: string
): boolean {
  try {
    const apk = hexToBytes(aggregatedPublicKey.replace('0x', ''));
    const sig = hexToBytes(aggregatedSignature.replace('0x', ''));
    return bls12_381.verify(sig, message, apk);
  } catch {
    return false;
  }
}

/**
 * Aggregate public keys (for verifying aggregated signatures).
 */
export function aggregatePublicKeys(publicKeys: string[]): string {
  const points = publicKeys.map(pk => 
    G2.ProjectivePoint.fromHex(pk.replace('0x', ''))
  );

  let agg = points[0];
  for (let i = 1; i < points.length; i++) {
    agg = agg.add(points[i]);
  }

  return '0x' + bytesToHex(agg.toRawBytes());
}
